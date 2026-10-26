//! Windows: Simple MAPI for the email (classic Outlook, Thunderbird and other
//! mail programs that register for it), the Share window of Windows 10/11
//! through `IDataTransferManagerInterop`, and `CF_HDROP` for the clipboard.
//! All three work from the Microsoft Store package too (full trust).

use std::cell::RefCell;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;

use tauri::{AppHandle, Manager, WebviewWindow};
use windows::ApplicationModel::DataTransfer::{DataRequestedEventArgs, DataTransferManager};
use windows::Foundation::TypedEventHandler;
use windows::Storage::{IStorageItem, StorageFile};
use windows::Win32::Foundation::{FARPROC, GlobalFree, HANDLE, HWND};
use windows::Win32::System::Com::{COINIT_APARTMENTTHREADED, CoInitializeEx, CoUninitialize};
use windows::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, OpenClipboard, RegisterClipboardFormatW, SetClipboardData,
};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::Win32::System::Mapi::{
    LPMAPISENDMAILW, MAPI_DIALOG, MAPI_E_USER_ABORT, MAPI_LOGON_UI, MapiFileDescW, MapiMessageW,
    SUCCESS_SUCCESS,
};
use windows::Win32::System::Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock};
use windows::Win32::System::Ole::{CF_HDROP, DROPEFFECT_COPY};
use windows::Win32::UI::Shell::IDataTransferManagerInterop;
use windows::core::{HSTRING, Interface, PWSTR, Ref, factory, s, w};
use windows_collections::IIterable;

use super::{Abilities, Anchor, Message, dropfiles, on_main, share_error};
use crate::CmdResult;

pub fn abilities() -> Abilities {
    Abilities {
        email: true,
        // Windows 10 1709 and later; an older one has no Share window for
        // desktop programs.
        share: DataTransferManager::IsSupported().unwrap_or(false),
        copy: true,
    }
}

fn wide(s: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain([0]).collect()
}

/// `MAPISendMailW` from mapi32.dll, which hands the message to the default
/// mail program. None when it has none that takes Simple MAPI (the new
/// Outlook, a web mail).
fn send_mail(message: &Message, paths: &[PathBuf]) -> Option<u32> {
    // SAFETY: a system DLL by name; the function has the documented signature.
    let send: LPMAPISENDMAILW = unsafe {
        let lib = LoadLibraryW(w!("mapi32.dll")).ok()?;
        std::mem::transmute::<FARPROC, LPMAPISENDMAILW>(GetProcAddress(lib, s!("MAPISendMailW")))
    };
    let mut subject = wide(&message.subject);
    let mut body = wide(&message.body);
    let mut names: Vec<(Vec<u16>, Vec<u16>)> = paths
        .iter()
        .map(|p| (wide(p), wide(p.file_name().unwrap_or(p.as_os_str()))))
        .collect();
    let mut files: Vec<MapiFileDescW> = names
        .iter_mut()
        .map(|(path, name)| MapiFileDescW {
            // No place in the text for the attachment.
            nPosition: u32::MAX,
            lpszPathName: PWSTR(path.as_mut_ptr()),
            lpszFileName: PWSTR(name.as_mut_ptr()),
            ..Default::default()
        })
        .collect();
    let msg = MapiMessageW {
        lpszSubject: PWSTR(subject.as_mut_ptr()),
        lpszNoteText: PWSTR(body.as_mut_ptr()),
        nFileCount: files.len() as u32,
        lpFiles: files.as_mut_ptr(),
        ..Default::default()
    };
    // No parent window: the mail program's window must not block ours.
    // SAFETY: every pointer in `msg` lives until the call returns.
    Some(unsafe { send?(0, 0, &msg, MAPI_LOGON_UI | MAPI_DIALOG, 0) })
}

/// True once the mail program showed the message, also when the user then
/// closed it unsent.
pub async fn email(_: &WebviewWindow, message: &Message, paths: &[PathBuf]) -> CmdResult<bool> {
    let message = message.clone();
    let paths = paths.to_vec();
    // The mail program may keep the call until its window closes, on a thread
    // of its own in a single-threaded apartment as Simple MAPI expects.
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        // SAFETY: paired with CoUninitialize on this thread.
        let com = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) }.is_ok();
        let rc = send_mail(&message, &paths);
        if com {
            unsafe { CoUninitialize() };
        }
        let _ = tx.send(rc);
    });
    let rc = tauri::async_runtime::spawn_blocking(move || rx.recv().ok().flatten())
        .await
        .map_err(|e| share_error(e.to_string()))?;
    Ok(matches!(rc, Some(SUCCESS_SUCCESS | MAPI_E_USER_ABORT)))
}

fn storage_items(paths: &[PathBuf]) -> windows::core::Result<IIterable<IStorageItem>> {
    let items = paths
        .iter()
        .map(|p| {
            StorageFile::GetFileFromPathAsync(&HSTRING::from(p.as_path()))?
                .join()?
                .cast()
                .map(Some)
        })
        .collect::<windows::core::Result<Vec<Option<IStorageItem>>>>()?;
    Ok(IIterable::from(items))
}

thread_local! {
    /// The handler for the window's share requests, replaced on every Share.
    static REQUESTED: RefCell<Option<(DataTransferManager, i64)>> = const { RefCell::new(None) };
}

fn show_share(hwnd: HWND, paths: Vec<PathBuf>) -> windows::core::Result<()> {
    let interop = factory::<DataTransferManager, IDataTransferManagerInterop>()?;
    // SAFETY: the app's own window.
    let manager: DataTransferManager = unsafe { interop.GetForWindow(hwnd)? };
    let title = HSTRING::from(Message::for_files(&paths).subject);
    // Windows asks for the data once its Share window is open.
    let handler = TypedEventHandler::new(
        move |_, args: Ref<DataRequestedEventArgs>| -> windows::core::Result<()> {
            let request = args.ok()?.Request()?;
            let data = request.Data()?;
            data.Properties()?.SetTitle(&title)?;
            match storage_items(&paths) {
                Ok(items) => data.SetStorageItemsReadOnly(&items),
                Err(e) => request.FailWithDisplayText(&HSTRING::from(e.message())),
            }
        },
    );
    let token = manager.DataRequested(&handler)?;
    REQUESTED.with(|r| {
        if let Some((old, token)) = r.replace(Some((manager, token))) {
            let _ = old.RemoveDataRequested(token);
        }
    });
    // SAFETY: as above.
    unsafe { interop.ShowShareUIForWindow(hwnd) }
}

pub async fn share(
    window: &WebviewWindow,
    paths: Vec<PathBuf>,
    _: Option<Anchor>,
) -> CmdResult<()> {
    let hwnd = window.hwnd().map_err(|e| share_error(e.to_string()))?;
    // An HWND is not Send; its value is.
    let raw = hwnd.0 as isize;
    on_main(window.app_handle(), move || {
        show_share(HWND(raw as _), paths).map_err(|e| share_error(e.message()))
    })
    .await
}

fn set_clipboard(format: u32, bytes: &[u8]) -> windows::core::Result<()> {
    // SAFETY: the memory is ours until SetClipboardData takes it; on failure it
    // is freed here.
    unsafe {
        let mem = GlobalAlloc(GMEM_MOVEABLE, bytes.len())?;
        let ptr = GlobalLock(mem);
        if ptr.is_null() {
            let _ = GlobalFree(Some(mem));
            return Err(windows::core::Error::from_thread());
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr.cast::<u8>(), bytes.len());
        let _ = GlobalUnlock(mem);
        if let Err(e) = SetClipboardData(format, Some(HANDLE(mem.0))) {
            let _ = GlobalFree(Some(mem));
            return Err(e);
        }
    }
    Ok(())
}

fn copy_files(paths: &[PathBuf]) -> windows::core::Result<()> {
    // SAFETY: opened and closed on this thread.
    unsafe { OpenClipboard(None)? };
    let result = (|| {
        unsafe { EmptyClipboard()? };
        set_clipboard(CF_HDROP.0 as u32, &dropfiles(paths))?;
        // Pasting in Explorer copies rather than moves.
        let effect = unsafe { RegisterClipboardFormatW(w!("Preferred DropEffect")) };
        set_clipboard(effect, &DROPEFFECT_COPY.0.to_le_bytes())
    })();
    let _ = unsafe { CloseClipboard() };
    result
}

pub async fn copy(_: &AppHandle, paths: Vec<PathBuf>) -> CmdResult<()> {
    tauri::async_runtime::spawn_blocking(move || copy_files(&paths))
        .await
        .map_err(|e| share_error(e.to_string()))?
        .map_err(|e| share_error(e.message()))
}
