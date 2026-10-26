//! macOS: the Compose Email sharing service (Mail through AppleScript when it
//! cannot), the share menu (`NSSharingServicePicker`: Mail, Messages,
//! AirDrop, WhatsApp, …) and file URLs on the general pasteboard. AppKit
//! wants all of it on the main thread.

use std::cell::RefCell;
use std::path::PathBuf;
use std::process::Command;

use objc2::rc::Retained;
use objc2::runtime::{AnyObject, ProtocolObject};
use objc2::{AnyThread, MainThreadMarker};
use objc2_app_kit::{
    NSPasteboard, NSPasteboardWriting, NSSharingService, NSSharingServiceNameComposeEmail,
    NSSharingServicePicker, NSView,
};
use objc2_foundation::{NSArray, NSPoint, NSRect, NSRectEdge, NSSize, NSString, NSURL};
use tauri::{AppHandle, Manager, WebviewWindow};

use super::{Abilities, Anchor, Message, mail_script, on_main, share_error};
use crate::CmdResult;

pub fn abilities() -> Abilities {
    Abilities {
        email: true,
        share: true,
        copy: true,
    }
}

fn file_urls(paths: &[PathBuf]) -> Vec<Retained<NSURL>> {
    paths
        .iter()
        .map(|p| NSURL::fileURLWithPath(&NSString::from_str(&p.to_string_lossy())))
        .collect()
}

fn objects(urls: Vec<Retained<NSURL>>) -> Vec<Retained<AnyObject>> {
    urls.into_iter()
        .map(|u| Retained::into_super(Retained::into_super(u)))
        .collect()
}

/// The Compose Email service of the default mail app; false when there is
/// none that takes the files.
fn compose(message: &Message, paths: &[PathBuf]) -> bool {
    // SAFETY: an AppKit constant.
    let name = unsafe { NSSharingServiceNameComposeEmail };
    let Some(service) = NSSharingService::sharingServiceNamed(name) else {
        return false;
    };
    service.setSubject(Some(&NSString::from_str(&message.subject)));
    let mut items: Vec<Retained<AnyObject>> = vec![Retained::into_super(Retained::into_super(
        NSString::from_str(&message.body),
    ))];
    items.extend(objects(file_urls(paths)));
    let items = NSArray::from_retained_slice(&items);
    // SAFETY: strings and file URLs, which the service takes.
    unsafe {
        if !service.canPerformWithItems(Some(&items)) {
            return false;
        }
        service.performWithItems(&items);
    }
    true
}

pub async fn email(
    window: &WebviewWindow,
    message: &Message,
    paths: &[PathBuf],
) -> CmdResult<bool> {
    let (m, p) = (message.clone(), paths.to_vec());
    if on_main(window.app_handle(), move || Ok(compose(&m, &p))).await? {
        return Ok(true);
    }
    let script = mail_script(message, paths);
    let status = tauri::async_runtime::spawn_blocking(move || {
        Command::new("osascript").arg("-e").arg(script).status()
    })
    .await
    .map_err(|e| share_error(e.to_string()))?;
    Ok(status.is_ok_and(|s| s.success()))
}

thread_local! {
    /// The picker on screen; AppKit does not keep it alive by itself.
    static PICKER: RefCell<Option<Retained<NSSharingServicePicker>>> = const { RefCell::new(None) };
}

pub async fn share(
    window: &WebviewWindow,
    paths: Vec<PathBuf>,
    anchor: Option<Anchor>,
) -> CmdResult<()> {
    let view = window.ns_view().map_err(|e| share_error(e.to_string()))? as usize;
    on_main(window.app_handle(), move || {
        MainThreadMarker::new().ok_or_else(|| share_error("Not on the main thread."))?;
        // SAFETY: the window's content view, which lives as long as the
        // window, used on the main thread.
        let view = unsafe { &*(view as *const NSView) };
        let items = NSArray::from_retained_slice(&objects(file_urls(&paths)));
        // SAFETY: file URLs, which the picker takes.
        let picker = unsafe {
            NSSharingServicePicker::initWithItems(NSSharingServicePicker::alloc(), &items)
        };
        // The web page's coordinates start at the top left.
        let bounds = view.bounds();
        let a = anchor.unwrap_or(Anchor {
            x: bounds.size.width / 2.0,
            y: bounds.size.height / 2.0,
            width: 1.0,
            height: 1.0,
        });
        let flipped = view.isFlipped();
        let y = if flipped {
            a.y
        } else {
            bounds.size.height - a.y - a.height
        };
        let rect = NSRect::new(NSPoint::new(a.x, y), NSSize::new(a.width, a.height));
        // Above the button: the buttons sit at the bottom of the dialogs.
        let edge = if flipped {
            NSRectEdge::MinY
        } else {
            NSRectEdge::MaxY
        };
        picker.showRelativeToRect_ofView_preferredEdge(rect, view, edge);
        PICKER.with(|p| p.replace(Some(picker)));
        Ok(())
    })
    .await
}

pub async fn copy(app: &AppHandle, paths: Vec<PathBuf>) -> CmdResult<()> {
    on_main(app, move || {
        let urls: Vec<Retained<ProtocolObject<dyn NSPasteboardWriting>>> = file_urls(&paths)
            .into_iter()
            .map(ProtocolObject::from_retained)
            .collect();
        let pasteboard = NSPasteboard::generalPasteboard();
        pasteboard.clearContents();
        if pasteboard.writeObjects(&NSArray::from_retained_slice(&urls)) {
            Ok(())
        } else {
            Err(share_error("The clipboard did not take the file."))
        }
    })
    .await
}
