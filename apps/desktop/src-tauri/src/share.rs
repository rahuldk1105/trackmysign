//! Passing a signed copy on: a new email with it attached, the system share
//! sheet (Windows Share, macOS share menu), or the file on the clipboard to
//! paste into a chat or a mail.
//!
//! Attachments cannot go through a `mailto:` link, so the email uses what each
//! system has for it: Simple MAPI on Windows, the Compose Email service on
//! macOS, `xdg-email` on Linux. Where that fails, the folder opens with the
//! file selected next to a `mailto:` message to attach it to by hand.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, WebviewWindow};

use super::{CmdResult, CommandError};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "linux")]
use linux as os;
#[cfg(target_os = "macos")]
use macos as os;
#[cfg(windows)]
use windows as os;

/// What this computer offers; the buttons for the rest are not shown.
#[derive(Serialize, Clone, Copy, Default)]
pub struct Abilities {
    email: bool,
    share: bool,
    copy: bool,
}

/// How the email went.
#[derive(Serialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum Mailed {
    /// A new message with the files attached is open in the mail app.
    Composed,
    /// The folder is open with the file selected, next to a new message
    /// without attachment.
    AttachByHand,
}

/// Where the button is in the window, for the share menu to point at
/// (macOS; Windows places its Share window itself).
#[derive(Deserialize, Clone, Copy, Debug)]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub struct Anchor {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

/// Subject and body of the new message.
#[derive(Clone)]
pub struct Message {
    pub subject: String,
    pub body: String,
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string_lossy().into_owned())
}

impl Message {
    pub fn for_files(paths: &[PathBuf]) -> Self {
        let names: Vec<String> = paths.iter().map(|p| file_name(p)).collect();
        match names.as_slice() {
            [one] => Message {
                subject: format!("Signed: {one}"),
                body: format!("Please find the signed document attached: {one}\n"),
            },
            [first, rest @ ..] => Message {
                subject: format!("Signed: {first} and {} more", rest.len()),
                body: format!(
                    "Please find the signed documents attached:\n{}\n",
                    names.join("\n")
                ),
            },
            [] => Message {
                subject: "Signed document".into(),
                body: String::new(),
            },
        }
    }
}

/// `mailto:` with only a subject and body (RFC 6068): everything but the
/// unreserved characters percent-encoded, line breaks as CRLF.
pub fn mailto(message: &Message) -> String {
    fn enc(s: &str) -> String {
        let crlf = s.replace("\r\n", "\n").replace('\n', "\r\n");
        let mut out = String::new();
        for b in crlf.bytes() {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                out.push(b as char);
            } else {
                out.push_str(&format!("%{b:02X}"));
            }
        }
        out
    }
    format!(
        "mailto:?subject={}&body={}",
        enc(&message.subject),
        enc(&message.body)
    )
}

#[cfg(any(windows, test))]
/// The clipboard's file list on Windows (`CF_HDROP`): a `DROPFILES` header
/// with wide names, then the paths in UTF-16, each ending in a NUL, and one
/// more NUL after the last.
pub fn dropfiles(paths: &[PathBuf]) -> Vec<u8> {
    const HEADER: u32 = 20;
    let mut out = Vec::new();
    out.extend_from_slice(&HEADER.to_le_bytes()); // pFiles
    out.extend_from_slice(&0i32.to_le_bytes()); // pt.x
    out.extend_from_slice(&0i32.to_le_bytes()); // pt.y
    out.extend_from_slice(&0i32.to_le_bytes()); // fNC
    out.extend_from_slice(&1i32.to_le_bytes()); // fWide
    for p in paths {
        for unit in p.to_string_lossy().encode_utf16().chain([0]) {
            out.extend_from_slice(&unit.to_le_bytes());
        }
    }
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

#[cfg(any(target_os = "linux", all(test, unix)))]
/// `text/uri-list`: one `file://` URI per line, CRLF after each.
pub fn uri_list(paths: &[PathBuf]) -> String {
    paths
        .iter()
        .filter_map(|p| tauri::Url::from_file_path(p).ok())
        .map(|u| format!("{u}\r\n"))
        .collect()
}

#[cfg(any(target_os = "macos", test))]
/// A string literal for AppleScript.
pub fn applescript_string(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(any(target_os = "macos", test))]
/// A new visible Mail message with the files attached.
pub fn mail_script(message: &Message, paths: &[PathBuf]) -> String {
    let mut script = format!(
        "tell application \"Mail\"\n\
         set m to make new outgoing message with properties {{subject:{}, content:{}, visible:true}}\n\
         tell content of m\n",
        applescript_string(&message.subject),
        applescript_string(&message.body),
    );
    for p in paths {
        script.push_str(&format!(
            "make new attachment with properties {{file name:(POSIX file {})}} at after last paragraph\n",
            applescript_string(&p.to_string_lossy())
        ));
    }
    script.push_str("end tell\nactivate\nend tell\n");
    script
}

fn share_error(message: impl Into<String>) -> CommandError {
    CommandError {
        kind: "share",
        message: message.into(),
    }
}

/// The paths, each of which must still be there.
fn existing(paths: Vec<String>) -> CmdResult<Vec<PathBuf>> {
    if paths.is_empty() {
        return Err(share_error("No file to share."));
    }
    paths
        .into_iter()
        .map(PathBuf::from)
        .map(|p| {
            if p.is_file() {
                Ok(p)
            } else {
                Err(share_error(format!(
                    "The signed copy is no longer at {}.",
                    p.display()
                )))
            }
        })
        .collect()
}

/// Opens the folder with the first file selected and a new message without
/// attachment, when the mail app cannot take one.
fn attach_by_hand(message: &Message, paths: &[PathBuf]) -> CmdResult<Mailed> {
    let io = |e: tauri_plugin_opener::Error| share_error(e.to_string());
    tauri_plugin_opener::reveal_item_in_dir(&paths[0]).map_err(io)?;
    tauri_plugin_opener::open_url(mailto(message), None::<&str>).map_err(io)?;
    Ok(Mailed::AttachByHand)
}

#[tauri::command]
pub async fn share_abilities() -> Abilities {
    tauri::async_runtime::spawn_blocking(os::abilities)
        .await
        .unwrap_or_default()
}

/// A new message in the default mail app with `paths` attached.
#[tauri::command]
pub async fn share_email(window: WebviewWindow, paths: Vec<String>) -> CmdResult<Mailed> {
    let paths = existing(paths)?;
    let message = Message::for_files(&paths);
    if os::email(&window, &message, &paths).await? {
        Ok(Mailed::Composed)
    } else {
        attach_by_hand(&message, &paths)
    }
}

/// The system share sheet for `paths`, pointing at `anchor`.
#[tauri::command]
pub async fn share_sheet(
    window: WebviewWindow,
    paths: Vec<String>,
    anchor: Option<Anchor>,
) -> CmdResult<()> {
    let paths = existing(paths)?;
    os::share(&window, paths, anchor).await
}

/// Puts `paths` on the clipboard as files.
#[tauri::command]
pub async fn share_copy(app: AppHandle, paths: Vec<String>) -> CmdResult<()> {
    let paths = existing(paths)?;
    os::copy(&app, paths).await
}

/// Runs `f` on the main thread (where the window's UI lives) and waits for it.
async fn on_main<T: Send + 'static>(
    app: &AppHandle,
    f: impl FnOnce() -> CmdResult<T> + Send + 'static,
) -> CmdResult<T> {
    let (tx, rx) = std::sync::mpsc::channel();
    app.run_on_main_thread(move || {
        let _ = tx.send(f());
    })
    .map_err(|e| share_error(e.to_string()))?;
    tauri::async_runtime::spawn_blocking(move || rx.recv())
        .await
        .map_err(|e| share_error(e.to_string()))?
        .map_err(|e| share_error(e.to_string()))?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(names: &[&str]) -> Vec<PathBuf> {
        names.iter().map(PathBuf::from).collect()
    }

    #[test]
    fn message_for_one_file() {
        let m = Message::for_files(&paths(&["/docs/Invoice 12_signed.pdf"]));
        assert_eq!(m.subject, "Signed: Invoice 12_signed.pdf");
        assert_eq!(
            m.body,
            "Please find the signed document attached: Invoice 12_signed.pdf\n"
        );
    }

    #[test]
    fn message_for_several_files() {
        let m = Message::for_files(&paths(&["/a/x_signed.pdf", "/b/y_signed.pdf", "/c/z.pdf"]));
        assert_eq!(m.subject, "Signed: x_signed.pdf and 2 more");
        assert_eq!(
            m.body,
            "Please find the signed documents attached:\nx_signed.pdf\ny_signed.pdf\nz.pdf\n"
        );
    }

    #[test]
    fn mailto_encodes_everything_but_unreserved() {
        let m = Message {
            subject: "Signed: a&b=c?.pdf".into(),
            body: "line 1\nलाइन 2".into(),
        };
        assert_eq!(
            mailto(&m),
            "mailto:?subject=Signed%3A%20a%26b%3Dc%3F.pdf\
             &body=line%201%0D%0A%E0%A4%B2%E0%A4%BE%E0%A4%87%E0%A4%A8%202"
        );
    }

    #[test]
    fn dropfiles_layout() {
        let data = dropfiles(&paths(&["C:\\a.pdf", "D:\\ü.pdf"]));
        assert_eq!(&data[..4], &20u32.to_le_bytes());
        assert_eq!(&data[16..20], &1i32.to_le_bytes());
        let units: Vec<u16> = data[20..]
            .chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let expected: Vec<u16> = "C:\\a.pdf\0D:\\ü.pdf\0\0".encode_utf16().collect();
        assert_eq!(units, expected);
    }

    #[cfg(unix)]
    #[test]
    fn uri_list_percent_encodes() {
        let list = uri_list(&paths(&["/home/r/My Docs/क_signed.pdf", "/tmp/a#b.pdf"]));
        assert_eq!(
            list,
            "file:///home/r/My%20Docs/%E0%A4%95_signed.pdf\r\nfile:///tmp/a%23b.pdf\r\n"
        );
    }

    #[test]
    fn applescript_quoting() {
        assert_eq!(applescript_string("plain"), "\"plain\"");
        assert_eq!(
            applescript_string(r#"say "hi" \ bye"#),
            r#""say \"hi\" \\ bye""#
        );
    }

    #[test]
    fn mail_script_attaches_each_file() {
        let files = paths(&["/Users/r/a \"q\".pdf", "/Users/r/b.pdf"]);
        let script = mail_script(&Message::for_files(&files), &files);
        assert!(script.contains("subject:\"Signed: a \\\"q\\\".pdf and 1 more\""));
        assert!(script.contains("(POSIX file \"/Users/r/a \\\"q\\\".pdf\")"));
        assert!(script.contains("(POSIX file \"/Users/r/b.pdf\")"));
        assert!(script.ends_with("activate\nend tell\n"));
    }

    #[test]
    fn missing_file_is_an_error() {
        let err = existing(vec!["/no/such/file_signed.pdf".into()]).unwrap_err();
        assert_eq!(err.kind, "share");
        assert!(existing(vec![]).is_err());
    }
}
