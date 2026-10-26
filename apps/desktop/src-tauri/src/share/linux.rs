//! Linux: `xdg-email` for the email, the GTK clipboard for the files. There
//! is no system share sheet.

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use gtk::gdk::SELECTION_CLIPBOARD;
use gtk::{Clipboard, TargetEntry, TargetFlags};
use tauri::{AppHandle, WebviewWindow};

use super::{Abilities, Anchor, Message, on_main, share_error, uri_list};
use crate::CmdResult;

fn xdg_email() -> bool {
    std::env::var_os("PATH")
        .is_some_and(|path| std::env::split_paths(&path).any(|d| d.join("xdg-email").is_file()))
}

pub fn abilities() -> Abilities {
    Abilities {
        email: xdg_email(),
        share: false,
        copy: true,
    }
}

/// `xdg-email` opens the default mail program's new message; whether the
/// attachment arrives depends on the program (Thunderbird and Evolution take
/// it). False when it could not run or failed. A mail program it starts may
/// keep it until the program quits, so after a while it counts as done.
pub async fn email(_: &WebviewWindow, message: &Message, paths: &[PathBuf]) -> CmdResult<bool> {
    let mut cmd = Command::new("xdg-email");
    cmd.args([
        "--utf8",
        "--subject",
        &message.subject,
        "--body",
        &message.body,
    ]);
    for p in paths {
        cmd.arg("--attach").arg(p);
    }
    tauri::async_runtime::spawn_blocking(move || {
        let Ok(mut child) = cmd.spawn() else {
            return false;
        };
        let started = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return status.success(),
                Ok(None) if started.elapsed() < Duration::from_secs(10) => {
                    std::thread::sleep(Duration::from_millis(100));
                }
                // Reaped in the background once the mail program lets go.
                Ok(None) => {
                    std::thread::spawn(move || child.wait());
                    return true;
                }
                Err(_) => return false,
            }
        }
    })
    .await
    .map_err(|e| share_error(e.to_string()))
}

pub async fn share(_: &WebviewWindow, _: Vec<PathBuf>, _: Option<Anchor>) -> CmdResult<()> {
    Err(share_error("Sharing is not available on Linux."))
}

/// Offered as `text/uri-list` (most programs) and as GNOME's copied files
/// (Files pastes them as a copy).
pub async fn copy(app: &AppHandle, paths: Vec<PathBuf>) -> CmdResult<()> {
    let uris = uri_list(&paths);
    let gnome = format!("copy\n{}", uris.trim_end().replace("\r\n", "\n"));
    on_main(app, move || {
        let targets = [
            TargetEntry::new("text/uri-list", TargetFlags::empty(), 0),
            TargetEntry::new("x-special/gnome-copied-files", TargetFlags::empty(), 1),
        ];
        let set =
            Clipboard::get(&SELECTION_CLIPBOARD).set_with_data(&targets, move |_, data, info| {
                let bytes = if info == 0 {
                    uris.as_bytes()
                } else {
                    gnome.as_bytes()
                };
                data.set(&data.target(), 8, bytes);
            });
        if set {
            Ok(())
        } else {
            Err(share_error("The clipboard did not take the file."))
        }
    })
    .await
}
