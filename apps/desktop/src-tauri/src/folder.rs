//! `verify_folder`: the signatures of every PDF in a folder, each result
//! sent to the window as it comes; the last check is kept for
//! `export_folder_report` and `export_folder_csv`.

use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::Serialize;
use tauri::ipc::Channel;
use tauri::{AppHandle, Manager};
use trackmysign_core::folder::{
    FileResult, FileStatus, FolderReport, Options, Progress, relative, verify_folder as check,
};

use super::{CmdResult, CommandError};

#[derive(Default)]
pub struct FolderState {
    last: Mutex<Option<FolderReport>>,
    stop: AtomicBool,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FileDto {
    path: String,
    relative: String,
    size: Option<usize>,
    /// "allValid" | "invalid" | "changed" | "unsigned" | "unreadable" | "password"
    status: &'static str,
    signatures: usize,
    signers: Vec<String>,
    error: Option<String>,
    /// The single-file summary line, when the file could be checked.
    summary: Option<String>,
    /// Opened only with the password given for the folder.
    used_password: bool,
}

impl From<&FileResult> for FileDto {
    fn from(f: &FileResult) -> Self {
        FileDto {
            path: f.path.to_string_lossy().into_owned(),
            relative: f.relative.clone(),
            size: f.size,
            status: match f.status {
                FileStatus::AllValid => "allValid",
                FileStatus::SomeInvalid => "invalid",
                FileStatus::ContentChanged => "changed",
                FileStatus::Unsigned => "unsigned",
                FileStatus::Unreadable => "unreadable",
                FileStatus::NeedsPassword => "password",
            },
            signatures: f.signatures().len(),
            signers: f.signers(),
            error: f.error.clone(),
            summary: f.report.as_ref().map(|r| r.summary()),
            used_password: f.used_password,
        }
    }
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase", tag = "state")]
pub enum FolderProgress {
    /// The PDFs to check, relative to the folder, before the first is checked.
    Found {
        files: Vec<String>,
    },
    Checked {
        index: usize,
        file: FileDto,
    },
}

fn other(message: String) -> CommandError {
    CommandError {
        kind: "other",
        message,
    }
}

/// Checks every PDF in `folder`; returns whether it was stopped early.
#[tauri::command]
pub async fn verify_folder(
    app: AppHandle,
    folder: String,
    recursive: bool,
    password: Option<String>,
    progress: Channel<FolderProgress>,
) -> CmdResult<bool> {
    let version = app.package_info().version.to_string();
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<FolderState>();
        state.stop.store(false, Ordering::Relaxed);
        let root = Path::new(&folder);
        let options = Options {
            recursive,
            password: password.filter(|p| !p.is_empty()),
        };
        let report = check(root, &options, &version, &state.stop, |p| {
            let _ = progress.send(match p {
                Progress::Found(paths) => FolderProgress::Found {
                    files: paths.iter().map(|p| relative(root, p)).collect(),
                },
                Progress::Checked(index, f) => FolderProgress::Checked {
                    index,
                    file: f.into(),
                },
            });
        })?;
        let stopped = report.stopped;
        *state.last.lock().unwrap_or_else(|p| p.into_inner()) = Some(report);
        Ok(stopped)
    })
    .await
    .map_err(|e| other(e.to_string()))?
}

/// Ends the running check after the files under way.
#[tauri::command]
pub fn stop_folder_verify(app: AppHandle) {
    app.state::<FolderState>()
        .stop
        .store(true, Ordering::Relaxed);
}

fn write_last(
    app: &AppHandle,
    output: &str,
    contents: impl FnOnce(&FolderReport) -> Vec<u8>,
) -> CmdResult<()> {
    let state = app.state::<FolderState>();
    let last = state.last.lock().unwrap_or_else(|p| p.into_inner());
    let report = last
        .as_ref()
        .ok_or_else(|| other("No folder has been checked yet.".into()))?;
    std::fs::write(output, contents(report))?;
    Ok(())
}

/// The last folder check as one PDF report.
#[tauri::command]
pub fn export_folder_report(app: AppHandle, output: String) -> CmdResult<()> {
    write_last(&app, &output, FolderReport::to_pdf)
}

/// The last folder check as CSV, one row per signature.
#[tauri::command]
pub fn export_folder_csv(app: AppHandle, output: String) -> CmdResult<()> {
    write_last(&app, &output, |r| r.to_csv().into_bytes())
}
