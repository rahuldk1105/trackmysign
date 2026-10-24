//! Signing history: every signature the app makes (single, batch, watch
//! folder, GST portal) goes into the log in the app's data folder, which the
//! command line writes to as well (`trackmysign_core::history`). The History
//! view lists, checks and exports it.

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};
use trackmysign_core::history::{self, Entry, History, Integrity, Settings};

use super::{CmdResult, CommandError};

/// How entries made here name the program.
pub const PROGRAM: &str = concat!("desktop ", env!("CARGO_PKG_VERSION"));

fn io_error(e: impl ToString) -> CommandError {
    CommandError {
        kind: "io",
        message: e.to_string(),
    }
}

fn store(app: &AppHandle) -> CmdResult<History> {
    let dir = app.path().app_data_dir().map_err(io_error)?;
    Ok(History::in_app_data(&dir))
}

/// Adds `entry` unless the history is turned off. A history that cannot be
/// written never stops signing.
pub fn record(app: &AppHandle, entry: Entry) {
    match store(app).map(|h| h.record(entry)) {
        Ok(Ok(true)) => {
            let _ = app.emit("history-changed", ());
        }
        Ok(Ok(false)) => {}
        Ok(Err(e)) => eprintln!("signing history: {e}"),
        Err(e) => eprintln!("signing history: {}", e.message),
    }
}

/// Deletes months past the retention period, at start.
pub fn start(app: &AppHandle) {
    let app = app.clone();
    std::thread::spawn(move || {
        if let Ok(h) = store(&app) {
            let _ = h.apply_retention(PROGRAM);
        }
    });
}

/// Every entry, oldest first.
#[tauri::command]
pub async fn history_entries(app: AppHandle) -> CmdResult<Vec<Entry>> {
    tauri::async_runtime::spawn_blocking(move || store(&app)?.entries().map_err(io_error))
        .await
        .map_err(io_error)?
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsDto {
    #[serde(flatten)]
    settings: Settings,
    /// Where the files are, for the privacy note.
    folder: String,
}

fn settings_dto(h: &History) -> SettingsDto {
    SettingsDto {
        settings: h.settings(),
        folder: h.dir().to_string_lossy().into_owned(),
    }
}

#[tauri::command]
pub fn history_settings(app: AppHandle) -> CmdResult<SettingsDto> {
    Ok(settings_dto(&store(&app)?))
}

#[tauri::command]
pub fn history_set_settings(app: AppHandle, settings: Settings) -> CmdResult<SettingsDto> {
    let h = store(&app)?;
    h.set_settings(settings, PROGRAM).map_err(io_error)?;
    let _ = app.emit("history-changed", ());
    Ok(settings_dto(&h))
}

/// Follows the hash chain through every file.
#[tauri::command]
pub async fn history_check(app: AppHandle) -> CmdResult<Integrity> {
    tauri::async_runtime::spawn_blocking(move || store(&app)?.check().map_err(io_error))
        .await
        .map_err(io_error)?
}

/// Deletes every entry; one entry saying so is left.
#[tauri::command]
pub fn history_clear(app: AppHandle) -> CmdResult<()> {
    store(&app)?.clear(PROGRAM).map_err(io_error)?;
    let _ = app.emit("history-changed", ());
    Ok(())
}

/// Writes the entries numbered `seqs` (the ones the view shows) to
/// `output`: the PDF, with the integrity check, or the CSV.
#[tauri::command]
pub async fn history_export(
    app: AppHandle,
    output: String,
    format: String,
    seqs: Vec<u64>,
) -> CmdResult<()> {
    tauri::async_runtime::spawn_blocking(move || {
        let h = store(&app)?;
        let entries = h.entries().map_err(io_error)?;
        let shown: Vec<&Entry> = entries.iter().filter(|e| seqs.contains(&e.seq)).collect();
        let data = if format == "csv" {
            history::to_csv(&shown).into_bytes()
        } else {
            let scope = if shown.len() == entries.len() {
                "All entries".to_string()
            } else {
                format!("{} of {} entries (filtered)", shown.len(), entries.len())
            };
            let integrity = h.check().map_err(io_error)?;
            history::to_pdf(
                &shown,
                &scope,
                Some(&integrity),
                env!("CARGO_PKG_VERSION"),
                chrono::Utc::now(),
            )
        };
        std::fs::write(&output, data)?;
        Ok(())
    })
    .await
    .map_err(io_error)?
}
