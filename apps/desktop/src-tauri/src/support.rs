//! Help & support: the support report (`trackmysign_core::support`) put
//! together with what the app knows, for the window to show in full before
//! it is copied or saved, and the log of recent errors it draws on. Nothing
//! is sent anywhere.

use std::path::Path;

use serde::Deserialize;
use tauri::{AppHandle, Manager};
use trackmysign_core::history::{Action, Entry, Outcome, Source};
use trackmysign_core::support::{
    self, AppInfo, Context, Event, EventLog, Include, Redactor, SettingsInfo, SystemInfo,
};
use trackmysign_core::token::installed_drivers;

use super::{CmdResult, CommandError, TOKEN_LOCK, background, portal, watch};

fn io_error(e: impl ToString) -> CommandError {
    CommandError {
        kind: "io",
        message: e.to_string(),
    }
}

fn log(app: &AppHandle) -> CmdResult<EventLog> {
    let dir = app.path().app_data_dir().map_err(io_error)?;
    Ok(EventLog::in_app_data(&dir))
}

fn add(app: &AppHandle, event: Event) {
    if let Ok(log) = log(app)
        && let Err(e) = log.record(event)
    {
        eprintln!("support log: {e}");
    }
}

/// Keeps `e` for the support report; `files` are the documents worked on,
/// which are left out of it.
pub fn record(app: &AppHandle, area: &str, e: &CommandError, files: &[&Path], signing: bool) {
    let chain = [format!("kind: {}", e.kind)];
    add(app, Event::error(area, &e.message, &chain, files, signing));
}

/// A failed signature, as the signing history records it.
pub fn record_failure(app: &AppHandle, entry: &Entry) {
    if entry.outcome != Some(Outcome::Failed) {
        return;
    }
    let area = match (entry.action, entry.source) {
        (Action::SignFile, _) => "sign-file",
        (_, Some(Source::Batch)) => "batch",
        (_, Some(Source::Watch)) => "watch",
        (_, Some(Source::Portal)) => "portal",
        _ => "sign",
    };
    let files: Vec<&Path> = [&entry.input, &entry.output]
        .into_iter()
        .flatten()
        .map(|f| Path::new(&f.path))
        .collect();
    let message = entry.error.as_deref().unwrap_or("Signing failed.");
    add(app, Event::error(area, message, &[], &files, true));
}

/// An error the window showed (an update check, a PDF that would not open).
#[tauri::command]
pub fn support_note(app: AppHandle, area: String, message: String, files: Vec<String>) {
    let area: String = area.chars().take(32).collect();
    let files: Vec<&Path> = files.iter().map(Path::new).collect();
    add(&app, Event::error(&area, &message, &[], &files, false));
}

/// What only the window knows: its own settings, the last update check and
/// the language.
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct ReportArgs {
    include: Include,
    timestamp: bool,
    tsa_url: String,
    ltv: bool,
    out_dir: String,
    auto_update: bool,
    /// The last update check, worded; none in the Store build.
    updater: Option<String>,
    locale: Option<String>,
    language: Option<String>,
}

fn build_name() -> &'static str {
    if cfg!(feature = "store") {
        "desktop (Microsoft Store)"
    } else {
        "desktop"
    }
}

/// The report as it will be shared: Markdown with the data as JSON at the end.
#[tauri::command]
pub async fn support_report(app: AppHandle, args: ReportArgs) -> CmdResult<String> {
    tauri::async_runtime::spawn_blocking(move || {
        let probes = {
            let _guard = TOKEN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
            support::probe(&installed_drivers())
        };
        let dir = app.path().app_data_dir().map_err(io_error)?;
        let include = args.include;
        let (background, autostart) = background::summary(&app);
        let out_dir = args.out_dir.trim().to_string();
        let settings = SettingsInfo {
            timestamp: Some(args.timestamp),
            timestamp_server: Some(support::url_host(&args.tsa_url))
                .filter(|h| args.timestamp && !h.is_empty()),
            ltv: Some(args.ltv),
            background: Some(background),
            start_at_sign_in: Some(autostart),
            watching: Some(watch::watching(&app)),
            signed_copy_folder: Some(!out_dir.is_empty()),
            signed_copy_folder_path: Some(out_dir).filter(|d| include.paths && !d.is_empty()),
            update_check: (!cfg!(feature = "store")).then_some(args.auto_update),
            ..SettingsInfo::from_app_data(&dir, include)
        };
        let ctx = Context {
            app: AppInfo {
                version: env!("CARGO_PKG_VERSION").into(),
                build: build_name().into(),
            },
            system: SystemInfo {
                webview: tauri::webview_version().ok(),
                locale: args.locale,
                language: args.language,
                ..SystemInfo::this_computer()
            },
            settings: Some(settings),
            portal: portal::support_info(&app),
            // The Store updates the app; there is no check of its own.
            updater: args.updater.filter(|_| !cfg!(feature = "store")),
            events: EventLog::in_app_data(&dir).events(),
        };
        let report = support::build(
            ctx,
            &probes,
            include,
            &Redactor::for_user(),
            chrono::Utc::now(),
        );
        Ok(report.to_text())
    })
    .await
    .map_err(io_error)?
}

/// Writes the report the user saw to `path`.
#[tauri::command]
pub fn support_save(path: String, text: String) -> CmdResult<()> {
    std::fs::write(path, text)?;
    Ok(())
}

/// A new issue with the version filled in; the user pastes the report.
#[tauri::command]
pub fn support_open_issue() -> CmdResult<()> {
    let url = support::issue_url(env!("CARGO_PKG_VERSION"));
    tauri_plugin_opener::open_url(url, None::<&str>).map_err(io_error)
}

/// Errors kept for the report, for "Clear" to show a count.
#[tauri::command]
pub fn support_log_count(app: AppHandle) -> CmdResult<usize> {
    Ok(log(&app)?.events().len())
}

#[tauri::command]
pub fn support_clear_log(app: AppHandle) -> CmdResult<()> {
    log(&app)?.clear().map_err(io_error)
}
