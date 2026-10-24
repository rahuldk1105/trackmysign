//! Running in the background: a tray (menu bar) icon, closing the window
//! hides it, and an optional start at sign-in, so the GST portal can ask for
//! signatures without the app being opened first. While a watch folder is
//! signing, the tray shows that too (also without background mode) and can
//! stop it.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::TrayIconBuilder;
#[cfg(not(target_os = "macos"))]
use tauri::tray::{MouseButton, MouseButtonState, TrayIconEvent};
use tauri::{AppHandle, Manager, Window, WindowEvent, Wry};
use tauri_plugin_autostart::ManagerExt;

use super::{CmdResult, CommandError, portal, watch};

/// Passed by the sign-in entry: start in the tray, without a window.
pub const ARG: &str = "--background";

const TRAY: &str = "main";

fn other(message: impl Into<String>) -> CommandError {
    CommandError {
        kind: "other",
        message: message.into(),
    }
}

/// Saved in the app's data folder.
#[derive(Serialize, Deserialize, Default, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
struct Settings {
    /// Unset: on while GST portal signing is.
    enabled: Option<bool>,
}

impl Settings {
    fn keeps_running(&self, portal_enabled: bool) -> bool {
        self.enabled.unwrap_or(portal_enabled)
    }
}

#[derive(Default)]
pub struct BackgroundState {
    /// Closing the window hides it; read on every close.
    active: AtomicBool,
}

/// Started by the sign-in entry.
pub fn launched_hidden<S: AsRef<str>>(args: impl IntoIterator<Item = S>) -> bool {
    args.into_iter().skip(1).any(|a| a.as_ref() == ARG)
}

fn path(app: &AppHandle) -> CmdResult<PathBuf> {
    let dir = app.path().app_data_dir().map_err(|e| CommandError {
        kind: "io",
        message: e.to_string(),
    })?;
    Ok(dir.join("background.json"))
}

fn load_settings(path: &Path) -> Settings {
    std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn save_settings(path: &Path, s: &Settings) -> CmdResult<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let json = serde_json::to_vec_pretty(s).map_err(|e| other(e.to_string()))?;
    std::fs::write(path, json)?;
    Ok(())
}

fn keeps_running(app: &AppHandle) -> bool {
    let Ok(path) = path(app) else { return false };
    load_settings(&path).keeps_running(portal::summary(app).0)
}

fn portal_label(enabled: bool, port: Option<u16>) -> String {
    match (enabled, port) {
        (false, _) => "GST portal signing: Off".into(),
        (true, Some(port)) => format!("GST portal signing: On (port {port})"),
        (true, None) => "GST portal signing: Not running".into(),
    }
}

/// Puts the tray and the sign-in entry in line with the settings, and the
/// status lines with the portal listener and the watch folder. Call after
/// any of them changes.
pub fn sync(app: &AppHandle) {
    let (tx, rx) = std::sync::mpsc::channel();
    let handle = app.clone();
    // Tray and menu live on the main thread; doing all of it there also
    // keeps two calls from racing.
    let sent = app.run_on_main_thread(move || {
        apply(&handle);
        let _ = tx.send(());
    });
    if sent.is_ok() {
        let _ = rx.recv();
    }
}

fn apply(app: &AppHandle) {
    let on = keeps_running(app);
    let state = app.state::<BackgroundState>();
    state.active.store(on, Ordering::SeqCst);
    if !on {
        let _ = app.autolaunch().disable();
        set_dock(app, true);
    }
    let watching = watch::tray_line(app);
    if !on && watching.is_none() {
        let _ = app.remove_tray_by_id(TRAY);
        return;
    }
    let (enabled, port) = portal::summary(app);
    let tooltip = match &watching {
        Some(line) => format!("TrackMySign — {line}"),
        None => "TrackMySign".into(),
    };
    let Ok(menu) = tray_menu(app, &portal_label(enabled, port), watching.as_deref()) else {
        return;
    };
    match app.tray_by_id(TRAY) {
        Some(tray) => {
            let _ = tray.set_menu(Some(menu));
            let _ = tray.set_tooltip(Some(tooltip));
        }
        None => {
            let _ = add_tray(app, menu, &tooltip);
        }
    }
}

fn tray_menu(app: &AppHandle, portal: &str, watching: Option<&str>) -> tauri::Result<Menu<Wry>> {
    let menu = Menu::with_items(
        app,
        &[
            &MenuItem::with_id(app, "open", "Open TrackMySign", true, None::<&str>)?,
            &MenuItem::with_id(app, "portal", portal, false, None::<&str>)?,
        ],
    )?;
    if let Some(line) = watching {
        menu.append(&MenuItem::with_id(app, "watch", line, false, None::<&str>)?)?;
        menu.append(&MenuItem::with_id(
            app,
            "stop-watch",
            "Stop watching",
            true,
            None::<&str>,
        )?)?;
    }
    menu.append(&PredefinedMenuItem::separator(app)?)?;
    menu.append(&MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?)?;
    Ok(menu)
}

fn add_tray(app: &AppHandle, menu: Menu<Wry>, tooltip: &str) -> tauri::Result<()> {
    let builder = TrayIconBuilder::with_id(TRAY)
        .tooltip(tooltip)
        .menu(&menu)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open" => show(app),
            "stop-watch" => watch::stop(app),
            "quit" => app.exit(0),
            _ => {}
        });
    // macOS draws a template image in the menu bar's colour.
    #[cfg(target_os = "macos")]
    let builder = builder
        .icon(tauri::image::Image::from_bytes(include_bytes!(
            "../icons/tray-template.png"
        ))?)
        .icon_as_template(true);
    // Windows: a left click opens the window, the right click shows the menu.
    #[cfg(not(target_os = "macos"))]
    let builder = {
        let builder = builder
            .show_menu_on_left_click(false)
            .on_tray_icon_event(|tray, event| {
                if let TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                } = event
                {
                    show(tray.app_handle());
                }
            });
        match app.default_window_icon() {
            Some(icon) => builder.icon(icon.clone()),
            None => builder,
        }
    };
    builder.build(app)?;
    Ok(())
}

/// macOS: a Dock icon only while the window is shown.
#[cfg_attr(not(target_os = "macos"), allow(unused_variables))]
fn set_dock(app: &AppHandle, visible: bool) {
    #[cfg(target_os = "macos")]
    let _ = app.set_activation_policy(if visible {
        tauri::ActivationPolicy::Regular
    } else {
        tauri::ActivationPolicy::Accessory
    });
}

/// Call before showing the window from the background.
pub fn showing(app: &AppHandle) {
    set_dock(app, true);
}

/// Brings the window back: tray, a second launch, a file handed over.
pub fn show(app: &AppHandle) {
    showing(app);
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

/// At launch: the window (hidden in tauri.conf.json, so a start at sign-in
/// does not flash it) is shown unless started in the background.
pub fn start(app: &AppHandle, hidden: bool) {
    sync(app);
    if hidden && app.state::<BackgroundState>().active.load(Ordering::SeqCst) {
        set_dock(app, false);
    } else if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
    }
}

/// Closing the window only hides it while the app keeps running.
pub fn on_window_event(window: &Window, event: &WindowEvent) {
    let WindowEvent::CloseRequested { api, .. } = event else {
        return;
    };
    let app = window.app_handle();
    if window.label() != "main" || !app.state::<BackgroundState>().active.load(Ordering::SeqCst) {
        return;
    }
    api.prevent_close();
    let _ = window.hide();
    set_dock(app, false);
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusDto {
    enabled: bool,
    /// Starts at sign-in, in the tray.
    autostart: bool,
}

fn status(app: &AppHandle) -> StatusDto {
    StatusDto {
        enabled: keeps_running(app),
        autostart: app.autolaunch().is_enabled().unwrap_or(false),
    }
}

#[tauri::command]
pub async fn background_status(app: AppHandle) -> StatusDto {
    status(&app)
}

/// Turning it off also removes the sign-in entry.
#[tauri::command]
pub async fn background_set(app: AppHandle, enabled: bool) -> CmdResult<StatusDto> {
    let path = path(&app)?;
    save_settings(
        &path,
        &Settings {
            enabled: Some(enabled),
        },
    )?;
    sync(&app);
    Ok(status(&app))
}

/// Adds or removes the sign-in entry (Windows: the Run key; macOS: a
/// LaunchAgent), which starts the app with [`ARG`].
#[tauri::command]
pub async fn background_set_autostart(app: AppHandle, enabled: bool) -> CmdResult<StatusDto> {
    let autolaunch = app.autolaunch();
    if !enabled {
        autolaunch.disable().map_err(|e| other(e.to_string()))?;
    } else if keeps_running(&app) {
        autolaunch.enable().map_err(|e| other(e.to_string()))?;
    } else {
        return Err(other("Turn on “Keep running in the background” first."));
    }
    Ok(status(&app))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn background_argument() {
        assert!(launched_hidden(["TrackMySign.exe", "--background"]));
        assert!(launched_hidden(["TrackMySign", "a.pdf", "--background"]));
        assert!(!launched_hidden(["TrackMySign.exe"]));
        assert!(!launched_hidden(["TrackMySign.exe", "C:\\docs\\a.pdf"]));
        // The program path itself is not an argument.
        assert!(!launched_hidden(["--background"]));
        assert!(!launched_hidden(["TrackMySign", "--background=1"]));
    }

    #[test]
    fn default_follows_portal_signing() {
        let unset = Settings::default();
        assert!(unset.keeps_running(true));
        assert!(!unset.keeps_running(false));
        let off = Settings {
            enabled: Some(false),
        };
        assert!(!off.keeps_running(true));
        let on = Settings {
            enabled: Some(true),
        };
        assert!(on.keeps_running(false));
    }

    #[test]
    fn settings_round_trip() {
        let dir = std::env::temp_dir().join(format!("tms-bg-{}", std::process::id()));
        let path = dir.join("background.json");
        assert_eq!(load_settings(&path), Settings::default());
        let on = Settings {
            enabled: Some(true),
        };
        assert!(save_settings(&path, &on).is_ok());
        assert_eq!(load_settings(&path), on);
        std::fs::write(&path, b"{not json").unwrap();
        assert_eq!(load_settings(&path), Settings::default());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn tray_portal_line() {
        assert_eq!(portal_label(false, None), "GST portal signing: Off");
        assert_eq!(portal_label(false, Some(1585)), "GST portal signing: Off");
        assert_eq!(
            portal_label(true, Some(2095)),
            "GST portal signing: On (port 2095)"
        );
        assert_eq!(portal_label(true, None), "GST portal signing: Not running");
    }
}
