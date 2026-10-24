//! Watch folder: PDFs put into a chosen folder are signed while a session
//! is open (`trackmysign_core::watch` does the watching).
//!
//! The settings, with a copy of the preset to sign with, are kept in the
//! app's data folder; the PIN never is. A session starts only when the user
//! enters the PIN; the token then stays logged in (and a PIN for a key that
//! asks on every signature stays in memory) until the session ends: Stop, the
//! time limit, sleep, the daily limit, a token or PIN error, or quitting.
//! A log of the last files (paths and outcome only) is kept for Settings.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager};
use trackmysign_core::token::{Token, TokenSigner};
use trackmysign_core::watch::{self, Control, Event, Folders, ImageChoice, Preset, Stop};
use trackmysign_core::{Error, SignRequest, sign_pdf};
use zeroize::Zeroize;

use super::{CmdResult, CommandError, TOKEN_LOCK, background, not_expired, saved_image};

/// Log entries kept; older ones drop off.
const LOG_CAP: usize = 200;

fn other(message: impl Into<String>) -> CommandError {
    CommandError {
        kind: "other",
        message: message.into(),
    }
}

/// Saved in the app's data folder (`watch.json`).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct Config {
    input: String,
    /// Empty for `<input>/signed`.
    output: String,
    /// Move originals to `<input>/done` once signed.
    move_done: bool,
    /// 0 for no limit.
    daily_limit: usize,
    /// How long a session lasts; 0 until stopped.
    minutes: u64,
    stop_on_sleep: bool,
    /// Copied from the preset chosen in Settings, so later edits there do
    /// not change what is signed here unnoticed.
    preset: Preset,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            input: String::new(),
            output: String::new(),
            move_done: true,
            daily_limit: watch::DEFAULT_DAILY_LIMIT,
            minutes: 60,
            stop_on_sleep: true,
            preset: Preset {
                reason: "Approved".into(),
                ..Default::default()
            },
        }
    }
}

impl Config {
    fn folders(&self) -> Result<Folders, String> {
        if self.input.trim().is_empty() {
            return Err("Choose the folder to watch.".into());
        }
        let output = Some(self.output.trim())
            .filter(|o| !o.is_empty())
            .map(Path::new);
        Folders::new(Path::new(self.input.trim()), output, self.move_done)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LogEntry {
    /// Unix seconds.
    time: i64,
    /// "started", "stopped", "signed", "failed" or "skipped".
    kind: String,
    file: Option<String>,
    /// Signed copy, or where a failed file went.
    output: Option<String>,
    message: Option<String>,
}

/// Saved as `watch-log.json`.
#[derive(Serialize, Deserialize, Default, Debug, PartialEq)]
#[serde(rename_all = "camelCase", default)]
struct Log {
    /// Local date the count is for, `YYYY-MM-DD`.
    day: String,
    signed_today: usize,
    /// Oldest first.
    entries: Vec<LogEntry>,
}

impl Log {
    fn today(&mut self) -> &mut usize {
        let day = chrono::Local::now().format("%Y-%m-%d").to_string();
        if self.day != day {
            self.day = day;
            self.signed_today = 0;
        }
        &mut self.signed_today
    }

    fn push(&mut self, entry: LogEntry) {
        self.entries.push(entry);
        let extra = self.entries.len().saturating_sub(LOG_CAP);
        self.entries.drain(..extra);
    }
}

/// Why the last session ended, for the front end to word.
#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Ended {
    /// "timeUp", "slept", "dailyLimit", "token", "folder" or "other".
    kind: &'static str,
    message: String,
}

struct Session {
    control: Arc<Control>,
    folder: PathBuf,
    signed: usize,
    started: i64,
    until: Option<i64>,
    thread: Option<JoinHandle<()>>,
}

#[derive(Default)]
pub struct WatchState {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    session: Option<Session>,
    ended: Option<Ended>,
    /// The app is closing: the tray and window are left alone.
    quitting: bool,
}

impl WatchState {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }
}

/// One read-modify-write of the files at a time.
static STORE_LOCK: Mutex<()> = Mutex::new(());

fn data_dir(app: &AppHandle) -> CmdResult<PathBuf> {
    app.path().app_data_dir().map_err(|e| CommandError {
        kind: "io",
        message: e.to_string(),
    })
}

fn read_json<T: Default + for<'a> Deserialize<'a>>(path: &Path) -> T {
    std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> CmdResult<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let json = serde_json::to_vec_pretty(value).map_err(|e| other(e.to_string()))?;
    std::fs::write(path, json)?;
    Ok(())
}

fn load_config(app: &AppHandle) -> Config {
    data_dir(app)
        .map(|d| read_json(&d.join("watch.json")))
        .unwrap_or_default()
}

fn load_log(app: &AppHandle) -> Log {
    data_dir(app)
        .map(|d| read_json(&d.join("watch-log.json")))
        .unwrap_or_default()
}

/// Adds an entry (and counts a signed file) in the stored log.
fn record(
    app: &AppHandle,
    kind: &str,
    file: Option<&Path>,
    output: Option<&Path>,
    message: Option<String>,
) {
    let _guard = STORE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let Ok(dir) = data_dir(app) else { return };
    let path = dir.join("watch-log.json");
    let mut log: Log = read_json(&path);
    if kind == "signed" {
        *log.today() += 1;
    }
    let text = |p: &Path| p.to_string_lossy().into_owned();
    log.push(LogEntry {
        time: chrono::Utc::now().timestamp(),
        kind: kind.into(),
        file: file.map(text),
        output: output.map(text),
        message,
    });
    let _ = write_json(&path, &log);
}

fn unix(t: SystemTime) -> i64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

fn folder_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| p.to_string_lossy().into_owned())
}

/// The tray line while watching: "Watching Invoices — 3 signed".
pub fn tray_line(app: &AppHandle) -> Option<String> {
    let inner = app.state::<WatchState>();
    let inner = inner.lock();
    let s = inner.session.as_ref()?;
    Some(format!(
        "Watching {} — {} signed",
        folder_name(&s.folder),
        s.signed
    ))
}

/// Stops from the tray.
pub fn stop(app: &AppHandle) {
    if let Some(s) = &app.state::<WatchState>().lock().session {
        s.control.stop();
    }
}

/// On quit: stops and waits a little for a file being signed.
pub fn quit(app: &AppHandle) {
    let thread = {
        let state = app.state::<WatchState>();
        let mut inner = state.lock();
        inner.quitting = true;
        let Some(s) = inner.session.as_mut() else {
            return;
        };
        s.control.stop();
        s.thread.take()
    };
    if let Some(t) = thread {
        for _ in 0..50 {
            if t.is_finished() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActiveDto {
    folder: String,
    output: String,
    signed: usize,
    started: i64,
    /// Unix seconds; none until stopped.
    until: Option<i64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusDto {
    config: Config,
    active: Option<ActiveDto>,
    ended: Option<Ended>,
    signed_today: usize,
    /// Most recent first.
    log: Vec<LogEntry>,
}

fn status(app: &AppHandle) -> StatusDto {
    let config = load_config(app);
    let mut log = load_log(app);
    let signed_today = *log.today();
    log.entries.reverse();
    let state = app.state::<WatchState>();
    let inner = state.lock();
    StatusDto {
        active: inner.session.as_ref().map(|s| ActiveDto {
            folder: s.folder.to_string_lossy().into_owned(),
            output: config
                .folders()
                .map(|f| f.output.to_string_lossy().into_owned())
                .unwrap_or_default(),
            signed: s.signed,
            started: s.started,
            until: s.until,
        }),
        ended: inner.ended.clone(),
        config,
        signed_today,
        log: log.entries,
    }
}

/// Tells the window, and the tray, that something changed.
fn changed(app: &AppHandle, tray: bool) {
    if app.state::<WatchState>().lock().quitting {
        return;
    }
    if tray {
        background::sync(app);
    }
    let _ = app.emit("watch-changed", ());
}

#[tauri::command]
pub async fn watch_status(app: AppHandle) -> StatusDto {
    status(&app)
}

/// Checks and saves the settings; not while watching.
#[tauri::command]
pub async fn watch_save(app: AppHandle, config: Config) -> CmdResult<StatusDto> {
    if app.state::<WatchState>().lock().session.is_some() {
        return Err(other("Stop watching to change these settings."));
    }
    config.preset.validate().map_err(other)?;
    if !config.input.trim().is_empty() {
        config.folders().map_err(other)?;
    }
    write_json(&data_dir(&app)?.join("watch.json"), &config)?;
    Ok(status(&app))
}

#[tauri::command]
pub async fn watch_stop(app: AppHandle) -> StatusDto {
    stop(&app);
    status(&app)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartArgs {
    cert_id: String,
    driver_path: String,
    pin: String,
}

/// Signs through the session opened at the start; the token lock is held
/// only while signing, so the rest of the app keeps working.
struct AppHost {
    app: AppHandle,
    signer: TokenSigner,
}

impl watch::Host for AppHost {
    fn sign(&mut self, data: &[u8], req: &SignRequest) -> Result<Vec<u8>, Error> {
        let _guard = TOKEN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        sign_pdf(data, req, &mut self.signer)
    }

    fn check(&mut self) -> Result<(), Error> {
        let _guard = TOKEN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        self.signer.check()
    }

    fn event(&mut self, event: Event) {
        match event {
            Event::Signed {
                input,
                output,
                warning,
                ..
            } => {
                record(&self.app, "signed", Some(&input), Some(&output), warning);
                if let Some(s) = &mut self.app.state::<WatchState>().lock().session {
                    s.signed += 1;
                }
                changed(&self.app, true);
                return;
            }
            Event::Failed {
                input,
                moved,
                reason,
            } => record(
                &self.app,
                "failed",
                Some(&input),
                moved.as_deref(),
                Some(reason),
            ),
            Event::Skipped { input, reason } => {
                record(&self.app, "skipped", Some(&input), None, Some(reason))
            }
        }
        changed(&self.app, false);
    }
}

fn ended(stop: &Stop) -> Option<Ended> {
    let kind = match stop {
        Stop::Requested => return None,
        Stop::TimeUp => "timeUp",
        Stop::Slept => "slept",
        Stop::DailyLimit(_) => "dailyLimit",
        Stop::Token(_) => "token",
        Stop::Folder(_) => "folder",
    };
    Some(Ended {
        kind,
        message: stop.to_string(),
    })
}

/// Logs in with `pin` (the only time it is asked for) and starts watching.
#[tauri::command]
pub async fn watch_start(app: AppHandle, mut args: StartArgs) -> CmdResult<StatusDto> {
    let handle = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let pin = std::mem::take(&mut args.pin);
        let started = start(&handle, &args, pin);
        started.map(|()| status(&handle))
    })
    .await
    .map_err(|e| other(e.to_string()))?
}

fn start(app: &AppHandle, args: &StartArgs, mut pin: String) -> CmdResult<()> {
    let result = open_session(app, args, &pin);
    pin.zeroize();
    let (config, folders, signer) = result?;
    let image = match config.preset.image {
        ImageChoice::Off => None,
        _ if config.preset.invisible => None,
        _ => Some(saved_image(app)?),
    };
    let now = SystemTime::now();
    let until = (config.minutes > 0).then(|| now + Duration::from_secs(config.minutes * 60));
    let opts = watch::Options {
        daily_limit: (config.daily_limit > 0).then_some(config.daily_limit),
        signed_today: *load_log(app).today(),
        until,
        stop_on_sleep: config.stop_on_sleep,
        ..Default::default()
    };
    if opts.daily_limit.is_some_and(|l| opts.signed_today >= l) {
        return Err(other(format!(
            "The daily limit of {} signed files was reached today.",
            config.daily_limit
        )));
    }
    let control = Arc::new(Control::default());
    {
        let state = app.state::<WatchState>();
        let mut inner = state.lock();
        if inner.session.is_some() {
            return Err(other("Already watching a folder."));
        }
        inner.ended = None;
        inner.session = Some(Session {
            control: control.clone(),
            folder: folders.input.clone(),
            signed: 0,
            started: unix(now),
            until: until.map(unix),
            thread: None,
        });
    }
    record(
        app,
        "started",
        Some(&folders.input),
        Some(&folders.output),
        None,
    );
    let thread_app = app.clone();
    let thread = std::thread::spawn(move || {
        let mut host = AppHost {
            app: thread_app.clone(),
            signer,
        };
        let stop = watch::run(
            &folders,
            &config.preset,
            image.as_ref(),
            &opts,
            &control,
            &mut host,
        );
        // Closes the session (the token logs out) and wipes a kept PIN.
        {
            let _guard = TOKEN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
            drop(host);
        }
        record(
            &thread_app,
            "stopped",
            Some(&folders.input),
            None,
            Some(stop.to_string()),
        );
        {
            let state = thread_app.state::<WatchState>();
            let mut inner = state.lock();
            inner.session = None;
            inner.ended = ended(&stop);
        }
        changed(&thread_app, true);
        // A window in the tray comes back to say why.
        if !matches!(stop, Stop::Requested) && !thread_app.state::<WatchState>().lock().quitting {
            background::show(&thread_app);
        }
    });
    if let Some(s) = &mut app.state::<WatchState>().lock().session {
        s.thread = Some(thread);
    }
    changed(app, true);
    Ok(())
}

fn open_session(
    app: &AppHandle,
    args: &StartArgs,
    pin: &str,
) -> CmdResult<(Config, Folders, TokenSigner)> {
    if app.state::<WatchState>().lock().session.is_some() {
        return Err(other("Already watching a folder."));
    }
    let config = load_config(app);
    config.preset.validate().map_err(other)?;
    let folders = config.folders().map_err(other)?;
    folders.create()?;
    if pin.is_empty() {
        return Err(other("Enter the PIN."));
    }
    let _guard = TOKEN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let token = Token::open(Path::new(&args.driver_path))?;
    let certs = token.signing_certificates()?;
    let cert = certs
        .iter()
        .find(|c| c.fingerprint() == args.cert_id)
        .ok_or_else(|| CommandError {
            kind: "token",
            message: "The selected certificate is no longer on the token.".into(),
        })?;
    not_expired(cert)?;
    let signer = token.signer(cert, pin)?;
    Ok((config, folders, signer))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_and_round_trip() {
        let c: Config = serde_json::from_str("{}").unwrap();
        assert_eq!(c, Config::default());
        assert!(c.move_done && c.stop_on_sleep);
        assert_eq!((c.daily_limit, c.minutes), (200, 60));
        assert!(c.preset.timestamp.is_none() && !c.preset.ltv);
        assert!(c.folders().is_err());
        let json = serde_json::to_string(&c).unwrap();
        // Never anything secret.
        assert!(!json.to_lowercase().contains("pin"));
        assert_eq!(serde_json::from_str::<Config>(&json).unwrap(), c);
    }

    #[test]
    fn log_keeps_the_last_entries_and_counts_today() {
        let mut log = Log {
            day: "2000-01-01".into(),
            signed_today: 7,
            entries: Vec::new(),
        };
        assert_eq!(*log.today(), 0);
        *log.today() += 1;
        assert_eq!(*log.today(), 1);
        for i in 0..LOG_CAP + 5 {
            log.push(LogEntry {
                time: i as i64,
                kind: "signed".into(),
                file: None,
                output: None,
                message: None,
            });
        }
        assert_eq!(log.entries.len(), LOG_CAP);
        assert_eq!(log.entries[0].time, 5);
    }
}
