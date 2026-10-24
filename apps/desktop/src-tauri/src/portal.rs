//! GST portal signing: the local listener the portal page talks to, turned
//! on in Settings, and the approval the user gives for every request.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use portal_bridge::identity::{self, Store};
use portal_bridge::{Config, Reply, Requests, Running, trust};
use serde::{Deserialize, Serialize};
use signdesk_core::portal::{self, Request, frame};
use signdesk_core::token::{Token, Tokens};
use tauri::{AppHandle, Emitter, Manager, State};

use super::{CertDto, CmdResult, CommandError, TOKEN_LOCK, cert_dto, not_expired};

fn other(message: impl Into<String>) -> CommandError {
    CommandError {
        kind: "other",
        message: message.into(),
    }
}

/// Saved in the app's data folder, so the listener starts with the app.
#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct Settings {
    enabled: bool,
    /// Version reported to the portal; the default when unset.
    version: Option<String>,
}

impl Settings {
    fn version(&self) -> String {
        self.version
            .clone()
            .unwrap_or_else(|| frame::DEFAULT_VERSION.into())
    }
}

/// A request shown to the user, waiting for Sign or Cancel.
struct Pending {
    id: u64,
    request: Request,
    origin: String,
    reply: Reply,
}

#[derive(Default)]
pub struct PortalState {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    running: Option<Running>,
    /// Why the listener is not running although it is turned on.
    error: Option<String>,
    pending: Option<Pending>,
    next_id: u64,
}

impl PortalState {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }
}

fn dir(app: &AppHandle) -> CmdResult<PathBuf> {
    let dir = app.path().app_data_dir().map_err(|e| CommandError {
        kind: "io",
        message: e.to_string(),
    })?;
    Ok(dir.join("portal"))
}

fn load_settings(dir: &Path) -> Settings {
    std::fs::read(dir.join("settings.json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn save_settings(dir: &Path, s: &Settings) -> CmdResult<()> {
    std::fs::create_dir_all(dir)?;
    let json = serde_json::to_vec_pretty(s).map_err(|e| other(e.to_string()))?;
    std::fs::write(dir.join("settings.json"), json)?;
    Ok(())
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RequestDto {
    id: u64,
    origin: String,
    pan: String,
    to_be_signed: String,
    /// "registration" (the PAN itself), "digest" (a hash of a return or
    /// form) or "text".
    kind: &'static str,
    expiry_check: bool,
}

impl RequestDto {
    fn new(p: &Pending) -> Self {
        let data = &p.request.to_be_signed;
        let kind = if !p.request.pan.is_empty() && data.eq_ignore_ascii_case(&p.request.pan) {
            "registration"
        } else if data.len() >= 40 && data.chars().all(|c| c.is_ascii_hexdigit()) {
            "digest"
        } else {
            "text"
        };
        RequestDto {
            id: p.id,
            origin: p.origin.clone(),
            pan: p.request.pan.clone(),
            to_be_signed: data.clone(),
            kind,
            expiry_check: p.request.expiry_check,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusDto {
    enabled: bool,
    port: Option<u16>,
    /// Ports before `port` that another program (emSigner) uses.
    taken: Vec<u16>,
    version: String,
    default_version: &'static str,
    error: Option<String>,
    /// The CA is still in the trust store (turned off, but removing it failed).
    certificate_left: bool,
    valid_until: Option<String>,
    log: Vec<String>,
}

fn status(app: &AppHandle, state: &PortalState) -> CmdResult<StatusDto> {
    let dir = dir(app)?;
    let settings = load_settings(&dir);
    let store = Store::new(&dir);
    let valid_until = std::fs::read(dir.join("server.cer"))
        .ok()
        .and_then(|c| identity::not_after(&c).ok())
        .map(|t| {
            chrono::DateTime::<chrono::Utc>::from(t)
                .format("%d %b %Y")
                .to_string()
        });
    let inner = state.lock();
    Ok(StatusDto {
        enabled: settings.enabled,
        port: inner.running.as_ref().map(|r| r.port),
        taken: inner
            .running
            .as_ref()
            .map(|r| r.taken.clone())
            .unwrap_or_default(),
        version: settings.version(),
        default_version: frame::DEFAULT_VERSION,
        error: inner.error.clone(),
        certificate_left: !settings.enabled && store.ca().is_some(),
        valid_until,
        log: inner
            .running
            .as_ref()
            .map(|r| r.log.lines())
            .unwrap_or_default(),
    })
}

/// Starts the listener with the saved identity; the error is kept for the
/// status too.
async fn start(app: &AppHandle) -> Result<(), String> {
    let result = async {
        let dir = dir(app).map_err(|e| e.message)?;
        let settings = load_settings(&dir);
        let stored = Store::new(&dir).load().map_err(|_| {
            "The portal signing certificate is missing. Turn portal signing off and on again."
                .to_string()
        })?;
        let expires = identity::not_after(&stored.cert).map_err(|e| e.to_string())?;
        if expires <= std::time::SystemTime::now() {
            return Err(
                "The portal signing certificate has expired. Turn portal signing off and on again to renew it."
                    .to_string(),
            );
        }
        let tls = identity::server_config(&stored.cert, &stored.key).map_err(|e| e.to_string())?;
        let config = Config {
            version: settings.version(),
            ..Config::default()
        };
        portal_bridge::start(config, tls)
            .await
            .map_err(|e| e.to_string())
    }
    .await;
    let state = app.state::<PortalState>();
    let result = match result {
        Ok((running, requests)) => {
            let mut inner = state.lock();
            if let Some(old) = inner.running.replace(running) {
                old.stop();
            }
            inner.error = None;
            drop(inner);
            tauri::async_runtime::spawn(serve(app.clone(), requests));
            Ok(())
        }
        Err(e) => {
            state.lock().error = Some(e.clone());
            Err(e)
        }
    };
    crate::background::sync(app);
    result
}

fn stop(state: &PortalState) {
    let mut inner = state.lock();
    if let Some(r) = inner.running.take() {
        r.stop();
    }
    inner.error = None;
    // Dropping the reply answers the page with "signing failed".
    inner.pending = None;
}

/// Shows each request to the user and keeps it until it is answered or the
/// page stops waiting.
async fn serve(app: AppHandle, mut requests: Requests) {
    while let Some(incoming) = requests.next().await {
        let (request, origin, reply, gone) = incoming.split();
        let state = app.state::<PortalState>();
        let dto = {
            let mut inner = state.lock();
            inner.next_id += 1;
            let pending = Pending {
                id: inner.next_id,
                request,
                origin,
                reply,
            };
            let dto = RequestDto::new(&pending);
            inner.pending = Some(pending);
            dto
        };
        let id = dto.id;
        let _ = app.emit("portal-request", dto);
        to_front(&app);
        let app = app.clone();
        tauri::async_runtime::spawn(async move {
            gone.wait().await;
            let state = app.state::<PortalState>();
            let mut inner = state.lock();
            if inner.pending.as_ref().is_some_and(|p| p.id == id) {
                inner.pending = None;
                drop(inner);
                let _ = app.emit("portal-closed", id);
            }
        });
    }
}

/// Brings the window up so the request is not missed behind the browser.
fn to_front(app: &AppHandle) {
    crate::background::showing(app);
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        // Windows does not let a background app take the focus; staying on
        // top for a moment gets the window seen anyway.
        let _ = w.set_always_on_top(true);
        let _ = w.set_focus();
        let _ = w.set_always_on_top(false);
        let _ = w.request_user_attention(Some(tauri::UserAttentionType::Critical));
    }
}

/// Whether portal signing is turned on, and the port while it is running.
pub fn summary(app: &AppHandle) -> (bool, Option<u16>) {
    let enabled = dir(app).is_ok_and(|d| load_settings(&d).enabled);
    let port = app
        .state::<PortalState>()
        .lock()
        .running
        .as_ref()
        .map(|r| r.port);
    (enabled, port)
}

/// Starts the listener at launch when portal signing is turned on.
pub fn start_if_enabled(app: &AppHandle) {
    let Ok(dir) = dir(app) else { return };
    if !load_settings(&dir).enabled {
        return;
    }
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let _ = start(&app).await;
    });
}

#[tauri::command]
pub fn portal_status(app: AppHandle, state: State<'_, PortalState>) -> CmdResult<StatusDto> {
    status(&app, &state)
}

/// Makes the certificate, adds its CA to the user's trust store (the system
/// asks for confirmation) and starts listening.
#[tauri::command]
pub async fn portal_enable(app: AppHandle) -> CmdResult<StatusDto> {
    let dir = dir(&app)?;
    let d = dir.clone();
    tauri::async_runtime::spawn_blocking(move || -> CmdResult<()> {
        let store = Store::new(&d);
        // A CA from an earlier attempt that is still trusted goes first.
        if let Some(old) = store.ca() {
            trust::remove(&store.ca_path(), &old).map_err(|e| other(e.to_string()))?;
        }
        let generated =
            identity::generate(std::time::SystemTime::now()).map_err(|e| other(e.to_string()))?;
        store.save(&generated).map_err(|e| other(e.to_string()))?;
        if let Err(e) = trust::install(&store.ca_path()) {
            let _ = store.remove();
            return Err(other(e.to_string()));
        }
        Ok(())
    })
    .await
    .map_err(|e| other(e.to_string()))??;
    let mut settings = load_settings(&dir);
    settings.enabled = true;
    save_settings(&dir, &settings)?;
    let _ = start(&app).await;
    status(&app, &app.state::<PortalState>())
}

/// Stops listening, takes the CA out of the trust store and deletes the
/// certificate files.
#[tauri::command]
pub async fn portal_disable(app: AppHandle) -> CmdResult<StatusDto> {
    stop(&app.state::<PortalState>());
    let dir = dir(&app)?;
    let mut settings = load_settings(&dir);
    settings.enabled = false;
    save_settings(&dir, &settings)?;
    crate::background::sync(&app);
    let d = dir.clone();
    tauri::async_runtime::spawn_blocking(move || -> CmdResult<()> {
        let store = Store::new(&d);
        if let Some(ca) = store.ca() {
            // Kept when this fails, so removing can be tried again.
            trust::remove(&store.ca_path(), &ca).map_err(|e| other(e.to_string()))?;
        }
        store.remove().map_err(|e| other(e.to_string()))
    })
    .await
    .map_err(|e| other(e.to_string()))??;
    status(&app, &app.state::<PortalState>())
}

/// Changes the version reported to the portal and restarts the listener.
#[tauri::command]
pub async fn portal_set_version(app: AppHandle, version: String) -> CmdResult<StatusDto> {
    let version = version.trim().to_string();
    if !version.is_empty()
        && (version.len() > 16
            || !version
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.'))
    {
        return Err(other("The version is a number such as 2.8."));
    }
    let dir = dir(&app)?;
    let mut settings = load_settings(&dir);
    settings.version = Some(version).filter(|v| !v.is_empty() && v != frame::DEFAULT_VERSION);
    save_settings(&dir, &settings)?;
    if settings.enabled {
        stop(&app.state::<PortalState>());
        let _ = start(&app).await;
    }
    status(&app, &app.state::<PortalState>())
}

/// The request waiting for the user, if any (for a window that missed the event).
#[tauri::command]
pub fn portal_pending(state: State<'_, PortalState>) -> Option<RequestDto> {
    state.lock().pending.as_ref().map(RequestDto::new)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalCertDto {
    #[serde(flatten)]
    cert: CertDto,
    /// The certificate names the requested PAN (as a hash in its subject).
    matches_pan: bool,
}

/// Certificates on the tokens, with those belonging to `pan` marked.
#[tauri::command]
pub async fn portal_certificates(pan: String) -> CmdResult<Vec<PortalCertDto>> {
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = TOKEN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let tokens = Tokens::open_installed()?;
        Ok(tokens
            .signing_certificates()?
            .iter()
            .map(|c| PortalCertDto {
                cert: cert_dto(c),
                matches_pan: portal::matches_pan(&c.der, &pan),
            })
            .collect())
    })
    .await
    .map_err(|e| other(e.to_string()))?
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortalSignArgs {
    id: u64,
    cert_id: String,
    driver_path: String,
    pin: String,
}

/// Signs the waiting request with the chosen certificate and answers the
/// page. A wrong PIN leaves the request waiting, so the user can try again.
#[tauri::command]
pub async fn portal_sign(app: AppHandle, args: PortalSignArgs) -> CmdResult<()> {
    let gone = || other("The GST portal page is no longer waiting for this signature.");
    let request = {
        let state = app.state::<PortalState>();
        let inner = state.lock();
        match &inner.pending {
            Some(p) if p.id == args.id => p.request.clone(),
            _ => return Err(gone()),
        }
    };
    let frame = tauri::async_runtime::spawn_blocking(move || -> CmdResult<String> {
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
        if request.expiry_check {
            not_expired(cert)?;
        }
        let mut signer = token.signer(cert, &args.pin)?;
        Ok(portal::sign(&mut signer, &request, chrono::Utc::now())?)
    })
    .await
    .map_err(|e| other(e.to_string()))??;
    let pending = {
        let state = app.state::<PortalState>();
        let mut inner = state.lock();
        match inner.pending.take() {
            Some(p) if p.id == args.id => p,
            other_request => {
                inner.pending = other_request;
                return Err(gone());
            }
        }
    };
    let sent = pending.reply.send(frame);
    let _ = app.emit("portal-closed", args.id);
    if sent { Ok(()) } else { Err(gone()) }
}

/// The user declined: the page shows "Signing Cancelled".
#[tauri::command]
pub fn portal_cancel(app: AppHandle, state: State<'_, PortalState>, id: u64) {
    let mut inner = state.lock();
    if inner.pending.as_ref().is_some_and(|p| p.id == id)
        && let Some(p) = inner.pending.take()
    {
        p.reply.send(frame::CANCELED.into());
        drop(inner);
        let _ = app.emit("portal-closed", id);
    }
}
