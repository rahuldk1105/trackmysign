//! Tauri backend: thin commands over `trackmysign-core`.

mod background;
mod certs;
mod folder;
mod incoming;
mod known;
mod output;
mod portal;
mod recent;
mod verify;
mod watch;

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use incoming::{Arrival, Incoming};
use serde::{Deserialize, Serialize};
use tauri::ipc::{Channel, Response};
use tauri::{AppHandle, Emitter, Manager, State};
use trackmysign_core::certinfo::{Validity, days_until};
use trackmysign_core::token::{Token, TokenCert, Tokens, installed_drivers};
use trackmysign_core::{
    DisplayRect, DocMdp, Error, ImagePosition, PdfError, SignRequest, StampImage,
    inspect_with_password, sign_pdf,
};

/// PKCS#11 drivers are process-global; never let two commands use one at once.
static TOKEN_LOCK: Mutex<()> = Mutex::new(());

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CommandError {
    kind: &'static str,
    message: String,
}

impl From<Error> for CommandError {
    fn from(e: Error) -> Self {
        let kind = match &e {
            Error::WrongPin { .. } => "wrongPin",
            Error::PinLocked => "pinLocked",
            Error::Token(_) => "token",
            Error::Pdf(PdfError::PasswordRequired | PdfError::WrongPassword) => "password",
            Error::Pdf(PdfError::SigningNotAllowed) => "permission",
            Error::Pdf(_) | Error::NotPermitted(_) => "pdf",
            Error::Timestamp(_) => "timestamp",
            Error::Ltv(_) => "ltv",
            _ => "other",
        };
        CommandError {
            kind,
            message: e.to_string(),
        }
    }
}

impl From<std::io::Error> for CommandError {
    fn from(e: std::io::Error) -> Self {
        CommandError {
            kind: "io",
            message: e.to_string(),
        }
    }
}

type CmdResult<T> = Result<T, CommandError>;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CertDto {
    /// SHA-256 fingerprint; picks the certificate again when signing.
    id: String,
    name: String,
    organization: Option<String>,
    issuer: String,
    valid_from: String,
    valid_until: String,
    expired: bool,
    /// Whole days until it expires; negative once expired.
    days_left: i64,
    /// Whole days until it becomes valid, when it is not yet (or the PC clock is wrong).
    starts_in: Option<i64>,
    can_sign: bool,
    token_label: String,
    driver: String,
    driver_path: String,
}

fn cert_dto(c: &TokenCert) -> CertDto {
    CertDto {
        id: c.fingerprint(),
        name: c.summary.subject_cn.clone(),
        organization: c.summary.organization.clone(),
        issuer: c.summary.issuer_cn.clone(),
        valid_from: c.summary.not_before.format("%d %b %Y").to_string(),
        valid_until: c.summary.not_after.format("%d %b %Y").to_string(),
        expired: c.summary.expired,
        days_left: days_until(chrono::Utc::now(), c.summary.not_after),
        starts_in: match c.summary.validity() {
            Validity::NotYetValid { days } => Some(days),
            _ => None,
        },
        can_sign: c.summary.can_sign,
        token_label: c.token_label.clone(),
        driver: c.driver.name.clone(),
        driver_path: c.driver.path.to_string_lossy().into_owned(),
    }
}

#[tauri::command]
async fn list_certificates(app: AppHandle) -> CmdResult<Vec<CertDto>> {
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = TOKEN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let tokens = Tokens::open_installed()?;
        let certs = tokens.signing_certificates()?;
        known::remember(&app, &certs);
        Ok(certs.iter().map(cert_dto).collect())
    })
    .await
    .map_err(|e| CommandError {
        kind: "other",
        message: e.to_string(),
    })?
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PinStatusDto {
    count_low: bool,
    final_try: bool,
    locked: bool,
}

/// What the token says about PIN attempts, read fresh when the PIN dialog opens.
#[tauri::command]
async fn pin_status(cert_id: String, driver_path: String) -> CmdResult<PinStatusDto> {
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = TOKEN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let token = Token::open(Path::new(&driver_path))?;
        let certs = token.signing_certificates()?;
        let cert = certs
            .iter()
            .find(|c| c.fingerprint() == cert_id)
            .ok_or_else(|| CommandError {
                kind: "token",
                message: "The selected certificate is no longer on the token.".into(),
            })?;
        let s = token.pin_status(cert.slot)?;
        Ok(PinStatusDto {
            count_low: s.count_low,
            final_try: s.final_try,
            locked: s.locked,
        })
    })
    .await
    .map_err(|e| CommandError {
        kind: "other",
        message: e.to_string(),
    })?
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PageDto {
    width: f64,
    height: f64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RectDto {
    x: f64,
    y: f64,
    w: f64,
    h: f64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FieldDto {
    name: String,
    page: Option<usize>,
    /// Points from the top-left of the displayed page; none when invisible.
    rect: Option<RectDto>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PdfDto {
    path: String,
    name: String,
    pages: Vec<PageDto>,
    signatures: usize,
    /// Signature fields waiting to be signed.
    empty_fields: Vec<FieldDto>,
    encrypted: bool,
    signing_allowed: bool,
    /// DocMDP level (1-3) when the document is certified.
    certified: Option<u8>,
}

/// `password` unlocks a protected PDF; it is only used for this call.
#[tauri::command]
fn pdf_info(path: String, password: Option<String>) -> CmdResult<PdfDto> {
    let data = std::fs::read(&path)?;
    let info = inspect_with_password(&data, password.as_deref())?;
    let name = Path::new(&path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    Ok(PdfDto {
        path,
        name,
        pages: info
            .pages
            .iter()
            .map(|p| PageDto {
                width: p.width,
                height: p.height,
            })
            .collect(),
        signatures: info.signatures,
        empty_fields: info
            .empty_fields
            .into_iter()
            .map(|f| FieldDto {
                name: f.name,
                page: f.page,
                rect: f.rect.map(|r| RectDto {
                    x: r.x,
                    y: r.y,
                    w: r.w,
                    h: r.h,
                }),
            })
            .collect(),
        encrypted: info.encrypted,
        signing_allowed: info.signing_allowed,
        certified: info.certified.map(DocMdp::level),
    })
}

/// Raw bytes for the PDF.js viewer.
#[tauri::command]
fn read_pdf(path: String) -> CmdResult<Response> {
    Ok(Response::new(std::fs::read(path)?))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RectArg {
    x: f64,
    y: f64,
    w: f64,
    h: f64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignArgs {
    path: String,
    page: usize,
    rect: Option<RectArg>,
    /// Pages that get the box; empty for just `page`.
    #[serde(default)]
    pages: Vec<usize>,
    reason: Option<String>,
    location: Option<String>,
    cert_id: String,
    /// Driver the certificate was listed from.
    driver_path: String,
    pin: String,
    /// TSA URL when "Add trusted timestamp" is on.
    #[serde(default)]
    timestamp: Option<String>,
    #[serde(default)]
    ltv: bool,
    /// Show the saved signature image, and where.
    #[serde(default)]
    image: Option<ImageArg>,
    /// Sign into this empty signature field instead of placing a box.
    #[serde(default)]
    field: Option<String>,
    /// Password of a protected PDF, as entered when opening it.
    #[serde(default)]
    password: Option<String>,
    /// Certify with this DocMDP level (1-3) instead of approving.
    #[serde(default)]
    certify: Option<u8>,
    /// Folder for the signed copy; next to the original when none.
    #[serde(default)]
    out_dir: Option<String>,
}

#[derive(Deserialize, Clone, Copy)]
#[serde(rename_all = "camelCase")]
enum ImageArg {
    Left,
    Above,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SignedDto {
    output: String,
    name: String,
}

#[tauri::command]
async fn sign(app: AppHandle, args: SignArgs) -> CmdResult<SignedDto> {
    tauri::async_runtime::spawn_blocking(move || {
        let input = PathBuf::from(&args.path);
        let data = std::fs::read(&input)?;
        let image = match args.image {
            Some(_) => Some(saved_image(&app)?),
            None => None,
        };
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
        let mut signer = token.signer(cert, &args.pin)?;
        let req = SignRequest {
            page: args.page,
            rect: args.rect.map(|r| DisplayRect {
                x: r.x,
                y: r.y,
                w: r.w,
                h: r.h,
            }),
            pages: args.pages,
            reason: args.reason.filter(|s| !s.trim().is_empty()),
            location: args.location.filter(|s| !s.trim().is_empty()),
            image,
            image_position: image_position(args.image),
            timestamp: trimmed_url(args.timestamp),
            ltv: args.ltv,
            field: args.field,
            password: args.password,
            certify: args.certify.map(|p| DocMdp::from_level(p.into())),
            ..Default::default()
        };
        let signed = sign_pdf(&data, &req, &mut signer)?;
        let out = output::write_signed(&input, args.out_dir.as_deref(), &signed)?;
        Ok(SignedDto {
            name: out
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            output: out.to_string_lossy().into_owned(),
        })
    })
    .await
    .map_err(|e| CommandError {
        kind: "other",
        message: e.to_string(),
    })?
}

/// A signature made with an expired certificate is invalid, so do not make one.
fn not_expired(cert: &TokenCert) -> CmdResult<()> {
    if cert.summary.expired {
        return Err(CommandError {
            kind: "expired",
            message: format!(
                "The certificate expired on {}. A signature made with it would not be valid. \
                 Renew your DSC with your provider.",
                cert.summary.not_after.format("%d %b %Y")
            ),
        });
    }
    Ok(())
}

fn image_position(arg: Option<ImageArg>) -> ImagePosition {
    match arg {
        Some(ImageArg::Above) => ImagePosition::Above,
        _ => ImagePosition::Left,
    }
}

fn trimmed_url(url: Option<String>) -> Option<String> {
    url.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// Page for every file of a batch: `"first"`, `"last"` or a page number (1 = first).
#[derive(Deserialize)]
#[serde(untagged)]
enum PageArg {
    Named(String),
    Number(usize),
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BatchArgs {
    paths: Vec<String>,
    page: PageArg,
    /// Points from the top-left of the page; moved and shrunk to fit each page.
    rect: Option<RectArg>,
    /// Box on every page of each file.
    #[serde(default)]
    all_pages: bool,
    /// Otherwise the box goes on these pages (zero-based, those a file has),
    /// or on just `page` when empty.
    #[serde(default)]
    pages: Vec<usize>,
    reason: Option<String>,
    location: Option<String>,
    cert_id: String,
    driver_path: String,
    pin: String,
    #[serde(default)]
    timestamp: Option<String>,
    #[serde(default)]
    ltv: bool,
    #[serde(default)]
    image: Option<ImageArg>,
    /// Password entered for the first file; tried on each file that has one.
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    certify: Option<u8>,
    #[serde(default)]
    out_dir: Option<String>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase", tag = "state")]
enum BatchProgress {
    Signing {
        index: usize,
    },
    Done {
        index: usize,
        output: String,
        name: String,
    },
    Failed {
        index: usize,
        message: String,
    },
}

fn sign_one(
    path: &Path,
    args: &BatchArgs,
    image: &Option<StampImage>,
    signer: &mut dyn trackmysign_core::Signer,
) -> CmdResult<PathBuf> {
    let data = std::fs::read(path)?;
    // Files that open without a password are not held up by the batch's one.
    let (info, password) = match inspect_with_password(&data, args.password.as_deref()) {
        Err(Error::Pdf(PdfError::WrongPassword)) => (inspect_with_password(&data, None)?, None),
        r => (r?, args.password.clone()),
    };
    let pages = info.pages.len();
    if pages == 0 {
        return Err(CommandError {
            kind: "pdf",
            message: "The PDF has no pages.".into(),
        });
    }
    let page = match &args.page {
        PageArg::Number(n) => n.saturating_sub(1).min(pages - 1),
        PageArg::Named(s) if s == "first" => 0,
        PageArg::Named(_) => pages - 1,
    };
    let size = &info.pages[page];
    let rect = args.rect.as_ref().map(|r| {
        let w = r.w.min(size.width);
        let h = r.h.min(size.height);
        DisplayRect {
            x: r.x.clamp(0.0, size.width - w),
            y: r.y.clamp(0.0, size.height - h),
            w,
            h,
        }
    });
    let pages = if args.all_pages {
        (0..pages).collect()
    } else {
        args.pages.iter().copied().filter(|p| *p < pages).collect()
    };
    let req = SignRequest {
        page,
        rect,
        pages,
        reason: args.reason.clone().filter(|s| !s.trim().is_empty()),
        location: args.location.clone().filter(|s| !s.trim().is_empty()),
        image: image.clone(),
        image_position: image_position(args.image),
        timestamp: trimmed_url(args.timestamp.clone()),
        ltv: args.ltv,
        password,
        certify: args.certify.map(|p| DocMdp::from_level(p.into())),
        ..Default::default()
    };
    let signed = sign_pdf(&data, &req, signer)?;
    output::write_signed(path, args.out_dir.as_deref(), &signed)
}

/// Signs every file with one login. Fails as a whole only when the token or
/// PIN does (also midway, for a key that asks for the PIN on every
/// signature); a file that cannot be signed is reported and skipped.
#[tauri::command]
async fn sign_batch(
    app: AppHandle,
    args: BatchArgs,
    progress: Channel<BatchProgress>,
) -> CmdResult<()> {
    tauri::async_runtime::spawn_blocking(move || {
        let image = match args.image {
            Some(_) => Some(saved_image(&app)?),
            None => None,
        };
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
        let mut signer = token.signer(cert, &args.pin)?;
        for (index, path) in args.paths.iter().enumerate() {
            let _ = progress.send(BatchProgress::Signing { index });
            let _ = progress.send(
                match sign_one(Path::new(path), &args, &image, &mut signer) {
                    // Another attempt with the same PIN could lock the token.
                    Err(e) if matches!(e.kind, "wrongPin" | "pinLocked") => return Err(e),
                    Ok(out) => BatchProgress::Done {
                        index,
                        name: out
                            .file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_default(),
                        output: out.to_string_lossy().into_owned(),
                    },
                    Err(e) => BatchProgress::Failed {
                        index,
                        message: e.message,
                    },
                },
            );
        }
        Ok(())
    })
    .await
    .map_err(|e| CommandError {
        kind: "other",
        message: e.to_string(),
    })?
}

/// The handwritten signature image, copied into the app's data folder.
fn image_path(app: &AppHandle) -> CmdResult<PathBuf> {
    let dir = app.path().app_data_dir().map_err(|e| CommandError {
        kind: "io",
        message: e.to_string(),
    })?;
    Ok(dir.join("signature-image"))
}

fn saved_image(app: &AppHandle) -> CmdResult<StampImage> {
    let path = image_path(app)?;
    if !path.is_file() {
        return Err(CommandError {
            kind: "other",
            message: "The signature image is missing. Choose it again in Settings.".into(),
        });
    }
    Ok(StampImage::open(&path)?)
}

/// Bytes of the saved signature image for the preview; empty when there is none.
#[tauri::command]
fn signature_image(app: AppHandle) -> CmdResult<Response> {
    let path = image_path(&app)?;
    let data = if path.is_file() {
        std::fs::read(path)?
    } else {
        Vec::new()
    };
    Ok(Response::new(data))
}

/// Checks that `path` is a usable PNG or JPEG and keeps a copy.
#[tauri::command]
fn set_signature_image(app: AppHandle, path: String) -> CmdResult<()> {
    let data = std::fs::read(&path)?;
    StampImage::from_bytes(&data)?;
    let dest = image_path(&app)?;
    if let Some(dir) = dest.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(dest, data)?;
    Ok(())
}

#[tauri::command]
fn clear_signature_image(app: AppHandle) -> CmdResult<()> {
    let path = image_path(&app)?;
    if path.is_file() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DriverDto {
    name: String,
    path: String,
}

/// PKCS#11 drivers installed on this computer, preferred first.
#[tauri::command]
fn token_drivers() -> Vec<DriverDto> {
    installed_drivers()
        .into_iter()
        .map(|d| DriverDto {
            name: d.name,
            path: d.path.to_string_lossy().into_owned(),
        })
        .collect()
}

/// Existing files among `args`, relative paths resolved against `cwd`,
/// sorted into PDFs and others.
fn file_args(args: impl IntoIterator<Item = String>, cwd: &Path) -> Arrival {
    Arrival::sort(
        args.into_iter()
            .map(|a| cwd.join(a))
            .filter(|p| p.is_file())
            .map(|p| p.to_string_lossy().into_owned()),
    )
}

/// Collects handed-over files; the window gets them once no more arrive.
fn hand_over(app: &AppHandle, arrival: Arrival) {
    if arrival.is_empty() {
        return;
    }
    if app.state::<Incoming>().arrive(arrival) {
        deliver_later(app.clone());
    }
    background::show(app);
}

/// Sends the collected files as one `open-files` event once no more arrive;
/// before the window listens, `startup_files` takes them.
fn deliver_later(app: AppHandle) {
    std::thread::spawn(move || {
        loop {
            match app.state::<Incoming>().poll() {
                incoming::Poll::Wait(d) => std::thread::sleep(d),
                incoming::Poll::Deliver(arrival) => {
                    let _ = app.emit("open-files", arrival);
                    break;
                }
                incoming::Poll::Held | incoming::Poll::Idle => break,
            }
        }
    });
}

/// Files opened before the window was ready to receive them.
#[tauri::command]
fn startup_files(state: State<'_, Incoming>) -> Arrival {
    state.startup()
}

/// The first PDF of [`startup_files`].
#[tauri::command]
fn startup_file(state: State<'_, Incoming>) -> Option<String> {
    startup_files(state).files.into_iter().next()
}

#[tauri::command]
fn open_file(path: String) -> CmdResult<()> {
    tauri_plugin_opener::open_path(path, None::<&str>).map_err(|e| CommandError {
        kind: "io",
        message: e.to_string(),
    })
}

#[tauri::command]
fn reveal_file(path: String) -> CmdResult<()> {
    tauri_plugin_opener::reveal_item_in_dir(path).map_err(|e| CommandError {
        kind: "io",
        message: e.to_string(),
    })
}

#[tauri::command]
fn open_website() -> CmdResult<()> {
    tauri_plugin_opener::open_url("https://sign.rahuldk.in", None::<&str>).map_err(|e| {
        CommandError {
            kind: "io",
            message: e.to_string(),
        }
    })
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let cwd = std::env::current_dir().unwrap_or_default();
    let hidden = background::launched_hidden(std::env::args());
    let startup = file_args(std::env::args().skip(1), &cwd);
    let builder = tauri::Builder::default();
    // Must be the first plugin: a second launch hands its files to this one and exits.
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    let builder = builder.plugin(tauri_plugin_single_instance::init(|app, args, cwd| {
        // Launching again shows the window, also when it is in the tray.
        if !background::launched_hidden(&args) {
            background::show(app);
        }
        hand_over(app, file_args(args.into_iter().skip(1), Path::new(&cwd)));
    }));
    // In-app updates; the front end decides when to check (settings).
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    let builder = builder
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        // Sign-in entry, named after the product (Run value / LaunchAgent).
        .plugin(
            tauri_plugin_autostart::Builder::new()
                .arg(background::ARG)
                .build(),
        );
    builder
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(Incoming::default())
        .manage(portal::PortalState::default())
        .manage(background::BackgroundState::default())
        .manage(folder::FolderState::default())
        .manage(watch::WatchState::default())
        .on_window_event(background::on_window_event)
        .setup(move |app| {
            background::start(app.handle(), hidden);
            if app.state::<Incoming>().arrive(startup) {
                deliver_later(app.handle().clone());
            }
            portal::start_if_enabled(app.handle());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            list_certificates,
            known::known_certificates,
            certs::certificate_details,
            certs::export_certificate,
            recent::recent_files,
            recent::recent_add,
            recent::recent_signed,
            recent::recent_clear,
            pdf_info,
            read_pdf,
            sign,
            sign_batch,
            pin_status,
            startup_file,
            startup_files,
            signature_image,
            set_signature_image,
            clear_signature_image,
            token_drivers,
            open_file,
            reveal_file,
            open_website,
            verify::verify_pdf,
            verify::export_report,
            folder::verify_folder,
            folder::stop_folder_verify,
            folder::export_folder_report,
            folder::export_folder_csv,
            portal::portal_status,
            portal::portal_enable,
            portal::portal_disable,
            portal::portal_set_version,
            portal::portal_pending,
            portal::portal_certificates,
            portal::portal_sign,
            portal::portal_cancel,
            background::background_status,
            background::background_set,
            background::background_set_autostart,
            watch::watch_status,
            watch::watch_save,
            watch::watch_start,
            watch::watch_stop
        ])
        .build(tauri::generate_context!())
        .expect("error while running TrackMySign")
        .run(on_run_event);
}

/// Finder: "Open With", drag onto the Dock icon, double-click when default.
/// Opening the app again (Finder, Launchpad) shows the window.
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn on_run_event(app: &AppHandle, event: tauri::RunEvent) {
    match event {
        tauri::RunEvent::Opened { urls } => {
            // Several events for one selection become one batch.
            let files = urls
                .iter()
                .filter_map(|u| u.to_file_path().ok())
                .map(|p| p.to_string_lossy().into_owned());
            hand_over(app, Arrival::sort(files));
        }
        #[cfg(target_os = "macos")]
        tauri::RunEvent::Reopen { .. } => background::show(app),
        tauri::RunEvent::Exit => watch::quit(app),
        _ => {}
    }
}

/// Quitting ends a watch-folder session.
#[cfg(not(any(target_os = "macos", target_os = "ios")))]
fn on_run_event(app: &AppHandle, event: tauri::RunEvent) {
    if let tauri::RunEvent::Exit = event {
        watch::quit(app);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_args_resolve_and_sort() {
        let dir = std::env::temp_dir().join(format!("tms-args-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.pdf"), b"%PDF").unwrap();
        std::fs::write(dir.join("B.PDF"), b"%PDF").unwrap();
        std::fs::write(dir.join("notes.txt"), b"").unwrap();
        let abs = dir.join("B.PDF").to_string_lossy().into_owned();
        let args = ["a.pdf", "notes.txt", "missing.pdf", "--flag", abs.as_str()];
        let found = file_args(args.iter().map(|s| s.to_string()), &dir);
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(
            found.files,
            vec![dir.join("a.pdf").to_string_lossy().into_owned(), abs]
        );
        assert_eq!(found.ignored, ["notes.txt"]);
    }

    /// The shape `scripts/updater-manifest.mjs` writes is what the updater accepts.
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    #[test]
    fn update_manifest_parses() {
        let base = "https://github.com/rahuldk1105/trackmysign/releases/download/v0.2.0";
        let manifest = serde_json::json!({
            "version": "0.2.0",
            "notes": "## What's Changed\n* Updates",
            "pub_date": "2026-10-23T10:00:00Z",
            "platforms": {
                "windows-x86_64": { "url": format!("{base}/TrackMySign-Setup-windows-x64.exe"), "signature": "c2ln" },
                "darwin-aarch64": { "url": format!("{base}/TrackMySign-macos-universal.app.tar.gz"), "signature": "c2ln" },
                "darwin-x86_64": { "url": format!("{base}/TrackMySign-macos-universal.app.tar.gz"), "signature": "c2ln" },
                "linux-x86_64-appimage": { "url": format!("{base}/TrackMySign-linux-x86_64.AppImage"), "signature": "c2ln" },
                "linux-x86_64-deb": { "url": format!("{base}/TrackMySign-linux-amd64.deb"), "signature": "c2ln" }
            }
        });
        let release: tauri_plugin_updater::RemoteRelease =
            serde_json::from_value(manifest).unwrap();
        assert_eq!(release.version.to_string(), "0.2.0");
        assert!(release.pub_date.is_some());
        for target in [
            "windows-x86_64",
            "darwin-aarch64",
            "darwin-x86_64",
            "linux-x86_64-appimage",
            "linux-x86_64-deb",
        ] {
            let url = release.download_url(target).unwrap();
            assert!(url.as_str().starts_with(base), "{url}");
            assert_eq!(release.signature(target).unwrap(), "c2ln");
        }
        assert!(release.download_url("linux-x86_64").is_err());
    }
}
