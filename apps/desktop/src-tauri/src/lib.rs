//! Tauri backend: thin commands over `signdesk-core`.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use signdesk_core::token::Token;
use signdesk_core::{
    DisplayRect, Error, ImagePosition, SignRequest, StampImage, inspect, sign_pdf, signed_path,
};
use tauri::ipc::{Channel, Response};
use tauri::{AppHandle, Emitter, Manager, State};

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
            Error::Pdf(_) => "pdf",
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
    index: usize,
    name: String,
    organization: Option<String>,
    issuer: String,
    valid_until: String,
    expired: bool,
    can_sign: bool,
    token_label: String,
}

#[tauri::command]
async fn list_certificates() -> CmdResult<Vec<CertDto>> {
    tauri::async_runtime::spawn_blocking(|| {
        let _guard = TOKEN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let token = Token::open_default()?;
        let certs = token.signing_certificates()?;
        Ok(certs
            .iter()
            .enumerate()
            .map(|(index, c)| CertDto {
                index,
                name: c.summary.subject_cn.clone(),
                organization: c.summary.organization.clone(),
                issuer: c.summary.issuer_cn.clone(),
                valid_until: c.summary.not_after.format("%d %b %Y").to_string(),
                expired: c.summary.expired,
                can_sign: c.summary.can_sign,
                token_label: c.token_label.clone(),
            })
            .collect())
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
struct PdfDto {
    path: String,
    name: String,
    pages: Vec<PageDto>,
    signatures: usize,
}

#[tauri::command]
fn pdf_info(path: String) -> CmdResult<PdfDto> {
    let data = std::fs::read(&path)?;
    let info = inspect(&data)?;
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
    reason: Option<String>,
    location: Option<String>,
    cert_index: usize,
    pin: String,
    /// Show the saved signature image, and where.
    #[serde(default)]
    image: Option<ImageArg>,
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
        let token = Token::open_default()?;
        let certs = token.signing_certificates()?;
        let cert = certs.get(args.cert_index).ok_or_else(|| CommandError {
            kind: "token",
            message: "The selected certificate is no longer on the token.".into(),
        })?;
        let mut signer = token.signer(cert, &args.pin)?;
        let req = SignRequest {
            page: args.page,
            rect: args.rect.map(|r| DisplayRect {
                x: r.x,
                y: r.y,
                w: r.w,
                h: r.h,
            }),
            reason: args.reason.filter(|s| !s.trim().is_empty()),
            location: args.location.filter(|s| !s.trim().is_empty()),
            image,
            image_position: match args.image {
                Some(ImageArg::Above) => ImagePosition::Above,
                _ => ImagePosition::Left,
            },
            ..Default::default()
        };
        let signed = sign_pdf(&data, &req, &mut signer)?;
        let out = signed_path(&input);
        std::fs::write(&out, signed)?;
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
    reason: Option<String>,
    location: Option<String>,
    cert_index: usize,
    pin: String,
    #[serde(default)]
    image: Option<ImageArg>,
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
    signer: &mut dyn signdesk_core::Signer,
) -> CmdResult<PathBuf> {
    let data = std::fs::read(path)?;
    let info = inspect(&data)?;
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
    let req = SignRequest {
        page,
        rect,
        reason: args.reason.clone().filter(|s| !s.trim().is_empty()),
        location: args.location.clone().filter(|s| !s.trim().is_empty()),
        image: image.clone(),
        image_position: match args.image {
            Some(ImageArg::Above) => ImagePosition::Above,
            _ => ImagePosition::Left,
        },
        ..Default::default()
    };
    let signed = sign_pdf(&data, &req, signer)?;
    let out = signed_path(path);
    std::fs::write(&out, signed)?;
    Ok(out)
}

/// Signs every file with one login. Fails as a whole only when the token or
/// PIN does; a file that cannot be signed is reported and skipped.
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
        let token = Token::open_default()?;
        let certs = token.signing_certificates()?;
        let cert = certs.get(args.cert_index).ok_or_else(|| CommandError {
            kind: "token",
            message: "The selected certificate is no longer on the token.".into(),
        })?;
        let mut signer = token.signer(cert, &args.pin)?;
        for (index, path) in args.paths.iter().enumerate() {
            let _ = progress.send(BatchProgress::Signing { index });
            let _ = progress.send(
                match sign_one(Path::new(path), &args, &image, &mut signer) {
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

/// Path of the PKCS#11 driver that will be used for the token, if one is installed.
#[tauri::command]
fn token_driver() -> Option<String> {
    signdesk_core::token::find_module().map(|p| p.to_string_lossy().into_owned())
}

/// PDFs handed over by the system: on the command line ("Open with",
/// "Sign with TrackMySign", drag onto the icon), by Finder, or by a second
/// launch while the app is running.
#[derive(Default)]
struct Opened {
    /// Set once the window has asked for its startup files; from then on new
    /// files are sent to it as `open-files` events.
    ready: bool,
    pending: Vec<String>,
}

/// Existing PDFs among `args`, relative paths resolved against `cwd`.
fn pdf_args(args: impl IntoIterator<Item = String>, cwd: &Path) -> Vec<String> {
    args.into_iter()
        .filter(|a| a.to_lowercase().ends_with(".pdf"))
        .map(|a| cwd.join(a))
        .filter(|p| p.is_file())
        .map(|p| p.to_string_lossy().into_owned())
        .collect()
}

fn hand_over(app: &AppHandle, files: Vec<String>) {
    if files.is_empty() {
        return;
    }
    let state = app.state::<Mutex<Opened>>();
    let mut opened = state.lock().unwrap_or_else(|p| p.into_inner());
    if opened.ready {
        let _ = app.emit("open-files", files);
    } else {
        opened.pending.extend(files);
    }
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

/// Files opened before the window was ready to receive them.
#[tauri::command]
fn startup_files(state: State<'_, Mutex<Opened>>) -> Vec<String> {
    let mut opened = state.lock().unwrap_or_else(|p| p.into_inner());
    opened.ready = true;
    std::mem::take(&mut opened.pending)
}

/// The first of [`startup_files`].
#[tauri::command]
fn startup_file(state: State<'_, Mutex<Opened>>) -> Option<String> {
    startup_files(state).into_iter().next()
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
    let opened = Opened {
        ready: false,
        pending: pdf_args(std::env::args().skip(1), &cwd),
    };
    let builder = tauri::Builder::default();
    // Must be the first plugin: a second launch hands its files to this one and exits.
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    let builder = builder.plugin(tauri_plugin_single_instance::init(|app, args, cwd| {
        hand_over(app, pdf_args(args.into_iter().skip(1), Path::new(&cwd)));
    }));
    builder
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(Mutex::new(opened))
        .invoke_handler(tauri::generate_handler![
            list_certificates,
            pdf_info,
            read_pdf,
            sign,
            sign_batch,
            startup_file,
            startup_files,
            signature_image,
            set_signature_image,
            clear_signature_image,
            token_driver,
            open_file,
            reveal_file,
            open_website
        ])
        .build(tauri::generate_context!())
        .expect("error while running TrackMySign")
        .run(on_run_event);
}

/// Finder: "Open With", drag onto the Dock icon, double-click when default.
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn on_run_event(app: &AppHandle, event: tauri::RunEvent) {
    if let tauri::RunEvent::Opened { urls } = event {
        let files = urls
            .iter()
            .filter_map(|u| u.to_file_path().ok())
            .map(|p| p.to_string_lossy().into_owned())
            .filter(|p| p.to_lowercase().ends_with(".pdf"))
            .collect();
        hand_over(app, files);
    }
}

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
fn on_run_event(_: &AppHandle, _: tauri::RunEvent) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pdf_args_resolve_and_filter() {
        let dir = std::env::temp_dir().join(format!("tms-args-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.pdf"), b"%PDF").unwrap();
        std::fs::write(dir.join("B.PDF"), b"%PDF").unwrap();
        std::fs::write(dir.join("notes.txt"), b"").unwrap();
        let abs = dir.join("B.PDF").to_string_lossy().into_owned();
        let args = ["a.pdf", "notes.txt", "missing.pdf", "--flag", abs.as_str()];
        let found = pdf_args(args.iter().map(|s| s.to_string()), &dir);
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(
            found,
            vec![dir.join("a.pdf").to_string_lossy().into_owned(), abs]
        );
    }
}
