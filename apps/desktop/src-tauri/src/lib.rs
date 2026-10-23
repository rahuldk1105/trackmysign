//! Tauri backend: thin commands over `signdesk-core`.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use signdesk_core::token::Token;
use signdesk_core::{DisplayRect, Error, SignRequest, inspect, sign_pdf, signed_path};
use tauri::ipc::Response;

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
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SignedDto {
    output: String,
    name: String,
}

#[tauri::command]
async fn sign(args: SignArgs) -> CmdResult<SignedDto> {
    tauri::async_runtime::spawn_blocking(move || {
        let input = PathBuf::from(&args.path);
        let data = std::fs::read(&input)?;
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
            time: None,
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

/// A PDF passed on the command line ("Open with TrackMySign", drag onto the icon).
#[tauri::command]
fn startup_file() -> Option<String> {
    std::env::args()
        .skip(1)
        .find(|a| a.to_lowercase().ends_with(".pdf") && Path::new(a).is_file())
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            list_certificates,
            pdf_info,
            read_pdf,
            sign,
            startup_file,
            open_file,
            reveal_file
        ])
        .run(tauri::generate_context!())
        .expect("error while running TrackMySign");
}
