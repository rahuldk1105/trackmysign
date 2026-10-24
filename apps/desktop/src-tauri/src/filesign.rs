//! Signing and checking files other than PDFs: `file_info` for the file
//! panel (size, SHA-256, the `.p7s` next to it checked), `sign_files` for a
//! batch with one PIN, `extract_signed` for "Save original" of a `.p7m`.

use std::path::Path;

use serde::{Deserialize, Serialize};
use tauri::AppHandle;
use tauri::ipc::Channel;
use trackmysign_core::filesig::{self, FileCheck, FileSignRequest};
use trackmysign_core::history::{Entry, Source};
use trackmysign_core::token::{Token, TokenCert};

use super::verify::SignatureDto;
use super::{BatchProgress, CmdResult, CommandError, TOKEN_LOCK, history};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileCheckDto {
    #[serde(flatten)]
    signature: SignatureDto,
    /// The file is inside the signature (`.p7m`).
    attached: bool,
}

impl From<&FileCheck> for FileCheckDto {
    fn from(c: &FileCheck) -> Self {
        FileCheckDto {
            signature: SignatureDto::from(&c.report),
            attached: c.attached,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileInfoDto {
    path: String,
    name: String,
    size: u64,
    /// "file" (to sign) or "signature" (a `.p7s` / `.p7m` to check).
    kind: &'static str,
    /// Of the file; for a signature, of the content it signs, when known.
    sha256: Option<String>,
    /// The signature that was checked: next to the file, or the file itself.
    signature_path: Option<String>,
    check: Option<FileCheckDto>,
    /// Why the signature could not be read.
    error: Option<String>,
    /// For a signature: the signed file found next to it.
    signed_path: Option<String>,
    /// `.p7s` / `.p7m` already next to the file (signing replaces it).
    has_p7s: bool,
    has_p7m: bool,
}

fn name_of(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn info(path: &Path) -> CmdResult<FileInfoDto> {
    let size = std::fs::metadata(path)?.len();
    let mut dto = FileInfoDto {
        path: path.to_string_lossy().into_owned(),
        name: name_of(path),
        size,
        kind: "file",
        sha256: None,
        signature_path: None,
        check: None,
        error: None,
        signed_path: None,
        has_p7s: filesig::signature_path(path, false).exists(),
        has_p7m: filesig::signature_path(path, true).exists(),
    };
    let data = std::fs::read(path)?;
    let (signature, content, name) = if filesig::is_signature_file(path) {
        dto.kind = "signature";
        let signed = filesig::signed_file_path(path).filter(|p| p.is_file());
        dto.signed_path = signed.as_ref().map(|p| p.to_string_lossy().into_owned());
        let content = signed.as_deref().map(std::fs::read).transpose()?;
        let name = signed.as_deref().map_or_else(|| name_of(path), name_of);
        (Some((path.to_path_buf(), data)), content, name)
    } else {
        dto.sha256 = Some(filesig::sha256_hex(&data));
        let sig = filesig::find_signature(path)
            .map(|p| std::fs::read(&p).map(|d| (p, d)))
            .transpose()?;
        (sig, Some(data), dto.name.clone())
    };
    if let Some((sig_path, sig)) = signature {
        dto.signature_path = Some(sig_path.to_string_lossy().into_owned());
        // A .p7m is checked on what it carries, not on a file beside it.
        let attached = filesig::read_signature(&sig)
            .and_then(|der| filesig::content(&der))
            .is_ok_and(|c| c.is_some());
        let content = if attached && dto.kind == "signature" {
            None
        } else {
            content
        };
        match filesig::verify_file(&sig, content.as_deref(), &name) {
            Ok(c) => {
                if dto.sha256.is_none() {
                    dto.sha256 = c.sha256.clone();
                }
                dto.check = Some(FileCheckDto::from(&c));
            }
            Err(e) => dto.error = Some(e.to_string()),
        }
    }
    Ok(dto)
}

/// Size, SHA-256 and the signature check of a file for the file panel.
#[tauri::command]
pub async fn file_info(path: String) -> CmdResult<FileInfoDto> {
    tauri::async_runtime::spawn_blocking(move || info(Path::new(&path)))
        .await
        .map_err(|e| CommandError {
            kind: "other",
            message: e.to_string(),
        })?
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileSignArgs {
    paths: Vec<String>,
    /// `.p7m` with the file inside, instead of a `.p7s` next to it.
    attached: bool,
    cert_id: String,
    driver_path: String,
    pin: String,
    #[serde(default)]
    timestamp: Option<String>,
}

/// The history entry for signing `path`.
fn file_entry(path: &Path, req: &FileSignRequest, cert: &TokenCert, source: Source) -> Entry {
    let mut e = Entry::file_signing(source, history::PROGRAM, path, req);
    e.cert_der(&cert.der);
    e
}

/// Signs one file and records it in the history.
fn sign_one(
    app: &AppHandle,
    path: &Path,
    req: &FileSignRequest,
    mut entry: Entry,
    signer: &mut dyn trackmysign_core::Signer,
) -> CmdResult<std::path::PathBuf> {
    let result = (|| -> CmdResult<(std::path::PathBuf, Vec<u8>)> {
        let data = std::fs::read(path)?;
        entry.input_data(&data);
        let sig = filesig::sign_file(&data, req, signer)?;
        let out = filesig::signature_path(path, req.attached);
        // The panel said that an existing signature would be replaced.
        filesig::write_signature(&out, &sig, true)?;
        Ok((out, sig))
    })();
    match result {
        Ok((out, sig)) => {
            history::record(app, entry.signed(&out, &sig));
            Ok(out)
        }
        Err(e) => {
            history::record(app, entry.failed(e.message.clone()));
            Err(e)
        }
    }
}

/// Signs every file with one login, writing `<file>.p7s` (or `.p7m`) next
/// to it. Fails as a whole only when the token or PIN does; a file that
/// cannot be signed is reported and skipped.
#[tauri::command]
pub async fn sign_files(
    app: AppHandle,
    args: FileSignArgs,
    progress: Channel<BatchProgress>,
) -> CmdResult<()> {
    tauri::async_runtime::spawn_blocking(move || {
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
        let req = FileSignRequest {
            attached: args.attached,
            timestamp: super::trimmed_url(args.timestamp.clone()),
            ..Default::default()
        };
        let source = if args.paths.len() == 1 {
            Source::Manual
        } else {
            Source::Batch
        };
        let login = super::not_expired(cert)
            .and_then(|()| super::watch::check_pin(&app, cert, &args.pin))
            .and_then(|()| Ok(token.signer(cert, &args.pin)?));
        let mut signer = match login {
            Ok(s) => s,
            Err(e) => {
                for path in &args.paths {
                    let entry = file_entry(Path::new(path), &req, cert, source);
                    history::record(&app, entry.failed(e.message.clone()));
                }
                return Err(e);
            }
        };
        for (index, path) in args.paths.iter().enumerate() {
            let _ = progress.send(BatchProgress::Signing { index });
            let entry = file_entry(Path::new(path), &req, cert, source);
            let _ = progress.send(
                match sign_one(&app, Path::new(path), &req, entry, &mut signer) {
                    // Another attempt with the same PIN could lock the token; a
                    // timestamp server that is down fails every file the same way.
                    Err(e) if matches!(e.kind, "wrongPin" | "pinLocked" | "timestamp") => {
                        return Err(e);
                    }
                    Ok(out) => BatchProgress::Done {
                        index,
                        name: name_of(&out),
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

/// Where "Save original" offers to put the file inside a `.p7m`.
#[tauri::command]
pub fn original_path(path: String) -> String {
    filesig::original_path(Path::new(&path))
        .to_string_lossy()
        .into_owned()
}

/// Writes the file carried inside the `.p7m` at `path` to `output`.
#[tauri::command]
pub async fn extract_signed(path: String, output: String) -> CmdResult<()> {
    tauri::async_runtime::spawn_blocking(move || {
        let der = filesig::read_signature(&std::fs::read(&path)?)?;
        let content = filesig::content(&der)?.ok_or_else(|| CommandError {
            kind: "other",
            message: "The signature is detached: the file is not inside it.".into(),
        })?;
        std::fs::write(&output, content)?;
        Ok(())
    })
    .await
    .map_err(|e| CommandError {
        kind: "other",
        message: e.to_string(),
    })?
}
