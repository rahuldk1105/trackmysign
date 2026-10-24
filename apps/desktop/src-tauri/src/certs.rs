//! Certificate details and export: only the public certificate (and its
//! issuers) ever leaves the token.

use std::path::Path;

use serde::{Deserialize, Serialize};
use signdesk_core::certdetails::{
    CertificateDetails, complete_chain, export_file_name, to_p7b, to_pem,
};
use signdesk_core::certinfo::{CertSummary, days_until};
use signdesk_core::token::{Token, TokenCert};
use tauri::{AppHandle, Manager};
use tauri_plugin_dialog::DialogExt;

use super::{CmdResult, CommandError, TOKEN_LOCK};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NamedOid {
    oid: String,
    name: Option<&'static str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainCertDto {
    name: String,
    issuer: String,
    valid_until: String,
    /// The CCA India 2022 root built into the app, not read from the token.
    built_in: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DetailsDto {
    name: String,
    organization: Option<String>,
    subject_serial: Option<String>,
    email: Option<String>,
    subject: String,
    issuer: String,
    issuer_name: String,
    serial: String,
    valid_from: String,
    valid_until: String,
    days_left: i64,
    key: String,
    key_usage: Option<Vec<&'static str>>,
    extended_key_usage: Vec<NamedOid>,
    policies: Vec<NamedOid>,
    sha1: String,
    sha256: String,
    /// Issuers above the certificate, nearest first.
    chain: Vec<ChainCertDto>,
}

/// The certificate and its issuer chain, read without a PIN.
fn read(cert_id: &str, driver_path: &str) -> CmdResult<(TokenCert, Vec<Vec<u8>>, usize)> {
    let _guard = TOKEN_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let token = Token::open(Path::new(driver_path))?;
    let cert = token
        .signing_certificates()?
        .into_iter()
        .find(|c| c.fingerprint() == cert_id)
        .ok_or_else(|| CommandError {
            kind: "token",
            message: "The selected certificate is no longer on the token.".into(),
        })?;
    let from_token = token.chain(&cert);
    let chain = complete_chain(&cert.der, &from_token);
    Ok((cert, chain, from_token.len()))
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> CmdResult<T> + Send + 'static,
) -> CmdResult<T> {
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|e| CommandError {
            kind: "other",
            message: e.to_string(),
        })?
}

#[tauri::command]
pub async fn certificate_details(cert_id: String, driver_path: String) -> CmdResult<DetailsDto> {
    blocking(move || {
        let (cert, chain, on_token) = read(&cert_id, &driver_path)?;
        let d = CertificateDetails::from_der(&cert.der)?;
        let named = |v: Vec<(String, Option<&'static str>)>| {
            v.into_iter()
                .map(|(oid, name)| NamedOid { oid, name })
                .collect()
        };
        let mut chain_dto = Vec::new();
        for (i, der) in chain.iter().enumerate() {
            let s = CertSummary::from_der(der)?;
            chain_dto.push(ChainCertDto {
                name: s.subject_cn,
                issuer: s.issuer_cn,
                valid_until: s.not_after.format("%d %b %Y").to_string(),
                built_in: i >= on_token,
            });
        }
        Ok(DetailsDto {
            days_left: days_until(chrono::Utc::now(), d.not_after),
            valid_from: d.not_before.format("%d %b %Y %H:%M UTC").to_string(),
            valid_until: d.not_after.format("%d %b %Y %H:%M UTC").to_string(),
            extended_key_usage: named(
                d.extended_key_usage
                    .into_iter()
                    .map(|u| (u.oid, u.name))
                    .collect(),
            ),
            policies: named(d.policies.into_iter().map(|p| (p.oid, p.name)).collect()),
            name: d.name,
            organization: d.organization,
            subject_serial: d.subject_serial,
            email: d.email,
            subject: d.subject,
            issuer: d.issuer,
            issuer_name: d.issuer_name,
            serial: d.serial_hex,
            key: d.key,
            key_usage: d.key_usage,
            sha1: d.sha1,
            sha256: d.sha256,
            chain: chain_dto,
        })
    })
    .await
}

#[derive(Deserialize, Clone, Copy)]
#[serde(rename_all = "camelCase")]
pub enum ExportFormat {
    /// DER, `.cer`.
    Der,
    Pem,
    /// The certificate and its issuers, PKCS#7 certs-only, `.p7b`.
    Chain,
}

/// Asks where to save and writes the public certificate there. Returns the
/// path, or none when the dialog was cancelled.
#[tauri::command]
pub async fn export_certificate(
    app: AppHandle,
    cert_id: String,
    driver_path: String,
    format: ExportFormat,
) -> CmdResult<Option<String>> {
    blocking(move || {
        let (cert, chain, _) = read(&cert_id, &driver_path)?;
        let (data, ext, kind) = match format {
            ExportFormat::Der => (cert.der.clone(), "cer", "Certificate (DER)"),
            ExportFormat::Pem => (to_pem(&cert.der).into_bytes(), "pem", "Certificate (PEM)"),
            ExportFormat::Chain => {
                let mut all = vec![cert.der.clone()];
                all.extend(chain);
                (to_p7b(&all)?, "p7b", "Certificate chain (PKCS#7)")
            }
        };
        let mut dialog = app
            .dialog()
            .file()
            .set_title("Save certificate")
            .set_file_name(export_file_name(&cert.summary.subject_cn, ext))
            .add_filter(kind, &[ext]);
        if let Some(w) = app.get_webview_window("main") {
            dialog = dialog.set_parent(&w);
        }
        let Some(path) = dialog.blocking_save_file() else {
            return Ok(None);
        };
        let path = path.into_path().map_err(|e| CommandError {
            kind: "io",
            message: e.to_string(),
        })?;
        std::fs::write(&path, data)?;
        Ok(Some(path.to_string_lossy().into_owned()))
    })
    .await
}
