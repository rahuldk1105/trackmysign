//! `verify_pdf`: the signatures already in a document, for the inspector;
//! `export_report`: the same check as a PDF report for auditors.

use std::path::Path;

use serde::Serialize;
use tauri::AppHandle;
use trackmysign_core::report::Report;
use trackmysign_core::verify::{Changes, SignatureReport, Status, Trust};

use super::CmdResult;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureDto {
    field: String,
    /// "valid" | "invalid" | "unknown"
    status: &'static str,
    notes: Vec<String>,
    signer: Option<String>,
    organization: Option<String>,
    issuer: Option<String>,
    cert_valid_from: Option<String>,
    cert_valid_until: Option<String>,
    signing_time: Option<String>,
    time_in_validity: Option<bool>,
    timestamped: bool,
    reason: Option<String>,
    location: Option<String>,
    sub_filter: Option<String>,
    digest: Option<&'static str>,
    /// "none" | "signatures" | "form" | "content" | "unknown"
    changes: &'static str,
    later_revisions: usize,
    bytes_after: usize,
    chain: Vec<String>,
    /// "cca" | "notChecked"
    trust: &'static str,
    /// DocMDP level (1-3) of a certification signature.
    certification: Option<u8>,
}

impl From<&SignatureReport> for SignatureDto {
    fn from(r: &SignatureReport) -> Self {
        SignatureDto {
            field: r.field.clone(),
            status: match r.status {
                Status::Valid => "valid",
                Status::Invalid => "invalid",
                Status::Unknown => "unknown",
            },
            notes: r.notes.clone(),
            signer: r
                .signer
                .as_ref()
                .map(|s| s.subject.clone())
                .or_else(|| r.name.clone()),
            organization: r.signer.as_ref().and_then(|s| s.organization.clone()),
            issuer: r.signer.as_ref().map(|s| s.issuer.clone()),
            cert_valid_from: r
                .signer
                .as_ref()
                .map(|s| s.not_before.format("%d %b %Y").to_string()),
            cert_valid_until: r
                .signer
                .as_ref()
                .map(|s| s.not_after.format("%d %b %Y").to_string()),
            signing_time: r
                .signing_time
                .map(|t| t.format("%Y.%m.%d %H:%M:%S %:z").to_string()),
            time_in_validity: r.time_in_validity,
            timestamped: r.timestamped,
            reason: r.reason.clone(),
            location: r.location.clone(),
            sub_filter: r.sub_filter.clone(),
            digest: r.digest_algorithm,
            changes: match r.changes {
                Changes::None => "none",
                Changes::Signatures => "signatures",
                Changes::FormOrAnnotations => "form",
                Changes::Content => "content",
                Changes::Unknown => "unknown",
            },
            later_revisions: r.later_revisions,
            bytes_after: r.bytes_after(),
            chain: r.chain.iter().map(|c| c.subject.clone()).collect(),
            trust: match r.trust {
                Trust::CcaIndia => "cca",
                Trust::NotChecked => "notChecked",
            },
            certification: r.certification.map(|p| p.level()),
        }
    }
}

#[tauri::command]
pub async fn verify_pdf(path: String, password: Option<String>) -> CmdResult<Vec<SignatureDto>> {
    tauri::async_runtime::spawn_blocking(move || {
        let data = std::fs::read(&path)?;
        let reports = trackmysign_core::verify_with_password(&data, password.as_deref())?;
        Ok(reports.iter().map(SignatureDto::from).collect())
    })
    .await
    .map_err(|e| super::CommandError {
        kind: "other",
        message: e.to_string(),
    })?
}

/// Checks the signatures of `path` again and writes the verification report
/// (PDF) to `output`.
#[tauri::command]
pub async fn export_report(
    app: AppHandle,
    path: String,
    password: Option<String>,
    output: String,
) -> CmdResult<()> {
    let version = app.package_info().version.to_string();
    tauri::async_runtime::spawn_blocking(move || {
        let data = std::fs::read(&path)?;
        let name = Path::new(&path)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let report = Report::new(&data, &name, password.as_deref(), &version)?;
        std::fs::write(&output, report.to_pdf())?;
        Ok(())
    })
    .await
    .map_err(|e| super::CommandError {
        kind: "other",
        message: e.to_string(),
    })?
}
