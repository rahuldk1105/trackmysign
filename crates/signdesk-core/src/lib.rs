//! TrackMySign core: sign PDFs with a DSC token without disturbing the original.

pub mod certinfo;
pub mod cms;
pub mod pdf;
pub mod token;
pub mod verify;

use std::path::{Path, PathBuf};

use chrono::{DateTime, FixedOffset, Local};
use sha2::{Digest, Sha256};

pub use pdf::reader::PdfError;
pub use pdf::sign::{DisplayRect, Placement};
pub use verify::{SignatureReport, verify};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    Rsa,
    Ec,
}

/// Something that holds a private key: a USB token, or a software key in tests.
pub trait Signer {
    fn certificate(&self) -> &[u8];
    /// Issuer certificates to embed (may be empty).
    fn chain(&self) -> &[Vec<u8>];
    fn key_kind(&self) -> KeyKind;
    fn signature_len(&self) -> usize;
    /// RSA: PKCS#1 v1.5 signature. EC: DER `ECDSA-Sig-Value`.
    fn sign_sha256(&mut self, digest: &[u8; 32]) -> Result<Vec<u8>, Error>;
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Pdf(#[from] PdfError),
    #[error("{0}")]
    Token(String),
    #[error("Wrong PIN.{}", if *final_try { " One attempt left before the token locks!" } else if *count_low { " Careful: few attempts left before the token locks." } else { "" })]
    WrongPin { final_try: bool, count_low: bool },
    #[error("The token PIN is locked. Contact your DSC provider to unlock it.")]
    PinLocked,
    #[error("signature encoding failed: {0}")]
    Cms(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Default)]
pub struct SignRequest {
    pub page: usize,
    pub rect: Option<DisplayRect>,
    pub reason: Option<String>,
    pub location: Option<String>,
    /// Defaults to now, in local time.
    pub time: Option<DateTime<FixedOffset>>,
}

/// Signs `input` and returns the complete new file.
pub fn sign_pdf(
    input: &[u8],
    req: &SignRequest,
    signer: &mut dyn Signer,
) -> Result<Vec<u8>, Error> {
    let summary = certinfo::CertSummary::from_der(signer.certificate())?;
    let time = req.time.unwrap_or_else(|| Local::now().fixed_offset());
    let fields = pdf::sign::SignatureFields {
        signer_name: summary.subject_cn.clone(),
        reason: req.reason.clone(),
        location: req.location.clone(),
        time,
    };
    let placement = Placement {
        page: req.page,
        rect: req.rect,
    };
    let prepared = pdf::sign::prepare(input, &placement, &fields, cms::estimate_size(signer))?;
    let mut h = Sha256::new();
    for part in prepared.signed_parts() {
        h.update(part);
    }
    let digest: [u8; 32] = h.finalize().into();
    let cms = cms::build_signed_data(signer, &digest, &time)?;
    Ok(prepared.finish(&cms)?)
}

#[derive(Debug, Clone)]
pub struct PageSize {
    pub width: f64,
    pub height: f64,
    pub rotate: i32,
}

#[derive(Debug, Clone)]
pub struct PdfInfo {
    pub pages: Vec<PageSize>,
    pub signatures: usize,
}

pub fn inspect(input: &[u8]) -> Result<PdfInfo, Error> {
    let doc = pdf::reader::Document::parse(input)?;
    let pages = doc
        .pages()?
        .iter()
        .map(|p| {
            let (width, height) = p.display_size();
            PageSize {
                width,
                height,
                rotate: p.rotate,
            }
        })
        .collect();
    let (_, signatures) = doc.form_fields()?;
    Ok(PdfInfo { pages, signatures })
}

/// `invoice.pdf` → `invoice_signed.pdf` (or `invoice_signed_2.pdf`, … if taken).
pub fn signed_path(input: &Path) -> PathBuf {
    let stem = input
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "document".into());
    let dir = input.parent().unwrap_or_else(|| Path::new("."));
    let first = dir.join(format!("{stem}_signed.pdf"));
    if !first.exists() {
        return first;
    }
    (2..)
        .map(|n| dir.join(format!("{stem}_signed_{n}.pdf")))
        .find(|p| !p.exists())
        .unwrap()
}

impl From<der::Error> for Error {
    fn from(e: der::Error) -> Self {
        Error::Cms(e.to_string())
    }
}
