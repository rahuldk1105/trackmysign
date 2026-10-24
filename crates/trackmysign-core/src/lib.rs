//! TrackMySign core: sign PDFs with a DSC token without disturbing the original.

pub mod certdetails;
pub mod certinfo;
pub mod cms;
pub mod folder;
mod http;
pub mod image;
pub mod ltv;
pub mod pdf;
pub mod portal;
pub mod report;
pub mod token;
pub mod tsa;
pub mod verify;
pub mod watch;

use std::path::{Path, PathBuf};

use chrono::{DateTime, FixedOffset, Local};
use sha2::{Digest, Sha256};

pub use image::{ImagePosition, StampImage};
pub use pdf::docmdp::DocMdp;
pub use pdf::reader::PdfError;
pub use pdf::sign::{DisplayRect, Placement};
pub use tsa::DEFAULT_TSA_URL;
pub use verify::{SignatureReport, verify, verify_with_password};

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
    /// RSA only: PKCS#1 v1.5 signature over a ready-made DER `DigestInfo`
    /// (the GST portal wants SHA-1, see [`portal::cms`]).
    fn sign_digest_info(&mut self, _digest_info: &[u8]) -> Result<Vec<u8>, Error> {
        Err(Error::Token(
            "This key cannot make this kind of signature.".into(),
        ))
    }
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
    #[error("Signature image: {0}")]
    Image(String),
    #[error("Timestamp failed: {0}")]
    Timestamp(String),
    #[error("Could not embed revocation info (LTV): {0}")]
    Ltv(String),
    /// The document's existing signatures rule this signature out.
    #[error("{0}")]
    NotPermitted(String),
}

#[derive(Debug, Clone, Default)]
pub struct SignRequest {
    pub page: usize,
    pub rect: Option<DisplayRect>,
    /// Pages that get the box (zero-based); empty means just `page`. `rect`
    /// is as drawn on `page` and repeated at the same spot on the others.
    pub pages: Vec<usize>,
    pub reason: Option<String>,
    pub location: Option<String>,
    /// Defaults to now, in local time.
    pub time: Option<DateTime<FixedOffset>>,
    /// Handwritten signature shown in the box (visible signatures only).
    pub image: Option<StampImage>,
    pub image_position: ImagePosition,
    /// RFC 3161 timestamp authority to countersign with (needs the internet).
    pub timestamp: Option<String>,
    /// Append OCSP/CRL data for the certificates in a `/DSS` (needs the internet).
    pub ltv: bool,
    /// Sign into this empty signature field (fully qualified name, as in
    /// [`PdfInfo::empty_fields`]); `page`, `rect` and `pages` are then unused.
    pub field: Option<String>,
    /// Password of a protected PDF (owner or user). Without one, the empty
    /// user password is tried. Never stored.
    pub password: Option<String>,
    /// Certify the document (an author signature) instead of approving it.
    pub certify: Option<DocMdp>,
}

/// Whether `input` may get a signature: a certification only on a document
/// without signatures, and nothing on one certified with "no changes".
pub fn check_permitted(input: &[u8], certify: Option<DocMdp>) -> Result<(), Error> {
    check_permitted_with_password(input, None, certify)
}

/// [`check_permitted`] for a password-protected PDF.
pub fn check_permitted_with_password(
    input: &[u8],
    password: Option<&str>,
    certify: Option<DocMdp>,
) -> Result<(), Error> {
    let doc = pdf::reader::Document::open(input, password)?;
    let signatures = pdf::fields::signature_fields(&doc, &doc.pages()?)?
        .iter()
        .filter(|f| f.signed)
        .count();
    let certified = pdf::docmdp::of_document(&doc)?;
    if certify.is_some() && (signatures > 0 || certified.is_some()) {
        return Err(Error::NotPermitted(
            "Only the first signature can certify a document, and this one is already signed. \
             Sign it as an approval signature instead."
                .into(),
        ));
    }
    if certified == Some(DocMdp::NoChanges) {
        return Err(Error::NotPermitted(
            "The document is certified with no changes allowed. \
             Another signature would invalidate the certification."
                .into(),
        ));
    }
    Ok(())
}

/// Signs `input` and returns the complete new file.
pub fn sign_pdf(
    input: &[u8],
    req: &SignRequest,
    signer: &mut dyn Signer,
) -> Result<Vec<u8>, Error> {
    let password = req.password.as_deref();
    check_permitted_with_password(input, password, req.certify)?;
    let summary = certinfo::CertSummary::from_der(signer.certificate())?;
    let time = req.time.unwrap_or_else(|| Local::now().fixed_offset());
    let fields = pdf::sign::SignatureFields {
        signer_name: summary.subject_cn.clone(),
        reason: req.reason.clone(),
        location: req.location.clone(),
        time,
        image: req.image.clone(),
        image_position: req.image_position,
        timestamp: req.timestamp.is_some(),
        certify: req.certify,
    };
    let placement = Placement {
        page: req.page,
        rect: req.rect,
        pages: req.pages.clone(),
        field: req.field.clone(),
    };
    let mut reserve = cms::estimate_size(signer);
    if req.timestamp.is_some() {
        reserve += tsa::TOKEN_RESERVE;
    }
    let prepared = pdf::sign::prepare_with_password(input, password, &placement, &fields, reserve)?;
    let mut h = Sha256::new();
    for part in prepared.signed_parts() {
        h.update(part);
    }
    let digest: [u8; 32] = h.finalize().into();
    let mut cms = cms::build_signed_data(signer, &digest, &time)?;
    if let Some(url) = &req.timestamp {
        let token = tsa::timestamp(url, &cms::signature_value(&cms)?)?;
        cms = cms::add_unsigned_attr(&cms, tsa::ID_AA_SIGNATURE_TIME_STAMP_TOKEN, &token)?;
    }
    let reserved = prepared.reserved;
    let signed = prepared.finish(&cms)?;
    if !req.ltv {
        return Ok(signed);
    }
    let data = ltv::collect(&cms)?;
    let mut contents = cms;
    contents.resize(reserved, 0);
    Ok(pdf::dss::append_with_password(
        &signed,
        password,
        &pdf::dss::Validation {
            contents: &contents,
            certs: &data.certs,
            ocsps: &data.ocsps,
            crls: &data.crls,
        },
    )?)
}

#[derive(Debug, Clone)]
pub struct PageSize {
    pub width: f64,
    pub height: f64,
    pub rotate: i32,
}

/// A signature field in the document that has not been signed yet.
#[derive(Debug, Clone)]
pub struct EmptyField {
    /// Fully qualified name, e.g. `approvals.director`.
    pub name: String,
    /// Zero-based page of its (first visible) widget.
    pub page: Option<usize>,
    /// As displayed on `page`; `None` for an invisible field.
    pub rect: Option<DisplayRect>,
}

#[derive(Debug, Clone)]
pub struct PdfInfo {
    pub pages: Vec<PageSize>,
    pub signatures: usize,
    /// Password-protected (possibly with an empty user password).
    pub encrypted: bool,
    /// The security settings, or the password given, allow adding a signature.
    pub signing_allowed: bool,
    /// Set when the document is certified.
    pub certified: Option<DocMdp>,
    pub empty_fields: Vec<EmptyField>,
}

pub fn inspect(input: &[u8]) -> Result<PdfInfo, Error> {
    inspect_with_password(input, None)
}

/// [`inspect`] for a password-protected PDF.
pub fn inspect_with_password(input: &[u8], password: Option<&str>) -> Result<PdfInfo, Error> {
    let doc = pdf::reader::Document::open(input, password)?;
    let page_info = doc.pages()?;
    let pages = page_info
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
    let fields = pdf::fields::signature_fields(&doc, &page_info)?;
    let signatures = fields.iter().filter(|f| f.signed).count();
    let empty_fields = fields
        .iter()
        .filter(|f| !f.signed)
        .map(|f| {
            let widget = f
                .widgets
                .iter()
                .find(|w| w.visible() && w.page.is_some())
                .or_else(|| f.widgets.iter().find(|w| w.page.is_some()));
            let page = widget.and_then(|w| w.page);
            EmptyField {
                name: f.name.clone(),
                page,
                rect: widget.filter(|w| w.visible()).and_then(|w| {
                    let p = &page_info[w.page?];
                    Some(pdf::fields::user_to_display(p, w.rect))
                }),
            }
        })
        .collect();
    Ok(PdfInfo {
        pages,
        signatures,
        encrypted: doc.crypt.is_some(),
        signing_allowed: doc.crypt.as_ref().is_none_or(|c| c.may_sign()),
        certified: pdf::docmdp::of_document(&doc)?,
        empty_fields,
    })
}

/// Parses a page selection such as `all` or `1-3,5` (numbered from 1) into
/// sorted zero-based page indexes.
pub fn parse_pages(spec: &str, count: usize) -> Result<Vec<usize>, String> {
    let spec = spec.trim();
    if spec.eq_ignore_ascii_case("all") {
        return Ok((0..count).collect());
    }
    let num = |s: &str| -> Result<usize, String> {
        match s.trim().parse::<usize>() {
            Ok(0) => Err("pages are numbered from 1".into()),
            Ok(n) if n > count => Err(format!("the PDF has only {count} page(s)")),
            Ok(n) => Ok(n - 1),
            Err(_) => Err(format!("\"{}\" is not a page number", s.trim())),
        }
    };
    let mut out = Vec::new();
    for part in spec.split(',').filter(|p| !p.trim().is_empty()) {
        match part.split_once('-') {
            Some((a, b)) => {
                let (a, b) = (num(a)?, num(b)?);
                if a > b {
                    return Err(format!("\"{}\" runs backwards", part.trim()));
                }
                out.extend(a..=b);
            }
            None => out.push(num(part)?),
        }
    }
    if out.is_empty() {
        return Err("no pages selected".into());
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

/// `invoice.pdf` → `invoice_signed.pdf` (or `invoice_signed_2.pdf`, … if taken).
pub fn signed_path(input: &Path) -> PathBuf {
    signed_path_in(input, input.parent().unwrap_or_else(|| Path::new(".")))
}

/// [`signed_path`], but in `dir` instead of next to the original.
pub fn signed_path_in(input: &Path, dir: &Path) -> PathBuf {
    let stem = input
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "document".into());
    let first = dir.join(format!("{stem}_signed.pdf"));
    if !first.exists() {
        return first;
    }
    (2..)
        .map(|n| dir.join(format!("{stem}_signed_{n}.pdf")))
        .find(|p| !p.exists())
        .unwrap()
}

/// Writes `data` to [`signed_path_in`] `dir` and returns the path used. The
/// file is created new, so one that appeared since the name was picked is
/// kept and the next name tried.
pub fn write_signed_in(input: &Path, dir: &Path, data: &[u8]) -> std::io::Result<PathBuf> {
    use std::io::Write;
    loop {
        let out = signed_path_in(input, dir);
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&out)
        {
            Ok(mut f) => {
                f.write_all(data)?;
                return Ok(out);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
}

impl From<der::Error> for Error {
    fn from(e: der::Error) -> Self {
        Error::Cms(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_lists() {
        assert_eq!(parse_pages("all", 3), Ok(vec![0, 1, 2]));
        assert_eq!(parse_pages(" 1-3, 5,2 ", 6), Ok(vec![0, 1, 2, 4]));
        assert_eq!(parse_pages("4", 4), Ok(vec![3]));
        assert!(parse_pages("0", 4).is_err());
        assert!(parse_pages("2-5", 4).is_err());
        assert!(parse_pages("3-1", 4).is_err());
        assert!(parse_pages("x", 4).is_err());
        assert!(parse_pages("", 4).is_err());
    }
}
