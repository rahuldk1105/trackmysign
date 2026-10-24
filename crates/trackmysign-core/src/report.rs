//! Verification report for auditors: the results of [`verify`] for one file,
//! with the file's SHA-256 and the time of the check, as an A4 PDF or as
//! JSON for automation (schema in the README, "Verification reports").
//!
//! [`verify`]: crate::verify::verify

use chrono::{DateTime, FixedOffset, SecondsFormat, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::pdf::appearance::Face;
use crate::pdf::docmdp::DocMdp;
use crate::pdf::textdoc::{Rgb, Style, TextDoc, transliterate};
use crate::verify::{CertDetails, Changes, SignatureReport, Status, Trust};
use crate::{Error, inspect_with_password, verify_with_password};

/// What the verifier checks, and what it does not (see `verify.rs`).
pub const SCOPE: &str = "Checks that the signed bytes are intact, that each signature matches \
    the signer's certificate, whether the certificates in the signature chain to the CCA India \
    2022 root, and what changed after each signature. Certificate revocation (CRL/OCSP) and \
    timestamp tokens are not checked, even when the PDF contains them (LTV).";

/// Version of the JSON layout; raised only when a field changes meaning or
/// is removed. New fields may appear without a new version.
pub const SCHEMA_VERSION: u32 = 1;

/// The JSON's `checked` and `not_checked`.
pub(crate) const CHECKED: &[&str] = &[
    "integrity",
    "signature",
    "certificate_chain",
    "changes_after_signing",
];
pub(crate) const NOT_CHECKED: &[&str] = &["revocation", "timestamp_token"];

const IST_SECS: i32 = 5 * 3600 + 30 * 60;

pub(crate) const INK: Rgb = [0.1, 0.1, 0.1];
pub(crate) const MUTED: Rgb = [0.42, 0.42, 0.42];
pub(crate) const LINE: Rgb = [0.8, 0.8, 0.8];
/// #1B3A8C, the app's accent.
pub(crate) const ACCENT: Rgb = [0.106, 0.227, 0.549];
pub(crate) const OK: Rgb = [0.09, 0.43, 0.21];
pub(crate) const BAD: Rgb = [0.72, 0.11, 0.11];

pub struct Report {
    pub file_name: String,
    pub file_size: usize,
    /// Lower-case hex.
    pub sha256: String,
    /// `None` when the page tree could not be read.
    pub pages: Option<usize>,
    pub encrypted: bool,
    pub checked_at: DateTime<Utc>,
    /// TrackMy Sign version that made the check.
    pub version: String,
    /// In signing order.
    pub signatures: Vec<SignatureReport>,
}

impl Report {
    /// Checks `data` now.
    pub fn new(
        data: &[u8],
        file_name: &str,
        password: Option<&str>,
        version: &str,
    ) -> Result<Report, Error> {
        let signatures = verify_with_password(data, password)?;
        // A damaged page tree does not stop the signatures being checked.
        let info = inspect_with_password(data, password).ok();
        Ok(Report {
            file_name: file_name.to_string(),
            file_size: data.len(),
            sha256: Sha256::digest(data)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
            pages: info.as_ref().map(|i| i.pages.len()),
            encrypted: info.is_some_and(|i| i.encrypted),
            checked_at: Utc::now(),
            version: version.to_string(),
            signatures,
        })
    }

    fn count(&self, s: Status) -> usize {
        self.signatures.iter().filter(|r| r.status == s).count()
    }

    /// Every signature valid and no content changed after any of them.
    pub fn all_valid(&self) -> bool {
        !self.signatures.is_empty()
            && self.count(Status::Valid) == self.signatures.len()
            && !self.content_changed()
            && !self.certification_broken()
    }

    pub fn content_changed(&self) -> bool {
        self.signatures
            .iter()
            .any(|r| r.changes == Changes::Content)
    }

    /// Changed after a certification that allowed no changes (as `verify` notes it).
    pub fn certification_broken(&self) -> bool {
        self.signatures.iter().any(|r| {
            r.certification == Some(DocMdp::NoChanges)
                && (matches!(r.changes, Changes::FormOrAnnotations | Changes::Content)
                    || self.signatures.iter().any(|o| o.signed_len > r.signed_len))
        })
    }

    /// One line: "3 signatures — all valid, document unchanged since the
    /// last signature", or what is wrong.
    pub fn summary(&self) -> String {
        let n = self.signatures.len();
        let Some(last) = self.signatures.last() else {
            return "No signatures found.".into();
        };
        let (invalid, unknown) = (self.count(Status::Invalid), self.count(Status::Unknown));
        let status = match (invalid, unknown) {
            (0, 0) if n == 1 => "valid".to_string(),
            (0, 0) => "all valid".to_string(),
            _ if n == 1 && invalid == 1 => "INVALID".to_string(),
            _ if n == 1 => "could not be verified".to_string(),
            _ if invalid == n => "all INVALID".to_string(),
            _ => {
                let mut parts = Vec::new();
                let valid = n - invalid - unknown;
                if valid > 0 {
                    parts.push(format!("{valid} valid"));
                }
                if invalid > 0 {
                    parts.push(format!("{invalid} INVALID"));
                }
                if unknown > 0 {
                    parts.push(format!("{unknown} could not be verified"));
                }
                parts.join(", ")
            }
        };
        let since = if n == 1 {
            "since it was signed"
        } else {
            "since the last signature"
        };
        let changes = match self
            .signatures
            .iter()
            .position(|r| r.changes == Changes::Content)
        {
            Some(_) if n == 1 => "CONTENT CHANGED after signing".to_string(),
            Some(i) => format!("CONTENT CHANGED after signature {}", i + 1),
            // What came after a signature that does not hold means nothing.
            None if last.status != Status::Valid => String::new(),
            None => match last.changes {
                Changes::None => format!("document unchanged {since}"),
                Changes::Signatures => format!("only signatures or validation data added {since}"),
                Changes::FormOrAnnotations => format!("form filled in or comments added {since}"),
                Changes::Content | Changes::Unknown => {
                    format!("changes {since} could not be analysed")
                }
            },
        };
        let mut line = format!("{} — {status}", plural(n, "signature"));
        if !changes.is_empty() {
            line = format!("{line}, {changes}");
        }
        if self.certification_broken() {
            line.push_str("; changed after a certification that allowed no changes");
        }
        line
    }

    // ------------------------------------------------------------- PDF

    pub fn to_pdf(&self) -> Vec<u8> {
        let title = Style::new(Face::Bold, 18.0, INK);
        let heading = Style::new(Face::Bold, 11.0, INK);
        let label = Style::new(Face::Regular, 9.0, MUTED);
        let value = Style::new(Face::Regular, 9.5, INK);
        let tone = |ok: bool, bad: bool| match (ok, bad) {
            (true, _) => OK,
            (_, true) => BAD,
            _ => INK,
        };
        const LABEL_WIDTH: f64 = 128.0;

        let mut d = TextDoc::new(&format!(
            "Generated by TrackMy Sign v{}. {SCOPE}",
            self.version
        ));
        d.paragraph("Signature verification report", title);
        d.rule(1.5, ACCENT, 8.0);
        let bad = self.count(Status::Invalid) > 0
            || self.content_changed()
            || self.certification_broken();
        d.paragraph(
            &self.summary(),
            Style::new(Face::Bold, 11.0, tone(self.all_valid(), bad)),
        );
        d.space(10.0);

        d.paragraph("Document", heading);
        d.space(3.0);
        let mut rows = vec![
            ("File", shown(&self.file_name)),
            ("SHA-256", self.sha256.clone()),
            ("Size", format!("{} bytes", thousands(self.file_size))),
            ("Pages", self.pages.map_or("—".into(), |n| n.to_string())),
        ];
        if self.encrypted {
            rows.push(("Protection", "Password-protected".into()));
        }
        rows.push(("Checked", ist_and_utc(self.checked_at)));
        rows.push(("Checked with", format!("TrackMy Sign {}", self.version)));
        for (k, v) in &rows {
            d.row(k, label, v, value, LABEL_WIDTH);
        }

        let n = self.signatures.len();
        for (i, r) in self.signatures.iter().enumerate() {
            d.keep(120.0);
            d.rule(0.5, LINE, 12.0);
            let (word, color) = verdict(r);
            d.paragraph(
                &format!("Signature {} of {n}: {word}", i + 1),
                Style::new(Face::Bold, 11.0, color),
            );
            d.space(3.0);
            for (k, v) in signature_rows(r) {
                let style = match k {
                    "Coverage" if r.changes == Changes::Content => Style {
                        color: BAD,
                        ..value
                    },
                    "Status" if r.status == Status::Invalid => Style {
                        color: BAD,
                        ..value
                    },
                    _ => value,
                };
                d.row(k, label, &v, style, LABEL_WIDTH);
            }
        }
        if n == 0 {
            d.space(6.0);
            d.paragraph("The document has no signed signature fields.", value);
        }
        d.finish(
            &format!("Signature verification report: {}", self.file_name),
            &format!("TrackMy Sign {}", self.version),
            self.checked_at,
        )
    }

    // ------------------------------------------------------------ JSON

    /// Pretty-printed JSON, schema version [`SCHEMA_VERSION`].
    pub fn to_json(&self) -> String {
        let doc = JsonReport {
            schema: "trackmysign.verification-report",
            schema_version: SCHEMA_VERSION,
            generator: format!("TrackMy Sign {}", self.version),
            checked_at: self.checked_at.to_rfc3339_opts(SecondsFormat::Secs, true),
            file: JsonFile {
                name: &self.file_name,
                size: self.file_size,
                sha256: &self.sha256,
                pages: self.pages,
                encrypted: self.encrypted,
            },
            summary: JsonSummary {
                text: self.summary(),
                signatures: self.signatures.len(),
                valid: self.count(Status::Valid),
                invalid: self.count(Status::Invalid),
                unknown: self.count(Status::Unknown),
                content_changed: self.content_changed(),
                all_valid: self.all_valid(),
            },
            checked: CHECKED,
            not_checked: NOT_CHECKED,
            signatures: self
                .signatures
                .iter()
                .enumerate()
                .map(|(i, r)| JsonSignature::new(i + 1, r))
                .collect(),
        };
        serde_json::to_string_pretty(&doc).expect("report serialises")
    }
}

/// "Valid", "Invalid", … and its colour, for a signature's heading.
pub(crate) fn verdict(r: &SignatureReport) -> (&'static str, Rgb) {
    match r.status {
        Status::Valid if r.changes == Changes::Content => ("Valid, content changed later", BAD),
        Status::Valid => ("Valid", OK),
        Status::Invalid => ("Invalid", BAD),
        Status::Unknown => ("Unknown", INK),
    }
}

pub(crate) fn signature_rows(r: &SignatureReport) -> Vec<(&'static str, String)> {
    let dash = || "—".to_string();
    let opt = |v: &Option<String>| v.as_deref().map_or_else(dash, shown);
    let mut rows = vec![
        (
            "Status",
            match r.status {
                Status::Valid => {
                    "Valid: the signed bytes are intact and the signature matches the certificate"
                }
                Status::Invalid => {
                    "Invalid: the signed bytes were altered or the signature does not match"
                }
                Status::Unknown => "Unknown: the signature could not be checked",
            }
            .to_string(),
        ),
        ("Field", shown(&r.field)),
    ];
    match &r.signer {
        Some(s) => rows.extend([
            ("Signer", shown(&s.subject)),
            ("Organisation", opt(&s.organization)),
            ("Issuer", shown(&s.issuer)),
            ("Certificate serial", s.serial_hex.clone()),
            (
                "Certificate validity",
                format!(
                    "{} to {}",
                    s.not_before.format("%d %b %Y, %H:%M:%S UTC"),
                    s.not_after.format("%d %b %Y, %H:%M:%S UTC")
                ),
            ),
        ]),
        None => rows.push((
            "Signer",
            match &r.name {
                Some(n) => format!("{} (certificate not found)", shown(n)),
                None => "Unknown (certificate not found)".into(),
            },
        )),
    }
    rows.push((
        "Signing time",
        match r.signing_time {
            Some(t) => format!(
                "{}, signer's clock{}",
                ist_and_utc(t.with_timezone(&Utc)),
                match r.time_in_validity {
                    Some(false) => ", OUTSIDE the certificate's validity",
                    _ => "",
                }
            ),
            None => dash(),
        },
    ));
    rows.push((
        "Timestamp",
        if r.timestamped {
            "Present (the timestamp token is not verified)".into()
        } else {
            "None".into()
        },
    ));
    rows.push(("Reason", opt(&r.reason)));
    rows.push(("Location", opt(&r.location)));
    if let Some(p) = r.certification {
        rows.push((
            "Certification",
            format!("Level {}: {}", p.level(), allowed(p)),
        ));
    }
    rows.push(("Coverage", coverage(r)));
    rows.push((
        "Chain to CCA India",
        match r.trust {
            Trust::CcaIndia => "Yes, chains to the CCA India 2022 root".into(),
            Trust::NotChecked => "Not checked (no chain to a known root)".into(),
        },
    ));
    if r.chain.len() > 1 {
        let names: Vec<String> = r.chain.iter().map(|c| shown(&c.subject)).collect();
        rows.push(("Certificate chain", names.join(" < ")));
    }
    let format: Vec<&str> = [r.sub_filter.as_deref(), r.digest_algorithm]
        .into_iter()
        .flatten()
        .collect();
    if !format.is_empty() {
        rows.push(("Format", format.join(", ")));
    }
    for (i, n) in r.notes.iter().enumerate() {
        rows.push((if i == 0 { "Notes" } else { "" }, shown(n)));
    }
    rows
}

fn allowed(p: DocMdp) -> &'static str {
    match p {
        DocMdp::NoChanges => "no changes allowed",
        DocMdp::FormFilling => "form filling and signing allowed",
        DocMdp::Annotations => "form filling, signing and comments allowed",
    }
}

fn coverage(r: &SignatureReport) -> String {
    let later = plural(r.later_revisions, "later revision");
    match r.changes {
        Changes::None => "Covers the whole document".into(),
        Changes::Signatures => format!("{later}: signatures only"),
        Changes::FormOrAnnotations => format!("{later}: form filling or comments"),
        Changes::Content => format!("{later}: CONTENT CHANGED"),
        Changes::Unknown if r.signed_len == 0 => "Could not be determined".into(),
        Changes::Unknown => format!(
            "{later} ({} bytes): could not be analysed",
            thousands(r.bytes_after())
        ),
    }
}

/// Text from the document as the report shows it, marked when it had to be
/// transliterated (the JSON keeps the original).
pub(crate) fn shown(s: &str) -> String {
    let t = transliterate(s);
    if t == s {
        t
    } else {
        format!("{t} (transliterated)")
    }
}

pub(crate) fn plural(n: usize, what: &str) -> String {
    if n == 1 {
        format!("1 {what}")
    } else {
        format!("{n} {what}s")
    }
}

pub(crate) fn thousands(n: usize) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// "24 Oct 2026, 15:00:12 IST (09:30:12 UTC)"; the UTC date is repeated
/// when it differs.
pub(crate) fn ist_and_utc(t: DateTime<Utc>) -> String {
    let ist = t.with_timezone(&FixedOffset::east_opt(IST_SECS).unwrap());
    let utc = if ist.date_naive() == t.date_naive() {
        t.format("%H:%M:%S UTC")
    } else {
        t.format("%d %b %Y, %H:%M:%S UTC")
    };
    format!("{} IST ({utc})", ist.format("%d %b %Y, %H:%M:%S"))
}

// ------------------------------------------------------------ JSON types

#[derive(Serialize)]
struct JsonReport<'a> {
    schema: &'static str,
    schema_version: u32,
    generator: String,
    checked_at: String,
    file: JsonFile<'a>,
    summary: JsonSummary,
    checked: &'static [&'static str],
    not_checked: &'static [&'static str],
    signatures: Vec<JsonSignature<'a>>,
}

#[derive(Serialize)]
struct JsonFile<'a> {
    name: &'a str,
    size: usize,
    sha256: &'a str,
    pages: Option<usize>,
    encrypted: bool,
}

#[derive(Serialize)]
struct JsonSummary {
    text: String,
    signatures: usize,
    valid: usize,
    invalid: usize,
    unknown: usize,
    content_changed: bool,
    all_valid: bool,
}

#[derive(Serialize)]
pub(crate) struct JsonSignature<'a> {
    index: usize,
    field: &'a str,
    status: &'static str,
    signer: Option<JsonCert<'a>>,
    /// The signature dictionary's `/Name`.
    name: Option<&'a str>,
    signing_time: Option<String>,
    signing_time_in_validity: Option<bool>,
    timestamp: JsonTimestamp,
    reason: Option<&'a str>,
    location: Option<&'a str>,
    sub_filter: Option<&'a str>,
    digest_algorithm: Option<&'static str>,
    certification: Option<JsonCertification>,
    coverage: JsonCoverage,
    trust: &'static str,
    chain: Vec<JsonCert<'a>>,
    notes: &'a [String],
}

#[derive(Serialize)]
struct JsonCert<'a> {
    subject: &'a str,
    organization: Option<&'a str>,
    issuer: &'a str,
    serial: &'a str,
    not_before: String,
    not_after: String,
}

#[derive(Serialize)]
struct JsonTimestamp {
    present: bool,
    verified: bool,
}

#[derive(Serialize)]
struct JsonCertification {
    level: u8,
    allows: &'static str,
}

#[derive(Serialize)]
struct JsonCoverage {
    whole_document: bool,
    signed_bytes: usize,
    file_bytes: usize,
    later_revisions: usize,
    changes: &'static str,
}

impl<'a> JsonCert<'a> {
    fn new(c: &'a CertDetails) -> Self {
        JsonCert {
            subject: &c.subject,
            organization: c.organization.as_deref(),
            issuer: &c.issuer,
            serial: &c.serial_hex,
            not_before: c.not_before.to_rfc3339_opts(SecondsFormat::Secs, true),
            not_after: c.not_after.to_rfc3339_opts(SecondsFormat::Secs, true),
        }
    }
}

impl<'a> JsonSignature<'a> {
    pub(crate) fn new(index: usize, r: &'a SignatureReport) -> Self {
        JsonSignature {
            index,
            field: &r.field,
            status: match r.status {
                Status::Valid => "valid",
                Status::Invalid => "invalid",
                Status::Unknown => "unknown",
            },
            signer: r.signer.as_ref().map(JsonCert::new),
            name: r.name.as_deref(),
            signing_time: r
                .signing_time
                .map(|t| t.to_rfc3339_opts(SecondsFormat::Secs, true)),
            signing_time_in_validity: r.time_in_validity,
            timestamp: JsonTimestamp {
                present: r.timestamped,
                verified: false,
            },
            reason: r.reason.as_deref(),
            location: r.location.as_deref(),
            sub_filter: r.sub_filter.as_deref(),
            digest_algorithm: r.digest_algorithm,
            certification: r.certification.map(|p| JsonCertification {
                level: p.level(),
                allows: match p {
                    DocMdp::NoChanges => "no_changes",
                    DocMdp::FormFilling => "form_filling",
                    DocMdp::Annotations => "form_filling_and_annotations",
                },
            }),
            coverage: JsonCoverage {
                whole_document: r.covers_whole_file(),
                signed_bytes: r.signed_len,
                file_bytes: r.file_len,
                later_revisions: r.later_revisions,
                changes: match r.changes {
                    Changes::None => "none",
                    Changes::Signatures => "signatures",
                    Changes::FormOrAnnotations => "form_or_annotations",
                    Changes::Content => "content",
                    Changes::Unknown => "unknown",
                },
            },
            trust: match r.trust {
                Trust::CcaIndia => "cca_india_2022",
                Trust::NotChecked => "not_checked",
            },
            chain: r.chain.iter().map(JsonCert::new).collect(),
            notes: &r.notes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn cert(name: &str) -> CertDetails {
        CertDetails {
            subject: name.into(),
            organization: Some("Personal".into()),
            issuer: "Verasys Sub CA 2022".into(),
            serial_hex: "0A1B2C3D".into(),
            not_before: Utc.with_ymd_and_hms(2025, 4, 1, 0, 0, 0).unwrap(),
            not_after: Utc.with_ymd_and_hms(2027, 3, 31, 23, 59, 59).unwrap(),
        }
    }

    fn sig(field: &str, signed_len: usize, changes: Changes) -> SignatureReport {
        SignatureReport {
            field: field.into(),
            status: Status::Valid,
            notes: vec![],
            sub_filter: Some("adbe.pkcs7.detached".into()),
            digest_algorithm: Some("SHA-256"),
            signer: Some(cert("RAHUL TEST DIRECTOR")),
            chain: vec![cert("RAHUL TEST DIRECTOR"), cert("Verasys Sub CA 2022")],
            trust: Trust::CcaIndia,
            signing_time: Some(DateTime::parse_from_rfc3339("2026-10-20T14:32:10+05:30").unwrap()),
            time_in_validity: Some(true),
            timestamped: false,
            name: None,
            reason: Some("Approved".into()),
            location: Some("Chennai".into()),
            signed_len,
            file_len: 3000,
            later_revisions: usize::from(changes != Changes::None),
            changes,
            certification: None,
        }
    }

    fn report(signatures: Vec<SignatureReport>) -> Report {
        Report {
            file_name: "invoice.pdf".into(),
            file_size: 3000,
            sha256: "ab".repeat(32),
            pages: Some(2),
            encrypted: false,
            checked_at: Utc.with_ymd_and_hms(2026, 10, 24, 20, 0, 5).unwrap(),
            version: "0.3.0".into(),
            signatures,
        }
    }

    #[test]
    fn summary_lines() {
        let three = report(vec![
            sig("A", 1000, Changes::Signatures),
            sig("B", 2000, Changes::Signatures),
            sig("C", 3000, Changes::None),
        ]);
        assert_eq!(
            three.summary(),
            "3 signatures — all valid, document unchanged since the last signature"
        );
        assert!(three.all_valid());

        let one = report(vec![sig("A", 1000, Changes::FormOrAnnotations)]);
        assert_eq!(
            one.summary(),
            "1 signature — valid, form filled in or comments added since it was signed"
        );

        let mut bad = sig("A", 1000, Changes::Signatures);
        bad.status = Status::Invalid;
        let mut unknown = sig("C", 2500, Changes::Content);
        unknown.status = Status::Unknown;
        let mixed = report(vec![bad, sig("B", 2000, Changes::Content), unknown]);
        assert_eq!(
            mixed.summary(),
            "3 signatures — 1 valid, 1 INVALID, 1 could not be verified, \
             CONTENT CHANGED after signature 2"
        );
        assert!(!mixed.all_valid());

        let mut first = sig("A", 1000, Changes::Signatures);
        let mut second = sig("B", 3000, Changes::None);
        first.status = Status::Invalid;
        second.status = Status::Invalid;
        assert_eq!(
            report(vec![first, second]).summary(),
            "2 signatures — all INVALID"
        );

        let mut certified = sig("A", 1000, Changes::Signatures);
        certified.certification = Some(DocMdp::NoChanges);
        let broken = report(vec![certified, sig("B", 3000, Changes::None)]);
        assert!(
            broken
                .summary()
                .ends_with("; changed after a certification that allowed no changes")
        );
        assert!(!broken.all_valid());

        assert_eq!(report(vec![]).summary(), "No signatures found.");
    }

    #[test]
    fn times_in_ist_and_utc() {
        let t = Utc.with_ymd_and_hms(2026, 10, 24, 9, 30, 12).unwrap();
        assert_eq!(ist_and_utc(t), "24 Oct 2026, 15:00:12 IST (09:30:12 UTC)");
        let t = Utc.with_ymd_and_hms(2026, 10, 24, 20, 0, 5).unwrap();
        assert_eq!(
            ist_and_utc(t),
            "25 Oct 2026, 01:30:05 IST (24 Oct 2026, 20:00:05 UTC)"
        );
        assert_eq!(thousands(1234567), "1,234,567");
        assert_eq!(thousands(999), "999");
    }

    #[test]
    fn non_latin_text_is_marked() {
        assert_eq!(shown("Chennai"), "Chennai");
        assert_eq!(shown("रमेश"), "Ramesha (transliterated)");
    }

    /// The JSON keys are a published interface: changing them needs a new
    /// SCHEMA_VERSION and a README update.
    #[test]
    fn json_schema_is_stable() {
        fn keys(v: &serde_json::Value) -> Vec<&str> {
            let mut k: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
            k.sort_unstable();
            k
        }
        let mut s = sig("Signature1", 3000, Changes::None);
        s.certification = Some(DocMdp::FormFilling);
        s.name = Some("रमेश".into());
        let v: serde_json::Value = serde_json::from_str(&report(vec![s]).to_json()).unwrap();
        assert_eq!(
            keys(&v),
            [
                "checked",
                "checked_at",
                "file",
                "generator",
                "not_checked",
                "schema",
                "schema_version",
                "signatures",
                "summary"
            ]
        );
        assert_eq!(v["schema"], "trackmysign.verification-report");
        assert_eq!(v["schema_version"], 1);
        assert_eq!(v["checked_at"], "2026-10-24T20:00:05Z");
        assert_eq!(
            keys(&v["file"]),
            ["encrypted", "name", "pages", "sha256", "size"]
        );
        assert_eq!(
            keys(&v["summary"]),
            [
                "all_valid",
                "content_changed",
                "invalid",
                "signatures",
                "text",
                "unknown",
                "valid"
            ]
        );
        assert_eq!(
            v["not_checked"],
            serde_json::json!(["revocation", "timestamp_token"])
        );
        let s = &v["signatures"][0];
        assert_eq!(
            keys(s),
            [
                "certification",
                "chain",
                "coverage",
                "digest_algorithm",
                "field",
                "index",
                "location",
                "name",
                "notes",
                "reason",
                "signer",
                "signing_time",
                "signing_time_in_validity",
                "status",
                "sub_filter",
                "timestamp",
                "trust"
            ]
        );
        assert_eq!(
            keys(&s["signer"]),
            [
                "issuer",
                "not_after",
                "not_before",
                "organization",
                "serial",
                "subject"
            ]
        );
        assert_eq!(
            keys(&s["coverage"]),
            [
                "changes",
                "file_bytes",
                "later_revisions",
                "signed_bytes",
                "whole_document"
            ]
        );
        assert_eq!(keys(&s["timestamp"]), ["present", "verified"]);
        assert_eq!(s["status"], "valid");
        assert_eq!(s["trust"], "cca_india_2022");
        assert_eq!(s["signing_time"], "2026-10-20T14:32:10+05:30");
        assert_eq!(s["signer"]["not_after"], "2027-03-31T23:59:59Z");
        assert_eq!(s["certification"]["allows"], "form_filling");
        assert_eq!(s["coverage"]["changes"], "none");
        // The original text, not the transliteration.
        assert_eq!(s["name"], "रमेश");
        assert_eq!(s["chain"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn pdf_report_reads_back() {
        let mut sigs: Vec<SignatureReport> = (0..12)
            .map(|i| sig(&format!("Signature{i}"), 1000 + i, Changes::Signatures))
            .collect();
        sigs[3].notes = vec!["The certificate was not valid at the signing time.".into()];
        sigs[5].signer.as_mut().unwrap().subject = "முருகன் ŁUKASZ 中".into();
        let r = report(sigs);
        let pdf = r.to_pdf();
        // A report of the report: a valid PDF with no signatures.
        let again = Report::new(&pdf, "report.pdf", None, "0.3.0").unwrap();
        assert!(
            again.pages > Some(1),
            "12 signatures need more than one page"
        );
        assert!(again.signatures.is_empty());
        assert!(!again.encrypted);
    }
}
