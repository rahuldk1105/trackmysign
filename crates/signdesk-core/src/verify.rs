//! Checks the signatures already in a PDF: that the signed bytes are intact,
//! that the CMS signature matches the signer's certificate, and what later
//! incremental updates changed.
//!
//! Trust is only checked against the CCA India 2022 root, and certificate
//! revocation (CRL / OCSP) is not checked at all.

use std::collections::HashSet;

use chrono::{DateTime, FixedOffset, TimeZone, Utc};
use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier};
use const_oid::ObjectIdentifier;
use const_oid::db::{rfc4519, rfc5280, rfc5911, rfc5912};
use der::asn1::{OctetString, UintRef};
use der::{Decode, Encode};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::pkcs8::DecodePublicKey;
use sha2::Digest;
use x509_cert::Certificate;
use x509_cert::attr::Attributes;
use x509_cert::ext::pkix::{BasicConstraints, SubjectKeyIdentifier};
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::Time;

use crate::pdf::docmdp::{self, DocMdp};
use crate::pdf::fields::text;
use crate::pdf::object::{Dict, Obj, is_ws};
use crate::pdf::reader::{Document, XrefEntry, find};
use crate::{Error, KeyKind, certinfo};

/// Root Certifying Authority of India, "CCA India 2022" (RSA 4096, valid
/// 2022-02-02 to 2042-02-02, SHA-256 fingerprint
/// 9A:3F:D3:17:67:98:E8:42:DD:CB:12:C2:62:F1:1C:FA:CC:A7:0A:8B:84:C6:EA:6F:DA:30:84:2A:95:A9:4C:D8).
/// Source: https://cca.gov.in/cca/sites/default/files/files/CCAIndia2022.cer,
/// linked from https://cca.gov.in/root_certificate.html; converted to DER.
const CCA_INDIA_2022: &[u8] = include_bytes!("roots/cca-india-2022.der");

const ID_AA_TIME_STAMP_TOKEN: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.14");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The signed bytes are intact and the signature matches the certificate.
    Valid,
    /// The signed bytes were altered, or the signature does not match.
    Invalid,
    /// Could not be checked (unsupported algorithm, unreadable signature data).
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    /// The certificates in the signature lead to the CCA India 2022 root.
    CcaIndia,
    /// No chain to a known root; trust was not checked.
    NotChecked,
}

/// What incremental updates after the signed revision changed, least
/// worrying first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Changes {
    /// The signature covers the whole file.
    None,
    /// Only signatures were added (with their fields, appearances and
    /// validation data).
    Signatures,
    /// Form fields were filled in, or annotations added or changed.
    FormOrAnnotations,
    /// Pages or other content changed.
    Content,
    /// Later revisions exist but could not be compared.
    Unknown,
}

#[derive(Debug, Clone)]
pub struct CertDetails {
    pub subject: String,
    pub organization: Option<String>,
    pub issuer: String,
    pub serial_hex: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct SignatureReport {
    /// Fully qualified form field name.
    pub field: String,
    pub status: Status,
    /// Why the status is not `Valid` comes first; then other warnings.
    pub notes: Vec<String>,
    pub sub_filter: Option<String>,
    pub digest_algorithm: Option<&'static str>,
    pub signer: Option<CertDetails>,
    /// Signer certificate first, then each issuer found.
    pub chain: Vec<CertDetails>,
    pub trust: Trust,
    /// From the CMS signing-time attribute, else the PDF's `/M` (both are
    /// the signer's clock).
    pub signing_time: Option<DateTime<FixedOffset>>,
    /// The signing time falls inside the signer certificate's validity.
    pub time_in_validity: Option<bool>,
    /// An RFC 3161 timestamp is attached (not verified).
    pub timestamped: bool,
    pub name: Option<String>,
    pub reason: Option<String>,
    pub location: Option<String>,
    /// End of the bytes covered by the signature.
    pub signed_len: usize,
    pub file_len: usize,
    /// Incremental updates appended after the signed revision.
    pub later_revisions: usize,
    pub changes: Changes,
    /// Set for a certification signature: the changes it allows afterwards.
    pub certification: Option<DocMdp>,
}

impl SignatureReport {
    pub fn covers_whole_file(&self) -> bool {
        self.changes == Changes::None
    }

    pub fn bytes_after(&self) -> usize {
        self.file_len.saturating_sub(self.signed_len)
    }
}

/// Checks every signed signature field, in signing order.
pub fn verify(input: &[u8]) -> Result<Vec<SignatureReport>, Error> {
    verify_with_password(input, None)
}

/// [`verify`] for a password-protected PDF.
pub fn verify_with_password(
    input: &[u8],
    password: Option<&str>,
) -> Result<Vec<SignatureReport>, Error> {
    let doc = Document::open(input, password)?;
    let mut out: Vec<SignatureReport> = signature_fields(&doc)?
        .into_iter()
        .map(|(field, sig)| check(input, &doc, field, &sig))
        .collect();
    out.sort_by_key(|r| r.signed_len);
    // Form filling and comments are not told apart, so only "no changes"
    // is held to: no later signature and no form or content change.
    let ends: Vec<usize> = out.iter().map(|r| r.signed_len).collect();
    for r in &mut out {
        if r.certification == Some(DocMdp::NoChanges)
            && r.status == Status::Valid
            && (matches!(r.changes, Changes::FormOrAnnotations | Changes::Content)
                || ends.iter().any(|&e| e > r.signed_len))
        {
            r.notes.push(
                "The document was changed after it was certified with no changes allowed.".into(),
            );
        }
    }
    Ok(out)
}

// ------------------------------------------------------------- fields

fn signature_fields(doc: &Document) -> Result<Vec<(String, Dict)>, Error> {
    let cat = doc.catalog()?;
    let Some(af) = cat.get("AcroForm") else {
        return Ok(vec![]);
    };
    let af = doc.resolve(af)?;
    let fields = match af.as_dict().and_then(|d| d.get("Fields")) {
        Some(f) => doc.resolve(f)?,
        None => return Ok(vec![]),
    };
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for f in fields.as_array().cloned().unwrap_or_default() {
        collect_fields(doc, &f, "", false, &mut seen, &mut out, 0);
    }
    Ok(out)
}

fn collect_fields(
    doc: &Document,
    node: &Obj,
    parent: &str,
    parent_is_sig: bool,
    seen: &mut HashSet<u32>,
    out: &mut Vec<(String, Dict)>,
    depth: usize,
) {
    if depth > 32 {
        return;
    }
    if let Obj::Ref(id, _) = node
        && !seen.insert(*id)
    {
        return;
    }
    let Ok(obj) = doc.resolve(node) else {
        return;
    };
    let Some(d) = obj.as_dict() else {
        return;
    };
    let name = match d.get("T") {
        Some(Obj::Str(t)) if parent.is_empty() => text(t),
        Some(Obj::Str(t)) => format!("{parent}.{}", text(t)),
        _ => parent.to_string(),
    };
    let is_sig = d.get("FT").map_or(parent_is_sig, |t| t.is_name("Sig"));
    if is_sig
        && let Some(v) = d.get("V")
        && let Ok(Obj::Dict(sig)) = doc.resolve(v)
    {
        out.push((name, sig));
        return;
    }
    if let Some(kids) = d.get("Kids")
        && let Ok(Obj::Array(kids)) = doc.resolve(kids)
    {
        for k in &kids {
            collect_fields(doc, k, &name, is_sig, seen, out, depth + 1);
        }
    }
}

/// `D:YYYYMMDDHHmmSSOHH'mm'`, every part after the year optional.
pub fn parse_pdf_date(s: &str) -> Option<DateTime<FixedOffset>> {
    let s = s.trim().strip_prefix("D:").unwrap_or(s.trim());
    let digits: String = s.chars().take_while(char::is_ascii_digit).collect();
    if digits.len() < 4 {
        return None;
    }
    let num = |a: usize, b: usize, default: u32| {
        digits
            .get(a..b)
            .and_then(|x| x.parse::<u32>().ok())
            .unwrap_or(default)
    };
    let rest = &s[digits.len()..];
    let secs = match rest.chars().next() {
        Some(c @ ('+' | '-')) => {
            let t: String = rest[1..].chars().filter(char::is_ascii_digit).collect();
            let part = |a: usize, b: usize| t.get(a..b).and_then(|x| x.parse::<i32>().ok());
            let secs = part(0, 2).unwrap_or(0) * 3600 + part(2, 4).unwrap_or(0) * 60;
            if c == '-' { -secs } else { secs }
        }
        _ => 0,
    };
    FixedOffset::east_opt(secs)?
        .with_ymd_and_hms(
            num(0, 4, 0) as i32,
            num(4, 6, 1),
            num(6, 8, 1),
            num(8, 10, 0),
            num(10, 12, 0),
            num(12, 14, 0),
        )
        .single()
}

// ---------------------------------------------------------- signature

enum Failure {
    Invalid(String),
    Unknown(String),
}

fn invalid(m: impl Into<String>) -> Failure {
    Failure::Invalid(m.into())
}

fn unknown(m: impl Into<String>) -> Failure {
    Failure::Unknown(m.into())
}

fn check(data: &[u8], doc: &Document, field: String, sig: &Dict) -> SignatureReport {
    let string = |k: &str| match sig.get(k) {
        Some(Obj::Str(s)) => Some(text(s)),
        _ => None,
    };
    let mut r = SignatureReport {
        field,
        status: Status::Unknown,
        notes: Vec::new(),
        sub_filter: match sig.get("SubFilter") {
            Some(Obj::Name(n)) => Some(String::from_utf8_lossy(n).into_owned()),
            _ => None,
        },
        digest_algorithm: None,
        signer: None,
        chain: Vec::new(),
        trust: Trust::NotChecked,
        signing_time: string("M").and_then(|m| parse_pdf_date(&m)),
        time_in_validity: None,
        timestamped: false,
        name: string("Name"),
        reason: string("Reason"),
        location: string("Location"),
        signed_len: 0,
        file_len: data.len(),
        later_revisions: 0,
        changes: Changes::Unknown,
        certification: docmdp::of_signature(doc, sig),
    };
    match check_signature(data, sig, &mut r) {
        Ok(()) => r.status = Status::Valid,
        Err(Failure::Invalid(m)) => {
            r.status = Status::Invalid;
            r.notes.insert(0, m);
        }
        Err(Failure::Unknown(m)) => {
            r.status = Status::Unknown;
            r.notes.insert(0, m);
        }
    }
    if r.signed_len > 0 {
        (r.later_revisions, r.changes) = later_changes(data, doc, r.signed_len);
    }
    if let (Some(t), Some(s)) = (r.signing_time, &r.signer) {
        let inside = s.not_before <= t && t <= s.not_after;
        r.time_in_validity = Some(inside);
        if !inside {
            r.notes
                .push("The certificate was not valid at the signing time.".into());
        }
    }
    r
}

fn check_signature(data: &[u8], sig: &Dict, r: &mut SignatureReport) -> Result<(), Failure> {
    let br: Vec<i64> = sig
        .get("ByteRange")
        .and_then(Obj::as_array)
        .map(|a| a.iter().filter_map(Obj::as_i64).collect())
        .unwrap_or_default();
    let [0, a, b, c] = br[..] else {
        return Err(invalid(
            "The /ByteRange is missing or does not start at the beginning of the file.",
        ));
    };
    if a < 0 || b < a || c < 0 || (b + c) as usize > data.len() {
        return Err(invalid("The /ByteRange does not fit the file."));
    }
    let (a, b, c) = (a as usize, b as usize, c as usize);
    r.signed_len = b + c;
    if b - a < 2 || data[a] != b'<' || data[b - 1] != b'>' {
        return Err(invalid("The /ByteRange gap is not the /Contents string."));
    }
    let gap = hex_decode(&data[a + 1..b - 1]);
    if !matches!(sig.get("Contents"), Some(Obj::Str(s)) if *s == gap) {
        return Err(invalid("/Contents is not the value in the /ByteRange gap."));
    }
    let parts = [&data[..a], &data[b..b + c]];

    // /Contents is zero-padded; the CMS is the first DER element.
    let cms_der = tlv(&gap, 0)
        .map(|(_, _, end)| &gap[..end])
        .ok_or_else(|| unknown("The signature data is not DER encoded."))?;
    let ci = ContentInfo::from_der(cms_der)
        .map_err(|e| unknown(format!("The signature data could not be read: {e}")))?;
    if ci.content_type != rfc5911::ID_SIGNED_DATA {
        return Err(unknown("The signature is not CMS SignedData."));
    }
    let sd: SignedData = ci
        .content
        .decode_as()
        .map_err(|e| unknown(format!("The signature data could not be read: {e}")))?;
    let certs: Vec<Certificate> = sd
        .certificates
        .iter()
        .flat_map(|s| s.0.iter())
        .filter_map(|c| match c {
            CertificateChoices::Certificate(c) => Some(c.clone()),
            _ => None,
        })
        .collect();
    let si = sd
        .signer_infos
        .0
        .iter()
        .next()
        .ok_or_else(|| unknown("The signature has no signer."))?;
    let signer = find_signer(&certs, &si.sid);
    if let Some(cert) = signer {
        r.signer = Some(details(cert));
        let (chain, trust) = build_chain(cert, &certs);
        r.chain = chain.iter().map(details).collect();
        r.trust = trust;
    }
    r.timestamped = si
        .unsigned_attrs
        .as_ref()
        .is_some_and(|a| a.iter().any(|x| x.oid == ID_AA_TIME_STAMP_TOKEN));

    let hash = Hash::from_oid(si.digest_alg.oid).ok_or_else(|| {
        unknown(format!(
            "Unsupported digest algorithm {}.",
            si.digest_alg.oid
        ))
    })?;
    r.digest_algorithm = Some(hash.name());

    let econtent = sd.encap_content_info.econtent.as_ref().map(|e| e.value());
    let content_digest = match econtent {
        None => hash.digest(&parts),
        Some(e) => {
            check_encapsulated(e, r, &parts)?;
            hash.digest(&[e])
        }
    };

    if let Some(attrs) = &si.signed_attrs {
        if let Some(t) = attr_der(attrs, rfc5911::ID_SIGNING_TIME)
            .and_then(|v| Time::from_der(&v).ok())
            .and_then(|t| {
                Utc.timestamp_opt(t.to_unix_duration().as_secs() as i64, 0)
                    .single()
            })
        {
            // Keep the time zone the signer wrote in /M, if any.
            let offset = r
                .signing_time
                .map_or(FixedOffset::east_opt(0).unwrap(), |m| *m.offset());
            r.signing_time = Some(t.with_timezone(&offset));
        }
        let md = attr_der(attrs, rfc5911::ID_MESSAGE_DIGEST)
            .and_then(|v| OctetString::from_der(&v).ok())
            .ok_or_else(|| invalid("The signature has no messageDigest attribute."))?;
        if md.as_bytes() != content_digest {
            return Err(invalid(
                "The document digest does not match: the signed bytes were changed.",
            ));
        }
    }

    let cert = signer
        .ok_or_else(|| unknown("The signer's certificate is not included in the signature."))?;
    let (kind, sig_hash) =
        signature_algorithm(si.signature_algorithm.oid, hash).ok_or_else(|| {
            unknown(format!(
                "Unsupported signature algorithm {}.",
                si.signature_algorithm.oid
            ))
        })?;
    let hashed = match &si.signed_attrs {
        Some(_) => {
            let raw = raw_signed_attrs(cms_der)
                .ok_or_else(|| unknown("The signed attributes could not be read."))?;
            sig_hash.digest(&[&raw])
        }
        None => content_digest,
    };
    let spki = &cert.tbs_certificate.subject_public_key_info;
    match verify_hashed(spki, kind, sig_hash, &hashed, si.signature.as_bytes()) {
        Ok(true) => Ok(()),
        Ok(false) => Err(invalid(
            "The signature does not match the signer's certificate.",
        )),
        Err(m) => Err(unknown(m)),
    }
}

/// Signed content inside the CMS: the SHA-1 of the document
/// (`adbe.pkcs7.sha1`) or a timestamp token (`ETSI.RFC3161`).
fn check_encapsulated(
    econtent: &[u8],
    r: &mut SignatureReport,
    parts: &[&[u8]],
) -> Result<(), Failure> {
    if r.sub_filter.as_deref() == Some("ETSI.RFC3161") {
        let (alg, imprint, time) =
            tst_info(econtent).ok_or_else(|| unknown("The timestamp token could not be read."))?;
        let h = Hash::from_oid(alg)
            .ok_or_else(|| unknown(format!("Unsupported digest algorithm {alg}.")))?;
        if h.digest(parts) != imprint {
            return Err(invalid(
                "The document digest does not match the timestamp: the signed bytes were changed.",
            ));
        }
        r.signing_time = time.or(r.signing_time);
    } else if Hash::Sha1.digest(parts) != econtent {
        return Err(invalid(
            "The document digest does not match: the signed bytes were changed.",
        ));
    }
    Ok(())
}

fn attr_der(attrs: &Attributes, oid: ObjectIdentifier) -> Option<Vec<u8>> {
    let a = attrs.iter().find(|a| a.oid == oid)?;
    a.values.iter().next()?.to_der().ok()
}

fn find_signer<'c>(certs: &'c [Certificate], sid: &SignerIdentifier) -> Option<&'c Certificate> {
    match sid {
        SignerIdentifier::IssuerAndSerialNumber(ias) => certs.iter().find(|c| {
            c.tbs_certificate.issuer == ias.issuer
                && c.tbs_certificate.serial_number == ias.serial_number
        }),
        SignerIdentifier::SubjectKeyIdentifier(ski) => certs.iter().find(|c| {
            extension::<SubjectKeyIdentifier>(c, rfc5280::ID_CE_SUBJECT_KEY_IDENTIFIER)
                .is_some_and(|k| k == *ski)
        }),
    }
}

fn extension<'a, T: Decode<'a>>(c: &'a Certificate, oid: ObjectIdentifier) -> Option<T> {
    let ext = c
        .tbs_certificate
        .extensions
        .iter()
        .flatten()
        .find(|e| e.extn_id == oid)?;
    T::from_der(ext.extn_value.as_bytes()).ok()
}

fn details(c: &Certificate) -> CertDetails {
    let tbs = &c.tbs_certificate;
    CertDetails {
        subject: certinfo::attr(&tbs.subject, rfc4519::CN)
            .unwrap_or_else(|| tbs.subject.to_string()),
        organization: certinfo::attr(&tbs.subject, rfc4519::O),
        issuer: certinfo::attr(&tbs.issuer, rfc4519::CN).unwrap_or_else(|| tbs.issuer.to_string()),
        serial_hex: tbs
            .serial_number
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect(),
        not_before: certinfo::to_chrono(tbs.validity.not_before),
        not_after: certinfo::to_chrono(tbs.validity.not_after),
    }
}

/// Follows issuer links through the certificates in the signature. Trust is
/// reported only when every issuer is a CA and the last one is signed by the
/// CCA India root.
fn build_chain(signer: &Certificate, pool: &[Certificate]) -> (Vec<Certificate>, Trust) {
    let root = Certificate::from_der(CCA_INDIA_2022).ok();
    let mut chain = vec![signer.clone()];
    let mut trust = Trust::NotChecked;
    while chain.len() < 10 {
        let cur = chain.last().unwrap();
        let tbs = &cur.tbs_certificate;
        if let Some(root) = &root
            && tbs.issuer == root.tbs_certificate.subject
            && signed_by(cur, root)
        {
            if chain[1..].iter().all(is_ca) {
                trust = Trust::CcaIndia;
            }
            if cur != root {
                chain.push(root.clone());
            }
            break;
        }
        if tbs.issuer == tbs.subject {
            break;
        }
        let Some(next) = pool
            .iter()
            .find(|c| c.tbs_certificate.subject == tbs.issuer && signed_by(cur, c))
        else {
            break;
        };
        if chain.contains(next) {
            break;
        }
        chain.push(next.clone());
    }
    (chain, trust)
}

fn is_ca(c: &Certificate) -> bool {
    extension::<BasicConstraints>(c, rfc5280::ID_CE_BASIC_CONSTRAINTS).is_some_and(|b| b.ca)
}

fn signed_by(cert: &Certificate, issuer: &Certificate) -> bool {
    let Some((kind, hash)) = signature_algorithm(cert.signature_algorithm.oid, Hash::Sha256) else {
        return false;
    };
    let Ok(tbs) = cert.tbs_certificate.to_der() else {
        return false;
    };
    let Some(sig) = cert.signature.as_bytes() else {
        return false;
    };
    let spki = &issuer.tbs_certificate.subject_public_key_info;
    verify_hashed(spki, kind, hash, &hash.digest(&[&tbs]), sig).unwrap_or(false)
}

// -------------------------------------------------------------- crypto

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Hash {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    fn from_oid(oid: ObjectIdentifier) -> Option<Self> {
        [
            (rfc5912::ID_SHA_1, Hash::Sha1),
            (rfc5912::ID_SHA_256, Hash::Sha256),
            (rfc5912::ID_SHA_384, Hash::Sha384),
            (rfc5912::ID_SHA_512, Hash::Sha512),
        ]
        .into_iter()
        .find(|(o, _)| *o == oid)
        .map(|(_, h)| h)
    }

    fn name(self) -> &'static str {
        match self {
            Hash::Sha1 => "SHA-1",
            Hash::Sha256 => "SHA-256",
            Hash::Sha384 => "SHA-384",
            Hash::Sha512 => "SHA-512",
        }
    }

    fn digest(self, parts: &[&[u8]]) -> Vec<u8> {
        fn run<D: Digest>(parts: &[&[u8]]) -> Vec<u8> {
            let mut h = D::new();
            for p in parts {
                h.update(p);
            }
            h.finalize().to_vec()
        }
        match self {
            Hash::Sha1 => run::<sha1::Sha1>(parts),
            Hash::Sha256 => run::<sha2::Sha256>(parts),
            Hash::Sha384 => run::<sha2::Sha384>(parts),
            Hash::Sha512 => run::<sha2::Sha512>(parts),
        }
    }
}

/// Key type and hash for a signature algorithm OID. Bare `rsaEncryption` /
/// `id-ecPublicKey` (common in CMS) take the separately given digest.
fn signature_algorithm(oid: ObjectIdentifier, digest: Hash) -> Option<(KeyKind, Hash)> {
    [
        (rfc5912::RSA_ENCRYPTION, KeyKind::Rsa, None),
        (
            rfc5912::SHA_1_WITH_RSA_ENCRYPTION,
            KeyKind::Rsa,
            Some(Hash::Sha1),
        ),
        (
            rfc5912::SHA_256_WITH_RSA_ENCRYPTION,
            KeyKind::Rsa,
            Some(Hash::Sha256),
        ),
        (
            rfc5912::SHA_384_WITH_RSA_ENCRYPTION,
            KeyKind::Rsa,
            Some(Hash::Sha384),
        ),
        (
            rfc5912::SHA_512_WITH_RSA_ENCRYPTION,
            KeyKind::Rsa,
            Some(Hash::Sha512),
        ),
        (rfc5912::ID_EC_PUBLIC_KEY, KeyKind::Ec, None),
        (rfc5912::ECDSA_WITH_SHA_256, KeyKind::Ec, Some(Hash::Sha256)),
        (rfc5912::ECDSA_WITH_SHA_384, KeyKind::Ec, Some(Hash::Sha384)),
        (rfc5912::ECDSA_WITH_SHA_512, KeyKind::Ec, Some(Hash::Sha512)),
    ]
    .into_iter()
    .find(|(o, _, _)| *o == oid)
    .map(|(_, k, h)| (k, h.unwrap_or(digest)))
}

/// RFC 8017 RSAPublicKey.
#[derive(der::Sequence)]
struct RsaPublicKey<'a> {
    modulus: UintRef<'a>,
    public_exponent: UintRef<'a>,
}

/// DER DigestInfo prefix for each hash (RFC 8017, section 9.2, note 1).
fn digest_info_prefix(hash: Hash) -> &'static [u8] {
    match hash {
        Hash::Sha1 => &[
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
            0x14,
        ],
        Hash::Sha256 => &[
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ],
        Hash::Sha384 => &[
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x02, 0x05, 0x00, 0x04, 0x30,
        ],
        Hash::Sha512 => &[
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x03, 0x05, 0x00, 0x04, 0x40,
        ],
    }
}

/// EMSA-PKCS1-v1_5 encoding of `hashed` for a `k`-byte modulus.
fn pkcs1_encode(hash: Hash, hashed: &[u8], k: usize) -> Option<Vec<u8>> {
    let prefix = digest_info_prefix(hash);
    let t_len = prefix.len() + hashed.len();
    if k < t_len + 11 {
        return None;
    }
    let mut em = vec![0xff; k];
    em[0] = 0;
    em[1] = 1;
    em[k - t_len - 1] = 0;
    em[k - t_len..k - hashed.len()].copy_from_slice(prefix);
    em[k - hashed.len()..].copy_from_slice(hashed);
    Some(em)
}

/// RSASSA-PKCS1-v1_5 verification. Only public values are involved, so
/// plain (variable-time) big-integer arithmetic is fine here.
fn rsa_verify(key: &RsaPublicKey, hash: Hash, hashed: &[u8], sig: &[u8]) -> bool {
    use num_bigint::BigUint;
    let n = BigUint::from_bytes_be(key.modulus.as_bytes());
    let e = BigUint::from_bytes_be(key.public_exponent.as_bytes());
    let k = key.modulus.as_bytes().len();
    let s = BigUint::from_bytes_be(sig);
    if sig.len() != k || s >= n {
        return false;
    }
    let m = s.modpow(&e, &n).to_bytes_be();
    let mut em = vec![0; k - m.len()];
    em.extend_from_slice(&m);
    pkcs1_encode(hash, hashed, k).is_some_and(|expected| expected == em)
}

/// `Ok(false)` for a wrong signature, `Err` when the key cannot be used.
fn verify_hashed(
    spki: &SubjectPublicKeyInfoOwned,
    kind: KeyKind,
    hash: Hash,
    hashed: &[u8],
    sig: &[u8],
) -> Result<bool, String> {
    let spki_der = spki.to_der().map_err(|e| e.to_string())?;
    match kind {
        KeyKind::Rsa => {
            let key = spki
                .subject_public_key
                .as_bytes()
                .and_then(|b| RsaPublicKey::from_der(b).ok())
                .ok_or_else(|| "The signer's RSA key is not supported.".to_string())?;
            Ok(rsa_verify(&key, hash, hashed, sig))
        }
        KeyKind::Ec => {
            let curve = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.decode_as::<ObjectIdentifier>().ok());
            let unsupported = || "The signer's elliptic curve is not supported.".to_string();
            if curve == Some(rfc5912::SECP_256_R_1) {
                use p256::ecdsa::{Signature, VerifyingKey};
                let key =
                    VerifyingKey::from_public_key_der(&spki_der).map_err(|_| unsupported())?;
                let Ok(s) = Signature::from_der(sig).or_else(|_| Signature::from_slice(sig)) else {
                    return Ok(false);
                };
                Ok(key.verify_prehash(hashed, &s).is_ok())
            } else if curve == Some(rfc5912::SECP_384_R_1) {
                use p384::ecdsa::{Signature, VerifyingKey};
                let key =
                    VerifyingKey::from_public_key_der(&spki_der).map_err(|_| unsupported())?;
                let Ok(s) = Signature::from_der(sig).or_else(|_| Signature::from_slice(sig)) else {
                    return Ok(false);
                };
                Ok(key.verify_prehash(hashed, &s).is_ok())
            } else {
                Err(unsupported())
            }
        }
    }
}

// ----------------------------------------------------------------- DER

/// The DER element at `pos`: (tag, content start, end).
fn tlv(d: &[u8], pos: usize) -> Option<(u8, usize, usize)> {
    let tag = *d.get(pos)?;
    let first = *d.get(pos + 1)? as usize;
    let (len, header) = if first < 0x80 {
        (first, 2)
    } else {
        let n = first & 0x7f;
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = len << 8 | *d.get(pos + 2 + i)? as usize;
        }
        (len, 2 + n)
    };
    let start = pos + header;
    let end = start.checked_add(len)?;
    (end <= d.len()).then_some((tag, start, end))
}

/// Child elements of a constructed element's content: (tag, start, content start, end).
fn children(d: &[u8], start: usize, end: usize) -> Option<Vec<(u8, usize, usize, usize)>> {
    let mut out = Vec::new();
    let mut pos = start;
    while pos < end {
        let (tag, cs, e) = tlv(d, pos)?;
        out.push((tag, pos, cs, e));
        pos = e;
    }
    Some(out)
}

/// The first signer's signed attributes exactly as encoded, re-tagged as
/// the SET OF the signature covers. Re-encoding the decoded attributes
/// would sort them, which breaks signers that did not.
fn raw_signed_attrs(cms: &[u8]) -> Option<Vec<u8>> {
    let (_, s, e) = tlv(cms, 0)?;
    let ci = children(cms, s, e)?;
    let &(0xa0, _, s, _) = ci.get(1)? else {
        return None;
    };
    let (_, s, e) = tlv(cms, s)?;
    let sd = children(cms, s, e)?;
    let &(0x31, _, s, _) = sd.last()? else {
        return None;
    };
    let (_, s, e) = tlv(cms, s)?;
    let si = children(cms, s, e)?;
    let &(_, start, _, end) = si.iter().find(|c| c.0 == 0xa0)?;
    let mut raw = cms[start..end].to_vec();
    raw[0] = 0x31;
    Some(raw)
}

/// From a DER `TSTInfo`: messageImprint algorithm and digest, and genTime.
fn tst_info(d: &[u8]) -> Option<(ObjectIdentifier, Vec<u8>, Option<DateTime<FixedOffset>>)> {
    let (_, s, e) = tlv(d, 0)?;
    let kids = children(d, s, e)?;
    let &(_, _, s, e) = kids.get(2)?;
    let imprint = children(d, s, e)?;
    let &(_, _, s, e) = imprint.first()?;
    let &(_, _, oid_s, oid_e) = children(d, s, e)?.first()?;
    let oid = ObjectIdentifier::from_bytes(&d[oid_s..oid_e]).ok()?;
    let &(_, _, hs, he) = imprint.get(1)?;
    let time = kids.get(4).and_then(|&(_, start, _, end)| {
        let t = Time::from_der(&d[start..end]).ok()?;
        let t = Utc
            .timestamp_opt(t.to_unix_duration().as_secs() as i64, 0)
            .single()?;
        Some(t.fixed_offset())
    });
    Some((oid, d[hs..he].to_vec(), time))
}

fn hex_decode(s: &[u8]) -> Vec<u8> {
    let digits: Vec<u8> = s
        .iter()
        .filter_map(|c| (*c as char).to_digit(16))
        .map(|d| d as u8)
        .collect();
    digits
        .chunks(2)
        .map(|p| p[0] << 4 | p.get(1).copied().unwrap_or(0))
        .collect()
}

// ------------------------------------------------------------- changes

/// How many revisions follow the signed bytes, and what they changed.
fn later_changes(data: &[u8], doc: &Document, end: usize) -> (usize, Changes) {
    let rest = &data[end..];
    if rest.iter().all(|b| is_ws(*b)) {
        return (0, Changes::None);
    }
    let mut revisions = 0;
    let mut i = 0;
    while let Some(p) = find(&rest[i..], b"%%EOF") {
        revisions += 1;
        i += p + 5;
    }
    let changes = doc
        .revision(&data[..end])
        .ok()
        .and_then(|rev| compare(doc, &rev))
        .unwrap_or(Changes::Unknown);
    (revisions.max(1), changes)
}

/// Compares every object that the newer cross-reference points somewhere
/// else. New objects only matter through the old objects that now refer to
/// them, so those are judged by what changed in the referring object.
fn compare(doc: &Document, rev: &Document) -> Option<Changes> {
    let info = match doc.trailer.get("Info") {
        Some(Obj::Ref(id, _)) => Some(*id),
        _ => None,
    };
    let mut worst = Changes::Signatures;
    for (&id, entry) in &doc.xref {
        let before = rev.xref.get(&id);
        let same_place = before == Some(entry)
            && match entry {
                XrefEntry::InStream { container, .. } => {
                    doc.xref.get(container) == rev.xref.get(container)
                }
                XrefEntry::Offset(..) => true,
            };
        if same_place || before.is_none() {
            continue;
        }
        let new = doc.get(id).ok()?;
        let old = rev.get(id).ok()?;
        if old == new {
            continue;
        }
        let c = if Some(id) == info {
            Changes::Signatures
        } else {
            changed(doc, rev, &old, &new)
        };
        worst = worst.max(c);
    }
    Some(worst)
}

fn is_type(d: &Dict, t: &str) -> bool {
    d.get("Type").is_some_and(|v| v.is_name(t))
}

fn changed(doc: &Document, rev: &Document, old: &Obj, new: &Obj) -> Changes {
    match (old, new) {
        (Obj::Array(a), Obj::Array(b)) => grown_array(doc, a, b),
        (Obj::Dict(a), Obj::Dict(b)) => changed_dict(doc, rev, a, b),
        (Obj::Stream(..), Obj::Stream(d, _))
            if is_type(d, "Metadata") || is_type(d, "XRef") || is_type(d, "ObjStm") =>
        {
            Changes::Signatures
        }
        _ => Changes::Content,
    }
}

fn changed_dict(doc: &Document, rev: &Document, old: &Dict, new: &Dict) -> Changes {
    let keys: Vec<&[u8]> = old
        .0
        .iter()
        .chain(new.0.iter())
        .map(|(k, _)| k.as_slice())
        .filter(|k| {
            let k = std::str::from_utf8(k).unwrap_or("");
            old.get(k) != new.get(k)
        })
        .collect();
    let only = |allowed: &[&str]| {
        keys.iter()
            .all(|k| allowed.iter().any(|a| a.as_bytes() == *k))
    };
    if is_type(new, "Catalog") {
        if !only(&["AcroForm", "DSS", "Metadata", "Extensions"]) {
            return Changes::Content;
        }
        if keys.contains(&b"AcroForm".as_slice()) {
            let resolve = |d: &Document, v: Option<&Obj>| {
                v.and_then(|v| d.resolve(v).ok())
                    .and_then(|o| o.as_dict().cloned())
                    .unwrap_or_default()
            };
            let (a, b) = (
                resolve(rev, old.get("AcroForm")),
                resolve(doc, new.get("AcroForm")),
            );
            return acroform(doc, rev, &a, &b);
        }
        Changes::Signatures
    } else if is_type(new, "Page") {
        if only(&["Annots"]) {
            list_change(doc, rev, old.get("Annots"), new.get("Annots"))
        } else {
            Changes::Content
        }
    } else if is_type(new, "DSS") {
        Changes::Signatures
    } else if new.get("Fields").is_some() && !is_type(new, "Annot") {
        acroform(doc, rev, old, new)
    } else if is_signature_field(doc, new)
        && !is_type(new, "Sig")
        && only(&["V", "AP", "AS", "F", "Lock"])
    {
        // An empty signature field (or its widget) that was signed.
        Changes::Signatures
    } else if (new.get("FT").is_some() || is_type(new, "Annot"))
        && only(&["V", "AP", "AS", "MK", "F", "M", "Contents"])
    {
        Changes::FormOrAnnotations
    } else {
        Changes::Content
    }
}

fn acroform(doc: &Document, rev: &Document, old: &Dict, new: &Dict) -> Changes {
    let mut worst = Changes::Signatures;
    for (k, _) in old.0.iter().chain(new.0.iter()) {
        let k = std::str::from_utf8(k).unwrap_or("");
        if old.get(k) == new.get(k) {
            continue;
        }
        let c = match k {
            "Fields" => list_change(doc, rev, old.get(k), new.get(k)),
            "SigFlags" => Changes::Signatures,
            "DA" | "DR" | "NeedAppearances" => Changes::FormOrAnnotations,
            _ => Changes::Content,
        };
        worst = worst.max(c);
    }
    worst
}

/// An `/Annots` or `/Fields` array, inline or indirect, before and after.
fn list_change(doc: &Document, rev: &Document, old: Option<&Obj>, new: Option<&Obj>) -> Changes {
    let array = |d: &Document, v: Option<&Obj>| {
        v.and_then(|v| d.resolve(v).ok())
            .and_then(|o| o.as_array().cloned())
            .unwrap_or_default()
    };
    grown_array(doc, &array(rev, old), &array(doc, new))
}

/// Arrays may only grow, and only by references to things a signer or a
/// form filler adds. Anything else (removed entries, changed numbers, a
/// new page in `/Kids`) is a content change.
fn grown_array(doc: &Document, old: &[Obj], new: &[Obj]) -> Changes {
    if !old.iter().all(|o| new.contains(o)) {
        return Changes::Content;
    }
    let mut worst = Changes::Signatures;
    for item in new.iter().filter(|o| !old.contains(o)) {
        let Obj::Ref(..) = item else {
            return Changes::Content;
        };
        let obj = doc.resolve(item).unwrap_or(Obj::Null);
        let Some(d) = obj.as_dict() else {
            return Changes::Content;
        };
        let c = if is_signature_field(doc, d) {
            Changes::Signatures
        } else if is_type(d, "Annot") || d.get("FT").is_some() || d.get("Parent").is_some() {
            Changes::FormOrAnnotations
        } else {
            Changes::Content
        };
        worst = worst.max(c);
    }
    worst
}

/// `/FT /Sig` on the dictionary or inherited from a parent field.
fn is_signature_field(doc: &Document, d: &Dict) -> bool {
    let mut d = d.clone();
    for _ in 0..32 {
        if let Some(ft) = d.get("FT") {
            return ft.is_name("Sig");
        }
        match d.get("Parent").and_then(|p| doc.resolve(p).ok()) {
            Some(Obj::Dict(p)) => d = p,
            _ => return false,
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SignRequest, Signer, sign_pdf};
    use num_bigint::BigUint;
    use p256::pkcs8::DecodePrivateKey;

    /// RFC 8017 RSAPrivateKey.
    #[derive(der::Sequence)]
    struct RsaPrivateKey<'a> {
        version: UintRef<'a>,
        modulus: UintRef<'a>,
        public_exponent: UintRef<'a>,
        private_exponent: UintRef<'a>,
        prime1: UintRef<'a>,
        prime2: UintRef<'a>,
        exponent1: UintRef<'a>,
        exponent2: UintRef<'a>,
        coefficient: UintRef<'a>,
    }

    struct RsaKey {
        n: BigUint,
        d: BigUint,
        k: usize,
    }

    impl RsaKey {
        fn from_pkcs8(der: &[u8]) -> Self {
            let info = p256::pkcs8::PrivateKeyInfo::from_der(der).unwrap();
            let key = RsaPrivateKey::from_der(info.private_key).unwrap();
            RsaKey {
                n: BigUint::from_bytes_be(key.modulus.as_bytes()),
                d: BigUint::from_bytes_be(key.private_exponent.as_bytes()),
                k: key.modulus.as_bytes().len(),
            }
        }

        fn sign(&self, hashed: &[u8]) -> Vec<u8> {
            let em = pkcs1_encode(Hash::Sha256, hashed, self.k).unwrap();
            let s = BigUint::from_bytes_be(&em)
                .modpow(&self.d, &self.n)
                .to_bytes_be();
            let mut out = vec![0; self.k - s.len()];
            out.extend_from_slice(&s);
            out
        }
    }

    enum Key {
        Rsa(RsaKey),
        Ec(p256::ecdsa::SigningKey),
    }

    struct SoftSigner {
        cert: Vec<u8>,
        key: Key,
    }

    impl SoftSigner {
        fn rsa() -> Self {
            SoftSigner {
                cert: include_bytes!("../testdata/rsa-cert.der").to_vec(),
                key: Key::Rsa(RsaKey::from_pkcs8(include_bytes!(
                    "../testdata/rsa-key.der"
                ))),
            }
        }

        fn ec() -> Self {
            SoftSigner {
                cert: include_bytes!("../testdata/ec-cert.der").to_vec(),
                key: Key::Ec(
                    p256::ecdsa::SigningKey::from_pkcs8_der(include_bytes!(
                        "../testdata/ec-key.der"
                    ))
                    .unwrap(),
                ),
            }
        }
    }

    impl Signer for SoftSigner {
        fn certificate(&self) -> &[u8] {
            &self.cert
        }
        fn chain(&self) -> &[Vec<u8>] {
            &[]
        }
        fn key_kind(&self) -> KeyKind {
            match self.key {
                Key::Rsa(_) => KeyKind::Rsa,
                Key::Ec(_) => KeyKind::Ec,
            }
        }
        fn signature_len(&self) -> usize {
            match self.key {
                Key::Rsa(_) => 128,
                Key::Ec(_) => 72,
            }
        }
        fn sign_sha256(&mut self, digest: &[u8; 32]) -> Result<Vec<u8>, Error> {
            match &self.key {
                Key::Rsa(k) => Ok(k.sign(digest)),
                Key::Ec(k) => {
                    use p256::ecdsa::signature::hazmat::PrehashSigner;
                    let s: p256::ecdsa::Signature = k.sign_prehash(digest).unwrap();
                    Ok(s.to_der().as_bytes().to_vec())
                }
            }
        }
    }

    /// Classic-xref file; `objs[i]` is object `i + 1`, object 1 the catalog.
    fn write_pdf(objs: &[&[u8]]) -> Vec<u8> {
        let mut out = b"%PDF-1.4\n".to_vec();
        let mut offsets = Vec::new();
        for (i, o) in objs.iter().enumerate() {
            offsets.push(out.len());
            out.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
            out.extend_from_slice(o);
            out.extend_from_slice(b"\nendobj\n");
        }
        let xref = out.len();
        out.extend_from_slice(
            format!("xref\n0 {}\n0000000000 65535 f\r\n", objs.len() + 1).as_bytes(),
        );
        for o in offsets {
            out.extend_from_slice(format!("{o:010} 00000 n\r\n").as_bytes());
        }
        out.extend_from_slice(
            format!(
                "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
                objs.len() + 1
            )
            .as_bytes(),
        );
        out
    }

    fn plain_pdf() -> Vec<u8> {
        write_pdf(&[
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R >>",
            b"<< /Length 23 >>\nstream\nBT 72 760 Td (Hi) Tj ET\nendstream",
        ])
    }

    /// Appends an incremental update replacing or adding the given objects.
    fn append_update(pdf: &[u8], objs: &[(u32, &[u8])]) -> Vec<u8> {
        let doc = Document::parse(pdf).unwrap();
        let mut out = pdf.to_vec();
        let mut xref = String::from("xref\n");
        let mut offsets = Vec::new();
        for (id, body) in objs {
            offsets.push((*id, out.len()));
            out.extend_from_slice(format!("{id} 0 obj\n").as_bytes());
            out.extend_from_slice(body);
            out.extend_from_slice(b"\nendobj\n");
        }
        for (id, off) in offsets {
            xref.push_str(&format!("{id} 1\n{off:010} 00000 n\r\n"));
        }
        let size = objs
            .iter()
            .map(|(id, _)| id + 1)
            .max()
            .unwrap()
            .max(doc.next_object_id());
        let pos = out.len();
        out.extend_from_slice(
            format!(
                "{xref}trailer\n<< /Size {size} /Root 1 0 R /Prev {} >>\nstartxref\n{pos}\n%%EOF\n",
                doc.startxref
            )
            .as_bytes(),
        );
        out
    }

    fn signed(pdf: &[u8], signer: &mut dyn Signer, time: &str) -> Vec<u8> {
        let req = SignRequest {
            page: 0,
            rect: Some(crate::DisplayRect {
                x: 300.0,
                y: 700.0,
                w: 170.0,
                h: 55.0,
            }),
            pages: Vec::new(),
            timestamp: None,
            ltv: false,
            reason: Some("Approved".into()),
            location: Some("Chennai".into()),
            time: Some(DateTime::parse_from_rfc3339(time).unwrap()),
            ..Default::default()
        };
        sign_pdf(pdf, &req, signer).unwrap()
    }

    const LATER: &str = "2035-06-01T10:00:00+05:30";

    #[test]
    fn rsa_signature_is_valid() {
        let pdf = signed(&plain_pdf(), &mut SoftSigner::rsa(), LATER);
        let r = verify(&pdf).unwrap();
        assert_eq!(r.len(), 1);
        let r = &r[0];
        assert_eq!(r.status, Status::Valid, "{:?}", r.notes);
        assert_eq!(r.field, "Signature1");
        assert_eq!(r.changes, Changes::None);
        assert_eq!(r.later_revisions, 0);
        assert_eq!(r.signed_len, pdf.len());
        let s = r.signer.as_ref().unwrap();
        assert_eq!(s.subject, "UNIT TEST RSA");
        assert_eq!(s.organization.as_deref(), Some("Unit Test Org"));
        assert_eq!(r.chain.len(), 1);
        assert_eq!(r.trust, Trust::NotChecked);
        assert_eq!(r.sub_filter.as_deref(), Some("adbe.pkcs7.detached"));
        assert_eq!(r.digest_algorithm, Some("SHA-256"));
        assert_eq!(r.reason.as_deref(), Some("Approved"));
        assert_eq!(r.location.as_deref(), Some("Chennai"));
        assert_eq!(
            r.signing_time.unwrap().to_rfc3339(),
            "2035-06-01T10:00:00+05:30"
        );
        assert_eq!(r.time_in_validity, Some(true));
        assert!(r.notes.is_empty());
    }

    #[test]
    fn ecdsa_signature_is_valid() {
        let pdf = signed(&plain_pdf(), &mut SoftSigner::ec(), LATER);
        let r = &verify(&pdf).unwrap()[0];
        assert_eq!(r.status, Status::Valid, "{:?}", r.notes);
        assert_eq!(r.signer.as_ref().unwrap().subject, "UNIT TEST EC");
    }

    #[test]
    fn changed_byte_is_invalid() {
        let mut pdf = signed(&plain_pdf(), &mut SoftSigner::rsa(), LATER);
        let at = find(&pdf, b"(Hi)").unwrap() + 1;
        pdf[at] = b'X';
        let r = &verify(&pdf).unwrap()[0];
        assert_eq!(r.status, Status::Invalid);
        assert!(r.notes[0].contains("digest"), "{:?}", r.notes);
    }

    #[test]
    fn wrong_signature_value_is_invalid() {
        let mut pdf = signed(&plain_pdf(), &mut SoftSigner::rsa(), LATER);
        // The RSA signature is the last element of the CMS; flip its last byte.
        let start = find(&pdf, b"/Contents <").unwrap() + 11;
        let end = start + find(&pdf[start..], b">").unwrap();
        let gap = hex_decode(&pdf[start..end]);
        let (_, _, len) = tlv(&gap, 0).unwrap();
        let at = start + 2 * len - 1;
        pdf[at] = if pdf[at] == b'0' { b'1' } else { b'0' };
        let r = &verify(&pdf).unwrap()[0];
        assert_eq!(r.status, Status::Invalid);
        assert!(
            r.notes[0].contains("does not match the signer"),
            "{:?}",
            r.notes
        );
    }

    #[test]
    fn second_signature_is_an_allowed_change() {
        let once = signed(&plain_pdf(), &mut SoftSigner::rsa(), LATER);
        let twice = signed(&once, &mut SoftSigner::ec(), LATER);
        let r = verify(&twice).unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].field, "Signature1");
        assert_eq!(r[0].status, Status::Valid);
        assert_eq!(r[0].changes, Changes::Signatures);
        assert_eq!(r[0].later_revisions, 1);
        assert_eq!(r[0].bytes_after(), twice.len() - once.len());
        assert_eq!(r[1].field, "Signature2");
        assert_eq!(r[1].status, Status::Valid);
        assert!(r[1].covers_whole_file());
    }

    /// "approvals" > "director" > separate widget, the AcroForm inline in
    /// the catalog; the field locks the text field "company".
    fn empty_field_pdf() -> Vec<u8> {
        write_pdf(&[
            b"<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [5 0 R 8 0 R] >> >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Rotate 90 /Contents 4 0 R /Annots [7 0 R] >>",
            b"<< /Length 23 >>\nstream\nBT 72 760 Td (Hi) Tj ET\nendstream",
            b"<< /T (approvals) /FT /Sig /Kids [6 0 R] >>",
            b"<< /T (director) /Parent 5 0 R /Kids [7 0 R] /Lock << /Type /SigFieldLock /Action /Include /Fields [(company)] >> >>",
            b"<< /Type /Annot /Subtype /Widget /Parent 6 0 R /Rect [60 500 120 700] /F 4 /P 3 0 R >>",
            b"<< /T (company) /FT /Tx /V (TrackMyTech) >>",
        ])
    }

    fn signed_into(pdf: &[u8], field: &str, signer: &mut dyn Signer) -> Result<Vec<u8>, Error> {
        let req = SignRequest {
            field: Some(field.into()),
            time: Some(DateTime::parse_from_rfc3339(LATER).unwrap()),
            ..Default::default()
        };
        sign_pdf(pdf, &req, signer)
    }

    #[test]
    fn signing_into_an_empty_field() {
        let pdf = empty_field_pdf();
        let info = crate::inspect(&pdf).unwrap();
        assert_eq!(info.signatures, 0);
        assert_eq!(info.empty_fields.len(), 1);
        let f = &info.empty_fields[0];
        assert_eq!(f.name, "approvals.director");
        assert_eq!(f.page, Some(0));
        // /Rotate 90: displayed 842 wide; the field shows 200 x 60.
        let r = f.rect.unwrap();
        assert_eq!((r.x, r.y, r.w, r.h), (500.0, 60.0, 200.0, 60.0));

        // A free box first, then the field: the first signature stays valid.
        let once = signed(&pdf, &mut SoftSigner::rsa(), LATER);
        let twice = signed_into(&once, "approvals.director", &mut SoftSigner::ec()).unwrap();
        let r = verify(&twice).unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].field, "Signature1");
        assert_eq!(r[0].changes, Changes::Signatures);
        assert_eq!(r[1].field, "approvals.director");
        assert_eq!(r[1].status, Status::Valid, "{:?}", r[1].notes);
        assert!(r[1].covers_whole_file());
        let info = crate::inspect(&twice).unwrap();
        assert_eq!(info.signatures, 2);
        assert!(info.empty_fields.is_empty());

        let doc = Document::parse(&twice).unwrap();
        let widget = doc.get(7).unwrap().as_dict().cloned().unwrap();
        let Some(Obj::Ref(ap, _)) = widget
            .get("AP")
            .and_then(|a| a.as_dict())
            .and_then(|a| a.get("N"))
            .cloned()
        else {
            panic!("widget has no appearance");
        };
        let ap = doc.get(ap).unwrap().as_dict().cloned().unwrap();
        let nums = |k: &str| -> Vec<f64> {
            ap.get(k)
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_f64().unwrap())
                .collect()
        };
        assert_eq!(nums("BBox"), [0.0, 0.0, 200.0, 60.0]);
        assert_eq!(nums("Matrix"), [0.0, 1.0, -1.0, 0.0, 60.0, 0.0]);
        // The widget keeps everything it had, the field gains only /V.
        let before = Document::parse(&pdf).unwrap();
        let old = before.get(7).unwrap().as_dict().cloned().unwrap();
        assert_eq!(
            widget.clone().with("AP", Obj::Null),
            old.with("AP", Obj::Null)
        );
        let field = doc.get(6).unwrap().as_dict().cloned().unwrap();
        let old = before.get(6).unwrap().as_dict().cloned().unwrap();
        assert_eq!(field.clone().with("V", Obj::Null), old.with("V", Obj::Null));
        let Some(Obj::Ref(sig, _)) = field.get("V").cloned() else {
            panic!("field has no /V");
        };
        let sig = doc.get(sig).unwrap().as_dict().cloned().unwrap();
        let mdp = &sig.get("Reference").unwrap().as_array().unwrap()[0];
        let params = mdp
            .as_dict()
            .unwrap()
            .get("TransformParams")
            .unwrap()
            .as_dict()
            .unwrap();
        assert!(params.get("Action").unwrap().is_name("Include"));
        assert_eq!(
            params.get("Fields"),
            Some(&Obj::Array(vec![Obj::str("company")]))
        );

        let err = signed_into(&twice, "approvals.director", &mut SoftSigner::rsa()).unwrap_err();
        assert!(err.to_string().contains("already signed"), "{err}");
        let err = signed_into(&pdf, "nope", &mut SoftSigner::rsa()).unwrap_err();
        assert!(err.to_string().contains("approvals.director"), "{err}");
    }

    #[test]
    fn seed_values_are_honoured() {
        let with_sv = |sv: &str| {
            let field = format!(
                "<< /Type /Annot /Subtype /Widget /FT /Sig /T (Sig) /Rect [0 0 0 0] /P 3 0 R /SV << {sv} >> >>"
            );
            write_pdf(&[
                b"<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [5 0 R] >> >>",
                b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
                b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Annots [5 0 R] >>",
                b"null",
                field.as_bytes(),
            ])
        };
        let sign = |sv: &str| signed_into(&with_sv(sv), "Sig", &mut SoftSigner::rsa());
        let pdf = sign("/Ff 2 /SubFilter [/ETSI.CAdES.detached]").unwrap();
        let r = &verify(&pdf).unwrap()[0];
        assert_eq!(r.status, Status::Valid, "{:?}", r.notes);
        assert_eq!(r.sub_filter.as_deref(), Some("ETSI.CAdES.detached"));
        // Not required: our own format is kept.
        let pdf = sign("/SubFilter [/ETSI.CAdES.detached]").unwrap();
        assert_eq!(
            verify(&pdf).unwrap()[0].sub_filter.as_deref(),
            Some("adbe.pkcs7.detached")
        );
        for (sv, msg) in [
            ("/Ff 64 /DigestMethod [/SHA512]", "SHA512"),
            ("/Ff 2 /SubFilter [/adbe.pkcs7.sha1]", "adbe.pkcs7.sha1"),
            ("/Ff 1 /Filter /Entrust.PPKEF", "Entrust.PPKEF"),
            (
                "/TimeStamp << /URL (http://tsa.example) /Ff 1 >>",
                "timestamp",
            ),
        ] {
            let err = sign(sv).unwrap_err().to_string();
            assert!(err.contains(msg), "{sv}: {err}");
        }
        assert!(sign("/Ff 64 /DigestMethod [/SHA256 /SHA512]").is_ok());
        assert!(sign("/Ff 8 /Reasons [(Approved)]").is_ok());
    }

    #[test]
    fn certifying_into_a_locked_field() {
        let req = SignRequest {
            field: Some("approvals.director".into()),
            certify: Some(DocMdp::FormFilling),
            time: Some(DateTime::parse_from_rfc3339(LATER).unwrap()),
            ..Default::default()
        };
        let pdf = sign_pdf(&empty_field_pdf(), &req, &mut SoftSigner::rsa()).unwrap();
        let r = &verify(&pdf).unwrap()[0];
        assert_eq!(r.status, Status::Valid, "{:?}", r.notes);
        assert_eq!(r.field, "approvals.director");
        assert_eq!(r.certification, Some(DocMdp::FormFilling));
        assert_eq!(
            crate::inspect(&pdf).unwrap().certified,
            Some(DocMdp::FormFilling)
        );
        // DocMDP and the field's FieldMDP side by side.
        let doc = Document::parse(&pdf).unwrap();
        let Some(Obj::Ref(sig, _)) = doc.get(6).unwrap().as_dict().unwrap().get("V").cloned()
        else {
            panic!("field has no /V");
        };
        let sig = doc.get(sig).unwrap();
        let methods: Vec<Obj> = sig
            .as_dict()
            .unwrap()
            .get("Reference")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                r.as_dict()
                    .unwrap()
                    .get("TransformMethod")
                    .cloned()
                    .unwrap()
            })
            .collect();
        assert_eq!(methods, [Obj::name("DocMDP"), Obj::name("FieldMDP")]);
    }

    fn certified(pdf: &[u8], level: DocMdp) -> Result<Vec<u8>, Error> {
        let req = SignRequest {
            certify: Some(level),
            time: Some(DateTime::parse_from_rfc3339(LATER).unwrap()),
            ..Default::default()
        };
        sign_pdf(pdf, &req, &mut SoftSigner::rsa())
    }

    #[test]
    fn certification_is_reported_and_allows_approvals() {
        let cert = certified(&plain_pdf(), DocMdp::FormFilling).unwrap();
        assert_eq!(
            crate::inspect(&cert).unwrap().certified,
            Some(DocMdp::FormFilling)
        );
        let r = &verify(&cert).unwrap()[0];
        assert_eq!(r.status, Status::Valid, "{:?}", r.notes);
        assert_eq!(r.certification, Some(DocMdp::FormFilling));
        let twice = signed(&cert, &mut SoftSigner::ec(), LATER);
        let r = verify(&twice).unwrap();
        assert_eq!(r[0].certification, Some(DocMdp::FormFilling));
        assert_eq!(r[0].changes, Changes::Signatures);
        assert!(r[0].notes.is_empty(), "{:?}", r[0].notes);
        assert_eq!(r[1].certification, None);
        assert_eq!(r[1].status, Status::Valid);
    }

    #[test]
    fn no_changes_certification_refuses_signatures() {
        let cert = certified(&plain_pdf(), DocMdp::NoChanges).unwrap();
        assert_eq!(
            verify(&cert).unwrap()[0].certification,
            Some(DocMdp::NoChanges)
        );
        let req = SignRequest::default();
        let e = sign_pdf(&cert, &req, &mut SoftSigner::ec()).unwrap_err();
        assert!(matches!(e, Error::NotPermitted(_)), "{e}");
        // A change made anyway is pointed out.
        let forced = append_update(&cert, &[(4, b"<< /Length 0 >>\nstream\n\nendstream")]);
        let r = &verify(&forced).unwrap()[0];
        assert!(
            r.notes.iter().any(|n| n.contains("certified")),
            "{:?}",
            r.notes
        );
    }

    #[test]
    fn only_the_first_signature_certifies() {
        let once = signed(&plain_pdf(), &mut SoftSigner::rsa(), LATER);
        let e = certified(&once, DocMdp::Annotations).unwrap_err();
        assert!(matches!(e, Error::NotPermitted(_)), "{e}");
        let cert = certified(&plain_pdf(), DocMdp::Annotations).unwrap();
        assert!(certified(&cert, DocMdp::Annotations).is_err());
        assert!(crate::check_permitted(&cert, None).is_ok());
    }

    #[test]
    fn content_change_after_signing_is_reported() {
        let pdf = signed(&plain_pdf(), &mut SoftSigner::rsa(), LATER);
        let pdf = append_update(
            &pdf,
            &[(
                4,
                b"<< /Length 23 >>\nstream\nBT 72 760 Td (No) Tj ET\nendstream",
            )],
        );
        let r = &verify(&pdf).unwrap()[0];
        assert_eq!(r.status, Status::Valid);
        assert_eq!(r.changes, Changes::Content);
        assert_eq!(r.later_revisions, 1);
    }

    #[test]
    fn added_comment_is_an_annotation_change() {
        let pdf = signed(&plain_pdf(), &mut SoftSigner::rsa(), LATER);
        let doc = Document::parse(&pdf).unwrap();
        let page = doc.get(3).unwrap();
        let annots = page.as_dict().unwrap().get("Annots").unwrap().clone();
        let Obj::Array(mut annots) = annots else {
            panic!("inline /Annots expected")
        };
        let note = doc.next_object_id();
        annots.push(Obj::Ref(note, 0));
        let mut page = page.as_dict().unwrap().clone();
        page.set("Annots", Obj::Array(annots));
        let mut page_bytes = Vec::new();
        crate::pdf::object::write_dict(&mut page_bytes, &page);
        let pdf = append_update(
            &pdf,
            &[
                (3, &page_bytes),
                (
                    note,
                    b"<< /Type /Annot /Subtype /Text /Rect [10 10 30 30] /Contents (ok) >>",
                ),
            ],
        );
        let r = &verify(&pdf).unwrap()[0];
        assert_eq!(r.status, Status::Valid);
        assert_eq!(r.changes, Changes::FormOrAnnotations);
    }

    #[test]
    fn signing_time_outside_certificate_validity() {
        let pdf = signed(&plain_pdf(), &mut SoftSigner::rsa(), "2001-01-01T00:00:00Z");
        let r = &verify(&pdf).unwrap()[0];
        assert_eq!(r.status, Status::Valid);
        assert_eq!(r.time_in_validity, Some(false));
        assert!(!r.notes.is_empty());
    }

    #[test]
    fn unsigned_file_has_no_reports() {
        assert!(verify(&plain_pdf()).unwrap().is_empty());
    }

    #[test]
    fn cca_root_is_self_signed() {
        let root = Certificate::from_der(CCA_INDIA_2022).unwrap();
        assert!(signed_by(&root, &root));
        assert!(is_ca(&root));
        assert_eq!(details(&root).subject, "CCA India 2022");
        let (chain, trust) = build_chain(&root, &[]);
        assert_eq!(chain.len(), 1);
        assert_eq!(trust, Trust::CcaIndia);
    }

    #[test]
    fn pdf_dates() {
        let t = parse_pdf_date("D:20261020143210+05'30'").unwrap();
        assert_eq!(t.to_rfc3339(), "2026-10-20T14:32:10+05:30");
        let t = parse_pdf_date("D:2026102014Z").unwrap();
        assert_eq!(t.to_rfc3339(), "2026-10-20T14:00:00+00:00");
        assert!(parse_pdf_date("yesterday").is_none());
    }
}
