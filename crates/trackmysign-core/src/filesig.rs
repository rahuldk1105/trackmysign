//! Signatures over any file (Word, Excel, ZIP, XML, images, …) as standard
//! CMS / PKCS#7 `SignedData`, the format OpenSSL, Windows and Java read:
//!
//! - detached: `<file>.p7s` next to the file, which stays as it is;
//! - attached (enveloping): `<file>.p7m`, which carries the file.
//!
//! Both are DER, SHA-256, with the signed attributes contentType,
//! signingTime, messageDigest and ESS signingCertificateV2 and the
//! certificate chain included (CAdES-BES); an RFC 3161 timestamp makes it
//! CAdES-T. The signature is built by [`crate::cms`] and checked by
//! [`crate::verify::verify_cms`], as for PDFs.

use std::path::{Path, PathBuf};

use base64::Engine;
use chrono::{DateTime, FixedOffset, Local};
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use const_oid::db::rfc5911;
use der::Decode;
use der::asn1::OctetString;
use sha2::{Digest, Sha256};

use crate::verify::SignatureReport;
use crate::{Error, Signer, cms as build, tsa};

pub const DETACHED_EXT: &str = "p7s";
pub const ATTACHED_EXT: &str = "p7m";

#[derive(Debug, Clone, Default)]
pub struct FileSignRequest {
    /// Put the file inside the signature (`.p7m`) instead of next to it (`.p7s`).
    pub attached: bool,
    /// RFC 3161 timestamp authority to countersign with (needs the internet).
    pub timestamp: Option<String>,
    /// Defaults to now, in local time.
    pub time: Option<DateTime<FixedOffset>>,
}

/// Signs `content` and returns the signature file (DER).
pub fn sign_file(
    content: &[u8],
    req: &FileSignRequest,
    signer: &mut dyn Signer,
) -> Result<Vec<u8>, Error> {
    let time = req.time.unwrap_or_else(|| Local::now().fixed_offset());
    let mut cms = if req.attached {
        build::build_signed_data_attached(signer, content, &time)?
    } else {
        let digest: [u8; 32] = Sha256::digest(content).into();
        build::build_signed_data(signer, &digest, &time)?
    };
    if let Some(url) = &req.timestamp {
        let token = tsa::timestamp(url, &build::signature_value(&cms)?)?;
        cms = build::add_unsigned_attr(&cms, tsa::ID_AA_SIGNATURE_TIME_STAMP_TOKEN, &token)?;
    }
    Ok(cms)
}

/// `report.docx` → `report.docx.p7s` (or `.p7m`), next to the file.
pub fn signature_path(input: &Path, attached: bool) -> PathBuf {
    let mut name = input.as_os_str().to_owned();
    name.push(".");
    name.push(if attached { ATTACHED_EXT } else { DETACHED_EXT });
    PathBuf::from(name)
}

/// Whether `path` looks like a signature file (`.p7s`, `.p7m`).
pub fn is_signature_file(path: &Path) -> bool {
    path.extension().and_then(|e| e.to_str()).is_some_and(|e| {
        e.eq_ignore_ascii_case(DETACHED_EXT) || e.eq_ignore_ascii_case(ATTACHED_EXT)
    })
}

/// The file a signature file belongs to: `report.docx.p7s` → `report.docx`.
pub fn signed_file_path(signature: &Path) -> Option<PathBuf> {
    is_signature_file(signature).then(|| signature.with_extension(""))
}

/// A detached signature lying next to `file`, if there is one.
pub fn find_signature(file: &Path) -> Option<PathBuf> {
    let p = signature_path(file, false);
    p.is_file().then_some(p)
}

/// Writes the signature file; an existing one is only replaced when
/// `replace` is set.
pub fn write_signature(path: &Path, data: &[u8], replace: bool) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = if replace {
        std::fs::File::create(path)?
    } else {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?
    };
    f.write_all(data)
}

/// Where "Save original" puts the content of `report.docx.p7m`:
/// `report.docx`, or `report (2).docx`, … when taken.
pub fn original_path(p7m: &Path) -> PathBuf {
    let first = match signed_file_path(p7m) {
        Some(p) => p,
        None => p7m.with_extension("bin"),
    };
    if !first.exists() {
        return first;
    }
    let stem = first
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let ext = first
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    (2..)
        .map(|n| first.with_file_name(format!("{stem} ({n}){ext}")))
        .find(|p| !p.exists())
        .unwrap()
}

/// The signature as DER: accepts DER, PEM (`-----BEGIN PKCS7-----`, `CMS`)
/// or bare Base64, and BER (indefinite lengths, chunked content, as
/// OpenSSL writes a `.p7m`).
pub fn read_signature(data: &[u8]) -> Result<Vec<u8>, Error> {
    let bad = || Error::Cms("not a PKCS#7 / CMS signature file".into());
    let der = if data.first() == Some(&0x30) {
        data.to_vec()
    } else {
        let text = std::str::from_utf8(data).map_err(|_| bad())?;
        let b64: String = text
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .flat_map(|l| l.chars())
            .filter(|c| !c.is_whitespace())
            .collect();
        base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|_| bad())?
    };
    let der = match ContentInfo::from_der(&der) {
        Ok(_) => der,
        Err(_) => ber_to_der(&der).ok_or_else(bad)?,
    };
    let ci = ContentInfo::from_der(&der).map_err(|_| bad())?;
    if ci.content_type != rfc5911::ID_SIGNED_DATA {
        return Err(Error::Cms(
            "the file is not a signature (SignedData)".into(),
        ));
    }
    Ok(der)
}

/// The file carried inside an attached signature; `None` for a detached one.
pub fn content(cms_der: &[u8]) -> Result<Option<Vec<u8>>, Error> {
    let sd: SignedData = ContentInfo::from_der(cms_der)?.content.decode_as()?;
    match sd.encap_content_info.econtent {
        None => Ok(None),
        Some(e) => Ok(Some(e.decode_as::<OctetString>()?.into_bytes())),
    }
}

/// What [`verify_file`] found.
#[derive(Debug, Clone)]
pub struct FileCheck {
    /// The signature checks; `field` holds the file name.
    pub report: SignatureReport,
    /// The file is inside the signature (`.p7m`).
    pub attached: bool,
    /// SHA-256 of the signed content (hex), when known.
    pub sha256: Option<String>,
}

/// Checks `signature` (any form [`read_signature`] accepts) over
/// `content`; for an attached signature `content` may be left out.
pub fn verify_file(
    signature: &[u8],
    content: Option<&[u8]>,
    name: &str,
) -> Result<FileCheck, Error> {
    let der = read_signature(signature)?;
    let inside = self::content(&der)?;
    let report = crate::verify::verify_cms(&der, content, name);
    let signed = inside.as_deref().or(content);
    Ok(FileCheck {
        report,
        attached: inside.is_some(),
        sha256: signed.map(sha256_hex),
    })
}

/// Upper-case hex SHA-256, as Windows and portals print it.
pub fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect()
}

/// Re-encodes BER as DER: definite lengths, and constructed (chunked)
/// strings joined into one. Returns `None` for anything malformed.
fn ber_to_der(data: &[u8]) -> Option<Vec<u8>> {
    let (out, end) = ber_element(data, 0, 0)?;
    (end == data.len()).then_some(out)
}

fn der_length(n: usize) -> Vec<u8> {
    if n < 0x80 {
        return vec![n as u8];
    }
    let bytes: Vec<u8> = n
        .to_be_bytes()
        .iter()
        .copied()
        .skip_while(|b| *b == 0)
        .collect();
    let mut v = vec![0x80 | bytes.len() as u8];
    v.extend(bytes);
    v
}

/// One element at `pos`: its DER encoding and where it ends.
fn ber_element(d: &[u8], pos: usize, depth: usize) -> Option<(Vec<u8>, usize)> {
    if depth > 64 {
        return None;
    }
    let tag = *d.get(pos)?;
    // High tag numbers are not used by CMS.
    if tag & 0x1f == 0x1f {
        return None;
    }
    let first = *d.get(pos + 1)?;
    let mut p = pos + 2;
    let len = match first {
        0x80 => None,
        n if n < 0x80 => Some(n as usize),
        n => {
            let k = (n & 0x7f) as usize;
            if k > 4 {
                return None;
            }
            let mut v = 0usize;
            for _ in 0..k {
                v = (v << 8) | *d.get(p)? as usize;
                p += 1;
            }
            Some(v)
        }
    };
    if tag & 0x20 == 0 {
        let n = len?;
        let content = d.get(p..p.checked_add(n)?)?;
        let mut out = vec![tag];
        out.extend(der_length(n));
        out.extend_from_slice(content);
        return Some((out, p + n));
    }
    let mut children = Vec::new();
    let end = match len {
        Some(n) => {
            let end = p.checked_add(n)?;
            if end > d.len() {
                return None;
            }
            while p < end {
                let (c, next) = ber_element(d, p, depth + 1)?;
                children.push(c);
                p = next;
            }
            if p != end {
                return None;
            }
            end
        }
        None => loop {
            if d.get(p..p + 2)? == [0, 0] {
                break p + 2;
            }
            let (c, next) = ber_element(d, p, depth + 1)?;
            children.push(c);
            p = next;
        },
    };
    // Universal constructed strings (OCTET STRING above all) become primitive.
    let string_tags = [0x23, 0x24, 0x2c, 0x33, 0x34, 0x36, 0x3a];
    if string_tags.contains(&tag) {
        let mut joined = Vec::new();
        for c in &children {
            let (_, start, stop) = header(c)?;
            joined.extend_from_slice(&c[start..stop]);
        }
        let mut out = vec![tag & !0x20];
        out.extend(der_length(joined.len()));
        out.extend(joined);
        return Some((out, end));
    }
    let body: Vec<u8> = children.concat();
    let mut out = vec![tag];
    out.extend(der_length(body.len()));
    out.extend(body);
    Some((out, end))
}

/// Tag, content start and end of a DER element.
fn header(d: &[u8]) -> Option<(u8, usize, usize)> {
    let tag = *d.first()?;
    let first = *d.get(1)?;
    let (len, start) = if first < 0x80 {
        (first as usize, 2)
    } else {
        let k = (first & 0x7f) as usize;
        let mut v = 0usize;
        for i in 0..k {
            v = (v << 8) | *d.get(2 + i)? as usize;
        }
        (v, 2 + k)
    };
    Some((tag, start, start + len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyKind;
    use crate::verify::{Status, Trust};
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use p256::ecdsa::{Signature, SigningKey};
    use p256::pkcs8::DecodePrivateKey;

    struct TestSigner {
        key: SigningKey,
        cert: Vec<u8>,
    }

    impl TestSigner {
        fn new() -> Self {
            TestSigner {
                key: SigningKey::from_pkcs8_der(include_bytes!("../testdata/ec-key.der")).unwrap(),
                cert: include_bytes!("../testdata/ec-cert.der").to_vec(),
            }
        }
    }

    impl Signer for TestSigner {
        fn certificate(&self) -> &[u8] {
            &self.cert
        }
        fn chain(&self) -> &[Vec<u8>] {
            &[]
        }
        fn key_kind(&self) -> KeyKind {
            KeyKind::Ec
        }
        fn signature_len(&self) -> usize {
            72
        }
        fn sign_sha256(&mut self, digest: &[u8; 32]) -> Result<Vec<u8>, Error> {
            let sig: Signature = self.key.sign_prehash(digest).unwrap();
            Ok(sig.to_der().as_bytes().to_vec())
        }
    }

    const DATA: &[u8] = b"PK\x03\x04 not really a zip, but any bytes will do";

    fn signed(attached: bool) -> Vec<u8> {
        let req = FileSignRequest {
            attached,
            ..Default::default()
        };
        sign_file(DATA, &req, &mut TestSigner::new()).unwrap()
    }

    #[test]
    fn detached_round_trip() {
        let sig = signed(false);
        assert_eq!(content(&sig).unwrap(), None);
        let c = verify_file(&sig, Some(DATA), "a.zip").unwrap();
        assert_eq!(c.report.status, Status::Valid, "{:?}", c.report.notes);
        assert!(!c.attached);
        assert_eq!(c.report.field, "a.zip");
        assert_eq!(c.report.signer.unwrap().subject, "UNIT TEST EC");
        assert_eq!(c.report.trust, Trust::NotChecked);
        assert_eq!(c.report.digest_algorithm, Some("SHA-256"));
        assert_eq!(c.sha256.unwrap(), sha256_hex(DATA));
        assert_eq!(c.report.time_in_validity, Some(true));
    }

    #[test]
    fn detached_tampered_or_missing() {
        let sig = signed(false);
        let mut other = DATA.to_vec();
        other[5] ^= 1;
        let c = verify_file(&sig, Some(&other), "a.zip").unwrap();
        assert_eq!(c.report.status, Status::Invalid);
        let c = verify_file(&sig, None, "a.zip").unwrap();
        assert_eq!(c.report.status, Status::Unknown);
        assert!(c.report.notes[0].contains("detached"));
    }

    #[test]
    fn attached_round_trip() {
        let sig = signed(true);
        assert_eq!(content(&sig).unwrap().as_deref(), Some(DATA));
        let c = verify_file(&sig, None, "a.zip.p7m").unwrap();
        assert_eq!(c.report.status, Status::Valid, "{:?}", c.report.notes);
        assert!(c.attached);
        // A different file next to it is not what was signed.
        let c = verify_file(&sig, Some(b"other"), "a.zip.p7m").unwrap();
        assert_eq!(c.report.status, Status::Invalid);
    }

    #[test]
    fn attached_tampered() {
        let mut sig = signed(true);
        let at = sig.windows(DATA.len()).position(|w| w == DATA).unwrap();
        sig[at] ^= 1;
        let c = verify_file(&sig, None, "a.zip.p7m").unwrap();
        assert_eq!(c.report.status, Status::Invalid);
    }

    #[test]
    fn pem_and_base64_accepted() {
        let sig = signed(false);
        let b64 = base64::engine::general_purpose::STANDARD.encode(&sig);
        let pem = format!("-----BEGIN PKCS7-----\n{}\n-----END PKCS7-----\n", b64);
        assert_eq!(read_signature(pem.as_bytes()).unwrap(), sig);
        assert_eq!(read_signature(b64.as_bytes()).unwrap(), sig);
        assert!(read_signature(b"hello").is_err());
    }

    /// The signature with every SEQUENCE/SET written with indefinite length
    /// and the content OCTET STRING in chunks, as OpenSSL streams it.
    fn to_ber(d: &[u8]) -> Vec<u8> {
        let (tag, start, end) = header(d).unwrap();
        if tag == 0x04 && end - start > 4 {
            let mut out = vec![0x24, 0x80];
            for chunk in d[start..end].chunks(4) {
                out.push(0x04);
                out.extend(der_length(chunk.len()));
                out.extend_from_slice(chunk);
            }
            out.extend([0, 0]);
            return out;
        }
        if tag & 0x20 == 0 || tag == 0x31 && end - start < 200 {
            return d[..end].to_vec();
        }
        let mut out = vec![tag, 0x80];
        let mut p = start;
        while p < end {
            let (_, s, e) = header(&d[p..]).unwrap();
            let _ = s;
            out.extend(to_ber(&d[p..p + e]));
            p += e;
        }
        out.extend([0, 0]);
        out
    }

    #[test]
    fn ber_accepted() {
        let sig = signed(true);
        let ber = to_ber(&sig);
        assert_ne!(ber, sig);
        assert!(ContentInfo::from_der(&ber).is_err());
        let c = verify_file(&ber, None, "a.zip.p7m").unwrap();
        assert_eq!(c.report.status, Status::Valid, "{:?}", c.report.notes);
        assert_eq!(
            content(&read_signature(&ber).unwrap()).unwrap().as_deref(),
            Some(DATA)
        );
    }

    #[test]
    fn paths() {
        let p = Path::new("/tmp/x/report.docx");
        assert_eq!(
            signature_path(p, false),
            Path::new("/tmp/x/report.docx.p7s")
        );
        assert_eq!(signature_path(p, true), Path::new("/tmp/x/report.docx.p7m"));
        assert_eq!(
            signed_file_path(Path::new("/tmp/x/report.docx.P7S")).unwrap(),
            p
        );
        assert!(signed_file_path(p).is_none());
        assert!(is_signature_file(Path::new("a.p7m")));
    }

    #[test]
    fn original_path_never_taken() {
        let dir = std::env::temp_dir().join(format!("tms-filesig-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p7m = dir.join("data.xml.p7m");
        assert_eq!(original_path(&p7m), dir.join("data.xml"));
        std::fs::write(dir.join("data.xml"), b"x").unwrap();
        assert_eq!(original_path(&p7m), dir.join("data (2).xml"));
        let sig = dir.join("data.xml.p7s");
        write_signature(&sig, b"1", false).unwrap();
        assert!(write_signature(&sig, b"2", false).is_err());
        write_signature(&sig, b"3", true).unwrap();
        assert_eq!(std::fs::read(&sig).unwrap(), b"3");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
