//! Human-readable facts about an X.509 certificate.

use const_oid::db::{rfc4519, rfc5280, rfc5912};
use der::asn1::UintRef;
use der::{Decode, Encode, Sequence, Tagged};
use x509_cert::Certificate;
use x509_cert::ext::pkix::{BasicConstraints, KeyUsage, KeyUsages};
use x509_cert::name::Name;

use crate::{Error, KeyKind};

#[derive(Debug, Clone)]
pub struct CertSummary {
    pub subject_cn: String,
    pub issuer_cn: String,
    pub organization: Option<String>,
    pub serial_hex: String,
    pub not_before: chrono::DateTime<chrono::Utc>,
    pub not_after: chrono::DateTime<chrono::Utc>,
    pub expired: bool,
    /// Key usage allows digital signatures / non-repudiation.
    pub can_sign: bool,
    pub is_ca: bool,
    pub key_kind: KeyKind,
    /// Signature size in bytes (RSA modulus length, or ECDSA DER upper bound).
    pub signature_len: usize,
    pub rsa_modulus: Option<Vec<u8>>,
    pub subject_der: Vec<u8>,
    pub issuer_der: Vec<u8>,
}

#[derive(Sequence)]
struct RsaPublicKey<'a> {
    n: UintRef<'a>,
    _e: UintRef<'a>,
}

fn attr(name: &Name, oid: const_oid::ObjectIdentifier) -> Option<String> {
    for rdn in name.0.iter() {
        for atv in rdn.0.iter() {
            if atv.oid == oid {
                let bytes = atv.value.value();
                return Some(if atv.value.tag() == der::Tag::BmpString {
                    let u: Vec<u16> = bytes
                        .chunks(2)
                        .map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]))
                        .collect();
                    String::from_utf16_lossy(&u)
                } else {
                    String::from_utf8_lossy(bytes).into_owned()
                });
            }
        }
    }
    None
}

fn to_chrono(t: x509_cert::time::Time) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp(t.to_unix_duration().as_secs() as i64, 0).unwrap_or_default()
}

impl CertSummary {
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let c = Certificate::from_der(der).map_err(|e| Error::Cms(e.to_string()))?;
        let tbs = &c.tbs_certificate;
        let subject_cn = attr(&tbs.subject, rfc4519::CN).unwrap_or_else(|| tbs.subject.to_string());
        let issuer_cn = attr(&tbs.issuer, rfc4519::CN).unwrap_or_else(|| tbs.issuer.to_string());
        let organization = attr(&tbs.subject, rfc4519::O);

        let mut can_sign = true; // no keyUsage extension = unrestricted
        let mut is_ca = false;
        for ext in tbs.extensions.iter().flatten() {
            if ext.extn_id == rfc5280::ID_CE_KEY_USAGE {
                if let Ok(ku) = KeyUsage::from_der(ext.extn_value.as_bytes()) {
                    can_sign = ku.0.contains(KeyUsages::DigitalSignature)
                        || ku.0.contains(KeyUsages::NonRepudiation);
                    if ku.0.contains(KeyUsages::KeyCertSign) {
                        is_ca = true;
                    }
                }
            } else if ext.extn_id == rfc5280::ID_CE_BASIC_CONSTRAINTS
                && let Ok(bc) = BasicConstraints::from_der(ext.extn_value.as_bytes())
            {
                is_ca |= bc.ca;
            }
        }

        let spki = &tbs.subject_public_key_info;
        let (key_kind, signature_len, rsa_modulus) =
            if spki.algorithm.oid == rfc5912::RSA_ENCRYPTION {
                let key = RsaPublicKey::from_der(spki.subject_public_key.raw_bytes())
                    .map_err(|e| Error::Cms(e.to_string()))?;
                let n = key.n.as_bytes().to_vec();
                (KeyKind::Rsa, n.len(), Some(n))
            } else if spki.algorithm.oid == rfc5912::ID_EC_PUBLIC_KEY {
                (KeyKind::Ec, 140, None)
            } else {
                return Err(Error::Token("Unsupported key type on certificate".into()));
            };

        let not_before = to_chrono(tbs.validity.not_before);
        let not_after = to_chrono(tbs.validity.not_after);
        let serial_hex = tbs
            .serial_number
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect();
        Ok(CertSummary {
            subject_cn,
            issuer_cn,
            organization,
            serial_hex,
            not_before,
            not_after,
            expired: chrono::Utc::now() > not_after,
            can_sign,
            is_ca,
            key_kind,
            signature_len,
            rsa_modulus,
            subject_der: tbs.subject.to_der().unwrap_or_default(),
            issuer_der: tbs.issuer.to_der().unwrap_or_default(),
        })
    }
}
