//! Everything a DSC holder may want to look up about their certificate, and
//! the public certificate as a file (DER, PEM or a PKCS#7 chain). Nothing
//! here touches a private key: the input is always certificate bytes.

use base64::Engine;
use cms::cert::CertificateChoices;
use cms::content_info::{CmsVersion, ContentInfo};
use cms::signed_data::{
    CertificateSet, DigestAlgorithmIdentifiers, EncapsulatedContentInfo, SignedData, SignerInfos,
};
use const_oid::ObjectIdentifier;
use const_oid::db::{rfc4519, rfc5280, rfc5911, rfc5912};
use der::asn1::{Any, SetOfVec};
use der::{Decode, Encode};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use x509_cert::Certificate;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    CertificatePolicies, ExtendedKeyUsage, KeyUsage, KeyUsages, SubjectAltName,
};

use crate::certinfo::{CertSummary, attr, to_chrono};
use crate::{Error, KeyKind, verify};

const EMAIL_ADDRESS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.1");

/// India PKI certificate policies, from the CCA's "OID Hierarchy for India
/// PKI" (CCA-OID) and "X.509 Certificate Policy for India PKI" (CCA-CP).
/// CA and sub-CA certificates carry the policy arc itself; subscriber
/// certificates carry a class. The policies do not tell an individual's
/// certificate from an organisation's.
const INDIA_PKI_POLICIES: &[(&str, &str)] = &[
    ("2.16.356.100.2", "India PKI certificate policy (CA)"),
    ("2.16.356.100.2.1", "Class 1"),
    ("2.16.356.100.2.2", "Class 2"),
    ("2.16.356.100.2.3", "Class 3"),
    ("2.16.356.100.2.4.1", "eKYC single factor"),
    ("2.16.356.100.2.4.2", "eKYC multi factor"),
];

/// Extended key usages seen on DSCs and their issuers.
const EXTENDED_KEY_USAGES: &[(&str, &str)] = &[
    ("1.3.6.1.5.5.7.3.1", "TLS server"),
    ("1.3.6.1.5.5.7.3.2", "Client authentication"),
    ("1.3.6.1.5.5.7.3.3", "Code signing"),
    ("1.3.6.1.5.5.7.3.4", "Email protection"),
    ("1.3.6.1.5.5.7.3.8", "Time stamping"),
    ("1.3.6.1.5.5.7.3.9", "OCSP signing"),
    ("1.3.6.1.5.5.7.3.36", "Document signing"),
    ("1.3.6.1.4.1.311.10.3.12", "Document signing (Microsoft)"),
    ("1.3.6.1.4.1.311.20.2.2", "Smart card logon"),
    ("1.2.840.113583.1.1.5", "Adobe authentic documents"),
    ("2.5.29.37.0", "Any purpose"),
];

/// A certificate policy, named when it is one of India PKI's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub oid: String,
    pub name: Option<&'static str>,
}

/// An extended key usage, named when it is a well-known one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Usage {
    pub oid: String,
    pub name: Option<&'static str>,
}

#[derive(Debug, Clone)]
pub struct CertificateDetails {
    pub name: String,
    pub organization: Option<String>,
    /// The subject's serialNumber attribute: Indian DSCs put a hash of the
    /// holder's PAN (or another ID) here.
    pub subject_serial: Option<String>,
    pub email: Option<String>,
    /// Full distinguished names, RFC 4514 style.
    pub subject: String,
    pub issuer: String,
    pub issuer_name: String,
    pub serial_hex: String,
    pub not_before: chrono::DateTime<chrono::Utc>,
    pub not_after: chrono::DateTime<chrono::Utc>,
    /// "RSA 2048", "EC P-256".
    pub key: String,
    /// Absent when the certificate has no key usage extension (unrestricted).
    pub key_usage: Option<Vec<&'static str>>,
    pub extended_key_usage: Vec<Usage>,
    pub policies: Vec<Policy>,
    pub is_ca: bool,
    /// `AB:CD:…`, as `openssl x509 -fingerprint` prints it.
    pub sha1: String,
    pub sha256: String,
}

fn colon_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn key_usage_names(ku: KeyUsage) -> Vec<&'static str> {
    [
        (KeyUsages::DigitalSignature, "Digital signature"),
        (KeyUsages::NonRepudiation, "Non-repudiation"),
        (KeyUsages::KeyEncipherment, "Key encipherment"),
        (KeyUsages::DataEncipherment, "Data encipherment"),
        (KeyUsages::KeyAgreement, "Key agreement"),
        (KeyUsages::KeyCertSign, "Certificate signing"),
        (KeyUsages::CRLSign, "CRL signing"),
        (KeyUsages::EncipherOnly, "Encipher only"),
        (KeyUsages::DecipherOnly, "Decipher only"),
    ]
    .into_iter()
    .filter(|(flag, _)| ku.0.contains(*flag))
    .map(|(_, name)| name)
    .collect()
}

pub fn policy_name(oid: &str) -> Option<&'static str> {
    INDIA_PKI_POLICIES
        .iter()
        .find(|(o, _)| *o == oid)
        .map(|(_, n)| *n)
}

pub fn usage_name(oid: &str) -> Option<&'static str> {
    EXTENDED_KEY_USAGES
        .iter()
        .find(|(o, _)| *o == oid)
        .map(|(_, n)| *n)
}

impl CertificateDetails {
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let summary = CertSummary::from_der(der)?;
        let c = Certificate::from_der(der)?;
        let tbs = &c.tbs_certificate;

        let mut email = attr(&tbs.subject, EMAIL_ADDRESS);
        let mut key_usage = None;
        let mut extended_key_usage = Vec::new();
        let mut policies = Vec::new();
        for ext in tbs.extensions.iter().flatten() {
            let value = ext.extn_value.as_bytes();
            if ext.extn_id == rfc5280::ID_CE_KEY_USAGE {
                key_usage = KeyUsage::from_der(value).ok().map(key_usage_names);
            } else if ext.extn_id == rfc5280::ID_CE_EXT_KEY_USAGE {
                if let Ok(eku) = ExtendedKeyUsage::from_der(value) {
                    extended_key_usage = eku
                        .0
                        .iter()
                        .map(|o| Usage {
                            oid: o.to_string(),
                            name: usage_name(&o.to_string()),
                        })
                        .collect();
                }
            } else if ext.extn_id == rfc5280::ID_CE_CERTIFICATE_POLICIES {
                if let Ok(cp) = CertificatePolicies::from_der(value) {
                    policies =
                        cp.0.iter()
                            .map(|p| {
                                let oid = p.policy_identifier.to_string();
                                Policy {
                                    name: policy_name(&oid),
                                    oid,
                                }
                            })
                            .collect();
                }
            } else if ext.extn_id == rfc5280::ID_CE_SUBJECT_ALT_NAME
                && email.is_none()
                && let Ok(san) = SubjectAltName::from_der(value)
            {
                email = san.0.iter().find_map(|n| match n {
                    GeneralName::Rfc822Name(m) => Some(m.to_string()),
                    _ => None,
                });
            }
        }

        let spki = &tbs.subject_public_key_info;
        let key = match summary.key_kind {
            KeyKind::Rsa => {
                let n = summary.rsa_modulus.as_deref().unwrap_or_default();
                let bits = n.len() * 8 - n.first().map_or(8, |b| b.leading_zeros() as usize);
                format!("RSA {bits}")
            }
            KeyKind::Ec => {
                let curve = spki
                    .algorithm
                    .parameters
                    .as_ref()
                    .and_then(|p| p.decode_as::<ObjectIdentifier>().ok());
                match curve {
                    Some(o) if o == rfc5912::SECP_256_R_1 => "EC P-256".into(),
                    Some(o) if o == rfc5912::SECP_384_R_1 => "EC P-384".into(),
                    Some(o) if o == rfc5912::SECP_521_R_1 => "EC P-521".into(),
                    Some(o) => format!("EC {o}"),
                    None => "EC".into(),
                }
            }
        };

        Ok(CertificateDetails {
            name: summary.subject_cn,
            organization: summary.organization,
            subject_serial: attr(&tbs.subject, rfc4519::SERIAL_NUMBER),
            email,
            subject: tbs.subject.to_string(),
            issuer: tbs.issuer.to_string(),
            issuer_name: summary.issuer_cn,
            serial_hex: summary.serial_hex,
            not_before: to_chrono(tbs.validity.not_before),
            not_after: to_chrono(tbs.validity.not_after),
            key,
            key_usage,
            extended_key_usage,
            policies,
            is_ca: summary.is_ca,
            sha1: colon_hex(&Sha1::digest(der)),
            sha256: colon_hex(&Sha256::digest(der)),
        })
    }
}

/// The certificate in PEM, as `openssl x509 -outform PEM` writes it.
pub fn to_pem(der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

/// A "certs-only" PKCS#7 file (`.p7b`, DER): a `SignedData` that holds the
/// certificates and nothing signed.
pub fn to_p7b(certs: &[Vec<u8>]) -> Result<Vec<u8>, Error> {
    let mut set = SetOfVec::new();
    for (i, c) in certs.iter().enumerate() {
        // A duplicate would make the SET OF invalid; skip it.
        if !certs[..i].contains(c) {
            set.insert(CertificateChoices::Certificate(Certificate::from_der(c)?))?;
        }
    }
    let sd = SignedData {
        version: CmsVersion::V1,
        digest_algorithms: DigestAlgorithmIdentifiers::new(),
        encap_content_info: EncapsulatedContentInfo {
            econtent_type: rfc5911::ID_DATA,
            econtent: None,
        },
        certificates: Some(CertificateSet(set)),
        crls: None,
        signer_infos: SignerInfos(SetOfVec::new()),
    };
    Ok(ContentInfo {
        content_type: rfc5911::ID_SIGNED_DATA,
        content: Any::encode_from(&sd)?,
    }
    .to_der()?)
}

/// `issuers` (the CA certificates found for `cert`, nearest first) followed
/// by the CCA India 2022 root when the last of them is signed by it.
pub fn complete_chain(cert: &[u8], issuers: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut chain = issuers.to_vec();
    let root = verify::CCA_INDIA_2022;
    let last = chain.last().map_or(cert, Vec::as_slice);
    if last != root
        && let (Ok(last), Ok(root_cert)) =
            (Certificate::from_der(last), Certificate::from_der(root))
        && last.tbs_certificate.issuer == root_cert.tbs_certificate.subject
        && verify::signed_by(&last, &root_cert)
    {
        chain.push(root.to_vec());
    }
    chain
}

/// Default file name for an exported certificate: `DK_RAHUL_DSC.cer`.
pub fn export_file_name(holder: &str, extension: &str) -> String {
    let mut stem = String::new();
    for ch in holder.chars() {
        if ch.is_alphanumeric() {
            stem.push(ch);
        } else if !stem.is_empty() && !stem.ends_with('_') {
            stem.push('_');
        }
    }
    let stem = stem.trim_end_matches('_');
    let stem = if stem.is_empty() { "certificate" } else { stem };
    format!("{stem}_DSC.{extension}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const RSA: &[u8] = include_bytes!("../testdata/rsa-cert.der");
    const EC: &[u8] = include_bytes!("../testdata/ec-cert.der");
    /// Class 3 style test DSC: PAN hash in serialNumber, India PKI policies.
    const CLASS3: &[u8] = include_bytes!("../testdata/portal/signer-cert.der");

    #[test]
    fn rsa_details() {
        let d = CertificateDetails::from_der(RSA).unwrap();
        assert_eq!(d.name, "UNIT TEST RSA");
        assert_eq!(d.organization.as_deref(), Some("Unit Test Org"));
        assert_eq!(d.issuer_name, "UNIT TEST RSA");
        assert!(d.subject.contains("CN=UNIT TEST RSA"));
        assert_eq!(d.key, "RSA 1024");
        assert_eq!(
            d.key_usage,
            Some(vec!["Digital signature", "Non-repudiation"])
        );
        assert!(d.policies.is_empty() && d.extended_key_usage.is_empty());
        assert_eq!(d.email, None);
        assert_eq!(d.sha256.len(), 32 * 3 - 1);
        assert_eq!(
            d.sha256.replace(':', "").to_lowercase(),
            Sha256::digest(RSA)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        assert_eq!(d.sha1.len(), 20 * 3 - 1);
    }

    #[test]
    fn ec_key() {
        let d = CertificateDetails::from_der(EC).unwrap();
        assert_eq!(d.key, "EC P-256");
        assert_eq!(d.organization, None);
    }

    #[test]
    fn india_pki_fields() {
        let d = CertificateDetails::from_der(CLASS3).unwrap();
        assert_eq!(d.name, "SWAKSHAR TEST SIGNER");
        assert_eq!(
            d.subject_serial.as_deref(),
            Some("6442fd73a940c1186d6268bd27f89233e12429902c7805037e8aab6e717be6d9")
        );
        assert_eq!(d.issuer_name, "Swakshar Test CA 2026");
        assert_eq!(
            d.policies,
            vec![
                Policy {
                    oid: "2.16.356.100.2.3".into(),
                    name: Some("Class 3")
                },
                Policy {
                    oid: "2.16.356.100.2.2".into(),
                    name: Some("Class 2")
                },
            ]
        );
        assert_eq!(d.not_before.format("%Y-%m-%d").to_string(), "2026-02-13");
        assert_eq!(d.not_after.format("%Y-%m-%d").to_string(), "2028-02-13");
    }

    #[test]
    fn names_for_oids() {
        assert_eq!(policy_name("2.16.356.100.2.4.2"), Some("eKYC multi factor"));
        assert_eq!(policy_name("2.16.356.100.1.8.2"), None);
        assert_eq!(
            usage_name("1.3.6.1.4.1.311.10.3.12"),
            Some("Document signing (Microsoft)")
        );
        assert_eq!(usage_name("1.2.3.4"), None);
    }

    #[test]
    fn pem_round_trip() {
        let pem = to_pem(RSA);
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(pem.ends_with("\n-----END CERTIFICATE-----\n"));
        assert!(pem.lines().all(|l| l.len() <= 64));
        let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(body)
                .unwrap(),
            RSA
        );
    }

    #[test]
    fn p7b_holds_the_certificates() {
        let p7b = to_p7b(&[RSA.to_vec(), EC.to_vec(), RSA.to_vec()]).unwrap();
        let ci = ContentInfo::from_der(&p7b).unwrap();
        assert_eq!(ci.content_type, rfc5911::ID_SIGNED_DATA);
        let sd: SignedData = ci.content.decode_as().unwrap();
        assert!(sd.signer_infos.0.is_empty());
        let mut certs: Vec<Vec<u8>> = sd
            .certificates
            .unwrap()
            .0
            .iter()
            .map(|c| match c {
                CertificateChoices::Certificate(c) => c.to_der().unwrap(),
                _ => unreachable!(),
            })
            .collect();
        certs.sort();
        let mut want = vec![RSA.to_vec(), EC.to_vec()];
        want.sort();
        assert_eq!(certs, want);
    }

    #[test]
    fn chain_ends_at_cca_root_only_when_signed_by_it() {
        // A self-signed test certificate does not lead to the CCA root.
        assert!(complete_chain(RSA, &[]).is_empty());
        assert_eq!(complete_chain(CLASS3, &[RSA.to_vec()]), vec![RSA.to_vec()]);
        // The root itself is not added twice.
        let root = verify::CCA_INDIA_2022.to_vec();
        assert_eq!(complete_chain(RSA, std::slice::from_ref(&root)), vec![root]);
    }

    #[test]
    fn file_names() {
        assert_eq!(export_file_name("DK RAHUL", "cer"), "DK_RAHUL_DSC.cer");
        assert_eq!(export_file_name(" A. B/C ", "pem"), "A_B_C_DSC.pem");
        assert_eq!(export_file_name("??", "p7b"), "certificate_DSC.p7b");
    }
}
