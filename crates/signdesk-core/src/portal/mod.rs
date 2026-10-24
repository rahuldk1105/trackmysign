//! Signing for the GST portal (gst.gov.in), which asks a local signer on
//! `wss://127.0.0.1` to sign text with the user's DSC. This module has the
//! frames and the signature; the listener lives in the `portal-bridge` crate.

pub mod cms;
pub mod frame;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use const_oid::ObjectIdentifier;
use const_oid::db::{rfc4519, rfc5280};
use der::Decode;
use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use x509_cert::Certificate;
use x509_cert::ext::pkix::CertificatePolicies;

use crate::certinfo::{CertSummary, Validity, attr, validity_at};
use crate::{Error, Signer};

pub use frame::{NotSigned, Request};

/// CCA India certificate policies for the DSC classes (`2.16.356.100.2.<n>`).
const CCA_CLASS_POLICY: &str = "2.16.356.100.2.";

/// Encodes a signature for the reply: URL-safe base64 without padding, as
/// in the reply the portal is known to accept.
pub fn encode_signature(cms_der: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(cms_der)
}

/// The DER of a reply's signature; padding and whitespace are tolerated.
pub fn decode_signature(text: &str) -> Result<Vec<u8>, Error> {
    URL_SAFE_NO_PAD
        .decode(text.trim().trim_end_matches('='))
        .map_err(|e| Error::Cms(e.to_string()))
}

/// SHA-256 of the PAN in lower-case hex: what CCA guidelines put in the
/// subject `serialNumber` of an individual's DSC.
pub fn pan_hash(pan: &str) -> String {
    Sha256::digest(pan.trim().to_ascii_uppercase().as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Whether the certificate belongs to the holder of `pan`: its subject
/// `serialNumber` is the PAN's hash (or, on some older DSCs, the PAN itself).
pub fn matches_pan(cert_der: &[u8], pan: &str) -> bool {
    let pan = pan.trim();
    if pan.is_empty() {
        return false;
    }
    let Ok(cert) = Certificate::from_der(cert_der) else {
        return false;
    };
    let Some(serial) = attr(&cert.tbs_certificate.subject, rfc4519::SERIAL_NUMBER) else {
        return false;
    };
    let serial = serial.trim();
    serial.eq_ignore_ascii_case(&pan_hash(pan)) || serial.eq_ignore_ascii_case(pan)
}

/// `Class 3`, `Class 2`, ... from the CCA policy OIDs; the highest wins.
/// Empty when the certificate names none.
pub fn cert_class(cert_der: &[u8]) -> String {
    let Ok(cert) = Certificate::from_der(cert_der) else {
        return String::new();
    };
    let mut class = None;
    for ext in cert.tbs_certificate.extensions.iter().flatten() {
        if ext.extn_id != rfc5280::ID_CE_CERTIFICATE_POLICIES {
            continue;
        }
        let Ok(policies) = CertificatePolicies::from_der(ext.extn_value.as_bytes()) else {
            continue;
        };
        for p in policies.0 {
            let oid: ObjectIdentifier = p.policy_identifier;
            if let Some(n) = oid
                .to_string()
                .strip_prefix(CCA_CLASS_POLICY)
                .and_then(|n| n.parse::<u8>().ok())
            {
                class = class.max(Some(n));
            }
        }
    }
    class.map(|n| format!("Class {n}")).unwrap_or_default()
}

/// The certificate facts the reply carries.
pub fn reply_cert(cert_der: &[u8]) -> Result<frame::ReplyCert, Error> {
    let s = CertSummary::from_der(cert_der)?;
    let serial = BigUint::parse_bytes(s.serial_hex.as_bytes(), 16)
        .map(|n| n.to_string())
        .unwrap_or_default();
    Ok(frame::ReplyCert {
        serial,
        common_name: s.subject_cn,
        issuer_name: s.issuer_cn,
        not_before: s.not_before,
        not_after: s.not_after,
        class: cert_class(cert_der),
    })
}

/// Signs `request` and returns the reply frame. The signature is checked
/// against the certificate before anything is sent.
pub fn sign(
    signer: &mut dyn Signer,
    request: &Request,
    now: DateTime<Utc>,
) -> Result<String, Error> {
    let summary = CertSummary::from_der(signer.certificate())?;
    if request.expiry_check {
        match validity_at(summary.not_before, summary.not_after, now) {
            Validity::Valid { .. } => {}
            Validity::Expired { .. } => {
                return Err(Error::NotPermitted(format!(
                    "The certificate expired on {}. The GST portal does not accept it.",
                    summary.not_after.format("%d %b %Y")
                )));
            }
            Validity::NotYetValid { .. } => {
                return Err(Error::NotPermitted(format!(
                    "The certificate is valid only from {}. Check the computer's date.",
                    summary.not_before.format("%d %b %Y")
                )));
            }
        }
    }
    let der = cms::build(signer, request.to_be_signed.as_bytes(), now)?;
    let checked = cms::check(&der)?;
    if checked.content != request.to_be_signed.as_bytes()
        || checked.certificate != signer.certificate()
    {
        return Err(Error::Cms(
            "portal signature check failed: content or certificate differs".into(),
        ));
    }
    Ok(frame::reply(
        &encode_signature(&der),
        &reply_cert(signer.certificate())?,
        now,
        &request.unique_id,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyKind;
    use ::cms::signed_data::SignedData;
    use chrono::TimeZone;
    use der::Encode;
    use num_bigint::BigUint;

    const REF_CERT: &[u8] = include_bytes!("../../testdata/portal/signer-cert.der");
    const REF_CMS: &[u8] = include_bytes!("../../testdata/portal/python-signtype1.der");
    const REF_REPLY: &str = include_str!("../../testdata/portal/python-reply.txt");

    fn signed_data(der: &[u8]) -> SignedData {
        ::cms::content_info::ContentInfo::from_der(der)
            .unwrap()
            .content
            .decode_as()
            .unwrap()
    }

    /// Hands back a fixed signature and records what it was asked to sign.
    struct Replay {
        cert: Vec<u8>,
        signature: Vec<u8>,
        asked: Vec<Vec<u8>>,
    }

    impl Signer for Replay {
        fn certificate(&self) -> &[u8] {
            &self.cert
        }
        fn chain(&self) -> &[Vec<u8>] {
            &[]
        }
        fn key_kind(&self) -> KeyKind {
            KeyKind::Rsa
        }
        fn signature_len(&self) -> usize {
            self.signature.len()
        }
        fn sign_sha256(&mut self, _: &[u8; 32]) -> Result<Vec<u8>, Error> {
            unreachable!("the portal signature is SHA-1")
        }
        fn sign_digest_info(&mut self, digest_info: &[u8]) -> Result<Vec<u8>, Error> {
            self.asked.push(digest_info.to_vec());
            Ok(self.signature.clone())
        }
    }

    /// A software RSA key (the repository's test key), signing a DigestInfo.
    struct SoftRsa {
        cert: Vec<u8>,
        n: BigUint,
        d: BigUint,
        k: usize,
        kind: KeyKind,
    }

    impl SoftRsa {
        fn new() -> Self {
            #[derive(der::Sequence)]
            struct RsaPrivateKey<'a> {
                version: der::asn1::UintRef<'a>,
                modulus: der::asn1::UintRef<'a>,
                public_exponent: der::asn1::UintRef<'a>,
                private_exponent: der::asn1::UintRef<'a>,
                prime1: der::asn1::UintRef<'a>,
                prime2: der::asn1::UintRef<'a>,
                exponent1: der::asn1::UintRef<'a>,
                exponent2: der::asn1::UintRef<'a>,
                coefficient: der::asn1::UintRef<'a>,
            }
            let info =
                p256::pkcs8::PrivateKeyInfo::from_der(include_bytes!("../../testdata/rsa-key.der"))
                    .unwrap();
            let key = RsaPrivateKey::from_der(info.private_key).unwrap();
            SoftRsa {
                cert: include_bytes!("../../testdata/rsa-cert.der").to_vec(),
                n: BigUint::from_bytes_be(key.modulus.as_bytes()),
                d: BigUint::from_bytes_be(key.private_exponent.as_bytes()),
                k: key.modulus.as_bytes().len(),
                kind: KeyKind::Rsa,
            }
        }
    }

    impl Signer for SoftRsa {
        fn certificate(&self) -> &[u8] {
            &self.cert
        }
        fn chain(&self) -> &[Vec<u8>] {
            &[]
        }
        fn key_kind(&self) -> KeyKind {
            self.kind
        }
        fn signature_len(&self) -> usize {
            self.k
        }
        fn sign_sha256(&mut self, digest: &[u8; 32]) -> Result<Vec<u8>, Error> {
            self.sign_digest_info(&crate::cms::sha256_digest_info(digest))
        }
        fn sign_digest_info(&mut self, t: &[u8]) -> Result<Vec<u8>, Error> {
            // EMSA-PKCS1-v1_5 padding, then the private-key operation.
            let mut em = vec![0xff; self.k];
            em[0] = 0;
            em[1] = 1;
            em[self.k - t.len() - 1] = 0;
            em[self.k - t.len()..].copy_from_slice(t);
            let s = BigUint::from_bytes_be(&em)
                .modpow(&self.d, &self.n)
                .to_bytes_be();
            let mut out = vec![0; self.k - s.len()];
            out.extend_from_slice(&s);
            Ok(out)
        }
    }

    fn request(data: &str) -> Request {
        frame::parse_request(&format!(
            "action=sign\ntobesigned={data}\npanNo=ABCDE1234F\nsigntype=1\nexpirycheck=true\n\
             issuername=\ncertclass=2|3\ncerttype=DSC\ncertdetails="
        ))
        .unwrap()
    }

    fn reference_time() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 9, 25, 0, 0, 0).unwrap()
    }

    /// The reference signature, which the portal accepts, is rebuilt byte for
    /// byte from the same certificate, content, time and RSA signature (RSA
    /// PKCS#1 v1.5 is deterministic, so this covers everything but the token).
    #[test]
    fn matches_the_reference_signature() {
        let reference = signed_data(REF_CMS);
        let si = reference.signer_infos.0.get(0).unwrap();
        let mut signer = Replay {
            cert: REF_CERT.to_vec(),
            signature: si.signature.as_bytes().to_vec(),
            asked: Vec::new(),
        };
        let der = cms::build(&mut signer, b"ABCDE1234F", reference_time()).unwrap();
        assert_eq!(der, REF_CMS);
        // The token was given the SHA-1 DigestInfo of the reference's signed attributes.
        let attrs = si.signed_attrs.as_ref().unwrap().to_der().unwrap();
        let expected = cms::sha1_digest_info(&sha1::Sha1::digest(&attrs).into());
        assert_eq!(signer.asked, vec![expected]);
        assert_eq!(cms::check(&der).unwrap().content, b"ABCDE1234F");
    }

    #[test]
    fn matches_the_reference_reply() {
        let reference = signed_data(REF_CMS);
        let mut signer = Replay {
            cert: REF_CERT.to_vec(),
            signature: reference
                .signer_infos
                .0
                .get(0)
                .unwrap()
                .signature
                .as_bytes()
                .to_vec(),
            asked: Vec::new(),
        };
        let req = request("ABCDE1234F");
        // The reference certificate is long expired by now; its own day is not.
        let reply = sign(&mut signer, &req, reference_time()).unwrap();
        assert_eq!(reply, REF_REPLY);
        assert_eq!(
            decode_signature(frame::signature_of(&reply).unwrap()).unwrap(),
            REF_CMS
        );
        assert!(matches_pan(REF_CERT, "ABCDE1234F"));
        assert!(matches_pan(REF_CERT, " abcde1234f"));
        assert!(!matches_pan(REF_CERT, "ABCDE1234G"));
        assert!(!matches_pan(REF_CERT, ""));
        assert_eq!(cert_class(REF_CERT), "Class 3");
    }

    #[test]
    fn signs_a_return_digest() {
        let mut signer = SoftRsa::new();
        let digest = "0f".repeat(32);
        let now = Utc::now();
        let reply = sign(&mut signer, &request(&digest), now).unwrap();
        let der = decode_signature(frame::signature_of(&reply).unwrap()).unwrap();
        let checked = cms::check(&der).unwrap();
        assert_eq!(checked.content, digest.as_bytes());
        assert_eq!(checked.certificate, signer.cert);
        assert_eq!(
            checked.signing_time.map(|t| t.timestamp()),
            Some(now.timestamp())
        );

        // Layout: attached content, SHA-1, three signed attributes, one certificate.
        let sd = signed_data(&der);
        assert_eq!(sd.certificates.as_ref().unwrap().0.len(), 1);
        assert_eq!(sd.signer_infos.0.len(), 1);
        let si = sd.signer_infos.0.get(0).unwrap();
        assert_eq!(si.digest_alg.oid, const_oid::db::rfc5912::ID_SHA_1);
        assert_eq!(si.signed_attrs.as_ref().unwrap().len(), 3);
        assert!(sd.encap_content_info.econtent.is_some());
        let text = frame::signature_of(&reply).unwrap();
        assert!(
            text.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
    }

    #[test]
    fn refuses_what_the_portal_would_not_accept() {
        // A tampered signature fails the check before anything is sent.
        let mut der = cms::build(&mut SoftRsa::new(), b"ABCDE1234F", Utc::now()).unwrap();
        let last = der.len() - 1;
        der[last] ^= 1;
        assert!(cms::check(&der).is_err());
        // The PDF signature (detached, SHA-256, ESS attribute) is not the portal's.
        let pdf = crate::cms::build_signed_data(
            &mut SoftRsa::new(),
            &[7; 32],
            &Utc::now().fixed_offset(),
        )
        .unwrap();
        assert!(cms::check(&pdf).is_err());

        let mut ec = SoftRsa::new();
        ec.kind = KeyKind::Ec;
        let err = sign(&mut ec, &request("ABCDE1234F"), Utc::now()).unwrap_err();
        assert!(err.to_string().contains("RSA"), "{err}");

        let mut old = SoftRsa::new();
        let after = CertSummary::from_der(&old.cert).unwrap().not_after + chrono::Duration::days(1);
        let err = sign(&mut old, &request("ABCDE1234F"), after).unwrap_err();
        assert!(err.to_string().contains("expired"), "{err}");
        let mut no_check = request("ABCDE1234F");
        no_check.expiry_check = false;
        assert!(sign(&mut old, &no_check, after).is_ok());
    }

    #[test]
    fn pan_hash_is_sha256_hex() {
        assert_eq!(
            pan_hash("ABCDE1234F"),
            "6442fd73a940c1186d6268bd27f89233e12429902c7805037e8aab6e717be6d9"
        );
        assert_eq!(pan_hash(" abcde1234f "), pan_hash("ABCDE1234F"));
    }
}
