//! Builds the detached CMS `SignedData` that goes into `/Contents`, and the
//! same signature over any file (`.p7s`, or `.p7m` with the file inside).
//!
//! Signed attributes: contentType, signingTime, messageDigest and
//! signingCertificateV2 (ESS, as PAdES and Adobe expect).

use chrono::{DateTime, FixedOffset};
use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::content_info::{CmsVersion, ContentInfo};
use cms::signed_data::{
    CertificateSet, DigestAlgorithmIdentifiers, EncapsulatedContentInfo, SignedData,
    SignerIdentifier, SignerInfo, SignerInfos,
};
use const_oid::ObjectIdentifier;
use const_oid::db::{rfc5911, rfc5912};
use der::asn1::{Any, Null, OctetString, SetOfVec, UtcTime};
use der::{Decode, Encode};
use sha2::{Digest, Sha256};
use x509_cert::Certificate;
use x509_cert::attr::{Attribute, AttributeValue};
use x509_cert::spki::AlgorithmIdentifierOwned;

use crate::{Error, KeyKind, Signer};

const ID_SIGNING_CERTIFICATE_V2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");

fn der_err(e: der::Error) -> Error {
    Error::Cms(e.to_string())
}

fn attr(oid: ObjectIdentifier, value: Any) -> Result<Attribute, Error> {
    let mut values = SetOfVec::new();
    values
        .insert(AttributeValue::from(value))
        .map_err(der_err)?;
    Ok(Attribute { oid, values })
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let n = content.len();
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let bytes: Vec<u8> = n
            .to_be_bytes()
            .iter()
            .copied()
            .skip_while(|b| *b == 0)
            .collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend_from_slice(&bytes);
    }
    out.extend_from_slice(content);
    out
}

/// SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2 }
/// ESSCertIDv2 ::= SEQUENCE { certHash OCTET STRING, issuerSerial IssuerSerial }
/// (hashAlgorithm omitted = SHA-256 default)
fn signing_certificate_v2(cert_der: &[u8], cert: &Certificate) -> Result<Any, Error> {
    let hash = Sha256::digest(cert_der);
    let issuer = cert.tbs_certificate.issuer.to_der().map_err(der_err)?;
    let serial = cert
        .tbs_certificate
        .serial_number
        .to_der()
        .map_err(der_err)?;
    let general_names = tlv(0x30, &tlv(0xa4, &issuer));
    let issuer_serial = tlv(0x30, &[general_names, serial].concat());
    let ess_cert_id = tlv(0x30, &[tlv(0x04, &hash), issuer_serial].concat());
    let v2 = tlv(0x30, &tlv(0x30, &ess_cert_id));
    Any::from_der(&v2).map_err(der_err)
}

fn sha256_alg() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: rfc5912::ID_SHA_256,
        parameters: None,
    }
}

/// DER `DigestInfo` for SHA-256, as fed to raw RSA PKCS#1 v1.5 signing.
pub fn sha256_digest_info(digest: &[u8; 32]) -> Vec<u8> {
    let mut v = vec![
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];
    v.extend_from_slice(digest);
    v
}

/// Converts a raw `r || s` ECDSA signature to DER `ECDSA-Sig-Value`.
pub fn ecdsa_raw_to_der(raw: &[u8]) -> Vec<u8> {
    let half = raw.len() / 2;
    let int = |b: &[u8]| {
        let b: Vec<u8> = b.iter().copied().skip_while(|x| *x == 0).collect();
        let mut c = if b.first().is_some_and(|x| x & 0x80 != 0) {
            vec![0]
        } else {
            vec![]
        };
        c.extend_from_slice(if b.is_empty() { &[0] } else { &b });
        tlv(0x02, &c)
    };
    tlv(0x30, &[int(&raw[..half]), int(&raw[half..])].concat())
}

/// Upper bound on the encoded size, used to reserve `/Contents` space.
pub fn estimate_size(signer: &dyn Signer) -> usize {
    let certs: usize = std::iter::once(signer.certificate().len())
        .chain(signer.chain().iter().map(Vec::len))
        .sum();
    certs + signer.signature_len() + 2048
}

pub fn build_signed_data(
    signer: &mut dyn Signer,
    content_digest: &[u8; 32],
    time: &DateTime<FixedOffset>,
) -> Result<Vec<u8>, Error> {
    build(signer, content_digest, time, None)
}

/// [`build_signed_data`] with `content` carried inside the signature
/// (enveloping, as in a `.p7m`).
pub fn build_signed_data_attached(
    signer: &mut dyn Signer,
    content: &[u8],
    time: &DateTime<FixedOffset>,
) -> Result<Vec<u8>, Error> {
    let digest: [u8; 32] = Sha256::digest(content).into();
    build(signer, &digest, time, Some(content))
}

fn build(
    signer: &mut dyn Signer,
    content_digest: &[u8; 32],
    time: &DateTime<FixedOffset>,
    content: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    let cert_der = signer.certificate().to_vec();
    let cert = Certificate::from_der(&cert_der).map_err(der_err)?;

    let mut signed_attrs = SetOfVec::new();
    signed_attrs
        .insert(attr(
            rfc5911::ID_CONTENT_TYPE,
            Any::encode_from(&rfc5911::ID_DATA).map_err(der_err)?,
        )?)
        .map_err(der_err)?;
    let st = UtcTime::from_unix_duration(std::time::Duration::from_secs(
        time.timestamp().max(0) as u64
    ))
    .map_err(der_err)?;
    signed_attrs
        .insert(attr(
            rfc5911::ID_SIGNING_TIME,
            Any::encode_from(&st).map_err(der_err)?,
        )?)
        .map_err(der_err)?;
    let md = OctetString::new(content_digest.to_vec()).map_err(der_err)?;
    signed_attrs
        .insert(attr(
            rfc5911::ID_MESSAGE_DIGEST,
            Any::encode_from(&md).map_err(der_err)?,
        )?)
        .map_err(der_err)?;
    signed_attrs
        .insert(attr(
            ID_SIGNING_CERTIFICATE_V2,
            signing_certificate_v2(&cert_der, &cert)?,
        )?)
        .map_err(der_err)?;

    // The signature covers the DER of the attributes as a SET OF.
    let to_sign = signed_attrs.to_der().map_err(der_err)?;
    let attrs_digest: [u8; 32] = Sha256::digest(&to_sign).into();
    let signature = signer.sign_sha256(&attrs_digest)?;

    let signature_algorithm = match signer.key_kind() {
        KeyKind::Rsa => AlgorithmIdentifierOwned {
            oid: rfc5912::SHA_256_WITH_RSA_ENCRYPTION,
            parameters: Some(Any::encode_from(&Null).map_err(der_err)?),
        },
        KeyKind::Ec => AlgorithmIdentifierOwned {
            oid: rfc5912::ECDSA_WITH_SHA_256,
            parameters: None,
        },
    };

    let signer_info = SignerInfo {
        version: CmsVersion::V1,
        sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: cert.tbs_certificate.issuer.clone(),
            serial_number: cert.tbs_certificate.serial_number.clone(),
        }),
        digest_alg: sha256_alg(),
        signed_attrs: Some(signed_attrs),
        signature_algorithm,
        signature: OctetString::new(signature).map_err(der_err)?,
        unsigned_attrs: None,
    };

    let mut certs = SetOfVec::new();
    certs
        .insert(CertificateChoices::Certificate(cert))
        .map_err(der_err)?;
    for c in signer.chain() {
        let c = Certificate::from_der(c).map_err(der_err)?;
        // Duplicates would make the SET OF invalid; skip them.
        let _ = certs.insert(CertificateChoices::Certificate(c));
    }

    let mut digest_algorithms = DigestAlgorithmIdentifiers::new();
    digest_algorithms.insert(sha256_alg()).map_err(der_err)?;
    let mut infos = SetOfVec::new();
    infos.insert(signer_info).map_err(der_err)?;

    let sd = SignedData {
        version: CmsVersion::V1,
        digest_algorithms,
        encap_content_info: EncapsulatedContentInfo {
            econtent_type: rfc5911::ID_DATA,
            econtent: content
                .map(|c| Any::encode_from(&OctetString::new(c).map_err(der_err)?).map_err(der_err))
                .transpose()?,
        },
        certificates: Some(CertificateSet(certs)),
        crls: None,
        signer_infos: SignerInfos(infos),
    };
    let ci = ContentInfo {
        content_type: rfc5911::ID_SIGNED_DATA,
        content: Any::encode_from(&sd).map_err(der_err)?,
    };
    ci.to_der().map_err(der_err)
}

fn signed_data(cms_der: &[u8]) -> Result<SignedData, Error> {
    let ci = ContentInfo::from_der(cms_der).map_err(der_err)?;
    ci.content.decode_as().map_err(der_err)
}

/// The signature value of the (only) signer, as sent to a timestamp authority.
pub fn signature_value(cms_der: &[u8]) -> Result<Vec<u8>, Error> {
    let sd = signed_data(cms_der)?;
    let si = sd
        .signer_infos
        .0
        .get(0)
        .ok_or_else(|| Error::Cms("no signer".into()))?;
    Ok(si.signature.as_bytes().to_vec())
}

/// Adds an unsigned attribute (e.g. a timestamp token) to the signer. The
/// signature itself does not change.
pub fn add_unsigned_attr(
    cms_der: &[u8],
    oid: ObjectIdentifier,
    value_der: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut sd = signed_data(cms_der)?;
    let mut infos = sd.signer_infos.0.into_vec();
    let si = infos
        .first_mut()
        .ok_or_else(|| Error::Cms("no signer".into()))?;
    let mut attrs = si.unsigned_attrs.take().unwrap_or_default();
    attrs
        .insert(attr(oid, Any::from_der(value_der).map_err(der_err)?)?)
        .map_err(der_err)?;
    si.unsigned_attrs = Some(attrs);
    sd.signer_infos = SignerInfos(SetOfVec::try_from(infos).map_err(der_err)?);
    let ci = ContentInfo {
        content_type: rfc5911::ID_SIGNED_DATA,
        content: Any::encode_from(&sd).map_err(der_err)?,
    };
    ci.to_der().map_err(der_err)
}

/// Every certificate carried by the signature: the signer's chain and those
/// inside any timestamp token. Signer certificate first.
pub fn embedded_certificates(cms_der: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    let sd = signed_data(cms_der)?;
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut push = |c: Vec<u8>| {
        if !out.contains(&c) {
            out.push(c);
        }
    };
    let certs = |sd: &SignedData| -> Result<Vec<Vec<u8>>, Error> {
        let mut v = Vec::new();
        for c in sd.certificates.iter().flat_map(|s| s.0.iter()) {
            if let CertificateChoices::Certificate(c) = c {
                v.push(c.to_der().map_err(der_err)?);
            }
        }
        Ok(v)
    };
    let all = certs(&sd)?;
    // Signer first, so callers can treat it specially.
    if let Some(SignerIdentifier::IssuerAndSerialNumber(ias)) =
        sd.signer_infos.0.get(0).map(|s| &s.sid)
    {
        for c in &all {
            let cert = Certificate::from_der(c).map_err(der_err)?;
            if cert.tbs_certificate.serial_number == ias.serial_number
                && cert.tbs_certificate.issuer == ias.issuer
            {
                push(c.clone());
            }
        }
    }
    all.into_iter().for_each(&mut push);
    for si in sd.signer_infos.0.iter() {
        for a in si.unsigned_attrs.iter().flat_map(|s| s.iter()) {
            if a.oid != crate::tsa::ID_AA_SIGNATURE_TIME_STAMP_TOKEN {
                continue;
            }
            for v in a.values.iter() {
                let tst = signed_data(&v.to_der().map_err(der_err)?)?;
                certs(&tst)?.into_iter().for_each(&mut push);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecdsa_der() {
        let raw = [[0x80u8; 32], [0x01u8; 32]].concat();
        let der = ecdsa_raw_to_der(&raw);
        assert_eq!(der[0], 0x30);
        assert_eq!(der[2], 0x02);
        assert_eq!(der[3], 33); // leading zero added for high bit
    }
}
