//! The signature the GST portal accepts (`signtype=1`): CMS `SignedData`
//! with the content attached, SHA-1, RSA PKCS#1 v1.5, exactly the signed
//! attributes contentType, signingTime and messageDigest, and only the
//! signer's certificate. Anything more (ESS attributes, the chain) is
//! refused by the portal, so this is kept apart from the PDF signature.

use chrono::{DateTime, Utc};
use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::content_info::{CmsVersion, ContentInfo};
use cms::signed_data::{
    CertificateSet, DigestAlgorithmIdentifiers, EncapsulatedContentInfo, SignedData,
    SignerIdentifier, SignerInfo, SignerInfos,
};
use const_oid::db::{rfc5911, rfc5912};
use der::asn1::{Any, Null, OctetString, SetOfVec, UtcTime};
use der::{Decode, Encode};
use sha1::{Digest, Sha1};
use x509_cert::Certificate;
use x509_cert::attr::{Attribute, AttributeValue};
use x509_cert::spki::AlgorithmIdentifierOwned;

use crate::verify::{Hash, verify_hashed};
use crate::{Error, KeyKind, Signer};

fn der_err(e: der::Error) -> Error {
    Error::Cms(e.to_string())
}

fn attr(oid: const_oid::ObjectIdentifier, value: Any) -> Result<Attribute, Error> {
    let mut values = SetOfVec::new();
    values
        .insert(AttributeValue::from(value))
        .map_err(der_err)?;
    Ok(Attribute { oid, values })
}

/// An algorithm with explicit NULL parameters, as the portal's signer writes them.
fn with_null(oid: const_oid::ObjectIdentifier) -> Result<AlgorithmIdentifierOwned, Error> {
    Ok(AlgorithmIdentifierOwned {
        oid,
        parameters: Some(Any::encode_from(&Null).map_err(der_err)?),
    })
}

/// DER `DigestInfo` for SHA-1, as fed to raw RSA PKCS#1 v1.5 signing.
pub fn sha1_digest_info(digest: &[u8; 20]) -> Vec<u8> {
    let mut v = vec![
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
    ];
    v.extend_from_slice(digest);
    v
}

/// Signs `content` (attached) for the portal. RSA keys only: the portal's
/// format names `rsaEncryption`, and no evidence shows it accepts ECDSA.
pub fn build(
    signer: &mut dyn Signer,
    content: &[u8],
    time: DateTime<Utc>,
) -> Result<Vec<u8>, Error> {
    if signer.key_kind() != KeyKind::Rsa {
        return Err(Error::Token(
            "The GST portal needs a certificate with an RSA key; this one has an elliptic-curve key."
                .into(),
        ));
    }
    let cert_der = signer.certificate().to_vec();
    let cert = Certificate::from_der(&cert_der).map_err(der_err)?;
    // The certificate is embedded re-encoded; one that does not round-trip
    // would reach the portal with bytes its CA never signed.
    if cert.to_der().map_err(der_err)? != cert_der {
        return Err(Error::Cms(
            "the certificate on the token is not in canonical DER form".into(),
        ));
    }

    let mut signed_attrs = SetOfVec::new();
    signed_attrs
        .insert(attr(
            rfc5911::ID_CONTENT_TYPE,
            Any::encode_from(&rfc5911::ID_DATA).map_err(der_err)?,
        )?)
        .map_err(der_err)?;
    let secs = u64::try_from(time.timestamp())
        .map_err(|_| Error::Cms("signing time before 1970".into()))?;
    let st = UtcTime::from_unix_duration(std::time::Duration::from_secs(secs)).map_err(der_err)?;
    signed_attrs
        .insert(attr(
            rfc5911::ID_SIGNING_TIME,
            Any::encode_from(&st).map_err(der_err)?,
        )?)
        .map_err(der_err)?;
    let md = OctetString::new(Sha1::digest(content).to_vec()).map_err(der_err)?;
    signed_attrs
        .insert(attr(
            rfc5911::ID_MESSAGE_DIGEST,
            Any::encode_from(&md).map_err(der_err)?,
        )?)
        .map_err(der_err)?;

    // The signature covers the DER of the attributes as a SET OF.
    let to_sign = signed_attrs.to_der().map_err(der_err)?;
    let signature = signer.sign_digest_info(&sha1_digest_info(&Sha1::digest(&to_sign).into()))?;

    let signer_info = SignerInfo {
        version: CmsVersion::V1,
        sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: cert.tbs_certificate.issuer.clone(),
            serial_number: cert.tbs_certificate.serial_number.clone(),
        }),
        digest_alg: with_null(rfc5912::ID_SHA_1)?,
        signed_attrs: Some(signed_attrs),
        signature_algorithm: with_null(rfc5912::RSA_ENCRYPTION)?,
        signature: OctetString::new(signature).map_err(der_err)?,
        unsigned_attrs: None,
    };

    let mut certs = SetOfVec::new();
    certs
        .insert(CertificateChoices::Certificate(cert))
        .map_err(der_err)?;
    let mut digest_algorithms = DigestAlgorithmIdentifiers::new();
    digest_algorithms
        .insert(with_null(rfc5912::ID_SHA_1)?)
        .map_err(der_err)?;
    let mut infos = SetOfVec::new();
    infos.insert(signer_info).map_err(der_err)?;

    let sd = SignedData {
        version: CmsVersion::V1,
        digest_algorithms,
        encap_content_info: EncapsulatedContentInfo {
            econtent_type: rfc5911::ID_DATA,
            econtent: Some(
                Any::encode_from(&OctetString::new(content).map_err(der_err)?).map_err(der_err)?,
            ),
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

/// What [`check`] found in a portal signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checked {
    pub content: Vec<u8>,
    pub certificate: Vec<u8>,
    pub signing_time: Option<DateTime<Utc>>,
}

/// Checks that `cms_der` has the portal's shape and that the signature is
/// correct, before it is sent: one signer, one certificate (the signer's),
/// attached content, SHA-1, exactly the three signed attributes and an RSA
/// signature that verifies with the certificate's key.
pub fn check(cms_der: &[u8]) -> Result<Checked, Error> {
    let bad = |m: &str| Error::Cms(format!("portal signature check failed: {m}"));
    let ci = ContentInfo::from_der(cms_der).map_err(der_err)?;
    if ci.content_type != rfc5911::ID_SIGNED_DATA {
        return Err(bad("not SignedData"));
    }
    let sd: SignedData = ci.content.decode_as().map_err(der_err)?;
    let sha1_null = with_null(rfc5912::ID_SHA_1)?;
    if sd.digest_algorithms.len() != 1 || sd.digest_algorithms.get(0) != Some(&sha1_null) {
        return Err(bad("digest algorithm is not SHA-1"));
    }
    if sd.encap_content_info.econtent_type != rfc5911::ID_DATA {
        return Err(bad("content type is not data"));
    }
    let content = sd
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or_else(|| bad("content is not attached"))?
        .decode_as::<OctetString>()
        .map_err(der_err)?
        .into_bytes();
    let certs: Vec<&Certificate> = sd
        .certificates
        .iter()
        .flat_map(|s| s.0.iter())
        .filter_map(|c| match c {
            CertificateChoices::Certificate(c) => Some(c),
            _ => None,
        })
        .collect();
    let [cert] = certs[..] else {
        return Err(bad("not exactly one certificate"));
    };
    if sd.crls.is_some() || sd.signer_infos.0.len() != 1 {
        return Err(bad("not exactly one signer"));
    }
    let si = sd.signer_infos.0.get(0).ok_or_else(|| bad("no signer"))?;
    match &si.sid {
        SignerIdentifier::IssuerAndSerialNumber(ias)
            if ias.issuer == cert.tbs_certificate.issuer
                && ias.serial_number == cert.tbs_certificate.serial_number => {}
        _ => return Err(bad("signer is not the certificate")),
    }
    if si.digest_alg != sha1_null || si.signature_algorithm != with_null(rfc5912::RSA_ENCRYPTION)? {
        return Err(bad("algorithms are not SHA-1 with RSA"));
    }
    if si.unsigned_attrs.is_some() {
        return Err(bad("unsigned attributes present"));
    }
    let attrs = si
        .signed_attrs
        .as_ref()
        .ok_or_else(|| bad("no signed attributes"))?;
    let oids: Vec<_> = attrs.iter().map(|a| a.oid).collect();
    if oids
        != [
            rfc5911::ID_CONTENT_TYPE,
            rfc5911::ID_SIGNING_TIME,
            rfc5911::ID_MESSAGE_DIGEST,
        ]
    {
        return Err(bad(
            "signed attributes are not contentType, signingTime, messageDigest",
        ));
    }
    let value = |i: usize| attrs.get(i).and_then(|a| a.values.get(0));
    if value(0).and_then(|v| v.decode_as::<const_oid::ObjectIdentifier>().ok())
        != Some(rfc5911::ID_DATA)
    {
        return Err(bad("contentType is not data"));
    }
    let signing_time = value(1)
        .and_then(|v| v.decode_as::<UtcTime>().ok())
        .and_then(|t| DateTime::from_timestamp(t.to_unix_duration().as_secs() as i64, 0));
    if value(2).and_then(|v| v.decode_as::<OctetString>().ok())
        != Some(OctetString::new(Sha1::digest(&content).to_vec()).map_err(der_err)?)
    {
        return Err(bad("messageDigest does not match the content"));
    }
    let to_sign = attrs.to_der().map_err(der_err)?;
    let hashed = Hash::Sha1.digest(&[&to_sign]);
    let ok = verify_hashed(
        &cert.tbs_certificate.subject_public_key_info,
        KeyKind::Rsa,
        Hash::Sha1,
        &hashed,
        si.signature.as_bytes(),
    )
    .map_err(|m| bad(&m))?;
    if !ok {
        return Err(bad("the signature does not match the certificate"));
    }
    Ok(Checked {
        content,
        certificate: cert.to_der().map_err(der_err)?,
        signing_time,
    })
}
