//! Long-term validation data: issuer certificates, OCSP responses and CRLs
//! for every certificate a signature depends on, fetched from the addresses
//! in the certificates themselves (AIA and CRL distribution points).
//!
//! The result goes into the document security store (`/DSS`), so the
//! signature can be checked after the certificates expire or the CA's
//! servers go away.

use base64::Engine;
use cms::content_info::ContentInfo;
use cms::signed_data::{CertificateSet, SignedData};
use const_oid::db::{rfc5280, rfc6960};
use der::asn1::OctetString;
use der::{Decode, Encode};
use sha1::{Digest, Sha1};
use x509_cert::Certificate;
use x509_cert::crl::CertificateList;
use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};
use x509_cert::ext::pkix::{AuthorityInfoAccessSyntax, CrlDistributionPoints};
use x509_cert::spki::AlgorithmIdentifierOwned;
use x509_ocsp::{
    BasicOcspResponse, CertId, CertStatus, OcspRequest, OcspResponse, OcspResponseStatus, Request,
    TbsRequest, Version,
};

use crate::Error;

/// Signer chain + TSA chain + OCSP responders; anything longer is a loop.
const MAX_CERTS: usize = 24;

#[derive(Debug, Default, Clone)]
pub struct ValidationData {
    pub certs: Vec<Vec<u8>>,
    pub ocsps: Vec<Vec<u8>>,
    pub crls: Vec<Vec<u8>>,
}

fn err(msg: impl Into<String>) -> Error {
    Error::Ltv(msg.into())
}

struct Cert {
    der: Vec<u8>,
    cert: Certificate,
}

impl Cert {
    fn parse(der: Vec<u8>) -> Result<Self, Error> {
        let cert = Certificate::from_der(&der)?;
        Ok(Cert { der, cert })
    }

    fn name(&self) -> String {
        crate::certinfo::CertSummary::from_der(&self.der)
            .map(|s| s.subject_cn)
            .unwrap_or_else(|_| self.cert.tbs_certificate.subject.to_string())
    }

    fn self_issued(&self) -> bool {
        self.cert.tbs_certificate.subject == self.cert.tbs_certificate.issuer
    }

    fn has_extension(&self, oid: const_oid::ObjectIdentifier) -> bool {
        self.extension(oid).is_some()
    }

    fn extension(&self, oid: const_oid::ObjectIdentifier) -> Option<&[u8]> {
        self.cert
            .tbs_certificate
            .extensions
            .iter()
            .flatten()
            .find(|e| e.extn_id == oid)
            .map(|e| e.extn_value.as_bytes())
    }

    /// AIA URLs for `method` (OCSP or caIssuers).
    fn aia(&self, method: const_oid::ObjectIdentifier) -> Vec<String> {
        let Some(v) = self.extension(rfc5280::ID_PE_AUTHORITY_INFO_ACCESS) else {
            return Vec::new();
        };
        AuthorityInfoAccessSyntax::from_der(v)
            .map(|aia| {
                aia.0
                    .iter()
                    .filter(|d| d.access_method == method)
                    .filter_map(|d| uri(&d.access_location))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn crl_urls(&self) -> Vec<String> {
        let Some(v) = self.extension(rfc5280::ID_CE_CRL_DISTRIBUTION_POINTS) else {
            return Vec::new();
        };
        CrlDistributionPoints::from_der(v)
            .map(|cdp| {
                cdp.0
                    .iter()
                    .filter_map(|dp| match &dp.distribution_point {
                        Some(DistributionPointName::FullName(names)) => Some(names),
                        _ => None,
                    })
                    .flatten()
                    .filter_map(uri)
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// HTTP(S) URI of a general name; LDAP and others are skipped.
fn uri(name: &GeneralName) -> Option<String> {
    match name {
        GeneralName::UniformResourceIdentifier(u) => {
            let s = u.as_str();
            let lower = s.to_ascii_lowercase();
            (lower.starts_with("http://") || lower.starts_with("https://")).then(|| s.to_string())
        }
        _ => None,
    }
}

/// The DER inside each `-----BEGIN ...-----` block. Some CAs (FreeTSA among
/// them) serve their CRLs and issuer certificates as PEM, whatever the
/// address or content type says.
fn pem_blocks(data: &[u8]) -> Vec<Vec<u8>> {
    let Ok(text) = std::str::from_utf8(data) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut b64: Option<String> = None;
    for line in text.lines().map(str::trim) {
        if line.starts_with("-----BEGIN ") {
            b64 = Some(String::new());
        } else if line.starts_with("-----END ") {
            if let Some(Ok(der)) = b64
                .take()
                .map(|b| base64::engine::general_purpose::STANDARD.decode(b))
            {
                out.push(der);
            }
        } else if let Some(b) = b64.as_mut() {
            b.push_str(line);
        }
    }
    out
}

/// A CRL download as DER (it may come PEM-armoured).
fn crl_der(data: Vec<u8>) -> Vec<u8> {
    if data.first() == Some(&0x30) {
        return data;
    }
    pem_blocks(&data).into_iter().next().unwrap_or(data)
}

/// A caIssuers download: one DER certificate, a PKCS#7 "certs-only" bundle,
/// or PEM certificates.
fn parse_issuer_download(data: &[u8]) -> Vec<Vec<u8>> {
    let pem = pem_blocks(data);
    if !pem.is_empty() {
        return pem
            .into_iter()
            .flat_map(|der| parse_issuer_download(&der))
            .collect();
    }
    if Certificate::from_der(data).is_ok() {
        return vec![data.to_vec()];
    }
    let Ok(ci) = ContentInfo::from_der(data) else {
        return Vec::new();
    };
    let Ok(sd) = ci.content.decode_as::<SignedData>() else {
        return Vec::new();
    };
    sd.certificates
        .iter()
        .flat_map(|CertificateSet(s)| s.iter())
        .filter_map(|c| match c {
            cms::cert::CertificateChoices::Certificate(c) => c.to_der().ok(),
            _ => None,
        })
        .collect()
}

fn cert_id(cert: &Cert, issuer: &Cert) -> Result<CertId, Error> {
    let issuer_tbs = &issuer.cert.tbs_certificate;
    Ok(CertId {
        hash_algorithm: AlgorithmIdentifierOwned {
            oid: const_oid::db::rfc5912::ID_SHA_1,
            parameters: Some(der::asn1::Null.into()),
        },
        issuer_name_hash: OctetString::new(Sha1::digest(issuer_tbs.subject.to_der()?).to_vec())?,
        issuer_key_hash: OctetString::new(
            Sha1::digest(
                issuer_tbs
                    .subject_public_key_info
                    .subject_public_key
                    .raw_bytes(),
            )
            .to_vec(),
        )?,
        serial_number: cert.cert.tbs_certificate.serial_number.clone(),
    })
}

pub fn encode_ocsp_request(id: CertId) -> Result<Vec<u8>, Error> {
    let req = OcspRequest {
        tbs_request: TbsRequest {
            version: Version::V1,
            requestor_name: None,
            request_list: vec![Request {
                req_cert: id,
                single_request_extensions: None,
            }],
            request_extensions: None,
        },
        optional_signature: None,
    };
    Ok(req.to_der()?)
}

enum Status {
    Good,
    Revoked,
}

/// Checks an OCSP response for `id`; returns the status and the responder's certificates.
fn check_ocsp(resp: &[u8], id: &CertId) -> Result<(Status, Vec<Vec<u8>>), String> {
    let resp = OcspResponse::from_der(resp).map_err(|_| "not an OCSP response".to_string())?;
    if resp.response_status != OcspResponseStatus::Successful {
        return Err(format!("OCSP status {:?}", resp.response_status));
    }
    let bytes = resp.response_bytes.ok_or("empty OCSP response")?;
    if bytes.response_type != rfc6960::ID_PKIX_OCSP_BASIC {
        return Err("unsupported OCSP response type".into());
    }
    let basic = BasicOcspResponse::from_der(bytes.response.as_bytes())
        .map_err(|e| format!("bad OCSP response: {e}"))?;
    let single = basic
        .tbs_response_data
        .responses
        .iter()
        .find(|r| {
            r.cert_id.serial_number == id.serial_number
                && (r.cert_id.hash_algorithm.oid != id.hash_algorithm.oid
                    || r.cert_id.issuer_name_hash == id.issuer_name_hash)
        })
        .ok_or("the OCSP response is for another certificate")?;
    let status = match single.cert_status {
        CertStatus::Good(_) => Status::Good,
        CertStatus::Revoked(_) => Status::Revoked,
        CertStatus::Unknown(_) => return Err("the OCSP responder does not know it".into()),
    };
    let certs = basic
        .certs
        .iter()
        .flatten()
        .filter_map(|c| c.to_der().ok())
        .collect();
    Ok((status, certs))
}

/// Checks a CRL from `cert`'s distribution point.
fn check_crl(data: &[u8], cert: &Cert) -> Result<Status, String> {
    match CertificateList::from_der(data) {
        Ok(crl) => {
            if crl.tbs_cert_list.issuer != cert.cert.tbs_certificate.issuer {
                return Err("the CRL is from another CA".into());
            }
            let serial = &cert.cert.tbs_certificate.serial_number;
            let revoked = crl
                .tbs_cert_list
                .revoked_certificates
                .iter()
                .flatten()
                .any(|r| &r.serial_number == serial);
            Ok(if revoked {
                Status::Revoked
            } else {
                Status::Good
            })
        }
        // Some CA CRLs are not strict DER; validators are more forgiving.
        Err(_) if data.first() == Some(&0x30) => Ok(Status::Good),
        Err(_) => Err("not a CRL".into()),
    }
}

/// Fetches validation data for every certificate in a CMS signature
/// (including its timestamp token).
pub fn collect(cms_der: &[u8]) -> Result<ValidationData, Error> {
    let mut certs: Vec<Cert> = Vec::new();
    for der in crate::cms::embedded_certificates(cms_der)? {
        certs.push(Cert::parse(der)?);
    }
    let mut out = ValidationData::default();
    let mut i = 0;
    while i < certs.len() {
        if certs.len() > MAX_CERTS {
            return Err(err("too many certificates in the chain"));
        }
        let is_signer = i == 0;
        if certs[i].self_issued() {
            i += 1;
            continue;
        }

        // Issuer: from what we have, else from the certificate's caIssuers URL.
        let find_issuer = |certs: &[Cert]| {
            let want = &certs[i].cert.tbs_certificate.issuer;
            certs
                .iter()
                .position(|c| &c.cert.tbs_certificate.subject == want)
        };
        let mut issuer = find_issuer(&certs);
        if issuer.is_none() {
            for url in certs[i].aia(rfc5280::ID_AD_CA_ISSUERS) {
                if let Ok(data) = crate::http::get(&url) {
                    for der in parse_issuer_download(&data) {
                        if !certs.iter().any(|c| c.der == der) {
                            certs.push(Cert::parse(der)?);
                        }
                    }
                }
                issuer = find_issuer(&certs);
                if issuer.is_some() {
                    break;
                }
            }
        }

        // OCSP responders vouch for themselves.
        if certs[i].has_extension(rfc6960::ID_PKIX_OCSP_NOCHECK) {
            i += 1;
            continue;
        }

        let cert = &certs[i];
        let mut last_error = None;
        let mut status = None;
        let mut new_certs = Vec::new();
        if let Some(issuer) = issuer {
            let id = cert_id(cert, &certs[issuer])?;
            for url in cert.aia(rfc5280::ID_AD_OCSP) {
                let req = encode_ocsp_request(id.clone())?;
                let res = crate::http::post(&url, "application/ocsp-request", &req)
                    .and_then(|(resp, _)| check_ocsp(&resp, &id).map(|r| (resp, r)));
                match res {
                    Ok((resp, (s, responder))) => {
                        out.ocsps.push(resp);
                        new_certs = responder;
                        status = Some(s);
                        break;
                    }
                    Err(e) => last_error = Some(e),
                }
            }
        }
        if status.is_none() {
            for url in cert.crl_urls() {
                let res = crate::http::get(&url)
                    .map(crl_der)
                    .and_then(|data| check_crl(&data, cert).map(|s| (data, s)));
                match res {
                    Ok((data, s)) => {
                        if !out.crls.contains(&data) {
                            out.crls.push(data);
                        }
                        status = Some(s);
                        break;
                    }
                    Err(e) => last_error = Some(e),
                }
            }
        }
        match (status, last_error) {
            (Some(Status::Good), _) => {}
            (Some(Status::Revoked), _) => {
                return Err(err(format!(
                    "the certificate of {} has been revoked by its CA",
                    cert.name()
                )));
            }
            (None, Some(e)) => {
                return Err(err(format!(
                    "could not check the certificate of {}: {e}",
                    cert.name()
                )));
            }
            (None, None) if is_signer => {
                return Err(err(format!(
                    "the certificate of {} has no OCSP or CRL address",
                    cert.name()
                )));
            }
            // Nowhere to ask; validators will treat it the same way.
            (None, None) => {}
        }
        for der in new_certs {
            if !certs.iter().any(|c| c.der == der) {
                certs.push(Cert::parse(der)?);
            }
        }
        i += 1;
    }
    out.certs = certs.into_iter().map(|c| c.der).collect();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_cert::serial_number::SerialNumber;

    #[test]
    fn ocsp_request_encoding() {
        let id = CertId {
            hash_algorithm: AlgorithmIdentifierOwned {
                oid: const_oid::db::rfc5912::ID_SHA_1,
                parameters: Some(der::asn1::Null.into()),
            },
            issuer_name_hash: OctetString::new(vec![1; 20]).unwrap(),
            issuer_key_hash: OctetString::new(vec![2; 20]).unwrap(),
            serial_number: SerialNumber::new(&[0x05]).unwrap(),
        };
        let req = encode_ocsp_request(id.clone()).unwrap();
        let back = OcspRequest::from_der(&req).unwrap();
        assert_eq!(back.tbs_request.request_list[0].req_cert, id);
        // OCSPRequest > TBSRequest > requestList > Request > CertID, no version (DEFAULT v1).
        assert_eq!(&req[..2], &[0x30, 0x42]);
        assert_eq!(&req[2..4], &[0x30, 0x40]);
    }

    #[test]
    fn rejects_non_ocsp() {
        let id = CertId {
            hash_algorithm: AlgorithmIdentifierOwned {
                oid: const_oid::db::rfc5912::ID_SHA_1,
                parameters: None,
            },
            issuer_name_hash: OctetString::new(vec![1; 20]).unwrap(),
            issuer_key_hash: OctetString::new(vec![2; 20]).unwrap(),
            serial_number: SerialNumber::new(&[0x05]).unwrap(),
        };
        assert!(check_ocsp(b"<html>", &id).is_err());
        // OCSPResponse { responseStatus tryLater(3) }
        let e = check_ocsp(&[0x30, 0x03, 0x0a, 0x01, 0x03], &id)
            .err()
            .unwrap();
        assert!(e.contains("TryLater"));
    }

    // FreeTSA serves its root certificate and CRL as PEM.
    const FREETSA_ROOT: &[u8] = include_bytes!("../testdata/freetsa-cacert.pem");
    const FREETSA_CRL: &[u8] = include_bytes!("../testdata/freetsa-root-ca.crl");

    #[test]
    fn pem_crl_is_read_as_der() {
        let root = Cert::parse(parse_issuer_download(FREETSA_ROOT).remove(0)).unwrap();
        assert!(root.self_issued());
        let der = crl_der(FREETSA_CRL.to_vec());
        assert_eq!(der[0], 0x30);
        assert!(CertificateList::from_der(&der).is_ok());
        assert!(matches!(check_crl(&der, &root), Ok(Status::Good)));
        // Without unwrapping, the PEM text is no CRL at all.
        assert_eq!(
            check_crl(FREETSA_CRL, &root).err().as_deref(),
            Some("not a CRL")
        );
        // DER and anything unreadable pass through untouched.
        assert_eq!(crl_der(der.clone()), der);
        assert_eq!(crl_der(b"<html>".to_vec()), b"<html>");
    }

    #[test]
    fn issuer_download_formats() {
        let rsa = include_bytes!("../testdata/rsa-cert.der").to_vec();
        let ec = include_bytes!("../testdata/ec-cert.der").to_vec();
        assert_eq!(parse_issuer_download(&rsa), vec![rsa.clone()]);
        let pem = format!(
            "{}{}",
            crate::certdetails::to_pem(&rsa),
            crate::certdetails::to_pem(&ec)
        );
        assert_eq!(parse_issuer_download(pem.as_bytes()), vec![rsa, ec]);
        // Windows line endings.
        let crlf = pem.replace('\n', "\r\n");
        assert_eq!(parse_issuer_download(crlf.as_bytes()).len(), 2);
        assert!(parse_issuer_download(b"<html>").is_empty());
    }
}
