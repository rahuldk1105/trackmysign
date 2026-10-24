//! RFC 3161 trusted timestamps over the signature value.
//!
//! The token goes into the signer's unsigned attributes as
//! `id-aa-signatureTimeStampToken`, which turns a PAdES-B signature into
//! PAdES-B-T.

use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use const_oid::ObjectIdentifier;
use const_oid::db::rfc5912;
use der::asn1::{Any, Int, OctetString};
use der::{Decode, Encode, Reader, Sequence, SliceReader, Tag, Tagged};
use sha2::{Digest, Sha256};
use x509_cert::spki::AlgorithmIdentifierOwned;

use crate::Error;

pub const DEFAULT_TSA_URL: &str = "http://timestamp.digicert.com";

pub const ID_AA_SIGNATURE_TIME_STAMP_TOKEN: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.14");
const ID_CT_TST_INFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");

/// Room in `/Contents` for the token: the TSA's signature plus its
/// certificate chain. Public TSAs send 2–8 KB.
pub const TOKEN_RESERVE: usize = 16 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
struct MessageImprint {
    hash_algorithm: AlgorithmIdentifierOwned,
    hashed_message: OctetString,
}

/// TimeStampReq ::= SEQUENCE { version, messageImprint, reqPolicy OPTIONAL,
/// nonce OPTIONAL, certReq BOOLEAN DEFAULT FALSE, extensions [0] OPTIONAL }
#[derive(Sequence)]
struct TimeStampReq {
    version: u8,
    message_imprint: MessageImprint,
    nonce: Int,
    cert_req: bool,
}

#[derive(Sequence)]
struct PkiStatusInfo {
    status: u32,
    #[asn1(optional = "true")]
    status_string: Option<Vec<String>>,
    #[asn1(optional = "true")]
    fail_info: Option<der::asn1::BitString>,
}

#[derive(Sequence)]
struct TimeStampResp {
    status: PkiStatusInfo,
    #[asn1(optional = "true")]
    time_stamp_token: Option<Any>,
}

fn err(msg: impl Into<String>) -> Error {
    Error::Timestamp(msg.into())
}

/// DER request for a SHA-256 imprint, asking for the TSA certificate.
pub fn encode_request(digest: &[u8; 32], nonce: &[u8]) -> Result<Vec<u8>, Error> {
    let req = TimeStampReq {
        version: 1,
        message_imprint: MessageImprint {
            hash_algorithm: AlgorithmIdentifierOwned {
                oid: rfc5912::ID_SHA_256,
                parameters: None,
            },
            hashed_message: OctetString::new(digest.to_vec())?,
        },
        nonce: Int::new(nonce)?,
        cert_req: true,
    };
    Ok(req.to_der()?)
}

/// Checks the response and returns the bare `TimeStampToken` (a CMS `ContentInfo`).
pub fn parse_response(resp: &[u8], digest: &[u8; 32], nonce: &[u8]) -> Result<Vec<u8>, Error> {
    let resp = TimeStampResp::from_der(resp)
        .map_err(|_| err("the server did not send a timestamp response (is the address right?)"))?;
    // 0 = granted, 1 = grantedWithMods.
    if resp.status.status > 1 {
        let text = resp
            .status
            .status_string
            .map(|s| s.join("; "))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| format!("status {}", resp.status.status));
        return Err(err(format!("the server refused the request: {text}")));
    }
    let token = resp
        .time_stamp_token
        .ok_or_else(|| err("the response has no timestamp token"))?
        .to_der()?;

    let ci = ContentInfo::from_der(&token)?;
    let sd: SignedData = ci.content.decode_as()?;
    if sd.encap_content_info.econtent_type != ID_CT_TST_INFO {
        return Err(err("the token does not contain timestamp info"));
    }
    let tst = sd
        .encap_content_info
        .econtent
        .ok_or_else(|| err("the token has no content"))?
        .decode_as::<OctetString>()?;

    let (imprint, token_nonce) = tst_fields(tst.as_bytes())?;
    if imprint.hash_algorithm.oid != rfc5912::ID_SHA_256
        || imprint.hashed_message.as_bytes() != digest
    {
        return Err(err("the timestamp is for different data"));
    }
    if token_nonce.as_deref() != Some(nonce) {
        return Err(err("the timestamp nonce does not match the request"));
    }
    Ok(token)
}

/// TSTInfo ::= SEQUENCE { version, policy, messageImprint, serialNumber,
/// genTime, accuracy OPTIONAL, ordering DEFAULT FALSE, nonce OPTIONAL, ... }
///
/// Walked by hand: genTime often carries fractional seconds, which the
/// strict DER `GeneralizedTime` type rejects.
fn tst_fields(tst: &[u8]) -> Result<(MessageImprint, Option<Vec<u8>>), Error> {
    let mut r = SliceReader::new(tst)?;
    let out = r.sequence(|r| {
        let _version: u8 = r.decode()?;
        let _policy: ObjectIdentifier = r.decode()?;
        let imprint: MessageImprint = r.decode()?;
        let _serial: Any = r.decode()?;
        let _gen_time: Any = r.decode()?;
        let mut nonce = None;
        while !r.is_finished() {
            let field: Any = r.decode()?;
            if field.tag() == Tag::Integer {
                nonce = Some(field.value().to_vec());
            }
        }
        Ok((imprint, nonce))
    })?;
    Ok(out)
}

/// A request nonce: unpredictable, positive, minimal DER.
fn make_nonce(seed: &[u8]) -> Vec<u8> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut h = Sha256::new();
    h.update(seed);
    h.update(now.to_be_bytes());
    h.update(std::process::id().to_be_bytes());
    let mut n = h.finalize()[..12].to_vec();
    n[0] = (n[0] & 0x7f) | 0x01;
    n
}

/// Asks the TSA at `url` to timestamp `signature` (the SignerInfo signature value).
pub fn timestamp(url: &str, signature: &[u8]) -> Result<Vec<u8>, Error> {
    let digest: [u8; 32] = Sha256::digest(signature).into();
    let nonce = make_nonce(signature);
    let req = encode_request(&digest, &nonce)?;
    let (resp, _) = crate::http::post(url, "application/timestamp-query", &req).map_err(err)?;
    parse_response(&resp, &digest, &nonce)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cms::content_info::CmsVersion;
    use cms::signed_data::{EncapsulatedContentInfo, SignerInfos};
    use const_oid::db::rfc5911;
    use der::asn1::SetOfVec;

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let n = content.len();
        let len = match n {
            0..0x80 => vec![n as u8],
            0x80..0x100 => vec![0x81, n as u8],
            _ => vec![0x82, (n >> 8) as u8, n as u8],
        };
        [&[tag][..], &len, content].concat()
    }

    /// A response the way a TSA would build it (without the TSA signature).
    fn response(status: u8, digest: &[u8; 32], nonce: &[u8]) -> Vec<u8> {
        let imprint = MessageImprint {
            hash_algorithm: AlgorithmIdentifierOwned {
                oid: rfc5912::ID_SHA_256,
                parameters: None,
            },
            hashed_message: OctetString::new(digest.to_vec()).unwrap(),
        };
        let tst = tlv(
            0x30,
            &[
                tlv(0x02, &[1]),
                ObjectIdentifier::new_unwrap("1.2.3.4").to_der().unwrap(),
                imprint.to_der().unwrap(),
                tlv(0x02, &[0x42]),
                tlv(0x18, b"20261023101112.345Z"),
                tlv(0x30, &tlv(0x02, &[1])),
                tlv(0x02, nonce),
            ]
            .concat(),
        );
        let sd = SignedData {
            version: CmsVersion::V3,
            digest_algorithms: SetOfVec::new(),
            encap_content_info: EncapsulatedContentInfo {
                econtent_type: ID_CT_TST_INFO,
                econtent: Some(Any::encode_from(&OctetString::new(tst).unwrap()).unwrap()),
            },
            certificates: None,
            crls: None,
            signer_infos: SignerInfos(SetOfVec::new()),
        };
        let token = ContentInfo {
            content_type: rfc5911::ID_SIGNED_DATA,
            content: Any::encode_from(&sd).unwrap(),
        }
        .to_der()
        .unwrap();
        let mut body = tlv(0x30, &tlv(0x02, &[status]));
        if status == 0 {
            body.extend_from_slice(&token);
        }
        tlv(0x30, &body)
    }

    #[test]
    fn request_encoding() {
        let digest = [0xab; 32];
        let req = encode_request(&digest, &[0x12, 0x34]).unwrap();
        let mut expected = vec![
            0x30, 0x3b, 0x02, 0x01, 0x01, 0x30, 0x2f, 0x30, 0x0b, 0x06, 0x09,
        ];
        expected.extend_from_slice(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]);
        expected.extend_from_slice(&[0x04, 0x20]);
        expected.extend_from_slice(&digest);
        expected.extend_from_slice(&[0x02, 0x02, 0x12, 0x34, 0x01, 0x01, 0xff]);
        assert_eq!(req, expected);
    }

    #[test]
    fn nonce_is_positive_and_minimal() {
        for seed in [&b"a"[..], b"b", b"c"] {
            let n = make_nonce(seed);
            assert!(n[0] != 0 && n[0] < 0x80);
            assert!(Int::new(&n).is_ok());
        }
    }

    #[test]
    fn accepts_matching_response() {
        let digest = [7u8; 32];
        let nonce = [0x11, 0x22, 0x33];
        let token = parse_response(&response(0, &digest, &nonce), &digest, &nonce).unwrap();
        assert_eq!(
            ContentInfo::from_der(&token).unwrap().content_type,
            rfc5911::ID_SIGNED_DATA
        );
    }

    #[test]
    fn rejects_bad_responses() {
        let digest = [7u8; 32];
        let nonce = [0x11, 0x22, 0x33];
        let msg = |r: Result<Vec<u8>, Error>| r.unwrap_err().to_string();
        assert!(
            msg(parse_response(
                &response(2, &digest, &nonce),
                &digest,
                &nonce
            ))
            .contains("refused")
        );
        assert!(
            msg(parse_response(
                &response(0, &[8u8; 32], &nonce),
                &digest,
                &nonce
            ))
            .contains("different data")
        );
        assert!(
            msg(parse_response(
                &response(0, &digest, &[0x44]),
                &digest,
                &nonce
            ))
            .contains("nonce")
        );
        assert!(msg(parse_response(b"<html>", &digest, &nonce)).contains("timestamp response"));
    }
}
