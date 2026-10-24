//! The text frames exchanged with the GST portal page over its WebSocket.
//!
//! Checked against the portal's own JavaScript (`directives1.4.js`,
//! `emSignerConn` and `dscAction`; constants in `common1.3.js`).

use chrono::{DateTime, FixedOffset, Utc};

/// Ports the portal tries, in order (`EM_PORTS`).
pub const PORTS: [u16; 5] = [1585, 2095, 2568, 2868, 4587];
/// `LATEST_EM_VERSION` the live portal expects; it changes now and then, so
/// it is a setting.
pub const DEFAULT_VERSION: &str = "2.8";
/// `EM_ENTY_ID` the greeting must carry.
pub const ENTITY_ID: &str = "gstnInfy";
/// Reply when the user declines or nobody answers in time.
pub const CANCELED: &str = "signing canceled";
/// Reply for anything else that went wrong.
pub const FAILED: &str = "signing failed";
/// Largest request frame accepted; real ones are a few hundred bytes.
pub const MAX_FRAME: usize = 16 * 1024;

/// Sent as soon as the WebSocket opens. The page splits it on `\n` and `=`,
/// trims, and needs `version` and `ID` to match; it also looks for the
/// literal `status = success`.
pub fn greeting(port: u16, version: &str) -> String {
    format!(
        "status = success\nport = {port}\nversion = {}\nID = {ENTITY_ID}",
        flatten(version)
    )
}

/// A signing request, as sent by the page's `dscAction`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// Signed as its UTF-8 bytes: the PAN at DSC registration, a hex digest
    /// for returns.
    pub to_be_signed: String,
    /// PAN of the taxpayer's authorised signatory, upper case.
    pub pan: String,
    /// Refuse certificates outside their validity period.
    pub expiry_check: bool,
    /// When not empty, the issuer the page asks for.
    pub issuer_name: String,
    /// E.g. `2|3`.
    pub cert_class: String,
    /// E.g. `DSC`.
    pub cert_type: String,
    /// Echoed in the reply.
    pub unique_id: String,
}

/// Why a frame is not a request this signer answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotSigned {
    /// Not `action=sign`: ignored.
    OtherAction(String),
    /// `action=sign` with a `signtype` other than 1, or nothing to sign:
    /// answered with [`FAILED`].
    Unsupported(String),
}

/// `key=value` lines; keys case-insensitive, values trimmed, the last
/// duplicate wins.
pub fn parse_request(frame: &str) -> Result<Request, NotSigned> {
    let mut fields: Vec<(String, String)> = Vec::new();
    for line in frame.lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let k = k.trim().to_ascii_lowercase();
        fields.retain(|(o, _)| *o != k);
        fields.push((k, v.trim().to_string()));
    }
    let get = |k: &str| {
        fields
            .iter()
            .find(|(o, _)| o == k)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };
    let action = get("action");
    if !action.eq_ignore_ascii_case("sign") {
        return Err(NotSigned::OtherAction(action));
    }
    let sign_type = get("signtype");
    if sign_type != "1" {
        return Err(NotSigned::Unsupported(format!("signtype {sign_type:?}")));
    }
    let to_be_signed = get("tobesigned");
    if to_be_signed.is_empty() {
        return Err(NotSigned::Unsupported("nothing to sign".into()));
    }
    if to_be_signed.chars().any(char::is_control) {
        return Err(NotSigned::Unsupported(
            "control characters in the data".into(),
        ));
    }
    Ok(Request {
        to_be_signed,
        pan: get("panno").to_ascii_uppercase(),
        expiry_check: !get("expirycheck").eq_ignore_ascii_case("false"),
        issuer_name: get("issuername"),
        cert_class: get("certclass"),
        cert_type: get("certtype"),
        unique_id: get("uniqueid"),
    })
}

/// Indian Standard Time, used for every date in the reply.
fn ist() -> FixedOffset {
    FixedOffset::east_opt(5 * 3600 + 1800).expect("valid offset")
}

/// What the reply says about the signer's certificate.
#[derive(Debug, Clone)]
pub struct ReplyCert {
    /// Serial number in decimal.
    pub serial: String,
    pub common_name: String,
    pub issuer_name: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    /// E.g. `Class 3`; empty when the certificate does not say.
    pub class: String,
}

/// The success reply. The page takes the signature as
/// `data.substring(11, data.indexOf("SerialNo") - 1)`, so the frame starts
/// with exactly `signature= ` and has one `\n` before `SerialNo`; every value
/// is kept to one line.
pub fn reply(
    signature: &str,
    cert: &ReplyCert,
    signing_time: DateTime<Utc>,
    unique_id: &str,
) -> String {
    let day = |t: DateTime<Utc>| t.with_timezone(&ist()).format("%d-%m-%Y").to_string();
    format!(
        "signature= {}\nSerialNo= {}\nCommonName= {}\nIssuerName= {}\nIssuedDate= {}\n\
         ExpiryDate= {}\nCertClass= {}\nSigningTime= {}\nuniqueID= {}",
        flatten(signature),
        flatten(&cert.serial),
        flatten(&cert.common_name),
        flatten(&cert.issuer_name),
        day(cert.not_before),
        day(cert.not_after),
        flatten(&cert.class),
        signing_time
            .with_timezone(&ist())
            .format("%d-%m-%Y %H:%M:%S"),
        flatten(unique_id),
    )
}

/// The signature as the page passes it on, out of a reply frame (the page's
/// own slicing, for tests and diagnostics).
pub fn signature_of(reply: &str) -> Option<&str> {
    let end = reply.find("SerialNo")?.checked_sub(1)?;
    reply.get(11..end).filter(|s| !s.is_empty())
}

fn flatten(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    /// Exactly what `dscAction` sends.
    const PORTAL_REQUEST: &str = "action=sign\ntobesigned=ABCDE1234F\npanNo=ABCDE1234F\nsigntype=1\n\
        expirycheck=true\nissuername=\ncertclass=2|3\ncerttype=DSC\ncertdetails=";

    #[test]
    fn greeting_passes_the_portal_check() {
        let g = greeting(2095, "2.8");
        assert_eq!(
            g,
            "status = success\nport = 2095\nversion = 2.8\nID = gstnInfy"
        );
        // The page's check: split on \n, then on =, trim both sides.
        let mut ok = 0;
        for line in g.split('\n') {
            let xd: Vec<&str> = line.split('=').collect();
            if (xd[0].trim() == "version" && xd[1].trim() == "2.8")
                || (xd[0].trim() == "ID" && xd[1].trim() == "gstnInfy")
            {
                ok += 1;
            }
        }
        assert_eq!(ok, 2);
        assert!(g.contains("status = success"));
        assert_eq!(greeting(1585, " 2.9\n"), greeting(1585, "2.9"));
    }

    #[test]
    fn parses_the_portal_request() {
        let r = parse_request(PORTAL_REQUEST).unwrap();
        assert_eq!(r.to_be_signed, "ABCDE1234F");
        assert_eq!(r.pan, "ABCDE1234F");
        assert!(r.expiry_check);
        assert_eq!(r.issuer_name, "");
        assert_eq!(r.cert_class, "2|3");
        assert_eq!(r.cert_type, "DSC");
        assert_eq!(r.unique_id, "");

        let digest = "a".repeat(64);
        let r = parse_request(&format!(
            "ACTION = Sign\r\ntobesigned= {digest} \npanno=abcde1234f\nsigntype=1\nexpirycheck=false\n\
             uniqueId=7\ntobesigned={digest}"
        ))
        .unwrap();
        assert_eq!(r.to_be_signed, digest);
        assert_eq!(r.pan, "ABCDE1234F");
        assert!(!r.expiry_check);
        assert_eq!(r.unique_id, "7");
    }

    #[test]
    fn refuses_other_requests() {
        assert_eq!(
            parse_request("action=listcert\nsigntype=1"),
            Err(NotSigned::OtherAction("listcert".into()))
        );
        assert!(matches!(
            parse_request(&PORTAL_REQUEST.replace("signtype=1", "signtype=2")),
            Err(NotSigned::Unsupported(_))
        ));
        assert!(matches!(
            parse_request(&PORTAL_REQUEST.replace("signtype=1\n", "")),
            Err(NotSigned::Unsupported(_))
        ));
        assert!(matches!(
            parse_request("action=sign\nsigntype=1\ntobesigned="),
            Err(NotSigned::Unsupported(_))
        ));
        assert!(matches!(
            parse_request("action=sign\nsigntype=1\ntobesigned=a\u{7}b"),
            Err(NotSigned::Unsupported(_))
        ));
        assert_eq!(
            parse_request(""),
            Err(NotSigned::OtherAction(String::new()))
        );
    }

    #[test]
    fn reply_is_sliced_like_the_portal_does() {
        let cert = ReplyCert {
            serial: "1311768467294899695".into(),
            common_name: "SIGNER\nSerialNo= 1".into(),
            issuer_name: "Test CA".into(),
            not_before: Utc.with_ymd_and_hms(2026, 2, 13, 10, 0, 0).unwrap(),
            not_after: Utc.with_ymd_and_hms(2028, 2, 13, 20, 0, 0).unwrap(),
            class: "Class 3".into(),
        };
        let time = Utc.with_ymd_and_hms(2026, 9, 25, 0, 0, 0).unwrap();
        let r = reply("MIIabc-_", &cert, time, "");
        assert!(r.starts_with("signature= MIIabc-_\nSerialNo= 1311768467294899695\n"));
        assert_eq!(signature_of(&r), Some("MIIabc-_"));
        // A newline in a value must not add a line before SerialNo.
        assert!(r.contains("CommonName= SIGNER SerialNo= 1\n"));
        // Dates in IST: 20:00 UTC is the next day in India.
        assert!(r.contains("IssuedDate= 13-02-2026\nExpiryDate= 14-02-2028\n"));
        assert!(r.contains("SigningTime= 25-09-2026 05:30:00\n"));
        assert!(r.ends_with("uniqueID= "));
        assert_eq!(signature_of(CANCELED), None);
    }
}
