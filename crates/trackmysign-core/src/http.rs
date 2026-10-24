//! Minimal blocking HTTP for timestamp, OCSP, CRL and issuer downloads.
//!
//! Only used when the user turns on timestamping or LTV; signing itself never
//! touches the network.

use std::time::Duration;

/// Large enough for the CRLs of Indian CAs, small enough to stop runaways.
const MAX_RESPONSE: u64 = 32 * 1024 * 1024;

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(10)))
        .timeout_global(Some(Duration::from_secs(30)))
        .user_agent(concat!("TrackMySign/", env!("CARGO_PKG_VERSION")))
        .build()
        .into()
}

fn check_url(url: &str) -> Result<(), String> {
    let lower = url.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        Ok(())
    } else {
        Err(format!("unsupported address {url}"))
    }
}

fn describe(url: &str, e: ureq::Error) -> String {
    match e {
        ureq::Error::StatusCode(code) => format!("{url} answered HTTP {code}"),
        ureq::Error::Timeout(_) => format!("{url} did not answer in time"),
        e => format!("could not reach {url}: {e}"),
    }
}

pub fn get(url: &str) -> Result<Vec<u8>, String> {
    check_url(url)?;
    let mut resp = agent().get(url).call().map_err(|e| describe(url, e))?;
    resp.body_mut()
        .with_config()
        .limit(MAX_RESPONSE)
        .read_to_vec()
        .map_err(|e| describe(url, e))
}

/// POSTs `body`; returns the response body and its content type.
pub fn post(url: &str, content_type: &str, body: &[u8]) -> Result<(Vec<u8>, String), String> {
    check_url(url)?;
    let mut resp = agent()
        .post(url)
        .header("Content-Type", content_type)
        .send(body)
        .map_err(|e| describe(url, e))?;
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let data = resp
        .body_mut()
        .with_config()
        .limit(MAX_RESPONSE)
        .read_to_vec()
        .map_err(|e| describe(url, e))?;
    Ok((data, ct))
}
