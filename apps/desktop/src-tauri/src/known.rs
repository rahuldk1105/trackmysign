//! Certificates seen on a token before, kept by fingerprint in the app's data
//! folder, so the expiry reminder can show while the token is not plugged in.

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};
use trackmysign_core::certinfo::days_until;
use trackmysign_core::token::TokenCert;

use super::{CmdResult, CommandError};

/// Forgotten this long after expiring.
const KEEP_EXPIRED_DAYS: i64 = 90;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Known {
    id: String,
    name: String,
    issuer: String,
    /// Unix seconds.
    not_after: i64,
}

impl From<&TokenCert> for Known {
    fn from(c: &TokenCert) -> Self {
        Known {
            id: c.fingerprint(),
            name: c.summary.subject_cn.clone(),
            issuer: c.summary.issuer_cn.clone(),
            not_after: c.summary.not_after.timestamp(),
        }
    }
}

impl Known {
    fn not_after(&self) -> DateTime<Utc> {
        DateTime::from_timestamp(self.not_after, 0).unwrap_or_default()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KnownDto {
    id: String,
    name: String,
    issuer: String,
    valid_until: String,
    /// Whole days left; negative once expired.
    days_left: i64,
}

fn store_path(app: &AppHandle) -> CmdResult<PathBuf> {
    let dir = app.path().app_data_dir().map_err(|e| CommandError {
        kind: "io",
        message: e.to_string(),
    })?;
    Ok(dir.join("known-certificates.json"))
}

fn load(app: &AppHandle) -> Vec<Known> {
    store_path(app)
        .ok()
        .and_then(|p| std::fs::read(p).ok())
        .and_then(|d| serde_json::from_slice(&d).ok())
        .unwrap_or_default()
}

/// Adds or refreshes `seen` and drops certificates long expired.
fn merge(mut known: Vec<Known>, seen: Vec<Known>, now: DateTime<Utc>) -> Vec<Known> {
    for s in seen {
        known.retain(|k| k.id != s.id);
        known.push(s);
    }
    known.retain(|k| days_until(k.not_after(), now) < KEEP_EXPIRED_DAYS);
    known
}

/// Remembers the certificates just listed. Failing to write only loses the reminder.
pub fn remember(app: &AppHandle, certs: &[TokenCert]) {
    let seen: Vec<Known> = certs
        .iter()
        .filter(|c| c.summary.can_sign)
        .map(Known::from)
        .collect();
    let before = load(app);
    let after = merge(before.clone(), seen, Utc::now());
    if after == before {
        return;
    }
    if let Ok(path) = store_path(app) {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Ok(data) = serde_json::to_vec_pretty(&after) {
            let _ = std::fs::write(path, data);
        }
    }
}

/// Known certificates, without those replaced by a renewal (same holder, same
/// issuer, valid until later).
fn current(known: Vec<Known>) -> Vec<Known> {
    known
        .iter()
        .filter(|k| {
            !known
                .iter()
                .any(|o| o.name == k.name && o.issuer == k.issuer && o.not_after > k.not_after)
        })
        .cloned()
        .collect()
}

#[tauri::command]
pub fn known_certificates(app: AppHandle) -> Vec<KnownDto> {
    let now = Utc::now();
    current(load(&app))
        .into_iter()
        .map(|k| KnownDto {
            valid_until: k.not_after().format("%d %b %Y").to_string(),
            days_left: days_until(now, k.not_after()),
            id: k.id,
            name: k.name,
            issuer: k.issuer,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert(id: &str, name: &str, not_after: i64) -> Known {
        Known {
            id: id.into(),
            name: name.into(),
            issuer: "Sub CA".into(),
            not_after,
        }
    }

    const DAY: i64 = 86_400;

    #[test]
    fn merge_refreshes_and_forgets() {
        let now = DateTime::from_timestamp(1000 * DAY, 0).unwrap();
        let old = vec![
            cert("a", "A", 1010 * DAY),
            cert("gone", "B", (1000 - KEEP_EXPIRED_DAYS - 1) * DAY),
            cert("recent", "C", 990 * DAY),
        ];
        let mut a = cert("a", "A renamed", 1010 * DAY);
        a.issuer = "Other".into();
        let merged = merge(old, vec![a.clone(), cert("new", "D", 1400 * DAY)], now);
        let ids: Vec<&str> = merged.iter().map(|k| k.id.as_str()).collect();
        assert_eq!(ids, ["recent", "a", "new"]);
        assert_eq!(merged[1], a);
    }

    #[test]
    fn renewal_hides_old_certificate() {
        let known = vec![
            cert("old", "A", 100 * DAY),
            cert("renewed", "A", 830 * DAY),
            cert("other", "B", 50 * DAY),
        ];
        let ids: Vec<String> = current(known).into_iter().map(|k| k.id).collect();
        assert_eq!(ids, ["renewed", "other"]);
    }
}
