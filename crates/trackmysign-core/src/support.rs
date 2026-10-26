//! Support report: what a maintainer needs to know when something goes
//! wrong (versions, token drivers, tokens, certificates, settings, recent
//! errors), for the user to read and share. Nothing here sends anything.
//!
//! Every text in a report goes through one [`Redactor`] pass: the home
//! folder becomes `~`, and email addresses, PAN-like codes and long hex
//! strings are replaced. Holder names, token serial numbers and folder
//! paths are left out unless the user asks for them ([`Include`]).
//!
//! The [`EventLog`] keeps the last [`EventLog::CAP`] errors in the app's data
//! folder (`support-log.json`) for the report: never a PIN, a password,
//! anything from inside a document or a document's path.

use std::io;
use std::path::{Path, PathBuf};

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};

use crate::certinfo::{CertSummary, Validity, validity_at};
use crate::token::{Driver, Token, TokenCert, TokenInfo};

/// The issue form a report goes with.
pub const ISSUE_URL: &str =
    "https://github.com/rahuldk1105/trackmysign/issues/new?template=bug_report.yml";

/// [`ISSUE_URL`] with the version field filled in.
pub fn issue_url(version: &str) -> String {
    let v: String = version
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
        .collect();
    format!("{ISSUE_URL}&version=v{v}")
}

// ------------------------------------------------------------------ redaction

/// Replaces what should not leave the computer. One pass over a text, in
/// this order: values to keep are set aside, the home folder becomes `~`,
/// then email addresses, PAN-like codes (`ABCDE1234F`) and runs of 16 or
/// more hex digits are replaced.
#[derive(Debug, Clone, Default)]
pub struct Redactor {
    home: Option<String>,
    keep: Vec<String>,
}

const KEEP_BASE: u32 = 0xF0000;

impl Redactor {
    pub fn new(home: Option<&Path>) -> Self {
        let home = home
            .map(|h| {
                h.to_string_lossy()
                    .trim_end_matches(['/', '\\'])
                    .to_string()
            })
            // "/" or "C:" would turn every path into a mess of "~".
            .filter(|h| h.len() >= 4);
        Redactor {
            home,
            keep: Vec::new(),
        }
    }

    /// For this user's home folder.
    pub fn for_user() -> Self {
        let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
        Self::new(std::env::var_os(var).map(PathBuf::from).as_deref())
    }

    /// Values the user chose to include (token serial numbers, say), left
    /// as they are even when they look like hex.
    pub fn keep(mut self, values: impl IntoIterator<Item = String>) -> Self {
        self.keep
            .extend(values.into_iter().filter(|v| !v.trim().is_empty()));
        // Longest first, so one value inside another is not split.
        self.keep.sort_by_key(|v| std::cmp::Reverse(v.len()));
        self
    }

    pub fn redact(&self, text: &str) -> String {
        let mut s = text.to_string();
        for (i, k) in self.keep.iter().enumerate() {
            if let Some(c) = char::from_u32(KEEP_BASE + i as u32) {
                s = s.replace(k.as_str(), &c.to_string());
            }
        }
        if let Some(home) = &self.home {
            s = replace_home(&s, home);
        }
        s = replace_emails(&s);
        s = replace_codes(&s);
        s.chars()
            .map(|c| match (c as u32).checked_sub(KEEP_BASE) {
                Some(i) if (i as usize) < self.keep.len() => self.keep[i as usize].clone(),
                _ => c.to_string(),
            })
            .collect()
    }
}

/// `home` (either slash, any case) followed by a separator or the end
/// becomes `~`.
fn replace_home(text: &str, home: &str) -> String {
    // ASCII lower-casing keeps every byte where it was.
    let hay = text.to_ascii_lowercase();
    let home = home.to_ascii_lowercase();
    let needles = [home.replace('\\', "/"), home.replace('/', "\\")];
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < text.len() {
        let found = needles.iter().find(|n| {
            hay[i..].starts_with(n.as_str())
                && hay[i + n.len()..]
                    .chars()
                    .next()
                    .is_none_or(|c| !(c.is_alphanumeric() || matches!(c, '_' | '-' | '.')))
        });
        match found {
            Some(n) => {
                out.push('~');
                i += n.len();
            }
            None => {
                let c = text[i..].chars().next().unwrap_or_default();
                out.push(c);
                i += c.len_utf8().max(1);
            }
        }
    }
    out
}

fn email_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '%' | '+' | '-' | '@')
}

fn replace_emails(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut word = String::new();
    let flush = |word: &mut String, out: &mut String| {
        if let Some((local, domain)) = word.split_once('@') {
            let trailing = domain.len() - domain.trim_end_matches('.').len();
            let domain = &domain[..domain.len() - trailing];
            if !local.is_empty() && domain.contains('.') && !domain.starts_with('.') {
                out.push_str("[email]");
                out.push_str(&".".repeat(trailing));
                word.clear();
                return;
            }
        }
        out.push_str(word);
        word.clear();
    };
    for c in text.chars() {
        if email_char(c) {
            word.push(c);
        } else {
            flush(&mut word, &mut out);
            out.push(c);
        }
    }
    flush(&mut word, &mut out);
    out
}

fn is_pan(w: &[char]) -> bool {
    w.len() == 10
        && w[..5].iter().all(|c| c.is_ascii_uppercase())
        && w[5..9].iter().all(|c| c.is_ascii_digit())
        && w[9].is_ascii_uppercase()
}

/// PAN-like codes anywhere, then runs of 16 or more hex digits.
fn replace_codes(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut pans = String::with_capacity(text.len());
    let mut i = 0;
    while i < chars.len() {
        if i + 10 <= chars.len() && is_pan(&chars[i..i + 10]) {
            pans.push_str("[PAN]");
            i += 10;
        } else {
            pans.push(chars[i]);
            i += 1;
        }
    }
    let mut out = String::with_capacity(pans.len());
    let mut run = String::new();
    let flush = |run: &mut String, out: &mut String| {
        if run.len() >= 16 {
            out.push_str("[hex]");
        } else {
            out.push_str(run);
        }
        run.clear();
    };
    for c in pans.chars() {
        if c.is_ascii_hexdigit() {
            run.push(c);
        } else {
            flush(&mut run, &mut out);
            out.push(c);
        }
    }
    flush(&mut run, &mut out);
    out
}

/// "RAHUL TEST DIRECTOR" → "R. T. D.".
pub fn initials(name: &str) -> String {
    let v: Vec<String> = name
        .split(|c: char| c.is_whitespace() || c == '.')
        .filter_map(|w| w.chars().next())
        .filter(|c| c.is_alphanumeric())
        .map(|c| format!("{}.", c.to_uppercase()))
        .collect();
    if v.is_empty() {
        "(no name)".into()
    } else {
        v.join(" ")
    }
}

/// The host of a timestamp server address, without the path or anything
/// else in it.
pub fn url_host(url: &str) -> String {
    let rest = url.trim();
    let rest = rest.split_once("://").map_or(rest, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority.rsplit('@').next().unwrap_or_default();
    host.to_string()
}

// ------------------------------------------------------------------ event log

/// An error worth knowing about when something goes wrong.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Event {
    /// RFC 3339, UTC.
    pub time: String,
    /// What was being done: "sign", "batch", "certificates", "update", …
    pub area: String,
    pub message: String,
    /// Underlying causes, outermost first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chain: Vec<String>,
    /// A signature was being made.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub signing: bool,
}

/// Longest message kept; error texts are short, documents are not.
const MAX_MESSAGE: usize = 600;

impl Event {
    /// An error, with `documents` (the files being worked on) replaced by
    /// `[document]` wherever their path or name shows up, then redacted.
    pub fn error(
        area: &str,
        message: &str,
        chain: &[String],
        documents: &[&Path],
        signing: bool,
    ) -> Event {
        let redactor = Redactor::for_user();
        let mut hide: Vec<String> = Vec::new();
        for d in documents {
            hide.push(d.to_string_lossy().into_owned());
            if let Ok(abs) = std::path::absolute(d) {
                hide.push(abs.to_string_lossy().into_owned());
            }
            if let Some(n) = d.file_name() {
                hide.push(n.to_string_lossy().into_owned());
            }
        }
        hide.retain(|h| h.len() >= 3);
        hide.sort_by_key(|h| std::cmp::Reverse(h.len()));
        let clean = |s: &str| {
            let mut s = s.to_string();
            for h in &hide {
                s = s.replace(h.as_str(), "[document]");
            }
            let mut s = redactor.redact(&s);
            if s.chars().count() > MAX_MESSAGE {
                s = s.chars().take(MAX_MESSAGE).collect::<String>() + "…";
            }
            s
        };
        Event {
            time: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            area: area.to_string(),
            message: clean(message),
            chain: chain
                .iter()
                .map(|c| clean(c))
                .filter(|c| *c != clean(message))
                .collect(),
            signing,
        }
    }
}

#[derive(Serialize, Deserialize, Default)]
struct LogFile {
    /// Oldest first.
    events: Vec<Event>,
}

/// The last [`Self::CAP`] errors, in `support-log.json` in the app's data
/// folder. Deleting the file clears it.
pub struct EventLog {
    path: PathBuf,
}

impl EventLog {
    pub const CAP: usize = 200;
    pub const FILE: &str = "support-log.json";

    pub fn in_app_data(app_data: &Path) -> Self {
        EventLog {
            path: app_data.join(Self::FILE),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Oldest first; empty when there is no log or it cannot be read.
    pub fn events(&self) -> Vec<Event> {
        std::fs::read(&self.path)
            .ok()
            .and_then(|b| serde_json::from_slice::<LogFile>(&b).ok())
            .map(|l| l.events)
            .unwrap_or_default()
    }

    /// Adds `event`, dropping the oldest beyond [`Self::CAP`]. The same
    /// error again (a token that stays unplugged) only moves the time.
    pub fn record(&self, event: Event) -> io::Result<()> {
        let mut events = self.events();
        if let Some(last) = events.last()
            && (&last.area, &last.message, &last.chain)
                == (&event.area, &event.message, &event.chain)
        {
            events.pop();
        }
        events.push(event);
        let extra = events.len().saturating_sub(Self::CAP);
        events.drain(..extra);
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let json = serde_json::to_vec_pretty(&LogFile { events }).map_err(io::Error::other)?;
        // Written aside and moved, so a crash never leaves half a file.
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, json)?;
        std::fs::rename(&tmp, &self.path)
    }

    pub fn clear(&self) -> io::Result<()> {
        match std::fs::remove_file(&self.path) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }
}

// ------------------------------------------------------------------ probing

/// A certificate as the report needs it.
#[derive(Debug, Clone)]
pub struct CertProbe {
    pub summary: CertSummary,
    /// "RSA 2048", "EC P-256".
    pub key: String,
    /// SHA-256, lower-case hex.
    pub fingerprint: String,
    pub token_label: String,
}

impl CertProbe {
    pub fn new(c: &TokenCert) -> Self {
        let key = crate::certdetails::CertificateDetails::from_der(&c.der)
            .map(|d| d.key)
            .unwrap_or_else(|_| match c.summary.key_kind {
                crate::KeyKind::Rsa => format!("RSA {}", c.summary.signature_len * 8),
                crate::KeyKind::Ec => "EC".into(),
            });
        CertProbe {
            summary: c.summary.clone(),
            key,
            fingerprint: c.fingerprint(),
            token_label: c.token_label.clone(),
        }
    }
}

/// What one driver showed: whether it loaded, its tokens and certificates.
#[derive(Debug, Clone)]
pub struct DriverProbe {
    pub driver: Driver,
    /// Why it did not load, or could not list tokens.
    pub error: Option<String>,
    pub tokens: Vec<TokenInfo>,
    pub certs: Vec<CertProbe>,
}

/// Loads each driver on its own and asks it for its tokens and signing
/// certificates (no PIN needed).
pub fn probe(drivers: &[Driver]) -> Vec<DriverProbe> {
    drivers
        .iter()
        .map(|d| {
            let mut p = DriverProbe {
                driver: d.clone(),
                error: None,
                tokens: Vec::new(),
                certs: Vec::new(),
            };
            match Token::open(&d.path) {
                Err(e) => p.error = Some(e.to_string()),
                Ok(t) => {
                    match t.tokens() {
                        Ok(v) => p.tokens = v,
                        Err(e) => p.error = Some(e.to_string()),
                    }
                    match t.signing_certificates() {
                        Ok(v) => p.certs = v.iter().map(CertProbe::new).collect(),
                        Err(e) => {
                            p.error.get_or_insert(e.to_string());
                        }
                    }
                }
            }
            p
        })
        .collect()
}

// ------------------------------------------------------------------ the report

/// What the user chose to share beyond the defaults.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct Include {
    /// Certificate holder names and organisations, and certificate serial numbers.
    pub names: bool,
    /// Token serial numbers.
    pub serials: bool,
    /// Watch folder and signed-copy folder paths.
    pub paths: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AppInfo {
    pub version: String,
    /// "desktop", "desktop (Microsoft Store)" or "command line".
    pub build: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SystemInfo {
    pub os: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,
    pub arch: String,
    /// WebView2 (Windows) or WebKit version, desktop app only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webview: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    /// The app's language setting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
}

impl SystemInfo {
    /// This computer, as far as the program can tell without a WebView.
    pub fn this_computer() -> Self {
        SystemInfo {
            os: std::env::consts::OS.into(),
            os_version: os_version(),
            arch: std::env::consts::ARCH.into(),
            webview: None,
            locale: env_locale(),
            language: None,
        }
    }
}

/// "Ubuntu 24.04.1 LTS (kernel 6.8.0)", "macOS 14.5", "Microsoft Windows [Version 10.0.22631.4317]".
pub fn os_version() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let name = std::fs::read_to_string("/etc/os-release")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find_map(|l| l.strip_prefix("PRETTY_NAME="))
                    .map(|v| v.trim_matches('"').to_string())
            })
            .unwrap_or_else(|| "Linux".into());
        let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .ok()
            .map(|k| k.trim().split('-').next().unwrap_or_default().to_string());
        Some(match kernel {
            Some(k) if !k.is_empty() => format!("{name} (kernel {k})"),
            _ => name,
        })
    }
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("sw_vers")
            .arg("-productVersion")
            .output()
            .ok()?;
        let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
        (!v.is_empty()).then(|| format!("macOS {v}"))
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let out = std::process::Command::new("cmd")
            .args(["/C", "ver"])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .ok()?;
        let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
        (!v.is_empty()).then_some(v)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        None
    }
}

fn env_locale() -> Option<String> {
    ["LC_ALL", "LC_MESSAGES", "LANG"]
        .iter()
        .filter_map(|v| std::env::var(v).ok())
        .find(|v| !v.is_empty())
}

/// Settings that matter for most problems. Unset fields are unknown here
/// (the command line cannot read the desktop app's own settings).
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SettingsInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<bool>,
    /// Host only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp_server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ltv: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub portal_signing: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub background: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_at_sign_in: Option<bool>,
    /// A watch folder is set up.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub watch_folder: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub watching: Option<bool>,
    /// Only with [`Include::paths`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub watch_folder_path: Option<String>,
    /// Signed copies go to a chosen folder instead of next to the original.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_copy_folder: Option<bool>,
    /// Only with [`Include::paths`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_copy_folder_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_history: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_check: Option<bool>,
}

impl SettingsInfo {
    /// What the app keeps in its data folder: portal signing, background
    /// mode, the watch folder and the signing history. The rest lives in
    /// the app's window and is unknown here.
    pub fn from_app_data(dir: &Path, include: Include) -> Self {
        let read = |p: PathBuf| -> Option<serde_json::Value> {
            serde_json::from_slice(&std::fs::read(p).ok()?).ok()
        };
        let flag = |v: &Option<serde_json::Value>, k: &str| {
            v.as_ref().and_then(|v| v.get(k)).and_then(|b| b.as_bool())
        };
        let portal = flag(&read(dir.join("portal").join("settings.json")), "enabled");
        // Unset: on while portal signing is (background.rs).
        let background =
            flag(&read(dir.join("background.json")), "enabled").or(Some(portal.unwrap_or(false)));
        let watch = read(dir.join("watch.json"));
        let input = watch
            .as_ref()
            .and_then(|w| w.get("input"))
            .and_then(|i| i.as_str())
            .map(|i| i.trim().to_string())
            .filter(|i| !i.is_empty());
        let history = crate::history::History::in_app_data(dir).settings().enabled;
        SettingsInfo {
            portal_signing: Some(portal.unwrap_or(false)),
            background,
            watch_folder: Some(input.is_some()),
            watch_folder_path: input.filter(|_| include.paths),
            signing_history: Some(history),
            ..Default::default()
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PortalInfo {
    pub enabled: bool,
    /// Listening, on this port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Ports passed over because another program uses them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub taken: Vec<u16>,
    /// Why it is not listening although it is on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The app's certificate authority is installed (in the user's trust store).
    pub ca_installed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_valid_until: Option<String>,
}

/// What the caller knows besides the tokens.
#[derive(Debug, Clone, Default)]
pub struct Context {
    pub app: AppInfo,
    pub system: SystemInfo,
    pub settings: Option<SettingsInfo>,
    pub portal: Option<PortalInfo>,
    /// The last update check; `None` where the app does not update itself
    /// (Microsoft Store, command line).
    pub updater: Option<String>,
    pub events: Vec<Event>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DriverReport {
    pub name: String,
    pub path: String,
    pub loaded: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TokenReport {
    pub driver: String,
    pub slot: u64,
    pub label: String,
    pub manufacturer: String,
    pub model: String,
    /// Only with [`Include::serials`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    /// "PIN locked", "few PIN attempts left", …
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flags: Vec<String>,
    pub certificates: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CertReport {
    /// Initials, unless names are included.
    pub subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    /// Only with [`Include::names`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    pub issuer: String,
    pub valid_from: String,
    pub valid_until: String,
    /// "valid", "expired" or "not yet valid".
    pub status: String,
    pub can_sign: bool,
    pub key: String,
    /// First 8 hex digits of the SHA-256 fingerprint.
    pub fingerprint: String,
    pub token: String,
    pub driver: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    /// RFC 3339, UTC.
    pub created: String,
    pub app: AppInfo,
    pub system: SystemInfo,
    pub drivers: Vec<DriverReport>,
    pub tokens: Vec<TokenReport>,
    pub certificates: Vec<CertReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<SettingsInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub portal: Option<PortalInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updater: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_signing_failure: Option<Event>,
    /// Most recent last.
    pub recent_errors: Vec<Event>,
    pub included: Include,
}

/// Errors shown in a report, of the [`EventLog::CAP`] kept.
pub const REPORT_EVENTS: usize = 25;

fn token_flags(t: &TokenInfo) -> Vec<String> {
    let mut v = Vec::new();
    if !t.initialized {
        v.push("not initialised".to_string());
    }
    if t.pin.locked {
        v.push("PIN locked".into());
    } else if t.pin.final_try {
        v.push("one PIN attempt left".into());
    } else if t.pin.count_low {
        v.push("few PIN attempts left".into());
    }
    if t.pin_to_be_changed {
        v.push("PIN must be changed".into());
    }
    v
}

fn day(t: DateTime<Utc>) -> String {
    t.format("%d %b %Y").to_string()
}

/// Puts the report together and redacts every text in it with `redactor`
/// (plus the token serials when they are included).
pub fn build(
    ctx: Context,
    probes: &[DriverProbe],
    include: Include,
    redactor: &Redactor,
    now: DateTime<Utc>,
) -> Report {
    let drivers = probes
        .iter()
        .map(|p| DriverReport {
            name: p.driver.name.clone(),
            path: p.driver.path.to_string_lossy().into_owned(),
            loaded: p.error.is_none() || !p.tokens.is_empty(),
            error: p.error.clone(),
        })
        .collect();
    let mut tokens = Vec::new();
    let mut certificates: Vec<CertReport> = Vec::new();
    let mut kept = Vec::new();
    for p in probes {
        for t in &p.tokens {
            let serial = t.serial.trim().to_string();
            if include.serials && !serial.is_empty() {
                kept.push(serial.clone());
            }
            tokens.push(TokenReport {
                driver: p.driver.name.clone(),
                slot: t.slot,
                label: t.label.clone(),
                manufacturer: t.manufacturer.clone(),
                model: t.model.clone(),
                serial: Some(serial).filter(|s| include.serials && !s.is_empty()),
                flags: token_flags(t),
                certificates: p.certs.iter().filter(|c| c.token_label == t.label).count(),
            });
        }
        for c in &p.certs {
            let s = &c.summary;
            // A token seen through two drivers is listed once.
            if certificates
                .iter()
                .any(|o| c.fingerprint.starts_with(&o.fingerprint) && o.token == c.token_label)
            {
                continue;
            }
            if include.names {
                kept.push(s.serial_hex.clone());
            }
            certificates.push(CertReport {
                subject: if include.names {
                    s.subject_cn.clone()
                } else {
                    initials(&s.subject_cn)
                },
                organization: s.organization.clone().filter(|_| include.names),
                serial: include.names.then(|| s.serial_hex.clone()),
                issuer: s.issuer_cn.clone(),
                valid_from: day(s.not_before),
                valid_until: day(s.not_after),
                status: match validity_at(s.not_before, s.not_after, now) {
                    Validity::Valid { .. } => "valid",
                    Validity::Expired { .. } => "expired",
                    Validity::NotYetValid { .. } => "not yet valid",
                }
                .into(),
                can_sign: s.can_sign,
                key: c.key.clone(),
                fingerprint: c.fingerprint.chars().take(8).collect(),
                token: c.token_label.clone(),
                driver: p.driver.name.clone(),
            });
        }
    }
    let events = ctx.events;
    let last_signing_failure = events.iter().rev().find(|e| e.signing).cloned();
    let recent_errors = events[events.len().saturating_sub(REPORT_EVENTS)..].to_vec();
    let report = Report {
        created: now.to_rfc3339_opts(SecondsFormat::Secs, true),
        app: ctx.app,
        system: ctx.system,
        drivers,
        tokens,
        certificates,
        settings: ctx.settings,
        portal: ctx.portal,
        updater: ctx.updater,
        last_signing_failure,
        recent_errors,
        included: include,
    };
    redact_report(report, &redactor.clone().keep(kept))
}

/// Every string in the report, through `redactor`.
fn redact_report(report: Report, redactor: &Redactor) -> Report {
    fn walk(v: &mut serde_json::Value, r: &Redactor) {
        match v {
            serde_json::Value::String(s) => *s = r.redact(s),
            serde_json::Value::Array(a) => a.iter_mut().for_each(|v| walk(v, r)),
            serde_json::Value::Object(o) => o.values_mut().for_each(|v| walk(v, r)),
            _ => {}
        }
    }
    let Ok(mut v) = serde_json::to_value(&report) else {
        return report;
    };
    walk(&mut v, redactor);
    serde_json::from_value(v).unwrap_or(report)
}

fn on_off(b: bool) -> &'static str {
    if b { "on" } else { "off" }
}

impl Report {
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }

    /// The report as Markdown, with the same data as JSON at the end.
    pub fn to_text(&self) -> String {
        let mut o = String::new();
        let mut line = |s: String| {
            o.push_str(&s);
            o.push('\n');
        };
        line("# TrackMy Sign support report".into());
        line(String::new());
        line(format!(
            "Created {}. Home folder shown as ~; email addresses, PAN-like codes and long hex strings replaced.",
            self.created
        ));
        line(String::new());

        line("## App and system".into());
        line(format!(
            "- TrackMy Sign {} ({})",
            self.app.version, self.app.build
        ));
        let s = &self.system;
        line(format!(
            "- OS: {}{} {}",
            s.os_version
                .as_ref()
                .map(|v| format!("{v}, "))
                .unwrap_or_default(),
            s.os,
            s.arch
        ));
        if let Some(w) = &s.webview {
            line(format!("- WebView: {w}"));
        }
        line(format!(
            "- Locale: {}{}",
            s.locale.as_deref().unwrap_or("unknown"),
            s.language
                .as_ref()
                .map(|l| format!(", app language: {l}"))
                .unwrap_or_default()
        ));
        line(String::new());

        line("## Token drivers".into());
        if self.drivers.is_empty() {
            line("- None found.".into());
        }
        for d in &self.drivers {
            line(format!(
                "- {}: {} ({})",
                d.name,
                d.path,
                match (&d.error, d.loaded) {
                    (None, _) => "loaded".to_string(),
                    (Some(e), true) => format!("loaded; {e}"),
                    (Some(e), false) => format!("failed: {e}"),
                }
            ));
        }
        line(String::new());

        line("## Tokens".into());
        if self.tokens.is_empty() {
            line("- None connected.".into());
        }
        for t in &self.tokens {
            let mut extra = vec![format!(
                "{} certificate{}",
                t.certificates,
                if t.certificates == 1 { "" } else { "s" }
            )];
            if let Some(s) = &t.serial {
                extra.push(format!("serial {s}"));
            }
            extra.extend(t.flags.iter().cloned());
            line(format!(
                "- {} ({} {}), slot {} via {}: {}",
                if t.label.is_empty() {
                    "(no label)"
                } else {
                    &t.label
                },
                t.manufacturer,
                t.model,
                t.slot,
                t.driver,
                extra.join(", ")
            ));
        }
        line(String::new());

        line("## Certificates".into());
        if self.certificates.is_empty() {
            line("- None found.".into());
        }
        for c in &self.certificates {
            let mut who = c.subject.clone();
            if let Some(org) = &c.organization {
                who.push_str(&format!(" ({org})"));
            }
            line(format!(
                "- {who}, issued by {}, valid {} to {} ({}{}), {}, fingerprint {}, on {}{}",
                c.issuer,
                c.valid_from,
                c.valid_until,
                c.status,
                if c.can_sign { "" } else { ", encryption only" },
                c.key,
                c.fingerprint,
                c.token,
                c.serial
                    .as_ref()
                    .map(|s| format!(", serial {s}"))
                    .unwrap_or_default()
            ));
        }
        line(String::new());

        if let Some(st) = &self.settings {
            line("## Settings".into());
            let mut set = |k: &str, v: Option<String>| {
                if let Some(v) = v {
                    line(format!("- {k}: {v}"));
                }
            };
            set(
                "Trusted timestamp",
                st.timestamp.map(|t| match (&st.timestamp_server, t) {
                    (Some(h), true) => format!("on ({h})"),
                    _ => on_off(t).into(),
                }),
            );
            set("Long-term validity (LTV)", st.ltv.map(|b| on_off(b).into()));
            set(
                "GST portal signing",
                st.portal_signing.map(|b| on_off(b).into()),
            );
            set(
                "Keep running in the background",
                st.background.map(|b| on_off(b).into()),
            );
            set(
                "Start at sign-in",
                st.start_at_sign_in.map(|b| on_off(b).into()),
            );
            set(
                "Watch folder",
                st.watch_folder.map(|b| {
                    let mut v = if b { "set up" } else { "not set up" }.to_string();
                    if st.watching == Some(true) {
                        v.push_str(", watching");
                    }
                    if let Some(p) = &st.watch_folder_path {
                        v.push_str(&format!(" ({p})"));
                    }
                    v
                }),
            );
            set(
                "Signed copies",
                st.signed_copy_folder.map(|b| {
                    if !b {
                        "next to the original".to_string()
                    } else if let Some(p) = &st.signed_copy_folder_path {
                        format!("in a chosen folder ({p})")
                    } else {
                        "in a chosen folder".into()
                    }
                }),
            );
            set(
                "Signing history",
                st.signing_history.map(|b| on_off(b).into()),
            );
            set(
                "Check for updates on launch",
                st.update_check.map(|b| on_off(b).into()),
            );
            line(String::new());
        }

        if let Some(p) = &self.portal {
            line("## GST portal listener".into());
            line(format!(
                "- {}",
                match (p.enabled, p.port, &p.error) {
                    (false, _, _) => "Turned off".to_string(),
                    (true, Some(port), _) => format!("Listening on 127.0.0.1:{port}"),
                    (true, None, Some(e)) => format!("Not running: {e}"),
                    (true, None, None) => "Not running".into(),
                }
            ));
            if !p.taken.is_empty() {
                let ports: Vec<String> = p.taken.iter().map(|t| t.to_string()).collect();
                line(format!(
                    "- Ports in use by another program: {}",
                    ports.join(", ")
                ));
            }
            line(format!(
                "- Certificate authority installed: {}{}",
                if p.ca_installed { "yes" } else { "no" },
                p.certificate_valid_until
                    .as_ref()
                    .map(|d| format!(" (certificate valid until {d})"))
                    .unwrap_or_default()
            ));
            line(String::new());
        }

        line("## Updates".into());
        line(format!(
            "- {}",
            self.updater
                .as_deref()
                .unwrap_or(match self.app.build.as_str() {
                    b if b.contains("Store") => "Updated by the Microsoft Store",
                    "command line" => "Not checked by the command-line tool",
                    _ => "Not checked",
                })
        ));
        line(String::new());

        line("## Last signing failure".into());
        match &self.last_signing_failure {
            None => line("- None recorded.".into()),
            Some(e) => {
                line(format!("- {} ({}): {}", e.time, e.area, e.message));
                for c in &e.chain {
                    line(format!("  - caused by: {c}"));
                }
            }
        }
        line(String::new());

        line(format!("## Recent errors ({})", self.recent_errors.len()));
        if self.recent_errors.is_empty() {
            line("- None recorded.".into());
        }
        for e in &self.recent_errors {
            let chain = if e.chain.is_empty() {
                String::new()
            } else {
                format!(" ({})", e.chain.join("; "))
            };
            line(format!("- {} {}: {}{chain}", e.time, e.area, e.message));
        }
        line(String::new());

        line("## Data".into());
        line(String::new());
        line("```json".into());
        line(self.to_json());
        line("```".into());
        o
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::PinStatus;
    use chrono::TimeZone;

    #[test]
    fn home_folder_becomes_tilde() {
        let r = Redactor::new(Some(Path::new("/home/rahul")));
        assert_eq!(
            r.redact("failed: /home/rahul/Documents/a.pdf and /home/rahul"),
            "failed: ~/Documents/a.pdf and ~"
        );
        // Another user whose name starts the same is not the home folder.
        assert_eq!(r.redact("/home/rahulk/x"), "/home/rahulk/x");

        let r = Redactor::new(Some(Path::new("C:\\Users\\Rahul")));
        assert_eq!(
            r.redact(r"C:\Users\Rahul\AppData\Roaming and c:\users\rahul\Desktop"),
            r"~\AppData\Roaming and ~\Desktop"
        );
        assert_eq!(r.redact("C:/Users/Rahul/x.pdf"), "~/x.pdf");
        // A home of "/" would replace every slash.
        assert_eq!(
            Redactor::new(Some(Path::new("/"))).redact("/usr/lib"),
            "/usr/lib"
        );
    }

    #[test]
    fn emails_pans_and_long_hex() {
        let r = Redactor::new(None);
        assert_eq!(
            r.redact("Contact rahul.dk+sign@example.co.in. Or a@b.c"),
            "Contact [email]. Or [email]"
        );
        assert_eq!(r.redact("not@an-address @x.com"), "not@an-address @x.com");
        assert_eq!(
            r.redact("PAN ABCDE1234F, file ABCDE1234F_invoice.pdf, xABCDE1234Fy"),
            "PAN [PAN], file [PAN]_invoice.pdf, x[PAN]y"
        );
        // Lower case and wrong shape are not PANs.
        assert_eq!(r.redact("abcde1234f ABCD1234FG"), "abcde1234f ABCD1234FG");
        assert_eq!(
            r.redact("sha 3f2a9c0e1b7d4a6f9e8c7b6a5d4c3b2a1f0e9d8c, fp 3f2a9c0e"),
            "sha [hex], fp 3f2a9c0e"
        );
        assert_eq!(r.redact("serial 0123456789ABCDEF"), "serial [hex]");
        assert_eq!(
            r.redact("version 10.0.22631.4317"),
            "version 10.0.22631.4317"
        );
        assert_eq!(r.redact("नमस्ते ABCDE1234F"), "नमस्ते [PAN]");
    }

    #[test]
    fn kept_values_survive() {
        let r =
            Redactor::new(Some(Path::new("/home/rahul"))).keep(["0123456789ABCDEF".to_string()]);
        assert_eq!(
            r.redact("serial 0123456789ABCDEF, other FEDCBA9876543210, /home/rahul/x"),
            "serial 0123456789ABCDEF, other [hex], ~/x"
        );
    }

    #[test]
    fn names_hosts_and_issue_link() {
        assert_eq!(initials("RAHUL TEST DIRECTOR"), "R. T. D.");
        assert_eq!(initials("d.k. rahul"), "D. K. R.");
        assert_eq!(initials("  "), "(no name)");
        assert_eq!(
            url_host("http://timestamp.digicert.com"),
            "timestamp.digicert.com"
        );
        assert_eq!(
            url_host("https://user:pw@tsa.example.in:8443/tsr?x=1"),
            "tsa.example.in:8443"
        );
        assert_eq!(
            issue_url("0.6.0"),
            "https://github.com/rahuldk1105/trackmysign/issues/new?template=bug_report.yml&version=v0.6.0"
        );
    }

    #[test]
    fn events_hide_documents() {
        let doc = Path::new("/srv/inbox/ABCDE1234F salary.pdf");
        let e = Event::error(
            "sign",
            "reading /srv/inbox/ABCDE1234F salary.pdf: not found",
            &["signing ABCDE1234F salary.pdf".into(), "Wrong PIN.".into()],
            &[doc],
            true,
        );
        assert_eq!(e.message, "reading [document]: not found");
        assert_eq!(e.chain, ["signing [document]", "Wrong PIN."]);
        assert!(e.signing);
        let long = "x".repeat(2000);
        assert!(
            Event::error("sign", &long, &[], &[], false)
                .message
                .chars()
                .count()
                <= MAX_MESSAGE + 1
        );
    }

    #[test]
    fn event_log_keeps_the_last_ones() {
        let dir = std::env::temp_dir().join(format!("tms-support-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let log = EventLog::in_app_data(&dir);
        assert!(log.events().is_empty());
        for i in 0..EventLog::CAP + 5 {
            log.record(Event::error("sign", &format!("error {i}"), &[], &[], false))
                .unwrap();
        }
        let events = log.events();
        assert_eq!(events.len(), EventLog::CAP);
        assert_eq!(events[0].message, "error 5");
        assert_eq!(
            events.last().unwrap().message,
            format!("error {}", EventLog::CAP + 4)
        );
        // The same error twice in a row is kept once.
        let again = Event::error("sign", "error 204", &[], &[], false);
        log.record(again).unwrap();
        assert_eq!(log.events().len(), EventLog::CAP);
        log.clear().unwrap();
        assert!(log.events().is_empty());
        log.clear().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn fake_cert(cn: &str, label: &str) -> CertProbe {
        let t = |y| Utc.with_ymd_and_hms(y, 1, 1, 0, 0, 0).unwrap();
        CertProbe {
            summary: CertSummary {
                subject_cn: cn.into(),
                issuer_cn: "Test Sub-CA for Class 3 Individual 2026".into(),
                organization: Some("Personal".into()),
                serial_hex: "4F1C2A9B8E7D6C5B4A39".into(),
                not_before: t(2025),
                not_after: t(2027),
                expired: false,
                can_sign: true,
                is_ca: false,
                key_kind: crate::KeyKind::Rsa,
                signature_len: 256,
                rsa_modulus: None,
                subject_der: Vec::new(),
                issuer_der: Vec::new(),
            },
            key: "RSA 2048".into(),
            fingerprint: "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809".into(),
            token_label: label.into(),
        }
    }

    fn fake_drivers() -> Vec<DriverProbe> {
        vec![
            DriverProbe {
                driver: Driver {
                    name: "Hypersecu HyperPKI".into(),
                    path: "/home/rahul/drivers/libcastle_v2.so".into(),
                },
                error: None,
                tokens: vec![TokenInfo {
                    slot: 1,
                    label: "HYP2003".into(),
                    manufacturer: "Feitian".into(),
                    model: "ePass2003".into(),
                    serial: "2A1B3C4D5E6F7081".into(),
                    initialized: true,
                    pin: PinStatus {
                        count_low: true,
                        final_try: false,
                        locked: false,
                    },
                    pin_to_be_changed: false,
                }],
                certs: vec![fake_cert("RAHUL TEST DIRECTOR", "HYP2003")],
            },
            DriverProbe {
                driver: Driver {
                    name: "OpenSC".into(),
                    path: "/usr/lib/opensc-pkcs11.so".into(),
                },
                error: Some("Could not load the token driver: missing symbol".into()),
                tokens: Vec::new(),
                certs: Vec::new(),
            },
        ]
    }

    fn context() -> Context {
        Context {
            app: AppInfo {
                version: "0.6.0".into(),
                build: "desktop".into(),
            },
            system: SystemInfo {
                os: "linux".into(),
                os_version: Some("Ubuntu 24.04 LTS".into()),
                arch: "x86_64".into(),
                webview: Some("2.44.0".into()),
                locale: Some("en-IN".into()),
                language: Some("system".into()),
            },
            settings: Some(SettingsInfo {
                timestamp: Some(true),
                timestamp_server: Some(url_host("http://timestamp.digicert.com/x")),
                ltv: Some(false),
                watch_folder: Some(true),
                watch_folder_path: None,
                ..Default::default()
            }),
            portal: Some(PortalInfo {
                enabled: true,
                port: Some(18_000),
                ca_installed: true,
                ..Default::default()
            }),
            updater: Some("Up to date (0.6.0)".into()),
            events: vec![
                Event {
                    time: "2026-10-26T10:00:00Z".into(),
                    area: "sign".into(),
                    message: "Wrong PIN. by rahul@example.com for ABCDE1234F in /home/rahul/x"
                        .into(),
                    chain: vec!["wrongPin".into()],
                    signing: true,
                },
                Event {
                    time: "2026-10-26T10:05:00Z".into(),
                    area: "certificates".into(),
                    message: "The DSC token is not plugged in (or was removed).".into(),
                    chain: Vec::new(),
                    signing: false,
                },
            ],
        }
    }

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 26, 12, 0, 0).unwrap()
    }

    #[test]
    fn report_by_default_leaves_out_names_and_serials() {
        let redactor = Redactor::new(Some(Path::new("/home/rahul")));
        let r = build(
            context(),
            &fake_drivers(),
            Include::default(),
            &redactor,
            now(),
        );
        let text = r.to_text();
        for hidden in [
            "RAHUL TEST DIRECTOR",
            "Personal",
            "2A1B3C4D5E6F7081",
            "4F1C2A9B8E7D6C5B4A39",
            "/home/rahul",
            "rahul@example.com",
            "ABCDE1234F",
            "1a2b3c4d5e6f",
        ] {
            assert!(!text.contains(hidden), "{hidden} in\n{text}");
        }
        for shown in [
            "TrackMy Sign 0.6.0 (desktop)",
            "Ubuntu 24.04 LTS",
            "WebView: 2.44.0",
            "~/drivers/libcastle_v2.so (loaded)",
            "failed: Could not load the token driver: missing symbol",
            "HYP2003 (Feitian ePass2003), slot 1 via Hypersecu HyperPKI: 1 certificate, few PIN attempts left",
            "R. T. D., issued by Test Sub-CA for Class 3 Individual 2026, valid 01 Jan 2025 to 01 Jan 2027 (valid), RSA 2048, fingerprint 1a2b3c4d, on HYP2003",
            "Trusted timestamp: on (timestamp.digicert.com)",
            "Watch folder: set up",
            "Listening on 127.0.0.1:18000",
            "Up to date (0.6.0)",
            "Wrong PIN. by [email] for [PAN] in ~/x",
            "## Recent errors (2)",
            "```json",
        ] {
            assert!(text.contains(shown), "{shown} not in\n{text}");
        }
        assert_eq!(r.last_signing_failure.as_ref().unwrap().area, "sign");
        // The JSON block is the report itself.
        let json = text
            .split("```json\n")
            .nth(1)
            .unwrap()
            .split("\n```")
            .next()
            .unwrap();
        let back: Report = serde_json::from_str(json).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn report_with_everything_ticked() {
        let redactor = Redactor::new(Some(Path::new("/home/rahul")));
        let include = Include {
            names: true,
            serials: true,
            paths: true,
        };
        let r = build(context(), &fake_drivers(), include, &redactor, now());
        let text = r.to_text();
        assert!(text.contains("RAHUL TEST DIRECTOR (Personal)"), "{text}");
        assert!(text.contains("serial 2A1B3C4D5E6F7081"), "{text}");
        assert!(text.contains("serial 4F1C2A9B8E7D6C5B4A39"), "{text}");
        // Still never the whole fingerprint, the home folder or a PAN.
        assert!(!text.contains("1a2b3c4d5e6f"));
        assert!(!text.contains("/home/rahul"));
        assert!(!text.contains("ABCDE1234F"));
    }

    #[test]
    fn store_and_command_line_reports() {
        let mut ctx = context();
        ctx.app.build = "desktop (Microsoft Store)".into();
        ctx.updater = None;
        let text = build(ctx, &[], Include::default(), &Redactor::default(), now()).to_text();
        assert!(text.contains("Updated by the Microsoft Store"));
        assert!(text.contains("## Token drivers\n- None found."));

        let ctx = Context {
            app: AppInfo {
                version: "0.6.0".into(),
                build: "command line".into(),
            },
            system: SystemInfo::this_computer(),
            ..Default::default()
        };
        let r = build(
            ctx,
            &fake_drivers(),
            Include::default(),
            &Redactor::default(),
            now(),
        );
        assert!(r.updater.is_none() && r.settings.is_none() && r.portal.is_none());
        let text = r.to_text();
        assert!(text.contains("Not checked by the command-line tool"));
        assert!(!text.contains("## Settings"));
        assert!(text.contains("## Last signing failure\n- None recorded."));
    }

    #[test]
    fn settings_from_the_app_data_folder() {
        let dir = std::env::temp_dir().join(format!("tms-support-settings-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = SettingsInfo::from_app_data(&dir, Include::default());
        assert_eq!(s.portal_signing, Some(false));
        assert_eq!(s.background, Some(false));
        assert_eq!(s.watch_folder, Some(false));
        assert_eq!(s.signing_history, Some(true));
        std::fs::create_dir_all(dir.join("portal")).unwrap();
        std::fs::write(dir.join("portal/settings.json"), br#"{"enabled": true}"#).unwrap();
        std::fs::write(dir.join("watch.json"), br#"{"input": "/srv/inbox"}"#).unwrap();
        let s = SettingsInfo::from_app_data(&dir, Include::default());
        assert_eq!(s.portal_signing, Some(true));
        assert_eq!(s.background, Some(true));
        assert_eq!(s.watch_folder, Some(true));
        assert_eq!(s.watch_folder_path, None);
        let with_paths = Include {
            paths: true,
            ..Default::default()
        };
        let s = SettingsInfo::from_app_data(&dir, with_paths);
        assert_eq!(s.watch_folder_path.as_deref(), Some("/srv/inbox"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
