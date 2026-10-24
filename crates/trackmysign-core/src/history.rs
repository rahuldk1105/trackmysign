//! Signing history: a private log of every signature made on this computer,
//! kept by the desktop app and the command line in the same folder (the
//! app's data folder, `history`).
//!
//! One JSON object per line, one file per month (`2026-10.jsonl`), only ever
//! appended to. Every entry holds the SHA-256 of the line before it, so an
//! edited or removed line breaks the chain, and `head.json` remembers the
//! last entry, so removing the newest ones shows too. Anyone who can write
//! the folder can still rewrite it all; the chain only shows changes made
//! without redoing every hash after them.
//!
//! An entry holds file paths, SHA-256 hashes, the certificate's names,
//! serial number and fingerprint, and the signing options: never a PIN, a
//! password or anything from inside a document.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Datelike, Duration, NaiveDate, SecondsFormat, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::certinfo::CertSummary;
use crate::folder::push_csv_row;
use crate::pdf::appearance::Face;
use crate::pdf::textdoc::{Style, TextDoc};
use crate::report::{ACCENT, BAD, INK, LINE, MUTED, OK, ist_and_utc, plural, shown};
use crate::{SignRequest, watch};

/// The desktop app's identifier: its data folder is named after it, and the
/// command line uses the same one.
pub const APP_ID: &str = "in.trackmytech.trackmysign";

/// Version of the entry layout; raised only when a field changes meaning or
/// is removed.
pub const SCHEMA_VERSION: u32 = 1;

/// `prev` of the first entry, and of the entry that starts a cleared history.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

const HEAD: &str = "head.json";
const SETTINGS: &str = "settings.json";
const LOCK: &str = ".lock";

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// An approval signature with a box on one page, or invisible.
    Sign,
    /// One signature with the box on several pages.
    SignPages,
    /// Signed into an empty signature field of the document.
    SignField,
    /// A certification (author) signature.
    Certify,
    /// A GST portal request (a hash or text, not a PDF).
    PortalSign,
    /// Any file signed as a `.p7s` (detached) or `.p7m` (attached).
    SignFile,
    /// The history was cleared; the chain starts again here.
    Cleared,
    /// Months older than the retention setting were deleted.
    Pruned,
    /// "Keep a signing history" was turned off; nothing is recorded after this.
    Paused,
    /// ... and on again.
    Resumed,
}

impl Action {
    pub fn label(self) -> &'static str {
        match self {
            Action::Sign => "Signed",
            Action::SignPages => "Signed on several pages",
            Action::SignField => "Signed a signature field",
            Action::Certify => "Certified",
            Action::PortalSign => "GST portal signature",
            Action::SignFile => "Signed a file (CMS)",
            Action::Cleared => "History cleared",
            Action::Pruned => "Old entries deleted",
            Action::Paused => "History turned off",
            Action::Resumed => "History turned on",
        }
    }

    /// A note about the history itself rather than a signature.
    pub fn is_marker(self) -> bool {
        matches!(
            self,
            Action::Cleared | Action::Pruned | Action::Paused | Action::Resumed
        )
    }

    pub fn key(self) -> &'static str {
        match self {
            Action::Sign => "sign",
            Action::SignPages => "sign_pages",
            Action::SignField => "sign_field",
            Action::Certify => "certify",
            Action::PortalSign => "portal_sign",
            Action::SignFile => "sign_file",
            Action::Cleared => "cleared",
            Action::Pruned => "pruned",
            Action::Paused => "paused",
            Action::Resumed => "resumed",
        }
    }
}

/// How the signature was asked for.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// One document, signed by hand.
    Manual,
    /// Several documents with one PIN entry.
    Batch,
    /// The watch folder.
    Watch,
    /// The GST portal page.
    Portal,
}

impl Source {
    pub fn label(self) -> &'static str {
        match self {
            Source::Manual => "Single",
            Source::Batch => "Batch",
            Source::Watch => "Watch folder",
            Source::Portal => "GST portal",
        }
    }

    pub fn key(self) -> &'static str {
        match self {
            Source::Manual => "manual",
            Source::Batch => "batch",
            Source::Watch => "watch",
            Source::Portal => "portal",
        }
    }

    pub fn parse(s: &str) -> Option<Source> {
        [Source::Manual, Source::Batch, Source::Watch, Source::Portal]
            .into_iter()
            .find(|v| v.key() == s)
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Signed,
    Failed,
}

impl Outcome {
    pub fn key(self) -> &'static str {
        match self {
            Outcome::Signed => "signed",
            Outcome::Failed => "failed",
        }
    }

    pub fn parse(s: &str) -> Option<Outcome> {
        [Outcome::Signed, Outcome::Failed]
            .into_iter()
            .find(|v| v.key() == s)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FileRef {
    pub path: String,
    /// Lower-case hex; none when the file could not be read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct CertRef {
    pub subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    pub issuer: String,
    pub serial: String,
    /// SHA-256 of the certificate, lower-case hex.
    pub fingerprint: String,
}

impl CertRef {
    pub fn from_der(der: &[u8]) -> Option<CertRef> {
        let s = CertSummary::from_der(der).ok()?;
        Some(CertRef {
            subject: s.subject_cn,
            organization: s.organization,
            issuer: s.issuer_cn,
            serial: s.serial_hex,
            fingerprint: sha256_hex(der),
        })
    }
}

/// What a GST portal request asked to sign.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PortalRef {
    /// PAN the portal asked for.
    pub pan: String,
    /// "registration" (the PAN itself), "digest" (a hash of a return or
    /// form) or "text".
    pub kind: String,
    /// The PAN or hash that was signed; none for text, which is only hashed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    /// SHA-256 of what was signed (UTF-8).
    pub sha256: String,
}

impl PortalRef {
    pub fn new(pan: &str, kind: &str, to_be_signed: &str) -> PortalRef {
        PortalRef {
            pan: pan.to_string(),
            kind: kind.to_string(),
            data: (kind != "text").then(|| to_be_signed.to_string()),
            sha256: sha256_hex(to_be_signed.as_bytes()),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Entry {
    /// [`SCHEMA_VERSION`].
    pub v: u32,
    /// Counts up by one from the first entry ever; a gap means entries are missing.
    pub seq: u64,
    #[serde(with = "rfc3339")]
    pub time: DateTime<Utc>,
    pub action: Action,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<Source>,
    /// "desktop 0.6.0" or "cli 0.6.0".
    pub program: String,
    /// The page that asked (GST portal).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<FileRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<FileRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub portal: Option<PortalRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert: Option<CertRef>,
    /// Pages that show the box, numbered from 1; empty when invisible or in a field.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pages: Vec<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    /// DocMDP level (1-3) of a certification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certify: Option<u8>,
    /// Timestamp server used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub ltv: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<Outcome>,
    /// Why it failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Entries deleted ([`Action::Cleared`], [`Action::Pruned`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed: Option<u64>,
    /// [`Action::Pruned`]: hash of the last deleted line, which the oldest
    /// line kept points to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<String>,
    /// SHA-256 of the line before, or [`GENESIS`].
    pub prev: String,
}

fn is_false(b: &bool) -> bool {
    !*b
}

impl Entry {
    /// An entry for `program` ("desktop 0.6.0"); `seq`, `time` and `prev`
    /// are set when it is recorded.
    pub fn new(action: Action, source: Option<Source>, program: &str) -> Entry {
        Entry {
            v: SCHEMA_VERSION,
            seq: 0,
            time: Utc::now(),
            action,
            source,
            program: program.to_string(),
            origin: None,
            input: None,
            output: None,
            portal: None,
            cert: None,
            pages: Vec::new(),
            field: None,
            reason: None,
            location: None,
            certify: None,
            timestamp: None,
            ltv: false,
            outcome: None,
            error: None,
            removed: None,
            anchor: None,
            prev: String::new(),
        }
    }

    /// Signing `input` as `req` asks; the action follows from the request.
    pub fn signing(source: Source, program: &str, input: &Path, req: &SignRequest) -> Entry {
        let action = if req.certify.is_some() {
            Action::Certify
        } else if req.field.is_some() {
            Action::SignField
        } else if req.pages.len() > 1 {
            Action::SignPages
        } else {
            Action::Sign
        };
        let mut e = Entry::new(action, Some(source), program);
        e.input = Some(FileRef {
            path: input.to_string_lossy().into_owned(),
            sha256: None,
        });
        e.pages = if req.field.is_some() || req.rect.is_none() {
            Vec::new()
        } else if req.pages.is_empty() {
            vec![req.page + 1]
        } else {
            req.pages.iter().map(|p| p + 1).collect()
        };
        e.field = req.field.clone();
        e.reason = req.reason.clone();
        e.location = req.location.clone();
        e.certify = req.certify.map(|c| c.level());
        e.timestamp = req.timestamp.clone();
        e.ltv = req.ltv;
        e
    }

    /// Signing `input` as a `.p7s` or `.p7m`.
    pub fn file_signing(
        source: Source,
        program: &str,
        input: &Path,
        req: &crate::filesig::FileSignRequest,
    ) -> Entry {
        let mut e = Entry::new(Action::SignFile, Some(source), program);
        e.input = Some(FileRef {
            path: input.to_string_lossy().into_owned(),
            sha256: None,
        });
        e.timestamp = req.timestamp.clone();
        e
    }

    /// The original as it was read.
    pub fn input_data(&mut self, data: &[u8]) {
        if let Some(f) = &mut self.input {
            f.sha256 = Some(sha256_hex(data));
        }
    }

    pub fn cert_der(&mut self, der: &[u8]) {
        self.cert = CertRef::from_der(der);
    }

    pub fn signed(mut self, output: &Path, data: &[u8]) -> Entry {
        self.output = Some(FileRef {
            path: output.to_string_lossy().into_owned(),
            sha256: Some(sha256_hex(data)),
        });
        self.outcome = Some(Outcome::Signed);
        self
    }

    /// Signed, with no file written (a GST portal request).
    pub fn succeeded(mut self) -> Entry {
        self.outcome = Some(Outcome::Signed);
        self
    }

    pub fn failed(mut self, reason: impl Into<String>) -> Entry {
        self.outcome = Some(Outcome::Failed);
        self.error = Some(reason.into());
        self
    }

    /// File name of the document (or the GST portal request), for tables.
    pub fn document(&self) -> String {
        if let Some(f) = &self.input {
            return Path::new(&f.path)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| f.path.clone());
        }
        if let Some(p) = &self.portal {
            return format!("GST portal ({}, PAN {})", p.kind, p.pan);
        }
        String::new()
    }
}

/// Builds the watch folder's entries: [`watch::Host::sign`] sees the
/// document and the request, the event that follows says which file it was
/// and where it went.
pub struct WatchRecorder {
    program: String,
    /// The last signing: its entry so far and the signed copy's hash, or why it failed.
    pending: Option<(Entry, Result<String, String>)>,
}

impl WatchRecorder {
    pub fn new(program: &str) -> WatchRecorder {
        WatchRecorder {
            program: program.to_string(),
            pending: None,
        }
    }

    /// Call from [`watch::Host::sign`] with what signing returned.
    pub fn signing(
        &mut self,
        data: &[u8],
        req: &SignRequest,
        cert_der: &[u8],
        result: &Result<Vec<u8>, crate::Error>,
    ) {
        let mut e = Entry::signing(Source::Watch, &self.program, Path::new(""), req);
        e.input_data(data);
        e.cert_der(cert_der);
        let result = match result {
            Ok(signed) => Ok(sha256_hex(signed)),
            Err(err) => Err(err.to_string()),
        };
        self.pending = Some((e, result));
    }

    /// The entry for `event`; none for a file left alone.
    pub fn event(&mut self, event: &watch::Event) -> Option<Entry> {
        let pending = self.pending.take();
        match event {
            watch::Event::Signed { input, output, .. } => {
                let (mut e, result) = pending?;
                set_path(&mut e, input);
                e.output = Some(FileRef {
                    path: output.to_string_lossy().into_owned(),
                    sha256: result.ok(),
                });
                e.outcome = Some(Outcome::Signed);
                Some(e)
            }
            watch::Event::Failed {
                input,
                moved,
                reason,
            } => {
                let mut e = match pending {
                    Some((e, _)) => e,
                    // Not signed at all (not a PDF, needs a password, ...).
                    None => {
                        let mut e = Entry::new(Action::Sign, Some(Source::Watch), &self.program);
                        e.input = Some(FileRef {
                            path: String::new(),
                            sha256: moved
                                .as_deref()
                                .and_then(|m| fs::read(m).ok())
                                .map(|d| sha256_hex(&d)),
                        });
                        e
                    }
                };
                set_path(&mut e, input);
                Some(e.failed(reason.clone()))
            }
            watch::Event::Skipped { .. } => None,
        }
    }

    /// A signing that stopped the watch (token removed, PIN refused, output
    /// folder gone) gets no event; it is recorded against the watched folder.
    pub fn stopped(&mut self, folder: &Path, stop: &watch::Stop) -> Option<Entry> {
        let (mut e, result) = self.pending.take()?;
        let reason = match (result, stop) {
            (Err(reason), _) => reason,
            (Ok(_), watch::Stop::Folder(reason)) => reason.clone(),
            // Signed and saved; its event came before.
            (Ok(_), _) => return None,
        };
        set_path(&mut e, folder);
        Some(e.failed(reason))
    }
}

fn set_path(e: &mut Entry, path: &Path) {
    if let Some(f) = &mut e.input {
        f.path = path.to_string_lossy().into_owned();
    }
}

mod rfc3339 {
    use chrono::{DateTime, SecondsFormat, Utc};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(t: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&t.to_rfc3339_opts(SecondsFormat::Secs, true))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<DateTime<Utc>, D::Error> {
        let s = String::deserialize(d)?;
        DateTime::parse_from_rfc3339(&s)
            .map(|t| t.with_timezone(&Utc))
            .map_err(serde::de::Error::custom)
    }
}

pub fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

// ------------------------------------------------------------ settings

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub enum Retention {
    #[default]
    Forever,
    Year,
    Days90,
}

impl Retention {
    pub fn days(self) -> Option<i64> {
        match self {
            Retention::Forever => None,
            Retention::Year => Some(365),
            Retention::Days90 => Some(90),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    /// "Keep a signing history"; on unless turned off.
    pub enabled: bool,
    pub retention: Retention,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            enabled: true,
            retention: Retention::Forever,
        }
    }
}

// ------------------------------------------------------------ the log

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct Head {
    seq: u64,
    hash: String,
}

/// A line of the log as stored.
struct Line {
    file: String,
    /// From 1.
    number: usize,
    text: String,
}

/// The history folder. Every change takes a lock file, so the app and the
/// command line can both write to it.
pub struct History {
    dir: PathBuf,
}

impl History {
    pub fn new(dir: impl Into<PathBuf>) -> History {
        History { dir: dir.into() }
    }

    /// The history kept in an app data folder (`<data>/in.trackmytech.trackmysign`).
    pub fn in_app_data(app_data: &Path) -> History {
        History::new(app_data.join("history"))
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn lock(&self) -> io::Result<File> {
        fs::create_dir_all(&self.dir)?;
        let f = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.dir.join(LOCK))?;
        f.lock()?;
        Ok(f)
    }

    pub fn settings(&self) -> Settings {
        fs::read(self.dir.join(SETTINGS))
            .ok()
            .and_then(|d| serde_json::from_slice(&d).ok())
            .unwrap_or_default()
    }

    /// Saves `s`; turning recording off or on is noted in the log, and a
    /// shorter retention deletes old months at once.
    pub fn set_settings(&self, s: Settings, program: &str) -> io::Result<()> {
        let _lock = self.lock()?;
        let before = self.settings();
        let json = serde_json::to_vec_pretty(&s).map_err(io::Error::other)?;
        fs::write(self.dir.join(SETTINGS), json)?;
        let now = Utc::now();
        if before.enabled != s.enabled {
            let action = if s.enabled {
                Action::Resumed
            } else {
                Action::Paused
            };
            self.append(Entry::new(action, None, program), now)?;
        }
        self.prune(s.retention, program, now)
    }

    /// Appends `entry` (unless recording is off) and returns whether it was.
    pub fn record(&self, entry: Entry) -> io::Result<bool> {
        let now = Utc::now();
        self.record_at(entry, now)
    }

    /// [`record`](Self::record) at `now`, for tests.
    pub fn record_at(&self, mut entry: Entry, now: DateTime<Utc>) -> io::Result<bool> {
        let settings = self.settings();
        if !settings.enabled {
            return Ok(false);
        }
        let _lock = self.lock()?;
        self.prune(settings.retention, &entry.program, now)?;
        entry.time = now;
        self.append(entry, now)?;
        Ok(true)
    }

    /// Deletes months that ended before the retention period; called on
    /// every recording, and by the app at start.
    pub fn apply_retention(&self, program: &str) -> io::Result<()> {
        let settings = self.settings();
        if settings.retention == Retention::Forever || !self.dir.is_dir() {
            return Ok(());
        }
        let _lock = self.lock()?;
        self.prune(settings.retention, program, Utc::now())
    }

    /// Deletes every entry and starts again with one that says so (and how
    /// many were deleted). Returns that number.
    pub fn clear(&self, program: &str) -> io::Result<u64> {
        let _lock = self.lock()?;
        let lines = self.lines()?;
        let last_seq = self.last_seq(&lines);
        let removed = lines.len() as u64;
        for f in self.files()? {
            fs::remove_file(self.dir.join(f))?;
        }
        let mut e = Entry::new(Action::Cleared, None, program);
        e.removed = Some(removed);
        e.seq = last_seq + 1;
        e.prev = GENESIS.to_string();
        self.write_line(e, Utc::now())?;
        Ok(removed)
    }

    /// Every entry, oldest first. Lines that cannot be read are left out
    /// ([`check`](Self::check) reports them).
    pub fn entries(&self) -> io::Result<Vec<Entry>> {
        Ok(self
            .lines()?
            .iter()
            .filter_map(|l| serde_json::from_str(&l.text).ok())
            .collect())
    }

    /// Month files, oldest first.
    fn files(&self) -> io::Result<Vec<String>> {
        let mut files = Vec::new();
        let dir = match fs::read_dir(&self.dir) {
            Ok(d) => d,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(files),
            Err(e) => return Err(e),
        };
        for item in dir {
            let name = item?.file_name().to_string_lossy().into_owned();
            if month_of(&name).is_some() {
                files.push(name);
            }
        }
        files.sort();
        Ok(files)
    }

    fn lines(&self) -> io::Result<Vec<Line>> {
        self.read_lines(&self.files()?)
    }

    /// The lines of the newest month that has any: enough to chain to.
    fn tail(&self) -> io::Result<Vec<Line>> {
        for file in self.files()?.into_iter().rev() {
            let lines = self.read_lines(&[file])?;
            if !lines.is_empty() {
                return Ok(lines);
            }
        }
        Ok(Vec::new())
    }

    fn read_lines(&self, files: &[String]) -> io::Result<Vec<Line>> {
        let mut out = Vec::new();
        for file in files {
            let data = fs::read(self.dir.join(file))?;
            let text = String::from_utf8_lossy(&data);
            for (i, l) in text.split('\n').enumerate() {
                let l = l.strip_suffix('\r').unwrap_or(l);
                if !l.is_empty() {
                    out.push(Line {
                        file: file.clone(),
                        number: i + 1,
                        text: l.to_string(),
                    });
                }
            }
        }
        Ok(out)
    }

    fn head(&self) -> Option<Head> {
        fs::read(self.dir.join(HEAD))
            .ok()
            .and_then(|d| serde_json::from_slice(&d).ok())
    }

    /// The highest number used so far, also by entries no longer in the files.
    fn last_seq(&self, lines: &[Line]) -> u64 {
        let in_files = lines
            .iter()
            .rev()
            .find_map(|l| serde_json::from_str::<Entry>(&l.text).ok())
            .map_or(0, |e| e.seq);
        in_files.max(self.head().map_or(0, |h| h.seq))
    }

    /// Chains `entry` to the last line and appends it. The lock is held.
    fn append(&self, mut entry: Entry, now: DateTime<Utc>) -> io::Result<()> {
        let lines = self.tail()?;
        entry.seq = self.last_seq(&lines) + 1;
        entry.prev = lines
            .last()
            .map_or_else(|| GENESIS.to_string(), |l| sha256_hex(l.text.as_bytes()));
        self.write_line(entry, now)
    }

    fn write_line(&self, mut entry: Entry, now: DateTime<Utc>) -> io::Result<()> {
        entry.time = now;
        let line = serde_json::to_string(&entry).map_err(io::Error::other)?;
        // A clock set back keeps writing to the newest month, so the files
        // stay in order.
        let name = self
            .files()?
            .pop()
            .filter(|f| *f > file_for(now))
            .unwrap_or_else(|| file_for(now));
        let path = self.dir.join(name);
        let mut f = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)?;
        // A line cut short by a crash stays on its own line.
        let len = f.metadata()?.len();
        if len > 0 {
            let mut last = [0u8];
            f.seek(SeekFrom::Start(len - 1))?;
            f.read_exact(&mut last)?;
            if last != *b"\n" {
                f.write_all(b"\n")?;
            }
        }
        f.write_all(format!("{line}\n").as_bytes())?;
        f.sync_all()?;
        let head = Head {
            seq: entry.seq,
            hash: sha256_hex(line.as_bytes()),
        };
        let json = serde_json::to_vec(&head).map_err(io::Error::other)?;
        let tmp = self.dir.join("head.json.tmp");
        fs::write(&tmp, json)?;
        fs::rename(tmp, self.dir.join(HEAD))
    }

    /// Deletes month files that ended more than `retention` before `now`,
    /// and notes it with the hash the oldest kept line points to.
    fn prune(&self, retention: Retention, program: &str, now: DateTime<Utc>) -> io::Result<()> {
        let Some(days) = retention.days() else {
            return Ok(());
        };
        let cutoff = now - Duration::days(days);
        let old: Vec<String> = self
            .files()?
            .into_iter()
            .filter(|f| month_of(f).is_some_and(|m| month_end(m) <= cutoff))
            .collect();
        if old.is_empty() {
            return Ok(());
        }
        let removed = self.read_lines(&old)?;
        let anchor = removed.last().map(|l| sha256_hex(l.text.as_bytes()));
        let count = removed.len() as u64;
        let lines = self.tail()?;
        let mut e = Entry::new(Action::Pruned, None, program);
        e.removed = Some(count);
        e.anchor = anchor;
        // Chained before deleting, so the note follows the last line written.
        e.seq = self.last_seq(&lines) + 1;
        e.prev = lines
            .last()
            .map_or_else(|| GENESIS.to_string(), |l| sha256_hex(l.text.as_bytes()));
        for f in &old {
            fs::remove_file(self.dir.join(f))?;
        }
        self.write_line(e, now)
    }

    /// Follows the chain through every file.
    pub fn check(&self) -> io::Result<Integrity> {
        let lines = self.lines()?;
        let mut problems = Vec::new();
        let mut entries: Vec<(&Line, Entry)> = Vec::new();
        for l in &lines {
            match serde_json::from_str::<Entry>(&l.text) {
                Ok(e) => entries.push((l, e)),
                Err(_) => problems.push(Problem::at(l, None, "This line is not a history entry.")),
            }
        }
        let anchors: Vec<&str> = entries
            .iter()
            .filter_map(|(_, e)| e.anchor.as_deref())
            .collect();
        let mut before: Option<(&Line, &Entry)> = None;
        for (l, e) in &entries {
            match before {
                None => {
                    let starts = e.prev == GENESIS && (e.seq == 1 || e.action == Action::Cleared);
                    if !starts && !anchors.contains(&e.prev.as_str()) {
                        problems.push(Problem::at(
                            l,
                            Some(e.seq),
                            "The entries before this one were deleted.",
                        ));
                    }
                }
                Some((pl, pe)) => {
                    if e.prev != sha256_hex(pl.text.as_bytes()) {
                        problems.push(Problem::at(
                            l,
                            Some(e.seq),
                            "The entry before this one was changed or deleted.",
                        ));
                    } else if e.seq != pe.seq + 1 {
                        problems.push(Problem::at(
                            l,
                            Some(e.seq),
                            &format!(
                                "Entries are missing before this one: {} to {}.",
                                pe.seq + 1,
                                e.seq.saturating_sub(1)
                            ),
                        ));
                    }
                }
            }
            before = Some((l, e));
        }
        let last = lines.last();
        match (self.head(), last) {
            (None, None) => {}
            (Some(_), None) => problems.push(Problem {
                file: String::new(),
                line: 0,
                seq: None,
                message: "Every entry was deleted.".into(),
            }),
            (None, Some(l)) => problems.push(Problem::at(
                l,
                None,
                "The record of the newest entry (head.json) is missing.",
            )),
            (Some(h), Some(l)) => {
                let hash = sha256_hex(l.text.as_bytes());
                let last_entry = entries.last().map(|(_, e)| e);
                // The app may have stopped between writing a line and the head.
                let one_ahead = last_entry.is_some_and(|e| e.seq == h.seq + 1 && e.prev == h.hash);
                if h.hash != hash && !one_ahead {
                    problems.push(Problem::at(
                        l,
                        last_entry.map(|e| e.seq),
                        &format!(
                            "The newest entries were changed or deleted. Last entry recorded: {}.",
                            h.seq
                        ),
                    ));
                }
            }
        }
        Ok(Integrity {
            entries: entries.len(),
            files: self.files()?.len(),
            problems,
        })
    }
}

/// `2026-10.jsonl` for a time in October 2026 (UTC).
fn file_for(t: DateTime<Utc>) -> String {
    format!("{:04}-{:02}.jsonl", t.year(), t.month())
}

fn month_of(name: &str) -> Option<NaiveDate> {
    let stem = name.strip_suffix(".jsonl")?;
    let (y, m) = stem.split_once('-')?;
    if y.len() != 4 || m.len() != 2 {
        return None;
    }
    NaiveDate::from_ymd_opt(y.parse().ok()?, m.parse().ok()?, 1)
}

/// The first moment after the month that starts at `first`.
fn month_end(first: NaiveDate) -> DateTime<Utc> {
    let next = first
        .checked_add_months(chrono::Months::new(1))
        .unwrap_or(first);
    Utc.from_utc_datetime(&next.and_hms_opt(0, 0, 0).unwrap())
}

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct Problem {
    /// Month file, empty for the folder as a whole.
    pub file: String,
    /// From 1; 0 when not about one line.
    pub line: usize,
    pub seq: Option<u64>,
    pub message: String,
}

impl Problem {
    fn at(l: &Line, seq: Option<u64>, message: &str) -> Problem {
        Problem {
            file: l.file.clone(),
            line: l.number,
            seq,
            message: message.to_string(),
        }
    }
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.file.is_empty() {
            write!(f, "{}", self.message)
        } else {
            write!(f, "{}, line {}: {}", self.file, self.line, self.message)
        }
    }
}

/// The result of [`History::check`].
#[derive(Serialize, Debug, Clone)]
pub struct Integrity {
    pub entries: usize,
    pub files: usize,
    pub problems: Vec<Problem>,
}

impl Integrity {
    pub fn ok(&self) -> bool {
        self.problems.is_empty()
    }

    pub fn summary(&self) -> String {
        if self.ok() {
            format!(
                "Intact: {} in {}, every link of the chain checked.",
                plural(self.entries, "entry"),
                plural(self.files, "file")
            )
        } else {
            format!(
                "NOT INTACT: {} found in {}.",
                plural(self.problems.len(), "problem"),
                plural(self.entries, "entry")
            )
        }
    }
}

// ------------------------------------------------------------ filters

/// What the History view and `trackmysign history` show.
#[derive(Default, Debug, Clone)]
pub struct Filter {
    pub since: Option<DateTime<Utc>>,
    /// Up to, not including.
    pub until: Option<DateTime<Utc>>,
    pub source: Option<Source>,
    pub outcome: Option<Outcome>,
    /// In the document's path, the signer's name or the PAN, any case.
    pub text: Option<String>,
}

impl Filter {
    pub fn matches(&self, e: &Entry) -> bool {
        if self.since.is_some_and(|t| e.time < t) || self.until.is_some_and(|t| e.time >= t) {
            return false;
        }
        // Notes about the history show unless a filter looks for signatures.
        if e.action.is_marker() {
            return self.source.is_none() && self.outcome.is_none() && self.text.is_none();
        }
        if self.source.is_some_and(|s| e.source != Some(s))
            || self.outcome.is_some_and(|o| e.outcome != Some(o))
        {
            return false;
        }
        match self.text.as_deref().map(str::trim) {
            None | Some("") => true,
            Some(q) => {
                let q = q.to_lowercase();
                [
                    e.input.as_ref().map(|f| f.path.as_str()),
                    e.output.as_ref().map(|f| f.path.as_str()),
                    e.cert.as_ref().map(|c| c.subject.as_str()),
                    e.cert.as_ref().and_then(|c| c.organization.as_deref()),
                    e.portal.as_ref().map(|p| p.pan.as_str()),
                    e.origin.as_deref(),
                ]
                .iter()
                .flatten()
                .any(|s| s.to_lowercase().contains(&q))
            }
        }
    }

    pub fn apply<'a>(&self, entries: &'a [Entry]) -> Vec<&'a Entry> {
        entries.iter().filter(|e| self.matches(e)).collect()
    }
}

// ------------------------------------------------------------ export

/// The outcome as a table shows it.
fn outcome_text(e: &Entry) -> String {
    match (e.outcome, &e.error) {
        (Some(Outcome::Signed), _) => "Signed".into(),
        (Some(Outcome::Failed), Some(r)) => format!("Failed: {r}"),
        (Some(Outcome::Failed), None) => "Failed".into(),
        (None, _) => match (e.action, e.removed) {
            (Action::Cleared | Action::Pruned, Some(n)) => {
                format!("{} deleted", plural(n as usize, "entry"))
            }
            _ => String::new(),
        },
    }
}

fn certify_text(level: u8) -> &'static str {
    match level {
        1 => "level 1, no changes allowed",
        2 => "level 2, form filling and signing allowed",
        _ => "level 3, form filling, signing and comments allowed",
    }
}

/// One row per entry. UTF-8 with a byte order mark and CRLF line ends, as
/// the folder CSV.
pub fn to_csv(entries: &[&Entry]) -> String {
    const HEADER: [&str; 27] = [
        "seq",
        "time_utc",
        "action",
        "source",
        "program",
        "outcome",
        "error",
        "document",
        "input_path",
        "input_sha256",
        "output_path",
        "output_sha256",
        "portal_origin",
        "portal_pan",
        "portal_kind",
        "portal_data",
        "portal_sha256",
        "signer",
        "issuer",
        "serial",
        "fingerprint",
        "pages",
        "field",
        "reason",
        "location",
        "certify",
        "timestamp_ltv",
    ];
    let mut out = String::from("\u{feff}");
    push_csv_row(&mut out, HEADER.iter().map(|s| s.to_string()));
    for e in entries {
        let file = |f: &Option<FileRef>| {
            f.as_ref().map_or((String::new(), String::new()), |f| {
                (f.path.clone(), f.sha256.clone().unwrap_or_default())
            })
        };
        let (input, input_hash) = file(&e.input);
        let (output, output_hash) = file(&e.output);
        let p = e.portal.as_ref();
        let c = e.cert.as_ref();
        let opt = |s: Option<&str>| s.unwrap_or_default().to_string();
        let row = [
            e.seq.to_string(),
            e.time.to_rfc3339_opts(SecondsFormat::Secs, true),
            e.action.key().to_string(),
            e.source.map(|s| s.key().to_string()).unwrap_or_default(),
            e.program.clone(),
            e.outcome.map(|o| o.key().to_string()).unwrap_or_default(),
            opt(e.error.as_deref()),
            if e.action.is_marker() {
                String::new()
            } else {
                e.document()
            },
            input,
            input_hash,
            output,
            output_hash,
            opt(e.origin.as_deref()),
            opt(p.map(|p| p.pan.as_str())),
            opt(p.map(|p| p.kind.as_str())),
            opt(p.and_then(|p| p.data.as_deref())),
            opt(p.map(|p| p.sha256.as_str())),
            opt(c.map(|c| c.subject.as_str())),
            opt(c.map(|c| c.issuer.as_str())),
            opt(c.map(|c| c.serial.as_str())),
            opt(c.map(|c| c.fingerprint.as_str())),
            e.pages
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(" "),
            opt(e.field.as_deref()),
            opt(e.reason.as_deref()),
            opt(e.location.as_deref()),
            e.certify.map(|l| l.to_string()).unwrap_or_default(),
            timestamp_ltv(e),
        ];
        push_csv_row(&mut out, row.into_iter());
    }
    out
}

fn timestamp_ltv(e: &Entry) -> String {
    match (&e.timestamp, e.ltv) {
        (Some(url), true) => format!("timestamp ({url}), LTV"),
        (Some(url), false) => format!("timestamp ({url})"),
        (None, true) => "LTV".into(),
        (None, false) => String::new(),
    }
}

/// The JSON `trackmysign history --json` prints.
pub fn to_json(entries: &[&Entry], integrity: &Integrity, version: &str) -> String {
    #[derive(Serialize)]
    struct Out<'a> {
        schema: &'static str,
        schema_version: u32,
        generator: String,
        integrity: &'a Integrity,
        entries: &'a [&'a Entry],
    }
    serde_json::to_string_pretty(&Out {
        schema: "trackmysign-history",
        schema_version: SCHEMA_VERSION,
        generator: format!("TrackMySign {version}"),
        integrity,
        entries,
    })
    .unwrap_or_default()
}

/// "Signing history" as an A4 PDF: a table of the entries, then each one
/// with its hashes and certificate.
pub fn to_pdf(
    entries: &[&Entry],
    scope: &str,
    integrity: Option<&Integrity>,
    version: &str,
    now: DateTime<Utc>,
) -> Vec<u8> {
    let title = Style::new(Face::Bold, 18.0, INK);
    let heading = Style::new(Face::Bold, 11.0, INK);
    let label = Style::new(Face::Regular, 9.0, MUTED);
    let value = Style::new(Face::Regular, 9.5, INK);
    let head = Style::new(Face::Bold, 8.5, MUTED);
    let cell = Style::new(Face::Regular, 8.5, INK);
    let small_label = Style::new(Face::Regular, 8.0, MUTED);
    let small = Style::new(Face::Regular, 8.5, INK);
    const LABEL_WIDTH: f64 = 128.0;
    const DETAIL_LABEL_WIDTH: f64 = 116.0;
    let tone = |e: &Entry| match e.outcome {
        Some(Outcome::Signed) => OK,
        Some(Outcome::Failed) => BAD,
        None => MUTED,
    };

    let mut d = TextDoc::new(&format!(
        "Generated by TrackMySign v{version} from the signing history kept on this computer. \
         It lists what this computer recorded; it does not check the signatures in the files."
    ));
    d.paragraph("Signing history", title);
    d.rule(1.5, ACCENT, 8.0);
    let signed = entries
        .iter()
        .filter(|e| e.outcome == Some(Outcome::Signed))
        .count();
    let failed = entries
        .iter()
        .filter(|e| e.outcome == Some(Outcome::Failed))
        .count();
    d.paragraph(
        &format!("{} signed, {} failed", signed, failed),
        Style::new(Face::Bold, 11.0, INK),
    );
    d.space(10.0);
    let mut rows = vec![
        ("Showing", scope.to_string()),
        ("Entries", entries.len().to_string()),
        ("Exported", ist_and_utc(now)),
    ];
    if let Some(i) = integrity {
        rows.push(("Log integrity", i.summary()));
    }
    for (k, v) in &rows {
        let style = match (*k, integrity) {
            ("Log integrity", Some(i)) => Style {
                color: if i.ok() { OK } else { BAD },
                ..value
            },
            _ => value,
        };
        d.row(k, label, v, style, LABEL_WIDTH);
    }
    if let Some(i) = integrity {
        for p in &i.problems {
            d.row(
                "",
                label,
                &p.to_string(),
                Style {
                    color: BAD,
                    ..value
                },
                LABEL_WIDTH,
            );
        }
    }

    if !entries.is_empty() {
        d.space(10.0);
        d.paragraph("Entries", heading);
        d.space(3.0);
        let w = TextDoc::width();
        let widths = [w * 0.07, w * 0.19, w * 0.27, w * 0.16, w * 0.18, w * 0.13];
        let table_row = |d: &mut TextDoc, cells: [(&str, Style); 6]| {
            let cells: Vec<(&str, f64, Style)> = cells
                .iter()
                .zip(widths)
                .map(|(&(text, style), width)| (text, width, style))
                .collect();
            d.columns(&cells);
        };
        table_row(
            &mut d,
            [
                ("No.", head),
                ("Date (IST)", head),
                ("Document", head),
                ("Action", head),
                ("Certificate", head),
                ("Outcome", head),
            ],
        );
        d.rule(0.5, LINE, 2.0);
        for e in entries {
            let ist = e
                .time
                .with_timezone(&chrono::FixedOffset::east_opt(5 * 3600 + 30 * 60).unwrap())
                .format("%d %b %Y %H:%M")
                .to_string();
            let action = match e.source {
                Some(s) => format!("{} ({})", e.action.label(), s.label()),
                None => e.action.label().to_string(),
            };
            let cert = e
                .cert
                .as_ref()
                .map(|c| shown(&c.subject))
                .unwrap_or_default();
            let outcome = match e.outcome {
                Some(Outcome::Signed) => "Signed".to_string(),
                Some(Outcome::Failed) => "Failed".to_string(),
                None => outcome_text(e),
            };
            table_row(
                &mut d,
                [
                    (&e.seq.to_string(), cell),
                    (&ist, cell),
                    (&shown(&e.document()), cell),
                    (&action, cell),
                    (&cert, cell),
                    (
                        &outcome,
                        Style {
                            color: tone(e),
                            ..cell
                        },
                    ),
                ],
            );
            d.rule(0.25, LINE, 1.5);
        }
    }

    let signatures: Vec<&&Entry> = entries.iter().filter(|e| !e.action.is_marker()).collect();
    if !signatures.is_empty() {
        d.keep(160.0);
        d.space(14.0);
        d.paragraph("Appendix: each entry", heading);
    }
    for e in signatures {
        d.keep(90.0);
        d.rule(0.5, LINE, 8.0);
        d.paragraph(
            &format!("{}. {}", e.seq, shown(&e.document())),
            Style::new(Face::Bold, 10.0, INK),
        );
        d.space(2.0);
        let mut rows: Vec<(&str, String)> = vec![("Time", ist_and_utc(e.time))];
        rows.push(("Outcome", outcome_text(e)));
        let mut action = e.action.label().to_string();
        if let Some(s) = e.source {
            action = format!("{action}, {}", s.label());
        }
        rows.push(("Action", action));
        rows.push(("Program", format!("TrackMySign {}", e.program)));
        if let Some(o) = &e.origin {
            rows.push(("Requested by", o.clone()));
        }
        if let Some(f) = &e.input {
            rows.push(("Original", shown(&f.path)));
            if let Some(h) = &f.sha256 {
                rows.push(("Original SHA-256", h.clone()));
            }
        }
        if let Some(f) = &e.output {
            rows.push(("Signed copy", shown(&f.path)));
            if let Some(h) = &f.sha256 {
                rows.push(("Signed SHA-256", h.clone()));
            }
        }
        if let Some(p) = &e.portal {
            rows.push(("PAN requested", p.pan.clone()));
            if let Some(v) = &p.data {
                rows.push(("Signed data", v.clone()));
            }
            rows.push(("Signed data SHA-256", p.sha256.clone()));
        }
        if let Some(c) = &e.cert {
            let org = c
                .organization
                .as_ref()
                .map(|o| format!(" ({})", shown(o)))
                .unwrap_or_default();
            rows.push(("Signer", format!("{}{org}", shown(&c.subject))));
            rows.push(("Issuer", shown(&c.issuer)));
            rows.push(("Serial number", c.serial.clone()));
            rows.push(("Fingerprint", c.fingerprint.clone()));
        }
        if !e.pages.is_empty() {
            let pages: Vec<String> = e.pages.iter().map(|p| p.to_string()).collect();
            rows.push(("Pages", pages.join(", ")));
        }
        if let Some(f) = &e.field {
            rows.push(("Field", shown(f)));
        }
        if let Some(v) = &e.reason {
            rows.push(("Reason", shown(v)));
        }
        if let Some(v) = &e.location {
            rows.push(("Location", shown(v)));
        }
        if let Some(l) = e.certify {
            rows.push(("Certification", certify_text(l).into()));
        }
        let extras = timestamp_ltv(e);
        if !extras.is_empty() {
            rows.push(("Timestamp / LTV", extras));
        }
        for (k, v) in &rows {
            let style = if *k == "Outcome" {
                Style {
                    color: tone(e),
                    ..small
                }
            } else {
                small
            };
            d.row(k, small_label, v, style, DETAIL_LABEL_WIDTH);
        }
    }
    d.finish("Signing history", &format!("TrackMySign {version}"), now)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROGRAM: &str = "cli 0.0.0";

    fn temp(name: &str) -> History {
        let dir = std::env::temp_dir().join(format!("tms-history-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        History::new(dir)
    }

    fn at(y: i32, m: u32, d: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, 10, 0, 0).unwrap()
    }

    fn signed(name: &str, source: Source) -> Entry {
        let req = SignRequest {
            page: 1,
            rect: Some(crate::DisplayRect {
                x: 0.0,
                y: 0.0,
                w: 10.0,
                h: 10.0,
            }),
            reason: Some("Approved".into()),
            ..Default::default()
        };
        let mut e = Entry::signing(source, PROGRAM, Path::new(&format!("/d/{name}")), &req);
        e.input_data(name.as_bytes());
        e.cert = Some(CertRef {
            subject: "DK RAHUL".into(),
            organization: None,
            issuer: "Test CA".into(),
            serial: "01".into(),
            fingerprint: "ab".into(),
        });
        e.signed(Path::new(&format!("/d/{name}.signed")), b"signed")
    }

    fn rewrite(h: &History, file: &str, f: impl Fn(Vec<String>) -> Vec<String>) {
        let path = h.dir().join(file);
        let lines: Vec<String> = fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect();
        let mut out = f(lines).join("\n");
        out.push('\n');
        fs::write(path, out).unwrap();
    }

    #[test]
    fn appends_and_chains() {
        let h = temp("append");
        assert!(
            h.record_at(signed("a.pdf", Source::Manual), at(2026, 10, 1))
                .unwrap()
        );
        assert!(
            h.record_at(signed("b.pdf", Source::Batch), at(2026, 10, 2))
                .unwrap()
        );
        let entries = h.entries().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!((entries[0].seq, entries[1].seq), (1, 2));
        assert_eq!(entries[0].prev, GENESIS);
        assert_eq!(entries[0].pages, [2]);
        assert_eq!(
            entries[0].input.as_ref().unwrap().sha256,
            Some(sha256_hex(b"a.pdf"))
        );
        assert_eq!(
            entries[1].output.as_ref().unwrap().sha256,
            Some(sha256_hex(b"signed"))
        );
        let text = fs::read_to_string(h.dir().join("2026-10.jsonl")).unwrap();
        let first = text.lines().next().unwrap();
        assert_eq!(entries[1].prev, sha256_hex(first.as_bytes()));
        let i = h.check().unwrap();
        assert!(i.ok(), "{:?}", i.problems);
        assert_eq!((i.entries, i.files), (2, 1));
        // Never a PIN or a password.
        assert!(!text.to_lowercase().contains("pin\""));
        assert!(!text.contains("password"));
        fs::remove_dir_all(h.dir()).unwrap();
    }

    #[test]
    fn edited_line_is_found() {
        let h = temp("edit");
        for (i, n) in ["a.pdf", "b.pdf", "c.pdf"].iter().enumerate() {
            h.record_at(signed(n, Source::Manual), at(2026, 10, i as u32 + 1))
                .unwrap();
        }
        rewrite(&h, "2026-10.jsonl", |mut l| {
            l[1] = l[1].replace("b.pdf", "x.pdf");
            l
        });
        let i = h.check().unwrap();
        assert_eq!(i.problems.len(), 1, "{:?}", i.problems);
        assert_eq!((i.problems[0].line, i.problems[0].seq), (3, Some(3)));
        assert!(i.summary().starts_with("NOT INTACT"));
        fs::remove_dir_all(h.dir()).unwrap();
    }

    #[test]
    fn deleted_lines_are_found() {
        let h = temp("delete");
        for d in 1..=4 {
            h.record_at(signed("a.pdf", Source::Manual), at(2026, 10, d))
                .unwrap();
        }
        // A line in the middle.
        rewrite(&h, "2026-10.jsonl", |mut l| {
            l.remove(1);
            l
        });
        assert!(!h.check().unwrap().ok());
        fs::remove_dir_all(h.dir()).unwrap();

        let h = temp("delete-tail");
        for d in 1..=4 {
            h.record_at(signed("a.pdf", Source::Manual), at(2026, 10, d))
                .unwrap();
        }
        // The newest line.
        rewrite(&h, "2026-10.jsonl", |mut l| {
            l.pop();
            l
        });
        let i = h.check().unwrap();
        assert_eq!(i.problems.len(), 1);
        assert!(i.problems[0].message.contains("newest"));
        // Writing again does not hide it: the numbers jump.
        h.record_at(signed("b.pdf", Source::Manual), at(2026, 10, 5))
            .unwrap();
        let i = h.check().unwrap();
        assert!(
            i.problems[0]
                .message
                .ends_with("missing before this one: 4 to 4."),
            "{:?}",
            i.problems
        );
        fs::remove_dir_all(h.dir()).unwrap();
    }

    #[test]
    fn monthly_files_chain_across() {
        let h = temp("rotate");
        h.record_at(signed("a.pdf", Source::Manual), at(2026, 9, 30))
            .unwrap();
        h.record_at(signed("b.pdf", Source::Watch), at(2026, 10, 1))
            .unwrap();
        h.record_at(signed("c.pdf", Source::Watch), at(2026, 11, 1))
            .unwrap();
        assert_eq!(
            h.files().unwrap(),
            ["2026-09.jsonl", "2026-10.jsonl", "2026-11.jsonl"]
        );
        assert!(h.check().unwrap().ok());
        // Deleting a whole month shows.
        fs::remove_file(h.dir().join("2026-10.jsonl")).unwrap();
        assert!(!h.check().unwrap().ok());
        // ... and so does deleting the oldest one.
        let h2 = temp("rotate-oldest");
        h2.record_at(signed("a.pdf", Source::Manual), at(2026, 9, 30))
            .unwrap();
        h2.record_at(signed("b.pdf", Source::Manual), at(2026, 10, 1))
            .unwrap();
        fs::remove_file(h2.dir().join("2026-09.jsonl")).unwrap();
        let i = h2.check().unwrap();
        assert!(
            i.problems[0]
                .message
                .contains("before this one were deleted")
        );
        fs::remove_dir_all(h.dir()).unwrap();
        fs::remove_dir_all(h2.dir()).unwrap();
    }

    #[test]
    fn retention_deletes_old_months_and_keeps_the_chain() {
        let h = temp("retention");
        h.record_at(signed("a.pdf", Source::Manual), at(2026, 1, 10))
            .unwrap();
        h.record_at(signed("b.pdf", Source::Manual), at(2026, 2, 10))
            .unwrap();
        let s = Settings {
            enabled: true,
            retention: Retention::Days90,
        };
        fs::write(h.dir().join(SETTINGS), serde_json::to_vec(&s).unwrap()).unwrap();
        // 90 days before 20 May is 19 Feb: January has ended by then,
        // February has not.
        h.record_at(signed("c.pdf", Source::Manual), at(2026, 5, 20))
            .unwrap();
        assert_eq!(h.files().unwrap(), ["2026-02.jsonl", "2026-05.jsonl"]);
        h.record_at(signed("d.pdf", Source::Manual), at(2026, 6, 20))
            .unwrap();
        assert_eq!(h.files().unwrap(), ["2026-05.jsonl", "2026-06.jsonl"]);
        let entries = h.entries().unwrap();
        let pruned: Vec<&Entry> = entries
            .iter()
            .filter(|e| e.action == Action::Pruned)
            .collect();
        assert_eq!(pruned.len(), 2);
        assert_eq!(pruned[0].removed, Some(1));
        let i = h.check().unwrap();
        assert!(i.ok(), "{:?}", i.problems);
        // Forever keeps everything.
        h.set_settings(Settings::default(), PROGRAM).unwrap();
        h.record_at(signed("f.pdf", Source::Manual), at(2030, 1, 1))
            .unwrap();
        assert_eq!(h.files().unwrap().len(), 3);
        assert!(h.check().unwrap().ok());
        fs::remove_dir_all(h.dir()).unwrap();
    }

    #[test]
    fn retention_of_everything_still_verifies() {
        let h = temp("retention-all");
        h.record_at(signed("a.pdf", Source::Manual), at(2025, 1, 10))
            .unwrap();
        let s = Settings {
            enabled: true,
            retention: Retention::Year,
        };
        fs::write(h.dir().join(SETTINGS), serde_json::to_vec(&s).unwrap()).unwrap();
        h.record_at(signed("b.pdf", Source::Manual), at(2026, 10, 1))
            .unwrap();
        assert_eq!(h.files().unwrap(), ["2026-10.jsonl"]);
        let entries = h.entries().unwrap();
        assert_eq!(entries[0].action, Action::Pruned);
        assert_eq!(entries[0].seq, 2);
        assert_eq!(entries[1].seq, 3);
        assert!(h.check().unwrap().ok());
        fs::remove_dir_all(h.dir()).unwrap();
    }

    #[test]
    fn clear_leaves_a_note() {
        let h = temp("clear");
        for d in 1..=3 {
            h.record_at(signed("a.pdf", Source::Manual), at(2026, 9, d))
                .unwrap();
        }
        assert_eq!(h.clear(PROGRAM).unwrap(), 3);
        let entries = h.entries().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action, Action::Cleared);
        assert_eq!((entries[0].seq, entries[0].removed), (4, Some(3)));
        h.record(signed("b.pdf", Source::Manual)).unwrap();
        assert!(h.check().unwrap().ok());
        fs::remove_dir_all(h.dir()).unwrap();
    }

    #[test]
    fn turned_off_records_nothing() {
        let h = temp("off");
        h.record(signed("a.pdf", Source::Manual)).unwrap();
        let off = Settings {
            enabled: false,
            ..Default::default()
        };
        h.set_settings(off, PROGRAM).unwrap();
        assert!(!h.record(signed("b.pdf", Source::Manual)).unwrap());
        h.set_settings(Settings::default(), PROGRAM).unwrap();
        let actions: Vec<Action> = h.entries().unwrap().iter().map(|e| e.action).collect();
        assert_eq!(actions, [Action::Sign, Action::Paused, Action::Resumed]);
        assert!(h.check().unwrap().ok());
        assert_eq!(temp("none").settings(), Settings::default());
        fs::remove_dir_all(h.dir()).unwrap();
    }

    #[test]
    fn filters() {
        let mut a = signed("Invoice-7.pdf", Source::Manual);
        a.time = at(2026, 10, 1);
        let mut b = signed("b.pdf", Source::Watch).failed("Wrong PIN.");
        b.time = at(2026, 10, 5);
        let mut c = Entry::new(Action::Cleared, None, PROGRAM);
        c.time = at(2026, 10, 3);
        let mut p = Entry::new(Action::PortalSign, Some(Source::Portal), PROGRAM);
        p.portal = Some(PortalRef::new("ABCDE1234F", "text", "secret text"));
        p.time = at(2026, 10, 4);
        let all = [a, b, c, p];
        let pick =
            |f: Filter| -> Vec<u64> { f.apply(&all).iter().map(|e| e.time.day() as u64).collect() };
        assert_eq!(pick(Filter::default()), [1, 5, 3, 4]);
        let since = Filter {
            since: Some(at(2026, 10, 3)),
            until: Some(at(2026, 10, 5)),
            ..Default::default()
        };
        assert_eq!(pick(since), [3, 4]);
        let watch = Filter {
            source: Some(Source::Watch),
            ..Default::default()
        };
        assert_eq!(pick(watch), [5]);
        let failed = Filter {
            outcome: Some(Outcome::Failed),
            ..Default::default()
        };
        assert_eq!(pick(failed), [5]);
        let text = |q: &str| Filter {
            text: Some(q.into()),
            ..Default::default()
        };
        assert_eq!(pick(text("invoice")), [1]);
        assert_eq!(pick(text("dk rahul")), [1, 5]);
        assert_eq!(pick(text("abcde1234f")), [4]);
        // Text is hashed, not kept.
        assert!(all[3].portal.as_ref().unwrap().data.is_none());
        assert_eq!(Source::parse("watch"), Some(Source::Watch));
        assert_eq!(Outcome::parse("failed"), Some(Outcome::Failed));
    }

    #[test]
    fn exports() {
        let mut a = signed("=cmd.pdf", Source::Manual);
        a.seq = 1;
        let b = Entry::new(Action::Cleared, None, PROGRAM);
        let entries = [&a, &b];
        let csv = to_csv(&entries);
        assert!(csv.starts_with("\u{feff}seq,time_utc,action,"));
        let lines: Vec<&str> = csv.trim_end().split("\r\n").collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[1].contains(",'=cmd.pdf,"), "{}", lines[1]);
        assert!(lines[1].contains(&sha256_hex(b"signed")));
        let i = Integrity {
            entries: 2,
            files: 1,
            problems: Vec::new(),
        };
        let pdf = to_pdf(&entries, "All entries", Some(&i), "0.0.0", Utc::now());
        assert!(pdf.starts_with(b"%PDF-"));
        let json: serde_json::Value =
            serde_json::from_str(&to_json(&entries, &i, "0.0.0")).unwrap();
        assert_eq!(json["schema"], "trackmysign-history");
        assert_eq!(
            json["entries"][0]["output"]["sha256"],
            sha256_hex(b"signed")
        );
    }

    #[test]
    fn watch_entries() {
        let req = SignRequest::default();
        let mut r = WatchRecorder::new(PROGRAM);
        r.signing(b"in", &req, b"not a certificate", &Ok(b"out".to_vec()));
        let e = r
            .event(&watch::Event::Signed {
                input: "/w/a.pdf".into(),
                output: "/w/signed/a_signed.pdf".into(),
                moved: None,
                warning: None,
            })
            .unwrap();
        assert_eq!(
            (e.source, e.outcome),
            (Some(Source::Watch), Some(Outcome::Signed))
        );
        assert_eq!(
            e.input.unwrap(),
            FileRef {
                path: "/w/a.pdf".into(),
                sha256: Some(sha256_hex(b"in"))
            }
        );
        assert_eq!(e.output.unwrap().sha256, Some(sha256_hex(b"out")));
        // A file that was never signed.
        let e = r
            .event(&watch::Event::Failed {
                input: "/w/b.pdf".into(),
                moved: None,
                reason: "Not a valid PDF.".into(),
            })
            .unwrap();
        assert_eq!(e.input.unwrap().path, "/w/b.pdf");
        assert_eq!(e.error.as_deref(), Some("Not a valid PDF."));
        assert!(
            r.event(&watch::Event::Skipped {
                input: "/w/c.pdf".into(),
                reason: String::new()
            })
            .is_none()
        );
        // The PIN refused midway stops the watch without an event.
        r.signing(b"in", &req, b"", &Err(crate::Error::PinLocked));
        let e = r
            .stopped(
                Path::new("/w"),
                &watch::Stop::Token(crate::Error::PinLocked),
            )
            .unwrap();
        assert_eq!(e.outcome, Some(Outcome::Failed));
        assert!(
            r.stopped(Path::new("/w"), &watch::Stop::Requested)
                .is_none()
        );
    }

    #[test]
    fn clock_set_back_stays_in_order() {
        let h = temp("clock");
        h.record_at(signed("a.pdf", Source::Manual), at(2026, 11, 2))
            .unwrap();
        h.record_at(signed("b.pdf", Source::Manual), at(2026, 10, 30))
            .unwrap();
        assert_eq!(h.files().unwrap(), ["2026-11.jsonl"]);
        assert!(h.check().unwrap().ok());
        fs::remove_dir_all(h.dir()).unwrap();
    }

    #[test]
    fn month_files() {
        assert_eq!(file_for(at(2026, 3, 31)), "2026-03.jsonl");
        assert_eq!(
            month_of("2026-03.jsonl"),
            NaiveDate::from_ymd_opt(2026, 3, 1)
        );
        assert_eq!(month_of("head.json"), None);
        assert_eq!(month_of("2026-3.jsonl"), None);
        assert_eq!(
            month_end(NaiveDate::from_ymd_opt(2026, 12, 1).unwrap()),
            Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap()
        );
    }
}
