//! Watch folder: PDFs put into a folder are signed one at a time, without a
//! click per document, while a signing session is open.
//!
//! Anyone who can write to the folder can get a document signed, so the
//! caller opens the session only after the user enters the PIN, and it ends
//! on a time limit, a daily limit, sleep, or the first token or PIN error.
//! A file is picked up once its size and modification time have not changed
//! for a while and it opens as a PDF. The signed copy goes to the output
//! folder (never overwriting), the original to `done` (optional) and a file
//! that cannot be signed to `failed`, with a `.txt` saying why.

use std::collections::{HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime};

use chrono::{Local, NaiveDate};
use notify_debouncer_mini::new_debouncer;
use notify_debouncer_mini::notify::RecursiveMode;
use serde::{Deserialize, Serialize};

use crate::pdf::reader::PdfError;
use crate::{
    DisplayRect, Error, ImagePosition, PdfInfo, SignRequest, StampImage, check_permitted, inspect,
    parse_pages, write_signed_in,
};

/// Default folder names inside the watched folder.
pub const SIGNED_DIR: &str = "signed";
pub const DONE_DIR: &str = "done";
pub const FAILED_DIR: &str = "failed";

/// Default cap on files signed per day.
pub const DEFAULT_DAILY_LIMIT: usize = 200;

/// The watched folder and where files go from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Folders {
    pub input: PathBuf,
    pub output: PathBuf,
    /// Originals are moved here after signing; left in place when `None`.
    pub done: Option<PathBuf>,
    pub failed: PathBuf,
}

/// An absolute path with `.` and `..` resolved, also for a folder that does
/// not exist yet.
fn normalize(path: &Path) -> io::Result<PathBuf> {
    if let Ok(p) = path.canonicalize() {
        return Ok(p);
    }
    let mut abs = PathBuf::new();
    for c in std::path::absolute(path)?.components() {
        match c {
            std::path::Component::ParentDir => {
                abs.pop();
            }
            std::path::Component::CurDir => {}
            c => abs.push(c),
        }
    }
    // The nearest existing ancestor resolved (links, case), then the rest.
    let mut rest = Vec::new();
    let mut base = abs.as_path();
    while !base.exists() {
        match (base.parent(), base.file_name()) {
            (Some(parent), Some(name)) => {
                rest.push(name);
                base = parent;
            }
            _ => break,
        }
    }
    let mut out = base.canonicalize().unwrap_or_else(|_| base.to_path_buf());
    out.extend(rest.into_iter().rev());
    Ok(out)
}

fn same(a: &Path, b: &Path) -> bool {
    if cfg!(any(windows, target_os = "macos")) {
        a.to_string_lossy().to_lowercase() == b.to_string_lossy().to_lowercase()
    } else {
        a == b
    }
}

fn inside(path: &Path, dir: &Path) -> bool {
    path.ancestors().skip(1).any(|a| same(a, dir))
}

impl Folders {
    /// Checks the folders: `output` defaults to `<input>/signed` and must not
    /// be the watched folder or anywhere else inside it, so signed copies are
    /// never picked up again.
    pub fn new(input: &Path, output: Option<&Path>, move_done: bool) -> Result<Self, String> {
        if !input.is_dir() {
            return Err(format!("The folder {} does not exist.", input.display()));
        }
        let input = normalize(input).map_err(|e| e.to_string())?;
        let signed = input.join(SIGNED_DIR);
        let output = match output {
            Some(o) => normalize(o).map_err(|e| e.to_string())?,
            None => signed.clone(),
        };
        if same(&output, &input) {
            return Err(
                "Signed copies cannot go into the watched folder itself: they would be \
                 signed again. Choose another folder, or leave it empty for the \"signed\" \
                 folder inside it."
                    .into(),
            );
        }
        if inside(&output, &input) && !same(&output, &signed) {
            return Err(format!(
                "Inside the watched folder, signed copies can only go to its \"{SIGNED_DIR}\" \
                 folder. Choose a folder outside it."
            ));
        }
        if inside(&input, &output) || same(&input, &output) {
            return Err("The watched folder cannot be inside the folder for signed copies.".into());
        }
        Ok(Folders {
            done: move_done.then(|| input.join(DONE_DIR)),
            failed: input.join(FAILED_DIR),
            output,
            input,
        })
    }

    pub fn create(&self) -> io::Result<()> {
        std::fs::create_dir_all(&self.output)?;
        if let Some(d) = &self.done {
            std::fs::create_dir_all(d)?;
        }
        std::fs::create_dir_all(&self.failed)
    }
}

/// Temporary and partial files that browsers, Office and copy tools leave
/// while a file is still being written, and hidden files.
pub fn ignored(name: &str) -> bool {
    let lower = name.to_lowercase();
    name.starts_with("~$")
        || name.starts_with('.')
        || [".tmp", ".crdownload", ".part", ".partial", ".download"]
            .iter()
            .any(|ext| lower.ends_with(ext))
}

/// A file the watcher looks at: a PDF by name that is not a temporary file.
pub fn is_candidate(name: &str) -> bool {
    !ignored(name) && name.to_lowercase().ends_with(".pdf")
}

/// `name.pdf` in `dir`, or `name_2.pdf`, `name_3.pdf`, … if taken.
pub fn free_path_in(dir: &Path, file: &Path) -> PathBuf {
    let stem = file
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "document".into());
    let ext = file
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    let first = dir.join(format!("{stem}{ext}"));
    if !first.exists() {
        return first;
    }
    (2..)
        .map(|n| dir.join(format!("{stem}_{n}{ext}")))
        .find(|p| !p.exists())
        .unwrap()
}

/// Moves `file` into `dir` without replacing anything there; returns the new path.
pub fn move_into(file: &Path, dir: &Path) -> io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    loop {
        let dest = free_path_in(dir, file);
        // A hard link fails if the name was taken meanwhile; a plain rename
        // would replace it. Not every file system has hard links.
        match std::fs::hard_link(file, &dest) {
            Ok(()) => {
                std::fs::remove_file(file)?;
                return Ok(dest);
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(_) if dest.exists() => continue,
            Err(_) => {
                std::fs::rename(file, &dest)?;
                return Ok(dest);
            }
        }
    }
}

/// Which page the box goes on, as saved in a preset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PageChoice {
    Named(NamedPage),
    /// 1 = first.
    Number(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NamedPage {
    First,
    Last,
}

impl PageChoice {
    /// Zero-based page in a document of `pages` pages (at least one).
    pub fn resolve(self, pages: usize) -> usize {
        match self {
            PageChoice::Named(NamedPage::First) => 0,
            PageChoice::Named(NamedPage::Last) => pages - 1,
            PageChoice::Number(n) => n.saturating_sub(1).min(pages - 1),
        }
    }
}

/// The box of a preset, in millimetres from the top-left of the page.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct BoxPlacement {
    pub page: PageChoice,
    pub x: f64,
    pub y: f64,
    pub w: f64,
    pub h: f64,
}

/// Whether the handwritten signature image is shown, and where.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ImageChoice {
    #[default]
    Off,
    Left,
    Above,
}

const PT_PER_MM: f64 = 72.0 / 25.4;
const BOX_W: f64 = 170.0;
const BOX_H: f64 = 55.0;
const BOX_MARGIN: f64 = 36.0;

/// How each file is signed: a saved preset of the desktop app (same JSON)
/// plus the options a watch folder allows. Certifying is not one of them.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Preset {
    pub name: String,
    pub reason: String,
    pub location: String,
    /// Bottom-right corner of the last page when unset.
    pub placement: Option<BoxPlacement>,
    /// More pages with the box: `all` or a list such as `1-3,5`; pages a
    /// file does not have are left out. Empty for just the placement's page.
    pub pages: String,
    pub image: ImageChoice,
    pub invisible: bool,
    /// RFC 3161 server; off by default (needs the internet).
    pub timestamp: Option<String>,
    pub ltv: bool,
}

impl Preset {
    /// Checks what can be checked without a document.
    pub fn validate(&self) -> Result<(), String> {
        let spec = self.pages.trim();
        if !spec.is_empty() && !spec.eq_ignore_ascii_case("all") {
            parse_pages(spec, usize::MAX).map_err(|e| format!("Pages: {e}"))?;
        }
        if let Some(p) = &self.placement
            && !(p.w > 0.0 && p.h > 0.0)
        {
            return Err("The signature box has no size.".into());
        }
        if let Some(url) = &self.timestamp
            && !url.starts_with("http://")
            && !url.starts_with("https://")
        {
            return Err(format!(
                "The timestamp server must be an http:// or https:// address, not {url:?}."
            ));
        }
        Ok(())
    }

    /// The request for one document; `image` is used when the preset shows it.
    pub fn request(&self, info: &PdfInfo, image: Option<&StampImage>) -> SignRequest {
        let count = info.pages.len().max(1);
        let text = |s: &str| Some(s.trim().to_string()).filter(|s| !s.is_empty());
        let (page, rect) = match &self.placement {
            Some(p) => {
                let page = p.page.resolve(count);
                (page, Some((p.x, p.y, p.w, p.h)))
            }
            None => (count - 1, None),
        };
        let rect = (!self.invisible).then(|| {
            let Some(s) = info.pages.get(page) else {
                return DisplayRect {
                    x: 0.0,
                    y: 0.0,
                    w: BOX_W,
                    h: BOX_H,
                };
            };
            match rect {
                // Kept inside the page, as the app does for a preset.
                Some((x, y, w, h)) => {
                    let w = (w * PT_PER_MM).min(s.width);
                    let h = (h * PT_PER_MM).min(s.height);
                    DisplayRect {
                        x: (x * PT_PER_MM).clamp(0.0, s.width - w),
                        y: (y * PT_PER_MM).clamp(0.0, s.height - h),
                        w,
                        h,
                    }
                }
                None => {
                    let w = BOX_W.min(s.width);
                    let h = BOX_H.min(s.height);
                    DisplayRect {
                        x: (s.width - w - BOX_MARGIN).max(0.0),
                        y: (s.height - h - BOX_MARGIN).max(0.0),
                        w,
                        h,
                    }
                }
            }
        });
        let pages = match self.pages.trim() {
            _ if self.invisible => Vec::new(),
            "" => Vec::new(),
            spec => parse_pages(spec, count)
                .or_else(|_| parse_pages(spec, usize::MAX))
                .unwrap_or_default()
                .into_iter()
                .filter(|p| *p < count)
                .collect(),
        };
        let image = match self.image {
            ImageChoice::Off => None,
            _ if self.invisible => None,
            _ => image.cloned(),
        };
        SignRequest {
            page,
            rect,
            pages,
            reason: text(&self.reason),
            location: text(&self.location),
            image,
            image_position: match self.image {
                ImageChoice::Above => ImagePosition::Above,
                _ => ImagePosition::Left,
            },
            timestamp: self.timestamp.as_deref().and_then(text),
            ltv: self.ltv,
            ..Default::default()
        }
    }
}

/// Size and modification time of each file seen, and since when they have
/// not changed.
#[derive(Default)]
pub struct Readiness {
    seen: HashMap<PathBuf, Seen>,
}

struct Seen {
    len: u64,
    modified: Option<SystemTime>,
    since: Instant,
}

impl Readiness {
    /// Records `path` as seen at `now`; returns how long it has been unchanged.
    pub fn observe(
        &mut self,
        path: &Path,
        len: u64,
        modified: Option<SystemTime>,
        now: Instant,
    ) -> Duration {
        match self.seen.get_mut(path) {
            Some(s) if s.len == len && s.modified == modified => {
                now.saturating_duration_since(s.since)
            }
            Some(s) => {
                *s = Seen {
                    len,
                    modified,
                    since: now,
                };
                Duration::ZERO
            }
            None => {
                self.seen.insert(
                    path.to_path_buf(),
                    Seen {
                        len,
                        modified,
                        since: now,
                    },
                );
                Duration::ZERO
            }
        }
    }

    /// Forgets files that are gone.
    pub fn retain(&mut self, present: &HashSet<PathBuf>) {
        self.seen.retain(|p, _| present.contains(p));
    }

    pub fn forget(&mut self, path: &Path) {
        self.seen.remove(path);
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

/// Stop requests and file-system changes, shared with the watcher thread.
#[derive(Default)]
pub struct Control {
    state: Mutex<Flags>,
    wake: Condvar,
}

#[derive(Default)]
struct Flags {
    stop: bool,
    changed: bool,
}

impl Control {
    fn flags(&self) -> std::sync::MutexGuard<'_, Flags> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Ends the session; the watcher returns within moments (after the file
    /// being signed, if any).
    pub fn stop(&self) {
        self.flags().stop = true;
        self.wake.notify_all();
    }

    pub fn is_stopped(&self) -> bool {
        self.flags().stop
    }

    fn changed(&self) {
        self.flags().changed = true;
        self.wake.notify_all();
    }

    /// Sleeps until `timeout`, a change in the folder or a stop.
    fn wait(&self, timeout: Duration) {
        let flags = self.flags();
        let (mut flags, _) = self
            .wake
            .wait_timeout_while(flags, timeout, |f| !f.stop && !f.changed)
            .unwrap_or_else(|p| p.into_inner());
        flags.changed = false;
    }
}

/// What happened to a file.
#[derive(Debug, Clone)]
pub enum Event {
    Signed {
        input: PathBuf,
        output: PathBuf,
        /// Where the original went, when originals are moved.
        moved: Option<PathBuf>,
        /// The original could not be moved (it is not signed again).
        warning: Option<String>,
    },
    Failed {
        input: PathBuf,
        /// The original, now in the `failed` folder (next to the `.txt`).
        moved: Option<PathBuf>,
        reason: String,
    },
    /// Left alone, reported once.
    Skipped { input: PathBuf, reason: String },
}

/// Why watching ended.
#[derive(Debug)]
pub enum Stop {
    Requested,
    TimeUp,
    /// The computer slept (a long gap between two checks).
    Slept,
    DailyLimit(usize),
    /// The token was removed or the PIN refused: the file stays where it is.
    Token(Error),
    /// The watched or output folder became unusable.
    Folder(String),
}

impl std::fmt::Display for Stop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Stop::Requested => write!(f, "Stopped."),
            Stop::TimeUp => write!(f, "The time limit was reached."),
            Stop::Slept => write!(f, "The computer went to sleep."),
            Stop::DailyLimit(n) => write!(f, "The daily limit of {n} signed files was reached."),
            Stop::Token(e) => write!(f, "{e}"),
            Stop::Folder(e) => write!(f, "{e}"),
        }
    }
}

/// The caller's side: signing with the open token session, and events.
pub trait Host {
    /// Signs one document (the app takes its token lock here).
    fn sign(&mut self, data: &[u8], req: &SignRequest) -> Result<Vec<u8>, Error>;
    /// Ok while the token session can sign.
    fn check(&mut self) -> Result<(), Error>;
    fn event(&mut self, event: Event);
}

#[derive(Debug, Clone)]
pub struct Options {
    /// A file must stay unchanged this long before it is read.
    pub settle: Duration,
    /// Folder rescan when no change is reported (network drives, missed events).
    pub rescan: Duration,
    pub daily_limit: Option<usize>,
    /// Files already signed today (from an earlier session's log).
    pub signed_today: usize,
    pub until: Option<SystemTime>,
    pub stop_on_sleep: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            settle: Duration::from_secs(2),
            rescan: Duration::from_secs(5),
            daily_limit: Some(DEFAULT_DAILY_LIMIT),
            signed_today: 0,
            until: None,
            stop_on_sleep: true,
        }
    }
}

/// A gap this much longer than the wait means the computer was asleep.
const SLEEP_GAP: Duration = Duration::from_secs(60);

/// Sets the `.txt` next to a file moved to `failed`.
fn write_reason(moved: &Path, original: &Path, reason: &str) -> io::Result<()> {
    let name = original
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let text = format!(
        "TrackMySign could not sign {name}.\n\nReason: {reason}\nTime: {}\n\n\
         The file was not changed. Fix the problem and put it back into the \
         watched folder to try again, or sign it in the app.\n",
        Local::now().format("%d %b %Y %H:%M:%S %:z"),
    );
    std::fs::write(moved.with_extension("txt"), text)
}

enum Outcome {
    Signed(PathBuf),
    /// Read failed or the file changed: look again later.
    NotReady,
    NotPdf(String),
    Failed(String),
    Fatal(Stop),
}

fn sign_file(
    path: &Path,
    len: u64,
    folders: &Folders,
    preset: &Preset,
    image: Option<&StampImage>,
    host: &mut dyn Host,
) -> Outcome {
    let Ok(data) = std::fs::read(path) else {
        return Outcome::NotReady;
    };
    if data.len() as u64 != len {
        return Outcome::NotReady;
    }
    // A copy that stalled midway can still parse (the reader repairs broken
    // cross-references), so the end must be there too.
    let tail = &data[data.len().saturating_sub(1024)..];
    if !tail.windows(5).any(|w| w == b"%%EOF") {
        return Outcome::NotPdf(
            "Not a valid PDF (it does not end like one; it may be incomplete).".into(),
        );
    }
    let info = match inspect(&data) {
        Ok(i) => i,
        Err(Error::Pdf(PdfError::PasswordRequired | PdfError::WrongPassword)) => {
            return Outcome::Failed(
                "The PDF needs a password to open. Sign it in the app, which asks for it.".into(),
            );
        }
        Err(e) => return Outcome::NotPdf(format!("Not a valid PDF ({e}).")),
    };
    if info.pages.is_empty() {
        return Outcome::Failed("The PDF has no pages.".into());
    }
    if !info.signing_allowed {
        return Outcome::Failed(format!(
            "{} Sign it in the app with the owner password.",
            PdfError::SigningNotAllowed
        ));
    }
    if let Err(e) = check_permitted(&data, None) {
        return Outcome::Failed(e.to_string());
    }
    let req = preset.request(&info, image);
    let signed = match host.sign(&data, &req) {
        Ok(s) => s,
        Err(e @ (Error::WrongPin { .. } | Error::PinLocked | Error::Token(_))) => {
            return Outcome::Fatal(Stop::Token(e));
        }
        Err(e) => return Outcome::Failed(e.to_string()),
    };
    match write_signed_in(path, &folders.output, &signed) {
        Ok(out) => Outcome::Signed(out),
        Err(e) => Outcome::Fatal(Stop::Folder(format!(
            "Could not save in {}: {e}",
            folders.output.display()
        ))),
    }
}

/// Lists the candidate files directly in `dir` (not in its folders).
fn scan(dir: &Path) -> io::Result<Vec<(PathBuf, u64, Option<SystemTime>)>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let Ok(entry) = entry else { continue };
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if !is_candidate(&name) {
            continue;
        }
        // Not followed: a link could point anywhere.
        let Ok(md) = std::fs::symlink_metadata(entry.path()) else {
            continue;
        };
        if md.is_file() {
            out.push((entry.path(), md.len(), md.modified().ok()));
        }
    }
    out.sort_by(|a, b| a.2.cmp(&b.2).then_with(|| a.0.cmp(&b.0)));
    Ok(out)
}

/// Watches `folders.input` until something in [`Stop`] happens.
pub fn run(
    folders: &Folders,
    preset: &Preset,
    image: Option<&StampImage>,
    opts: &Options,
    control: &Arc<Control>,
    host: &mut dyn Host,
) -> Stop {
    if let Err(e) = folders.create() {
        return Stop::Folder(format!("Could not create the folders: {e}"));
    }
    let wake = control.clone();
    let debouncer = new_debouncer(Duration::from_millis(300), move |_| wake.changed());
    // Without change events (some network drives) the rescan does the work.
    let (_debouncer, rescan) = match debouncer {
        Ok(mut d) => match d
            .watcher()
            .watch(&folders.input, RecursiveMode::NonRecursive)
        {
            Ok(()) => (Some(d), opts.rescan),
            Err(_) => (None, opts.rescan.min(Duration::from_secs(2))),
        },
        Err(_) => (None, opts.rescan.min(Duration::from_secs(2))),
    };
    let grace = (opts.settle * 5).max(Duration::from_secs(10));
    let mut ready = Readiness::default();
    // Originals left in place: signed already in this session, or skipped.
    let mut handled: HashSet<(PathBuf, u64, Option<SystemTime>)> = HashSet::new();
    let mut reported: HashSet<PathBuf> = HashSet::new();
    let mut day: NaiveDate = Local::now().date_naive();
    let mut today = opts.signed_today;
    let mut timeout = Duration::ZERO;
    loop {
        let before = SystemTime::now();
        control.wait(timeout);
        if control.is_stopped() {
            return Stop::Requested;
        }
        let now = SystemTime::now();
        if opts.stop_on_sleep
            && now.duration_since(before).unwrap_or_default() > timeout + SLEEP_GAP
        {
            return Stop::Slept;
        }
        if opts.until.is_some_and(|u| now >= u) {
            return Stop::TimeUp;
        }
        if let Err(e) = host.check() {
            return Stop::Token(e);
        }
        if Local::now().date_naive() != day {
            day = Local::now().date_naive();
            today = 0;
        }
        let files = match scan(&folders.input) {
            Ok(f) => f,
            Err(e) => {
                return Stop::Folder(format!(
                    "The watched folder {} is not available: {e}",
                    folders.input.display()
                ));
            }
        };
        ready.retain(&files.iter().map(|f| f.0.clone()).collect());
        let mut waiting = false;
        for (path, len, modified) in files {
            if handled.contains(&(path.clone(), len, modified)) {
                continue;
            }
            if folders.done.is_none() && folders.output.join(signed_name(&path)).exists() {
                handled.insert((path.clone(), len, modified));
                if reported.insert(path.clone()) {
                    host.event(Event::Skipped {
                        reason: "A signed copy is already in the output folder.".into(),
                        input: path,
                    });
                }
                continue;
            }
            let stable = ready.observe(&path, len, modified, Instant::now());
            if stable < opts.settle {
                waiting = true;
                continue;
            }
            if control.is_stopped() {
                return Stop::Requested;
            }
            let fail = |host: &mut dyn Host, reason: String| {
                let moved = move_into(&path, &folders.failed).ok();
                if let Some(m) = &moved {
                    let _ = write_reason(m, &path, &reason);
                }
                host.event(Event::Failed {
                    input: path.clone(),
                    moved,
                    reason,
                });
            };
            match sign_file(&path, len, folders, preset, image, host) {
                Outcome::Signed(output) => {
                    ready.forget(&path);
                    let (moved, warning) = match &folders.done {
                        Some(done) => match move_into(&path, done) {
                            Ok(m) => (Some(m), None),
                            Err(e) => {
                                handled.insert((path.clone(), len, modified));
                                (None, Some(format!("The original could not be moved: {e}")))
                            }
                        },
                        None => {
                            handled.insert((path.clone(), len, modified));
                            (None, None)
                        }
                    };
                    host.event(Event::Signed {
                        input: path.clone(),
                        output,
                        moved,
                        warning,
                    });
                    today += 1;
                    if let Some(limit) = opts.daily_limit
                        && today >= limit
                    {
                        return Stop::DailyLimit(limit);
                    }
                }
                Outcome::NotReady => waiting = true,
                Outcome::NotPdf(reason) if stable >= grace => {
                    ready.forget(&path);
                    fail(host, reason);
                }
                Outcome::NotPdf(_) => waiting = true,
                Outcome::Failed(reason) => {
                    ready.forget(&path);
                    fail(host, reason);
                }
                Outcome::Fatal(stop) => return stop,
            }
        }
        timeout = if waiting {
            Duration::from_millis(500)
        } else {
            rescan
        };
    }
}

/// `invoice.pdf` → `invoice_signed.pdf`, the first name a signed copy gets.
fn signed_name(path: &Path) -> String {
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "document".into());
    format!("{stem}_signed.pdf")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PageSize;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("tms-watch-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        normalize(&dir).unwrap()
    }

    #[test]
    fn temporary_files_are_ignored() {
        for name in [
            "~$report.pdf",
            ".hidden.pdf",
            "._invoice.pdf",
            "invoice.pdf.crdownload",
            "invoice.pdf.part",
            "invoice.PDF.tmp",
            "invoice.pdf.download",
            "notes.txt",
            "invoice",
        ] {
            assert!(!is_candidate(name), "{name}");
        }
        for name in ["invoice.pdf", "SCAN 01.PDF", "a.b.pdf", "~invoice.pdf"] {
            assert!(is_candidate(name), "{name}");
        }
        assert!(ignored("x.tmp") && ignored("~$x.docx") && !ignored("x.pdf"));
    }

    #[test]
    fn readiness_needs_an_unchanged_file() {
        let mut r = Readiness::default();
        let p = Path::new("/w/a.pdf");
        let t0 = Instant::now();
        let m = Some(SystemTime::UNIX_EPOCH);
        assert_eq!(r.observe(p, 10, m, t0), Duration::ZERO);
        let t1 = t0 + Duration::from_secs(1);
        assert_eq!(r.observe(p, 10, m, t1), Duration::from_secs(1));
        // Grew: the clock starts again.
        let t2 = t0 + Duration::from_secs(2);
        assert_eq!(r.observe(p, 20, m, t2), Duration::ZERO);
        let t3 = t0 + Duration::from_secs(5);
        assert_eq!(r.observe(p, 20, m, t3), Duration::from_secs(3));
        // Same size, touched again.
        let m2 = Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1));
        assert_eq!(r.observe(p, 20, m2, t3), Duration::ZERO);
        r.retain(&HashSet::new());
        assert!(r.is_empty());
        assert_eq!(r.observe(p, 20, m2, t3), Duration::ZERO);
    }

    #[test]
    fn output_folder_rules() {
        let input = temp("rules");
        let outside = temp("rules-out");
        let f = Folders::new(&input, None, true).unwrap();
        assert_eq!(f.output, input.join("signed"));
        assert_eq!(f.done, Some(input.join("done")));
        assert_eq!(f.failed, input.join("failed"));
        assert_eq!(Folders::new(&input, None, false).unwrap().done, None);
        // The dedicated folder, also spelled out (it need not exist yet).
        let f = Folders::new(&input, Some(&input.join("x/../signed")), true).unwrap();
        assert_eq!(f.output, input.join("signed"));
        assert!(Folders::new(&input, Some(&input), true).is_err());
        assert!(Folders::new(&input, Some(&input.join(".")), true).is_err());
        assert!(Folders::new(&input, Some(&input.join("done")), true).is_err());
        assert!(Folders::new(&input, Some(&input.join("other")), true).is_err());
        assert!(Folders::new(&input, Some(&input.join("signed/deeper")), true).is_err());
        assert!(Folders::new(&outside, Some(&input.join("..")), true).is_err());
        assert_eq!(
            Folders::new(&input, Some(&outside), true).unwrap().output,
            outside
        );
        assert!(Folders::new(&input.join("missing"), None, true).is_err());
        std::fs::remove_dir_all(&input).unwrap();
        std::fs::remove_dir_all(&outside).unwrap();
    }

    #[test]
    fn moving_never_replaces() {
        let dir = temp("move");
        let done = dir.join("done");
        for (i, want) in ["a.pdf", "a_2.pdf", "a_3.pdf"].iter().enumerate() {
            std::fs::write(dir.join("a.pdf"), [i as u8]).unwrap();
            let moved = move_into(&dir.join("a.pdf"), &done).unwrap();
            assert_eq!(moved, done.join(want));
            assert!(!dir.join("a.pdf").exists());
        }
        assert_eq!(std::fs::read(done.join("a.pdf")).unwrap(), [0]);
        assert_eq!(std::fs::read(done.join("a_3.pdf")).unwrap(), [2]);
        assert_eq!(
            free_path_in(&done, Path::new("/x/b.PDF")),
            done.join("b.PDF")
        );
        write_reason(
            &done.join("a_2.pdf"),
            &dir.join("a.pdf"),
            "Not a valid PDF.",
        )
        .unwrap();
        let txt = std::fs::read_to_string(done.join("a_2.txt")).unwrap();
        assert!(txt.contains("could not sign a.pdf") && txt.contains("Not a valid PDF."));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn info(pages: usize) -> PdfInfo {
        PdfInfo {
            pages: (0..pages)
                .map(|_| PageSize {
                    width: 595.0,
                    height: 842.0,
                    rotate: 0,
                })
                .collect(),
            signatures: 0,
            encrypted: false,
            signing_allowed: true,
            certified: None,
            empty_fields: Vec::new(),
        }
    }

    #[test]
    fn preset_json_from_the_app() {
        let p: Preset = serde_json::from_str(
            r#"{"name":"Invoices","reason":"Approved","location":" Chennai ",
                "placement":{"page":"first","x":10,"y":20,"w":60,"h":20},"image":"above"}"#,
        )
        .unwrap();
        assert_eq!(
            p.placement.unwrap().page,
            PageChoice::Named(NamedPage::First)
        );
        let req = p.request(&info(3), None);
        assert_eq!(req.page, 0);
        let r = req.rect.unwrap();
        assert!((r.x - 28.35).abs() < 0.01 && (r.w - 170.08).abs() < 0.01);
        assert_eq!(req.location.as_deref(), Some("Chennai"));
        assert_eq!(req.image_position, ImagePosition::Above);
        assert!(req.timestamp.is_none() && !req.ltv && req.certify.is_none());
        // A page number the file does not have falls back to its last page.
        let p: Preset =
            serde_json::from_str(r#"{"placement":{"page":5,"x":0,"y":0,"w":60,"h":20}}"#).unwrap();
        assert_eq!(p.request(&info(2), None).page, 1);
        assert!(p.validate().is_ok());
    }

    #[test]
    fn preset_defaults_and_pages() {
        let p = Preset::default();
        let req = p.request(&info(2), None);
        assert_eq!(req.page, 1);
        let r = req.rect.unwrap();
        assert_eq!(
            (r.x, r.y, r.w, r.h),
            (595.0 - 206.0, 842.0 - 91.0, 170.0, 55.0)
        );
        assert!(req.reason.is_none());
        let p = Preset {
            pages: "1-3,5".into(),
            ..Default::default()
        };
        assert_eq!(p.request(&info(4), None).pages, vec![0, 1, 2]);
        let p = Preset {
            pages: "all".into(),
            ..Default::default()
        };
        assert_eq!(p.request(&info(3), None).pages, vec![0, 1, 2]);
        let p = Preset {
            invisible: true,
            pages: "all".into(),
            ..Default::default()
        };
        let req = p.request(&info(3), None);
        assert!(req.rect.is_none() && req.pages.is_empty());
        assert!(
            Preset {
                pages: "3-1".into(),
                ..Default::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            Preset {
                timestamp: Some("timestamp.digicert.com".into()),
                ..Default::default()
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn control_wakes_the_watcher() {
        let c = Arc::new(Control::default());
        let start = Instant::now();
        c.changed();
        c.wait(Duration::from_secs(5));
        assert!(start.elapsed() < Duration::from_secs(1));
        let other = c.clone();
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            other.stop();
        });
        c.wait(Duration::from_secs(5));
        t.join().unwrap();
        assert!(c.is_stopped() && start.elapsed() < Duration::from_secs(2));
    }
}
