//! Verifying every PDF in a folder: the files are found, checked a few at a
//! time with [`Report::new`], and summed up as one A4 PDF, a CSV with a row
//! per signature, or JSON for automation (schema in the README, "Verifying a
//! folder"). A file that cannot be read is reported, never fatal.

use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::pdf::appearance::Face;
use crate::pdf::textdoc::{Style, TextDoc};
use crate::report::{
    ACCENT, BAD, CHECKED, INK, JsonSignature, LINE, MUTED, NOT_CHECKED, OK, Report, SCOPE,
    ist_and_utc, plural, shown, signature_rows, thousands, verdict,
};
use crate::verify::{Changes, SignatureReport, Status, Trust};
use crate::{Error, PdfError};

/// Version of the JSON layout; raised only when a field changes meaning or
/// is removed. New fields may appear without a new version.
pub const SCHEMA_VERSION: u32 = 1;

/// Most files checked at once: parsing is quick, the disk is the limit.
const THREADS: usize = 4;
/// Deeper folders are not searched (and a link loop that escapes the
/// canonical-path check ends here).
const MAX_DEPTH: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileStatus {
    /// Every signature valid, nothing but signatures or form filling after them.
    AllValid,
    /// A signature is invalid or could not be checked.
    SomeInvalid,
    /// The content changed after a signature, or after a certification that
    /// allowed no changes.
    ContentChanged,
    /// No signed signature fields.
    Unsigned,
    /// Not a PDF, damaged, or the file could not be read.
    Unreadable,
    /// Password-protected, and no password (or a wrong one) was given.
    NeedsPassword,
}

impl FileStatus {
    /// Name in the JSON and CSV.
    pub fn key(self) -> &'static str {
        match self {
            FileStatus::AllValid => "all_valid",
            FileStatus::SomeInvalid => "some_invalid",
            FileStatus::ContentChanged => "content_changed",
            FileStatus::Unsigned => "unsigned",
            FileStatus::Unreadable => "unreadable",
            FileStatus::NeedsPassword => "needs_password",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            FileStatus::AllValid => "All valid",
            FileStatus::SomeInvalid => "Invalid signature",
            FileStatus::ContentChanged => "Changed after signing",
            FileStatus::Unsigned => "Unsigned",
            FileStatus::Unreadable => "Unreadable",
            FileStatus::NeedsPassword => "Needs a password",
        }
    }

    /// Signed but not valid as it is.
    pub fn is_problem(self) -> bool {
        matches!(self, FileStatus::SomeInvalid | FileStatus::ContentChanged)
    }
}

#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Also check the PDFs in subfolders.
    pub recursive: bool,
    /// Tried on files that do not open without a password.
    pub password: Option<String>,
}

pub struct FileResult {
    pub path: PathBuf,
    /// Relative to the folder, with `/` between folder names.
    pub relative: String,
    /// `None` when the file could not be read at all.
    pub size: Option<usize>,
    /// Lower-case hex.
    pub sha256: Option<String>,
    pub status: FileStatus,
    /// Why the file could not be checked.
    pub error: Option<String>,
    /// It opened only with the password given in [`Options`].
    pub used_password: bool,
    /// Set unless the file could not be checked.
    pub report: Option<Report>,
}

impl FileResult {
    pub fn signatures(&self) -> &[SignatureReport] {
        self.report.as_ref().map_or(&[], |r| &r.signatures)
    }

    /// Who signed, in signing order, each name once.
    pub fn signers(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for r in self.signatures() {
            let name = r.signer.as_ref().map(|s| &s.subject).or(r.name.as_ref());
            if let Some(n) = name
                && !out.contains(n)
            {
                out.push(n.clone());
            }
        }
        out
    }
}

/// What [`verify_folder`] reports while it works, from several threads.
pub enum Progress<'a> {
    /// The PDFs that will be checked, before the first is.
    Found(&'a [PathBuf]),
    /// File `index` of the list has been checked.
    Checked(usize, &'a FileResult),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Totals {
    pub files: usize,
    pub all_valid: usize,
    pub some_invalid: usize,
    pub content_changed: usize,
    pub unsigned: usize,
    pub unreadable: usize,
    pub needs_password: usize,
    pub signatures: usize,
}

impl Totals {
    /// Signed files that are not valid as they are.
    pub fn problems(&self) -> usize {
        self.some_invalid + self.content_changed
    }
}

pub struct FolderReport {
    pub folder: PathBuf,
    pub recursive: bool,
    pub checked_at: DateTime<Utc>,
    /// TrackMySign version that made the check.
    pub version: String,
    /// In path order; when stopped, only the files checked by then.
    pub files: Vec<FileResult>,
    /// Stopped before every file was checked.
    pub stopped: bool,
}

// ------------------------------------------------------------- finding

/// The PDFs in `dir` (`*.pdf` in any case), sorted by path. Hidden files
/// and folders (a leading `.`, or the Windows hidden or system attribute)
/// are skipped; links are followed, each folder searched once. A subfolder
/// that cannot be read is skipped.
pub fn find_pdfs(dir: &Path, recursive: bool) -> io::Result<Vec<PathBuf>> {
    let mut seen = HashSet::from([fs::canonicalize(dir)?]);
    let mut out = Vec::new();
    walk(dir, recursive, &mut seen, &mut out, 0)?;
    out.sort_by_cached_key(|p| p.to_string_lossy().to_lowercase());
    Ok(out)
}

fn walk(
    dir: &Path,
    recursive: bool,
    seen: &mut HashSet<PathBuf>,
    out: &mut Vec<PathBuf>,
    depth: usize,
) -> io::Result<()> {
    for entry in fs::read_dir(dir)?.flatten() {
        if hidden(&entry) {
            continue;
        }
        let path = entry.path();
        // Follows links; a broken one is skipped.
        let Ok(meta) = fs::metadata(&path) else {
            continue;
        };
        if meta.is_dir() {
            if recursive
                && depth < MAX_DEPTH
                && fs::canonicalize(&path).is_ok_and(|c| seen.insert(c))
            {
                let _ = walk(&path, recursive, seen, out, depth + 1);
            }
        } else if meta.is_file() && is_pdf(&path) {
            out.push(path);
        }
    }
    Ok(())
}

fn is_pdf(path: &Path) -> bool {
    path.extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("pdf"))
}

fn hidden(entry: &fs::DirEntry) -> bool {
    if entry.file_name().to_string_lossy().starts_with('.') {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const HIDDEN_OR_SYSTEM: u32 = 0x2 | 0x4;
        if let Ok(m) = entry.metadata()
            && m.file_attributes() & HIDDEN_OR_SYSTEM != 0
        {
            return true;
        }
    }
    false
}

/// `path` relative to `root`, with `/` between folder names.
pub fn relative(root: &Path, path: &Path) -> String {
    let rel = path.strip_prefix(root).unwrap_or(path);
    rel.components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

// ------------------------------------------------------------ checking

/// Checks one file: first without a password, then with `password` if it
/// needs one.
pub fn check_file(
    path: &Path,
    relative: String,
    password: Option<&str>,
    version: &str,
) -> FileResult {
    let mut result = FileResult {
        path: path.to_path_buf(),
        relative,
        size: None,
        sha256: None,
        status: FileStatus::Unreadable,
        error: None,
        used_password: false,
        report: None,
    };
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            result.error = Some(e.to_string());
            return result;
        }
    };
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut checked = Report::new(&data, &name, None, version);
    if let (Err(Error::Pdf(PdfError::PasswordRequired)), Some(pw)) = (&checked, password) {
        checked = Report::new(&data, &name, Some(pw), version);
        result.used_password = true;
    }
    match checked {
        Ok(report) => {
            result.size = Some(report.file_size);
            result.sha256 = Some(report.sha256.clone());
            result.status = status_of(&report);
            result.report = Some(report);
        }
        Err(e) => {
            result.size = Some(data.len());
            result.sha256 = Some(
                Sha256::digest(&data)
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect(),
            );
            result.used_password = false;
            if matches!(
                e,
                Error::Pdf(PdfError::PasswordRequired | PdfError::WrongPassword)
            ) {
                result.status = FileStatus::NeedsPassword;
            }
            result.error = Some(e.to_string());
        }
    }
    result
}

fn status_of(r: &Report) -> FileStatus {
    if r.signatures.is_empty() {
        FileStatus::Unsigned
    } else if r.signatures.iter().any(|s| s.status != Status::Valid) {
        FileStatus::SomeInvalid
    } else if r.content_changed() || r.certification_broken() {
        FileStatus::ContentChanged
    } else {
        FileStatus::AllValid
    }
}

/// Finds the PDFs in `folder` and checks them, a few in parallel. Fails
/// only when `folder` itself cannot be read. Setting `stop` ends the check
/// after the files under way.
pub fn verify_folder(
    folder: &Path,
    options: &Options,
    version: &str,
    stop: &AtomicBool,
    progress: impl Fn(Progress<'_>) + Sync,
) -> io::Result<FolderReport> {
    let checked_at = Utc::now();
    let paths = find_pdfs(folder, options.recursive)?;
    progress(Progress::Found(&paths));
    let next = AtomicUsize::new(0);
    let done: Mutex<Vec<Option<FileResult>>> = Mutex::new((0..paths.len()).map(|_| None).collect());
    let threads = std::thread::available_parallelism()
        .map_or(1, |n| n.get())
        .clamp(1, THREADS)
        .min(paths.len());
    std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| {
                loop {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(path) = paths.get(i) else {
                        break;
                    };
                    let r = check_file(
                        path,
                        relative(folder, path),
                        options.password.as_deref(),
                        version,
                    );
                    progress(Progress::Checked(i, &r));
                    done.lock().unwrap_or_else(|p| p.into_inner())[i] = Some(r);
                }
            });
        }
    });
    let done = done.into_inner().unwrap_or_else(|p| p.into_inner());
    let stopped = done.iter().any(Option::is_none);
    Ok(FolderReport {
        folder: folder.to_path_buf(),
        recursive: options.recursive,
        checked_at,
        version: version.to_string(),
        files: done.into_iter().flatten().collect(),
        stopped,
    })
}

// -------------------------------------------------------------- report

impl FolderReport {
    pub fn totals(&self) -> Totals {
        let mut t = Totals {
            files: self.files.len(),
            ..Totals::default()
        };
        for f in &self.files {
            t.signatures += f.signatures().len();
            *match f.status {
                FileStatus::AllValid => &mut t.all_valid,
                FileStatus::SomeInvalid => &mut t.some_invalid,
                FileStatus::ContentChanged => &mut t.content_changed,
                FileStatus::Unsigned => &mut t.unsigned,
                FileStatus::Unreadable => &mut t.unreadable,
                FileStatus::NeedsPassword => &mut t.needs_password,
            } += 1;
        }
        t
    }

    /// Every signed file valid and every file checked; with `require_signed`
    /// unsigned files fail too.
    pub fn passed(&self, require_signed: bool) -> bool {
        !self.stopped
            && self.files.iter().all(|f| match f.status {
                FileStatus::AllValid => true,
                FileStatus::Unsigned => !require_signed,
                _ => false,
            })
    }

    /// "7 files: 2 all valid, 2 with problems, 1 unsigned, 1 unreadable,
    /// 1 needs a password"; the last part only when there are such files.
    pub fn summary(&self) -> String {
        let t = self.totals();
        if t.files == 0 {
            return "No PDF files found.".into();
        }
        let mut line = format!(
            "{}: {} all valid, {} with problems, {} unsigned, {} unreadable",
            plural(t.files, "file"),
            t.all_valid,
            t.problems(),
            t.unsigned,
            t.unreadable
        );
        match t.needs_password {
            0 => {}
            1 => line.push_str(", 1 needs a password"),
            n => line.push_str(&format!(", {n} need a password")),
        }
        line
    }

    // ------------------------------------------------------------- PDF

    pub fn to_pdf(&self) -> Vec<u8> {
        let title = Style::new(Face::Bold, 18.0, INK);
        let heading = Style::new(Face::Bold, 11.0, INK);
        let label = Style::new(Face::Regular, 9.0, MUTED);
        let value = Style::new(Face::Regular, 9.5, INK);
        let head = Style::new(Face::Bold, 8.5, MUTED);
        let cell = Style::new(Face::Regular, 8.5, INK);
        let small_label = Style::new(Face::Regular, 8.0, MUTED);
        let small = Style::new(Face::Regular, 8.5, INK);
        let tone = |s: FileStatus| match s {
            FileStatus::AllValid => OK,
            FileStatus::SomeInvalid | FileStatus::ContentChanged => BAD,
            _ => INK,
        };
        const LABEL_WIDTH: f64 = 128.0;
        const DETAIL_LABEL_WIDTH: f64 = 116.0;
        let t = self.totals();

        let mut d = TextDoc::new(&format!(
            "Generated by TrackMySign v{}. {SCOPE}",
            self.version
        ));
        d.paragraph("Folder verification report", title);
        d.rule(1.5, ACCENT, 8.0);
        let color = if t.problems() > 0 {
            BAD
        } else if self.passed(false) && t.all_valid > 0 {
            OK
        } else {
            INK
        };
        d.paragraph(&self.summary(), Style::new(Face::Bold, 11.0, color));
        if self.stopped {
            d.paragraph(
                "The check was stopped before every file was checked.",
                Style::new(Face::Bold, 9.5, BAD),
            );
        }
        d.space(10.0);

        let rows = [
            ("Folder", shown(&self.folder.to_string_lossy())),
            (
                "Subfolders",
                if self.recursive {
                    "Included"
                } else {
                    "Not included"
                }
                .to_string(),
            ),
            ("Signatures", t.signatures.to_string()),
            ("Checked", ist_and_utc(self.checked_at)),
            ("Checked with", format!("TrackMySign {}", self.version)),
        ];
        for (k, v) in &rows {
            d.row(k, label, v, value, LABEL_WIDTH);
        }

        if !self.files.is_empty() {
            d.space(10.0);
            d.paragraph("Files", heading);
            d.space(3.0);
            let w = TextDoc::width();
            let widths = [w * 0.40, w * 0.19, w * 0.07, w * 0.34];
            let table_row = |d: &mut TextDoc, cells: [(&str, Style); 4]| {
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
                    ("File", head),
                    ("Status", head),
                    ("Sig.", head),
                    ("Signed by", head),
                ],
            );
            d.rule(0.5, LINE, 2.0);
            for f in &self.files {
                let n = f.signatures().len().to_string();
                let signers = f
                    .signers()
                    .iter()
                    .map(|s| shown(s))
                    .collect::<Vec<_>>()
                    .join(", ");
                table_row(
                    &mut d,
                    [
                        (&shown(&f.relative), cell),
                        (
                            f.status.label(),
                            Style {
                                color: tone(f.status),
                                ..cell
                            },
                        ),
                        (if f.report.is_some() { &n } else { "—" }, cell),
                        (if signers.is_empty() { "—" } else { &signers }, cell),
                    ],
                );
                d.rule(0.25, LINE, 1.5);
            }
        }

        if !self.files.is_empty() {
            d.keep(160.0);
            d.space(14.0);
            d.paragraph("Appendix: each file", heading);
        }
        for (i, f) in self.files.iter().enumerate() {
            d.keep(90.0);
            d.rule(0.5, LINE, 8.0);
            d.paragraph(
                &format!("{}. {}", i + 1, shown(&f.relative)),
                Style::new(Face::Bold, 10.0, INK),
            );
            d.space(2.0);
            let mut rows = vec![(
                "Status",
                match &f.report {
                    Some(r) => format!("{}: {}", f.status.label(), r.summary()),
                    None => f.status.label().to_string(),
                },
            )];
            if let Some(e) = &f.error {
                rows.push(("Error", shown(e)));
            }
            if let Some(size) = f.size {
                rows.push(("Size", format!("{} bytes", thousands(size))));
            }
            if let Some(h) = &f.sha256 {
                rows.push(("SHA-256", h.clone()));
            }
            if let Some(r) = &f.report {
                rows.push(("Pages", r.pages.map_or("—".into(), |n| n.to_string())));
                if r.encrypted {
                    rows.push(("Protection", "Password-protected".into()));
                }
            }
            for (k, v) in &rows {
                let style = match k {
                    &"Status" => Style {
                        color: tone(f.status),
                        ..small
                    },
                    _ => small,
                };
                d.row(k, small_label, v, style, DETAIL_LABEL_WIDTH);
            }
            let sigs = f.signatures();
            for (j, r) in sigs.iter().enumerate() {
                d.keep(60.0);
                d.space(5.0);
                let (word, color) = verdict(r);
                d.paragraph(
                    &format!("Signature {} of {}: {word}", j + 1, sigs.len()),
                    Style::new(Face::Bold, 9.0, color),
                );
                for (k, v) in signature_rows(r) {
                    let bad = (k == "Coverage" && r.changes == Changes::Content)
                        || (k == "Status" && r.status == Status::Invalid);
                    let style = if bad {
                        Style {
                            color: BAD,
                            ..small
                        }
                    } else {
                        small
                    };
                    d.row(k, small_label, &v, style, DETAIL_LABEL_WIDTH);
                }
            }
        }
        d.finish(
            &format!(
                "Folder verification report: {}",
                self.folder.to_string_lossy()
            ),
            &format!("TrackMySign {}", self.version),
            self.checked_at,
        )
    }

    // ------------------------------------------------------------- CSV

    /// One row per signature, with the file's columns repeated; a file with
    /// no signatures (or that could not be checked) has one row of its own.
    /// UTF-8 with a byte order mark, so spreadsheet programs show Indian
    /// scripts; CRLF line ends (RFC 4180).
    pub fn to_csv(&self) -> String {
        const HEADER: [&str; 23] = [
            "file",
            "size",
            "sha256",
            "file_status",
            "signatures",
            "file_error",
            "signature",
            "field",
            "status",
            "signer",
            "organization",
            "issuer",
            "serial",
            "not_before",
            "not_after",
            "signing_time",
            "timestamp",
            "reason",
            "location",
            "certification",
            "changes",
            "trust",
            "notes",
        ];
        let mut out = String::from("\u{feff}");
        push_csv_row(&mut out, HEADER.iter().map(|s| s.to_string()));
        let time = |t: DateTime<Utc>| t.to_rfc3339_opts(SecondsFormat::Secs, true);
        for f in &self.files {
            let sigs = f.signatures();
            let file = [
                f.relative.clone(),
                f.size.map(|s| s.to_string()).unwrap_or_default(),
                f.sha256.clone().unwrap_or_default(),
                f.status.key().to_string(),
                if f.report.is_some() {
                    sigs.len().to_string()
                } else {
                    String::new()
                },
                f.error.clone().unwrap_or_default(),
            ];
            if sigs.is_empty() {
                push_csv_row(
                    &mut out,
                    file.iter().cloned().chain(std::iter::repeat_n(
                        String::new(),
                        HEADER.len() - file.len(),
                    )),
                );
            }
            for (i, r) in sigs.iter().enumerate() {
                let s = r.signer.as_ref();
                let sig = [
                    (i + 1).to_string(),
                    r.field.clone(),
                    status_key(r.status).to_string(),
                    s.map(|c| c.subject.clone())
                        .or_else(|| r.name.clone())
                        .unwrap_or_default(),
                    s.and_then(|c| c.organization.clone()).unwrap_or_default(),
                    s.map(|c| c.issuer.clone()).unwrap_or_default(),
                    s.map(|c| c.serial_hex.clone()).unwrap_or_default(),
                    s.map(|c| time(c.not_before)).unwrap_or_default(),
                    s.map(|c| time(c.not_after)).unwrap_or_default(),
                    r.signing_time
                        .map(|t| t.to_rfc3339_opts(SecondsFormat::Secs, true))
                        .unwrap_or_default(),
                    r.timestamped.to_string(),
                    r.reason.clone().unwrap_or_default(),
                    r.location.clone().unwrap_or_default(),
                    r.certification
                        .map(|p| p.level().to_string())
                        .unwrap_or_default(),
                    changes_key(r.changes).to_string(),
                    trust_key(r.trust).to_string(),
                    r.notes.join(" "),
                ];
                push_csv_row(&mut out, file.iter().cloned().chain(sig));
            }
        }
        out
    }

    // ------------------------------------------------------------ JSON

    /// Pretty-printed JSON, schema version [`SCHEMA_VERSION`].
    pub fn to_json(&self) -> String {
        let t = self.totals();
        let doc = JsonFolder {
            schema: "trackmysign.folder-verification-report",
            schema_version: SCHEMA_VERSION,
            generator: format!("TrackMySign {}", self.version),
            checked_at: self.checked_at.to_rfc3339_opts(SecondsFormat::Secs, true),
            folder: self.folder.to_string_lossy().into_owned(),
            recursive: self.recursive,
            complete: !self.stopped,
            summary: self.summary(),
            totals: JsonTotals {
                files: t.files,
                all_valid: t.all_valid,
                problems: t.problems(),
                some_invalid: t.some_invalid,
                content_changed: t.content_changed,
                unsigned: t.unsigned,
                unreadable: t.unreadable,
                needs_password: t.needs_password,
                signatures: t.signatures,
            },
            checked: CHECKED,
            not_checked: NOT_CHECKED,
            files: self
                .files
                .iter()
                .map(|f| JsonFile {
                    path: &f.relative,
                    size: f.size,
                    sha256: f.sha256.as_deref(),
                    status: f.status.key(),
                    error: f.error.as_deref(),
                    pages: f.report.as_ref().and_then(|r| r.pages),
                    encrypted: f.report.as_ref().map(|r| r.encrypted),
                    summary: f.report.as_ref().map(Report::summary),
                    signatures: f
                        .signatures()
                        .iter()
                        .enumerate()
                        .map(|(i, r)| JsonSignature::new(i + 1, r))
                        .collect(),
                })
                .collect(),
        };
        serde_json::to_string_pretty(&doc).expect("report serialises")
    }
}

fn status_key(s: Status) -> &'static str {
    match s {
        Status::Valid => "valid",
        Status::Invalid => "invalid",
        Status::Unknown => "unknown",
    }
}

fn changes_key(c: Changes) -> &'static str {
    match c {
        Changes::None => "none",
        Changes::Signatures => "signatures",
        Changes::FormOrAnnotations => "form_or_annotations",
        Changes::Content => "content",
        Changes::Unknown => "unknown",
    }
}

fn trust_key(t: Trust) -> &'static str {
    match t {
        Trust::CcaIndia => "cca_india_2022",
        Trust::NotChecked => "not_checked",
    }
}

pub(crate) fn push_csv_row(out: &mut String, cells: impl Iterator<Item = String>) {
    let cells: Vec<String> = cells.map(|c| csv_cell(&c)).collect();
    out.push_str(&cells.join(","));
    out.push_str("\r\n");
}

/// Quoted when needed. Text from a PDF that a spreadsheet would run as a
/// formula (`=`, `+`, `-`, `@` first) gets a leading `'`.
fn csv_cell(s: &str) -> String {
    let s = if s.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{s}")
    } else {
        s.to_string()
    };
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s
    }
}

// ------------------------------------------------------------ JSON types

#[derive(Serialize)]
struct JsonFolder<'a> {
    schema: &'static str,
    schema_version: u32,
    generator: String,
    checked_at: String,
    folder: String,
    recursive: bool,
    complete: bool,
    summary: String,
    totals: JsonTotals,
    checked: &'static [&'static str],
    not_checked: &'static [&'static str],
    files: Vec<JsonFile<'a>>,
}

#[derive(Serialize)]
struct JsonTotals {
    files: usize,
    all_valid: usize,
    problems: usize,
    some_invalid: usize,
    content_changed: usize,
    unsigned: usize,
    unreadable: usize,
    needs_password: usize,
    signatures: usize,
}

#[derive(Serialize)]
struct JsonFile<'a> {
    path: &'a str,
    size: Option<usize>,
    sha256: Option<&'a str>,
    status: &'static str,
    error: Option<&'a str>,
    pages: Option<usize>,
    encrypted: Option<bool>,
    summary: Option<String>,
    signatures: Vec<JsonSignature<'a>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::CertDetails;
    use chrono::TimeZone;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("tms-folder-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn finds_pdfs_only() {
        let dir = temp_dir("find");
        for f in [
            "b.pdf",
            "A.PDF",
            "c.Pdf",
            "notes.txt",
            "pdf",
            ".hidden.pdf",
            "sub/d.pdf",
            "sub/deeper/e.pdf",
            ".git/f.pdf",
        ] {
            let p = dir.join(f);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, b"%PDF").unwrap();
        }
        fs::create_dir_all(dir.join("folder.pdf")).unwrap();
        let rel =
            |v: Vec<PathBuf>| -> Vec<String> { v.iter().map(|p| relative(&dir, p)).collect() };

        assert_eq!(
            rel(find_pdfs(&dir, false).unwrap()),
            ["A.PDF", "b.pdf", "c.Pdf"]
        );
        #[cfg(unix)]
        {
            // A link back up must not loop; a broken link is skipped.
            std::os::unix::fs::symlink(&dir, dir.join("sub/loop")).unwrap();
            std::os::unix::fs::symlink(dir.join("missing.pdf"), dir.join("broken.pdf")).unwrap();
        }
        assert_eq!(
            rel(find_pdfs(&dir, true).unwrap()),
            ["A.PDF", "b.pdf", "c.Pdf", "sub/d.pdf", "sub/deeper/e.pdf"]
        );
        assert!(find_pdfs(&dir.join("nope"), true).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn bad_files_are_reported() {
        let dir = temp_dir("bad");
        fs::write(dir.join("junk.pdf"), b"not a pdf at all").unwrap();
        fs::write(dir.join("empty.pdf"), b"").unwrap();
        let stop = AtomicBool::new(false);
        let found = Mutex::new(0);
        let checked = AtomicUsize::new(0);
        let r = verify_folder(&dir, &Options::default(), "0.4.0", &stop, |p| match p {
            Progress::Found(f) => *found.lock().unwrap() = f.len(),
            Progress::Checked(..) => {
                checked.fetch_add(1, Ordering::Relaxed);
            }
        })
        .unwrap();
        fs::remove_dir_all(&dir).unwrap();
        assert_eq!(*found.lock().unwrap(), 2);
        assert_eq!(checked.load(Ordering::Relaxed), 2);
        assert_eq!(r.files.len(), 2);
        for f in &r.files {
            assert_eq!(f.status, FileStatus::Unreadable);
            assert!(f.error.is_some() && f.report.is_none());
        }
        assert_eq!(r.files[1].relative, "junk.pdf");
        assert_eq!(r.files[1].size, Some(16));
        assert!(!r.passed(false));
    }

    fn cert(name: &str) -> CertDetails {
        CertDetails {
            subject: name.into(),
            organization: None,
            issuer: "Verasys Sub CA 2022".into(),
            serial_hex: "0A1B".into(),
            not_before: Utc.with_ymd_and_hms(2025, 4, 1, 0, 0, 0).unwrap(),
            not_after: Utc.with_ymd_and_hms(2027, 3, 31, 0, 0, 0).unwrap(),
        }
    }

    fn sig(signer: &str, status: Status, changes: Changes) -> SignatureReport {
        SignatureReport {
            field: format!("Sig {signer}"),
            status,
            notes: vec![],
            sub_filter: Some("adbe.pkcs7.detached".into()),
            digest_algorithm: Some("SHA-256"),
            signer: Some(cert(signer)),
            chain: vec![cert(signer)],
            trust: Trust::NotChecked,
            signing_time: None,
            time_in_validity: None,
            timestamped: false,
            name: None,
            reason: Some("=HYPERLINK(\"x\")".into()),
            location: None,
            signed_len: 100,
            file_len: 200,
            later_revisions: 1,
            changes,
            certification: None,
        }
    }

    fn file(name: &str, sigs: Option<Vec<SignatureReport>>) -> FileResult {
        let report = sigs.map(|signatures| Report {
            file_name: name.into(),
            file_size: 200,
            sha256: "ab".repeat(32),
            pages: Some(1),
            encrypted: false,
            checked_at: Utc::now(),
            version: "0.4.0".into(),
            signatures,
        });
        FileResult {
            path: PathBuf::from(name),
            relative: name.into(),
            size: Some(200),
            sha256: Some("ab".repeat(32)),
            status: report.as_ref().map_or(FileStatus::Unreadable, status_of),
            error: report.is_none().then(|| "not a PDF file".to_string()),
            used_password: false,
            report,
        }
    }

    fn folder(files: Vec<FileResult>) -> FolderReport {
        FolderReport {
            folder: PathBuf::from("/srv/invoices"),
            recursive: true,
            checked_at: Utc.with_ymd_and_hms(2026, 10, 24, 9, 30, 12).unwrap(),
            version: "0.4.0".into(),
            files,
            stopped: false,
        }
    }

    #[test]
    fn statuses_and_totals() {
        use Changes::{Content, None as Whole, Signatures};
        let r = folder(vec![
            file(
                "a.pdf",
                Some(vec![
                    sig("A", Status::Valid, Signatures),
                    sig("B", Status::Valid, Whole),
                ]),
            ),
            file("b.pdf", Some(vec![sig("A", Status::Valid, Whole)])),
            file("c.pdf", Some(vec![sig("A", Status::Invalid, Whole)])),
            file("d.pdf", Some(vec![sig("A", Status::Unknown, Whole)])),
            file("e.pdf", Some(vec![sig("C", Status::Valid, Content)])),
            file("f.pdf", Some(vec![])),
            file("g.pdf", None),
        ]);
        let statuses: Vec<FileStatus> = r.files.iter().map(|f| f.status).collect();
        use FileStatus::*;
        assert_eq!(
            statuses,
            [
                AllValid,
                AllValid,
                SomeInvalid,
                SomeInvalid,
                ContentChanged,
                Unsigned,
                Unreadable
            ]
        );
        let t = r.totals();
        assert_eq!(
            t,
            Totals {
                files: 7,
                all_valid: 2,
                some_invalid: 2,
                content_changed: 1,
                unsigned: 1,
                unreadable: 1,
                needs_password: 0,
                signatures: 6,
            }
        );
        assert_eq!(
            r.summary(),
            "7 files: 2 all valid, 3 with problems, 1 unsigned, 1 unreadable"
        );
        assert_eq!(r.files[0].signers(), ["A", "B"]);
        assert!(!r.passed(false));

        let ok = folder(vec![
            file("a.pdf", Some(vec![sig("A", Status::Valid, Whole)])),
            file("f.pdf", Some(vec![])),
        ]);
        assert!(ok.passed(false));
        assert!(!ok.passed(true));
        let mut locked = file("h.pdf", None);
        locked.status = NeedsPassword;
        let mut stopped = folder(vec![locked]);
        assert!(
            stopped
                .summary()
                .ends_with(", 0 unreadable, 1 needs a password")
        );
        stopped.files.clear();
        assert_eq!(stopped.summary(), "No PDF files found.");
        assert!(stopped.passed(true));
        stopped.stopped = true;
        assert!(!stopped.passed(false));
    }

    #[test]
    fn csv_rows() {
        let r = folder(vec![
            file(
                "sub/a,b.pdf",
                Some(vec![
                    sig("A", Status::Valid, Changes::Signatures),
                    sig("B", Status::Valid, Changes::None),
                ]),
            ),
            file("g.pdf", None),
        ]);
        let csv = r.to_csv();
        assert!(csv.starts_with("\u{feff}file,size,sha256,file_status,"));
        let lines: Vec<&str> = csv.trim_end().split("\r\n").collect();
        assert_eq!(lines.len(), 4);
        assert!(lines.iter().all(|l| l.matches(',').count() >= 22));
        assert!(lines[1].starts_with("\"sub/a,b.pdf\",200,"));
        assert!(lines[1].contains(",all_valid,2,,1,Sig A,valid,A,,"));
        assert!(lines[1].contains(",\"'=HYPERLINK(\"\"x\"\")\","));
        assert!(lines[2].contains(",2,Sig B,valid,B,"));
        assert!(lines[3].starts_with("g.pdf,200,"));
        assert!(lines[3].contains(",unreadable,,not a PDF file,"));
        assert_eq!(csv_cell("-5"), "'-5");
        assert_eq!(csv_cell("plain"), "plain");
        assert_eq!(csv_cell("two\nlines"), "\"two\nlines\"");
    }

    /// The JSON keys are a published interface, like the single-file report's.
    #[test]
    fn json_schema_is_stable() {
        fn keys(v: &serde_json::Value) -> Vec<&str> {
            let mut k: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
            k.sort_unstable();
            k
        }
        let r = folder(vec![
            file("a.pdf", Some(vec![sig("A", Status::Valid, Changes::None)])),
            file("g.pdf", None),
        ]);
        let v: serde_json::Value = serde_json::from_str(&r.to_json()).unwrap();
        assert_eq!(
            keys(&v),
            [
                "checked",
                "checked_at",
                "complete",
                "files",
                "folder",
                "generator",
                "not_checked",
                "recursive",
                "schema",
                "schema_version",
                "summary",
                "totals"
            ]
        );
        assert_eq!(v["schema"], "trackmysign.folder-verification-report");
        assert_eq!(v["schema_version"], 1);
        assert_eq!(
            keys(&v["totals"]),
            [
                "all_valid",
                "content_changed",
                "files",
                "needs_password",
                "problems",
                "signatures",
                "some_invalid",
                "unreadable",
                "unsigned"
            ]
        );
        assert_eq!(
            keys(&v["files"][0]),
            [
                "encrypted",
                "error",
                "pages",
                "path",
                "sha256",
                "signatures",
                "size",
                "status",
                "summary"
            ]
        );
        assert_eq!(v["files"][0]["status"], "all_valid");
        assert_eq!(v["files"][0]["signatures"][0]["index"], 1);
        assert_eq!(
            v["files"][0]["signatures"][0]["coverage"]["changes"],
            "none"
        );
        assert_eq!(v["files"][1]["status"], "unreadable");
        assert_eq!(v["files"][1]["pages"], serde_json::Value::Null);
        assert_eq!(v["totals"]["files"], 2);
    }

    #[test]
    fn pdf_report_reads_back() {
        let files: Vec<FileResult> = (0..30)
            .map(|i| {
                let sigs = (i % 3 != 2)
                    .then(|| vec![sig("रमेश", Status::Valid, Changes::None); i % 3 + 1]);
                file(&format!("folder/file-{i}.pdf"), sigs)
            })
            .collect();
        let pdf = folder(files).to_pdf();
        let again = Report::new(&pdf, "report.pdf", None, "0.4.0").unwrap();
        assert!(again.pages > Some(2), "{:?} pages", again.pages);
        assert!(again.signatures.is_empty());
    }
}
