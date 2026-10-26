//! `trackmysign` command-line tool — the test-phase front end for the core library.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail};
use chrono::{Local, NaiveDate, TimeZone};
use clap::{Parser, Subcommand, ValueEnum};
use trackmysign_core::certdetails::{
    CertificateDetails, complete_chain, export_file_name, to_p7b, to_pem,
};
use trackmysign_core::certinfo::{CertSummary, Validity};
use trackmysign_core::filesig::{self, FileCheck, FileSignRequest};
use trackmysign_core::folder::{self, FileResult, FileStatus, Options, Progress};
use trackmysign_core::history::{self, Entry, Filter, History, WatchRecorder};
use trackmysign_core::pdf::assemble::{self, Item, Notice};
use trackmysign_core::report::Report;
use trackmysign_core::support::{self, Event, EventLog};
use trackmysign_core::token::{
    Driver, TokenCert, TokenSigner, Tokens, driver_name, installed_drivers,
};
use trackmysign_core::verify::{Changes, SignatureReport, Status, Trust};
use trackmysign_core::{
    DEFAULT_TSA_URL, DisplayRect, DocMdp, Error, ImagePosition, PdfError, PdfInfo, SignRequest,
    Signer, StampImage, StampStyle, check_permitted_with_password, inspect_with_password,
    parse_pages, sign_pdf, signed_path, watch,
};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "trackmysign",
    version,
    about = "Sign PDFs and other files with your DSC token"
)]
struct Cli {
    /// PKCS#11 driver of the token. If omitted, every known driver is tried,
    /// or the ones listed in TRACKMYSIGN_PKCS11_MODULE.
    #[arg(long, global = true)]
    module: Option<PathBuf>,
    /// Password of a protected PDF: the user (open) password, or the owner
    /// (permissions) password when the PDF does not allow signing. Asked
    /// for when needed and not given.
    #[arg(long, global = true, env = "TRACKMYSIGN_PDF_PASSWORD", hide_env = true)]
    password: Option<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
// Parsed once at startup, so the size of Sign does not matter.
#[allow(clippy::large_enum_variant)]
enum Cmd {
    /// List certificates on the connected token(s), show their details or
    /// save one (the public certificate only) to a file.
    Certs {
        /// Show every field: email, serial number, key, key usage, policies,
        /// fingerprints and the issuer chain.
        #[arg(long)]
        details: bool,
        /// Save certificate N (number from the list) to a file.
        #[arg(long, value_name = "N")]
        export: Option<usize>,
        /// File to write. Default: <Name>_DSC.cer (.pem, .p7b) in the current folder.
        #[arg(long, requires = "export")]
        out: Option<PathBuf>,
        /// Write PEM (Base64 text) instead of DER.
        #[arg(long, requires = "export", conflicts_with = "chain")]
        pem: bool,
        /// Write the certificate with its issuer chain as a PKCS#7 file (.p7b, DER).
        #[arg(long, requires = "export")]
        chain: bool,
    },
    /// Show page count, page sizes, existing signatures and empty signature fields.
    Info { pdf: PathBuf },
    /// Sign one or more PDFs with one PIN entry. Writes <name>_signed.pdf
    /// next to each unless --out is given (single PDF only).
    Sign {
        #[arg(required = true)]
        pdfs: Vec<PathBuf>,
        #[arg(long)]
        out: Option<PathBuf>,
        /// Page number (1 = first). Default: last page.
        #[arg(long)]
        page: Option<usize>,
        /// Put the box on several pages under one signature: `all` or a list
        /// such as `1-3,5`. --rect is measured on --page (default: the first
        /// of these) and repeated at the same distance from the nearest corner.
        #[arg(long)]
        pages: Option<String>,
        /// Where on the page the box goes.
        #[arg(long, value_enum, default_value_t = Corner::BottomRight)]
        position: Corner,
        /// Exact box in points from the top-left of the page: x,y,width,height.
        #[arg(long, value_parser = parse_rect)]
        rect: Option<DisplayRect>,
        /// Make the signature invisible (no box on the page).
        #[arg(long)]
        invisible: bool,
        /// Sign into this empty signature field of the PDF (name as shown by
        /// `trackmysign info`); the box takes the field's place and size.
        #[arg(long, conflicts_with_all = ["page", "pages", "position", "rect", "invisible"])]
        field: Option<String>,
        #[arg(long)]
        reason: Option<String>,
        #[arg(long)]
        location: Option<String>,
        /// Handwritten signature (PNG or JPEG) to show in the box.
        #[arg(long)]
        image: Option<PathBuf>,
        /// Where the image goes, relative to the text.
        #[arg(long, value_enum, default_value_t = ImageSide::Left)]
        image_position: ImageSide,
        /// How the box looks: a style saved as JSON (see the README).
        #[arg(long, value_name = "FILE")]
        style: Option<PathBuf>,
        /// Company seal or logo (PNG or JPEG) to show in the box, placed as
        /// the style says (right of the text by default).
        #[arg(long, value_name = "FILE")]
        seal: Option<PathBuf>,
        /// Which certificate to use (number from `trackmysign certs`).
        #[arg(long, default_value_t = 1)]
        cert: usize,
        /// Add a trusted timestamp from this RFC 3161 server (needs the internet).
        #[arg(long, value_name = "URL", num_args = 0..=1, default_missing_value = DEFAULT_TSA_URL)]
        timestamp: Option<String>,
        /// Embed revocation info (OCSP/CRL) for long-term validation (needs the internet).
        #[arg(long)]
        ltv: bool,
        /// Sign even if the certificate has expired. The signature will not be
        /// accepted as valid.
        #[arg(long)]
        allow_expired: bool,
        /// Certify the document (first signature only) and set what may change
        /// afterwards: nothing, form filling and signing, or also comments.
        #[arg(long, value_enum, value_name = "ALLOWED")]
        certify: Option<Certify>,
        /// PIN (for scripted tests only; normally you are prompted).
        #[arg(long, env = "TRACKMYSIGN_PIN", hide = true)]
        pin: Option<String>,
    },
    /// Sign any files (Word, Excel, ZIP, XML, images, …) with one PIN entry,
    /// as standard CMS / PKCS#7 signatures: <file>.p7s next to each file
    /// (detached), or <file>.p7m with the file inside (--attached).
    SignFile {
        #[arg(required = true)]
        files: Vec<PathBuf>,
        /// Put the file inside the signature (.p7m) instead of next to it (.p7s).
        #[arg(long)]
        attached: bool,
        /// Signature file to write (single file only).
        #[arg(long)]
        out: Option<PathBuf>,
        /// Replace a signature file that already exists.
        #[arg(long)]
        force: bool,
        #[arg(long, default_value_t = 1)]
        cert: usize,
        /// Add a trusted timestamp from this RFC 3161 server (needs the internet).
        #[arg(long, value_name = "URL", num_args = 0..=1, default_missing_value = DEFAULT_TSA_URL)]
        timestamp: Option<String>,
        #[arg(long, env = "TRACKMYSIGN_PIN", hide = true)]
        pin: Option<String>,
    },
    /// Check a .p7s or .p7m signature of any file. FILE is the signed file
    /// (its FILE.p7s is found next to it) or the .p7s / .p7m itself. Exits
    /// with status 2 if the signature is not valid.
    VerifyFile {
        file: PathBuf,
        /// The detached signature, when it is not FILE.p7s.
        #[arg(long, value_name = "FILE.p7s")]
        sig: Option<PathBuf>,
        /// Save the file inside a .p7m (to --out, or next to it without the .p7m).
        #[arg(long)]
        extract: bool,
        #[arg(long, requires = "extract")]
        out: Option<PathBuf>,
    },
    /// Sign every PDF put into FOLDER until Ctrl+C, with one PIN entry.
    /// Signed copies go to --out (default FOLDER/signed), originals to
    /// FOLDER/done, files that cannot be signed to FOLDER/failed with a .txt
    /// saying why. Anyone who can write to FOLDER while this runs can get
    /// documents signed with your DSC: use a folder only you can write to.
    Watch {
        folder: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
        /// A preset saved as JSON: reason, location, placement (page "first",
        /// "last" or a number; x, y, w, h in mm from the top-left), image
        /// ("off", "left", "above"), pages, invisible, timestamp, ltv, style.
        #[arg(long, value_name = "FILE")]
        preset_json: Option<PathBuf>,
        /// Box on more pages: `all` or a list such as `1-3,5` (pages a file
        /// does not have are left out).
        #[arg(long)]
        pages: Option<String>,
        #[arg(long)]
        reason: Option<String>,
        #[arg(long)]
        location: Option<String>,
        /// Handwritten signature (PNG or JPEG); needed when the preset shows one.
        #[arg(long)]
        image: Option<PathBuf>,
        /// How the box looks, instead of the preset's style.
        #[arg(long, value_name = "FILE")]
        style: Option<PathBuf>,
        /// Company seal or logo (PNG or JPEG); needed when the style shows one.
        #[arg(long, value_name = "FILE")]
        seal: Option<PathBuf>,
        #[arg(long)]
        invisible: bool,
        /// Leave originals in FOLDER instead of moving them to FOLDER/done.
        #[arg(long)]
        keep_originals: bool,
        /// Stop after this many signed files in a day (0: no limit).
        #[arg(long, default_value_t = watch::DEFAULT_DAILY_LIMIT)]
        daily_limit: usize,
        /// Stop after this many hours.
        #[arg(long)]
        hours: Option<f64>,
        #[arg(long, value_name = "URL", num_args = 0..=1, default_missing_value = DEFAULT_TSA_URL)]
        timestamp: Option<String>,
        #[arg(long)]
        ltv: bool,
        #[arg(long, default_value_t = 1)]
        cert: usize,
        #[arg(long, env = "TRACKMYSIGN_PIN", hide = true)]
        pin: Option<String>,
    },
    /// Prepare a PDF for signing: merge, pick, reorder, turn, delete pages or
    /// add a blank one. Always writes a new file (default
    /// <name>_prepared.pdf); signatures already in a source do not carry over.
    Pages {
        #[command(subcommand)]
        op: PagesCmd,
    },
    /// Check the signatures in a PDF. Exits with status 2 if any signature is
    /// invalid or the content was changed after signing.
    Verify {
        pdf: PathBuf,
        /// Also write a verification report for auditors (A4 PDF) to this file.
        #[arg(long, value_name = "FILE")]
        report: Option<PathBuf>,
        /// Print the result as JSON instead of text (schema in the README).
        #[arg(long)]
        json: bool,
    },
    /// Check the signatures of every PDF in a folder (one --password is tried
    /// on protected files). Exits with status 2 if a signed file is not
    /// valid or a PDF could not be checked; unsigned files count only with
    /// --require-signed.
    VerifyFolder {
        dir: PathBuf,
        /// Also check the PDFs in subfolders.
        #[arg(long)]
        recursive: bool,
        /// Also write one report for auditors (A4 PDF) to this file.
        #[arg(long, value_name = "FILE")]
        report: Option<PathBuf>,
        /// Also write a CSV file, one row per signature.
        #[arg(long, value_name = "FILE")]
        csv: Option<PathBuf>,
        /// Print the result as JSON instead of text (schema in the README).
        #[arg(long)]
        json: bool,
        /// Fail on PDFs that have no signature, too.
        #[arg(long)]
        require_signed: bool,
    },
    /// Show the signing history kept on this computer, the same one the
    /// desktop app shows, oldest first. Exits with status 2 if the history
    /// was changed outside TrackMy Sign.
    History {
        /// Only entries from this day on (YYYY-MM-DD, this computer's time zone).
        #[arg(long, value_name = "DATE", value_parser = parse_day)]
        since: Option<NaiveDate>,
        /// Only entries up to and including this day.
        #[arg(long, value_name = "DATE", value_parser = parse_day)]
        until: Option<NaiveDate>,
        #[arg(long, value_enum)]
        source: Option<HistorySource>,
        #[arg(long, value_enum)]
        outcome: Option<HistoryOutcome>,
        /// Only entries whose file, signer or PAN contains this text.
        #[arg(long)]
        search: Option<String>,
        /// Print the entries and the integrity check as JSON.
        #[arg(long, conflicts_with = "csv")]
        json: bool,
        /// Print the entries as CSV.
        #[arg(long)]
        csv: bool,
        /// Also write the entries shown as a PDF (A4) to this file.
        #[arg(long, value_name = "FILE")]
        report: Option<PathBuf>,
    },
    /// Print a support report to attach to a bug report: versions, token
    /// drivers, tokens, certificates, settings and recent errors. Your home
    /// folder, email addresses, PANs and long hex strings are replaced, and
    /// nothing is sent anywhere. Read it before you share it.
    Doctor {
        /// Print only the data, as JSON.
        #[arg(long)]
        json: bool,
        /// Include certificate holder names, organisations and serial
        /// numbers (initials only by default).
        #[arg(long)]
        include_names: bool,
        /// Include token serial numbers.
        #[arg(long)]
        include_serials: bool,
        /// Include the watch folder's path.
        #[arg(long)]
        include_paths: bool,
    },
}

impl Cmd {
    /// For the support log when the command fails: what it was doing, the
    /// files it worked on (never written there) and whether it was signing.
    fn log_target(&self) -> Option<(&'static str, Vec<PathBuf>, bool)> {
        let opt = |o: &Option<PathBuf>| o.iter().cloned().collect::<Vec<_>>();
        Some(match self {
            Cmd::Certs { out, .. } => ("certificates", opt(out), false),
            Cmd::Info { pdf } => ("info", vec![pdf.clone()], false),
            Cmd::Sign {
                pdfs,
                out,
                image,
                style,
                seal,
                ..
            } => (
                "sign",
                [pdfs.clone(), opt(out), opt(image), opt(style), opt(seal)].concat(),
                true,
            ),
            Cmd::SignFile { files, out, .. } => {
                ("sign-file", [files.clone(), opt(out)].concat(), true)
            }
            Cmd::VerifyFile { file, sig, out, .. } => (
                "verify-file",
                [vec![file.clone()], opt(sig), opt(out)].concat(),
                false,
            ),
            Cmd::Watch {
                folder,
                out,
                preset_json,
                image,
                style,
                seal,
                ..
            } => (
                "watch",
                [
                    vec![folder.clone()],
                    opt(out),
                    opt(preset_json),
                    opt(image),
                    opt(style),
                    opt(seal),
                ]
                .concat(),
                true,
            ),
            Cmd::Pages { op } => {
                let (pdfs, out) = match op {
                    PagesCmd::Merge { pdfs, out } => (pdfs.clone(), out),
                    PagesCmd::Select { pdf, out, .. }
                    | PagesCmd::Rotate { pdf, out, .. }
                    | PagesCmd::Delete { pdf, out, .. }
                    | PagesCmd::InsertBlank { pdf, out, .. } => (vec![pdf.clone()], out),
                };
                ("pages", [pdfs, opt(&out.out)].concat(), false)
            }
            Cmd::Verify { pdf, report, .. } => {
                ("verify", [vec![pdf.clone()], opt(report)].concat(), false)
            }
            Cmd::VerifyFolder {
                dir, report, csv, ..
            } => (
                "verify-folder",
                [vec![dir.clone()], opt(report), opt(csv)].concat(),
                false,
            ),
            Cmd::History { .. } | Cmd::Doctor { .. } => return None,
        })
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum HistorySource {
    Manual,
    Batch,
    Watch,
    Portal,
}

#[derive(Clone, Copy, ValueEnum)]
enum HistoryOutcome {
    Signed,
    Failed,
}

/// `TrackMySign` as named in history entries made here.
const PROGRAM: &str = concat!("cli ", env!("CARGO_PKG_VERSION"));

/// The history in the desktop app's data folder (where Tauri's
/// `app_data_dir` points: `%APPDATA%`, `~/Library/Application Support` or
/// `$XDG_DATA_HOME`, then the app's identifier), so both keep one log.
fn history_store() -> Option<History> {
    app_data().map(|d| History::in_app_data(&d))
}

/// The desktop app's data folder (see [`history_store`]).
fn app_data() -> Option<PathBuf> {
    dirs::data_dir().map(|d| d.join(history::APP_ID))
}

/// Adds `entry` to the history, unless it is turned off in the app.
fn record(entry: Entry) {
    let Some(h) = history_store() else { return };
    if let Err(e) = h.record(entry) {
        eprintln!(
            "Warning: could not write the signing history in {}: {e}",
            h.dir().display()
        );
    }
}

fn parse_day(s: &str) -> Result<NaiveDate, String> {
    NaiveDate::parse_from_str(s.trim(), "%Y-%m-%d").map_err(|_| "expected YYYY-MM-DD".into())
}

/// `p` from the root, as the history keeps it.
fn absolute(p: &Path) -> PathBuf {
    std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf())
}

/// Midnight starting `day` on this computer's clock.
fn local_midnight(day: NaiveDate) -> chrono::DateTime<chrono::Utc> {
    let t = day.and_hms_opt(0, 0, 0).unwrap();
    Local
        .from_local_datetime(&t)
        .earliest()
        .map(|t| t.with_timezone(&chrono::Utc))
        .unwrap_or_else(|| chrono::Utc.from_utc_datetime(&t))
}

/// "12  24 Oct 2026, 14:03:11 IST  Signed (Batch)  invoice.pdf  DK RAHUL  signed".
fn describe_entry(e: &Entry) -> String {
    let ist = e
        .time
        .with_timezone(&chrono::FixedOffset::east_opt(5 * 3600 + 30 * 60).unwrap());
    let mut parts = vec![
        format!("{:>4}", e.seq),
        ist.format("%d %b %Y, %H:%M:%S IST").to_string(),
        match e.source {
            Some(s) => format!("{} ({})", e.action.label(), s.label()),
            None => e.action.label().to_string(),
        },
    ];
    if !e.action.is_marker() {
        parts.push(e.document());
    }
    if let Some(c) = &e.cert {
        parts.push(c.subject.clone());
    }
    match (e.outcome, &e.error, e.removed) {
        (Some(history::Outcome::Signed), _, _) => parts.push("signed".into()),
        (Some(history::Outcome::Failed), Some(r), _) => parts.push(format!("FAILED: {r}")),
        (Some(history::Outcome::Failed), None, _) => parts.push("FAILED".into()),
        (None, _, Some(n)) => parts.push(format!("{n} entries deleted")),
        _ => {}
    }
    parts.join("  ")
}

#[derive(Subcommand)]
enum PagesCmd {
    /// Join PDFs, in the order given.
    Merge {
        #[arg(required = true, num_args = 2..)]
        pdfs: Vec<PathBuf>,
        #[command(flatten)]
        out: PagesOut,
    },
    /// Keep only some pages, in the order given: `1-3,5,7-` (`7-` runs to
    /// the end, `5-3` backwards, a page may repeat).
    Select {
        pdf: PathBuf,
        pages: String,
        #[command(flatten)]
        out: PagesOut,
    },
    /// Turn pages clockwise by 90, 180 or 270 degrees (-90 turns left).
    Rotate {
        pdf: PathBuf,
        #[arg(allow_negative_numbers = true)]
        angle: i32,
        /// Pages to turn: `all` or a list such as `2,4` (default: all).
        #[arg(long)]
        pages: Option<String>,
        #[command(flatten)]
        out: PagesOut,
    },
    /// Leave out pages: a list such as `2,4-6`.
    Delete {
        pdf: PathBuf,
        pages: String,
        #[command(flatten)]
        out: PagesOut,
    },
    /// Add an empty page after page N (0: before the first page).
    InsertBlank {
        pdf: PathBuf,
        #[arg(long, value_name = "N")]
        after: usize,
        /// A4, Letter, or `same` as the page next to it.
        #[arg(long, value_enum, default_value_t = BlankSize::Same)]
        size: BlankSize,
        #[command(flatten)]
        out: PagesOut,
    },
}

#[derive(clap::Args)]
struct PagesOut {
    /// File to write. Default: <first input>_prepared.pdf next to it. Never
    /// one of the inputs.
    #[arg(short, long)]
    out: Option<PathBuf>,
    /// Go ahead without asking when a source PDF is signed.
    #[arg(long)]
    yes: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum BlankSize {
    Same,
    A4,
    Letter,
}

#[derive(Clone, Copy, ValueEnum)]
enum Corner {
    BottomRight,
    BottomLeft,
    TopRight,
    TopLeft,
}

#[derive(Clone, Copy, ValueEnum)]
enum Certify {
    None,
    Forms,
    Annotations,
}

impl From<Certify> for DocMdp {
    fn from(c: Certify) -> Self {
        match c {
            Certify::None => DocMdp::NoChanges,
            Certify::Forms => DocMdp::FormFilling,
            Certify::Annotations => DocMdp::Annotations,
        }
    }
}

fn describe_certification(p: DocMdp) -> &'static str {
    match p {
        DocMdp::NoChanges => "no changes allowed",
        DocMdp::FormFilling => "form filling and signing allowed",
        DocMdp::Annotations => "form filling, signing and comments allowed",
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum ImageSide {
    Left,
    Above,
}

/// A signature style saved as JSON, checked.
fn read_style(path: &Path) -> Result<StampStyle> {
    let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    StampStyle::from_json(&data)
        .map_err(anyhow::Error::msg)
        .with_context(|| format!("{} is not a signature style", path.display()))
}

fn parse_rect(s: &str) -> Result<DisplayRect, String> {
    let v: Vec<f64> = s
        .split(',')
        .map(|p| p.trim().parse::<f64>())
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;
    match v.as_slice() {
        [x, y, w, h] if *w > 0.0 && *h > 0.0 => Ok(DisplayRect {
            x: *x,
            y: *y,
            w: *w,
            h: *h,
        }),
        _ => Err("expected x,y,width,height".into()),
    }
}

/// One PDF read and placed, waiting for the token.
struct Job {
    data: Vec<u8>,
    page: usize,
    pages: Vec<usize>,
    rect: Option<DisplayRect>,
    password: Option<String>,
}

/// Runs `f` on a PDF, asking for its password on the terminal when it has
/// one and --password was not given. Returns the password that worked.
fn with_password<T>(
    pdf: &Path,
    given: Option<&str>,
    f: impl Fn(Option<&str>) -> Result<T, Error>,
) -> Result<(T, Option<String>)> {
    match f(given) {
        Err(Error::Pdf(PdfError::PasswordRequired)) if std::io::stdin().is_terminal() => {
            let pw = rpassword::prompt_password(format!("Password for {}: ", pdf.display()))?;
            Ok((f(Some(&pw))?, Some(pw)))
        }
        Err(e @ Error::Pdf(PdfError::PasswordRequired)) => bail!("{e} (--password)"),
        r => Ok((r?, given.map(str::to_string))),
    }
}

/// A PDF read, unlocked and checked that it may be signed.
struct Opened {
    data: Vec<u8>,
    info: PdfInfo,
    password: Option<String>,
}

fn open_for_signing(pdf: &Path, password: Option<&str>, certify: Option<DocMdp>) -> Result<Opened> {
    let data = std::fs::read(pdf).with_context(|| format!("reading {}", pdf.display()))?;
    let (info, password) = with_password(pdf, password, |pw| inspect_with_password(&data, pw))?;
    if !info.signing_allowed {
        bail!("{} (--password)", PdfError::SigningNotAllowed);
    }
    check_permitted_with_password(&data, password.as_deref(), certify)?;
    Ok(Opened {
        data,
        info,
        password,
    })
}

/// Works out the page index, the extra pages and the box for an opened PDF.
fn read_and_place(
    opened: Opened,
    page: Option<usize>,
    pages: Option<&str>,
    position: Corner,
    rect: Option<DisplayRect>,
    invisible: bool,
    field: Option<&str>,
) -> Result<Job> {
    let Opened {
        data,
        info,
        password,
    } = opened;
    if let Some(name) = field {
        if !info.empty_fields.iter().any(|f| f.name == name) {
            let names: Vec<&str> = info.empty_fields.iter().map(|f| f.name.as_str()).collect();
            if names.is_empty() {
                bail!("no empty signature field \"{name}\": the PDF has none");
            }
            bail!(
                "no empty signature field \"{name}\"; empty fields: {}",
                names.join(", ")
            );
        }
        return Ok(Job {
            data,
            page: 0,
            pages: Vec::new(),
            rect: None,
            password,
        });
    }
    let pages = match pages {
        Some(_) if invisible => bail!("--pages needs a visible signature"),
        Some(spec) => parse_pages(spec, info.pages.len()).map_err(anyhow::Error::msg)?,
        None => Vec::new(),
    };
    let page_idx = match page {
        Some(0) => bail!("pages are numbered from 1"),
        Some(n) if n > info.pages.len() => {
            bail!("the PDF has only {} page(s)", info.pages.len())
        }
        Some(n) => n - 1,
        None => pages.first().copied().unwrap_or(info.pages.len() - 1),
    };
    let p = &info.pages[page_idx];
    let rect = if invisible {
        None
    } else {
        Some(rect.unwrap_or_else(|| {
            let (w, h, m) = (170.0, 55.0, 36.0);
            let (x, y) = match position {
                Corner::BottomRight => (p.width - w - m, p.height - h - m),
                Corner::BottomLeft => (m, p.height - h - m),
                Corner::TopRight => (p.width - w - m, m),
                Corner::TopLeft => (m, m),
            };
            DisplayRect { x, y, w, h }
        }))
    };
    Ok(Job {
        data,
        page: page_idx,
        pages,
        rect,
        password,
    })
}

fn open_tokens(module: &Option<PathBuf>) -> Result<Tokens> {
    Ok(match module {
        Some(m) => Tokens::open(&[Driver {
            name: driver_name(m),
            path: m.clone(),
        }])?,
        None => Tokens::open_installed()?,
    })
}

fn days(n: i64) -> String {
    if n == 1 {
        "1 day".into()
    } else {
        format!("{n} days")
    }
}

/// "expires in 12 days", "EXPIRED 3 days ago", "NOT YET VALID (starts in 2 days)".
fn validity_text(v: Validity) -> String {
    match v {
        Validity::Valid { days_left: 0 } => "expires in less than a day".into(),
        Validity::Valid { days_left } => format!("expires in {}", days(days_left)),
        Validity::Expired { days: 0 } => "EXPIRED today".into(),
        Validity::Expired { days: n } => format!("EXPIRED {} ago", days(n)),
        Validity::NotYetValid { days: 0 } => "NOT YET VALID (starts later today)".into(),
        Validity::NotYetValid { days: n } => format!("NOT YET VALID (starts in {})", days(n)),
    }
}

fn describe(i: usize, c: &TokenCert) -> String {
    let s = &c.summary;
    let validity = s.validity();
    let mut flags = Vec::new();
    if !s.can_sign {
        flags.push("encryption only");
    }
    match validity {
        Validity::Expired { .. } => flags.push("EXPIRED"),
        Validity::NotYetValid { .. } => flags.push("NOT YET VALID"),
        Validity::Valid { .. } => {}
    }
    let flags = if flags.is_empty() {
        String::new()
    } else {
        format!("  [{}]", flags.join(", "))
    };
    format!(
        "{i}. {}{}\n   Issued by: {}\n   Valid until: {} ({})\n   Token: {}\n   Driver: {}{}",
        s.subject_cn,
        s.organization
            .as_ref()
            .map(|o| format!(" ({o})"))
            .unwrap_or_default(),
        s.issuer_cn,
        s.not_after.format("%d %b %Y"),
        validity_text(validity),
        c.token_label,
        c.driver.name,
        flags
    )
}

/// The fields of `certs --details`, below the short description.
fn describe_details(der: &[u8], chain: &[Vec<u8>]) -> Result<String> {
    let d = CertificateDetails::from_der(der)?;
    let mut out = Vec::new();
    let mut line = |k: &str, v: String| out.push(format!("   {k}: {v}"));
    line("Subject", d.subject.clone());
    if let Some(v) = &d.subject_serial {
        line("Subject serial number", v.clone());
    }
    if let Some(v) = &d.email {
        line("Email", v.clone());
    }
    line("Issuer", d.issuer.clone());
    line("Serial number", d.serial_hex.clone());
    line(
        "Valid",
        format!(
            "{} to {}",
            d.not_before.format("%d %b %Y %H:%M:%S UTC"),
            d.not_after.format("%d %b %Y %H:%M:%S UTC")
        ),
    );
    line("Key", d.key.clone());
    line(
        "Key usage",
        match &d.key_usage {
            Some(v) => v.join(", "),
            None => "not restricted".into(),
        },
    );
    if !d.extended_key_usage.is_empty() {
        let v: Vec<String> = d
            .extended_key_usage
            .iter()
            .map(|u| match u.name {
                Some(n) => format!("{n} ({})", u.oid),
                None => u.oid.clone(),
            })
            .collect();
        line("Extended key usage", v.join(", "));
    }
    for p in &d.policies {
        line(
            "Policy",
            match p.name {
                Some(n) => format!("{n} ({})", p.oid),
                None => p.oid.clone(),
            },
        );
    }
    line("SHA-1", d.sha1.clone());
    line("SHA-256", d.sha256.clone());
    let mut names = vec![d.name.clone()];
    for c in chain {
        names.push(CertSummary::from_der(c)?.subject_cn);
    }
    line("Chain", names.join(" <- "));
    Ok(out.join("\n"))
}

fn describe_signature(r: &SignatureReport) -> String {
    let mut out = vec![format!(
        "{}: {}",
        r.field,
        match r.status {
            Status::Valid => "VALID",
            Status::Invalid => "INVALID",
            Status::Unknown => "UNKNOWN",
        }
    )];
    let mut line = |k: &str, v: String| out.push(format!("   {k}: {v}"));
    if let Some(s) = &r.signer {
        let org = s
            .organization
            .as_ref()
            .map(|o| format!(" ({o})"))
            .unwrap_or_default();
        line("Signed by", format!("{}{org}", s.subject));
        line("Issued by", s.issuer.clone());
        line(
            "Certificate",
            format!(
                "valid {} to {}",
                s.not_before.format("%d %b %Y"),
                s.not_after.format("%d %b %Y")
            ),
        );
    } else if let Some(n) = &r.name {
        line("Signed by", format!("{n} (certificate not found)"));
    }
    if let Some(t) = r.signing_time {
        let inside = match r.time_in_validity {
            Some(true) => ", within certificate validity",
            Some(false) => ", OUTSIDE certificate validity",
            None => "",
        };
        line(
            "Signed at",
            format!(
                "{} (signer's clock{inside})",
                t.format("%Y.%m.%d %H:%M:%S %:z")
            ),
        );
    }
    if r.timestamped {
        line("Timestamp", "attached (not verified)".into());
    }
    if let Some(p) = r.certification {
        line(
            "Certifies",
            format!("level {}, {}", p.level(), describe_certification(p)),
        );
    }
    if let Some(v) = &r.reason {
        line("Reason", v.clone());
    }
    if let Some(v) = &r.location {
        line("Location", v.clone());
    }
    line(
        "Format",
        [r.sub_filter.as_deref(), r.digest_algorithm]
            .iter()
            .flatten()
            .copied()
            .collect::<Vec<_>>()
            .join(", "),
    );
    let after = match r.changes {
        Changes::None => None,
        Changes::Signatures => Some("only signatures added"),
        Changes::FormOrAnnotations => Some("form filled in or annotations changed"),
        Changes::Content => Some("CONTENT CHANGED after signing"),
        Changes::Unknown => Some("changes could not be analysed"),
    };
    line(
        "Coverage",
        match after {
            None => "whole document".into(),
            Some(what) => format!(
                "{} later revision(s), {} bytes: {what}",
                r.later_revisions,
                r.bytes_after()
            ),
        },
    );
    if !r.chain.is_empty() {
        let names: Vec<&str> = r.chain.iter().map(|c| c.subject.as_str()).collect();
        line("Chain", names.join(" <- "));
    }
    line(
        "Trust",
        match r.trust {
            Trust::CcaIndia => "chains to CCA India 2022 (revocation not checked)".into(),
            Trust::NotChecked => "not checked".into(),
        },
    );
    for n in &r.notes {
        line("Note", n.clone());
    }
    out.join("\n")
}

/// `verify-file` output: the fields of a PDF signature that apply to a file.
fn describe_file_check(c: &FileCheck, sig: &Path) -> String {
    let r = &c.report;
    let mut out = vec![format!(
        "{}: {}",
        r.field,
        match r.status {
            Status::Valid => "VALID",
            Status::Invalid => "INVALID",
            Status::Unknown => "UNKNOWN",
        }
    )];
    let mut line = |k: &str, v: String| out.push(format!("   {k}: {v}"));
    line(
        "Signature",
        format!(
            "{} ({})",
            file_name(sig),
            if c.attached {
                "attached: the file is inside"
            } else {
                "detached"
            }
        ),
    );
    if let Some(h) = &c.sha256 {
        line("SHA-256", h.clone());
    }
    if let Some(s) = &r.signer {
        let org = s
            .organization
            .as_ref()
            .map(|o| format!(" ({o})"))
            .unwrap_or_default();
        line("Signed by", format!("{}{org}", s.subject));
        line("Issued by", s.issuer.clone());
        line(
            "Certificate",
            format!(
                "valid {} to {}",
                s.not_before.format("%d %b %Y"),
                s.not_after.format("%d %b %Y")
            ),
        );
    }
    if let Some(t) = r.signing_time {
        let inside = match r.time_in_validity {
            Some(false) => ", OUTSIDE certificate validity",
            _ => "",
        };
        line(
            "Signed at",
            format!(
                "{} (signer's clock{inside})",
                t.format("%Y.%m.%d %H:%M:%S %:z")
            ),
        );
    }
    if r.timestamped {
        line("Timestamp", "attached (not verified)".into());
    }
    if let Some(d) = r.digest_algorithm {
        line("Format", format!("CMS / PKCS#7, {d}"));
    }
    if !r.chain.is_empty() {
        let names: Vec<&str> = r.chain.iter().map(|c| c.subject.as_str()).collect();
        line("Chain", names.join(" <- "));
    }
    line(
        "Trust",
        match r.trust {
            Trust::CcaIndia => "chains to CCA India 2022 (revocation not checked)".into(),
            Trust::NotChecked => "not checked".into(),
        },
    );
    for n in &r.notes {
        line("Note", n.clone());
    }
    out.join("\n")
}

/// The watch folder's side of the token: one session for the whole run.
struct WatchHost {
    signer: TokenSigner,
    signed: usize,
    history: WatchRecorder,
}

fn file_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

impl watch::Host for WatchHost {
    fn sign(&mut self, data: &[u8], req: &SignRequest) -> Result<Vec<u8>, Error> {
        let result = sign_pdf(data, req, &mut self.signer);
        let cert = self.signer.certificate().to_vec();
        self.history.signing(data, req, &cert, &result);
        result
    }
    fn check(&mut self) -> Result<(), Error> {
        self.signer.check()
    }
    fn event(&mut self, event: watch::Event) {
        if let Some(entry) = self.history.event(&event) {
            record(entry);
        }
        match event {
            watch::Event::Signed {
                input,
                output,
                warning,
                ..
            } => {
                self.signed += 1;
                println!("Signed: {} -> {}", file_name(&input), output.display());
                if let Some(w) = warning {
                    eprintln!("Warning: {}: {w}", file_name(&input));
                }
            }
            watch::Event::Failed {
                input,
                moved,
                reason,
            } => match moved {
                Some(m) => println!(
                    "Failed: {}: {reason} (moved to {})",
                    file_name(&input),
                    m.display()
                ),
                None => println!("Failed: {}: {reason}", file_name(&input)),
            },
            watch::Event::Skipped { input, reason } => {
                println!("Skipped: {}: {reason}", file_name(&input))
            }
        }
    }
}

/// Certificate `n` from the list, if it may sign: not encryption-only, not expired.
fn signing_cert(certs: &[TokenCert], n: usize) -> Result<&TokenCert> {
    let chosen = certs
        .get(n.wrapping_sub(1))
        .with_context(|| format!("no certificate #{n}; run `trackmysign certs`"))?;
    if !chosen.summary.can_sign {
        bail!("certificate #{n} is for encryption only; pick the signing certificate");
    }
    if let v @ Validity::Expired { .. } = chosen.summary.validity() {
        bail!(
            "certificate #{n} {} (valid until {}). A signature made with it is not valid; \
             renew your DSC.",
            validity_text(v).to_lowercase(),
            chosen.summary.not_after.format("%d %b %Y")
        );
    }
    Ok(chosen)
}

fn main() {
    let cli = Cli::parse();
    let target = cli.cmd.log_target();
    if let Err(e) = run(cli) {
        // Kept for `trackmysign doctor` and the app's support report.
        if let (Some((area, files, signing)), Some(dir)) = (target, app_data()) {
            let chain: Vec<String> = e.chain().skip(1).map(|c| c.to_string()).collect();
            let files: Vec<&Path> = files.iter().map(PathBuf::as_path).collect();
            let event = Event::error(area, &e.to_string(), &chain, &files, signing);
            let _ = EventLog::in_app_data(&dir).record(event);
        }
        eprintln!("Error: {e:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.cmd {
        Cmd::Certs {
            details,
            export,
            out,
            pem,
            chain,
        } => {
            let tokens = open_tokens(&cli.module)?;
            if let Some(n) = export {
                let certs = tokens.signing_certificates()?;
                let c = certs
                    .get(n.wrapping_sub(1))
                    .with_context(|| format!("no certificate #{n}; run `trackmysign certs`"))?;
                let (data, ext) = if chain {
                    let mut all = vec![c.der.clone()];
                    all.extend(complete_chain(&c.der, &tokens.chain(c)));
                    (to_p7b(&all)?, "p7b")
                } else if pem {
                    (to_pem(&c.der).into_bytes(), "pem")
                } else {
                    (c.der.clone(), "cer")
                };
                let out =
                    out.unwrap_or_else(|| export_file_name(&c.summary.subject_cn, ext).into());
                std::fs::write(&out, data).with_context(|| format!("writing {}", out.display()))?;
                println!("Saved: {}", out.display());
                return Ok(());
            }
            for t in &tokens.tokens {
                println!("Driver: {} ({})", t.driver.name, t.driver.path.display());
            }
            for (d, e) in &tokens.failed {
                println!(
                    "Driver: {} ({}) — not loaded: {e}",
                    d.name,
                    d.path.display()
                );
            }
            let certs = tokens.signing_certificates()?;
            if certs.is_empty() {
                bail!("no certificates found — is the token plugged in?");
            }
            for (i, c) in certs.iter().enumerate() {
                println!("{}", describe(i + 1, c));
                if details {
                    let chain = complete_chain(&c.der, &tokens.chain(c));
                    println!("{}", describe_details(&c.der, &chain)?);
                }
            }
        }
        Cmd::Info { pdf } => {
            let data = std::fs::read(&pdf).with_context(|| format!("reading {}", pdf.display()))?;
            let (info, _) = with_password(&pdf, cli.password.as_deref(), |pw| {
                inspect_with_password(&data, pw)
            })?;
            println!("Pages: {}", info.pages.len());
            for (i, p) in info.pages.iter().enumerate() {
                println!(
                    "  {}: {:.0} x {:.0} pt{}",
                    i + 1,
                    p.width,
                    p.height,
                    if p.rotate != 0 {
                        format!(" (rotated {})", p.rotate)
                    } else {
                        String::new()
                    }
                );
            }
            println!("Existing signatures: {}", info.signatures);
            if !info.empty_fields.is_empty() {
                println!("Empty signature fields: {}", info.empty_fields.len());
            }
            for f in &info.empty_fields {
                let place = match (f.page, f.rect) {
                    (Some(p), Some(r)) => format!(
                        "page {}, {:.0},{:.0},{:.0},{:.0}",
                        p + 1,
                        r.x,
                        r.y,
                        r.w,
                        r.h
                    ),
                    (Some(p), None) => format!("page {}, invisible", p + 1),
                    _ => "invisible".into(),
                };
                println!("  {}: {place}", f.name);
            }
            if let Some(p) = info.certified {
                println!(
                    "Certified: level {}, {}",
                    p.level(),
                    describe_certification(p)
                );
            }
            if info.encrypted {
                println!(
                    "Password-protected{}",
                    if info.signing_allowed {
                        ""
                    } else {
                        "; signing not allowed without the owner password"
                    }
                );
            }
        }
        Cmd::Sign {
            pdfs,
            out,
            page,
            pages,
            position,
            rect,
            invisible,
            field,
            reason,
            location,
            image,
            image_position,
            style,
            seal,
            cert,
            timestamp,
            ltv,
            allow_expired,
            certify,
            pin,
        } => {
            let certify = certify.map(DocMdp::from);
            if out.is_some() && pdfs.len() > 1 {
                bail!("--out works with a single PDF; signed copies go next to each original");
            }
            if let Some(url) = &timestamp
                && !url.starts_with("http://")
                && !url.starts_with("https://")
            {
                bail!("--timestamp expects an http:// or https:// address, got {url:?}");
            }
            let image = image
                .map(|p| StampImage::open(&p).with_context(|| format!("reading {}", p.display())))
                .transpose()?;
            let mut style = style
                .as_deref()
                .map(read_style)
                .transpose()?
                .unwrap_or_default();
            let seal = seal
                .map(|p| StampImage::open(&p).with_context(|| format!("reading {}", p.display())))
                .transpose()?;
            match (&seal, style.seal) {
                (Some(_), None) => style.seal = Some(Default::default()),
                (None, Some(_)) => bail!("the style shows a company seal; give it with --seal"),
                _ => {}
            }
            let single = pdfs.len() == 1;
            let mut failed = 0;
            // A bad file is reported and skipped; a single PDF fails as before.
            let mut report = |pdf: &PathBuf, e: anyhow::Error| -> Result<()> {
                if single {
                    return Err(e);
                }
                eprintln!("Failed: {}: {e:#}", pdf.display());
                failed += 1;
                Ok(())
            };

            // Read and place everything first, so problems show before the PIN prompt.
            let mut jobs = Vec::new();
            for pdf in &pdfs {
                let password = cli.password.as_deref();
                match open_for_signing(pdf, password, certify).and_then(|opened| {
                    read_and_place(
                        opened,
                        page,
                        pages.as_deref(),
                        position,
                        rect,
                        invisible,
                        field.as_deref(),
                    )
                }) {
                    Ok(job) => jobs.push((pdf, job)),
                    Err(e) => report(pdf, e)?,
                }
            }
            if jobs.is_empty() {
                bail!("none of the PDFs could be read");
            }

            let tokens = open_tokens(&cli.module)?;
            let certs = tokens.signing_certificates()?;
            let chosen = certs
                .get(cert.wrapping_sub(1))
                .with_context(|| format!("no certificate #{cert}; run `trackmysign certs`"))?;
            if !chosen.summary.can_sign {
                bail!("certificate #{cert} is for encryption only; pick the signing certificate");
            }
            match chosen.summary.validity() {
                v @ Validity::Expired { .. } if !allow_expired => bail!(
                    "certificate #{cert} {} (valid until {}). A signature made with it is not \
                     valid; renew your DSC. Use --allow-expired to sign anyway.",
                    validity_text(v).to_lowercase(),
                    chosen.summary.not_after.format("%d %b %Y")
                ),
                Validity::Expired { .. } => eprintln!(
                    "Warning: certificate #{cert} has expired; the signature will not be valid."
                ),
                v @ Validity::NotYetValid { .. } => eprintln!(
                    "Warning: certificate #{cert} is {}; check this computer's clock. \
                     The signature may not be accepted as valid.",
                    validity_text(v).to_lowercase()
                ),
                Validity::Valid { .. } => {}
            }
            println!("Signing as: {}", chosen.summary.subject_cn);
            let pin = match pin {
                Some(p) => p,
                None => rpassword::prompt_password("Token PIN: ")?,
            };
            let source = if single {
                history::Source::Manual
            } else {
                history::Source::Batch
            };
            let request = |job: &Job| SignRequest {
                page: job.page,
                rect: job.rect,
                pages: job.pages.clone(),
                reason: reason.clone(),
                location: location.clone(),
                image: image.clone(),
                image_position: match image_position {
                    ImageSide::Left => ImagePosition::Left,
                    ImageSide::Above => ImagePosition::Above,
                },
                seal: seal.clone(),
                style: style.clone(),
                timestamp: timestamp.clone(),
                ltv,
                field: field.clone(),
                password: job.password.clone(),
                certify,
                ..Default::default()
            };
            let entry = |pdf: &Path, job: &Job, req: &SignRequest| {
                let mut e = Entry::signing(source, PROGRAM, &absolute(pdf), req);
                e.input_data(&job.data);
                e.cert_der(&chosen.der);
                e
            };
            let mut signer = match tokens.signer(chosen, &pin) {
                Ok(s) => s,
                Err(e) => {
                    for (pdf, job) in &jobs {
                        record(entry(pdf, job, &request(job)).failed(e.to_string()));
                    }
                    return Err(e.into());
                }
            };
            for (pdf, job) in jobs {
                let req = request(&job);
                let entry = entry(pdf, &job, &req);
                let out = out.clone().unwrap_or_else(|| signed_path(pdf));
                let done = match sign_pdf(&job.data, &req, &mut signer) {
                    // Stop the batch: another attempt could lock the token.
                    Err(e @ (Error::WrongPin { .. } | Error::PinLocked)) => {
                        record(entry.failed(e.to_string()));
                        return Err(e.into());
                    }
                    Err(e @ Error::Timestamp(_)) => Err(anyhow::anyhow!(
                        "{e}\nNothing was saved. Run again without --timestamp to sign without one."
                    )),
                    Err(e @ Error::Ltv(_)) => Err(anyhow::anyhow!(
                        "{e}\nNothing was saved. Run again without --ltv to sign without it."
                    )),
                    r => r.map_err(anyhow::Error::from),
                }
                .and_then(|signed| {
                    std::fs::write(&out, &signed)
                        .with_context(|| format!("writing {}", out.display()))?;
                    Ok(signed)
                });
                match done {
                    Ok(signed) => {
                        record(entry.signed(&absolute(&out), &signed));
                        println!("Signed: {}", out.display())
                    }
                    Err(e) => {
                        record(entry.failed(format!("{e:#}")));
                        report(pdf, e)?
                    }
                }
            }
            if failed > 0 {
                bail!("{failed} of {} PDFs could not be signed", pdfs.len());
            }
        }
        Cmd::SignFile {
            files,
            attached,
            out,
            force,
            cert,
            timestamp,
            pin,
        } => {
            if out.is_some() && files.len() > 1 {
                bail!("--out works with a single file; signatures go next to each file");
            }
            if let Some(url) = &timestamp
                && !url.starts_with("http://")
                && !url.starts_with("https://")
            {
                bail!("--timestamp expects an http:// or https:// address, got {url:?}");
            }
            let single = files.len() == 1;
            let mut failed = 0;
            let mut report = |file: &PathBuf, e: anyhow::Error| -> Result<()> {
                if single {
                    return Err(e);
                }
                eprintln!("Failed: {}: {e:#}", file.display());
                failed += 1;
                Ok(())
            };
            // Read everything first, so problems show before the PIN prompt.
            let mut jobs = Vec::new();
            for file in &files {
                let target = out
                    .clone()
                    .unwrap_or_else(|| filesig::signature_path(file, attached));
                let read = std::fs::read(file)
                    .with_context(|| format!("reading {}", file.display()))
                    .and_then(|data| {
                        if !force && target.exists() {
                            bail!("{} already exists (--force replaces it)", target.display());
                        }
                        Ok(data)
                    });
                match read {
                    Ok(data) => jobs.push((file, data, target)),
                    Err(e) => report(file, e)?,
                }
            }
            if jobs.is_empty() {
                bail!("none of the files could be read");
            }
            let tokens = open_tokens(&cli.module)?;
            let certs = tokens.signing_certificates()?;
            let chosen = signing_cert(&certs, cert)?;
            println!("Signing as: {}", chosen.summary.subject_cn);
            let pin = Zeroizing::new(match pin {
                Some(p) => p,
                None => rpassword::prompt_password("Token PIN: ")?,
            });
            let req = FileSignRequest {
                attached,
                timestamp,
                ..Default::default()
            };
            let source = if single {
                history::Source::Manual
            } else {
                history::Source::Batch
            };
            let entry = |file: &Path, data: &[u8]| {
                let mut e = Entry::file_signing(source, PROGRAM, &absolute(file), &req);
                e.input_data(data);
                e.cert_der(&chosen.der);
                e
            };
            let mut signer = match tokens.signer(chosen, &pin) {
                Ok(s) => s,
                Err(e) => {
                    for (file, data, _) in &jobs {
                        record(entry(file, data).failed(e.to_string()));
                    }
                    return Err(e.into());
                }
            };
            drop(pin);
            for (file, data, target) in &jobs {
                let entry = entry(file, data);
                let done = match filesig::sign_file(data, &req, &mut signer) {
                    // Stop the batch: another attempt could lock the token.
                    Err(e @ (Error::WrongPin { .. } | Error::PinLocked)) => {
                        record(entry.failed(e.to_string()));
                        return Err(e.into());
                    }
                    Err(e @ Error::Timestamp(_)) => Err(anyhow::anyhow!(
                        "{e}\nNothing was saved. Run again without --timestamp to sign without one."
                    )),
                    r => r.map_err(anyhow::Error::from),
                }
                .and_then(|sig| {
                    filesig::write_signature(target, &sig, force)
                        .with_context(|| format!("writing {}", target.display()))?;
                    Ok(sig)
                });
                match done {
                    Ok(sig) => {
                        record(entry.signed(&absolute(target), &sig));
                        println!("Signed: {}", target.display())
                    }
                    Err(e) => {
                        record(entry.failed(format!("{e:#}")));
                        report(file, e)?
                    }
                }
            }
            if failed > 0 {
                bail!("{failed} of {} files could not be signed", files.len());
            }
        }
        Cmd::VerifyFile {
            file,
            sig,
            extract,
            out,
        } => {
            let read =
                |p: &Path| std::fs::read(p).with_context(|| format!("reading {}", p.display()));
            // FILE is the signature itself, or the signed file with its .p7s.
            let (sig_path, content_path) = match sig {
                Some(s) => (s, Some(file.clone())),
                None if filesig::is_signature_file(&file) => {
                    let signed = filesig::signed_file_path(&file).filter(|p| p.is_file());
                    (file.clone(), signed)
                }
                None => match filesig::find_signature(&file) {
                    Some(s) => (s, Some(file.clone())),
                    None => bail!(
                        "no signature found: {} does not exist (--sig names another one)",
                        filesig::signature_path(&file, false).display()
                    ),
                },
            };
            let der = filesig::read_signature(&read(&sig_path)?)
                .with_context(|| format!("reading {}", sig_path.display()))?;
            let inside = filesig::content(&der)?;
            // A .p7m is checked on what it carries; a separate file only
            // when named with --sig.
            let content = match (&inside, &content_path) {
                (Some(_), Some(p)) if *p == file => Some(read(p)?),
                (None, Some(p)) => Some(read(p)?),
                _ => None,
            };
            let name = file_name(content_path.as_deref().unwrap_or(&sig_path));
            let checked = filesig::verify_file(&der, content.as_deref(), &name)?;
            println!("{}", describe_file_check(&checked, &sig_path));
            if extract {
                let Some(data) = inside else {
                    bail!(
                        "{} is detached: the file is not inside it",
                        sig_path.display()
                    );
                };
                let target = out.unwrap_or_else(|| filesig::original_path(&sig_path));
                filesig::write_signature(&target, &data, false)
                    .with_context(|| format!("writing {}", target.display()))?;
                println!("Saved: {}", target.display());
            }
            if checked.report.status != Status::Valid {
                std::process::exit(2);
            }
        }
        Cmd::Watch {
            folder,
            out,
            preset_json,
            pages,
            reason,
            location,
            image,
            style,
            seal,
            invisible,
            keep_originals,
            daily_limit,
            hours,
            timestamp,
            ltv,
            cert,
            pin,
        } => {
            let mut preset: watch::Preset = match &preset_json {
                Some(p) => {
                    let data =
                        std::fs::read(p).with_context(|| format!("reading {}", p.display()))?;
                    serde_json::from_slice(&data)
                        .with_context(|| format!("{} is not a preset", p.display()))?
                }
                None => watch::Preset {
                    reason: "Approved".into(),
                    ..Default::default()
                },
            };
            if let Some(v) = pages {
                preset.pages = v;
            }
            if let Some(v) = reason {
                preset.reason = v;
            }
            if let Some(v) = location {
                preset.location = v;
            }
            preset.invisible |= invisible;
            if timestamp.is_some() {
                preset.timestamp = timestamp;
            }
            preset.ltv |= ltv;
            preset.validate().map_err(anyhow::Error::msg)?;
            let image = match &image {
                Some(p) => {
                    if preset.image == watch::ImageChoice::Off {
                        preset.image = watch::ImageChoice::Left;
                    }
                    Some(StampImage::open(p).with_context(|| format!("reading {}", p.display()))?)
                }
                None if preset.image == watch::ImageChoice::Off => None,
                None => bail!("the preset shows a signature image; give it with --image"),
            };
            if let Some(p) = &style {
                preset.style = Some(read_style(p)?);
            }
            let seal = match &seal {
                Some(p) => {
                    let style = preset.style.get_or_insert_with(Default::default);
                    style.seal.get_or_insert_with(Default::default);
                    Some(StampImage::open(p).with_context(|| format!("reading {}", p.display()))?)
                }
                None if preset.shows_seal() => {
                    bail!("the style shows a company seal; give it with --seal")
                }
                None => None,
            };
            let folders = watch::Folders::new(&folder, out.as_deref(), !keep_originals)
                .map_err(anyhow::Error::msg)?;
            let opts = watch::Options {
                daily_limit: (daily_limit > 0).then_some(daily_limit),
                until: hours.map(|h| SystemTime::now() + Duration::from_secs_f64(h * 3600.0)),
                ..Default::default()
            };

            let tokens = open_tokens(&cli.module)?;
            let certs = tokens.signing_certificates()?;
            let chosen = signing_cert(&certs, cert)?;
            println!("Signing as: {}", chosen.summary.subject_cn);
            let pin = Zeroizing::new(match pin {
                Some(p) => p,
                None => rpassword::prompt_password("Token PIN: ")?,
            });
            let signer = tokens.signer(chosen, &pin)?;
            drop(pin);

            let control = Arc::new(watch::Control::default());
            let stop = control.clone();
            ctrlc::set_handler(move || stop.stop()).context("setting the Ctrl+C handler")?;
            println!("Watching: {}", folders.input.display());
            println!("Signed copies: {}", folders.output.display());
            match &folders.done {
                Some(d) => println!("Originals: {}", d.display()),
                None => println!("Originals: left in place"),
            }
            println!("Not signed: {}", folders.failed.display());
            println!(
                "Anyone who can write to this folder can now get documents signed with your DSC. \
                 Press Ctrl+C to stop."
            );
            let mut host = WatchHost {
                signer,
                signed: 0,
                history: WatchRecorder::new(PROGRAM),
            };
            let end = watch::run(
                &folders,
                &preset,
                image.as_ref(),
                seal.as_ref(),
                &opts,
                &control,
                &mut host,
            );
            if let Some(entry) = host.history.stopped(&folders.input, &end) {
                record(entry);
            }
            let signed = host.signed;
            // Closes the session and wipes a PIN kept for keys that ask on every signature.
            drop(host);
            match end {
                watch::Stop::Token(_) | watch::Stop::Folder(_) => {
                    bail!("{end} Stopped watching; {signed} file(s) signed.")
                }
                _ => println!("{end} {signed} file(s) signed."),
            }
        }
        Cmd::Pages { op } => pages(op, cli.password.as_deref())?,
        Cmd::Verify { pdf, report, json } => {
            let data = std::fs::read(&pdf).with_context(|| format!("reading {}", pdf.display()))?;
            let name = pdf
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let (checked, _) = with_password(&pdf, cli.password.as_deref(), |pw| {
                Report::new(&data, &name, pw, env!("CARGO_PKG_VERSION"))
            })?;
            if json {
                println!("{}", checked.to_json());
            } else {
                if checked.signatures.is_empty() {
                    println!("No signatures found.");
                }
                for r in &checked.signatures {
                    println!("{}", describe_signature(r));
                }
            }
            if let Some(path) = &report {
                std::fs::write(path, checked.to_pdf())
                    .with_context(|| format!("writing {}", path.display()))?;
                if !json {
                    println!("Report: {}", path.display());
                }
            }
            if checked
                .signatures
                .iter()
                .any(|r| r.status == Status::Invalid || r.changes == Changes::Content)
            {
                std::process::exit(2);
            }
        }
        Cmd::VerifyFolder {
            dir,
            recursive,
            report,
            csv,
            json,
            require_signed,
        } => {
            let options = Options {
                recursive,
                password: cli.password.clone(),
            };
            let total = std::sync::atomic::AtomicUsize::new(0);
            let done = std::sync::atomic::AtomicUsize::new(0);
            let counting = std::io::stderr().is_terminal();
            let stop = std::sync::atomic::AtomicBool::new(false);
            let checked =
                folder::verify_folder(&dir, &options, env!("CARGO_PKG_VERSION"), &stop, |p| {
                    use std::sync::atomic::Ordering::Relaxed;
                    match p {
                        Progress::Found(files) => total.store(files.len(), Relaxed),
                        Progress::Checked(..) if counting => {
                            let n = done.fetch_add(1, Relaxed) + 1;
                            eprint!("\rChecked {n} of {}", total.load(Relaxed));
                        }
                        Progress::Checked(..) => {}
                    }
                })
                .with_context(|| format!("reading {}", dir.display()))?;
            if counting && !checked.files.is_empty() {
                eprintln!();
            }
            if json {
                println!("{}", checked.to_json());
            } else {
                for f in &checked.files {
                    println!("{}", describe_file(f));
                }
                println!("{}", checked.summary());
            }
            for (path, contents, what) in [
                (&report, checked.to_pdf(), "Report"),
                (&csv, checked.to_csv().into_bytes(), "CSV"),
            ] {
                if let Some(path) = path {
                    std::fs::write(path, contents)
                        .with_context(|| format!("writing {}", path.display()))?;
                    if !json {
                        println!("{what}: {}", path.display());
                    }
                }
            }
            if !checked.passed(require_signed) {
                std::process::exit(2);
            }
        }
        Cmd::History {
            since,
            until,
            source,
            outcome,
            search,
            json,
            csv,
            report,
        } => {
            let store = history_store().context("this computer has no data folder")?;
            let entries = store
                .entries()
                .with_context(|| format!("reading {}", store.dir().display()))?;
            let integrity = store
                .check()
                .with_context(|| format!("reading {}", store.dir().display()))?;
            let filter = Filter {
                since: since.map(local_midnight),
                until: until.and_then(|d| d.succ_opt()).map(local_midnight),
                source: source.map(|s| match s {
                    HistorySource::Manual => history::Source::Manual,
                    HistorySource::Batch => history::Source::Batch,
                    HistorySource::Watch => history::Source::Watch,
                    HistorySource::Portal => history::Source::Portal,
                }),
                outcome: outcome.map(|o| match o {
                    HistoryOutcome::Signed => history::Outcome::Signed,
                    HistoryOutcome::Failed => history::Outcome::Failed,
                }),
                text: search,
            };
            let shown = filter.apply(&entries);
            if json {
                println!(
                    "{}",
                    history::to_json(&shown, &integrity, env!("CARGO_PKG_VERSION"))
                );
            } else if csv {
                print!("{}", history::to_csv(&shown));
            } else {
                println!("History: {}", store.dir().display());
                if !store.settings().enabled {
                    println!("Recording is turned off (desktop app: Settings → Signing history).");
                }
                if shown.is_empty() {
                    println!("No entries.");
                }
                for e in &shown {
                    println!("{}", describe_entry(e));
                }
                println!("{}", integrity.summary());
            }
            for p in &integrity.problems {
                eprintln!("Problem: {p}");
            }
            if let Some(path) = &report {
                let scope = if shown.len() == entries.len() {
                    "All entries".to_string()
                } else {
                    format!("{} of {} entries (filtered)", shown.len(), entries.len())
                };
                let pdf = history::to_pdf(
                    &shown,
                    &scope,
                    Some(&integrity),
                    env!("CARGO_PKG_VERSION"),
                    chrono::Utc::now(),
                );
                std::fs::write(path, pdf).with_context(|| format!("writing {}", path.display()))?;
                if !json && !csv {
                    println!("Report: {}", path.display());
                }
            }
            if !integrity.ok() {
                std::process::exit(2);
            }
        }
        Cmd::Doctor {
            json,
            include_names,
            include_serials,
            include_paths,
        } => {
            let include = support::Include {
                names: include_names,
                serials: include_serials,
                paths: include_paths,
            };
            let drivers = match &cli.module {
                Some(m) => vec![Driver {
                    name: driver_name(m),
                    path: m.clone(),
                }],
                None => installed_drivers(),
            };
            let probes = support::probe(&drivers);
            let data = app_data();
            let ctx = support::Context {
                app: support::AppInfo {
                    version: env!("CARGO_PKG_VERSION").into(),
                    build: "command line".into(),
                },
                system: support::SystemInfo::this_computer(),
                settings: data
                    .as_deref()
                    .map(|d| support::SettingsInfo::from_app_data(d, include)),
                portal: None,
                updater: None,
                events: data
                    .map(|d| EventLog::in_app_data(&d).events())
                    .unwrap_or_default(),
            };
            let report = support::build(
                ctx,
                &probes,
                include,
                &support::Redactor::for_user(),
                chrono::Utc::now(),
            );
            if json {
                println!("{}", report.to_json());
            } else {
                print!("{}", report.to_text());
                eprintln!(
                    "\nNothing was sent. Read the report, then paste it into a new issue:\n{}",
                    support::issue_url(env!("CARGO_PKG_VERSION"))
                );
            }
        }
    }
    Ok(())
}

/// `trackmysign pages …`: reads the sources, works out the new page order,
/// warns about what will not carry over and writes the new file.
fn pages(op: PagesCmd, password: Option<&str>) -> Result<()> {
    let (paths, out) = match &op {
        PagesCmd::Merge { pdfs, out } => (pdfs.clone(), out),
        PagesCmd::Select { pdf, out, .. }
        | PagesCmd::Rotate { pdf, out, .. }
        | PagesCmd::Delete { pdf, out, .. }
        | PagesCmd::InsertBlank { pdf, out, .. } => (vec![pdf.clone()], out),
    };
    let target = out
        .out
        .clone()
        .unwrap_or_else(|| assemble::prepared_path(&paths[0]));
    let same = |a: &Path, b: &Path| match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    };
    if let Some(p) = paths.iter().find(|p| same(p, &target)) {
        bail!(
            "{} is one of the inputs; the original is never changed (--out)",
            p.display()
        );
    }
    let data = paths
        .iter()
        .map(|p| std::fs::read(p).with_context(|| format!("reading {}", p.display())))
        .collect::<Result<Vec<_>>>()?;
    let docs = paths
        .iter()
        .zip(&data)
        .map(|(p, d)| {
            with_password(p, password, |pw| assemble::open(d, pw).map_err(Error::from))
                .map(|(doc, _)| doc)
                .with_context(|| p.display().to_string())
        })
        .collect::<Result<Vec<_>>>()?;
    let pages: Vec<_> = docs.iter().map(|d| d.pages()).collect::<Result<_, _>>()?;
    let all = |s: usize| {
        (0..pages[s].len()).map(move |page| Item::Page {
            source: s,
            page,
            rotate: 0,
        })
    };
    let count = pages[0].len();
    let items: Vec<Item> = match &op {
        PagesCmd::Merge { .. } => (0..docs.len()).flat_map(all).collect(),
        PagesCmd::Select { pages: spec, .. } => assemble::parse_selection(spec, count)
            .map_err(anyhow::Error::msg)?
            .into_iter()
            .map(|page| Item::Page {
                source: 0,
                page,
                rotate: 0,
            })
            .collect(),
        PagesCmd::Rotate {
            angle, pages: spec, ..
        } => {
            if angle % 90 != 0 {
                bail!("pages turn by 90, 180 or 270 degrees");
            }
            let turn = match spec {
                Some(spec) => parse_pages(spec, count).map_err(anyhow::Error::msg)?,
                None => (0..count).collect(),
            };
            (0..count)
                .map(|page| Item::Page {
                    source: 0,
                    page,
                    rotate: if turn.contains(&page) { *angle } else { 0 },
                })
                .collect()
        }
        PagesCmd::Delete { pages: spec, .. } => {
            let gone = parse_pages(spec, count).map_err(anyhow::Error::msg)?;
            if gone.len() == count {
                bail!("that would delete every page");
            }
            all(0)
                .filter(|i| !matches!(i, Item::Page { page, .. } if gone.contains(page)))
                .collect()
        }
        PagesCmd::InsertBlank { after, size, .. } => {
            if *after > count {
                bail!("the PDF has only {count} page(s)");
            }
            let (width, height) = match size {
                BlankSize::A4 => (595.28, 841.89),
                BlankSize::Letter => (612.0, 792.0),
                BlankSize::Same => pages[0][after.saturating_sub(1)].display_size(),
            };
            let mut items: Vec<Item> = all(0).collect();
            items.insert(*after, Item::Blank { width, height });
            items
        }
    };

    let names: Vec<String> = paths
        .iter()
        .map(|p| {
            p.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
        })
        .collect();
    let mut signed = false;
    for (i, doc) in docs.iter().enumerate() {
        for n in assemble::notices(i, doc)? {
            if matches!(n, Notice::SignaturesRemoved { .. }) {
                signed = true;
                eprintln!("Warning: {}", n.describe(&names));
            }
        }
    }
    if signed && !out.yes {
        if !std::io::stdin().is_terminal() {
            bail!("not written: a source PDF is signed (--yes to go ahead)");
        }
        eprint!("Write the new file without these signatures? [y/N] ");
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if !matches!(answer.trim(), "y" | "Y" | "yes") {
            bail!("not written");
        }
    }
    let made = assemble::assemble(&docs, &items)?;
    for n in &made.notices {
        if !matches!(n, Notice::SignaturesRemoved { .. }) {
            eprintln!("Note: {}", n.describe(&names));
        }
    }
    std::fs::write(&target, &made.data).with_context(|| format!("writing {}", target.display()))?;
    println!(
        "Saved: {} ({} page{})",
        target.display(),
        items.len(),
        if items.len() == 1 { "" } else { "s" }
    );
    Ok(())
}

/// "INVALID SIGNATURE  sub/invoice.pdf  (2 signatures: A, B)".
fn describe_file(f: &FileResult) -> String {
    let detail = match (&f.error, f.signatures().len()) {
        (Some(e), _) if f.status == FileStatus::NeedsPassword => format!("{e} (--password)"),
        (Some(e), _) => e.clone(),
        (None, 0) => String::new(),
        (None, n) => format!(
            "{} signature{}: {}",
            n,
            if n == 1 { "" } else { "s" },
            f.signers().join(", ")
        ),
    };
    let line = format!("{:<22} {}", f.status.label().to_uppercase(), f.relative);
    if detail.is_empty() {
        line
    } else {
        format!("{line}  ({detail})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The command line writes to the history the desktop app reads: Tauri's
    /// `app_data_dir` is `dirs::data_dir()` joined with the identifier.
    #[test]
    fn history_is_in_the_apps_data_folder() {
        let conf: serde_json::Value = serde_json::from_str(include_str!(
            "../../../apps/desktop/src-tauri/tauri.conf.json"
        ))
        .unwrap();
        assert_eq!(conf["identifier"], history::APP_ID);
        assert_eq!(
            history_store().unwrap().dir(),
            dirs::data_dir()
                .unwrap()
                .join("in.trackmytech.trackmysign")
                .join("history")
        );
    }

    #[test]
    fn validity_wording() {
        let t = |v| validity_text(v);
        assert_eq!(t(Validity::Valid { days_left: 12 }), "expires in 12 days");
        assert_eq!(t(Validity::Valid { days_left: 1 }), "expires in 1 day");
        assert_eq!(
            t(Validity::Valid { days_left: 0 }),
            "expires in less than a day"
        );
        assert_eq!(t(Validity::Expired { days: 3 }), "EXPIRED 3 days ago");
        assert_eq!(t(Validity::Expired { days: 0 }), "EXPIRED today");
        assert_eq!(
            t(Validity::NotYetValid { days: 2 }),
            "NOT YET VALID (starts in 2 days)"
        );
    }
}
