//! `trackmysign` command-line tool — the test-phase front end for the core library.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use signdesk_core::token::{Driver, TokenCert, Tokens, driver_name};
use signdesk_core::verify::{Changes, SignatureReport, Status, Trust};
use signdesk_core::{
    DEFAULT_TSA_URL, DisplayRect, Error, ImagePosition, SignRequest, StampImage, inspect,
    parse_pages, sign_pdf, signed_path, verify,
};

#[derive(Parser)]
#[command(name = "trackmysign", version, about = "Sign PDFs with your DSC token")]
struct Cli {
    /// PKCS#11 driver of the token. If omitted, every known driver is tried,
    /// or the ones listed in TRACKMYSIGN_PKCS11_MODULE.
    #[arg(long, global = true)]
    module: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
// Parsed once at startup, so the size of Sign does not matter.
#[allow(clippy::large_enum_variant)]
enum Cmd {
    /// List certificates on the connected token(s).
    Certs,
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
        /// Which certificate to use (number from `trackmysign certs`).
        #[arg(long, default_value_t = 1)]
        cert: usize,
        /// Add a trusted timestamp from this RFC 3161 server (needs the internet).
        #[arg(long, value_name = "URL", num_args = 0..=1, default_missing_value = DEFAULT_TSA_URL)]
        timestamp: Option<String>,
        /// Embed revocation info (OCSP/CRL) for long-term validation (needs the internet).
        #[arg(long)]
        ltv: bool,
        /// PIN (for scripted tests only; normally you are prompted).
        #[arg(long, env = "TRACKMYSIGN_PIN", hide = true)]
        pin: Option<String>,
    },
    /// Check the signatures in a PDF. Exits with status 2 if any signature is
    /// invalid or the content was changed after signing.
    Verify { pdf: PathBuf },
}

#[derive(Clone, Copy, ValueEnum)]
enum Corner {
    BottomRight,
    BottomLeft,
    TopRight,
    TopLeft,
}

#[derive(Clone, Copy, ValueEnum)]
enum ImageSide {
    Left,
    Above,
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
}

/// Reads `pdf` and works out the page index, the extra pages and the box for it.
fn read_and_place(
    pdf: &PathBuf,
    page: Option<usize>,
    pages: Option<&str>,
    position: Corner,
    rect: Option<DisplayRect>,
    invisible: bool,
    field: Option<&str>,
) -> Result<Job> {
    let data = std::fs::read(pdf).with_context(|| format!("reading {}", pdf.display()))?;
    let info = inspect(&data)?;
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

fn describe(i: usize, c: &TokenCert) -> String {
    let s = &c.summary;
    let mut flags = Vec::new();
    if !s.can_sign {
        flags.push("encryption only");
    }
    if s.expired {
        flags.push("EXPIRED");
    }
    let flags = if flags.is_empty() {
        String::new()
    } else {
        format!("  [{}]", flags.join(", "))
    };
    format!(
        "{i}. {}{}\n   Issued by: {}\n   Valid until: {}\n   Token: {}\n   Driver: {}{}",
        s.subject_cn,
        s.organization
            .as_ref()
            .map(|o| format!(" ({o})"))
            .unwrap_or_default(),
        s.issuer_cn,
        s.not_after.format("%d %b %Y"),
        c.token_label,
        c.driver.name,
        flags
    )
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

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Certs => {
            let tokens = open_tokens(&cli.module)?;
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
            }
        }
        Cmd::Info { pdf } => {
            let data = std::fs::read(&pdf).with_context(|| format!("reading {}", pdf.display()))?;
            let info = inspect(&data)?;
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
            cert,
            timestamp,
            ltv,
            pin,
        } => {
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
                match read_and_place(
                    pdf,
                    page,
                    pages.as_deref(),
                    position,
                    rect,
                    invisible,
                    field.as_deref(),
                ) {
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
            println!("Signing as: {}", chosen.summary.subject_cn);
            let pin = match pin {
                Some(p) => p,
                None => rpassword::prompt_password("Token PIN: ")?,
            };
            let mut signer = tokens.signer(chosen, &pin)?;
            for (pdf, job) in jobs {
                let req = SignRequest {
                    page: job.page,
                    rect: job.rect,
                    pages: job.pages,
                    reason: reason.clone(),
                    location: location.clone(),
                    image: image.clone(),
                    image_position: match image_position {
                        ImageSide::Left => ImagePosition::Left,
                        ImageSide::Above => ImagePosition::Above,
                    },
                    timestamp: timestamp.clone(),
                    ltv,
                    field: field.clone(),
                    ..Default::default()
                };
                let out = out.clone().unwrap_or_else(|| signed_path(pdf));
                let done = match sign_pdf(&job.data, &req, &mut signer) {
                    Err(e @ Error::Timestamp(_)) => Err(anyhow::anyhow!(
                        "{e}\nNothing was saved. Run again without --timestamp to sign without one."
                    )),
                    Err(e @ Error::Ltv(_)) => Err(anyhow::anyhow!(
                        "{e}\nNothing was saved. Run again without --ltv to sign without it."
                    )),
                    r => r.map_err(anyhow::Error::from),
                }
                .and_then(|signed| {
                    std::fs::write(&out, signed)
                        .with_context(|| format!("writing {}", out.display()))
                });
                match done {
                    Ok(()) => println!("Signed: {}", out.display()),
                    Err(e) => report(pdf, e)?,
                }
            }
            if failed > 0 {
                bail!("{failed} of {} PDFs could not be signed", pdfs.len());
            }
        }
        Cmd::Verify { pdf } => {
            let data = std::fs::read(&pdf).with_context(|| format!("reading {}", pdf.display()))?;
            let reports = verify(&data)?;
            if reports.is_empty() {
                println!("No signatures found.");
            }
            for r in &reports {
                println!("{}", describe_signature(r));
            }
            if reports
                .iter()
                .any(|r| r.status == Status::Invalid || r.changes == Changes::Content)
            {
                std::process::exit(2);
            }
        }
    }
    Ok(())
}
