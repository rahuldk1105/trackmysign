//! `trackmysign` command-line tool — the test-phase front end for the core library.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use signdesk_core::token::{Token, TokenCert};
use signdesk_core::{
    DisplayRect, ImagePosition, SignRequest, StampImage, inspect, sign_pdf, signed_path,
};

#[derive(Parser)]
#[command(name = "trackmysign", version, about = "Sign PDFs with your DSC token")]
struct Cli {
    /// PKCS#11 driver of the token (auto-detected if omitted).
    #[arg(long, global = true, env = "TRACKMYSIGN_PKCS11_MODULE")]
    module: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// List certificates on the connected token(s).
    Certs,
    /// Show page count, page sizes and existing signatures.
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
        /// Where on the page the box goes.
        #[arg(long, value_enum, default_value_t = Corner::BottomRight)]
        position: Corner,
        /// Exact box in points from the top-left of the page: x,y,width,height.
        #[arg(long, value_parser = parse_rect)]
        rect: Option<DisplayRect>,
        /// Make the signature invisible (no box on the page).
        #[arg(long)]
        invisible: bool,
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
        /// PIN (for scripted tests only; normally you are prompted).
        #[arg(long, env = "TRACKMYSIGN_PIN", hide = true)]
        pin: Option<String>,
    },
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

/// Reads `pdf` and works out the page index and box for it.
fn read_and_place(
    pdf: &PathBuf,
    page: Option<usize>,
    position: Corner,
    rect: Option<DisplayRect>,
    invisible: bool,
) -> Result<(Vec<u8>, usize, Option<DisplayRect>)> {
    let data = std::fs::read(pdf).with_context(|| format!("reading {}", pdf.display()))?;
    let info = inspect(&data)?;
    let page_idx = match page {
        Some(0) => bail!("pages are numbered from 1"),
        Some(n) if n > info.pages.len() => {
            bail!("the PDF has only {} page(s)", info.pages.len())
        }
        Some(n) => n - 1,
        None => info.pages.len() - 1,
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
    Ok((data, page_idx, rect))
}

fn open_token(module: &Option<PathBuf>) -> Result<Token> {
    Ok(match module {
        Some(m) => Token::open(m)?,
        None => Token::open_default()?,
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
        "{i}. {}{}\n   Issued by: {}\n   Valid until: {}\n   Token: {}{}",
        s.subject_cn,
        s.organization
            .as_ref()
            .map(|o| format!(" ({o})"))
            .unwrap_or_default(),
        s.issuer_cn,
        s.not_after.format("%d %b %Y"),
        c.token_label,
        flags
    )
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
            let token = open_token(&cli.module)?;
            println!("Driver: {}", token.module.display());
            let certs = token.signing_certificates()?;
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
        }
        Cmd::Sign {
            pdfs,
            out,
            page,
            position,
            rect,
            invisible,
            reason,
            location,
            image,
            image_position,
            cert,
            pin,
        } => {
            if out.is_some() && pdfs.len() > 1 {
                bail!("--out works with a single PDF; signed copies go next to each original");
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
                match read_and_place(pdf, page, position, rect, invisible) {
                    Ok((data, page, rect)) => jobs.push((pdf, data, page, rect)),
                    Err(e) => report(pdf, e)?,
                }
            }
            if jobs.is_empty() {
                bail!("none of the PDFs could be read");
            }

            let token = open_token(&cli.module)?;
            let certs = token.signing_certificates()?;
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
            let mut signer = token.signer(chosen, &pin)?;
            for (pdf, data, page, rect) in jobs {
                let req = SignRequest {
                    page,
                    rect,
                    reason: reason.clone(),
                    location: location.clone(),
                    image: image.clone(),
                    image_position: match image_position {
                        ImageSide::Left => ImagePosition::Left,
                        ImageSide::Above => ImagePosition::Above,
                    },
                    ..Default::default()
                };
                let out = out.clone().unwrap_or_else(|| signed_path(pdf));
                let done = sign_pdf(&data, &req, &mut signer)
                    .map_err(anyhow::Error::from)
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
    }
    Ok(())
}
