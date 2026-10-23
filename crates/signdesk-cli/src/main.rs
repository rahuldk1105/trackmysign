//! `trackmysign` command-line tool — the test-phase front end for the core library.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use signdesk_core::token::{Token, TokenCert};
use signdesk_core::verify::{Changes, SignatureReport, Status, Trust};
use signdesk_core::{DisplayRect, SignRequest, inspect, sign_pdf, signed_path, verify};

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
    /// Sign a PDF. Writes <name>_signed.pdf next to it unless --out is given.
    Sign {
        pdf: PathBuf,
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
        /// Which certificate to use (number from `trackmysign certs`).
        #[arg(long, default_value_t = 1)]
        cert: usize,
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
            pdf,
            out,
            page,
            position,
            rect,
            invisible,
            reason,
            location,
            cert,
            pin,
        } => {
            let data = std::fs::read(&pdf).with_context(|| format!("reading {}", pdf.display()))?;
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
            let req = SignRequest {
                page: page_idx,
                rect,
                reason,
                location,
                time: None,
            };
            let signed = sign_pdf(&data, &req, &mut signer)?;
            let out = out.unwrap_or_else(|| signed_path(&pdf));
            std::fs::write(&out, signed).with_context(|| format!("writing {}", out.display()))?;
            println!("Signed: {}", out.display());
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
