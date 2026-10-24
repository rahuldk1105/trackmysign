//! Page tools: pages of one or more PDFs put together into a new file
//! (`trackmysign_core::pdf::assemble`) to prepare it for signing. The
//! sources are only read; the new file is never one of them.

use std::path::Path;

use serde::{Deserialize, Serialize};
use trackmysign_core::Error;
use trackmysign_core::pdf::assemble::{self, Item, Notice};

use super::{CmdResult, CommandError};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceArg {
    path: String,
    /// Kept in memory only.
    password: Option<String>,
}

/// What using a PDF as a source loses (its signatures, its password, its
/// bookmarks); checked when it is added, so the user is warned before saving.
#[tauri::command]
pub async fn pages_source(path: String, password: Option<String>) -> CmdResult<Vec<Notice>> {
    tauri::async_runtime::spawn_blocking(move || {
        let data = std::fs::read(&path)?;
        let doc = assemble::open(&data, password.as_deref()).map_err(Error::from)?;
        Ok(assemble::notices(0, &doc).map_err(Error::from)?)
    })
    .await
    .map_err(|e| CommandError {
        kind: "other",
        message: e.to_string(),
    })?
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssembleArgs {
    sources: Vec<SourceArg>,
    items: Vec<Item>,
    /// Chosen in the save dialog, which asked before replacing a file.
    output: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssembledDto {
    output: String,
    notices: Vec<Notice>,
}

/// Writes the new PDF to `output`.
#[tauri::command]
pub async fn assemble_pages(args: AssembleArgs) -> CmdResult<AssembledDto> {
    tauri::async_runtime::spawn_blocking(move || {
        let output = Path::new(&args.output);
        let same = |p: &str| match (Path::new(p).canonicalize(), output.canonicalize()) {
            (Ok(a), Ok(b)) => a == b,
            _ => Path::new(p) == output,
        };
        if args.sources.iter().any(|s| same(&s.path)) {
            return Err(CommandError {
                kind: "io",
                message: "Save the new PDF under another name: the original is never changed."
                    .into(),
            });
        }
        let data = args
            .sources
            .iter()
            .map(|s| std::fs::read(&s.path))
            .collect::<std::io::Result<Vec<_>>>()?;
        let docs = args
            .sources
            .iter()
            .zip(&data)
            .map(|(s, d)| assemble::open(d, s.password.as_deref()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(Error::from)?;
        let made = assemble::assemble(&docs, &args.items).map_err(Error::from)?;
        std::fs::write(output, &made.data)?;
        Ok(AssembledDto {
            output: args.output,
            notices: made.notices,
        })
    })
    .await
    .map_err(|e| CommandError {
        kind: "other",
        message: e.to_string(),
    })?
}
