//! Form filling: the fields of the open PDF, and a filled-in copy saved
//! without signing (signing fills them in through `SignArgs::fill`).

use std::path::PathBuf;

use serde::Serialize;
use trackmysign_core::{FillValue, Form, fill_form, read_form};

use super::{CmdResult, CommandError, output};

/// The fillable fields, in tab order; none when the PDF has no form.
#[tauri::command]
pub fn form_fields(path: String, password: Option<String>) -> CmdResult<Form> {
    let data = std::fs::read(&path)?;
    Ok(read_form(&data, password.as_deref())?)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FilledDto {
    output: String,
    name: String,
    /// A font replaced, text transliterated for display.
    warnings: Vec<String>,
}

/// Saves `<name>_filled.pdf`; the original is not changed. `break_locks`
/// fills fields locked by a signature too (the user agreed it breaks).
#[tauri::command]
pub async fn save_filled(
    path: String,
    password: Option<String>,
    values: Vec<FillValue>,
    break_locks: bool,
    out_dir: Option<String>,
) -> CmdResult<FilledDto> {
    tauri::async_runtime::spawn_blocking(move || {
        let input = PathBuf::from(&path);
        let data = std::fs::read(&input)?;
        let filled = fill_form(&data, password.as_deref(), &values, break_locks)?;
        let out = output::write_filled(&input, out_dir.as_deref(), &filled.data)?;
        Ok(FilledDto {
            name: out
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            output: out.to_string_lossy().into_owned(),
            warnings: filled.warnings,
        })
    })
    .await
    .map_err(|e| CommandError {
        kind: "other",
        message: e.to_string(),
    })?
}
