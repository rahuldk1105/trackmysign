//! Empty signature fields drawn in the app for others to sign later
//! (`trackmysign_core::add_signature_fields`), saved as a new file. The
//! original is only read.

use std::path::Path;

use serde::Deserialize;
use trackmysign_core::{DisplayRect, FieldLock, NewField, add_signature_fields};

use super::{CmdResult, CommandError, RectArg};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind", content = "fields")]
pub enum LockArg {
    All,
    Fields(Vec<String>),
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldArg {
    name: String,
    page: usize,
    /// Points from the top-left of the displayed page.
    rect: RectArg,
    #[serde(default)]
    tooltip: Option<String>,
    /// Place in the signing order, from 1.
    #[serde(default)]
    order: Option<u32>,
    #[serde(default)]
    lock: Option<LockArg>,
    /// Ask for adbe.pkcs7.detached with SHA-256.
    #[serde(default)]
    seed: bool,
}

pub fn new_fields(args: Vec<FieldArg>) -> Vec<NewField> {
    args.into_iter()
        .map(|f| NewField {
            name: f.name.trim().to_string(),
            page: f.page,
            rect: DisplayRect {
                x: f.rect.x,
                y: f.rect.y,
                w: f.rect.w,
                h: f.rect.h,
            },
            tooltip: f.tooltip.filter(|t| !t.trim().is_empty()),
            order: f.order,
            lock: f.lock.map(|l| match l {
                LockArg::All => FieldLock::All,
                LockArg::Fields(f) => FieldLock::Fields(f),
            }),
            seed: f.seed,
        })
        .collect()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddFieldsArgs {
    path: String,
    /// As entered when opening the PDF; kept in memory only.
    password: Option<String>,
    fields: Vec<FieldArg>,
    /// Chosen in the save dialog, which asked before replacing a file.
    output: String,
}

/// Writes the PDF with the new fields to `output`, never over the original.
#[tauri::command]
pub async fn add_fields(args: AddFieldsArgs) -> CmdResult<String> {
    tauri::async_runtime::spawn_blocking(move || {
        let output = Path::new(&args.output);
        let same = match (Path::new(&args.path).canonicalize(), output.canonicalize()) {
            (Ok(a), Ok(b)) => a == b,
            _ => Path::new(&args.path) == output,
        };
        if same {
            return Err(CommandError {
                kind: "io",
                message: "Save the PDF with the fields under another name: the original is never changed."
                    .into(),
            });
        }
        let data = std::fs::read(&args.path)?;
        let made = add_signature_fields(&data, args.password.as_deref(), &new_fields(args.fields))?;
        std::fs::write(output, made)?;
        Ok(args.output)
    })
    .await
    .map_err(|e| CommandError {
        kind: "other",
        message: e.to_string(),
    })?
}

#[cfg(test)]
mod tests {
    use super::*;

    /// As `api.ts` sends them.
    #[test]
    fn fields_from_the_front_end() {
        let args: Vec<FieldArg> = serde_json::from_str(
            r#"[
                {"name": " Director ", "page": 1, "rect": {"x": 40, "y": 60, "w": 200, "h": 60},
                 "tooltip": "Director (Rahul)", "order": 1, "lock": {"kind": "all"}, "seed": true},
                {"name": "Auditor", "page": 0, "rect": {"x": 1, "y": 2, "w": 3, "h": 4},
                 "tooltip": " ", "order": null, "lock": {"kind": "fields", "fields": ["Director"]}, "seed": false}
            ]"#,
        )
        .unwrap();
        let f = new_fields(args);
        assert_eq!(f[0].name, "Director");
        assert_eq!((f[0].page, f[0].rect.w, f[0].order), (1, 200.0, Some(1)));
        assert_eq!(f[0].lock, Some(FieldLock::All));
        assert!(f[0].seed);
        assert_eq!(f[1].tooltip, None);
        assert_eq!(f[1].lock, Some(FieldLock::Fields(vec!["Director".into()])));
    }
}
