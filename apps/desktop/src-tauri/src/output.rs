//! Where signed copies are written: next to the original, or in the folder
//! chosen in Settings. An existing file is never overwritten.

use std::path::{Path, PathBuf};

use trackmysign_core::{write_copy_in, write_signed_in};

use super::{CmdResult, CommandError};

/// The chosen folder, or the original's; a chosen folder that is gone is an error.
fn target_dir(input: &Path, folder: Option<&str>) -> CmdResult<PathBuf> {
    match folder.map(str::trim).filter(|f| !f.is_empty()) {
        Some(f) if Path::new(f).is_dir() => Ok(PathBuf::from(f)),
        Some(f) => Err(CommandError {
            kind: "io",
            message: format!(
                "The folder for signed copies ({f}) is not available. \
                 Choose it again in Settings, or save next to the original."
            ),
        }),
        None => Ok(input
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."))),
    }
}

/// Writes `data` as `<name>_signed.pdf` (or `_signed_2`, `_signed_3`, …) and
/// returns the path used.
pub fn write_signed(input: &Path, folder: Option<&str>, data: &[u8]) -> CmdResult<PathBuf> {
    let dir = target_dir(input, folder)?;
    Ok(write_signed_in(input, &dir, data)?)
}

/// Writes a filled-in form, not signed, as `<name>_filled.pdf` where a
/// signed copy would go.
pub fn write_filled(input: &Path, folder: Option<&str>, data: &[u8]) -> CmdResult<PathBuf> {
    let dir = target_dir(input, folder)?;
    Ok(write_copy_in(input, &dir, "filled", data)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("tms-out-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write(input: &Path, folder: Option<&str>, data: &[u8]) -> PathBuf {
        write_signed(input, folder, data)
            .map_err(|e| e.message)
            .unwrap()
    }

    fn names(paths: &[PathBuf]) -> Vec<String> {
        paths
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn next_to_original_numbers_taken_names() {
        let dir = temp("same");
        let input = dir.join("invoice.pdf");
        std::fs::write(&input, b"%PDF").unwrap();
        let outs: Vec<PathBuf> = (0..3).map(|i| write(&input, None, &[i])).collect();
        assert_eq!(
            names(&outs),
            [
                "invoice_signed.pdf",
                "invoice_signed_2.pdf",
                "invoice_signed_3.pdf"
            ]
        );
        assert!(outs.iter().all(|o| o.parent() == Some(dir.as_path())));
        // Nothing was overwritten.
        assert_eq!(std::fs::read(&outs[0]).unwrap(), [0]);
        assert_eq!(std::fs::read(&input).unwrap(), b"%PDF");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn chosen_folder() {
        let src = temp("src");
        let dest = temp("dest");
        let input = src.join("a.pdf");
        std::fs::write(dest.join("a_signed.pdf"), b"keep").unwrap();
        let folder = dest.to_string_lossy().into_owned();
        let out = write(&input, Some(&folder), b"new");
        assert_eq!(out, dest.join("a_signed_2.pdf"));
        assert_eq!(std::fs::read(dest.join("a_signed.pdf")).unwrap(), b"keep");
        assert!(!src.join("a_signed.pdf").exists());
        // A blank setting means next to the original.
        let out = write(&input, Some("  "), b"x");
        assert_eq!(out, src.join("a_signed.pdf"));
        std::fs::remove_dir_all(&src).unwrap();
        std::fs::remove_dir_all(&dest).unwrap();
    }

    #[test]
    fn missing_folder_is_an_error() {
        let src = temp("missing");
        let gone = src.join("not-there").to_string_lossy().into_owned();
        let err = write_signed(&src.join("a.pdf"), Some(&gone), b"x").unwrap_err();
        assert_eq!(err.kind, "io");
        assert!(std::fs::read_dir(&src).unwrap().next().is_none());
        std::fs::remove_dir_all(&src).unwrap();
    }
}
