//! Recently opened PDFs, kept in the app's data folder for the start screen
//! and the Open menu. Only paths, names, dates and page counts are stored:
//! never a PIN, a password or anything from inside a document.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

use super::{CmdResult, CommandError};

/// Entries kept; older ones drop off the end.
const CAP: usize = 10;

/// One read-modify-write of the file at a time.
static STORE_LOCK: Mutex<()> = Mutex::new(());

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Recent {
    path: String,
    name: String,
    /// Unix seconds.
    opened: i64,
    /// Unknown for a file signed in a batch without being shown.
    pages: Option<usize>,
    /// Where our signed copy went, when it was signed here.
    signed: Option<String>,
}

fn store_path(app: &AppHandle) -> CmdResult<PathBuf> {
    let dir = app.path().app_data_dir().map_err(|e| CommandError {
        kind: "io",
        message: e.to_string(),
    })?;
    Ok(dir.join("recent-files.json"))
}

fn load(app: &AppHandle) -> Vec<Recent> {
    store_path(app)
        .ok()
        .and_then(|p| std::fs::read(p).ok())
        .and_then(|d| serde_json::from_slice(&d).ok())
        .unwrap_or_default()
}

fn store(app: &AppHandle, list: &[Recent]) -> CmdResult<()> {
    let path = store_path(app)?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let data = serde_json::to_vec_pretty(list).map_err(|e| CommandError {
        kind: "io",
        message: e.to_string(),
    })?;
    std::fs::write(path, data)?;
    Ok(())
}

/// Windows and macOS file names are not case-sensitive (by default).
fn same_path(a: &str, b: &str) -> bool {
    if cfg!(any(windows, target_os = "macos")) {
        a.to_lowercase() == b.to_lowercase()
    } else {
        a == b
    }
}

fn file_name(path: &str) -> String {
    Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string())
}

/// Puts `entry` first, replacing an older entry for the same file (and keeping
/// what that one knew), and keeps at most [`CAP`].
fn push(mut list: Vec<Recent>, mut entry: Recent) -> Vec<Recent> {
    if let Some(i) = list.iter().position(|r| same_path(&r.path, &entry.path)) {
        let old = list.remove(i);
        entry.pages = entry.pages.or(old.pages);
        entry.signed = entry.signed.or(old.signed);
    }
    list.insert(0, entry);
    list.truncate(CAP);
    list
}

/// Drops files that are gone, and signed copies that are gone.
fn prune(list: Vec<Recent>, exists: impl Fn(&Path) -> bool) -> Vec<Recent> {
    list.into_iter()
        .filter(|r| exists(Path::new(&r.path)))
        .map(|mut r| {
            if r.signed.as_deref().is_some_and(|s| !exists(Path::new(s))) {
                r.signed = None;
            }
            r
        })
        .collect()
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Recent files that still exist, most recent first.
#[tauri::command]
pub fn recent_files(app: AppHandle) -> Vec<Recent> {
    let _guard = STORE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let before = load(&app);
    let after = prune(before.clone(), Path::is_file);
    if after != before {
        let _ = store(&app, &after);
    }
    after
}

/// Records that `path` was opened.
#[tauri::command]
pub fn recent_add(app: AppHandle, path: String, pages: usize) -> CmdResult<Vec<Recent>> {
    let _guard = STORE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let entry = Recent {
        name: file_name(&path),
        path,
        opened: now(),
        pages: Some(pages),
        signed: None,
    };
    let list = push(prune(load(&app), Path::is_file), entry);
    store(&app, &list)?;
    Ok(list)
}

/// Records that `path` was signed into `output`.
#[tauri::command]
pub fn recent_signed(app: AppHandle, path: String, output: String) -> CmdResult<Vec<Recent>> {
    let _guard = STORE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let entry = Recent {
        name: file_name(&path),
        path,
        opened: now(),
        pages: None,
        signed: Some(output),
    };
    let list = push(prune(load(&app), Path::is_file), entry);
    store(&app, &list)?;
    Ok(list)
}

#[tauri::command]
pub fn recent_clear(app: AppHandle) -> CmdResult<()> {
    let _guard = STORE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let path = store_path(&app)?;
    if path.is_file() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &str, opened: i64) -> Recent {
        Recent {
            path: path.into(),
            name: file_name(path),
            opened,
            pages: Some(1),
            signed: None,
        }
    }

    fn paths(list: &[Recent]) -> Vec<&str> {
        list.iter().map(|r| r.path.as_str()).collect()
    }

    #[test]
    fn push_moves_to_front_and_keeps_signed_copy() {
        let mut a = entry("/d/a.pdf", 1);
        a.signed = Some("/d/a_signed.pdf".into());
        a.pages = Some(4);
        let list = vec![entry("/d/b.pdf", 2), a];
        let mut again = entry("/d/a.pdf", 3);
        again.pages = None;
        let list = push(list, again);
        assert_eq!(paths(&list), ["/d/a.pdf", "/d/b.pdf"]);
        assert_eq!(list[0].opened, 3);
        assert_eq!(list[0].pages, Some(4));
        assert_eq!(list[0].signed.as_deref(), Some("/d/a_signed.pdf"));
    }

    #[test]
    fn push_keeps_ten() {
        let mut list = Vec::new();
        for i in 0..12 {
            list = push(list, entry(&format!("/d/{i}.pdf"), i));
        }
        assert_eq!(list.len(), CAP);
        assert_eq!(list[0].path, "/d/11.pdf");
        assert_eq!(list[CAP - 1].path, "/d/2.pdf");
        // The same file again does not grow the list or push anything out.
        let list = push(list, entry("/d/5.pdf", 20));
        assert_eq!(list.len(), CAP);
        assert_eq!(list[0].path, "/d/5.pdf");
        assert!(list.iter().any(|r| r.path == "/d/2.pdf"));
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[test]
    fn push_ignores_case() {
        let list = push(vec![entry("C:\\D\\A.pdf", 1)], entry("c:\\d\\a.PDF", 2));
        assert_eq!(paths(&list), ["c:\\d\\a.PDF"]);
    }

    #[test]
    fn prune_drops_missing_files() {
        let mut kept = entry("/d/kept.pdf", 3);
        kept.signed = Some("/d/kept_signed.pdf".into());
        let mut lost_copy = entry("/d/other.pdf", 2);
        lost_copy.signed = Some("/d/moved_signed.pdf".into());
        let list = vec![kept.clone(), entry("/d/gone.pdf", 1), lost_copy];
        let present = ["/d/kept.pdf", "/d/kept_signed.pdf", "/d/other.pdf"];
        let list = prune(list, |p| present.iter().any(|x| Path::new(x) == p));
        assert_eq!(paths(&list), ["/d/kept.pdf", "/d/other.pdf"]);
        assert_eq!(list[0], kept);
        assert_eq!(list[1].signed, None);
    }

    #[test]
    fn stored_entries_hold_no_more_than_listed() {
        let mut r = entry("/d/a.pdf", 1);
        r.signed = Some("/d/a_signed.pdf".into());
        let json = serde_json::to_value(&r).unwrap();
        let mut keys: Vec<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(|k| k.as_str())
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, ["name", "opened", "pages", "path", "signed"]);
    }
}
