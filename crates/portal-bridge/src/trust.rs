//! Adding the per-install CA to the current user's trust store, so the
//! browser accepts `wss://127.0.0.1`, and taking it out again. Windows shows
//! its own security warning, macOS asks for the login password. Linux has no
//! trust store all browsers share: the CA goes into the NSS databases of
//! Chrome/Chromium (`~/.pki/nssdb`) and of each Firefox profile, with
//! `certutil` from the NSS tools.

use std::path::Path;
use std::process::Command;

use crate::Error;
use crate::identity::thumbprint;

fn run(cmd: &mut Command) -> Result<(), String> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // No console window flashing up behind the system's dialog.
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    let out = cmd.output().map_err(|e| e.to_string())?;
    if out.status.success() {
        return Ok(());
    }
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    Err(text.trim().to_string())
}

/// Whether a tool's output says the user said no.
#[cfg(any(windows, target_os = "macos"))]
fn declined(output: &str) -> bool {
    let o = output.to_ascii_lowercase();
    o.contains("1223") || o.contains("cancel") || o.contains("authorization was denied")
}

#[cfg(target_os = "macos")]
fn login_keychain() -> Result<std::path::PathBuf, Error> {
    let home = std::env::var_os("HOME").ok_or_else(|| Error::new("HOME is not set"))?;
    Ok(Path::new(&home).join("Library/Keychains/login.keychain-db"))
}

/// Trusts the CA in `ca_path` (DER) for the current user.
pub fn install(ca_path: &Path) -> Result<(), Error> {
    #[cfg(windows)]
    {
        run(Command::new("certutil")
            .args(["-user", "-addstore", "Root"])
            .arg(ca_path))
        .map_err(|e| {
            if declined(&e) {
                Error::new(
                    "The certificate was not installed: Windows asked and the answer was No.",
                )
            } else {
                Error::new(format!("Could not add the certificate to Windows: {e}"))
            }
        })
    }
    #[cfg(target_os = "macos")]
    {
        let keychain = login_keychain()?;
        run(Command::new("/usr/bin/security")
            .args(["add-trusted-cert", "-r", "trustRoot", "-k"])
            .arg(&keychain)
            .arg(ca_path))
        .map_err(|e| {
            if declined(&e) {
                Error::new("The certificate was not installed: macOS asked and it was cancelled.")
            } else {
                Error::new(format!(
                    "Could not add the certificate to the login keychain: {e}"
                ))
            }
        })
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        nss::install(ca_path)
    }
}

/// Removes the CA (`ca` is its DER, also saved at `ca_path`) from the
/// current user's trust store. A certificate that is not there is fine.
pub fn remove(ca_path: &Path, ca: &[u8]) -> Result<(), Error> {
    #[cfg(windows)]
    {
        let _ = ca_path;
        match run(Command::new("certutil").args(["-user", "-delstore", "Root", &thumbprint(ca)])) {
            Ok(()) => Ok(()),
            Err(e) if e.contains("0x80092004") || e.to_ascii_lowercase().contains("not found") => {
                Ok(())
            }
            Err(e) if declined(&e) => Err(Error::new(
                "The certificate is still installed: Windows asked and the answer was No.",
            )),
            Err(e) => Err(Error::new(format!(
                "Could not remove the certificate from Windows: {e}"
            ))),
        }
    }
    #[cfg(target_os = "macos")]
    {
        let keychain = login_keychain()?;
        // First the trust setting (asks for the password), then the certificate.
        let trust = run(Command::new("/usr/bin/security")
            .arg("remove-trusted-cert")
            .arg(ca_path));
        if let Err(e) = &trust
            && declined(e)
        {
            return Err(Error::new(
                "The certificate is still trusted: macOS asked and it was cancelled.",
            ));
        }
        match run(Command::new("/usr/bin/security")
            .args(["delete-certificate", "-Z", &thumbprint(ca)])
            .arg(&keychain))
        {
            Ok(()) => Ok(()),
            Err(e) if e.to_ascii_lowercase().contains("could not be found") => Ok(()),
            Err(e) => Err(Error::new(format!(
                "Could not remove the certificate from the login keychain: {e}"
            ))),
        }
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = ca_path;
        nss::remove(ca)
    }
}

/// Linux and the BSDs: the NSS databases browsers read their trusted
/// certificates from. Nothing asks for a password here; turning portal
/// signing on in Settings is the confirmation.
#[cfg(not(any(windows, target_os = "macos")))]
mod nss {
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use super::{run, thumbprint};
    use crate::Error;

    const NO_CERTUTIL: &str = "Portal signing needs certutil to add its certificate to Chrome and \
        Firefox. Install it (Ubuntu and Debian: sudo apt install libnss3-tools; Fedora: sudo dnf \
        install nss-tools; Arch: sudo pacman -S nss) and try again.";

    /// Name of the CA in the databases; tells this install's CA apart from
    /// one made earlier.
    pub(super) fn nickname(ca: &[u8]) -> String {
        format!("TrackMySign portal CA {}", &thumbprint(ca)[..16])
    }

    fn home() -> Result<PathBuf, Error> {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| Error::new("HOME is not set"))
    }

    /// Chrome/Chromium's database (also when it does not exist yet) and
    /// those of the Firefox profiles, including the snap and Flatpak ones.
    pub(super) fn databases(home: &Path) -> Vec<PathBuf> {
        let mut v = vec![home.join(".pki/nssdb")];
        let chromium_snap = home.join("snap/chromium/current/.pki/nssdb");
        if chromium_snap.join("cert9.db").is_file() {
            v.push(chromium_snap);
        }
        for root in [
            ".mozilla/firefox",
            "snap/firefox/common/.mozilla/firefox",
            ".var/app/org.mozilla.firefox/.mozilla/firefox",
        ] {
            let Ok(rd) = std::fs::read_dir(home.join(root)) else {
                continue;
            };
            let mut profiles: Vec<PathBuf> = rd
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.join("cert9.db").is_file())
                .collect();
            profiles.sort();
            v.extend(profiles);
        }
        v
    }

    fn certutil(db: &Path) -> Command {
        let mut cmd = Command::new("certutil");
        cmd.arg("-d").arg(format!("sql:{}", db.display()));
        cmd
    }

    fn has_certutil() -> bool {
        !matches!(
            Command::new("certutil").arg("--version").output(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound
        )
    }

    pub(super) fn install(ca_path: &Path) -> Result<(), Error> {
        let ca = std::fs::read(ca_path).map_err(|e| Error::new(e.to_string()))?;
        install_in(&home()?, ca_path, &ca)
    }

    pub(super) fn install_in(home: &Path, ca_path: &Path, ca: &[u8]) -> Result<(), Error> {
        if !has_certutil() {
            return Err(Error::new(NO_CERTUTIL));
        }
        let name = nickname(ca);
        for db in databases(home) {
            let added = (|| {
                if !db.join("cert9.db").is_file() {
                    std::fs::create_dir_all(&db).map_err(|e| e.to_string())?;
                    run(certutil(&db).args(["-N", "--empty-password"]))?;
                }
                // "C": trusted to issue server certificates.
                run(certutil(&db)
                    .args(["-A", "-t", "C,,", "-n", &name, "-i"])
                    .arg(ca_path))
            })();
            if let Err(e) = added {
                // All or nothing, as on the other systems.
                let _ = remove_in(home, ca);
                return Err(Error::new(format!(
                    "Could not add the certificate to {}: {e}",
                    db.display()
                )));
            }
        }
        Ok(())
    }

    pub(super) fn remove(ca: &[u8]) -> Result<(), Error> {
        remove_in(&home()?, ca)
    }

    /// A database without the certificate is fine.
    pub(super) fn remove_in(home: &Path, ca: &[u8]) -> Result<(), Error> {
        let name = nickname(ca);
        let dbs: Vec<PathBuf> = databases(home)
            .into_iter()
            .filter(|db| db.join("cert9.db").is_file())
            .collect();
        if dbs.is_empty() {
            return Ok(());
        }
        if !has_certutil() {
            return Err(Error::new(NO_CERTUTIL));
        }
        for db in dbs {
            match run(certutil(&db).args(["-D", "-n", &name])) {
                Ok(()) => {}
                Err(e) if e.contains("could not find certificate") => {}
                Err(e) => {
                    return Err(Error::new(format!(
                        "Could not remove the certificate from {}: {e}",
                        db.display()
                    )));
                }
            }
        }
        Ok(())
    }
}

#[cfg(all(test, not(any(windows, target_os = "macos"))))]
mod tests {
    use std::process::Command;

    use super::nss;
    use crate::identity::generate;

    fn listed(db: &std::path::Path) -> String {
        let out = Command::new("certutil")
            .arg("-d")
            .arg(format!("sql:{}", db.display()))
            .arg("-L")
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    #[test]
    fn nss_install_and_remove() {
        if Command::new("certutil").arg("--version").output().is_err() {
            eprintln!("certutil not installed; skipped");
            return;
        }
        let home = std::env::temp_dir().join(format!("tms-nss-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        // A Firefox profile with a database, and a folder that is not one.
        let profile = home.join(".mozilla/firefox/abcd.default-release");
        std::fs::create_dir_all(&profile).unwrap();
        std::fs::create_dir_all(home.join(".mozilla/firefox/Crash Reports")).unwrap();
        let made = Command::new("certutil")
            .arg("-d")
            .arg(format!("sql:{}", profile.display()))
            .args(["-N", "--empty-password"])
            .status()
            .unwrap();
        assert!(made.success());
        assert_eq!(
            nss::databases(&home),
            vec![home.join(".pki/nssdb"), profile.clone()]
        );

        let ca = generate(std::time::SystemTime::now()).unwrap().ca;
        let ca_path = home.join("ca.der");
        std::fs::write(&ca_path, &ca).unwrap();
        let name = nss::nickname(&ca);
        nss::install_in(&home, &ca_path, &ca).unwrap();
        for db in [home.join(".pki/nssdb"), profile.clone()] {
            assert!(listed(&db).contains(&name), "{}", db.display());
        }
        nss::remove_in(&home, &ca).unwrap();
        // Removing again is fine.
        nss::remove_in(&home, &ca).unwrap();
        for db in [home.join(".pki/nssdb"), profile] {
            assert!(!listed(&db).contains(&name), "{}", db.display());
        }
        std::fs::remove_dir_all(&home).unwrap();
    }
}
