//! Adding the per-install CA to the current user's trust store, so the
//! browser accepts `wss://127.0.0.1`, and taking it out again. Both ask the
//! user: Windows shows its own security warning, macOS asks for the login
//! password.

use std::path::Path;
#[cfg(any(windows, target_os = "macos"))]
use std::process::Command;

use crate::Error;
#[cfg(any(windows, target_os = "macos"))]
use crate::identity::thumbprint;

#[cfg(any(windows, target_os = "macos"))]
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
        let _ = ca_path;
        Err(Error::new(
            "Portal signing can install its certificate on Windows and macOS only.",
        ))
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
        let _ = (ca_path, ca);
        Ok(())
    }
}
