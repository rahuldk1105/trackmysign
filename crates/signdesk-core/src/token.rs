//! USB DSC tokens through their PKCS#11 driver.

use std::path::{Path, PathBuf};

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Function, Pkcs11};
use cryptoki::error::{Error as CkError, Rv, RvError};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use der::Decode;
use sha2::{Digest, Sha256};
use x509_cert::Certificate;

use crate::certinfo::CertSummary;
use crate::cms::{ecdsa_raw_to_der, sha256_digest_info};
use crate::{Error, KeyKind, Signer};

/// Environment variable that overrides driver auto-detection.
pub const MODULE_ENV: &str = "TRACKMYSIGN_PKCS11_MODULE";

/// A PKCS#11 driver installed on this computer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Driver {
    /// Product the driver belongs to, e.g. "Watchdata ProxKey".
    pub name: String,
    pub path: PathBuf,
}

/// Where token vendors install their drivers: product, folder, file name.
/// A `*` in the file name stands for a version number that changes between
/// releases. Vendor drivers come first; OpenSC is the last resort.
fn known_locations() -> Vec<(&'static str, PathBuf, &'static str)> {
    let mut v: Vec<(&'static str, PathBuf, &'static str)> = Vec::new();
    #[cfg(windows)]
    {
        let win = std::env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".into());
        let sys = Path::new(&win).join("System32");
        let pf = PathBuf::from(
            std::env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".into()),
        );
        for (name, file) in [
            ("Hypersecu HyperPKI", "eps2003csp11v2.dll"),
            ("Feitian ePass2003", "eps2003csp11.dll"),
            ("Watchdata ProxKey", "SignatureP11.dll"),
            ("Trust Key", "TRUSTKEYP11*.dll"),
            ("Longmai mToken CryptoID", "CryptoIDA_pkcs11.dll"),
            ("Watchdata", "wdpkcs.dll"),
            ("SafeNet eToken", "eTPKCS11.dll"),
            ("Gemalto IDPrime", "IDPrimePKCS11.dll"),
            ("Bit4id", "bit4xpki.dll"),
            ("Bit4id", "bit4ipki.dll"),
        ] {
            v.push((name, sys.clone(), file));
        }
        v.push((
            "Gemalto IDPrime",
            pf.join("Gemalto\\IDGo 800 PKCS#11"),
            "IDPrimePKCS1164.dll",
        ));
        v.push((
            "OpenSC",
            pf.join("OpenSC Project\\OpenSC\\pkcs11"),
            "opensc-pkcs11.dll",
        ));
    }
    #[cfg(target_os = "macos")]
    {
        let lib = PathBuf::from("/usr/local/lib");
        v.push(("Hypersecu HyperPKI", lib.clone(), "libcastle_v2*.dylib"));
        v.push(("Feitian ePass2003", lib.clone(), "libcastle.*.dylib"));
        v.push((
            "Feitian ePass2003",
            "/usr/local".into(),
            "libcastle.*.dylib",
        ));
        v.push((
            "Watchdata ProxKey",
            lib.join("wdProxKeyUsbKeyTool"),
            "libwdpkcs_Proxkey.dylib",
        ));
        for dir in [
            "/usr/local/lib",
            "/Applications/CryptoIDEUserTools.app/Contents/lib/mac",
            "/Applications/CryptoUserTools.app/Contents/lib/mac",
            "/opt/CryptoIDE/lib",
        ] {
            v.push((
                "Longmai mToken CryptoID",
                dir.into(),
                "libcryptoid*_pkcs11.dylib",
            ));
        }
        v.push(("SafeNet eToken", lib.clone(), "libeTPkcs11.dylib"));
        v.push(("Gemalto IDPrime", lib.clone(), "libIDPrimePKCS11.dylib"));
        v.push((
            "Bit4id",
            "/Library/bit4id/pkcs11".into(),
            "libbit4xpki.dylib",
        ));
        v.push((
            "Bit4id",
            "/Library/bit4id/pkcs11".into(),
            "libbit4ipki.dylib",
        ));
        v.push((
            "Bit4id",
            "/Applications/PKIManager-bit4id.app/Contents/Resources/etc".into(),
            "libbit4xpki.dylib",
        ));
        for dir in ["/Library/OpenSC/lib", "/opt/homebrew/lib", "/usr/local/lib"] {
            v.push(("OpenSC", dir.into(), "opensc-pkcs11.so"));
        }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        for dir in ["/usr/lib/x86_64-linux-gnu", "/usr/lib"] {
            v.push(("OpenSC", dir.into(), "opensc-pkcs11.so"));
        }
    }
    v
}

/// Case-insensitive file name match with at most one `*`.
fn name_matches(pattern: &str, name: &str) -> bool {
    let (p, n) = (pattern.to_lowercase(), name.to_lowercase());
    match p.split_once('*') {
        Some((pre, suf)) => {
            n.len() >= pre.len() + suf.len() && n.starts_with(pre) && n.ends_with(suf)
        }
        None => p == n,
    }
}

/// Product name for a driver file, or its file name if it is not a known one.
pub fn driver_name(path: &Path) -> String {
    let file = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    known_locations()
        .into_iter()
        .find(|(_, _, pattern)| name_matches(pattern, &file))
        .map(|(name, _, _)| name.to_string())
        .unwrap_or(file)
}

/// Drivers present on this computer, preferred first. With [`MODULE_ENV`] set,
/// only the ones it lists (separated like `PATH`).
pub fn installed_drivers() -> Vec<Driver> {
    if let Some(list) = std::env::var_os(MODULE_ENV).filter(|p| !p.is_empty()) {
        return std::env::split_paths(&list)
            .map(|path| Driver {
                name: driver_name(&path),
                path,
            })
            .collect();
    }
    let mut out: Vec<Driver> = Vec::new();
    let mut seen: Vec<PathBuf> = Vec::new();
    for (name, dir, pattern) in known_locations() {
        let mut found: Vec<PathBuf> = if pattern.contains('*') {
            let Ok(rd) = std::fs::read_dir(&dir) else {
                continue;
            };
            rd.flatten()
                .filter(|e| name_matches(pattern, &e.file_name().to_string_lossy()))
                .map(|e| e.path())
                .collect()
        } else {
            vec![dir.join(pattern)]
        };
        // Newest version first.
        found.sort();
        found.reverse();
        for path in found.into_iter().filter(|p| p.is_file()) {
            // The same library is often reachable through a symlink as well.
            let real = std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
            if seen.contains(&real) {
                continue;
            }
            seen.push(real);
            out.push(Driver {
                name: name.to_string(),
                path,
            });
        }
    }
    out
}

fn no_driver() -> Error {
    Error::Token(
        "No DSC token driver found. Install the software that came with your token.".into(),
    )
}

fn ck(e: CkError) -> Error {
    match e {
        CkError::Pkcs11(RvError::TokenNotPresent | RvError::DeviceRemoved, _) => {
            Error::Token("The DSC token is not plugged in (or was removed).".into())
        }
        CkError::LibraryLoading(e) => Error::Token(format!("Could not load the token driver: {e}")),
        e => Error::Token(e.to_string()),
    }
}

/// A certificate found on a token.
#[derive(Debug, Clone)]
pub struct TokenCert {
    /// Driver the certificate was read through; sign with the same one.
    pub driver: Driver,
    pub slot: Slot,
    pub token_label: String,
    pub ck_id: Vec<u8>,
    pub der: Vec<u8>,
    pub summary: CertSummary,
}

impl TokenCert {
    /// SHA-256 of the certificate, in hex: identifies it across driver reloads.
    pub fn fingerprint(&self) -> String {
        Sha256::digest(&self.der)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PinStatus {
    pub count_low: bool,
    pub final_try: bool,
    pub locked: bool,
}

pub struct Token {
    ctx: Pkcs11,
    pub driver: Driver,
}

impl Token {
    pub fn open(module: &Path) -> Result<Self, Error> {
        let ctx = Pkcs11::new(module).map_err(ck)?;
        match ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
            Ok(()) | Err(CkError::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {}
            Err(e) => return Err(ck(e)),
        }
        Ok(Token {
            ctx,
            driver: Driver {
                name: driver_name(module),
                path: module.to_path_buf(),
            },
        })
    }

    pub fn pin_status(&self, slot: Slot) -> Result<PinStatus, Error> {
        pin_status(&self.ctx, slot)
    }

    /// All X.509 certificates on all connected tokens (no PIN needed).
    pub fn certificates(&self) -> Result<Vec<TokenCert>, Error> {
        let mut out = Vec::new();
        for slot in self.ctx.get_slots_with_token().map_err(ck)? {
            let Ok(info) = self.ctx.get_token_info(slot) else {
                continue;
            };
            if !info.token_initialized() {
                continue;
            }
            let label = info.label().trim().to_string();
            // Drivers often expose empty or unusable slots; skip them.
            let Ok(session) = self.ctx.open_ro_session(slot) else {
                continue;
            };
            let Ok(handles) = session.find_objects(&[Attribute::Class(ObjectClass::CERTIFICATE)])
            else {
                continue;
            };
            for h in handles {
                let attrs = session
                    .get_attributes(h, &[AttributeType::Value, AttributeType::Id])
                    .map_err(ck)?;
                let mut der = None;
                let mut id = Vec::new();
                for a in attrs {
                    match a {
                        Attribute::Value(v) => der = Some(v),
                        Attribute::Id(v) => id = v,
                        _ => {}
                    }
                }
                let Some(der) = der else { continue };
                let Ok(summary) = CertSummary::from_der(&der) else {
                    continue;
                };
                out.push(TokenCert {
                    driver: self.driver.clone(),
                    slot,
                    token_label: label.clone(),
                    ck_id: id,
                    der,
                    summary,
                });
            }
        }
        Ok(out)
    }

    /// End-entity certificates usable for signing, signing-capable first.
    pub fn signing_certificates(&self) -> Result<Vec<TokenCert>, Error> {
        let mut v: Vec<TokenCert> = self
            .certificates()?
            .into_iter()
            .filter(|c| !c.summary.is_ca)
            .collect();
        v.sort_by_key(|c| (!c.summary.can_sign, c.summary.expired));
        Ok(v)
    }

    /// Logs in with `pin` and returns a signer bound to `cert`'s private key.
    /// The session stays logged in, so one signer can sign a whole batch.
    pub fn signer(&self, cert: &TokenCert, pin: &str) -> Result<TokenSigner, Error> {
        let status = self.pin_status(cert.slot).unwrap_or_default();
        if status.locked {
            return Err(Error::PinLocked);
        }
        let session = self.ctx.open_ro_session(cert.slot).map_err(ck)?;
        match session.login(UserType::User, Some(&AuthPin::from(pin))) {
            Ok(()) | Err(CkError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => {}
            Err(e) => return Err(login_error(&self.ctx, cert.slot, e)),
        }

        let key = find_private_key(&session, cert)?;
        let always_auth = session
            .get_attributes(key, &[AttributeType::AlwaysAuthenticate])
            .unwrap_or_default()
            .iter()
            .any(|a| matches!(a, Attribute::AlwaysAuthenticate(true)));
        let per_signature = if always_auth {
            Some(PerSignaturePin::new(&self.driver.path, pin)?)
        } else {
            None
        };

        // Issuer chain from the other certificates stored on the token.
        let all = self.certificates().unwrap_or_default();
        let mut chain: Vec<Vec<u8>> = Vec::new();
        let mut current = cert.summary.clone();
        for _ in 0..8 {
            if current.issuer_der == current.subject_der {
                break;
            }
            let Some(parent) = all
                .iter()
                .find(|c| c.summary.subject_der == current.issuer_der && c.der != cert.der)
            else {
                break;
            };
            if chain.contains(&parent.der) {
                break;
            }
            chain.push(parent.der.clone());
            current = parent.summary.clone();
        }

        Ok(TokenSigner {
            ctx: self.ctx.clone(),
            slot: cert.slot,
            session,
            key,
            per_signature,
            kind: cert.summary.key_kind,
            sig_len: cert.summary.signature_len,
            cert: cert.der.clone(),
            chain,
        })
    }
}

/// Every installed driver that loaded, so certificates on tokens from
/// different vendors can be listed side by side.
pub struct Tokens {
    pub tokens: Vec<Token>,
    /// Installed drivers that failed to load.
    pub failed: Vec<(Driver, Error)>,
}

impl Tokens {
    /// Loads each driver; one that fails is set aside, not fatal.
    pub fn open(drivers: &[Driver]) -> Result<Self, Error> {
        let mut tokens = Vec::new();
        let mut failed = Vec::new();
        for d in drivers {
            match Token::open(&d.path) {
                Ok(mut t) => {
                    t.driver.name = d.name.clone();
                    tokens.push(t);
                }
                Err(e) => failed.push((d.clone(), e)),
            }
        }
        if tokens.is_empty() {
            return Err(match failed.into_iter().next() {
                Some((_, e)) => e,
                None => no_driver(),
            });
        }
        Ok(Tokens { tokens, failed })
    }

    pub fn open_installed() -> Result<Self, Error> {
        Self::open(&installed_drivers())
    }

    /// Signing certificates from all tokens, signing-capable first. A token
    /// seen by two drivers (vendor and OpenSC, say) is listed once, under the
    /// preferred driver.
    pub fn signing_certificates(&self) -> Result<Vec<TokenCert>, Error> {
        let mut out: Vec<TokenCert> = Vec::new();
        let mut first_err = None;
        let mut any_ok = false;
        for t in &self.tokens {
            match t.signing_certificates() {
                Ok(certs) => {
                    any_ok = true;
                    for c in certs {
                        if !out.iter().any(|o| o.der == c.der) {
                            out.push(c);
                        }
                    }
                }
                Err(e) => {
                    first_err.get_or_insert(e);
                }
            }
        }
        if let (false, Some(e)) = (any_ok, first_err) {
            return Err(e);
        }
        out.sort_by_key(|c| (!c.summary.can_sign, c.summary.expired));
        Ok(out)
    }

    /// Logs in through the driver `cert` was read from.
    pub fn signer(&self, cert: &TokenCert, pin: &str) -> Result<TokenSigner, Error> {
        self.tokens
            .iter()
            .find(|t| t.driver.path == cert.driver.path)
            .ok_or_else(|| {
                Error::Token("The token driver for this certificate is not loaded.".into())
            })?
            .signer(cert, pin)
    }
}

fn pin_status(ctx: &Pkcs11, slot: Slot) -> Result<PinStatus, Error> {
    let ti = ctx.get_token_info(slot).map_err(ck)?;
    Ok(PinStatus {
        count_low: ti.user_pin_count_low(),
        final_try: ti.user_pin_final_try(),
        locked: ti.user_pin_locked(),
    })
}

/// A failed `C_Login`, with the attempts left when the token tells.
fn login_error(ctx: &Pkcs11, slot: Slot, e: CkError) -> Error {
    match e {
        CkError::Pkcs11(RvError::PinIncorrect | RvError::PinLenRange, _) => {
            let s = pin_status(ctx, slot).unwrap_or_default();
            if s.locked {
                return Error::PinLocked;
            }
            Error::WrongPin {
                final_try: s.final_try,
                count_low: s.count_low,
            }
        }
        CkError::Pkcs11(RvError::PinLocked, _) => Error::PinLocked,
        e => ck(e),
    }
}

fn find_private_key(session: &Session, cert: &TokenCert) -> Result<ObjectHandle, Error> {
    if !cert.ck_id.is_empty() {
        let found = session
            .find_objects(&[
                Attribute::Class(ObjectClass::PRIVATE_KEY),
                Attribute::Id(cert.ck_id.clone()),
            ])
            .map_err(ck)?;
        if let Some(h) = found.first() {
            return Ok(*h);
        }
    }
    // No CKA_ID match: compare RSA moduli.
    let keys = session
        .find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY)])
        .map_err(ck)?;
    if let Some(modulus) = &cert.summary.rsa_modulus {
        for k in &keys {
            if let Ok(attrs) = session.get_attributes(*k, &[AttributeType::Modulus]) {
                for a in attrs {
                    if let Attribute::Modulus(m) = a {
                        let m: Vec<u8> = m.into_iter().skip_while(|b| *b == 0).collect();
                        if &m == modulus {
                            return Ok(*k);
                        }
                    }
                }
            }
        }
    }
    if keys.len() == 1 {
        return Ok(keys[0]);
    }
    Err(Error::Token(
        "The private key for this certificate was not found on the token.".into(),
    ))
}

/// For a key with `CKA_ALWAYS_AUTHENTICATE`: the PIN is given again after
/// every `C_SignInit` (a `CKU_CONTEXT_SPECIFIC` login). It is kept only while
/// the signer lives, so a batch needs one entry, and is wiped on drop.
struct PerSignaturePin {
    /// `None` once the token refused it: retrying would only use up attempts.
    pin: Option<AuthPin>,
    /// `C_Sign` on its own; cryptoki only calls it right after its own `C_SignInit`.
    sign: unsafe extern "C" fn(
        cryptoki_sys::CK_SESSION_HANDLE,
        *mut u8,
        cryptoki_sys::CK_ULONG,
        *mut u8,
        *mut cryptoki_sys::CK_ULONG,
    ) -> cryptoki_sys::CK_RV,
    /// The driver loaded once more (the OS shares the one already loaded),
    /// keeping `sign` valid.
    _lib: cryptoki_sys::Pkcs11,
}

impl PerSignaturePin {
    fn new(module: &Path, pin: &str) -> Result<Self, Error> {
        let missing = || Error::Token("The token driver does not provide C_Sign.".into());
        // SAFETY: the same library cryptoki already loaded and initialised;
        // the function list it hands out lives as long as the library does.
        unsafe {
            let lib = cryptoki_sys::Pkcs11::new(module)
                .map_err(|e| Error::Token(format!("Could not load the token driver: {e}")))?;
            if lib.C_GetFunctionList.is_err() {
                return Err(missing());
            }
            let mut list: *mut cryptoki_sys::CK_FUNCTION_LIST = std::ptr::null_mut();
            Rv::from(lib.C_GetFunctionList(&mut list))
                .into_result(Function::GetFunctionList)
                .map_err(ck)?;
            let sign = list.as_ref().and_then(|l| l.C_Sign).ok_or_else(missing)?;
            Ok(PerSignaturePin {
                pin: Some(AuthPin::from(pin)),
                sign,
                _lib: lib,
            })
        }
    }
}

pub struct TokenSigner {
    ctx: Pkcs11,
    slot: Slot,
    session: Session,
    key: ObjectHandle,
    per_signature: Option<PerSignaturePin>,
    kind: KeyKind,
    sig_len: usize,
    cert: Vec<u8>,
    chain: Vec<Vec<u8>>,
}

impl TokenSigner {
    fn sign(&mut self, mechanism: &Mechanism, data: &[u8]) -> Result<Vec<u8>, Error> {
        let Some(per) = &mut self.per_signature else {
            return self.session.sign(mechanism, self.key, data).map_err(ck);
        };
        let Some(pin) = per.pin.take() else {
            return Err(Error::Token(
                "Signing stopped: the token did not accept the PIN for this key.".into(),
            ));
        };
        self.session.sign_init(mechanism, self.key).map_err(ck)?;
        match self.session.login(UserType::ContextSpecific, Some(&pin)) {
            // Some drivers answer this when the key needs no further login.
            Ok(()) | Err(CkError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => per.pin = Some(pin),
            Err(e) => return Err(login_error(&self.ctx, self.slot, e)),
        }
        let session = self.session.handle();
        let call = |out: *mut u8, len: &mut cryptoki_sys::CK_ULONG| {
            // SAFETY: `data` and `out` (when not null) outlive the call, and
            // `len` is the size of `out`.
            Rv::from(unsafe {
                (per.sign)(
                    session,
                    data.as_ptr() as *mut u8,
                    data.len() as cryptoki_sys::CK_ULONG,
                    out,
                    len,
                )
            })
            .into_result(Function::Sign)
            .map_err(ck)
        };
        let mut len: cryptoki_sys::CK_ULONG = 0;
        call(std::ptr::null_mut(), &mut len)?;
        let mut sig = vec![0u8; len as usize];
        call(sig.as_mut_ptr(), &mut len)?;
        sig.truncate(len as usize);
        Ok(sig)
    }
}

impl Signer for TokenSigner {
    fn certificate(&self) -> &[u8] {
        &self.cert
    }
    fn chain(&self) -> &[Vec<u8>] {
        &self.chain
    }
    fn key_kind(&self) -> KeyKind {
        self.kind
    }
    fn signature_len(&self) -> usize {
        self.sig_len
    }
    fn sign_sha256(&mut self, digest: &[u8; 32]) -> Result<Vec<u8>, Error> {
        match self.kind {
            KeyKind::Rsa => self.sign(&Mechanism::RsaPkcs, &sha256_digest_info(digest)),
            KeyKind::Ec => {
                let raw = self.sign(&Mechanism::Ecdsa, digest)?;
                Ok(ecdsa_raw_to_der(&raw))
            }
        }
    }
}

/// Parse helper kept here so callers need not depend on x509-cert.
pub fn parse_certificate(der: &[u8]) -> Result<Certificate, Error> {
    Certificate::from_der(der).map_err(|e| Error::Cms(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn driver_file_names() {
        assert!(name_matches("TRUSTKEYP11*.dll", "TrustKeyP11_ND_v34.dll"));
        assert!(name_matches("libcastle.*.dylib", "libcastle.1.0.0.dylib"));
        assert!(!name_matches(
            "libcastle.*.dylib",
            "libcastle_v2.1.0.0.dylib"
        ));
        assert!(name_matches("eTPKCS11.dll", "etpkcs11.dll"));
        assert!(!name_matches("eps2003csp11.dll", "eps2003csp11v2.dll"));
        assert_eq!(
            driver_name(Path::new("/x/unknown-pkcs11.so")),
            "unknown-pkcs11.so"
        );
    }
}
