//! USB DSC tokens through their PKCS#11 driver.

use std::path::{Path, PathBuf};

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as CkError, RvError};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use der::Decode;
use x509_cert::Certificate;

use crate::certinfo::CertSummary;
use crate::cms::{ecdsa_raw_to_der, sha256_digest_info};
use crate::{Error, KeyKind, Signer};

/// Environment variable that overrides driver auto-detection.
pub const MODULE_ENV: &str = "TRACKMYSIGN_PKCS11_MODULE";

/// Known driver locations, most specific first.
pub fn module_candidates() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = Vec::new();
    if let Ok(p) = std::env::var(MODULE_ENV) {
        v.push(p.into());
    }
    #[cfg(windows)]
    {
        let sys = std::env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".into());
        for dll in ["eps2003csp11v2.dll", "eps2003csp11.dll"] {
            v.push(Path::new(&sys).join("System32").join(dll));
        }
        let pf = std::env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".into());
        v.push(Path::new(&pf).join("OpenSC Project\\OpenSC\\pkcs11\\opensc-pkcs11.dll"));
    }
    #[cfg(target_os = "macos")]
    {
        for dir in ["/usr/local/lib", "/Library/Frameworks", "/usr/lib"] {
            if let Ok(rd) = std::fs::read_dir(dir) {
                for e in rd.flatten() {
                    let n = e.file_name().to_string_lossy().to_lowercase();
                    if (n.contains("eps2003") || n.contains("castle") || n.contains("hyper"))
                        && n.ends_with(".dylib")
                    {
                        v.push(e.path());
                    }
                }
            }
        }
        v.push("/Library/OpenSC/lib/opensc-pkcs11.so".into());
        v.push("/opt/homebrew/lib/opensc-pkcs11.so".into());
        v.push("/usr/local/lib/opensc-pkcs11.so".into());
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        v.push("/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so".into());
        v.push("/usr/lib/opensc-pkcs11.so".into());
    }
    v
}

pub fn find_module() -> Option<PathBuf> {
    module_candidates().into_iter().find(|p| p.is_file())
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
    pub slot: Slot,
    pub token_label: String,
    pub ck_id: Vec<u8>,
    pub der: Vec<u8>,
    pub summary: CertSummary,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PinStatus {
    pub count_low: bool,
    pub final_try: bool,
    pub locked: bool,
}

pub struct Token {
    ctx: Pkcs11,
    pub module: PathBuf,
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
            module: module.to_path_buf(),
        })
    }

    pub fn open_default() -> Result<Self, Error> {
        let m = find_module().ok_or_else(|| {
            Error::Token("No DSC token driver found. Install the HyperPKI software or choose the driver file.".into())
        })?;
        Self::open(&m)
    }

    pub fn pin_status(&self, slot: Slot) -> Result<PinStatus, Error> {
        let ti = self.ctx.get_token_info(slot).map_err(ck)?;
        Ok(PinStatus {
            count_low: ti.user_pin_count_low(),
            final_try: ti.user_pin_final_try(),
            locked: ti.user_pin_locked(),
        })
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
    pub fn signer(&self, cert: &TokenCert, pin: &str) -> Result<TokenSigner, Error> {
        let status = self.pin_status(cert.slot).unwrap_or_default();
        if status.locked {
            return Err(Error::PinLocked);
        }
        let session = self.ctx.open_ro_session(cert.slot).map_err(ck)?;
        match session.login(UserType::User, Some(&AuthPin::new(pin.into()))) {
            Ok(()) | Err(CkError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => {}
            Err(CkError::Pkcs11(RvError::PinIncorrect | RvError::PinLenRange, _)) => {
                let s = self.pin_status(cert.slot).unwrap_or_default();
                if s.locked {
                    return Err(Error::PinLocked);
                }
                return Err(Error::WrongPin {
                    final_try: s.final_try,
                    count_low: s.count_low,
                });
            }
            Err(CkError::Pkcs11(RvError::PinLocked, _)) => return Err(Error::PinLocked),
            Err(e) => return Err(ck(e)),
        }

        let key = find_private_key(&session, cert)?;

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
            session,
            key,
            kind: cert.summary.key_kind,
            sig_len: cert.summary.signature_len,
            cert: cert.der.clone(),
            chain,
        })
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

pub struct TokenSigner {
    session: Session,
    key: ObjectHandle,
    kind: KeyKind,
    sig_len: usize,
    cert: Vec<u8>,
    chain: Vec<Vec<u8>>,
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
            KeyKind::Rsa => self
                .session
                .sign(&Mechanism::RsaPkcs, self.key, &sha256_digest_info(digest))
                .map_err(ck),
            KeyKind::Ec => {
                let raw = self
                    .session
                    .sign(&Mechanism::Ecdsa, self.key, digest)
                    .map_err(ck)?;
                Ok(ecdsa_raw_to_der(&raw))
            }
        }
    }
}

/// Parse helper kept here so callers need not depend on x509-cert.
pub fn parse_certificate(der: &[u8]) -> Result<Certificate, Error> {
    Certificate::from_der(der).map_err(|e| Error::Cms(e.to_string()))
}
