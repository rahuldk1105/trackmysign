//! The TLS certificate the listener presents on `https://127.0.0.1`.
//!
//! Each installation makes its own certificate authority, limited by name
//! constraints to `127.0.0.1` and `localhost`, uses it once to issue the
//! server certificate, and throws its private key away. Only the CA's public
//! certificate is kept, to be added to (and later removed from) the user's
//! trust store; nothing else can ever be issued under it.

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use der::Decode;
use rcgen::{
    BasicConstraints, CertificateParams, CidrSubnet, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    NameConstraints, SanType, SerialNumber,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha1::{Digest, Sha1};

use crate::Error;

/// Server certificate lifetime. Apple platforms refuse TLS certificates
/// valid for more than 825 days, also under a root the user added.
pub const VALID_DAYS: i64 = 820;

const CA_FILE: &str = "ca.cer";
const CERT_FILE: &str = "server.cer";
const KEY_FILE: &str = "server.key";

/// A freshly made identity. The CA's private key is already gone.
pub struct Generated {
    /// Public certificate of the per-install CA (DER).
    pub ca: Vec<u8>,
    /// Server certificate (DER), issued by `ca`.
    pub cert: Vec<u8>,
    /// Server private key (PKCS#8 DER).
    pub key: Vec<u8>,
}

fn random_serial() -> Result<SerialNumber, Error> {
    let mut bytes = [0u8; 16];
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(&mut bytes)
        .map_err(|_| Error::new("no random numbers available"))?;
    // Positive and without a leading zero byte.
    bytes[0] = (bytes[0] & 0x7f) | 0x40;
    Ok(SerialNumber::from_slice(&bytes))
}

/// Makes the CA and the server certificate, valid from `now` (minus a day,
/// for clocks that are slightly off).
pub fn generate(now: std::time::SystemTime) -> Result<Generated, Error> {
    let now = time::OffsetDateTime::from(now);
    let not_before = now - time::Duration::days(1);
    let not_after = now + time::Duration::days(VALID_DAYS);

    let ca_key = KeyPair::generate().map_err(Error::from_rcgen)?;
    let mut ca = CertificateParams::default();
    let mut name = DistinguishedName::new();
    name.push(DnType::OrganizationName, "TrackMySign");
    // Unique, so one installation's CA can be told from another's.
    let id: String = random_serial()?
        .to_bytes()
        .iter()
        .take(4)
        .map(|b| format!("{b:02X}"))
        .collect();
    name.push(
        DnType::CommonName,
        format!("TrackMySign local signer CA {id} (127.0.0.1 only)"),
    );
    ca.distinguished_name = name;
    ca.serial_number = Some(random_serial()?);
    ca.not_before = not_before;
    ca.not_after = not_after;
    ca.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca.name_constraints = Some(NameConstraints {
        permitted_subtrees: vec![
            GeneralSubtree::IpAddress(CidrSubnet::from_v4_prefix([127, 0, 0, 1], 32)),
            GeneralSubtree::DnsName("localhost".into()),
        ],
        excluded_subtrees: Vec::new(),
    });
    let ca_cert = ca.self_signed(&ca_key).map_err(Error::from_rcgen)?;

    let key = KeyPair::generate().map_err(Error::from_rcgen)?;
    let mut leaf = CertificateParams::default();
    let mut name = DistinguishedName::new();
    name.push(DnType::OrganizationName, "TrackMySign");
    name.push(DnType::CommonName, "127.0.0.1");
    leaf.distinguished_name = name;
    leaf.serial_number = Some(random_serial()?);
    leaf.not_before = not_before;
    leaf.not_after = not_after;
    leaf.is_ca = IsCa::ExplicitNoCa;
    leaf.subject_alt_names = vec![
        SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        SanType::DnsName("localhost".try_into().map_err(Error::from_rcgen)?),
    ];
    leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf.use_authority_key_identifier_extension = true;
    let issuer = Issuer::new(ca, ca_key);
    let cert = leaf.signed_by(&key, &issuer).map_err(Error::from_rcgen)?;
    // The CA key goes here: nothing else can be issued under this CA.
    drop(issuer);

    Ok(Generated {
        ca: ca_cert.der().to_vec(),
        cert: cert.der().to_vec(),
        key: key.serialize_der(),
    })
}

/// SHA-1 thumbprint in upper-case hex, as Windows and `security` name
/// certificates.
pub fn thumbprint(der: &[u8]) -> String {
    Sha1::digest(der)
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect()
}

/// Last day of a certificate's validity.
pub fn not_after(der: &[u8]) -> Result<std::time::SystemTime, Error> {
    let cert = x509_cert::Certificate::from_der(der).map_err(|e| Error::new(e.to_string()))?;
    Ok(cert.tbs_certificate.validity.not_after.to_system_time())
}

/// The identity's files in the app's data folder.
#[derive(Debug, Clone)]
pub struct Store {
    pub dir: PathBuf,
}

/// A stored identity.
pub struct Stored {
    pub ca: Vec<u8>,
    pub cert: Vec<u8>,
    pub key: Vec<u8>,
}

impl Store {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Store { dir: dir.into() }
    }

    /// Path of the CA certificate, as handed to the trust-store tools.
    pub fn ca_path(&self) -> PathBuf {
        self.dir.join(CA_FILE)
    }

    pub fn save(&self, g: &Generated) -> Result<(), Error> {
        std::fs::create_dir_all(&self.dir)?;
        write_private(&self.dir.join(KEY_FILE), &g.key)?;
        write_private(&self.dir.join(CERT_FILE), &g.cert)?;
        write_private(&self.ca_path(), &g.ca)?;
        Ok(())
    }

    pub fn load(&self) -> Result<Stored, Error> {
        Ok(Stored {
            ca: std::fs::read(self.ca_path())?,
            cert: std::fs::read(self.dir.join(CERT_FILE))?,
            key: std::fs::read(self.dir.join(KEY_FILE))?,
        })
    }

    /// The CA certificate, if one was saved.
    pub fn ca(&self) -> Option<Vec<u8>> {
        std::fs::read(self.ca_path()).ok()
    }

    /// Deletes the files; missing ones are fine.
    pub fn remove(&self) -> Result<(), Error> {
        for f in [KEY_FILE, CERT_FILE, CA_FILE] {
            match std::fs::remove_file(self.dir.join(f)) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
                _ => {}
            }
        }
        Ok(())
    }
}

/// Written readable by the owner only (on Windows the per-user app data
/// folder already is).
fn write_private(path: &Path, data: &[u8]) -> Result<(), Error> {
    let _ = std::fs::remove_file(path);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    use std::io::Write;
    options.open(path)?.write_all(data)?;
    Ok(())
}

/// rustls configuration presenting `cert`.
pub fn server_config(cert: &[u8], key: &[u8]) -> Result<Arc<rustls::ServerConfig>, Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::new(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert.to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec())),
        )
        .map_err(|e| Error::new(format!("unusable server certificate: {e}")))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::Encode;
    use x509_cert::Certificate;
    use x509_cert::ext::pkix::name::GeneralName;
    use x509_cert::ext::pkix::{BasicConstraints, NameConstraints, SubjectAltName};

    fn ext<'a, T: der::Decode<'a>>(c: &'a Certificate, oid: &str) -> Option<T> {
        let oid = der::oid::ObjectIdentifier::new_unwrap(oid);
        c.tbs_certificate
            .extensions
            .iter()
            .flatten()
            .find(|e| e.extn_id == oid)
            .and_then(|e| T::from_der(e.extn_value.as_bytes()).ok())
    }

    #[test]
    fn ca_is_constrained_and_leaf_is_loopback_only() {
        let now = std::time::SystemTime::now();
        let g = generate(now).unwrap();
        let ca = Certificate::from_der(&g.ca).unwrap();
        let leaf = Certificate::from_der(&g.cert).unwrap();

        let bc: BasicConstraints = ext(&ca, "2.5.29.19").unwrap();
        assert!(bc.ca);
        assert_eq!(bc.path_len_constraint, Some(0));
        let nc: NameConstraints = ext(&ca, "2.5.29.30").unwrap();
        let permitted: Vec<GeneralName> = nc
            .permitted_subtrees
            .unwrap()
            .into_iter()
            .map(|s| s.base)
            .collect();
        assert_eq!(permitted.len(), 2);
        assert!(
            permitted
                .iter()
                .any(|n| matches!(n, GeneralName::DnsName(d) if d.as_str() == "localhost"))
        );
        assert!(
            permitted
                .iter()
                .any(|n| matches!(n, GeneralName::IpAddress(ip)
            if ip.as_bytes() == [127, 0, 0, 1, 255, 255, 255, 255]))
        );

        assert_eq!(leaf.tbs_certificate.issuer, ca.tbs_certificate.subject);
        let san: SubjectAltName = ext(&leaf, "2.5.29.17").unwrap();
        assert_eq!(san.0.len(), 2);
        let bc: BasicConstraints = ext(&leaf, "2.5.29.19").unwrap();
        assert!(!bc.ca);
        let days = (leaf.tbs_certificate.validity.not_after.to_unix_duration()
            - leaf.tbs_certificate.validity.not_before.to_unix_duration())
        .as_secs()
            / 86_400;
        assert!(days <= 825, "{days}");

        // A second install gets a different CA.
        let other = generate(now).unwrap();
        assert_ne!(
            Certificate::from_der(&other.ca)
                .unwrap()
                .tbs_certificate
                .subject
                .to_der()
                .unwrap(),
            ca.tbs_certificate.subject.to_der().unwrap()
        );
        assert!(server_config(&g.cert, &g.key).is_ok());
    }

    #[test]
    fn store_round_trip_and_private_files() {
        let dir = std::env::temp_dir().join(format!("tms-portal-store-{}", std::process::id()));
        let store = Store::new(&dir);
        let g = generate(std::time::SystemTime::now()).unwrap();
        store.save(&g).unwrap();
        let s = store.load().unwrap();
        assert_eq!(
            (s.ca, s.cert, s.key),
            (g.ca.clone(), g.cert.clone(), g.key.clone())
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for f in [KEY_FILE, CERT_FILE, CA_FILE] {
                let mode = std::fs::metadata(dir.join(f)).unwrap().permissions().mode();
                assert_eq!(mode & 0o777, 0o600, "{f}");
            }
        }
        store.remove().unwrap();
        assert!(store.load().is_err());
        store.remove().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(
            thumbprint(b"abc"),
            "A9993E364706816ABA3E25717850C26C9CD0D89D"
        );
    }
}
