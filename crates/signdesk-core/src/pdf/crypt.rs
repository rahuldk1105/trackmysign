//! Standard security handler: password-protected PDFs.
//!
//! Revisions 2–4 (RC4 40/128-bit and AES-128, keys derived per object) and
//! 5–6 (AES-256, one file key). Most protected PDFs have an empty user
//! password and only restrict what may be done with them; those open
//! without asking.
//!
//! Not encrypted, so never decrypted: the `/Encrypt` dictionary, cross-
//! reference streams, and the `/Contents` of signature dictionaries (the
//! signed bytes must be the hex string in the file).

use aes::cipher::block_padding::{NoPadding, Pkcs7};
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use md5::{Digest, Md5};
use sha2::{Sha256, Sha384, Sha512};

use super::object::{Dict, Obj};
use super::reader::{PdfError, Result};

const PAD: [u8; 32] = [
    0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
    0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
];

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

#[derive(Debug, Clone, Copy, PartialEq)]
enum Method {
    Identity,
    Rc4,
    Aes128,
    Aes256,
}

#[derive(Debug, Clone)]
pub struct Crypt {
    key: Vec<u8>,
    revision: i64,
    strings: Method,
    streams: Method,
    /// Named crypt filters, for streams with a `/Crypt` filter of their own.
    filters: Vec<(Vec<u8>, Method)>,
    encrypt_metadata: bool,
    /// The `/P` permission bits.
    pub permissions: u32,
    /// Opened with the owner password: no restrictions apply.
    pub owner: bool,
    /// Object number of the `/Encrypt` dictionary, if indirect.
    pub encrypt_id: Option<u32>,
}

/// Everything the handler needs from `/Encrypt`.
struct Params<'a> {
    revision: i64,
    len: usize,
    o: &'a [u8],
    u: &'a [u8],
    p: u32,
    id0: &'a [u8],
    encrypt_metadata: bool,
}

impl Crypt {
    /// Unlocks the document with `password`, as owner or user. `None` tries
    /// the empty password, which opens most protected files.
    pub fn open(encrypt: &Dict, id0: &[u8], password: Option<&str>) -> Result<Crypt> {
        let unsupported = |what: &str| PdfError::Encrypted(what.to_string());
        if !encrypt.get("Filter").is_some_and(|f| f.is_name("Standard")) {
            return Err(unsupported("it is locked to certificates, not a password"));
        }
        let int = |k: &str| encrypt.get(k).and_then(Obj::as_i64);
        let bytes = |k: &str| match encrypt.get(k) {
            Some(Obj::Str(s)) => s.as_slice(),
            _ => &[],
        };
        let v = int("V").unwrap_or(0);
        let revision = int("R").unwrap_or(0);
        if !matches!(v, 1 | 2 | 4 | 5) || !(2..=6).contains(&revision) {
            return Err(unsupported(&format!(
                "security handler version {v}, revision {revision}"
            )));
        }
        let encrypt_metadata = !matches!(encrypt.get("EncryptMetadata"), Some(Obj::Bool(false)));

        // Crypt filters (V4+); V1 and V2 use RC4 for everything.
        let mut filters = Vec::new();
        let (strings, streams) = if v >= 4 {
            if let Some(Obj::Dict(cf)) = encrypt.get("CF") {
                for (name, f) in &cf.0 {
                    let cfm = f.as_dict().and_then(|d| d.get("CFM"));
                    let m = match cfm {
                        Some(Obj::Name(n)) if n == b"V2" => Method::Rc4,
                        Some(Obj::Name(n)) if n == b"AESV2" => Method::Aes128,
                        Some(Obj::Name(n)) if n == b"AESV3" => Method::Aes256,
                        None => Method::Identity,
                        Some(Obj::Name(n)) if n == b"None" => Method::Identity,
                        Some(_) => return Err(unsupported("an unknown crypt filter")),
                    };
                    filters.push((name.clone(), m));
                }
            }
            let named = |k: &str| match encrypt.get(k) {
                Some(Obj::Name(n)) => lookup(&filters, n),
                _ => Method::Identity,
            };
            (named("StrF"), named("StmF"))
        } else {
            (Method::Rc4, Method::Rc4)
        };

        let p = int("P").unwrap_or(0) as u32;
        let len = if revision >= 5 {
            32
        } else if revision == 2 {
            5
        } else if filters.iter().any(|(_, m)| *m == Method::Aes128) {
            16
        } else {
            (int("Length").unwrap_or(40) / 8).clamp(5, 16) as usize
        };
        let params = Params {
            revision,
            len,
            o: bytes("O"),
            u: bytes("U"),
            p,
            id0,
            encrypt_metadata,
        };
        let pw = password.unwrap_or("");
        let unlocked = if revision >= 5 {
            let pw = utf8_password(pw);
            owner_key_r6(&params, bytes("OE"), &pw)
                .map(|k| (k, true))
                .or_else(|| user_key_r6(&params, bytes("UE"), &pw).map(|k| (k, false)))
        } else {
            let pw = latin1_password(pw);
            owner_key(&params, &pw)
                .map(|k| (k, true))
                .or_else(|| user_key(&params, &pad(&pw)).map(|k| (k, false)))
        };
        let Some((key, owner)) = unlocked else {
            return Err(match password {
                None => PdfError::PasswordRequired,
                Some(_) => PdfError::WrongPassword,
            });
        };
        Ok(Crypt {
            key,
            revision,
            strings,
            streams,
            filters,
            encrypt_metadata,
            permissions: p,
            owner,
            encrypt_id: None,
        })
    }

    /// Whether a signature may be added: "fill in form fields" (bit 9,
    /// revision 3+) or "annotate and fill in forms" (bit 6), or the owner
    /// password was given.
    pub fn may_sign(&self) -> bool {
        let p = self.permissions;
        self.owner || p & (1 << 5) != 0 || (self.revision >= 3 && p & (1 << 8) != 0)
    }

    /// Decrypts the strings and stream data of object `id`.
    pub fn decrypt(&self, id: u32, gn: u16, obj: Obj) -> Obj {
        self.apply(id, gn, obj, false)
    }

    /// Encrypts a new or changed object for writing.
    pub fn encrypt(&self, id: u32, gn: u16, obj: &Obj) -> Obj {
        self.apply(id, gn, obj.clone(), true)
    }

    fn apply(&self, id: u32, gn: u16, obj: Obj, enc: bool) -> Obj {
        match obj {
            Obj::Str(s) => Obj::Str(self.run(self.strings, id, gn, &s, enc)),
            Obj::Array(a) => {
                Obj::Array(a.into_iter().map(|o| self.apply(id, gn, o, enc)).collect())
            }
            Obj::Dict(d) => Obj::Dict(self.apply_dict(id, gn, d, enc)),
            Obj::Stream(d, data) => {
                if is_type(&d, "XRef") {
                    return Obj::Stream(d, data);
                }
                let mut d = self.apply_dict(id, gn, d, enc);
                let method = if !self.encrypt_metadata && is_type(&d, "Metadata") {
                    Method::Identity
                } else if enc {
                    self.streams
                } else {
                    take_crypt_filter(&mut d)
                        .map(|name| lookup(&self.filters, &name))
                        .unwrap_or(self.streams)
                };
                let data = self.run(method, id, gn, &data, enc);
                Obj::Stream(d, data)
            }
            o => o,
        }
    }

    fn apply_dict(&self, id: u32, gn: u16, d: Dict, enc: bool) -> Dict {
        let sig = is_signature(&d);
        Dict(
            d.0.into_iter()
                .map(|(k, v)| {
                    if sig && k == b"Contents" {
                        (k, v)
                    } else {
                        (k, self.apply(id, gn, v, enc))
                    }
                })
                .collect(),
        )
    }

    fn run(&self, method: Method, id: u32, gn: u16, data: &[u8], enc: bool) -> Vec<u8> {
        match method {
            Method::Identity => data.to_vec(),
            Method::Rc4 => rc4(&self.object_key(id, gn, false), data),
            Method::Aes128 | Method::Aes256 => {
                let key = if method == Method::Aes256 {
                    self.key.clone()
                } else {
                    self.object_key(id, gn, true)
                };
                if enc {
                    aes_encrypt(&key, data)
                } else {
                    aes_decrypt(&key, data)
                }
            }
        }
    }

    /// Algorithm 1: the file key extended with the object number and generation.
    fn object_key(&self, id: u32, gn: u16, aes: bool) -> Vec<u8> {
        if self.revision >= 5 {
            return self.key.clone();
        }
        let mut h = Md5::new();
        h.update(&self.key);
        h.update(&id.to_le_bytes()[..3]);
        h.update(gn.to_le_bytes());
        if aes {
            h.update(b"sAlT");
        }
        let mut k = h.finalize().to_vec();
        k.truncate((self.key.len() + 5).min(16));
        k
    }
}

fn lookup(filters: &[(Vec<u8>, Method)], name: &[u8]) -> Method {
    if name == b"Identity" {
        return Method::Identity;
    }
    filters
        .iter()
        .find(|(n, _)| n == name)
        .map_or(Method::Identity, |(_, m)| *m)
}

fn is_type(d: &Dict, t: &str) -> bool {
    d.get("Type").is_some_and(|v| v.is_name(t))
}

/// Signature and document timestamp dictionaries keep `/Contents` in the clear.
pub fn is_signature(d: &Dict) -> bool {
    is_type(d, "Sig")
        || is_type(d, "DocTimeStamp")
        || (d.get("ByteRange").is_some() && d.get("Contents").is_some())
}

/// Removes a leading `/Crypt` filter from a stream dictionary and returns the
/// crypt filter it names (`/Identity` when it names none).
fn take_crypt_filter(d: &mut Dict) -> Option<Vec<u8>> {
    let first_is_crypt = match d.get("Filter") {
        Some(Obj::Array(a)) => a.first().is_some_and(|f| f.is_name("Crypt")),
        Some(f) => f.is_name("Crypt"),
        None => false,
    };
    if !first_is_crypt {
        return None;
    }
    let parms = match d.get("DecodeParms") {
        Some(Obj::Array(a)) => a.first().cloned(),
        Some(p) => Some(p.clone()),
        None => None,
    };
    let name = match parms
        .as_ref()
        .and_then(Obj::as_dict)
        .and_then(|p| p.get("Name"))
    {
        Some(Obj::Name(n)) => n.clone(),
        _ => b"Identity".to_vec(),
    };
    for key in ["Filter", "DecodeParms"] {
        match d.get(key).cloned() {
            Some(Obj::Array(mut a)) if a.len() > 1 => {
                a.remove(0);
                d.set(key, Obj::Array(a));
            }
            Some(_) => d.remove(key),
            None => {}
        }
    }
    Some(name)
}

// ------------------------------------------------------- revisions 2-4

/// Passwords are PDFDocEncoding; Latin-1 covers what people type.
fn latin1_password(pw: &str) -> Vec<u8> {
    if pw.chars().all(|c| (c as u32) < 256) {
        pw.chars().map(|c| c as u8).collect()
    } else {
        pw.as_bytes().to_vec()
    }
}

fn pad(pw: &[u8]) -> [u8; 32] {
    let mut out = PAD;
    let n = pw.len().min(32);
    out[..n].copy_from_slice(&pw[..n]);
    out[n..].copy_from_slice(&PAD[..32 - n]);
    out
}

/// Algorithm 2: file key from a (padded) user password.
fn file_key(p: &Params, padded: &[u8; 32]) -> Vec<u8> {
    let mut h = Md5::new();
    h.update(padded);
    h.update(p.o);
    h.update(p.p.to_le_bytes());
    h.update(p.id0);
    if p.revision >= 4 && !p.encrypt_metadata {
        h.update([0xff; 4]);
    }
    let mut key = h.finalize().to_vec();
    if p.revision >= 3 {
        for _ in 0..50 {
            key = Md5::digest(&key[..p.len]).to_vec();
        }
    }
    key.truncate(p.len);
    key
}

/// Algorithms 4–6: the file key if `padded` is the user password.
fn user_key(p: &Params, padded: &[u8; 32]) -> Option<Vec<u8>> {
    let key = file_key(p, padded);
    let ok = if p.revision == 2 {
        p.u.len() >= 32 && rc4(&key, &PAD) == p.u[..32]
    } else {
        let mut h = Md5::new();
        h.update(PAD);
        h.update(p.id0);
        let mut x = rc4(&key, &h.finalize());
        for i in 1..=19u8 {
            x = rc4(&xor_key(&key, i), &x);
        }
        p.u.len() >= 16 && x[..16] == p.u[..16]
    };
    ok.then_some(key)
}

/// Algorithm 7: the owner password decrypts `/O` to the user password.
fn owner_key(p: &Params, pw: &[u8]) -> Option<Vec<u8>> {
    let mut k = Md5::digest(pad(pw)).to_vec();
    if p.revision >= 3 {
        for _ in 0..50 {
            k = Md5::digest(&k).to_vec();
        }
    }
    k.truncate(p.len);
    let o = p.o.get(..32)?;
    let user = if p.revision == 2 {
        rc4(&k, o)
    } else {
        (0..=19u8)
            .rev()
            .fold(o.to_vec(), |x, i| rc4(&xor_key(&k, i), &x))
    };
    user_key(p, &user.try_into().ok()?)
}

fn xor_key(key: &[u8], i: u8) -> Vec<u8> {
    key.iter().map(|b| b ^ i).collect()
}

// ------------------------------------------------------- revisions 5-6

/// UTF-8, at most 127 bytes (SASLprep is skipped; it changes nothing for
/// passwords people type).
fn utf8_password(pw: &str) -> Vec<u8> {
    let mut b = pw.as_bytes().to_vec();
    b.truncate(127);
    b
}

fn user_key_r6(p: &Params, ue: &[u8], pw: &[u8]) -> Option<Vec<u8>> {
    let (hash, rest) = p.u.get(..48)?.split_at(32);
    if hash_r6(p.revision, pw, &rest[..8], &[]) != hash {
        return None;
    }
    let k = hash_r6(p.revision, pw, &rest[8..], &[]);
    unwrap_key(&k, ue)
}

fn owner_key_r6(p: &Params, oe: &[u8], pw: &[u8]) -> Option<Vec<u8>> {
    let (hash, rest) = p.o.get(..48)?.split_at(32);
    let u = p.u.get(..48)?;
    if hash_r6(p.revision, pw, &rest[..8], u) != hash {
        return None;
    }
    let k = hash_r6(p.revision, pw, &rest[8..], u);
    unwrap_key(&k, oe)
}

/// `/UE` or `/OE`: the file key, AES-256 encrypted with a zero IV.
fn unwrap_key(k: &[u8; 32], wrapped: &[u8]) -> Option<Vec<u8>> {
    let wrapped = wrapped.get(..32)?;
    Aes256CbcDec::new_from_slices(k, &[0; 16])
        .ok()?
        .decrypt_padded_vec_mut::<NoPadding>(wrapped)
        .ok()
}

/// Revision 5: SHA-256. Revision 6: Algorithm 2.B, rounds of AES-128 and
/// SHA-256/384/512 until the last byte says stop (at least 64).
fn hash_r6(revision: i64, pw: &[u8], salt: &[u8], udata: &[u8]) -> [u8; 32] {
    let mut k: Vec<u8> = Sha256::new()
        .chain_update(pw)
        .chain_update(salt)
        .chain_update(udata)
        .finalize()
        .to_vec();
    if revision >= 6 {
        let mut round = 0u32;
        loop {
            let mut k1 = Vec::with_capacity(64 * (pw.len() + k.len() + udata.len()));
            for _ in 0..64 {
                k1.extend_from_slice(pw);
                k1.extend_from_slice(&k);
                k1.extend_from_slice(udata);
            }
            let e = Aes128CbcEnc::new_from_slices(&k[..16], &k[16..32])
                .expect("16-byte key and IV")
                .encrypt_padded_vec_mut::<NoPadding>(&k1);
            k = match e[..16].iter().map(|b| *b as u32).sum::<u32>() % 3 {
                0 => Sha256::digest(&e).to_vec(),
                1 => Sha384::digest(&e).to_vec(),
                _ => Sha512::digest(&e).to_vec(),
            };
            round += 1;
            if round >= 64 && (e[e.len() - 1] as u32) + 32 <= round {
                break;
            }
        }
    }
    let mut out = [0; 32];
    out.copy_from_slice(&k[..32]);
    out
}

// ------------------------------------------------------------ ciphers

fn rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
    use rc4::consts::*;
    use rc4::{KeyInit, Rc4, StreamCipher};
    let mut out = data.to_vec();
    macro_rules! run {
        ($($n:literal => $t:ty),*) => {
            match key.len() {
                $($n => Rc4::<$t>::new_from_slice(key)
                    .expect("key length matches")
                    .apply_keystream(&mut out),)*
                n => unreachable!("RC4 key of {n} bytes"),
            }
        };
    }
    run!(5 => U5, 6 => U6, 7 => U7, 8 => U8, 9 => U9, 10 => U10, 11 => U11,
         12 => U12, 13 => U13, 14 => U14, 15 => U15, 16 => U16);
    out
}

/// AES-CBC with the IV in front and PKCS#7 padding. Damaged data comes back
/// as decrypted as possible rather than failing the whole file.
fn aes_decrypt(key: &[u8], data: &[u8]) -> Vec<u8> {
    if data.len() < 32 {
        return Vec::new();
    }
    let (iv, body) = data.split_at(16);
    let body = &body[..body.len() / 16 * 16];
    let run = |pkcs7: bool| -> Option<Vec<u8>> {
        if key.len() == 32 {
            let d = Aes256CbcDec::new_from_slices(key, iv).ok()?;
            if pkcs7 {
                d.decrypt_padded_vec_mut::<Pkcs7>(body).ok()
            } else {
                d.decrypt_padded_vec_mut::<NoPadding>(body).ok()
            }
        } else {
            let d = Aes128CbcDec::new_from_slices(key, iv).ok()?;
            if pkcs7 {
                d.decrypt_padded_vec_mut::<Pkcs7>(body).ok()
            } else {
                d.decrypt_padded_vec_mut::<NoPadding>(body).ok()
            }
        }
    };
    run(true).or_else(|| run(false)).unwrap_or_default()
}

fn aes_encrypt(key: &[u8], data: &[u8]) -> Vec<u8> {
    let iv = random_iv();
    let body = if key.len() == 32 {
        Aes256CbcEnc::new_from_slices(key, &iv)
            .expect("32-byte key")
            .encrypt_padded_vec_mut::<Pkcs7>(data)
    } else {
        Aes128CbcEnc::new_from_slices(key, &iv)
            .expect("16-byte key")
            .encrypt_padded_vec_mut::<Pkcs7>(data)
    };
    [iv.as_slice(), &body].concat()
}

fn random_iv() -> [u8; 16] {
    let mut iv = [0; 16];
    if getrandom::getrandom(&mut iv).is_err() {
        // An IV only has to be unpredictable enough not to repeat.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        iv.copy_from_slice(&Md5::digest(now.as_nanos().to_le_bytes()));
    }
    iv
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rc4_known_answer() {
        // RFC 6229, 40-bit key 0102030405.
        let out = rc4(&[1, 2, 3, 4, 5], &[0; 8]);
        assert_eq!(out, [0xb2, 0x39, 0x63, 0x05, 0xf0, 0x3d, 0xc0, 0x27]);
    }

    #[test]
    fn aes_round_trip() {
        for key in [vec![7u8; 16], vec![9u8; 32]] {
            let data = b"Digitally signed by DK RAHUL";
            let enc = aes_encrypt(&key, data);
            assert_eq!(enc.len(), 16 + 32);
            assert_eq!(aes_decrypt(&key, &enc), data);
        }
    }

    #[test]
    fn signature_contents_stay_in_the_clear() {
        let crypt = Crypt {
            key: vec![1; 16],
            revision: 4,
            strings: Method::Aes128,
            streams: Method::Aes128,
            filters: vec![],
            encrypt_metadata: true,
            permissions: 0,
            owner: false,
            encrypt_id: None,
        };
        let sig = Obj::Dict(
            Dict::new()
                .with("Type", Obj::name("Sig"))
                .with("Name", Obj::str("DK RAHUL"))
                .with("Contents", Obj::Str(vec![0x30, 0x82])),
        );
        let enc = crypt.encrypt(5, 0, &sig);
        let d = enc.as_dict().unwrap();
        assert_eq!(d.get("Contents"), Some(&Obj::Str(vec![0x30, 0x82])));
        assert_ne!(d.get("Name"), Some(&Obj::str("DK RAHUL")));
        assert_eq!(crypt.decrypt(5, 0, enc), sig);
    }

    #[test]
    fn crypt_filter_is_taken_off() {
        let mut d = Dict::new()
            .with(
                "Filter",
                Obj::Array(vec![Obj::name("Crypt"), Obj::name("FlateDecode")]),
            )
            .with(
                "DecodeParms",
                Obj::Array(vec![
                    Obj::Dict(Dict::new().with("Name", Obj::name("Identity"))),
                    Obj::Null,
                ]),
            );
        assert_eq!(take_crypt_filter(&mut d), Some(b"Identity".to_vec()));
        assert_eq!(
            d.get("Filter"),
            Some(&Obj::Array(vec![Obj::name("FlateDecode")]))
        );
    }
}
