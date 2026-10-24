//! Document security store (PAdES-B-LT): validation data appended after a
//! signature in a second incremental update.
//!
//! Only new objects and a catalog with a `/DSS` entry are written, which
//! validators accept as a permitted change after signing.

use std::collections::BTreeMap;
use std::io::Write as _;

use sha1::{Digest, Sha1};

use super::object::{Dict, Obj};
use super::reader::{Document, Result, XrefEntry, decode_stream};
use super::sign::{write_objects, write_xref_stream, write_xref_table};

/// What goes into the store for one signature.
pub struct Validation<'a> {
    /// The signature's full `/Contents` bytes, padding included (VRI key).
    pub contents: &'a [u8],
    pub certs: &'a [Vec<u8>],
    pub ocsps: &'a [Vec<u8>],
    pub crls: &'a [Vec<u8>],
}

/// VRI key: upper-case hex SHA-1 of the signature's `/Contents`.
pub fn vri_key(contents: &[u8]) -> String {
    Sha1::digest(contents)
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect()
}

fn flate(data: &[u8]) -> Vec<u8> {
    let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    let _ = z.write_all(data);
    z.finish().unwrap_or_default()
}

/// Appends a `/DSS` update to `input`, merging with any store already there.
pub fn append(input: &[u8], v: &Validation) -> Result<Vec<u8>> {
    append_with_password(input, None, v)
}

/// [`append`] for a password-protected PDF; the new objects are encrypted.
pub fn append_with_password(
    input: &[u8],
    password: Option<&str>,
    v: &Validation,
) -> Result<Vec<u8>> {
    let doc = Document::open(input, password)?;
    let (cat_id, cat_gen) = doc.catalog_ref()?;
    let mut catalog = doc.catalog()?;

    let mut next = doc.next_object_id();
    let mut objs: BTreeMap<u32, (u16, Obj)> = BTreeMap::new();

    let (dss_ref, mut dss) = match catalog.get("DSS") {
        Some(Obj::Ref(id, gn)) => (
            Some((*id, *gn)),
            doc.get(*id)?.as_dict().cloned().unwrap_or_default(),
        ),
        Some(Obj::Dict(d)) => (None, d.clone()),
        _ => (None, Dict::new()),
    };

    let mut vri_entry = Dict::new();
    for (key, items) in [("Certs", v.certs), ("OCSPs", v.ocsps), ("CRLs", v.crls)] {
        let mut array = match dss.get(key) {
            Some(o) => doc.resolve(o)?.as_array().cloned().unwrap_or_default(),
            None => Vec::new(),
        };
        // Reuse streams already in the store instead of storing them twice.
        let mut existing: Vec<(Vec<u8>, Obj)> = Vec::new();
        for r in &array {
            if let Obj::Ref(id, _) = r
                && let Obj::Stream(d, raw) = doc.get(*id)?
                && let Ok(data) = decode_stream(&d, &raw)
            {
                existing.push((data, r.clone()));
            }
        }
        let mut refs = Vec::new();
        for item in items {
            if let Some((_, r)) = existing.iter().find(|(d, _)| d == item) {
                refs.push(r.clone());
                continue;
            }
            let id = next;
            next += 1;
            let dict = Dict::new().with("Filter", Obj::name("FlateDecode"));
            objs.insert(id, (0, Obj::Stream(dict, flate(item))));
            existing.push((item.clone(), Obj::Ref(id, 0)));
            array.push(Obj::Ref(id, 0));
            refs.push(Obj::Ref(id, 0));
        }
        if !array.is_empty() {
            dss.set(key, Obj::Array(array));
        }
        if !refs.is_empty() {
            let vri_name = match key {
                "Certs" => "Cert",
                "OCSPs" => "OCSP",
                _ => "CRL",
            };
            vri_entry.set(vri_name, Obj::Array(refs));
        }
    }

    let mut vri = match dss.get("VRI") {
        Some(o) => doc.resolve(o)?.as_dict().cloned().unwrap_or_default(),
        None => Dict::new(),
    };
    vri.set(&vri_key(v.contents), Obj::Dict(vri_entry));
    dss.set("VRI", Obj::Dict(vri));
    dss.set("Type", Obj::name("DSS"));

    match dss_ref {
        Some((id, gn)) => {
            objs.insert(id, (gn, Obj::Dict(dss)));
        }
        None => {
            let id = next;
            next += 1;
            objs.insert(id, (0, Obj::Dict(dss)));
            catalog.set("DSS", Obj::Ref(id, 0));
            objs.insert(cat_id, (cat_gen, Obj::Dict(catalog)));
        }
    }

    // --- write ----------------------------------------------------------
    let mut out = input.to_vec();
    if !matches!(out.last(), Some(b'\n') | Some(b'\r')) {
        out.push(b'\n');
    }
    let mut offsets: BTreeMap<u32, (usize, u16)> = BTreeMap::new();
    write_objects(&mut out, &doc, &objs, &mut offsets);

    let mut trailer = Dict::new();
    trailer.set("Root", Obj::Ref(cat_id, cat_gen));
    for key in ["Info", "ID", "Encrypt"] {
        if let Some(v) = doc.trailer.get(key) {
            trailer.set(key, v.clone());
        }
    }
    let mut entries: BTreeMap<u32, XrefEntry> = offsets
        .iter()
        .map(|(id, (off, gn))| (*id, XrefEntry::Offset(*off, *gn)))
        .collect();
    let xref_pos = out.len();
    if doc.repaired {
        // The previous section could not be read: write a complete one.
        let mut all = doc.sorted_xref();
        all.append(&mut entries);
        let size = next.max(all.keys().max().map(|m| m + 1).unwrap_or(1));
        if doc.has_compressed_objects() {
            all.insert(next, XrefEntry::Offset(xref_pos, 0));
            write_xref_stream(&mut out, next, &all, size + 1, trailer, true);
        } else {
            write_xref_table(&mut out, &all, size, trailer, true);
        }
    } else {
        trailer.set("Prev", Obj::int(doc.startxref as i64));
        if doc.xref_is_stream {
            entries.insert(next, XrefEntry::Offset(xref_pos, 0));
            write_xref_stream(&mut out, next, &entries, next + 1, trailer, false);
        } else {
            write_xref_table(&mut out, &entries, next, trailer, false);
        }
    }
    out.extend_from_slice(format!("startxref\n{xref_pos}\n%%EOF\n").as_bytes());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PDF: &[u8] = b"%PDF-1.7\n1 0 obj\n<</Type/Catalog/Pages 2 0 R>>\nendobj\n2 0 obj\n<</Type/Pages/Kids[]/Count 0>>\nendobj\nxref\n0 3\n0000000000 65535 f\r\n0000000009 00000 n\r\n0000000054 00000 n\r\ntrailer\n<</Size 3/Root 1 0 R>>\nstartxref\n100\n%%EOF\n";

    #[test]
    fn vri_key_is_upper_hex_sha1() {
        assert_eq!(vri_key(b"abc"), "A9993E364706816ABA3E25717850C26C9CD0D89D");
    }

    #[test]
    fn appends_and_merges() {
        let certs = vec![b"cert-a".to_vec(), b"cert-b".to_vec()];
        let ocsps = vec![b"ocsp".to_vec()];
        let one = append(
            PDF,
            &Validation {
                contents: b"sig1",
                certs: &certs,
                ocsps: &ocsps,
                crls: &[],
            },
        )
        .unwrap();
        assert!(one.starts_with(PDF));
        let doc = Document::parse(&one).unwrap();
        assert!(!doc.repaired);
        let dss = doc
            .resolve(doc.catalog().unwrap().get("DSS").unwrap())
            .unwrap();
        let dss = dss.as_dict().unwrap();
        assert_eq!(dss.get("Certs").unwrap().as_array().unwrap().len(), 2);
        assert!(dss.get("CRLs").is_none());

        // A second signature reuses the stored certificate.
        let certs2 = vec![b"cert-b".to_vec(), b"cert-c".to_vec()];
        let two = append(
            &one,
            &Validation {
                contents: b"sig2",
                certs: &certs2,
                ocsps: &[],
                crls: &[b"crl".to_vec()],
            },
        )
        .unwrap();
        assert!(two.starts_with(&one));
        let doc = Document::parse(&two).unwrap();
        let dss = doc
            .resolve(doc.catalog().unwrap().get("DSS").unwrap())
            .unwrap();
        let dss = dss.as_dict().unwrap();
        assert_eq!(dss.get("Certs").unwrap().as_array().unwrap().len(), 3);
        assert_eq!(dss.get("CRLs").unwrap().as_array().unwrap().len(), 1);
        let vri = dss.get("VRI").unwrap().as_dict().unwrap();
        assert!(vri.get(&vri_key(b"sig1")).is_some());
        assert!(vri.get(&vri_key(b"sig2")).is_some());
    }
}
