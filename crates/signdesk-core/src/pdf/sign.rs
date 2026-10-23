//! Appends a signature to a PDF as an incremental update.
//!
//! The original bytes are never modified: new and changed objects, a new
//! cross-reference section and trailer are written after the existing
//! `%%EOF`. That keeps earlier signatures valid.

use std::collections::BTreeMap;

use chrono::{DateTime, FixedOffset};

use super::appearance::{self, Face, Line};
use super::object::{Dict, Obj, write_obj};
use super::reader::{Document, PageInfo, PdfError, Result, XrefEntry};

/// Rectangle on the page as the user sees it: points, origin at the top-left
/// of the displayed (cropped and rotated) page — the same space as a PDF.js
/// viewport at scale 1.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DisplayRect {
    pub x: f64,
    pub y: f64,
    pub w: f64,
    pub h: f64,
}

#[derive(Debug, Clone)]
pub struct SignatureFields {
    pub signer_name: String,
    pub reason: Option<String>,
    pub location: Option<String>,
    pub time: DateTime<FixedOffset>,
}

#[derive(Debug, Clone)]
pub struct Placement {
    /// Zero-based page index.
    pub page: usize,
    /// `None` for an invisible signature.
    pub rect: Option<DisplayRect>,
}

/// A PDF with the signature dictionary in place but `/Contents` still empty.
pub struct Prepared {
    pub data: Vec<u8>,
    /// `[0, contents_start, contents_end, rest]`.
    pub byte_range: [usize; 4],
    pub reserved: usize,
}

impl Prepared {
    /// The two byte ranges covered by the signature.
    pub fn signed_parts(&self) -> [&[u8]; 2] {
        let [_, a, b, c] = self.byte_range;
        [&self.data[..a], &self.data[b..b + c]]
    }

    pub fn finish(mut self, cms_der: &[u8]) -> Result<Vec<u8>> {
        if cms_der.len() > self.reserved {
            return Err(PdfError::Malformed(format!(
                "signature ({} bytes) larger than reserved space ({} bytes)",
                cms_der.len(),
                self.reserved
            )));
        }
        let start = self.byte_range[1] + 1;
        for (i, b) in cms_der.iter().enumerate() {
            let h = format!("{:02X}", b);
            self.data[start + 2 * i] = h.as_bytes()[0];
            self.data[start + 2 * i + 1] = h.as_bytes()[1];
        }
        Ok(self.data)
    }
}

pub fn display_to_user(page: &PageInfo, r: DisplayRect) -> [f64; 4] {
    let [cx0, cy0, cx1, cy1] = page.crop_box;
    let map = |dx: f64, dy: f64| -> (f64, f64) {
        match page.rotate {
            90 => (cx0 + dy, cy0 + dx),
            180 => (cx1 - dx, cy0 + dy),
            270 => (cx1 - dy, cy1 - dx),
            _ => (cx0 + dx, cy1 - dy),
        }
    };
    let (ax, ay) = map(r.x, r.y);
    let (bx, by) = map(r.x + r.w, r.y + r.h);
    [ax.min(bx), ay.min(by), ax.max(bx), ay.max(by)]
}

/// PDF date string, e.g. `D:20261020143210+05'30'`.
pub fn pdf_date(t: &DateTime<FixedOffset>) -> String {
    let off = t.offset().local_minus_utc();
    let sign = if off < 0 { '-' } else { '+' };
    let off = off.abs();
    format!(
        "D:{}{}{:02}'{:02}'",
        t.format("%Y%m%d%H%M%S"),
        sign,
        off / 3600,
        (off % 3600) / 60
    )
}

/// PDF text string: plain bytes for ASCII, UTF-16BE with BOM otherwise.
pub fn text_string(s: &str) -> Obj {
    if s.is_ascii() {
        Obj::Str(s.as_bytes().to_vec())
    } else {
        let mut v = vec![0xfe, 0xff];
        for u in s.encode_utf16() {
            v.extend_from_slice(&u.to_be_bytes());
        }
        Obj::Str(v)
    }
}

pub fn prepare(
    input: &[u8],
    placement: &Placement,
    fields: &SignatureFields,
    reserved: usize,
) -> Result<Prepared> {
    let doc = Document::parse(input)?;
    let pages = doc.pages()?;
    let page = pages
        .get(placement.page)
        .ok_or(PdfError::NoSuchPage(placement.page + 1))?;
    let (cat_id, cat_gen) = doc.catalog_ref()?;
    let mut catalog = doc.catalog()?;

    let mut next = doc.next_object_id();
    let mut alloc = || {
        let id = next;
        next += 1;
        id
    };
    let sig_id = alloc();
    let widget_id = alloc();
    let widget_ref = Obj::Ref(widget_id, 0);

    // Objects to write: id -> (gn, object). BTreeMap keeps the output tidy.
    let mut objs: BTreeMap<u32, (u16, Obj)> = BTreeMap::new();

    // --- form field name -------------------------------------------------
    let (existing, _) = doc.form_fields()?;
    let field_name = (1..)
        .map(|n| format!("Signature{n}"))
        .find(|n| !existing.contains(n))
        .unwrap();

    // --- widget + appearance --------------------------------------------
    let mut widget = Dict::new()
        .with("Type", Obj::name("Annot"))
        .with("Subtype", Obj::name("Widget"))
        .with("FT", Obj::name("Sig"))
        .with("T", text_string(&field_name))
        .with("V", Obj::Ref(sig_id, 0))
        .with("F", Obj::int(132))
        .with("P", Obj::Ref(page.id.0, page.id.1));
    match placement.rect {
        Some(r) => {
            let user = display_to_user(page, r);
            widget.set(
                "Rect",
                Obj::Array(user.iter().map(|v| Obj::real(*v)).collect()),
            );
            let ap_id = alloc();
            let f1 = alloc();
            let f2 = alloc();
            let mut lines = vec![
                Line {
                    text: "Digitally signed by".into(),
                    face: Face::Regular,
                    scale: 1.0,
                },
                Line {
                    text: fields.signer_name.clone(),
                    face: Face::Bold,
                    scale: 1.15,
                },
                Line {
                    text: format!("Date: {}", fields.time.format("%Y.%m.%d %H:%M:%S %:z")),
                    face: Face::Regular,
                    scale: 1.0,
                },
            ];
            if let Some(reason) = fields.reason.as_ref().filter(|s| !s.is_empty()) {
                lines.push(Line {
                    text: format!("Reason: {reason}"),
                    face: Face::Regular,
                    scale: 1.0,
                });
            }
            if let Some(loc) = fields.location.as_ref().filter(|s| !s.is_empty()) {
                lines.push(Line {
                    text: format!("Location: {loc}"),
                    face: Face::Regular,
                    scale: 1.0,
                });
            }
            let content = appearance::content_stream(r.w, r.h, &lines);
            let m = appearance::rotation_matrix(page.rotate, r.w, r.h);
            let font = |base: &str| {
                Obj::Dict(
                    Dict::new()
                        .with("Type", Obj::name("Font"))
                        .with("Subtype", Obj::name("Type1"))
                        .with("BaseFont", Obj::name(base))
                        .with("Encoding", Obj::name("WinAnsiEncoding")),
                )
            };
            objs.insert(f1, (0, font("Helvetica")));
            objs.insert(f2, (0, font("Helvetica-Bold")));
            let ap = Dict::new()
                .with("Type", Obj::name("XObject"))
                .with("Subtype", Obj::name("Form"))
                .with(
                    "BBox",
                    Obj::Array(vec![
                        Obj::int(0),
                        Obj::int(0),
                        Obj::real(r.w),
                        Obj::real(r.h),
                    ]),
                )
                .with(
                    "Matrix",
                    Obj::Array(m.iter().map(|v| Obj::real(*v)).collect()),
                )
                .with(
                    "Resources",
                    Obj::Dict(
                        Dict::new().with(
                            "Font",
                            Obj::Dict(
                                Dict::new()
                                    .with("F1", Obj::Ref(f1, 0))
                                    .with("F2", Obj::Ref(f2, 0)),
                            ),
                        ),
                    ),
                );
            objs.insert(ap_id, (0, Obj::Stream(ap, content)));
            widget.set("AP", Obj::Dict(Dict::new().with("N", Obj::Ref(ap_id, 0))));
        }
        None => {
            widget.set("Rect", Obj::Array(vec![Obj::int(0); 4]));
        }
    }
    objs.insert(widget_id, (0, Obj::Dict(widget)));

    // --- page /Annots ---------------------------------------------------
    let mut page_dict = page.dict.clone();
    let mut page_changed = true;
    match page_dict.get("Annots").cloned() {
        Some(Obj::Ref(aid, agen)) => match doc.get(aid)? {
            Obj::Array(mut a) => {
                a.push(widget_ref.clone());
                objs.insert(aid, (agen, Obj::Array(a)));
                page_changed = false;
            }
            _ => page_dict.set("Annots", Obj::Array(vec![widget_ref.clone()])),
        },
        Some(Obj::Array(mut a)) => {
            a.push(widget_ref.clone());
            page_dict.set("Annots", Obj::Array(a));
        }
        _ => page_dict.set("Annots", Obj::Array(vec![widget_ref.clone()])),
    }
    if page_changed {
        objs.insert(page.id.0, (page.id.1, Obj::Dict(page_dict)));
    }

    // --- AcroForm -------------------------------------------------------
    let add_field = |af: &mut Dict, objs: &mut BTreeMap<u32, (u16, Obj)>| -> Result<()> {
        match af.get("Fields").cloned() {
            Some(Obj::Ref(fid, fgen)) => match doc.get(fid)? {
                Obj::Array(mut a) => {
                    a.push(widget_ref.clone());
                    objs.insert(fid, (fgen, Obj::Array(a)));
                }
                _ => af.set("Fields", Obj::Array(vec![widget_ref.clone()])),
            },
            Some(Obj::Array(mut a)) => {
                a.push(widget_ref.clone());
                af.set("Fields", Obj::Array(a));
            }
            _ => af.set("Fields", Obj::Array(vec![widget_ref.clone()])),
        }
        let flags = af.get("SigFlags").and_then(Obj::as_i64).unwrap_or(0);
        af.set("SigFlags", Obj::int(flags | 3));
        Ok(())
    };
    match catalog.get("AcroForm").cloned() {
        Some(Obj::Ref(afid, afgen)) if doc.get(afid)?.as_dict().is_some() => {
            let mut af = doc.get(afid)?.as_dict().cloned().unwrap();
            add_field(&mut af, &mut objs)?;
            objs.insert(afid, (afgen, Obj::Dict(af)));
        }
        Some(Obj::Dict(mut af)) => {
            add_field(&mut af, &mut objs)?;
            catalog.set("AcroForm", Obj::Dict(af));
            objs.insert(cat_id, (cat_gen, Obj::Dict(catalog)));
        }
        _ => {
            let afid = alloc();
            let mut af = Dict::new();
            add_field(&mut af, &mut objs)?;
            objs.insert(afid, (0, Obj::Dict(af)));
            catalog.set("AcroForm", Obj::Ref(afid, 0));
            objs.insert(cat_id, (cat_gen, Obj::Dict(catalog)));
        }
    }

    // --- write ----------------------------------------------------------
    let mut out = input.to_vec();
    if !matches!(out.last(), Some(b'\n') | Some(b'\r')) {
        out.push(b'\n');
    }
    let mut offsets: BTreeMap<u32, (usize, u16)> = BTreeMap::new();

    // Signature dictionary first, with fixed-width placeholders.
    offsets.insert(sig_id, (out.len(), 0));
    out.extend_from_slice(format!("{sig_id} 0 obj\n<<").as_bytes());
    let mut sig = Dict::new()
        .with("Type", Obj::name("Sig"))
        .with("Filter", Obj::name("Adobe.PPKLite"))
        .with("SubFilter", Obj::name("adbe.pkcs7.detached"))
        .with("Name", text_string(&fields.signer_name))
        .with("M", Obj::Str(pdf_date(&fields.time).into_bytes()));
    if let Some(r) = fields.reason.as_ref().filter(|s| !s.is_empty()) {
        sig.set("Reason", text_string(r));
    }
    if let Some(l) = fields.location.as_ref().filter(|s| !s.is_empty()) {
        sig.set("Location", text_string(l));
    }
    sig.set(
        "Prop_Build",
        Obj::Dict(Dict::new().with(
            "App",
            Obj::Dict(Dict::new().with("Name", Obj::name("TrackMySign"))),
        )),
    );
    for (k, v) in &sig.0 {
        super::object::write_name(&mut out, k);
        out.push(b' ');
        write_obj(&mut out, v);
        out.push(b'\n');
    }
    out.extend_from_slice(b"/ByteRange [0 ");
    let br_pos = out.len();
    out.extend_from_slice(&[b' '; 32]);
    out.extend_from_slice(b"]\n/Contents ");
    let contents_start = out.len();
    out.push(b'<');
    out.extend(std::iter::repeat_n(b'0', reserved * 2));
    out.push(b'>');
    let contents_end = out.len();
    out.extend_from_slice(b"\n>>\nendobj\n");

    for (id, (gn, obj)) in &objs {
        offsets.insert(*id, (out.len(), *gn));
        out.extend_from_slice(format!("{id} {gn} obj\n").as_bytes());
        write_obj(&mut out, obj);
        out.extend_from_slice(b"\nendobj\n");
    }

    let mut trailer = Dict::new();
    trailer.set("Root", Obj::Ref(cat_id, cat_gen));
    for key in ["Info", "ID"] {
        if let Some(v) = doc.trailer.get(key) {
            trailer.set(key, v.clone());
        }
    }

    let xref_pos;
    if doc.repaired {
        // The old cross-reference is unusable: write a complete one, no /Prev.
        let mut all: BTreeMap<u32, XrefEntry> = doc.sorted_xref();
        for (id, (off, gn)) in &offsets {
            all.insert(*id, XrefEntry::Offset(*off, *gn));
        }
        let size = next.max(all.keys().max().map(|m| m + 1).unwrap_or(1));
        if doc.has_compressed_objects() {
            let xid = next;
            xref_pos = out.len();
            all.insert(xid, XrefEntry::Offset(xref_pos, 0));
            write_xref_stream(&mut out, xid, &all, size + 1, trailer, true);
        } else {
            xref_pos = out.len();
            write_xref_table(&mut out, &all, size, trailer, true);
        }
    } else {
        trailer.set("Prev", Obj::int(doc.startxref as i64));
        let entries: BTreeMap<u32, XrefEntry> = offsets
            .iter()
            .map(|(id, (off, gn))| (*id, XrefEntry::Offset(*off, *gn)))
            .collect();
        if doc.xref_is_stream {
            let xid = next;
            xref_pos = out.len();
            let mut entries = entries;
            entries.insert(xid, XrefEntry::Offset(xref_pos, 0));
            write_xref_stream(&mut out, xid, &entries, next + 1, trailer, false);
        } else {
            xref_pos = out.len();
            write_xref_table(&mut out, &entries, next, trailer, false);
        }
    }
    out.extend_from_slice(format!("startxref\n{xref_pos}\n%%EOF\n").as_bytes());

    let rest = out.len() - contents_end;
    let br = format!("{:<10} {:<10} {:<10}", contents_start, contents_end, rest);
    if br.len() > 32 {
        return Err(PdfError::Malformed("file too large".into()));
    }
    out[br_pos..br_pos + br.len()].copy_from_slice(br.as_bytes());

    Ok(Prepared {
        data: out,
        byte_range: [0, contents_start, contents_end, rest],
        reserved,
    })
}

/// Consecutive runs of object ids, for xref subsections / `/Index`.
fn runs(ids: &[u32]) -> Vec<(u32, u32)> {
    let mut out: Vec<(u32, u32)> = Vec::new();
    for &id in ids {
        match out.last_mut() {
            Some((start, count)) if *start + *count == id => *count += 1,
            _ => out.push((id, 1)),
        }
    }
    out
}

fn write_xref_table(
    out: &mut Vec<u8>,
    entries: &BTreeMap<u32, XrefEntry>,
    size: u32,
    mut trailer: Dict,
    full: bool,
) {
    out.extend_from_slice(b"xref\n");
    let mut ids: Vec<u32> = entries.keys().copied().collect();
    if full {
        // Every id from 0 up, free where unknown.
        ids = (0..size).collect();
    }
    for (start, count) in runs(&ids) {
        out.extend_from_slice(format!("{start} {count}\n").as_bytes());
        for id in start..start + count {
            let line = match entries.get(&id) {
                Some(XrefEntry::Offset(off, gn)) => format!("{off:010} {gn:05} n\r\n"),
                _ if id == 0 => "0000000000 65535 f\r\n".to_string(),
                _ => "0000000000 00001 f\r\n".to_string(),
            };
            out.extend_from_slice(line.as_bytes());
        }
    }
    trailer.set("Size", Obj::int(size as i64));
    out.extend_from_slice(b"trailer\n");
    write_obj(out, &Obj::Dict(trailer));
    out.push(b'\n');
}

fn write_xref_stream(
    out: &mut Vec<u8>,
    xid: u32,
    entries: &BTreeMap<u32, XrefEntry>,
    size: u32,
    trailer: Dict,
    full: bool,
) {
    let max_off = entries
        .values()
        .map(|e| match e {
            XrefEntry::Offset(o, _) => *o as u64,
            XrefEntry::InStream { container, .. } => *container as u64,
        })
        .max()
        .unwrap_or(0);
    let w1 = ((64 - max_off.leading_zeros()).div_ceil(8)).max(1) as usize;
    let ids: Vec<u32> = if full {
        (0..size).collect()
    } else {
        entries.keys().copied().collect()
    };
    let mut data = Vec::new();
    let put = |v: u64, w: usize, data: &mut Vec<u8>| {
        for i in (0..w).rev() {
            data.push((v >> (8 * i)) as u8);
        }
    };
    for id in &ids {
        match entries.get(id) {
            Some(XrefEntry::Offset(o, g)) => {
                put(1, 1, &mut data);
                put(*o as u64, w1, &mut data);
                put(*g as u64, 2, &mut data);
            }
            Some(XrefEntry::InStream { container, index }) => {
                put(2, 1, &mut data);
                put(*container as u64, w1, &mut data);
                put(*index as u64, 2, &mut data);
            }
            None => {
                put(0, 1, &mut data);
                put(0, w1, &mut data);
                put(if *id == 0 { 65535 } else { 0 }, 2, &mut data);
            }
        }
    }
    let index: Vec<Obj> = runs(&ids)
        .into_iter()
        .flat_map(|(s, c)| [Obj::int(s as i64), Obj::int(c as i64)])
        .collect();
    let mut d = trailer;
    d.set("Type", Obj::name("XRef"));
    d.set("Size", Obj::int(size as i64));
    d.set(
        "W",
        Obj::Array(vec![Obj::int(1), Obj::int(w1 as i64), Obj::int(2)]),
    );
    d.set("Index", Obj::Array(index));
    out.extend_from_slice(format!("{xid} 0 obj\n").as_bytes());
    write_obj(out, &Obj::Stream(d, data));
    out.extend_from_slice(b"\nendobj\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(rotate: i32) -> PageInfo {
        PageInfo {
            id: (3, 0),
            dict: Dict::new(),
            media_box: [0.0, 0.0, 600.0, 800.0],
            crop_box: [0.0, 0.0, 600.0, 800.0],
            rotate,
        }
    }

    #[test]
    fn display_rect_maps_to_user_space() {
        let r = DisplayRect {
            x: 10.0,
            y: 20.0,
            w: 100.0,
            h: 50.0,
        };
        assert_eq!(display_to_user(&page(0), r), [10.0, 730.0, 110.0, 780.0]);
        // Rotated 90°: displayed page is 800 wide, 600 tall.
        assert_eq!(display_to_user(&page(90), r), [20.0, 10.0, 70.0, 110.0]);
        assert_eq!(display_to_user(&page(180), r), [490.0, 20.0, 590.0, 70.0]);
        assert_eq!(display_to_user(&page(270), r), [530.0, 690.0, 580.0, 790.0]);
    }

    #[test]
    fn pdf_dates() {
        let t = DateTime::parse_from_rfc3339("2026-10-20T14:32:10+05:30").unwrap();
        assert_eq!(pdf_date(&t), "D:20261020143210+05'30'");
    }

    #[test]
    fn id_runs() {
        assert_eq!(runs(&[1, 2, 3, 7, 9, 10]), vec![(1, 3), (7, 1), (9, 2)]);
    }
}
