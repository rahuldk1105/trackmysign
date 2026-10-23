//! Appends a signature to a PDF as an incremental update.
//!
//! The original bytes are never modified: new and changed objects, a new
//! cross-reference section and trailer are written after the existing
//! `%%EOF`. That keeps earlier signatures valid.

use std::collections::BTreeMap;

use chrono::{DateTime, FixedOffset};

use super::appearance::{self, Face, ImageSlot, Line};
use super::object::{Dict, Obj, write_obj};
use super::reader::{Document, PageInfo, PdfError, Result, XrefEntry};
use crate::image::{ImagePosition, StampImage};

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
    pub image: Option<StampImage>,
    pub image_position: ImagePosition,
}

#[derive(Debug, Clone)]
pub struct Placement {
    /// Zero-based page index.
    pub page: usize,
    /// `None` for an invisible signature.
    pub rect: Option<DisplayRect>,
    /// Zero-based pages that get the box; empty means just `page`. With more
    /// than one, the signature field gets one widget per page, each placed
    /// by [`rect_on_page`] from the box as drawn on `page`.
    pub pages: Vec<usize>,
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

/// Moves a box drawn on `from` to the same spot on `to`: each edge keeps its
/// distance from the nearer side of the page (judged by the box centre on
/// `from`), so a bottom-right stamp stays bottom-right on a bigger, smaller
/// or landscape page. The result is clamped to fit `to`.
pub fn rect_on_page(r: DisplayRect, from: &PageInfo, to: &PageInfo) -> DisplayRect {
    let (fw, fh) = from.display_size();
    let (tw, th) = to.display_size();
    let w = r.w.min(tw);
    let h = r.h.min(th);
    let x = if r.x + r.w / 2.0 > fw / 2.0 {
        tw - w - (fw - r.x - r.w)
    } else {
        r.x
    };
    let y = if r.y + r.h / 2.0 > fh / 2.0 {
        th - h - (fh - r.y - r.h)
    } else {
        r.y
    };
    DisplayRect {
        x: x.clamp(0.0, tw - w),
        y: y.clamp(0.0, th - h),
        w,
        h,
    }
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
    let mut targets = placement.pages.clone();
    if targets.is_empty() || placement.rect.is_none() {
        targets = vec![placement.page];
    }
    targets.sort_unstable();
    targets.dedup();
    if let Some(&p) = targets.iter().find(|&&p| p >= pages.len()) {
        return Err(PdfError::NoSuchPage(p + 1));
    }
    let single = targets.len() == 1;
    let (cat_id, cat_gen) = doc.catalog_ref()?;
    let mut catalog = doc.catalog()?;

    let mut next = doc.next_object_id();
    let mut alloc = || {
        let id = next;
        next += 1;
        id
    };
    let sig_id = alloc();
    let field_id = alloc();
    let field_ref = Obj::Ref(field_id, 0);

    // Objects to write: id -> (gn, object). BTreeMap keeps the output tidy.
    let mut objs: BTreeMap<u32, (u16, Obj)> = BTreeMap::new();

    // --- form field name -------------------------------------------------
    let (existing, _) = doc.form_fields()?;
    let field_name = (1..)
        .map(|n| format!("Signature{n}"))
        .find(|n| !existing.contains(n))
        .unwrap();

    // --- field + widgets ------------------------------------------------
    // One page: the field is its own widget. Several pages: one field with a
    // widget per page in /Kids, so viewers still show a single signature.
    let field = Dict::new()
        .with("FT", Obj::name("Sig"))
        .with("T", text_string(&field_name))
        .with("V", Obj::Ref(sig_id, 0));
    let mut widgets: Vec<(&PageInfo, u32, Dict)> = Vec::new();
    for &t in &targets {
        let target = &pages[t];
        let mut w = Dict::new()
            .with("Type", Obj::name("Annot"))
            .with("Subtype", Obj::name("Widget"));
        if single {
            w.0.extend(field.0.iter().cloned());
        } else {
            w.set("Parent", field_ref.clone());
        }
        w.set("F", Obj::int(132));
        w.set("P", Obj::Ref(target.id.0, target.id.1));
        let id = if single { field_id } else { alloc() };
        widgets.push((target, id, w));
    }
    match placement.rect {
        Some(r) => {
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
            let slot = fields.image.as_ref().map(|img| ImageSlot {
                aspect: img.aspect(),
                position: fields.image_position,
            });
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
            let mut resources = Dict::new().with(
                "Font",
                Obj::Dict(
                    Dict::new()
                        .with("F1", Obj::Ref(f1, 0))
                        .with("F2", Obj::Ref(f2, 0)),
                ),
            );
            // One image object, shared by the appearances on every page.
            if let Some(img) = &fields.image {
                let im = alloc();
                let smask = img.mask_obj().map(|m| {
                    let id = alloc();
                    objs.insert(id, (0, m));
                    Obj::Ref(id, 0)
                });
                objs.insert(im, (0, img.image_obj(smask)));
                resources.set(
                    "XObject",
                    Obj::Dict(Dict::new().with("Im1", Obj::Ref(im, 0))),
                );
            }
            // Each page gets its own appearance: the box may be clamped to a
            // smaller page, and the matrix follows the page's /Rotate.
            for (target, _, widget) in &mut widgets {
                let r = rect_on_page(r, page, target);
                let user = display_to_user(target, r);
                widget.set(
                    "Rect",
                    Obj::Array(user.iter().map(|v| Obj::real(*v)).collect()),
                );
                let ap_id = alloc();
                let content = appearance::content_stream_with_image(r.w, r.h, &lines, slot);
                let m = appearance::rotation_matrix(target.rotate, r.w, r.h);
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
                    .with("Resources", Obj::Dict(resources.clone()));
                objs.insert(ap_id, (0, Obj::Stream(ap, content)));
                widget.set("AP", Obj::Dict(Dict::new().with("N", Obj::Ref(ap_id, 0))));
            }
        }
        None => {
            for (_, _, widget) in &mut widgets {
                widget.set("Rect", Obj::Array(vec![Obj::int(0); 4]));
            }
        }
    }
    if !single {
        let kids = widgets.iter().map(|(_, id, _)| Obj::Ref(*id, 0)).collect();
        objs.insert(
            field_id,
            (0, Obj::Dict(field.with("Kids", Obj::Array(kids)))),
        );
    }
    for (_, id, widget) in &widgets {
        objs.insert(*id, (0, Obj::Dict(widget.clone())));
    }

    // --- page /Annots ---------------------------------------------------
    // An indirect /Annots array is updated in place and the page left alone.
    // Pages sharing one array get all their widgets added to it.
    let mut annot_arrays: BTreeMap<u32, (u16, Vec<Obj>)> = BTreeMap::new();
    for (target, id, _) in &widgets {
        let widget_ref = Obj::Ref(*id, 0);
        let mut page_dict = target.dict.clone();
        match page_dict.get("Annots").cloned() {
            Some(Obj::Ref(aid, agen)) => {
                if let Some((_, a)) = annot_arrays.get_mut(&aid) {
                    a.push(widget_ref);
                    continue;
                }
                match doc.get(aid)? {
                    Obj::Array(mut a) => {
                        a.push(widget_ref);
                        annot_arrays.insert(aid, (agen, a));
                        continue;
                    }
                    _ => page_dict.set("Annots", Obj::Array(vec![widget_ref])),
                }
            }
            Some(Obj::Array(mut a)) => {
                a.push(widget_ref);
                page_dict.set("Annots", Obj::Array(a));
            }
            _ => page_dict.set("Annots", Obj::Array(vec![widget_ref])),
        }
        objs.insert(target.id.0, (target.id.1, Obj::Dict(page_dict)));
    }
    for (aid, (agen, a)) in annot_arrays {
        objs.insert(aid, (agen, Obj::Array(a)));
    }

    // --- AcroForm -------------------------------------------------------
    let add_field = |af: &mut Dict, objs: &mut BTreeMap<u32, (u16, Obj)>| -> Result<()> {
        match af.get("Fields").cloned() {
            Some(Obj::Ref(fid, fgen)) => match doc.get(fid)? {
                Obj::Array(mut a) => {
                    a.push(field_ref.clone());
                    objs.insert(fid, (fgen, Obj::Array(a)));
                }
                _ => af.set("Fields", Obj::Array(vec![field_ref.clone()])),
            },
            Some(Obj::Array(mut a)) => {
                a.push(field_ref.clone());
                af.set("Fields", Obj::Array(a));
            }
            _ => af.set("Fields", Obj::Array(vec![field_ref.clone()])),
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

pub(super) fn write_xref_table(
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

pub(super) fn write_xref_stream(
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
    fn box_keeps_its_corner_on_other_pages() {
        let a4 = page(0);
        let mut big = page(90);
        big.crop_box = [0.0, 0.0, 1000.0, 1200.0];
        let mut tiny = page(0);
        tiny.crop_box = [0.0, 0.0, 120.0, 40.0];
        let bottom_right = DisplayRect {
            x: 400.0,
            y: 700.0,
            w: 170.0,
            h: 55.0,
        };
        assert_eq!(rect_on_page(bottom_right, &a4, &a4), bottom_right);
        // Displayed 1200 x 1000: same 30 pt / 45 pt margins from the corner.
        assert_eq!(
            rect_on_page(bottom_right, &a4, &big),
            DisplayRect {
                x: 1000.0,
                y: 900.0,
                w: 170.0,
                h: 55.0
            }
        );
        let top_left = DisplayRect {
            x: 20.0,
            y: 30.0,
            ..bottom_right
        };
        assert_eq!(rect_on_page(top_left, &a4, &big), top_left);
        // Shrunk and clamped onto a page smaller than the box.
        assert_eq!(
            rect_on_page(bottom_right, &a4, &tiny),
            DisplayRect {
                x: 0.0,
                y: 0.0,
                w: 120.0,
                h: 40.0
            }
        );
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
