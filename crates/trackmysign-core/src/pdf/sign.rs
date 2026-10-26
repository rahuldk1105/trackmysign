//! Appends a signature to a PDF as an incremental update.
//!
//! The original bytes are never modified: new and changed objects, a new
//! cross-reference section and trailer are written after the existing
//! `%%EOF`. That keeps earlier signatures valid.

use std::collections::BTreeMap;

use chrono::{DateTime, FixedOffset};

use super::appearance::{self, ImageKind, ImageSlot, Images};
use super::docmdp::DocMdp;
use super::object::{Dict, Obj, write_obj};
use super::reader::{Document, PageInfo, PdfError, Result, XrefEntry};
use crate::ctc::Ctc;
use crate::image::{ImagePosition, StampImage};
use crate::stamp::{StampLine, StampStyle, StampValues, stamp_lines};

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
    /// The certificate's O=, for a style that shows the organisation.
    pub organisation: Option<String>,
    pub reason: Option<String>,
    pub location: Option<String>,
    pub time: DateTime<FixedOffset>,
    pub image: Option<StampImage>,
    pub image_position: ImagePosition,
    /// Company seal or logo, placed as `style.seal` says (right of the text
    /// when it does not say).
    pub seal: Option<StampImage>,
    pub style: StampStyle,
    /// A timestamp will be added (some fields require one).
    pub timestamp: bool,
    /// Make this the certification signature, allowing only these changes.
    pub certify: Option<DocMdp>,
    /// "Certified true copy" stamps, as more widgets of the signature field.
    pub ctc: Option<Ctc>,
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
    /// Sign into this existing empty signature field (fully qualified name)
    /// instead of adding one; `page`, `rect` and `pages` are then unused.
    pub field: Option<String>,
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

pub(super) type Objects = BTreeMap<u32, (u16, Obj)>;

pub(super) fn take(next: &mut u32) -> u32 {
    let id = *next;
    *next += 1;
    id
}

/// What every appearance of one signature shares: the style, the text,
/// the image slots and resources (fonts and images written once to `objs`).
struct Stamp {
    style: StampStyle,
    lines: Vec<StampLine>,
    images: Images,
    resources: Dict,
}

fn stamp(fields: &SignatureFields, objs: &mut Objects, next: &mut u32) -> Stamp {
    stamp_with(
        fields,
        &fields.style,
        [fields.image.as_ref(), fields.seal.as_ref()],
        objs,
        next,
    )
}

/// The box `style` draws for `fields`, with the signature image and seal
/// given in `pictures` (either may be left out).
fn stamp_with(
    fields: &SignatureFields,
    style: &StampStyle,
    pictures: [Option<&StampImage>; 2],
    objs: &mut Objects,
    next: &mut u32,
) -> Stamp {
    let f1 = take(next);
    let f2 = take(next);
    // English whatever the app's language: the standard fonts (WinAnsi)
    // have no Devanagari or Tamil glyphs, so such text is transliterated.
    let lines = stamp_lines(
        style,
        &StampValues {
            name: fields.signer_name.clone(),
            organisation: fields.organisation.clone(),
            reason: fields.reason.clone(),
            location: fields.location.clone(),
            time: fields.time,
        },
    );
    let [image, seal] = pictures;
    let images = Images {
        signature: image.map(|img| ImageSlot {
            aspect: img.aspect(),
            position: fields.image_position,
        }),
        seal: seal.map(|img| (img.aspect(), style.seal.unwrap_or_default())),
    };
    // Which images the style shows does not depend on the size of the box.
    let probe = appearance::draw(style, &lines, images, 170.0, 55.0);
    let font = |base: &str| {
        Obj::Dict(
            Dict::new()
                .with("Type", Obj::name("Font"))
                .with("Subtype", Obj::name("Type1"))
                .with("BaseFont", Obj::name(base))
                .with("Encoding", Obj::name("WinAnsiEncoding")),
        )
    };
    let [regular, bold] = appearance::base_fonts(style.font);
    objs.insert(f1, (0, font(regular)));
    objs.insert(f2, (0, font(bold)));
    let mut resources = Dict::new().with(
        "Font",
        Obj::Dict(
            Dict::new()
                .with("F1", Obj::Ref(f1, 0))
                .with("F2", Obj::Ref(f2, 0)),
        ),
    );
    // One object per image, shared by the appearances on every page.
    let mut xobjects = Dict::new();
    for (name, kind, img) in [
        ("Im1", ImageKind::Signature, image),
        ("Im2", ImageKind::Seal, seal),
    ] {
        let Some(img) = img.filter(|_| probe.uses(kind)) else {
            continue;
        };
        let im = take(next);
        let smask = img.mask_obj().map(|m| {
            let id = take(next);
            objs.insert(id, (0, m));
            Obj::Ref(id, 0)
        });
        objs.insert(im, (0, img.image_obj(smask)));
        xobjects.set(name, Obj::Ref(im, 0));
    }
    if !xobjects.0.is_empty() {
        resources.set("XObject", Obj::Dict(xobjects));
    }
    if let Some(alpha) = probe.opacity() {
        let gs = Dict::new()
            .with("Type", Obj::name("ExtGState"))
            .with("ca", Obj::real(alpha))
            .with("CA", Obj::real(alpha));
        resources.set(
            "ExtGState",
            Obj::Dict(Dict::new().with("GS1", Obj::Dict(gs))),
        );
    }
    Stamp {
        style: style.clone(),
        lines,
        images,
        resources,
    }
}

/// Appearance stream for a `w`×`h` box (upright as the reader sees it),
/// turned `rotate` degrees counterclockwise onto the page.
fn appearance_obj(stamp: &Stamp, w: f64, h: f64, rotate: i32) -> Obj {
    let content = appearance::draw(&stamp.style, &stamp.lines, stamp.images, w, h).content_stream();
    let m = appearance::rotation_matrix(rotate, w, h);
    let ap = Dict::new()
        .with("Type", Obj::name("XObject"))
        .with("Subtype", Obj::name("Form"))
        .with(
            "BBox",
            Obj::Array(vec![Obj::int(0), Obj::int(0), Obj::real(w), Obj::real(h)]),
        )
        .with(
            "Matrix",
            Obj::Array(m.iter().map(|v| Obj::real(*v)).collect()),
        )
        .with("Resources", Obj::Dict(stamp.resources.clone()));
    Obj::Stream(ap, content)
}

/// Lists each widget in its page's `/Annots`. An indirect `/Annots` array
/// is updated in place and the page left alone; pages sharing one array get
/// all their widgets added to it, as does a page with several widgets.
pub(super) fn add_to_annots(
    doc: &Document,
    widgets: &[(&PageInfo, u32, u16)],
    objs: &mut Objects,
) -> Result<()> {
    let mut annot_arrays: BTreeMap<u32, (u16, Vec<Obj>)> = BTreeMap::new();
    for (target, id, gn) in widgets {
        let widget_ref = Obj::Ref(*id, *gn);
        // Several widgets on one page: build on the page as already updated.
        let mut page_dict = match objs.get(&target.id.0) {
            Some((_, Obj::Dict(d))) => d.clone(),
            _ => target.dict.clone(),
        };
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
    Ok(())
}

pub fn prepare(
    input: &[u8],
    placement: &Placement,
    fields: &SignatureFields,
    reserved: usize,
) -> Result<Prepared> {
    prepare_with_password(input, None, placement, fields, reserved)
}

/// [`prepare`] for a password-protected PDF. The update is encrypted with
/// the document's key, except the signature's `/Contents`, which the
/// standard keeps in the clear.
pub fn prepare_with_password(
    input: &[u8],
    password: Option<&str>,
    placement: &Placement,
    fields: &SignatureFields,
    reserved: usize,
) -> Result<Prepared> {
    let doc = Document::open(input, password)?;
    if doc.crypt.as_ref().is_some_and(|c| !c.may_sign()) {
        return Err(PdfError::SigningNotAllowed);
    }
    let pages = doc.pages()?;
    if let Some(name) = &placement.field {
        if fields.ctc.is_some() {
            return Err(PdfError::Field(
                "Certified true copy stamps cannot be added when signing into an existing \
                 signature field. Place a signature box instead."
                    .into(),
            ));
        }
        return prepare_field(&doc, &pages, name, fields, reserved);
    }
    let page = pages
        .get(placement.page)
        .ok_or(PdfError::NoSuchPage(placement.page + 1))?;
    let mut targets = placement.pages.clone();
    if targets.is_empty() || placement.rect.is_none() {
        targets = vec![placement.page];
    }
    // An invisible signature with stamps shows only the stamps.
    if placement.rect.is_none() && fields.ctc.is_some() {
        targets.clear();
    }
    targets.sort_unstable();
    targets.dedup();
    if let Some(&p) = targets.iter().find(|&&p| p >= pages.len()) {
        return Err(PdfError::NoSuchPage(p + 1));
    }
    let mut stamped = match &fields.ctc {
        Some(c) if c.pages.is_empty() => (0..pages.len()).collect(),
        Some(c) => c.pages.clone(),
        None => Vec::new(),
    };
    stamped.sort_unstable();
    stamped.dedup();
    if let Some(&p) = stamped.iter().find(|&&p| p >= pages.len()) {
        return Err(PdfError::NoSuchPage(p + 1));
    }
    let single = targets.len() == 1 && fields.ctc.is_none();
    let (cat_id, cat_gen) = doc.catalog_ref()?;
    let mut catalog = doc.catalog()?;

    let mut next = doc.next_object_id();
    let sig_id = take(&mut next);
    let field_id = take(&mut next);
    let field_ref = Obj::Ref(field_id, 0);

    // Objects to write: id -> (gn, object). BTreeMap keeps the output tidy.
    let mut objs: Objects = BTreeMap::new();

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
        let id = if single { field_id } else { take(&mut next) };
        widgets.push((target, id, w));
    }
    match placement.rect {
        Some(r) => {
            let stamp = stamp(fields, &mut objs, &mut next);
            // Each page gets its own appearance: the box may be clamped to a
            // smaller page, and the matrix follows the page's /Rotate.
            for (target, _, widget) in &mut widgets {
                let r = rect_on_page(r, page, target);
                let user = display_to_user(target, r);
                widget.set(
                    "Rect",
                    Obj::Array(user.iter().map(|v| Obj::real(*v)).collect()),
                );
                let ap_id = take(&mut next);
                let ap = appearance_obj(&stamp, r.w, r.h, target.rotate);
                objs.insert(ap_id, (0, ap));
                widget.set("AP", Obj::Dict(Dict::new().with("N", Obj::Ref(ap_id, 0))));
            }
        }
        None => {
            for (_, _, widget) in &mut widgets {
                widget.set("Rect", Obj::Array(vec![Obj::int(0); 4]));
            }
        }
    }
    // --- certified true copy stamps -------------------------------------
    if let Some(ctc) = &fields.ctc {
        let seal = ctc.seal.as_ref();
        let stamp = stamp_with(fields, &ctc.style.style, [None, seal], &mut objs, &mut next);
        for &p in &stamped {
            let target = &pages[p];
            let (w, h) = target.display_size();
            let r = ctc.style.rect_on(w, h);
            let user = display_to_user(target, r);
            let ap_id = take(&mut next);
            objs.insert(ap_id, (0, appearance_obj(&stamp, r.w, r.h, target.rotate)));
            // Print, ReadOnly, Locked: printed, and not to be moved or edited.
            let widget = Dict::new()
                .with("Type", Obj::name("Annot"))
                .with("Subtype", Obj::name("Widget"))
                .with("Parent", field_ref.clone())
                .with("F", Obj::int(196))
                .with("P", Obj::Ref(target.id.0, target.id.1))
                .with(
                    "Rect",
                    Obj::Array(user.iter().map(|v| Obj::real(*v)).collect()),
                )
                .with("AP", Obj::Dict(Dict::new().with("N", Obj::Ref(ap_id, 0))))
                .with("Contents", text_string("Certified true copy"));
            widgets.push((target, take(&mut next), widget));
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
    let listed: Vec<(&PageInfo, u32, u16)> =
        widgets.iter().map(|(p, id, _)| (*p, *id, 0)).collect();
    add_to_annots(&doc, &listed, &mut objs)?;

    // --- AcroForm -------------------------------------------------------
    let add_field = |af: &mut Dict, objs: &mut Objects| -> Result<()> {
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
    // The catalog itself changes only for an inline /AcroForm, a new one,
    // or a certification.
    let mut catalog_changed = false;
    match catalog.get("AcroForm").cloned() {
        Some(Obj::Ref(afid, afgen)) if doc.get(afid)?.as_dict().is_some() => {
            let mut af = doc.get(afid)?.as_dict().cloned().unwrap();
            add_field(&mut af, &mut objs)?;
            objs.insert(afid, (afgen, Obj::Dict(af)));
        }
        Some(Obj::Dict(mut af)) => {
            add_field(&mut af, &mut objs)?;
            catalog.set("AcroForm", Obj::Dict(af));
            catalog_changed = true;
        }
        _ => {
            let afid = take(&mut next);
            let mut af = Dict::new();
            add_field(&mut af, &mut objs)?;
            objs.insert(afid, (0, Obj::Dict(af)));
            catalog.set("AcroForm", Obj::Ref(afid, 0));
            catalog_changed = true;
        }
    }
    // --- certification ----------------------------------------------------
    if fields.certify.is_some() {
        certify_catalog(&doc, &mut catalog, sig_id)?;
        catalog_changed = true;
    }
    if catalog_changed {
        objs.insert(cat_id, (cat_gen, Obj::Dict(catalog)));
    }

    let sig = sig_dict(fields, "adbe.pkcs7.detached", None);
    write_update(&doc, sig_id, sig, objs, next, reserved)
}

/// Signs into the existing empty signature field `name`: the field gets
/// `/V`, each visible widget an appearance sized to its `/Rect`; nothing
/// else about the field changes. A `/Lock` is carried into the signature as
/// a FieldMDP reference, and required `/SV` seed values are honoured.
fn prepare_field(
    doc: &Document,
    pages: &[PageInfo],
    name: &str,
    fields: &SignatureFields,
    reserved: usize,
) -> Result<Prepared> {
    let all = super::fields::signature_fields(doc, pages)?;
    let Some(field) = all.iter().find(|f| f.name == name) else {
        let empty: Vec<&str> = all
            .iter()
            .filter(|f| !f.signed)
            .map(|f| f.name.as_str())
            .collect();
        return Err(PdfError::Field(if empty.is_empty() {
            format!("There is no signature field \"{name}\"; this PDF has no empty ones.")
        } else {
            format!(
                "There is no signature field \"{name}\". Empty signature fields: {}.",
                empty.join(", ")
            )
        }));
    };
    if field.signed {
        return Err(PdfError::Field(format!(
            "The signature field \"{name}\" is already signed."
        )));
    }
    let format =
        super::fields::check_seed_values(doc, field, fields.reason.as_deref(), fields.timestamp)?;
    let (cat_id, cat_gen) = doc.catalog_ref()?;
    let reference = super::fields::field_mdp_reference(doc, field, (cat_id, cat_gen))?;

    let mut next = doc.next_object_id();
    let sig_id = take(&mut next);
    let mut objs: Objects = BTreeMap::new();

    let stamp = field
        .widgets
        .iter()
        .any(|w| w.visible())
        .then(|| stamp(fields, &mut objs, &mut next));
    let mut unlisted = Vec::new();
    for w in &field.widgets {
        let mut wd = w.dict.clone();
        let page = w.page.map(|p| &pages[p]);
        if let Some(stamp) = &stamp
            && w.visible()
        {
            let [x0, y0, x1, y1] = w.rect;
            let rotate = w.rotation(doc, page);
            // The box as the reader sees it: turned a quarter, it swaps sides.
            let (w, h) = if rotate % 180 == 0 {
                (x1 - x0, y1 - y0)
            } else {
                (y1 - y0, x1 - x0)
            };
            let ap_id = take(&mut next);
            objs.insert(ap_id, (0, appearance_obj(stamp, w, h, rotate)));
            wd.set("AP", Obj::Dict(Dict::new().with("N", Obj::Ref(ap_id, 0))));
        }
        if w.id == field.id {
            wd.set("V", Obj::Ref(sig_id, 0));
        }
        objs.insert(w.id.0, (w.id.1, Obj::Dict(wd)));
        if let Some(p) = page {
            let listed = match p.dict.get("Annots").map(|a| doc.resolve(a)) {
                Some(Ok(Obj::Array(a))) => a
                    .iter()
                    .any(|r| matches!(r, Obj::Ref(id, _) if *id == w.id.0)),
                _ => false,
            };
            if !listed {
                unlisted.push((p, w.id.0, w.id.1));
            }
        }
    }
    if !field.widgets.iter().any(|w| w.id == field.id) {
        let fd = field.dict.clone().with("V", Obj::Ref(sig_id, 0));
        objs.insert(field.id.0, (field.id.1, Obj::Dict(fd)));
    }
    // A widget found only through its /P is added to that page.
    add_to_annots(doc, &unlisted, &mut objs)?;

    // --- AcroForm /SigFlags ----------------------------------------------
    let mut catalog = doc.catalog()?;
    let mut catalog_changed = false;
    let with_flags = |mut af: Dict| {
        let flags = af.get("SigFlags").and_then(Obj::as_i64).unwrap_or(0);
        (flags & 3 != 3).then(|| {
            af.set("SigFlags", Obj::int(flags | 3));
            af
        })
    };
    match catalog.get("AcroForm").cloned() {
        Some(Obj::Ref(afid, afgen)) => {
            if let Some(af) = doc.get(afid)?.as_dict().cloned().and_then(with_flags) {
                objs.insert(afid, (afgen, Obj::Dict(af)));
            }
        }
        Some(Obj::Dict(af)) => {
            if let Some(af) = with_flags(af) {
                catalog.set("AcroForm", Obj::Dict(af));
                catalog_changed = true;
            }
        }
        _ => {}
    }
    if fields.certify.is_some() {
        certify_catalog(doc, &mut catalog, sig_id)?;
        catalog_changed = true;
    }
    if catalog_changed {
        objs.insert(cat_id, (cat_gen, Obj::Dict(catalog)));
    }

    let sig = sig_dict(fields, format.sub_filter, reference);
    write_update(doc, sig_id, sig, objs, next, reserved)
}

/// Points the catalog's `/Perms /DocMDP` at the signature. `/Perms` keeps
/// any other entries (such as usage rights) and gets an inline copy if it
/// was indirect.
fn certify_catalog(doc: &Document, catalog: &mut Dict, sig_id: u32) -> Result<()> {
    let mut perms = match catalog.get("Perms") {
        Some(p) => doc.resolve(p)?.as_dict().cloned().unwrap_or_default(),
        None => Dict::new(),
    };
    perms.set("DocMDP", Obj::Ref(sig_id, 0));
    catalog.set("Perms", Obj::Dict(perms));
    Ok(())
}

/// The signature dictionary, without `/ByteRange` and `/Contents`.
fn sig_dict(fields: &SignatureFields, sub_filter: &str, field_lock: Option<Obj>) -> Dict {
    let mut sig = Dict::new()
        .with("Type", Obj::name("Sig"))
        .with("Filter", Obj::name("Adobe.PPKLite"))
        .with("SubFilter", Obj::name(sub_filter))
        .with("Name", text_string(&fields.signer_name))
        .with("M", Obj::Str(pdf_date(&fields.time).into_bytes()));
    if let Some(r) = fields.reason.as_ref().filter(|s| !s.is_empty()) {
        sig.set("Reason", text_string(r));
    }
    if let Some(l) = fields.location.as_ref().filter(|s| !s.is_empty()) {
        sig.set("Location", text_string(l));
    }
    // DocMDP for a certification, FieldMDP for a field's lock; both may apply.
    let mut refs = Vec::new();
    for r in fields
        .certify
        .map(DocMdp::reference)
        .into_iter()
        .chain(field_lock)
    {
        if let Obj::Array(a) = r {
            refs.extend(a);
        }
    }
    if !refs.is_empty() {
        sig.set("Reference", Obj::Array(refs));
    }
    sig.set(
        "Prop_Build",
        Obj::Dict(Dict::new().with(
            "App",
            Obj::Dict(Dict::new().with("Name", Obj::name("TrackMy Sign"))),
        )),
    );
    sig
}

/// Appends the signature dictionary (with placeholders), `objs` and a new
/// cross-reference section to the original bytes.
fn write_update(
    doc: &Document,
    sig_id: u32,
    mut sig: Dict,
    objs: Objects,
    next: u32,
    reserved: usize,
) -> Result<Prepared> {
    let (cat_id, cat_gen) = doc.catalog_ref()?;
    let mut out = doc.data.to_vec();
    if !matches!(out.last(), Some(b'\n') | Some(b'\r')) {
        out.push(b'\n');
    }
    let mut offsets: BTreeMap<u32, (usize, u16)> = BTreeMap::new();

    // Signature dictionary first, with fixed-width placeholders.
    offsets.insert(sig_id, (out.len(), 0));
    out.extend_from_slice(format!("{sig_id} 0 obj\n<<").as_bytes());
    if let Some(c) = &doc.crypt
        && let Obj::Dict(d) = c.encrypt(sig_id, 0, &Obj::Dict(sig.clone()))
    {
        sig = d;
    }
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

    write_objects(&mut out, doc, &objs, &mut offsets);

    let mut trailer = Dict::new();
    trailer.set("Root", Obj::Ref(cat_id, cat_gen));
    for key in ["Info", "ID", "Encrypt"] {
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

/// Writes `objs` (encrypted when the document is) and records their offsets.
pub(super) fn write_objects(
    out: &mut Vec<u8>,
    doc: &Document,
    objs: &BTreeMap<u32, (u16, Obj)>,
    offsets: &mut BTreeMap<u32, (usize, u16)>,
) {
    for (id, (gn, obj)) in objs {
        offsets.insert(*id, (out.len(), *gn));
        out.extend_from_slice(format!("{id} {gn} obj\n").as_bytes());
        match &doc.crypt {
            Some(c) => write_obj(out, &c.encrypt(*id, *gn, obj)),
            None => write_obj(out, obj),
        }
        out.extend_from_slice(b"\nendobj\n");
    }
}

/// Appends `objs` to the document as an incremental update without a
/// signature (validation data, new fields); `next` is the first unused id.
pub(super) fn append_update(doc: &Document, objs: &Objects, next: u32) -> Result<Vec<u8>> {
    let (cat_id, cat_gen) = doc.catalog_ref()?;
    let mut out = doc.data.to_vec();
    if !matches!(out.last(), Some(b'\n') | Some(b'\r')) {
        out.push(b'\n');
    }
    let mut offsets: BTreeMap<u32, (usize, u16)> = BTreeMap::new();
    write_objects(&mut out, doc, objs, &mut offsets);

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

    /// Two pages, the second turned a quarter.
    fn two_page_pdf() -> Vec<u8> {
        let objs: [&[u8]; 5] = [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 5 0 R >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Rotate 90 /Contents 5 0 R >>",
            b"<< /Length 23 >>\nstream\nBT 72 760 Td (Hi) Tj ET\nendstream",
        ];
        let mut out = b"%PDF-1.4\n".to_vec();
        let mut offsets = Vec::new();
        for (i, o) in objs.iter().enumerate() {
            offsets.push(out.len());
            out.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
            out.extend_from_slice(o);
            out.extend_from_slice(b"\nendobj\n");
        }
        let xref = out.len();
        out.extend_from_slice(b"xref\n0 6\n0000000000 65535 f\r\n");
        for o in offsets {
            out.extend_from_slice(format!("{o:010} 00000 n\r\n").as_bytes());
        }
        out.extend_from_slice(
            format!("trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n").as_bytes(),
        );
        out
    }

    fn png(w: u32, h: u32) -> StampImage {
        let mut out = Vec::new();
        let mut e = png::Encoder::new(&mut out, w, h);
        e.set_color(png::ColorType::Rgba);
        e.set_depth(png::BitDepth::Eight);
        let data: Vec<u8> = (0..w * h * 4).map(|i| (i * 7 % 256) as u8).collect();
        e.write_header().unwrap().write_image_data(&data).unwrap();
        StampImage::from_bytes(&out).unwrap()
    }

    /// The stamp without a style is the one every earlier version drew, to
    /// the byte (hashes taken before styles existed; renewed only when the
    /// application name in Prop_Build became "TrackMy Sign").
    #[test]
    fn default_stamp_unchanged() {
        use sha2::{Digest, Sha256};
        let pdf = two_page_pdf();
        let base = SignatureFields {
            signer_name: "RAMESH KUMAR".into(),
            organisation: Some("ACME LTD".into()),
            reason: Some("Approved".into()),
            location: Some("Chennai".into()),
            time: DateTime::parse_from_rfc3339("2026-10-20T14:32:10+05:30").unwrap(),
            image: None,
            image_position: ImagePosition::Left,
            seal: None,
            style: StampStyle::default(),
            timestamp: false,
            certify: None,
            ctc: None,
        };
        let rect = DisplayRect {
            x: 380.0,
            y: 740.0,
            w: 170.0,
            h: 55.0,
        };
        let cases = [
            (base.clone(), vec![]),
            (
                SignatureFields {
                    image: Some(png(60, 20)),
                    reason: None,
                    ..base.clone()
                },
                vec![0, 1],
            ),
            (
                SignatureFields {
                    image: Some(png(30, 40)),
                    image_position: ImagePosition::Above,
                    signer_name: "A VERY LONG DIRECTOR NAME INDEED (HR)".into(),
                    ..base.clone()
                },
                vec![1],
            ),
        ];
        let hashes: Vec<String> = cases
            .into_iter()
            .map(|(fields, pages)| {
                let placement = Placement {
                    page: 0,
                    rect: Some(rect),
                    pages,
                    field: None,
                };
                let p = prepare(&pdf, &placement, &fields, 4000).unwrap();
                Sha256::digest(&p.data)
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect()
            })
            .collect();
        assert_eq!(
            hashes,
            [
                "8bd08eec05bf8936a06556a7f2e908ded087959de07ffb58dcd2f282c6bc5ac7",
                "463e415665b782521b8e9c0afa03f7ae98887325453f8f4d8ae0a58bc721ced5",
                "f7c6af19bd8ea6e5ec2d4ea42f33454c85f4449e90e21557a83e42e1af0af93d",
            ]
        );
    }

    #[test]
    fn styled_stamp_resources() {
        use crate::stamp::{FontFamily, Layout, SealPosition, SealStyle};
        let style = StampStyle {
            font: FontFamily::Times,
            layout: Layout::TextOnly,
            seal: Some(SealStyle {
                position: SealPosition::Behind,
                opacity: 0.3,
            }),
            ..Default::default()
        };
        let fields = SignatureFields {
            signer_name: "RAMESH KUMAR".into(),
            organisation: None,
            reason: None,
            location: None,
            time: DateTime::parse_from_rfc3339("2026-10-20T14:32:10+05:30").unwrap(),
            // Not shown: the layout is text only.
            image: Some(png(60, 20)),
            image_position: ImagePosition::Left,
            seal: Some(png(40, 40)),
            style,
            timestamp: false,
            certify: None,
            ctc: None,
        };
        let placement = Placement {
            page: 1,
            rect: Some(DisplayRect {
                x: 20.0,
                y: 20.0,
                w: 170.0,
                h: 55.0,
            }),
            pages: vec![],
            field: None,
        };
        let p = prepare(&two_page_pdf(), &placement, &fields, 4000).unwrap();
        let doc = Document::parse(&p.data).unwrap();
        for (id, font) in [(8, "Times-Roman"), (9, "Times-Bold")] {
            let Obj::Dict(d) = doc.get(id).unwrap() else {
                panic!()
            };
            assert!(d.get("BaseFont").unwrap().is_name(font));
        }
        let text = String::from_utf8_lossy(&p.data);
        assert!(text.contains("/Im2") && !text.contains("/Im1"));
        assert!(text.contains("/ExtGState") && text.contains("/ca 0.3"));
    }
}
