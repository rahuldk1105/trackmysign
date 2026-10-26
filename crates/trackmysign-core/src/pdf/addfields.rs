//! Empty signature fields for others to sign later (co-directors, the
//! auditor, the company secretary), added as an incremental update.
//!
//! Each field is a top-level `/FT /Sig` field merged with its widget, shown
//! as a light dashed box with its name, so it also prints. Only new fields,
//! their pages' `/Annots` and the AcroForm change: validators count that as
//! an allowed change after the signatures already in the document.

use super::appearance::{Face, escape, rotation_matrix};
use super::object::{Dict, Obj, fmt_real};
use super::reader::{Document, PdfError, Result};
use super::sign::{
    DisplayRect, Objects, add_to_annots, append_update, display_to_user, take, text_string,
};
use super::textdoc::{encode, text_width};

/// Custom field key holding the place in the intended signing order (from
/// 1), so TrackMy Sign can say whose signature it is waiting for. Other
/// readers ignore it.
pub const ORDER_KEY: &str = "TrackMySignOrder";

/// What signing a field locks (its FieldMDP `/Lock`).
#[derive(Debug, Clone, PartialEq)]
pub enum FieldLock {
    /// Every field of the form.
    All,
    /// These fields, by full name.
    Fields(Vec<String>),
    /// Every field but these.
    AllExcept(Vec<String>),
}

impl FieldLock {
    /// The `/Lock` dictionary of a field, if it has a readable one.
    pub fn of_field(doc: &Document, dict: &Dict) -> Option<FieldLock> {
        let lock = doc.resolve(dict.get("Lock")?).ok()?;
        let lock = lock.as_dict()?;
        let names = || -> Vec<String> {
            lock.get("Fields")
                .and_then(|f| doc.resolve(f).ok())
                .and_then(|f| f.as_array().cloned())
                .unwrap_or_default()
                .iter()
                .filter_map(|o| match o {
                    Obj::Str(s) => Some(super::fields::text(s)),
                    _ => None,
                })
                .collect()
        };
        match lock.get("Action")? {
            a if a.is_name("All") => Some(FieldLock::All),
            a if a.is_name("Include") => Some(FieldLock::Fields(names())),
            a if a.is_name("Exclude") => Some(FieldLock::AllExcept(names())),
            _ => None,
        }
    }
}

/// An empty signature field to add.
#[derive(Debug, Clone)]
pub struct NewField {
    /// Field name; unique, no `.` (no nested fields).
    pub name: String,
    /// Zero-based page.
    pub page: usize,
    /// As displayed on `page`.
    pub rect: DisplayRect,
    /// Tooltip (`/TU`), e.g. "Director — Rahul Dhileep Kumar"; also shown in
    /// the box.
    pub tooltip: Option<String>,
    /// Place in the signing order, from 1.
    pub order: Option<u32>,
    pub lock: Option<FieldLock>,
    /// Seed values asking for adbe.pkcs7.detached with SHA-256.
    pub seed: bool,
}

/// Checks a field name: something, without `.`, no longer than readers show.
pub fn check_name(name: &str) -> std::result::Result<(), String> {
    if name.trim().is_empty() {
        return Err("A signature field needs a name.".into());
    }
    if name.trim() != name {
        return Err(format!(
            "The field name \"{name}\" starts or ends with a space."
        ));
    }
    if name.contains('.') {
        return Err(format!(
            "The field name \"{name}\" contains a dot, which PDF uses between the parts of nested names."
        ));
    }
    if name.chars().count() > 100 {
        return Err(format!("The field name \"{name}\" is too long."));
    }
    Ok(())
}

/// Adds `fields` to the document. Refuses names already in its form (or
/// given twice), boxes outside their page and locks naming no field.
pub fn add(input: &[u8], password: Option<&str>, fields: &[NewField]) -> Result<Vec<u8>> {
    let doc = Document::open(input, password)?;
    if doc.crypt.as_ref().is_some_and(|c| !c.may_sign()) {
        return Err(PdfError::SigningNotAllowed);
    }
    if fields.is_empty() {
        return Err(PdfError::Field("No signature fields to add.".into()));
    }
    let pages = doc.pages()?;
    let (mut taken, _) = doc.form_fields()?;
    taken.extend(
        super::fields::signature_fields(&doc, &pages)?
            .into_iter()
            .map(|f| f.name),
    );
    for f in fields {
        check_name(&f.name).map_err(PdfError::Field)?;
        if taken.contains(&f.name) {
            return Err(PdfError::Field(format!(
                "There is already a field named \"{}\" in this PDF; choose another name.",
                f.name
            )));
        }
        taken.push(f.name.clone());
        let page = pages.get(f.page).ok_or(PdfError::NoSuchPage(f.page + 1))?;
        let (w, h) = page.display_size();
        let r = f.rect;
        if !(r.w >= 1.0 && r.h >= 1.0 && r.x >= -0.5 && r.y >= -0.5)
            || r.x + r.w > w + 0.5
            || r.y + r.h > h + 0.5
        {
            return Err(PdfError::Field(format!(
                "The box of the field \"{}\" does not fit on page {}.",
                f.name,
                f.page + 1
            )));
        }
        if matches!(&f.lock, Some(FieldLock::Fields(l)) if l.is_empty()) {
            return Err(PdfError::Field(format!(
                "The field \"{}\" locks fields but names none.",
                f.name
            )));
        }
    }

    let mut next = doc.next_object_id();
    let mut objs: Objects = Objects::new();
    let mut refs = Vec::new();
    let mut listed = Vec::new();
    for f in fields {
        let page = &pages[f.page];
        let id = take(&mut next);
        let ap_id = take(&mut next);
        let user = display_to_user(page, f.rect);
        let mut w = Dict::new()
            .with("Type", Obj::name("Annot"))
            .with("Subtype", Obj::name("Widget"))
            .with("FT", Obj::name("Sig"))
            .with("T", text_string(&f.name));
        if let Some(tu) = f
            .tooltip
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            w.set("TU", text_string(tu));
        }
        w.set("F", Obj::int(4));
        w.set("P", Obj::Ref(page.id.0, page.id.1));
        w.set(
            "Rect",
            Obj::Array(user.iter().map(|v| Obj::real(*v)).collect()),
        );
        w.set("AP", Obj::Dict(Dict::new().with("N", Obj::Ref(ap_id, 0))));
        if let Some(lock) = &f.lock {
            w.set("Lock", lock_dict(lock));
        }
        if f.seed {
            w.set("SV", seed_values());
        }
        if let Some(n) = f.order {
            w.set(ORDER_KEY, Obj::int(n as i64));
        }
        objs.insert(id, (0, Obj::Dict(w)));
        objs.insert(
            ap_id,
            (
                0,
                appearance(&f.name, f.tooltip.as_deref(), f.rect, page.rotate),
            ),
        );
        refs.push(Obj::Ref(id, 0));
        listed.push((page, id, 0));
    }
    add_to_annots(&doc, &listed, &mut objs)?;

    // --- AcroForm -------------------------------------------------------
    let (cat_id, cat_gen) = doc.catalog_ref()?;
    let mut catalog = doc.catalog()?;
    let add_fields = |af: &mut Dict, objs: &mut Objects| -> Result<()> {
        match af.get("Fields").cloned() {
            Some(Obj::Ref(fid, fgen)) => match doc.get(fid)? {
                Obj::Array(mut a) => {
                    a.extend(refs.iter().cloned());
                    objs.insert(fid, (fgen, Obj::Array(a)));
                }
                _ => af.set("Fields", Obj::Array(refs.clone())),
            },
            Some(Obj::Array(mut a)) => {
                a.extend(refs.iter().cloned());
                af.set("Fields", Obj::Array(a));
            }
            _ => af.set("Fields", Obj::Array(refs.clone())),
        }
        // SignaturesExist: the form has signature fields.
        let flags = af.get("SigFlags").and_then(Obj::as_i64).unwrap_or(0);
        if flags & 1 == 0 {
            af.set("SigFlags", Obj::int(flags | 1));
        }
        Ok(())
    };
    match catalog.get("AcroForm").cloned() {
        Some(Obj::Ref(afid, afgen)) if doc.get(afid)?.as_dict().is_some() => {
            let mut af = doc.get(afid)?.as_dict().cloned().unwrap();
            add_fields(&mut af, &mut objs)?;
            objs.insert(afid, (afgen, Obj::Dict(af)));
        }
        Some(Obj::Dict(mut af)) => {
            add_fields(&mut af, &mut objs)?;
            catalog.set("AcroForm", Obj::Dict(af));
            objs.insert(cat_id, (cat_gen, Obj::Dict(catalog)));
        }
        _ => {
            let afid = take(&mut next);
            let mut af = Dict::new();
            add_fields(&mut af, &mut objs)?;
            objs.insert(afid, (0, Obj::Dict(af)));
            catalog.set("AcroForm", Obj::Ref(afid, 0));
            objs.insert(cat_id, (cat_gen, Obj::Dict(catalog)));
        }
    }
    append_update(&doc, &objs, next)
}

fn lock_dict(lock: &FieldLock) -> Obj {
    let d = Dict::new().with("Type", Obj::name("SigFieldLock"));
    Obj::Dict(match lock {
        FieldLock::All => d.with("Action", Obj::name("All")),
        FieldLock::Fields(names) => d
            .with("Action", Obj::name("Include"))
            .with("Fields", names_array(names)),
        FieldLock::AllExcept(names) => d
            .with("Action", Obj::name("Exclude"))
            .with("Fields", names_array(names)),
    })
}

fn names_array(names: &[String]) -> Obj {
    Obj::Array(names.iter().map(|n| text_string(n)).collect())
}

/// adbe.pkcs7.detached with SHA-256, both required (`/Ff` bits 2 and 7):
/// what TrackMy Sign makes, and what Acrobat then makes as well.
fn seed_values() -> Obj {
    Obj::Dict(
        Dict::new()
            .with("Type", Obj::name("SV"))
            .with("Filter", Obj::name("Adobe.PPKLite"))
            .with(
                "SubFilter",
                Obj::Array(vec![Obj::name("adbe.pkcs7.detached")]),
            )
            .with("DigestMethod", Obj::Array(vec![Obj::name("SHA256")]))
            .with("Ff", Obj::int(2 | 64)),
    )
}

const PAD: f64 = 4.0;
/// Accent blue, #1B3A8C.
const INK: &str = "0.106 0.227 0.549";

/// Largest size up to `max` at which `s` fits `room` points, not below 4.
fn fitting_size(s: &str, face: Face, max: f64, room: f64) -> f64 {
    let at_one = text_width(s, face, 1.0);
    if at_one <= 0.0 {
        return max;
    }
    (room / at_one).clamp(4.0, max)
}

/// `s` cut with "..." to fit `room` at `size`.
fn clipped(s: &str, face: Face, size: f64, room: f64) -> String {
    if text_width(s, face, size) <= room {
        return s.to_string();
    }
    let mut chars: Vec<char> = s.chars().collect();
    while !chars.is_empty() {
        chars.pop();
        let t: String = chars.iter().collect::<String>().trim_end().to_string() + "...";
        if text_width(&t, face, size) <= room {
            return t;
        }
    }
    String::new()
}

/// The empty field's look: a dashed box with the name in bold and the
/// tooltip below it, upright to the reader whatever the page's `/Rotate`.
fn appearance(name: &str, tooltip: Option<&str>, r: DisplayRect, rotate: i32) -> Obj {
    let (w, h) = (r.w, r.h);
    let mut c: Vec<u8> = Vec::new();
    let half = 0.375;
    c.extend_from_slice(
        format!(
            "q {INK} RG 0.75 w [3 2] 0 d {} {} {} {} re S Q\n",
            fmt_real(half),
            fmt_real(half),
            fmt_real(w - 2.0 * half),
            fmt_real(h - 2.0 * half)
        )
        .as_bytes(),
    );
    let tooltip = tooltip
        .map(str::trim)
        .filter(|t| !t.is_empty() && *t != name);
    let room = (w - 2.0 * PAD).max(1.0);
    let lines = 1.0 + tooltip.is_some() as u8 as f64;
    // Line height 1.25 × the size; the tooltip a little smaller than the name.
    let by_height = ((h - 2.0 * PAD) / (lines * 1.25)).max(4.0);
    let size = fitting_size(name, Face::Bold, by_height.min(10.0), room);
    let mut runs = vec![("F2", Face::Bold, size, name.to_string())];
    if let Some(t) = tooltip {
        let s2 = fitting_size(t, Face::Regular, (size * 0.85).max(4.0), room);
        runs.push(("F1", Face::Regular, s2, t.to_string()));
    }
    let mut y = h - PAD;
    c.extend_from_slice(format!("BT {INK} rg\n").as_bytes());
    for (font, face, size, text) in runs {
        y -= size;
        if y < 1.0 {
            break;
        }
        let text = clipped(&text, face, size, room);
        c.extend_from_slice(
            format!(
                "/{font} {} Tf 1 0 0 1 {} {} Tm ",
                fmt_real(size),
                fmt_real(PAD),
                fmt_real(y)
            )
            .as_bytes(),
        );
        c.extend_from_slice(&escape(&encode(&text)));
        c.extend_from_slice(b" Tj\n");
        y -= size * 0.25;
    }
    c.extend_from_slice(b"ET\n");

    let font = |base: &str| {
        Obj::Dict(
            Dict::new()
                .with("Type", Obj::name("Font"))
                .with("Subtype", Obj::name("Type1"))
                .with("BaseFont", Obj::name(base))
                .with("Encoding", Obj::name("WinAnsiEncoding")),
        )
    };
    let resources = Dict::new().with(
        "Font",
        Obj::Dict(
            Dict::new()
                .with("F1", font("Helvetica"))
                .with("F2", font("Helvetica-Bold")),
        ),
    );
    let m = rotation_matrix(rotate, w, h);
    Obj::Stream(
        Dict::new()
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
            .with("Resources", Obj::Dict(resources)),
        c,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdf::reader::decode_stream;

    /// One page turned a quarter, an AcroForm with a text field.
    fn rotated_pdf() -> Vec<u8> {
        let objs: [&[u8]; 4] = [
            b"<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [4 0 R] >> >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Rotate 90 >>",
            b"<< /T (company) /FT /Tx /V (TrackMyTech) >>",
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
        out.extend_from_slice(b"xref\n0 5\n0000000000 65535 f\r\n");
        for o in offsets {
            out.extend_from_slice(format!("{o:010} 00000 n\r\n").as_bytes());
        }
        out.extend_from_slice(
            format!("trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n").as_bytes(),
        );
        out
    }

    fn field(name: &str) -> NewField {
        NewField {
            name: name.into(),
            page: 0,
            rect: DisplayRect {
                x: 500.0,
                y: 60.0,
                w: 200.0,
                h: 60.0,
            },
            tooltip: Some("Company Secretary \u{2014} A. Kumar".into()),
            order: None,
            lock: Some(FieldLock::All),
            seed: false,
        }
    }

    #[test]
    fn field_on_a_turned_page() {
        let pdf = rotated_pdf();
        let out = add(&pdf, None, &[field("Company Secretary")]).unwrap();
        assert!(out.starts_with(&pdf));
        let doc = Document::parse(&out).unwrap();
        let pages = doc.pages().unwrap();
        let all = crate::pdf::fields::signature_fields(&doc, &pages).unwrap();
        assert_eq!(all.len(), 1);
        let f = &all[0];
        assert!(!f.signed);
        assert_eq!(f.widgets[0].page, Some(0));
        // Displayed 842 wide: the box is 60 wide and 200 tall in user space.
        assert_eq!(f.widgets[0].rect, [60.0, 500.0, 120.0, 700.0]);
        assert_eq!(FieldLock::of_field(&doc, &f.dict), Some(FieldLock::All));
        assert!(f.dict.get("SV").is_none() && f.dict.get(ORDER_KEY).is_none());
        let Some(Obj::Ref(ap, _)) = f
            .dict
            .get("AP")
            .and_then(|a| a.as_dict())
            .and_then(|a| a.get("N"))
            .cloned()
        else {
            panic!("no appearance");
        };
        let Obj::Stream(d, raw) = doc.get(ap).unwrap() else {
            panic!("appearance is not a stream");
        };
        assert_eq!(
            d.get("Matrix"),
            Some(&Obj::Array(
                [0.0, 1.0, -1.0, 0.0, 60.0, 0.0]
                    .iter()
                    .map(|v| Obj::real(*v))
                    .collect()
            ))
        );
        let content = decode_stream(&d, &raw).unwrap();
        let has = |s: &[u8]| content.windows(s.len()).any(|w| w == s);
        assert!(has(b"[3 2] 0 d"));
        assert!(has(b"(Company Secretary) Tj"));
        // The em dash in WinAnsi.
        assert!(has(b"(Company Secretary \x97 A. Kumar) Tj"));
        // The text field is still there; the new field sits beside it.
        let (names, _) = doc.form_fields().unwrap();
        assert_eq!(names, ["company", "Company Secretary"]);
    }

    #[test]
    fn names_are_checked() {
        let pdf = rotated_pdf();
        for (name, msg) in [
            ("company", "already a field"),
            ("", "needs a name"),
            (" Director", "space"),
            ("a.b", "dot"),
        ] {
            let e = add(&pdf, None, &[field(name)]).unwrap_err().to_string();
            assert!(e.contains(msg), "{name}: {e}");
        }
        let e = add(&pdf, None, &[field("Director"), field("Director")]).unwrap_err();
        assert!(e.to_string().contains("already a field"), "{e}");
        let mut f = field("Director");
        f.lock = Some(FieldLock::Fields(vec![]));
        assert!(add(&pdf, None, &[f]).is_err());
    }

    #[test]
    fn long_labels_are_cut() {
        let s = clipped("A VERY LONG NAME FOR A SMALL BOX", Face::Bold, 8.0, 60.0);
        assert!(
            s.ends_with("...") && text_width(&s, Face::Bold, 8.0) <= 60.0,
            "{s}"
        );
        assert_eq!(clipped("Auditor", Face::Bold, 8.0, 60.0), "Auditor");
    }
}
