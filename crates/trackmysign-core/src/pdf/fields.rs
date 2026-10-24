//! Signature fields already in a document: finding them (also under `/Kids`
//! of a parent field), and the constraints a field puts on the signature
//! that fills it (`/Lock`, `/SV`).

use std::collections::{HashMap, HashSet};

use super::object::{Dict, Obj};
use super::reader::{Document, PageInfo, PdfError, Result};
use super::sign::DisplayRect;

/// A terminal signature field (one with a value or room for one).
#[derive(Debug, Clone)]
pub struct SigField {
    /// Fully qualified name, e.g. `approvals.director`.
    pub name: String,
    pub id: (u32, u16),
    pub dict: Dict,
    pub signed: bool,
    /// Its widget annotations; the field itself when they are merged.
    pub widgets: Vec<Widget>,
}

#[derive(Debug, Clone)]
pub struct Widget {
    pub id: (u32, u16),
    pub dict: Dict,
    /// Zero-based page whose `/Annots` lists it (or its `/P`).
    pub page: Option<usize>,
    /// User space, normalised `[x0, y0, x1, y1]`.
    pub rect: [f64; 4],
}

impl Widget {
    pub fn visible(&self) -> bool {
        self.rect[2] - self.rect[0] > 0.5 && self.rect[3] - self.rect[1] > 0.5
    }

    /// Rotation of the appearance, counterclockwise: the widget's `/MK /R`
    /// when it has one, otherwise the page's `/Rotate`, so the box reads
    /// upright to the viewer.
    pub fn rotation(&self, doc: &Document, page: Option<&PageInfo>) -> i32 {
        let mk = self
            .dict
            .get("MK")
            .and_then(|m| doc.resolve(m).ok())
            .and_then(|m| m.as_dict().and_then(|m| m.get("R")).and_then(Obj::as_i64));
        match mk {
            Some(r) => ((r.rem_euclid(360) as i32 + 45) / 90 * 90) % 360,
            None => page.map_or(0, |p| p.rotate),
        }
    }
}

/// PDF text string: UTF-16BE with BOM, UTF-8 with BOM, else PDFDocEncoding
/// (close enough to Latin-1 for names and reasons).
pub fn text(b: &[u8]) -> String {
    if let Some(rest) = b.strip_prefix(&[0xfe, 0xff]) {
        let u: Vec<u16> = rest
            .chunks(2)
            .map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]))
            .collect();
        String::from_utf16_lossy(&u)
    } else if let Some(rest) = b.strip_prefix(&[0xef, 0xbb, 0xbf]) {
        String::from_utf8_lossy(rest).into_owned()
    } else {
        b.iter().map(|&c| c as char).collect()
    }
}

/// Every signature field in the AcroForm, in document order.
pub fn signature_fields(doc: &Document, pages: &[PageInfo]) -> Result<Vec<SigField>> {
    let cat = doc.catalog()?;
    let Some(af) = cat.get("AcroForm") else {
        return Ok(vec![]);
    };
    let af = doc.resolve(af)?;
    let Some(fields) = af.as_dict().and_then(|d| d.get("Fields")) else {
        return Ok(vec![]);
    };
    // Widget id -> page, from the pages' /Annots.
    let mut on_page: HashMap<u32, usize> = HashMap::new();
    for (i, p) in pages.iter().enumerate() {
        if let Some(a) = p.dict.get("Annots")
            && let Ok(Obj::Array(a)) = doc.resolve(a)
        {
            for r in a {
                if let Obj::Ref(id, _) = r {
                    on_page.entry(id).or_insert(i);
                }
            }
        }
    }
    let mut walk = Walk {
        doc,
        pages,
        on_page,
        seen: HashSet::new(),
        out: Vec::new(),
    };
    for f in doc.resolve(fields)?.as_array().cloned().unwrap_or_default() {
        walk.node(&f, "", false, 0);
    }
    Ok(walk.out)
}

struct Walk<'d, 'a> {
    doc: &'d Document<'a>,
    pages: &'d [PageInfo],
    on_page: HashMap<u32, usize>,
    seen: HashSet<u32>,
    out: Vec<SigField>,
}

impl Walk<'_, '_> {
    fn node(&mut self, node: &Obj, parent: &str, parent_is_sig: bool, depth: usize) {
        // Fields are indirect objects; anything else cannot be updated anyway.
        let Obj::Ref(id, gn) = *node else {
            return;
        };
        if depth > 32 || !self.seen.insert(id) {
            return;
        }
        let Ok(obj) = self.doc.get(id) else {
            return;
        };
        let Some(d) = obj.as_dict().cloned() else {
            return;
        };
        let name = match d.get("T") {
            Some(Obj::Str(t)) if parent.is_empty() => text(t),
            Some(Obj::Str(t)) => format!("{parent}.{}", text(t)),
            _ => parent.to_string(),
        };
        let is_sig = d.get("FT").map_or(parent_is_sig, |t| t.is_name("Sig"));
        let kids = match d.get("Kids").map(|k| self.doc.resolve(k)) {
            Some(Ok(Obj::Array(k))) => k,
            _ => Vec::new(),
        };
        // Kids with a /T are fields of their own; the rest are widgets.
        let mut widgets = Vec::new();
        if d.get("Rect").is_some() || d.get("Subtype").is_some_and(|s| s.is_name("Widget")) {
            widgets.push(self.widget((id, gn), d.clone()));
        }
        for k in &kids {
            let Obj::Ref(kid, kgn) = *k else { continue };
            let Some(kd) = self.doc.get(kid).ok().and_then(|o| o.as_dict().cloned()) else {
                continue;
            };
            if kd.get("T").is_some() {
                self.node(k, &name, is_sig, depth + 1);
            } else if self.seen.insert(kid) {
                widgets.push(self.widget((kid, kgn), kd));
            }
        }
        if is_sig && (kids.is_empty() || !widgets.is_empty()) && !name.is_empty() {
            let signed = d
                .get("V")
                .and_then(|v| self.doc.resolve(v).ok())
                .is_some_and(|v| v.as_dict().is_some());
            self.out.push(SigField {
                name,
                id: (id, gn),
                dict: d,
                signed,
                widgets,
            });
        }
    }

    fn widget(&self, id: (u32, u16), dict: Dict) -> Widget {
        let rect = dict
            .get("Rect")
            .and_then(|r| self.doc.resolve(r).ok())
            .and_then(|r| r.as_array().cloned())
            .filter(|a| a.len() == 4)
            .map(|a| {
                let n: Vec<f64> = a
                    .iter()
                    .map(|o| {
                        self.doc
                            .resolve(o)
                            .ok()
                            .and_then(|o| o.as_f64())
                            .unwrap_or(0.0)
                    })
                    .collect();
                [
                    n[0].min(n[2]),
                    n[1].min(n[3]),
                    n[0].max(n[2]),
                    n[1].max(n[3]),
                ]
            })
            .unwrap_or([0.0; 4]);
        let page = self
            .on_page
            .get(&id.0)
            .copied()
            .or_else(|| match dict.get("P") {
                Some(Obj::Ref(p, _)) => self.pages.iter().position(|pg| pg.id.0 == *p),
                _ => None,
            });
        Widget {
            id,
            dict,
            page,
            rect,
        }
    }
}

/// Inverse of [`super::sign::display_to_user`]: a user-space rectangle as
/// the viewer shows it, points from the top-left of the displayed page.
pub fn user_to_display(page: &PageInfo, r: [f64; 4]) -> DisplayRect {
    let [cx0, cy0, cx1, cy1] = page.crop_box;
    let map = |ux: f64, uy: f64| -> (f64, f64) {
        match page.rotate {
            90 => (uy - cy0, ux - cx0),
            180 => (cx1 - ux, uy - cy0),
            270 => (cy1 - uy, cx1 - ux),
            _ => (ux - cx0, cy1 - uy),
        }
    };
    let (ax, ay) = map(r[0], r[1]);
    let (bx, by) = map(r[2], r[3]);
    DisplayRect {
        x: ax.min(bx),
        y: ay.min(by),
        w: (ax - bx).abs(),
        h: (ay - by).abs(),
    }
}

/// What the signature filling a field will use.
#[derive(Debug, Clone, PartialEq)]
pub struct SigFormat {
    pub sub_filter: &'static str,
}

/// Checks the field's seed values (`/SV`) against what this signature
/// will be: SHA-256, `adbe.pkcs7.detached` (or `ETSI.CAdES.detached` when
/// the field insists), the given reason and whether a timestamp is added.
/// Only required constraints (`/Ff` bits) can refuse.
pub fn check_seed_values(
    doc: &Document,
    field: &SigField,
    reason: Option<&str>,
    timestamp: bool,
) -> Result<SigFormat> {
    let mut format = SigFormat {
        sub_filter: "adbe.pkcs7.detached",
    };
    let Some(sv) = field
        .dict
        .get("SV")
        .and_then(|v| doc.resolve(v).ok())
        .and_then(|v| v.as_dict().cloned())
    else {
        return Ok(format);
    };
    let refuse = |what: String| {
        Err(PdfError::Field(format!(
            "The signature field \"{}\" {what}",
            field.name
        )))
    };
    let flags = sv.get("Ff").and_then(Obj::as_i64).unwrap_or(0);
    let required = |bit: i64| flags & bit != 0;
    let names = |key: &str| -> Vec<String> {
        sv.get(key)
            .and_then(|v| doc.resolve(v).ok())
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default()
            .iter()
            .filter_map(|o| match o {
                // Names per the spec; some writers use strings.
                Obj::Name(n) => Some(String::from_utf8_lossy(n).into_owned()),
                Obj::Str(s) => Some(text(s)),
                _ => None,
            })
            .collect()
    };

    if required(1)
        && let Some(Obj::Name(f)) = sv.get("Filter")
        && f != b"Adobe.PPKLite"
    {
        return refuse(format!(
            "requires the signature handler {}, which TrackMy Sign does not use.",
            String::from_utf8_lossy(f)
        ));
    }
    let subs = names("SubFilter");
    if required(2) && !subs.is_empty() && !subs.iter().any(|s| s == "adbe.pkcs7.detached") {
        if subs.iter().any(|s| s == "ETSI.CAdES.detached") {
            format.sub_filter = "ETSI.CAdES.detached";
        } else {
            return refuse(format!(
                "requires the signature format {}; TrackMy Sign makes adbe.pkcs7.detached or ETSI.CAdES.detached signatures.",
                subs.join(" or ")
            ));
        }
    }
    let digests = names("DigestMethod");
    if required(64)
        && !digests.is_empty()
        && !digests
            .iter()
            .any(|d| d.eq_ignore_ascii_case("SHA256") || d.eq_ignore_ascii_case("SHA-256"))
    {
        return refuse(format!(
            "requires the digest {}; TrackMy Sign signs with SHA-256.",
            digests.join(" or ")
        ));
    }
    if required(8)
        && let Some(Obj::Array(list)) = sv.get("Reasons")
    {
        let allowed: Vec<String> = list
            .iter()
            .filter_map(|o| match o {
                Obj::Str(s) => Some(text(s)),
                _ => None,
            })
            .filter(|s| s != ".")
            .collect();
        let reason = reason.filter(|r| !r.is_empty());
        let ok = match reason {
            None => true,
            Some(r) => allowed.iter().any(|a| a == r),
        };
        if !ok {
            return refuse(if allowed.is_empty() {
                "does not allow a reason; leave the reason empty.".into()
            } else {
                format!("only accepts the reason {}.", quoted(&allowed))
            });
        }
    }
    if required(32) && sv.get("AddRevInfo").is_some_and(|v| *v == Obj::Bool(true)) {
        return refuse(
            "requires revocation info inside the signature (adbe.pkcs7 AddRevInfo), which TrackMy Sign does not add.".into(),
        );
    }
    if required(128)
        && sv
            .get("LockDocument")
            .is_some_and(|v| *v == Obj::Bool(true) || v.is_name("true"))
    {
        return refuse(
            "requires the signature to lock the whole document, which TrackMy Sign does not do."
                .into(),
        );
    }
    if !timestamp
        && let Some(ts) = sv.get("TimeStamp").and_then(|v| doc.resolve(v).ok())
        && ts
            .as_dict()
            .and_then(|t| t.get("Ff"))
            .and_then(Obj::as_i64)
            .is_some_and(|f| f & 1 != 0)
    {
        return refuse("requires a trusted timestamp; turn on the timestamp option.".into());
    }
    Ok(format)
}

fn quoted(list: &[String]) -> String {
    list.iter()
        .map(|s| format!("\"{s}\""))
        .collect::<Vec<_>>()
        .join(" or ")
}

/// `/Reference` entry for a field with a `/Lock`: a FieldMDP signature
/// reference that carries the lock into the signature.
pub fn field_mdp_reference(
    doc: &Document,
    field: &SigField,
    catalog: (u32, u16),
) -> Result<Option<Obj>> {
    let Some(lock) = field
        .dict
        .get("Lock")
        .and_then(|v| doc.resolve(v).ok())
        .and_then(|v| v.as_dict().cloned())
    else {
        return Ok(None);
    };
    let action = match lock.get("Action") {
        Some(a @ Obj::Name(n)) if matches!(n.as_slice(), b"All" | b"Include" | b"Exclude") => {
            a.clone()
        }
        _ => {
            return Err(PdfError::Field(format!(
                "The signature field \"{}\" has an unreadable lock (/Lock without a valid /Action).",
                field.name
            )));
        }
    };
    let mut params = Dict::new()
        .with("Type", Obj::name("TransformParams"))
        .with("Action", action.clone());
    if !action.is_name("All") {
        let fields = lock
            .get("Fields")
            .and_then(|f| doc.resolve(f).ok())
            .unwrap_or(Obj::Array(vec![]));
        params.set("Fields", fields);
    }
    params.set("V", Obj::name("1.2"));
    // PDF 2.0 lock permissions; Acrobat records them here as well.
    if let Some(p) = lock.get("P").and_then(|p| doc.resolve(p).ok())
        && p.as_i64().is_some()
    {
        params.set("P", p);
    }
    Ok(Some(Obj::Array(vec![Obj::Dict(
        Dict::new()
            .with("Type", Obj::name("SigRef"))
            .with("TransformMethod", Obj::name("FieldMDP"))
            .with("Data", Obj::Ref(catalog.0, catalog.1))
            .with("TransformParams", Obj::Dict(params)),
    )])))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdf::sign::display_to_user;

    fn page(rotate: i32) -> PageInfo {
        PageInfo {
            id: (3, 0),
            dict: Dict::new(),
            media_box: [0.0, 0.0, 600.0, 800.0],
            crop_box: [10.0, 20.0, 590.0, 780.0],
            rotate,
        }
    }

    #[test]
    fn display_round_trip() {
        let r = DisplayRect {
            x: 10.0,
            y: 20.0,
            w: 100.0,
            h: 50.0,
        };
        for rot in [0, 90, 180, 270] {
            let p = page(rot);
            assert_eq!(user_to_display(&p, display_to_user(&p, r)), r, "{rot}");
        }
    }
}
