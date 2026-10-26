//! Fillable form fields (AcroForm): what a PDF asks to be filled in, and
//! filling it in as an incremental update.
//!
//! Each widget of a filled field gets an appearance stream drawn here from
//! the field's `/DA` (font, size, colour) and `/Q` (alignment), so every
//! viewer shows the values without regenerating them; `/NeedAppearances`
//! is turned off. The fields stay fillable: nothing is flattened. Forms that
//! exist only as XFA are refused.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::{Deserialize, Serialize};

use super::appearance::{code_width, rotation_matrix};
use super::docmdp::{self, DocMdp};
use super::fields::{signature_fields, text, user_to_display};
use super::object::{Dict, Lexer, Obj, Tok, fmt_real};
use super::reader::{Document, PageInfo, PdfError, Result, decode_stream};
use super::sign::{DisplayRect, append_update, text_string};
use super::textdoc::{transliterate, win_ansi_code};
use crate::stamp::FontFamily;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FieldKind {
    Text,
    Checkbox,
    Radio,
    /// A drop-down list, possibly also taking typed text (`editable`).
    Combo,
    List,
}

impl FieldKind {
    pub fn label(self) -> &'static str {
        match self {
            FieldKind::Text => "text",
            FieldKind::Checkbox => "check box",
            FieldKind::Radio => "radio button group",
            FieldKind::Combo => "drop-down",
            FieldKind::List => "list",
        }
    }
}

/// A field the user can fill in (signature fields and push buttons are not).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FormField {
    /// Fully qualified name, e.g. `applicant.name`.
    pub name: String,
    pub kind: FieldKind,
    /// The tooltip (`/TU`), which readers show as the field's label.
    pub label: Option<String>,
    /// The text; the chosen options; a check box's or radio group's chosen
    /// export value. Empty when unset or off.
    pub value: Vec<String>,
    /// Choices of a drop-down or list; the export value of each check box
    /// or radio button.
    pub options: Vec<FieldOption>,
    pub read_only: bool,
    pub required: bool,
    pub multiline: bool,
    pub password: bool,
    /// Text spread over `max_len` equal boxes.
    pub comb: bool,
    pub max_len: Option<usize>,
    /// A drop-down that also takes typed text.
    pub editable: bool,
    pub multi_select: bool,
    /// Signatures whose lock (FieldMDP) covers this field: filling it in
    /// would invalidate them.
    pub locked_by: Vec<String>,
    pub widgets: Vec<FormWidget>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FieldOption {
    /// What is stored as the field's value.
    pub value: String,
    /// What the reader shows.
    pub label: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FormWidget {
    /// Zero-based page.
    pub page: Option<usize>,
    /// As displayed on `page`; `None` for a hidden or zero-size widget.
    pub rect: Option<DisplayRect>,
    /// Check boxes and radio buttons: the export value this one stands for.
    pub on: Option<String>,
    /// From `/DA`; 0 means "fit the box".
    pub font_size: f64,
    /// 0 left, 1 centred, 2 right.
    pub align: u8,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Form {
    /// In tab order: page by page, as each page's `/Tabs` says.
    pub fields: Vec<FormField>,
    /// The document also has an XFA form.
    pub xfa: bool,
    /// Why the form cannot be filled in at all, when it cannot.
    pub blocked: Option<String>,
}

/// A value to put into a field. Text and drop-downs take one value, a list
/// one or more; a check box takes its export value (or `Off`, `true`,
/// `false`), a radio group the export value of one button or `Off`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct FillValue {
    pub name: String,
    pub value: Vec<String>,
}

pub struct Filled {
    pub data: Vec<u8>,
    /// Things the user should know: a font that was replaced, text that
    /// was transliterated for display.
    pub warnings: Vec<String>,
}

pub const XFA_ONLY: &str = "XFA forms aren't supported: this PDF's form exists only as XFA, which TrackMy Sign cannot fill in.";

// Field flags (`/Ff`), ISO 32000-1 tables 221, 226, 228, 230.
const READ_ONLY: i64 = 1;
const REQUIRED: i64 = 1 << 1;
const MULTILINE: i64 = 1 << 12;
const PASSWORD: i64 = 1 << 13;
const RADIO: i64 = 1 << 15;
const PUSH_BUTTON: i64 = 1 << 16;
const COMBO: i64 = 1 << 17;
const EDIT: i64 = 1 << 18;
const MULTI_SELECT: i64 = 1 << 21;
const COMB: i64 = 1 << 24;

/// Field attributes a kid takes from its parent unless it has its own.
#[derive(Clone, Default)]
struct Inherited {
    ft: Option<Vec<u8>>,
    ff: i64,
    v: Option<Obj>,
    da: Option<Vec<u8>>,
    q: Option<i64>,
    opt: Option<Obj>,
    max_len: Option<i64>,
}

/// A terminal field as found in the document.
struct Node {
    name: String,
    id: (u32, u16),
    dict: Dict,
    kind: FieldKind,
    ff: i64,
    value: Option<Obj>,
    da: Option<Vec<u8>>,
    q: i64,
    opt: Vec<Obj>,
    max_len: Option<usize>,
    widgets: Vec<WidgetNode>,
}

struct WidgetNode {
    id: (u32, u16),
    dict: Dict,
    page: Option<usize>,
    /// Position in the page's tab order.
    order: usize,
    rect: [f64; 4],
}

impl WidgetNode {
    fn visible(&self) -> bool {
        self.rect[2] - self.rect[0] > 0.5 && self.rect[3] - self.rect[1] > 0.5
    }
}

impl Node {
    fn read_only(&self) -> bool {
        self.ff & READ_ONLY != 0
    }

    fn multiline(&self) -> bool {
        self.kind == FieldKind::Text && self.ff & MULTILINE != 0
    }

    fn comb(&self) -> bool {
        self.kind == FieldKind::Text
            && self.ff & COMB != 0
            && self.ff & (MULTILINE | PASSWORD) == 0
            && self.max_len.is_some_and(|m| m > 0)
    }

    /// Choices as (export value, display text).
    fn options(&self) -> Vec<FieldOption> {
        self.opt
            .iter()
            .filter_map(|o| match o {
                Obj::Str(s) => Some(FieldOption {
                    value: text(s),
                    label: text(s),
                }),
                Obj::Array(a) => match (a.first(), a.get(1)) {
                    (Some(Obj::Str(v)), Some(Obj::Str(l))) => Some(FieldOption {
                        value: text(v),
                        label: text(l),
                    }),
                    (Some(Obj::Str(v)), None) => Some(FieldOption {
                        value: text(v),
                        label: text(v),
                    }),
                    _ => None,
                },
                _ => None,
            })
            .collect()
    }

    /// Export value of the `i`th widget of a check box or radio group: its
    /// `/Opt` entry when there is one, else its on state.
    fn export(&self, doc: &Document, i: usize) -> Option<String> {
        if let Some(Obj::Str(s)) = self.opt.get(i) {
            return Some(text(s));
        }
        on_state(doc, &self.widgets[i]).map(|s| String::from_utf8_lossy(&s).into_owned())
    }

    fn values(&self, doc: &Document) -> Vec<String> {
        let v = match self.value.as_ref().map(|v| doc.resolve(v)) {
            Some(Ok(v)) => v,
            _ => return vec![],
        };
        match (self.kind, v) {
            (FieldKind::Checkbox | FieldKind::Radio, Obj::Name(n)) if n != b"Off" => {
                let i = self
                    .widgets
                    .iter()
                    .position(|w| on_state(doc, w).is_some_and(|s| s == n));
                vec![match i.and_then(|i| self.export(doc, i)) {
                    Some(e) => e,
                    None => String::from_utf8_lossy(&n).into_owned(),
                }]
            }
            (FieldKind::Checkbox | FieldKind::Radio, _) => vec![],
            (_, Obj::Str(s)) if s.is_empty() => vec![],
            (_, Obj::Str(s)) => vec![text(&s)],
            (_, Obj::Array(a)) => a
                .iter()
                .filter_map(|o| match o {
                    Obj::Str(s) => Some(text(s)),
                    _ => None,
                })
                .collect(),
            // Rich text values come as a stream.
            (_, Obj::Stream(d, raw)) => decode_stream(&d, &raw)
                .map(|b| vec![text(&b)])
                .unwrap_or_default(),
            _ => vec![],
        }
    }
}

/// The on-state name of a check box or radio button widget: the key of its
/// normal appearance that is not `Off`.
fn on_state(doc: &Document, w: &WidgetNode) -> Option<Vec<u8>> {
    let ap = doc.resolve(w.dict.get("AP")?).ok()?;
    let n = doc.resolve(ap.as_dict()?.get("N")?).ok()?;
    n.as_dict()?
        .0
        .iter()
        .map(|(k, _)| k)
        .find(|k| k.as_slice() != b"Off")
        .cloned()
}

fn rect_of(doc: &Document, d: &Dict) -> [f64; 4] {
    d.get("Rect")
        .and_then(|r| doc.resolve(r).ok())
        .and_then(|r| r.as_array().cloned())
        .filter(|a| a.len() == 4)
        .map(|a| {
            let n: Vec<f64> = a
                .iter()
                .map(|o| doc.resolve(o).ok().and_then(|o| o.as_f64()).unwrap_or(0.0))
                .collect();
            [
                n[0].min(n[2]),
                n[1].min(n[3]),
                n[0].max(n[2]),
                n[1].max(n[3]),
            ]
        })
        .unwrap_or([0.0; 4])
}

struct Walk<'d, 'a> {
    doc: &'d Document<'a>,
    pages: &'d [PageInfo],
    /// Widget id -> (page, position in that page's tab order).
    on_page: HashMap<u32, (usize, usize)>,
    seen: HashSet<u32>,
    out: Vec<Node>,
}

impl Walk<'_, '_> {
    fn node(&mut self, node: &Obj, parent: &str, inherited: &Inherited, depth: usize) {
        let Obj::Ref(id, gn) = *node else {
            return;
        };
        if depth > 32 || !self.seen.insert(id) {
            return;
        }
        let Some(d) = self.doc.get(id).ok().and_then(|o| o.as_dict().cloned()) else {
            return;
        };
        let name = match d.get("T") {
            Some(Obj::Str(t)) if parent.is_empty() => text(t),
            Some(Obj::Str(t)) => format!("{parent}.{}", text(t)),
            _ => parent.to_string(),
        };
        let resolve = |k: &str| d.get(k).and_then(|v| self.doc.resolve(v).ok());
        let mut inh = inherited.clone();
        if let Some(Obj::Name(n)) = resolve("FT") {
            inh.ft = Some(n);
        }
        if let Some(f) = resolve("Ff").and_then(|f| f.as_i64()) {
            inh.ff = f;
        }
        if let Some(v) = d.get("V") {
            inh.v = Some(v.clone());
        }
        if let Some(Obj::Str(s)) = resolve("DA") {
            inh.da = Some(s);
        }
        if let Some(q) = resolve("Q").and_then(|q| q.as_i64()) {
            inh.q = Some(q);
        }
        if let Some(o) = resolve("Opt") {
            inh.opt = Some(o);
        }
        if let Some(m) = resolve("MaxLen").and_then(|m| m.as_i64()) {
            inh.max_len = Some(m);
        }
        let kids = match resolve("Kids") {
            Some(Obj::Array(k)) => k,
            _ => Vec::new(),
        };
        // Kids with a /T are fields of their own; the rest are widgets.
        let mut widgets = Vec::new();
        if d.get("Rect").is_some() || d.get("Subtype").is_some_and(|s| s.is_name("Widget")) {
            widgets.push(self.widget((id, gn), d.clone()));
        }
        let mut has_fields = false;
        for k in &kids {
            let Obj::Ref(kid, kgn) = *k else { continue };
            let Some(kd) = self.doc.get(kid).ok().and_then(|o| o.as_dict().cloned()) else {
                continue;
            };
            if kd.get("T").is_some() {
                has_fields = true;
                self.node(k, &name, &inh, depth + 1);
            } else if self.seen.insert(kid) {
                widgets.push(self.widget((kid, kgn), kd));
            }
        }
        if has_fields || name.is_empty() {
            return;
        }
        let kind = match inh.ft.as_deref() {
            Some(b"Tx") => FieldKind::Text,
            Some(b"Btn") if inh.ff & PUSH_BUTTON != 0 => return,
            Some(b"Btn") if inh.ff & RADIO != 0 => FieldKind::Radio,
            Some(b"Btn") => FieldKind::Checkbox,
            Some(b"Ch") if inh.ff & COMBO != 0 => FieldKind::Combo,
            Some(b"Ch") => FieldKind::List,
            _ => return,
        };
        self.out.push(Node {
            name,
            id: (id, gn),
            dict: d,
            kind,
            ff: inh.ff,
            value: inh.v,
            da: inh.da,
            q: inh.q.unwrap_or(0),
            opt: inh
                .opt
                .and_then(|o| o.as_array().cloned())
                .unwrap_or_default()
                .iter()
                .map(|o| self.doc.resolve(o).unwrap_or(Obj::Null))
                .collect(),
            max_len: inh.max_len.filter(|m| *m > 0).map(|m| m as usize),
            widgets,
        });
    }

    fn widget(&self, id: (u32, u16), dict: Dict) -> WidgetNode {
        let placed = self
            .on_page
            .get(&id.0)
            .copied()
            .or_else(|| match dict.get("P") {
                Some(Obj::Ref(p, _)) => self
                    .pages
                    .iter()
                    .position(|pg| pg.id.0 == *p)
                    .map(|p| (p, usize::MAX)),
                _ => None,
            });
        WidgetNode {
            rect: rect_of(self.doc, &dict),
            id,
            dict,
            page: placed.map(|p| p.0),
            order: placed.map_or(usize::MAX, |p| p.1),
        }
    }
}

/// Widget id -> (page, tab position): `/Annots` order, or by rows (`/Tabs
/// /R`) or columns (`/Tabs /C`).
fn tab_order(doc: &Document, pages: &[PageInfo]) -> HashMap<u32, (usize, usize)> {
    let mut out = HashMap::new();
    for (i, p) in pages.iter().enumerate() {
        let Some(Ok(Obj::Array(annots))) = p.dict.get("Annots").map(|a| doc.resolve(a)) else {
            continue;
        };
        let mut list: Vec<(u32, [f64; 4])> = annots
            .iter()
            .filter_map(|r| match r {
                Obj::Ref(id, _) => Some((
                    *id,
                    doc.get(*id)
                        .ok()
                        .and_then(|o| o.as_dict().map(|d| rect_of(doc, d)))
                        .unwrap_or([0.0; 4]),
                )),
                _ => None,
            })
            .collect();
        match p.dict.get("Tabs") {
            Some(t) if t.is_name("R") => list.sort_by(|a, b| {
                (-a.1[3], a.1[0])
                    .partial_cmp(&(-b.1[3], b.1[0]))
                    .unwrap_or(std::cmp::Ordering::Equal)
            }),
            Some(t) if t.is_name("C") => list.sort_by(|a, b| {
                (a.1[0], -a.1[3])
                    .partial_cmp(&(b.1[0], -b.1[3]))
                    .unwrap_or(std::cmp::Ordering::Equal)
            }),
            _ => {}
        }
        for (n, (id, _)) in list.into_iter().enumerate() {
            out.entry(id).or_insert((i, n));
        }
    }
    out
}

fn acroform(doc: &Document) -> Result<Option<Dict>> {
    let cat = doc.catalog()?;
    Ok(match cat.get("AcroForm") {
        Some(af) => doc.resolve(af)?.as_dict().cloned(),
        None => None,
    })
}

fn nodes(doc: &Document, pages: &[PageInfo], af: &Dict) -> Result<Vec<Node>> {
    let Some(fields) = af.get("Fields") else {
        return Ok(vec![]);
    };
    let mut walk = Walk {
        doc,
        pages,
        on_page: tab_order(doc, pages),
        seen: HashSet::new(),
        out: Vec::new(),
    };
    let top = Inherited {
        da: match af.get("DA").map(|d| doc.resolve(d)) {
            Some(Ok(Obj::Str(s))) => Some(s),
            _ => None,
        },
        q: af
            .get("Q")
            .and_then(|q| doc.resolve(q).ok())
            .and_then(|q| q.as_i64()),
        ..Default::default()
    };
    for f in doc.resolve(fields)?.as_array().cloned().unwrap_or_default() {
        walk.node(&f, "", &top, 0);
    }
    let mut out = walk.out;
    // Tab order: by the first widget on a page; fields on no page last.
    out.sort_by_key(|n| {
        n.widgets
            .iter()
            .filter_map(|w| w.page.map(|p| (p, w.order)))
            .min()
            .unwrap_or((usize::MAX, usize::MAX))
    });
    Ok(out)
}

/// What a signature's FieldMDP lock covers.
enum Lock {
    All,
    Include(Vec<String>),
    Exclude(Vec<String>),
}

impl Lock {
    fn covers(&self, field: &str) -> bool {
        let listed = |names: &[String]| {
            names.iter().any(|n| {
                field == n
                    || field
                        .strip_prefix(n.as_str())
                        .is_some_and(|r| r.starts_with('.'))
            })
        };
        match self {
            Lock::All => true,
            Lock::Include(names) => listed(names),
            Lock::Exclude(names) => !listed(names),
        }
    }

    fn from_params(doc: &Document, d: &Dict) -> Option<Lock> {
        let names = || -> Vec<String> {
            d.get("Fields")
                .and_then(|f| doc.resolve(f).ok())
                .and_then(|f| f.as_array().cloned())
                .unwrap_or_default()
                .iter()
                .filter_map(|o| match doc.resolve(o).ok()? {
                    Obj::Str(s) => Some(text(&s)),
                    _ => None,
                })
                .collect()
        };
        // PDF 2.0: nothing at all may change after this signature.
        if d.get("P").and_then(Obj::as_i64) == Some(1) {
            return Some(Lock::All);
        }
        match d.get("Action") {
            Some(a) if a.is_name("All") => Some(Lock::All),
            Some(a) if a.is_name("Include") => Some(Lock::Include(names())),
            Some(a) if a.is_name("Exclude") => Some(Lock::Exclude(names())),
            _ => None,
        }
    }
}

/// The locks of the signatures already made, by signature field name: the
/// field's `/Lock`, or the FieldMDP reference in the signature.
fn signature_locks(doc: &Document, pages: &[PageInfo]) -> Result<Vec<(String, Lock)>> {
    let mut out = Vec::new();
    for f in signature_fields(doc, pages)?
        .into_iter()
        .filter(|f| f.signed)
    {
        if let Some(lock) = f
            .dict
            .get("Lock")
            .and_then(|l| doc.resolve(l).ok())
            .and_then(|l| l.as_dict().and_then(|l| Lock::from_params(doc, l)))
        {
            out.push((f.name, lock));
            continue;
        }
        let sig = f
            .dict
            .get("V")
            .and_then(|v| doc.resolve(v).ok())
            .and_then(|v| v.as_dict().cloned())
            .unwrap_or_default();
        let refs = sig
            .get("Reference")
            .and_then(|r| doc.resolve(r).ok())
            .and_then(|r| r.as_array().cloned())
            .unwrap_or_default();
        for r in refs {
            let Some(r) = doc.resolve(&r).ok().and_then(|r| r.as_dict().cloned()) else {
                continue;
            };
            if !r
                .get("TransformMethod")
                .is_some_and(|m| m.is_name("FieldMDP"))
            {
                continue;
            }
            if let Some(lock) = r
                .get("TransformParams")
                .and_then(|p| doc.resolve(p).ok())
                .and_then(|p| p.as_dict().and_then(|p| Lock::from_params(doc, p)))
            {
                out.push((f.name.clone(), lock));
            }
        }
    }
    Ok(out)
}

/// Why nothing in the form may be filled in, if so.
fn blocked(doc: &Document, af: &Dict, has_fields: bool) -> Result<Option<String>> {
    if af.get("XFA").is_some() && !has_fields {
        return Ok(Some(XFA_ONLY.into()));
    }
    if doc.crypt.as_ref().is_some_and(|c| !c.may_sign()) {
        return Ok(Some(
            "This PDF's security settings do not allow filling in its form; enter its owner (permissions) password."
                .into(),
        ));
    }
    if docmdp::of_document(doc)? == Some(DocMdp::NoChanges) {
        return Ok(Some(
            "The document is certified with no changes allowed. Filling in its form would invalidate the certification."
                .into(),
        ));
    }
    Ok(None)
}

/// The fillable fields of `doc`, in tab order.
pub fn read(doc: &Document) -> Result<Form> {
    let Some(af) = acroform(doc)? else {
        return Ok(Form::default());
    };
    let pages = doc.pages()?;
    let nodes = nodes(doc, &pages, &af)?;
    let locks = signature_locks(doc, &pages)?;
    let fields = nodes
        .iter()
        .map(|n| {
            let button = matches!(n.kind, FieldKind::Checkbox | FieldKind::Radio);
            let mut options = n.options();
            let widgets = n
                .widgets
                .iter()
                .enumerate()
                .map(|(i, w)| {
                    let on = if button { n.export(doc, i) } else { None };
                    if let Some(on) = &on
                        && !options.iter().any(|o| &o.value == on)
                    {
                        options.push(FieldOption {
                            value: on.clone(),
                            label: on.clone(),
                        });
                    }
                    let da = parse_da(widget_da(n, w));
                    FormWidget {
                        page: w.page,
                        rect: match w.page {
                            Some(p) if w.visible() && !hidden(w) => {
                                Some(user_to_display(&pages[p], w.rect))
                            }
                            _ => None,
                        },
                        on,
                        font_size: da.size,
                        align: widget_q(doc, n, w) as u8,
                    }
                })
                .collect();
            if button {
                options.retain(|o| n.kind == FieldKind::Radio || !o.value.is_empty());
            }
            FormField {
                name: n.name.clone(),
                kind: n.kind,
                label: match n.dict.get("TU").map(|t| doc.resolve(t)) {
                    Some(Ok(Obj::Str(s))) => Some(text(&s)).filter(|s| !s.trim().is_empty()),
                    _ => None,
                },
                value: n.values(doc),
                options,
                read_only: n.read_only(),
                required: n.ff & REQUIRED != 0,
                multiline: n.multiline(),
                password: n.kind == FieldKind::Text && n.ff & PASSWORD != 0,
                comb: n.comb(),
                max_len: if n.kind == FieldKind::Text {
                    n.max_len
                } else {
                    None
                },
                editable: n.kind == FieldKind::Combo && n.ff & EDIT != 0,
                multi_select: n.kind == FieldKind::List && n.ff & MULTI_SELECT != 0,
                locked_by: locks
                    .iter()
                    .filter(|(_, l)| l.covers(&n.name))
                    .map(|(s, _)| s.clone())
                    .collect(),
                widgets,
            }
        })
        .collect::<Vec<_>>();
    Ok(Form {
        xfa: af.get("XFA").is_some(),
        blocked: blocked(doc, &af, !fields.is_empty())?,
        fields,
    })
}

/// Annotation flag 2: hidden.
fn hidden(w: &WidgetNode) -> bool {
    w.dict
        .get("F")
        .and_then(Obj::as_i64)
        .is_some_and(|f| f & 2 != 0)
}

fn widget_da<'n>(n: &'n Node, w: &'n WidgetNode) -> &'n [u8] {
    match w.dict.get("DA") {
        Some(Obj::Str(s)) => s,
        _ => n.da.as_deref().unwrap_or(b""),
    }
}

fn widget_q(doc: &Document, n: &Node, w: &WidgetNode) -> i64 {
    w.dict
        .get("Q")
        .and_then(|q| doc.resolve(q).ok())
        .and_then(|q| q.as_i64())
        .unwrap_or(n.q)
        .clamp(0, 2)
}

/// A field's default appearance: font resource, size (0 = auto), colour.
struct Da {
    font: Vec<u8>,
    size: f64,
    color: String,
}

fn parse_da(da: &[u8]) -> Da {
    let mut out = Da {
        font: Vec::new(),
        size: 0.0,
        color: "0 g".into(),
    };
    let mut lx = Lexer::new(da, 0);
    let mut operands: Vec<Tok> = Vec::new();
    let num = |t: &Tok| match t {
        Tok::Num(n) => Some(n.clone()),
        _ => None,
    };
    while let Ok(Some(tok)) = lx.next_tok() {
        let Tok::Kw(op) = tok else {
            operands.push(tok);
            continue;
        };
        let n = operands.len();
        match op.as_slice() {
            b"Tf" if n >= 2 => {
                if let Tok::Name(f) = &operands[n - 2] {
                    out.font = f.clone();
                }
                out.size = num(&operands[n - 1])
                    .and_then(|s| s.parse::<f64>().ok())
                    .unwrap_or(0.0)
                    .max(0.0);
            }
            b"g" | b"rg" | b"k" => {
                let count = match op.as_slice() {
                    b"g" => 1,
                    b"rg" => 3,
                    _ => 4,
                };
                let args: Option<Vec<String>> = operands
                    .get(n.saturating_sub(count)..)
                    .filter(|a| a.len() == count)
                    .map(|a| a.iter().map(num).collect::<Option<Vec<_>>>())
                    .unwrap_or(None);
                if let Some(args) = args {
                    out.color = format!("{} {}", args.join(" "), String::from_utf8_lossy(&op));
                }
            }
            _ => {}
        }
        operands.clear();
    }
    out
}

const STANDARD_14: [&str; 14] = [
    "Helvetica",
    "Helvetica-Bold",
    "Helvetica-Oblique",
    "Helvetica-BoldOblique",
    "Times-Roman",
    "Times-Bold",
    "Times-Italic",
    "Times-BoldItalic",
    "Courier",
    "Courier-Bold",
    "Courier-Oblique",
    "Courier-BoldOblique",
    "Symbol",
    "ZapfDingbats",
];

/// The standard font a `/BaseFont` is, or has the same metrics as (Arial,
/// Times New Roman and Courier New as Windows names them).
fn standard_name(base: &str) -> Option<&'static str> {
    if let Some(s) = STANDARD_14.iter().find(|s| **s == base) {
        return Some(s);
    }
    let b: String = base.chars().filter(|c| !c.is_whitespace()).collect();
    let family = if b.starts_with("Arial") || b.starts_with("Helvetica") {
        0
    } else if b.starts_with("TimesNewRoman") || b.starts_with("Times") {
        1
    } else if b.starts_with("CourierNew") || b.starts_with("Courier") {
        2
    } else {
        return None;
    };
    let bold = b.contains("Bold");
    let italic = b.contains("Italic") || b.contains("Oblique");
    Some(STANDARD_14[family * 4 + usize::from(bold) + 2 * usize::from(italic)])
}

/// Width metrics for a standard font (italic faces measure as upright).
fn metrics(base: &str) -> (FontFamily, bool) {
    let family = if base.starts_with("Times") {
        FontFamily::Times
    } else if base.starts_with("Courier") {
        FontFamily::Courier
    } else {
        FontFamily::Helvetica
    };
    (family, base.contains("Bold"))
}

/// Font resource names that readers know without a `/DR` entry.
fn known_resource(name: &[u8]) -> Option<&'static str> {
    Some(match name {
        b"Helv" => "Helvetica",
        b"HeBo" => "Helvetica-Bold",
        b"TiRo" => "Times-Roman",
        b"TiBo" => "Times-Bold",
        b"Cour" => "Courier",
        b"ZaDb" => "ZapfDingbats",
        _ => return None,
    })
}

/// The font an appearance is drawn with.
struct Font {
    resource: Vec<u8>,
    base: &'static str,
    obj: Obj,
}

impl Font {
    fn width(&self, bytes: &[u8], size: f64) -> f64 {
        let (family, bold) = metrics(self.base);
        bytes
            .iter()
            .map(|&b| code_width(b, family, bold))
            .sum::<f64>()
            * size
            / 1000.0
    }
}

/// Widths of the ZapfDingbats glyphs used for check marks, in 1/1000.
fn dingbat_width(c: u8) -> f64 {
    match c {
        b'4' => 760.0,
        b'8' => 776.0,
        b'l' => 791.0,
        b'n' => 762.0,
        b'u' => 788.0,
        b'H' => 816.0,
        _ => 800.0,
    }
}

/// Text in WinAnsi, the encoding of the fonts we draw with, and whether
/// some of it had to be transliterated.
fn win_ansi(s: &str) -> (Vec<u8>, bool) {
    let t = transliterate(s);
    let changed = s.chars().any(|c| win_ansi_code(c).is_none() && c != '\n');
    (
        t.chars()
            .filter(|&c| c != '\n')
            .map(|c| win_ansi_code(c).unwrap_or(b'?'))
            .collect(),
        changed,
    )
}

fn escape(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() + 2);
    s.push('(');
    for &b in bytes {
        match b {
            b'(' | b')' | b'\\' => {
                s.push('\\');
                s.push(b as char);
            }
            0x20..=0x7e => s.push(b as char),
            _ => s.push_str(&format!("\\{b:03o}")),
        }
    }
    s.push(')');
    s
}

/// Where a widget's appearance is drawn: its box upright as the reader
/// sees it, the turn onto the page, and the background and border from
/// `/MK` and `/BS`.
struct Frame {
    w: f64,
    h: f64,
    rotate: i32,
    background: Option<String>,
    border: Option<(String, f64, bool)>,
}

impl Frame {
    fn new(doc: &Document, w: &WidgetNode) -> Frame {
        let mk = w
            .dict
            .get("MK")
            .and_then(|m| doc.resolve(m).ok())
            .and_then(|m| m.as_dict().cloned())
            .unwrap_or_default();
        let rotate = mk
            .get("R")
            .and_then(Obj::as_i64)
            .map_or(0, |r| ((r.rem_euclid(360) as i32 + 45) / 90 * 90) % 360);
        let [x0, y0, x1, y1] = w.rect;
        let (bw, bh) = if rotate % 180 == 0 {
            (x1 - x0, y1 - y0)
        } else {
            (y1 - y0, x1 - x0)
        };
        let color = |key: &str, stroke: bool| -> Option<String> {
            let a = mk.get(key).and_then(|c| doc.resolve(c).ok())?;
            let n: Vec<String> = a
                .as_array()?
                .iter()
                .map(|v| fmt_real(v.as_f64().unwrap_or(0.0)))
                .collect();
            let op = match (n.len(), stroke) {
                (1, false) => "g",
                (3, false) => "rg",
                (4, false) => "k",
                (1, true) => "G",
                (3, true) => "RG",
                (4, true) => "K",
                _ => return None,
            };
            Some(format!("{} {op}", n.join(" ")))
        };
        let bs = w
            .dict
            .get("BS")
            .and_then(|b| doc.resolve(b).ok())
            .and_then(|b| b.as_dict().cloned())
            .unwrap_or_default();
        let width = bs.get("W").and_then(Obj::as_f64).unwrap_or(1.0);
        let underline = bs.get("S").is_some_and(|s| s.is_name("U"));
        Frame {
            w: bw,
            h: bh,
            rotate,
            background: color("BG", false),
            border: color("BC", true)
                .filter(|_| width > 0.0)
                .map(|c| (c, width, underline)),
        }
    }

    fn border_width(&self) -> f64 {
        self.border.as_ref().map_or(0.0, |b| b.1)
    }

    /// Inset of text from the edges.
    fn padding(&self) -> f64 {
        (2.0 * self.border_width()).max(2.0)
    }

    fn draw(&self) -> String {
        let r = |v: f64| fmt_real(v);
        let mut s = String::new();
        if let Some(bg) = &self.background {
            s += &format!("{bg}\n0 0 {} {} re f\n", r(self.w), r(self.h));
        }
        if let Some((color, bw, underline)) = &self.border {
            let half = bw / 2.0;
            if *underline {
                s += &format!(
                    "{color} {} w\n0 {} m {} {} l S\n",
                    r(*bw),
                    r(half),
                    r(self.w),
                    r(half)
                );
            } else {
                s += &format!(
                    "{color} {} w\n{} {} {} {} re S\n",
                    r(*bw),
                    r(half),
                    r(half),
                    r(self.w - bw),
                    r(self.h - bw)
                );
            }
        }
        s
    }

    fn stream(&self, content: String, resources: Dict) -> Obj {
        let m = rotation_matrix(self.rotate, self.w, self.h);
        Obj::Stream(
            Dict::new()
                .with("Type", Obj::name("XObject"))
                .with("Subtype", Obj::name("Form"))
                .with(
                    "BBox",
                    Obj::Array(vec![
                        Obj::int(0),
                        Obj::int(0),
                        Obj::real(self.w),
                        Obj::real(self.h),
                    ]),
                )
                .with(
                    "Matrix",
                    Obj::Array(m.iter().map(|v| Obj::real(*v)).collect()),
                )
                .with("Resources", Obj::Dict(resources)),
            content.into_bytes(),
        )
    }
}

/// One line of text placed in a box.
struct Placed {
    x: f64,
    y: f64,
    bytes: Vec<u8>,
}

/// Breaks `text` into lines at most `max` points wide: at spaces where
/// possible, inside a word only when the word alone is too wide.
fn wrap(font: &Font, size: f64, text: &[u8], max: f64) -> Vec<Vec<u8>> {
    let w = |s: &[u8]| font.width(s, size);
    let mut lines: Vec<Vec<u8>> = Vec::new();
    let mut line: Vec<u8> = Vec::new();
    for word in text.split(|&b| b == b' ') {
        let mut candidate = line.clone();
        if !candidate.is_empty() {
            candidate.push(b' ');
        }
        candidate.extend_from_slice(word);
        if w(&candidate) <= max || line.is_empty() && w(word) <= max {
            line = candidate;
            continue;
        }
        if !line.is_empty() {
            lines.push(std::mem::take(&mut line));
        }
        for &b in word {
            line.push(b);
            if w(&line) > max && line.len() > 1 {
                line.pop();
                lines.push(std::mem::replace(&mut line, vec![b]));
            }
        }
    }
    lines.push(line);
    lines
}

const LEADING: f64 = 1.15;

type Objects = BTreeMap<u32, (u16, Obj)>;

/// The objects of one fill update as they are built.
struct Update<'d, 'a> {
    doc: &'d Document<'a>,
    dr_fonts: Dict,
    objs: Objects,
    next: u32,
    /// Standard fonts written in this update, by base name.
    fonts: HashMap<&'static str, Obj>,
    warnings: Vec<String>,
}

impl Update<'_, '_> {
    fn add(&mut self, obj: Obj) -> Obj {
        let id = self.next;
        self.next += 1;
        self.objs.insert(id, (0, obj));
        Obj::Ref(id, 0)
    }

    /// `id`'s dictionary as changed so far in this update.
    fn edit(&mut self, id: (u32, u16), original: &Dict, f: impl FnOnce(&mut Dict)) {
        let mut d = match self.objs.get(&id.0) {
            Some((_, Obj::Dict(d))) => d.clone(),
            _ => original.clone(),
        };
        f(&mut d);
        self.objs.insert(id.0, (id.1, Obj::Dict(d)));
    }

    fn warn(&mut self, w: String) {
        if !self.warnings.contains(&w) {
            self.warnings.push(w);
        }
    }

    fn standard_font(&mut self, base: &'static str) -> Obj {
        if let Some(r) = self.fonts.get(base) {
            return r.clone();
        }
        let mut d = Dict::new()
            .with("Type", Obj::name("Font"))
            .with("Subtype", Obj::name("Type1"))
            .with("BaseFont", Obj::name(base));
        if !matches!(base, "Symbol" | "ZapfDingbats") {
            d.set("Encoding", Obj::name("WinAnsiEncoding"));
        }
        let r = self.add(Obj::Dict(d));
        self.fonts.insert(base, r.clone());
        r
    }

    /// The font for `field`'s text: the `/DR` font named in `/DA` when it
    /// is a standard font (reused when it is WinAnsi-encoded), otherwise
    /// Helvetica.
    fn font(&mut self, field: &str, resource: &[u8]) -> Font {
        let doc = self.doc;
        let entry = self
            .dr_fonts
            .get(&String::from_utf8_lossy(resource))
            .cloned();
        let dict = entry
            .as_ref()
            .and_then(|e| doc.resolve(e).ok())
            .and_then(|o| o.as_dict().cloned());
        let resource = if resource.is_empty() {
            b"Helv".to_vec()
        } else {
            resource.to_vec()
        };
        let found = match &dict {
            Some(d) => {
                let embedded = d
                    .get("FontDescriptor")
                    .and_then(|f| doc.resolve(f).ok())
                    .and_then(|f| f.as_dict().cloned())
                    .is_some_and(|f| {
                        ["FontFile", "FontFile2", "FontFile3"]
                            .iter()
                            .any(|k| f.get(k).is_some())
                    });
                let simple = d
                    .get("Subtype")
                    .is_some_and(|s| s.is_name("Type1") || s.is_name("TrueType"));
                match d.get("BaseFont") {
                    Some(Obj::Name(b)) if simple && !embedded => {
                        standard_name(&String::from_utf8_lossy(b)).map(|base| {
                            let win_ansi = d
                                .get("Encoding")
                                .is_some_and(|e| e.is_name("WinAnsiEncoding"));
                            let reuse = matches!(entry, Some(Obj::Ref(..)))
                                && (win_ansi || matches!(base, "Symbol" | "ZapfDingbats"));
                            (base, reuse.then(|| entry.clone().unwrap()))
                        })
                    }
                    _ => None,
                }
            }
            None => known_resource(&resource).map(|b| (b, None)),
        };
        let (base, reuse) = match found {
            Some((base, reuse)) if !matches!(base, "Symbol" | "ZapfDingbats") => (base, reuse),
            _ => {
                self.warn(format!(
                    "The form field \"{field}\" uses a font TrackMy Sign cannot draw with (embedded, or not a standard PDF font); its value is shown in Helvetica."
                ));
                ("Helvetica", None)
            }
        };
        let obj = match reuse {
            Some(r) => r,
            None => self.standard_font(base),
        };
        Font {
            resource,
            base,
            obj,
        }
    }

    fn text_bytes(&mut self, field: &str, s: &str) -> Vec<u8> {
        let (bytes, changed) = win_ansi(s);
        if changed {
            self.warn(format!(
                "The form's fonts cannot show every letter typed into \"{field}\": the value is stored as typed but shown as \"{}\".",
                transliterate(s).replace('\n', " ")
            ));
        }
        bytes
    }

    /// Text field or drop-down: the value in the widget's box.
    fn text_appearance(&mut self, n: &Node, w: &WidgetNode, value: &str) -> Obj {
        let frame = Frame::new(self.doc, w);
        let da = parse_da(widget_da(n, w));
        let font = self.font(&n.name, &da.font);
        let q = widget_q(self.doc, n, w);
        let pad = frame.padding();
        let bw = frame.border_width();
        let (fw, fh) = (frame.w, frame.h);
        let avail = (fw - 2.0 * pad).max(1.0);
        let shown: String = if n.kind == FieldKind::Text && n.ff & PASSWORD != 0 {
            "*".repeat(value.chars().count())
        } else {
            value.to_string()
        };
        let mut placed = Vec::new();
        let size;
        if n.multiline() {
            let paragraphs: Vec<Vec<u8>> = shown
                .split('\n')
                .map(|p| self.text_bytes(&n.name, p.trim_end_matches('\r')))
                .collect();
            let lay = |size: f64| -> Vec<Vec<u8>> {
                paragraphs
                    .iter()
                    .flat_map(|p| wrap(&font, size, p, avail))
                    .collect()
            };
            size = if da.size > 0.0 {
                da.size
            } else {
                let mut s = 12.0;
                while s > 4.0 && lay(s).len() as f64 * s * LEADING > fh - 2.0 * pad {
                    s -= 0.5;
                }
                s
            };
            for (i, line) in lay(size).into_iter().enumerate() {
                let tw = font.width(&line, size);
                placed.push(Placed {
                    x: align_x(q, pad, avail, tw),
                    y: fh - pad - size * (0.85 + i as f64 * LEADING),
                    bytes: line,
                });
            }
        } else {
            let one = shown.replace(['\r', '\n'], " ");
            let bytes = self.text_bytes(&n.name, &one);
            let cells = if n.comb() { n.max_len } else { None };
            size = if da.size > 0.0 {
                da.size
            } else {
                let by_height = ((fh - 2.0 * bw) / 1.35).max(1.0);
                let width = match cells {
                    Some(c) => {
                        bytes
                            .iter()
                            .map(|&b| font.width(&[b], 1.0))
                            .fold(0.0, f64::max)
                            * c as f64
                    }
                    None => font.width(&bytes, 1.0),
                };
                let room = if cells.is_some() { fw } else { avail };
                if width > 0.0 {
                    by_height.min(room / width).max(4.0)
                } else {
                    by_height
                }
            };
            let y = fh / 2.0 - 0.3 * size;
            match cells {
                Some(c) => {
                    let cell = fw / c as f64;
                    for (i, &b) in bytes.iter().take(c).enumerate() {
                        let cw = font.width(&[b], size);
                        placed.push(Placed {
                            x: i as f64 * cell + (cell - cw) / 2.0,
                            y,
                            bytes: vec![b],
                        });
                    }
                }
                None => {
                    let tw = font.width(&bytes, size);
                    placed.push(Placed {
                        x: align_x(q, pad, avail, tw),
                        y,
                        bytes,
                    });
                }
            }
        }
        let r = |v: f64| fmt_real(v);
        let mut s = String::from("/Tx BMC\nq\n");
        s += &frame.draw();
        s += &format!(
            "{} {} {} {} re W n\nBT\n/{} {} Tf\n{}\n",
            r(bw),
            r(bw),
            r(fw - 2.0 * bw),
            r(fh - 2.0 * bw),
            String::from_utf8_lossy(&font.resource),
            r(size),
            da.color
        );
        for p in placed.iter().filter(|p| !p.bytes.is_empty()) {
            s += &format!("1 0 0 1 {} {} Tm {} Tj\n", r(p.x), r(p.y), escape(&p.bytes));
        }
        s += "ET\nQ\nEMC\n";
        let resources = font_resources(&font);
        let ap = frame.stream(s, resources);
        self.add(ap)
    }

    /// List box: the options from the top index, chosen ones highlighted.
    fn list_appearance(&mut self, n: &Node, w: &WidgetNode, chosen: &[usize]) -> Obj {
        let frame = Frame::new(self.doc, w);
        let da = parse_da(widget_da(n, w));
        let font = self.font(&n.name, &da.font);
        let q = widget_q(self.doc, n, w);
        let size = if da.size > 0.0 { da.size } else { 12.0 };
        let (bw, pad) = (frame.border_width(), frame.padding());
        let (fw, fh) = (frame.w, frame.h);
        let avail = (fw - 2.0 * pad).max(1.0);
        let top = n.dict.get("TI").and_then(Obj::as_i64).unwrap_or(0).max(0) as usize;
        let row = size * LEADING;
        let r = |v: f64| fmt_real(v);
        let mut s = String::from("/Tx BMC\nq\n");
        s += &frame.draw();
        s += &format!(
            "{} {} {} {} re W n\n",
            r(bw),
            r(bw),
            r(fw - 2.0 * bw),
            r(fh - 2.0 * bw)
        );
        let options = n.options();
        let mut text = String::new();
        for (i, o) in options.iter().enumerate().skip(top) {
            let y_top = fh - bw - (i - top) as f64 * row;
            if y_top < bw {
                break;
            }
            if chosen.contains(&i) {
                s += &format!(
                    "0.6 0.75 0.86 rg\n{} {} {} {} re f\n",
                    r(bw),
                    r(y_top - row),
                    r(fw - 2.0 * bw),
                    r(row)
                );
            }
            let bytes = self.text_bytes(&n.name, &o.label);
            let tw = font.width(&bytes, size);
            text += &format!(
                "1 0 0 1 {} {} Tm {} Tj\n",
                r(align_x(q, pad, avail, tw)),
                r(y_top - row + (row - size) / 2.0 + 0.22 * size),
                escape(&bytes)
            );
        }
        s += &format!(
            "BT\n/{} {} Tf\n{}\n{text}ET\nQ\nEMC\n",
            String::from_utf8_lossy(&font.resource),
            r(size),
            da.color
        );
        let resources = font_resources(&font);
        let ap = frame.stream(s, resources);
        self.add(ap)
    }

    /// Normal appearances `{on, Off}` for a check box or radio button that
    /// has none: the `/MK /CA` mark (a tick, or a dot for radio buttons) in
    /// ZapfDingbats.
    fn button_appearance(&mut self, n: &Node, w: &WidgetNode, on: &[u8]) -> Obj {
        let frame = Frame::new(self.doc, w);
        let da = parse_da(widget_da(n, w));
        let mark = w
            .dict
            .get("MK")
            .and_then(|m| self.doc.resolve(m).ok())
            .and_then(|m| match m.as_dict()?.get("CA")? {
                Obj::Str(s) => s.first().copied(),
                _ => None,
            })
            .unwrap_or(if n.kind == FieldKind::Radio {
                b'l'
            } else {
                b'4'
            });
        let side = frame.w.min(frame.h) - 2.0 * frame.border_width();
        let size = if da.size > 0.0 { da.size } else { side * 0.8 };
        let gw = dingbat_width(mark) * size / 1000.0;
        let r = |v: f64| fmt_real(v);
        let color = if da.color.is_empty() {
            "0 g".to_string()
        } else {
            da.color.clone()
        };
        let on_content = format!(
            "q\n{}BT\n/ZaDb {} Tf\n{color}\n1 0 0 1 {} {} Tm {} Tj\nET\nQ\n",
            frame.draw(),
            r(size),
            r((frame.w - gw) / 2.0),
            r((frame.h - 0.7 * size) / 2.0),
            escape(&[mark])
        );
        let zadb = self.standard_font("ZapfDingbats");
        let resources = Dict::new().with("Font", Obj::Dict(Dict::new().with("ZaDb", zadb)));
        let on_ap = self.add(frame.stream(on_content, resources));
        let off_ap = self.add(frame.stream(format!("q\n{}Q\n", frame.draw()), Dict::new()));
        let mut states = Dict::new();
        states.0.push((on.to_vec(), on_ap));
        states.set("Off", off_ap);
        Obj::Dict(Dict::new().with("N", Obj::Dict(states)))
    }

    fn set(&mut self, n: &Node, values: &[String], signed: bool) -> Result<()> {
        let refuse = |what: String| {
            Err(PdfError::Form(format!(
                "The form field \"{}\" {what}",
                n.name
            )))
        };
        let single = || -> Result<String> {
            match values {
                [] => Ok(String::new()),
                [v] => Ok(v.clone()),
                _ => Err(PdfError::Form(format!(
                    "The form field \"{}\" takes one value, not {}.",
                    n.name,
                    values.len()
                ))),
            }
        };
        match n.kind {
            FieldKind::Text => {
                let v = single()?;
                if let Some(max) = n.max_len
                    && v.chars().count() > max
                {
                    return refuse(format!("takes at most {max} characters."));
                }
                let v = if n.multiline() {
                    v.replace("\r\n", "\n")
                } else {
                    v.replace(['\r', '\n'], " ")
                };
                self.edit(n.id, &n.dict, |d| d.set("V", text_string(&v)));
                for w in &n.widgets {
                    let ap = self.text_appearance(n, w, &v);
                    self.edit(w.id, &w.dict, |d| {
                        d.set("AP", Obj::Dict(Dict::new().with("N", ap)))
                    });
                }
            }
            FieldKind::Checkbox | FieldKind::Radio => {
                let v = single()?;
                let doc = self.doc;
                let exports: Vec<Option<String>> =
                    (0..n.widgets.len()).map(|i| n.export(doc, i)).collect();
                // On-state name of each widget; one without appearances
                // takes its position (with /Opt) or "Yes".
                let states: Vec<Vec<u8>> = n
                    .widgets
                    .iter()
                    .enumerate()
                    .map(|(i, w)| {
                        on_state(doc, w).unwrap_or_else(|| {
                            if n.opt.is_empty() {
                                b"Yes".to_vec()
                            } else {
                                i.to_string().into_bytes()
                            }
                        })
                    })
                    .collect();
                let off = matches!(
                    v.to_ascii_lowercase().as_str(),
                    "" | "off" | "false" | "no" | "0" | "unchecked"
                );
                let on_word = matches!(
                    v.to_ascii_lowercase().as_str(),
                    "on" | "true" | "yes" | "1" | "checked" | "x"
                );
                let matched = exports
                    .iter()
                    .position(|e| e.as_deref() == Some(v.as_str()))
                    .or_else(|| {
                        exports
                            .iter()
                            .position(|e| e.as_ref().is_some_and(|e| e.eq_ignore_ascii_case(&v)))
                    });
                let distinct: HashSet<&Vec<u8>> = states.iter().collect();
                let state = match matched {
                    Some(i) => Some(states[i].clone()),
                    None if off => None,
                    None if on_word && n.kind == FieldKind::Checkbox && distinct.len() == 1 => {
                        Some(states[0].clone())
                    }
                    None => {
                        let mut choices: Vec<String> = exports.iter().flatten().cloned().collect();
                        choices.dedup();
                        choices.push("Off".into());
                        return refuse(format!(
                            "is a {}; use {}.",
                            n.kind.label(),
                            choices
                                .iter()
                                .map(|c| format!("\"{c}\""))
                                .collect::<Vec<_>>()
                                .join(" or ")
                        ));
                    }
                };
                let v_name = Obj::Name(state.clone().unwrap_or_else(|| b"Off".to_vec()));
                self.edit(n.id, &n.dict, |d| d.set("V", v_name));
                for (w, own) in n.widgets.iter().zip(&states) {
                    let shown = if state.as_ref() == Some(own) {
                        own.clone()
                    } else {
                        b"Off".to_vec()
                    };
                    let ap =
                        (on_state(doc, w).is_none()).then(|| self.button_appearance(n, w, own));
                    self.edit(w.id, &w.dict, |d| {
                        d.set("AS", Obj::Name(shown));
                        if let Some(ap) = ap {
                            d.set("AP", ap);
                        }
                    });
                }
            }
            FieldKind::Combo | FieldKind::List => {
                let options = n.options();
                let mut chosen = Vec::new();
                let mut stored = Vec::new();
                let editable = n.kind == FieldKind::Combo && n.ff & EDIT != 0;
                let list = values.iter().filter(|v| !v.is_empty()).collect::<Vec<_>>();
                if list.len() > 1 && !(n.kind == FieldKind::List && n.ff & MULTI_SELECT != 0) {
                    return refuse("takes one choice.".into());
                }
                for v in list {
                    match options
                        .iter()
                        .position(|o| &o.value == v)
                        .or_else(|| options.iter().position(|o| &o.label == v))
                    {
                        Some(i) => {
                            chosen.push(i);
                            stored.push(options[i].value.clone());
                        }
                        None if editable => stored.push(v.clone()),
                        None => {
                            return refuse(format!(
                                "has no choice \"{v}\". Choices: {}.",
                                options
                                    .iter()
                                    .map(|o| format!("\"{}\"", o.value))
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            ));
                        }
                    }
                }
                chosen.sort_unstable();
                let v_obj = match stored.as_slice() {
                    [] => Obj::Str(Vec::new()),
                    [one] => text_string(one),
                    many => Obj::Array(many.iter().map(|s| text_string(s)).collect()),
                };
                // Only touched before the first signature: validators count a
                // changed /I as more than filling in the form.
                let indices = (n.kind == FieldKind::List
                    && !signed
                    && (n.ff & MULTI_SELECT != 0 || n.dict.get("I").is_some()))
                .then(|| Obj::Array(chosen.iter().map(|&i| Obj::int(i as i64)).collect()));
                self.edit(n.id, &n.dict, |d| {
                    d.set("V", v_obj);
                    if let Some(i) = indices {
                        d.set("I", i);
                    }
                });
                let shown = match chosen.first() {
                    Some(&i) => options[i].label.clone(),
                    None => stored.first().cloned().unwrap_or_default(),
                };
                for w in &n.widgets {
                    let ap = if n.kind == FieldKind::List {
                        self.list_appearance(n, w, &chosen)
                    } else {
                        self.text_appearance(n, w, &shown)
                    };
                    self.edit(w.id, &w.dict, |d| {
                        d.set("AP", Obj::Dict(Dict::new().with("N", ap)))
                    });
                }
            }
        }
        Ok(())
    }
}

fn align_x(q: i64, pad: f64, avail: f64, tw: f64) -> f64 {
    match q {
        1 => pad + (avail - tw) / 2.0,
        2 => pad + avail - tw,
        _ => pad,
    }
    .max(pad.min(pad + avail - tw))
}

fn font_resources(font: &Font) -> Dict {
    let mut fonts = Dict::new();
    fonts.0.push((font.resource.clone(), font.obj.clone()));
    Dict::new().with("Font", Obj::Dict(fonts))
}

/// Fills in `values` as an incremental update and returns the new file.
/// Fields locked by an existing signature are refused unless `break_locks`
/// (that signature will no longer be valid).
pub fn fill(
    input: &[u8],
    password: Option<&str>,
    values: &[FillValue],
    break_locks: bool,
) -> Result<Filled> {
    let doc = Document::open(input, password)?;
    let af = acroform(&doc)?.unwrap_or_default();
    let pages = doc.pages()?;
    let nodes = nodes(&doc, &pages, &af)?;
    if let Some(why) = blocked(&doc, &af, !nodes.is_empty())? {
        return Err(PdfError::Form(why));
    }
    if values.is_empty() {
        return Ok(Filled {
            data: input.to_vec(),
            warnings: Vec::new(),
        });
    }
    let locks = signature_locks(&doc, &pages)?;
    let signed = signature_fields(&doc, &pages)?.iter().any(|f| f.signed);
    let dr_fonts = af
        .get("DR")
        .and_then(|d| doc.resolve(d).ok())
        .and_then(|d| d.as_dict()?.get("Font").cloned())
        .and_then(|f| doc.resolve(&f).ok())
        .and_then(|f| f.as_dict().cloned())
        .unwrap_or_default();
    let mut up = Update {
        doc: &doc,
        dr_fonts,
        objs: BTreeMap::new(),
        next: doc.next_object_id(),
        fonts: HashMap::new(),
        warnings: Vec::new(),
    };
    for v in values {
        let Some(n) = nodes.iter().find(|n| n.name == v.name) else {
            let mut names: Vec<&str> = nodes.iter().map(|n| n.name.as_str()).collect();
            let more = names.len() > 20;
            names.truncate(20);
            return Err(PdfError::Form(if names.is_empty() {
                format!(
                    "There is no form field \"{}\"; this PDF has no fields to fill in.",
                    v.name
                )
            } else {
                format!(
                    "There is no form field \"{}\". Fields: {}{}.",
                    v.name,
                    names.join(", "),
                    if more { ", …" } else { "" }
                )
            }));
        };
        if n.read_only() {
            return Err(PdfError::Form(format!(
                "The form field \"{}\" is read-only.",
                n.name
            )));
        }
        if !break_locks && let Some((sig, _)) = locks.iter().find(|(_, l)| l.covers(&n.name)) {
            return Err(PdfError::Form(format!(
                "The form field \"{}\" is locked by the signature \"{sig}\": filling it in would invalidate that signature.",
                n.name
            )));
        }
        up.set(n, &v.value, signed)?;
    }

    // --- AcroForm: we drew the appearances ---------------------------------
    let mut af_new = af.clone();
    if af
        .get("NeedAppearances")
        .and_then(|v| doc.resolve(v).ok())
        .is_some_and(|v| v == Obj::Bool(true))
    {
        af_new.set("NeedAppearances", Obj::Bool(false));
    }
    if af.get("XFA").is_some() {
        if signed {
            up.warn(
                "This PDF also has an XFA version of the form, which is not updated; some readers may show that one instead."
                    .into(),
            );
        } else {
            // Readers that prefer XFA would show the old values.
            af_new.remove("XFA");
            up.warn(
                "This PDF also had an XFA version of the form; it was removed so readers show the filled-in fields."
                    .into(),
            );
        }
    }
    if af_new != af {
        let mut catalog = doc.catalog()?;
        match catalog.get("AcroForm") {
            Some(Obj::Ref(id, gn)) => {
                up.objs.insert(*id, (*gn, Obj::Dict(af_new)));
            }
            _ => {
                catalog.set("AcroForm", Obj::Dict(af_new));
                let (id, gn) = doc.catalog_ref()?;
                up.objs.insert(id, (gn, Obj::Dict(catalog)));
            }
        }
    }
    let data = append_update(&doc, &up.objs, up.next)?;
    Ok(Filled {
        data,
        warnings: up.warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A one-page form: text (auto size, centred), multiline, comb, check
    /// box, radio pair, drop-down, list, read-only and nested fields.
    fn form_pdf(extra_af: &str) -> Vec<u8> {
        let objs: Vec<String> = vec![
            format!(
                "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [5 0 R 6 0 R 7 0 R 8 0 R 9 0 R 12 0 R 13 0 R 14 0 R 15 0 R] /DA (/Helv 0 Tf 0 g) /DR << /Font << /Helv 4 0 R /ZaDb 18 0 R >> >> {extra_af}>> >>"
            ),
            "<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 600 800] >>".into(),
            "<< /Type /Page /Parent 2 0 R /Annots [5 0 R 6 0 R 7 0 R 8 0 R 10 0 R 11 0 R 12 0 R 13 0 R 14 0 R 17 0 R] >>".into(),
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>".into(),
            "<< /Type /Annot /Subtype /Widget /FT /Tx /T (name) /TU (Full name) /Q 1 /Rect [50 700 250 720] /F 4 /P 3 0 R /Ff 2 /MK << /BC [0 0 1] >> >>".into(),
            "<< /Type /Annot /Subtype /Widget /FT /Tx /T (address) /DA (/Helv 10 Tf 1 0 0 rg) /Ff 4096 /Rect [50 600 250 680] /P 3 0 R >>".into(),
            "<< /Type /Annot /Subtype /Widget /FT /Tx /T (pin) /MaxLen 6 /Ff 16777216 /Rect [50 560 170 580] /P 3 0 R >>".into(),
            "<< /Type /Annot /Subtype /Widget /FT /Btn /T (agree) /Rect [50 520 64 534] /P 3 0 R /MK << /CA (4) >> >>".into(),
            "<< /FT /Btn /T (gender) /Ff 49152 /Kids [10 0 R 11 0 R] /V /Off >>".into(),
            "<< /Type /Annot /Subtype /Widget /Parent 9 0 R /Rect [50 480 64 494] /P 3 0 R /AP << /N << /M 16 0 R /Off 16 0 R >> >> /AS /Off >>".into(),
            "<< /Type /Annot /Subtype /Widget /Parent 9 0 R /Rect [80 480 94 494] /P 3 0 R /AP << /N << /F 16 0 R /Off 16 0 R >> >> /AS /Off >>".into(),
            "<< /Type /Annot /Subtype /Widget /FT /Ch /Ff 131072 /T (state) /Opt [[(TN) (Tamil Nadu)] [(KA) (Karnataka)]] /Rect [50 440 200 460] /P 3 0 R >>".into(),
            "<< /Type /Annot /Subtype /Widget /FT /Ch /Ff 2097152 /T (langs) /Opt [(Hindi) (Tamil) (English)] /Rect [50 360 200 420] /P 3 0 R >>".into(),
            "<< /Type /Annot /Subtype /Widget /FT /Tx /T (ref) /Ff 1 /V (R-1) /Rect [300 700 400 720] /P 3 0 R >>".into(),
            "<< /T (applicant) /Kids [17 0 R] >>".into(),
            "<< /Length 0 >>\nstream\n\nendstream".into(),
            "<< /Type /Annot /Subtype /Widget /FT /Tx /T (city) /Parent 15 0 R /Rect [300 600 400 620] /P 3 0 R >>".into(),
            "<< /Type /Font /Subtype /Type1 /BaseFont /ZapfDingbats >>".into(),
        ];
        let mut out = b"%PDF-1.7\n".to_vec();
        let mut offsets = Vec::new();
        for (i, o) in objs.iter().enumerate() {
            offsets.push(out.len());
            out.extend_from_slice(format!("{} 0 obj\n{o}\nendobj\n", i + 1).as_bytes());
        }
        let xref = out.len();
        out.extend_from_slice(
            format!("xref\n0 {}\n0000000000 65535 f\r\n", objs.len() + 1).as_bytes(),
        );
        for o in offsets {
            out.extend_from_slice(format!("{o:010} 00000 n\r\n").as_bytes());
        }
        out.extend_from_slice(
            format!(
                "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
                objs.len() + 1
            )
            .as_bytes(),
        );
        out
    }

    fn set(name: &str, v: &[&str]) -> FillValue {
        FillValue {
            name: name.into(),
            value: v.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn field<'f>(form: &'f Form, name: &str) -> &'f FormField {
        form.fields.iter().find(|f| f.name == name).unwrap()
    }

    #[test]
    fn lists_fields() {
        let pdf = form_pdf("");
        let form = read(&Document::parse(&pdf).unwrap()).unwrap();
        let names: Vec<&str> = form.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "name",
                "address",
                "pin",
                "agree",
                "gender",
                "state",
                "langs",
                "ref",
                "applicant.city"
            ]
        );
        let name = field(&form, "name");
        assert!(name.required && !name.read_only);
        assert_eq!(name.label.as_deref(), Some("Full name"));
        assert_eq!(name.widgets[0].align, 1);
        let r = name.widgets[0].rect.unwrap();
        assert_eq!((r.x, r.y, r.w, r.h), (50.0, 80.0, 200.0, 20.0));
        assert!(field(&form, "address").multiline);
        let pin = field(&form, "pin");
        assert!(pin.comb && pin.max_len == Some(6));
        assert_eq!(field(&form, "agree").kind, FieldKind::Checkbox);
        let gender = field(&form, "gender");
        assert_eq!(gender.kind, FieldKind::Radio);
        assert_eq!(
            gender
                .options
                .iter()
                .map(|o| o.value.as_str())
                .collect::<Vec<_>>(),
            ["M", "F"]
        );
        let state = field(&form, "state");
        assert_eq!(state.kind, FieldKind::Combo);
        assert_eq!(state.options[0].label, "Tamil Nadu");
        assert!(field(&form, "langs").multi_select);
        let r = field(&form, "ref");
        assert!(r.read_only && r.value == ["R-1"]);
        assert!(form.blocked.is_none() && !form.xfa);
    }

    #[test]
    fn fills_and_draws() {
        let pdf = form_pdf("/NeedAppearances true ");
        let filled = fill(
            &pdf,
            None,
            &[
                set("name", &["Rahul DK"]),
                set("address", &["12 Anna Salai\nChennai 600002"]),
                set("pin", &["600002"]),
                set("agree", &["true"]),
                set("gender", &["F"]),
                set("state", &["Karnataka"]),
                set("langs", &["Tamil", "English"]),
                set("applicant.city", &["Chennai"]),
            ],
            false,
        )
        .unwrap();
        assert!(filled.data.starts_with(&pdf));
        assert!(filled.warnings.is_empty(), "{:?}", filled.warnings);
        let doc = Document::parse(&filled.data).unwrap();
        assert!(!doc.repaired);
        let form = read(&doc).unwrap();
        let values = |n: &str| field(&form, n).value.clone();
        assert_eq!(values("name"), ["Rahul DK"]);
        assert_eq!(values("address"), ["12 Anna Salai\nChennai 600002"]);
        assert_eq!(values("agree"), ["Yes"]);
        assert_eq!(values("gender"), ["F"]);
        assert_eq!(values("state"), ["KA"]);
        assert_eq!(values("langs"), ["Tamil", "English"]);
        assert_eq!(values("applicant.city"), ["Chennai"]);
        let af = acroform(&doc).unwrap().unwrap();
        assert_eq!(af.get("NeedAppearances"), Some(&Obj::Bool(false)));

        let ap = |id: u32| -> String {
            let w = doc.get(id).unwrap();
            let n = doc
                .resolve(w.as_dict().unwrap().get("AP").unwrap())
                .unwrap()
                .as_dict()
                .unwrap()
                .get("N")
                .cloned()
                .unwrap();
            match doc.resolve(&n).unwrap() {
                Obj::Stream(_, data) => String::from_utf8_lossy(&data).into_owned(),
                _ => panic!(),
            }
        };
        // Auto size from the height, centred, the DR font reused.
        let name = ap(5);
        assert!(
            name.contains("/Helv 13.3333 Tf") && name.contains("(Rahul DK) Tj"),
            "{name}"
        );
        assert!(name.contains("0 0 1 RG"));
        let address = ap(6);
        assert!(
            address.contains("/Helv 10 Tf\n1 0 0 rg") && address.contains("(Chennai 600002) Tj")
        );
        // One character per comb cell, 20 pt apart.
        let pin = ap(7);
        assert_eq!(pin.matches(" Tj").count(), 6);
        assert!(
            pin.contains("1 0 0 1 25.") && pin.contains("1 0 0 1 105."),
            "{pin}"
        );
        assert!(ap(13).contains("0.6 0.75 0.86 rg"));
        // The check box had no appearance: a tick is drawn.
        let agree = doc.get(8).unwrap();
        let agree = agree.as_dict().unwrap();
        assert!(agree.get("AS").unwrap().is_name("Yes"));
        assert!(agree.get("V").unwrap().is_name("Yes"));
        for (id, state) in [(10, "Off"), (11, "F")] {
            assert!(
                doc.get(id)
                    .unwrap()
                    .as_dict()
                    .unwrap()
                    .get("AS")
                    .unwrap()
                    .is_name(state)
            );
        }
        assert!(
            doc.get(9)
                .unwrap()
                .as_dict()
                .unwrap()
                .get("V")
                .unwrap()
                .is_name("F")
        );
    }

    #[test]
    fn refusals() {
        let pdf = form_pdf("");
        let err = |v: FillValue| fill(&pdf, None, &[v], false).err().unwrap().to_string();
        assert!(err(set("ref", &["X"])).contains("read-only"));
        assert!(err(set("pin", &["1234567"])).contains("at most 6 characters"));
        assert!(err(set("state", &["Goa"])).contains("Choices: \"TN\", \"KA\""));
        assert!(err(set("gender", &["X"])).contains("\"M\" or \"F\" or \"Off\""));
        assert!(
            err(set("nope", &["X"])).contains("There is no form field \"nope\". Fields: name,")
        );
        assert!(err(set("name", &["a", "b"])).contains("takes one value"));
        let xfa = form_pdf("/XFA 16 0 R ");
        let form = read(&Document::parse(&xfa).unwrap()).unwrap();
        assert!(form.xfa && form.blocked.is_none());
    }

    /// Filled in, then new signature fields added (as the app does before
    /// signing one of them): both updates keep the other's changes.
    #[test]
    fn fields_added_after_filling() {
        use crate::pdf::addfields::NewField;
        let pdf = form_pdf("");
        let filled = fill(&pdf, None, &[set("name", &["Rahul DK"])], false).unwrap();
        let both = crate::add_signature_fields(
            &filled.data,
            None,
            &[NewField {
                name: "Director".into(),
                page: 0,
                rect: DisplayRect {
                    x: 300.0,
                    y: 600.0,
                    w: 200.0,
                    h: 60.0,
                },
                tooltip: None,
                order: None,
                lock: None,
                seed: false,
            }],
        )
        .unwrap();
        assert!(both.starts_with(&filled.data));
        let doc = Document::parse(&both).unwrap();
        assert_eq!(field(&read(&doc).unwrap(), "name").value, ["Rahul DK"]);
        let sigs = signature_fields(&doc, &doc.pages().unwrap()).unwrap();
        assert!(sigs.iter().any(|f| f.name == "Director" && !f.signed));
    }

    #[test]
    fn transliterates_with_a_warning() {
        let pdf = form_pdf("");
        let filled = fill(&pdf, None, &[set("name", &["रमेश"])], false).unwrap();
        assert_eq!(filled.warnings.len(), 1);
        assert!(filled.warnings[0].contains("\"Ramesha\""));
        let doc = Document::parse(&filled.data).unwrap();
        assert_eq!(field(&read(&doc).unwrap(), "name").value, ["रमेश"]);
    }

    #[test]
    fn default_appearance() {
        let da = parse_da(b"/Helv 0 Tf 0.2 0.4 0.6 rg");
        assert_eq!(da.font, b"Helv");
        assert_eq!(da.size, 0.0);
        assert_eq!(da.color, "0.2 0.4 0.6 rg");
        let da = parse_da(b"0 g /TiBo 9.5 Tf");
        assert_eq!(
            (da.font.as_slice(), da.size, da.color.as_str()),
            (&b"TiBo"[..], 9.5, "0 g")
        );
        assert_eq!(standard_name("ArialMT"), Some("Helvetica"));
        assert_eq!(
            standard_name("Arial,BoldItalic"),
            Some("Helvetica-BoldOblique")
        );
        assert_eq!(standard_name("TimesNewRomanPS-BoldMT"), Some("Times-Bold"));
        assert_eq!(standard_name("Calibri"), None);
    }
}
