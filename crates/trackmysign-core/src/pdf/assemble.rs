//! Builds a new PDF from pages of one or more PDFs — merge, reorder, rotate,
//! delete, insert blank pages — to prepare a document before it is signed.
//! The sources are only read; the result is a new, unencrypted file with a
//! classic cross-reference table.
//!
//! Everything a kept page uses (contents, resources, fonts, images,
//! annotations, form fields) is copied under new object numbers, and what it
//! inherits from the page tree is written on the page itself. Stream data is
//! copied as it is, still compressed. Signatures cannot survive this (the
//! bytes they cover change), so signed signature fields are left out.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use chrono::Local;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::fields::{signature_fields, text};
use super::object::{Dict, Obj, write_obj};
use super::reader::{Document, PageInfo, PdfError, Result, XrefEntry};
use super::sign::{pdf_date, text_string, write_xref_table};

/// One page of the new document.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Item {
    /// Page `page` (zero-based) of source `source`, turned clockwise by
    /// `rotate` degrees (a multiple of 90) on top of its own rotation.
    Page {
        source: usize,
        page: usize,
        #[serde(default)]
        rotate: i32,
    },
    /// An empty page, size in points.
    Blank { width: f64, height: f64 },
}

/// Something about the new file the user should know.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Notice {
    /// The source is signed: the new file has none of its signatures.
    SignaturesRemoved { source: usize, count: usize },
    /// The source is password-protected: the new file is not.
    PasswordRemoved { source: usize },
    /// The source has bookmarks; they are not carried over.
    BookmarksDropped { source: usize },
    /// A form field had the name of one already in the new file.
    FieldRenamed { from: String, to: String },
}

impl Notice {
    /// English text; `names` are the sources' file names.
    pub fn describe(&self, names: &[String]) -> String {
        let name = |i: &usize| names.get(*i).map_or("a source PDF", String::as_str);
        match self {
            Notice::SignaturesRemoved { source, count } => format!(
                "{} has {count} signature{}. The new file will not contain {}: \
                 changing pages always breaks existing signatures. Use it only \
                 to prepare a document for signing.",
                name(source),
                if *count == 1 { "" } else { "s" },
                if *count == 1 { "it" } else { "them" },
            ),
            Notice::PasswordRemoved { source } => format!(
                "{} is password-protected; the new file will open without a password.",
                name(source)
            ),
            Notice::BookmarksDropped { source } => {
                format!("The bookmarks of {} are not carried over.", name(source))
            }
            Notice::FieldRenamed { from, to } => {
                format!("Form field \"{from}\" was renamed \"{to}\": the name was taken.")
            }
        }
    }
}

pub struct Assembled {
    pub data: Vec<u8>,
    pub notices: Vec<Notice>,
}

/// Opens a source PDF, refusing one whose security settings do not allow
/// changing its pages unless the owner password was given.
pub fn open<'a>(data: &'a [u8], password: Option<&str>) -> Result<Document<'a>> {
    let doc = Document::open(data, password)?;
    if doc.crypt.as_ref().is_some_and(|c| !c.may_assemble()) {
        return Err(PdfError::AssemblyNotAllowed);
    }
    Ok(doc)
}

/// What using `doc` as source number `source` will lose: its signatures,
/// its password, its bookmarks.
pub fn notices(source: usize, doc: &Document) -> Result<Vec<Notice>> {
    let pages = doc.pages()?;
    let mut out = Vec::new();
    let count = signature_fields(doc, &pages)?
        .iter()
        .filter(|f| f.signed)
        .count();
    if count > 0 {
        out.push(Notice::SignaturesRemoved { source, count });
    }
    if doc.crypt.is_some() {
        out.push(Notice::PasswordRemoved { source });
    }
    let outlines = match doc.catalog()?.get("Outlines") {
        Some(o) => doc.resolve(o)?,
        None => Obj::Null,
    };
    if outlines.as_dict().is_some_and(|d| d.get("First").is_some()) {
        out.push(Notice::BookmarksDropped { source });
    }
    Ok(out)
}

/// Writes a new PDF with `items` as its pages, in order.
pub fn assemble(docs: &[Document], items: &[Item]) -> Result<Assembled> {
    if items.is_empty() {
        return Err(PdfError::Pages(
            "the new PDF needs at least one page".into(),
        ));
    }
    let mut sources = docs.iter().map(Source::new).collect::<Result<Vec<_>>>()?;

    // Number the pages first: links and annotations point at them.
    // 1 is the catalog, 2 the page tree.
    let mut next = 3;
    let mut page_ids = Vec::with_capacity(items.len());
    for item in items {
        match *item {
            Item::Page {
                source,
                page,
                rotate,
            } => {
                let s = sources
                    .get_mut(source)
                    .ok_or_else(|| PdfError::Pages(format!("no source PDF {}", source + 1)))?;
                let old = s
                    .pages
                    .get(page)
                    .ok_or(PdfError::NoSuchPage(page + 1))?
                    .id
                    .0;
                if rotate % 90 != 0 {
                    return Err(PdfError::Pages(format!(
                        "pages turn by multiples of 90 degrees, not {rotate}"
                    )));
                }
                let id = take(&mut next);
                s.placed.entry(old).or_insert(id);
                page_ids.push(id);
            }
            Item::Blank { width, height } => {
                let ok = |v: f64| v.is_finite() && (3.0..=14400.0).contains(&v);
                if !ok(width) || !ok(height) {
                    return Err(PdfError::Pages(format!(
                        "a blank page of {width} x {height} pt is not possible"
                    )));
                }
                page_ids.push(take(&mut next));
            }
        }
    }

    // Form fields that come along: those with a widget on a kept page.
    for s in &mut sources {
        s.find_fields()?;
    }
    let mut notices = Vec::new();
    let mut names: HashSet<Vec<u8>> = HashSet::new();
    for s in &mut sources {
        for &top in &s.tops {
            let Some(Obj::Str(t)) = s.doc.get(top)?.as_dict().and_then(|d| d.get("T")).cloned()
            else {
                continue;
            };
            if names.insert(t.clone()) {
                continue;
            }
            let from = text(&t);
            let (to, bytes) = (2..)
                .map(|n| format!("{from}_{n}"))
                .map(|to| {
                    let Obj::Str(b) = text_string(&to) else {
                        unreachable!()
                    };
                    (to, b)
                })
                .find(|(_, b)| !names.contains(b))
                .unwrap();
            names.insert(bytes.clone());
            s.renamed.insert(top, bytes);
            notices.push(Notice::FieldRenamed { from, to });
        }
    }

    let mut objs: BTreeMap<u32, Obj> = BTreeMap::new();
    for (item, &id) in items.iter().zip(&page_ids) {
        let page = match *item {
            Item::Page {
                source,
                page,
                rotate,
            } => sources[source].page(page, id, rotate, &mut objs, &mut next)?,
            Item::Blank { width, height } => Dict::new()
                .with("Type", Obj::name("Page"))
                .with(
                    "MediaBox",
                    Obj::Array(vec![
                        Obj::int(0),
                        Obj::int(0),
                        Obj::real(width),
                        Obj::real(height),
                    ]),
                )
                .with("Resources", Obj::Dict(Dict::new())),
        };
        objs.insert(id, Obj::Dict(page.with("Parent", Obj::Ref(2, 0))));
    }

    let acroform = acroform(&mut sources, &mut next)?;
    for s in &mut sources {
        s.drain(&mut objs, &mut next)?;
    }

    let mut catalog = Dict::new()
        .with("Type", Obj::name("Catalog"))
        .with("Pages", Obj::Ref(2, 0));
    if let Some(af) = acroform {
        catalog.set("AcroForm", Obj::Dict(af));
    }
    objs.insert(1, Obj::Dict(catalog));
    objs.insert(
        2,
        Obj::Dict(
            Dict::new()
                .with("Type", Obj::name("Pages"))
                .with(
                    "Kids",
                    Obj::Array(page_ids.iter().map(|&id| Obj::Ref(id, 0)).collect()),
                )
                .with("Count", Obj::int(page_ids.len() as i64)),
        ),
    );
    let info = take(&mut next);
    let now = pdf_date(&Local::now().fixed_offset());
    objs.insert(
        info,
        Obj::Dict(
            Dict::new()
                .with("Producer", Obj::str("TrackMySign"))
                .with("CreationDate", Obj::str(&now))
                .with("ModDate", Obj::str(&now)),
        ),
    );

    let used: HashSet<usize> = items
        .iter()
        .filter_map(|i| match i {
            Item::Page { source, .. } => Some(*source),
            Item::Blank { .. } => None,
        })
        .collect();
    let mut lost = Vec::new();
    for (i, doc) in docs.iter().enumerate() {
        if used.contains(&i) {
            lost.extend(self::notices(i, doc)?);
        }
    }
    lost.extend(notices);

    Ok(Assembled {
        data: write(&objs, next, info),
        notices: lost,
    })
}

fn take(next: &mut u32) -> u32 {
    let id = *next;
    *next += 1;
    id
}

/// The file: header, objects in order, a full cross-reference table.
fn write(objs: &BTreeMap<u32, Obj>, size: u32, info: u32) -> Vec<u8> {
    let mut out = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n".to_vec();
    let mut entries = BTreeMap::new();
    for (id, obj) in objs {
        entries.insert(*id, XrefEntry::Offset(out.len(), 0));
        out.extend_from_slice(format!("{id} 0 obj\n").as_bytes());
        write_obj(&mut out, obj);
        out.extend_from_slice(b"\nendobj\n");
    }
    let file_id = Obj::Str(Sha256::digest(&out)[..16].to_vec());
    let trailer = Dict::new()
        .with("Root", Obj::Ref(1, 0))
        .with("Info", Obj::Ref(info, 0))
        .with("ID", Obj::Array(vec![file_id.clone(), file_id]));
    let xref = out.len();
    write_xref_table(&mut out, &entries, size, trailer, true);
    out.extend_from_slice(format!("startxref\n{xref}\n%%EOF\n").as_bytes());
    out
}

/// The new `/AcroForm`: the fields that came along, the first source's
/// default appearance, the sources' default resources merged.
fn acroform(sources: &mut [Source], next: &mut u32) -> Result<Option<Dict>> {
    let mut fields = Vec::new();
    let mut da = None;
    let mut dr = Dict::new();
    let mut need_appearances = false;
    for s in sources.iter_mut().filter(|s| !s.tops.is_empty()) {
        for top in s.tops.clone() {
            fields.push(s.copy_ref(top, next));
        }
        let af = match s.doc.catalog()?.get("AcroForm") {
            Some(af) => s.doc.resolve(af)?,
            None => continue,
        };
        let Some(af) = af.as_dict() else { continue };
        if da.is_none() {
            da = af.get("DA").map(|v| s.copy(v, next));
        }
        if af
            .get("NeedAppearances")
            .is_some_and(|v| *v == Obj::Bool(true))
        {
            need_appearances = true;
        }
        let Some(res) = af.get("DR") else { continue };
        let res = s.doc.resolve(res)?;
        for (k, v) in res.as_dict().map(|d| d.0.clone()).unwrap_or_default() {
            // Same-named fonts are almost always the same font; the first one stays.
            let v = s.doc.resolve(&v)?;
            let have = dr.0.iter().position(|(key, _)| *key == k);
            match (v, have) {
                (Obj::Dict(sub), Some(i)) => {
                    for (name, val) in sub.0 {
                        let Obj::Dict(have) = &dr.0[i].1 else { break };
                        if !have.0.iter().any(|(n, _)| *n == name) {
                            let val = s.copy(&val, next);
                            if let Obj::Dict(have) = &mut dr.0[i].1 {
                                have.0.push((name, val));
                            }
                        }
                    }
                }
                (_, Some(_)) => {}
                (v, None) => {
                    let v = s.copy(&v, next);
                    dr.0.push((k, v));
                }
            }
        }
    }
    if fields.is_empty() {
        return Ok(None);
    }
    let mut af = Dict::new().with("Fields", Obj::Array(fields));
    if let Some(da) = da {
        af.set("DA", da);
    }
    if !dr.0.is_empty() {
        af.set("DR", Obj::Dict(dr));
    }
    if need_appearances {
        af.set("NeedAppearances", Obj::Bool(true));
    }
    Ok(Some(af))
}

/// One source PDF and what has been copied from it.
struct Source<'d, 'a> {
    doc: &'d Document<'a>,
    pages: Vec<PageInfo>,
    /// Old page id to new, for the first time the page is used.
    placed: HashMap<u32, u32>,
    /// The catalog, the page tree and every page: never followed by a
    /// reference (a page that is kept is reached through `placed`).
    tree: HashSet<u32>,
    /// Old object id to new, for everything else.
    map: HashMap<u32, u32>,
    /// Copied ids whose objects still have to be written.
    queue: Vec<(u32, u32)>,
    /// Widgets and fields of signed signature fields: left out.
    signed: HashSet<u32>,
    /// Kept widgets and the fields above them: only these stay in a `/Kids`.
    form: HashSet<u32>,
    /// Top-level fields that come along, in page order.
    tops: Vec<u32>,
    /// New `/T` for top-level fields whose name was taken.
    renamed: HashMap<u32, Vec<u8>>,
}

impl<'d, 'a> Source<'d, 'a> {
    fn new(doc: &'d Document<'a>) -> Result<Self> {
        let pages = doc.pages()?;
        let mut tree: HashSet<u32> = HashSet::from([doc.catalog_ref()?.0]);
        for p in &pages {
            tree.insert(p.id.0);
            let mut parent = p.dict.get("Parent").cloned();
            while let Some(Obj::Ref(id, _)) = parent {
                if !tree.insert(id) {
                    break;
                }
                parent = doc
                    .get(id)?
                    .as_dict()
                    .and_then(|d| d.get("Parent"))
                    .cloned();
            }
        }
        let mut signed = HashSet::new();
        for f in signature_fields(doc, &pages)?.iter().filter(|f| f.signed) {
            signed.insert(f.id.0);
            signed.extend(f.widgets.iter().map(|w| w.id.0));
        }
        Ok(Source {
            doc,
            pages,
            placed: HashMap::new(),
            tree,
            map: HashMap::new(),
            queue: Vec::new(),
            signed,
            form: HashSet::new(),
            tops: Vec::new(),
            renamed: HashMap::new(),
        })
    }

    /// The annotations listed on a page, as given.
    fn annots(&self, page: &Dict) -> Result<Vec<Obj>> {
        Ok(match page.get("Annots") {
            Some(a) => self.doc.resolve(a)?.as_array().cloned().unwrap_or_default(),
            None => Vec::new(),
        })
    }

    /// Records the widgets on the kept pages and the fields above them.
    fn find_fields(&mut self) -> Result<()> {
        let kept: Vec<Dict> = self
            .pages
            .iter()
            .filter(|p| self.placed.contains_key(&p.id.0))
            .map(|p| p.dict.clone())
            .collect();
        for page in kept {
            for a in self.annots(&page)? {
                let Obj::Ref(id, _) = a else { continue };
                if self.signed.contains(&id) {
                    continue;
                }
                let obj = self.doc.get(id)?;
                let Some(d) = obj.as_dict() else { continue };
                if !d.get("Subtype").is_some_and(|s| s.is_name("Widget")) {
                    continue;
                }
                let mut top = d.get("FT").or_else(|| d.get("T")).is_some().then_some(id);
                self.form.insert(id);
                let mut parent = d.get("Parent").cloned();
                for _ in 0..32 {
                    let Some(Obj::Ref(pid, _)) = parent else {
                        break;
                    };
                    self.form.insert(pid);
                    top = Some(pid);
                    parent = self
                        .doc
                        .get(pid)?
                        .as_dict()
                        .and_then(|d| d.get("Parent"))
                        .cloned();
                }
                if let Some(top) = top
                    && !self.tops.contains(&top)
                {
                    self.tops.push(top);
                }
            }
        }
        Ok(())
    }

    /// The value of an inheritable page attribute from the page tree above `page`.
    fn inherited(&self, page: &Dict, key: &str) -> Result<Option<Obj>> {
        let mut parent = page.get("Parent").cloned();
        for _ in 0..64 {
            let Some(Obj::Ref(id, _)) = parent else { break };
            let node = self.doc.get(id)?;
            let Some(d) = node.as_dict() else { break };
            if let Some(v) = d.get(key) {
                return Ok(Some(v.clone()));
            }
            parent = d.get("Parent").cloned();
        }
        Ok(None)
    }

    /// The new page dictionary for page `index`, which becomes object `id`.
    fn page(
        &mut self,
        index: usize,
        id: u32,
        rotate: i32,
        objs: &mut BTreeMap<u32, Obj>,
        next: &mut u32,
    ) -> Result<Dict> {
        let info = self.pages[index].clone();
        let mut d = info.dict.clone();
        for key in ["Resources", "MediaBox", "CropBox"] {
            if d.get(key).is_none()
                && let Some(v) = self.inherited(&info.dict, key)?
            {
                d.set(key, v);
            }
        }
        if d.get("MediaBox").is_none() {
            d.set(
                "MediaBox",
                Obj::Array([0, 0, 612, 792].map(Obj::int).to_vec()),
            );
        }
        if d.get("Resources").is_none() {
            d.set("Resources", Obj::Dict(Dict::new()));
        }
        // Structure and article threads belong to the old catalog.
        for key in ["Parent", "Annots", "Rotate", "StructParents", "B"] {
            d.remove(key);
        }
        let mut page = self.copy_dict(&d, next);
        let first = self.placed.get(&info.id.0) == Some(&id);
        let annots = self.page_annots(&info.dict, id, first, objs, next)?;
        if !annots.is_empty() {
            page.set("Annots", Obj::Array(annots));
        }
        let r = (info.rotate + rotate).rem_euclid(360);
        if r != 0 {
            page.set("Rotate", Obj::int(r as i64));
        }
        Ok(page)
    }

    /// Copies the annotations of a page that becomes object `id`. Signed
    /// signature fields and links to pages left out are dropped. A page used
    /// again gets its own copies of its comments; form fields stay with its
    /// first use.
    fn page_annots(
        &mut self,
        page: &Dict,
        id: u32,
        first: bool,
        objs: &mut BTreeMap<u32, Obj>,
        next: &mut u32,
    ) -> Result<Vec<Obj>> {
        let mut out = Vec::new();
        for a in self.annots(page)? {
            let old = match a {
                Obj::Ref(r, _) => Some(r),
                _ => None,
            };
            if old.is_some_and(|r| self.signed.contains(&r)) {
                continue;
            }
            let annot = self.doc.resolve(&a)?;
            let Some(d) = annot.as_dict() else { continue };
            let subtype = |s: &str| d.get("Subtype").is_some_and(|v| v.is_name(s));
            if subtype("Link") && !self.link_kept(d)? {
                continue;
            }
            if first {
                out.push(match old {
                    Some(r) => self.copy_ref(r, next),
                    None => self.copy(&annot, next),
                });
                continue;
            }
            if subtype("Widget") || subtype("Popup") {
                continue;
            }
            let mut d = d.clone();
            d.remove("Popup");
            d.remove("P");
            let mut copy = self.copy_dict(&d, next);
            copy.set("P", Obj::Ref(id, 0));
            let n = take(next);
            objs.insert(n, Obj::Dict(copy));
            out.push(Obj::Ref(n, 0));
        }
        Ok(out)
    }

    /// Whether a link still has somewhere to go: a page that is kept, or
    /// outside the document. Named destinations live in the old catalog.
    fn link_kept(&self, link: &Dict) -> Result<bool> {
        let dest = match link.get("Dest") {
            Some(d) => Some(d.clone()),
            None => match link.get("A").map(|a| self.doc.resolve(a)).transpose()? {
                Some(Obj::Dict(a)) if a.get("S").is_some_and(|s| s.is_name("GoTo")) => {
                    a.get("D").cloned()
                }
                _ => None,
            },
        };
        let Some(dest) = dest else { return Ok(true) };
        Ok(match self.doc.resolve(&dest)? {
            Obj::Array(a) => match a.first() {
                Some(Obj::Ref(p, _)) => self.placed.contains_key(p),
                _ => true,
            },
            _ => false,
        })
    }

    fn copy(&mut self, obj: &Obj, next: &mut u32) -> Obj {
        match obj {
            Obj::Ref(id, _) => self.copy_ref(*id, next),
            Obj::Array(a) => Obj::Array(a.iter().map(|o| self.copy(o, next)).collect()),
            Obj::Dict(d) => Obj::Dict(self.copy_dict(d, next)),
            Obj::Stream(d, data) => {
                // The writer sets /Length; an indirect one is not needed.
                let mut d = d.clone();
                d.remove("Length");
                Obj::Stream(self.copy_dict(&d, next), data.clone())
            }
            o => o.clone(),
        }
    }

    fn copy_dict(&mut self, d: &Dict, next: &mut u32) -> Dict {
        Dict(
            d.0.iter()
                .map(|(k, v)| (k.clone(), self.copy(v, next)))
                .collect(),
        )
    }

    /// The new reference for object `id`, queueing it for copying the first
    /// time. The page tree is not followed: a page left out becomes null.
    fn copy_ref(&mut self, id: u32, next: &mut u32) -> Obj {
        if let Some(&n) = self.placed.get(&id) {
            return Obj::Ref(n, 0);
        }
        if self.tree.contains(&id) || !self.doc.xref.contains_key(&id) {
            return Obj::Null;
        }
        if let Some(&n) = self.map.get(&id) {
            return Obj::Ref(n, 0);
        }
        let n = take(next);
        self.map.insert(id, n);
        self.queue.push((id, n));
        Obj::Ref(n, 0)
    }

    /// Copies every queued object, and what they refer to, into `objs`.
    fn drain(&mut self, objs: &mut BTreeMap<u32, Obj>, next: &mut u32) -> Result<()> {
        while let Some((old, new)) = self.queue.pop() {
            let mut obj = self.doc.get(old)?;
            if let Obj::Dict(d) | Obj::Stream(d, _) = &mut obj {
                if self.form.contains(&old)
                    && let Some(kids) = d.get("Kids")
                {
                    let kids = self.doc.resolve(kids)?;
                    let kept: Vec<Obj> = kids
                        .as_array()
                        .map(|k| {
                            k.iter()
                                .filter(|k| matches!(k, Obj::Ref(id, _) if self.form.contains(id)))
                                .cloned()
                                .collect()
                        })
                        .unwrap_or_default();
                    d.set("Kids", Obj::Array(kept));
                }
                if let Some(t) = self.renamed.get(&old) {
                    d.set("T", Obj::Str(t.clone()));
                }
            }
            let copy = self.copy(&obj, next);
            objs.insert(new, copy);
        }
        Ok(())
    }
}

/// Parses a page selection that also orders: `1-3,5,7-` (numbered from 1;
/// `7-` runs to the last page, `5-3` backwards, `all` is every page).
/// Pages may repeat.
pub fn parse_selection(spec: &str, count: usize) -> std::result::Result<Vec<usize>, String> {
    let spec = spec.trim();
    if spec.eq_ignore_ascii_case("all") {
        return Ok((0..count).collect());
    }
    let num = |s: &str| -> std::result::Result<usize, String> {
        match s.trim().parse::<usize>() {
            Ok(0) => Err("pages are numbered from 1".into()),
            Ok(n) if n > count => Err(format!("the PDF has only {count} page(s)")),
            Ok(n) => Ok(n - 1),
            Err(_) => Err(format!("\"{}\" is not a page number", s.trim())),
        }
    };
    let mut out = Vec::new();
    for part in spec.split(',').filter(|p| !p.trim().is_empty()) {
        match part.split_once('-') {
            Some((a, b)) => {
                let a = if a.trim().is_empty() { 0 } else { num(a)? };
                let b = if b.trim().is_empty() {
                    count.saturating_sub(1)
                } else {
                    num(b)?
                };
                if a <= b {
                    out.extend(a..=b);
                } else {
                    out.extend((b..=a).rev());
                }
            }
            None => out.push(num(part)?),
        }
    }
    if out.is_empty() {
        return Err("no pages selected".into());
    }
    Ok(out)
}

/// `contract.pdf` → `contract_prepared.pdf` (or `contract_prepared_2.pdf`, …
/// if taken), next to it.
pub fn prepared_path(input: &Path) -> PathBuf {
    let dir = input.parent().unwrap_or_else(|| Path::new("."));
    let stem = input
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "document".into());
    let first = dir.join(format!("{stem}_prepared.pdf"));
    if !first.exists() {
        return first;
    }
    (2..)
        .map(|n| dir.join(format!("{stem}_prepared_{n}.pdf")))
        .find(|p| !p.exists())
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A PDF from numbered object bodies (streams given as `stream:` + content).
    fn pdf(objs: &[(u32, &str)]) -> Vec<u8> {
        let mut out = b"%PDF-1.7\n".to_vec();
        let mut offsets = Vec::new();
        for (id, body) in objs {
            offsets.push((*id, out.len()));
            out.extend_from_slice(format!("{id} 0 obj\n").as_bytes());
            match body.strip_prefix("stream:") {
                Some(s) => out.extend_from_slice(
                    format!("<< /Length {} >>\nstream\n{s}\nendstream", s.len()).as_bytes(),
                ),
                None => out.extend_from_slice(body.as_bytes()),
            }
            out.extend_from_slice(b"\nendobj\n");
        }
        let size = objs.iter().map(|(id, _)| id + 1).max().unwrap();
        let xref = out.len();
        out.extend_from_slice(format!("xref\n0 {size}\n0000000000 65535 f\r\n").as_bytes());
        for id in 1..size {
            match offsets.iter().find(|(i, _)| *i == id) {
                Some((_, off)) => {
                    out.extend_from_slice(format!("{off:010} 00000 n\r\n").as_bytes())
                }
                None => out.extend_from_slice(b"0000000000 00001 f\r\n"),
            }
        }
        out.extend_from_slice(
            format!("trailer\n<< /Size {size} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n")
                .as_bytes(),
        );
        out
    }

    /// Two pages under an intermediate node that holds their resources,
    /// size and rotation; page 2 has its own size and a link to page 1.
    fn inherited_pdf() -> Vec<u8> {
        pdf(&[
            (1, "<< /Type /Catalog /Pages 2 0 R /Outlines 9 0 R >>"),
            (
                2,
                "<< /Type /Pages /Kids [3 0 R] /Count 2 /MediaBox [0 0 595.2756 841.8898] >>",
            ),
            (
                3,
                "<< /Type /Pages /Parent 2 0 R /Kids [4 0 R 5 0 R] /Count 2 /Rotate 90 \
                 /Resources << /Font << /F1 6 0 R >> >> >>",
            ),
            (4, "<< /Type /Page /Parent 3 0 R /Contents 7 0 R >>"),
            (
                5,
                "<< /Type /Page /Parent 3 0 R /MediaBox [0 0 200 100] /Rotate 0 /Contents 7 0 R \
                 /Annots [8 0 R] >>",
            ),
            (6, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"),
            (7, "stream:BT /F1 12 Tf 10 10 Td (Hi) Tj ET"),
            (
                8,
                "<< /Type /Annot /Subtype /Link /Rect [0 0 50 20] /Dest [4 0 R /Fit] >>",
            ),
            (
                9,
                "<< /Type /Outlines /First 10 0 R /Last 10 0 R /Count 1 >>",
            ),
            (10, "<< /Title (One) /Parent 9 0 R /Dest [4 0 R /Fit] >>"),
        ])
    }

    /// One page with a text field and a signed signature field.
    fn form_pdf() -> Vec<u8> {
        pdf(&[
            (
                1,
                "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [5 0 R 6 0 R] /DA (/Helv 0 Tf 0 g) \
                 /DR << /Font << /Helv 8 0 R >> >> /SigFlags 3 >> >>",
            ),
            (2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"),
            (
                3,
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 300] /Annots [5 0 R 6 0 R] >>",
            ),
            (
                5,
                "<< /Type /Annot /Subtype /Widget /FT /Tx /T (name) /V (A) /Rect [10 10 100 30] /P 3 0 R >>",
            ),
            (
                6,
                "<< /Type /Annot /Subtype /Widget /FT /Sig /T (sig) /V 7 0 R /Rect [10 50 100 90] /P 3 0 R >>",
            ),
            (
                7,
                "<< /Type /Sig /Filter /Adobe.PPKLite /ByteRange [0 1 2 3] /Contents <00> >>",
            ),
            (8, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"),
        ])
    }

    fn page(doc: &Document, i: usize) -> PageInfo {
        doc.pages().unwrap()[i].clone()
    }

    fn p(source: usize, page: usize, rotate: i32) -> Item {
        Item::Page {
            source,
            page,
            rotate,
        }
    }

    #[test]
    fn inherited_attributes_go_on_the_page() {
        let data = inherited_pdf();
        let src = Document::parse(&data).unwrap();
        let out = assemble(&[src], &[p(0, 1, 0), p(0, 0, 90)]).unwrap();
        let doc = Document::parse(&out.data).unwrap();
        assert_eq!(doc.pages().unwrap().len(), 2);
        let (a, b) = (page(&doc, 0), page(&doc, 1));
        assert_eq!(a.media_box, [0.0, 0.0, 200.0, 100.0]);
        assert_eq!(a.rotate, 0);
        // Inherited 90, turned 90 more; the size keeps its exact digits.
        assert_eq!(b.rotate, 180);
        assert_eq!(
            b.dict.get("MediaBox"),
            Some(&Obj::Array(
                ["0", "0", "595.2756", "841.8898"]
                    .map(|n| Obj::Num(n.into()))
                    .to_vec()
            ))
        );
        for pg in [&a, &b] {
            let res = doc.resolve(pg.dict.get("Resources").unwrap()).unwrap();
            let font = res
                .as_dict()
                .unwrap()
                .get("Font")
                .unwrap()
                .as_dict()
                .unwrap();
            let f1 = doc.resolve(font.get("F1").unwrap()).unwrap();
            assert!(
                f1.as_dict()
                    .unwrap()
                    .get("BaseFont")
                    .unwrap()
                    .is_name("Helvetica")
            );
            assert_eq!(pg.dict.get("Parent"), Some(&Obj::Ref(2, 0)));
        }
        // One shared content stream and font, copied once.
        assert_eq!(a.dict.get("Contents"), b.dict.get("Contents"));
        let Obj::Stream(_, content) = doc.resolve(a.dict.get("Contents").unwrap()).unwrap() else {
            panic!()
        };
        assert_eq!(content, b"BT /F1 12 Tf 10 10 Td (Hi) Tj ET");
        // The link points at the page's new number.
        let annots = a.dict.get("Annots").unwrap().as_array().unwrap();
        let link = doc.resolve(&annots[0]).unwrap();
        let dest = link
            .as_dict()
            .unwrap()
            .get("Dest")
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(dest[0], Obj::Ref(b.id.0, 0));
        assert!(
            out.notices
                .contains(&Notice::BookmarksDropped { source: 0 })
        );
        assert!(doc.catalog().unwrap().get("Outlines").is_none());
    }

    #[test]
    fn objects_are_renumbered_densely_and_old_tree_is_not_copied() {
        let data = inherited_pdf();
        let src = Document::parse(&data).unwrap();
        let out = assemble(&[src], &[p(0, 0, 0)]).unwrap();
        let doc = Document::parse(&out.data).unwrap();
        assert!(!doc.repaired);
        // Catalog, tree, page, contents, font, info: nothing else.
        let ids: Vec<u32> = doc.sorted_xref().keys().copied().collect();
        assert_eq!(ids, (1..=6).collect::<Vec<_>>());
        for id in ids {
            let o = doc.get(id).unwrap();
            if let Some(d) = o.as_dict() {
                assert!(!d.get("Type").is_some_and(|t| t.is_name("Outlines")));
            }
        }
        // Page 2 is left out: its link went with it.
        assert!(page(&doc, 0).dict.get("Annots").is_none());
    }

    #[test]
    fn links_to_pages_left_out_are_dropped() {
        let data = inherited_pdf();
        let src = Document::parse(&data).unwrap();
        let out = assemble(&[src], &[p(0, 1, 0)]).unwrap();
        let doc = Document::parse(&out.data).unwrap();
        assert!(page(&doc, 0).dict.get("Annots").is_none());
    }

    #[test]
    fn rotation_and_blank_pages() {
        let data = inherited_pdf();
        let src = Document::parse(&data).unwrap();
        let items = [
            p(0, 1, -90),
            Item::Blank {
                width: 595.28,
                height: 841.89,
            },
            p(0, 1, 450),
        ];
        let doc_out = assemble(&[src], &items).unwrap();
        let doc = Document::parse(&doc_out.data).unwrap();
        assert_eq!(page(&doc, 0).rotate, 270);
        assert_eq!(page(&doc, 2).rotate, 90);
        let blank = page(&doc, 1);
        assert_eq!(blank.media_box, [0.0, 0.0, 595.28, 841.89]);
        assert!(blank.dict.get("Contents").is_none());
        let src = Document::parse(&data).unwrap();
        assert!(matches!(
            assemble(&[src], &[p(0, 0, 45)]),
            Err(PdfError::Pages(_))
        ));
        let src = Document::parse(&data).unwrap();
        assert!(matches!(
            assemble(&[src], &[p(0, 2, 0)]),
            Err(PdfError::NoSuchPage(3))
        ));
    }

    #[test]
    fn page_used_twice_gets_its_own_annotations() {
        let data = inherited_pdf();
        let src = Document::parse(&data).unwrap();
        let out = assemble(&[src], &[p(0, 0, 0), p(0, 1, 0), p(0, 1, 0)]).unwrap();
        let doc = Document::parse(&out.data).unwrap();
        let pages = doc.pages().unwrap();
        assert_ne!(pages[1].id, pages[2].id);
        let a1 = pages[1].dict.get("Annots").unwrap().as_array().unwrap()[0].clone();
        let a2 = pages[2].dict.get("Annots").unwrap().as_array().unwrap()[0].clone();
        assert_ne!(a1, a2);
        let p2 = doc.resolve(&a2).unwrap();
        assert_eq!(
            p2.as_dict().unwrap().get("P"),
            Some(&Obj::Ref(pages[2].id.0, 0))
        );
    }

    #[test]
    fn form_fields_merge_signatures_are_dropped() {
        let data = form_pdf();
        let a = Document::parse(&data).unwrap();
        let b = Document::parse(&data).unwrap();
        let out = assemble(&[a, b], &[p(0, 0, 0), p(1, 0, 0)]).unwrap();
        let doc = Document::parse(&out.data).unwrap();
        let cat = doc.catalog().unwrap();
        let af = cat.get("AcroForm").unwrap().as_dict().unwrap();
        let fields = af.get("Fields").unwrap().as_array().unwrap();
        let names: Vec<String> = fields
            .iter()
            .map(
                |f| match doc.resolve(f).unwrap().as_dict().unwrap().get("T") {
                    Some(Obj::Str(t)) => text(t),
                    _ => String::new(),
                },
            )
            .collect();
        assert_eq!(names, ["name", "name_2"]);
        assert!(af.get("SigFlags").is_none());
        assert!(af.get("DR").is_some());
        assert_eq!(af.get("DA"), Some(&Obj::Str(b"/Helv 0 Tf 0 g".to_vec())));
        for pg in doc.pages().unwrap() {
            assert_eq!(pg.dict.get("Annots").unwrap().as_array().unwrap().len(), 1);
        }
        for id in doc.sorted_xref().keys() {
            let o = doc.get(*id).unwrap();
            assert!(
                !o.as_dict()
                    .is_some_and(|d| d.get("Type").is_some_and(|t| t.is_name("Sig")))
            );
        }
        assert_eq!(
            out.notices,
            [
                Notice::SignaturesRemoved {
                    source: 0,
                    count: 1
                },
                Notice::SignaturesRemoved {
                    source: 1,
                    count: 1
                },
                Notice::FieldRenamed {
                    from: "name".into(),
                    to: "name_2".into()
                },
            ]
        );
    }

    #[test]
    fn output_parses_back_cleanly() {
        let data = form_pdf();
        let src = Document::parse(&data).unwrap();
        let out = assemble(&[src], &[p(0, 0, 0)]).unwrap();
        assert!(out.data.starts_with(b"%PDF-1.7"));
        let doc = Document::parse(&out.data).unwrap();
        assert!(!doc.repaired);
        let info = doc.resolve(doc.trailer.get("Info").unwrap()).unwrap();
        assert!(info.as_dict().unwrap().get("Producer").is_some());
        // Every reference points at an object that exists.
        for id in doc.sorted_xref().keys() {
            let mut stack = vec![doc.get(*id).unwrap()];
            while let Some(o) = stack.pop() {
                match o {
                    Obj::Ref(r, _) => assert!(doc.xref.contains_key(&r), "dangling {r}"),
                    Obj::Array(a) => stack.extend(a),
                    Obj::Dict(d) | Obj::Stream(d, _) => {
                        stack.extend(d.0.into_iter().map(|(_, v)| v))
                    }
                    _ => {}
                }
            }
        }
    }

    #[test]
    fn selections() {
        assert_eq!(parse_selection("1-3,5,7-", 8), Ok(vec![0, 1, 2, 4, 6, 7]));
        assert_eq!(parse_selection("3-1", 3), Ok(vec![2, 1, 0]));
        assert_eq!(parse_selection("2,2", 3), Ok(vec![1, 1]));
        assert_eq!(parse_selection("all", 2), Ok(vec![0, 1]));
        assert_eq!(parse_selection("-2", 3), Ok(vec![0, 1]));
        assert!(parse_selection("4", 3).is_err());
        assert!(parse_selection("0", 3).is_err());
        assert!(parse_selection(" , ", 3).is_err());
    }
}
