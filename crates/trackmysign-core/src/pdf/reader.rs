//! Read-only access to an existing PDF: cross-reference tables and streams,
//! object streams, the page tree. Damaged files fall back to a full scan.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::rc::Rc;

use super::crypt::Crypt;
use super::object::{Dict, Lexer, Obj, Parser, Tok, is_ws};

#[derive(Debug, thiserror::Error)]
pub enum PdfError {
    #[error("not a PDF file")]
    NotPdf,
    #[error("this PDF is encrypted in a way TrackMySign cannot open: {0}")]
    Encrypted(String),
    #[error("this PDF is password-protected; enter its password to open it")]
    PasswordRequired,
    #[error("the PDF password is not correct")]
    WrongPassword,
    #[error(
        "this PDF's security settings do not allow signing; enter its owner (permissions) password to sign it"
    )]
    SigningNotAllowed,
    #[error(
        "this PDF's security settings do not allow changing its pages; enter its owner (permissions) password"
    )]
    AssemblyNotAllowed,
    #[error("could not read PDF structure: {0}")]
    Malformed(String),
    #[error("page {0} does not exist")]
    NoSuchPage(usize),
    /// Pages that cannot be put together as asked.
    #[error("{0}")]
    Pages(String),
    /// An existing signature field that cannot be signed as asked.
    #[error("{0}")]
    Field(String),
}

impl From<super::object::SyntaxError> for PdfError {
    fn from(e: super::object::SyntaxError) -> Self {
        PdfError::Malformed(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, PdfError>;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum XrefEntry {
    Offset(usize, u16),
    InStream { container: u32, index: u32 },
}

#[derive(Debug, Clone)]
pub struct PageInfo {
    pub id: (u32, u16),
    pub dict: Dict,
    pub media_box: [f64; 4],
    pub crop_box: [f64; 4],
    /// Normalised to 0, 90, 180 or 270.
    pub rotate: i32,
}

impl PageInfo {
    /// Size as displayed (after rotation), in points.
    pub fn display_size(&self) -> (f64, f64) {
        let w = self.crop_box[2] - self.crop_box[0];
        let h = self.crop_box[3] - self.crop_box[1];
        if self.rotate % 180 == 0 {
            (w, h)
        } else {
            (h, w)
        }
    }
}

struct ObjStm {
    data: Vec<u8>,
    offsets: Vec<(u32, usize)>,
}

pub struct Document<'a> {
    pub data: &'a [u8],
    pub xref: HashMap<u32, XrefEntry>,
    pub trailer: Dict,
    /// Byte offset of the newest cross-reference section (`/Prev` for our update).
    pub startxref: usize,
    /// The newest section is a cross-reference stream (PDF 1.5+).
    pub xref_is_stream: bool,
    /// The cross-reference data was unusable and rebuilt by scanning the file.
    pub repaired: bool,
    /// Set for password-protected files: objects read are decrypted, and
    /// objects written to an update must be encrypted with it.
    pub crypt: Option<Crypt>,
    objstm_cache: RefCell<HashMap<u32, Rc<ObjStm>>>,
}

/// How to unlock an encrypted file.
enum Unlock<'p> {
    Password(Option<&'p str>),
    /// The key of a later revision of the same file.
    Known(&'p Crypt),
}

impl<'a> Document<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        Self::open(data, None)
    }

    /// Like [`Document::parse`], unlocking an encrypted file with `password`
    /// (owner or user). Without one, the empty password is tried.
    pub fn open(data: &'a [u8], password: Option<&str>) -> Result<Self> {
        Self::load(data, Unlock::Password(password))
    }

    /// An earlier revision (a prefix) of this file, with the same key.
    pub fn revision<'b>(&self, data: &'b [u8]) -> Result<Document<'b>> {
        match &self.crypt {
            Some(c) => Document::load(data, Unlock::Known(c)),
            None => Document::parse(data),
        }
    }

    fn load(data: &'a [u8], unlock: Unlock) -> Result<Self> {
        let head = &data[..data.len().min(1024)];
        if find(head, b"%PDF-").is_none() {
            return Err(PdfError::NotPdf);
        }
        let mut doc = Document {
            data,
            xref: HashMap::new(),
            trailer: Dict::new(),
            startxref: 0,
            xref_is_stream: false,
            repaired: false,
            crypt: None,
            objstm_cache: RefCell::new(HashMap::new()),
        };
        let loaded = doc.load_xref().is_ok();
        if loaded {
            doc.unlock(&unlock)?;
        }
        if !loaded || !doc.looks_sane() {
            doc.reconstruct(&unlock)?;
        }
        Ok(doc)
    }

    /// Reads `/Encrypt` from the trailer and derives the file key.
    fn unlock(&mut self, how: &Unlock) -> Result<()> {
        self.crypt = None;
        self.objstm_cache.borrow_mut().clear();
        let Some(enc) = self.trailer.get("Encrypt").cloned() else {
            return Ok(());
        };
        let dict = self
            .resolve(&enc)?
            .as_dict()
            .cloned()
            .ok_or_else(|| PdfError::Malformed("unreadable /Encrypt dictionary".into()))?;
        let mut crypt = match how {
            Unlock::Known(c) => (*c).clone(),
            Unlock::Password(pw) => {
                let id0 = match self.trailer.get("ID").and_then(Obj::as_array) {
                    Some(a) => match a.first() {
                        Some(Obj::Str(s)) => s.clone(),
                        _ => Vec::new(),
                    },
                    None => Vec::new(),
                };
                Crypt::open(&dict, &id0, *pw)?
            }
        };
        crypt.encrypt_id = match enc {
            Obj::Ref(id, _) => Some(id),
            _ => None,
        };
        self.crypt = Some(crypt);
        Ok(())
    }

    /// One past the highest object number in use.
    pub fn next_object_id(&self) -> u32 {
        let size = self
            .trailer
            .get("Size")
            .and_then(Obj::as_i64)
            .unwrap_or(0)
            .max(0) as u32;
        let max = self.xref.keys().max().map(|m| m + 1).unwrap_or(1);
        size.max(max).max(1)
    }

    fn looks_sane(&self) -> bool {
        match self.trailer.get("Root") {
            Some(Obj::Ref(id, _)) => matches!(self.get(*id), Ok(o) if o.as_dict().is_some()),
            _ => false,
        }
    }

    // ---------------------------------------------------------------- xref

    fn load_xref(&mut self) -> Result<()> {
        let tail_start = self.data.len().saturating_sub(4096);
        let pos = rfind(&self.data[tail_start..], b"startxref")
            .map(|p| p + tail_start)
            .ok_or_else(|| PdfError::Malformed("no startxref".into()))?;
        let mut lx = Lexer::new(self.data, pos + 9);
        let off = match lx.next_tok()? {
            Some(Tok::Num(n)) => n
                .parse::<usize>()
                .map_err(|_| PdfError::Malformed("bad startxref".into()))?,
            _ => return Err(PdfError::Malformed("bad startxref".into())),
        };
        self.startxref = off;

        let mut next = Some(off);
        let mut seen = Vec::new();
        let mut first = true;
        while let Some(off) = next {
            if seen.contains(&off) || off >= self.data.len() {
                break;
            }
            seen.push(off);
            let (trailer, is_stream) = self.read_xref_section(off)?;
            if first {
                self.trailer = trailer.clone();
                self.xref_is_stream = is_stream;
                first = false;
            }
            // Hybrid-reference files: the classic table points at a stream too.
            if let Some(stm) = trailer.get("XRefStm").and_then(Obj::as_i64) {
                let _ = self.read_xref_section(stm as usize);
            }
            next = trailer
                .get("Prev")
                .and_then(Obj::as_i64)
                .map(|p| p as usize);
        }
        Ok(())
    }

    /// Reads one section; entries already known (from newer sections) win.
    fn read_xref_section(&mut self, off: usize) -> Result<(Dict, bool)> {
        let mut lx = Lexer::new(self.data, off);
        lx.skip_ws();
        if self.data[lx.pos..].starts_with(b"xref") {
            lx.pos += 4;
            self.read_xref_table(lx).map(|d| (d, false))
        } else {
            self.read_xref_stream(off).map(|d| (d, true))
        }
    }

    fn read_xref_table(&mut self, mut lx: Lexer) -> Result<Dict> {
        let bad = || PdfError::Malformed("bad xref table".into());
        loop {
            match lx.next_tok()? {
                Some(Tok::Kw(k)) if k == b"trailer" => break,
                Some(Tok::Num(start)) => {
                    let start: u32 = start.parse().map_err(|_| bad())?;
                    let count: u32 = match lx.next_tok()? {
                        Some(Tok::Num(c)) => c.parse().map_err(|_| bad())?,
                        _ => return Err(bad()),
                    };
                    for i in 0..count {
                        let (Some(Tok::Num(o)), Some(Tok::Num(g)), Some(Tok::Kw(t))) =
                            (lx.next_tok()?, lx.next_tok()?, lx.next_tok()?)
                        else {
                            return Err(bad());
                        };
                        let id = start + i;
                        if t == b"n" {
                            let o: usize = o.parse().map_err(|_| bad())?;
                            let g: u16 = g.parse().unwrap_or(0);
                            if o > 0 {
                                self.xref.entry(id).or_insert(XrefEntry::Offset(o, g));
                            }
                        }
                    }
                }
                _ => {
                    return Err(bad());
                }
            }
        }
        let mut p = Parser { lx };
        match p.parse()? {
            Obj::Dict(d) => Ok(d),
            _ => Err(bad()),
        }
    }

    fn read_xref_stream(&mut self, off: usize) -> Result<Dict> {
        let (_, obj) = self.parse_indirect_at(off)?;
        let Obj::Stream(dict, raw) = obj else {
            return Err(PdfError::Malformed("xref offset is not a stream".into()));
        };
        if !dict.get("Type").is_some_and(|t| t.is_name("XRef")) {
            return Err(PdfError::Malformed("xref stream has wrong /Type".into()));
        }
        let data = decode_stream(&dict, &raw)?;
        let w: Vec<usize> = dict
            .get("W")
            .and_then(Obj::as_array)
            .map(|a| a.iter().map(|o| o.as_i64().unwrap_or(0) as usize).collect())
            .ok_or_else(|| PdfError::Malformed("xref stream without /W".into()))?;
        if w.len() != 3 {
            return Err(PdfError::Malformed("bad /W".into()));
        }
        let size = dict.get("Size").and_then(Obj::as_i64).unwrap_or(0);
        let index: Vec<i64> = match dict.get("Index").and_then(Obj::as_array) {
            Some(a) => a.iter().filter_map(Obj::as_i64).collect(),
            None => vec![0, size],
        };
        let row = w.iter().sum::<usize>();
        if row == 0 {
            return Err(PdfError::Malformed("bad /W".into()));
        }
        let field = |b: &[u8]| b.iter().fold(0u64, |acc, x| acc << 8 | *x as u64);
        let mut cursor = 0;
        for pair in index.chunks(2) {
            let (start, count) = (pair[0] as u32, *pair.get(1).unwrap_or(&0) as u32);
            for i in 0..count {
                if cursor + row > data.len() {
                    break;
                }
                let r = &data[cursor..cursor + row];
                cursor += row;
                let t = if w[0] == 0 { 1 } else { field(&r[..w[0]]) };
                let f2 = field(&r[w[0]..w[0] + w[1]]);
                let f3 = field(&r[w[0] + w[1]..]);
                let id = start + i;
                let entry = match t {
                    1 if f2 > 0 => XrefEntry::Offset(f2 as usize, f3 as u16),
                    2 => XrefEntry::InStream {
                        container: f2 as u32,
                        index: f3 as u32,
                    },
                    _ => continue,
                };
                self.xref.entry(id).or_insert(entry);
            }
        }
        Ok(dict)
    }

    /// Rebuild the cross-reference by scanning for `N G obj`.
    fn reconstruct(&mut self, unlock: &Unlock) -> Result<()> {
        self.xref.clear();
        self.crypt = None;
        self.objstm_cache.borrow_mut().clear();
        self.repaired = true;
        let d = self.data;
        let mut i = 0;
        while let Some(p) = find(&d[i..], b"obj") {
            let at = i + p;
            i = at + 3;
            if let Some((id, gn, start)) = obj_header_before(d, at) {
                if d.get(at + 3).is_some_and(|b| b.is_ascii_alphanumeric()) {
                    continue;
                }
                self.xref.insert(id, XrefEntry::Offset(start, gn));
            }
        }
        let ids: Vec<(u32, usize)> = self
            .xref
            .iter()
            .filter_map(|(id, e)| match e {
                XrefEntry::Offset(o, _) => Some((*id, *o)),
                _ => None,
            })
            .collect();
        let mut trailer: Option<Dict> = None;
        let mut objstms = Vec::new();
        for (id, off) in ids {
            if let Ok((_, Obj::Stream(sd, _))) = self.parse_indirect_at(off) {
                if sd.get("Type").is_some_and(|t| t.is_name("ObjStm")) {
                    objstms.push(id);
                } else if sd.get("Type").is_some_and(|t| t.is_name("XRef"))
                    && sd.get("Root").is_some()
                {
                    trailer = Some(sd.clone());
                }
            }
        }
        // Classic trailers (last one with a /Root wins).
        let mut j = 0;
        while let Some(p) = find(&d[j..], b"trailer") {
            let at = j + p;
            j = at + 7;
            if let Ok(Obj::Dict(td)) = Parser::new(d, at + 7).parse()
                && td.get("Root").is_some()
            {
                trailer = Some(td);
            }
        }
        // The key is needed to read object streams in an encrypted file.
        if let Some(t) = &trailer {
            self.trailer = t.clone();
            self.unlock(unlock)?;
        }
        // Compressed objects: pull in entries from any object streams found.
        for id in objstms {
            if let Ok(stm) = self.load_objstm(id) {
                for (idx, (oid, _)) in stm.offsets.iter().enumerate() {
                    self.xref.entry(*oid).or_insert(XrefEntry::InStream {
                        container: id,
                        index: idx as u32,
                    });
                }
            }
        }
        let mut trailer = match trailer {
            Some(t) => t,
            None => {
                // Last resort: find the catalog.
                let mut root = None;
                for &id in self.xref.keys() {
                    if let Ok(o) = self.get(id)
                        && o.as_dict()
                            .is_some_and(|dd| dd.get("Type").is_some_and(|t| t.is_name("Catalog")))
                    {
                        root = Some(id);
                    }
                }
                let root =
                    root.ok_or_else(|| PdfError::Malformed("no document catalog found".into()))?;
                Dict::new().with("Root", Obj::Ref(root, 0))
            }
        };
        for k in [
            "Prev",
            "XRefStm",
            "W",
            "Index",
            "Filter",
            "DecodeParms",
            "Length",
            "Type",
        ] {
            trailer.remove(k);
        }
        self.trailer = trailer;
        self.xref_is_stream = false;
        if !self.looks_sane() {
            return Err(PdfError::Malformed("document catalog is unreadable".into()));
        }
        Ok(())
    }

    // ------------------------------------------------------------- objects

    /// Parses `N G obj ... endobj` at `off`.
    fn parse_indirect_at(&self, off: usize) -> Result<((u32, u16), Obj)> {
        let mut lx = Lexer::new(self.data, off);
        let bad = || PdfError::Malformed(format!("no object at offset {off}"));
        let (Some(Tok::Num(id)), Some(Tok::Num(gn)), Some(Tok::Kw(k))) =
            (lx.next_tok()?, lx.next_tok()?, lx.next_tok()?)
        else {
            return Err(bad());
        };
        if k != b"obj" {
            return Err(bad());
        }
        let id: u32 = id.parse().map_err(|_| bad())?;
        let gn: u16 = gn.parse().map_err(|_| bad())?;
        let mut p = Parser { lx };
        let obj = p.parse()?;
        let mut lx = p.lx;
        if let Obj::Dict(dict) = &obj
            && let Some(Tok::Kw(k)) = lx.next_tok()?
            && k == b"stream"
        {
            let mut s = lx.pos;
            if self.data.get(s) == Some(&b'\r') {
                s += 1;
            }
            if self.data.get(s) == Some(&b'\n') {
                s += 1;
            }
            let data = self.stream_body(dict, s, id)?;
            return Ok(((id, gn), Obj::Stream(dict.clone(), data)));
        }
        Ok(((id, gn), obj))
    }

    /// [`Self::parse_indirect_at`], decrypted. Objects inside object streams
    /// are not encrypted on their own: the stream around them is.
    fn object_at(&self, off: usize) -> Result<((u32, u16), Obj)> {
        let ((id, gn), obj) = self.parse_indirect_at(off)?;
        match &self.crypt {
            Some(c) if c.encrypt_id != Some(id) => Ok(((id, gn), c.decrypt(id, gn, obj))),
            _ => Ok(((id, gn), obj)),
        }
    }

    fn stream_body(&self, dict: &Dict, start: usize, self_id: u32) -> Result<Vec<u8>> {
        let len = match dict.get("Length") {
            Some(Obj::Ref(id, _)) if *id != self_id => self.get(*id).ok().and_then(|o| o.as_i64()),
            Some(o) => o.as_i64(),
            None => None,
        };
        if let Some(len) = len {
            let end = start + len.max(0) as usize;
            if end <= self.data.len() {
                let mut k = end;
                while k < self.data.len() && is_ws(self.data[k]) {
                    k += 1;
                }
                if self.data[k..].starts_with(b"endstream") {
                    return Ok(self.data[start..end].to_vec());
                }
            }
        }
        // Wrong or missing /Length: look for the terminator instead.
        let rel = find(&self.data[start..], b"endstream")
            .ok_or_else(|| PdfError::Malformed("unterminated stream".into()))?;
        let mut end = start + rel;
        if end > start && self.data[end - 1] == b'\n' {
            end -= 1;
        }
        if end > start && self.data[end - 1] == b'\r' {
            end -= 1;
        }
        Ok(self.data[start..end].to_vec())
    }

    pub fn get(&self, id: u32) -> Result<Obj> {
        match self.xref.get(&id) {
            Some(XrefEntry::Offset(off, _)) => {
                let ((found, _), obj) = self.object_at(*off)?;
                if found != id {
                    return Err(PdfError::Malformed(format!(
                        "xref for object {id} points at object {found}"
                    )));
                }
                Ok(obj)
            }
            Some(XrefEntry::InStream { container, index }) => {
                let stm = self.load_objstm(*container)?;
                let (oid, off) = *stm
                    .offsets
                    .get(*index as usize)
                    .filter(|(oid, _)| *oid == id)
                    .or_else(|| stm.offsets.iter().find(|(oid, _)| *oid == id))
                    .ok_or_else(|| {
                        PdfError::Malformed(format!("object {id} missing from object stream"))
                    })?;
                debug_assert_eq!(oid, id);
                Ok(Parser::new(&stm.data, off).parse()?)
            }
            None => Ok(Obj::Null),
        }
    }

    /// Follows a reference (one level is enough for PDF semantics).
    pub fn resolve(&self, obj: &Obj) -> Result<Obj> {
        match obj {
            Obj::Ref(id, _) => self.get(*id),
            o => Ok(o.clone()),
        }
    }

    pub fn gen_of(&self, id: u32) -> u16 {
        match self.xref.get(&id) {
            Some(XrefEntry::Offset(_, g)) => *g,
            _ => 0,
        }
    }

    fn load_objstm(&self, id: u32) -> Result<Rc<ObjStm>> {
        if let Some(s) = self.objstm_cache.borrow().get(&id) {
            return Ok(s.clone());
        }
        let off = match self.xref.get(&id) {
            Some(XrefEntry::Offset(off, _)) => *off,
            _ => return Err(PdfError::Malformed(format!("object stream {id} not found"))),
        };
        let (_, obj) = self.object_at(off)?;
        let Obj::Stream(dict, raw) = obj else {
            return Err(PdfError::Malformed(format!(
                "object {id} is not an object stream"
            )));
        };
        let data = decode_stream(&dict, &raw)?;
        let n = dict.get("N").and_then(Obj::as_i64).unwrap_or(0) as usize;
        let first = dict.get("First").and_then(Obj::as_i64).unwrap_or(0) as usize;
        let mut lx = Lexer::new(&data, 0);
        let mut offsets = Vec::with_capacity(n);
        for _ in 0..n {
            match (lx.next_tok()?, lx.next_tok()?) {
                (Some(Tok::Num(a)), Some(Tok::Num(b))) => {
                    offsets.push((
                        a.parse().unwrap_or(0),
                        first + b.parse::<usize>().unwrap_or(0),
                    ));
                }
                _ => break,
            }
        }
        let stm = Rc::new(ObjStm { data, offsets });
        self.objstm_cache.borrow_mut().insert(id, stm.clone());
        Ok(stm)
    }

    // ---------------------------------------------------------- structure

    pub fn catalog_ref(&self) -> Result<(u32, u16)> {
        match self.trailer.get("Root") {
            Some(Obj::Ref(id, g)) => Ok((*id, *g)),
            _ => Err(PdfError::Malformed("trailer has no /Root".into())),
        }
    }

    pub fn catalog(&self) -> Result<Dict> {
        let (id, _) = self.catalog_ref()?;
        self.get(id)?
            .as_dict()
            .cloned()
            .ok_or_else(|| PdfError::Malformed("catalog is not a dictionary".into()))
    }

    pub fn pages(&self) -> Result<Vec<PageInfo>> {
        let cat = self.catalog()?;
        let root = cat
            .get("Pages")
            .cloned()
            .ok_or_else(|| PdfError::Malformed("catalog has no /Pages".into()))?;
        let mut out = Vec::new();
        let mut visited = Vec::new();
        self.walk_pages(&root, &Inherited::default(), &mut out, &mut visited, 0)?;
        if out.is_empty() {
            return Err(PdfError::Malformed("document has no pages".into()));
        }
        Ok(out)
    }

    fn walk_pages(
        &self,
        node: &Obj,
        inh: &Inherited,
        out: &mut Vec<PageInfo>,
        visited: &mut Vec<u32>,
        depth: usize,
    ) -> Result<()> {
        let Obj::Ref(id, gn) = node else {
            return Ok(());
        };
        if visited.contains(id) || depth > 64 {
            return Ok(());
        }
        visited.push(*id);
        let obj = self.get(*id)?;
        let Some(d) = obj.as_dict() else {
            return Ok(());
        };
        let mut inh = inh.clone();
        if let Some(v) = d.get("MediaBox") {
            inh.media_box = self.rect(v);
        }
        if let Some(v) = d.get("CropBox") {
            inh.crop_box = self.rect(v);
        }
        if let Some(v) = d.get("Rotate") {
            inh.rotate = self.resolve(v)?.as_i64().map(|r| r as i32);
        }
        let is_pages = d.get("Type").is_some_and(|t| t.is_name("Pages")) || d.get("Kids").is_some();
        if is_pages && !d.get("Type").is_some_and(|t| t.is_name("Page")) {
            let kids = self.resolve(d.get("Kids").unwrap_or(&Obj::Null))?;
            for k in kids.as_array().cloned().unwrap_or_default() {
                self.walk_pages(&k, &inh, out, visited, depth + 1)?;
            }
        } else {
            let media_box = inh.media_box.unwrap_or([0.0, 0.0, 612.0, 792.0]);
            let crop_box = intersect(inh.crop_box.unwrap_or(media_box), media_box);
            let r = inh.rotate.unwrap_or(0).rem_euclid(360);
            let rotate = ((r + 45) / 90 * 90) % 360;
            out.push(PageInfo {
                id: (*id, *gn),
                dict: d.clone(),
                media_box,
                crop_box,
                rotate,
            });
        }
        Ok(())
    }

    fn rect(&self, v: &Obj) -> Option<[f64; 4]> {
        let v = self.resolve(v).ok()?;
        let a = v.as_array()?;
        if a.len() != 4 {
            return None;
        }
        let n: Vec<f64> = a
            .iter()
            .map(|o| self.resolve(o).ok().and_then(|o| o.as_f64()).unwrap_or(0.0))
            .collect();
        Some([
            n[0].min(n[2]),
            n[1].min(n[3]),
            n[0].max(n[2]),
            n[1].max(n[3]),
        ])
    }

    /// Names (`/T`) of all top-level form fields, and how many are signatures.
    pub fn form_fields(&self) -> Result<(Vec<String>, usize)> {
        let cat = self.catalog()?;
        let Some(af) = cat.get("AcroForm") else {
            return Ok((vec![], 0));
        };
        let af = self.resolve(af)?;
        let Some(af) = af.as_dict() else {
            return Ok((vec![], 0));
        };
        let fields = self.resolve(af.get("Fields").unwrap_or(&Obj::Null))?;
        let mut names = Vec::new();
        let mut sigs = 0;
        for f in fields.as_array().cloned().unwrap_or_default() {
            if let Ok(fo) = self.resolve(&f)
                && let Some(fd) = fo.as_dict()
            {
                if let Some(Obj::Str(t)) = fd.get("T") {
                    names.push(String::from_utf8_lossy(t).into_owned());
                }
                if fd.get("FT").is_some_and(|t| t.is_name("Sig")) && fd.get("V").is_some() {
                    sigs += 1;
                }
            }
        }
        Ok((names, sigs))
    }

    /// Whether the newest section's entries are all expressible in a classic table.
    pub fn has_compressed_objects(&self) -> bool {
        self.xref
            .values()
            .any(|e| matches!(e, XrefEntry::InStream { .. }))
    }

    pub fn sorted_xref(&self) -> BTreeMap<u32, XrefEntry> {
        self.xref.iter().map(|(k, v)| (*k, *v)).collect()
    }
}

#[derive(Clone, Default)]
struct Inherited {
    media_box: Option<[f64; 4]>,
    crop_box: Option<[f64; 4]>,
    rotate: Option<i32>,
}

fn intersect(a: [f64; 4], b: [f64; 4]) -> [f64; 4] {
    let r = [
        a[0].max(b[0]),
        a[1].max(b[1]),
        a[2].min(b[2]),
        a[3].min(b[3]),
    ];
    if r[2] > r[0] && r[3] > r[1] { r } else { b }
}

/// If `obj_at` is the start of an `obj` keyword preceded by `N G`, returns them.
fn obj_header_before(d: &[u8], obj_at: usize) -> Option<(u32, u16, usize)> {
    let mut i = obj_at;
    let take_ws = |i: &mut usize| {
        let s = *i;
        while *i > 0 && is_ws(d[*i - 1]) {
            *i -= 1;
        }
        s != *i
    };
    let take_digits = |i: &mut usize| {
        let e = *i;
        while *i > 0 && d[*i - 1].is_ascii_digit() {
            *i -= 1;
        }
        (*i != e)
            .then(|| std::str::from_utf8(&d[*i..e]).ok())
            .flatten()
    };
    if !take_ws(&mut i) {
        return None;
    }
    let gn = take_digits(&mut i)?.parse().ok()?;
    if !take_ws(&mut i) {
        return None;
    }
    let id = take_digits(&mut i)?.parse().ok()?;
    if i > 0 && !is_ws(d[i - 1]) && !super::object::is_delim(d[i - 1]) {
        return None;
    }
    Some((id, gn, i))
}

pub fn decode_stream(dict: &Dict, raw: &[u8]) -> Result<Vec<u8>> {
    let filters: Vec<Obj> = match dict.get("Filter") {
        None => vec![],
        Some(Obj::Array(a)) => a.clone(),
        Some(o) => vec![o.clone()],
    };
    let parms: Vec<Obj> = match dict.get("DecodeParms") {
        None => vec![],
        Some(Obj::Array(a)) => a.clone(),
        Some(o) => vec![o.clone()],
    };
    let mut data = raw.to_vec();
    for (i, f) in filters.iter().enumerate() {
        if !(f.is_name("FlateDecode") || f.is_name("Fl")) {
            return Err(PdfError::Malformed(
                "unsupported filter on structural stream".into(),
            ));
        }
        let mut out = Vec::new();
        let mut z = flate2::read::ZlibDecoder::new(&data[..]);
        if z.read_to_end(&mut out).is_err() && out.is_empty() {
            return Err(PdfError::Malformed("corrupt compressed stream".into()));
        }
        if let Some(p) = parms.get(i).and_then(Obj::as_dict) {
            out = unpredict(p, out)?;
        }
        data = out;
    }
    Ok(data)
}

fn unpredict(p: &Dict, data: Vec<u8>) -> Result<Vec<u8>> {
    let predictor = p.get("Predictor").and_then(Obj::as_i64).unwrap_or(1);
    if predictor < 10 {
        return Ok(data);
    }
    let colors = p.get("Colors").and_then(Obj::as_i64).unwrap_or(1) as usize;
    let bpc = p.get("BitsPerComponent").and_then(Obj::as_i64).unwrap_or(8) as usize;
    let columns = p.get("Columns").and_then(Obj::as_i64).unwrap_or(1) as usize;
    let bpp = (colors * bpc).div_ceil(8).max(1);
    let row = (colors * bpc * columns).div_ceil(8);
    let mut out = Vec::with_capacity(data.len());
    let mut prev = vec![0u8; row];
    for chunk in data.chunks(row + 1) {
        if chunk.len() < row + 1 {
            break;
        }
        let ft = chunk[0];
        let mut cur = chunk[1..].to_vec();
        for i in 0..row {
            let a = if i >= bpp { cur[i - bpp] as i32 } else { 0 };
            let b = prev[i] as i32;
            let c = if i >= bpp { prev[i - bpp] as i32 } else { 0 };
            let add = match ft {
                0 => 0,
                1 => a,
                2 => b,
                3 => (a + b) / 2,
                4 => {
                    let pp = a + b - c;
                    let (pa, pb, pc) = ((pp - a).abs(), (pp - b).abs(), (pp - c).abs());
                    if pa <= pb && pa <= pc {
                        a
                    } else if pb <= pc {
                        b
                    } else {
                        c
                    }
                }
                _ => return Err(PdfError::Malformed("bad PNG predictor".into())),
            };
            cur[i] = cur[i].wrapping_add(add as u8);
        }
        out.extend_from_slice(&cur);
        prev = cur;
    }
    Ok(out)
}

pub fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

pub fn rfind(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).rposition(|w| w == needle)
}
