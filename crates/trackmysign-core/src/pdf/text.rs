//! The text on a page and where it is: enough to find a phrase such as
//! "Authorised Signatory" and the box around it, not a faithful text
//! extractor. Shows text with `Tj`, `TJ`, `'` and `"`, follows the text
//! and graphics matrices (also into form XObjects) and decodes simple fonts
//! (WinAnsi, Standard and MacRoman encodings with `/Differences`) and
//! composite fonts through their `/ToUnicode` map. Text that cannot be
//! decoded is read as U+FFFD, so it never matches a phrase.

use std::collections::HashMap;
use std::rc::Rc;

use super::appearance::code_width;
use super::object::{Dict, Lexer, Obj, Tok};
use super::reader::{Document, PageInfo, PdfError, Result, decode_stream};
use super::sign::DisplayRect;
use crate::stamp::FontFamily;

/// A line of text as it reads on the displayed page.
#[derive(Debug, Clone)]
pub struct Line {
    pub text: String,
    /// Display-space box of each `char` of `text`, `[x0, y0, x1, y1]`
    /// (points, origin at the top-left of the displayed page).
    pub boxes: Vec<[f64; 4]>,
}

impl Line {
    /// Box around chars `from..to` of `text`.
    pub fn span(&self, from: usize, to: usize) -> DisplayRect {
        let b = &self.boxes[from..to.max(from + 1).min(self.boxes.len())];
        let x0 = b.iter().map(|r| r[0]).fold(f64::INFINITY, f64::min);
        let y0 = b.iter().map(|r| r[1]).fold(f64::INFINITY, f64::min);
        let x1 = b.iter().map(|r| r[2]).fold(f64::NEG_INFINITY, f64::max);
        let y1 = b.iter().map(|r| r[3]).fold(f64::NEG_INFINITY, f64::max);
        DisplayRect {
            x: x0,
            y: y0,
            w: x1 - x0,
            h: y1 - y0,
        }
    }

    pub fn bounds(&self) -> DisplayRect {
        self.span(0, self.boxes.len())
    }
}

/// Form XObjects inside form XObjects are followed this deep.
const MAX_FORM_DEPTH: usize = 8;
/// Glyphs read from one page at most; the rest of a huge page is skipped.
const MAX_GLYPHS: usize = 200_000;

/// The lines of text on `page`, top to bottom as read. A page whose
/// content cannot be read gives what was read before the problem.
pub fn page_lines(doc: &Document, page: &PageInfo) -> Result<Vec<Line>> {
    let resources = inherited(doc, &page.dict, "Resources")
        .and_then(|r| doc.resolve(&r).ok())
        .and_then(|r| r.as_dict().cloned())
        .unwrap_or_default();
    let content = page_content(doc, &page.dict)?;
    let mut reader = Reader {
        doc,
        fonts: HashMap::new(),
        glyphs: Vec::new(),
        to_display: DisplayMap::new(page),
    };
    reader.run(&content, &resources, Matrix::IDENTITY, 0);
    Ok(lines(reader.glyphs))
}

/// A page attribute, looked up the `/Parent` chain when the page lacks it.
fn inherited(doc: &Document, page: &Dict, key: &str) -> Option<Obj> {
    let mut node = page.clone();
    for _ in 0..32 {
        if let Some(v) = node.get(key) {
            return Some(v.clone());
        }
        node = doc.resolve(node.get("Parent")?).ok()?.as_dict()?.clone();
    }
    None
}

/// The page's content streams, decoded and joined.
fn page_content(doc: &Document, page: &Dict) -> Result<Vec<u8>> {
    let contents = match page.get("Contents") {
        Some(c) => doc.resolve(c)?,
        None => return Ok(Vec::new()),
    };
    let parts = match contents {
        Obj::Array(a) => a,
        o => vec![o],
    };
    let mut out = Vec::new();
    for part in parts {
        // A stream with a filter we cannot decode adds nothing.
        if let Ok(Obj::Stream(d, raw)) = doc.resolve(&part)
            && let Ok(data) = decode(&d, &raw)
        {
            out.extend_from_slice(&data);
            out.push(b'\n');
        }
    }
    Ok(out)
}

/// [`decode_stream`], also taking the ASCII filters some producers put in
/// front of Flate.
fn decode(dict: &Dict, raw: &[u8]) -> Result<Vec<u8>> {
    let filters: Vec<Obj> = match dict.get("Filter") {
        None => return Ok(raw.to_vec()),
        Some(Obj::Array(a)) => a.clone(),
        Some(o) => vec![o.clone()],
    };
    let parms = match dict.get("DecodeParms") {
        Some(Obj::Array(a)) => a.clone(),
        Some(o) => vec![o.clone()],
        None => vec![],
    };
    let mut data = raw.to_vec();
    for (i, f) in filters.iter().enumerate() {
        data = if f.is_name("ASCII85Decode") || f.is_name("A85") {
            ascii85(&data)?
        } else if f.is_name("ASCIIHexDecode") || f.is_name("AHx") {
            ascii_hex(&data)
        } else {
            let mut one = Dict::new().with("Filter", f.clone());
            if let Some(p) = parms.get(i).filter(|p| !matches!(p, Obj::Null)) {
                one.set("DecodeParms", p.clone());
            }
            decode_stream(&one, &data)?
        };
    }
    Ok(data)
}

fn ascii85(data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(data.len() * 4 / 5);
    let mut group = [0u8; 5];
    let mut n = 0;
    let body = data.strip_prefix(b"<~").unwrap_or(data);
    for &c in body {
        match c {
            b'~' => break,
            b'z' if n == 0 => out.extend_from_slice(&[0; 4]),
            b'!'..=b'u' => {
                group[n] = c - b'!';
                n += 1;
                if n == 5 {
                    let v = group.iter().fold(0u64, |v, &d| v * 85 + d as u64);
                    if v > u32::MAX as u64 {
                        return Err(PdfError::Malformed("bad ASCII85 data".into()));
                    }
                    out.extend_from_slice(&(v as u32).to_be_bytes());
                    n = 0;
                }
            }
            _ => {}
        }
    }
    if n > 1 {
        for slot in group.iter_mut().skip(n) {
            *slot = 84;
        }
        let v = group.iter().fold(0u64, |v, &d| v * 85 + d as u64);
        out.extend_from_slice(&(v.min(u32::MAX as u64) as u32).to_be_bytes()[..n - 1]);
    }
    Ok(out)
}

fn ascii_hex(data: &[u8]) -> Vec<u8> {
    let digits: Vec<u8> = data
        .iter()
        .take_while(|&&c| c != b'>')
        .filter_map(|&c| (c as char).to_digit(16).map(|d| d as u8))
        .collect();
    digits
        .chunks(2)
        .map(|p| p[0] << 4 | p.get(1).copied().unwrap_or(0))
        .collect()
}

// ---------------------------------------------------------------- geometry

#[derive(Debug, Clone, Copy, PartialEq)]
struct Matrix([f64; 6]);

impl Matrix {
    const IDENTITY: Matrix = Matrix([1.0, 0.0, 0.0, 1.0, 0.0, 0.0]);

    fn from_operands(ops: &[Obj]) -> Option<Matrix> {
        if ops.len() < 6 {
            return None;
        }
        let mut m = [0.0; 6];
        for (slot, o) in m.iter_mut().zip(&ops[ops.len() - 6..]) {
            *slot = o.as_f64()?;
        }
        Some(Matrix(m))
    }

    fn translate(x: f64, y: f64) -> Matrix {
        Matrix([1.0, 0.0, 0.0, 1.0, x, y])
    }

    /// `self` applied first, then `other`.
    fn then(&self, other: &Matrix) -> Matrix {
        let [a, b, c, d, e, f] = self.0;
        let [a2, b2, c2, d2, e2, f2] = other.0;
        Matrix([
            a * a2 + b * c2,
            a * b2 + b * d2,
            c * a2 + d * c2,
            c * b2 + d * d2,
            e * a2 + f * c2 + e2,
            e * b2 + f * d2 + f2,
        ])
    }

    fn apply(&self, x: f64, y: f64) -> (f64, f64) {
        let [a, b, c, d, e, f] = self.0;
        (a * x + c * y + e, b * x + d * y + f)
    }
}

/// User space to the displayed page (cropped, rotated, y down).
struct DisplayMap {
    crop: [f64; 4],
    rotate: i32,
}

impl DisplayMap {
    fn new(page: &PageInfo) -> Self {
        DisplayMap {
            crop: page.crop_box,
            rotate: page.rotate,
        }
    }

    fn map(&self, ux: f64, uy: f64) -> (f64, f64) {
        let [cx0, cy0, cx1, cy1] = self.crop;
        match self.rotate {
            90 => (uy - cy0, ux - cx0),
            180 => (cx1 - ux, uy - cy0),
            270 => (cy1 - uy, cx1 - ux),
            _ => (ux - cx0, cy1 - uy),
        }
    }
}

// ------------------------------------------------------------------- fonts

struct Font {
    /// Composite (Type0) font: codes of one or more bytes, see `ranges`.
    composite: bool,
    /// `(bytes, low, high)` code space ranges of a composite font.
    ranges: Vec<CodeRange>,
    to_unicode: HashMap<u32, String>,
    /// Simple fonts: the text of each code from the encoding.
    encoding: Vec<String>,
    /// Glyph widths in text space units (thousandths already applied).
    widths: HashMap<u32, f64>,
    default_width: f64,
    ascent: f64,
    descent: f64,
}

impl Font {
    fn load(doc: &Document, dict: &Dict) -> Font {
        let r = |o: Option<&Obj>| o.and_then(|o| doc.resolve(o).ok());
        let subtype = dict.get("Subtype");
        let composite = subtype.is_some_and(|s| s.is_name("Type0"));
        let to_unicode = match r(dict.get("ToUnicode")) {
            Some(Obj::Stream(d, raw)) => decode(&d, &raw)
                .map(|data| parse_cmap(&data).1)
                .unwrap_or_default(),
            _ => HashMap::new(),
        };
        let mut font = Font {
            composite,
            ranges: Vec::new(),
            to_unicode,
            encoding: Vec::new(),
            widths: HashMap::new(),
            default_width: 0.0,
            ascent: 0.8,
            descent: -0.2,
        };
        let descriptor;
        if composite {
            font.ranges = match r(dict.get("Encoding")) {
                Some(Obj::Stream(d, raw)) => decode(&d, &raw)
                    .map(|data| parse_cmap(&data).0)
                    .unwrap_or_default(),
                _ => Vec::new(),
            };
            if font.ranges.is_empty() {
                // Identity-H and the other predefined CMaps in use are two-byte.
                font.ranges.push((2, 0, 0xffff));
            }
            let cid_font = r(dict.get("DescendantFonts"))
                .and_then(|a| a.as_array().and_then(|a| a.first().cloned()))
                .and_then(|f| doc.resolve(&f).ok())
                .and_then(|f| f.as_dict().cloned())
                .unwrap_or_default();
            font.default_width = r(cid_font.get("DW"))
                .and_then(|w| w.as_f64())
                .unwrap_or(1000.0)
                / 1000.0;
            if let Some(Obj::Array(w)) = r(cid_font.get("W")) {
                cid_widths(doc, &w, &mut font.widths);
            }
            descriptor = r(cid_font.get("FontDescriptor"));
        } else {
            let base = match dict.get("BaseFont") {
                Some(Obj::Name(n)) => n.clone(),
                _ => Vec::new(),
            };
            font.encoding = simple_encoding(doc, dict, &base);
            let type3 = subtype.is_some_and(|s| s.is_name("Type3"));
            // Type 3 widths are in glyph space, scaled by the font matrix.
            let scale = if type3 {
                match r(dict.get("FontMatrix")) {
                    Some(Obj::Array(m)) => m.first().and_then(Obj::as_f64).unwrap_or(0.001),
                    _ => 0.001,
                }
            } else {
                0.001
            };
            descriptor = r(dict.get("FontDescriptor"));
            let first = r(dict.get("FirstChar"))
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            match r(dict.get("Widths")) {
                Some(Obj::Array(w)) => {
                    for (i, v) in w.iter().enumerate() {
                        if let Some(v) = doc.resolve(v).ok().and_then(|v| v.as_f64()) {
                            font.widths.insert((first + i as i64) as u32, v * scale);
                        }
                    }
                    font.default_width = descriptor
                        .as_ref()
                        .and_then(|d| d.as_dict()?.get("MissingWidth")?.as_f64())
                        .unwrap_or(0.0)
                        * scale;
                }
                _ => {
                    // The standard 14 fonts may come without widths.
                    let (family, bold) = standard_family(&base);
                    for code in 0..=255u8 {
                        font.widths
                            .insert(code as u32, code_width(code, family, bold) / 1000.0);
                    }
                    font.default_width = 0.5;
                }
            }
            if type3 {
                return font;
            }
        }
        if let Some(d) = descriptor.as_ref().and_then(Obj::as_dict) {
            let num = |k: &str| {
                d.get(k)
                    .and_then(|v| doc.resolve(v).ok())
                    .and_then(|v| v.as_f64())
            };
            if let Some(a) = num("Ascent").map(|a| a / 1000.0)
                && a > 0.3
                && a < 1.5
            {
                font.ascent = a;
            }
            if let Some(dsc) = num("Descent").map(|d| d / 1000.0)
                && dsc < 0.0
                && dsc > -1.0
            {
                font.descent = dsc;
            }
        }
        font
    }

    /// Splits a string into codes, each with its byte count.
    fn codes(&self, s: &[u8]) -> Vec<(u32, usize)> {
        if !self.composite {
            return s.iter().map(|&b| (b as u32, 1)).collect();
        }
        let mut out = Vec::new();
        let mut i = 0;
        while i < s.len() {
            let mut code = 0u32;
            let mut len = 0;
            for n in 1..=4.min(s.len() - i) {
                code = (code << 8) | s[i + n - 1] as u32;
                if self
                    .ranges
                    .iter()
                    .any(|&(bytes, lo, hi)| bytes == n && (lo..=hi).contains(&code))
                {
                    len = n;
                    break;
                }
            }
            if len == 0 {
                // Not in any range: take the shortest code length used.
                len = self
                    .ranges
                    .iter()
                    .map(|r| r.0)
                    .min()
                    .unwrap_or(1)
                    .min(s.len() - i);
                code = s[i..i + len].iter().fold(0, |c, &b| (c << 8) | b as u32);
            }
            out.push((code, len));
            i += len;
        }
        out
    }

    fn text(&self, code: u32) -> String {
        if let Some(t) = self.to_unicode.get(&code) {
            return t.clone();
        }
        match self.encoding.get(code as usize) {
            Some(t) if !self.composite && !t.is_empty() => t.clone(),
            _ => "\u{fffd}".into(),
        }
    }

    fn width(&self, code: u32) -> f64 {
        self.widths
            .get(&code)
            .copied()
            .unwrap_or(self.default_width)
    }
}

/// `/W` of a CID font: `c [w1 w2 …]` and `first last w`.
fn cid_widths(doc: &Document, w: &[Obj], out: &mut HashMap<u32, f64>) {
    let mut i = 0;
    while i < w.len() {
        let Some(first) = w[i].as_i64() else {
            i += 1;
            continue;
        };
        match w.get(i + 1).map(|o| doc.resolve(o)) {
            Some(Ok(Obj::Array(list))) => {
                for (k, v) in list.iter().enumerate() {
                    if let Some(v) = v.as_f64() {
                        out.insert(first as u32 + k as u32, v / 1000.0);
                    }
                }
                i += 2;
            }
            Some(Ok(last)) => {
                if let (Some(last), Some(v)) = (last.as_i64(), w.get(i + 2).and_then(Obj::as_f64)) {
                    // A bogus huge range is not worth a map entry per code.
                    for c in first..=last.min(first + 0xffff) {
                        out.insert(c as u32, v / 1000.0);
                    }
                }
                i += 3;
            }
            _ => break,
        }
    }
}

fn standard_family(base: &[u8]) -> (FontFamily, bool) {
    let name = String::from_utf8_lossy(base).to_ascii_lowercase();
    // A subset prefix such as `ABCDEF+` does not matter.
    let name = name.rsplit('+').next().unwrap_or_default().to_string();
    let family = if name.starts_with("times") {
        FontFamily::Times
    } else if name.starts_with("courier") {
        FontFamily::Courier
    } else {
        FontFamily::Helvetica
    };
    (family, name.contains("bold"))
}

/// The text of each code of a simple font: its base encoding (the font's
/// `/BaseEncoding`, or Standard for a Type 1 font, WinAnsi otherwise) with
/// the `/Differences` applied.
fn simple_encoding(doc: &Document, font: &Dict, base: &[u8]) -> Vec<String> {
    let enc = font.get("Encoding").and_then(|e| doc.resolve(e).ok());
    let named = |n: &Obj| match n {
        Obj::Name(n) => Some(n.clone()),
        _ => None,
    };
    let (base_name, differences) = match &enc {
        Some(o @ Obj::Name(_)) => (named(o), None),
        Some(Obj::Dict(d)) => (
            d.get("BaseEncoding").and_then(named),
            d.get("Differences").and_then(|v| doc.resolve(v).ok()),
        ),
        _ => (None, None),
    };
    let symbolic = base.ends_with(b"Symbol") || base.ends_with(b"Dingbats");
    let type1 = font.get("Subtype").is_some_and(|s| s.is_name("Type1"));
    let mut table: Vec<String> = (0..=255u8)
        .map(|c| match base_name.as_deref() {
            Some(b"MacRomanEncoding") => mac_roman(c),
            Some(b"WinAnsiEncoding") => win_ansi(c),
            Some(b"StandardEncoding") => standard(c),
            _ if symbolic => None,
            _ if type1 => standard(c),
            _ => win_ansi(c),
        })
        .map(|c| c.map(String::from).unwrap_or_default())
        .collect();
    if let Some(Obj::Array(diff)) = differences {
        let mut code = 0usize;
        for item in diff {
            match item {
                Obj::Num(_) => code = item.as_i64().unwrap_or(0).max(0) as usize,
                Obj::Name(n) => {
                    if let Some(slot) = table.get_mut(code) {
                        *slot = glyph_text(&String::from_utf8_lossy(&n)).unwrap_or_default();
                    }
                    code += 1;
                }
                _ => {}
            }
        }
    }
    table
}

fn win_ansi(c: u8) -> Option<char> {
    const HIGH: &str = "€\u{fffd}‚ƒ„…†‡ˆ‰Š‹Œ\u{fffd}Ž\u{fffd}\u{fffd}‘’“”•–—˜™š›œ\u{fffd}žŸ";
    match c {
        0x20..=0x7e | 0xa0..=0xff => Some(c as char),
        0x80..=0x9f => HIGH.chars().nth((c - 0x80) as usize),
        _ => None,
    }
}

fn mac_roman(c: u8) -> Option<char> {
    const HIGH: &str = "ÄÅÇÉÑÖÜáàâäãåçéèêëíìîïñóòôöõúùûü†°¢£§•¶ß®©™´¨≠ÆØ∞±≤≥¥µ∂∑∏π∫ªºΩæø\
                        ¿¡¬√ƒ≈∆«»…\u{a0}ÀÃÕŒœ–—“”‘’÷◊ÿŸ⁄¤‹›ﬁﬂ‡·‚„‰ÂÊÁËÈÍÎÏÌÓÔ\u{fffd}ÒÚÛÙıˆ˜¯˘˙˚¸˝˛ˇ";
    match c {
        0x20..=0x7e => Some(c as char),
        0x80..=0xff => HIGH.chars().nth((c - 0x80) as usize),
        _ => None,
    }
}

fn standard(c: u8) -> Option<char> {
    Some(match c {
        0x27 => '’',
        0x60 => '‘',
        0x20..=0x7e => c as char,
        0xa1 => '¡',
        0xa2 => '¢',
        0xa3 => '£',
        0xa4 => '⁄',
        0xa5 => '¥',
        0xa6 => 'ƒ',
        0xa7 => '§',
        0xa8 => '¤',
        0xa9 => '\'',
        0xaa => '“',
        0xab => '«',
        0xac => '‹',
        0xad => '›',
        0xae => 'ﬁ',
        0xaf => 'ﬂ',
        0xb1 => '–',
        0xb2 => '†',
        0xb3 => '‡',
        0xb4 => '·',
        0xb6 => '¶',
        0xb7 => '•',
        0xb8 => '‚',
        0xb9 => '„',
        0xba => '”',
        0xbb => '»',
        0xbc => '…',
        0xbd => '‰',
        0xbf => '¿',
        0xc1 => '`',
        0xc2 => '´',
        0xc3 => 'ˆ',
        0xc4 => '˜',
        0xc5 => '¯',
        0xc6 => '˘',
        0xc7 => '˙',
        0xc8 => '¨',
        0xca => '˚',
        0xcb => '¸',
        0xcd => '˝',
        0xce => '˛',
        0xcf => 'ˇ',
        0xd0 => '—',
        0xe1 => 'Æ',
        0xe3 => 'ª',
        0xe8 => 'Ł',
        0xe9 => 'Ø',
        0xea => 'Œ',
        0xeb => 'º',
        0xf1 => 'æ',
        0xf5 => 'ı',
        0xf8 => 'ł',
        0xf9 => 'ø',
        0xfa => 'œ',
        0xfb => 'ß',
        _ => return None,
    })
}

/// Text of a glyph name from `/Differences`: `uniXXXX`, `uXXXX`, the names
/// of letters, digits and punctuation, and names the encodings above use.
fn glyph_text(name: &str) -> Option<String> {
    // `a.sc`, `one.oldstyle`: the part before the dot.
    let name = name.split('.').next().unwrap_or(name);
    if let Some(hex) = name.strip_prefix("uni")
        && hex.len() >= 4
        && hex.len() % 4 == 0
    {
        let units: Option<Vec<u16>> = hex
            .as_bytes()
            .chunks(4)
            .map(|c| u16::from_str_radix(std::str::from_utf8(c).ok()?, 16).ok())
            .collect();
        return Some(String::from_utf16_lossy(&units?));
    }
    if let Some(hex) = name.strip_prefix('u')
        && (4..=6).contains(&hex.len())
        && let Ok(v) = u32::from_str_radix(hex, 16)
    {
        return char::from_u32(v).map(String::from);
    }
    if name.len() == 1 && name.as_bytes()[0].is_ascii_alphabetic() {
        return Some(name.into());
    }
    const DIGITS: [&str; 10] = [
        "zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine",
    ];
    if let Some(d) = DIGITS.iter().position(|d| *d == name) {
        return Some(d.to_string());
    }
    let s = match name {
        "space" | "nbspace" | "nonbreakingspace" => " ",
        "exclam" => "!",
        "quotedbl" => "\"",
        "numbersign" => "#",
        "dollar" => "$",
        "percent" => "%",
        "ampersand" => "&",
        "quotesingle" => "'",
        "quoteright" => "’",
        "quoteleft" => "‘",
        "parenleft" => "(",
        "parenright" => ")",
        "asterisk" => "*",
        "plus" => "+",
        "comma" => ",",
        "hyphen" | "minus" => "-",
        "period" => ".",
        "slash" => "/",
        "colon" => ":",
        "semicolon" => ";",
        "less" => "<",
        "equal" => "=",
        "greater" => ">",
        "question" => "?",
        "at" => "@",
        "bracketleft" => "[",
        "backslash" => "\\",
        "bracketright" => "]",
        "asciicircum" => "^",
        "underscore" => "_",
        "grave" => "`",
        "braceleft" => "{",
        "bar" => "|",
        "braceright" => "}",
        "asciitilde" => "~",
        "endash" => "–",
        "emdash" => "—",
        "bullet" => "•",
        "quotedblleft" => "“",
        "quotedblright" => "”",
        "ellipsis" => "…",
        "fi" => "fi",
        "fl" => "fl",
        "ff" => "ff",
        "ffi" => "ffi",
        "ffl" => "ffl",
        "rupee" | "rupeeindian" => "₹",
        _ => return None,
    };
    Some(s.into())
}

/// A code space range: bytes per code, lowest and highest code.
type CodeRange = (usize, u32, u32);

/// Code space ranges and `bfchar` / `bfrange` mappings of a CMap.
fn parse_cmap(data: &[u8]) -> (Vec<CodeRange>, HashMap<u32, String>) {
    let mut lx = Lexer::new(data, 0);
    let mut toks = Vec::new();
    while let Ok(Some(t)) = lx.next_tok() {
        toks.push(t);
    }
    let code = |b: &[u8]| b.iter().take(4).fold(0u32, |c, &x| (c << 8) | x as u32);
    let utf16 = |b: &[u8]| {
        let units: Vec<u16> = b
            .chunks(2)
            .map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]))
            .collect();
        String::from_utf16_lossy(&units)
    };
    let mut ranges = Vec::new();
    let mut map = HashMap::new();
    let mut i = 0;
    while i < toks.len() {
        let Tok::Kw(k) = &toks[i] else {
            i += 1;
            continue;
        };
        i += 1;
        match k.as_slice() {
            b"begincodespacerange" => {
                while let (Some(Tok::Str(lo)), Some(Tok::Str(hi))) = (toks.get(i), toks.get(i + 1))
                {
                    ranges.push((lo.len(), code(lo), code(hi)));
                    i += 2;
                }
            }
            b"beginbfchar" => {
                while let (Some(Tok::Str(src)), Some(Tok::Str(dst))) =
                    (toks.get(i), toks.get(i + 1))
                {
                    map.insert(code(src), utf16(dst));
                    i += 2;
                }
            }
            b"beginbfrange" => {
                while let (Some(Tok::Str(lo)), Some(Tok::Str(hi))) = (toks.get(i), toks.get(i + 1))
                {
                    let (lo, hi) = (code(lo), code(hi));
                    // Ranges are meant to stay within one last byte.
                    let hi = hi.min(lo.saturating_add(0xffff));
                    match toks.get(i + 2) {
                        Some(Tok::Str(dst)) => {
                            let mut units: Vec<u16> = dst
                                .chunks(2)
                                .map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]))
                                .collect();
                            for c in lo..=hi {
                                map.insert(c, String::from_utf16_lossy(&units));
                                if let Some(last) = units.last_mut() {
                                    *last = last.wrapping_add(1);
                                }
                            }
                            i += 3;
                        }
                        Some(Tok::ArrOpen) => {
                            i += 3;
                            let mut c = lo;
                            while let Some(Tok::Str(dst)) = toks.get(i) {
                                if c <= hi {
                                    map.insert(c, utf16(dst));
                                }
                                c += 1;
                                i += 1;
                            }
                            if toks.get(i) == Some(&Tok::ArrClose) {
                                i += 1;
                            }
                        }
                        _ => break,
                    }
                }
            }
            _ => {}
        }
    }
    (ranges, map)
}

// ------------------------------------------------------------------ reader

#[derive(Clone)]
struct State {
    ctm: Matrix,
    font: Option<Rc<Font>>,
    size: f64,
    char_spacing: f64,
    word_spacing: f64,
    scale: f64,
    leading: f64,
    rise: f64,
}

/// One glyph as shown, in display space.
struct Glyph {
    ch: char,
    /// Reading direction on the displayed page, in quarter turns clockwise.
    turn: u8,
    /// Along the line: where the glyph starts and ends.
    u0: f64,
    u1: f64,
    /// Across the line: the baseline, increasing downwards as read.
    v: f64,
    /// Font size as displayed.
    size: f64,
    rect: [f64; 4],
}

struct Reader<'d, 'a> {
    doc: &'d Document<'a>,
    fonts: HashMap<u32, Rc<Font>>,
    glyphs: Vec<Glyph>,
    to_display: DisplayMap,
}

impl Reader<'_, '_> {
    fn run(&mut self, content: &[u8], resources: &Dict, ctm: Matrix, depth: usize) {
        let mut gs = State {
            ctm,
            font: None,
            size: 0.0,
            char_spacing: 0.0,
            word_spacing: 0.0,
            scale: 1.0,
            leading: 0.0,
            rise: 0.0,
        };
        let mut stack: Vec<State> = Vec::new();
        let mut tm = Matrix::IDENTITY;
        let mut tlm = Matrix::IDENTITY;
        let mut ops: Vec<Obj> = Vec::new();
        let mut lx = Lexer::new(content, 0);
        loop {
            if self.glyphs.len() > MAX_GLYPHS {
                return;
            }
            let tok = match lx.next_tok() {
                Ok(Some(t)) => t,
                _ => return,
            };
            let op = match tok {
                Tok::Kw(k) if !matches!(k.as_slice(), b"true" | b"false" | b"null") => k,
                t => {
                    match operand(&mut lx, t, 0) {
                        Some(o) => ops.push(o),
                        None => return,
                    }
                    continue;
                }
            };
            let num = |i: usize| -> f64 {
                ops.len()
                    .checked_sub(i)
                    .and_then(|k| ops.get(k))
                    .and_then(Obj::as_f64)
                    .unwrap_or(0.0)
            };
            match op.as_slice() {
                b"q" => stack.push(gs.clone()),
                b"Q" => {
                    if let Some(s) = stack.pop() {
                        gs = s;
                    }
                }
                b"cm" => {
                    if let Some(m) = Matrix::from_operands(&ops) {
                        gs.ctm = m.then(&gs.ctm);
                    }
                }
                b"BT" => {
                    tm = Matrix::IDENTITY;
                    tlm = Matrix::IDENTITY;
                }
                b"Tf" => {
                    gs.size = num(1);
                    gs.font = match ops.len().checked_sub(2).and_then(|i| ops.get(i)) {
                        Some(Obj::Name(n)) => self.font(resources, n),
                        _ => None,
                    };
                }
                b"Tc" => gs.char_spacing = num(1),
                b"Tw" => gs.word_spacing = num(1),
                b"Tz" => gs.scale = num(1) / 100.0,
                b"TL" => gs.leading = num(1),
                b"Ts" => gs.rise = num(1),
                b"Td" => {
                    tlm = Matrix::translate(num(2), num(1)).then(&tlm);
                    tm = tlm;
                }
                b"TD" => {
                    gs.leading = -num(1);
                    tlm = Matrix::translate(num(2), num(1)).then(&tlm);
                    tm = tlm;
                }
                b"Tm" => {
                    if let Some(m) = Matrix::from_operands(&ops) {
                        tlm = m;
                        tm = m;
                    }
                }
                b"T*" => {
                    tlm = Matrix::translate(0.0, -gs.leading).then(&tlm);
                    tm = tlm;
                }
                b"Tj" => {
                    if let Some(Obj::Str(s)) = ops.last() {
                        self.show(s, &gs, &mut tm);
                    }
                }
                b"'" | b"\"" => {
                    if op == b"\"" {
                        gs.word_spacing = num(3);
                        gs.char_spacing = num(2);
                    }
                    tlm = Matrix::translate(0.0, -gs.leading).then(&tlm);
                    tm = tlm;
                    if let Some(Obj::Str(s)) = ops.last() {
                        self.show(s, &gs, &mut tm);
                    }
                }
                b"TJ" => {
                    if let Some(Obj::Array(items)) = ops.last() {
                        for item in items {
                            match item {
                                Obj::Str(s) => self.show(s, &gs, &mut tm),
                                o => {
                                    let adj = o.as_f64().unwrap_or(0.0);
                                    tm = Matrix::translate(-adj / 1000.0 * gs.size * gs.scale, 0.0)
                                        .then(&tm);
                                }
                            }
                        }
                    }
                }
                b"Do" => {
                    if let Some(Obj::Name(n)) = ops.last() {
                        self.form(resources, n, &gs, depth);
                    }
                }
                b"BI" => skip_inline_image(&mut lx),
                _ => {}
            }
            ops.clear();
        }
    }

    fn font(&mut self, resources: &Dict, name: &[u8]) -> Option<Rc<Font>> {
        let doc = self.doc;
        let fonts = doc.resolve(resources.get("Font")?).ok()?;
        let entry = fonts
            .as_dict()?
            .0
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())?;
        if let Obj::Ref(id, _) = entry
            && let Some(f) = self.fonts.get(&id)
        {
            return Some(f.clone());
        }
        let dict = doc.resolve(&entry).ok()?.as_dict()?.clone();
        let font = Rc::new(Font::load(doc, &dict));
        if let Obj::Ref(id, _) = entry {
            self.fonts.insert(id, font.clone());
        }
        Some(font)
    }

    fn form(&mut self, resources: &Dict, name: &[u8], gs: &State, depth: usize) {
        if depth >= MAX_FORM_DEPTH {
            return;
        }
        let doc = self.doc;
        let Some(xobjects) = resources.get("XObject").and_then(|x| doc.resolve(x).ok()) else {
            return;
        };
        let Some(entry) = xobjects
            .as_dict()
            .and_then(|d| d.0.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone()))
        else {
            return;
        };
        let Ok(Obj::Stream(dict, raw)) = doc.resolve(&entry) else {
            return;
        };
        if !dict.get("Subtype").is_some_and(|s| s.is_name("Form")) {
            return;
        }
        let Ok(content) = decode(&dict, &raw) else {
            return;
        };
        let matrix = match dict.get("Matrix").and_then(|m| doc.resolve(m).ok()) {
            Some(Obj::Array(m)) => Matrix::from_operands(&m).unwrap_or(Matrix::IDENTITY),
            _ => Matrix::IDENTITY,
        };
        let own = dict
            .get("Resources")
            .and_then(|r| doc.resolve(r).ok())
            .and_then(|r| r.as_dict().cloned());
        let res = own.unwrap_or_else(|| resources.clone());
        self.run(&content, &res, matrix.then(&gs.ctm), depth + 1);
    }

    /// Shows a string: records each glyph and moves the text matrix on.
    fn show(&mut self, s: &[u8], gs: &State, tm: &mut Matrix) {
        let Some(font) = gs.font.clone() else {
            return;
        };
        for (code, len) in font.codes(s) {
            let w0 = font.width(code);
            let trm = Matrix([gs.size * gs.scale, 0.0, 0.0, gs.size, 0.0, gs.rise])
                .then(tm)
                .then(&gs.ctm);
            self.glyph(&font.text(code), &font, w0, &trm);
            let space = if len == 1 && code == 32 {
                gs.word_spacing
            } else {
                0.0
            };
            let tx = (w0 * gs.size + gs.char_spacing + space) * gs.scale;
            *tm = Matrix::translate(tx, 0.0).then(tm);
        }
    }

    /// Records the glyph(s) of `text`, drawn with `trm` and `w0` wide.
    fn glyph(&mut self, text: &str, font: &Font, w0: f64, trm: &Matrix) {
        let d = |x: f64, y: f64| {
            let (ux, uy) = trm.apply(x, y);
            self.to_display.map(ux, uy)
        };
        let o = d(0.0, 0.0);
        let along = d(1.0, 0.0);
        let up = d(0.0, 1.0);
        let size = ((up.0 - o.0).powi(2) + (up.1 - o.1).powi(2)).sqrt();
        if !(size > 0.01 && size.is_finite()) {
            return;
        }
        let angle = (along.1 - o.1)
            .atan2(along.0 - o.0)
            .to_degrees()
            .rem_euclid(360.0);
        let turn = ((angle + 45.0) / 90.0).floor() as i64 % 4;
        // Diagonal text (watermarks) is not part of any line.
        if (angle - turn as f64 * 90.0)
            .abs()
            .min(360.0 - (angle - turn as f64 * 90.0).abs())
            > 20.0
        {
            return;
        }
        let (dx, dy) = [(1.0, 0.0), (0.0, 1.0), (-1.0, 0.0), (0.0, -1.0)][turn as usize];
        let frame = |p: (f64, f64)| (p.0 * dx + p.1 * dy, p.1 * dx - p.0 * dy);
        let corners = [
            d(0.0, font.descent),
            d(w0, font.descent),
            d(0.0, font.ascent),
            d(w0, font.ascent),
        ];
        let rect = [
            corners.iter().map(|c| c.0).fold(f64::INFINITY, f64::min),
            corners.iter().map(|c| c.1).fold(f64::INFINITY, f64::min),
            corners
                .iter()
                .map(|c| c.0)
                .fold(f64::NEG_INFINITY, f64::max),
            corners
                .iter()
                .map(|c| c.1)
                .fold(f64::NEG_INFINITY, f64::max),
        ];
        let (u0, v) = frame(o);
        let (u1, _) = frame(d(w0, 0.0));
        let chars: Vec<char> = text.chars().flat_map(expand_ligature).collect();
        let n = chars.len().max(1) as f64;
        let (along_x, along_y) = ((rect[2] - rect[0]) / n, (rect[3] - rect[1]) / n);
        for (i, ch) in chars.into_iter().enumerate() {
            let k = i as f64;
            // Several chars from one glyph share its box, split along the line.
            let part = match turn {
                0 => [
                    rect[0] + along_x * k,
                    rect[1],
                    rect[0] + along_x * (k + 1.0),
                    rect[3],
                ],
                2 => [
                    rect[2] - along_x * (k + 1.0),
                    rect[1],
                    rect[2] - along_x * k,
                    rect[3],
                ],
                1 => [
                    rect[0],
                    rect[1] + along_y * k,
                    rect[2],
                    rect[1] + along_y * (k + 1.0),
                ],
                _ => [
                    rect[0],
                    rect[3] - along_y * (k + 1.0),
                    rect[2],
                    rect[3] - along_y * k,
                ],
            };
            let step = (u1 - u0) / n;
            self.glyphs.push(Glyph {
                ch,
                turn: turn as u8,
                u0: u0 + step * k,
                u1: u0 + step * (k + 1.0),
                v,
                size,
                rect: part,
            });
        }
    }
}

fn expand_ligature(c: char) -> Vec<char> {
    match c {
        'ﬀ' => vec!['f', 'f'],
        'ﬁ' => vec!['f', 'i'],
        'ﬂ' => vec!['f', 'l'],
        'ﬃ' => vec!['f', 'f', 'i'],
        'ﬄ' => vec!['f', 'f', 'l'],
        'ﬅ' | 'ﬆ' => vec!['s', 't'],
        '\u{a0}' | '\t' => vec![' '],
        c => vec![c],
    }
}

/// An operand starting with `tok`; `None` when the content ends badly.
fn operand(lx: &mut Lexer, tok: Tok, depth: usize) -> Option<Obj> {
    if depth > 32 {
        return None;
    }
    Some(match tok {
        Tok::Num(n) => Obj::Num(n),
        Tok::Str(s) => Obj::Str(s),
        Tok::Name(n) => Obj::Name(n),
        Tok::ArrOpen => {
            let mut items = Vec::new();
            loop {
                match lx.next_tok().ok()?? {
                    Tok::ArrClose => break,
                    t => items.push(operand(lx, t, depth + 1)?),
                }
            }
            Obj::Array(items)
        }
        Tok::DictOpen => {
            // Marked-content properties: read past them.
            let mut d = Dict::new();
            loop {
                match lx.next_tok().ok()?? {
                    Tok::DictClose => break,
                    Tok::Name(k) => {
                        let t = lx.next_tok().ok()??;
                        d.0.push((k, operand(lx, t, depth + 1)?));
                    }
                    _ => {}
                }
            }
            Obj::Dict(d)
        }
        Tok::Kw(k) => match k.as_slice() {
            b"true" => Obj::Bool(true),
            b"false" => Obj::Bool(false),
            _ => Obj::Null,
        },
        Tok::ArrClose | Tok::DictClose => Obj::Null,
    })
}

/// Skips `… ID <data> EI` after `BI`.
fn skip_inline_image(lx: &mut Lexer) {
    while let Ok(Some(t)) = lx.next_tok() {
        if t == Tok::Kw(b"ID".to_vec()) {
            break;
        }
    }
    let d = lx.data;
    let mut i = lx.pos + 1;
    while i + 2 <= d.len() {
        if &d[i..i + 2] == b"EI"
            && i > 0
            && super::object::is_ws(d[i - 1])
            && d.get(i + 2).is_none_or(|&c| super::object::is_ws(c))
        {
            lx.pos = i + 2;
            return;
        }
        i += 1;
    }
    lx.pos = d.len();
}

// ------------------------------------------------------------------- lines

/// Puts glyphs together into lines: same reading direction and baseline,
/// in order along the line, with a space where there is a gap and a new
/// line where the gap is wide (another column).
fn lines(mut glyphs: Vec<Glyph>) -> Vec<Line> {
    glyphs.sort_by(|a, b| {
        a.turn
            .cmp(&b.turn)
            .then(a.v.total_cmp(&b.v))
            .then(a.u0.total_cmp(&b.u0))
    });
    let mut rows: Vec<Vec<Glyph>> = Vec::new();
    for g in glyphs {
        match rows.last_mut() {
            Some(row)
                if row[0].turn == g.turn
                    && (g.v - row[0].v).abs() <= 0.35 * row[0].size.max(g.size) =>
            {
                row.push(g)
            }
            _ => rows.push(vec![g]),
        }
    }
    let mut out = Vec::new();
    for mut row in rows {
        row.sort_by(|a, b| a.u0.total_cmp(&b.u0));
        let mut line = Line {
            text: String::new(),
            boxes: Vec::new(),
        };
        let mut last: Option<&Glyph> = None;
        for g in &row {
            if let Some(p) = last {
                let size = p.size.max(g.size);
                let gap = g.u0 - p.u1;
                // Text drawn twice for a bold effect.
                if g.ch == p.ch && (g.u0 - p.u0).abs() < 0.15 * size {
                    continue;
                }
                if gap > 3.0 * size {
                    finish(&mut line, &mut out);
                } else if gap > 0.2 * size && g.ch != ' ' && !line.text.ends_with(' ') {
                    line.text.push(' ');
                    line.boxes.push([
                        p.rect[2].min(g.rect[0]),
                        p.rect[1],
                        g.rect[0].max(p.rect[2]),
                        p.rect[3],
                    ]);
                }
            }
            if g.ch.is_whitespace() {
                if !line.text.is_empty() && !line.text.ends_with(' ') {
                    line.text.push(' ');
                    line.boxes.push(g.rect);
                }
            } else {
                line.text.push(g.ch);
                line.boxes.push(g.rect);
            }
            last = Some(g);
        }
        finish(&mut line, &mut out);
    }
    out
}

fn finish(line: &mut Line, out: &mut Vec<Line>) {
    while line.text.ends_with(' ') {
        line.text.pop();
        line.boxes.pop();
    }
    if !line.text.is_empty() {
        out.push(std::mem::replace(
            line,
            Line {
                text: String::new(),
                boxes: Vec::new(),
            },
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(data: &[u8]) -> Vec<Vec<Line>> {
        let doc = Document::parse(data).unwrap();
        doc.pages()
            .unwrap()
            .iter()
            .map(|p| page_lines(&doc, p).unwrap())
            .collect()
    }

    fn find<'l>(lines: &'l [Line], s: &str) -> (&'l Line, DisplayRect) {
        for l in lines {
            if let Some(i) = l.text.find(s) {
                let from = l.text[..i].chars().count();
                return (l, l.span(from, from + s.chars().count()));
            }
        }
        panic!(
            "{s:?} not in {:?}",
            lines.iter().map(|l| &l.text).collect::<Vec<_>>()
        );
    }

    fn near(a: f64, b: f64, tol: f64) -> bool {
        (a - b).abs() <= tol
    }

    #[test]
    fn encodings_have_128_high_codes() {
        assert_eq!(mac_roman(0xff), Some('ˇ'));
        assert_eq!(mac_roman(0x80), Some('Ä'));
        assert_eq!(win_ansi(0x80), Some('€'));
        assert_eq!(win_ansi(0x9f), Some('Ÿ'));
        assert_eq!(standard(0x27), Some('’'));
        assert_eq!(glyph_text("uni0915").as_deref(), Some("क"));
        assert_eq!(glyph_text("a.sc").as_deref(), Some("a"));
        assert_eq!(glyph_text("seven").as_deref(), Some("7"));
    }

    // Made with reportlab, see testdata/text/make.py.
    #[test]
    fn standard_fonts() {
        let pages = read(include_bytes!("../../testdata/text/standard.pdf"));
        assert_eq!(pages.len(), 2);
        let (_, r) = find(&pages[0], "Board Resolution");
        // drawString(72, 770) in Helvetica-Bold 16 on A4.
        assert!(near(r.x, 72.0, 0.5), "{r:?}");
        assert!(near(r.y + r.h, 841.89 - 770.0 + 16.0 * 0.2, 1.0), "{r:?}");
        assert!(near(r.h, 16.0, 0.5), "{r:?}");
        let (line, r) = find(&pages[1], "Authorised Signatory");
        assert_eq!(line.text, "Authorised Signatory");
        assert!(
            near(r.x, 380.0, 0.5) && near(r.y + r.h, 841.89 - 150.0 + 2.2, 1.0),
            "{r:?}"
        );
        // Times and Courier, kerning in TJ, word spacing, a MacRoman font
        // with /Differences.
        find(&pages[1], "For TrackMyTech Private Limited");
        find(&pages[1], "Place: Chennai");
        find(&pages[1], "Date: 26 Oct 2026");
        find(&pages[1], "Spaced out words");
        find(&pages[1], "Café Signature");
        find(&pages[1], "Kerned Signatory");
    }

    #[test]
    fn truetype_with_to_unicode() {
        let pages = read(include_bytes!("../../testdata/text/truetype.pdf"));
        let (_, r) = find(&pages[0], "Managing Director");
        assert!(near(r.x, 100.0, 0.5), "{r:?}");
        find(&pages[0], "Signed by DK RAHUL");
    }

    #[test]
    fn identity_h_font() {
        let pages = read(include_bytes!("../../testdata/text/identity-h.pdf"));
        let (_, r) = find(&pages[0], "Authorised Signatory");
        assert!(near(r.x, 300.0, 0.5), "{r:?}");
        // 20 chars at 500/1000 of 12 pt.
        assert!(near(r.w, 120.0, 0.5), "{r:?}");
        find(&pages[0], "Company Secretary");
    }

    #[test]
    fn rotated_page() {
        let pages = read(include_bytes!("../../testdata/text/rotated.pdf"));
        // A landscape media box with /Rotate 90 shows as A4 portrait. Text
        // drawn turned with the page reads upright, at (380, 150) from the
        // bottom-left as displayed.
        let (_, r) = find(&pages[0], "Authorised Signatory");
        assert!(near(r.x, 380.0, 1.0), "{r:?}");
        assert!(near(r.y + r.h, 841.89 - 150.0 + 12.0 * 0.2, 1.5), "{r:?}");
        // Text drawn normally on the rotated page reads downwards, and is
        // still found as a line.
        let (_, r) = find(&pages[0], "Sideways note");
        assert!(r.h > r.w, "{r:?}");
    }

    #[test]
    fn form_xobject_and_inline_image() {
        let data = b"BT /F1 10 Tf 1 0 0 1 50 50 Tm (A) Tj ET \
BI /W 2 /H 1 /BPC 8 /CS /G ID \x00EI EI \
q 2 0 0 2 10 20 cm BT /F1 10 Tf 5 5 Td [(Si) -250 (gn)] TJ ET Q";
        let mut r = Reader {
            doc: &Document::parse(include_bytes!("../../testdata/text/standard.pdf")).unwrap(),
            fonts: HashMap::new(),
            glyphs: Vec::new(),
            to_display: DisplayMap {
                crop: [0.0, 0.0, 200.0, 200.0],
                rotate: 0,
            },
        };
        let font = Obj::Dict(
            Dict::new()
                .with("Subtype", Obj::name("Type1"))
                .with("BaseFont", Obj::name("Helvetica")),
        );
        let res = Dict::new().with("Font", Obj::Dict(Dict::new().with("F1", font)));
        r.run(data, &res, Matrix::IDENTITY, 0);
        let lines = lines(r.glyphs);
        let texts: Vec<&str> = lines.iter().map(|l| l.text.as_str()).collect();
        assert_eq!(texts, ["A", "Si gn"]);
        // 20 pt, starting at 10 + 2 * 5.
        assert!(near(lines[1].boxes[0][0], 20.0, 0.01));
        assert!(near(lines[1].boxes[0][3], 200.0 - 30.0 + 20.0 * 0.2, 0.01));
    }

    #[test]
    fn cmap_ranges() {
        let cmap = b"1 begincodespacerange <0000> <FFFF> endcodespacerange
2 beginbfchar <0003> <0020> <0011> <00660069> endbfchar
2 beginbfrange <0024> <0026> <0041> <0030> <0031> [<0915> <0916>] endbfrange";
        let (ranges, map) = parse_cmap(cmap);
        assert_eq!(ranges, [(2, 0, 0xffff)]);
        assert_eq!(map[&3], " ");
        assert_eq!(map[&0x11], "fi");
        assert_eq!(map[&0x26], "C");
        assert_eq!(map[&0x31], "ख");
    }
}
