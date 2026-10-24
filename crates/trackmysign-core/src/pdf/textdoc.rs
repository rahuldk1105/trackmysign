//! Small text-only PDF documents (the verification report): A4 pages with
//! Helvetica and Helvetica-Bold in WinAnsi encoding, wrapped text, thin
//! rules and a footer on every page. Nothing is embedded; any text that
//! WinAnsi cannot show is transliterated or replaced by `?`.

use std::io::Write as _;

use chrono::{DateTime, Utc};
use flate2::Compression;
use flate2::write::ZlibEncoder;

use super::appearance::{Face, HELVETICA, HELVETICA_BOLD};
use super::object::{Dict, Obj, fmt_real, write_obj};

pub const A4: (f64, f64) = (595.28, 841.89);
const MARGIN: f64 = 56.0;
const FOOTER_SIZE: f64 = 7.5;

pub type Rgb = [f64; 3];

#[derive(Clone, Copy)]
pub struct Style {
    pub face: Face,
    pub size: f64,
    pub color: Rgb,
}

impl Style {
    pub const fn new(face: Face, size: f64, color: Rgb) -> Self {
        Style { face, size, color }
    }

    fn leading(&self) -> f64 {
        self.size * 1.35
    }
}

const FOOTER: Style = Style::new(Face::Regular, FOOTER_SIZE, [0.35, 0.35, 0.35]);

// ------------------------------------------------------------ encoding

/// Widths of WinAnsi 0x80..=0xFF (from the standard 14 font metrics);
/// unused codes are never written.
#[rustfmt::skip]
pub(super) const HELVETICA_HIGH: [u16; 128] = [
    556,350,222,556,333,1000,556,556,333,1000,667,333,1000,350,611,350,
    350,222,222,333,333,350,556,1000,333,1000,500,333,944,350,500,667,
    278,333,556,556,556,556,260,556,333,737,370,556,584,333,737,333,
    400,584,333,333,333,556,537,278,333,333,365,556,834,834,834,611,
    667,667,667,667,667,667,1000,722,667,667,667,667,278,278,278,278,
    722,722,778,778,778,778,778,584,778,722,722,722,722,667,667,611,
    556,556,556,556,556,556,889,500,556,556,556,556,278,278,278,278,
    556,556,556,556,556,556,556,584,611,556,556,556,556,500,556,500,
];

#[rustfmt::skip]
pub(super) const HELVETICA_BOLD_HIGH: [u16; 128] = [
    556,350,278,556,500,1000,556,556,333,1000,667,333,1000,350,611,350,
    350,278,278,500,500,350,556,1000,333,1000,556,333,944,350,500,667,
    278,333,556,556,556,556,280,556,333,737,370,556,584,333,737,333,
    400,584,333,333,333,611,556,278,333,333,365,556,834,834,834,611,
    722,722,722,722,722,722,1000,722,667,667,667,667,278,278,278,278,
    722,722,778,778,778,778,778,584,778,722,722,722,722,667,667,611,
    556,556,556,556,556,556,889,556,556,556,556,556,278,278,278,278,
    611,611,611,611,611,611,611,584,611,611,611,611,611,556,611,556,
];

/// The WinAnsi code of `c`, if the encoding has it.
pub fn win_ansi_code(c: char) -> Option<u8> {
    let u = c as u32;
    Some(match u {
        0x20..=0x7e | 0xa0..=0xff => u as u8,
        0x20ac => 0x80,
        0x201a => 0x82,
        0x0192 => 0x83,
        0x201e => 0x84,
        0x2026 => 0x85,
        0x2020 => 0x86,
        0x2021 => 0x87,
        0x02c6 => 0x88,
        0x2030 => 0x89,
        0x0160 => 0x8a,
        0x2039 => 0x8b,
        0x0152 => 0x8c,
        0x017d => 0x8e,
        0x2018 => 0x91,
        0x2019 => 0x92,
        0x201c => 0x93,
        0x201d => 0x94,
        0x2022 => 0x95,
        0x2013 => 0x96,
        0x2014 => 0x97,
        0x02dc => 0x98,
        0x2122 => 0x99,
        0x0161 => 0x9a,
        0x203a => 0x9b,
        0x0153 => 0x9c,
        0x017e => 0x9e,
        0x0178 => 0x9f,
        _ => return None,
    })
}

fn code_width(b: u8, face: Face) -> f64 {
    let (low, high) = match face {
        Face::Regular => (&HELVETICA, &HELVETICA_HIGH),
        Face::Bold => (&HELVETICA_BOLD, &HELVETICA_BOLD_HIGH),
    };
    (match b {
        0x20..=0x7e => low[(b - 0x20) as usize],
        0x80..=0xff => high[(b - 0x80) as usize],
        _ => 0,
    }) as f64
}

/// Width of `s` in points, as [`encode`] would write it.
pub fn text_width(s: &str, face: Face, size: f64) -> f64 {
    encode(s).iter().map(|&b| code_width(b, face)).sum::<f64>() * size / 1000.0
}

/// WinAnsi bytes for `s`; anything [`transliterate`] leaves unencodable
/// becomes `?`.
pub fn encode(s: &str) -> Vec<u8> {
    transliterate(s)
        .chars()
        .filter(|&c| c != '\n')
        .map(|c| win_ansi_code(c).unwrap_or(b'?'))
        .collect()
}

/// Latin Extended-A (U+0100..U+017F) without accents.
const LATIN_EXT_A: &str = "AaAaAaCcCcCcCcDdDdEeEeEeEeEeGgGgGgGgHhHhIiIiIiIiIiIiJjKkkLlLlLlLlLlNnNnNnnNnOoOoOoOoRrRrRrSsSsSsSsTtTtTtUuUuUuUuUuUuWwYyYZzZzZzs";

/// Latin for the letters of the nine Brahmic scripts from Devanagari to
/// Malayalam (U+0900..U+0D7F), which share one layout: index = code point
/// within its 128-character block.
#[rustfmt::skip]
const INDIC: [&str; 128] = [
    "n", "n", "n", "h", "a", "a", "a", "i", "i", "u", "u", "ri", "li", "e", "e", "e",
    "ai", "o", "o", "o", "au", "k", "kh", "g", "gh", "n", "ch", "chh", "j", "jh", "n", "t",
    "th", "d", "dh", "n", "t", "th", "d", "dh", "n", "n", "p", "ph", "b", "bh", "m", "y",
    "r", "r", "l", "l", "zh", "v", "sh", "sh", "s", "h", "", "", "", "", "a", "i",
    "i", "u", "u", "ri", "ri", "e", "e", "e", "ai", "o", "o", "o", "au", "", "", "",
    "om", "", "", "", "", "", "", "", "q", "kh", "g", "z", "r", "rh", "f", "y",
    "ri", "li", "li", "li", ".", ".", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
    ".", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
];

fn is_indic(c: char) -> bool {
    ('\u{0900}'..='\u{0D7F}').contains(&c)
}

/// Text that WinAnsi can show: accented Latin loses its accents, Indian
/// scripts are transliterated letter by letter (no schwa deletion, so
/// "रमेश" reads "Ramesha"), anything else becomes `?`. Newlines are kept.
pub fn transliterate(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    // A consonant was written whose inherent "a" is still owed.
    let mut owed_a = false;
    for c in s.chars() {
        if is_indic(c) {
            let block = c as u32 & !0x7f;
            let off = (c as u32 & 0x7f) as usize;
            let consonant = matches!(off, 0x15..=0x39 | 0x58..=0x5f);
            let vowel_sign = matches!(off, 0x3a..=0x3b | 0x3e..=0x4c | 0x55..=0x57 | 0x62..=0x63);
            let (virama, nukta) = (off == 0x4d, off == 0x3c);
            if owed_a && !vowel_sign && !virama && !nukta {
                out.push('a');
            }
            owed_a = false;
            if virama {
                continue;
            }
            if nukta {
                owed_a = true;
                continue;
            }
            // Malayalam chillu letters: consonants without a vowel.
            let latin = match (block, off) {
                (0x0d00, 0x7a | 0x7b) => "n",
                (0x0d00, 0x7c) => "r",
                (0x0d00, 0x7d | 0x7e) => "l",
                (0x0d00, 0x7f) => "k",
                _ => INDIC[off],
            };
            let word_start = !out.chars().next_back().is_some_and(char::is_alphanumeric);
            let mut chars = latin.chars();
            if let Some(first) = chars.next() {
                out.push(if word_start {
                    first.to_ascii_uppercase()
                } else {
                    first
                });
                out.extend(chars);
            }
            owed_a = consonant;
            continue;
        }
        if owed_a {
            out.push('a');
            owed_a = false;
        }
        let u = c as u32;
        match c {
            '\n' => out.push('\n'),
            _ if win_ansi_code(c).is_some() => out.push(c),
            '\t' | '\u{2000}'..='\u{200b}' | '\u{202f}' | '\u{3000}' => out.push(' '),
            // Combining accents, zero-width joiners, direction marks.
            '\u{0300}'..='\u{036f}' | '\u{200c}'..='\u{200f}' | '\u{feff}' => {}
            '\u{0100}'..='\u{017f}' => {
                out.push(LATIN_EXT_A.as_bytes()[(u - 0x100) as usize] as char)
            }
            '\u{2010}'..='\u{2012}' | '\u{2212}' => out.push('-'),
            '\u{20b9}' => out.push_str("Rs"),
            _ if c.is_control() => {}
            _ => out.push(iast_base(c).unwrap_or('?')),
        }
    }
    if owed_a {
        out.push('a');
    }
    out
}

/// Dotted and barred letters of romanised Indian names (IAST, ISO 15919).
fn iast_base(c: char) -> Option<char> {
    Some(match c {
        'ḍ' | 'ḏ' => 'd',
        'Ḍ' | 'Ḏ' => 'D',
        'ḥ' => 'h',
        'Ḥ' => 'H',
        'ḷ' | 'ḹ' | 'ḻ' => 'l',
        'Ḷ' | 'Ḹ' | 'Ḻ' => 'L',
        'ṁ' | 'ṃ' => 'm',
        'Ṁ' | 'Ṃ' => 'M',
        'ṅ' | 'ṇ' | 'ṉ' => 'n',
        'Ṅ' | 'Ṇ' | 'Ṉ' => 'N',
        'ṛ' | 'ṝ' | 'ṟ' => 'r',
        'Ṛ' | 'Ṝ' | 'Ṟ' => 'R',
        'ṣ' | 'ṡ' => 's',
        'Ṣ' | 'Ṡ' => 'S',
        'ṭ' | 'ṯ' => 't',
        'Ṭ' | 'Ṯ' => 'T',
        'ẏ' => 'y',
        'Ẏ' => 'Y',
        _ => return None,
    })
}

/// Breaks `text` into lines no wider than `width` points: at spaces where
/// possible, inside a word only when the word alone is too wide. Newlines
/// start a new line.
pub fn wrap(text: &str, face: Face, size: f64, width: f64) -> Vec<String> {
    let text = transliterate(text);
    let w = |s: &str| text_width(s, face, size);
    let mut lines = Vec::new();
    for para in text.split('\n') {
        let mut line = String::new();
        for word in para.split(' ').filter(|w| !w.is_empty()) {
            let candidate = if line.is_empty() {
                word.to_string()
            } else {
                format!("{line} {word}")
            };
            if w(&candidate) <= width {
                line = candidate;
                continue;
            }
            if !line.is_empty() {
                lines.push(std::mem::take(&mut line));
            }
            // A word wider than the line (a hash, a long field name).
            for c in word.chars() {
                let mut next = line.clone();
                next.push(c);
                if !line.is_empty() && w(&next) > width {
                    lines.push(std::mem::replace(&mut line, c.to_string()));
                } else {
                    line = next;
                }
            }
        }
        lines.push(line);
    }
    lines
}

/// A PDF literal string: `(`, `)` and `\` escaped, other bytes outside
/// printable ASCII in octal so the content stream stays plain text.
fn literal(bytes: &[u8]) -> String {
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

/// Content stream operators that show `s` with its baseline at `x`, `y`.
fn text_op(x: f64, y: f64, s: &str, style: Style) -> String {
    let font = match style.face {
        Face::Regular => "/F1",
        Face::Bold => "/F2",
    };
    let [r, g, b] = style.color.map(fmt_real);
    format!(
        "BT {font} {} Tf {r} {g} {b} rg 1 0 0 1 {} {} Tm {} Tj ET\n",
        fmt_real(style.size),
        fmt_real(x),
        fmt_real(y),
        literal(&encode(s))
    )
}

// -------------------------------------------------------------- layout

/// Lays text out top to bottom, starting a new page when the current one
/// is full.
pub struct TextDoc {
    pages: Vec<String>,
    y: f64,
    bottom: f64,
    footer: Vec<String>,
}

impl TextDoc {
    /// `footer` is repeated at the bottom of every page, with the page number.
    pub fn new(footer: &str) -> Self {
        let footer = wrap(footer, FOOTER.face, FOOTER.size, Self::width() - 60.0);
        let bottom = MARGIN + footer.len() as f64 * FOOTER.leading() + 14.0;
        TextDoc {
            pages: vec![String::new()],
            y: A4.1 - MARGIN,
            bottom,
            footer,
        }
    }

    /// Width of the text area.
    pub fn width() -> f64 {
        A4.0 - 2.0 * MARGIN
    }

    fn page(&mut self) -> &mut String {
        self.pages.last_mut().unwrap()
    }

    /// Starts a new page unless `height` points are left on this one.
    pub fn keep(&mut self, height: f64) {
        if self.y - height < self.bottom && self.y < A4.1 - MARGIN {
            self.pages.push(String::new());
            self.y = A4.1 - MARGIN;
        }
    }

    pub fn space(&mut self, height: f64) {
        self.y -= height;
    }

    fn draw(&mut self, x: f64, y: f64, s: &str, style: Style) {
        let op = text_op(x, y, s, style);
        self.page().push_str(&op);
    }

    /// Wrapped text across the full width.
    pub fn paragraph(&mut self, text: &str, style: Style) {
        for line in wrap(text, style.face, style.size, Self::width()) {
            self.keep(style.leading());
            self.y -= style.leading();
            let y = self.y + style.size * 0.25;
            self.draw(MARGIN, y, &line, style);
        }
    }

    /// A label in a column `label_width` wide and its value beside it, both
    /// wrapped.
    pub fn row(
        &mut self,
        label: &str,
        label_style: Style,
        value: &str,
        style: Style,
        label_width: f64,
    ) {
        let labels = wrap(label, label_style.face, label_style.size, label_width - 8.0);
        let values = wrap(value, style.face, style.size, Self::width() - label_width);
        let leading = style.leading().max(label_style.leading());
        for i in 0..labels.len().max(values.len()) {
            self.keep(leading);
            self.y -= leading;
            let y = self.y + style.size * 0.25;
            if let Some(l) = labels.get(i) {
                self.draw(MARGIN, y, l, label_style);
            }
            if let Some(v) = values.get(i) {
                self.draw(MARGIN + label_width, y, v, style);
            }
        }
    }

    /// One row of a table: each cell is its text, column width and style,
    /// wrapped within the column. A row of up to four lines is not split
    /// across pages.
    pub fn columns(&mut self, cells: &[(&str, f64, Style)]) {
        let lines: Vec<Vec<String>> = cells
            .iter()
            .map(|(text, width, s)| wrap(text, s.face, s.size, width - 8.0))
            .collect();
        let leading = cells.iter().map(|c| c.2.leading()).fold(0.0, f64::max);
        let rows = lines.iter().map(Vec::len).max().unwrap_or(0);
        if rows <= 4 {
            self.keep(rows as f64 * leading);
        }
        for i in 0..rows {
            self.keep(leading);
            self.y -= leading;
            let mut x = MARGIN;
            for ((_, width, style), cell) in cells.iter().zip(&lines) {
                if let Some(l) = cell.get(i) {
                    let y = self.y + style.size * 0.25;
                    self.draw(x, y, l, *style);
                }
                x += width;
            }
        }
    }

    /// A horizontal line across the text area, with `pad` points above and below.
    pub fn rule(&mut self, weight: f64, color: Rgb, pad: f64) {
        self.keep(2.0 * pad + weight);
        self.y -= pad;
        let [r, g, b] = color.map(fmt_real);
        let op = format!(
            "{r} {g} {b} RG {} w {} {} m {} {} l S\n",
            fmt_real(weight),
            fmt_real(MARGIN),
            fmt_real(self.y),
            fmt_real(A4.0 - MARGIN),
            fmt_real(self.y)
        );
        self.page().push_str(&op);
        self.y -= pad;
    }

    /// The finished PDF: footer and page numbers on every page, `title` in
    /// the document information.
    pub fn finish(mut self, title: &str, producer: &str, created: DateTime<Utc>) -> Vec<u8> {
        let total = self.pages.len();
        for (i, page) in self.pages.iter_mut().enumerate() {
            let mut y = self.bottom - 6.0;
            let line = format!(
                "0.75 0.75 0.75 RG 0.5 w {m} {y} m {} {y} l S\n",
                fmt_real(A4.0 - MARGIN),
                m = fmt_real(MARGIN),
                y = fmt_real(y)
            );
            page.push_str(&line);
            let number = format!("Page {} of {total}", i + 1);
            let nx = A4.0 - MARGIN - text_width(&number, FOOTER.face, FOOTER.size);
            for (j, l) in self.footer.iter().enumerate() {
                y -= FOOTER.leading();
                page.push_str(&text_op(MARGIN, y, l, FOOTER));
                if j == 0 {
                    page.push_str(&text_op(nx, y, &number, FOOTER));
                }
            }
        }

        let mut objects: Vec<Obj> = Vec::new();
        let n = self.pages.len();
        let page_id = |i: usize| 6 + 2 * i as u32;
        objects.push(Obj::Dict(
            Dict::new()
                .with("Type", Obj::name("Catalog"))
                .with("Pages", Obj::Ref(2, 0)),
        ));
        objects.push(Obj::Dict(
            Dict::new()
                .with("Type", Obj::name("Pages"))
                .with(
                    "Kids",
                    Obj::Array((0..n).map(|i| Obj::Ref(page_id(i), 0)).collect()),
                )
                .with("Count", Obj::int(n as i64)),
        ));
        for base in ["Helvetica", "Helvetica-Bold"] {
            objects.push(Obj::Dict(
                Dict::new()
                    .with("Type", Obj::name("Font"))
                    .with("Subtype", Obj::name("Type1"))
                    .with("BaseFont", Obj::name(base))
                    .with("Encoding", Obj::name("WinAnsiEncoding")),
            ));
        }
        objects.push(Obj::Dict(
            Dict::new()
                .with("Title", Obj::Str(pdf_text(title)))
                .with("Producer", Obj::Str(pdf_text(producer)))
                .with(
                    "CreationDate",
                    Obj::str(&created.format("D:%Y%m%d%H%M%SZ").to_string()),
                ),
        ));
        let fonts = Dict::new()
            .with("F1", Obj::Ref(3, 0))
            .with("F2", Obj::Ref(4, 0));
        for (i, content) in self.pages.iter().enumerate() {
            objects.push(Obj::Dict(
                Dict::new()
                    .with("Type", Obj::name("Page"))
                    .with("Parent", Obj::Ref(2, 0))
                    .with(
                        "MediaBox",
                        Obj::Array(vec![
                            Obj::int(0),
                            Obj::int(0),
                            Obj::real(A4.0),
                            Obj::real(A4.1),
                        ]),
                    )
                    .with(
                        "Resources",
                        Obj::Dict(Dict::new().with("Font", Obj::Dict(fonts.clone()))),
                    )
                    .with("Contents", Obj::Ref(page_id(i) + 1, 0)),
            ));
            let mut z = ZlibEncoder::new(Vec::new(), Compression::default());
            z.write_all(content.as_bytes()).unwrap();
            objects.push(Obj::Stream(
                Dict::new().with("Filter", Obj::name("FlateDecode")),
                z.finish().unwrap(),
            ));
        }

        let mut out = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n".to_vec();
        let mut offsets = Vec::with_capacity(objects.len());
        for (i, o) in objects.iter().enumerate() {
            offsets.push(out.len());
            out.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
            write_obj(&mut out, o);
            out.extend_from_slice(b"\nendobj\n");
        }
        let xref = out.len();
        out.extend_from_slice(
            format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1).as_bytes(),
        );
        for off in offsets {
            out.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
        }
        let trailer = Dict::new()
            .with("Size", Obj::int(objects.len() as i64 + 1))
            .with("Root", Obj::Ref(1, 0))
            .with("Info", Obj::Ref(5, 0));
        out.extend_from_slice(b"trailer\n");
        write_obj(&mut out, &Obj::Dict(trailer));
        out.extend_from_slice(format!("\nstartxref\n{xref}\n%%EOF\n").as_bytes());
        out
    }
}

/// A PDF text string: UTF-16BE with a byte order mark, so any name survives
/// in the document information.
fn pdf_text(s: &str) -> Vec<u8> {
    let mut b = vec![0xfe, 0xff];
    for u in s.encode_utf16() {
        b.extend_from_slice(&u.to_be_bytes());
    }
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdf::reader::Document;

    #[test]
    fn win_ansi_codes() {
        assert_eq!(win_ansi_code('A'), Some(b'A'));
        assert_eq!(win_ansi_code('é'), Some(0xe9));
        assert_eq!(win_ansi_code('—'), Some(0x97));
        assert_eq!(win_ansi_code('€'), Some(0x80));
        assert_eq!(win_ansi_code('\u{81}'), None);
        assert_eq!(win_ansi_code('ł'), None);
        assert_eq!(encode("Ré—x€ ₹5 中"), b"R\xe9\x97x\x80 Rs5 ?");
        assert_eq!(literal(b"a(b)\\\x97"), "(a\\(b\\)\\\\\\227)");
    }

    #[test]
    fn transliterates_to_win_ansi() {
        assert_eq!(LATIN_EXT_A.len(), 128);
        assert_eq!(transliterate("Łukasz Dvořák"), "Lukasz Dvorák");
        assert_eq!(transliterate("Ṛṣi Śaṅkara"), "Rsi Sankara");
        assert_eq!(transliterate("Müller"), "Müller");
        // Devanagari, Tamil, Bengali, Malayalam, Gujarati.
        assert_eq!(transliterate("रमेश कुमार"), "Ramesha Kumara");
        assert_eq!(transliterate("स्वीकृत"), "Svikrita");
        assert_eq!(transliterate("முருகன்"), "Murukan");
        assert_eq!(transliterate("সৌরভ"), "Saurabha");
        assert_eq!(transliterate("രാജൻ"), "Rajan");
        assert_eq!(transliterate("અમદાવાદ, ૨૦૨૬"), "Amadavada, 2026");
        assert_eq!(transliterate("क्ष\u{200d}त्र"), "Kshatra");
        assert_eq!(transliterate("a\tb\u{7}c\nд"), "a bc\n?");
        for s in ["रमेश", "中文", "Ω≈∑", "\u{1F600}"] {
            assert!(transliterate(s).chars().all(|c| win_ansi_code(c).is_some()));
        }
    }

    #[test]
    fn wraps_within_width() {
        let text = "The document digest does not match: the signed bytes were changed after \
                    signing, so this signature is not valid any more.";
        let lines = wrap(text, Face::Regular, 10.0, 150.0);
        assert!(lines.len() > 2);
        assert!(
            lines
                .iter()
                .all(|l| text_width(l, Face::Regular, 10.0) <= 150.0)
        );
        assert_eq!(lines.join(" "), text);

        // A hash is broken inside the word, nothing lost.
        let hash = "9a3fd3176798e842ddcb12c262f11cfacca70a8b84c6ea6fda30842a95a94cd8";
        let lines = wrap(&format!("SHA {hash}"), Face::Bold, 10.0, 120.0);
        assert_eq!(lines[0], "SHA");
        assert_eq!(lines[1..].concat(), hash);
        assert!(
            lines
                .iter()
                .all(|l| text_width(l, Face::Bold, 10.0) <= 120.0)
        );

        assert_eq!(wrap("a\n\nb", Face::Regular, 10.0, 100.0), ["a", "", "b"]);
        assert_eq!(wrap("", Face::Regular, 10.0, 100.0), [""]);
    }

    #[test]
    fn breaks_pages() {
        let mut d = TextDoc::new("Footer text that is repeated on every page.");
        for i in 0..200 {
            d.row(
                &format!("Label {i}"),
                Style::new(Face::Regular, 9.0, [0.4; 3]),
                "रमेश (unencodable) and some text long enough to wrap onto a second line \
                 in the value column of the row",
                Style::new(Face::Regular, 9.5, [0.0; 3]),
                128.0,
            );
        }
        let pdf = d.finish("Test रमेश", "Test", Utc::now());
        let doc = Document::open(&pdf, None).unwrap();
        let pages = doc.pages().unwrap();
        assert!(pages.len() > 5, "{} pages", pages.len());
    }
}
