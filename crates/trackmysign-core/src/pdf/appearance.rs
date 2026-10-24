//! The visible signature box: a Form XObject with text in one of the
//! standard 14 fonts and, if chosen, a signature image (`/Im1`) and a
//! company seal (`/Im2`).
//!
//! [`draw`] lays a box out once, as a [`Drawing`]. The content stream is
//! written from it, and the desktop app draws its preview from the same
//! `Drawing`, so the preview cannot drift from the PDF.

use serde::Serialize;

use super::object::fmt_real;
use super::textdoc::{HELVETICA_BOLD_HIGH, HELVETICA_HIGH, encode};
use crate::image::ImagePosition;
use crate::stamp::{
    Align, Background, FontFamily, Layout, SealPosition, SealStyle, StampLine, StampStyle,
    parse_color,
};

#[rustfmt::skip]
pub(super) const HELVETICA: [u16; 95] = [
    278,278,355,556,556,889,667,191,333,333,389,584,278,333,278,278, // ' '..'/'
    556,556,556,556,556,556,556,556,556,556,278,278,584,584,584,556, // '0'..'?'
    1015,667,667,722,722,667,611,778,722,278,500,667,556,833,722,778, // '@'..'O'
    667,778,722,667,611,722,667,944,667,667,611,278,278,278,469,556, // 'P'..'_'
    333,556,556,500,556,556,278,556,556,222,222,500,222,833,556,556, // '`'..'o'
    556,556,333,500,278,556,500,722,500,500,500,334,260,334,584,     // 'p'..'~'
];

#[rustfmt::skip]
pub(super) const HELVETICA_BOLD: [u16; 95] = [
    278,333,474,556,556,889,722,238,333,333,389,584,278,333,278,278,
    556,556,556,556,556,556,556,556,556,556,333,333,584,584,584,611,
    975,722,722,722,722,667,611,778,722,278,556,722,611,833,722,778,
    667,778,722,667,611,722,667,944,667,667,611,333,278,333,584,556,
    333,556,611,556,611,556,333,611,611,278,278,556,278,889,611,611,
    611,611,389,556,333,611,556,778,556,556,500,389,280,389,584,
];

#[rustfmt::skip]
const TIMES: [u16; 95] = [
    250,333,408,500,500,833,778,180,333,333,500,564,250,333,250,278,
    500,500,500,500,500,500,500,500,500,500,278,278,564,564,564,444,
    921,722,667,667,722,611,556,722,722,333,389,722,611,889,722,722,
    556,722,667,556,611,722,722,944,722,722,611,333,278,333,469,500,
    333,444,500,444,500,444,333,500,500,278,278,500,278,778,500,500,
    500,500,333,389,278,500,500,722,500,500,444,480,200,480,541,
];

#[rustfmt::skip]
const TIMES_BOLD: [u16; 95] = [
    250,333,555,500,500,1000,833,278,333,333,500,570,250,333,250,278,
    500,500,500,500,500,500,500,500,500,500,333,333,570,570,570,500,
    930,722,667,722,722,667,611,778,778,389,500,778,667,944,722,778,
    611,778,722,556,667,722,722,1000,722,722,667,333,278,333,581,500,
    333,500,556,444,556,444,333,500,556,278,333,556,278,833,556,500,
    556,556,444,389,333,556,500,722,500,500,444,394,220,394,520,
];

/// WinAnsi 0x80..=0xFF; unused codes are never written.
#[rustfmt::skip]
const TIMES_HIGH: [u16; 128] = [
    500,350,333,500,444,1000,500,500,333,1000,556,333,889,350,611,350,
    350,333,333,444,444,350,500,1000,333,980,389,333,722,350,444,722,
    250,333,500,500,500,500,200,500,333,760,276,500,564,333,760,333,
    400,564,300,300,333,500,453,250,333,300,310,500,750,750,750,444,
    722,722,722,722,722,722,889,667,611,611,611,611,333,333,333,333,
    722,722,722,722,722,722,722,564,722,722,722,722,722,722,556,500,
    444,444,444,444,444,444,667,444,444,444,444,444,278,278,278,278,
    500,500,500,500,500,500,500,564,500,500,500,500,500,500,500,500,
];

#[rustfmt::skip]
const TIMES_BOLD_HIGH: [u16; 128] = [
    500,350,333,500,500,1000,500,500,333,1000,556,333,1000,350,667,350,
    350,333,333,500,500,350,500,1000,333,1000,389,333,722,350,444,722,
    250,333,500,500,500,500,220,500,333,747,300,500,570,333,747,333,
    400,570,300,300,333,556,540,250,333,300,330,500,750,750,750,500,
    722,722,722,722,722,722,1000,722,667,667,667,667,389,389,389,389,
    722,722,778,778,778,778,778,570,778,722,722,722,722,722,611,556,
    500,500,500,500,500,500,722,444,444,444,444,444,278,278,278,278,
    500,556,500,500,500,500,500,570,500,556,556,556,556,500,556,500,
];

#[derive(Clone, Copy, PartialEq)]
pub enum Face {
    Regular,
    Bold,
}

/// `/BaseFont` of the regular (`/F1`) and bold (`/F2`) face.
pub fn base_fonts(family: FontFamily) -> [&'static str; 2] {
    match family {
        FontFamily::Helvetica => ["Helvetica", "Helvetica-Bold"],
        FontFamily::Times => ["Times-Roman", "Times-Bold"],
        FontFamily::Courier => ["Courier", "Courier-Bold"],
    }
}

/// Width of a WinAnsi code, in thousandths of the font size.
fn code_width(b: u8, family: FontFamily, bold: bool) -> f64 {
    let (low, high) = match (family, bold) {
        (FontFamily::Courier, _) => return 600.0,
        (FontFamily::Helvetica, false) => (&HELVETICA, &HELVETICA_HIGH),
        (FontFamily::Helvetica, true) => (&HELVETICA_BOLD, &HELVETICA_BOLD_HIGH),
        (FontFamily::Times, false) => (&TIMES, &TIMES_HIGH),
        (FontFamily::Times, true) => (&TIMES_BOLD, &TIMES_BOLD_HIGH),
    };
    (match b {
        0x20..=0x7e => low[(b - 0x20) as usize],
        0x80..=0xff => high[(b - 0x80) as usize],
        _ => 0,
    }) as f64
}

fn width_units(bytes: &[u8], family: FontFamily, bold: bool) -> f64 {
    bytes.iter().map(|&b| code_width(b, family, bold)).sum()
}

fn escape(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() + 2);
    out.push(b'(');
    for &b in bytes {
        if matches!(b, b'(' | b')' | b'\\') {
            out.push(b'\\');
        }
        out.push(b);
    }
    out.push(b')');
    out
}

/// An image in the box: its width / height and where it goes.
#[derive(Debug, Clone, Copy)]
pub struct ImageSlot {
    pub aspect: f64,
    pub position: ImagePosition,
}

/// `[x, y, w, h]` in form space (origin bottom-left).
pub type Area = [f64; 4];

pub type Rgb = [f64; 3];

fn padding(w: f64, h: f64) -> f64 {
    (h.min(w) * 0.08).clamp(1.5, 6.0)
}

/// Splits a `w`×`h` box into the image area and the text area. The text
/// area keeps the box padding on its own edges; the image takes at most
/// 45% of the width (left) or half the height (above).
pub fn layout(w: f64, h: f64, slot: ImageSlot) -> (Area, Area) {
    layout_padded(w, h, slot, padding(w, h))
}

fn layout_padded(w: f64, h: f64, slot: ImageSlot, pad: f64) -> (Area, Area) {
    match slot.position {
        ImagePosition::Left => {
            let mut ih = h - 2.0 * pad;
            let iw = (ih * slot.aspect).min((w - 2.0 * pad) * 0.45);
            ih = ih.min(iw / slot.aspect);
            let image = [pad, (h - ih) / 2.0, iw, ih];
            (image, [pad + iw, 0.0, w - pad - iw, h])
        }
        ImagePosition::Above => {
            let mut iw = w - 2.0 * pad;
            let ih = (iw / slot.aspect).min((h - 2.0 * pad) * 0.5);
            iw = iw.min(ih * slot.aspect);
            let image = [(w - iw) / 2.0, h - pad - ih, iw, ih];
            (image, [0.0, 0.0, w, h - pad - ih])
        }
    }
}

/// The largest `aspect` rectangle inside `area`, centred.
fn fit(area: Area, aspect: f64) -> Area {
    let [x, y, w, h] = area;
    let (iw, ih) = if w / h > aspect {
        (h * aspect, h)
    } else {
        (w, w / aspect)
    };
    [x + (w - iw) / 2.0, y + (h - ih) / 2.0, iw, ih]
}

/// Takes an image area off the right of `text` (which keeps its padding),
/// at most `max_w` wide.
fn take_right(text: &mut Area, aspect: f64, pad: f64, max_w: f64) -> Area {
    let [tx, ty, tw, th] = *text;
    let mut ih = th - 2.0 * pad;
    let iw = (ih * aspect).min(max_w);
    ih = ih.min(iw / aspect);
    text[2] = tw - iw - pad;
    [tx + tw - pad - iw, ty + (th - ih) / 2.0, iw, ih]
}

const CLASSIC_BLUE: Rgb = [0.13, 0.36, 0.67];
const LIGHT_FILL: Rgb = [0.953, 0.961, 0.98];
const TICK_GREEN: Rgb = [0.1, 0.55, 0.25];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ImageKind {
    Signature,
    Seal,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlacedImage {
    pub kind: ImageKind,
    pub rect: Area,
    pub opacity: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Stroke {
    pub color: Rgb,
    pub width: f64,
}

/// One line of text; `y` is its baseline.
#[derive(Debug, Clone, Serialize)]
pub struct TextRun {
    pub text: String,
    #[serde(skip)]
    bytes: Vec<u8>,
    pub bold: bool,
    pub size: f64,
    pub x: f64,
    pub y: f64,
    pub width: f64,
}

/// Everything in one box, in form space, in painting order: background,
/// border, images, text, tick.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Drawing {
    pub width: f64,
    pub height: f64,
    pub font: FontFamily,
    pub background: Option<Rgb>,
    pub border: Option<Stroke>,
    pub images: Vec<PlacedImage>,
    pub text_color: Rgb,
    pub text: Vec<TextRun>,
    /// The text is clipped to this area (fixed font size only).
    pub clip: Option<Area>,
    pub tick: Option<Area>,
}

/// The images given for a box, as width / height.
#[derive(Debug, Clone, Copy, Default)]
pub struct Images {
    pub signature: Option<ImageSlot>,
    pub seal: Option<(f64, SealStyle)>,
}

enum Mode {
    Text,
    Image(ImageSlot),
    ImageOnly,
}

/// Lays out a `w`×`h` box (upright as the reader sees it).
pub fn draw(style: &StampStyle, lines: &[StampLine], images: Images, w: f64, h: f64) -> Drawing {
    let pad = style.padding.unwrap_or_else(|| padding(w, h));
    let sig = images.signature;
    let mode = match style.layout {
        Layout::Auto => sig.map_or(Mode::Text, Mode::Image),
        Layout::TextOnly => Mode::Text,
        Layout::ImageLeft | Layout::ImageAbove => match sig {
            Some(s) => Mode::Image(ImageSlot {
                position: if style.layout == Layout::ImageLeft {
                    ImagePosition::Left
                } else {
                    ImagePosition::Above
                },
                ..s
            }),
            None => Mode::Text,
        },
        Layout::ImageOnly if sig.is_some() || images.seal.is_some() => Mode::ImageOnly,
        Layout::ImageOnly => Mode::Text,
    };
    let mut d = Drawing {
        width: w,
        height: h,
        font: style.font,
        background: (style.background == Background::Light).then_some(LIGHT_FILL),
        border: style.border.then(|| Stroke {
            color: style
                .border_color
                .as_deref()
                .and_then(parse_color)
                .unwrap_or(CLASSIC_BLUE),
            width: style.border_width,
        }),
        images: Vec::new(),
        text_color: parse_color(&style.text_color).unwrap_or([0.0; 3]),
        text: Vec::new(),
        clip: None,
        tick: None,
    };
    let inner = |a: Area| [a[0] + pad, a[1] + pad, a[2] - 2.0 * pad, a[3] - 2.0 * pad];
    let placed = |kind, rect, opacity| PlacedImage {
        kind,
        rect,
        opacity,
    };
    let behind = images
        .seal
        .filter(|(_, s)| s.position == SealPosition::Behind);
    let right = images.seal.filter(|(_, s)| s.position == SealPosition::Right);

    let mut text = [0.0, 0.0, w, h];
    match mode {
        Mode::ImageOnly => {
            let mut area = text;
            match (sig, images.seal) {
                (Some(s), Some((aspect, seal))) => {
                    if seal.position == SealPosition::Behind {
                        d.images
                            .push(placed(ImageKind::Seal, fit(inner(area), aspect), seal.opacity));
                    } else {
                        let r = take_right(&mut area, aspect, pad, (w - 2.0 * pad) * 0.5);
                        d.images.push(placed(ImageKind::Seal, r, seal.opacity));
                    }
                    d.images
                        .push(placed(ImageKind::Signature, fit(inner(area), s.aspect), 1.0));
                }
                (Some(s), None) => d
                    .images
                    .push(placed(ImageKind::Signature, fit(inner(area), s.aspect), 1.0)),
                (None, Some((aspect, seal))) => d.images.push(placed(
                    ImageKind::Seal,
                    fit(inner(area), aspect),
                    seal.opacity,
                )),
                (None, None) => {}
            }
            if style.tick {
                let s = tick_size(w, h);
                d.tick = Some([w - pad - s, h - pad - s, s, s]);
            }
            return d;
        }
        Mode::Image(slot) => {
            if let Some((aspect, seal)) = behind {
                d.images
                    .push(placed(ImageKind::Seal, fit(inner(text), aspect), seal.opacity));
            }
            let (i, t) = layout_padded(w, h, slot, pad);
            d.images.push(placed(ImageKind::Signature, i, 1.0));
            text = t;
        }
        Mode::Text => {
            if let Some((aspect, seal)) = behind {
                d.images
                    .push(placed(ImageKind::Seal, fit(inner(text), aspect), seal.opacity));
            }
        }
    }
    if let Some((aspect, seal)) = right {
        let r = take_right(&mut text, aspect, pad, (w - 2.0 * pad) * 0.35);
        d.images.push(placed(ImageKind::Seal, r, seal.opacity));
    }
    if style.tick {
        let [tx, ty, tw, th] = text;
        let s = tick_size(tw, th);
        d.tick = Some([tx + tw - pad - s, ty + th - pad - s, s, s]);
        text[2] = tw - s - pad * 0.5;
    }
    d.text = lay_text(style, lines, text, pad);
    if style.font_size.is_some() {
        // Inside the border, which sits in the padding.
        let [tx, ty, tw, th] = text;
        d.clip = Some([tx, ty + pad / 2.0, tw, th - pad]);
    }
    d
}

fn tick_size(w: f64, h: f64) -> f64 {
    (w.min(h) * 0.22).clamp(5.0, 12.0)
}

struct Laid {
    bytes: Vec<u8>,
    bold: bool,
    scale: f64,
}

fn lay_text(style: &StampStyle, lines: &[StampLine], area: Area, pad: f64) -> Vec<TextRun> {
    let [tx, ty, tw, th] = area;
    let family = style.font;
    let mut laid: Vec<Laid> = lines
        .iter()
        .enumerate()
        .map(|(i, l)| {
            let emphasis = style.bold_name && l.name;
            Laid {
                bytes: encode(&l.text),
                bold: emphasis || (style.bold_first_line && i == 0),
                scale: if emphasis { 1.15 } else { 1.0 },
            }
        })
        .collect();
    let size = match style.font_size {
        // Largest body size such that every line fits horizontally and all
        // lines (at 1.2 leading) fit vertically.
        None => {
            let total_scale: f64 = laid.iter().map(|l| l.scale * 1.2).sum();
            let mut size = ((th - 2.0 * pad) / total_scale).min(11.0);
            for l in &laid {
                let wu = width_units(&l.bytes, family, l.bold) * l.scale / 1000.0;
                if wu > 0.0 {
                    size = size.min((tw - 2.0 * pad) / wu);
                }
            }
            size.max(2.0)
        }
        Some(size) => {
            laid = laid
                .into_iter()
                .flat_map(|l| {
                    let max = (tw - 2.0 * pad) * 1000.0 / (l.scale * size);
                    wrap(&l.bytes, family, l.bold, max)
                        .into_iter()
                        .map(move |bytes| Laid { bytes, ..l })
                })
                .collect();
            size
        }
    };
    let block: f64 = laid.iter().map(|l| l.scale * size * 1.2).sum();
    let mut y = match style.font_size {
        None => ty + th - (th - block) / 2.0,
        // Too much text starts at the top and is cut off at the bottom.
        Some(_) => ty + th - ((th - block) / 2.0).max(pad),
    };
    laid.into_iter()
        .map(|l| {
            let fs = l.scale * size;
            y -= fs * 1.2;
            let width = width_units(&l.bytes, family, l.bold) * fs / 1000.0;
            let x = match style.align {
                Align::Left => tx + pad,
                Align::Center => tx + (tw - width) / 2.0,
            };
            TextRun {
                text: l.bytes.iter().map(|&b| decode(b)).collect(),
                bytes: l.bytes,
                bold: l.bold,
                size: fs,
                x,
                y: y + fs * 0.25,
                width,
            }
        })
        .collect()
}

/// Breaks WinAnsi `text` into lines at most `max` units wide: at spaces
/// where possible, inside a word only when the word alone is too wide.
fn wrap(text: &[u8], family: FontFamily, bold: bool, max: f64) -> Vec<Vec<u8>> {
    let w = |s: &[u8]| width_units(s, family, bold);
    let mut lines: Vec<Vec<u8>> = Vec::new();
    let mut line: Vec<u8> = Vec::new();
    for word in text.split(|&b| b == b' ').filter(|w| !w.is_empty()) {
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
    if !line.is_empty() || lines.is_empty() {
        lines.push(line);
    }
    lines
}

/// The character a WinAnsi code shows.
fn decode(b: u8) -> char {
    const HIGH: &str = "€?‚ƒ„…†‡ˆ‰Š‹Œ?Ž??‘’“”•–—˜™š›œ?žŸ";
    match b {
        0x80..=0x9f => HIGH.chars().nth((b - 0x80) as usize).unwrap_or('?'),
        _ => b as char,
    }
}

impl Drawing {
    /// Content stream: fonts `/F1` regular and `/F2` bold, images `/Im1`
    /// (signature) and `/Im2` (seal), `/GS1` for a seal's opacity.
    pub fn content_stream(&self) -> Vec<u8> {
        let (w, h) = (self.width, self.height);
        let r = |v: f64| fmt_real(v);
        let rgb = |c: Rgb| format!("{} {} {}", r(c[0]), r(c[1]), r(c[2]));
        let mut s = Vec::new();
        s.extend_from_slice(b"q\n");
        if let Some(c) = self.background {
            s.extend_from_slice(format!("{} rg\n0 0 {} {} re f\n", rgb(c), r(w), r(h)).as_bytes());
        }
        if let Some(b) = &self.border {
            let half = b.width / 2.0;
            s.extend_from_slice(
                format!(
                    "{} RG {} w\n{} {} {} {} re S\n",
                    rgb(b.color),
                    r(b.width),
                    r(half),
                    r(half),
                    r(w - b.width),
                    r(h - b.width)
                )
                .as_bytes(),
            );
        }
        for im in &self.images {
            let [ix, iy, iw, ih] = im.rect;
            let gs = if im.opacity < 1.0 { "/GS1 gs\n" } else { "" };
            let name = match im.kind {
                ImageKind::Signature => "/Im1",
                ImageKind::Seal => "/Im2",
            };
            s.extend_from_slice(
                format!(
                    "q\n{gs}{} 0 0 {} {} {} cm\n{name} Do\nQ\n",
                    r(iw),
                    r(ih),
                    r(ix),
                    r(iy)
                )
                .as_bytes(),
            );
        }
        if !self.text.is_empty() {
            if let Some([x, y, cw, ch]) = self.clip {
                s.extend_from_slice(
                    format!("q\n{} {} {} {} re W n\n", r(x), r(y), r(cw), r(ch)).as_bytes(),
                );
            }
            s.extend_from_slice(format!("BT\n{} rg\n", rgb(self.text_color)).as_bytes());
            for t in &self.text {
                let font = if t.bold { "/F2" } else { "/F1" };
                s.extend_from_slice(
                    format!(
                        "{font} {} Tf\n1 0 0 1 {} {} Tm\n",
                        r(t.size),
                        r(t.x),
                        r(t.y)
                    )
                    .as_bytes(),
                );
                s.extend_from_slice(&escape(&t.bytes));
                s.extend_from_slice(b" Tj\n");
            }
            s.extend_from_slice(b"ET\n");
            if self.clip.is_some() {
                s.extend_from_slice(b"Q\n");
            }
        }
        if let Some([x, y, size, _]) = self.tick {
            let p = |fx: f64, fy: f64| format!("{} {}", r(x + fx * size), r(y + fy * size));
            s.extend_from_slice(
                format!(
                    "q\n{} RG {} w 1 J 1 j\n{} m\n{} l\n{} l\nS\nQ\n",
                    rgb(TICK_GREEN),
                    r(size * 0.14),
                    p(0.12, 0.52),
                    p(0.4, 0.2),
                    p(0.88, 0.82)
                )
                .as_bytes(),
            );
        }
        s.extend_from_slice(b"Q\n");
        s
    }

    /// The opacity `/GS1` sets, when an image needs one.
    pub fn opacity(&self) -> Option<f64> {
        self.images
            .iter()
            .map(|i| i.opacity)
            .find(|&o| o < 1.0)
    }

    pub fn uses(&self, kind: ImageKind) -> bool {
        self.images.iter().any(|i| i.kind == kind)
    }
}

/// Form `/Matrix` that keeps the box upright on a page with `/Rotate`.
pub fn rotation_matrix(rotate: i32, w: f64, h: f64) -> [f64; 6] {
    match rotate {
        90 => [0.0, 1.0, -1.0, 0.0, h, 0.0],
        180 => [-1.0, 0.0, 0.0, -1.0, w, h],
        270 => [0.0, -1.0, 1.0, 0.0, 0.0, w],
        _ => [1.0, 0.0, 0.0, 1.0, 0.0, 0.0],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stamp::LineField;

    fn lines(texts: &[&str]) -> Vec<StampLine> {
        texts
            .iter()
            .enumerate()
            .map(|(i, t)| StampLine {
                text: t.to_string(),
                name: i == 1,
            })
            .collect()
    }

    fn classic() -> Vec<StampLine> {
        lines(&[
            "Digitally signed by",
            "A VERY LONG DIRECTOR NAME INDEED",
            "Date: 2026.10.24 09:05:07 +05:30",
        ])
    }

    fn inside(inner: Area, outer: Area) -> bool {
        let e = 1e-9;
        inner[0] >= outer[0] - e
            && inner[1] >= outer[1] - e
            && inner[0] + inner[2] <= outer[0] + outer[2] + e
            && inner[1] + inner[3] <= outer[1] + outer[3] + e
    }

    #[test]
    fn auto_fit() {
        let d = draw(&StampStyle::default(), &classic(), Images::default(), 150.0, 50.0);
        let name = &d.text[1];
        assert!(name.bold && !d.text[0].bold);
        // The widest line sets the size and fills the width inside the padding.
        let pad = padding(150.0, 50.0);
        assert!((name.width - (150.0 - 2.0 * pad)).abs() < 1e-9);
        assert!((name.size / d.text[0].size - 1.15).abs() < 1e-9);
        assert!(d.text.iter().all(|t| t.x == pad));
        // Short lines in a big box stop at 11 pt.
        let d = draw(
            &StampStyle::default(),
            &lines(&["a", "b"]),
            Images::default(),
            400.0,
            300.0,
        );
        assert_eq!(d.text[0].size, 11.0);
        let cs = String::from_utf8(d.content_stream()).unwrap();
        assert!(cs.starts_with(
            "q\n0.13 0.36 0.67 RG 0.8 w\n0.4 0.4 399.2 299.2 re S\nBT\n0 0 0 rg\n/F1 11 Tf\n"
        ));
    }

    #[test]
    fn fixed_size_wraps() {
        let style = StampStyle {
            font_size: Some(8.0),
            lines: Some(vec![LineField::Custom1]),
            ..Default::default()
        };
        let text = lines(&["For and on behalf of Acme Exports Private Limited, Chennai"]);
        let d = draw(&style, &text, Images::default(), 120.0, 60.0);
        assert!(d.text.len() > 1);
        let max = 120.0 - 2.0 * padding(120.0, 60.0);
        assert!(d.text.iter().all(|t| t.size == 8.0 && t.width <= max));
        let joined: Vec<&str> = d.text.iter().map(|t| t.text.as_str()).collect();
        assert_eq!(joined.join(" "), text[0].text);
        assert_eq!(d.clip, Some([0.0, 2.4, 120.0, 55.2]));
        assert!(
            String::from_utf8(d.content_stream())
                .unwrap()
                .contains("re W n\n")
        );
        // A word wider than the box is broken.
        assert_eq!(
            wrap(b"WWWWWW", FontFamily::Courier, false, 2000.0),
            vec![b"WWW".to_vec(), b"WWW".to_vec()]
        );
    }

    #[test]
    fn centred() {
        let style = StampStyle {
            align: Align::Center,
            ..Default::default()
        };
        let d = draw(&style, &classic(), Images::default(), 200.0, 60.0);
        for t in &d.text {
            assert!((t.x + t.width / 2.0 - 100.0).abs() < 1e-9);
        }
    }

    #[test]
    fn fonts() {
        let style = StampStyle {
            font: FontFamily::Times,
            ..Default::default()
        };
        assert_eq!(base_fonts(style.font), ["Times-Roman", "Times-Bold"]);
        assert_eq!(width_units(b"Hi", FontFamily::Times, false), 722.0 + 278.0);
        assert_eq!(width_units(b"Hi", FontFamily::Times, true), 778.0 + 278.0);
        assert_eq!(width_units(b"Hi\xe9", FontFamily::Courier, true), 1800.0);
        assert_eq!(width_units(b"\xe9", FontFamily::Helvetica, false), 556.0);
        // Other metrics, another size for the same box.
        let times = draw(&style, &classic(), Images::default(), 150.0, 50.0);
        let helv = draw(&StampStyle::default(), &classic(), Images::default(), 150.0, 50.0);
        assert_ne!(times.text[1].size, helv.text[1].size);
        // Text the fonts cannot show is transliterated.
        let d = draw(&style, &lines(&["रमेश", "x"]), Images::default(), 150.0, 50.0);
        assert_eq!(d.text[0].text, "Ramesha");
        assert_eq!(decode(0x80), '€');
    }

    #[test]
    fn image_layout() {
        let left = ImageSlot {
            aspect: 2.0,
            position: ImagePosition::Left,
        };
        // 170x55 box, pad 4.4: image limited by height (46.2 tall, 92.4 wide)
        // would exceed 45% of the width, so it is narrowed to 72.54.
        let ([ix, iy, iw, ih], [tx, _, tw, th]) = layout(170.0, 55.0, left);
        assert!((iw - (170.0 - 8.8) * 0.45).abs() < 1e-9);
        assert!((ih - iw / 2.0).abs() < 1e-9);
        assert!((iy - (55.0 - ih) / 2.0).abs() < 1e-9);
        assert_eq!(ix, 4.4);
        assert!((tx + tw - 170.0).abs() < 1e-9 && th == 55.0);

        let above = ImageSlot {
            aspect: 4.0,
            position: ImagePosition::Above,
        };
        // 170x80 box, pad 6: limited to half the inner height (34 tall).
        let ([ix, iy, iw, ih], [_, ty, tw, th]) = layout(170.0, 80.0, above);
        assert_eq!([ix, iy, iw, ih], [17.0, 40.0, 136.0, 34.0]);
        assert_eq!([ty, tw, th], [0.0, 170.0, 40.0]);
    }

    #[test]
    fn layouts() {
        let sig = ImageSlot {
            aspect: 2.0,
            position: ImagePosition::Left,
        };
        let with = |layout, images: Images| {
            let style = StampStyle {
                layout,
                ..Default::default()
            };
            draw(&style, &classic(), images, 170.0, 55.0)
        };
        let images = Images {
            signature: Some(sig),
            seal: None,
        };
        let auto = with(Layout::Auto, images);
        assert!(auto.uses(ImageKind::Signature) && !auto.text.is_empty());
        let cs = String::from_utf8(auto.content_stream()).unwrap();
        assert!(cs.contains("/Im1 Do") && !cs.contains("/Im2"));
        // Text starts right of the image.
        assert!(auto.text[0].x > auto.images[0].rect[0] + auto.images[0].rect[2]);

        let above = with(Layout::ImageAbove, images);
        let [_, iy, _, _] = above.images[0].rect;
        assert!(above.text.iter().all(|t| t.y + t.size <= iy + 1e-9));

        let text = with(Layout::TextOnly, images);
        assert!(text.images.is_empty());
        assert!(
            !String::from_utf8(text.content_stream())
                .unwrap()
                .contains("Do")
        );

        let only = with(Layout::ImageOnly, images);
        assert!(only.text.is_empty() && only.images.len() == 1);
        let pad = padding(170.0, 55.0);
        let inner = [pad, pad, 170.0 - 2.0 * pad, 55.0 - 2.0 * pad];
        assert!(inside(only.images[0].rect, inner));
        assert!(
            !String::from_utf8(only.content_stream())
                .unwrap()
                .contains("BT")
        );

        // Image only, without a signature image: the seal.
        let seal_only = with(
            Layout::ImageOnly,
            Images {
                signature: None,
                seal: Some((1.0, SealStyle::default())),
            },
        );
        assert_eq!(seal_only.images[0].kind, ImageKind::Seal);
        // Nothing to show: text after all.
        assert!(!with(Layout::ImageOnly, Images::default()).text.is_empty());
        assert!(with(Layout::ImageLeft, Images::default()).images.is_empty());
    }

    #[test]
    fn seals() {
        let seal = |position, opacity| Images {
            signature: Some(ImageSlot {
                aspect: 2.0,
                position: ImagePosition::Left,
            }),
            seal: Some((1.0, SealStyle { position, opacity })),
        };
        let style = StampStyle::default();
        let d = draw(&style, &classic(), seal(SealPosition::Right, 1.0), 200.0, 60.0);
        let s = d.images.iter().find(|i| i.kind == ImageKind::Seal).unwrap();
        // On the right, clear of the text.
        assert!(s.rect[0] + s.rect[2] <= 200.0);
        assert!(d.text.iter().all(|t| t.x + t.width <= s.rect[0] + 1e-9));
        assert_eq!(d.opacity(), None);

        let d = draw(&style, &classic(), seal(SealPosition::Behind, 0.3), 200.0, 60.0);
        // Under everything else, centred in the box.
        assert_eq!(d.images[0].kind, ImageKind::Seal);
        let [x, y, w, h] = d.images[0].rect;
        assert!((x + w / 2.0 - 100.0).abs() < 1e-9 && (y + h / 2.0 - 30.0).abs() < 1e-9);
        assert_eq!(d.opacity(), Some(0.3));
        let cs = String::from_utf8(d.content_stream()).unwrap();
        let gs = cs.find("/GS1 gs\n").unwrap();
        assert!(gs < cs.find("/Im2 Do").unwrap() && cs.find("/Im2 Do") < cs.find("/Im1 Do"));
    }

    #[test]
    fn box_tick_and_colours() {
        let style = StampStyle {
            border: false,
            background: Background::Light,
            tick: true,
            text_color: crate::stamp::DARK_BLUE.into(),
            ..Default::default()
        };
        let d = draw(&style, &classic(), Images::default(), 170.0, 55.0);
        let [x, y, s, _] = d.tick.unwrap();
        assert!(x + s <= 170.0 && y + s <= 55.0);
        assert!(d.text.iter().all(|t| t.x + t.width <= x + 1e-9));
        let cs = String::from_utf8(d.content_stream()).unwrap();
        assert!(cs.starts_with("q\n0.953 0.961 0.98 rg\n0 0 170 55 re f\n"));
        assert!(!cs.contains(" RG 0.8 w") && cs.contains("0.106 0.227 0.549 rg\n"));
        assert!(cs.contains(" m\n") && cs.ends_with("l\nS\nQ\nQ\n"));
        let style = StampStyle {
            border_color: Some("#FF0000".into()),
            border_width: 2.0,
            padding: Some(10.0),
            ..Default::default()
        };
        let d = draw(&style, &classic(), Images::default(), 170.0, 55.0);
        assert!(d.text.iter().all(|t| t.x == 10.0));
        let cs = String::from_utf8(d.content_stream()).unwrap();
        assert!(cs.starts_with("q\n1 0 0 RG 2 w\n1 1 168 53 re S\n"));
    }

    #[test]
    fn escapes_parens() {
        assert_eq!(escape(b"a(b)\\"), b"(a\\(b\\)\\\\)");
        assert_eq!(encode("Ré—x€"), vec![b'R', 0xe9, 0x97, b'x', 0x80]);
    }
}
