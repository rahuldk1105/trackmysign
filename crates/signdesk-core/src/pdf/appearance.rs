//! The visible signature box: a Form XObject with Helvetica text and, if
//! chosen, a signature image (`/Im1`).

use super::object::fmt_real;
use crate::image::ImagePosition;

#[rustfmt::skip]
const HELVETICA: [u16; 95] = [
    278,278,355,556,556,889,667,191,333,333,389,584,278,333,278,278, // ' '..'/'
    556,556,556,556,556,556,556,556,556,556,278,278,584,584,584,556, // '0'..'?'
    1015,667,667,722,722,667,611,778,722,278,500,667,556,833,722,778, // '@'..'O'
    667,778,722,667,611,722,667,944,667,667,611,278,278,278,469,556, // 'P'..'_'
    333,556,556,500,556,556,278,556,556,222,222,500,222,833,556,556, // '`'..'o'
    556,556,333,500,278,556,500,722,500,500,500,334,260,334,584,     // 'p'..'~'
];

#[rustfmt::skip]
const HELVETICA_BOLD: [u16; 95] = [
    278,333,474,556,556,889,722,238,333,333,389,584,278,333,278,278,
    556,556,556,556,556,556,556,556,556,556,333,333,584,584,584,611,
    975,722,722,722,722,667,611,778,722,278,556,722,611,833,722,778,
    667,778,722,667,611,722,667,944,667,667,611,333,278,333,584,556,
    333,556,611,556,611,556,333,611,611,278,278,556,278,889,611,611,
    611,611,389,556,333,611,556,778,556,556,500,389,280,389,584,
];

#[derive(Clone, Copy, PartialEq)]
pub enum Face {
    Regular,
    Bold,
}

pub struct Line {
    pub text: String,
    pub face: Face,
    /// Relative size (1.0 = body text).
    pub scale: f64,
}

/// Encode as WinAnsi; characters outside Latin-1 become `?`.
pub fn win_ansi(s: &str) -> Vec<u8> {
    s.chars()
        .map(|c| match c as u32 {
            0x20..=0x7e | 0xa0..=0xff => c as u32 as u8,
            0x2019 => b'\'',
            0x2013 | 0x2014 => b'-',
            _ => b'?',
        })
        .collect()
}

fn width_units(bytes: &[u8], face: Face) -> f64 {
    let table = match face {
        Face::Regular => &HELVETICA,
        Face::Bold => &HELVETICA_BOLD,
    };
    bytes
        .iter()
        .map(|&b| match b {
            0x20..=0x7e => table[(b - 0x20) as usize] as f64,
            _ => 556.0,
        })
        .sum()
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

/// `[x, y, w, h]` in form space.
pub type Area = [f64; 4];

fn padding(w: f64, h: f64) -> f64 {
    (h.min(w) * 0.08).clamp(1.5, 6.0)
}

/// Splits a `w`×`h` box into the image area and the text area. The text
/// area keeps the box padding on its own edges; the image takes at most
/// 45% of the width (left) or half the height (above).
pub fn layout(w: f64, h: f64, slot: ImageSlot) -> (Area, Area) {
    let pad = padding(w, h);
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

/// Content stream for a `w`×`h` box (form space, upright). Fonts: `/F1`
/// regular, `/F2` bold.
pub fn content_stream(w: f64, h: f64, lines: &[Line]) -> Vec<u8> {
    content_stream_with_image(w, h, lines, None)
}

/// [`content_stream`] with the signature image `/Im1` placed by [`layout`].
pub fn content_stream_with_image(
    w: f64,
    h: f64,
    lines: &[Line],
    image: Option<ImageSlot>,
) -> Vec<u8> {
    let pad = padding(w, h);
    let encoded: Vec<Vec<u8>> = lines.iter().map(|l| win_ansi(&l.text)).collect();
    let (image, [tx, ty, tw, th]) = match image {
        Some(slot) => {
            let (i, t) = layout(w, h, slot);
            (Some(i), t)
        }
        None => (None, [0.0, 0.0, w, h]),
    };

    // Largest body size such that every line fits horizontally and all lines
    // (at 1.2 leading) fit vertically.
    let total_scale: f64 = lines.iter().map(|l| l.scale * 1.2).sum();
    let mut size = ((th - 2.0 * pad) / total_scale).min(11.0);
    for (l, e) in lines.iter().zip(&encoded) {
        let wu = width_units(e, l.face) * l.scale / 1000.0;
        if wu > 0.0 {
            size = size.min((tw - 2.0 * pad) / wu);
        }
    }
    let size = size.max(2.0);

    let mut s = Vec::new();
    let r = |v: f64| fmt_real(v);
    s.extend_from_slice(
        format!(
            "q\n0.13 0.36 0.67 RG 0.8 w\n{} {} {} {} re S\n",
            r(0.4),
            r(0.4),
            r(w - 0.8),
            r(h - 0.8)
        )
        .as_bytes(),
    );
    if let Some([ix, iy, iw, ih]) = image {
        s.extend_from_slice(
            format!(
                "q\n{} 0 0 {} {} {} cm\n/Im1 Do\nQ\n",
                r(iw),
                r(ih),
                r(ix),
                r(iy)
            )
            .as_bytes(),
        );
    }
    s.extend_from_slice(b"BT\n0 0 0 rg\n");
    let block: f64 = lines.iter().map(|l| l.scale * size * 1.2).sum();
    let mut y = ty + th - (th - block) / 2.0;
    for (l, e) in lines.iter().zip(&encoded) {
        let fs = l.scale * size;
        y -= fs * 1.2;
        let font = match l.face {
            Face::Regular => "/F1",
            Face::Bold => "/F2",
        };
        s.extend_from_slice(
            format!(
                "{font} {} Tf\n1 0 0 1 {} {} Tm\n",
                r(fs),
                r(tx + pad),
                r(y + fs * 0.25)
            )
            .as_bytes(),
        );
        s.extend_from_slice(&escape(e));
        s.extend_from_slice(b" Tj\n");
    }
    s.extend_from_slice(b"ET\nQ\n");
    s
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

    #[test]
    fn text_fits_box() {
        let lines = vec![
            Line {
                text: "Digitally signed by".into(),
                face: Face::Regular,
                scale: 1.0,
            },
            Line {
                text: "A VERY LONG DIRECTOR NAME INDEED".into(),
                face: Face::Bold,
                scale: 1.2,
            },
        ];
        let cs = String::from_utf8(content_stream(150.0, 50.0, &lines)).unwrap();
        assert!(cs.contains("(A VERY LONG DIRECTOR NAME INDEED) Tj"));
        let bold_size: f64 = cs
            .lines()
            .find(|l| l.starts_with("/F2"))
            .unwrap()
            .split(' ')
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        let width =
            width_units(b"A VERY LONG DIRECTOR NAME INDEED", Face::Bold) * bold_size / 1000.0;
        assert!(width <= 150.0);
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

        let lines = [Line {
            text: "Digitally signed by".into(),
            face: Face::Regular,
            scale: 1.0,
        }];
        let cs =
            String::from_utf8(content_stream_with_image(170.0, 55.0, &lines, Some(left))).unwrap();
        assert!(cs.contains("/Im1 Do"));
        assert!(
            !String::from_utf8(content_stream(170.0, 55.0, &lines))
                .unwrap()
                .contains("/Im1")
        );
    }

    #[test]
    fn escapes_parens() {
        assert_eq!(escape(b"a(b)\\"), b"(a\\(b\\)\\\\)");
        assert_eq!(win_ansi("Ré—x€"), vec![b'R', 0xe9, b'-', b'x', b'?']);
    }
}
