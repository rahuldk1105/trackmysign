//! Where a document expects its signer to sign: phrases such as
//! "Authorised Signatory", "For <organisation>" or the signer's own name
//! are looked for in the text of the pages ([`crate::pdf::text`]), each
//! one found is a candidate, and the box goes just above, below or beside
//! it, on free space where there is some. Candidates are ranked: the last
//! pages first, lower on the page first, the signer's name and "Authorised
//! Signatory" before generic words, a phrase standing on its own line
//! before one inside a sentence.

use crate::certinfo::CertSummary;
use crate::pdf::fields::{signature_fields, user_to_display};
use crate::pdf::reader::Document;
use crate::pdf::sign::DisplayRect;
use crate::pdf::text::{Line, page_lines};
use crate::{Error, SignRequest};

/// In a phrase, stands for the certificate holder's name (CN=).
pub const NAME: &str = "{name}";
/// In a phrase, stands for the certificate's organisation (O=).
pub const ORGANISATION: &str = "{organisation}";

/// The phrases looked for when none are configured. Case does not matter.
pub const DEFAULT_PHRASES: [&str; 9] = [
    "Authorised Signatory",
    "Authorized Signatory",
    "For {organisation}",
    "{name}",
    "Managing Director",
    "Company Secretary",
    "Director",
    "Signature",
    "Signed by",
];

/// Only this many pages, the last ones, are read: signature blocks are at
/// the end, and a long document should not hold up opening it.
const MAX_PAGES: usize = 50;
/// Space between the phrase and the box.
const GAP: f64 = 4.0;

/// Who signs, to fill in [`NAME`] and [`ORGANISATION`].
#[derive(Debug, Clone, Default)]
pub struct Holder {
    pub name: Option<String>,
    pub organisation: Option<String>,
}

impl Holder {
    pub fn of(summary: &CertSummary) -> Holder {
        Holder {
            name: Some(summary.subject_cn.clone()).filter(|n| !n.trim().is_empty()),
            organisation: summary.organization.clone(),
        }
    }
}

/// What a phrase stands for, which decides its rank and where the box goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// The certificate holder's name: the box goes above it.
    Name,
    /// "Authorised Signatory" and the like: above.
    Signatory,
    /// "For <organisation>": the space below it is for the signature.
    Organisation,
    /// "Director", "Company Secretary": above.
    Title,
    /// "Signature", "Signed by": a label, the box goes beside it.
    Label,
    /// A phrase added in the settings.
    Other,
}

impl Kind {
    fn of(phrase: &str) -> Kind {
        let p = phrase.to_lowercase();
        if p.trim() == NAME {
            Kind::Name
        } else if p.contains(ORGANISATION) {
            Kind::Organisation
        } else if p.contains("signatory") {
            Kind::Signatory
        } else if p.contains("signature") || p.contains("signed by") {
            Kind::Label
        } else if p.contains("director") || p.contains("secretary") {
            Kind::Title
        } else {
            Kind::Other
        }
    }

    fn weight(self) -> f64 {
        match self {
            Kind::Name | Kind::Signatory => 40.0,
            Kind::Organisation => 30.0,
            Kind::Title | Kind::Other => 25.0,
            Kind::Label => 20.0,
        }
    }

    fn sides(self) -> [Side; 3] {
        match self {
            Kind::Organisation => [Side::Below, Side::Above, Side::Right],
            Kind::Label => [Side::Right, Side::Above, Side::Below],
            _ => [Side::Above, Side::Right, Side::Below],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Side {
    Above,
    Below,
    Right,
}

/// A phrase found in the document.
#[derive(Debug, Clone)]
pub struct Anchor {
    /// Zero-based page.
    pub page: usize,
    /// As printed.
    pub text: String,
    /// The phrase it matched, as configured (placeholders not filled in).
    pub phrase: String,
    pub kind: Kind,
    /// Around the text, as displayed (points from the top-left).
    pub rect: DisplayRect,
    /// On a line of its own (apart from labels such as "Name:"), not
    /// inside a sentence.
    pub standalone: bool,
}

/// A place for the box next to an anchor.
#[derive(Debug, Clone)]
pub struct Spot {
    pub anchor: Anchor,
    /// The box, on `anchor.page`.
    pub rect: DisplayRect,
    /// Over no text and no signature field.
    pub free: bool,
    /// Higher is better.
    pub score: f64,
}

/// One page as read for anchors.
struct Page {
    index: usize,
    width: f64,
    height: f64,
    lines: Vec<Line>,
    /// Boxes of words, where the box should not go.
    words: Vec<DisplayRect>,
    /// Signature fields on the page, and whether each is signed.
    fields: Vec<(DisplayRect, bool)>,
}

fn read_pages(input: &[u8], password: Option<&str>) -> Result<(Vec<Page>, usize), Error> {
    let doc = Document::open(input, password)?;
    let pages = doc.pages()?;
    let fields = signature_fields(&doc, &pages).unwrap_or_default();
    let first = pages.len().saturating_sub(MAX_PAGES);
    let mut out = Vec::new();
    for (index, p) in pages.iter().enumerate().skip(first) {
        let (width, height) = p.display_size();
        let lines = page_lines(&doc, p).unwrap_or_default();
        let words = lines.iter().flat_map(words).collect();
        let fields = fields
            .iter()
            .flat_map(|f| f.widgets.iter().map(move |w| (w, f.signed)))
            .filter(|(w, _)| w.page == Some(index) && w.visible())
            .map(|(w, signed)| (user_to_display(p, w.rect), signed))
            .collect();
        out.push(Page {
            index,
            width,
            height,
            lines,
            words,
            fields,
        });
    }
    Ok((out, pages.len()))
}

/// Boxes of the words of a line. Fillers (`____`, `....`) are where one
/// writes, so they are left out.
fn words(line: &Line) -> Vec<DisplayRect> {
    let mut out = Vec::new();
    let chars: Vec<char> = line.text.chars().collect();
    let mut start = None;
    for i in 0..=chars.len() {
        let solid = chars
            .get(i)
            .is_some_and(|c| !c.is_whitespace() && !matches!(c, '_' | '.' | '…' | '-' | '–'));
        match (solid, start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                out.push(line.span(s, i));
                start = None;
            }
            _ => {}
        }
    }
    out
}

/// Lowercased, runs of spaces as one, full stops dropped ("Pvt. Ltd." is
/// "pvt ltd"); with the index in `text` of each char kept.
fn normalize(text: &str) -> (Vec<char>, Vec<usize>) {
    let mut chars = Vec::new();
    let mut index = Vec::new();
    for (i, c) in text.chars().enumerate() {
        if c == '.' {
            continue;
        }
        if c.is_whitespace() {
            if chars.last().is_none_or(|l| *l != ' ') {
                chars.push(' ');
                index.push(i);
            }
            continue;
        }
        for l in c.to_lowercase() {
            chars.push(l);
            index.push(i);
        }
    }
    (chars, index)
}

/// Words around a phrase that still leave it on a line of its own.
const LABEL_WORDS: [&str; 11] = [
    "name",
    "designation",
    "signature",
    "sign",
    "sd",
    "place",
    "date",
    "for",
    "by",
    "and",
    "on",
];

fn standalone(line: &str, from: usize, to: usize) -> bool {
    let rest: String = line
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if (from..to).contains(&i) || !c.is_alphanumeric() {
                ' '
            } else {
                c
            }
        })
        .collect::<String>()
        .to_lowercase();
    rest.split_whitespace()
        .filter(|w| !LABEL_WORDS.contains(w))
        .map(|w| w.chars().count())
        .sum::<usize>()
        <= 4
}

/// The phrases with the holder filled in; those the holder cannot fill are
/// left out.
fn filled(phrases: &[String], holder: &Holder) -> Vec<(String, Vec<char>)> {
    let defaults: Vec<String>;
    let phrases = if phrases.iter().all(|p| p.trim().is_empty()) {
        defaults = DEFAULT_PHRASES.iter().map(|p| p.to_string()).collect();
        &defaults
    } else {
        phrases
    };
    let name = holder
        .name
        .as_deref()
        .map(str::trim)
        .filter(|n| !n.is_empty());
    let org = holder
        .organisation
        .as_deref()
        .map(str::trim)
        .filter(|o| !o.is_empty());
    phrases
        .iter()
        .filter_map(|p| {
            let lower = p.to_lowercase();
            let mut s = p.trim().to_string();
            if lower.contains(NAME) {
                s = replace_ci(&s, NAME, name?);
            }
            if lower.contains(ORGANISATION) {
                s = replace_ci(&s, ORGANISATION, org?);
            }
            let (norm, _) = normalize(&s);
            let norm: Vec<char> = trim_spaces(norm);
            (!norm.is_empty()).then(|| (p.trim().to_string(), norm))
        })
        .collect()
}

fn replace_ci(s: &str, placeholder: &str, value: &str) -> String {
    match s.to_lowercase().find(placeholder) {
        // Placeholders are ASCII, so the index is the same in `s`.
        Some(i) if s.is_char_boundary(i) && s.is_char_boundary(i + placeholder.len()) => {
            format!("{}{value}{}", &s[..i], &s[i + placeholder.len()..])
        }
        _ => s.to_string(),
    }
}

fn trim_spaces(mut v: Vec<char>) -> Vec<char> {
    while v.last() == Some(&' ') {
        v.pop();
    }
    while v.first() == Some(&' ') {
        v.remove(0);
    }
    v
}

fn page_anchors(page: &Page, phrases: &[(String, Vec<char>)]) -> Vec<Anchor> {
    let mut out = Vec::new();
    for line in &page.lines {
        let (norm, index) = normalize(&line.text);
        // (from, to) in chars of `line.text`, phrase.
        let mut found: Vec<(usize, usize, usize)> = Vec::new();
        for (k, (_, p)) in phrases.iter().enumerate() {
            if p.len() > norm.len() {
                continue;
            }
            for s in 0..=norm.len() - p.len() {
                let e = s + p.len();
                if norm[s..e] != p[..]
                    || (s > 0 && norm[s - 1].is_alphanumeric())
                    || norm.get(e).is_some_and(|c| c.is_alphanumeric())
                {
                    continue;
                }
                found.push((index[s], index[e - 1] + 1, k));
            }
        }
        // "Director" inside "Managing Director" is the same anchor.
        found.sort_by_key(|&(from, to, k)| (std::cmp::Reverse(to - from), k));
        let mut kept: Vec<(usize, usize, usize)> = Vec::new();
        for f in found {
            if !kept.iter().any(|k| f.0 < k.1 && k.0 < f.1) {
                kept.push(f);
            }
        }
        for (from, to, k) in kept {
            let phrase = &phrases[k].0;
            out.push(Anchor {
                page: page.index,
                text: line.text.chars().skip(from).take(to - from).collect(),
                phrase: phrase.clone(),
                kind: Kind::of(phrase),
                rect: line.span(from, to),
                standalone: standalone(&line.text, from, to),
            });
        }
    }
    out
}

/// Every phrase found, by page and from the top. Only the last 50 pages
/// are read.
pub fn anchors(
    input: &[u8],
    password: Option<&str>,
    phrases: &[String],
    holder: &Holder,
) -> Result<Vec<Anchor>, Error> {
    let (pages, _) = read_pages(input, password)?;
    let phrases = filled(phrases, holder);
    let mut out: Vec<Anchor> = pages
        .iter()
        .flat_map(|p| page_anchors(p, &phrases))
        .collect();
    out.sort_by(|a, b| {
        a.page
            .cmp(&b.page)
            .then(a.rect.y.total_cmp(&b.rect.y))
            .then(a.rect.x.total_cmp(&b.rect.x))
    });
    Ok(out)
}

/// Places for a `w` × `h` box, the best first; empty when no phrase is
/// found (a scanned document, say).
pub fn spots(
    input: &[u8],
    password: Option<&str>,
    phrases: &[String],
    holder: &Holder,
    w: f64,
    h: f64,
) -> Result<Vec<Spot>, Error> {
    let (pages, count) = read_pages(input, password)?;
    let phrases = filled(phrases, holder);
    let mut all = Vec::new();
    for page in &pages {
        let context: Vec<DisplayRect> = page
            .lines
            .iter()
            .filter(|l| {
                let t = l.text.trim_start().to_lowercase();
                t.starts_with("place") || t.starts_with("date")
            })
            .map(Line::bounds)
            .collect();
        for anchor in page_anchors(page, &phrases) {
            all.push(spot(page, count, anchor, &context, w, h));
        }
    }
    all.sort_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then(b.anchor.page.cmp(&a.anchor.page))
            .then(b.anchor.rect.y.total_cmp(&a.anchor.rect.y))
    });
    // Two phrases of one signature block give one spot.
    let mut out: Vec<Spot> = Vec::new();
    for s in all {
        if !out
            .iter()
            .any(|o| o.anchor.page == s.anchor.page && overlap(o.rect, s.rect) > 0.5 * w * h)
        {
            out.push(s);
        }
    }
    Ok(out)
}

fn spot(
    page: &Page,
    count: usize,
    anchor: Anchor,
    context: &[DisplayRect],
    w: f64,
    h: f64,
) -> Spot {
    let w = w.min(page.width);
    let h = h.min(page.height);
    let a = anchor.rect;
    let clamp = |x: f64, y: f64| DisplayRect {
        x: x.clamp(0.0, page.width - w),
        y: y.clamp(0.0, page.height - h),
        w,
        h,
    };
    let crowding = |r: DisplayRect| -> f64 {
        page.words.iter().map(|o| overlap(r, *o)).sum::<f64>()
            + page.fields.iter().map(|(o, _)| overlap(r, *o)).sum::<f64>()
    };
    let mut best: Option<(DisplayRect, f64)> = None;
    let mut natural = None;
    'search: for side in anchor.kind.sides() {
        for step in 0..8 {
            let d = GAP + step as f64 * 6.0;
            let tries = match side {
                Side::Above | Side::Below => {
                    let y = if side == Side::Above {
                        a.y - d - h
                    } else {
                        a.y + a.h + d
                    };
                    [a.x + a.w / 2.0 - w / 2.0, a.x, a.x + a.w - w].map(|x| clamp(x, y))
                }
                Side::Right => {
                    let x = a.x + a.w + d;
                    [a.y + a.h / 2.0 - h / 2.0, a.y + a.h - h, a.y].map(|y| clamp(x, y))
                }
            };
            for r in tries {
                natural.get_or_insert(r);
                let c = crowding(r);
                if best.is_none_or(|(_, b)| c < b) {
                    best = Some((r, c));
                }
                if c < 1.0 {
                    break 'search;
                }
            }
        }
    }
    let (rect, crowd) = best.unwrap_or((clamp(a.x, a.y - GAP - h), 0.0));
    let free = crowd < 1.0;
    let mut score = anchor.kind.weight();
    if anchor.standalone {
        score += 25.0;
    }
    score += 30.0 * (anchor.page + 1) as f64 / count.max(1) as f64;
    score += 15.0 * (a.y + a.h / 2.0) / page.height.max(1.0);
    if context.iter().any(|c| (c.y - a.y).abs() < 150.0) {
        score += 10.0;
    }
    if !free {
        score -= 20.0;
    }
    // Someone has signed right there already.
    if let Some(n) = natural
        && page
            .fields
            .iter()
            .any(|(f, signed)| *signed && overlap(n, *f) > 0.0)
    {
        score -= 40.0;
    }
    Spot {
        anchor,
        rect,
        free,
        score,
    }
}

fn overlap(a: DisplayRect, b: DisplayRect) -> f64 {
    let w = (a.x + a.w).min(b.x + b.w) - a.x.max(b.x);
    let h = (a.y + a.h).min(b.y + b.h) - a.y.max(b.y);
    if w > 0.0 && h > 0.0 { w * h } else { 0.0 }
}

/// Moves the box of `req` to the best spot, keeping its size; `page` limits
/// the search to that page. Left alone (and `None`) when nothing is found,
/// the signature is invisible, goes into a field or onto several pages.
pub fn place(
    req: &mut SignRequest,
    input: &[u8],
    phrases: &[String],
    holder: &Holder,
    page: Option<usize>,
) -> Option<Spot> {
    if req.field.is_some() || req.pages.len() > 1 {
        return None;
    }
    let r = req.rect?;
    let spot = spots(input, req.password.as_deref(), phrases, holder, r.w, r.h)
        .ok()?
        .into_iter()
        .find(|s| page.is_none_or(|p| s.anchor.page == p))?;
    req.page = spot.anchor.page;
    req.rect = Some(spot.rect);
    req.pages.clear();
    Some(spot)
}

#[cfg(test)]
mod tests {
    use super::*;

    const STANDARD: &[u8] = include_bytes!("../testdata/text/standard.pdf");

    fn holder() -> Holder {
        Holder {
            name: Some("DK RAHUL".into()),
            organisation: Some("TrackMyTech Private Limited".into()),
        }
    }

    #[test]
    fn phrases_are_filled_and_normalized() {
        let f = filled(&[], &holder());
        let texts: Vec<String> = f.iter().map(|(_, n)| n.iter().collect()).collect();
        assert!(texts.contains(&"for trackmytech private limited".to_string()));
        assert!(texts.contains(&"dk rahul".to_string()));
        // Without a certificate the placeholders drop out.
        assert_eq!(
            filled(&[], &Holder::default()).len(),
            DEFAULT_PHRASES.len() - 2
        );
        let custom = filled(&["  Partner ".into(), "{NAME}".into()], &holder());
        assert_eq!(custom[0].0, "Partner");
        assert_eq!(custom[1].1.iter().collect::<String>(), "dk rahul");
    }

    #[test]
    fn standalone_lines() {
        assert!(standalone("Authorised Signatory", 0, 20));
        assert!(standalone("Name: DK RAHUL", 6, 14));
        assert!(standalone("Signature: ____________", 0, 9));
        assert!(!standalone(
            "This digital signature certificate is issued by",
            13,
            22
        ));
    }

    #[test]
    fn finds_anchors_with_their_boxes() {
        let found = anchors(STANDARD, None, &[], &holder()).unwrap();
        let texts: Vec<(&str, usize)> = found.iter().map(|a| (a.text.as_str(), a.page)).collect();
        assert!(
            texts.contains(&("For TrackMyTech Private Limited", 1)),
            "{texts:?}"
        );
        assert!(texts.contains(&("Authorised Signatory", 1)), "{texts:?}");
        // Inside other words, or a longer phrase, is not a match of its own.
        assert!(!texts.contains(&("Signatory", 1)), "{texts:?}");
        let a = found
            .iter()
            .find(|a| a.text == "Authorised Signatory")
            .unwrap();
        assert_eq!(a.kind, Kind::Signatory);
        assert!(a.standalone);
        assert!((a.rect.x - 380.0).abs() < 0.5);
    }

    #[test]
    fn best_spot_is_above_authorised_signatory() {
        let s = spots(STANDARD, None, &[], &holder(), 170.0, 55.0).unwrap();
        let best = &s[0];
        assert_eq!(best.anchor.text, "Authorised Signatory");
        assert!(best.free, "{best:?}");
        // Between "For …" and "Authorised Signatory", within the page.
        let org = anchors(STANDARD, None, &[], &holder())
            .unwrap()
            .into_iter()
            .find(|a| a.kind == Kind::Organisation)
            .unwrap()
            .rect;
        let sig = best.anchor.rect;
        assert!(best.rect.y >= org.y + org.h, "{best:?} {org:?}");
        assert!(best.rect.y + best.rect.h <= sig.y, "{best:?}");
        assert!(best.rect.x + best.rect.w <= 595.28);
        // The spot below "For …" is the same one, so it is not offered again.
        assert!(!s.iter().any(|s| s.anchor.kind == Kind::Organisation));
        // Every spot keeps the box size.
        assert!(s.iter().all(|s| s.rect.w == 170.0 && s.rect.h == 55.0));
    }

    #[test]
    fn place_moves_the_box_or_leaves_it() {
        let mut req = SignRequest {
            page: 0,
            rect: Some(DisplayRect {
                x: 10.0,
                y: 10.0,
                w: 150.0,
                h: 50.0,
            }),
            ..Default::default()
        };
        let spot = place(&mut req, STANDARD, &[], &holder(), None).unwrap();
        assert_eq!(req.page, 1);
        assert_eq!(req.rect, Some(spot.rect));
        // Only on a page with an anchor.
        let before = req.clone();
        assert!(place(&mut req, STANDARD, &[], &holder(), Some(0)).is_none());
        assert_eq!(req.rect, before.rect);
        // No phrase on the page at all.
        let mut req = before.clone();
        assert!(place(&mut req, STANDARD, &["Witness".into()], &holder(), None).is_none());
        assert_eq!(req.rect, before.rect);
    }

    #[test]
    fn rotated_page_spots_are_in_display_space() {
        let data = include_bytes!("../testdata/text/rotated.pdf");
        let s = spots(data, None, &[], &Holder::default(), 170.0, 55.0).unwrap();
        let best = &s[0];
        assert_eq!(best.anchor.text, "Authorised Signatory");
        // A landscape media box turned to portrait: 595 x 842 as displayed,
        // the box centred above the phrase.
        let a = best.anchor.rect;
        assert!((a.x - 380.0).abs() < 1.0, "{a:?}");
        assert!(best.rect.x + best.rect.w <= 595.3 && best.rect.y + best.rect.h <= 841.9);
        assert!(best.rect.y + best.rect.h <= a.y + 0.01, "{best:?}");
        assert!(
            (best.rect.x + 85.0 - (a.x + a.w / 2.0)).abs() < 0.01,
            "{best:?}"
        );
    }
}
