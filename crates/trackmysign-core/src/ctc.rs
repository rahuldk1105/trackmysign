//! "Certified true copy" stamps: a box of text on every page (or chosen
//! pages) that a director or company secretary certifies, added with the
//! signature that certifies it.
//!
//! Each stamp is one more widget of the new signature field, drawn by the
//! signature box's engine ([`crate::pdf::appearance`]) and written in the
//! same incremental update. That keeps earlier signatures valid: validators
//! (this crate's [`crate::verify`], pyHanko) count a new signature field's
//! widgets as "signatures added", whereas free annotations such as `/Stamp`
//! after a signature are commenting, which a certification at level 2
//! forbids and pyHanko reports as unexplained changes. The page content is
//! never touched, and the signature covers the stamps.

use serde::{Deserialize, Deserializer, Serialize};

use crate::image::StampImage;
use crate::pdf::docmdp::DocMdp;
use crate::pdf::sign::DisplayRect;
use crate::stamp::{Align, LineField, StampStyle};
use crate::{Error, pdf};

/// The newest [`CtcStyle::version`] this build understands.
pub const CTC_VERSION: u32 = 1;

/// The first line of a new stamp.
pub const HEADING: &str = "CERTIFIED TRUE COPY";

/// The heading (`custom_1`), "For {organisation}", the name, the role and a
/// free line (`custom_2`, e.g. "DIN: 01234567") when it is filled in.
pub const CTC_LINES: [LineField; 5] = [
    LineField::Custom1,
    LineField::Organisation,
    LineField::Name,
    LineField::Role,
    LineField::Custom2,
];

/// Which corner of the page the stamp keeps its distance from.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Corner {
    #[default]
    TopRight,
    TopLeft,
    BottomRight,
    BottomLeft,
}

/// The stamp: what it says and how it looks (a signature box style), its
/// size and where it sits. Saved with presets as JSON (snake_case); a
/// partial `style` is laid over [`ctc_box_style`], not the signature box's
/// defaults.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "snake_case")]
pub struct CtcStyle {
    pub version: u32,
    #[serde(deserialize_with = "over_ctc_default")]
    pub style: StampStyle,
    pub corner: Corner,
    /// Points from the corner's side and top or bottom edge, on every page
    /// (as the reader sees it, rotation applied).
    pub margin_x: f64,
    pub margin_y: f64,
    /// Points; shrunk to fit a smaller page.
    pub width: f64,
    pub height: f64,
}

impl Default for CtcStyle {
    fn default() -> Self {
        CtcStyle {
            version: CTC_VERSION,
            style: ctc_box_style(),
            corner: Corner::TopRight,
            margin_x: 36.0,
            margin_y: 36.0,
            width: 180.0,
            height: 72.0,
        }
    }
}

/// How a new stamp looks: the usual border, centred text, the heading bold.
pub fn ctc_box_style() -> StampStyle {
    StampStyle {
        lines: Some(CTC_LINES.to_vec()),
        custom_1: HEADING.into(),
        role: "Director".into(),
        bold_name: false,
        bold_first_line: true,
        align: Align::Center,
        ..Default::default()
    }
}

fn over_ctc_default<'de, D: Deserializer<'de>>(d: D) -> Result<StampStyle, D::Error> {
    use serde::de::Error as _;
    let given = serde_json::Value::deserialize(d)?;
    let mut style = serde_json::to_value(ctc_box_style()).map_err(D::Error::custom)?;
    if let (Some(base), serde_json::Value::Object(given)) = (style.as_object_mut(), given) {
        base.extend(given);
    }
    serde_json::from_value(style).map_err(D::Error::custom)
}

impl CtcStyle {
    /// A stamp from JSON, checked.
    pub fn from_json(json: &[u8]) -> Result<Self, String> {
        let style: CtcStyle = serde_json::from_slice(json).map_err(|e| e.to_string())?;
        style.validate()?;
        Ok(style)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.version > CTC_VERSION {
            return Err(format!(
                "The certified true copy stamp is version {}; this version of TrackMy Sign reads up to {CTC_VERSION}. Update TrackMy Sign.",
                self.version
            ));
        }
        if !(20.0..=600.0).contains(&self.width) || !(10.0..=600.0).contains(&self.height) {
            return Err(
                "The certified true copy stamp must be 20 to 600 points wide and 10 to 600 tall."
                    .into(),
            );
        }
        if !(0.0..=1000.0).contains(&self.margin_x) || !(0.0..=1000.0).contains(&self.margin_y) {
            return Err(
                "The certified true copy stamp must be 0 to 1000 points from the edges.".into(),
            );
        }
        self.style.validate()
    }

    /// Where the stamp goes on a page displayed `w`×`h`: kept inside it.
    pub fn rect_on(&self, w: f64, h: f64) -> DisplayRect {
        let sw = self.width.min(w);
        let sh = self.height.min(h);
        let x = match self.corner {
            Corner::TopLeft | Corner::BottomLeft => self.margin_x,
            Corner::TopRight | Corner::BottomRight => w - sw - self.margin_x,
        };
        let y = match self.corner {
            Corner::TopLeft | Corner::TopRight => self.margin_y,
            Corner::BottomLeft | Corner::BottomRight => h - sh - self.margin_y,
        };
        DisplayRect {
            x: x.clamp(0.0, w - sw),
            y: y.clamp(0.0, h - sh),
            w: sw,
            h: sh,
        }
    }
}

/// Stamps to add with a signature.
#[derive(Debug, Clone, Default)]
pub struct Ctc {
    pub style: CtcStyle,
    /// Zero-based pages that get a stamp; every page when empty.
    pub pages: Vec<usize>,
    /// Company seal, placed as `style.style.seal` says.
    pub seal: Option<StampImage>,
}

/// Whether `input` may get stamps: not when signing into an existing field
/// (checked by the caller) and not on a document certified to allow only
/// form filling and signing, or no changes at all.
pub fn check_permitted(input: &[u8], password: Option<&str>) -> Result<(), Error> {
    let doc = pdf::reader::Document::open(input, password)?;
    match pdf::docmdp::of_document(&doc)? {
        Some(DocMdp::NoChanges) => Err(Error::NotPermitted(
            "The document is certified with no changes allowed. \
             Another signature would invalidate the certification."
                .into(),
        )),
        Some(DocMdp::FormFilling) => Err(Error::NotPermitted(
            "The document is certified to allow only form filling and signing. \
             Certified true copy stamps add marks to its pages, which that certification \
             does not allow. Sign it without the stamps."
                .into(),
        )),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stamp::{FontFamily, StampValues, stamp_lines};
    use chrono::DateTime;

    #[test]
    fn default_lines() {
        let values = StampValues {
            name: "RAMESH KUMAR".into(),
            organisation: Some("ACME LTD".into()),
            reason: None,
            location: None,
            time: DateTime::parse_from_rfc3339("2026-10-24T09:05:07+05:30").unwrap(),
        };
        let style = CtcStyle::default().style;
        let lines: Vec<String> = stamp_lines(&style, &values)
            .into_iter()
            .map(|l| l.text)
            .collect();
        assert_eq!(
            lines,
            [
                "CERTIFIED TRUE COPY",
                "For ACME LTD",
                "RAMESH KUMAR",
                "Director"
            ]
        );
        let d = crate::stamp::drawing(&style, &values, Default::default(), 180.0, 72.0);
        assert!(d.text[0].bold && !d.text[2].bold);
        assert!((d.text[0].x + d.text[0].width / 2.0 - 90.0).abs() < 1e-9);
    }

    #[test]
    fn json_lays_over_the_stamp_defaults() {
        let s = CtcStyle::from_json(
            br#"{"corner":"bottom_left","width":150,"style":{"font":"times","custom_2":"DIN: 01234567"}}"#,
        )
        .unwrap();
        assert_eq!(s.corner, Corner::BottomLeft);
        assert_eq!(s.width, 150.0);
        assert_eq!(s.height, 72.0);
        assert_eq!(s.style.font, FontFamily::Times);
        assert_eq!(s.style.custom_1, HEADING);
        assert_eq!(s.style.custom_2, "DIN: 01234567");
        assert!(s.style.bold_first_line && !s.style.bold_name);
        assert_eq!(CtcStyle::from_json(b"{}").unwrap(), CtcStyle::default());
        let back: CtcStyle = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(back, s);
        assert!(CtcStyle::from_json(br#"{"version":2}"#).is_err());
        assert!(CtcStyle::from_json(br#"{"width":5}"#).is_err());
        assert!(CtcStyle::from_json(br##"{"style":{"text_color":"blue"}}"##).is_err());
    }

    #[test]
    fn placed_by_corner() {
        let s = CtcStyle::default();
        let r = s.rect_on(595.0, 842.0);
        assert_eq!(
            (r.x, r.y, r.w, r.h),
            (595.0 - 180.0 - 36.0, 36.0, 180.0, 72.0)
        );
        let s = CtcStyle {
            corner: Corner::BottomLeft,
            margin_x: 10.0,
            margin_y: 20.0,
            ..Default::default()
        };
        let r = s.rect_on(842.0, 595.0);
        assert_eq!((r.x, r.y), (10.0, 595.0 - 72.0 - 20.0));
        // A page smaller than the stamp: shrunk and kept inside.
        let r = s.rect_on(100.0, 50.0);
        assert_eq!((r.x, r.y, r.w, r.h), (0.0, 0.0, 100.0, 50.0));
    }
}
