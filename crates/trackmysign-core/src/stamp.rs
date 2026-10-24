//! How the visible signature box looks: a [`StampStyle`], saved with
//! presets as JSON (snake_case), and the lines of text it shows.
//!
//! Every field has a default, and the defaults draw the box every earlier
//! version drew, so a missing or empty style changes nothing.

use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};

pub use crate::pdf::appearance::{Drawing, ImageSlot, Images};
use crate::pdf::textdoc::transliterate;

/// The newest [`StampStyle::version`] this build understands.
pub const STYLE_VERSION: u32 = 1;

/// Dark blue offered next to black for the text.
pub const DARK_BLUE: &str = "#1B3A8C";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "snake_case")]
pub struct StampStyle {
    pub version: u32,
    pub layout: Layout,
    /// The lines shown, in order; `None` for "Digitally signed by", the
    /// name, the date, the reason and the location. A line whose value is
    /// empty (no reason given, say) is left out.
    pub lines: Option<Vec<LineField>>,
    /// Shown by [`LineField::Organisation`]; the certificate's O= when empty.
    pub organisation: String,
    /// Shown by [`LineField::Role`], e.g. "Director".
    pub role: String,
    pub custom_1: String,
    pub custom_2: String,
    pub date_format: DateFormat,
    pub font: FontFamily,
    /// Lines with the signer's name are bold and a little larger.
    pub bold_name: bool,
    pub bold_first_line: bool,
    /// Body size in points; `None` makes the text as large as fits. A fixed
    /// size wraps long lines at spaces instead.
    pub font_size: Option<f64>,
    /// `#RRGGBB`.
    pub text_color: String,
    pub align: Align,
    pub border: bool,
    /// `#RRGGBB`; `None` for the usual blue.
    pub border_color: Option<String>,
    pub border_width: f64,
    pub background: Background,
    /// Points inside the edge; `None` scales with the box.
    pub padding: Option<f64>,
    /// A small tick drawn in the top-right corner (decoration only).
    pub tick: bool,
    /// Where the company seal or logo goes, when one is given.
    pub seal: Option<SealStyle>,
}

impl Default for StampStyle {
    fn default() -> Self {
        StampStyle {
            version: STYLE_VERSION,
            layout: Layout::Auto,
            lines: None,
            organisation: String::new(),
            role: String::new(),
            custom_1: String::new(),
            custom_2: String::new(),
            date_format: DateFormat::Classic,
            font: FontFamily::Helvetica,
            bold_name: true,
            bold_first_line: false,
            font_size: None,
            text_color: "#000000".into(),
            align: Align::Left,
            border: true,
            border_color: None,
            border_width: 0.8,
            background: Background::None,
            padding: None,
            tick: false,
            seal: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Layout {
    /// Text, with the signature image where the request puts it, if any.
    #[default]
    Auto,
    TextOnly,
    ImageLeft,
    ImageAbove,
    /// Just the signature image, or the seal when there is no image.
    ImageOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LineField {
    /// "Digitally signed by", with the name on the next line.
    SignedByLabel,
    Name,
    /// "Digitally signed by {name}" on one line.
    SignedBy,
    /// "For {organisation}".
    Organisation,
    Role,
    Date,
    Reason,
    Location,
    #[serde(rename = "custom_1")]
    Custom1,
    #[serde(rename = "custom_2")]
    Custom2,
}

pub const CLASSIC_LINES: [LineField; 5] = [
    LineField::SignedByLabel,
    LineField::Name,
    LineField::Date,
    LineField::Reason,
    LineField::Location,
];

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DateFormat {
    /// 2026.10.24 14:05:09 +05:30
    #[default]
    Classic,
    /// 24-10-2026 14:05 IST
    DdMmYyyyHhMm,
    /// 24-10-2026 14:05:09 IST
    DdMmYyyyHhMmSs,
    /// 24 Oct 2026
    DdMmmYyyy,
}

impl DateFormat {
    pub fn format(self, t: &DateTime<FixedOffset>) -> String {
        // IST by name; anywhere else by offset.
        let zone = || match t.offset().local_minus_utc() {
            19_800 => "IST".to_string(),
            _ => t.format("%:z").to_string(),
        };
        match self {
            DateFormat::Classic => t.format("%Y.%m.%d %H:%M:%S %:z").to_string(),
            DateFormat::DdMmYyyyHhMm => format!("{} {}", t.format("%d-%m-%Y %H:%M"), zone()),
            DateFormat::DdMmYyyyHhMmSs => format!("{} {}", t.format("%d-%m-%Y %H:%M:%S"), zone()),
            DateFormat::DdMmmYyyy => t.format("%d %b %Y").to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FontFamily {
    #[default]
    Helvetica,
    Times,
    Courier,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Align {
    #[default]
    Left,
    Center,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Background {
    #[default]
    None,
    Light,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "snake_case")]
pub struct SealStyle {
    pub position: SealPosition,
    /// 0 (invisible) to 1 (opaque).
    pub opacity: f64,
}

impl Default for SealStyle {
    fn default() -> Self {
        SealStyle {
            position: SealPosition::Right,
            opacity: 1.0,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SealPosition {
    /// Beside the text, on the right.
    #[default]
    Right,
    /// Under the text, across the box.
    Behind,
}

/// RGB, 0 to 1, from `#RRGGBB`.
pub fn parse_color(hex: &str) -> Option<[f64; 3]> {
    let h = hex.trim().strip_prefix('#')?;
    if h.len() != 6 || !h.is_ascii() {
        return None;
    }
    let c = |i: usize| u8::from_str_radix(&h[i..i + 2], 16).ok();
    let round = |v: u8| (v as f64 / 255.0 * 1000.0).round() / 1000.0;
    Some([round(c(0)?), round(c(2)?), round(c(4)?)])
}

const MAX_TEXT: usize = 120;

impl StampStyle {
    /// A style from JSON, checked.
    pub fn from_json(json: &[u8]) -> Result<Self, String> {
        let style: StampStyle = serde_json::from_slice(json).map_err(|e| e.to_string())?;
        style.validate()?;
        Ok(style)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.version > STYLE_VERSION {
            return Err(format!(
                "The signature style is version {}; this version of TrackMySign reads up to {STYLE_VERSION}. Update TrackMySign.",
                self.version
            ));
        }
        if parse_color(&self.text_color).is_none() {
            return Err(format!(
                "Text colour {:?} is not a #RRGGBB colour.",
                self.text_color
            ));
        }
        if let Some(c) = &self.border_color
            && parse_color(c).is_none()
        {
            return Err(format!("Border colour {c:?} is not a #RRGGBB colour."));
        }
        if let Some(s) = self.font_size
            && !(4.0..=36.0).contains(&s)
        {
            return Err("The font size must be between 4 and 36 points.".into());
        }
        if !(0.1..=5.0).contains(&self.border_width) {
            return Err("The border width must be between 0.1 and 5 points.".into());
        }
        if let Some(p) = self.padding
            && !(0.0..=20.0).contains(&p)
        {
            return Err("The padding must be between 0 and 20 points.".into());
        }
        if let Some(s) = &self.seal
            && !(0.0..=1.0).contains(&s.opacity)
        {
            return Err("The seal opacity must be between 0 and 1.".into());
        }
        for s in [
            &self.organisation,
            &self.role,
            &self.custom_1,
            &self.custom_2,
        ] {
            if s.chars().count() > MAX_TEXT {
                return Err(format!(
                    "A line of the signature box is longer than {MAX_TEXT} characters."
                ));
            }
        }
        Ok(())
    }

    /// The fields shown, in order.
    pub fn line_fields(&self) -> &[LineField] {
        self.lines.as_deref().unwrap_or(&CLASSIC_LINES)
    }
}

/// What the box says, before the style lays it out.
#[derive(Debug, Clone)]
pub struct StampValues {
    pub name: String,
    /// The certificate's O=, if any.
    pub organisation: Option<String>,
    pub reason: Option<String>,
    pub location: Option<String>,
    pub time: DateTime<FixedOffset>,
}

/// One line of the box. `name` marks the lines with the signer's name.
#[derive(Debug, Clone, PartialEq)]
pub struct StampLine {
    pub text: String,
    pub name: bool,
}

/// The lines `style` shows for `values`, in order, untransliterated.
pub fn stamp_lines(style: &StampStyle, values: &StampValues) -> Vec<StampLine> {
    let given = |s: Option<&str>| s.map(str::trim).filter(|s| !s.is_empty()).map(String::from);
    let organisation =
        given(Some(&style.organisation)).or_else(|| given(values.organisation.as_deref()));
    let mut out = Vec::new();
    for field in style.line_fields() {
        let (text, name) = match field {
            LineField::SignedByLabel => (Some("Digitally signed by".to_string()), false),
            LineField::Name => (Some(values.name.clone()), true),
            LineField::SignedBy => (Some(format!("Digitally signed by {}", values.name)), true),
            LineField::Organisation => (organisation.as_ref().map(|o| format!("For {o}")), false),
            LineField::Role => (given(Some(&style.role)), false),
            LineField::Date => (
                Some(format!("Date: {}", style.date_format.format(&values.time))),
                false,
            ),
            LineField::Reason => (
                given(values.reason.as_deref()).map(|r| format!("Reason: {r}")),
                false,
            ),
            LineField::Location => (
                given(values.location.as_deref()).map(|l| format!("Location: {l}")),
                false,
            ),
            LineField::Custom1 => (given(Some(&style.custom_1)), false),
            LineField::Custom2 => (given(Some(&style.custom_2)), false),
        };
        if let Some(text) = text {
            out.push(StampLine { text, name });
        }
    }
    out
}

/// A `w`×`h` box laid out exactly as [`crate::sign_pdf`] draws it, for
/// previews.
pub fn drawing(
    style: &StampStyle,
    values: &StampValues,
    images: Images,
    w: f64,
    h: f64,
) -> Drawing {
    crate::pdf::appearance::draw(style, &stamp_lines(style, values), images, w, h)
}

/// `s` as the box prints it: the standard PDF fonts cannot show Indian
/// scripts, so those are transliterated ("रमेश" prints as "Ramesha").
pub fn printed(s: &str) -> String {
    transliterate(s).replace('\n', " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values() -> StampValues {
        StampValues {
            name: "RAMESH KUMAR".into(),
            organisation: Some("ACME LTD".into()),
            reason: Some("Approved".into()),
            location: Some(" ".into()),
            time: DateTime::parse_from_rfc3339("2026-10-24T09:05:07+05:30").unwrap(),
        }
    }

    #[test]
    fn default_lines() {
        let lines = stamp_lines(&StampStyle::default(), &values());
        let text: Vec<&str> = lines.iter().map(|l| l.text.as_str()).collect();
        assert_eq!(
            text,
            [
                "Digitally signed by",
                "RAMESH KUMAR",
                "Date: 2026.10.24 09:05:07 +05:30",
                "Reason: Approved"
            ]
        );
        assert!(lines[1].name && !lines[0].name);
    }

    #[test]
    fn template_lines() {
        let style = StampStyle {
            lines: Some(vec![
                LineField::Role,
                LineField::SignedBy,
                LineField::Organisation,
                LineField::Date,
                LineField::Custom2,
                LineField::Location,
            ]),
            role: "Director".into(),
            custom_2: "GSTIN 33ABCDE1234F1Z5".into(),
            date_format: DateFormat::DdMmYyyyHhMm,
            ..Default::default()
        };
        let text: Vec<String> = stamp_lines(&style, &values())
            .into_iter()
            .map(|l| l.text)
            .collect();
        assert_eq!(
            text,
            [
                "Director",
                "Digitally signed by RAMESH KUMAR",
                "For ACME LTD",
                "Date: 24-10-2026 09:05 IST",
                "GSTIN 33ABCDE1234F1Z5"
            ]
        );
        // A typed organisation wins over the certificate's.
        let style = StampStyle {
            lines: Some(vec![LineField::Organisation]),
            organisation: "Acme Exports".into(),
            ..Default::default()
        };
        assert_eq!(stamp_lines(&style, &values())[0].text, "For Acme Exports");
    }

    #[test]
    fn date_formats() {
        let t = DateTime::parse_from_rfc3339("2026-03-04T17:08:09+01:00").unwrap();
        assert_eq!(
            DateFormat::DdMmYyyyHhMmSs.format(&t),
            "04-03-2026 17:08:09 +01:00"
        );
        assert_eq!(DateFormat::DdMmmYyyy.format(&t), "04 Mar 2026");
    }

    #[test]
    fn json_round_trip_and_checks() {
        let s = StampStyle::from_json(br##"{"font":"times","text_color":"#1B3A8C","align":"center",
            "seal":{"position":"behind","opacity":0.3},"lines":["signed_by","custom_1"],"future":1}"##)
        .unwrap();
        assert_eq!(s.font, FontFamily::Times);
        assert_eq!(s.seal.unwrap().position, SealPosition::Behind);
        assert!(s.border && s.bold_name);
        let back: StampStyle = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(back, s);
        assert_eq!(StampStyle::from_json(b"{}").unwrap(), StampStyle::default());
        assert!(StampStyle::from_json(br#"{"version":2}"#).is_err());
        assert!(StampStyle::from_json(br##"{"text_color":"#12345"}"##).is_err());
        assert!(StampStyle::from_json(br#"{"font_size":80}"#).is_err());
        assert_eq!(parse_color(DARK_BLUE), Some([0.106, 0.227, 0.549]));
    }

    #[test]
    fn printed_text() {
        assert_eq!(printed("रमेश कुमार"), "Ramesha Kumara");
        assert_eq!(printed("Café"), "Café");
    }
}
