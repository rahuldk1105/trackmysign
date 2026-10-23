//! Handwritten signature image for the visible stamp.
//!
//! JPEG is embedded as is (`/DCTDecode`). PNG is decoded to 8-bit grey or RGB
//! with any transparency as a separate `/SMask`, both Flate-compressed.

use std::io::{Cursor, Write};
use std::path::Path;

use flate2::Compression;
use flate2::write::ZlibEncoder;

use crate::Error;
use crate::pdf::object::{Dict, Obj};

/// Where the image goes in the box, relative to the text.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ImagePosition {
    #[default]
    Left,
    Above,
}

#[derive(Clone)]
enum Data {
    Jpeg {
        bytes: Vec<u8>,
        /// Adobe CMYK JPEGs are stored inverted.
        inverted: bool,
    },
    /// Flate-compressed samples.
    Pixels {
        color: Vec<u8>,
        alpha: Option<Vec<u8>>,
    },
}

#[derive(Clone)]
pub struct StampImage {
    pub width: u32,
    pub height: u32,
    /// Colour components per pixel: 1 grey, 3 RGB, 4 CMYK.
    components: u8,
    data: Data,
}

impl std::fmt::Debug for StampImage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match self.data {
            Data::Jpeg { .. } => "JPEG",
            Data::Pixels { alpha: Some(_), .. } => "PNG with alpha",
            Data::Pixels { .. } => "PNG",
        };
        write!(f, "StampImage({kind}, {}x{})", self.width, self.height)
    }
}

fn bad(msg: impl std::fmt::Display) -> Error {
    Error::Image(msg.to_string())
}

fn deflate(data: &[u8]) -> Vec<u8> {
    let mut z = ZlibEncoder::new(Vec::new(), Compression::default());
    z.write_all(data).expect("writing to a Vec");
    z.finish().expect("writing to a Vec")
}

impl StampImage {
    pub fn open(path: &Path) -> Result<Self, Error> {
        Self::from_bytes(&std::fs::read(path)?)
    }

    /// Accepts PNG or JPEG.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.starts_with(&[0xff, 0xd8]) {
            Self::jpeg(bytes)
        } else if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
            Self::png(bytes)
        } else {
            Err(bad("only PNG and JPEG images are supported"))
        }
    }

    /// Width / height.
    pub fn aspect(&self) -> f64 {
        self.width as f64 / self.height as f64
    }

    pub fn has_mask(&self) -> bool {
        matches!(self.data, Data::Pixels { alpha: Some(_), .. })
    }

    fn jpeg(bytes: &[u8]) -> Result<Self, Error> {
        let mut adobe = false;
        let mut i = 2;
        while i + 4 <= bytes.len() {
            if bytes[i] != 0xff {
                return Err(bad("damaged JPEG file"));
            }
            let marker = bytes[i + 1];
            if marker == 0xff {
                i += 1;
                continue;
            }
            if matches!(marker, 0x01 | 0xd0..=0xd7) {
                i += 2;
                continue;
            }
            let len = u16::from_be_bytes([bytes[i + 2], bytes[i + 3]]) as usize;
            let seg = bytes
                .get(i + 4..i + 2 + len)
                .ok_or_else(|| bad("damaged JPEG file"))?;
            match marker {
                0xee if seg.starts_with(b"Adobe") => adobe = true,
                // Start of frame (all kinds except DHT, JPG and DAC).
                0xc0..=0xcf if !matches!(marker, 0xc4 | 0xc8 | 0xcc) => {
                    if seg.len() < 6 {
                        return Err(bad("damaged JPEG file"));
                    }
                    if seg[0] != 8 {
                        return Err(bad("only 8-bit JPEG images are supported"));
                    }
                    let height = u16::from_be_bytes([seg[1], seg[2]]) as u32;
                    let width = u16::from_be_bytes([seg[3], seg[4]]) as u32;
                    let components = seg[5];
                    if width == 0 || height == 0 || !matches!(components, 1 | 3 | 4) {
                        return Err(bad("unsupported JPEG image"));
                    }
                    return Ok(StampImage {
                        width,
                        height,
                        components,
                        data: Data::Jpeg {
                            bytes: bytes.to_vec(),
                            inverted: components == 4 && adobe,
                        },
                    });
                }
                0xda | 0xd9 => break,
                _ => {}
            }
            i += 2 + len;
        }
        Err(bad("damaged JPEG file"))
    }

    fn png(bytes: &[u8]) -> Result<Self, Error> {
        let mut decoder = png::Decoder::new(Cursor::new(bytes));
        decoder.set_transformations(png::Transformations::normalize_to_color8());
        let mut reader = decoder.read_info().map_err(bad)?;
        let size = reader
            .output_buffer_size()
            .ok_or_else(|| bad("image too large"))?;
        let mut buf = vec![0; size];
        let info = reader.next_frame(&mut buf).map_err(bad)?;
        let (width, height) = (info.width, info.height);
        let pixels = &buf[..info.buffer_size()];
        let (components, has_alpha) = match info.color_type {
            png::ColorType::Grayscale => (1, false),
            png::ColorType::GrayscaleAlpha => (1, true),
            png::ColorType::Rgb => (3, false),
            png::ColorType::Rgba => (3, true),
            png::ColorType::Indexed => return Err(bad("unsupported PNG image")),
        };
        let (color, alpha) = if has_alpha {
            let n = components as usize + 1;
            let mut color = Vec::with_capacity(pixels.len() / n * (n - 1));
            let mut alpha = Vec::with_capacity(pixels.len() / n);
            for px in pixels.chunks_exact(n) {
                color.extend_from_slice(&px[..n - 1]);
                alpha.push(px[n - 1]);
            }
            let opaque = alpha.iter().all(|&a| a == 255);
            (color, (!opaque).then_some(alpha))
        } else {
            (pixels.to_vec(), None)
        };
        Ok(StampImage {
            width,
            height,
            components,
            data: Data::Pixels {
                color: deflate(&color),
                alpha: alpha.as_deref().map(deflate),
            },
        })
    }

    fn base_dict(&self, color_space: &str) -> Dict {
        Dict::new()
            .with("Type", Obj::name("XObject"))
            .with("Subtype", Obj::name("Image"))
            .with("Width", Obj::int(self.width as i64))
            .with("Height", Obj::int(self.height as i64))
            .with("ColorSpace", Obj::name(color_space))
            .with("BitsPerComponent", Obj::int(8))
    }

    /// The soft mask (transparency) stream, if the image has one.
    pub fn mask_obj(&self) -> Option<Obj> {
        match &self.data {
            Data::Pixels {
                alpha: Some(alpha), ..
            } => Some(Obj::Stream(
                self.base_dict("DeviceGray")
                    .with("Filter", Obj::name("FlateDecode")),
                alpha.clone(),
            )),
            _ => None,
        }
    }

    /// The image XObject; `smask` refers to the object from [`Self::mask_obj`].
    pub fn image_obj(&self, smask: Option<Obj>) -> Obj {
        let cs = match self.components {
            1 => "DeviceGray",
            4 => "DeviceCMYK",
            _ => "DeviceRGB",
        };
        let mut d = self.base_dict(cs);
        let data = match &self.data {
            Data::Jpeg { bytes, inverted } => {
                d.set("Filter", Obj::name("DCTDecode"));
                if *inverted {
                    d.set(
                        "Decode",
                        Obj::Array([1, 0, 1, 0, 1, 0, 1, 0].map(Obj::int).to_vec()),
                    );
                }
                bytes.clone()
            }
            Data::Pixels { color, .. } => {
                d.set("Filter", Obj::name("FlateDecode"));
                color.clone()
            }
        };
        if let Some(m) = smask {
            d.set("SMask", m);
        }
        Obj::Stream(d, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png_bytes(color: png::ColorType, w: u32, h: u32, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut e = png::Encoder::new(&mut out, w, h);
        e.set_color(color);
        e.set_depth(png::BitDepth::Eight);
        e.write_header().unwrap().write_image_data(data).unwrap();
        out
    }

    #[test]
    fn png_alpha_becomes_mask() {
        let rgba = [255, 0, 0, 255, 0, 0, 255, 0];
        let img = StampImage::from_bytes(&png_bytes(png::ColorType::Rgba, 2, 1, &rgba)).unwrap();
        assert_eq!((img.width, img.height, img.components), (2, 1, 3));
        assert!(img.has_mask());
        let Data::Pixels { color, alpha } = &img.data else {
            panic!()
        };
        let inflate = |d: &[u8]| {
            let mut v = Vec::new();
            std::io::Read::read_to_end(&mut flate2::read::ZlibDecoder::new(d), &mut v).unwrap();
            v
        };
        assert_eq!(inflate(color), [255, 0, 0, 0, 0, 255]);
        assert_eq!(inflate(alpha.as_ref().unwrap()), [255, 0]);
    }

    #[test]
    fn opaque_png_has_no_mask() {
        let ga = [10, 255, 20, 255];
        let img =
            StampImage::from_bytes(&png_bytes(png::ColorType::GrayscaleAlpha, 1, 2, &ga)).unwrap();
        assert_eq!(img.components, 1);
        assert!(!img.has_mask());
        assert!(img.mask_obj().is_none());
    }

    #[test]
    fn jpeg_header() {
        // SOI, APP0 (JFIF), SOF0 3 components 40x20, EOI.
        let mut j = vec![0xff, 0xd8, 0xff, 0xe0, 0, 7, b'J', b'F', b'I', b'F', 0];
        j.extend_from_slice(&[0xff, 0xc0, 0, 17, 8, 0, 20, 0, 40, 3]);
        j.extend_from_slice(&[1, 0x22, 0, 2, 0x11, 1, 3, 0x11, 1]);
        j.extend_from_slice(&[0xff, 0xd9]);
        let img = StampImage::from_bytes(&j).unwrap();
        assert_eq!((img.width, img.height, img.components), (40, 20, 3));
        assert_eq!(img.aspect(), 2.0);
        let Obj::Stream(d, data) = img.image_obj(None) else {
            panic!()
        };
        assert!(d.get("Filter").unwrap().is_name("DCTDecode"));
        assert_eq!(data, j);
    }

    #[test]
    fn rejects_other_files() {
        assert!(StampImage::from_bytes(b"GIF89a").is_err());
        assert!(StampImage::from_bytes(&[0xff, 0xd8, 0x00]).is_err());
    }
}
