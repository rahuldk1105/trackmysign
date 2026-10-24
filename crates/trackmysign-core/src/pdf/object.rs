//! PDF object model and a lossless-enough parser.
//!
//! Numbers keep their original source text so that objects we copy into an
//! incremental update (page, catalog, AcroForm) are byte-for-byte identical in
//! meaning to the original — re-formatting `841.8897637795` as an `f32` would
//! count as a modification to signature validators.

use std::fmt::Write as _;

#[derive(Debug, Clone, PartialEq)]
pub enum Obj {
    Null,
    Bool(bool),
    /// Raw numeric token, e.g. `12`, `-0.5`, `841.8897637795`.
    Num(String),
    Str(Vec<u8>),
    Name(Vec<u8>),
    Array(Vec<Obj>),
    Dict(Dict),
    Ref(u32, u16),
    Stream(Dict, Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Dict(pub Vec<(Vec<u8>, Obj)>);

impl Dict {
    pub fn new() -> Self {
        Dict(Vec::new())
    }
    pub fn get(&self, key: &str) -> Option<&Obj> {
        self.0
            .iter()
            .find(|(k, _)| k == key.as_bytes())
            .map(|(_, v)| v)
    }
    pub fn set(&mut self, key: &str, value: Obj) {
        if let Some(slot) = self.0.iter_mut().find(|(k, _)| k == key.as_bytes()) {
            slot.1 = value;
        } else {
            self.0.push((key.as_bytes().to_vec(), value));
        }
    }
    pub fn remove(&mut self, key: &str) {
        self.0.retain(|(k, _)| k != key.as_bytes());
    }
    pub fn with(mut self, key: &str, value: Obj) -> Self {
        self.set(key, value);
        self
    }
}

impl Obj {
    pub fn name(s: &str) -> Obj {
        Obj::Name(s.as_bytes().to_vec())
    }
    pub fn int(n: i64) -> Obj {
        Obj::Num(n.to_string())
    }
    pub fn real(v: f64) -> Obj {
        Obj::Num(fmt_real(v))
    }
    pub fn str(s: &str) -> Obj {
        Obj::Str(s.as_bytes().to_vec())
    }
    pub fn as_dict(&self) -> Option<&Dict> {
        match self {
            Obj::Dict(d) | Obj::Stream(d, _) => Some(d),
            _ => None,
        }
    }
    pub fn as_array(&self) -> Option<&Vec<Obj>> {
        match self {
            Obj::Array(a) => Some(a),
            _ => None,
        }
    }
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Obj::Num(s) => s.parse::<f64>().ok().or_else(|| lenient_number(s)),
            _ => None,
        }
    }
    pub fn as_i64(&self) -> Option<i64> {
        self.as_f64().map(|f| f as i64)
    }
    pub fn is_name(&self, n: &str) -> bool {
        matches!(self, Obj::Name(v) if v == n.as_bytes())
    }
}

/// Some producers write numbers like `--5` or `5.-`; take what we can.
fn lenient_number(s: &str) -> Option<f64> {
    let neg = s.starts_with('-');
    let cleaned: String = s
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let first_dot = cleaned.find('.');
    let cleaned: String = cleaned
        .char_indices()
        .filter(|(i, c)| *c != '.' || Some(*i) == first_dot)
        .map(|(_, c)| c)
        .collect();
    let v: f64 = cleaned.parse().ok()?;
    Some(if neg { -v } else { v })
}

pub fn fmt_real(v: f64) -> String {
    if (v - v.round()).abs() < 1e-9 {
        return format!("{}", v.round() as i64);
    }
    let mut s = format!("{:.4}", v);
    while s.ends_with('0') {
        s.pop();
    }
    if s.ends_with('.') {
        s.pop();
    }
    if s == "-0" {
        s = "0".into();
    }
    s
}

// ---------------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------------

pub fn is_ws(b: u8) -> bool {
    matches!(b, 0 | 9 | 10 | 12 | 13 | 32)
}

pub fn is_delim(b: u8) -> bool {
    matches!(
        b,
        b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
    )
}

#[derive(Debug, Clone, PartialEq)]
pub enum Tok {
    Num(String),
    Str(Vec<u8>),
    Name(Vec<u8>),
    ArrOpen,
    ArrClose,
    DictOpen,
    DictClose,
    Kw(Vec<u8>),
}

pub struct Lexer<'a> {
    pub data: &'a [u8],
    pub pos: usize,
}

#[derive(Debug, thiserror::Error)]
#[error("PDF syntax error at byte {pos}: {msg}")]
pub struct SyntaxError {
    pub pos: usize,
    pub msg: String,
}

pub type PResult<T> = Result<T, SyntaxError>;

impl<'a> Lexer<'a> {
    pub fn new(data: &'a [u8], pos: usize) -> Self {
        Lexer { data, pos }
    }

    fn err<T>(&self, msg: &str) -> PResult<T> {
        Err(SyntaxError {
            pos: self.pos,
            msg: msg.to_string(),
        })
    }

    pub fn skip_ws(&mut self) {
        while self.pos < self.data.len() {
            let b = self.data[self.pos];
            if is_ws(b) {
                self.pos += 1;
            } else if b == b'%' {
                while self.pos < self.data.len() && !matches!(self.data[self.pos], b'\r' | b'\n') {
                    self.pos += 1;
                }
            } else {
                break;
            }
        }
    }

    pub fn next_tok(&mut self) -> PResult<Option<Tok>> {
        self.skip_ws();
        let d = self.data;
        if self.pos >= d.len() {
            return Ok(None);
        }
        let b = d[self.pos];
        match b {
            b'[' => {
                self.pos += 1;
                Ok(Some(Tok::ArrOpen))
            }
            b']' => {
                self.pos += 1;
                Ok(Some(Tok::ArrClose))
            }
            b'<' if d.get(self.pos + 1) == Some(&b'<') => {
                self.pos += 2;
                Ok(Some(Tok::DictOpen))
            }
            b'>' if d.get(self.pos + 1) == Some(&b'>') => {
                self.pos += 2;
                Ok(Some(Tok::DictClose))
            }
            b'<' => self.hex_string().map(Some),
            b'(' => self.literal_string().map(Some),
            b'/' => {
                self.pos += 1;
                let mut name = Vec::new();
                while self.pos < d.len() && !is_ws(d[self.pos]) && !is_delim(d[self.pos]) {
                    let c = d[self.pos];
                    if c == b'#'
                        && self.pos + 2 < d.len()
                        && let Some(v) = hex2(d[self.pos + 1], d[self.pos + 2])
                    {
                        name.push(v);
                        self.pos += 3;
                        continue;
                    }
                    name.push(c);
                    self.pos += 1;
                }
                Ok(Some(Tok::Name(name)))
            }
            b'{' | b'}' => {
                self.pos += 1;
                Ok(Some(Tok::Kw(vec![b])))
            }
            b')' | b'>' => {
                // Stray delimiter; skip it rather than failing the whole file.
                self.pos += 1;
                self.next_tok()
            }
            b'0'..=b'9' | b'+' | b'-' | b'.' => {
                let start = self.pos;
                while self.pos < d.len() && matches!(d[self.pos], b'0'..=b'9' | b'+' | b'-' | b'.')
                {
                    self.pos += 1;
                }
                Ok(Some(Tok::Num(
                    String::from_utf8_lossy(&d[start..self.pos]).into_owned(),
                )))
            }
            _ => {
                let start = self.pos;
                while self.pos < d.len() && !is_ws(d[self.pos]) && !is_delim(d[self.pos]) {
                    self.pos += 1;
                }
                Ok(Some(Tok::Kw(d[start..self.pos].to_vec())))
            }
        }
    }

    fn hex_string(&mut self) -> PResult<Tok> {
        self.pos += 1;
        let mut nibbles = Vec::new();
        while self.pos < self.data.len() {
            let c = self.data[self.pos];
            self.pos += 1;
            if c == b'>' {
                if nibbles.len() % 2 == 1 {
                    nibbles.push(0);
                }
                return Ok(Tok::Str(
                    nibbles.chunks(2).map(|p| p[0] << 4 | p[1]).collect(),
                ));
            }
            if let Some(v) = hexval(c) {
                nibbles.push(v);
            }
        }
        self.err("unterminated hex string")
    }

    fn literal_string(&mut self) -> PResult<Tok> {
        self.pos += 1;
        let d = self.data;
        let mut out = Vec::new();
        let mut depth = 1;
        while self.pos < d.len() {
            let c = d[self.pos];
            self.pos += 1;
            match c {
                b'(' => {
                    depth += 1;
                    out.push(c);
                }
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Ok(Tok::Str(out));
                    }
                    out.push(c);
                }
                b'\\' => {
                    let Some(&e) = d.get(self.pos) else { break };
                    self.pos += 1;
                    match e {
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'b' => out.push(8),
                        b'f' => out.push(12),
                        b'\r' => {
                            if d.get(self.pos) == Some(&b'\n') {
                                self.pos += 1;
                            }
                        }
                        b'\n' => {}
                        b'0'..=b'7' => {
                            let mut v = (e - b'0') as u32;
                            for _ in 0..2 {
                                match d.get(self.pos) {
                                    Some(&o @ b'0'..=b'7') => {
                                        v = v * 8 + (o - b'0') as u32;
                                        self.pos += 1;
                                    }
                                    _ => break,
                                }
                            }
                            out.push(v as u8);
                        }
                        other => out.push(other),
                    }
                }
                _ => out.push(c),
            }
        }
        self.err("unterminated literal string")
    }
}

fn hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn hex2(a: u8, b: u8) -> Option<u8> {
    Some(hexval(a)? << 4 | hexval(b)?)
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

pub struct Parser<'a> {
    pub lx: Lexer<'a>,
}

const MAX_DEPTH: usize = 256;

impl<'a> Parser<'a> {
    pub fn new(data: &'a [u8], pos: usize) -> Self {
        Parser {
            lx: Lexer::new(data, pos),
        }
    }

    pub fn parse(&mut self) -> PResult<Obj> {
        let tok = self.lx.next_tok()?;
        self.parse_from(tok, 0)
    }

    fn parse_from(&mut self, tok: Option<Tok>, depth: usize) -> PResult<Obj> {
        if depth > MAX_DEPTH {
            return self.lx.err("nesting too deep");
        }
        let Some(tok) = tok else {
            return self.lx.err("unexpected end of data");
        };
        Ok(match tok {
            Tok::Num(n) => {
                // Look ahead for `<int> <int> R`.
                let save = self.lx.pos;
                if is_uint(&n)
                    && let Ok(Some(Tok::Num(g))) = self.lx.next_tok()
                    && is_uint(&g)
                    && let Ok(Some(Tok::Kw(k))) = self.lx.next_tok()
                    && k == b"R"
                    && let (Ok(id), Ok(gn)) = (n.parse(), g.parse())
                {
                    return Ok(Obj::Ref(id, gn));
                }
                self.lx.pos = save;
                Obj::Num(n)
            }
            Tok::Str(s) => Obj::Str(s),
            Tok::Name(n) => Obj::Name(n),
            Tok::ArrOpen => {
                let mut items = Vec::new();
                loop {
                    match self.lx.next_tok()? {
                        Some(Tok::ArrClose) => break,
                        None => return self.lx.err("unterminated array"),
                        t => items.push(self.parse_from(t, depth + 1)?),
                    }
                }
                Obj::Array(items)
            }
            Tok::DictOpen => {
                let mut d = Dict::new();
                loop {
                    match self.lx.next_tok()? {
                        Some(Tok::DictClose) => break,
                        Some(Tok::Name(k)) => {
                            let t = self.lx.next_tok()?;
                            if t == Some(Tok::DictClose) {
                                d.0.push((k, Obj::Null));
                                break;
                            }
                            let v = self.parse_from(t, depth + 1)?;
                            d.0.push((k, v));
                        }
                        None => return self.lx.err("unterminated dictionary"),
                        Some(_) => {} // garbage inside a dict: skip
                    }
                }
                Obj::Dict(d)
            }
            Tok::Kw(k) => match k.as_slice() {
                b"true" => Obj::Bool(true),
                b"false" => Obj::Bool(false),
                b"null" => Obj::Null,
                _ => {
                    return self.lx.err(&format!(
                        "unexpected keyword {}",
                        String::from_utf8_lossy(&k)
                    ));
                }
            },
            Tok::ArrClose | Tok::DictClose => return self.lx.err("unexpected closing delimiter"),
        })
    }
}

fn is_uint(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

// ---------------------------------------------------------------------------
// Serializer
// ---------------------------------------------------------------------------

pub fn write_obj(out: &mut Vec<u8>, obj: &Obj) {
    match obj {
        Obj::Null => out.extend_from_slice(b"null"),
        Obj::Bool(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
        Obj::Num(n) => out.extend_from_slice(n.as_bytes()),
        Obj::Str(s) => write_hex_string(out, s),
        Obj::Name(n) => write_name(out, n),
        Obj::Array(a) => {
            out.push(b'[');
            for (i, o) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b' ');
                }
                write_obj(out, o);
            }
            out.push(b']');
        }
        Obj::Dict(d) => write_dict(out, d),
        Obj::Ref(id, gn) => out.extend_from_slice(format!("{id} {gn} R").as_bytes()),
        Obj::Stream(d, data) => {
            let mut d = d.clone();
            d.set("Length", Obj::int(data.len() as i64));
            write_dict(out, &d);
            out.extend_from_slice(b"\nstream\n");
            out.extend_from_slice(data);
            out.extend_from_slice(b"\nendstream");
        }
    }
}

pub fn write_dict(out: &mut Vec<u8>, d: &Dict) {
    out.extend_from_slice(b"<<");
    for (k, v) in &d.0 {
        write_name(out, k);
        out.push(b' ');
        write_obj(out, v);
        out.push(b'\n');
    }
    out.extend_from_slice(b">>");
}

pub fn write_name(out: &mut Vec<u8>, n: &[u8]) {
    out.push(b'/');
    for &b in n {
        if (0x21..=0x7e).contains(&b) && !is_delim(b) && b != b'#' {
            out.push(b);
        } else {
            let _ = write!(HexSink(out), "#{:02X}", b);
        }
    }
}

pub fn write_hex_string(out: &mut Vec<u8>, s: &[u8]) {
    out.push(b'<');
    for b in s {
        let _ = write!(HexSink(out), "{:02X}", b);
    }
    out.push(b'>');
}

struct HexSink<'a>(&'a mut Vec<u8>);
impl std::fmt::Write for HexSink<'_> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        self.0.extend_from_slice(s.as_bytes());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Obj {
        Parser::new(s.as_bytes(), 0).parse().unwrap()
    }

    #[test]
    fn parses_basic_objects() {
        assert_eq!(p("12 0 R"), Obj::Ref(12, 0));
        assert_eq!(p("841.8897637795"), Obj::Num("841.8897637795".into()));
        assert_eq!(p("(a\\(b\\)c\\101)"), Obj::Str(b"a(b)cA".to_vec()));
        assert_eq!(p("<48656C6C6F>"), Obj::Str(b"Hello".to_vec()));
        assert_eq!(p("/A#20B"), Obj::Name(b"A B".to_vec()));
        let d = p("<< /Type /Page /Kids [1 0 R 2 0 R] /Rotate 90 /X << /Y null >> >>");
        let d = d.as_dict().unwrap();
        assert!(d.get("Type").unwrap().is_name("Page"));
        assert_eq!(d.get("Kids").unwrap().as_array().unwrap().len(), 2);
        assert_eq!(d.get("Rotate").unwrap().as_i64(), Some(90));
    }

    #[test]
    fn numbers_round_trip_exactly() {
        let src = "[0 0 595.2756 841.8897637795 -.5]";
        let mut out = Vec::new();
        write_obj(&mut out, &p(src));
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "[0 0 595.2756 841.8897637795 -.5]"
        );
    }

    #[test]
    fn names_are_escaped() {
        let mut out = Vec::new();
        write_name(&mut out, b"A B#(");
        assert_eq!(out, b"/A#20B#23#28");
    }
}
