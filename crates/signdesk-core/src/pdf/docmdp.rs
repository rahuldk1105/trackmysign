//! Certification ("author") signatures: the DocMDP transform that says which
//! changes later revisions may make (ISO 32000-1, 12.8.2.2).

use super::object::{Dict, Obj};
use super::reader::{Document, Result};

/// What a certified document still allows, by its `/P` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DocMdp {
    /// 1: no changes at all; even another signature breaks the certification.
    NoChanges,
    /// 2: filling in forms and signing.
    FormFilling,
    /// 3: also adding, editing and deleting comments.
    Annotations,
}

impl DocMdp {
    pub fn level(self) -> u8 {
        match self {
            DocMdp::NoChanges => 1,
            DocMdp::FormFilling => 2,
            DocMdp::Annotations => 3,
        }
    }

    /// Anything other than 1 or 3 reads as 2, the default.
    pub fn from_level(p: i64) -> Self {
        match p {
            1 => DocMdp::NoChanges,
            3 => DocMdp::Annotations,
            _ => DocMdp::FormFilling,
        }
    }

    /// The `/Reference` array for the signature dictionary.
    pub fn reference(self) -> Obj {
        let params = Dict::new()
            .with("Type", Obj::name("TransformParams"))
            .with("P", Obj::int(self.level() as i64))
            .with("V", Obj::name("1.2"));
        Obj::Array(vec![Obj::Dict(
            Dict::new()
                .with("Type", Obj::name("SigRef"))
                .with("TransformMethod", Obj::name("DocMDP"))
                .with("TransformParams", Obj::Dict(params))
                .with("DigestMethod", Obj::name("SHA256")),
        )])
    }
}

/// The DocMDP permission in a signature dictionary's `/Reference`, if it is
/// a certification signature.
pub fn of_signature(doc: &Document, sig: &Dict) -> Option<DocMdp> {
    let refs = doc.resolve(sig.get("Reference")?).ok()?;
    refs.as_array()?.iter().find_map(|r| {
        let r = doc.resolve(r).ok()?;
        let r = r.as_dict()?;
        if !r.get("TransformMethod")?.is_name("DocMDP") {
            return None;
        }
        let p = r
            .get("TransformParams")
            .and_then(|t| doc.resolve(t).ok())
            .and_then(|t| t.as_dict().and_then(|t| t.get("P")).and_then(Obj::as_i64))
            .unwrap_or(2);
        Some(DocMdp::from_level(p))
    })
}

/// The document's certification, from the catalog's `/Perms /DocMDP`.
pub fn of_document(doc: &Document) -> Result<Option<DocMdp>> {
    let cat = doc.catalog()?;
    let Some(perms) = cat.get("Perms") else {
        return Ok(None);
    };
    let perms = doc.resolve(perms)?;
    let sig = match perms.as_dict().and_then(|p| p.get("DocMDP")) {
        Some(s) => doc.resolve(s)?,
        None => return Ok(None),
    };
    Ok(sig
        .as_dict()
        .map(|s| of_signature(doc, s).unwrap_or(DocMdp::FormFilling)))
}
