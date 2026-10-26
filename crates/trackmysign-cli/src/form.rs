//! `trackmysign form`: list a PDF's fillable fields and fill them in.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::Subcommand;
use trackmysign_core::{
    FieldKind, FillValue, Form, FormField, copy_path_in, fill_form, read_form, write_copy_in,
};

use crate::with_password;

#[derive(Subcommand)]
pub enum FormCmd {
    /// Show the fields that can be filled in, with their current values.
    List {
        pdf: PathBuf,
        /// Print the fields as JSON instead.
        #[arg(long)]
        json: bool,
    },
    /// Fill in fields and save a copy (default <name>_filled.pdf next to the
    /// original). The fields stay fillable.
    Fill {
        pdf: PathBuf,
        /// NAME=VALUE; repeat for more fields (and for several choices of a
        /// list). Check boxes take their value, `Yes`/`On` or `Off`.
        #[arg(long = "set", value_name = "NAME=VALUE")]
        set: Vec<String>,
        /// Values from a JSON file: {"Name": "Rahul", "Agree": true, "Languages": ["Hindi", "Tamil"]}.
        #[arg(long, value_name = "FILE")]
        json: Option<PathBuf>,
        /// File to write; never the original.
        #[arg(short, long)]
        out: Option<PathBuf>,
        /// Go ahead without asking when a field is locked by a signature
        /// (that signature will no longer be valid).
        #[arg(long)]
        yes: bool,
    },
}

pub fn run(cmd: FormCmd, password: Option<&str>) -> Result<()> {
    match cmd {
        FormCmd::List { pdf, json } => {
            let data = std::fs::read(&pdf).with_context(|| format!("reading {}", pdf.display()))?;
            let (form, _) = with_password(&pdf, password, |pw| read_form(&data, pw))?;
            if json {
                println!("{}", serde_json::to_string_pretty(&form)?);
                return Ok(());
            }
            print!("{}", describe_form(&form));
        }
        FormCmd::Fill {
            pdf,
            set,
            json,
            out,
            yes,
        } => {
            let mut values = match &json {
                Some(path) => read_values(path)?,
                None => Vec::new(),
            };
            merge_set(&mut values, &set)?;
            if values.is_empty() {
                bail!("nothing to fill in: give --set NAME=VALUE or --json FILE");
            }
            let data = std::fs::read(&pdf).with_context(|| format!("reading {}", pdf.display()))?;
            let (form, password) = with_password(&pdf, password, |pw| read_form(&data, pw))?;
            let force = confirm_locks(&form, &values, yes)?;
            let filled = fill_form(&data, password.as_deref(), &values, force)?;
            for w in &filled.warnings {
                eprintln!("Warning: {w}");
            }
            let dir = pdf.parent().unwrap_or_else(|| Path::new("."));
            let saved = match out {
                Some(out) => {
                    if same_file(&out, &pdf) {
                        bail!("the original is never changed; choose another --out");
                    }
                    std::fs::write(&out, &filled.data)
                        .with_context(|| format!("writing {}", out.display()))?;
                    out
                }
                None => write_copy_in(&pdf, dir, "filled", &filled.data).with_context(|| {
                    format!("writing {}", copy_path_in(&pdf, dir, "filled").display())
                })?,
            };
            println!("Filled: {}", saved.display());
        }
    }
    Ok(())
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// `{"Name": "Rahul", "Agree": true, "Languages": ["Hindi", "Tamil"], "Age": 30}`.
pub fn read_values(path: &Path) -> Result<Vec<FillValue>> {
    let text = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let json: serde_json::Value = serde_json::from_slice(&text)
        .with_context(|| format!("{} is not valid JSON", path.display()))?;
    let Some(map) = json.as_object() else {
        bail!(
            "{}: expected an object of field names and values",
            path.display()
        );
    };
    let one = |v: &serde_json::Value| -> Result<String> {
        Ok(match v {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Bool(true) => "true".into(),
            serde_json::Value::Bool(false) => "Off".into(),
            serde_json::Value::Number(n) => n.to_string(),
            _ => bail!(
                "{}: values are text, numbers, true/false or lists",
                path.display()
            ),
        })
    };
    map.iter()
        .map(|(name, v)| {
            let value = match v {
                serde_json::Value::Null => Vec::new(),
                serde_json::Value::Array(a) => a.iter().map(one).collect::<Result<_>>()?,
                v => vec![one(v)?],
            };
            Ok(FillValue {
                name: name.clone(),
                value,
            })
        })
        .collect()
}

/// Adds `--set NAME=VALUE` arguments: a name given again adds a choice
/// (lists), and replaces what the JSON file said.
fn merge_set(values: &mut Vec<FillValue>, set: &[String]) -> Result<()> {
    let mut seen: Vec<&str> = Vec::new();
    for s in set {
        let Some((name, value)) = s.split_once('=') else {
            bail!("--set expects NAME=VALUE, got {s:?}");
        };
        let name = name.trim();
        match values.iter_mut().find(|v| v.name == name) {
            Some(v) if seen.contains(&name) => v.value.push(value.to_string()),
            Some(v) => v.value = vec![value.to_string()],
            None => values.push(FillValue {
                name: name.to_string(),
                value: vec![value.to_string()],
            }),
        }
        seen.push(name);
    }
    Ok(())
}

/// Whether to fill fields locked by a signature: asks on a terminal, else
/// needs `--yes`. Returns true when such fields are to be filled.
pub fn confirm_locks(form: &Form, values: &[FillValue], yes: bool) -> Result<bool> {
    let locked: Vec<&FormField> = values
        .iter()
        .filter_map(|v| form.fields.iter().find(|f| f.name == v.name))
        .filter(|f| !f.locked_by.is_empty())
        .collect();
    if locked.is_empty() {
        return Ok(false);
    }
    for f in &locked {
        eprintln!(
            "Warning: the field \"{}\" is locked by the signature {}; filling it in will make that signature invalid.",
            f.name,
            f.locked_by
                .iter()
                .map(|s| format!("\"{s}\""))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if yes {
        return Ok(true);
    }
    if !std::io::stdin().is_terminal() {
        bail!("not filled: a field is locked by a signature (--yes to go ahead)");
    }
    eprint!("Fill it in anyway? [y/N] ");
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    if !matches!(answer.trim(), "y" | "Y" | "yes") {
        bail!("not filled");
    }
    Ok(true)
}

fn quoted(list: &[String]) -> String {
    list.iter()
        .map(|s| format!("\"{s}\""))
        .collect::<Vec<_>>()
        .join(", ")
}

/// One block per field: name, kind and flags, value, choices, page.
fn describe_form(form: &Form) -> String {
    let mut out = String::new();
    if let Some(why) = &form.blocked {
        out += &format!("{why}\n");
    }
    if form.fields.is_empty() {
        if form.blocked.is_none() {
            out += "No fillable form fields.\n";
        }
        return out;
    }
    out += &format!("Form fields: {}\n", form.fields.len());
    for f in &form.fields {
        let mut flags = vec![f.kind.label().to_string()];
        if f.required {
            flags.push("required".into());
        }
        if f.read_only {
            flags.push("read-only".into());
        }
        if f.multiline {
            flags.push("multiline".into());
        }
        if f.password {
            flags.push("password".into());
        }
        match (f.comb, f.max_len) {
            (true, Some(n)) => flags.push(format!("{n} boxes")),
            (false, Some(n)) => flags.push(format!("max {n} characters")),
            _ => {}
        }
        if f.editable {
            flags.push("typing allowed".into());
        }
        if f.multi_select {
            flags.push("several choices".into());
        }
        let value = if f.value.is_empty() {
            match f.kind {
                FieldKind::Checkbox | FieldKind::Radio => "Off".to_string(),
                _ => "(empty)".to_string(),
            }
        } else {
            quoted(&f.value)
        };
        out += &format!("  {} [{}] = {value}\n", f.name, flags.join(", "));
        if let Some(label) = &f.label {
            out += &format!("      Label: {label}\n");
        }
        if !f.options.is_empty() {
            let choices: Vec<String> = f
                .options
                .iter()
                .map(|o| {
                    if o.label == o.value {
                        format!("\"{}\"", o.value)
                    } else {
                        format!("\"{}\" ({})", o.value, o.label)
                    }
                })
                .collect();
            out += &format!("      Choices: {}\n", choices.join(", "));
        }
        let mut pages: Vec<usize> = f.widgets.iter().filter_map(|w| w.page).collect();
        pages.dedup();
        if !pages.is_empty() {
            let pages: Vec<String> = pages.iter().map(|p| (p + 1).to_string()).collect();
            out += &format!(
                "      Page{}: {}\n",
                if pages.len() == 1 { "" } else { "s" },
                pages.join(", ")
            );
        }
        if !f.locked_by.is_empty() {
            out += &format!("      Locked by signature: {}\n", quoted(&f.locked_by));
        }
    }
    if form.xfa {
        out += "This PDF also has an XFA version of the form; the fields above are filled in.\n";
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_arguments() {
        let mut v = vec![FillValue {
            name: "Agree".into(),
            value: vec!["Off".into()],
        }];
        merge_set(
            &mut v,
            &[
                "Name=Rahul = DK".into(),
                "Agree=Yes".into(),
                "Langs=Hindi".into(),
                "Langs=Tamil".into(),
            ],
        )
        .unwrap();
        assert_eq!(v[0].value, ["Yes"]);
        assert_eq!(v[1].name, "Name");
        assert_eq!(v[1].value, ["Rahul = DK"]);
        assert_eq!(v[2].value, ["Hindi", "Tamil"]);
        assert!(merge_set(&mut v, &["nothing".into()]).is_err());
    }
}
