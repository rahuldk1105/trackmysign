"""Check a filled-in form (filled only, or filled and then signed).

Usage: python3 tests/check_form.py [--password PW] [--first-sig LEVEL] [--broken NAME]
                                   <original.pdf> <filled.pdf> <values.json> <trust-root.pem>...
Checks: the original bytes are untouched; pypdf reads every value from
values.json (check boxes and radio buttons as their state); the fields are
still there and fillable (not flattened) and /NeedAppearances is not set;
rendered with pdftoppm, every filled widget looks different from before
(its appearance shows the value) while the page around it does not.
--first-sig: pyHanko rates the changes after the first signature as LEVEL
(e.g. FORM_FILLING) and its DocMDP still holds; --broken: pyHanko finds the
signature NAME broken by the changes (a field it locks was filled in).
"""
import io
import json
import logging
import os
import subprocess
import sys
import tempfile

from PIL import Image, ImageChops
from pypdf import PdfReader
from pyhanko.keys import load_cert_from_pemder
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext

logging.disable(logging.CRITICAL)
args = sys.argv[1:]
opts = {}
while args[0].startswith("--"):
    opts[args[0][2:]] = args[1]
    args = args[2:]
orig_path, path, values_path, *roots = args
password = opts.get("password")
values = json.load(open(values_path))
problems = []

orig = open(orig_path, "rb").read()
data = open(path, "rb").read()
if not data.startswith(orig):
    problems.append("original bytes were modified")


def reader(b):
    r = PdfReader(io.BytesIO(b))
    if r.is_encrypted:
        r.decrypt(password or "")
    return r


before, after = reader(orig), reader(data)
fields = after.get_fields() or {}


def form_fields(r):
    """Field names, without signature fields (signing adds one)."""
    return sorted(n for n, f in (r.get_fields() or {}).items() if f.get("/FT") != "/Sig")


if form_fields(after) != form_fields(before):
    problems.append(f"fields changed: {form_fields(before)} -> {form_fields(after)}")
if after.trailer["/Root"]["/AcroForm"].get("/NeedAppearances") is True:
    problems.append("/NeedAppearances is still set")


def expected(f, want):
    """The /V pypdf should read for `want` (a values.json entry)."""
    if f.get("/FT") == "/Btn":
        if want is True:
            return None  # any on state
        return "/Off" if want in (False, None, "Off") else "/" + str(want)
    if isinstance(want, list):
        return want if len(want) > 1 else want[0]
    return str(want)


for name, want in values.items():
    f = fields.get(name)
    if f is None:
        problems.append(f"{name}: no such field")
        continue
    got = f.get("/V")
    exp = expected(f, want)
    if isinstance(got, list):
        got = [str(g) for g in got]
    ok = got not in (None, "/Off") if exp is None else (str(got) == exp if not isinstance(exp, list) else got == exp)
    print(f"  {name}: {got!r}")
    if not ok:
        problems.append(f"{name}: value {got!r}, expected {exp!r}")


def widgets(r, page):
    """Widget rects (x0, y0, x1, y1) on `page` by fully qualified field name."""
    out = {}
    for a in r.pages[page].get("/Annots") or []:
        a = a.get_object()
        if a.get("/Subtype") != "/Widget":
            continue
        d, parts = a, []
        while d is not None:
            if "/T" in d:
                parts.insert(0, str(d["/T"]))
            d = d.get("/Parent").get_object() if "/Parent" in d else None
        name = ".".join(parts)
        if "/AS" in a and a["/AS"] == "/Off":
            continue  # a radio button or check box that is not the chosen one
        x0, y0, x1, y1 = [float(v) for v in a["/Rect"]]
        out.setdefault(name, []).append((min(x0, x1), min(y0, y1), max(x0, x1), max(y0, y1)))
    return out


def render(pdf):
    with tempfile.TemporaryDirectory() as d:
        pw = ["-upw", password] if password else []
        subprocess.run(["pdftoppm", *pw, "-r", "72", "-f", "1", "-l", "1", "-png", pdf, f"{d}/p"], check=True)
        return Image.open(os.path.join(d, os.listdir(d)[0])).convert("RGB")


with tempfile.NamedTemporaryFile(suffix=".pdf") as o:
    o.write(orig)
    o.flush()
    old_img = render(o.name)
new_img = render(path)
height = float(after.pages[0].mediabox.height)
diff = ImageChops.difference(old_img, new_img).convert("L").point(lambda v: 255 if v > 40 else 0)
mask = Image.new("L", diff.size, 0)
placed = widgets(after, 0)
for name, want in values.items():
    for x0, y0, x1, y1 in placed.get(name, []):
        box = (int(x0) - 1, int(height - y1) - 1, int(x1) + 2, int(height - y0) + 2)
        mask.paste(255, box)
        if want not in ("", None, False, "Off", []) and not diff.crop(box).getbbox():
            problems.append(f"{name}: the rendered page shows no change in the field")
outside = ImageChops.subtract(diff, mask)
# The new signature box may also be on the page.
sig_boxes = [a.get_object() for a in after.pages[0].get("/Annots") or [] if a.get_object().get("/FT") == "/Sig"]
for a in sig_boxes:
    x0, y0, x1, y1 = [float(v) for v in a["/Rect"]]
    outside.paste(0, (int(min(x0, x1)) - 1, int(height - max(y0, y1)) - 1, int(max(x0, x1)) + 2, int(height - min(y0, y1)) + 2))
if outside.getbbox():
    problems.append(f"the page changed outside the filled fields: {outside.getbbox()}")

if "first-sig" in opts or "broken" in opts:
    vc = ValidationContext(trust_roots=[load_cert_from_pemder(r) for r in roots], allow_fetching=False)
    r = PdfFileReader(io.BytesIO(data), strict=False)
    if r.encrypted:
        r.decrypt(password or "")
    sigs = r.embedded_signatures
    if "first-sig" in opts:
        st = validate_pdf_signature(sigs[0], vc)
        mod = st.modification_level.name if st.modification_level else None
        print(f"  {sigs[0].field_name}: intact={st.intact} valid={st.valid} modifications={mod} docmdp_ok={st.docmdp_ok}")
        if not (st.intact and st.valid) or mod != opts["first-sig"] or st.docmdp_ok is False:
            problems.append(f"{sigs[0].field_name}: modifications {mod}, docmdp_ok {st.docmdp_ok}; expected {opts['first-sig']}")
    if "broken" in opts:
        s = next(s for s in sigs if s.field_name == opts["broken"])
        st = validate_pdf_signature(s, vc)
        mod = st.modification_level.name if st.modification_level else None
        print(f"  {s.field_name}: intact={st.intact} modifications={mod} docmdp_ok={st.docmdp_ok}")
        if mod in (None, "NONE", "LTA_UPDATES", "FORM_FILLING") and st.docmdp_ok is not False:
            problems.append(f"{s.field_name}: still rated {mod}, though a field it locks was filled in")

if problems:
    print("FAIL", path)
    for p in problems:
        print("   -", p)
    sys.exit(1)
print("PASS", path)
