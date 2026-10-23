"""Check a signature made into an existing empty signature field.

Usage: python3 tests/check_field.py [--rotate N] [--subfilter S] [--lock FIELD]
                                    [--certify N] [--password PW] <original.pdf> <signed.pdf> <field> <trust-root.pem>...
Checks: the newest signature is in <field> (fully qualified name), valid and
trusted; no field was added; the field's widget kept its /Rect and other
entries and got an appearance whose box, turned by /Matrix, fills the /Rect
(--rotate: the expected rotation, counterclockwise); --subfilter: the
signature's /SubFilter; --lock: the signature carries the field's lock as a
FieldMDP reference including FIELD, and filling FIELD afterwards breaks it;
--certify: the signature also certifies with DocMDP level N (otherwise it
must not certify); --password: open an encrypted PDF with it.
"""
import io
import logging
import sys

from pyhanko.keys import load_cert_from_pemder
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.diff_analysis import ModificationLevel
from pyhanko.sign.fields import FieldMDPAction
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext

logging.disable(logging.CRITICAL)
args = sys.argv[1:]
opts = {}
while args[0].startswith("--"):
    opts[args[0][2:]] = args[1]
    args = args[2:]
orig_path, signed_path, name, *roots = args
vc = ValidationContext(trust_roots=[load_cert_from_pemder(r) for r in roots], allow_fetching=False)
problems = []


def all_fields(r):
    """(fully qualified name, field dict, widgets) for every terminal field."""
    out = []

    def walk(ref, parent):
        d = ref.get_object()
        n = d["/T"] if "/T" in d else None
        full = f"{parent}.{n}" if parent and n is not None else (str(n) if n is not None else parent)
        kids = list(d["/Kids"]) if "/Kids" in d else []
        sub = [k for k in kids if "/T" in k.get_object()]
        widgets = [k for k in kids if "/T" not in k.get_object()]
        if "/Rect" in d:
            widgets.insert(0, ref)
        for k in sub:
            walk(k, full)
        if not sub or widgets:
            out.append((full, d, widgets))

    for f in r.root["/AcroForm"]["/Fields"]:
        walk(f, "")
    return out


def opened(data):
    r = PdfFileReader(io.BytesIO(data), strict=False)
    if r.encrypted:
        r.decrypt(opts.get("password", ""))
    return r


def by_name(r):
    return {n: (d, w) for n, d, w in all_fields(r)}


before = by_name(opened(open(orig_path, "rb").read()))
signed = open(signed_path, "rb").read()
r = opened(signed)
after = by_name(r)
if sorted(after) != sorted(before):
    problems.append(f"fields changed: {sorted(before)} -> {sorted(after)}")

sigs = r.embedded_signatures
newest = sigs[-1] if sigs else None
if newest is None or newest.field_name != name:
    problems.append(f"newest signature is in {newest.field_name if newest else None}, expected {name}")
else:
    st = validate_pdf_signature(newest, vc)
    print(f"  {name}: intact={st.intact} valid={st.valid} trusted={st.trusted} subfilter={newest.sig_object['/SubFilter']}")
    if not (st.intact and st.valid and st.trusted):
        problems.append(f"{name}: not intact/valid/trusted")
    level = newest.docmdp_level
    want = int(opts["certify"]) if "certify" in opts else None
    if (level.value if level else None) != want:
        problems.append(f"certification is {level}, expected {want}")
    if "subfilter" in opts and newest.sig_object["/SubFilter"] != "/" + opts["subfilter"]:
        problems.append(f"/SubFilter is {newest.sig_object['/SubFilter']}, expected {opts['subfilter']}")

    old_field, old_widgets = before[name]
    field, widgets = after[name]
    for k in old_field:
        if k not in ("/V", "/AP") and field.raw_get(k) != old_field.raw_get(k):
            problems.append(f"field entry {k} changed")
    for ow, w in zip(old_widgets, widgets):
        od, wd = ow.get_object(), w.get_object()
        for k in od:
            if k not in ("/V", "/AP") and wd.raw_get(k) != od.raw_get(k):
                problems.append(f"widget entry {k} changed")
        if "/AP" not in wd:
            problems.append("widget has no appearance")
            continue
        ap = wd["/AP"]["/N"]
        bw, bh = float(ap["/BBox"][2]), float(ap["/BBox"][3])
        a, b, c, d, e, f = (float(v) for v in ap["/Matrix"])
        x0, y0, x1, y1 = (float(v) for v in wd["/Rect"])
        # Corners of the box through the matrix, as an axis-aligned extent.
        pts = [(a * x + c * y + e, b * x + d * y + f) for x, y in ((0, 0), (bw, 0), (0, bh), (bw, bh))]
        ext = (max(p[0] for p in pts) - min(p[0] for p in pts), max(p[1] for p in pts) - min(p[1] for p in pts))
        if abs(ext[0] - (x1 - x0)) > 0.01 or abs(ext[1] - (y1 - y0)) > 0.01:
            problems.append(f"appearance {ext} does not fill the rect {x1 - x0, y1 - y0}")
        rot = {(1, 0): 0, (0, 1): 90, (-1, 0): 180, (0, -1): 270}.get((round(a), round(b)))
        if "rotate" in opts and rot != int(opts["rotate"]):
            problems.append(f"appearance rotated {rot}, expected {opts['rotate']}")
        print(f"  widget rect {[x0, y0, x1, y1]} box {bw:g}x{bh:g} rotated {rot}")

    if "lock" in opts:
        mdp = newest.fieldmdp
        if mdp is None:
            problems.append("no FieldMDP reference in the signature")
        elif mdp.action != FieldMDPAction.INCLUDE or opts["lock"] not in (mdp.fields or []):
            problems.append(f"FieldMDP {mdp} does not lock {opts['lock']}")
        else:
            print(f"  lock carried: {mdp.action.name} {mdp.fields}")
            # Fill the locked field afterwards: the signature must object.
            w = IncrementalPdfFileWriter(io.BytesIO(signed))
            if w.prev.encrypted:
                w.encrypt(opts["password"])
            fd = next(f.get_object() for f in w.root["/AcroForm"]["/Fields"] if f.get_object().get("/T") == opts["lock"])
            fd["/V"] = generic.TextStringObject("Changed after signing")
            w.update_container(fd)
            out = io.BytesIO()
            w.write(out)
            r2 = PdfFileReader(out, strict=False)
            st2 = validate_pdf_signature(next(s for s in r2.embedded_signatures if s.field_name == name), vc)
            print(f"  after filling {opts['lock']}: modifications={st2.modification_level.name} docmdp_ok={st2.docmdp_ok}")
            if st2.docmdp_ok and st2.modification_level <= ModificationLevel.FORM_FILLING:
                problems.append(f"filling the locked field {opts['lock']} was accepted")

if problems:
    print("FAIL", signed_path)
    for p in problems:
        print("   -", p)
    sys.exit(1)
print("PASS", signed_path, "field", name)
