"""Check empty signature fields added with `trackmysign fields add`.

Usage: python3 tests/check_newfields.py [--order] [--seed] [--password PW] [--certify N] <original.pdf> <with-fields.pdf> <trust-root.pem> -- NAME[:TOOLTIP]...
Checks: the original bytes are untouched and qpdf finds no problem; each
NAME is a new, unsigned, top-level /FT /Sig field merged with a visible
widget that its page lists in /Annots and that has a normal appearance (a
form XObject that draws its name); TOOLTIP (if given) is its /TU; with
--order, fields carry their place in the given order; with --seed, /SV
asks for adbe.pkcs7.detached with SHA-256 (otherwise there is none). Signatures already in the original stay
intact and valid, and pyHanko classifies the new fields as an allowed
change (at most form filling; with --certify N under the Acrobat-like
policy, as validate.py does).
"""
import io
import logging
import subprocess
import sys

from pyhanko.keys import load_cert_from_pemder
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.diff_analysis import DEFAULT_DIFF_POLICY, ModificationLevel
from pyhanko.sign.fields import enumerate_sig_fields
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext

from acrobat_policy import ACROBAT_POLICY

logging.disable(logging.CRITICAL)
args = sys.argv[1:]
opts = {}
while args[0].startswith("--") and args[0] != "--":
    if args[0] in ("--order", "--seed"):
        opts[args[0][2:]] = True
        args = args[1:]
    else:
        opts[args[0][2:]] = args[1]
        args = args[2:]
split = args.index("--")
orig_path, path, *roots = args[:split]
specs = [s.split(":", 1) for s in args[split + 1:]]
problems = []

orig = open(orig_path, "rb").read()
data = open(path, "rb").read()
if not data.startswith(orig):
    problems.append("original bytes were modified")
pw = opts.get("password")
pw_arg = [f"--password={pw}"] if pw is not None else []
qc = subprocess.run(["qpdf", "--check", *pw_arg, path], capture_output=True, text=True)
if qc.returncode != 0 or "WARNING" in qc.stdout + qc.stderr:
    problems.append("qpdf --check: " + (qc.stdout + qc.stderr).strip()[-500:])


def opened(b):
    r = PdfFileReader(io.BytesIO(b), strict=False)
    if r.encrypted:
        r.decrypt(pw or "")
    return r


old_names = {name for name, _, _ in enumerate_sig_fields(opened(orig))}
r = opened(data)
fields = {name: (value, ref) for name, value, ref in enumerate_sig_fields(r)}
top = [str(f.get_object()["/T"]) for f in r.root["/AcroForm"]["/Fields"]]
annots = {}
for i in range(r.root["/Pages"]["/Count"]):
    page = r.find_page_for_modification(i)[0].get_object()
    for a in page["/Annots"] if "/Annots" in page else []:
        annots[a.idnum] = i

for n, (name, *tooltip) in enumerate(specs, 1):
    if name in old_names:
        problems.append(f"{name}: was already in the original")
        continue
    if name not in fields:
        problems.append(f"{name}: no such signature field")
        continue
    value, ref = fields[name]
    d = ref.get_object()
    if value is not None:
        problems.append(f"{name}: already has a value")
    if name not in top:
        problems.append(f"{name}: not a top-level field")
    if d.get("/Subtype") != "/Widget" or d.get("/FT") != "/Sig":
        problems.append(f"{name}: not a signature field merged with its widget")
    rect = [float(x) for x in d["/Rect"]]
    if rect[2] - rect[0] < 1 or rect[3] - rect[1] < 1 or int(d.get("/F", 0)) & 4 == 0:
        problems.append(f"{name}: not visible and printed ({rect}, /F {d.get('/F')})")
    if ref.idnum not in annots:
        problems.append(f"{name}: no page lists its widget in /Annots")
    ap = d["/AP"]["/N"] if "/AP" in d and "/N" in d["/AP"] else None
    if ap is None or ap["/Subtype"] != "/Form":
        problems.append(f"{name}: no normal appearance")
    elif name.encode("latin-1", "replace") not in ap.data:
        problems.append(f"{name}: the appearance does not show its name")
    tu = str(d["/TU"]) if "/TU" in d else None
    if tooltip and tu != tooltip[0]:
        problems.append(f"{name}: tooltip {tu!r}, expected {tooltip[0]!r}")
    if opts.get("order") and d.get("/TrackMySignOrder") != n:
        problems.append(f"{name}: signing order {d.get('/TrackMySignOrder')}, expected {n}")
    sv = d["/SV"] if "/SV" in d else None
    if not opts.get("seed"):
        if sv is not None:
            problems.append(f"{name}: seed values although none were asked for")
    elif sv is None or list(sv["/SubFilter"]) != ["/adbe.pkcs7.detached"] or list(sv["/DigestMethod"]) != ["/SHA256"]:
        problems.append(f"{name}: seed values {sv}")

vc = ValidationContext(trust_roots=[load_cert_from_pemder(x) for x in roots], allow_fetching=False)
policy = ACROBAT_POLICY if "certify" in opts else DEFAULT_DIFF_POLICY
for s in r.embedded_signatures:
    st = validate_pdf_signature(s, vc, diff_policy=policy)
    mod = st.modification_level
    print(f"  {s.field_name}: intact={st.intact} valid={st.valid} modifications={mod.name if mod else None}")
    if not (st.intact and st.valid):
        problems.append(f"{s.field_name}: not intact/valid after adding fields")
    if mod is None or mod > ModificationLevel.FORM_FILLING:
        problems.append(f"{s.field_name}: adding fields not an allowed change ({mod})")
    if "certify" in opts and s.docmdp_level and not st.docmdp_ok:
        problems.append(f"{s.field_name}: new fields not permitted by the certification")

if problems:
    print(f"FAIL {path}:")
    for p in problems:
        print("   -", p)
    sys.exit(1)
print(f"PASS {path}: {len(specs)} empty signature fields")
