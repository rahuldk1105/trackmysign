"""Independently validate signed PDFs with pyHanko and qpdf.

Usage: python3 tests/validate.py <original.pdf> <signed.pdf> <trust-root.pem>...
Checks: original bytes untouched, qpdf structure check, every signature
intact + valid + trusted, earlier signatures still valid with only allowed
modifications after them.
"""
import subprocess
import sys

from pyhanko.keys import load_cert_from_pemder
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.diff_analysis import ModificationLevel
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext

orig_path, signed_path, *roots = sys.argv[1:]
orig = open(orig_path, "rb").read()
signed = open(signed_path, "rb").read()
problems = []

if not signed.startswith(orig):
    problems.append("original bytes were modified")

qc = subprocess.run(["qpdf", "--check", signed_path], capture_output=True, text=True)
if qc.returncode not in (0, 3):  # 3 = warnings only
    problems.append("qpdf --check failed: " + qc.stdout[-500:] + qc.stderr[-500:])
elif "WARNING" in qc.stdout + qc.stderr:
    problems.append("qpdf warnings: " + (qc.stdout + qc.stderr).strip()[-500:])

vc = ValidationContext(trust_roots=[load_cert_from_pemder(r) for r in roots], allow_fetching=False)
with open(signed_path, "rb") as f:
    r = PdfFileReader(f, strict=False)
    sigs = r.embedded_signatures
    if not sigs:
        problems.append("no signatures found")
    for s in sigs:
        st = validate_pdf_signature(s, vc)
        name = s.field_name
        ok = st.intact and st.valid and st.trusted
        mod = st.modification_level
        print(f"  {name}: intact={st.intact} valid={st.valid} trusted={st.trusted} "
              f"coverage={st.coverage.name} modifications={mod.name if mod else None} by={st.signing_cert.subject.human_friendly}")
        if not ok:
            problems.append(f"{name}: not intact/valid/trusted")
        if mod is not None and mod > ModificationLevel.FORM_FILLING:
            problems.append(f"{name}: disallowed changes after signing ({mod.name})")

if problems:
    print("FAIL", signed_path)
    for p in problems:
        print("   -", p)
    sys.exit(1)
print("PASS", signed_path)
