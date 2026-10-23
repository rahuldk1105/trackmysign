"""Compare `trackmysign verify` with pyHanko's validation of the same file.

Usage: python3 tests/verify_check.py [--password=PW] <trackmysign> <signed.pdf> <valid|invalid> <trust-root.pem>...
Checks, per signature field: same fields found, VALID exactly when pyHanko
says intact + valid, whole-document coverage when pyHanko says ENTIRE_FILE,
"content changed" only when pyHanko reports modifications beyond
annotations (judged as Acrobat does, see acrobat_policy.py), and the same
certification (DocMDP) level. `invalid` expects every signature to be INVALID.
"""
import logging
import re
import subprocess
import sys

from pyhanko.keys import load_cert_from_pemder
from pyhanko.pdf_utils.crypt import AuthStatus
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.diff_analysis import ModificationLevel
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext

from acrobat_policy import ACROBAT_POLICY

args = sys.argv[1:]
password = next((a.split("=", 1)[1] for a in args if a.startswith("--password=")), None)
binary, path, expect, *roots = [a for a in args if not a.startswith("--password=")]
pw_arg = [f"--password={password}"] if password is not None else []
# pyHanko logs its diff analysis of modified files; only the results matter here.
logging.disable(logging.CRITICAL)
problems = []

run = subprocess.run([binary, "verify", *pw_arg, path], capture_output=True, text=True)
ours = {}
for block in re.split(r"\n(?=\S)", run.stdout.strip()):
    head, *rest = block.splitlines()
    m = re.match(r"(.+): (VALID|INVALID|UNKNOWN)$", head)
    if not m:
        continue
    fields = dict(l.strip().split(": ", 1) for l in rest if ": " in l)
    ours[m.group(1)] = (m.group(2), fields)

any_bad = any(s == "INVALID" or "CONTENT CHANGED" in f.get("Coverage", "") for s, f in ours.values())
if run.returncode != (2 if any_bad else 0):
    problems.append(f"exit status {run.returncode}: {run.stderr.strip()}")

vc = ValidationContext(trust_roots=[load_cert_from_pemder(r) for r in roots], allow_fetching=False)
with open(path, "rb") as f:
    r = PdfFileReader(f, strict=False)
    theirs = {}
    readable = not r.encrypted or r.decrypt(password or "").status != AuthStatus.FAILED
    levels = {}
    for s in r.embedded_signatures if readable else []:
        st = validate_pdf_signature(s, vc, diff_policy=ACROBAT_POLICY)
        theirs[s.field_name] = st
        levels[s.field_name] = s.docmdp_level.value if s.docmdp_level else None

if not readable:
    # pyHanko does not read the deprecated AES-256 revision 5: compare with
    # the expectation instead.
    print("  pyHanko cannot open this encryption")
    if not ours:
        problems.append("no signatures found")
    for name, (status, _) in ours.items():
        if (status == "VALID") != (expect == "valid"):
            problems.append(f"{name}: {status}, expected {expect}")
elif sorted(ours) != sorted(theirs):
    problems.append(f"fields differ: ours {sorted(ours)}, pyHanko {sorted(theirs)}")

for name, st in theirs.items():
    if name not in ours:
        continue
    status, fields = ours[name]
    coverage = fields.get("Coverage", "")
    print(f"  {name}: {status}; {coverage} | pyHanko intact={st.intact} valid={st.valid} "
          f"coverage={st.coverage.name} modifications={st.modification_level.name if st.modification_level else None}")
    if expect == "invalid":
        if status != "INVALID" or st.intact:
            problems.append(f"{name}: expected INVALID (pyHanko intact={st.intact})")
        continue
    if (status == "VALID") != (st.intact and st.valid):
        problems.append(f"{name}: {status} but pyHanko intact={st.intact} valid={st.valid}")
    if (coverage == "whole document") != (st.coverage.name == "ENTIRE_FILE"):
        problems.append(f"{name}: coverage '{coverage}' but pyHanko {st.coverage.name}")
    other = st.modification_level is not None and st.modification_level > ModificationLevel.ANNOTATIONS
    if ("CONTENT CHANGED" in coverage) != other:
        problems.append(f"{name}: coverage '{coverage}' but pyHanko modifications {st.modification_level}")
    m = re.match(r"level (\d)", fields.get("Certifies", ""))
    level = int(m.group(1)) if m else None
    if level != levels[name]:
        problems.append(f"{name}: certification level {level} but pyHanko {levels[name]}")

if problems:
    print("FAIL verify", path)
    for p in problems:
        print("   -", p)
    sys.exit(1)
print("PASS verify", path)
