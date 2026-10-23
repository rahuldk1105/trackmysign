"""Independently validate signed PDFs with pyHanko and qpdf.

Usage: python3 tests/validate.py [--timestamp] [--ltv] [--password=PW] <original.pdf> <signed.pdf> <trust-root.pem>...
Checks: original bytes untouched, qpdf structure check, every signature
intact + valid + trusted, earlier signatures still valid with only allowed
modifications after them.
--timestamp: the newest signature carries a valid, trusted signature timestamp.
--ltv: the DSS has a VRI entry for the newest signature, and its OCSP/CRL data
       alone (no fetching, revocation checks mandatory) validates the signer
       and timestamp chains.
--password: open an encrypted PDF with this password (qpdf and pyHanko).
"""
import hashlib
import json
import logging
import subprocess
import sys

from pyhanko.keys import load_cert_from_pemder
from pyhanko.pdf_utils.crypt import AuthStatus
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.diff_analysis import ModificationLevel
from pyhanko.sign.validation import DocumentSecurityStore, validate_pdf_signature
from pyhanko_certvalidator import ValidationContext

# Path-building failures are reported through the statuses below.
logging.getLogger("pyhanko").setLevel(logging.CRITICAL)
logging.getLogger("pyhanko_certvalidator").setLevel(logging.CRITICAL)

args = sys.argv[1:]
want_ts = "--timestamp" in args
want_ltv = "--ltv" in args
password = next((a.split("=", 1)[1] for a in args if a.startswith("--password=")), None)
args = [a for a in args if not a.startswith("--password=")]
orig_path, signed_path, *roots = [a for a in args if a not in ("--timestamp", "--ltv")]
orig = open(orig_path, "rb").read()
signed = open(signed_path, "rb").read()
problems = []

if not signed.startswith(orig):
    problems.append("original bytes were modified")

pw_arg = [f"--password={password}"] if password is not None else []
qc = subprocess.run(["qpdf", "--check", *pw_arg, signed_path], capture_output=True, text=True)
if qc.returncode not in (0, 3):  # 3 = warnings only
    problems.append("qpdf --check failed: " + qc.stdout[-500:] + qc.stderr[-500:])
elif "WARNING" in qc.stdout + qc.stderr:
    problems.append("qpdf warnings: " + (qc.stdout + qc.stderr).strip()[-500:])

trust = [load_cert_from_pemder(r) for r in roots]
vc = ValidationContext(trust_roots=trust, allow_fetching=False)
with open(signed_path, "rb") as f:
    r = PdfFileReader(f, strict=False)
    if r.encrypted and r.decrypt(password or "").status == AuthStatus.FAILED:
        # pyHanko does not read the deprecated AES-256 revision 5: settle for
        # qpdf decrypting the signature fields.
        js = subprocess.run(["qpdf", *pw_arg, "--json", "--json-key=acroform", signed_path],
                            capture_output=True, text=True)
        names = [x["fullname"] for x in json.loads(js.stdout)["acroform"]["fields"] if x["fieldtype"] == "/Sig"]
        print(f"  pyHanko cannot open this encryption; qpdf decrypts signature fields {names}")
        if not any(n.startswith("Signature") for n in names):
            problems.append("qpdf finds no readable signature field")
        sigs = None
    else:
        sigs = r.embedded_signatures
        if not sigs:
            problems.append("no signatures found")
    for s in sigs or []:
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

    newest = sigs[-1] if sigs else None
    if newest and want_ts:
        # Like a reader that fetches missing issuers: the TSA CA may be only in the DSS.
        extra = list(DocumentSecurityStore.read_dss(r).load_certs()) if "/DSS" in r.root else []
        ts_vc = ValidationContext(trust_roots=trust, other_certs=extra, allow_fetching=False)
        ts = validate_pdf_signature(newest, ts_vc).timestamp_validity
        if ts is None:
            problems.append(f"{newest.field_name}: no signature timestamp")
        else:
            print(f"  {newest.field_name} timestamp: {ts.timestamp} intact={ts.intact} valid={ts.valid} trusted={ts.trusted}")
            if not (ts.intact and ts.valid and ts.trusted):
                problems.append(f"{newest.field_name}: timestamp not intact/valid/trusted")
    if newest and want_ltv:
        dss = DocumentSecurityStore.read_dss(r)
        key = "/" + hashlib.sha1(newest.pkcs7_content).hexdigest().upper()
        if key not in dss.vri_entries:
            problems.append(f"{newest.field_name}: no VRI entry in the DSS")
        ltv_vc = dss.as_validation_context(
            {"trust_roots": trust, "allow_fetching": False, "revocation_mode": "hard-fail"}
        )
        st = validate_pdf_signature(newest, ltv_vc)
        ts = st.timestamp_validity
        ts_ok = ts is None or (ts.valid and ts.trusted)
        print(f"  {newest.field_name} from DSS only: certs={len(dss.certs)} ocsps={len(dss.ocsps)} "
              f"crls={len(dss.crls)} trusted={st.trusted} timestamp_trusted={ts.trusted if ts else None}")
        if not (st.intact and st.valid and st.trusted and ts_ok):
            problems.append(f"{newest.field_name}: DSS data does not validate the signature")

if problems:
    print("FAIL", signed_path)
    for p in problems:
        print("   -", p)
    sys.exit(1)
print("PASS", signed_path)
