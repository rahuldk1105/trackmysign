"""Check `trackmysign verify-folder` with --report, --csv and --json.

Usage: python3 tests/check_folder.py [--password=PW] [--recursive] [--require-signed]
           <trackmysign> <folder> <out-dir> <exit status> <path>=<status>...
Each <path> (relative, `/`-separated) must be listed with that status, and
no other file. The JSON must have the documented keys, hashes and sizes
that match the files, and totals that agree with the files. The CSV must
have one row per signature (one for a file without any) with the file's
columns. The PDF report must pass qpdf --check, and pdftotext must find the
title, the summary line, each file with its status in the table and in
the appendix, and the footer on every page.
"""
import csv
import hashlib
import io
import json
import os
import re
import subprocess
import sys

flags = [a for a in sys.argv[1:] if a.startswith("--")]
binary, folder, out_dir, want_exit, *expected = [a for a in sys.argv[1:] if not a.startswith("--")]
expected = dict(e.split("=", 1) for e in expected)
tag = "-".join(f.lstrip("-").split("=")[0] for f in flags) or "plain"
report = os.path.join(out_dir, f"folder-{tag}.pdf")
csv_path = os.path.join(out_dir, f"folder-{tag}.csv")
problems = []

run = subprocess.run([binary, "verify-folder", *flags, folder, "--report", report, "--csv", csv_path, "--json"],
                     capture_output=True, text=True)
try:
    doc = json.loads(run.stdout)
except json.JSONDecodeError:
    print("FAIL verify-folder", folder, flags, run.stdout, run.stderr)
    sys.exit(1)
if run.returncode != int(want_exit):
    problems.append(f"exit status {run.returncode}, expected {want_exit}: {run.stderr.strip()}")

keys = {
    "": ["checked", "checked_at", "complete", "files", "folder", "generator", "not_checked", "recursive",
         "schema", "schema_version", "summary", "totals"],
    "totals": ["all_valid", "content_changed", "files", "needs_password", "problems", "signatures",
               "some_invalid", "unreadable", "unsigned"],
}
for part, want in keys.items():
    got = sorted(doc[part] if part else doc)
    if got != want:
        problems.append(f"JSON {part or 'top level'} keys {got}")
if doc["schema"] != "trackmysign.folder-verification-report" or doc["schema_version"] != 1 or not doc["complete"]:
    problems.append(f"schema {doc['schema']} {doc['schema_version']} complete={doc['complete']}")
if doc["recursive"] != ("--recursive" in flags):
    problems.append(f"recursive {doc['recursive']}")

files = doc["files"]
got = {f["path"]: f["status"] for f in files}
if got != expected:
    problems.append(f"statuses {got}")
if [f["path"] for f in files] != sorted((f["path"] for f in files), key=str.lower):
    problems.append("files not in path order")
for f in files:
    data = open(os.path.join(folder, f["path"]), "rb").read()
    if f["sha256"] != hashlib.sha256(data).hexdigest() or f["size"] != len(data):
        problems.append(f"{f['path']}: hash or size does not match the file")
    if sorted(f) != ["encrypted", "error", "pages", "path", "sha256", "signatures", "size", "status", "summary"]:
        problems.append(f"{f['path']}: keys {sorted(f)}")
    if (f["error"] is None) != (f["status"] not in ("unreadable", "needs_password")):
        problems.append(f"{f['path']}: error {f['error']!r} with status {f['status']}")
totals = doc["totals"]
count = lambda s: sum(f["status"] == s for f in files)
want_totals = {
    "files": len(files),
    "all_valid": count("all_valid"),
    "some_invalid": count("some_invalid"),
    "content_changed": count("content_changed"),
    "problems": count("some_invalid") + count("content_changed"),
    "unsigned": count("unsigned"),
    "unreadable": count("unreadable"),
    "needs_password": count("needs_password"),
    "signatures": sum(len(f["signatures"]) for f in files),
}
if totals != want_totals:
    problems.append(f"totals {totals}, expected {want_totals}")
line = (f"{len(files)} file{'s' if len(files) != 1 else ''}: {totals['all_valid']} all valid, "
        f"{totals['problems']} with problems, {totals['unsigned']} unsigned, {totals['unreadable']} unreadable")
if doc["summary"] != line and not doc["summary"].startswith(line + ", "):
    problems.append(f"summary {doc['summary']!r}")

raw = open(csv_path, "rb").read()
if not raw.startswith(b"\xef\xbb\xbf") or b"\r\n" not in raw:
    problems.append("CSV lacks the BOM or CRLF line ends")
rows = list(csv.DictReader(io.StringIO(raw.decode("utf-8-sig"), newline="")))
if len(rows) != sum(max(1, len(f["signatures"])) for f in files):
    problems.append(f"CSV has {len(rows)} rows")
for f in files:
    mine = [r for r in rows if r["file"] == f["path"]]
    if any(r["sha256"] != f["sha256"] or r["file_status"] != f["status"] for r in mine):
        problems.append(f"CSV file columns of {f['path']}")
    sigs = [(r["signature"], r["field"], r["status"]) for r in mine if r["signature"]]
    if sigs != [(str(s["index"]), s["field"], s["status"]) for s in f["signatures"]]:
        problems.append(f"CSV signatures of {f['path']}: {sigs}")

check = subprocess.run(["qpdf", "--check", report], capture_output=True, text=True)
if check.returncode != 0:
    problems.append(f"qpdf --check: {check.stdout.strip()} {check.stderr.strip()}")
pages = subprocess.run(["pdfinfo", report], capture_output=True, text=True).stdout
pages = int(re.search(r"^Pages:\s+(\d+)", pages, re.M).group(1))
text = subprocess.run(["pdftotext", "-layout", "-enc", "UTF-8", report, "-"], capture_output=True, text=True).stdout
flat = " ".join(text.split())
labels = {"all_valid": "All valid", "some_invalid": "Invalid signature", "content_changed": "Changed after signing",
          "unsigned": "Unsigned", "unreadable": "Unreadable", "needs_password": "Needs a password"}
want = ["Folder verification report", doc["summary"], "IST (", "Subfolders Included" if doc["recursive"] else
        "Subfolders Not included", "Appendix: each file"]
for i, f in enumerate(files, 1):
    want.append(f"{f['path']} {labels[f['status']]}")
    want.append(f"{i}. {f['path']} Status {labels[f['status']]}")
    for s in f["signatures"]:
        want.append(f"Signature {s['index']} of {len(f['signatures'])}: {s['status'].capitalize()}")
for w in want:
    if " ".join(w.split()) not in flat:
        problems.append(f"report lacks {w!r}")
footers = len(re.findall(r"Generated by TrackMySign v\S+\. Checks", flat))
if footers != pages or f"Page {pages} of {pages}" not in flat:
    problems.append(f"{footers} footers on {pages} pages")

if problems:
    print("FAIL verify-folder", folder, " ".join(flags))
    for p in problems:
        print("   -", p)
    sys.exit(1)
print(f"PASS verify-folder {' '.join(flags) or '(no options)'}: {doc['summary']} (exit {run.returncode}, {pages} pages)")
