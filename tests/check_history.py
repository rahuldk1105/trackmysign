"""Check the signing history that `trackmysign sign` and `watch` write.

Usage: python3 tests/check_history.py <trackmysign> <history-dir> <out-dir>
           <input>|<output>|<action>|<source>...
Each signing must be in `history --json` with the hashes of both files, the
certificate and the action and source given; the chain must be intact. The
filters (--since, --source, --outcome, --search), --csv and --report are
checked, then an edited line, a deleted line and a deleted newest line must
each make `history` exit with status 2 (the files are put back after).
"""
import csv
import datetime
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys

binary, folder, out_dir, *signings = sys.argv[1:]
problems = []


def sha(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def history(*args):
    run = subprocess.run([binary, "history", *args], capture_output=True, text=True)
    return run.returncode, run.stdout, run.stderr


def entries(*args):
    code, out, err = history("--json", *args)
    try:
        return code, json.loads(out)
    except json.JSONDecodeError:
        problems.append(f"history --json {' '.join(args)}: not JSON: {out[:200]} {err}")
        return code, {"entries": [], "integrity": {"problems": []}}


code, doc = entries()
if code != 0 or doc["integrity"]["problems"]:
    problems.append(f"history exit {code}: {doc['integrity']['problems']}")
if doc.get("schema") != "trackmysign-history" or doc.get("schema_version") != 1:
    problems.append(f"schema {doc.get('schema')} {doc.get('schema_version')}")
all_entries = doc["entries"]
seqs = [e["seq"] for e in all_entries]
if not seqs or seqs != list(range(seqs[0], seqs[0] + len(seqs))):
    problems.append(f"entries not numbered one by one: {seqs[:10]}")

for s in signings:
    src, out, action, source = s.split("|")
    found = [e for e in all_entries if e.get("output", {}).get("path") == os.path.abspath(out)]
    if len(found) != 1:
        problems.append(f"{out}: {len(found)} entries")
        continue
    e = found[0]
    want = {
        "outcome": "signed",
        "action": action,
        "source": source,
        "input": {"path": os.path.abspath(src), "sha256": sha(src)},
        "output": {"path": os.path.abspath(out), "sha256": sha(out)},
    }
    for k, v in want.items():
        if e.get(k) != v:
            problems.append(f"{out}: {k} is {e.get(k)!r}, expected {v!r}")
    c = e.get("cert") or {}
    if not c.get("subject") or not c.get("issuer") or not c.get("serial") or not re.fullmatch(r"[0-9a-f]{64}", c.get("fingerprint", "")):
        problems.append(f"{out}: certificate {c}")
    if not e["program"].startswith("cli "):
        problems.append(f"{out}: program {e['program']}")
    datetime.datetime.fromisoformat(e["time"].replace("Z", "+00:00"))

# Nothing secret on disk: no PIN, no password field.
for name in os.listdir(folder):
    if name.endswith(".jsonl"):
        text = open(os.path.join(folder, name), encoding="utf-8").read()
        for word in ('"pin"', '"password"', '"' + os.environ.get("TRACKMYSIGN_PIN", "12345678") + '"'):
            if word in text:
                problems.append(f"{name} holds {word}")

watch = entries("--source", "watch")[1]["entries"]
if len([e for e in watch if e.get("outcome") == "signed"]) < 2 or any(e.get("source") != "watch" for e in watch):
    problems.append(f"--source watch: {[(e.get('source'), e.get('outcome')) for e in watch]}")
failed = entries("--outcome", "failed")[1]["entries"]
if not failed or any(e.get("outcome") != "failed" or not e.get("error") for e in failed):
    problems.append(f"--outcome failed: {failed[:3]}")
if not any("certified" in e.get("error", "") for e in failed):
    problems.append("the watch folder's certified file is not listed as failed")
tomorrow = (datetime.date.today() + datetime.timedelta(days=2)).isoformat()
if entries("--since", tomorrow)[1]["entries"]:
    problems.append("--since in the future lists entries")
name = os.path.basename(signings[0].split("|")[1])
found = entries("--search", name.upper())[1]["entries"]
if not found or any(name not in json.dumps(e) for e in found):
    problems.append(f"--search {name}: {len(found)} entries")

code, out, err = history("--csv")
rows = list(csv.reader(io.StringIO(out, newline="")))
if code != 0 or not rows or rows[0][:4] != ["﻿seq", "time_utc", "action", "source"]:
    problems.append(f"--csv header: {rows[:1]}")
if len(rows) != len(all_entries) + 1:
    problems.append(f"--csv has {len(rows) - 1} rows for {len(all_entries)} entries")
elif any(r[0] != str(e["seq"]) or r[11] != e.get("output", {}).get("sha256", "") for r, e in zip(rows[1:], all_entries)):
    problems.append("--csv rows do not match the entries")

report = os.path.join(out_dir, "history.pdf")
code, out, err = history("--report", report)
if code != 0 or "Intact:" not in out:
    problems.append(f"history text: {code} {out[-200:]} {err}")
elif subprocess.run(["qpdf", "--check", report], capture_output=True).returncode != 0:
    problems.append("history.pdf fails qpdf --check")
else:
    text = subprocess.run(["pdftotext", "-layout", report, "-"], capture_output=True, text=True).stdout
    for want in ("Signing history", "Log integrity", "Intact", name, sha(signings[0].split("|")[1])):
        if want not in text:
            problems.append(f"history.pdf lacks {want!r}")

# Tampering: each change is found, and putting the file back clears it.
months = sorted(n for n in os.listdir(folder) if n.endswith(".jsonl"))
newest = os.path.join(folder, months[-1])
backup = newest + ".bak"
shutil.copy(newest, backup)
original = open(newest, encoding="utf-8").read().splitlines(keepends=True)
middle = len(original) // 2


def tampered(what, lines):
    with open(newest, "w", encoding="utf-8") as f:
        f.writelines(lines)
    code, doc = entries()
    found = doc["integrity"]["problems"]
    if code != 2 or not found:
        problems.append(f"{what}: exit {code}, problems {found}")
    shutil.copy(backup, newest)


edited = list(original)
edited[middle] = edited[middle].replace(".pdf", ".PDF", 1)
if edited[middle] == original[middle]:
    edited[middle] = edited[middle].replace('"seq"', '"seq" ', 1)
tampered("edited line", edited)
tampered("deleted line", original[:middle] + original[middle + 1:])
tampered("deleted newest line", original[:-1])
os.remove(backup)
code, doc = entries()
if code != 0 or doc["integrity"]["problems"]:
    problems.append(f"after putting the file back: exit {code} {doc['integrity']['problems']}")

if problems:
    print("FAIL signing history:")
    for p in problems:
        print("  " + p)
    sys.exit(1)
print(f"PASS signing history: {len(signings)} signings with matching hashes, filters, CSV, PDF, tampering found")
