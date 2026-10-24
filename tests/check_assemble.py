"""Check a PDF written by `trackmysign pages` against the pages it came from.

Usage: python3 tests/check_assemble.py [--password=PW] [--fields=A,B] <out.pdf> <page>...
Each <page> says where the output page at that position came from:
  src.pdf#N       page N (from 1) of src.pdf
  src.pdf#N@R     ... turned clockwise by R more degrees
  src.pdf#all     every page of src.pdf, in order
  ...~            (suffix) a signature shown on the page was left out:
                  compare loosely
  blank=WxH       an empty page of W x H points
Checks: qpdf --check passes, not encrypted, no signatures; page count;
/Rotate, MediaBox and CropBox per page; each page renders (pdftoppm) like
its source page turned by R, and blank pages render white. --password opens
the sources; --fields lists the form field names expected, in order.
"""
import logging
import os
import subprocess
import sys
import tempfile

from PIL import Image, ImageChops, ImageFilter, ImageStat
from pypdf import PdfReader

args = sys.argv[1:]
opts = dict(a[2:].split("=", 1) for a in args if a.startswith("--"))
out, *specs = [a for a in args if not a.startswith("--")]
password = opts.get("password")
problems = []
logging.getLogger("pypdf").setLevel(logging.ERROR)  # broken.pdf is broken on purpose

readers = {}


def reader(path):
    if path not in readers:
        r = PdfReader(path)
        if r.is_encrypted:
            r.decrypt(password or "")
        readers[path] = r
    return readers[path]


expected = []
for s in specs:
    if s.startswith("blank="):
        w, h = (float(v) for v in s[6:].split("x"))
        expected.append(("blank", w, h))
        continue
    path, _, which = s.rpartition("#")
    loose = which.endswith("~")
    which, _, rot = which.rstrip("~").partition("@")
    pages = range(len(reader(path).pages)) if which == "all" else [int(which) - 1]
    expected.extend(("page", path, p, int(rot or 0), loose) for p in pages)

check = subprocess.run(["qpdf", "--check", out], capture_output=True, text=True)
if check.returncode != 0:
    problems.append("qpdf --check: " + (check.stdout + check.stderr).strip().splitlines()[-1])

r = PdfReader(out)
if r.is_encrypted:
    problems.append("output is encrypted")
if len(r.pages) != len(expected):
    problems.append(f"{len(r.pages)} pages, expected {len(expected)}")

root = r.trailer["/Root"]
fields = []
if "/AcroForm" in root:
    for f in root["/AcroForm"].get("/Fields", []):
        f = f.get_object()
        fields.append(str(f.get("/T", "")))
        if f.get("/FT") == "/Sig" and "/V" in f:
            problems.append(f"signed field {f.get('/T')} carried over")
if "fields" in opts and fields != [n for n in opts["fields"].split(",") if n]:
    problems.append(f"fields are {fields}, expected {opts['fields']}")


def box(page, name):
    return [round(float(v), 2) for v in getattr(page, name)]


def render(path, n, pw=None):
    with tempfile.TemporaryDirectory() as d:
        cmd = ["pdftoppm", "-r", "24", "-f", str(n + 1), "-l", str(n + 1), "-png"]
        if pw:
            cmd += ["-upw", pw]
        subprocess.run([*cmd, path, os.path.join(d, "p")], check=True, capture_output=True)
        (f,) = os.listdir(d)
        return Image.open(os.path.join(d, f)).convert("L")


for i, (page, exp) in enumerate(zip(r.pages, expected)):
    got = render(out, i)
    if exp[0] == "blank":
        _, w, h = exp
        if box(page, "mediabox") != [0, 0, round(w, 2), round(h, 2)]:
            problems.append(f"page {i + 1}: blank page is {box(page, 'mediabox')}, expected {w} x {h}")
        if ImageStat.Stat(got).extrema[0][0] < 250:
            problems.append(f"page {i + 1}: blank page is not empty")
        continue
    _, path, n, rot, loose = exp
    src = reader(path).pages[n]
    want_rotate = (src.rotation + rot) % 360
    if page.rotation != want_rotate:
        problems.append(f"page {i + 1}: /Rotate {page.rotation}, expected {want_rotate}")
    for name in ("mediabox", "cropbox"):
        if box(page, name) != box(src, name):
            problems.append(f"page {i + 1}: {name} {box(page, name)}, expected {box(src, name)}")
    want = render(path, n, password if reader(path).is_encrypted else None)
    want = want.rotate(-rot, expand=True)
    if got.size != want.size:
        problems.append(f"page {i + 1}: renders {got.size}, expected {want.size}")
        continue
    # Blurred: a page turned by the renderer and one turned here differ in
    # anti-aliasing only.
    blur = ImageFilter.GaussianBlur(2)
    diff = ImageStat.Stat(ImageChops.difference(got.filter(blur), want.filter(blur))).mean[0]
    if diff > (3.0 if loose else 1.0):
        problems.append(f"page {i + 1}: renders differently from {os.path.basename(path)} page {n + 1} ({diff:.1f})")
    if ImageStat.Stat(want).extrema[0][0] < 128 and ImageStat.Stat(got).extrema[0][0] > 128:
        problems.append(f"page {i + 1}: content is missing")

name = os.path.basename(out)
if problems:
    print(f"FAIL {name}:")
    for p in problems:
        print("  -", p)
    sys.exit(1)
print(f"PASS {name}: {len(expected)} pages match their sources")
