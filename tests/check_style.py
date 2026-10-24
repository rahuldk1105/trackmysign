"""Check a styled signature box: what its appearance uses, and how it renders.

Usage: python3 tests/check_style.py [--password=PW] <original.pdf> <signed.pdf> <page> <check>...
Page is numbered from 1. The box is found by rendering the page with
pdftoppm (72 dpi, one pixel per point) before and after signing: the
changed pixels. Checks:
  font=NAME     the appearance uses this /BaseFont
  xobj=NAME     the appearance has this image (Im1 signature, Im2 seal)
  no-xobj=NAME  ... and not this one
  ca=VALUE      /GS1 sets this fill opacity
  no-text       the appearance draws no text
  wide          the box is wider than tall on screen (upright on a rotated page)
  ink           dark text shows in the box
  blue-text     dark blue (#1B3A8C) text shows
  centered      the text is centred: as much room left as right
  seal-tint     the seal shows faded (light blue)
  seal-solid    the seal shows opaque (blue)
  red           the signature image (red half of sig.png) shows
  tick          the green tick shows
"""
import os
import subprocess
import sys
import tempfile

from PIL import Image
from pyhanko.pdf_utils.reader import PdfFileReader

args = sys.argv[1:]
password = next((a.split("=", 1)[1] for a in args if a.startswith("--password=")), None)
orig, path, page, *checks = [a for a in args if not a.startswith("--password=")]
page = int(page)
problems = []

with open(path, "rb") as f:
    r = PdfFileReader(f, strict=False)
    if r.encrypted:
        r.decrypt(password or "")
    field = r.embedded_signatures[-1].sig_field
    widget = field if "/Rect" in field else field["/Kids"][0].get_object()
    ap = widget["/AP"]["/N"]
    res = ap["/Resources"]
    fonts = {str(res["/Font"][k]["/BaseFont"]) for k in res["/Font"]}
    xobjs = {str(k)[1:] for k in res["/XObject"]} if "/XObject" in res else set()
    ca = float(res["/ExtGState"]["/GS1"]["/ca"]) if "/ExtGState" in res else None
    content = ap.data
    for c in checks:
        key, _, val = c.partition("=")
        if key == "font" and "/" + val not in fonts:
            problems.append(f"fonts are {sorted(fonts)}, expected {val}")
        elif key == "xobj" and val not in xobjs:
            problems.append(f"images are {sorted(xobjs)}, expected {val}")
        elif key == "no-xobj" and val in xobjs:
            problems.append(f"has image {val}")
        elif key == "ca" and (ca is None or abs(ca - float(val)) > 1e-6):
            problems.append(f"opacity is {ca}, expected {val}")
        elif key == "no-text" and b"BT" in content:
            problems.append("the appearance draws text")


def render(pdf):
    with tempfile.TemporaryDirectory() as d:
        pw = ["-upw", password] if password else []
        subprocess.run(["pdftoppm", *pw, "-r", "72", "-f", str(page), "-l", str(page), "-png", pdf, f"{d}/p"], check=True)
        return Image.open(os.path.join(d, os.listdir(d)[0])).convert("RGB")


after, before = render(path), render(orig)
W, H = after.size
a, b = after.load(), before.load()
changed = [(x, y) for y in range(H) for x in range(W) if sum(abs(p - q) for p, q in zip(a[x, y], b[x, y])) > 30]
if not changed:
    problems.append("nothing drawn on the page")
    changed = [(0, 0)]
x0, x1 = min(p[0] for p in changed), max(p[0] for p in changed)
y0, y1 = min(p[1] for p in changed), max(p[1] for p in changed)
inside = [a[x, y] for x in range(x0 + 3, x1 - 2) for y in range(y0 + 3, y1 - 2)]


def count(test):
    return sum(1 for px in inside if test(*px))


def green(r, g, b):
    return g - r > 50 and g - b > 40


ink_cols = [x for x in range(x0 + 3, x1 - 2) if any(max(a[x, y]) < 160 and not green(*a[x, y]) for y in range(y0 + 3, y1 - 2))]
for c in checks:
    if c == "wide" and not (x1 - x0) > (y1 - y0):
        problems.append(f"box is {x1 - x0} x {y1 - y0} px on screen, expected wider than tall")
    elif c == "ink" and count(lambda r, g, b: max(r, g, b) < 110) < 40:
        problems.append("no dark text in the box")
    elif c == "blue-text" and count(lambda r, g, b: b > 90 and b - r > 50 and r < 100 and g < 120) < 40:
        problems.append("no dark blue text in the box")
    elif c == "centered":
        if not ink_cols:
            problems.append("no text to centre")
        elif abs((ink_cols[0] - x0) - (x1 - ink_cols[-1])) > 4:
            problems.append(f"text from {ink_cols[0] - x0} px to {x1 - ink_cols[-1]} px from the edges, expected centred")
    elif c == "seal-tint" and count(lambda r, g, b: b > 230 and 130 < r < 225 and abs(r - g) < 20) < 200:
        problems.append("no faded seal in the box")
    elif c == "seal-solid" and count(lambda r, g, b: b > 200 and r < 60 and g < 60) < 100:
        problems.append("no opaque seal in the box")
    elif c == "tick" and count(green) < 5:
        problems.append("no tick in the box")
    elif c == "red" and count(lambda r, g, b: r > 180 and g < 70 and b < 70) < 100:
        problems.append("no signature image in the box")

if problems:
    print("FAIL", path, "style", " ".join(checks))
    for p in problems:
        print("   -", p)
    sys.exit(1)
print("PASS", path, "style", " ".join(checks))
