"""Check the signature image in the newest signature box.

Usage: python3 tests/check_image.py <original.pdf> <signed.pdf> <page> <png|jpg> <left|above>
Expects the default box (170 x 55 pt, bottom-right, 36 pt margin) and the
test image from make_fixtures.py: 2:1, left half transparent (PNG) or green
(JPEG), right half red. Checks the XObject (DCTDecode passthrough, /SMask
for PNG) and renders the page with pdftoppm to see both halves where they
belong, upright on rotated pages too; through the transparent half the
original page must show unchanged.
"""
import os
import subprocess
import sys
import tempfile

from PIL import Image
from pyhanko.pdf_utils.reader import PdfFileReader

orig, path, page, kind, position = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5]
problems = []

with open(path, "rb") as f:
    r = PdfFileReader(f, strict=False)
    widget = r.root["/AcroForm"]["/Fields"][-1].get_object()
    if "/Kids" in widget:  # one field, a widget on each page
        widget = widget["/Kids"][0].get_object()
    im = widget["/AP"]["/N"]["/Resources"]["/XObject"]["/Im1"]
    flt = im["/Filter"]
    if kind == "jpg":
        if flt != "/DCTDecode" or "/SMask" in im:
            problems.append(f"JPEG: filter {flt}, smask {'/SMask' in im}")
    else:
        if flt != "/FlateDecode" or "/SMask" not in im:
            problems.append(f"PNG: filter {flt}, smask {'/SMask' in im}")
        elif len(im["/SMask"].data) != 200 * 100:
            problems.append("PNG: soft mask has the wrong size")
        if len(im.data) != 200 * 100 * 3:
            problems.append("PNG: colour samples have the wrong size")


def render(pdf):
    """The page at 72 dpi: one pixel per point, as displayed (rotation applied)."""
    with tempfile.TemporaryDirectory() as d:
        subprocess.run(["pdftoppm", "-r", "72", "-f", str(page), "-l", str(page), "-png", pdf, f"{d}/p"], check=True)
        return Image.open(os.path.join(d, os.listdir(d)[0])).convert("RGB")


img, before = render(path), render(orig)

W, H = img.size
bx, by, bw, bh = W - 170 - 36, H - 55 - 36, 170, 55
pad = min(max(min(bw, bh) * 0.08, 1.5), 6)
aspect = 2.0
if position == "left":
    ih = bh - 2 * pad
    iw = min(ih * aspect, (bw - 2 * pad) * 0.45)
    ih = min(ih, iw / aspect)
    ix, iy = bx + pad, by + (bh - ih) / 2
else:
    iw = bw - 2 * pad
    ih = min(iw / aspect, (bh - 2 * pad) * 0.5)
    iw = min(iw, ih * aspect)
    ix, iy = bx + (bw - iw) / 2, by + pad


def at(im, fx, fy):
    return im.getpixel((int(ix + fx * iw), int(iy + fy * ih)))


red = at(img, 0.75, 0.5)
left = at(img, 0.25, 0.5)
if not (red[0] > 180 and red[1] < 70 and red[2] < 70):
    problems.append(f"right half of the image is {red}, expected red")
if kind == "jpg" and not (left[1] > 120 and left[0] < 70 and left[2] < 70):
    problems.append(f"left half of the image is {left}, expected green")
if kind != "jpg" and left != at(before, 0.25, 0.5):
    problems.append(f"left half of the image is {left}, expected the page through it ({at(before, 0.25, 0.5)})")

if problems:
    print("FAIL", path, "image")
    for p in problems:
        print("   -", p)
    sys.exit(1)
print("PASS", path, "image")
