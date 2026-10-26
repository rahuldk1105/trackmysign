"""Check "certified true copy" stamps: widgets of the newest signature on the
expected pages, and what they show when rendered.

Usage: python3 tests/check_ctc.py [--password=PW] [--text=HEADING] [--seal] <original.pdf> <signed.pdf> <signature-count> <page>...
Pages are numbered from 1. Checks: exactly <signature-count> signatures; the
stamps (widgets flagged Print, ReadOnly and Locked) of the newest one sit on
exactly the given pages, each listed in its page's /Annots, pointing back at
the field, with an appearance stream that writes the heading (default
"CERTIFIED TRUE COPY"), and inside the page. Each stamped page is rendered
with pdftoppm (72 dpi) before and after signing: the stamp area shows dark,
upright text (wider than tall), with --seal a blue seal too, and nothing
changed on the page outside the new signature's widgets.
"""
import os
import subprocess
import sys
import tempfile

from PIL import Image
from pyhanko.pdf_utils.reader import PdfFileReader

args = sys.argv[1:]
opt = lambda name: next((a.split("=", 1)[1] for a in args if a.startswith(f"--{name}=")), None)
password = opt("password")
heading = opt("text") or "CERTIFIED TRUE COPY"
want_seal = "--seal" in args
orig, path, count, *expected = [a for a in args if not a.startswith("--")]
expected = sorted(int(p) for p in expected)
problems = []

PRINT_READONLY_LOCKED = 4 | 64 | 128


def page_refs(node, out):
    obj = node.get_object()
    if "/Kids" in obj:
        for k in obj["/Kids"]:
            page_refs(k, out)
    else:
        out.append(node.reference)
    return out


def inherited(page, key):
    while page is not None:
        if key in page:
            return page[key]
        page = page["/Parent"] if "/Parent" in page else None
    return None


def to_display(page, rect):
    """A widget /Rect as the page is shown: pixels at 72 dpi from the top-left."""
    cx0, cy0, cx1, cy1 = (float(v) for v in inherited(page, "/CropBox") or inherited(page, "/MediaBox"))
    rot = int(inherited(page, "/Rotate") or 0) % 360
    x0, y0, x1, y1 = (float(v) for v in rect)

    def m(ux, uy):
        return {
            0: (ux - cx0, cy1 - uy),
            90: (uy - cy0, ux - cx0),
            180: (cx1 - ux, uy - cy0),
            270: (cy1 - uy, cx1 - ux),
        }[rot]

    (ax, ay), (bx, by) = m(x0, y0), m(x1, y1)
    return min(ax, bx), min(ay, by), max(ax, bx), max(ay, by)


stamps = {}
boxes = {}
with open(path, "rb") as f:
    r = PdfFileReader(f, strict=False)
    if r.encrypted:
        r.decrypt(password or "")
    sigs = r.embedded_signatures
    if len(sigs) != int(count):
        problems.append(f"expected {count} signature(s), found {len(sigs)}")
    pages = page_refs(r.root.raw_get("/Pages"), [])
    field = sigs[-1].sig_field
    kids = list(field["/Kids"]) if "/Kids" in field else []
    for w in kids:
        wd = w.get_object()
        p = wd.raw_get("/P").reference
        if p not in pages:
            problems.append(f"widget {w.reference}: /P is not a page")
            continue
        n = pages.index(p) + 1
        page = p.get_object()
        rect = to_display(page, wd["/Rect"])
        boxes.setdefault(n, []).append(rect)
        if int(wd.get("/F", 0)) != PRINT_READONLY_LOCKED:
            continue
        if n in stamps:
            problems.append(f"page {n}: two stamps")
        stamps[n] = rect
        if wd.raw_get("/Parent").reference != field.container_ref:
            problems.append(f"page {n}: stamp has the wrong /Parent")
        if w.reference not in [a.reference for a in (page["/Annots"] if "/Annots" in page else [])]:
            problems.append(f"page {n}: stamp missing from /Annots")
        ap = wd["/AP"]["/N"] if "/AP" in wd else None
        if ap is None:
            problems.append(f"page {n}: stamp has no appearance")
        elif f"({heading}) Tj".encode() not in ap.data:
            problems.append(f"page {n}: appearance does not write {heading!r}")
        elif want_seal and "/Im2" not in ap["/Resources"].get("/XObject", {}):
            problems.append(f"page {n}: appearance has no seal")
        x0, y0, x1, y1 = rect
        bx1, by1 = to_display(page, inherited(page, "/CropBox") or inherited(page, "/MediaBox"))[2:]
        if x0 < -0.01 or y0 < -0.01 or x1 > bx1 + 0.01 or y1 > by1 + 0.01:
            problems.append(f"page {n}: stamp {rect} outside the page")
if sorted(stamps) != expected:
    problems.append(f"stamps on pages {sorted(stamps)}, expected {expected}")


def render(pdf, n):
    with tempfile.TemporaryDirectory() as d:
        pw = ["-upw", password] if password else []
        subprocess.run(["pdftoppm", *pw, "-r", "72", "-f", str(n), "-l", str(n), "-png", pdf, f"{d}/p"], check=True)
        return Image.open(os.path.join(d, os.listdir(d)[0])).convert("RGB")


for n, (x0, y0, x1, y1) in sorted(stamps.items()):
    after, before = render(path, n), render(orig, n)
    a, b = after.load(), before.load()
    W, H = after.size
    inner = [(x, y) for x in range(int(x0) + 3, min(int(x1) - 2, W)) for y in range(int(y0) + 3, min(int(y1) - 2, H))]
    ink = [(x, y) for x, y in inner if max(a[x, y]) < 110 and sum(abs(p - q) for p, q in zip(a[x, y], b[x, y])) > 30]
    if len(ink) < 40:
        problems.append(f"page {n}: no dark text in the stamp")
    else:
        iw = max(x for x, _ in ink) - min(x for x, _ in ink)
        ih = max(y for _, y in ink) - min(y for _, y in ink)
        if not iw > ih:
            problems.append(f"page {n}: text in the stamp is {iw} x {ih} px, expected wider than tall (upright)")
    if want_seal and sum(1 for x, y in inner if a[x, y][2] > 200 and a[x, y][0] < 60 and a[x, y][1] < 60) < 50:
        problems.append(f"page {n}: no seal in the stamp")
    # Nothing else moved: every changed pixel is in one of the new widgets.
    near = lambda x, y: any(bx0 - 2 <= x <= bx1 + 2 and by0 - 2 <= y <= by1 + 2 for bx0, by0, bx1, by1 in boxes[n])
    stray = sum(1 for y in range(H) for x in range(W)
                if sum(abs(p - q) for p, q in zip(a[x, y], b[x, y])) > 30 and not near(x, y))
    if stray:
        problems.append(f"page {n}: {stray} pixel(s) changed outside the signature's widgets")

if problems:
    print("FAIL", path, "ctc")
    for p in problems:
        print("   -", p)
    sys.exit(1)
print("PASS", path, "stamps on pages", ",".join(map(str, expected)))
