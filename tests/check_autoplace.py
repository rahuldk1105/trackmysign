"""Check where `sign --position auto` put the box.

Usage: python3 tests/check_autoplace.py <signed.pdf> <anchors.json> <name>
anchors.json (from make_fixtures.py) says, per fixture, on which page the
phrase was drawn and where, as displayed (points from the top-left), or the
box expected when there is nothing to find ("fallback"). Read with pypdf:
the newest signature's widget, its page and /Rect, turned into display space
with the page's crop box and /Rotate. Near means: not over the phrase, at
most 40 pt from it, and above it or beside it.
"""
import json
import sys

from pypdf import PdfReader

path, spec_path, name = sys.argv[1:]
spec = json.load(open(spec_path))[name]
r = PdfReader(path)
problems = []

widgets = []
for n, page in enumerate(r.pages, 1):
    for a in page.get("/Annots") or []:
        a = a.get_object()
        field = a if "/FT" in a else a.get("/Parent", {}).get_object() if "/Parent" in a else a
        if a.get("/Subtype") == "/Widget" and field.get("/FT") == "/Sig" and "/V" in field:
            widgets.append((n, page, [float(v) for v in a["/Rect"]]))
if len(widgets) != 1:
    problems.append(f"expected one signed widget, found {len(widgets)}")
else:
    n, page, (x0, y0, x1, y1) = widgets[0]
    cx0, cy0, cx1, cy1 = (float(v) for v in page.cropbox)
    rot = int(page.get("/Rotate", 0)) % 360

    def disp(ux, uy):
        return {
            90: (uy - cy0, ux - cx0),
            180: (cx1 - ux, uy - cy0),
            270: (cy1 - uy, cx1 - ux),
        }.get(rot, (ux - cx0, cy1 - uy))

    (ax, ay), (bx, by) = disp(x0, y0), disp(x1, y1)
    box = [min(ax, bx), min(ay, by), abs(ax - bx), abs(ay - by)]
    dw, dh = (cx1 - cx0, cy1 - cy0) if rot % 180 == 0 else (cy1 - cy0, cx1 - cx0)
    if n != spec["page"]:
        problems.append(f"box on page {n}, expected page {spec['page']}")
    if box[0] < -0.01 or box[1] < -0.01 or box[0] + box[2] > dw + 0.01 or box[1] + box[3] > dh + 0.01:
        problems.append(f"box {box} outside the {dw:.0f} x {dh:.0f} page")
    if "fallback" in spec:
        if any(abs(a - b) > 0.5 for a, b in zip(box, spec["fallback"])):
            problems.append(f"box {box}, expected the fallback {spec['fallback']}")
    else:
        x, y, w, h = spec["rect"]
        gap_x = max(x - (box[0] + box[2]), box[0] - (x + w), 0)
        gap_y = max(y - (box[1] + box[3]), box[1] - (y + h), 0)
        if gap_x == 0 and gap_y == 0:
            problems.append(f"box {box} covers the phrase at {spec['rect']}")
        elif max(gap_x, gap_y) > 40:
            problems.append(f"box {box} is {max(gap_x, gap_y):.0f} pt from the phrase at {spec['rect']}")
        elif box[1] > y + h:
            problems.append(f"box {box} is below the phrase at {spec['rect']}")

if problems:
    print("FAIL", path)
    for p in problems:
        print("   -", p)
    sys.exit(1)
print("PASS", path, "box placed", "at the fallback" if "fallback" in spec else "next to the phrase", "on page", spec["page"])
