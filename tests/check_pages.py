"""Check that the newest signature has one widget on each expected page.

Usage: python3 tests/check_pages.py <signed.pdf> <signature-count> <page>...
Pages are numbered from 1. Checks: exactly <signature-count> signatures, the
newest one's widgets sit on exactly the given pages, each is listed in its
page's /Annots, points back at the field, has an appearance and lies within
the page.
"""
import sys

from pyhanko.pdf_utils.reader import PdfFileReader

path, count, *expected = sys.argv[1:]
expected = sorted(int(p) for p in expected)
problems = []


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


with open(path, "rb") as f:
    r = PdfFileReader(f, strict=False)
    sigs = r.embedded_signatures
    if len(sigs) != int(count):
        problems.append(f"expected {count} signature(s), found {len(sigs)}")
    pages = page_refs(r.root.raw_get("/Pages"), [])
    name = sigs[-1].field_name
    field_ref = next(f for f in r.root["/AcroForm"]["/Fields"] if f.get_object().get("/T") == name)
    field = field_ref.get_object()
    widgets = list(field["/Kids"]) if "/Kids" in field else [field_ref]
    found = []
    for w in widgets:
        wd = w.get_object()
        if "/Kids" in field and wd.raw_get("/Parent").reference != field_ref.reference:
            problems.append(f"widget {w.reference} has the wrong /Parent")
        p = wd.raw_get("/P").reference
        if p not in pages:
            problems.append(f"widget {w.reference}: /P is not a page")
            continue
        n = pages.index(p) + 1
        found.append(n)
        page = p.get_object()
        if w.reference not in [a.reference for a in (page["/Annots"] if "/Annots" in page else [])]:
            problems.append(f"page {n}: widget missing from /Annots")
        if "/AP" not in wd:
            problems.append(f"page {n}: widget has no appearance")
        x0, y0, x1, y1 = (float(v) for v in wd["/Rect"])
        bx0, by0, bx1, by1 = (float(v) for v in inherited(page, "/CropBox") or inherited(page, "/MediaBox"))
        if x0 < bx0 - 0.01 or y0 < by0 - 0.01 or x1 > bx1 + 0.01 or y1 > by1 + 0.01:
            problems.append(f"page {n}: widget {[x0, y0, x1, y1]} outside the page")
    if sorted(found) != expected:
        problems.append(f"widgets on pages {sorted(found)}, expected {expected}")

if problems:
    print("FAIL", path)
    for p in problems:
        print("   -", p)
    sys.exit(1)
print("PASS", path, "widgets on pages", ",".join(map(str, expected)))
