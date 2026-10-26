"""Makes the PDFs the text reader is tested with (src/pdf/text.rs).

Usage: python3 make.py   (writes next to this file)
Needs: reportlab, pypdf, DejaVu Sans. The output is committed; run again
only to change the fixtures.
"""
import io
import os
import zlib

from pypdf import PdfReader, PdfWriter
from pypdf.generic import ArrayObject, DictionaryObject, NameObject, NumberObject
from reportlab.lib.pagesizes import A4
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas

HERE = os.path.dirname(os.path.abspath(__file__))
P = lambda n: os.path.join(HERE, n)


def standard():
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4, invariant=1)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(72, 770, "Board Resolution")
    c.setFont("Helvetica", 11)
    for i in range(10):
        c.drawString(72, 740 - i * 16, f"Resolved that the board approves item {i + 1} of the agenda.")
    c.showPage()
    c.setFont("Times-Roman", 11)
    c.drawString(380, 220, "For TrackMyTech Private Limited")
    c.setFont("Helvetica", 11)
    c.drawString(380, 150, "Authorised Signatory")
    c.setFont("Courier", 10)
    c.drawString(72, 160, "Place: Chennai")
    c.drawString(72, 145, "Date: 26 Oct 2026")
    t = c.beginText(72, 400)
    t.setFont("Helvetica", 11)
    t.setWordSpace(6)
    t.textLine("Spaced out words")
    c.drawText(t)
    f1 = c._doc.getInternalFontName("Helvetica")
    c._code.append(f"BT {f1} 11 Tf 72 330 Td [(Ker) 60 (ned Sig) -15 (natory)] TJ ET")
    # Filled in below: a MacRoman font with /Differences.
    c._code.append("BT /FM 11 Tf 72 300 Td (Caf\\216 Si\\001nature) Tj ET")
    c.showPage()
    c.save()
    r = PdfReader(io.BytesIO(buf.getvalue()))
    w = PdfWriter(clone_from=r)
    page = w.pages[1]
    fonts = page["/Resources"]["/Font"]
    enc = DictionaryObject({
        NameObject("/Type"): NameObject("/Encoding"),
        NameObject("/BaseEncoding"): NameObject("/MacRomanEncoding"),
        NameObject("/Differences"): ArrayObject([NumberObject(1), NameObject("/g")]),
    })
    fonts[NameObject("/FM")] = w._add_object(DictionaryObject({
        NameObject("/Type"): NameObject("/Font"),
        NameObject("/Subtype"): NameObject("/Type1"),
        NameObject("/BaseFont"): NameObject("/Helvetica"),
        NameObject("/Encoding"): enc,
    }))
    with open(P("standard.pdf"), "wb") as f:
        w.write(f)


def truetype():
    pdfmetrics.registerFont(TTFont("DejaVu", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"))
    c = canvas.Canvas(P("truetype.pdf"), pagesize=A4, invariant=1)
    c.setFont("DejaVu", 12)
    c.drawString(100, 400, "Managing Director")
    c.drawString(100, 380, "Signed by DK RAHUL")
    c.showPage()
    c.save()


def rotated():
    c = canvas.Canvas(P("rotated.pdf"), pagesize=A4, invariant=1)
    c.setPageRotation(90)
    c.setFont("Helvetica", 12)
    c.drawString(72, 500, "Sideways note")
    c.saveState()
    c.translate(A4[1], 0)
    c.rotate(90)
    c.drawString(380, 150, "Authorised Signatory")
    c.restoreState()
    c.showPage()
    c.save()


def identity_h():
    """A Type 0 font with Identity-H encoding: two-byte codes, read only
    through /ToUnicode (CID = 0x100 + the ASCII code)."""
    def hexs(s):
        return "<" + "".join(f"{0x100 + ord(ch):04X}" for ch in s) + ">"

    content = (
        f"BT /F0 12 Tf 300 400 Td {hexs('Authorised Signatory')} Tj ET\n"
        f"BT /F0 12 Tf 300 360 Td [{hexs('Company')} -300 {hexs('Secretary')}] TJ ET\n"
    ).encode()
    cmap = b"""/CIDInit /ProcSet findresource begin 12 dict begin begincmap
/CMapName /Adobe-Identity-UCS def /CMapType 2 def
1 begincodespacerange <0000> <FFFF> endcodespacerange
1 beginbfrange <0120> <017E> <0020> endbfrange
endcmap CMapName currentdict /CMap defineresource pop end end"""
    objs = {
        1: b"<< /Type /Catalog /Pages 2 0 R >>",
        2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 595.28 841.89] >>",
        3: b"<< /Type /Page /Parent 2 0 R /Resources << /Font << /F0 5 0 R >> >> /Contents 4 0 R >>",
        5: b"<< /Type /Font /Subtype /Type0 /BaseFont /ABCDEF+TestSans /Encoding /Identity-H "
           b"/DescendantFonts [6 0 R] /ToUnicode 7 0 R >>",
        6: b"<< /Type /Font /Subtype /CIDFontType2 /BaseFont /ABCDEF+TestSans "
           b"/CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> "
           b"/FontDescriptor 8 0 R /DW 500 /W [1 [250]] /CIDToGIDMap /Identity >>",
        8: b"<< /Type /FontDescriptor /FontName /ABCDEF+TestSans /Flags 32 /FontBBox [0 -200 1000 900] "
           b"/ItalicAngle 0 /Ascent 900 /Descent -200 /CapHeight 700 /StemV 80 >>",
    }
    streams = {4: zlib.compress(content), 7: zlib.compress(cmap)}
    out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets = {}
    for n in range(1, 9):
        offsets[n] = len(out)
        if n in streams:
            data = streams[n]
            out += b"%d 0 obj\n<< /Length %d /Filter /FlateDecode >>\nstream\n" % (n, len(data))
            out += data + b"\nendstream\nendobj\n"
        else:
            out += b"%d 0 obj\n" % n + objs[n] + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 9\n0000000000 65535 f \n"
    for n in range(1, 9):
        out += b"%010d 00000 n \n" % offsets[n]
    out += b"trailer\n<< /Size 9 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % xref
    with open(P("identity-h.pdf"), "wb") as f:
        f.write(out)


standard()
truetype()
rotated()
identity_h()
