"""Generate test PDFs covering the structures TrackMySign must handle.

Usage: python3 tests/make_fixtures.py <outdir>
Needs: reportlab (with Pillow), pyhanko, qpdf, openssl.
"""
import os
import subprocess
import sys

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

out = sys.argv[1]
os.makedirs(out, exist_ok=True)
P = lambda n: os.path.join(out, n)


def text_page(c, title, lines=20):
    c.setFont("Helvetica-Bold", 18)
    c.drawString(72, 770, title)
    c.setFont("Helvetica", 11)
    for i in range(lines):
        c.drawString(72, 740 - i * 18, f"Line {i + 1}: Board resolution / financial statement sample text.")


# 1. plain, classic xref
c = canvas.Canvas(P("plain.pdf"), pagesize=A4)
for n in range(2):
    text_page(c, f"Plain document - page {n + 1}")
    c.showPage()
c.save()

# 2. rotated pages
c = canvas.Canvas(P("rotated.pdf"), pagesize=A4)
for r in (0, 90, 180, 270):
    c.setPageRotation(r)
    text_page(c, f"Page with /Rotate {r}")
    c.showPage()
c.save()

# 2b. mixed page sizes, one of them also rotated
c = canvas.Canvas(P("mixed.pdf"))
for size, r in ((A4, 0), ((842, 595), 0), ((612, 1008), 0), ((420, 595), 90), ((200, 150), 0)):
    c.setPageSize(size)
    c.setPageRotation(r)
    text_page(c, f"{size[0]:.0f} x {size[1]:.0f} pt, /Rotate {r}", 3)
    c.showPage()
c.save()

# 3. object streams + xref stream
subprocess.run(["qpdf", "--object-streams=generate", P("plain.pdf"), P("objstm.pdf")], check=True)

# 4. AcroForm with text fields
c = canvas.Canvas(P("form.pdf"), pagesize=A4)
text_page(c, "Form with fields", 5)
c.acroForm.textfield(name="company", tooltip="Company", x=72, y=500, width=300, height=20, value="TrackMyTech Pvt Ltd")
c.acroForm.textfield(name="din", tooltip="DIN", x=72, y=460, width=150, height=20, value="01234567")
c.showPage()
c.save()

# 5. CropBox not at origin
c = canvas.Canvas(P("cropbox.pdf"), pagesize=A4)
text_page(c, "Cropped page")
c.setCropBox((40, 60, 555, 800))
c.showPage()
c.save()

# 6. hand-written: indirect /Annots and indirect /Fields arrays, an existing link annot
objs = {
    1: b"<< /Type /Catalog /Pages 2 0 R /AcroForm 6 0 R >>",
    2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 595.2756 841.8898] >>",
    3: b"<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 7 0 R >> >> /Contents 4 0 R /Annots 5 0 R >>",
    5: b"[8 0 R]",
    6: b"<< /Fields 9 0 R /DA (/Helv 0 Tf 0 g) >>",
    7: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    8: b"<< /Type /Annot /Subtype /Link /Rect [72 700 200 720] /Border [0 0 1] /A << /S /URI /URI (https://example.com) >> >>",
    9: b"[]",
}
content = b"BT /F1 14 Tf 72 760 Td (Indirect Annots and Fields) Tj ET"
buf = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
offsets = {}
for i in range(1, 10):
    offsets[i] = len(buf)
    if i == 4:
        buf += b"4 0 obj\n<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream\nendobj\n"
    else:
        buf += b"%d 0 obj\n" % i + objs[i] + b"\nendobj\n"
xref = len(buf)
buf += b"xref\n0 10\n0000000000 65535 f\r\n"
for i in range(1, 10):
    buf += b"%010d 00000 n\r\n" % offsets[i]
buf += b"trailer\n<< /Size 10 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % xref
open(P("indirect.pdf"), "wb").write(bytes(buf))

# 7. broken startxref (forces the repair path)
data = open(P("plain.pdf"), "rb").read()
i = data.rfind(b"startxref")
broken = data[:i] + b"startxref\n999999\n%%EOF\n"
open(P("broken.pdf"), "wb").write(broken)

# 8. already signed by someone else (pyHanko, separate CA)
pki = os.path.join(out, "auditor-pki")
os.makedirs(pki, exist_ok=True)
q = dict(check=True, capture_output=True)
subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{pki}/ca.key", "-out", f"{pki}/ca.pem",
                "-days", "3650", "-subj", "/CN=Test Auditor CA", "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign"], **q)
subprocess.run(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{pki}/aud.key", "-out", f"{pki}/aud.csr",
                "-subj", "/CN=CA AUDITOR PARTNER"], **q)
with open(f"{pki}/ext.cnf", "w") as f:
    f.write("keyUsage=critical,digitalSignature,nonRepudiation\n")
subprocess.run(["openssl", "x509", "-req", "-in", f"{pki}/aud.csr", "-CA", f"{pki}/ca.pem", "-CAkey", f"{pki}/ca.key",
                "-CAcreateserial", "-out", f"{pki}/aud.pem", "-days", "730", "-extfile", f"{pki}/ext.cnf"], **q)

from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import fields, signers

aud = signers.SimpleSigner.load(f"{pki}/aud.key", f"{pki}/aud.pem", ca_chain_files=(f"{pki}/ca.pem",))
for src, dst in (("plain.pdf", "presigned.pdf"), ("objstm.pdf", "presigned-objstm.pdf"), ("form.pdf", "presigned-form.pdf")):
    with open(P(src), "rb") as inf, open(P(dst), "wb") as outf:
        w = IncrementalPdfFileWriter(inf)
        signers.sign_pdf(
            w,
            signers.PdfSignatureMetadata(field_name="AuditorSignature", reason="Audited"),
            signer=aud,
            new_field_spec=fields.SigFieldSpec("AuditorSignature", on_page=-1, box=(60, 60, 240, 110)),
            output=outf,
        )
# 9. handwritten signature images: transparent left half / red right half
# (PNG, RGBA and palette + tRNS), green left / red right (JPEG)
from PIL import Image

sig = Image.new("RGBA", (200, 100), (0, 0, 0, 0))
sig.paste((220, 0, 0, 255), (100, 0, 200, 100))
sig.save(P("sig.png"))
pal = Image.new("P", (200, 100), 0)
pal.putpalette([0, 0, 0, 220, 0, 0])
pal.paste(1, (100, 0, 200, 100))
pal.save(P("sig-palette.png"), transparency=0)
jpg = Image.new("RGB", (200, 100), (0, 160, 0))
jpg.paste((220, 0, 0), (100, 0, 200, 100))
jpg.save(P("sig.jpg"), quality=95)
# company seal: a blue disc on a transparent square
from PIL import ImageDraw

seal = Image.new("RGBA", (120, 120), (0, 0, 0, 0))
ImageDraw.Draw(seal).ellipse((4, 4, 116, 116), fill=(0, 0, 255, 255))
seal.save(P("seal.png"))

# 10. password-protected (qpdf): name, source, user password, owner password, options
for name, src, user, owner, opts in (
    ("enc-rc40", "plain.pdf", "", "own", ["40"]),
    ("enc-rc128", "plain.pdf", "user", "own", ["128", "--use-aes=n"]),
    ("enc-aes128", "objstm.pdf", "", "own", ["128", "--use-aes=y"]),
    ("enc-aes128-meta", "plain.pdf", "user", "own", ["128", "--use-aes=y", "--cleartext-metadata"]),
    ("enc-aes256", "objstm.pdf", "user", "own", ["256"]),
    ("enc-aes256-r5", "plain.pdf", "", "own", ["256", "--force-R5"]),
    ("enc-restricted", "form.pdf", "", "own", ["256", "--form=n", "--annotate=n"]),
):
    # --allow-weak-crypto: RC4 is what older PDFs use, so it must still be read.
    subprocess.run(["qpdf", "--allow-weak-crypto", "--encrypt", user, owner, *opts, "--", P(src), P(name + ".pdf")], check=True)

# 11. encrypted and already signed (pyHanko encrypts its update with the file key)
for src, pw in (("enc-aes256.pdf", "user"), ("enc-rc128.pdf", "user")):
    with open(P(src), "rb") as inf, open(P("presigned-" + src), "wb") as outf:
        w = IncrementalPdfFileWriter(inf)
        w.encrypt(pw)
        signers.sign_pdf(
            w,
            signers.PdfSignatureMetadata(field_name="AuditorSignature", reason="Audited"),
            signer=aud,
            new_field_spec=fields.SigFieldSpec("AuditorSignature", on_page=-1, box=(60, 60, 240, 110)),
            output=outf,
        )
# 12. empty signature fields to sign into: simple, two fields of which one
# is signed, with a /Lock on a text field, with seed values (/SV) (pyHanko);
# nested under a parent field and on rotated pages (hand-written)
from pyhanko.sign.fields import FieldMDPAction, FieldMDPSpec, SigSeedSubFilter, SigSeedValFlags, SigSeedValueSpec


def with_fields(src, dst, *specs):
    with open(P(src), "rb") as inf, open(P(dst), "wb") as outf:
        w = IncrementalPdfFileWriter(inf)
        for spec in specs:
            fields.append_signature_field(w, spec)
        w.write(outf)


with_fields("plain.pdf", "field-simple.pdf", fields.SigFieldSpec("ClientSignature", on_page=0, box=(360, 80, 540, 140)))
with_fields("plain.pdf", "field-two.pdf",
            fields.SigFieldSpec("Director", on_page=0, box=(340, 80, 540, 140)),
            fields.SigFieldSpec("Auditor", on_page=1, box=(60, 80, 260, 140)))
with open(P("field-two.pdf"), "rb") as inf, open(P("field-mixed.pdf"), "wb") as outf:
    signers.sign_pdf(IncrementalPdfFileWriter(inf), signers.PdfSignatureMetadata(field_name="Auditor", reason="Audited"),
                     signer=aud, existing_fields_only=True, output=outf)
with_fields("form.pdf", "field-lock.pdf",
            fields.SigFieldSpec("Approver", box=(340, 80, 540, 140),
                                field_mdp_spec=FieldMDPSpec(FieldMDPAction.INCLUDE, ["company"])))
with_fields("plain.pdf", "field-sv.pdf",
            fields.SigFieldSpec("CadesOnly", box=(340, 80, 540, 140), seed_value_dict=SigSeedValueSpec(
                flags=SigSeedValFlags.SUBFILTER, subfilters=[SigSeedSubFilter.PADES])),
            fields.SigFieldSpec("Sha512Only", box=(60, 80, 260, 140), seed_value_dict=SigSeedValueSpec(
                flags=SigSeedValFlags.DIGEST_METHOD, digest_methods=["sha512"])))


def raw_pdf(path, objs):
    """Classic-xref PDF; objs maps id -> bytes, or (extra dict entries, stream data)."""
    buf = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets = {}
    for i in sorted(objs):
        offsets[i] = len(buf)
        o = objs[i]
        if isinstance(o, tuple):
            d, data = o
            buf += b"%d 0 obj\n<< %s/Length %d >>\nstream\n" % (i, d, len(data)) + data + b"\nendstream\nendobj\n"
        else:
            buf += b"%d 0 obj\n" % i + o + b"\nendobj\n"
    size = max(objs) + 1
    xref = len(buf)
    buf += b"xref\n0 %d\n0000000000 65535 f\r\n" % size
    for i in range(1, size):
        buf += b"%010d 00000 n\r\n" % offsets[i] if i in offsets else b"0000000000 00001 f\r\n"
    buf += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (size, xref)
    open(path, "wb").write(bytes(buf))


font = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"
# "approvals" (/FT /Sig) > "director" > a separate widget; the AcroForm is
# inline in the catalog and has no /SigFlags.
raw_pdf(P("field-nested.pdf"), {
    1: b"<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [5 0 R] /DA (/Helv 0 Tf 0 g) >> >>",
    2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 595.2756 841.8898] >>",
    3: b"<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 8 0 R >> >> /Contents 4 0 R /Annots [7 0 R] >>",
    4: (b"", b"BT /F1 14 Tf 72 760 Td (Nested signature field) Tj ET"),
    5: b"<< /T (approvals) /FT /Sig /Kids [6 0 R] >>",
    6: b"<< /T (director) /Parent 5 0 R /Kids [7 0 R] >>",
    7: b"<< /Type /Annot /Subtype /Widget /Parent 6 0 R /Rect [340 90 540 150] /F 4 /P 3 0 R >>",
    8: font,
})
# /Rotate 90 with /MK /R 90 on the widget, /Rotate 270 without /MK.
raw_pdf(P("field-rotated.pdf"), {
    1: b"<< /Type /Catalog /Pages 2 0 R /AcroForm 9 0 R >>",
    2: b"<< /Type /Pages /Kids [3 0 R 5 0 R] /Count 2 /MediaBox [0 0 595.2756 841.8898] >>",
    3: b"<< /Type /Page /Parent 2 0 R /Rotate 90 /Resources << /Font << /F1 8 0 R >> >> /Contents 4 0 R /Annots [7 0 R] >>",
    4: (b"", b"BT /F1 14 Tf 72 760 Td (Rotated pages with signature fields) Tj ET"),
    5: b"<< /Type /Page /Parent 2 0 R /Rotate 270 /Resources << /Font << /F1 8 0 R >> >> /Contents 4 0 R /Annots [10 0 R] >>",
    7: b"<< /Type /Annot /Subtype /Widget /FT /Sig /T (Rotated90) /Rect [60 560 120 760] /F 4 /P 3 0 R /MK << /R 90 >> >>",
    8: font,
    9: b"<< /Fields [7 0 R 10 0 R] /SigFlags 0 >>",
    10: b"<< /Type /Annot /Subtype /Widget /FT /Sig /T (Rotated270) /Rect [480 80 540 280] /F 4 /P 5 0 R >>",
})
# ... and one in a password-protected PDF
subprocess.run(["qpdf", "--encrypt", "user", "own", "256", "--", P("field-nested.pdf"), P("field-enc.pdf")], check=True)

# 13. where a signature is asked for (--position auto): "Authorised Signatory"
# on page 2 of 2, on a page turned with /Rotate, a scan (an image, no text) and
# the signer's own name. anchors.json says where each phrase was drawn, as
# displayed (points from the top-left), for tests/check_autoplace.py.
import json

from reportlab.pdfbase.pdfmetrics import stringWidth

anchors = {}


def anchor(name, page, text, x, baseline_from_top, size=11):
    anchors[name] = {"page": page, "rect": [x, baseline_from_top - size * 0.72, stringWidth(text, "Helvetica", size), size]}


c = canvas.Canvas(P("anchor-p2.pdf"), pagesize=A4)
text_page(c, "Agreement - page 1")
c.showPage()
text_page(c, "Agreement - page 2", 8)
c.setFont("Helvetica", 11)
c.drawString(360, 230, "For TrackMyTech Private Limited")
c.drawString(380, 140, "Authorised Signatory")
c.drawString(72, 150, "Place: Chennai")
c.drawString(72, 135, "Date: 26 Oct 2026")
c.showPage()
c.save()
anchor("anchor-p2", 2, "Authorised Signatory", 380, A4[1] - 140)

# reportlab turns the media box for /Rotate 90, so the page shows as A4
# portrait; the text is drawn turned with it, upright to the reader.
c = canvas.Canvas(P("anchor-rotated.pdf"), pagesize=A4)
c.setPageRotation(90)
c.translate(A4[1], 0)
c.rotate(90)
text_page(c, "Rotated page", 10)
c.setFont("Helvetica", 11)
c.drawString(330, 160, "Authorised Signatory")
c.showPage()
c.save()
anchor("anchor-rotated", 1, "Authorised Signatory", 330, A4[1] - 160)

scan = Image.new("L", (595, 842), 245)
draw = ImageDraw.Draw(scan)
for i in range(30):
    draw.rectangle((72, 80 + i * 22, 520, 90 + i * 22), fill=60)
scan.save(P("scan.png"))
c = canvas.Canvas(P("anchor-scan.pdf"), pagesize=A4)
c.drawImage(P("scan.png"), 0, 0, A4[0], A4[1])
c.showPage()
c.save()
anchors["anchor-scan"] = {"page": 1, "fallback": [A4[0] - 170 - 36, A4[1] - 55 - 36, 170, 55]}

c = canvas.Canvas(P("anchor-name.pdf"), pagesize=A4)
text_page(c, "Undertaking", 6)
c.setFont("Helvetica", 11)
c.drawString(72, 560, "We confirm the above with our signature below and accept the terms.")
c.drawString(72, 200, "______________________")
c.drawString(72, 185, "RAHUL TEST DIRECTOR")
c.drawString(72, 170, "Director")
c.showPage()
c.save()
anchor("anchor-name", 1, "RAHUL TEST DIRECTOR", 72, A4[1] - 185)
with open(P("anchors.json"), "w") as f:
    json.dump(anchors, f, indent=1)
print("fixtures written to", out)
