"""Generate test PDFs covering the structures SignDesk must handle.

Usage: python3 tests/make_fixtures.py <outdir>
Needs: reportlab, pyhanko, qpdf, openssl.
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
print("fixtures written to", out)
