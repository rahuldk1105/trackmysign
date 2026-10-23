"""Make modified copies of a signed PDF for the verification tests.

Usage: python3 tests/tamper.py <flip|content> <signed.pdf> <out.pdf>
  flip     change one byte inside the first signed byte range
  content  append an incremental update that draws on the first page
"""
import sys

mode, src, dst = sys.argv[1:]
data = bytearray(open(src, "rb").read())

if mode == "flip":
    i = data.find(b"ReportLab Generated")
    assert i > 0, "no ReportLab header comment to change"
    data[i] = ord("r")
    open(dst, "wb").write(bytes(data))
elif mode == "content":
    from io import BytesIO

    from pyhanko.pdf_utils import generic
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

    w = IncrementalPdfFileWriter(BytesIO(bytes(data)))
    stream = generic.StreamObject(stream_data=b"BT /F1 24 Tf 72 400 Td (CHANGED) Tj ET")
    w.add_stream_to_page(0, w.add_object(stream))
    out = BytesIO()
    w.write(out)
    open(dst, "wb").write(out.getvalue())
else:
    sys.exit(f"unknown mode {mode}")
