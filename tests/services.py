"""Local stand-ins for a CA's online services, so the LTV tests run offline.

Usage: python3 tests/services.py <pki-dir> <port>
  POST /tsa    RFC 3161 timestamps (openssl ts -reply, Test Timestamp Authority)
  POST /tsa-nochain  same, without the TSA CA certificate (it must be fetched via AIA)
  POST /ocsp   OCSP for certificates of the test sub CA (openssl ocsp)
  GET  /<file> CRLs and CA certificates from <pki-dir>/www
"""
import os
import subprocess
import sys
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PKI, PORT = sys.argv[1], int(sys.argv[2])
TSA_CNF = os.path.join(PKI, "tsa.cnf")
with open(TSA_CNF, "w") as f:
    f.write(f"""[tsa]
default_tsa = t
[t]
serial = {PKI}/tsaserial
signer_digest = sha256
default_policy = 1.2.3.4.1
digests = sha256, sha384, sha512
accuracy = secs:1
ess_cert_id_alg = sha256
""")


def p(name):
    return os.path.join(PKI, name)


def run_openssl(args, request):
    with tempfile.TemporaryDirectory() as d:
        req, resp = os.path.join(d, "req"), os.path.join(d, "resp")
        with open(req, "wb") as f:
            f.write(request)
        args = [a.replace("{req}", req).replace("{resp}", resp) for a in args]
        subprocess.run(["openssl", *args], check=True, capture_output=True)
        with open(resp, "rb") as f:
            return f.read()


class Handler(BaseHTTPRequestHandler):
    def reply(self, body, ctype):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = os.path.join(PKI, "www", os.path.basename(self.path))
        if not os.path.isfile(path):
            self.send_error(404)
            return
        with open(path, "rb") as f:
            self.reply(f.read(), "application/octet-stream")

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        try:
            if self.path in ("/tsa", "/tsa-nochain"):
                chain = ["-chain", p("tsaca.pem")] if self.path == "/tsa" else []
                resp = run_openssl(["ts", "-reply", "-config", TSA_CNF, "-queryfile", "{req}", *chain,
                                    "-signer", p("tsa.pem"), "-inkey", p("tsa.key"), "-out", "{resp}"], body)
                self.reply(resp, "application/timestamp-reply")
            elif self.path == "/ocsp":
                resp = run_openssl(["ocsp", "-index", p("sub-index.txt"), "-CA", p("sub.pem"),
                                    "-rsigner", p("ocsp.pem"), "-rkey", p("ocsp.key"), "-nmin", "60",
                                    "-reqin", "{req}", "-respout", "{resp}"], body)
                self.reply(resp, "application/ocsp-response")
            else:
                self.send_error(404)
        except subprocess.CalledProcessError as e:
            sys.stderr.write(e.stderr.decode(errors="replace"))
            self.send_error(500)

    def log_message(self, *args):
        pass


ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
