# SignDesk

Sign PDFs with your USB DSC token (tested design: Hypersecu HyperPKI HYP2003) — no Adobe.

- Signs as an **incremental update**: the original bytes are never changed, so
  signatures already on the document (auditor, CA, co-director) stay valid.
- Standard `adbe.pkcs7.detached` / SHA-256 signatures that Adobe Reader validates.
- Visible "Digitally signed by …" box, or invisible.
- Your PIN is never stored.

Status: **test phase** — command-line tool. The desktop app (Windows, then macOS) comes next.

## Try it on Windows with your token

1. Download `signdesk-windows-x64` from the latest successful
   [CI run](../../actions/workflows/ci.yml) (Artifacts section) and unzip `signdesk.exe`,
   e.g. into `Downloads`.
2. Plug in the token, open PowerShell in that folder:

```powershell
.\signdesk.exe certs
```

   You should see your name, the issuing CA and the expiry date.

3. Sign a test PDF (bottom-right of the last page by default):

```powershell
.\signdesk.exe sign "C:\path\to\test.pdf" --reason "Approved" --location "Chennai"
```

   Enter your PIN when asked. The result is `test_signed.pdf` next to the original.

4. Open `test_signed.pdf` in Adobe Reader and check the signature panel.

Other options:

```powershell
.\signdesk.exe info file.pdf                       # pages, existing signatures
.\signdesk.exe sign file.pdf --page 1 --position top-right
.\signdesk.exe sign file.pdf --rect 400,700,170,55  # x,y,width,height in points from top-left
.\signdesk.exe sign file.pdf --invisible
.\signdesk.exe --module C:\Windows\System32\eps2003csp11v2.dll certs   # explicit driver
```

## Development

```
cargo test                 # unit tests
tests/run.sh               # end-to-end: SoftHSM virtual token + generated PDFs,
                           # validated independently with pyHanko and qpdf
```

`tests/run.sh` needs `softhsm2`, `opensc`, `qpdf`, `openssl` and `pip install pyhanko reportlab`.

Layout:

- `crates/signdesk-core` — PDF reader/incremental writer, CMS, PKCS#11 token access
- `crates/signdesk-cli` — `signdesk` command
- `PLAN.md` — decisions and roadmap
