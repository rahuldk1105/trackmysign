# TrackMySign

Sign PDFs with your USB DSC token (tested design: Hypersecu HyperPKI HYP2003) — no Adobe.

- Signs as an **incremental update**: the original bytes are never changed, so
  signatures already on the document (auditor, CA, co-director) stay valid.
- Standard `adbe.pkcs7.detached` / SHA-256 signatures that Adobe Reader validates.
- Visible "Digitally signed by …" box, or invisible.
- Your PIN is never stored.

Status: desktop app for Windows (installer) and macOS (dmg), plus a command-line tool.

## Install the app

Download from [sign.rahuldk.in](https://sign.rahuldk.in) or the [latest release](../../releases/latest):

- Windows: `TrackMySign-Setup-windows-x64.exe` — run it (no admin needed). If SmartScreen warns, choose *More info → Run anyway*.
- macOS: `TrackMySign-macos-universal.dmg` (Apple Silicon and Intel).

Open a PDF (or drag it into the window), click where the signature should go, press **Sign document**, enter your PIN. The signed copy is saved next to the original as `name_signed.pdf`.

## Supported tokens

Install the driver software that came with your token, then plug it in. TrackMySign
looks for these PKCS#11 drivers, loads every one that is installed and lists the
certificates from all of them (the settings panel shows which drivers were found):

| Token | Windows (`System32` unless noted) | macOS |
|---|---|---|
| Hypersecu HyperPKI | `eps2003csp11v2.dll` | `/usr/local/lib/libcastle_v2*.dylib` |
| Feitian ePass2003 | `eps2003csp11.dll` | `/usr/local/lib/libcastle.*.dylib` |
| Watchdata ProxKey | `SignatureP11.dll` | `/usr/local/lib/wdProxKeyUsbKeyTool/libwdpkcs_Proxkey.dylib` |
| Trust Key | `TRUSTKEYP11_ND_v34.dll` (any version) | — |
| Longmai mToken CryptoID | `CryptoIDA_pkcs11.dll` | `libcryptoid*_pkcs11.dylib` (CryptoID tools) |
| Watchdata | `wdpkcs.dll` | — |
| SafeNet / Thales eToken | `eTPKCS11.dll` | `/usr/local/lib/libeTPkcs11.dylib` |
| Gemalto IDPrime | `IDPrimePKCS11.dll`, `Program Files\Gemalto\IDGo 800 PKCS#11\IDPrimePKCS1164.dll` | `/usr/local/lib/libIDPrimePKCS11.dylib` |
| Bit4id | `bit4xpki.dll`, `bit4ipki.dll` | `/Library/bit4id/pkcs11/`, PKIManager app |
| OpenSC (last resort) | `Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll` | `/Library/OpenSC/lib/opensc-pkcs11.so` |

Signing always goes through the driver the chosen certificate was read from. A driver
that fails to load is skipped. If your token's driver lives elsewhere, point
`TRACKMYSIGN_PKCS11_MODULE` at it (several paths separated by `;` on Windows, `:` on
macOS), or pass `--module` to the command-line tool.

## Command-line tool (Windows)

1. Download `trackmysign-windows-x64.exe` from the
   [latest release](../../releases/latest), rename it to `trackmysign.exe`
   and put it in e.g. `Downloads`.
2. Plug in the token, open PowerShell in that folder:

```powershell
.\trackmysign.exe certs
```

   You should see your name, the issuing CA, the expiry date and the driver it was read through.

3. Sign a test PDF (bottom-right of the last page by default):

```powershell
.\trackmysign.exe sign "C:\path\to\test.pdf" --reason "Approved" --location "Chennai"
```

   Enter your PIN when asked. The result is `test_signed.pdf` next to the original.

4. Open `test_signed.pdf` in Adobe Reader and check the signature panel.

Other options:

```powershell
.\trackmysign.exe info file.pdf                       # pages, existing signatures
.\trackmysign.exe verify file.pdf                     # check existing signatures
.\trackmysign.exe sign file.pdf --page 1 --position top-right
.\trackmysign.exe sign file.pdf --rect 400,700,170,55  # x,y,width,height in points from top-left
.\trackmysign.exe sign file.pdf --pages all            # one signature, box on every page
.\trackmysign.exe sign file.pdf --pages 1-3,5          # ... or on some pages
.\trackmysign.exe sign file.pdf --invisible
.\trackmysign.exe --module C:\Windows\System32\eps2003csp11v2.dll certs   # explicit driver
.\trackmysign.exe sign file.pdf --timestamp --ltv     # long-term validity (needs internet)
.\trackmysign.exe sign file.pdf --timestamp=http://timestamp.sectigo.com
```

Long-term validity is off by default, so signing works fully offline. `--timestamp`
adds an RFC 3161 trusted timestamp (default server `http://timestamp.digicert.com`;
only a hash of the signature is sent). `--ltv` embeds your CA's OCSP/CRL answers
in the PDF so the signature can be validated after the certificate expires. The
desktop app has the same options under *Settings → Long-term validity*. If a
server cannot be reached, nothing is saved and you can sign again without it.

## Development

```
cargo test                 # unit tests
cd apps/desktop && npm ci && npx tauri dev   # run the desktop app
tests/run.sh               # end-to-end: SoftHSM virtual token + generated PDFs,
                           # validated independently with pyHanko and qpdf
```

`tests/run.sh` needs `softhsm2`, `opensc`, `qpdf`, `openssl`, `curl` and `pip install pyhanko reportlab`.
The timestamp and LTV tests run a local TSA, OCSP responder and CRL server (`tests/services.py`), so no internet is needed.

Layout:

- `crates/signdesk-core` — PDF reader/incremental writer, CMS, PKCS#11 token access
- `crates/signdesk-cli` — `trackmysign` command
- `apps/desktop` — Tauri desktop app (React + PDF.js front end)
- `PLAN.md` — decisions and roadmap
