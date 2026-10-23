# TrackMySign

Sign PDFs with your USB DSC token (tested design: Hypersecu HyperPKI HYP2003) — no Adobe.

- Signs as an **incremental update**: the original bytes are never changed, so
  signatures already on the document (auditor, CA, co-director) stay valid.
- Standard `adbe.pkcs7.detached` / SHA-256 signatures that Adobe Reader validates.
- Visible "Digitally signed by …" box, or invisible.
- Your PIN is never stored. Tokens whose key asks for the PIN on every
  signature work too, batches included, with the PIN entered once.

Status: desktop app for Windows (installer) and macOS (dmg), plus a command-line tool.

## Install the app

Download from [sign.rahuldk.in](https://sign.rahuldk.in) or the [latest release](../../releases/latest):

- Windows: `TrackMySign-Setup-windows-x64.exe` — run it (no admin needed). If SmartScreen warns, choose *More info → Run anyway*.
- macOS: `TrackMySign-macos-universal.dmg` (Apple Silicon and Intel).

Open a PDF (or drag it into the window), click where the signature should go, press **Sign document**, enter your PIN. The signed copy is saved next to the original as `name_signed.pdf`.

You can also right-click a PDF and choose **Sign with TrackMySign** (Windows), or use **Open With → TrackMySign** (Windows and macOS). Your default PDF viewer stays as it is.

### Updates

On launch the app asks GitHub whether a newer release is out (it fetches
`latest.json` from the latest release; nothing about you or your documents is sent).
If there is one, a bar offers **Install and restart**: the update is downloaded,
checked against the signing key built into the app, installed and the app
reopens. Turn the check off, or check by hand, under *Settings → Updates*.

Releases: CI signs the update files when the `TAURI_SIGNING_PRIVATE_KEY` and
`TAURI_SIGNING_PRIVATE_KEY_PASSWORD` secrets are set (public key in
`tauri.conf.json`), and attaches `latest.json` only to tagged releases, never to
`test-build`. The tag must match the version in `tauri.conf.json` (`v0.1.5` ↔ `0.1.5`).

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

   You should see your name, the issuing CA, the expiry date (with the days left) and the driver it was read through.

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
.\trackmysign.exe sign a.pdf b.pdf c.pdf               # several PDFs, one PIN entry
.\trackmysign.exe sign file.pdf --image signature.png  # handwritten signature in the box (PNG or JPEG)
.\trackmysign.exe sign file.pdf --image signature.png --image-position above
.\trackmysign.exe --module C:\Windows\System32\eps2003csp11v2.dll certs   # explicit driver
.\trackmysign.exe sign file.pdf --timestamp --ltv     # long-term validity (needs internet)
.\trackmysign.exe sign file.pdf --timestamp=http://timestamp.sectigo.com
.\trackmysign.exe sign file.pdf --certify forms       # certify as the author (first signature only)
```

Long-term validity is off by default, so signing works fully offline. `--timestamp`
adds an RFC 3161 trusted timestamp (default server `http://timestamp.digicert.com`;
only a hash of the signature is sent). `--ltv` embeds your CA's OCSP/CRL answers
in the PDF so the signature can be validated after the certificate expires. The
desktop app has the same options under *Settings → Long-term validity*. If a
server cannot be reached, nothing is saved and you can sign again without it.

An expired certificate is refused, since a signature made with it is not valid
(`--allow-expired` signs anyway, with a warning). The desktop app reminds you to
renew 30 days ahead (15, 60 or off under *Settings → Expiry reminder*), also
when the token is not plugged in, and turns signing off once the DSC has expired.

`--certify none|forms|annotations` makes the signature a certification (author)
signature that says what may change afterwards: nothing, form filling and
signing, or also comments. Only an unsigned document can be certified, and a
document certified with `none` cannot be signed again. In the desktop app this
is *Signature type → Certify* in the side panel.

## Development

```
cargo test                 # unit tests
cd apps/desktop && npm ci && npx tauri dev   # run the desktop app
tests/run.sh               # end-to-end: SoftHSM virtual token + generated PDFs,
                           # validated independently with pyHanko and qpdf
```

`tests/run.sh` needs `softhsm2`, `opensc`, `qpdf`, `poppler-utils` (pdftoppm), `openssl`, `curl` and `pip install pyhanko reportlab`.
The timestamp and LTV tests run a local TSA, OCSP responder and CRL server (`tests/services.py`), so no internet is needed.

Layout:

- `crates/signdesk-core` — PDF reader/incremental writer, CMS, PKCS#11 token access
- `crates/signdesk-cli` — `trackmysign` command
- `apps/desktop` — Tauri desktop app (React + PDF.js front end)
- `PLAN.md` — decisions and roadmap

## Project

- [CONTRIBUTING.md](CONTRIBUTING.md) — building, tests, code style, adding a token driver
- [PRIVACY.md](PRIVACY.md) — nothing leaves your computer except optional timestamp/LTV requests and the update check
- [SECURITY.md](SECURITY.md) — reporting vulnerabilities privately
- [CHANGELOG.md](CHANGELOG.md) — changes in each release, also on [sign.rahuldk.in/changelog](https://sign.rahuldk.in/changelog/)

MIT licence, see [LICENSE](LICENSE).
