# TrackMySign

Sign PDFs with your USB DSC token (tested design: Hypersecu HyperPKI HYP2003) — no Adobe.

- Signs as an **incremental update**: the original bytes are never changed, so
  signatures already on the document (auditor, CA, co-director) stay valid.
- Standard `adbe.pkcs7.detached` / SHA-256 signatures that Adobe Reader validates.
- Visible "Digitally signed by …" box, or invisible.
- Your PIN is never stored. Tokens whose key asks for the PIN on every
  signature work too, batches included, with the PIN entered once.

Status: desktop app for Windows (installer), macOS (dmg) and Linux (AppImage, .deb), plus a command-line tool.

## Install the app

Download from [sign.rahuldk.in](https://sign.rahuldk.in) or the [latest release](../../releases/latest):

- Windows: `TrackMySign-Setup-windows-x64.exe` — run it (no admin needed). If SmartScreen warns, choose *More info → Run anyway*.
- macOS: `TrackMySign-macos-universal.dmg` (Apple Silicon and Intel).
- Linux (x86_64, glibc 2.35+, e.g. Ubuntu 22.04 or Debian 12 and newer):
  `TrackMySign-linux-x86_64.AppImage` — `chmod +x` it and run it; or on Debian and Ubuntu
  `sudo apt install ./TrackMySign-linux-amd64.deb`. Install your token's Linux driver (or
  OpenSC) and `pcscd`.

Open a PDF (or drag it into the window), click where the signature should go, press **Sign document**, enter your PIN. The signed copy is saved next to the original as `name_signed.pdf`, or in a folder you pick under *Settings → Save signed copies to*; an existing file is never replaced (`name_signed_2.pdf` instead). Recently opened files are listed on the start screen and under the Open button.

Forms from banks and government offices often come with empty signature fields. These are
highlighted on the page and listed in the side panel: click one and the signature fills that field.

*Certificate details* (next to the certificate, and in *Settings → DSC token*) shows the class, fingerprints and chain of your DSC, and saves the public certificate as `.cer`, `.pem` or `.p7b` for a portal or bank that asks for it.

You can also right-click a PDF and choose **Sign with TrackMySign** (Windows), or use **Open With → TrackMySign** (Windows, macOS and Linux). Your default PDF viewer stays as it is.

### Updates

On launch the app asks GitHub whether a newer release is out (it fetches
`latest.json` from the latest release; nothing about you or your documents is sent).
If there is one, a bar offers **Install and restart**: the update is downloaded,
checked against the signing key built into the app, installed and the app
reopens (on Linux the AppImage replaces itself; a .deb install asks for your
password to run `dpkg`). Turn the check off, or check by hand, under *Settings → Updates*.

Releases: CI signs the update files when the `TAURI_SIGNING_PRIVATE_KEY` and
`TAURI_SIGNING_PRIVATE_KEY_PASSWORD` secrets are set (public key in
`tauri.conf.json`), and attaches `latest.json` only to tagged releases, never to
`test-build`. The tag must match the version in `tauri.conf.json` (`v0.1.5` ↔ `0.1.5`).

## Supported tokens

Install the driver software that came with your token, then plug it in. TrackMySign
looks for these PKCS#11 drivers, loads every one that is installed and lists the
certificates from all of them (the settings panel shows which drivers were found):

| Token | Windows (`System32` unless noted) | macOS | Linux (`/usr/lib` and the like unless noted) |
|---|---|---|---|
| Hypersecu HyperPKI | `eps2003csp11v2.dll` | `/usr/local/lib/libcastle_v2*.dylib` | `libcastle_v2.so.1.0.0` |
| Feitian ePass2003 | `eps2003csp11.dll` | `/usr/local/lib/libcastle.*.dylib` | `libcastle.so.1.0.0`, `libeps2003csp11.so` |
| Watchdata ProxKey | `SignatureP11.dll` | `/usr/local/lib/wdProxKeyUsbKeyTool/libwdpkcs_Proxkey.dylib` | `libwdpkcs_*.so`, also in `/usr/lib/WatchData/ProxKey/lib` |
| Trust Key | `TRUSTKEYP11_ND_v34.dll` (any version) | — | — |
| Longmai mToken CryptoID | `CryptoIDA_pkcs11.dll` | `libcryptoid*_pkcs11.dylib` (CryptoID tools) | `libcryptoid*_pkcs11.so`, also in `/opt/CryptoIDE/lib` |
| Watchdata | `wdpkcs.dll` | — | — |
| SafeNet / Thales eToken | `eTPKCS11.dll` | `/usr/local/lib/libeTPkcs11.dylib` | `libeTPkcs11.so` |
| Gemalto IDPrime | `IDPrimePKCS11.dll`, `Program Files\Gemalto\IDGo 800 PKCS#11\IDPrimePKCS1164.dll` | `/usr/local/lib/libIDPrimePKCS11.dylib` | `libIDPrimePKCS11.so` |
| Bit4id | `bit4xpki.dll`, `bit4ipki.dll` | `/Library/bit4id/pkcs11/`, PKIManager app | `/usr/lib/bit4id/libbit4xpki.so`, `libbit4ipki.so` |
| OpenSC (last resort) | `Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll` | `/Library/OpenSC/lib/opensc-pkcs11.so` | `opensc-pkcs11.so` |
| p11-kit proxy (only if nothing else is found) | — | — | `p11-kit-proxy.so` |

On Linux the folders searched are `/usr/lib`, `/usr/lib/x86_64-linux-gnu`, `/usr/lib64`
and `/usr/local/lib`; most tokens also need `pcscd` running. Some Linux names in the table
are taken from the vendors' Windows and macOS drivers and are not yet confirmed (see
`token.rs`); if yours is not found, set `TRACKMYSIGN_PKCS11_MODULE` and please open an issue.

Signing always goes through the driver the chosen certificate was read from. A driver
that fails to load is skipped. If your token's driver lives elsewhere, point
`TRACKMYSIGN_PKCS11_MODULE` at it (several paths separated by `;` on Windows, `:` on
macOS and Linux), or pass `--module` to the command-line tool.

## Command-line tool (Windows)

1. Download `trackmysign-windows-x64.exe` from the
   [latest release](../../releases/latest), rename it to `trackmysign.exe`
   and put it in e.g. `Downloads`. (macOS and Linux: `trackmysign-macos-arm64` and
   `trackmysign-linux-x64`; `chmod +x` and run them as `./trackmysign-linux-x64 certs`.)
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
.\trackmysign.exe certs --details                    # email, serial, key, policies, fingerprints, chain
.\trackmysign.exe certs --export 1                   # save certificate 1 as <Name>_DSC.cer (--pem, --chain for .p7b)
.\trackmysign.exe info file.pdf                       # pages, existing signatures, empty signature fields
.\trackmysign.exe sign file.pdf --field Director      # sign into an empty signature field
.\trackmysign.exe verify file.pdf                     # check existing signatures
.\trackmysign.exe verify file.pdf --report report.pdf # ... and save a PDF report for auditors
.\trackmysign.exe verify file.pdf --json              # ... as JSON, for scripts
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
.\trackmysign.exe sign file.pdf --password "secret"  # password-protected PDF
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

Password-protected PDFs (RC4, AES-128 and AES-256) can be signed too; the signed copy
keeps the same password and restrictions. Most of them only restrict editing and open
without a password. If a PDF needs one, the app asks for it (the command-line tool
asks too, or takes `--password`); it is never stored. If the PDF's security settings
do not allow signing, give its owner (permissions) password instead.

`--certify none|forms|annotations` makes the signature a certification (author)
signature that says what may change afterwards: nothing, form filling and
signing, or also comments. Only an unsigned document can be certified, and a
document certified with `none` cannot be signed again. In the desktop app this
is *Signature type → Certify* in the side panel.

## Verification reports

The *Signatures* panel of the app has **Export report…**, which saves a PDF
report of the signature check (by default `name_verification.pdf` next to the
document); `trackmysign verify file.pdf --report report.pdf` does the same.
The report is A4 and plain text: the file name, its SHA-256, page count, the
time of the check in IST and UTC and the TrackMySign version, a one-line
summary ("3 signatures — all valid, document unchanged since the last
signature", or what is wrong), and for each signature its status, signer,
organisation, issuer, certificate serial and validity, signing time,
timestamp, reason and location, certification level, what changed after it,
whether it chains to CCA India, and notes.

What is checked: that the signed bytes are intact, that each signature matches
the signer's certificate, whether the certificates in the signature chain to
the CCA India 2022 root, and what later revisions changed. **Not checked:**
certificate revocation (CRL/OCSP) and timestamp tokens, even when the PDF
contains them (LTV). The footer of every page says so. Names in Indian
scripts are transliterated in the PDF and marked "(transliterated)"; the JSON
keeps the original text.

`trackmysign verify file.pdf --json` prints the same result as JSON. The exit
status is 2 when a signature is invalid or the content changed after signing.
Schema version 1 (`schema_version` is raised only when a field is removed or
changes meaning; new fields may be added):

| Field | Meaning |
|---|---|
| `schema` | `"trackmysign.verification-report"` |
| `schema_version` | `1` |
| `generator` | e.g. `"TrackMySign 0.3.0"` |
| `checked_at` | time of the check, RFC 3339 UTC |
| `file` | `name`, `size` (bytes), `sha256` (lower-case hex), `pages` (`null` if the page tree is unreadable), `encrypted` |
| `summary` | `text` (the summary line), `signatures`, `valid`, `invalid`, `unknown` (counts), `content_changed`, `all_valid` (every signature valid, no content changed, no certification broken) |
| `checked` | `["integrity", "signature", "certificate_chain", "changes_after_signing"]` |
| `not_checked` | `["revocation", "timestamp_token"]` |
| `signatures[]` | in signing order, see below |

Each signature:

| Field | Meaning |
|---|---|
| `index` | 1 = signed first |
| `field` | signature field name |
| `status` | `valid`, `invalid` or `unknown` (could not be checked) |
| `signer` | certificate: `subject`, `organization`, `issuer`, `serial` (hex), `not_before`, `not_after`; `null` if not in the signature |
| `name` | the PDF's `/Name` entry, if any |
| `signing_time` | RFC 3339 with the signer's offset (signer's clock), or `null` |
| `signing_time_in_validity` | the signing time is inside the certificate's validity |
| `timestamp` | `present`; `verified` is always `false` |
| `reason`, `location` | as written by the signer, or `null` |
| `sub_filter`, `digest_algorithm` | e.g. `adbe.pkcs7.detached`, `SHA-256` |
| `certification` | `null`, or `level` (1-3) and `allows`: `no_changes`, `form_filling`, `form_filling_and_annotations` |
| `coverage` | `whole_document`, `signed_bytes`, `file_bytes`, `later_revisions`, `changes`: `none`, `signatures`, `form_or_annotations`, `content`, `unknown` |
| `trust` | `cca_india_2022` or `not_checked` |
| `chain` | certificates, signer first, same fields as `signer` |
| `notes` | why the status is not valid first, then other warnings |

## Portal signing (GST)

The GST portal (gst.gov.in) signs DSC registrations and returns through a
program on your own computer, normally eMudhra's emSigner: the portal page
connects to `wss://127.0.0.1` on port 1585 (or 2095, 2568, 2868, 4587) and asks
it to sign. TrackMySign can answer those requests instead, with the DSC on your
token:

1. *Settings → GST portal signing → Enable portal signing.* TrackMySign makes a
   certificate authority for this computer only, uses it once to issue a
   certificate for `127.0.0.1`, and deletes its private key, so it can never
   vouch for anything else (it is also limited to `127.0.0.1` and `localhost`
   by name constraints). Its certificate is added to your user's trusted
   certificates so the browser accepts the connection: Windows shows a security
   warning to confirm, macOS asks for your password. Linux has no shared list:
   the certificate goes into Chrome/Chromium's (`~/.pki/nssdb`) and each
   Firefox profile's, which needs `certutil` (Debian/Ubuntu: `sudo apt install
   libnss3-tools`, Fedora: `nss-tools`, Arch: `nss`); restart Firefox
   afterwards. The status bar then shows *Portal signing: on (port 1585)*.
2. On the portal, choose to sign with DSC as usual. TrackMySign comes to the
   front and shows which site asks, the PAN and exactly what will be signed
   (your PAN at DSC registration, a hash of the return when filing). It picks
   the certificate for that PAN when the certificate shows it (CCA rules put a
   hash of the PAN in the certificate), you can choose another, enter the PIN
   and press **Sign**, or **Cancel** (the portal then says "Signing
   Cancelled"). An expired certificate is refused.

TrackMySign listens only while it is running, only on `127.0.0.1` (never on the
network), and answers only pages from `https://gst.gov.in` and its
subdomains. If emSigner is running on port 1585, TrackMySign takes the next
free port and Settings says so; the portal tries the ports in order, so quit
emSigner to sign with TrackMySign. The portal checks the emSigner version it
expects (2.8 when this was written); if it says "Please install and use correct
version of emSigner", change the version in Settings.

So the portal works without opening TrackMySign first, *Settings → Background →
Keep running in the background* (on by default once portal signing is on)
makes closing the window leave TrackMySign in the system tray (Windows, Linux;
GNOME needs the AppIndicator extension, which Ubuntu has) or the menu bar
(macOS). Its icon shows whether portal signing is on and on which
port, and has **Open TrackMySign** and **Quit**; a portal request brings the
window up as usual. *Start TrackMySign when I sign in* starts it there at
sign-in, without a window: on Windows an entry under
`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, which the uninstaller
removes; on macOS `~/Library/LaunchAgents/TrackMySign.plist` (turn the option
off before deleting the app, or delete that file); on Linux
`~/.config/autostart/TrackMySign.desktop`. Turning background mode off
also removes the entry.

Browsers:

- **Chrome / Edge** may ask whether gst.gov.in may access apps and services on
  this device (the local network access prompt). Allow it, or the portal cannot
  reach TrackMySign.
- **Firefox** uses its own certificate list. Recent versions also trust
  certificates you added to Windows or macOS; if Firefox still refuses the
  connection, set `security.enterprise_roots.enabled` to `true` in
  `about:config`. On Linux the certificate is added to the Firefox profiles
  directly (snap and Flatpak ones included); a profile made later does not
  have it, so turn portal signing off and on again.

*Disable and remove* stops the listener, removes the certificate from your
trusted certificates (Windows and macOS ask again; on Linux from the same
Chrome and Firefox lists) and deletes its files.

MCA21 V3 and the Income Tax portal are **not** supported: they use eMudhra's
emBridge, whose requests are encrypted with keys licensed to eMudhra. Portal
signing is an independent, interoperable implementation of the local protocol
the GST portal's own JavaScript uses; TrackMySign is not affiliated with or
endorsed by GSTN, the GST Council or eMudhra.

## Development

```
cargo test                 # unit tests
cd apps/desktop && npm ci && npx tauri dev   # run the desktop app
tests/run.sh               # end-to-end: SoftHSM virtual token + generated PDFs,
                           # validated independently with pyHanko and qpdf
```

`tests/run.sh` needs `softhsm2`, `opensc`, `qpdf`, `poppler-utils` (pdftoppm), `openssl`, `curl`, Node.js and `pip install pyhanko reportlab`.
The timestamp and LTV tests run a local TSA, OCSP responder and CRL server (`tests/services.py`), so no internet is needed.

Layout:

- `crates/signdesk-core` — PDF reader/incremental writer, CMS, PKCS#11 token access
- `crates/signdesk-cli` — `trackmysign` command
- `crates/portal-bridge` — local signer for the GST portal (TLS identity, trust store, WebSocket listener)
- `apps/desktop` — Tauri desktop app (React + PDF.js front end)
- `PLAN.md` — decisions and roadmap

## Project

- [CONTRIBUTING.md](CONTRIBUTING.md) — building, tests, code style, adding a token driver
- [PRIVACY.md](PRIVACY.md) — nothing leaves your computer except optional timestamp/LTV requests and the update check
- [SECURITY.md](SECURITY.md) — reporting vulnerabilities privately
- [CHANGELOG.md](CHANGELOG.md) — changes in each release, also on [sign.rahuldk.in/changelog](https://sign.rahuldk.in/changelog/)

MIT licence, see [LICENSE](LICENSE).
