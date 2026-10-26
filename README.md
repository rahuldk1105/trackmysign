# TrackMy Sign

Sign PDFs with your USB DSC token (tested design: Hypersecu HyperPKI HYP2003) — no Adobe.

- Signs as an **incremental update**: the original bytes are never changed, so
  signatures already on the document (auditor, CA, co-director) stay valid.
- Standard `adbe.pkcs7.detached` / SHA-256 signatures that Adobe Reader validates.
- Visible "Digitally signed by …" box, or invisible.
- Other files (Word, Excel, ZIP, XML, …) are signed as standard `.p7s` / `.p7m`
  (CMS / PKCS#7) signatures, see [Signing other files](#signing-other-files-p7s--p7m).
- Your PIN is never stored. Tokens whose key asks for the PIN on every
  signature work too, batches included, with the PIN entered once.

Status: desktop app for Windows (installer), macOS (dmg) and Linux (AppImage, .deb), plus a command-line tool.

## Install the app

Download from [sign.rahuldk.in](https://sign.rahuldk.in) or the [latest release](../../releases/latest):

- Windows: **[Get it from the Microsoft Store](https://apps.microsoft.com/detail/9NV4G85VML2K)** (recommended: signed by Microsoft, updates automatically).
  Or download `TrackMySign-Setup-windows-x64.exe` and run it (no admin needed); it isn't code-signed yet, so if SmartScreen warns, choose *More info → Run anyway*.
- macOS: `TrackMySign-macos-universal.dmg` (Apple Silicon and Intel).
- Linux (x86_64, glibc 2.35+, e.g. Ubuntu 22.04 or Debian 12 and newer):
  `TrackMySign-linux-x86_64.AppImage` — `chmod +x` it and run it; or on Debian and Ubuntu
  `sudo apt install ./TrackMySign-linux-amd64.deb`. Install your token's Linux driver (or
  OpenSC) and `pcscd`.

### Install with winget

```
winget install --id TrackMyTech.TrackMySign
```

This works once Microsoft has approved the package in the winget community
repository; until then, use the installer above. New releases are submitted
there too, so `winget upgrade` picks them up after review. See
[packaging/winget](packaging/winget/README.md).

### Microsoft Store

A Microsoft Store edition is being prepared: the same app as an MSIX package,
updated by the Store instead of by the app. It has no right-click "Sign with
TrackMy Sign" entry (use *Open with*), and its settings and history stay
inside the package. See [packaging/msstore](packaging/msstore/README.md).

Open a PDF (or drag it into the window), click where the signature should go, press **Sign document**, enter your PIN. The signed copy is saved next to the original as `name_signed.pdf`, or in a folder you pick under *Settings → Save signed copies to*; an existing file is never replaced (`name_signed_2.pdf` instead). Recently opened files are listed on the start screen and under the Open button.

Forms from banks and government offices often come with empty signature fields. These are
highlighted on the page and listed in the side panel: click one and the signature fills that field.

*Certificate details* (next to the certificate, and in *Settings → DSC token*) shows the class, fingerprints and chain of your DSC, and saves the public certificate as `.cer`, `.pem` or `.p7b` for a portal or bank that asks for it.

You can also right-click a PDF and choose **Sign with TrackMy Sign** (Windows), or use **Open With → TrackMy Sign** (Windows, macOS and Linux). Your default PDF viewer stays as it is. Select several PDFs first and they open together as one batch, signed with one PIN entry; files that are not PDFs are left out. If a batch is already loaded, the app asks whether to add them to it or replace it.

The app speaks English, Hindi (हिन्दी) and Tamil (தமிழ்); it follows your system language, or choose one under *Settings → Appearance → Language*. The text printed in the signature box stays in English.

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

Install the driver software that came with your token, then plug it in. TrackMy Sign
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
.\trackmysign.exe verify-folder C:\Invoices --recursive --report invoices.pdf --csv invoices.csv
.\trackmysign.exe sign-file bid.docx prices.xlsx      # bid.docx.p7s, prices.xlsx.p7s (see Signing other files)
.\trackmysign.exe verify-file bid.docx               # check bid.docx.p7s
.\trackmysign.exe sign file.pdf --page 1 --position top-right
.\trackmysign.exe sign file.pdf --rect 400,700,170,55  # x,y,width,height in points from top-left
.\trackmysign.exe sign file.pdf --pages all            # one signature, box on every page
.\trackmysign.exe sign file.pdf --pages 1-3,5          # ... or on some pages
.\trackmysign.exe sign file.pdf --invisible
.\trackmysign.exe sign a.pdf b.pdf c.pdf               # several PDFs, one PIN entry
.\trackmysign.exe sign file.pdf --image signature.png  # handwritten signature in the box (PNG or JPEG)
.\trackmysign.exe sign file.pdf --image signature.png --image-position above
.\trackmysign.exe sign file.pdf --style style.json --seal seal.png  # own box design and company seal
.\trackmysign.exe --module C:\Windows\System32\eps2003csp11v2.dll certs   # explicit driver
.\trackmysign.exe sign file.pdf --timestamp --ltv     # long-term validity (needs internet)
.\trackmysign.exe sign file.pdf --timestamp=http://timestamp.sectigo.com
.\trackmysign.exe sign file.pdf --password "secret"  # password-protected PDF
.\trackmysign.exe sign file.pdf --certify forms       # certify as the author (first signature only)
.\trackmysign.exe watch C:\Scans                      # sign every PDF put into a folder (see Watch folder)
.\trackmysign.exe history --since 2026-10-01          # what was signed on this computer (see Signing history)
.\trackmysign.exe pages merge a.pdf b.pdf -o out.pdf  # merge, reorder, turn, delete pages (see Preparing pages)
.\trackmysign.exe doctor                              # support report for a bug report (see Reporting a problem)
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

## Preparing pages before signing

**Pages** in the toolbar opens the open document's pages as thumbnails: drag
them into order, turn them left or right, delete them, insert a blank page
(the size of the page before it), append other PDFs with **Add PDF…**, and
undo (Ctrl+Z). **Save as…** writes a new PDF (by default
`name_prepared.pdf` next to the original), which then opens, ready to sign.
The original files are never changed. The command line does the same:

```powershell
.\trackmysign.exe pages merge a.pdf b.pdf -o out.pdf            # join PDFs in this order
.\trackmysign.exe pages select in.pdf "1-3,5,7-" -o out.pdf     # keep and order pages (7- = to the end, 5-3 backwards)
.\trackmysign.exe pages rotate in.pdf 90 --pages 2,4 -o out.pdf # turn clockwise (-90 turns left); all pages without --pages
.\trackmysign.exe pages delete in.pdf 2,4-6 -o out.pdf
.\trackmysign.exe pages insert-blank in.pdf --after 3 --size a4 -o out.pdf  # --after 0: before the first page; --size same|a4|letter
```

Without `-o` the result is `<first input>_prepared.pdf`; an input file is
never accepted as the output. Contents, fonts, images, links between kept
pages, comments and form fields are copied; page sizes and rotation stay as
they were (also when inherited from the page tree); form fields from different
files with the same name are renamed (`company` becomes `company_2`).
Bookmarks are not carried over. A password-protected PDF is opened with its
password (`--password`, or asked for) and the new file has no password; a PDF
whose security settings do not allow changing pages needs its owner
(permissions) password.

Existing signatures cannot survive changes to the pages: the new file does not
contain them. When a source is signed, the app warns before saving and asks
again, and the command line asks (or needs `--yes`). Use the page tools to
prepare a document for signing, not to edit one that is already signed.

## Signature box design

*Appearance → Design…* in the side panel changes how the box looks, with a
preview at the size of the box you placed. The preview is drawn from the same
layout the PDF is written from, so what you see is what is signed.

- **Layout**: text only, signature image left of or above the text, or the
  image alone (the company seal when there is no signature image).
- **Company seal or logo** (PNG with a transparent background, or JPEG): right
  of the text, or behind it with an opacity of your choice.
- **Text lines**, switched on and off and put in any order: *Digitally signed
  by* with the name below it or on one line, *For* the organisation (the
  certificate's O=, or one you type), a role such as *Director* or *Authorised
  Signatory*, the date (`2026.10.24 14:05:09 +05:30`, `24-10-2026 14:05 IST`,
  with seconds, or `24 Oct 2026`), the reason, the location and two lines of
  your own.
- **Text**: Helvetica, Times or Courier (the standard PDF fonts, nothing is
  embedded), name and/or first line in bold, size fitted to the box or fixed
  (long lines then wrap), black, dark blue or any colour, left or centred.
- **Box**: border on or off with its colour and width, a light background,
  padding, and a small tick mark. The tick is decoration only: PDF readers show
  their own check of the signature.

The box is printed in English letters: Hindi, Tamil and other Indian scripts
typed into a line are transliterated (*रमेश* prints as *Ramesha*), and the
designer shows how a line will print. The design is saved with presets, so the
watch folder uses it too. Without a design, the box looks exactly as before.

On the command line, `--style style.json` takes the same settings (all
optional, snake_case; the app saves them in this form in each preset's
`style`):

```json
{"version": 1, "layout": "auto", "lines": ["signed_by", "organisation", "role", "date"],
 "role": "Director", "date_format": "dd_mm_yyyy_hh_mm", "font": "times",
 "bold_first_line": true, "text_color": "#1B3A8C", "align": "center",
 "seal": {"position": "behind", "opacity": 0.25}}
```

`layout`: `auto` (as `--image-position` says), `text_only`, `image_left`,
`image_above`, `image_only`. `lines`: `signed_by_label`, `name`, `signed_by`,
`organisation`, `role`, `date`, `reason`, `location`, `custom_1`, `custom_2`
(default: `signed_by_label`, `name`, `date`, `reason`, `location`).
`date_format`: `classic`, `dd_mm_yyyy_hh_mm`, `dd_mm_yyyy_hh_mm_ss`,
`dd_mmm_yyyy`. Also `organisation`, `custom_1`, `custom_2`, `font`
(`helvetica`, `times`, `courier`), `bold_name`, `font_size` (points, `null` to
fit), `border`, `border_color`, `border_width`, `background` (`none`,
`light`), `padding`, `tick`. A style with `seal` needs `--seal seal.png`.

## Verification reports

The *Signatures* panel of the app has **Export report…**, which saves a PDF
report of the signature check (by default `name_verification.pdf` next to the
document); `trackmysign verify file.pdf --report report.pdf` does the same.
The report is A4 and plain text: the file name, its SHA-256, page count, the
time of the check in IST and UTC and the TrackMy Sign version, a one-line
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
| `generator` | e.g. `"TrackMy Sign 0.3.0"` |
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

### Verifying a folder

**Verify folder…** (the shield button in the toolbar, the start screen, or
*Verify all PDFs in this folder…* in the Signatures panel) checks every PDF in a
folder, optionally with its subfolders, and lists each file as it is checked:
*All valid*, *Invalid signature*, *Changed after signing*, *Unsigned*,
*Unreadable* (not a PDF, or damaged) or *Needs a password*. Filter the list by
*All*, *Problems* or *Unsigned*, click a file to open it, and save the result
with **Export report…** (one PDF) or **Export CSV…** (by default
`Invoices_verification.pdf` / `.csv` for a folder `Invoices`, saved next to
it, not inside it). A password
typed in the dialog is tried on every PDF that does not open without one; it is
not stored. Files and folders whose names start with `.` (and, on Windows,
hidden or system files) are skipped; links are followed, each folder once.

```powershell
.\trackmysign.exe verify-folder C:\Invoices                      # one line per PDF, then the totals
.\trackmysign.exe verify-folder C:\Invoices --recursive --password "secret" --report invoices.pdf --csv invoices.csv
.\trackmysign.exe verify-folder C:\Invoices --json               # JSON, for scripts
```

The exit status is 0 when every signed PDF is valid, and 2 when a signature is
invalid, the content changed after signing, or a PDF could not be read or needs
a password. PDFs without signatures do not count unless `--require-signed` is
given.

The PDF report has the folder, the time of the check (IST and UTC), the totals
("12 files: 8 all valid, 2 with problems, 1 unsigned, 1 unreadable"), a table
of the files with their status and signers, and an appendix with each file's
size, SHA-256 and the same signature details as the single-file report. The
CSV has one row per signature (one row for a file without any), with the file's
columns repeated: `file`, `size`, `sha256`, `file_status`, `signatures`,
`file_error`, `signature` (1 = signed first), `field`, `status`, `signer`,
`organization`, `issuer`, `serial`, `not_before`, `not_after`, `signing_time`,
`timestamp`, `reason`, `location`, `certification` (level), `changes`, `trust`,
`notes`. It is UTF-8 with a byte order mark so spreadsheet programs show
Indian scripts; text from a PDF that starts with `=`, `+`, `-` or `@` gets a
leading `'` so it is not run as a formula.

JSON schema version 1 (`schema_version` is raised only when a field is removed
or changes meaning):

| Field | Meaning |
|---|---|
| `schema` | `"trackmysign.folder-verification-report"` |
| `schema_version` | `1` |
| `generator`, `checked_at` | as in the single-file report |
| `folder`, `recursive` | the folder checked, and whether subfolders were |
| `complete` | `false` when the check was stopped before every file was checked |
| `summary` | the totals line |
| `totals` | `files`, `all_valid`, `problems` (= `some_invalid` + `content_changed`), `some_invalid`, `content_changed`, `unsigned`, `unreadable`, `needs_password`, `signatures` |
| `checked`, `not_checked` | as in the single-file report |
| `files[]` | in path order: `path` (relative, `/` between folders), `size`, `sha256`, `status` (`all_valid`, `some_invalid`, `content_changed`, `unsigned`, `unreadable`, `needs_password`), `error` (why it could not be checked, else `null`), `pages`, `encrypted`, `summary` (the single-file summary line), `signatures` (as in the single-file report) |

`some_invalid` means a signature is invalid or could not be checked;
`content_changed` means the content changed after a signature, or anything
changed after a certification that allowed no changes.

## Signing other files (.p7s / .p7m)

Word, Excel, ZIP, XML, images or any other file can be signed with the DSC as a
standard CMS / PKCS#7 signature (RFC 5652), the format OpenSSL, Java and
Windows tools read:

- **Separate file (`.p7s`, detached, the default)**: `bid.docx.p7s` is saved
  next to `bid.docx`, which stays as it is. Send or upload both.
- **File inside (`.p7m`, attached / enveloping)**: `bid.docx.p7m` contains the
  file and its signature. Send or upload the `.p7m`; the recipient gets the
  file back with *Save original…* (or `openssl cms -verify`).

Both are DER, SHA-256 (RSA PKCS#1 v1.5 or ECDSA, as the key is), with the
signed attributes contentType, signingTime, messageDigest and ESS
signingCertificateV2 and the certificate chain included, which is CAdES-BES;
with a trusted timestamp (RFC 3161, the server from Settings or `--timestamp`)
it is CAdES-T. This is the same signature TrackMy Sign puts into a PDF, built
by the same code.

Where these are accepted: there is no single published format for "signed
documents" on Indian e-procurement portals. GePNIC portals (CPPP
eprocure.gov.in and the state portals built on it) sign bid documents inside
the browser with their own DSC signer component while you upload them, so they
do not need a `.p7s` from you. Detached `.p7s` / attached `.p7m` is the
general-purpose format for the other cases, when a department, buyer or
auditor wants a file other than a PDF digitally signed with a DSC. Check what the receiving office
expects (and whether it wants the `.p7s` or the `.p7m`) before relying on one.
A PDF is better signed as a PDF (the signature shows in Adobe Reader); a
`.p7s` of a PDF works too.

In the app, **Sign other files…** (the toolbar button next to *Verify folder*,
or the start screen) or dropping / opening a file that is not a PDF shows the
file panel: each file with its size, SHA-256 and the `.p7s` already next to it,
checked as for a PDF signature (valid or not, signer, issuer, signing time,
chain, CCA India trust). Choose *Separate file (.p7s)* or *File inside
(.p7m)*, optionally the timestamp, and **Sign**: one PIN entry for all files,
as with a PDF batch (also for keys that ask for the PIN on every signature).
An existing `.p7s` / `.p7m` is replaced, after the panel has said so. A `.p7s`
or `.p7m` opened or dropped is checked (a `.p7s` against the file of the same
name next to it); for a `.p7m`, **Save original…** writes the file inside.
"Sign with TrackMy Sign" in Explorer's right-click menu stays for PDFs only:
registering it for every file type would add the entry to every file on the
PC; use *Open with* or drag the files onto the window instead.

```powershell
.\trackmysign.exe sign-file bid.docx prices.xlsx drawing.zip       # bid.docx.p7s, … : one PIN for all
.\trackmysign.exe sign-file --attached data.xml                    # data.xml.p7m with the file inside
.\trackmysign.exe sign-file bid.docx --timestamp --out C:\Out\bid.p7s --force
.\trackmysign.exe verify-file bid.docx                             # finds bid.docx.p7s next to it
.\trackmysign.exe verify-file bid.docx --sig signature.p7s
.\trackmysign.exe verify-file data.xml.p7m --extract               # saves data.xml (or "data (2).xml")
```

`sign-file` does not replace an existing signature file unless `--force` is
given; `--out` is for a single file. `verify-file` accepts DER, PEM or Base64
signatures, and BER as OpenSSL writes a `.p7m`; it exits with status 2 when the
signature is not valid (the file changed, or the signature does not match the
certificate) or could not be checked (for example a `.p7s` without its file).
Trust is checked against the CCA India 2022 root as for PDFs; revocation is not
checked, and an attached timestamp is reported but not verified. The same
signature checks with OpenSSL:

```sh
openssl cms -verify -binary -inform DER -in bid.docx.p7s -content bid.docx -CAfile CCAIndia2022.pem
openssl cms -verify -binary -inform DER -in data.xml.p7m -out data.xml -CAfile CCAIndia2022.pem
```

## Watch folder

*Settings → Watch folder* signs every PDF put into a folder you choose, one at
a time, without a click per document: for invoices exported by an accounting
program, scans from a copier, and the like.

**Trust model: anyone who can write to that folder while watching is on can
get documents signed with your DSC.** Use a private folder on your own
computer that only your user account can write to, not a shared, network or
synced (OneDrive, Google Drive, Dropbox) folder, and watch only while you need
it. What limits the damage:

- Nothing is signed until you press **Start watching** and enter the PIN. The
  token then stays logged in (for a key that asks for the PIN on every
  signature, the PIN is kept in memory to give it each time, and wiped when
  watching stops). A logged-in token accepts any PIN, so while watching, a
  PIN typed anywhere else in the app (signing, batches, the GST portal) is
  checked against a salted hash of the session's PIN, kept in memory only,
  and a wrong one is refused without using up the token's attempts. The PIN
  is never written anywhere.
- Watching stops after the time you choose (1 hour, 8 hours or until
  stopped), when the computer sleeps (unless you turn that off), when you
  quit TrackMy Sign, when the token is removed or the PIN is refused, and when
  the daily limit (200 signed files by default) is reached. The status bar
  and the tray icon show *Watching <folder> — N signed* while it runs, with
  **Stop**; when it stops on its own, the window comes up and says why.
- Each file is signed with a copy of the preset chosen in Settings (reason,
  location, page and box, signature image), saved without any PIN in the
  app's data folder (`watch.json`). Trusted timestamp and LTV are off unless
  you turn them on there; certifying is not offered.

How files are handled:

- A file is picked up once its size has not changed for about 2 seconds and it
  opens as a PDF. Temporary names (`~$…`, `.tmp`, `.part`, `.crdownload`,
  hidden files) and links are left alone; only files directly in the folder
  are looked at, not its subfolders.
- The signed copy goes to the `signed` folder inside it, or a folder of your
  choice outside it (not elsewhere inside it), as `name_signed.pdf`; nothing
  is ever overwritten. The original moves to `done` (turn this off to leave it
  in place; a file whose signed copy is already in the output folder is then
  skipped).
- A file that cannot be signed goes to `failed`, with `name.txt` saying why:
  not a PDF, a password-protected PDF, security settings that do not allow
  signing, or a document certified with no changes allowed. PDFs that already
  carry signatures are signed as usual; their signatures stay valid.
- *Settings → Watch folder* lists the last 200 events (time, file path,
  outcome), kept in `watch-log.json` in the app's data folder.

The command-line tool does the same, for a server or a scanner PC:

```powershell
.\trackmysign.exe watch C:\Scans --out D:\Signed --preset-json preset.json
.\trackmysign.exe watch C:\Scans --reason Approved --pages all --hours 8
```

It asks for the PIN once and runs until Ctrl+C. `--preset-json` takes a preset
as JSON (`{"reason": "Approved", "location": "Chennai", "placement": {"page":
"last", "x": 120, "y": 250, "w": 60, "h": 20}}`, millimetres from the top-left;
also `pages`, `image` with `--image`, `invisible`, `timestamp`, `ltv`, and
`style` as below, with `--seal` when it shows a seal; `--style` replaces it);
`--keep-originals`, `--daily-limit N` (0 for none) and `--hours` work as in
the app.

## Signing history

TrackMy Sign keeps a private log of every signature it makes on your computer:
single documents, batches, every-page and empty-field signatures,
certifications, files signed as `.p7s` or `.p7m`, the watch folder and GST
portal requests, from the app and the command line. **History** (toolbar or
start screen) lists them, newest first,
with the date (IST; the UTC time is in the details), document, action,
certificate and outcome. Search by file name or signer, filter by dates,
source (single, batch, watch folder, GST portal) and outcome, and click an
entry for its details: both files' paths and SHA-256 hashes, the
certificate's issuer, serial number and fingerprint, the pages, reason,
location, certification level, timestamp and LTV, or why it failed, with
*Open signed copy* and *Show in folder*. *Export PDF…* and *Export CSV…* save
the entries shown; the PDF is an A4 "Signing history" for auditors and
includes the integrity check.

Each entry also holds the SHA-256 of the line before it, so an entry changed
or deleted outside TrackMy Sign breaks the chain: *Check log integrity* follows
it through every file and names the line where it breaks. This shows edits
made without recomputing every hash after them; it is not a signature, and
anyone who can write to the folder can delete or rebuild the whole log.

*Settings → Signing history* turns it off (on by default; turning it off or on
is itself noted), keeps entries forever, for 1 year or for 90 days (older
months are deleted, with a note saying how many entries went), and clears it
(after a confirmation; one entry recording the clearing is kept). It never
holds a PIN, a password or anything from inside a document; for a GST portal
request it keeps the PAN and the hash signed, and for text only its SHA-256.
See [PRIVACY.md](PRIVACY.md).

The log is one JSON object per line, one file per month (`2026-10.jsonl`), in
the app's data folder: `%APPDATA%\in.trackmytech.trackmysign\history` on
Windows, `~/Library/Application Support/in.trackmytech.trackmysign/history` on
macOS and `~/.local/share/in.trackmytech.trackmysign/history` (or
`$XDG_DATA_HOME/…`) on Linux. The command-line tool writes to the same log, as
the same user, and reads it:

```powershell
.\trackmysign.exe history                                   # every entry, then the integrity check
.\trackmysign.exe history --since 2026-10-01 --until 2026-10-31 --source watch --outcome failed
.\trackmysign.exe history --search invoice --csv > signed.csv
.\trackmysign.exe history --json                            # entries and integrity check, for scripts
.\trackmysign.exe history --report history.pdf              # the PDF the app exports
```

Dates are days in this computer's time zone. `history` exits with status 2
when the integrity check finds a problem. `--json` prints `schema`
(`"trackmysign-history"`), `schema_version` (1), `generator`, `integrity`
(`entries`, `files`, `problems[]` with `file`, `line`, `seq`, `message`) and
`entries[]`, each with `seq`, `time` (UTC), `action` (`sign`, `sign_pages`,
`sign_field`, `certify`, `portal_sign`, `sign_file`, or the notes `cleared`, `pruned`,
`paused`, `resumed`), `source` (`manual`, `batch`, `watch`, `portal`),
`program`, `input` and `output` (`path`, `sha256`), `origin` and `portal`
(`pan`, `kind`, `data`, `sha256`) for the GST portal, `cert` (`subject`,
`organization`, `issuer`, `serial`, `fingerprint`), `pages`, `field`, `reason`,
`location`, `certify`, `timestamp`, `ltv`, `outcome` (`signed`, `failed`),
`error`, `removed`, and `prev` (the hash of the line before). Fields without a
value are left out.

## Portal signing (GST)

The GST portal (gst.gov.in) signs DSC registrations and returns through a
program on your own computer, normally eMudhra's emSigner: the portal page
connects to `wss://127.0.0.1` on port 1585 (or 2095, 2568, 2868, 4587) and asks
it to sign. TrackMy Sign can answer those requests instead, with the DSC on your
token:

1. *Settings → GST portal signing → Enable portal signing.* TrackMy Sign makes a
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
2. On the portal, choose to sign with DSC as usual. TrackMy Sign comes to the
   front and shows which site asks, the PAN and exactly what will be signed
   (your PAN at DSC registration, a hash of the return when filing). It picks
   the certificate for that PAN when the certificate shows it (CCA rules put a
   hash of the PAN in the certificate), you can choose another, enter the PIN
   and press **Sign**, or **Cancel** (the portal then says "Signing
   Cancelled"). An expired certificate is refused.

TrackMy Sign listens only while it is running, only on `127.0.0.1` (never on the
network), and answers only pages from `https://gst.gov.in` and its
subdomains. If emSigner is running on port 1585, TrackMy Sign takes the next
free port and Settings says so; the portal tries the ports in order, so quit
emSigner to sign with TrackMy Sign. The portal checks the emSigner version it
expects (2.8 when this was written); if it says "Please install and use correct
version of emSigner", change the version in Settings.

So the portal works without opening TrackMy Sign first, *Settings → Background →
Keep running in the background* (on by default once portal signing is on)
makes closing the window leave TrackMy Sign in the system tray (Windows, Linux;
GNOME needs the AppIndicator extension, which Ubuntu has) or the menu bar
(macOS). Its icon shows whether portal signing is on and on which
port, and has **Open TrackMy Sign** and **Quit**; a portal request brings the
window up as usual. *Start TrackMy Sign when I sign in* starts it there at
sign-in, without a window: on Windows an entry under
`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, which the uninstaller
removes; on macOS `~/Library/LaunchAgents/TrackMySign.plist` (turn the option
off before deleting the app, or delete that file); on Linux
`~/.config/autostart/TrackMySign.desktop`. Turning background mode off
also removes the entry.

Browsers:

- **Chrome / Edge** may ask whether gst.gov.in may access apps and services on
  this device (the local network access prompt). Allow it, or the portal cannot
  reach TrackMy Sign.
- **Firefox** uses its own certificate list. Recent versions also trust
  certificates you added to Windows or macOS; if Firefox still refuses the
  connection, set `security.enterprise_roots.enabled` to `true` in
  `about:config`. On Linux the certificate is added to the Firefox profiles
  directly (snap and Flatpak ones included); a profile made later does not
  have it, so turn portal signing off and on again.

*Disable and remove* stops the listener, removes the certificate from your
trusted certificates (Windows and macOS ask again; on Linux from the same
Chrome and Firefox lists) and deletes its files.

MCA21 V3, the Income Tax portal and TRACES (tdscpc.gov.in) are **not**
supported: they use eMudhra's emBridge, whose requests are encrypted with keys
licensed to eMudhra. TRACES and the old MCA V2 forms portal used a
WebSocket protocol like the GST portal's, but the old TRACES site now redirects to
the new one, which signs through emBridge, and MCA V2 no longer accepts
filings, so there is nothing left to connect to. Portal
signing is an independent, interoperable implementation of the local protocol
the GST portal's own JavaScript uses; TrackMy Sign is not affiliated with or
endorsed by GSTN, the GST Council or eMudhra.

## Reporting a problem

When something does not work, a support report tells us what we need:
*Settings → Help & support → Create support report…* in the app (or
*Report a problem* next to an error), or on the command line, also on a server:

```
trackmysign doctor                    # Markdown, with the same data as JSON at the end
trackmysign doctor --json             # only the JSON
trackmysign doctor --include-names    # also holder names, organisations and certificate serials
```

It lists the version and build (direct download or Microsoft Store), the
operating system, WebView version and language, the token drivers found and
whether each loaded (with the error when not), the connected tokens (maker,
model, label, PIN locked or attempts running low), the certificates (holder's
initials, issuer, validity, key, the first 8 characters of the fingerprint),
a settings summary, the GST portal listener's status, the last update check,
the last signing failure and the recent errors the app and the command-line
tool keep in the app's data folder (`support-log.json`, last 200). Your home
folder is shown as `~`, and email addresses, PAN-like codes and long hex
strings are replaced; names, token serial numbers (`--include-serials`) and
folder paths (`--include-paths`) only go in when you tick them. The app shows
the exact text first and sends nothing: copy or save it, then *Open GitHub
issue* opens the bug report form with the version filled in for you to paste
it into. See [PRIVACY.md](PRIVACY.md).

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

- `crates/trackmysign-core` — PDF reader/incremental writer, CMS, PKCS#11 token access
- `crates/trackmysign-cli` — `trackmysign` command
- `crates/portal-bridge` — local signer for the GST portal (TLS identity, trust store, WebSocket listener)
- `apps/desktop` — Tauri desktop app (React + PDF.js front end)
- `PLAN.md` — decisions and roadmap

## Trademarks

TrackMy Sign is an independent open-source project, not affiliated with, endorsed or certified by GSTN, MCA, the CCA or any vendor named here. emSigner, emBridge and eMudhra are trademarks of eMudhra Ltd; ePass2003 (Feitian), ProxKey (Watchdata), SafeNet and Gemalto (Thales), HyperPKI (Hypersecu) and Adobe Acrobat Reader (Adobe) are trademarks of their respective owners and are named only to describe compatibility.

"SignDesk" appears in old commit history as an early working name of this project. It is unrelated to Desk Nine Private Limited (SignDesk, now Melento). See [TRADEMARKS.md](TRADEMARKS.md).

## Project

- [CONTRIBUTING.md](CONTRIBUTING.md) — building, tests, code style, adding a token driver
- [PRIVACY.md](PRIVACY.md) — nothing leaves your computer except optional timestamp/LTV requests and the update check
- [SECURITY.md](SECURITY.md) — reporting vulnerabilities privately
- [CHANGELOG.md](CHANGELOG.md) — changes in each release, also on [sign.rahuldk.in/changelog](https://sign.rahuldk.in/changelog/)

MIT licence, see [LICENSE](LICENSE).
