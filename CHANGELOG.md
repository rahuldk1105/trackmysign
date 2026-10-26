# Changelog

All notable changes to TrackMy Sign are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- TrackMy Sign is on the [Microsoft Store](https://apps.microsoft.com/detail/9NV4G85VML2K). The website and README now point Windows users there first; the direct installer stays available.

- Automatic placement: when a PDF opens, the box goes where the document
  asks for a signature, next to "Authorised Signatory", "For
  <organisation>", the certificate holder's name, "Managing Director",
  "Company Secretary", "Director", "Signature" or "Signed by", on free space
  and away from existing signatures; the last pages and the lowest spot come
  first. The side panel says where (*Placed at "Authorised Signatory"*) and
  **Show other spots** offers the others; the box drags as usual. *Settings →
  Automatic placement* turns it off (on by default) and edits the phrases.
  Presets can place automatically, and batches and the watch folder have
  *Auto (fallback: preset position)*. A scan without text keeps the usual
  box. Command line: `sign --position auto`, `watch --auto-place` (or
  `"auto": true` in the preset JSON) and `info --anchors file.pdf`, which
  lists the phrases found with their boxes. The page text is read by a new
  text reader in the core library (standard and embedded fonts, `/ToUnicode`
  maps, Identity-H, rotated pages).

### Changed

- Website: the features section is grouped (signing, documents and files,
  verification and records, automation, platform and privacy), with a drawing
  and concrete details for each feature, and a new page,
  [sign.rahuldk.in/features](https://sign.rahuldk.in/features/), explains
  every feature at length. Every page now has its own title and description,
  Open Graph and Twitter cards with a social image, structured data
  (software, organisation, FAQ, breadcrumbs), icons and a web app manifest; the
  site has a sitemap, robots.txt and a 404 page. See `website/README.md` for
  what to update on each release.

## [0.6.0] - 2026-10-24

### Added

- Signing history: every signature made on this computer, in the app or on
  the command line (single, batch, every page, empty field, certification,
  `.p7s` / `.p7m` file signatures, watch folder, GST portal), is recorded with
  the time, the original's and the signed copy's paths and SHA-256 hashes,
  the certificate (name, issuer,
  serial number, fingerprint), the options used and the outcome; never a PIN,
  a password or document content. **History** (toolbar or start screen) lists
  it with search and filters (dates, source, outcome), opens a signed copy,
  exports the entries shown as a PDF or CSV and checks the log's hash chain
  (*Check log integrity*). *Settings → Signing history* turns it off, keeps
  entries forever, 1 year or 90 days, and clears it. Kept as one JSON Lines
  file per month in the app's data folder. Command line:
  `trackmysign history [--since DATE] [--until DATE] [--source …] [--outcome …]
  [--search TEXT] [--json | --csv] [--report out.pdf]`, exit status 2 when the
  log was changed.

- Sign any file with the DSC: **Sign other files…** (toolbar, start screen) or
  dropping / opening a file that is not a PDF shows a file panel with each
  file's size, SHA-256 and the `.p7s` already next to it, checked. Signs as a
  standard CMS / PKCS#7 signature, SHA-256, CAdES-BES (contentType,
  signingTime, messageDigest, ESS signingCertificateV2, certificate chain):
  a detached `<file>.p7s` next to the file, or an attached `<file>.p7m` with
  the file inside; optional RFC 3161 timestamp; one PIN for several files. A
  `.p7s` / `.p7m` opened is checked like a PDF signature (chain to CCA India),
  and **Save original…** writes the file inside a `.p7m`. Command line:
  `sign-file FILE... [--attached] [--out PATH] [--timestamp [URL]] [--force]`
  and `verify-file FILE [--sig FILE.p7s] [--extract [--out PATH]]` (reads DER,
  PEM, Base64 and BER signatures, as other tools write them).

- Page tools to prepare a document before signing: **Pages** in the toolbar
  shows the pages as thumbnails to drag into order, turn, delete, insert blank
  pages and append other PDFs (**Add PDF…**), with undo; **Save as…** writes a
  new PDF (`name_prepared.pdf` by default) and opens it for signing. Command
  line: `trackmysign pages merge|select|rotate|delete|insert-blank … -o
  out.pdf`. The originals are never changed. Page contents, resources,
  inherited sizes and rotation, links, comments and form fields are copied
  (same-named fields renamed); bookmarks are not. Password-protected sources
  are opened with their password and the new file has none. Signatures in a
  source cannot carry over: the app and the command line warn and ask first.

- winget manifests (`TrackMyTech.TrackMySign`) in `packaging/winget`, with a
  generator, validation against the official schemas (run in CI) and a CI job
  that opens the winget-pkgs pull request for each release when the
  `WINGET_TOKEN` secret is set. `winget install --id TrackMyTech.TrackMySign`
  works once the package is approved.

- Microsoft Store package: every Windows build also makes
  `TrackMySign-windows-x64.msix` (release asset) for Partner Center, from the
  app built with the `store` feature: updated by the Store (no in-app
  updater), start at sign-in through the package's StartupTask, PDFs under
  *Open with*. Manifest, logos, packing script and the submission steps are
  in `packaging/msstore`.

### Changed

- The app is now called **TrackMy Sign**: window title, start screen,
  settings, tray, reports ("Generated by TrackMy Sign"), the application name
  in signatures and PDF properties, Apps & Features, the "Sign with TrackMy
  Sign" menu entry, Finder and the Dock, the Linux menu, installer images and
  the website. File names, the `trackmysign` command, the install folder,
  the app's data folder and the download names stay `TrackMySign`, so
  updates and links keep working.
- The publisher is now TrackMy Tech Private Limited (Apps & Features, the
  programs' file properties, the .deb maintainer). Updating from 0.5.0 keeps
  an install folder chosen back then.
- winget: releases are submitted with the manifests the generator makes
  (`komac submit`), so they carry the new publisher and name.
- Files that are not PDFs, handed over by the system or dropped on the window,
  go to the file panel instead of being left out with a note.

## [0.5.0] - 2026-10-24

### Added

- Signature box designer: *Appearance → Design…* sets the layout (text only,
  image left or above, image only), a company seal or logo right of or behind
  the text (with opacity), the text lines and their order ("Digitally signed
  by", name, "For" organisation from the certificate or typed, role, date in
  one of four formats, reason, location, two lines of your own), font
  (Helvetica, Times, Courier), bold, fixed or fitted size, colour, alignment,
  border, background, padding and a decorative tick, with a preview drawn from
  the signing engine's own layout. Saved with presets and used by the watch
  folder; command line: `--style style.json` and `--seal seal.png` for `sign`
  and `watch`, and `style` in `--preset-json`. Without a design the box is
  unchanged, byte for byte.

- Verify a whole folder: **Verify folder…** (toolbar, start screen, or the
  Signatures panel for the open document's folder) checks every PDF in a
  folder, optionally with subfolders, and lists each file as it is checked:
  all valid, invalid signature, changed after signing, unsigned, unreadable or
  needs a password (one password can be given for all). Filter by problems or
  unsigned files, click one to open it, and export one PDF report for the
  folder or a CSV with a row per signature. Command line:
  `trackmysign verify-folder <folder> [--recursive] [--password P]
  [--report out.pdf] [--csv out.csv] [--json] [--require-signed]`, exit status
  2 when anything signed is not valid or a PDF could not be checked.
- Several PDFs selected in Explorer, Finder or a Linux file manager and opened
  with *Sign with TrackMySign* or *Open With* arrive as one batch instead of one
  file after another. Files that come in within 0.7 s of each other are put
  together (Explorer starts the app once per file); if a batch is already
  loaded, the app asks whether to add them or replace it. Files that are not
  PDFs are left out, with a note. On Windows the menu entry now also shows for
  more than 15 selected PDFs (up to 100).
- Watch folder: *Settings → Watch folder* signs every PDF put into a folder
  you choose, with a copy of a saved preset, after you press *Start watching*
  and enter the PIN once. Signed copies go to its `signed` folder (or one you
  pick outside it) and are never overwritten; originals move to `done`; files
  that cannot be signed go to `failed` with a `.txt` saying why. A file is
  picked up once it has stopped changing and opens as a PDF; temporary files
  are left alone. Watching stops after 1 or 8 hours (or when stopped), when the
  computer sleeps, on quit, when the token is removed or the PIN refused, and
  at a daily limit (200 files by default). The status bar and the tray show
  *Watching <folder> — N signed* with *Stop*, and Settings lists the last 200
  files. Anyone who can write to the folder while watching can get documents
  signed with your DSC, so use a private folder (see the README).
- `trackmysign watch <FOLDER> [--out DIR] [--preset-json FILE] [--pages …]`
  does the same from the command line, asking for the PIN once and running
  until Ctrl+C.

### Changed

- Text in the signature box that the standard PDF fonts cannot show (Hindi,
  Tamil and other Indian scripts) is transliterated instead of printed as `?`.

## [0.4.0] - 2026-10-24

### Added

- Signature verification report for auditors: **Export report…** in the
  Signatures panel, or `trackmysign verify file.pdf --report report.pdf`,
  saves an A4 PDF with the file's SHA-256, the time of the check (IST and UTC),
  a summary line and every signature's details, and says what is not checked
  (revocation, timestamp tokens). `trackmysign verify --json` prints the
  result as JSON with a documented schema.
- Recent files: the last 10 PDFs you opened are listed on the start screen and
  under the arrow next to *Open…*, with their folder and date; files signed in
  the app are marked and their signed copy opens with one click. Files that no
  longer exist drop out. The list is kept in the app's data folder; turn it off
  or clear it under *Settings → Recent files*.
- The Open dialog, and *Add files…* for a batch, start in the folder of the
  PDF you opened last.
- *Settings → Save signed copies to*: next to the original (as before) or a
  folder you choose, for single and batch signing. An existing file is never
  overwritten; the copy becomes `name_signed_2.pdf`, `name_signed_3.pdf`, ….
- Run in the background: with *Settings → Background → Keep running in the
  background* (on by default when GST portal signing is on), closing the window
  keeps TrackMySign in the system tray (Windows) or menu bar (macOS), so the GST
  portal can sign without the app being opened first. The tray menu shows the
  portal signing status and has *Open TrackMySign* and *Quit*. *Start
  TrackMySign when I sign in* starts it there at sign-in, without a window; the
  Windows uninstaller removes that entry. Launching the app again, or opening a
  PDF with it, brings the window back.
- Certificate details: *Details* next to the certificate picker (or
  *Certificate details* under the signer and in *Settings → DSC token*) shows
  the holder, organisation, PAN hash (subject serial number), email, issuing
  CA, serial number, validity with days left, key type and size, key usage,
  certificate policies (India PKI Class 1/2/3 and eKYC named), SHA-1 and
  SHA-256 fingerprints to copy, and the chain up to the CCA India root. The
  public certificate can be saved as `.cer` (DER), `.pem`, or with its chain
  as `.p7b`. On the command line: `trackmysign certs --details`, and
  `trackmysign certs --export N [--pem | --chain] [--out FILE]`.
- Linux (x86_64): the desktop app as an AppImage and a .deb, and the
  command-line tool as `trackmysign-linux-x64`. Token drivers are found in the
  usual Linux folders (HyperPKI, ePass2003, ProxKey, mToken CryptoID, SafeNet,
  IDPrime, Bit4id, OpenSC, and the p11-kit proxy when nothing else is
  installed). PDFs open with *Open With → TrackMySign* without changing the
  default viewer, the in-app updater updates the AppImage and the .deb, and
  GST portal signing adds its certificate to Chrome's and Firefox's
  certificate lists (needs `certutil` from the NSS tools). Running in the
  background puts TrackMySign in the system tray there too (GNOME needs the
  AppIndicator extension, which Ubuntu has).
- The desktop app in Hindi and Tamil. It follows the system language; choose
  System, English, हिन्दी or தமிழ் under *Settings → Appearance → Language*.
  The signature box in the PDF stays in English.

### Changed

- Internal crates renamed to `trackmysign-core` and `trackmysign-cli`; README,
  website footer and TRADEMARKS.md now carry a trademark and non-affiliation
  notice. ("SignDesk" in old history was an early working name, unrelated to
  Desk Nine Private Limited / Melento.)

## [0.3.0] - 2026-10-24

### Added

- GST portal signing: the GST portal (gst.gov.in) can sign DSC registrations
  and returns with your DSC through TrackMySign instead of emSigner. Turn it on
  under *Settings → GST portal signing*; it adds a certificate for `127.0.0.1`
  to your trusted certificates (Windows or macOS asks you first), listens on
  this computer only, answers only gst.gov.in pages, and shows every request
  for approval with your PIN. *Disable and remove* takes the certificate out
  again. MCA21 V3 and Income Tax are not supported.

### Security

- The updater no longer includes the zip extractor (RUSTSEC-2026-0367,
  RUSTSEC-2026-0368, RUSTSEC-2026-0369); updates are an installer on Windows
  and a .tar.gz on macOS.

## [0.2.0] - 2026-10-24

### Added

- More token drivers detected automatically on Windows and macOS: Feitian
  ePass2003, Watchdata ProxKey, Trust Key, Longmai mToken CryptoID, Watchdata,
  SafeNet eToken, Gemalto IDPrime, Bit4id and OpenSC, alongside HyperPKI. Every
  installed driver is loaded, certificates from all of them are listed, and
  Settings shows which drivers were found. `TRACKMYSIGN_PKCS11_MODULE` accepts a
  list of drivers.
- Signature verification: a Signatures panel in the app and a new
  `trackmysign verify` command check every signature in a PDF, show the signer,
  issuer and certificate chain, and report what was changed after each signature.
- Sign every page, or a page range: one signature with the box shown on each
  selected page (`--pages all`, `--pages 1-3,5`; *Pages* in Placement).
- Optional trusted timestamp (RFC 3161) and long-term validity (OCSP/CRL data
  embedded in the PDF), off by default (`--timestamp`, `--ltv`;
  *Settings → Long-term validity*).
- Right-click a PDF and choose **Sign with TrackMySign** on Windows, or
  **Open With → TrackMySign** on Windows and macOS. The default PDF viewer is not
  changed.
- Presets that save the reason, location and box placement.
- Handwritten signature image (PNG or JPEG) in the signature box, left of the
  text or above it (`--image`, `--image-position`).
- Batch signing: several PDFs with one PIN entry (`trackmysign sign a.pdf b.pdf`).
- DSC expiry reminder: days left are shown wherever certificates are listed.
  The app reminds you 30 days ahead (15, 60 or off in *Settings → Expiry
  reminder*), also when the token is not plugged in, and will not sign with an
  expired certificate. `trackmysign sign` refuses one unless `--allow-expired`.
- Password-protected PDFs (RC4 40/128-bit, AES-128, AES-256) can be opened,
  checked and signed; the signed copy keeps the same password and restrictions.
  PDFs that only restrict editing open without asking; otherwise the app asks
  for the password (`--password` on the command line). It is never stored. A
  PDF whose permissions do not allow signing needs its owner password.
- Sign into empty signature fields already in a PDF (common in bank and
  government forms): the app highlights them and the signature fills the field
  you click; `trackmysign info` lists them and `sign --field NAME` uses one.
  Field locks are recorded in the signature, and a field that demands a format
  TrackMySign cannot produce is refused with an explanation.
- Certification signatures (*Signature type → Certify*, `--certify`): the first
  signature can say what may change afterwards — nothing, form filling and
  signing, or also comments.
- Tokens whose key asks for the PIN on every signature: the PIN is entered once,
  also for batches, and the PIN dialog warns when few attempts are left.
- In-app updates: the app checks GitHub Releases on launch (can be turned off in
  Settings) and installs a new version in one click. Copies installed from
  0.1.x need to install 0.2.0 by hand once.

### Security

- Signature verification checks RSA signatures without the `rsa` crate
  (RUSTSEC-2023-0071).

## [0.1.4] - 2026-10-23

### Security

- Updated tokio to 1.54.1 (RUSTSEC-2026-0384).

### Changed

- Website: removed the macOS "right-click → Open" step, no longer needed now
  that the app is notarized.

## [0.1.3] - 2026-10-23

### Changed

- The macOS app is signed with a Developer ID and notarized by Apple.
- Website: full-width layout, signing-chain and file-structure diagrams, step
  illustrations and an engraved background pattern in the hero.

## [0.1.2] - 2026-10-23

### Changed

- Pitch-black dark mode for the app and the website.

## [0.1.1] - 2026-10-23

### Changed

- Redesigned desktop app, with a flat ink-blue logo and new installer artwork.
- Redesigned website.

### Added

- Code signing policy page on the website.

### Fixed

- Download sizes shown on the website.

## [0.1.0] - 2026-10-23

First release.

### Added

- Signing engine: signs PDFs as an incremental update, so the original bytes
  and earlier signatures stay intact. `adbe.pkcs7.detached` / SHA-256
  signatures that Adobe Reader validates, with a visible "Digitally signed by"
  box or invisible. Reads PDFs with classic or stream cross-reference tables
  and object streams, and repairs broken ones.
- PKCS#11 token access, with the Hypersecu HyperPKI (HYP2003) driver detected
  automatically. The PIN is never stored.
- Command-line tool `trackmysign` with `certs`, `info` and `sign`.
- Desktop app for Windows and macOS: open or drop a PDF, click to place the
  signature box (drag to move or resize, position remembered), pick the
  certificate, set reason and location, enter the PIN; the signed copy is saved
  next to the original as `name_signed.pdf`. Settings for theme (light, dark,
  system), default reason and location.
- Windows installer (no admin rights needed) and a universal macOS dmg for
  Apple Silicon and Intel.
- Website at [sign.rahuldk.in](https://sign.rahuldk.in).
- End-to-end tests with a SoftHSM virtual token, validated with pyHanko and qpdf.

[Unreleased]: https://github.com/rahuldk1105/trackmysign/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/rahuldk1105/trackmysign/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/rahuldk1105/trackmysign/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/rahuldk1105/trackmysign/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/rahuldk1105/trackmysign/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/rahuldk1105/trackmysign/compare/v0.1.4...v0.2.0
[0.1.4]: https://github.com/rahuldk1105/trackmysign/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/rahuldk1105/trackmysign/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/rahuldk1105/trackmysign/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/rahuldk1105/trackmysign/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/rahuldk1105/trackmysign/releases/tag/v0.1.0
