# Changelog

All notable changes to TrackMySign are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/rahuldk1105/trackmysign/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/rahuldk1105/trackmysign/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/rahuldk1105/trackmysign/compare/v0.1.4...v0.2.0
[0.1.4]: https://github.com/rahuldk1105/trackmysign/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/rahuldk1105/trackmysign/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/rahuldk1105/trackmysign/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/rahuldk1105/trackmysign/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/rahuldk1105/trackmysign/releases/tag/v0.1.0
