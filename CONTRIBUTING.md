# Contributing to TrackMySign

Thanks for helping. Bug reports, token reports ("my token isn't detected") and
pull requests are all welcome. For anything larger than a small fix, open an
issue first so we can agree on the approach before you spend time on it.

## Repository layout

- `crates/signdesk-core`: the signing engine. Its own PDF reader and incremental
  writer (`pdf/`), CMS signatures (`cms.rs`), PKCS#11 token access (`token.rs`),
  signature verification (`verify.rs`), timestamps and LTV (`tsa.rs`, `ltv.rs`, `http.rs`).
- `crates/signdesk-cli`: the `trackmysign` command (`certs`, `info`, `sign`, `verify`).
- `apps/desktop`: the Tauri desktop app. React + TypeScript + PDF.js in `src/`,
  Tauri commands in `src-tauri/src/lib.rs`.
- `website/`: the static site at [sign.rahuldk.in](https://sign.rahuldk.in) (no build step).
- `tests/`: end-to-end tests with a virtual token.
- `PLAN.md`: decisions and roadmap.

## Building

You need Rust (stable, via [rustup](https://rustup.rs)) and Node.js 20 or newer
(CI uses Node 22).

```sh
git clone https://github.com/rahuldk1105/trackmysign
cd trackmysign
cargo build -p trackmysign                       # command-line tool -> target/debug/trackmysign
cd apps/desktop && npm ci && npx tauri dev       # desktop app with live reload
```

On Linux the desktop app also needs the WebKitGTK development packages, for
example on Ubuntu: `sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev`.
The app is built for Windows, macOS and Linux (`npx tauri build --bundles deb`
makes a .deb locally).

The desktop crate embeds the built front end, so run `npm run build` in
`apps/desktop` once before `cargo clippy` or `cargo test` at the workspace root.

`npm run dev` (Vite alone, no Tauri) opens the front end in a browser with a mock
token (PIN `1234`), which is handy for UI work. Put any PDF at
`apps/desktop/public/sample.pdf` (ignored by git) for it to open.

Please don't run release builds (`npx tauri build`) for a pull request; CI builds
the installers.

## Tests

```sh
cargo test                     # unit tests
cargo build -p trackmysign
tests/run.sh                   # end-to-end, prints "ALL PASSED"
```

`tests/run.sh` creates a SoftHSM2 virtual token that looks like an Indian Class 3
DSC, generates test PDFs (plain, rotated, forms, object streams, broken xref,
already signed by someone else), signs them with the CLI and validates every
result independently with pyHanko and qpdf. The timestamp and LTV tests start a
local TSA, OCSP responder and CRL server (`tests/services.py`), so no internet is
needed.

It needs:

- `softhsm2`, `opensc` (for `pkcs11-tool`), `qpdf`, `poppler-utils` (`pdftoppm`),
  `openssl`, `curl`
- Python 3 with `pip install pyhanko pyhanko-certvalidator reportlab`

On Ubuntu: `sudo apt install softhsm2 opensc qpdf poppler-utils`. SoftHSM's
token directory is usually only writable by the `softhsm` group; either add
yourself to it or run the script as CI does: `sudo -E env "PATH=$PATH" tests/run.sh`.

Set `TRACKMYSIGN_BIN` to test a binary other than `target/debug/trackmysign`, and
`WORK` to keep the generated files in a folder you can inspect.

If you change how PDFs are written, add a fixture to `tests/make_fixtures.py` and
a line to `tests/run.sh` that signs and validates it.

## Code style

CI runs all of these, and a pull request needs them to pass:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cd apps/desktop && npx tsc --noEmit && npx vite build
tests/run.sh
```

Beyond that, match the code around you: the same naming, the same density of
comments (explain why, not what), no new dependency where a few lines will do.
In the UI, keep the existing look: sharp corners, the CSS variables already
defined in `styles.css`, the ink-blue accent in light mode and pitch black in
dark mode.

## Adding a token driver

Most tokens sold in India ship a PKCS#11 driver, so supporting a new one is
usually a one-line change:

1. Find the driver file the vendor installs. On Windows it is a `.dll`, usually in
   `C:\Windows\System32`; on macOS a `.dylib`, often in `/usr/local/lib`; on Linux a
   `.so`, usually in `/usr/lib`. Check that
   it works first:
   `trackmysign --module <path to driver> certs` (or set `TRACKMYSIGN_PKCS11_MODULE`).
2. Add it to `known_locations()` in `crates/signdesk-core/src/token.rs` as
   `(product name, folder, file name)`, in the `#[cfg(windows)]`,
   `#[cfg(target_os = "macos")]` or Linux block. A `*` in the file name matches a version
   number that changes between driver releases (`TRUSTKEYP11*.dll`). Vendor drivers
   go before OpenSC, which stays last.
3. If you used a `*` or the name is close to an existing one, add a case to the
   `driver_file_names` test in the same file.
4. Add a row to the "Supported tokens" table in `README.md`.

Mention in the pull request which token, driver version and operating system you
tested with. If you can't build, open a "Token not detected" issue with the
driver's path instead and it will be added for you.

## Pull requests

- Keep each pull request to one change, with a short description of what and why.
- Say how you tested it, especially with a real token (make, model, OS).
- Add or update tests for behaviour changes; signing changes need an end-to-end
  case in `tests/run.sh`.
- Update `README.md` and the "Unreleased" section of `CHANGELOG.md` when users
  will notice the change.
- Commit messages: a short imperative summary line ("Detect Bit4id drivers on macOS").

## Never commit secrets

Never commit or paste into issues a real DSC certificate (`.cer`, `.pem`, `.pfx`,
`.p12`), a private key, a PIN, or a PDF signed with your real certificate: a
signed PDF contains your full name and certificate details. The tests generate
their own throwaway certificates and keys at run time; use those. When a log or
screenshot shows your name, email, phone number or certificate serial number,
blank it out first.

Security problems go through private reporting, not public issues; see
[SECURITY.md](SECURITY.md).

## Licence

By contributing you agree that your contribution is licensed under the
[MIT licence](LICENSE), like the rest of the project.
