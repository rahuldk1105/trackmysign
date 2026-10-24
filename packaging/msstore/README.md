# Microsoft Store

The Microsoft Store edition of TrackMy Sign is an MSIX package of the same
app. Tauri has no MSIX bundler, so the Windows desktop job in
`.github/workflows/ci.yml` builds the app a second time for the Store and packs
it with the Windows SDK:

```
TRACKMYSIGN_STORE=1 npx tauri build --no-bundle --features store   (in apps/desktop)
pwsh packaging/msstore/pack.ps1 -Exe target/release/TrackMySign.exe -Out TrackMySign-windows-x64.msix
```

Every Windows build does this; the package is attached to the release (and to
the `test-build` pre-release) as `TrackMySign-windows-x64.msix`. If only this
step fails, the job still publishes the installer and shows the failure as a
warning.

The package is not signed. Partner Center takes unsigned packages and the
Store signs them with a Microsoft certificate once certification passes
([Store FAQ](https://learn.microsoft.com/en-us/windows/apps/publish/faq/get-started-with-the-microsoft-store),
[code signing options](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options)).
An unsigned package cannot be installed by double-clicking; to try one, turn
on Developer Mode and register the unpacked folder
(`Add-AppxPackage -Register <folder>\AppxManifest.xml`), or sign a copy with a
test certificate whose subject is the `Publisher` below.

## Files

- `AppxManifest.xml.in`: the package manifest. Identity from Partner Center
  (Product management → Product identity):
  - `Package/Identity/Name`: `TrackMyTech.TrackMySign`
  - `Package/Identity/Publisher`: `CN=84F6D874-B94E-4E3F-BC9F-B3CF100CD932`
  - `Package/Properties/PublisherDisplayName`: `TrackMy Tech`
  - `DisplayName`: `TrackMy Sign`, the name reserved in Partner Center. To
    also show up as "TrackMySign", reserve that name too (Product management →
    Product identity → Reserve more names); the manifest can only use reserved
    names.
- `manifest.py`: `fill` writes the manifest with the version of
  `tauri.conf.json` as `X.Y.Z.0` (the Store keeps the last part at 0);
  `check` looks for placeholders, the version format and missing images.
  makeappx validates the manifest against the Windows SDK schemas when it packs.
  Tests: `python3 -m unittest discover -s packaging/msstore` (CI runs them).
- `assets.py`: `logos` renders `apps/desktop/src-tauri/icons/logo.svg` into
  `Assets/` (committed; run it again after the logo changes; needs cairosvg and
  Pillow). `screenshots DIR` converts the website's app screenshots to PNG for
  the Store listing.
- `pack.ps1`: lays out the package (exe, `Assets/`, manifest), builds
  `resources.pri` (makepri, so the taskbar picks the `targetsize-*` icons) and
  packs it with makeappx.

## How the Store edition differs

Built with the `store` cargo feature and `TRACKMYSIGN_STORE=1` for the front
end. Without them (the installer, the macOS and Linux builds) none of this is
compiled in.

- **Updates** come from the Store. The in-app updater is not registered,
  Settings has no Updates section and About says "Updated through the
  Microsoft Store".
- **Start at sign-in** (Settings → Background) turns the package's
  StartupTask (`TrackMySignStartup`) on and off instead of writing the Run key,
  which a packaged app cannot use. Windows starts the app without arguments;
  the app tells a start at sign-in from its activation kind and starts in the
  tray as usual. If the user turned it off in Windows Settings → Apps →
  Startup, only they can turn it on again there; the app says so.
- **Explorer**: PDFs get TrackMy Sign under "Open with" (the file type
  association in the manifest); the default PDF app is not changed. The
  right-click "Sign with TrackMy Sign" entry of the installer is not there:
  the installer writes it, and the package has no installer.
- **App data** (settings, recent files, signing history, presets, the portal
  CA) is written under `%APPDATA%\in.trackmytech.trackmysign` as usual, which
  Windows redirects into the package's private copy of AppData. It works the
  same for the app, but other programs, including the `trackmysign`
  command-line tool, see the real folder, so the CLI does not see the Store
  app's history. Uninstalling the Store app deletes that data. Files that an
  installer version left in the real folder are still read.
- Nothing is written into the install folder, which is read-only in a package.
  Signed PDFs go next to the original or to the chosen folder as usual.
- **GST portal signing** adds its CA with `certutil -user -addstore Root`
  like the installer version. This needs checking on a real install, see
  below.
- The app needs the WebView2 runtime, which Windows 11 and current Windows 10
  have; unlike the installer, the package cannot install it.
- Installed side by side with the installer version, both are one app to
  Windows' single-instance check: starting one while the other runs hands the
  files over to the running one.

## First submission in Partner Center

Partner Center: <https://partner.microsoft.com/dashboard/apps-and-games/overview>,
the product reserved as "TrackMy Sign".

1. Get the package: `TrackMySign-windows-x64.msix` from the GitHub release
   (or from `test-build` for a first try).
2. **Pricing and availability**: Markets: all (or India only); Visibility:
   Public; Pricing: Free; no free trial.
3. **Properties**:
   - Category: Productivity (or Business); no subcategory needed.
   - Privacy policy URL: <https://github.com/rahuldk1105/trackmysign/blob/main/PRIVACY.md>
   - Website: <https://sign.rahuldk.in>
   - Support contact: <https://github.com/rahuldk1105/trackmysign/issues>
   - Product declarations: leave the defaults; the app does not need
     Windows "accessibility" or "pen" declarations.
   - System requirements: optionally note under Hardware "A USB DSC token
     with its vendor's driver installed".
4. **Age ratings**: fill the IARC questionnaire as an app (not a game),
   "no" to every content question. The app has no user-to-user communication,
   no purchases and shares no location. Expect "3+ / Everyone".
5. **Packages**: upload the `.msix`. Partner Center reads the identity,
   version (`X.Y.Z.0`), `Windows.Desktop` 10.0.17763.0 or later, x64. It
   rejects the upload if the identity does not match the product.
6. **Store listings** → English (United States) (Hindi and Tamil listings are
   optional; the app itself follows the Windows language):
   - Description:

     > TrackMy Sign signs PDF documents with the Digital Signature Certificate
     > (DSC) on your USB token. Open a PDF, place the signature, enter the
     > token PIN and save a signed copy. The PIN and the private key never leave
     > the token.
     >
     > Signatures are added as an incremental update, so the original bytes and
     > any signatures already on the document stay valid. TrackMy Sign also
     > verifies signatures and writes verification reports, signs many PDFs at
     > once or a watched folder, adds timestamps and long-term validation data,
     > signs other files as .p7s/.p7m, and can sign GST portal returns with
     > your DSC.
     >
     > Works with the tokens sold in India (ePass2003, ProxKey, HyperPKI,
     > SafeNet and others) through their PKCS#11 driver. Free and open source
     > (MIT).
   - What's new in this version: the release notes.
   - Product features (one per line): Sign PDFs with your USB DSC token ·
     Keeps existing signatures valid · Verify signatures and export a report ·
     Batch and watch-folder signing · Timestamps and long-term validation ·
     GST portal signing · English, Hindi and Tamil.
   - Screenshots (1366×768 or larger, up to 3840×2160): run
     `python3 packaging/msstore/assets.py screenshots shots/` and upload
     `shots/app-light.png` and `shots/app-dark.png` (2560×1600).
   - Short description: Sign PDFs with the DSC on your USB token.
   - Search terms: DSC, digital signature, PDF sign, USB token, GST.
   - Copyright: Copyright (c) 2026 DK Rahul. Additional license terms: MIT,
     <https://github.com/rahuldk1105/trackmysign/blob/main/LICENSE>.
7. **Submission options**:
   - Restricted capabilities, `runFullTrust`, paste:

     > TrackMy Sign is a desktop app that loads the user's USB DSC token
     > PKCS#11 driver (the vendor DLL installed with the token) to sign PDF
     > documents with the certificate on the token. Loading that native driver
     > needs a full-trust desktop process.
   - Notes for certification:

     > Signing needs a USB DSC token, which testers will not have. Without one
     > the app opens and displays PDFs, verifies existing signatures (open a
     > signed PDF; the Signatures panel shows the result) and shows Settings.
     > The app starts from the Start menu; closing the window keeps it in the
     > tray only when "Keep running in the background" is on.
8. Submit for certification. After it is published, later versions are an
   update submission with the new `.msix` (each version must be higher).

## Not verified yet

These need a Windows machine with the package installed (Developer Mode,
`Add-AppxPackage -Register`):

- The pack step itself (it only runs on the Windows runner).
- Start at sign-in through the StartupTask, and that a start at sign-in opens
  in the tray.
- GST portal signing: that the CA added by `certutil -user -addstore Root`
  from inside the package lands in the real user store (check with
  `certutil -user -store Root` from an ordinary command prompt, and that the
  browser accepts the portal connection). If Windows keeps it in the
  package's private registry, exclude the store from registry virtualization
  in the manifest (`virtualization:RegistryWriteVirtualization` with the
  excluded key `HKEY_CURRENT_USER\Software\Microsoft\SystemCertificates`, which
  needs the `unvirtualizedResources` restricted capability).
- Opening PDFs through "Open with", one and several at a time.
