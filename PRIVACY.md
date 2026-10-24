# Privacy

TrackMySign signs PDFs on your own computer. There is no TrackMySign server and
no account, and the project collects nothing about you.

## The app and the command-line tool

**What stays on your computer: everything, by default.** Your PDFs, the signed
copies, your certificate and your token are only ever handled locally. The
private key never leaves the token; the app gives the token a hash to sign
through the driver your token's vendor installed. You can sign with the network
cable unplugged.

**Your PIN is never stored.** It is passed to the token driver for one signing
(or one batch, or one watch-folder session) and then dropped. It is not written to settings, logs or disk.

**No analytics, no telemetry, no crash reports.** The app does not count users,
does not report errors anywhere and has no tracking code.

**Network requests happen only for features you turn on:**

| Feature | Off by default? | What is sent, and to whom |
|---|---|---|
| Trusted timestamp (*Settings → Long-term validity*, CLI `--timestamp`) | Yes | A SHA-256 hash of the signature value, to the timestamp server you choose (DigiCert by default). Not the document, not your PIN. |
| Long-term validity, LTV (*Settings → Long-term validity*, CLI `--ltv`) | Yes | OCSP requests (the issuer's identity and your certificate's serial number), CRL and issuer-certificate downloads, sent to the addresses your Certifying Authority wrote into your certificate. This is the same check Adobe Reader does when it validates a signature online. |
| Update check | Can be turned off in *Settings* | The app checks GitHub Releases for a new version. Nothing about you or your documents is sent; GitHub sees your IP address, as with any download. |

If a timestamp or LTV server cannot be reached, nothing is saved and you can
sign again without it.

**GST portal signing (off by default).** When you turn it on in *Settings*,
the app listens for the GST portal page on `127.0.0.1` only, so nothing on your
network or the internet can connect to it, and it accepts connections only from
pages at `https://gst.gov.in` and its subdomains. Each request is shown to you
and signed only when you enter your PIN; the signature goes back to that
browser page and nowhere else (the portal page then sends it to the GST
portal, as it would with emSigner). The app itself makes no network request
for this. Turning it on keeps a certificate for `127.0.0.1` and its key in the
app's data folder and adds a matching certificate authority, whose private key
was deleted right after use, to your user's trusted certificates; *Disable and
remove* deletes both. A short log of recent portal connections (time, site,
outcome) is kept in memory while the app runs, never on disk.

**Running in the background (off by default, on with GST portal signing).**
With *Settings → Background → Keep running in the background* on, closing the
window leaves the app running in the system tray or menu bar, so the portal
listener keeps answering; *Quit* there stops it. *Start TrackMySign when I sign
in* adds a sign-in entry for the app (Windows: the `Run` key of your user
account; macOS: a LaunchAgent in `~/Library/LaunchAgents`) and nothing else; it
is removed when you turn either option off. Neither sends anything anywhere.

**Watch folder (off until you start it).** *Settings → Watch folder* signs
the PDFs put into a folder you choose, on your computer; nothing is sent
anywhere unless you turn on timestamp or LTV there. The PIN is given to the
token once when you start watching and is never saved; for a key that asks
for it on every signature it is kept in memory until watching stops, then
wiped. The settings (folders, limits and a copy of the chosen preset) are kept
in the app's data folder (`watch.json`), and so is a log of the last 200
events (`watch-log.json`): the time, the file's path, where the signed copy
or the file went, and the outcome or the reason it could not be signed. It
never holds a PIN or anything from inside a document. Files that cannot be
signed are moved to a `failed` folder next to them, with a `.txt` saying why.

Clicking a link in the app (for example to this project's website) opens it in
your browser; the app itself does not load web pages.

**What is saved locally.** Your preferences (default reason and location, saved
presets, the last signature-box position, theme, timestamp and LTV choices, the folder for signed copies) are
kept in the app's own storage on your computer. If you add a handwritten
signature image, a copy is kept in the app's data folder so it can be reused.
None of it is sent anywhere.

**Recent files.** The app keeps a list of the last 10 PDFs you opened in its
data folder (`recent-files.json`): for each, the file's path and name, when you
opened it, its page count and, if you signed it in the app, where the signed
copy was saved. It never holds a PIN, a password or anything from inside a
document, and it stays on your computer. *Settings → Recent files* clears the
list; turning the setting off clears it and stops recording (the Open dialog
then remembers the last folder only until you close the app).

## The website (sign.rahuldk.in)

The website is a static site hosted on GitHub Pages. It has no cookies, no
analytics and no tracking. Besides its own files, it loads only:

- **Google Fonts**: the stylesheet from `fonts.googleapis.com` and the font files
  from `fonts.gstatic.com` (Archivo, IBM Plex Sans, IBM Plex Mono).
- **GitHub API** (`api.github.com`), read-only and without any login:
  - `/repos/rahuldk1105/trackmysign/releases/latest` for the current version
    number and the SHA-256 checksums shown next to the downloads;
  - `/repos/rahuldk1105/trackmysign` for the star count;
  - `/repos/rahuldk1105/trackmysign/releases` on the changelog page, for the
    release notes.

Download buttons link to files on `github.com` (GitHub Releases). Your light or
dark theme choice is saved in your browser's local storage (`tms-theme`) and
never leaves it.

As with any website, GitHub Pages, Google Fonts and the GitHub API receive your
IP address and browser details when your browser contacts them; their own
privacy policies apply to that.

## Questions

Open an issue at
[github.com/rahuldk1105/trackmysign/issues](https://github.com/rahuldk1105/trackmysign/issues).
For anything security-related, see [SECURITY.md](SECURITY.md).
