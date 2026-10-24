# Security policy

TrackMy Sign handles digital signatures, so security reports are taken seriously
and answered first.

## Supported versions

Only the latest release gets fixes. Releases are small and frequent, and a fix
ships as a new version on the
[releases page](https://github.com/rahuldk1105/trackmysign/releases/latest)
rather than as a patch to an older one.

| Version | Supported |
|---|---|
| Latest 0.1.x release | Yes |
| Older releases | No, please update |

## Reporting a vulnerability

Please **do not open a public issue** for a security problem.

Report it privately through GitHub:
[Report a vulnerability](https://github.com/rahuldk1105/trackmysign/security/advisories/new)
(the *Security* tab of the repository, then *Report a vulnerability*). Only the
maintainer can see the report.

Include what you can of:

- the version and operating system, and the token make and model if it matters;
- what an attacker can do, and the steps or a file that shows it;
- for PDF issues, a sample PDF made with a test certificate.

Never send your real PIN, private key or certificate file, or a document signed
with your real certificate.

You will get an answer within a few days. Once a fix is released, the advisory
is published with credit to you, unless you prefer to stay anonymous.

## What counts

Examples of what to report privately:

- a signature that TrackMy Sign or Adobe Reader shows as valid although the
  document was changed after signing, or `trackmysign verify` accepting a forged
  or altered signature;
- signing that changes or invalidates the bytes of the original document or of
  earlier signatures;
- the PIN being written to disk or logs, or sent anywhere;
- a crafted PDF that makes the app run code, read or write files it should not,
  or sign something other than what was shown;
- network requests the app makes when timestamp, LTV and update checks are off;
- a problem with the published binaries or the release process (see the
  [code signing policy](https://sign.rahuldk.in/code-signing/)).

Crashes on malformed PDFs without any of these effects, and problems inside a
token vendor's own driver, can go to the normal
[issue tracker](https://github.com/rahuldk1105/trackmysign/issues).
