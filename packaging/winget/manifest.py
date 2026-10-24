"""winget manifests for TrackMySign (microsoft/winget-pkgs, schema 1.12.0).

Usage:
  python3 packaging/winget/manifest.py generate --version 0.5.0 \
      (--sha256 HEX | --installer TrackMySign-Setup-windows-x64.exe) \
      [--url URL] [--release-date 2026-10-24] [--out packaging/winget/manifests]
  python3 packaging/winget/manifest.py validate [DIR ...]

generate writes the three files winget-pkgs expects (version, en-US default
locale, installer) to <out>/t/TrackMyTech/TrackMySign/<version>/. The URL
defaults to the Windows installer of the GitHub release v<version>.

validate checks every version folder under DIR (default: the manifests in this
directory) against the official JSON schemas in schemas/ and checks that the
files agree with each other and with their path. Needs PyYAML and jsonschema.

The uninstall entry is the one Tauri's NSIS installer writes for a per-user
install (tauri-bundler, nsis/installer.nsi): the key
HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\<productName>, with
DisplayName = productName and Publisher = bundle.publisher. Its key name is
what winget calls the ProductCode.
"""
import argparse
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
TAURI_CONF = os.path.join(ROOT, "apps", "desktop", "src-tauri", "tauri.conf.json")

MANIFEST_VERSION = "1.12.0"
IDENTIFIER = "TrackMyTech.TrackMySign"
LOCALE = "en-US"
REPO = "https://github.com/rahuldk1105/trackmysign"
INSTALLER_ASSET = "TrackMySign-Setup-windows-x64.exe"

DESCRIPTION = """\
TrackMySign signs PDF documents with the Digital Signature Certificate (DSC) on a USB token, through the token's PKCS#11 driver. Open a PDF, place the signature, enter the token PIN and save a signed copy; the PIN and the private key never leave the token.
Signatures are added as an incremental update, so the original bytes and any signatures already on the document stay valid. It also verifies signatures, signs batches and watched folders, adds timestamps and long-term validation data, and can sign returns on the GST portal.
Free and open source (MIT)."""

TAGS = [
    "digital-signature",
    "dsc",
    "esign",
    "gst",
    "india",
    "pdf",
    "pdf-signing",
    "pkcs11",
    "usb-token",
]


def tauri_conf():
    with open(TAURI_CONF, encoding="utf-8") as f:
        return json.load(f)


def package_dir(out, version):
    publisher, package = IDENTIFIER.split(".", 1)
    return os.path.join(out, publisher[0].lower(), publisher, package, version)


def installer_url(version):
    return f"{REPO}/releases/download/v{version}/{INSTALLER_ASSET}"


def manifests(version, url, sha256, release_date=None):
    """The three manifests as (file name, schema type, ordered fields)."""
    conf = tauri_conf()
    product = conf["productName"]
    common = [("PackageIdentifier", IDENTIFIER), ("PackageVersion", version)]
    tail = [("ManifestVersion", MANIFEST_VERSION)]

    installer = common + [
        ("InstallerLocale", LOCALE),
        ("InstallerType", "nullsoft"),
        # bundle.windows.nsis.installMode = currentUser: no elevation, HKCU.
        ("Scope", "user"),
        ("InstallModes", ["interactive", "silent", "silentWithProgress"]),
        # /S is NSIS's own silent switch; /P is Tauri's passive mode (progress only).
        ("InstallerSwitches", [("Silent", "/S"), ("SilentWithProgress", "/P")]),
        # The installer replaces an older version in place.
        ("UpgradeBehavior", "install"),
        ("FileExtensions", ["pdf"]),
        ("ProductCode", product),
    ]
    if release_date:
        installer.append(("ReleaseDate", release_date))
    installer += [
        ("AppsAndFeaturesEntries", [[
            ("DisplayName", product),
            ("Publisher", conf["bundle"]["publisher"]),
            ("ProductCode", product),
        ]]),
        ("InstallationMetadata", [("DefaultInstallLocation", "%LocalAppData%\\" + product)]),
        ("Installers", [[
            ("Architecture", "x64"),
            ("InstallerUrl", url),
            ("InstallerSha256", sha256.upper()),
        ]]),
        ("ManifestType", "installer"),
    ] + tail

    locale = common + [
        ("PackageLocale", LOCALE),
        ("Publisher", "TrackMy Tech Private Limited"),
        ("PublisherUrl", conf["bundle"]["homepage"]),
        ("PublisherSupportUrl", f"{REPO}/issues"),
        ("PrivacyUrl", f"{REPO}/blob/main/PRIVACY.md"),
        ("Author", "DK Rahul"),
        ("PackageName", product),
        ("PackageUrl", REPO),
        ("License", conf["bundle"]["license"]),
        ("LicenseUrl", f"{REPO}/blob/main/LICENSE"),
        ("Copyright", conf["bundle"]["copyright"]),
        ("ShortDescription", "Sign PDFs with the Digital Signature Certificate (DSC) on your USB token."),
        ("Description", DESCRIPTION),
        ("Moniker", product.lower()),
        ("Tags", TAGS),
        ("ReleaseNotesUrl", f"{REPO}/releases/tag/v{version}"),
        ("ManifestType", "defaultLocale"),
    ] + tail

    version_manifest = common + [
        ("DefaultLocale", LOCALE),
        ("ManifestType", "version"),
    ] + tail

    return [
        (f"{IDENTIFIER}.yaml", "version", version_manifest),
        (f"{IDENTIFIER}.locale.{LOCALE}.yaml", "defaultLocale", locale),
        (f"{IDENTIFIER}.installer.yaml", "installer", installer),
    ]


# ---- YAML output. The manifests only hold strings, lists and mappings, so a
# small writer is enough and keeps the script free of dependencies.

PLAIN = re.compile(r"[A-Za-z0-9/][A-Za-z0-9 ._/:%\\()+,-]*")
NOT_PLAIN = re.compile(
    r"[-+]?(\d[\d_]*)?(\.\d*)?([eE][-+]?\d+)?|\d{4}-\d\d-\d\d|"
    r"(?i:y|n|yes|no|on|off|true|false|null|~)"
)


def scalar(s):
    if PLAIN.fullmatch(s) and not NOT_PLAIN.fullmatch(s) and ": " not in s and not s.endswith(":"):
        return s
    return "'" + s.replace("'", "''") + "'"


def emit(fields, indent=0):
    pad = " " * indent
    out = []
    for key, value in fields:
        if isinstance(value, str) and "\n" in value:
            out.append(f"{pad}{key}: |-")
            out += [f"{pad}  {line}" if line else "" for line in value.split("\n")]
        elif isinstance(value, str):
            # Dates stay plain, as in winget-pkgs.
            text = value if key == "ReleaseDate" else scalar(value)
            out.append(f"{pad}{key}: {text}")
        elif value and isinstance(value[0], str):
            out.append(f"{pad}{key}:")
            out += [f"{pad}- {scalar(v)}" for v in value]
        elif value and isinstance(value[0], list):
            out.append(f"{pad}{key}:")
            for item in value:
                lines = emit(item, indent + 2)
                lines[0] = f"{pad}- " + lines[0][indent + 2:]
                out += lines
        else:
            out.append(f"{pad}{key}:")
            out += emit(value, indent + 2)
    return out


def render(schema_type, fields):
    head = [
        "# Created with packaging/winget/manifest.py",
        f"# yaml-language-server: $schema=https://aka.ms/winget-manifest.{schema_type}.{MANIFEST_VERSION}.schema.json",
        "",
    ]
    return "\n".join(head + emit(fields)) + "\n"


def generate(version, url, sha256, out, release_date=None):
    if not re.fullmatch(r"[0-9A-Fa-f]{64}", sha256):
        raise SystemExit(f"not a SHA-256: {sha256}")
    folder = package_dir(out, version)
    os.makedirs(folder, exist_ok=True)
    for name, schema_type, fields in manifests(version, url, sha256, release_date):
        with open(os.path.join(folder, name), "w", encoding="utf-8", newline="\n") as f:
            f.write(render(schema_type, fields))
    return folder


# ---- Validation

def load_yaml(path):
    import yaml

    class Loader(yaml.SafeLoader):
        pass

    # Keep dates as strings: the schemas declare ReleaseDate as a string.
    Loader.yaml_implicit_resolvers = {
        k: [(tag, rx) for tag, rx in v if tag != "tag:yaml.org,2002:timestamp"]
        for k, v in yaml.SafeLoader.yaml_implicit_resolvers.items()
    }
    with open(path, encoding="utf-8") as f:
        return yaml.load(f, Loader=Loader)


def validate_folder(folder):
    """Errors for one <version> folder; empty if it is a valid submission."""
    import jsonschema

    errors = []
    files = sorted(os.listdir(folder))
    docs = {}
    for name in files:
        if not name.endswith(".yaml"):
            errors.append(f"{name}: unexpected file")
            continue
        doc = load_yaml(os.path.join(folder, name))
        kind = doc.get("ManifestType") if isinstance(doc, dict) else None
        if kind not in ("version", "defaultLocale", "locale", "installer"):
            errors.append(f"{name}: unknown ManifestType {kind!r}")
            continue
        version = doc.get("ManifestVersion")
        schema_path = os.path.join(HERE, "schemas", f"manifest.{kind}.{version}.json")
        if not os.path.exists(schema_path):
            errors.append(f"{name}: no schema for {kind} {version}")
            continue
        with open(schema_path, encoding="utf-8") as f:
            schema = json.load(f)
        checker = jsonschema.Draft7Validator(schema, format_checker=jsonschema.FormatChecker())
        for e in checker.iter_errors(doc):
            where = "/".join(str(p) for p in e.absolute_path) or "(root)"
            errors.append(f"{name}: {where}: {e.message}")
        docs[kind] = (name, doc)

    for kind in ("version", "defaultLocale", "installer"):
        if kind not in docs:
            errors.append(f"missing {kind} manifest")
    if errors:
        return errors

    identifier = docs["version"][1]["PackageIdentifier"]
    version = docs["version"][1]["PackageVersion"]
    locale = docs["version"][1]["DefaultLocale"]
    for name, doc in docs.values():
        if doc["PackageIdentifier"] != identifier or doc["PackageVersion"] != version:
            errors.append(f"{name}: identifier/version differ from the version manifest")
        if len({d["ManifestVersion"] for _, d in docs.values()}) != 1:
            errors.append("files use different ManifestVersions")
            break
    if docs["defaultLocale"][1]["PackageLocale"] != locale:
        errors.append("defaultLocale manifest is not for DefaultLocale")
    expected = {
        "version": f"{identifier}.yaml",
        "defaultLocale": f"{identifier}.locale.{locale}.yaml",
        "installer": f"{identifier}.installer.yaml",
    }
    for kind, want in expected.items():
        if docs[kind][0] != want:
            errors.append(f"{docs[kind][0]}: should be named {want}")
    parts = identifier.split(".")
    want_tail = [parts[0][0].lower(), *parts, version]
    got_tail = os.path.normpath(folder).split(os.sep)[-len(want_tail):]
    if got_tail != want_tail:
        errors.append(f"folder should end in {'/'.join(want_tail)}")
    for inst in docs["installer"][1]["Installers"]:
        if version not in inst["InstallerUrl"]:
            errors.append(f"installer URL is not version specific: {inst['InstallerUrl']}")
    return errors


def version_folders(root):
    for dirpath, _, filenames in os.walk(root):
        if any(f.endswith(".yaml") for f in filenames):
            yield dirpath


def main(argv):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generate")
    g.add_argument("--version", required=True)
    g.add_argument("--url")
    g.add_argument("--sha256")
    g.add_argument("--installer", help="hash this file instead of passing --sha256")
    g.add_argument("--release-date")
    g.add_argument("--out", default=os.path.join(HERE, "manifests"))
    v = sub.add_parser("validate")
    v.add_argument("dirs", nargs="*", default=[os.path.join(HERE, "manifests")])
    a = p.parse_args(argv)

    if a.cmd == "generate":
        version = a.version.removeprefix("v")
        if a.installer:
            with open(a.installer, "rb") as f:
                sha256 = hashlib.file_digest(f, "sha256").hexdigest()
        elif a.sha256:
            sha256 = a.sha256
        else:
            raise SystemExit("--sha256 or --installer is required")
        print(generate(version, a.url or installer_url(version), sha256, a.out, a.release_date))
        return 0

    failed = False
    count = 0
    for root in a.dirs:
        for folder in version_folders(root):
            count += 1
            errors = validate_folder(folder)
            for e in errors:
                print(f"{folder}: {e}", file=sys.stderr)
            failed |= bool(errors)
    if count == 0:
        print("no manifests found", file=sys.stderr)
        return 1
    if not failed:
        print(f"{count} manifest folder(s) valid (schema {MANIFEST_VERSION})")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
