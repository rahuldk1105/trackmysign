"""AppxManifest.xml of the Microsoft Store (MSIX) package.

Usage:
  python3 packaging/msstore/manifest.py fill [--version 0.5.0] --out AppxManifest.xml
  python3 packaging/msstore/manifest.py check AppxManifest.xml

fill writes the manifest from AppxManifest.xml.in: the Partner Center identity
below and the version (default: tauri.conf.json) as X.Y.Z.0; the Store keeps
the fourth part at 0.

check makes sure the manifest is well formed, holds no placeholder, has an
X.Y.Z.0 version and that every image it names is in Assets/. makeappx
validates it against the Windows SDK's schemas when it packs.
"""
import argparse
import json
import os
import re
import sys
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
TAURI_CONF = os.path.join(ROOT, "apps", "desktop", "src-tauri", "tauri.conf.json")
TEMPLATE = os.path.join(HERE, "AppxManifest.xml.in")
ASSETS = os.path.join(HERE, "Assets")

# Partner Center: Product management -> Product identity.
IDENTITY = {
    "IDENTITY_NAME": "TrackMyTech.TrackMySign",
    "IDENTITY_PUBLISHER": "CN=84F6D874-B94E-4E3F-BC9F-B3CF100CD932",
    "PUBLISHER_DISPLAY_NAME": "TrackMy Tech",
    # Must be a name reserved for the product in Partner Center.
    "DISPLAY_NAME": "TrackMy Sign",
}

NS = {
    "f": "http://schemas.microsoft.com/appx/manifest/foundation/windows10",
    "uap": "http://schemas.microsoft.com/appx/manifest/uap/windows10",
    "desktop": "http://schemas.microsoft.com/appx/manifest/desktop/windows10",
    "rescap": "http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities",
}

def package_version(version):
    """0.5.0 -> 0.5.0.0. Each part is 0..65535."""
    version = version.removeprefix("v")
    m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", version)
    if not m or any(int(p) > 65535 for p in m.groups()):
        raise SystemExit(f"not an X.Y.Z version: {version}")
    return ".".join(str(int(p)) for p in m.groups()) + ".0"


def fill(version):
    with open(TEMPLATE, encoding="utf-8") as f:
        text = f.read()
    values = dict(IDENTITY, VERSION=package_version(version))
    for key, value in values.items():
        text = text.replace(f"@{key}@", value)
    return text


def images(root):
    """Asset paths the manifest names (Logo elements and *Logo attributes)."""
    found = set()
    for el in root.iter():
        if el.tag.endswith("}Logo") and el.text:
            found.add(el.text.strip())
        for name, value in el.attrib.items():
            if name.endswith("Logo"):
                found.add(value)
    return sorted(found)


def check(path):
    errors = []
    with open(path, encoding="utf-8") as f:
        text = f.read()
    left = re.findall(r"@[A-Z_]+@", text)
    if left:
        errors.append(f"placeholders left: {', '.join(sorted(set(left)))}")
    try:
        root = ET.fromstring(text.encode("utf-8"))
    except ET.ParseError as e:
        return errors + [f"not well formed: {e}"]
    identity = root.find("f:Identity", NS)
    if identity is None:
        return errors + ["no Identity"]
    if not re.fullmatch(r"\d+\.\d+\.\d+\.0", identity.get("Version", "")):
        errors.append(f"Identity Version must be X.Y.Z.0: {identity.get('Version')}")
    for name in images(root):
        if not os.path.isfile(os.path.join(HERE, name.replace("\\", os.sep))):
            errors.append(f"missing image {name}")
    return errors


def main(argv):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fill")
    f.add_argument("--version")
    f.add_argument("--out", required=True)
    c = sub.add_parser("check")
    c.add_argument("manifest")
    a = p.parse_args(argv)

    if a.cmd == "fill":
        if a.version:
            version = a.version
        else:
            with open(TAURI_CONF, encoding="utf-8") as conf:
                version = json.load(conf)["version"]
        with open(a.out, "w", encoding="utf-8", newline="\n") as out:
            out.write(fill(version))
        print(a.out)
        return 0

    errors = check(a.manifest)
    for e in errors:
        print(f"{a.manifest}: {e}", file=sys.stderr)
    if not errors:
        print(f"{a.manifest}: OK")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
