"""Tests for manifest.py. Run: python3 -m unittest discover -s packaging/msstore"""
import json
import os
import shutil
import tempfile
import unittest
import xml.etree.ElementTree as ET

import manifest

NS = manifest.NS


class Manifest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)

    def write(self, text):
        path = os.path.join(self.tmp, "AppxManifest.xml")
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return path

    def test_filled_manifest(self):
        path = self.write(manifest.fill("1.2.3"))
        self.assertEqual(manifest.check(path), [])
        root = ET.parse(path).getroot()
        identity = root.find("f:Identity", NS)
        self.assertEqual(identity.get("Name"), "TrackMyTech.TrackMySign")
        self.assertEqual(identity.get("Publisher"), "CN=84F6D874-B94E-4E3F-BC9F-B3CF100CD932")
        self.assertEqual(identity.get("Version"), "1.2.3.0")
        self.assertEqual(root.findtext("f:Properties/f:DisplayName", namespaces=NS), "TrackMy Sign")
        self.assertEqual(root.findtext("f:Properties/f:PublisherDisplayName", namespaces=NS), "TrackMy Tech")
        app = root.find("f:Applications/f:Application", NS)
        self.assertEqual(app.get("Executable"), "TrackMySign.exe")
        self.assertEqual(app.get("EntryPoint"), "Windows.FullTrustApplication")
        self.assertEqual(app.find("uap:VisualElements", NS).get("DisplayName"), "TrackMy Sign")
        task = app.find("f:Extensions/desktop:Extension/desktop:StartupTask", NS)
        self.assertEqual(task.get("TaskId"), "TrackMySignStartup")
        self.assertEqual(task.get("Enabled"), "false")
        types = app.findall(".//uap:FileTypeAssociation/uap:SupportedFileTypes/uap:FileType", NS)
        self.assertEqual([t.text for t in types], [".pdf"])
        self.assertEqual(root.find("f:Capabilities/rescap:Capability", NS).get("Name"), "runFullTrust")
        family = root.find("f:Dependencies/f:TargetDeviceFamily", NS)
        self.assertEqual((family.get("Name"), family.get("MinVersion")), ("Windows.Desktop", "10.0.17763.0"))
        langs = [r.get("Language") for r in root.findall("f:Resources/f:Resource", NS)]
        self.assertEqual(langs, ["en-US", "hi-IN", "ta-IN"])

    def test_version_defaults_to_the_app(self):
        with open(manifest.TAURI_CONF, encoding="utf-8") as f:
            version = json.load(f)["version"]
        out = os.path.join(self.tmp, "m.xml")
        self.assertEqual(manifest.main(["fill", "--out", out]), 0)
        identity = ET.parse(out).getroot().find("f:Identity", NS)
        self.assertEqual(identity.get("Version"), version + ".0")

    def test_versions(self):
        self.assertEqual(manifest.package_version("v0.5.0"), "0.5.0.0")
        self.assertEqual(manifest.package_version("10.0.65535"), "10.0.65535.0")
        for bad in ["0.5", "0.5.0.1", "0.5.0-beta", "1.65536.0", "x"]:
            with self.assertRaises(SystemExit, msg=bad):
                manifest.package_version(bad)

    def test_every_asset_is_named_and_present(self):
        root = ET.fromstring(manifest.fill("0.5.0").encode())
        named = manifest.images(root)
        self.assertIn("Assets\\Square44x44Logo.png", named)
        for name in named:
            self.assertTrue(os.path.isfile(os.path.join(manifest.HERE, name.replace("\\", os.sep))), name)
        sizes = [n for n in os.listdir(manifest.ASSETS) if n.startswith("Square44x44Logo.targetsize-")]
        self.assertEqual(len(sizes), 5)

    def test_problems_are_reported(self):
        text = manifest.fill("0.5.0")
        self.assertIn("placeholders left", manifest.check(self.write(text.replace("TrackMy Tech<", "@X@<")))[0])
        self.assertIn("not well formed", manifest.check(self.write(text.replace("</Package>", "")))[-1])
        self.assertIn("missing image", "\n".join(manifest.check(self.write(text.replace("StoreLogo.png", "Nope.png")))))
        errors = manifest.check(self.write(text.replace('Version="0.5.0.0"', 'Version="0.5.0.1"')))
        self.assertTrue(any("X.Y.Z.0" in e for e in errors), errors)


if __name__ == "__main__":
    unittest.main()
