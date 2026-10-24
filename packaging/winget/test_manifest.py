"""Tests for manifest.py. Run: python3 -m unittest discover -s packaging/winget"""
import os
import shutil
import tempfile
import unittest

import manifest

V = "0.5.0"
# SHA-256 of the v0.5.0 release asset TrackMySign-Setup-windows-x64.exe
SHA = "C0919833B197D8E595C3E99D9F9AD55FF257EEC01EBA5B8A483EF91D7689B590"
COMMITTED = manifest.package_dir(os.path.join(manifest.HERE, "manifests"), V)


class Manifests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)

    def generated(self, version=V):
        return manifest.generate(version, manifest.installer_url(version), SHA, self.tmp, "2026-10-24")

    def test_committed_manifests_are_valid(self):
        for folder in manifest.version_folders(os.path.join(manifest.HERE, "manifests")):
            self.assertEqual(manifest.validate_folder(folder), [], folder)

    def test_committed_manifests_match_the_generator(self):
        folder = self.generated()
        self.assertEqual(sorted(os.listdir(folder)), sorted(os.listdir(COMMITTED)))
        for name in os.listdir(folder):
            with open(os.path.join(folder, name)) as a, open(os.path.join(COMMITTED, name)) as b:
                self.assertEqual(a.read(), b.read(), name)

    def test_generated_fields(self):
        folder = self.generated("1.2.3")
        self.assertTrue(folder.endswith(os.path.join("t", "TrackMyTech", "TrackMySign", "1.2.3")))
        self.assertEqual(manifest.validate_folder(folder), [])
        inst = manifest.load_yaml(os.path.join(folder, "TrackMyTech.TrackMySign.installer.yaml"))
        self.assertEqual(inst["PackageVersion"], "1.2.3")
        self.assertEqual(inst["ReleaseDate"], "2026-10-24")
        self.assertEqual(inst["Scope"], "user")
        self.assertEqual(inst["AppsAndFeaturesEntries"][0]["ProductCode"], "TrackMySign")
        self.assertEqual(inst["InstallationMetadata"]["DefaultInstallLocation"], "%LocalAppData%\\TrackMySign")
        self.assertEqual(
            inst["Installers"][0]["InstallerUrl"],
            "https://github.com/rahuldk1105/trackmysign/releases/download/v1.2.3/TrackMySign-Setup-windows-x64.exe",
        )

    def edit(self, folder, name, old, new):
        path = os.path.join(folder, name)
        with open(path) as f:
            text = f.read()
        self.assertIn(old, text)
        with open(path, "w") as f:
            f.write(text.replace(old, new))

    def test_schema_errors_are_reported(self):
        folder = self.generated()
        self.edit(folder, "TrackMyTech.TrackMySign.installer.yaml", "Scope: user", "Scope: everyone")
        self.edit(folder, "TrackMyTech.TrackMySign.locale.en-US.yaml", "License: MIT\n", "")
        errors = "\n".join(manifest.validate_folder(folder))
        self.assertIn("Scope", errors)
        self.assertIn("'License' is a required property", errors)

    def test_inconsistent_files_are_reported(self):
        folder = self.generated()
        self.edit(folder, "TrackMyTech.TrackMySign.installer.yaml", "PackageVersion: 0.5.0", "PackageVersion: 0.5.1")
        errors = manifest.validate_folder(folder)
        self.assertTrue(any("identifier/version differ" in e for e in errors), errors)

    def test_folder_must_match_identifier_and_version(self):
        folder = self.generated()
        moved = os.path.join(self.tmp, "0.5.0")
        shutil.move(folder, moved)
        self.assertTrue(any("folder should end in" in e for e in manifest.validate_folder(moved)))

    def test_scalars_survive_yaml(self):
        for s in ["1.10", "0.5", "yes", "null", "2026-10-24", "a: b", "it's", "#x", "%x%", "/S", "-x", "1e5"]:
            text = manifest.render("version", [("K", s)])
            path = os.path.join(self.tmp, "s.yaml")
            with open(path, "w") as f:
                f.write(text)
            self.assertEqual(manifest.load_yaml(path)["K"], s, text)


if __name__ == "__main__":
    unittest.main()
