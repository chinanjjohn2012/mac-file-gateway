"""P004 source-only fake installed RECORD T0. Never import six external Wheels."""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.lbe_pipenv_p004_import_probe import (
    EXPECTED_IMPORTS, EXISTING_PINNED, P004Error,
    _forbid_external_side_effects, main, verify_installed,
)

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "ci/lbe-pipenv-p002-metadata-candidates.json"
VERSIONS = {
    "distlib": "0.4.4", "filelock": "4.2.4",
    "platformdirs": "4.11.10", "python-discovery": "1.6.1",
    "setuptools": "84.2.1", "virtualenv": "21.15.0",
    "packaging": "26.3",
}


def hash_b64(content: bytes) -> str:
    return base64.urlsafe_b64encode(
        hashlib.sha256(content).digest()).rstrip(b"=").decode("ascii")


def fake_distribution(root: Path, name: str, version: str):
    pkg = name.replace("-", "_")
    module = root / pkg / "__init__.py"
    module.parent.mkdir()
    module.write_bytes(b"# inert fake fixture; never imported\n")
    distinfo = root / (pkg + "-" + version + ".dist-info")
    distinfo.mkdir()
    meta = distinfo / "METADATA"
    meta.write_text("Metadata-Version: 2.1\nName: " + name +
                    "\nVersion: " + version + "\n", encoding="utf-8")
    entries = []
    for path in (module, meta):
        data = path.read_bytes()
        entries.append((path.relative_to(root).as_posix(),
                        "sha256=" + hash_b64(data), str(len(data))))
    entries.append(((distinfo / "RECORD").relative_to(root).as_posix(), "", ""))
    with (distinfo / "RECORD").open("w", newline="", encoding="utf-8") as fp:
        csv.writer(fp).writerows(entries)
    return module, distinfo


class OfflineInstalledSourceT0(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve(strict=True)
        self.site = self.root / "lbe-p004-private-site"
        self.site.mkdir()
        self.files = {
            name: fake_distribution(self.site, name, version)
            for name, version in VERSIONS.items()
        }

    def test_full_fake_seven_installed_records_verify_without_import(self):
        attested = verify_installed(self.site, VERSIONS)
        self.assertEqual(set(attested), set(VERSIONS))
        self.assertTrue(all(v == 2 for v in attested.values()))

    def _record_fake_virtualenv_script(self):
        distinfo = self.files["virtualenv"][1]
        ep = distinfo / "entry_points.txt"
        ep.write_text("[console_scripts]\\nvirtualenv = virtualenv.__main__:run_with_catch\\n".replace("\\n", "\n"),
                      encoding="utf-8")
        script_dir = self.site / "bin"
        script_dir.mkdir()
        script = script_dir / "virtualenv"
        script.write_bytes(b"#!/usr/bin/env python3\\n# never executed\\n".replace(b"\\n", b"\n"))
        record = distinfo / "RECORD"
        with record.open(newline="", encoding="utf-8") as fp:
            entries = list(csv.reader(fp))
        entries.insert(-1, [ep.relative_to(self.site).as_posix(),
                            "sha256=" + hash_b64(ep.read_bytes()),
                            str(ep.stat().st_size)])
        entries.insert(-1, ["../../bin/virtualenv",
                            "sha256=" + hash_b64(script.read_bytes()),
                            str(script.stat().st_size)])
        with record.open("w", newline="", encoding="utf-8") as fp:
            csv.writer(fp).writerows(entries)
        return record

    def test_exact_pip_target_virtualenv_generated_script_is_attested(self):
        self._record_fake_virtualenv_script()
        attested = verify_installed(self.site, VERSIONS)
        self.assertEqual(attested["virtualenv"], 4)

    def test_unlisted_console_script_traversal_is_still_rejected(self):
        record = self._record_fake_virtualenv_script()
        data = record.read_text(encoding="utf-8")
        record.write_text(data.replace("../../bin/virtualenv",
                                       "../../../bin/virtualenv"),
                          encoding="utf-8")
        with self.assertRaisesRegex(P004Error, "traversal"):
            verify_installed(self.site, VERSIONS)

    def test_undeclared_console_script_is_rejected(self):
        self._record_fake_virtualenv_script()
        distinfo = self.files["virtualenv"][1]
        entrypoint = distinfo / "entry_points.txt"
        entrypoint.write_text(
            "[console_scripts]\\nother = other:main\\n".replace("\\n", "\n"),
            encoding="utf-8")
        # Keep the synthetic RECORD valid so this adversarial case reaches
        # the distinct unauthorized-console-entrypoint check.
        record = distinfo / "RECORD"
        with record.open(newline="", encoding="utf-8") as fp:
            rows = list(csv.reader(fp))
        entrypoint_record = entrypoint.relative_to(self.site).as_posix()
        matches = [row for row in rows if row[0] == entrypoint_record]
        self.assertEqual(len(matches), 1)
        matches[0][1] = "sha256=" + hash_b64(entrypoint.read_bytes())
        matches[0][2] = str(entrypoint.stat().st_size)
        with record.open("w", newline="", encoding="utf-8") as fp:
            csv.writer(fp).writerows(rows)
        with self.assertRaisesRegex(P004Error, "not declared"):
            verify_installed(self.site, VERSIONS)

    def test_one_mutated_fake_installed_byte_fails(self):
        module = self.files["distlib"][0]
        module.write_bytes(b"changed after RECORD\n")
        with self.assertRaisesRegex(P004Error, "byte mismatch"):
            verify_installed(self.site, VERSIONS)

    def test_missing_or_extra_distribution_record_fails(self):
        shutil.rmtree(self.files["filelock"][1])
        with self.assertRaisesRegex(P004Error, "distribution count"):
            verify_installed(self.site, VERSIONS)

    def test_symlink_installed_module_fails(self):
        module = self.files["virtualenv"][0]
        other = self.root / "untrusted.py"
        other.write_text("# fake", encoding="utf-8")
        module.unlink()
        module.symlink_to(other)
        with self.assertRaises(P004Error):
            verify_installed(self.site, VERSIONS)

    def test_unexpected_package_identity_fails(self):
        meta = self.files["packaging"][1] / "METADATA"
        meta.write_text("Name: wrong-distribution\nVersion: 26.3\n",
                        encoding="utf-8")
        with self.assertRaises(P004Error):
            verify_installed(self.site, VERSIONS)

    def test_missing_install_root_rejected(self):
        shutil.rmtree(self.site)
        with self.assertRaisesRegex(P004Error, "root invalid"):
            verify_installed(self.site, VERSIONS)

    def test_python_audit_network_and_spawn_tripwire(self):
        for event in ("socket.connect", "socket.bind", "subprocess.Popen",
                      "os.system", "os.execve", "os.posix_spawn",
                      "ctypes.dlopen"):
            with self.subTest(event=event), self.assertRaises(P004Error):
                _forbid_external_side_effects(event, ())
        _forbid_external_side_effects("import", ())

    def test_package_import_list_is_six_only(self):
        self.assertEqual(set(EXPECTED_IMPORTS), set(VERSIONS) - {"packaging"})
        self.assertEqual(EXISTING_PINNED, {"packaging": "26.3"})
        self.assertEqual(EXPECTED_IMPORTS["python-discovery"],
                         "python_discovery")

    def test_missing_p003_real_byte_evidence_stops_before_import(self):
        with mock.patch.dict(os.environ, {"RUNNER_TEMP": str(self.root)}):
            self.assertEqual(main(["--lock", str(LOCK),
                                   "--runner-temp", str(self.root)]), 2)
        self.assertFalse((self.root / "lbe-p004-import-evidence.json").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
