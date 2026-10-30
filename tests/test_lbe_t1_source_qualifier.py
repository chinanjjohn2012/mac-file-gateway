"""Offline T0 for P001 artifact checking. No Go/Pipenv executable is invoked."""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.lbe_t1_source_qualifier import (
    QualificationError, GO_REQUIRED, inspect_go_archive,
    inspect_pipenv_wheel, qualification_main, safe_member_name, verified_file,
)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fake_go(path: Path, *, malicious: str | None = None,
            linked: bool = False) -> bytes:
    with tarfile.open(path, "w:gz") as archive:
        for name in sorted(GO_REQUIRED):
            info = tarfile.TarInfo(name)
            content = b"source-only fake Go fixture"
            if linked and name == "go/bin/go":
                info.type = tarfile.SYMTYPE
                info.linkname = "../escape"
                info.size = 0
                archive.addfile(info)
            else:
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
        if malicious is not None:
            extra = tarfile.TarInfo(malicious)
            extra.size = 1
            archive.addfile(extra, io.BytesIO(b"x"))
    return path.read_bytes()


def fake_wheel(path: Path, *, bad_record: bool = False,
               malicious: str | None = None) -> bytes:
    meta = (
        "Metadata-Version: 2.1\nName: pipenv\nVersion: 2026.10.4\n"
        "Requires-Dist: setuptools>=67\n"
        "Requires-Dist: virtualenv>=20\n\n"
    ).encode()
    files = {
        "pipenv/__init__.py": b"# never imported\n",
        "pipenv-2026.10.4.dist-info/METADATA": meta,
        "pipenv-2026.10.4.dist-info/WHEEL":
            b"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
    }
    if malicious is not None:
        files[malicious] = b"malicious marker"
    record_name = "pipenv-2026.10.4.dist-info/RECORD"
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    for name, content in files.items():
        digest = base64.urlsafe_b64encode(
            hashlib.sha256(content).digest()).rstrip(b"=").decode()
        if bad_record and name == "pipenv/__init__.py":
            digest = "0" * 43
        writer.writerow([name, "sha256=" + digest, str(len(content))])
    writer.writerow([record_name, "", ""])
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as wheel:
        for name, content in files.items():
            wheel.writestr(name, content)
        wheel.writestr(record_name, buf.getvalue())
    return path.read_bytes()


class SourceQualificationT0(unittest.TestCase):
    def test_safe_member_rejects_traversal_absolute_ambiguous(self):
        for name in ("../escape", "/etc/passwd", "go/../escape",
                     "go//bin", "go/./bin", "go\\bin", "", "."):
            with self.subTest(name=name), self.assertRaises(QualificationError):
                safe_member_name(name)
        self.assertEqual(safe_member_name("go/bin/go"), "go/bin/go")

    def test_sha_and_single_regular_file_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            file = root / "go-source"
            file.write_bytes(b"fixture")
            self.assertEqual(verified_file(file, sha(b"fixture"), 7, 100), 7)
            for expected_sha, expected_size in (
                ("0" * 64, 7), (sha(b"fixture"), 8)
            ):
                with self.assertRaises(QualificationError):
                    verified_file(file, expected_sha, expected_size, 100)
            link = root / "link"
            link.symlink_to(file)
            with self.assertRaises(QualificationError):
                verified_file(link, sha(b"fixture"), 7, 100)
            second = root / "hardlink"
            os.link(file, second)
            with self.assertRaises(QualificationError):
                verified_file(file, sha(b"fixture"), 7, 100)

    def test_good_go_archive_inspects_without_running_go(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fake-go.tar.gz"
            data = fake_go(path)
            result = inspect_go_archive(path, sha(data), len(data))
            self.assertEqual(result["status"],
                             "ARCHIVE_BYTES_VERIFIED_MEMBERS_INSPECTED")
            self.assertEqual(result["members"], len(GO_REQUIRED))
            self.assertFalse(result["go_executed"])

    def test_go_archive_traversal_and_link_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "go.tar.gz"
            data = fake_go(path, malicious="../wrong-root")
            with self.assertRaises(QualificationError):
                inspect_go_archive(path, sha(data), len(data))
            data = fake_go(path, linked=True)
            with self.assertRaises(QualificationError):
                inspect_go_archive(path, sha(data), len(data))

    def test_go_mismatched_hash_prevents_archive_inspection(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "go.tar.gz"
            data = fake_go(path)
            with self.assertRaises(QualificationError):
                inspect_go_archive(path, "a" * 64, len(data))

    def test_pipenv_wheel_metadata_and_record_are_verified(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "pipenv.whl"
            data = fake_wheel(path)
            result = inspect_pipenv_wheel(path, sha(data), len(data))
            self.assertEqual(result["status"], "WHEEL_BYTES_AND_RECORD_VERIFIED")
            self.assertIn("setuptools>=67", result["requires_dist"])
            self.assertIn("virtualenv>=20", result["requires_dist"])
            self.assertFalse(result["dependency_closure_locked"])
            self.assertFalse(result["pipenv_executed"])

    def test_pipenv_tampered_record_or_member_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "pipenv.whl"
            data = fake_wheel(path, bad_record=True)
            with self.assertRaises(QualificationError):
                inspect_pipenv_wheel(path, sha(data), len(data))
            data = fake_wheel(path, malicious="../outside")
            with self.assertRaises(QualificationError):
                inspect_pipenv_wheel(path, sha(data), len(data))

    def test_missing_authorized_real_artifacts_fails_closed_no_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with mock.patch.dict(os.environ, {"RUNNER_TEMP": str(root)}):
                self.assertEqual(qualification_main([
                    "--runner-temp", str(root)]), 2)
            self.assertFalse((root / "lbe-p001-source-evidence.json").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
