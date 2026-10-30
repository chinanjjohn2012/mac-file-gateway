"""PR101 P003 pure fake-wheel T0: no external downloads, installs or imports."""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.lbe_pipenv_p003_wheel_bytes import (
    ByteQualificationError, NoRedirect, _archive_name, _audit_wheel,
    _download_wheel, _official_wheel_url, source_only_main,
)

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "ci/lbe-pipenv-p002-metadata-candidates.json"
FILENAME = "distlib-0.4.4-py2.py3-none-any.whl"
URL = "https://files.pythonhosted.org/packages/fake/" + FILENAME


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fake_wheel(path: Path, *, bad_record: bool = False,
               bad_name: bool = False, symlink: bool = False,
               wrong_metadata: bool = False, bad_package: bool = False,
               case_collision: bool = False) -> tuple[dict, int]:
    prefix = "distlib-0.4.4.dist-info/"
    body_name = "../evil.py" if bad_name else "distlib/__init__.py"
    files = {
        body_name: b"# fake bytes; never imported\n",
        prefix + "METADATA": (
            "Metadata-Version: 2.1\nName: distlib\nVersion: " +
            ("0.4.5" if wrong_metadata else "0.4.4") + "\n\n").encode(),
        prefix + "WHEEL": (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\n"
            b"Tag: py2-none-any\nTag: py3-none-any\n"),
    }
    if bad_package:
        files["different_package/x.py"] = b"recorded but not installed"
    if case_collision:
        files["DISTLIB/__init__.py"] = b"casefold collision"
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")
    for key, payload in files.items():
        value = base64.urlsafe_b64encode(
            hashlib.sha256(payload).digest()).rstrip(b"=").decode()
        if bad_record and key.endswith("__init__.py"):
            value = "0" * 43
        writer.writerow([key, "sha256=" + value, str(len(payload))])
    writer.writerow([prefix + "RECORD", "", ""])
    with zipfile.ZipFile(path, mode="w", compression=zipfile.ZIP_DEFLATED) as wheel:
        for key, payload in files.items():
            if symlink and key == body_name:
                info = zipfile.ZipInfo(key)
                info.create_system = 3
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                wheel.writestr(info, b"target")
            else:
                wheel.writestr(key, payload)
        wheel.writestr(prefix + "RECORD", output.getvalue())
    raw = path.read_bytes()
    return {
        "name": "distlib", "version": "0.4.4",
        "filename": FILENAME, "sha256": digest(raw),
    }, len(raw)


class FakeHTTP(io.BytesIO):
    status = 200

    def __init__(self, payload: bytes, url: str):
        super().__init__(payload)
        self._url = url

    def geturl(self):
        return self._url


class FakeOpener:
    def __init__(self, payload: bytes, result_url: str):
        self.payload = payload
        self.result_url = result_url
        self.calls = 0

    def open(self, req, timeout):
        self.calls += 1
        return FakeHTTP(self.payload, self.result_url)


class WheelByteSourceT0(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve(strict=True)
        self.wheel = self.root / FILENAME

    def test_fake_wheel_sha256_and_all_record_bytes_positive_source_only(self):
        row, size = fake_wheel(self.wheel)
        proof = _audit_wheel(self.wheel, row, size)
        self.assertEqual(proof["actual_sha256"], row["sha256"])
        self.assertGreaterEqual(proof["record_files_verified"], 4)
        self.assertFalse(proof["installed"])
        self.assertFalse(proof["imported"])
        self.assertFalse(proof["executed"])
        self.assertEqual(proof["security_source_review"], "NOT_ISSUED")

    def test_wrong_actual_wheel_hash_fails_before_archive_trust(self):
        row, size = fake_wheel(self.wheel)
        row["sha256"] = "0" * 64
        with self.assertRaisesRegex(ByteQualificationError, "SHA256"):
            _audit_wheel(self.wheel, row, size)

    def test_malformed_record_or_wrong_version_rejected(self):
        for cfg in ({"bad_record": True}, {"wrong_metadata": True}):
            with self.subTest(config=cfg):
                row, size = fake_wheel(self.wheel, **cfg)
                with self.assertRaises(ByteQualificationError):
                    _audit_wheel(self.wheel, row, size)

    def test_traversal_symlink_or_case_conflict_rejected(self):
        for cfg in ({"bad_name": True}, {"symlink": True},
                    {"case_collision": True}):
            with self.subTest(config=cfg):
                row, size = fake_wheel(self.wheel, **cfg)
                with self.assertRaises(ByteQualificationError):
                    _audit_wheel(self.wheel, row, size)

    def test_archive_names_and_https_origin_fail_closed(self):
        for bad in ("../escape", "a/../b", "a//b", "/abs/x",
                    "pkg\\evil.py", "a/\x00b", "a\nb"):
            with self.subTest(bad=bad), self.assertRaises(ByteQualificationError):
                _archive_name(bad)
        for bad in ("http://files.pythonhosted.org/packages/fake/" + FILENAME,
                    "https://evil.example/packages/fake/" + FILENAME,
                    "https://files.pythonhosted.org:444/packages/fake/" + FILENAME,
                    "https://files.pythonhosted.org/packages/../" + FILENAME):
            with self.subTest(bad=bad), self.assertRaises(ByteQualificationError):
                _official_wheel_url(bad, FILENAME)
        _official_wheel_url(URL, FILENAME)
        with self.assertRaises(ByteQualificationError):
            NoRedirect().redirect_request(None, None, 302, "Redirect", {}, URL)

    def test_fake_http_exact_sha_download_no_package_execution(self):
        payload = b"fake HTTP-only bytes"
        opener = FakeOpener(payload, URL)
        _download_wheel(URL, self.wheel, len(payload), digest(payload), opener)
        self.assertEqual(opener.calls, 1)
        self.assertEqual(self.wheel.read_bytes(), payload)
        self.assertEqual(self.wheel.stat().st_mode & 0o777, 0o600)
        self.assertFalse((self.root / "lbe-p003-wheel-byte-evidence.json").exists())

    def test_redirect_mismatch_and_oversize_http_rejected(self):
        data = b"hello"
        opener = FakeOpener(data, "https://evil.example/packages/" + FILENAME)
        with self.assertRaisesRegex(ByteQualificationError, "redirect"):
            _download_wheel(URL, self.wheel, len(data), digest(data), opener)
        self.assertEqual(opener.calls, 1)
        opener2 = FakeOpener(b"larger-than-five", URL)
        with self.assertRaisesRegex(ByteQualificationError, "oversize"):
            _download_wheel(URL, self.wheel, 5, digest(b"hello"), opener2)

    def test_missing_official_release_json_denies_without_fetch_or_report(self):
        with mock.patch.dict(os.environ, {"RUNNER_TEMP": str(self.root)}):
            self.assertEqual(source_only_main([
                "--lock", str(LOCK), "--runner-temp", str(self.root)]), 2)
        self.assertFalse((self.root / "lbe-p003-six-wheel-bytes").exists())
        self.assertFalse(
            (self.root / "lbe-p003-wheel-byte-evidence.json").exists())

    def test_symlink_wheel_and_hardlinked_wheel_rejected(self):
        row, size = fake_wheel(self.wheel)
        other = self.root / "linked.whl"
        os.link(self.wheel, other)
        with self.assertRaisesRegex(ByteQualificationError, "links"):
            _audit_wheel(self.wheel, row, size)
        other.unlink()
        link = self.root / "symlink.whl"
        link.symlink_to(self.wheel)
        with self.assertRaises(ByteQualificationError):
            _audit_wheel(link, row, size)


if __name__ == "__main__":
    unittest.main(verbosity=2)
