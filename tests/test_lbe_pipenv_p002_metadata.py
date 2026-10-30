"""P002 public-release-metadata comparison, pure offline T0; no wheel downloads."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.lbe_pipenv_p002_metadata import (
    EXPECTED, SourceMetadataError, _load_regular_json, inspect_metadata_dir,
    inspect_release, main, read_lock,
)

LOCK = ROOT / "ci/lbe-pipenv-p002-metadata-candidates.json"


def metadata(row: dict) -> dict:
    """Fake PyPI release: no actual third-party wheel or package is imported."""
    filename = row["filename"]
    return {
        "info": {"name": row["name"], "version": row["version"],
                 "requires_python": ">=3.10",
                 "requires_dist": ["example-extra>=5; extra == 'tests'"]},
        "urls": [{"filename": filename, "packagetype": "bdist_wheel",
                  "digests": {"sha256": row["sha256"]}, "size": 12345,
                  "yanked": False,
                  "url": "https://files.pythonhosted.org/packages/fake/" +
                         filename}],
    }


class CandidatePublicMetadataT0(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.dir = self.root / "p002-json"
        self.dir.mkdir()
        self.rows = read_lock(LOCK)
        for entry in self.rows:
            (self.dir / (entry["name"] + "-" + entry["version"] + ".json")).write_text(
                json.dumps(metadata(entry)), encoding="utf-8")

    def row(self, name: str) -> dict:
        return next(x for x in self.rows if x["name"] == name)

    def path(self, name: str) -> Path:
        entry = self.row(name)
        return self.dir / (entry["name"] + "-" + entry["version"] + ".json")

    def change(self, name: str, func):
        path = self.path(name)
        obj = json.loads(path.read_text("utf-8"))
        func(obj)
        path.write_text(json.dumps(obj), encoding="utf-8")

    def test_expected_six_versions_and_published_digests_are_exact(self):
        self.assertEqual([x["name"] for x in self.rows], sorted(EXPECTED))
        self.assertEqual(len(self.rows), 6)
        for row in self.rows:
            self.assertEqual((row["version"], row["filename"]),
                             EXPECTED[row["name"]])
            self.assertEqual(len(row["sha256"]), 64)

    def test_frozen_candidate_release_metadata_positive_no_closure_claim(self):
        out = inspect_metadata_dir(LOCK, self.dir)
        self.assertEqual(out["candidate_release_count"], 6)
        self.assertEqual(out["status"],
                         "PYPI_DECLARED_METADATA_MATCHED_CANDIDATE_ONLY")
        self.assertFalse(out["pipenv_recursive_closure_qualified"])
        self.assertFalse(out["new_third_party_wheel_bytes_downloaded"])
        self.assertFalse(out["new_third_party_wheels_installed_or_imported"])
        self.assertEqual(out["Go_or_Pipenv_native_T1"], "NOT_RUN")
        self.assertEqual(out["independent_BC_source_review"], "NOT_ISSUED")

    def test_unexpected_metadata_sha_rejects_even_for_existing_release(self):
        self.change("virtualenv", lambda r: r["urls"][0]["digests"].update(
            {"sha256": "0" * 64}))
        with self.assertRaisesRegex(SourceMetadataError, "digest"):
            inspect_metadata_dir(LOCK, self.dir)

    def test_wrong_version_rejects(self):
        self.change("virtualenv", lambda r: r["info"].update(
            {"version": "21.15.1"}))
        with self.assertRaisesRegex(SourceMetadataError, "identity"):
            inspect_metadata_dir(LOCK, self.dir)

    def test_extra_json_file_rejects(self):
        (self.dir / "surprise.json").write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(SourceMetadataError, "missing/extra"):
            inspect_metadata_dir(LOCK, self.dir)

    def test_symlink_metadata_rejected_without_following(self):
        path = self.path("setuptools")
        other = self.root / "safe.json"
        other.write_bytes(path.read_bytes())
        path.unlink()
        path.symlink_to(other)
        with self.assertRaisesRegex(SourceMetadataError, "path/type/size"):
            inspect_metadata_dir(LOCK, self.dir)

    def test_duplicate_release_json_key_rejects(self):
        path = self.path("distlib")
        path.write_text('{"info":{},"info":{},"urls":[]}', encoding="utf-8")
        with self.assertRaisesRegex(SourceMetadataError, "duplicate JSON"):
            _load_regular_json(path, 4000000)

    def test_non_pypi_url_or_credentials_reject(self):
        self.change("filelock", lambda r: r["urls"][0].update(
            {"url": "https://evil.test/packages/x/" +
                    self.row("filelock")["filename"]}))
        with self.assertRaisesRegex(SourceMetadataError, "official HTTPS"):
            inspect_metadata_dir(LOCK, self.dir)

    def test_yanked_or_oversize_wheel_reject(self):
        row = self.row("platformdirs")
        data = metadata(row)
        data["urls"][0]["yanked"] = True
        with self.assertRaisesRegex(SourceMetadataError, "size/yanked"):
            inspect_release(row, data)
        data["urls"][0]["yanked"] = False
        data["urls"][0]["size"] = 200000000
        with self.assertRaisesRegex(SourceMetadataError, "size/yanked"):
            inspect_release(row, data)

    def test_unrecognized_requires_dist_is_preserved_not_silently_allowed(self):
        self.change("python-discovery", lambda r: r["info"].update(
            {"requires_dist": [
                "new-transitive-package>=999; python_version >= '3.13'"]}))
        result = inspect_metadata_dir(LOCK, self.dir)
        entry = next(x for x in result["entries"]
                     if x["distribution"] == "python-discovery")
        self.assertIn("new-transitive-package>=999; python_version >= '3.13'",
                      entry["requires_dist_raw"])
        self.assertEqual(entry["python313_marker_closure"], "NOT_EVALUATED")
        self.assertFalse(result["pipenv_recursive_closure_qualified"])

    def test_main_writes_private_report_only_and_refuses_overwrite(self):
        with mock.patch.dict(os.environ, {"RUNNER_TEMP": str(self.root)}):
            args = ["--lock", str(LOCK), "--metadata-dir", str(self.dir),
                    "--runner-temp", str(self.root)]
            self.assertEqual(main(args), 0)
            output = self.root / "lbe-p002-public-pypi-metadata-only.json"
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(output.read_text())["Go_or_Pipenv_native_T1"],
                             "NOT_RUN")
            self.assertEqual(main(args), 2)

    def test_missing_json_fails_closed_no_report(self):
        self.path("virtualenv").unlink()
        with mock.patch.dict(os.environ, {"RUNNER_TEMP": str(self.root)}):
            self.assertEqual(main(["--lock", str(LOCK),
                                   "--metadata-dir", str(self.dir),
                                   "--runner-temp", str(self.root)]), 2)
        self.assertFalse(
            (self.root / "lbe-p002-public-pypi-metadata-only.json").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
