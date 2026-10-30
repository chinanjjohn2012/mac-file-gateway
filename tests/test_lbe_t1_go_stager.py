"""Go P001 nonexecuting byte-stage T0. Only synthetic tar fixtures."""
from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.lbe_t1_source_qualifier import GO_REQUIRED, QualificationError
from tools.lbe_t1_go_stager import stage_nonexecutable_go


def make_archive(path: Path, *, extra: tuple[str, ...] = (),
                 link: str | None = None) -> bytes:
    with tarfile.open(path, "w:gz") as archive:
        for name in sorted(GO_REQUIRED | frozenset(extra)):
            info = tarfile.TarInfo(name)
            content = ("safe fixture for " + name).encode()
            if link == name:
                info.type = tarfile.SYMTYPE
                info.linkname = "../untrusted"
                archive.addfile(info)
            else:
                info.mode = 0o755 if name.endswith(("/go", "/compile")) else 0o644
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
    return path.read_bytes()


class P001GoStagerT0(unittest.TestCase):
    def test_regular_archive_is_nonexecutable_after_staging(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "fake-go.tar.gz"
            data = make_archive(archive)
            dest = root / "staged"
            evidence = stage_nonexecutable_go(
                archive, dest,
                expected_digest=hashlib.sha256(data).hexdigest(),
                expected_size=len(data))
            self.assertEqual(evidence["status"], "BYTES_STAGED_NONEXECUTABLE")
            self.assertEqual(evidence["file_count"], len(GO_REQUIRED))
            self.assertFalse(evidence["go_binary_executed"])
            self.assertFalse(evidence["go_runtime_approved"])
            self.assertEqual(evidence["source_review"], "NOT_ISSUED")
            for name in GO_REQUIRED:
                staged = dest / name
                self.assertTrue(staged.is_file())
                self.assertEqual(staged.stat().st_nlink, 1)
                self.assertEqual(stat.S_IMODE(staged.stat().st_mode) & 0o111, 0)
                self.assertIn(b"safe fixture", staged.read_bytes())

    def test_archive_sha_mismatch_prevents_creating_staging_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "go.tar.gz"
            content = make_archive(archive)
            dest = root / "staged"
            with self.assertRaises(QualificationError):
                stage_nonexecutable_go(
                    archive, dest, expected_digest="0" * 64,
                    expected_size=len(content))
            self.assertFalse(dest.exists())

    def test_symlink_archive_member_rejected_before_staging(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "go.tar.gz"
            content = make_archive(archive, link="go/bin/go")
            dest = root / "stage"
            with self.assertRaises(QualificationError):
                stage_nonexecutable_go(
                    archive, dest,
                    expected_digest=hashlib.sha256(content).hexdigest(),
                    expected_size=len(content))
            self.assertFalse(dest.exists())

    def test_preexisting_stage_or_symlink_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "go.tar.gz"
            data = make_archive(archive)
            dest = root / "existing"
            dest.mkdir()
            (dest / "sentinel").write_text("keep")
            with self.assertRaises(QualificationError):
                stage_nonexecutable_go(
                    archive, dest,
                    expected_digest=hashlib.sha256(data).hexdigest(),
                    expected_size=len(data))
            self.assertEqual((dest / "sentinel").read_text(), "keep")
            link = root / "stage-link"
            link.symlink_to(dest, target_is_directory=True)
            with self.assertRaises(QualificationError):
                stage_nonexecutable_go(
                    archive, link,
                    expected_digest=hashlib.sha256(data).hexdigest(),
                    expected_size=len(data))

    def test_casefold_colliding_names_rejected_even_in_hashed_tar(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "go.tar.gz"
            data = make_archive(archive, extra=("go/x/ABC.go", "go/x/abc.go"))
            with self.assertRaisesRegex(
                    QualificationError, "case-conflicting"):
                stage_nonexecutable_go(
                    archive, root / "stage",
                    expected_digest=hashlib.sha256(data).hexdigest(),
                    expected_size=len(data))


if __name__ == "__main__":
    unittest.main(verbosity=2)
