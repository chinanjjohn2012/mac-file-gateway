"""P007 source-only Go tar/stage proof with inert fixtures; NEVER runs Go."""
from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
import tempfile
import tarfile
import unittest
from unittest import mock

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.lbe_p007_go_source_inventory import (
    CRITICAL, ProvenanceError, _origin, inspect_stage, main,
)
from tools.lbe_t1_go_stager import stage_nonexecutable_go
from tools.lbe_t1_source_qualifier import GO_REQUIRED

PAYLOADS = {
    "go/VERSION": b"go1.27.3\n",
    "go/bin/go": b"\xcf\xfa\xed\xfe FAKE GO BINARY NOT EXECUTABLE",
    "go/pkg/tool/darwin_arm64/compile": b"\xcf\xfa\xed\xfe fake compiler",
    "go/pkg/tool/darwin_arm64/link": b"\xcf\xfa\xed\xfe fake linker",
    "go/src/runtime/proc.go": b"package runtime\n",
    "go/src/internal/poll/fd.go": b"package poll\n",
    "go/pkg/runtime/fixture.a": b"fake artifact not executable",
}
assert GO_REQUIRED <= set(PAYLOADS)
assert CRITICAL <= set(PAYLOADS)


def write_tar(path: Path, omit=()):
    with tarfile.open(path, "w:gz") as stream:
        for name in sorted(set(PAYLOADS)-set(omit)):
            content = PAYLOADS[name]
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mode = 0o755 if name in (
                "go/bin/go", "go/pkg/tool/darwin_arm64/compile",
                "go/pkg/tool/darwin_arm64/link") else 0o644
            stream.addfile(info, io.BytesIO(content))
    raw = path.read_bytes()
    return hashlib.sha256(raw).hexdigest(), len(raw)


class GoNonexecutingP007T0(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.archive = self.root / "fixture.tar.gz"
        self.sha, self.size = write_tar(self.archive)
        self.stage = self.root / "staged"
        self.prior = stage_nonexecutable_go(
            self.archive, self.stage, expected_digest=self.sha,
            expected_size=self.size)

    def proof(self, **overrides):
        args = {"sha": self.sha, "size": self.size,
                "stage_hash": self.prior["staged_file_manifest_sha256"]}
        args.update(overrides)
        return inspect_stage(self.archive, self.stage, **args)

    def test_fake_complete_source_exact_manifest_hash_passes(self):
        report = self.proof()
        self.assertEqual(report["file_count"], len(PAYLOADS))
        self.assertEqual(report["stage_sha256_manifest"],
                         self.prior["staged_file_manifest_sha256"])
        self.assertEqual(len(report["critical_sources"]), len(CRITICAL))
        self.assertFalse(report["go_executed"])
        self.assertEqual(report["native_T1"], "NOT_RUN")
        self.assertEqual(report["independent_source_security"], "NOT_ISSUED")

    def test_fake_macho_is_manual_hint_not_execution(self):
        kind, flags = _origin("go/pkg/tool/darwin_arm64/link",
                              b"\xcf\xfa\xed\xfe")
        self.assertEqual(kind, "go_compiler_or_tool")
        self.assertIn("macho_source_manual_review", flags)
        self.assertFalse(self.proof()["go_executed"])

    def test_changed_staged_bytes_rejected(self):
        (self.stage / "go/VERSION").write_bytes(b"tampered!\n")
        with self.assertRaisesRegex(ProvenanceError, "source does not match|unsafe"):
            self.proof()

    def test_additional_unlisted_staged_file_rejected(self):
        (self.stage / "go/surprise.txt").write_text("untrusted")
        with self.assertRaisesRegex(ProvenanceError, "unlisted"):
            self.proof()

    def test_removed_staged_file_rejected(self):
        (self.stage / "go/bin/go").unlink()
        with self.assertRaises(ProvenanceError):
            self.proof()

    def test_symlink_shadow_of_compiler_rejected(self):
        compiler = self.stage / "go/pkg/tool/darwin_arm64/compile"
        compiler.unlink()
        compiler.symlink_to(self.archive)
        with self.assertRaises(ProvenanceError):
            self.proof()

    def test_stage_executable_mode_regression_rejected(self):
        (self.stage / "go/bin/go").chmod(0o700)
        with self.assertRaisesRegex(ProvenanceError, "unsafe or executable"):
            self.proof()

    def test_stage_sha_mismatch_rejected_after_same_bytes(self):
        with self.assertRaisesRegex(ProvenanceError, "manifest SHA256 mismatch"):
            self.proof(stage_hash="0" * 64)

    def test_wrong_tar_hash_rejected_even_when_stage_matches(self):
        with self.assertRaises(ValueError):
            self.proof(sha="f" * 64)

    def test_tar_without_required_linker_rejected(self):
        omitted = self.root / "omitted-linker.tar.gz"
        digest, size = write_tar(omitted, omit=("go/pkg/tool/darwin_arm64/link",))
        other_stage = self.root / "other_stage"
        stage_nonexecutable_go(omitted, other_stage,
                               expected_digest=digest, expected_size=size)
        with self.assertRaisesRegex(ProvenanceError, "critical"):
            inspect_stage(omitted, other_stage, sha=digest, size=size)

    def test_symlink_root_rejected(self):
        alias = self.root / "stage_alias"
        alias.symlink_to(self.stage, target_is_directory=True)
        with self.assertRaisesRegex(ProvenanceError, "not canonical"):
            inspect_stage(self.archive, alias, sha=self.sha, size=self.size)

    def test_missing_original_p001_evidence_prevents_main(self):
        with mock.patch.dict(os.environ, {"RUNNER_TEMP": str(self.root)}):
            self.assertEqual(main(["--runner-temp", str(self.root)]), 2)
        self.assertFalse((self.root / "lbe-p007-go-source-report.json").exists())

    def test_p001_hash_is_sorted_digest_records_not_path_order(self):
        files = self.proof()["files"]
        digest_order = sorted(
            row["sha256"] + "  ./" + row["path"] for row in files)
        expected = hashlib.sha256(
            ("\n".join(digest_order) + "\n").encode()).hexdigest()
        self.assertEqual(self.prior["staged_file_manifest_sha256"], expected)


if __name__ == "__main__":
    unittest.main(verbosity=2)
