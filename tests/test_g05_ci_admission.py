"""Disposable local Git checks for the G05 checkout admission gate.

These tests do not start a Gateway server, real Exec Apply, native child signal,
actual user Tunnel, or a real remote Git operation.
"""
from __future__ import annotations

import hashlib
import importlib.machinery
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "g05_ci_admission.py"


def run_git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args], cwd=root, text=True, capture_output=True, check=True,
    )


def make_manifest(root: Path) -> None:
    items = [p for p in root.rglob("*") if p.is_file() and ".git" not in p.parts]
    items = [p for p in items if p.name != "MANIFEST.sha256"]
    records = []
    for path in items:
        rel = path.relative_to(root).as_posix()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        records.append((rel, digest))
    (root / "MANIFEST.sha256").write_text(
        "".join(f"{digest}  ./{rel}\n" for rel, digest in sorted(records)),
        encoding="ascii",
    )


@pytest.fixture
def checkout(tmp_path: Path) -> Path:
    root = tmp_path / "disposable-checkout"
    root.mkdir()
    run_git(root, "init", "-q")
    run_git(root, "config", "user.name", "G05 Test")
    run_git(root, "config", "user.email", "g05-test@example.invalid")
    (root / ".gitignore").write_text("ignored_shadow.py\n*.log\n__pycache__/\n.venv/\n", encoding="utf-8")
    (root / "gateway").mkdir()
    (root / "gateway" / "__init__.py").write_text("\"\"\"Disposable package.\"\"\"\n", encoding="utf-8")
    (root / "gateway" / "feature.py").write_text("FEATURE = 'safe'\n", encoding="utf-8")
    (root / "tools").mkdir()
    shutil.copyfile(SCRIPT, root / "tools" / "g05_ci_admission.py")
    make_manifest(root)
    run_git(root, "add", ".")
    run_git(root, "commit", "-q", "-m", "g05 fixture")
    return root


def run_gate(root: Path, expected_head: str | None = None, extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    sha = run_git(root, "rev-parse", "HEAD").stdout.strip()
    env = os.environ.copy()
    for name in (
        "PYTHONPATH", "PYTHONHOME", "PYTHONUSERBASE", "PYTHONSTARTUP",
        "PYTHONPYCACHEPREFIX", "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR",
        "GIT_OBJECT_DIRECTORY", "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
    ):
        env.pop(name, None)
    env.update(extra_env or {})
    return subprocess.run(
        [sys.executable, "-I", "-S", str(root / "tools" / "g05_ci_admission.py"),
         "--expected-head", expected_head or sha],
        cwd=root, text=True, capture_output=True, env=env, check=False,
    )


def assert_denied(result: subprocess.CompletedProcess[str], reason: str) -> None:
    assert result.returncode == 2, (result.stdout, result.stderr)
    assert "G05_REPOSITORY_ADMISSION=FAIL" in result.stderr
    assert "G05_R01_GATE=INCOMPLETE" in result.stderr
    assert reason in result.stderr
    assert "G05_REPOSITORY_ADMISSION=PASS" not in result.stdout


def test_clean_checkout_manifest_and_import_root_pass(checkout: Path) -> None:
    out = run_gate(checkout)
    assert out.returncode == 0, (out.stdout, out.stderr)
    assert "G05_REPOSITORY_ADMISSION=PASS" in out.stdout
    assert "G05_TRACKED_SHA256_MANIFEST=PASS count=4" in out.stdout
    assert "G05_EXECUTION_IMPORT_ROOT=gateway/__init__.py" in out.stdout
    assert "G05_THIRD_PARTY_DEPENDENCY_PROVENANCE=NOT_ATTESTED" in out.stdout
    assert run_git(checkout, "status", "--porcelain").stdout == ""


def test_ignored_python_import_shadow_rejected_though_git_diff_is_green(checkout: Path) -> None:
    ignored = checkout / "gateway" / "ignored_shadow.py"
    ignored.write_text("PAYLOAD = 'not reviewed'\n", encoding="utf-8")
    # The old tracked-only oracle incorrectly returned exit 0.
    assert run_git(checkout, "diff", "--quiet", "HEAD").returncode == 0
    assert run_git(checkout, "ls-files", "--others", "--exclude-standard").stdout == ""
    assert "gateway/ignored_shadow.py" in run_git(
        checkout, "ls-files", "--others", "--ignored", "--exclude-standard"
    ).stdout
    # Metadata discovery only: do not execute the unreviewed module.
    spec = importlib.machinery.PathFinder.find_spec("ignored_shadow", [str(checkout / "gateway")])
    assert spec is not None and Path(spec.origin or "") == ignored
    assert_denied(run_gate(checkout), "ignored")


def test_ignored_directory_with_runtime_module_rejected(checkout: Path) -> None:
    poison = checkout / ".venv" / "lib" / "outside.py"
    poison.parent.mkdir(parents=True)
    poison.write_text("MALICIOUS = True\n", encoding="utf-8")
    assert_denied(run_gate(checkout), "ignored")


def test_untracked_script_rejected(checkout: Path) -> None:
    (checkout / "gateway" / "extra.py").write_text("EXTRA = 1\n", encoding="utf-8")
    assert_denied(run_gate(checkout), "untracked")


def test_untracked_nonexecuting_file_also_fail_closed(checkout: Path) -> None:
    (checkout / "unplanned.txt").write_text("unreviewed\n", encoding="utf-8")
    assert_denied(run_gate(checkout), "untracked")


def test_tracked_content_edit_rejected(checkout: Path) -> None:
    (checkout / "gateway" / "feature.py").write_text("FEATURE = 'changed'\n", encoding="utf-8")
    assert_denied(run_gate(checkout), "tracked changes")


def test_wrong_head_rejected(checkout: Path) -> None:
    assert_denied(run_gate(checkout, expected_head="0" * 40), "Head")


def test_unapproved_pythonpath_rejected(checkout: Path) -> None:
    assert_denied(run_gate(checkout, extra_env={"PYTHONPATH": "/unreviewed"}), "PYTHONPATH")


def test_manifest_tracked_path_omitted_rejected(checkout: Path) -> None:
    manifest = checkout / "MANIFEST.sha256"
    records = manifest.read_text(encoding="ascii").splitlines()
    manifest.write_text("\n".join(records[:-1]) + "\n", encoding="ascii")
    assert_denied(run_gate(checkout), "tracked changes")


def test_cache_from_prior_build_is_denied_and_proves_prebuild_timing(checkout: Path) -> None:
    cache = checkout / "gateway" / "__pycache__" / "feature.cpython-313.pyc"
    cache.parent.mkdir()
    cache.write_bytes(b"unreviewed bytecode")
    assert_denied(run_gate(checkout), "ignored")


def test_rejects_bad_expected_sha_syntax(checkout: Path) -> None:
    assert_denied(run_gate(checkout, expected_head="short"), "40-char")


def test_clean_committed_snapshot_with_forged_manifest_hash_is_denied(checkout: Path) -> None:
    # Not merely a dirty-worktree test: both the forged Manifest and HEAD are
    # committed. The gate must detect a wrong SHA256 within a clean Git tree.
    path = checkout / "MANIFEST.sha256"
    first, *rest = path.read_text(encoding="ascii").splitlines()
    forged = "0" * 64 + first[64:]
    path.write_text("\n".join([forged, *rest]) + "\n", encoding="ascii")
    run_git(checkout, "add", "MANIFEST.sha256")
    run_git(checkout, "commit", "-q", "-m", "forged manifest in committed tree")
    assert run_git(checkout, "status", "--porcelain").stdout == ""
    assert_denied(run_gate(checkout), "content hash mismatch")


def test_committed_symlink_is_not_treated_as_manifest_regular_file(checkout: Path) -> None:
    link = checkout / "gateway" / "link.py"
    link.symlink_to("feature.py")
    # Manifest follows symlinks when constructing a test record, but the gate
    # must not treat such content as an immutable regular Git blob identity.
    make_manifest(checkout)
    run_git(checkout, "add", "gateway/link.py", "MANIFEST.sha256")
    run_git(checkout, "commit", "-q", "-m", "tracked symlink")
    assert run_git(checkout, "status", "--porcelain").stdout == ""
    assert_denied(run_gate(checkout), "not a regular file")


# PR #74 r001 Standards P2-01 real Git RED->GREEN cases: Git porcelain and
# mutable Manifest self-consistency are NOT sufficient HEAD provenance.
def _coordinated_worktree_tamper(root: Path) -> None:
    source = root / "gateway" / "feature.py"
    source.write_text("FEATURE = 'unreviewed'\n", encoding="utf-8")
    manifest = root / "MANIFEST.sha256"
    rows = manifest.read_text(encoding="ascii").splitlines()
    rows = [
        hashlib.sha256(source.read_bytes()).hexdigest() + "  ./gateway/feature.py"
        if row.endswith("  ./gateway/feature.py") else row
        for row in rows
    ]
    manifest.write_text("\n".join(rows) + "\n", encoding="ascii")
    assert run_git(root, "rev-parse", "HEAD:gateway/feature.py").stdout.strip() != run_git(
        root, "hash-object", "--no-filters", "gateway/feature.py"
    ).stdout.strip()
    assert run_git(root, "rev-parse", "HEAD:MANIFEST.sha256").stdout.strip() != run_git(
        root, "hash-object", "--no-filters", "MANIFEST.sha256"
    ).stdout.strip()


def test_assume_unchanged_forged_source_and_manifest_fail_closed(checkout: Path) -> None:
    run_git(checkout, "update-index", "--assume-unchanged", "gateway/feature.py", "MANIFEST.sha256")
    _coordinated_worktree_tamper(checkout)
    assert run_git(checkout, "status", "--porcelain=v1").stdout == ""
    assert "h gateway/feature.py" in run_git(checkout, "ls-files", "-v").stdout
    assert_denied(run_gate(checkout), "index flags")


def test_skip_worktree_forged_source_and_manifest_fail_closed(checkout: Path) -> None:
    run_git(checkout, "update-index", "--skip-worktree", "gateway/feature.py", "MANIFEST.sha256")
    _coordinated_worktree_tamper(checkout)
    assert run_git(checkout, "status", "--porcelain=v1").stdout == ""
    assert "S gateway/feature.py" in run_git(checkout, "ls-files", "-v").stdout
    assert_denied(run_gate(checkout), "index flags")


def test_core_filemode_false_hides_executable_drift_but_gate_denies(checkout: Path) -> None:
    run_git(checkout, "config", "core.filemode", "false")
    source = checkout / "gateway" / "feature.py"
    source.chmod(source.stat().st_mode | 0o111)
    assert run_git(checkout, "status", "--porcelain=v1").stdout == ""
    assert_denied(run_gate(checkout), "core.filemode")


def _real_gate_module():
    # Run the actual gate module in the local process WITHOUT executing its
    # CLI or any unreviewed Gateway/runtime module.
    spec = importlib.util.spec_from_file_location("g05_gate_under_test", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_native_head_tree_detects_manifest_byte_drift_directly(checkout: Path) -> None:
    gate = _real_gate_module()
    manifest = checkout / "MANIFEST.sha256"
    manifest.write_text(manifest.read_text().replace("a", "b", 1))
    with pytest.raises(gate.AdmissionError, match="HEAD Tree blob content mismatch: MANIFEST.sha256"):
        gate.verify_head_tree(checkout, set(run_git(checkout, "ls-files").stdout.splitlines()))


def test_native_head_tree_detects_exec_bit_drift_directly(checkout: Path) -> None:
    gate = _real_gate_module()
    run_git(checkout, "config", "core.filemode", "false")
    source = checkout / "gateway" / "feature.py"
    source.chmod(source.stat().st_mode | 0o111)
    with pytest.raises(gate.AdmissionError, match="HEAD Tree executable mode mismatch: gateway/feature.py"):
        gate.verify_head_tree(checkout, set(run_git(checkout, "ls-files").stdout.splitlines()))


def test_legitimate_committed_executable_mode_still_passes(checkout: Path) -> None:
    script = checkout / "gateway" / "feature.py"
    script.chmod(script.stat().st_mode | 0o111)
    run_git(checkout, "add", "gateway/feature.py")
    run_git(checkout, "commit", "-q", "-m", "allow source executable mode in HEAD")
    assert run_git(checkout, "ls-tree", "HEAD", "gateway/feature.py").stdout.startswith("100755 blob")
    result = run_gate(checkout)
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert "G05_HEAD_BLOB_AND_EXEC_MODE=PASS" in result.stdout
