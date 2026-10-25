"""Isolated positive and negative wheel provenance unit tests; no network or installs."""
import json
import hashlib
from pathlib import Path
import subprocess
import sys
import zipfile

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "ci_dependency_provenance.py"


def make_wheel(folder: Path, filename: str = "safe_lib-1.0-py3-none-any.whl") -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / filename
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("safe_lib/__init__.py", "VALUE = 'reviewed'\n")
        z.writestr("safe_lib-1.0.dist-info/WHEEL", "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
    return path


def run(stage: str, root: Path, record: Path):
    lock = record.with_suffix(".lock")
    if not lock.exists():
        rows = [f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}"
                for path in sorted(root.glob("*.whl"))]
        lock.write_text("\n".join(rows) + "\n", encoding="ascii")
    return subprocess.run([sys.executable, "-I", "-S", str(SCRIPT), stage,
                           "--wheelhouse", str(root), "--wheel-record", str(record),
                           "--source-lock", str(lock),
                           "--installed-record", str(record.with_suffix(".installed.json"))],
                          text=True, capture_output=True)


def test_attests_legitimate_wheel_bytes(tmp_path: Path):
    wheel = make_wheel(tmp_path / "wheels")
    record = tmp_path / "wheels.json"
    out = run("wheels", wheel.parent, record)
    assert out.returncode == 0, out.stderr
    assert "CI_WHEEL_SHA256=" in out.stdout
    assert "CROSS_RUN_LOCK=SOURCE_SHA256_PINNED" in out.stdout
    assert json.loads(record.read_text())["wheels"][0]["filename"] == wheel.name


def test_changed_wheel_after_record_is_rejected(tmp_path: Path):
    wheel = make_wheel(tmp_path / "wheels")
    record = tmp_path / "wheels.json"
    assert run("wheels", wheel.parent, record).returncode == 0
    with wheel.open("ab") as f:
        f.write(b"tampering-after-record")
    out = run("installed", wheel.parent, record)
    assert out.returncode == 2, out.stdout
    assert "wheelhouse differs" in out.stderr


def test_non_wheel_file_is_rejected(tmp_path: Path):
    wheel = make_wheel(tmp_path / "wheels")
    (wheel.parent / "source.tar.gz").write_bytes(b"unchecked")
    out = run("wheels", wheel.parent, tmp_path / "wheels.json")
    assert out.returncode == 2, out.stdout
    assert "non-wheel" in out.stderr


def test_wheel_symlink_is_rejected(tmp_path: Path):
    wheel = make_wheel(tmp_path / "wheels")
    (wheel.parent / "evil_lib-1.0-py3-none-any.whl").symlink_to(wheel.name)
    out = run("wheels", wheel.parent, tmp_path / "wheels.json")
    assert out.returncode == 2, out.stdout
    assert "not an actual regular" in out.stderr


def test_duplicate_distribution_wheels_are_rejected(tmp_path: Path):
    wheel = make_wheel(tmp_path / "wheels")
    make_wheel(wheel.parent, "safe_lib-2.0-py3-none-any.whl")
    out = run("wheels", wheel.parent, tmp_path / "wheels.json")
    assert out.returncode == 2, out.stdout
    assert "duplicate" in out.stderr


def test_attestation_record_cannot_be_overwritten(tmp_path: Path):
    wheel = make_wheel(tmp_path / "wheels")
    record = tmp_path / "wheels.json"
    assert run("wheels", wheel.parent, record).returncode == 0
    out = run("wheels", wheel.parent, record)
    assert out.returncode == 2
    assert "overwrite" in out.stderr


def test_source_controlled_wheel_digest_mismatch_is_denied(tmp_path: Path):
    wheel = make_wheel(tmp_path / "wheels")
    record = tmp_path / "wheels.json"
    assert run("wheels", wheel.parent, record).returncode == 0
    lock = record.with_suffix(".lock")
    row = lock.read_text()
    lock.write_text("0" * 64 + row[64:])
    out = run("installed", wheel.parent, record)
    assert out.returncode == 2
    assert "source-controlled platform SHA256 lock" in out.stderr


def test_source_controlled_wheel_omission_is_denied(tmp_path: Path):
    wheel = make_wheel(tmp_path / "wheels")
    record = tmp_path / "wheels.json"
    lock = record.with_suffix(".lock")
    lock.write_text("")
    out = run("wheels", wheel.parent, record)
    assert out.returncode == 2
    assert "source-controlled platform SHA256 lock" in out.stderr


# Independent synthetic E4 counterexamples; no real package installation.
from tools.ci_dependency_provenance import ProvenanceError, scan_site_import_root


def test_recorded_importable_source_is_accepted(tmp_path: Path):
    root = tmp_path / "site-packages"
    package = root / "known"
    package.mkdir(parents=True)
    source = package / "__init__.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    result = scan_site_import_root(root, {source})
    assert result["files"] == 1
    assert result["pth_files"] == 0


def test_record_unlisted_package_module_is_denied(tmp_path: Path):
    root = tmp_path / "site-packages"
    package = root / "known"
    package.mkdir(parents=True)
    source = package / "__init__.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    (package / "unlisted.py").write_text("VALUE = 'unreviewed'\n", encoding="utf-8")
    with pytest.raises(ProvenanceError, match="unrecorded importable source"):
        scan_site_import_root(root, {source})


def test_record_unlisted_sitecustomize_is_denied(tmp_path: Path):
    root = tmp_path / "site-packages"
    root.mkdir()
    (root / "sitecustomize.py").write_text("VALUE = 2\n", encoding="utf-8")
    with pytest.raises(ProvenanceError, match="unrecorded importable source"):
        scan_site_import_root(root, set())


def test_record_unlisted_pth_import_hook_is_denied(tmp_path: Path):
    root = tmp_path / "site-packages"
    root.mkdir()
    (root / "unlisted.pth").write_text("import os\n", encoding="utf-8")
    with pytest.raises(ProvenanceError, match="unrecorded importable source"):
        scan_site_import_root(root, set())


def test_record_unlisted_compiled_extension_is_denied(tmp_path: Path):
    root = tmp_path / "site-packages"
    root.mkdir()
    (root / "injected.cpython-313-darwin.so").write_bytes(b"payload")
    with pytest.raises(ProvenanceError, match="unrecorded importable source"):
        scan_site_import_root(root, set())


def test_orphan_bytecode_and_symlink_are_denied(tmp_path: Path):
    root = tmp_path / "site-packages"
    root.mkdir()
    cache = root / "__pycache__"
    cache.mkdir()
    (cache / "ghost.cpython-313.pyc").write_bytes(b"untrusted")
    with pytest.raises(ProvenanceError, match="unrecorded importable source"):
        scan_site_import_root(root, set())
    (cache / "ghost.cpython-313.pyc").unlink()
    target = tmp_path / "target.py"
    target.write_text("VALUE = 1\n", encoding="utf-8")
    (root / "linked.py").symlink_to(target)
    with pytest.raises(ProvenanceError, match="actual regular file"):
        scan_site_import_root(root, set())


def test_recorded_importable_content_drift_changes_digest(tmp_path: Path):
    root = tmp_path / "site-packages"
    root.mkdir()
    source = root / "known.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    first = scan_site_import_root(root, {source})
    source.write_text("VALUE = 2\n", encoding="utf-8")
    second = scan_site_import_root(root, {source})
    assert first["content_sha256"] != second["content_sha256"]


def test_recorded_pth_external_path_is_denied(tmp_path: Path):
    root = tmp_path / "site-packages"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    hook = root / "scope.pth"
    hook.write_text(str(outside) + "\n", encoding="utf-8")
    with pytest.raises(ProvenanceError, match="external import root"):
        scan_site_import_root(root, {hook})
