"""Pure T0 tests: selection is deterministic; no network/installation."""
from __future__ import annotations

from pathlib import Path
import subprocess
import sys

import pytest

from tools.ci_wheel_constraints import constraints_from_lock

SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "ci_wheel_constraints.py"


def make_lock(tmp_path: Path, count: int = 36) -> Path:
    lock = tmp_path / "wheels.sha256"
    rows = ["%064x  pkg_%02d-1.2.%d-py3-none-any.whl" % (i + 1, i, i)
            for i in range(count)]
    lock.write_text("\n".join(rows) + "\n", encoding="ascii")
    return lock


def test_locked_versions_and_count_are_explicit(tmp_path: Path):
    lock = make_lock(tmp_path)
    text = constraints_from_lock(lock)
    rows = text.splitlines()
    assert len(rows) == 36
    assert rows[0] == "pkg-00==1.2.0"
    assert rows[-1] == "pkg-35==1.2.35"
    assert len(set(rows)) == 36


def test_respects_source_locked_version_instead_of_latest(tmp_path: Path):
    lock = make_lock(tmp_path)
    locked = constraints_from_lock(lock)
    lock.write_text(lock.read_text().replace("pkg_00-1.2.0-", "pkg_00-9.9.9-"))
    assert "pkg-00==9.9.9" in constraints_from_lock(lock)
    assert "pkg-00==1.2.0" in locked


def test_missing_or_extra_distributions_fail(tmp_path: Path):
    with pytest.raises(ValueError, match="exactly 36"):
        constraints_from_lock(make_lock(tmp_path, count=35))
    with pytest.raises(ValueError, match="exactly 36"):
        constraints_from_lock(make_lock(tmp_path, count=37))


def test_duplicate_canonical_name_rejected(tmp_path: Path):
    lock = make_lock(tmp_path)
    text = lock.read_text().replace("pkg_01-1.2.1", "pkg_00-1.2.1")
    lock.write_text(text)
    with pytest.raises(ValueError, match="duplicate"):
        constraints_from_lock(lock)


@pytest.mark.parametrize("broken", [
    "not-a-hash  pkg_00-1.2.0-py3-none-any.whl",
    "0" * 64 + "  pkg_00-1.2.0-py3-none-any.whl --index-url=https://bad",
    "0" * 64 + "  ../../pkg_00-1.2.0-py3-none-any.whl",
    "0" * 64 + "  pkg_00-1.2.0-py3-none-any.tar.gz",
    "0" * 64 + "  pkg_00-1.2.0-py3-none-any.whl\nextra",
])
def test_invalid_lock_record_rejected(tmp_path: Path, broken: str):
    lock = make_lock(tmp_path)
    rows = lock.read_text().splitlines()
    rows[0] = broken
    lock.write_text("\n".join(rows) + "\n")
    with pytest.raises(ValueError):
        constraints_from_lock(lock)


def test_unsorted_lock_rejected(tmp_path: Path):
    lock = make_lock(tmp_path)
    rows = lock.read_text().splitlines()
    rows[1], rows[2] = rows[2], rows[1]
    lock.write_text("\n".join(rows) + "\n")
    with pytest.raises(ValueError, match="sorted"):
        constraints_from_lock(lock)


def test_linked_lock_rejected(tmp_path: Path):
    lock = make_lock(tmp_path)
    alias = tmp_path / "alias.sha256"
    alias.symlink_to(lock.name)
    with pytest.raises(ValueError, match="not a link"):
        constraints_from_lock(alias)


def test_cli_fails_without_output_on_bad_lock(tmp_path: Path):
    lock = make_lock(tmp_path, count=35)
    result = subprocess.run([sys.executable, "-I", "-S", str(SCRIPT),
                             "--source-lock", str(lock)],
                            text=True, capture_output=True, timeout=5)
    assert result.returncode == 2
    assert result.stdout == ""
    assert "CI_WHEEL_CONSTRAINTS=INCOMPLETE" in result.stderr


def test_cli_pins_exact_versions(tmp_path: Path):
    lock = make_lock(tmp_path)
    result = subprocess.run([sys.executable, "-I", "-S", str(SCRIPT),
                             "--source-lock", str(lock)],
                            text=True, capture_output=True, timeout=5)
    assert result.returncode == 0
    assert result.stdout.splitlines()[0] == "pkg-00==1.2.0"
    assert "PINNED_FROM_SOURCE_LOCK count=36" in result.stderr
