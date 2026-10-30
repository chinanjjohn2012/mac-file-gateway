"""Read-only source identity candidate tests; never execute toolchains."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

import pytest

from tools.lbe_toolchain_candidates import inspect, main


def _executable(root: Path, name: str, contents: bytes = b"sample") -> Path:
    root.mkdir(parents=True, exist_ok=True)
    item = root / name
    item.write_bytes(contents)
    item.chmod(0o755)
    return item


def test_candidate_hash_is_read_only_never_a_native_qualification(
    tmp_path, monkeypatch,
):
    """Executable is only hashed, not started, imported or installed."""
    expected = b"not a genuine go toolchain"
    path = _executable(tmp_path, "go", expected)

    def no_popen(*_args, **_kwargs):
        raise AssertionError("candidate inspection must not start subprocesses")
    with monkeypatch.context() as m:
        m.setattr(subprocess.Popen, "__init__", no_popen)
        result = inspect("go", str(tmp_path))
    assert result["status"] == "CANDIDATES_UNQUALIFIED"
    assert result["native_qualified"] is False
    assert result["execution"] == "NOT_RUN"
    assert result["candidates"][0]["status"] == "CANDIDATE_ONLY"
    assert result["candidates"][0]["sha256"] == hashlib.sha256(expected).hexdigest()
    assert path.read_bytes() == expected


def test_no_candidate_or_non_executable_is_never_qualified(tmp_path):
    assert inspect("pipenv", str(tmp_path))["status"] == "NOT_FOUND"
    item = tmp_path / "pipenv"
    item.write_text("script")
    item.chmod(0o600)
    result = inspect("pipenv", str(tmp_path))
    assert result["status"] == "CANDIDATES_UNQUALIFIED"
    assert result["candidates"][0]["status"] == "UNSAFE_CANDIDATE"
    assert result["native_qualified"] is False


@pytest.mark.parametrize("search", ["", ".", ":/bin", "/bin:", "/bin:relative"])
def test_unsafe_relative_or_empty_path_search_fails_closed(search):
    result = inspect("go", search)
    assert result["status"] == "UNSAFE_PATH_SEARCH"
    assert result["candidates"] == []
    assert result["native_qualified"] is False


def test_symlink_candidate_is_identified_but_unqualified(tmp_path):
    target = _executable(tmp_path / "target", "go")
    entry = tmp_path / "entry"
    entry.mkdir()
    (entry / "go").symlink_to(target)
    result = inspect("go", str(entry))
    assert result["status"] == "CANDIDATES_UNQUALIFIED"
    assert result["candidates"][0]["linked_path"] is True
    assert result["candidates"][0]["status"] == "CANDIDATE_ONLY"
    assert result["native_qualified"] is False


def test_two_path_shadow_candidates_remain_unqualified(tmp_path):
    first = tmp_path / "one"
    second = tmp_path / "two"
    _executable(first, "go", b"one")
    _executable(second, "go", b"two")
    result = inspect("go", os.pathsep.join((str(first), str(second))))
    assert len(result["candidates"]) == 2
    assert result["candidates"][0]["sha256"] != result["candidates"][1]["sha256"]
    assert result["native_qualified"] is False


def test_only_disposable_runner_temp_receives_report(tmp_path, monkeypatch):
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setenv("PATH", str(tmp_path))
    _executable(tmp_path, "pipenv", b"candidate")
    output = tmp_path / "candidate-report.json"
    assert main(["--output", str(output)]) == 0
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    payload = json.loads(output.read_text())
    assert payload["all_native_qualified"] is False
    assert payload["native_go_pipenv"] == "NOT_RUN"
    assert payload["external_toolchains"][1]["program"] == "pipenv"
    assert payload["external_toolchains"][1]["native_qualified"] is False
    with pytest.raises(FileExistsError):
        main(["--output", str(output)])
    outside = tmp_path / "other"
    outside.mkdir()
    assert main(["--output", str(outside / "report.json")]) == 2
    assert not (outside / "report.json").exists()
