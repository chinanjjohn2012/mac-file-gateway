"""Safe T0 tests for host candidate collection; discovered hash is never authority."""
import hashlib
import os
from pathlib import Path
import subprocess

from tools.d4_r006_host_source_collect_t0 import _collect


def test_collect_regular_private_file_without_execution(tmp_path, monkeypatch):
    root = tmp_path / "safe"
    root.mkdir(mode=0o700)
    f = root / "source"
    data = b"candidate bytes only\n"
    f.write_bytes(data)
    f.chmod(0o600)
    def forbidden(*_a, **_kw):
        raise AssertionError("candidate collection cannot execute or signal")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "kill", forbidden)
    row = _collect(str(f))
    assert row["status"] == "CANDIDATE_ONLY"
    assert row["sha256"] == hashlib.sha256(data).hexdigest()
    assert "native_launch_allowed" not in row


def test_collect_symlink_and_writable_file_fail_closed(tmp_path):
    root = tmp_path / "safe"
    root.mkdir(mode=0o700)
    target = root / "target"
    target.write_bytes(b"x")
    target.chmod(0o600)
    link = root / "link"
    link.symlink_to(target)
    assert _collect(str(link))["status"] == "UNAVAILABLE"
    target.chmod(0o666)
    assert _collect(str(target))["status"] == "UNQUALIFIED_METADATA"


def test_collect_missing_and_traversal_never_qualify(tmp_path):
    assert _collect(str(tmp_path / "missing"))["status"] == "UNAVAILABLE"
    assert _collect("/tmp/../etc/passwd")["status"] == "INVALID"

def test_system_version_claim_is_bounded_shape(monkeypatch):
    import plistlib
    from tools import d4_r006_host_source_collect_t0 as mod

    data = plistlib.dumps({
        "ProductName": "macOS",
        "ProductVersion": "15.8.2",
        "ProductBuildVersion": "24G90",
    })
    class F:
        def __init__(self): self._done = False
        def __enter__(self): return self
        def __exit__(self, *a): return None
        def read(self, n=-1):
            if self._done: return b""
            self._done = True
            return data
    monkeypatch.setattr("builtins.open", lambda *a, **k: F())
    assert mod._system_version_claim() == {
        "status": "CLAIM_ONLY", "ProductName": "macOS",
        "ProductVersion": "15.8.2", "ProductBuildVersion": "24G90",
    }
