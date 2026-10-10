import json
import subprocess
import sys


def run(root, *args):
    return subprocess.run([sys.executable, "-m", "gateway", "--root", str(root), "--check", *args], capture_output=True, text=True, timeout=10)


def test_cli_allow_write(tmp_path):
    r = run(tmp_path, "--allow-write")
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout)["write_policy"]["enabled"] is True


def test_cli_write_scope_repeatable(tmp_path):
    r = run(tmp_path, "--allow-write", "--write-path", "src", "--write-path", "tests")
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout)["write_policy"]["paths"] == ["src", "tests"]


def test_cli_scope_without_allow_write_fails(tmp_path):
    assert run(tmp_path, "--write-path", "src").returncode == 2


def test_cli_scope_cannot_escape(tmp_path):
    assert run(tmp_path, "--allow-write", "--write-path", "../outside").returncode == 2


def test_cli_backup_retention_policy(tmp_path):
    r = run(tmp_path, "--allow-write", "--backup-retention-days", "21")
    assert r.returncode == 0, r.stderr
    policy = json.loads(r.stdout)["write_policy"]
    assert policy["backup_retention_days"] == 21
    assert policy["max_backup_files"] == 10000
    assert policy["max_backup_bytes"] == 5120 * 1024 * 1024


def test_cli_rejects_invalid_backup_retention(tmp_path):
    for value in ("0", "-1", "3651", "invalid"):
        assert run(tmp_path, "--allow-write", "--backup-retention-days", value).returncode == 2
