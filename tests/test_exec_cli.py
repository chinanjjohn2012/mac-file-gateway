import json
import subprocess
import sys


def run(root, *args):
    return subprocess.run(
        [sys.executable, "-m", "gateway", "--root", str(root), "--check", *args],
        capture_output=True, text=True, timeout=10,
    )


def test_allow_exec_requires_scope(tmp_path):
    r = run(tmp_path, "--allow-exec")
    assert r.returncode == 2
    assert "--exec-path" in r.stderr


def test_exec_scope_without_allow_exec_fails(tmp_path):
    assert run(tmp_path, "--exec-path", "service-c").returncode == 2


def test_exec_policy_and_runner_mapping(tmp_path):
    (tmp_path / "service-c").mkdir()
    (tmp_path / "service-c" / "Pipfile").write_text("[packages]\n")
    r = run(
        tmp_path,
        "--allow-exec",
        "--exec-path", "service-c",
        "--exec-runner", "service-c=pipenv",
    )
    assert r.returncode == 0, r.stderr
    info = json.loads(r.stdout)
    assert info["exec_policy"]["enabled"] is True
    assert info["exec_policy"]["paths"] == ["service-c"]
    assert info["exec_policy"]["configured_runners"] == {"service-c": "pipenv"}


def test_exec_scope_cannot_escape(tmp_path):
    r = run(tmp_path, "--allow-exec", "--exec-path", "../outside")
    assert r.returncode == 2
