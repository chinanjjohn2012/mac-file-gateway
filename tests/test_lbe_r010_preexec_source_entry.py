"""R010 tracked pre-product entrypoint ordering, SAFE T0 only."""
from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "gateway" / "r010_preexec_source_entry.py"
TOKEN = "synthetic-entry-bearer-1234567890"
SOCK = "/private/tmp/r010-entry-agent.sock"
URL = (
    "https://pipelines.actions.githubusercontent.com/"
    "_apis/oidc/token?api-version=2.0"
)


def _env(*, extra=None):
    values = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/private/tmp/r010-entry-home",
        "TMPDIR": "/private/tmp/r010-entry-tmp",
        "LANG": "C",
        "LC_ALL": "C",
        "GITHUB_ACTIONS": "true",
        "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_REPOSITORY": "chinanjjohn2012/mac-file-gateway",
        "GITHUB_RUN_ID": "42640408843",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_JOB": "r010_preexec_hold",
        "G05_EXPECTED_HEAD": "a" * 40,
        "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "macOS",
        "RUNNER_ARCH": "ARM64",
        "ImageOS": "macos15",
        "ImageVersion": "20261104.0514.1",
        "SSH_AUTH_SOCK": SOCK,
        "ACTIONS_ID_TOKEN_REQUEST_URL": URL,
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN": TOKEN,
    }
    if extra:
        values.update(extra)
    return values


def _args():
    return [
        "--expected-run-id", "42640408843",
        "--expected-run-attempt", "1",
        "--expected-head", "a" * 40,
        "--expected-job", "r010_preexec_hold",
        "--expected-image-version", "20261104.0514.1",
        "--expected-home", "/private/tmp/r010-entry-home",
        "--expected-tmp", "/private/tmp/r010-entry-tmp",
    ]


def _run(*, env=None):
    return subprocess.run(
        [sys.executable, str(ENTRY), *_args()],
        cwd=ROOT, env=_env() if env is None else env,
        capture_output=True, text=True, check=False, timeout=20)


def test_entry_exists_and_has_no_top_level_gateway_or_network_import():
    assert ENTRY.exists(), "RED: tracked pre-product source entrypoint is missing"
    tree = ast.parse(ENTRY.read_text(encoding="utf-8"))
    allowed = {
        "__future__", "argparse", "hashlib", "importlib", "json",
        "os", "pathlib", "stat", "sys",
    }
    seen = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            seen.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            seen.add((node.module or "").split(".", 1)[0])
    assert seen <= allowed
    assert "gateway" not in seen
    assert "socket" not in seen
    assert "subprocess" not in seen
    assert "urllib" not in seen


def test_entry_scrubs_before_gateway_product_import_in_same_process():
    result = _run()
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "PREIMPORT_ENTRY_PRODUCT_IMPORTED_SOURCE_ONLY_NO_T1"
    assert payload["gateway_modules_before_scrub"] == []
    assert payload["gateway_modules_after_scrub"] == []
    assert payload["product_module"] == "gateway.lbe_r010_product_pipeline"
    assert payload["helper_keys"] == ["HOME", "LANG", "LC_ALL", "PATH", "TMPDIR"]
    assert payload["native_launch_allowed"] is False
    assert payload["product_t1"] == "NOT_RUN"
    assert len(payload["receipt_sha256"]) == 64
    assert len(payload["gate_source_sha256"]) == 64
    assert TOKEN not in result.stdout
    assert SOCK not in result.stdout
    assert URL not in result.stdout


def test_entry_rejects_extra_bootstrap_key_without_secret_echo():
    env = _env(extra={"HTTP_PROXY": "http://untrusted.invalid/"})
    result = _run(env=env)
    assert result.returncode != 0
    combined = result.stdout + result.stderr
    assert "R010_PREEXEC_SOURCE_ENTRY_DENY" in combined
    assert TOKEN not in combined
    assert SOCK not in combined
    assert URL not in combined


def test_entry_rejects_if_gateway_package_was_loaded_before_file_execution():
    code = (
        "import runpy,sys;"
        "import gateway.workspaces;"
        "sys.argv=['r010_preexec_source_entry.py'," +
        ",".join(repr(x) for x in _args()) +
        "];"
        "runpy.run_path('gateway/r010_preexec_source_entry.py',run_name='__main__')"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], cwd=ROOT, env=_env(),
        capture_output=True, text=True, check=False, timeout=20)
    assert result.returncode != 0
    combined = result.stdout + result.stderr
    assert "R010_PREEXEC_SOURCE_ENTRY_DENY" in combined
    assert TOKEN not in combined
    assert SOCK not in combined
    assert URL not in combined
