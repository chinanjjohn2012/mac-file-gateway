"""R010 pre-product-import environment scrub gate, SAFE T0 only."""
from __future__ import annotations

import ast
import json
from pathlib import Path
import subprocess
import sys
import textwrap


ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "gateway" / "lbe_r010_preimport_gate.py"


def _run_fresh(script: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", textwrap.dedent(script)],
        cwd=ROOT, capture_output=True, text=True, check=False)


def _bootstrap_script(extra: str = "", preload: str = "") -> str:
    return f"""
import json
import os
import sys
{preload}
from gateway.lbe_r010_preimport_gate import (
    R010PreimportExpected,
    R010PreimportScrubDenied,
    scrub_r010_preimport_environment,
)
expected = R010PreimportExpected(
    run_id="42640408843", run_attempt="1", head_sha="a" * 40,
    job_name="r010_preexec_hold", image_version="20261104.0514.1",
    private_home="/private/tmp/r010-home",
    private_tmp="/private/tmp/r010-tmp",
)
values = {{
    "PATH": "/usr/bin:/bin", "HOME": expected.private_home,
    "TMPDIR": expected.private_tmp, "LANG": "C", "LC_ALL": "C",
    "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "pull_request",
    "GITHUB_REPOSITORY": "chinanjjohn2012/mac-file-gateway",
    "GITHUB_RUN_ID": expected.run_id,
    "GITHUB_RUN_ATTEMPT": expected.run_attempt,
    "GITHUB_JOB": expected.job_name, "G05_EXPECTED_HEAD": expected.head_sha,
    "RUNNER_ENVIRONMENT": "github-hosted",
    "RUNNER_OS": "macOS", "RUNNER_ARCH": "ARM64",
    "ImageOS": "macos15", "ImageVersion": expected.image_version,
    "SSH_AUTH_SOCK": "/private/tmp/r010-agent.sock",
    "ACTIONS_ID_TOKEN_REQUEST_URL":
        "https://pipelines.actions.githubusercontent.com/_apis/oidc/token?api-version=2.0",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "synthetic-bearer-1234567890",
}}
{extra}
os.environ.clear()
os.environ.update(values)
"""


def test_preimport_gate_source_has_no_gateway_product_imports():
    assert GATE.exists(), "RED: dedicated stdlib-only pre-import gate is missing"
    tree = ast.parse(GATE.read_text(encoding="utf-8"))
    allowed = {
        "__future__", "collections", "dataclasses", "hashlib", "json",
        "os", "re", "sys", "urllib",
    }
    seen = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            seen.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            seen.add((node.module or "").split(".", 1)[0])
    assert seen <= allowed
    assert "gateway" not in seen


def test_fresh_process_scrubs_selectors_before_any_product_import():
    script = _bootstrap_script() + r"""
assert not [n for n in sys.modules if n.startswith("gateway.") and
            n != "gateway.lbe_r010_preimport_gate"]
receipt = scrub_r010_preimport_environment(expected=expected)
assert receipt.product_modules_absent_before_scrub is True
assert receipt.selectors_scrubbed is True
assert receipt.native_launch_allowed is False
assert set(os.environ) == {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL"}
assert "SSH_AUTH_SOCK" not in os.environ
assert "ACTIONS_ID_TOKEN_REQUEST_TOKEN" not in os.environ
assert "ACTIONS_ID_TOKEN_REQUEST_URL" not in os.environ
before = set(sys.modules)
from gateway import lbe_r010_preexec_source
assert "gateway.lbe_r010_preexec_source" not in before
assert "gateway.lbe_r010_preexec_source" in sys.modules
print(json.dumps({"receipt": receipt.receipt_sha256,
                  "helper": receipt.helper_env_sha256}))
"""
    result = _run_fresh(script)
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert len(payload["receipt"]) == 64
    assert len(payload["helper"]) == 64


def test_preimport_gate_denies_if_product_module_loaded_first_and_clears_env():
    script = _bootstrap_script(preload="import gateway.workspaces") + r"""
try:
    scrub_r010_preimport_environment(expected=expected)
except R010PreimportScrubDenied as exc:
    assert str(exc) == "gateway product module loaded before PREEXEC scrub"
    assert dict(os.environ) == {}
else:
    raise AssertionError("product import before PREEXEC scrub was accepted")
"""
    result = _run_fresh(script)
    assert result.returncode == 0, result.stderr


def test_preimport_gate_denies_extra_selector_and_clears_env():
    script = _bootstrap_script(extra='values["HTTP_PROXY"] = "http://bad.example"') + r"""
try:
    scrub_r010_preimport_environment(expected=expected)
except R010PreimportScrubDenied as exc:
    assert str(exc) == "PREEXEC inherited extra/missing keys"
    assert dict(os.environ) == {}
else:
    raise AssertionError("extra selector was accepted")
"""
    result = _run_fresh(script)
    assert result.returncode == 0, result.stderr
