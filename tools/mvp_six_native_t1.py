"""PR #114: authorized disposable macOS ARM64 six-command native PRODUCT_T1.

This is NOT a SAFE-T0 fake. All 18 positive observations use the actual
WorkspaceService, native LbeWorker/Popen and first-party Python/Pipenv/Go
fixtures on a NEW GitHub-hosted macOS 15 ARM64 runner. REST and SDK MCP
use a real loopback Uvicorn HTTP listener, never a public Tunnel.

No forced kill, process-tree-termination experiment, ambiguous retry,
production resource, real user Workspace, live OIDC or SSH-agent call.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import venv

from mcp.types import (
    CLIENT_CAPABILITIES_META_KEY,
    CLIENT_INFO_META_KEY,
    PROTOCOL_VERSION_META_KEY,
)
import uvicorn

from gateway.http_multi import create_multi_app
from gateway.lbe_mvp_first_setup import initialize_fresh_v2_exec_state
from gateway.lbe_six_fixed_commands import SIX_FIXED_COMMANDS
from gateway.workspaces import ActiveRuntimeInventory, WorkspaceService
from gateway.workspaces_config import parse_workspace_config

REPO = "chinanjjohn2012/mac-file-gateway"
BRANCH = "feat/lbe-five-day-d2-nonoperative-prelaunch-20261106"
WORKFLOW = "six-command-mvp-native-t1-pr114"
MCP_VERSION = "2026-07-28"
ACCEPT = "application/json, text/event-stream"


def require_approved_runner() -> tuple[Path, str, str]:
    # Fail before fixture creation or any product child.
    required = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_REPOSITORY": REPO,
        "GITHUB_HEAD_REF": BRANCH,
        "GITHUB_WORKFLOW": WORKFLOW,
        "RUNNER_OS": "macOS",
        "RUNNER_ARCH": "ARM64",
        "MVP_T1_APPROVED_PR": "114",
    }
    if any(os.environ.get(key) != value for key, value in required.items()):
        raise RuntimeError("T1 runner is outside the PR114 Owner approval")
    if sys.platform != "darwin" or platform.machine().lower() != "arm64":
        raise RuntimeError("T1 requires real GitHub macOS ARM64")
    temp = Path(os.environ.get("RUNNER_TEMP", "")).resolve(strict=True)
    if not temp.is_dir() or not temp.is_absolute():
        raise RuntimeError("T1 runner temporary root unavailable")
    head = subprocess.check_output(
        ["/usr/bin/git", "rev-parse", "HEAD"], text=True).strip()
    tree = subprocess.check_output(
        ["/usr/bin/git", "rev-parse", "HEAD^{tree}"], text=True).strip()
    if head != os.environ.get("G05_EXPECTED_HEAD"):
        raise RuntimeError("G05 checked-out Head and native T1 source differ")
    if len(head) != 40 or len(tree) != 40:
        raise RuntimeError("T1 source identity unavailable")
    return temp, head, tree


def _digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(65536):
            h.update(chunk)
    return h.hexdigest()


def _fixture(root: Path) -> None:
    direct = root / "py-direct"
    (direct / "src").mkdir(parents=True)
    (direct / "src" / "example.py").write_text("ANSWER = 42\n")
    (direct / "test_fixture.py").write_text(
        "from src.example import ANSWER\n"
        "def test_fixture(): assert ANSWER == 42\n")
    (direct / "src" / "__init__.py").write_text("")
    pip = root / "py-pipenv"
    pip.mkdir()
    (pip / "Pipfile").write_text(
        "[packages]\npytest = '*'\n[requires]\npython_version = '3.13'\n")
    venv.EnvBuilder(system_site_packages=True, with_pip=False).create(
        pip / ".venv")
    python = pip / ".venv" / "bin" / "python"
    if not python.is_file() or not os.access(python, os.X_OK):
        raise RuntimeError("Pipenv fixture venv interpreter unavailable")
    (pip / "test_fixture.py").write_text(
        "def test_pipenv_fixture(): assert 21 * 2 == 42\n")
    go = root / "go-project"
    (go / "cmd" / "app").mkdir(parents=True)
    (go / "bin").mkdir()
    (go / "go.mod").write_text(
        "module example.invalid/disposable\n\ngo 1.23.0\n")
    (go / "fixture_test.go").write_text(
        "package fixture\nimport \"testing\"\n"
        "func TestNativeFixture(t *testing.T) { if 6*7 != 42 { t.Fatal(\"fixture\") } }\n")
    (go / "fixture.go").write_text("package fixture\nconst Answer = 42\n")
    (go / "cmd" / "app" / "main.go").write_text(
        "package main\nfunc main() {}\n")


def _choose_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _http(url: str, body: dict | None = None, *,
          headers: dict[str, str] | None = None) -> tuple[int, dict]:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    content = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(
        url, data=content,
        headers=headers or {"Content-Type": "application/json"},
    )
    try:
        with opener.open(req, timeout=150) as r:
            raw = r.read()
            return r.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        return exc.code, json.loads(raw) if raw else {}


def _mcp(base: str, name: str, args: dict, request_id: int) -> dict:
    # This is the actual official SDK-backed MCP streamable HTTP route
    # over the loopback socket, using the tested modern SDK protocol envelope
    # (not an in-process FakeWorker/ASGI TestClient).
    method = "tools/call"
    body = {
        "jsonrpc": "2.0", "id": request_id, "method": method,
        "params": {
            "name": name, "arguments": args,
            "_meta": {
                PROTOCOL_VERSION_META_KEY: MCP_VERSION,
                CLIENT_INFO_META_KEY: {
                    "name": "pr114-authorized-native-t1", "version": "1"},
                CLIENT_CAPABILITIES_META_KEY: {},
            },
        },
    }
    status, result = _http(
        base + "/mcp", body,
        headers={
            "Accept": ACCEPT, "Content-Type": "application/json",
            "MCP-Protocol-Version": MCP_VERSION,
            "Mcp-Method": method,
            "Mcp-Name": name,
        },
    )
    if status != 200 or "result" not in result:
        raise AssertionError(
            f"MCP call rejected: HTTP={status} error={result.get('error')}")
    return result["result"]


def _check_result(result: dict, *, command_id: str, mode: str) -> dict:
    if (result.get("status") != "exited" or result.get("executed") is not True
            or result.get("exit_code") != 0
            or not isinstance(result.get("stdout"), str)
            or not isinstance(result.get("stderr"), str)
            or result.get("workspace") != "a"
            or result.get("timed_out") is not False):
        raise AssertionError(
            f"T1 {mode}/{command_id} failed: "
            f"status={result.get('status')} code={result.get('exit_code')} "
            f"executed={result.get('executed')} "
            f"stderr_prefix={str(result.get('stderr', ''))[:160]!r}")
    observation = {
        "kind": "NATIVE_T1",
        "mode": mode,
        "command_id": command_id,
        "status": result["status"],
        "exit_code": result["exit_code"],
        "executed": True,
        "stdout_chars": len(result["stdout"]),
        "stderr_chars": len(result["stderr"]),
        "output_complete": result.get("output_complete"),
        "process_may_be_running": result.get("process_may_be_running"),
    }
    print("MVP_T1_OBSERVATION=" + json.dumps(observation, sort_keys=True),
          flush=True)
    return observation


def main() -> None:
    temp, head, tree = require_approved_runner()
    pipenv_path = shutil.which("pipenv")
    go_path = shutil.which("go")
    if not pipenv_path or not go_path:
        raise RuntimeError("Native T1 dependencies not installed on runner")
    observations: list[dict] = []
    report = {
        "review_target": "PR114 LBE-SIX-COMMAND-MVP PRODUCT_T1",
        "source_head": head, "source_tree": tree,
        "runner": "GitHub-hosted macos-15 ARM64",
        "contract_blob": "d90df6de3bdbd81a314109d5f73959799b5a10a6",
        "approved_routes": ["Direct", "REST", "MCP"],
        "expected_positive_observations": 18,
        "actual_positive_observations": 0,
        "status": "IN_PROGRESS",
    }
    result_path = temp / "mvp-six-native-t1-result.json"
    with tempfile.TemporaryDirectory(prefix="pr114-mvp-t1-", dir=temp) as d:
        boundary = Path(d)
        root = boundary / "workspaces" / "a"
        root.mkdir(parents=True)
        private = boundary / "private"
        private.mkdir(mode=0o700)
        private.chmod(0o700)
        runtime = boundary / "runtime"
        runtime.mkdir()
        _fixture(root)
        config_file = private / "mvp-exec-tools.json"
        config_file.write_text(json.dumps({
            "executables": {
                "python": sys.executable,
                "pipenv": str(Path(pipenv_path).absolute()),
                "go": str(Path(go_path).absolute()),
            },
        }))
        config_file.chmod(0o600)
        initialize_fresh_v2_exec_state(
            private, operator_confirmed_first_install=True,
            operator_confirmed_gateway_stopped=True,
        )
        config = parse_workspace_config({
            "schema_version": 2,
            "server": {"port": 8765, "transport": "http",
                       "exec": {"enabled": True}},
            "workspaces": {"a": {"root": str(root),
                "exec": {"enabled": True,
                         "paths": ["py-direct", "py-pipenv", "go-project"],
                         "runners": ["py-pipenv=pipenv"]},
            }},
        })
        report["tools"] = {
            "python_path": str(Path(sys.executable).resolve()),
            "pipenv_path": str(Path(pipenv_path).resolve()),
            "go_path": str(Path(go_path).resolve()),
            "python_sha256": _digest(Path(sys.executable).resolve()),
            "pipenv_sha256": _digest(Path(pipenv_path).resolve()),
            "go_sha256": _digest(Path(go_path).resolve()),
        }
        # Diagnose operator-pinned tools without starting or qualifying a
        # child.  This reads ONLY three already selected local executables.
        # Keep the original MvpTrustedTools/WorkspaceService gates unchanged.
        from gateway.lbe_mvp_tools import _snapshot
        from gateway.private_fs import read_private_json, PrivateFileError
        probes = {}
        for name, selected in (
                ("python", sys.executable),
                ("pipenv", str(Path(pipenv_path).absolute())),
                ("go", str(Path(go_path).absolute()))):
            try:
                _snapshot(selected)
            except ValueError as exc:
                # Read-only identity reason for disposable test-selected tools.
                # No path or file content leaves this bounded receipt.
                try:
                    st = os.stat(selected)
                except OSError:
                    probes[name] = {"reason": str(exc), "metadata": "UNAVAILABLE"}
                else:
                    probes[name] = {
                        "reason": str(exc),
                        "regular": stat.S_ISREG(st.st_mode),
                        "executable": os.access(selected, os.X_OK),
                        "owned_by_root_or_runner": st.st_uid in (0, os.geteuid()),
                        "mode": oct(stat.S_IMODE(st.st_mode)),
                        "group_writable": bool(st.st_mode & 0o020),
                        "other_writable": bool(st.st_mode & 0o002),
                    }
            except (OSError, UnicodeError, RuntimeError) as exc:
                probes[name] = "DENY:" + type(exc).__name__
            else:
                probes[name] = "QUALIFIED"
        try:
            read_private_json(config_file)
        except PrivateFileError:
            probes["private_file"] = "DENIED"
        else:
            probes["private_file"] = "READ_OK"
        report["tool_qualification_probe"] = probes
        print("MVP_T1_TOOL_QUALIFICATION=" + json.dumps(
            probes, sort_keys=True), flush=True)
        service = WorkspaceService(
            config, config_dir=private,
            inventory=ActiveRuntimeInventory(paths=(runtime,)),
        )
        port = _choose_port()
        server = None
        thread = None
        try:
            policy = service.info()["exec_policy"]
            # Read-only diagnostic: only booleans/status codes; never tool
            # paths, credentials, retained private records or launch grants.
            admission = {
                "apply_configured": policy["apply_configured"],
                "available": policy["available"],
                "tool_selection_ready": policy["tool_selection_ready"],
                "durability_state": policy["durability_state"],
                "quarantined": policy["quarantined"],
                "owner_unavailable": policy["owner_unavailable"],
                "tool_selection_issue": service._mvp_tools_issue,
                "state_issue": service._exec_state_issue,
            }
            report["admission"] = admission
            print("MVP_T1_ADMISSION=" + json.dumps(admission, sort_keys=True),
                  flush=True)
            if (not policy["apply_configured"] or not policy["available"]
                    or not policy["tool_selection_ready"]):
                raise AssertionError("Native MVP positive Exec admission unavailable")
            for row in SIX_FIXED_COMMANDS:
                result = service.invoke_exec(
                    "a", row.cwd, list(row.requested_argv),
                    timeout_seconds=120, dry_run=False,
                )
                observations.append(_check_result(
                    result, command_id=row.command_id, mode="Direct"))
            app = create_multi_app(service, port=port, enable_mcp=True)
            server = uvicorn.Server(uvicorn.Config(
                app, host="127.0.0.1", port=port, log_level="warning",
                access_log=False, lifespan="on",
            ))
            thread = threading.Thread(
                target=server.run, name="pr114-t1-loopback", daemon=False)
            thread.start()
            base = f"http://127.0.0.1:{port}"
            deadline = time.monotonic() + 20
            while not server.started:
                if not thread.is_alive() or time.monotonic() > deadline:
                    raise RuntimeError("Official MCP/REST loopback listener not ready")
                time.sleep(0.05)
            status, health = _http(base + "/health")
            if status != 200 or not health.get("mcp_enabled"):
                raise AssertionError("Real REST/MCP listener health failed")
            for row in SIX_FIXED_COMMANDS:
                args = {
                    "workspace": "a", "cwd": row.cwd,
                    "argv": list(row.requested_argv),
                    "timeout_seconds": 120, "dry_run": False,
                }
                status, rest = _http(base + "/run", args)
                if status != 200:
                    raise AssertionError(
                        f"REST {row.command_id}: HTTP={status} "
                        f"error={rest.get('error')}")
                observations.append(_check_result(
                    rest, command_id=row.command_id, mode="REST"))
            for idx, row in enumerate(SIX_FIXED_COMMANDS, 1):
                args = {
                    "workspace": "a", "cwd": row.cwd,
                    "argv": list(row.requested_argv),
                    "timeout_seconds": 120, "dry_run": False,
                }
                mcp = _mcp(base, "run_command", args, idx)
                if mcp.get("isError") is True:
                    raise AssertionError(
                        f"MCP {row.command_id} error="
                        f"{mcp.get('structuredContent', {}).get('error')}")
                observations.append(_check_result(
                    mcp["structuredContent"],
                    command_id=row.command_id, mode="MCP"))
            if len(observations) != 18:
                raise AssertionError("T1 expected exactly 18 native executions")
            # Negative controls on each route must NEVER invoke a seventh
            # command or use arbitrary program flags.
            invalid = {
                "workspace": "a", "cwd": "go-project",
                "argv": ["go", "test", "./another"],
                "timeout_seconds": 120, "dry_run": False,
            }
            from gateway.core import GatewayError
            try:
                service.invoke_exec(
                    "a", invalid["cwd"], invalid["argv"],
                    timeout_seconds=120, dry_run=False)
            except GatewayError as exc:
                if exc.code != "command_not_allowed":
                    raise
            else:
                raise AssertionError("Direct allowed a non-six command")
            status, rejected = _http(base + "/run", invalid)
            if status == 200 or rejected.get("error") != "command_not_allowed":
                raise AssertionError("REST allowed a non-six command")
            rejected_mcp = _mcp(base, "run_command", invalid, 100)
            if (not rejected_mcp.get("isError")
                    or rejected_mcp.get("structuredContent", {}).get("error")
                    != "command_not_allowed"):
                raise AssertionError("MCP allowed a non-six command")
            report["status"] = "PASS"
        finally:
            if server is not None:
                server.should_exit = True
            if thread is not None:
                thread.join(timeout=20)
                if thread.is_alive():
                    raise RuntimeError(
                        "T1 loopback service did not stop gracefully; no force kill")
            service.close()
            report["actual_positive_observations"] = len(observations)
            report["observations"] = observations
            result_path.write_text(
                json.dumps(report, indent=2, sort_keys=True) + "\n")
            print("MVP_T1_RESULT=" + json.dumps({
                "status": report["status"],
                "observations": len(observations),
                "expected": 18,
                "source_head": head,
                "source_tree": tree,
            }, sort_keys=True), flush=True)
    if report["status"] != "PASS":
        raise AssertionError("Native T1 did not reach success")


if __name__ == "__main__":
    main()
