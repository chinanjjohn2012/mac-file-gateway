"""Native macOS ARM64 Multi-Workspace Exec acceptance (temporary loopback only).

Starts an actual Multi Gateway Uvicorn process, sends real TCP REST/MCP
requests, and runs only disposable Python scripts. This does not open a
Tunnel, load Native C, or test an arbitrary user project.
"""
from __future__ import annotations

import itertools
import json
import os
from pathlib import Path
import platform
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

from mcp.types import (
    CLIENT_CAPABILITIES_META_KEY, CLIENT_INFO_META_KEY,
    PROTOCOL_VERSION_META_KEY,
)
from smoke_live import smoke_environment


VERSION = "2026-07-28"
ACCEPT = "application/json, text/event-stream"


def wait_until(predicate, seconds=6):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.04)
    return bool(predicate())


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def events(jobs, mode):
    path = jobs / (mode + ".events")
    return path.read_text().splitlines() if path.exists() else []


def write_disposable_scripts(jobs):
    (jobs / "once.py").write_text("print('multi-arm64-real-exec')\n")
    (jobs / "hold.py").write_text(
        "import sys, time\n"
        "from pathlib import Path\n"
        "mode = sys.argv[1]\n"
        "with Path(mode + '.events').open('a') as f: f.write('started\\n')\n"
        "deadline = time.monotonic() + 12\n"
        "while not Path(mode + '.release').exists():\n"
        "    if time.monotonic() > deadline: raise RuntimeError('fixture release timeout')\n"
        "    time.sleep(.02)\n"
        "with Path(mode + '.events').open('a') as f: f.write('finished\\n')\n"
    )
    (jobs / "heartbeat.py").write_text(
        "import os, time\n"
        "from pathlib import Path\n"
        "Path('linked.child.pid').write_text(str(os.getpid()))\n"
        "while True:\n"
        "    Path('linked.heartbeat').write_text(str(time.monotonic_ns()))\n"
        "    time.sleep(.05)\n"
    )
    (jobs / "parent.py").write_text(
        "import os, subprocess, sys, time\n"
        "from pathlib import Path\n"
        "child = subprocess.Popen([sys.executable, 'heartbeat.py'],\n"
        "    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,\n"
        "    stderr=subprocess.DEVNULL)\n"
        "Path('linked.parent.pid').write_text(str(os.getpid()))\n"
        "while True: time.sleep(.05)\n"
    )


def main():
    assert sys.platform == "darwin" and platform.machine().lower() == "arm64", (
        sys.platform, platform.machine()
    )
    base_repo = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="gateway-multi-macos-") as temporary:
        # macOS /var is often a symlink; strict pinned root requires real path.
        base = Path(temporary).resolve(strict=True)
        a, b = base / "project-a", base / "project-b"
        a.mkdir()
        b.mkdir()
        jobs = a / "jobs"
        jobs.mkdir()
        (b / "readme.txt").write_text("only-b\n")
        write_disposable_scripts(jobs)
        control = base / "control"
        control.mkdir(mode=0o700)
        control.chmod(0o700)
        config = control / "gateway.json"
        port = free_port()
        config.write_text(json.dumps({
            "schema_version": 1,
            "server": {"port": port, "transport": "http",
                       "exec": {"enabled": True}, "git": {"enabled": False}},
            "workspaces": {
                "a": {"root": str(a), "exec": {"enabled": True,
                      "paths": ["jobs"], "runners": ["jobs=direct"]}},
                "b": {"root": str(b)},
            },
        }))
        config.chmod(0o600)
        env = smoke_environment()
        env["PATH"] = str(Path(sys.executable).parent) + os.pathsep + env.get("PATH", "")
        env["HOME"] = str(base)
        proc = subprocess.Popen(
            [sys.executable, "-m", "gateway", "--config", str(config)],
            cwd=base_repo, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, env=env,
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        url = f"http://127.0.0.1:{port}"
        ids = itertools.count(1)
        report = {"platform": platform.platform(),
                  "machine": platform.machine(), "python": sys.version.split()[0],
                  "checks": []}

        def request(path, body=None, headers=None, timeout=12):
            values = {"Content-Type": "application/json", **(headers or {})}
            payload = None if body is None else json.dumps(body).encode("utf-8")
            req = urllib.request.Request(url + path, data=payload, headers=values)
            try:
                with opener.open(req, timeout=timeout) as res:
                    raw = res.read()
                    return res.status, json.loads(raw) if raw else None
            except urllib.error.HTTPError as exc:
                raw = exc.read()
                return exc.code, json.loads(raw) if raw else None

        def exec_rest(script, *args, workspace="a", dry_run=False,
                      timeout_seconds=10):
            return request("/run", {
                "workspace": workspace, "cwd": "jobs",
                "argv": ["python", script, *args],
                "dry_run": dry_run, "timeout_seconds": timeout_seconds,
            }, timeout=timeout_seconds + 10)

        def rpc(method, params=None):
            args = dict(params or {})
            args["_meta"] = {
                PROTOCOL_VERSION_META_KEY: VERSION,
                CLIENT_INFO_META_KEY: {"name": "mac-multi-native-e2e", "version": "1"},
                CLIENT_CAPABILITIES_META_KEY: {},
            }
            headers = {
                "Accept": ACCEPT, "MCP-Protocol-Version": VERSION,
                "Mcp-Method": method,
            }
            if method == "tools/call":
                headers["Mcp-Name"] = args["name"]
            ident = next(ids)
            code, result = request("/mcp", {
                "jsonrpc": "2.0", "id": ident, "method": method, "params": args,
            }, headers, timeout=14)
            assert code == 200 and result["id"] == ident, (method, code, result)
            assert "result" in result, (method, result)
            return result["result"]

        def exec_rpc(script, *args, workspace="a", dry_run=False):
            return rpc("tools/call", {
                "name": "run_command",
                "arguments": {
                    "workspace": workspace, "cwd": "jobs",
                    "argv": ["python", script, *args],
                    "timeout_seconds": 10, "dry_run": dry_run,
                },
            })

        def disconnect(path, payload, *, method=None):
            body = json.dumps(payload).encode("utf-8")
            special = ""
            if method is not None:
                special = (f"MCP-Protocol-Version: {VERSION}\r\n"
                           "Mcp-Method: tools/call\r\n"
                           "Mcp-Name: run_command\r\n"
                           f"Accept: {ACCEPT}\r\n")
            wire = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{port}\r\n"
                "Content-Type: application/json\r\n"
                f"{special}"
                f"Content-Length: {len(body)}\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii") + body
            sock = socket.create_connection(("127.0.0.1", port), timeout=5)
            sock.sendall(wire)
            return sock

        def mcp_wire(mode):
            return {"jsonrpc": "2.0", "id": next(ids), "method": "tools/call",
                    "params": {
                        "_meta": {
                            PROTOCOL_VERSION_META_KEY: VERSION,
                            CLIENT_INFO_META_KEY: {"name": "mac-disconnect", "version": "1"},
                            CLIENT_CAPABILITIES_META_KEY: {},
                        },
                        "name": "run_command",
                        "arguments": {"workspace": "a", "cwd": "jobs",
                                      "argv": ["python", "hold.py", mode],
                                      "dry_run": False, "timeout_seconds": 10},
                    }}

        try:
            def healthy():
                if proc.poll() is not None:
                    raise RuntimeError("Gateway exited: " + proc.communicate()[1])
                try:
                    status, value = request("/health", timeout=1)
                    return status == 200 and value.get("mcp_enabled") is True
                except (OSError, urllib.error.URLError):
                    return False

            assert wait_until(healthy, 12), "Gateway listener never became ready"
            status, info = request("/info")
            assert status == 200 and info["exec_policy"]["available"]
            assert info["exec_policy"]["adapter_exposed"]
            assert info["read_only"] is False and info["file_read_only"] is True
            report["checks"].append("real_macos_arm64_multi_listener")

            code, preview = exec_rest("once.py", dry_run=True)
            assert code == 200 and preview["executed"] is False
            code, applied = exec_rest("once.py")
            assert code == 200 and applied["exit_code"] == 0
            assert "multi-arm64-real-exec" in applied["stdout"]
            code, denied = exec_rest("once.py", workspace="b")
            assert code == 403 and denied["error"] == "exec_disabled"
            report["checks"].append("rest_preview_apply_and_workspace_denial")

            discover = rpc("server/discover")
            assert VERSION in discover["supportedVersions"]
            names = {t["name"] for t in rpc("tools/list")["tools"]}
            assert "run_command" in names
            dry = exec_rpc("once.py", dry_run=True)
            assert dry["structuredContent"]["executed"] is False
            actual = exec_rpc("once.py")
            assert actual["structuredContent"]["exit_code"] == 0
            rejected = exec_rpc("once.py", workspace="b")
            assert rejected["isError"] is True
            report["checks"].append("real_modern_mcp_apply_and_denial")

            # Linked child inherits parent's new session/process group.
            code, timed = exec_rest("parent.py", timeout_seconds=2)
            assert code == 200 and timed["timed_out"] is True
            assert timed["exit_code"] is None
            assert (jobs / "linked.heartbeat").exists()
            sample = (jobs / "linked.heartbeat").read_text()
            time.sleep(0.45)
            assert (jobs / "linked.heartbeat").read_text() == sample, (
                "Linked child still making progress after timeout/group termination"
            )
            report["checks"].append("timeout_stops_linked_child_heartbeat")

            # The real HTTP client sends once, disconnects after start, no retry.
            req = {"workspace": "a", "cwd": "jobs",
                   "argv": ["python", "hold.py", "rest"],
                   "dry_run": False, "timeout_seconds": 10}
            sock = disconnect("/run", req)
            try:
                assert wait_until(lambda: events(jobs, "rest") == ["started"], 6)
                sock.shutdown(socket.SHUT_RDWR)
            finally:
                sock.close()
            code, busy = exec_rest("once.py", dry_run=True)
            assert code == 409 and busy["error"] == "busy"
            code, read = request("/list?workspace=b")
            assert code == 200 and read["workspace"] == "b"
            (jobs / "rest.release").touch()
            assert wait_until(lambda: events(jobs, "rest") == ["started", "finished"], 5)
            assert wait_until(lambda: exec_rest("once.py", dry_run=True)[0] == 200, 5)
            assert events(jobs, "rest") == ["started", "finished"]
            report["checks"].append("real_tcp_rest_disconnect_worker_lease")

            sock = disconnect("/mcp", mcp_wire("mcp"), method="tools/call")
            try:
                assert wait_until(lambda: events(jobs, "mcp") == ["started"], 6)
                sock.shutdown(socket.SHUT_RDWR)
            finally:
                sock.close()
            code, busy = exec_rest("once.py", dry_run=True)
            assert code == 409 and busy["error"] == "busy"
            (jobs / "mcp.release").touch()
            assert wait_until(lambda: events(jobs, "mcp") == ["started", "finished"], 5)
            assert wait_until(lambda: exec_rest("once.py", dry_run=True)[0] == 200, 5)
            assert events(jobs, "mcp") == ["started", "finished"]
            report["checks"].append("real_tcp_mcp_disconnect_worker_lease")

            # During server shutdown, a live started Worker must not be lost.
            sock = disconnect("/run", {
                "workspace": "a", "cwd": "jobs",
                "argv": ["python", "hold.py", "shutdown"],
                "dry_run": False, "timeout_seconds": 10,
            })
            try:
                assert wait_until(lambda: events(jobs, "shutdown") == ["started"], 6)
                sock.shutdown(socket.SHUT_RDWR)
            finally:
                sock.close()
            proc.send_signal(signal.SIGTERM)
            time.sleep(0.4)
            assert proc.poll() is None, "Gateway stopped while controlled Worker remained live"
            assert events(jobs, "shutdown") == ["started"]
            (jobs / "shutdown.release").touch()
            assert wait_until(lambda: events(jobs, "shutdown") ==
                              ["started", "finished"], 6)
            proc.wait(timeout=14)
            assert proc.returncode == 0, f"Gateway shutdown status: {proc.returncode}"
            report["checks"].append("real_listener_shutdown_waits_for_worker")

            report["status"] = "PARTIAL_NATIVE_ACCEPTANCE_PASS"
            report["not_proven"] = [
                "detached_descendant_cleanup_and_fail_closed_quarantine",
                "crash_restart_recovery",
                "real_private_Tunnel",
                "unknown_cleanup_worker_isolation",
            ]
            print(json.dumps({"multi_exec_macos_lifecycle": report}, indent=2))
        finally:
            for name in ("rest", "mcp", "shutdown"):
                (jobs / (name + ".release")).touch()
            # Defensively reap only the PID created by this disposable fixture.
            pid_file = jobs / "linked.child.pid"
            if pid_file.exists():
                try:
                    os.kill(int(pid_file.read_text()), signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
            if proc.poll() is None:
                proc.terminate()
            try:
                proc.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate(timeout=5)


if __name__ == "__main__":
    main()
