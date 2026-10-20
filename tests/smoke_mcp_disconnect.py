"""Real modern MCP disconnect/timeout contract for a temporary controlled command.

This smoke never touches a user project or executes business Skills. It launches
one loopback-only Gateway and harmless Python scripts inside a TemporaryDirectory.
A disconnected HTTP client need not imply that an already-started command was
cancelled; the Gateway's own timeout and process-group handling still apply.
"""
from __future__ import annotations

import json
import os
import shlex
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

from mcp.types import (
    CLIENT_CAPABILITIES_META_KEY,
    CLIENT_INFO_META_KEY,
    PROTOCOL_VERSION_META_KEY,
)

from smoke_live import smoke_environment


VERSION = "2026-07-28"


def wait_until(predicate, *, seconds=5):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.04)
    return bool(predicate())


def process_exists(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def main():
    package_root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="gateway-mcp-disconnect-") as directory:
        root = Path(directory) / "project"
        jobs = root / "jobs"
        jobs.mkdir(parents=True)
        (jobs / "harmless.py").write_text(
            "import os, sys, time\n"
            "from pathlib import Path\n"
            "mode = sys.argv[1]\n"
            "Path(mode + '.pid').write_text(str(os.getpid()))\n"
            "with Path(mode + '.events').open('a') as f: f.write('started\\n')\n"
            "time.sleep(1.25 if mode == 'disconnect' else 5 if mode == 'timeout' else 0.01)\n"
            "with Path(mode + '.events').open('a') as f: f.write('finished\\n')\n",
            encoding="utf-8",
        )
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            port = reserved.getsockname()[1]
        env = smoke_environment()
        # "python" in the allowlisted argv must resolve to the test venv, on macOS too.
        env["PATH"] = str(Path(sys.executable).parent) + os.pathsep + env.get("PATH", "")
        server = subprocess.Popen(
            [
                sys.executable, "-m", "gateway", "--root", str(root),
                "--port", str(port), "--allow-exec", "--exec-path", "jobs",
            ],
            cwd=package_root,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        base = f"http://127.0.0.1:{port}"
        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "MCP-Protocol-Version": VERSION,
            "Mcp-Method": "tools/call",
            "Mcp-Name": "run_command",
        }
        ids = iter(range(1, 10))

        def body(mode, timeout_seconds=4, dry_run=False):
            return {
                "jsonrpc": "2.0",
                "id": next(ids),
                "method": "tools/call",
                "params": {
                    "_meta": {
                        PROTOCOL_VERSION_META_KEY: VERSION,
                        CLIENT_INFO_META_KEY: {"name": "disconnect-smoke", "version": "1"},
                        CLIENT_CAPABILITIES_META_KEY: {},
                    },
                    "name": "run_command",
                    "arguments": {
                        "cwd": "jobs",
                        "argv": ["python", "harmless.py", mode],
                        "timeout_seconds": timeout_seconds,
                        "dry_run": dry_run,
                    },
                },
            }

        def command(mode, *, timeout_seconds=4, dry_run=False):
            request = urllib.request.Request(
                base + "/mcp", headers=headers,
                data=json.dumps(body(mode, timeout_seconds, dry_run)).encode("utf-8"),
            )
            with opener.open(request, timeout=10) as response:
                assert response.status == 200
                payload = json.load(response)
            assert "result" in payload, payload
            return payload["result"]

        def events(mode):
            path = jobs / (mode + ".events")
            return path.read_text(encoding="utf-8").splitlines() if path.exists() else []

        try:
            def healthy():
                if server.poll() is not None:
                    raise RuntimeError("Temporary Gateway exited: " + server.communicate()[1])
                try:
                    with opener.open(base + "/health", timeout=1) as response:
                        data = json.load(response)
                        return response.status == 200 and data.get("mcp_enabled") is True
                except (OSError, urllib.error.URLError):
                    return False

            assert wait_until(healthy, seconds=10), "Temporary Gateway failed health check"

            # Ordinary synchronous completion still reports an exact result.
            preview = command("normal", dry_run=True)
            assert preview["structuredContent"]["executed"] is False
            assert events("normal") == []
            completed = command("normal")
            assert completed.get("isError", False) is False
            assert completed["structuredContent"]["executed"] is True
            assert completed["structuredContent"]["exit_code"] == 0
            assert events("normal") == ["started", "finished"]

            # Send an actual modern tools/call over TCP, then close the client
            # after the script has confirmed it started; never retry this request.
            raw = json.dumps(body("disconnect")).encode("utf-8")
            wire = (
                f"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
                "Accept: application/json, text/event-stream\r\n"
                "Content-Type: application/json\r\n"
                f"MCP-Protocol-Version: {VERSION}\r\n"
                "Mcp-Method: tools/call\r\nMcp-Name: run_command\r\n"
                f"Content-Length: {len(raw)}\r\nConnection: close\r\n\r\n"
            ).encode("ascii") + raw
            with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
                sock.sendall(wire)
                assert wait_until(
                    lambda: events("disconnect") == ["started"], seconds=5
                ), "Controlled command never started before disconnect"
                sock.shutdown(socket.SHUT_RDWR)
            assert wait_until(
                lambda: events("disconnect") == ["started", "finished"], seconds=5
            ), "Started command was unexpectedly lost after client disconnect"
            disconnected_pid = int((jobs / "disconnect.pid").read_text())
            assert wait_until(lambda: not process_exists(disconnected_pid), seconds=3)
            assert healthy(), "Listener became unavailable after disconnected response"

            # The Gateway retains control of process-group timeout, regardless
            # of how the SDK handles an HTTP client's response lifecycle.
            timed = command("timeout", timeout_seconds=1)
            assert timed.get("isError", False) is False
            assert timed["structuredContent"]["timed_out"] is True
            assert timed["structuredContent"]["exit_code"] is None
            assert events("timeout") == ["started"]
            timed_pid = int((jobs / "timeout.pid").read_text())
            assert wait_until(lambda: not process_exists(timed_pid), seconds=3)
            assert events("timeout") == ["started"]
            assert healthy()

            print(json.dumps({
                "real_mcp_disconnect": "PASS",
                "contract": "disconnect_does_not_cancel_started_command",
                "checks": [
                    "modern_mcp_command_preview",
                    "modern_mcp_command_completion",
                    "disconnect_after_confirmed_start",
                    "no_automatic_retry_or_duplicate",
                    "worker_exits_after_disconnect",
                    "command_timeout_kills_process",
                    "listener_healthy_after_disconnect_and_timeout",
                ],
            }, indent=2))
        finally:
            if server.poll() is None:
                server.terminate()
            try:
                server.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
                server.communicate(timeout=5)




def git_disconnect_smoke():
    """E/T14: native Git commit Hook survives a disconnected modern MCP caller.

    The client sends EXACTLY ONE non-idempotent commit request and drops TCP
    after real Git has launched a hook. There is no automatic client retry.
    """
    package_root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="gateway-git-disconnect-") as path:
        base = Path(path)
        repo = base / "project"
        repo.mkdir()
        def git(*args):
            return subprocess.run(["git", *args], cwd=repo, capture_output=True,
                                  text=True, check=True).stdout.strip()
        git("init", "-q")
        git("config", "user.name", "E disconnect")
        git("config", "user.email", "disconnect@example.invalid")
        tracked = repo / "tracked.txt"
        tracked.write_text("first\n")
        git("add", "tracked.txt")
        git("commit", "-qm", "initial")
        tracked.write_text("second\n")
        git("add", "tracked.txt")

        events = base / "hook.events"
        hook = repo / ".git" / "hooks" / "pre-commit"
        hook.write_text(
            "#!/bin/sh\n"
            f"printf 'started\\n' >> {shlex.quote(str(events))}\n"
            "sleep 1.5\n"
            f"printf 'finished\\n' >> {shlex.quote(str(events))}\n"
        )
        hook.chmod(0o755)
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            port = reserved.getsockname()[1]
        env = smoke_environment()
        env["HOME"] = str(base)
        server = subprocess.Popen(
            [sys.executable, "-m", "gateway", "--root", str(repo),
             "--port", str(port), "--allow-git", "--git-command", "commit",
             "--git-command", "status"],
            cwd=package_root, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        url = f"http://127.0.0.1:{port}"
        def probe():
            if server.poll() is not None:
                raise RuntimeError("E Git smoke Gateway exited: " + server.communicate()[1])
            try:
                with opener.open(url + "/health", timeout=1) as response:
                    return response.status == 200
            except (OSError, urllib.error.URLError):
                return False
        try:
            assert wait_until(probe, seconds=10)
            preview_body = {"command": "commit", "options": {"message": "one Git commit"}}
            preview_req = urllib.request.Request(
                url + "/git/run", data=json.dumps(preview_body).encode(),
                headers={"Content-Type": "application/json"},
            )
            with opener.open(preview_req, timeout=7) as response:
                preview = json.load(response)
            assert preview["dry_run"] is True
            assert preview["execute_started"] is False
            assert not events.exists()

            params = {
                "_meta": {
                    PROTOCOL_VERSION_META_KEY: VERSION,
                    CLIENT_INFO_META_KEY: {"name": "e-git-disconnect", "version": "1"},
                    CLIENT_CAPABILITIES_META_KEY: {},
                },
                "name": "run_git",
                "arguments": {
                    "command": "commit",
                    "options": {"message": "one Git commit"},
                    "timeout_seconds": 20,
                    "dry_run": False,
                },
            }
            wire_body = json.dumps({
                "jsonrpc": "2.0", "id": 991,
                "method": "tools/call", "params": params,
            }).encode()
            wire = (
                f"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
                "Accept: application/json, text/event-stream\r\n"
                "Content-Type: application/json\r\n"
                f"MCP-Protocol-Version: {VERSION}\r\n"
                "Mcp-Method: tools/call\r\nMcp-Name: run_git\r\n"
                f"Content-Length: {len(wire_body)}\r\nConnection: close\r\n\r\n"
            ).encode("ascii") + wire_body

            def events_now():
                return events.read_text().splitlines() if events.exists() else []

            with socket.create_connection(("127.0.0.1", port), timeout=4) as client:
                client.sendall(wire)
                assert wait_until(lambda: events_now() == ["started"], seconds=7), \
                    "Actual pre-commit hook never started"
                client.shutdown(socket.SHUT_RDWR)

            assert wait_until(lambda: events_now() == ["started", "finished"],
                              seconds=7), "Disconnected Git hook did not finish"
            assert wait_until(lambda: git("rev-list", "--count", "HEAD") == "2",
                              seconds=7), "Started Git commit did not finish"
            assert events_now() == ["started", "finished"]
            status_req = urllib.request.Request(
                url + "/git/run",
                data=json.dumps({"command": "status", "dry_run": False}).encode(),
                headers={"Content-Type": "application/json"},
            )
            with opener.open(status_req, timeout=9) as response:
                status = json.load(response)
            assert status["exit_code"] == 0
            assert status["cleanup_status"] == "complete"
            assert not list((base / ".config" / "mac-file-gateway" /
                             "git-legacy-state").iterdir())
            assert probe()
            print(json.dumps({
                "real_git_mcp_disconnect": "PASS",
                "checks": [
                    "native_hook_started_before_tcp_disconnect",
                    "single_non_idempotent_git_commit",
                    "hook_finishes_after_disconnect",
                    "no_automatic_retry",
                    "worker_cleanup_and_status_after_disconnect",
                ],
            }, indent=2))
        finally:
            if server.poll() is None:
                server.terminate()
            try:
                server.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
                server.communicate(timeout=5)

if __name__ == "__main__":
    main()
    git_disconnect_smoke()
