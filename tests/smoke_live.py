"""Run actual REST requests against a temporary Uvicorn subprocess.

Uses only temporary test files. It does not open a tunnel or exercise MCP.
Run from any working directory: python tests/smoke_live.py
"""
from __future__ import annotations
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request


def main() -> None:
    package_root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="gateway-live-") as directory:
        root = Path(directory) / "project"
        root.mkdir()
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        process = subprocess.Popen(
            [sys.executable, "-m", "gateway", "--root", str(root), "--port", str(port), "--allow-write", "--http-only"],
            cwd=package_root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

        def request(path: str, data: dict | None = None) -> tuple[int, dict]:
            body = None if data is None else json.dumps(data).encode()
            r = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=body,
                                       headers={"Content-Type": "application/json"})
            try:
                with opener.open(r, timeout=3) as response:
                    return response.status, json.load(response)
            except urllib.error.HTTPError as exc:
                return exc.code, json.load(exc)

        try:
            deadline = time.monotonic() + 10
            while True:
                if process.poll() is not None:
                    raise RuntimeError("Gateway process exited: " + process.communicate()[1])
                try:
                    status, data = request("/health")
                    if status == 200:
                        break
                except (OSError, urllib.error.URLError):
                    pass
                if time.monotonic() >= deadline:
                    raise RuntimeError("Temporary gateway did not become ready")
                time.sleep(0.05)
            assert data["read_only"] is False and data["mcp_enabled"] is False
            mkdir_args = {"path": "src/generated", "parents": True}
            status, preview = request("/mkdir", mkdir_args)
            assert status == 200 and not preview["applied"] and not (root / "src").exists()
            status, created_dir = request("/mkdir", {**mkdir_args, "dry_run": False})
            assert status == 200 and created_dir["created_paths"] == ["src", "src/generated"]
            status, existing = request("/mkdir", {**mkdir_args, "dry_run": False})
            assert status == 200 and existing["already_exists"] and not existing["applied"]
            status, _ = request("/mkdir", {**mkdir_args, "exist_ok": False, "dry_run": False})
            assert status == 409
            status, _ = request("/create", {"path": "src/generated/hello.py", "content": "pass\n", "dry_run": False})
            assert status == 200 and (root / "src/generated/hello.py").read_bytes() == b"pass\n"
            status, _ = request("/mkdir", {"path": "src/generated/hello.py", "dry_run": False})
            assert status == 409
            status, _ = request("/mkdir", {"path": "new/.git/hooks", "parents": True, "dry_run": False})
            assert status == 403 and not (root / "new").exists()
            status, preview = request("/create", {"path": "demo.py", "content": "count = 1\n"})
            assert status == 200 and not preview["applied"] and not (root / "demo.py").exists()
            status, created = request("/create", {"path": "demo.py", "content": "count = 1\n", "dry_run": False})
            assert status == 200 and created["applied"] and (root / "demo.py").read_bytes() == b"count = 1\n"
            status, read = request("/read?path=demo.py")
            assert status == 200
            status, edited = request("/replace", {"path": "demo.py", "old_text": "1", "new_text": "2", "expected_sha256": read["file_sha256"], "dry_run": False})
            assert status == 200 and edited["applied"]
            assert (root / edited["backup_path"]).read_bytes() == b"count = 1\n"
            status, full = request("/write", {"path": "demo.py", "content": "count = 3\n", "expected_sha256": edited["new_sha256"], "dry_run": False})
            assert status == 200 and full["applied"]
            status, error = request("/write", {"path": "demo.py", "content": "stale\n", "expected_sha256": read["file_sha256"], "dry_run": False})
            assert status == 409 and error["error"] == "conflict"
            assert (root / "demo.py").read_bytes() == b"count = 3\n"
            status, _ = request("/create", {"path": "src/move_me.py", "content": "move me\n", "dry_run": False})
            assert status == 200
            status, move_read = request("/read?path=src/move_me.py")
            assert status == 200
            status, move_preview = request("/move", {"source": "src/move_me.py", "destination": "src/generated/moved.py", "expected_sha256": move_read["file_sha256"]})
            assert status == 200 and not move_preview["applied"] and (root / "src/move_me.py").exists()
            status, moved = request("/move", {"source": "src/move_me.py", "destination": "src/generated/moved.py", "expected_sha256": move_read["file_sha256"], "dry_run": False})
            assert status == 200 and moved["applied"] and not (root / "src/move_me.py").exists()
            assert (root / "src/generated/moved.py").read_bytes() == b"move me\n"
            status, moved_read = request("/read?path=src/generated/moved.py")
            assert status == 200
            status, delete_preview = request("/delete", {"path": "src/generated/moved.py", "expected_sha256": moved_read["file_sha256"]})
            assert status == 200 and not delete_preview["applied"] and (root / "src/generated/moved.py").exists()
            status, deleted = request("/delete", {"path": "src/generated/moved.py", "expected_sha256": moved_read["file_sha256"], "dry_run": False})
            assert status == 200 and deleted["applied"] and not (root / "src/generated/moved.py").exists()
            assert (root / deleted["backup_path"]).read_bytes() == b"move me\n"
            status, error = request("/create", {"path": ".env", "content": "hidden", "dry_run": False})
            assert status == 403 and not (root / ".env").exists()
            print(json.dumps({"real_http_listener": "PASS", "checks": ["mkdir_preview", "recursive_mkdir", "existing_directory_noop", "strict_directory_conflict", "file_inside_new_directory", "mkdir_file_conflict", "mkdir_blocked_path", "health", "preview_no_change", "create", "read_raw_hash", "exact_replace", "backup_original_bytes", "whole_file_write", "stale_conflict", "move_preview", "move_apply", "delete_preview", "delete_apply_backup", "hidden_file_blocked"], "mcp_verified": False}, indent=2))
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate(timeout=5)


if __name__ == "__main__":
    main()
