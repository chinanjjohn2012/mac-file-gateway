"""Operator grants for exact Hard source lines.

Grants live outside every Workspace. A remote MCP or REST client cannot
create one. Classification stays Hard; a grant only names line text the
local operator has already reviewed.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import sys
import threading
import time
from typing import Any, Callable

from .core import GatewayError, _parts


PENDING_TTL_SECONDS = 600
PENDING_LIMIT = 32


def default_config_dir() -> Path:
    return Path.home() / ".config" / "mac-file-gateway"


def default_grants_path() -> Path:
    return default_config_dir() / "sensitive-grants.json"


def default_socket_path() -> Path:
    """Local socket the operator CLI connects to.

    macOS rejects an AF_UNIX path of 104 bytes or more. A long temporary
    home directory therefore uses a short per-user path instead of the
    config directory.
    """
    preferred = default_config_dir() / "sensitive-approve.sock"
    if len(os.fsencode(preferred)) < 104:
        return preferred
    return Path(f"/tmp/mfg-{os.getuid()}.sock")


def line_sha256(line_text: str) -> str:
    return hashlib.sha256(line_text.encode("utf-8")).hexdigest()


def grants_lock_path(path: str | Path) -> Path:
    target = Path(path)
    return target.with_name(target.name + ".lock")


def announce_pending(pending_id: str, token: str) -> None:
    """Tell the operator the approval capability. Never include source text."""
    print(f"sensitive approval pending_id={pending_id} token={token}", file=sys.stderr)


def _parse_utc(value: str, *, require_future: bool) -> datetime:
    if not isinstance(value, str):
        raise GatewayError("invalid_argument", "Grant expiry must be UTC.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
            raise ValueError
        parsed = parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        raise GatewayError("invalid_argument", "Grant expiry must be UTC.") from None
    if require_future and parsed <= datetime.now(timezone.utc):
        raise GatewayError("invalid_argument", "Grant expiry must be in the future.")
    return parsed


class SensitiveGrantTable:
    """File-backed grants for one Workspace, reloaded when the file changes."""

    def __init__(self, path: str | Path, workspace: str):
        if not isinstance(workspace, str) or not workspace or any(ch in workspace for ch in "/\\"):
            raise GatewayError("invalid_argument", "workspace_name must be a nonempty name.")
        self.path = Path(path)
        self.workspace = workspace
        self._lock = threading.Lock()
        self._mtime_ns: int | None = None
        self._records: list[dict[str, str]] = []
        self._loaded: list[dict[str, Any]] = []

    def line_visible(self, canonical_path: str, line_text: str) -> bool:
        digest = line_sha256(line_text)
        parts = _parts(canonical_path)
        with self._lock:
            self._reload()
            now_mono = time.monotonic()
            now_utc = datetime.now(timezone.utc)
            for grant in self._loaded:
                if grant["workspace"] != self.workspace or grant["line_sha256"] != digest:
                    continue
                prefix = grant["prefix"]
                if parts[:len(prefix)] != prefix:
                    continue
                # A backward wall-clock jump must not extend the monotonic
                # deadline captured when this file version was loaded.
                if now_mono < grant["deadline"] and now_utc < grant["expires_utc"]:
                    return True
            return False

    def status(self) -> dict[str, Any]:
        with self._lock:
            self._reload()
            now_mono = time.monotonic()
            now_utc = datetime.now(timezone.utc)
            active = [
                grant for grant in self._loaded
                if grant["workspace"] == self.workspace
                and now_mono < grant["deadline"]
                and now_utc < grant["expires_utc"]
            ]
            earliest = min((grant["expires_at"] for grant in active), default=None)
            return {"grant_count": len(active), "earliest_expires_at": earliest}

    def add(self, *, path_prefix: str, line_hashes: list[str], expires_at: str) -> dict[str, Any]:
        expiry = _parse_utc(expires_at, require_future=True)
        prefix = _parts(path_prefix)
        if prefix == () and path_prefix != ".":
            raise GatewayError("invalid_argument", "Grant path must be a relative path or '.'.")
        normalized_prefix = "/".join(prefix) or "."
        hashes: list[str] = []
        for digest in line_hashes:
            if not isinstance(digest, str) or len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
                raise GatewayError("invalid_argument", "Grant line hash must be 64 lowercase hex characters.")
            if digest not in hashes:
                hashes.append(digest)
        if not hashes:
            raise GatewayError("invalid_argument", "A grant needs at least one line hash.")
        record_expiry = expiry.isoformat()
        with self._lock:
            self._replace(normalized_prefix, hashes, record_expiry)
        return self.status()

    def _replace(self, normalized_prefix: str, hashes: list[str], record_expiry: str) -> None:
        """Re-read under an exclusive file lock so another Workspace is not lost."""
        parent = self.path.parent
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        lock_path = grants_lock_path(self.path)
        handle = lock_path.open("a+")
        try:
            os.chmod(lock_path, 0o600)
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            self._mtime_ns = None
            self._reload()
            records = [dict(record) for record in self._records]
            for digest in hashes:
                _put_grant(records, self.workspace, normalized_prefix, digest, record_expiry)
            self._write(records)
            self._mtime_ns = None
            self._reload()
        finally:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
            handle.close()

    def _reload(self) -> None:
        try:
            st = self.path.stat()
        except FileNotFoundError:
            self._mtime_ns = None
            self._records = []
            self._loaded = []
            return
        except OSError:
            self._mtime_ns = None
            self._records = []
            self._loaded = []
            return
        if self._mtime_ns == st.st_mtime_ns:
            return
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
            self._mtime_ns = st.st_mtime_ns
            self._records = []
            self._loaded = []
            return
        records: list[dict[str, str]] = []
        loaded: list[dict[str, Any]] = []
        grants = payload.get("grants") if isinstance(payload, dict) and payload.get("schema_version") == 1 else None
        if isinstance(grants, list):
            now = datetime.now(timezone.utc)
            mono = time.monotonic()
            for item in grants:
                record = _record(item)
                if record is None:
                    continue
                records.append(record)
                try:
                    expires = _parse_utc(record["expires_at"], require_future=False)
                    prefix = _parts(record["path_prefix"])
                except GatewayError:
                    continue
                remaining = (expires - now).total_seconds()
                loaded.append({
                    "workspace": record["workspace"],
                    "prefix": prefix,
                    "line_sha256": record["line_sha256"],
                    "expires_at": expires.isoformat(),
                    "expires_utc": expires,
                    "deadline": mono + remaining,
                })
        self._mtime_ns = st.st_mtime_ns
        self._records = records
        self._loaded = loaded

    def _write(self, records: list[dict[str, str]]) -> None:
        parent = self.path.parent
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(parent, 0o700)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        payload = {"schema_version": 1, "grants": records}
        temporary.write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
        os.chmod(temporary, 0o600)
        os.replace(temporary, self.path)
        os.chmod(self.path, 0o600)


def _same_secret(stored: str, supplied: str) -> bool:
    try:
        return secrets.compare_digest(stored, supplied)
    except (TypeError, ValueError):
        return False


def _put_grant(records: list[dict[str, str]], workspace: str, prefix: str,
               digest: str, expires_at: str) -> None:
    for record in records:
        if (record["workspace"] == workspace and record["path_prefix"] == prefix
                and record["line_sha256"] == digest):
            record["expires_at"] = expires_at
            return
    records.append({
        "workspace": workspace,
        "path_prefix": prefix,
        "line_sha256": digest,
        "expires_at": expires_at,
    })


def _record(item: Any) -> dict[str, str] | None:
    if not isinstance(item, dict):
        return None
    workspace = item.get("workspace")
    prefix = item.get("path_prefix")
    digest = item.get("line_sha256")
    expires_at = item.get("expires_at")
    if (not isinstance(workspace, str) or not workspace or any(ch in workspace for ch in "/\\")
            or not isinstance(prefix, str) or not prefix
            or not isinstance(digest, str) or len(digest) != 64
            or any(ch not in "0123456789abcdef" for ch in digest)
            or not isinstance(expires_at, str)):
        return None
    try:
        _parse_utc(expires_at, require_future=False)
        if prefix != ".":
            _parts(prefix)
    except GatewayError:
        return None
    return {
        "workspace": workspace,
        "path_prefix": prefix,
        "line_sha256": digest,
        "expires_at": _parse_utc(expires_at, require_future=False).isoformat(),
    }


class PendingApprovals:
    """In-memory rejected candidates. Restarting the process drops them."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._items: dict[str, dict[str, Any]] = {}

    def remember(self, *, workspace: str, path: str, lines: list[tuple[int, str]]) -> tuple[str, str]:
        pending_id = secrets.token_hex(16)
        token = secrets.token_urlsafe(32)
        stored = [{
            "line": number,
            "text": text,
            "line_sha256": line_sha256(text),
        } for number, text in lines]
        with self._lock:
            self._purge()
            if len(self._items) >= PENDING_LIMIT:
                oldest = min(self._items, key=lambda key: self._items[key]["created"])
                del self._items[oldest]
            self._items[pending_id] = {
                "workspace": workspace,
                "path": path,
                "lines": stored,
                "token": token,
                "created": time.monotonic(),
            }
        return pending_id, token

    def reveal(self, pending_id: str, token: str, *, consume: bool) -> dict[str, Any] | None:
        if not isinstance(pending_id, str) or not isinstance(token, str) or not token:
            return None
        with self._lock:
            self._purge()
            item = self._items.get(pending_id)
            if item is None or not _same_secret(item["token"], token):
                return None
            snapshot = {
                "workspace": item["workspace"],
                "path": item["path"],
                "lines": [dict(line) for line in item["lines"]],
            }
            if consume:
                del self._items[pending_id]
            return snapshot

    def _purge(self) -> None:
        now = time.monotonic()
        expired = [key for key, item in self._items.items() if now - item["created"] >= PENDING_TTL_SECONDS]
        for key in expired:
            del self._items[key]


class ApprovalService:
    """Local review of pending Hard lines. Not an MCP or HTTP tool."""

    def __init__(self) -> None:
        self._gateways: list[Any] = []
        self._lock = threading.Lock()

    def register(self, gateway: Any) -> None:
        with self._lock:
            if gateway not in self._gateways:
                self._gateways.append(gateway)

    def show(self, pending_id: str, token: str) -> dict[str, Any]:
        found = self._find(pending_id, token, consume=False)
        if found is None:
            raise GatewayError("unavailable", "Approval request expired or is unknown.")
        _gateway, pending = found
        return {
            "workspace": pending["workspace"],
            "path": pending["path"],
            "lines": pending["lines"],
        }

    def approve(self, pending_id: str, expires_at: str, path_prefix: str | None,
                confirm: bool, token: str) -> dict[str, Any]:
        if confirm is not True:
            raise GatewayError("invalid_argument", "Approval requires explicit confirmation.")
        found = self._find(pending_id, token, consume=False)
        if found is None:
            raise GatewayError("unavailable", "Approval request expired or is unknown.")
        _parse_utc(expires_at, require_future=True)
        gateway, pending = found
        selected = path_prefix if path_prefix is not None else pending["path"]
        pending_parts = _parts(pending["path"])
        prefix_parts = () if selected == "." else _parts(selected)
        if pending_parts[:len(prefix_parts)] != prefix_parts:
            raise GatewayError("invalid_argument", "Grant path must cover the rejected file.")
        consumed = self._find(pending_id, token, consume=True)
        if consumed is None:
            raise GatewayError("unavailable", "Approval request expired or is unknown.")
        _gateway, pending = consumed
        hashes = []
        for line in pending["lines"]:
            if line["line_sha256"] not in hashes:
                hashes.append(line["line_sha256"])
        return gateway.sensitive_grants.add(
            path_prefix=selected, line_hashes=hashes, expires_at=expires_at,
        )

    def _find(self, pending_id: str, token: str, *, consume: bool) -> tuple[Any, dict[str, Any]] | None:
        with self._lock:
            gateways = list(self._gateways)
        for gateway in gateways:
            pending = gateway.pending.reveal(pending_id, token, consume=False)
            if pending is None or pending["workspace"] != gateway.workspace_name:
                continue
            if consume:
                pending = gateway.pending.reveal(pending_id, token, consume=True)
                if pending is None:
                    return None
            return gateway, pending
        return None


class ApprovalListener:
    """Unix socket the local CLI uses. The agent HTTP/MCP port does not serve it."""

    def __init__(self, service: ApprovalService, path: str | Path | None = None):
        self.service = service
        self.path = Path(path) if path is not None else default_socket_path()
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._closed = False

    def start(self) -> None:
        parent = self.path.parent
        try:
            created = not parent.exists()
            parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            # Never chmod a shared directory such as /tmp. Only a directory
            # this process created belongs to the operator.
            if created:
                os.chmod(parent, 0o700)
        except OSError:
            raise GatewayError("unavailable", "Approval socket could not be opened.") from None
        if self.path.exists():
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                probe.settimeout(0.2)
                probe.connect(str(self.path))
            except OSError:
                try:
                    self.path.unlink()
                except OSError:
                    raise GatewayError("unavailable", "Approval socket could not be replaced.") from None
            else:
                raise GatewayError("unavailable", "Approval socket is already served.")
            finally:
                probe.close()
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.bind(str(self.path))
            os.chmod(self.path, 0o600)
            sock.listen(4)
            sock.settimeout(0.2)
        except OSError:
            sock.close()
            raise GatewayError("unavailable", "Approval socket could not be opened.") from None
        self._sock = sock
        self._thread = threading.Thread(target=self._serve, name="sensitive-approve", daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._closed = True
        sock = self._sock
        self._sock = None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=1)
        try:
            self.path.unlink()
        except OSError:
            pass

    def _serve(self) -> None:
        sock = self._sock
        if sock is None:
            return
        while not self._closed:
            try:
                connection, _address = sock.accept()
            except (TimeoutError, socket.timeout):
                continue
            except OSError:
                return
            threading.Thread(target=self._handle, args=(connection,), daemon=True).start()

    def _handle(self, connection: socket.socket) -> None:
        try:
            connection.settimeout(2)
            chunks = bytearray()
            while b"\n" not in chunks and len(chunks) <= 65536:
                piece = connection.recv(4096)
                if not piece:
                    break
                chunks.extend(piece)
            if b"\n" not in chunks or len(chunks) > 65536:
                response = {"ok": False, "error": "invalid_argument", "message": "Approval request was not a single JSON line."}
            else:
                response = _dispatch(self.service, bytes(chunks.split(b"\n", 1)[0]))
            connection.sendall(json.dumps(response, ensure_ascii=True).encode("ascii") + b"\n")
        except OSError:
            return
        finally:
            try:
                connection.close()
            except OSError:
                pass


def _dispatch(service: ApprovalService, raw: bytes) -> dict[str, Any]:
    try:
        request = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return {"ok": False, "error": "invalid_argument", "message": "Approval request must be JSON."}
    if not isinstance(request, dict):
        return {"ok": False, "error": "invalid_argument", "message": "Approval request must be a JSON object."}
    try:
        op = request.get("op")
        pending_id = request.get("pending_id")
        if not isinstance(pending_id, str) or not pending_id:
            raise GatewayError("invalid_argument", "pending_id is required.")
        token = request.get("token")
        if not isinstance(token, str):
            token = ""
        if op == "show":
            return {"ok": True, **service.show(pending_id, token)}
        if op == "approve":
            prefix = request.get("path_prefix")
            if prefix is not None and not isinstance(prefix, str):
                raise GatewayError("invalid_argument", "path_prefix must be a string.")
            status = service.approve(
                pending_id, request.get("expires_at"), prefix, request.get("confirm") is True, token,
            )
            return {"ok": True, "sensitive_grants": status}
        raise GatewayError("invalid_argument", "Unknown approval operation.")
    except GatewayError as exc:
        # Local socket errors stay generic. Line text is returned only by show.
        return {"ok": False, "error": exc.code, "message": str(exc)}


def approval_request(payload: dict[str, Any], socket_path: str | Path | None = None) -> dict[str, Any]:
    path = Path(socket_path) if socket_path is not None else default_socket_path()
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        connection.settimeout(5)
        connection.connect(str(path))
        connection.sendall(json.dumps(payload).encode("utf-8") + b"\n")
        chunks = bytearray()
        while b"\n" not in chunks and len(chunks) <= 1_048_576:
            piece = connection.recv(65536)
            if not piece:
                break
            chunks.extend(piece)
    except OSError:
        raise GatewayError("unavailable", "Approval socket is not available.") from None
    finally:
        connection.close()
    if b"\n" not in chunks:
        raise GatewayError("unavailable", "Approval socket returned no result.")
    try:
        response = json.loads(bytes(chunks.split(b"\n", 1)[0]).decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise GatewayError("unavailable", "Approval socket returned no result.") from None
    if not isinstance(response, dict):
        raise GatewayError("unavailable", "Approval socket returned no result.")
    return response


def approve_cli(argv: list[str], *, input_fn: Callable[[str], str] | None = None,
                 output_fn: Callable[[str], None] | None = None) -> int:
    import argparse
    import sys
    parser = argparse.ArgumentParser(description="Approve exact Hard source lines already rejected by this machine's Gateway.")
    parser.add_argument("--pending-id", required=True)
    parser.add_argument("--token", required=True, help="Operator token printed by the Gateway, not the pending id")
    parser.add_argument("--expires-at", required=True, help="Absolute UTC expiry, Z or +00:00")
    parser.add_argument("--path-prefix", default=None, help="Relative prefix covering the rejected file; default is that file")
    parser.add_argument("--socket", default=None, help="Local approval socket; default is the Gateway config socket")
    parser.add_argument("--yes", action="store_true", help="Confirm without an interactive prompt")
    args = parser.parse_args(argv)
    emit = output_fn or (lambda line: print(line, file=sys.stderr))
    try:
        shown = approval_request(
            {"op": "show", "pending_id": args.pending_id, "token": args.token}, args.socket,
        )
    except GatewayError as exc:
        emit(f"Gateway: {exc}")
        return 2
    if shown.get("ok") is not True:
        emit(f"Gateway: {shown.get('message', 'Approval request expired or is unknown.')}")
        return 2
    emit(f"workspace: {shown.get('workspace')}")
    emit(f"path: {shown.get('path')}")
    for line in shown.get("lines") or []:
        emit(f"{line.get('line')}: {line.get('text')}")
    if not args.yes:
        reader = input_fn or input
        try:
            answer = reader("Type approve to grant these exact lines: ")
        except EOFError:
            emit("Approval was not confirmed.")
            return 2
        if answer.strip() != "approve":
            emit("Approval was not confirmed.")
            return 2
    try:
        result = approval_request({
            "op": "approve",
            "pending_id": args.pending_id,
            "token": args.token,
            "expires_at": args.expires_at,
            "path_prefix": args.path_prefix,
            "confirm": True,
        }, args.socket)
    except GatewayError as exc:
        emit(f"Gateway: {exc}")
        return 2
    if result.get("ok") is not True:
        emit(f"Gateway: {result.get('message', 'Approval was not recorded.')}")
        return 2
    emit("Grant recorded.")
    return 0
