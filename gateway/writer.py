"""Opt-in write policy and bounded previews, shared by MCP and REST."""
from __future__ import annotations

from contextlib import nullcontext
import difflib
import hashlib
import os
import re
import stat
import threading
from typing import Any, TYPE_CHECKING

from .core import FileSnapshot, GatewayError, _integer, _parts, _redact, _sensitive_line_flags
from . import write_storage as storage

if TYPE_CHECKING:
    from .core import Gateway

MAX_DIFF_CHARS = 24_000


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _preview(old: bytes, new: bytes, path: str) -> tuple[str, bool]:
    if len(old) + len(new) > 524_288:
        return "[Diff omitted: input exceeds the preview budget.]", True
    a = old.decode("utf-8").splitlines(keepends=True)
    b = new.decode("utf-8").splitlines(keepends=True)
    if len(a) + len(b) > 2_000:
        return "[Diff omitted: too many lines for the preview budget.]", True
    pieces: list[str] = []
    used = 0
    for line in difflib.unified_diff(a, b, fromfile="a/" + path, tofile="b/" + path):
        if not line.endswith("\n"):
            line += "\n\\ No newline at end of file\n"
        if used + len(line) > MAX_DIFF_CHARS:
            pieces.append(line[:MAX_DIFF_CHARS - used])
            return "".join(pieces), True
        pieces.append(line)
        used += len(line)
    return "".join(pieces), False


class FileWriter:
    def __init__(self, gateway: Gateway, write_paths: tuple[str, ...]):
        self.gateway = gateway
        if isinstance(write_paths, str):
            raise GatewayError("invalid_argument", "write_paths must be a sequence of relative paths.")
        self.paths: tuple[tuple[str, ...], ...] = tuple(_parts(path) for path in write_paths)
        if any(not gateway._allowed(path, is_file=False) for path in self.paths):
            raise GatewayError("blocked_path", "A write scope is excluded by file-access policy.")
        if self.paths and not gateway.allow_write:
            raise GatewayError("invalid_argument", "write_paths requires allow_write.")
        self._lock = threading.RLock()

    def policy(self) -> dict[str, Any]:
        return {"enabled": self.gateway.allow_write,
                "paths": ["/".join(p) or "." for p in self.paths] or ["."],
                "dry_run_default": True, "source_hash_required_for_updates": True,
                "max_file_bytes": self.gateway.limits.max_file_bytes,
                "backup_directory": storage.BACKUP_DIR,
                "max_backup_files": storage.BACKUP_COUNT_LIMIT,
                "max_backup_bytes": storage.BACKUP_BYTES_LIMIT,
                "parent_directories_must_exist": True,  # File operations; mkdir is explicit.
                "directory_creation": {"enabled": self.gateway.allow_write,
                                       "parents_default": False, "exist_ok_default": True,
                                       "max_depth": self.gateway.limits.max_depth, "new_mode": "0700"},
                "scope_matching": "case-exact path components",
                "file_delete": self.gateway.allow_write,
                "file_move": self.gateway.allow_write,
                "directory_delete": False,
                "command_tools": False}

    def _path(self, path: str, *, is_file: bool = True) -> tuple[str, ...]:
        if not self.gateway.allow_write:
            raise GatewayError("write_disabled", "Writes are disabled. Restart locally with --allow-write to enable them.")
        parts = self.gateway._checked(path, is_file=is_file)
        if self.paths and not any(parts[:len(base)] == base for base in self.paths):
            raise GatewayError("write_scope", "This path is outside the explicitly writable scope.")
        return parts

    def _content(self, text: str, *, reject_sensitive: bool = True) -> bytes:
        if not isinstance(text, str):
            raise GatewayError("invalid_argument", "File contents must be a UTF-8 string.")
        if len(text) > self.gateway.limits.max_file_bytes:
            raise GatewayError("too_large", "New file content exceeds the byte limit.")
        try:
            raw = text.encode("utf-8")
        except UnicodeEncodeError:
            raise GatewayError("invalid_argument", "File contents must be valid UTF-8.") from None
        if len(raw) > self.gateway.limits.max_file_bytes:
            raise GatewayError("too_large", "New file content exceeds the byte limit.")
        if b"\x00" in raw:
            raise GatewayError("not_text", "NUL bytes are not allowed in text files.")
        if "[REDACTED]" in text or "[...line truncated...]" in text:
            raise GatewayError("sensitive_content", "Never write redacted or truncated display placeholders back to a file.")
        if reject_sensitive and _redact(text)[1]:
            raise GatewayError("sensitive_content", "Credential-like content is not accepted by this gateway's write policy.")
        return raw

    @staticmethod
    def _visible_match_spans(source_text: str, old_text: str) -> list[tuple[int, int]]:
        flags = _sensitive_line_flags(source_text)
        sensitive_spans: list[tuple[int, int]] = []
        offset = 0
        for line, sensitive in zip(source_text.splitlines(keepends=True), flags):
            end = offset + len(line)
            if sensitive:
                sensitive_spans.append((offset, end))
            offset = end
        matches: list[tuple[int, int]] = []
        start = 0
        sensitive_index = 0
        while True:
            found = source_text.find(old_text, start)
            if found < 0:
                return matches
            match_end = found + len(old_text)
            while sensitive_index < len(sensitive_spans) and sensitive_spans[sensitive_index][1] <= found:
                sensitive_index += 1
            overlaps_sensitive = (
                sensitive_index < len(sensitive_spans)
                and found < sensitive_spans[sensitive_index][1]
                and match_end > sensitive_spans[sensitive_index][0]
            )
            if not overlaps_sensitive:
                matches.append((found, match_end))
            start = match_end

    @staticmethod
    def _replace_spans(source_text: str, spans: list[tuple[int, int]], new_text: str) -> str:
        pieces: list[str] = []
        cursor = 0
        for start, end in spans:
            pieces.append(source_text[cursor:start])
            pieces.append(new_text)
            cursor = end
        pieces.append(source_text[cursor:])
        return "".join(pieces)

    @staticmethod
    def _absent(parent: int, name: str) -> None:
        try:
            os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise GatewayError("already_exists", "Creation refused: the destination already exists.")

    def change(self, operation: str, path: str, *, content: str | None = None,
               old_text: str | None = None, new_text: str | None = None,
               expected_sha256: str | None = None, expected_count: int = 1,
               dry_run: bool = True) -> dict[str, Any]:
        parts = self._path(path)
        if type(dry_run) is not bool:
            raise GatewayError("invalid_argument", "dry_run must be a boolean.")
        if operation != "create":
            if not isinstance(expected_sha256, str) or re.fullmatch("[0-9a-f]{64}", expected_sha256) is None:
                raise GatewayError("invalid_argument", "expected_sha256 must be the 64-character file_sha256 from read_file.")
        if operation == "replace":
            _integer(expected_count, "expected_count", 1, 100)
            if not isinstance(old_text, str) or not old_text:
                raise GatewayError("invalid_argument", "old_text must be a nonempty exact string.")
            self._content(old_text)
            self._content(new_text)
        else:
            self._content(content)
        canonical = "/".join(parts)
        with self._lock, self.gateway._directory(parts[:-1]) as parent:
            context = nullcontext(None) if dry_run else storage.write_lock(self.gateway._root_fd)
            with context as state:
                snapshot: FileSnapshot | None = None
                replacements: int | None = None
                if operation == "create":
                    self._absent(parent, parts[-1])
                    previous = b""
                else:
                    snapshot = self.gateway._snapshot_at(parent, parts[-1])
                    source_has_sensitive = _redact(snapshot.text)[1] > 0
                    if operation == "write" and source_has_sensitive:
                        raise GatewayError("sensitive_content", "This source contains redacted data and cannot be whole-file overwritten through the gateway.")
                    if not snapshot.metadata.st_mode & 0o222:
                        raise GatewayError("write_protected", "Source has no POSIX write bits; change permissions locally before editing.")
                    if snapshot.sha256 != expected_sha256:
                        raise GatewayError("conflict", "Source changed since it was read. Read it again and review a new preview.")
                    previous = snapshot.raw
                if operation == "replace":
                    # Unlike displayed text, this preserves BOM, CRLF, and final newlines.
                    source_text = previous.decode("utf-8")
                    visible_matches = self._visible_match_spans(source_text, old_text)
                    replacements = len(visible_matches)
                    if replacements != expected_count:
                        raise GatewayError("match_count", "Exact-match count differs from expected_count in visible source text; no change was applied.")
                    updated_text = self._replace_spans(source_text, visible_matches, new_text)
                    raw = self._content(updated_text, reject_sensitive=False)
                else:
                    raw = self._content(content)
                changed = snapshot is None or raw != previous
                diff, truncated = _preview(previous, raw, canonical)
                result = {"operation": operation, "path": canonical, "dry_run": dry_run,
                          "applied": False, "changed": changed,
                          "old_sha256": snapshot.sha256 if snapshot else None,
                          "new_sha256": _digest(raw), "size_bytes": len(raw),
                          "diff": diff, "diff_truncated": truncated, "backup_path": None,
                          "warnings": [], "content_trust": "untrusted_file_data"}
                if replacements is not None:
                    result["replacements"] = replacements
                if dry_run or not changed:
                    return result
                if snapshot is not None:
                    assert state is not None
                    result["backup_path"] = storage.save_backup(state, canonical, snapshot.raw, snapshot.sha256)

                def verify() -> None:
                    if snapshot is None:
                        self._absent(parent, parts[-1])
                        return
                    try:
                        latest = self.gateway._snapshot_at(parent, parts[-1])
                    except GatewayError:
                        raise GatewayError("conflict", "Destination changed before commit; read it again.") from None
                    fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
                    if latest.sha256 != snapshot.sha256 or any(getattr(latest.metadata, x) != getattr(snapshot.metadata, x) for x in fields):
                        raise GatewayError("conflict", "Destination changed before commit; read it again.")

                mode = stat.S_IMODE(snapshot.metadata.st_mode) if snapshot else 0o600
                result["warnings"] = storage.install_file(parent, parts[-1], raw, mode, verify, create=snapshot is None)
                result["applied"] = True
                return result
