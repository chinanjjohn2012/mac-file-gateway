"""Guarded file deletion and no-clobber move/rename operations."""
from __future__ import annotations

from contextlib import nullcontext
import os
import re
from typing import Any, TYPE_CHECKING

from .core import FileSnapshot, GatewayError
from . import write_storage as storage

if TYPE_CHECKING:
    from .writer import FileWriter

_HASH = re.compile(r"^[0-9a-f]{64}$")
_METADATA_FIELDS = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")


def _expected_hash(value: str | None) -> str:
    if not isinstance(value, str) or _HASH.fullmatch(value) is None:
        raise GatewayError("invalid_argument", "expected_sha256 must be the 64-character file_sha256 from read_file.")
    return value


def _same_snapshot(left: FileSnapshot, right: FileSnapshot) -> bool:
    return left.sha256 == right.sha256 and all(
        getattr(left.metadata, field) == getattr(right.metadata, field)
        for field in _METADATA_FIELDS
    )


def _current(writer: FileWriter, parent: int, name: str, expected_sha256: str) -> FileSnapshot:
    snapshot = writer.gateway._snapshot_at(parent, name)
    if snapshot.sha256 != expected_sha256:
        raise GatewayError("conflict", "Source changed since it was read. Read it again before applying this operation.")
    return snapshot


def delete_file(writer: FileWriter, path: str, expected_sha256: str, dry_run: bool = True) -> dict[str, Any]:
    parts = writer._path(path)
    expected_sha256 = _expected_hash(expected_sha256)
    if type(dry_run) is not bool:
        raise GatewayError("invalid_argument", "dry_run must be a boolean.")
    canonical = "/".join(parts)

    with writer._lock, writer.gateway._directory(parts[:-1]) as parent:
        context = nullcontext(None) if dry_run else storage.write_lock(writer.gateway._root_fd)
        with context as state:
            snapshot = _current(writer, parent, parts[-1], expected_sha256)
            result: dict[str, Any] = {
                "operation": "delete", "path": canonical, "dry_run": dry_run,
                "applied": False, "changed": True,
                "old_sha256": snapshot.sha256, "new_sha256": None,
                "size_bytes": len(snapshot.raw), "backup_path": None,
                "warnings": [], "content_trust": "untrusted_file_data",
            }
            if dry_run:
                return result

            assert state is not None
            result["backup_path"] = storage.save_backup(state, canonical, snapshot.raw, snapshot.sha256)

            def verify() -> None:
                try:
                    latest = writer.gateway._snapshot_at(parent, parts[-1])
                except GatewayError:
                    raise GatewayError("conflict", "Source changed before deletion; read it again.") from None
                if not _same_snapshot(snapshot, latest):
                    raise GatewayError("conflict", "Source changed before deletion; read it again.")

            result["warnings"] = storage.remove_file(parent, parts[-1], verify)
            result["applied"] = True
            return result


def move_file(writer: FileWriter, source: str, destination: str,
              expected_sha256: str, dry_run: bool = True) -> dict[str, Any]:
    source_parts = writer._path(source)
    destination_parts = writer._path(destination)
    expected_sha256 = _expected_hash(expected_sha256)
    if type(dry_run) is not bool:
        raise GatewayError("invalid_argument", "dry_run must be a boolean.")
    if source_parts == destination_parts:
        raise GatewayError("invalid_argument", "Source and destination must be different paths.")
    source_name = "/".join(source_parts)
    destination_name = "/".join(destination_parts)

    with writer._lock, writer.gateway._directory(source_parts[:-1]) as source_parent, writer.gateway._directory(destination_parts[:-1]) as destination_parent:
        context = nullcontext(None) if dry_run else storage.write_lock(writer.gateway._root_fd)
        with context:
            snapshot = _current(writer, source_parent, source_parts[-1], expected_sha256)
            writer._absent(destination_parent, destination_parts[-1])
            result: dict[str, Any] = {
                "operation": "move", "source": source_name, "destination": destination_name,
                "dry_run": dry_run, "applied": False, "changed": True,
                "old_sha256": snapshot.sha256, "new_sha256": snapshot.sha256,
                "size_bytes": len(snapshot.raw), "backup_path": None,
                "warnings": [], "content_trust": "untrusted_file_data",
            }
            if dry_run:
                return result

            def verify() -> None:
                try:
                    latest = writer.gateway._snapshot_at(source_parent, source_parts[-1])
                except GatewayError:
                    raise GatewayError("conflict", "Source changed before move; read it again.") from None
                if not _same_snapshot(snapshot, latest):
                    raise GatewayError("conflict", "Source changed before move; read it again.")
                writer._absent(destination_parent, destination_parts[-1])

            result["warnings"] = storage.move_no_replace(
                source_parent, source_parts[-1], destination_parent, destination_parts[-1], verify
            )
            result["applied"] = True
            return result
