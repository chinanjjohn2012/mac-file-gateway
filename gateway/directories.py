"""Bounded, opt-in mkdir. No shell, links, chmod of existing paths, or deletion.

Recursive creation is not a transaction: an I/O failure may leave directories.
Errors carry the relative paths created by this request; never auto-remove them.
"""
from __future__ import annotations

from contextlib import ExitStack, nullcontext
import errno
import os
import stat
from typing import Any, TYPE_CHECKING

from .core import GatewayError
from . import write_storage as storage

if TYPE_CHECKING:
    from .writer import FileWriter

DIRECTORY_MODE = 0o700
MAX_COMPONENT_BYTES = 255
_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _open_child(parent: int, name: str, *, final: bool) -> int | None:
    """Return a pinned, non-symlink directory or None if missing."""
    try:
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(before.st_mode):
        raise GatewayError("blocked_type", "Directory paths must not contain symbolic links.")
    if not stat.S_ISDIR(before.st_mode):
        code = "already_exists" if final else "blocked_type"
        raise GatewayError(code, "A path component exists but is not a directory; nothing will be overwritten.")
    fd = os.open(name, _FLAGS, dir_fd=parent)
    try:
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise GatewayError("conflict", "A directory changed during traversal; inspect it before retrying.")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _plan(writer: FileWriter, parts: tuple[str, ...], parents: bool, exist_ok: bool) -> list[str]:
    missing: list[str] = []
    with ExitStack() as stack:
        parent = os.dup(writer.gateway._root_fd)
        stack.callback(os.close, parent)
        for index, name in enumerate(parts):
            final = index == len(parts) - 1
            child = None if missing else _open_child(parent, name, final=final)
            if child is None:
                if not final and not parents:
                    raise GatewayError("parent_missing", "Parent directory is missing; explicitly use parents=true to create it.")
                path = "/".join(parts[:index + 1])
                # Existing ancestors may be outside the write scope; new ones may not.
                writer._path(path, is_file=False)
                missing.append(path)
            else:
                stack.callback(os.close, child)
                parent = child
                if final and not exist_ok:
                    raise GatewayError("already_exists", "Directory already exists and exist_ok=false.")
    return missing


def _apply(writer: FileWriter, parts: tuple[str, ...], parents: bool, exist_ok: bool,
           created: list[str], warnings: list[str]) -> None:
    with ExitStack() as stack:
        parent = os.dup(writer.gateway._root_fd)
        stack.callback(os.close, parent)
        for index, name in enumerate(parts):
            final = index == len(parts) - 1
            child = _open_child(parent, name, final=final)
            if child is None:
                if not final and not parents:
                    raise GatewayError("parent_missing", "A parent directory disappeared before creation.")
                path = "/".join(parts[:index + 1])
                writer._path(path, is_file=False)
                made = False
                try:
                    os.mkdir(name, mode=DIRECTORY_MODE, dir_fd=parent)
                    created.append(path)  # Record immediately, even if a later open fails.
                    made = True
                except FileExistsError:
                    # A non-cooperating process may create the name after our lookup.
                    if final and not exist_ok:
                        raise GatewayError("already_exists", "Destination appeared before creation; no overwrite was attempted.") from None
                child = _open_child(parent, name, final=final)
                if child is None:
                    raise GatewayError("conflict", "Directory disappeared during creation; inspect the reported paths.")
                stack.callback(os.close, child)
                if made:
                    try:
                        os.fsync(parent)
                    except OSError:
                        warning = "Directory created, but directory sync failed; crash durability is not guaranteed."
                        if warning not in warnings:
                            warnings.append(warning)
            else:
                stack.callback(os.close, child)
                if final and not exist_ok:
                    raise GatewayError("already_exists", "Directory already exists and exist_ok=false.")
            parent = child


def create_directory(writer: FileWriter, path: str, parents: bool = False,
                     exist_ok: bool = True, dry_run: bool = True) -> dict[str, Any]:
    parts = writer._path(path, is_file=False)
    for key, value in (("parents", parents), ("exist_ok", exist_ok), ("dry_run", dry_run)):
        if type(value) is not bool:
            raise GatewayError("invalid_argument", f"{key} must be a boolean.")
    if not parts:
        raise GatewayError("invalid_path", "Select a directory below the project root, not the root itself.")
    if len(parts) > writer.gateway.limits.max_depth or any(len(p.encode("utf-8")) > MAX_COMPONENT_BYTES for p in parts):
        raise GatewayError("invalid_path", "Directory path exceeds the configured depth or 255-byte component limit.")
    canonical = "/".join(parts)
    created: list[str] = []
    warnings: list[str] = []
    result: dict[str, Any] = {
        "operation": "mkdir", "path": canonical, "parents": parents,
        "exist_ok": exist_ok, "dry_run": dry_run, "applied": False,
        "changed": False, "already_exists": False, "planned_paths": [],
        "created_paths": created, "warnings": warnings,
        "content_trust": "untrusted_file_data",
    }
    try:
        with writer._lock:
            missing = _plan(writer, parts, parents, exist_ok)
            result.update(planned_paths=missing, changed=bool(missing), already_exists=not missing)
            if dry_run or not missing:
                return result
            with storage.write_lock(writer.gateway._root_fd):
                # Repeat under the same advisory lock used for guarded file writes.
                missing = _plan(writer, parts, parents, exist_ok)
                result.update(planned_paths=missing, changed=bool(missing), already_exists=not missing)
                if missing:
                    _apply(writer, parts, parents, exist_ok, created, warnings)
                result.update(applied=bool(created), changed=bool(created), already_exists=not created)
                return result
    except (GatewayError, OSError) as exc:
        code = exc.code if isinstance(exc, GatewayError) else "write_failed"
        message = str(exc) if isinstance(exc, GatewayError) else "Directory operation failed; inspect the reported paths before retrying."
        details = {"operation": "mkdir", "path": canonical, "created_paths": list(created),
                   "partial": bool(created), "warnings": list(warnings)}
        raise GatewayError(code, message, details=details) from None



def delete_directory(writer: FileWriter, path: str, dry_run: bool = True) -> dict[str, Any]:
    """Remove exactly one empty directory. No recursive deletion or link following."""
    parts = writer._path(path, is_file=False)
    if type(dry_run) is not bool:
        raise GatewayError("invalid_argument", "dry_run must be a boolean.")
    if not parts:
        raise GatewayError("invalid_path", "Cannot delete the project root.")
    canonical = "/".join(parts)
    with writer._lock, writer.gateway._directory(parts[:-1]) as parent:
        context = nullcontext() if dry_run else storage.write_lock(writer.gateway._root_fd)
        with context:
            fd = _open_child(parent, parts[-1], final=True)
            if fd is None:
                raise GatewayError("unavailable", "Directory does not exist.")
            try:
                original = os.fstat(fd)
                with os.scandir(fd) as entries:
                    if next(entries, None) is not None:
                        raise GatewayError("not_empty", "Directory is not empty; delete its files first.")
                result = {
                    "operation": "rmdir", "path": canonical, "dry_run": dry_run,
                    "applied": False, "changed": True, "warnings": [],
                    "content_trust": "untrusted_file_data",
                }
                if dry_run:
                    return result
                latest = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
                if (not stat.S_ISDIR(latest.st_mode)
                        or (latest.st_dev, latest.st_ino, latest.st_ctime_ns)
                        != (original.st_dev, original.st_ino, original.st_ctime_ns)):
                    raise GatewayError("conflict", "Directory changed before deletion.")
                try:
                    os.rmdir(parts[-1], dir_fd=parent)
                except OSError as exc:
                    if exc.errno in (errno.ENOTEMPTY, errno.EEXIST):
                        raise GatewayError("not_empty", "Directory is no longer empty.") from None
                    raise GatewayError("write_failed", "Directory deletion failed; inspect the path.") from None
                try:
                    os.fsync(parent)
                except OSError:
                    result["warnings"].append(
                        "Directory deleted, but directory sync failed; crash durability is not guaranteed."
                    )
                result["applied"] = True
                return result
            finally:
                os.close(fd)
