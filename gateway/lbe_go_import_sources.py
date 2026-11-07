"""Actual first-party Go direct-import to staged source inventory (safe T0).

This strictly limited source selection reads selected .go/go.mod bytes using
pinned Workspace nofollow descriptors and maps only explicit direct imports
onto fully pinned local first-party or provisioner Go stdlib *source files*.
It does not execute Go, resolve transitive imports/build tags/generated files,
qualify upstream archive/OS runner provenance or grant NativeLauncher/F1.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import re
import stat
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .lbe_product_fixture import D4FixtureCandidate
    from .workspaces import WorkspaceContext


class D4GoImportSourceDenied(ValueError):
    """No complete static direct-import selection from pinned source bytes."""


@dataclass(frozen=True, slots=True)
class D4GoDirectImportObservation:
    module_path: str
    selected_imports: tuple[str, ...]
    first_party_members: tuple[tuple[str, tuple[str, ...]], ...]
    stdlib_stage_members: tuple[tuple[str, tuple[str, ...]], ...]
    status: str = "FIRST_PARTY_DIRECT_IMPORTS_MAPPED_TO_STAGED_GO_SOURCE_T0"
    transitive_import_closure_proven: bool = False
    generated_build_inputs_proven: bool = False
    actual_loaded_source_graph_proven: bool = False
    native_launch_allowed: bool = False


_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
_ID = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns",
       "st_mode", "st_uid", "st_nlink")
_PATH = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_./-]*\Z")
_IDENT = re.compile(rb"[A-Za-z_][A-Za-z0-9_]*")
_MAX_SOURCE = 1024 * 1024
_MAX_TOKENS = 45000


def _controlled(fd: int, *, directory: bool) -> tuple[int, ...]:
    stat_result = os.fstat(fd)
    if (stat_result.st_uid != os.getuid() or stat_result.st_mode & 0o022
            or (not stat.S_ISDIR(stat_result.st_mode) if directory
                else not stat.S_ISREG(stat_result.st_mode))
            or (not directory and stat_result.st_nlink != 1)):
        raise D4GoImportSourceDenied("Go selected source inode unqualified")
    return tuple(getattr(stat_result, field) for field in _ID)


def _selected_bytes(project_fd: int, relative: str,
                    expected_digest: str,
                    expected_identity: tuple[int, ...]) -> bytes:
    parts = relative.split("/")
    if (not parts or any(re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", p)
                         is None or p in (".", "..") for p in parts)):
        raise D4GoImportSourceDenied("unqualified Go source path")
    fd = os.dup(project_fd)
    try:
        _controlled(fd, directory=True)
        for part in parts[:-1]:
            next_fd = os.open(part, _DIR, dir_fd=fd)
            os.close(fd)
            fd = next_fd
            _controlled(fd, directory=True)
        leaf = os.open(parts[-1], _FILE, dir_fd=fd)
        try:
            before = _controlled(leaf, directory=False)
            if (before != expected_identity or not 0 < before[2] <= _MAX_SOURCE):
                raise D4GoImportSourceDenied("Go source inode drift or size")
            result = bytearray()
            while len(result) < before[2]:
                chunk = os.read(leaf, min(65536, before[2] - len(result)))
                if not chunk:
                    raise D4GoImportSourceDenied("Go source truncated")
                result.extend(chunk)
            if (_controlled(leaf, directory=False) != before
                    or hashlib.sha256(result).hexdigest() != expected_digest):
                raise D4GoImportSourceDenied("Go source bytes or inode changed")
            return bytes(result)
        finally:
            os.close(leaf)
    finally:
        os.close(fd)


def _tokens(raw: bytes) -> list[tuple[str, bytes]]:
    """Conservative bounded lexical tokens; never compile or invoke Go."""
    result: list[tuple[str, bytes]] = []
    i = 0
    while i < len(raw):
        b = raw[i]
        if b >= 128 or b == 0:
            raise D4GoImportSourceDenied("unqualified non-ASCII Go input")
        if b in b" \t\r\n":
            i += 1
            continue
        if raw[i:i+2] == b"//":
            end = raw.find(b"\n", i+2)
            i = len(raw) if end < 0 else end+1
            continue
        if raw[i:i+2] == b"/*":
            end = raw.find(b"*/", i+2)
            if end < 0:
                raise D4GoImportSourceDenied("unterminated Go block comment")
            i = end+2
            continue
        if b in (34, 39, 96):
            delim = b
            j = i+1
            while j < len(raw):
                if raw[j] == delim:
                    break
                if raw[j] == 92 and delim != 96:
                    j += 1
                j += 1
            if j >= len(raw):
                raise D4GoImportSourceDenied("unterminated Go string/rune")
            result.append(("string" if delim != 39 else "rune", raw[i+1:j]))
            i = j+1
        else:
            match = _IDENT.match(raw, i)
            if match:
                result.append(("id", match.group(0)))
                i = match.end()
            else:
                result.append(("symbol", raw[i:i+1]))
                i += 1
        if len(result) > _MAX_TOKENS:
            raise D4GoImportSourceDenied("Go token inventory exceeds limit")
    return result


def _direct_imports(raw: bytes) -> tuple[str, ...]:
    tokens = _tokens(raw)
    imports: set[str] = set()

    def import_spec(at: int) -> int:
        if at < len(tokens) and (tokens[at][0] == "id"
                                  or tokens[at] == ("symbol", b".")):
            at += 1  # named, dot or blank alias
        if at >= len(tokens) or tokens[at][0] != "string":
            raise D4GoImportSourceDenied("Go import declaration not qualified")
        value = tokens[at][1]
        try:
            path = value.decode("ascii")
        except UnicodeError:
            raise D4GoImportSourceDenied("Go import path is not ASCII") from None
        if (path == "C" or _PATH.fullmatch(path) is None
                or "//" in path or any(segment in ("", ".", "..")
                                     for segment in path.split("/"))):
            raise D4GoImportSourceDenied("foreign/cgo/invalid Go import source")
        imports.add(path)
        return at+1

    pos = 0
    while pos < len(tokens):
        if tokens[pos] != ("id", b"import"):
            pos += 1
            continue
        pos += 1
        if pos < len(tokens) and tokens[pos] == ("symbol", b"("):
            pos += 1
            while pos < len(tokens) and tokens[pos] != ("symbol", b")"):
                if tokens[pos] == ("symbol", b";"):
                    pos += 1
                    continue
                pos = import_spec(pos)
            if pos >= len(tokens):
                raise D4GoImportSourceDenied("unterminated Go import block")
            pos += 1
        else:
            pos = import_spec(pos)
    return tuple(sorted(imports))


def inspect_d4_go_direct_import_sources(
    ctx: "WorkspaceContext", candidate: "D4FixtureCandidate", *,
    staged_go_manifest: tuple[tuple[str, str | None], ...],
) -> D4GoDirectImportObservation:
    """Bind selected first-party direct imports to P007 candidate source paths.

    The caller must separately validate the full P007 stage archive before
    accepting this partial mapping. No dynamic/transitive Go loader is run.
    """
    from .lbe_product_fixture import D4FixtureCandidate
    from .workspaces import WorkspaceContext

    if (type(ctx) is not WorkspaceContext
            or type(candidate) is not D4FixtureCandidate
            or candidate.plan.cwd != "go-project"
            or candidate.plan.workspace != ctx.name
            or type(staged_go_manifest) is not tuple):
        raise D4GoImportSourceDenied("invalid service-owned Go source request")
    rows = dict(candidate.source_sha256)
    id_rows = dict(candidate.source_identity)
    go_sources = sorted(path for path in rows
                        if path.startswith("go-project/") and path.endswith(".go"))
    if (not go_sources or len(rows) != len(candidate.source_sha256)
            or len(id_rows) != len(candidate.source_identity)
            or set(rows) != set(id_rows)):
        raise D4GoImportSourceDenied("selected first-party source list ambiguous")
    stage_files: dict[str, str] = {}
    for item in staged_go_manifest:
        if (type(item) is not tuple or len(item) != 2
                or type(item[0]) is not str
                or type(item[1]) not in (str, type(None))
                or item[0] in stage_files):
            raise D4GoImportSourceDenied("malformed Go staged source manifest")
        stage_files[item[0]] = item[1]
    root_fd = os.dup(ctx.gateway._root_fd)
    try:
        _controlled(root_fd, directory=True)
        project_fd = os.open("go-project", _DIR, dir_fd=root_fd)
        try:
            _controlled(project_fd, directory=True)
            mod = _selected_bytes(project_fd, "go.mod", rows["go-project/go.mod"],
                                  id_rows["go-project/go.mod"])
            try:
                module_lines = [line[len("module "):].strip()
                                for line in mod.decode("ascii").splitlines()
                                if line.startswith("module ")]
            except UnicodeError:
                raise D4GoImportSourceDenied("Go module source not ASCII") from None
            if len(module_lines) != 1 or _PATH.fullmatch(module_lines[0]) is None:
                raise D4GoImportSourceDenied("Go module identity unavailable")
            module = module_lines[0]
            full_imports: set[str] = set()
            for path in go_sources:
                src = _selected_bytes(project_fd, path[len("go-project/"):],
                                      rows[path], id_rows[path])
                full_imports.update(_direct_imports(src))
        finally:
            os.close(project_fd)
    except (OSError, KeyError, OverflowError, ValueError) as exc:
        if type(exc) is D4GoImportSourceDenied:
            raise
        raise D4GoImportSourceDenied("Go project source mapping unavailable") from None
    finally:
        os.close(root_fd)
    local: list[tuple[str, tuple[str, ...]]] = []
    stdlib: list[tuple[str, tuple[str, ...]]] = []
    for path in sorted(full_imports):
        if path == module or path.startswith(module + "/"):
            suffix = path[len(module):].lstrip("/")
            prefix = "go-project/" + (suffix + "/" if suffix else "")
            members = tuple(sorted(name for name in go_sources
                                   if name.startswith(prefix)
                                   and "/" not in name[len(prefix):]))
            if not members:
                raise D4GoImportSourceDenied("missing first-party imported package")
            local.append((path, members))
        elif "." in path.split("/")[0]:
            raise D4GoImportSourceDenied("unreviewed external Go module import")
        else:
            prefix = "src/" + path + "/"
            members = tuple(sorted(name for name, digest in stage_files.items()
                                   if name.startswith(prefix)
                                   and name.endswith(".go")
                                   and "/" not in name[len(prefix):]
                                   and isinstance(digest, str)))
            if not members:
                raise D4GoImportSourceDenied("Go stdlib import absent from staged source")
            stdlib.append((path, members))
    return D4GoDirectImportObservation(
        module_path=module, selected_imports=tuple(sorted(full_imports)),
        first_party_members=tuple(local), stdlib_stage_members=tuple(stdlib),
    )
