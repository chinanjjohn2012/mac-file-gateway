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
    # Still hash and recheck inactive sources; only their direct import
    # strings are excluded from this Darwin ARM64 static selection.
    inactive_first_party_sources: tuple[str, ...] = ()
    selected_go_command: str = ""
    # This is filename-only stdlib source selection from the full pinned
    # staged archive. Go's actual stdlib build tags, generated inputs and
    # transitive import graph remain unverified by SOURCE/T0.
    stdlib_build_constraints_proven: bool = False
    target_goos: str = "darwin"
    target_goarch: str = "arm64"
    build_constraint_closure_proven: bool = False
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
# Conservative known Go filename selectors. Unknown suffixes are NOT
# silently interpreted as an inactive platform: default is inventorying
# and parsing the file, possibly rejecting an unqualified import.
_GOOS = frozenset((
    "aix", "android", "darwin", "dragonfly", "freebsd", "illumos",
    "ios", "js", "linux", "netbsd", "openbsd", "plan9", "solaris",
    "wasip1", "windows",
))
_GOARCH = frozenset((
    "386", "amd64", "arm", "arm64", "loong64", "mips", "mipsle",
    "mips64", "mips64le", "ppc64", "ppc64le", "riscv64",
    "s390x", "wasm",
))
_MODERN_BUILD = re.compile(rb"(?m)^[ \t]*//go:build[ \t]+([^\r\n]+)")
_LEGACY_BUILD = re.compile(rb"(?m)^[ \t]*//[ \t]+\+build[ \t]+([^\r\n]+)")
_BUILD_DIRECTIVE = re.compile(
    rb"(?m)^[ \t]*//[ \t]*(?:go:build|\+build)(?:[ \t\r]|$)"
)
_BUILD_TOKEN = re.compile(rb"&&|\|\||!|\(|\)|[A-Za-z0-9_.]+")
_MAX_BUILD_TOKENS = 128


def _tag_on_target(name: bytes) -> bool:
    """Only evaluate fixed, independently known Go 1.27.3 darwin/arm64 tags."""
    try:
        tag = name.decode("ascii")
    except UnicodeError:
        raise D4GoImportSourceDenied("unknown Go build tag") from None
    if tag in _GOOS:
        return tag == "darwin"
    if tag in _GOARCH:
        return tag == "arm64"
    if tag == "unix" or tag == "gc":
        return True
    if tag == "cgo":
        return False  # closed R003 effective environment sets CGO_ENABLED=0
    if re.fullmatch(r"go1\.[0-9]{1,2}", tag):
        return 1 <= int(tag[4:]) <= 27
    # Arbitrary -tags, architecture tool tags, experiments and release
    # candidate tags cannot be interpreted by this bounded static source.
    raise D4GoImportSourceDenied("Go custom/tool build tag not qualified")


def _eval_modern_go_build(value: bytes) -> bool:
    """Safe bounded Go //go:build expression subset: !, &&, ||, parentheses."""
    if not 0 < len(value) <= 512:
        raise D4GoImportSourceDenied("Go build expression out of bound")
    tokens: list[bytes] = []
    pos = 0
    while pos < len(value):
        if value[pos] in b" \t":
            pos += 1
            continue
        match = _BUILD_TOKEN.match(value, pos)
        if match is None or len(tokens) >= _MAX_BUILD_TOKENS:
            raise D4GoImportSourceDenied("unknown Go build expression syntax")
        tokens.append(match.group(0))
        pos = match.end()
    if not tokens:
        raise D4GoImportSourceDenied("missing Go build expression")
    position = 0

    def parse_atom(depth: int) -> bool:
        nonlocal position
        if depth > 20 or position >= len(tokens):
            raise D4GoImportSourceDenied("Go build expression nesting/arity invalid")
        token = tokens[position]
        position += 1
        if token == b"!":
            return not parse_atom(depth + 1)
        if token == b"(":
            value = parse_or(depth + 1)
            if position >= len(tokens) or tokens[position] != b")":
                raise D4GoImportSourceDenied("unclosed Go build expression")
            position += 1
            return value
        if token in (b")", b"&&", b"||"):
            raise D4GoImportSourceDenied("invalid Go build expression atom")
        return _tag_on_target(token)

    def parse_and(depth: int) -> bool:
        nonlocal position
        value = parse_atom(depth)
        while position < len(tokens) and tokens[position] == b"&&":
            position += 1
            next_value = parse_atom(depth)
            value = value and next_value
        return value

    def parse_or(depth: int) -> bool:
        nonlocal position
        value = parse_and(depth)
        while position < len(tokens) and tokens[position] == b"||":
            position += 1
            next_value = parse_and(depth)
            value = value or next_value
        return value

    selected = parse_or(0)
    if position != len(tokens):
        raise D4GoImportSourceDenied("Go build expression trailing tokens")
    return selected


def _eval_legacy_go_build(lines: list[bytes]) -> bool:
    """Legacy +build lines: AND lines, OR fields, comma-AND signed tags."""
    if not 1 <= len(lines) <= 16:
        raise D4GoImportSourceDenied("Go legacy build line count invalid")
    accepted = True
    for line in lines:
        if not 0 < len(line) <= 512:
            raise D4GoImportSourceDenied("Go legacy build line too long")
        clauses = line.split()
        if not clauses or len(clauses) > 32:
            raise D4GoImportSourceDenied("Go legacy build clause count invalid")
        line_accepted = False
        for clause in clauses:
            atoms = clause.split(b",")
            if not atoms or len(atoms) > 32:
                raise D4GoImportSourceDenied("Go legacy comma list invalid")
            clause_accepted = True
            for atom in atoms:
                if not atom:
                    raise D4GoImportSourceDenied("empty Go legacy build tag")
                negated = atom.startswith(b"!")
                term = atom[1:] if negated else atom
                if not re.fullmatch(rb"[A-Za-z0-9_.]+", term):
                    raise D4GoImportSourceDenied("invalid Go legacy build tag")
                tag = _tag_on_target(term)
                clause_accepted = clause_accepted and (not tag if negated else tag)
            line_accepted = line_accepted or clause_accepted
        accepted = accepted and line_accepted
    return accepted


def _darwin_arm64_explicit_selected(raw: bytes) -> bool:
    """Recognize bounded explicit Go build tags without running Go.

    Every declared tag is checked, even in a dead boolean branch. Unsupported
    tool/custom tags, wrong placement and contradictory modern/legacy
    directions fail closed. This is static first-party source selection,
    NOT compiler-verified actual loaded-source, release/tool tag or T1 proof.
    """
    modern = _MODERN_BUILD.findall(raw)
    legacy = _LEGACY_BUILD.findall(raw)
    directives = _BUILD_DIRECTIVE.findall(raw)
    if len(directives) != len(modern) + len(legacy):
        raise D4GoImportSourceDenied("ambiguous Go build directive")
    if len(modern) > 1 or len(legacy) > 16:
        raise D4GoImportSourceDenied("duplicate Go build directives")
    if not directives:
        return True
    # Verify the actual leading Go comment region, not a raw grep of all
    # source lines. A copyright /*...*/ block before the build tag is legal;
    # a //go:build marker inside that block or after package is NOT.
    # Legacy +build has an additional blank-line separation requirement:
    # without it Go ignores that old constraint, so treating it as a
    # source-selection condition could silently omit actual compiler input.
    header = raw.splitlines()
    inside_block = False
    package_at = None
    last_legacy_at = None
    for pos, line in enumerate(header):
        stripped = line.strip()
        if inside_block:
            if _BUILD_DIRECTIVE.match(stripped):
                raise D4GoImportSourceDenied(
                    "build tag embedded in Go block comment")
            if b"*/" in stripped:
                inside_block = False
                remainder = stripped.split(b"*/", 1)[1].strip()
                if remainder and not remainder.startswith(b"//"):
                    raise D4GoImportSourceDenied(
                        "ambiguous Go header after block comment")
            continue
        if not stripped:
            continue
        if stripped.startswith(b"/*"):
            if b"*/" in stripped:
                remainder = stripped.split(b"*/", 1)[1].strip()
                if remainder and not remainder.startswith(b"//"):
                    raise D4GoImportSourceDenied(
                        "ambiguous Go header after block comment")
            else:
                inside_block = True
            continue
        if stripped.startswith(b"//"):
            if _LEGACY_BUILD.fullmatch(stripped):
                last_legacy_at = pos
            continue
        if re.match(rb"package[ \t]+[A-Za-z_][A-Za-z0-9_]*", stripped):
            package_at = pos
            break
        raise D4GoImportSourceDenied("unqualified Go build directive header")
    if inside_block or package_at is None:
        raise D4GoImportSourceDenied("Go build source has no valid package header")
    if any(_BUILD_DIRECTIVE.match(line.strip())
           for line in header[package_at:]):
        raise D4GoImportSourceDenied("build tag after Go package clause")
    if (last_legacy_at is not None
            and not any(not line.strip()
                        for line in header[last_legacy_at + 1:package_at])):
        raise D4GoImportSourceDenied(
            "legacy Go build constraints not separated from package")
    # Allow exactly one modern expression plus optional old +build lines.
    modern_selected = _eval_modern_go_build(modern[0]) if modern else None
    legacy_selected = _eval_legacy_go_build(legacy) if legacy else None
    if (modern_selected is not None and legacy_selected is not None
            and modern_selected != legacy_selected):
        raise D4GoImportSourceDenied("divergent Go modern and legacy build tags")
    return modern_selected if modern_selected is not None else legacy_selected


def _darwin_arm64_filename_selected(relative: str) -> bool:
    """Apply only Go's conventional implicit file-name build selectors.

    This is NOT a substitute for the go/build parser, custom -tags, cgo
    or generated sources. Unrecognized patterns are included conservatively.
    The target is fixed by D4 R003 to macOS 15 ARM64; no host GOOS/GOARCH.
    """
    if type(relative) is not str or not relative.endswith(".go"):
        raise D4GoImportSourceDenied("invalid Go source filename")
    stem = relative.rsplit("/", 1)[-1][:-3]
    if stem.endswith("_test"):
        stem = stem[:-5]
    parts = stem.split("_")
    if len(parts) >= 3 and parts[-2] in _GOOS and parts[-1] in _GOARCH:
        return parts[-2] == "darwin" and parts[-1] == "arm64"
    if parts[-1] in _GOOS:
        return parts[-1] == "darwin"
    if parts[-1] in _GOARCH:
        return parts[-1] == "arm64"
    return True


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
    # Keep every ancestor directory FD pinned for the ENTIRE read. Merely
    # checking a source leaf before/after the byte stream misses chmod or
    # ownership/mode drift of an already-open package directory mid-read.
    ancestor_fds = [os.dup(project_fd)]
    ancestor_ids: list[tuple[int, ...]] = []
    try:
        fd = ancestor_fds[-1]
        ancestor_ids.append(_controlled(fd, directory=True))
        for part in parts[:-1]:
            next_fd = os.open(part, _DIR, dir_fd=fd)
            ancestor_fds.append(next_fd)
            fd = next_fd
            ancestor_ids.append(_controlled(fd, directory=True))
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
            if any(_controlled(opened, directory=True) != identity
                   for opened, identity in zip(ancestor_fds, ancestor_ids)):
                raise D4GoImportSourceDenied(
                    "Go source parent metadata changed during read")
            return bytes(result)
        finally:
            os.close(leaf)
    finally:
        for opened in reversed(ancestor_fds):
            os.close(opened)

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
    requested = candidate.plan.requested_argv
    if (type(requested) is not tuple or len(requested) < 3
            or requested[0] != "go"
            or requested[1] not in ("build", "test", "vet")
            or type(candidate.plan.effective_argv) is not tuple
            or candidate.plan.effective_argv != requested):
        raise D4GoImportSourceDenied("unqualified Go action for source selection")
    # go build ignores *_test.go. go test and go vet can inspect test
    # sources; our static selection must not silently omit their imports.
    go_action = requested[1]
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
            active_go_sources: list[str] = []
            inactive_go_sources: list[str] = []
            for path in go_sources:
                # Hash and inode-verify even inactive source files. A later
                # change in either bytes or name needs a fresh candidate.
                raw = _selected_bytes(project_fd, path[len("go-project/"):],
                                      rows[path], id_rows[path])
                if (not _darwin_arm64_filename_selected(path)
                        or (go_action == "build" and path.endswith("_test.go"))
                        or "/testdata/" in path):
                    inactive_go_sources.append(path)
                    continue
                if not _darwin_arm64_explicit_selected(raw):
                    inactive_go_sources.append(path)
                    continue
                active_go_sources.append(path)
                full_imports.update(_direct_imports(raw))
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
            members = tuple(sorted(name for name in active_go_sources
                                   if name.startswith(prefix)
                                   and "/" not in name[len(prefix):]))
            if not members:
                raise D4GoImportSourceDenied("missing first-party imported package")
            local.append((path, members))
        elif "." in path.split("/")[0]:
            raise D4GoImportSourceDenied("unreviewed external Go module import")
        else:
            prefix = "src/" + path + "/"
            members = tuple(sorted(
                name for name, digest in stage_files.items()
                if name.startswith(prefix)
                and name.endswith(".go")
                and not name.endswith("_test.go")
                and "/" not in name[len(prefix):]
                and _darwin_arm64_filename_selected(name)
                and isinstance(digest, str)
                and len(digest) == 64
                and all(ch in "0123456789abcdef" for ch in digest)
            ))
            if not members:
                raise D4GoImportSourceDenied("Go stdlib import absent from staged source")
            stdlib.append((path, members))
    return D4GoDirectImportObservation(
        module_path=module, selected_imports=tuple(sorted(full_imports)),
        first_party_members=tuple(local), stdlib_stage_members=tuple(stdlib),
        inactive_first_party_sources=tuple(inactive_go_sources),
        selected_go_command=go_action,
    )
