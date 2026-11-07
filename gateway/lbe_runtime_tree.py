"""Closed staged native-source tree inventory for D4 R003 product preparation.

Checks actual *staged* files/dirs via owner-controlled, nofollow descriptor
walks. The expected complete file set and SHA256 digests must come from an
independently reviewed provisioner, NOT a client request or this scan. This
module neither imports nor executes unqualified foreign code; it cannot attest
what a future interpreter/compiler will actually load, which runner image is
used, nor an OS CPU/RAM resource domain. No receipt confers Exec authority.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import os
import re
import stat


class D4RuntimeTreeDenied(ValueError):
    """Unknown, changing, or unsafe staged executable source tree."""


_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_COMPONENT = re.compile(r"[A-Za-z0-9_.+@-]{1,255}\Z")
_MAX_ENTRIES = 24000
_MAX_DEPTH = 24
_MAX_SINGLE_FILE = 128 * 1024 * 1024
_MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
_FIELDS = ("st_dev", "st_ino", "st_size", "st_mtime_ns",
           "st_ctime_ns", "st_mode", "st_uid", "st_nlink")
# Ordinary Python .pth files can execute import statements at site startup.
# Until there is an independently reviewed site/seed loader selection, reject
# even a correctly hashed .pth. These are source-selection *denials*, not a
# claim that other files cannot import foreign code.
_UNQUALIFIED_STARTUP = frozenset({
    "sitecustomize.py", "usercustomize.py", "__pycache__",
})
# Immutable PR101 P007 source-only Go 1.27.3 darwin-arm64 archive->stage
# CONTENT inventory. The P007 archive SHA is separate, and matching its
# canonical stage digest does NOT attest upstream publisher, provenance,
# loaded compiler/stdlib/modules, or native Go qualification.
# Reference: tools/lbe_p007_go_source_inventory.py, P007 PINNED_*.
_P007_GO_STAGE_FILE_COUNT = 15657
_P007_GO_STAGE_SHA256 = (
    "e43f516501f4e9b07de05dd470ffdab0b4c2acc086acf1e282d39c40fb00dc6a"
)
_P007_GO_CRITICAL_FILES = frozenset({
    "VERSION", "bin/go", "pkg/tool/darwin_arm64/compile",
    "pkg/tool/darwin_arm64/link", "src/runtime/proc.go",
})


@dataclass(frozen=True, slots=True)
class D4ClosedTreeSnapshot:
    relative_root: str
    entry_count: int
    file_count: int
    total_file_bytes: int
    observed_identity_sha256: str
    status: str = "STAGED_CLOSED_FILE_SET_ONLY"
    staged_sources_closed: bool = True
    actual_loader_selected_sources_proven: bool = False
    runner_attested: bool = False
    resource_domain_enforced: bool = False
    native_launch_allowed: bool = False


def _parts(path: object, label: str) -> tuple[str, ...]:
    if (type(path) is not str or not 2 <= len(path) <= 2048
            or not path.startswith("/") or "\\" in path
            or ":" in path or any(ord(c) < 33 or ord(c) >= 127 for c in path)):
        raise D4RuntimeTreeDenied("invalid absolute " + label)
    parts = path[1:].split("/")
    if any(_COMPONENT.fullmatch(p) is None or p in (".", "..")
           for p in parts):
        raise D4RuntimeTreeDenied("noncanonical " + label)
    return tuple(parts)


def _rel(path: object) -> tuple[str, ...]:
    if type(path) is not str or not path:
        raise D4RuntimeTreeDenied("invalid staged relative path")
    parts = path.split("/")
    if (len(parts) > _MAX_DEPTH
            or any(_COMPONENT.fullmatch(p) is None or p in (".", "..")
                   for p in parts)):
        raise D4RuntimeTreeDenied("unqualified staged relative path")
    if any(p in _UNQUALIFIED_STARTUP or p.endswith(".pth") for p in parts):
        raise D4RuntimeTreeDenied("unqualified Python startup source")
    return tuple(parts)


def _identity(fd: int, *, directory: bool) -> tuple[int, ...]:
    st = os.fstat(fd)
    if ((not stat.S_ISDIR(st.st_mode) if directory else
         not stat.S_ISREG(st.st_mode))
            or st.st_uid != os.getuid() or st.st_mode & 0o022
            or (not directory and st.st_nlink != 1)):
        raise D4RuntimeTreeDenied("unsafe staged source inode")
    return tuple(getattr(st, f) for f in _FIELDS)


def _manifest(expected: object) -> dict[str, str | None]:
    if (type(expected) is not tuple
            or not 1 <= len(expected) <= _MAX_ENTRIES):
        raise D4RuntimeTreeDenied("missing bounded exact source manifest")
    entries: dict[str, str | None] = {}
    for row in expected:
        if (type(row) is not tuple or len(row) != 2
                or type(row[0]) is not str
                or type(row[1]) not in (str, type(None))):
            raise D4RuntimeTreeDenied("invalid expected tree row")
        name, digest = row
        if name != "":
            _rel(name)
        if (name in entries or
                (digest is not None and
                 (_SHA.fullmatch(digest) is None or digest == "0" * 64))):
            raise D4RuntimeTreeDenied("duplicate or invalid source manifest")
        entries[name] = digest
    if "" not in entries or entries[""] is not None:
        raise D4RuntimeTreeDenied("expected tree root must be a directory")
    for path in entries:
        if path:
            parent = path.rpartition("/")[0]
            if parent not in entries or entries[parent] is not None:
                raise D4RuntimeTreeDenied("expected parent directory missing")
    return entries


def _root_fd(private: tuple[str, ...],
             selected: tuple[str, ...]) -> int:
    if len(selected) <= len(private) or selected[:len(private)] != private:
        raise D4RuntimeTreeDenied("staged tree outside private runner")
    fd = os.open("/", _DIR_FLAGS)
    try:
        for index, part in enumerate(selected):
            child = os.open(part, _DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
            if index + 1 >= len(private):
                _identity(fd, directory=True)
        return fd
    except BaseException:
        os.close(fd)
        raise


def inspect_d4_closed_staged_tree(
    *, private_root: str, staged_root: str,
    expected: tuple[tuple[str, str | None], ...],
) -> D4ClosedTreeSnapshot:
    """Match the ENTIRE selected tree and metadata, not just listed leaves.

    A successful result only certifies this bounded staged tree's observed
    bytes, names, modes and FD identities at inspection time. Files outside
    this tree, dynamic imports, the process image, shared libraries, symlinks,
    mounts and pathname-exec races remain separately unproven.
    """
    private = _parts(private_root, "private root")
    chosen = _parts(staged_root, "staged root")
    wanted = _manifest(expected)
    count = 0
    file_count = 0
    byte_count = 0
    digest = hashlib.sha256()

    def observe(name: str, sha: str | None, identity: tuple[int, ...]) -> None:
        nonlocal count
        if name not in wanted or wanted[name] != sha:
            raise D4RuntimeTreeDenied("unknown or modified staged tree entry")
        count += 1
        if count > _MAX_ENTRIES:
            raise D4RuntimeTreeDenied("staged source tree exceeds entry limit")
        digest.update(repr((name, sha, identity)).encode("ascii"))
        digest.update(b"\n")

    def bounded_names(fd: int) -> tuple[str, ...]:
        # Do not let a not-yet-approved staging tree force Python's
        # os.listdir() to materialize millions of names before checking
        # the entry budget. Scan the pinned FD with an early cutoff.
        names: list[str] = []
        with os.scandir(fd) as entries:
            for item in entries:
                if len(names) >= _MAX_ENTRIES:
                    raise D4RuntimeTreeDenied("staged source directory too large")
                _rel(item.name)
                names.append(item.name)
        return tuple(sorted(names))

    def walk(fd: int, prefix: str, level: int) -> None:
        nonlocal file_count, byte_count
        before = _identity(fd, directory=True)
        names = bounded_names(fd)
        observe(prefix, None, before)
        for part in names:
            _rel(part)
            name = prefix + "/" + part if prefix else part
            if name not in wanted:
                raise D4RuntimeTreeDenied("unlisted staged source file")
            if wanted[name] is None:
                if level >= _MAX_DEPTH:
                    raise D4RuntimeTreeDenied("staged source tree too deep")
                child = os.open(part, _DIR_FLAGS, dir_fd=fd)
                try:
                    walk(child, name, level + 1)
                finally:
                    os.close(child)
            else:
                child = os.open(part, _FILE_FLAGS, dir_fd=fd)
                try:
                    identity = _identity(child, directory=False)
                    size = identity[2]
                    if (size < 0 or size > _MAX_SINGLE_FILE
                            or byte_count + size > _MAX_TOTAL_BYTES):
                        raise D4RuntimeTreeDenied("staged source byte budget exceeded")
                    stream = hashlib.sha256()
                    remaining = size
                    while remaining:
                        data = os.read(child, min(65536, remaining))
                        if not data:
                            raise D4RuntimeTreeDenied("staged source truncated")
                        stream.update(data)
                        remaining -= len(data)
                    if _identity(child, directory=False) != identity:
                        raise D4RuntimeTreeDenied("staged source inode changed")
                    file_count += 1
                    byte_count += size
                    observe(name, stream.hexdigest(), identity)
                finally:
                    os.close(child)
        if (bounded_names(fd) != names
                or _identity(fd, directory=True) != before):
            raise D4RuntimeTreeDenied("staged source directory drifted")

    try:
        fd = _root_fd(private, chosen)
        try:
            walk(fd, "", 0)
        finally:
            os.close(fd)
    except (OSError, ValueError) as exc:
        if type(exc) is D4RuntimeTreeDenied:
            raise
        raise D4RuntimeTreeDenied("staged source tree cannot be safely read") from None
    if count != len(wanted):
        raise D4RuntimeTreeDenied("expected staged sources not all present")
    return D4ClosedTreeSnapshot(
        relative_root="/".join(chosen[len(private):]),
        entry_count=count, file_count=file_count,
        total_file_bytes=byte_count,
        observed_identity_sha256=digest.hexdigest(),
    )


@dataclass(frozen=True, slots=True)
class D4OperatorSourceManifest:
    """Observed operator bytes for independent review, never a trusted grant.

    The caller must separately approve the exact manifest and trusted provider
    before supplying it to the existing stage/assembly path. A source tree
    cannot vouch for its own origin, selected loader graph or target runner.
    """
    kind: str
    proposed_manifest: tuple[tuple[str, str | None], ...]
    observed_source_identity_sha256: str
    entry_count: int
    file_count: int
    total_file_bytes: int
    status: str = "OBSERVED_OPERATOR_SOURCE_ONLY_NOT_ATTESTED"
    # P007 sorts the COMPLETE "SHA256  ./go/path" lines, not filenames.
    # This is only a reproducible source-byte comparison. The actual P007
    # Go archive and loader graph are NOT verified by this receipt.
    go_p007_stage_manifest_sha256: str | None = None
    go_1_27_3_p007_stage_manifest_matched: bool = False
    trusted_operator_attested: bool = False
    manifest_independently_approved: bool = False
    actual_loaded_source_graph_proven: bool = False
    native_launch_allowed: bool = False


def _observe_d4_selected_source_manifest(
    *, source_root: str, selected_name: str, kind: str, status: str,
) -> D4OperatorSourceManifest:
    """Observe a precise preselected file tree; NEVER infer approval.

    Both the operator's go/bin/lib and the first-party Pipenv .venv use the
    SAME bounded nofollow source stream and full second tree verification.
    The validated bytes are only a proposed source identity at this instant,
    not an independently approved manifest, an import/loader closure or T1.
    """
    parts = _parts(source_root, "selected source parent")
    rows: list[tuple[str, str | None]] = []
    files, total_bytes = 0, 0

    def bounded_names(fd: int) -> tuple[str, ...]:
        names: list[str] = []
        with os.scandir(fd) as iterator:
            for entry in iterator:
                if len(names) >= _MAX_ENTRIES:
                    raise D4RuntimeTreeDenied("operator directory entry limit")
                _rel(entry.name)
                names.append(entry.name)
        return tuple(sorted(names))

    def walk(fd: int, relative: str, depth: int) -> None:
        nonlocal files, total_bytes
        if len(rows) >= _MAX_ENTRIES or depth > _MAX_DEPTH:
            raise D4RuntimeTreeDenied("operator source entry or depth limit")
        initial = _identity(fd, directory=True)
        names = bounded_names(fd)
        rows.append((relative, None))
        for name in names:
            selected = relative + "/" + name if relative else name
            _rel(selected)
            st = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(st.st_mode):
                child = os.open(name, _DIR_FLAGS, dir_fd=fd)
                try:
                    walk(child, selected, depth + 1)
                finally:
                    os.close(child)
            elif stat.S_ISREG(st.st_mode):
                child = os.open(name, _FILE_FLAGS, dir_fd=fd)
                try:
                    initial_file = _identity(child, directory=False)
                    size = initial_file[2]
                    if (len(rows) >= _MAX_ENTRIES
                            or size < 0 or size > _MAX_SINGLE_FILE
                            or total_bytes + size > _MAX_TOTAL_BYTES):
                        raise D4RuntimeTreeDenied(
                            "operator source bytes or entries exceed limit")
                    digest = hashlib.sha256()
                    remaining = size
                    while remaining:
                        data = os.read(child, min(65536, remaining))
                        if not data:
                            raise D4RuntimeTreeDenied(
                                "operator source was truncated")
                        digest.update(data)
                        remaining -= len(data)
                    if _identity(child, directory=False) != initial_file:
                        raise D4RuntimeTreeDenied(
                            "operator file inode changed during snapshot")
                    rows.append((selected, digest.hexdigest()))
                    files += 1
                    total_bytes += size
                finally:
                    os.close(child)
            else:
                raise D4RuntimeTreeDenied(
                    "operator source is neither a private directory nor file")
        if (bounded_names(fd) != names
                or _identity(fd, directory=True) != initial):
            raise D4RuntimeTreeDenied("operator directory drifted")

    try:
        fd = os.open("/", _DIR_FLAGS)
        try:
            for part in parts:
                child = os.open(part, _DIR_FLAGS, dir_fd=fd)
                os.close(fd)
                fd = child
            _identity(fd, directory=True)
            selected = os.open(selected_name, _DIR_FLAGS, dir_fd=fd)
            try:
                walk(selected, "", 0)
            finally:
                os.close(selected)
        finally:
            os.close(fd)
        proposed = tuple(sorted(rows))
        # Re-validate the ENTIRE candidate through the same authoritative
        # staged-tree inspector, including metadata and all paths. This
        # catches drift between initial observation and manifest delivery.
        verified = inspect_d4_closed_staged_tree(
            private_root=source_root,
            staged_root=source_root + "/" + selected_name,
            expected=proposed,
        )
    except (OSError, ValueError) as exc:
        if type(exc) is D4RuntimeTreeDenied:
            raise
        raise D4RuntimeTreeDenied(
            "operator source manifest observation unavailable") from None
    return D4OperatorSourceManifest(
        kind=kind, proposed_manifest=proposed,
        observed_source_identity_sha256=verified.observed_identity_sha256,
        entry_count=verified.entry_count,
        file_count=files, total_file_bytes=total_bytes,
        status=status,
    )


def _d4_p007_go_stage_digest(
    proposed: tuple[tuple[str, str | None], ...],
) -> str:
    """Reproduce the P007 canonical archive-to-stage manifest algorithm.

    The full bounded source tree has ALREADY been nofollow and content/owner
    checked. Compute the SHA-prefixed line sort over regular files ONLY;
    the Go archive P007 input included the leading go/ root in each path.
    This cannot authorize a Go process or establish compiler imports.
    """
    lines = sorted(
        digest + "  ./go/" + name
        for name, digest in proposed if digest is not None
    )
    return hashlib.sha256(("\n".join(lines) + "\n").encode("ascii")).hexdigest()


def observe_d4_operator_source_manifest(
    *, provisioner_root: str, kind: str,
) -> D4OperatorSourceManifest:
    """Expose reviewable go/bin/lib operator bytes without self-approval."""
    if type(kind) is not str or kind not in {"go", "bin", "lib"}:
        raise D4RuntimeTreeDenied("unsupported operator source tree kind")
    observed = _observe_d4_selected_source_manifest(
        source_root=provisioner_root, selected_name=kind, kind=kind,
        status="OBSERVED_OPERATOR_SOURCE_ONLY_NOT_ATTESTED",
    )
    if kind != "go":
        return observed
    stage_sha = _d4_p007_go_stage_digest(observed.proposed_manifest)
    file_names = {
        name for name, digest in observed.proposed_manifest
        if digest is not None
    }
    matches_exact_release = (
        observed.file_count == _P007_GO_STAGE_FILE_COUNT
        and _P007_GO_CRITICAL_FILES.issubset(file_names)
        and stage_sha == _P007_GO_STAGE_SHA256
    )
    return replace(
        observed,
        go_p007_stage_manifest_sha256=stage_sha,
        go_1_27_3_p007_stage_manifest_matched=matches_exact_release,
    )


def observe_d4_pipenv_venv_manifest(
    *, project_root: str,
) -> D4OperatorSourceManifest:
    """Observe real first-party .venv files, including sites, without import.

    This source tree is IN THE WORKSPACE, not the operator provisioner.
    Safe first-party selection, expected exact path and unchanged source
    identity must still be checked by WorkspaceService before/after use.
    Even an exact manifest does NOT prove CPython's effective import paths,
    executable-resolution closure, complete seed/site modules, nor T1 rights.
    """
    return _observe_d4_selected_source_manifest(
        source_root=project_root, selected_name=".venv", kind="venv",
        status="OBSERVED_FIRST_PARTY_VENV_ONLY_NOT_ATTESTED",
    )
