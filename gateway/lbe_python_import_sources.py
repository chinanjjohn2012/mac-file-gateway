"""Selected first-party Python source import mapping for D4 SOURCE/T0.

Only reads exact previously-pinned Python source through nofollow owned file
descriptors. AST parsing NEVER imports or executes the source. It classifies
known first-party references, independently reports unknown/third-party and
dynamic imports, and never proves interpreter/site/sys.path loader closure.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
import hashlib
import os
import stat
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .lbe_product_fixture import D4FixtureCandidate
    from .workspaces import WorkspaceContext


class D4PythonImportDenied(ValueError):
    """First-party Python import source cannot be qualified safely."""


@dataclass(frozen=True, slots=True)
class D4PythonSourceImportObservation:
    selected_source_files: tuple[str, ...]
    first_party_import_edges: tuple[tuple[str, str], ...]
    unresolved_external_imports: tuple[str, ...]
    dynamic_import_sites: tuple[str, ...]
    status: str = "SELECTED_STATIC_PYTHON_IMPORT_SOURCES_ONLY"
    actual_sys_path_proven: bool = False
    imported_external_sources_proven: bool = False
    dynamic_import_closure_proven: bool = False
    actual_loaded_source_graph_proven: bool = False
    native_launch_allowed: bool = False


_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
_ID = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns",
       "st_mode", "st_uid", "st_nlink")
_MAX_PY_SOURCE = 1024 * 1024
_MAX_FILES = 128


def _checked_identity(fd: int, *, directory: bool) -> tuple[int, ...]:
    st = os.fstat(fd)
    if (st.st_uid != os.getuid() or st.st_mode & 0o022
            or (not stat.S_ISDIR(st.st_mode) if directory
                else not stat.S_ISREG(st.st_mode))
            or (not directory and st.st_nlink != 1)):
        raise D4PythonImportDenied("Python source inode or mode unqualified")
    return tuple(getattr(st, k) for k in _ID)


def _read_selected(project_fd: int, relative: str, *, project: str,
                   expected_dirs: dict[str, tuple[int, ...]],
                   expected_digest: str,
                   expected_identity: tuple[int, ...]) -> bytes:
    parts = relative.split("/")
    if (not parts or any(not p or p in (".", "..") or "/" in p
                         for p in parts)
            or not relative.endswith(".py")):
        raise D4PythonImportDenied("invalid Python selected source path")
    fd = os.dup(project_fd)
    try:
        if _checked_identity(fd, directory=True) != expected_dirs[project]:
            raise D4PythonImportDenied("Python project directory drift")
        accumulated = project
        for name in parts[:-1]:
            child = os.open(name, _DIR, dir_fd=fd)
            os.close(fd)
            fd = child
            accumulated += "/" + name
            if _checked_identity(fd, directory=True) != expected_dirs[accumulated]:
                raise D4PythonImportDenied("Python package directory drift")
        leaf = os.open(parts[-1], _FILE, dir_fd=fd)
        try:
            before = _checked_identity(leaf, directory=False)
            if (before != expected_identity or not 0 < before[2] <= _MAX_PY_SOURCE):
                raise D4PythonImportDenied("Python source inode or size changed")
            data = bytearray()
            while len(data) < before[2]:
                fragment = os.read(leaf, min(65536, before[2] - len(data)))
                if not fragment:
                    raise D4PythonImportDenied("Python selected source truncated")
                data.extend(fragment)
            if (_checked_identity(leaf, directory=False) != before
                    or hashlib.sha256(data).hexdigest() != expected_digest):
                raise D4PythonImportDenied("Python selected source changed")
            return bytes(data)
        finally:
            os.close(leaf)
    finally:
        os.close(fd)


def _resolve_first_party(module: str,
                         selected: set[str]) -> str | None:
    """Resolve only unambiguous already-inventoried module/package files."""
    parts = module.split(".")
    if not parts or any(not p or not p.isidentifier() for p in parts):
        return None
    base = "/".join(parts)
    for filename in (base + ".py", base + "/__init__.py"):
        if filename in selected:
            return filename
    return None


def _local_import_members(module: str, selected: set[str]) -> tuple[str, ...] | None:
    """Map module and parent initializers, allowing PEP420 namespace parents.

    Parent __init__.py files are executed when importing a package member,
    and thus are real selected first-party inputs. Namespace parents have
    no source bytes of their own and are never passed off as a loaded graph.
    """
    parts = module.split(".")
    if not parts or any(not p or not p.isidentifier() for p in parts):
        return None
    resolved = _resolve_first_party(module, selected)
    prefix = "/".join(parts) + "/"
    if resolved is None and not any(name.startswith(prefix) for name in selected):
        return None
    members = {resolved} if resolved is not None else set()
    for pos in range(1, len(parts)):
        parent = "/".join(parts[:pos]) + "/__init__.py"
        if parent in selected:
            members.add(parent)
    return tuple(sorted(members))


def _classify_source(path: str, raw: bytes,
                     selected: set[str]) -> tuple[set[tuple[str, str]],
                                                   set[str], set[str]]:
    """Extract statically visible import edges; never evaluate source code."""
    try:
        parsed = ast.parse(raw, filename=path, mode="exec")
    except (SyntaxError, UnicodeError, ValueError, MemoryError, RecursionError):
        raise D4PythonImportDenied("selected Python AST cannot be inspected") from None
    edges: set[tuple[str, str]] = set()
    external: set[str] = set()
    dynamic: set[str] = set()
    origin = path[:-3].replace("/", ".")
    # Python 3 package __init__ has a package name, not an __init__ module.
    container = (origin.rsplit(".", 1)[0] if not origin.endswith(".__init__")
                 else origin[:-len(".__init__")])
    for node in ast.walk(parsed):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.name
                if name.startswith(("src.", "tests.")) or name in ("src", "tests"):
                    members = _local_import_members(name, selected)
                    if members is None:
                        raise D4PythonImportDenied("selected first-party import missing")
                    edges.update((path, member) for member in members)
                else:
                    external.add(name)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                package = container.split(".") if container else []
                if node.level > len(package):
                    raise D4PythonImportDenied("relative Python import escapes project")
                head = package[:len(package) - node.level + 1]
                name = ".".join(head + (node.module.split(".") if node.module else []))
                first_party = True
            elif node.module is not None:
                name = node.module
                first_party = (name.startswith(("src.", "tests."))
                               or name in ("src", "tests"))
            else:
                raise D4PythonImportDenied("ambiguous Python import")
            if first_party:
                members = _local_import_members(name, selected)
                if members is None:
                    raise D4PythonImportDenied("selected first-party import missing")
                edges.update((path, member) for member in members)
                # from package import submodule may load a submodule even
                # when the package initializer itself is the base import.
                # A missing child can also be an attribute in __init__, so
                # do not invent a loaded child or falsely deny valid code.
                for alias in node.names:
                    if alias.name == "*":
                        # Runtime-defined exported names are not closed by AST.
                        dynamic.add(path)
                    else:
                        child = _local_import_members(
                            name + "." + alias.name, selected)
                        if child is not None:
                            edges.update((path, member) for member in child)
            else:
                external.add(name)
        elif isinstance(node, ast.Call):
            function = node.func
            if ((isinstance(function, ast.Name)
                 and function.id in ("__import__", "exec", "eval"))
                    or (isinstance(function, ast.Attribute)
                        and function.attr in ("import_module", "exec_module"))):
                dynamic.add(path)
    return edges, external, dynamic


def inspect_d4_python_first_party_import_sources(
    ctx: "WorkspaceContext", candidate: "D4FixtureCandidate",
) -> D4PythonSourceImportObservation:
    """Service-owned source observation, with no native or public Exec grant."""
    from .lbe_product_fixture import D4FixtureCandidate
    from .workspaces import WorkspaceContext

    if (type(ctx) is not WorkspaceContext
            or type(candidate) is not D4FixtureCandidate
            or candidate.plan.workspace != ctx.name
            or candidate.plan.cwd not in ("py-direct", "py-pipenv")):
        raise D4PythonImportDenied("invalid service-owned Python selection")
    project = candidate.plan.cwd
    hashes = dict(candidate.source_sha256)
    identities = dict(candidate.source_identity)
    dirs = dict(candidate.directory_identity)
    selected = {
        path[len(project) + 1:] for path in hashes
        if path.startswith(project + "/") and path.endswith(".py")
    }
    if ((not selected and project == "py-direct")
            or len(selected) > _MAX_FILES
            or len(hashes) != len(candidate.source_sha256)
            or len(identities) != len(candidate.source_identity)
            or len(dirs) != len(candidate.directory_identity)
            or set(hashes) != set(identities)):
        raise D4PythonImportDenied("ambiguous Python source inventory")
    edges: set[tuple[str, str]] = set()
    external: set[str] = set()
    dynamic: set[str] = set()
    root_fd = os.dup(ctx.gateway._root_fd)
    try:
        _checked_identity(root_fd, directory=True)
        project_fd = os.open(project, _DIR, dir_fd=root_fd)
        try:
            for relative in sorted(selected):
                path = project + "/" + relative
                raw = _read_selected(
                    project_fd, relative, project=project,
                    expected_dirs=dirs, expected_digest=hashes[path],
                    expected_identity=identities[path])
                local, unknown, unsafe = _classify_source(relative, raw, selected)
                edges.update(local)
                external.update(unknown)
                dynamic.update(unsafe)
        finally:
            os.close(project_fd)
    except (OSError, KeyError, OverflowError):
        raise D4PythonImportDenied("Python selected source inaccessible") from None
    finally:
        os.close(root_fd)
    return D4PythonSourceImportObservation(
        selected_source_files=tuple(sorted(selected)),
        first_party_import_edges=tuple(sorted(edges)),
        unresolved_external_imports=tuple(sorted(external)),
        dynamic_import_sites=tuple(sorted(dynamic)),
    )
