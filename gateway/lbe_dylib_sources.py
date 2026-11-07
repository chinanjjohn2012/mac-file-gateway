"""Actual private Mach-O linked-library candidate graph, with no execution.

The service has already staged a complete selected private bin/go/lib file
set from an operator-controlled source. This module follows ONLY statically
declared Mach-O direct library names that resolve to manifest-pinned private
files, hashes each real selected candidate with nofollow FDs and traverses
bounded nested declarations. System dylibs, indirect dyld resolution,
code-signatures, loaded Python modules and Go module/plugin outputs remain
UNATTESTED. This never imports, loads, runs, signals or authorizes code.
"""
from __future__ import annotations

from dataclasses import dataclass
import posixpath
from typing import TYPE_CHECKING

from .lbe_macho_loader import (
    D4MachOLoaderDenied, D4MachOLoaderObservation,
    inspect_d4_selected_macho_loader,
)
from .lbe_native_loader_set import (
    D4NativeLoaderSetObservation, D4NativeLoaderSetDenied,
)
from .lbe_runtime_source import _below, _canonical, D4RuntimeSourceDenied

if TYPE_CHECKING:
    from .lbe_worker import LbeWorkPlan
    from .workspaces import WorkspaceContext


class D4PrivateDylibDenied(ValueError):
    """Unqualified static private Mach-O dynamic-library source candidate."""


_MAX_LIBRARIES = 64
_MAX_DEPTH = 8
_SYSTEM_PREFIXES = ("/usr/lib/", "/System/Library/")


@dataclass(frozen=True, slots=True)
class D4PrivateDylibCandidateGraph:
    private_native_images: tuple[tuple[str, D4MachOLoaderObservation], ...]
    unverified_system_library_names: tuple[str, ...]
    unresolved_dynamic_loader_names: tuple[str, ...]
    private_declared_sources_inspected: bool = True
    actual_dyld_resolution_verified: bool = False
    dynamically_loaded_all_sources_proven: bool = False
    host_system_library_provenance_attested: bool = False
    host_or_image_attested: bool = False
    physical_resource_domain_attached: bool = False
    native_launch_allowed: bool = False
    status: str = "PRIVATE_MACHO_DECLARED_CANDIDATES_ONLY"


def _anchored(ref: str, caller: str, main_executable: str,
              root: str) -> str | None:
    """Resolve a candidate lexical private path, never a filesystem alias."""
    if ref.startswith("@loader_path/"):
        base, part = posixpath.dirname(caller), ref[len("@loader_path/"):]
    elif ref.startswith("@executable_path/"):
        base, part = posixpath.dirname(main_executable), ref[len("@executable_path/"):]
    elif ref.startswith("/"):
        base, part = "/", ref.lstrip("/")
    else:
        return None
    path = posixpath.normpath(posixpath.join(base, part))
    try:
        _below(root, _canonical(path, "private declared dylib"))
    except D4RuntimeSourceDenied:
        return None
    return path


def _rpath_candidates(ref: str, image: D4MachOLoaderObservation,
                      caller: str, main_executable: str,
                      root: str) -> tuple[str, ...]:
    suffix = ref[len("@rpath/"):]
    candidates = set()
    for entry in image.declared_rpaths:
        base = _anchored(entry, caller, main_executable, root)
        if base is None:
            continue
        derived = _anchored(
            posixpath.join(base, suffix),
            caller, main_executable, root,
        )
        if derived is not None:
            candidates.add(derived)
    return tuple(sorted(candidates))


def inspect_d4_private_dylib_candidates(
    selected: D4NativeLoaderSetObservation, *, private_root: str,
    expected_private_dylibs: tuple[tuple[str, str], ...],
) -> D4PrivateDylibCandidateGraph:
    """Hash bounded directly named PRIVATE dylib files and follow references.

    A source manifest can identify the exact bytes to inspect, but cannot
    attest that dyld will load those files. Unmatched @rpath, host system
    libraries and unselected direct names are retained as explicit gaps.
    The caller MUST already have validated its real private staged manifest,
    and a complete binary graph alone is never an Exec grant.
    """
    if (type(selected) is not D4NativeLoaderSetObservation
            or selected.native_launch_allowed is not False
            or selected.actual_loaded_source_graph_proven is not False
            or type(expected_private_dylibs) is not tuple
            or len(expected_private_dylibs) > _MAX_LIBRARIES):
        raise D4PrivateDylibDenied("untrusted selected loader-set and source list")
    try:
        root = _canonical(private_root, "private root")
        approved: dict[str, str] = {}
        for record in expected_private_dylibs:
            if (type(record) is not tuple or len(record) != 2
                    or type(record[0]) is not str
                    or type(record[1]) is not str
                    or not record[0].endswith(".dylib")
                    or len(record[1]) != 64
                    or any(c not in "0123456789abcdef" for c in record[1])):
                raise D4PrivateDylibDenied("invalid private dylib source lock")
            selected_path = _canonical(root + "/" + record[0], "private dylib")
            _below(root, selected_path)
            if selected_path in approved:
                raise D4PrivateDylibDenied("duplicate private dylib identity")
            approved[selected_path] = record[1]
        images: dict[str, D4MachOLoaderObservation] = {}
        host_system: set[str] = set()
        unresolved: set[str] = set()
        for row in selected.static_selected_executables:
            if (type(row) is not tuple or len(row) != 2
                    or type(row[0]) is not str
                    or type(row[1]) is not D4MachOLoaderObservation
                    or row[1].native_launch_allowed is not False):
                raise D4PrivateDylibDenied("unqualified selected Mach-O set row")
            original = row[1]
            main = _canonical(
                root + "/" + original.selected_relative_executable,
                "selected executable")
            _below(root, main)
            # This is not another copy of the selected native source: it
            # was already hashed in the pinned selected-executable set.
            pending = [(main, main, original, 0)]
            observed_paths: set[str] = set()
            while pending:
                caller, main_exe, image, depth = pending.pop()
                if depth > _MAX_DEPTH:
                    raise D4PrivateDylibDenied("private dylib source graph too deep")
                for name in image.declared_direct_libraries:
                    if any(name.startswith(prefix)
                           for prefix in _SYSTEM_PREFIXES):
                        host_system.add(name)
                        continue
                    if name.startswith("@rpath/"):
                        matches = [
                            path for path in _rpath_candidates(
                                name, image, caller, main_exe, root)
                            if path in approved
                        ]
                        if len(matches) != 1:
                            unresolved.add(name)
                            continue
                        target = matches[0]
                    else:
                        target = _anchored(name, caller, main_exe, root)
                        if target is None or target not in approved:
                            unresolved.add(name)
                            continue
                    if target in observed_paths:
                        continue
                    observed_paths.add(target)
                    if len(observed_paths) > _MAX_LIBRARIES:
                        raise D4PrivateDylibDenied("private loader source count exceeded")
                    parsed = inspect_d4_selected_macho_loader(
                        private_root=root, selected_executable=target,
                        expected_sha256=approved[target])
                    existing = images.get(target)
                    if existing is not None and existing != parsed:
                        raise D4PrivateDylibDenied(
                            "private candidate dylib identity changed between roots")
                    images[target] = parsed
                    pending.append((target, main_exe, parsed, depth + 1))
        return D4PrivateDylibCandidateGraph(
            private_native_images=tuple(sorted(
                ((path[len(root) + 1:], obs) for path, obs in images.items()),
                key=lambda pair: pair[0])),
            unverified_system_library_names=tuple(sorted(host_system)),
            unresolved_dynamic_loader_names=tuple(sorted(unresolved)),
        )
    except (D4MachOLoaderDenied, D4NativeLoaderSetDenied,
            D4RuntimeSourceDenied, ValueError, OSError) as exc:
        if type(exc) is D4PrivateDylibDenied:
            raise
        raise D4PrivateDylibDenied(
            "actual private loader source inspection unavailable") from None


class D4PrivateDylibSourceRecheck:
    """Repeat the pinned private dylib candidate scan at one-use Worker burn."""

    __slots__ = ("_ctx", "_plan", "_root", "_expected", "_set", "_observed")

    def __init__(self, ctx: "WorkspaceContext", plan: "LbeWorkPlan",
                 selected: D4NativeLoaderSetObservation,
                 observation: D4PrivateDylibCandidateGraph, *,
                 private_root: str,
                 expected_private_dylibs: tuple[tuple[str, str], ...]):
        from .lbe_worker import LbeWorkPlan
        from .workspaces import WorkspaceContext
        if (type(ctx) is not WorkspaceContext
                or type(plan) is not LbeWorkPlan
                or type(selected) is not D4NativeLoaderSetObservation
                or type(observation) is not D4PrivateDylibCandidateGraph
                or observation.native_launch_allowed is not False
                or selected.native_launch_allowed is not False):
            raise D4PrivateDylibDenied("invalid private dylib one-use source")
        self._ctx = ctx
        self._plan = plan
        self._root = _canonical(private_root, "private root")
        self._expected = expected_private_dylibs
        self._set = selected
        self._observed = observation

    def check_binding(self, ctx: "WorkspaceContext", plan: "LbeWorkPlan") -> None:
        if ctx is not self._ctx or plan is not self._plan:
            raise D4PrivateDylibDenied("private dylib binding identity changed")

    def recheck_for(self, ctx: "WorkspaceContext", plan: "LbeWorkPlan") -> None:
        self.check_binding(ctx, plan)
        latest = inspect_d4_private_dylib_candidates(
            self._set, private_root=self._root,
            expected_private_dylibs=self._expected)
        if latest != self._observed:
            raise D4PrivateDylibDenied(
                "declared private library bytes or source selection changed")


def authorize_d4_native_from_private_dylibs(_candidate: object) -> None:
    """Even full private file matches do not prove actual loaded source."""
    raise D4PrivateDylibDenied(
        "PRODUCT_T1=NOT_AUTHORIZED: dyld resolver, system image, loaded imports, "
        "whole child-domain and exact owner T1 grant remain unproven"
    )
