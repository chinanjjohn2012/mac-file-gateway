"""Complete *selected executable set* Mach-O observations for D4 R003.

The product's pinned source includes three Go executables (go/compile/link),
the selected direct Python binary, or the Pipenv script's exact private
Python interpreter. Inspect all selected executable byte streams and direct
Mach-O load declarations via nofollow FDs, with no native subprocess.

This source set is NOT the dynamically selected Go module/test executable
graph, indirect dylib/dependency graph, Python site/seed import closure,
immutable runner image, whole-descendant OS resource domain or T1 grant.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .lbe_macho_loader import (
    D4MachOLoaderObservation, D4MachOLoaderDenied,
    inspect_d4_selected_macho_loader,
)
from .lbe_runtime_source import (
    D4RuntimeSourceObservation, D4RuntimeSourceDenied, _canonical, _below,
)
from .lbe_launch_recipe import D4NativeLaunchRecipe

if TYPE_CHECKING:
    from .lbe_worker import LbeWorkPlan
    from .workspaces import WorkspaceContext


class D4NativeLoaderSetDenied(ValueError):
    """Unqualified pinned runtime selected native executable source set."""


_EXPECTED = {
    "go": (
        "go/bin/go", "go/pkg/tool/darwin_arm64/compile",
        "go/pkg/tool/darwin_arm64/link",
    ),
    "python_direct": ("bin/python",),
    "pipenv": ("bin/pipenv", "py-pipenv/.venv/bin/python"),
}


@dataclass(frozen=True, slots=True)
class D4NativeLoaderSetObservation:
    runtime_kind: str
    static_selected_executables: tuple[
        tuple[str, D4MachOLoaderObservation], ...
    ]
    unresolved_declared_install_names: tuple[str, ...]
    selected_executable_bytes_checked: bool = True
    declared_direct_loader_names_checked: bool = True
    actual_loaded_source_graph_proven: bool = False
    real_dyld_resolution_proven: bool = False
    actual_process_image_attested: bool = False
    whole_child_resource_domain_enforced: bool = False
    native_launch_allowed: bool = False
    status: str = "SELECTED_ARM64_EXECUTABLE_SET_STATIC_ONLY"


def inspect_d4_native_loader_set(
    observation: D4RuntimeSourceObservation,
    recipe: D4NativeLaunchRecipe, *,
    private_root: str,
) -> D4NativeLoaderSetObservation:
    """Match the exact selected service-owned executable inventory."""
    if (type(observation) is not D4RuntimeSourceObservation
            or type(recipe) is not D4NativeLaunchRecipe
            or observation.kind not in _EXPECTED
            or observation.native_launch_allowed is not False
            or observation.actual_import_graph_attested is not False
            or observation.owner_native_t1_grant is not False
            or recipe.native_launch_allowed is not False
            or recipe.actual_loaded_source_graph_proven is not False
            or recipe.physical_cpu_memory_enforcement_proven is not False
            or recipe.owner_t1_grant_present is not False
            or observation.workspace != recipe.workspace):
        raise D4NativeLoaderSetDenied("unqualified candidate/recipe source")
    try:
        root = _canonical(private_root, "runner private root")
        if type(observation.staged_executables) is not tuple:
            raise D4NativeLoaderSetDenied("staged executable source set missing")
        recorded = {}
        for entry in observation.staged_executables:
            if (type(entry) is not tuple or len(entry) != 2
                    or type(entry[0]) is not str
                    or type(entry[1]) is not str
                    or entry[0] in recorded
                    or len(entry[1]) != 64
                    or any(c not in "0123456789abcdef" for c in entry[1])):
                raise D4NativeLoaderSetDenied("invalid static executable source")
            recorded[entry[0]] = entry[1]
        if set(recorded) != set(_EXPECTED[observation.kind]):
            raise D4NativeLoaderSetDenied("missing selected binary toolchain")
        if observation.kind == "pipenv":
            if recipe.resolved_executable != root + "/bin/pipenv":
                raise D4NativeLoaderSetDenied("Pipenv recipe wrong entrypoint")
            chosen = ("py-pipenv/.venv/bin/python",)
        elif observation.kind == "go":
            if recipe.resolved_executable != root + "/go/bin/go":
                raise D4NativeLoaderSetDenied("Go primary recipe changed")
            chosen = _EXPECTED["go"]
        else:
            if recipe.resolved_executable != root + "/bin/python":
                raise D4NativeLoaderSetDenied("direct Python recipe changed")
            chosen = _EXPECTED["python_direct"]
        results: list[tuple[str, D4MachOLoaderObservation]] = []
        for label in chosen:
            if observation.kind == "pipenv":
                # Project-relative staged source label; actual absolute
                # interpreter sits in the checked Workspace project root.
                selected = recipe.working_directory + "/.venv/bin/python"
            else:
                selected = root + "/" + label
            _below(root, _canonical(selected, "selected Mach-O file"))
            image = inspect_d4_selected_macho_loader(
                private_root=root,
                selected_executable=selected,
                expected_sha256=recorded[label],
            )
            results.append((label, image))
        unresolved = tuple(sorted({
            name for _, image in results
            for name in image.unresolved_install_names
        }))
        return D4NativeLoaderSetObservation(
            runtime_kind=observation.kind,
            static_selected_executables=tuple(results),
            unresolved_declared_install_names=unresolved,
        )
    except (D4RuntimeSourceDenied, D4MachOLoaderDenied,
            ValueError) as exc:
        if type(exc) is D4NativeLoaderSetDenied:
            raise
        raise D4NativeLoaderSetDenied(
            "selected ARM64 loader source cannot be verified") from None


class D4NativeLoaderSetRecheck:
    """Recheck exactly this observed selected executable set at one-use burn.

    Only the service can bind a real WorkspaceContext and exact LbeWorkPlan;
    neither an in-memory class nor a forged recheck is a native T1 grant.
    """

    __slots__ = ("_ctx", "_plan", "_root", "_staged", "_recipe",
                 "_observed")

    def __init__(self, ctx: "WorkspaceContext", plan: "LbeWorkPlan",
                 observation: D4RuntimeSourceObservation,
                 recipe: D4NativeLaunchRecipe,
                 loader: D4NativeLoaderSetObservation, *, private_root: str):
        from .lbe_worker import LbeWorkPlan
        from .workspaces import WorkspaceContext

        if (type(ctx) is not WorkspaceContext
                or type(plan) is not LbeWorkPlan
                or type(observation) is not D4RuntimeSourceObservation
                or type(recipe) is not D4NativeLaunchRecipe
                or type(loader) is not D4NativeLoaderSetObservation
                or observation.workspace != ctx.name
                or recipe.workspace != ctx.name
                or loader.runtime_kind != observation.kind
                or recipe.requested_argv != plan.requested_argv
                or recipe.service_effective_argv != plan.effective_argv
                or loader.native_launch_allowed is not False):
            raise D4NativeLoaderSetDenied("invalid one-use loader-set binding")
        root = _canonical(private_root, "private root")
        self._ctx = ctx
        self._plan = plan
        self._root = root
        self._staged = observation
        self._recipe = recipe
        self._observed = loader

    def check_binding(self, ctx: "WorkspaceContext", plan: "LbeWorkPlan") -> None:
        if ctx is not self._ctx or plan is not self._plan:
            raise D4NativeLoaderSetDenied("loader-set context or plan drift")

    def recheck_for(self, ctx: "WorkspaceContext", plan: "LbeWorkPlan") -> None:
        self.check_binding(ctx, plan)
        current = inspect_d4_native_loader_set(
            self._staged, self._recipe, private_root=self._root)
        if current != self._observed:
            raise D4NativeLoaderSetDenied(
                "native selected executable set drifted before Worker")


def authorize_d4_native_from_loader_set(_observation: object) -> None:
    """Static Mach-O source selection never grants native PRODUCT_T1."""
    raise D4NativeLoaderSetDenied(
        "PRODUCT_T1=NOT_AUTHORIZED: actual loaded imports/dylib/Go module "
        "and whole-OS-domain plus independently approved owner grant absent"
    )
