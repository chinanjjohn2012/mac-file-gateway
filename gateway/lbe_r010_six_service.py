"""R010 complete SIX-row source binding on one live WorkspaceService.

This is the actual shared-service source selection and recheck, not six
independent client/REST/MCP previews or an execution approval. All rows use
one WorkspaceContext and the existing D4 first-party source inventory; a
stale row/Workspace/plan cannot be swapped into a future private Worker.
PRODUCT_T1 remains gated on independent current-Head B1 qualification,
provider Job, original Owner grant, runtime resources and native evidence.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .lbe_product_fixture import D4FixtureCandidate
from .lbe_r010_row_fs import (
    R010D4SelectedSourceObservation, R010RowFiniteDenied, _ROWS,
    capture_r010_d4_selected_source_from_service,
)

if TYPE_CHECKING:
    from .workspaces import WorkspaceContext, WorkspaceService


class R010SixSourceDenied(ValueError):
    """The shared six-command source snapshot is not qualified."""


@dataclass(frozen=True, slots=True)
class R010ServiceSourceRow:
    index: int
    command_id: str
    candidate: D4FixtureCandidate
    selected: R010D4SelectedSourceObservation
    native_launch_allowed: bool = False


@dataclass(frozen=True, slots=True)
class R010SixSourcePlan:
    workspace: str
    rows: tuple[R010ServiceSourceRow, ...]
    status: str = "SIX_SOURCE_ROWS_CHECKED_NO_RUNTIME_AUTHORITY"
    source_only: bool = True
    native_launch_allowed: bool = False
    six_command_product_t1_pass: bool = False

    def summary(self) -> dict[str, object]:
        """A safe diagnostic, not the candidates or private FDs."""
        return {
            "status": self.status,
            "workspace": self.workspace,
            "row_count": len(self.rows),
            "rows": tuple(
                (row.index, row.command_id, row.selected.source_count)
                for row in self.rows
            ),
            "native_launch_allowed": False,
            "six_command_product_t1_pass": False,
        }


_IDS = (
    "py-direct-pytest",
    "py-direct-compileall",
    "py-pipenv-pytest",
    "go-test",
    "go-vet",
    "go-build",
)


def _checked_shared_owner(
    service: "WorkspaceService", ctx: "WorkspaceContext",
) -> None:
    from .workspaces import WorkspaceContext, WorkspaceService
    if (type(service) is not WorkspaceService
            or type(ctx) is not WorkspaceContext
            or service.settings.schema_version != 2
            or ctx is not service.get(ctx.name)
            or service._closing or service._closed
            or service._exec_state is None or service._lbe_owner is None):
        raise R010SixSourceDenied("no live same-instance WorkspaceService")
    try:
        service._exec_state.require_healthy()
        owner = service._lbe_owner.snapshot()
    except Exception:
        raise R010SixSourceDenied("owner or state became unavailable") from None
    if (owner.get("unavailable") is not False
            or owner.get("closing") is not False):
        raise R010SixSourceDenied("shared DirectChildOwner is unavailable")


def recheck_r010_service_six_source(
    *, service: "WorkspaceService", ctx: "WorkspaceContext",
    snapshot: R010SixSourcePlan,
) -> R010SixSourcePlan:
    """Re-read EVERY reviewed source before a later separate launch gate.

    A matching source-only observation cannot mint Provider/Owner authority.
    """
    _checked_shared_owner(service, ctx)
    if (type(snapshot) is not R010SixSourcePlan
            or snapshot.workspace != ctx.name
            or len(snapshot.rows) != 6
            or snapshot.native_launch_allowed is not False
            or snapshot.six_command_product_t1_pass is not False):
        raise R010SixSourceDenied("six-row snapshot not bound to this service")
    for rownum, (record, recipe) in enumerate(zip(snapshot.rows, _ROWS), 1):
        cwd, _runner, argv, _go_output = recipe
        if (type(record) is not R010ServiceSourceRow
                or record.index != rownum
                or record.command_id != _IDS[rownum - 1]
                or type(record.candidate) is not D4FixtureCandidate
                or type(record.selected) is not R010D4SelectedSourceObservation
                or record.candidate.plan.workspace != ctx.name
                or record.candidate.plan.cwd != cwd
                or record.candidate.plan.requested_argv != argv
                or record.selected.workspace != ctx.name
                or record.native_launch_allowed is not False):
            raise R010SixSourceDenied("row-order/candidate binding drift")
        try:
            fresh = capture_r010_d4_selected_source_from_service(
                row=rownum, ctx=ctx, candidate=record.candidate)
        except R010RowFiniteDenied:
            raise R010SixSourceDenied(
                "selected source changed since six-row snapshot") from None
        if fresh != record.selected:
            raise R010SixSourceDenied("six-row selected source drift")
    return snapshot


def prepare_r010_service_six_source(
    *, service: "WorkspaceService", ctx: "WorkspaceContext",
    timeout_seconds: int = 120,
) -> R010SixSourcePlan:
    """Read all six from the SAME service, then recheck the entire set.

    The caller must hold the service's active-operation lease throughout.
    No native Worker, command reservation, Popen, OIDC or grant is touched.
    """
    _checked_shared_owner(service, ctx)
    if (type(timeout_seconds) is not int
            or not 1 <= timeout_seconds <= 120):
        raise R010SixSourceDenied("invalid six-row timeout")
    rows = []
    for number, (cwd, _runner, argv, _go_output) in enumerate(_ROWS, 1):
        try:
            selected = service._prepare_d4_r003_fixture_candidate(
                ctx.name, cwd, list(argv), timeout_seconds=timeout_seconds)
            checked = capture_r010_d4_selected_source_from_service(
                row=number, ctx=ctx, candidate=selected)
        except Exception:
            raise R010SixSourceDenied(
                "service did not qualify exact R010 source row") from None
        rows.append(R010ServiceSourceRow(
            index=number, command_id=_IDS[number - 1],
            candidate=selected, selected=checked))
    plan = R010SixSourcePlan(workspace=ctx.name, rows=tuple(rows))
    return recheck_r010_service_six_source(
        service=service, ctx=ctx, snapshot=plan)
