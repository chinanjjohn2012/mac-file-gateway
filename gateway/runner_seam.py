"""R1 non-operational Runner protocol and fail-closed coordination seam.

This module is NOT connected to WorkspaceService, REST, MCP or ExecStateStore.
It has no process-launch, signal, VM, filesystem, network or worker functions.
The current D0/F1 contract still rejects all ordinary dry_run=False Exec.

Protocol types describe *proposed* future interfaces, not cleanup proof.
Only a new reviewed, explicitly authorized phase may implement a backend.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Literal, Protocol

_ID = re.compile(r"[a-f0-9]{32}\Z")
_WORKSPACE = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")

CleanupScope = Literal["none", "original_group_only", "full_bound_domain"]
FullTreeProof = Literal["not_proven", "proven"]


@dataclass(frozen=True, slots=True)
class AttemptIdentity:
    """Untrusted structural identity, not an OS process or owner proof."""

    workspace: str
    workspace_dev: int
    workspace_ino: int
    attempt_id: str
    owner_generation: str

    def __post_init__(self) -> None:
        if type(self.workspace) is not str or not _WORKSPACE.fullmatch(self.workspace):
            raise ValueError("invalid Workspace identity")
        for number in (self.workspace_dev, self.workspace_ino):
            if type(number) is not int or number < 0:
                raise ValueError("invalid Workspace dev/ino")
        for token in (self.attempt_id, self.owner_generation):
            if type(token) is not str or not _ID.fullmatch(token):
                raise ValueError("invalid attempt or generation token")


@dataclass(frozen=True, slots=True)
class ProposedCommand:
    """Data for a *future* policy-validated command; never an admission grant."""

    cwd: str
    argv: tuple[str, ...] = field(repr=False)
    timeout_seconds: int = 60

    def __post_init__(self) -> None:
        if type(self.cwd) is not str or not self.cwd:
            raise ValueError("invalid command cwd")
        if type(self.argv) is not tuple or not self.argv:
            raise ValueError("invalid command argv")
        if any(type(arg) is not str or not arg for arg in self.argv):
            raise ValueError("invalid command argument")
        if type(self.timeout_seconds) is not int or not 1 <= self.timeout_seconds <= 300:
            raise ValueError("invalid command timeout")


@dataclass(frozen=True, slots=True)
class BoundReference:
    """Opaque future backend reference; numeric PID/PGID is never authority."""

    attempt: AttemptIdentity
    backend_id: str
    opaque_ref: str = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.attempt) is not AttemptIdentity:
            raise ValueError("invalid bound attempt")
        if type(self.backend_id) is not str or not self.backend_id:
            raise ValueError("invalid backend id")
        if type(self.opaque_ref) is not str or not self.opaque_ref:
            raise ValueError("invalid opaque reference")


@dataclass(frozen=True, slots=True)
class BackendQualification:
    """R1 only admits a NONE value, not a caller-minted proof capability."""

    completion_capability: Literal["none"] = "none"

    def __post_init__(self) -> None:
        if self.completion_capability != "none":
            raise ValueError("positive backend qualification is unavailable in R1")


@dataclass(frozen=True, slots=True)
class CommandOutcome:
    executed: bool
    exit_code: int | None = None
    timed_out: bool = False

    def __post_init__(self) -> None:
        if type(self.executed) is not bool or type(self.timed_out) is not bool:
            raise ValueError("invalid command result flags")
        if self.exit_code is not None and type(self.exit_code) is not int:
            raise ValueError("invalid exit code")
        if not self.executed and (self.exit_code is not None or self.timed_out):
            raise ValueError("nonexecuted command cannot have exit or timeout")


@dataclass(frozen=True, slots=True)
class CleanupEvidence:
    """Descriptive data only; this type cannot authorize Exec retirement."""

    scope: CleanupScope = "none"
    full_descendant_tree_clean: FullTreeProof = "not_proven"
    observed_detached_survivor: bool = False

    def __post_init__(self) -> None:
        if self.scope not in ("none", "original_group_only", "full_bound_domain"):
            raise ValueError("invalid cleanup scope")
        if self.full_descendant_tree_clean not in ("not_proven", "proven"):
            raise ValueError("invalid full-tree proof marker")
        if type(self.observed_detached_survivor) is not bool:
            raise ValueError("invalid survivor observation")
        if self.observed_detached_survivor and (
            self.scope != "none" or self.full_descendant_tree_clean != "not_proven"
        ):
            raise ValueError("observed detached survivor requires unknown cleanup")
        if (self.full_descendant_tree_clean == "proven"
                and self.scope != "full_bound_domain"):
            raise ValueError("group-only cleanup cannot prove full descendants")


@dataclass(frozen=True, slots=True)
class DeliveryOutcome:
    response_attempted: bool = False
    acknowledged: bool | None = None

    def __post_init__(self) -> None:
        if type(self.response_attempted) is not bool:
            raise ValueError("invalid response flag")
        if self.acknowledged is not None and type(self.acknowledged) is not bool:
            raise ValueError("invalid acknowledgment flag")
        if self.acknowledged is True and not self.response_attempted:
            raise ValueError("cannot acknowledge an unattempted response")


class RunnerBackend(Protocol):
    """FUTURE protocol only: no implementation or live caller in R1."""

    def qualification(self) -> BackendQualification: ...
    def allocate(self, intent: AttemptIdentity) -> BoundReference: ...
    def start_once(self, ref: BoundReference, command: ProposedCommand) -> None: ...
    def observe(self, ref: BoundReference) -> CommandOutcome: ...
    def terminate_and_prove(self, ref: BoundReference) -> CleanupEvidence: ...
    def reconcile(self, intent: AttemptIdentity) -> CleanupEvidence: ...


@dataclass(frozen=True, slots=True)
class AdmissionDecision:
    """A denied decision is the *only* outcome representable by R1."""

    allowed: bool = False
    error_code: Literal["exec_cleanup_proof_required"] = "exec_cleanup_proof_required"
    completion_capability: Literal["none"] = "none"

    def __post_init__(self) -> None:
        if (self.allowed is not False
                or self.error_code != "exec_cleanup_proof_required"
                or self.completion_capability != "none"):
            raise ValueError("R1 cannot grant positive execution")


class RunnerCoordinator:
    """Inert interface seam; ignores untrusted/fake backends, always denies.

    It is intentionally not integrated into production routing. In particular,
    this class never calls the RunnerBackend protocol, allocates an attempt,
    persists PREPARED, sends a signal or produces completion evidence.
    """

    __slots__ = ()

    def evaluate(
        self, intent: AttemptIdentity, *, backend: RunnerBackend | None = None
    ) -> AdmissionDecision:
        if type(intent) is not AttemptIdentity:
            raise TypeError("an AttemptIdentity is required")
        # backend is deliberately never inspected, called, stored or trusted.
        return AdmissionDecision()
