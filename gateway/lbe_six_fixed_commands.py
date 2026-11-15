"""Pure schema-v2 six-command selector for a future reviewed apply gate.

This helper cannot launch, reserve, or authorize any command.  Current F1
positive Exec denial and the existing Native Launcher remain unchanged.
A future WorkspaceService must independently validate config opt-ins,
Workspace/path authority, durable old state, and original-child capacity.
"""
from __future__ import annotations

from dataclasses import dataclass
import re


@dataclass(frozen=True, slots=True)
class FixedCommand:
    command_id: str
    cwd: str
    runner: str
    requested_argv: tuple[str, ...]
    effective_argv: tuple[str, ...]
    planned_go_output: str | None = None


SIX_FIXED_COMMANDS: tuple[FixedCommand, ...] = (
    FixedCommand("py-direct-pytest", "py-direct", "direct",
                 ("python", "-m", "pytest", "-q"),
                 ("python", "-m", "pytest", "-q")),
    FixedCommand("py-direct-compileall", "py-direct", "direct",
                 ("python", "-m", "compileall", "-q", "./src"),
                 ("python", "-m", "compileall", "-q", "./src")),
    FixedCommand("py-pipenv-pytest", "py-pipenv", "pipenv",
                 ("python", "-m", "pytest", "-q"),
                 ("pipenv", "run", "python", "-m", "pytest", "-q")),
    FixedCommand("go-test", "go-project", "direct",
                 ("go", "test", "./..."), ("go", "test", "./...")),
    FixedCommand("go-vet", "go-project", "direct",
                 ("go", "vet", "./..."), ("go", "vet", "./...")),
    FixedCommand("go-build", "go-project", "direct",
                 ("go", "build", "-o", "bin/app", "./cmd/app"),
                 ("go", "build", "-o", "bin/app", "./cmd/app"),
                 "go-project/bin/app"),
)

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def match_fixed_six_command(
    *, workspace: str, cwd: str, runner: str, runner_project: str,
    requested_argv: tuple[str, ...], effective_argv: tuple[str, ...],
    timeout_seconds: int, planned_go_output: str | None = None,
    planned_script_sha256: str | None = None,
    planned_pipfile_sha256: str | None = None,
) -> str | None:
    """Classify an exact trusted plan; return None on any non-six shape.

    This is NOT admission: it accepts no enable flag or owner token and does
    not access the host, mutate Exec state, or create a child.  The service
    must compare its own recomputed plan immediately before a later launcher.
    """
    if (type(workspace) is not str or not workspace
            or type(cwd) is not str or type(runner) is not str
            or type(runner_project) is not str or runner_project != cwd
            or type(timeout_seconds) is not int
            or not 1 <= timeout_seconds <= 300
            or type(requested_argv) is not tuple
            or type(effective_argv) is not tuple
            or any(type(x) is not str for x in requested_argv)
            or any(type(x) is not str for x in effective_argv)
            or planned_script_sha256 is not None
            or (planned_go_output is not None
                and type(planned_go_output) is not str)
            or (planned_pipfile_sha256 is not None
                and type(planned_pipfile_sha256) is not str)):
        return None

    for entry in SIX_FIXED_COMMANDS:
        if (cwd != entry.cwd or runner != entry.runner
                or requested_argv != entry.requested_argv
                or effective_argv != entry.effective_argv
                or planned_go_output != entry.planned_go_output):
            continue
        if entry.runner == "pipenv":
            if (planned_pipfile_sha256 is None
                    or _SHA256.fullmatch(planned_pipfile_sha256) is None):
                return None
        elif planned_pipfile_sha256 is not None:
            return None
        return entry.command_id
    return None
