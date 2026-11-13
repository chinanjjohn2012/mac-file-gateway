"""Operator-selected native tools for the six-command local_best_effort MVP.

A private startup-only JSON file, NOT the public Workspace schema or a
per-request environment, fixes exactly one Python, Pipenv and Go executable:
  <private_config_dir>/mvp-exec-tools.json
  {"executables":{"python":"/abs/python","pipenv":"/abs/pipenv","go":"/abs/go"}}

No tool path, shell selection or environment override is accepted from REST,
MCP or a Workspace root.  This is light local tool identity, not a sandbox,
image/loader attestation, executable authority or native test qualification.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import pwd
import stat
from typing import TYPE_CHECKING

from .private_fs import PrivateFileError, read_private_json
from .lbe_worker import LbeNoChildStarted

if TYPE_CHECKING:
    from .lbe_worker import LbeWorkPlan

_TOOL_NAMES = frozenset({"python", "pipenv", "go"})
_PRIVATE_FILENAME = "mvp-exec-tools.json"


@dataclass(frozen=True)
class _Executable:
    selected: str
    resolved: str
    identity: tuple[int, int, int, int, int]
    interpreter: str | None
    interpreter_identity: tuple[int, int, int, int, int] | None


def _identity(path: str) -> tuple[int, int, int, int, int]:
    st = os.stat(path)
    if (not stat.S_ISREG(st.st_mode)
            or not os.access(path, os.X_OK)
            or st.st_uid not in (0, os.geteuid())
            or st.st_mode & 0o022):
        raise ValueError("selected tool is not an owner-controlled executable")
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_mode)


def _snapshot(path: str) -> _Executable:
    if (type(path) is not str or not path.startswith("/")
            or any(part in {"", ".", ".."} for part in path.split("/")[1:])
            or len(path.encode("utf-8", errors="strict")) > 4096):
        raise ValueError("selected executable must be an absolute canonical path")
    resolved = str(Path(path).resolve(strict=True))
    if not os.path.isabs(resolved):
        raise ValueError("selected executable must resolve to an absolute path")
    identity = _identity(resolved)
    with open(resolved, "rb") as f:
        first = f.read(256)
    interpreter = None
    interp_id = None
    if first.startswith(b"#!"):
        # In a shebang the OS selects an interpreter, not the visible script.
        # Reject /usr/bin/env or a relative interpreter which could silently
        # choose a different tool using a mutable PATH.
        line = first.split(b"\n", 1)[0][2:].strip()
        parts = line.split()
        if not parts:
            raise ValueError("selected script is missing a shebang interpreter")
        candidate = os.fsdecode(parts[0])
        if (not candidate.startswith("/")
                or candidate.endswith("/env")
                or any(part in {"", ".", ".."} for part in candidate.split("/")[1:])):
            raise ValueError("selected script interpreter is not absolute")
        interpreter = str(Path(candidate).resolve(strict=True))
        interp_id = _identity(interpreter)
    return _Executable(path, resolved, identity, interpreter, interp_id)


@dataclass(frozen=True)
class MvpTrustedTools:
    """Exactly three startup-frozen tool identities, no public grant fields."""

    python: _Executable
    pipenv: _Executable
    go: _Executable
    home: str

    @classmethod
    def load(cls, config_dir: str | Path, *,
             workspace_roots: tuple[str, ...]) -> "MvpTrustedTools":
        raw = read_private_json(Path(config_dir) / _PRIVATE_FILENAME)
        if (type(raw) is not dict or set(raw) != {"executables"}
                or type(raw["executables"]) is not dict
                or set(raw["executables"]) != _TOOL_NAMES):
            raise PrivateFileError("Invalid private MVP executable selection.")
        try:
            tools = {name: _snapshot(raw["executables"][name])
                     for name in sorted(_TOOL_NAMES)}
            # A local Workspace whose File API could rewrite a selected
            # executable or its script interpreter is not an operator tool.
            roots = tuple(Path(root).resolve(strict=True)
                          for root in workspace_roots)
            for selected in tools.values():
                candidates = (selected.resolved, selected.selected,
                              selected.interpreter)
                if any(Path(value).is_relative_to(root)
                       for value in candidates if value is not None
                       for root in roots):
                    raise ValueError("MVP executable overlaps Workspace")
            home = pwd.getpwuid(os.geteuid()).pw_dir
            if not home.startswith("/") or not Path(home).is_dir():
                raise ValueError("MVP home is unavailable")
            return cls(tools["python"], tools["pipenv"], tools["go"], home)
        except (OSError, ValueError, UnicodeError, RuntimeError) as exc:
            raise PrivateFileError(
                "Private MVP executable selection is unavailable.") from None

    def _get(self, name: str) -> _Executable:
        if name == "python":
            return self.python
        if name == "pipenv":
            return self.pipenv
        if name == "go":
            return self.go
        raise LbeNoChildStarted("no child: unrecognized six-command tool")

    def select_launch(self, plan: "LbeWorkPlan", *,
                      workspace_root: Path) -> tuple[list[str], dict[str, str]]:
        """Recheck startup-pinned file and shebang before Popen, no child."""
        name = "pipenv" if plan.runner == "pipenv" else plan.requested_argv[0]
        tool = self._get(name)
        try:
            current = _snapshot(tool.selected)
            if current != tool:
                raise ValueError("selected executable changed after startup")
            # The executable chosen by the server is always an absolute path
            # even when the public request uses the fixed logical token.
            argv = [tool.resolved, *plan.effective_argv[1:]]
            dirs = (
                str(Path(self.python.resolved).parent),
                str(Path(self.pipenv.resolved).parent),
                str(Path(self.go.resolved).parent),
                "/usr/bin", "/bin", "/usr/sbin", "/sbin",
            )
            # Stable deduplicated search path, not inherited PATH or cwd.
            paths = tuple(dict.fromkeys(dirs))
            env = {
                "PATH": os.pathsep.join(paths),
                "HOME": self.home,
                "TMPDIR": "/tmp",
                "LANG": "C",
                "LC_ALL": "C",
                "PYTHONUNBUFFERED": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
            }
            if name == "go":
                env.update(GOFLAGS="", GOENV="off",
                           GOTOOLCHAIN="local", CGO_ENABLED="0")
            if name == "pipenv":
                project = workspace_root / plan.runner_project
                pipfile = project / "Pipfile"
                python = project / ".venv" / "bin" / "python"
                if (not pipfile.is_file() or pipfile.is_symlink()
                        or not python.is_file()
                        or not os.access(python, os.X_OK)):
                    raise ValueError("selected Pipenv project is incomplete")
                # PIPENV_VENV_IN_PROJECT alone documents the preferred
                # location, but does not select the exact interpreter.
                # Validate the existing project-local interpreter's resolved
                # executable before asking Pipenv to run the fixed command.
                # An ordinary venv/bin/python symlink is allowed; its target
                # must be a regular executable controlled by this operator.
                selected_python = str(python.resolve(strict=True))
                _identity(selected_python)
                env.update(
                    PIPENV_PIPFILE=str(pipfile),
                    PIPENV_PYTHON=str(python),
                    PIPENV_NOSPIN="1",
                    PIPENV_IGNORE_VIRTUALENVS="1",
                    PIPENV_VENV_IN_PROJECT="1",
                    PIPENV_DONT_LOAD_ENV="1",
                )
            return argv, env
        except (OSError, ValueError, UnicodeError, RuntimeError):
            raise LbeNoChildStarted(
                "no child: selected local tool or runtime changed") from None
