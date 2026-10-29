"""Source-only Go planning tests: never launch go or any other command."""
from __future__ import annotations

from pathlib import Path
import os

import pytest
from gateway.lbe_go_policy import GoPolicyError, validate_go_command


@pytest.fixture
def project(tmp_path: Path):
    root = tmp_path / "workspace"
    (root / "go-project" / "cmd").mkdir(parents=True)
    (root / "python-project").mkdir()
    (root / "go-project" / "bin").mkdir()
    (root / "go-project" / "Pipfile").write_text("[packages]\n")
    return root


def plan(root, argv, cwd="go-project", paths=("go-project",)):
    return validate_go_command(argv, workspace_root=root, cwd=cwd, exec_paths=paths)


@pytest.mark.parametrize("argv", [
    ["go", "test", "./..."],
    ["go", "vet", "./..."],
    ["go", "build", "./..."],
    ["go", "build", "./cmd/server"],
    ["go", "build", "-v", "-trimpath", "./cmd/server"],
    ["go", "test", "-v", "./..."],
    ["go", "build", "-o", "bin/server", "./cmd/server"],
    ["go", "build", "-o=bin/server", "./cmd/server"],
])
def test_allowlist_returns_direct_plan_without_spawning(project, argv):
    result = plan(project, argv)
    assert result.runner == "direct"
    assert result.argv == tuple(argv)
    if "-o" in argv or any(x.startswith("-o=") for x in argv):
        assert result.output_relative_to_workspace == "go-project/bin/server"
    else:
        assert result.output_relative_to_workspace is None


@pytest.mark.parametrize("argv", [
    ["go", "run", "./cmd/server"],
    ["go", "env"],
    ["go", "build", "-o"],
    ["go", "build", "-o="],
    ["go", "build", "-o", "/tmp/binary", "./cmd/server"],
    ["go", "build", "-o", "../binary", "./cmd/server"],
    ["go", "build", "-o", "~/binary", "./cmd/server"],
    ["go", "build", "-o", "bin/../escape", "./cmd/server"],
    ["go", "build", "-o", "bin/server", "-o=bin/other", "./..."],
    ["go", "test", "-o", "bin/server", "./..."],
    ["go", "build", "./cmd/server", "-o=bin/server"],
    ["go", "build", "-exec", "/bin/sh", "./..."],
    ["go", "build", "-exec=/bin/sh", "./..."],
    ["go", "build", "-toolexec=sh", "./..."],
    ["go", "build", "-vettool", "bin/tool", "./..."],
    ["go", "build", "-overlay=config.json", "./..."],
    ["go", "build", "-modfile=go.mod", "./..."],
    ["go", "build", "-ldflags=-extld=/bin/sh", "./..."],
    ["go", "build", "-gcflags=all=-N", "./..."],
    ["go", "build", "-buildmode=plugin", "./..."],
    ["go", "build", "-o", "bin/not-existing/server", "./..."],
    ["go", "build", "example.com/pkg"],
    ["go", "build", "../../outside"],
    ["go", "build", "./pkg/../../outside"],
    ["go", "build", "-o", "bin/server\\other", "./..."],
    ["go", "build", "-o", "bin/server\nline", "./..."],
    ["go", "build", "@flags"],
])
def test_refuse_bad_arg_or_output(project, argv):
    with pytest.raises(GoPolicyError):
        plan(project, argv)


def test_no_scope_or_other_workspace_refused(project):
    for paths in [(), ("python-project",)]:
        with pytest.raises(GoPolicyError):
            plan(project, ["go", "build", "./..."], paths=paths)
    with pytest.raises(GoPolicyError):
        plan(project, ["go", "build", "./..."], cwd="../elsewhere")


def test_explicit_scope_root_and_nested_cwd(project):
    sub = project / "go-project" / "cmd"
    (sub / "bin").mkdir()
    assert plan(project, ["go", "build", "-o", "bin/app", "./..."],
                cwd="go-project/cmd").output_relative_to_workspace == "go-project/cmd/bin/app"


def test_existing_regular_unlinked_output_allowed(project):
    target = project / "go-project" / "bin" / "app"
    target.write_bytes(b"old build")
    assert plan(project, ["go", "build", "-o=bin/app", "./..."]).runner == "direct"
    assert target.read_bytes() == b"old build"


def test_symlink_leaf_and_symlink_parent_rejected(project):
    binary = project / "go-project" / "bin" / "linked"
    binary.symlink_to("app")
    with pytest.raises(GoPolicyError):
        plan(project, ["go", "build", "-o", "bin/linked", "./..."])
    (project / "go-project" / "out").symlink_to("bin", target_is_directory=True)
    with pytest.raises(GoPolicyError):
        plan(project, ["go", "build", "-o", "out/server", "./..."])


def test_hardlinked_and_nonregular_output_rejected(project):
    target = project / "go-project" / "bin" / "app"
    target.write_bytes(b"keep")
    os.link(target, project / "go-project" / "bin" / "link")
    with pytest.raises(GoPolicyError):
        plan(project, ["go", "build", "-o", "bin/app", "./..."])
    with pytest.raises(GoPolicyError):
        plan(project, ["go", "build", "-o", "bin", "./..."])


def test_symlink_cwd_rejected_at_output_validation(project):
    (project / "go-project" / "alias").symlink_to("cmd", target_is_directory=True)
    with pytest.raises(GoPolicyError):
        plan(project, ["go", "build", "-o", "bin/app", "./..."], cwd="go-project/alias")


def test_deny_invalid_argv_types_and_controls(project):
    for argv in (["go", "build", 1], ["go", "build", "./...\x00"],
                 ["go", "build", "./...\n"], ["go"], ["go", "build", "a" * 1025]):
        with pytest.raises(GoPolicyError):
            plan(project, argv)


def test_never_creates_output_or_dirs(project):
    target = project / "go-project" / "bin" / "app"
    assert not target.exists()
    plan(project, ["go", "build", "-o", "bin/app", "./..."])
    assert not target.exists()
