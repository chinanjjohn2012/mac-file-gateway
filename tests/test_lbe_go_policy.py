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
    return validate_go_command(
        argv, workspace_root=root, cwd=cwd, exec_paths=paths,
        output_allowed=lambda _parts: True,
    )


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


@pytest.mark.parametrize("malicious_replacement", [
    ["go", "run", "-o", "../../escape", "./cmd/server"],
    ["go", "build", "-toolexec=/bin/sh", "./cmd/server"],
])
def test_input_argv_is_frozen_before_output_stat_interleaving(
        project, monkeypatch, malicious_replacement):
    """B100-R001-P2-01: live argv must never leak into a checked immutable plan.

    Mutation is deterministic *during* the validated plan's output FD check.
    The original r001 source returns the attacker's unchecked Go plan (RED).
    This is source-only T0, with no process or compiler started.
    """
    from gateway import lbe_go_policy as policy

    original = ["go", "build", "-o", "bin/app", "./cmd/server"]
    caller_owned = list(original)
    original_inspect = policy._inspect_output
    check_calls = []

    def interleaved_inspect(*args):
        check_calls.append(True)
        caller_owned[:] = malicious_replacement
        return original_inspect(*args)

    monkeypatch.setattr(policy, "_inspect_output", interleaved_inspect)
    planned = policy.validate_go_command(
        caller_owned, workspace_root=project, cwd="go-project",
        exec_paths=("go-project",),
        output_allowed=lambda _parts: True)
    assert check_calls == [True]
    assert caller_owned == malicious_replacement
    assert planned.argv == tuple(original)
    assert planned.output_relative_to_workspace == "go-project/bin/app"
    assert planned.runner == "direct"


@pytest.mark.parametrize("missing_package", [
    ["go", "build", "-v"],
    ["go", "test"],
    ["go", "vet"],
    ["go", "build", "-o=bin/app"],
])
def test_go_command_requires_explicit_package_operand(project, missing_package):
    """Conservative C100-R001-P3-01 resolution: no implicit Go cwd package."""
    with pytest.raises(GoPolicyError, match="package"):
        plan(project, missing_package)


def test_argv_snapshot_is_immutable_before_preflight(project, monkeypatch):
    """No re-read of mutable caller input after a legal original snapshot."""
    from gateway import lbe_go_policy as policy

    requested = ["go", "build", "-o", "bin/app", "./..."]
    expected = tuple(requested)
    actual_inspect = policy._inspect_output

    def mutate_before_return(*args):
        requested.clear()
        requested.extend(["go", "run", "./..."])
        return actual_inspect(*args)

    monkeypatch.setattr(policy, "_inspect_output", mutate_before_return)
    checked = policy.validate_go_command(
        requested, workspace_root=project, cwd="go-project",
        exec_paths=("go-project",),
        output_allowed=lambda _parts: True)
    assert checked.argv == expected
    assert checked.output_relative_to_workspace == "go-project/bin/app"


def test_gateway_output_policy_denial_precedes_any_output_parent_file_io(
    project, monkeypatch,
):
    """A forbidden -o leaf must not cause even a read-only output FD walk."""
    from gateway import lbe_go_policy as policy

    seen = []
    def policy_denial(parts):
        seen.append(parts)
        return False

    def forbidden_stat(*_args, **_kwargs):
        raise AssertionError("Go parent output FDs must not be inspected")

    monkeypatch.setattr(policy, "_inspect_output", forbidden_stat)
    with pytest.raises(GoPolicyError, match="blocked by Workspace policy"):
        policy.validate_go_command(
            ["go", "build", "-o", "bin/app", "./cmd/server"],
            workspace_root=project, cwd="go-project",
            exec_paths=("go-project",), output_allowed=policy_denial,
        )
    assert seen == [("go-project", "bin", "app")]


def test_gateway_output_policy_must_return_exact_boolean_true(project):
    """No permissive truthy object may accidentally authorize a Go output."""
    for answer in (None, 1, "yes"):
        with pytest.raises(GoPolicyError, match="blocked by Workspace policy"):
            validate_go_command(
                ["go", "build", "-o=bin/app", "./cmd/server"],
                workspace_root=project, cwd="go-project",
                exec_paths=("go-project",),
                output_allowed=lambda _parts: answer,
            )
