"""SAFE T0: exact-six planning predicate, never native process execution."""
from __future__ import annotations


import pytest

from gateway.lbe_six_fixed_commands import (
    SIX_FIXED_COMMANDS, match_fixed_six_command,
)


def _candidate(row):
    return dict(
        workspace="a", cwd=row.cwd, runner=row.runner,
        runner_project=row.cwd, requested_argv=row.requested_argv,
        effective_argv=row.effective_argv, timeout_seconds=60,
        planned_go_output=row.planned_go_output,
        planned_pipfile_sha256=("a" * 64 if row.runner == "pipenv" else None),
    )


@pytest.mark.parametrize("row", SIX_FIXED_COMMANDS, ids=lambda row: row.command_id)
def test_exact_six_rows_classify_without_spawning(row, monkeypatch):
    import subprocess

    def no_spawn(*args, **kwargs):
        raise AssertionError("source-only selector must never execute")

    monkeypatch.setattr(subprocess, "Popen", no_spawn)
    assert match_fixed_six_command(**_candidate(row)) == row.command_id


def test_fixture_matrix_and_ids_stay_exact():
    assert len(SIX_FIXED_COMMANDS) == 6
    assert len({row.command_id for row in SIX_FIXED_COMMANDS}) == 6
    assert len({(row.cwd, row.runner, row.requested_argv, row.effective_argv)
                for row in SIX_FIXED_COMMANDS}) == 6
    # When run in the real repository, independently lock this future
    # selector to the existing nonoperative D4 fixture and source ID set.
    try:
        from gateway.lbe_product_fixture import _MATRIX
        from gateway.lbe_r010_six_service import _IDS
    except ImportError:
        pytest.skip("parity with existing repository modules not available")
    assert tuple((row.cwd, row.runner, row.requested_argv, row.effective_argv)
                 for row in SIX_FIXED_COMMANDS) == _MATRIX
    assert tuple(row.command_id for row in SIX_FIXED_COMMANDS) == _IDS


@pytest.mark.parametrize("row", SIX_FIXED_COMMANDS, ids=lambda row: row.command_id)
def test_noncanonical_runner_workspace_and_effective_argv_refused(row):
    good = _candidate(row)
    bad_cases = (
        {"workspace": ""},
        {"cwd": "."},
        {"cwd": row.cwd + "/"},
        {"runner_project": "other-project"},
        {"runner": "pipenv" if row.runner == "direct" else "direct"},
        {"requested_argv": row.requested_argv + ("--extra",)},
        {"effective_argv": row.effective_argv + ("--extra",)},
        {"timeout_seconds": 0},
        {"timeout_seconds": 301},
        {"timeout_seconds": True},
        {"planned_script_sha256": "a" * 64},
        {"planned_go_output": "other/bin/app"},
        {"planned_pipfile_sha256": None if row.runner == "pipenv" else "b" * 64},
    )
    for patch in bad_cases:
        assert match_fixed_six_command(**(good | patch)) is None, (row, patch)


@pytest.mark.parametrize("argv", [
    ("go", "test", "./another"),
    ("go", "build", "./other"),
    ("go", "run", "./cmd/app"),
    ("go", "test", "-exec=/tmp/helper", "./..."),
    ("python", "-c", "print('hi')"),
    ("pipenv", "run", "python", "-m", "pytest", "-q"),
    ("python", "-m", "pytest", "-q", "--pdb"),
])
def test_non_six_arguments_never_match(argv):
    row = SIX_FIXED_COMMANDS[0]
    assert match_fixed_six_command(**(_candidate(row) | {
        "requested_argv": argv, "effective_argv": argv,
    })) is None


@pytest.mark.parametrize("wrong", [[], "python", None, ("python", 4), (object(),)])
def test_reject_malformed_argv_before_comparing(wrong):
    row = SIX_FIXED_COMMANDS[0]
    assert match_fixed_six_command(**(_candidate(row) | {
        "requested_argv": wrong,
    })) is None


def test_untrusted_equality_is_never_called():
    class Hostile:
        def __eq__(self, other):
            raise AssertionError("untrusted equality must not be invoked")
    row = SIX_FIXED_COMMANDS[0]
    assert match_fixed_six_command(**(_candidate(row) | {
        "requested_argv": (Hostile(),),
    })) is None


def test_valid_pipfile_digest_is_required_only_for_pipenv():
    row = next(r for r in SIX_FIXED_COMMANDS if r.runner == "pipenv")
    good = _candidate(row)
    for invalid in ("", "A" * 64, "a" * 63, "g" * 64, 8):
        assert match_fixed_six_command(**(good | {
            "planned_pipfile_sha256": invalid,
        })) is None


def test_go_output_is_only_allowed_for_fixed_build_target():
    rows = {r.command_id: r for r in SIX_FIXED_COMMANDS}
    build = _candidate(rows["go-build"])
    assert match_fixed_six_command(**build) == "go-build"
    assert match_fixed_six_command(**(build | {
        "planned_go_output": None,
    })) is None
    test = _candidate(rows["go-test"])
    assert match_fixed_six_command(**test) == "go-test"
    assert match_fixed_six_command(**(test | {
        "planned_go_output": "go-project/bin/app",
    })) is None
