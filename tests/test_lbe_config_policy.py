"""T0 tests for dormant v2 Exec path/runner fragments; no real Exec."""
from __future__ import annotations

import copy
import json
import pytest

from gateway.lbe_config_policy import (
    LbeConfigError, LbeExecGrant, parse_lbe_exec_fragment,
)


_ABSENT = object()


def parse(*, paths=None, runners=None, server=None, raw=_ABSENT, version=2):
    if raw is _ABSENT:
        exec_obj = {}
        if paths is not None:
            exec_obj["paths"] = paths
        if runners is not None:
            exec_obj["runners"] = runners
        raw = {"exec": exec_obj}
    return parse_lbe_exec_fragment(
        schema_version=version,
        server={} if server is None else server,
        workspace=raw,
    )


def test_empty_or_absent_paths_never_create_grants():
    for raw in ({}, {"exec": {}}, {"exec": {"paths": []}}):
        obj = parse(raw=raw)
        assert isinstance(obj, LbeExecGrant)
        assert not obj.enabled
        assert obj.paths == ()
        assert obj.runners == ()
        with pytest.raises(LbeConfigError, match="outside explicit"):
            obj.runner_for(".", "python")


def test_user_sample_python_pipenv_and_go_direct():
    grant = parse(
        paths=["python-project", "go-project"],
        runners=["python-project=pipenv", "go-project=direct"],
    )
    assert grant.enabled
    assert grant.paths == (("python-project",), ("go-project",))
    assert grant.runner_for("python-project", "python") == "pipenv"
    assert grant.runner_for("python-project/app", "python") == "pipenv"
    assert grant.runner_for("go-project", "go") == "direct"
    assert grant.runner_for("go-project/cmd", "python") == "direct"
    assert grant.runner_for("python-project", "go") == "direct"


def test_missing_runner_defaults_to_direct_but_not_global_grant():
    grant = parse(paths=["go-project"])
    assert grant.runner_for("go-project/cmd", "python") == "direct"
    assert grant.runner_for("go-project", "go") == "direct"
    with pytest.raises(LbeConfigError, match="outside"):
        grant.runner_for("python-project", "python")


def test_longest_nested_runner_wins_without_extending_authority():
    grant = parse(
        paths=["project"],
        runners=["project=direct", "project/sub=pipenv"],
    )
    assert grant.runner_for("project", "python") == "direct"
    assert grant.runner_for("project/sub", "python") == "pipenv"
    assert grant.runner_for("project/sub/deeper", "python") == "pipenv"
    assert grant.runner_for("project/sub", "go") == "direct"
    with pytest.raises(LbeConfigError, match="outside"):
        grant.runner_for("projected/sub", "python")


def test_explicit_dot_grants_workspace_only_when_named():
    grant = parse(paths=["."], runners=[".=pipenv"])
    assert grant.enabled
    assert grant.runner_for(".", "python") == "pipenv"
    assert grant.runner_for("go-project/nested", "python") == "pipenv"
    assert grant.runner_for(".", "go") == "direct"


@pytest.mark.parametrize("version", [1, 0, 3, True, 2.0, "2", None, False])
def test_unsupported_or_wrong_type_version_refuses(version):
    with pytest.raises(LbeConfigError, match="schema_version=2"):
        parse(paths=["project"], version=version)


@pytest.mark.parametrize("server", [
    {"exec": {"enabled": False}},
    {"exec": {"enabled": True}},
    {"exec": {"paths": ["project"]}},
    {"exec": True},
    {"exec": []},
    {"exec": "enabled"},
])
def test_server_exec_never_mints_v2_grants(server):
    with pytest.raises(LbeConfigError):
        parse(paths=["project"], server=server)


@pytest.mark.parametrize("raw", [
    {"exec": {"enabled": False, "paths": ["project"]}},
    {"exec": {"enabled": True, "paths": ["project"]}},
    {"exec": {"mode": "local_best_effort", "paths": ["project"]}},
    {"exec": {"path": ["project"]}},
    {"exec": None},
    {"exec": True},
    {"exec": ["project"]},
    [],
    None,
])
def test_unknown_workspace_exec_switches_or_types_fail_closed(raw):
    with pytest.raises(LbeConfigError):
        parse(raw=raw)


@pytest.mark.parametrize("paths", [
    "project",
    ("project",),
    None,
    [1],
    [True],
    [""],
    ["/tmp"],
    ["~/proj"],
    ["project/../outside"],
    ["project//other"],
    ["project/./other"],
    ["project/"],
    ["./project"],
    ["project\\nested"],
    ["project:alt"],
    ["project/*"],
    ["project/[a]"],
    ["project\nname"],
    ["project\x00name"],
    ["project\u007f"],
    ["a" * 2049],
])
def test_invalid_paths_reject(paths):
    with pytest.raises(LbeConfigError):
        parse(raw={"exec": {"paths": paths}})


@pytest.mark.parametrize("paths", [
    ["project", "project"],
    ["Project", "project"],
    ["proj/sub", "proj/SUB"],
    ["." , "."],
    ["p"] * 33,
])
def test_duplicate_case_ambiguous_or_oversized_grants_reject(paths):
    with pytest.raises(LbeConfigError):
        parse(paths=paths)


@pytest.mark.parametrize("runners", [
    ["project=pipenv"],
    ["project=invalid"],
    ["other=pipenv"],
    ["project==pipenv"],
    ["project"],
    ["=pipenv"],
    ["project="],
    ["project=direct", "project=pipenv"],
    ["project=direct", "PROJECT=pipenv"],
    ["project/../outside=pipenv"],
    [12],
    [True],
    "project=pipenv",
    ("project=pipenv",),
    ["project=direct"] * 33,
])
def test_invalid_runner_rules_reject(runners):
    with pytest.raises(LbeConfigError):
        parse(paths=["project"], runners=runners) if runners != ["project=pipenv"] else parse(paths=[], runners=runners)


def test_runner_rule_on_explicit_subscope_can_be_allowed():
    g = parse(paths=["project"], runners=["project/sub=pipenv"])
    assert g.runner_for("project/sub", "python") == "pipenv"
    assert g.runner_for("project", "python") == "direct"


def test_case_only_sibling_path_is_not_implicitly_authorized():
    grant = parse(paths=["Team"])
    with pytest.raises(LbeConfigError, match="outside"):
        grant.runner_for("team", "python")


@pytest.mark.parametrize("cwd", [
    "../project", "/tmp", "project/..", "project//sub",
    "project/*", "project\\sub", "project/x\n", "",
])
def test_invalid_runtime_cwd_rejected_even_in_pure_selection(cwd):
    g = parse(paths=["project"])
    with pytest.raises(LbeConfigError):
        g.runner_for(cwd, "python")


@pytest.mark.parametrize("kind", ["shell", "", "pipenv", "Go", None, True])
def test_invalid_command_kind_does_not_select_unsafe_fallback(kind):
    g = parse(paths=["project"])
    with pytest.raises(LbeConfigError, match="unknown command kind"):
        g.runner_for("project", kind)


def test_return_is_immutable_and_not_aliased_to_input_lists():
    source = {
        "exec": {
            "paths": ["python-project", "go-project"],
            "runners": ["python-project=pipenv"],
        },
        "root": "/some/path",
    }
    before = copy.deepcopy(source)
    grant = parse(raw=source)
    assert source == before
    source["exec"]["paths"].clear()
    source["exec"]["runners"][0] = "go-project=pipenv"
    source["exec"]["enabled"] = True
    assert grant.enabled
    assert grant.runner_for("python-project", "python") == "pipenv"
    assert grant.runner_for("go-project", "python") == "direct"
    with pytest.raises((AttributeError, TypeError)):
        grant.paths = ()


@pytest.mark.parametrize("raw_json", [
    r'{"exec":{"paths":["\ud800"]}}',
    r'{"exec":{"paths":["\udfff"]}}',
    r'{"exec":{"paths":["project"],"runners":["project/\ud800=pipenv"]}}',
    r'{"exec":{"paths":["project"],"runners":["project/\udfff=direct"]}}',
])
def test_json_escaped_lone_surrogate_is_bounded_config_error(raw_json):
    # json.loads legitimately decodes these escapes to lone-surrogate str.
    # The pure v2 parser must fail closed with its own sanitized error,
    # never leak a raw UnicodeEncodeError from str.encode.
    payload = json.loads(raw_json)
    with pytest.raises(LbeConfigError, match="path string"):
        parse(raw=payload)


def test_runtime_selector_rejects_lone_surrogate_without_encoding_error():
    grant = parse(paths=["project"])
    with pytest.raises(LbeConfigError, match="path string"):
        grant.runner_for("project/\ud800", "python")
    assert grant.runner_for("project", "go") == "direct"


def test_no_file_operation_or_subprocess_required(monkeypatch):
    import os
    import subprocess

    def deny(*args, **kwargs):
        raise AssertionError("pure config preflight must not access FS or start subprocess")

    monkeypatch.setattr(subprocess, "Popen", deny)
    monkeypatch.setattr(os, "open", deny)
    g = parse(paths=["proj"], runners=["proj=pipenv"])
    assert g.runner_for("proj", "python") == "pipenv"
