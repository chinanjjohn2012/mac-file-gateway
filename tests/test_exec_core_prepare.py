"""Immutable declaration planning uses the signed validator, never its runner."""
from dataclasses import FrozenInstanceError
import pytest
from gateway.core import GatewayError
from exec_core_helpers import core_service


def payload(**extra):
    return {"workspace": "a", "cwd": "service", "argv": ["go", "test", "./..."], **extra}


def test_request_defaults_and_exact_types():
    from gateway.exec_contracts import parse_execution_request
    request = parse_execution_request({"workspace": "a", "argv": ["pytest"]})
    assert (request.cwd, request.timeout_seconds, request.dry_run) == (".", 60, True)
    for t in (1, 300):
        assert parse_execution_request(payload(timeout_seconds=t)).timeout_seconds == t


@pytest.mark.parametrize("bad", [
    None, [], {}, {"argv": ["pytest"]},
    payload(timeout_seconds=0), payload(timeout_seconds=301), payload(timeout_seconds=True),
    payload(timeout_seconds=1.0), payload(dry_run=0), payload(workspace=1),
    payload(workspace=""), payload(workspace="A"), payload(workspace="a"*33),
    payload(cwd=""), payload(cwd="../x"), payload(cwd="/tmp"), payload(cwd="a//b"),
    payload(cwd="service\ud800"), payload(argv=["pytest", "\ud800"]),
    payload(argv=[]), payload(argv=("pytest",)), payload(argv=["pytest", 1]),
    payload(argv=["pytest"]*65), payload(argv=["pytest", "a"*1025]),
    payload(argv=["pytest"]+["a"*1024]*8), payload(unknown=True),
])
def test_request_rejects_invalid_payload(bad):
    from gateway.exec_contracts import parse_execution_request
    with pytest.raises(GatewayError):
        parse_execution_request(bad)


def test_request_snapshot_is_immutable():
    from gateway.exec_contracts import parse_execution_request
    raw = payload()
    request = parse_execution_request(raw)
    raw["argv"][0] = "sh"
    assert request.argv == ("go", "test", "./...")
    with pytest.raises(FrozenInstanceError):
        request.workspace = "b"


@pytest.mark.parametrize("change,code", [
    ({"workspace": "b"}, "exec_disabled"), ({"workspace": "missing"}, "workspace_not_found"),
    ({"cwd": "service-extra"}, "exec_scope"), ({"cwd": "."}, "exec_scope"),
    ({"cwd": "service/.hidden"}, "blocked_path"),
])
def test_service_denies_other_workspace_and_prefix_scope(tmp_path, change, code):
    with core_service(tmp_path) as service:
        with pytest.raises(GatewayError) as exc:
            service.prepare_execution(payload(**change))
        assert exc.value.code == code


DENIED = [
    ["go", "test", "--exec=external"], ["go", "vet", "--toolexec=external"],
    ["go", "test", "-C=service"], ["go", "test", "-pgo=../external"],
    ["go", "test", "-debug-actiongraph=graph.json"], ["go", "test", "--debug-trace=trace.json"],
    ["pytest", "-k", "@args.txt"], ["pytest", "-qoaddopts=--pdb"],
    ["pytest", "-o", "cache_dir=${HOME}/cache"], ["pytest", "--junit-xml=../report.xml"],
]


@pytest.mark.parametrize("argv", DENIED)
def test_prepare_reuses_signed_validator(tmp_path, monkeypatch, argv):
    from gateway.executor import _validate_command
    def forbidden(*a, **kw):
        raise AssertionError("planning invoked a runner")
    monkeypatch.setattr("subprocess.Popen", forbidden)
    monkeypatch.setattr("gateway.executor.CommandRunner.run", forbidden)
    with pytest.raises(GatewayError) as baseline:
        _validate_command(argv)
    with core_service(tmp_path) as service:
        with pytest.raises(GatewayError) as actual:
            service.prepare_execution(payload(argv=argv))
    assert actual.value.code == baseline.value.code


@pytest.mark.parametrize("argv", [["pytest", "-o", "cache_dir=cache files"],
    ["pytest", "-o", "log_file=reports/test results.log"],
    ["pytest", "-o", 'testpaths=tests "more tests"'], ["go", "test", "-pgo=auto"], ["go", "test", "-pgo=off"]])
def test_prepare_safe_arguments_without_runtime(tmp_path, monkeypatch, argv):
    def forbidden(*a, **kw):
        raise AssertionError("unexpected runtime")
    monkeypatch.setattr("subprocess.Popen", forbidden)
    monkeypatch.setattr("gateway.executor.CommandRunner.run", forbidden)
    with core_service(tmp_path) as service:
        intent = service.prepare_execution(payload(argv=argv))
        assert intent.scope == "service"
        assert intent.request.argv == tuple(argv)
        assert intent.runtime_ready is False
        assert intent.runner_hint == "auto"
        assert intent.runner_project_hint is None


def test_internal_prepare_never_advertises_exec(tmp_path):
    with core_service(tmp_path) as service:
        service.prepare_execution(payload())
        assert all(w["exec"] is False for w in service.list_workspaces()["workspaces"])
        assert all(w["exec"] is False for w in service.info()["workspaces"])


@pytest.mark.parametrize("operation", ["run_command", "prepare_execution", "_reserve_execution", "close", "__init__"])
def test_invoke_cannot_call_internal_or_run_command(tmp_path, operation):
    with core_service(tmp_path) as service:
        with pytest.raises(GatewayError):
            service.invoke("a", operation)


def test_runner_hint_uses_longest_declared_path_only(tmp_path):
    policies = {"a": {"enabled": True, "paths": ["service"],
                      "runners": {"service": "pipenv", "service/sub": "direct"}}}
    with core_service(tmp_path, policies) as service:
        a = service.prepare_execution(payload())
        b = service.prepare_execution(payload(cwd="service/sub"))
        assert (a.runner_hint, a.runner_project_hint) == ("pipenv", "service")
        assert (b.runner_hint, b.runner_project_hint) == ("direct", "service/sub")
