"""Pure T0 of private R006 positive boundary; Popen is always fake."""
import os
import subprocess

import pytest

from gateway.lbe_hosted_source_probe import D4HostedSelectedSourceObservation
from gateway.lbe_launch_recipe import D4NativeLaunchRecipe
from gateway.lbe_owner_grant_bootstrap import (
    D4ConsumedOwnerGrant, D4OwnerBootstrapDenied,
)
from gateway.lbe_product_fixture import D4FixtureDenied, D4OneUseAttemptMarker
from gateway.lbe_r006_macos_allowlist import (\n    D4R006HostAllowlistObservation, R006_RUNNER_PROFILE_FINGERPRINT,\n)
from gateway import lbe_r006_native_runner as mod
from gateway.lbe_r006_native_runner import (
    D4R006NativeLaunchBoundary, D4R006NativeRunnerDenied,
)
from gateway.lbe_worker import LbeNoChildStarted, LbeWorkPlan
from gateway.workspaces import WorkspaceContext

PRODUCT = "d" * 64
HOST = "7c2b07cc58c98add78ad5ec5aa1b47610eba4345bca0f770565e89503d5990ee"
RUNNER = R006_RUNNER_PROFILE_FINGERPRINT

def _plan():
    argv=("python","-m","pytest","-q")
    return LbeWorkPlan(
        workspace="a",cwd="py-direct",requested_argv=argv,effective_argv=argv,
        runner="direct",runner_project="py-direct",timeout_seconds=120,
        planned_go_output=None,planned_script_sha256=None,planned_pipfile_sha256=None)

def _recipe(plan):
    return D4NativeLaunchRecipe(
        workspace="a",profile_git_blob="f8556b48ab5f4af7390fb015092862a8a87768fb",
        runner="direct",requested_argv=plan.requested_argv,
        service_effective_argv=plan.effective_argv,
        resolved_executable="/private/bin/python",
        resolved_spawn_argv=("/private/bin/python","-m","pytest","-q"),
        working_directory="/private/py-direct",
        closed_child_environment=(
            ("HOME","/private/home"),("PATH","/private/bin:/usr/bin:/bin"),
            ("PYTHONNOUSERSITE","1"),("TMPDIR","/private/tmp")),
        selected_source_fingerprint=PRODUCT,canonical_output_path=None,
        original_timeout_seconds=120)

def _host():
    obs=D4HostedSelectedSourceObservation(
        root_identity=(1,2,3,4,5,0o40755,0,1),
        selected=(("x","b"*64,(1,2,1,4,5,0o100444,0,1)),),
        root_ancestor_identities=((1,2,0o40755,0),))
    return D4R006HostAllowlistObservation(
        system=obs,usr=obs,source_fingerprint=HOST,
        runner_profile_fingerprint=RUNNER,image_version="20261104.0514.1",
        macos_version="15.8.2", os_build="24H232",
        kernel_sysname="Darwin", machine="arm64",
        run_id=42445537246, run_attempt=1, job_name="r007-t0",
        mount_table_fingerprint="f"*64,
        actual_host_safety_verified=True,
        no_ambient_credentials_observed=True,
        no_ambient_proxy_observed=True,
        no_writable_nonlocal_mounts_observed=True)

def _ctx():
    # Exact type is required; only name is read by constructor in this T0.
    item=object.__new__(WorkspaceContext)
    object.__setattr__(item,"name","a")
    object.__setattr__(item,"settings",None)
    object.__setattr__(item,"pinned_root",None)
    object.__setattr__(item,"gateway",None)
    return item

def _primitives(monkeypatch):
    plan=_plan(); recipe=_recipe(plan); host=_host()
    consumed=object.__new__(D4ConsumedOwnerGrant)
    marker=object.__new__(D4OneUseAttemptMarker)
    monkeypatch.setattr(D4ConsumedOwnerGrant,"check_binding",
                        lambda self,p,r: None)
    monkeypatch.setattr(D4OneUseAttemptMarker,"consume_for",
                        lambda self,p: None)
    monkeypatch.setattr(mod,"verify_r006_fixed_host_allowlist_t0",
                        lambda: host)
    return plan,recipe,host,consumed,marker

def test_fake_popen_receives_exact_recipe_only_after_all_rechecks(monkeypatch):
    plan,recipe,host,consumed,marker=_primitives(monkeypatch)
    calls=[]
    fake=object()
    def popen(argv,**kw):
        calls.append((argv,kw)); return fake
    monkeypatch.setattr(subprocess,"Popen",popen)
    boundary=D4R006NativeLaunchBoundary(
        _ctx(),plan,recipe,host,consumed,marker)
    assert boundary.launch(plan) is fake
    assert calls==[([
        "/private/bin/python","-m","pytest","-q"],{
        "cwd":"/private/py-direct",
        "env":{"HOME":"/private/home","PATH":"/private/bin:/usr/bin:/bin",
               "PYTHONNOUSERSITE":"1","TMPDIR":"/private/tmp"},
        "stdin":subprocess.DEVNULL,"stdout":subprocess.PIPE,
        "stderr":subprocess.PIPE,"close_fds":True,"start_new_session":False})]

@pytest.mark.parametrize("failure",["consumed","marker","host"])
def test_prelaunch_failure_has_zero_popen(monkeypatch,failure):
    plan,recipe,host,consumed,marker=_primitives(monkeypatch)
    calls=[]
    monkeypatch.setattr(subprocess,"Popen",lambda *a,**k:calls.append(True))
    if failure=="consumed":
        monkeypatch.setattr(D4ConsumedOwnerGrant,"check_binding",
            lambda *a: (_ for _ in ()).throw(D4OwnerBootstrapDenied("x")))
    elif failure=="marker":
        monkeypatch.setattr(D4OneUseAttemptMarker,"consume_for",
            lambda *a: (_ for _ in ()).throw(D4FixtureDenied("x")))
    else:
        monkeypatch.setattr(mod,"verify_r006_fixed_host_allowlist_t0",
                            lambda: _host().__class__(**{
                                **{f:getattr(host,f) for f in host.__dataclass_fields__},
                                "image_version":"changed"}))
    if failure=="consumed":
        with pytest.raises(D4R006NativeRunnerDenied):
            D4R006NativeLaunchBoundary(_ctx(),plan,recipe,host,consumed,marker)
    else:
        boundary=D4R006NativeLaunchBoundary(
            _ctx(),plan,recipe,host,consumed,marker)
        with pytest.raises(LbeNoChildStarted):
            boundary.launch(plan)
    assert calls==[]

def test_recipe_or_environment_mismatch_rejected_before_popen(monkeypatch):
    plan,recipe,host,consumed,marker=_primitives(monkeypatch)
    bad=D4NativeLaunchRecipe(
        **{**{f:getattr(recipe,f) for f in recipe.__dataclass_fields__},
           "resolved_spawn_argv":("/private/bin/python","-c","bad")})
    with pytest.raises(D4R006NativeRunnerDenied):
        D4R006NativeLaunchBoundary(_ctx(),plan,bad,host,consumed,marker)

def test_popen_exception_is_not_mislabeled_no_child(monkeypatch):
    plan,recipe,host,consumed,marker=_primitives(monkeypatch)
    boundary=D4R006NativeLaunchBoundary(_ctx(),plan,recipe,host,consumed,marker)
    monkeypatch.setattr(subprocess,"Popen",
        lambda *a,**k: (_ for _ in ()).throw(OSError("ambiguous")))
    with pytest.raises(OSError):
        boundary.launch(plan)


_VECTORS = (
    ("py-direct", "direct",
     ("python", "-m", "pytest", "-q"),
     ("python", "-m", "pytest", "-q"), None),
    ("py-direct", "direct",
     ("python", "-m", "compileall", "-q", "./src"),
     ("python", "-m", "compileall", "-q", "./src"), None),
    ("py-pipenv", "pipenv",
     ("python", "-m", "pytest", "-q"),
     ("pipenv", "run", "python", "-m", "pytest", "-q"), None),
    ("go-project", "direct",
     ("go", "test", "./..."), ("go", "test", "./..."), None),
    ("go-project", "direct",
     ("go", "vet", "./..."), ("go", "vet", "./..."), None),
    ("go-project", "direct",
     ("go", "build", "-o", "bin/app", "./cmd/app"),
     ("go", "build", "-o", "bin/app", "./cmd/app"), "go-project/bin/app"),
)


def _vector_plan(cwd, runner, requested, effective, go_output):
    return LbeWorkPlan(
        workspace="a", cwd=cwd,
        requested_argv=requested, effective_argv=effective,
        runner=runner, runner_project=cwd, timeout_seconds=120,
        planned_go_output=go_output,
        planned_script_sha256=None,
        planned_pipfile_sha256=("a" * 64 if runner == "pipenv" else None),
    )


def _vector_recipe(plan):
    executable = {
        "go": "/private/bin/go",
        "pipenv": "/private/bin/pipenv",
        "python": "/private/bin/python",
    }[plan.effective_argv[0]]
    return D4NativeLaunchRecipe(
        workspace=plan.workspace,
        profile_git_blob="f8556b48ab5f4af7390fb015092862a8a87768fb",
        runner=plan.runner, requested_argv=plan.requested_argv,
        service_effective_argv=plan.effective_argv,
        resolved_executable=executable,
        resolved_spawn_argv=(executable, *plan.effective_argv[1:]),
        working_directory="/private/" + plan.cwd,
        closed_child_environment=(
            ("HOME", "/private/home"),
            ("PATH", "/private/bin:/usr/bin:/bin"),
            ("TMPDIR", "/private/tmp"),
        ),
        selected_source_fingerprint=PRODUCT,
        canonical_output_path=(
            "/private/" + plan.planned_go_output
            if plan.planned_go_output is not None else None),
        original_timeout_seconds=plan.timeout_seconds,
    )


@pytest.mark.parametrize(
    "cwd,runner,requested,effective,go_output", _VECTORS)
def test_all_six_r006_product_vectors_reach_one_exact_native_boundary_t0(
        monkeypatch, cwd, runner, requested, effective, go_output):
    plan = _vector_plan(cwd, runner, requested, effective, go_output)
    recipe = _vector_recipe(plan)
    host = _host()
    consumed = object.__new__(D4ConsumedOwnerGrant)
    marker = object.__new__(D4OneUseAttemptMarker)
    monkeypatch.setattr(
        D4ConsumedOwnerGrant, "check_binding", lambda self, p, r: None)
    monkeypatch.setattr(
        D4OneUseAttemptMarker, "consume_for", lambda self, p: None)
    monkeypatch.setattr(
        mod, "verify_r006_fixed_host_allowlist_t0", lambda: host)
    calls = []
    sentinel = object()

    def fake_popen(argv, **kwargs):
        calls.append((argv, kwargs))
        return sentinel

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    boundary = D4R006NativeLaunchBoundary(
        _ctx(), plan, recipe, host, consumed, marker)
    assert boundary.launch(plan) is sentinel
    assert len(calls) == 1
    argv, kwargs = calls[0]
    assert argv == list(recipe.resolved_spawn_argv)
    assert kwargs["cwd"] == recipe.working_directory
    assert kwargs["env"] == dict(recipe.closed_child_environment)
    assert kwargs["stdin"] is subprocess.DEVNULL
    assert kwargs["stdout"] is subprocess.PIPE
    assert kwargs["stderr"] is subprocess.PIPE
    assert kwargs["close_fds"] is True
    assert kwargs["start_new_session"] is False
