"""M2 SOURCE_TOOLCHAIN_T1 preparation T0: synthetic, nonoperative only.

The existing Linux CI runs these tests. No real Go/Pipenv entrypoint,
network probe, system policy, timeout signal, or other native T1 is performed.
"""
from __future__ import annotations

from dataclasses import replace
import hashlib
from pathlib import Path
from types import MappingProxyType
import socket
import subprocess

import pytest

from gateway.lbe_prelaunch_binding_t0 import (
    LbePrelaunchBindingT0Error,
    bind_go_prelaunch_t0, bind_pipenv_prelaunch_t0,
)
from gateway.lbe_m2_native_t1_preflight_t0 import (
    LbeM2T1PreflightError,
    prepare_m2_source_t1_plan_t0,
)

_HOST = "/usr/bin:/bin:/usr/sbin:/sbin"


def _write(root: Path, name: str, data: bytes, executable=False) -> str:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    if executable:
        path.chmod(0o700)
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def synthetic_stage(tmp_path):
    root = tmp_path / "stage"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    go = {
        "go/VERSION": _write(root, "go/VERSION", b"go1.27.3\n"),
        "go/bin/go": _write(root, "go/bin/go", b"fake go", True),
        "go/pkg/tool/darwin_arm64/compile": _write(
            root, "go/pkg/tool/darwin_arm64/compile", b"fake compile", True),
        "go/pkg/tool/darwin_arm64/link": _write(
            root, "go/pkg/tool/darwin_arm64/link", b"fake link", True),
        "go/src/runtime/proc.go": _write(
            root, "go/src/runtime/proc.go", b"package runtime\n"),
    }
    pip = {
        "project/Pipfile": _write(root, "project/Pipfile", b"[packages]\n"),
        "project/Pipfile.lock": _write(
            root, "project/Pipfile.lock", b"{}\n"),
        "project/.venv/pyvenv.cfg": _write(
            root, "project/.venv/pyvenv.cfg", b"version=3.13\n"),
        "project/.venv/bin/python": _write(
            root, "project/.venv/bin/python", b"fake python", True),
        "pipenv-env/bin/pipenv": _write(
            root, "pipenv-env/bin/pipenv", b"fake pipenv", True),
    }
    fixtures = {
        "fixture/go.mod": _write(root, "fixture/go.mod", b"module safe\n"),
        "fixture/cmd/service/main.go": _write(
            root, "fixture/cmd/service/main.go", b"package main\n"),
        "project/ok.py": _write(root, "project/ok.py", b"print('ok')\n"),
    }
    return root, go, pip, fixtures


def _stage_inputs(scene, kind):
    root, go, pip, _ = scene
    shared = dict(private_root=root, trusted_base=root.parent,
                  expected_members=go if kind == "go" else pip,
                  parent_env={"PATH": _HOST}, expected_parent_path=_HOST,
                  home=root / "home", temp=root / "tmp")
    if kind == "go":
        shared.update(go_path=root / "gopath",
                      mod_cache=root / "gomodcache",
                      build_cache=root / "gocache")
    return shared


def _stage_binding(scene, kind):
    args = _stage_inputs(scene, kind)
    return (bind_go_prelaunch_t0 if kind == "go" else
            bind_pipenv_prelaunch_t0)(**args)


def _proposal(scene, kind, **overrides):
    binding = _stage_binding(scene, kind)
    members = dict(binding.checked_member_sha256)
    extras = scene[3]
    if kind == "go":
        members.update({k: extras[k] for k in (
            "fixture/go.mod", "fixture/cmd/service/main.go")})
        argv = ("go", "test", "./...")
    else:
        members["project/ok.py"] = extras["project/ok.py"]
        argv = ("pipenv", "run", "python", "ok.py")
    request = dict(
        kind=kind, argv=argv, candidate=binding,
        m1_recheck_inputs=_stage_inputs(scene, kind),
        proposed_head="a" * 40, proposed_tree="b" * 40,
        source_lock=members,
        runner=dict(
            provider="GITHUB_HOSTED_DISPOSABLE", os="macOS",
            os_major="15", arch="ARM64", python="3.13",
            image_id="macos15-arm64-proposed"),
        budget=dict(
            job_seconds=1200, child_seconds=120,
            cpu_seconds=120, memory_mib=2048,
            stdout_raw_bytes=48000, stderr_raw_bytes=48000,
            stdout_redacted_chars=48000, stderr_redacted_chars=48000,
            active_source_children=1),
        offline_policy=dict(
            mode="OFFLINE_ONLY", mechanism="ISOLATED_DISPOSABLE_VM",
            tcp="DENY", udp="DENY", dns="DENY", proxy="DENY",
            descendants="SAME_ENFORCEMENT_DOMAIN",
            attachment="BEFORE_ANY_NATIVE_INSTRUCTION",
            canary="SAME_DOMAIN_DENIAL_REQUIRED"),
    )
    request.update(overrides)
    return prepare_m2_source_t1_plan_t0(**request)


@pytest.mark.parametrize("kind", ["go", "pipenv"])
def test_real_m1_candidate_produces_only_blocked_m2_plan(
        synthetic_stage, kind, monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("native spawn or network is forbidden by T0")
    with monkeypatch.context() as m:
        m.setattr(subprocess, "Popen", forbidden)
        m.setattr(socket, "socket", forbidden)
        plan = _proposal(synthetic_stage, kind)
    assert plan.review_target == "STANDALONE_SOURCE_TOOLCHAIN_T1"
    assert plan.status == "NONOPERATIVE_M2_TEST_PLAN_T0"
    assert plan.kind == kind
    assert plan.native_t1 == "NOT_RUN"
    assert plan.launch_allowed is False
    assert plan.workspace_service_exec_authorized is False
    assert plan.loaded_source_identity == "NOT_ATTESTED"
    assert plan.runner_execution_identity == "NOT_ATTESTED"
    assert plan.precontact_egress_enforcement == "NOT_ATTESTED"
    assert plan.resource_enforcement == "NOT_ATTESTED"
    assert plan.same_domain_canary == "NOT_RUN"
    assert "PRECONTACT_DENY_ALL_EGRESS_NOT_ATTESTED" in plan.blockers
    assert "SAME_DOMAIN_PRECONTACT_DENIAL_CANARY_NOT_RUN" in plan.blockers
    for name in ("source_lock", "runner_proposal", "budget_proposal",
                 "egress_proposal"):
        with pytest.raises(TypeError):
            getattr(plan, name)["arbitrary"] = "wrong"


@pytest.mark.parametrize("argv", [
    ("go", "vet", "./..."),
    ("go", "build", "./cmd/service"),
    ("go", "build", "-o", "bin/service", "./cmd/service"),
])
def test_go_approved_source_only_matrix_stays_nonoperative(
        synthetic_stage, argv):
    plan = _proposal(synthetic_stage, "go", argv=argv)
    assert plan.argv == argv and plan.launch_allowed is False


@pytest.mark.parametrize("kind,argv", [
    ("go", ("go", "run", "./...")),
    ("go", ("go", "build", "-o", "/tmp/escape", "./cmd/service")),
    ("go", ("go", "build", "-toolexec=/outside", "./...")),
    ("go", ("go", "test", "../outside")),
    ("go", ("bash", "-c", "go test ./...")),
    ("pipenv", ("pipenv", "install")),
    ("pipenv", ("pipenv", "run", "python", "-c", "print(1)")),
    ("pipenv", ("pipenv", "run", "python", "../escape.py")),
    ("pipenv", ("python", "ok.py")),
    ("pipenv", ("pipenv", "run", "go", "test", "./...")),
])
def test_disallowed_or_modified_t1_commands_denied(synthetic_stage, kind, argv):
    with pytest.raises(LbeM2T1PreflightError):
        _proposal(synthetic_stage, kind, argv=argv)


@pytest.mark.parametrize("wrong", [
    [], ["go", "test", "./..."], ["pipenv", "run", "python", "ok.py"],
])
def test_command_is_not_loosened_by_mutable_argv(synthetic_stage, wrong):
    with pytest.raises(LbeM2T1PreflightError):
        _proposal(synthetic_stage, "go", argv=wrong)


@pytest.mark.parametrize("kind", ["go", "pipenv"])
@pytest.mark.parametrize("sha", ["x" * 40, "A" * 40, "", None])
def test_invalid_commit_identity_denied(synthetic_stage, kind, sha):
    with pytest.raises(LbeM2T1PreflightError):
        _proposal(synthetic_stage, kind, proposed_head=sha)


@pytest.mark.parametrize("kind", ["go", "pipenv"])
def test_identical_head_and_tree_denied(synthetic_stage, kind):
    with pytest.raises(LbeM2T1PreflightError):
        _proposal(synthetic_stage, kind, proposed_tree="a" * 40)


@pytest.mark.parametrize("kind", ["go", "pipenv"])
def test_source_lock_must_match_actual_checked_m1_members(synthetic_stage, kind):
    valid = _proposal(synthetic_stage, kind)
    changed = dict(valid.source_lock)
    member = next(iter(sorted(
        name for name in changed if name != "project/ok.py"
        and not name.startswith("fixture/"))))
    changed[member] = "0" * 64
    with pytest.raises(LbeM2T1PreflightError):
        _proposal(synthetic_stage, kind, source_lock=changed)


@pytest.mark.parametrize("kind", ["go", "pipenv"])
def test_source_lock_requires_fixture_and_valid_paths(synthetic_stage, kind):
    valid = _proposal(synthetic_stage, kind)
    omitted = dict(valid.source_lock)
    omitted.pop("fixture/go.mod" if kind == "go" else "project/ok.py")
    with pytest.raises(LbeM2T1PreflightError):
        _proposal(synthetic_stage, kind, source_lock=omitted)
    rogue = dict(valid.source_lock)
    rogue["../outside"] = "a" * 64
    with pytest.raises(LbeM2T1PreflightError):
        _proposal(synthetic_stage, kind, source_lock=rogue)
    corrupt = dict(valid.source_lock)
    corrupt[next(iter(corrupt))] = "NOT_A_SHA256"
    with pytest.raises(LbeM2T1PreflightError):
        _proposal(synthetic_stage, kind, source_lock=corrupt)


@pytest.mark.parametrize("field,value", [
    ("provider", "LOCAL_USER_MAC"), ("os", "Linux"),
    ("os_major", "14"), ("arch", "x86_64"),
    ("python", "3.12"), ("image_id", "not an image identity"),
])
def test_wrong_or_ambiguous_runner_profile_denied(
        synthetic_stage, field, value):
    good = _proposal(synthetic_stage, "go")
    wrong = dict(good.runner_proposal)
    wrong[field] = value
    with pytest.raises(LbeM2T1PreflightError):
        _proposal(synthetic_stage, "go", runner=wrong)


@pytest.mark.parametrize("field,value", [
    ("job_seconds", 1201), ("child_seconds", 121),
    ("cpu_seconds", 121), ("memory_mib", 2049),
    ("stdout_raw_bytes", 48001), ("stderr_raw_bytes", 48001),
    ("stdout_redacted_chars", 48001),
    ("stderr_redacted_chars", 48001),
    ("active_source_children", 2),
    ("child_seconds", 0), ("cpu_seconds", True),
])
def test_unbounded_resource_proposal_denied(synthetic_stage, field, value):
    good = _proposal(synthetic_stage, "go")
    budget = dict(good.budget_proposal)
    budget[field] = value
    with pytest.raises(LbeM2T1PreflightError):
        _proposal(synthetic_stage, "go", budget=budget)


@pytest.mark.parametrize("field,value", [
    ("mode", "BOUNDED_EGRESS"),
    ("mechanism", "GOPROXY=off"),
    ("mechanism", "PIP_NO_INDEX=1"),
    ("tcp", "ALLOW"), ("udp", "ALLOW"),
    ("dns", "ALLOW"), ("proxy", "ALLOW"),
    ("descendants", "PARENT_ONLY"),
    ("attachment", "AFTER_NATIVE_START"),
    ("canary", "POST_CONTACT_URL_MONITOR"),
])
def test_no_weak_or_postcontact_network_isolation(
        synthetic_stage, field, value):
    good = _proposal(synthetic_stage, "pipenv")
    policy = dict(good.egress_proposal)
    policy[field] = value
    with pytest.raises(LbeM2T1PreflightError):
        _proposal(synthetic_stage, "pipenv", offline_policy=policy)


def test_claimed_successful_network_attestation_is_not_a_capability(
        synthetic_stage):
    good = _proposal(synthetic_stage, "go")
    fake = dict(good.egress_proposal)
    fake["policy_attached"] = "true"
    fake["canary_passed"] = "true"
    with pytest.raises(LbeM2T1PreflightError):
        _proposal(synthetic_stage, "go", offline_policy=fake)
    # Even a perfectly shaped request is only a design; no actual OS witness.
    assert good.launch_allowed is False
    assert good.same_domain_canary == "NOT_RUN"


@pytest.mark.parametrize("kind", ["go", "pipenv"])
def test_qualified_m1_candidate_is_required_and_cannot_mint_authority(
        synthetic_stage, kind):
    valid = _proposal(synthetic_stage, kind)
    binding = _stage_binding(synthetic_stage, kind)
    for altered in (
        replace(binding, exec_authorized=True),
        replace(binding, source_loaded_identity="ATTESTED"),
        replace(binding, original_child_native_t1="PASS"),
        replace(binding, status="NATIVE_T1_READY"),
    ):
        with pytest.raises(LbeM2T1PreflightError):
            _proposal(synthetic_stage, kind, candidate=altered)
    assert valid.launch_allowed is False


@pytest.mark.parametrize("kind,selector", [
    ("go", "GOFLAGS"), ("pipenv", "PIPENV_PYTHON"),
])
def test_parent_runtime_shadow_denied_before_any_m2_plan(
        synthetic_stage, kind, selector):
    root, go, pip, _ = synthetic_stage
    args = dict(private_root=root, trusted_base=root.parent,
                expected_members=go if kind == "go" else pip,
                parent_env={"PATH": _HOST, selector: "/outside"},
                expected_parent_path=_HOST,
                home=root / "home", temp=root / "tmp")
    if kind == "go":
        args.update(go_path=root / "gopath",
                    mod_cache=root / "gomodcache",
                    build_cache=root / "gocache")
    with pytest.raises(LbePrelaunchBindingT0Error):
        (bind_go_prelaunch_t0 if kind == "go" else
         bind_pipenv_prelaunch_t0)(**args)


# Independent B/C r001 review cases: actual module negative tests, not mock
# replacements for review, not real foreign native execution.


@pytest.mark.parametrize("kind,poison", [
    ("go", {"GOFLAGS": "-toolexec=/outside/unreviewed-tool"}),
    ("go", {"PATH": "/outside/attacker/bin"}),
    ("go", {"LD_PRELOAD": "/outside/attacker.so"}),
    ("pipenv", {"PATH": "/outside/attacker/bin"}),
    ("pipenv", {"PIPENV_PYTHON": "/outside/python"}),
    ("pipenv", {"PIPENV_PIPFILE": "/outside/attacker/Pipfile"}),
])
def test_review_p2_108_01_forged_m1_closed_env_is_denied(
        synthetic_stage, kind, poison, monkeypatch):
    """A public frozen dataclass's status must not qualify forged env bytes."""
    real = _stage_binding(synthetic_stage, kind)
    altered = dict(real.child_env)
    altered.update(poison)
    forged = replace(real, child_env=MappingProxyType(altered))

    def no_child(*_args, **_kwargs):
        raise AssertionError("nonoperative T0 must never spawn")
    monkeypatch.setattr(subprocess, "Popen", no_child)
    monkeypatch.setattr(socket, "socket", no_child)
    with pytest.raises(LbeM2T1PreflightError):
        _proposal(synthetic_stage, kind, candidate=forged)


@pytest.mark.parametrize("kind", ["go", "pipenv"])
def test_review_p2_108_01_forged_m1_sha_map_denied_even_when_lock_matches(
        synthetic_stage, kind, monkeypatch):
    """Caller-provided equal fake candidate/source_lock is not FD evidence."""
    real = _stage_binding(synthetic_stage, kind)
    original = _proposal(synthetic_stage, kind)
    member = "go/VERSION" if kind == "go" else "project/Pipfile"
    altered = dict(real.checked_member_sha256)
    altered[member] = "f" * 64
    forged = replace(real, checked_member_sha256=MappingProxyType(altered))
    matching_fake_lock = dict(original.source_lock)
    matching_fake_lock[member] = "f" * 64

    def no_child(*_args, **_kwargs):
        raise AssertionError("nonoperative T0 must never spawn")
    monkeypatch.setattr(subprocess, "Popen", no_child)
    with pytest.raises(LbeM2T1PreflightError):
        _proposal(synthetic_stage, kind, candidate=forged,
                  source_lock=matching_fake_lock)


@pytest.mark.parametrize("bad_kind", [
    [], {}, set(), None, 7, ["go"], {"go": True},
])
def test_review_p2_108_02_unhashable_kind_is_normalized(
        synthetic_stage, bad_kind, monkeypatch):
    def no_child(*_args, **_kwargs):
        raise AssertionError("nonoperative T0 must never spawn")
    monkeypatch.setattr(subprocess, "Popen", no_child)
    with pytest.raises(LbeM2T1PreflightError):
        _proposal(synthetic_stage, "go", kind=bad_kind)


@pytest.mark.parametrize("field", ["mode", "mechanism", "tcp", "canary"])
def test_review_p2_108_02_hostile_policy_comparison_is_never_invoked(
        synthetic_stage, field, monkeypatch):
    class HostileEquality:
        def __eq__(self, _other):
            raise AssertionError("dangerous comparison was called")
        def __ne__(self, _other):
            raise AssertionError("dangerous comparison was called")

    policy = dict(_proposal(synthetic_stage, "pipenv").egress_proposal)
    policy[field] = HostileEquality()

    def no_child(*_args, **_kwargs):
        raise AssertionError("nonoperative T0 must never spawn")
    monkeypatch.setattr(subprocess, "Popen", no_child)
    with pytest.raises(LbeM2T1PreflightError):
        _proposal(synthetic_stage, "pipenv", offline_policy=policy)


def test_review_p3_108_01_child_budget_must_fit_inside_job(synthetic_stage):
    budget = dict(_proposal(synthetic_stage, "go").budget_proposal)
    budget["job_seconds"] = 60
    budget["child_seconds"] = 120
    with pytest.raises(LbeM2T1PreflightError):
        _proposal(synthetic_stage, "go", budget=budget)



@pytest.mark.parametrize("kind,relative", [
    ("go", "go/VERSION"),
    ("pipenv", "project/Pipfile"),
])
def test_review_m1_rehash_rejects_stage_changed_after_original_check(
        synthetic_stage, kind, relative, monkeypatch):
    """Original M1 candidate checked, then underlying file is changed at M2."""
    actual = prepare_m2_source_t1_plan_t0
    root = synthetic_stage[0]

    def modify_after_m1_binding_before_m2(**kwargs):
        (root / relative).write_bytes(b"changed after the M1 source-only pass")
        return actual(**kwargs)

    # This only simulates checked-source drift and never spawns a child.
    monkeypatch.setitem(globals(), "prepare_m2_source_t1_plan_t0",
                        modify_after_m1_binding_before_m2)
    with pytest.raises(LbeM2T1PreflightError):
        _proposal(synthetic_stage, kind)


@pytest.mark.parametrize("kind", ["go", "pipenv"])
def test_review_recheck_cannot_use_other_trusted_base(synthetic_stage, kind):
    original = _stage_inputs(synthetic_stage, kind)
    altered = dict(original)
    altered["trusted_base"] = synthetic_stage[0]
    with pytest.raises(LbeM2T1PreflightError):
        _proposal(synthetic_stage, kind, m1_recheck_inputs=altered)


@pytest.mark.parametrize("kind", ["go", "pipenv"])
@pytest.mark.parametrize("malformed", [None, [], {}, {"PATH": "wrong"}])
def test_review_recheck_requires_complete_exact_source_env_args(
        synthetic_stage, kind, malformed):
    with pytest.raises(LbeM2T1PreflightError):
        _proposal(synthetic_stage, kind, m1_recheck_inputs=malformed)


def test_review_budget_has_safe_job_child_margin_boundary(synthetic_stage):
    valid = dict(_proposal(synthetic_stage, "go").budget_proposal)
    valid["job_seconds"] = 180
    valid["child_seconds"] = 120
    plan = _proposal(synthetic_stage, "go", budget=valid)
    assert plan.native_t1 == "NOT_RUN"
    assert plan.launch_allowed is False
    valid["job_seconds"] = 179
    with pytest.raises(LbeM2T1PreflightError):
        _proposal(synthetic_stage, "go", budget=valid)


def test_review_untrusted_runner_comparisons_rejected_before_execution(
        synthetic_stage):
    class HostileComparison:
        def __ne__(self, _other):
            raise AssertionError("runner comparison must not run")

    good = _proposal(synthetic_stage, "go")
    invalid = dict(good.runner_proposal)
    invalid["provider"] = HostileComparison()
    with pytest.raises(LbeM2T1PreflightError):
        _proposal(synthetic_stage, "go", runner=invalid)
