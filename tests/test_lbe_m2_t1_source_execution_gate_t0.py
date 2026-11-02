"""SOURCE_TOOLCHAIN_T1 isolated-runner admission, T0 ONLY.

Synthetic fake Go/Pipenv files. No real foreign command, real egress canary,
OS sandbox, process, host firewall, signals, T2/T3, or product Exec.
"""
from __future__ import annotations

from dataclasses import replace
import hashlib
import os
from pathlib import Path
import socket
import subprocess
from types import MappingProxyType

import pytest

from gateway.lbe_m2_native_t1_preflight_t0 import (
    prepare_m2_source_t1_plan_t0,
)
from gateway.lbe_prelaunch_binding_t0 import (
    bind_go_prelaunch_t0, bind_pipenv_prelaunch_t0,
)
from gateway.lbe_m2_t1_source_tree_t0 import (
    LbeT1SourceTreeError, inspect_t1_private_source_tree_t0,
)
from gateway.lbe_m2_t1_source_execution_gate_t0 import (
    LbeT1SourceRunDenied, prepare_source_t1_execution_gate_t0,
    execute_source_toolchain_t1,
)
from gateway.lbe_source_preflight import (
    LbeSourcePreflightError, require_real_egress_witness_t0,
)

_HOST = "/usr/bin:/bin:/usr/sbin:/sbin"


def _file(root, name, data, executable=False):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(0o700 if executable else 0o600)
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def source_stage(tmp_path):
    base = tmp_path / "owner-controlled"
    base.mkdir(mode=0o700)
    base.chmod(0o700)
    go_root = base / "go-stage"
    pip_root = base / "pip-stage"
    for directory in (go_root, pip_root):
        directory.mkdir(mode=0o700)
        directory.chmod(0o700)
    go = {
        "go/VERSION": _file(go_root, "go/VERSION", b"go1.27.3\n"),
        "go/bin/go": _file(go_root, "go/bin/go", b"synthetic go", True),
        "go/pkg/tool/darwin_arm64/compile": _file(
            go_root, "go/pkg/tool/darwin_arm64/compile", b"synthetic compile", True),
        "go/pkg/tool/darwin_arm64/link": _file(
            go_root, "go/pkg/tool/darwin_arm64/link", b"synthetic link", True),
        "go/src/runtime/proc.go": _file(
            go_root, "go/src/runtime/proc.go", b"package runtime\n"),
        "fixture/go.mod": _file(go_root, "fixture/go.mod", b"module safe\n"),
        "fixture/cmd/service/main.go": _file(
            go_root, "fixture/cmd/service/main.go", b"package main\n"),
    }
    pipenv = {
        "project/Pipfile": _file(pip_root, "project/Pipfile", b"[packages]\n"),
        "project/Pipfile.lock": _file(pip_root, "project/Pipfile.lock", b"{}\n"),
        "project/.venv/pyvenv.cfg": _file(
            pip_root, "project/.venv/pyvenv.cfg", b"version=3.13\n"),
        "project/.venv/bin/python": _file(
            pip_root, "project/.venv/bin/python", b"synthetic Python", True),
        "pipenv-env/bin/pipenv": _file(
            pip_root, "pipenv-env/bin/pipenv", b"synthetic Pipenv", True),
        "project/ok.py": _file(pip_root, "project/ok.py", b"print('ok')\n"),
    }
    return base, {"go": go_root, "pipenv": pip_root}, {
        "go": go, "pipenv": pipenv,
    }


def _m1_args(scene, kind):
    base, roots, source = scene
    root = roots[kind]
    critical = {
        "go": ("go/VERSION", "go/bin/go",
               "go/pkg/tool/darwin_arm64/compile",
               "go/pkg/tool/darwin_arm64/link", "go/src/runtime/proc.go"),
        "pipenv": ("project/Pipfile", "project/Pipfile.lock",
                   "project/.venv/pyvenv.cfg",
                   "project/.venv/bin/python", "pipenv-env/bin/pipenv"),
    }
    common = dict(
        private_root=root, trusted_base=base,
        expected_members={
            name: source[kind][name] for name in critical[kind]
        },
        parent_env={"PATH": _HOST},
        expected_parent_path=_HOST,
        home=root / "home", temp=root / "tmp",
    )
    if kind == "go":
        common.update(
            go_path=root / "gopath", mod_cache=root / "gomodcache",
            build_cache=root / "gocache",
        )
    return common


def _plan(scene, kind):
    base, roots, sources = scene
    args = _m1_args(scene, kind)
    candidate = (bind_go_prelaunch_t0 if kind == "go" else
                 bind_pipenv_prelaunch_t0)(**args)
    return prepare_m2_source_t1_plan_t0(
        kind=kind,
        argv=(("go", "test", "./...") if kind == "go" else
              ("pipenv", "run", "python", "ok.py")),
        candidate=candidate, m1_recheck_inputs=args,
        proposed_head="a"*40, proposed_tree="b"*40,
        source_lock=dict(sources[kind]),
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


def _executables(kind):
    return (
        ("go/bin/go", "go/pkg/tool/darwin_arm64/compile",
         "go/pkg/tool/darwin_arm64/link")
        if kind == "go"
        else ("project/.venv/bin/python", "pipenv-env/bin/pipenv")
    )


def _prepare(scene, kind, **options):
    base, roots, _sources = scene
    root = roots[kind]
    args = dict(
        private_root=root, trusted_base=base,
        executable_members=_executables(kind),
    )
    args.update(options)
    if "plan" not in args:
        args["plan"] = _plan(scene, kind)
    return prepare_source_t1_execution_gate_t0(**args)


@pytest.mark.parametrize("kind", ("go", "pipenv"))
def test_real_m1_and_m2_t0_to_full_source_tree_still_block_execution(
    source_stage, kind, monkeypatch,
):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("T0 must not spawn or open a network socket")
    with monkeypatch.context() as m:
        m.setattr(subprocess, "Popen", forbidden)
        m.setattr(socket, "socket", forbidden)
        plan = _plan(source_stage, kind)
        stage = inspect_t1_private_source_tree_t0(
            private_root=source_stage[1][kind], trusted_base=source_stage[0],
            source_lock=dict(plan.source_lock),
            executable_members=_executables(kind),
        )
        gate = _prepare(source_stage, kind, plan=plan)

    actual_manifest = "".join(
        f"{plan.source_lock[name]}  ./{name}\n"
        for name in sorted(plan.source_lock)
    )
    assert stage.manifest_sha256 == hashlib.sha256(
        actual_manifest.encode("ascii")).hexdigest()
    assert gate.source_manifest_sha256 == stage.manifest_sha256
    assert gate.checked_source_members == len(plan.source_lock)
    assert gate.checked_source_bytes > 0
    assert gate.kind == kind
    assert gate.argv == plan.argv
    assert gate.native_t1 == "NOT_RUN"
    assert gate.execution_allowed is False
    assert gate.product_exec_authorized is False
    assert gate.status == "BLOCKED_PRECONTACT_EXECUTION_GATE_T0"
    assert gate.domain_policy == "NOT_ATTESTED"
    assert gate.domain_canary == "NOT_RUN"
    assert gate.runner_image_identity == "NOT_ATTESTED"
    assert gate.source_loaded_identity == "NOT_ATTESTED"
    assert gate.cpu_memory_enforced == "NOT_ATTESTED"
    assert "OFFLINE_ONLY_ATTACHED_CHILD_DESCENDANTS_NOT_ATTESTED" in gate.blockers
    assert "OS_CPU_MEMORY_WALL_AND_OUTPUT_CAPS_NOT_ENFORCED" in gate.blockers
    assert stage.actual_native_loaded_source == "NOT_ATTESTED"
    assert stage.snapshot_immutable_after_check is False
    assert stage.launch_allowed is False
    assert stage.native_t1 == "NOT_RUN"
    with pytest.raises(TypeError):
        stage.member_sha256["new"] = "f"*64


@pytest.mark.parametrize("kind", ("go", "pipenv"))
@pytest.mark.parametrize("status", (
    "NOT_ATTESTED", "VERIFIED", "PASSED", None, True, 1, {},
))
def test_source_t1_execution_entrypoint_hard_denies_claims(
    source_stage, kind, status, monkeypatch,
):
    plan = _plan(source_stage, kind)
    gate = _prepare(source_stage, kind, plan=plan)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("any native child or outbound probe is forbidden")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    with pytest.raises(LbeT1SourceRunDenied, match="NATIVE_T1=NOT_RUN"):
        execute_source_toolchain_t1(
            gate, {"owner": status}, {"egress_attached": status},
            {"runner_identity": status},
        )


@pytest.mark.parametrize("kind", ("go", "pipenv"))
def test_even_forged_successful_execution_receipt_cannot_unlock(
        source_stage, kind):
    gate = _prepare(source_stage, kind)
    forged = replace(
        gate, execution_allowed=True, domain_policy="ATTACHED",
        domain_canary="PASS", runner_image_identity="ATTESTED",
        source_loaded_identity="ATTESTED", cpu_memory_enforced="ATTESTED",
        native_t1="PASS", product_exec_authorized=True, blockers=(),
    )
    with pytest.raises(LbeT1SourceRunDenied):
        execute_source_toolchain_t1(forged, True, True, True)


@pytest.mark.parametrize("kind", ("go", "pipenv"))
def test_environment_claims_do_not_count_as_hosted_image_or_egress(
        source_stage, kind, monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("RUNNER_OS", "macOS")
    monkeypatch.setenv("RUNNER_ARCH", "ARM64")
    monkeypatch.setenv("GOPROXY", "off")
    monkeypatch.setenv("PIP_NO_INDEX", "1")
    monkeypatch.setenv("LBE_NATIVE_T1_AUTHORIZED", "YES")
    gate = _prepare(source_stage, kind)
    assert gate.execution_allowed is False
    assert gate.domain_policy == "NOT_ATTESTED"
    assert gate.runner_image_identity == "NOT_ATTESTED"
    with pytest.raises(LbeT1SourceRunDenied):
        execute_source_toolchain_t1(gate, True, True, True)


@pytest.mark.parametrize("kind", ("go", "pipenv"))
def test_unlisted_importable_pth_and_unreviewed_executable_are_denied(
        source_stage, kind):
    _, roots, _ = source_stage
    root = roots[kind]
    _file(root, "unreviewed/site-packages/autoimport.pth", b"import bad\n")
    with pytest.raises(LbeT1SourceRunDenied):
        _prepare(source_stage, kind)
    (root / "unreviewed/site-packages/autoimport.pth").unlink()
    (root / "unreviewed" / "rogue").write_text("evil\n")
    (root / "unreviewed" / "rogue").chmod(0o700)
    with pytest.raises(LbeT1SourceRunDenied):
        _prepare(source_stage, kind)


@pytest.mark.parametrize("kind", ("go", "pipenv"))
def test_unlisted_link_or_symlinked_directory_denied(
        source_stage, kind, tmp_path):
    _, roots, _ = source_stage
    root = roots[kind]
    (root / "import-shadow.py").symlink_to(
        tmp_path / "other-import.py")
    with pytest.raises(LbeT1SourceRunDenied):
        _prepare(source_stage, kind)
    (root / "import-shadow.py").unlink()
    (root / "unreviewed-module").symlink_to(root / "go", target_is_directory=True)
    with pytest.raises(LbeT1SourceRunDenied):
        _prepare(source_stage, kind)


@pytest.mark.parametrize("kind", ("go", "pipenv"))
def test_previously_locked_source_changed_after_m2_t0_denied(
        source_stage, kind):
    plan = _plan(source_stage, kind)
    _, roots, _ = source_stage
    root = roots[kind]
    member = "go/VERSION" if kind == "go" else "project/Pipfile.lock"
    (root / member).write_bytes(b"tampered after M2\n")
    with pytest.raises(LbeT1SourceRunDenied):
        _prepare(source_stage, kind, plan=plan)


@pytest.mark.parametrize("kind", ("go", "pipenv"))
def test_missing_locked_file_denied(source_stage, kind):
    plan = _plan(source_stage, kind)
    _, roots, _ = source_stage
    root = roots[kind]
    member = "fixture/go.mod" if kind == "go" else "project/ok.py"
    (root / member).unlink()
    with pytest.raises(LbeT1SourceRunDenied):
        _prepare(source_stage, kind, plan=plan)


@pytest.mark.parametrize("kind", ("go", "pipenv"))
def test_executable_mode_mismatch_denied(source_stage, kind):
    plan = _plan(source_stage, kind)
    _, roots, _ = source_stage
    root = roots[kind]
    member = _executables(kind)[0]
    (root / member).chmod(0o600)
    with pytest.raises(LbeT1SourceRunDenied):
        _prepare(source_stage, kind, plan=plan)


@pytest.mark.parametrize("kind", ("go", "pipenv"))
def test_group_writable_directory_or_file_denied(source_stage, kind):
    plan = _plan(source_stage, kind)
    _, roots, _ = source_stage
    root = roots[kind]
    (root / "project" if kind == "pipenv" else root / "go").chmod(0o770)
    with pytest.raises(LbeT1SourceRunDenied):
        _prepare(source_stage, kind, plan=plan)


@pytest.mark.parametrize("kind", ("go", "pipenv"))
def test_hardlinked_source_leaf_denied(source_stage, kind, tmp_path):
    plan = _plan(source_stage, kind)
    _, roots, _ = source_stage
    root = roots[kind]
    member = "go/VERSION" if kind == "go" else "project/Pipfile"
    os.link(root / member, tmp_path / "unreviewed-hardlink")
    with pytest.raises(LbeT1SourceRunDenied):
        _prepare(source_stage, kind, plan=plan)


@pytest.mark.parametrize("kind", ("go", "pipenv"))
def test_unlisted_fifo_refused_without_blocking(source_stage, kind):
    _, roots, _ = source_stage
    root = roots[kind]
    os.mkfifo(root / "unexpected.pipe")
    with pytest.raises(LbeT1SourceRunDenied):
        _prepare(source_stage, kind)


@pytest.mark.parametrize("kind", ("go", "pipenv"))
def test_untrusted_extra_source_lock_hash_rejected(
        source_stage, kind):
    plan = _plan(source_stage, kind)
    _, roots, _ = source_stage
    root = roots[kind]
    extra = _file(root, "extra.py", b"no\n")
    locked = dict(plan.source_lock)
    locked["extra.py"] = extra
    forged = replace(plan, source_lock=MappingProxyType(locked))
    # Exact bytes are present, but a forged M2 dataclass is still no authority.
    gate = _prepare(source_stage, kind, plan=forged)
    assert gate.execution_allowed is False
    assert gate.native_t1 == "NOT_RUN"


@pytest.mark.parametrize("kind", ("go", "pipenv"))
def test_wrong_digests_and_invalid_manifest_denied(
        source_stage, kind):
    plan = _plan(source_stage, kind)
    lock = dict(plan.source_lock)
    name = sorted(lock)[0]
    lock[name] = "0"*64
    forged = replace(plan, source_lock=MappingProxyType(lock))
    with pytest.raises(LbeT1SourceRunDenied):
        _prepare(source_stage, kind, plan=forged)
    for invalid in ({}, {"../escape": "a"*64}, {"ok.py": True}):
        with pytest.raises(LbeT1SourceTreeError):
            inspect_t1_private_source_tree_t0(
                private_root=source_stage[1][kind], trusted_base=source_stage[0],
                source_lock=invalid, executable_members=(),
            )


@pytest.mark.parametrize("kind", ("go", "pipenv"))
def test_executable_set_must_match_all_actual_executable_modes(
        source_stage, kind):
    plan = _plan(source_stage, kind)
    too_few = _executables(kind)[:-1]
    with pytest.raises(LbeT1SourceRunDenied):
        _prepare(source_stage, kind, plan=plan, executable_members=too_few)
    with pytest.raises(LbeT1SourceRunDenied):
        _prepare(source_stage, kind, plan=plan,
                 executable_members=_executables(kind) +
                 ("unknown/foreign",))


@pytest.mark.parametrize("kind", ("go", "pipenv"))
def test_scope_never_includes_product_workspaces_or_native_egress(
        source_stage, kind):
    receipt = _prepare(source_stage, kind)
    assert receipt.product_exec_authorized is False
    assert receipt.domain_policy == "NOT_ATTESTED"
    assert receipt.source_loaded_identity == "NOT_ATTESTED"
    with pytest.raises(LbeSourcePreflightError):
        require_real_egress_witness_t0({"claimed": "attached"})


@pytest.mark.parametrize("kind", ("go", "pipenv"))
def test_wrong_trusted_base_or_root_does_not_become_a_grant(
        source_stage, kind, tmp_path):
    plan = _plan(source_stage, kind)
    with pytest.raises(LbeT1SourceRunDenied):
        _prepare(source_stage, kind, plan=plan, trusted_base=tmp_path)
    with pytest.raises(LbeT1SourceRunDenied):
        _prepare(source_stage, kind, plan=plan, private_root=tmp_path)


@pytest.mark.parametrize("kind", ("go", "pipenv"))
def test_oversized_single_member_budget_fail_closed(
        source_stage, kind, monkeypatch):
    import gateway.lbe_m2_t1_source_tree_t0 as source
    monkeypatch.setattr(source, "_MAX_SINGLE", 3)
    with pytest.raises(LbeT1SourceRunDenied):
        _prepare(source_stage, kind)



@pytest.mark.parametrize("kind", ("go", "pipenv"))
@pytest.mark.parametrize("field,patch", (
    ("runner_proposal", {"provider": "USER_MAC"}),
    ("budget_proposal", {"child_seconds": 121}),
    ("budget_proposal", {"cpu_seconds": True}),
    ("egress_proposal", {"mode": "BOUNDED_EGRESS"}),
    ("egress_proposal", {"descendants": "PARENT_ONLY"}),
    ("egress_proposal", {"attachment": "AFTER_EXEC"}),
))
def test_forged_m2_plan_security_budget_or_runner_is_rejected(
        source_stage, kind, field, patch):
    plan = _plan(source_stage, kind)
    fake_map = dict(getattr(plan, field))
    fake_map.update(patch)
    forged = replace(plan, **{field: MappingProxyType(fake_map)})
    with pytest.raises(LbeT1SourceRunDenied):
        _prepare(source_stage, kind, plan=forged)


@pytest.mark.parametrize("kind", ("go", "pipenv"))
def test_forged_m2_plan_mappingproxy_dict_subclass_is_not_queried(
        source_stage, kind):
    plan = _plan(source_stage, kind)
    calls = []
    class LyingDict(dict):
        def items(self):
            calls.append("items")
            raise AssertionError("untrusted dict-subclass method ran")
        def __iter__(self):
            calls.append("iter")
            raise AssertionError("untrusted iterator ran")
    forged = replace(
        plan, egress_proposal=MappingProxyType(
            LyingDict(dict(plan.egress_proposal))))
    with pytest.raises(LbeT1SourceRunDenied):
        _prepare(source_stage, kind, plan=forged)
    assert calls == []


@pytest.mark.parametrize("kind", ("go", "pipenv"))
def test_forged_m2_plan_identity_or_stage_cannot_become_eligible(
        source_stage, kind):
    plan = _plan(source_stage, kind)
    for changed in (
        replace(plan, proposed_head="0"*40, proposed_tree="0"*40),
        replace(plan, status="NATIVE_T1_READY"),
        replace(plan, launch_allowed=True),
        replace(plan, native_t1="PASS"),
        replace(plan, review_target="T1_PRODUCT"),
    ):
        with pytest.raises(LbeT1SourceRunDenied):
            _prepare(source_stage, kind, plan=changed)
