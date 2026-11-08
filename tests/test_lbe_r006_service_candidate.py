"""Safe T0 of private R006 prepare -> owner grant -> durable consume -> Worker."""
from datetime import datetime, timezone
import json
import os
import time

import pytest

from gateway.core import GatewayError
from gateway.exec_state import ExecStateStore
from gateway.lbe_hosted_source_probe import D4HostedSelectedSourceObservation
from gateway.lbe_launch_recipe import D4NativeLaunchRecipe
from gateway.lbe_owner_grant import verify_d4_owner_github_comment_t0
from gateway.lbe_owner_grant_bootstrap import _argv_fingerprint
from gateway.lbe_product_fixture import D4OneUseAttemptMarker
from gateway.lbe_r006_macos_allowlist import (
    D4R006HostAllowlistObservation, R006_HOST_SOURCE_FINGERPRINT,
    R006_RUNNER_PROFILE_FINGERPRINT,
)
from gateway import lbe_r006_macos_allowlist as allowlist_mod
from gateway.lbe_r006_native_runner import (
    D4R006NativeLaunchBoundary, D4R006PreparedAttempt,
)
from gateway.lbe_r006_review_gate import D4VerifiedReviewPair
from gateway.lbe_r006_trusted_bootstrap import D4TrustedBootstrapBundle
from gateway.lbe_r006_runtime_identity import D4VerifiedRuntimeIdentity
from gateway.lbe_worker import LbeNoChildStarted
from gateway.workspaces import ActiveRuntimeInventory, WorkspaceService
from gateway.workspaces_config import parse_workspace_config

H = "a" * 40
M = "b" * 64
PRODUCT = "d" * 64
NOW = 1794100000


def _host():
    obs = D4HostedSelectedSourceObservation(
        root_identity=(1, 2, 3, 4, 5, 0o40755, 0, 1),
        selected=(("x", M, (1, 2, 1, 4, 5, 0o100444, 0, 1)),),
        root_ancestor_identities=((1, 2, 0o40755, 0),),
    )
    return D4R006HostAllowlistObservation(
        system=obs, usr=obs,
        source_fingerprint=R006_HOST_SOURCE_FINGERPRINT,
        runner_profile_fingerprint=R006_RUNNER_PROFILE_FINGERPRINT,
        image_version="20261104.0514.1", macos_version="15.8.2",
        os_build="24H232",
    )


def _service(tmp_path):
    root = tmp_path / "projects" / "a"
    (root / "py-direct" / "src").mkdir(parents=True)
    (root / "py-direct" / "src" / "main.py").write_text("x = 1\n")
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    private.chmod(0o700)
    (private / "d4-journal").mkdir(mode=0o700)
    store = ExecStateStore(
        private / "exec-state", workspace_roots=(str(root),))
    store.close()
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    settings = parse_workspace_config({
        "schema_version": 2,
        "server": {"port": 8765, "transport": "http"},
        "workspaces": {
            "a": {"root": str(root), "exec": {"paths": ["py-direct"]}},
        },
    })
    return (WorkspaceService(
        settings, config_dir=private,
        inventory=ActiveRuntimeInventory(paths=(runtime,))),
        private)


def _recipe(plan):
    return D4NativeLaunchRecipe(
        workspace=plan.workspace,
        profile_git_blob="f8556b48ab5f4af7390fb015092862a8a87768fb",
        runner=plan.runner, requested_argv=plan.requested_argv,
        service_effective_argv=plan.effective_argv,
        resolved_executable="/private/bin/python",
        resolved_spawn_argv=(
            "/private/bin/python", *plan.effective_argv[1:]),
        working_directory="/private/py-direct",
        closed_child_environment=(
            ("HOME", "/private/home"),
            ("PATH", "/private/bin:/usr/bin:/bin"),
            ("PYTHONNOUSERSITE", "1"),
            ("TMPDIR", "/private/tmp"),
        ),
        selected_source_fingerprint=PRODUCT,
        canonical_output_path=None,
        original_timeout_seconds=plan.timeout_seconds,
    )


def _grant(plan):
    created = datetime.fromtimestamp(
        NOW, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    expires = datetime.fromtimestamp(
        NOW + 900, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    p = {
        "authorization": "PRODUCT_T1_ONE_ATTEMPT_ONLY",
        "risk_acceptance": "R006_NINE_RESIDUAL_RISKS_ACCEPTED",
        "repo": "chinanjjohn2012/mac-file-gateway", "pr": 114,
        "base_sha": H, "head_sha": H, "head_tree": H,
        "manifest_sha256": M,
        "r006_design_blob": "b8d8a1cb32fb7130dfa6d00b37831dfddfaad11c",
        "b_design_review_id": "PRR_kwDOU5v3IM8AAAABWq0I_w",
        "c_design_review_id": "PRR_kwDOU5v3IM8AAAABWq0iKA",
        "b_code_review_id": "PRR_currentStandards123",
        "c_code_review_id": "PRR_currentSpecReview123",
        "github_run_id": 42445537246, "github_run_attempt": 1,
        "image_os": "macos15", "image_version": "20261104.0514.1",
        "os_build": "24H232",
        "source_fingerprint": R006_HOST_SOURCE_FINGERPRINT,
        "runner_fingerprint": R006_RUNNER_PROFILE_FINGERPRINT,
        "product_recipe_fingerprint": PRODUCT,
        "workspace": plan.workspace, "cwd": plan.cwd,
        "runner": plan.runner,
        "requested_argv_sha256": _argv_fingerprint(plan.requested_argv),
        "effective_argv_sha256": _argv_fingerprint(plan.effective_argv),
        "timeout_seconds": plan.timeout_seconds,
        "nonce": "c" * 64, "expires_at": expires,
    }
    cid = 7712345678
    obj = {
        "id": cid,
        "body": "R006_OWNER_T1_GRANT_V1\n" + json.dumps(
            p, sort_keys=True, separators=(",", ":")),
        "html_url": (
            "https://github.com/chinanjjohn2012/mac-file-gateway/pull/114"
            f"#issuecomment-{cid}"),
        "issue_url": (
            "https://api.github.com/repos/chinanjjohn2012/mac-file-gateway/issues/114"),
        "created_at": created, "updated_at": created,
        "author_association": "OWNER",
        "user": {"login": "chinanjjohn2012", "type": "User"},
        "performed_via_github_app": None,
    }
    return verify_d4_owner_github_comment_t0(
        json.dumps(obj, separators=(",", ":")).encode())


def _patch_assembly(service, monkeypatch, host):
    candidate = service._prepare_d4_r003_fixture_candidate(
        "a", "py-direct", ["python", "-m", "pytest", "-q"],
        timeout_seconds=120)
    ctx = service.get("a")
    marker = D4OneUseAttemptMarker(candidate, ctx)
    recipe = _recipe(candidate.plan)

    def assembled(_self, *_a, **_kw):
        return candidate, marker, None, recipe, None, None, None, ()

    monkeypatch.setattr(
        WorkspaceService, "_assemble_d4_r003_source_only_runner", assembled)
    monkeypatch.setattr(
        allowlist_mod, "verify_r006_fixed_host_allowlist_t0", lambda: host)
    return candidate, recipe


def _bootstrap(monkeypatch, plan, *, head_sha=H):
    grant = _grant(plan)
    reviews = object.__new__(D4VerifiedReviewPair)
    monkeypatch.setattr(
        D4VerifiedReviewPair, "check_grant", lambda self, value: None)
    runtime = object.__new__(D4VerifiedRuntimeIdentity)
    for name, value in {
        "_base_sha": H, "_head_sha": head_sha, "_head_tree": H,
        "_manifest_sha256": M, "_run_id": 42445537246,
        "_run_attempt": 1, "_pid": os.getpid(),
    }.items():
        object.__setattr__(runtime, name, value)
    bundle = object.__new__(D4TrustedBootstrapBundle)
    monkeypatch.setattr(
        D4TrustedBootstrapBundle, "components",
        lambda self: (grant, reviews, runtime))
    return bundle


def _prepare(service):
    return service._prepare_d4_r006_private_attempt(
        "a", "py-direct", ["python", "-m", "pytest", "-q"],
        private_root="/not-used-by-patched-assembly",
        provisioner_root="/not-used-by-patched-assembly",
        staged_manifests={"bin": (), "lib": ()},
        timeout_seconds=120,
    )


def test_private_candidate_consumes_grant_before_worker_but_public_exec_stays_denied(
        tmp_path, monkeypatch):
    monkeypatch.setattr(time, "time", lambda: NOW)
    service, private = _service(tmp_path)
    host = _host()
    candidate, recipe = _patch_assembly(service, monkeypatch, host)
    prepared = _prepare(service)
    assert type(prepared) is D4R006PreparedAttempt
    assert prepared.recipe_fingerprint == PRODUCT

    # Safe T0: Worker reaches its launcher, but this test supplies an explicit
    # no-child witness instead of invoking the new Popen source boundary.
    monkeypatch.setattr(
        D4R006NativeLaunchBoundary, "launch",
        lambda self, plan: (_ for _ in ()).throw(
            LbeNoChildStarted("T0 no child")))

    try:
        # Parser-built pieces or arbitrary objects are no longer a product
        # entrypoint. Reject before burning the prepared candidate.
        with pytest.raises(GatewayError):
            service._execute_d4_r006_private_attempt(
                prepared, object())
        assert list((private / "d4-journal").iterdir()) == []

        result = service._execute_d4_r006_private_attempt(
            prepared, _bootstrap(monkeypatch, candidate.plan))
        assert result["status"] == "launch_failed"
        assert result["executed"] is False
        assert len(list((private / "d4-journal").iterdir())) == 1

        with pytest.raises(GatewayError):
            service._execute_d4_r006_private_attempt(
                prepared, _bootstrap(monkeypatch, candidate.plan))

        with pytest.raises(GatewayError) as denied:
            service.invoke_exec(
                "a", "py-direct", ["python", "-m", "pytest", "-q"],
                timeout_seconds=120, dry_run=False)
        assert denied.value.code == "exec_cleanup_proof_required"
    finally:
        service.close()


def test_wrong_runtime_binding_burns_prepared_candidate_without_durable_record(
        tmp_path, monkeypatch):
    monkeypatch.setattr(time, "time", lambda: NOW)
    service, private = _service(tmp_path)
    host = _host()
    candidate, _recipe_value = _patch_assembly(service, monkeypatch, host)
    prepared = _prepare(service)
    try:
        with pytest.raises(GatewayError):
            service._execute_d4_r006_private_attempt(
                prepared, _bootstrap(
                    monkeypatch, candidate.plan, head_sha="e" * 40))
        assert list((private / "d4-journal").iterdir()) == []
        with pytest.raises(GatewayError):
            service._execute_d4_r006_private_attempt(
                prepared, _bootstrap(monkeypatch, candidate.plan))
    finally:
        service.close()
