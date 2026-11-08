"""Safe T0: durable R006 nonce consumption, no native child."""
from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from datetime import datetime, timezone
import json
import os
import subprocess
import time

import pytest

from gateway.lbe_durable_attempt import (
    D4AttemptIdentity, D4DurableAttemptDenied, D4DurableAttemptJournal,
)

S = "a" * 64
H = "b" * 40
R006 = "b8d8a1cb32fb7130dfa6d00b37831dfddfaad11c"


def example(nonce=S, run_attempt=1):
    return D4AttemptIdentity(
        nonce=nonce, run_id=1001, run_attempt=run_attempt,
        repo="chinanjjohn2012/mac-file-gateway", pr=114,
        base_sha=H, head_sha=H, head_tree=H,
        manifest_sha256=S, r006_design_blob=R006,
        b_design_review_id="PRR_kwDOU5v3IM8AAAABWq0I_w",
        c_design_review_id="PRR_kwDOU5v3IM8AAAABWq0iKA",
        b_code_review_id="PRR_currentStandards123",
        c_code_review_id="PRR_currentSpecReview123",
        image_version="20261104.0514.1", os_build="24G90",
        source_fingerprint=S, runner_fingerprint=S,
        workspace="first-party", cwd="src", runner="direct",
        requested_argv_fingerprint=S, effective_argv_fingerprint=S,
        timeout_seconds=120, owner_comment_id=7712345678,
        expires_at_unix=4102444800,
    )


def _open(tmp_path):
    root = tmp_path / "d4-ledger"
    root.mkdir(mode=0o700)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    return root, fd


def _in_other_process(path, identity):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with D4DurableAttemptJournal(fd) as ledger:
            return ledger.consume(identity)
    except D4DurableAttemptDenied:
        return "DENY"
    finally:
        os.close(fd)


def test_exact_attempt_consume_and_restart_replay_denied(tmp_path, monkeypatch):
    root, fd = _open(tmp_path)
    def forbidden(*args, **kwargs):
        raise AssertionError("T0 may not spawn or signal any child")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "kill", forbidden)
    try:
        with D4DurableAttemptJournal(fd) as journal:
            assert len(journal.consume(example())) == 64
            with pytest.raises(D4DurableAttemptDenied):
                journal.consume(example())
        with D4DurableAttemptJournal(fd) as restarted:
            with pytest.raises(D4DurableAttemptDenied):
                restarted.consume(example())
            # Even a distinct run attempt cannot reuse the SAME nonce.
            with pytest.raises(D4DurableAttemptDenied):
                restarted.consume(example(run_attempt=2))
    finally:
        os.close(fd)
    assert len(list(root.iterdir())) == 1


def test_concurrent_thread_contenders_only_one_consumes(tmp_path):
    _, fd = _open(tmp_path)
    try:
        with D4DurableAttemptJournal(fd) as journal:
            def contender(_):
                try:
                    journal.consume(example())
                    return True
                except D4DurableAttemptDenied:
                    return False
            with ThreadPoolExecutor(max_workers=12) as pool:
                result = list(pool.map(contender, range(40)))
            assert result.count(True) == 1
    finally:
        os.close(fd)


def test_competing_processes_only_one_consumes(tmp_path):
    root, fd = _open(tmp_path)
    os.close(fd)
    with ProcessPoolExecutor(max_workers=3) as pool:
        result = list(pool.map(_in_other_process,
                               [str(root)] * 9, [example()] * 9))
    assert sum(value != "DENY" for value in result) == 1


@pytest.mark.parametrize("changes", [
    {"nonce": "WRONG"}, {"r006_design_blob": H},
    {"repo": "someone/else"}, {"workspace": "../escape"},
    {"run_attempt": 0}, {"run_id": True},
    {"source_fingerprint": "0" * 63}, {"head_tree": "bad"},
])
def test_malformed_binding_fails_before_any_tombstone(tmp_path, changes):
    root, fd = _open(tmp_path)
    try:
        with D4DurableAttemptJournal(fd) as journal:
            with pytest.raises(D4DurableAttemptDenied):
                journal.consume(replace(example(), **changes))
        assert list(root.iterdir()) == []
    finally:
        os.close(fd)


def test_different_nonces_do_not_share_authority(tmp_path):
    root, fd = _open(tmp_path)
    try:
        with D4DurableAttemptJournal(fd) as journal:
            assert journal.consume(example()) != journal.consume(
                example(nonce="c" * 64))
        assert len(list(root.iterdir())) == 2
    finally:
        os.close(fd)


def test_tampered_existing_tombstone_cannot_be_redeemed(tmp_path):
    root, fd = _open(tmp_path)
    try:
        with D4DurableAttemptJournal(fd) as journal:
            journal.consume(example())
            (root / ("d4-" + S + ".json")).write_text("malformed")
            with pytest.raises(D4DurableAttemptDenied):
                journal.consume(example())
    finally:
        os.close(fd)


def test_private_owner_mode_and_closed_or_forked_denied(tmp_path, monkeypatch):
    root, fd = _open(tmp_path)
    root.chmod(0o777)
    try:
        with pytest.raises(D4DurableAttemptDenied):
            D4DurableAttemptJournal(fd)
        root.chmod(0o700)
        journal = D4DurableAttemptJournal(fd)
        monkeypatch.setattr(os, "getpid", lambda: -99)
        with pytest.raises(D4DurableAttemptDenied):
            journal.consume(example())
        monkeypatch.undo()
        journal.close()
        with pytest.raises(D4DurableAttemptDenied):
            journal.consume(example())
    finally:
        os.close(fd)

def test_real_service_owner_locked_source_only_journal_restart(tmp_path, monkeypatch):
    from gateway.core import GatewayError
    from gateway.exec_state import ExecStateStore
    from gateway.lbe_owner_grant import verify_d4_owner_github_comment_t0
    from gateway.workspaces import WorkspaceService, ActiveRuntimeInventory
    from gateway.workspaces_config import parse_workspace_config

    now = 1794100000
    monkeypatch.setattr(time, "time", lambda: now)
    created = datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    expires = datetime.fromtimestamp(now + 900, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = {
        "authorization": "PRODUCT_T1_ONE_ATTEMPT_ONLY",
        "risk_acceptance": "R006_NINE_RESIDUAL_RISKS_ACCEPTED",
        "repo": "chinanjjohn2012/mac-file-gateway", "pr": 114,
        "base_sha": H, "head_sha": H, "head_tree": H,
        "manifest_sha256": S, "r006_design_blob": R006,
        "b_design_review_id": "PRR_kwDOU5v3IM8AAAABWq0I_w",
        "c_design_review_id": "PRR_kwDOU5v3IM8AAAABWq0iKA",
        "b_code_review_id": "PRR_currentStandards123",
        "c_code_review_id": "PRR_currentSpecReview123",
        "github_run_id": 42445537246, "github_run_attempt": 1,
        "image_os": "macos15", "image_version": "20261104.0514.1",
        "os_build": "24G90", "source_fingerprint": S,
        "runner_fingerprint": S, "workspace": "a", "cwd": "src",
        "runner": "direct", "requested_argv_sha256": S,
        "effective_argv_sha256": S, "timeout_seconds": 120,
        "nonce": "d" * 64, "expires_at": expires,
    }
    cid = 7712345678
    response = {
        "id": cid,
        "body": "R006_OWNER_T1_GRANT_V1\n" + json.dumps(
            payload, sort_keys=True, separators=(",", ":")),
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
    verified = verify_d4_owner_github_comment_t0(
        json.dumps(response, sort_keys=True, separators=(",", ":")).encode())

    root = tmp_path / "projects" / "a"
    root.mkdir(parents=True)
    (root / "src").mkdir()
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    private.chmod(0o700)
    (private / "d4-journal").mkdir(mode=0o700)
    store = ExecStateStore(private / "exec-state",
                           workspace_roots=(str(root),))
    store.close()
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    settings = parse_workspace_config({
        "schema_version": 2,
        "server": {"port": 8765, "transport": "http"},
        "workspaces": {"a": {"root": str(root), "exec": {"paths": ["src"]}}},
    })
    for round in range(2):
        with_service = WorkspaceService(
            settings, config_dir=private,
            inventory=ActiveRuntimeInventory(paths=(runtime,)))
        try:
            assert with_service._exec_state.durability_state == "healthy"
            # A plain attempt dataclass is deliberately not enough anymore.
            with pytest.raises(GatewayError):
                with_service._consume_d4_r006_attempt_source_only(
                    replace(example(), workspace="a"))
            if round == 0:
                assert len(with_service._consume_d4_r006_attempt_source_only(
                    verified)) == 64
            else:
                # The exact verifier-produced grant remains burned after restart.
                with pytest.raises(GatewayError):
                    with_service._consume_d4_r006_attempt_source_only(verified)
            assert with_service._lbe_positive_authorized is False
            with pytest.raises(GatewayError) as denied:
                with_service.invoke_exec("a", "src", ["python", "-m", "pytest", "-q"],
                                         dry_run=False)
            assert denied.value.code == "exec_cleanup_proof_required"
        finally:
            with_service.close()
    assert len(list((private / "d4-journal").iterdir())) == 1
    # Strict legacy ExecStateStore boot-scan must not be polluted.
    assert set(p.name for p in (private / "exec-state").iterdir()) == {"owner.lock"}


def test_service_without_existing_private_journal_never_creates_one(tmp_path):
    from gateway.exec_state import ExecStateStore
    from gateway.workspaces import WorkspaceService, ActiveRuntimeInventory
    from gateway.workspaces_config import parse_workspace_config
    from gateway.core import GatewayError

    root = tmp_path / "projects" / "a"
    root.mkdir(parents=True)
    (root / "src").mkdir()
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    store = ExecStateStore(private / "exec-state",
                           workspace_roots=(str(root),))
    store.close()
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    settings = parse_workspace_config({
        "schema_version": 2,
        "server": {"port": 8765, "transport": "http"},
        "workspaces": {"a": {"root": str(root), "exec": {"paths": ["src"]}}},
    })
    service = WorkspaceService(
        settings, config_dir=private,
        inventory=ActiveRuntimeInventory(paths=(runtime,)))
    try:
        with pytest.raises(GatewayError):
            service._consume_d4_r006_attempt_source_only(
                replace(example(), workspace="a"))
        assert service._d4_attempt_journal is None
    finally:
        service.close()
    assert not (private / "d4-journal").exists()
