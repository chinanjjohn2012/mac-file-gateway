"""R2-T02-B1-A: internal disposable acceptance qualification contracts.

This batch verifies *minting and identity checks only*: no real child, no
group signal, no Worker retirement, no ordinary-Gateway proof gate and no
Native C. The private factory must create its OWN new trusted temporary
roots; an external filesystem path must never become a qualification.
"""
from __future__ import annotations

import copy
import importlib
import json
import os
from pathlib import Path
import pickle
import signal
import stat
import subprocess

import pytest

from gateway.private_fs import PrivateFileError
from gateway.workspaces_config import parse_workspace_config


def _new():
    try:
        module = importlib.import_module("gateway._exec_test_grant")
        factory = getattr(module, "create_private_disposable_acceptance")
    except (ModuleNotFoundError, AttributeError) as exc:
        pytest.fail("B1A_RED_PRIVATE_ACCEPTANCE_FACTORY_ABSENT: " +
                    type(exc).__name__, pytrace=False)
    return factory()


def _qualified(fx, workspace="a", host="127.0.0.1", service=None):
    svc = fx.service if service is None else service
    return fx.grant.qualifies(svc, workspace, listener_host=host)


def test_b1a_fresh_private_root_pinned_state_and_exact_workspace_identity():
    with _new() as fx:
        root = Path(fx.root)
        state = Path(fx.state_path)
        assert root.is_dir()
        assert stat.S_IMODE(root.lstat().st_mode) == 0o700
        assert root.lstat().st_uid == os.geteuid()
        assert state.parent.is_dir() and state.is_dir()
        assert stat.S_IMODE(state.lstat().st_mode) == 0o700
        assert stat.S_IMODE((state / "owner.lock").stat().st_mode) == 0o600
        assert fx.service._exec_state is not None
        assert fx.service._exec_state.durability_state == "healthy"
        assert (os.fstat(fx.service._exec_state._fd).st_dev,
                os.fstat(fx.service._exec_state._fd).st_ino) == (
                state.lstat().st_dev, state.lstat().st_ino)
        assert _qualified(fx) is True
        assert _qualified(fx) is True  # sequential attempts within scope
        assert fx.service.settings.exec_enabled is True
        assert fx.service.get("a").settings.exec_enabled is True
        assert fx.service.get("b").settings.exec_enabled is False
        assert str(root) not in repr(fx.grant)


def test_b1a_disposable_roots_are_unique_never_user_supplied_or_reused():
    with _new() as a, _new() as b:
        assert a.root != b.root
        assert Path(a.root).lstat().st_ino != Path(b.root).lstat().st_ino
        assert a.grant is not b.grant
        assert _qualified(a) and _qualified(b)
        with pytest.raises((RuntimeError, ValueError, PermissionError)):
            a.reissue()
        assert _qualified(a)
        assert _qualified(b)


def test_b1a_wrong_instance_rejected_even_if_both_services_healthy():
    with _new() as first, _new() as second:
        assert _qualified(first) and _qualified(second)
        assert first.grant.qualifies(second.service, "a",
                                     listener_host="127.0.0.1") is False
        assert second.grant.qualifies(first.service, "a",
                                      listener_host="127.0.0.1") is False
        assert _qualified(first) and _qualified(second)


def test_b1a_wrong_workspace_or_identity_alias_not_qualified():
    with _new() as fx:
        assert _qualified(fx, "a") is True
        assert _qualified(fx, "b") is False
        assert _qualified(fx, "missing") is False
        assert _qualified(fx, "../a") is False
        assert _qualified(fx, "") is False
        assert _qualified(fx, 42) is False


def test_b1a_rejects_nonloopback_listener_and_bad_listener_types():
    with _new() as fx:
        assert _qualified(fx, host="127.0.0.1")
        for host in ("0.0.0.0", "192.168.1.10", "localhost",
                     "::", "example.com", "", None, 0):
            assert _qualified(fx, host=host) is False, repr(host)


def test_b1a_root_rename_revokes_qualification_even_if_fd_is_alive():
    with _new() as fx:
        root = Path(fx.root)
        moved = root.with_name(root.name + "-moved")
        assert _qualified(fx)
        root.rename(moved)
        try:
            assert _qualified(fx) is False
        finally:
            moved.rename(root)
        # A transient observed identity change is a one-way invalidation.
        assert _qualified(fx) is False


def test_b1a_workspace_path_replacement_revokes_original_inode_scope():
    with _new() as fx:
        root = Path(fx.workspace_root("a"))
        renamed = root.with_name(root.name + "-moved")
        assert _qualified(fx)
        root.rename(renamed)
        root.mkdir(mode=0o700)
        try:
            assert _qualified(fx) is False
        finally:
            root.rmdir()
            renamed.rename(root)
        assert _qualified(fx) is False


def test_b1a_process_identity_change_revokes_qualification(monkeypatch):
    with _new() as fx:
        assert _qualified(fx)
        module = importlib.import_module("gateway._exec_test_grant")
        original_pid = os.getpid()
        with monkeypatch.context() as patch:
            patch.setattr(module.os, "getpid", lambda: original_pid + 1)
            assert _qualified(fx) is False
        assert _qualified(fx) is False  # terminal invalidation, not revival


def test_b1a_durable_unknown_quarantine_revokes_qualification():
    with _new() as fx:
        assert _qualified(fx)
        store = fx.service._exec_state
        ctx = fx.service.get("a")
        st = os.fstat(ctx.pinned_root.fd)
        attempt = store.prepare("a", (st.st_dev, st.st_ino))
        assert _qualified(fx)  # a healthy PREPARED is not itself a grant
        store.mark_unknown(attempt)
        assert store.durability_state == "quarantined"
        assert _qualified(fx) is False
        assert json.loads(
            (fx.state_path / ("r-" + attempt + ".json")).read_bytes()
        )["phase"] == "UNKNOWN"


def test_b1a_owner_lock_fd_loss_revokes_grant():
    with _new() as fx:
        assert _qualified(fx)
        fx.service._exec_state.close()
        assert _qualified(fx) is False


def test_b1a_service_close_revokes_without_transferring_to_restarted_service():
    fx = _new()
    try:
        svc = fx.service
        grant = fx.grant
        assert _qualified(fx)
        svc.close()
        assert grant.qualifies(svc, "a", listener_host="127.0.0.1") is False
        assert _qualified(fx) is False
    finally:
        fx.close()
    assert grant.qualifies(svc, "a", listener_host="127.0.0.1") is False


def test_b1a_grant_not_pickle_copy_or_json_serializable():
    with _new() as fx:
        g = fx.grant
        for action in (lambda: pickle.dumps(g), lambda: copy.copy(g),
                       lambda: copy.deepcopy(g), lambda: json.dumps(g)):
            with pytest.raises((TypeError, ValueError, pickle.PicklingError)):
                action()
        assert str(fx.root) not in repr(g)
        assert _qualified(fx) is True


def test_b1a_fixture_lifecycle_never_spawns_or_signals_host(monkeypatch):
    calls = []
    real_popen = subprocess.Popen

    class _ForbiddenPopen(real_popen):
        def __new__(cls, *args, **kwargs):
            calls.append("subprocess.Popen")
            raise AssertionError("B1A_UNAUTHORIZED_HOST_SPAWN")

    def forbidden(*args, **kwargs):
        calls.append("host_signal_or_spawn")
        raise AssertionError("B1A_UNAUTHORIZED_HOST_SIGNAL")

    with monkeypatch.context() as m:
        m.setattr(subprocess, "Popen", _ForbiddenPopen)
        for name in ("kill", "killpg", "posix_spawn", "posix_spawnp",
                     "fork", "forkpty"):
            if hasattr(os, name):
                m.setattr(os, name, forbidden)
        with _new() as fx:
            assert _qualified(fx) is True
        assert _qualified(fx) is False
    assert calls == []


def test_b1a_private_grant_never_appears_in_status_or_workspace_metadata():
    with _new() as fx:
        svc = fx.service
        policy = svc.info()["exec_policy"]
        json_payload = json.dumps(svc.info()) + json.dumps(svc.list_workspaces())
        assert _qualified(fx) is True
        assert "test_grant" not in json_payload
        assert "TestOnlyGroupRetirementGrant" not in json_payload
        assert str(fx.root) not in json_payload
        assert policy["enabled"] is True


def test_b1a_existing_gateway_configuration_and_env_cannot_mint_qualification(
        monkeypatch):
    monkeypatch.setenv("GATEWAY_EXEC_TEST_GRANT", "1")
    monkeypatch.setenv("GATEWAY_TEST_ONLY_EXEC", "true")
    with _new() as fx:
        assert _qualified(fx)
        # A serialized field is always invalid even in a disposable root.
        with pytest.raises(PrivateFileError):
            parse_workspace_config({
                "schema_version": 1,
                "server": {"exec": {"enabled": True, "test_grant": True}},
                "workspaces": {"a": {"root": str(fx.workspace_root("a"))}},
            })
        assert not hasattr(fx.service.settings, "test_grant")
        assert "GATEWAY_EXEC_TEST_GRANT" not in fx.service.info().__str__()
        assert _qualified(fx)


def test_b1a_b0_existing_normal_service_has_no_private_test_grant_surface():
    """Baseline should remain GREEN even before grant module exists."""
    from gateway.workspaces import WorkspaceService
    from gateway.workspaces_config import GatewaySettings
    from gateway import multi_cli
    # Neither the ordinary service, its constructor nor the CLI may
    # implicitly mint or receive an acceptance grant from client/config.
    assert "_exec_test_grant" not in multi_cli.run_multi.__code__.co_names
    assert "_exec_test_grant" not in WorkspaceService.__init__.__code__.co_names
    assert "test_grant" not in GatewaySettings.__dataclass_fields__
