"""R010 product PREEXEC envelope filesystem mechanics, SAFE T0 only.

Uses only tmp_path, local fs, synthetic Job strings and no real GitHub/JWT,
network, subprocess, signal, SSH agent or native PRODUCT_T1. Tests directly
exercise real open/mkdir/O_EXCL/fsync/fstat operations on disposable paths.
"""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import hashlib
import json
import os
import stat
import subprocess

import pytest

from gateway.lbe_r010_job_envelope import (
    R010JobEnvelopeDenied, R010JobKey, _create_once_in_pinned_anchor,
    canonical_run_attempt,
)

DESIGN = "f57e39543a6fe3d64fe99b8669fc7da854b93a64"
HEAD = "a" * 40


def example_key(**changes):
    original = dict(
        repo="chinanjjohn2012/mac-file-gateway", pr=114,
        workflow_id=145, workflow_path=".github/workflows/lbe-r010.yml",
        workflow_ref="chinanjjohn2012/mac-file-gateway/.github/workflows/lbe-r010.yml@refs/heads/main",
        run_id=42495003699, run_attempt=2, check_run_id=128775348933,
        job_name="r010_preexec_hold", head_sha=HEAD,
        design_id="MWE-LBE-R010-AUTHORITY-CHAIN-DESIGN-013-CANDIDATE",
        design_blob=DESIGN, owner_choice_comment_id=6740275850,
        host_option="A1", review_sequence_option="B1",
        state_domain="R010_EPHEMERAL_JOB_STATE_V1",
    )
    original.update(changes)
    return R010JobKey(**original)


def _anchor(tmp_path):
    anchor = tmp_path / "verified-anchor"
    anchor.mkdir(mode=0o700)
    anchor.chmod(0o700)
    fd = os.open(anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    return anchor, fd


def _deny_real_popen(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("R010 SAFE T0 never launches an OS child")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "kill", forbidden)
    monkeypatch.setattr(os, "killpg", forbidden, raising=False)


def test_create_once_pins_root_lease_secret_and_preexec_only(tmp_path, monkeypatch):
    _deny_real_popen(monkeypatch)
    anchor, fd = _anchor(tmp_path)
    key = example_key()
    try:
        with _create_once_in_pinned_anchor(fd, key) as envelope:
            pub = envelope.snapshot()
            assert pub["status"] == "JOB_PREEXEC_HOLD"
            assert pub["native_launch_allowed"] is False
            assert pub["provider_verified"] is False
            assert pub["owner_product_t1_grant_verified"] is False
            assert pub["job_envelope_key"] == key.key_sha256()
            assert len(pub["job_local_secret_sha256"]) == 64
            assert len(pub["service_instance_nonce_sha256"]) == 64
            assert not hasattr(envelope, "start_row")
            root = anchor / ("mfg-r010-job-" + key.key_sha256())
            assert root.exists()
            assert stat.S_IMODE(root.stat().st_mode) == 0o700
            for child in ("service-config", "exec-state", "command-journal"):
                assert stat.S_IMODE((root / child).stat().st_mode) == 0o700
            lease_path = root / "job-lease.json"
            assert stat.S_IMODE(lease_path.stat().st_mode) == 0o600
            data = json.loads(lease_path.read_text())
            assert data["design_blob"] == DESIGN
            assert data["owner_choice_comment_id"] == 6740275850
            assert data["job"]["run_attempt"] == 2
            assert hashlib.sha256(bytes.fromhex(
                data["job_local_secret_hex"])).hexdigest() == pub["job_local_secret_sha256"]
            assert hashlib.sha256(bytes.fromhex(
                data["service_instance_nonce_hex"])).hexdigest() == pub["service_instance_nonce_sha256"]
            assert data["job_local_secret_hex"] not in repr(pub)
            assert data["service_instance_nonce_hex"] not in repr(pub)
            rows = json.loads((root / "command-journal" / "row-state.json").read_text())
            assert rows == {
                "state": "JOB_PREEXEC_HOLD", "expected_row": 1,
                "rows": ["ROW_NOT_RUN"] * 6,
                "native_launch_allowed": False,
            }
        with pytest.raises(R010JobEnvelopeDenied):
            _create_once_in_pinned_anchor(fd, key)
    finally:
        os.close(fd)


def test_simultaneous_services_cannot_claim_same_job_with_alternate_config(tmp_path):
    # No service config path is accepted by the factory; both callers use
    # one deterministic Job key, even if they keep unrelated configs.
    anchor, fd = _anchor(tmp_path)
    try:
        (tmp_path / "config-a").mkdir()
        (tmp_path / "config-b").mkdir()
        with _create_once_in_pinned_anchor(fd, example_key()) as first:
            with pytest.raises(R010JobEnvelopeDenied):
                _create_once_in_pinned_anchor(fd, example_key())
            assert first.snapshot()["status"] == "JOB_PREEXEC_HOLD"
        with pytest.raises(R010JobEnvelopeDenied):
            _create_once_in_pinned_anchor(fd, example_key())
    finally:
        os.close(fd)


def test_40_thread_contenders_only_one_creates_same_job(tmp_path):
    _, fd = _anchor(tmp_path)
    try:
        def contender(_):
            try:
                with _create_once_in_pinned_anchor(fd, example_key()):
                    return True
            except R010JobEnvelopeDenied:
                return False
        with ThreadPoolExecutor(max_workers=12) as pool:
            actual = list(pool.map(contender, range(40)))
        assert actual.count(True) == 1
    finally:
        os.close(fd)


def test_altered_provider_signed_job_identity_is_separate_key_not_replay(tmp_path):
    anchor, fd = _anchor(tmp_path)
    try:
        a = example_key(check_run_id=128775348933)
        b = example_key(check_run_id=128775348934)
        assert a.key_sha256() != b.key_sha256()
        with _create_once_in_pinned_anchor(fd, a), _create_once_in_pinned_anchor(fd, b):
            assert len(list(anchor.iterdir())) == 2
    finally:
        os.close(fd)


@pytest.mark.parametrize("attempt", ["", "0", "01", "-1", "+2", "\u0662", "\uff12", " 2", "2 ", "2.0", "1e2"])
def test_run_attempt_noncanonical_decimal_denied(attempt):
    with pytest.raises(R010JobEnvelopeDenied):
        canonical_run_attempt(attempt)


def test_run_attempt_ascii_retries_allowed_by_canonical_parser():
    assert canonical_run_attempt("1") == 1
    assert canonical_run_attempt("2") == 2


@pytest.mark.parametrize("changed", [
    {"repo": "attacker/repo"}, {"pr": 113}, {"run_id": True},
    {"run_attempt": 0}, {"check_run_id": 0}, {"head_sha": "f" * 39},
    {"head_sha": "F" * 40}, {"workflow_id": True},
    {"job_name": "../escape"}, {"workflow_path": "../file"},
    {"workflow_ref": "repo:any"}, {"workflow_ref": "x/../anything"},
    {"design_blob": "b" * 40}, {"owner_choice_comment_id": 1},
    {"host_option": "A0"}, {"review_sequence_option": "B0"},
    {"state_domain": "R009_PERSISTENT"},
])
def test_untrusted_identity_cannot_create_job_root(tmp_path, changed):
    anchor, fd = _anchor(tmp_path)
    try:
        with pytest.raises(R010JobEnvelopeDenied):
            _create_once_in_pinned_anchor(fd, replace(example_key(), **changed))
        assert list(anchor.iterdir()) == []
    finally:
        os.close(fd)


def test_existing_symlink_root_never_adopted_or_removed(tmp_path):
    anchor, fd = _anchor(tmp_path)
    target = tmp_path / "outside"
    target.mkdir()
    name = "mfg-r010-job-" + example_key().key_sha256()
    (anchor / name).symlink_to(target, target_is_directory=True)
    try:
        with pytest.raises(R010JobEnvelopeDenied):
            _create_once_in_pinned_anchor(fd, example_key())
        assert (anchor / name).is_symlink()
        assert list(target.iterdir()) == []
    finally:
        os.close(fd)


def test_fsync_fault_leaves_consumed_root_does_not_retry(tmp_path, monkeypatch):
    anchor, fd = _anchor(tmp_path)
    old_fsync = os.fsync
    fail_once = {"yes": True}
    def broken_fsync(descriptor):
        if fail_once["yes"]:
            fail_once["yes"] = False
            raise OSError("injected fsync failure")
        return old_fsync(descriptor)
    try:
        with monkeypatch.context() as m:
            m.setattr(os, "fsync", broken_fsync)
            with pytest.raises(R010JobEnvelopeDenied):
                _create_once_in_pinned_anchor(fd, example_key())
        assert len(list(anchor.iterdir())) == 1
        with pytest.raises(R010JobEnvelopeDenied):
            _create_once_in_pinned_anchor(fd, example_key())
    finally:
        os.close(fd)


def test_replaced_root_entry_invalidates_live_pinned_envelope(tmp_path):
    anchor, fd = _anchor(tmp_path)
    try:
        with _create_once_in_pinned_anchor(fd, example_key()) as env:
            original = anchor / env.snapshot()["envelope_root_name"]
            changed = anchor / "renamed-old-envelope"
            original.rename(changed)
            original.mkdir(mode=0o700)
            with pytest.raises(R010JobEnvelopeDenied):
                env.snapshot()
    finally:
        os.close(fd)


def test_replaced_private_journal_entry_invalidates_live_envelope(tmp_path):
    anchor, fd = _anchor(tmp_path)
    try:
        with _create_once_in_pinned_anchor(fd, example_key()) as env:
            root = anchor / env.snapshot()["envelope_root_name"]
            (root / "command-journal").rename(root / "old-journal")
            (root / "command-journal").mkdir(mode=0o700)
            with pytest.raises(R010JobEnvelopeDenied):
                env.snapshot()
    finally:
        os.close(fd)


def test_forked_or_closed_handle_is_not_authoritative(tmp_path, monkeypatch):
    _, fd = _anchor(tmp_path)
    try:
        env = _create_once_in_pinned_anchor(fd, example_key())
        with monkeypatch.context() as m:
            m.setattr(os, "getpid", lambda: -1)
            with pytest.raises(R010JobEnvelopeDenied):
                env.snapshot()
        env.close()
        with pytest.raises(R010JobEnvelopeDenied):
            env.snapshot()
    finally:
        os.close(fd)


def test_durable_latched_failure_never_reopens(tmp_path):
    anchor, fd = _anchor(tmp_path)
    try:
        env = _create_once_in_pinned_anchor(fd, example_key())
        root = anchor / env.snapshot()["envelope_root_name"]
        env.latch_failure("preexec_unavailable")
        with pytest.raises(R010JobEnvelopeDenied):
            env.snapshot()
        latch = json.loads((root / "command-journal" / "latch-failure.json").read_text())
        assert latch["state"] == "JOB_FAILED_LATCHED" or latch["status"] == "JOB_FAILED_LATCHED"
        with pytest.raises(R010JobEnvelopeDenied):
            _create_once_in_pinned_anchor(fd, example_key())
    finally:
        os.close(fd)


def test_private_anchor_not_world_writable_and_no_alt_root_override(tmp_path):
    anchor, fd = _anchor(tmp_path)
    try:
        anchor.chmod(0o777)
        with pytest.raises(R010JobEnvelopeDenied):
            _create_once_in_pinned_anchor(fd, example_key())
    finally:
        anchor.chmod(0o700)
        os.close(fd)
