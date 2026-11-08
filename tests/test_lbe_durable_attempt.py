"""Safe T0: durable R006 nonce consumption, no native child."""
from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import os
import subprocess

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
        source_fingerprint=S, runner_fingerprint=S,
        workspace="first-party", command_fingerprint=S,
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
