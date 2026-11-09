"""R010 durable nonce guard: real disposable FS, SAFE T0, no OS child."""
import hashlib
import json
import os
import socket
import subprocess

import pytest

from gateway.lbe_r010_job_envelope import (
    R010JobKey, _create_once_in_pinned_anchor,
)
from gateway.lbe_r010_serial_journal import (
    R010SerialAdmissionDenied, R010SerialNonceJournal,
)


@pytest.fixture(autouse=True)
def no_child(monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("T0 must not spawn or connect")
    monkeypatch.setattr(subprocess, "Popen", denied)
    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(os, "kill", denied)
    monkeypatch.setattr(os, "killpg", denied, raising=False)


def job_key():
    return R010JobKey(
        repo="chinanjjohn2012/mac-file-gateway", pr=114,
        workflow_id=145, workflow_path=".github/workflows/r010.yml",
        workflow_ref="chinanjjohn2012/mac-file-gateway/.github/workflows/r010.yml@refs/heads/main",
        run_id=42640408843, run_attempt=1, check_run_id=129239691259,
        job_name="r010_preexec_hold", head_sha="a" * 40,
        design_id="MWE-LBE-R010-AUTHORITY-CHAIN-DESIGN-013-CANDIDATE",
        design_blob="f57e39543a6fe3d64fe99b8669fc7da854b93a64",
        owner_choice_comment_id=6740275850,
        host_option="A1", review_sequence_option="B1",
        state_domain="R010_EPHEMERAL_JOB_STATE_V1",
    )


def nonces():
    raw = tuple(f"{i:064x}" for i in range(1, 7))
    hashed = tuple(hashlib.sha256(bytes.fromhex(x)).hexdigest() for x in raw)
    return raw, hashed


@pytest.fixture
def envelope(tmp_path):
    anchor = tmp_path / "anchor"
    anchor.mkdir(mode=0o700)
    fd = os.open(anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with _create_once_in_pinned_anchor(fd, job_key()) as instance:
            yield anchor, instance
    finally:
        os.close(fd)


def test_once_durable_burn_and_no_exec(envelope):
    anchor, instance = envelope
    raw, hashes = nonces()
    journal = R010SerialNonceJournal(instance, six_nonce_sha256=hashes)
    assert journal.burn_first_nonce(raw[0]) == {
        "row": 1, "nonce_burned": True,
        "native_launch_allowed": False, "row_success_attested": False,
    }
    root = anchor / instance.snapshot()["envelope_root_name"]
    stored = json.loads((root / "command-journal" / "row-01-burn.json").read_text())
    assert stored["nonce_sha256"] == hashes[0]
    assert raw[0] not in repr(stored)
    with pytest.raises(R010SerialAdmissionDenied, match="already burned"):
        journal.burn_first_nonce(raw[0])
    with pytest.raises(R010SerialAdmissionDenied, match="not implemented"):
        journal.begin_later_row(2, raw[1])
    with pytest.raises(R010SerialAdmissionDenied, match="not proven"):
        journal.claim_six_command_pass()


def test_wrong_nonce_does_not_burn(envelope):
    _, instance = envelope
    raw, hashes = nonces()
    journal = R010SerialNonceJournal(instance, six_nonce_sha256=hashes)
    for bad in (raw[1], "not-a-nonce", "A" * 64, "f" * 64):
        with pytest.raises(R010SerialAdmissionDenied):
            journal.burn_first_nonce(bad)
    assert journal.burn_first_nonce(raw[0])["nonce_burned"] is True


def test_duplicated_or_missing_nonce_digest_denied(envelope):
    _, instance = envelope
    _, hashes = nonces()
    for wrong in (hashes[:5], hashes[:5] + (hashes[0],),
                  ("0" * 63,) + hashes[1:], list(hashes)):
        with pytest.raises(R010SerialAdmissionDenied):
            R010SerialNonceJournal(instance, six_nonce_sha256=wrong)
    R010SerialNonceJournal(instance, six_nonce_sha256=hashes)


def test_second_adapter_and_restart_like_reuse_denied(envelope):
    _, instance = envelope
    raw, hashes = nonces()
    first = R010SerialNonceJournal(instance, six_nonce_sha256=hashes)
    first.burn_first_nonce(raw[0])
    del first
    with pytest.raises(R010SerialAdmissionDenied, match="already claimed"):
        R010SerialNonceJournal(instance, six_nonce_sha256=hashes)


def test_fail_latches_void_and_prevents_replay(envelope):
    anchor, instance = envelope
    raw, hashes = nonces()
    journal = R010SerialNonceJournal(instance, six_nonce_sha256=hashes)
    journal.burn_first_nonce(raw[0])
    journal.latch_failure("original_nonzero")
    root = anchor / instance.snapshot()["envelope_root_name"]
    failure = json.loads((root / "command-journal" / "r010-row-failure.json").read_text())
    assert failure["rows_remaining"] == "ROW_VOID"
    with pytest.raises(R010SerialAdmissionDenied, match="latched"):
        journal.burn_first_nonce(raw[0])


def test_close_invalidates_first_nonce_burn(envelope):
    _, instance = envelope
    raw, hashes = nonces()
    journal = R010SerialNonceJournal(instance, six_nonce_sha256=hashes)
    instance.close()
    with pytest.raises(R010SerialAdmissionDenied, match="unavailable"):
        journal.burn_first_nonce(raw[0])
