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


@pytest.mark.parametrize("outcome,expected_reason", [
    ("ROW_OBSERVED_NONZERO", "original_nonzero"),
    ("ROW_OBSERVED_ZERO_INVALID_OUTPUT_OR_FS", "invalid_output_or_fs"),
    ("ROW_AMBIGUOUS", "owner_reader_ambiguous"),
])
def test_actual_source_nonpositive_row_latches_durable_global_deny(
        envelope, outcome, expected_reason):
    """No synthetic response can authorize a later Popen or row."""
    from gateway.lbe_r010_owned_row import R010OwnedRowSourceObservation

    anchor, instance = envelope
    raw, hashes = nonces()
    journal = R010SerialNonceJournal(instance, six_nonce_sha256=hashes)
    journal.burn_first_nonce(raw[0])
    observation = R010OwnedRowSourceObservation(
        row=1, nonce_sha256=hashes[0], outcome=outcome,
        observed_original_exit_code=3 if outcome == "ROW_OBSERVED_NONZERO" else None,
        original_child_reaped=outcome != "ROW_AMBIGUOUS",
        owner_reader_healthy=outcome != "ROW_AMBIGUOUS",
        output_complete=outcome != "ROW_AMBIGUOUS",
    )
    journal.latch_from_owned_row(observation)
    root = anchor / instance.snapshot()["envelope_root_name"]
    data = json.loads(
        (root / "command-journal" / "r010-row-failure.json").read_text())
    assert data["status"] == "JOB_FAILED_LATCHED"
    assert data["reason"] == expected_reason
    assert data["rows_remaining"] == "ROW_VOID"
    with pytest.raises(R010SerialAdmissionDenied, match="latched"):
        journal.burn_first_nonce(raw[0])
    with pytest.raises(R010SerialAdmissionDenied, match="not implemented"):
        journal.begin_later_row(2, raw[1])


def test_valid_fake_exit_zero_never_advances_six_row_journal(envelope):
    """A healthy Owner/Worker source-only result is not full T1 acceptance."""
    from gateway.lbe_r010_owned_row import R010OwnedRowSourceObservation

    _, instance = envelope
    raw, hashes = nonces()
    journal = R010SerialNonceJournal(instance, six_nonce_sha256=hashes)
    journal.burn_first_nonce(raw[0])
    observation = R010OwnedRowSourceObservation(
        row=1, nonce_sha256=hashes[0],
        outcome="ORIGINAL_ZERO_READER_HEALTHY_FINITE_FS_NOT_CHECKED",
        observed_original_exit_code=0,
        original_child_reaped=True, owner_reader_healthy=True,
        output_complete=True,
    )
    with pytest.raises(R010SerialAdmissionDenied, match="lacks full product"):
        journal.latch_from_owned_row(observation)
    with pytest.raises(R010SerialAdmissionDenied, match="not implemented"):
        journal.begin_later_row(2, raw[1])


def test_cross_nonce_or_wrong_row_receipt_is_rejected_before_any_latch(envelope):
    from dataclasses import replace
    from gateway.lbe_r010_owned_row import R010OwnedRowSourceObservation

    _, instance = envelope
    raw, hashes = nonces()
    journal = R010SerialNonceJournal(instance, six_nonce_sha256=hashes)
    journal.burn_first_nonce(raw[0])
    base = R010OwnedRowSourceObservation(
        row=1, nonce_sha256=hashes[0], outcome="ROW_AMBIGUOUS",
        observed_original_exit_code=None,
        original_child_reaped=False, owner_reader_healthy=False,
        output_complete=False,
    )
    for altered in (
        replace(base, row=2),
        replace(base, nonce_sha256=hashes[1]),
        replace(base, native_launch_allowed=True),
        replace(base, row_positive_success=True),
    ):
        with pytest.raises(R010SerialAdmissionDenied, match="not bound"):
            journal.latch_from_owned_row(altered)
    journal.latch_from_owned_row(base)


def test_all_six_nonce_commitments_are_durable_before_first_row(envelope):
    anchor, instance = envelope
    _, hashes = nonces()
    R010SerialNonceJournal(instance, six_nonce_sha256=hashes)
    root = anchor / instance.snapshot()["envelope_root_name"]
    manifest = json.loads(
        (root / "command-journal" / "six-nonce-manifest.json").read_text())
    assert manifest["version"] == "R010_SIX_NONCE_MANIFEST_V1"
    assert manifest["six_nonce_sha256"] == list(hashes)
    assert manifest["native_launch_allowed"] is False


def test_burn_record_tracks_exact_six_row_sequence_without_allow(envelope):
    anchor, instance = envelope
    raw, hashes = nonces()
    journal = R010SerialNonceJournal(instance, six_nonce_sha256=hashes)
    journal.burn_first_nonce(raw[0])
    root = anchor / instance.snapshot()["envelope_root_name"]
    record = json.loads(
        (root / "command-journal" / "row-01-burn.json").read_text())
    assert record["job_state"] == "JOB_ROW_RUNNING_1"
    assert record["expected_row"] == 1
    assert record["rows"] == ["ROW_RUNNING"] + ["ROW_NOT_RUN"] * 5
    assert record["native_launch_allowed"] is False


@pytest.mark.parametrize("code,expected_first", [
    ("original_nonzero", "ROW_OBSERVED_NONZERO"),
    ("invalid_output_or_fs", "ROW_OBSERVED_ZERO_INVALID_OUTPUT_OR_FS"),
    ("owner_reader_ambiguous", "ROW_AMBIGUOUS"),
])
def test_failure_records_exact_one_row_and_five_voided(envelope, code,
                                                        expected_first):
    anchor, instance = envelope
    raw, hashes = nonces()
    journal = R010SerialNonceJournal(instance, six_nonce_sha256=hashes)
    journal.burn_first_nonce(raw[0])
    journal.latch_failure(code)
    root = anchor / instance.snapshot()["envelope_root_name"]
    result = json.loads(
        (root / "command-journal" / "r010-row-failure.json").read_text())
    assert result["rows"] == [expected_first] + ["ROW_VOID"] * 5
    assert result["active_row"] == 1
    assert result["next_expected_row"] is None
    with pytest.raises(R010SerialAdmissionDenied):
        journal.begin_later_row(2, raw[1])


def test_failure_before_any_burn_voids_all_six_rows(envelope):
    anchor, instance = envelope
    _, hashes = nonces()
    journal = R010SerialNonceJournal(instance, six_nonce_sha256=hashes)
    journal.latch_failure("preexec_unavailable")
    root = anchor / instance.snapshot()["envelope_root_name"]
    result = json.loads(
        (root / "command-journal" / "r010-row-failure.json").read_text())
    assert result["active_row"] is None
    assert result["rows"] == ["ROW_VOID"] * 6
    assert result["native_launch_allowed"] is False


def _source_only_first_row_finite(tmp_path):
    """Real local nofollow FS observations; no Worker or subprocess launch."""
    from gateway.lbe_r010_finite_integrity import observe_selected_source_files
    from gateway.lbe_r010_row_fs import (
        observe_r010_private_tree, verify_r010_finite_row_after)
    from gateway.lbe_worker import LbeWorkPlan

    selected = tmp_path / "first-party"
    selected.mkdir(mode=0o700)
    (selected / "main.py").write_text("x = 1\n")
    private = tmp_path / "private-cache"
    private.mkdir(mode=0o700)
    src_fd = os.open(selected, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    cache_fd = os.open(private, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        source_before = observe_selected_source_files(
            root_fd=src_fd, relative_paths=("main.py",))
        cache_before = observe_r010_private_tree(root_fd=cache_fd)
        fixed = LbeWorkPlan(
            workspace="py-direct", cwd="py-direct",
            runner="direct", runner_project="py-direct",
            timeout_seconds=120,
            requested_argv=("python", "-m", "pytest", "-q"),
            effective_argv=("python", "-m", "pytest", "-q"))
        return verify_r010_finite_row_after(
            row=1, plan=fixed,
            selected_root_fd=src_fd, selected_before=source_before,
            private_root_fd=cache_fd, private_before=cache_before)
    finally:
        os.close(src_fd)
        os.close(cache_fd)


def _fake_source_only_owned(digest):
    from gateway.lbe_r010_owned_row import R010OwnedRowSourceObservation
    return R010OwnedRowSourceObservation(
        row=1, nonce_sha256=digest,
        outcome="ORIGINAL_ZERO_READER_HEALTHY_FINITE_FS_NOT_CHECKED",
        observed_original_exit_code=0,
        original_child_reaped=True, owner_reader_healthy=True,
        output_complete=True)


def test_finite_plus_source_owned_zero_persists_but_never_advances(
        envelope, tmp_path):
    anchor, instance = envelope
    raw, hashes = nonces()
    journal = R010SerialNonceJournal(instance, six_nonce_sha256=hashes)
    journal.burn_first_nonce(raw[0])
    # Replay reuses the exact immutable source receipt, not a new fixture.
    finite_receipt = _source_only_first_row_finite(tmp_path)
    result = journal.record_source_only_first_row_zero(
        owned=_fake_source_only_owned(hashes[0]),
        finite=finite_receipt)
    assert result["next_row_allowed"] is False
    assert result["native_launch_allowed"] is False
    assert result["six_command_product_t1_pass"] is False
    root = anchor / instance.snapshot()["envelope_root_name"]
    persisted = json.loads(
        (root / "command-journal" / "row-01-source-only.json").read_text())
    assert persisted["row_positive_success"] is False
    assert persisted["next_row_allowed"] is False
    assert persisted["original_exit_code"] == 0
    with pytest.raises(R010SerialAdmissionDenied, match="duplicate"):
        journal.record_source_only_first_row_zero(
            owned=_fake_source_only_owned(hashes[0]),
            finite=finite_receipt)
    with pytest.raises(R010SerialAdmissionDenied, match="not implemented"):
        journal.begin_later_row(2, raw[1])


def test_cross_nonce_and_wrong_finite_receipt_cannot_mint_source_success(
        envelope, tmp_path):
    from dataclasses import replace
    anchor, instance = envelope
    raw, hashes = nonces()
    journal = R010SerialNonceJournal(instance, six_nonce_sha256=hashes)
    journal.burn_first_nonce(raw[0])
    valid = _source_only_first_row_finite(tmp_path)
    for owned, finite in (
        (_fake_source_only_owned(hashes[1]), valid),
        (_fake_source_only_owned(hashes[0]),
         replace(valid, row=2)),
        (_fake_source_only_owned(hashes[0]),
         replace(valid, native_launch_allowed=True)),
        (_fake_source_only_owned(hashes[0]),
         replace(valid, six_command_product_t1_pass=True)),
    ):
        with pytest.raises(R010SerialAdmissionDenied, match="unqualified"):
            journal.record_source_only_first_row_zero(
                owned=owned, finite=finite)
    root = anchor / instance.snapshot()["envelope_root_name"]
    assert not (root / "command-journal" / "row-01-source-only.json").exists()



def test_real_journal_reports_six_row_state_but_never_models_fake_completion(
        envelope):
    _, instance = envelope
    raw, commits = nonces()
    journal = R010SerialNonceJournal(instance, six_nonce_sha256=commits)
    before = journal.row_state_snapshot()
    assert before["job_state_model"] == "JOB_PREEXEC_HOLD"
    assert before["rows_model"] == ("ROW_NOT_RUN",) * 6
    journal.burn_first_nonce(raw[0])
    during = journal.row_state_snapshot()
    assert during["job_state_model"] == "JOB_ROW_RUNNING_1"
    assert during["rows_model"] == ("ROW_RUNNING",) + ("ROW_NOT_RUN",) * 5
    assert during["six_command_product_t1_pass"] is False
    with pytest.raises(R010SerialAdmissionDenied, match="not implemented"):
        journal.begin_later_row(2, raw[1])
    journal.latch_failure("owner_reader_ambiguous")
    with pytest.raises(R010SerialAdmissionDenied):
        journal.row_state_snapshot()
