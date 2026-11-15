"""R010 real append-only fsync row serialization; synthetic SAFE T0 only."""
import hashlib
import json
import os
import socket
import subprocess

import pytest

from gateway.lbe_r010_job_envelope import (
    R010JobEnvelopeDenied, R010JobKey, _create_once_in_pinned_anchor,
)
from gateway.lbe_r010_six_durable import (
    R010SixDurableDenied, R010SixRowDurableKernel,
)


@pytest.fixture(autouse=True)
def forbid_native_or_network(monkeypatch):
    def denied(*_args, **_kwargs):
        raise AssertionError("SAFE T0 forbids native child/network/signal")
    monkeypatch.setattr(subprocess, "Popen", denied)
    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(os, "kill", denied)
    monkeypatch.setattr(os, "killpg", denied, raising=False)


def key():
    return R010JobKey(
        repo="chinanjjohn2012/mac-file-gateway", pr=114,
        workflow_id=145, workflow_path=".github/workflows/r010.yml",
        workflow_ref=("chinanjjohn2012/mac-file-gateway/"
                      ".github/workflows/r010.yml@refs/heads/main"),
        run_id=42640408843, run_attempt=1,
        check_run_id=129239691259, job_name="r010_preexec_hold",
        head_sha="a" * 40,
        design_id="MWE-LBE-R010-AUTHORITY-CHAIN-DESIGN-013-CANDIDATE",
        design_blob="f57e39543a6fe3d64fe99b8669fc7da854b93a64",
        owner_choice_comment_id=6740275850,
        host_option="A1", review_sequence_option="B1",
        state_domain="R010_EPHEMERAL_JOB_STATE_V1",
    )


def nonces():
    raw = tuple("%064x" % i for i in range(1, 7))
    hashed = tuple(hashlib.sha256(bytes.fromhex(x)).hexdigest() for x in raw)
    return raw, hashed


@pytest.fixture
def job(tmp_path):
    folder = tmp_path / "fresh"
    folder.mkdir(mode=0o700)
    fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with _create_once_in_pinned_anchor(fd, key()) as instance:
            raw, commitments = nonces()
            engine = R010SixRowDurableKernel(
                instance, nonce_sha256=commitments, source_sha256="f" * 64)
            root = folder / instance.snapshot()["envelope_root_name"]
            yield engine, instance, root / "command-journal", raw, commitments
    finally:
        os.close(fd)


def test_all_six_persist_real_fsync_and_hash_chain_but_no_product_t1(job):
    store, _, journal_dir, raw, commits = job
    state = store.snapshot()
    assert state.job_state_model == "JOB_PREEXEC_HOLD"
    assert state.source_model_only is True
    assert state.native_launch_allowed is False
    assert state.records_written == 1
    records = []
    for row, nonce in enumerate(raw, 1):
        state = store.burn_model_row(row, nonce)
        assert state.job_state_model == "JOB_ROW_RUNNING_" + str(row)
        assert state.active_row_model == row
        burn = journal_dir / ("r010-source-model-%02d-burn.json" % row)
        burn_bytes = burn.read_bytes()
        record = json.loads(burn_bytes)
        assert record["nonce_sha256"] == commits[row - 1]
        assert nonce not in repr(record)
        assert record["native_launch_allowed"] is False
        assert record["source_model_only"] is True
        records.append((burn_bytes, record))
        state = store.finish_model_row(
            row, "ROW_POSITIVE_SUCCESS",
            evidence_sha256=hashlib.sha256(("fixture:" + str(row)).encode()).hexdigest())
        result = journal_dir / ("r010-source-model-%02d-result.json" % row)
        result_bytes = result.read_bytes()
        result_data = json.loads(result_bytes)
        assert result_data["classification_model"] == "ROW_POSITIVE_SUCCESS"
        assert result_data["six_command_product_t1_pass"] is False
        assert result_data["row_positive_success"] is False
        assert result_data["source_model_only"] is True
        records.append((result_bytes, result_data))
        assert state.records_written == 1 + row * 2
        assert state.native_launch_allowed is False
        assert state.six_command_product_t1_pass is False
    assert state.job_state_model == "JOB_SIX_COMMAND_COMPLETE"
    assert state.expected_row_model is None
    assert state.rows_model == ("ROW_POSITIVE_SUCCESS",) * 6
    first_manifest = (journal_dir / "r010-source-model-six-manifest.json").read_bytes()
    previous_sha = hashlib.sha256(first_manifest).hexdigest()
    for raw_bytes, record in records:
        assert record["previous_record_sha256"] == previous_sha
        previous_sha = hashlib.sha256(raw_bytes).hexdigest()
    assert state.last_record_sha256 == previous_sha
    with pytest.raises(R010SixDurableDenied, match="not PRODUCT_T1"):
        store.claim_product_t1_pass()
    with pytest.raises(R010SixDurableDenied, match="no authenticated"):
        store.grant_native_launch()
    with pytest.raises(R010SixDurableDenied):
        store.burn_model_row(6, raw[5])


@pytest.mark.parametrize("failed_row", range(1, 7))
@pytest.mark.parametrize("classification", [
    "ROW_OBSERVED_NONZERO", "ROW_OBSERVED_ZERO_INVALID_OUTPUT_OR_FS",
    "ROW_AMBIGUOUS",
])
def test_failure_at_every_row_voids_remaining_permanently(
        job, failed_row, classification):
    store, _, journal_dir, raw, _ = job
    for row in range(1, failed_row):
        store.burn_model_row(row, raw[row - 1])
        store.finish_model_row(
            row, "ROW_POSITIVE_SUCCESS", evidence_sha256="e" * 64)
    store.burn_model_row(failed_row, raw[failed_row - 1])
    state = store.finish_model_row(
        failed_row, classification, evidence_sha256="b" * 64)
    assert state.job_state_model == "JOB_FAILED_LATCHED"
    assert state.expected_row_model is None
    assert state.rows_model == (
        ("ROW_POSITIVE_SUCCESS",) * (failed_row - 1) +
        (classification,) + ("ROW_VOID",) * (6 - failed_row))
    terminal = json.loads((
        journal_dir / ("r010-source-model-%02d-result.json" % failed_row)
    ).read_text())
    assert terminal["remaining_rows_void"] is True
    with pytest.raises(R010SixDurableDenied):
        store.burn_model_row(min(6, failed_row + 1), raw[min(5, failed_row)])


def test_out_of_order_wrong_replay_and_unstarted_latch(job):
    store, _, folder, raw, _ = job
    with pytest.raises(R010SixDurableDenied):
        store.burn_model_row(2, raw[1])
    with pytest.raises(R010SixDurableDenied):
        store.burn_model_row(1, raw[1])
    state = store.burn_model_row(1, raw[0])
    assert state.active_row_model == 1
    with pytest.raises(R010SixDurableDenied):
        store.burn_model_row(1, raw[0])
    with pytest.raises(R010SixDurableDenied):
        store.burn_model_row(2, raw[1])
    with pytest.raises(R010SixDurableDenied):
        store.finish_model_row(
            2, "ROW_POSITIVE_SUCCESS", evidence_sha256="0" * 64)
    with pytest.raises(R010SixDurableDenied):
        store.latch_unstarted_model(evidence_sha256="a" * 64)
    state = store.finish_model_row(
        1, "ROW_POSITIVE_SUCCESS", evidence_sha256="a" * 64)
    assert state.expected_row_model == 2
    state = store.latch_unstarted_model(evidence_sha256="a" * 64)
    assert state.rows_model == ("ROW_POSITIVE_SUCCESS",) + ("ROW_VOID",) * 5
    assert state.job_state_model == "JOB_FAILED_LATCHED"
    with pytest.raises(R010SixDurableDenied):
        store.burn_model_row(2, raw[1])


def test_partial_fsync_exception_consumes_lease_without_replay(job, monkeypatch):
    from gateway import lbe_r010_six_durable as mod
    store, instance, _, raw, commits = job
    store.burn_model_row(1, raw[0])
    def damaged(*_a, **_kw):
        raise R010JobEnvelopeDenied("synthetic fsync failure")
    monkeypatch.setattr(mod, "_write_once", damaged)
    with pytest.raises(R010SixDurableDenied, match="uncertain"):
        store.finish_model_row(
            1, "ROW_POSITIVE_SUCCESS", evidence_sha256="a" * 64)
    with pytest.raises(R010SixDurableDenied, match="permanent"):
        store.snapshot()
    with pytest.raises(R010SixDurableDenied, match="already claimed"):
        R010SixRowDurableKernel(
            instance, nonce_sha256=commits, source_sha256="f" * 64)


def test_closed_job_or_bad_nonce_tuple_is_never_reclaimed(job):
    store, instance, _, raw, commits = job
    with pytest.raises(R010SixDurableDenied):
        R010SixRowDurableKernel(
            instance, nonce_sha256=commits, source_sha256="f" * 64)
    instance.close()
    with pytest.raises(R010SixDurableDenied, match="unavailable"):
        store.burn_model_row(1, raw[0])


def test_row_model_input_types_are_strict(job):
    store, _, _, raw, _ = job
    for row, nonce in ((True, raw[0]), (1, "not-a-nonce"), (0, raw[0]),
                       (7, raw[0])):
        with pytest.raises(R010SixDurableDenied):
            store.burn_model_row(row, nonce)
    store.burn_model_row(1, raw[0])
    for classification, witness in (("ROW_LAUNCH_ALLOWED", "f" * 64),
                                    ("ROW_POSITIVE_SUCCESS", "bad"),
                                    ("ROW_POSITIVE_SUCCESS", True)):
        with pytest.raises(R010SixDurableDenied):
            store.finish_model_row(1, classification, evidence_sha256=witness)
    state = store.snapshot()
    assert state.job_state_model == "JOB_ROW_RUNNING_1"
