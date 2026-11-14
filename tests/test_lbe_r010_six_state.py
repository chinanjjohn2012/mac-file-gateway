"""Production six-row transition algebra under SAFE T0, no native authority."""
import hashlib
import os
import socket
import subprocess

import pytest

from gateway.lbe_r010_six_state import (
    R010SixRowPolicy, R010SixRowPolicyDenied,
)


@pytest.fixture(autouse=True)
def cannot_spawn_or_signal(monkeypatch):
    def denied(*_args, **_kwargs):
        raise AssertionError("R010 source-policy state tests cannot spawn")
    monkeypatch.setattr(subprocess, "Popen", denied)
    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(os, "kill", denied)
    monkeypatch.setattr(os, "killpg", denied, raising=False)


def six():
    raw = tuple(f"{i:064x}" for i in range(1, 7))
    hashes = tuple(hashlib.sha256(bytes.fromhex(x)).hexdigest() for x in raw)
    return raw, hashes


def test_six_ordered_positive_source_model_never_becomes_t1():
    raw, commits = six()
    state = R010SixRowPolicy.hold(commits)
    state = state.ready_model_first()
    for row in range(1, 7):
        before = state.snapshot()
        assert before["expected_row_model"] == row
        assert before["authenticated_original_child_results"] is False
        state = state.burn_model(row, raw[row - 1])
        assert state.rows[row - 1] == "ROW_RUNNING"
        assert state.active_row == row
        state = state.finish_model(row, "ROW_POSITIVE_SUCCESS")
    assert state.job_state == "JOB_SIX_COMMAND_COMPLETE"
    assert state.rows == ("ROW_POSITIVE_SUCCESS",) * 6
    assert state.snapshot()["native_launch_allowed"] is False
    assert state.snapshot()["six_command_product_t1_pass"] is False
    assert state.snapshot()["authenticated_original_child_results"] is False
    with pytest.raises(R010SixRowPolicyDenied):
        state.burn_model(1, raw[0])
    with pytest.raises(R010SixRowPolicyDenied):
        state.finish_model(6, "ROW_POSITIVE_SUCCESS")


@pytest.mark.parametrize("fail_row", (1, 2, 3, 4, 5, 6))
@pytest.mark.parametrize("reason", (
    "ROW_OBSERVED_NONZERO",
    "ROW_OBSERVED_ZERO_INVALID_OUTPUT_OR_FS",
    "ROW_AMBIGUOUS",
))
def test_negative_at_any_row_latches_and_voids_every_remaining_row(
        fail_row, reason):
    raw, commitments = six()
    model = R010SixRowPolicy.hold(commitments).ready_model_first()
    for row in range(1, fail_row + 1):
        model = model.burn_model(row, raw[row - 1])
        model = model.finish_model(
            row, reason if row == fail_row else "ROW_POSITIVE_SUCCESS")
    assert model.job_state == "JOB_FAILED_LATCHED"
    assert model.rows == (
        ("ROW_POSITIVE_SUCCESS",) * (fail_row - 1) +
        (reason,) + ("ROW_VOID",) * (6 - fail_row))
    assert model.expected_row is None
    assert model.active_row is None
    with pytest.raises(R010SixRowPolicyDenied):
        model.burn_model(min(fail_row + 1, 6), raw[min(fail_row, 5)])


@pytest.mark.parametrize("attempt", [0, 2, 6, 7, -1, True])
def test_out_of_order_before_first_row_denied(attempt):
    raw, commitments = six()
    model = R010SixRowPolicy.hold(commitments).ready_model_first()
    with pytest.raises(R010SixRowPolicyDenied):
        model.burn_model(attempt, raw[0])


def test_global_across_workspaces_no_second_row_during_first_running():
    raw, hashes = six()
    model = R010SixRowPolicy.hold(hashes).ready_model_first()
    model = model.burn_model(1, raw[0])
    with pytest.raises(R010SixRowPolicyDenied):
        model.burn_model(2, raw[1])
    with pytest.raises(R010SixRowPolicyDenied):
        model.burn_model(1, raw[0])
    with pytest.raises(R010SixRowPolicyDenied):
        model.finish_model(2, "ROW_POSITIVE_SUCCESS")
    assert model.snapshot()["native_launch_allowed"] is False


def test_wrong_nonce_duplicate_sha_and_model_replay_denied():
    raw, hashes = six()
    with pytest.raises(R010SixRowPolicyDenied):
        R010SixRowPolicy.hold(hashes[:5] + (hashes[0],))
    state = R010SixRowPolicy.hold(hashes).ready_model_first()
    with pytest.raises(R010SixRowPolicyDenied):
        state.burn_model(1, raw[1])
    with pytest.raises(R010SixRowPolicyDenied):
        state.burn_model(1, "A" * 64)
    state = state.burn_model(1, raw[0]).finish_model(
        1, "ROW_POSITIVE_SUCCESS")
    with pytest.raises(R010SixRowPolicyDenied):
        state.burn_model(2, raw[0])
    state = state.burn_model(2, raw[1])
    with pytest.raises(R010SixRowPolicyDenied):
        state.finish_model(1, "ROW_POSITIVE_SUCCESS")


def test_lost_ack_before_row_and_after_prior_success_void_remaining():
    raw, commits = six()
    state = R010SixRowPolicy.hold(commits)
    failed = state.fail_unstarted_model()
    assert failed.rows == ("ROW_VOID",) * 6
    with pytest.raises(R010SixRowPolicyDenied):
        failed.ready_model_first()
    state = state.ready_model_first().burn_model(1, raw[0])
    state = state.finish_model(1, "ROW_POSITIVE_SUCCESS")
    failed = state.fail_unstarted_model()
    assert failed.rows == ("ROW_POSITIVE_SUCCESS",) + ("ROW_VOID",) * 5
    assert failed.job_state == "JOB_FAILED_LATCHED"


def test_ambiguous_or_unknown_classification_never_advances():
    raw, commits = six()
    model = R010SixRowPolicy.hold(commits).ready_model_first()
    model = model.burn_model(1, raw[0])
    for bad in ("SOURCE_ONLY_EXIT0", "ROW_RUNNING", "ROW_NOT_RUN", "", None):
        with pytest.raises(R010SixRowPolicyDenied):
            model.finish_model(1, bad)
