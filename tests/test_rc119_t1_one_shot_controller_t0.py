"""SAFE T0 simulated one-run state-machine: no runtime/Owner/native authority."""
from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from tools import rc119_t1_one_shot_controller as c


NOW = 1_000_000


def claim(**kwargs):
    d = {
        "schema_version": 1, "repo": c.REPO, "product_pr": c.RC_PR,
        "product_head": c.RC_HEAD, "product_tree": c.RC_TREE,
        "profile_blob": c.PROFILE_B_BLOB,
        "control_head": "1" * 40, "control_tree": "2" * 40,
        "input_lock_sha256": "3" * 64,
        "actor": c.OWNER, "event_name": "workflow_dispatch",
        "run_id": 2468, "run_attempt": 1, "nonce_sha256": "4" * 64,
        "checked_at": NOW, "expires_at": NOW + 3000,
        "authority_grade": c.AUTHORITY_GRADE,
        "source_grade": c.SOURCE_GRADE, "host_grade": c.HOST_GRADE,
    }
    d.update(kwargs)
    return d


def controller(tmp_path):
    return c.LocalT0Controller(tmp_path / "synthetic-ledger.sqlite")


def test_exact_synthetic_two_phase_success_never_grants_native(tmp_path):
    a = controller(tmp_path)
    d = claim()
    seen = [a.reserve(d,now=NOW)]
    seen.append(a.advance(d,now=NOW + 2,event="START_SIX"))
    seen.append(a.advance(d,now=NOW + 4,event="COMPLETE_SIX",
                          receipt=c.receipt_for_t0(d,now=NOW+4,kind="COMPLETE_SIX")))
    seen.append(a.advance(d,now=NOW + 5,event="START_MIXED"))
    seen.append(a.advance(d,now=NOW + 6,event="COMPLETE_MIXED",
                          receipt=c.receipt_for_t0(d,now=NOW+6,kind="COMPLETE_MIXED")))
    assert [r["t0_state"] for r in seen] == [
        "SIX_RESERVED","SIX_CONSUMED","SIX_PASSED","MIXED_CONSUMED","MIXED_FINALIZED"]
    assert all(r["native_execution_authorized"] is False for r in seen)
    assert all(r["cross_runner_lease_qualified"] is False for r in seen)
    assert a.state(run_id=d["run_id"],claim=d,now=NOW+7)["t0_state"] == "MIXED_FINALIZED"
    with pytest.raises(c.ControllerDenied,match="STATE_REPLAY"):
        a.advance(d,now=NOW+8,event="START_MIXED")


@pytest.mark.parametrize("changes", [
    {"repo":"other/other"}, {"product_pr":113}, {"product_head":"9"*40},
    {"product_tree":"8"*40}, {"profile_blob":"a"*40},
    {"actor":"unauthorized"}, {"event_name":"push"},
    {"run_attempt":2}, {"run_attempt":True}, {"run_id":0},
    {"control_head":"invalid"}, {"control_tree":"missing"},
    {"input_lock_sha256":"a"*40}, {"nonce_sha256":"bad"},
    {"authority_grade":"GITHUB_OWNER_VERIFIED"},
    {"source_grade":"PRELAUNCH_INPUTS_ATTESTED_ONLY"},
    {"host_grade":"QUALIFIED"}, {"expires_at":NOW-1},
    {"expires_at":NOW+10000}, {"checked_at":NOW-1000},
])
def test_false_claims_deny_before_local_lease(tmp_path,changes):
    a = controller(tmp_path)
    with pytest.raises(c.ControllerDenied):
        a.reserve(claim(**changes),now=NOW)


def test_extra_or_missing_fields_fail_closed(tmp_path):
    a=controller(tmp_path)
    d=claim()
    d["native_execution_authorized"] = True
    with pytest.raises(c.ControllerDenied,match="INVALID_OR_EXTRA"):
        a.reserve(d,now=NOW)
    d=claim()
    del d["control_tree"]
    with pytest.raises(c.ControllerDenied,match="INVALID_OR_EXTRA"):
        a.reserve(d,now=NOW)


def test_duplicate_same_run_and_nonce_new_run_denied(tmp_path):
    a=controller(tmp_path)
    d=claim()
    a.reserve(d,now=NOW)
    with pytest.raises(c.ControllerDenied,match="DUPLICATE"):
        a.reserve(d,now=NOW)
    with pytest.raises(c.ControllerDenied,match="DUPLICATE"):
        a.reserve(claim(run_id=9876),now=NOW)


def test_two_local_clients_duplicate_race_one_wins(tmp_path):
    target=tmp_path / "lease.sqlite"
    a=c.LocalT0Controller(target)
    b=c.LocalT0Controller(target)
    d=claim()
    def once(x):
        try:
            return x.reserve(d,now=NOW)["t0_state"]
        except c.ControllerDenied:
            return "DENIED"
    with ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(once,[a,b]))
    assert sorted(results) == ["DENIED", "SIX_RESERVED"]


def test_mixed_cannot_start_without_six_receipt(tmp_path):
    a=controller(tmp_path)
    d=claim()
    a.reserve(d,now=NOW)
    with pytest.raises(c.ControllerDenied,match="STATE_REPLAY"):
        a.advance(d,now=NOW,event="START_MIXED")
    a.advance(d,now=NOW,event="START_SIX")
    with pytest.raises(c.ControllerDenied,match="STATE_REPLAY"):
        a.advance(d,now=NOW,event="START_MIXED")


def test_receipt_from_other_run_or_phase_is_rejected(tmp_path):
    a=controller(tmp_path)
    d=claim()
    a.reserve(d,now=NOW)
    a.advance(d,now=NOW,event="START_SIX")
    wrong = c.receipt_for_t0(d,now=NOW,kind="COMPLETE_SIX")
    for m in ({"run_id":123},{"grade":"AUTHENTICATED"},{"kind":"COMPLETE_MIXED"},
              {"binding":"0"*64},{"result":"UNKNOWN"}):
        obj=copy.copy(wrong)
        obj.update(m)
        with pytest.raises(c.ControllerDenied,match="UNTRUSTED_PHASE"):
            a.advance(d,now=NOW,event="COMPLETE_SIX",receipt=obj)
    with pytest.raises(c.ControllerDenied):
        a.advance(d,now=NOW,event="COMPLETE_SIX")
    assert a.state(run_id=d["run_id"],claim=d,now=NOW)["t0_state"] == "SIX_CONSUMED"


def test_revoke_and_failure_are_terminal(tmp_path):
    a=controller(tmp_path)
    d=claim()
    a.reserve(d,now=NOW)
    assert a.cancel(d,now=NOW,reason="REVOKED")["t0_state"] == "REVOKED"
    with pytest.raises(c.ControllerDenied):
        a.advance(d,now=NOW,event="START_SIX")
    with pytest.raises(c.ControllerDenied):
        a.cancel(d,now=NOW,reason="FAILED")
    # A separate synthetic run must use a FRESH disposable DB file.
    a2=c.LocalT0Controller(tmp_path / "fresh-private-ledger.sqlite")
    d2=claim(run_id=13,nonce_sha256="a"*64)
    a2.reserve(d2,now=NOW)
    a2.advance(d2,now=NOW,event="START_SIX")
    a2.cancel(d2,now=NOW,reason="FAILED")
    with pytest.raises(c.ControllerDenied):
        a2.advance(d2,now=NOW,event="COMPLETE_SIX")


def test_expiration_persists_across_db_reopen_and_denies(tmp_path):
    a=controller(tmp_path)
    d=claim(expires_at=NOW+10)
    a.reserve(d,now=NOW)
    b=controller(tmp_path)
    assert b.state(run_id=d["run_id"],claim=d,now=NOW+11)["t0_state"] == "EXPIRED"
    with pytest.raises(c.ControllerDenied,match="RUN_EXPIRED"):
        b.advance(d,now=NOW+12,event="START_SIX")


def test_replayed_changed_bound_identity_denied(tmp_path):
    a=controller(tmp_path)
    d=claim()
    a.reserve(d,now=NOW)
    with pytest.raises(c.ControllerDenied,match="CHANGED_RUN_BINDING"):
        a.advance(claim(control_head="b"*40),now=NOW+5,event="START_SIX")
    with pytest.raises(c.ControllerDenied,match="RUN_ID_MISMATCH"):
        a.state(run_id=4321,claim=d,now=NOW+5)



def test_distinct_run_and_nonce_denied_in_same_private_ledger_before_and_after_completion(tmp_path):
    a=controller(tmp_path)
    first=claim()
    second=claim(run_id=9001,nonce_sha256="f"*64)
    a.reserve(first,now=NOW)
    with pytest.raises(c.ControllerDenied,match="PRIVATE_LEDGER_ALREADY_USED"):
        a.reserve(second,now=NOW)
    a.advance(first,now=NOW,event="START_SIX")
    a.advance(first,now=NOW,event="COMPLETE_SIX",
              receipt=c.receipt_for_t0(first,now=NOW,kind="COMPLETE_SIX"))
    a.advance(first,now=NOW,event="START_MIXED")
    a.advance(first,now=NOW,event="COMPLETE_MIXED",
              receipt=c.receipt_for_t0(first,now=NOW,kind="COMPLETE_MIXED"))
    with pytest.raises(c.ControllerDenied,match="PRIVATE_LEDGER_ALREADY_USED"):
        a.reserve(second,now=NOW+1)


def test_two_different_run_ids_concurrently_only_one_private_reservation(tmp_path):
    path=tmp_path / "one-db-two-clients.sqlite"
    a=c.LocalT0Controller(path)
    b=c.LocalT0Controller(path)
    first=claim()
    second=claim(run_id=9002,nonce_sha256="e"*64)
    def reserve(pair):
        ctl,d=pair
        try:
            ctl.reserve(d,now=NOW)
            return "RESERVED"
        except c.ControllerDenied:
            return "DENIED"
    with ThreadPoolExecutor(max_workers=2) as pool:
        answers=list(pool.map(reserve,[(a,first),(b,second)]))
    assert sorted(answers)==["DENIED","RESERVED"]


def test_expired_or_revoked_ledger_does_not_silently_rearm(tmp_path):
    a=controller(tmp_path)
    first=claim(expires_at=NOW+10)
    a.reserve(first,now=NOW)
    assert a.state(run_id=first["run_id"],claim=first,now=NOW+11)["t0_state"]=="EXPIRED"
    with pytest.raises(c.ControllerDenied,match="PRIVATE_LEDGER_ALREADY_USED"):
        a.reserve(claim(run_id=9003,nonce_sha256="d"*64),now=NOW+11)
    # Revoked private run also cannot silently issue a second grant.
    b=c.LocalT0Controller(tmp_path / "revoked-simulation.sqlite")
    other=claim(run_id=9004,nonce_sha256="c"*64)
    b.reserve(other,now=NOW)
    b.cancel(other,now=NOW,reason="REVOKED")
    with pytest.raises(c.ControllerDenied,match="PRIVATE_LEDGER_ALREADY_USED"):
        b.reserve(claim(run_id=9005,nonce_sha256="b"*64),now=NOW)


def test_unknown_outcome_is_sticky_terminal_and_blocks_reuse(tmp_path):
    a=controller(tmp_path)
    d=claim()
    a.reserve(d,now=NOW)
    a.advance(d,now=NOW,event="START_SIX")
    assert a.cancel(d,now=NOW+2,reason="UNKNOWN")["t0_state"]=="UNKNOWN"
    assert a.state(run_id=d["run_id"],claim=d,now=NOW+4000)["t0_state"]=="UNKNOWN"
    with pytest.raises(c.ControllerDenied,match="STATE_REPLAY"):
        a.advance(d,now=NOW+3,event="COMPLETE_SIX",
                  receipt=c.receipt_for_t0(d,now=NOW,kind="COMPLETE_SIX"))
    with pytest.raises(c.ControllerDenied,match="PRIVATE_LEDGER_ALREADY_USED"):
        a.reserve(claim(run_id=9006,nonce_sha256="a"*64),now=NOW+3)


def test_dangling_symlink_ledger_path_denied_even_when_target_missing(tmp_path):
    link=tmp_path / "dangling-simulation.sqlite"
    link.symlink_to(tmp_path / "does-not-exist.sqlite")
    with pytest.raises(c.ControllerDenied,match="SYMLINK_DATABASE_DENIED"):
        c.LocalT0Controller(link)
    assert not (tmp_path / "does-not-exist.sqlite").exists()


def test_visible_symlink_replacement_before_db_call_denied(tmp_path):
    a=controller(tmp_path)
    path=a.db_file
    path.unlink()
    replacement=tmp_path / "dummy-replacement.sqlite"
    replacement.write_bytes(b"synthetic noncredential bytes")
    path.symlink_to(replacement)
    with pytest.raises(c.ControllerDenied,match="SYMLINK_DATABASE_DENIED"):
        a.reserve(claim(),now=NOW)
    assert replacement.read_bytes()==b"synthetic noncredential bytes"


def test_no_actual_execution_mode_or_github_writes():
    assert c.NATIVE_EXECUTION_ENABLED is False
    with pytest.raises(c.ControllerDenied,match="NATIVE_T1_NOT_AUTHORIZED"):
        c.native_execution_decision()
    txt=Path(c.__file__).read_text()
    for bad in ("import subprocess", "subprocess.Popen", "urllib.request", "requests.get", "os.system", "exec("):
        assert bad not in txt
