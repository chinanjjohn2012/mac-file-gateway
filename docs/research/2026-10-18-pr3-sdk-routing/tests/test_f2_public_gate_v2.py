"""Exercise the public probe's exit contract using synthetic violation records.

These tests do not impersonate real SDK qualification. Real SDK ASGI is run
separately; these prove bad probe results cannot be promoted to PASS.
"""
import sys
from pathlib import Path

import anyio
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import fullchain_probe_v2 as probe


def f2_result(**patch):
    record = {
        "case": "cancel_at_real_predispatch_backpressure",
        "real_zero_buffer_send_blocked": True,
        "cancelled_request_dispatched": False,
        "route_entry_retained_after_ASGI_exit": False,
        "open_send_streams": 0,
        "open_receive_streams": 0,
        "safety_assertion_no_abandoned_predispatch_route": True,
        "cancelled_id_seen_before_replay": True,
        "cancelled_id_seen_before_DELETE": True,
        "replay_status": 409,
        "replay_route_writes": 0,
        "replay_responder_registrations": 0,
        "replay_business_dispatch_delta": 0,
        "route_absent_after_replay": True,
        "A_positive_succeeded": True,
        "subsequent_positive_succeeded": True,
    }
    record.update(patch)
    return record


@pytest.mark.parametrize("changes", [
    {"cancelled_request_dispatched": True},
    {"cancelled_id_seen_before_replay": False},
    {"cancelled_id_seen_before_DELETE": False},
    {"replay_status": 200},
    {"replay_route_writes": 1},
    {"replay_responder_registrations": 1},
    {"replay_business_dispatch_delta": 1},
    {"route_absent_after_replay": False},
])
def test_public_main_must_reject_invalid_f2_even_when_routes_and_streams_closed(monkeypatch, tmp_path, changes):
    async def fake_related():
        return {'case': 'FastMCP_Context_related_ID_type',
                'safety_assertion_related_owner_preserved': True,
                'final_HTTP_results_correct': {'A': True, 'B': True}}

    async def fake_progress():
        return {'case': 'FastMCP_Context_progress_typed_related_ID',
                'safety_assertion_progress_owner_preserved': True,
                'final_HTTP_results_correct': {'A': True, 'B': True}}

    async def fake_cancel():
        return f2_result(**changes)

    async def fake_bytes():
        return {'case': 'retained_ID_bytes'}

    monkeypatch.setattr(probe, 'related_context_collision', fake_related)
    monkeypatch.setattr(probe, 'progress_context_collision', fake_progress)
    monkeypatch.setattr(probe, 'predispatch_cancel', fake_cancel)
    monkeypatch.setattr(probe, 'retained_ID_bytes', fake_bytes)
    monkeypatch.setattr(sys, 'argv', ['fullchain_probe_v2.py', 'candidate', str(tmp_path/'result.json')])
    with pytest.raises(AssertionError):
        anyio.run(probe.main)


def test_public_main_accepts_good_f2(monkeypatch, tmp_path):
    async def fake_related():
        return {'case': 'FastMCP_Context_related_ID_type',
                'safety_assertion_related_owner_preserved': True,
                'final_HTTP_results_correct': {'A': True, 'B': True}}

    async def fake_progress():
        return {'case': 'FastMCP_Context_progress_typed_related_ID',
                'safety_assertion_progress_owner_preserved': True,
                'final_HTTP_results_correct': {'A': True, 'B': True}}

    async def fake_cancel():
        return f2_result()

    async def fake_bytes():
        return {'case': 'retained_ID_bytes'}

    for name, fn in [('related_context_collision',fake_related),
                     ('progress_context_collision',fake_progress),
                     ('predispatch_cancel',fake_cancel),
                     ('retained_ID_bytes',fake_bytes)]:
        monkeypatch.setattr(probe, name, fn)
    monkeypatch.setattr(sys, 'argv', ['fullchain_probe_v2.py', 'candidate', str(tmp_path/'result.json')])
    anyio.run(probe.main)
