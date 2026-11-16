"""Sanitized, read-only readiness reasons for the six-command MVP.

This module never grants Exec, reads files or probes an executable.  Actual
request admission and the pre-Popen recheck remain in WorkspaceService.
"""
from __future__ import annotations


def summarize_mvp_readiness(
    *, enabled: bool, apply_configured: bool, tools_ready: bool,
    durability: str, owner_unavailable: bool, capacity_exhausted: bool,
    closing: bool, apply_eligible: bool, preview_eligible: bool,
) -> dict[str, object]:
    """Only aggregate runtime status; not per-command or native-test proof."""
    reasons: list[str] = []
    if not enabled:
        reasons.append("exec_paths_disabled")
    if not apply_configured:
        reasons.append("dual_opt_in_or_scope_missing")
    if apply_configured and not tools_ready:
        reasons.append("selected_tools_unavailable")
    if enabled and durability == "quarantined":
        reasons.append("historical_state_quarantined")
    elif enabled and durability != "healthy":
        reasons.append("historical_state_unavailable")
    if owner_unavailable:
        reasons.append("original_child_owner_unavailable")
    if capacity_exhausted:
        reasons.append("original_child_capacity_exhausted")
    if closing:
        reasons.append("service_closing")
    if not apply_eligible and not reasons:
        reasons.append("workspace_original_child_slot_unavailable")
    return {
        "six_command_apply": "eligible" if apply_eligible else "blocked",
        "preview": "eligible" if preview_eligible else "blocked",
        "blocking_codes": reasons,
        "evidence_grade": "runtime_status_only_not_native_test",
    }


__all__ = ["summarize_mvp_readiness"]
