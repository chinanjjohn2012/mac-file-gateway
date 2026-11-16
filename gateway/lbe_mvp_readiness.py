"""Sanitized, read-only readiness reasons for the six-command MVP.

This module never grants Exec, reads files or probes an executable.  Actual
request admission and the pre-Popen recheck remain in WorkspaceService.
"""
from __future__ import annotations



def has_supported_six_command_scope(
    exec_paths: tuple[str, ...],
    exec_runners: tuple[str, ...],
) -> bool:
    """Does a trusted v2 Workspace configuration support ANY fixed row?

    This is a conservative, PURE metadata-only feasibility predicate, not
    authorization or a proof that a real cwd/Pipfile/toolchain is usable.
    The per-request nofollow/denylist/exact-six/owner/launcher checks remain
    authoritative. No filesystem reads, imports of foreign code or child run.
    """
    from .lbe_six_fixed_commands import SIX_FIXED_COMMANDS

    scopes = tuple(() if value == "." else tuple(value.split("/"))
                   for value in exec_paths)
    runners: list[tuple[tuple[str, ...], str]] = []
    for value in exec_runners:
        path, sep, name = value.partition("=")
        if sep != "=" or name not in {"direct", "pipenv"}:
            return False  # defensive: parser already rejects malformed grants
        runners.append((() if path == "." else tuple(path.split("/")), name))

    def within(cwd: tuple[str, ...], grant: tuple[str, ...]) -> bool:
        return len(cwd) >= len(grant) and cwd[:len(grant)] == grant

    for row in SIX_FIXED_COMMANDS:
        cwd = tuple(row.cwd.split("/"))
        granted = [scope for scope in scopes if within(cwd, scope)]
        if not granted:
            continue
        # Go in schema-v2 is always Direct even if a Python runner is
        # configured for the same directory. S4/S5 offer no output artifact
        # so they are the minimal structural Go readiness rows.
        if row.requested_argv[0] == "go":
            return True

        configured = [(scope, name) for scope, name in runners
                      if within(cwd, scope)]
        if configured:
            # Match CommandRunner._configured_runner() longest-prefix rule.
            runner_project, selected = max(configured, key=lambda p: len(p[0]))
        else:
            # With auto_pipenv=False, nearest grant is the runner_project.
            runner_project = max(granted, key=len)
            selected = "direct"
        if (selected == row.runner and runner_project == cwd):
            return True
    return False

def summarize_mvp_readiness(
    *, enabled: bool, apply_configured: bool, scope_ready: bool,
    tools_ready: bool,
    durability: str, owner_unavailable: bool, capacity_exhausted: bool,
    closing: bool, apply_eligible: bool, preview_eligible: bool,
) -> dict[str, object]:
    """Only aggregate runtime status; not per-command or native-test proof."""
    reasons: list[str] = []
    if not enabled:
        reasons.append("exec_paths_disabled")
    if not apply_configured:
        reasons.append("dual_opt_in_or_scope_missing")
    if apply_configured and not scope_ready:
        reasons.append("six_command_scope_unavailable")
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


__all__ = ["summarize_mvp_readiness", "has_supported_six_command_scope"]
