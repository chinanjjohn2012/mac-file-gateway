"""R2-T01 RED stub only. No production Worker integration or process launch."""
from __future__ import annotations

from pathlib import Path


class ExecStateStore:
    def __init__(self, state_dir: str | Path, *,
                 workspace_roots: tuple[str, ...] = ()):
        self.durability_state = "healthy"
        self.quarantine_reason_code = None

    def require_healthy(self) -> None:
        return None

    def prepare(self, workspace: str, workspace_identity: tuple[int, int]) -> str:
        return "0" * 32

    def mark_unknown(self, attempt_id: str) -> None:
        return None

    def close(self) -> None:
        return None
