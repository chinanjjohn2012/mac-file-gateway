"""Server-owned, startup-only bounded heuristic write-audit policy."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import time

from .core import GatewayError, _parts


class SensitiveAudit:
    def __init__(self, *, paths: tuple[str, ...] = (), expires_at: str | None = None,
                 write_paths: tuple[str, ...] = ()):
        self.paths: tuple[tuple[str, ...], ...] = ()
        self.expires_at: str | None = None
        self._expires_utc: datetime | None = None
        self.deadline: float | None = None
        if not paths and expires_at is None:
            return
        if not paths or not isinstance(expires_at, str):
            raise GatewayError("invalid_argument", "Sensitive audit requires paths and an absolute expiry.")
        try:
            date = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            # Check the original offset before normalizing. Converting first
            # would silently accept non-UTC offsets such as +09:00.
            if date.tzinfo is None or date.utcoffset() != timedelta(0):
                raise ValueError
            date = date.astimezone(timezone.utc)
        except (ValueError, OverflowError):
            raise GatewayError("invalid_argument", "Sensitive audit expiry must be UTC.") from None
        remaining = (date - datetime.now(timezone.utc)).total_seconds()
        if remaining > 3600 or remaining <= 0:
            raise GatewayError("invalid_argument", "Sensitive audit must expire in the next 60 minutes.")
        scopes = tuple(_parts(p) for p in paths)
        allowed = tuple(_parts(p) for p in write_paths)
        if any(not p or any(part.startswith(".") and part == ".." for part in p)
               for p in scopes):
            raise GatewayError("invalid_argument", "Sensitive audit needs nonempty relative paths.")
        if allowed and any(not any(p[:len(a)] == a for a in allowed) for p in scopes):
            raise GatewayError("invalid_argument", "Sensitive audit scopes must lie inside writable scopes.")
        self.paths = scopes
        self.expires_at = date.isoformat()
        self._expires_utc = date
        self.deadline = time.monotonic() + remaining

    def allows(self, canonical_path: str) -> bool:
        if not self.allows_scope_time():
            return False
        parts = _parts(canonical_path)
        return any(parts[:len(path)] == path for path in self.paths)

    def status(self) -> dict[str, object]:
        active = self.deadline is not None and self.allows_scope_time()
        return {"write_mode": "audit" if active else "enforce",
                "read_redaction_enabled": True,
                "expires_at": self.expires_at if active else None,
                "audit_scope_count": len(self.paths) if active else 0}

    def allows_scope_time(self) -> bool:
        # A wall-clock forward jump must expire audit immediately; a backward
        # jump must not extend the monotonic cap.
        return (self.deadline is not None and self._expires_utc is not None
                and time.monotonic() < self.deadline
                and datetime.now(timezone.utc) < self._expires_utc)
