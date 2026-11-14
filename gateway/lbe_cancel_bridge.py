"""Transport cancellation notification for the shared schema-v2 Exec gate.

Only the synchronous WorkspaceService authorizes commands. A cancelled
HTTP/MCP waiter may stop waiting; it never proves direct-child termination,
releases the owner's child reservation, retries, or signals a process.
"""
from __future__ import annotations

from collections.abc import Awaitable, Callable
from functools import partial
import threading
from typing import Any

import anyio

from .workspaces import WorkspaceService


async def invoke_exec_with_cancel(
    service: WorkspaceService, workspace: str, cwd: str, argv: list[str],
    timeout_seconds: int = 60, dry_run: bool = True, *,
    is_disconnected: Callable[[], Awaitable[bool]] | None = None,
) -> dict[str, Any]:
    """Bridge an async waiter to the real synchronous Exec Worker.

    The Worker remains accountable for its own child/reaper/pipe lifetime
    after an async request is abandoned. A disconnect only sets a one-way
    threading.Event; it never asserts cleanup or produces an ACK.
    """
    cancelled = threading.Event()
    finished = anyio.Event()

    async def watch_disconnect() -> None:
        assert is_disconnected is not None
        try:
            while not finished.is_set():
                # The ASGI disconnect probe itself can stall while the
                # sync Worker has already finished. Bound each observation
                # so the original success/error response is never held by
                # a blocked receive. Probe timeout is NOT disconnection.
                with anyio.move_on_after(0.1):
                    if await is_disconnected():
                        cancelled.set()
                        return
                with anyio.move_on_after(0.05):
                    await finished.wait()
        except Exception:
            # If polling the connection fails, never presume a healthy
            # waiter. Signal loss of wait; do not assert child cleanup.
            cancelled.set()

    # An AnyIO task group wraps exceptions from its body in ExceptionGroup.
    # Existing REST/MCP contracts require the original GatewayError instead.
    # Capture it while inside the group, then re-raise only AFTER exit.
    result: dict[str, Any] | None = None
    error: BaseException | None = None
    async with anyio.create_task_group() as tasks:
        if is_disconnected is not None:
            tasks.start_soon(watch_disconnect)
        try:
            result = await anyio.to_thread.run_sync(
                partial(
                    service.invoke_exec, workspace, cwd, argv,
                    timeout_seconds, dry_run, cancelled=cancelled,
                ),
                abandon_on_cancel=True,
            )
        except BaseException as exc:
            # Covers cancellation as well as a failed sync Worker. A
            # detached Worker remains responsible for its own child.
            cancelled.set()
            error = exc
        finally:
            finished.set()
    if error is not None:
        raise error
    assert result is not None
    return result
