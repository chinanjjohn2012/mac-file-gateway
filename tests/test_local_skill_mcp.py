import asyncio
import threading

from gateway.core import Gateway
from gateway.mcp_adapter import build_mcp


class FakeBridge:
    def info(self):
        return {"configured": True, "status": "enabled", "entries": []}

    def begin(self, skill, request):
        return {"skill": skill, "request": request}

    def read(self, skill_run_id, skill, path):
        return {"skill_run_id": skill_run_id, "skill": skill, "path": path}

    def run(self, skill_run_id, skill, script, argv, timeout_seconds=60):
        return {"skill_run_id": skill_run_id, "skill": skill, "script": script, "argv": argv}


def _tool_names(mcp):
    return {tool.name for tool in asyncio.run(mcp.list_tools())}


def test_local_skill_tools_are_opt_in(tmp_path):
    gateway = Gateway(tmp_path)
    try:
        without = _tool_names(build_mcp(gateway))
        assert "local_skill_info" not in without
        assert "begin_local_skill" not in without
        assert "read_skill_file" not in without
        assert "run_skill_script" not in without

        with_bridge = _tool_names(build_mcp(gateway, local_skill_bridge=FakeBridge()))
        assert with_bridge - without == {
            "local_skill_info",
            "begin_local_skill",
            "read_skill_file",
            "run_skill_script",
        }
    finally:
        gateway.close()


def test_local_skill_tools_do_not_add_general_shell(tmp_path):
    gateway = Gateway(tmp_path)
    try:
        names = _tool_names(build_mcp(gateway, local_skill_bridge=FakeBridge()))
        assert "run_local_skill" not in names
        assert "shell" not in names
        assert "exec" not in names
        assert "run_command" not in names
    finally:
        gateway.close()


class PausedSkillBridge(FakeBridge):
    """No real Skill files, hooks, scripts, credentials, or external services."""

    def __init__(self):
        self.started = threading.Event()
        self.release = threading.Event()
        self.finished = threading.Event()
        self.call_count = 0

    def run(self, skill_run_id, skill, script, argv, timeout_seconds=60):
        self.call_count += 1
        self.started.set()
        try:
            if not self.release.wait(5):
                raise RuntimeError("Test-only skill worker release timed out")
            return {"skill": skill, "script": script, "argv": argv, "call_count": self.call_count}
        finally:
            self.finished.set()


def test_cancelled_skill_tool_waiter_does_not_undo_or_repeat_running_worker(tmp_path):
    """Cancellation of an awaiting coroutine is not a rollback of a sync worker.

    This tests the MCP -> run_in_threadpool handoff using a fake Bridge, not
    the runtime business Skill executor (whose timeout has separate tests).
    """
    gateway = Gateway(tmp_path)
    bridge = PausedSkillBridge()
    server = build_mcp(gateway, local_skill_bridge=bridge)

    async def exercise():
        task = asyncio.create_task(server.call_tool(
            "run_skill_script",
            {"skill_run_id": "test-run", "skill": "demo",
             "script": "scripts/harmless.sh", "argv": [], "timeout_seconds": 2},
        ))
        try:
            assert await asyncio.to_thread(bridge.started.wait, 3), "Fake Bridge was not invoked"
            task.cancel()
        finally:
            bridge.release.set()

        try:
            result = await asyncio.wait_for(task, 4)
        except asyncio.CancelledError:
            pass
        else:
            assert result.is_error is not True
            assert result.structured_content is not None
            assert result.structured_content["call_count"] == 1
        assert await asyncio.to_thread(bridge.finished.wait, 3)
        assert bridge.call_count == 1

    try:
        asyncio.run(exercise())
    finally:
        bridge.release.set()
        gateway.close()
