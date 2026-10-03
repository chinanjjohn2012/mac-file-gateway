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
    return {tool.name for tool in mcp._tool_manager.list_tools()}


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
