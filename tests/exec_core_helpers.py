"""Synthetic owner fixtures stay in tests, never in the runtime modules."""
from contextlib import contextmanager
from gateway.workspaces import WorkspaceService, ActiveRuntimeInventory
from gateway.workspaces_config import parse_workspace_config


@contextmanager
def core_service(tmp_path, policies=None):
    projects = tmp_path / "projects"
    projects.mkdir()
    config = tmp_path / "config"
    config.mkdir(mode=0o700)
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    policies = policies or {"a": {"enabled": True, "paths": ["service"]}, "b": {"enabled": False}}
    workspaces = {}
    for name, policy in policies.items():
        root = projects / name
        root.mkdir()
        (root / "service").mkdir()
        (root / "service" / "test.txt").write_text("fixture")
        workspaces[name] = {"root": str(root), "exec": policy}
    settings = parse_workspace_config({"schema_version": 1, "workspaces": workspaces})
    service = WorkspaceService(settings, config_dir=config, inventory=ActiveRuntimeInventory(paths=(runtime,)))
    try:
        yield service
    finally:
        service.close()
