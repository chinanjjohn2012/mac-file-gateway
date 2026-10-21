"""Command-line entry point. Never chooses a filesystem root implicitly."""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys

from .core import Gateway, GatewayError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read one explicitly selected project, with optional guarded writes and controlled command execution.")
    parser.add_argument("--root", default=argparse.SUPPRESS, help="Existing project directory; never / or the entire home directory")
    parser.add_argument("--config", help="Private Multi-Workspace gateway.json; mutually exclusive with legacy --root")
    parser.add_argument("--port", type=int, default=argparse.SUPPRESS, help="Loopback HTTP port (1024-65535; default 8765)")
    parser.add_argument("--exclude", action="append", default=argparse.SUPPRESS, help="Additional case-insensitive exclusion glob; repeatable")
    parser.add_argument("--allow-hidden-path", action="append", default=argparse.SUPPRESS, help="Allow one exact project-relative hidden directory (repeatable; protected names remain denied)")
    parser.add_argument("--allow-write", action="store_true", default=argparse.SUPPRESS, help="Enable guarded file writes and directory creation (default: read-only)")
    parser.add_argument("--write-path", action="append", default=argparse.SUPPRESS, help="Writable relative subtree or file; repeatable; requires --allow-write")
    parser.add_argument("--backup-retention-days", type=int, default=argparse.SUPPRESS, help="Backup retention in UTC days (1-3650; default 15)")
    parser.add_argument("--allow-exec", action="store_true", default=argparse.SUPPRESS, help="Enable controlled project command execution (default: disabled)")
    parser.add_argument("--exec-path", action="append", default=argparse.SUPPRESS, help="Executable relative subtree; repeatable; required with --allow-exec")
    parser.add_argument("--exec-runner", action="append", default=argparse.SUPPRESS, help="Project runner mapping PATH=direct or PATH=pipenv; repeatable; requires --allow-exec")
    parser.add_argument("--allow-git", action="store_true", default=argparse.SUPPRESS, help="Explicit Legacy Git CLI opt-in (default: disabled)")
    parser.add_argument("--git-command", action="append", default=argparse.SUPPRESS, help="One explicitly permitted Git V1 command; repeatable and requires --allow-git")
    parser.add_argument("--local-skill-root", default=argparse.SUPPRESS, help="Optional project-relative agent-runtime root for Local Skill Bridge")
    parser.add_argument("--local-skill-policy-dir", default=argparse.SUPPRESS, help="Private local audit policy directory (default: ~/.config/mac-file-gateway/local-skill-policy)")
    parser.add_argument("--transport", choices=("http", "stdio"), default="http")
    parser.add_argument("--http-only", action="store_true", help="Explicit REST-only mode; cannot connect as an MCP server")
    parser.add_argument("--check", action="store_true", help="Check the root and print policy JSON without opening a network listener")
    # Suppressed defaults preserve explicit canonical option presence even
    # for abbreviations, --option=value and values equal to the old defaults.
    # Restore the legacy defaults only after deciding which mode was selected.
    legacy_defaults = {
        'root': None, 'port': 8765, 'exclude': [], 'allow_hidden_path': [],
        'allow_write': False, 'write_path': [], 'backup_retention_days': 15,
        'allow_exec': False, 'exec_path': [], 'exec_runner': [],
        'allow_git': False, 'git_command': [],
        'local_skill_root': None, 'local_skill_policy_dir': None,
    }
    args = parser.parse_args(argv)
    if args.config is not None:
        if not args.config.strip():
            parser.error("--config requires a nonempty path")
        if any(hasattr(args, name) for name in legacy_defaults):
            parser.error("--config cannot be combined with legacy project or permission arguments")
        if args.transport != "http":
            parser.error("--config requires HTTP transport; multi stdio is not supported")
        from .multi_cli import run_multi
        return run_multi(args)
    for name, default in legacy_defaults.items():
        if not hasattr(args, name):
            setattr(args, name, default)
    if not args.root:
        parser.error("the following arguments are required: --root")
    if args.local_skill_policy_dir and not args.local_skill_root:
        parser.error("--local-skill-policy-dir requires --local-skill-root")
    if not 1024 <= args.port <= 65535:
        parser.error("--port must be from 1024 to 65535")
    if args.http_only and args.transport != "http":
        parser.error("--http-only requires --transport http")
    if args.write_path and not args.allow_write:
        parser.error("--write-path requires --allow-write")
    if not 1 <= args.backup_retention_days <= 3650:
        parser.error("--backup-retention-days must be from 1 to 3650")
    if (args.exec_path or args.exec_runner) and not args.allow_exec:
        parser.error("--exec-path/--exec-runner require --allow-exec")
    if args.allow_exec and not args.exec_path:
        parser.error("--allow-exec requires at least one --exec-path")
    if args.git_command and not args.allow_git:
        parser.error("--git-command requires --allow-git")
    if args.allow_git and not args.git_command:
        parser.error("--allow-git requires at least one --git-command")
    gateway = None
    try:
        gateway = Gateway(args.root, excludes=tuple(args.exclude), allow_hidden_paths=tuple(args.allow_hidden_path), allow_write=args.allow_write, write_paths=tuple(args.write_path), backup_retention_days=args.backup_retention_days, allow_exec=args.allow_exec, exec_paths=tuple(args.exec_path), exec_runners=tuple(args.exec_runner), allow_git=args.allow_git, git_allowed_commands=tuple(args.git_command))
        local_skill_bridge = None
        if args.local_skill_root:
            from .local_skills import LocalSkillBridge
            local_skill_bridge = LocalSkillBridge.create(
                gateway, args.local_skill_root,
                policy_dir=Path(args.local_skill_policy_dir).expanduser() if args.local_skill_policy_dir else None,
            )
        if args.check:
            result = gateway.info()
            result["mcp_sdk_installed"] = importlib.util.find_spec("mcp") is not None
            if local_skill_bridge is not None:
                result["local_skill_bridge"] = local_skill_bridge.status_info()
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return 0
        if not args.http_only and importlib.util.find_spec("mcp") is None:
            print("Official MCP SDK is missing. Run: bash setup.sh", file=sys.stderr)
            return 2
        if args.transport == "stdio":
            from .mcp_adapter import build_mcp
            build_mcp(gateway, port=args.port, local_skill_bridge=local_skill_bridge).run(transport="stdio")
        else:
            import uvicorn
            from .http import create_app
            app = create_app(gateway, enable_mcp=not args.http_only, port=args.port, token=os.environ.get("GATEWAY_TOKEN"), local_skill_bridge=local_skill_bridge)
            mode = "REST only; MCP disabled" if args.http_only else "MCP + REST"
            write_policy = "WRITES ENABLED (preview by default)" if args.allow_write else "file writes disabled"
            exec_policy = "EXEC ENABLED (preview by default)" if args.allow_exec else "exec disabled"
            git_info = gateway.info()["git_policy"]
            if git_info["adapter_exposed"]:
                git_policy = ("Git adapter registered (separate opt-in; preview default)"
                              if git_info["available"]
                              else "Git adapter registered (state unavailable; apply denied)")
            else:
                git_policy = "Git disabled" if not args.allow_git else "Git unavailable"
            if local_skill_bridge is not None:
                print(f"Local Skill Bridge: {local_skill_bridge.status_info()['status']}", file=sys.stderr)
            print(f"Mac File Gateway: {mode}, {write_policy}, {exec_policy}, {git_policy}, listening on 127.0.0.1:{args.port}", file=sys.stderr)
            if args.allow_write:
                print("Write scope: " + ", ".join(gateway.info()["write_policy"]["paths"]), file=sys.stderr)
            if args.allow_exec:
                print("Exec scope: " + ", ".join(gateway.info()["exec_policy"]["paths"]), file=sys.stderr)
            print("Only selected project files are exposed. Press Ctrl-C to stop.", file=sys.stderr)
            uvicorn.run(app, host="127.0.0.1", port=args.port, access_log=False,
                        proxy_headers=False, limit_concurrency=16, timeout_keep_alive=5,
                        timeout_graceful_shutdown=10, log_level="warning")
        return 0
    except (GatewayError, ValueError) as exc:
        print(f"Gateway: {exc}", file=sys.stderr)
        return 2
    except ImportError:
        print("A dependency is missing or incompatible. Run: bash setup.sh", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 0
    finally:
        if gateway is not None:
            gateway.close()


if __name__ == "__main__":
    raise SystemExit(main())
