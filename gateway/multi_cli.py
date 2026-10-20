"""Explicit Multi-Workspace CLI path; never auto-selects local roots."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sys

from .workspaces_config import read_workspace_config
from .workspaces import WorkspaceService
from .private_fs import PrivateFileError
from .core import GatewayError


def run_multi(args) -> int:
    """One process + one MCP HTTP transport; no Phase-2/3 tools."""
    config = Path(args.config).expanduser()
    try:
        settings = read_workspace_config(str(config))
        service = WorkspaceService(settings, config_dir=config.parent)
        try:
            if args.check:
                result = service.info()
                result['mcp_sdk_installed'] = importlib.util.find_spec('mcp') is not None
                print(json.dumps(result, indent=2, ensure_ascii=False))
                return 0
            if not args.http_only and importlib.util.find_spec('mcp') is None:
                print('Official MCP SDK is missing. Run: bash setup.sh', file=sys.stderr)
                return 2
            import uvicorn
            from .http_multi import create_multi_app
            app = create_multi_app(service, enable_mcp=not args.http_only,
                                   port=settings.port, token=os.environ.get('GATEWAY_TOKEN'))
            print(f'Mac File Gateway: multi mode, {len(settings.workspaces)} workspaces, '
                  f'listening on 127.0.0.1:{settings.port}', file=sys.stderr)
            git_state = ('internally enabled (public adapters pending)' if service.any_git
                         else 'disabled by policy or unavailable')
            print('General Exec and Local Skills disabled; Git CLI ' + git_state + '.', file=sys.stderr)
            uvicorn.run(app, host='127.0.0.1', port=settings.port,
                        access_log=False, proxy_headers=False, limit_concurrency=16,
                        timeout_keep_alive=5, timeout_graceful_shutdown=10, log_level='warning')
            return 0
        finally:
            service.close()
    except (PrivateFileError, GatewayError, ValueError) as exc:
        print(f'Gateway: {exc}', file=sys.stderr)
        return 2
    except ImportError:
        print('A dependency is missing or incompatible. Run: bash setup.sh', file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 0
