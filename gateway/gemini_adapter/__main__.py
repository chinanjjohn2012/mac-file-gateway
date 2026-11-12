"""Manual, opt-in Gemini adapter lifecycle and local approval controls."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .config import initialize_config, load_config, SCOPES
from .store import Store

DEFAULT_CONFIG = "~/.config/mac-file-gateway/gemini.json"


def main(args: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Local Gemini MCP OAuth adapter (independent from Gateway)")
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init",help="Create private OAuth credentials exactly once")
    init.add_argument("--public-url",required=True,help="Stable HTTPS origin for the Gemini Tunnel")
    init.add_argument("--workspace",action="append",default=[],help="Authorized multi-workspace ID; repeatable")
    for name in ("init","check","serve","pending","approve","deny","revoke-all"):
        p = init if name == "init" else sub.add_parser(name)
        p.add_argument("--config",default=DEFAULT_CONFIG)
        if name in ("approve","deny"):
            p.add_argument("request_id")
        if name == "approve":
            p.add_argument("--scope",action="append",choices=sorted(SCOPES),default=None)
            p.add_argument("--workspace",action="append",default=None)
    ns=parser.parse_args(args)
    try:
        if ns.command == "init":
            config = initialize_config(ns.config,public_url=ns.public_url,workspaces=tuple(ns.workspace))
            print("Created private Gemini configuration. Keep this credential secret.")
            print("Client ID:",config.client_id)
            print("Client secret:",config.client_secret)
            return 0
        config=load_config(ns.config)
        if ns.command == "check":
            print(json.dumps({"public_url":config.public_url,"upstream":config.upstream,
                              "listen_port":config.listen_port,"scopes":config.scopes,"workspaces":config.workspaces},indent=2))
            return 0
        if ns.command == "serve":
            import uvicorn
            from .app import create_app
            print(f"Gemini Adapter listening on 127.0.0.1:{config.listen_port} (local only)",file=sys.stderr)
            uvicorn.run(create_app(config),host="127.0.0.1",port=config.listen_port,
                        proxy_headers=False,access_log=False,limit_concurrency=16,
                        timeout_keep_alive=5,log_level="warning")
            return 0
        store=Store(config.state_file)
        try:
            if ns.command == "pending":
                print(json.dumps(store.pending(),indent=2))
            elif ns.command == "approve":
                store.approve(ns.request_id, scopes=tuple(ns.scope) if ns.scope is not None else None,
                              workspaces=tuple(ns.workspace) if ns.workspace is not None else None)
                print("Authorized locally. Continue from the original browser consent page.")
            elif ns.command == "deny":
                store.deny(ns.request_id)
                print("Denied locally.")
            elif ns.command == "revoke-all":
                store.revoke_all()
                print("All previously issued grants revoked.")
        finally:
            store.close()
        return 0
    except (ValueError,OSError,json.JSONDecodeError) as exc:
        print(f"Gemini Adapter: {exc}",file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
