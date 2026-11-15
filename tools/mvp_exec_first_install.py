"""Manually initialize a BRAND NEW v2 Gateway Exec state; never execute.

Invocation, with the Gateway STOPPED and no previous Exec history:
  python -m tools.mvp_exec_first_install --config-dir /abs/private \
      --confirm-first-install --confirm-gateway-stopped

DO NOT run this tool to repair missing/UNKNOWN/corrupt/historical state.
"""
from __future__ import annotations

import argparse
import json

from gateway.lbe_mvp_first_setup import initialize_fresh_v2_exec_state
from gateway.private_fs import PrivateFileError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(
        "Explicit first-install ONLY Exec state provisioning; "
        "does not reset state, launch commands or authorize T1."))
    parser.add_argument("--config-dir", required=True,
                        help="Existing operator-owned 0700 private Gateway config directory")
    parser.add_argument("--confirm-first-install", action="store_true",
                        help="Assert no prior Exec state/history exists on this installation")
    parser.add_argument("--confirm-gateway-stopped", action="store_true",
                        help="Assert all Gateway instances using this state are stopped")
    args = parser.parse_args(argv)
    try:
        result = initialize_fresh_v2_exec_state(
            args.config_dir,
            operator_confirmed_first_install=args.confirm_first_install,
            operator_confirmed_gateway_stopped=args.confirm_gateway_stopped,
        )
    except PrivateFileError as exc:
        print(json.dumps({"status": "refused", "reason": str(exc)},
                         sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
