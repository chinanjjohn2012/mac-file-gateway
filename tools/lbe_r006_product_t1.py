"""Reviewed R006 PRODUCT_T1 entrypoint source. DO NOT run without exact T1 authority.

This is the tracked direct-route harness a future authorized disposable macOS
job may invoke after B/C FULL review and an exact repository-owner grant. It
does not accept owner/review/runtime evidence from an Exec request; it uses the
canonical private bootstrap and then calls the ordinary shared invoke_exec gate.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from gateway.core import GatewayError
from gateway.lbe_r006_t1_harness import (
    D4R006HarnessDenied, D4R006SourceBundle,
    load_r006_source_bundle, prepare_and_install_r006_one_shot,
)
from gateway.private_fs import PrivateFileError
from gateway.workspaces import WorkspaceService
from gateway.workspaces_config import read_workspace_config


def run_r006_product_t1_once(
    service: WorkspaceService, bundle: D4R006SourceBundle, *,
    owner_comment_id: int, g05_receipt_path: str,
):
    """Install exact verified one-shot then consume via shared invoke_exec."""
    if type(service) is not WorkspaceService or type(bundle) is not D4R006SourceBundle:
        raise D4R006HarnessDenied("untrusted PRODUCT_T1 entry inputs")
    prepare_and_install_r006_one_shot(
        service, bundle, owner_comment_id=owner_comment_id,
        g05_receipt_path=g05_receipt_path)
    return service.invoke_exec(
        bundle.workspace, bundle.cwd, list(bundle.argv),
        timeout_seconds=bundle.timeout_seconds, dry_run=False)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--source-bundle", required=True)
    parser.add_argument("--source-bundle-sha256", required=True)
    parser.add_argument("--owner-comment-id", type=int, required=True)
    parser.add_argument("--g05-receipt", required=True)
    args=parser.parse_args(argv)
    service=None
    try:
        config=Path(args.config)
        if (not config.is_absolute() or config.is_symlink()
                or not config.parent.is_dir()):
            raise D4R006HarnessDenied("private config path invalid")
        bundle=load_r006_source_bundle(
            args.source_bundle, args.source_bundle_sha256)
        settings=read_workspace_config(str(config))
        service=WorkspaceService(settings, config_dir=config.parent)
        result=run_r006_product_t1_once(
            service, bundle, owner_comment_id=args.owner_comment_id,
            g05_receipt_path=args.g05_receipt)
        print(json.dumps(result, sort_keys=True, separators=(",",":")))
        return 0
    except (D4R006HarnessDenied, PrivateFileError, GatewayError, ValueError) as exc:
        print("R006_PRODUCT_T1=BLOCKED: "+str(exc), file=sys.stderr)
        return 2
    finally:
        if service is not None:
            service.close()


if __name__=="__main__":
    raise SystemExit(main())
