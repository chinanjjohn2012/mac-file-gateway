#!/usr/bin/env python3
"""R010 tracked PREEXEC source entrypoint; stdlib-only until selector scrub.

Run by file path, never as a gateway package module. The entrypoint loads the
reviewed scrub gate directly from its tracked sibling file without importing
the gateway package. Only after the exact 18+2 environment has been destroyed
does it import the canonical gateway receipt type and product pipeline.

This source does not request OIDC, touch SSH agent protocol, open autofs,
launch a product child, grant PRODUCT_T1, or establish provider/Owner proof.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys


_MAX_GATE_BYTES = 65536
_PRIVATE_MODULE = "_mfg_r010_preimport_gate_bootstrap"
_HELPER_KEYS = ("HOME", "LANG", "LC_ALL", "PATH", "TMPDIR")
_SAFE_REASON_CODES = {
    "gateway package already loaded before PREEXEC entry": "GATEWAY_PRELOADED",
    "entrypoint is a symlink": "ENTRYPOINT_SYMLINK",
    "gateway package loaded before selector scrub": "GATEWAY_PRELOADED",
    "source path is a symlink": "GATE_SOURCE_SYMLINK",
    "source file identity unsafe": "GATE_SOURCE_IDENTITY",
    "source changed while reading": "GATE_SOURCE_DRIFT",
    "source file unavailable": "GATE_SOURCE_UNAVAILABLE",
    "scrub source loader unavailable": "GATE_LOADER_UNAVAILABLE",
    "scrub source could not be loaded": "GATE_LOAD_FAILED",
    "scrub source imported gateway before environment destruction":
        "GATE_IMPORTED_PRODUCT",
    "scrub source changed after load": "GATE_SOURCE_DRIFT",
    "gateway product loaded before selector scrub completed":
        "PRODUCT_PRELOADED_AFTER_SCRUB",
    "post-scrub process environment is not closed": "POST_SCRUB_ENV_DRIFT",
    "scrub gate source drift": "GATE_SOURCE_DRIFT",
    "canonical gate import failed": "CANONICAL_GATE_IMPORT_FAILED",
    "canonical receipt validation failed": "CANONICAL_RECEIPT_INVALID",
    "receipt did not come from current process environment":
        "RECEIPT_NOT_PROCESS_SOURCE",
    "product import failed:ImportError": "PRODUCT_IMPORT_IMPORT_ERROR",
    "product import failed:ModuleNotFoundError": "PRODUCT_IMPORT_MODULE_MISSING",
    "product import failed:FileNotFoundError": "PRODUCT_IMPORT_FILE_MISSING",
    "product import failed:OSError": "PRODUCT_IMPORT_OS_ERROR",
    "product import failed:RuntimeError": "PRODUCT_IMPORT_RUNTIME_ERROR",
    "product import failed:TypeError": "PRODUCT_IMPORT_TYPE_ERROR",
    "product import failed:ValueError": "PRODUCT_IMPORT_VALUE_ERROR",
    "product import failed:KeyError": "PRODUCT_IMPORT_KEY_ERROR",
    "product import failed:AttributeError": "PRODUCT_IMPORT_ATTRIBUTE_ERROR",
    "product import failed:OTHER": "PRODUCT_IMPORT_OTHER",
    "wrong product module imported": "WRONG_PRODUCT_MODULE",
    "pre-product source entry failed closed": "UNQUALIFIED_SOURCE",
}


class R010PreexecSourceEntryDenied(ValueError):
    """Pre-product import ordering or exact source identity was not preserved."""


def _gateway_modules() -> tuple[str, ...]:
    return tuple(sorted(
        name for name in sys.modules
        if name == "gateway" or name.startswith("gateway.")))


def _read_regular_source(path: Path) -> tuple[bytes, str]:
    fd = -1
    try:
        if path.is_symlink():
            raise R010PreexecSourceEntryDenied("source path is a symlink")
        fd = os.open(
            path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_size <= 0
                or before.st_size > _MAX_GATE_BYTES):
            raise R010PreexecSourceEntryDenied("source file identity unsafe")
        raw = os.read(fd, _MAX_GATE_BYTES + 1)
        after = os.fstat(fd)
        identity = lambda st: (
            st.st_dev, st.st_ino, st.st_uid, st.st_nlink, st.st_mode,
            st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        if (len(raw) != before.st_size or len(raw) > _MAX_GATE_BYTES
                or identity(before) != identity(after)):
            raise R010PreexecSourceEntryDenied("source changed while reading")
        return raw, hashlib.sha256(raw).hexdigest()
    except R010PreexecSourceEntryDenied:
        raise
    except (OSError, ValueError, TypeError):
        raise R010PreexecSourceEntryDenied("source file unavailable") from None
    finally:
        if fd >= 0:
            os.close(fd)


def _load_gate_without_gateway(gate: Path):
    if _gateway_modules():
        raise R010PreexecSourceEntryDenied(
            "gateway package loaded before selector scrub")
    raw, digest = _read_regular_source(gate)
    try:
        spec = importlib.util.spec_from_file_location(_PRIVATE_MODULE, gate)
        if spec is None or spec.loader is None:
            raise R010PreexecSourceEntryDenied("scrub source loader unavailable")
        module = importlib.util.module_from_spec(spec)
        sys.modules[_PRIVATE_MODULE] = module
        spec.loader.exec_module(module)
    except R010PreexecSourceEntryDenied:
        raise
    except BaseException:
        raise R010PreexecSourceEntryDenied(
            "scrub source could not be loaded") from None
    if _gateway_modules():
        raise R010PreexecSourceEntryDenied(
            "scrub source imported gateway before environment destruction")
    reread, check = _read_regular_source(gate)
    if reread != raw or check != digest:
        raise R010PreexecSourceEntryDenied("scrub source changed after load")
    return module, digest


def bootstrap_r010_preexec_source_entry(
    *, run_id: str, run_attempt: str, head_sha: str, job_name: str,
    image_version: str, private_home: str, private_tmp: str,
) -> dict[str, object]:
    """Scrub first, then import canonical product modules in the same process."""
    before = _gateway_modules()
    if before:
        raise R010PreexecSourceEntryDenied(
            "gateway package already loaded before PREEXEC entry")
    entry = Path(__file__)
    if entry.is_symlink():
        raise R010PreexecSourceEntryDenied("entrypoint is a symlink")
    gate = entry.resolve().with_name("lbe_r010_preimport_gate.py")
    try:
        module, gate_sha = _load_gate_without_gateway(gate)
        expected = module.R010PreimportExpected(
            run_id=run_id, run_attempt=run_attempt, head_sha=head_sha,
            job_name=job_name, image_version=image_version,
            private_home=private_home, private_tmp=private_tmp)
        receipt = module.scrub_r010_preimport_environment(expected=expected)
        after_scrub = _gateway_modules()
        if after_scrub:
            raise R010PreexecSourceEntryDenied(
                "gateway product loaded before selector scrub completed")
        if tuple(sorted(os.environ)) != _HELPER_KEYS:
            raise R010PreexecSourceEntryDenied(
                "post-scrub process environment is not closed")
        _raw, gate_sha_after = _read_regular_source(gate)
        if gate_sha_after != gate_sha:
            raise R010PreexecSourceEntryDenied("scrub gate source drift")

        repo_root = str(entry.resolve().parent.parent)
        if repo_root not in sys.path:
            sys.path.insert(0, repo_root)
        try:
            canonical_gate = importlib.import_module(
                "gateway.lbe_r010_preimport_gate")
        except BaseException:
            raise R010PreexecSourceEntryDenied(
                "canonical gate import failed") from None
        canonical = canonical_gate.R010PreimportScrubReceipt(
            head_sha=receipt.head_sha,
            run_id=receipt.run_id,
            run_attempt=receipt.run_attempt,
            job_name=receipt.job_name,
            helper_keys=tuple(receipt.helper_keys),
            helper_env_sha256=receipt.helper_env_sha256,
            selectors_scrubbed=receipt.selectors_scrubbed,
            product_modules_absent_before_scrub=(
                receipt.product_modules_absent_before_scrub),
            source_original_os=receipt.source_original_os,
        )
        try:
            canonical_gate.validate_r010_preimport_receipt_source(
                canonical,
                head_sha=head_sha, run_id=run_id, run_attempt=run_attempt,
                job_name=job_name, helper_keys=_HELPER_KEYS,
                helper_env_sha256=canonical.helper_env_sha256)
        except BaseException:
            raise R010PreexecSourceEntryDenied(
                "canonical receipt validation failed") from None
        if canonical.source_original_os is not True:
            raise R010PreexecSourceEntryDenied(
                "receipt did not come from current process environment")
        try:
            product = importlib.import_module(
                "gateway.lbe_r010_product_pipeline")
        except BaseException as exc:
            kind = type(exc).__name__
            if kind not in {
                "ImportError", "ModuleNotFoundError", "FileNotFoundError",
                "OSError", "RuntimeError", "TypeError", "ValueError",
                "KeyError", "AttributeError",
            }:
                kind = "OTHER"
            raise R010PreexecSourceEntryDenied(
                "product import failed:" + kind) from None
        if product.__name__ != "gateway.lbe_r010_product_pipeline":
            raise R010PreexecSourceEntryDenied("wrong product module imported")
        return {
            "status": "PREIMPORT_ENTRY_PRODUCT_IMPORTED_SOURCE_ONLY_NO_T1",
            "gateway_modules_before_scrub": list(before),
            "gateway_modules_after_scrub": list(after_scrub),
            "product_module": product.__name__,
            "helper_keys": list(_HELPER_KEYS),
            "receipt_sha256": canonical.receipt_sha256,
            "gate_source_sha256": gate_sha,
            "native_launch_allowed": False,
            "product_t1": "NOT_RUN",
        }
    except R010PreexecSourceEntryDenied:
        raise
    except BaseException:
        raise R010PreexecSourceEntryDenied(
            "pre-product source entry failed closed") from None
    finally:
        sys.modules.pop(_PRIVATE_MODULE, None)


def _parse(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-run-id", required=True)
    parser.add_argument("--expected-run-attempt", required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--expected-job", required=True)
    parser.add_argument("--expected-image-version", required=True)
    parser.add_argument("--expected-home", required=True)
    parser.add_argument("--expected-tmp", required=True)
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = _parse(argv)
    try:
        result = bootstrap_r010_preexec_source_entry(
            run_id=args.expected_run_id,
            run_attempt=args.expected_run_attempt,
            head_sha=args.expected_head,
            job_name=args.expected_job,
            image_version=args.expected_image_version,
            private_home=args.expected_home,
            private_tmp=args.expected_tmp,
        )
        print(json.dumps(
            result, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
        return 0
    except BaseException as exc:
        try:
            os.environ.clear()
        except BaseException:
            pass
        reason = (
            _SAFE_REASON_CODES.get(str(exc), "UNQUALIFIED_SOURCE")
            if type(exc) is R010PreexecSourceEntryDenied
            else "UNQUALIFIED_SOURCE"
        )
        print(json.dumps({
            "status": "R010_PREEXEC_SOURCE_ENTRY_DENY",
            "reason_code": reason,
            "native_launch_allowed": False,
            "product_t1": "NOT_RUN",
        }, sort_keys=True, separators=(",", ":"), ensure_ascii=True),
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
