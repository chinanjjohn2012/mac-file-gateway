#!/usr/bin/env python3
"""Exercise the installed gateway on disposable projects, never on user files.

Run from the gateway installation with its own interpreter:
  .venv/bin/python tools/diagnose_lock.py --rounds 50
Or use this downloaded copy with --project /path/to/gateway-installation.
No network, credentials, nonstandard dependencies, or absolute error paths.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import errno
import hashlib
import json
import platform
from pathlib import Path
import sys
import tempfile
import threading
import traceback


def safe_exception(exc: BaseException) -> dict:
    """Keep error numbers and code locations, not OS filenames or contents."""
    frames = []
    seen = set()
    current = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        item = {"type": type(current).__name__}
        if isinstance(current, OSError):
            item["errno"] = current.errno
            item["errno_name"] = errno.errorcode.get(current.errno, "UNKNOWN")
        item["trace"] = [
            {"module": Path(frame.filename).name, "line": frame.lineno, "function": frame.name}
            for frame in traceback.extract_tb(current.__traceback__)[-4:]
        ]
        frames.append(item)
        current = current.__cause__ or current.__context__
    result = {"outcome": getattr(exc, "code", "unexpected_error"), "exception_chain": frames}
    details = getattr(exc, "details", None)
    if isinstance(details, dict):
        result["details"] = {key: details[key] for key in ("stage", "errno", "errno_name") if key in details}
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, default=Path.cwd(), help="gateway installation (not the served project)")
    parser.add_argument("--rounds", type=int, default=20)
    args = parser.parse_args()
    if not 1 <= args.rounds <= 500:
        parser.error("--rounds must be between 1 and 500")
    installation = args.project.expanduser().resolve()
    storage_path = installation / "gateway" / "write_storage.py"
    if not storage_path.is_file():
        parser.error("Run inside the gateway installation, or pass --project with its directory")
    sys.path.insert(0, str(installation))
    from gateway.core import Gateway, GatewayError

    print(json.dumps({"python": platform.python_version(), "platform": sys.platform,
                      "storage_sha256": hashlib.sha256(storage_path.read_bytes()).hexdigest(),
                      "test": "two threads, independent Gateway instances, fresh temporary project each round"}))
    failed = 0
    expected = hashlib.sha256(b"before").hexdigest()
    with tempfile.TemporaryDirectory(prefix="gateway-lock-check-") as tmp:
        for number in range(1, args.rounds + 1):
            root = Path(tmp) / ("project-%03d" % number)
            root.mkdir()
            (root / "app.py").write_bytes(b"before")
            first = second = None
            try:
                first = Gateway(root, allow_write=True)
                second = Gateway(root, allow_write=True)
                barrier = threading.Barrier(2)

                def update(gateway, text):
                    try:
                        barrier.wait(timeout=5)
                        result = gateway.write_file("app.py", text, expected, dry_run=False)
                        return {"outcome": "applied" if result["applied"] else "not_applied"}
                    except Exception as exc:
                        return safe_exception(exc)

                with ThreadPoolExecutor(max_workers=2) as pool:
                    futures = [pool.submit(update, first, "one"), pool.submit(update, second, "two")]
                    results = [future.result(timeout=15) for future in futures]
                outcomes = [result["outcome"] for result in results]
                backups = list((root / ".gateway-backups").glob("*.bak"))
                valid = (sorted(outcomes) == ["applied", "conflict"]
                         and (root / "app.py").read_bytes() in (b"one", b"two")
                         and len(backups) == 1 and backups[0].read_bytes() == b"before")
                if not valid:
                    failed += 1
                    if failed <= 3:
                        print(json.dumps({"round": number, "results": results, "backup_count": len(backups)}))
            except Exception as exc:
                failed += 1
                if failed <= 3:
                    print(json.dumps({"round": number, "setup_error": safe_exception(exc)}))
            finally:
                if second is not None:
                    second.close()
                if first is not None:
                    first.close()
    passed = args.rounds - failed
    print(f"Concurrent write check: {passed}/{args.rounds} passed; {failed} failed.")
    print("Only disposable temporary projects were written; no served project was accessed.")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
