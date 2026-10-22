"""Non-networked AST worker. Input is source on stdin; output only line numbers."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys

def main() -> int:
    source = sys.stdin.buffer.read(32769)
    if len(source) > 32768:
        return 2
    try:
        path = Path(__file__).resolve().with_name("contextvar_semantics.py")
        spec = importlib.util.spec_from_file_location("_contextvar_semantics_worker", path)
        if spec is None or spec.loader is None:
            return 2
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        lines = module.proven_contextvar_lines(source.decode("utf-8-sig"))
        sys.stdout.write(json.dumps(lines, separators=(",", ":")))
        return 0
    except (SyntaxError, ValueError, RecursionError, MemoryError, OSError):
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
