"""Run fixed R006 host-source verification as SAFE T0; print no secrets."""
from __future__ import annotations
from dataclasses import asdict
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from gateway.lbe_r006_macos_allowlist import (
    collect_r006_host_safety_diagnostics_t0,
    verify_r006_fixed_host_allowlist_t0,
)
def main():
    diagnostic = collect_r006_host_safety_diagnostics_t0()
    print(json.dumps(
        diagnostic, sort_keys=True, separators=(",", ":")))
    item = verify_r006_fixed_host_allowlist_t0()
    print(json.dumps(asdict(item), sort_keys=True, separators=(",", ":")))
    return 0
if __name__ == "__main__":
    raise SystemExit(main())
