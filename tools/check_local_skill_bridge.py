"""Validate the real audited Local Skill tree without executing Skill query scripts."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from gateway.core import Gateway, GatewayError
from gateway.local_skills import LocalSkillBridge
from gateway.local_skills.config import load_audit_policy


_ALLOWED = {"PASS", "PASS_WITH_CONSTRAINTS"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check real Local Skill audit hashes, hook self-tests, and Entry availability without executing Skill query scripts."
    )
    parser.add_argument("project_root", help="Absolute path to the selected project root, for example the project directory")
    parser.add_argument(
        "--local-skill-root",
        default="agent-runtime",
        help="Project-relative audited codeagent root (default: agent-runtime)",
    )
    parser.add_argument("--local-skill-policy-dir", help="Private local audit policy directory")
    args = parser.parse_args(argv)

    gateway = Gateway(args.project_root)
    try:
        policy_dir = Path(args.local_skill_policy_dir).expanduser() if args.local_skill_policy_dir else None
        bridge = LocalSkillBridge.create(gateway, args.local_skill_root, policy_dir=policy_dir)
        info = bridge.info()
        policy = load_audit_policy(policy_dir)
        expected = sorted(
            name
            for name, record in policy.compatibility["skills"].items()
            if record.get("role") == "entry" and record.get("disposition") in _ALLOWED
        )
        entries = {
            item["name"]: {
                "available": bool(item.get("available")),
                **({"reason": item["reason"]} if item.get("reason") else {}),
            }
            for item in info.get("entries", [])
        }
        actual = sorted(entries)
        unavailable = sorted(name for name, item in entries.items() if not item["available"])
        forbidden_present = sorted(set(actual) - set(expected))
        ok = (
            info.get("status") == "enabled"
            and actual == expected
            and not unavailable
            and not forbidden_present
        )
        result = {
            "status": "PASS" if ok else "FAIL",
            "bridge_status": info.get("status"),
            "reason": info.get("reason"),
            "expected_entries": expected,
            "entries": entries,
            "forbidden_entries_present": forbidden_present,
            "external_skill_scripts_executed": False,
        }
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0 if ok else 1
    except GatewayError as exc:
        print(json.dumps({"status": "FAIL", "reason": exc.code, "external_skill_scripts_executed": False}))
        return 1
    finally:
        gateway.close()


if __name__ == "__main__":
    raise SystemExit(main())
