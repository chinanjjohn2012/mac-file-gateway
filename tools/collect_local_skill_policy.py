"""Collect changed audit hashes into a private, non-executable policy draft.

This tool does not run hooks or query scripts, grant permissions, infer SQL
mappings, add Skills, or update the active policy. Review both output JSON files
before changing review_status from draft to approved and validating them.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import sys

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from gateway.core import Gateway, GatewayError
from gateway.local_skills.config import AuditValidator, load_audit_policy
from gateway.local_skills.hooks import _parse_hook_manifest


def collect(project_root: Path, skill_root: str, policy_dir: Path, output_dir: Path) -> dict:
    policy_dir = policy_dir.expanduser().resolve()
    output_dir = output_dir.expanduser().absolute()
    project_root = project_root.resolve()
    if policy_dir.is_relative_to(project_root) or output_dir.resolve().is_relative_to(project_root):
        raise GatewayError("skill_bridge_unavailable", "Policy and draft must be outside the Gateway project scope.")
    if output_dir.exists() or output_dir.is_symlink():
        raise GatewayError("conflict", "Draft directory must be new; existing files are never overwritten.")
    policy = load_audit_policy(policy_dir)
    compatibility = copy.deepcopy(policy.compatibility)
    hook_data = json.loads((policy_dir / "hook-selftests.json").read_text(encoding="utf-8"))
    changes: list[dict] = []
    gateway = Gateway(project_root)
    try:
        validator = AuditValidator(gateway, skill_root, policy)

        def refresh(item: dict, relative_path: str, label: str) -> None:
            previous = item["sha256"]
            try:
                current = validator.sha256(relative_path)
            except GatewayError as exc:
                changes.append({"item": label, "path": relative_path, "status": "unavailable", "reason": exc.code})
                return
            if current != previous:
                changes.append({"item": label, "path": relative_path, "status": "changed", "previous_sha256": previous, "current_sha256": current})
                item["sha256"] = current

        for name, record in compatibility["skills"].items():
            for evidence in record.get("evidence", []):
                if evidence.get("kind") == "code_fact":
                    refresh(evidence, evidence["path"], f"skill:{name}")
        manifest = hook_data["hooks_manifest"]
        refresh(manifest, manifest["path"], "hooks_manifest")
        for hook in hook_data["hooks"]:
            refresh(hook, f"{skill_root}/{hook['script']}", f"hook:{hook['name']}")
        try:
            specs = _parse_hook_manifest(validator.snapshot(manifest["path"]).text)
            manifest_names = {spec.name for spec in specs}
            known_names = {hook["name"] for hook in hook_data["hooks"]}
            if manifest_names != known_names:
                changes.append({"item": "hook_coverage", "status": "requires_manual_audit", "added": sorted(manifest_names - known_names), "removed": sorted(known_names - manifest_names)})
        except GatewayError as exc:
            changes.append({"item": "hook_coverage", "status": "unavailable", "reason": exc.code})
    finally:
        gateway.close()

    compatibility["review_status"] = "draft"
    hook_data["review_status"] = "draft"
    report = {"review_status": "draft", "changes": changes, "permissions_updated": False, "scripts_executed": False}
    output_dir.mkdir(mode=0o700, parents=True)
    os.chmod(output_dir, 0o700)
    for name, value in (("skill-compatibility.json", compatibility), ("hook-selftests.json", hook_data), ("changes.json", report)):
        path = output_dir / name
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project_root", type=Path)
    parser.add_argument("--local-skill-root", required=True)
    parser.add_argument("--local-skill-policy-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report = collect(args.project_root, args.local_skill_root, args.local_skill_policy_dir, args.output_dir)
    except (GatewayError, OSError, RuntimeError) as exc:
        print(json.dumps({"status": "FAIL", "reason": exc.code if isinstance(exc, GatewayError) else "policy_io_error"}))
        return 1
    print(json.dumps({"status": "DRAFT", "changes": len(report["changes"]), "scripts_executed": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
