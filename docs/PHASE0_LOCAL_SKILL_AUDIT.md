# Local Skill audit baseline

The original business-specific audit facts and conclusions are kept in private local policy. This public document no longer publishes actual Skill names, database tables, instance aliases or source hashes.

`samples/local-skill-policy/` contains synthetic format examples only. These examples are not a production audit, are never an automatic runtime fallback, and cannot establish availability of real Skills.

Runtime trust comes from the two reviewed local JSON files selected by `--local-skill-policy-dir`. A script-bearing Skill requires an explicit supported `kind`; script paths, argument constraints, dependencies, evidence hashes and Hook allow/deny vectors remain part of that private audit.

Use `tools/check_local_skill_bridge.py` with the selected private directory to validate source hashes and Hook self-tests without executing external query scripts. Use `tools/collect_local_skill_policy.py` to collect changed hashes into a non-executable draft for manual review. Source changes do not automatically grant new permissions.
