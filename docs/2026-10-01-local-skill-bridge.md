> Privacy update: all business names, table names and instance aliases in this public reference are synthetic. Production configuration is private local policy selected by `--local-skill-policy-dir`, with no automatic sample fallback. The executable handler is selected by explicit Skill `kind`; names are not authorization rules.

# Local Skill Bridge v1 — Frozen Development Spec

Date: 2026-10-01  
Status: **Frozen after Phase 0 audit**

## 1. v1 decisions

1. v1 supports **Web mode only**.
2. Database access is **read-only**.
3. `agent-runtime/skills` is an immutable, read-only source of truth from the Gateway's perspective.
4. Local/Cursor execution mode is not part of v1.
5. Existing hooks are retained as **defense-in-depth**, not as the primary security boundary.

## 2. v1 Skill scope

### Entry Skills

- `sample-clickhouse`
- `sample-mysql`
- `sample-metrics`
- `sample-cloud`
- `sample-trace`
- `sample-compare`
- `sample-diagnosis`

### Dependency-only

- `sample-source`

### Deferred

- `sample-deferred`

`sample-deferred` is deferred by product decision and remains outside v1. The independent File MCP kubeconfig credential issue must also be remediated before it is reconsidered.

## 3. MCP surface

v1 adds four generic tools:

- `local_skill_info`
- `begin_local_skill`
- `read_skill_file`
- `run_skill_script`

There is no `run_local_skill` in v1. Dependency reads are handled through `read_skill_file` under the active `skill_run_id`.

## 4. Skill run model

`begin_local_skill`:

1. validates that the requested Skill is an allowed Entry Skill;
2. validates audit freshness;
3. creates a `skill_run_id`;
4. loads the Skill instructions;
5. applies the v1 InstructionOverlay;
6. returns discoverable references/schemas, allowed scripts, allowed dependencies, and disabled workflows.

The top-level execution mode is fixed to Web mode for v1.

## 5. Dependency rules

Dependencies are explicitly allowlisted per Entry Skill. "Same trusted root" alone is not sufficient.

Gateway security constraints override all Skill instructions.

Entry Skill interaction/confirmation rules may override dependency Skill interaction/confirmation rules.

Dependency Skill data rules remain effective and cannot be overridden by an Entry Skill.

If a dependency is unavailable or audit-stale, unavailability propagates to every Entry Skill that depends on it before execution begins.

## 6. InstructionOverlay

The overlay applies whenever an Entry or dependency `SKILL.md` is returned.

It communicates the execution environment, including:

- database access is read-only;
- schema synchronization workflows are unavailable;
- operational/system-schema diagnostics are unavailable where prohibited;
- Bash script execution must use `run_skill_script`;
- arguments are passed as argv arrays;
- Windows/PowerShell execution instructions are ignored in Web mode;
- an unknown MySQL table should be inspected with `SHOW COLUMNS` or `DESCRIBE`, not inferred from external repositories;
- `sample-metrics` should add `business_namespace="sample"` before execution; this remains instruction-level guidance rather than a hard PromQL security gate;
- any Skill-specific disabled workflows from the runtime compatibility policy.

## 7. Path normalization

Skill paths may be expressed by Skill instructions in different absolute/relative forms. Gateway normalizes them to:

`skill name + relative path`

Absolute local paths returned to Web are rewritten with `$SKILL_ROOT`.

All reads and executions must remain inside the audited Skill root/Skill directory. Reject:

- `..`
- absolute caller-controlled paths
- symlink escape
- hidden/blocked paths
- `scripts/__pycache__`
- arbitrary local paths outside declared File MCP dependencies

Scripts are executable through `run_skill_script` but their source is not readable by default.

## 8. SkillArgValidator

Validation happens before hooks or script execution.

Global rules:

- omitted optional argument may use an audited default;
- explicit empty string is rejected;
- NUL/control characters are rejected;
- excessive length is rejected;
- enum values are exact;
- extra arguments are rejected unless explicitly declared;
- unknown command names are rejected instead of falling through to script help/default behavior.

### sample-clickhouse

`ck_query.sh`:

- argv[0]: non-empty SQL;
- argv[1]: optional instance, default only when omitted;
- allowed instances: `sample-primary`, `sample-secondary`, `sample-third`.

### sample-mysql

`mysql_query.sh`:

- argv[0]: non-empty SQL;
- argv[1]: optional format;
- allowed formats: `pretty`, `csv`.

### sample-metrics

`collect_prom.sh`:

- PromQL: non-empty;
- offset_minutes: positive integer, default 30, v1 policy max 1440;
- step_seconds: positive integer, default 60;
- `offset_minutes * 60 / step_seconds <= 11000`.

The 1440 maximum and 11000 point limit are v1 policy decisions, not claims about the source script.

### sample-trace

`query_trace.sh`:

- trace_id: non-empty;
- `--limit`: 1..500;
- `--max-field-chars`: 100..100000.

### sample-cloud

All command names are exact enums.

DigitalOcean path-bearing IDs:

- droplet ID: `^[0-9]+$`;
- Kubernetes cluster ID: UUID;
- load balancer ID: UUID.

Linode path-bearing IDs:

- instance ID: `^[0-9]+$`;
- NodeBalancer ID: `^[0-9]+$`;
- LKE cluster ID: `^[0-9]+$`;
- LKE pool ID: `^[0-9]+$` when supplied.

DigitalOcean monitoring metric is one of:

- `cpu`
- `memory`
- `disk`
- `bandwidth_out`
- `bandwidth_in`

Free-text search/pattern arguments are length bounded and reject NUL/control characters. Tag/region/slug arguments use the exact patterns recorded in `skill-compatibility.json`.

## 9. SqlPolicyGate

SqlPolicyGate is the primary database safety boundary.

Processing order:

1. require a single statement;
2. unwrap ordinary `EXPLAIN`;
3. reject `EXPLAIN ANALYZE`;
4. validate statement class;
5. perform token-aware side-effect scan;
6. enforce system-schema policy;
7. enforce SHOW subtype policy;
8. reject dangerous/external table functions;
9. enforce QueryScopeGate.

The token scan:

- works on tokens/whole words;
- ignores comments and string literals;
- does not treat a keyword immediately followed by `(` as a write statement keyword;
- therefore normal functions such as `replace(...)` / `replaceAll(...)` remain usable.

## 10. Read-only SQL policy

Allowed top-level forms:

- `SELECT`
- `WITH`
- `SHOW`
- `DESC`
- `DESCRIBE`
- ordinary `EXPLAIN`

Write/side-effect forms remain rejected, including write statements hidden behind `WITH` or `EXPLAIN`.

ClickHouse table/external functions rejected in v1 include:

- `url(`
- `s3(`
- `file(`
- `merge(`
- `cluster(`
- `clusterAllReplicas(`

`INTO OUTFILE` is rejected.

## 11. SHOW policy

v1 allowlist:

- `SHOW TABLES`
- `SHOW CREATE TABLE`
- `SHOW COLUMNS`

Other SHOW forms are rejected, including process/config/account diagnostics.

## 12. System schema policy

MySQL deny:

- `information_schema.*`
- `performance_schema.*`
- `mysql.*`
- `sys.*`

ClickHouse deny:

- `system.*`
- `INFORMATION_SCHEMA.*`

## 13. QueryScopeGate

Gateway physically enforces only:

- `*_realtime` <= 2 hours;
- `*_small` <= 24 hours.

The 30-day `_data/_day` guidance and 7-day other-table guidance remain Skill instructions, not Gateway enforcement.

### realtime rules

A realtime query must be provably safe. Otherwise reject.

v1 requires:

- table exists in audited schema mapping;
- correct audited time column is used;
- single-table query;
- no CTE/JOIN/UNION/subquery;
- time predicate is a top-level WHERE/PREWHERE AND-connected condition;
- OR makes scope unprovable and is rejected;
- relative lower bound may omit explicit upper bound, with current time as upper bound;
- absolute ranges require constant lower and upper bounds;
- proven duration must not exceed 2 hours.

Supported expression forms are recorded in test fixtures. Unsupported function-wrapped/dynamic expressions are rejected rather than guessed.

For `sample_api_tracking_realtime`, v1 uses `time` as a **policy decision**, not a source-code fact.

### small rules

Phase 0 found no audited `_small` schemas. Therefore all `_small` queries are rejected in v1 until an audited schema/time-column mapping exists.

## 14. ExistingHookRunner

Hooks remain a second defensive layer:

`SkillArgValidator -> SqlPolicyGate -> ExistingHookRunner -> SkillScriptExecutor`

`hooks.json` is the source of truth for the hook set.

Gateway maps hook script names to `<codeagent-root>/hooks/<name>.sh`; it does not execute the embedded `git rev-parse` shell text from `hooks.json`.

### hook result protocol

Only two outcomes are valid:

- exit 0 + empty stdout => allow;
- exit 2 + valid JSON with `hookSpecificOutput.permissionDecision == "deny"` => deny.

Every other exit/stdout combination is a hook error and execution is denied.

### startup self-test

Every hook listed in `hooks.json`, including hooks not otherwise used by v1 Skills, must have both:

- must-allow vector;
- must-deny vector.

The self-test and runtime use the same argv-to-command builder.

A missing policy vector, hook timeout/error, `hooks.json` hash mismatch, or enabled hook script hash mismatch disables the entire Local Skill Bridge.

## 15. Audit freshness

Audited code facts bind to sha256 hashes in `skill-compatibility.json`.

A changed audited Skill file disables that Skill with:

`skill_audit_stale`

Unavailability propagates to dependent Entry Skills.

Common hook manifest/script staleness disables the entire bridge.

Policy decisions are explicitly marked as policy decisions and are not misrepresented as facts derived from Skill source code.

## 16. SkillScriptExecutor

- only audited allowed scripts are executable;
- no generic shell tool is introduced;
- cwd is the Gateway artifact directory for the active Skill run;
- stdin is disabled;
- environment is allowlisted/minimized;
- `PYTHONDONTWRITEBYTECODE=1`;
- execution has timeout/process-group cancellation;
- stdout/stderr are bounded and sanitized.

Schema synchronization scripts are not allowed in v1.

## 17. Skill-specific v1 disabled workflows

At minimum:

- sample-clickhouse: schema sync;
- sample-mysql: writes, schema sync, system/operational diagnostics;
- sample-trace: image download and visual review;
- sample-cloud: cloud writes;
- sample-source: execution (read/search dependency only).

## 18. Output boundary

All Skill instructions/references/schema content and script output returned to Web pass through the Gateway sanitizer.

Sanitizer remains best-effort credential/path protection, not complete DLP.

Large/raw business results should be bounded and summarized when possible.

## 19. Runtime policy and regression sources

Runtime trust policy lives outside the selected Gateway project, by default in `~/.config/mac-file-gateway/local-skill-policy/`. Public format examples only:

- `samples/local-skill-policy/skill-compatibility.json`
- `samples/local-skill-policy/hook-selftests.json`

Regression-only test vectors live in:

- `tests/fixtures/skill-rejections.json`

The audit report does not duplicate these facts:

- `docs/PHASE0_LOCAL_SKILL_AUDIT.md`

## 20. Non-goals

v1 does not include:

- Local/Cursor mode;
- automatic Web -> Local -> Web handoff;
- modification of `agent-runtime/skills`;
- generic shell execution;
- dynamic mode routing;
- automatic Skill mutation;
- arbitrary dependency access;
- direct SSH/K8s Skill exposure;
- `sample-deferred`.

## 21. Implementation order after Phase 0

1. Config + audit hash validation + HookSelfTest
2. SkillRegistry + dependency availability propagation
3. SkillRun
4. PathNormalizer
5. SkillReader + InstructionOverlay
6. SkillArgValidator
7. SqlPolicyGate
   - ReadOnlyGate
   - QueryScopeGate
   - SystemSchemaGate
   - ShowGate
   - ExplainGate
8. ExistingHookRunner
9. SkillScriptExecutor
10. Sanitizer
11. MCP adapter
12. integration/rejection tests
