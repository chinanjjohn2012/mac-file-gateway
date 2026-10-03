# Local Skill Bridge v1 — Implementation Plan

Status: **implemented on release/ms1; release validation remains partial**

Current branch: `release/ms1`

Original implementation branch: `feature/local-skill-bridge-v1`

Status reviewed: 2026-10-02, against `3a330d6f512be9fd39b3d19e8fb43a8a056189b4`

This document records the implementation phases for the frozen v1 spec in `docs/2026-10-01-local-skill-bridge.md`. Public names and paths in this document are synthetic examples. Real audit policy lives in a private local directory selected by `--local-skill-policy-dir`; `samples/local-skill-policy/` contains format examples only. Regression-only rejection vectors remain under `tests/fixtures/`.

Privacy migration: runtime policy is now selected from a private local directory; executable handlers use explicit `kind` metadata. Public policy and rejection tests use synthetic business identifiers. The migration suite passes with **502 tests** and HTTP smoke on Linux/Python 3.12; real macOS tree verification still requires the installed private policy. The original Phase 0 audit baseline has been retained separately, outside the public checkout.

## Current phase status

“Implemented” below means the component and its runtime wiring exist; it does not certify every original acceptance item or production readiness. The phase bodies retain the original design requirements and acceptance gates for comparison.

| Phase | Current status | Code/test evidence and limits |
|---|---|---|
| 0 — Compatibility audit | Closed | `docs/PHASE0_LOCAL_SKILL_AUDIT.md`; real trust policy is private; public policy examples are synthetic. |
| 1 — Config / audit / HookSelfTest | Implemented | `config.py`, `hooks.py`, CLI opt-in; config and hook tests cover strict JSON, stale hashes, allow/deny, malformed output and timeout. |
| 2 — Registry / dependencies | Implemented | `registry.py`; registry tests cover the seven Entries, dependency-only/DEFER rejection and availability propagation. |
| 3 — SkillRun | Implemented | `runs.py`; registry tests cover frozen dependency scope, bounded eviction and refreshed availability. |
| 4 — PathNormalizer | Implemented | `paths.py`; path tests cover legacy forms and rejection vectors; reader uses Gateway safe snapshots. |
| 5 — Reader / overlay | Implemented | `reader.py`; reader tests cover inventories, dependency overlays, script-source rejection, stale reads and sanitization. |
| 6 — Argument validation | Implemented | `args.py`; argument tests exercise policy defaults, infra identifiers, bounds and fixture vectors. |
| 7 — SQL policy | Implemented with v1 constraints | `sql_policy.py`, `sql_lexer.py`, `sql_scope.py`; SQL fixture and regression tests exist. Audited realtime ranges are limited to 2h; `_small` queries remain denied without audited mapping. |
| 8 — Runtime hooks | Implemented | Executor calls hooks after argument/SQL checks; hook tests cover runtime deny and freshness. Hook tests use temporary hooks/policies, not the real macOS hooks. |
| 9 — Script executor | Implemented | `executor.py`; tests execute temporary scripts and cover artifact cwd, closed stdin, no bytecode, unchanged demo source tree, timeout and bounded/redacted output. This is not a real `sample-trace` source-integrity or live-service test. |
| 10 — Sanitizer | Implemented | `sanitize.py`, shared reader/executor/Bridge output handling; reader/executor tests cover root and credential redaction. |
| 11 — Bridge / MCP | Implemented and wired | `bridge.py`, `mcp_adapter.py`, CLI and HTTP wiring. Four opt-in tools are registered; `run_skill_script` invokes `bridge.run` and the dedicated executor. MCP tests cover registration/no generic shell; Bridge tests exercise begin/read/run with a temporary Skill tree. No Local Skill REST endpoints were added. |
| 12 — Integration / rejection / release tests | Partially validated | Fake-tree integration and argument/SQL/path fixture tests exist. Registry rejection tests are explicit rather than driven by the registry fixture cases. `tools/check_local_skill_bridge.py` provides the opt-in real-tree check; real-tree/macOS and live DB/API validation are not established by these tests. |

Verification on 2026-10-02 (Linux, Python 3.12): `bash verify.sh --require-mcp` passed: official MCP SDK import, compileall, **490 pytest tests** (one dependency deprecation warning), and the real HTTP listener smoke test. The HTTP smoke result reports `mcp_verified: false`; it does not establish an end-to-end Tunnel/MCP client session. The real-tree checker and live external queries were not run.

Local Skill Bridge remains disabled unless `--local-skill-root` is supplied. A configured Bridge exposes diagnostic info even when safety initialization disables execution. `sample-source` is dependency-only; `sample-deferred`, `sample-ssh` and `sample-kubernetes` are not enabled as v1 executable Entries. PromQL namespace scoping remains instruction guidance, not a hard gate.

## 1. Implementation principles

1. Do not modify `agent-runtime`.
2. Do not reuse the existing general `CommandRunner` as the Skill script executor.
   - Existing `CommandRunner` is for allowlisted pytest/python/go commands under `--allow-exec`.
   - Local Skill execution has different controls: audited script allowlists, Skill-specific argv validation, SQL policy, hook checks, artifact cwd, and source-hash freshness.
3. Keep the existing File Gateway behavior unchanged when Local Skill Bridge is not configured.
4. Local Skill Bridge is opt-in.
5. Web mode only.
6. No generic shell/exec tool is added.
7. Runtime security checks must be deterministic and fail closed.
8. The selected private `skill-compatibility.json` is the runtime audit/config source; public samples are never a fallback.
9. The matching private `hook-selftests.json` is the runtime hook self-test source.
10. `tests/fixtures/skill-rejections.json` is test input only, not runtime configuration.

## 2. Implemented source layout

The package exists on `release/ms1`:

```text
gateway/
  local_skills/
    __init__.py
    config.py
    registry.py
    runs.py
    paths.py
    reader.py
    args.py
    sql_policy.py
    sql_lexer.py
    sql_scope.py
    hooks.py
    executor.py
    sanitize.py
    bridge.py
```

Existing Local Skill test files:

```text
tests/
  test_local_skill_config.py
  test_local_skill_registry.py
  test_local_skill_paths.py
  test_local_skill_reader.py
  test_local_skill_args.py
  test_local_skill_sql_policy.py
  test_local_skill_hooks.py
  test_local_skill_executor.py
  test_local_skill_bridge.py
  test_local_skill_mcp.py
```

Do not put Local Skill Bridge logic into `gateway/core.py` beyond any small shared helper extraction that is demonstrably reusable.

## 3. CLI/configuration

### 3.1 New CLI flag

Add to `gateway/__main__.py`:

```text
--local-skill-root <project-relative-path>
```

Example:

```bash
bash run.sh /path/to/project \
  --local-skill-root agent-runtime
```

Rules:

- absent => Local Skill Bridge disabled and Local Skill MCP tools are not registered;
- value is project-relative, never absolute;
- value must resolve through the Gateway's existing safe project-root path model;
- expected layout:
  - `<local-skill-root>/skills/`
  - `<local-skill-root>/hooks.json`
  - `<local-skill-root>/hooks/`
- no path is returned to Web as an absolute filesystem path.

Do not require `--allow-exec`. Skill execution is a separate capability with its own fixed allowlist and safety gates.

### 3.2 Private policy location

`--local-skill-policy-dir` selects a local directory containing `skill-compatibility.json` and `hook-selftests.json`. Without the flag, the default is `~/.config/mac-file-gateway/local-skill-policy/`. The directory must be outside the Gateway project scope. It is chosen by the local startup operator, not by Skill content or an MCP tool.

Public examples live under `samples/local-skill-policy/`. They use invented names and placeholder hashes and are not loaded automatically. Every executable Skill declares a supported `kind`; SQL/runtime dispatch does not depend on a business Skill name. Missing policy and unapproved draft policy fail closed.

`tools/collect_local_skill_policy.py` writes a new private draft directory and preserves permission decisions. After manual review, mark both files approved, validate with `tools/check_local_skill_bridge.py --local-skill-policy-dir ...`, and restart Gateway using the reviewed directory.

### 3.3 Startup states

```text
not_configured
enabled
disabled
```

If `--local-skill-root` is absent:

- bridge object is not created;
- four Local Skill MCP tools are not exposed.

If configured but a common safety dependency fails:

- Gateway itself still starts;
- Local Skill Bridge state becomes `disabled`;
- `local_skill_info` remains callable and reports a sanitized failure code;
- `begin_local_skill`, `read_skill_file`, and `run_skill_script` reject with `skill_bridge_unavailable`.

Common safety failures include:

- malformed/unsupported policy schema;
- `hooks.json` hash mismatch;
- enabled hook hash mismatch;
- hook self-test failure;
- required common bridge configuration unavailable.

## 4. Phase 1 — Config, audit freshness, HookSelfTest

### 4.1 Files

Create:

- `gateway/local_skills/config.py`
- `gateway/local_skills/hooks.py`

Modify:

- `gateway/__main__.py`

Tests:

- `tests/test_local_skill_config.py`
- `tests/test_local_skill_hooks.py`

### 4.2 Config loader

`config.py` responsibilities:

- load JSON with strict UTF-8;
- reject duplicate JSON keys;
- require `schema_version == 1`;
- load compatibility policy;
- load hook self-test policy;
- validate structural fields needed by runtime;
- distinguish:
  - code facts/evidence;
  - policy decisions;
- never accept configuration from Skill content.

The compatibility policy is data, not executable instruction.

### 4.3 Audit hash validation

For every active v1 Entry/dependency Skill:

- validate every evidence entry with `kind == "code_fact"`;
- compute SHA-256 from raw bytes;
- compare with policy;
- mismatch marks that Skill `skill_audit_stale`.

Do not make a stale individual Skill disable the whole Gateway or whole Bridge.

Dependency propagation is implemented in Phase 2.

Common hook hashes are different:

- `hooks.json` mismatch => Bridge disabled;
- any hook script mismatch => Bridge disabled.

### 4.4 Freshness timing

Perform a full validation at Bridge startup.

Also revalidate relevant executable/read-critical evidence before:

- `begin_local_skill`;
- `run_skill_script`.

This closes the gap where `agent-runtime` changes after Gateway startup.

A stale result updates in-memory availability immediately and fails closed.

### 4.5 Hook manifest parsing

`hooks.json` is the source of truth.

Parser accepts only the frozen v1 manifest shape needed for `preToolUse`.

For each hook command:

- extract the script basename from the configured command;
- map to `<local-skill-root>/hooks/<basename>`;
- do not execute the embedded `git rev-parse` expression.

Every hook listed in `hooks.json` must have matching self-test data.

Unknown/new hook without vectors => Bridge disabled.

### 4.6 Shared command builder

Implement one function used by both startup self-test and runtime hook invocation:

```python
build_hook_command(script_path, argv) -> str
```

Behavior:

- command is generated from script path + argv using `shlex.join`;
- hook policy vectors store argv arrays, never prejoined command strings;
- no shell evaluation occurs in Gateway.

### 4.7 Hook invocation contract

Input to hook stdin:

```json
{"tool_input":{"command":"<generated-command>"}}
```

Valid hook outcomes only:

```text
exit 0 + stdout == ""            => allow
exit 2 + valid deny JSON         => deny
everything else                  => error
```

Deny JSON must contain:

```text
hookSpecificOutput.permissionDecision == "deny"
```

Timeout/crash/malformed stdout => error.

Startup self-test error => Bridge disabled.

Runtime hook error => current Skill execution denied.

### 4.8 Phase 1 acceptance gate

Tests must prove:

- malformed policy rejects;
- duplicate JSON keys reject;
- unsupported schema version rejects;
- stale Skill hash marks only the Skill unavailable;
- stale `hooks.json` disables Bridge;
- stale hook script disables Bridge;
- every manifest hook requires allow + deny vectors;
- must-allow vector really allows;
- must-deny vector really denies;
- malformed hook output fails closed;
- hook timeout fails closed;
- quoting containing single quotes is identical between self-test and runtime builder.

Phase 1 originally excluded MCP registration; the four tools are now implemented and wired by Phase 11.

## 5. Phase 2 — SkillRegistry and dependency availability

### 5.1 Files

Create:

- `gateway/local_skills/registry.py`

Tests:

- `tests/test_local_skill_registry.py`

### 5.2 Registry model

Build immutable runtime records from `skill-compatibility.json`:

```text
SkillRecord
  name
  role
  disposition
  allowed_scripts
  disabled_workflows
  dependencies
  evidence
  argv_policy
  instruction_overlay
  availability
```

Only:

```text
role == entry
disposition == PASS_WITH_CONSTRAINTS or PASS
```

may be started directly.

`sample-source` remains dependency-only.

`sample-deferred` remains unavailable/DEFER.

### 5.3 Dependency propagation

After direct freshness validation:

```text
dependency unavailable
=> all Entries that depend on it unavailable
```

Do this before any Skill run begins.

Examples:

- stale `sample-mysql` => `sample-diagnosis` unavailable;
- stale `sample-clickhouse` => `sample-compare` and `sample-diagnosis` unavailable.

Return sanitized availability reason codes, not local paths.

### 5.4 Phase 2 acceptance gate

Tests prove:

- Entry list exactly matches fixture;
- dependency-only Skill cannot begin directly;
- DEFER Skill cannot begin;
- unknown Skill rejects;
- unavailable dependency propagates transitively;
- unrelated Skill remains available;
- allowed dependency access is exact, not same-root implicit trust.

## 6. Phase 3 — SkillRun

### 6.1 Files

Create:

- `gateway/local_skills/runs.py`

Tests:

- add to `tests/test_local_skill_bridge.py`

### 6.2 Run state

A `SkillRun` contains:

```text
skill_run_id
entry_skill
accessible_skills
allowed_scripts
created_at
```

Use unpredictable IDs generated locally.

The active dependency set is frozen when the run is created.

A later stale audit check can invalidate execution even if the run was previously created.

v1 is single-user local MCP; no separate principal/auth model is introduced inside SkillRun.

### 6.3 Bounded storage

Keep runs in memory only.

Use a bounded registry so abandoned runs cannot grow memory without limit.

Implementation target:

- max 256 live runs;
- oldest run evicted when limit is reached.

This is an implementation resource bound, not a security authorization mechanism.

### 6.4 Phase 3 acceptance gate

Tests prove:

- new run IDs are unique;
- dependency set comes only from registry;
- caller cannot add dependencies;
- unknown/evicted run rejects;
- stale Skill discovered after run creation still prevents later read/execute.

## 7. Phase 4 — PathNormalizer

### 7.1 Files

Create:

- `gateway/local_skills/paths.py`

Tests:

- `tests/test_local_skill_paths.py`

### 7.2 Accepted source forms

Normalize Skill-authored path forms to:

```text
(skill_name, relative_path)
```

Support the frozen compatibility forms:

- `<rel>` for current Skill;
- `../<skill>/<rel>`;
- `${LOCAL_SKILL_AGENT_DIR}/skills/<skill>/<rel>`;
- `service-a/.cursor/skills/<skill>/<rel>`;
- `<repo>/agent-runtime/skills/<skill>/<rel>`;
- `$SKILL_ROOT/<skill>/<rel>`.

The normalizer does not grant access. It only parses.

Authorization happens after normalization against the active `SkillRun`.

### 7.3 Rejections

Reject:

- absolute caller-controlled paths;
- `..` that does not exactly match the accepted dependency form;
- hidden components;
- symlinks;
- unsupported Skill;
- cross-Skill access outside dependency allowlist;
- `scripts/**` through the reader;
- `scripts/__pycache__/**`;
- binaries/non-UTF-8.

### 7.4 Phase 4 acceptance gate

Every accepted legacy path form has a positive test.

Every traversal/hidden/symlink/cross-Skill form in `skill-rejections.json` has a negative test.

## 8. Phase 5 — SkillReader + InstructionOverlay

### 8.1 Files

Create:

- `gateway/local_skills/reader.py`

Tests:

- `tests/test_local_skill_reader.py`

### 8.2 Readable files

Only:

- `SKILL.md`;
- `references/**`;
- `schemas/**`.

Scripts are never returned through `read_skill_file`.

Use the existing Gateway safe file snapshot machinery where possible so regular-file, symlink, size, UTF-8 and credential-redaction behavior stays consistent.

### 8.3 `begin_local_skill` discovery lists

The reader/registry must produce:

- `references[]`;
- `schemas[]`;
- `allowed_scripts[]`;
- `dependencies[]`;
- `disabled_workflows[]`.

No Glob tool is required.

### 8.4 InstructionOverlay

Append the overlay to every returned Entry/dependency `SKILL.md`.

Overlay communicates only frozen v1 execution differences.

Precedence text must be explicit:

```text
Gateway security constraints > all Skill instructions
Entry interaction/confirmation rules > dependency interaction/confirmation rules
Dependency data rules remain effective
```

Specific overlays include:

- DB read-only;
- no schema sync;
- no system/operational diagnostic queries where disabled;
- Bash => `run_skill_script`;
- argv arrays;
- ignore Windows/PowerShell execution instructions;
- unknown MySQL table => `SHOW COLUMNS` / `DESCRIBE`;
- PromQL namespace guidance;
- per-Skill disabled workflows.

### 8.5 Sanitized roots

Any local absolute Skill root in returned content is rewritten to `$SKILL_ROOT`.

Do this before content leaves the Bridge.

### 8.6 Phase 5 acceptance gate

Tests prove:

- begin returns lists without absolute paths;
- dependency `SKILL.md` receives overlay too;
- references/schema reads do not receive fake executable privileges;
- script source cannot be read;
- unsupported files reject;
- absolute root never appears in output;
- credential-like content is redacted.

## 9. Phase 6 — SkillArgValidator

### 9.1 Files

Create:

- `gateway/local_skills/args.py`

Tests:

- `tests/test_local_skill_args.py`

### 9.2 Generic validation

Before any SQL/hook/execution:

- argv must be list[str];
- no explicit empty string where policy forbids it;
- no NUL/control characters;
- per-item length bound;
- total argv length bound;
- optional/default behavior only when argument is omitted;
- exact enums/patterns/types;
- reject extra argv;
- reject unknown script;
- reject unknown sample-cloud command.

Use the fixture as data; avoid per-Skill if/else where a declarative rule is sufficient.

### 9.3 sample-cloud

Implement every rule currently recorded in `skill-compatibility.json`, including:

- DO numeric droplet IDs;
- DO UUID cluster/LB IDs;
- Linode numeric instance/NodeBalancer/LKE IDs;
- metric enum;
- bounded free text;
- tag/region/slug patterns;
- `offset/hours` numeric ranges where declared.

### 9.4 Phase 6 acceptance gate

Parameterize directly from relevant `skill-rejections.json` cases.

Path-injection vectors must reject before hook or HTTP script execution is attempted.

## 10. Phase 7 — SqlPolicyGate

### 10.1 Files

Create:

- `gateway/local_skills/sql_policy.py`

Tests:

- `tests/test_local_skill_sql_policy.py`

### 10.2 No full SQL parser in v1

Implement a small conservative lexer/state machine sufficient to:

- remove/ignore comments;
- recognize quoted strings/identifiers safely;
- split one statement;
- identify whole-word tokens;
- distinguish function calls from statement keywords;
- recognize parenthesis depth needed by scope checks.

Unknown/ambiguous => deny.

### 10.3 Pipeline

```text
single statement
  -> ExplainGate
  -> ReadOnlyGate
  -> token-aware side-effect scan
  -> SystemSchemaGate
  -> ShowGate
  -> table/external function deny
  -> QueryScopeGate
```

### 10.4 ExplainGate

- ordinary `EXPLAIN <statement>` unwraps and the inner statement is fully checked;
- `EXPLAIN ANALYZE` rejects.

### 10.5 ReadOnlyGate

Allowed statement classes:

- SELECT
- WITH
- SHOW
- DESC
- DESCRIBE
- EXPLAIN after unwrap logic

Detect write forms hidden behind `WITH`.

Token-aware scan:

- whole tokens only;
- strings/comments ignored;
- token followed by `(` can be a function call;
- therefore `REPLACE(...)`, `replaceAll(...)` do not trigger write rejection.

### 10.6 ShowGate

Allow only:

- SHOW TABLES
- SHOW CREATE TABLE
- SHOW COLUMNS

Reject every other SHOW subtype.

### 10.7 SystemSchemaGate

Apply frozen MySQL and ClickHouse schema denies case-insensitively after identifier normalization.

### 10.8 Table/external functions

Reject frozen v1 functions, including:

- url
- s3
- file
- merge
- cluster
- clusterAllReplicas

Reject `INTO OUTFILE`.

### 10.9 QueryScopeGate

Only physically enforce:

- `*_realtime <= 2h`;
- `*_small <= 24h`.

For realtime:

- table must exist in audited mapping;
- use audited time column;
- tracking table uses `time` because fixture marks that policy decision;
- only single-table form;
- CTE/JOIN/UNION/subquery reject;
- OR reject;
- top-level WHERE/PREWHERE AND predicates only;
- relative lower bound supports HOUR/MINUTE;
- absolute range requires both constant endpoints;
- unsupported/dynamic expression => `skill_query_scope_unknown`.

Because Phase 0 has zero `_small` schemas, every `_small` query rejects until policy mapping exists.

### 10.10 Phase 7 acceptance gate

Run every SQL case in `skill-rejections.json` as parameterized tests.

Add explicit must-allow tests for:

- REPLACE() function;
- replaceAll()/replaceRegexpAll() where dialect allows lexical recognition;
- strings containing write keywords;
- SHOW COLUMNS;
- DESCRIBE;
- realtime 2h relative range.

No live DB connection is needed for this phase.

## 11. Phase 8 — ExistingHookRunner runtime integration

### 11.1 Files

Extend:

- `gateway/local_skills/hooks.py`

Tests:

- `tests/test_local_skill_hooks.py`

### 11.2 Runtime order

For DB scripts:

```text
SkillArgValidator
-> SqlPolicyGate
-> ExistingHookRunner
-> SkillScriptExecutor
```

For non-DB scripts:

```text
SkillArgValidator
-> ExistingHookRunner
-> SkillScriptExecutor
```

All configured manifest hooks receive the generated command, matching existing hook semantics.

The hook layer is not used to decide whether a script is allowlisted.

### 11.3 Phase 8 acceptance gate

Tests prove:

- primary policy rejects before hooks;
- hook deny blocks an otherwise valid request;
- hook malformed output blocks;
- command quoting matches startup self-test;
- runtime never executes `git rev-parse` from manifest text.

## 12. Phase 9 — SkillScriptExecutor

### 12.1 Files

Create:

- `gateway/local_skills/executor.py`

Tests:

- `tests/test_local_skill_executor.py`

### 12.2 Do not reuse CommandRunner policy

The executor may reuse small bounded-output/redaction helpers after extracting them to a neutral shared utility if useful.

It must not reuse `CommandRunner._validate_command`, because Skill scripts have a separate allowlist model.

### 12.3 Script launch

Execution form:

```python
subprocess.Popen(
    ["bash", audited_script_path, *argv],
    shell=False,
    ...
)
```

Before launch:

- active run permits the Skill;
- Skill permits the script;
- script hash is still audited/current;
- argv passed SkillArgValidator;
- SQL passed SqlPolicyGate when applicable;
- hooks allowed.

### 12.4 Artifact cwd

Use:

```text
~/.local/share/mac-file-gateway/artifacts/<skill_run_id>/
```

Requirements:

- directory mode 0700;
- never execute with cwd in Skill source tree;
- output artifacts cannot modify `agent-runtime/skills`.

### 12.5 Environment

Allow only the frozen minimal set needed by audited scripts:

- HOME
- PATH
- USER
- LANG
- LC_*
- TMPDIR
- SSH_AUTH_SOCK
- LOCAL_SKILL_AGENT_DIR, set by Gateway
- PYTHONDONTWRITEBYTECODE=1

Do not inherit arbitrary credential environment variables.

Audited scripts load their own existing local config files as they do today.

### 12.6 Runtime

- stdin = DEVNULL;
- timeout 1..300 seconds;
- process group/session;
- kill process group on timeout;
- bounded stdout/stderr;
- sanitize before returning;
- `timed_out` is explicit;
- no arbitrary executable;
- no `shell=True`.

### 12.7 Source-tree integrity test

For representative Python execution:

- hash Skill source tree before execution;
- execute;
- hash after;
- assert unchanged.

At minimum cover `sample-trace` bytecode behavior with `PYTHONDONTWRITEBYTECODE=1`.

### 12.8 Phase 9 acceptance gate

Tests prove:

- nonallowlisted script cannot launch;
- schema-sync scripts cannot launch;
- `__pycache__` is not created;
- timeout kills local process group;
- stdin unavailable;
- cwd is artifact directory;
- output is bounded/redacted;
- source Skill hash unchanged.

Live external API/DB calls remain disabled in unit tests.

## 13. Phase 10 — Sanitizer

### 13.1 Files

Create:

- `gateway/local_skills/sanitize.py`

Tests:

- add to reader/executor tests.

### 13.2 Reuse existing credential redaction

Reuse/extract the existing Gateway credential redaction logic rather than creating a second credential scanner.

Local Skill sanitizer adds:

- replace absolute Gateway project root;
- replace absolute codeagent/Skill root;
- replace HOME where exposed;
- replace `~/.agent-config` paths;
- replace SSH key paths;
- bound output.

Do not attempt semantic DLP/business-data classification.

### 13.3 Phase 10 acceptance gate

Tests ensure no absolute project/HOME/Skill root appears in:

- Skill text;
- schema/reference content;
- hook error;
- script stdout/stderr;
- structured Gateway error details.

## 14. Phase 11 — Bridge service + MCP adapter

### 14.1 Files

Create:

- `gateway/local_skills/bridge.py`
- `gateway/local_skills/__init__.py`

Modify:

- `gateway/__main__.py`
- `gateway/mcp_adapter.py`
- `gateway/http.py`

Tests:

- `tests/test_local_skill_bridge.py`
- `tests/test_local_skill_mcp.py`
- extend `tests/test_cli.py`
- extend `tests/test_http.py`

### 14.2 LocalSkillBridge public API

Internal methods mirror the four MCP tools:

```python
bridge.info()
bridge.begin(skill, request)
bridge.read(skill_run_id, skill, path)
bridge.run(skill_run_id, skill, script, argv, timeout_seconds)
```

### 14.3 MCP tools

Register only when `--local-skill-root` is configured:

#### local_skill_info

Read-only.

Returns:

- bridge status;
- Entry Skill names/descriptions;
- availability;
- no absolute paths;
- no credentials/config file contents.

When Bridge safety initialization failed, this tool still returns sanitized disabled status.

#### begin_local_skill

Read-only from MCP annotation perspective; it creates only in-memory run state.

Inputs:

- `skill`;
- `request`.

Returns:

- `skill_run_id`;
- sanitized Entry SKILL.md + overlay;
- references list;
- schemas list;
- allowed scripts;
- dependencies;
- disabled workflows.

#### read_skill_file

Read-only.

Inputs:

- run ID;
- target Skill;
- normalized/legacy path.

Enforces active-run dependency scope.

#### run_skill_script

Execution tool:

- readOnlyHint = false;
- destructiveHint = false for the Gateway itself, but openWorldHint = true because scripts query external systems;
- no `dry_run` option: the Skill script call is the actual bounded operation after policy checks.

Inputs:

- run ID;
- target Skill;
- script;
- argv array;
- timeout seconds.

No general shell string is accepted.

### 14.4 HTTP surface

Do not add REST equivalents for Local Skill tools in v1.

`gateway/http.py` only needs to pass the optional Bridge into `build_mcp`.

This keeps the new capability MCP-only as frozen.

### 14.5 CLI --check

When Local Skill Bridge is configured, `--check` should include only sanitized status:

```json
{
  "local_skill_bridge": {
    "configured": true,
    "status": "enabled"
  }
}
```

or disabled reason code.

No absolute root.

### 14.6 Phase 11 acceptance gate

MCP tests verify:

- exactly four Skill tools appear when configured;
- no Skill tools appear when unconfigured;
- existing File MCP tools remain unchanged;
- begin/read/run schemas are bounded;
- unavailable bridge exposes diagnostic info but denies begin/read/run;
- direct `sample-source` begin rejects;
- `sample-deferred` begin rejects;
- script source cannot be read;
- no general shell tool appears.

## 15. Phase 12 — Integration/rejection/release tests

### 15.1 Fixture-driven tests

`skill-rejections.json` becomes parameterized input for:

- arg validator;
- SQL policy;
- registry/script rejection;
- path normalization/read rejection.

`hook-selftests.json` drives:

- startup self-test;
- hook behavior regression tests.

### 15.2 Fake codeagent tree

Unit/integration tests create a temporary fake layout:

```text
project/
  agent-runtime/
    hooks.json
    hooks/
    skills/
```

Do not require the real production `agent-runtime` tree for normal CI.

Where hash-sensitive tests need production fixture semantics, generate temporary test files and test fixture hashes together.

### 15.3 Real-tree compatibility test

Provide an opt-in local test/verification command that points at the real selected `project/agent-runtime` tree and checks:

- policy hashes current;
- hook self-tests pass;
- all Entry/dependency availability matches expectation;
- no external script query is executed.

This is a compatibility validation, not a live DB/API test.

### 15.4 Existing regression suite

Every phase must continue to pass:

```bash
python -m pytest -q
bash verify.sh --require-mcp
```

Existing File Gateway read/write/exec tests must remain unchanged in behavior.

## 16. Error codes

Use `GatewayError` for a single error transport model.

Add stable Local Skill codes as needed:

```text
skill_bridge_unavailable
skill_not_available
skill_audit_stale
skill_run_not_found
skill_dependency_not_allowed
skill_file_not_allowed
skill_script_not_allowed
skill_arg_not_allowed
skill_sql_not_readonly
skill_system_schema_not_allowed
skill_show_not_allowed
skill_explain_analyze_not_allowed
skill_table_function_not_allowed
skill_query_scope_unknown
skill_query_scope_exceeded
skill_hook_denied
skill_hook_error
skill_execution_failed
skill_result_too_large
```

Messages/details must not include absolute local paths or credentials.

## 17. Original commit/implementation sequence

The following was the planned sequence, not a remaining-work list or a claim that current history uses these exact commit boundaries:

1. `feat: add local skill config and hook self-test`
2. `feat: add audited skill registry and dependency propagation`
3. `feat: add local skill run state and path normalization`
4. `feat: add skill reader and instruction overlay`
5. `feat: add skill argument validation`
6. `feat: add read-only SQL policy gates`
7. `feat: add runtime hook enforcement`
8. `feat: add bounded skill script executor`
9. `feat: add local skill sanitization`
10. `feat: expose local skill MCP tools`
11. `test: add fixture-driven local skill integration coverage`

Do not combine all components into one commit.

## 18. Implementation stop/go gates

These gates remain requirements for future changes; implementation presence alone does not prove that every acceptance item has been tested.

Do not proceed to the next phase if the current phase's focused tests fail.

Especially:

- HookSelfTest must be green before runtime hook integration.
- SkillArgValidator must be green before enabling `sample-cloud`.
- SqlPolicyGate fixture suite must be green before any DB Skill script can execute.
- Source-tree integrity test must be green before `sample-trace` execution is enabled.
- MCP integration must not expose Local Skill tools unless Bridge is explicitly configured.

## 19. Release gate

The implementation is already present on `release/ms1`. Retain these criteria for release validation and future changes; the merge itself does not establish that every criterion passed. In particular, the current review does not verify the real selected `agent-runtime` tree or macOS hook self-tests.

Release criteria:

1. all existing Gateway tests pass;
2. all new Local Skill unit/integration tests pass;
3. real-tree audit compatibility check passes against current `agent-runtime`;
4. all hook startup self-tests pass on macOS;
5. no test writes to `agent-runtime/skills`;
6. Local Skill Bridge remains disabled by default;
7. `sample-deferred`, `sample-ssh`, and `sample-kubernetes` cannot be started or executed;
8. no arbitrary shell/command interface is introduced;
9. outputs contain no absolute project/HOME/Skill source paths;
10. fixture-driven rejection cases all pass.

## 20. Original first implementation target (historical)

The initial Phase 1-only target has been implemented; it is no longer the next step. The original first-commit scope was:

```text
Config loader
+ policy schema validation
+ audit SHA-256 validator
+ hooks.json parser
+ shared shlex command builder
+ HookSelfTest runner
```

That first-commit restriction was sequencing guidance. MCP tools and Skill script execution now exist through Phases 9–11; remaining validation is described above and in the release gate.
