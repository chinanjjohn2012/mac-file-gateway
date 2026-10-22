# Sensitive content policy (V2)

Status: implementation in progress. Based on the Standards/Spec approved design against
`d3373649b968f23c85b3ee09d8e984eefecea5c3`.

## Positive static provenance subset (P2-03)

ContextVar exemption is an **opt-in static proof**, not a claim that
arbitrary Python can be security-verified. The parser first checks a
**positive AST grammar** and only then performs the existing stable-binding
and matching set/finally-reset checks. An unsupported construct returns an
empty proof, retaining the original heuristic protection on reads, search,
diff, create, replace and whole-file writes.

The admitted source-local grammar is intentionally limited:

- Explicit imports only from reviewed standard modules
  (\`contextvars\`, \`contextlib\`, \`builtins\`, \`types\`, \`sys\`, \`typing\`)
  and a finite set of exported symbols. No star import, arbitrary third-party
  module, unknown re-export or dynamic import receives an exemption.
- Module-level declarations may include inert string expressions, literal
  or name assignments, a recognized \`ContextVar(...)\` constructor, and
  undecorated class/function definitions that themselves use the checked
  grammar. The only admitted import-time attribute read is a stable
  \`sys.platform\`. Unreviewed module-level calls, dynamic expressions,
  class bases/metaclasses, arbitrary decorators, evaluated annotations and
  default expressions cannot establish trusted provenance.
- A reviewed \`contextlib.contextmanager\` decorator may wrap a function.
  Function statements are limited to passive assignments, simple returns
  or yields, a recognized \`active.set(value)\` and matching
  \`try/finally: active.reset(token)\`. No unknown calls, dynamic control
  flow, arbitrary operators, custom hash/iterator evaluations, or
  reflection are allowed to influence this static proof.
- AST nodes or language versions outside the explicitly recognized grammar
  are rejected conservatively. Failing to prove does **not** authorize
  writes; the original read-redaction and sensitive-write policy apply.

This is a source-local guarantee under ordinary trusted Python standard
library semantics. It does not verify code execution, other processes, or
external monkeypatching at runtime. A complex but legitimate Python module
may be denied this exemption; the operator can use the explicitly scoped,
short-lived heuristic audit policy when its separate authorization and
time constraints permit. The audit path never disables hard credential
blocking, file/path protection or read redaction.

## Detection

The gateway continues to redact sensitive file lines on read, search, and
diff, and reject credential-like content on guarded writes. Python .py files
can use a bounded static ContextVar proof to avoid misclassifying a genuine
ContextVar.set() restoration handle as a credential. Only statically proven
imports, stable module-level bindings and matching try/finally reset calls
qualify. Unknown or syntactically invalid sources fall back to the
conservative heuristic scanner. Dynamic namespace operations such as
`vars()`, `globals()`, first-class aliases of reflective builtins, and
module/frame `__dict__` access cannot prove stable ContextVar binding and
therefore retain the original conservative heuristic. The static analyzer
does not execute any user source or guarantee dynamic Python runtime types.

A stable `import contextvars` spelling is **not** sufficient to establish
module-object identity. The proof fails closed for source-level changes to
module classes (`__class__`) or import implementation attributes,
`sys.modules` access and aliases, `sys.meta_path` / other import-hook
registries, importlib reload/import operations and registry-key mutation
targeting `contextvars`. This is deliberately conservative: the analyzer
cannot safely execute source to decide what an opaque import-cache mapping
refers to. Ordinary `import sys` plus unrelated inspection such as
`sys.platform` does not disable an otherwise proven ContextVar handle.
An imported module namespace is equally unprovable when exposed through an
`ImportFrom` alias: for example `from contextvars import __dict__ as registry`
followed by mutation of `registry["ContextVar"]`. The analyzer examines
the **imported member name**, not merely the local alias or literal key;
`__dict__` and `__builtins__` namespace exports are conservatively
disqualified (including opaque reexports). Importing ordinary symbols
such as `ContextVar` and `Token` continues to support proof.

Imported reflection primitives are classified by their original
`ImportFrom.alias.name`, **before** applying `as` renames, across builtins
and opaque module reexports. The same central list covers direct expression
names, attribute access and imported functions such as `setattr`, `delattr`,
`getattr`, `vars`, `globals`, `locals`, `exec`, `eval`, `compile`
and `__import__`. Star imports (`from module import *`) also disable
provenance exemption because they may overwrite trusted module/constructor
names without an explicit named assignment. Harmless explicit imports
(`from builtins import len`, `str`, `print`) remain eligible; unknown
reflection/namespace sources fail closed without executing project code.


The ContextVar proof also fails closed when source code writes or deletes the
`ContextVar` constructor module attribute or any of its nested members. The
binding inventory includes both explicit assignment and implicit Python
name binding: `match/case` captures (`MatchAs`, `MatchStar`,
`MatchMapping.rest`), exception handler aliases (`except ... as name`),
imports, parameters, and declarations. A constructor import, module alias,
module-level ContextVar variable, or temporary reset handle with an
unproven shadow/rebinding is not exempted. This can conservatively redact
some valid code; it must never promote an unknown `.set()/reset()` pair
into a proven ContextVar.

Python parsing uses a fixed trusted helper program in a separate isolated
interpreter. Input is limited to 32 KiB, 1,024 physical lines, 2,048
characters per line, 4,096 tokens, 256 tokens per logical statement and 32
delimiter nesting levels. Parsing times out after 250 ms. An error, timeout
or ambiguous binding grants no exemption.

## Temporary heuristic audit

The default mode is `enforce`. A trusted local administrator may explicitly
configure a temporary `audit` period, *only* within an already writable
subtree of one workspace. During this period, heuristic findings may be
written, but hard credential findings remain denied. File access checks,
the source-hash guard, full-file write restrictions for redacted sources,
existing hidden-line provenance, backup safeguards and read/search/diff
redaction remain in force.

Multi-workspace `gateway.json`, inside one workspace's `write` object:

```json
{
  "sensitive_content": {
    "mode": "audit",
    "paths": ["src"],
    "expires_at": "2026-10-22T19:30:00+00:00"
  }
}
```

The timestamp is illustrative and is already expired; set a UTC deadline
within the next 60 minutes for a real session. Remove this block or use
`"mode": "enforce"` for normal operation. Config is strict; invalid or
incomplete mode settings cause a startup error.

Legacy CLI mode (with an existing `--allow-write` grant):

```text
--sensitive-content-audit-path src
--sensitive-content-audit-until <UTC_TIMESTAMP>
```

The expiry must include an explicit UTC timezone marker (for example `Z`
or `+00:00`). Naive timestamps and nonzero offsets such as `+09:00`
are rejected, rather than silently converted. Runtime expiration compares
UTC instants, not formatted timestamp strings, and uses an independent
monotonic deadline so moving the system clock backward cannot prolong audit.

In Multi-Workspace mode, `/workspaces`, `/info`, and the MCP tools
`list_workspaces` and `gateway_info` all expose an effective
`sensitive_content` object under **each workspace** with `write_mode`
(`enforce` or `audit`), `read_redaction_enabled`, `expires_at`,
and `audit_scope_count`. This is computed from the live policy, not the
original config: an expired audit automatically reports `enforce`.
The responses do not disclose absolute Workspace or private config paths.

Configuration is applied at startup, not by remote request. `gateway_info`
and `list_workspaces` expose the effective mode and expiry without absolute
filesystem paths or sensitive values. A monotonic and UTC deadline limits
the lifetime; audit authorization is rechecked after acquiring the write
lock and immediately before the atomic file installation. A write already
committed before expiry is not rolled back due to a later parent fsync.

This is a narrow operational escape hatch, not a credential management
workflow. Never intentionally write real credentials through the gateway.
