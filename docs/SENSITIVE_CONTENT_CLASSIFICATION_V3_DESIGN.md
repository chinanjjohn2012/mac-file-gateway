# Sensitive Content Classification V3 — Credential Values in Python Source

**Authority:** PR #52 product decision [#6346229197](https://github.com/chinanjjohn2012/mac-file-gateway/pull/52#issuecomment-6346229197).
**Design status:** DESIGN_FIX_READY after independent [Review #5618129565](https://github.com/chinanjjohn2012/mac-file-gateway/pull/52#pullrequestreview-5618129565); three P2 contracts updated but Standards/Spec design re-review is NOT YET PASS.
**Baseline at design start:** Base `d3373649b968f23c85b3ee09d8e984eefecea5c3`; PR Head `64e43f72d597001054e4d1dbecc0e62a3d9452cc`.
**Scope:** exact canonical suffix `.py` or `.pyi` only. Do not treat this document as implemented behavior.

## 1. Product contract / problem

The gateway protects **credential material actually present in source bytes**, not names of variables that could contain credentials at runtime. A Python assignment to a variable named `token`, `password`, `secret`, or `api_key` must NOT be classified as sensitive solely because of that name or because its right-hand side is a function call or reference.

Examples which MUST remain visible, searchable and editable (assuming normal path/write permission):

```python
token = active.set(value)
token = vault.set(value)
token = get_token()
password = config.password
api_key = os.getenv("API_KEY")
token = None
```

No ContextVar type/provenance proof is required. Whether `active` is a genuine ContextVar, `FakeVar`, or an arbitrary object is irrelevant. The gateway does not execute project code and cannot know whether a runtime call returns a secret.

The following remain protected independently of Python variable naming:

- Hard-coded nonempty credential string/bytes literals in a credential-value position.
- Recognized credential formats (existing `TOKEN_VALUE` including `sk-`, `gh[pousr]_`, `AKIA` patterns), credential-bearing authentication URIs, and PEM private-key blocks.
- Already protected absolute paths and sensitive/hidden filesystem paths.
- All existing non-Python rules, including JSON/YAML key/value protection and protected filename/path rules.

This is a static source-data guard, **not** general runtime secret discovery or full DLP.

## 2. Explicit compatibility boundary

1. Dispatch from **canonical path + complete original raw file bytes**, once per snapshot/candidate. Only exact `.py`/`.pyi` files use V3 value classification. Other extensions, extensionless files and files such as `.PY` continue on the existing V2/legacy path until a separate review. The extension decision is not based on a request fragment or the user-supplied display filename.
2. For read/search/diff, classify the same complete snapshot bytes as guarded create/replace/write. `replace_text` fragments are syntax/size/placeholder validated only; sensitive checks run on the **whole updated candidate**. Do not scan fragments as standalone assignments.
3. Classification returns per-physical-line findings with ordered severity `hard > heuristic > none`; at most one effective severity per line. Multiple reasons remain internally unioned without logging raw values. Existing API shapes, hashes and error `sensitive_content` remain compatible; diagnostics may add a nonsecret `rule_id` and line number.
4. No implicit relaxation of JSON/YAML/config/other-language detection, path controls, hidden-file authorization, repository/Git/exec permissions, backup behavior or audit. All existing grants stay opt-in.
5. Until approved code lands, `docs/SENSITIVE_CONTENT_POLICY.md` continues to describe currently deployed V2 behavior; this V3 document is the normative **future design**, not a claim of deployed protection.

## 3. Evidence model and precedence

### 3.1 Hard — always protected, including during Audit

Independent of Python grammar:
- A recognized token/key format anywhere in text (including strings, comments or literals), including a known-format token assembled from adjacent Python string/bytes constants or literal-only `+` concatenation (§3.3), **even without a credential-named field**. No arbitrary source evaluation.
- A credential URI with embedded userinfo password or other existing authentication-URI pattern.
- A PEM `BEGIN ... PRIVATE KEY` through `END ... PRIVATE KEY`, including an unterminated block until EOF.
- Any exact preconfigured protected absolute path matching current component-boundary logic; likewise the established filesystem path/hidden-name denial rules.
- A **nonempty** Python `str`/`bytes` literal or literal-bearing value **associated with a credential field**, per §3.2–3.4.

A literal need not be proven valid, live or high-entropy. `api_key = "abc"` and `password = b"literal"` are protected, as specified by the user's product decision. Empty `""`/`b""`, `None`, `True` and `False` are not credential literals merely because a name contains `token`.

### 3.2 Credential-value positions (grammar, not incidental text)

Use the existing credential-name family as the authoritative named-field vocabulary: `api_key`, `access_key`, `secret_key`, `client_secret`, `password`, `passwd`, `token`, `access_token`, `refresh_token`, `auth_token`, `authorization`, `database_url`, `client_key_data`, `client_certificate_data`, `certificate_authority_data`; preserve current normalization of underscores/hyphens/case where applicable, but do not treat arbitrary substring matches as a credential field.

Recognized Python value positions:
- Target of `Assign`, `AnnAssign`, and `NamedExpr` (including `config.password` / `self.token` only as an actual assignment target).
- Constant-string keys in dictionary literal entries, e.g. `{"api_key": "abc"}`.
- Explicit keyword argument values, e.g. `request(password="abc")` (only the matching keyword, not all arguments).
- **Function parameter defaults** of `FunctionDef`, `AsyncFunctionDef`, and `Lambda`: pair `arguments.defaults` from the right with the combined `posonlyargs + args`; pair `arguments.kw_defaults` positionally with `kwonlyargs` (a `None` AST slot means no default). Only a default on a credential-named parameter is a credential-value position. Thus `def connect(api_key="abc"): pass`, `async def send(*, password="secret"): pass`, and `lambda token="abc": token` are **Hard**. A parameter name or annotation without a credential literal is not a finding; `api_key=None` and `token=get_token()` are **none** absent other Hard evidence.
- Literal-bearing values within all the above expressions and defaults, including multiline/parenthesized forms, string/bytes, f-strings and implicit/explicit concatenation. Never execute default expressions; protect their original physical lines and the declaration line when needed to avoid partial disclosure. Findings for nonempty credential-value literals are **Hard** and cannot be Audit-bypassed.

Do **not** classify `token` merely because it appears as a reference, annotation, function name, import alias, comment word, dictionary key with dynamic value, or prose string containing the word. Quoted **lookup keys** are not source credential **values**.

These finite, syntax-recognized environment reference expressions MUST be **none** when the key contains no independent known-secret signature and no other hard evidence:
- `api_key = os.getenv("API_KEY")`
- `api_key = os.environ.get("API_KEY")`
- `api_key = os.environ["API_KEY"]`

The same reference/key distinction applies inside credential-named function defaults and call keyword values. `api_key = os.getenv("API_KEY", "fallback-secret")` and `api_key = os.environ.get("API_KEY", "fallback-secret")` are **Hard** because the nonempty fallback is a candidate credential **value**. A known token signature in even the lookup key is independently **Hard**. Do not generalize these specific reference patterns to an arbitrary call/subscript on an unknown object or infer dynamic runtime values; absent actual credential-value literal evidence, do not revert to name-only assignment blocking.

### 3.3 Literal composition, f-strings and dynamic values

When a credential field has a value built **partly or wholly** from a nonempty source literal that contributes directly to the assigned value, treat the corresponding physical source lines as **Hard**:
- `token = "ab" "cd"` (implicit concatenation).
- `password = ("ab" + "cd")` and `api_key = "prefix" + suffix` (one or more actual contributing literal fragments).
- `token = b"ab" + b"cd"`.
- `token = f"prefix-{runtime}"` (a nonempty literal fragment).
- `token = "secret".encode()` or `token = wrapper("secret")` where a literal supplies the credential field's candidate value. Do not execute `wrapper`; its literal argument is observable evidence.
- Parenthesized, backslash-continued and multi-physical-line forms must not evade the same rule.

For `f"{runtime}"`, `token = get_token()`, `token = str(runtime)`, `token = config.token`, `token = active.set(value)`, `token = os.getenv("API_KEY")`, and comparable **pure runtime references with no credential literal**, return **none** unless an independent hard pattern or protected path is present. AST complexity or a suspicious variable name never by itself reintroduces the old assignment-name heuristic.

The scanner must distinguish environment-variable **lookup keys** and source credential **value literals**, including `os.environ["..."]`. A known-secret signature in an env key always remains Hard; other unreviewed function arguments containing a literal in a credential-value position are conservatively protected, not name-only dynamic calls.

**Split known-format key (P3):** Static, finite adjacent `str`/`bytes` literals and literal-only `Constant + Constant` expressions MUST be assembled for an independent recognized-key-format check without running project code. For example `marker = ("ghp_" "ABCDEFGHIJKLMNOPQRSTUVWX")` and `marker = "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWX"` are **Hard** although `marker` is not a credential field. Support multiline/parenthesized literal-only forms; do not compute arbitrary runtime expressions or guess secret suffixes. Retain the existing signature length and character rules.

This conservatism means a literal prefix such as `token = f"Bearer {value}"` is Hard: an explicit contributing literal exists, even if a human might regard it as scaffolding. A future placeholder/prefix allowlist is out of scope and requires separate review.

### 3.4 Syntax and line ownership

- For syntactically valid Python, identify assignment target/keyword/dictionary context using **only syntax**, not symbol/type/provenance resolution. A Python `tokenize`-based bounded lexical pass and a small, explicit expression/target parser may be used. Do not import/evaluate project modules, call user functions, or invoke the ContextVar Worker.
- Recognize Python string prefixes, escaped quotes, triple strings, bytes and Python 3.12+/3.13 f-string tokenization; decode literals without executing them, and bound decoding/allocations. A string that contains example code is not automatically an AST assignment.
- **Mandatory Hard for explicit credential literals in real Python comments/docstrings.** A lexical `#` comment with an identifiable credential field `=` or `:` followed by a nonempty quoted `str`/`bytes` value (e.g. `# password = "abc"` or `# api_key = "actual-key"`) is **Hard**. The same recognizable field/value literal notation within an actual module/class/function docstring, including triple-quoted/multiline docstrings, is **Hard**. These literal values are source-visible credential material even when not executed; neither may be written under Audit.
- Neither an incidental mention of the word `password` nor an ordinary dynamic expression in a comment is sufficient. `# token = get_token()`, `# what is a password?` and `help_text = "the password variable is documented here"` must be **none** absent independent Hard evidence. A `#` character inside an arbitrary string literal is not a comment, and arbitrary strings containing sample code must not be reinterpreted as live assignments; this rule applies to lexical comment tokens and actual docstrings containing explicit `credential_field = "nonempty literal"` notation.
- Associate all original physical lines containing such comment/docstring credential evidence (and any enclosing delimiter/declaration lines needed to prevent partial leakage); preserve BOM, CRLF and source positions exactly.
- Associate protected material with **all physical lines carrying the original literal/credential evidence** and the relevant assignment/construct when required to avoid partial line leaks. Keep raw line numbering stable across BOM, LF, CRLF and multiline literals. A secret split across lines or adjacent literals cannot disappear by line splitting.
- `Hard` findings union with independent known-key/URI/PEM/path findings; no “ContextVar exemption” (or any exemption inferred from variable type) may remove a Hard mark. If ordinary runtime code appears on the same line as a Hard literal, **Hard wins**.

### 3.5 Heuristic, parser uncertainty and Audit

- The old rule “credential-looking left-hand name + arbitrary RHS” is **removed only for Python**. A dynamic Python expression with no detectable embedded credential literal yields `none`, not `heuristic`, regardless of its name.
- `heuristic` remains available for **observable ambiguous literal-bearing syntax** that cannot be classified exactly without execution (e.g. truncated/malformed composite source with a credential-value literal cue), never a name-only assignment. In `enforce` mode it remains redacted and denied for newly introduced content; within valid scoped `audit` it may be written **without** disabling read/search/diff redaction.
- A tokenizer/decoder unable to finish within the approved input/complexity budget must NOT return `none` for unexamined bytes. Treat `scan_unavailable` as a separate **file-level scanner-integrity failure**, not as a heuristic or a newly inferred credential field. **Temporary Audit MUST NOT bypass it** and cannot turn this result into an allowed write.
- **User-visible fallback:** `read_file` returns generic redaction placeholder text for the **entire unscannable file** (not partially scanned raw text); count the reliably determined physical lines in the existing `redacted_lines` field, or report one file-level redaction if line counting itself is unavailable. `search_files` returns **no matches/snippets from that file**, using the existing skipped/error accounting with bounded nonsecret reason `scan_unavailable`. No preview/diff may disclose unscanned source bytes: `create_file`, `replace_text` and `write_file` **preview and apply** reject with the existing public error code `sensitive_content`, optionally annotated `rule_id=SCAN_UNAVAILABLE`, no raw values or false line numbers. Replacing from an unscannable original source is likewise denied before mutation. Active Audit changes nothing and does not authorize a backup/install.
- Before implementation RED, **freeze** lexical token/line/decoded-literal work, resource/CPU/memory/concurrency budgets and failure accounting in the implementation plan. Compare 32 KiB+ and the actual maximum file-size boundaries on Linux/macOS: ordinary in-limit source must not inherit obsolete ContextVar Worker time/size refusal. Failures must not leak bytes through HTTP/MCP errors, status, logs or partial diff.
- On syntactic parse failure but successful complete lexical scan, retain known secret/URI/PEM/path and evident quoted credential assignments; never silently hide syntax errors by treating arbitrary dynamic assignments as hard. If lexical scanning itself is incomplete, use the fail-closed rule above.
- All findings have bounded count/size; never expose raw credential fragments in logs, errors, traces, statuses or debug metadata.

## 4. Write and visibility invariants (unchanged)

1. `read_file`, `search_files` and redacted diffs show placeholders for all protected lines. Search and replace must never match across, inside or spanning originally hidden content. Multiplicity comparisons cannot “cancel out” new identical secret lines.
2. `create_file`, `replace_text` and `write_file` validate whole new bytes against `classify(canonical_path, bytes)`. Newly introduced **Hard** material is rejected before mutation. Existing protected lines retain exact origin and bytes when replacing visible ranges. Whole-file overwrite of a source containing redacted lines stays prohibited.
3. Atomic install and authorization checks remain under the existing write lock. Original `file_sha256`, expected-hash conflict, backup creation/retention, temporary file cleanup and failure provenance remain unchanged.
4. The Workspace-scoped `write.sensitive_content` Audit policy is **default `enforce`**, explicit, startup-only, path-restricted and max 60 minutes. UTC + monotonic expiry, lock-time and pre-install checks, per-Workspace status/REST/MCP reporting remain unchanged. It relaxes **only `heuristic` writes**, never Hard, protected files/paths, raw credential formats, read-redaction or `scan_unavailable`.
5. Filesystem permissions and protected hidden paths are independent of content classification. No new bypass through rename, path argument or file extension spoofing. Git permissions remain default-denied and unchanged.

## 5. Migration / code-removal design (not yet authorized to implement)

Implementation after independent **design** PASS:

1. Replace Python's `_credential_assignment_is_sensitive` blanket-RHS behavior only in the new path-aware Python branch of `SensitiveContentPolicy.classify`. Preserve existing non-Python classification function and compatibility of public `classify`, `full_flags`, `redact_lines`, `redacted_diff_lines`, `visible_matches`, `preserves_hidden_lines` and `new_sensitive_content` semantics.
2. Implement syntax-aware **literal evidence scanning**, not Python variable/ContextVar identity proof. Prefer a bounded tokenizer and small declarative assignment/value grammar; no arbitrary Python semantic evaluation. Resource exhaustion/error path defined in §3.5.
3. Once all callers and tests are migrated, remove `gateway/contextvar_semantics.py`, `gateway/contextvar_analysis.py`, `gateway/contextvar_worker.py` and their ContextVar-proof-only checks/Worker smoke tests. **Retain** normal ContextVar false-positive and credential-protection business tests, rewriting expectations to this V3 contract; do not delete failed regression tests merely to get GREEN.
4. Update `docs/SENSITIVE_CONTENT_POLICY.md` from current V2 operational behavior to V3 only **after code implements and passes checks**. Synchronize `MANIFEST.sha256` with file additions/deletions.
5. Leave non-Python credential behavior, scoped Audit, Git/exec, HTTP/MCP protocol contracts, lifecycle and path/backup policies untouched.

## 6. Acceptance contracts — RED before implementation, GREEN after

| Test input / context | Python V3 result | Severity |
|---|---|---|
| `token = active.set(value)`, genuine/fake/unknown `.set()` | Visible, searchable, writable | none |
| `token = get_token()`, `password = config.password`, `api_key = os.getenv("API_KEY")` | Visible, searchable, writable | none |
| `token = None`, `token = f"{runtime}"` | Visible, searchable, writable | none |
| `password = "literal"`, `api_key = b"literal"` | Redact; reject new write | hard |
| `{"password": "literal"}`, `request(token="literal")` | Redact; reject new write | hard |
| `token = "ab" + "cd"`, adjacent literals, multiline literals | Redact; reject new write | hard |
| `token = f"prefix-{runtime}"`, `os.getenv("API_KEY", "fallback")` | Redact; reject new write | hard |
| Known key signature, authenticated URI, PEM or protected absolute path anywhere | Redact; reject new write | hard |
| Mixed `token = active.set(value); password = "literal"` | Entire evidence line protected | hard |
| Ambiguous but evident nonempty literal cue | Redact; `audit` may allow eligible write | heuristic |
| Unscannable/over-budget source | Do not return raw content or admit changed write, even in Audit | scan_unavailable |
| JSON/YAML hard-coded credential and heuristic cases | Precisely **unchanged** from pre-V3 | existing |

Required test breadth:
- Source parsing: assignment, annotated/walrus, dict/keyword, nested calls, env-key vs fallback, escaped/bytes/raw/triple/f-string, implicit/explicit concatenation, multi-line, comments/docstrings, malformed source, 32KiB+ and Gateway max-sized files, BOM, CRLF/LF, mixed Hard+ordinary code.
- Flow: create preview/apply, read/redaction, search, diff, exact replacement preview/apply, whole write, hidden-line origin and multiplicity, backup/sha/conflict, Audit active/expired/lock/install deadline, Multi-Workspace isolation, REST/MCP parity.
- Compare JSON/YAML/non-Python output on fixed baseline fixtures **byte-for-byte**, and preserve error semantics and counters. Run RED first, then implementation GREEN, full Linux and GitHub-hosted macOS `verify.sh --require-mcp`, real HTTP/MCP/Git smoke, manifest validation and exact-Head independent Standards/Spec **code** review.
- Existing sporadic macOS CRLF false denial remains separately tracked as P3; hosted macOS tests cannot substitute for user-machine Gateway/Tunnel E2E.

## 7. Independent design-review decision points

**Standards reviewer:** evaluate incomplete/invalid Python lexical fallback, scanner budget and DoS, distinguishing env lookup key vs value literals, UTF-8/BOM/CRLF line provenance, hard secrets in comments/multiline, no unscanned content leaks, no API/permission regression, Audit/Hard isolation and removal of unnecessary Worker.

**Spec reviewer:** run each acceptance row against this precise contract, including source-value vs runtime-reference classification, name-only false-positive elimination, single-line mixed evidence, JSON/YAML unchanged, observed false-positive tradeoff for static `f"Bearer {value}"`, and proper staged gate order.

**Exit criterion:** independent Standards PASS **and** Spec PASS at one fixed design SHA. Until then, NO code migration, removal of old Worker, merge, release, deployment or local Tunnel modification. This supersedes the old ContextVar-provenance **design direction**, not existing deployed runtime behavior.
