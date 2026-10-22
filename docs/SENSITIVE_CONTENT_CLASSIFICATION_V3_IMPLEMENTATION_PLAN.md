# V3 Credential-Value Classification — Implementation Plan

**Status:** IMPLEMENTATION_PLAN / RED pending. Independent Standards/Spec DESIGN PASS at GitHub PR #52 [Review #5622005954](https://github.com/chinanjjohn2012/mac-file-gateway/pull/52#pullrequestreview-5622005954), fixed design SHA `4791b32158a94c725f2e20997668388bdc951a6b`.
**Authoritative design:** [SENSITIVE_CONTENT_CLASSIFICATION_V3_DESIGN.md](SENSITIVE_CONTENT_CLASSIFICATION_V3_DESIGN.md).
**Target:** Same Draft PR #52; no merge, release or deployment.
**Scope:** Python exact `.py` and `.pyi`; JSON/YAML/non-Python semantics unchanged.

## Technical boundaries and frozen initial budgets

The full canonical path and original complete UTF-8 bytes are the only classification inputs. No scanning of replacement fragments as if they were independent Python documents. Python source code is **never imported or evaluated**.

Freeze these ceilings before RED, review any adjustment and document measurements: source raw bytes <= 1,048,576 (the existing default Gateway maximum); <= 200,000 tokenize tokens; <= 120,000 physical source lines; <= 150,000 AST nodes; <= 1,048,576 decoded string characters handled per source; <= 512 AST nesting depth; >= 32 KiB ordinary files must remain usable. Parse work must check byte/count limits before AST construction, use iterative AST traversal and a monotonic budget for preparse and scan operations; robust scanner-integrity failure is a separate `scan_unavailable` outcome. No old ContextVar Worker 32 KiB/250 ms cap remains in production.

If AST parsing fails but the bounded lexical scan completes, classify independent known formats and concrete field/value literals conservatively. If the scanner cannot complete or result provenance is unreliable, return a **file-level** `scan_unavailable`, never `none` for unchecked content. Audit can never authorize this failure.

## Work items

**T01 / RED contract:** A new V3 Gateway test suite must show old behavior failing on ordinary `token = get_token()`, `password = config.password`, fake `active.set()`, and `os.environ["API_KEY"]`, including read/search/diff/create/apply/replace/write. Test hard-coded literals in assignments, annotated/walrus, dict/keyword/default parameter positions; docstrings and `# password = "..." ` comments; standalone recognized signatures split across adjacent/plus literals; UTF-8 BOM/LF/CRLF and multiline/fstrings; ordinary JSON/YAML unchanged.

**T02 / Scanner:** Add a dedicated, source-value-only Python classifier using standard-library tokenizer + syntax; protect hard-known token/URI/PEM/protected paths regardless of expression position. No imported project code/ContextVar type/source proofs. Preserve accurate original physical line ownership and reason severity for whole file.

**T03 / Visibility/writes:** Route exact canonical Python suffix only to T02 in `SensitiveContentPolicy.classify`. All read/search/diff and create/replace/whole-write use same full-document classification. Keep non-Python path unchanged. Reject scan-integrity failure for dry-run/apply even with active audit, redact entire file on read, skip its search matches and suppress diff content. Preserve hidden-line provenance, byte identity, raw SHA and source conflict/backup/permission boundaries. Ensure unchanged API output shape, original `sensitive_content` error, optional nonsecret rule diagnostics.

**T04 / Audit and edge cases:** Under valid startup-scoped audit allow only newly introduced `heuristic` content; never Hard/scan-unavailable. Recheck expiry after lock and pre-install. Cover malformed/tokenizer-budget cases, escaped/bytes/triple/f-string and credential-bearing literal fallback to env getters; nested/dynamic string values are not runtime secret detection.

**T05 / Remove obsolete proof code:** Migrate **behavior** tests that previously expected arbitrary Python `.set()` rejection, rather than deleting security tests for green. Remove `contextvar_semantics.py`, `contextvar_analysis.py`, `contextvar_worker.py` and worker-only test requirements after all callers are replaced. ContextVar need not be proven for normal assignment; embedded hard values must still be denied.

**T06 / Verification and independent review:** Update policy document and `MANIFEST.sha256` after source/tests land. Run full Linux/macOS `verify.sh --require-mcp` from one fixed Head, check real HTTP/MCP/Git smoke and raw CI job logs. Publish SHA-bound `FIX_READY` with RED/GREEN evidence only after both green. Request separate independent Standards/Spec CODE review; no merge/deploy; physical Mac/Tunnel acceptance remains separate.

## Review gates

- Gate RED: expected failures for original V2 behavior, after adding tests only.
- Gate GREEN: no behavior-regression weakening, JSON/YAML byte-for-byte parity, full dual-platform CI on fixed Head.
- Gate CODE PASS: independent SHA-bound Standards and Spec verdict, distinct from design PASS.
- Gate local: real user's Mac/Tunnel, only after code review.
