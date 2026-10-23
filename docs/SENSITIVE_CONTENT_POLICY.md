# Sensitive Content Policy — V3 implementation candidate

**Status:** PR #52 V3 independently CODE PASS at pinned Head but remains Draft,
unmerged and undeployed. Path Text Visibility V1 is proposed independently in
Draft PR #61; this document describes that candidate behavior, not a
claim of production deployment. The approved V3 **design** is
[SENSITIVE_CONTENT_CLASSIFICATION_V3_DESIGN.md](SENSITIVE_CONTENT_CLASSIFICATION_V3_DESIGN.md),
independent Standards/Spec DESIGN PASS at Head
`4791b32158a94c725f2e20997668388bdc951a6b`.

## 1. Classification rules

File access controls and sensitive filename/hidden-path permissions apply
**before** content classification and are independent of this policy.
Content is classified using complete original bytes and the canonical path.

For exact Python suffixes `.py` and `.pyi`, source-value evidence determines
whether a line is protected. A bare variable or function name is **not**
credential material. Ordinary code including
`token = active.set(value)`, `token = vault.set(value)`,
`token = get_token()`, `password = config.password`,
`api_key = os.getenv("API_KEY")`,
`api_key = os.environ.get("API_KEY")`, and
`api_key = os.environ["API_KEY"]` is not sensitive solely by those names.
No ContextVar provenance/typing/source Worker is executed or required.

**Hard** findings include:

- Nonempty `str`/`bytes` literals contributing to a named credential
  assignment (including annotated/walrus), dictionary value, call keyword,
  or `def`/`async def`/`lambda` parameter default.
- Composite static literals, string concatenation, literal-bearing
  f-strings, and nested value expressions. A nonempty static fallback
  in `os.getenv("KEY", "fallback")` is a candidate value; the quoted
  lookup key by itself is not. Ordinary dynamic expressions without a
  credential-value literal remain visible even when their variable
  names resemble credential fields.
- Explicit `# password = "abc"` comments and corresponding real Python
  module/class/function docstrings; mere prose mentioning the word
  `password` or `# token = get_token()` is not Hard.
- Independently recognized token/key signatures (`sk-`, GitHub PAT,
  `AKIA`), authenticated URIs, complete or partial PEM private-key
  blocks, and protected absolute paths. Known key signatures reconstructed
  from adjacent or literal-only concatenated constants are Hard even under
  noncredential field names.

Hard source lines are redacted on reads/search/diffs, and newly introduced
Hard content is rejected on create/replace/whole-file write. Hard wins over
heuristic and cannot be allowed by Audit.

For JSON, YAML, other non-Python files, and extensionless source, existing
V2/legacy content rules are retained. This PR does not change them, and
an independent read/seek/REST/MCP regression covers parity.

## 1.1 Ordinary pathname text — V1 amendment

See [Path Text Visibility V1 design](PATH_TEXT_VISIBILITY_V1_DESIGN.md).
A plain path appearing in permitted source content is not secret evidence.
Absolute paths, private/Home/config roots, other Workspace roots, digit-leading
components, and references to protected filenames (`.env`, `.ssh`, keys) are
visible/searchable/writable as **text** unless the same line independently
contains an actual credential value, recognized token/signature,
authenticated URI or private-key content.

This removes only the previous `protected absolute path` **content-match**
rule in Python and non-Python formats. It does **not** grant access to the
path target. Existing root confinement, hidden-file denial, Workspace
authorization, write scopes and symlink safeguards remain unchanged.
Untokenizable Python retains `scan_unavailable` fail-closed behavior; a raw
unquoted malformed path expression is not automatically valid Python.
Construction-time `protected_content_paths`/`protected_paths` arguments remain
accepted but cannot silently reinstate text-only path redaction.

## 2. Scanner-integrity fallback

The Python classifier uses only the Python standard library's bounded
tokenizer and syntax parser. It does not import, evaluate, introspect or call
project source. It checks file size <= 1,048,576 bytes, <= 120,000
physical lines, <= 200,000 tokenize tokens, <= 150,000 AST nodes,
<= 512 AST depth, <= 1,048,576 characters per static literal,
and a 3-second monotonic scan budget. Ordinary > 32 KiB source does not
inherit the removed ContextVar Worker budget.

A complete lexical scan with malformed AST may preserve known signatures,
comments, and evident credential-value literal cues. Ambiguous *actual
literal-bearing* cases can be heuristic; an assignment name with a dynamic
RHS is never a heuristic merely for its name.

When tokenization or a resource constraint prevents a complete
classification, `scan_unavailable` is a distinct **file-level** failure:

- Read: redact the whole file (with original raw `file_sha256`).
- Search: skip the file, report a nonsecret `scan_unavailable` limit reason,
  return no source snippet or match from that file.
- Diff and write preview: never show unscanned bytes.
- Create, replace, whole-file write: refuse both preview and apply with
  `sensitive_content` and optional `rule_id=SCAN_UNAVAILABLE`;
  do not mutate/backup/commit.
- Temporary Audit cannot override scanning-integrity failure.

## 3. Hidden content and guarded writes

The same full-document classification is used by read, search, preview and
writes. An exact replacement may only match visible source ranges, must
preserve hidden lines by original byte provenance, and may not cancel
additional identical hard lines. Whole-file replacement of a source
containing redacted lines is prohibited. Write authorization, write locks,
raw-file SHA conflicts, original backups, atomic installation and fsync
failure semantics are unchanged. Redacted/truncated display placeholders
are never valid write content.

## 4. Temporary heuristic Audit (unchanged)

Default is `enforce`. A trusted local administrator can explicitly enable
`audit` **at startup** for already-writable paths in one Workspace, expiring
within at most 60 minutes. It only allows writes whose new findings are
**heuristic**, not Hard or `scan_unavailable`. Redaction, file/path denial,
and all other write permissions remain active.

Multi-workspace `gateway.json`, inside one Workspace's `write` object:

```json
{
  "sensitive_content": {
    "mode": "audit",
    "paths": ["src"],
    "expires_at": "2026-10-23T08:00:00+00:00"
  }
}
```

The timestamp is illustrative, not an instruction to use an expired value.
For Legacy mode with `--allow-write`, the matching startup flags are
`--sensitive-content-audit-path src` and
`--sensitive-content-audit-until <UTC_TIMESTAMP>`.
The expiry must be explicit UTC (`Z` or `+00:00`): a timezone without
offset or a nonzero offset is rejected.

Expiry is checked against both UTC and a monotonic deadline. Authorization
is rechecked after the write lock and immediately before atomic install.
A write committed before the deadline is not rolled back due to later
parent-directory fsync failure.

Multi-Workspace `/workspaces`, `/info`, `list_workspaces` and
`gateway_info` expose effective per-Workspace `sensitive_content`
status: `write_mode`, `read_redaction_enabled`, `expires_at`,
`audit_scope_count`; private host paths are not disclosed.

This policy is source-only credential evidence protection, not general
runtime secret detection or a guarantee that project code is safe to run.


## 5. V3 physical-line and malformed-source integrity

Python classification and every display/authorization consumer use **one**
physical line model: CRLF, CR and LF delimit lines, with the same numbering as
Python's AST/tokenizer. The other characters recognized by
`str.splitlines()` (including Unicode U+2028/U+2029, U+0085, vertical tab,
form feed and information separators) remain characters within their original
physical source line. This same model determines the read response's
`total_lines`/`redacted_lines`, protected searches, diff previews,
visible replacement spans, hidden-line provenance and newly introduced Hard
findings. Source bytes, BOM, CRLF and the raw `file_sha256` are preserved.
If the classification flag/line counts cannot be reconciled, display and
editing fail closed rather than exposing unmatched lines.

When Python is fully tokenizable but the complete module has a
`SyntaxError`, source credential evidence is recovered by grouping bounded
**logical statements** and parsing each independently; statement line
offsets are mapped back to original physical lines. Thus a valid
multiline `token = ("literal")` cannot be ignored merely because another
statement later in the file is invalid. If a credential-named malformed
statement with string evidence cannot be attributed reliably, the scanner
fails closed as `scan_unavailable`. Dynamic getters without embedded
credential values remain ordinary code; clearly incomplete quoted values
may be heuristic only under existing narrow Audit policy.

For explicit `tuple`/`list` destructuring, each credential-named target
is matched only to its own statically corresponding RHS element, with a
bounded positional starred-target case. The unrelated `"ok"` assigned
to `label` in `token, label = get_token(), "ok"` is not a token
credential; `token, label = "secret", "ok"` remains Hard. Known secret
signatures and protected paths remain Hard independently of any target name.

This section records implementation refinements following PR #52's initial
independent CODE_FIX_REQUIRED review; it **does not** replace the approved
V3 design or claim a subsequent independent CODE PASS.
