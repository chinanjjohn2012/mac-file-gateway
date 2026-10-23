# Path Text Visibility V1 — scoped amendment to V3 source classification

**Status:** Proposed implementation on independent stacked PR; requires independent Standards / Spec review.
**Baseline:** PR #52 V3 at `bfbba0a9df6a2338bc8d870abf1d5ea8ff781a52` (previously independently CODE PASS).
**Decision:** Ordinary *text that represents a filesystem path* is not a credential and must not be classified Hard, heuristic, or redacted solely because it matches a private, workspace, Home, config, temporary, or hidden-file pathname.

This document supersedes **only** the `protected absolute path` **content-matching** clause of
`docs/SENSITIVE_CONTENT_CLASSIFICATION_V3_DESIGN.md` and its V3 non-Python parity
constraint **for path-text matches alone**. All other V3 safeguards remain normative.
No change to current PR #52 source or to production is implied by this document.

## 1. Product contract

1. Plain text paths remain visible, searchable and eligible for normal guarded source edits in `.py`, `.pyi`, `.json`, `.yaml`, `.yml`, `.txt` and other allowed files. This includes absolute paths under `/Users/`, `/private/var/`, `/tmp/`, paths whose components begin with digits, paths of other workspaces, private Gateway config locations, and pathname strings mentioning `.env`, `.ssh` or `*.key`. No generic path substring is secret evidence.
2. A path's appearance in permitted source content does **not** grant the ability to read, enumerate, search, write or delete that filesystem target. Existing root/canonical path checks, protected filename denial, symlink/hardlink handling, hidden-directory gates, workspace isolation, source-file limits, write scopes and Git/Exec controls remain unchanged.
3. Credential **values** remain protected. `password="abc"`, hardcoded API tokens, known credential formats, private key bodies, and credential URIs with actual authentication material remain Hard even when embedded in a path-bearing line. A URL with embedded authentication is not a harmless path. Preserve per-line Hard precedence.
4. The previous server-generated `protected_content_paths`/ `protected_paths` list must no longer be applied as a content-visibility regex; it is not a file authorization boundary. Retain compatibility with existing constructors accepting these arguments without making them re-enable path-text redaction.
5. For other non-Python classification, retain existing name/literal and signature rules. Intentional behavior change relative to V3: *only* protected-root-path-string hits cease to be Hard. All unrelated JSON/YAML V2 cases continue to classify as before.
6. Malformed or untokenizable Python remains subject to the V3 integrity rule: `scan_unavailable` still redacts the entire unscannable file, skips search, refuses preview/apply, and is not Audit-bypassable. An unquoted absolute pathname used as a syntactically invalid Python line is **not** a reason to skip tokenization errors; valid quoted paths and comment text do not justify whole-file denial.
7. The source bytes, BOM, LF/CRLF/CR line model, raw SHA, redacted diff, hidden-source provenance, write lock, backup, Audit expiry and error sanitization remain unchanged. Never substitute path visibility for access authorization.

## 2. Implementation boundaries

- `gateway/visibility.py`: stop compiling/using the `_expr` path-content rule. Retain the credential/URI/PEM/known-token classifiers and non-Python legacy rules. Preserve constructor compatibility.
- `gateway/python_values.py`: remove the use of optional `protected_expr` as a Hard source-line cue while keeping old call shape accepted, and leave tokenizer/AST/scanner-integrity behavior unchanged.
- `gateway/workspaces.py`: stop supplying unrelated Workspace, Home and config paths to source-content classification; keep all admission and access control logic.
- `gateway/core.py`: keep the optional legacy `protected_content_paths` constructor parameter compatible (inert for content redaction); ensure no new read/write authorization.
- Update `docs/SENSITIVE_CONTENT_POLICY.md`, release manifest, and path-specific tests. Do not widen Python extension matching or Audit exemptions.

## 3. Acceptance and RED -> GREEN

- Independently verify direct policy and actual Gateway read/search/create/write/replace/diff with valid quoted absolute paths, commented paths and non-credential YAML/JSON paths, including numerical leading components and other Workspace roots. Path text stays visible; writes honor existing expected SHA, backup, provenance and scope.
- Multi-Workspace REST and MCP tools must show path text in Workspace A without enabling Workspace B file access. An attempt to read a blocked file or escape a root remains denied.
- Mixed path+credential line remains Hard; known-format token, authenticated URI and private-key content remain Hard; Audit cannot override Hard or `scan_unavailable`.
- An unquoted invalid Python source line must not bypass the fail-closed scanner.
- Keep existing credential-hidden newline deletion rejection and safe adjacent editing regressions; adapt any older test that treated *pathname strings alone* as secrets rather than weakening assertions for genuine credentials.
- Record genuine RED on pre-fix source and GREEN on one final fixed SHA, including Linux/macOS ARM64 Pytest, REST/MCP/Git smokes and `MANIFEST.sha256`. User-hosted Mac/Tunnel E2E and prior CRLF P3 remain separately tracked.

## 4. Review gates

This is a **new product contract**, not a retrospective weakening of the previously approved PR #52 CODE PASS. Independent Design Standards/Spec and Code Standards/Spec reviews must explicitly assess the scope above. Keep PR #52 and this stacked PR Draft until separately authorized. Do not merge, tag, release, deploy, or alter production Git permissions.
