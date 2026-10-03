# Guarded local file writes, gateway 2.0

Goal: extend the existing downloadable macOS gateway with opt-in creation and
modification of UTF-8 project files, without editing the user's live project.

## Contract
- Existing four read tools and existing GET endpoints remain compatible.
- New tools: create_file(path, content, dry_run=True), write_file(path, content,
  expected_sha256, dry_run=True), replace_text(path, old_text, new_text,
  expected_sha256, expected_count=1, dry_run=True).
- Writing is disabled unless --allow-write is passed. Optional repeated
  --write-path restricts writes to specified project-relative subtrees/files.
- No delete, rename, mkdir, chmod, terminal, arbitrary HTTP, or shell tools.
  Parent directories must already exist. Allowed extensions/exclusions from v1
  also apply to every write, including previews.
- Writes accept UTF-8 text of at most 1 MiB. Reject NUL, redacted/truncated
  placeholders and credential-like text. Never overwrite a redacted source.
- read_file adds file_sha256 over actual source bytes; keep content_sha256's
  existing normalized/redacted meaning for backwards compatibility.
- All modifications require file_sha256, checked immediately before committing.
  Exact text replacement also requires the declared non-overlapping match count.
- Dry runs change no files and return a bounded unified diff or an explicit
  omitted/truncated indication. They are previews, NOT proof of human approval.
- Actual updates save original bytes in .gateway-backups (0700, files 0600),
  then install a complete temporary sibling atomically. Creations never clobber
  an existing name. Fail closed if a mandatory backup cannot be saved.
- Single-process and cooperating gateway writes are serialized. External editors
  are NOT transactional participants; hash checking cannot eliminate the small
  final check-to-rename race. No guarantees against a malicious local process
  moving directories during a request. Use on a trusted, single-user machine.
- Preserve regular permission bits for replacement, use 0600 for new files.
  ACLs, extended attributes and all macOS filesystem behavior need native tests;
  atomic replacement does not promise to preserve those metadata.
- State and temporary files use non-following descriptor-relative operations.
  Read/write cannot traverse symlinks, hardlinked target files, or parent '..'.
- Writes are MCP tools with readOnlyHint=false and appropriate destructiveHint;
  annotations are NOT authorization. Real enforcement is server-side opt-in,
  path checks and tunnel access. Client confirmation is an additional layer.
- HTTP writes use only JSON POST /create, /write, /replace. Reject other content
  types, duplicate/unknown arguments, invalid types and oversized bodies.
- Keep 64 KiB HTTP request cap in read-only mode. Write mode allows a bounded
  larger JSON envelope sufficient for a 1 MiB UTF-8 file and JSON escaping.
- Same private tunnel; its runtime API key still needs Tunnels Read + Use, not
  Manage. Refresh/re-publish the custom app's tool snapshot before use.

## Verification
Run the original suite, security/edge-case write tests, real HTTP subprocess
smoke tests, and real SDK tests when the SDK can be installed. Report any skips,
macOS/APFS gaps and absence of a live ChatGPT/tunnel end-to-end test explicitly.
