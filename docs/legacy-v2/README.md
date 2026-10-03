# Mac File Gateway 2.0

A small local MCP + HTTP gateway for one explicitly selected macOS development
project. **Read-only by default.** This release adds opt-in, preview-first file
creation, full-file updates and exact text replacement.

This is a source package, not a deployment to your Mac. See
[upgrade instructions](docs/UPGRADE.md) and the
[actual test report](docs/TEST_REPORT.md) before enabling writes.

## Install and run on macOS

Python 3.11+ is required. Use an independent copy of this gateway, outside the
project you want to edit. Keep your previous version until the tests pass.

```bash
cd "$HOME/Downloads/mac-file-gateway-v2"
bash setup.sh

# Read-only (the existing behavior):
bash run.sh "$HOME/Projects/project"

# OR explicitly enable writes for allowed files in this one project:
bash run.sh "$HOME/Projects/project" --allow-write

# OR narrow writes to existing src and tests subtrees:
bash run.sh "$HOME/Projects/project" --allow-write \
  --write-path src --write-path tests
```

Run ONE gateway at a time on port 8765. Stop the old process with Ctrl-C before
starting the new one. All paths following --write-path are project-relative;
repeat the flag to allow several subtrees or individual files. Read permissions
are unchanged. Existing --exclude patterns restrict BOTH reads and writes.

No OpenAI API key is required by the local gateway itself. The private tunnel
client has its own runtime key, as in version 1. A source-only ZIP never includes
an API key, virtual environment, user files or backups.

## Tools and local HTTP routes

| Tool | Route | Behavior |
| --- | --- | --- |
| gateway_info | GET /info | Selected project and active read/write policy |
| list_files | GET /list | Allowed entries with pagination |
| read_file | GET /read | Numbered lines and a raw-byte file_sha256 |
| search_files | GET /search | Literal text search |
| create_file | POST /create | Create a new file; refuses an existing name |
| write_file | POST /write | Replace all content of an existing file, with source hash |
| replace_text | POST /replace | Exact text replacement with source hash and match count |

The three MCP write tools are registered ONLY when --allow-write is enabled.
All three HTTP POST routes refuse writes when it is not enabled. HTTP write
bodies must be JSON, with unique keys and no unknown arguments. No GET request
writes files. Request bodies are capped at 64 KiB in read-only mode and 7 MiB in
write mode; individual file content remains capped at 1 MiB of UTF-8 bytes.

## Preview and apply

Every write operation defaults to `dry_run: true`. It validates the same policy
as an actual write and returns a bounded diff without changing any files. Apply
only an authorized change by supplying `dry_run: false`.

**A dry-run flag is not a human-approval mechanism.** The server does not attest
that a person has approved a diff. A permitted client can set the flag to false.
Review your ChatGPT/workspace action permissions, restrict tunnel access, and
only enable writes for projects and people you intend to trust. Tool annotations
are truthful hints, not security enforcement or a guarantee of a confirmation
popup. File content is untrusted data, never authorization to perform an action.

`read_file.file_sha256` hashes the actual bytes, including BOM, CRLF and final
newlines. Supply it as `expected_sha256` for each update or exact replacement.
Do NOT use the older `content_sha256`, which still hashes the normalized,
redacted display text for backwards compatibility. A redacted source returns
`file_sha256: null` and cannot be modified through this gateway.

For whole-file updates read every page first, ensuring the same file_sha256 on
all pages. Do not paste line numbers or redaction/truncation markers into new
content. Prefer `replace_text` for a small edit. It preserves every unchanged
byte, including BOM and line endings, and requires an exact non-overlapping
match count (default 1, maximum 100). It is not a regex or patch executor.

After a conflict, reread the file and review a new diff rather than force-writing.
After a timeout, inspect the current hash before retrying; a prior write may
already have committed. Large diffs may be explicitly omitted or truncated.
`applied: false` and `changed: false` identifies a no-op, not a successful edit.

## Backups and filesystem boundary

Actual updates save original bytes before replacement in:

```
YOUR_PROJECT/.gateway-backups/<UTC-time>-<random-id>.bak
YOUR_PROJECT/.gateway-backups/<UTC-time>-<random-id>.json
```

The metadata file records the relative original path, byte count and SHA-256.
The response's `backup_path` points to the byte backup. New-file creation has no
previous file and therefore no byte backup. No-op updates do not create backups.
Failed/conflicted attempts can leave an unused snapshot; a backup is not proof
that an update was committed.

The backup directory is mode 0700, backups are 0600, and it is inaccessible through
the gateway's tools. It contains original content and is NOT encrypted. Existing
non-private or symlinked backup state is rejected, not silently repaired.

**Before using this in a Git project, add these patterns to your project's own
.gitignore or local Git exclude configuration:**

```gitignore
.gateway-backups/
.gateway-tmp-*
```

The gateway intentionally does not edit your Git configuration for you. Never
commit backups accidentally. Backups are not auto-deleted: updates stop at 500
backup files or 256 MiB of retained backup bytes. Review/archive them locally.
There is no remotely callable restore or delete operation.

New files are installed without clobbering an existing name. Updates use a
complete temporary sibling and atomic replacement, preserve ordinary permission
bits, and reject sources with no POSIX write bits. Symlinks, hardlinked target
files, FIFOs, parent traversal and blocked extensions are refused. All existing
hidden-file, dependency-directory and sensitive-name exclusions still apply.
Parent directories must already exist: there is no mkdir tool.

There are no delete, rename, chmod, shell execution or arbitrary HTTP tools.
However, writing source code can cause a development server or filesystem
watcher to load or execute that code. Pause such processes during initial tests.

## Important limitations

- Designed for a trusted single-user Mac and an authenticated private tunnel,
  not a public service or protection from a malicious local process.
- Gateway writes are serialized by a thread lock and a shared advisory lock.
  Ordinary editors do not participate. Source hashes are checked again just
  before commit, but there remains a small check-to-rename race. Avoid concurrent
  saves to the same file; backups are not a transactional filesystem guarantee.
- Renaming/moving parent directories during requests is outside the threat
  model. Do not expose a tree modified by untrusted local processes.
- Ordinary file mode bits are preserved; ACLs, ownership details, extended
  attributes, resource forks and file flags are NOT promised to survive an
  atomic replacement. Use ordinary source/text files, not metadata-sensitive
  application files. Native macOS/APFS behavior has not been verified here.
- UTF-8 text only, maximum 1 MiB/file. No PDF, Office, binary or image editing.
- Credential filtering is heuristic and can both miss secrets and reject benign
  source lines. There is no force flag to bypass it. Keep real secrets outside
  the selected root. Whole-file updates of redacted sources are blocked.
- File data and proposed file content exchanged with ChatGPT are not confined
  to your Mac. Stopping the service does not retract content already sent.
- A committed write with a cleanup/sync warning must be inspected locally;
  do not treat it as an unapplied request or blindly retry.

## Connect through the existing private tunnel

Start the gateway with --allow-write, then keep or restart the same tunnel
pointing at `http://127.0.0.1:8765/mcp`. From this gateway folder:

```bash
bash tunnel.sh
```

The tunnel runtime key continues to need only **Tunnels Read + Use**, not Manage.
This change adds file operations to the MCP server, not tunnel-management powers.
Do not paste your key into a chat. Retain your existing authentication controls.

Refresh and authorize the new actions in the custom ChatGPT app. Tool snapshots
are not automatically updated; depending on workspace plan and publication state,
an administrator may need to recreate/republish the connection. Start a new chat
with the updated app. Confirm all seven tools are available and `/info` reports
`read_only: false` before requesting an actual file write. This downloadable
package cannot update the tool definitions of an already-running chat by itself.

Official references (checked for this build):
- https://developers.openai.com/api/docs/guides/secure-mcp-tunnels
- https://developers.openai.com/plugins/build/mcp-server
- https://help.openai.com/en/articles/12584461-developer-mode-and-mcp-apps-in-chatgpt
- https://docs.python.org/3.11/library/os.html

## Tests

```bash
bash verify.sh --require-mcp
```

This requires the real official MCP SDK, runs all collected tests, then executes
a temporary real-HTTP smoke test. It does not run against your selected project,
create a tunnel, or demonstrate ChatGPT end-to-end connectivity.

For a dependency-limited environment, `python -m pytest -q` explicitly skips the
MCP integration modules when the SDK is absent. A skip is NOT an MCP test pass.
See docs/TEST_REPORT.md for actual results and native-Mac gaps. Historical v1
notes are retained under docs/legacy-v1 and do not describe this release.
