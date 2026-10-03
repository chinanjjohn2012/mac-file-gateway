# File delete, move and rename API (2.2.0)

These operations are available only when the gateway is started with `--allow-write`.
They inherit the existing `--write-path`, exclude, hidden-path, sensitive-name, regular-file,
size and source-hash policies.

## Delete aliases

The MCP tools `delete_file`, `remove_file` and `unlink` are aliases with identical behavior.
REST aliases are `POST /delete`, `POST /remove` and `POST /unlink`.

Arguments:

- `path`: project-relative allowed regular file.
- `expected_sha256`: exact `file_sha256` from `read_file`.
- `dry_run`: defaults to `true`.

A real delete (`dry_run=false`) acquires the project write lock, re-reads and verifies the
source, saves the exact original bytes to `.gateway-backups/`, revalidates the source, then
unlinks it. Directories, symlinks, hard-linked files, stale hashes and blocked paths are refused.
Redacted files may be deleted because the operation never reconstructs their contents.

## Move / rename aliases

The MCP tools `move` and `rename` are aliases with identical behavior. REST endpoints are
`POST /move` and `POST /rename`.

Arguments:

- `source`: existing project-relative allowed regular file.
- `destination`: different project-relative allowed file path whose parent already exists.
- `expected_sha256`: exact source `file_sha256` from `read_file`.
- `dry_run`: defaults to `true`.

Both paths must be inside writable scope. The destination must not already exist. Apply uses a
descriptor-relative atomic no-overwrite primitive: `renameatx_np(..., RENAME_EXCL)` on macOS
and `renameat2(..., RENAME_NOREPLACE)` on Linux. If that primitive or filesystem support is
unavailable, the operation fails closed. Cross-filesystem moves are refused; the gateway does
not silently copy then delete. Destination parents are never created implicitly.

## Deliberate boundaries

- No directory deletion (`rmdir`, recursive delete, tree removal).
- No destination overwrite flag.
- No shell or command execution.
- Deletion backups are not remotely restorable or remotely pruned.
- The advisory project lock coordinates gateway instances, not unrelated editors/processes.
