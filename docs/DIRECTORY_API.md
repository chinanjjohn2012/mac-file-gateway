# Directory creation API (v2.1)

## Contract

MCP tool: `create_directory`

HTTP: `POST /mkdir`, Content-Type application/json (no query arguments).

```python
create_directory(path: str, parents: bool = False,
                 exist_ok: bool = True, dry_run: bool = True)
```

| Argument | Required/default | Behavior |
| --- | --- | --- |
| path | required | Relative path below the project root. Root itself is rejected. |
| parents | false | Explicitly create missing ancestor directories when true. |
| exist_ok | true | A real existing directory is a no-op; false makes it a conflict. |
| dry_run | true | Preview only; false requests the authorized filesystem change. |

Boolean fields are strict: strings such as "false", integers and null are
rejected. Unknown JSON arguments and duplicate JSON keys are rejected.
Neither existence mode allows overwriting a file, special file or symlink.

## Examples

Preview a new directory whose parent exists:

```json
{"path":"src/generated"}
```

Create a recursive directory path:

```json
{"path":"src/generated/helpers","parents":true,"dry_run":false}
```

Example selected response fields when src already existed:

```json
{
  "operation":"mkdir",
  "path":"src/generated/helpers",
  "dry_run":false,
  "applied":true,
  "changed":true,
  "already_exists":false,
  "planned_paths":["src/generated","src/generated/helpers"],
  "created_paths":["src/generated","src/generated/helpers"],
  "warnings":[]
}
```

Previews have applied=false and created_paths=[]; changed means a change would
be needed. A no-op has applied=false, changed=false, already_exists=true.
planned_paths reflects the preflight under the project lock for actual changes;
created_paths lists only successful mkdir calls made by this request.

## Policy and limits

Requires --allow-write. All new directory paths, including every new parent,
must be inside a --write-path scope when one is specified. Existing ancestors
may be traversed outside that narrower scope, but may not be created there.
Scopes match case-exact path components (src does not grant SRC or src-other).
Existing deny rules and --exclude are checked before the first requested mkdir.
Directories do not need a text-file extension.

The path is limited to 2048 characters, each component to 255 UTF-8 bytes, and
total component depth to Limits.max_depth (20 by default). Creates directories
with requested mode 0700, further restricted by the process umask. It does not
change permissions of existing directories and does not expose a chmod option.

Traversal uses descriptor-relative operations and O_NOFOLLOW. Symlinks are
rejected even when their targets are within the project. This is still a trusted
single-user filesystem service, not isolation from a malicious local process
that renames/moves an open directory. Avoid concurrent directory moves.

Actual changes share the same private advisory lock as file writes. This may
create .gateway-backups/.lock even though mkdir saves no byte backup. Preview
and normal existing-directory no-ops do not create lock state. An advisory lock
does not coordinate unrelated tools that do not use that lock.

## Failures and partial success

Recursive creation is NOT atomic. The full requested path and scope are
prevalidated, but an I/O or permission error can occur after earlier levels were
created. No automatic rollback/deletion is attempted, since another process may
already be using a created directory.

HTTP errors include a safe code/message and, for traversal/apply errors, details:

```json
{
  "error":"write_failed",
  "message":"Directory operation failed; inspect the reported paths before retrying.",
  "details":{
    "operation":"mkdir",
    "path":"first/second",
    "created_paths":["first"],
    "partial":true,
    "warnings":[]
  }
}
```

MCP returns an error tool result with equivalent JSON details in its text.
Inspect paths before retrying after any error, timeout or lost connection.
A crash may prevent the partial result from reaching the caller.

HTTP status examples: 403 for read-only/scope/blocked-type policy; 404 for a
missing parent with parents=false; 409 for exist_ok=false or a file conflict;
400 for invalid flags or paths; 500 for local filesystem failures. A directory
fsync failure after successful creation produces an applied=true result with a
warning rather than falsely reporting that nothing happened.

A successful preview is not proof of future filesystem permissions, disk space,
or human approval. dry_run=false is not authenticated evidence that a person
reviewed it. Preserve your tunnel authentication and app action controls.

## Non-goals

No directory deletion, rename, chmod, remote cleanup, command execution, or
transactional multi-directory rollback. This API does not change create_file's
requirement that its parent already exists: call create_directory first.
