# Upgrade from the read-only Mac gateway to 2.0

## 1. Keep the old installation; use a new directory

Extract `mac-file-gateway-v2.zip` to a separate folder. Do not overwrite your
existing virtual environment, shell configuration or tunnel credentials.

```bash
cd "$HOME/Downloads/mac-file-gateway-v2"
bash setup.sh
```

Setup must succeed with the official MCP SDK installed. The ZIP does not bundle
dependencies. No changes to your target project occur during setup: automated
write tests use temporary projects only.

## 2. Restart the service with explicit write permission

Stop the previous gateway on port 8765 using Ctrl-C in its terminal. Replace the
example project path below with your real project path.

```bash
bash run.sh "$HOME/Projects/project" --allow-write
```

For tighter scope, use this instead:

```bash
bash run.sh "$HOME/Projects/project" --allow-write \
  --write-path src --write-path tests
```

The directories should already exist. Creation of directories and hidden files
is deliberately unsupported. Existing exclusions are still honored. Omit
--allow-write and restart to return to read-only mode.

Add `.gateway-backups/` and `.gateway-tmp-*` to the target project's Git ignore
or local exclude configuration before writing. The gateway does not do that for
you. Code watchers/dev servers may execute changed code: stop them while testing.

## 3. Verify the local policy

```bash
curl --noproxy '*' -fsS http://127.0.0.1:8765/health
curl --noproxy '*' -fsS http://127.0.0.1:8765/info
```

Normal MCP+HTTP mode must report `read_only: false` and `mcp_enabled: true`.
The info response reports the writable scope. `--http-only` is for local REST
troubleshooting and cannot connect as an MCP server.

## 4. Preserve the private tunnel; refresh the ChatGPT tools

An existing tunnel that still points at this same loopback URL does not need a
new runtime key or extra key permissions. Restart it if needed:

```bash
cd "$HOME/Downloads/mac-file-gateway-v2"
bash tunnel.sh
```

Keep the gateway and tunnel processes running. The key needs only Tunnels Read
and Use. There is no reason to grant Manage, model execution or file APIs for
this upgrade. An API key's tunnel permissions are different from the writable
paths exposed by this MCP server.

Update the custom app's action snapshot, authorize its new write actions, and
start a new chat with that updated connection. Verify these new tools appear:

```
create_file
write_file
replace_text
```

ChatGPT app updates are not automatic. Current OpenAI documentation states that
published Business apps may need to be recreated/republished; Enterprise/Edu
administrators can refresh/configure actions. Use the controls your workspace
actually presents. A tool annotation cannot guarantee a human confirmation
prompt and is not a substitute for server-side restrictions.

## 5. First test: preview only

Use a disposable project with no secrets for the first test. Through ChatGPT,
request a preview to create `gateway_demo.txt` containing `hello` and a newline.
Specify that it must not apply the change yet. The result should have
`dry_run: true`, `applied: false`, and the file should not exist.

Equivalent local REST request:

```bash
curl --noproxy '*' -fsS http://127.0.0.1:8765/create \
  -H 'Content-Type: application/json' \
  --data-binary '{"path":"gateway_demo.txt","content":"hello\n"}'
```

Only after reviewing the target and content, apply to this disposable file:

```bash
curl --noproxy '*' -fsS http://127.0.0.1:8765/create \
  -H 'Content-Type: application/json' \
  --data-binary '{"path":"gateway_demo.txt","content":"hello\n","dry_run":false}'
```

Creation refuses an existing file. For updates, read the source first and use
`file_sha256` as `expected_sha256`; do not use `content_sha256`.

## Parameters

`create_file(path, content, dry_run=True)` creates a new allowed UTF-8 file.
An existing parent is required. There is no overwrite flag.

`write_file(path, content, expected_sha256, dry_run=True)` replaces the entire
existing file. It backs up original bytes before committing. A hash mismatch
returns `conflict`, not a force overwrite. Read all source pages first and keep
the raw-byte hash consistent across pages.

`replace_text(path, old_text, new_text, expected_sha256,
expected_count=1, dry_run=True)` replaces an exact string. Repeated text must
match exactly the explicit expected_count. It preserves all other bytes, which
is safer than reconstructing a file from numbered, truncated display output.

Each result includes path, operation, applied, changed, old/new hashes, size,
a bounded diff, diff_truncated, backup_path, and possible warnings. The hash is a
conflict check, not proof that all intended edits are semantically correct.

## Recovery

Stop writes to the file before restoring it. Read the local backup metadata to
confirm the original relative path and digest, then restore the corresponding
`.bak` using your local editor/file tools. Backups contain exact old bytes but
not a complete record of ACLs, extended attributes or other special metadata.
No remote restore/delete interface is exposed. Git remains useful for reviewing
and reverting code changes, but do not add the backup directory to Git.

## Explicit boundaries

This is not yet a verified Mac -> Secure MCP Tunnel -> ChatGPT write deployment.
See TEST_REPORT.md. Source and HTTP behavior were tested in Linux; MCP execution
was skipped because the SDK could not be installed in the build environment.
Native filesystem and actual client integration must pass on your Mac before
using this on important work. Use a dedicated test project first.
