# Upgrade from v2.0 to Mac File Gateway 2.1

This is a source update, not a deployment to your Mac. No user project or live
connector was changed while building it. Previous file tools retain their
parameters; v2.1 adds one MCP tool and one HTTP route.

## Install separately, then restart

Keep the previous installation and its credentials. Extract the new ZIP to a
separate folder outside the project you intend to expose:

```bash
cd "$HOME/Downloads/mac-file-gateway-v2.1"
bash setup.sh
```

Stop the old gateway using Ctrl-C. Start the new gateway with your real project:

```bash
bash run.sh "$HOME/Projects/project" --allow-write
```

Or allow changes only in src and tests (including creating those directories):

```bash
bash run.sh "$HOME/Projects/project" --allow-write   --write-path src --write-path tests
```

Scope matching is now case-exact for both files and directories. Use the exact
spelling of the configured scope. Every newly created ancestor must also be
within scope: scope `src/generated` allows creating generated if src exists, but
does NOT grant permission to create src when src itself is missing.

The existing exclusions and hidden/sensitive-file policy still apply. Without
--allow-write the new tool is not registered, and POST /mkdir is forbidden.

Check policy locally:

```bash
curl --noproxy '*' -fsS http://127.0.0.1:8765/info
```

Expect version 2.1.0, read_only false and
write_policy.directory_creation.enabled true. No health response proves a
working external tunnel or ChatGPT connection.

## Keep the tunnel and update the app's tool snapshot

The gateway uses the same port and MCP endpoint, so the tunnel configuration
can stay unchanged. Restart the existing tunnel if necessary with `bash tunnel.sh`.
No extra tunnel API permissions are needed for mkdir. The API key controls
using the tunnel; --allow-write and --write-path control local operations.

Have the authorized app owner/admin rescan and enable create_directory, review
and publish the updated action set, and start a new chat with the updated app.
Business published apps may require recreation/republishing; Enterprise/Edu
supports action refresh. Follow the controls actually available in your workspace.
A running chat's tool definitions are not updated by downloading this archive.

Official reference, checked 2026-09-22:
https://help.openai.com/en/articles/12584461-developer-mode-and-mcp-apps-in-chatgpt

## First test on a disposable project

Preview (no directory creation):

```bash
curl --noproxy '*' -fsS http://127.0.0.1:8765/mkdir   -H 'Content-Type: application/json'   --data-binary '{"path":"src/generated/helpers","parents":true}'
```

Apply only after checking the preview:

```bash
curl --noproxy '*' -fsS http://127.0.0.1:8765/mkdir   -H 'Content-Type: application/json'   --data-binary '{"path":"src/generated/helpers","parents":true,"dry_run":false}'
```

The fields planned_paths and created_paths distinguish intent from completed
changes. Existing directories return a no-op by default; a file or symlink at
the destination is always rejected. create_file can then create a file inside
the directory. Nothing silently creates parents for create_file itself.

Read DIRECTORY_API.md for non-transactional recursive failures. Keep the v2
backup exclusions `.gateway-backups/` and `.gateway-tmp-*` out of Git. mkdir has
no original content to back up, but actual creation shares the private project
lock in .gateway-backups. Directory state is not automatically deleted.

## Verification boundary

setup.sh installs the real official SDK and runs the complete local suite plus
an actual temporary HTTP smoke test. This build environment could not install
the SDK, so MCP tests here are explicitly skipped, not counted as passes.
macOS/APFS and Mac -> tunnel -> ChatGPT are not verified here. See TEST_REPORT.md.
