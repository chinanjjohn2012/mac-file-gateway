# Upgrade to Mac File Gateway 2.5.0

This document describes the **2.5.0 source**. A source version is not
evidence that a GitHub Release/tag exists, a deployment has completed, or
production Git command execution has been approved.

## Git CLI V1 — separate opt-in, disabled by default

- Legacy: Git tools require both `--allow-git` and one or more `--git-command NAME` grants.
- Multi: set `server.git.enabled=true` **and** a Workspace-specific
  `git.allowed_commands` list; default sample grants no Git commands.
- Git supports `status`, `diff`, `log`, `branch`, `switch`, `add`, `commit`,
  `fetch`, `pull`, and `push`, through structured MCP `run_git` or `POST /git/run`.
- `dry_run=true` is the default and launches no Git process. Explicit
  `dry_run=false` can modify the parent Git repository, invoke Git hooks,
  filters or credential helpers, and access configured remotes.
- File `read_only`, file redaction, hidden/exclude rules and file backups
  do **not** limit native Git effects or output. Multi stdio remains unsupported.
- Lost MCP/Tunnel responses do not prove cancellation. Never automatically
  retry `commit`, `pull` or `push`; durable uncertain-state quarantine can only
  be recovered offline by a trusted local administrator after verifying
  all relevant processes have exited.

## Upgrade and rollback safety

1. Record the currently approved deployment and local configuration. Stop
   Gateway and Tunnel safely only after checking that no authorized Git or
   other long-running work remains in flight.
2. On a **disposable test repository**, validate the 2.5.0 source with
   `bash setup.sh` (includes `bash verify.sh --require-mcp`) and a separate
   Secure MCP Tunnel. Check actual tool grants rather than only tool discovery.
3. Keep Git disabled in production by default; do not copy Git grants from
   the disposable tests. After explicit operator approval, start with the
   narrowest read-only Git grant and keep the private config outside the repo.
4. To roll back, first establish whether any Git command is still running or
   has an unknown result. Stop admitting new Git work; return to the previously
   approved Gateway source and local configuration only when safe. Never
   delete or reset private Git quarantine markers remotely to force recovery.

For complete options and risks see [README.md](../README.md) and
[Git CLI V1 design](./GIT_CLI_V1_DESIGN.md).

---

## Historical upgrade notes: Mac File Gateway 2.3.0

2.3.0 keeps all 2.2.0 file APIs and adds the optional `run_command` MCP tool plus `POST /run`.

Execution remains disabled unless the local process is started with `--allow-exec` and at least one `--exec-path`.

For the current RTB layout:

```bash
bash run.sh "/absolute/path/to/project" \
  --allow-write \
  --allow-exec \
  --exec-path service-c \
  --exec-path service-a \
  --exec-runner service-c=pipenv
```

This makes `service-c` Python/pytest requests run through `pipenv run` without maintaining an interactive `pipenv shell`. `service-a` Go commands run directly.

Allowed command shapes are documented in `CONTROLLED_EXEC.md`. Arbitrary shell execution remains unavailable.

Because 2.3.0 adds a new MCP tool schema, restart the local gateway/tunnel and refresh the ChatGPT MCP action snapshot so `run_command` is discovered.

No additional Secure MCP Tunnel API-key permission is required. Execution authority is local to the gateway configuration.

Before using on important projects, run:

```bash
bash setup.sh
bash verify.sh --require-mcp
```

Then preview a command with `dry_run=true` before first real execution.
