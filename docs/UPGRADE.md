# Upgrade to Mac File Gateway 2.3.0

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
