# Controlled command execution (2.3.0)

Controlled execution is an opt-in MCP/HTTP capability for running trusted project validation commands. It is not a general-purpose terminal and it is not an OS sandbox.

## Enable

```bash
bash run.sh "/absolute/path/to/project" \
  --allow-exec \
  --exec-path service-c \
  --exec-path service-a \
  --exec-runner service-c=pipenv
```

`--allow-exec` requires at least one `--exec-path`. `--exec-runner PATH=pipenv|direct` is optional and must be inside an exec scope.

## Tool

```text
run_command(
  cwd="service-c",
  argv=["pytest", "-q"],
  timeout_seconds=60,
  dry_run=true
)
```

`dry_run=true` returns the resolved runner/effective argv and starts no process. `dry_run=false` executes.

## Runner selection

Explicit mapping wins. For `service-c=pipenv`, the example above resolves to:

```text
["pipenv", "run", "pytest", "-q"]
```

If no mapping applies, the gateway searches from `cwd` upward **only as far as the containing exec scope** for a regular `Pipfile`. A found Pipfile selects `pipenv run`; otherwise execution is direct. No interactive `pipenv shell` is maintained.

## Command allowlist

Accepted shapes:

- `pytest ...`
- `python -m pytest ...`
- `python -m compileall ...`
- `python relative/path.py ...`
- `go test ...`
- `go vet ...`

Rejected include shell executables, arbitrary programs, `python -c`, Python stdin mode, interactive pytest modes, Go external tool hooks, explicit absolute/outside paths, and parent traversal arguments.

The gateway passes an argv array directly to `subprocess.Popen(..., shell=False)`; shell metacharacters have no shell meaning.

## Process controls

- stdin: `DEVNULL`
- timeout: 1-300 seconds, default 60
- timeout termination: process group kill
- stdout/stderr: continuously drained with bounded retained bytes
- returned output: best-effort credential line redaction and 48k-character cap per stream
- inherited environment: small allowlist only; `VIRTUAL_ENV` and common secret variables are not inherited
- Pipenv: gateway sets `PIPENV_PIPFILE` and uses `pipenv run`

## Security boundary

**This feature executes project code with the OS permissions of the account running the gateway.** Tests and scripts can themselves read/write outside the selected project, spawn children, or use the network. `exec_path` and command validation limit how the gateway starts a process; they do not sandbox what trusted code does afterward.

Use this only for trusted repositories. For stronger isolation, run the gateway under a dedicated OS account/container/VM with filesystem and network restrictions.

The Secure MCP Tunnel transports the MCP call; Tunnel permissions do not grant or limit local process execution. Local `--allow-exec` and `--exec-path` are the execution authority.
