# Mac File Gateway 2.3.0 verification report

Date: 2026-09-30
Branch: `feature/controlled-exec`
Verified commit: `2b0f500b99342c5cb617bd8b0a6e10bded0880f5`
GitHub Actions run: 36734206118

## Result

GitHub Actions Ubuntu runner, Python 3.13.15:

```text
391 passed, 1 warning in 8.23s
```

The official MCP SDK was installed from `requirements-dev.txt` during this run (`mcp 1.30.0`), so MCP schema and real `tools/call` tests executed rather than being skipped.

Additional checks in the same successful workflow:

- `python tests/smoke_live.py`: PASS
- `python -m compileall -q gateway tests tools`: PASS
- `bash -n setup.sh run.sh verify.sh tunnel.sh`: PASS

The one warning is Starlette's existing `anyio.abc.BlockingPortal` deprecation warning; it did not fail the suite.

## Controlled execution coverage

Tests cover:

- execution disabled by default
- explicit `--allow-exec` + `--exec-path`
- execution scope rejection
- `dry_run=true` starts no process
- direct runner and explicit Pipenv runner
- automatic Pipfile detection constrained to the containing exec scope
- `service-c`-style `pipenv run pytest` / `pipenv run python ...`
- Go `test` and `vet` command shapes
- Python `-m pytest`, `-m compileall`, and relative script execution
- shell/arbitrary program rejection
- `python -c` / stdin mode rejection
- external/parent path argument rejection
- Go external tool hook rejection
- minimized inherited environment
- timeout/process-group termination
- bounded continuously-drained stdout/stderr
- output credential redaction
- HTTP `POST /run`
- MCP `run_command` schema, preview and actual call
- `run_command` absent when execution is disabled

## Security boundary

This is controlled process launch, not an OS sandbox. Once trusted project tests/scripts are running, they inherit the permissions of the OS account that runs the gateway and may access files or the network outside the configured exec scope. The scope and command allowlist constrain how the gateway starts code, not what that code can do after startup.

For stronger isolation, run the gateway under a dedicated macOS account, container, VM, or other OS sandbox.

## Native Mac checks still required

GitHub Actions validates Linux behavior. On the target Mac run:

```bash
bash setup.sh
bash verify.sh --require-mcp
```

Then start with narrow execution scopes and preview the first command before `dry_run=false`.
