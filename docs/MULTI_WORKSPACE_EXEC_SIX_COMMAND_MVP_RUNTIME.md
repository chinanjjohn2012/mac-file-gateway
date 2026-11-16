# Multi-Workspace Exec — Six Fixed Commands MVP (development candidate)

Design contract: MWE-LBE-SIX-COMMAND-MVP-DESIGN-002, exact immutable Git Blob d90df6de3bdbd81a314109d5f73959799b5a10a6. B and C TARGETED design PASS; user authorized implementing the six-command-only local_best_effort exception on 2026-11-13. This document does not certify real native T1, integration, FULL code review, or release.

## Explicit opt-in (schema_version=2 only)

A legacy version-two exec.paths-only configuration still permits *nonspawning preview*, not positive execution. To permit positive execution, BOTH server.exec.enabled and the chosen workspace.exec.enabled must be strict JSON booleans true and the workspace must explicitly scope the canonical command cwd.

Example fragment (other top-level workspace fields omitted):

    {
      "schema_version": 2,
      "server": {"exec": {"enabled": true}},
      "workspaces": {"a": {
        "root": "/Users/operator/projects",
        "exec": {
          "enabled": true,
          "paths": ["py-direct", "py-pipenv", "go-project"],
          "runners": ["py-direct=direct", "py-pipenv=pipenv",
                      "go-project=direct"]
        }
      }}
    }

The root must pass the existing Phase1 protected-root checks. A private exec-state root and owner.lock must already exist and pass existing-only quarantine/lock admission; no automatic reset or bootstrap is permitted. Any old PREPARED/RUNNING/UNKNOWN/RETIRED, corrupt or foreign record continues to quarantine Exec, not independent File/Git operations.

## Operator-selected local tool binaries

For real positive application, the service requires a second *private* startup-only file next to the existing private Gateway config, named mvp-exec-tools.json. Its content is an exact object with absolute, operator-chosen Python, Pipenv, and Go executable paths (illustrative paths must be replaced by actual installed tools):

    {
      "executables": {
        "python": "/opt/homebrew/bin/python3",
        "pipenv": "/opt/homebrew/bin/pipenv",
        "go": "/opt/homebrew/bin/go"
      }
    }

Note: the request argv always begins with the fixed token "python"; the selected private interpreter need not have the basename "python". Create this file with the same ownership and *0600* private-file permissions as the Gateway control-plane JSON, in the same existing private config directory. Do not place it in a Workspace root or in Git. The service snapshots the exact resolved executables and any console-script shebang interpreter at initialization; a missing/changed tool disables or refuses positive launch. There is no client-controlled PATH or fallback; parent GOFLAGS, PIPENV_PIPFILE, PYTHONPATH, OIDC, proxy and SSH variables are not forwarded. The immediate child environment is deliberately bounded, but this is NOT an OS sandbox or a guarantee about arbitrary project-code/network side effects. A script relying on /usr/bin/env to select its interpreter is not an acceptable selected console script for this MVP.

For Pipenv the chosen py-pipenv project needs an existing Pipfile and executable .venv/bin/python; the application explicitly selects both PIPENV_PIPFILE and PIPENV_PYTHON from this project (never the inherited environment), validates the interpreter's resolved executable before launch, and keeps PIPENV_VENV_IN_PROJECT=1. Go local tools use GOFLAGS="", GOENV="off", GOTOOLCHAIN="local", CGO_ENABLED="0" and local tool paths. An absent locally installed tool produces a truthful refusal rather than a fake success or automatic install.

## Only these six request vectors may actually execute

| cwd | requested argv | derived runner and effective argv |
| --- | --- | --- |
| py-direct | python -m pytest -q | direct; unchanged |
| py-direct | python -m compileall -q ./src | direct; unchanged |
| py-pipenv | python -m pytest -q | pipenv; pipenv run python -m pytest -q |
| go-project | go test ./... | direct; unchanged |
| go-project | go vet ./... | direct; unchanged |
| go-project | go build -o bin/app ./cmd/app | direct; unchanged |

Different flags/packages, shell commands, Python -c, Go toolhooks, wrong cwd/runner, output outside the fixed target or inferred paths-only consent must not reach Popen. REST /run and official MCP run_command use WorkspaceService.invoke_exec rather than a second native-launch service. No private R006 grant or preexisting preview authorizes a generic positive path.

## Best-effort result and interruption semantics

The returned result reflects the actual observed direct-child exit code and bounded stdout/stderr or a truthful launch_failed/timed_out/uncertain state. Timeout, request disconnect, and cancel MAY stop only the waiter; they do not send kill signals, do not guarantee the child or descendants stop and must not release the original-child reservation before direct-child wait/reap. At most 1 original child per Workspace and 4 per instance. Do not automatically replay a command after a lost ACK or crash. There is no per-new-attempt fsynced PREPARED/RUNNING record or guaranteed crash/restart deduplication; a manually repeated command may duplicate side effects. Existing historical ExecStateStore and owner.lock remain protected.

Status should distinguish preview availability, positive opt-ins, private tool readiness, healthy old state and actually free original-child capacity. "Six commands implemented" does not imply "six real native commands tested": a separately approved disposable macOS PRODUCT_T1 profile and genuine same-instance Direct/REST/official MCP tests are still required.

## Evidence and release

Allowed now: source and nonspawning SAFE T0 tests (FakeChild or monkeypatched Popen). NOT authorized by this document: real Python/Pipenv/Go native product T1 on an unapproved host, live OIDC/SSH/autofs, T2 kill/forced restart, T3 shared/production, merge, tag, release or deployment. New code needs an immutable complete milestone Head/Base/Tree/Manifest and original CI, independent B/C FULL role reviews, and separate actual integration/R10 signoff.


## Explicit fresh-install provisioning (not recovery)

The schema-v2 service deliberately does NOT create an absent exec-state directory
on startup. On a genuinely NEW installation only, first STOP every Gateway
instance that could use the private control plane, verify there has been no
previous Exec state/lock/history and that the private config directory already
exists, belongs to this user and has POSIX mode 0700. Then an operator can
explicitly initialize an EMPTY state root/owner.lock once:

    python -m tools.mvp_exec_first_install \
      --config-dir /ABS/PRIVATE/GATEWAY_CONFIG_DIR \
      --confirm-first-install --confirm-gateway-stopped

This operator-only offline command creates exec-state (0700) and owner.lock
(0600), fsyncs them and returns a nonexecution receipt. It does not start
the Gateway, touch any Workspace source, run Python/Pipenv/Go or grant Exec.
It deliberately refuses when ANY exec-state entry (including a symlink or
incomplete previous attempt) already exists. Never use it to recover a missing
old lock, UNKNOWN/PREPARED/RUNNING/RETIRED state, corrupt history or a live
Gateway; those cases remain blocked for separate operator investigation.

## Read-only six-command status diagnostics (usability milestone 001)

Schema-v2 `GET /info`, `GET /health`, and existing MCP `gateway_info`
now expose the same `exec_policy.mvp_readiness` fields. They derive from
one service status snapshot, perform no file probing, do not mutate
permissions, and launch NO Python/Pipenv/Go child.

For an already authorized local status read, `GET /info` (or official MCP
`gateway_info`) includes, for example:

    "mvp_readiness": {
      "six_command_apply": "blocked",
      "preview": "eligible",
      "blocking_codes": ["dual_opt_in_or_scope_missing"],
      "evidence_grade": "runtime_status_only_not_native_test"
    }

Fixed codes are `exec_paths_disabled`,
`dual_opt_in_or_scope_missing`, `selected_tools_unavailable`,
`historical_state_quarantined`, `historical_state_unavailable`,
`original_child_owner_unavailable`,
`original_child_capacity_exhausted`, `service_closing`, and
`workspace_original_child_slot_unavailable`. Codes are non-sensitive:
they never reveal absolute roots, tool paths, process identifiers, files,
secret values or private owner state. A blocked status may list several
causes. Do not erase/recreate an old Exec state or lock to clear a code.

**An "eligible" status is NOT authorization, actual native qualification,
or integration PASS.** It means only aggregate configuration/tool/state/slot
readiness at this instant; each request must still pass command, Workspace,
cwd, runner, binary identity and all service/launcher checks. Preview is
separate from APPLY, and an unknown timed-out/lost ACK MUST NOT be retried
automatically. Git/File permissions are independent.

### Official SDK ClientSession — SAFE T0 coverage

`tests/test_lbe_mvp_usability_t0.py` uses the official pinned MCP SDK
`ClientSession` through its in-memory `Client(build_multi_mcp(service))`
in legacy and modern modes. It checks all six fixed command PREVIEWS,
a missing-opt-in apply refusal, six FakeWorker applies, and illegal/cross-
Workspace refusals. Every `subprocess.Popen` is hard-trapped during the
test. The separate REST/MCP-server T0 regression checks `/info`,
`/health` and `gateway_info` status consistency.

The additional `test_official_streamable_http_client_session_over_inprocess_asgi`
executes `ClientSession` through the SDK `streamable_http_client` over
`httpx2.ASGITransport` using the real SDK `/mcp` ASGI handler, with a
hard `Popen` refusal. It verifies six previews, read-only diagnostic parity,
and disabled-apply rejection. This is an in-process HTTP-protocol T0, not a
socket listener, not a user-machine Tunnel test, and not native T1.

These are **not** an actual socket-based ClientSession test, user Mac/Tunnel,
real Go/Pipenv/Python execution, third-party source/credential qualification
or production integration. Real native/Tunnel/T1 tests require their own
authorized target, isolated environment, R10 and independent evidence.

### Nonexecuting operator troubleshooting

1. Read `gateway_info` or `GET /info`; distinguish `preview_available`,
   `apply_configured`, `tool_selection_ready`, `durability_state` and
   `mvp_readiness`.
2. For an explicitly operator-approved schema-v2 setup verify BOTH
   `server.exec.enabled` and `workspaces.<id>.exec.enabled` and exactly
   scoped paths. Never auto-migrate paths-only/v1 into positive APPLY.
3. When permitted, inspect the already-private operator-selected
   `mvp-exec-tools.json` and existing-only historical owner.lock/state.
   Do not auto-provision, reset, install foreign tools or run a command to
   obtain a prettier status.
4. Select ONLY one of the six request vectors above and use `dry_run=true`.
   This validates a preview, not a positive grant. Actual apply is outside
   this unapproved testing environment.
