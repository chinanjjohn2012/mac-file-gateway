# Multi-Workspace Controlled Exec — Product Candidate (opt-in)

**Status:** Draft implementation. Independent Standards/Spec PRODUCT CANDIDATE
review [#5621997787](https://github.com/chinanjjohn2012/mac-file-gateway/pull/56#pullrequestreview-5621997787)
was PASS/PASS **only** on old fixed Head
`933f2bc7d4add6b651e87c7d0a90369440a1ddfe`; subsequent P3
changes require a fresh fixed-Head independent review. macOS native E2E
and production acceptance remain NOT_RUN. Based directly on `release/ms1`
2.5.0, not on unmerged PR #13 or C3 Candidate B native research. Do not
merge, deploy, or activate production Exec without separate authorization.

## What this candidate adds

- Global `server.exec.enabled` defaults to `false`; each Workspace must
  separately set `exec.enabled: true` and nonempty `exec.paths`.
- Every request specifies a Workspace ID and a project-relative `cwd`.
  No file-API reflection/fallback or implicit cross-Workspace delegation.
- Reuses existing Legacy `CommandRunner` for the known pytest/Go/Python
  allowlist, no shell or stdin, `dry_run=true` by default, bounded/redacted
  stdout/stderr, 1–300 second timeout and direct/pipenv project runner.
- Synchronous command Worker is admitted under the WorkspaceService lock
  and holds its root-FD lifetime lease until return, including after an
  HTTP/MCP waiter disconnect. One active attempt per Workspace, four across
  the instance; excess demand returns `busy` without queue/retry.
- REST `POST /run` and MCP `run_command` register only when any Workspace
  has effective Exec permission. Git has independent grants; Local Skills
  remain unsupported in Multi-Workspace.
- Operator startup logging reports effective Controlled Exec registration
  separately from Local Skills and Git. Multi `read_only` conservatively
  means no File Write, Exec, **or registered Git capability**. Because Git
  can modify repository metadata or invoke helpers even for ostensibly
  inspect-only commands, a Git-enabled instance reports `read_only=false`.
  `file_read_only` separately reports only the File Write authorization;
  both fields agree between `/info` and `/health`.

## Default-off JSON configuration

```json
{
  "schema_version": 1,
  "server": {
    "port": 8765,
    "transport": "http",
    "exec": {"enabled": false},
    "git": {"enabled": false}
  },
  "workspaces": {
    "project-a": {
      "root": "/absolute/path/to/project-a",
      "exec": {"enabled": false, "paths": [], "runners": []}
    }
  }
}
```

For **disposable test projects only**, an operator may explicitly enable
the global and per-Workspace flags, then configure e.g.
`paths: ["src"]` with `runners: ["src=direct"]` or
`runners: ["src=pipenv"]`. Runner paths must be within granted paths,
and hidden directories must be independently allowed.

## Important security boundary

**An Exec path grant is NOT an OS filesystem sandbox.** The scope limits
which project directory and Python script the Gateway will launch, but
authorized project code runs as the Gateway OS user and can itself access
other readable/writable files, launch child processes or use the network
within that user's privileges. Do not grant Exec to untrusted projects.
Workspace-specific routing must not be described as OS-level containment.

## What is verified vs still pending

The product candidate exercises real commands in disposable workspaces,
REST and MCP routing, strict input rejection, no-Exec defaults, busy
admission and close-drain leases. P3 follow-up tests additionally exercise
four distinct Worker leases rejecting a fifth, actual REST ASGI admission
with a real disposable child surviving simulated disconnect/cancelled
awaiter until controlled release, and cancelled MCP SDK tool dispatch with
a still-held synchronous Worker lease. These are **not** real TCP/Tunnel
disconnect, macOS ARM64 native or descendant-tree cleanup results.

It does **not** yet prove complete detached-descendant termination, actual
remote cancellation/disconnection behavior, crash/restart recovery,
cross-Workspace OS filesystem confinement, or bounded stop of an
uninterruptible command. Existing Legacy CommandRunner's timeout uses a
process-group KILL and waits for its leader; a returned result alone is
not proof that every descendant was reclaimed.

Before any production activation:
1. Independent fixed-Head Standards + Spec code review, with the real
   full GitHub CI jobs and exact Manifest verified.
2. Native macOS ARM64 end-to-end runs with actual timeout, blocked
   descendants, disconnect, cancellation and shutdown concurrency.
3. A clear fail-closed outcome when process cleanup cannot be confirmed.
   Do not claim STOPPED/clean merely from leader exit or killed PGID.

This candidate does not authorize Native C loading, any C3/B03-T01
research step, G2/G3/G4/G5, merge, release or deployment.
