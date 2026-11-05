# D4 candidate: trusted local_best_effort product test permission profile (PROPOSED)

TASK_ID: MULTI-EXEC-LBE-FIVE-DAY-CANDIDATE-20261105
CONTRACT_ID: MWE-LBE-TRUSTED-PRODUCT-T1-PROFILE-R001
REVIEW_STAGE: D4_CONTRACT_PROPOSAL
REVIEW_SCOPE: TARGETED DESIGN (not live native T1, not full product)
STATUS: NONOPERATIVE_PROPOSAL / NOT_EFFECTIVE / NATIVE_NOT_AUTHORIZED
RULESET_ID: ICR-V2.0
HANDOFF_PROTOCOL_ID: GHRH-2.0
EVIDENCE_PROFILE_ID: ETP-V2.0

## Goal, applicable authority, and explicit separation

This D4 profile proposes a disposable-hosted test of the lighter
local_best_effort PRODUCT_T1, distinct from the PR102 SOURCE_TOOLCHAIN_T1
OFFLINE_ONLY research experiment. It preserves the PR98 r002 product's
operator-trusted-code model, one original child per Workspace, maximum
four original children in a service, direct-child observability without
full descendant cleanup, no F3, no rollback, and no OS sandbox promise.

Authority remains PR98 r002 fixed design GitBlob
9e6622401b198138039c692efe91fba1a8d06891;
PR102 r002 existing Gate B GitBlob
7db3b77aadca8b0c284e28fa5ee64e315e9275d2;
PR113 r001 independently B/C TARGETED PASS (D1 only),
fixed Head ca90cf30095695479615e475b8440e09f02f34d9,
Tree 7ce5e1f0ba2ce401d51312ad46512dc285e0523c;
operative D0/F1/Phase1/G05/R004 and old UNKNOWN/quarantine unchanged.
No prior PASS or prior Gate A/B approval grants this new profile.

## A. Restricted future live test envelope (PROPOSED, NOT GRANTED)

- Target: one fresh, GitHub-hosted disposable macOS 15 ARM64 runner,
  no user Mac, no Tunnel, no shared/production runner, credentials,
  real data, secrets or writable production mounts. Repo checkout must
  use exact immutable approved Head, credentials disabled, G05 before
  dependency installation/import and a pinned tree/Manifest.
- Intended code: separately reviewed PRODUCT_T1 runnable first-party
  WorkspaceService+Worker+NativeLauncher snapshot, not a standalone
  go command as substitute. No test-only env/header/client override
  can grant public positive Exec. Exact commit/tree, Go toolchain bytes,
  private fixture/Go compiler+linker, Pipenv CLI, CPython/venv/Pipfile.lock,
  module and site loaded sources MUST be resolved and pinned BEFORE
  owner gives permission. THESE INPUTS ARE NOT YET FIXED.
- Allowed future commands, only against explicitly constructed fresh
  disposable first-party fixtures:
  python -m pytest -q; python -m compileall;
  pipenv run python -m pytest -q; go test ./...; go vet ./...;
  go build -o bin/app ./cmd/app.
  No go run, shell, arbitrary executables, network fetching,
  shell-derived hooks or user-selected Python -c.
  First-party preview must match the selected real command contract.
- Proposed limits: at most one product test job concurrently, total
  job <=20 minutes, each planned original child <=120 seconds,
  actual public Worker timeout <=300 seconds, one active original child
  per Workspace and max four per service; raw output capture <=48000
  bytes per stream, public redacted text <=48000 characters per
  stream. Internal streams, child wait, cancellation, timeout and
  output_complete must truthfully reflect observed evidence.
  CPU/RAM and *whole process tree* limits are NOT specified as
  enforceable macOS limits here: they require a separate ability/budget
  decision before any test falsely claiming physical containment.
- Network: intentionally NO OFFLINE_ONLY claim. Trusted selected code
  may have outbound access and same-UID filesystem/process powers.
  No production token or confidential network target is allowed.
  A's Go environment hint GOPROXY=off/PIP_NO_INDEX=1 prevents neither
  code networking nor unexpected module/loader execution and does
  NOT satisfy PR102's offline source profile.
- Prelaunch: owner locks old v1 private ExecStateStore, checks old
  PREPARED/RUNNING/UNKNOWN and corrupted/untrusted state, effective
  v2 paths, no shell/Go toolhook, fresh closed child Go/Pipenv env,
  exact no-follow source bytes and chosen interpreter, safe cwd and
  -o path. Python/Go/Pipenv preflight must be repeated at actual
  launch. A static positive PLAN is not permission to spawn.
- Timeout/crash/lost ACK: NEVER send signal to unknown PID/PGID,
  never fake complete process-tree cleanup, never auto-unquarantine
  or replay. Direct child and descendants can survive; client
  retries after a lost ACK, or after Gateway restart, can duplicate
  irreversible actions. This is a user-risk decision, not a bug
  covered by a test GREEN badge.

## B. Explicit required review and owner decision

1. Freeze and independently review THIS exact version against PR98/102
   with B Standards and C Spec. Both must assess host/network/source/
   process residual risks and scope, not claim approval from D1 T0 PASS.
2. User must explicitly approve the precise version and residual
   outbound-network/host-access/crash-replay risks *and* a runnable
   Head/Tree, loader/source/venv identities, resource envelope and
   authorized commands. General five-day direction alone is not
   sufficient consent.
3. Only a separately reviewed current-Head implementation with a
   non-client-mintable authorization boundary may run positive native
   Go/Pipenv PRODUCT_T1 on the approved disposable runner. A cannot
   lower the existing PR102 standalone SOURCE_TOOLCHAIN_T1 Gate B by
   renaming it to PRODUCT_T1.
4. If owner or B/C rejects, source inputs are missing, actual
   platform/environment is wrong, or the resource/loaded-source
   checks cannot be established, DO NOT RUN. Report exact
   NOT_RUN / BLOCKED status and continue nonoperative source work.

## C. Current D4 code/test facts and open blockers

- T0 fix prevents a self-consistent but outside-private GOROOT,
  Go executable and PATH from passing the typed environment candidate
  validation. This is not physical OS proof and does not authorize
  an actual compiler/toolchain.
- Same live WorkspaceService accepts Go test/vet/build and
  Python Direct/Pipenv preview from Direct, REST and official MCP;
  all ordinary positive requests still F1 DENY BEFORE Worker/Popen,
  without writing new Exec attempts. These Linux T0 tests use
  no positive native command. Existing physical Git and File
  independently authorized behavior is unchanged.
- Real macOS Go/Pipenv, source/native/product T1, direct-child
  original OS lifecycle for these commands and full positive
  Direct/REST/MCP integration: NOT_RUN.
- PR112 Seatbelt research remains separate; this proposal
  explicitly does not inherit its OS security promise.

INTEGRATION_STATUS: NOT_TESTED
R10_STATUS: BLOCKED
FULL_CODE_REVIEW_PASS: NOT_ISSUED
GATE_B_ALTERNATIVE_OWNER_APPROVAL: NOT_GIVEN
NATIVE_GO_PIPENV: NOT_RUN
NEXT_ROLE: A finish concentrated safe candidate, then B/C independent
milestone review and user exact revised D4 contract/fixture decision.
