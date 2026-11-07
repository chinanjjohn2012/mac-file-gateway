# D6: Internal LBE launcher must validate plan shape before comparing values

TASK_ID: MULTI-EXEC-LBE-FIVE-DAY-CANDIDATE-20261105
REVIEW_ROUND: r004
STATUS: NONOPERATIVE_SAFE_T0 / LIVE_NATIVE_NOT_AUTHORIZED
REVIEW_TARGET: Internal launcher plan-field type validation before equality, with
test-first RED and retained negative counterexamples plus valid-path regression.
RULESET_ID: ICR-V2.0
HANDOFF_PROTOCOL_ID: GHRH-2.0
EVIDENCE_PROFILE_ID: ETP-V2.0

## Starting authority and original RED

PR114 r003 reviewed Head 7ff25bcbff1035bf3c825dc5b9ef46054876aa75
Tree 5e269af8f96456e3411047623f44e5b51222f8eb, B/C separate
TARGETED_REVIEW_PASS only for nonoperative D2-D5 T0/design.
PR98 lightweight product, PR102 stronger OFFLINE_ONLY Gate B and current
F1 positive denial / D0 / Phase1 / G05 / R004 remain unchanged.
The user has not granted network-capable trusted PRODUCT_T1, real Go/Pipenv
or a positive D0 exception. Five-day sprint direction does not waive gates.

Test-first RED distinct Head 79259398b7d2752aaa34e67c3ccd3ca1035b8b65
Tree 7ec1494d57a5c8950c3ebae0e38d2a120e0ecb63:
GitHub Actions Run 42171744046 Job 127740929758; G05 checked-out
exact Head+Tree, 291 Git blobs and 290 Manifest records passed.
Original pytest: 4 failed first-party forged internal plan cases,
2210 passed, 19 skipped, 1 warning, 52 subtests passed. The forged
LbeWorkPlan allowed a user-defined comparison hook to influence the
internal equality identity check so execution reached a monkeypatched
Popen trap. No native child was created, no Go/Pipenv was launched;
these are internal direct launcher inputs, not a claimed public F1 bypass.
Downstream smoke/final manifest NOT_RUN due intentional RED pytest failure.

## D6 repair and qualification

gateway/lbe_native_launcher.py now calls the exact LbeWorker._check_plan
type+argv+cwd+runner validation before any caller-controlled attribute
comparison, and translates any invalid-plan result into the trusted
LbeNoChildStarted pre-spawn denial. It retains re-prepare-of-authoritative
plan immediately before launch, exact equality check only after primitive
validation, no shell and hard Go/Pipenv source denial. No new Popen path,
public flag, network power, approval or product positive Exec is added.

The first-party negative test uses same real WorkspaceService context,
revalidated private state and internally prepared valid Python plan.
Forged workspace, cwd, runner, runner_project, requested_argv and
effective_argv variants must raise LbeNoChildStarted BEFORE invoking
any hostile equality or reaching monkeypatched Popen. Existing
legitimate Python-only hosted fixture path and public Direct/REST/MCP
preview+positive-denial behavior are required adjacent regressions.
The new Head original CI must be read before any handoff PASS claim.

## Explicit scope and blockers

Current real product and Go/Pipenv native T1 remain NOT_RUN.
Three chosen Go files' read-only digests are not loaded source closure.
Even a passing guarded launcher check does not qualify a real compiler,
virtualenv, site, network isolation, OS resource enforcement, source
publisher, pathname race, original child/reaper or positive integration.
No destructive PID/PGID signal, shared/user Mac/Tunnel/production,
merge, release or deployment is authorized.

EVIDENCE_STATUS: D6_R004_ORIGINAL_HEAD_CI_PASS_OBSERVED
ORIGINAL_D6_HEAD_SHA: f0e94679242412e1a14bab1e05d87a024e146c61
ORIGINAL_D6_HEAD_TREE: a77978fdbd05154f048f72206f1e8681a8296962
ORIGINAL_D6_CI: https://github.com/chinanjjohn2012/mac-file-gateway/actions/runs/42172004726/job/127741766040
ORIGINAL_D6_RESULT: 2216 passed, 19 skipped, 1 warning, 52 subtests; 22 of 22 job steps success; G05 292 blobs and 291 Manifest. HISTORICAL evidence for any later Head.
INTEGRATION_STATUS: NOT_TESTED
R10_STATUS: BLOCKED
FULL_CODE_REVIEW_PASS: NOT_ISSUED
NEXT_ROLE: B Standards and C Spec independent r004 TARGETED internal
launcher input guard and unchanged product F1/native Go/Pipenv hard stops.
Further native/product implementation needs separate exact approved
operator-risk contract and runnable source/runner/fixture scope.
