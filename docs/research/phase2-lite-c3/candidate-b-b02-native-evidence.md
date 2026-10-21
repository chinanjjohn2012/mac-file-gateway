# Candidate B B-02 — Darwin isolated Controller-survives-TERM native evidence

**Status: AUTHOR-SIDE NATIVE RED→GREEN COMPLETE FOR B02-T01...T08; INDEPENDENT FIXED-HEAD STANDARDS/SPEC CODE REVIEW PENDING. NOT G2.**

- **Design reviewed:** [PR #30](https://github.com/chinanjjohn2012/mac-file-gateway/pull/30) immutable Head `804168047895994fcbaeed97c334d762f75dbd83`, independently supplied Standards PASS / Spec PASS, P2-01/P2-02 CLOSED. Base B-01 implementation PR #29 code-review PASS at `f84d2d2abdec76dd7e0f34cb19d78250433b8087`.
- **Implementation Draft PR:** [#32](https://github.com/chinanjjohn2012/mac-file-gateway/pull/32), stacked **only on reviewed PR #30 Head**; native source and Runner are **new isolated research files** and do not modify Gateway products or PR #29 code. The first full 8-mode implementation commit is `fdf0b5ded249f1fa38629e24e03f22d8d66d6758`. Final documentation-only Head must run its own CI and receive independent code review.
- **Scope:** fresh test-owned `0700` process roots and fixed named modes only, no caller-supplied existing PID/PGID, command, external binary or Workspace; Darwin native **SIGTERM** targeted once to the newly created held Anchor group by the sole Owner. **No SIGKILL / B-03**; `reuse_proven=0`, `g2_qualified=false`.

## A. Verifiable test-first RED → native implementation

| Stage | Fixed code Head and independent Action evidence | Interpretation |
| --- | --- | --- |
| **B02-R1 contract RED** | `78f52b8145f7f740c8c4c26e470c2b12985083b1`; [macOS-15 ARM64 #39539807394](https://github.com/chinanjjohn2012/mac-file-gateway/actions/runs/39539807394): Python 3.13 and 3.14 each **6 failed / 3 passed**; [Linux #39539844427](https://github.com/chinanjjohn2012/mac-file-gateway/actions/runs/39539844427): **6 failed / 870 passed / 10 skipped / 1 warning** | RED is due to **absent standalone C Helper and Python Driver**; **not** Darwin signal-race reproduction |
| **T01–T06 synthetic native first GREEN** | `7dc870884fed6db2c3ae54a8edc31935f9045c28`; [ARM64 #39540387014](https://github.com/chinanjjohn2012/mac-file-gateway/actions/runs/39540387014): **both Python 3.13 / 3.14 = 9 passed**; [Linux #39540391888](https://github.com/chinanjjohn2012/mac-file-gateway/actions/runs/39540391888): **876 passed / 10 skipped / 1 warning** | One true, limited SIGTERM/Worker `waitpid`; two adverse inheritance negative controls; Controller/Anchor identity and deadline refusals; three mutation checks |
| **T07–T08 expanded contract RED** | `623dbb97cae8957437951bf4de219e419d77bef2`; [ARM64 #39540692487](https://github.com/chinanjjohn2012/mac-file-gateway/actions/runs/39540692487): **each 4 failed / 6 passed**, missing Canary and post-`waitpid` result-loss mechanisms; [Linux #39540696907](https://github.com/chinanjjohn2012/mac-file-gateway/actions/runs/39540696907): expected contract failure | Genuine contract expansion RED; not evidence of process-group collision |
| **Eight-mode native GREEN** | `fdf0b5ded249f1fa38629e24e03f22d8d66d6758`; [macOS-15 ARM64 #39540939902](https://github.com/chinanjjohn2012/mac-file-gateway/actions/runs/39540939902): **both Python 3.13/3.14 = 10 passed each**; [PR-native #39540945927](https://github.com/chinanjjohn2012/mac-file-gateway/actions/runs/39540945927): SUCCESS; [Linux #39540945973](https://github.com/chinanjjohn2012/mac-file-gateway/actions/runs/39540945973): **877 passed / 10 skipped / 1 warning** | All 8 original design modes yielded the expected native result, 3 mutations were detected and no Action log reported `Terminate orphan process:`; Smoke, Python compileall and Manifest PASS |

Every native Job actually runs a freshly compiled C Helper with direct kernel `posix_spawn`, `getpgid`, `getsid`, `proc_pidinfo(PROC_PIDTBSDINFO)`, `kill(-owned_anchor_pgid,SIGTERM)` (only when eligible), and legal direct-child `waitpid`. This is not a string-only simulation. Both tested Python versions executed all named modes and standalone fault variants.

## B. Fixed native mode matrix (both macOS ARM64 versions)

| Design mode | Observed test-owned evidence | Strict classification |
| --- | --- | --- |
| B02-T01 `term-positive` | Controller's real PGID equals its PID and differs from held Anchor; Controller truly set, observed and reported `SIGTERM=SIG_IGN` **and blocked TERM** before Worker spawn. Worker READY confirms default, unblocked TERM; Worker ARMED event and Owner identity check precede **one** successful group SIGTERM; Controller's legitimate Worker `waitpid` proves `WIFSIGNALED && WTERMSIG=SIGTERM`; `cleanup_complete=1` | `POSITIVE_EXPERIMENT` |
| B02-T02 `missing-sigdef` | Same **observed adverse Controller inheritance** but Worker reports `worker_default_term=0`, `worker_unblocked_term=1`; TERM action happened, Controller reaps Worker's cooperative normal exit, **not** a signal exit; cleanup verified | `EXPECTED_BLOCK` |
| B02-T03 `missing-sigmask` | Controller still truly ignored/blocked TERM before Worker spawn; Worker reports `worker_default_term=1`, `worker_unblocked_term=0`; group TERM action happened, no fabricated Worker SIGTERM exit; cooperative `waitpid` & cleanup | `EXPECTED_BLOCK` |
| B02-T04 `controller-group-regression` | Controller's PGID **not** its PID, even though outside Anchor group; Owner rejects **before Worker spawn/gate** with `term_attempts=0`, `cleanup_complete=1` | `SAFE_REFUSAL` |
| B02-T05 `anchor-lost-before-term` | Owner first cooperatively retires and **reaps** held Anchor, observes identity no longer valid, never attempts group TERM (`term_attempts=0`), cleans direct children | `SAFE_REFUSAL` |
| B02-T06 `deadline-before-term` | Test passes *real* Worker ARMED barrier, then waits to **derived admission cutoff** while original global deadline is still live. Native TERM admission function rejects with `term_attempts=0`, `admission_cutoff_expired=1`, `outer_live_at_refusal=1`; no extra cleanup clock; lawful cooperative Worker wait, Owner reaps and FD closure within original budget, `cleanup_complete=1` | `EXPECTED_BLOCK` |
| B02-T07 `canary-isolation` | Owner creates a **second independent test-owned PGID** whose default/unblocked TERM disposition and live identity are verified; Worker in original target receives real TERM, Controller reaps it, and native Owner independently confirms Canary PG leader remains alive; later cooperatively reaps Canary; `canary_survived=1` | `POSITIVE_EXPERIMENT` |
| B02-T08 `controller-result-lost` | Controller's actual Worker `waitpid` succeeds before its Final status is deliberately omitted. A private test-only marker `C3B02_AFTER_WAIT_BEFORE_FINAL` confirms the **controlled injection point** but is **not trusted Worker exit evidence**. Owner sees EOF without legal Final and outputs **`worker_result_unknown=1`, `worker_observed_term=0`, `controller_waited=0`, `result_lost_after_wait=1`, `cleanup_complete=0`** while also recording `owner_children_reaped=1`. No promotion of EOF/TERM_SENT/audit marker to Worker result or independently verified cleanup | `EXPECTED_BLOCK` with `UNKNOWN / UNRESOLVED` |

### Evidence trust boundaries

The Owner owns and directly reaps Anchor / Controller / Canary; Controller alone is Worker parent and waiter. The research-only private pipes prevent Worker from writing trusted Owner control messages through stdout, but this does **not** prove a production-grade authenticated IPC transport or arbitrary process-tree lifecycle.

T08 distinguishes **the actual synthetic cleanup observation** (all test-owned processes returned and Owner's direct children were successfully reaped) from **the evidence qualification** (Owner has no legal Worker exit status; `cleanup=UNRESOLVED`). `C3B02_AFTER_WAIT_BEFORE_FINAL` is a controlled fault **timing marker**, not an alternate Worker status channel. A separate future before-Wait Controller crash would require its own contract and could leave arbitrary descendants unobserved; this study does not claim otherwise.

Two user-space admission checks precede native group TERM: live held Anchor / Controller native identity and monotonically bounded `term_admission_cutoff` plus `outer_deadline`. `term_attempts` increments before the signal syscall. There remains an unavoidable **non-atomic window between user-space eligibility and kernel `kill`**, and **no real PID/PGID numeric reuse** is reproduced. The one Canary shows *this test-owned independent group* survived, not the safety of arbitrary other host groups.

Owner and Controller explicitly ignore SIGPIPE so a broken control pipe returns a detectable write error rather than terminating those processes by default. T08 is a deliberate Controller final-result omission **after** Worker wait; a full injected EPIPE failure-path suite and arbitrary FD leak audit are not yet proven. Synthetic Worker/Anchor/Controller self-expiry bounds and private gate cleanup were observed for these modes, but cannot substitute for generic subtree cleanup, stdout/stderr drain, exit ownership at scale or real Gateway shutdown.

## C. Three independent native mutations

1. `C3B02_MUT_OMIT_SIGDEF`: on T01's **truly ignored/blocked TERM** Controller baseline, omit Worker's disposition restoration. Worker READY reports `default_term=0`, `unblocked=1`; native Owner refuses eligibility, **zero** group attempts and synthetic cleanup before printing strict controlled mutant evidence.
2. `C3B02_MUT_OMIT_SIGMASK`: separately omit Worker's unblocking, observe `default_term=1`, `unblocked=0`; same fail-closed outcome with distinct expected marker.
3. `C3B02_MUT_CTRL_GROUP`: omit Controller's own PGID creation; actual `getpgid(controller)!=controller_pid` makes Owner refuse before Worker launch, `term_attempts=0`.

All three throwaway binaries were compiled and executed separately on **both ARM64 Python 3.13/3.14**, with exact expected fail reasons; the native Driver reports `C3B02_MUTATIONS_DETECTED=true`. The research source and fixed production Gateway remain unchanged by each throwaway mutation.

## D. Final gate and external code review requirements

**Current decision: `PARTIAL_B02_TERM_NOT_G2`** (author-side native research evidence only). **Do not label B02-R4 Standards / Spec CODE PASS before a separate independent read-only review against the eventual final fixed Head and original Job logs.** PR #32 remains Open/Draft/unmerged. GitHub Actions hosted runs are evidence for these specific macOS builds, not a formal proof across Darwin versions.

Independent review should particularly inspect: correct source of Worker status (Controller direct `waitpid`), exclusive Anchor owner and no lost identity signaling, SIGTERM default+mask restoration under *adverse* inheritance, real Canary independence, first admission cutoff versus unchanged overall cleanup deadline, fault marker not becoming an exit result in T08, trust and inheritance of controlled pipes, SIGPIPE/EPIPE failure handling, deadline-bounded abnormal cleanup, actual action-vs-attempt-vs-exit separation, orphan cleanup in original CI and strict mutation proof.

B-03 forced group KILL **NOT AUTHORIZED**. True PGID reuse / kernel-atomic group authority, universal descendants, Direct/Pipenv, full stdout/stderr, Permit/Lease lifecycle, real ExecSupervisor, REST/MCP Multi exec and G2/G3/G4/G5 remain **BLOCK**. Do not merge research PRs, update `release/ms1`, restart Gateway or deploy.
