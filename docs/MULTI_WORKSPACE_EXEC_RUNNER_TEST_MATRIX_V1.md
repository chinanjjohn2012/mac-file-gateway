# Multi-Workspace Runner R0 / R1 / Native / Strict test and evidence matrix V1

Status: DESIGN MATRIX; positive Exec = NOT_RUN/NOT_AUTHORIZED. Every code/CI outcome is tied to a future exact Base/Head/Tree and original Job/log; a design matrix is not a PASS.

Inherited current PR #76 Head: 0fc1ae245de7cb582a69162c79c201d15bfaa258. Related PR #77 Head c9b625e322697175887a4cedf23bc191dd8a91c3 is frozen research, B blocked for unproved feasibility, C targeted T0 plan only. PR #77 original CI failed at sse-starlette wheel-lock mismatch (locked 3.5.1, downloaded 3.6.0), downstream pytest/smokes NOT_RUN. No historical outcome transfers.

## Evidence risk levels

T0: static, deterministic Mock/fake, manifest/source verification; permitted within no-real-Exec scope.
T1: isolated non-destructive genuine REST/MCP, disposable Git/File and private-FS/owner-lock fixtures; must evaluate environment and policy before execution.
T2: controlled native child lifecycle, process termination, forced crashes, macOS VM stop and full descendant probes; requires separate exact disposable resource, timeout/watchdog, stop-identity, rollback and user authorization.
T3: user Mac/Tunnel, production, shared/high-impact operations; independent approval, NOT_AUTHORIZED.

## Contract traceability

| ID | Scope | Legal success | Illegal rejection / adversarial | Boundary / abnormal | Required evidence | Current |
| --- | --- | --- | --- | --- | --- | --- |
| R-C01 | F1 | valid direct/Pipenv preview | no ordinary apply before Worker/PREPARED/Popen | no-proof before busy; disabled/quarantine precedence | real REST+official MCP, worker and state witness | historical F1 only |
| R-C02 | policy | authorized cwd/argv/project/runner | bad cwd/argv, wrong workspace, client proof spoof | malformed types/zero quota | source/T0 + real ingress T1 | NOT_RUN new Head |
| R-C03 | adjacent | real Git apply + File Write in same Exec-disabled service | unauthorized Git/File denied | UNKNOWN Exec stays denied, unrelated actions work | disposable actual Git/File not mock | NOT_RUN new Head |
| R-C04 | launch | one qualified start per attempt | replay/duplicate ACK cannot re-run | start response lost and stale callback | T0 fake; later backend native | NOT_RUN |
| R-C05 | durable | fsync PREPARED before any possible launch | no launch on fsync/rename/temp trust failure | owner.lock duplicate/boot corruption | T0+real private FS | NOT_RUN new Head |
| R-C06 | Native | direct child and known original-group cleanup observed | never report all descendants proven | timed-out, cancelled, leader-exit | T2 macOS ARM64 | NOT_AUTHORIZED |
| R-C07 | Native limits | normal trusted Pipenv and Go output/exit | setsid/double-fork escape cannot be claimed clean | early orphan / continued work | T0 warning plus T2 native probe | NOT_AUTHORIZED |
| R-C08 | crash | reconciled authenticated attempt | no old pid signal / auto retry | before allocate, after start, during stop, final fsync lost | T0 mock, T2 true crash | NOT_AUTHORIZED native |
| R-C09 | identity | current generation can operate own domain | stale generation/wrong dev-ino or PID-reuse fails closed | ABA/old callback race | T0 + T2 if approved | NOT_RUN |
| R-C10 | Strict | OS-enforced domain retains arbitrary descendants | setsid/double fork/reparent/concurrent fork cannot escape | original leader exits; domain stops | platform mechanism + T2 independent observation | NOT_PROVEN |
| R-C11 | Strict | whole-domain stop/anti-restore evidence | requestStop accepted/heartbeat quiet alone insufficient | stop callback lost, image restore | T2 native and supported APIs | NOT_PROVEN |
| R-C12 | compatibility | host Native existing Pipenv, Python, Go, PATH, output/cwd | guest is not assumed host equivalent | native extension, file writeback, mount/IPC | real disposable project compatibility | NOT_RUN |
| R-C13 | transport | Direct + genuine REST/SDK MCP keep same gate | unauthorized profile/fallback never reachable | disconnect/cancel/shutdown Worker lease | T1 network; T3 Tunnel separately | NOT_RUN new Head |
| R-C14 | provenance | exact Head checkout/Tree/Manifest and pinned inputs | wheel lock substitution/import shadows denied | synthetic merge differs from Head | G05, original CI jobs, wheel/RECORD and G01-G08 if effective | NOT_RUN new Head |
| R-C15 | migration | old config continues default deny | v1 RETIRED cannot upgrade to F3 or clear UNKNOWN | unknown new state, binary downgrade | T0/T1 version fixtures | NOT_RUN |

## R0 review questions and acceptance

B and C independently examine: (1) explicit change proposed to historical D0 section 0.4; (2) whether Native limited residual risks and warnings are acceptable; (3) strict non-fallback; (4) durable identity/recovery and state migration; (5) error precedence and File/Git/Legacy adjacency; (6) actual future T2 experiments and operator recovery; (7) ability to falsify D1–D6. Each adds their own legal/illegal/boundary/exception counterexamples. No approval claimed by writing this matrix.

R0 requires only new exact-Head source and doc integrity, no code/runtime or dangerous native tests. It may receive TARGETED design PASS only if its defined documentation-only scope meets applicable rule and evidence criteria. B/C findings can instead BLOCK based on contractual ambiguity; A does not sign for them. **No R0 outcome alone qualifies positive Exec or R10 FULL.**

## R1 and later gates

R1: interface-only, no externally reachable positive path, full F1 default deny with real REST/MCP and same-service Git/File legal success; original Linux/macOS CI source identity, all tests and skips reported. R2/R3: trusted-native implementation with exact T2 authorization, actual process identity evidence and user acceptance of weaker cleanup; Strict R4/R5: independent D1–D6 real domain proof + verified compatibility, resources, recovery, B/C scope and integration acceptance.

Raw CI rule: Record PASS/FAIL/SKIP/NOT_RUN and cause, including dependency drift. Source/manifest success cannot turn downstream skipped tests green. Never relax wheel locks merely to make CI green; resolve the root cause in a separate reviewed Head. Old B/C reviews tied to earlier SHAs never become new PASS.

Prohibited here: gateway/** changes, actual Exec apply, host process/group signals, VM creation/stop, user Tunnel, production config, merge, deploy, tag, release and automated UNKNOWN reset.
