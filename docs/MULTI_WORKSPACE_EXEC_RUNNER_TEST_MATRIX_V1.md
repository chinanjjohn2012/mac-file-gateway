# Multi-Workspace Runner R0 / R1 / Native / Strict test and evidence matrix V1

Status: r002 corrected DESIGN MATRIX after independent r001 B/C BLOCKED; positive Exec = NOT_RUN/NOT_AUTHORIZED. R0 fixes are design obligations, not executed RED/GREEN. Every code/CI outcome is tied to a future exact Base/Head/Tree and original Job/log; a design matrix is not a PASS.

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
| R-C07 | Native limits | future limited completion only after leader+original group authenticated absent and no positively seen detached survivor | **positively observed** detached child => UNKNOWN/global quarantine; never F3 proof | **unobserved** detached remains possible and is disclosed risk | T0 case table; T2 native probe separately authorized | NOT_AUTHORIZED |
| R-C08 | crash | reconciled authenticated attempt | no old pid signal / auto retry | before allocate, after start, during stop, final fsync lost | T0 mock, T2 true crash | NOT_AUTHORIZED native |
| R-C09 | identity | current generation can operate own domain | stale generation/wrong dev-ino or PID-reuse fails closed | ABA/old callback race | T0 + T2 if approved | NOT_RUN |
| R-C10 | Strict | OS-enforced domain retains arbitrary descendants | setsid/double fork/reparent/concurrent fork cannot escape | original leader exits; domain stops | platform mechanism + T2 independent observation | NOT_PROVEN |
| R-C11 | Strict | whole-domain stop/anti-restore evidence | requestStop accepted/heartbeat quiet alone insufficient | stop callback lost, image restore | T2 native and supported APIs | NOT_PROVEN |
| R-C12 | compatibility | host Native existing Pipenv, Python, Go, PATH, output/cwd | guest is not assumed host equivalent | native extension, file writeback, mount/IPC | real disposable project compatibility | NOT_RUN |
| R-C13 | transport | Direct + genuine REST/SDK MCP keep same gate | unauthorized profile/fallback never reachable | disconnect/cancel/shutdown Worker lease | T1 network; T3 Tunnel separately | NOT_RUN new Head |
| R-C14 | provenance | exact Head checkout/Tree/Manifest and pinned inputs | wheel lock substitution/import shadows denied | synthetic merge differs from Head | G05, original CI jobs, wheel/RECORD and G01-G08 if effective | NOT_RUN new Head |
| R-C15 | migration | old config continues default deny | v1 RETIRED cannot upgrade to F3 or clear UNKNOWN | unknown new state, binary downgrade | T0/T1 version fixtures | NOT_RUN |

## r002 P2 closing counterexamples — future RED/GREEN predicates, not run now

| Case | Future permitted/legal path | Illegal/boundary rejection and expected status | Evidence phase |
| --- | --- | --- | --- |
| R-C16 TRUST-MUTABLE | Operator-local explicit, versioned consent for `native_limited+mutable_workspace` bound to root dev/ino+Exec scope/backend; approved File Write changes script then next command remains within **explicitly accepted future-mutable scope** | Without owner approval, missing consent or after local revocation => no launch/PREPARED; wrong root, expanded paths or backend identity => re-consent required; no automatic hash-based safety claim | T0 mock first; T1 Git/File on disposable service; actual Exec only separately authorized T2 |
| R-C17 TRUST-GIT/PIPENV | With valid approved mutable-scope consent, Git HEAD changes, Pipfile/dependency mutation and local source edits intentionally do not auto-revoke consent (operator assumes risk) | Strict profile cannot borrow Native consent; no remote field/header/test_grant can grant it; runner cannot claim unchanged byte identity | T0 state cases; T1 real disposable File/Git; T2 Mac integration later |
| R-C18 KNOWN-DETACHED | After Native leader/group evidence and **no positive detached survivor observation**, only future approved mode may RETIRED_LIMITED with full_tree=not_proven | Positively observed surviving setsid/double-fork descendant => UNKNOWN + global quarantine even if group absent; no clean success and no new Exec | T0 injected observations; T2 real native child with watchdog and separate authority |
| R-C19 UNKNOWN-IDENTITY | A bound, live signal target may be used only under supported macOS race-resistant ownership mechanism | Group disappears between verify and signal, stale PGID aliases unrelated process => **no signal**, UNKNOWN/quarantine; no blind kill after crash | T0 simulated ABA; separate T2 native no-collateral signal |
| R-C20 QUOTA-LEAK | Within approved limited contract, 1/4 controls only admitted Workers | Repeated unseen detached survivors can accumulate; claim of total-process cap is FALSE. Known survivor blocks new admission even after Worker slot releases; unresolved counted separately | T0 source risk analysis; T2 bounded OS observation later |
| R-C21 BOOT/MIGRATION | Current v1 F1 deny-only stays intact; future v2 limited marker has distinct profile, owner generation and evidence scope | v1 group-only RETIRED, v2 unknown/mixed/old mode/downgrade may not auto-qualify Native/Strict/clear UNKNOWN | T0 schema fixtures and future private-FS T1 |
| R-C22 RESULT-STATUS | Separate command exit, limited cleanup result and delivery status; future Native cap `native_original_group_limited` only with qualified consent | Zero exit + unknown cleanup not clean; `full_tree_qualified` never from native; REST/MCP/info/health status parity, strict no fallback | T0 and T1 genuine transport after product PR |
| R-C23 OWNER-DECISION | Product owner formally approves mutable Workspace + actor/daemon residual risk before Native code/admission | If owner declines or chooses revision-pinned alternative, Native remains NO-GO and requires a redesigned contract; no B/C design PASS substitutes for user authorization | Explicit user approval, fixed-doc B/C review, not a test |

**Known/not-known distinction:** An affirmative observation of a live detached child is a hard safety signal. Mere failure to observe one with a group-only tracker is NOT proof of no detached children. Current D0 §5 / §7J retains hard UNKNOWN quarantine on the former; a separately reviewed Native Limited agreement may later accept residual uncertainty in the latter. B/C independently invent additional counterexamples. R0 has executed none of these tests.

## R0 review questions and acceptance

B and C independently examine: (1) explicit change proposed to historical D0 section 0.4; (2) whether Native limited residual risks and warnings are acceptable; (3) strict non-fallback; (4) durable identity/recovery and state migration; (5) error precedence and File/Git/Legacy adjacency; (6) actual future T2 experiments and operator recovery; (7) ability to falsify D1–D6. Each adds their own legal/illegal/boundary/exception counterexamples. No approval claimed by writing this matrix.

R0 requires only new exact-Head source and doc integrity, no code/runtime or dangerous native tests. It may receive TARGETED design PASS only if its defined documentation-only scope meets applicable rule and evidence criteria. B/C findings can instead BLOCK based on contractual ambiguity; A does not sign for them. **No R0 outcome alone qualifies positive Exec or R10 FULL.**

## R1 and later gates

R1: interface-only, no externally reachable positive path, full F1 default deny with real REST/MCP and same-service Git/File legal success; original Linux/macOS CI source identity, all tests and skips reported. R2/R3: trusted-native implementation with exact T2 authorization, actual process identity evidence and user acceptance of weaker cleanup; Strict R4/R5: independent D1–D6 real domain proof + verified compatibility, resources, recovery, B/C scope and integration acceptance.

**Independent r001 findings driving r002:** B-P2-01 and C-P2-NATIVE-RETIRE-02 require a normative known-survivor UNKNOWN table; C-P2-NATIVE-TRUST-01 requires a concrete operator code-trust choice. This r002 proposal chooses mutable Workspace candidate A as a design for **future owner approval**; it does not assert that approval. B-P3 signal TOCTOU and accumulation risk remain future no-go gates absent physical platform proof. There are no current-source product-code positive Exec fixes in this design PR.

Raw CI rule: Record PASS/FAIL/SKIP/NOT_RUN and cause, including dependency drift. Source/manifest success cannot turn downstream skipped tests green. Never relax wheel locks merely to make CI green; resolve the root cause in a separate reviewed Head. Old B/C reviews tied to earlier SHAs never become new PASS.

Prohibited here: gateway/** changes, actual Exec apply, host process/group signals, VM creation/stop, user Tunnel, production config, merge, deploy, tag, release and automated UNKNOWN reset.
