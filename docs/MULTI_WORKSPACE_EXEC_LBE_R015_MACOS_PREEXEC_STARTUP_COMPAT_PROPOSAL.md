# R015 DESIGN-014: macOS PREEXEC startup compatibility design candidate

DESIGN_ID: MWE-LBE-R015-MACOS-PREEXEC-STARTUP-COMPAT-DESIGN-014-CANDIDATE
REVIEW_ROUND: D4-R015-MACOS-PREEXEC-STARTUP-DESIGN-014
REVIEW_TARGET: TARGETED, nonoperative macOS PREEXEC startup environment only
REVIEW_SCOPE: TARGETED
STATUS: PROPOSED_NOT_EFFECTIVE
PARENT_CONTRACT: MWE-LBE-R010-AUTHORITY-CHAIN-DESIGN-013-CANDIDATE
PARENT_CONTRACT_GIT_BLOB: f57e39543a6fe3d64fe99b8669fc7da854b93a64
EXISTING_OWNER_SCOPE: PR114 issuecomment-6740275850 A1+B1 SOURCE + SAFE T0 ONLY
RULESET_ID: ICR-V2.0
HANDOFF_PROTOCOL_ID: GHRH-2.0
EVIDENCE_PROFILE_ID: ETP-V2.0
CURRENT_B_DESIGN_REVIEW: NOT_ISSUED
CURRENT_C_DESIGN_REVIEW: NOT_ISSUED
USER_APPROVAL_FOR_CHANGE: NOT_ISSUED

This is a NEW PROPOSAL, not a change to the effective source gate or the
existing DESIGN-013. No PROD/T1/live-OIDC permission follows from this text.
The exact 18+2 launch environment, exact five-key helper, closed child
environment and old D0/F1/R006/PR98/PR102 denial rules remain unchanged.
If the design is not explicitly approved, the only valid behavior is DENY.

## 1. Observed problem; do not infer origin

On GitHub-hosted macos-15-arm64, the current SAFE T0 first invokes the
reviewed 18+2 PREEXEC environment with absolute /usr/bin/env -i. When the
launched Python interpreter inspects os.environ, all nine observed candidate
invocations contain one additional key name __CF_USER_TEXT_ENCODING, no
missing prescribed keys and zero other extra names. The workflow fails
closed as R010_PREEXEC_PYTHON_EXACT_ENV_UNAVAILABLE.

Original sources:
- PR114 macOS Run 43267616793 / Job 131355309056 on Head db26685686f0815c1ded30564df08465bb127d1b.
- PR114 macOS Run 43330917456 and 43331591739 on later exact Heads.
- PR114 B preliminary independent review 5883671361: findings
  B114-PREEXEC-EXACT-ENV-P2-01 (post-launch extra key) and
  B114-PREEXEC-EXACT-ENV-P2-02 (unverified Python executable/loader identity).
- Linux source SAFE T0 on Head 2fd06f59052f6dbd0aac057ec15eecf9858649fd,
  Run 43334429542 / Job 131586913918: 4110 passed, 19 skipped;
  this is NOT macOS startup or native product qualification.

The value, provenance, injection time and injected-code identity have NOT
been observed or independently verified. Python os.environ is a POST-startup
observation; it alone cannot distinguish runtime, dyld/CoreFoundation,
loader, interpreter or other source. Do NOT label the key as OS-origin proven.

## 2. Explicit decision alternatives

Option A -- RETAIN STRICT DENY. Preserve DESIGN-013 exact 20-key gate
without exception. The observed macOS host cannot satisfy its positive
PREEXEC path. This remains the default on lack of evidence or approval.

Option B -- PROPOSED LIMITED STARTUP-ORIGIN EXCEPTION. This option can be
considered by B/C only if ALL stage identities, provenance and value
conditions below are specified and independently shown satisfiable.
It cannot be implemented or enabled merely because the key name matches.

E0, ORIGINAL PREEXEC LAUNCH INPUT: an independently trusted entry witness
proves the precise execve environment has the DESIGN-013 prescribed
18+2 key/value pairs, and nothing else, BEFORE the target interpreter
or its libraries can run. It binds current Job, frozen workflow,
single source-locked executable/loader graph and immutable source identity.
GitHub env logs, a caller-provided mapping or Python os.environ alone are
not a trusted E0 witness.

E1, PYTHON POST-EXEC / PRE-PRODUCT-IMPORT: only following a verified E0
witness and a fixed interpreter/loader, a single exact extra key name
__CF_USER_TEXT_ENCODING may be investigated as a startup-only candidate.
Any additional/missing name, unknown origin, unproven value or mismatched
source identity => DENY. Its bounded value grammar AND source provenance
must be specified in a separately frozen version before any positive
implementation. Existing raw logs show the name ONLY; no value grammar
or injection provenance is being invented here.

E2, POST-SCRUB: destroy SSH_AUTH_SOCK, ACTIONS_ID_TOKEN_REQUEST_URL,
ACTIONS_ID_TOKEN_REQUEST_TOKEN, raw OIDC JWT and other selectors and
remove any strictly verified E1-only key BEFORE importing gateway/product.
Recheck the exact five helper keys PATH=/usr/bin:/bin,
HOME=<pinned private>, TMPDIR=<pinned private>, LANG=C, LC_ALL=C.
Unexpected E1 reinjection after scrub, scrub error or any selector leak
=> DENY; never fall back to helper environment inheritance.

E3, PRIVATE PRODUCT CHILD: its separate exact recipe may not inherit
any E0/E1 key, agent socket, OIDC selector, ambient env or credential
under an alias. No PRODUCT Popen or T1 until separately independently
reviewed, source-qualified and freshly Owner-granted.

The future startup witness may require a small source-locked native
exec-replacement bootstrap. This is a DESIGN POSSIBILITY ONLY:
its build, binary, loader, source, trusted syscall trace and execution
must be independently qualified and separately authorized. It cannot be
silently inserted as a new helper or claim full OS-image attestation.
It must never access SSH-agent, autofs targets, live OIDC or user Mac
without explicit applicable authorization.

## 3. Negative, legitimate, boundary and adjacent acceptance matrix

Case | Proposed outcome | Evidence requirement
--- | --- | ---
Trusted E0 20 + pinned interpreter + independently proven E1 origin/value | E1-only exception, E2 exact five, still DENY PRODUCT_T1 | Fresh qualified original macOS SAFE T0; currently NOT_RUN
E0 includes spoofed __CF_USER_TEXT_ENCODING or other key | DENY before runtime; no foreign child | Synthetic plus trusted E0 evidence
E0 missing/renamed prescribed key or changed OIDC/Job/Head | DENY, no legacy fallback | SAFE T0
E1 has two extras, LC_CTYPE/SDKROOT, a proxy, or wrong/malformed value | DENY; never add broad __* allowlist | SAFE T0
Different interpreter/dyld binary or shadowed import path | DENY, no first-passing unpinned candidate | Pinned binary + loader identity proof
Valid E2 five-key map without independent E0 witness | DENY; E2 is insufficient | Independent negative SAFE T0
E1 key or any credential selector reappears after scrub | DENY; zero product import/child | SAFE T0
Scrub fails, exception/timeout, replay/concurrency/Job drift | DENY, erase selectors, latch Job | SAFE T0
Old v1/F1/PR102 and unrelated File/Git/REST/MCP | Existing legal paths preserved, positive Exec DENY | Linux adjacent source/smoke evidence
Real OIDC/SSH/native child/T1/T2/T3/production | NOT_RUN and NOT_AUTHORIZED | Separate explicit user grant

No value, path, bearer or token from a real runner is allowed in a
developer diagnostic log. Bounded nonsecret key names and counts only
do not prove E0 or E1 provenance.

## 4. Independent B/C target and finding closure

B PRELIMINARY P2-01 only closes when E0, E1 and E2 have unambiguous
reviewed contracts and E1 original provenance and value rule are
independently demonstrated, OR when the Owner expressly elects Option A
and accepts macOS positive PREEXEC remaining unavailable.
Simply deleting the key from Python os.environ or widening the
20-key allowlist does not close the proof gap.

B PRELIMINARY P2-02 only closes when the *one* selected Python executable,
its relevant loader/import graph, current Job/source provenance and
drift rejection are bound to a fixed, reviewer-qualified identity.
Changing iteration order among unpinned Python candidates is insufficient.

For this DESIGN-only candidate B and C must each independently review
the same complete GitBlob, Base/Head/Tree, current parent DESIGN-013,
original macOS failed Job and Linux control evidence. Each must propose
its own negative counterexamples, decide whether Option B is fully
specified or requires another design version, and report actual verdict,
EVIDENCE_STATUS, P0-P3 and NOT_RUN. Neither review substitutes for the
other, a product r006 FULL code review or T1 execution qualification.

This proposal deliberately records that E1 origin/value is currently
UNPROVEN. Therefore no developer may treat its mere publication or
any conditional reviewer statement as approval to change code gates.
If the reviewers need additional trusted source evidence before
design PASS, report BLOCKED and keep Option A.

## 5. Freeze, approval and security

A formal DESIGN-targeted handoff must report:
REPO/PR/TASK_ID, DESIGN_ID, fixed BASE_SHA/HEAD_SHA/HEAD_TREE,
this complete document GitBlob resolved AFTER committing (never
embedded as its own hash), parent DESIGN-013 exact GitBlob, observed
macOS fail + Linux SAFE T0 Head identity, G05/Manifest, and the
conservative V2.0 rules/evidence basis.

B/C separately issue their own native GitHub COMMENT Reviews on that
same fixed design target. Only **AFTER** both sufficient current-version
independent review conclusions may the real Owner explicitly approve
one complete version, option and applicable risk statement.
A is not B or C and cannot supply approval. V2.0 EFFECTIVE_FOR_NEW_ROUNDS
still requires the three-Project same-version verification and approval.

No authority here to edit the old exact 20/five-key source contract,
enable live OIDC/id-token:write, run an SSH agent/autofs experiment,
execute native Python/Pipenv/Go, execute a shim, terminate a process,
run T2/T3, touch user/shared/production hosts, merge, tag or deploy.
Full code review, positive same-instance integration and R10 remain
NOT_ISSUED / NOT_TESTED / BLOCKED.

DEVELOPER_A_CANDIDATE: PREPARED_ONLY
STANDARDS_B_R015: NOT_ISSUED
SPEC_C_R015: NOT_ISSUED
OWNER_R015_APPROVAL: NOT_ISSUED
DESIGN_013_SOURCE_GATE: UNCHANGED
