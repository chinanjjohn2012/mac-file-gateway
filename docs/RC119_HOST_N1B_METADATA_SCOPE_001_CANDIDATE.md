# RC119 — 真实主机只读资格验证精确测试范围（A 提案，待独立安全复审）

DOCUMENT_ID: RC119-HOST-N1B-METADATA-ONLY-TEST-SCOPE-001-CANDIDATE
STATUS: NONOPERATIVE_PROPOSAL / EXECUTION_NOT_AUTHORIZED
AUTHOR_ROLE: A_DEVELOPER; cannot substitute for B Standards, C Spec, authenticated Owner or product R10
USER_CHAT_REQUEST: 2026-11-20 "审批真实主机只读资格验证的精确测试范围"
OWNER_SCOPE_BOUNDARY: limited intention to seek approval of this specific read-only host-qualification design; document itself is A's independently drafted precise proposal, NOT a first-hand user acknowledgement of this yet-unseen immutable Blob or actual-run permission
REVIEW_SCOPE: TARGETED_HOST_SAFETY_DESIGN (NOT native T1, full code or integration)
REPO: chinanjjohn2012/mac-file-gateway
PRODUCT_PR: #119
PRODUCT_BASE_SHA: ec25c34492912f3a82175fa9c1060e0632814687
PRODUCT_HEAD_SHA: 33c30b6c2710cac0f8533370c1ca42f31ef6747a
PRODUCT_HEAD_TREE: 27e26c423e700cdbad0aeca27efcdf82594507c1
CONTROL_DEV_PR: #122
CONTROL_BASE_SHA: 22bae3bf359ccc0678a6f691b1e8188a4872cee2
CONTROL_HEAD_SHA: 77d262c8afba8a98512c30f72172bf22ae1fe5a0
CONTROL_HEAD_TREE: 55c1dd70498642a6fa568f4432a2aef988310d83
SOURCE_BLOB_PROFILEB: 1df5ccf9dbf920ff243e04d0e57f45a82e1b2a13 (PR121 TARGETED B/C DESIGN PASS, NOT operative host or test qualification)
SOURCE_BLOB_PR102_GATEB: 7db3b77aadca8b0c284e28fa5ee64e315e9275d2 (retained stronger precontact obligations unless exact approved exception operative)
SOURCE_BLOB_SIX_PRODUCT: d90df6de3bdbd81a314109d5f73959799b5a10a6
RULESET_ID: ICR-V2.0
HANDOFF_PROTOCOL_ID: GHRH-2.0
EVIDENCE_PROFILE_ID: ETP-V2.0
TEST_RISK: REAL_HOST_NONDESTRUCTIVE_T1_QUALIFICATION_METADATA_ONLY (not ordinary synthetic T0)
INTEGRATION_STATUS: NOT_TESTED
NATIVE_S1_S6_T1: NOT_RUN/NOT_AUTHORIZED
R10_STATUS: BLOCKED

## 1. Precise future target (before any test)

- ONE fresh dedicated disposable GitHub-hosted macOS 15 ARM64 VM per explicitly authorized qualification attempt, not an existing old PR101/PR114 runner, developer/user Mac, Tunnel, shared agent, production resource, unpinned container, or generic macOS machine.
- Actual runner instance, image release/version, OS/architecture, UID/GID, source verifier HEAD/TREE and GitHub run_id + run_attempt MUST be measured and bound; no assumed image or inherited previous-run authority. If not independently identified, stop.
- Existing GitHub-hosted runner software list and label are only host ID observations, NOT a no-accessible-secret statement. A clean unrelated runner cannot sign for the future native T1 process.
- Separate trusted bootstrap/checkout action provenance and credentials must be isolated before any test-domain instruction. No unreviewed downloaded actions or arbitrary packages.
- Scope is ONE future bounded read-only qualification job only AFTER B/C independently review this exact scope and a separate exact Owner run authorization; execution budget is proposed max 10 minutes, max 1 job, no real Go/Pipenv worker/REST/MCP or source-install workflow.

## 2. What one later approved metadata-only verifier MAY inspect

A. SOURCE/PROCESS MATCH: original CI event and run attempt, Git commit/Tree, exact fixed verifier content hash, OS uname/sw_vers/architecture, runner image release, actual effective UID/GID, process ancestry classification and filesystem domain identity. Use fixed trusted system/stdlib metadata APIs; if verifier origin is not independently approved => NO TEST.

B. AMBIENT ENV: Only Boolean/presence or safe status categories for secret-related environment names, selected effective environment, token/OIDC request availability, SSH_AUTH_SOCK, known cloud credential selectors, PATH/import selector classes. NEVER read, print, encode, hash, transmit or log any environment VALUE or credential.

C. EXACT-PATH PERMISSION METADATA: On approved bounded exact-path categories only (current checkout .git/config and credential-helper/credential-file status; HOME .ssh/.config/.netrc/cache sensitive classes; workspace source roots and private scratch), record lstat/fstat owner/mode/type, symlink/nonlocal risk and safe access-control predicates. No arbitrary HOME crawl, file content read, file open in read mode, directory listing of secrets, or accessing target of a symlink. Log category+PASS/BLOCKED/UNKNOWN only, never personal path text or contents.

D. INHERITED FD/UNIX SOCKET METADATA: Identify only number, file type, disposition/category of open descriptors or inherited socket handles from the SAME expected UID/process domain, without reading FD contents, connecting, writing, SSH-agent handshake or open-ended socket enumeration. If safe discovery is unavailable or an unknown potentially credential-bearing FD/socket remains, outcome is UNKNOWN/BLOCKED, not a negative proof.

E. MOUNT/AUTOFS: Read kernel/platform mount identity/readonly/type classifications and compare against an explicitly preapproved disposable runner mount expectation; flag nonlocal writable mount, unexpected shared/home/autofs, symlink alias or mutable checkout. Do not mount/unmount, traverse nonlocal paths, list secrets, change permissions or modify host config. If required proof unavailable, record NOT_ATTESTED and deny higher grades.

F. CLOUD METADATA/OIDC: Use only existing trustworthy provider/platform attestation metadata supplied without calling the metadata service or credential endpoint. NO TCP/UDP/DNS/HTTP/SSH/unix-socket connectivity test, token request, credential helper invocation or cloud identity probe; absence of an env key DOES NOT prove inaccessible metadata. Missing independent corroboration => NOT_ATTESTED/BLOCKED.

G. SAFE SENTINEL: Only inspect existence/permission metadata of an independently precreated, synthetic NO-SECRET sentinel in an explicitly private disposable fixture (via lstat/access), not a real secret or an arbitrary system file. Creating/writing this fixture inside the test is NOT authorized; if separately prepared trusted fixture absent => SKIP/NOT_ATTESTED. No deliberate agent/socket/cloud metadata canary.

H. STABILITY & ORIGINAL EVIDENCE: Re-check effective UID, image, run_id, selected source/host snapshot and approved metadata-only predicates at safe end of same test; retain original GitHub Job/Step/exit and bounded redacted categorical output. No claim this metadata-only verifier shares the future P2/P3/P4 actual first-foreign same-UID FD/socket/metadata domain unless independently proven by future reviewed controller.

## 3. Explicit prohibited operations

- No source archive acquisition beyond existing 10 confirmed archives; NO third-party installation/venv seeding/.pth/import/build hooks, go test/vet/build, pipenv run, any S1-S6 original child, REST/MCP physical product integration or File/Git physical side-effect tests.
- NO actual secret reading, credential token/mint/refresh/HTTP request/agent handshake, secret file open, SSH or cloud metadata network query, net/egress/port scanning, TLS probes, arbitrary socket connect, artificial outbound DENY canary.
- NO privileged system actions, chmod/chown, changes to firewall/pf/launchctl/network/host configuration, process signaling, kill/killpg, crash/restart/timeout-survivor experiments, shared/user Mac/production/T2/T3.
- NO GitHub workflow dispatch/re-run, code push, executable test controller enablement, changing PR119/120/121 frozen source, or activating Profile B merely through this design review.
- NO console/artifact publication of environment values, credentials, raw paths from private HOME, FD targets or socket peer addresses. Only allowlisted categorical redacted evidence.

## 4. Future denial and evidence-grade matrix

1. Non-hosted, wrong architecture/image, mismatched UID/process snapshot, unsafe checkout/root/verifier, or unqualified bootstrap => NO_TEST, HOST_BLOCKED.
2. Any secret-related env present, access-permitted credential file or helper, inherited credential FD/socket, writable nonlocal/shared mount, or externally reachable identity from independently approved metadata => HOST_DENIED. STOP, do NOT read secret/resolve socket or retest until an independently approved new snapshot.
3. Any unreadable/unverifiable category, incomplete FD/socket reachability, unknown metadata service access, changed mount or stale same-domain identity => HOST_UNKNOWN/NOT_ATTESTED and NO N1-B PASS.
4. A synthetic sentinel positive does not prove any real credential inaccessible. A clean env + 10/10 verified source archives does NOT establish no-secrets or an approved native runner.
5. Because this scope disallows live credential reachability probes, HOST_METADATA_OBSERVED may be recorded on exact run only; N1B_QUALIFIED_PRE_FOREIGN must stay NOT_ISSUED unless later separately independently corroborated same-UID/FD/socket/metadata-domain no-secret proof is permitted and verified. No bypass of current R006 failure.
6. All unauthorized tests are NOT_RUN; reviewed design text and a GREEN metadata step cannot count as actual T1, full executed-source closure, RC119 B/C role FULL, R10, integration, release or production.

## 5. Independent review and separate authorizations

- B Standards and C Spec each independently review this immutable precise host-safety design against PR121 §8A.1/§8A.2, retained PR102/R006, same-Head original logs and a meaningful negative for env-clean+FD4-agent, HOME credential helper, writable autofs, metadata/OIDC reachability, and wrong UID/image. Do not inherit prior broad ProfileB design PASS.
- This is a GHRH-2.0 conditional safety/design blocker: a targeted independent design decision is needed before any actual host test; A cannot sign it.
- User chat phrase approving/initiating scope review is NOT a separate original real-host run authorization for a newly specified host and immutable test controller. Future A handoff must bind actual approved test code Head/Tree, runner/image, exact one-run identity and independent B/C safety review. Owner then separately permits ONE exact read-only host job.
- After metadata-only host observation, a different authorization and design review may be required to establish real same-future-process secret-free qualification. Separate source staging/install and native T1 remain NOT_AUTHORIZED.
- Existing R006: PR122 actual Head 77d262c8... original Job 134451313611 G05 446 blobs/445 manifest PASS but R006 FAIL due ambient credential-bearing env. This is NOT reversed or waived here.
- No merge, version tag, release or deployment.

NEXT_ROLE: B Standards AND C Spec for independent TARGETED SAFETY DESIGN only if they explicitly accept the stable immutable design target; otherwise A retains proposal revision. There is NO formal GH_HANDOFF_V2 review of the incomplete PR122 implementation milestone.
