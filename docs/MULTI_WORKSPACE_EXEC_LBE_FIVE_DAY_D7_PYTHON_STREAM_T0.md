# D7 - bounded selected Python executable byte hash T0

REPO: chinanjjohn2012/mac-file-gateway
PR: #114
TASK_ID: MULTI-EXEC-LBE-FIVE-DAY-CANDIDATE-20261105
REVIEW_ROUND: r005
REVIEW_SCOPE: TARGETED SAFE T0
CONTRACT_SCOPE: PR98 r002 LBE; PR102 r002 OFFLINE_ONLY Gate B; D4 proposed PRODUCT_T1 R002 NOT_EFFECTIVE; operative D0/F1/Phase1/G05/R004 unchanged.
RULESET_ID: ICR-V2.0
HANDOFF_PROTOCOL_ID: GHRH-2.0
EVIDENCE_PROFILE_ID: ETP-V2.0
AUTHORIZATION_STATUS: SAFE_T0_ONLY; NATIVE_NOT_AUTHORIZED

## RED
The old readonly Pipenv snapshot applied its 1 MiB text metadata limit
also to the selected Python executable, and allocated a full-size bytearray.
A synthetic 2+ MiB NON-PYTHON dummy file must be allowable under a
separately bounded interpreter size. The original GitHub test-first RED
Head b5583efc6db54553bbb5a8a4dc50035e73ecac6a,
Tree cf0c70adae36dde5ad25ab43d715f39449564fcd,
Run 42187900851 Job 127792513906:
G05 292 Blob/mode and 291 SHA Manifest PASS; pytest
1 expected failure (fixture file oversized), 2218 passed, 19 skipped.
No executable load, real Python, Go, Pipenv or signal was attempted;
smoke and final Manifest NOT_RUN after pytest expected failure.

## Fix and safe tests
Retain the 1 MiB cap for Pipfile, Pipfile.lock and pyvenv.cfg.
For exactly .venv/bin/python only, use O_NOFOLLOW read-only FD,
owner, regular file, executable bit, one-link and non-writable checks,
a distinct 128 MiB maximum and <=64 KiB SHA256 streamed reads.
Reject premature EOF or before/after inode/mtime/ctime/mode/owner/link
drift, wrong fixed digest and oversized input. Keep the original
hard DENY native capability function independent of all receipts.

Tests use disposable fake bytes rather than a real interpreter;
positive 2+ MiB hashing with Popen/run/socket trapped, negative
oversized small metadata, same-size mutation, fixed upper bound,
and existing symlink/pointer/unsafe mode cases. No native
go/pipenv/python or network contact is authorized, executed, or
claimed as proof.

## r004 P3 doc repair
B r004 P3-114-B-02 found the r004 D6 document had a stale
PENDING_CURRENT_HEAD_CI line. Update the text to name original r004
Head f0e94679242412e1a14bab1e05d87a024e146c61 and Job
127741766040 as observed GREEN, explicitly historical for r005.
This is a candidate wording close, not B/C independent signoff.

## Deferred gates
Observed source bytes on a selected FD are not real loaded interpreter
or stdlib/site/.pth/Pipenv code provenance; post-close pathname races,
macOS OS resource/egress and any real native lifecycle remain
unqualified. PR102 SOURCE_TOOLCHAIN_T1 OFFLINE_ONLY remains mandatory;
D4 non-isolated trusted PRODUCT_T1 needs independently reviewed
exact runnable code/source/runner/budgets and new owner risk consent.
F1 shared public positive Exec stays DENIED. Integration/T1/T2/T3,
production, user Mac, merge and deployment are NOT_RUN/NOT_AUTHORIZED.

INTEGRATION_STATUS: NOT_TESTED
R10_STATUS: BLOCKED
FULL_CODE_REVIEW_PASS: NOT_ISSUED
NEXT_ROLE: B Standards and C Spec independent r005 TARGETED, only after
new exact Head original GREEN CI and frozen A handoff.
