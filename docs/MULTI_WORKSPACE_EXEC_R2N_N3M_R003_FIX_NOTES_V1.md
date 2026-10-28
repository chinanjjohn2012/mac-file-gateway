# PR #95 r003 — N3-M pure-memory Runner ancestry repair and evidence gate

**DEVELOPER FIX CANDIDATE — NOT B/C ACCEPTANCE, NOT N3-F0, NOT REAL NATIVE.** Old r002 Head `99677afb30a57b12b8233dee3f49c16824fa55f0` and two independent native reviews are unchanged, both with blockers. New r003 Head/Tree and complete GitHub original CI to be fixed in the next GitHub GH_HANDOFF_V2 FIX_READY comment, not guessed here.

REPO: chinanjjohn2012/mac-file-gateway
PR: #95
TASK_ID: MULTI-EXEC-R2N-N3M-MEMORY-20261028
REVIEW_ROUND: r003
REVIEW_TARGET: FULL BOUNDED STDLIB-ONLY N3-M PURE-MEMORY authoritative consent binding / Runner selection / Fake retirement / STARTING / response FK / original 42 + r002 17 + r003 9 Python T0 tests, source-static unchanged F1/Git/File adjacency.
REVIEW_SCOPE: FULL (BOUNDED N3-M T0 ONLY; NOT full Gateway or real Native)
RULESET_ID: ICR-V2.0
HANDOFF_PROTOCOL_ID: GHRH-2.0
EVIDENCE_PROFILE_ID: ETP-V2.0
BASE_SHA: bf11211f06c8f8c3ac21deba64b8508489281a98
ORIGINAL_R002_HEAD_SHA: 99677afb30a57b12b8233dee3f49c16824fa55f0
R002_A_HANDOFF: https://github.com/chinanjjohn2012/mac-file-gateway/pull/95#issuecomment-6473534419
R002_B_STANDARDS: https://github.com/chinanjjohn2012/mac-file-gateway/pull/95#pullrequestreview-5685916270 REVIEW_COMPLETE / EVIDENCE INSUFFICIENT / BLOCKED for exact-source full 59-case T0 NOT_RUN, no new P0-P2, B95-R002-P3-01 Unicode surrogate normalization.
R002_C_SPEC: https://github.com/chinanjjohn2012/mac-file-gateway/pull/95#pullrequestreview-5685964047 REVIEW_COMPLETE / SUFFICIENT for confirmed P2 / FAIL; P2-C95-R002-01 model incorrectly accepts descendant pipenv under configured direct ancestor (confirmed in source-extracted C T0); persisted schema, real T1/Native/CI remain P3/NOT_RUN.
CONTRACT_AUTHORITY: user-approved immutable PR94 r001 N3-D future private-state design, proposed PR92 Native Limited D0/plan, operative D0 F1/Phase1/G05/R004. N3-M code and tests only; Native Limited future exception NOT operative and F1 remains hard deny. All prior role reports are independent previous-round evidence, NOT new r003 verdicts.

## 1. In-scope changes

- N3MBinding now requires an explicit canonical `runner_cwd` in its deterministic equality digest. It validates actual Workspace path scope containment and `PATH=direct|pipenv` maps using the same nearest/longest configured **ancestor** selection order as inherited `gateway/executor.py::_configured_runner`. Exact selected `runner_id` and `runner_project` must BOTH match nearest configured ancestor; a configured `src=direct` with cwd `src/tools` cannot claim `src/tools=pipenv`.
- Overlapping maps (e.g., `src=direct` and `src/tools=pipenv`) select the most-specific ancestor; '.' root map applies everywhere within selected grants. In the absence of a configured ancestor, a hypothetical direct fallback must identify the nearest containing Exec grant as runner project, while a hypothetical pipenv fallback may identify only a cwd-ancestor inside the chosen scope. This is a *type-consistency bound*, NOT proof of actual Pipfile presence or OS runner admission. The existing explicit `runner_fallback=nearest_pipfile_else_direct` string remains in digest and the model remains unwired from all runtime.
- The configured Workspace grant and mapping, selected cwd/runner/project, backend and risk fingerprint, exact `profile=native_limited`/`trust_scope=mutable_workspace` and owner/consent/attempt identities still bind the record. No server paths invented: actual server.exec is Boolean. Mutable in-root scripts/Git HEAD do not themselves invalidate consent.
- Strict JSON UTF-8 sizing now catches an invalid Python Unicode surrogate and raises `N3MBlocked('invalid_json')` rather than leaking `UnicodeEncodeError`, addressing nonblocking B95-R002-P3-01's exact-input normalization. This alone does not qualify physical input sanitization.
- New tests/test_r2n_n3m_review_r003.py adds NINE r003 test methods: wrong ancestor direct vs falsely claimed child pipenv, legitimate configured ancestor direct, valid more-specific pipenv override and mutation, root-dot map, nearest granted-scope no-map direct, hypothetical pipenv project with no real Pipfile claim, selected cwd mutation fencing previous PREPARED, malformed cwd/project rejection, malformed Unicode JSON. Original tests/test_r2n_n3m_offline.py 42 methods and tests/test_r2n_n3m_review_r002.py 17 methods now include the mandatory runner_cwd fixture; they are separate actual source files, not excerpt reconstructions.
- No changes to operative F1, WorkspaceService, executor.py, Runner process, REST/MCP, Git/File, real FS/owner.lock/fsync, v1/S2/N2, config, native backend, dependencies or CI workflows. Inherited appropriate source Blob and mode identities should be independently checked in cumulative PR Diff.

## 2. Exact-source T0 validation and blocking evidence

The CURRENT r003 FULL-EXACT-SOURCE 42+17+9 = **68 Python unittest method executions have NOT been observed by A**. Existing old r001 developer 42 test GREEN was for an older Git Blob and r002 developer 8/8+10/10 GREEN was **source-extracted reduced-method tests**, not the actual 59; neither can certify new r003 code, import graph or full 68 regressions. Do NOT label any current r003 68 cases PASS/SKIP/FAIL without raw execution evidence.

The disconnected model test container cannot fetch raw new GitHub bytes through its network; directly verified source/static GitHub Blob text and SHA-256 are not an executed full clone. Only pure-memory T0 is authorized; NO invocation of a user Mac/Tunnel/shared/production environment for completeness. Safe next proof is to materialize exact committed GitHub `gateway/r2n_n3m_offline.py`, inherited `gateway/__init__.py`, and THREE `tests/test_r2n_n3m_*.py` files into an isolated T0-only source root, independently verify their Git Blob + SHA256 and parent/source files, inspect for unexpected imports, then run ONLY those three stdlib unittest modules with -B -I -S and explicit root/test `sys.path`. If a verified runner is available, the REPRODUCIBLE T0-only test script to execute from that root is:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B -I -S - <<'PY'
import os, sys, unittest
root = os.getcwd()  # ONLY an attested isolated T0-only copy, NOT live Gateway/private state
sys.path[:0] = [root, os.path.join(root, 'tests')]
names = ('test_r2n_n3m_offline', 'test_r2n_n3m_review_r002', 'test_r2n_n3m_review_r003')
suites = [unittest.defaultTestLoader.loadTestsFromName(name) for name in names]
suite = unittest.TestSuite(suites)
res = unittest.TextTestRunner(verbosity=2).run(suite)
assert res.testsRun == 68, 'unexpected test discovery/identity count'
raise SystemExit(0 if res.wasSuccessful() else 1)
PY
```

The command is an **unexecuted reproducibility instruction**, NOT this round's observed result. Need raw stdout+stderr, exit status, interpreter/platform/inputs and before/after source/module identities; avoid unsafe Git/SDK/Native/FS state tests. If testing finds a new P0–P2, A must fix within authorized T0 under a NEW Head/round, independent B/C again. Never silently claim 68 GREEN.

## 3. Future hard gates and remaining gaps

- True local operator consent/owner identity, trusted monotone time, native_limited active scope and backend, ancestor Runner source and Pipfile identity from a real execution environment, durable N3 private 0700/0600 FS/owner.lock/fsync, lineage/rollback anchor, fd/dir-fsync/crash/ENOSPC, 4096/4096/16MiB budgets with forensic reservation, server decision as-of-marker and transport ACK; all NOT_RUN/NOT_AUTHORIZED, not proven by this memory code.
- B94 N3-private file metadata strict rules cannot alter Phase1 legitimate loose Workspace/config/Preview/Git/File. Future legal real Git T1 must pin disposable HOME, Git system/global/local configs/includes/hooks/fsmonitor/filters/credential helpers/SSH and root; separately authorized only. C94 original late-survivor/final-fence/pre-dir-fsync and trusted lineage gaps remain.
- B/C independent current r003 FULL BOUNDED role reviews with actual exact Head Git Tree/Manifest/diff/original CI required; r002 BLOCKED and FAIL cannot be upgraded or reused. Even hypothetical both role PASS does not equal FULL_CODE_REVIEW_PASS, INTEGRATION_PASS or permission to implement N3-F0/F1, Native, signals, T1/T2/T3.
- Native positive, OS process/signal/PGID/killpg, full descendant cleanup/F3, USER Mac/Tunnel/shared/prod, state schema rollout, UNKNOWN clearing, integration, merge/tag/release/deploy are HARD NO-GO. Current F1 dry_run=false after valid opt-ins still denies with exec_cleanup_proof_required before Worker/PREPARED/Runner/Popen, legitimate Preview and independent Git/File unaffected.
