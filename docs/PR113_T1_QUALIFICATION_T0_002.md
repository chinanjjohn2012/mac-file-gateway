# PR113 one-time T1 qualification preflight — iteration 002 (T0 only)

DESIGN_SCOPE: PR113-T1-NETWORK-DESIGN-002 immutable Git Blob `89206350f8025425c74033780a3166df5d68b88c`.
SOURCE: PR113 product Head `fc94cc36ce793e32a3fb97d5a500a47608be6781`, Tree `fa51d2a7a881f8e4915badcfe0fb088f2fca0ee3`.
PR116 CONTROL BASE: Head `d4b5a70415db6422fef7996f186bdc235436bbc3`, Tree `a180edbd0d6e0f87c20f527fea5245f6566e5e47`.
RULES: ICR-V2.0 / GHRH-2.0 / ETP-V2.0; Design-002 six-command product Blob `d90df6de3bdbd81a314109d5f73959799b5a10a6`; PR102 Gate B `7db3b77aadca8b0c284e28fa5ee64e315e9275d2` (no blanket waiver).
STATUS: DEVELOPING — OFFLINE T0 ONLY / NO NATIVE T1 AUTHORIZATION / NO WORKFLOW / NO NETWORK ACCESS.

## Product / controller separation and Owner risk selection

Owner's answer **“批准 B”** to A's exact immutable network design choice authorizes **only** the proposed one-time, disposable, trusted-local HOSTED six-command *network-risk model*. A's GitHub record at PR116 `issuecomment-6897512856` is a *developer relay* of first-hand A chat, not independent Owner GitHub proof for B/C or a run grant. It does not allow a new T1/T2/T3, persistent service, user Mac/production/shared resource, R006 policy change, merge/deploy/release, network probing, OS firewall or process signals.

Mode B is a **weaker** explicit one-off exception to PR102 Gate B SOURCE_CLOSED claim. It is NOT PR102 BOUNDED_EGRESS, not a network sandbox, and not verified no-egress. Arbitrary foreign-child DNS/HTTPS, dynamic downloads, extra descendants and same-UID writes are potential irreversible effects. A still requires precontact isolation and independently approved harmless same-context witness; there is no silent fallback from A to B. Mode B is selected in the T0 manifest but an actual native Job remains forbidden without a separate precise Owner authorization and independently qualified no-accessible-credentials evidence.

## Actual new control functions and limits

`tools/pr113_t1_qualification_t0.py` (stdlib plus previously reviewed inert `tools/pr113_t1_control_t0.py`):

- **Six × three fixed vectors**: compare command ID, operator-selected `workspace_id` and separately fixed Workspace-relative `cwd`, runner, transport, client REQUEST argv and service EFFECTIVE argv. The trusted operator Workspace ID must come from the reviewed fixture/context and MUST NOT be inferred from candidate data. Independent Design-002 §1 literal row expectations and static AST comparison against `gateway/lbe_six_fixed_commands.py` prevent source-table/self-test tautology without importing or executing product code. Cross-workspace, wrong-cwd, type/alias and illegal-command negatives remain strict SAFE T0. This repair closes the identified P2 source shape, not any external input/Owner/native-execution gate. S3 REQUEST `python -m pytest -q` differs from EFFECTIVE `pipenv run python -m pytest -q`. No arbitrary shell, Go run or seventh command; matching a vector is data-only, not a product launch.
- **Network event oracle**: T01–T12 must have exact origin and an observed-vs-unverified flag. Under selected B, ordinary child public DNS/HTTP T04 is accepted *risk*, while controller-late download T02 is POLICY FAIL, unqualified child executable T06 and test-affecting unknown data T05 disqualify native evidence, and credential/private service T08/T09 are SECURITY FAIL. Original-child exit0 remains separately observable; it never makes a T0 receipt a T1 PASS. No monitor -> `NOT_ASSESSED`, never "no egress".
- **Nine foreign-input classes**: typed manifest shows runner image, Python, Go, Pipenv, complete wheelhouse/install RECORD, Go stdlib/module/fixture, Pipenv source/venv, pinned workflow actions and separate future test-control/fixture bytes. Three hashes belong only to historical PR114 receipts; no new selected binary/wheel/fixture source is verified. Even a forged manifest with all booleans true remains nonoperative. No new external installation/acquisition is performed by this code.
- **Read-only disposable file digest**: open each ancestor with directory descriptors and `O_NOFOLLOW`, reject symlinks, hardlinks, wrong owner, unsafe mode, nonregular files, parent escape, and in-read size/mtime/inode change. This reduces T0 read races; it does NOT attest a fully closed loader, nor guarantee file stability after the descriptor is closed, nor sandbox same-UID external writes.
- **Executable-but-nonoperative CLI status**: `python3 -B -m tools.pr113_t1_qualification_t0` reads ONLY the fixed in-repo JSON lock, prints a redacted machine-readable `DENY` + outstanding gaps and always exits **3**. There are no command, target, arbitrary path or unsafe override arguments. `native_execution_decision` always throws `GateDenied`; no real child adapter, workflow trigger, network call or process-kill path is present. The prior PR116 local `O_EXCL` demonstration is NOT a globally consumed one-shot Owner authorization across GitHub Runner VMs.

## Safe T0 evidence and RED/GREEN scope

A local disposable Python 3.13.5 container runs `python3 -B -m unittest discover -s tests -p 'test_pr113_t1*' -v`. Existing 33 T0 tests plus the new vector/event/receipt/manifest/file-descriptor regressions are pure stdlib. No Go/Pipenv S1–S6 product commands, real mixed Git/File original child, outbound canary, hostname test, DNS probe or process signals. Exact new Head GitHub CI and relevant raw Job logs must be fetched separately after committing; do not claim a green result from a local test or when strict R006 remains failed. Original PR116 Linux T0 Run 43728899881 = 4,238 passed / 19 skipped, G05 PASS; macOS strict R006 Run 43728899849 = FAIL with ambient credentials. These earlier jobs are not tests of the new control Head or native T1.

## Required later executable qualification — all remain blocked

- B/C separately qualify actual runnable test controller SHA/Tree/manifest, exact hosted macOS image and trust context, immutable action pins, full selected wheel/Go/Pipenv/source bytes, generated fixtures, earliest installer/build/import-hook identities, no shadowed import roots and no accessible private credentials before the first foreign instruction.
- Implement and test globally authenticated Owner one-use run_id, attempt=1, replay/duplicate/label/revocation failure, two sequential Job phases, admission budget, original-child ownership, output truth, safe no-seventh-child negative and mixed S1/Git/File old-UNKNOWN chronology. A local O_EXCL file or self-declared event fields are not independent Owner proof.
- Obtain precise new Owner authorization for exactly one PR113 Head/Tree, control Head/Tree, runner, input lock, 18 observations, one mixed observation and resource limits **after** source/contract safety qualification. The earlier network mode B approval is not that execution consent.
- Keep PR113 B `P2-EVID-02` OPEN, native T1 `NOT_RUN`, INTEGRATION `NOT_TESTED`, FULL_CODE_REVIEW_PASS `NOT_ISSUED`, R10 `BLOCKED` until applicable independent proof exists. No unqualified F1/D0 or PR102 gate relax.

This file is a **developer implementation note**, not a fresh independent B/C Review, a GH_HANDOFF_V2, an authenticated Owner message or a T1 approval.

## PR117 Spec P2-C117-T0-01 concentrated repair (new snapshot)

The previous frozen T0 oracle wrongly equated `workspace` with the row cwd (`py-direct`, `py-pipenv`, `go-project`). The repaired inert record explicitly contains both `workspace_id` (chosen independently by the reviewed operator fixture) and `cwd` (exact Design-002 row). `check_command_vector(..., operator_workspace_id=...)` rejects mismatches separately and does not derive authorization from the untrusted record. Positive operator IDs are not hardcoded to `a`. This is ONLY offline source/T0 preparation; CLI remains unconditional DENY/exit 3, with no native process, no credentials, no network, no T1, no product grant and no changes to frozen PR113 or PR116.
