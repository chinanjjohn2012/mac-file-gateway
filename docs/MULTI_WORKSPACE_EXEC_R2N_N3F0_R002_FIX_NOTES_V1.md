# R2-N N3-F0 r002 -- T0 cross-node / independent-lineage topology fix

This is a **bounded T0-only developer fix**, not actual N3 private-FS or OS provenance qualification.
The current reviewed F1 default synchronous `exec_cleanup_proof_required` remains unchanged.
No Live Gateway module, ExecStateStore v1, S2, N3-M, Git/File/REST/MCP, SDK, workflow,
or Native process/Runner code is modified or invoked by this PR increment.

## Frozen r001 source and two independent reported defects

- Parent PR #96 r001 Base: `3479f6732c1ac357eac701871d3800adc9ab64c7`.
- r001 reviewed Head: `8e5941642bacc21eb642c6d3d507ed411a2ca5df`, Tree:
  `60b04b6678a97cde35edcb127610c9b7c9baa85d`.
- B Standards native Review: https://github.com/chinanjjohn2012/mac-file-gateway/pull/96#pullrequestreview-5691861919
  `B96-R001-P2-01`, one bounded T0 P2; B exact 32/32 old T0 PASS but eight
  cross-root topology counterexamples were not covered by the old tests.
- C Spec native Review: https://github.com/chinanjjohn2012/mac-file-gateway/pull/96#pullrequestreview-5691862201
  `P2-C96-R001-01`, one bounded T0 P2; C independently reported six concrete
  old-source cross-node fake `dev+ino` contradictions returning healthy metadata.
- Old original model Git Blob `fc4d14de548edec20813f812e10917f462752839`
  and old 32 unittest source Blob `2cb015a71c7599aacb6597d288dedaaa7a5fa66e`.
  Both reproduced by A from byte-identical original GitHub source (Blob+SHA256).

## r002 changes (no T1)

1. `gateway/r2n_n3f0_offline.py` rejects *all* cross-node `(dev,ino)`
   collisions among state parent/root, independent lineage parent/root, and
   singly-linked owner lock. A directory and regular file cannot alias one
   dev+ino, nor can a parent/root be the same claimed node.
2. Adds `N3F0SyntheticTopology`, an explicitly **untrusted fake** complete
   ancestor-chain projection: ordered control-ancestor -> immediate parent ->
   private leaf for each branch. The T0 scanner now requires both chains to
   be typed, bounded, individually unique, anchored to the same modeled
   control ancestor, with endpoints matching the fake parent/root FDs.
   Shared *prefix* ancestors are legal; after divergence the chains cannot
   rejoin or contain the opposite root. The owner lock may not alias an
   intermediate directory either. Missing/truncated/contradictory chains
   yield `private_boundary_unverified` and NEVER healthy metadata.
3. The original `verified_pinned_parents` and
   `roots_disjoint_from_workspaces` flags are retained for T0 compatibility,
   but neither is accepted as sufficient evidence of independent lineage
   topology. The fake topology is never client-mintable production proof.
4. The original 32 test methods are retained with a positive distinct-sibling
   fake topology in the common fixture. Adds 24 new pure-T0 regression
   methods for the C six and B cross-alias orientations, own-parent/root
   identity, old-owner collision, deeper containment, unknown/malformed
   chain, rejoining, legal shared ancestors/different devices, and the
   unchanged unconditional physical-port denial.
5. `boot_read_order` now advertises a modeled topology verification stage;
   this is a proposed ordering, NOT an executed `openat/fstat` protocol.

## Evidence and hard boundaries

- A exact old-source T0 RED: original 32 tests pass; A independently authored
  8 r001 cross-node fail-closed assertions, **8 actual FAIL, exit 1**.
  This is expected source-level RED, not a hosted CI failure.
- A changed-source GREEN: all original **32/32** and new **24/24** source
  methods execute with `-B -I -S`, no skipped cases, exit 0. See tracked
  `docs/evidence/R2N_N3F0_R002_T0_EVIDENCE_INDEX_20261029.log` for
  a human-readable command/exit/hash index and the base64-gzipped *verbatim*
  original transcript `docs/evidence/R2N_N3F0_R002_T0_RED_GREEN_20261029.log.gz.b64`
  (full method stdout/stderr and source pre/post SHA256).
- This T0 test uses a synthetic parent chain and fake fstat-derived IDs.
  A real trusted *complete* pinned-FD topology is NOT proven, installed,
  callable or approved. The static model still always reports `available=false`,
  `completion_capability=none`, `t0_model_only=true`, and its physical entrypoint
  always raises `N3F0NotAuthorized`.
- No authorized first-install, new consent, Native start, process signal,
  reset/quarantine clearing or production integration is added.
- Head/Merge GitHub hosted CI, G05 actual checkout and R004 36-Wheel/RECORD,
  macOS native FD/`flock`/`fsync`, safe temporary real Git/File/REST/MCP,
  power-loss/ENOSPC and owner-lock race tests are **NOT_RUN**, not PASS.
  Real private filesystem T1 requires separate exact resource-specific
  user approval; Native/T2/T3/merge/release/deploy remain prohibited.
- A's test results do not substitute B/C fresh separate `r002` native
  SHA-bound Review; old r001 FAIL remains valid for the original Head.
