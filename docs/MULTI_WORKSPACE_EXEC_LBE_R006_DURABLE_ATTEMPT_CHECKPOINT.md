# R006 durable consumed-attempt source milestone (NOT native authority)

R006 fixed Git Blob: b8d8a1cb32fb7130dfa6d00b37831dfddfaad11c.
The owner accepted its nine risk disclosures in the current conversation;
A transcribed this to PR #114 comment 6717010359. That is not a
GitHub-native owner signature, and is not an exact T1 run-attempt approval.

This commit introduces a durable **tombstone primitive**, not a client-mintable
execution grant. The private directory FD must originate from an independently
owner-locked, pinned, persistent ExecStateStore location; the Journal does not
itself establish that owner lock. Every consumed nonce is recorded before
reservations and Popen and never removed by the primitive. Filesystem O_EXCL
provides same-directory cross-process contention and fsync is attempted before
success is returned. A lost ACK, cancelled call, or ambiguous IO must not
release a nonce. Disaster recovery/volume rollback is not proven: absent
an independently witnessed durable ledger, deny new executable admission.

**Still required before positive product execution:** owner-approved exact
signed grant/verification channel (not environmental flags or user-provided
dataclass), binding GitHub run ID/attempt and Head/Base/Tree, selected
image/release/source, six command vector and expiry; durable owner.lock +
UNKNOWN screening; shared WorkspaceService consumption before Worker; replay
after crash, restore and cross-run tests; source and pre-Popen drift; genuine
GitHub-hosted macos-15 arm64 qualification and real source/credential checks;
independent new-code B/C review and separate exact T1 permission.

No operative F1/D0 exception, no native Runner/Popen activation, no
PR102 OFFLINE_ONLY relaxation, no T2/T3 or production approval.
This is a DEVELOPING r006 checkpoint, not GH_HANDOFF_V2.
