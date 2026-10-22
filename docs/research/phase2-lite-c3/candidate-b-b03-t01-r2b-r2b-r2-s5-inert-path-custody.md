# C3 B03-T01 / R2b-R2b-R2-S5 — Inert Path and Inode Custody Observation (NO LOAD / NO C EXEC)

**Status: AUTHOR S5 FILESYSTEM-ONLY PARTIAL EVIDENCE, independent Standards / Spec CODE Review PENDING. NO LOAD / NO C EXEC.**

**Independently reviewed parent:** [PR #50 Review #5612620571](https://github.com/chinanjjohn2012/mac-file-gateway/pull/50#pullrequestreview-5612620571), fixed Head `4f388a0344fbd2326574ba7d82f9c1eb5d6cfd1c` / Git Tree `3af5720dd01553cc189174fbd0365cdff37e1fcc`, Standards PASS / Spec PASS strictly for S4 SOURCE-ONLY AST + DATA-ONLY Python/C ABI PARTIAL. All stacked research PRs are Draft and unmerged. S0/S2/S3 and S4 earlier narrow substage approvals do not authorize Candidate C load or group signals. P3-01 and P3-02 remain OPEN; P3-03 is CLOSED.

## 1. Research scope, explicit non-authority

This stage deliberately DOES NOT use the actual linked .dylib/.so observed in the earlier S3 research. It creates **only a short inert DATA file** (ASCII diagnostic bytes, no executable program or native machine code), inside a fresh, owned, private `0700` temporary directory. It creates no executable C, compiles no candidate C, links no library, imports no FFI Adapter and NEVER calls `ctypes.CDLL`, `dlopen`, any actual C function, loader, Native Helper, Runner, Owner/Controller/Worker or process-group signal. The sole subprocess actions inherited through S0 validation are `git rev-parse`; no test requires a compiler or linker.

Its narrow objective is to acquire **real, machine-produced filesystem observations** and demonstrate fail-closed checks for mutable path aliases, symlinks, hardlinks, wrong file type, owner/mode/size/content SHA, and replacement by a different inode with **identical bytes**. Tests use synthetic private fixture paths only; never an actual deployment library, PID/PGID or external process.

## 2. What is actually observed

1. Before creating the inert file: verify current Git Head/Tree and complete sorted `MANIFEST.sha256` with previously independently reviewed S0 checks; frozen C/header byte SHA are unchanged. These Git IDs and hashes are observations, not future loader authority.
2. Create a temp private root with owner `os.getuid()`, mode exactly `0700`; canonicalize and check each ancestor for symlinks and untrusted group/other write permission, accepting only a **root-owned sticky parent** exception for OS temp facilities. This is a controlled-temp policy, **not** a universal safe-ancestor proof against an untrusted same-UID process.
3. Obtain a directory FD with `O_DIRECTORY|O_NOFOLLOW`, compare lstat and fstat root identity; create the fixed inert file through that descriptor using `O_CREAT|O_EXCL|O_NOFOLLOW`, write fixed non-native bytes, change mode to `0400`, fsync and close. No candidate object/image is present.
4. Use `os.stat(..., dir_fd=..., follow_symlinks=False)`, `os.open(..., dir_fd=..., O_NOFOLLOW)`, FD `fstat` before/after hashing and post-observation path `stat` to check dev/inode, uid, nlink==1, mode==0400, size, mtime/ctime, and SHA256 **for that read interval only**. Directory FD root fstat/path lstat are checked again. Repeat a second complete observation and compare all recorded fields.
5. On every positive demonstration return exactly `UNCHANGED_STATIC_OBSERVATION_NOT_LOADER_CUSTODY` and `REVIEW_REQUIRED_NO_LOAD` plus `future_loader_same_inode_proven=false`, `atomic_loader_check_use_proven=false`, `same_uid_writer_absence_proven=false`, `first_c_load_authorized=false` and `native_dispatches=0`. The private temp directory is deleted before returning.

**Important P3-01 limit:** the descriptor is closed **before** future use. These operations do not pin the future dynamic loader lookup to that inode, nor do they exclude concurrent same-UID writers, rename after verification, shared-library dependencies, filesystem substitution, or library initialization side effects. File mode `0400`, hardlink count one, and same SHA **are not** proof of immutable loader path custody. `/proc/self/fd` behavior on Linux must not be assumed for macOS dyld. No OS-specific atomic loader strategy is implemented.

## 3. Negative evidence, with exact limits

The dedicated three-platform CI runs real inert-file cases:

- A leaf symlink or directory alias is refused, and an ancestor made world-writable without root-owned sticky protection is refused.
- A leaf hardlink (nlink=2), missing file, incorrect mode, size or SHA is refused.
- A different **real inode with identical inert bytes**, swapped into the same pathname between observations, is detected by dev/inode comparison. This is deterministic proof that *two snapshots* disagree, not protection against a future replacement after the second observation.
- Missing field, changed inode or false single-observation FD/path assertion is rejected; unchanged static evidence never grants load authorization.

Tests are **not** a true concurrent dynamic loader TOCTOU counterexample, not an actual Mach-O/ELF linked-library mutation, and not a proof against a hostile same-UID actor. No real loader path is exercised. Unknown is STOP; cannot promote this fixture to an S5 full lock.

## 4. Remaining gates and review

**P3-01 OPEN:** S1 compiler/assembler/linker/SDK/sysroot complete closure, non-atomic S2/S3 source-to-final chain, and real S5 same-inode loader check/use with transitive dependency lookup still unproven. **P3-02 OPEN:** final code CFG, imports/relocations/initializers and actual FFI Adapter binding are incomplete. **P3-03 CLOSED** remains unchanged. Full S5 and S6 `NOT_RUN/BLOCK`; first Native C load/call forbidden.

**191 expected RED** Native contracts remain unchanged: 19 B03-R1 missing Helper/Runner and 172 R2b-R1 missing Native C Helper/Adapter; Linux Full must be accurately reported as FAILURE, never GREEN; unexpected failures must be fixed.

**Hard BLOCK:** `group_kill_authorized=false`, `reuse_proven=false`, `g2_qualified=false`. T04/T08b/T10 `NOT_RUN/BLOCK`. First Native load, R2b-R2b-R3/R2b-R3/T01-R3, real group TERM/SIGKILL, Native Owner/Controller/Worker, G2/G3/G4/G5, Gateway production ExecSupervisor / REST/MCP Multi-Workspace Exec, merge and deploy all remain blocked. No stage field grants authorization.

Independent reviewer must read actual changed code/negative tests/Manifest, fixed current Head and Git Tree, previous PR Reviews and **original three-platform Job logs**. Standards / Spec PASS can close only **S5 inert-file pathname/FD observation PARTIAL**, never full loader binding, complete S5 or S6.