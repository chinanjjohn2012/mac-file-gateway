# B03-T01-R2b-R2a — SOURCE_AND_OBJECT_ADMISSION_ONLY

**Status:** AUTHOR SOURCE/OBJECT ADMISSION CANDIDATE, INDEPENDENT STANDARDS / SPEC REVIEW PENDING.

**Classification:** strict compile-and-inspect **NO SIGNAL** research stage. **C_EXECUTED=false** throughout this PR; there is no Python native Adapter, no linked executable, no dynamic library, no native run, no group TERM/SIGKILL, no real PID/PGID, no real waitpid or resource-cleanup proof. This is NOT the R2b-R2 contract GREEN stage, and is never a Native KILL run-admission authorization.

## 1. Immutable parent and provenance

- Parent [PR #41](https://github.com/chinanjjohn2012/mac-file-gateway/pull/41) at **Head** `c3ee680bf0598f41e03ee82455e32d2662e1e064` / **Git Tree** `061a6bebe8f85b393c5149b380ea02769a2a4cc3`; latest independent [Review #5608447958](https://github.com/chinanjjohn2012/mac-file-gateway/pull/41#pullrequestreview-5608447958) = **Standards PASS / Spec PASS**, P2-01–P2-04 CLOSED. R2b-R1 still has a genuine **172 expected RED** tests because the final Native Helper and the probe adapter do not yet exist.
- Frozen upstream: [R2b-D0 design](candidate-b-b03-t01-r2b-native-admission-design.md); [R2b-R1 contract](candidate-b-b03-t01-r2b-r1-contract.md). The reviewed exact 12-field Python Adapter request, 19-field result, 67 synthetic fault IDs and same-ledger 3-operation bounds are NOT weakened or changed by this PR.
- **This candidate has a different deliberately inert source name:** `tools/research/c3_candidate_b_t01_no_signal_candidate.c`. The future native helper path `tools/research/c3_candidate_b_kill.c`, future probe `tools/research/c3_candidate_b_kill_t01_no_signal_probe.py` and any live Runner `tools/research/run_c3_candidate_b_kill.py` must all remain ABSENT at this stage. Therefore the frozen 172 R2b-R1 behaviour checks remain RED; no fake GREEN is claimed.

## 2. Scope and dangerous entrypoint exclusion

| Artifact | Allowed effect | Disallowed effect |
| --- | --- | --- |
| `tools/research/c3_candidate_b_t01_no_signal_candidate.c` | One C11 pure-data function `c3b03_t01_no_signal_candidate` using synthetic in-memory counters/typed deadline snapshots | Spawn, fork, shell, syscall, signal, host PID/PGID, FD manipulation, waiting children, linking a fallback |
| `tests/test_c3_candidate_b_t01_r2b_r2a_source_admission.py` | Compiler `cc -fsyntax-only` and `cc -c` only, `nm -u`, `nm -g`, `otool -tv` on Darwin or `objdump -dr` on Linux, SHA256 the temporary object, static checks | Execute compiled object, load as shared library, use `ctypes`/`dlopen`, call the C candidate, mark Native Wait/cleanup verified |
| `.github/workflows/c3-candidate-b-t01-r2b-r2a-source-admission.yml` | 3-OS/Python source and object safety verification plus existing pure-Gate GREEN tests | `workflow_dispatch`, protected/native-signal approval, production execution, C run |
| `MANIFEST.sha256` | Fixed source/contract file digests | Runtime authorization |

The C model includes only `<stdint.h>` and the approved test-owned `c3_b03_t01_no_signal_contract.h`; the latter enforces `C3B03_TEST_NO_SIGNAL_STUB=1`, and the candidate independently enforces the same exact macro. Deliberate `-D0`, `-D2` and absent variants all fail. **No operating-system header** is included in the candidate. A C input is test-only eight-field deadlines, opaque nonzero uint64 synthetic nonce, bounded fake TERM/KILL steps, enumerated synthetic scenario and fictional fact masks. A successful fake counter cannot stand in for live Anchor/Controller/Worker identity.

### Gate math under compile-only source inspection

The proposed pure C Gate validates positive original budgets; strictly increasing `t0 < term_cutoff < kill_cutoff < outer_deadline`; overflow-free addition; exact frozen original vs attempt policy snapshots; TERM within the original cutoff; KILL only after the original TERM, full grace and before original KILL cutoff; and a single in-memory attempt for each allowed synthetic operation. Every simulated denial closes the local synthetic authority. There is no retransmission after a KILL attempt, even on simulated EINTR/ESRCH/EPERM. Input facts are synthetic masks, **not** actual native `getpgid`, `proc_pidinfo`, Controller IPC or lawful `waitpid` evidence.

**Important qualification:** Compile-and-inspect tests DO NOT execute the candidate or test its semantics. They only establish the exact absence of reachable *external* runtime dependencies in this compiled C object and confirm the static source/ABI relationship. The R2b-R1 behaviour contracts must remain real RED until a separately approved *test-only* Adapter and checked linked binary exist.

## 3. Original source and object security checks BEFORE any future load

Each job verifies exact Git HEAD, complete SHA256 Manifest, exact allowed candidate and absent future Helper/Runner/Adapter. Then, in a temporary directory outside tracked paths, it performs:

1. Reject all include headers except the approved C test ABI and `stdint.h`, and reject direct/indirect C source references to group signals, host PID, process creation/wait and native loader APIs. The source check is **necessary but not sufficient**.
2. Compile with `cc -std=c11 -O0 -Wall -Wextra -Werror -pedantic -fno-stack-protector -fno-builtin`, approved include directory, exact `-DC3B03_TEST_NO_SIGNAL_STUB=1`; `-c` outputs **only a temporary object**. Deliberately absent, 0 and 2 macro variants must fail in `-fsyntax-only` mode. The same source and flags are frozen by PR Git Tree and Job log. The resulting *.o is not installed, linked, imported, loaded or launched.
3. Record SHA256 of the exact object as `C3B03_T01_R2B_R2A_OBJECT_SHA256`. Require `nm -u` to return **zero undefined symbols**, and `nm -g` to expose **exactly one** allowed external symbol (`c3b03_t01_no_signal_candidate`). No imported library/kernel symbol or late-linked escape route is acceptable. Reject any unexpected relocation/symbol.
4. Disassemble with `otool -tv` (Darwin ARM64) or `objdump -dr` (Linux). Require non-empty output and reject direct syscall trap mnemonic patterns. Preserve the original Job and disassembly examination evidence for independent review. This must not be claimed as an *atomic* proof of future linked-binary runtime safety. This source/object-stage result is limited to **no live group-signal path in the inspected object**; **binary provenance** remains incomplete until the final separately reviewed linked artifact and Python Adapter call chain are verified.
5. Print `C3B03_T01_R2B_R2A_C_EXECUTED=false` and never call the compiled code. No timing vector, real Controller wait, Anchor held identity or cleanup state is obtained.

**P3-01 remains open for R2b-R2b:** this PR is **not** Adapter provenance. The future Python Adapter must independently verify source SHA, exact reviewed commit, build macro, binary SHA and built object symbols/relocations/disassembly, prove the actual Python→approved C call chain, and repeat inspection on the **final linked loadable binary before any load**. A self-reported `real_group_signal_syscalls=0`, nonce echo or `c_adapter_dispatches` is insufficient. Only after separate independent pre-execution PASS can the frozen 172 contracts be run against no-signal C. Never convert code-coverage tokens into actual lawful wait proof.

## 4. CI truth boundaries and next gate

- The dedicated new workflow may become **GREEN** only for *C source/object admission tests* and existing Python Gate tests. The 172 new R2b-R1 behavior contracts should remain **RED**; the frozen B03-R1 19 native-signal contracts remain RED. The Linux full suite is not expected to be globally GREEN.
- Existing B03-R2 native pre-signal workflow must remain **SUCCESS**, since the real Native Helper/Runner/Probe paths are still absent. Avoid changing frozen PR #41, its Head, behavior contracts or other workflows.
- If compiled candidate has even one undefined external symbol, unsafe include, trap instruction, suspicious relocation, wrong macro, unexpected exported entry or dynamic loader path, **STOP / BLOCK**, do not execute the model.
- Even independent Standards / Spec PASS at R2b-R2a permits only the next **separate no-signal binary+Adapter admission and behavior GREEN** stage; it does not authorize true group TERM/SIGKILL or deployment.

Hard status: `group_kill_authorized=false`, `reuse_proven=false`, `g2_qualified=false`, T04/T08b/T10 = `NOT_RUN/BLOCK`, R2b-R3 and T01-R3 real group signal studies BLOCK, G2/G3/G4/G5 and production Gateway ExecSupervisor/REST/MCP Multi Exec BLOCK. PR remains Draft/unmerged; no Approval or deployment is implied.

## 5. Independent Standards / Spec review checklist

1. Is the only C candidate impossible to call an OS service given its source and **compiled object** inspection evidence? Any hidden external dependency, dynamic loader, direct syscall/trap or unsafe macro default?
2. Did `nm -u`, `nm -g` and architecture-specific disassembly genuinely inspect the *exact temporary object* produced from the fixed commit, with SHA256 logged and no runtime invocation?
3. Can any PR/push workflow, Python test or C build accidentally **load** or invoke the candidate, or pass a host PID/PGID? Are both Native Helper and signal Runner still absent?
4. Are all reported static results honest and **not** misrepresented as the 172 behavior GREEN, true lawful wait, bounded native timing or G2 qualification?
5. Does this phase explicitly carry P3-01 until the final linked binary SHA/symbol/call-chain provenance has been independently verified **before running** any no-signal C?
6. Has the original R2b-R1 reviewed Head/tree, full Manifest and 11-mode BLOCK status been preserved?
