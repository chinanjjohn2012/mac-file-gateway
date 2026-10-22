/*
 * B03-T01-R2b-R1 contract ABI. TEST-ONLY. NOT a native signal implementation.
 *
 * This header cannot accept a host PID/PGID. Only the fixed synthetic fixture
 * token is valid in any eventual no-signal adapter. The future Native Owner
 * must establish real process identity separately and never use these mock
 * facts as permission to issue an OS group signal.
 */
#ifndef C3_B03_T01_NO_SIGNAL_CONTRACT_H
#define C3_B03_T01_NO_SIGNAL_CONTRACT_H

#ifndef C3B03_TEST_NO_SIGNAL_STUB
#error "C3B03_TEST_NO_SIGNAL_STUB required for contract-only compilation"
#endif

#include <stdint.h>
#define C3B03_T01_NO_SIGNAL_ABI_VERSION UINT32_C(1)
#define C3B03_T01_SYNTHETIC_TARGET "fixture:synthetic-owned-anchor-group-T01"

typedef enum {
    C3B03_T01_MODE_ESCALATE_POSITIVE = 1,
    C3B03_T01_MODE_BLOCK = 2
} c3b03_t01_mode_t;

typedef enum {
    C3B03_T01_PHASE_TERM = 1,
    C3B03_T01_PHASE_KILL = 2,
    C3B03_T01_PHASE_CLASSIFY = 3
} c3b03_t01_phase_t;

typedef enum {
    C3B03_T01_BLOCK = 0,
    C3B03_T01_SYNTHETIC_TERM_ADMITTED = 1,
    C3B03_T01_SYNTHETIC_KILL_ADMITTED = 2
} c3b03_t01_admission_t;

typedef struct {
    int64_t t0_ms;
    int64_t outer_budget_ms;
    int64_t cleanup_reserve_ms;
    int64_t term_grace_ms;
    int64_t kill_entry_margin_ms;
    int64_t outer_deadline_ms;
    int64_t term_cutoff_ms;
    int64_t kill_cutoff_ms;
} c3b03_t01_deadline_t;

typedef struct {
    uint32_t abi_version;
    c3b03_t01_mode_t mode;
    c3b03_t01_phase_t phase;
    /* This is an opaque unit-test value, NEVER a PID, PGID, FD or handle. */
    uint64_t scenario_nonce;
    /* All of these values are test facts. Real native witnesses are separate. */
    uint64_t term_fact_mask;
    uint64_t kill_fact_mask;
    int64_t now_ms;
    int64_t term_sent_at_ms;
    c3b03_t01_deadline_t policy;
} c3b03_t01_mock_input_t;

typedef struct {
    uint32_t abi_version;
    c3b03_t01_admission_t decision;
    uint64_t scenario_nonce;
    uint32_t fake_term_transport_calls;
    uint32_t fake_kill_transport_calls;
    uint32_t real_group_signal_syscalls;
    uint32_t term_attempts;
    uint32_t kill_attempts;
    uint32_t signals_closed;
    uint32_t group_signals_after_close;
} c3b03_t01_mock_output_t;

/* Deliberately NO call to kill(), killpg(), syscall(), posix_spawn() here.
 * There is no executable helper, no syscall wrapper and no native runner.
 * R2b-R2 may implement an *independently reviewed* test-only function under
 * C3B03_TEST_NO_SIGNAL_STUB, never a linkable group-signaling fallback.
 */
#endif /* C3_B03_T01_NO_SIGNAL_CONTRACT_H */
