/*
 * B03-T01 R2b-R2b-R2-D2: C11 ABI layout STATIC ASSERTIONS ONLY.
 * Do not link, load, execute, import, or call the reviewed candidate C.
 * This translation unit holds zero executable functions or native syscalls.
 */
#if !defined(C3B03_TEST_NO_SIGNAL_STUB) || C3B03_TEST_NO_SIGNAL_STUB != 1
#error "C3B03 ABI compile-only check requires no-signal stub exactly 1"
#endif
#include <stddef.h>
#include <stdint.h>
#include "c3_b03_t01_no_signal_contract.h"

#define CHECK_SIZE(T, N) _Static_assert(sizeof(T) == (N), "ABI_SIZE_" #T)
#define CHECK_ALIGN(T, N) _Static_assert(_Alignof(T) == (N), "ABI_ALIGN_" #T)
#define CHECK_OFF(T, FIELD, N) \
    _Static_assert(offsetof(T, FIELD) == (N), "ABI_OFFSET_" #T "_" #FIELD)
#define CHECK_FIELD_SIZE(T, FIELD, N) \
    _Static_assert(sizeof(((T *)0)->FIELD) == (N), "ABI_FIELD_SIZE_" #T "_" #FIELD)

CHECK_SIZE(uint32_t, 4);
CHECK_SIZE(uint64_t, 8);
CHECK_SIZE(int64_t, 8);
CHECK_SIZE(c3b03_t01_mode_t, 4);
CHECK_SIZE(c3b03_t01_phase_t, 4);
CHECK_SIZE(c3b03_t01_admission_t, 4);
CHECK_ALIGN(c3b03_t01_mode_t, 4);
CHECK_ALIGN(c3b03_t01_phase_t, 4);
CHECK_ALIGN(c3b03_t01_admission_t, 4);

_Static_assert(C3B03_T01_NO_SIGNAL_ABI_VERSION == 1, "ABI_VERSION");
_Static_assert(C3B03_T01_MAX_ATTEMPT_STEPS == 3, "ABI_MAX_STEPS");
_Static_assert(C3B03_T01_MAX_SCENARIO_ID == 67, "ABI_MAX_SCENARIO");
_Static_assert(C3B03_T01_MODE_ESCALATE_POSITIVE == 1, "ABI_MODE");
_Static_assert(C3B03_T01_PHASE_TERM == 1, "ABI_TERM");
_Static_assert(C3B03_T01_PHASE_KILL == 2, "ABI_KILL");
_Static_assert(C3B03_T01_PHASE_CLASSIFY == 3, "ABI_CLASSIFY");
_Static_assert(C3B03_T01_BLOCK == 0, "ABI_BLOCK");
_Static_assert(C3B03_T01_SYNTHETIC_TERM_ADMITTED == 1, "ABI_TERM_DECISION");
_Static_assert(C3B03_T01_SYNTHETIC_KILL_ADMITTED == 2, "ABI_KILL_DECISION");

CHECK_SIZE(c3b03_t01_deadline_t, 64);
CHECK_ALIGN(c3b03_t01_deadline_t, 8);
CHECK_OFF(c3b03_t01_deadline_t, t0_ms, 0);
CHECK_OFF(c3b03_t01_deadline_t, outer_budget_ms, 8);
CHECK_OFF(c3b03_t01_deadline_t, cleanup_reserve_ms, 16);
CHECK_OFF(c3b03_t01_deadline_t, term_grace_ms, 24);
CHECK_OFF(c3b03_t01_deadline_t, kill_entry_margin_ms, 32);
CHECK_OFF(c3b03_t01_deadline_t, outer_deadline_ms, 40);
CHECK_OFF(c3b03_t01_deadline_t, term_cutoff_ms, 48);
CHECK_OFF(c3b03_t01_deadline_t, kill_cutoff_ms, 56);
CHECK_FIELD_SIZE(c3b03_t01_deadline_t, t0_ms, 8);
CHECK_FIELD_SIZE(c3b03_t01_deadline_t, outer_budget_ms, 8);
CHECK_FIELD_SIZE(c3b03_t01_deadline_t, cleanup_reserve_ms, 8);
CHECK_FIELD_SIZE(c3b03_t01_deadline_t, term_grace_ms, 8);
CHECK_FIELD_SIZE(c3b03_t01_deadline_t, kill_entry_margin_ms, 8);
CHECK_FIELD_SIZE(c3b03_t01_deadline_t, outer_deadline_ms, 8);
CHECK_FIELD_SIZE(c3b03_t01_deadline_t, term_cutoff_ms, 8);
CHECK_FIELD_SIZE(c3b03_t01_deadline_t, kill_cutoff_ms, 8);

CHECK_SIZE(c3b03_t01_mock_input_t, 208);
CHECK_ALIGN(c3b03_t01_mock_input_t, 8);
CHECK_OFF(c3b03_t01_mock_input_t, abi_version, 0);
CHECK_OFF(c3b03_t01_mock_input_t, mode, 4);
CHECK_OFF(c3b03_t01_mock_input_t, phase, 8);
CHECK_OFF(c3b03_t01_mock_input_t, scenario_nonce, 16);
CHECK_OFF(c3b03_t01_mock_input_t, scenario_fault_id, 24);
CHECK_OFF(c3b03_t01_mock_input_t, attempt_sequence_len, 28);
CHECK_OFF(c3b03_t01_mock_input_t, attempt_sequence, 32);
CHECK_FIELD_SIZE(c3b03_t01_mock_input_t, attempt_sequence, 12);
CHECK_OFF(c3b03_t01_mock_input_t, term_fact_mask, 48);
CHECK_OFF(c3b03_t01_mock_input_t, kill_fact_mask, 56);
CHECK_OFF(c3b03_t01_mock_input_t, now_ms, 64);
CHECK_OFF(c3b03_t01_mock_input_t, term_sent_at_ms, 72);
CHECK_OFF(c3b03_t01_mock_input_t, original_policy, 80);
CHECK_OFF(c3b03_t01_mock_input_t, attempt_policy, 144);
CHECK_FIELD_SIZE(c3b03_t01_mock_input_t, original_policy, 64);
CHECK_FIELD_SIZE(c3b03_t01_mock_input_t, attempt_policy, 64);
CHECK_FIELD_SIZE(c3b03_t01_mock_input_t, abi_version, 4);
CHECK_FIELD_SIZE(c3b03_t01_mock_input_t, mode, 4);
CHECK_FIELD_SIZE(c3b03_t01_mock_input_t, phase, 4);
CHECK_FIELD_SIZE(c3b03_t01_mock_input_t, scenario_nonce, 8);
CHECK_FIELD_SIZE(c3b03_t01_mock_input_t, scenario_fault_id, 4);
CHECK_FIELD_SIZE(c3b03_t01_mock_input_t, attempt_sequence_len, 4);
CHECK_FIELD_SIZE(c3b03_t01_mock_input_t, term_fact_mask, 8);
CHECK_FIELD_SIZE(c3b03_t01_mock_input_t, kill_fact_mask, 8);
CHECK_FIELD_SIZE(c3b03_t01_mock_input_t, now_ms, 8);
CHECK_FIELD_SIZE(c3b03_t01_mock_input_t, term_sent_at_ms, 8);

CHECK_SIZE(c3b03_t01_mock_output_t, 48);
CHECK_ALIGN(c3b03_t01_mock_output_t, 8);
CHECK_OFF(c3b03_t01_mock_output_t, abi_version, 0);
CHECK_OFF(c3b03_t01_mock_output_t, decision, 4);
CHECK_OFF(c3b03_t01_mock_output_t, scenario_nonce, 8);
CHECK_OFF(c3b03_t01_mock_output_t, fake_term_transport_calls, 16);
CHECK_OFF(c3b03_t01_mock_output_t, fake_kill_transport_calls, 20);
CHECK_OFF(c3b03_t01_mock_output_t, real_group_signal_syscalls, 24);
CHECK_OFF(c3b03_t01_mock_output_t, term_attempts, 28);
CHECK_OFF(c3b03_t01_mock_output_t, kill_attempts, 32);
CHECK_OFF(c3b03_t01_mock_output_t, signals_closed, 36);
CHECK_OFF(c3b03_t01_mock_output_t, group_signals_after_close, 40);
CHECK_FIELD_SIZE(c3b03_t01_mock_output_t, abi_version, 4);
CHECK_FIELD_SIZE(c3b03_t01_mock_output_t, decision, 4);
CHECK_FIELD_SIZE(c3b03_t01_mock_output_t, scenario_nonce, 8);
CHECK_FIELD_SIZE(c3b03_t01_mock_output_t, fake_term_transport_calls, 4);
CHECK_FIELD_SIZE(c3b03_t01_mock_output_t, fake_kill_transport_calls, 4);
CHECK_FIELD_SIZE(c3b03_t01_mock_output_t, real_group_signal_syscalls, 4);
CHECK_FIELD_SIZE(c3b03_t01_mock_output_t, term_attempts, 4);
CHECK_FIELD_SIZE(c3b03_t01_mock_output_t, kill_attempts, 4);
CHECK_FIELD_SIZE(c3b03_t01_mock_output_t, signals_closed, 4);
CHECK_FIELD_SIZE(c3b03_t01_mock_output_t, group_signals_after_close, 4);

/* No functions, exports, initializer or code to invoke. */
typedef char c3b03_compile_only_layout_proof[1];
