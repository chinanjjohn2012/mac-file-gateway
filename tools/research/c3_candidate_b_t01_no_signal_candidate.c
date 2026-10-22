/*
 * C3 B03-T01 R2b-R2a: INERT C TEST MODEL, SOURCE-ADMISSION CANDIDATE.
 *
 * NOT a Native Owner, Anchor, Controller or Worker implementation.
 * No operating system headers, identifiers, syscalls, process creation,
 * signal transport, linkable signal fallback or native wait evidence.
 * Object is compiled/inspected ONLY. NEVER load/execute at this stage.
 *
 * This file uses exclusively typed, caller-validated SYNTHETIC test facts.
 * Successful fake counters can NEVER prove real process identity or cleanup.
 */
#if !defined(C3B03_TEST_NO_SIGNAL_STUB)
#error "test C candidate requires exact no-signal stub 1"
#elif C3B03_TEST_NO_SIGNAL_STUB != 1
#error "test C candidate requires exact no-signal stub 1"
#endif

#include "c3_b03_t01_no_signal_contract.h"
#include <stdint.h>

#define C3_TERM_TEST_FACTS UINT64_C(0x3fff)
#define C3_KILL_TEST_FACTS UINT64_C(0x1fff)

static int c3_deadline_valid(const c3b03_t01_deadline_t *p) {
    int64_t outer, kill_at, term_at;
    if (p == 0 ||
        p->t0_ms < 0 || p->outer_budget_ms <= 0 ||
        p->cleanup_reserve_ms <= 0 || p->term_grace_ms <= 0 ||
        p->kill_entry_margin_ms <= 0) {
        return 0;
    }
    if (p->t0_ms > INT64_MAX - p->outer_budget_ms) return 0;
    outer = p->t0_ms + p->outer_budget_ms;
    if (p->cleanup_reserve_ms >= p->outer_budget_ms) return 0;
    kill_at = outer - p->cleanup_reserve_ms;
    if (p->term_grace_ms >= kill_at - p->t0_ms) return 0;
    term_at = kill_at - p->term_grace_ms;
    if (p->kill_entry_margin_ms >= term_at - p->t0_ms) return 0;
    term_at -= p->kill_entry_margin_ms;
    return p->outer_deadline_ms == outer &&
           p->kill_cutoff_ms == kill_at &&
           p->term_cutoff_ms == term_at &&
           p->t0_ms < term_at && term_at < kill_at &&
           kill_at < outer;
}

static int c3_deadline_identical(
    const c3b03_t01_deadline_t *a,
    const c3b03_t01_deadline_t *b
) {
    return a->t0_ms == b->t0_ms &&
           a->outer_budget_ms == b->outer_budget_ms &&
           a->cleanup_reserve_ms == b->cleanup_reserve_ms &&
           a->term_grace_ms == b->term_grace_ms &&
           a->kill_entry_margin_ms == b->kill_entry_margin_ms &&
           a->outer_deadline_ms == b->outer_deadline_ms &&
           a->term_cutoff_ms == b->term_cutoff_ms &&
           a->kill_cutoff_ms == b->kill_cutoff_ms;
}

static int c3_term_gate(const c3b03_t01_mock_input_t *in) {
    int64_t t = in->term_sent_at_ms;
    const c3b03_t01_deadline_t *p = &in->original_policy;
    if (in->phase == C3B03_T01_PHASE_TERM) t = in->now_ms;
    return t >= p->t0_ms && t < p->term_cutoff_ms &&
           (in->term_fact_mask & C3_TERM_TEST_FACTS) == C3_TERM_TEST_FACTS;
}

static int c3_kill_gate(const c3b03_t01_mock_input_t *in) {
    const c3b03_t01_deadline_t *p = &in->original_policy;
    int64_t term = in->term_sent_at_ms;
    if (!c3_deadline_identical(p, &in->attempt_policy) ||
        term < p->t0_ms || term >= p->term_cutoff_ms ||
        term > INT64_MAX - p->term_grace_ms ||
        term + p->term_grace_ms >= p->kill_cutoff_ms ||
        in->now_ms < term + p->term_grace_ms ||
        in->now_ms >= p->kill_cutoff_ms ||
        (in->kill_fact_mask & C3_KILL_TEST_FACTS) != C3_KILL_TEST_FACTS) {
        return 0;
    }
    return 1;
}

/*
 * Synthetic fault IDs are fixed *test injection* numbers, never a CLI or
 * runtime signal-authority switch. Native kernel identity is NOT available.
 */
static int c3_term_fault(uint32_t id) {
    return (id >= 1 && id <= 14) || (id >= 52 && id <= 55) ||
           id == 33 || id == 36 || id == 37;
}
static int c3_kill_fault(uint32_t id) {
    return (id >= 17 && id <= 29) || (id >= 56 && id <= 61);
}
static int c3_term_fake_errno(uint32_t id) {
    return id >= 38 && id <= 40;
}
static int c3_kill_fake_errno(uint32_t id) {
    return id >= 41 && id <= 43;
}
static int c3_post_send_evidence_fault(uint32_t id) {
    return (id >= 44 && id <= 51) || id == 64 || id == 65;
}

static void c3_closed_output(
    const c3b03_t01_mock_input_t *in,
    c3b03_t01_mock_output_t *out
) {
    out->abi_version = C3B03_T01_NO_SIGNAL_ABI_VERSION;
    out->decision = C3B03_T01_BLOCK;
    out->scenario_nonce = in ? in->scenario_nonce : UINT64_C(0);
    out->fake_term_transport_calls = 0;
    out->fake_kill_transport_calls = 0;
    out->real_group_signal_syscalls = 0;
    out->term_attempts = 0;
    out->kill_attempts = 0;
    out->signals_closed = 1;
    out->group_signals_after_close = 0;
}

/*
 * A compile-only candidate: DOES NOT call the OS or invoke a signal.
 * Counters track fake, in-memory transport *attempts*, not kernel events.
 * The caller must validate Python target/mode/nonce/ABI/phase/fault/steps
 * and separately prove the loaded object identity BEFORE any later run.
 */
int c3b03_t01_no_signal_candidate(
    const c3b03_t01_mock_input_t *in,
    c3b03_t01_mock_output_t *out
) {
    uint32_t index;
    int term_sent = 0, kill_sent = 0;
    if (out == 0) return 0;
    c3_closed_output(in, out);
    if (in == 0) return 0;
    if (in->abi_version != C3B03_T01_NO_SIGNAL_ABI_VERSION ||
        in->mode != C3B03_T01_MODE_ESCALATE_POSITIVE ||
        in->scenario_nonce == UINT64_C(0) ||
        in->scenario_fault_id == 0 ||
        in->scenario_fault_id > C3B03_T01_MAX_SCENARIO_ID ||
        in->attempt_sequence_len == 0 ||
        in->attempt_sequence_len > C3B03_T01_MAX_ATTEMPT_STEPS ||
        !c3_deadline_valid(&in->original_policy) ||
        !c3_deadline_valid(&in->attempt_policy)) {
        return 1;
    }

    for (index = 0; index < in->attempt_sequence_len; ++index) {
        const c3b03_t01_phase_t step = in->attempt_sequence[index];
        if (step == C3B03_T01_PHASE_TERM) {
            /* Never repeat TERM after first attempt / KILL / refusal. */
            if (term_sent || kill_sent || c3_term_fault(in->scenario_fault_id) ||
                !c3_term_gate(in)) {
                out->decision = C3B03_T01_BLOCK;
                out->signals_closed = 1;
                return 1;
            }
            out->term_attempts = 1;
            out->fake_term_transport_calls = 1;
            term_sent = 1;
            if (c3_term_fake_errno(in->scenario_fault_id)) {
                out->decision = C3B03_T01_BLOCK;
                out->signals_closed = 1;
                return 1;
            }
            out->signals_closed = 0;
            out->decision = C3B03_T01_SYNTHETIC_TERM_ADMITTED;
        } else if (step == C3B03_T01_PHASE_KILL) {
            /* Exact original policy, post-grace, one synthetic KILL only. */
            if (!term_sent || kill_sent ||
                c3_kill_fault(in->scenario_fault_id) ||
                !c3_kill_gate(in) || out->signals_closed) {
                out->decision = C3B03_T01_BLOCK;
                out->signals_closed = 1;
                return 1;
            }
            out->kill_attempts = 1;
            out->fake_kill_transport_calls = 1;
            kill_sent = 1;
            out->signals_closed = 1;
            if (c3_kill_fake_errno(in->scenario_fault_id) ||
                c3_post_send_evidence_fault(in->scenario_fault_id)) {
                out->decision = C3B03_T01_BLOCK;
                return 1;
            }
            out->decision = C3B03_T01_SYNTHETIC_KILL_ADMITTED;
        } else {
            out->decision = C3B03_T01_BLOCK;
            out->signals_closed = 1;
            return 1;
        }
    }
    /* No-signal model never produces lawful waitpid or VERIFIED cleanup. */
    return 1;
}
