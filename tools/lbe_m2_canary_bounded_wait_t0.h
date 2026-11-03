/*
 * M2 macOS canary-only bounded CHILD OBSERVATION, T0 candidate.
 *
 * No fork, no process start, no networking, no signals or cleanup here.
 * This header NEVER proves a timed-out or unknown child has exited.
 * It polls ONLY an already-owned child with WNOHANG and a monotonic
 * deadline. Even TIMEOUT returns FAIL_UNVERIFIED, NOT a retire grant.
 * A future macOS canary must not run until a separately reviewed runner
 * can safely bound/own any surviving descendant without unapproved kill.
 */
#ifndef LBE_M2_CANARY_BOUNDED_WAIT_T0_H
#define LBE_M2_CANARY_BOUNDED_WAIT_T0_H

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>

#define LBE_CANARY_MAX_WAIT_MS 2000U
#define LBE_CANARY_POLL_NS 10000000L
#define LBE_CANARY_MAX_POLLS 256U

typedef enum {
    LBE_CANARY_CHILD_EXIT_0 = 0,
    LBE_CANARY_CHILD_EXIT_FAILURE = 1,
    LBE_CANARY_CHILD_UNVERIFIED_TIMEOUT = 2,
    LBE_CANARY_CHILD_UNVERIFIED_WAIT_ERROR = 3,
    LBE_CANARY_CHILD_UNVERIFIED_CLOCK_ERROR = 4,
    LBE_CANARY_CHILD_UNVERIFIED_SLEEP_ERROR = 5,
    LBE_CANARY_CHILD_UNVERIFIED_INVALID_INPUT = 6
} lbe_canary_wait_result;

typedef pid_t (*lbe_canary_wait_call)(pid_t, int *, int);
typedef int (*lbe_canary_clock_call)(clockid_t, struct timespec *);
typedef int (*lbe_canary_sleep_call)(const struct timespec *, struct timespec *);

/* Deny invalid/non-monotonic time, not merely a tick-count approximation. */
static bool lbe_canary_deadline_reached(
    const struct timespec *start, const struct timespec *now,
    unsigned int max_wait_ms, bool *expired
) {
    if (start == NULL || now == NULL || expired == NULL ||
        max_wait_ms == 0 || max_wait_ms > LBE_CANARY_MAX_WAIT_MS ||
        start->tv_sec < 0 || now->tv_sec < start->tv_sec ||
        start->tv_nsec < 0 || start->tv_nsec >= 1000000000L ||
        now->tv_nsec < 0 || now->tv_nsec >= 1000000000L) {
        return false;
    }
    const int64_t seconds = (int64_t)(now->tv_sec - start->tv_sec);
    /* Short-circuit large jumps before any multiplication overflow. */
    if (seconds > 10) {
        *expired = true;
        return true;
    }
    const int64_t elapsed_ns = seconds * 1000000000LL
        + (int64_t)now->tv_nsec - (int64_t)start->tv_nsec;
    if (elapsed_ns < 0) {
        return false;
    }
    *expired = (uint64_t)elapsed_ns >=
        ((uint64_t)max_wait_ms * 1000000ULL);
    return true;
}

/*
 * A CLOCK_MONOTONIC fault-injection observer must NEVER accept a timestamp
 * earlier than the PREVIOUS observation. Comparison against the initial
 * start alone misses start=0 -> 1500ms -> 100ms rollback. This guard is
 * an algorithmic T0 oracle, NOT independent OS clock attestation.
 */
static bool lbe_canary_clock_not_reversed(
    const struct timespec *previous, const struct timespec *now
) {
    return previous != NULL && now != NULL &&
        previous->tv_sec >= 0 && now->tv_sec >= 0 &&
        previous->tv_nsec >= 0 && previous->tv_nsec < 1000000000L &&
        now->tv_nsec >= 0 && now->tv_nsec < 1000000000L &&
        (now->tv_sec > previous->tv_sec ||
         (now->tv_sec == previous->tv_sec &&
          now->tv_nsec >= previous->tv_nsec));
}

/*
 * _with injects deterministic first-party T0 callbacks ONLY. Native helper
 * always binds exact libc waitpid/clock_gettime/nanosleep functions.
 * There is deliberately no POSIX kill/killpg/signal/escalation path.
 */
static lbe_canary_wait_result lbe_canary_wait_bounded_with(
    pid_t child, unsigned int max_wait_ms,
    lbe_canary_wait_call wait_call,
    lbe_canary_clock_call clock_call,
    lbe_canary_sleep_call sleep_call
) {
    if (child <= 0 || max_wait_ms == 0 ||
        max_wait_ms > LBE_CANARY_MAX_WAIT_MS ||
        wait_call == NULL || clock_call == NULL || sleep_call == NULL) {
        return LBE_CANARY_CHILD_UNVERIFIED_INVALID_INPUT;
    }
    struct timespec start = {0, 0};
    if (clock_call(CLOCK_MONOTONIC, &start) != 0 ||
        start.tv_sec < 0 || start.tv_nsec < 0 ||
        start.tv_nsec >= 1000000000L) {
        return LBE_CANARY_CHILD_UNVERIFIED_CLOCK_ERROR;
    }
    struct timespec previous = start;
    for (unsigned int poll = 0; poll < LBE_CANARY_MAX_POLLS; ++poll) {
        struct timespec now = {0, 0};
        bool timed_out = false;
        if (clock_call(CLOCK_MONOTONIC, &now) != 0 ||
            !lbe_canary_clock_not_reversed(&previous, &now) ||
            !lbe_canary_deadline_reached(
                &start, &now, max_wait_ms, &timed_out)) {
            return LBE_CANARY_CHILD_UNVERIFIED_CLOCK_ERROR;
        }
        previous = now;
        if (timed_out) {
            return LBE_CANARY_CHILD_UNVERIFIED_TIMEOUT;
        }
        int status = 0;
        errno = 0;
        const pid_t observed = wait_call(child, &status, WNOHANG);
        if (observed == child) {
            /*
             * Do not accept an exit after a potentially delayed waitpid or
             * scheduler preemption. At exactly the deadline, refuse success.
             * This is still not a physical OS-enforced wall-time guarantee.
             */
            struct timespec after_wait = {0, 0};
            bool expired_after_wait = false;
            if (clock_call(CLOCK_MONOTONIC, &after_wait) != 0 ||
                !lbe_canary_clock_not_reversed(&previous, &after_wait) ||
                !lbe_canary_deadline_reached(
                    &start, &after_wait, max_wait_ms,
                    &expired_after_wait)) {
                return LBE_CANARY_CHILD_UNVERIFIED_CLOCK_ERROR;
            }
            if (expired_after_wait) {
                return LBE_CANARY_CHILD_UNVERIFIED_TIMEOUT;
            }
            if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                return LBE_CANARY_CHILD_EXIT_0;
            }
            return LBE_CANARY_CHILD_EXIT_FAILURE;
        }
        if (observed != 0 && !(observed < 0 && errno == EINTR)) {
            return LBE_CANARY_CHILD_UNVERIFIED_WAIT_ERROR;
        }
        const struct timespec tick = {0, LBE_CANARY_POLL_NS};
        if (sleep_call(&tick, NULL) != 0 && errno != EINTR) {
            return LBE_CANARY_CHILD_UNVERIFIED_SLEEP_ERROR;
        }
    }
    /* A stopped/malicious clock cannot keep the parent in an endless loop. */
    return LBE_CANARY_CHILD_UNVERIFIED_TIMEOUT;
}

static lbe_canary_wait_result lbe_canary_wait_bounded(pid_t child) {
    return lbe_canary_wait_bounded_with(
        child, LBE_CANARY_MAX_WAIT_MS, waitpid, clock_gettime, nanosleep);
}

#endif /* LBE_M2_CANARY_BOUNDED_WAIT_T0_H */
