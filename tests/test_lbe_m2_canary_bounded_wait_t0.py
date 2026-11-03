"""M2 finite canary child-wait T0: compiled pure C, no native macOS probe.

The test executable calls an exact first-party header with mock waitpid,
monotonic-clock and nanosleep callbacks. There is NO fork, kill, network,
Seatbelt/sandbox_init, compiler toolchain Go/Pipenv or real child. A nominal
timeout means CHILD UNVERIFIED, never proof of process cleanup.
"""
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_HEADER = _ROOT / "tools" / "lbe_m2_canary_bounded_wait_t0.h"
_HELPER = _ROOT / "tools" / "lbe_m2_seatbelt_canary_only.c"

_HARNESS = r"""
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "lbe_m2_canary_bounded_wait_t0.h"

static const char *case_name;
static int wait_count;
static int clock_count;
static int sleep_count;
static long long fake_ns;

static pid_t fake_wait(pid_t child, int *status, int flags) {
    if (child != 12345 || flags != WNOHANG) {
        errno = EINVAL;
        return -1;
    }
    wait_count++;
    if (strcmp(case_name, "late_exit") == 0) {
        /* The selected child exits after spending 2500ms in waitpid. */
        fake_ns = 2500000000LL;
        *status = 0;
        return child;
    }
    if (strcmp(case_name, "midstream_rollback") == 0 &&
        wait_count >= 3) {
        *status = 0;
        return child;
    }
    if (strcmp(case_name, "exit0") == 0) {
        *status = 0;
        return child;
    }
    if (strcmp(case_name, "exit_later") == 0 && wait_count >= 3) {
        *status = 0;
        return child;
    }
    if (strcmp(case_name, "exit_nonzero") == 0) {
        *status = 7 << 8;
        return child;
    }
    if (strcmp(case_name, "signaled") == 0) {
        *status = 9;
        return child;
    }
    if (strcmp(case_name, "eintr_then_exit") == 0) {
        if (wait_count == 1) {
            errno = EINTR;
            return -1;
        }
        *status = 0;
        return child;
    }
    if (strcmp(case_name, "no_child") == 0) {
        errno = ECHILD;
        return -1;
    }
    if (strcmp(case_name, "wrong_child") == 0) {
        return child + 1;
    }
    if (strcmp(case_name, "wait_error") == 0) {
        errno = EIO;
        return -1;
    }
    return 0;
}

static int fake_clock(clockid_t clk, struct timespec *now) {
    if (clk != CLOCK_MONOTONIC) return -1;
    clock_count++;
    if (strcmp(case_name, "clock_error") == 0) {
        errno = EIO;
        return -1;
    }
    if (strcmp(case_name, "midstream_rollback") == 0) {
        /* 0 at start/poll1 -> 1500ms at poll2 -> 100ms at poll3. */
        now->tv_sec = clock_count == 3 ? 1 : 0;
        now->tv_nsec = clock_count == 3 ? 500000000L :
            (clock_count >= 4 ? 100000000L : 0L);
        return 0;
    }
    if (strcmp(case_name, "clock_reverse") == 0) {
        now->tv_sec = clock_count == 1 ? 3 : 2;
        now->tv_nsec = 0;
        return 0;
    }
    if (strcmp(case_name, "clock_invalid_nsec") == 0) {
        now->tv_sec = 0;
        now->tv_nsec = 1000000000L;
        return 0;
    }
    if (strcmp(case_name, "clock_jump") == 0 && clock_count >= 2) {
        now->tv_sec = 15;
        now->tv_nsec = 0;
        return 0;
    }
    now->tv_sec = fake_ns / 1000000000LL;
    now->tv_nsec = fake_ns % 1000000000LL;
    return 0;
}

static int fake_sleep(const struct timespec *tick, struct timespec *remaining) {
    (void)remaining;
    sleep_count++;
    if (tick == NULL || tick->tv_sec != 0 ||
        tick->tv_nsec != LBE_CANARY_POLL_NS) {
        errno = EINVAL;
        return -1;
    }
    if (strcmp(case_name, "sleep_error") == 0) {
        errno = EIO;
        return -1;
    }
    if (strcmp(case_name, "sleep_eintr") == 0 && sleep_count == 1) {
        fake_ns += LBE_CANARY_POLL_NS;
        errno = EINTR;
        return -1;
    }
    if (strcmp(case_name, "stuck_clock") != 0) {
        fake_ns += LBE_CANARY_POLL_NS;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) return 70;
    /* Reference the native wrapper without calling real waitpid in T0. */
    lbe_canary_wait_result (*never_invoke_native)(pid_t) =
        lbe_canary_wait_bounded;
    (void)never_invoke_native;
    case_name = argv[1];
    lbe_canary_wait_result got;
    lbe_canary_wait_result expected;
    if (strcmp(case_name, "invalid_child") == 0) {
        got = lbe_canary_wait_bounded_with(
            0, 2000, fake_wait, fake_clock, fake_sleep);
        expected = LBE_CANARY_CHILD_UNVERIFIED_INVALID_INPUT;
    } else if (strcmp(case_name, "invalid_budget") == 0) {
        got = lbe_canary_wait_bounded_with(
            12345, LBE_CANARY_MAX_WAIT_MS + 1U,
            fake_wait, fake_clock, fake_sleep);
        expected = LBE_CANARY_CHILD_UNVERIFIED_INVALID_INPUT;
    } else if (strcmp(case_name, "missing_callback") == 0) {
        got = lbe_canary_wait_bounded_with(
            12345, 100U, NULL, fake_clock, fake_sleep);
        expected = LBE_CANARY_CHILD_UNVERIFIED_INVALID_INPUT;
    } else {
        got = lbe_canary_wait_bounded_with(
            12345, 2000U, fake_wait, fake_clock, fake_sleep);
        if (strcmp(case_name, "exit0") == 0 ||
            strcmp(case_name, "exit_later") == 0 ||
            strcmp(case_name, "eintr_then_exit") == 0) {
            expected = LBE_CANARY_CHILD_EXIT_0;
        } else if (strcmp(case_name, "exit_nonzero") == 0 ||
                   strcmp(case_name, "signaled") == 0) {
            expected = LBE_CANARY_CHILD_EXIT_FAILURE;
        } else if (strcmp(case_name, "no_child") == 0 ||
                   strcmp(case_name, "wrong_child") == 0 ||
                   strcmp(case_name, "wait_error") == 0) {
            expected = LBE_CANARY_CHILD_UNVERIFIED_WAIT_ERROR;
        } else if (strcmp(case_name, "clock_error") == 0 ||
                   strcmp(case_name, "clock_reverse") == 0 ||
                   strcmp(case_name, "clock_invalid_nsec") == 0 ||
                   strcmp(case_name, "midstream_rollback") == 0) {
            expected = LBE_CANARY_CHILD_UNVERIFIED_CLOCK_ERROR;
        } else if (strcmp(case_name, "late_exit") == 0) {
            expected = LBE_CANARY_CHILD_UNVERIFIED_TIMEOUT;
        } else if (strcmp(case_name, "sleep_error") == 0) {
            expected = LBE_CANARY_CHILD_UNVERIFIED_SLEEP_ERROR;
        } else {
            expected = LBE_CANARY_CHILD_UNVERIFIED_TIMEOUT;
        }
    }
    if (got != expected) {
        fprintf(stderr, "%s: got=%d expected=%d polls=%d clock=%d sleep=%d\n",
                case_name, (int)got, (int)expected, wait_count,
                clock_count, sleep_count);
        return 71;
    }
    if (wait_count > (int)LBE_CANARY_MAX_POLLS ||
        sleep_count > (int)LBE_CANARY_MAX_POLLS) return 72;
    if ((strcmp(case_name, "stuck_clock") == 0 ||
         strcmp(case_name, "timeout") == 0) &&
        (got != LBE_CANARY_CHILD_UNVERIFIED_TIMEOUT ||
         wait_count == 0)) return 73;
    /* Unknown child/survivor cases can NEVER be interpreted as PASS. */
    if ((strcmp(case_name, "no_child") == 0 ||
         strcmp(case_name, "timeout") == 0 ||
         strcmp(case_name, "stuck_clock") == 0) &&
         got == LBE_CANARY_CHILD_EXIT_0) return 74;
    return 0;
}
"""


@pytest.fixture(scope="module")
def fake_wait_binary(tmp_path_factory):
    if sys.platform != "linux":
        pytest.skip("Portable C callback fixture is Linux-only T0")
    compiler = shutil.which("cc")
    assert compiler, "T0 C compiler is missing; do not claim C PASS"
    base = tmp_path_factory.mktemp("m2_canary_wait_t0")
    src = base / "fake_wait.c"
    out = base / "fake_wait"
    src.write_text(_HARNESS, encoding="ascii")
    result = subprocess.run([
        compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-O0",
        "-I", str(_ROOT / "tools"), str(src), "-o", str(out),
    ], capture_output=True, text=True, timeout=20, check=False)
    assert result.returncode == 0, result.stderr[-3500:]
    return out


@pytest.mark.parametrize("case", (
    "exit0", "exit_later", "exit_nonzero", "signaled",
    "eintr_then_exit", "no_child", "wrong_child", "wait_error",
    "clock_error", "clock_reverse", "clock_invalid_nsec", "clock_jump",
    "sleep_error", "sleep_eintr", "stuck_clock", "timeout",
    "invalid_child", "invalid_budget", "missing_callback",
    "late_exit", "midstream_rollback",
))
def test_bounded_wait_first_party_compiled_header_with_fake_os(
    fake_wait_binary, case,
):
    r = subprocess.run(
        [str(fake_wait_binary), case],
        stdin=subprocess.DEVNULL, capture_output=True, text=True,
        timeout=5, check=False,
    )
    assert r.returncode == 0, (
        f"{case} RC {r.returncode}: {r.stderr[-2000:]}"
    )


def test_canary_helper_has_no_blocking_waitpid_and_no_os_kill_path():
    helper = _HELPER.read_text(encoding="ascii")
    header = _HEADER.read_text(encoding="ascii")
    assert '#include "lbe_m2_canary_bounded_wait_t0.h"' in helper
    assert "lbe_canary_wait_bounded(child)" in helper
    assert "waitpid(child, &status, 0)" not in helper
    assert "WNOHANG" in header
    assert "CLOCK_MONOTONIC" in header
    assert "LBE_CANARY_MAX_WAIT_MS 2000U" in header
    assert "LBE_CANARY_MAX_POLLS 256U" in header
    assert "LBE_CANARY_CHILD_UNVERIFIED_TIMEOUT" in header
    assert "kill(" not in header and "killpg(" not in header
    assert "posix_spawn(" not in header and "execve(" not in header
    assert "return 69;" in helper
