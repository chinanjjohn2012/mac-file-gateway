"""PR110 r002 high-numbered inherited-FD regression, harmless T0 only.

No native Seatbelt, Go/Pipenv, public networking, privilege, process signals
or host-level resource changes. Only a disposable child Python interpreter
demonstrates the r001 C source loop's defect on a private AF_UNIX descriptor.
"""
from pathlib import Path
import subprocess
import sys
import textwrap

_ROOT = Path(__file__).resolve().parents[1]
_C = _ROOT / "tools" / "lbe_m2_seatbelt_canary_only.c"


def test_r002_p2_soft_nofile_range_is_not_complete_fd_cleanup():
    source = _C.read_text(encoding="ascii")
    # PR110 r001 loop bounded solely by soft RLIMIT_NOFILE omitted open FDs
    # at higher indices. A new implementation must NOT depend on that cap.
    assert "for (int fd = 3; (rlim_t)fd < rlim.rlim_cur; fd++)" not in source
    assert "lbe_scrub_inherited_fds()" in source


def test_r002_p2_source_must_enumerate_and_verify_all_open_fds():
    source = _C.read_text(encoding="ascii")
    assert '#include "lbe_m2_fd_scrub_t0.h"' in source
    header = _ROOT / "tools" / "lbe_m2_fd_scrub_t0.h"
    checked = header.read_text(encoding="ascii")
    assert "opendir(directory)" in checked
    assert "readdir(" in checked
    assert "dirfd(" in checked
    assert "lbe_verify_no_remaining_fds" in checked
    assert "getrlimit(RLIMIT_NOFILE" not in checked


def test_r002_p2_actual_safe_posix_fd_above_reduced_soft_limit_survives_old_loop():
    # Run this in a disposable Python child, so no changes leak into pytest's
    # parent RLIMIT or open FDs; socketpair is local AF_UNIX, no network.
    script = textwrap.dedent("""
        import errno
        import fcntl
        import os
        import resource
        import socket

        pair = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        high = fcntl.fcntl(pair[0].fileno(), fcntl.F_DUPFD, 128)
        for sock in pair:
            sock.close()
        before = fcntl.fcntl(high, fcntl.F_GETFD)
        assert before >= 0
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        assert soft >= 129
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, hard))
        assert resource.getrlimit(resource.RLIMIT_NOFILE)[0] == 64
        # Exactly source-equivalent r001 algorithm, not compiled C:
        for fd in range(3, 64):
            try:
                os.close(fd)
            except OSError as exc:
                assert exc.errno == errno.EBADF
        assert fcntl.fcntl(high, fcntl.F_GETFD) >= 0
        os.close(high)
    """)
    result = subprocess.run(
        [sys.executable, "-I", "-c", script],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr[:1500]



# Linux only: compile the EXACT portable first-party FD scrub header in an
# isolated disposable helper with no sandbox_init, Go/Pipenv, outbound
# connections or host privilege. This is T0 algorithm evidence, NOT a
# native Darwin Seatbelt canary or proof of its policy inheritance.
import shutil
import pytest


_POSIX_FD_T0_HARNESS = r"""
#define _DEFAULT_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include "lbe_m2_fd_scrub_t0.h"

static int injected_close_error(int fd) {
    (void)fd;
    errno = EIO;
    return -1;
}

int main(int argc, char **argv) {
    if (argc != 2) return 80;
    if (strcmp(argv[1], "clean") == 0)
        return lbe_scrub_inherited_fds() ? 0 : 81;
    if (strcmp(argv[1], "missing-directory") == 0)
        return lbe_scrub_inherited_fds_with(
            "/this/does/not/exist/pr110/fd-scrub", close) ? 82 : 0;
    if (strcmp(argv[1], "stdio-socket") == 0) {
        int fds[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) return 83;
        if (dup2(fds[0], 0) < 0) return 84;
        if (close(fds[0]) != 0 || close(fds[1]) != 0) return 85;
        return lbe_scrub_inherited_fds() ? 86 : 0;
    }
    if (strcmp(argv[1], "high") != 0 &&
        strcmp(argv[1], "close-error") != 0)
        return 87;
    struct rlimit limits;
    if (getrlimit(RLIMIT_NOFILE, &limits) != 0 ||
        limits.rlim_cur < 129) return 88;
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) return 89;
    int high = fcntl(fds[0], F_DUPFD, 128);
    if (high < 128) return 90;
    if (close(fds[0]) != 0 || close(fds[1]) != 0) return 91;
    if (fcntl(high, F_GETFD) < 0) return 92;
    limits.rlim_cur = 64;  /* lower ONLY own disposable child */
    if (setrlimit(RLIMIT_NOFILE, &limits) != 0) return 93;
    if (strcmp(argv[1], "close-error") == 0) {
        bool accepted = lbe_scrub_inherited_fds_with(
            LBE_FD_DIRECTORY, injected_close_error);
        return accepted ? 94 : 0;
    }
    if (!lbe_scrub_inherited_fds()) return 95;
    errno = 0;
    if (fcntl(high, F_GETFD) != -1 || errno != EBADF) return 96;
    return 0;
}
"""


@pytest.mark.skipif(sys.platform != "linux",
                    reason="safe standalone C FD-algorithm fixture runs on Linux only")
@pytest.mark.parametrize("case", (
    "clean", "high", "close-error", "missing-directory", "stdio-socket",
))
def test_r002_p2_actual_compiled_first_party_fd_scrub_t0(
        tmp_path, case):
    compiler = shutil.which("cc")
    assert compiler, "required safe T0 C compiler not available"
    c_file = tmp_path / "fd_harness.c"
    executable = tmp_path / "fd_harness"
    c_file.write_text(_POSIX_FD_T0_HARNESS, encoding="ascii")
    built = subprocess.run([
        compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-O0",
        "-I", str(_ROOT / "tools"), str(c_file),
        "-o", str(executable),
    ], capture_output=True, text=True, check=False)
    assert built.returncode == 0, built.stderr[-2400:]
    ran = subprocess.run(
        [str(executable), case], stdin=subprocess.DEVNULL,
        capture_output=True, text=True, check=False)
    assert ran.returncode == 0, (
        f"{case} returned {ran.returncode}, stderr={ran.stderr[-1500:]}"
    )
