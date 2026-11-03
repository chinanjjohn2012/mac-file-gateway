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
