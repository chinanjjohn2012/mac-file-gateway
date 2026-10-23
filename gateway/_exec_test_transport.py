"""Private B1-B0 disposable real TCP/REST/MCP listener provenance.

Only the internal acceptance harness imports this module. Every fixture
mints a new private B1-A root and owns one actual, kernel-bound loopback
TCP listener. No normal Gateway/CLI/REST/MCP input grants qualification.

IMPORTANT: This witnesses a *test-only listener*, not a Worker cleanup
proof or permission to spawn a subprocess. Never forward a client Host,
transport string or source-IP as substitute proof.
"""
from __future__ import annotations

import errno
import json
import os
import socket
import sys
import stat
import threading
import time
import urllib.error
import urllib.request

import uvicorn

from ._exec_test_grant import create_private_disposable_acceptance

_KEY = object()
_DARWIN = sys.platform == "darwin"


class _TrustedLoopbackListener:
    """Bound transport and real on-the-wire readiness, not a Host label."""

    def __init__(self, fixture, *, _key=None):
        if _key is not _KEY:
            raise TypeError("Only the internal disposable listener factory may bind.")
        self._fixture = fixture
        self._service = fixture.service
        self._pid = os.getpid()
        self._socket = None
        self._server = None
        self._thread = None
        self._socket_fd = -1
        self._socket_identity = None
        self._wire_ready = False
        self._active = False
        self._error = None
        self.host = "127.0.0.1"
        self.port = 0

    def start(self) -> None:
        """Start only after wrapper owns this instance for failure cleanup.

        The outer fixture must retain a reference BEFORE Uvicorn can become
        active. A startup exception followed by failed join cannot orphan a
        live listener while releasing the service's FD-pinned state root.
        """
        if self._socket is not None or self._thread is not None:
            raise RuntimeError("Disposable Listener may only start once.")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket = sock
            # NO SO_REUSEPORT and NO pick-a-port-close-rebind race:
            # the same kernel-owned socket is handed to Uvicorn.
            sock.bind(("127.0.0.1", 0))
            sock.listen(32)
            sock.setblocking(False)
            addr = sock.getsockname()
            if addr[0] != "127.0.0.1" or type(addr[1]) is not int or addr[1] <= 0:
                raise RuntimeError("Disposable listener did not bind loopback.")
            self.port = addr[1]
            self._socket_fd = sock.fileno()
            pinned = os.fstat(self._socket_fd)
            if not stat.S_ISSOCK(pinned.st_mode):
                raise RuntimeError("Disposable listener is not a socket.")
            self._socket_identity = (pinned.st_dev, pinned.st_ino)

            from .http_multi import create_multi_app
            app = create_multi_app(self._service, enable_mcp=True, port=self.port)
            config = uvicorn.Config(
                app, host=self.host, port=self.port, log_level="error",
                lifespan="on", access_log=False, server_header=False,
                date_header=False,
            )
            self._server = uvicorn.Server(config)
            self._thread = threading.Thread(
                target=self._serve, name="mfg-private-b1b0-loopback",
                daemon=True,
            )
            self._thread.start()
            self._wait_for_real_wire()
            self._active = True
        except BaseException:
            # close() is bounded and retains pinned service resources when
            # an actual listener thread has not been proven exited.
            self.close()
            raise

    def _serve(self) -> None:
        try:
            # The Uvicorn socket is prebound by this exact fixture; no
            # externally specified port or host and no subprocess fork.
            self._server.run(sockets=[self._socket])
        except BaseException as exc:
            self._error = type(exc).__name__

    def _wait_for_real_wire(self) -> None:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        deadline = time.monotonic() + 8.0
        url = f"http://127.0.0.1:{self.port}/health"
        while time.monotonic() < deadline:
            if self._thread is None or not self._thread.is_alive():
                raise RuntimeError("Disposable Uvicorn Listener exited.")
            if self._server.started:
                try:
                    with opener.open(url, timeout=0.5) as response:
                        data = json.loads(response.read())
                        if (response.status == 200 and
                                data.get("status") == "ok" and
                                data.get("mode") == "multi" and
                                data.get("mcp_enabled") is True):
                            self._wire_ready = True
                            return
                except (OSError, ValueError, urllib.error.URLError):
                    pass
            time.sleep(0.025)
        raise RuntimeError("Disposable Listener never became wire-ready.")

    def _listening_socket_proven(self, sock: socket.socket) -> bool:
        """Fail closed on all platforms; Darwin lacks SO_ACCEPTCONN getsockopt.

        Linux checks the pinned listener FD directly. On Darwin, and ONLY
        for the unsupported-option errno, require a bounded real loopback
        TCP handshake to the previously bound port. The caller additionally
        proves original FD identity, sockaddr, active owner, actual HTTP
        readiness and live Uvicorn thread. No Host string alone is trusted.
        """
        try:
            return sock.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 1
        except OSError as exc:
            if not (_DARWIN and exc.errno == errno.ENOPROTOOPT):
                return False
            try:
                with socket.create_connection(
                        (self.host, self.port), timeout=0.35) as probe:
                    return probe.getpeername() == (self.host, self.port)
            except (OSError, ValueError):
                return False

    def _proves_live(self) -> bool:
        """Witness the still-open *original socket* and real served app."""
        if (not self._active or not self._wire_ready or
                os.getpid() != self._pid or self._socket is None or
                self._thread is None or self._server is None):
            return False
        try:
            sock = self._socket
            fd = sock.fileno()
            if (fd < 0 or fd != self._socket_fd or
                    sock.family != socket.AF_INET or
                    sock.type & socket.SOCK_STREAM != socket.SOCK_STREAM):
                return False
            st = os.fstat(fd)
            if (not stat.S_ISSOCK(st.st_mode) or
                    (st.st_dev, st.st_ino) != self._socket_identity):
                return False
            if (sock.getsockname() != ("127.0.0.1", self.port) or
                    not self._listening_socket_proven(sock)):
                return False
            if not self._thread.is_alive() or not self._server.started:
                return False
            return True
        except (OSError, ValueError, AttributeError):
            return False

    def close(self) -> None:
        # Revoke BEFORE network teardown, so no concurrent check can
        # reauthorize a closed listener. The disposable wrapper closes the
        # whole fixture only AFTER this method returns.
        self._active = False
        self._wire_ready = False
        if self._fixture is not None and getattr(self._fixture, "grant", None):
            self._fixture.grant.revoke()
        if self._server is not None:
            self._server.should_exit = True
        # Stop accepting NEW connections before waiting for existing
        # requests and Uvicorn's ASGI lifespan to drain. In particular,
        # a failed/timeout join cannot leave the bound socket accepting.
        # Closing a listener does not terminate an already accepted request.
        if self._socket is not None:
            self._socket.close()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=7)
            if self._thread.is_alive():
                # The wrapper MUST retain service, pinned Workspace root,
                # ExecStateStore and owner lock for a later bounded retry.
                raise RuntimeError("Disposable Uvicorn Listener did not shut down.")


class _BoundDisposableAcceptance:
    """Self-contained, once-issued fixture plus physically bound transport."""

    def __init__(self, *, _key=None):
        if _key is not _KEY:
            raise TypeError("Not a public Gateway service or transport factory.")
        self.fixture = None
        self.listener = None
        self.service = None
        self.grant = None
        self.host = None
        self.port = 0
        try:
            self.fixture = create_private_disposable_acceptance()
            self.service = self.fixture.service
            self.grant = self.fixture.grant
            # Retain partial listener ownership BEFORE any socket/thread
            # startup so a failed constructor cannot drop the fixture
            # while a live Uvicorn thread still references its resources.
            self.listener = _TrustedLoopbackListener(self.fixture, _key=_KEY)
            self.listener.start()
            # The only attachment happens here, after a physical
            # loopback bind+listen and successful REST /health wire read.
            if getattr(self.fixture, "_trusted_bound_listener", None) is not None:
                raise RuntimeError("Disposable Listener already attached.")
            self.fixture._trusted_bound_listener = self.listener
            self.host, self.port = self.listener.host, self.listener.port
        except BaseException:
            self.close()
            raise

    def __enter__(self):
        if self.fixture is None or not self.fixture._active:
            raise RuntimeError("Disposable bound fixture is no longer active.")
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False

    def close(self) -> None:
        # NEVER put fixture.close() in a finally: a failed or timed-out
        # join leaves an actual network thread alive with service/FD
        # references. Preserve ownership and propagate the shutdown
        # error; retry later, after Listener exit is independently proven.
        if self.listener is not None:
            self.listener.close()
        if self.fixture is not None:
            self.fixture.close()


def create_private_bound_transport():
    """Never accept user paths, host, port, existing service or credentials."""
    return _BoundDisposableAcceptance(_key=_KEY)


__all__ = ("create_private_bound_transport",)
