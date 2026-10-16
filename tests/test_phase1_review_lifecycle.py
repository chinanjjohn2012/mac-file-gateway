"""F2: synchronous operations outlive cancellation, but not their owned FDs.

Fixtures use isolated directories, real AnyIO workers and a temporary listener.
No production services or business commands are touched.
"""
import asyncio
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import pytest
from starlette.concurrency import run_in_threadpool
from starlette.testclient import TestClient

from gateway import write_storage
from gateway.core import GatewayError
from gateway.http_multi import create_multi_app
from gateway.workspaces import ActiveRuntimeInventory, WorkspaceService
from gateway.workspaces_config import parse_workspace_config


@pytest.fixture
def service_tree(tmp_path):
    paths = {name: tmp_path / name for name in ('a', 'b', 'config', 'runtime')}
    for path in paths.values():
        path.mkdir()
    (paths['a'] / 'sample.py').write_bytes(b'before\n')
    (paths['b'] / 'sample.py').write_bytes(b'readonly\n')
    settings = parse_workspace_config({'schema_version': 1, 'workspaces': {
        'a': {'root': str(paths['a']), 'write': {'enabled': True, 'paths': ['.']}},
        'b': {'root': str(paths['b'])},
    }})
    service = WorkspaceService(settings, config_dir=paths['config'],
                               inventory=ActiveRuntimeInventory(paths=(paths['runtime'],)))
    yield service, paths
    service.close()


@pytest.mark.parametrize('closer_count', [1, 2])
def test_cancelled_awaiter_cannot_release_a_live_write_descriptor(service_tree, monkeypatch, closer_count):
    service, paths = service_tree
    original_lock = write_storage.write_lock
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    captured, results, errors = [], [], []
    close_done = [threading.Event() for _ in range(closer_count)]

    @contextmanager
    def paused_lock(root_fd):
        captured.append(root_fd)
        entered.set()
        if not release.wait(8):
            raise RuntimeError('test worker was not released')
        with original_lock(root_fd) as state:
            yield state

    monkeypatch.setattr(write_storage, 'write_lock', paused_lock)

    def write():
        try:
            results.append(service.invoke('a', 'write_file', 'sample.py', 'after\n',
                                          hashlib.sha256(b'before\n').hexdigest(), False))
        except BaseException as exc:
            errors.append(exc)
        finally:
            finished.set()

    def close(index):
        try:
            service.close()
        except BaseException as exc:
            errors.append(exc)
        finally:
            close_done[index].set()

    async def scenario():
        request = asyncio.create_task(run_in_threadpool(write))
        threads, allocations = [], []
        try:
            assert await asyncio.to_thread(entered.wait, 3)
            # One slow Workspace must not hold the service state mutex.
            other = await asyncio.wait_for(run_in_threadpool(service.invoke, 'b', 'read_file', 'sample.py'), 2)
            assert 'readonly' in other['content']
            assert len(service.list_workspaces()['workspaces']) == 2
            request.cancel()
            with pytest.raises(asyncio.CancelledError):
                await request
            assert not finished.is_set()
            for i in range(closer_count):
                thread = threading.Thread(target=close, args=(i,), daemon=True)
                thread.start()
                threads.append(thread)
            # Close must remain blocked while the actual sync write is paused.
            returned_early = await asyncio.to_thread(close_done[0].wait, 0.15)
            # Ordinary allocation, never dup2(): old code naturally reuses A's FD.
            for _ in range(64):
                allocations.append(os.open(paths['b'], os.O_RDONLY | os.O_DIRECTORY))
            descriptor_reused = captured[0] in allocations
            release.set()
            assert await asyncio.to_thread(finished.wait, 4)
            for done in close_done:
                assert await asyncio.to_thread(done.wait, 4)
            assert not returned_early, 'close returned while a cancelled request worker still owned root_fd'
            assert not descriptor_reused, 'a live operation root_fd was reallocated to another Workspace'
            assert not errors, errors
            assert results[0]['applied'] is True
            assert (paths['a'] / 'sample.py').read_bytes() == b'after\n'
            assert (paths['a'] / results[0]['backup_path']).read_bytes() == b'before\n'
            assert (paths['b'] / 'sample.py').read_bytes() == b'readonly\n'
            assert not (paths['b'] / '.gateway-backups').exists()
        finally:
            release.set()
            await asyncio.to_thread(finished.wait, 4)
            for thread in threads:
                await asyncio.to_thread(thread.join, 4)
            for fd in allocations:
                os.close(fd)
            if not request.done():
                request.cancel()
                await asyncio.gather(request, return_exceptions=True)

    asyncio.run(scenario())


def test_operation_exception_releases_lease_and_close_is_idempotent(service_tree):
    service, _ = service_tree
    with pytest.raises(GatewayError):
        service.invoke('a', 'read_file', 'missing.py')
    done = threading.Event()
    thread = threading.Thread(target=lambda: (service.close(), done.set()), daemon=True)
    thread.start()
    assert done.wait(3), 'failed operations must release their lifecycle lease'
    thread.join(3)
    service.close()


def test_work_started_after_shutdown_is_rejected_before_filesystem_dispatch(service_tree, monkeypatch):
    service, paths = service_tree
    gateway = service.get('a').gateway
    called = []
    monkeypatch.setattr(gateway, 'read_file', lambda *a, **k: called.append(True))
    service.close()
    with pytest.raises(GatewayError) as exc:
        service.invoke('a', 'read_file', 'sample.py')
    assert exc.value.code == 'service_closing'
    assert not called


def test_rest_read_and_write_are_unavailable_after_service_shutdown(service_tree):
    service, paths = service_tree
    with TestClient(create_multi_app(service, enable_mcp=False), base_url='http://127.0.0.1:8765') as client:
        service.close()
        read = client.get('/read', params={'workspace': 'a', 'path': 'sample.py'})
        write = client.post('/create', json={'workspace': 'a', 'path': 'new.py', 'content': 'x', 'dry_run': False})
        for response in (read, write):
            assert response.status_code == 503
            assert response.json()['error'] == 'service_closing'
        assert not (paths['a'] / 'new.py').exists()


_CHILD = r'''
import sys, time
from pathlib import Path
from contextlib import contextmanager
from types import SimpleNamespace
import uvicorn
from gateway import write_storage
from gateway import multi_cli
root, config = Path(sys.argv[1]), sys.argv[2]
original_lock = write_storage.write_lock
@contextmanager
def pause(root_fd):
    (root / 'entered').touch()
    deadline = time.monotonic() + 15
    while not (root / 'release').exists():
        if time.monotonic() > deadline:
            raise RuntimeError('isolated test release timeout')
        time.sleep(0.01)
    with original_lock(root_fd) as state:
        yield state
write_storage.write_lock = pause
original_close = multi_cli.WorkspaceService.close
def close(self):
    (root / 'closing').touch()
    return original_close(self)
multi_cli.WorkspaceService.close = close
original_run = uvicorn.run
def run(*args, **kwargs):
    kwargs['timeout_graceful_shutdown'] = 0.1
    return original_run(*args, **kwargs)
uvicorn.run = run
raise SystemExit(multi_cli.run_multi(SimpleNamespace(config=config, check=False, http_only=True)))
'''


def test_real_listener_forced_graceful_timeout_drains_sync_write(tmp_path):
    """Shortened real Uvicorn timeout, not a simulation of arbitrary slow disks."""
    if os.name != 'posix':
        pytest.skip('POSIX process signals required')
    for name in ('a', 'b', 'config'):
        (tmp_path / name).mkdir()
    (tmp_path / 'a' / 'sample.py').write_bytes(b'before\n')
    (tmp_path / 'b' / 'sample.py').write_bytes(b'readonly\n')
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    config = tmp_path / 'config' / 'gateway.json'
    config.write_text(json.dumps({'schema_version': 1, 'server': {'port': port}, 'workspaces': {
        'a': {'root': str(tmp_path / 'a'), 'write': {'enabled': True, 'paths': ['.']}},
        'b': {'root': str(tmp_path / 'b')},
    }}))
    env = os.environ.copy()
    env.pop('GATEWAY_TOKEN', None)
    base = f'http://127.0.0.1:{port}'

    def request_write():
        body = json.dumps({'workspace': 'a', 'path': 'sample.py', 'content': 'after\n',
                           'expected_sha256': hashlib.sha256(b'before\n').hexdigest(), 'dry_run': False}).encode()
        try:
            with urlopen(Request(base + '/write', data=body, headers={'Content-Type': 'application/json'}), timeout=12) as response:
                return response.status
        except (HTTPError, URLError, OSError):
            # The ASGI waiter may be cancelled. The sync worker still must drain.
            return None

    def wait_until(predicate, seconds=5):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if predicate():
                return True
            if proc.poll() is not None:
                return False
            time.sleep(0.02)
        return False

    with (tmp_path / 'listener.log').open('w') as log:
        proc = subprocess.Popen([sys.executable, '-c', _CHILD, str(tmp_path), str(config)],
                                cwd=Path(__file__).resolve().parents[1], env=env,
                                stdout=log, stderr=log, start_new_session=True)
        with ThreadPoolExecutor(max_workers=1) as executor:
            try:
                def ready():
                    try:
                        with urlopen(base + '/health', timeout=0.2) as response:
                            return response.status == 200
                    except (URLError, OSError):
                        return False
                assert wait_until(ready), 'temporary listener did not start'
                future = executor.submit(request_write)
                assert wait_until(lambda: (tmp_path / 'entered').exists())
                proc.send_signal(signal.SIGTERM)
                assert wait_until(lambda: (tmp_path / 'closing').exists()), 'service close was not reached'
                # Still-running write must keep the process/owned FDs alive.
                time.sleep(0.15)
                remained_alive = proc.poll() is None
                (tmp_path / 'release').touch()
                proc.wait(timeout=5)
                future.result(timeout=5)
                assert remained_alive, 'listener exited without draining its synchronous operation'
                assert (tmp_path / 'a' / 'sample.py').read_bytes() == b'after\n'
                backups = list((tmp_path / 'a' / '.gateway-backups').glob('*.bak'))
                assert len(backups) == 1 and backups[0].read_bytes() == b'before\n'
                assert not (tmp_path / 'b' / '.gateway-backups').exists()
                assert (tmp_path / 'b' / 'sample.py').read_bytes() == b'readonly\n'
            finally:
                (tmp_path / 'release').touch()
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=5)
