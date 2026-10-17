"""Disposable real-SDK ASGI mechanism matrix. No Gateway/listener/subprocess.

Run in separate interpreters with PYTHONPATH selecting an immutable SDK copy.
State inspection and explicit barriers are test instrumentation, not fake SDKs.
"""
from pathlib import Path
from contextlib import asynccontextmanager
from collections import defaultdict
import hashlib
import importlib.metadata
import inspect
import json
import os
import subprocess
import sys
from unittest.mock import patch

import anyio
import httpx
from starlette.middleware.authentication import AuthenticationMiddleware
from mcp.server.auth.middleware.bearer_auth import BearerAuthBackend
from mcp.server.auth.provider import AccessToken
from mcp.server.fastmcp import FastMCP, Context
import mcp.server.streamable_http as transport_module

HEADERS = {'Accept': 'application/json, text/event-stream', 'Content-Type': 'application/json',
           'MCP-Protocol-Version': '2025-11-25', 'Authorization': 'Bearer synthetic-A'}
spawn_attempts = []


def no_spawn(*args, **kwargs):
    spawn_attempts.append(True)
    raise AssertionError('SDK-only fixture forbids subprocesses')


async def until(predicate, seconds=1):
    with anyio.fail_after(seconds):
        while not predicate():
            await anyio.sleep(0.001)


class TrackedDict(dict):
    def __init__(self, data=()):
        super().__init__(data)
        self.writes = []

    def __setitem__(self, key, value):
        self.writes.append({'key_type': type(key).__name__, 'key': str(key)})
        return super().__setitem__(key, value)


class SyntheticVerifier:
    async def verify_token(self, token):
        if token not in ('synthetic-A', 'synthetic-B'):
            return None
        return AccessToken(token=token, client_id=token, subject=token, scopes=[],
                           claims={'iss': 'urn:synthetic-pr3'})


class Fixture:
    def __init__(self, stateless=False):
        self.started = defaultdict(anyio.Event)
        self.release = defaultdict(anyio.Event)
        self.cancelled = defaultdict(anyio.Event)
        self.finished = defaultdict(anyio.Event)
        self.sessions = {}
        self.calls = []
        self.server = FastMCP('throwaway-pr3', stateless_http=stateless, json_response=True,
                             host='127.0.0.1', port=9878, log_level='ERROR')
        fixture = self

        @self.server.tool()
        async def synthetic_wait(label: str, ctx: Context, wait: bool = False) -> dict[str, str]:
            fixture.calls.append(label)
            fixture.sessions[label] = ctx.session
            fixture.started[label].set()
            try:
                if wait:
                    await fixture.release[label].wait()
                return {'served_label': label}
            except anyio.get_cancelled_exc_class():
                fixture.cancelled[label].set()
                raise
            finally:
                fixture.finished[label].set()

        self.app = self.server.streamable_http_app()
        self.auth_app = AuthenticationMiddleware(self.app, backend=BearerAuthBackend(SyntheticVerifier()))
        self.stateless = stateless

    @asynccontextmanager
    async def run(self):
        async with self.app.router.lifespan_context(self.app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=self.auth_app),
                                        base_url='http://127.0.0.1:9878', headers=HEADERS) as client:
                self.client = client
                if not self.stateless:
                    self.sid = await self.initialize()
                try:
                    yield self
                finally:
                    for event in self.release.values():
                        event.set()

    async def initialize(self, owner='synthetic-A'):
        headers = {'Authorization': 'Bearer ' + owner}
        response = await self.client.post('/mcp', headers=headers, json={
            'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
            'params': {'protocolVersion': '2025-11-25', 'capabilities': {},
                       'clientInfo': {'name': 'throwaway-pr3', 'version': '1'}}})
        assert response.status_code == 200
        sid = response.headers['mcp-session-id']
        await self.client.post('/mcp', headers={**headers, 'Mcp-Session-Id': sid},
                               json={'jsonrpc': '2.0', 'method': 'notifications/initialized'})
        transport = self.server.session_manager._server_instances[sid]
        transport._request_streams = TrackedDict(transport._request_streams)
        return sid

    def transport(self, sid=None):
        return self.server.session_manager._server_instances[sid or self.sid]

    def route_key(self, wire_id):
        encoder = getattr(transport_module, '_probe_rpc_route_key', str)
        return encoder(wire_id)

    async def post(self, rid, label, wait=False, sid=None, owner='synthetic-A'):
        headers = {'Authorization': 'Bearer ' + owner}
        if not self.stateless:
            headers['Mcp-Session-Id'] = sid or self.sid
        with anyio.move_on_after(1.5) as scope:
            response = await self.client.post('/mcp', headers=headers, json={
                'jsonrpc': '2.0', 'id': rid, 'method': 'tools/call',
                'params': {'name': 'synthetic_wait', 'arguments': {'label': label, 'wait': wait}}})
            return {'status': response.status_code, 'body': response.json()}
        assert scope.cancel_called
        return {'waiter_timeout': True}

    async def cancel(self, rid, sid=None, owner='synthetic-A'):
        response = await self.client.post('/mcp', headers={
            'Mcp-Session-Id': sid or self.sid, 'Authorization': 'Bearer ' + owner},
            json={'jsonrpc': '2.0', 'method': 'notifications/cancelled', 'params': {'requestId': rid}})
        return response.status_code


def correct(response, rid, label):
    body = response.get('body', {})
    return (response.get('status') == 200 and type(body.get('id')) is type(rid)
            and body.get('id') == rid and not body.get('result', {}).get('isError', True)
            and body.get('result', {}).get('structuredContent', {}).get('served_label') == label)


async def pair(ids, cancel_index=None, separate_sessions=False):
    async with Fixture().run() as f:
        responses = {}
        done = defaultdict(anyio.Event)
        sid_b = await f.initialize('synthetic-B') if separate_sessions else f.sid

        async def issue(label, rid, sid, owner):
            responses[label] = await f.post(rid, label, True, sid, owner)
            done[label].set()

        async with anyio.create_task_group() as tg:
            tg.start_soon(issue, 'A', ids[0], f.sid, 'synthetic-A')
            await until(lambda: f.started['A'].is_set())
            tg.start_soon(issue, 'B', ids[1], sid_b, 'synthetic-B' if separate_sessions else 'synthetic-A')
            await until(lambda: f.started['B'].is_set())
            before = f.transport(sid_b)._request_streams.get(f.route_key(ids[1]))
            if cancel_index is None:
                f.release['A'].set()
                await until(lambda: done['A'].is_set() or done['B'].is_set(), 2)
            else:
                rid = ids[cancel_index]
                await f.cancel(rid, f.sid if cancel_index == 0 else sid_b,
                               'synthetic-A' if cancel_index == 0 or not separate_sessions else 'synthetic-B')
                await until(lambda: f.cancelled['A' if cancel_index == 0 else 'B'].is_set())
                await until(lambda: done['A'].is_set() or done['B'].is_set(), 2)
            unaffected = 'B' if cancel_index != 1 else 'A'
            unaffected_cancelled = f.cancelled[unaffected].is_set()
            remaining_route = f.transport(sid_b)._request_streams.get(f.route_key(ids[1]))
            b_route_owned = remaining_route is before if cancel_index != 1 else True
            f.release['A'].set(); f.release['B'].set()
            await until(lambda: done['A'].is_set() and done['B'].is_set(), 2)
        if cancel_index is None:
            passed = correct(responses['A'], ids[0], 'A') and correct(responses['B'], ids[1], 'B')
        else:
            target = 'A' if cancel_index == 0 else 'B'
            other = 'B' if cancel_index == 0 else 'A'
            body = responses[target].get('body', {})
            passed = (f.cancelled[target].is_set() and not unaffected_cancelled
                      and correct(responses[other], ids[1 - cancel_index], other)
                      and type(body.get('id')) is type(ids[cancel_index])
                      and body.get('id') == ids[cancel_index] and 'error' in body)
        return {'passed': passed and b_route_owned, 'ids': ids, 'responses': responses,
                'cancel_index': cancel_index, 'unaffected_cancelled': unaffected_cancelled,
                'B_response_route_not_replaced_by_A_cleanup': b_route_owned,
                'routes_after': list(f.transport()._request_streams),
                'separate_sessions': separate_sessions}


async def concurrent_duplicate():
    async with Fixture().run() as f:
        responses = {}; done = defaultdict(anyio.Event)
        async def issue(label):
            responses[label] = await f.post(42, label, True)
            done[label].set()
        async with anyio.create_task_group() as tg:
            tg.start_soon(issue, 'A'); await until(lambda: f.started['A'].is_set())
            transport = f.transport(); key = f.route_key(42)
            original_route = transport._request_streams[key]
            session = f.sessions['A']; session._in_flight = TrackedDict(session._in_flight)
            original_responder = session._in_flight[42]
            writes_before = len(transport._request_streams.writes)
            tg.start_soon(issue, 'B')
            await until(lambda: f.started['B'].is_set() or done['B'].is_set())
            route_unchanged = transport._request_streams.get(key) is original_route
            responder_unchanged = session._in_flight.get(42) is original_responder
            route_writes = len(transport._request_streams.writes) - writes_before
            registrations = len(session._in_flight.writes)
            f.release['A'].set(); f.release['B'].set()
            await until(lambda: done['A'].is_set() and done['B'].is_set(), 2)
        passed = (responses['B'].get('status') == 409 and correct(responses['A'], 42, 'A')
                  and route_unchanged and responder_unchanged and route_writes == 0
                  and registrations == 0 and f.calls == ['A'])
        return {'passed': passed, 'responses': responses, 'original_route_unchanged': route_unchanged,
                'original_responder_unchanged': responder_unchanged,
                'duplicate_transport_writes': route_writes, 'duplicate_responder_registrations': registrations,
                'calls': f.calls}


async def completed_duplicate():
    async with Fixture().run() as f:
        first = await f.post(43, 'A'); duplicate = await f.post(43, 'B')
        init_reuse = await f.post(1, 'C')
        return {'passed': correct(first, 43, 'A') and duplicate.get('status') == 409
                and init_reuse.get('status') == 409 and f.calls == ['A'],
                'responses': [first, duplicate, init_reuse], 'calls': f.calls}


class LiveGET:
    def __init__(self, f, gate_body=None, fail_after_gate=False):
        self.f = f; self.disconnect = anyio.Event(); self.started = anyio.Event()
        self.done = anyio.Event(); self.parts = []; self.errors = []
        self.gate_body = gate_body; self.fail_after_gate = fail_after_gate
        self.body_gate_entered = anyio.Event(); self.release_body = anyio.Event()
        self.send_failure_raised = False

    async def run(self):
        sent_request = False
        async def receive():
            nonlocal sent_request
            if not sent_request:
                sent_request = True
                return {'type': 'http.request', 'body': b'', 'more_body': False}
            await self.disconnect.wait()
            return {'type': 'http.disconnect'}
        async def send(message):
            if message['type'] == 'http.response.start':
                self.status = message['status']; self.started.set()
            elif message['type'] == 'http.response.body':
                part = message.get('body', b'').decode(errors='replace')
                if self.gate_body and self.gate_body in part:
                    with anyio.CancelScope(shield=True):
                        self.body_gate_entered.set(); await self.release_body.wait()
                        if self.fail_after_gate:
                            self.send_failure_raised = True
                            raise RuntimeError('Synthetic ASGI send failure')
                self.parts.append(part)
        scope = {'type': 'http', 'asgi': {'version': '3.0', 'spec_version': '2.1'},
                 'http_version': '1.1', 'method': 'GET', 'scheme': 'http', 'path': '/mcp',
                 'raw_path': b'/mcp', 'query_string': b'', 'root_path': '',
                 'server': ('127.0.0.1', 9878), 'client': ('127.0.0.1', 10001),
                 'headers': [(b'host', b'127.0.0.1:9878'), (b'accept', b'text/event-stream'),
                             (b'mcp-protocol-version', b'2025-11-25'),
                             (b'mcp-session-id', self.f.sid.encode()),
                             (b'authorization', b'Bearer synthetic-A')]}
        try:
            with anyio.move_on_after(4) as self.scope:
                await self.f.auth_app(scope, receive, send)
        except Exception as exc:
            self.errors.append(type(exc).__name__)
        finally:
            self.done.set()

    async def stop(self):
        self.release_body.set()
        self.disconnect.set()
        if hasattr(self, 'scope'):
            self.scope.cancel()
        await until(lambda: self.done.is_set())


async def get_coexists():
    async with Fixture().run() as f:
        get = LiveGET(f)
        async with anyio.create_task_group() as tg:
            tg.start_soon(get.run)
            await until(lambda: '_GET_stream' in f.transport()._request_streams)
            original = f.transport()._request_streams['_GET_stream']
            response = await f.post('_GET_stream', 'GET_POST')
            after_post = f.transport()._request_streams.get('_GET_stream') is original
            # Public request-ID close must not close the unrelated GET route.
            f.transport().close_sse_stream('_GET_stream')
            after_close = f.transport()._request_streams.get('_GET_stream') is original
            await f.sessions['GET_POST'].send_log_message('info', {'probe': 'GET_STILL_OWNED'})
            with anyio.move_on_after(0.2):
                await until(lambda: 'GET_STILL_OWNED' in ''.join(get.parts))
            notification = 'GET_STILL_OWNED' in ''.join(get.parts)
            await get.stop()
        return {'passed': correct(response, '_GET_stream', 'GET_POST') and after_post and after_close and notification,
                'post_response': response, 'GET_owner_after_POST': after_post,
                'GET_owner_after_public_request_close': after_close,
                'server_notification_reached_GET': notification, 'GET_errors': get.errors}


async def get_cleanup_owner():
    async with Fixture().run() as f:
        first = LiveGET(f); second = LiveGET(f); entered = anyio.Event(); release = anyio.Event()
        old_cleanup_executed = anyio.Event()
        transport = f.transport(); original_cleanup = transport._clean_up_memory_streams
        intercepted = False
        async def gated_cleanup(key, *args):
            nonlocal intercepted
            if key == '_GET_stream' and not intercepted:
                intercepted = True
                # Controlled race: prove actual old cleanup executes even when
                # the old SSE sender's enclosing task group is being cancelled.
                with anyio.CancelScope(shield=True):
                    entered.set(); await release.wait()
                    await original_cleanup(key, *args)
                    old_cleanup_executed.set()
            else:
                await original_cleanup(key, *args)
        transport._clean_up_memory_streams = gated_cleanup
        async with anyio.create_task_group() as tg:
            tg.start_soon(first.run)
            await until(lambda: '_GET_stream' in transport._request_streams)
            transport.close_standalone_sse_stream()
            await until(lambda: entered.is_set())
            tg.start_soon(second.run)
            await until(lambda: '_GET_stream' in transport._request_streams)
            successor = transport._request_streams['_GET_stream']
            release.set()
            await until(lambda: old_cleanup_executed.is_set())
            await until(lambda: first.done.is_set())
            preserved = transport._request_streams.get('_GET_stream') is successor
            response = await f.post(88, 'GET_REOPEN')
            await f.sessions['GET_REOPEN'].send_log_message('info', {'probe': 'SUCCESSOR_GET'})
            with anyio.move_on_after(0.2):
                await until(lambda: 'SUCCESSOR_GET' in ''.join(second.parts))
            notification = 'SUCCESSOR_GET' in ''.join(second.parts)
            await first.stop(); await second.stop()
        return {'passed': preserved and notification and correct(response, 88, 'GET_REOPEN'),
                'successor_GET_preserved_after_old_cleanup': preserved,
                'notification_reached_successor': notification,
                'old_cleanup_actually_executed': old_cleanup_executed.is_set(),
                'instrumentation': 'Shielded barrier forces old real cleanup after real GET reconnect; not a claim about every natural disconnect path'}


async def get_outer_exception_owner():
    async with Fixture().run() as f:
        await f.post(80, 'SESSION')
        first = LiveGET(f, 'FAIL_OLD_ASGI', True); second = LiveGET(f)
        transport = f.transport(); original_cleanup = transport._clean_up_memory_streams
        outer_cleanup_seen = False
        inner_cleanup_done = anyio.Event()
        async def observed_cleanup(key, *args):
            nonlocal outer_cleanup_seen
            caller = inspect.currentframe().f_back.f_code.co_name
            if key == '_GET_stream' and caller == '_handle_get_request':
                outer_cleanup_seen = True
            try:
                await original_cleanup(key, *args)
            finally:
                if key == '_GET_stream' and caller == 'standalone_sse_writer':
                    inner_cleanup_done.set()
        transport._clean_up_memory_streams = observed_cleanup
        async with anyio.create_task_group() as tg:
            tg.start_soon(first.run)
            await until(lambda: '_GET_stream' in transport._request_streams)
            await f.sessions['SESSION'].send_log_message('info', {'probe': 'FAIL_OLD_ASGI'})
            await until(lambda: first.body_gate_entered.is_set())
            transport.close_standalone_sse_stream()
            # Let the old normal sender finish before creating the successor;
            # the old HTTP send remains shielded at its explicit failure barrier.
            await until(lambda: inner_cleanup_done.is_set())
            tg.start_soon(second.run)
            await until(lambda: '_GET_stream' in transport._request_streams)
            successor = transport._request_streams['_GET_stream']
            first.release_body.set()
            await until(lambda: first.done.is_set())
            preserved = transport._request_streams.get('_GET_stream') is successor
            await f.sessions['SESSION'].send_log_message('info', {'probe': 'AFTER_ASGI_ERROR'})
            with anyio.move_on_after(0.2):
                await until(lambda: 'AFTER_ASGI_ERROR' in ''.join(second.parts))
            delivered = 'AFTER_ASGI_ERROR' in ''.join(second.parts)
            await first.stop(); await second.stop()
        return {'passed': preserved and delivered and first.send_failure_raised and outer_cleanup_seen,
                'old_ASGI_send_actually_raised': first.send_failure_raised,
                'outer_GET_exception_cleanup_executed': outer_cleanup_seen,
                'successor_GET_preserved': preserved, 'notification_reached_successor': delivered}


async def router_closed_send_owner():
    from anyio.streams.memory import MemoryObjectSendStream
    async with Fixture().run() as f:
        await f.post(81, 'SESSION')
        first = LiveGET(f, 'BLOCK_WIRE'); second = LiveGET(f)
        transport = f.transport(); send_error_entered = anyio.Event(); release_error = anyio.Event()
        send_error_propagated = anyio.Event(); flood_done = anyio.Event()
        original_send = MemoryObjectSendStream.send
        old_sender = None
        async def delayed_real_send(sender, item):
            try:
                return await original_send(sender, item)
            except (anyio.BrokenResourceError, anyio.ClosedResourceError):
                if sender is old_sender:
                    with anyio.CancelScope(shield=True):
                        send_error_entered.set(); await release_error.wait()
                        send_error_propagated.set()
                raise
        async def flood():
            try:
                for index in range(22):
                    await f.sessions['SESSION'].send_log_message('info', {'probe': 'FILL', 'n': index})
            finally:
                flood_done.set()
        async with anyio.create_task_group() as tg:
            with patch.object(MemoryObjectSendStream, 'send', delayed_real_send):
                tg.start_soon(first.run)
                await until(lambda: '_GET_stream' in transport._request_streams)
                old_sender = transport._request_streams['_GET_stream'][0]
                await f.sessions['SESSION'].send_log_message('info', {'probe': 'BLOCK_WIRE'})
                await until(lambda: first.body_gate_entered.is_set())
                tg.start_soon(flood)
                await until(lambda: old_sender.statistics().tasks_waiting_send > 0)
                transport.close_standalone_sse_stream()
                await until(lambda: send_error_entered.is_set())
                first.release_body.set()
                await until(lambda: first.done.is_set())
                tg.start_soon(second.run)
                await until(lambda: '_GET_stream' in transport._request_streams)
                successor = transport._request_streams['_GET_stream']
                release_error.set()
                await until(lambda: send_error_propagated.is_set() and flood_done.is_set())
                preserved = transport._request_streams.get('_GET_stream') is successor
                await f.sessions['SESSION'].send_log_message('info', {'probe': 'AFTER_ROUTER_ERROR'})
                with anyio.move_on_after(0.2):
                    await until(lambda: 'AFTER_ROUTER_ERROR' in ''.join(second.parts))
                delivered = 'AFTER_ROUTER_ERROR' in ''.join(second.parts)
                await first.stop(); await second.stop()
        return {'passed': preserved and delivered and send_error_propagated.is_set(),
                'actual_closed_memory_stream_send_propagated': send_error_propagated.is_set(),
                'successor_GET_preserved': preserved, 'notification_reached_successor': delivered,
                'instrumentation': 'Real buffered SDK notification send blocks, is closed, then its actual error is delayed until GET reconnect'}


async def capacity_and_retirement():
    async with Fixture().run() as f:
        transport = f.transport()
        if not hasattr(transport, '_probe_seen_ids'):
            return {'not_run': 'Unmodified SDK has no seen-ID policy/cap; candidate-only policy test'}
        transport._probe_max_seen_ids = 3  # initialize already uses one ID.
        a = await f.post(2, 'A'); b = await f.post(3, 'B'); denied = await f.post(4, 'DENIED')
        duplicate = await f.post(2, 'DUPLICATE')
        wrong_owner = await f.post(9, 'WRONG_OWNER', owner='synthetic-B')
        owner_denied = wrong_owner.get('status') == 404 and len(transport._probe_seen_ids) == 3
        old_sid = f.sid
        retired = await f.client.delete('/mcp', headers={'Mcp-Session-Id': old_sid})
        await until(lambda: old_sid not in f.server.session_manager._server_instances)
        old_rejected = await f.post(10, 'OLD', sid=old_sid)
        new_sid = await f.initialize()
        new_request = await f.post(2, 'NEW', sid=new_sid)
        return {'passed': correct(a, 2, 'A') and correct(b, 3, 'B') and denied.get('status') == 429
                and duplicate.get('status') == 409 and owner_denied and retired.status_code == 200
                and old_rejected.get('status') == 404 and correct(new_request, 2, 'NEW')
                and not transport._probe_seen_ids and f.calls == ['A', 'B', 'NEW'],
                'cap_error': denied, 'duplicate_after_cap': duplicate, 'wrong_owner_denied': owner_denied,
                'retired_history_cleared_only_after_invalid': not transport._probe_seen_ids,
                'old_session_rejected': old_rejected.get('status') == 404,
                'new_session_old_ID_legal': correct(new_request, 2, 'NEW'), 'calls': f.calls}


async def stateless_compat():
    async with Fixture(stateless=True).run() as f:
        a = await f.post(71, 'A'); b = await f.post(71, 'B')
        return {'passed': correct(a, 71, 'A') and correct(b, 71, 'B'),
                'no_cross_independent_request_dedup': f.calls == ['A', 'B']}


async def id_domain():
    ids = [0, -1, 2**64, '', 'rpc:i:71', 'rpc:s:"71"', '_GET_stream', '猫', '\\', '"']
    async with Fixture().run() as f:
        outcomes = []
        for index, rid in enumerate(ids):
            response = await f.post(rid, 'ID_' + str(index))
            outcomes.append(correct(response, rid, 'ID_' + str(index)))
        return {'passed': all(outcomes), 'ids': ids, 'individual_roundtrips': outcomes}


async def main():
    mode = sys.argv[1]; output = Path(sys.argv[2])
    expected_sdk = Path(os.environ['PYTHONPATH']) / 'mcp/server/streamable_http.py'
    assert Path(transport_module.__file__).resolve() == expected_sdk.resolve()
    cases = [('integer_positive', lambda: pair([71, 72])),
             ('string_positive', lambda: pair(['71', '72'])),
             ('mixed_ID_response_and_cleanup', lambda: pair([71, '71'])),
             ('mixed_cancel_integer', lambda: pair([71, '71'], 0)),
             ('mixed_cancel_string', lambda: pair([71, '71'], 1)),
             ('concurrent_duplicate_before_any_route_write', concurrent_duplicate),
             ('completed_and_initialize_ID_reuse', completed_duplicate),
             ('cross_session_same_ID_cancel_owned', lambda: pair([71, 71], 0, True)),
             ('GET_and_reserved_spelling_coexist', get_coexists),
             ('late_GET_cleanup_cannot_delete_successor', get_cleanup_owner),
             ('GET_outer_ASGI_send_exception_is_owned', get_outer_exception_owner),
             ('router_old_closed_send_cannot_remove_successor', router_closed_send_owner),
             ('seen_cap_owner_and_session_retirement', capacity_and_retirement),
             ('stateless_independent_same_ID_compat', stateless_compat),
             ('legal_ID_domain_roundtrips', id_domain)]
    rows = []
    with patch.object(subprocess, 'Popen', no_spawn):
        for name, case in cases:
            try:
                with anyio.fail_after(8):
                    result = await case()
            except Exception as exc:
                result = {'passed': False, 'harness_or_mechanism_exception': type(exc).__name__,
                          'detail': str(exc)[:300]}
            rows.append({'case': name, **result})
            print(json.dumps(rows[-1], ensure_ascii=False), flush=True)
    result = {'mode': mode, 'SDK_version': importlib.metadata.version('mcp'),
              'SDK_file': transport_module.__file__, 'SDK_file_sha256': hashlib.sha256(expected_sdk.read_bytes()).hexdigest(),
              'python': sys.version, 'cases': rows, 'Popen_attempts': len(spawn_attempts),
              'listener_started': False, 'Gateway_started': False, 'production_code_or_config_changed': False,
              'scope': 'Real SDK ASGI mechanics only; no Gateway, Service, subprocess worker, or client migration acceptance'}
    with output.open('x') as f:
        json.dump(result, f, ensure_ascii=False, indent=2); f.write('\n')
    assert not spawn_attempts
    if mode == 'candidate':
        assert all(row.get('passed') is True for row in rows), 'Candidate did not pass all mechanism cases'
    else:
        assert rows[0].get('passed') and rows[1].get('passed'), 'Unmodified SDK positive controls failed'
        assert rows[2].get('passed') is False, 'Unmodified SDK mixed-ID counterexample not detected'


if __name__ == '__main__':
    anyio.run(main)
