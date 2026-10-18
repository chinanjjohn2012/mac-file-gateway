"""Real MCP SDK routing primitive, not a Gateway/Phase2 implementation.

Legal distinct IDs are deliberately concurrent. No listener or child process.
All ASGI waiters have a two-second bound; synthetic tools are released at exit.
"""
from pathlib import Path
import json
import importlib.metadata
import subprocess
from unittest.mock import patch

import anyio
import httpx
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

E = Path(__file__).resolve().parent
HEADERS = {'Accept': 'application/json, text/event-stream',
           'Content-Type': 'application/json', 'MCP-Protocol-Version': '2025-11-25'}
spawn_attempts = []


def forbid_spawn(*args, **kwargs):
    spawn_attempts.append(True)
    raise AssertionError('This SDK-only probe forbids subprocesses')


async def run_case(name, ids):
    started = {label: anyio.Event() for label in ('A', 'B')}
    release = {label: anyio.Event() for label in ('A', 'B')}
    done = {label: anyio.Event() for label in ('A', 'B')}
    first_response = anyio.Event()
    calls = []
    responses = {}
    # A strictly type-preserving history regards these as different IDs.
    typed_keys = [(type(value).__name__, value) for value in ids]
    assert len(set(typed_keys)) == len(ids)
    server = FastMCP('synthetic-typed-ids', stateless_http=False, json_response=True,
                    transport_security=TransportSecuritySettings(
                        enable_dns_rebinding_protection=True,
                        allowed_hosts=['127.0.0.1:9877']))

    @server.tool()
    async def synthetic_wait(label: str) -> dict[str, str]:
        calls.append(label)
        started[label].set()
        await release[label].wait()
        return {'served_label': label}

    app = server.streamable_http_app()
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                    base_url='http://127.0.0.1:9877', headers=HEADERS) as client:
            init = await client.post('/mcp', json={
                'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
                'params': {'protocolVersion': '2025-11-25', 'capabilities': {},
                           'clientInfo': {'name': 'synthetic-typed-ids', 'version': '1'}}})
            assert init.status_code == 200
            client.headers['Mcp-Session-Id'] = init.headers['mcp-session-id']
            await client.post('/mcp', json={'jsonrpc': '2.0', 'method': 'notifications/initialized'})

            async def issue(label, request_id):
                try:
                    with anyio.move_on_after(2) as scope:
                        response = await client.post('/mcp', json={
                            'jsonrpc': '2.0', 'id': request_id, 'method': 'tools/call',
                            'params': {'name': 'synthetic_wait', 'arguments': {'label': label}}})
                        responses[label] = {'status': response.status_code, 'body': response.json()}
                        first_response.set()
                    if scope.cancel_called:
                        responses[label] = {'waiter_timed_out': True}
                finally:
                    done[label].set()

            async with anyio.create_task_group() as tg:
                try:
                    tg.start_soon(issue, 'A', ids[0])
                    with anyio.fail_after(1):
                        await started['A'].wait()
                    tg.start_soon(issue, 'B', ids[1])
                    with anyio.fail_after(1):
                        await started['B'].wait()
                    # Response A is routed while B is definitely active.
                    release['A'].set()
                    with anyio.fail_after(1):
                        await first_response.wait()
                    release['B'].set()
                    with anyio.fail_after(3):
                        await done['A'].wait()
                        await done['B'].wait()
                finally:
                    release['A'].set()
                    release['B'].set()

    def correct(label, expected_id):
        result = responses[label]
        if result.get('waiter_timed_out'):
            return False
        body = result['body']
        return (result['status'] == 200 and type(body.get('id')) is type(expected_id)
                and body.get('id') == expected_id
                and body.get('result', {}).get('structuredContent', {}).get('served_label') == label)

    assert calls == ['A', 'B']
    return {'case': name, 'request_ids': ids, 'typed_guard_would_admit_both': True,
            'sdk_stream_keys': [str(value) for value in ids], 'calls': calls,
            'responses': responses,
            'each_request_received_own_typed_id_and_result':
                correct('A', ids[0]) and correct('B', ids[1])}


async def main():
    rows = []
    with patch.object(subprocess, 'Popen', forbid_spawn):
        rows.append(await run_case('integer-positive', [71, 72]))
        rows.append(await run_case('string-positive', ['71', '72']))
        rows.append(await run_case('mixed-type-alias', [71, '71']))
    assert rows[0]['each_request_received_own_typed_id_and_result']
    assert rows[1]['each_request_received_own_typed_id_and_result']
    assert not rows[2]['each_request_received_own_typed_id_and_result']
    assert rows[2]['responses']['B']['body']['id'] == 71
    assert type(rows[2]['responses']['B']['body']['id']) is int
    assert rows[2]['responses']['B']['body']['result']['structuredContent']['served_label'] == 'A'
    assert rows[2]['responses']['A']['waiter_timed_out']
    assert not spawn_attempts
    result = {'mcp': importlib.metadata.version('mcp'), 'cases': rows,
              'all_wire_ids_are_legal_and_nonrepeating_within_each_session': True,
              'Popen_attempts': 0, 'listener_started': False, 'Gateway_started': False,
              'production_guard_or_Phase2_code_tested': False,
              'meaning_of_exit_zero': 'Positive controls and SDK routing counterexample reproduced'}
    with (E / 'sdk-typed-id-routing-result.json').open('x') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
        f.write('\n')
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    anyio.run(main)
