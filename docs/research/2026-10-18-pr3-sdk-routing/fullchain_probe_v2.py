"""Independent synthetic ASGI probes; no Gateway, listeners, exec or SDK edits."""
from pathlib import Path
import anyio
from anyio.streams.memory import MemoryObjectSendStream, MemoryObjectReceiveStream
import importlib.metadata
import json
import os
import subprocess
import sys
from unittest.mock import patch

PUBLIC=Path(__file__).resolve().parent
sys.path.insert(0,str(PUBLIC))
import sdk_asgi_matrix as matrix
from mcp.server.fastmcp import Context
from mcp.server.session import ServerSession
from mcp.server.streamable_http import EventMessage
import mcp.server.streamable_http as transport_module

spawn=[]
def no_spawn(*args,**kwargs):
    spawn.append(True)
    raise AssertionError('No subprocess in real SDK probes')

async def post_tool(f,rid,name,arguments):
    with anyio.move_on_after(4) as scope:
        r=await f.client.post('/mcp',headers={'Mcp-Session-Id':f.sid},json={
            'jsonrpc':'2.0','id':rid,'method':'tools/call','params':{'name':name,'arguments':arguments}})
        return {'status':r.status_code,'body':r.json()}
    assert scope.cancel_called
    return {'waiter_timeout':True}

async def related_context_collision():
    f=matrix.Fixture()
    started={v:anyio.Event() for v in ['A','B']}
    send_logs=anyio.Event(); logs_done={v:anyio.Event() for v in ['A','B']}; release=anyio.Event()
    context_ids={}; delivered=[]; responses={}; entries={}
    @f.server.tool()
    async def synthetic_context_log(label:str,ctx:Context)->dict[str,str]:
        context_ids[label]={'raw_type':type(ctx.request_context.request_id).__name__,
                            'raw_value':ctx.request_context.request_id,
                            'helper_type':type(ctx.request_id).__name__, 'helper_value':ctx.request_id}
        started[label].set(); await send_logs.wait()
        await ctx.info('OWNED_LOG_'+label)
        logs_done[label].set(); await release.wait()
        return {'served_label':label}
    real_receive=MemoryObjectReceiveStream.receive
    async def traced_receive(receiver):
        item=await real_receive(receiver)
        if isinstance(item,EventMessage) and getattr(item.message.root,'method',None)=='notifications/message':
            payload=item.message.root.params.get('data')
            if isinstance(payload,str) and payload.startswith('OWNED_LOG_'):
                owner=next((label for label,entry in entries.items() if entry[1] is receiver),'unowned')
                delivered.append({'source_label':payload.removeprefix('OWNED_LOG_'),'receiver_owner':owner})
        return item
    async with f.run():
        async def issue(label,rid):
            responses[label]=await post_tool(f,rid,'synthetic_context_log',{'label':label})
        with patch.object(MemoryObjectReceiveStream,'receive',traced_receive):
            async with anyio.create_task_group() as tg:
                tg.start_soon(issue,'A',71); await started['A'].wait()
                entries['A']=f.transport()._request_streams[f.route_key(71)]
                tg.start_soon(issue,'B','71'); await started['B'].wait()
                entries['B']=f.transport()._request_streams[f.route_key('71')]
                send_logs.set(); await logs_done['A'].wait(); await logs_done['B'].wait()
                await matrix.until(lambda:len(delivered)==2)
                release.set()
        # HTTP final responses can pass while intermediate related messages misroute.
        final_ids={label:{'type':type(r.get('body',{}).get('id')).__name__,'value':r.get('body',{}).get('id')}
                   for label,r in responses.items()}
    return {'case':'FastMCP_Context_related_ID_type','context_ids':context_ids,
            'actual_related_deliveries':delivered,'final_response_ids':final_ids,
            'final_HTTP_results_correct':{label:matrix.correct(responses[label],rid,label) for label,rid in [('A',71),('B','71')]},
            'safety_assertion_related_owner_preserved':all(r['source_label']==r['receiver_owner'] for r in delivered)}

async def predispatch_cancel():
    f=matrix.Fixture(); server_gate=anyio.Event(); release_reader=anyio.Event()
    done=anyio.Event(); scope_holder={}; responseA={}; server_context={}
    original_received=ServerSession._received_request
    async def gated_received(session,responder):
        # Real SDK receive loop is held after receiving A, before it can receive B.
        if responder.request_id==901:
            server_context['session']=session
            server_gate.set(); await release_reader.wait()
        return await original_received(session,responder)
    async with f.run():
        transport=f.transport()
        async def first(): responseA.update(await f.post(901,'A',False))
        async def blocked():
            try:
                with anyio.CancelScope() as scope:
                    scope_holder['scope']=scope
                    await f.post(902,'CANCELLED_BEFORE_DISPATCH',False)
            finally: done.set()
        with patch.object(ServerSession,'_received_request',gated_received):
            async with anyio.create_task_group() as tg:
                tg.start_soon(first); await server_gate.wait()
                tg.start_soon(blocked)
                await matrix.until(lambda:transport._read_stream_writer.statistics().tasks_waiting_send==1)
                # Awaiting the REAL zero-buffer memory send, not a fake send result.
                blocked_sender_observed=True
                key=f.route_key(902); entry=transport._request_streams[key]
                scope_holder['scope'].cancel(); await done.wait()
                await anyio.sleep(0)
                remained=transport._request_streams.get(key) is entry
                stats=entry[0].statistics()
                record={'case':'cancel_at_real_predispatch_backpressure',
                        'real_zero_buffer_send_blocked':blocked_sender_observed,
                        'cancelled_request_dispatched':'CANCELLED_BEFORE_DISPATCH' in f.calls,
                        'route_entry_retained_after_ASGI_exit':remained,
                        'open_send_streams':stats.open_send_streams,'open_receive_streams':stats.open_receive_streams,
                        'safety_assertion_no_abandoned_predispatch_route':not remained}
                # A cancelled, pre-dispatch request must remain unavailable for
                # reuse until the SESSION retires; its active route is removed.
                seen_before_replay=key in transport._probe_seen_ids
                session=server_context['session']
                session._in_flight=matrix.TrackedDict(session._in_flight)
                route_writes_before=len(transport._request_streams.writes)
                calls_before=len(f.calls)
                try:
                    replay=await f.post(902,'REPLAY_CANCELLED_ID',False)
                finally:
                    release_reader.set()
                record['cancelled_id_seen_before_replay']=seen_before_replay
                record['replay_status']=replay.get('status')
                record['replay_route_writes']=len(transport._request_streams.writes)-route_writes_before
                record['replay_responder_registrations']=len(session._in_flight.writes)
                record['replay_business_dispatch_delta']=len(f.calls)-calls_before
                record['route_absent_after_replay']=key not in transport._request_streams
        positive=await f.post(903,'AFTER_CANCEL',False)
        record['subsequent_positive_succeeded']=matrix.correct(positive,903,'AFTER_CANCEL')
        record['A_positive_succeeded']=matrix.correct(responseA,901,'A')
        # Check the tombstone after the positive request, BEFORE session DELETE.
        record['cancelled_id_seen_before_DELETE']=key in transport._probe_seen_ids
        # Observe replay-labelled work again AFTER A and the new request have
        # both finished. The earlier delta predates reader release and cannot
        # detect delayed dispatch; do not count legitimate A/903 calls here.
        record['replay_business_dispatch_final']=f.calls.count('REPLAY_CANCELLED_ID')
        # Explicitly retire this fixture and prove eventual session cleanup still works.
        retired=await f.client.delete('/mcp',headers={'Mcp-Session-Id':f.sid})
        record['retire_status']=retired.status_code
        record['routes_after_retire']=len(transport._request_streams)
        record['cancelled_request_dispatched']='CANCELLED_BEFORE_DISPATCH' in f.calls
        return record

async def progress_context_collision():
    """Real FastMCP ctx.report_progress retains typed request ownership."""
    f = matrix.Fixture()
    entered = {n: anyio.Event() for n in ('A', 'B')}
    release = anyio.Event()
    done = {n: anyio.Event() for n in ('A', 'B')}
    progress_deliveries = []
    entries = {}
    replies = {}

    @f.server.tool()
    async def synthetic_context_progress(label: str, ctx: Context) -> dict[str, str]:
        entered[label].set()
        await release.wait()
        await ctx.report_progress(1, 2, 'PROGRESS_' + label)
        done[label].set()
        return {'served_label': label}

    real_recv = MemoryObjectReceiveStream.receive
    async def trace_progress(receiver):
        event = await real_recv(receiver)
        if isinstance(event, EventMessage) and getattr(event.message.root, 'method', None) == 'notifications/progress':
            token = event.message.root.params.get('progressToken')
            owner = next((label for label, entry in entries.items() if entry[1] is receiver), 'unowned')
            progress_deliveries.append({'source': token, 'owner': owner})
        return event

    async with f.run():
        async def issue(label, request_id):
            response = await f.client.post('/mcp', headers={'Mcp-Session-Id': f.sid}, json={
                'jsonrpc': '2.0', 'id': request_id, 'method': 'tools/call',
                'params': {'name': 'synthetic_context_progress',
                           'arguments': {'label': label}, '_meta': {'progressToken': 'PROGRESS_' + label}},
            })
            replies[label] = {'status': response.status_code, 'body': response.json()}
        with patch.object(MemoryObjectReceiveStream, 'receive', trace_progress):
            async with anyio.create_task_group() as tg:
                tg.start_soon(issue, 'A', 71)
                await entered['A'].wait()
                entries['A'] = f.transport()._request_streams[f.route_key(71)]
                tg.start_soon(issue, 'B', '71')
                await entered['B'].wait()
                entries['B'] = f.transport()._request_streams[f.route_key('71')]
                release.set()
                await done['A'].wait()
                await done['B'].wait()
                await matrix.until(lambda: len(progress_deliveries) == 2)
    return {'case': 'FastMCP_Context_progress_typed_related_ID',
            'deliveries': progress_deliveries,
            'safety_assertion_progress_owner_preserved': all(
                row['source'] == 'PROGRESS_' + row['owner'] for row in progress_deliveries),
            'final_HTTP_results_correct': {
                label: matrix.correct(replies[label], rid, label) for label, rid in [('A', 71), ('B', '71')]},
            }


async def retained_ID_bytes():
    f=matrix.Fixture()
    async with f.run():
        t=f.transport()
        if not hasattr(t,'_probe_seen_ids'):
            return {'case':'retained_ID_bytes','not_applicable':'original SDK has no persistent seen ledger'}
        t._probe_max_seen_ids=5
        measurements=[]
        for n in range(3):
            rid=str(n)+'x'*(256*1024)
            r=await f.post(rid,'BIG_'+str(n),False)
            assert matrix.correct(r,rid,'BIG_'+str(n))
            measurements.append({'completed_requests':n+1,'live_routes':len(t._request_streams),
                                 'ledger_entries':len(t._probe_seen_ids),
                                 'retained_canonical_ID_utf8_bytes':sum(len(k.encode('utf-8')) for k in t._probe_seen_ids)})
        return {'case':'retained_ID_bytes','input_ID_chars':256*1024+1,'measurements':measurements,
                'mechanism':'full ID keys persist after all request routes complete; only entry count checked'}

async def main():
    rows=[]
    with patch.object(subprocess,'Popen',no_spawn):
        for fn in [related_context_collision,progress_context_collision,predispatch_cancel,retained_ID_bytes]:
            with anyio.fail_after(12): rows.append(await fn())
    data={'mode':sys.argv[1],'sdk_version':importlib.metadata.version('mcp'),
          'SDK_file':transport_module.__file__,'Popen_attempts':len(spawn),
          'Gateway_started':False,'listener_started':False,'results':rows}
    Path(sys.argv[2]).write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(data,ensure_ascii=False,indent=2))
    assert not spawn
    if sys.argv[1] == 'candidate':
        by_case = {row['case']: row for row in rows}
        related = by_case['FastMCP_Context_related_ID_type']
        progress = by_case['FastMCP_Context_progress_typed_related_ID']
        cleanup = by_case['cancel_at_real_predispatch_backpressure']
        assert related['safety_assertion_related_owner_preserved'], 'F1: FastMCP related ID misrouted'
        assert all(related['final_HTTP_results_correct'].values()), 'F1: final HTTP positive control failed'
        assert progress['safety_assertion_progress_owner_preserved'], 'F1: progress misrouted'
        assert all(progress['final_HTTP_results_correct'].values()), 'F1: progress positive control failed'
        assert cleanup['real_zero_buffer_send_blocked'] is True, 'F2: zero-buffer backpressure not observed'
        assert cleanup['safety_assertion_no_abandoned_predispatch_route'], 'F2: route retained after cancelled ASGI request'
        assert cleanup['open_send_streams'] == 0 and cleanup['open_receive_streams'] == 0, 'F2: stream endpoints remain open'
        assert cleanup['cancelled_request_dispatched'] is False, 'F2: cancelled request dispatched'
        assert cleanup['cancelled_id_seen_before_replay'] is True, 'F2: cancelled request ID tombstone missing before replay'
        assert cleanup['cancelled_id_seen_before_DELETE'] is True, 'F2: cancelled request ID tombstone missing before DELETE'
        assert cleanup['replay_status'] == 409, 'F2: same-session replay not rejected'
        assert cleanup['replay_route_writes'] == 0, 'F2: replay changed active request route'
        assert cleanup['replay_responder_registrations'] == 0, 'F2: replay registered a responder'
        assert cleanup['replay_business_dispatch_delta'] == 0, 'F2: replay dispatched business work'
        assert cleanup['replay_business_dispatch_final'] == 0, 'F2: replay business dispatched after reader resumed'
        assert cleanup['route_absent_after_replay'] is True, 'F2: replay created or retained a route'
        assert cleanup['A_positive_succeeded'] and cleanup['subsequent_positive_succeeded'], 'F2: positive controls failed'

if __name__=='__main__': anyio.run(main)
