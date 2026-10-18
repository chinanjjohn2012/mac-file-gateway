"""Real SDK ASGI: raw related ID zero/empty must differ from absent None."""
from pathlib import Path
import anyio
from anyio.streams.memory import MemoryObjectSendStream
import json
import hashlib
import subprocess
import sys
from unittest.mock import patch
import fullchain_probe_v2 as core
from mcp.server.fastmcp import Context
from mcp.server.streamable_http import EventMessage

async def main():
    rows=[]
    with patch.object(subprocess,'Popen',core.no_spawn):
        for rid in [71,0,'',72]:
            f=core.matrix.Fixture(); routes=[]
            @f.server.tool()
            async def synthetic_raw_related(label:str,ctx:Context)->dict[str,str]:
                await ctx.session.send_log_message('info','RAW_RELATED_'+label,
                                                   related_request_id=None if rid==72 else ctx.request_context.request_id)
                return {'served_label':label}
            async with f.run():
                real_send=MemoryObjectSendStream.send
                async def traced_send(sender,item):
                    if isinstance(item,EventMessage) and getattr(item.message.root,'method',None)=='notifications/message':
                        if str(item.message.root.params.get('data','')).startswith('RAW_RELATED_'):
                            routes.append(next((key for key,entry in f.transport()._request_streams.items() if entry[0] is sender),'missing'))
                    return await real_send(sender,item)
                live=core.matrix.LiveGET(f)
                with patch.object(MemoryObjectSendStream,'send',traced_send):
                    async with anyio.create_task_group() as tg:
                        tg.start_soon(live.run)
                        await core.matrix.until(lambda:'_GET_stream' in f.transport()._request_streams)
                        r=await core.post_tool(f,rid,'synthetic_raw_related',{'label':'TEST'})
                        await core.matrix.until(lambda:len(routes)==1)
                        if rid==72:
                            await core.matrix.until(lambda:'RAW_RELATED_TEST' in ''.join(live.parts))
                        related=None if rid==72 else rid
                        expected='_GET_stream' if related is None else f.route_key(rid)
                        rows.append({'raw_related_ID_type':type(related).__name__,'raw_related_ID':related,
                                     'actual_route':routes[0],'expected_route':expected,
                                     'safety_assertion_related_route_preserved':routes[0]==expected,
                                     'log_arrived_on_unsolicited_GET':'RAW_RELATED_TEST' in ''.join(live.parts),
                                     'final_response_correct':core.matrix.correct(r,rid,'TEST')})
                        await live.stop()
    sdk_file=Path(core.transport_module.__file__)
    result={'mode':sys.argv[1],'SDK_file':str(sdk_file),'SDK_file_sha256':hashlib.sha256(sdk_file.read_bytes()).hexdigest(),'Popen_attempts':len(core.spawn),'rows':rows}
    Path(sys.argv[2]).write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(result,ensure_ascii=False,indent=2))
    if sys.argv[1] == 'candidate':
        assert len(rows) == 4
        for row in rows:
            assert row['safety_assertion_related_route_preserved'], 'F1: falsey related ID misrouted'
            assert row['final_response_correct']
            assert row['log_arrived_on_unsolicited_GET'] == (row['raw_related_ID'] is None)

if __name__=='__main__': anyio.run(main)
