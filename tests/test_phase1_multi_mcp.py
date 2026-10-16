"""Real FastMCP transport, strict raw JSON and Workspace args."""
import pytest
pytest.importorskip('mcp', reason='The official MCP SDK is needed')
from starlette.testclient import TestClient
from gateway.workspaces_config import parse_workspace_config
from gateway.workspaces import WorkspaceService, ActiveRuntimeInventory
from gateway.http_multi import create_multi_app

HEADERS={'Accept':'application/json, text/event-stream', 'Content-Type':'application/json'}


def rpc(client, method, params=None):
    result=client.post('/mcp',headers=HEADERS,json={'jsonrpc':'2.0','id':2,'method':method,'params':params or {}})
    assert result.status_code==200, result.text
    return result.json()


def test_real_mcp_registry_and_workspace_isolation(tmp_path):
    a,b=tmp_path/'a',tmp_path/'b'
    a.mkdir();b.mkdir()
    (a/'x.py').write_text('print(1)\n')
    (b/'x.py').write_text('print(2)\n')
    config=tmp_path/'config';config.mkdir(mode=0o700);config.chmod(0o700)
    runtime=tmp_path/'trusted-runtime';runtime.mkdir()
    settings=parse_workspace_config({'schema_version':1,'workspaces':{
        'a':{'root':str(a),'write':{'enabled':True,'paths':['.']}},
        'b':{'root':str(b),'write':{'enabled':False}}
    }})
    service=WorkspaceService(settings,config_dir=config,inventory=ActiveRuntimeInventory(paths=(runtime,)))
    try:
        with TestClient(create_multi_app(service),base_url='http://127.0.0.1:8765') as client:
            assert 'result' in rpc(client,'initialize',{'protocolVersion':'2025-11-25','capabilities':{},'clientInfo':{'name':'multi-tests','version':'1'}})
            client.post('/mcp',headers=HEADERS,json={'jsonrpc':'2.0','method':'notifications/initialized'})
            tools=rpc(client,'tools/list')['result']['tools']
            names={t['name'] for t in tools}
            assert {'gateway_info','list_workspaces','read_file','write_file','create_file'}<=names
            assert 'run_command' not in names and 'run_skill_script' not in names
            wrong=rpc(client,'tools/call',{'name':'read_file','arguments':{'path':'x.py'}})['result']
            assert wrong.get('isError') is True
            wrong=rpc(client,'tools/call',{'name':'read_file','arguments':{'workspace':'a','path':'x.py','destination_workspace':'b'}})['result']
            assert wrong.get('isError') is True
            for workspace,value in [('a','print(1)'),('b','print(2)')]:
                answer=rpc(client,'tools/call',{'name':'read_file','arguments':{'workspace':workspace,'path':'x.py'}})['result']
                assert answer['structuredContent']['content'].endswith(value)
            raw=b'{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"workspace":"a","workspace":"b","path":"x.py"}}}'
            bad=client.post('/mcp',headers=HEADERS,content=raw)
            assert bad.status_code==400

            # Phase-1 MCP writes must pass through the same source-hash and
            # Workspace authorization boundary as REST writes.
            created=rpc(client,'tools/call',{'name':'create_file','arguments':{
                'workspace':'a','path':'mcp-roundtrip.py',
                'content':'state = 1\n','dry_run':False}})['result']
            assert created.get('isError') is not True
            assert created['structuredContent']['applied'] is True
            assert (a/'mcp-roundtrip.py').read_text() == 'state = 1\n'

            read=rpc(client,'tools/call',{'name':'read_file','arguments':{
                'workspace':'a','path':'mcp-roundtrip.py'}})['result']['structuredContent']
            replaced=rpc(client,'tools/call',{'name':'replace_text','arguments':{
                'workspace':'a','path':'mcp-roundtrip.py','old_text':'1',
                'new_text':'2','expected_sha256':read['file_sha256'],
                'dry_run':False}})['result']
            assert replaced['structuredContent']['applied'] is True
            assert (a/'mcp-roundtrip.py').read_text() == 'state = 2\n'

            newest=rpc(client,'tools/call',{'name':'read_file','arguments':{
                'workspace':'a','path':'mcp-roundtrip.py'}})['result']['structuredContent']
            denied=rpc(client,'tools/call',{'name':'delete_file','arguments':{
                'workspace':'b','path':'mcp-roundtrip.py',
                'expected_sha256':newest['file_sha256'],'dry_run':False}})['result']
            assert denied.get('isError') is True
            removed=rpc(client,'tools/call',{'name':'delete_file','arguments':{
                'workspace':'a','path':'mcp-roundtrip.py',
                'expected_sha256':newest['file_sha256'],'dry_run':False}})['result']
            assert removed['structuredContent']['applied'] is True
            assert not (a/'mcp-roundtrip.py').exists()
    finally:
        service.close()
