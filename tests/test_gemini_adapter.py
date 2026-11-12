"""Gemini adapter security/compatibility tests independent of cloud credentials."""
from __future__ import annotations

import base64
import hashlib
import json
import re
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from starlette.testclient import TestClient

from gateway.gemini_adapter.app import create_app
from gateway.gemini_adapter.config import Config, initialize_config, load_config
from gateway.gemini_adapter.proxy import MCPRelay
from gateway.gemini_adapter.store import Store, challenge_for


@pytest.fixture
def context(tmp_path):
    home = tmp_path / "private"
    home.mkdir(mode=0o700)
    config = Config(public_url="https://gemini-mcp.example.com",client_id="gemini-test-client-id",
                    client_secret="s"*48,state_file=home/"gemini-state.sqlite3",
                    workspaces=("a",),scopes=("files:read","files:write","files:delete"),
                    redirect_uris=("https://oauth-redirect.googleusercontent.com/r/testclient",
                                   "https://oauth-redirect.googleusercontent.com/r/abc"))
    store=Store(config.state_file)
    calls=[]
    async def fake_upstream(req):
        assert req.url.port == 8765 and req.url.path == "/mcp"
        assert "authorization" not in req.headers and req.headers.get("host") == "127.0.0.1:8765"
        body=json.loads(req.content)
        calls.append(body)
        method=body["method"]
        if method == "notifications/initialized":
            return httpx.Response(202)
        if method == "initialize":
            result={"protocolVersion":body["params"]["protocolVersion"],"capabilities":{},"serverInfo":{"name":"main-gateway","version":"2.5"}}
        elif method == "server/discover":
            result={"supportedVersions":["2026-07-28","2025-11-25"]}
        elif method == "tools/list":
            tools=["gateway_info","list_workspaces","list_files","read_file","search_files",
                   "create_file","write_file","replace_text","create_directory","delete_file",
                   "delete_directory","remove_file","unlink","move","rename","run_git","run_command"]
            result={"tools":[{"name":n,"inputSchema":{"type":"object"},"annotations":{"readOnlyHint":n in {"list_files","read_file"}}} for n in tools]}
        elif method == "tools/call":
            tool=body["params"]["name"]
            if tool == "list_workspaces":
                info={"workspaces":[{"id":"a","read":True,"write":True},
                                    {"id":"b","read":True,"write":True}],"workspace_count":2}
            elif tool == "gateway_info":
                info={"name":"Mac File Gateway","workspaces":[{"id":"a"},{"id":"b"}],"workspace_count":2,
                      "git_policy":{"enabled":True,"allowed_commands":["push"]}}
            else:
                info={"applied":body["params"].get("arguments",{}).get("dry_run") is False,"path":"a.txt"}
            result={"content":[{"type":"text","text":json.dumps(info)}],"structuredContent":info,"isError":False}
        else:
            return httpx.Response(404,json={"error":"unknown_method"})
        return httpx.Response(200,json={"jsonrpc":"2.0","id":body.get("id"),"result":result})
    transport=httpx.MockTransport(fake_upstream)
    upstream=httpx.AsyncClient(transport=transport,follow_redirects=False)
    relay=MCPRelay(config,client=upstream)
    with TestClient(create_app(config,store=store,relay=relay),base_url="https://127.0.0.1:8766") as client:
        yield config,store,client,calls
    store.close()
    import anyio
    anyio.run(upstream.aclose)


def grant(context, scopes=None, workspaces=("a",)):
    config,store,client,_=context
    verifier="V"*64
    args={"client_id":config.client_id,
          "redirect_uri":"https://oauth-redirect.googleusercontent.com/r/testclient",
          "response_type":"code","state":"xyz-123","scope":" ".join(scopes or config.scopes),
          "code_challenge":challenge_for(verifier),"code_challenge_method":"S256"}
    auth=client.get("/oauth/authorize",params=args)
    assert auth.status_code==200,auth.text
    rid=re.search(r"Request ID: <code>([^<]+)</code>",auth.text).group(1)
    store.approve(rid,workspaces=tuple(workspaces))
    continued=client.post("/oauth/continue",data={"request_id":rid},follow_redirects=False)
    assert continued.status_code==303,continued.text
    code=parse_qs(urlparse(continued.headers["location"]).query)["code"][0]
    params={"grant_type":"authorization_code","client_id":config.client_id,
            "client_secret":config.client_secret,"code":code,"code_verifier":verifier,"redirect_uri":args["redirect_uri"]}
    token=client.post("/oauth/token",data=params)
    assert token.status_code==200,token.text
    return token.json(), params


def rpc(client,token,method,params=None,headers=None):
    headers={"Authorization":"Bearer "+token,"Accept":"application/json, text/event-stream","Content-Type":"application/json",**(headers or {})}
    return client.post("/mcp",headers=headers,json={"jsonrpc":"2.0","id":1,"method":method,"params":params or {}})


def test_discovery_and_unprotected_routes(context):
    config,store,client,calls=context
    resource=client.get("/.well-known/oauth-protected-resource")
    assert resource.status_code==200
    assert resource.json()["resource"]=="https://gemini-mcp.example.com/mcp"
    meta=client.get("/.well-known/oauth-authorization-server").json()
    assert meta["code_challenge_methods_supported"]==["S256"]
    assert "registration_endpoint" not in meta
    forbidden=rpc(client,"no-token","tools/list")
    assert forbidden.status_code==401
    assert "resource_metadata=" in forbidden.headers["WWW-Authenticate"]
    assert not calls
    assert client.get("/read").status_code==404
    assert client.get("/git/run").status_code==404
    assert client.get("/mcp").status_code==401


def test_oauth_operator_grants_refresh_and_revoke(context):
    config,store,client,calls=context
    token,params=grant(context)
    assert rpc(client,token["access_token"],"tools/list").status_code==200
    replay=client.post("/oauth/token",data=params)
    assert replay.status_code==400 and replay.json()["error"]=="invalid_grant"
    refresh=client.post("/oauth/token",data={"grant_type":"refresh_token",
                         "client_id":config.client_id,"client_secret":config.client_secret,
                         "refresh_token":token["refresh_token"]})
    assert refresh.status_code==200
    token2=refresh.json()
    assert token2["access_token"]!=token["access_token"]
    client.post("/oauth/revoke",data={"token":token2["refresh_token"],
                                     "client_id":config.client_id,"client_secret":config.client_secret})
    assert rpc(client,token["access_token"],"tools/list").status_code==401
    assert rpc(client,token2["access_token"],"tools/list").status_code==401


def test_permissions_and_workspace_boundary(context):
    _,_,client,calls=context
    token,_=grant(context,scopes=("files:read",))
    key=token["access_token"]
    tools=rpc(client,key,"tools/list").json()["result"]["tools"]
    assert {x["name"] for x in tools}=={"gateway_info","list_workspaces","list_files","read_file","search_files"}
    assert rpc(client,key,"tools/call",{"name":"create_file","arguments":{"path":"demo.py","content":"1"}}).json()["error"]["code"]==-32601
    assert rpc(client,key,"tools/call",{"name":"read_file","arguments":{"workspace":"b","path":"a.py"}}).json()["error"]["code"]==-32602
    assert rpc(client,key,"tools/call",{"name":"run_git","arguments":{}}).json()["error"]["code"]==-32601
    assert not [x for x in calls if x.get("params",{}).get("name") in {"create_file","run_git"}]


def test_file_writes_and_no_retry(context):
    _,_,client,calls=context
    token,_=grant(context)
    key=token["access_token"]
    tools={x["name"]:x for x in rpc(client,key,"tools/list").json()["result"]["tools"]}
    assert "run_command" not in tools and "run_git" not in tools
    assert tools["create_file"]["annotations"]["destructiveHint"] is True
    args={"name":"create_file","arguments":{"path":"new.py","content":"x=1","dry_run":True}}
    assert rpc(client,key,"tools/call",args).json()["result"]["structuredContent"]["applied"] is False
    args["arguments"]["dry_run"]=False
    assert rpc(client,key,"tools/call",args).json()["result"]["structuredContent"]["applied"] is True
    assert len([x for x in calls if x.get("params",{}).get("name")=="create_file"])==2
    names={"create_file","write_file","replace_text","create_directory","delete_file","delete_directory","remove_file","unlink","move","rename"}
    assert names <= set(tools)


def test_duplicate_json_and_bad_headers(context):
    _,_,client,calls=context
    token,_=grant(context)
    key=token["access_token"]
    headers={"Authorization":"Bearer "+key,"Content-Type":"application/json","Accept":"application/json"}
    raw=b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","name":"create_file","arguments":{}}}'
    result=client.post("/mcp",data=raw,headers=headers)
    assert result.status_code==400
    assert result.json()["error"]["code"]==-32700
    assert client.post("/mcp",data=b'{}',headers={**headers,"Host":"public.example.com"}).status_code==421


def test_read_context_does_not_leak_other_workspaces(context):
    _,_,client,calls=context
    token,_=grant(context)
    for name in ("list_workspaces","gateway_info"):
        result=rpc(client,token["access_token"],"tools/call",{"name":name,"arguments":{}})
        assert result.status_code==200,result.text
        assert '"b"' not in result.text


def test_config_private_and_redirect_validation(tmp_path):
    private=tmp_path/"cfg"
    private.mkdir(mode=0o700)
    path=private/"gemini.json"
    config=initialize_config(path,public_url="https://example.com",workspaces=("project",))
    assert path.stat().st_mode & 0o777 == 0o600
    assert load_config(path).workspaces == ("project",)
    assert not config.validate_redirect("https://oauth-redirect.googleusercontent.com/r/abc")
    from dataclasses import replace
    approved=replace(config,redirect_uris=("https://oauth-redirect.googleusercontent.com/r/abc",))
    assert approved.validate_redirect("https://oauth-redirect.googleusercontent.com/r/abc")
    for target in ("https://evil.example.com/r/abc",
                   "https://oauth-redirect.googleusercontent.com.evil.com/r/abc",
                   "https://oauth-redirect.googleusercontent.com/r/../evil",
                   "https://oauth-redirect.googleusercontent.com/r/abc?next=evil"):
        assert not config.validate_redirect(target)
    path.chmod(0o644)
    with pytest.raises(ValueError):
        load_config(path)


def test_oauth_unauthenticated_and_invalid_grants(context):
    config,store,client,calls=context
    verifier="z"*64
    args={"client_id":config.client_id,
          "redirect_uri":"https://oauth-redirect.googleusercontent.com/r/abc",
          "response_type":"code","scope":"files:read files:write",
          "code_challenge":challenge_for(verifier),"code_challenge_method":"S256","state":"test-state"}
    for data in ({**args,"redirect_uri":"https://attacker.example/r/abc"},
                 {**args,"code_challenge_method":"plain"},
                 {**args,"resource":"https://other.example/mcp"}):
        assert client.get("/oauth/authorize",params=data).status_code == 400
    response=client.get("/oauth/authorize",params=args)
    assert response.status_code==200
    rid=re.search(r"Request ID: <code>([^<]+)</code>",response.text).group(1)
    # No local approval, no code. Browser CSRF cookie alone is insufficient.
    assert client.post("/oauth/continue",data={"request_id":rid},follow_redirects=False).status_code==409
    store.approve(rid)
    client.cookies.clear()
    assert client.post("/oauth/continue",data={"request_id":rid},follow_redirects=False).status_code==409


def test_scope_pinning_after_config_change(context):
    config,store,client,calls=context
    key,_=grant(context)
    token=key["access_token"]
    # In a real restart, the operator can remove write from the config.
    from dataclasses import replace
    narrower=replace(config,scopes=("files:read",),workspaces=())
    new_client=httpx.AsyncClient(transport=httpx.MockTransport(lambda req:httpx.Response(200,json={"jsonrpc":"2.0","id":1,"result":{"tools":[]}})))
    with TestClient(create_app(narrower,store=store,relay=MCPRelay(narrower,client=new_client)),base_url="https://127.0.0.1:8766") as limited:
        resp=rpc(limited,token,"tools/call",{"name":"create_file","arguments":{}})
        assert resp.json()["error"]["code"]==-32601
        assert rpc(limited,token,"tools/call",{"name":"read_file","arguments":{"workspace":"a","path":"x"}}).json()["error"]["code"]==-32602
    import anyio
    anyio.run(new_client.aclose)


def test_store_operator_pending_limit_and_oauth_replay(tmp_path):
    from gateway.gemini_adapter.store import Store
    private=tmp_path/"private-store"
    private.mkdir(mode=0o700)
    store=Store(private/"auth.db")
    try:
        items=[]
        for _ in range(32):
            rid,sid=store.create_request(client="c",redirect="https://oauth-redirect.googleusercontent.com/r/a",
                                          state="x",challenge=challenge_for("a"*64),scopes=("files:read",),workspaces=())
            items.append((rid,sid))
        with pytest.raises(ValueError):
            store.create_request(client="c",redirect="https://oauth-redirect.googleusercontent.com/r/a",
                                 state="x",challenge=challenge_for("a"*64),scopes=("files:read",),workspaces=())
        rid,sid=items[0]
        store.approve(rid)
        code,_,_=store.issue_code(rid,sid)
        assert store.exchange_code(code=code,client="c",redirect="https://oauth-redirect.googleusercontent.com/r/a",verifier="wrong"*10) is None
        assert store.exchange_code(code=code,client="c",redirect="https://oauth-redirect.googleusercontent.com/r/a",verifier="a"*64)
        assert store.exchange_code(code=code,client="c",redirect="https://oauth-redirect.googleusercontent.com/r/a",verifier="a"*64) is None
    finally:
        store.close()


def test_emergency_revoke_invalidates_unredeemed_authorization(context):
    config,store,client,calls=context
    verifier="A"*64
    params={"client_id":config.client_id,
            "redirect_uri":"https://oauth-redirect.googleusercontent.com/r/abc",
            "response_type":"code","scope":"files:read",
            "code_challenge":challenge_for(verifier),"code_challenge_method":"S256"}
    auth=client.get("/oauth/authorize",params=params)
    rid=re.search(r"Request ID: <code>([^<]+)</code>",auth.text).group(1)
    store.approve(rid)
    code=parse_qs(urlparse(client.post("/oauth/continue",data={"request_id":rid},follow_redirects=False).headers["location"]).query)["code"][0]
    store.revoke_all()
    result=client.post("/oauth/token",data={"grant_type":"authorization_code",
                 "client_id":config.client_id,"client_secret":config.client_secret,
                 "redirect_uri":params["redirect_uri"],"code_verifier":verifier,"code":code})
    assert result.status_code==400
    assert result.json()["error"]=="invalid_grant"


def test_exact_oauth_redirect_allowlist(context):
    config,store,client,calls=context
    payload={"client_id":config.client_id,"response_type":"code","scope":"files:read",
             "code_challenge":challenge_for("A"*64),"code_challenge_method":"S256"}
    assert client.get("/oauth/authorize",params={**payload,"redirect_uri":"https://oauth-redirect.googleusercontent.com/r/unknown"}).status_code==400
    assert client.get("/oauth/authorize",params={**payload,"redirect_uri":"https://oauth-redirect.googleusercontent.com/r/abc"}).status_code==200
