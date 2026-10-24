"""B1-B1-B/R0 expected-RED bridge contract. NO subprocesses or group signals.

Existing genuine subprocess/REST/MCP/slot/cancel tests are untouched.
The private test-only qualification is not an ordinary network credential.
"""
from __future__ import annotations

import ast
import copy
import functools
import fcntl
import importlib
import importlib.util
import inspect
import json
import os
from pathlib import Path
import pickle
import signal
import subprocess
import threading
from types import FunctionType
import httpx
from types import ModuleType, SimpleNamespace
import urllib.error
import urllib.request

import pytest
from mcp.server.streamable_http_manager import (StreamableHTTPASGIApp,
                                                StreamableHTTPSessionManager)
from mcp.server.transport_security import RequestBodyLimitMiddleware
from mcp.types import CallToolResult, TextContent
from mcp.server.lowlevel.server import Server as LowLevelServer, HandlerEntry
from mcp.server.mcpserver.tools.tool_manager import ToolManager
from mcp.server.mcpserver.tools.base import Tool
from mcp.server.mcpserver.utilities.func_metadata import FuncMetadata
from starlette.testclient import TestClient
from starlette.applications import Starlette
from starlette.exceptions import HTTPException, WebSocketException
from starlette.middleware.errors import ServerErrorMiddleware
from starlette.middleware.exceptions import ExceptionMiddleware
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route, Router, request_response

from gateway.core import GatewayError
from gateway._exec_test_transport import create_private_bound_transport
from gateway._exec_test_grant import _owner_lock_proven
from gateway.http import Boundary
from gateway.http_multi import create_multi_app, _GET_ROUTES, _POST_ROUTES
from gateway.mcp_multi import StrictWorkspaceMCP
from gateway.multi_admission import StrictPostAdmission
from gateway.multi_cli import run_multi
from gateway.workspaces import WorkspaceService

HEADERS = {"Content-Type": "application/json",
           "Accept": "application/json, text/event-stream"}
APPLY = {"workspace": "a", "cwd": "src",
         "argv": ["python", "hello.py"], "dry_run": False}


class _NoHostActions:
    def __init__(self):
        self.calls = []

    def deny(self, action):
        def denied(*args, **kwargs):
            self.calls.append(action)
            raise AssertionError("B1B1B_FORBIDDEN_HOST_ACTION:" + action)
        return denied

    def install(self, patch):
        original_popen = subprocess.Popen
        guard = self

        class _NeverPopen(original_popen):
            def __new__(cls, *args, **kwargs):
                return guard.deny("Popen")(*args, **kwargs)

        patch.setattr(subprocess, "Popen", _NeverPopen)
        for attr in ("kill", "killpg", "fork", "forkpty", "posix_spawn",
                     "posix_spawnp", "system", "execv", "execve",
                     "spawnv", "spawnve"):
            if hasattr(os, attr):
                patch.setattr(os, attr, self.deny("os." + attr))
        for attr in ("pthread_kill", "raise_signal"):
            if hasattr(signal, attr):
                patch.setattr(signal, attr, self.deny("signal." + attr))


@pytest.fixture(autouse=True)
def _no_host_process_or_signal(monkeypatch):
    guard = _NoHostActions()
    guard.install(monkeypatch)
    yield
    assert not guard.calls, guard.calls


def _wire(port, path, payload=None, headers=None):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=None if payload is None else json.dumps(payload).encode("utf-8"),
        headers={**HEADERS, **(headers or {})})
    try:
        with opener.open(request, timeout=4) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        return exc.code, json.loads(raw) if raw else None


def _records(env):
    return tuple(sorted(
        (p.name, p.lstat().st_mode, p.lstat().st_nlink,
         p.read_bytes() if p.is_file() and not p.is_symlink() else None)
        for p in env.fixture.state_path.iterdir()))


def _physical_oracle(env):
    """Reuse exactly the fixed, separately reviewed B1-B1-A physical witness.

    The original source, SHA and 31 GREEN oracle selfchecks are frozen by CI.
    New bridge tests must not fall back to a snapshot-only no-intent claim.
    """
    fixed = (Path(__file__).resolve().parents[1] / "b1b1_contracts"
             / "contract_multi_exec_default_deny_b1b1.py")
    spec = importlib.util.spec_from_file_location(
        "_b1b1a_reviewed_oracle", fixed)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    scene = SimpleNamespace(state=env.fixture.state_path)
    return scene, module._IntentWitness(scene.state), (
        module._records), module._never_started


def _runner_spy(env, monkeypatch):
    calls = []

    def fake(*args, **kwargs):
        calls.append((args, kwargs))
        return {"executed": True, "exit_code": 0, "timed_out": False,
                "stdout": "UNAUTHORIZED", "stderr": "", "dry_run": False}

    monkeypatch.setattr(env.service.get("a").gateway, "run_command", fake)
    return calls


def _require(ok, marker, facts):
    if not ok:
        pytest.fail("B1B1B_RED_" + marker + ": " + repr(facts)[:420],
                    pytrace=False)


_BRIDGE_MODULE = "gateway._exec_test_bridge"
_FACTORY_NAME = "create_private_exec_acceptance_bridge"
_MISSING = object()


def _parameter_free(factory):
    """No caller root/state/grant/listener or **kwargs, even optional ones."""
    try:
        return callable(factory) and not inspect.signature(factory).parameters
    except (TypeError, ValueError):
        return False


def _load_factory(marker):
    try:
        module = importlib.import_module(_BRIDGE_MODULE)
    except ModuleNotFoundError as exc:
        # Never disguise a broken nested dependency as an expected RED.
        if exc.name != _BRIDGE_MODULE:
            raise
        _require(False, marker, {"missing_module": exc.name})
        raise AssertionError("unreachable")
    # vars avoids module.__getattr__ converting an initialization failure
    # to an expected missing attribute. Only an actually ABSENT member is RED.
    factory = vars(module).get(_FACTORY_NAME, _MISSING)
    if factory is _MISSING:
        _require(False, marker, {"missing_factory": _FACTORY_NAME})
        raise AssertionError("unreachable")
    return factory


def _bridge(marker):
    factory = _load_factory(marker)
    _require(_parameter_free(factory), marker,
             {"factory_signature": str(inspect.signature(factory))})
    return factory()


def _public_app_graph_contains(root, target):
    """Detect direct/mounted and common wrapped ASGI routing to trusted app.

    Runtime path canaries and private nonpreview denials are ALSO necessary;
    object inequality alone is never a proof of network isolation.
    """
    queue = [root]
    visited = set()
    while queue:
        current = queue.pop()
        if current is target:
            return True
        if id(current) in visited:
            continue
        visited.add(id(current))
        if isinstance(current, (tuple, list, set)):
            queue.extend(current)
            continue
        for field in ("app", "_app", "application", "router", "routes",
                      "_routes", "endpoint"):
            try:
                next_item = getattr(current, field, None)
            except (AttributeError, RuntimeError):
                continue
            if next_item is not None and next_item is not current:
                queue.append(next_item)
    return False


def _stock_starlette_route_handler(route):
    """The actual executed Route.app must be the stock Starlette endpoint wrapper.

    Starlette Route.handle calls self.app, not self.endpoint. Check code
    identity, defaults, and the bound closure, not merely the endpoint
    name/path/methods (which remain unchanged in malicious proxies).
    """
    if (type(route) is not Route or not inspect.isfunction(route.app)
            or "handle" in vars(route)
            or route.handle.__func__ is not Route.handle):
        return False
    expected = request_response(route.endpoint)
    candidate = route.app
    if (candidate.__code__ is not expected.__code__
            or candidate.__globals__ is not expected.__globals__
            or candidate.__defaults__ != expected.__defaults__
            or candidate.__kwdefaults__ != expected.__kwdefaults__):
        return False
    cells = candidate.__closure__ or ()
    expected_cells = expected.__closure__ or ()
    if len(cells) != len(expected_cells):
        return False
    for actual, canonical in zip(cells, expected_cells):
        try:
            a, b = actual.cell_contents, canonical.cell_contents
        except ValueError:
            return False
        if a is b:
            continue
        if (isinstance(a, functools.partial)
                and isinstance(b, functools.partial)
                and a.func is b.func
                and a.args == b.args and a.keywords == b.keywords):
            continue
        return False
    return True


def _stock_starlette_dispatch(core):
    """Only the stock public middleware/handler/router execution chain.

    An unchanged routes list is NOT proof: Starlette calls middleware_stack
    first, then router.middleware_stack, then Route.app and exception handlers.
    """
    if type(core) is not Starlette or type(core.router) is not Router:
        return False
    if core.debug is not False:
        return False
    if type(core.user_middleware) is not list or core.user_middleware:
        return False
    if type(core.exception_handlers) is not dict or core.exception_handlers:
        return False
    router = core.router
    default = getattr(router, "default", None)
    dispatch = getattr(router, "middleware_stack", None)
    if (not inspect.ismethod(default) or default.__self__ is not router
            or default.__func__ is not Router.not_found
            or not inspect.ismethod(dispatch) or dispatch.__self__ is not router
            or dispatch.__func__ is not Router.app):
        return False
    outer = core.middleware_stack
    if type(outer) is not ServerErrorMiddleware:
        return False
    inner = outer.app
    if (type(inner) is not ExceptionMiddleware or inner.app is not router
            or outer.handler is not None or outer.debug is not False
            or inner.debug is not False or inner._status_handlers != {}
            or set(inner._exception_handlers) != {
                HTTPException, WebSocketException}):
        return False
    for exc, fn in ((HTTPException, ExceptionMiddleware.http_exception),
                    (WebSocketException, ExceptionMiddleware.websocket_exception)):
        h = inner._exception_handlers[exc]
        if not inspect.ismethod(h) or h.__self__ is not inner or h.__func__ is not fn:
            return False
    return True


def _mcp_parameter_defaults_equal(actual, canonical):
    """Compare independently constructed MCP argument defaults without
    confusing distinct but equivalent Pydantic FieldInfo instances.
    """
    if actual is canonical:
        return True
    if type(actual) is not type(canonical):
        return False
    if type(actual) is tuple:
        return (len(actual) == len(canonical)
                and all(_mcp_parameter_defaults_equal(x, y)
                        for x, y in zip(actual, canonical)))
    if type(actual) is dict:
        return (actual.keys() == canonical.keys()
                and all(_mcp_parameter_defaults_equal(actual[k], canonical[k])
                        for k in actual))
    if type(actual) in (str, int, bool, float, type(None)):
        return actual == canonical
    # A Field(default_factory=...) is recreated on each official MCP
    # factory call; identity comparison would reject valid real servers.
    # Pin its exact Pydantic class and full public representation instead.
    return (type(actual).__module__ == "pydantic.fields"
            and type(actual).__name__ == "FieldInfo"
            and repr(actual) == repr(canonical))


def _mcp_tool_captures_service(fn, baseline, service, seen=None):
    """Inspect ALL function closures, including read_file -> invoke -> service.

    Comparing only a direct freevar named service misses an indirect
    callback from a different, validly constructed WorkspaceService.
    An unknown function/delegate or differing non-value closure fails
    closed rather than granting transferable authority.
    """
    if (not inspect.isfunction(fn) or not inspect.isfunction(baseline)
            or fn.__code__ is not baseline.__code__
            or fn.__globals__ is not baseline.__globals__
            or fn.__code__.co_freevars != baseline.__code__.co_freevars
            or not _mcp_parameter_defaults_equal(
                fn.__defaults__, baseline.__defaults__)
            or not _mcp_parameter_defaults_equal(
                fn.__kwdefaults__, baseline.__kwdefaults__)):
        return False
    seen = set() if seen is None else seen
    pair = (id(fn), id(baseline))
    if pair in seen:
        return True
    seen.add(pair)
    keys = fn.__code__.co_freevars
    a = fn.__closure__ or ()
    b = baseline.__closure__ or ()
    if len(keys) != len(a) or len(a) != len(b):
        return False
    for key, actual_cell, reference_cell in zip(keys, a, b):
        try:
            actual, canonical = actual_cell.cell_contents, reference_cell.cell_contents
        except ValueError:
            return False
        if key == "service":
            if actual is not service or canonical is not service:
                return False
        elif inspect.isfunction(actual) or inspect.isfunction(canonical):
            if not _mcp_tool_captures_service(
                    actual, canonical, service, seen):
                return False
        elif actual is not canonical:
            # Two fresh, correct factories may capture equal primitive
            # value settings; never compare service/objects by equality.
            if (type(actual) is not type(canonical)
                    or type(actual) not in (str, int, bool, type(None))
                    or actual != canonical):
                return False
    return True


# SDK v2.3.0 executable-callable identities frozen at contract import time,
# before constructing any public or foreign disposable acceptance instance.
_SDK_LOWLEVEL_REQUEST_HANDLER = LowLevelServer.get_request_handler
_SDK_MANAGER_GET_TOOL = ToolManager.get_tool
_SDK_MANAGER_CALL_TOOL = ToolManager.call_tool
_SDK_TOOL_RUN = Tool.run
_SDK_META_VALIDATE = FuncMetadata.validate_arguments
_SDK_META_PREPARSE = FuncMetadata.pre_parse_json
_SDK_META_CALL = FuncMetadata.call_fn
_SDK_META_CONVERT = FuncMetadata.convert_result


def _stock_sdk_bound(obj, cls, method, original):
    """Exact class + no instance override + original executable function."""
    if type(obj) is not cls or method in vars(obj):
        return False
    actual = getattr(obj, method, None)
    return (inspect.ismethod(actual) and actual.__self__ is obj
            and actual.__func__ is original
            and getattr(cls, method) is original)


def _same_generated_sdk_output_model(actual, baseline):
    """Official factory may mint distinct Pydantic output class identities.

    Never use Python class != as an authorization test for separately built
    SDK tool factories. Their canonical wire schema, parent, name and module
    must match; a different effective output-conversion delegate is still
    rejected by the pinned FuncMetadata.convert_result method check.
    """
    if actual is baseline or actual == baseline:
        return True
    if not inspect.isclass(actual) or not inspect.isclass(baseline):
        return False
    if (actual.__base__ is not baseline.__base__
            or actual.__name__ != baseline.__name__
            or actual.__module__ != baseline.__module__):
        return False
    schema_a = getattr(actual, "model_json_schema", None)
    schema_b = getattr(baseline, "model_json_schema", None)
    return (callable(schema_a) and callable(schema_b)
            and schema_a() == schema_b())


def _tool_dispatch_provenance(manager, stock, service):
    """Follow the actual MCP 2.3.0 ToolManager -> Tool.run -> fn_metadata.

    Correct registration Tool.fn alone cannot prove which function executes:
    get_tool/call_tool, Tool.run, metadata.call_fn and Pydantic argument
    interpretation are all active execution/authorization routing seams.
    """
    if (not _stock_sdk_bound(manager, ToolManager, "get_tool",
                             _SDK_MANAGER_GET_TOOL)
            or not _stock_sdk_bound(manager, ToolManager, "call_tool",
                                    _SDK_MANAGER_CALL_TOOL)
            or type(stock) is not ToolManager
            or "get_tool" in vars(stock) or "call_tool" in vars(stock)):
        return False
    tools = manager._tools
    reference = stock._tools
    if (type(tools) is not dict or type(reference) is not dict
            or tools.keys() != reference.keys()
            or "gateway_info" not in tools or "run_command" not in tools):
        return False
    for name, tool in tools.items():
        expected = reference[name]
        if (not _stock_sdk_bound(tool, Tool, "run", _SDK_TOOL_RUN)
                or type(expected) is not Tool
                or tool.name != name or expected.name != name
                or tool.model_dump(exclude={"fn", "fn_metadata"})
                   != expected.model_dump(exclude={"fn", "fn_metadata"})):
            return False
        meta, canonical = tool.fn_metadata, expected.fn_metadata
        if type(meta) is not FuncMetadata or type(canonical) is not FuncMetadata:
            return False
        for method, original in (
            ("validate_arguments", _SDK_META_VALIDATE),
            ("pre_parse_json", _SDK_META_PREPARSE),
            ("call_fn", _SDK_META_CALL),
            ("convert_result", _SDK_META_CONVERT),
        ):
            if not _stock_sdk_bound(meta, FuncMetadata, method, original):
                return False
        if (meta.output_schema != canonical.output_schema
                or not _same_generated_sdk_output_model(
                    meta.output_model, canonical.output_model)
                or meta.wrap_output != canonical.wrap_output
                or meta.arg_model.__base__ is not canonical.arg_model.__base__
                or meta.arg_model.model_json_schema()
                   != canonical.arg_model.model_json_schema()
                or set(meta.arg_model.model_fields)
                   != set(canonical.arg_model.model_fields)):
            return False
        if not _mcp_tool_captures_service(tool.fn, expected.fn, service):
            return False
    for required in ("gateway_info", "run_command"):
        fn = tools[required].fn
        captures = dict(zip(fn.__code__.co_freevars,
                            (c.cell_contents for c in fn.__closure__ or ())))
        if captures.get("service") is not service:
            return False
    return True


def _mcp_dispatch_chain_unmodified(lowlevel, reference, server):
    """The actual SDK runner executes middleware BEFORE request handlers.

    Also block instance-level shadowing of StrictWorkspaceMCP.call_tool,
    which the genuine MCPServer._handle_call_tool calls dynamically.
    """
    current, stock = lowlevel.middleware, reference.middleware
    if (not _stock_sdk_bound(
            lowlevel, LowLevelServer, "get_request_handler",
            _SDK_LOWLEVEL_REQUEST_HANDLER)
            or type(reference) is not LowLevelServer
            or "get_request_handler" in vars(reference)
            or type(current) is not list or type(stock) is not list
            or len(current) != len(stock) or len(current) != 2
            or type(server) is not StrictWorkspaceMCP
            or "call_tool" in vars(server)
            or "call_tool" in vars(type(server)) and
               type(server).call_tool is not StrictWorkspaceMCP.call_tool):
        return False
    for actual, canonical in zip(current, stock):
        if (type(actual) is not type(canonical)
                or type(actual).__call__ is not type(canonical).__call__
                or "__call__" in getattr(actual, "__dict__", {})):
            return False
    return True


def _mcp_manager_provenance(endpoint, canonical_endpoint, service):
    """Audit the actual wire dispatch behind SDK's official callable object.

    StreamableHTTPASGIApp.__call__ delegates to session_manager.asgi_app.
    A normal SDK class with an arbitrary manager, ASGI proxy, low-level
    Server, or tool callback is NOT a verified public service endpoint.
    """
    if (type(endpoint) is not StreamableHTTPASGIApp
            or type(canonical_endpoint) is not StreamableHTTPASGIApp):
        return False
    manager = endpoint.session_manager
    reference = canonical_endpoint.session_manager
    if (type(manager) is not StreamableHTTPSessionManager
            or type(reference) is not StreamableHTTPSessionManager
            or "_handle_request" in vars(manager)):
        return False
    wire = manager.asgi_app
    ref_wire = reference.asgi_app
    if (type(wire) is not RequestBodyLimitMiddleware
            or type(ref_wire) is not RequestBodyLimitMiddleware
            or wire.max_body_size != ref_wire.max_body_size):
        return False
    callback = wire.app
    if (not inspect.ismethod(callback)
            or callback.__self__ is not manager
            or callback.__func__ is not StreamableHTTPSessionManager._handle_request):
        return False
    for field in ("json_response", "stateless", "max_request_body_size",
                  "max_sessions", "retry_interval", "event_store",
                  "session_idle_timeout"):
        if getattr(manager, field) != getattr(reference, field):
            return False
    security = manager.security_settings
    ref_security = reference.security_settings
    if (security is None or ref_security is None
            or type(security) is not type(ref_security)
            or security.model_dump() != ref_security.model_dump()):
        return False
    lowlevel = manager.app
    ref_lowlevel = reference.app
    if (type(lowlevel) is not type(ref_lowlevel)
            or getattr(lowlevel, "_session_manager", None) is not manager):
        return False
    # The MCP tool execution callback is a bound method on the actual
    # StrictWorkspaceMCP whose low-level Server must be THIS manager.app.
    entry = getattr(lowlevel, "_request_handlers", {}).get("tools/call")
    ref_entry = getattr(ref_lowlevel, "_request_handlers", {}).get("tools/call")
    if entry is None or ref_entry is None:
        return False
    callback = entry.handler
    ref_callback = ref_entry.handler
    if (not inspect.ismethod(callback)
            or not inspect.ismethod(ref_callback)
            or callback.__func__ is not ref_callback.__func__
            or type(callback.__self__) is not StrictWorkspaceMCP
            or callback.__self__._lowlevel_server is not lowlevel
            or type(callback.__self__).call_tool is not StrictWorkspaceMCP.call_tool):
        return False
    server = callback.__self__
    reference_server = ref_callback.__self__
    if (not _mcp_dispatch_chain_unmodified(
            lowlevel, ref_lowlevel, server)
            or "call_tool" in vars(server)
            or "call_tool" in vars(reference_server)):
        return False
    return _tool_dispatch_provenance(
        server._tool_manager, reference_server._tool_manager, service)


def _same_mcp_sdk_handler(actual, canonical, service):
    """SDK route provenance by original executable function/type identity.

    A fake __module__ string beginning with mcp. or starlette. is not
    sufficient; the reference comes from a separately built official SDK app.
    """
    if type(actual) is not type(canonical):
        return False
    if ("handle" in vars(actual)
            or actual.handle.__func__ is not type(actual).handle):
        return False
    if type(actual) is Route:
        a, b = actual.endpoint, canonical.endpoint
        if inspect.ismethod(a):
            if (not inspect.ismethod(b) or a.__func__ is not b.__func__
                    or type(a.__self__) is not type(b.__self__)):
                return False
        elif inspect.isfunction(a):
            if (not inspect.isfunction(b) or a.__code__ is not b.__code__
                    or a.__module__ != b.__module__):
                return False
        elif (type(a) is not StreamableHTTPASGIApp
              or type(a) is not type(b)):
            return False
        if type(a) is StreamableHTTPASGIApp:
            # Official SDK 2.3.0 uses a *callable instance* as the Route
            # endpoint; Starlette binds that exact object as Route.app.
            # Requiring a function closure here would reject valid MCP.
            return (actual.app is a and canonical.app is b
                    and type(a).__call__ is StreamableHTTPASGIApp.__call__
                    and _mcp_manager_provenance(a, b, service))
        return _stock_starlette_route_handler(actual)
    if type(actual) is Mount:
        if actual.app is not actual._base_app:
            return False
        a, b = actual.app, canonical.app
        if type(a) is not type(b) or type(a).__call__ is not type(b).__call__:
            return False
        return True
    return False


def _same_rest_route_endpoint(route, canonical, service):
    """Pin the effective REST function *and* its captured Service identity.

    Same __code__/module/globals with a foreign Service remains unauthorized.
    The canonical route is freshly constructed by the reviewed public
    factory for this exact listener service, and is NOT user-configurable.
    """
    if (type(route) is not Route or type(canonical) is not Route
            or route.path != canonical.path
            or route.methods != canonical.methods):
        return False
    actual, reference = route.endpoint, canonical.endpoint
    if (not inspect.isfunction(actual)
            or not inspect.isfunction(reference)
            or actual.__code__ is not reference.__code__
            or actual.__globals__ is not reference.__globals__
            or actual.__defaults__ != reference.__defaults__
            or actual.__kwdefaults__ != reference.__kwdefaults__
            or actual.__code__.co_freevars != reference.__code__.co_freevars):
        return False
    keys = actual.__code__.co_freevars
    a, b = actual.__closure__ or (), reference.__closure__ or ()
    if len(keys) != len(a) or len(a) != len(b):
        return False
    if "service" not in keys:
        return False
    for key, c1, c2 in zip(keys, a, b):
        try:
            current, expected = c1.cell_contents, c2.cell_contents
        except ValueError:
            return False
        if key == "service":
            if current is not service or expected is not service:
                return False
        elif current is not expected:
            if (type(current) is not type(expected)
                    or type(current) not in (str, int, bool, type(None))
                    or current != expected):
                return False
    return _stock_starlette_route_handler(route)


def _public_network_route_allowlisted(public, trusted, *,
                                      service=None, port=None):
    """Fail closed on unknown HTTP/MCP routing or callable execution chains.

    A trusted in-process app cannot be selected by body/header/Host/path.
    The exact public Starlette shell, Router, real route.app callables,
    middleware_stack, exception handlers and SDK-origin /mcp are audited.
    """
    if type(public) is not Boundary:
        return False
    admission = public.app
    if type(admission) is not StrictPostAdmission:
        return False
    app = admission.app
    if not _stock_starlette_dispatch(app):
        return False
    if _public_app_graph_contains(public, trusted):
        return False
    if not isinstance(service, WorkspaceService) or type(port) is not int:
        return False
    # Independent stock reference: actual SDK source/type code, not
    # a mutable __module__ string or user-provided app/scope parameter.
    canonical = create_multi_app(
        service, enable_mcp=True, port=port).app.app
    canonical_routes = {r.path: r for r in canonical.router.routes}
    sdk_route = canonical_routes.get("/mcp")
    if sdk_route is None:
        return False
    expected_get = {
        "/health", "/info", "/workspaces", *_GET_ROUTES.keys()}
    expected_post = set(_POST_ROUTES)
    expected = expected_get | expected_post | {"/mcp"}
    routes = getattr(app.router, "routes", ())
    if type(routes) is not list:
        return False
    seen = set()
    for route in routes:
        if type(route) not in (Route, Mount):
            return False
        path = route.path
        if type(path) is not str or path not in expected or path in seen:
            return False
        seen.add(path)
        if path == "/mcp":
            if not _same_mcp_sdk_handler(route, sdk_route, service):
                return False
            continue
        if type(route) is not Route:
            return False
        expected_methods = (
            {"GET", "HEAD"} if path in expected_get else {"POST"})
        if route.methods != expected_methods:
            return False
        endpoint = route.endpoint
        code = getattr(endpoint, "__code__", None)
        name = ("read_endpoint" if path in expected_get
                else "write_endpoint")
        if (code is None
                or getattr(endpoint, "__module__", None) != "gateway.http_multi"
                or code.co_filename != create_multi_app.__code__.co_filename
                or code.co_qualname
                != "create_multi_app.<locals>." + name
                or not _same_rest_route_endpoint(
                    route, canonical_routes[path], service)):
            return False
    return seen == expected


def _rest_rejects_client_proof(status, body):
    return (status == 400 and type(body) is dict
            and body.get("error") == "invalid_argument")


def _mcp_rejects_client_proof(status, body):
    if status != 200 or type(body) is not dict:
        return False
    result = body.get("result")
    if type(result) is not dict or result.get("isError") is not True:
        return False
    structured = result.get("structuredContent")
    return (type(structured) is dict
            and structured.get("error") == "invalid_argument"
            and structured.get("executed") is not True
            and result.get("executed") is not True)


def _assert_bridge_resources_pinned(env):
    """Physical FDs AND owner-lock EXCLUSIVE lease must survive failed join.

    A still-open owner.lock FD with flock(LOCK_UN) is NOT ownership.
    Reuse the reviewed B1-A independent second-OFD competition witness.
    """
    service, store = env.service, env.service._exec_state
    assert store is not None
    assert not service._closed
    assert store.durability_state == "healthy"
    os.fstat(store._fd)
    os.fstat(store._lock_fd)
    os.fstat(service.get("a").pinned_root.fd)
    assert _owner_lock_proven(
        store._fd, store._lock_fd, env.grant._lock_stat), (
        "B1B1B_OWNER_LOCK_EXCLUSIVE_LEASE_LOST")


def _held_real_preview(env, monkeypatch):
    """Hold an actual loopback TCP request in the real sync preview Worker."""
    gateway = env.service.get("a").gateway
    real = gateway.run_command
    entered, release = threading.Event(), threading.Event()
    results = []
    def held(cwd, argv, timeout_seconds=60, dry_run=True):
        if not dry_run:
            raise AssertionError("B1B1B_HOLD_PREVIEW_CANNOT_EXECUTE")
        entered.set()
        if not release.wait(7):
            raise AssertionError("B1B1B_HELD_HTTP_NOT_RELEASED")
        return real(cwd, argv, timeout_seconds, dry_run)
    monkeypatch.setattr(gateway, "run_command", held)
    def caller():
        try:
            results.append(_wire(env.port, "/run", {
                **APPLY, "dry_run": True}))
        except BaseException as exc:
            results.append(exc)
    thread = threading.Thread(target=caller, daemon=True)
    thread.start()
    if not entered.wait(3):
        release.set()
        thread.join(timeout=5)
        raise AssertionError("B1B1B_REAL_HTTP_PREVIEW_NOT_ENTERED")
    assert env.listener._thread.is_alive()
    return release, thread, results


def test_b1b1b_private_direct_untrusted_apply_denied_before_runner(monkeypatch):
    with create_private_bound_transport() as env:
        calls = _runner_spy(env, monkeypatch)
        scene, witness, snapshot, no_intent = _physical_oracle(env)
        with monkeypatch.context() as patch:
            witness.install(patch)
            before = snapshot(scene)
            try:
                env.service.invoke_exec(
                    "a", "src", ["python", "hello.py"], dry_run=False)
                code = "returned"
            except GatewayError as exc:
                code = exc.code
            clean = no_intent(scene, witness, before, calls)
        _require(code == "exec_cleanup_proof_required" and clean,
                 "PRIVATE_DIRECT_DENY",
                 {"code": code, "runner_calls": len(calls),
                  "physical_events": witness.events})


@pytest.mark.parametrize("metadata", ["plain", "forged"])
def test_b1b1b_private_wire_rest_apply_requires_nonclient_proof(
        monkeypatch, metadata):
    with create_private_bound_transport() as env:
        calls = _runner_spy(env, monkeypatch)
        scene, witness, snapshot, no_intent = _physical_oracle(env)
        headers = ({"x-gateway-test-mode": "true"}
                   if metadata == "forged" else {})
        with monkeypatch.context() as patch:
            witness.install(patch)
            before = snapshot(scene)
            status, data = _wire(env.port, "/run", APPLY, headers)
            clean = no_intent(scene, witness, before, calls)
        _require(status == 503
                 and data == {"error": "exec_cleanup_proof_required"}
                 and clean, "PRIVATE_WIRE_REST_DENY",
                 {"metadata": metadata, "status": status,
                  "response": repr(data)[:130],
                  "calls": len(calls), "events": witness.events})


@pytest.mark.parametrize("metadata", ["plain", "forged"])
def test_b1b1b_private_wire_mcp_apply_requires_nonclient_proof(
        monkeypatch, metadata):
    with create_private_bound_transport() as env:
        calls = _runner_spy(env, monkeypatch)
        scene, witness, snapshot, no_intent = _physical_oracle(env)
        headers = ({"x-internal-group-retirement-grant": "true"}
                   if metadata == "forged" else {})
        with monkeypatch.context() as patch:
            witness.install(patch)
            before = snapshot(scene)
            status, init = _wire(env.port, "/mcp", {
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-11-25",
                           "capabilities": {},
                           "clientInfo": {"name": "b1b1b-red",
                                          "version": "1"}}}, headers)
            assert status == 200 and "result" in init
            _wire(env.port, "/mcp", {
                "jsonrpc": "2.0", "method": "notifications/initialized"},
                headers)
            status, data = _wire(env.port, "/mcp", {
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "run_command", "arguments": APPLY}},
                headers)
            clean = no_intent(scene, witness, before, calls)
        result = data.get("result", {}) if isinstance(data, dict) else {}
        _require(status == 200 and result.get("isError") is True
                 and (result.get("structuredContent") or {}).get("error")
                 == "exec_cleanup_proof_required" and clean,
                 "PRIVATE_WIRE_MCP_DENY",
                 {"metadata": metadata, "status": status,
                  "result": repr(result)[:160], "calls": len(calls),
                  "events": witness.events})


def test_b1b1b_bridge_factory_rejects_caller_selected_scope():
    """Enforce Python zero-argument signature AND actual argument rejection."""
    factory = _load_factory("BRIDGE_FACTORY_NO_ARGS")
    _require(_parameter_free(factory), "BRIDGE_FACTORY_NO_ARGS",
             {"signature": repr(inspect.signature(factory))})
    sentinel = object()  # never a real user root, token, or file path
    unexpected = []
    for args, kwargs in (
            ((sentinel,), {}),
            ((), {"root": sentinel}),
            ((), {"workspace": "foreign"}),
            ((), {"state_root": sentinel}),
            ((), {"grant": sentinel}),
            ((), {"transport": sentinel}),
            ((), {"test_mode": True})):
        try:
            factory(*args, **kwargs)
        except TypeError:
            continue
        unexpected.append((args, kwargs))
    _require(not unexpected, "BRIDGE_FACTORY_NO_ARGS",
             {"accepted_args": repr(unexpected)[:140]})


def test_b1b1b_trusted_bridge_factory_is_live_and_instance_bound():
    with _bridge("TRUSTED_BRIDGE_FACTORY") as env:
        allowed = env.grant.qualifies_transport(
            env.service, "a", transport=env.listener)
        denied = env.grant.qualifies_transport(
            env.service, "b", transport=env.listener)
        _require(allowed and not denied and env.host == "127.0.0.1"
                 and env.listener._proves_live(), "TRUSTED_BRIDGE_FACTORY",
                 {"allowed": allowed, "denied": denied})


def test_b1b1b_bridge_wire_apply_denies_every_untrusted_client(monkeypatch):
    """A new bridge itself must not mount its trusted ASGI on raw TCP."""
    with _bridge("BRIDGE_WIRE_DENY") as env:
        calls = _runner_spy(env, monkeypatch)
        scene, witness, snapshot, no_intent = _physical_oracle(env)
        for headers in ({}, {"x-gateway-test-mode": "true"}):
            with monkeypatch.context() as patch:
                witness.install(patch)
                before = snapshot(scene)
                status, body = _wire(env.port, "/run", APPLY, headers)
                clean = no_intent(scene, witness, before, calls)
            _require(status == 503
                     and body == {"error": "exec_cleanup_proof_required"}
                     and clean, "BRIDGE_WIRE_DENY",
                     {"headers": tuple(headers), "status": status,
                      "calls": len(calls), "events": witness.events})


@pytest.mark.parametrize("metadata", ["plain", "forged"])
def test_b1b1b_bridge_real_wire_mcp_nonpreview_denied(monkeypatch, metadata):
    """New bridge's own REAL SDK MCP listener, never only the B1-B0 one."""
    with _bridge("BRIDGE_WIRE_MCP_DENY") as env:
        calls = _runner_spy(env, monkeypatch)
        scene, witness, snapshot, no_intent = _physical_oracle(env)
        headers = ({"x-internal-group-retirement-grant": "true"}
                   if metadata == "forged" else {})
        with monkeypatch.context() as patch:
            witness.install(patch)
            before = snapshot(scene)
            status, init = _wire(env.port, "/mcp", {
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-11-25",
                           "capabilities": {},
                           "clientInfo": {"name": "bridge-own-wire",
                                          "version": "1"}}}, headers)
            assert status == 200 and "result" in init
            _wire(env.port, "/mcp", {
                "jsonrpc": "2.0",
                "method": "notifications/initialized"}, headers)
            status, result_body = _wire(env.port, "/mcp", {
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "run_command",
                           "arguments": APPLY}}, headers)
            clean = no_intent(scene, witness, before, calls)
        reply = (result_body.get("result", {})
                 if isinstance(result_body, dict) else {})
        _require(status == 200 and reply.get("isError") is True
                 and (reply.get("structuredContent") or {}).get("error")
                 == "exec_cleanup_proof_required" and clean,
                 "BRIDGE_WIRE_MCP_DENY",
                 {"metadata": metadata, "status": status,
                  "reply": repr(reply)[:160],
                  "calls": len(calls), "events": witness.events})


def test_b1b1b_bridge_foreign_instance_never_borrows_grant():
    with _bridge("BRIDGE_FOREIGN_INSTANCE") as owner:
        with _bridge("BRIDGE_FOREIGN_INSTANCE") as other:
            assert owner.grant.qualifies_transport(
                owner.service, "a", transport=owner.listener)
            wrong_service = owner.grant.qualifies_transport(
                other.service, "a", transport=owner.listener)
            wrong_listener = owner.grant.qualifies_transport(
                owner.service, "a", transport=other.listener)
            _require(not wrong_service and not wrong_listener,
                     "BRIDGE_FOREIGN_INSTANCE",
                     {"wrong_service": wrong_service,
                      "wrong_listener": wrong_listener})


def test_b1b1b_trusted_inprocess_asgi_preview_is_not_network_auth():
    with _bridge("TRUSTED_ASGI_PREVIEW") as env:
        trusted = env.trusted_asgi_app
        _require(trusted is not None and
                 _public_network_route_allowlisted(
                     env.listener._server.config.app, trusted,
                     service=env.service, port=env.port),
                 "TRUSTED_ASGI_PREVIEW",
                 {"trusted_present": trusted is not None,
                  "trusted_in_public_routing": (
                      _public_app_graph_contains(
                          env.listener._server.config.app, trusted)
                      if trusted is not None else None)})
        with TestClient(trusted,
                        base_url="http://127.0.0.1:8765") as client:
            response = client.post("/run", json={
                **APPLY, "dry_run": True})
        status, wire = _wire(env.port, "/run", {
            **APPLY, "dry_run": True})
        _require(response.status_code == 200
                 and response.json().get("executed") is False
                 and status == 200 and wire.get("executed") is False,
                 "TRUSTED_ASGI_PREVIEW",
                 {"internal": response.status_code, "wire": status})


def test_b1b1b_trusted_inprocess_route_canary_is_not_network_reachable(
        monkeypatch):
    """Dynamic canary observes mounts/wrappers, not just different app IDs."""
    with _bridge("BRIDGE_TRUSTED_ROUTE_CANARY") as env:
        trusted = env.trusted_asgi_app
        _require(trusted is not None and
                 _public_network_route_allowlisted(
                     env.listener._server.config.app, trusted,
                     service=env.service, port=env.port),
                 "BRIDGE_TRUSTED_ROUTE_CANARY",
                 {"trusted_in_public_routing": True})
        router = getattr(trusted, "router", None)
        _require(router is not None and
                 callable(getattr(router, "add_route", None)),
                 "BRIDGE_TRUSTED_ROUTE_CANARY",
                 {"trusted_router_missing": router is None})
        calls = []
        canary = "/__b1b1b_private_canary_8fc3bd__"
        async def handle(request):
            calls.append("private")
            return JSONResponse({"b1b1b": "TRUSTED_ONLY"})
        router.add_route(canary, handle, methods=["GET"])
        with TestClient(trusted,
                        base_url="http://127.0.0.1:8765") as client:
            local = client.get(canary)
        _require(local.status_code == 200
                 and local.json() == {"b1b1b": "TRUSTED_ONLY"}
                 and calls == ["private"],
                 "BRIDGE_TRUSTED_ROUTE_CANARY",
                 {"local": local.status_code, "calls": calls})
        calls.clear()
        for path in (canary, "/internal" + canary,
                     "/trusted" + canary, "/__test__" + canary):
            status, data = _wire(env.port, path)
            _require(status in (404, 405) and not calls,
                     "BRIDGE_TRUSTED_ROUTE_CANARY",
                     {"network_path": path, "status": status,
                      "canary_calls": calls})
        runner = _runner_spy(env, monkeypatch)
        scene, witness, snapshot, no_intent = _physical_oracle(env)
        for path in ("/internal/run", "/trusted/run",
                     "/__test__/run", "/private/run"):
            with monkeypatch.context() as patch:
                witness.install(patch)
                before = snapshot(scene)
                status, _ = _wire(env.port, path, APPLY,
                                  {"x-gateway-test-mode": "true"})
                clean = no_intent(scene, witness, before, runner)
            _require(status in (404, 405) and clean and not calls,
                     "BRIDGE_TRUSTED_ROUTE_CANARY",
                     {"network_path": path, "status": status,
                      "events": witness.events, "runner": len(runner)})
        _require(_public_network_route_allowlisted(
                     env.listener._server.config.app, trusted,
                     service=env.service, port=env.port),
                 "BRIDGE_TRUSTED_ROUTE_CANARY",
                 {"public_network_topology_unsafe": True})


def test_b1b1b_bridge_close_revokes_one_way():
    env = _bridge("BRIDGE_CLOSE_REVOKE")
    grant, service, listener = env.grant, env.service, env.listener
    try:
        assert grant.qualifies_transport(service, "a", transport=listener)
    finally:
        env.close()
    _require(not grant.qualifies_transport(
                 service, "a", transport=listener)
             and not listener._proves_live(), "BRIDGE_CLOSE_REVOKE",
             {"listener_live": listener._proves_live()})


@pytest.mark.parametrize("fault", ["join_exception", "join_returns_alive"])
def test_b1b1b_bridge_close_preserves_real_inflight_ownership_on_fault(
        monkeypatch, fault):
    """Live HTTP Worker, real Uvicorn thread, injected join ONLY (no fake is_alive)."""
    env = _bridge("BRIDGE_CLOSE_OWNER_RETAIN")
    release = caller = closer = None
    close_done = threading.Event()
    close_errors = []
    try:
        grant = env.grant
        service = env.service
        assert grant.qualifies_transport(service, "a", transport=env.listener)
        release, caller, _ = _held_real_preview(env, monkeypatch)
        assert env.listener._thread.is_alive()

        def join_fault(timeout):
            assert isinstance(timeout, (int, float)) and 0 < timeout <= 7
            assert env.listener._thread.is_alive()
            if fault == "join_exception":
                raise TimeoutError("B1B1B_INJECTED_JOIN_EXCEPTION")
            return None  # no-op join while the REAL listener remains live

        def attempt_close():
            try:
                env.close()
            except BaseException as exc:
                close_errors.append(exc)
            finally:
                close_done.set()

        with monkeypatch.context() as patch:
            patch.setattr(env.listener._thread, "join", join_fault)
            closer = threading.Thread(target=attempt_close, daemon=True)
            closer.start()
            assert close_done.wait(3), (
                "Bridge attempted to close pinned service under an inflight "
                "TCP Listener instead of returning bounded close failure")
            assert len(close_errors) == 1
            if fault == "join_exception":
                assert isinstance(close_errors[0], TimeoutError)
                assert "B1B1B_INJECTED_JOIN_EXCEPTION" in str(close_errors[0])
            else:
                assert isinstance(close_errors[0], RuntimeError)
                assert "did not shut down" in str(close_errors[0])
            assert env.listener._thread.is_alive()
            assert env.listener._socket.fileno() == -1
            assert not grant.qualifies_transport(
                service, "a", transport=env.listener)
            _assert_bridge_resources_pinned(env)
    finally:
        if release is not None:
            release.set()
        if caller is not None:
            caller.join(timeout=5)
        if closer is not None:
            closer.join(timeout=5)
        env.close()  # bounded retry only after real request/drain completed
    assert not env.listener._thread.is_alive()
    assert service._closed


def test_b1b1b_guard_real_listener_loopback_preview_without_execution():
    with create_private_bound_transport() as env:
        before = _records(env)
        assert env.listener._proves_live()
        assert env.listener._socket.getsockname() == ("127.0.0.1", env.port)
        public = env.listener._server.config.app
        core = public.app.app
        reference = create_multi_app(
            env.service, enable_mcp=True, port=env.port).app.app
        real_mcp = next(r for r in core.router.routes if r.path == "/mcp")
        stock_mcp = next(r for r in reference.router.routes
                         if r.path == "/mcp")
        if not _public_network_route_allowlisted(
                public, Starlette(), service=env.service, port=env.port):
            real_low = real_mcp.endpoint.session_manager.app
            stock_low = stock_mcp.endpoint.session_manager.app
            real_server = real_low._request_handlers["tools/call"].handler.__self__
            stock_server = stock_low._request_handlers["tools/call"].handler.__self__
            real_manager, expected_manager = (
                real_server._tool_manager, stock_server._tool_manager)
            facets = []
            for name, tool in real_manager._tools.items():
                other = expected_manager._tools[name]
                meta, baseline = tool.fn_metadata, other.fn_metadata
                facets.append((
                    name,
                    _stock_sdk_bound(tool, Tool, "run", _SDK_TOOL_RUN),
                    tool.model_dump(exclude={"fn", "fn_metadata"})
                      == other.model_dump(exclude={"fn", "fn_metadata"}),
                    meta.output_schema == baseline.output_schema,
                    meta.output_model == baseline.output_model,
                    meta.wrap_output == baseline.wrap_output,
                    meta.arg_model.__base__ is baseline.arg_model.__base__,
                    meta.arg_model.model_json_schema()
                      == baseline.arg_model.model_json_schema(),
                    all(_stock_sdk_bound(meta, FuncMetadata, method, fn)
                        for method, fn in (
                            ("validate_arguments", _SDK_META_VALIDATE),
                            ("pre_parse_json", _SDK_META_PREPARSE),
                            ("call_fn", _SDK_META_CALL),
                            ("convert_result", _SDK_META_CONVERT))),
                    _mcp_tool_captures_service(tool.fn, other.fn,
                                               env.service),
                ))
            print("B1B1B_SDK_STOCK_FACETS",
                  "lowlevel_ok=", _mcp_dispatch_chain_unmodified(
                      real_low, stock_low, real_server),
                  "manager_get=", _stock_sdk_bound(
                      real_manager, ToolManager, "get_tool",
                      _SDK_MANAGER_GET_TOOL),
                  "manager_call=", _stock_sdk_bound(
                      real_manager, ToolManager, "call_tool",
                      _SDK_MANAGER_CALL_TOOL),
                  "mcp_handler=", _same_mcp_sdk_handler(
                      real_mcp, stock_mcp, env.service),
                  "per_tool_fields=", facets, flush=True)
            bad = [(item[0], [i for i, passed in enumerate(item[1:], 1)
                              if not passed]) for item in facets
                   if not all(item[1:])]
            raise AssertionError(
                "B1B1B_STOCK_MCP_DIAGNOSTIC: " + repr({
                    "bad_tools": bad,
                    "lowlevel_ok": _mcp_dispatch_chain_unmodified(
                        real_low, stock_low, real_server),
                    "manager_get": _stock_sdk_bound(
                        real_manager, ToolManager, "get_tool",
                        _SDK_MANAGER_GET_TOOL),
                    "manager_call": _stock_sdk_bound(
                        real_manager, ToolManager, "call_tool",
                        _SDK_MANAGER_CALL_TOOL),
                }))
        assert _public_network_route_allowlisted(
            public, Starlette(), service=env.service, port=env.port), (
            "B1B1B_KNOWN_PUBLIC_ROUTE_SHAPE_REJECTED", {
                "stock_dispatch": _stock_starlette_dispatch(core),
                "user_middleware": repr(core.user_middleware),
                "exception_handlers": repr(core.exception_handlers),
                "stack": repr(type(core.middleware_stack)),
                "middle": repr(type(getattr(
                    core.middleware_stack, "app", None))),
                "inner": repr(type(getattr(getattr(
                    core.middleware_stack, "app", None), "app", None))),
                "routes": [(r.path, type(r).__name__,
                            _stock_starlette_route_handler(r)
                            if type(r) is Route else None)
                           for r in core.router.routes],
                "mcp_origin": repr((
                    type(real_mcp), type(real_mcp.app),
                    getattr(real_mcp.endpoint, "__module__", None),
                    getattr(stock_mcp.endpoint, "__module__", None))),
                "mcp_source": _same_mcp_sdk_handler(
                    real_mcp, stock_mcp, env.service),
            })
        status, data = _wire(env.port, "/run", {
            "workspace": "a", "cwd": "src", "argv": ["python", "hello.py"]})
        assert status == 200 and data["dry_run"] is True
        assert data["executed"] is False and data["workspace"] == "a"
        assert _records(env) == before


def test_b1b1b_guard_foreign_listener_cannot_transfer_qualification():
    with create_private_bound_transport() as left:
        with create_private_bound_transport() as right:
            assert left.grant.qualifies_transport(
                left.service, "a", transport=left.listener)
            assert not left.grant.qualifies_transport(
                left.service, "a", transport=right.listener)
            assert not right.grant.qualifies_transport(
                right.service, "a", transport=left.listener)


@pytest.mark.parametrize("field", ["test_mode", "group_only_test_grant"])
def test_b1b1b_guard_request_fields_cannot_set_internal_proof(
        monkeypatch, field):
    with create_private_bound_transport() as env:
        calls = _runner_spy(env, monkeypatch)
        before = _records(env)
        status, data = _wire(env.port, "/run", {**APPLY, field: True})
        assert status == 400 and data.get("error") == "invalid_argument"
        assert not calls and _records(env) == before


def test_b1b1b_guard_nested_import_or_initialization_error_is_not_expected_red(
        monkeypatch):
    """A missing *dependency* is NEVER legitimate missing-bridge RED."""
    for failure in (
            ModuleNotFoundError(
                "synthetic missing internal dependency",
                name="gateway._missing_internal_dependency"),
            AttributeError("synthetic initializer failure")):
        with monkeypatch.context() as patch:
            def fail_import(name):
                assert name == _BRIDGE_MODULE
                raise failure
            patch.setattr(importlib, "import_module", fail_import)
            with pytest.raises(type(failure)) as info:
                _bridge("TRUSTED_BRIDGE_FACTORY")
            assert str(info.value) == str(failure)
            assert "B1B1B_RED_" not in str(info.value)
    # A present module that simply lacks its factory is different.
    module = ModuleType(_BRIDGE_MODULE)
    with monkeypatch.context() as patch:
        patch.setattr(importlib, "import_module", lambda n: module)
        with pytest.raises(BaseException) as failure:
            _bridge("TRUSTED_BRIDGE_FACTORY")
        assert "B1B1B_RED_TRUSTED_BRIDGE_FACTORY" in str(failure.value)
        assert "missing_factory" in str(failure.value)


def test_b1b1b_guard_factory_signature_rejects_optional_untrusted_scope():
    """Synthetic unsafe callable signatures must never qualify."""
    def safe():
        return None
    def optional(*, root_override=None):
        return None
    def variadic(*args, **kwargs):
        return None
    def positional(root):
        return None
    assert _parameter_free(safe)
    for candidate in (optional, variadic, positional):
        assert not _parameter_free(candidate)


def test_b1b1b_guard_network_mount_or_wrapper_graph_is_detectable():
    """Mutation selfcheck: known Starlette Mount + outer wrapper is detected."""
    trusted = Starlette()
    nested = Starlette(routes=[
        Mount("/private", app=trusted)])
    class Wrapped:
        def __init__(self, app):
            self.app = app
    assert _public_app_graph_contains(trusted, trusted)
    assert _public_app_graph_contains(Wrapped(nested), trusted)
    assert not _public_app_graph_contains(Starlette(), trusted)


@pytest.mark.parametrize("field", [
    "test_mode", "group_only_test_grant", "_trusted_bound_listener",
    "_internal_exec_grant",
])
def test_b1b1b_bridge_rest_body_cannot_mint_private_scope(
        monkeypatch, field):
    """NEW bridge's REAL TCP REST: no client body can select test authority."""
    with _bridge("BRIDGE_BODY_REST_DENY") as env:
        calls = _runner_spy(env, monkeypatch)
        scene, witness, snapshot, no_intent = _physical_oracle(env)
        policy = env.service.info()["exec_policy"]
        with monkeypatch.context() as patch:
            witness.install(patch)
            before = snapshot(scene)
            status, body = _wire(env.port, "/run", {
                **APPLY, field: {"token": "forged"} if field.startswith("_")
                else True})
            clean = no_intent(scene, witness, before, calls)
        _require(_rest_rejects_client_proof(status, body) and clean
                 and env.service.info()["exec_policy"] == policy,
                 "BRIDGE_BODY_REST_DENY",
                 {"field": field, "status": status,
                  "body": repr(body)[:130],
                  "calls": len(calls), "events": witness.events})


@pytest.mark.parametrize("field", [
    "test_mode", "group_only_test_grant", "_trusted_bound_listener",
    "_internal_exec_grant",
])
def test_b1b1b_bridge_mcp_arguments_cannot_mint_private_scope(
        monkeypatch, field):
    """NEW bridge's official MCP SDK wire: private proof in arguments DENY."""
    with _bridge("BRIDGE_BODY_MCP_DENY") as env:
        calls = _runner_spy(env, monkeypatch)
        scene, witness, snapshot, no_intent = _physical_oracle(env)
        policy = env.service.info()["exec_policy"]
        with monkeypatch.context() as patch:
            witness.install(patch)
            before = snapshot(scene)
            status, init = _wire(env.port, "/mcp", {
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-11-25",
                           "capabilities": {},
                           "clientInfo": {"name": "body-spoof",
                                          "version": "1"}}})
            assert status == 200 and "result" in init
            _wire(env.port, "/mcp", {
                "jsonrpc": "2.0",
                "method": "notifications/initialized"})
            status, body = _wire(env.port, "/mcp", {
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "run_command",
                           "arguments": {**APPLY, field: {
                               "token": "forged"} if field.startswith("_")
                               else True}}})
            clean = no_intent(scene, witness, before, calls)
        _require(_mcp_rejects_client_proof(status, body) and clean
                 and env.service.info()["exec_policy"] == policy,
                 "BRIDGE_BODY_MCP_DENY",
                 {"field": field, "status": status,
                  "body": repr(body)[:150],
                  "calls": len(calls), "events": witness.events})


def test_b1b1b_guard_owner_lock_release_with_live_fd_is_detected():
    """Mutation: original FD stays statable after LOCK_UN; second owner wins."""
    with create_private_bound_transport() as env:
        store = env.service._exec_state
        fd = store._lock_fd
        competitor = -1
        _assert_bridge_resources_pinned(env)
        fcntl.flock(fd, fcntl.LOCK_UN)
        try:
            assert os.fstat(fd).st_nlink == 1  # open FD alone is insufficient
            competitor = os.open(
                "owner.lock", os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=store._fd)
            fcntl.flock(competitor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with pytest.raises(AssertionError,
                               match="B1B1B_OWNER_LOCK_EXCLUSIVE_LEASE_LOST"):
                _assert_bridge_resources_pinned(env)
        finally:
            if competitor >= 0:
                fcntl.flock(competitor, fcntl.LOCK_UN)
                os.close(competitor)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _assert_bridge_resources_pinned(env)
        assert env.grant.qualifies_transport(
            env.service, "a", transport=env.listener)


def test_b1b1b_guard_dynamic_dispatcher_and_metadata_route_are_rejected():
    """Mutation: a private target in arbitrary dispatch mapping is not safe."""
    trusted = Starlette()
    class Dispatcher:
        def __init__(self):
            self.dispatch = {"/nonstandard-private/run": trusted}
            self.metadata = {"x-gateway-test-mode": "private"}
        def resolve(self, path, headers):
            return self.dispatch.get(path) if headers.get(
                "x-gateway-test-mode") == "private" else None
    bad = Dispatcher()
    assert not _public_app_graph_contains(bad, trusted)
    assert bad.resolve("/nonstandard-private/run", bad.metadata) is trusted
    assert not _public_network_route_allowlisted(bad, trusted)
    # A valid public shell also must fail if injected with a catch-all route.
    with create_private_bound_transport() as env:
        shell = env.listener._server.config.app
        assert _public_network_route_allowlisted(
            shell, trusted, service=env.service, port=env.port)
        core = shell.app.app
        async def proxy(request):
            return JSONResponse({"leaked": True})
        route = Route("/nonstandard-private/{path:path}", proxy,
                      methods=["POST"])
        core.router.routes.append(route)
        try:
            assert not _public_network_route_allowlisted(
            shell, trusted, service=env.service, port=env.port)
        finally:
            core.router.routes.remove(route)
        assert _public_network_route_allowlisted(
            shell, trusted, service=env.service, port=env.port)


def test_b1b1b_guard_closure_forwarding_private_asgi_is_rejected():
    """Real Starlette/hxx transport: unknown closure path reaches trusted.

    The previous app identity check and four guessed path probes missed it.
    A closed-route structural audit must reject it regardless of canary name.
    """
    trusted = Starlette()
    canary = "/__b1b1b_private_canary_8fc3bd__"
    async def trusted_only(request):
        return JSONResponse({"b1b1b": "TRUSTED_ONLY"})
    trusted.router.add_route(canary, trusted_only, methods=["GET"])
    async def proxy(request):
        target = "/" + request.path_params["path"]
        async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=trusted),
                base_url="http://private.local") as client:
            result = await client.get(target)
        return JSONResponse(result.json(), status_code=result.status_code)
    public = Starlette(routes=[
        Route("/unlisted/{path:path}", proxy, methods=["GET"])])
    assert not _public_app_graph_contains(public, trusted)
    with TestClient(public) as client:
        leaked = client.get("/unlisted" + canary)
    assert leaked.status_code == 200
    assert leaked.json() == {"b1b1b": "TRUSTED_ONLY"}
    assert not _public_network_route_allowlisted(public, trusted)


def test_b1b1b_guard_body_sourced_parser_proxy_bypass_is_not_denial():
    """Synthetic unsafe REST/MCP proxy must fail the shared denial oracles."""
    async def unsafe(request):
        payload = await request.json()
        allowed = bool(payload.get("test_mode"))
        return JSONResponse({
            "executed": allowed, "error": None if allowed else "invalid_argument"
        }, status_code=200 if allowed else 400)
    with TestClient(Starlette(routes=[
            Route("/run", unsafe, methods=["POST"])])) as client:
        leaked = client.post("/run", json={**APPLY, "test_mode": True})
    assert leaked.status_code == 200 and leaked.json()["executed"] is True
    assert not _rest_rejects_client_proof(
        leaked.status_code, leaked.json())
    forged_mcp = {"result": {"isError": False,
                             "structuredContent": {"executed": True}}}
    assert not _mcp_rejects_client_proof(200, forged_mcp)
    assert _rest_rejects_client_proof(
        400, {"error": "invalid_argument"})
    assert _mcp_rejects_client_proof(
        200, {"result": {"isError": True,
                         "structuredContent": {"error": "invalid_argument"},
                         "content": [{"type": "text",
                                      "text": "invalid_argument: forbidden"}]}})


def test_b1b1b_guard_route_app_header_forwarding_is_detected():
    """Real bound loopback: same endpoint/path/methods, altered Route.app."""
    with create_private_bound_transport() as env:
        public = env.listener._server.config.app
        core = public.app.app
        trusted = Starlette()
        async def private(request):
            return JSONResponse({"private": True})
        trusted.router.add_route("/run", private, methods=["POST"])
        route = next(r for r in core.router.routes if r.path == "/run")
        assert _public_network_route_allowlisted(
            public, trusted, service=env.service, port=env.port)
        original, endpoint = route.app, route.endpoint
        async def attacker(scope, receive, send):
            headers = dict(scope["headers"])
            if headers.get(b"x-bridge-route") == b"internal":
                return await trusted(scope, receive, send)
            return await original(scope, receive, send)
        route.app = attacker
        try:
            assert route.endpoint is endpoint
            assert route.path == "/run" and route.methods == {"POST"}
            assert not _public_network_route_allowlisted(
                public, trusted, service=env.service, port=env.port)
            status, data = _wire(
                env.port, "/run", APPLY, {"x-bridge-route": "internal"})
            assert status == 200 and data == {"private": True}
        finally:
            route.app = original
        assert _public_network_route_allowlisted(
            public, trusted, service=env.service, port=env.port)


def test_b1b1b_guard_mutated_middleware_and_exception_handlers_rejected():
    """Unchanged route list never makes a conditional proxy safe."""
    with create_private_bound_transport() as env:
        public = env.listener._server.config.app
        core = public.app.app
        trusted = Starlette()
        assert _public_network_route_allowlisted(
            public, trusted, service=env.service, port=env.port)
        stack = core.middleware_stack
        async def injected(scope, receive, send):
            if (scope["type"] == "http"
                    and dict(scope["headers"]).get(b"x-bridge-route")
                    == b"internal"):
                return await JSONResponse({"private": True})(
                    scope, receive, send)
            return await stack(scope, receive, send)
        core.middleware_stack = injected
        try:
            assert not _public_network_route_allowlisted(
                public, trusted, service=env.service, port=env.port)
            status, data = _wire(
                env.port, "/health", headers={"x-bridge-route": "internal"})
            assert status == 200 and data == {"private": True}
        finally:
            core.middleware_stack = stack
        assert _public_network_route_allowlisted(
            public, trusted, service=env.service, port=env.port)
        async def handler(request, exc):
            return JSONResponse({"private": True})
        core.exception_handlers[404] = handler
        try:
            assert not _public_network_route_allowlisted(
                public, trusted, service=env.service, port=env.port)
        finally:
            del core.exception_handlers[404]
        assert _public_network_route_allowlisted(
            public, trusted, service=env.service, port=env.port)
        # User-middleware definitions also redirect before routes are tried.
        class Forward:
            def __init__(self, app):
                self.app = app
            async def __call__(self, scope, receive, send):
                await self.app(scope, receive, send)
        from starlette.middleware import Middleware
        core.user_middleware.append(Middleware(Forward))
        try:
            assert not _public_network_route_allowlisted(
                public, trusted, service=env.service, port=env.port)
        finally:
            core.user_middleware.clear()
        assert _public_network_route_allowlisted(
            public, trusted, service=env.service, port=env.port)
    # A real Starlette 404 exception handler can turn an unlisted private
    # path into an HTTP 200 despite an unmodified standard router.
    with TestClient(Starlette(exception_handlers={404: handler})) as client:
        response = client.get("/unlisted-private")
        assert response.status_code == 200
        assert response.json() == {"private": True}


def test_b1b1b_guard_mcp_structured_error_precedence_selfcheck():
    """Free-text invalid_argument never substitutes for structured error."""
    wrong = {"result": {
        "isError": True,
        "structuredContent": {"error": "exec_cleanup_proof_required"},
        "content": [{"type": "text",
                     "text": "Request contained invalid_argument field"}]}}
    assert not _mcp_rejects_client_proof(200, wrong)
    assert not _mcp_rejects_client_proof(
        200, {"result": {"isError": True, "content": [
            {"type": "text", "text": "invalid_argument"}]}})
    assert not _mcp_rejects_client_proof(
        200, {"result": {"isError": False, "structuredContent": {
            "error": "invalid_argument"}}})
    assert not _mcp_rejects_client_proof(
        200, {"result": {"isError": True, "structuredContent": {
            "error": "invalid_argument", "executed": True}}})
    assert _mcp_rejects_client_proof(
        200, {"result": {"isError": True, "structuredContent": {
            "error": "invalid_argument"}, "content": [
            {"type": "text", "text": "rejected"}]}})


def test_b1b1b_guard_fake_mcp_sdk_handler_origin_rejected():
    """A forged SDK __module__ string is not actual SDK handler provenance."""
    with create_private_bound_transport() as env:
        public = env.listener._server.config.app
        trusted = Starlette()
        assert _public_network_route_allowlisted(
            public, trusted, service=env.service, port=env.port)
        mcp_route = next(r for r in public.app.app.router.routes
                         if r.path == "/mcp")
        if type(mcp_route) is Route:
            original = mcp_route.endpoint
            async def proxy(req):
                return JSONResponse({"private": True})
            proxy.__module__ = "mcp.server.mcpserver"
            mcp_route.endpoint = proxy
            try:
                assert not _public_network_route_allowlisted(
                    public, trusted, service=env.service, port=env.port)
            finally:
                mcp_route.endpoint = original
        else:
            assert type(mcp_route) is Mount
            original = mcp_route.app
            mcp_route.app = trusted
            try:
                assert not _public_network_route_allowlisted(
                    public, trusted, service=env.service, port=env.port)
            finally:
                mcp_route.app = original
        assert _public_network_route_allowlisted(
            public, trusted, service=env.service, port=env.port)


def test_b1b1b_guard_route_handle_instance_override_detected():
    """Same Route.app/endpoint, but Route.__call__ invokes overwritten handle."""
    with create_private_bound_transport() as env:
        public = env.listener._server.config.app
        trusted = Starlette()
        async def private(request):
            return JSONResponse({"private": True})
        trusted.router.add_route("/run", private, methods=["POST"])
        route = next(r for r in public.app.app.router.routes if r.path == "/run")
        assert _public_network_route_allowlisted(
            public, trusted, service=env.service, port=env.port)
        original = route.handle
        async def hijacked(scope, receive, send):
            if dict(scope["headers"]).get(b"x-bridge-route") == b"internal":
                return await trusted(scope, receive, send)
            return await original(scope, receive, send)
        route.handle = hijacked
        try:
            assert "handle" in vars(route)
            assert not _public_network_route_allowlisted(
                public, trusted, service=env.service, port=env.port)
            status, body = _wire(
                env.port, "/run", APPLY, {"x-bridge-route": "internal"})
            assert status == 200 and body == {"private": True}
        finally:
            del route.handle
        assert _public_network_route_allowlisted(
            public, trusted, service=env.service, port=env.port)


def test_b1b1b_guard_cloned_route_app_foreign_globals_detected():
    """Real TCP spoof with identical code/closure, altered execution globals."""
    with create_private_bound_transport() as env:
        public = env.listener._server.config.app
        trusted = Starlette()
        async def private(request):
            return JSONResponse({"private": True})
        trusted.router.add_route("/run", private, methods=["POST"])
        route = next(r for r in public.app.app.router.routes if r.path == "/run")
        assert _public_network_route_allowlisted(
            public, trusted, service=env.service, port=env.port)
        original = route.app
        globals_copy = dict(original.__globals__)
        real_wrap = original.__globals__["wrap_app_handling_exceptions"]
        def forged_wrap(app, conn):
            stock = real_wrap(app, conn)
            async def proxy(scope, receive, send):
                if dict(scope["headers"]).get(b"x-bridge-route") == b"internal":
                    return await trusted(scope, receive, send)
                return await stock(scope, receive, send)
            return proxy
        globals_copy["wrap_app_handling_exceptions"] = forged_wrap
        clone = FunctionType(original.__code__, globals_copy,
                             original.__name__, original.__defaults__,
                             original.__closure__)
        clone.__kwdefaults__ = original.__kwdefaults__
        assert clone.__code__ is original.__code__
        assert clone.__closure__ is original.__closure__
        route.app = clone
        try:
            assert not _public_network_route_allowlisted(
                public, trusted, service=env.service, port=env.port)
            status, body = _wire(
                env.port, "/run", APPLY, {"x-bridge-route": "internal"})
            assert status == 200 and body == {"private": True}
        finally:
            route.app = original
        assert _public_network_route_allowlisted(
            public, trusted, service=env.service, port=env.port)


def test_b1b1b_guard_sdk_manager_proxy_or_foreign_service_rejected():
    """Actual SDK class does not grant a foreign manager or delegated ASGI.

    All mutations are in the disposable real loopback listener and restored
    before teardown. The wire shows that a novel client-controlled header
    could reach an unreviewed MCP callback without this stricter oracle.
    """
    with create_private_bound_transport() as env:
        public = env.listener._server.config.app
        trusted = Starlette()
        async def private(request):
            return JSONResponse({"private": True})
        trusted.router.add_route("/mcp", private, methods=["POST"])
        route = next(r for r in public.app.app.router.routes if r.path == "/mcp")
        assert type(route.endpoint) is StreamableHTTPASGIApp
        assert _public_network_route_allowlisted(
            public, trusted, service=env.service, port=env.port)
        endpoint = route.endpoint
        original_manager = endpoint.session_manager
        class ForgedManager:
            def __init__(self, underlying):
                self.underlying = underlying
            async def asgi_app(self, scope, receive, send):
                if dict(scope["headers"]).get(b"x-bridge-route") == b"internal":
                    return await trusted(scope, receive, send)
                return await self.underlying.asgi_app(scope, receive, send)
        endpoint.session_manager = ForgedManager(original_manager)
        try:
            assert not _public_network_route_allowlisted(
                public, trusted, service=env.service, port=env.port)
            status, body = _wire(env.port, "/mcp", {
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-11-25",
                           "capabilities": {},
                           "clientInfo": {"name": "manager-spoof",
                                          "version": "1"}}},
                {"x-bridge-route": "internal"})
            assert status == 200 and body == {"private": True}
        finally:
            endpoint.session_manager = original_manager
        assert _public_network_route_allowlisted(
            public, trusted, service=env.service, port=env.port)
        # The same nominal manager class is still unsafe when its actual
        # lower-level ASGI delegate or service-bound MCP Server is replaced.
        manager = original_manager
        original_wire = manager.asgi_app
        async def wire_proxy(scope, receive, send):
            return await trusted(scope, receive, send)
        manager.asgi_app = wire_proxy
        try:
            assert not _public_network_route_allowlisted(
                public, trusted, service=env.service, port=env.port)
        finally:
            manager.asgi_app = original_wire
        original_lowlevel = manager.app
        manager.app = object()
        try:
            assert not _public_network_route_allowlisted(
                public, trusted, service=env.service, port=env.port)
        finally:
            manager.app = original_lowlevel
        assert _public_network_route_allowlisted(
            public, trusted, service=env.service, port=env.port)


@pytest.mark.parametrize("path", [
    pytest.param("/info", id="info"),
    pytest.param("/run", id="run"),
])
def test_b1b1b_guard_rest_endpoint_foreign_service_same_code_rejected(
        monkeypatch, path):
    """Two genuine disposable services, same source functions, FOREIGN owner.

    Replacing both endpoint and its standard Route.app wrapper would pass a
    code/qualname/globals-only audit. Real bound TCP then reaches the other
    service, even though no new subprocess or durable intent is possible.
    """
    with create_private_bound_transport() as public:
        with create_private_bound_transport() as foreign:
            app = public.listener._server.config.app
            local = next(r for r in app.app.app.router.routes if r.path == path)
            foreign_route = next(
                r for r in foreign.listener._server.config.app.app.app.router.routes
                if r.path == path)
            baseline = (local.endpoint, local.app)
            trusted = Starlette()
            assert _public_network_route_allowlisted(
                app, trusted, service=public.service, port=public.port)
            assert local.endpoint.__code__ is foreign_route.endpoint.__code__
            assert local.endpoint.__globals__ is foreign_route.endpoint.__globals__
            assert local.endpoint.__code__.co_freevars == foreign_route.endpoint.__code__.co_freevars
            if path == "/info":
                monkeypatch.setattr(foreign.service, "info",
                                    lambda: {"b1b1b_source": "FOREIGN_REST_SERVICE"})
            else:
                def foreign_preview(workspace, cwd, argv, timeout_seconds=60,
                                    dry_run=True):
                    assert dry_run is True
                    return {"b1b1b_source": "FOREIGN_REST_SERVICE",
                            "executed": False, "dry_run": True}
                monkeypatch.setattr(foreign.service, "invoke_exec", foreign_preview)
            public_before, foreign_before = _records(public), _records(foreign)
            local.endpoint = foreign_route.endpoint
            local.app = request_response(local.endpoint)
            try:
                assert _stock_starlette_route_handler(local)
                assert not _public_network_route_allowlisted(
                    app, trusted, service=public.service, port=public.port)
                if path == "/info":
                    status, data = _wire(public.port, path)
                else:
                    status, data = _wire(
                        public.port, path, {**APPLY, "dry_run": True})
                assert status == 200 and data.get("b1b1b_source") == "FOREIGN_REST_SERVICE"
                assert _records(public) == public_before
                assert _records(foreign) == foreign_before
            finally:
                local.endpoint, local.app = baseline
            assert _public_network_route_allowlisted(
                app, trusted, service=public.service, port=public.port)


def _b1b1b_mcp_server(env):
    route = next(r for r in env.listener._server.config.app.app.app.router.routes
                 if r.path == "/mcp")
    lowlevel = route.endpoint.session_manager.app
    server = lowlevel._request_handlers["tools/call"].handler.__self__
    return route, lowlevel, server


def _b1b1b_call_on_wire(env, name, arguments, *, headers=None):
    status, init = _wire(env.port, "/mcp", {
        "jsonrpc": "2.0", "id": 101, "method": "initialize",
        "params": {"protocolVersion": "2025-11-25",
                   "capabilities": {},
                   "clientInfo": {"name": "b1b1b-mcp-owner-test",
                                  "version": "1"}}}, headers)
    assert status == 200 and "result" in init
    _wire(env.port, "/mcp", {
        "jsonrpc": "2.0", "method": "notifications/initialized"}, headers)
    return _wire(env.port, "/mcp", {
        "jsonrpc": "2.0", "id": 102, "method": "tools/call",
        "params": {"name": name, "arguments": arguments}}, headers)


@pytest.mark.parametrize("name,arguments", [
    pytest.param("read_file", {"workspace": "a", "path": "hello.py"},
                 id="read_file"),
    pytest.param("list_files", {"workspace": "a", "path": "."},
                 id="list_files"),
])
def test_b1b1b_guard_mcp_indirect_invoke_foreign_service_rejected(
        monkeypatch, name, arguments):
    """Actual MCP tool.fn -> invoke -> service foreign binding, real SDK wire."""
    with create_private_bound_transport() as public:
        with create_private_bound_transport() as foreign:
            app = public.listener._server.config.app
            _, _, server = _b1b1b_mcp_server(public)
            _, _, outsider = _b1b1b_mcp_server(foreign)
            tools = server._tool_manager._tools
            old = tools[name]
            attack = outsider._tool_manager._tools[name]
            assert old.fn.__code__ is attack.fn.__code__
            assert "invoke" in old.fn.__code__.co_freevars
            trusted = Starlette()
            assert _public_network_route_allowlisted(
                app, trusted, service=public.service, port=public.port)
            def foreign_invoke(ws, operation, *args):
                assert ws == "a" and operation == name
                return {"b1b1b_source": "FOREIGN_MCP_INVOKE",
                        "workspace": ws}
            monkeypatch.setattr(foreign.service, "invoke", foreign_invoke)
            public_before, foreign_before = _records(public), _records(foreign)
            tools[name] = attack
            try:
                assert not _public_network_route_allowlisted(
                    app, trusted, service=public.service, port=public.port)
                status, reply = _b1b1b_call_on_wire(public, name, arguments)
                assert status == 200
                assert "FOREIGN_MCP_INVOKE" in json.dumps(reply)
                assert _records(public) == public_before
                assert _records(foreign) == foreign_before
            finally:
                tools[name] = old
            assert _public_network_route_allowlisted(
                app, trusted, service=public.service, port=public.port)


def test_b1b1b_guard_sdk_middleware_can_short_circuit_wire_and_is_rejected():
    """Actual v2.3.0 runner middleware chain intercepts before tools/call."""
    with create_private_bound_transport() as env:
        app = env.listener._server.config.app
        _, low, _ = _b1b1b_mcp_server(env)
        trusted = Starlette()
        assert _public_network_route_allowlisted(
            app, trusted, service=env.service, port=env.port)
        before = _records(env)
        class UntrustedMiddleware:
            async def __call__(self, ctx, call_next):
                if ctx.method == "tools/call":
                    return {"isError": False, "content": [
                        {"type": "text", "text": "B1B1B_MIDDLEWARE_UNAUTHORIZED"}]}
                return await call_next(ctx)
        extra = UntrustedMiddleware()
        low.middleware.append(extra)
        try:
            assert not _public_network_route_allowlisted(
                app, trusted, service=env.service, port=env.port)
            status, data = _b1b1b_call_on_wire(env, "gateway_info", {})
            assert status == 200 and "B1B1B_MIDDLEWARE_UNAUTHORIZED" in json.dumps(data)
            assert _records(env) == before
        finally:
            low.middleware.remove(extra)
        assert _public_network_route_allowlisted(
            app, trusted, service=env.service, port=env.port)


def test_b1b1b_guard_mcp_instance_call_tool_shadow_rejected():
    """Stock class method still exists while instance call_tool is replaced."""
    with create_private_bound_transport() as env:
        app = env.listener._server.config.app
        _, _, server = _b1b1b_mcp_server(env)
        trusted = Starlette()
        assert _public_network_route_allowlisted(
            app, trusted, service=env.service, port=env.port)
        before = _records(env)
        async def shadow_call(name, arguments, context=None):
            return CallToolResult(content=[
                TextContent(type="text", text="B1B1B_INSTANCE_CALL_TOOL_SHADOW")])
        server.call_tool = shadow_call
        try:
            assert type(server).call_tool is StrictWorkspaceMCP.call_tool
            assert not _public_network_route_allowlisted(
                app, trusted, service=env.service, port=env.port)
            status, data = _b1b1b_call_on_wire(env, "gateway_info", {})
            assert status == 200 and "B1B1B_INSTANCE_CALL_TOOL_SHADOW" in json.dumps(data)
            assert _records(env) == before
        finally:
            del server.call_tool
        assert _public_network_route_allowlisted(
            app, trusted, service=env.service, port=env.port)


def test_b1b1b_guard_mcp_route_handle_override_rejected():
    """Even a genuine SDK endpoint may be bypassed by Route.handle itself."""
    with create_private_bound_transport() as env:
        app = env.listener._server.config.app
        route, _, _ = _b1b1b_mcp_server(env)
        trusted = Starlette()
        assert _public_network_route_allowlisted(
            app, trusted, service=env.service, port=env.port)
        original = route.handle
        before = _records(env)
        async def hijacked(scope, receive, send):
            if dict(scope["headers"]).get(b"x-bridge-route") == b"internal":
                return await JSONResponse({"b1b1b": "MCP_HANDLE_UNAUTHORIZED"})(
                    scope, receive, send)
            return await original(scope, receive, send)
        route.handle = hijacked
        try:
            assert not _public_network_route_allowlisted(
                app, trusted, service=env.service, port=env.port)
            status, data = _wire(env.port, "/mcp", {
                "jsonrpc": "2.0", "id": 201, "method": "initialize",
                "params": {"protocolVersion": "2025-11-25",
                           "capabilities": {},
                           "clientInfo": {"name": "mcp-route-hijack", "version": "1"}}},
                {"x-bridge-route": "internal"})
            assert status == 200 and data == {"b1b1b": "MCP_HANDLE_UNAUTHORIZED"}
            assert _records(env) == before
        finally:
            del route.handle
        assert _public_network_route_allowlisted(
            app, trusted, service=env.service, port=env.port)


@pytest.mark.parametrize("method", ["get_tool", "call_tool"])
def test_b1b1b_guard_sdk_manager_effective_foreign_dispatch_rejected(
        monkeypatch, method):
    """Real MCP TCP: unchanged _tools/Tool.fn but bound manager method foreign.

    A legitimate public tool table is NOT evidence of which tool executes:
    both official ToolManager.call_tool and get_tool resolve dynamically.
    """
    with create_private_bound_transport() as public:
        with create_private_bound_transport() as foreign:
            app = public.listener._server.config.app
            _, _, owner = _b1b1b_mcp_server(public)
            _, _, outsider = _b1b1b_mcp_server(foreign)
            manager, foreign_manager = (
                owner._tool_manager, outsider._tool_manager)
            trusted = Starlette()
            assert _public_network_route_allowlisted(
                app, trusted, service=public.service, port=public.port)
            assert manager._tools["read_file"].fn is not (
                foreign_manager._tools["read_file"].fn)
            assert (manager._tools["read_file"].fn.__code__
                    is foreign_manager._tools["read_file"].fn.__code__)
            def foreign_read(ws, operation, *args):
                assert ws == "a" and operation == "read_file"
                return {"b1b1b_source": "FOREIGN_MANAGER_" + method}
            monkeypatch.setattr(foreign.service, "invoke", foreign_read)
            public_before, foreign_before = _records(public), _records(foreign)
            setattr(manager, method, getattr(foreign_manager, method))
            try:
                assert (manager._tools["read_file"].fn.__code__
                        is foreign_manager._tools["read_file"].fn.__code__)
                assert not _public_network_route_allowlisted(
                    app, trusted, service=public.service, port=public.port)
                status, data = _b1b1b_call_on_wire(public, "read_file", {
                    "workspace": "a", "path": "hello.py"})
                assert status == 200
                assert "FOREIGN_MANAGER_" + method in json.dumps(data)
                assert _records(public) == public_before
                assert _records(foreign) == foreign_before
            finally:
                delattr(manager, method)
            assert _public_network_route_allowlisted(
                app, trusted, service=public.service, port=public.port)
            status, good = _b1b1b_call_on_wire(public, "gateway_info", {})
            assert status == 200 and "result" in good
            assert _records(public) == public_before


def test_b1b1b_guard_sdk_tool_run_instance_shadow_rejected(
        monkeypatch):
    """Actual MCP Tool.run bound to a foreign Tool changes wire execution."""
    with create_private_bound_transport() as public:
        with create_private_bound_transport() as foreign:
            app = public.listener._server.config.app
            _, _, owner = _b1b1b_mcp_server(public)
            _, _, outsider = _b1b1b_mcp_server(foreign)
            public_tool = owner._tool_manager._tools["read_file"]
            foreign_tool = outsider._tool_manager._tools["read_file"]
            trusted = Starlette()
            assert _public_network_route_allowlisted(
                app, trusted, service=public.service, port=public.port)
            assert public_tool.fn is owner._tool_manager._tools["read_file"].fn
            def foreign_read(ws, operation, *args):
                assert ws == "a" and operation == "read_file"
                return {"b1b1b_source": "FOREIGN_TOOL_RUN"}
            monkeypatch.setattr(foreign.service, "invoke", foreign_read)
            a, b = _records(public), _records(foreign)
            object.__setattr__(public_tool, "run", foreign_tool.run)
            try:
                assert not _public_network_route_allowlisted(
                    app, trusted, service=public.service, port=public.port)
                status, result = _b1b1b_call_on_wire(public, "read_file", {
                    "workspace": "a", "path": "hello.py"})
                assert status == 200
                assert "FOREIGN_TOOL_RUN" in json.dumps(result)
                assert _records(public) == a and _records(foreign) == b
            finally:
                object.__delattr__(public_tool, "run")
            assert _public_network_route_allowlisted(
                app, trusted, service=public.service, port=public.port)


def test_b1b1b_guard_sdk_tool_subclass_run_same_fn_rejected():
    """A subclass Tool may override run without changing Tool.fn at all."""
    with create_private_bound_transport() as env:
        app = env.listener._server.config.app
        _, _, owner = _b1b1b_mcp_server(env)
        registry = owner._tool_manager._tools
        original = registry["gateway_info"]
        trusted = Starlette()
        assert _public_network_route_allowlisted(
            app, trusted, service=env.service, port=env.port)
        before = _records(env)
        class WrongTool(Tool):
            async def run(self, arguments, context, convert_result=False):
                return CallToolResult(content=[
                    TextContent(type="text", text="SUBCLASS_RUN_CANARY")])
        malicious = WrongTool.model_construct(**vars(original))
        assert malicious.fn is original.fn
        registry["gateway_info"] = malicious
        try:
            assert not _public_network_route_allowlisted(
                app, trusted, service=env.service, port=env.port)
            status, data = _b1b1b_call_on_wire(env, "gateway_info", {})
            assert status == 200 and "SUBCLASS_RUN_CANARY" in json.dumps(data)
            assert _records(env) == before
        finally:
            registry["gateway_info"] = original
        assert _public_network_route_allowlisted(
            app, trusted, service=env.service, port=env.port)


def test_b1b1b_guard_sdk_fn_metadata_call_fn_shadow_rejected():
    """Tool.fn untouched; actual fn_metadata.call_fn returns synthetic result."""
    with create_private_bound_transport() as env:
        app = env.listener._server.config.app
        _, _, owner = _b1b1b_mcp_server(env)
        tool = owner._tool_manager._tools["gateway_info"]
        meta = tool.fn_metadata
        trusted = Starlette()
        assert _public_network_route_allowlisted(
            app, trusted, service=env.service, port=env.port)
        before = _records(env)
        async def unsafe_metadata(fn, is_async, args, direct=None):
            return {"b1b1b_source": "METADATA_CALL_FN_CANARY"}
        object.__setattr__(meta, "call_fn", unsafe_metadata)
        try:
            assert tool.fn is owner._tool_manager._tools["gateway_info"].fn
            assert not _public_network_route_allowlisted(
                app, trusted, service=env.service, port=env.port)
            status, data = _b1b1b_call_on_wire(env, "gateway_info", {})
            assert status == 200
            assert "METADATA_CALL_FN_CANARY" in json.dumps(data)
            assert _records(env) == before
        finally:
            object.__delattr__(meta, "call_fn")
        assert _public_network_route_allowlisted(
            app, trusted, service=env.service, port=env.port)


def test_b1b1b_guard_sdk_lowlevel_get_request_handler_shadow_rejected():
    """Official ServerRunner calls this method before the registered handler."""
    with create_private_bound_transport() as env:
        app = env.listener._server.config.app
        _, low, _ = _b1b1b_mcp_server(env)
        trusted = Starlette()
        assert _public_network_route_allowlisted(
            app, trusted, service=env.service, port=env.port)
        before = _records(env)
        old_get = low.get_request_handler
        entry = low._request_handlers["tools/call"]
        async def wrong_handler(ctx, params):
            return CallToolResult(content=[
                TextContent(type="text", text="LOWLEVEL_HANDLER_CANARY")])
        def injected(method):
            if method == "tools/call":
                return HandlerEntry(entry.params_type, wrong_handler)
            return old_get(method)
        low.get_request_handler = injected
        try:
            assert low._request_handlers["tools/call"] is entry
            assert not _public_network_route_allowlisted(
                app, trusted, service=env.service, port=env.port)
            status, data = _b1b1b_call_on_wire(env, "gateway_info", {})
            assert status == 200
            assert "LOWLEVEL_HANDLER_CANARY" in json.dumps(data)
            assert _records(env) == before
        finally:
            del low.get_request_handler
        assert _public_network_route_allowlisted(
            app, trusted, service=env.service, port=env.port)


def test_b1b1b_guard_historical_real_subprocess_tests_are_present():
    source = (Path(__file__).resolve().parents[1]
              / "test_multi_exec_product.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    names = {x.name for x in tree.body
             if isinstance(x, (ast.FunctionDef, ast.AsyncFunctionDef))}
    required = {
        "test_exec_preview_and_real_execution_are_workspace_scoped",
        "test_rest_explicit_routing_and_types",
        "test_worker_lease_blocks_same_workspace_and_close_waits",
        "test_mcp_registry_and_grants",
        "test_global_four_slots_reject_fifth_until_one_releases",
        "test_asgi_rest_disconnect_keeps_real_worker_until_exit",
        "test_cancelled_mcp_tool_waiter_does_not_release_sync_worker",
    }
    assert required <= names
    assert source.count("dry_run=False") >= 5
    assert "hold.py" in source
    assert "pytest.mark.skip" not in source


def test_b1b1b_guard_normal_product_has_no_private_bridge_factory_import():
    assert "_exec_test_bridge" not in WorkspaceService.__init__.__code__.co_names
    assert "_exec_test_bridge" not in run_multi.__code__.co_names
    assert "_exec_test_bridge" not in create_multi_app.__code__.co_names


def test_b1b1b_guard_existing_test_grant_not_serializable_or_reusable():
    with create_private_bound_transport() as env:
        grant, service, listener = env.grant, env.service, env.listener
        assert grant.qualifies_transport(service, "a", transport=listener)
        with pytest.raises(TypeError):
            pickle.dumps(grant)
        with pytest.raises(TypeError):
            copy.copy(grant)
        assert "TestOnlyGroupRetirementGrant" not in json.dumps(
            env.service.info())
    assert not grant.qualifies_transport(
        service, "a", transport=listener)
