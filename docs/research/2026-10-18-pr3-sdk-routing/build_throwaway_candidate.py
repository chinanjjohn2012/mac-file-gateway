"""Build an isolated, disposable SDK-routing experiment. NEVER apply to production."""
from pathlib import Path
import difflib
import hashlib
import json

R = Path(__file__).resolve().parent
original = R / 'sdk-original/mcp/server/streamable_http.py'
candidate = R / 'sdk-candidate/mcp/server/streamable_http.py'
text = original.read_text()


def replace(old, new, count=1):
    global text
    assert text.count(old) == count, (old[:100], text.count(old), count)
    text = text.replace(old, new)


replace('GET_STREAM_KEY = "_GET_stream"', '''GET_STREAM_KEY = "_GET_stream"


def _probe_rpc_route_key(request_id: RequestId) -> str:
    """THROWAWAY: injective internal key; never rewrite external JSON-RPC IDs."""
    if type(request_id) is int:
        return "rpc:i:" + str(request_id)
    if type(request_id) is str:
        return "rpc:s:" + json.dumps(request_id, ensure_ascii=True, separators=(",", ":"))
    raise ValueError("Invalid request ID type")
''')
replace('''        self.mcp_session_id = mcp_session_id
''', '''        # Research scope only. Unqualified modes must fail rather than silently work.
        if not is_json_response_enabled or event_store is not None:
            raise ValueError("Throwaway candidate requires JSON response and no EventStore")
        self._probe_seen_ids: set[str] = set()
        self._probe_max_seen_ids = 1024  # Probe parameter, NOT an approved product value.
        self.mcp_session_id = mcp_session_id
''')
replace('''        writer = self._sse_stream_writers.pop(request_id, None)
''', '''        self._probe_close_route(_probe_rpc_route_key(request_id))

    def _probe_close_route(self, request_id: str) -> None:
        """Internal route keys and public wire IDs are separate domains."""
        writer = self._sse_stream_writers.pop(request_id, None)
''')
replace('''        self.close_sse_stream(GET_STREAM_KEY)
''', '''        self._probe_close_route(GET_STREAM_KEY)
''')
start = text.index('    async def _clean_up_memory_streams(')
end = text.index('    async def handle_request(', start)
text = text[:start] + '''    async def _clean_up_memory_streams(self, request_id: RequestId, expected_entry=None) -> None:
        """THROWAWAY: close only the captured owner, compare-remove after awaits."""
        entry = expected_entry if expected_entry is not None else self._request_streams.get(request_id)
        if entry is None:
            return
        # Only in-memory close operations are shielded; this says nothing about
        # Gateway sync workers or OS-process cancellation qualification.
        with anyio.CancelScope(shield=True):
            try:
                await entry[0].aclose()
                await entry[1].aclose()
            finally:
                if self._request_streams.get(request_id) is entry:
                    self._request_streams.pop(request_id, None)

''' + text[end:]
replace('''            try:  # pragma: no cover
                message = JSONRPCMessage.model_validate(raw_message)
''', '''            # Preserve the wire type before Pydantic can coerce bool/float IDs.
            if (isinstance(raw_message, dict) and "method" in raw_message and "id" in raw_message
                    and type(raw_message["id"]) not in (str, int)):
                response = Response('{"error":"invalid_request_id_type"}', status_code=400,
                                    media_type="application/json")
                await response(scope, receive, send)
                return
            try:  # pragma: no cover
                message = JSONRPCMessage.model_validate(raw_message)
''')
replace('''            request_id = str(message.root.id)
''', '''            request_id = _probe_rpc_route_key(message.root.id)
            # Session/credential/header validation above already succeeded. Single
            # event-loop owner: no await from check through reservation/first route write.
            if request_id in self._probe_seen_ids:
                response = Response('{"error":"duplicate_request_id"}', status_code=409,
                                    media_type="application/json")
                await response(scope, receive, send)
                return
            if len(self._probe_seen_ids) >= self._probe_max_seen_ids:
                response = Response('{"error":"session_request_limit"}', status_code=429,
                                    media_type="application/json")
                await response(scope, receive, send)
                return
            self._probe_seen_ids.add(request_id)
''')
replace('''                standalone_stream_reader = self._request_streams[GET_STREAM_KEY][1]
''', '''                standalone_stream_entry = self._request_streams[GET_STREAM_KEY]
                standalone_stream_reader = standalone_stream_entry[1]
''')
replace('''                await self._clean_up_memory_streams(GET_STREAM_KEY)
''', '''                await self._clean_up_memory_streams(GET_STREAM_KEY, standalone_stream_entry)
''')
replace('''                            response_id = str(message.root.id)
''', '''                            response_id = _probe_rpc_route_key(message.root.id)
''')
replace('''                            target_request_id = str(session_message.metadata.related_request_id)
''', '''                            target_request_id = _probe_rpc_route_key(session_message.metadata.related_request_id)
''')
# The SSE-POST branch is gated off, but keep its callback argument a wire ID.
replace('''                        session_message = self._create_session_message(message, request, request_id, protocol_version)
''', '''                        session_message = self._create_session_message(message, request, message.root.id, protocol_version)
''')
replace('''        self._terminated = True
''', '''        self._terminated = True
        self._probe_seen_ids.clear()  # Session is now invalid; never clear a live history.
''')

# GET ownership is established before EventSourceResponse can yield/start its
# sender. Every normal/exception exit retains this same captured tuple.
replace('''        sse_stream_writer, sse_stream_reader = anyio.create_memory_object_stream[SSEEvent](0)

        async def standalone_sse_writer():
''', '''        sse_stream_writer, sse_stream_reader = anyio.create_memory_object_stream[SSEEvent](0)
        standalone_stream_entry = anyio.create_memory_object_stream[EventMessage](REQUEST_STREAM_BUFFER_SIZE)
        self._request_streams[GET_STREAM_KEY] = standalone_stream_entry

        async def standalone_sse_writer():
''')
replace('''                self._request_streams[GET_STREAM_KEY] = anyio.create_memory_object_stream[EventMessage](
                    REQUEST_STREAM_BUFFER_SIZE
                )
                standalone_stream_entry = self._request_streams[GET_STREAM_KEY]
                standalone_stream_reader = standalone_stream_entry[1]
''', '''                standalone_stream_reader = standalone_stream_entry[1]
''')
replace('''            await self._clean_up_memory_streams(GET_STREAM_KEY)
''', '''            await self._clean_up_memory_streams(GET_STREAM_KEY, standalone_stream_entry)
''')
replace('''        finally:
            await sse_stream_writer.aclose()
            await sse_stream_reader.aclose()
''', '''        finally:
            await self._clean_up_memory_streams(GET_STREAM_KEY, standalone_stream_entry)
            with anyio.CancelScope(shield=True):
                await sse_stream_writer.aclose()
                await sse_stream_reader.aclose()
''')
replace('''                                await self._request_streams[request_stream_id][0].send(EventMessage(message, event_id))
''', '''                                route_entry = self._request_streams[request_stream_id]
                                await route_entry[0].send(EventMessage(message, event_id))
''')
replace('''                                self._request_streams.pop(request_stream_id, None)
''', '''                                if self._request_streams.get(request_stream_id) is route_entry:
                                    self._request_streams.pop(request_stream_id, None)
''')

compile(text, str(candidate), 'exec')
candidate.write_text(text)
diff = ''.join(difflib.unified_diff(original.read_text().splitlines(True), text.splitlines(True),
                                 fromfile='sdk-original/mcp/server/streamable_http.py',
                                 tofile='sdk-candidate/mcp/server/streamable_http.py'))
(R / 'evidence/throwaway-sdk-candidate.diff').write_text(diff)
meta = {'kind': 'THROWAWAY mechanism probe, NOT product fix', 'modified_files': ['mcp/server/streamable_http.py'],
        'original_sha256': hashlib.sha256(original.read_bytes()).hexdigest(),
        'candidate_sha256': hashlib.sha256(candidate.read_bytes()).hexdigest(),
        'scope': 'JSON POST responses + standalone GET; EventStore/SSE POST explicitly unqualified',
        'production_or_installed_SDK_changed': False}
(R / 'evidence/candidate-build.json').write_text(json.dumps(meta, indent=2) + '\n')
print(json.dumps(meta, indent=2))
