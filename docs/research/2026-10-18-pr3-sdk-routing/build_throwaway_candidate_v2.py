"""Apply PR6 F1/F2 research fixes to a disposable *v1-built* SDK copy.

This is not a vendor patch and must never write to site-packages.
F3 is repaired independently in run_matrix_v2.py.
"""
from __future__ import annotations

import difflib
import hashlib
import json
from pathlib import Path

R = Path(__file__).resolve().parent
MANIFEST = json.loads((R / 'SDK_SOURCE_SHA256.json').read_text())
FILES = ('server/streamable_http.py', 'server/fastmcp/server.py', 'shared/session.py')
V1_TRANSPORT_SHA256 = '6b9fef82b68c070c6f66f9181ac91221832655c1abd80d3a7afe498ed5a5a3ef'


def digest(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def change_once(s: str, old: str, new: str, count: int = 1) -> str:
    actual = s.count(old)
    if actual != count:
        raise ValueError(f'v2 source pattern mismatch: expected {count}, observed {actual}: {old[:70]!r}')
    return s.replace(old, new)


def main() -> None:
    before = R / 'sdk-original/mcp'
    after = R / 'sdk-candidate/mcp'
    for relative in FILES:
        original = before / relative
        current = after / relative
        expected = V1_TRANSPORT_SHA256 if relative == FILES[0] else MANIFEST[relative]
        if digest(original.read_bytes()) != MANIFEST[relative] or digest(current.read_bytes()) != expected:
            raise ValueError(f'Preimage drift: {relative}; build from pinned SDK + v1 builder first')

    s = (after / FILES[1]).read_text()
    # Preserve the publicly visible string Context.request_id; internal metadata uses raw wire ID.
    s = change_once(s, 'related_request_id=self.request_id,',
                    'related_request_id=self.request_context.request_id,', count=4)
    (after / FILES[1]).write_text(s)

    s = (after / FILES[2]).read_text()
    s = change_once(s,
                    'metadata=ServerMessageMetadata(related_request_id=related_request_id) if related_request_id else None,',
                    'metadata=ServerMessageMetadata(related_request_id=related_request_id) if related_request_id is not None else None,')
    (after / FILES[2]).write_text(s)

    s = (after / FILES[0]).read_text()
    s = change_once(s, '''                self._request_streams[request_id] = anyio.create_memory_object_stream[EventMessage](
                    REQUEST_STREAM_BUFFER_SIZE
                )
                request_stream_reader = self._request_streams[request_id][1]
                # Process the message
                metadata = ServerMessageMetadata(request_context=request)
                session_message = SessionMessage(message, metadata=metadata)
                await writer.send(session_message)
                try:
''', '''                # Construct the message BEFORE registering transport state.
                metadata = ServerMessageMetadata(request_context=request)
                session_message = SessionMessage(message, metadata=metadata)
                route_entry = anyio.create_memory_object_stream[EventMessage](REQUEST_STREAM_BUFFER_SIZE)
                self._request_streams[request_id] = route_entry
                request_stream_reader = route_entry[1]
                try:
                    # This first cancellable dispatch must already be under cleanup.
                    await writer.send(session_message)
''')
    s = change_once(s, '''                finally:
                    await self._clean_up_memory_streams(request_id)
            else:  # pragma: no cover
''', '''                finally:
                    await self._clean_up_memory_streams(request_id, route_entry)
            else:  # pragma: no cover
''')
    (after / FILES[0]).write_text(s)

    # Patch is the exact multi-file diff against official preimage, not the old v1 patch.
    diff = ''.join(
        ''.join(difflib.unified_diff((before / rel).read_text().splitlines(True),
                                     (after / rel).read_text().splitlines(True),
                                     fromfile='sdk-original/mcp/' + rel,
                                     tofile='sdk-candidate/mcp/' + rel))
        for rel in FILES
    )
    (R / 'evidence').mkdir(exist_ok=True)
    (R / 'evidence/throwaway-sdk-candidate-v2.diff').write_text(diff)
    hashes = {rel: digest((after / rel).read_bytes()) for rel in FILES}
    result = {'kind': 'throwaway PR6-F1/F2 research only; product qualification BLOCK',
              'modified_files': list(FILES), 'candidate_sha256': hashes,
              'original_sdk_manifest_sha256': digest((R / 'SDK_SOURCE_SHA256.json').read_bytes()),
              'production_sdk_changed': False}
    (R / 'evidence/candidate-v2-build.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
