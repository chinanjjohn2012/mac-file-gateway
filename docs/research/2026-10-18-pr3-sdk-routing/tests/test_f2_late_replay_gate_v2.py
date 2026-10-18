"""F2 acceptance-window regression on a throwaway, pinned MCP SDK candidate.

The fault injects a synthetic tool call using A's Context after the 902 replay
returned 409. It tests the acceptance gate, NOT a naturally occurring SDK
misdispatch or a real business/Gateway process.
"""
from hashlib import sha256
from importlib import metadata
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from unittest.mock import patch

import anyio
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
EXPECTED_V2 = {
    'server/streamable_http.py': 'ba2b7d77564d45411601353e4db5e483afc8b2a8f9f38ef6311116895d0fa0c5',
    'server/fastmcp/server.py': '0c6ec532af013b4618071d9ab0b80d954bcee9ac65140ad5a18de465479b7a53',
    'shared/session.py': '786adf75620fee4166b29e5077ed6df05ea0394101dfd788e699bd3d7906ff5f',
}


@pytest.fixture(scope='module')
def candidate_env(tmp_path_factory):
    """Recreate the reviewed SDK patch in an out-of-repo directory, not site-packages."""
    from run_research_v2 import V2_SHA
    assert V2_SHA == EXPECTED_V2
    assert metadata.version('mcp') == '1.30.0'
    manifest = json.loads((ROOT / 'SDK_SOURCE_SHA256.json').read_text())
    installed = Path(metadata.distribution('mcp').locate_file('mcp'))
    scratch = tmp_path_factory.mktemp('sdk-f2-late-gate')
    for name in ('build_throwaway_candidate.py', 'build_throwaway_candidate_v2.py',
                 'SDK_SOURCE_SHA256.json'):
        shutil.copyfile(ROOT / name, scratch / name)
    (scratch / 'evidence').mkdir()
    for relative, expected in manifest.items():
        source = installed / relative
        assert sha256(source.read_bytes()).hexdigest() == expected, relative
        for mode in ('original', 'candidate'):
            target = scratch / f'sdk-{mode}' / 'mcp' / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
    for builder in ('build_throwaway_candidate.py', 'build_throwaway_candidate_v2.py'):
        subprocess.run([sys.executable, '-B', str(scratch / builder)],
                       cwd=scratch, check=True, capture_output=True, timeout=25)
    for relative, expected in manifest.items():
        candidate = scratch / 'sdk-candidate/mcp' / relative
        assert sha256(candidate.read_bytes()).hexdigest() == EXPECTED_V2.get(relative, expected), relative
    env = dict(os.environ)
    # Candidate source wins. Keep the installed distribution's normal parent
    # available for dependency imports and its verified wheel metadata.
    env['PYTHONPATH'] = str(scratch / 'sdk-candidate') + os.pathsep + str(installed.parent)
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    return env


def run_delayed_replay_injection(output: Path):
    # Load the real SDK via the caller's verified, disposable PYTHONPATH.
    sys.path.insert(0, str(ROOT))
    import fullchain_probe_v2 as probe
    matrix = probe.matrix
    original_init = matrix.Fixture.__init__
    original_post = matrix.Fixture.post
    injected = []

    def instrument_init(fixture, *args, **kwargs):
        original_init(fixture, *args, **kwargs)
        fixture._replay_response_seen = False
        tool = fixture.server._tool_manager.get_tool('synthetic_wait')
        original_fn = tool.fn

        async def instrumented_tool(*tool_args, **tool_kwargs):
            if tool_kwargs.get('label') == 'A' and fixture._replay_response_seen:
                injected.append(fixture)
                await original_fn(label='REPLAY_CANCELLED_ID',
                                  ctx=tool_kwargs['ctx'], wait=False)
            return await original_fn(*tool_args, **tool_kwargs)

        tool.fn = instrumented_tool

    async def instrument_post(fixture, request_id, label, *args, **kwargs):
        response = await original_post(fixture, request_id, label, *args, **kwargs)
        if label == 'REPLAY_CANCELLED_ID':
            assert request_id == 902 and response.get('status') == 409
            fixture._replay_response_seen = True
        return response

    with patch.object(matrix.Fixture, '__init__', instrument_init), \
         patch.object(matrix.Fixture, 'post', instrument_post), \
         patch.object(sys, 'argv', ['fullchain_probe_v2.py', 'candidate', str(output)]):
        try:
            anyio.run(probe.main)
        finally:
            assert len(injected) == 1, 'fault injection did not reach the real synthetic tool'
            assert injected[0].calls == ['REPLAY_CANCELLED_ID', 'A', 'AFTER_CANCEL']


def f2_record(path: Path):
    payload = json.loads(path.read_text())
    return next(row for row in payload['results']
                if row['case'] == 'cancel_at_real_predispatch_backpressure')


def test_normal_sdk_asgi_remains_valid(candidate_env, tmp_path):
    output = tmp_path / 'normal.json'
    run = subprocess.run([sys.executable, '-B', str(ROOT / 'fullchain_probe_v2.py'),
                          'candidate', str(output)],
                         env=candidate_env, capture_output=True, text=True, timeout=35)
    assert run.returncode == 0, run.stderr[-1800:]
    row = f2_record(output)
    assert row['replay_business_dispatch_delta'] == 0
    assert row['replay_business_dispatch_final'] == 0
    assert row['A_positive_succeeded'] and row['subsequent_positive_succeeded']


def test_delayed_replay_cli_is_rejected_and_runner_cannot_promote(candidate_env, tmp_path):
    # The versioned negative case is executable both as a script and via pytest.
    # A nonzero research subprocess must raise through the existing runner.
    from run_research_v2 import run_stage
    output = tmp_path / 'delayed.json'
    stage_root = tmp_path / 'runner'
    stage_root.mkdir()
    argv = [sys.executable, '-B', str(Path(__file__).resolve()), str(output)]
    with pytest.raises(RuntimeError, match=r'late-replay: exit 1'):
        run_stage(stage_root, 'late-replay', argv, candidate_env, timeout=35)
    command = json.loads((stage_root / 'record-late-replay/command.json').read_text())
    assert command['exit_code'] == 1
    assert 'F2: replay business dispatched after reader resumed' in (
        stage_root / 'record-late-replay/stderr.log').read_text()
    row = f2_record(output)
    assert row['replay_status'] == 409
    assert row['replay_business_dispatch_delta'] == 0
    assert row['replay_business_dispatch_final'] == 1
    assert row['A_positive_succeeded'] and row['subsequent_positive_succeeded']
    assert not (stage_root / 'PUBLIC_V2_SUMMARY.json').exists()


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('usage: test_f2_late_replay_gate_v2.py OUTPUT_JSON')
    run_delayed_replay_injection(Path(sys.argv[1]))
