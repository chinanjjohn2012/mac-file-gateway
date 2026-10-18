"""Failing then passing regression tests for PR6-F3 (no network, no SDK)."""
from pathlib import Path
import importlib.util
import json
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('pr3_run_matrix_v2', ROOT / 'run_matrix_v2.py')


def execute(tmp_path, script_text, timeout=2):
    assert SPEC is not None and SPEC.loader is not None
    module = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(module)
    script = tmp_path / 'synthetic.py'
    script.write_text(script_text)
    output = tmp_path / 'evidence'
    output.mkdir()
    result = module.record_command(
        argv=[sys.executable, '-B', str(script)], cwd=tmp_path,
        output_dir=output, env={'PATH': '/usr/bin:/bin'}, timeout_seconds=timeout,
        matrix_sha256='synthetic-test-only', sdk_transport_sha256='synthetic-test-only',
    )
    return result, output


def check_artifacts(output):
    for path in ('stdout.log', 'stderr.log', 'command.json'):
        assert (output / path).exists(), path
    return json.loads((output / 'command.json').read_text())


def test_timeout_records_partial_logs_and_failure(tmp_path):
    result, output = execute(tmp_path,
        'import sys,time\nprint("OUTPUT_FIRST",flush=True)\n'
        'print("ERROR_FIRST",file=sys.stderr,flush=True)\ntime.sleep(10)\n', timeout=1.5)
    record = check_artifacts(output)
    assert 'OUTPUT_FIRST' in (output / 'stdout.log').read_text()
    assert 'ERROR_FIRST' in (output / 'stderr.log').read_text()
    assert record['timed_out'] is True
    assert record['exit_code'] is not None and record['exit_code'] != 0
    assert result == record['exit_code']


def test_nonzero_exit_records_logs_and_exit_code(tmp_path):
    result, output = execute(tmp_path,
        'import sys\nprint("NONZERO_MARKER",flush=True)\nsys.exit(17)\n')
    record = check_artifacts(output)
    assert result == 17 and record['exit_code'] == 17
    assert record['timed_out'] is False
    assert 'NONZERO_MARKER' in (output / 'stdout.log').read_text()


def test_launch_failure_preserves_command_metadata(tmp_path):
    assert SPEC and SPEC.loader
    module = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(module)
    output = tmp_path / 'evidence'
    output.mkdir()
    result = module.record_command(argv=['/definitely-not-a-real-executable'], cwd=tmp_path,
        output_dir=output, env={'PATH': '/usr/bin:/bin'}, timeout_seconds=1,
        matrix_sha256='synthetic-test-only', sdk_transport_sha256='synthetic-test-only')
    record = check_artifacts(output)
    assert result != 0 and record['exit_code'] != 0
    assert record['timed_out'] is False
    assert record['exception_type'] == 'FileNotFoundError'
