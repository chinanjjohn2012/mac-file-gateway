"""Research-only runner: persist subprocess evidence even on timeout or spawn failure.

Never runs Gateway code or a command sourced from an HTTP/MCP user request.
The matrix executable is explicitly fixed by this checked-in research script.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

R = Path(__file__).resolve().parent


def record_command(
    *, argv: list[str], cwd: Path, output_dir: Path, env: dict[str, str],
    timeout_seconds: float, matrix_sha256: str, sdk_transport_sha256: str,
) -> int:
    """Run a research subprocess once, writing evidence before observing its result.

    Returns 124 on timeout, 125 on launch error, or the real child exit code.
    Python subprocess.run kills/reaps the direct child on TimeoutExpired;
    only self-created synthetic research children are in scope.
    """
    start = datetime.now(timezone.utc).isoformat()
    mono = time.monotonic()
    result: dict[str, object] = {
        'utc_start': start, 'utc_end': None, 'elapsed_seconds': None,
        'argv': argv, 'cwd': str(cwd), 'env': env, 'timeout_seconds': timeout_seconds,
        'timed_out': False, 'exit_code': None, 'exception_type': None,
        'matrix_sha256': matrix_sha256, 'sdk_transport_sha256': sdk_transport_sha256,
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    code = 125
    try:
        with (output_dir / 'stdout.log').open('xb') as stdout, (output_dir / 'stderr.log').open('xb') as stderr:
            try:
                child = subprocess.run(argv, cwd=cwd, env=env, stdout=stdout,
                                       stderr=stderr, timeout=timeout_seconds, check=False)
                code = child.returncode
            except subprocess.TimeoutExpired as exc:
                result['timed_out'] = True
                result['exception_type'] = type(exc).__name__
                code = 124
            except OSError as exc:
                result['exception_type'] = type(exc).__name__
                result['error_errno'] = exc.errno  # No local path in public summaries.
                code = 125
    finally:
        result['utc_end'] = datetime.now(timezone.utc).isoformat()
        result['elapsed_seconds'] = round(time.monotonic() - mono, 6)
        result['exit_code'] = code
        with (output_dir / 'command.json').open('x', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
            f.write('\n')
    return code


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit('usage: run_matrix_v2.py original|candidate SUFFIX')
    mode, tag = sys.argv[1:3]
    if mode not in ('original', 'candidate') or not tag.replace('-', '').isalnum():
        raise SystemExit('invalid research mode/tag')
    dest = R / 'evidence/runs' / f'{mode}-{tag}'
    dest.mkdir(parents=True, exist_ok=False)
    for name in ('home', 'tmp'):
        (dest / name).mkdir()
    exe = sys.executable
    env = {'PATH': str(Path(exe).parent) + ':/usr/bin:/bin', 'HOME': str(dest / 'home'),
           'TMPDIR': str(dest / 'tmp'),
           'PYTHONPATH': str(R / ('sdk-original' if mode == 'original' else 'sdk-candidate')),
           'PYTHONDONTWRITEBYTECODE': '1', 'PYTEST_DISABLE_PLUGIN_AUTOLOAD': '1'}
    matrix = R / 'sdk_asgi_matrix.py'
    sdk_source = R / f'sdk-{mode}/mcp/server/streamable_http.py'
    code = record_command(
        argv=[exe, '-B', str(matrix), mode, str(dest / 'result.json')],
        cwd=dest, output_dir=dest, env=env, timeout_seconds=65,
        matrix_sha256=hashlib.sha256(matrix.read_bytes()).hexdigest(),
        sdk_transport_sha256=hashlib.sha256(sdk_source.read_bytes()).hexdigest(),
    )
    result_file = dest / 'result.json'
    if code == 0 and result_file.is_file():
        data = json.loads(result_file.read_text())
        print(json.dumps({'mode': mode, 'exit_code': code,
                          'cases': [{k: v for k, v in c.items() if k in
                                     ('case','passed','not_run','harness_or_mechanism_exception','detail')}
                                    for c in data['cases']]}, ensure_ascii=False, indent=2))
    else:
        print(f'Research matrix failed or timed out: {mode}, exit={code}; inspect preserved logs', file=sys.stderr)
        raise SystemExit(code or 125)


if __name__ == '__main__':
    main()
