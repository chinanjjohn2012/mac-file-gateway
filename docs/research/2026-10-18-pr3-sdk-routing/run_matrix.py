"""Execute one isolated SDK ASGI matrix with complete logs, no overwrites."""
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import subprocess
import sys

R = Path(__file__).resolve().parent
mode, tag = sys.argv[1:3]
assert mode in ('original', 'candidate') and tag.replace('-', '').isalnum()
D = R / 'evidence/runs' / f'{mode}-{tag}'
D.mkdir(parents=True)
for name in ('home', 'tmp'):
    (D / name).mkdir()
exe = sys.executable
env = {'PATH': str(Path(exe).parent) + ':/usr/bin:/bin', 'HOME': str(D / 'home'),
       'TMPDIR': str(D / 'tmp'), 'PYTHONPATH': str(R / ('sdk-original' if mode == 'original' else 'sdk-candidate')),
       'PYTHONDONTWRITEBYTECODE': '1', 'PYTEST_DISABLE_PLUGIN_AUTOLOAD': '1'}
argv = [exe, '-B', str(R / 'sdk_asgi_matrix.py'), mode, str(D / 'result.json')]
p = subprocess.run(argv, cwd=D, env=env, capture_output=True, timeout=65)
for name, data in [('stdout.log', p.stdout), ('stderr.log', p.stderr)]:
    with (D / name).open('xb') as f:
        f.write(data)
with (D / 'command.json').open('x') as f:
    json.dump({'utc': datetime.now(timezone.utc).isoformat(), 'argv': argv, 'cwd': str(D), 'env': env,
               'exit_code': p.returncode, 'matrix_sha256': hashlib.sha256((R / 'sdk_asgi_matrix.py').read_bytes()).hexdigest()},
              f, ensure_ascii=False, indent=2)
    f.write('\n')
if (D / 'result.json').exists():
    result = json.loads((D / 'result.json').read_text())
    print(json.dumps({'mode': mode, 'exit_code': p.returncode,
                      'cases': [{k: v for k, v in c.items() if k in
                                 ('case', 'passed', 'not_run', 'harness_or_mechanism_exception', 'detail')}
                                for c in result['cases']]}, ensure_ascii=False, indent=2))
else:
    print('Missing result JSON, exit', p.returncode, p.stderr.decode(errors='replace')[-4000:])
assert p.returncode == 0, 'Probe command failed; see preserved complete logs'
