"""Rebuild and check PR6-F1/F2/F3 research in an isolated output directory.

Requires a *disposable* Python environment with the official MCP 1.30.0 and
its real dependencies. No production Gateway, subprocess workers or live URLs.
The historical v1 reproduction and data files are not changed.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import shutil
import sys

from run_matrix_v2 import record_command
from run_research import verify_sdk, digest, BASELINE

R = Path(__file__).resolve().parent
V1_TRANSPORT = '6b9fef82b68c070c6f66f9181ac91221832655c1abd80d3a7afe498ed5a5a3ef'
V2_SHA = {
    'server/streamable_http.py': 'ba2b7d77564d45411601353e4db5e483afc8b2a8f9f38ef6311116895d0fa0c5',
    'server/fastmcp/server.py': '0c6ec532af013b4618071d9ab0b80d954bcee9ac65140ad5a18de465479b7a53',
    'shared/session.py': '786adf75620fee4166b29e5077ed6df05ea0394101dfd788e699bd3d7906ff5f',
}
STAGES = ('sdk_asgi_matrix.py', 'build_throwaway_candidate.py',
          'build_throwaway_candidate_v2.py', 'run_matrix_v2.py',
          'fullchain_probe_v2.py', 'falsey_probe_v2.py', 'SDK-LICENSE.txt')


def run_stage(out: Path, name: str, argv: list[str], env: dict[str, str], timeout: float = 150) -> None:
    stage = out / ('record-' + name)
    stage.mkdir()
    transport = out / 'sdk-candidate/mcp/server/streamable_http.py'
    code = record_command(
        argv=argv, cwd=out, output_dir=stage, env=env, timeout_seconds=timeout,
        matrix_sha256=digest(Path(argv[2])) if len(argv)>2 and Path(argv[2]).is_file() else 'n/a',
        sdk_transport_sha256=digest(transport) if transport.is_file() else 'not-yet-built',
    )
    if code != 0:
        raise RuntimeError(f'{name}: exit {code}; see preserved {stage.name}/ logs in private output directory')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True,
                        help='new path outside every Git checkout; raw evidence stays private')
    args = parser.parse_args()
    output = args.output.expanduser().resolve()
    if any((p / '.git').exists() for p in (output, *output.parents)):
        parser.error('private --output must be outside all Git worktrees')
    if output.exists() or not output.parent.is_dir():
        parser.error('--output must be a new path with an existing parent directory')
    version = importlib.metadata.version('mcp')
    if version != '1.30.0':
        parser.error('requires pinned MCP 1.30.0 in an isolated research environment')
    sdk = Path(importlib.metadata.distribution('mcp').locate_file('mcp')).resolve()
    manifest = json.loads((R / 'SDK_SOURCE_SHA256.json').read_text())
    verify_sdk(sdk, manifest)

    output.mkdir()
    for name in ('home','tmp','evidence'):
        (output / name).mkdir()
    for name in STAGES:
        shutil.copyfile(R / name, output / name)
    for mode in ('original','candidate'):
        for rel in manifest:
            dest = output / f'sdk-{mode}/mcp' / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(sdk / rel, dest)
    shutil.copyfile(R / 'SDK_SOURCE_SHA256.json', output / 'SDK_SOURCE_SHA256.json')
    env = {'PATH': str(Path(sys.executable).parent) + os.pathsep + os.defpath,
           'HOME': str(output/'home'), 'TMPDIR': str(output/'tmp'),
           'PYTHONDONTWRITEBYTECODE':'1', 'PYTEST_DISABLE_PLUGIN_AUTOLOAD':'1'}
    (output/'provenance.json').write_text(json.dumps({
        'date':datetime.now(timezone.utc).isoformat(), 'python':sys.version,
        'platform':platform.platform(), 'review_baseline':BASELINE,
        'mcp_version':version, 'official_sdk_root_sha256':digest(R/'SDK_SOURCE_SHA256.json'),
        'script_sha256':{name:digest(R/name) for name in STAGES if name.endswith('.py')},
    },indent=2)+'\n')

    try:
        run_stage(output,'builder-v1',[sys.executable,'-B',str(output/'build_throwaway_candidate.py')],env)
        transport = output/'sdk-candidate/mcp/server/streamable_http.py'
        if digest(transport) != V1_TRANSPORT:
            raise RuntimeError('v1 builder mismatch before v2; STOP')
        if (output/'evidence/throwaway-sdk-candidate.diff').read_bytes() != (
                R/'patches/mcp-1.30.0-routing-prototype.patch').read_bytes():
            raise RuntimeError('v1 historical patch differs; STOP')

        run_stage(output,'builder-v2',[sys.executable,'-B',str(output/'build_throwaway_candidate_v2.py')],env)
        if (output/'evidence/throwaway-sdk-candidate-v2.diff').read_bytes() != (
                R/'patches/mcp-1.30.0-routing-v2-prototype.patch').read_bytes():
            raise RuntimeError('v2 patch differs; STOP')
        for rel, expected in manifest.items():
            actual = digest(output / 'sdk-candidate/mcp' / rel)
            if actual != V2_SHA.get(rel, expected):
                raise RuntimeError(f'unexpected candidate SDK file hash: {rel}; STOP')

        expected = json.loads((R/'results/recorded-research-summary.json').read_text())
        public = {'kind':'PR3 v2 research only; Phase 2 BLOCK',
                  'review_baseline':BASELINE, 'original_matrix':{},
                  'candidate_matrix':{}, 'extra_cases':{}}
        for mode in ('original','candidate'):
            # Runner is itself a subprocess: evidence is preserved by both record_command layers.
            run_stage(output,'matrix-'+mode,[sys.executable,'-B',str(output/'run_matrix_v2.py'),mode,'v2'],env)
            result = json.loads((output/f'evidence/runs/{mode}-v2/result.json').read_text())
            rows = result['cases']; reference = expected['runs'][mode]['cases']
            if [x['case'] for x in rows] != [x['case'] for x in reference]:
                raise RuntimeError('old 15-case matrix changed unexpectedly')
            for actual, past in zip(rows,reference):
                if (actual.get('passed') is not past.get('passed')
                    or actual.get('not_run') != past.get('not_run')
                    or 'harness_or_mechanism_exception' in actual):
                    raise RuntimeError(f'old matrix mismatch: {mode} {actual["case"]}')
            public[mode+'_matrix'] = {'cases':len(rows),'passed':sum(row.get('passed') is True for row in rows),
                                     'not_run':sum(bool(row.get('not_run')) for row in rows)}
        for script in ('fullchain_probe_v2.py','falsey_probe_v2.py'):
            mode='candidate'
            probe_env=dict(env, PYTHONPATH=str(output/'sdk-candidate'))
            result_file=output/f'evidence/{script}.json'
            run_stage(output,script,[sys.executable,'-B',str(output/script),mode,str(result_file)],probe_env)
            data=json.loads(result_file.read_text())
            assert data['Popen_attempts']==0 and data['mode']=='candidate'
            public['extra_cases'][script]={'passed':True, 'SDK_process_spawns':0}
        (output/'PUBLIC_V2_SUMMARY.json').write_text(json.dumps(public,indent=2)+'\n')
    finally:
        verify_sdk(sdk,manifest)
        verify_sdk(output/'sdk-original/mcp',manifest)
    print('PR3 v2 isolated experiments completed (see PUBLIC_V2_SUMMARY.json).')
    print('This is not SDK product qualification or Phase 2 acceptance.')


if __name__=='__main__':
    main()
