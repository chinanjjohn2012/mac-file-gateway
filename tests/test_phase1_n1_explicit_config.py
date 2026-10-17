"""N1: an explicitly supplied empty --config must never fall back to legacy mode."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from gateway import __main__ as entry
from gateway import multi_cli


_EMPTY_FORMS = [
    ['--config='], ['--config', ''], ['--conf='], ['--conf', ''],
    ['--config', '   '],
]


@pytest.mark.parametrize('empty_config', _EMPTY_FORMS)
@pytest.mark.parametrize('legacy_first', [False, True])
def test_empty_config_rejected_before_either_mode(tmp_path, monkeypatch, capsys,
                                                  empty_config, legacy_first):
    constructed = []

    def forbidden(*args, **kwargs):
        constructed.append((args, kwargs))
        raise AssertionError('Neither Multi nor legacy construction is allowed')

    monkeypatch.setattr(entry, 'Gateway', forbidden)
    monkeypatch.setattr(multi_cli, 'run_multi', forbidden)
    legacy = ['--root', str(tmp_path), '--check']
    argv = legacy + empty_config if legacy_first else empty_config + legacy
    with pytest.raises(SystemExit) as caught:
        entry.main(argv)
    assert caught.value.code == 2
    assert '--config requires a nonempty path' in capsys.readouterr().err
    assert constructed == []


@pytest.mark.parametrize('empty_config', _EMPTY_FORMS)
def test_empty_config_without_legacy_root_is_rejected_early(monkeypatch, capsys, empty_config):
    monkeypatch.setattr(entry, 'Gateway', lambda *a, **kw: pytest.fail('legacy constructed'))
    monkeypatch.setattr(multi_cli, 'run_multi', lambda *a, **kw: pytest.fail('multi started'))
    with pytest.raises(SystemExit) as caught:
        entry.main([*empty_config, '--check'])
    assert caught.value.code == 2
    assert '--config requires a nonempty path' in capsys.readouterr().err


def test_empty_config_sys_argv_is_rejected_before_construction(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(entry, 'Gateway', lambda *a, **kw: pytest.fail('legacy constructed'))
    monkeypatch.setattr(multi_cli, 'run_multi', lambda *a, **kw: pytest.fail('multi started'))
    monkeypatch.setattr(sys, 'argv', ['gateway', '--conf=', '--root', str(tmp_path), '--check'])
    with pytest.raises(SystemExit) as caught:
        entry.main()
    assert caught.value.code == 2
    assert '--config requires a nonempty path' in capsys.readouterr().err


@pytest.mark.parametrize('empty_config', _EMPTY_FORMS[:4])
def test_empty_config_subprocess_exit_2_without_legacy_json(tmp_path, empty_config):
    project = tmp_path / 'project'
    project.mkdir()
    env = os.environ.copy()
    env.pop('GATEWAY_TOKEN', None)
    env.pop('PYTHONPATH', None)
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    result = subprocess.run([
        sys.executable, '-B', '-m', 'gateway', *empty_config,
        '--root', str(project), '--check',
    ], cwd=Path(__file__).resolve().parents[1], env=env,
       capture_output=True, text=True, timeout=10)
    assert result.returncode == 2
    assert '--config requires a nonempty path' in result.stderr
    assert result.stdout == '', 'Legacy project JSON must not be emitted'
