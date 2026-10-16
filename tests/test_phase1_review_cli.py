"""F6: every explicitly supplied legacy option conflicts with config mode."""
import json
import sys

import pytest

from gateway.__main__ import main
from gateway import multi_cli


OPTIONS = [
    ('--root', '--roo', '/tmp/unused-project'),
    ('--port', '--po', '8765'),
    ('--exclude', '--excl', 'private/*'),
    ('--allow-hidden-path', '--allow-h', '.scratch'),
    ('--allow-write', '--allow-w', None),
    ('--write-path', '--write-p', '.'),
    ('--backup-retention-days', '--backup-r', '15'),
    ('--allow-exec', '--allow-e', None),
    ('--exec-path', '--exec-p', '.'),
    ('--exec-runner', '--exec-r', '.=direct'),
    ('--local-skill-root', '--local-skill-r', 'agent'),
    ('--local-skill-policy-dir', '--local-skill-p', '/tmp/unused-policy'),
]
CASES = []
for full, short, value in OPTIONS:
    for option in (full, short):
        CASES.append([option] if value is None else [option, value])
        if value is not None:
            CASES.append([option + '=' + value])


@pytest.mark.parametrize('extra', CASES)
@pytest.mark.parametrize('config_first', [True, False])
def test_full_abbreviated_and_equals_legacy_options_rejected_before_multi_start(monkeypatch, extra, config_first):
    entered = []
    monkeypatch.setattr(multi_cli, 'run_multi', lambda args: entered.append(args) or 0)
    config = ['--config', '/nonexistent/gateway.json', '--check']
    args = config + extra if config_first else extra + config
    with pytest.raises(SystemExit) as exc:
        main(args)
    assert exc.value.code == 2
    assert not entered, 'invalid mixed mode reached config loading or listener startup'


def test_sys_argv_abbreviations_are_checked_too(monkeypatch):
    entered = []
    monkeypatch.setattr(multi_cli, 'run_multi', lambda args: entered.append(args) or 0)
    monkeypatch.setattr(sys, 'argv', ['gateway', '--config=/nonexistent/gateway.json', '--po=8765'])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 2
    assert not entered


@pytest.mark.parametrize('config_option', ['--config', '--conf'])
def test_multi_mode_without_legacy_options_still_reaches_runner(monkeypatch, config_option):
    entered = []
    monkeypatch.setattr(multi_cli, 'run_multi', lambda args: entered.append(args) or 0)
    assert main([config_option, '/nonexistent/gateway.json', '--check']) == 0
    assert len(entered) == 1 and entered[0].check is True


def test_legacy_defaults_and_abbreviations_preserved(tmp_path, capsys):
    root = tmp_path / 'project'
    root.mkdir()
    assert main(['--roo', str(root), '--check']) == 0
    initial = json.loads(capsys.readouterr().out)
    assert initial['read_only'] is True
    assert initial['exec_policy']['enabled'] is False
    assert initial['hidden_paths'] == []
    assert initial['write_policy']['backup_retention_days'] == 15
    assert main(['--roo=' + str(root), '--po=8765', '--excl', 'private/*', '--allow-w',
                 '--write-p=.', '--backup-r=15', '--allow-e', '--exec-p=.',
                 '--exec-r=.=direct', '--allow-h=.scratch', '--check']) == 0
    explicit = json.loads(capsys.readouterr().out)
    assert explicit['read_only'] is False
    assert explicit['exec_policy']['enabled'] is True
    assert explicit['exec_policy']['paths'] == ['.']
    assert explicit['hidden_paths'] == ['.scratch']
    # Defaults must not be mutated by a preceding parse in the same process.
    assert main(['--root', str(root), '--check']) == 0
    again = json.loads(capsys.readouterr().out)
    assert again['read_only'] is True
    assert again['hidden_paths'] == []
    assert again['exec_policy']['enabled'] is False
