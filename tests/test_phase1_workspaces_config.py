from pathlib import Path
import sys
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from gateway.private_fs import PrivateFileError
from gateway.workspaces_config import parse_workspace_config, read_workspace_config


def valid(root='/tmp/work-a'):
    return {
        'schema_version': 1, 'server': {'port': 8765, 'transport': 'http'},
        'workspaces': {
            'project-a': {'root': root, 'read': {'enabled': True, 'excludes': ['private/*']},
                          'hidden_paths': ['.scratch'],
                          'write': {'enabled': True, 'paths': ['src', '.scratch'], 'backup_retention_days': 15},
                          'exec': {'enabled': False}, 'local_skills': {'enabled': False}},
            'project-b': {'root': '/tmp/work-b', 'write': {'enabled': False}}
        }
    }


def test_valid_schema():
    result = parse_workspace_config(valid())
    assert result.port == 8765 and len(result.workspaces) == 2
    assert result.workspaces[0].write_paths == ('src', '.scratch')
    assert result.workspaces[1].allow_write is False


@pytest.mark.parametrize('change', [
    lambda o: o.update(extra=True),
    lambda o: o.update(schema_version=True),
    lambda o: o['server'].update(port=True),
    lambda o: o['server'].update(transport='stdio'),
    lambda o: o['workspaces']['project-a']['write'].update(enabled=False),
    lambda o: o['workspaces']['project-a']['write'].update(paths=[]),
    lambda o: o['workspaces']['project-a']['exec'].update(enabled=True),
    lambda o: o['workspaces']['project-a']['local_skills'].update(enabled=True),
    lambda o: o['workspaces']['project-a'].update(root='/'),
    lambda o: o['workspaces']['project-a'].update(root='/tmp/../tmp'),
    lambda o: o['workspaces']['project-a'].update(root='/tmp/.private/code'),
    lambda o: o['workspaces']['project-a']['read'].update(enabled=False),
    lambda o: o['workspaces']['project-a']['read'].update(excludes=['../private']),
    lambda o: o['workspaces']['project-a'].update(hidden_paths=['src']),
    lambda o: o['workspaces']['project-a']['write'].update(paths=['/tmp']),
    lambda o: o['workspaces']['project-a']['write'].update(backup_retention_days=True),
    lambda o: o['workspaces']['project-a'].update(unknown_option=1),
])
def test_reject_schema_error(change):
    o = valid()
    change(o)
    with pytest.raises(PrivateFileError):
        parse_workspace_config(o)


def test_too_many_workspaces():
    o = valid()
    o['workspaces'] = {f'w{i}': {'root': f'/tmp/w{i}'} for i in range(17)}
    with pytest.raises(PrivateFileError):
        parse_workspace_config(o)
