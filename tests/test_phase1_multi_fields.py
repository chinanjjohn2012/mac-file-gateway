import pytest
from gateway.core import GatewayError
from gateway.multi_fields import validate_tool_arguments


def test_multi_requires_workspace_and_rejects_unknown_extra():
    with pytest.raises(GatewayError) as e:
        validate_tool_arguments('read_file',{'path':'x.py'},multi=True)
    assert e.value.code=='workspace_required'
    with pytest.raises(GatewayError):
        validate_tool_arguments('read_file',{'workspace':'a','path':'x.py','destination_workspace':'b'},multi=True)
    assert validate_tool_arguments('read_file',{'workspace':'a','path':'x.py'},multi=True)['workspace']=='a'


def test_local_skill_tools_are_never_exposed_in_multi():
    for name in ['local_skill_info','run_skill_script','begin_local_skill']:
        with pytest.raises(GatewayError):
            validate_tool_arguments(name,{'workspace':'a'},multi=True)


def test_multi_exec_requires_explicit_workspace_and_strict_arguments():
    valid = {'workspace':'a','cwd':'.','argv':['python','-m','compileall']}
    assert validate_tool_arguments('run_command', valid, multi=True) == valid
    with pytest.raises(GatewayError) as exc:
        validate_tool_arguments('run_command', {'cwd':'.','argv':['python','-m','pytest']}, multi=True)
    assert exc.value.code == 'workspace_required'
    for extra in ({'timeout_seconds':True}, {'timeout_seconds':301},
                  {'dry_run':'false'}, {'argv':['python',3]},
                  {'destination_workspace':'b'}):
        with pytest.raises(GatewayError):
            validate_tool_arguments('run_command', {**valid, **extra}, multi=True)


def test_legacy_rejects_workspace_override_and_skill_dry_run():
    with pytest.raises(GatewayError):
        validate_tool_arguments('read_file',{'path':'x.py','workspace':'b'},multi=False)
    with pytest.raises(GatewayError):
        validate_tool_arguments('run_skill_script',{'skill_run_id':'x','skill':'s','script':'x.sh','dry_run':True},multi=False)


def test_strict_bool_and_wrong_types():
    for args in [{'workspace':'a','path':'x.py','dry_run':1},
                 {'workspace':'a','path':'x.py','dry_run':'false'},
                 {'workspace':'a','path':'x.py','dry_run':0}]:
        with pytest.raises(GatewayError):
            validate_tool_arguments('create_directory', args, multi=True)
