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



@pytest.mark.parametrize("schema_version", [1, 2])
@pytest.mark.parametrize("field", [
    "root", "read.excludes", "hidden_paths", "write.paths",
    "write.sensitive_content.paths", "git.allowed_commands",
])
@pytest.mark.parametrize("escaped", [r"\ud800", r"\udfff"])
def test_json_lone_surrogates_in_common_fields_are_private_errors(
    schema_version, field, escaped,
):
    import json

    bad = json.loads('"' + escaped + '"')
    config = valid()
    config["schema_version"] = schema_version
    ws = config["workspaces"]["project-a"]
    if schema_version == 2:
        ws["exec"] = {"paths": ["src"], "runners": []}
    if field == "root":
        ws["root"] = "/tmp/" + bad
    elif field == "read.excludes":
        ws["read"]["excludes"] = ["private/" + bad]
    elif field == "hidden_paths":
        ws["hidden_paths"] = [".scratch/" + bad]
    elif field == "write.paths":
        ws["write"]["paths"] = ["src/" + bad]
    elif field == "write.sensitive_content.paths":
        ws["write"]["sensitive_content"] = {
            "mode": "audit", "paths": ["src/" + bad],
            "expires_at": "2099-01-01T00:00:00Z",
        }
    elif field == "git.allowed_commands":
        ws["git"] = {"allowed_commands": ["git/" + bad]}
    # Real JSON serialization preserves the escaped surrogate input.
    config = json.loads(json.dumps(config, ensure_ascii=True))
    with pytest.raises(PrivateFileError):
        parse_workspace_config(config)


@pytest.mark.parametrize("field", ["paths", "runners"])
@pytest.mark.parametrize("escaped", [r"\ud800", r"\udfff"])
def test_v1_exec_common_lists_reject_json_lone_surrogates(field, escaped):
    import json

    config = valid()
    config["server"]["exec"] = {"enabled": True}
    ws = config["workspaces"]["project-a"]
    ws["exec"] = {
        "enabled": True, "paths": ["src"], "runners": ["src=direct"],
    }
    bad = json.loads('"' + escaped + '"')
    ws["exec"][field] = ["src/" + bad + "=direct"] if field == "runners" else ["src/" + bad]
    config = json.loads(json.dumps(config, ensure_ascii=True))
    with pytest.raises(PrivateFileError):
        parse_workspace_config(config)


@pytest.mark.parametrize("schema_version", [1, 2])
def test_common_config_accepts_json_unicode_surrogate_pair(schema_version):
    import json

    emoji = json.loads(r'"\ud83d\ude00"')
    assert len(emoji) == 1 and len(emoji.encode("utf-8")) == 4
    config = valid(root="/tmp/unicode-" + emoji)
    config["schema_version"] = schema_version
    config["workspaces"]["project-a"]["read"]["excludes"] = ["safe/" + emoji]
    if schema_version == 2:
        config["workspaces"]["project-a"]["exec"] = {
            "paths": ["src"], "runners": [],
        }
    settings = parse_workspace_config(json.loads(json.dumps(config, ensure_ascii=True)))
    assert settings.workspaces[0].root.endswith(emoji)
    assert settings.workspaces[0].excludes == ("safe/" + emoji,)


@pytest.mark.parametrize("schema_version", [1, 2])
def test_common_config_root_utf8_byte_limit_exact_and_over(schema_version):
    config = valid(root="/tmp/" + "r" * (4096 - len("/tmp/")))
    config["schema_version"] = schema_version
    if schema_version == 2:
        config["workspaces"]["project-a"]["exec"] = {
            "paths": ["src"], "runners": [],
        }
    assert parse_workspace_config(config).workspaces[0].root == config["workspaces"]["project-a"]["root"]
    config["workspaces"]["project-a"]["root"] += "r"
    with pytest.raises(PrivateFileError):
        parse_workspace_config(config)


@pytest.mark.parametrize("schema_version", [1, 2])
def test_common_config_list_utf8_byte_limit_exact_and_over(schema_version):
    config = valid()
    config["schema_version"] = schema_version
    if schema_version == 2:
        config["workspaces"]["project-a"]["exec"] = {
            "paths": ["src"], "runners": [],
        }
    emoji = "\U0001f600"
    config["workspaces"]["project-a"]["read"]["excludes"] = [emoji * 512]
    assert len((emoji * 512).encode("utf-8")) == 2048
    assert parse_workspace_config(config).workspaces[0].excludes == (emoji * 512,)
    config["workspaces"]["project-a"]["read"]["excludes"] = [emoji * 513]
    with pytest.raises(PrivateFileError):
        parse_workspace_config(config)


def test_too_many_workspaces():
    o = valid()
    o['workspaces'] = {f'w{i}': {'root': f'/tmp/w{i}'} for i in range(17)}
    with pytest.raises(PrivateFileError):
        parse_workspace_config(o)
