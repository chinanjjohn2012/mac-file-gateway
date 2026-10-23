import pytest
from gateway.visibility import SensitiveContentPolicy


def test_hidden_lines_do_not_leak_via_search_or_replace_matching():
    policy=SensitiveContentPolicy(('/tmp/project-b',))
    a='visible=hello\npassword=alpha\nedit=ready\n'
    b='visible=hello\npassword=beta\nedit=ready\n'
    assert policy.redact_lines(a)[1] == 1
    assert policy.redact_lines(b)[1] == 1
    assert policy.visible_matches(a, 'alpha') == policy.visible_matches(b,'alpha') == []
    assert len(policy.visible_matches(a, 'ready')) == 1
    assert len(policy.visible_matches(b, 'ready')) == 1
    assert policy.visible_matches(a, 'hello\npassword') == []
    assert policy.visible_matches(a, '[REDACTED]') == []


def test_plain_path_text_is_visible_in_reads_search_and_diff():
    policy=SensitiveContentPolicy(('/tmp/project-b', '/tmp/project-a/config.json'))
    data='before\nroot=/tmp/project-b/lib/x.py\nafter\n'
    lines,n=policy.redact_lines(data)
    assert n==0
    assert '/tmp/project-b/lib/x.py' in '\n'.join(lines)
    diff=''.join(policy.redacted_diff_lines(data))
    assert '/tmp/project-b/lib/x.py' in diff
    assert 'root=' in diff
    assert policy.visible_matches(data, '/tmp/project-b/lib/x.py')
    assert not policy.is_sensitive('hello /tmp/project-b/path')
    assert not policy.is_sensitive('hello /tmp/project-b-other/path')
    # Credential evidence stays protected even if a path appears on its line.
    assert policy.is_sensitive('password="abc" # /tmp/project-b/path')


def test_new_sensitive_lines_are_rejected_not_existing_ones():
    p=SensitiveContentPolicy(('/tmp/project-b',))
    old='password=alpha\nedit=hello\n'
    assert not p.new_sensitive_content(old, 'password=alpha\nedit=world\n')
    assert p.new_sensitive_content(old, 'password=alpha\nedit=password=beta\n')
    assert not p.new_sensitive_content(old, 'password=alpha\nedit=/tmp/project-b/path\n')
    assert p.new_sensitive_content(old, 'password=alpha\npassword=alpha\nedit=hello\n')
