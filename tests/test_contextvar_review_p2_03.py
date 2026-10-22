"""Migrated P2-03 real-Gateway security regressions for the approved V3.

The former ContextVar provenance worker is intentionally no longer required:
module-import rebinding and dynamic Python operations do not, by themselves,
contain credential values. Each former bypass category is checked both for
normal visible source and for an *independent* hard-coded credential value.
No project source is imported or executed by Gateway or these tests.
"""
from __future__ import annotations

import pytest

from gateway.core import Gateway, GatewayError


_SCOPE = (
    "def scope(value):\n"
    "    token = active.set(value)\n"
    "    try:\n"
    "        yield value\n"
    "    finally:\n"
    "        active.reset(token)\n"
)

_FAKE = (
    "class FakeVar:\n"
    "    def __init__(self, *args, **kwargs): pass\n"
    "    def set(self, value): return 71\n"
    "    def reset(self, handle): pass\n"
)

_PREAMBLES = [
    "import contextvars\n" + _FAKE
    + "contextvars.ContextVar = FakeVar\n"
    + "active = contextvars.ContextVar()\n",
    "import contextvars as alias\n" + _FAKE
    + "alias.ContextVar = FakeVar\n"
    + "active = alias.ContextVar()\n",
    "import contextvars\n" + _FAKE
    + "contextvars.__class__ = FakeModule\n"
    + "active = contextvars.ContextVar()\n",
    "import contextvars\n"
    + "from contextvars import __dict__ as registry\n"
    + _FAKE + "registry['ContextVar'] = FakeVar\n"
    + "active = contextvars.ContextVar()\n",
    "import contextvars\n"
    + "from contextvars import __dict__ as registry\n"
    + _FAKE + "registry.update({'ContextVar': FakeVar})\n"
    + "active = contextvars.ContextVar()\n",
    "import sys\n" + _FAKE
    + "sys.modules['contextvars'] = FakeVar\n"
    + "import contextvars\n"
    + "active = contextvars.ContextVar()\n",
    "from sys import modules as cache\n" + _FAKE
    + "cache['contextvars'] = FakeVar\n"
    + "import contextvars\nactive = contextvars.ContextVar()\n",
    "import contextvars\n"
    + "from builtins import setattr as mutate\n" + _FAKE
    + "mutate(contextvars, 'ContextVar', FakeVar)\n"
    + "active = contextvars.ContextVar()\n",
    "import contextvars\n"
    + "from builtins import vars as namespace\n" + _FAKE
    + "namespace(contextvars)['ContextVar'] = FakeVar\n"
    + "active = contextvars.ContextVar()\n",
    "import contextvars\n"
    + "from operator import attrgetter as resolve\n" + _FAKE
    + "resolve('__dict__')(contextvars)['ContextVar'] = FakeVar\n"
    + "active = contextvars.ContextVar()\n",
    "import contextvars\n"
    + "from operator import methodcaller as apply\n" + _FAKE
    + "apply('__setattr__', 'ContextVar', FakeVar)(contextvars)\n"
    + "active = contextvars.ContextVar()\n",
    "from contextvars import ContextVar\n"
    + "active = ContextVar('active')\n"
    + "from unrelated import *\n",
    "import contextvars\n"
    + "active = contextvars.ContextVar('active')\n"
    + "change_unknown_registry()\n",
    "import contextvars\n"
    + "active = contextvars.ContextVar('active')\n"
    + "items = [f(x) for x in (1, 2)]\n",
    "from contextvars import ContextVar\n"
    + "active = ContextVar('active')\n"
    + "def mutate():\n"
    + "    return getattr(active, '__dict__')\n",
    "from contextvars import ContextVar\n"
    + "active = ContextVar('active')\n",
]


@pytest.mark.parametrize("preamble", _PREAMBLES)
@pytest.mark.parametrize("hardcoded", [False, True])
def test_migrated_module_identity_cases_depend_on_source_values(
    tmp_path, preamble, hardcoded,
):
    source = preamble + _SCOPE
    if hardcoded:
        source += '\npassword = "literal-in-source"\n'
    root = tmp_path / "project"
    root.mkdir()
    gateway = Gateway(root, allow_write=True)
    try:
        if hardcoded:
            with pytest.raises(GatewayError) as error:
                gateway.create_file("sample.py", source, dry_run=False)
            assert error.value.code == "sensitive_content"
            assert not (root / "sample.py").exists()
        else:
            applied = gateway.create_file("sample.py", source, dry_run=False)
            assert applied["applied"] is True

        if hardcoded:
            (root / "sample.py").write_bytes(source.encode("utf-8"))
        read = gateway.read_file("sample.py")
        if hardcoded:
            assert read["redacted_lines"] >= 1
            assert "literal-in-source" not in read["content"]
            assert gateway.search_files("literal-in-source")["matches"] == []
        else:
            assert read["redacted_lines"] == 0
        assert "token = active.set(value)" in read["content"]
        assert gateway.search_files("token = active.set(value)")["matches"]
    finally:
        gateway.close()


@pytest.mark.parametrize("expr", [
    "value + 1",
    "value[0]",
    "value.render()",
    "value or 17",
    "next(value)",
])
def test_dynamic_contextvar_set_arguments_are_not_secrets(tmp_path, expr):
    source = (
        "def scope(active, value):\n"
        f"    token = active.set({expr})\n"
        "    try:\n"
        "        yield\n"
        "    finally:\n"
        "        active.reset(token)\n"
    )
    root = tmp_path / "project"
    root.mkdir()
    gateway = Gateway(root, allow_write=True)
    try:
        assert gateway.create_file("sample.py", source, dry_run=False)["applied"]
        read = gateway.read_file("sample.py")
        assert read["redacted_lines"] == 0
        assert "token = active.set" in read["content"]
    finally:
        gateway.close()


@pytest.mark.parametrize("bom", ["", "\ufeff"])
@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_known_contextmanager_source_remains_visible(tmp_path, bom, newline):
    source = (
        "from contextlib import contextmanager\n"
        "from contextvars import ContextVar\n"
        "active = ContextVar('active', default=None)\n"
        "@contextmanager\n"
        + _SCOPE
    )
    source = bom + source.replace("\n", newline)
    root = tmp_path / "project"
    root.mkdir()
    gateway = Gateway(root, allow_write=True)
    try:
        assert gateway.create_file("sample.py", source, dry_run=False)["applied"]
        read = gateway.read_file("sample.py")
        assert read["redacted_lines"] == 0
        assert "token = active.set(value)" in read["content"]
    finally:
        gateway.close()
