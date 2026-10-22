"""Real Gateway RED/GREEN regression for PR #52 independent P2-03.

Source snippets are treated as untrusted file bytes. This test does NOT
import or execute the embedded Python modules in the host test process.
"""
from __future__ import annotations

import pytest

from gateway.contextvar_analysis import proven_lines
from gateway.core import Gateway, GatewayError


_SCOPE = (
    "def scope(value):\n"
    "    token = active.set(value)\n"
    "    try:\n"
    "        pass\n"
    "    finally:\n"
    "        active.reset(token)\n"
)

_FAKE = (
    "class FakeVar:\n"
    "    def set(self, value): return 71\n"
    "    def reset(self, handle): pass\n"
)

_FAKE_MODULE = (
    "from types import ModuleType\n"
    + _FAKE
    + "class FakeModule(ModuleType):\n"
    "    def __getattribute__(self, name):\n"
    "        if name == 'ContextVar': return FakeVar\n"
    "        return ModuleType.__getattribute__(self, name)\n"
)

_CACHE_MODULE = (
    _FAKE
    + "class FakeModule:\n"
    "    def ContextVar(self): return FakeVar()\n"
)


@pytest.mark.parametrize("source", [
    # Review #5614561695: module object changes its lookup behavior.
    "import contextvars\n" + _FAKE_MODULE
    + "contextvars.__class__ = FakeModule\n"
    + "active = contextvars.ContextVar()\n" + _SCOPE,
    "import contextvars as cv\n" + _FAKE_MODULE
    + "cv.__class__ = FakeModule\n"
    + "active = cv.ContextVar()\n" + _SCOPE,
    "import contextvars\n" + _FAKE_MODULE
    + "alias = contextvars\n"
    + "alias.__class__ = FakeModule\n"
    + "active = contextvars.ContextVar()\n" + _SCOPE,
    # Review #5614561695: import graph changes before the trusted import.
    "import sys\n" + _CACHE_MODULE
    + "sys.modules['contextvars'] = FakeModule()\n"
    + "import contextvars\n"
    + "active = contextvars.ContextVar()\n" + _SCOPE,
    "from sys import modules as cache\n" + _CACHE_MODULE
    + "cache['contextvars'] = FakeModule()\n"
    + "from contextvars import ContextVar\n"
    + "active = ContextVar()\n" + _SCOPE,
    "import sys as runtime\n" + _CACHE_MODULE
    + "cache = runtime.modules\n"
    + "cache.update({'contextvars': FakeModule()})\n"
    + "import contextvars\n"
    + "active = contextvars.ContextVar()\n" + _SCOPE,
    "from sys import modules as cache\n"
    + "from types import SimpleNamespace\n"
    + _FAKE
    + "cache['contextvars'] = SimpleNamespace(ContextVar=FakeVar)\n"
    + "from contextvars import ContextVar\n"
    + "active = ContextVar('active')\n" + _SCOPE,
    "import sys\n"
    + "sys.meta_path.insert(0, untrusted_finder)\n"
    + "from contextvars import ContextVar\n"
    + "active = ContextVar('active')\n" + _SCOPE,
    "import builtins\n"
    + "builtins.__import__ = untrusted_import\n"
    + "from contextvars import ContextVar\n"
    + "active = ContextVar('active')\n" + _SCOPE,
    "import sys\n" + _CACHE_MODULE
    + "sys.modules.update({'contextvars': FakeModule()})\n"
    + "from contextvars import ContextVar\n"
    + "active = ContextVar()\n" + _SCOPE,
])
def test_p2_03_untrusted_module_identity_never_exempted(tmp_path, source):
    root = tmp_path / "project"
    root.mkdir()
    gateway = Gateway(root, allow_write=True)
    try:
        # First assert the public Gateway security boundary, so RED directly
        # records a false acceptance rather than stopping at worker output.
        with pytest.raises(GatewayError) as error:
            gateway.create_file("blocked.py", source, dry_run=False)
        assert error.value.code == "sensitive_content"
        assert not (root / "blocked.py").exists()

        # An already present file also must not disclose the same handle line.
        (root / "existing.py").write_bytes(source.encode("utf-8"))
        visible = gateway.read_file("existing.py")
        assert visible["redacted_lines"] >= 1
        assert "token = active.set(value)" not in visible["content"]
        result = gateway.search_files("token = active.set(value)", file_glob="existing.py")
        assert result["matches"] == []
        # The actual isolated, bounded AST worker must agree with Gateway.
        assert proven_lines(source.encode("utf-8")) == ()
    finally:
        gateway.close()


@pytest.mark.parametrize("namespace_import,mutation", [
    ("from contextvars import __dict__ as registry",
     "registry['ContextVar'] = FakeVar"),
    ("from contextvars import __dict__ as aliases",
     "aliases.update({'ContextVar': FakeVar})"),
    ("from contextvars import __dict__",
     "__dict__['ContextVar'] = FakeVar"),
    ("from contextvars import __dict__ as registry",
     "copy = registry\ncopy['ContextVar'] = FakeVar"),
    ("from contextvars import __dict__ as registry",
     "registry |= {'ContextVar': FakeVar}"),
    ("from contextvars import __dict__ as registry\n"
     "from contextvars import ContextVar",
     "registry['ContextVar'] = FakeVar"),
])
def test_p2_03_imported_module_namespace_never_exempted(tmp_path, namespace_import, mutation):
    # Review #5616180244: ImportFrom.alias is not an ast.Attribute.
    # This file is parsed as untrusted bytes, never executed by Gateway.
    source = (
        "import contextvars\n"
        + namespace_import + "\n"
        + _FAKE
        + mutation + "\n"
        + "active = contextvars.ContextVar('active')\n"
        + _SCOPE
    )
    root = tmp_path / "project"
    root.mkdir()
    gateway = Gateway(root, allow_write=True)
    try:
        # RED must demonstrate a failure at the actual Gateway security boundary.
        with pytest.raises(GatewayError) as error:
            gateway.create_file("blocked.py", source, dry_run=False)
        assert error.value.code == "sensitive_content"
        assert not (root / "blocked.py").exists()

        # Existing source must not be visible or searchable.
        (root / "existing.py").write_bytes(source.encode("utf-8"))
        visible = gateway.read_file("existing.py")
        assert visible["redacted_lines"] >= 1
        assert "token = active.set(value)" not in visible["content"]
        matches = gateway.search_files(
            "token = active.set(value)", file_glob="existing.py",
        )
        assert matches["matches"] == []
        assert proven_lines(source.encode("utf-8")) == ()
    finally:
        gateway.close()


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
@pytest.mark.parametrize("bom", ["", "\ufeff"])
@pytest.mark.parametrize("head", [
    "import contextvars\nactive = contextvars.ContextVar('active')\n",
    "from contextvars import ContextVar\nactive = ContextVar('active')\n",
    # Benign sys import/inspection alone should not invalidate provenance.
    "import sys\nruntime_platform = sys.platform\n"
    "import contextvars\nactive = contextvars.ContextVar('active')\n",
])
def test_p2_03_normal_contextvar_file_still_accepted(tmp_path, head, newline, bom):
    raw = (bom + head + _SCOPE).replace("\n", newline)
    root = tmp_path / "project"
    root.mkdir()
    gateway = Gateway(root, allow_write=True)
    try:
        lines = proven_lines(raw.encode("utf-8"))
        assert len(lines) == 1
        response = gateway.create_file("normal.py", raw, dry_run=False)
        assert response["applied"] is True
        read = gateway.read_file("normal.py")
        assert read["redacted_lines"] == 0
        assert "token = active.set(value)" in read["content"]
        assert gateway.search_files("token = active.set(value)")["matches"]
        assert (root / "normal.py").read_bytes() == raw.encode("utf-8")
    finally:
        gateway.close()
