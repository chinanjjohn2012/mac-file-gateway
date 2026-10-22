"""Security regression contracts for independent PR #52 Review #5614007389.

These use real Gateway file writes and reads, not only a standalone AST probe.
Workspace source code is parsed but never imported or executed.
"""
from __future__ import annotations

import pytest

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
    "    def set(self, value): return value\n"
    "    def reset(self, token): pass\n"
)


@pytest.mark.parametrize("header", [
    # P2-01: direct module member Store and Del bypassed Name(Store).
    "import contextvars\n" + _FAKE
    + "contextvars.ContextVar = FakeVar\n"
    + "active = contextvars.ContextVar()\n",
    "import contextvars as ctx\n" + _FAKE
    + "ctx.ContextVar = FakeVar\n"
    + "active = ctx.ContextVar()\n",
    "import contextvars as ctx\n"
    + "active = ctx.ContextVar('active')\n"
    + "del ctx.ContextVar\n",
    "import contextvars as ctx\n" + _FAKE
    + "ctx.ContextVar: type = FakeVar\n"
    + "active = ctx.ContextVar()\n",
    # Importing a direct constructor after member rebinding is also unproven.
    "import contextvars\n" + _FAKE
    + "contextvars.ContextVar = FakeVar\n"
    + "from contextvars import ContextVar\n"
    + "active = ContextVar()\n",
])
def test_review_p2_01_constructor_member_rebinding_denied(tmp_path, header):
    _assert_fails_closed(tmp_path, header + _SCOPE)


@pytest.mark.parametrize("header", [
    # P2-02: module pattern/handler bindings do not become Name(Store).
    "from contextvars import ContextVar\n" + _FAKE
    + "active = ContextVar('active')\n"
    + "vault = FakeVar()\n"
    + "match {'obj': vault}:\n"
    + "    case {'obj': active}: pass\n",
    "from contextvars import ContextVar\n" + _FAKE
    + "active = ContextVar('active')\n"
    + "vault = FakeVar()\n"
    + "match [vault]:\n"
    + "    case [*active]: pass\n",
    "from contextvars import ContextVar\n" + _FAKE
    + "active = ContextVar('active')\n"
    + "match {'obj': FakeVar()}:\n"
    + "    case {'obj': _, **active}: pass\n",
    "from contextvars import ContextVar\n"
    + "active = ContextVar('active')\n"
    + "try:\n"
    + "    raise Exception('replacement')\n"
    + "except Exception as active:\n"
    + "    pass\n",
    # Pattern also can replace a supposedly stable constructor itself.
    "from contextvars import ContextVar\n" + _FAKE
    + "match {'c': FakeVar}:\n"
    + "    case {'c': ContextVar}: pass\n"
    + "active = ContextVar()\n",
    # ExceptHandler.name can replace a source module alias as well.
    "import contextvars as ctx\n"
    + "try:\n"
    + "    raise Exception('binding')\n"
    + "except Exception as ctx:\n"
    + "    pass\n"
    + "active = ctx.ContextVar('active')\n",
])
def test_review_p2_02_implicit_module_binding_denied(tmp_path, header):
    _assert_fails_closed(tmp_path, header + _SCOPE)


@pytest.mark.parametrize("function_body", [
    # Pattern captures can shadow the proven global ContextVar locally.
    "    match {'obj': 7}:\n"
    "        case {'obj': active}: pass\n",
    "    match [7]:\n"
    "        case [*active]: pass\n",
    "    match {'obj': 7}:\n"
    "        case {'obj': _, **active}: pass\n",
    "    try:\n"
    "        raise Exception('shadow')\n"
    "    except Exception as active:\n"
    "        pass\n",
])
def test_review_p2_02_implicit_function_binding_denied(tmp_path, function_body):
    source = (
        "from contextvars import ContextVar\n"
        "active = ContextVar('active')\n"
        "def scope(value):\n"
        + function_body
        + "    token = active.set(value)\n"
          "    try:\n"
          "        pass\n"
          "    finally:\n"
          "        active.reset(token)\n"
    )
    _assert_fails_closed(tmp_path, source)


@pytest.mark.parametrize("extra", [
    "        match {'obj': 7}:\n"
    "            case {'obj': token}: pass\n",
    "        match [7]:\n"
    "            case [*token]: pass\n",
    "        try:\n"
    "            raise Exception('shadow')\n"
    "        except Exception as token:\n"
    "            pass\n",
])
def test_review_p2_02_reset_handle_implicitly_rebound_denied(tmp_path, extra):
    source = (
        "from contextvars import ContextVar\n"
        "active = ContextVar('active')\n"
        "def scope(value):\n"
        "    token = active.set(value)\n"
        "    try:\n"
        + extra
        + "    finally:\n"
          "        active.reset(token)\n"
    )
    _assert_fails_closed(tmp_path, source)


@pytest.mark.parametrize("source", [
    # Positive controls: no unnecessary regression for direct and module imports.
    "from contextvars import ContextVar\n"
    "active = ContextVar('active')\n" + _SCOPE,
    "from contextvars import ContextVar as CV\n"
    "active = CV('active')\n" + _SCOPE,
    "import contextvars\n"
    "active = contextvars.ContextVar('active')\n" + _SCOPE,
    "import contextvars as ctx\n"
    "active = ctx.ContextVar('active')\n" + _SCOPE,
])
def test_review_normal_contextvar_still_allowed(tmp_path, source):
    root = tmp_path / "project"
    root.mkdir()
    gateway = Gateway(root, allow_write=True)
    try:
        written = gateway.create_file("good.py", source, dry_run=False)
        assert written["applied"] is True
        read = gateway.read_file("good.py")
        assert read["redacted_lines"] == 0
        assert "token = active.set(value)" in read["content"]
        assert gateway.search_files("token = active.set(value)")["matches"]
    finally:
        gateway.close()


def _assert_fails_closed(tmp_path, source):
    root = tmp_path / "project"
    root.mkdir()
    gateway = Gateway(root, allow_write=True)
    try:
        with pytest.raises(GatewayError) as blocked:
            gateway.create_file("blocked.py", source, dry_run=False)
        assert blocked.value.code == "sensitive_content"
        assert not (root / "blocked.py").exists()

        # Even an existing on-disk file must not reveal the handle line through
        # read_file or search_files, regardless of the write admission result.
        (root / "existing.py").write_text(source, encoding="utf-8")
        read = gateway.read_file("existing.py")
        assert read["redacted_lines"] >= 1
        assert "token = active.set(value)" not in read["content"]
        matches = gateway.search_files("token = active.set(value)", file_glob="existing.py")
        assert matches["matches"] == []
    finally:
        gateway.close()
