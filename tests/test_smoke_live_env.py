"""Regression: the independent REST smoke must not inherit server authentication.

The smoke probe sends no Authorization header by design, even when the current
Terminal runs another Gateway with GATEWAY_TOKEN set.
"""
from pathlib import Path
import importlib.util
import os
import sys

import pytest

_SMOKE_PATH = Path(__file__).resolve().parent / "smoke_live.py"
_SPEC = importlib.util.spec_from_file_location("gateway_smoke_live_isolated", _SMOKE_PATH)
assert _SPEC is not None and _SPEC.loader is not None
smoke = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = smoke
_SPEC.loader.exec_module(smoke)


def test_smoke_environment_strips_only_gateway_token(monkeypatch):
    monkeypatch.setenv("GATEWAY_TOKEN", "inherited-test-token")
    monkeypatch.setenv("GATEWAY_SMOKE_MARKER", "should-survive")
    env = smoke.smoke_environment()

    assert "GATEWAY_TOKEN" not in env
    assert env["GATEWAY_SMOKE_MARKER"] == "should-survive"
    assert os.environ["GATEWAY_TOKEN"] == "inherited-test-token"
    assert env is not os.environ


def test_smoke_main_passes_sanitized_env_to_subprocess(monkeypatch):
    monkeypatch.setenv("GATEWAY_TOKEN", "inherited-test-token")
    captured = {}

    class ExitedChild:
        def __init__(self, *args, **kwargs):
            captured.update(kwargs)

        def poll(self):
            return 1

        def communicate(self, timeout=None):
            return "", "fake child exited"

    monkeypatch.setattr(smoke.subprocess, "Popen", ExitedChild)
    with pytest.raises(RuntimeError, match="Gateway process exited: fake child exited"):
        smoke.main()
    assert "GATEWAY_TOKEN" not in captured["env"]
    assert "PATH" in captured["env"]
