"""T16: the disposable Git MCP smoke must tolerate symlinked TMPDIR ancestors.

The test exercises the real Legacy and Multi loopback Git subprocesses with
local temporary repositories. It does not weaken control-plane path checks.
"""
from __future__ import annotations

from pathlib import Path
import tempfile

import pytest

from gateway.private_fs import PrivateFileError, open_pinned_directory


def test_git_smoke_uses_physical_tmpdir_before_starting_real_multi_gateway(
    tmp_path, monkeypatch,
):
    import smoke_git_cli

    actual_tmp = tmp_path / "physical-tmp"
    actual_tmp.mkdir()
    actual_tmp = actual_tmp.resolve(strict=True)
    alias = tmp_path / "symlinked-tmp"
    alias.symlink_to(actual_tmp, target_is_directory=True)

    # Simulate macOS TMPDIR /var/... pointing to /private/var/...
    # without changing any real OS environment or Gateway policy.
    monkeypatch.setattr(tempfile, "tempdir", str(alias))
    with tempfile.TemporaryDirectory(prefix="symlink-tmp-probe-") as original:
        assert Path(original) != Path(original).resolve(strict=True)

    observed = []
    real_mode = smoke_git_cli.assert_http_git_mode

    def checked_mode(root: Path, *, multi: bool) -> None:
        # This assertion MUST fail with the old smoke fixture and pass
        # after it resolves the temporary root before creating config.
        assert root == root.resolve(strict=True), root
        assert root.is_relative_to(actual_tmp), root
        observed.append(multi)
        real_mode(root, multi=multi)

    monkeypatch.setattr(smoke_git_cli, "assert_http_git_mode", checked_mode)
    smoke_git_cli.main()
    assert observed == [False, True]


def test_private_control_directory_still_rejects_symlinked_ancestor(tmp_path):
    real = tmp_path / "control-parent"
    real.mkdir()
    control = real / "private-control"
    control.mkdir()
    alias = tmp_path / "control-alias"
    alias.symlink_to(real, target_is_directory=True)

    with pytest.raises(PrivateFileError, match="unavailable or unsafe"):
        open_pinned_directory(alias / "private-control", private_leaf=True)
    physically_pinned = open_pinned_directory(
        control.resolve(strict=True), private_leaf=True,
    )
    physically_pinned.close()
