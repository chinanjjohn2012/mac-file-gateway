"""R010 six exact product recipe + real disposable finite filesystem T0."""
from dataclasses import replace
import os
import socket
import subprocess

import pytest

from gateway.lbe_worker import LbeWorkPlan
from gateway.lbe_r010_finite_integrity import (
    observe_selected_source_files, observe_go_output_absent,
)
from gateway.lbe_r010_row_fs import (
    R010RowFiniteDenied, observe_r010_private_tree,
    validate_r010_fixed_row_plan, verify_r010_finite_row_after,
)


@pytest.fixture(autouse=True)
def no_product_launch(monkeypatch):
    def forbidden(*_a, **_kw):
        raise AssertionError("SAFE T0 forbids real process or network")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "kill", forbidden)
    monkeypatch.setattr(os, "killpg", forbidden, raising=False)
    monkeypatch.setattr(socket.socket, "connect", forbidden)


def plan(row):
    table = (
        ("py-direct", "direct", ("python", "-m", "pytest", "-q"), None),
        ("py-direct", "direct",
         ("python", "-m", "compileall", "-q", "./src"), None),
        ("py-pipenv", "pipenv", ("python", "-m", "pytest", "-q"), None),
        ("go-project", "direct", ("go", "test", "./..."), None),
        ("go-project", "direct", ("go", "vet", "./..."), None),
        ("go-project", "direct", ("go", "build", "-o", "bin/app", "./cmd/app"),
         "go-project/bin/app"),
    )
    workspace, runner, requested, output = table[row - 1]
    effective = (("pipenv", "run", *requested) if runner == "pipenv"
                 else requested)
    return LbeWorkPlan(
        workspace=workspace, cwd=workspace, runner=runner,
        runner_project=workspace, timeout_seconds=120,
        requested_argv=requested, effective_argv=effective,
        planned_go_output=output,
        planned_pipfile_sha256=("f" * 64 if row == 3 else None))


@pytest.fixture
def fixture_root(tmp_path):
    selected = tmp_path / "selected"
    selected.mkdir(mode=0o700)
    (selected / "main.py").write_text("value = 1\n")
    # R003 requires a pinned existing go-project/bin before build.
    (selected / "bin").mkdir(mode=0o700)
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    # R003: the private src parent exists BEFORE compileall starts.
    # Only __pycache__/pyc may appear as the legal row-2 delta.
    (private / "src").mkdir(mode=0o700)
    srcfd = os.open(selected, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    cachefd = os.open(private, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        before_source = observe_selected_source_files(
            root_fd=srcfd, relative_paths=("main.py",))
        before_tree = observe_r010_private_tree(root_fd=cachefd)
        yield selected, private, srcfd, cachefd, before_source, before_tree
    finally:
        os.close(srcfd)
        os.close(cachefd)


def verify(row, fixture, **extra):
    _, _, sfd, pfd, source, tree = fixture
    return verify_r010_finite_row_after(
        row=row, plan=plan(row), selected_root_fd=sfd,
        selected_before=source, private_root_fd=pfd,
        private_before=tree, **extra)


@pytest.mark.parametrize("row", [1, 2, 3, 4, 5, 6])
def test_six_exact_command_plans_are_reviewed_but_not_exec(row):
    validate_r010_fixed_row_plan(row, plan(row))


@pytest.mark.parametrize("row", [0, 7, -1, True, "1"])
def test_other_row_ids_denied(row):
    with pytest.raises(R010RowFiniteDenied):
        validate_r010_fixed_row_plan(row, plan(1))


@pytest.mark.parametrize("field,value", [
    ("requested_argv", ("python", "-m", "pytest", "-x")),
    ("effective_argv", ("python", "-m", "pytest", "-x")),
    ("workspace", ""), ("cwd", "py-pipenv"),
    ("runner_project", "other"),
    ("runner", "pipenv"), ("timeout_seconds", 121),
    ("planned_go_output", "py-direct/bin/app"),
])
def test_unreviewed_recipe_denied(field, value):
    with pytest.raises(R010RowFiniteDenied):
        validate_r010_fixed_row_plan(1, replace(plan(1), **{field: value}))


def test_pipenv_uses_exact_effective_prefix_and_pipfile_sha():
    good = plan(3)
    validate_r010_fixed_row_plan(3, good)
    with pytest.raises(R010RowFiniteDenied):
        validate_r010_fixed_row_plan(
            3, replace(good, planned_pipfile_sha256=None))
    with pytest.raises(R010RowFiniteDenied):
        validate_r010_fixed_row_plan(
            3, replace(good, effective_argv=good.requested_argv))


def test_go_build_requires_exact_new_bin_app_output():
    validate_r010_fixed_row_plan(6, plan(6))
    with pytest.raises(R010RowFiniteDenied):
        validate_r010_fixed_row_plan(
            6, replace(plan(6), planned_go_output=None))


def test_pytest_private_cache_delta_and_no_source_drift(fixture_root):
    _, private, *_ = fixture_root
    (private / "pytest-cache").mkdir()
    sub = private / "pytest-cache" / "v" / "cache"
    sub.mkdir(parents=True)
    (sub / "nodeids").write_text('["test_x"]')
    result = verify(1, fixture_root)
    assert "pytest-cache/v/cache/nodeids" in result.changed_private_paths
    assert result.selected_source_stable is True
    assert result.finite_private_delta_valid is True
    assert result.native_launch_allowed is False
    assert result.row_positive_success is False
    assert result.transient_mutation_absence_proven is False
    assert result.unobserved_host_side_effects_proven_absent is False


def test_private_delta_in_unreviewed_root_denied(fixture_root):
    _, private, *_ = fixture_root
    (private / "outside-root").write_bytes(b"unexpected")
    with pytest.raises(R010RowFiniteDenied, match="unreviewed"):
        verify(1, fixture_root)


def test_source_mutation_even_if_cache_is_allowed_denied(fixture_root):
    selected, private, *_ = fixture_root
    (private / "python-cache").mkdir()
    (selected / "main.py").write_text("value = 2\n")
    with pytest.raises(R010RowFiniteDenied):
        verify(1, fixture_root)


def test_symlink_in_private_cache_is_denied(fixture_root):
    _, private, *_ = fixture_root
    cache = private / "pytest-cache"
    cache.mkdir()
    (cache / "escape").symlink_to("/etc/passwd")
    with pytest.raises(R010RowFiniteDenied):
        verify(1, fixture_root)


def test_hardlink_or_world_writable_private_cache_denied(fixture_root):
    _, private, *_ = fixture_root
    cache = private / "pytest-cache"
    cache.mkdir()
    item = cache / "bytes"
    item.write_bytes(b"x")
    os.link(item, cache / "alias")
    with pytest.raises(R010RowFiniteDenied):
        verify(1, fixture_root)
    (cache / "alias").unlink()
    item.chmod(0o666)
    with pytest.raises(R010RowFiniteDenied):
        verify(1, fixture_root)


def test_python_cache_rejects_unreviewed_loader_sources(fixture_root):
    _, private, *_ = fixture_root
    cache = private / "pytest-cache"
    cache.mkdir()
    (cache / "startup.pth").write_text("import os")
    with pytest.raises(R010RowFiniteDenied, match="unreviewed"):
        verify(3, fixture_root)


def test_compileall_exact_src_pycache_is_allowed(fixture_root):
    _, private, *_ = fixture_root
    d = private / "src" / "__pycache__"
    d.mkdir(parents=True)
    (d / "main.cpython-313.pyc").write_bytes(b"synthetic pyc")
    result = verify(2, fixture_root)
    assert "src/__pycache__/main.cpython-313.pyc" in result.changed_private_paths


def test_compileall_non_pyc_delta_is_denied(fixture_root):
    _, private, *_ = fixture_root
    d = private / "src" / "__pycache__"
    d.mkdir(parents=True)
    (d / "unexpected.so").write_bytes(b"not a safe pyc")
    with pytest.raises(R010RowFiniteDenied):
        verify(2, fixture_root)


def test_go_cache_delta_allowed_for_go_test_only(fixture_root):
    _, private, *_ = fixture_root
    cache = private / "go-cache"
    cache.mkdir()
    (cache / "hash-entry").write_bytes(b"archive")
    result = verify(4, fixture_root)
    assert "go-cache/hash-entry" in result.changed_private_paths
    with pytest.raises(R010RowFiniteDenied):
        verify(1, fixture_root)


def test_build_requires_preabsent_and_exact_new_artifact(fixture_root, tmp_path):
    selected, private, *_ = fixture_root
    binparent = selected / "bin"
    # Preexisting pinned workspace output parent (created by fixture_root).
    fd = os.open(binparent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        prior = observe_go_output_absent(parent_fd=fd)
        (binparent / "app").write_bytes(b"synthetic executable")
        (binparent / "app").chmod(0o700)
        receipt = verify(
            6, fixture_root,
            go_output_parent_fd=fd, go_output_before=prior)
        assert len(receipt.go_build_artifact_sha256) == 64
        assert receipt.six_command_product_t1_pass is False
    finally:
        os.close(fd)


def test_build_missing_or_unsafe_artifact_denied(fixture_root, tmp_path):
    selected, private, *_ = fixture_root
    root = selected / "bin"
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        prior = observe_go_output_absent(parent_fd=fd)
        with pytest.raises(R010RowFiniteDenied):
            verify(6, fixture_root, go_output_parent_fd=fd,
                   go_output_before=prior)
        (root / "app").write_bytes(b"old")
        (root / "app").chmod(0o666)
        with pytest.raises(R010RowFiniteDenied):
            verify(6, fixture_root, go_output_parent_fd=fd,
                   go_output_before=prior)
    finally:
        os.close(fd)


def test_go_row_1_5_reject_out_of_sequence_build_artifact(fixture_root, tmp_path):
    root = tmp_path / "bin"
    root.mkdir(mode=0o700)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        prior = observe_go_output_absent(parent_fd=fd)
        with pytest.raises(R010RowFiniteDenied):
            verify(5, fixture_root, go_output_parent_fd=fd,
                   go_output_before=prior)
    finally:
        os.close(fd)


def test_private_root_identity_and_mode_drift_denied(fixture_root):
    _, private, _, pfd, *_ = fixture_root
    private.chmod(0o777)
    with pytest.raises(R010RowFiniteDenied):
        verify(1, fixture_root)


def test_transient_created_then_deleted_not_claimed_absent(fixture_root):
    _, private, *_ = fixture_root
    transient = private / "transient"
    transient.write_bytes(b"short lived")
    transient.unlink()
    obs = verify(1, fixture_root)
    assert obs.changed_private_paths == ()
    assert obs.unobserved_host_side_effects_proven_absent is False
    assert obs.transient_mutation_absence_proven is False


def test_preexisting_private_src_permission_drift_denied(fixture_root):
    _, private, *_ = fixture_root
    (private / "src").chmod(0o755)
    # Mode remains owner-safe but violates pre/post directory identity.
    with pytest.raises(R010RowFiniteDenied, match="unreviewed"):
        verify(2, fixture_root)


def test_go_output_parent_is_not_an_alternate_external_directory(
        fixture_root, tmp_path):
    other = tmp_path / "other-bin"
    other.mkdir(mode=0o700)
    fd = os.open(other, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        before = observe_go_output_absent(parent_fd=fd)
        (other / "app").write_bytes(b"untrusted alternate output")
        (other / "app").chmod(0o700)
        with pytest.raises(R010RowFiniteDenied, match="selected bin"):
            verify(6, fixture_root, go_output_parent_fd=fd,
                   go_output_before=before)
    finally:
        os.close(fd)


def test_go_bin_parent_replacement_does_not_borrow_old_fd(
        fixture_root, tmp_path):
    selected, _, *_ = fixture_root
    root = selected / "bin"
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        before = observe_go_output_absent(parent_fd=fd)
        root.rename(selected / "old-bin")
        root.mkdir(mode=0o700)
        (selected / "old-bin" / "app").write_bytes(b"old inode")
        (selected / "old-bin" / "app").chmod(0o700)
        with pytest.raises(R010RowFiniteDenied, match="selected bin"):
            verify(6, fixture_root, go_output_parent_fd=fd,
                   go_output_before=before)
    finally:
        os.close(fd)


def test_lbe_r003_fixed_command_matrix_has_not_drifted():
    from gateway.lbe_product_fixture import _MATRIX
    from gateway.lbe_r010_row_fs import _ROWS

    assert len(_MATRIX) == len(_ROWS) == 6
    for row, (workspace, runner, requested, effective) in enumerate(_MATRIX, 1):
        assert _ROWS[row - 1][0] == workspace
        assert _ROWS[row - 1][1] == runner
        assert _ROWS[row - 1][2] == requested
        assert effective == plan(row).effective_argv
