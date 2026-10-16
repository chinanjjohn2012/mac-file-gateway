"""F1: object identity, not a full pathname-prefix chain, defines overlap."""
from pathlib import Path
import sys
import tempfile

import pytest

from gateway import workspaces
from gateway.private_fs import PinnedDirectory, PrivateFileError, open_pinned_directory
from gateway.workspaces import ActiveRuntimeInventory, WorkspaceService, _intersects
from gateway.workspaces_config import parse_workspace_config


def pin(*ids):
    return PinnedDirectory(-1, tuple((1, value) for value in ids))


@pytest.mark.parametrize('left,right', [
    (pin(1, 2, 9), pin(1, 3, 4, 9)),
    (pin(1, 2, 9), pin(1, 3, 4, 9, 10)),
    (pin(1, 3, 4, 9, 10), pin(1, 2, 9)),
])
def test_different_ancestor_routes_to_same_or_nested_object_overlap(left, right):
    assert _intersects(left, right)
    assert _intersects(right, left)


@pytest.mark.parametrize('left,right', [
    (pin(1, 2, 9), pin(1, 2, 10)),
    (pin(1, 2, 9), pin(1, 3, 10)),
])
def test_shared_ancestor_does_not_make_sibling_roots_overlap(left, right):
    assert not _intersects(left, right)
    assert not _intersects(right, left)


@pytest.mark.parametrize('left,right', [(pin(), pin(1, 2)), (pin(1, 2), pin())])
def test_missing_identity_evidence_fails_closed(left, right):
    with pytest.raises(PrivateFileError):
        _intersects(left, right)


def settings(*roots):
    return parse_workspace_config({
        'schema_version': 1,
        'workspaces': {f'w{i}': {'root': str(root)} for i, root in enumerate(roots)},
    })


def data_alias(path):
    """Verify the platform facility instead of assuming a path is an alias."""
    path = Path(path)
    alias = Path('/System/Volumes/Data') / path.relative_to('/')
    try:
        if (path.stat().st_dev, path.stat().st_ino) != (alias.stat().st_dev, alias.stat().st_ino):
            pytest.skip('Data-volume alias does not name the same filesystem object')
    except OSError:
        pytest.skip('Data-volume alias is not available on this filesystem')
    return alias


@pytest.fixture
def darwin_tree():
    if sys.platform != 'darwin':
        pytest.skip('Native Darwin firmlink acceptance requires macOS')
    # /Users is a standard firmlink target. Do not use symlinked /var paths.
    with tempfile.TemporaryDirectory(prefix='mfg-f1-', dir=Path.home()) as raw:
        root = Path(raw).resolve()
        data_alias(root)
        for name in ('a', 'b', 'config', 'runtime'):
            (root / name).mkdir()
        yield root


@pytest.mark.parametrize('kind', ['same', 'child', 'parent', 'config', 'runtime'])
def test_native_firmlink_overlap_is_rejected_before_gateway_construction(darwin_tree, kind):
    root = darwin_tree
    a, config, runtime = root / 'a', root / 'config', root / 'runtime'
    constructed = []

    def forbidden_factory(*args, **kwargs):
        constructed.append(args)
        raise AssertionError('Unsafe aliases reached Gateway construction')

    roots = [a, data_alias(a)]
    if kind in {'child', 'parent'}:
        child = a / 'child'
        child.mkdir()
        roots = [a, data_alias(child)] if kind == 'child' else [data_alias(child), a]
    elif kind == 'config':
        roots = [data_alias(config)]
    elif kind == 'runtime':
        roots = [data_alias(runtime)]
    with pytest.raises(PrivateFileError):
        WorkspaceService(settings(*roots), config_dir=config,
                         inventory=ActiveRuntimeInventory(paths=(runtime,)),
                         gateway_factory=forbidden_factory)
    assert constructed == []


def test_native_default_inventory_rejects_active_package_alias(darwin_tree):
    install = Path(workspaces.__file__).resolve().parent.parent
    alias = data_alias(install)
    constructed = []

    def forbidden_factory(*args, **kwargs):
        constructed.append(args)
        raise AssertionError('Active package was admitted as a Workspace')

    with pytest.raises(PrivateFileError):
        WorkspaceService(settings(alias), config_dir=darwin_tree / 'config',
                         gateway_factory=forbidden_factory)
    assert constructed == []


@pytest.mark.parametrize('variant', ['case', 'unicode'])
def test_native_case_or_unicode_alias_identity_stays_protected(darwin_tree, variant):
    name, alternate = ('CaseRoot', 'caseroot') if variant == 'case' else ('caf\u00e9', 'cafe\u0301')
    source = darwin_tree / name
    source.mkdir()
    alias = darwin_tree / alternate
    if not alias.exists() or not source.samefile(alias):
        pytest.skip(f'This volume does not alias the {variant} spelling')
    with pytest.raises(PrivateFileError):
        WorkspaceService(settings(source, alias), config_dir=darwin_tree / 'config',
                         inventory=ActiveRuntimeInventory(paths=(darwin_tree / 'runtime',)))
