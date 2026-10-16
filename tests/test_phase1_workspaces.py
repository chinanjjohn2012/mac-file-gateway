from pathlib import Path
import pytest
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from gateway.private_fs import PrivateFileError
from gateway.workspaces_config import parse_workspace_config
from gateway.workspaces import WorkspaceService, ActiveRuntimeInventory
from gateway.core import GatewayError


def make_tree(tmp_path):
    parent=tmp_path/'projects'; parent.mkdir()
    a=parent/'a'; b=parent/'b'
    a.mkdir(); b.mkdir()
    config=tmp_path/'config'; config.mkdir(mode=0o700); config.chmod(0o700)
    runtime=tmp_path/'runtime'; runtime.mkdir()
    return a,b,config,runtime


def settings(a,b, a_write=True):
    return parse_workspace_config({'schema_version':1, 'workspaces':{
        'a':{'root':str(a),'write':{'enabled':a_write,'paths':['.'] if a_write else []}},
        'b':{'root':str(b),'write':{'enabled':False}},
    }})


def test_isolated_routing_and_permissions(tmp_path):
    a,b,config,runtime=make_tree(tmp_path)
    inventory=ActiveRuntimeInventory(paths=(runtime,))
    service=WorkspaceService(settings(a,b),config_dir=config,inventory=inventory)
    try:
        assert service.invoke('a','list_files','.')['workspace']=='a'
        assert service.invoke('b','list_files','.')['workspace']=='b'
        assert service.invoke('a','create_file','x.py','abc')['workspace']=='a'
        with pytest.raises(GatewayError) as exc:
            service.invoke('b','create_file','x.py','abc')
        assert exc.value.code=='write_disabled'
        with pytest.raises(GatewayError) as exc:
            service.invoke('other','list_files','.')
        assert exc.value.code=='workspace_not_found'
        with pytest.raises(GatewayError) as exc:
            service.invoke('', 'list_files','.')
        assert exc.value.code=='workspace_required'
        assert service.info()['workspace_count']==2
        assert all('root' not in entry for entry in service.list_workspaces()['workspaces'])
        with pytest.raises(GatewayError):
            service.invoke('a','run_command','.',['go','test'])
    finally:
        service.close()


def test_overlapping_root_denied(tmp_path):
    a,b,config,runtime=make_tree(tmp_path)
    nested=a/'nested'; nested.mkdir()
    s=settings(a,nested)
    with pytest.raises(PrivateFileError):
        WorkspaceService(s,config_dir=config,inventory=ActiveRuntimeInventory(paths=(runtime,)))


def test_runtime_root_ancestor_intersection_denied(tmp_path):
    a,b,config,runtime=make_tree(tmp_path)
    nested=a/'active-install'; nested.mkdir()
    with pytest.raises(PrivateFileError):
        WorkspaceService(settings(a,b),config_dir=config,inventory=ActiveRuntimeInventory(paths=(nested,)))
    # Runtime cannot be a parent of a Workspace either.
    with pytest.raises(PrivateFileError):
        WorkspaceService(settings(a,b),config_dir=config,inventory=ActiveRuntimeInventory(paths=(a.parent,)))


def test_config_root_intersection_denied(tmp_path):
    a,b,config,runtime=make_tree(tmp_path)
    child=config/'workspace'; child.mkdir()
    with pytest.raises(PrivateFileError):
        WorkspaceService(settings(child,b),config_dir=config,inventory=ActiveRuntimeInventory(paths=(runtime,)))


def test_symlink_workspace_root_denied(tmp_path):
    a,b,config,runtime=make_tree(tmp_path)
    link = a.parent/'alias'; link.symlink_to(a)
    with pytest.raises(PrivateFileError):
        WorkspaceService(settings(link,b),config_dir=config,inventory=ActiveRuntimeInventory(paths=(runtime,)))


def test_pinned_root_identity(tmp_path):
    a,b,config,runtime=make_tree(tmp_path)
    svc=WorkspaceService(settings(a,b),config_dir=config,inventory=ActiveRuntimeInventory(paths=(runtime,)))
    try:
        old = a.with_name('original-a'); a.rename(old)
        a.mkdir()
        assert svc.get('a').pinned_root.ancestor_ids[-1] != (a.stat().st_dev,a.stat().st_ino)
    finally:
        svc.close()


def test_phase1_start_accepts_world_writable_workspace_root(tmp_path):
    a,b,config,runtime=make_tree(tmp_path)
    a.parent.chmod(0o777)
    a.chmod(0o777)
    config.chmod(0o777)
    svc=WorkspaceService(settings(a,b),config_dir=config,
                         inventory=ActiveRuntimeInventory(paths=(runtime,)))
    try:
        assert svc.info()['workspace_count']==2
        assert svc.get('a').pinned_root.ancestor_ids[-1]==(a.stat().st_dev,a.stat().st_ino)
        assert svc.get('a').settings.allow_write is True
        assert svc.get('b').settings.allow_write is False
    finally:
        svc.close()
