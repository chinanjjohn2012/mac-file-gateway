"""REDUCED contract-only reconstruction; NOT a byte-identical GitHub module run.
No real FS, process, network, Git, SDK, Native, or OS signal operations.
"""
from dataclasses import asdict, dataclass, replace
import hashlib
import json
import re
import unittest


def canonical(a):
    return json.dumps(a, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)


def scope(path):
    return (type(path) is str and bool(path) and len(path.encode('utf-8')) <= 2048
            and not path.startswith(('/', '~')) and ':' not in path and '\\' not in path
            and all(ord(c) >= 32 and ord(c) != 127 for c in path)
            and not any(c in '*?[]' for c in path)
            and (path == '.' or all(p and p not in ('.', '..') for p in path.split('/'))))


def inside(path, grant):
    return grant == '.' or path == grant or path.startswith(grant + '/')


@dataclass(frozen=True)
class ReducedBinding:
    workspace_exec_paths: tuple[str, ...]
    workspace_exec_runners: tuple[str, ...]
    runner_cwd: str
    runner_id: str
    runner_project: str
    backend_config_sha256: str = 'a'*64

    def __post_init__(self):
        paths = self.workspace_exec_paths
        if (type(paths) is not tuple or not 1 <= len(paths) <= 32
            or any(not scope(p) for p in paths)
            or len(set(paths)) != len(paths)):
            raise ValueError('invalid_workspace_exec_paths')
        maps = self.workspace_exec_runners
        if (type(maps) is not tuple or len(maps) > 32
            or any(type(item) is not str for item in maps)
            or len(set(maps)) != len(maps)):
            raise ValueError('invalid_workspace_exec_runners')
        configured = {}
        for item in maps:
            if item.count('=') != 1:
                raise ValueError('invalid_workspace_exec_runner_mapping')
            p, mode = item.split('=', 1)
            if (not scope(p) or mode not in ('direct', 'pipenv')
                or not any(inside(p, grant) for grant in paths)):
                raise ValueError('invalid_workspace_exec_runner_mapping')
            configured[p] = mode
        if (not scope(self.runner_cwd) or not scope(self.runner_project)
            or not any(inside(self.runner_cwd, grant) for grant in paths)
            or self.runner_id not in ('direct', 'pipenv')):
            raise ValueError('invalid_effective_runner_identity')
        def depth(p):
            return 0 if p == '.' else p.count('/') + 1
        matches = [(p, mode) for p, mode in configured.items() if inside(self.runner_cwd, p)]
        if matches:
            best = max(matches, key=lambda x: depth(x[0]))
            if (self.runner_project, self.runner_id) != best:
                raise ValueError('configured_runner_precedence_mismatch')
        else:
            containing = max((p for p in paths if inside(self.runner_cwd, p)), key=depth)
            if self.runner_id == 'direct':
                if self.runner_project != containing:
                    raise ValueError('fallback_direct_scope_mismatch')
            elif not (inside(self.runner_cwd, self.runner_project)
                      and inside(self.runner_project, containing)):
                raise ValueError('fallback_pipenv_project_mismatch')

    def encoded_binding(self):
        d = asdict(self)
        d['workspace_exec_paths'] = sorted(self.workspace_exec_paths)
        effective = {}
        for item in self.workspace_exec_runners:
            p, mode = item.split('=', 1)
            effective[p] = mode
        d['workspace_exec_runners'] = [f'{p}={effective[p]}' for p in sorted(effective)]
        return canonical(d)

    def digest(self):
        return hashlib.sha256(self.encoded_binding().encode('ascii')).hexdigest()


def binding(**changes):
    values = dict(workspace_exec_paths=('src', 'src/tools'),
                  workspace_exec_runners=('src=direct', 'src/tools=pipenv'),
                  runner_cwd='src/tools/deep', runner_id='pipenv', runner_project='src/tools')
    values.update(changes)
    return ReducedBinding(**values)


class T0(unittest.TestCase):
    def test_01_unordered_paths_valid(self):
        self.assertEqual(binding(workspace_exec_paths=('src/tools','src')).digest(), binding().digest())
    def test_02_unordered_map_valid(self):
        self.assertEqual(binding(workspace_exec_runners=('src/tools=pipenv','src=direct')).digest(), binding().digest())
    def test_03_both_permutations_equal(self):
        b=binding(workspace_exec_paths=('src/tools','src'),workspace_exec_runners=('src/tools=pipenv','src=direct'))
        self.assertEqual(b.encoded_binding(), binding().encoded_binding())
    def test_04_nearest_child_pipenv(self):
        self.assertEqual((binding().runner_id,binding().runner_project),('pipenv','src/tools'))
    def test_05_wrong_parent_claim_fails(self):
        with self.assertRaises(ValueError): binding(runner_id='direct',runner_project='src')
    def test_06_exact_duplicate_scope_fails(self):
        with self.assertRaises(ValueError): binding(workspace_exec_paths=('src','src'))
    def test_07_exact_duplicate_map_fails(self):
        with self.assertRaises(ValueError): binding(workspace_exec_runners=('src=direct','src=direct'))
    def test_08_same_path_last_wins_pipenv(self):
        b=binding(workspace_exec_runners=('src=direct','src/tools=direct','src/tools=pipenv'))
        self.assertEqual(b.runner_id,'pipenv')
        self.assertEqual(b.digest(),binding().digest())
    def test_09_same_path_last_wins_direct(self):
        b=binding(workspace_exec_runners=('src=direct','src/tools=pipenv','src/tools=direct'),runner_id='direct')
        self.assertEqual(b.runner_id,'direct')
        self.assertNotEqual(b.digest(),binding().digest())
    def test_10_root_dot_valid(self):
        b=binding(workspace_exec_paths=('src','.'),workspace_exec_runners=('.=direct',),runner_cwd='src/tools',runner_id='direct',runner_project='.')
        self.assertEqual(b.digest(),binding(workspace_exec_paths=('.','src'),workspace_exec_runners=('.=direct',),runner_cwd='src/tools',runner_id='direct',runner_project='.').digest())
    def test_11_invalid_path(self):
        with self.assertRaises(ValueError): binding(workspace_exec_paths=('src/../unsafe',))
    def test_12_invalid_mode(self):
        with self.assertRaises(ValueError): binding(workspace_exec_runners=('src=shell',))
    def test_13_invalid_outside_map(self):
        with self.assertRaises(ValueError): binding(workspace_exec_runners=('outside=pipenv',))
    def test_14_changed_backend_fences_digest(self):
        self.assertNotEqual(binding().digest(),binding(backend_config_sha256='b'*64).digest())
    def test_15_no_map_nearest_scope_direct(self):
        b=binding(workspace_exec_runners=(),runner_id='direct',runner_project='src/tools')
        self.assertEqual(b.runner_project,'src/tools')
    def test_16_no_map_hypothetical_pipenv(self):
        b=binding(workspace_exec_runners=(),runner_id='pipenv',runner_project='src/tools')
        self.assertEqual(b.runner_project,'src/tools')
    def test_17_dot_scope_order_independent(self):
        b=binding(workspace_exec_paths=('.', 'src'), workspace_exec_runners=(),runner_id='direct',runner_project='src')
        self.assertEqual(b.digest(),binding(workspace_exec_paths=('src','.'),workspace_exec_runners=(),runner_id='direct',runner_project='src').digest())

if __name__ == '__main__':
    unittest.main(verbosity=2)
