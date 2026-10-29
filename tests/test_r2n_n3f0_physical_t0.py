"""In-memory port ONLY. No OS file, FD, flock, fsync or Native call.

Tests deliberately never instantiate RealFDPort or invoke physical syscalls.
"""
from __future__ import annotations

import json
from pathlib import Path
import stat
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from gateway.r2n_n3f0_physical import (  # noqa: E402
    N3F0PhysicalDenied, N3F0PhysicalSnapshot, N3F0PinnedReadOnlySession,
    RealFDPort, _DIR_FLAGS, _FILE_FLAGS,
)

UID = 1001
ROOT_ID = (7, 1)
EXTERNAL_ID = (7, 2)
CONTROL_ID = (7, 10)
STATE_PARENT_ID = (7, 20)
LINEAGE_PARENT_ID = (7, 21)
STATE_ID = (7, 30)
LINEAGE_ID = (7, 31)
LOCK_ID = (7, 40)
WS_ID = (7, 60)


def st(ino: int, directory: bool = True, mode: int | None = None,
       *, uid: int = UID, dev: int = 7, nlink: int = 1, size: int = 0):
    if mode is None:
        mode = 0o700 if directory else 0o600
    return type("Stat", (), dict(st_dev=dev, st_ino=ino, st_uid=uid,
        st_mode=(stat.S_IFDIR if directory else stat.S_IFREG) | mode,
        st_nlink=nlink, st_size=size))()


def control():
    return dict(schema_id="native-n3-v1", namespace_id="n3_good_fixture",
      lineage_generation=1, owner_generation=2, state_generation=3,
      consent_epoch=0, consent_record_id="inactive", consent_active=False,
      consent_expiry_or_null=None, consent_binding_digest="a"*64,
      owner_lock_dev=LOCK_ID[0], owner_lock_ino=LOCK_ID[1],
      global_quarantined=False, global_quarantine_reason="none",
      max_attempts=4096, max_attempt_bytes=4096,
      max_total_attempt_payload=16777216,
      unresolved_retired_tombstone_count=0)


def witness():
    return dict(schema_id="native-n3-lineage-v1", namespace_id="n3_good_fixture",
                lineage_generation=1, state_generation=3,
                operator_provisioned=True)


def enc(x):
    return json.dumps(x, sort_keys=True, separators=(",", ":")).encode()


TOKENS = {name: i + 100 for i, name in enumerate((
    "control", "state_parent", "lineage_parent", "state", "lineage",
    "workspace", "lock", "control_record", "witness", "authority",
    "attempts", "responses"))}
REV_TOKENS = {value: name for name, value in TOKENS.items()}


class FakeFDPort:
    """Closed-world test fixture. Every syscall is an in-memory dictionary hit."""
    def _key(self, fd):
        return REV_TOKENS[fd] if type(fd) is int else fd
    def __init__(self):
        self.stats = dict(control=st(10), state_parent=st(20),
            lineage_parent=st(21), state=st(30), lineage=st(31),
            workspace=st(60), lock=st(40, False),
            control_record=st(41, False), witness=st(42, False),
            authority=st(43, False), attempts=st(44), responses=st(45))
        self.chains = dict(control=(ROOT_ID, EXTERNAL_ID, CONTROL_ID),
            state_parent=(ROOT_ID, EXTERNAL_ID, CONTROL_ID, STATE_PARENT_ID),
            lineage_parent=(ROOT_ID, EXTERNAL_ID, CONTROL_ID, LINEAGE_PARENT_ID),
            state=(ROOT_ID, EXTERNAL_ID, CONTROL_ID, STATE_PARENT_ID, STATE_ID),
            lineage=(ROOT_ID, EXTERNAL_ID, CONTROL_ID, LINEAGE_PARENT_ID, LINEAGE_ID),
            workspace=(ROOT_ID, EXTERNAL_ID, (7, 50), WS_ID),
            attempts=(ROOT_ID, EXTERNAL_ID, CONTROL_ID, STATE_PARENT_ID, STATE_ID,(7,44)),
            responses=(ROOT_ID, EXTERNAL_ID, CONTROL_ID, STATE_PARENT_ID, STATE_ID,(7,45)))
        self.child_dirs = {("state_parent", "native-n3-state"): "state",
                           ("lineage_parent", "native-n3-lineage"): "lineage",
                           ("state", "attempts"): "attempts",
                           ("state", "responses"): "responses"}
        self.child_files = {("state", "owner.lock"): "lock",
                            ("state", "control.v1"): "control_record",
                            ("lineage", "provision-witness.v1"): "witness",
                            ("lineage", "owner-authority.v1"): "authority"}
        self.entries = dict(state=("owner.lock", "control.v1", "attempts", "responses"),
                            lineage=("provision-witness.v1", "owner-authority.v1"),
                            attempts=(), responses=())
        self.payload = dict(control_record=enc(control()), witness=enc(witness()),
                            authority=b"not-verified-operator-authority")
        for key in self.payload:
            self.stats[key].st_size = len(self.payload[key])
        self.locked = False
        self.lock_raises = False
        self.replaced_lock = False
        self.raise_read = False
        self.unexpected_syscall = False
        self.events = []
        self.closed = set()
        self.opened = set()

    def euid(self): return UID
    def fstat(self, fd): return self.stats[self._key(fd)]
    def open_directory(self, name, parent_fd):
        assert name in {"native-n3-state", "native-n3-lineage", "attempts", "responses"}
        try:
            child = self.child_dirs[self._key(parent_fd), name]
        except KeyError as exc:
            raise FileNotFoundError("synthetic missing existing directory") from exc
        self.opened.add(child)
        self.events.append(("open_directory", child))
        return TOKENS[child]
    def open_file(self, name, parent_fd):
        assert name in {"owner.lock", "control.v1", "provision-witness.v1", "owner-authority.v1"}
        child = self.child_files[self._key(parent_fd), name]
        self.opened.add(child)
        self.events.append(("open_file", child))
        return TOKENS[child]
    def named_stat(self, name, parent_fd):
        child = self.child_files[self._key(parent_fd), name]
        if self.replaced_lock and child == "lock":
            return st(999, False)
        return self.stats[child]
    def names(self, fd, limit):
        assert limit == 4097
        return self.entries[self._key(fd)]
    def bytes_from(self, fd, limit):
        assert limit == 4096
        if self.raise_read: raise OSError("synthetic injected I/O fault")
        self.events.append(("read", self._key(fd)))
        return self.payload[self._key(fd)]
    def ancestor_ids(self, fd, limit):
        assert limit == 64
        return self.chains[self._key(fd)]
    def exclusive_lock(self, fd):
        if self.lock_raises or self.locked:
            raise OSError("synthetic owner conflict")
        self.locked = True
        self.events.append(("lock", self._key(fd)))
    def close(self, fd):
        fd = self._key(fd)
        if fd in self.closed: raise AssertionError("double-close " + fd)
        self.closed.add(fd)
        self.events.append(("close", fd))
        if fd == "lock": self.locked = False


def scan(port: FakeFDPort):
    return N3F0PinnedReadOnlySession.open_existing(
        port=port, trusted_control_fd=TOKENS["control"],
        state_parent_fd=TOKENS["state_parent"],
        lineage_parent_fd=TOKENS["lineage_parent"],
        workspace_root_fds=(TOKENS["workspace"],))


class FDReadOnlyT0(unittest.TestCase):
    def good(self):
        p = FakeFDPort()
        sess = scan(p)
        self.assertFalse(sess.closed)
        self.assertTrue(p.locked)
        self.assertFalse(sess.report.available)
        self.assertEqual(sess.report.completion_capability, "none")
        self.assertEqual(sess.report.durability_state, "unavailable")
        self.assertEqual(sess.report.quarantine_reason_code,
                         "offline_authority_unverified")
        self.assertEqual(p.closed, {"control_record", "witness", "authority",
                                    "attempts", "responses"})
        sess.close()
        self.assertFalse(p.locked)
        self.assertEqual(p.closed, p.opened)
        self.assertNotIn("control", p.closed)
        self.assertNotIn("workspace", p.closed)
        return p

    def deny(self, p: FakeFDPort, reason: str):
        with self.assertRaises(N3F0PhysicalDenied) as cm: scan(p)
        self.assertEqual(cm.exception.reason_code, reason)
        self.assertFalse(cm.exception.available)
        self.assertFalse(p.locked)
        self.assertEqual(p.closed, p.opened)
        self.assertNotIn("control", p.closed)
        self.assertNotIn("workspace", p.closed)

    def test_01_valid_sibling_separate_parent_only_unqualified_metadata(self):
        self.good()

    def test_02_session_context_releases_lifetime_owner(self):
        p = FakeFDPort()
        with scan(p) as s:
            self.assertTrue(p.locked)
            self.assertFalse(s.closed)
        self.assertFalse(p.locked)
        self.assertTrue(s.closed)
        s.close()

    def test_03_same_parent_r001_style_forbidden(self):
        p=FakeFDPort()
        p.chains["lineage_parent"]=p.chains["state_parent"]
        p.stats["lineage_parent"].st_ino=20
        self.deny(p,"lineage_not_independent")

    def test_04_workspace_ancestor_control_forbidden(self):
        p=FakeFDPort()
        p.chains["workspace"]=(ROOT_ID,EXTERNAL_ID,CONTROL_ID,(7,61),WS_ID)
        self.deny(p,"workspace_overlap")

    def test_05_control_inside_workspace_forbidden(self):
        p=FakeFDPort()
        p.chains["workspace"]=(ROOT_ID,EXTERNAL_ID)
        p.stats["workspace"].st_ino=2
        self.deny(p,"workspace_overlap")

    def test_06_state_is_workspace_ancestor_forbidden(self):
        p=FakeFDPort()
        p.chains["workspace"]=(ROOT_ID,EXTERNAL_ID,CONTROL_ID,STATE_PARENT_ID,STATE_ID,WS_ID)
        self.deny(p,"workspace_overlap")

    def test_07_workspace_equals_lineage_root_forbidden(self):
        p=FakeFDPort()
        p.chains["workspace"]=p.chains["lineage"]
        p.stats["workspace"].st_ino=31
        self.deny(p,"workspace_overlap")

    def test_08_diverged_then_rejoined_forbidden(self):
        p=FakeFDPort()
        p.chains["lineage"]=(ROOT_ID,EXTERNAL_ID,CONTROL_ID,(7,21),STATE_PARENT_ID,LINEAGE_ID)
        self.deny(p,"lineage_not_independent")

    def test_09_opposite_root_containment_forbidden(self):
        p=FakeFDPort()
        p.chains["lineage"]=(ROOT_ID,EXTERNAL_ID,CONTROL_ID,STATE_PARENT_ID,STATE_ID,LINEAGE_PARENT_ID,LINEAGE_ID)
        self.deny(p,"lineage_not_independent")

    def test_10_missing_trusted_workspace_refs_forbidden(self):
        p=FakeFDPort()
        with self.assertRaises(N3F0PhysicalDenied) as cm:
            N3F0PinnedReadOnlySession.open_existing(port=p,
                trusted_control_fd=TOKENS["control"],
                state_parent_fd=TOKENS["state_parent"],
                lineage_parent_fd=TOKENS["lineage_parent"],workspace_root_fds=())
        self.assertEqual(cm.exception.reason_code,"missing_trusted_scope")

    def test_11_wrong_owner_uid_forbidden(self):
        p=FakeFDPort();p.stats["control"].st_uid=999
        self.deny(p,"invalid_private_object")

    def test_12_weak_private_root_mode_forbidden(self):
        p=FakeFDPort();p.stats["state"].st_mode=stat.S_IFDIR | 0o775
        self.deny(p,"invalid_private_object")

    def test_13_hardlinked_owner_forbidden(self):
        p=FakeFDPort();p.stats["lock"].st_nlink=2
        self.deny(p,"invalid_private_object")

    def test_14_symlink_file_type_forbidden(self):
        p=FakeFDPort();p.stats["lock"].st_mode=stat.S_IFLNK|0o600
        self.deny(p,"invalid_private_object")

    def test_15_second_owner_lock_forbidden(self):
        p=FakeFDPort();p.lock_raises=True
        self.deny(p,"private_fs_unavailable")

    def test_16_renamed_lock_forbidden(self):
        p=FakeFDPort();p.replaced_lock=True
        self.deny(p,"owner_lock_replaced")

    def test_17_missing_witness_forbidden(self):
        p=FakeFDPort();p.entries["lineage"]=("owner-authority.v1",)
        self.deny(p,"unresolved_directory_entry")

    def test_18_missing_namespace_forbidden(self):
        p=FakeFDPort();del p.child_dirs[("state_parent","native-n3-state")]
        self.deny(p,"private_fs_unavailable")

    def test_19_boot_deny_forbidden(self):
        p=FakeFDPort();p.entries["state"] += ("boot-deny.v1",)
        self.deny(p,"unresolved_directory_entry")

    def test_20_pending_or_final_fence_forbidden(self):
        for s in ("pending-foo","final-fence-foo","tmp-foo"):
            with self.subTest(name=s):
                p=FakeFDPort();p.entries["state"] += (s,)
                self.deny(p,"unresolved_directory_entry")

    def test_21_unresolved_attempt_forbidden(self):
        p=FakeFDPort();p.entries["attempts"]=("r-something.json",)
        self.deny(p,"unresolved_attempt")

    def test_22_unresolved_response_forbidden(self):
        p=FakeFDPort();p.entries["responses"]=("d-something.json",)
        self.deny(p,"unresolved_attempt")

    def test_23_duplicate_json_key_forbidden(self):
        p=FakeFDPort();p.payload["control_record"] += b',"schema_id":"native-n3-v1"}'
        p.stats["control_record"].st_size=len(p.payload["control_record"])
        self.deny(p,"corrupt_record")

    def test_24_wrong_schema_forbidden(self):
        p=FakeFDPort();x=control();x["schema_id"]="v1";p.payload["control_record"]=enc(x)
        p.stats["control_record"].st_size=len(p.payload["control_record"])
        self.deny(p,"corrupt_record")

    def test_25_bool_count_forbidden(self):
        p=FakeFDPort();x=control();x["max_attempts"]=True;p.payload["control_record"]=enc(x)
        p.stats["control_record"].st_size=len(p.payload["control_record"])
        self.deny(p,"corrupt_record")

    def test_26_active_consent_forbidden(self):
        p=FakeFDPort();x=control();x["consent_active"]=True;x["consent_epoch"]=1
        p.payload["control_record"]=enc(x);p.stats["control_record"].st_size=len(p.payload["control_record"])
        self.deny(p,"prior_uncertainty")

    def test_27_unknown_quarantine_forbidden(self):
        p=FakeFDPort();x=control();x["global_quarantined"]=True;x["global_quarantine_reason"]="unknown"
        p.payload["control_record"]=enc(x);p.stats["control_record"].st_size=len(p.payload["control_record"])
        self.deny(p,"prior_uncertainty")

    def test_28_mismatched_lineage_generation_forbidden(self):
        p=FakeFDPort();w=witness();w["lineage_generation"]=999
        p.payload["witness"]=enc(w);p.stats["witness"].st_size=len(p.payload["witness"])
        self.deny(p,"lineage_mismatch")

    def test_29_stale_lock_in_control_forbidden(self):
        p=FakeFDPort();x=control();x["owner_lock_ino"]=777
        p.payload["control_record"]=enc(x);p.stats["control_record"].st_size=len(p.payload["control_record"])
        self.deny(p,"lineage_mismatch")

    def test_30_read_error_unavailable_without_leak(self):
        p=FakeFDPort();p.raise_read=True
        self.deny(p,"private_fs_unavailable")

    def test_31_duplicate_names_forbidden(self):
        p=FakeFDPort();p.entries["lineage"] += ("owner-authority.v1",)
        self.deny(p,"unresolved_directory_entry")

    def test_32_owner_file_ancestor_alias_forbidden(self):
        p=FakeFDPort();p.stats["lock"].st_ino=20
        self.deny(p,"inode_alias")

    def test_33_untrusted_actor_cannot_construct_positive_snapshot(self):
        with self.assertRaises(ValueError):
            N3F0PhysicalSnapshot(available=True)
        with self.assertRaises(ValueError):
            N3F0PhysicalSnapshot(completion_capability="native")
        with self.assertRaises(ValueError):
            N3F0PhysicalSnapshot(durability_state="healthy_metadata_only")

    def test_34_real_port_untouched_by_fake_executions(self):
        # Explicit fake-port execution, not a claim of physical T1.
        with mock.patch.object(RealFDPort,"open_directory",side_effect=AssertionError("OS port")), \
             mock.patch.object(RealFDPort,"exclusive_lock",side_effect=AssertionError("OS port")):
            self.good()

    def test_35_import_only_references_os_not_physical_call(self):
        p=FakeFDPort();s=scan(p)
        self.assertNotIn("native", s.report.completion_capability)
        self.assertFalse(p.unexpected_syscall)
        s.close()

    def test_36_unexpected_names_limit_forbidden(self):
        p=FakeFDPort();p.entries["state"] = tuple("extra"+str(i) for i in range(4097))
        self.deny(p,"unresolved_directory_entry")

    def test_37_incomplete_ancestry_forbidden(self):
        p=FakeFDPort();p.chains["state_parent"]=(STATE_PARENT_ID,)
        self.deny(p,"unverified_ancestry")

    def test_38_reordered_ancestry_forbidden(self):
        p=FakeFDPort();p.chains["lineage"]=(ROOT_ID,CONTROL_ID,EXTERNAL_ID,LINEAGE_PARENT_ID,LINEAGE_ID)
        self.deny(p,"lineage_not_independent")

    def test_39_stale_file_type_owner_forbidden(self):
        p=FakeFDPort();p.stats["authority"].st_mode=stat.S_IFDIR|0o700
        self.deny(p,"invalid_private_object")

    def test_40_unrecognized_operator_authority_does_not_mint_health(self):
        p=self.good()
        self.assertEqual(p.payload["authority"],b"not-verified-operator-authority")


if __name__ == "__main__":
    unittest.main()
