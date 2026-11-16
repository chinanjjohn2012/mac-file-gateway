"""Independent safe T0 counterexamples for PR113 nonoperative admission claims.

No product subprocess, host credential, network, GitHub API or native fixture.
"""
from __future__ import annotations

import copy
import hashlib
import os
from pathlib import Path
import tempfile
import unittest

from tools.pr113_t1_control_t0 import GateDenied, exact_product_identity
from tools.pr113_t1_attestation_t0 import (
    CHILD_ENV_KEYS, NETWORK_DESIGN_BLOB, PRODUCT_HEAD, PRODUCT_TREE,
    PROFILE_B, REPO, REVIEW_ROUND, WORKFLOW_PATH, OWNER_LOGIN,
    inspect_minimal_child_env_names_t0, inspect_private_bytes_t0,
    inspect_two_job_transcript_t0, inspect_untrusted_run_claim_t0,
    check_prod_claim_t0, native_execution_decision,
)

HEAD = "a" * 40
TREE = "b" * 40
LOCK = "c" * 64
RUN = 121234567
SIX_JOB = 23232323
MIXED_JOB = 24242424


def claim(phase="six", job=SIX_JOB):
    return {
        "repository": REPO, "pr": 113, "product_head": PRODUCT_HEAD,
        "product_tree": PRODUCT_TREE, "control_head": HEAD,
        "control_tree": TREE, "network_design_blob": NETWORK_DESIGN_BLOB,
        "network_profile": PROFILE_B, "review_round": REVIEW_ROUND,
        "workflow_path": WORKFLOW_PATH, "event": "workflow_dispatch",
        "actor": OWNER_LOGIN, "run_id": RUN, "run_attempt": 1,
        "job_id": job, "phase": phase, "input_lock_sha256": LOCK,
    }


def check_claim(obj, *, phase="six", job=SIX_JOB):
    return inspect_untrusted_run_claim_t0(obj, expected_control_head=HEAD,
            expected_control_tree=TREE, expected_lock_sha256=LOCK,
            expected_run_id=RUN, expected_job_id=job, expected_phase=phase)


def history():
    rows=[]
    for i, (phase, status, job) in enumerate((("six", "STARTED", SIX_JOB), ("six", "PASS", SIX_JOB),
                               ("mixed", "STARTED", MIXED_JOB), ("mixed", "PASS", MIXED_JOB))):
        rows.append({"phase":phase, "status":status, "run_id":RUN,
                     "run_attempt":1, "job_id":job,
                     "control_head":HEAD, "receipt_sha256":f"{i+1:064x}"})
    return rows


def inspect_history(rows):
    return inspect_two_job_transcript_t0(rows, run_id=RUN, expected_control_head=HEAD)


def receipt(data: bytes, cls="selected_python", rel="wheel.whl"):
    return {"input_class": cls, "relative_path": rel,
            "expected_sha256": hashlib.sha256(data).hexdigest(),
            "expected_size_bytes": len(data), "expected_git_blob": None}


class ImmutableClaimT0(unittest.TestCase):
    def test_expected_valid_shape_but_not_authenticated(self):
        v=check_claim(claim())
        self.assertEqual(v["claim_shape"], "MATCHED_UNTRUSTED_T0_ONLY")
        for key in ("owner_authenticated", "github_origin_authenticated", "one_shot_consumed",
                    "native_execution_authorized"):
            self.assertFalse(v[key])

    def test_untrusted_claim_cannot_mint_owner_permission(self):
        changed=claim()
        changed["owner_authorized"] = True
        with self.assertRaises(GateDenied):
            check_claim(changed)

    def test_required_identity_fields_all_deny_drift(self):
        bad={"repository":"intruder/elsewhere", "pr":114,
             "product_head":"0"*40, "product_tree":"0"*40,
             "control_head":"0"*40, "control_tree":"0"*40,
             "network_design_blob":"0"*40,
             "network_profile":"SOURCE_CLOSED_OFFLINE", "review_round":"r001",
             "workflow_path":".github/workflows/auto.yml", "event":"pull_request",
             "actor":"bot", "run_id":RUN+1, "run_attempt":2,
             "job_id":MIXED_JOB, "phase":"mixed", "input_lock_sha256":"0"*64}
        for field, wrong in bad.items():
            with self.subTest(field=field), self.assertRaises(GateDenied):
                check_claim({**claim(),field:wrong})

    def test_missing_field_or_extra_token_rejected(self):
        for v in (dict(list(claim().items())[:-1]), {**claim(), "grant_token": "x"}):
            with self.assertRaises(GateDenied):
                check_claim(v)

    def test_bool_cannot_impersonate_run_id_job_id_attempt_or_pr(self):
        for field in ("run_id", "job_id", "run_attempt", "pr"):
            with self.subTest(field=field), self.assertRaises(GateDenied):
                check_claim({**claim(), field:True})

    def test_missing_trusted_external_expectation_rejected(self):
        for override in ({"expected_control_head": "z"*40},
                         {"expected_control_tree": ""},
                         {"expected_lock_sha256": "bad"},
                         {"expected_run_id": 0},
                         {"expected_job_id": True},
                         {"expected_phase": "unknown"}):
            args=dict(expected_control_head=HEAD,expected_control_tree=TREE,
                      expected_lock_sha256=LOCK,expected_run_id=RUN,
                      expected_job_id=SIX_JOB,expected_phase="six")
            args.update(override)
            with self.assertRaises(GateDenied):
                inspect_untrusted_run_claim_t0(claim(),**args)

    def test_valid_mixed_phase_only_when_explicitly_expected(self):
        v=check_claim(claim("mixed",MIXED_JOB),phase="mixed",job=MIXED_JOB)
        self.assertFalse(v["native_execution_authorized"])
        with self.assertRaises(GateDenied):
            check_claim(claim("mixed",MIXED_JOB))

    def test_wrong_product_claim_denied(self):
        check_prod_claim_t0(exact_product_identity())
        with self.assertRaises(GateDenied):
            check_prod_claim_t0({**exact_product_identity(), "head_sha":"0"*40})

    def test_native_never_runs_even_if_claim_is_syntactically_perfect(self):
        with self.assertRaisesRegex(GateDenied,"NOT AUTHORIZED"):
            native_execution_decision(claim())


class TwoJobStateT0(unittest.TestCase):
    def test_complete_transcript_is_shape_only(self):
        a=inspect_history(history())
        self.assertEqual(a["chronology"],"SHAPE_MATCH_ONLY")
        self.assertEqual(a["distinct_jobs"],2)
        self.assertFalse(a["receipts_authenticated"])
        self.assertFalse(a["globally_consumed"])
        self.assertFalse(a["native_execution_authorized"])

    def test_mixed_first_or_job_repeated_denied(self):
        a=history()
        for h in (a[::-1],a[1:]+a[:1]):
            with self.assertRaises(GateDenied):
                inspect_history(h)
        b=history()
        b[2]["job_id"]=SIX_JOB
        b[3]["job_id"]=SIX_JOB
        with self.assertRaises(GateDenied):
            inspect_history(b)

    def test_two_job_source_owner_or_run_drift_denied(self):
        fields={"control_head":"a"*39+"c", "run_id":RUN+1,
                "run_attempt":2,"job_id":MIXED_JOB,"receipt_sha256":"g"*64}
        for fld,val in fields.items():
            b=history()
            b[0][fld]=val
            with self.subTest(field=fld),self.assertRaises(GateDenied):
                inspect_history(b)

    def test_mixed_job_must_remain_same_within_phase(self):
        b=history()
        b[3]["job_id"]=MIXED_JOB+1
        with self.assertRaises(GateDenied):
            inspect_history(b)

    def test_missing_success_duplicate_or_retry_denied(self):
        invalid=(history()[:3], history()+[history()[-1]],
                 [{**x,"status":"PASS"} if i==0 else x for i,x in enumerate(history())],
                 [{**x,"run_attempt":2} for x in history()],
                 [{**x,"run_id":RUN+1} for x in history()])
        for h in invalid:
            with self.subTest(case=str(h)[:55]),self.assertRaises(GateDenied):
                inspect_history(h)

    def test_duplicate_receipt_replay_denied(self):
        rows=history()
        rows[2]["receipt_sha256"] = rows[1]["receipt_sha256"]
        with self.assertRaises(GateDenied):
            inspect_history(rows)

    def test_no_global_replay_claim_even_when_reused_transcript_passes(self):
        a=inspect_history(history())
        b=inspect_history(history())
        self.assertFalse(a["globally_consumed"] or b["globally_consumed"])


class ChildEnvironmentShapeT0(unittest.TestCase):
    def test_minimal_key_shape_not_a_secret_absence_proof(self):
        result=inspect_minimal_child_env_names_t0(["PATH","HOME","TMPDIR"])
        self.assertEqual(result["environment_key_shape"],"CLOSED_LIST_T0_ONLY")
        self.assertFalse(result["environment_values_qualified"])
        self.assertFalse(result["accessible_secret_files_absent_proven"])

    def test_explicit_local_fixture_flags_are_only_names(self):
        names=["PATH","HOME","TMPDIR","PIPENV_PIPFILE","PIP_NO_INDEX","GOPROXY"]
        self.assertEqual(inspect_minimal_child_env_names_t0(names)["observed_key_count"],6)

    def test_inherited_credentials_and_selectors_rejected(self):
        forbidden=("GITHUB_TOKEN","GH_TOKEN","ACTIONS_ID_TOKEN_REQUEST_TOKEN","SSH_AUTH_SOCK",
                   "AWS_ACCESS_KEY_ID","GOFLAGS","GOCACHEPROG","PYTHONPATH","VIRTUAL_ENV",
                   "PIPENV_PYTHON","LD_PRELOAD","DYLD_INSERT_LIBRARIES","HTTP_PROXY",
                   "HTTPS_PROXY","PIP_CONFIG_FILE","WORKON_HOME","GITHUB_ACTIONS")
        for key in forbidden:
            self.assertNotIn(key,CHILD_ENV_KEYS)
            with self.subTest(key=key), self.assertRaises(GateDenied):
                inspect_minimal_child_env_names_t0(["PATH","HOME","TMPDIR",key])

    def test_duplicates_missing_or_case_confusion_rejected(self):
        for v in (["PATH","HOME","HOME"], ["PATH","HOME"], ["path","HOME","TMPDIR"],
                  ["PATH","HOME","TMPDIR", True]):
            with self.subTest(v=str(v)), self.assertRaises(GateDenied):
                inspect_minimal_child_env_names_t0(v)


class ActualPrivateByteReceiptT0(unittest.TestCase):
    def test_file_sha256_positive_only_untrusted_expectation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            root.chmod(0o700)
            p=root/"wheel.whl"
            p.write_bytes(b"offline disposable dummy wheel bytes")
            out=inspect_private_bytes_t0(root,[receipt(p.read_bytes())])
            self.assertEqual(len(out),1)
            self.assertEqual(out[0]["status"],"BYTES_MATCH_UNAUTHENTICATED_T0_ONLY")
            self.assertFalse(out[0]["loaded_runtime_identity_attested"])
            self.assertFalse(out[0]["native_execution_authorized"])

    def test_bogus_digest_or_size_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700)
            p=root/"wheel.whl";p.write_bytes(b"known")
            c=receipt(b"known")
            for attr,bad in (("expected_sha256","0"*64),("expected_size_bytes",99),
                             ("expected_size_bytes",True),("expected_sha256","1234")):
                with self.subTest(attr=attr),self.assertRaises(GateDenied):
                    inspect_private_bytes_t0(root,[{**c,attr:bad}])

    def test_unqualified_git_object_claim_not_reopened_or_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700)
            (root/"wheel.whl").write_bytes(b"known")
            c=receipt(b"known")
            c["expected_git_blob"]="b"*40
            with self.assertRaisesRegex(GateDenied,"NOT_ATTESTED"):
                inspect_private_bytes_t0(root,[c])

    def test_missing_or_duplicate_input_classes_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700)
            (root/"wheel.whl").write_bytes(b"known")
            for claims in ([],[receipt(b"known"),receipt(b"known")],
                           [{**receipt(b"known"),"input_class":"unknown"}]):
                with self.assertRaises(GateDenied):
                    inspect_private_bytes_t0(root,claims)

    def test_symlinks_hardlinks_and_parent_escape_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/"private"
            root.mkdir(mode=0o700)
            f=root/"wheel.whl";f.write_bytes(b"fixture")
            (root/"alias").symlink_to(f)
            os.link(f,root/"other")
            for rel in ("alias","other","../private/wheel.whl","/tmp/wheel.whl", "dir//f", "./wheel.whl"):
                with self.subTest(rel=rel),self.assertRaises(GateDenied):
                    inspect_private_bytes_t0(root,[receipt(b"fixture",rel=rel)])

    def test_external_or_public_root_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/"wheel.whl").write_bytes(b"known")
            root.chmod(0o755)
            with self.assertRaises(GateDenied):
                inspect_private_bytes_t0(root,[receipt(b"known")])

    def test_more_than_nine_claims_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            with self.assertRaises(GateDenied):
                inspect_private_bytes_t0(root,[receipt(b"x",cls="selected_python") for _ in range(10)])

    def test_no_file_install_or_network_side_effects_from_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700)
            f=root/"wheel.whl";f.write_bytes(b"immutable")
            start=f.stat()
            inspect_private_bytes_t0(root,[receipt(f.read_bytes())])
            end=f.stat()
            self.assertEqual(start.st_size,end.st_size)
            self.assertEqual(start.st_mtime_ns,end.st_mtime_ns)


if __name__ == "__main__":
    unittest.main()

# These RECORD tests are in-memory ZIP checks: no wheel install and no import.
# A correct RECORD for synthetic bytes is not evidence of an installed source.
import base64
import io
import zipfile
from tools.pr113_t1_attestation_t0 import inspect_wheel_record_bytes_t0


def _record_hash(contents: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(contents).digest()).decode("ascii").rstrip("=")


def _synthetic_wheel(*, payload: bytes = b"print('not executed')\n", bad_hash=False,
                     missing=False, duplicate=False, extra=False, unsafe=False,
                     bad_self=False, missing_wheel_metadata=False) -> bytes:
    pack = "safe_pkg/__init__.py"
    payload_path = "../escape.py" if unsafe else pack
    wheel_path = "safe_pkg-1.0.dist-info/WHEEL"
    record_path = "safe_pkg-1.0.dist-info/RECORD"
    wheel_meta = b"Wheel-Version: 1.0\nGenerator: standalone-T0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    rows = [f"{payload_path},{'sha256='+'0'*43 if bad_hash else _record_hash(payload)},{len(payload)}"]
    if not missing_wheel_metadata:
        rows.append(f"{wheel_path},{_record_hash(wheel_meta)},{len(wheel_meta)}")
    if extra:
        rows.append(f"extra/unknown.py,{_record_hash(b'extra')},5")
    if duplicate:
        rows.append(rows[0])
    if not missing:
        rows.append(f"{record_path},{_record_hash(b'bad') if bad_self else ''},")
    record_data = ("\n".join(rows)+"\n").encode("utf-8")
    out=io.BytesIO()
    with zipfile.ZipFile(out,"w",compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(payload_path,payload)
        if not missing_wheel_metadata:
            archive.writestr(wheel_path,wheel_meta)
        archive.writestr(record_path,record_data)
    return out.getvalue()


class WheelRecordT0(unittest.TestCase):
    def test_complete_synthetic_record_only(self):
        o=inspect_wheel_record_bytes_t0(_synthetic_wheel())
        self.assertEqual(o["record_self_consistency"],"PASS_T0_ONLY")
        self.assertEqual(o["declared_files_verified"],2)
        self.assertFalse(o["dependency_closure_qualified"])
        self.assertFalse(o["actual_loaded_source_proven"])
        self.assertFalse(o["native_execution_authorized"])

    def test_hashed_payload_mutation_detected(self):
        with self.assertRaises(GateDenied):
            inspect_wheel_record_bytes_t0(_synthetic_wheel(bad_hash=True))

    def test_record_omission_and_duplicate_fail_closed(self):
        for kwargs in ({"missing":True},{"duplicate":True},{"extra":True},
                       {"bad_self":True},{"missing_wheel_metadata":True}):
            with self.subTest(kwargs=kwargs), self.assertRaises(GateDenied):
                inspect_wheel_record_bytes_t0(_synthetic_wheel(**kwargs))

    def test_path_escape_or_unknown_zip_name_rejected(self):
        with self.assertRaises(GateDenied):
            inspect_wheel_record_bytes_t0(_synthetic_wheel(unsafe=True))

    def test_not_a_zip_or_wrong_input_type(self):
        for bad in (b"not zip", "hello", None, b"", b"x"*10_000_001):
            with self.subTest(type=str(type(bad))),self.assertRaises(GateDenied):
                inspect_wheel_record_bytes_t0(bad)

    def test_large_compression_ratio_disallowed_before_member_load(self):
        with self.assertRaises(GateDenied):
            inspect_wheel_record_bytes_t0(_synthetic_wheel(payload=b"A"*3_000_000))

    def test_archive_member_case_shadowing_rejected(self):
        data=_synthetic_wheel()
        inp=io.BytesIO()
        with zipfile.ZipFile(inp,"w") as z:
            with zipfile.ZipFile(io.BytesIO(data)) as source:
                for info in source.infolist():
                    z.writestr(info.filename,source.read(info.filename))
            z.writestr("SAFE_PKG/__init__.py",b"shadowed")
        with self.assertRaises(GateDenied):
            inspect_wheel_record_bytes_t0(inp.getvalue())
