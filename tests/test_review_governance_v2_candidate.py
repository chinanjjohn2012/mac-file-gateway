"""Pure T0 governance-design and migration-state simulations for PR #75.

These tests read tracked Markdown from the PR checkout. They do not access
external Projects, native processes, secrets, networking or production state.
Passing means the candidate's static/source and simulated invariants hold;
it does NOT approve the rules or activate V2 for any real review round.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1] / "docs" / "review-governance-v2"
CANONICAL_A = {
    "INDEPENDENT_CODE_REVIEW_RULES_V2_CANDIDATE.md":
        "9bece5bf9c74e1fc899d6fcb09a067d4793b8ba3a61f6efc2c54eba2898cae3b",
    "GITHUB_REVIEW_HANDOFF_V2_CANDIDATE.md":
        "b01cdc055bb35e586019781710229dadc4ca6ed80b6f97b2e0605db78965eef0",
    "EVIDENCE_AND_TEST_PROFILES_V2_CANDIDATE.md":
        "36402e54a3b5515eed649a6cad4402cc5d41c86fe5fee36fa93d1e70f5b1e0e5",
    "ROLE_A_DEVELOPER_V2_CANDIDATE.md":
        "9655c6406fdf21a42739b9b670513309b417dd44fbd68f6a85e89be93d2d6dec",
}


def _text(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def simulated_activation(*, b_design_pass=False, c_design_pass=False,
                         user_approved=False, three_projects_same_bytes=False,
                         t0_migration_pass=False, future_round=False,
                         snapshot_stable=True) -> bool:
    """Policy *model* for negative tests, NOT the live B/C orchestration engine."""
    return all((b_design_pass, c_design_pass, user_approved,
                three_projects_same_bytes, t0_migration_pass,
                future_round, snapshot_stable))


def simulated_review(*, b_pass=False, c_pass=False, scope_full=False,
                     same_snapshot=True, blockers=0, evidence_ok=True):
    """A small T0 counterexample table: never substitutes for a role Review."""
    if not same_snapshot:
        return "SNAPSHOT_CHANGED"
    if blockers or not evidence_ok:
        return "BLOCKED"
    if not b_pass:
        return "NEXT_ROLE_B"
    if not c_pass:
        return "NEXT_ROLE_C"
    if not scope_full:
        return "TARGETED_ONLY"
    return "ROLE_PAIR_ELIGIBLE_FOR_SEPARATE_R10_CHECK"


class CandidateSourceIdentityTests(unittest.TestCase):
    def test_four_a_project_sources_byte_exact(self):
        for name, expected in CANONICAL_A.items():
            with self.subTest(name=name):
                actual = hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                self.assertEqual(actual, expected)

    def test_core_enforces_actual_execution_modes_and_verified_red(self):
        core = _text("INDEPENDENT_CODE_REVIEW_RULES_V2_CANDIDATE.md")
        self.assertIn("不同执行模式", core)
        self.assertNotIn("不同比例的运行模式", core)
        self.assertIn("等效原始失败证据已独立核验", core)
        self.assertIn("R10 — 完整代码验收门槛", core)

    def test_etp_requires_head_merge_difference_and_retest_decision(self):
        etp = _text("EVIDENCE_AND_TEST_PROFILES_V2_CANDIDATE.md")
        self.assertIn("EVIDENCE_PROFILE_ID: ETP-V2.0", etp)
        self.assertIn("合成 Merge", etp)
        self.assertIn("Head Tree", etp)
        self.assertIn("重新执行针对 Head 的验证", etp)
        self.assertIn("E4 — 执行源污染防护", etp)

    def test_b_and_c_mandatory_full_read_and_gap_block(self):
        for name in ("ROLE_B_STANDARDS_V2_CANDIDATE.md",
                     "ROLE_C_SPEC_V2_CANDIDATE.md"):
            with self.subTest(name=name):
                text = _text(name)
                for required in ("必须实际完整读取", "R01–R10",
                                 "第三节报告格式", "第四节禁止事项",
                                 "第五节启用/适用边界",
                                 "EVIDENCE_STATUS: INSUFFICIENT",
                                 "VERDICT: BLOCKED",
                                 "ROLE_FULL_SCOPE_PASS",
                                 "COMMENT", "commit_id"):
                    self.assertIn(required, text)

    def test_draft_identity_and_no_automatic_prod_go(self):
        readme = _text("README.md")
        self.assertIn("NOT_EFFECTIVE", readme)
        self.assertIn("PROJECT_SOURCE_SYNC=NOT_VERIFIED", readme)
        self.assertIn("EXTERNAL_PROCESS_GATE", readme)
        self.assertIn("不授权合并", readme)
        migration = _text("MIGRATION_ACCEPTANCE_V2_CANDIDATE.md")
        self.assertIn("EFFECTIVE_FOR_NEW_ROUNDS", migration)
        self.assertIn("GH_HANDOFF_V1", migration)
        self.assertIn("T0", migration)


class MigrationTableTests(unittest.TestCase):
    def test_positive_model_only_when_all_gates_true(self):
        gates = dict(b_design_pass=True, c_design_pass=True,
                     user_approved=True, three_projects_same_bytes=True,
                     t0_migration_pass=True, future_round=True,
                     snapshot_stable=True)
        self.assertTrue(simulated_activation(**gates))
        for field in gates:
            with self.subTest(removed=field):
                altered = dict(gates, **{field: False})
                self.assertFalse(simulated_activation(**altered))

    def test_unapproved_or_unsynced_looks_like_current_state(self):
        self.assertFalse(simulated_activation(b_design_pass=False,
                                              c_design_pass=False,
                                              user_approved=False,
                                              three_projects_same_bytes=False))

    def test_only_b_finished_needs_c(self):
        self.assertEqual(simulated_review(b_pass=True, c_pass=False, scope_full=True),
                         "NEXT_ROLE_C")

    def test_only_c_finished_needs_b(self):
        self.assertEqual(simulated_review(b_pass=False, c_pass=True, scope_full=True),
                         "NEXT_ROLE_B")

    def test_two_targeted_roles_are_not_full(self):
        self.assertEqual(simulated_review(b_pass=True, c_pass=True, scope_full=False),
                         "TARGETED_ONLY")

    def test_two_full_roles_still_require_separate_r10(self):
        self.assertEqual(simulated_review(b_pass=True, c_pass=True, scope_full=True),
                         "ROLE_PAIR_ELIGIBLE_FOR_SEPARATE_R10_CHECK")

    def test_head_base_or_tree_drift_invalidates_old_signoff(self):
        self.assertEqual(simulated_review(b_pass=True, c_pass=True, scope_full=True,
                                          same_snapshot=False), "SNAPSHOT_CHANGED")

    def test_missing_source_or_evidence_blocks(self):
        self.assertEqual(simulated_review(b_pass=True, c_pass=True, scope_full=True,
                                          evidence_ok=False), "BLOCKED")

    def test_p1_defect_blocks_regardless_of_green_roles(self):
        self.assertEqual(simulated_review(b_pass=True, c_pass=True, scope_full=True,
                                          blockers=1), "BLOCKED")



class ReviewerR004CounterexampleTests(unittest.TestCase):
    """Direct T0 RED probes from current r003 B/C independent findings."""

    @staticmethod
    def _git(cwd, *args):
        return subprocess.check_output(["git", *args], cwd=cwd, stderr=subprocess.PIPE)

    def _fixture(self, directory):
        repo = Path(directory)
        self._git(repo, "init", "-q")
        self._git(repo, "config", "core.filemode", "true")
        path = repo / "governance.md"
        path.write_text("test-only governance fixture\n", encoding="utf-8")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        (repo / "MANIFEST.sha256").write_text(
            digest + "  ./governance.md\n", encoding="utf-8"
        )
        self._git(repo, "add", "-A")
        self._git(repo, "-c", "user.name=T0", "-c",
                  "user.email=t0@example.invalid", "commit", "-q", "-m", "fixture")
        return repo, path, self._git(repo, "rev-parse", "HEAD").decode().strip()

    def _run_real_preflight(self, repo, expected_head):
        checkout = ROOT.parents[1]
        script = checkout / "tools" / "review_governance_v2_preflight.py"
        if script.is_file():
            cmd = [sys.executable, "-I", "-S", str(script),
                   "--expected-head", expected_head]
        else:
            workflow = (checkout / ".github" / "workflows" /
                        "review-governance-v2-candidate.yml").read_text("utf-8")
            # On r003, run the actual inlined CI verifier verbatim. On r004,
            # the same tests run the newly extracted production-of-this-workflow
            # preflight script, not a second hand-written imitation.
            marker = "          python3 -I -S - <<'PY'\n"
            self.assertIn(marker, workflow)
            inline = workflow.split(marker, 1)[1].split("\n          PY", 1)[0]
            cmd = [sys.executable, "-I", "-S", "-c", textwrap.dedent(inline)]
        return subprocess.run(
            cmd, cwd=repo, env={**os.environ, "EXPECTED_HEAD": expected_head},
            capture_output=True, text=True, check=False,
        )

    def test_r006_each_high_risk_change_not_only_one_point(self):
        core = _text("INDEPENDENT_CODE_REVIEW_RULES_V2_CANDIDATE.md")
        role = _text("ROLE_B_STANDARDS_V2_CANDIDATE.md")
        self.assertIn("每个高风险变更点至少独立设计一个有意义的反例", core)
        self.assertIn("每个高风险变更点", role)
        self.assertNotIn("对至少一个有意义的高风险点", role)

    def test_proven_p1_must_report_fail_not_evidence_blocked(self):
        # r003 incorrectly returns BLOCKED for a conclusively proven P1.
        self.assertEqual(
            simulated_review(b_pass=True, c_pass=True, scope_full=True,
                             blockers=1, evidence_ok=True), "FAIL"
        )

    def test_preflight_rejects_executable_bit_drift_even_if_status_clean(self):
        with tempfile.TemporaryDirectory(prefix="v2-t0-mode-") as tmp:
            repo, path, head = self._fixture(tmp)
            self.assertEqual(self._run_real_preflight(repo, head).returncode, 0)
            path.chmod(0o755)
            self._git(repo, "config", "core.filemode", "false")
            self.assertEqual(self._git(repo, "status", "--porcelain"), b"")
            result = self._run_real_preflight(repo, head)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_preflight_rejects_undisclosed_assume_unchanged_flag(self):
        with tempfile.TemporaryDirectory(prefix="v2-t0-index-") as tmp:
            repo, path, head = self._fixture(tmp)
            self._git(repo, "update-index", "--assume-unchanged", "governance.md")
            self.assertEqual(self._git(repo, "status", "--porcelain"), b"")
            result = self._run_real_preflight(repo, head)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

if __name__ == "__main__":
    unittest.main()
