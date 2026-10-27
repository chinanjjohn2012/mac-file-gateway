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
import re
from typing import NamedTuple


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


class ReviewIdentity(NamedTuple):
    """One full reviewer-visible version tuple, not merely a Head SHA."""
    base: str
    head: str
    tree: str
    contract_version: str
    ruleset_id: str


class ReviewEvaluation(NamedTuple):
    review_progress: str
    evidence_status: str
    verdict: str
    decision: str
    review_level: str


SAMPLE_TARGET = ReviewIdentity("a" * 40, "b" * 40, "c" * 40,
                               "S0-contract-v1", "ICR-V2.0")


def simulated_review(*, target: ReviewIdentity,
                     b_review: ReviewIdentity | None = None,
                     c_review: ReviewIdentity | None = None,
                     b_verdict: str | None = None,
                     c_verdict: str | None = None,
                     b_scope_full: bool = False,
                     c_scope_full: bool = False,
                     confirmed_defect: str | None = None,
                     evidence_ok: bool = True,
                     required_test_not_run: bool = False,
                     review_activities_complete: bool = True) -> ReviewEvaluation:
    """Isolated state-table simulator, NOT the actual GitHub review engine.

    A known proven P0/P1/P2 merits REVIEW_COMPLETE+SUFFICIENT+FAIL.
    Missing decisive evidence merits REVIEW_COMPLETE+INSUFFICIENT+BLOCKED.
    Snapshot and contract identities are compared independently per role.
    """
    def result(progress, evidence, verdict, decision, level="NONE"):
        return ReviewEvaluation(progress, evidence, verdict, decision, level)

    if not all(re.fullmatch(r"[0-9a-f]{40}", val)
               for val in (target.base, target.head, target.tree)):
        return result("REVIEW_COMPLETE", "INSUFFICIENT", "BLOCKED", "BLOCKED")
    if not target.contract_version or not target.ruleset_id:
        return result("REVIEW_COMPLETE", "INSUFFICIENT", "BLOCKED", "BLOCKED")
    if any(v is not None and v != target for v in (b_review, c_review)):
        return result("SNAPSHOT_CHANGED", "INSUFFICIENT", "BLOCKED",
                      "SNAPSHOT_CHANGED")
    if confirmed_defect in ("P0", "P1", "P2") or "FAIL" in (b_verdict, c_verdict):
        return result("REVIEW_COMPLETE", "SUFFICIENT", "FAIL", "FAIL")
    if not review_activities_complete:
        return result("REVIEW_INCOMPLETE", "NOT_ASSESSED",
                      "NOT_ISSUED", "REVIEW_INCOMPLETE")
    if not evidence_ok or required_test_not_run or "BLOCKED" in (b_verdict, c_verdict):
        return result("REVIEW_COMPLETE", "INSUFFICIENT", "BLOCKED", "BLOCKED")
    if b_review is None or b_verdict is None:
        return result("REVIEW_INCOMPLETE", "NOT_ASSESSED",
                      "NOT_ISSUED", "NEXT_ROLE_B")
    if c_review is None or c_verdict is None:
        return result("REVIEW_INCOMPLETE", "NOT_ASSESSED",
                      "NOT_ISSUED", "NEXT_ROLE_C")
    if b_verdict != "PASS" or c_verdict != "PASS":
        return result("REVIEW_COMPLETE", "INSUFFICIENT", "BLOCKED", "BLOCKED")
    if not (b_scope_full and c_scope_full):
        return result("REVIEW_COMPLETE", "SUFFICIENT", "PASS",
                      "TARGETED_ONLY", "TARGETED_REVIEW_PASS")
    return result("REVIEW_COMPLETE", "SUFFICIENT", "PASS",
                  "ROLE_PAIR_ELIGIBLE_FOR_SEPARATE_R10_CHECK",
                  "ROLE_FULL_SCOPE_PASS")


def simulated_executed_identity(*, target: ReviewIdentity,
                               executed_commit: str, executed_tree: str,
                               merge_commit: str,
                               merge_parents: tuple[str, str]) -> str:
    """Separates observed Head from synthetic Merge without auto-retest waiver."""
    if executed_commit == target.head and executed_tree == target.tree:
        return "HEAD_EXECUTED"
    if executed_commit == merge_commit and merge_parents == (target.base, target.head):
        if executed_tree == target.tree:
            return "SAME_TREE_MERGE_EXECUTED_HEAD_NOT_SEPARATELY_EXECUTED"
        return "MERGE_TREE_DIFFERENT_HEAD_RETEST_REQUIRED"
    return "EXECUTED_IDENTITY_UNPROVEN"


def simulated_source_visibility(remote_committed_only: bool,
                                claim_local_uncommitted: bool) -> str:
    if remote_committed_only and claim_local_uncommitted:
        return "LOCAL_WORKTREE_NOT_OBSERVED"
    return "BOUNDED_SOURCE_CLAIM_ONLY"


def simulated_reviewer_independence(same_github_account: bool) -> str:
    return ("LOGICAL_SESSIONS_ONLY_NOT_TWO_HUMANS"
            if same_github_account else "ACCOUNT_DIFFERENCE_NOT_HUMAN_PROOF")


def simulated_command_access(role: str, command: str) -> str:
    if role == "A" and command == "下一步":
        return "READ_ONLY"
    return "REQUIRES_DISTINCT_AUTHORIZATION"


def simulated_risk_test(tier: str, explicitly_authorized: bool) -> str:
    if tier not in {"T0", "T1", "T2", "T3"}:
        return "NOT_RUN"
    if tier == "T0":
        return "SAFE_MODEL_ONLY"
    return "ISOLATED_ONLY" if explicitly_authorized else "NOT_RUN"


def simulated_legacy_review_transfer(old_v1_approved: bool,
                                     new_v2_activated: bool) -> str:
    return "HISTORICAL_ONLY_NO_AUTO_PASS"


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
    def evaluate(self, *, b=True, c=True, scope_full=True, **other):
        return simulated_review(
            target=SAMPLE_TARGET,
            b_review=SAMPLE_TARGET if b else None,
            c_review=SAMPLE_TARGET if c else None,
            b_verdict="PASS" if b else None,
            c_verdict="PASS" if c else None,
            b_scope_full=scope_full,
            c_scope_full=scope_full,
            **other,
        )

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
        output = self.evaluate(b=True, c=False)
        self.assertEqual(output.decision, "NEXT_ROLE_C")
        self.assertEqual(output.verdict, "NOT_ISSUED")

    def test_only_c_finished_needs_b(self):
        output = self.evaluate(b=False, c=True)
        self.assertEqual(output.decision, "NEXT_ROLE_B")
        self.assertEqual(output.review_progress, "REVIEW_INCOMPLETE")

    def test_two_targeted_roles_are_not_full(self):
        output = self.evaluate(scope_full=False)
        self.assertEqual(output.decision, "TARGETED_ONLY")
        self.assertEqual(output.review_level, "TARGETED_REVIEW_PASS")
        self.assertNotEqual(output.decision, "FULL_CODE_REVIEW_PASS")

    def test_two_full_roles_still_require_separate_r10(self):
        output = self.evaluate()
        self.assertEqual(output.decision,
                         "ROLE_PAIR_ELIGIBLE_FOR_SEPARATE_R10_CHECK")
        self.assertEqual(output.evidence_status, "SUFFICIENT")
        self.assertNotEqual(output.decision, "FULL_CODE_REVIEW_PASS")

    def test_head_base_tree_contract_and_ruleset_mismatch_each_fence(self):
        for field, altered in (
            ("base", SAMPLE_TARGET._replace(base="d" * 40)),
            ("head", SAMPLE_TARGET._replace(head="e" * 40)),
            ("tree", SAMPLE_TARGET._replace(tree="f" * 40)),
            ("contract", SAMPLE_TARGET._replace(contract_version="other")),
            ("rules", SAMPLE_TARGET._replace(ruleset_id="ICR-V1.0")),
        ):
            with self.subTest(mismatch=field):
                for b_bad in (True, False):
                    outcome = simulated_review(
                        target=SAMPLE_TARGET,
                        b_review=altered if b_bad else SAMPLE_TARGET,
                        c_review=SAMPLE_TARGET if b_bad else altered,
                        b_verdict="PASS", c_verdict="PASS",
                        b_scope_full=True, c_scope_full=True,
                    )
                    self.assertEqual(outcome.decision, "SNAPSHOT_CHANGED")
                    self.assertEqual(outcome.verdict, "BLOCKED")

    def test_base_advanced_without_new_head_must_recheck(self):
        advanced = SAMPLE_TARGET._replace(base="d" * 40)
        output = simulated_review(
            target=advanced, b_review=SAMPLE_TARGET, c_review=SAMPLE_TARGET,
            b_verdict="PASS", c_verdict="PASS",
            b_scope_full=True, c_scope_full=True,
        )
        self.assertEqual(output.review_progress, "SNAPSHOT_CHANGED")

    def test_missing_source_or_external_evidence_blocks(self):
        output = self.evaluate(evidence_ok=False)
        self.assertEqual(
            (output.review_progress, output.evidence_status, output.verdict),
            ("REVIEW_COMPLETE", "INSUFFICIENT", "BLOCKED"),
        )

    def test_required_native_test_not_run_is_complete_but_blocked(self):
        output = self.evaluate(required_test_not_run=True)
        self.assertEqual(
            (output.review_progress, output.evidence_status, output.verdict),
            ("REVIEW_COMPLETE", "INSUFFICIENT", "BLOCKED"),
        )

    def test_confirmed_p1_is_fail_not_blocked_or_incomplete(self):
        output = self.evaluate(confirmed_defect="P1", required_test_not_run=True)
        self.assertEqual(
            (output.review_progress, output.evidence_status, output.verdict),
            ("REVIEW_COMPLETE", "SUFFICIENT", "FAIL"),
        )

    def test_confirmed_p0_and_p2_are_also_fail(self):
        for severity in ("P0", "P2"):
            with self.subTest(severity=severity):
                self.assertEqual(
                    self.evaluate(confirmed_defect=severity).verdict, "FAIL"
                )

    def test_known_role_fail_cannot_be_relabelled_blocked_or_pass(self):
        outcome = simulated_review(
            target=SAMPLE_TARGET, b_review=SAMPLE_TARGET,
            b_verdict="FAIL", c_review=None,
        )
        self.assertEqual(outcome.verdict, "FAIL")

    def test_unfinished_review_activity_not_relabelled_complete(self):
        output = self.evaluate(review_activities_complete=False)
        self.assertEqual(
            (output.review_progress, output.evidence_status, output.verdict),
            ("REVIEW_INCOMPLETE", "NOT_ASSESSED", "NOT_ISSUED"),
        )

    def test_incomplete_target_identity_blocks(self):
        broken = SAMPLE_TARGET._replace(head="unknown")
        output = simulated_review(target=broken)
        self.assertEqual(output.decision, "BLOCKED")

    def test_head_vs_merge_execution_is_not_same_commit_proof(self):
        merge = "d" * 40
        self.assertEqual(simulated_executed_identity(
            target=SAMPLE_TARGET, executed_commit=SAMPLE_TARGET.head,
            executed_tree=SAMPLE_TARGET.tree, merge_commit=merge,
            merge_parents=(SAMPLE_TARGET.base, SAMPLE_TARGET.head),
        ), "HEAD_EXECUTED")
        self.assertEqual(simulated_executed_identity(
            target=SAMPLE_TARGET, executed_commit=merge,
            executed_tree=SAMPLE_TARGET.tree, merge_commit=merge,
            merge_parents=(SAMPLE_TARGET.base, SAMPLE_TARGET.head),
        ), "SAME_TREE_MERGE_EXECUTED_HEAD_NOT_SEPARATELY_EXECUTED")
        self.assertEqual(simulated_executed_identity(
            target=SAMPLE_TARGET, executed_commit=merge,
            executed_tree="f" * 40, merge_commit=merge,
            merge_parents=(SAMPLE_TARGET.base, SAMPLE_TARGET.head),
        ), "MERGE_TREE_DIFFERENT_HEAD_RETEST_REQUIRED")

    def test_remote_pr_never_proves_local_uncommitted_state(self):
        self.assertEqual(
            simulated_source_visibility(True, True),
            "LOCAL_WORKTREE_NOT_OBSERVED",
        )

    def test_same_github_account_not_two_independent_humans(self):
        self.assertEqual(
            simulated_reviewer_independence(True),
            "LOGICAL_SESSIONS_ONLY_NOT_TWO_HUMANS",
        )

    def test_a_next_step_is_read_only(self):
        self.assertEqual(simulated_command_access("A", "下一步"), "READ_ONLY")
        self.assertNotEqual(simulated_command_access("A", "继续开发"), "READ_ONLY")

    def test_t2_t3_requires_separate_authorization(self):
        for tier in ("T1", "T2", "T3"):
            with self.subTest(tier=tier):
                self.assertEqual(simulated_risk_test(tier, False), "NOT_RUN")
        self.assertEqual(simulated_risk_test("T0", False), "SAFE_MODEL_ONLY")

    def test_legacy_v1_review_no_auto_pass_under_v2(self):
        self.assertEqual(
            simulated_legacy_review_transfer(True, True),
            "HISTORICAL_ONLY_NO_AUTO_PASS",
        )


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
        output = simulated_review(
            target=SAMPLE_TARGET, b_review=SAMPLE_TARGET,
            c_review=SAMPLE_TARGET, b_verdict="PASS", c_verdict="PASS",
            b_scope_full=True, c_scope_full=True,
            confirmed_defect="P1", evidence_ok=True,
        )
        self.assertEqual(output.verdict, "FAIL")
        self.assertEqual(output.review_progress, "REVIEW_COMPLETE")
        self.assertEqual(output.evidence_status, "SUFFICIENT")

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

    def test_preflight_clean_core_filemode_false_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="v2-t0-coremode-") as tmp:
            repo, path, head = self._fixture(tmp)
            self._git(repo, "config", "core.filemode", "false")
            self.assertNotEqual(
                self._run_real_preflight(repo, head).returncode, 0,
            )

    def test_preflight_rejects_skip_worktree_index_flag(self):
        with tempfile.TemporaryDirectory(prefix="v2-t0-skipflag-") as tmp:
            repo, path, head = self._fixture(tmp)
            self._git(repo, "update-index", "--skip-worktree", "governance.md")
            self.assertNotEqual(
                self._run_real_preflight(repo, head).returncode, 0,
            )

    def test_preflight_rejects_true_mode_drift_even_when_config_true(self):
        with tempfile.TemporaryDirectory(prefix="v2-t0-true-mode-") as tmp:
            repo, path, head = self._fixture(tmp)
            path.chmod(0o755)
            self.assertNotEqual(
                self._run_real_preflight(repo, head).returncode, 0,
            )

    def test_preflight_rejects_head_tree_index_mode_drift(self):
        with tempfile.TemporaryDirectory(prefix="v2-t0-indexmode-") as tmp:
            repo, path, head = self._fixture(tmp)
            self._git(repo, "update-index", "--chmod=+x", "governance.md")
            self.assertNotEqual(
                self._run_real_preflight(repo, head).returncode, 0,
            )

    def test_preflight_rejects_ignored_import_shadow(self):
        with tempfile.TemporaryDirectory(prefix="v2-t0-shadow-") as tmp:
            repo, path, _ = self._fixture(tmp)
            ignored = repo / ".gitignore"
            ignored.write_text("shadow.py\n", encoding="utf-8")
            original = (repo / "MANIFEST.sha256").read_text("utf-8")
            (repo / "MANIFEST.sha256").write_text(
                hashlib.sha256(ignored.read_bytes()).hexdigest()
                + "  ./.gitignore\n" + original, encoding="utf-8",
            )
            self._git(repo, "add", ".gitignore", "MANIFEST.sha256")
            self._git(repo, "-c", "user.name=T0", "-c",
                      "user.email=t0@example.invalid", "commit", "-q", "-m", "ignored")
            head = self._git(repo, "rev-parse", "HEAD").decode().strip()
            (repo / "shadow.py").write_text(
                "raise RuntimeError('untrusted shadow import')\n",
                encoding="utf-8",
            )
            self.assertEqual(self._git(repo, "status", "--porcelain"), b"")
            self.assertNotEqual(
                self._run_real_preflight(repo, head).returncode, 0,
            )

    def test_preflight_rejects_untracked_and_wrong_expected_head(self):
        with tempfile.TemporaryDirectory(prefix="v2-t0-untracked-") as tmp:
            repo, path, head = self._fixture(tmp)
            self.assertNotEqual(
                self._run_real_preflight(repo, "e" * 40).returncode, 0,
            )
            (repo / "untracked.py").write_text("shadow = True\n", encoding="utf-8")
            self.assertNotEqual(
                self._run_real_preflight(repo, head).returncode, 0,
            )


    def _posttest_fixture(self, directory):
        """Commit exact checked-in preflight tool to an isolated temporary repo."""
        repo, tracked, _ = self._fixture(directory)
        source = ROOT.parents[1] / "tools" / "review_governance_v2_preflight.py"
        target = repo / "tools" / "review_governance_v2_preflight.py"
        target.parent.mkdir(parents=True)
        target.write_bytes(source.read_bytes())
        paths = ("governance.md", "tools/review_governance_v2_preflight.py")
        (repo / "MANIFEST.sha256").write_text(
            "".join(
                hashlib.sha256((repo / path).read_bytes()).hexdigest()
                + "  ./" + path + "\n"
                for path in paths
            ), encoding="utf-8",
        )
        self._git(repo, "add", "-A")
        self._git(repo, "-c", "user.name=T0", "-c",
                  "user.email=t0@example.invalid", "commit", "-q", "-m",
                  "commit source verifier for final-gate T0")
        return repo, tracked, self._git(repo, "rev-parse", "HEAD").decode().strip()

    def _run_actual_ci_final_step(self, repo, expected_head):
        """Execute the ACTUAL final workflow shell step, not a modelled copy."""
        workflow = (ROOT.parents[1] / ".github" / "workflows" /
                    "review-governance-v2-candidate.yml").read_text("utf-8")
        marker = "      - name: Final checkout integrity (no source changed by tests)\n"
        self.assertEqual(workflow.count(marker), 1)
        tail = workflow.split(marker, 1)[1]
        self.assertIn("        run: |\n", tail)
        raw = tail.split("        run: |\n", 1)[1]
        lines = []
        for line in raw.splitlines():
            if line.startswith("          "):
                lines.append(line[10:])
            elif not line.strip():
                break
            else:
                self.fail("Unsupported final YAML shell indentation")
        self.assertTrue(lines)
        return subprocess.run(
            ["bash", "-c", "\n".join(lines) + "\n"],
            cwd=repo, env={**os.environ, "EXPECTED_HEAD": expected_head},
            capture_output=True, text=True, check=False,
        )

    def test_posttest_workflow_uses_same_strict_verifier_twice(self):
        workflow = (ROOT.parents[1] / ".github" / "workflows" /
                    "review-governance-v2-candidate.yml").read_text("utf-8")
        command = ('python3 -I -S tools/review_governance_v2_preflight.py '
                   '--expected-head "$EXPECTED_HEAD"')
        self.assertEqual(workflow.count(command), 2)
        pre, final = workflow.split(
            "      - name: Final checkout integrity (no source changed by tests)\n",
            1,
        )
        self.assertIn(command, pre)
        self.assertIn(command, final)
        self.assertIn("EXPECTED_HEAD:", final)
        self.assertIn("V2_GOVERNANCE_T0_FINAL_SOURCE_UNCHANGED=PASS", final)

    def test_posttest_actual_step_accepts_clean_disposable_repo(self):
        with tempfile.TemporaryDirectory(prefix="v2-post-clean-") as tmp:
            repo, tracked, head = self._posttest_fixture(tmp)
            result = self._run_actual_ci_final_step(repo, head)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("V2_GOVERNANCE_T0_FINAL_SOURCE_UNCHANGED=PASS",
                          result.stdout)

    def test_posttest_actual_step_rejects_chmod_and_filemode_false(self):
        with tempfile.TemporaryDirectory(prefix="v2-post-mode-") as tmp:
            repo, tracked, head = self._posttest_fixture(tmp)
            self.assertEqual(self._run_actual_ci_final_step(repo, head).returncode, 0)
            tracked.chmod(0o755)
            self._git(repo, "config", "core.filemode", "false")
            self.assertEqual(self._git(repo, "status", "--porcelain"), b"")
            result = self._run_actual_ci_final_step(repo, head)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("CORE_FILEMODE_DISABLED", result.stderr)
            self.assertNotIn("V2_GOVERNANCE_T0_FINAL_SOURCE_UNCHANGED=PASS",
                             result.stdout)

    def test_posttest_actual_step_rejects_assume_unchanged(self):
        with tempfile.TemporaryDirectory(prefix="v2-post-assume-") as tmp:
            repo, tracked, head = self._posttest_fixture(tmp)
            self._git(repo, "update-index", "--assume-unchanged", "governance.md")
            self.assertEqual(self._git(repo, "status", "--porcelain"), b"")
            result = self._run_actual_ci_final_step(repo, head)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("HIDDEN_INDEX_FLAG_OR_DUPLICATE", result.stderr)

    def test_posttest_actual_step_rejects_skip_worktree(self):
        with tempfile.TemporaryDirectory(prefix="v2-post-skip-") as tmp:
            repo, tracked, head = self._posttest_fixture(tmp)
            self._git(repo, "update-index", "--skip-worktree", "governance.md")
            self.assertEqual(self._git(repo, "status", "--porcelain"), b"")
            result = self._run_actual_ci_final_step(repo, head)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("HIDDEN_INDEX_FLAG_OR_DUPLICATE", result.stderr)

    def test_posttest_actual_step_rejects_ignored_source_shadow(self):
        with tempfile.TemporaryDirectory(prefix="v2-post-shadow-") as tmp:
            repo, tracked, head = self._posttest_fixture(tmp)
            with (repo / ".git" / "info" / "exclude").open(
                "a", encoding="utf-8"
            ) as ignored_rules:
                ignored_rules.write("\nshadow.py\n")
            (repo / "shadow.py").write_text(
                "raise RuntimeError('not imported by these tests')\n",
                encoding="utf-8",
            )
            self.assertEqual(self._git(repo, "status", "--porcelain"), b"")
            result = self._run_actual_ci_final_step(repo, head)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("IGNORED_REPOSITORY_INPUT", result.stderr)

    def test_posttest_actual_step_rejects_untracked_source(self):
        with tempfile.TemporaryDirectory(prefix="v2-post-untracked-") as tmp:
            repo, tracked, head = self._posttest_fixture(tmp)
            (repo / "foreign.py").write_text("x = 1\n", encoding="utf-8")
            result = self._run_actual_ci_final_step(repo, head)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)



if __name__ == "__main__":
    unittest.main()
