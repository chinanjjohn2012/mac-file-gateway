"""T0 counterexamples for the Darwin firmlink CI evidence-admission guard.

All fixture XML here is synthetic, not real native macOS acceptance evidence.
"""
from __future__ import annotations

from pathlib import Path
import re
from xml.etree import ElementTree

import pytest

from tools.ci_firmlink_required_cases import (
    ALLOWED_CLASSNAMES,
    MAX_REPORT_BYTES,
    REQUIRED_CASES,
    MandatoryFirmlinkCaseError,
    main,
    verify_required_cases,
)


OPTIONAL = (
    "test_native_case_or_unicode_alias_identity_stays_protected[case]",
    "test_native_case_or_unicode_alias_identity_stays_protected[unicode]",
)
GENERICS = tuple("test_generic_fixture_" + str(i) for i in range(7))
CLASSNAME = "tests.test_phase1_review_identity"


def report(tmp_path, *, skips=(), fails=(), errors=(), missing=(),
           duplicate=(), wrong_module=(), optional_skips=(), only_required=False):
    """Build a representative pytest JUnit XML under an isolated temp path."""
    root = ElementTree.Element("testsuites")
    suite = ElementTree.SubElement(root, "testsuite", name="pytest")
    names = sorted(REQUIRED_CASES - set(missing))
    if not only_required:
        names = list(GENERICS) + names + list(OPTIONAL)
    for name in names + list(duplicate):
        klass = "unrelated.test_phase1_review_identity" if name in wrong_module else CLASSNAME
        case = ElementTree.SubElement(suite, "testcase", name=name, classname=klass)
        if name in skips or name in optional_skips:
            ElementTree.SubElement(case, "skipped", message="platform unavailable")
        elif name in fails:
            ElementTree.SubElement(case, "failure", message="assertion failed")
        elif name in errors:
            ElementTree.SubElement(case, "error", message="setup failed")
    path = tmp_path / "junit.xml"
    path.write_bytes(ElementTree.tostring(root))
    return path


def test_real_15_of_15_positive(tmp_path):
    path = report(tmp_path)
    assert verify_required_cases(path) == REQUIRED_CASES
    assert main([str(path)]) == 0


def test_valid_six_mandatory_with_both_optional_skipped_still_passes(tmp_path):
    path = report(tmp_path, optional_skips=OPTIONAL)
    assert verify_required_cases(path) == REQUIRED_CASES


@pytest.mark.parametrize("missing_core", sorted(REQUIRED_CASES))
def test_each_mandatory_case_skipped_is_rejected_even_if_optional_pass(tmp_path, missing_core):
    path = report(tmp_path, skips={missing_core})
    # The r013 aggregate >=13 predicate incorrectly accepted 14 passed/1 skipped.
    assert re.search(r"(?<!\d)(\d+) passed(?:[,\s]|$)", "14 passed, 1 skipped").group(1) == "14"
    with pytest.raises(MandatoryFirmlinkCaseError, match="required_case_not_passed"):
        verify_required_cases(path)


def test_two_required_skipped_optional_success_cannot_hide_them(tmp_path):
    path = report(tmp_path, skips=set(sorted(REQUIRED_CASES)[:2]))
    # The r013 aggregate >=13 predicate also accepted 13 passed/2 skipped.
    assert int(re.search(r"(?<!\d)(\d+) passed", "13 passed, 2 skipped").group(1)) >= 13
    with pytest.raises(MandatoryFirmlinkCaseError, match="required_case_not_passed"):
        verify_required_cases(path)


@pytest.mark.parametrize("status", ("fails", "errors"))
def test_required_failure_or_error_rejected(tmp_path, status):
    kwargs = {status: {sorted(REQUIRED_CASES)[0]}}
    with pytest.raises(MandatoryFirmlinkCaseError, match="required_case_not_passed"):
        verify_required_cases(report(tmp_path, **kwargs))


@pytest.mark.parametrize("case", sorted(REQUIRED_CASES))
def test_missing_each_required_case_fails_closed(tmp_path, case):
    with pytest.raises(MandatoryFirmlinkCaseError, match="missing_required_cases"):
        verify_required_cases(report(tmp_path, missing={case}))


def test_duplicate_required_case_fails_even_when_both_pass(tmp_path):
    case = sorted(REQUIRED_CASES)[0]
    with pytest.raises(MandatoryFirmlinkCaseError, match="duplicate_required_case"):
        verify_required_cases(report(tmp_path, duplicate={case}))


def test_wrong_module_cannot_masquerade_as_required_case(tmp_path):
    case = sorted(REQUIRED_CASES)[0]
    with pytest.raises(MandatoryFirmlinkCaseError, match="wrong_module"):
        verify_required_cases(report(tmp_path, wrong_module={case}))


def test_required_status_not_run_fails_closed(tmp_path):
    path = report(tmp_path)
    doc = ElementTree.parse(path)
    case = next(x for x in doc.iter("testcase") if x.get("name") in REQUIRED_CASES)
    case.set("status", "notrun")
    doc.write(path)
    with pytest.raises(MandatoryFirmlinkCaseError, match="required_case_not_passed"):
        verify_required_cases(path)


def test_only_six_mandatory_case_records_succeed(tmp_path):
    assert verify_required_cases(report(tmp_path, only_required=True)) == REQUIRED_CASES


@pytest.mark.parametrize("raw", (b"", b"<invalid", b"<other/>", b"x" * (MAX_REPORT_BYTES + 1)))
def test_invalid_or_unbounded_xml_denied(tmp_path, raw):
    path = tmp_path / "invalid.xml"
    path.write_bytes(raw)
    with pytest.raises(MandatoryFirmlinkCaseError):
        verify_required_cases(path)
    assert main([str(path)]) == 1


def test_missing_file_fails_without_pass_message(tmp_path, capsys):
    assert main([str(tmp_path / "missing.xml")]) == 1
    out = capsys.readouterr()
    assert "=PASS" not in (out.out + out.err)
    assert "=FAIL" in out.err


def test_cli_missing_argument_denied(capsys):
    assert main([]) == 2
    assert "=FAIL" in capsys.readouterr().err


def test_allowed_pytest_junit_classname_variants(tmp_path):
    assert CLASSNAME in ALLOWED_CLASSNAMES
    path = report(tmp_path, only_required=True)
    tree = ElementTree.parse(path)
    for case in tree.iter("testcase"):
        case.set("classname", "test_phase1_review_identity")
    tree.write(path)
    assert verify_required_cases(path) == REQUIRED_CASES
