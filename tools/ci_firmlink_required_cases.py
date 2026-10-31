"""Fail closed unless all six mandatory real Darwin firmlink cases passed.

Inspect pytest's JUnit report from an approved disposable macOS runner.  Optional
case-folding and Unicode-normalization cases may skip, but must never compensate
for missing, skipped, failed or duplicated mandatory physical checks.
"""
from __future__ import annotations

from pathlib import Path
import sys
from xml.etree import ElementTree


REQUIRED_CASES = frozenset(
    {
        *(
            "test_native_firmlink_overlap_is_rejected_before_gateway_construction"
            f"[{kind}]"
            for kind in ("same", "child", "parent", "config", "runtime")
        ),
        "test_native_default_inventory_rejects_active_package_alias",
    }
)
ALLOWED_CLASSNAMES = frozenset(
    {"tests.test_phase1_review_identity", "test_phase1_review_identity"}
)
MAX_REPORT_BYTES = 262144


class MandatoryFirmlinkCaseError(ValueError):
    """The six physical identity tests were not each verified as passed."""


def verify_required_cases(report_path: Path) -> frozenset[str]:
    """Read one bounded JUnit report; require six exact unique successful cases."""
    with Path(report_path).open("rb") as stream:
        source = stream.read(MAX_REPORT_BYTES + 1)
    if not source or len(source) > MAX_REPORT_BYTES:
        raise MandatoryFirmlinkCaseError("empty_or_oversized_report")
    try:
        root = ElementTree.fromstring(source)
    except ElementTree.ParseError as exc:
        raise MandatoryFirmlinkCaseError("malformed_junit_xml") from exc
    if root.tag not in {"testsuites", "testsuite"}:
        raise MandatoryFirmlinkCaseError("invalid_junit_root")

    passed: set[str] = set()
    for case in root.iter("testcase"):
        name = case.get("name")
        if name not in REQUIRED_CASES:
            continue
        if case.get("classname") not in ALLOWED_CLASSNAMES:
            raise MandatoryFirmlinkCaseError("required_case_wrong_module:" + name)
        if name in passed:
            raise MandatoryFirmlinkCaseError("duplicate_required_case:" + name)
        if case.get("status", "run") != "run" or any(
            case.find(tag) is not None for tag in ("skipped", "failure", "error")
        ):
            raise MandatoryFirmlinkCaseError("required_case_not_passed:" + name)
        passed.add(name)

    absent = REQUIRED_CASES - passed
    if absent:
        raise MandatoryFirmlinkCaseError("missing_required_cases:" + ",".join(sorted(absent)))
    return frozenset(passed)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("LBE_MACOS_FIRMLINK_T1_REQUIRED_SIX=FAIL usage", file=sys.stderr)
        return 2
    try:
        cases = verify_required_cases(Path(args[0]))
    except (OSError, MandatoryFirmlinkCaseError) as exc:
        print("LBE_MACOS_FIRMLINK_T1_REQUIRED_SIX=FAIL " + str(exc), file=sys.stderr)
        return 1
    print("LBE_MACOS_FIRMLINK_T1_REQUIRED_SIX=PASS count=" + str(len(cases)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
