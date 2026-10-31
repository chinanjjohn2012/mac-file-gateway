"""PR101 P005 pure T0 marker-aware base dependency graph adversarial tests.

No external HTTP, Pipenv import, Go compiler, native T1, or new Wheel install.
Packaging parser is imported lazily by evaluate_base_graph; in native CI it
must be sourced from the already attested original R004 packaging wheel.
"""
from __future__ import annotations

import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.lbe_pipenv_p005_closure import (
    ADDITIONAL_SOURCE_ONLY, EXPECTED, NEW_SIX, P005Error,
    evaluate_base_graph,
)


# P004 first attests all seven installed RECORDs. Under Python -I -S,
# reuse ONLY the pre-attested private packaging 26.3 for PEP 508 parsing.
# Linux pytest uses the preattested original R004 CI wheelhouse instead.
_private = Path(os.environ.get("RUNNER_TEMP", "/nonexistent-runner-temp"))
_private = _private / "lbe-p004-private-site"
if _private.is_dir():
    from tools.lbe_pipenv_p004_import_probe import verify_installed
    verify_installed(
        _private, {name: vals[0] for name, vals in EXPECTED.items()
                   if name not in ("pipenv", "certifi")})
    sys.path.insert(0, str(_private))


def env():
    return {
        "python_version": "3.13",
        "python_full_version": "3.13.17",
        "implementation_name": "cpython",
        "platform_machine": "arm64",
        "sys_platform": "darwin",
        "platform_system": "Darwin",
        "os_name": "posix",
        "extra": "",
    }


def metadata():
    reqs = {
        "pipenv": [
            "certifi", "packaging>=22", "setuptools>=67",
            "virtualenv>=21.14.6",
            'black>=25; extra == "dev"',
        ],
        "virtualenv": [
            "distlib<1,>=0.4.3",
            'filelock<5,>=3.24.2; python_version >= "3.10"',
            'filelock==3.19.1; python_version < "3.10"',
            "packaging>=26.3", "platformdirs>=4.4,<5",
            "python-discovery>=1.6.1",
            'typing-extensions>=4.16; python_version < "3.11"',
        ],
        "python-discovery": ["filelock>=3.15.4"],
        "setuptools": [
            'jaraco.functools>=4; extra == "core"',
            'build[virtualenv]>=1; extra == "test"',
        ],
    }
    return {
        name: {
            "name": name, "version": vals[0],
            "requires_dist": reqs.get(name, []),
            "requires_python": None if name == "distlib" else ">=3.10",
        }
        for name, vals in EXPECTED.items()
    }


class RuntimeGraphT0(unittest.TestCase):
    def test_exact_nine_runtime_base_graph_with_inactive_extras(self):
        checked = evaluate_base_graph(metadata(), env())
        self.assertEqual(
            checked["base_requires_dist_marker_graph"],
            "SATISFIED_FOR_EXPLICIT_EXTRAS_EMPTY")
        self.assertEqual(set(checked["runtime_distributions"]), set(EXPECTED))
        self.assertEqual(checked["python_requires_undeclared"], ["distlib"])
        self.assertEqual(checked["python313_full_compatibility"], "NOT_PROVEN")
        self.assertGreater(len(checked["active_requirements"]), 5)
        self.assertGreater(len(checked["inactive_optional_or_platform_requirements"]), 2)
        self.assertEqual(checked["full_Pipenv_native_T1"], "NOT_RUN")

    def test_frozen_nine_sources_only_six_plus_two_original_and_primary(self):
        self.assertEqual(len(EXPECTED), 9)
        self.assertEqual(set(ADDITIONAL_SOURCE_ONLY), {"pipenv", "certifi"})
        self.assertEqual(len(NEW_SIX), 6)
        self.assertNotIn("packaging", NEW_SIX)
        self.assertNotIn("pipenv", NEW_SIX)

    def test_unlocked_active_requirement_fails_closed(self):
        m = metadata()
        m["pipenv"]["requires_dist"].append("rogue-thing>=1")
        with self.assertRaisesRegex(P005Error, "unlocked active"):
            evaluate_base_graph(m, env())

    def test_disallowed_version_conflict_fails_closed(self):
        m = metadata()
        m["virtualenv"]["requires_dist"][0] = "distlib>=0.5"
        with self.assertRaisesRegex(P005Error, "does not satisfy"):
            evaluate_base_graph(m, env())

    def test_python_requires_version_conflict_fails_closed(self):
        m = metadata()
        m["distlib"]["requires_python"] = ">=3.14"
        with self.assertRaisesRegex(P005Error, "Python version outside"):
            evaluate_base_graph(m, env())

    def test_extra_marked_unknown_not_installed_by_default(self):
        m = metadata()
        m["pipenv"]["requires_dist"].append(
            'unapproved[feature]>=1; extra == "dev"')
        checked = evaluate_base_graph(m, env())
        self.assertTrue(any(
            "unapproved" in row["raw"]
            for row in checked["inactive_optional_or_platform_requirements"]))

    def test_extra_marker_or_python_condition_evaluates_true(self):
        m = metadata()
        m["pipenv"]["requires_dist"].append(
            'unapproved>=1; extra == "dev" or python_version >= "3.10"')
        with self.assertRaisesRegex(P005Error, "unlocked active"):
            evaluate_base_graph(m, env())

    def test_active_dependency_extras_cannot_silently_expand_scope(self):
        m = metadata()
        m["pipenv"]["requires_dist"].append("packaging[docs]>=22")
        with self.assertRaisesRegex(P005Error, "activates unknown extra"):
            evaluate_base_graph(m, env())

    def test_direct_url_requirements_are_denied(self):
        m = metadata()
        m["pipenv"]["requires_dist"].append(
            "filelock @ https://untrusted.example/dummy.whl")
        with self.assertRaisesRegex(P005Error, "direct-URL"):
            evaluate_base_graph(m, env())

    def test_bad_requirement_syntax_does_not_disappear(self):
        m = metadata()
        m["virtualenv"]["requires_dist"][0] = "distlib>=???"
        with self.assertRaisesRegex(P005Error, "invalid Requires-Dist"):
            evaluate_base_graph(m, env())

    def test_missing_metadata_distribution_fails(self):
        m = metadata()
        m.pop("filelock")
        with self.assertRaisesRegex(P005Error, "platform/identity scope|source distribution|runtime graph"):
            evaluate_base_graph(m, env())

    def test_wrong_runtime_platform_is_rejected(self):
        for name, value in (("sys_platform", "linux"),
                            ("platform_machine", "x86_64"),
                            ("python_version", "3.14"),
                            ("extra", "dev")):
            with self.subTest(name=name):
                e = env()
                e[name] = value
                with self.assertRaisesRegex(P005Error, "platform/identity"):
                    evaluate_base_graph(metadata(), e)

    def test_unreachable_pinned_distribution_is_not_silently_accepted(self):
        m = metadata()
        m["pipenv"]["requires_dist"].remove("setuptools>=67")
        with self.assertRaisesRegex(P005Error, "unreachable"):
            evaluate_base_graph(m, env())

    def test_cyclic_pinned_dependency_does_not_loop(self):
        m = metadata()
        m["distlib"]["requires_dist"].append("pipenv>=2026.10.4")
        result = evaluate_base_graph(m, env())
        self.assertEqual(len(result["runtime_distributions"]), 9)

    def test_missing_requires_python_does_not_become_compatibility_pass(self):
        m = metadata()
        m["platformdirs"]["requires_python"] = None
        result = evaluate_base_graph(m, env())
        self.assertEqual(
            result["python_requires_undeclared"], ["distlib", "platformdirs"])
        self.assertEqual(result["python313_full_compatibility"], "NOT_PROVEN")


if __name__ == "__main__":
    unittest.main(verbosity=2)
