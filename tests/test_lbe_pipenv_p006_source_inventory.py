"""PR101 P006 fake-Wheel source inventory T0; NEVER execute wheel contents."""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.lbe_pipenv_p005_closure import EXPECTED
from tools.lbe_pipenv_p006_source_inventory import (
    InventoryError, MAX_AST_SOURCE_BYTES, inventory_wheel, main, source_path,
)

DISTLIB = EXPECTED["distlib"]
NAME = DISTLIB[1]


def make_fake(path: Path, contents: dict[str, bytes],
              *, invalid_hash: bool = False, native_link: bool = False) -> tuple:
    prefix = "distlib-0.4.4.dist-info/"
    files = {
        "distlib/__init__.py": (
            b"raise RuntimeError('would be unsafe to execute source!')\n"
        ),
        prefix + "METADATA": b"Metadata-Version: 2.1\nName: distlib\nVersion: 0.4.4\n",
        prefix + "WHEEL": b"Wheel-Version: 1.0\nTag: py3-none-any\n",
    }
    files.update(contents)
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    for name, content in files.items():
        checksum = base64.urlsafe_b64encode(
            hashlib.sha256(content).digest()).rstrip(b"=").decode()
        if invalid_hash and name == "distlib/__init__.py":
            checksum = "x" * 43
        writer.writerow([name, "sha256=" + checksum, str(len(content))])
    writer.writerow([prefix + "RECORD", "", ""])
    with zipfile.ZipFile(path, mode="w",
                         compression=zipfile.ZIP_DEFLATED) as z:
        for name, content in files.items():
            if native_link and name == "distlib/native.so":
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                z.writestr(info, b"target")
            else:
                z.writestr(name, content)
        z.writestr(prefix + "RECORD", out.getvalue())
    raw = path.read_bytes()
    return ("0.4.4", NAME, hashlib.sha256(raw).hexdigest())


class SourceInventoryT0(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.root = Path(t.name).resolve(strict=True)
        self.wheel = self.root / NAME

    def _source(self, entries=None, **kwargs):
        expected = make_fake(self.wheel, entries or {}, **kwargs)
        # The test fixture SHA must be accepted only for the fake test.
        with mock.patch.dict(
                EXPECTED, {"distlib": expected}):
            result = inventory_wheel(
                self.wheel, "distlib", expected)
        return result

    def test_record_attested_full_file_manifest_positive_without_import(self):
        value = self._source({
            "distlib/network.py": (
                b"import socket\nimport os\nsubprocess.run(['false'])\n"
                b"eval('0')\n"),
            "distlib/another.pth": b"import badmodule\n",
            "benchmarks/probe.py": b"import subprocess\n",
            "distlib/native.so": b"fake native bytes never loaded",
        })
        self.assertEqual(value["distribution"], "distlib")
        self.assertEqual(value["version"], "0.4.4")
        self.assertGreaterEqual(value["file_count"], 8)
        self.assertEqual(len(value["source_files"]), value["file_count"])
        self.assertEqual(len(value["member_hash_stream_sha256"]), 64)
        self.assertTrue(value["sha256_and_RECORD_checked"])
        self.assertEqual(value["safe_code_verdict"], "NOT_ASSESSED")
        self.assertEqual(value["manual_security_source_review"], "NOT_ISSUED")
        self.assertFalse(value["wheel_imported_or_executed_by_P006"])
        signals = value["review_hint_counts"]
        self.assertGreater(signals.get("startup_or_path_hook", 0), 0)
        self.assertGreater(signals.get("native_or_compiled_member", 0), 0)
        self.assertGreater(signals.get("pipenv_benchmarks_unreviewed", 0), 0)
        self.assertGreater(signals.get("process_or_signal_call", 0), 0)
        self.assertGreater(signals.get("dynamic_eval_or_import_call", 0), 0)

    def test_untrusted_archive_python_content_is_not_executed(self):
        result = self._source({})
        self.assertFalse(result["wheel_imported_or_executed_by_P006"])
        self.assertTrue(any(x["path"] == "distlib/__init__.py"
                            for x in result["source_files"]))

    def test_python313_static_syntax_hints_are_bounded_and_never_execute(self):
        value = self._source({
            "distlib/syntax_ok.py": b"raise RuntimeError('DO_NOT_EXECUTE')\n",
            "distlib/syntax_bad.py": b"def broken(:\\n",
            "distlib/oversize.py": b"#" * (MAX_AST_SOURCE_BYTES + 1),
            "distlib/undecodable.py": b"\xff",
        })
        hints = {row["path"]: row["manual_review_hints"]
                 for row in value["source_files"]}
        self.assertNotIn("python313_ast_unparseable",
                         hints["distlib/syntax_ok.py"])
        self.assertIn("python313_ast_unparseable",
                      hints["distlib/syntax_bad.py"])
        self.assertIn("python313_ast_skipped_size",
                      hints["distlib/oversize.py"])
        self.assertIn("non_utf8_python_source",
                      hints["distlib/undecodable.py"])
        self.assertEqual(value["python313_ast_source_byte_cap"],
                         MAX_AST_SOURCE_BYTES)
        self.assertTrue(value["python313_ast_is_only_static_syntax_hint"])
        self.assertEqual(value["python313_runtime_compatibility"],
                         "NOT_PROVEN")
        self.assertEqual(value["safe_code_verdict"], "NOT_ASSESSED")
        self.assertFalse(value["wheel_imported_or_executed_by_P006"])

    def test_overcap_and_invalid_utf8_emit_both_independent_hints(self):
        value = self._source({
            "distlib/overcap_invalid.py":
                b"\xff" + b"#" * MAX_AST_SOURCE_BYTES,
        })
        hints = next(row["manual_review_hints"]
                     for row in value["source_files"]
                     if row["path"] == "distlib/overcap_invalid.py")
        self.assertIn("non_utf8_python_source", hints)
        self.assertIn("python313_ast_skipped_size", hints)
        self.assertEqual(
            value["review_hint_counts"]["python313_ast_skipped_size"], 1)
        self.assertEqual(value["safe_code_verdict"], "NOT_ASSESSED")
        self.assertFalse(value["wheel_imported_or_executed_by_P006"])

    def test_utf8_bom_valid_source_is_parsed_but_embedded_bom_is_invalid(self):
        value = self._source({
            "distlib/valid_bom.py":
                b"\xef\xbb\xbfraise RuntimeError('NOT_EXECUTED')\n",
            "distlib/embedded_bom.py":
                b"print('ok')\n\xef\xbb\xbfprint('not executed')\n",
        })
        hints = {row["path"]: row["manual_review_hints"]
                 for row in value["source_files"]}
        self.assertNotIn("python313_ast_unparseable",
                         hints["distlib/valid_bom.py"])
        self.assertIn("python313_ast_unparseable",
                      hints["distlib/embedded_bom.py"])
        self.assertFalse(value["wheel_imported_or_executed_by_P006"])

    def test_exact_ast_byte_cap_is_still_parsed_not_skipped(self):
        value = self._source({
            "distlib/exact_cap.py": b"#" * (MAX_AST_SOURCE_BYTES - 1) + b"\n",
        })
        hints = next(row["manual_review_hints"]
                     for row in value["source_files"]
                     if row["path"] == "distlib/exact_cap.py")
        self.assertNotIn("python313_ast_skipped_size", hints)
        self.assertNotIn("python313_ast_unparseable", hints)

    def test_source_bytes_encoding_cookie_conflict_is_syntax_hint(self):
        value = self._source({
            "distlib/bom_conflicting_cookie.py":
                b"\xef\xbb\xbf# coding: latin-1\nx = 1\n",
            "distlib/bom_matching_cookie.py":
                b"\xef\xbb\xbf# coding: utf-8\nx = 1\n",
            "distlib/unknown_cookie.py":
                b"# coding: nonexistent-codec-name\nx = 1\n",
            "distlib/latin1_ascii_cookie.py":
                b"# coding: latin-1\nx = 1\n",
        })
        hints = {row["path"]: row["manual_review_hints"]
                 for row in value["source_files"]}
        for path in ("distlib/bom_conflicting_cookie.py",
                     "distlib/unknown_cookie.py"):
            self.assertIn("python313_ast_unparseable", hints[path], path)
        for path in ("distlib/bom_matching_cookie.py",
                     "distlib/latin1_ascii_cookie.py"):
            self.assertNotIn("python313_ast_unparseable", hints[path], path)
        self.assertEqual(value["safe_code_verdict"], "NOT_ASSESSED")
        self.assertEqual(value["python313_runtime_compatibility"], "NOT_PROVEN")
        self.assertFalse(value["wheel_imported_or_executed_by_P006"])

    def test_declared_source_encoding_must_reject_bytes_not_decodable(self):
        value = self._source({
            "distlib/ascii_cookie_utf8_nonascii.py":
                b"# coding: ascii\nx = '\xc3\xa9'\n",
            "distlib/utf8_cookie_utf8_nonascii.py":
                b"# coding: utf-8\nx = '\xc3\xa9'\n",
            "distlib/latin1_utf8_identifier_drift.py":
                b"# coding: latin-1\n\xcf\x80 = 1\n",
            "distlib/utf8_identifier_positive.py":
                b"# coding: utf-8\n\xcf\x80 = 1\n",
        })
        flags = {x["path"]: x["manual_review_hints"]
                 for x in value["source_files"]}
        for path in ("distlib/ascii_cookie_utf8_nonascii.py",
                     "distlib/latin1_utf8_identifier_drift.py"):
            self.assertIn("python313_ast_unparseable", flags[path], path)
        for path in ("distlib/utf8_cookie_utf8_nonascii.py",
                     "distlib/utf8_identifier_positive.py"):
            self.assertNotIn("python313_ast_unparseable", flags[path], path)
        self.assertFalse(value["wheel_imported_or_executed_by_P006"])
        self.assertEqual(value["safe_code_verdict"], "NOT_ASSESSED")

    def test_conflicting_bom_cookie_even_when_non_utf8_bytes(self):
        value = self._source({
            "distlib/bom_cookie_and_non_utf8.py":
                b"\xef\xbb\xbf# coding: latin-1\nx = '\xff'\n",
            "distlib/valid_nonutf8_latin1.py":
                b"# coding: latin-1\nx = '\xe9'\n",
        })
        flags = {x["path"]: x["manual_review_hints"]
                 for x in value["source_files"]}
        both = flags["distlib/bom_cookie_and_non_utf8.py"]
        self.assertIn("python313_ast_unparseable", both)
        self.assertIn("non_utf8_python_source", both)
        only = flags["distlib/valid_nonutf8_latin1.py"]
        self.assertIn("non_utf8_python_source", only)
        self.assertNotIn("python313_ast_unparseable", only)
        self.assertFalse(value["wheel_imported_or_executed_by_P006"])
        self.assertEqual(value["python313_runtime_compatibility"], "NOT_PROVEN")

    def test_wrong_physical_wheel_sha_denied(self):
        expected = make_fake(self.wheel, {})
        wrong = (expected[0], expected[1], "0" * 64)
        with mock.patch.dict(EXPECTED, {"distlib": wrong}):
            with self.assertRaises(ValueError):
                inventory_wheel(self.wheel, "distlib", wrong)

    def test_internal_record_mismatch_denied(self):
        expected = make_fake(self.wheel, {}, invalid_hash=True)
        with mock.patch.dict(EXPECTED, {"distlib": expected}):
            with self.assertRaises(ValueError):
                inventory_wheel(self.wheel, "distlib", expected)

    def test_traversal_member_denied_before_manifest_claim(self):
        expected = make_fake(self.wheel, {"../escaped.py": b"do not use"})
        with mock.patch.dict(EXPECTED, {"distlib": expected}):
            with self.assertRaises(ValueError):
                inventory_wheel(self.wheel, "distlib", expected)

    def test_symlink_native_member_denied(self):
        expected = make_fake(self.wheel,
                             {"distlib/native.so": b"unsafe"},
                             native_link=True)
        with mock.patch.dict(EXPECTED, {"distlib": expected}):
            with self.assertRaises(ValueError):
                inventory_wheel(self.wheel, "distlib", expected)

    def test_wrong_name_mapping_or_unknown_source_rejected(self):
        expected = make_fake(self.wheel, {})
        with self.assertRaisesRegex(InventoryError, "identity changed"):
            inventory_wheel(self.wheel, "filelock", expected)
        with self.assertRaisesRegex(InventoryError, "unapproved"):
            source_path(self.root, "not-in-lock")

    def test_source_path_bound_to_exact_preapproved_private_directory(self):
        folder = self.root / "lbe-p003-six-wheel-bytes"
        folder.mkdir(mode=0o700)
        expected = folder / NAME
        expected.write_bytes(b"synthetic source")
        self.assertEqual(source_path(self.root, "distlib"), expected)
        expected.unlink()
        outsider = self.root / "outside.whl"
        outsider.write_bytes(b"do not follow")
        expected.symlink_to(outsider)
        with self.assertRaisesRegex(InventoryError, "not regular"):
            source_path(self.root, "distlib")

    def test_missing_p005_real_graph_prevents_inventory_run(self):
        with mock.patch.dict(os.environ, {"RUNNER_TEMP": str(self.root)}):
            result = main(["--runner-temp", str(self.root)])
        self.assertEqual(result, 2)
        self.assertFalse(
            (self.root / "lbe-p006-nine-wheel-review-inventory.json").exists())

    def test_noncanonical_runner_temp_is_rejected(self):
        with mock.patch.dict(os.environ, {"RUNNER_TEMP": str(self.root)}):
            self.assertEqual(main(["--runner-temp", str(self.root / "..")]), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
