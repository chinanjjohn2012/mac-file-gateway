"""PR101 P008 source-only per-hop HTTPS origin negatives using fake openers.

No network requests, third-party imports, Go/Pipenv execution or OS signals.
Every denied intermediate hop must be rejected BEFORE fake open() is called.
"""
from __future__ import annotations

from io import BytesIO
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from urllib.error import HTTPError

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.lbe_p008_https_source_fetch import (
    GO_URL, GO_NAME, META_URL, META_NAME, WHEEL_NAME,
    P008Error, require_allowed_url, acquire, main,
)


class Reply:
    def __init__(self, url, body: bytes):
        self.url = url
        self.source = BytesIO(body)
        self.status = 200

    def geturl(self):
        return self.url

    def read(self, count=-1):
        return self.source.read(count)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.source.close()


class FakeOpener:
    def __init__(self, mapping):
        self.mapping = mapping
        self.called = []

    def open(self, request, timeout):
        url = request.full_url
        self.called.append(url)
        outcome = self.mapping[url]
        if isinstance(outcome, str):
            raise HTTPError(url, 302, "fake redirect",
                            {"Location": outcome}, None)
        return Reply(url, outcome)


class PerHopOriginT0(unittest.TestCase):
    def setUp(self):
        context = tempfile.TemporaryDirectory()
        self.addCleanup(context.cleanup)
        self.root = Path(context.name).resolve(strict=True)

    def test_exact_permitted_source_origin_shapes(self):
        self.assertEqual(require_allowed_url("go", GO_URL), "go.dev")
        self.assertEqual(
            require_allowed_url(
                "go", "https://dl.google.com/go/" + GO_NAME), "dl.google.com")
        self.assertEqual(
            require_allowed_url("metadata", META_URL), "pypi.org")
        self.assertEqual(
            require_allowed_url(
                "wheel", "https://files.pythonhosted.org/packages/a/b/c/" +
                WHEEL_NAME), "files.pythonhosted.org")

    def test_reject_approved_to_evil_to_approved_before_evil_contact(self):
        intermediate = "https://evil.example.org/pass-through"
        trusted = "https://dl.google.com/go/" + GO_NAME
        fake = FakeOpener({
            GO_URL: intermediate,
            intermediate: trusted,
            trusted: b"never downloaded",
        })
        out = self.root / GO_NAME
        with self.assertRaisesRegex(P008Error, "unapproved"):
            acquire("go", GO_URL, out, opener=fake)
        self.assertEqual(fake.called, [GO_URL])
        self.assertFalse(out.exists())

    def test_reject_lookalike_host_before_contact(self):
        fake = FakeOpener({
            GO_URL: "https://go.dev.attacker.invalid/dl/" + GO_NAME,
        })
        with self.assertRaisesRegex(P008Error, "unapproved"):
            acquire("go", GO_URL, self.root / GO_NAME, opener=fake)
        self.assertEqual(fake.called, [GO_URL])

    def test_reject_unreviewed_approved_host_path(self):
        for url in [
            "https://dl.google.com/private/" + GO_NAME,
            "https://storage.googleapis.com/other/" + GO_NAME,
            "https://go.dev/dl/other.tar.gz",
            "https://files.pythonhosted.org/packages/a/b/evil.whl",
        ]:
            with self.subTest(url=url):
                with self.assertRaises(P008Error):
                    require_allowed_url("go", url)

    def test_reject_http_userinfo_query_port_fragment_and_percent(self):
        urls = [
            "http://go.dev/dl/" + GO_NAME,
            "https://go.dev@evil.invalid/dl/" + GO_NAME,
            "https://go.dev:444/dl/" + GO_NAME,
            "https://go.dev/dl/" + GO_NAME + "?next=evil",
            "https://go.dev/dl/" + GO_NAME + "#src",
            "https://go.dev/dl/%2e%2e/" + GO_NAME,
            "https://go.dev/dl/../" + GO_NAME,
            "https://go.dev//dl/" + GO_NAME,
        ]
        for url in urls:
            with self.subTest(url=url), self.assertRaises(P008Error):
                require_allowed_url("go", url)

    def test_disallow_metadata_redirect_to_wheel_domain(self):
        fake = FakeOpener({
            META_URL: "https://files.pythonhosted.org/packages/a/b/c/" +
                      WHEEL_NAME,
        })
        with self.assertRaisesRegex(P008Error, "unapproved"):
            acquire("metadata", META_URL, self.root / META_NAME,
                    opener=fake)
        self.assertEqual(fake.called, [META_URL])

    def test_metadata_exact_source_happy_path_fake_bytes_only(self):
        body = json.dumps({"urls": [], "info": {"version": "2026.10.4"}}).encode()
        fake = FakeOpener({META_URL: body})
        output = self.root / META_NAME
        report = acquire("metadata", META_URL, output, opener=fake)
        self.assertEqual(output.read_bytes(), body)
        self.assertEqual(report["redirect_count"], 0)
        self.assertEqual(report["source_host_chain"], ["pypi.org"])
        self.assertFalse(report["verified_go_or_wheel_hash"])
        self.assertTrue(report["no_external_code_executed"])

    def test_exact_allowed_redirect_followed_by_wrong_go_bytes_fail_closed(self):
        trusted = "https://dl.google.com/go/" + GO_NAME
        fake = FakeOpener({
            GO_URL: trusted,
            trusted: b"synthetic-not-a-real-go-archive",
        })
        with self.assertRaisesRegex(P008Error, "actual bytes"):
            acquire("go", GO_URL, self.root / GO_NAME, opener=fake)
        self.assertEqual(fake.called, [GO_URL, trusted])

    def test_even_approved_redirect_loop_is_rejected(self):
        trusted = "https://dl.google.com/go/" + GO_NAME
        fake = FakeOpener({
            GO_URL: trusted,
            trusted: GO_URL,
        })
        with self.assertRaisesRegex(P008Error, "cycle"):
            acquire("go", GO_URL, self.root / GO_NAME, opener=fake)
        self.assertEqual(fake.called, [GO_URL, trusted])

    def test_response_auto_redirect_without_validation_rejected(self):
        fake = FakeOpener({META_URL: b"dummy"})
        original = fake.open

        def unacceptable(request, timeout):
            return Reply("https://evil.example.org/unreviewed", b"dummy")

        fake.open = unacceptable
        with self.assertRaisesRegex(P008Error, "automatic redirect"):
            acquire("metadata", META_URL, self.root / META_NAME,
                    opener=fake)
        self.assertFalse((self.root / META_NAME).exists())
        fake.open = original

    def test_existing_source_file_and_symlink_cannot_be_overwritten(self):
        dest = self.root / META_NAME
        dest.write_text("don't replace")
        with self.assertRaisesRegex(P008Error, "empty private"):
            acquire("metadata", META_URL, dest, opener=FakeOpener({}))
        self.assertEqual(dest.read_text(), "don't replace")
        dest.unlink()
        dest.symlink_to(self.root / "no-target")
        with self.assertRaisesRegex(P008Error, "empty private"):
            acquire("metadata", META_URL, dest, opener=FakeOpener({}))

    def test_main_refuses_untrusted_runner_root_before_network(self):
        with mock.patch.dict(os.environ, {"RUNNER_TEMP": str(self.root)}):
            self.assertEqual(
                main(["--kind", "go", "--runner-temp", str(self.root / "..")]),
                2)
        self.assertFalse((self.root / GO_NAME).exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
