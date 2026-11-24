from contextlib import redirect_stderr, redirect_stdout
import hashlib
from http.client import IncompleteRead
from io import BytesIO, StringIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request

from refresh_allowlists import (
    _StrictHttpsRedirectHandler,
    cidr_entries,
    compile_rules,
    domain_entries,
    main,
    publish_preview,
    recently_refreshed,
)


DOMAINS = b"payload:\n  - 'example.com'\n  - '+.example.net'\n  - '+.cn'\n"
NETWORKS = b"payload:\n  - '1.0.1.0/24'\n  - '2400:3200::/32'\n"


class RefreshTests(unittest.TestCase):
    def test_domain_matching_keeps_exact_and_suffix_distinct(self):
        self.assertEqual(
            domain_entries(DOMAINS),
            ["full:example.com", "domain:example.net", "domain:cn"],
        )

    def test_matches_both_ip_families(self):
        self.assertEqual(cidr_entries(NETWORKS), ["1.0.1.0/24", "2400:3200::/32"])

    def test_overbroad_or_invalid_prefix_fails(self):
        for value in ("0.0.0.0/0", "128.0.0.0/1", "1.0.1.5/24", "1.0.1.5",
                      "198.18.0.0/15", "fc00::/18", "10.2.0.0/16"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                cidr_entries(f"payload:\n  - '{value}'\n".encode())

    def test_rejects_wrong_structure_and_domain(self):
        for raw in (b"data:\n  - 'example.com'", b"payload:\n", b"payload:\n  - example.com",
                    b"payload:\n  - '*.example.com'", b"payload:\n  - 'https://example.com'",
                    b"payload:\n  - '1.1.1.1'"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                domain_entries(raw)

    def test_proxy_category_preempts_both_lists_and_no_direct_catch_all(self):
        rules = compile_rules(domain_entries(DOMAINS), cidr_entries(NETWORKS))
        self.assertEqual(rules[2]["domain"], ["geosite:geolocation-!cn"])
        self.assertEqual([rule["outboundTag"] for rule in rules], [
            "direct", "direct", "proxy", "direct", "direct", "proxy",
        ])
        self.assertEqual(rules[-1]["port"], "0-65535")

    def test_blocks_http_downgrade_and_cross_host_redirects(self):
        handler = _StrictHttpsRedirectHandler()
        req = Request("https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/direct.txt")
        for bad_target in (
            "http://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/direct.txt",
            "https://evil.example.com/direct.txt",
        ):
            with self.subTest(target=bad_target), self.assertRaises(HTTPError):
                handler.redirect_request(req, BytesIO(), 302, "Found", {}, bad_target)

    def test_enforces_expected_sha256_digests(self):
        with TemporaryDirectory() as folder, redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            root = Path(folder)
            output = root / "previews"
            good_direct = hashlib.sha256(DOMAINS).hexdigest()
            good_cidr = hashlib.sha256(NETWORKS).hexdigest()
            with patch("refresh_allowlists.read_payload", side_effect=[DOMAINS, NETWORKS]):
                self.assertEqual(
                    main([
                        "--output-directory", str(output),
                        "--expected-direct-sha256", "0" * 64,
                        "--expected-cidr-sha256", good_cidr,
                    ]),
                    1,
                )
            self.assertFalse(output.exists())
            with patch("refresh_allowlists.read_payload", side_effect=[DOMAINS, NETWORKS]):
                self.assertEqual(
                    main([
                        "--output-directory", str(output),
                        "--expected-direct-sha256", good_direct,
                        "--expected-cidr-sha256", good_cidr,
                    ]),
                    0,
                )
            self.assertEqual(len(list(output.iterdir())), 1)

    def test_failed_conversion_keeps_previous_preview(self):
        with TemporaryDirectory() as folder, redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            root = Path(folder)
            (root / "direct.txt").write_bytes(DOMAINS)
            (root / "cncidr.txt").write_bytes(NETWORKS)
            output = root / "previews"
            args = ["--from-directory", str(root), "--output-directory", str(output)]
            self.assertEqual(main(args), 0)
            preview, = output.iterdir()
            old_bytes = preview.read_bytes()
            self.assertEqual(json.loads(old_bytes)[-1]["outboundTag"], "proxy")
            with patch("refresh_allowlists.read_payload", side_effect=OSError("unavailable")):
                self.assertEqual(main(args), 1)
            with patch("refresh_allowlists.read_payload", side_effect=IncompleteRead(b"partial")):
                self.assertEqual(main(args), 1)
            (root / "cncidr.txt").write_bytes(b"payload:\n")
            self.assertEqual(main(args), 1)
            self.assertEqual(list(output.iterdir()), [preview])
            self.assertEqual(preview.read_bytes(), old_bytes)

    def test_daily_cadence_skips_refresh_of_recent_preview(self):
        with TemporaryDirectory() as folder, redirect_stdout(StringIO()):
            args = ["--output-directory", folder]
            with patch("refresh_allowlists.read_payload", side_effect=[DOMAINS, NETWORKS]):
                self.assertEqual(main(args), 0)
            with patch("refresh_allowlists.read_payload", side_effect=AssertionError("unexpected fetch")):
                self.assertEqual(main(args + ["--max-age-hours", "24"]), 0)

    def test_failed_publish_closes_and_removes_temporary_file(self):
        with TemporaryDirectory() as folder:
            output = Path(folder) / "previews"
            original = publish_preview(output, [{"prior": True}])
            original_bytes = original.read_bytes()
            with patch("refresh_allowlists.json.dump", side_effect=OSError("disk full")) as dump:
                with self.assertRaisesRegex(OSError, "disk full"):
                    publish_preview(output, [])
            self.assertTrue(dump.call_args.args[1].closed)
            self.assertEqual(list(output.iterdir()), [original])
            self.assertEqual(original.read_bytes(), original_bytes)

    def test_disappearing_preview_does_not_abort_freshness_check(self):
        with TemporaryDirectory() as folder:
            root = Path(folder)
            candidate = root / "routing-20261120T010203000000Z-deadbeef.json"
            with patch.object(Path, "glob", return_value=[candidate]):
                self.assertFalse(recently_refreshed(root, 24))


if __name__ == "__main__":
    unittest.main()
