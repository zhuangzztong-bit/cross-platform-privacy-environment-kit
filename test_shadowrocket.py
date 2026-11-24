from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from mobile.validate_shadowrocket import validate


MOBILE = Path(__file__).resolve().parent / "mobile"
TEMPLATE = MOBILE / "shadowrocket-local-proxy.conf"


class ShadowrocketTests(unittest.TestCase):
    def setUp(self):
        self.profile = TEMPLATE.read_text(encoding="utf-8-sig")

    def test_bundled_profile_captures_ipv6_and_has_eleven_local_exceptions(self):
        self.assertEqual(validate(self.profile), 11)

    def test_allows_verified_ipv6_proxy_catchall_alternative(self):
        proxied_v6 = self.profile.replace(
            "IP-CIDR6,::/0,REJECT,no-resolve",
            "IP-CIDR6,::/0,PROXY,no-resolve",
        )
        self.assertEqual(validate(proxied_v6), 11)

    def test_each_required_direct_rule_is_checked(self):
        lines = self.profile.splitlines()
        for index, line in enumerate(lines):
            if ",DIRECT" in line:
                with self.subTest(rule=line):
                    with self.assertRaisesRegex(ValueError, "missing required local direct"):
                        validate("\n".join(lines[:index] + lines[index + 1:]))

    def test_cli_rejects_unsafe_ipv6_false_and_incomplete_profiles(self):
        with tempfile.TemporaryDirectory() as temporary:
            profile = Path(temporary) / "incomplete.conf"
            profile.write_text("[General]\nipv6 = false\n[Rule]\nFINAL,PROXY\n", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, "-B", str(MOBILE / "validate_shadowrocket.py"), str(profile)],
                capture_output=True, text=True, timeout=10,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("ipv6 = false is unsafe", result.stderr)
        self.assertNotIn("PASS", result.stdout)

    def test_changed_rules_missing_dns_hijack_and_bad_order_are_rejected(self):
        edits = (
            ("10.0.0.0/8", "10.0.0.0/9"),
            ("10.0.0.0/8", "0.0.0.0/0"),
            (",no-resolve", ""),
            ("ipv6 = true", "ipv6 = false"),
            ("hijack-dns = *:53\n", ""),
            ("IP-CIDR6,::/0,REJECT,no-resolve\n", ""),
            ("IP-CIDR6,::/0,REJECT,no-resolve", "IP-CIDR6,::/0,DIRECT,no-resolve"),
            ("FINAL,PROXY", "FINAL,DIRECT"),
            ("FINAL,PROXY", "FINAL,PROXY\nDOMAIN,localhost,DIRECT"),
            ("DOMAIN,localhost,DIRECT", "DOMAIN,localhost,DIRECT\nDOMAIN,localhost,DIRECT"),
        )
        for old, new in edits:
            with self.subTest(replacement=new), self.assertRaises(ValueError):
                validate(self.profile.replace(old, new))


if __name__ == "__main__":
    unittest.main()
