import copy
from pathlib import Path
import subprocess
import sys
import unittest

from mobile.validate_android_v2rayng import read_safe_json, validate_v2rayng_rules


MOBILE = Path(__file__).resolve().parent / "mobile"
RULE_FILE = MOBILE / "android-v2rayng-claude-routing.json"
PRETTY_FILE = MOBILE / "android-v2rayng-claude-routing.pretty.json"


class AndroidV2rayNGTests(unittest.TestCase):
    def setUp(self):
        self.rules = read_safe_json(RULE_FILE)

    def test_bundled_minified_and_pretty_rules_validate(self):
        self.assertEqual(validate_v2rayng_rules(self.rules), 13)
        pretty = read_safe_json(PRETTY_FILE)
        self.assertEqual(pretty, self.rules)
        result = subprocess.run(
            [sys.executable, "-B", str(MOBILE / "validate_android_v2rayng.py"), str(RULE_FILE)],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PASS: 13 rules", result.stdout)

    def test_rejects_typo_domain_and_direct_catchall(self):
        bad_typo = copy.deepcopy(self.rules)
        for rule in bad_typo:
            if "domain" in rule and "domain:claudemcpcontent.com" in rule["domain"]:
                rule["domain"].append("domain:claudemcpclient.com")
        with self.assertRaisesRegex(ValueError, "typo domain"):
            validate_v2rayng_rules(bad_typo)

        bad_catchall = copy.deepcopy(self.rules)
        bad_catchall.append({"remarks": "bad", "port": "0-65535", "outboundTag": "direct", "enabled": True})
        with self.assertRaisesRegex(ValueError, "catch-all"):
            validate_v2rayng_rules(bad_catchall)

    def test_rejects_claude_after_cn_direct(self):
        reordered = copy.deepcopy(self.rules)
        claude_idx = next(i for i, r in enumerate(reordered) if "domain:claude.ai" in (r.get("domain") or []))
        cn_idx = next(i for i, r in enumerate(reordered) if "geosite:cn" in (r.get("domain") or []))
        reordered[claude_idx], reordered[cn_idx] = reordered[cn_idx], reordered[claude_idx]
        with self.assertRaisesRegex(ValueError, "precede domestic"):
            validate_v2rayng_rules(reordered)


if __name__ == "__main__":
    unittest.main()
