import contextlib
from io import StringIO
import ipaddress
import json
from pathlib import Path
import tempfile
import unittest

from build_routing import (
    ANTHROPIC_IPV4_CIDRS,
    ANTHROPIC_IPV6_BLOCK,
    CLAUDE_ECOSYSTEM_DOMAINS,
    build_rules,
    main,
    unique_json_object,
    validate_rules,
)


ROOT = Path(__file__).resolve().parent


class RoutingTests(unittest.TestCase):
    def test_default_order_and_coverage(self):
        rules = build_rules()
        self.assertEqual(rules[0]["domain"], ["geosite:private"])
        self.assertIn("100.64.0.0/10", rules[1]["ip"])
        direct_networks = [ipaddress.ip_network(value) for value in rules[1]["ip"]]
        for fake_ip_range in ("198.18.0.0/15", "fc00::/18"):
            fake_network = ipaddress.ip_network(fake_ip_range)
            self.assertFalse(any(network.overlaps(fake_network) for network in direct_networks))
        self.assertEqual(rules[2]["domain"], ["geosite:cn"])
        self.assertEqual(rules[3]["ip"], ["geoip:cn"])
        self.assertEqual((rules[-1]["outboundTag"], rules[-1]["port"]), ("proxy", "0-65535"))
        validate_rules(rules)

    def test_bundled_template_validates(self):
        template_path = ROOT / "routing-template.json"
        if template_path.is_file():
            with contextlib.redirect_stdout(StringIO()):
                self.assertEqual(main(["validate", str(template_path)]), 0)

    def test_optional_external_rule_precedes_domestic(self):
        rules = build_rules(external_first_xray=True)
        self.assertEqual(rules[2]["domain"], ["geosite:geolocation-!cn"])
        self.assertEqual(rules[2]["outboundTag"], "proxy")
        self.assertEqual(rules[3]["domain"], ["geosite:cn"])
        validate_rules(rules, external_first_xray=True)
        with self.assertRaises(ValueError):
            validate_rules(rules)

    def test_global_proxy_mode_omits_domestic_split_tunnel(self):
        rules = build_rules(global_proxy=True)
        self.assertEqual(len(rules), 3)
        self.assertEqual([r["outboundTag"] for r in rules], ["direct", "direct", "proxy"])
        validate_rules(rules, global_proxy=True)
        with self.assertRaises(ValueError):
            validate_rules(rules)

    def test_claude_ecosystem_split_and_global_presets(self):
        split_rules = build_rules(claude_ecosystem=True)
        self.assertEqual(len(split_rules), 9)
        self.assertEqual((split_rules[0]["network"], split_rules[0]["port"], split_rules[0]["outboundTag"]), ("udp", "443", "block"))
        self.assertEqual(split_rules[1]["ip"], ANTHROPIC_IPV6_BLOCK)
        self.assertEqual(split_rules[1]["outboundTag"], "block")
        self.assertEqual(split_rules[2]["domain"], CLAUDE_ECOSYSTEM_DOMAINS)
        self.assertEqual(split_rules[2]["outboundTag"], "proxy")
        self.assertIn("domain:claudemcpcontent.com", split_rules[2]["domain"])
        self.assertNotIn("domain:claudemcpclient.com", split_rules[2]["domain"])
        self.assertEqual(split_rules[3]["ip"], ANTHROPIC_IPV4_CIDRS)
        self.assertEqual(split_rules[3]["outboundTag"], "proxy")
        self.assertEqual(split_rules[4]["domain"], ["geosite:private"])
        self.assertEqual(split_rules[-1]["outboundTag"], "proxy")
        validate_rules(split_rules, claude_ecosystem=True)
        with self.assertRaises(ValueError):
            validate_rules(split_rules)

        global_rules = build_rules(global_proxy=True, claude_ecosystem=True)
        self.assertEqual(len(global_rules), 7)
        self.assertEqual(
            [r["outboundTag"] for r in global_rules],
            ["block", "block", "proxy", "proxy", "direct", "direct", "proxy"],
        )
        validate_rules(global_rules, global_proxy=True, claude_ecosystem=True)

    def test_bundled_claude_presets_and_doh_output(self):
        split_preset = ROOT / "routing-claude-ecosystem.json"
        global_preset = ROOT / "routing-claude-global.json"
        if split_preset.is_file():
            with contextlib.redirect_stdout(StringIO()):
                self.assertEqual(main(["validate", str(split_preset), "--claude-ecosystem"]), 0)
        if global_preset.is_file():
            with contextlib.redirect_stdout(StringIO()):
                self.assertEqual(main(["validate", str(global_preset), "--global-proxy", "--claude-ecosystem"]), 0)
        buf = StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(main(["print-doh-domains"]), 0)
        lines = [line.strip() for line in buf.getvalue().splitlines() if line.strip()]
        self.assertEqual(lines, CLAUDE_ECOSYSTEM_DOMAINS)

    def test_unsafe_catch_all_is_rejected(self):
        rules = build_rules()
        rules[-1]["outboundTag"] = "direct"
        with self.assertRaises(ValueError):
            validate_rules(rules)

    def test_unexpected_filter_or_non_boolean_rule_fails(self):
        rules = build_rules()
        rules[-1]["inboundTag"] = ["http"]
        with self.assertRaises(ValueError):
            validate_rules(rules)
        rules = build_rules()
        rules[-1]["enabled"] = 1
        with self.assertRaises(ValueError):
            validate_rules(rules)

    def test_rule_order_is_validated(self):
        rules = build_rules()
        rules[0], rules[-1] = rules[-1], rules[0]
        with self.assertRaises(ValueError):
            validate_rules(rules)

    def test_duplicate_json_fields_are_rejected(self):
        with self.assertRaises(ValueError):
            json.loads('{"outboundTag":"proxy","outboundTag":"direct"}', object_pairs_hook=unique_json_object)

    def test_cli_round_trip_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "routing.json"
            with contextlib.redirect_stdout(StringIO()), contextlib.redirect_stderr(StringIO()):
                self.assertEqual(main(["generate", str(path)]), 0)
                self.assertEqual(main(["validate", str(path)]), 0)
                data = path.read_bytes()
                with self.assertRaises(SystemExit) as raised:
                    main(["generate", str(path), "--external-first-xray"])
                self.assertEqual(raised.exception.code, 1)
                self.assertEqual(path.read_bytes(), data)


if __name__ == "__main__":
    unittest.main()
