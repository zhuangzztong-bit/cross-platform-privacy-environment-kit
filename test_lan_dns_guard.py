from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
import unittest

import build_lan_dns_guard as lan_dns


class LanDnsGuardPlanTests(unittest.TestCase):
    def test_builds_four_port53_rules_covering_rfc1918_cgnat_ula_linklocal(self):
        plan = lan_dns.build_plan(["WLAN 2", "以太网"])
        self.assertEqual(plan["SchemaVersion"], 1)
        self.assertEqual(plan["InterfaceAliases"], ["WLAN 2", "以太网"])
        self.assertEqual(plan["RuleCount"], 4)
        by_name = {rule["Name"]: rule for rule in plan["Rules"]}
        self.assertEqual(set(by_name), {
            "CPPEK-LanDnsGuard-v1-IPv4-UDP53",
            "CPPEK-LanDnsGuard-v1-IPv4-TCP53",
            "CPPEK-LanDnsGuard-v1-IPv6-UDP53",
            "CPPEK-LanDnsGuard-v1-IPv6-TCP53",
        })
        for suffix in ("IPv4-UDP53", "IPv4-TCP53"):
            rule = by_name["CPPEK-LanDnsGuard-v1-" + suffix]
            self.assertEqual(rule["RemoteAddresses"], list(lan_dns.LAN_IPV4_PREFIXES))
            self.assertEqual(rule["RemotePorts"], ["53"])
            self.assertEqual(rule["LocalPorts"], [])
        for suffix in ("IPv6-UDP53", "IPv6-TCP53"):
            rule = by_name["CPPEK-LanDnsGuard-v1-" + suffix]
            self.assertEqual(rule["RemoteAddresses"], list(lan_dns.LAN_IPV6_PREFIXES))
            self.assertEqual(rule["RemotePorts"], ["53"])
            self.assertEqual(rule["LocalPorts"], [])

    def test_rejects_wildcards_duplicates_and_any(self):
        for bad in ([], [""], ["Any"], ["Wi-Fi", "wi-fi"], ["Wi*"], ["-Eth0"], ["Eth`1"]):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                lan_dns.build_plan(bad)

    def test_cli_outputs_ascii_json(self):
        stdout = StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(lan_dns.main(["--interface-alias=以太网", "--interface-alias=WLAN 2"]), 0)
        self.assertTrue(stdout.getvalue().isascii())
        data = json.loads(stdout.getvalue())
        self.assertEqual(data["RuleCount"], 4)
        with redirect_stderr(StringIO()), self.assertRaises(SystemExit) as error:
            lan_dns.main(["--interface-alias=Any"])
        self.assertEqual(error.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
