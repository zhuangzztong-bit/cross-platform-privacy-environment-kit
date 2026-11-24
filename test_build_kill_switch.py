from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from ipaddress import IPv4Address
import json
import unittest

import build_kill_switch as kill_switch


class KillSwitchPlanTests(unittest.TestCase):
    def build(self, **changes):
        options = {
            "interface_aliases": ["Wi-Fi", "Ethernet"],
            "upstream_address": "8.8.8.8",
            "upstream_port": 443,
            "upstream_protocol": "TCP",
        }
        return kill_switch.build_plan(**(options | changes))

    def rules_by_name(self, plan):
        return {
            rule["Name"].removeprefix(kill_switch.RULE_PREFIX): rule
            for rule in plan["Rules"]
        }

    def assert_ipv4_complement(self, rule, excluded):
        prior = -1
        holes = set()
        for span in rule["RemoteAddresses"]:
            lower, separator, upper = span.partition("-")
            start = int(IPv4Address(lower))
            end = int(IPv4Address(upper if separator else lower))
            self.assertLess(prior, start)
            self.assertLessEqual(start, end)
            self.assertLessEqual(start - prior - 1, len(excluded))
            holes.update(str(IPv4Address(num)) for num in range(prior + 1, start))
            prior = end
        self.assertLessEqual((1 << 32) - 1 - prior, len(excluded))
        holes.update(str(IPv4Address(num)) for num in range(prior + 1, 1 << 32))
        self.assertEqual(holes, set(excluded))

    def test_blocks_other_ipv4_all_ipv6_and_non_tcp_udp_protocols(self):
        plan = self.build()
        rules = self.rules_by_name(plan)
        self.assertEqual(plan["SchemaVersion"], 2)
        self.assertEqual(plan["InterfaceAliases"], ["Ethernet", "Wi-Fi"])
        self.assertEqual(plan["DhcpServers"], [])
        self.assertEqual(len(rules), 12)
        self.assert_ipv4_complement(rules["IPv4OtherAddresses"], {"8.8.8.8"})
        for key in ("IPv4OtherAddresses", "IPv6"):
            self.assertEqual(rules[key]["Protocol"], "Any")
            self.assertEqual(rules[key]["RemotePorts"], [])
            self.assertEqual(rules[key]["LocalPorts"], [])
        self.assertEqual(rules["IPv6"]["RemoteAddresses"], ["::/0"])
        for suffix, proto in kill_switch.NON_TCP_UDP_PROTOCOLS:
            self.assertEqual(rules[suffix]["Protocol"], proto)
            self.assertEqual(rules[suffix]["RemoteAddresses"], ["8.8.8.8"])

    def test_reserves_only_selected_transport_and_port_at_upstream(self):
        for transport, other in (("TCP", "UDP"), ("UDP", "TCP")):
            for port, denied in ((1, ["0", "2-65535"]), (443, ["0-442", "444-65535"]),
                                 (65535, ["0-65534"])):
                with self.subTest(transport=transport, port=port):
                    rules = self.rules_by_name(
                        self.build(upstream_protocol=transport, upstream_port=port)
                    )
                    other_transport = rules["UpstreamOtherTransport"]
                    other_ports = rules["UpstreamOtherPorts"]
                    self.assertEqual(other_transport["RemoteAddresses"], ["8.8.8.8"])
                    self.assertEqual(other_transport["Protocol"], other)
                    self.assertEqual(other_transport["RemotePorts"], [])
                    self.assertEqual(other_ports["RemoteAddresses"], ["8.8.8.8"])
                    self.assertEqual(other_ports["Protocol"], transport)
                    self.assertEqual(other_ports["RemotePorts"], denied)

    def test_dhcp_exception_is_limited_to_exact_addresses_ports_and_blocks_other_protocols(self):
        plan = self.build(dhcp_servers=["192.168.1.1", "10.1.1.2", "10.1.1.2"])
        rules = self.rules_by_name(plan)
        self.assertEqual(len(rules), 15)
        self.assertEqual(plan["DhcpServers"], ["10.1.1.2", "192.168.1.1"])
        dhcp = ["10.1.1.2", "192.168.1.1", "255.255.255.255"]
        expected_exceptions = ["8.8.8.8", *dhcp]
        self.assert_ipv4_complement(rules["IPv4OtherAddresses"], set(expected_exceptions))
        for suffix, _ in kill_switch.NON_TCP_UDP_PROTOCOLS:
            self.assertEqual(rules[suffix]["RemoteAddresses"], expected_exceptions)
        for key in ("DhcpTcp", "DhcpOtherRemotePorts", "DhcpOtherLocalPorts"):
            self.assertEqual(rules[key]["RemoteAddresses"], dhcp)
        self.assertEqual(rules["DhcpTcp"]["Protocol"], "TCP")
        self.assertEqual(rules["DhcpTcp"]["RemotePorts"], [])
        self.assertEqual(rules["DhcpOtherRemotePorts"]["Protocol"], "UDP")
        self.assertEqual(rules["DhcpOtherRemotePorts"]["RemotePorts"], ["0-66", "68-65535"])
        self.assertEqual(rules["DhcpOtherLocalPorts"]["Protocol"], "UDP")
        self.assertEqual(rules["DhcpOtherLocalPorts"]["RemotePorts"], ["67"])
        self.assertEqual(rules["DhcpOtherLocalPorts"]["LocalPorts"], ["0-67", "69-65535"])

    def test_rejects_ambiguous_interface_names_and_wildcards(self):
        for aliases in ([], [""], ["Wi*", "Ethernet"], ["[W]i-Fi"], ["Wi?Fi"], ["Wi`Fi"],
                        [" Wi-Fi"], ["Wi-Fi "], ["-Wi-Fi"], ["Any"], ["ANY"], ["Wi-Fi", "wi-fi"],
                        ['Ethernet"2'], [r"Ethernet\2"], ["Ethernet\n2"], ["A" * 129]):
            with self.subTest(aliases=aliases), self.assertRaises(ValueError):
                self.build(interface_aliases=aliases)

    def test_requires_ipv4_unicast_and_disjoint_dhcp_server(self):
        for address in ("example.org", "::1", "224.0.0.1", "255.255.255.255", "127.0.0.1",
                        "169.254.1.1", "0.0.0.0", "198.18.0.1", "100.64.0.1"):
            with self.subTest(address=address), self.assertRaises(ValueError):
                self.build(upstream_address=address)
        with self.assertRaises(ValueError):
            self.build(dhcp_servers=["8.8.8.8"])
        with self.assertRaises(ValueError):
            self.build(upstream_address="10.0.0.1", dhcp_servers=["10.0.0.1"])
        self.assertEqual(self.build(upstream_address="10.0.0.1")["UpstreamAddress"], "10.0.0.1")

    def test_rejects_invalid_transport_and_port(self):
        for port in (0, 65536, -1):
            with self.subTest(port=port), self.assertRaises(ValueError):
                self.build(upstream_port=port)
        with self.assertRaises(ValueError):
            self.build(upstream_protocol="ICMP")

    def test_cli_outputs_ascii_json_and_has_nonzero_error(self):
        args = ["--interface-alias=无线网络", "--upstream-address=8.8.8.8",
                "--upstream-port=443", "--upstream-protocol=TCP"]
        stdout = StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(kill_switch.main(args), 0)
        self.assertTrue(stdout.getvalue().isascii())
        self.assertEqual(json.loads(stdout.getvalue())["InterfaceAliases"], ["无线网络"])
        with redirect_stderr(StringIO()), self.assertRaises(SystemExit) as error:
            kill_switch.main([*args, "--interface-alias=Any"])
        self.assertEqual(error.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
