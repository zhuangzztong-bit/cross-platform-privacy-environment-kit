import json
import unittest

from inspect_unix_network import collect, mac_defaults, proc_defaults


IPV4_HEADER = "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n"
MAC_HEADER = "Destination Gateway Flags Netif Expire\n"


def commands(fixtures):
    return lambda *args: fixtures.get(args)


class NetworkEvidenceTests(unittest.TestCase):
    def test_linux_json_uses_local_link_metadata_and_counted_defaults(self):
        fixtures = {
            ("ip", "-j", "-details", "link", "show"): json.dumps([
                {"ifname": "custom-private", "linkinfo": {"info_kind": "wireguard"}},
                {"ifname": "veth123", "linkinfo": {"info_kind": "veth"}},
            ]),
            ("ip", "-j", "-4", "route", "show", "table", "all", "default"): json.dumps([
                {"dst": "default", "dev": "custom-private", "gateway": "192.168.50.5"},
                {"dst": "default", "type": "blackhole"},
                {"dst": "0.0.0.0/0", "nexthops": [
                    {"dev": "custom-private"}, {"dev": "veth123"},
                ]},
            ]),
            ("ip", "-j", "-4", "route", "show", "table", "all"): json.dumps([
                {"dst": "0.0.0.0/1", "dev": "custom-private"},
                {"dst": "128.0.0.0/1", "dev": "custom-private"},
            ]),
            ("ip", "-j", "-6", "route", "show", "table", "all", "default"): "[]",
            ("ip", "-j", "-6", "route", "show", "table", "all"): "[]",
            ("resolvectl", "dns"): "Global: 1.1.1.1\nLink 2 (custom-private): 127.0.0.53\n",
        }
        report = collect("Linux", reader=lambda _: None, run=commands(fixtures))
        route = report["default_routes"]["ipv4"]
        self.assertEqual(route, {
            "status": "observed",
            "source": "iproute2_all_tables",
            "default_route_count": 3,
            "forwarding_candidate_count": 2,
            "candidate_interface_types": {"tunnel_candidate": 1, "virtual_or_bridge": 1},
        })
        self.assertEqual(report["split_tunnel_routes"]["ipv4"]["split_route_count"], 2)
        self.assertEqual(report["split_tunnel_routes"]["ipv4"]["candidate_interface_types"], {"tunnel_candidate": 1})
        self.assertEqual(report["default_routes"]["ipv6"]["default_route_count"], 0)
        self.assertEqual(report["dns_configuration"]["resolver_address_types"], {
            "global_address": 1, "loopback": 1,
        })
        evidence = json.dumps(report)
        for private in ("custom-private", "veth123", "192.168.50.5", "1.1.1.1", "127.0.0.53"):
            self.assertNotIn(private, evidence)

    def test_linux_resolvectl_supports_ports_sni_and_wrapped_ipv6_lines(self):
        fixtures = {
            ("ip", "-j", "-details", "link", "show"): "[]",
            ("ip", "-j", "-4", "route", "show", "table", "all", "default"): "[]",
            ("ip", "-j", "-4", "route", "show", "table", "all"): "[]",
            ("ip", "-j", "-6", "route", "show", "table", "all", "default"): "[]",
            ("ip", "-j", "-6", "route", "show", "table", "all"): "[]",
            ("resolvectl", "dns"): (
                "Global: 1.1.1.1:853#cloudflare-dns.com\n"
                "Link 2 (eth0): [2606:4700:4700::1111]:853#cloudflare-dns.com\n"
                "               fe80:0::1%2\n"
            ),
        }
        report = collect("Linux", reader=lambda _: None, run=commands(fixtures))
        self.assertEqual(report["dns_configuration"], {
            "status": "observed",
            "source": "systemd_resolved",
            "configured_resolver_count": 3,
            "resolver_address_types": {"global_address": 2, "link_local": 1},
            "dns_transport_tested": False,
        })

    def test_linux_proc_fallback_and_dns_stub(self):
        ipv6_default = " ".join(["0" * 32, "00", "0" * 32, "00", "0" * 32,
                                 "00300000", "00000000", "00000000", "00200200", "lo"])
        files = {
            "/proc/net/route": IPV4_HEADER + "wlan41 00000000 0100000A 0003 0 0 100 00000000 0 0 0\n",
            "/proc/net/ipv6_route": ipv6_default + "\n",
            "/etc/resolv.conf": "search home.private\nnameserver 127.0.0.53\n",
        }
        report = collect("Linux", reader=files.get, run=lambda *args: None)
        self.assertEqual(report["default_routes"]["ipv4"]["candidate_interface_types"], {
            "wifi_candidate": 1,
        })
        ipv6 = report["default_routes"]["ipv6"]
        self.assertEqual(ipv6["default_route_count"], 1)
        self.assertEqual(ipv6["forwarding_candidate_count"], 0)
        self.assertEqual(report["dns_configuration"]["source"], "resolv_conf")
        self.assertEqual(report["dns_configuration"]["resolver_address_types"], {"loopback": 1})
        self.assertNotIn("home.private", json.dumps(report))

    def test_linux_malformed_json_falls_back_to_empty_proc_table(self):
        fixtures = {("ip", "-j", "-4", "route", "show", "table", "all", "default"): "not JSON"}
        report = collect("Linux", reader={
            "/proc/net/route": IPV4_HEADER,
            "/proc/net/ipv6_route": "truncated",
        }.get, run=commands(fixtures))
        self.assertEqual(report["default_routes"]["ipv4"]["default_route_count"], 0)
        self.assertEqual(report["default_routes"]["ipv6"], {"status": "unavailable"})
        self.assertEqual(report["dns_configuration"]["status"], "unavailable")

    def test_macos_scoped_dns_default_and_split_routes_do_not_disclose_values(self):
        fixtures = {
            ("netstat", "-rn", "-f", "inet"): MAC_HEADER + (
                "default 192.168.40.1 UGScg en09\n"
                "0/1 198.18.0.1 UGSc utun61\n"
                "128.0/1 198.18.0.1 UGSc utun61\n"
            ),
            ("netstat", "-rn", "-f", "inet6"): MAC_HEADER + (
                "default fe80::123%utun61 UGcIg utun61\n"
                "default fe80::789%en09 UGRg en09\n"
                "2000::/3 link#44 Uc utun61\n"
            ),
            ("scutil", "--dns"): (
                "resolver #1\n  domain : family.internal\n  nameserver[0] : 100.64.2.4\n"
                "resolver #2\n  nameserver[0] : fe80::123%utun61\n"
                "resolver #3\n  nameserver[0] : 100.64.2.4\n"
            ),
        }
        report = collect("Darwin", reader=lambda _: None, run=commands(fixtures))
        routes = report["default_routes"]
        self.assertEqual(routes["ipv4"]["candidate_interface_types"], {"wired_or_wifi_candidate": 1})
        self.assertEqual(routes["ipv6"]["forwarding_candidate_count"], 1)
        self.assertEqual(routes["ipv6"]["candidate_interface_types"], {"tunnel_candidate": 1})
        self.assertEqual(report["split_tunnel_routes"]["ipv4"]["split_route_count"], 2)
        self.assertEqual(report["split_tunnel_routes"]["ipv4"]["candidate_interface_types"], {"tunnel_candidate": 1})
        self.assertEqual(report["split_tunnel_routes"]["ipv6"]["split_route_count"], 1)
        self.assertEqual(report["split_tunnel_routes"]["ipv6"]["candidate_interface_types"], {"tunnel_candidate": 1})
        self.assertEqual(report["dns_configuration"]["configured_resolver_count"], 2)
        self.assertFalse(report["dns_configuration"]["dns_transport_tested"])
        evidence = json.dumps(report)
        for private in ("family.internal", "100.64.2.4", "en09", "fe80::123", "utun61", "192.168.40.1"):
            self.assertNotIn(private, evidence)

    def test_malformed_tables_are_not_reported_as_empty(self):
        with self.assertRaises(ValueError):
            proc_defaults("denied", "ipv4")
        with self.assertRaises(ValueError):
            mac_defaults("not available")

    def test_macos_route_table_reads_netif_after_legacy_columns(self):
        legacy_header = "Destination Gateway Flags Refs Use Netif Expire\n"
        routes = mac_defaults(legacy_header + "default 192.168.1.1 UGSc 4 0 utun3\n")
        self.assertEqual(routes, [(True, ("utun3",))])

    def test_linux_proc_recognizes_tunnel_names_without_link_metadata(self):
        report = collect(
            "Linux",
            reader={"/proc/net/route": IPV4_HEADER + (
                "singbox_tun 00000000 00000000 0003 0 0 0 00000000 0 0 0\n"
            )}.get,
            run=lambda *args: None,
        )
        self.assertEqual(
            report["default_routes"]["ipv4"]["candidate_interface_types"],
            {"tunnel_candidate": 1},
        )

    def test_unsupported_platform_makes_no_probes(self):
        def reject(*args):
            self.fail("unsupported system called a probe")

        self.assertEqual(collect("Windows", reader=reject, run=reject), {"status": "unsupported_platform"})


if __name__ == "__main__":
    unittest.main()
