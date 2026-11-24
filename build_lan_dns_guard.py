"""Plan scoped Windows Firewall rules blocking physical-NIC LAN/router DNS (port 53) bypass."""

import argparse
import json


RULE_PREFIX = "CPPEK-LanDnsGuard-v1-"
LAN_IPV4_PREFIXES = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
)
LAN_IPV6_PREFIXES = (
    "fc00::/7",
    "fe80::/10",
)


def _literal_interfaces(names):
    if not names:
        raise ValueError("Supply at least one physical interface alias.")
    seen = set()
    for name in names:
        if (
            not 1 <= len(name) <= 128
            or name != name.strip()
            or name.startswith("-")
            or name.casefold() == "any"
            or any(not char.isprintable() or char in '*?[]`"\\' for char in name)
        ):
            raise ValueError("Use literal interface aliases without wildcards or control characters.")
        if name.casefold() in seen:
            raise ValueError("Interface aliases must be unique.")
        seen.add(name.casefold())
    return sorted(names, key=str.casefold)


def _rule(suffix, addresses, protocol):
    return {
        "Name": RULE_PREFIX + suffix,
        "RemoteAddresses": list(addresses),
        "Protocol": protocol,
        "RemotePorts": ["53"],
        "LocalPorts": [],
    }


def build_plan(interface_aliases):
    aliases = _literal_interfaces(interface_aliases)
    rules = [
        _rule("IPv4-UDP53", LAN_IPV4_PREFIXES, "UDP"),
        _rule("IPv4-TCP53", LAN_IPV4_PREFIXES, "TCP"),
        _rule("IPv6-UDP53", LAN_IPV6_PREFIXES, "UDP"),
        _rule("IPv6-TCP53", LAN_IPV6_PREFIXES, "TCP"),
    ]
    return {
        "SchemaVersion": 1,
        "InterfaceAliases": aliases,
        "RuleCount": len(rules),
        "Rules": rules,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface-alias", action="append", required=True)
    args = parser.parse_args(argv)
    try:
        plan = build_plan(args.interface_alias)
    except ValueError as error:
        parser.error(str(error))
    print(json.dumps(plan, indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
