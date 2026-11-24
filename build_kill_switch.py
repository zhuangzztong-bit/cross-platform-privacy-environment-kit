"""Plan scoped Windows Firewall block rules without changing the host."""

import argparse
from ipaddress import IPv4Address, IPv4Network
import json


RULE_PREFIX = "CPPEK-KillSwitch-v1-"
PRIVATE_NETWORKS = tuple(
    IPv4Network(network) for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
DHCP_BROADCAST = IPv4Address("255.255.255.255")
NON_TCP_UDP_PROTOCOLS = (
    ("ExceptionProtoICMPv4", "ICMPv4"),
    ("ExceptionProtoIGMP", "2"),
    ("ExceptionProtoIPv4Encap", "4"),
    ("ExceptionProtoIPv6Encap", "41"),
    ("ExceptionProtoGRE", "47"),
    ("ExceptionProtoESP", "50"),
    ("ExceptionProtoAH", "51"),
    ("ExceptionProtoSCTP", "132"),
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


def _ipv4(value):
    try:
        return IPv4Address(value)
    except ValueError:
        raise ValueError("Use a literal IPv4 address.") from None


def _is_private(address):
    return any(address in network for network in PRIVATE_NETWORKS)


def _upstream(value):
    address = _ipv4(value)
    if (
        not (_is_private(address) or address.is_global)
        or address.is_multicast
        or address.is_reserved
        or address.is_loopback
        or address.is_link_local
        or address.is_unspecified
    ):
        raise ValueError("Use a public or RFC 1918 unicast IPv4 address for the upstream.")
    return address


def _dhcp_servers(values, upstream):
    servers = sorted({_ipv4(value) for value in values})
    for server in servers:
        if not _is_private(server):
            raise ValueError("DHCP servers must be literal RFC 1918 IPv4 addresses.")
        if server == upstream:
            raise ValueError("The upstream and a DHCP server cannot share an address.")
    return servers


def _complement(start, end, exclusions):
    """Yield closed ranges within the inclusive bounds, excluding exact values."""
    lower = start
    for value in exclusions:
        if lower < value:
            yield lower, value - 1
        lower = value + 1
    if lower <= end:
        yield lower, end


def _ranges(start, end, exclusions, render=str):
    return [
        render(lo) if lo == hi else f"{render(lo)}-{render(hi)}"
        for lo, hi in _complement(start, end, exclusions)
    ]


def _rule(name, addresses, protocol="Any", remote_ports=None, local_ports=None):
    return {
        "Name": RULE_PREFIX + name,
        "RemoteAddresses": addresses,
        "Protocol": protocol,
        "RemotePorts": remote_ports or [],
        "LocalPorts": local_ports or [],
    }


def build_plan(interface_aliases, upstream_address, upstream_port, upstream_protocol, dhcp_servers=()):
    aliases = _literal_interfaces(interface_aliases)
    upstream = _upstream(upstream_address)
    if not 1 <= upstream_port <= 65535:
        raise ValueError("The upstream port must be in 1–65535.")
    if upstream_protocol not in ("TCP", "UDP"):
        raise ValueError("Use TCP or UDP for the upstream protocol.")
    servers = _dhcp_servers(dhcp_servers, upstream)
    dhcp_addresses = [*servers, DHCP_BROADCAST] if servers else []
    ordered_exception_ints = sorted(int(address) for address in (upstream, *dhcp_addresses))
    ipv4_other = _ranges(0, (1 << 32) - 1, ordered_exception_ints, lambda address: str(IPv4Address(address)))

    upstream_addresses = [str(upstream)]
    exception_addresses = [str(IPv4Address(address)) for address in ordered_exception_ints]
    other_transport = "UDP" if upstream_protocol == "TCP" else "TCP"
    other_ports = _ranges(0, 65535, (upstream_port,))
    rules = [
        _rule("IPv4OtherAddresses", ipv4_other),
        _rule("IPv6", ["::/0"]),
        _rule("UpstreamOtherTransport", upstream_addresses, other_transport),
        _rule("UpstreamOtherPorts", upstream_addresses, upstream_protocol, other_ports),
    ]
    for suffix, proto in NON_TCP_UDP_PROTOCOLS:
        rules.append(_rule(suffix, exception_addresses, proto))
    if dhcp_addresses:
        dhcp = [str(address) for address in dhcp_addresses]
        rules.extend([
            _rule("DhcpTcp", dhcp, "TCP"),
            _rule("DhcpOtherRemotePorts", dhcp, "UDP", _ranges(0, 65535, (67,))),
            _rule("DhcpOtherLocalPorts", dhcp, "UDP", ["67"], _ranges(0, 65535, (68,))),
        ])

    return {
        "SchemaVersion": 2,
        "InterfaceAliases": aliases,
        "UpstreamAddress": str(upstream),
        "UpstreamPort": upstream_port,
        "UpstreamProtocol": upstream_protocol,
        "DhcpServers": [str(address) for address in servers],
        "Rules": rules,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface-alias", action="append", required=True,
                        help="Exact physical adapter alias. Repeat for each adapter.")
    parser.add_argument("--upstream-address", required=True, help="Fixed IPv4 address.")
    parser.add_argument("--upstream-port", type=int, required=True)
    parser.add_argument("--upstream-protocol", choices=("TCP", "UDP"), required=True)
    parser.add_argument("--dhcp-server", action="append", default=[],
                        help="Optional exact private DHCP server IPv4. Repeat for multiple servers.")
    args = parser.parse_args(argv)
    try:
        plan = build_plan(
            args.interface_alias, args.upstream_address, args.upstream_port,
            args.upstream_protocol, args.dhcp_server,
        )
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(plan, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
