#!/usr/bin/env python3
"""Report local macOS/Linux routing and resolver observations without addresses."""

from collections import Counter
import ipaddress
import json
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys


SYSTEM_COMMAND_PATH = "/usr/bin:/usr/sbin:/bin:/sbin"
MAX_TEXT = 2 * 1024 * 1024
ROUTE_REJECT = 0x0200
ROUTE_UP = 0x0001
TUNNEL_KINDS = {
    "tun", "tap", "tuntap", "wireguard", "gre", "gretap", "ip6gre",
    "ip6tnl", "ipip", "sit", "vti", "vti6", "xfrm",
}
TUNNEL_NAME = re.compile(
    r"(?:(?:tun|tap|utun|ppp|wg|tailscale)(?:\d+|[-_].+)?|"
    r"(?:sing[-_]?box|mihomo|clash)(?:[-_].+)?)"
)
RESOLVECTL_HEADER = re.compile(r"^(?:Global|Link \d+ \([^\n]*\)):(.*)$", re.MULTILINE)
SPLIT_IPV4_PREFIXES = {"0.0.0.0/1", "128.0.0.0/1"}
SPLIT_IPV6_PREFIXES = {"::/1", "8000::/1", "2000::/3"}


def read_command(*args):
    executable = shutil.which(args[0], path=SYSTEM_COMMAND_PATH)
    if executable is None:
        return None
    try:
        result = subprocess.run(
            [executable, *args[1:]], capture_output=True, timeout=4, check=True,
            encoding="utf-8", errors="replace", env={"LC_ALL": "C", "PATH": SYSTEM_COMMAND_PATH},
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout if len(result.stdout) <= MAX_TEXT else None


def read_local_file(path):
    try:
        with Path(path).open(encoding="utf-8", errors="replace") as source:
            result = source.read(MAX_TEXT + 1)
    except OSError:
        return None
    return result if len(result) <= MAX_TEXT else None


def interface_kind(name, link_kinds):
    name = name.lower()
    link_kind = link_kinds.get(name, "")
    if link_kind in TUNNEL_KINDS or TUNNEL_NAME.fullmatch(name):
        return "tunnel_candidate"
    if name == "lo" or name == "lo0" or link_kind == "loopback":
        return "loopback"
    if link_kind in {"bridge", "veth", "vlan", "bond", "dummy", "macvlan"} or re.match(
        r"^(?:br[0-9-]|docker|veth|vlan|vmnet|virbr)", name,
    ):
        return "virtual_or_bridge"
    if name.startswith("wl"):
        return "wifi_candidate"
    if name.startswith(("en", "eth")):
        return "wired_or_wifi_candidate"
    return "other_or_unknown"


def _iproute_prefixes(text, allowed_destinations):
    rows = json.loads(text)
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ValueError("Unexpected route structure")
    routes = []
    for row in rows:
        destination = row.get("dst")
        if not isinstance(destination, str) or destination not in allowed_destinations:
            continue
        candidates = [row.get("dev")]
        nexthops = row.get("nexthops", [])
        if isinstance(nexthops, list):
            candidates.extend(hop.get("dev") for hop in nexthops if isinstance(hop, dict))
        interfaces = tuple(name for name in candidates if isinstance(name, str) and name)
        routes.append((row.get("type", "unicast") == "unicast", interfaces))
    return routes


def iproute_defaults(text, family):
    destinations = {"default", "0.0.0.0/0" if family == "ipv4" else "::/0"}
    return _iproute_prefixes(text, destinations)


def iproute_split_routes(text, family):
    destinations = SPLIT_IPV4_PREFIXES if family == "ipv4" else SPLIT_IPV6_PREFIXES
    return _iproute_prefixes(text, destinations)


def proc_defaults(text, family, *, split_only=False):
    rows = text.splitlines()
    if family == "ipv4":
        if not rows or rows[0].split()[:4] != ["Iface", "Destination", "Gateway", "Flags"]:
            raise ValueError("Unexpected IPv4 route table")
        rows = rows[1:]
    routes = []
    for row in rows:
        fields = row.split()
        if not fields:
            continue
        if family == "ipv4":
            if len(fields) < 8:
                raise ValueError("Truncated IPv4 route row")
            if split_only:
                # /1 mask in little-endian hex on x86/ARM Linux is 00000080 (or big-endian 80000000)
                if fields[7].upper() not in {"00000080", "80000000"}:
                    continue
                if fields[1].upper() not in {"00000000", "00000080", "80000000"}:
                    continue
            else:
                if fields[1] != "00000000" or fields[7] != "00000000":
                    continue
            interface, flags = fields[0], int(fields[3], 16)
        else:
            if len(fields) < 10:
                raise ValueError("Truncated IPv6 route row")
            if split_only:
                is_half = fields[1] == "01" and fields[0].lower() in {"0" * 32, "8" + "0" * 31}
                is_global_unicast = fields[1] == "03" and fields[0].lower() == "2" + "0" * 31
                if not (is_half or is_global_unicast):
                    continue
            else:
                if fields[0] != "0" * 32 or fields[1] != "00":
                    continue
            interface, flags = fields[9], int(fields[8], 16)
        routes.append((bool(flags & ROUTE_UP) and not bool(flags & ROUTE_REJECT), (interface,)))
    return routes


def _normalize_mac_split_dest(token):
    if token in {"0/1", "0.0.0.0/1"}:
        return "0.0.0.0/1"
    if token in {"128.0/1", "128.0.0.0/1"}:
        return "128.0.0.0/1"
    if token in SPLIT_IPV6_PREFIXES:
        return token
    return None


def mac_defaults(text, *, split_only=False):
    routes = []
    netif_index = None
    for row in text.splitlines():
        fields = row.split()
        if fields[:3] == ["Destination", "Gateway", "Flags"]:
            if "Netif" not in fields:
                raise ValueError("Missing Netif column in route-table header")
            netif_index = fields.index("Netif")
            continue
        if not fields:
            continue
        matched = (
            _normalize_mac_split_dest(fields[0]) is not None
            if split_only
            else fields[0] in {"default", "0.0.0.0/0", "::/0"}
        )
        if matched:
            if netif_index is None:
                raise ValueError("Missing route-table header")
            if len(fields) <= netif_index:
                raise ValueError("Truncated default route row")
            flags = fields[2]
            routes.append(("U" in flags and "R" not in flags and "B" not in flags, (fields[netif_index],)))
    if netif_index is None:
        raise ValueError("Missing route-table header")
    return routes


def linux_link_kinds(text):
    try:
        rows = json.loads(text) if text else []
    except ValueError:
        return {}
    if not isinstance(rows, list):
        return {}
    kinds = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("ifname"), str):
            continue
        information = row.get("linkinfo")
        kind = information.get("info_kind") if isinstance(information, dict) else row.get("link_type")
        if isinstance(kind, str):
            kinds[row["ifname"].lower()] = kind
    return kinds


def route_summary(routes, source, link_kinds, count_key="default_route_count"):
    if routes is None:
        return {"status": "unavailable"}
    candidates = {name for eligible, names in routes if eligible for name in names}
    return {
        "status": "observed",
        "source": source,
        count_key: len(routes),
        "forwarding_candidate_count": sum(eligible for eligible, _ in routes),
        "candidate_interface_types": dict(sorted(Counter(
            interface_kind(name, link_kinds) for name in candidates
        ).items())),
    }


def linux_routes(family, reader, run, link_kinds):
    version = "-4" if family == "ipv4" else "-6"
    result = run("ip", "-j", version, "route", "show", "table", "all", "default")
    if result is not None:
        try:
            return route_summary(iproute_defaults(result, family), "iproute2_all_tables", link_kinds)
        except ValueError:
            pass
    path = "/proc/net/route" if family == "ipv4" else "/proc/net/ipv6_route"
    text = reader(path)
    if text is not None:
        try:
            return route_summary(proc_defaults(text, family), "linux_proc_route", link_kinds)
        except ValueError:
            pass
    return route_summary(None, None, link_kinds)


def linux_split_routes(family, reader, run, link_kinds):
    version = "-4" if family == "ipv4" else "-6"
    result = run("ip", "-j", version, "route", "show", "table", "all")
    if result is not None:
        try:
            return route_summary(
                iproute_split_routes(result, family), "iproute2_all_tables", link_kinds, "split_route_count"
            )
        except ValueError:
            pass
    path = "/proc/net/route" if family == "ipv4" else "/proc/net/ipv6_route"
    text = reader(path)
    if text is not None:
        try:
            return route_summary(
                proc_defaults(text, family, split_only=True), "linux_proc_route", link_kinds, "split_route_count"
            )
        except ValueError:
            pass
    return route_summary(None, None, link_kinds, "split_route_count")


def mac_routes(family, run):
    text = run("netstat", "-rn", "-f", "inet" if family == "ipv4" else "inet6")
    if text is not None:
        try:
            return (
                route_summary(mac_defaults(text), "macos_netstat", {}),
                route_summary(mac_defaults(text, split_only=True), "macos_netstat", {}, "split_route_count"),
            )
        except ValueError:
            pass
    return route_summary(None, None, {}), route_summary(None, None, {}, "split_route_count")


def _parse_resolver_ip(value):
    candidate = value.split("#", 1)[0].strip()
    if candidate.startswith("["):
        host, separator, rest = candidate[1:].partition("]")
        if not separator:
            return None
        rest = rest.split("%", 1)[0]
        if rest:
            port = rest[1:]
            if not rest.startswith(":") or not port.isascii() or not port.isdecimal():
                return None
            if not (1 <= int(port) <= 65535):
                return None
        candidate = host.split("%", 1)[0]
    elif candidate.count(":") == 1:
        host, port_and_zone = candidate.split(":", 1)
        port = port_and_zone.split("%", 1)[0]
        if not port.isascii() or not port.isdecimal() or not (1 <= int(port) <= 65535):
            return None
        candidate = host.split("%", 1)[0]
    else:
        candidate = candidate.split("%", 1)[0]
    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        return None


def _extract_resolvectl_tokens(text):
    tokens = []
    in_dns_section = False
    for line in text.splitlines():
        match = RESOLVECTL_HEADER.match(line)
        if match is not None:
            in_dns_section = True
            tokens.extend(match.group(1).split())
        elif in_dns_section and line[:1].isspace():
            tokens.extend(line.split())
        else:
            in_dns_section = False
    return tokens


def resolver_summary(values, source):
    if values is None:
        return {"status": "unavailable", "dns_transport_tested": False}
    addresses = set()
    for value in values:
        parsed = _parse_resolver_ip(value)
        if parsed is not None:
            addresses.add(parsed)
    counters = Counter()
    for address in addresses:
        if address.is_loopback:
            counters["loopback"] += 1
        elif address.is_link_local:
            counters["link_local"] += 1
        elif address.is_global and not address.is_multicast:
            counters["global_address"] += 1
        else:
            counters["other_address"] += 1
    return {
        "status": "observed",
        "source": source,
        "configured_resolver_count": len(addresses),
        "resolver_address_types": dict(sorted(counters.items())),
        "dns_transport_tested": False,
    }


def collect(system, reader=read_local_file, run=read_command):
    if system == "Linux":
        link_kinds = linux_link_kinds(run("ip", "-j", "-details", "link", "show"))
        routes = {family: linux_routes(family, reader, run, link_kinds) for family in ("ipv4", "ipv6")}
        split_routes = {family: linux_split_routes(family, reader, run, link_kinds) for family in ("ipv4", "ipv6")}
        text = run("resolvectl", "dns")
        if text is not None and RESOLVECTL_HEADER.search(text):
            values = _extract_resolvectl_tokens(text)
            dns = resolver_summary(values, "systemd_resolved")
        else:
            text = reader("/etc/resolv.conf")
            values = None if text is None else re.findall(r"^\s*nameserver\s+(\S+)", text, re.MULTILINE)
            dns = resolver_summary(values, "resolv_conf")
    elif system == "Darwin":
        v4_default, v4_split = mac_routes("ipv4", run)
        v6_default, v6_split = mac_routes("ipv6", run)
        routes = {"ipv4": v4_default, "ipv6": v6_default}
        split_routes = {"ipv4": v4_split, "ipv6": v6_split}
        text = run("scutil", "--dns")
        values = None if text is None else re.findall(
            r"^\s*nameserver\[\d+\]\s*:\s*(\S+)", text, re.MULTILINE,
        )
        dns = resolver_summary(values, "macos_scutil")
    else:
        return {"status": "unsupported_platform"}
    return {
        "status": "local_observations_collected",
        "platform": "macos" if system == "Darwin" else "linux",
        "default_routes": routes,
        "split_tunnel_routes": split_routes,
        "dns_configuration": dns,
        "limitations": [
            "Default and split-tunnel route candidates do not establish policy-routing rule precedence.",
            "Interface types are inferred from local names and available link metadata.",
            "Resolver settings do not establish upstream DNS, browser DoH, or per-app traffic.",
            "No packets were sent; traffic path, firewall rules, and failure blocking remain untested.",
        ],
    }


def main():
    if len(sys.argv) != 1:
        print("Usage: python3 inspect_unix_network.py", file=sys.stderr)
        return 2
    report = collect(platform.system())
    print(json.dumps(report, indent=2))
    return 2 if report["status"] == "unsupported_platform" else 0


if __name__ == "__main__":
    raise SystemExit(main())
