#!/usr/bin/env python3
"""Offline static check for the bundled Android v2rayNG Claude routing rule set."""

import argparse
import json
import os
from pathlib import Path
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from build_routing import (
    ANTHROPIC_IPV4_CIDRS,
    ANTHROPIC_IPV6_BLOCK,
    CLAUDE_ECOSYSTEM_DOMAINS,
    unique_json_object,
)
from config_snapshot import SnapshotError, checked_stat, local_path


FORBIDDEN_TYPO_DOMAINS = frozenset({"domain:claudemcpclient.com", "claudemcpclient.com"})
REQUIRED_LAN_IPS = frozenset({"geoip:private", "100.64.0.0/10"})


def validate_v2rayng_rules(rules):
    if not isinstance(rules, list) or len(rules) < 8:
        raise ValueError("Expected a non-empty Android v2rayNG routing rule list.")

    udp443_idx = None
    v6_guard_idx = None
    claude_dom_idx = None
    claude_v4_idx = None
    lan_ip_idx = None
    cn_idx = None

    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise ValueError(f"Rule {index + 1} must be a JSON object.")
        if rule.get("enabled") is not True:
            raise ValueError(f"Rule {index + 1} must be enabled.")
        outbound = rule.get("outboundTag")
        if outbound not in {"proxy", "direct", "block"}:
            raise ValueError(f"Rule {index + 1} has invalid outboundTag.")

        domains = rule.get("domain") or []
        ips = rule.get("ip") or []
        for dom in domains:
            if dom in FORBIDDEN_TYPO_DOMAINS:
                raise ValueError(f"Rule {index + 1} contains known typo domain: {dom}")

        if outbound == "direct":
            if not domains and not ips:
                raise ValueError(f"Rule {index + 1} is an unfiltered direct catch-all.")
            if "0.0.0.0/0" in ips or "::/0" in ips or str(rule.get("port", "")) == "0-65535":
                raise ValueError(f"Rule {index + 1} contains an unsafe direct catch-all.")

        if outbound == "block" and rule.get("network") == "udp" and str(rule.get("port", "")) == "443":
            udp443_idx = index
        if outbound == "block" and set(ANTHROPIC_IPV6_BLOCK).issubset(set(ips)):
            v6_guard_idx = index
        if outbound == "proxy" and set(CLAUDE_ECOSYSTEM_DOMAINS).issubset(set(domains)):
            claude_dom_idx = index
        if outbound == "proxy" and set(ANTHROPIC_IPV4_CIDRS).issubset(set(ips)):
            claude_v4_idx = index
        if outbound == "direct" and REQUIRED_LAN_IPS.issubset(set(ips)):
            lan_ip_idx = index
        if outbound == "direct" and ("geosite:cn" in domains or "geoip:cn" in ips):
            if cn_idx is None:
                cn_idx = index

    if udp443_idx is None:
        raise ValueError("Missing UDP/443 QUIC block rule.")
    if v6_guard_idx is None:
        raise ValueError("Missing Anthropic IPv6 502 guard block rule.")
    if claude_dom_idx is None:
        raise ValueError("Missing complete 23-domain Claude ecosystem proxy rule.")
    if claude_v4_idx is None:
        raise ValueError("Missing Anthropic IPv4 CIDR (160.79.104.0/21) proxy rule.")
    if lan_ip_idx is None:
        raise ValueError("Missing local LAN + 100.64.0.0/10 direct IP rule.")
    if cn_idx is not None:
        if not (v6_guard_idx < cn_idx and claude_dom_idx < cn_idx and claude_v4_idx < cn_idx):
            raise ValueError("Claude ecosystem, IPv4 CIDR, and IPv6 guard rules must precede domestic direct rules.")

    last = rules[-1]
    if str(last.get("port", "")) == "0-65535" and last.get("outboundTag") != "proxy":
        raise ValueError("Final catch-all rule must route port 0-65535 to proxy.")
    return len(rules)


def read_safe_json(path: Path):
    raw_local = local_path(path)
    checked_stat(raw_local)
    resolved_parent = local_path(raw_local.parent.resolve())
    safe_path = resolved_parent / raw_local.name
    info = checked_stat(safe_path)
    if not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024:
        raise ValueError("Rule file must be a regular local file under 1 MiB.")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(safe_path, flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("Rule file is not a regular file.")
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            text = stream.read(1024 * 1024 + 1).decode("utf-8-sig")
            return json.loads(text, object_pairs_hook=unique_json_object)
    finally:
        if fd >= 0:
            os.close(fd)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rule_file", type=Path)
    args = parser.parse_args(argv)
    try:
        count = validate_v2rayng_rules(read_safe_json(args.rule_file))
    except (OSError, SnapshotError, UnicodeError, ValueError) as exc:
        parser.exit(1, f"FAIL: {exc}\n")
    print(f"PASS: {count} rules; UDP/443 block + Anthropic IPv6 guard + 23 Claude domains + IPv4 CIDR + proxy fallback.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
