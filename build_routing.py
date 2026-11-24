#!/usr/bin/env python3
"""Generate or check a narrowly scoped v2rayN routing-rule import file."""

import argparse
import json
import os
from pathlib import Path
import stat
import sys

from config_snapshot import SnapshotError, check_ancestors, checked_stat, local_path


# List the intended ranges explicitly. Broad reserved-range datasets can
# contain synthetic DNS ranges that must remain under the tunnel's control.
LOCAL_NETWORKS = [
    "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fd00::/8", "fe80::/10",
]

# Anthropic IPv6 prefixes that often return 502 over IPv4-only exits.
ANTHROPIC_IPV6_BLOCK = [
    "2607:6bc0::/48",
    "2607:6bc0:11::/48",
]

# Core Claude/Anthropic domains plus peripheral telemetry, verification,
# payment, support, and identity domains observed in client audits.
CLAUDE_ECOSYSTEM_DOMAINS = [
    "domain:claude.ai",
    "domain:claude.com",
    "domain:clau.de",
    "domain:anthropic.com",
    "domain:claudeusercontent.com",
    "domain:claudemcpcontent.com",
    "domain:modelcontextprotocol.io",
    "domain:sentry.io",
    "domain:datadoghq.com",
    "keyword:browser-intake",
    "domain:growthbook.io",
    "domain:segment.io",
    "domain:siftscience.com",
    "domain:usefathom.com",
    "domain:hcaptcha.com",
    "domain:challenges.cloudflare.com",
    "domain:recaptcha.net",
    "domain:stripe.com",
    "domain:stripe.network",
    "domain:stripecdn.com",
    "domain:intercom.io",
    "domain:intercomcdn.com",
    "domain:withpersona.com",
]

# Anthropic official IPv4 allocation (AS399358).
ANTHROPIC_IPV4_CIDRS = [
    "160.79.104.0/21",
]


def build_rules(external_first_xray=False, global_proxy=False, claude_ecosystem=False):
    if external_first_xray and global_proxy:
        raise ValueError("Choose either --external-first-xray or --global-proxy, not both.")
    rules = []
    if claude_ecosystem:
        rules.extend([
            {"remarks": "Block QUIC UDP 443", "network": "udp", "port": "443", "outboundTag": "block"},
            {"remarks": "Block Anthropic IPv6 (502 guard)", "ip": list(ANTHROPIC_IPV6_BLOCK), "outboundTag": "block"},
            {"remarks": "Claude and peripheral ecosystem", "domain": list(CLAUDE_ECOSYSTEM_DOMAINS), "outboundTag": "proxy"},
            {"remarks": "Anthropic IPv4 CIDR", "ip": list(ANTHROPIC_IPV4_CIDRS), "outboundTag": "proxy"},
        ])
    rules.extend([
        {"remarks": "Local domains", "domain": ["geosite:private"], "outboundTag": "direct"},
        {"remarks": "Local address ranges", "ip": list(LOCAL_NETWORKS), "outboundTag": "direct"},
    ])
    if not global_proxy:
        if external_first_xray:
            rules.append({
                "remarks": "External domain category",
                "domain": ["geosite:geolocation-!cn"],
                "outboundTag": "proxy",
            })
        rules.extend([
            {"remarks": "Domestic domains", "domain": ["geosite:cn"], "outboundTag": "direct"},
            {"remarks": "Domestic IP ranges", "ip": ["geoip:cn"], "outboundTag": "direct"},
        ])
    rules.append({"remarks": "Remaining traffic", "port": "0-65535", "outboundTag": "proxy"})
    return [dict(rule, enabled=True) for rule in rules]


def validate_rules(rules, external_first_xray=False, global_proxy=False, claude_ecosystem=False):
    expected = build_rules(external_first_xray, global_proxy, claude_ecosystem=claude_ecosystem)
    if not isinstance(rules, list) or len(rules) != len(expected):
        raise ValueError(f"Expected one array containing exactly {len(expected)} rules.")
    for index, (actual, template) in enumerate(zip(rules, expected), start=1):
        if not isinstance(actual, dict) or actual.keys() != template.keys():
            raise ValueError(f"Rule {index} has missing, extra, or invalid fields.")
        if actual["enabled"] is not True:
            raise ValueError(f"Rule {index} must be enabled.")
        remarks = actual["remarks"]
        if not isinstance(remarks, str) or not remarks.strip() or not remarks.isprintable():
            raise ValueError(f"Rule {index} needs a single-line label.")
        if any(actual[key] != template[key] for key in template if key != "remarks"):
            raise ValueError(f"Rule {index} does not match its required destination, action, or order.")


def unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("A JSON object contains a duplicate field.")
        result[key] = value
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    generate = actions.add_parser("generate", help="Write a new v2rayN rule-array file.")
    generate.add_argument("output", type=Path)
    validate = actions.add_parser("validate", help="Check a rule array against the package template.")
    validate.add_argument("input", type=Path)
    actions.add_parser("print-doh-domains", help="Print the 23 Claude ecosystem domains for remote DoH pinning.")
    for action in (generate, validate):
        mode_group = action.add_mutually_exclusive_group()
        mode_group.add_argument(
            "--external-first-xray", action="store_true",
            help="Use only with an Xray routing core whose geosite.dat includes geolocation-!cn.",
        )
        mode_group.add_argument(
            "--global-proxy", action="store_true",
            help="Local-only direct exceptions; route all public traffic via proxy (recommended with Kill Switch).",
        )
        action.add_argument(
            "--claude-ecosystem", action="store_true",
            help="Prepend QUIC UDP/443 block, Anthropic IPv6 502 guard, 23 Claude ecosystem domains, and 160.79.104.0/21 proxy rules.",
        )
    args = parser.parse_args(argv)
    try:
        if args.action == "print-doh-domains":
            for item in CLAUDE_ECOSYSTEM_DOMAINS:
                print(item)
        elif args.action == "generate":
            raw_out = local_path(args.output)
            if os.path.lexists(raw_out):
                raise FileExistsError("Output already exists.")
            resolved_parent = local_path(raw_out.parent.resolve(strict=True))
            out_path = resolved_parent / raw_out.name
            if os.path.lexists(out_path):
                raise FileExistsError("Output already exists.")
            rules = build_rules(args.external_first_xray, args.global_proxy, claude_ecosystem=args.claude_ecosystem)
            with out_path.open("x", encoding="utf-8", newline="\n") as destination:
                json.dump(rules, destination, ensure_ascii=False, indent=2)
                destination.write("\n")
            print("Created a new routing template. No client settings were applied.")
        else:
            raw_in = local_path(args.input)
            checked_stat(raw_in)
            resolved_parent = local_path(raw_in.parent.resolve(strict=True))
            in_path = resolved_parent / raw_in.name
            info = checked_stat(in_path)
            if not stat.S_ISREG(info.st_mode) or info.st_size > 16 * 1024 * 1024:
                raise ValueError("Input must be a regular local file.")
            with in_path.open(encoding="utf-8-sig") as source:
                rules = json.load(source, object_pairs_hook=unique_json_object)
            validate_rules(rules, args.external_first_xray, args.global_proxy, claude_ecosystem=args.claude_ecosystem)
            print("Rule array matches the package template. Live routing was not tested.")
    except FileExistsError:
        parser.exit(1, "Error: choose a new output file. The existing file was left unchanged.\n")
    except (OSError, SnapshotError, UnicodeError, ValueError) as error:
        parser.exit(1, f"Error: {error}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
