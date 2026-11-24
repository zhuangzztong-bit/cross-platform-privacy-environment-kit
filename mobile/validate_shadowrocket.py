"""Check the bundled Shadowrocket template's tunnel-capturing local-only policy."""

import argparse
import os
from pathlib import Path
import stat
import sys

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config_snapshot import SnapshotError, check_ancestors, checked_stat, local_path


REQUIRED_GENERAL_SETTINGS = {
    ("ipv6", "true"),
    ("hijack-dns", "*:53"),
}

REQUIRED_DIRECT_RULES = {
    ("DOMAIN", "localhost", "DIRECT"),
    ("DOMAIN-SUFFIX", "local", "DIRECT"),
    ("IP-CIDR", "127.0.0.0/8", "DIRECT", "no-resolve"),
    ("IP-CIDR", "10.0.0.0/8", "DIRECT", "no-resolve"),
    ("IP-CIDR", "100.64.0.0/10", "DIRECT", "no-resolve"),
    ("IP-CIDR", "169.254.0.0/16", "DIRECT", "no-resolve"),
    ("IP-CIDR", "172.16.0.0/12", "DIRECT", "no-resolve"),
    ("IP-CIDR", "192.168.0.0/16", "DIRECT", "no-resolve"),
    ("IP-CIDR6", "::1/128", "DIRECT", "no-resolve"),
    ("IP-CIDR6", "fc00::/7", "DIRECT", "no-resolve"),
    ("IP-CIDR6", "fe80::/10", "DIRECT", "no-resolve"),
}

ALLOWED_IPV6_CATCHALL_RULES = {
    ("IP-CIDR6", "::/0", "REJECT", "no-resolve"),
    ("IP-CIDR6", "::/0", "PROXY", "no-resolve"),
}


def validate(content: str) -> int:
    section = ""
    sections = set()
    general_settings = set()
    direct_matches = set()
    ipv6_catchall = None
    proxy_fallback = False

    for number, raw_line in enumerate(content.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if proxy_fallback:
            raise ValueError(f"line {number}: FINAL,PROXY must be last")

        if line.startswith("["):
            if line not in {"[General]", "[Rule]"} or line in sections:
                raise ValueError(f"line {number}: unsupported or duplicate section")
            if line == "[Rule]" and general_settings != REQUIRED_GENERAL_SETTINGS:
                raise ValueError(
                    f"line {number}: [General] must set ipv6 = true and hijack-dns = *:53 first "
                    "(setting ipv6 = false leaves native cellular/Wi-Fi IPv6 outside the tunnel)"
                )
            section = line
            sections.add(line)
            continue

        if section == "[General]":
            if "=" not in line:
                raise ValueError(f"line {number}: invalid [General] setting")
            key, _, val = line.partition("=")
            setting = (key.strip(), val.strip())
            if setting == ("ipv6", "false"):
                raise ValueError(
                    f"line {number}: ipv6 = false is unsafe on iOS because native IPv6 bypasses utun"
                )
            if setting not in REQUIRED_GENERAL_SETTINGS:
                raise ValueError(f"line {number}: unsupported [General] setting")
            if setting in general_settings:
                raise ValueError(f"line {number}: duplicate [General] setting")
            general_settings.add(setting)
            continue

        if section != "[Rule]":
            raise ValueError(f"line {number}: expected a section header")

        rule = tuple(part.strip() for part in line.split(","))
        if rule == ("FINAL", "PROXY"):
            if ipv6_catchall is None:
                raise ValueError(
                    f"line {number}: IP-CIDR6,::/0,REJECT,no-resolve (or PROXY) must precede FINAL,PROXY"
                )
            proxy_fallback = True
            continue
        if rule in ALLOWED_IPV6_CATCHALL_RULES:
            if ipv6_catchall is not None:
                raise ValueError(f"line {number}: duplicate IPv6 catch-all rule")
            ipv6_catchall = rule
            continue
        if ipv6_catchall is not None:
            raise ValueError(f"line {number}: local direct rules must precede IPv6 catch-all")
        if rule not in REQUIRED_DIRECT_RULES:
            raise ValueError(f"line {number}: unsupported rule")
        if rule in direct_matches:
            raise ValueError(f"line {number}: duplicate direct rule")
        direct_matches.add(rule)

    if not proxy_fallback:
        raise ValueError("missing FINAL,PROXY")
    missing = REQUIRED_DIRECT_RULES - direct_matches
    if missing:
        labels = ", ".join(rule[1] for rule in sorted(missing))
        raise ValueError(f"missing required local direct rules: {labels}")
    return len(direct_matches)


def read_safe_profile(path: Path) -> str:
    raw_local = local_path(path)
    info = checked_stat(raw_local)
    resolved_parent = local_path(raw_local.parent.resolve())
    safe_path = resolved_parent / raw_local.name
    info = checked_stat(safe_path)
    if not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024:
        raise ValueError("profile must be a regular local file under 1 MiB")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(safe_path, flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("profile is not a regular file")
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            return stream.read(1024 * 1024 + 1).decode("utf-8-sig")
    finally:
        if fd >= 0:
            os.close(fd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", type=Path)
    args = parser.parse_args()
    try:
        count = validate(read_safe_profile(args.profile))
    except (OSError, SnapshotError, UnicodeError, ValueError) as exc:
        parser.exit(1, f"FAIL: {exc}\n")
    print(f"PASS: {count} local direct rules; IPv6 tunnel capture + DNS hijack + final proxy policy; static check only.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
