"""Build a versioned v2rayN routing preview from Loyalsoldier's public lists."""

import argparse
from datetime import datetime, timezone
import hashlib
from http.client import HTTPException
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
import stat
import sys
import tempfile
import time
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener
from uuid import uuid4

from build_routing import LOCAL_NETWORKS
from config_snapshot import SnapshotError, check_ancestors, checked_stat, hash_regular_file, local_path


UPSTREAM_HOST = "raw.githubusercontent.com"
UPSTREAM_REPO_PREFIX = "/Loyalsoldier/clash-rules/"
DEFAULT_REF = "release"
COMMIT_SHA = re.compile(r"[0-9a-fA-F]{40}")
SHA256_HEX = re.compile(r"[0-9a-fA-F]{64}")
MAX_BYTES = 8 * 1024 * 1024
ITEM = re.compile(r" +-[ \t]+'([^']+)'[ \t]*")
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
VERSIONED_PREVIEW = re.compile(r"routing-\d{8}T\d{12}Z-[0-9a-f]{8}\.json")
DIRECT = "direct"
PROXY = "proxy"
FAKE_NETWORKS = [ipaddress.ip_network(value) for value in ("198.18.0.0/15", "fc00::/18")]


class _StrictHttpsRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urlparse(newurl)
        if parsed.scheme != "https" or parsed.hostname != UPSTREAM_HOST:
            raise HTTPError(newurl, code, "Blocked unsafe or cross-host redirect", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _https_urlopen(url, timeout=20):
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != UPSTREAM_HOST:
        raise ValueError("Only https://raw.githubusercontent.com upstream URLs are supported.")
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    opener = build_opener(HTTPSHandler(context=context), _StrictHttpsRedirectHandler())
    request = Request(url, headers={"User-Agent": "cross-platform-privacy-environment-kit/0.3.4"})
    return opener.open(request, timeout=timeout)


def _validated_sha256(value):
    if not SHA256_HEX.fullmatch(value):
        raise argparse.ArgumentTypeError("Expected a 64-character hexadecimal SHA-256 digest.")
    return value.lower()


def _validated_commit(value):
    if not COMMIT_SHA.fullmatch(value):
        raise argparse.ArgumentTypeError("Expected a full 40-character commit SHA.")
    return value.lower()


def read_payload(name, source_dir, commit=None):
    if source_dir is None:
        ref = commit or DEFAULT_REF
        url = f"https://{UPSTREAM_HOST}{UPSTREAM_REPO_PREFIX}{ref}/{name}"
        with _https_urlopen(url, timeout=20) as stream:
            data = stream.read(MAX_BYTES + 1)
    else:
        raw_dir = local_path(source_dir)
        checked_stat(raw_dir)
        safe_dir = local_path(raw_dir.resolve(strict=True))
        candidate = safe_dir / name
        info = checked_stat(candidate)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f"{name}: source must be a regular local file")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(candidate, flags)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ValueError(f"{name}: source changed type")
            with os.fdopen(fd, "rb") as stream:
                fd = -1
                data = stream.read(MAX_BYTES + 1)
        finally:
            if fd >= 0:
                os.close(fd)
    if len(data) > MAX_BYTES:
        raise ValueError(f"{name}: list exceeds {MAX_BYTES} bytes")
    return data


def parse_items(data, name):
    lines = data.decode("utf-8-sig").splitlines()
    if not lines or lines[0] != "payload:":
        raise ValueError(f"{name}: expected a payload: header")
    items = []
    for index, line in enumerate(lines[1:], start=2):
        if not line.strip():
            continue
        item = ITEM.fullmatch(line)
        if item is None:
            raise ValueError(f"{name}: unsupported rule syntax at line {index}")
        items.append((index, item.group(1)))
    if not items:
        raise ValueError(f"{name}: list is empty")
    return items


def domain_entries(data):
    compiled = []
    for index, value in parse_items(data, "direct.txt"):
        suffix = value.startswith("+.")
        hostname = (value[2:] if suffix else value).lower()
        if len(hostname) > 253 or not all(LABEL.fullmatch(label) for label in hostname.split(".")):
            raise ValueError(f"direct.txt: invalid domain at line {index}")
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            pass
        else:
            raise ValueError(f"direct.txt: IP literal at line {index}")
        compiled.append(("domain:" if suffix else "full:") + hostname)
    return list(dict.fromkeys(compiled))


def cidr_entries(data):
    compiled = []
    for index, value in parse_items(data, "cncidr.txt"):
        try:
            address = ipaddress.ip_network(value, strict=True)
        except ValueError:
            raise ValueError(f"cncidr.txt: invalid CIDR at line {index}") from None
        minimum_prefix = 8 if address.version == 4 else 16
        overlaps_fake = any(address.overlaps(pool) for pool in FAKE_NETWORKS)
        if (
            "/" not in value or address.prefixlen < minimum_prefix
            or not address.is_global or address.is_multicast or overlaps_fake
        ):
            raise ValueError(f"cncidr.txt: unexpected non-public prefix at line {index}")
        compiled.append(str(address))
    return list(dict.fromkeys(compiled))


def compile_rules(domains, networks):
    def rule(label, outbound, **match):
        return {"remarks": label, "outboundTag": outbound, "enabled": True, **match}

    return [
        rule("Local domains", DIRECT, domain=["geosite:private"]),
        rule("Local networks", DIRECT, ip=list(LOCAL_NETWORKS)),
        rule("External domain category", PROXY, domain=["geosite:geolocation-!cn"]),
        rule("Loyalsoldier direct domains", DIRECT, domain=domains),
        rule("Loyalsoldier domestic networks", DIRECT, ip=networks),
        rule("Remaining traffic", PROXY, port="0-65535"),
    ]


def publish_preview(directory, rules):
    raw_dir = local_path(directory)
    if os.path.lexists(raw_dir):
        checked_stat(raw_dir)
    raw_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    checked_stat(raw_dir)
    safe_dir = local_path(raw_dir.resolve(strict=True))
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    target = safe_dir / f"routing-{timestamp}-{uuid4().hex[:8]}.json"
    if os.path.lexists(target):
        raise ValueError("Target preview file already exists")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="\n", dir=safe_dir, delete=False,
        ) as stream:
            temporary = Path(stream.name)
            json.dump(rules, stream, ensure_ascii=True, indent=2)
            stream.write("\n")
        hash_regular_file(temporary)
        temporary.rename(target)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return target


def recently_refreshed(directory, hours):
    raw_dir = local_path(directory)
    if not raw_dir.exists():
        return False
    checked_stat(raw_dir)
    safe_dir = local_path(raw_dir.resolve(strict=True))
    now = time.time()
    cutoff = now - hours * 3600
    for path in safe_dir.glob("routing-*.json"):
        if not VERSIONED_PREVIEW.fullmatch(path.name):
            continue
        try:
            info = checked_stat(path)
        except (OSError, SnapshotError):
            continue
        if stat.S_ISREG(info.st_mode) and cutoff <= info.st_mtime <= now + 2.0:
            return True
    return False


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--from-directory", type=Path, help="Read the two saved lists instead of fetching.")
    parser.add_argument("--commit", type=_validated_commit,
                        help="Pin an exact 40-char upstream git commit SHA instead of rolling release.")
    parser.add_argument("--expected-direct-sha256", type=_validated_sha256,
                        help="Require direct.txt to match this SHA-256 digest.")
    parser.add_argument("--expected-cidr-sha256", type=_validated_sha256,
                        help="Require cncidr.txt to match this SHA-256 digest.")
    parser.add_argument("--max-age-hours", type=int, choices=range(1, 169), metavar="1-168",
                        help="Skip if this directory already has a fresh versioned preview.")
    args = parser.parse_args(argv)
    try:
        if args.max_age_hours and recently_refreshed(args.output_directory, args.max_age_hours):
            print("A recent preview already exists. No files were changed.")
            return 0
        if args.from_directory is None:
            raw_domains = read_payload("direct.txt", None, commit=args.commit) if args.commit else read_payload("direct.txt", None)
            raw_networks = read_payload("cncidr.txt", None, commit=args.commit) if args.commit else read_payload("cncidr.txt", None)
        else:
            raw_domains = read_payload("direct.txt", args.from_directory)
            raw_networks = read_payload("cncidr.txt", args.from_directory)
        direct_sha = hashlib.sha256(raw_domains).hexdigest()
        cidr_sha = hashlib.sha256(raw_networks).hexdigest()
        if args.expected_direct_sha256 and direct_sha != args.expected_direct_sha256:
            raise ValueError("direct.txt SHA-256 did not match --expected-direct-sha256")
        if args.expected_cidr_sha256 and cidr_sha != args.expected_cidr_sha256:
            raise ValueError("cncidr.txt SHA-256 did not match --expected-cidr-sha256")
        domains = domain_entries(raw_domains)
        networks = cidr_entries(raw_networks)
        target = publish_preview(args.output_directory, compile_rules(domains, networks))
    except (OSError, SnapshotError, ValueError, HTTPException) as error:
        print(f"Refresh stopped: {error}. Existing previews were retained.", file=sys.stderr)
        return 1
    print(f"Preview: {target}")
    print(f"Domains: {len(domains)}. CIDRs: {len(networks)}.")
    print(f"direct.txt SHA-256: {direct_sha}")
    print(f"cncidr.txt SHA-256: {cidr_sha}")
    if args.from_directory is None and not args.commit and not (
        args.expected_direct_sha256 and args.expected_cidr_sha256
    ):
        print("Notice: fetched from mutable upstream branch without commit/hash pinning. Review diff before importing.")
    print("Client settings were not changed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
