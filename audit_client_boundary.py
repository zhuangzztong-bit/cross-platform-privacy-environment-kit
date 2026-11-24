#!/usr/bin/env python3
"""Read-only, redacted audit of host OS locale/timezone and local Claude client footprints."""

import argparse
from datetime import datetime
import json
import locale
import os
from pathlib import Path
import platform
import sys


def _utc_offset_hours(now_local):
    offset = now_local.utcoffset()
    if offset is None:
        return None
    return round(offset.total_seconds() / 3600.0, 2)


def _detect_timezone_name(sys_name, local_time):
    if sys_name == "Windows" and os.name == "nt":
        try:
            import winreg
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\TimeZoneInformation",
            ) as key:
                key_name, _ = winreg.QueryValueEx(key, "TimeZoneKeyName")
                if isinstance(key_name, str) and key_name.strip():
                    return key_name.strip()
        except OSError:
            pass
    tz = local_time.tzname() or "unknown"
    if "?" in tz:
        offset = _utc_offset_hours(local_time)
        if offset is not None:
            sign = "+" if offset >= 0 else ""
            return f"UTC{sign}{offset:g}"
    return tz


def _detect_locale():
    lang_tag = None
    try:
        loc = locale.getlocale()
        if loc and loc[0]:
            lang_tag = loc[0]
    except (OSError, ValueError):
        lang_tag = None
    if not lang_tag:
        for env_key in ("LC_ALL", "LC_MESSAGES", "LANG"):
            raw = (os.environ.get(env_key) or "").strip()
            if raw:
                lang_tag = raw.split(".", 1)[0]
                break
    return lang_tag or "unknown"


def _safe_exists(path):
    try:
        return os.path.lexists(path)
    except OSError:
        return False


def _has_msix_claude(local_appdata):
    if not local_appdata:
        return False
    packages = Path(local_appdata) / "Packages"
    try:
        if not packages.is_dir():
            return False
        return any(entry.name.startswith("Claude_") for entry in packages.iterdir())
    except OSError:
        return False


def collect_boundary_audit(system=None, home=None, env=None, now_local=None):
    sys_name = system or platform.system()
    env_map = os.environ if env is None else env
    home_dir = Path(home) if home is not None else Path.home()
    local_time = now_local or datetime.now().astimezone()

    config_override = (env_map.get("CLAUDE_CONFIG_DIR") or "").strip()
    cli_dir = Path(config_override) if config_override else (home_dir / ".claude")
    cli_json = home_dir / ".claude.json"

    desktop_appdata_present = False
    desktop_msix_present = False
    if sys_name == "Windows":
        appdata = (env_map.get("APPDATA") or "").strip()
        local_appdata = (env_map.get("LOCALAPPDATA") or "").strip()
        if appdata:
            desktop_appdata_present = _safe_exists(Path(appdata) / "Claude")
        desktop_msix_present = _has_msix_claude(local_appdata)
    elif sys_name == "Darwin":
        desktop_appdata_present = _safe_exists(home_dir / "Library" / "Application Support" / "Claude")
    elif sys_name == "Linux":
        xdg_config = (env_map.get("XDG_CONFIG_HOME") or "").strip()
        base = Path(xdg_config) if xdg_config else (home_dir / ".config")
        desktop_appdata_present = _safe_exists(base / "Claude")

    env_flags = {
        "ANTHROPIC_BASE_URL_set": bool((env_map.get("ANTHROPIC_BASE_URL") or "").strip()),
        "CLAUDE_CONFIG_DIR_set": bool(config_override),
        "HTTP_PROXY_set": bool((env_map.get("HTTP_PROXY") or env_map.get("http_proxy") or "").strip()),
        "HTTPS_PROXY_set": bool((env_map.get("HTTPS_PROXY") or env_map.get("https_proxy") or "").strip()),
        "ALL_PROXY_set": bool((env_map.get("ALL_PROXY") or env_map.get("all_proxy") or "").strip()),
        "NO_PROXY_set": bool((env_map.get("NO_PROXY") or env_map.get("no_proxy") or "").strip()),
    }

    desktop_present = desktop_appdata_present or desktop_msix_present
    cli_present = _safe_exists(cli_dir) or _safe_exists(cli_json)
    warnings = []
    if desktop_present:
        warnings.append(
            "Native Claude Desktop data footprint detected. Desktop reads host OS locale/timezone directly "
            "and issues cold-start network requests (Sentry, first-party events, updates) even when logged out."
        )
    if cli_present:
        warnings.append(
            "Local Claude Code CLI footprint detected. CLI reads host OS timezone, sends non-disableable "
            "metadata.user_id on API requests, and reports custom ANTHROPIC_BASE_URL hostnames to GrowthBook."
        )
    if env_flags["ANTHROPIC_BASE_URL_set"]:
        warnings.append(
            "ANTHROPIC_BASE_URL is set in the environment. Keep host CLI sessions strictly separated from "
            "isolated web browser profiles."
        )

    return {
        "schemaVersion": 1,
        "platform": sys_name,
        "scope": "Read-only redacted host boundary audit. Values, paths, usernames, and tokens are omitted.",
        "hostEnvironment": {
            "timezoneName": _detect_timezone_name(sys_name, local_time),
            "utcOffsetHours": _utc_offset_hours(local_time),
            "detectedLocale": _detect_locale(),
        },
        "localClientFootprints": {
            "claudeCliConfigDirPresent": _safe_exists(cli_dir),
            "claudeCliStateFilePresent": _safe_exists(cli_json),
            "claudeDesktopDataPresent": desktop_appdata_present,
            "claudeDesktopMsixPresent": desktop_msix_present,
        },
        "environmentVariableFlags": env_flags,
        "boundaryNotes": warnings or [
            "No native Claude Desktop or CLI data footprints were observed in default host locations."
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    result = collect_boundary_audit()
    print(json.dumps(result, indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
