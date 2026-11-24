"""Collect a local, read-only desktop environment report."""

import argparse
import json
import locale
import os
from pathlib import Path
import platform
import stat
import subprocess
import sys

from config_snapshot import SnapshotError, checked_stat


ROOT = Path(__file__).resolve().parent


def _decode_json_bytes(raw):
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        encoding = locale.getpreferredencoding(False) or "utf-8"
        return raw.decode(encoding)


def _windows_powershell(system_root):
    root = Path(system_root)
    powershell_path = Path("WindowsPowerShell") / "v1.0" / "powershell.exe"
    if os.environ.get("PROCESSOR_ARCHITEW6432"):
        # Sysnative is Windows' native system directory alias for WOW64 processes.
        sysnative = root / "Sysnative" / powershell_path
        if sysnative.is_file():
            return str(sysnative)
    return str(root / "System32" / powershell_path)


def _ensure_unlinked_script(script_path):
    try:
        info = checked_stat(script_path)
        return stat.S_ISREG(info.st_mode)
    except (OSError, SnapshotError):
        return False


def capture_json(command):
    try:
        result = subprocess.run(command, capture_output=True, timeout=70, check=False)
    except (OSError, subprocess.SubprocessError):
        return {"status": "unavailable", "reason": "collector-start-or-timeout"}
    if result.returncode != 0:
        return {"status": "unavailable", "reason": "collector-exit", "exitCode": result.returncode}
    try:
        data = json.loads(_decode_json_bytes(result.stdout))
    except (UnicodeError, ValueError):
        return {"status": "unavailable", "reason": "invalid-collector-output"}
    if not isinstance(data, dict):
        return {"status": "unavailable", "reason": "unexpected-collector-shape"}
    return {"status": "collected", "data": data}


def build_report(system, config_dir=None, project_dir=None, evidence_directory=None):
    report = {
        "schemaVersion": 1,
        "platform": system,
        "scope": "Local observations only. No route, DNS, or disconnection guarantee.",
    }
    if system not in {"Windows", "Darwin", "Linux"}:
        report["status"] = "unsupported-platform"
        return report

    if system == "Windows":
        system_root = (os.environ.get("SystemRoot") or "").strip()
        win_collector = ROOT / "Collect-WindowsEvidence.ps1"
        if not system_root:
            report["network"] = {"status": "unavailable", "reason": "windows-system-root-unset"}
        elif not _ensure_unlinked_script(win_collector):
            report["network"] = {"status": "unavailable", "reason": "collector-script-invalid"}
        else:
            command = [
                _windows_powershell(system_root),
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(win_collector),
            ]
            if evidence_directory is not None:
                # Preserve symlinks/junctions so Collect-WindowsEvidence.ps1 can reject reparse points.
                command.extend(["-EvidenceDirectory", os.path.abspath(evidence_directory)])
            report["network"] = capture_json(command)
    else:
        unix_collector = ROOT / "inspect_unix_network.py"
        if not _ensure_unlinked_script(unix_collector):
            report["network"] = {"status": "unavailable", "reason": "collector-script-invalid"}
        else:
            report["network"] = capture_json([sys.executable, "-B", str(unix_collector)])

    claude_script = ROOT / "claude_local_data.py"
    if not _ensure_unlinked_script(claude_script):
        report["claudeLocalData"] = {"status": "unavailable", "reason": "collector-script-invalid"}
    else:
        local_data = [sys.executable, "-B", str(claude_script), "audit"]
        if config_dir is not None:
            local_data.extend(["--config-dir", str(config_dir)])
        if project_dir is not None:
            local_data.extend(["--project-dir", str(project_dir)])
        report["claudeLocalData"] = capture_json(local_data)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config-dir", type=Path, help="Override the Claude configuration directory.")
    parser.add_argument("--project-dir", type=Path, help="Inspect one explicit project configuration.")
    parser.add_argument("--evidence-directory", type=Path, help="Windows-only saved probe results.")
    args = parser.parse_args()
    system = platform.system()
    if args.evidence_directory is not None and system != "Windows":
        parser.error("--evidence-directory is only supported on Windows")
    report = build_report(system, args.config_dir, args.project_dir, args.evidence_directory)
    print(json.dumps(report, indent=2, ensure_ascii=True))
    if report.get("status") == "unsupported-platform":
        return 2
    return 0 if all(report[key]["status"] == "collected" for key in ("network", "claudeLocalData")) else 2


if __name__ == "__main__":
    sys.exit(main())
