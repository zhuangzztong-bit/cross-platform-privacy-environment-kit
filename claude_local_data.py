"""Offline inventory and local snapshots of selected Claude Code work files."""

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from uuid import uuid4

sys.dont_write_bytecode = True

from config_snapshot import (
    SnapshotError, check_ancestors, checked_stat, copy_tree, ensure_distinct, inventory, local_path,
    paths_overlap, restrict_private_permissions, safe_rmtree,
)


CONFIG_NAMES = {
    "projects": "sessions_and_project_data",
    "history.jsonl": "history",
    "CLAUDE.md": "instructions",
    "CLAUDE.local.md": "instructions",
    "skills": "skills",
    "hooks": "hooks",
    "commands": "commands",
    "agents": "agents",
    "agent-memory": "memory",
    "rules": "rules",
    "settings.json": "settings",
    "settings.local.json": "settings",
    ".mcp.json": "mcp",
}
PROJECT_NAMES = {
    "CLAUDE.md": "instructions",
    "CLAUDE.local.md": "instructions",
    ".mcp.json": "mcp",
}
DEDICATED_NAMES = {
    ".claude.json", ".claude.json.backup", ".credentials.json", "credentials.json",
    "oauth_tokens.json", ".git", "keyring", "keychains",
    ".npmrc", ".netrc", ".pypirc", "id_rsa", "id_ed25519", "id_ecdsa",
    "secrets.json", "token.json", "auth.json",
}
SENSITIVE_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".jks", ".kdbx")
SECRET_CHECKED_JSON_NAMES = {"settings.json", "settings.local.json", ".mcp.json"}
SECRET_KEY_PATTERN = re.compile(
    r"(?:api[_-]?key|auth[_-]?token|access[_-]?token|refresh[_-]?token|secret|"
    r"password|passwd|private[_-]?key|authorization|bearer|client[_-]?secret)",
    re.IGNORECASE,
)
SECRET_VALUE_PATTERN = re.compile(
    r"(?:^sk-ant-[A-Za-z0-9_-]{8,}|^sk-[A-Za-z0-9_-]{16,}|^gh[pousr]_[A-Za-z0-9]{16,}|"
    r"^github_pat_[A-Za-z0-9_]{16,}|^xox[baprs]-[A-Za-z0-9-]{10,}|^Bearer\s+\S{8,})",
    re.IGNORECASE,
)
FORMAT_VERSION = 2
MANIFEST_NAME = "manifest.json"
PAYLOAD_NAME = "work"


@dataclass(frozen=True)
class WorkFile:
    source: Path
    relative: Path
    category: str
    identity: tuple
    posix_mode: int | None


def _configured_env_dir():
    value = os.environ.get("CLAUDE_CONFIG_DIR")
    # Whitespace-only does not specify a directory. Preserve nonblank paths verbatim.
    return value if value and value.strip() else None


def selected_config(value=None):
    return local_path(value or _configured_env_dir() or Path.home() / ".claude")


def identity_of(info):
    # Mask st_mode to file type only: on Windows, lstat() sets execute bits for
    # .bat/.cmd/.exe/.com while fstat() does not, which caused false mismatches.
    return (stat.S_IFMT(info.st_mode), info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def is_sensitive_name(name):
    folded = name.casefold()
    return (
        folded in DEDICATED_NAMES
        or folded == ".env"
        or folded.startswith(".env.")
        or folded.endswith(SENSITIVE_SUFFIXES)
    )


def _contains_inline_secret(node, parent_key=""):
    if isinstance(node, dict):
        for key, value in node.items():
            key_str = str(key)
            if isinstance(value, str) and value.strip():
                val = value.strip()
                # Ignore dynamic variable placeholders such as ${MY_TOKEN} or $TOKEN.
                if not (val.startswith("${") or (val.startswith("$") and " " not in val)):
                    if SECRET_KEY_PATTERN.search(key_str) or SECRET_VALUE_PATTERN.search(val):
                        return True
                    if parent_key.casefold() in {"env", "headers"} and SECRET_KEY_PATTERN.search(key_str):
                        return True
            elif _contains_inline_secret(value, key_str):
                return True
    elif isinstance(node, list):
        for item in node:
            if _contains_inline_secret(item, parent_key):
                return True
    return False


def _inspect_copied_json_for_secrets(copied_path, original_name):
    if original_name.casefold() not in SECRET_CHECKED_JSON_NAMES:
        return
    try:
        text = copied_path.read_text(encoding="utf-8-sig")
        parsed = json.loads(text)
    except (OSError, UnicodeError, ValueError):
        return
    if _contains_inline_secret(parsed):
        raise SnapshotError(
            "Inline API keys or auth tokens were detected in settings or .mcp.json. "
            "Move secrets to environment variables/keychain, or pass --allow-inline-secrets."
        )


def scan_work(config, project=None):
    files = []
    directories = []
    skipped = {"unsafe_or_unavailable": 0, "excluded_secret_entries": 0}
    roots = {"user_config_present": False, "project_selected": project is not None}

    def visit(source, relative, category):
        if is_sensitive_name(source.name):
            skipped["excluded_secret_entries"] += 1
            return
        try:
            info = checked_stat(source)
            if stat.S_ISDIR(info.st_mode):
                directories.append(relative)
                for entry in sorted(source.iterdir(), key=lambda item: item.name):
                    visit(entry, relative / entry.name, category)
            elif stat.S_ISREG(info.st_mode):
                # Strip group/world write bits (0o022) when recording POSIX permissions.
                mode = (info.st_mode & 0o755) if os.name == "posix" else None
                files.append(WorkFile(source, relative, category, identity_of(info), mode))
            else:
                skipped["unsafe_or_unavailable"] += 1
        except (OSError, SnapshotError):
            skipped["unsafe_or_unavailable"] += 1

    def selected_names(directory, prefix, names):
        case_insensitive = os.name == "nt" or sys.platform == "darwin"
        if case_insensitive:
            names = {name.casefold(): category for name, category in names.items()}
        try:
            check_ancestors(directory)
            for entry in sorted(directory.iterdir(), key=lambda item: item.name.casefold()):
                if is_sensitive_name(entry.name):
                    skipped["excluded_secret_entries"] += 1
                    continue
                match_name = entry.name.casefold() if case_insensitive else entry.name
                if match_name in names:
                    visit(entry, prefix / entry.name, names[match_name])
            return True
        except FileNotFoundError:
            return False
        except (OSError, SnapshotError):
            skipped["unsafe_or_unavailable"] += 1
            return False

    roots["user_config_present"] = selected_names(config, Path("user-config"), CONFIG_NAMES)
    if project is not None:
        active_project_config = project / ".claude"
        if paths_overlap(config, project) or paths_overlap(config, active_project_config):
            raise SnapshotError("Select non-overlapping user and project scopes.")
        roots["project_present"] = selected_names(project, Path("project"), PROJECT_NAMES)
        roots["project_config_present"] = selected_names(
            active_project_config, Path("project") / ".claude", CONFIG_NAMES,
        )
    return files, directories, skipped, roots


def audit(config, project=None):
    config = local_path(config)
    project = local_path(project) if project is not None else None
    files, directories, skipped, roots = scan_work(config, project)
    categories = {}
    for entry in files:
        count = categories.setdefault(entry.category, {"files": 0, "bytes": 0})
        count["files"] += 1
        count["bytes"] += entry.identity[3]
    return {
        **roots,
        **skipped,
        "files": len(files),
        "directories": len(directories),
        "bytes": sum(entry.identity[3] for entry in files),
        "categories": categories,
        "mixed_account_state_backed_up": False,
        "contents_read": False,
    }


def enforce_unchanged(entry):
    check_ancestors(entry.source.parent)
    if identity_of(checked_stat(entry.source)) != entry.identity:
        raise SnapshotError("A selected source changed. Close its writer and retry.")


def copy_file(entry, destination):
    enforce_unchanged(entry)
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    digest = hashlib.sha256()
    size = 0
    open_flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(entry.source, open_flags)
    try:
        opened_stat = os.fstat(fd)
        if (
            not stat.S_ISREG(opened_stat.st_mode)
            or getattr(opened_stat, "st_nlink", 1) > 1
            or identity_of(opened_stat) != entry.identity
        ):
            raise SnapshotError("A selected source changed before it was read.")
        with os.fdopen(fd, "rb") as source, destination.open("xb") as target:
            fd = -1
            if os.name == "posix":
                os.fchmod(target.fileno(), 0o600)
            while block := source.read(1024 * 1024):
                digest.update(block)
                target.write(block)
                size += len(block)
            if identity_of(os.fstat(source.fileno())) != entry.identity or size != entry.identity[3]:
                raise SnapshotError("A selected source changed during copying.")
    finally:
        if fd >= 0:
            os.close(fd)
    enforce_unchanged(entry)
    return {"size": size, "sha256": digest.hexdigest()}


def publish(stage, destination, prefix):
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    target = destination / f"{prefix}-{timestamp}-{uuid4().hex}"
    if os.path.lexists(target):
        raise SnapshotError("A publication path is already present.")
    stage.rename(target)
    return target


def permissions_digest(modes):
    metadata = json.dumps(modes, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(metadata.encode("ascii")).hexdigest()


def read_verified_snapshot(snapshot):
    snapshot = local_path(snapshot)
    check_ancestors(snapshot)
    present_entries = {entry.name for entry in snapshot.iterdir()}
    if not present_entries <= {MANIFEST_NAME, PAYLOAD_NAME}:
        raise SnapshotError("Snapshot directory contains unexpected files.")
    manifest = snapshot / MANIFEST_NAME
    info = checked_stat(manifest)
    if not stat.S_ISREG(info.st_mode) or info.st_size > 64 * 1024 * 1024:
        raise SnapshotError("Invalid backup manifest.")
    try:
        expected = json.loads(manifest.read_text(encoding="utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise SnapshotError("Invalid backup manifest.") from exc
    if (not isinstance(expected, dict) or type(expected.get("format")) is not int
            or expected["format"] not in (1, FORMAT_VERSION)):
        raise SnapshotError("Unsupported backup format.")
    actual = inventory(snapshot / PAYLOAD_NAME)
    if not actual["files"] or actual != expected.get("inventory"):
        raise SnapshotError("Backup contents do not match the manifest.")
    if expected["format"] == 1:
        return actual, None  # These snapshots never recorded the source permissions.
    if "posix_modes" not in expected:
        raise SnapshotError("Backup file permissions are missing.")
    modes = expected["posix_modes"]
    if modes is not None and (
        not isinstance(modes, dict) or modes.keys() != actual["files"].keys()
        or any(
            type(mode) is not int or not 0 <= mode <= 0o777 or (mode & 0o022) != 0
            for mode in modes.values()
        )
    ):
        raise SnapshotError("Invalid or overly permissive backup file permissions.")
    if permissions_digest(modes) != expected.get("posix_modes_sha256"):
        raise SnapshotError("Backup file permissions do not match their checksum.")
    return actual, modes


def verify(snapshot):
    return read_verified_snapshot(snapshot)[0]


def require_destination(destination):
    try:
        check_ancestors(destination)
    except FileNotFoundError as exc:
        raise SnapshotError("The destination directory does not exist.") from exc


def backup(config, project, destination, *, require_config=True, allow_inline_secrets=False):
    config = local_path(config)
    project = local_path(project) if project is not None else None
    destination = local_path(destination)
    require_destination(destination)
    ensure_distinct(config, destination)
    if project is not None:
        ensure_distinct(project, destination)
    selection = scan_work(config, project)
    files, directories, skipped, roots = selection
    if skipped["unsafe_or_unavailable"]:
        raise SnapshotError("Audit found links, hardlinks, special files or unavailable work data.")
    if require_config and not roots["user_config_present"]:
        raise SnapshotError("The selected user configuration directory does not exist.")
    if project is not None and not roots["project_present"]:
        raise SnapshotError("The selected project directory does not exist.")
    if not files:
        raise SnapshotError("No selected work files were found.")
    stage = Path(tempfile.mkdtemp(prefix=".claude-work-stage-", dir=destination))
    try:
        restrict_private_permissions(stage, is_dir=True)
        payload = stage / PAYLOAD_NAME
        payload.mkdir(mode=0o700)
        for relative in directories:
            (payload / relative).mkdir(mode=0o700, parents=True, exist_ok=True)
        expected_files = {}
        for entry in files:
            copied_dest = payload / entry.relative
            expected_files[entry.relative.as_posix()] = copy_file(entry, copied_dest)
            if not allow_inline_secrets:
                _inspect_copied_json_for_secrets(copied_dest, entry.source.name)
        if selection != scan_work(config, project):
            raise SnapshotError("The selected source changed during backup.")
        checked = inventory(payload)
        if expected_files != checked["files"]:
            raise SnapshotError("Backup validation failed.")
        modes = None
        if os.name == "posix":
            modes = {entry.relative.as_posix(): entry.posix_mode for entry in files}
        manifest = {
            "format": FORMAT_VERSION, "inventory": checked, "scopes": roots,
            "posix_modes": modes, "posix_modes_sha256": permissions_digest(modes),
        }
        (stage / MANIFEST_NAME).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        verify(stage)
        return publish(stage, destination, "claude-work")
    finally:
        safe_rmtree(stage)


def recover(snapshot, destination):
    snapshot, destination = local_path(snapshot), local_path(destination)
    require_destination(destination)
    ensure_distinct(snapshot, destination)
    expected, modes = read_verified_snapshot(snapshot)
    staging_root = Path(tempfile.mkdtemp(prefix=".claude-recover-stage-", dir=destination))
    try:
        restrict_private_permissions(staging_root, is_dir=True)
        recovery = staging_root / "recovery"
        copy_tree(snapshot / PAYLOAD_NAME, recovery, expected, preserve_metadata=False)
        if os.name == "posix":
            for name in expected["files"]:
                target = recovery / name
                mode = (modes[name] & 0o755) if modes is not None else 0o600
                target.chmod(mode)
                if stat.S_IMODE(checked_stat(target).st_mode) != mode:
                    raise SnapshotError("The recovery filesystem did not preserve file permissions.")
        return publish(recovery, destination, "claude-recovery")
    finally:
        safe_rmtree(staging_root)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for operation in ("audit", "backup"):
        entry = commands.add_parser(operation)
        entry.add_argument("--config-dir", help="Defaults to CLAUDE_CONFIG_DIR or ~/.claude.")
        entry.add_argument("--project-dir", help="Optionally select one project for local settings.")
        if operation == "backup":
            entry.add_argument("--destination", required=True, help="Existing private local directory.")
            entry.add_argument(
                "--allow-inline-secrets", action="store_true",
                help="Allow backing up settings/.mcp.json even if inline tokens or API keys are detected.",
            )
    for operation in ("verify", "recover"):
        entry = commands.add_parser(operation)
        entry.add_argument("snapshot")
        if operation == "recover":
            entry.add_argument("--destination", required=True, help="Existing private local directory.")
    args = parser.parse_args(argv)
    try:
        if args.command in ("audit", "backup"):
            config = selected_config(args.config_dir)
            project = local_path(args.project_dir) if args.project_dir else None
            if args.command == "audit":
                print(json.dumps(audit(config, project), sort_keys=True, indent=2))
            else:
                require_config = args.config_dir is not None or _configured_env_dir() is not None
                path = backup(
                    config, project, args.destination,
                    require_config=require_config,
                    allow_inline_secrets=args.allow_inline_secrets,
                )
                print(f"Verified local backup: {path}")
        else:
            snapshot = local_path(args.snapshot)
            if args.command == "verify":
                checked = verify(snapshot)
                print(f"Verified local backup ({len(checked['files'])} work files).")
            else:
                path = recover(snapshot, local_path(args.destination))
                print(f"Verified recovery copy: {path}")
    except SnapshotError as error:
        print(f"Claude work operation stopped: {error}", file=sys.stderr)
        return 1
    except (OSError, ValueError) as error:
        print(f"Claude work operation stopped ({type(error).__name__}).", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
