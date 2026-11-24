"""Local v2rayN data snapshots. Use Python 3.10 or later."""

import argparse
from datetime import datetime
import hashlib
import json
import ntpath
import os
from pathlib import Path, PurePath
import shutil
import stat
import subprocess
import sys
import tempfile
import types
from uuid import uuid4


CONFIG_NAME = "guiNConfig.json"
MANIFEST_NAME = "manifest.json"
PAYLOAD_NAME = "data"
LAUNCHER_FILES = ("restore.py", "config_snapshot.py")
DEFAULT_BACKUP_ROOT = Path.home() / "clash-guard-backup"
MAX_MANIFEST_BYTES = 64 * 1024 * 1024
NETWORK_FS_TYPES = {
    "nfs", "nfs4", "cifs", "smb3", "smbfs", "ncpfs", "afs", "9p",
    "fuse.sshfs", "fuse.rclone", "davfs", "webdav",
}
PROXY_PROCESS_NAMES = (
    "v2rayN", "xray", "sing-box", "v2ray", "mihomo", "verge-mihomo", "clash",
    "hysteria", "hysteria2", "tuic-client", "naive", "naiveproxy", "juicity",
    "nekoray", "hiddify", "flclash",
)


class SnapshotError(Exception):
    """Snapshot or recovery precondition failed."""


def _remove_readonly(func, path, exc):
    error = exc[1] if isinstance(exc, tuple) else exc
    if not isinstance(error, PermissionError) or func not in (os.unlink, os.rmdir):
        raise error

    candidate = Path(path)
    check_ancestors(candidate.parent)
    entry = checked_stat(candidate)
    if not (stat.S_ISDIR(entry.st_mode) or (stat.S_ISREG(entry.st_mode) and entry.st_nlink == 1)):
        raise error
    os.chmod(candidate, stat.S_IMODE(entry.st_mode) | stat.S_IWUSR)
    func(path)


def safe_rmtree(path):
    if not os.path.lexists(path):
        return
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=_remove_readonly)
    else:
        shutil.rmtree(path, onerror=_remove_readonly)


def _windows_drive_type(root):
    import ctypes

    get_drive_type = ctypes.WinDLL("kernel32.dll").GetDriveTypeW
    get_drive_type.argtypes = [ctypes.c_wchar_p]
    get_drive_type.restype = ctypes.c_uint
    return get_drive_type(root)


def _windows_volume_supports_acls(root):
    import ctypes
    import ctypes.wintypes as wt

    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
    get_vol_info = kernel32.GetVolumeInformationW
    get_vol_info.argtypes = [
        wt.LPCWSTR, wt.LPWSTR, wt.DWORD, ctypes.POINTER(wt.DWORD),
        ctypes.POINTER(wt.DWORD), ctypes.POINTER(wt.DWORD), wt.LPWSTR, wt.DWORD,
    ]
    get_vol_info.restype = wt.BOOL
    flags = wt.DWORD(0)
    if not get_vol_info(root, None, 0, None, None, ctypes.byref(flags), None, 0):
        return False
    # FS_PERSISTENT_ACLS = 0x00000008
    return bool(flags.value & 0x00000008)


def _windows_current_user_sid():
    import ctypes
    import ctypes.wintypes as wt

    advapi32 = ctypes.WinDLL("advapi32.dll", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)

    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = wt.HANDLE
    kernel32.CloseHandle.argtypes = [wt.HANDLE]
    kernel32.CloseHandle.restype = wt.BOOL
    kernel32.LocalFree.argtypes = [wt.HLOCAL]
    kernel32.LocalFree.restype = wt.HLOCAL

    advapi32.OpenProcessToken.argtypes = [wt.HANDLE, wt.DWORD, ctypes.POINTER(wt.HANDLE)]
    advapi32.OpenProcessToken.restype = wt.BOOL
    advapi32.GetTokenInformation.argtypes = [
        wt.HANDLE, ctypes.c_int, wt.LPVOID, wt.DWORD, ctypes.POINTER(wt.DWORD),
    ]
    advapi32.GetTokenInformation.restype = wt.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [wt.LPVOID, ctypes.POINTER(wt.LPWSTR)]
    advapi32.ConvertSidToStringSidW.restype = wt.BOOL

    class _SidAndAttributes(ctypes.Structure):
        _fields_ = [("Sid", wt.LPVOID), ("Attributes", wt.DWORD)]

    token = wt.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
        raise OSError(ctypes.get_last_error(), "OpenProcessToken failed")
    try:
        needed = wt.DWORD(0)
        advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        buf = ctypes.create_string_buffer(needed.value)
        if not advapi32.GetTokenInformation(token, 1, buf, needed.value, ctypes.byref(needed)):
            raise OSError(ctypes.get_last_error(), "GetTokenInformation failed")
        sid_attr = ctypes.cast(buf, ctypes.POINTER(_SidAndAttributes)).contents
        sid_str = wt.LPWSTR()
        if not advapi32.ConvertSidToStringSidW(sid_attr.Sid, ctypes.byref(sid_str)):
            raise OSError(ctypes.get_last_error(), "ConvertSidToStringSidW failed")
        try:
            return sid_str.value
        finally:
            kernel32.LocalFree(sid_str)
    finally:
        kernel32.CloseHandle(token)


def restrict_private_permissions(path, *, is_dir=False):
    """Restrict newly created snapshot directories/files to the current user."""
    target = Path(path)
    if os.name == "posix":
        os.chmod(target, 0o700 if is_dir else 0o600)
        return
    if sys.platform != "win32" or not isinstance(os, types.ModuleType):
        return
    root = ntpath.splitdrive(os.fspath(target))[0] + "\\"
    if not _windows_volume_supports_acls(root):
        return

    import ctypes
    import ctypes.wintypes as wt

    advapi32 = ctypes.WinDLL("advapi32.dll", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
    kernel32.LocalFree.argtypes = [wt.HLOCAL]
    kernel32.LocalFree.restype = wt.HLOCAL
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wt.LPCWSTR, wt.DWORD, ctypes.POINTER(wt.LPVOID), ctypes.POINTER(wt.ULONG),
    ]
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wt.BOOL
    advapi32.GetSecurityDescriptorDacl.argtypes = [
        wt.LPVOID, ctypes.POINTER(wt.BOOL), ctypes.POINTER(wt.LPVOID), ctypes.POINTER(wt.BOOL),
    ]
    advapi32.GetSecurityDescriptorDacl.restype = wt.BOOL
    advapi32.SetNamedSecurityInfoW.argtypes = [
        wt.LPWSTR, ctypes.c_int, wt.DWORD, wt.LPVOID, wt.LPVOID, wt.LPVOID, wt.LPVOID,
    ]
    advapi32.SetNamedSecurityInfoW.restype = wt.DWORD

    sid = _windows_current_user_sid()
    inherit = "OICI;" if is_dir else ";"
    if is_dir:
        sddl = f"D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{sid})"
    else:
        sddl = f"D:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{sid})"

    sd = wt.LPVOID()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, 1, ctypes.byref(sd), None
    ):
        raise SnapshotError("Could not build a private Windows security descriptor.")
    try:
        dacl = wt.LPVOID()
        present = wt.BOOL()
        defaulted = wt.BOOL()
        if not advapi32.GetSecurityDescriptorDacl(
            sd, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)
        ):
            raise SnapshotError("Could not read the private Windows security descriptor.")
        # SE_FILE_OBJECT = 1, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION
        rc = advapi32.SetNamedSecurityInfoW(
            os.fspath(target), 1, 0x00000004 | 0x80000000, None, None, dacl, None
        )
        if rc != 0:
            raise SnapshotError("Could not apply private NTFS permissions to the snapshot path.")
    finally:
        kernel32.LocalFree(sd)


def _windows_long_path_if_exists(path_str):
    if sys.platform != "win32" or not isinstance(os, types.ModuleType):
        return path_str
    import ctypes
    import ctypes.wintypes as wt

    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
    get_long = kernel32.GetLongPathNameW
    get_long.argtypes = [wt.LPCWSTR, wt.LPWSTR, wt.DWORD]
    get_long.restype = wt.DWORD

    # Resolve longest existing prefix so short 8.3 parent components cannot mask overlap.
    current = path_str
    suffix_parts = []
    while current:
        needed = get_long(current, None, 0)
        if needed > 0:
            buf = ctypes.create_unicode_buffer(needed)
            if get_long(current, buf, needed) > 0:
                resolved = buf.value
                for part in reversed(suffix_parts):
                    resolved = ntpath.join(resolved, part)
                return resolved
            break
        parent, leaf = ntpath.split(current)
        if not leaf or parent == current:
            break
        suffix_parts.append(leaf)
        current = parent
    return path_str


def _check_unix_local_fs(path):
    if sys.platform == "darwin":
        home = Path.home()
        for cloud_dir in (home / "Library" / "Mobile Documents", home / "Library" / "CloudStorage"):
            p_fold = PurePath(os.fspath(path).casefold())
            c_fold = PurePath(os.fspath(cloud_dir).casefold())
            if p_fold == c_fold or p_fold.is_relative_to(c_fold):
                raise SnapshotError("Cloud-synced storage directories are unsupported for plaintext snapshots.")
    elif sys.platform.startswith("linux"):
        try:
            mounts_text = Path("/proc/mounts").read_text(encoding="utf-8", errors="replace")
        except OSError:
            return
        best_mount = ""
        best_fstype = ""
        target_str = os.fspath(path)
        for line in mounts_text.splitlines():
            parts = line.split()
            if len(parts) < 3:
                continue
            mount_point = parts[1].replace("\\040", " ")
            fstype = parts[2].lower()
            if (target_str == mount_point or target_str.startswith(mount_point.rstrip("/") + "/") or mount_point == "/"):
                if len(mount_point) > len(best_mount):
                    best_mount = mount_point
                    best_fstype = fstype
        if best_fstype in NETWORK_FS_TYPES:
            raise SnapshotError("Network filesystems are unsupported for plaintext snapshots.")


def recorded_path(value):
    """Normalize a path without requiring its drive to be connected."""
    if sys.platform != "win32":
        return Path(os.path.abspath(Path(value).expanduser()))

    expanded = ntpath.expanduser(os.fspath(value)).replace("/", "\\")
    if expanded.casefold().startswith(("\\\\", "\\??\\", "\\device\\", "\\global??\\")):
        raise SnapshotError("Use a local drive-letter path, not a network or device path.")
    drive, tail = ntpath.splitdrive(expanded)
    # An absolute path saved in a manifest is metadata. Do not touch its drive.
    absolute = ntpath.normpath(expanded) if drive and tail.startswith("\\") else ntpath.abspath(expanded)
    drive, tail = ntpath.splitdrive(absolute)
    if not (len(drive) == 2 and drive[0].isascii() and drive[0].isalpha()
            and drive[1] == ":" and tail.startswith("\\")):
        raise SnapshotError("Use a local drive-letter path, not a network or device path.")
    return Path(absolute)


def local_path(value):
    path = recorded_path(value)
    if sys.platform == "win32":
        root = ntpath.splitdrive(os.fspath(path))[0] + "\\"
        try:
            drive_type = _windows_drive_type(root)
        except (AttributeError, OSError) as exc:
            raise SnapshotError("Cannot verify that the selected drive is local.") from exc
        # GetDriveTypeW: removable, fixed, optical and RAM drives are local.
        if drive_type not in {2, 3, 5, 6}:
            raise SnapshotError("Use a verified local drive. Network or unavailable drives are unsupported.")
    else:
        _check_unix_local_fs(path)
    return path


def checked_stat(path):
    entry = path.lstat()
    reparse_point = getattr(entry, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
    if stat.S_ISLNK(entry.st_mode) or reparse_point:
        raise SnapshotError("The path contains a symbolic link or reparse point.")
    if stat.S_ISREG(entry.st_mode) and getattr(entry, "st_nlink", 1) > 1:
        raise SnapshotError("The path contains a hard-linked file.")
    return entry


def check_ancestors(path, *, allow_missing=False):
    for ancestor in (*reversed(path.parents), path):
        try:
            mode = checked_stat(ancestor).st_mode
        except FileNotFoundError:
            if allow_missing:
                return
            raise
        if not stat.S_ISDIR(mode):
            raise SnapshotError("A directory path contains a non-directory entry.")


def require_data_directory(path):
    check_ancestors(path)
    try:
        if stat.S_ISREG(checked_stat(path / CONFIG_NAME).st_mode):
            return
    except FileNotFoundError:
        pass
    raise SnapshotError(f"The data directory must contain a regular {CONFIG_NAME} file.")


def hash_regular_file(path):
    info = checked_stat(path)
    if not stat.S_ISREG(info.st_mode):
        raise SnapshotError("The tree contains a non-regular file.")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or getattr(opened, "st_nlink", 1) > 1
            or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino)
        ):
            raise SnapshotError("The file changed or is not an unlinked regular file.")
        digest = hashlib.sha256()
        size = 0
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            while block := stream.read(1024 * 1024):
                size += len(block)
                digest.update(block)
    finally:
        if fd >= 0:
            os.close(fd)
    return {"size": size, "sha256": digest.hexdigest()}


def inventory(directory):
    check_ancestors(directory)
    folders = []
    files = {}

    def visit(folder):
        for entry in sorted(folder.iterdir(), key=lambda item: item.name):
            name = entry.relative_to(directory).as_posix()
            mode = checked_stat(entry).st_mode
            if stat.S_ISDIR(mode):
                folders.append(name)
                visit(entry)
            elif stat.S_ISREG(mode):
                files[name] = hash_regular_file(entry)
            else:
                raise SnapshotError("The tree contains a non-regular file.")

    visit(directory)
    return {"directories": folders, "files": files}


def copy_tree(source, destination, expected, *, preserve_metadata=True):
    # Read paths discovered in the source itself, never paths from a snapshot manifest.
    observed = inventory(source)
    if observed != expected:
        raise SnapshotError("The source tree changed before copying.")
    destination.mkdir(mode=0o700)
    restrict_private_permissions(destination, is_dir=True)
    for folder in observed["directories"]:
        sub = destination / folder
        sub.mkdir(mode=0o700)
    copy_file = shutil.copy2 if preserve_metadata else shutil.copyfile
    for name in observed["files"]:
        origin = source / name
        check_ancestors(origin.parent)
        info = checked_stat(origin)
        if not stat.S_ISREG(info.st_mode):
            raise SnapshotError("A source file changed type during the copy.")
        copy_file(origin, destination / name, follow_symlinks=False)
        if os.name == "posix" and not preserve_metadata:
            os.chmod(destination / name, 0o600)
    if inventory(destination) != expected or inventory(source) != expected:
        raise SnapshotError("The source or copy changed during the operation.")


def _comparable_path(path):
    raw = os.fspath(path)
    if sys.platform == "win32":
        raw = _windows_long_path_if_exists(raw)
    if os.name == "nt" or sys.platform == "darwin":
        return PurePath(raw.casefold())
    return PurePath(raw)


def path_is_within(candidate, root):
    if candidate.is_relative_to(root):
        return True
    c_cand, c_root = _comparable_path(candidate), _comparable_path(root)
    if c_cand == c_root or c_cand.is_relative_to(c_root):
        return True
    if isinstance(os, types.ModuleType):
        try:
            if os.path.exists(candidate) and os.path.exists(root) and os.path.samefile(candidate, root):
                return True
        except OSError:
            pass
    return False


def paths_overlap(left, right):
    return path_is_within(left, right) or path_is_within(right, left)


def ensure_distinct(left, right):
    if paths_overlap(left, right):
        raise SnapshotError("The snapshot and data directory must not overlap.")


def write_restore_launcher(stage, original_source):
    shutil.copyfile(Path(__file__).resolve(), stage / "config_snapshot.py")
    launcher = f'''"""Offline, config-only restore for this snapshot."""
from pathlib import Path
import sys

sys.dont_write_bytecode = True
SNAPSHOT_DIR = Path(__file__).absolute().parent
ALLOWED_ENTRIES = {{"data", "manifest.json", "config_snapshot.py", "restore.py"}}
if any(entry.name not in ALLOWED_ENTRIES for entry in SNAPSHOT_DIR.iterdir()):
    sys.exit("Refusing to run: unexpected files are present in the snapshot directory.")
if str(SNAPSHOT_DIR) not in sys.path:
    sys.path.insert(0, str(SNAPSHOT_DIR))
from config_snapshot import main

flags = sys.argv[1:]
if any(flag not in {{"--apply", "--client-stopped", "--help", "-h"}} for flag in flags):
    sys.exit("Supported options: --apply --client-stopped, or --help.")
args = ["restore", str(SNAPSHOT_DIR), "--config-dir", {str(original_source)!r}]
raise SystemExit(main([*args, *flags]))
'''
    (stage / "restore.py").write_text(launcher, encoding="utf-8")
    return {name: hash_regular_file(stage / name) for name in LAUNCHER_FILES}


def create_snapshot(source, backup_root=DEFAULT_BACKUP_ROOT):
    source, backup_root = local_path(source), local_path(backup_root)
    require_data_directory(source)
    ensure_distinct(source, backup_root)
    check_ancestors(backup_root, allow_missing=True)
    created_root = not backup_root.exists()
    backup_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if created_root:
        restrict_private_permissions(backup_root, is_dir=True)
    check_ancestors(backup_root)
    expected = inventory(source)
    if CONFIG_NAME not in expected["files"]:
        raise SnapshotError("The data directory changed during the backup.")
    stage = Path(tempfile.mkdtemp(prefix=".v2rayn-backup-", dir=backup_root))
    try:
        restrict_private_permissions(stage, is_dir=True)
        copy_tree(source, stage / PAYLOAD_NAME, expected)
        launcher_hashes = write_restore_launcher(stage, source)
        manifest = {
            "version": 1,
            "source": str(source),
            "inventory": expected,
            "launcher": launcher_hashes,
        }
        (stage / MANIFEST_NAME).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        verify_snapshot(stage)
        label = datetime.now().strftime("%Y%m%d-%H%M%S")
        snapshot = backup_root / f"{label}-{uuid4().hex[:8]}"
        stage.rename(snapshot)
        return snapshot
    finally:
        safe_rmtree(stage)


def verify_snapshot(snapshot):
    snapshot = local_path(snapshot)
    check_ancestors(snapshot)
    allowed_entries = {PAYLOAD_NAME, MANIFEST_NAME, *LAUNCHER_FILES}
    present_entries = {entry.name for entry in snapshot.iterdir()}
    if not present_entries <= allowed_entries:
        raise SnapshotError("The snapshot directory contains unexpected files.")
    manifest_path = snapshot / MANIFEST_NAME
    manifest_stat = checked_stat(manifest_path)
    if not stat.S_ISREG(manifest_stat.st_mode) or manifest_stat.st_size > MAX_MANIFEST_BYTES:
        raise SnapshotError("The snapshot manifest must be a regular file.")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise SnapshotError("The snapshot manifest is invalid.") from exc
    if (
        not isinstance(manifest, dict)
        or manifest.get("version") != 1
        or not isinstance(manifest.get("source"), str)
        or not Path(manifest["source"]).is_absolute()
    ):
        raise SnapshotError("The snapshot format or source path is invalid.")
    launcher_record = manifest.get("launcher")
    has_launcher_files = bool(present_entries & set(LAUNCHER_FILES))
    if launcher_record is not None or has_launcher_files:
        if (
            not isinstance(launcher_record, dict)
            or set(launcher_record.keys()) != set(LAUNCHER_FILES)
            or not set(LAUNCHER_FILES) <= present_entries
        ):
            raise SnapshotError("The snapshot restore launcher metadata is missing or incomplete.")
        actual_launcher = {name: hash_regular_file(snapshot / name) for name in LAUNCHER_FILES}
        if actual_launcher != launcher_record:
            raise SnapshotError("The snapshot restore launcher does not match its manifest.")
    payload = snapshot / PAYLOAD_NAME
    require_data_directory(payload)
    verified = inventory(payload)
    if verified != manifest.get("inventory"):
        raise SnapshotError("The backup does not match its manifest.")
    # A verified backup can be inspected or recovered after its original drive is removed.
    return recorded_path(manifest["source"]), verified


def recover_snapshot(snapshot, destination):
    snapshot, destination = local_path(snapshot), local_path(destination)
    original_source, expected = verify_snapshot(snapshot)
    check_ancestors(destination)
    if path_is_within(destination, snapshot) or path_is_within(destination, original_source):
        raise SnapshotError("Choose a recovery directory outside the snapshot and the original data.")

    # Reserve the name atomically. Only publish guiConfigs once its full inventory matches.
    folder = Path(tempfile.mkdtemp(prefix="v2rayn-recovery-", dir=destination))
    prepared = folder / ".prepared"
    recovered = folder / "guiConfigs"
    try:
        restrict_private_permissions(folder, is_dir=True)
        copy_tree(snapshot / PAYLOAD_NAME, prepared, expected)
        prepared.rename(recovered)
    except BaseException:
        safe_rmtree(folder)
        raise
    return recovered


def _trusted_windows_system_root():
    if sys.platform == "win32" and isinstance(os, types.ModuleType):
        import ctypes
        import ctypes.wintypes as wt

        kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
        get_sys_win = kernel32.GetSystemWindowsDirectoryW
        get_sys_win.argtypes = [wt.LPWSTR, wt.UINT]
        get_sys_win.restype = wt.UINT
        buf = ctypes.create_unicode_buffer(512)
        length = get_sys_win(buf, len(buf))
        if 0 < length < len(buf):
            return buf.value
    return (os.environ.get("SystemRoot") or "").strip()


def ensure_v2rayn_stopped():
    if os.name != "nt":
        raise SnapshotError("Applying a restore requires Windows.")
    system_root = _trusted_windows_system_root()
    if not system_root:
        raise SnapshotError("Could not locate Windows PowerShell.")
    powershell = Path(system_root) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    quoted_names = ", ".join(f"'{name}'" for name in PROXY_PROCESS_NAMES)
    result = subprocess.run(
        [
            str(powershell),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            f"@(Get-Process -ErrorAction Stop | Where-Object {{ $_.ProcessName -in @({quoted_names}) }}).Count",
        ],
        capture_output=True,
        timeout=20,
        check=True,
    )
    if result.stdout.decode("utf-8-sig", errors="replace").strip() != "0":
        raise SnapshotError("v2rayN or its proxy core is running, or its state could not be confirmed.")


def restore_snapshot(snapshot, target, *, apply=False, client_stopped=False):
    snapshot, target = local_path(snapshot), local_path(target)
    original_source, expected = verify_snapshot(snapshot)
    if _comparable_path(original_source) != _comparable_path(target):
        raise SnapshotError("The target does not match the data directory recorded in the snapshot.")
    ensure_distinct(snapshot, target)
    check_ancestors(target.parent)
    had_target = os.path.lexists(target)
    if had_target:
        require_data_directory(target)
        inventory(target)
    if not apply:
        return None
    if not client_stopped:
        raise SnapshotError("Close the GUI and its core, then use --apply --client-stopped.")

    ensure_v2rayn_stopped()
    stage = Path(tempfile.mkdtemp(prefix=".v2rayn-restore-", dir=target.parent))
    prepared = stage / "prepared"
    previous = stage / "previous"
    try:
        restrict_private_permissions(stage, is_dir=True)
        copy_tree(snapshot / PAYLOAD_NAME, prepared, expected)
        if had_target != os.path.lexists(target):
            raise SnapshotError("The target appeared or disappeared during preparation.")
        if had_target:
            require_data_directory(target)
            inventory(target)
        ensure_v2rayn_stopped()
        try:
            if had_target:
                target.rename(previous)
            prepared.rename(target)
        except (OSError, KeyboardInterrupt) as primary_error:
            if os.path.lexists(previous):
                try:
                    if os.path.lexists(target):
                        raise OSError("Restore destination appeared during promotion.")
                    previous.rename(target)
                except OSError as rollback_error:
                    raise SnapshotError(
                        f"Automatic recovery failed. The prior data is still in {previous}."
                    ) from rollback_error
            raise SnapshotError("Promotion failed. The prior data remains at its original path if it existed.") from primary_error
        return previous if had_target else None
    finally:
        if not os.path.lexists(previous):
            safe_rmtree(stage)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    backup = commands.add_parser("backup", help="Create a local, verified data-directory snapshot")
    backup.add_argument("--config-dir", required=True)
    backup.add_argument("--backup-root", default=DEFAULT_BACKUP_ROOT)

    verify = commands.add_parser("verify", help="Verify a snapshot before use")
    verify.add_argument("snapshot")

    recover = commands.add_parser("recover", help="Recover a verified copy in a new folder")
    recover.add_argument("snapshot")
    recover.add_argument("--destination", required=True, help="Existing local parent for the new recovery folder")

    restore = commands.add_parser("restore", help="Preview or apply a config-only restore")
    restore.add_argument("snapshot")
    restore.add_argument("--config-dir", required=True)
    restore.add_argument("--apply", action="store_true")
    restore.add_argument("--client-stopped", action="store_true")

    args = parser.parse_args(argv)
    try:
        if args.command == "backup":
            print(f"Verified snapshot: {create_snapshot(args.config_dir, args.backup_root)}")
        elif args.command == "verify":
            source, checked = verify_snapshot(args.snapshot)
            print(f"Snapshot verified ({len(checked['files'])} files). Original directory: {source}")
        elif args.command == "recover":
            print(f"Verified recovery copy: {recover_snapshot(args.snapshot, args.destination)}")
        else:
            previous = restore_snapshot(args.snapshot, args.config_dir,
                                        apply=args.apply, client_stopped=args.client_stopped)
            if args.apply:
                print("Config-only restore completed.")
                if previous is not None:
                    print(f"Prior config retained at: {previous}")
            else:
                print("Restore preview validated. No files changed.")
    except SnapshotError as error:
        print(f"Snapshot operation stopped: {error}", file=sys.stderr)
        return 1
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        # Avoid displaying exception contents that could contain local data.
        print(f"Snapshot operation stopped ({type(error).__name__}).", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
