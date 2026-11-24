from contextlib import redirect_stderr
from io import StringIO
import os
from pathlib import Path
import unittest
from unittest.mock import patch

import claude_local_data
import config_snapshot as snapshots


@patch.object(snapshots.sys, "platform", "win32")
class WindowsStoragePolicyTests(unittest.TestCase):
    def test_accepts_known_local_volume_types(self):
        for drive_type in (2, 3, 5, 6):
            with self.subTest(drive_type=drive_type), patch.object(
                snapshots, "_windows_drive_type", return_value=drive_type
            ) as query:
                self.assertEqual(str(snapshots.local_path("C:/fixture")), r"C:\fixture")
                query.assert_called_once_with("C:\\")

    def test_unc_and_device_namespaces_are_rejected_before_resolution(self):
        inputs = (r"\\server\share\work", "//server/share/work", r"\\?\C:\work",
                  r"\\?\UNC\server\share", r"\\.\pipe\name", r"\??\UNC\server\share",
                  r"\Device\Mup\server\share")
        with patch.object(snapshots.ntpath, "abspath") as resolve, patch.object(
            snapshots, "_windows_drive_type"
        ) as query:
            for value in inputs:
                with self.subTest(value=value), self.assertRaises(snapshots.SnapshotError):
                    snapshots.local_path(value)
            resolve.assert_not_called()
            query.assert_not_called()

    def test_relative_path_in_network_current_directory_is_rejected(self):
        with patch.object(snapshots.ntpath, "abspath", return_value=r"\\server\share\folder"), patch.object(
            snapshots, "_windows_drive_type"
        ) as query:
            with self.assertRaises(snapshots.SnapshotError):
                snapshots.local_path("folder")
            query.assert_not_called()

    def test_remote_unknown_and_unavailable_drives_are_rejected(self):
        for drive_type in (4, 0, 1, 99):
            with self.subTest(drive_type=drive_type), patch.object(
                snapshots, "_windows_drive_type", return_value=drive_type
            ), self.assertRaises(snapshots.SnapshotError):
                snapshots.local_path("Z:/work")
        with patch.object(snapshots, "_windows_drive_type", side_effect=OSError), self.assertRaises(
            snapshots.SnapshotError
        ):
            snapshots.local_path("Z:/work")

    def test_recorded_absolute_source_never_requires_an_attached_volume(self):
        with patch.object(snapshots.ntpath, "abspath") as resolve, patch.object(
            snapshots, "_windows_drive_type"
        ) as query:
            self.assertEqual(str(snapshots.recorded_path("E:/old/guiConfigs")), r"E:\old\guiConfigs")
            resolve.assert_not_called()
            query.assert_not_called()

    def test_both_backup_commands_reject_a_mapped_destination_before_io(self):
        def drive_type(root):
            return {"C:\\": 3, "Z:\\": 4}[root]

        with patch.object(snapshots, "_windows_drive_type", side_effect=drive_type), patch.object(
            snapshots, "require_data_directory"
        ) as inspect_config, patch.object(claude_local_data, "scan_work") as scan, redirect_stderr(StringIO()):
            self.assertEqual(snapshots.main([
                "backup", "--config-dir", "C:/test/guiConfigs", "--backup-root", "Z:/backups"
            ]), 1)
            self.assertEqual(claude_local_data.main([
                "backup", "--config-dir", "C:/test/claude", "--destination", "Z:/backups"
            ]), 1)
            inspect_config.assert_not_called()
            scan.assert_not_called()


@unittest.skipUnless(os.name == "nt", "Requires native Windows GetDriveTypeW")
class NativeWindowsStorageTests(unittest.TestCase):
    def test_system_volume_is_local(self):
        system_dir = Path(os.environ["SystemRoot"])
        self.assertEqual(snapshots.local_path(system_dir), system_dir)


if __name__ == "__main__":
    unittest.main()
