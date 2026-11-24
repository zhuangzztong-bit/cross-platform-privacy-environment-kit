import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import config_snapshot as snapshots


class ConfigSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(lambda: snapshots.safe_rmtree(self.temp.name))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.config = self.root / "guiConfigs"
        self.config.mkdir()
        self.marker = self.config / snapshots.CONFIG_NAME
        self.marker.write_text('{"fixture": "baseline"}', encoding="utf-8")
        (self.config / "profiles").mkdir()
        (self.config / "profiles" / "example.db").write_bytes(b"fixture-db")
        (self.config / "empty").mkdir()
        self.backups = self.root / "backups"

    def create(self):
        return snapshots.create_snapshot(self.config, self.backups)

    def test_verified_copy_covers_directories_and_data(self):
        path = self.create()
        original, contents = snapshots.verify_snapshot(path)
        self.assertEqual(original, self.config)
        self.assertEqual(contents["directories"], ["empty", "profiles"])
        self.assertEqual(set(contents["files"]), {snapshots.CONFIG_NAME, "profiles/example.db"})

    def test_self_contained_restore_launcher_previews_and_rejects_injected_modules(self):
        path = self.create()
        self.marker.write_text("current", encoding="utf-8")
        env = dict(os.environ, PYTHONSAFEPATH="1")
        result = subprocess.run([sys.executable, str(path / "restore.py")], capture_output=True,
                                check=True, timeout=10, text=True, env=env)
        self.assertIn("Restore preview validated", result.stdout)
        self.assertEqual(self.marker.read_text(encoding="utf-8"), "current")
        self.assertFalse((path / "__pycache__").exists())

        # Dropping an unexpected file in the snapshot directory is caught by both verify and restore.py
        (path / "rogue.py").write_text("raise RuntimeError('hijacked')\n", encoding="utf-8")
        with self.assertRaisesRegex(snapshots.SnapshotError, "unexpected files"):
            snapshots.verify_snapshot(path)
        blocked = subprocess.run([sys.executable, str(path / "restore.py")], capture_output=True,
                                 timeout=10, text=True, env=env)
        self.assertNotEqual(blocked.returncode, 0)
        self.assertIn("unexpected files", blocked.stderr)

    def test_tampered_restore_launcher_is_rejected_by_verify(self):
        path = self.create()
        (path / "restore.py").write_text("# tampered\n", encoding="utf-8")
        with self.assertRaisesRegex(snapshots.SnapshotError, "launcher does not match"):
            snapshots.verify_snapshot(path)

    @unittest.skipUnless(os.name == "nt", "Requires Windows NTFS ACLs")
    def test_windows_snapshot_directory_removes_inherited_shared_user_acls(self):
        path = self.create()
        out = subprocess.check_output(["icacls", str(path)], text=True)
        for shared_principal in ("BUILTIN\\Users", "NT AUTHORITY\\Authenticated Users", "Everyone"):
            self.assertNotIn(shared_principal, out)

    def test_hardlinked_config_file_is_rejected(self):
        outside = self.root / "outside-secret.json"
        outside.write_text('{"secret": true}', encoding="utf-8")
        try:
            os.link(outside, self.config / "hardlinked.json")
        except OSError:
            self.skipTest("hardlinks unavailable")
        with self.assertRaisesRegex(snapshots.SnapshotError, "hard-linked"):
            self.create()

    def test_modified_backup_is_rejected(self):
        path = self.create()
        (path / snapshots.PAYLOAD_NAME / snapshots.CONFIG_NAME).write_text("changed", encoding="utf-8")
        with self.assertRaisesRegex(snapshots.SnapshotError, "does not match"):
            snapshots.verify_snapshot(path)

    def test_invalid_manifest_json_raises_snapshot_error(self):
        path = self.create()
        (path / snapshots.MANIFEST_NAME).write_text("{corrupted", encoding="utf-8")
        with self.assertRaisesRegex(snapshots.SnapshotError, "manifest is invalid"):
            snapshots.verify_snapshot(path)

    def test_readonly_files_can_abort_and_clean_stage(self):
        readonly_file = self.config / "profiles" / "readonly.json"
        readonly_file.write_text("{}", encoding="utf-8")
        os.chmod(readonly_file, stat.S_IREAD)
        try:
            actual_copy = snapshots.shutil.copy2

            def copy_and_change(source, destination, **kwargs):
                actual_copy(source, destination, **kwargs)
                self.marker.write_text("changed", encoding="utf-8")

            with patch.object(snapshots.shutil, "copy2", side_effect=copy_and_change):
                with self.assertRaisesRegex(snapshots.SnapshotError, "changed during"):
                    self.create()
            self.assertEqual(list(self.backups.iterdir()), [])
        finally:
            os.chmod(readonly_file, stat.S_IWRITE | stat.S_IREAD)

    def test_readonly_cleanup_leaves_parent_permissions_alone(self):
        readonly_file = self.config / "readonly.json"
        readonly_file.write_text("fixture", encoding="utf-8")
        readonly_file.chmod(stat.S_IREAD)
        original_parent_mode = self.config.stat().st_mode
        snapshots._remove_readonly(os.unlink, readonly_file, PermissionError())
        self.assertFalse(readonly_file.exists())
        self.assertEqual(self.config.stat().st_mode, original_parent_mode)

    def test_readonly_cleanup_does_not_change_link_target(self):
        link = self.config / "linked.json"
        try:
            link.symlink_to(self.marker)
        except OSError:
            self.skipTest("Creating a fixture symlink is unavailable")
        original_mode = self.marker.stat().st_mode
        with self.assertRaisesRegex(snapshots.SnapshotError, "link or reparse point"):
            snapshots._remove_readonly(os.unlink, link, PermissionError())
        self.assertEqual(self.marker.stat().st_mode, original_mode)

    def test_tampered_inventory_cannot_select_paths(self):
        path = self.create()
        manifest_path = path / snapshots.MANIFEST_NAME
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["inventory"]["files"]["../outside"] = {"size": 0, "sha256": "0" * 64}
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(snapshots.SnapshotError, "does not match"):
            snapshots.verify_snapshot(path)
        self.assertFalse((self.root / "outside").exists())

    def test_unrecognized_directory_and_overlapping_backup_are_rejected(self):
        with self.assertRaises(snapshots.SnapshotError):
            snapshots.create_snapshot(self.config, self.config / "backups")
        self.marker.unlink()
        with self.assertRaises((snapshots.SnapshotError, FileNotFoundError)):
            self.create()
        self.assertFalse(self.backups.exists())

    def test_symbolic_links_are_rejected(self):
        try:
            (self.config / "linked.json").symlink_to(self.marker)
        except OSError:
            self.skipTest("Creating a fixture symlink is unavailable")
        with self.assertRaisesRegex(snapshots.SnapshotError, "link or reparse point"):
            self.create()
        self.assertEqual(list(self.backups.iterdir()), [])

    def test_source_change_during_copy_leaves_no_published_backup(self):
        actual_copy = snapshots.shutil.copy2

        def copy_and_change(source, destination, **kwargs):
            actual_copy(source, destination, **kwargs)
            self.marker.write_text("modified while copying", encoding="utf-8")

        with patch.object(snapshots.shutil, "copy2", side_effect=copy_and_change):
            with self.assertRaisesRegex(snapshots.SnapshotError, "changed during"):
                self.create()
        self.assertEqual(list(self.backups.iterdir()), [])

    def test_restore_requires_original_path(self):
        path = self.create()
        with self.assertRaisesRegex(snapshots.SnapshotError, "target does not match"):
            snapshots.restore_snapshot(path, self.root / "other")
        self.assertIn("baseline", self.marker.read_text(encoding="utf-8"))

    def test_recover_cli_with_missing_marker_preserves_damaged_original(self):
        snapshot = self.create()
        self.marker.unlink()
        database = self.config / "profiles" / "example.db"
        database.write_bytes(b"remaining local data")
        with self.assertRaisesRegex(snapshots.SnapshotError, snapshots.CONFIG_NAME):
            snapshots.restore_snapshot(snapshot, self.config)

        script = Path(snapshots.__file__).resolve()
        subprocess.run([sys.executable, "-B", str(script), "recover", str(snapshot),
                        "--destination", str(self.root)], capture_output=True, check=True, timeout=10)
        recovered, = self.root.glob("v2rayn-recovery-*/guiConfigs")
        _, expected = snapshots.verify_snapshot(snapshot)
        self.assertEqual(snapshots.inventory(recovered), expected)
        self.assertFalse(self.marker.exists())
        self.assertEqual(database.read_bytes(), b"remaining local data")

    def test_detached_recovery_and_retries_do_not_touch_original_or_each_other(self):
        snapshot = self.create()
        snapshots.safe_rmtree(self.config)
        actual_local_path = snapshots.local_path

        def accessible_path(value):
            if Path(value) == self.config:
                self.fail("Recovery queried the original path")
            return actual_local_path(value)

        with patch.object(snapshots, "local_path", side_effect=accessible_path):
            first = snapshots.recover_snapshot(snapshot, self.root)
            (first / snapshots.CONFIG_NAME).write_text("prior recovery")
            second = snapshots.recover_snapshot(snapshot, self.root)
        self.assertNotEqual(first.parent, second.parent)
        self.assertEqual((first / snapshots.CONFIG_NAME).read_text(), "prior recovery")
        self.assertIn("baseline", (second / snapshots.CONFIG_NAME).read_text())
        self.assertFalse(self.config.exists())

    def test_recovery_rejects_overlapping_and_missing_destinations(self):
        snapshot = self.create()
        for destination in (snapshot, snapshot / snapshots.PAYLOAD_NAME, self.config, self.config / "empty"):
            with self.subTest(destination=destination), self.assertRaisesRegex(snapshots.SnapshotError, "outside"):
                snapshots.recover_snapshot(snapshot, destination)
        with self.assertRaises(FileNotFoundError):
            snapshots.recover_snapshot(snapshot, self.root / "missing")
        self.assertFalse(list(self.root.rglob("v2rayn-recovery-*")))

    def test_recovery_rejects_linked_destination(self):
        snapshot = self.create()
        link = self.root / "linked-destination"
        try:
            link.symlink_to(self.root, target_is_directory=True)
        except OSError:
            self.skipTest("Creating a fixture directory symlink is unavailable")
        try:
            with self.assertRaisesRegex(snapshots.SnapshotError, "link or reparse point"):
                snapshots.recover_snapshot(snapshot, link)
            self.assertFalse(list(self.root.glob("v2rayn-recovery-*")))
        finally:
            link.unlink()

    def test_recovery_rejects_tampering_and_cleans_partial_copy(self):
        snapshot = self.create()
        with patch.object(snapshots.shutil, "copy2", side_effect=OSError("fixture copy failure")):
            with self.assertRaisesRegex(OSError, "fixture copy failure"):
                snapshots.recover_snapshot(snapshot, self.root)
        self.assertFalse(list(self.root.glob("v2rayn-recovery-*")))
        (snapshot / snapshots.PAYLOAD_NAME / snapshots.CONFIG_NAME).write_text("damaged")
        with self.assertRaisesRegex(snapshots.SnapshotError, "does not match"):
            snapshots.recover_snapshot(snapshot, self.root)
        self.assertFalse(list(self.root.glob("v2rayn-recovery-*")))

    def test_preview_and_missing_stop_confirmation_do_not_write(self):
        path = self.create()
        self.marker.write_text("current", encoding="utf-8")
        with patch.object(snapshots, "ensure_v2rayn_stopped") as check:
            self.assertIsNone(snapshots.restore_snapshot(path, self.config))
            with self.assertRaisesRegex(snapshots.SnapshotError, "Close the GUI"):
                snapshots.restore_snapshot(path, self.config, apply=True)
            check.assert_not_called()
        self.assertEqual(self.marker.read_text(encoding="utf-8"), "current")
        self.assertFalse(list(self.root.glob(".v2rayn-restore-*")))

    def test_running_gui_blocks_restore(self):
        path = self.create()
        self.marker.write_text("current", encoding="utf-8")
        with patch.object(snapshots, "ensure_v2rayn_stopped", side_effect=snapshots.SnapshotError("running")):
            with self.assertRaisesRegex(snapshots.SnapshotError, "running"):
                snapshots.restore_snapshot(path, self.config, apply=True, client_stopped=True)
        self.assertEqual(self.marker.read_text(encoding="utf-8"), "current")
        self.assertFalse(list(self.root.glob(".v2rayn-restore-*")))

    def test_windows_restore_check_counts_gui_and_all_supported_cores(self):
        windows = SimpleNamespace(name="nt", environ={"SystemRoot": str(self.root)})
        with patch.object(snapshots, "os", windows), patch.object(
            snapshots.subprocess, "run",
            return_value=subprocess.CompletedProcess([], 0, stdout=b"1\n"),
        ) as run:
            with self.assertRaisesRegex(snapshots.SnapshotError, "proxy core is running"):
                snapshots.ensure_v2rayn_stopped()
            arguments = run.call_args.args[0]
        for name in ("v2rayN", "xray", "sing-box", "v2ray", "mihomo", "hysteria2", "tuic-client", "naive"):
            self.assertIn(f"'{name}'", arguments[-1])

    def test_restore_promotes_verified_copy_and_preserves_previous(self):
        path = self.create()
        self.marker.write_text("current", encoding="utf-8")
        with patch.object(snapshots, "ensure_v2rayn_stopped") as check:
            previous = snapshots.restore_snapshot(path, self.config, apply=True, client_stopped=True)
            self.assertEqual(check.call_count, 2)
        self.assertIn("baseline", self.marker.read_text(encoding="utf-8"))
        self.assertEqual((previous / snapshots.CONFIG_NAME).read_text(encoding="utf-8"), "current")

    def test_failed_promotion_rolls_back_previous(self):
        path = self.create()
        self.marker.write_text("current", encoding="utf-8")
        actual_rename = Path.rename

        def fail_promotion(source, target):
            if source.name == "prepared":
                raise OSError("fixture error during promotion")
            return actual_rename(source, target)

        with patch.object(snapshots, "ensure_v2rayn_stopped"), patch.object(Path, "rename", fail_promotion):
            with self.assertRaisesRegex(snapshots.SnapshotError, "remains at its original path"):
                snapshots.restore_snapshot(path, self.config, apply=True, client_stopped=True)
        self.assertEqual(self.marker.read_text(encoding="utf-8"), "current")
        self.assertFalse(list(self.root.glob(".v2rayn-restore-*")))

    def test_interrupted_promotion_can_restore_previous(self):
        path = self.create()
        self.marker.write_text("current", encoding="utf-8")
        actual_rename = Path.rename

        def interrupt_promotion(source, target):
            if source.name == "prepared":
                raise KeyboardInterrupt()
            return actual_rename(source, target)

        with patch.object(snapshots, "ensure_v2rayn_stopped"), patch.object(Path, "rename", interrupt_promotion):
            with self.assertRaisesRegex(snapshots.SnapshotError, "remains at its original path"):
                snapshots.restore_snapshot(path, self.config, apply=True, client_stopped=True)
        self.assertEqual(self.marker.read_text(encoding="utf-8"), "current")

    def test_failed_automatic_recovery_retains_previous(self):
        path = self.create()
        self.marker.write_text("current", encoding="utf-8")
        actual_rename = Path.rename

        def fail_both_moves(source, target):
            if source.name in {"prepared", "previous"}:
                raise OSError("fixture error during promotion or recovery")
            return actual_rename(source, target)

        with patch.object(snapshots, "ensure_v2rayn_stopped"), patch.object(Path, "rename", fail_both_moves):
            with self.assertRaisesRegex(snapshots.SnapshotError, "Automatic recovery failed"):
                snapshots.restore_snapshot(path, self.config, apply=True, client_stopped=True)
        self.assertFalse(self.config.exists())
        previous, = self.root.glob(".v2rayn-restore-*/previous")
        self.assertEqual((previous / snapshots.CONFIG_NAME).read_text(encoding="utf-8"), "current")


if __name__ == "__main__":
    unittest.main()
