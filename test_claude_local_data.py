from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import claude_local_data as data


class ClaudeLocalDataTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.config = self.root / "private-config-name"
        self.project = self.root / "private-project-name"
        self.destination = self.root / "backups"
        self.recovery_path = self.root / "recovered"
        self.destination.mkdir()
        self.recovery_path.mkdir()

    def seed(self, path, content=b"private-test-content"):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    def test_absent_config_produces_empty_redacted_json(self):
        out = StringIO()
        before = set(self.root.iterdir())
        with redirect_stdout(out):
            self.assertEqual(data.main(["audit", "--config-dir", str(self.config)]), 0)
        self.assertEqual(set(self.root.iterdir()), before)
        result = json.loads(out.getvalue())
        self.assertFalse(result["user_config_present"])
        self.assertFalse(result["contents_read"])
        self.assertEqual(result["files"], 0)
        self.assertNotIn(self.config.name, out.getvalue())

    def test_default_override_applies_with_explicit_precedence(self):
        self.seed(self.config / "history.jsonl")
        out = StringIO()
        with patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": str(self.config)}), redirect_stdout(out):
            self.assertEqual(data.selected_config(), self.config)
            self.assertEqual(data.selected_config(str(self.project)), self.project)
            self.assertEqual(data.main(["audit"]), 0)
        self.assertEqual(json.loads(out.getvalue())["files"], 1)

    def test_audit_reads_metadata_without_opening_files(self):
        self.seed(self.config / "projects" / "private-session-name.jsonl")
        self.seed(self.config / ".credentials.json", b"TEST-ONLY-NEVER-PRINT")
        self.seed(self.project / ".mcp.json")
        out = StringIO()
        with patch.object(Path, "open", side_effect=AssertionError("unexpected content read")), redirect_stdout(out):
            self.assertEqual(data.main(["audit", "--config-dir", str(self.config),
                                        "--project-dir", str(self.project)]), 0)
        value = json.loads(out.getvalue())
        self.assertEqual(value["files"], 2)
        self.assertEqual(value["excluded_secret_entries"], 1)
        for secret in ("private-config", "private-project", "private-session", "TEST-ONLY", "private-test-content"):
            self.assertNotIn(secret, out.getvalue())

    def test_backup_recovers_selected_files_byte_for_byte(self):
        items = (
            (self.config, "user-config", "projects/foo/session.jsonl"),
            (self.config, "user-config", "skills/example/SKILL.md"),
            (self.config, "user-config", "hooks/hook.py"),
            (self.config, "user-config", "hooks/hook.cmd"),
            (self.config, "user-config", "settings.json"),
            (self.project, "project", "CLAUDE.md"),
            (self.project, "project", ".claude/CLAUDE.md"),
            (self.project, "project", ".mcp.json"),
        )
        for base, _, relative in items:
            self.seed(base / relative, relative.encode())
        self.seed(self.config / ".claude.json")
        self.seed(self.config / "projects" / "private" / ".env.local")
        self.seed(self.config / "skills" / "example" / "private.pem")
        self.seed(self.project / ".git" / "config")
        self.seed(self.project / "source.py")
        self.seed(self.config / "cache" / "cached.bin")
        snapshot = data.backup(self.config, self.project, self.destination)
        self.assertEqual(len(data.verify(snapshot)["files"]), len(items))
        recovered = data.recover(snapshot, self.recovery_path)
        for base, scope, relative in items:
            original = base / relative
            restored = recovered / scope / relative
            self.assertEqual(restored.read_bytes(), original.read_bytes())
        for unsupported in (".claude.json", "projects/private/.env.local", "skills/example/private.pem", "cache/cached.bin"):
            self.assertFalse((recovered / "user-config" / unsupported).exists())
        self.assertFalse((recovered / "project" / ".git").exists())
        self.assertFalse((recovered / "project" / "source.py").exists())
        self.assertFalse((recovered / data.MANIFEST_NAME).exists())
        again = data.recover(snapshot, self.recovery_path)
        self.assertNotEqual(recovered, again)

    def test_blocks_inline_secrets_in_mcp_and_settings_by_default(self):
        self.seed(
            self.project / ".mcp.json",
            b'{"mcpServers":{"gh":{"env":{"GITHUB_PERSONAL_ACCESS_TOKEN":"ghp_1234567890abcdefghij"}}}}',
        )
        with self.assertRaisesRegex(data.SnapshotError, "Inline API keys or auth tokens"):
            data.backup(self.config, self.project, self.destination, require_config=False)
        self.assertEqual(list(self.destination.iterdir()), [])

        # Placeholder env references (${TOKEN}) are safe and allowed.
        self.seed(
            self.project / ".mcp.json",
            b'{"mcpServers":{"gh":{"env":{"GITHUB_PERSONAL_ACCESS_TOKEN":"${GITHUB_TOKEN}"}}}}',
        )
        snapshot = data.backup(self.config, self.project, self.destination, require_config=False)
        self.assertEqual(set(data.verify(snapshot)["files"]), {"project/.mcp.json"})

    def test_hardlinked_secret_file_is_rejected(self):
        secret = self.config / ".credentials.json"
        self.seed(secret, b"TOP-SECRET-TOKEN")
        disguised = self.config / "projects" / "innocent.jsonl"
        disguised.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.link(secret, disguised)
        except OSError:
            self.skipTest("hardlinks unavailable")
        self.assertEqual(data.audit(self.config)["unsafe_or_unavailable"], 1)
        with self.assertRaises(data.SnapshotError):
            data.backup(self.config, None, self.destination)
        self.assertEqual(list(self.destination.iterdir()), [])

    def test_windows_execute_bit_difference_between_lstat_and_fstat_is_ignored(self):
        lstat_info = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o777, st_dev=1, st_ino=2, st_size=10, st_mtime_ns=100,
        )
        fstat_info = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o666, st_dev=1, st_ino=2, st_size=10, st_mtime_ns=100,
        )
        self.assertEqual(data.identity_of(lstat_info), data.identity_of(fstat_info))

    def test_backup_rejects_missing_explicit_project_without_publishing(self):
        self.seed(self.config / "history.jsonl")
        with redirect_stderr(StringIO()) as errors:
            result = data.main(["backup", "--config-dir", str(self.config),
                                "--project-dir", str(self.project), "--destination", str(self.destination)])
        self.assertEqual(result, 1)
        self.assertIn("project directory does not exist", errors.getvalue())
        self.assertEqual(list(self.destination.iterdir()), [])

    def test_backup_rejects_missing_explicit_or_configured_user_directory(self):
        self.seed(self.project / "CLAUDE.md")
        base = ["backup", "--project-dir", str(self.project), "--destination", str(self.destination)]
        for explicit in (True, False):
            with self.subTest(explicit=explicit), redirect_stderr(StringIO()) as errors:
                with patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": str(self.config)}):
                    args = base + ["--config-dir", str(self.config)] if explicit else base
                    self.assertEqual(data.main(args), 1)
            self.assertIn("user configuration directory does not exist", errors.getvalue())
            self.assertEqual(list(self.destination.iterdir()), [])

    def test_project_only_backup_allows_absent_implicit_user_and_project_dot_claude(self):
        self.seed(self.project / "CLAUDE.md")
        with patch.object(Path, "home", return_value=self.root), patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": ""}):
            with redirect_stdout(StringIO()):
                self.assertEqual(data.main(["backup", "--project-dir", str(self.project),
                                            "--destination", str(self.destination)]), 0)
        snapshot, = self.destination.iterdir()
        self.assertEqual(set(data.verify(snapshot)["files"]), {"project/CLAUDE.md"})

    def test_whitespace_env_and_claude_backup_secret_are_handled(self):
        self.seed(self.config / ".claude.json.backup")
        self.seed(self.config / "projects" / "private" / ".CLAUDE.JSON.BACKUP")
        self.seed(self.config / "history.jsonl")
        self.seed(self.project / "CLAUDE.md")

        self.assertEqual(data.audit(self.config)["excluded_secret_entries"], 2)
        snapshot = data.backup(self.config, None, self.destination)
        self.assertEqual(set(data.verify(snapshot)["files"]), {"user-config/history.jsonl"})
        with patch.object(Path, "home", return_value=self.root), patch.dict(
            os.environ, {"CLAUDE_CONFIG_DIR": "   "}
        ), redirect_stdout(StringIO()):
            self.assertEqual(data.selected_config(), self.root / ".claude")
            self.assertEqual(data.main(["backup", "--project-dir", str(self.project),
                                        "--destination", str(self.destination)]), 0)

    def test_missing_destination_raises_snapshot_error(self):
        self.seed(self.config / "history.jsonl")
        missing = self.root / "missing-dest"
        snapshot = data.backup(self.config, None, self.destination)
        with self.assertRaisesRegex(data.SnapshotError, "destination directory does not exist"):
            data.backup(self.config, None, missing)
        with self.assertRaisesRegex(data.SnapshotError, "destination directory does not exist"):
            data.recover(snapshot, missing)
        self.assertFalse(missing.exists())

    def test_windows_config_names_are_case_insensitive(self):
        self.seed(self.config / "History.JSONL")
        self.seed(self.project / "claude.md")
        with patch.object(data, "os", SimpleNamespace(name="nt")):
            files, _, _, _ = data.scan_work(self.config, self.project)
        self.assertEqual({entry.relative.as_posix() for entry in files},
                         {"user-config/History.JSONL", "project/claude.md"})

    @unittest.skipUnless(os.name == "posix", "POSIX file permissions")
    def test_private_payload_recovers_checked_permissions_and_ignores_special_bits(self):
        modes = {"hooks/run.sh": 0o755, "skills/example/helper.sh": 0o700, "settings.json": 0o600}
        for name, mode in modes.items():
            source = self.config / name
            self.seed(source)
            source.chmod(mode)
        (self.config / "hooks/run.sh").chmod(0o4755)
        with redirect_stdout(StringIO()):
            self.assertEqual(data.main(["backup", "--config-dir", str(self.config),
                                        "--destination", str(self.destination)]), 0)
            snapshot, = self.destination.iterdir()
            self.assertEqual(data.main(["verify", str(snapshot)]), 0)
            self.assertEqual(data.main(["recover", str(snapshot), "--destination", str(self.recovery_path)]), 0)
        recovered, = self.recovery_path.iterdir()
        for name, mode in modes.items():
            private = snapshot / data.PAYLOAD_NAME / "user-config" / name
            self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o600)
            target = recovered / "user-config" / name
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), mode)
            self.assertEqual(target.read_bytes(), private.read_bytes())

    def test_missing_invalid_overpermissive_and_corrupt_permission_records_fail_before_recovery(self):
        self.seed(self.config / "history.jsonl")
        snapshot = data.backup(self.config, None, self.destination)
        manifest = snapshot / data.MANIFEST_NAME
        original = json.loads(manifest.read_text(encoding="utf-8"))
        name = "user-config/history.jsonl"
        for modes in ({}, {name: 0o4755}, {name: True}, {name: 0o700}):
            with self.subTest(modes=modes):
                changed = dict(original, posix_modes=modes, posix_modes_sha256="bad")
                manifest.write_text(json.dumps(changed), encoding="utf-8")
                with self.assertRaisesRegex(data.SnapshotError, "permissions"):
                    data.verify(snapshot)
                with self.assertRaises(data.SnapshotError):
                    data.recover(snapshot, self.recovery_path)
        # Even with a valid checksum, group/world-writable modes (0o777, 0o666) must fail.
        for writable_mode in (0o777, 0o666):
            modes = {name: writable_mode}
            changed = dict(original, posix_modes=modes, posix_modes_sha256=data.permissions_digest(modes))
            manifest.write_text(json.dumps(changed), encoding="utf-8")
            with self.assertRaisesRegex(data.SnapshotError, "permissions"):
                data.verify(snapshot)
        self.assertEqual(list(self.recovery_path.iterdir()), [])

    def test_v1_and_windows_origin_snapshots_without_modes_recover_privately(self):
        self.seed(self.config / "hooks" / "run.sh")
        snapshot = data.backup(self.config, None, self.destination)
        manifest = snapshot / data.MANIFEST_NAME
        original = json.loads(manifest.read_text(encoding="utf-8"))
        legacy = {"format": 1, "inventory": original["inventory"]}
        windows = dict(original, posix_modes=None, posix_modes_sha256=data.permissions_digest(None))
        for record in (legacy, windows):
            with self.subTest(version=record["format"]):
                manifest.write_text(json.dumps(record), encoding="utf-8")
                self.assertEqual(len(data.verify(snapshot)["files"]), 1)
                recovered = data.recover(snapshot, self.recovery_path)
                restored = recovered / "user-config" / "hooks" / "run.sh"
                self.assertEqual(restored.read_bytes(), b"private-test-content")
                if os.name == "posix":
                    self.assertEqual(stat.S_IMODE(restored.stat().st_mode), 0o600)

    def test_backup_and_recovery_reject_overlapping_destinations(self):
        self.seed(self.config / "history.jsonl")
        with self.assertRaises(data.SnapshotError):
            data.backup(self.config, None, self.config)
        nested_config = self.project / ".claude" / "nested"
        self.seed(nested_config / "history.jsonl")
        with self.assertRaises(data.SnapshotError):
            data.audit(nested_config, self.project)
        snapshot = data.backup(self.config, None, self.destination)
        with self.assertRaises(data.SnapshotError):
            data.recover(snapshot, snapshot)

    def test_audit_counts_links_and_backup_rejects_them(self):
        self.seed(self.config / "projects" / "safe.jsonl")
        self.seed(self.root / "outside.jsonl")
        candidate = self.config / "projects" / "unsafe.jsonl"
        try:
            candidate.symlink_to(self.root / "outside.jsonl")
        except OSError:
            self.skipTest("symlinks unavailable")
        self.assertEqual(data.audit(self.config)["unsafe_or_unavailable"], 1)
        with self.assertRaises(data.SnapshotError):
            data.backup(self.config, None, self.destination)
        self.assertEqual(list(self.destination.iterdir()), [])

    def test_changed_source_aborts_without_publishing(self):
        source = self.config / "history.jsonl"
        self.seed(source)
        original = data.copy_file

        def copy_and_change(entry, destination):
            result = original(entry, destination)
            source.write_bytes(b"new longer synthetic contents")
            return result

        with patch.object(data, "copy_file", side_effect=copy_and_change):
            with self.assertRaises(data.SnapshotError):
                data.backup(self.config, None, self.destination)
        self.assertEqual(list(self.destination.iterdir()), [])

    def test_verify_rejects_equal_length_altered_payload(self):
        path = "history.jsonl"
        self.seed(self.config / path, b"AAAA")
        snapshot = data.backup(self.config, None, self.destination)
        (snapshot / data.PAYLOAD_NAME / "user-config" / path).write_bytes(b"BBBB")
        with self.assertRaises(data.SnapshotError):
            data.verify(snapshot)
        with self.assertRaises(data.SnapshotError):
            data.recover(snapshot, self.recovery_path)
        self.assertEqual(list(self.recovery_path.iterdir()), [])

    def test_manifest_cannot_select_a_recovery_path(self):
        self.seed(self.config / "history.jsonl")
        snapshot = data.backup(self.config, None, self.destination)
        manifest = snapshot / data.MANIFEST_NAME
        expected = json.loads(manifest.read_text(encoding="utf-8"))
        expected["inventory"]["files"]["../outside.txt"] = {"size": 0, "sha256": "f" * 64}
        manifest.write_text(json.dumps(expected), encoding="utf-8")
        with self.assertRaises(data.SnapshotError):
            data.recover(snapshot, self.recovery_path)
        self.assertFalse((self.root / "outside.txt").exists())

    def test_errors_suppress_source_filenames(self):
        output = StringIO()
        with redirect_stderr(output):
            self.assertEqual(data.main(["verify", str(self.root / "private-name")]), 1)
        self.assertNotIn("private-name", output.getvalue())


if __name__ == "__main__":
    unittest.main()
