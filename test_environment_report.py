import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from environment_report import build_report, capture_json


class ReportTests(unittest.TestCase):
    def test_unknown_platform_does_not_launch_anything(self):
        with patch("environment_report.capture_json") as run:
            self.assertEqual(build_report("Android")["status"], "unsupported-platform")
        run.assert_not_called()

    def test_unix_passes_paths_as_arguments(self):
        folder = Path("path with spaces")
        with patch("environment_report.capture_json", return_value={"status": "collected"}) as run:
            report = build_report("Darwin", config_dir=folder)
        self.assertEqual(report["network"]["status"], "collected")
        self.assertEqual(run.call_args_list[1].args[0][-2:], ["--config-dir", str(folder)])

    def test_windows_uses_system_powershell_and_explicit_evidence_path(self):
        with patch.dict(os.environ, {"SystemRoot": "C:/Windows"}):
            with patch("environment_report.capture_json", return_value={"status": "collected"}) as run:
                build_report("Windows", evidence_directory=Path("evidence"))
        first_call = run.call_args_list[0].args[0]
        self.assertTrue(first_call[0].lower().endswith("powershell.exe"))
        self.assertIn("Bypass", first_call)
        self.assertEqual(first_call[-2:], ["-EvidenceDirectory", os.path.abspath(Path("evidence"))])

    def test_windows_whitespace_system_root_is_unavailable(self):
        with patch.dict(os.environ, {"SystemRoot": "   "}):
            with patch("environment_report.capture_json", return_value={"status": "collected"}) as run:
                report = build_report("Windows")
        self.assertEqual(report["network"]["reason"], "windows-system-root-unset")
        self.assertEqual(run.call_count, 1)

    def test_windows_uses_sysnative_when_available_under_wow64(self):
        settings = {"SystemRoot": "C:/Windows", "PROCESSOR_ARCHITEW6432": "AMD64"}
        for available, expected_dir in ((True, "Sysnative"), (False, "System32")):
            with self.subTest(available=available), patch.dict(os.environ, settings), patch.object(
                Path, "is_file", return_value=available,
            ), patch("environment_report.capture_json", return_value={"status": "collected"}) as run:
                build_report("Windows")
                command = run.call_args_list[0].args[0]
                expected = Path("C:/Windows") / expected_dir / "WindowsPowerShell" / "v1.0" / "powershell.exe"
                self.assertEqual(command[0], str(expected))

    def test_utf8_bom_output_is_parsed(self):
        child = SimpleNamespace(returncode=0, stdout=b'\xef\xbb\xbf{"observed": true}')
        with patch("environment_report.subprocess.run", return_value=child):
            result = capture_json(["collector"])
        self.assertEqual(result, {"status": "collected", "data": {"observed": True}})

    def test_invalid_or_failed_output_is_not_copied(self):
        for exit_code, output in ((0, b"bad raw output"), (5, b'{"secret":"raw output"}')):
            child = SimpleNamespace(returncode=exit_code, stdout=output)
            with patch("environment_report.subprocess.run", return_value=child):
                result = capture_json(["collector"])
            self.assertEqual(result["status"], "unavailable")
            self.assertNotIn("raw output", json.dumps(result))

    def test_timed_out_collector_cannot_hang_report(self):
        with patch("environment_report.subprocess.run", side_effect=subprocess.TimeoutExpired("collector", 70)):
            self.assertEqual(capture_json(["collector"])["reason"], "collector-start-or-timeout")


if __name__ == "__main__":
    unittest.main()
