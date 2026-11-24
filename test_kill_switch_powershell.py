"""Parse and cross-verify PowerShell security scripts on Windows."""

import json
import os
from pathlib import Path
import subprocess
import unittest

import build_kill_switch as kill_switch
import build_lan_dns_guard as lan_dns_guard


SCRIPTS = Path(__file__).resolve().parent


@unittest.skipUnless(os.name == "nt", "Requires Windows PowerShell")
class KillSwitchPowerShellTests(unittest.TestCase):
    def setUp(self):
        system_root = Path(os.environ["SystemRoot"])
        self.powershell = system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"

    def test_windows_powershell_parses_all_bundled_scripts(self):
        command = """
$ErrorActionPreference = 'Stop'
$scripts = @(
    'Manage-WindowsKillSwitch.ps1',
    'Manage-WindowsLanDnsGuard.ps1',
    'Get-WindowsKillSwitchEvidence.ps1',
    'Test-ProxyState.ps1',
    'Inspect-WindowsProxy.ps1',
    'Inspect-WindowsFirewall.ps1',
    'Collect-WindowsEvidence.ps1'
)
foreach ($path in $scripts) {
    $parseTokens = $null
    $parseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile(
        (Join-Path (Get-Location).Path $path), [ref]$parseTokens, [ref]$parseErrors
    )
    if ($parseErrors.Count -gt 0) {
        $parseErrors | ForEach-Object { [Console]::Error.WriteLine($_.ToString()) }
        exit 1
    }
}
"""
        result = subprocess.run(
            [str(self.powershell), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
            cwd=SCRIPTS, capture_output=True, text=True, timeout=30, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_native_powershell_planner_matches_python_without_external_py_exe(self):
        # Empty PATH proves Manage-WindowsKillSwitch.ps1 no longer resolves py.exe from PATH.
        isolated_env = dict(os.environ, PATH=r"C:\nonexistent-empty-path")
        command = (
            "& .\\Manage-WindowsKillSwitch.ps1 -Action Preview "
            "-InterfaceAlias @('Wi-Fi', 'Ethernet') "
            "-UpstreamAddress '8.8.8.8' -UpstreamPort 443 -UpstreamProtocol 'TCP' "
            "-DhcpServer @('192.168.1.1', '10.1.1.2')"
        )
        result = subprocess.run(
            [str(self.powershell), "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command],
            cwd=SCRIPTS, env=isolated_env, capture_output=True, text=True, encoding="utf-8", timeout=20, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        ps_plan = json.loads(result.stdout)
        py_plan = kill_switch.build_plan(
            ["Wi-Fi", "Ethernet"], "8.8.8.8", 443, "TCP", ["192.168.1.1", "10.1.1.2"]
        )
        self.assertEqual(ps_plan, py_plan)

    def test_native_lan_dns_guard_planner_matches_python_without_external_py_exe(self):
        isolated_env = dict(os.environ, PATH=r"C:\nonexistent-empty-path")
        command = (
            "& .\\Manage-WindowsLanDnsGuard.ps1 -Action Preview "
            "-InterfaceAlias @('Wi-Fi', 'Ethernet')"
        )
        result = subprocess.run(
            [str(self.powershell), "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command],
            cwd=SCRIPTS, env=isolated_env, capture_output=True, text=True, encoding="utf-8", timeout=20, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        ps_plan = json.loads(result.stdout)
        py_plan = lan_dns_guard.build_plan(["Wi-Fi", "Ethernet"])
        self.assertEqual(ps_plan, py_plan)

    def test_evidence_collector_requires_source_port_by_default(self):
        command = (
            "& .\\Get-WindowsKillSwitchEvidence.ps1 "
            "-Since (Get-Date).AddMinutes(-5) -Until (Get-Date) "
            "-DestinationAddress '93.184.216.34' -DestinationPort 443 -ApplicationName 'curl.exe'"
        )
        result = subprocess.run(
            [str(self.powershell), "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command],
            cwd=SCRIPTS, capture_output=True, text=True, encoding="utf-8", timeout=20, check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SourcePort", result.stderr)


if __name__ == "__main__":
    unittest.main()
