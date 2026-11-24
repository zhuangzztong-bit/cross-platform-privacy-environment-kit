#requires -Version 5.1
<#
.SYNOPSIS
Creates a read-only, redacted snapshot of proxy-related settings on Windows.

.DESCRIPTION
Uses local Windows APIs only. Does not inspect process arguments or subscription
files, and does not query an external service. Custom directory segments under
UserProfile, custom network interface aliases, and custom startup entry names are
masked to prevent leaking personal or corporate identifiers.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    throw 'Run this inventory in Windows PowerShell on the target Windows computer.'
}

$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = $utf8NoBom
try {
    [Console]::OutputEncoding = $utf8NoBom
} catch {
    # Ignore if stdout is not attached to a console handle.
}

$warnings = New-Object 'System.Collections.Generic.List[string]'
$clientNames = New-Object 'System.Collections.Hashtable' ([System.StringComparer]::OrdinalIgnoreCase)
foreach ($entry in @{
    'v2rayn'            = 'v2rayN'
    'clash-verge'       = 'Clash Verge'
    'clash-verge-rev'   = 'Clash Verge Rev'
    'clash for windows' = 'Clash for Windows'
    'mihomo-party'      = 'Mihomo Party'
    'clash-party'       = 'Clash Party'
    'flclash'           = 'FlClash'
    'nekoray'           = 'NekoRay'
    'surge'             = 'Surge'
    'hiddify'           = 'Hiddify'
    'xray'              = 'Xray core'
    'v2ray'             = 'V2Ray core'
    'sing-box'          = 'sing-box core'
    'mihomo'            = 'Mihomo core'
    'verge-mihomo'      = 'Mihomo core'
    'clash'             = 'Clash core'
    'hysteria'          = 'Hysteria core'
    'hysteria2'         = 'Hysteria core'
    'tuic-client'       = 'TUIC core'
    'naive'             = 'NaiveProxy core'
    'naiveproxy'        = 'NaiveProxy core'
    'juicity'           = 'Juicity core'
    'tailscale'         = 'Tailscale'
    'tailscale-ipn'     = 'Tailscale'
    'tailscaled'        = 'Tailscale'
}.GetEnumerator()) {
    $clientNames[$entry.Key] = $entry.Value
}
$startupNamePattern = '(?i)v2rayn|clash.verge|mihomo.party|clash.party|sing.box|flclash|nekoray|hiddify|surge|tailscale'
$installedNamePattern = '^(?i:v2rayN|Clash Verge(?: Rev)?|Clash for Windows|Mihomo Party|Clash Party|FlClash|NekoRay|Surge|Hiddify|Tailscale)(?:\s|$)'
$tunnelPattern = '(?i)(?:^|[\s_.-])(?:u?tun\d*|wintun\d*|wireguard|tailscale|sing[-_]?box|mihomo|clash)(?:$|[\s_.-])'
$genericInterfacePattern = '^(?i:Ethernet(?:\s+\d+)?|Wi-Fi(?:\s+\d+)?|WLAN(?:\s+\d+)?|Local Area Connection(?:\s*\*?\s*\d+)?|Loopback Pseudo-Interface\s+\d+|vEthernet\s*\(Default Switch\)|以太网(?:\s+\d+)?|无线网络连接(?:\s+\d+)?|本地连接(?:\s*\*?\s*\d+)?)$'

function Add-WarningOnce {
    param([string]$Message)
    if (-not $warnings.Contains($Message)) { $warnings.Add($Message) }
}

function Invoke-LocalProbe {
    param([string]$Label, [scriptblock]$Body)
    try {
        & $Body
    } catch {
        Add-WarningOnce "$Label unavailable"
    }
}

$windows = Invoke-LocalProbe 'Windows version' {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    [pscustomobject]@{
        Caption      = $os.Caption
        Version      = $os.Version
        Architecture = $os.OSArchitecture
        Build        = $os.BuildNumber
    }
}

# Order more-specific AppData folders ahead of UserProfile.
$pathsToMask = [ordered]@{}
foreach ($folder in @('LocalApplicationData', 'ApplicationData', 'ProgramFiles', 'ProgramFilesX86', 'UserProfile')) {
    $folderPath = [System.Environment]::GetFolderPath($folder)
    if ($folderPath -and -not $pathsToMask.Contains($folderPath)) {
        $pathsToMask[$folderPath] = "<$folder>"
    }
}

function Protect-LocalPath {
    param([string]$Path)
    foreach ($prefix in $pathsToMask.Keys) {
        $label = $pathsToMask[$prefix]
        if ($Path.Equals($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $label
        }
        if ($Path.StartsWith($prefix + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
            $rel = $Path.Substring($prefix.Length + 1)
            $parts = @($rel -split '\\' | Where-Object { $_ })
            if ($label -eq '<UserProfile>' -and $parts.Count -gt 2) {
                # Redact intermediate personal/project directories under UserProfile.
                return "$label\...\$($parts[-2])\$($parts[-1])"
            }
            if ($parts.Count -gt 3) {
                return "$label\$($parts[0])\...\$($parts[-1])"
            }
            return "$label\$rel"
        }
    }
    return "<OtherLocalPath>\$([System.IO.Path]::GetFileName($Path))"
}

function Protect-InterfaceAlias {
    param([string]$Alias, [int]$Index)
    if ([string]::IsNullOrWhiteSpace($Alias)) { return "<Interface#$Index>" }
    if ($Alias -match $genericInterfacePattern) { return $Alias }
    if ($Alias -match $tunnelPattern) { return "<TunnelInterface#$Index>" }
    return "<CustomInterface#$Index>"
}

function Match-StartupClientLabel {
    param([string]$RawName)
    foreach ($token in @('v2rayN', 'Clash Verge', 'Mihomo Party', 'Clash Party', 'sing-box', 'FlClash', 'NekoRay', 'Hiddify', 'Surge', 'Tailscale')) {
        $escaped = ($token -replace '[- ]', '.?')
        if ($RawName -match "(?i)$escaped") {
            return "$token-related"
        }
    }
    return 'Proxy-related'
}

function Test-LocalDrivePath {
    param([string]$Path)
    if (-not $Path -or $Path -notmatch '^[A-Za-z]:\\') { return $false }
    try {
        $drive = New-Object -TypeName System.IO.DriveInfo -ArgumentList ($Path.Substring(0, 3))
        return [string]$drive.DriveType -in @('Fixed', 'Removable', 'Ram')
    } catch {
        return $false
    }
}

function Test-LocalUnlinkedPath {
    param([string]$Path, [switch]$File)
    if (-not (Test-LocalDrivePath $Path)) { return $false }
    try {
        $fullPath = [System.IO.Path]::GetFullPath($Path)
        $directory = [System.IO.DirectoryInfo]::new($fullPath)
        if ($File) { $directory = $directory.Parent }
        $ancestors = @()
        for ($item = $directory; $null -ne $item; $item = $item.Parent) {
            $ancestors = @($item) + $ancestors
        }
        foreach ($ancestor in $ancestors) {
            $attributes = [System.IO.File]::GetAttributes($ancestor.FullName)
            if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
                ($attributes -band [System.IO.FileAttributes]::Directory) -eq 0) {
                return $false
            }
        }
        if ($File) {
            $attributes = [System.IO.File]::GetAttributes($fullPath)
            $excluded = [System.IO.FileAttributes]::ReparsePoint -bor [System.IO.FileAttributes]::Directory
            return ($attributes -band $excluded) -eq 0
        }
        return $true
    } catch {
        return $false
    }
}

$processes = @(Invoke-LocalProbe 'Proxy processes' {
    Get-Process -ErrorAction Stop | Where-Object { $clientNames.ContainsKey($_.ProcessName) }
})

$processRows = @(
    foreach ($process in $processes) {
        $path = Invoke-LocalProbe 'Executable path' { $process.Path }
        $protectedPath = $null
        if ($path -and (Test-LocalDrivePath $path)) {
            $protectedPath = Protect-LocalPath $path
        }
        [pscustomobject]@{
            Client    = $clientNames[$process.ProcessName]
            Process   = $process.ProcessName
            ProcessId = $process.Id
            Location  = $protectedPath
        }
    }
)
$processNameById = @{}
foreach ($process in $processes) {
    $processNameById[[int]$process.Id] = $process.ProcessName
}

$dataDirectories = @(Invoke-LocalProbe 'v2rayN directory candidates' {
    $installedRoots = @(
        foreach ($folder in @('LocalApplicationData', 'ApplicationData', 'ProgramFiles')) {
            $basePath = [System.Environment]::GetFolderPath($folder)
            if ($basePath) { [System.IO.Path]::Combine($basePath, 'v2rayN') }
        }
        foreach ($process in $processes) {
            if ($clientNames[$process.ProcessName] -eq 'v2rayN') {
                $path = try { $process.Path } catch { $null }
                if ($path -and (Test-LocalDrivePath $path)) { [System.IO.Path]::GetDirectoryName($path) }
            }
        }
    )
    foreach ($root in ($installedRoots | Sort-Object -Unique)) {
        $directory = [System.IO.Path]::Combine($root, 'guiConfigs')
        if (Test-LocalUnlinkedPath $directory) {
            $configFile = [System.IO.Path]::Combine($directory, 'guiNConfig.json')
            [pscustomobject]@{
                Directory          = Protect-LocalPath $directory
                GuiSettingsPresent = Test-LocalUnlinkedPath $configFile -File
            }
        }
    }
})

$installedClients = @(Invoke-LocalProbe 'Installed proxy clients' {
    $uninstallRoots = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    foreach ($keyPath in $uninstallRoots) {
        if (-not (Test-Path -LiteralPath $keyPath)) { continue }
        foreach ($key in (Get-ChildItem -LiteralPath $keyPath -ErrorAction SilentlyContinue)) {
            try {
                $name = [string]$key.GetValue('DisplayName')
                if ($name -match $installedNamePattern) {
                    $displayName = $matches[0].Trim()
                    $version = [string]$key.GetValue('DisplayVersion')
                    if ($version -notmatch '^[A-Za-z0-9_.+\-]{1,40}$') { $version = $null }
                    [pscustomobject]@{ Name = $displayName; Version = $version }
                }
            } catch {
                continue
            } finally {
                $key.Close()
            }
        }
    }
} | Sort-Object -Property Name, Version -Unique)

$services = @(Invoke-LocalProbe 'Relevant services' {
    Get-Service -ErrorAction Stop |
        Where-Object { $_.Name -match $startupNamePattern } |
        ForEach-Object {
            [pscustomobject]@{
                ClientHint = Match-StartupClientLabel $_.Name
                Status     = [string]$_.Status
            }
        }
})

$startup = @(Invoke-LocalProbe 'Startup registry entries' {
    $locations = @{
        CurrentUser = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
        AllUsers    = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
    }
    foreach ($scope in ($locations.Keys | Sort-Object)) {
        if (-not (Test-Path -LiteralPath $locations[$scope])) { continue }
        $key = Get-Item -LiteralPath $locations[$scope] -ErrorAction Stop
        try {
            foreach ($name in $key.GetValueNames()) {
                if ($name -match $startupNamePattern) {
                    [pscustomobject]@{
                        Scope      = $scope
                        ClientHint = Match-StartupClientLabel $name
                        Kind       = 'RegistryRun'
                    }
                }
            }
        } finally {
            $key.Close()
        }
    }
})

foreach ($scope in @('Startup', 'CommonStartup')) {
    $startup += @(Invoke-LocalProbe "Startup folder entries ($scope)" {
        $folder = [System.Environment]::GetFolderPath($scope)
        if (-not (Test-LocalUnlinkedPath $folder)) { return }
        Get-ChildItem -LiteralPath $folder -File -ErrorAction Stop |
            Where-Object { $_.BaseName -match $startupNamePattern } |
            ForEach-Object {
                [pscustomobject]@{
                    Scope      = $scope
                    ClientHint = Match-StartupClientLabel $_.BaseName
                    Kind       = 'StartupFolder'
                }
            }
    })
}

$startup += @(Invoke-LocalProbe 'Scheduled task startup candidates' {
    $query = Get-Command -Name Get-ScheduledTask -ErrorAction Stop
    & $query -ErrorAction Stop |
        Where-Object { $_.TaskName -match $startupNamePattern } |
        ForEach-Object {
            [pscustomobject]@{
                Scope      = 'TaskScheduler'
                ClientHint = Match-StartupClientLabel $_.TaskName
                Kind       = 'ScheduledTask'
                State      = [string]$_.State
            }
        }
})

$systemProxy = Invoke-LocalProbe 'Current user system proxy' {
    $proxySettings = Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop
    $proxyEnableProp = $proxySettings.PSObject.Properties['ProxyEnable']
    $proxyServerProp = $proxySettings.PSObject.Properties['ProxyServer']
    $autoConfigProp  = $proxySettings.PSObject.Properties['AutoConfigURL']
    $parsedEnable = 0
    $manualEnabled = (
        $null -ne $proxyEnableProp -and
        [int]::TryParse([string]$proxyEnableProp.Value, [ref]$parsedEnable) -and $parsedEnable -ne 0
    )
    [pscustomobject]@{
        WinInetManualProxyEnabled = $manualEnabled
        ProxyServerValuePresent   = ($null -ne $proxyServerProp) -and (-not [string]::IsNullOrWhiteSpace([string]$proxyServerProp.Value))
        AutoConfigUrlPresent      = ($null -ne $autoConfigProp) -and (-not [string]::IsNullOrWhiteSpace([string]$autoConfigProp.Value))
    }
}

$tunnelCandidates = @(Invoke-LocalProbe 'Tunnel adapter candidates' {
    Get-NetAdapter -IncludeHidden -ErrorAction Stop |
        Where-Object { "$($_.Name) $($_.InterfaceDescription)" -match $tunnelPattern } |
        ForEach-Object {
            [pscustomobject]@{
                InterfaceLabel = Protect-InterfaceAlias ([string]$_.Name) ([int]$_.ifIndex)
                ifIndex        = $_.ifIndex
                Status         = [string]$_.Status
            }
        }
})

$dns = @(Invoke-LocalProbe 'Interface DNS configuration' {
    Get-DnsClientServerAddress -ErrorAction Stop |
        ForEach-Object {
            $addresses = @($_.ServerAddresses | Where-Object { $_ })
            if ($addresses.Count -eq 0) { return }
            $family = [string]$_.AddressFamily
            if ($family -eq '2') { $family = 'IPv4' }
            if ($family -eq '23') { $family = 'IPv6' }
            [pscustomobject]@{
                InterfaceLabel        = Protect-InterfaceAlias ([string]$_.InterfaceAlias) ([int]$_.InterfaceIndex)
                InterfaceIndex        = $_.InterfaceIndex
                Family                = $family
                ServerCount           = $addresses.Count
                TailscaleQuad100      = $addresses -contains '100.100.100.100'
                TailscaleQuad100First = $addresses[0] -eq '100.100.100.100'
            }
        }
})

$tcpListeners = @()
$udpEndpoints = @()
if ($processes.Count -gt 0) {
    $tcpListeners = @(Invoke-LocalProbe 'Proxy TCP listeners' {
        try {
            Get-NetTCPConnection -State Listen -ErrorAction Stop |
                Where-Object { $processNameById.ContainsKey([int]$_.OwningProcess) } |
                ForEach-Object {
                    $parsedIp = $null
                    $isLoopback = if ([System.Net.IPAddress]::TryParse([string]$_.LocalAddress, [ref]$parsedIp)) {
                        [System.Net.IPAddress]::IsLoopback($parsedIp)
                    } else {
                        $false
                    }
                    [pscustomobject]@{
                        Process   = $processNameById[[int]$_.OwningProcess]
                        LocalPort = $_.LocalPort
                        Loopback  = $isLoopback
                    }
                } | Sort-Object -Property Process, LocalPort, Loopback -Unique
        } catch {
            if ($_.CategoryInfo.Category -ne [System.Management.Automation.ErrorCategory]::ObjectNotFound -or
                $_.FullyQualifiedErrorId -notin @('CmdletizationQuery_NotFound_State,Get-NetTCPConnection', 'CmdletizationQuery_NotFound,Get-NetTCPConnection')) {
                throw
            }
        }
    })
    $udpEndpoints = @(Invoke-LocalProbe 'Proxy UDP endpoints' {
        try {
            Get-NetUDPEndpoint -ErrorAction Stop |
                Where-Object { $processNameById.ContainsKey([int]$_.OwningProcess) } |
                ForEach-Object {
                    $parsedIp = $null
                    $isLoopback = if ([System.Net.IPAddress]::TryParse([string]$_.LocalAddress, [ref]$parsedIp)) {
                        [System.Net.IPAddress]::IsLoopback($parsedIp)
                    } else {
                        $false
                    }
                    [pscustomobject]@{
                        Process   = $processNameById[[int]$_.OwningProcess]
                        LocalPort = $_.LocalPort
                        Loopback  = $isLoopback
                    }
                } | Sort-Object -Property Process, LocalPort, Loopback -Unique
        } catch {
            if ($_.CategoryInfo.Category -ne [System.Management.Automation.ErrorCategory]::ObjectNotFound -or
                $_.FullyQualifiedErrorId -notin @('CmdletizationQuery_NotFound,Get-NetUDPEndpoint')) {
                throw
            }
        }
    })
}

[pscustomobject][ordered]@{
    SchemaVersion             = 2
    CollectedAtUtc            = [System.DateTime]::UtcNow.ToString('o')
    Windows                   = $windows
    PowerShellVersion         = $PSVersionTable.PSVersion.ToString()
    ProxyProcessCandidates    = $processRows
    InstalledClientCandidates = $installedClients
    V2RayNDirectoryCandidates = $dataDirectories
    ServiceCandidates         = $services
    StartupCandidates         = $startup
    CurrentUserSystemProxy    = $systemProxy
    TunnelAdapterCandidates   = $tunnelCandidates
    DnsByInterface            = $dns
    TailscaleDnsConfigured    = @($dns | Where-Object { $_.TailscaleQuad100 }).Count -gt 0
    ProxyTcpListeners         = $tcpListeners
    ProxyUdpEndpoints         = $udpEndpoints
    Warnings                  = @($warnings.ToArray())
    EvidenceLimits            = @(
        'DNS values describe interface configuration. Active resolver traffic and interface use are not observed.'
        'Tunnel adapter labels and listening ports identify redacted candidates; they do not establish effective routing.'
    )
} | ConvertTo-Json -Depth 6
