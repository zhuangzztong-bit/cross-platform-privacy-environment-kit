#Requires -Version 5.1
<#
.SYNOPSIS
Summarizes local Windows routing, DNS, and existing firewall evidence.

.DESCRIPTION
Emits redacted JSON. Reads the active configuration, existing Windows Security
events, and optional saved Test-ProxyState JSON. No probes are sent and no
settings or logs are changed. An ordinary terminal is sufficient; Windows may
deny access to the Security log, which is reported as unavailable.

.EXAMPLE
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Collect-WindowsEvidence.ps1 -EvidenceDirectory .\evidence
#>

[CmdletBinding()]
param(
    [string]$EvidenceDirectory,

    [ValidateRange(1, 1440)]
    [int]$FirewallLookbackMinutes = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'Run this collector on the target Windows computer.'
}

$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = $utf8NoBom
try {
    [Console]::OutputEncoding = $utf8NoBom
} catch {
    # Ignore if stdout is not attached to a console handle.
}

function Read-LocalObservation {
    param([scriptblock]$Command)
    try {
        [pscustomobject]@{ Status = 'observed'; Data = @(& $Command) }
    } catch {
        [pscustomobject]@{ Status = 'unavailable'; Data = @() }
    }
}

function Get-OptionalField {
    param([object]$Object, [string]$Name)
    if ($null -ne $Object) {
        $property = $Object.PSObject.Properties[$Name]
        if ($null -ne $property) { $property.Value }
    }
}

function Read-JsonTextAutoEncoding {
    param([string]$LiteralPath)

    # Accept BOMs from Windows PowerShell 5.1 redirection and UTF-8 editors.
    $strictUtf8 = [System.Text.UTF8Encoding]::new($false, $true)
    $reader = [System.IO.StreamReader]::new($LiteralPath, $strictUtf8, $true)
    try {
        return $reader.ReadToEnd()
    } finally {
        $reader.Dispose()
    }
}

function Get-RouteSummary {
    param($RouteObservation, $InterfaceObservation)

    $prefixes = @('0.0.0.0/0', '0.0.0.0/1', '128.0.0.0/1', '::/0', '::/1', '8000::/1')
    $routes = @(
        foreach ($route in $RouteObservation.Data) {
            if ($route.DestinationPrefix -notin $prefixes) { continue }
            $interface = $InterfaceObservation.Data | Where-Object {
                $_.InterfaceIndex -eq $route.InterfaceIndex -and [string]$_.AddressFamily -eq [string]$route.AddressFamily
            } | Select-Object -First 1
            $routeMetric = Get-OptionalField $route 'RouteMetric'
            $interfaceMetric = Get-OptionalField $interface 'InterfaceMetric'
            $connectionState = Get-OptionalField $interface 'ConnectionState'
            if ([string]$connectionState -notin @('Connected', 'Disconnected')) { $connectionState = $null }
            [pscustomobject]@{
                DestinationPrefix = [string]$route.DestinationPrefix
                AddressFamily     = [string]$route.AddressFamily
                InterfaceIndex    = [int]$route.InterfaceIndex
                InterfaceState    = $connectionState
                RouteMetric       = if ($null -ne $routeMetric) { [int]$routeMetric } else { $null }
                InterfaceMetric   = if ($null -ne $interfaceMetric) { [int]$interfaceMetric } else { $null }
                CombinedMetric    = if ($null -ne $routeMetric -and $null -ne $interfaceMetric) {
                    [int]$routeMetric + [int]$interfaceMetric
                } else { $null }
            }
        }
    )
    [pscustomobject]@{
        ActiveStore = $RouteObservation.Status
        Interfaces  = $InterfaceObservation.Status
        Candidates  = @($routes | Sort-Object DestinationPrefix, CombinedMetric, InterfaceIndex)
    }
}

function Get-DnsSummary {
    param($ResolverObservation, $DohObservation)

    $dohByAddress = @{}
    foreach ($resolver in $DohObservation.Data) {
        if ($resolver.ServerAddress) {
            $dohByAddress[[string]$resolver.ServerAddress] = $resolver
        }
    }
    $interfaces = @(
        foreach ($row in $ResolverObservation.Data) {
            $family = [string]$row.AddressFamily
            if ($family -eq '2') { $family = 'IPv4' }
            elseif ($family -eq '23') { $family = 'IPv6' }
            $addresses = @($row.ServerAddresses | Where-Object { $_ })
            $registered = @($addresses | ForEach-Object { $dohByAddress[[string]$_] } | Where-Object { $_ })
            $autoUpgrade = @($registered | Where-Object { [string]$_.AutoUpgrade -eq 'True' })
            $fallback = @($autoUpgrade | Where-Object { [string]$_.AllowFallbackToUdp -eq 'True' })
            [pscustomobject]@{
                InterfaceIndex          = [int]$row.InterfaceIndex
                AddressFamily           = $family
                ResolverCount           = $addresses.Count
                TailscaleQuad100First   = $addresses.Count -gt 0 -and $addresses[0] -eq '100.100.100.100'
                RegisteredDohCount      = if ($DohObservation.Status -eq 'observed') { $registered.Count } else { $null }
                AutoUpgradeCount        = if ($DohObservation.Status -eq 'observed') { $autoUpgrade.Count } else { $null }
                AutoUpgradeWithFallback = if ($DohObservation.Status -eq 'observed') { $fallback.Count } else { $null }
            }
        }
    )
    [pscustomobject]@{
        AdapterResolvers    = $ResolverObservation.Status
        SystemRegistrations = $DohObservation.Status
        Interfaces          = @($interfaces | Sort-Object InterfaceIndex, AddressFamily)
        BrowserAndAppDoh    = 'not-observed'
        ResolverTraffic     = 'not-observed'
    }
}

function Read-FilteringEvents {
    param([datetime]$Since)

    $filter = @{ LogName = 'Security'; Id = @(5152, 5157); StartTime = $Since }
    try {
        $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents 201 -ErrorAction Stop)
    } catch {
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {
            return [pscustomobject]@{
                Status = 'unavailable'; PacketBlocks = $null; ConnectionBlocks = $null; Truncated = $null
            }
        }
        $events = @()
    }
    $sample = @($events | Select-Object -First 200)
    [pscustomobject]@{
        Status           = 'observed'
        PacketBlocks     = @($sample | Where-Object { $_.Id -eq 5152 }).Count
        ConnectionBlocks = @($sample | Where-Object { $_.Id -eq 5157 }).Count
        Truncated        = $events.Count -gt 200
    }
}

function Read-SavedProbes {
    param([string]$Directory)

    if (-not $Directory) {
        return [pscustomobject]@{ Status = 'not-requested'; FilesRead = 0; FilesIgnored = 0; Truncated = $false; Groups = @() }
    }

    $stages = @('normal', 'upstream-unreachable', 'tun-down', 'client-down')
    $families = @('auto', 'ipv4', 'ipv6')
    $roles = @('primary', 'operator-designated-direct')
    $outcomes = @('https-response', 'tcp-connected-no-https-response', 'name-resolution-failed',
                  'no-connection-observed', 'other-curl-error', 'probe-process-error',
                  'supervisor-timeout', 'output-timeout', 'unparsed-curl-output')
    try {
        $path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Directory)
        if ($path -notmatch '^[a-zA-Z]:\\') { throw 'Expected a local Windows path.' }
        $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($path))
        if ([string]$drive.DriveType -notin @('Fixed', 'Removable', 'Ram')) { throw 'Expected a local drive.' }
        $ancestors = @()
        for ($item = [IO.DirectoryInfo]::new($path); $null -ne $item; $item = $item.Parent) {
            $ancestors = @($item) + $ancestors
        }
        foreach ($ancestor in $ancestors) {
            $attributes = [IO.File]::GetAttributes($ancestor.FullName)
            if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                ($attributes -band [IO.FileAttributes]::Directory) -eq 0) {
                throw 'Expected an existing directory with no reparse points.'
            }
        }
        $files = @(Get-ChildItem -LiteralPath $path -Filter '*.json' -File -ErrorAction Stop |
            Select-Object -First 101)
    } catch {
        return [pscustomobject]@{ Status = 'unavailable'; FilesRead = 0; FilesIgnored = 0; Truncated = $null; Groups = @() }
    }

    $groups = @{}
    $readCount = 0
    $ignoredCount = 0
    foreach ($file in ($files | Select-Object -First 100)) {
        try {
            if ($file.Length -gt 262144 -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'Unsupported evidence file.'
            }
            $rawJson = Read-JsonTextAutoEncoding -LiteralPath $file.FullName
            $report = $rawJson | ConvertFrom-Json -ErrorAction Stop
            if ($null -eq $report) { throw 'Unsupported probe report.' }
            $stage = Get-OptionalField $report 'Stage'
            $probesProperty = $report.PSObject.Properties['Probes']
            if ($null -eq $probesProperty -or $probesProperty.Value -isnot [array]) {
                throw 'Unsupported probe report.'
            }
            $probes = @($probesProperty.Value)
            if ($stage -isnot [string] -or $stage -cnotin $stages -or $probes.Count -notin @(1, 2)) {
                throw 'Unsupported probe report.'
            }
            $validated = @(
                foreach ($probe in $probes) {
                    $family = Get-OptionalField $probe 'AddressFamily'
                    $role = Get-OptionalField $probe 'Role'
                    $outcome = Get-OptionalField $probe 'Observation'
                    if (($family -isnot [string] -or $family -cnotin $families) -or
                        ($role -isnot [string] -or $role -cnotin $roles) -or
                        ($outcome -isnot [string] -or $outcome -cnotin $outcomes)) {
                        throw 'Unsupported probe observation.'
                    }
                    [pscustomobject]@{ Family = $family; Role = $role; Outcome = $outcome }
                }
            )
        } catch {
            $ignoredCount += 1
            continue
        }
        $readCount += 1
        foreach ($entry in $validated) {
            $key = "$stage/$($entry.Family)/$($entry.Role)/$($entry.Outcome)"
            if (-not $groups.ContainsKey($key)) {
                $groups[$key] = [pscustomobject]@{
                    Stage = $stage; AddressFamily = $entry.Family; Role = $entry.Role
                    Observation = $entry.Outcome; Count = 0
                }
            }
            $groups[$key].Count += 1
        }
    }
    [pscustomobject]@{
        Status       = 'observed'
        FilesRead    = $readCount
        FilesIgnored = $ignoredCount
        Truncated    = $files.Count -gt 100
        Groups       = @($groups.Values | Sort-Object Stage, AddressFamily, Role, Observation)
    }
}

$now = [datetime]::UtcNow
$interfaces = Read-LocalObservation { Get-NetIPInterface -ErrorAction Stop }
$routes = Read-LocalObservation { Get-NetRoute -PolicyStore ActiveStore -ErrorAction Stop }
$resolvers = Read-LocalObservation { Get-DnsClientServerAddress -ErrorAction Stop }
$doh = Read-LocalObservation { Get-DnsClientDohServerAddress -ErrorAction Stop }
$profiles = Read-LocalObservation {
    Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{
            Profile = [string]$_.Name; Enabled = [string]$_.Enabled
            DefaultOutboundAction = [string]$_.DefaultOutboundAction; LogBlocked = [string]$_.LogBlocked
        }
    }
}

[pscustomobject]@{
    ObservedAtUtc      = $now.ToString('o')
    Routing            = Get-RouteSummary $routes $interfaces
    Dns                = Get-DnsSummary $resolvers $doh
    Firewall           = [pscustomobject]@{
        ActiveStore        = $profiles.Status
        Profiles           = $profiles.Data
        LookbackMinutes    = $FirewallLookbackMinutes
        SecurityDropEvents = Read-FilteringEvents $now.AddMinutes(-$FirewallLookbackMinutes)
    }
    SavedProbes        = Read-SavedProbes $EvidenceDirectory
    FailClosedVerified = $false
    EvidenceLimits     = @(
        'Routing lists default and split-default prefixes only. More-specific routes or app behavior can change the actual exit.'
        'System DNS registrations do not establish which resolver received traffic; private app/browser DNS is not checked.'
        'Security event counts are system-wide and are not linked to saved probes. Zero or inaccessible events cannot prove an allow or a block.'
        'Saved stages are operator labels. The aggregated HTTPS observations do not verify adapter, public IP, or system-wide fail-closed behavior.'
    )
} | ConvertTo-Json -Depth 7
