#Requires -Version 5.1
<#
.SYNOPSIS
Correlates a completed, operator-controlled probe with Windows Security event 5157.
.DESCRIPTION
Reads at most MaxEvents recent WFP connection blocks and checks the rule origin,
ownership description, and interface against the currently effective toolkit rules.
Requires an explicit SourcePort by default so unrelated connections in the window
are not misattributed. Emits redacted JSON.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [datetime] $Since,
    [datetime] $Until = (Get-Date),

    [Parameter(Mandatory)]
    [string] $DestinationAddress,
    [Parameter(Mandatory)]
    [ValidateRange(1, 65535)]
    [int] $DestinationPort,
    [Parameter(Mandatory)]
    [ValidatePattern('\A[^\\/:*?"<>|\x00-\x1f]+\.exe\z')]
    [string] $ApplicationName,

    [ValidateSet('TCP', 'UDP')]
    [string] $Protocol = 'TCP',
    [ValidateRange(1, 65535)]
    [int] $SourcePort,
    [switch] $AllowAnySourcePort,
    [ValidateRange(1, 5000)]
    [int] $MaxEvents = 500
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'Run this collector on the target Windows computer.'
}

$utf8 = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = $utf8
try { [Console]::OutputEncoding = $utf8 } catch {}

$sourcePortSpecified = $PSBoundParameters.ContainsKey('SourcePort')
if (-not $sourcePortSpecified -and -not $AllowAnySourcePort) {
    throw 'Supply -SourcePort (matching curl --local-port) to prevent false attribution, or pass -AllowAnySourcePort explicitly.'
}

$sinceUtc = $Since.ToUniversalTime()
$untilUtc = $Until.ToUniversalTime()
$nowUtc = [DateTime]::UtcNow
if ($sinceUtc -ge $untilUtc -or $untilUtc -gt $nowUtc.AddSeconds(5) -or
    $sinceUtc -lt $nowUtc.AddHours(-1)) {
    throw 'Select a probe window within the past hour, with Since before Until.'
}

$targetAddress = $null
if ($DestinationAddress -notmatch '\A[0-9a-fA-F:.]+\z' -or
    -not [System.Net.IPAddress]::TryParse($DestinationAddress, [ref] $targetAddress) -or
    ($targetAddress.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork -and
        $targetAddress.ToString() -cne $DestinationAddress)) {
    throw 'Use a literal IPv4 or IPv6 destination address without brackets or a zone ID.'
}

$ruleGroup = 'CPPEK-KillSwitch-v1'
$ruleOwner = 'Cross-platform privacy environment kit: managed uplink guard v1'
$knownNames = @(
    'IPv4OtherAddresses', 'IPv6', 'UpstreamOtherTransport', 'UpstreamOtherPorts',
    'ExceptionProtoICMPv4', 'ExceptionProtoIGMP', 'ExceptionProtoIPv4Encap', 'ExceptionProtoIPv6Encap',
    'ExceptionProtoGRE', 'ExceptionProtoESP', 'ExceptionProtoAH', 'ExceptionProtoSCTP',
    'DhcpTcp', 'DhcpOtherRemotePorts', 'DhcpOtherLocalPorts'
) | ForEach-Object { "$ruleGroup-$_" }

$protocolNumber = if ($Protocol -eq 'TCP') { '6' } else { '17' }
$ipFamily = if ($targetAddress.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
    'IPv4'
} else {
    'IPv6'
}

function Read-EventFields {
    param($Event)

    $document = [System.Xml.XmlDocument]::new()
    $document.XmlResolver = $null
    $document.LoadXml($Event.ToXml())
    $fields = @{}
    foreach ($field in $document.SelectNodes("/*[local-name()='Event']/*[local-name()='EventData']/*[local-name()='Data']")) {
        $name = $field.GetAttribute('Name')
        if ($name -and -not $fields.ContainsKey($name)) { $fields.Add($name, $field.InnerText) }
    }
    return $fields
}

function Read-FilteringBlocks {
    param([datetime] $Start, [datetime] $End, [int] $Limit)

    $filter = @{
        LogName = 'Security'
        ProviderName = 'Microsoft-Windows-Security-Auditing'
        Id = 5157
        StartTime = $Start
        EndTime = $End
    }
    try {
        $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents ($Limit + 1) -ErrorAction Stop)
        return [pscustomobject] @{ Status = 'readable'; Events = $events }
    } catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
            return [pscustomobject] @{ Status = 'no-events-in-window'; Events = @() }
        }
        return [pscustomobject] @{ Status = 'unavailable'; Events = @() }
    }
}

function Read-CurrentRuleScope {
    $index = @{}
    $boot = $null
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        if ($null -ne $os.LastBootUpTime) {
            $boot = ([datetime] $os.LastBootUpTime).ToUniversalTime()
        }
        $interfaces = @(Get-NetIPInterface -AddressFamily $ipFamily -ErrorAction Stop)
        $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Group $ruleGroup -ErrorAction Stop)
        foreach ($rule in $rules) {
            if ($rule.Group -cne $ruleGroup -or
                $rule.Name -cnotin $knownNames -or
                $rule.Description -cne $ruleOwner -or
                [string] $rule.Enabled -ne 'True' -or
                [string] $rule.Direction -ne 'Outbound' -or [string] $rule.Action -ne 'Block') {
                continue
            }
            $filters = @(Get-NetFirewallInterfaceFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
            if ($filters.Count -ne 1) { continue }
            $aliases = @($filters[0].InterfaceAlias | Where-Object { $_ -and $_ -ne 'Any' })
            $indexes = @(
                $interfaces |
                    Where-Object { $_.InterfaceAlias -in $aliases } |
                    ForEach-Object { [int] $_.InterfaceIndex }
            )
            $index[$rule.Name] = $indexes
        }
        return [pscustomobject] @{ Status = 'readable'; RuleInterfaces = $index; BootTimeUtc = $boot }
    } catch {
        return [pscustomobject] @{ Status = 'unavailable'; RuleInterfaces = @{}; BootTimeUtc = $boot }
    }
}

$sample = Read-FilteringBlocks $sinceUtc $untilUtc $MaxEvents
$lookup = $null
$reviewed = @($sample.Events | Select-Object -First $MaxEvents)
$matchesFound = @(
    foreach ($event in $reviewed) {
        try {
            $fields = Read-EventFields $event
            if ($fields['Direction'] -notin @('%%14593', 'Outbound') -or
                $fields['Protocol'] -ne $protocolNumber -or
                [string]::IsNullOrWhiteSpace($fields['Application']) -or
                [IO.Path]::GetFileName($fields['Application']) -ine $ApplicationName) {
                continue
            }
            $actualPort = 0
            $actualSourcePort = 0
            $actualAddress = $null
            if (-not [int]::TryParse($fields['DestPort'], [ref] $actualPort) -or
                $actualPort -ne $DestinationPort -or
                ($sourcePortSpecified -and (-not [int]::TryParse($fields['SourcePort'], [ref] $actualSourcePort) -or
                    $actualSourcePort -ne $SourcePort)) -or
                -not [System.Net.IPAddress]::TryParse($fields['DestAddress'], [ref] $actualAddress) -or
                -not $targetAddress.Equals($actualAddress)) {
                continue
            }

            $eventUtc = $event.TimeCreated.ToUniversalTime()
            if ($eventUtc -lt $sinceUtc -or $eventUtc -gt $untilUtc) { continue }

            $origin = [string] $fields['FilterOrigin']
            $ifIndex = 0
            $hasInterface = [int]::TryParse($fields['InterfaceIndex'], [ref] $ifIndex) -and $ifIndex -gt 0
            $runtimeId = [uint64] 0
            $hasRuntimeId = [uint64]::TryParse($fields['FilterRTID'], [ref] $runtimeId) -and $runtimeId -gt 0
            $knownRule = $null
            $attribution = 'filter-origin-unavailable'

            if ($origin -cin $knownNames) {
                if ($null -eq $lookup) { $lookup = Read-CurrentRuleScope }
                if ($lookup.Status -ne 'readable') {
                    $attribution = 'active-rule-scope-unavailable'
                } elseif (-not $lookup.RuleInterfaces.ContainsKey($origin)) {
                    $attribution = 'no-current-managed-block-rule'
                } else {
                    $knownRule = $origin
                    if ($null -eq $lookup.BootTimeUtc -or $eventUtc -lt $lookup.BootTimeUtc) {
                        $attribution = 'current-boot-unconfirmed'
                    } elseif (-not $hasInterface -or $ifIndex -notin $lookup.RuleInterfaces[$origin]) {
                        $attribution = 'managed-rule-match-interface-unconfirmed'
                    } else {
                        $attribution = 'attributed-to-managed-rule'
                    }
                }
            } elseif ($origin) {
                $attribution = 'other-filter-origin'
            }

            [pscustomobject] @{
                RecordId = $event.RecordId
                ObservedAtUtc = $eventUtc.ToString('o')
                RuleName = $knownRule
                InterfaceIndex = if ($hasInterface) { $ifIndex } else { $null }
                FilterRuntimeId = if ($hasRuntimeId) { [string] $runtimeId } else { $null }
                Attribution = $attribution
            }
        } catch {
            # A malformed event is not evidence. Do not output raw event data.
            continue
        }
    }
)

$attributed = @($matchesFound | Where-Object { $_.Attribution -eq 'attributed-to-managed-rule' })
[pscustomobject] [ordered] @{
    SchemaVersion = 1
    EvidenceStatus = if ($attributed.Count -gt 0) { 'attributed-block-observed' } else { 'inconclusive' }
    SecurityLogStatus = $sample.Status
    WindowStartUtc = $sinceUtc.ToString('o')
    WindowEndUtc = $untilUtc.ToString('o')
    ReviewedEventCount = $reviewed.Count
    MatchingEventCount = $matchesFound.Count
    AttributedBlockCount = $attributed.Count
    SampleLimited = $sample.Events.Count -gt $MaxEvents
    SourcePortSpecified = $sourcePortSpecified
    Matches = $matchesFound
    Limitations = @(
        'A match applies to the sampled connection and managed rule only.'
        'Automatic attribution requires modern Filter Origin and Interface Index fields on the current boot.'
        'An unreadable log, a truncated scan, or no matching event cannot establish whether traffic was blocked.'
    )
} | ConvertTo-Json -Depth 5
