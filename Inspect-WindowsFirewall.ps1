#requires -Version 5.1
<#
.SYNOPSIS
Summarizes effective Windows Firewall policy without changing it.

.DESCRIPTION
Returns JSON. Uses local queries only and omits network names, addresses,
rule names, application paths, and logs. Observed settings and rule counts
alone cannot prove that traffic is blocked when a tunnel goes down.

.EXAMPLE
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Inspect-WindowsFirewall.ps1
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    throw 'Run this inventory on the target Windows computer.'
}

$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = $utf8NoBom
try {
    [Console]::OutputEncoding = $utf8NoBom
} catch {
    # Ignore if stdout is not attached to a console handle.
}

$warnings = New-Object 'System.Collections.Generic.List[string]'

function Invoke-LocalFirewallProbe {
    param([string]$Label, [scriptblock]$Body)

    try {
        & $Body
    } catch {
        $message = "$Label unavailable"
        if (-not $warnings.Contains($message)) {
            $warnings.Add($message)
        }
    }
}

$profiles = @(Invoke-LocalFirewallProbe 'ActiveStore firewall profiles' {
    Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop |
        Sort-Object -Property Name |
        ForEach-Object {
            [pscustomobject]@{
                Profile               = [string]$_.Name
                Enabled               = [string]$_.Enabled
                DefaultInboundAction  = [string]$_.DefaultInboundAction
                DefaultOutboundAction = [string]$_.DefaultOutboundAction
                AllowLocalRules       = [string]$_.AllowLocalFirewallRules
                LogBlocked            = [string]$_.LogBlocked
            }
        }
})

$services = @(
    foreach ($serviceName in @('BFE', 'MpsSvc')) {
        $service = Invoke-LocalFirewallProbe "Service $serviceName" {
            Get-Service -Name $serviceName -ErrorAction Stop
        }
        [pscustomobject]@{
            Service = $serviceName
            Status  = if ($null -eq $service) { 'Unavailable' } else { [string]$service.Status }
        }
    }
)

$networkCategories = @(Invoke-LocalFirewallProbe 'Network connection categories' {
    try {
        Get-NetConnectionProfile -ErrorAction Stop |
            Group-Object -Property NetworkCategory -NoElement |
            Sort-Object -Property Name |
            ForEach-Object {
                [pscustomobject]@{ Category = $_.Name; Connections = $_.Count }
            }
    } catch {
        if ($_.CategoryInfo.Category -ne [System.Management.Automation.ErrorCategory]::ObjectNotFound -or
            $_.FullyQualifiedErrorId -notin @('CmdletizationQuery_NotFound,Get-NetConnectionProfile')) {
            throw
        }
    }
})

$outboundRules = Invoke-LocalFirewallProbe 'ActiveStore outbound rules' {
    $counts = [ordered]@{ Allow = 0; Block = 0; Other = 0 }
    $allowBreakdown = [ordered]@{ BuiltInOrMicrosoft = 0; OtherThirdPartyOrCustom = 0 }
    $port53BlockCount = 0
    try {
        Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop |
            Where-Object { [string]$_.Direction -eq 'Outbound' -and [string]$_.Enabled -eq 'True' } |
            ForEach-Object {
                $rule = $_
                switch ([string]$rule.Action) {
                    'Allow' {
                        $counts.Allow += 1
                        $nameText = "$($rule.Name) $($rule.DisplayName) $($rule.Group)"
                        if ($nameText -match '(?i)(?:Microsoft\.|Windows|@\{Microsoft\.|@FirewallAPI\.dll|Core Networking|mDNS|Cortana|Edge|Office|OneDrive|Defender)') {
                            $allowBreakdown.BuiltInOrMicrosoft += 1
                        } else {
                            $allowBreakdown.OtherThirdPartyOrCustom += 1
                        }
                    }
                    'Block' {
                        $counts.Block += 1
                        try {
                            $portFilter = $rule | Get-NetFirewallPortFilter -ErrorAction Stop
                            if (@($portFilter.RemotePort) -contains '53') {
                                $port53BlockCount += 1
                            }
                        } catch {
                            # Ignore port filter lookup failures on individual rules.
                        }
                    }
                    default { $counts.Other += 1 }
                }
            }
    } catch {
        if ($_.CategoryInfo.Category -ne [System.Management.Automation.ErrorCategory]::ObjectNotFound -or
            $_.FullyQualifiedErrorId -notin @('CmdletizationQuery_NotFound,Get-NetFirewallRule')) {
            throw
        }
    }
    [pscustomobject]@{
        Counts                  = [pscustomobject]$counts
        AllowBreakdown          = [pscustomobject]$allowBreakdown
        Port53OutboundBlockCount = $port53BlockCount
    }
}

[pscustomobject]@{
    ObservedAtUtc                   = [datetime]::UtcNow.ToString('o')
    ActiveStoreProfiles             = $profiles
    FirewallServices                = $services
    CurrentNetworkCategories        = $networkCategories
    EnabledOutboundRuleCounts       = if ($null -ne $outboundRules) { $outboundRules.Counts } else { $null }
    EnabledOutboundAllowBreakdown   = if ($null -ne $outboundRules) { $outboundRules.AllowBreakdown } else { $null }
    LanDnsPort53OutboundBlockCount  = if ($null -ne $outboundRules) { $outboundRules.Port53OutboundBlockCount } else { $null }
    Warnings                        = @($warnings.ToArray())
    EvidenceLimits                  = @(
        'Counts cover enabled outbound rules in ActiveStore across all profiles. Individual rules can have additional conditions.'
        'An unset or NotConfigured action is not a verified allow or block result.'
        'Allow breakdown classifies rules heuristically by name/group without exposing paths or rule names; review third-party allow rules locally.'
        'This inventory sends no traffic and cannot verify whether tunnel failure blocks subsequent connections.'
    )
} | ConvertTo-Json -Depth 5
