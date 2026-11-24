#Requires -Version 5.1
<#
.SYNOPSIS
Manage scoped outbound Windows Firewall rules blocking LAN/router port 53 DNS bypass on physical adapters.
.DESCRIPTION
Prevents processes from querying private/CGNAT/ULA/link-local router DNS (TCP/UDP 53) directly over
physical network interfaces when switching routers or hotspots, while leaving router admin (80/443),
DHCP (67/68), LAN sharing, loopback, and virtual TUN adapters unaffected.
Preview computes the rule plan natively in PowerShell without invoking external interpreters or
changing the host. Install and Remove require an elevated local Windows console, verify that the
script directory is not writable by shared unprivileged groups, export a firewall policy backup
with SHA-256 hash before Install, and write a private redacted log.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Preview', 'Install', 'Status', 'Remove')]
    [string]$Action,

    [string[]]$InterfaceAlias,
    [switch]$IncludeAllPhysicalAdapters,
    [switch]$AllowUncoveredPhysicalAdapters,
    [string]$LogDirectory = $env:LOCALAPPDATA
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Group = 'CPPEK-LanDnsGuard-v1'
$Owner = 'Cross-platform privacy environment kit: physical-NIC LAN DNS port 53 guard v1'
$LanIPv4Prefixes = @('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10')
$LanIPv6Prefixes = @('fc00::/7', 'fe80::/10')
$KnownNames = @('IPv4-UDP53', 'IPv4-TCP53', 'IPv6-UDP53', 'IPv6-TCP53') | ForEach-Object { "$Group-$_" }

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'Run this script in Windows PowerShell 5.1 or newer on the target computer.'
}
try {
    [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
} catch {
    # Output may not be attached to a console.
}

function ConvertTo-ValidatedInterfaceAliases {
    param([string[]]$Names)
    if (-not $Names -or $Names.Count -eq 0) {
        throw 'Supply at least one physical interface alias.'
    }
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $clean = New-Object 'System.Collections.Generic.List[string]'
    foreach ($name in $Names) {
        if ($null -eq $name -or $name.Length -lt 1 -or $name.Length -gt 128 -or
            $name -cne $name.Trim() -or $name.StartsWith('-') -or
            $name.Equals('any', [StringComparison]::OrdinalIgnoreCase) -or
            $name -match '[\*\?\[\]`"\\]') {
            throw 'Use literal interface aliases without wildcards or control characters.'
        }
        foreach ($ch in $name.ToCharArray()) {
            if ([char]::IsControl($ch)) {
                throw 'Use literal interface aliases without wildcards or control characters.'
            }
        }
        if (-not $seen.Add($name)) {
            throw 'Interface aliases must be unique.'
        }
        $clean.Add($name)
    }
    $sorted = @($clean.ToArray() | Sort-Object { $_.ToLowerInvariant() })
    ,$sorted
}

function New-LanDnsGuardPlan {
    param([string[]]$Aliases)
    $validatedAliases = ConvertTo-ValidatedInterfaceAliases -Names $Aliases
    $rules = @(
        [pscustomobject][ordered]@{
            Name            = "$Group-IPv4-UDP53"
            RemoteAddresses = @($LanIPv4Prefixes)
            Protocol        = 'UDP'
            RemotePorts     = @('53')
            LocalPorts      = @()
        }
        [pscustomobject][ordered]@{
            Name            = "$Group-IPv4-TCP53"
            RemoteAddresses = @($LanIPv4Prefixes)
            Protocol        = 'TCP'
            RemotePorts     = @('53')
            LocalPorts      = @()
        }
        [pscustomobject][ordered]@{
            Name            = "$Group-IPv6-UDP53"
            RemoteAddresses = @($LanIPv6Prefixes)
            Protocol        = 'UDP'
            RemotePorts     = @('53')
            LocalPorts      = @()
        }
        [pscustomobject][ordered]@{
            Name            = "$Group-IPv6-TCP53"
            RemoteAddresses = @($LanIPv6Prefixes)
            Protocol        = 'TCP'
            RemotePorts     = @('53')
            LocalPorts      = @()
        }
    )
    [pscustomobject][ordered]@{
        SchemaVersion    = 1
        InterfaceAliases = @($validatedAliases)
        RuleCount        = $rules.Count
        Rules            = $rules
    }
}

function Assert-Elevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Install and Remove must run from an elevated local PowerShell console.'
    }
    $identity.User
}

function Assert-UnlinkedLocalDirectory {
    param([string]$Path, [string]$Label)
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path.StartsWith('\\')) {
        throw "$Label must be a local directory."
    }
    $full = [IO.Path]::GetFullPath($Path)
    if ($full.StartsWith('\\')) { throw "$Label must be a local directory." }
    $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($full))
    if ($drive.DriveType -notin @([IO.DriveType]::Fixed, [IO.DriveType]::Removable, [IO.DriveType]::Ram)) {
        throw "$Label must be on a local filesystem."
    }
    if (-not [IO.Directory]::Exists($full)) {
        throw "$Label does not exist."
    }
    $ancestors = @()
    for ($dir = [IO.DirectoryInfo]::new($full); $null -ne $dir; $dir = $dir.Parent) {
        $ancestors = @($dir) + $ancestors
    }
    foreach ($dir in $ancestors) {
        $attr = [IO.File]::GetAttributes($dir.FullName)
        if (($attr -band [IO.FileAttributes]::ReparsePoint) -or -not ($attr -band [IO.FileAttributes]::Directory)) {
            throw "$Label must be a real directory without redirected parents."
        }
    }
    $full
}

function Assert-SafeElevatedScriptPath {
    if (-not $PSCommandPath) { return }
    $scriptDir = Assert-UnlinkedLocalDirectory -Path (Split-Path -Parent $PSCommandPath) -Label 'Script directory'
    $attr = [IO.File]::GetAttributes($PSCommandPath)
    if (($attr -band [IO.FileAttributes]::ReparsePoint) -or ($attr -band [IO.FileAttributes]::Directory)) {
        throw 'Manage-WindowsLanDnsGuard.ps1 must be a regular local file without links.'
    }
    $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($scriptDir))
    if ($drive.DriveFormat -notin @('NTFS', 'ReFS')) { return }

    $sharedSids = @('S-1-1-0', 'S-1-5-32-545', 'S-1-5-11', 'S-1-5-32-546')
    $writeMask = [Security.AccessControl.FileSystemRights]::Write -bor
        [Security.AccessControl.FileSystemRights]::Modify -bor
        [Security.AccessControl.FileSystemRights]::FullControl -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    foreach ($itemPath in @($scriptDir, $PSCommandPath)) {
        $acl = Get-Acl -LiteralPath $itemPath -ErrorAction Stop
        foreach ($rule in $acl.Access) {
            if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
            $sid = try { $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { $null }
            if ($sid -in $sharedSids -and (($rule.FileSystemRights -band $writeMask) -ne 0)) {
                throw 'Move this kit into a private directory (such as your user profile or Program Files) before running elevated.'
            }
        }
    }
}

function Set-PrivateFileAcl {
    param([string]$FilePath, [Security.Principal.SecurityIdentifier]$OperatorSid)
    $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($FilePath))
    if ($drive.DriveFormat -notin @('NTFS', 'ReFS')) { return }
    $acl = New-Object Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sidValue in @('S-1-5-18', 'S-1-5-32-544', $OperatorSid.Value)) {
        $sid = New-Object Security.Principal.SecurityIdentifier($sidValue)
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            $sid, [Security.AccessControl.FileSystemRights]::FullControl, [Security.AccessControl.AccessControlType]::Allow
        )
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $FilePath -AclObject $acl -ErrorAction Stop
}

function Get-PolicySet {
    param([string]$Store)
    @(Get-NetFirewallRule -PolicyStore $Store -ErrorAction Stop | Where-Object {
        $_.Name -in $KnownNames -or $_.Group -eq $Group
    })
}

function Test-OwnedRule {
    param($Rule)
    $Rule.Name -cin $KnownNames -and $Rule.Group -ceq $Group -and $Rule.Description -ceq $Owner
}

function Test-SameSet {
    param($Left, $Right)
    $l = @($Left | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Where-Object { $_ } | Sort-Object -Unique)
    $r = @($Right | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Where-Object { $_ } | Sort-Object -Unique)
    if ($l.Count -ne $r.Count) { return $false }
    for ($i = 0; $i -lt $l.Count; $i++) {
        if ($l[$i] -cne $r[$i]) { return $false }
    }
    $true
}

function Normalize-RemoteAddress {
    param([string]$Value)
    switch ($Value.Trim().ToLowerInvariant()) {
        '10.0.0.0/255.0.0.0'      { return '10.0.0.0/8' }
        '172.16.0.0/255.240.0.0'  { return '172.16.0.0/12' }
        '192.168.0.0/255.255.0.0' { return '192.168.0.0/16' }
        '100.64.0.0/255.192.0.0'  { return '100.64.0.0/10' }
        default                   { return $Value.Trim().ToLowerInvariant() }
    }
}

function Normalize-Protocol {
    param([string]$Value)
    switch ($Value.Trim().ToUpperInvariant()) {
        '6'   { 'TCP' }
        'TCP' { 'TCP' }
        '17'  { 'UDP' }
        'UDP' { 'UDP' }
        default { $Value.Trim() }
    }
}

function Test-Any {
    param($Value)
    @($Value | Where-Object { $_ -and [string]$_ -ne 'Any' }).Count -eq 0
}

function Test-RulesMatch {
    param($Actual, $Plan, [bool]$Enabled)
    if (@($Actual).Count -ne @($Plan.Rules).Count) { return $false }
    foreach ($entry in $Plan.Rules) {
        $matched = @($Actual | Where-Object { $_.Name -ceq $entry.Name })
        if ($matched.Count -ne 1) { return $false }
        $rule = $matched[0]
        if (-not (Test-OwnedRule $rule) -or [string]$rule.Direction -ne 'Outbound' -or
            [string]$rule.Action -ne 'Block' -or [string]$rule.Profile -ne 'Any' -or
            (([string]$rule.Enabled -eq 'True') -ne $Enabled)) {
            return $false
        }
        $addresses = $rule | Get-NetFirewallAddressFilter -ErrorAction Stop
        $ports = $rule | Get-NetFirewallPortFilter -ErrorAction Stop
        $interfaces = $rule | Get-NetFirewallInterfaceFilter -ErrorAction Stop
        $types = $rule | Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop
        $application = $rule | Get-NetFirewallApplicationFilter -ErrorAction Stop
        $service = $rule | Get-NetFirewallServiceFilter -ErrorAction Stop
        $protocol = Normalize-Protocol ([string]$ports.Protocol)
        $actualAddresses = @($addresses.RemoteAddress | ForEach-Object { Normalize-RemoteAddress $_ })
        if ($protocol -cne $entry.Protocol -or
            -not (Test-Any $ports.LocalPort) -or
            -not (Test-SameSet $ports.RemotePort $entry.RemotePorts) -or
            -not (Test-SameSet $actualAddresses $entry.RemoteAddresses) -or
            -not (Test-SameSet $interfaces.InterfaceAlias $Plan.InterfaceAliases) -or
            -not (Test-Any $addresses.LocalAddress) -or -not (Test-Any $types.InterfaceType) -or
            -not (Test-Any $application.Program) -or -not (Test-Any $service.Service)) {
            return $false
        }
        $package = $application.PSObject.Properties['Package']
        if ($null -ne $package -and -not (Test-Any $package.Value)) { return $false }
    }
    $true
}

function Get-GuardPrerequisites {
    param($Plan)
    $windowsServices = @(Get-Service -Name BFE, MpsSvc -ErrorAction Stop)
    if ($windowsServices.Count -ne 2 -or @($windowsServices | Where-Object { $_.Status -ne 'Running' }).Count) {
        throw 'The Base Filtering Engine and Windows Firewall services must be running.'
    }
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
    if (-not (Test-SameSet @($profiles.Name) @('Domain', 'Private', 'Public'))) {
        throw 'Could not verify the three effective firewall profiles.'
    }
    foreach ($firewallProfile in $profiles) {
        if ([string]$firewallProfile.Enabled -ne 'True' -or [string]$firewallProfile.AllowLocalFirewallRules -eq 'False') {
            throw 'All profiles must have Windows Firewall and local rule merging enabled.'
        }
    }
    $allAdapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop)
    $physical = @($allAdapters | Where-Object { $_.HardwareInterface -eq $true })
    foreach ($alias in $Plan.InterfaceAliases) {
        if (@($physical | Where-Object { $_.Name -eq $alias }).Count -ne 1) {
            throw "The selected physical adapter could not be identified: $alias"
        }
    }
    $otherActivePhysical = @($physical | Where-Object {
        $_.Status -eq 'Up' -and $_.Name -notin $Plan.InterfaceAliases
    } | ForEach-Object { $_.Name })
    [pscustomobject]@{
        Profiles                    = @($profiles.Name)
        PhysicalAdapterCount        = @($Plan.InterfaceAliases).Count
        OtherActivePhysicalAdapters = $otherActivePhysical
        AllActivePhysicalCovered    = ($otherActivePhysical.Count -eq 0)
    }
}

function Remove-OwnedRules {
    param([string[]]$Names)
    $removed = @()
    foreach ($rule in @(Get-PolicySet 'PersistentStore')) {
        if ($rule.Name -cin $Names -and (Test-OwnedRule $rule)) {
            Remove-NetFirewallRule -PolicyStore PersistentStore -Name $rule.Name -ErrorAction Stop
            $removed += $rule.Name
        }
    }
    $removed
}

function Resolve-TargetAliases {
    if ($IncludeAllPhysicalAdapters) {
        if ($InterfaceAlias -and $InterfaceAlias.Count -gt 0) {
            throw 'Use either -InterfaceAlias or -IncludeAllPhysicalAdapters, not both.'
        }
        $discovered = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop |
            Where-Object { $_.HardwareInterface -eq $true } |
            ForEach-Object { [string]$_.Name })
        if ($discovered.Count -eq 0) {
            throw 'No physical network adapters were detected on this host.'
        }
        return ,$discovered
    }
    ,$InterfaceAlias
}

$plan = $null
if ($Action -in @('Preview', 'Install') -or ($Action -eq 'Status' -and ($IncludeAllPhysicalAdapters -or ($InterfaceAlias -and $InterfaceAlias.Count -gt 0)))) {
    $resolvedAliases = Resolve-TargetAliases
    $plan = New-LanDnsGuardPlan -Aliases $resolvedAliases
}

if ($Action -eq 'Preview') {
    $plan | ConvertTo-Json -Depth 6
    exit 0
}

if ($Action -eq 'Status') {
    $persisted = @(Get-PolicySet 'PersistentStore')
    $active = @(Get-PolicySet 'ActiveStore')
    $matched = $null
    $prereq = $null
    if ($null -ne $plan) {
        $prereq = Get-GuardPrerequisites -Plan $plan
        $coverageOk = $AllowUncoveredPhysicalAdapters.IsPresent -or $prereq.AllActivePhysicalCovered
        $matched = $coverageOk -and (Test-RulesMatch $persisted $plan $true) -and (Test-RulesMatch $active $plan $true)
    }
    [pscustomobject][ordered]@{
        ObservedAtUtc            = [DateTime]::UtcNow.ToString('o')
        Group                    = $Group
        PersistedCount           = $persisted.Count
        ActiveCount              = $active.Count
        PersistedNames           = @($persisted | ForEach-Object { $_.Name } | Sort-Object)
        ActiveNames              = @($active | ForEach-Object { $_.Name } | Sort-Object)
        MatchedPlan              = $matched
        AllActivePhysicalCovered = if ($null -ne $prereq) { $prereq.AllActivePhysicalCovered } else { $null }
    } | ConvertTo-Json -Depth 5
    exit 0
}

$operatorSid = Assert-Elevated
Assert-SafeElevatedScriptPath
$safeLogDir = Assert-UnlinkedLocalDirectory -Path $LogDirectory -Label 'LogDirectory'
$stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
$logPath = Join-Path $safeLogDir "CPPEK-LanDnsGuard-$stamp.jsonl"

$fileStream = [IO.File]::Open($logPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
$logWriter = [IO.StreamWriter]::new($fileStream, [Text.UTF8Encoding]::new($false))
try {
    Set-PrivateFileAcl -FilePath $logPath -OperatorSid $operatorSid
    if ($Action -eq 'Remove') {
        $foreign = @(Get-PolicySet 'PersistentStore' | Where-Object { -not (Test-OwnedRule $_) })
        if ($foreign.Count -gt 0) {
            throw 'Refusing to remove unmanaged firewall rules sharing this rule group or prefix.'
        }
        $removed = Remove-OwnedRules -Names $KnownNames
        $logWriter.WriteLine(([ordered]@{ Utc = [DateTime]::UtcNow.ToString('o'); Action = 'Remove'; RemovedCount = @($removed).Count } | ConvertTo-Json -Compress))
        [pscustomobject][ordered]@{
            Action       = 'Remove'
            Group        = $Group
            RemovedCount = @($removed).Count
            RemovedNames = @($removed)
            LogPath      = $logPath
        } | ConvertTo-Json -Depth 4
        exit 0
    }

    $prereq = Get-GuardPrerequisites -Plan $plan
    if (-not $prereq.AllActivePhysicalCovered -and -not $AllowUncoveredPhysicalAdapters) {
        throw 'At least one active physical adapter is not covered. Pass -IncludeAllPhysicalAdapters or -AllowUncoveredPhysicalAdapters.'
    }
    $foreign = @(Get-PolicySet 'PersistentStore' | Where-Object { -not (Test-OwnedRule $_) })
    if ($foreign.Count -gt 0) {
        throw 'Refusing to overwrite unmanaged firewall rules sharing this rule group or prefix.'
    }

    $backupPath = Join-Path $safeLogDir "CPPEK-LanDnsGuard-before-$stamp.wfw"
    $netsh = Join-Path ([Environment]::SystemDirectory) 'netsh.exe'
    & $netsh advfirewall export $backupPath | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not [IO.File]::Exists($backupPath)) {
        throw 'Failed to export Windows Firewall backup before Install.'
    }
    Set-PrivateFileAcl -FilePath $backupPath -OperatorSid $operatorSid
    $backupHash = (Get-FileHash -LiteralPath $backupPath -Algorithm SHA256).Hash

    [void](Remove-OwnedRules -Names $KnownNames)
    foreach ($entry in $plan.Rules) {
        New-NetFirewallRule -PolicyStore PersistentStore `
            -Name $entry.Name `
            -DisplayName $entry.Name `
            -Group $Group `
            -Description $Owner `
            -Direction Outbound `
            -Action Block `
            -Enabled True `
            -Profile Any `
            -InterfaceAlias $plan.InterfaceAliases `
            -Protocol $entry.Protocol `
            -RemotePort $entry.RemotePorts `
            -RemoteAddress $entry.RemoteAddresses `
            -ErrorAction Stop | Out-Null
    }

    $persisted = @(Get-PolicySet 'PersistentStore')
    $active = @(Get-PolicySet 'ActiveStore')
    if (-not (Test-RulesMatch $persisted $plan $true) -or -not (Test-RulesMatch $active $plan $true)) {
        [void](Remove-OwnedRules -Names $KnownNames)
        throw 'Verification after Install failed; newly added rules were rolled back.'
    }

    $logWriter.WriteLine(([ordered]@{
        Utc            = [DateTime]::UtcNow.ToString('o')
        Action         = 'Install'
        InterfaceCount = @($plan.InterfaceAliases).Count
        RuleCount      = @($plan.Rules).Count
        BackupSha256   = $backupHash
    } | ConvertTo-Json -Compress))

    [pscustomobject][ordered]@{
        Action         = 'Install'
        Group          = $Group
        InterfaceCount = @($plan.InterfaceAliases).Count
        RuleCount      = @($plan.Rules).Count
        BackupPath     = $backupPath
        BackupSha256   = $backupHash
        LogPath        = $logPath
        Verified       = $true
    } | ConvertTo-Json -Depth 4
} finally {
    $logWriter.Dispose()
}
