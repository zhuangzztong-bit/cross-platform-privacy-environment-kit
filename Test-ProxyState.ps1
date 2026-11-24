#Requires -Version 5.1
<#
.SYNOPSIS
Observe HTTPS connectivity at an operator-selected Windows proxy stage.
.DESCRIPTION
Run in a non-elevated terminal. This script never changes the network or prepares
an outage. Because the probe disables curl proxy use (--noproxy "*") to follow
OS system routing, running it in -Stage normal without an active TUN/tunnel route
would bypass System Proxy and expose your real IP to ProbeUrl. Therefore, the
script performs a local TUN route preflight check first and refuses to send a
normal-stage probe if no active tunnel route is detected (unless explicitly
overridden via -AllowDirectWithoutTun).
.EXAMPLE
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Test-ProxyState.ps1 -Stage normal -AsJson
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('normal', 'upstream-unreachable', 'tun-down', 'client-down')]
    [string] $Stage,

    [uri] $ProbeUrl = 'https://example.com/',

    [uri] $DirectUrl,

    [ValidateSet('auto', 'ipv4', 'ipv6')]
    [string] $AddressFamily = 'auto',

    [ValidateRange(3, 60)]
    [int] $TimeoutSeconds = 12,

    [switch] $AllowDirectWithoutTun,

    [switch] $AsJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'Run this script in a non-elevated Windows terminal.'
}

$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = $utf8NoBom
try {
    [Console]::OutputEncoding = $utf8NoBom
} catch {
    # Ignore if stdout is not attached to a console handle.
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
try {
    $principal = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList $identity
    if ($identity.IsSystem -or $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this test as an ordinary user in a non-elevated terminal.'
    }
} finally {
    $identity.Dispose()
}

$curlPath = Join-Path ([Environment]::SystemDirectory) 'curl.exe'
if (-not (Test-Path -LiteralPath $curlPath -PathType Leaf)) {
    throw 'Windows system curl.exe was not found. No network probes were sent.'
}

function Test-NonPublicIpHost {
    param([string] $HostName)
    $clean = $HostName.Trim('[', ']')
    $ip = $null
    if (-not [Net.IPAddress]::TryParse($clean, [ref] $ip)) {
        return $false
    }
    if ([Net.IPAddress]::IsLoopback($ip)) { return $true }
    if ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
        $b = $ip.GetAddressBytes()
        $val = ([uint32]$b[0] -shl 24) -bor ([uint32]$b[1] -shl 16) -bor ([uint32]$b[2] -shl 8) -bor [uint32]$b[3]
        return (
            (($val -band 0xFF000000L) -eq 0x00000000L) -or # 0.0.0.0/8
            (($val -band 0xFF000000L) -eq 0x0A000000L) -or # 10.0.0.0/8
            (($val -band 0xFFC00000L) -eq 0x64400000L) -or # 100.64.0.0/10
            (($val -band 0xFF000000L) -eq 0x7F000000L) -or # 127.0.0.0/8
            (($val -band 0xFFFF0000L) -eq 0xA9FE0000L) -or # 169.254.0.0/16
            (($val -band 0xFFF00000L) -eq 0xAC100000L) -or # 172.16.0.0/12
            (($val -band 0xFFFF0000L) -eq 0xC0A80000L) -or # 192.168.0.0/16
            (($val -band 0xFFFE0000L) -eq 0xC6120000L) -or # 198.18.0.0/15
            (($val -band 0xF0000000L) -eq 0xE0000000L) -or # 224.0.0.0/4
            (($val -band 0xF0000000L) -eq 0xF0000000L)     # 240.0.0.0/4
        )
    }
    if ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) {
        return (
            $ip.IsIPv6LinkLocal -or $ip.IsIPv6SiteLocal -or $ip.IsIPv6Multicast -or
            (($ip.GetAddressBytes()[0] -band 0xFE) -eq 0xFC) -or
            $ip.Equals([Net.IPAddress]::IPv6None)
        )
    }
    return $true
}

function Assert-ProbeUrl {
    param([uri] $Url)

    if (
        -not $Url.IsAbsoluteUri -or $Url.Scheme -ne 'https' -or
        [string]::IsNullOrWhiteSpace($Url.Host) -or $Url.UserInfo -or
        $Url.Query -or $Url.Fragment -or $Url.IsLoopback -or
        (Test-NonPublicIpHost $Url.IdnHost) -or
        $Url.AbsoluteUri.Length -gt 2048 -or $Url.AbsoluteUri -match '["\s\\\x00-\x1F\x7F]'
    ) {
        throw 'Use a public HTTPS probe URL without private IP literals, credentials, a query, or a fragment.'
    }
}

function Test-ActiveTunnelRoutePresent {
    $tunnelPattern = '(?i)(?:^|[\s_.-])(?:u?tun\d*|wintun\d*|wireguard|tailscale|sing[-_]?box|mihomo|clash)(?:$|[\s_.-])'
    try {
        $tunnelIndexes = @(
            Get-NetAdapter -IncludeHidden -ErrorAction Stop |
                Where-Object { $_.Status -eq 'Up' -and "$($_.Name) $($_.InterfaceDescription)" -match $tunnelPattern } |
                ForEach-Object { [int]$_.ifIndex }
        )
        if ($tunnelIndexes.Count -eq 0) { return $false }
        $prefixes = switch ($AddressFamily) {
            'ipv4' { @('0.0.0.0/0', '0.0.0.0/1', '128.0.0.0/1') }
            'ipv6' { @('::/0', '::/1', '8000::/1', '2000::/3') }
            default { @('0.0.0.0/0', '0.0.0.0/1', '128.0.0.0/1', '::/0', '::/1', '8000::/1', '2000::/3') }
        }
        $tunnelRoutes = @(
            Get-NetRoute -PolicyStore ActiveStore -ErrorAction Stop |
                Where-Object { $_.DestinationPrefix -in $prefixes -and ([int]$_.InterfaceIndex) -in $tunnelIndexes }
        )
        return ($tunnelRoutes.Count -gt 0)
    } catch {
        return $false
    }
}

function Test-HostInDnsCache {
    param([string] $HostName)
    try {
        $entries = @(Get-DnsClientCache -Name $HostName -ErrorAction SilentlyContinue)
        return ($entries.Count -gt 0)
    } catch {
        return $false
    }
}

function Invoke-HTTPSProbe {
    param([uri] $Url)

    $processInfo = New-Object Diagnostics.ProcessStartInfo
    $processInfo.FileName = $curlPath
    $processInfo.UseShellExecute = $false
    $processInfo.CreateNoWindow = $true
    $processInfo.RedirectStandardOutput = $true
    $processInfo.RedirectStandardError = $true

    foreach ($name in @($processInfo.EnvironmentVariables.Keys)) {
        if ($name -match '^(all|https?|ftp|no)_proxy$|^(SSLKEYLOGFILE|QLOGDIR)$') {
            $processInfo.EnvironmentVariables.Remove([string] $name)
        }
    }

    $connectTimeout = [Math]::Min($TimeoutSeconds, 8)
    $familyOption = switch ($AddressFamily) {
        'ipv4' { '--ipv4 ' }
        'ipv6' { '--ipv6 ' }
        default { '' }
    }

    $processInfo.Arguments = (
        '-q --noproxy "*" --proto "=https" --globoff --head --silent --show-error ' +
        "--connect-timeout $connectTimeout --max-time $TimeoutSeconds " +
        '--output NUL --write-out "http=%{http_code};tcp=%{time_connect};total=%{time_total}" ' +
        $familyOption + '-- "' + $Url.AbsoluteUri + '"'
    )

    $process = New-Object Diagnostics.Process
    $process.StartInfo = $processInfo
    $started = $false
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $observation = [ordered] @{
        CurlExitCode = $null
        HttpStatus = $null
        TcpConnectSeconds = $null
        CurlTotalSeconds = $null
        WallMilliseconds = $null
        State = 'probe-process-error'
    }

    try {
        $started = $process.Start()
        if (-not $started) {
            return [pscustomobject] $observation
        }

        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(($TimeoutSeconds + 3) * 1000)) {
            try {
                $process.Kill()
                [void] $process.WaitForExit(1000)
            } catch [InvalidOperationException] {
            }
            $observation.WallMilliseconds = $timer.ElapsedMilliseconds
            $observation.State = 'supervisor-timeout'
            return [pscustomobject] $observation
        }

        $observation.CurlExitCode = $process.ExitCode
        $observation.WallMilliseconds = $timer.ElapsedMilliseconds
        $streams = [Threading.Tasks.Task[]] @($stdout, $stderr)
        if (-not [Threading.Tasks.Task]::WaitAll($streams, 1000)) {
            $observation.State = 'output-timeout'
            return [pscustomobject] $observation
        }

        if ($stdout.Result.Trim() -notmatch '^http=(\d{3});tcp=(\d+(?:[.,]\d+)?);total=(\d+(?:[.,]\d+)?)$') {
            $observation.State = 'unparsed-curl-output'
            return [pscustomobject] $observation
        }

        $culture = [Globalization.CultureInfo]::InvariantCulture
        $observation.HttpStatus = [int] $Matches[1]
        $observation.TcpConnectSeconds = [decimal]::Parse($Matches[2].Replace(',', '.'), $culture)
        $observation.CurlTotalSeconds = [decimal]::Parse($Matches[3].Replace(',', '.'), $culture)

        if ($observation.HttpStatus -ge 100) {
            $observation.State = 'https-response'
        } elseif ($observation.TcpConnectSeconds -gt 0) {
            $observation.State = 'tcp-connected-no-https-response'
        } elseif ($observation.CurlExitCode -eq 6) {
            $observation.State = 'name-resolution-failed'
        } elseif ($observation.CurlExitCode -in @(7, 28)) {
            $observation.State = 'no-connection-observed'
        } else {
            $observation.State = 'other-curl-error'
        }
    } catch {
        $observation.WallMilliseconds = $timer.ElapsedMilliseconds
        $observation.State = 'probe-process-error'
    } finally {
        if ($started -and -not $process.HasExited) {
            try {
                $process.Kill()
            } catch [InvalidOperationException] {
            }
        }
        $process.Dispose()
    }

    [pscustomobject] $observation
}

Assert-ProbeUrl -Url $ProbeUrl
if ($null -ne $DirectUrl) {
    Assert-ProbeUrl -Url $DirectUrl
    if ($DirectUrl.AbsoluteUri -eq $ProbeUrl.AbsoluteUri) {
        throw 'Choose distinct URLs for the primary and direct probes.'
    }
}

$tunnelRouteActive = Test-ActiveTunnelRoutePresent
if ($Stage -in @('normal', 'upstream-unreachable') -and -not $tunnelRouteActive -and -not $AllowDirectWithoutTun) {
    throw (
        'No active TUN/tunnel default route was detected. Because this script disables curl proxy use (--noproxy "*"), ' +
        'running it with only a System HTTP/SOCKS Proxy would connect directly using your real IP. ' +
        'Enable TUN mode first, or pass -AllowDirectWithoutTun if a direct probe is intentional.'
    )
}

$targets = @([pscustomobject] @{ Role = 'primary'; Url = $ProbeUrl })
if ($null -ne $DirectUrl) {
    $targets += [pscustomobject] @{ Role = 'operator-designated-direct'; Url = $DirectUrl }
}

$results = @(
    foreach ($target in $targets) {
        $expectResponse = $Stage -eq 'normal' -or (
            $Stage -eq 'upstream-unreachable' -and $target.Role -eq 'operator-designated-direct'
        )
        $dnsCached = Test-HostInDnsCache -HostName $target.Url.IdnHost
        $sampledUtc = [DateTime]::UtcNow.ToString('o')
        $probe = Invoke-HTTPSProbe -Url $target.Url
        $hasConnection = $probe.State -in @('https-response', 'tcp-connected-no-https-response')
        if ($expectResponse) {
            $verdict = if ($probe.State -eq 'https-response') { 'observed' } else { 'not-observed' }
        } elseif ($hasConnection) {
            $verdict = 'unexpected-connectivity'
        } elseif ($probe.State -eq 'no-connection-observed') {
            $verdict = 'observed'
        } else {
            $verdict = 'inconclusive'
        }

        [pscustomobject] [ordered] @{
            Stage = $Stage
            SampledUtc = $sampledUtc
            Role = $target.Role
            Host = $target.Url.IdnHost
            AddressFamily = $AddressFamily
            DnsCachedBeforeProbe = $dnsCached
            Expected = if ($expectResponse) { 'https-response' } else { 'no-connection-observed' }
            Observation = $probe.State
            CurlExitCode = $probe.CurlExitCode
            HttpStatus = $probe.HttpStatus
            TcpConnectSeconds = $probe.TcpConnectSeconds
            CurlTotalSeconds = $probe.CurlTotalSeconds
            WallMilliseconds = $probe.WallMilliseconds
            Verdict = $verdict
        }
    }
)

$needsReview = @($results | Where-Object { $_.Verdict -ne 'observed' }).Count -gt 0
$report = [pscustomobject] [ordered] @{
    Stage = $Stage
    TunnelRouteDetected = $tunnelRouteActive
    DirectRouteProbeIncluded = $null -ne $DirectUrl
    Coverage = 'One curl HEAD attempt per URL with curl proxy use disabled. Preflight verifies TUN route presence unless overridden. DNS transport, firewall block attribution, and other applications require separate verification.'
    ObservationsMatchStage = -not $needsReview
    Probes = $results
}

if ($AsJson) {
    $report | ConvertTo-Json -Depth 5
} else {
    $report
}
if ($needsReview) { exit 2 }
exit 0
