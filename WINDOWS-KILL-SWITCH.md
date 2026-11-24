# Windows 断网开关安装与实机验收

本工具在指定物理网卡上创建持久化的 Windows Defender 防火墙出站阻断规则。代理客户端或 TUN 退出后，规则仍由 Windows 防火墙服务执行。

> **安全加固说明**：
> - `Manage-WindowsKillSwitch.ps1` 现已完全采用原生 PowerShell 计算规则，**不再在管理员权限下调用外部 `py.exe` 或外部 Python 脚本**，并在运行前校验脚本所在目录未被普通共享用户组赋予写权限（请将工具包放在个人主目录子文件夹或 `C:\Program Files` 下运行，不要放在公共可写分区根目录）。
> - 默认要求覆盖**所有当前处于连接（Up）状态的物理网卡**（推荐直接使用 `-IncludeAllPhysicalAdapters` 把机器上所有有线/无线物理网卡一次全部纳入），防止漏掉第二张活动网卡。新增 USB 共享网络、扩展坞网卡或虚拟交换机后，需重新运行 `Install` 更新范围。
> - 对例外 IP（上游地址与可选 DHCP 地址）已同步封堵 ICMPv4、IGMP、IP-in-IP、IPv6-in-IPv4（6to4/ISATAP）、GRE、ESP、AH 与 SCTP 协议。
> - 安装日志 `CPPEK-KillSwitch-*.jsonl` 自动设置当前用户私有 NTFS 权限，并**已脱敏移除真实代理上游 IP、内网网关 IP 与网卡名**。

## 预览、安装与卸载

在个人主目录下的解压目录中打开 Windows PowerShell 5.1。安装、卸载使用本机管理员 PowerShell。上游是**本机代理直接拨接的固定独享 IPv4 地址**（避免使用与日常网页共用的共享 CDN IP，否则代理退出后访问同 IP 站点仍会匹配端口例外）。

```powershell
Get-NetAdapter -Physical -IncludeHidden | Select-Object Name, ifIndex, Status

$settings = @{
    IncludeAllPhysicalAdapters = $true
    UpstreamAddress            = '<固定上游 IPv4>'
    UpstreamPort               = 443
    UpstreamProtocol           = 'TCP'
}
& .\Manage-WindowsKillSwitch.ps1 -Action Preview @settings
```

- 所选网卡上的 IPv6 出站会被全部阻断；IPv4 仅放行指定上游的单一 TCP/UDP 端口。
- 所选物理网卡上的直连分流（如 `geosite:cn` / `geoip:cn` 直连）在启用断网开关后会被防火墙拦截——**启用断网保护时，客户端应配合使用全局代理路由（如 `py -3 .\build_routing.py generate .\routing-global.json --global-proxy`），不要混用国内直连分流**。
- 若电脑通过 DHCP 获取 IPv4 租约，可在预览前加入 `$settings['DhcpServer'] = '<DHCP 服务器的私有 IPv4>'`，仅放行本机 68 端口至该地址及广播地址 67 端口的 UDP 续租包。

确认预览后，在管理员 PowerShell 运行安装：

```powershell
& .\Manage-WindowsKillSwitch.ps1 -Action Install @settings
& .\Manage-WindowsKillSwitch.ps1 -Action Status @settings
```

需要恢复连接时，运行离线卸载：

```powershell
& .\Manage-WindowsKillSwitch.ps1 -Action Remove
& .\Manage-WindowsKillSwitch.ps1 -Action Status
```

如果工具目录无法访问，可从本机管理员 PowerShell 用系统命令撤销：

```powershell
$group = 'CPPEK-KillSwitch-v1'
$names = @(
    'IPv4OtherAddresses', 'IPv6', 'UpstreamOtherTransport', 'UpstreamOtherPorts',
    'ExceptionProtoICMPv4', 'ExceptionProtoIGMP', 'ExceptionProtoIPv4Encap', 'ExceptionProtoIPv6Encap',
    'ExceptionProtoGRE', 'ExceptionProtoESP', 'ExceptionProtoAH', 'ExceptionProtoSCTP',
    'DhcpTcp', 'DhcpOtherRemotePorts', 'DhcpOtherLocalPorts'
) | ForEach-Object { "$group-$_" }
Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object {
    $_.Name -cin $names -and $_.Group -ceq $group -and
        $_.Description -ceq 'Cross-platform privacy environment kit: managed uplink guard v1'
} | ForEach-Object { Remove-NetFirewallRule -PolicyStore PersistentStore -Name $_.Name }
```

## 实机验收与 5157 阻断事件关联

临时开启筛选平台连接失败审计（测完按原状恢复）：

```powershell
$subcategory = '{0CCE9226-69AE-11D9-BED3-505054503030}'
auditpol.exe /get "/subcategory:$subcategory"
auditpol.exe /set "/subcategory:$subcategory" /failure:enable
```

在普通用户 PowerShell 固定源端口发起单次直连探测：

```powershell
$testName = '<自有 HTTPS 测试站点的证书域名>'
$testIp = '<该站点的固定 IPv4>'
$sourcePort = 49231
$since = Get-Date
$since.ToUniversalTime().ToString('o')
& "$env:SystemRoot\System32\curl.exe" -q --noproxy '*' --ipv4 --head --connect-timeout 5 --max-time 10 --local-port $sourcePort --resolve "${testName}:443:${testIp}" "https://$testName/"
$LASTEXITCODE
[DateTime]::UtcNow.ToString('o')
```

在管理员窗口关联同一次探测（`-SourcePort` 现为必填项，防止误关联窗口内其他阻断记录）：

```powershell
$since = [DateTimeOffset]::Parse('<上一条探测输出的 UTC 时间>').LocalDateTime
$until = [DateTimeOffset]::Parse('<同一次探测结束的 UTC 时间>').LocalDateTime
& .\Get-WindowsKillSwitchEvidence.ps1 -Since $since -Until $until -DestinationAddress '<同一测试 IP>' -DestinationPort 443 -Protocol TCP -ApplicationName 'curl.exe' -SourcePort 49231
```

若测试前失败审计原为关闭，验收后恢复关闭：

```powershell
auditpol.exe /set "/subcategory:{0CCE9226-69AE-11D9-BED3-505054503030}" /failure:disable
```

## 补充：保留国内直连分流时的「物理网卡防路由器 DNS 旁路」

如果你当前使用国内直连分流（未开启上文的全量断网开关），仍建议安装独立的轻量级物理网卡防 DNS 旁路规则 `Manage-WindowsLanDnsGuard.ps1`（规则组 `CPPEK-LanDnsGuard-v1`，仅阻断物理网卡发往 RFC1918 / CGNAT / ULA / 链路本地地址的 TCP/UDP 53）：

```powershell
# 1. 普通用户预览规则计划（不改动系统）
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Manage-WindowsLanDnsGuard.ps1 -Action Preview -IncludeAllPhysicalAdapters

# 2. 管理员 PowerShell 安装（安装前自动导出 .wfw 防火墙备份并校验 SHA-256）
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Manage-WindowsLanDnsGuard.ps1 -Action Install -IncludeAllPhysicalAdapters

# 3. 核查生效状态或随时一键精准卸载
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Manage-WindowsLanDnsGuard.ps1 -Action Status -IncludeAllPhysicalAdapters
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Manage-WindowsLanDnsGuard.ps1 -Action Remove
```

该规则不依赖具体路由器 IP（切换 `192.168.0.1` / `192.168.1.1` / `192.168.5.1` 或手机热点均自动生效），且不影响路由器 80/443 管理页、DHCP（67/68）、局域网文件共享及 TUN 虚拟网卡。
