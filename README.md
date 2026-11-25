# 跨平台网络隐私与本机环境工具包 v0.3.5（Claude 生态防漏与逆向研究整合版）

同一个压缩包覆盖 **Windows、macOS、Linux、Android、iPhone／iPad**，并随包整合完整的 [Claude 封号机制与逆向研究报告汇编（23 份，含微信原件与离线 HTML 综合报告）](research-reports/克劳德封号机制与逆向报告完整汇编-含微信原件-2026-11-22/README.md)。桌面脚本使用 Python 3.10 或更新版本。默认操作均为只读。

> 新手与升级入口：先看 [CLAUDE-PROXY-OPTIMIZATION-GUIDE.md](CLAUDE-PROXY-OPTIMIZATION-GUIDE.md)，它把逆向报告中的每一条网络/客户端证据直接对应到本包的规则、脚本与边界提醒。

## v0.3.5 整合升级重点（基于 v0.3.4 安全加固版）

1. **新增 Claude 生态完整防分裂路由与远程 DoH 清单**：`build_routing.py` 新增 `--claude-ecosystem` 选项（可独立分流或组合 `--global-proxy`），置顶阻断 `udp/443` 与 Anthropic IPv6（`2607:6bc0::/48`、`2607:6bc0:11::/48`，防单 IPv4 出口 502），置顶代理 23 个核心/产物/遥测/验证/支付/客服/核验域名（已修正 `claudemcpcontent.com`）与官方 IPv4 网段 `160.79.104.0/21`；随包提供开箱即用的 [routing-claude-ecosystem.json](routing-claude-ecosystem.json)、[routing-claude-global.json](routing-claude-global.json) 及 [claude-doh-domains.txt](claude-doh-domains.txt)。
2. **新增 Windows 物理网卡路由器/内网防 DNS 旁路工具**：新增纯原生 PowerShell 脚本 [Manage-WindowsLanDnsGuard.ps1](Manage-WindowsLanDnsGuard.ps1) 及对照规划器 [build_lan_dns_guard.py](build_lan_dns_guard.py)，适用于保留国内直连分流或频繁切换路由器/热点的 Windows 主机——自动按物理网卡封堵去往 `10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`、`100.64.0.0/10`、`fc00::/7`、`fe80::/10` 的 TCP/UDP 53，安装前自动备份 `.wfw` 并校验 SHA-256，支持一键精准移除。
3. **新增 Android `v2rayNG` Claude 生态规则包、二维码与离线校验器**：`mobile/` 新增经 Xray 核心校验的 [android-v2rayng-claude-routing.json](mobile/android-v2rayng-claude-routing.json)、扫码直导的 [android-v2rayng-claude-routing-qr.png](mobile/android-v2rayng-claude-routing-qr.png) 与 [validate_android_v2rayng.py](mobile/validate_android_v2rayng.py)；[mobile/README.md](mobile/README.md) 明确补充 Android 原生 App 本地硬件/物理网卡 IPv6 枚举与 iOS 的架构差异。
4. **新增宿主机/客户端边界只读体检与防火墙审计增强**：新增只读脱敏脚本 [audit_client_boundary.py](audit_client_boundary.py) 盘点宿主机时区/locale、Claude Desktop（含 MSIX）/ CLI 足迹及代理环境变量存在性（不输出任何路径或密钥）；[Inspect-WindowsFirewall.ps1](Inspect-WindowsFirewall.ps1) 新增 `EnabledOutboundAllowBreakdown` 与 `LanDnsPort53OutboundBlockCount` 只读计数。
5. **完整整合 23 份研究报告原件与综合分析**：保留 [research-reports/克劳德封号机制与逆向报告完整汇编-含微信原件-2026-11-22/](research-reports/克劳德封号机制与逆向报告完整汇编-含微信原件-2026-11-22/README.md) 全部 23 份文件（离线 HTML + Markdown 综合报告 + 2 份微信 Windows Desktop 静态逆向原件 + 18 份 GitHub 公开研究源码/报告），并新增 [CLAUDE-PROXY-OPTIMIZATION-GUIDE.md](CLAUDE-PROXY-OPTIMIZATION-GUIDE.md) 明确「网络优化能解决 vs 不能解决」的边界。

## 沿用的 v0.3.4 安全修复重点

1. **修复 iOS Shadowrocket 原生 IPv6 绕过泄漏**：`mobile/shadowrocket-local-proxy.conf` 改为开启 `ipv6 = true` 与 `hijack-dns = *:53` 接管 4G/5G 及双栈 Wi-Fi 的 IPv6 路由与明文 DNS，并在隧道内通过 `IP-CIDR6,::/0,REJECT,no-resolve` 兜底阻断直接公网 IPv6 连接。
2. **修复 `Test-ProxyState.ps1` 主动裸连风险**：探测前先在本地检查是否存在活动的 TUN/隧道默认路由；若仅开启了系统代理（HTTP/SOCKS）而未开启 TUN，默认拒绝发送 `--noproxy "*"` 请求，避免直接暴露真实公网 IP。
3. **修复 Windows 断网开关（Kill Switch）提权攻击面与多网卡/协议漏拦**：`Manage-WindowsKillSwitch.ps1` 改为纯原生 PowerShell 计算规则（不再在管理员权限下调用外部 `py.exe`），运行前校验脚本目录未被共享普通用户组赋予写权限；默认要求覆盖所有活动物理网卡（支持 `-IncludeAllPhysicalAdapters`），并对例外地址补齐 ICMPv4、IGMP、IP-in-IP、IPv6-in-IPv4（41）、GRE（47）、ESP（50）、AH（51）及 SCTP（132）阻断规则；安装日志自动设为私有 NTFS 权限并脱敏隐藏真实节点 IP。
4. **加固备份权限、内联密钥拦截与恢复脚本校验**：Windows 下创建的快照与恢复目录自动移除继承权限、仅允许当前用户访问；`claude_local_data.py` 默认拦截 `.mcp.json` / `settings*.json` 中的明文 API Key/Token、排除私钥后缀文件并拒绝硬链接；`config_snapshot.py` 的 `verify` 同步校验快照内嵌 `restore.py` 与 `config_snapshot.py` 完整性并防止额外文件注入。
5. **加固直连名单更新器**：`refresh_allowlists.py` 禁止跨源或 HTTP 降级重定向，支持 `--commit` 与 `--expected-*-sha256` 固定版本校验，并拦截符号链接与 UNC 网络共享路径。

---

| 平台 | 从这里开始 |
| --- | --- |
| Windows | `py -3 .\environment_report.py` 与 `py -3 .\audit_client_boundary.py` 生成只读脱敏报告。 |
| macOS | `python3 environment_report.py` 与 `python3 audit_client_boundary.py` 汇总路由、DNS、边界和 Claude 文件概要。 |
| Linux | `python3 environment_report.py` 与 `python3 audit_client_boundary.py` 汇总路由、DNS、边界和 Claude 文件概要。 |
| Edge / Chrome | 代理客户端开启 TUN 或系统代理即可适配；Edge 需按 [PRIVACY-CHECKLIST.md（Edge 专用配置清单）](PRIVACY-CHECKLIST.md#microsoft-edge-浏览器专用配置清单) 关闭内置安全 DNS 与 Edge 安全网络并使用独立 Profile。 |
| Android | [mobile/README.md](mobile/README.md) 扫码或剪贴板导入 `v2rayNG` Claude 生态规则、配置 DoH 并核查防漏开关与原生 App 边界。 |
| iPhone／iPad | [mobile/README.md](mobile/README.md) 导入已开启 IPv6 隧道接管的 Shadowrocket 模板并验收。 |
| 深度资料 | [CLAUDE-PROXY-OPTIMIZATION-GUIDE.md](CLAUDE-PROXY-OPTIMIZATION-GUIDE.md) 与 [离线综合报告 HTML](research-reports/克劳德封号机制与逆向报告完整汇编-含微信原件-2026-11-22/00-克劳德封号机制与逆向研究完整综合报告.html)。 |

> **克隆后开箱说明**：所有 Python 脚本仅使用 Python 3.10+ 标准库（无需 `pip install`）。本仓库不包含代理软件本体与节点，下载后需自行准备代理客户端（如 Windows `v2rayN` / Android `v2rayNG` / iOS `Shadowrocket`）及合规节点，并按需导入本仓库规则文件与核对 [PRIVACY-CHECKLIST.md](PRIVACY-CHECKLIST.md)。

### Claude Code 文件保护

```powershell
py -3 .\claude_local_data.py audit
py -3 .\claude_local_data.py backup --destination "C:\Users\<你的用户名>\claude-backups"
py -3 .\claude_local_data.py verify "生成的快照目录"
py -3 .\claude_local_data.py recover "生成的快照目录" --destination "C:\Users\<你的用户名>\claude-recovered"
```

- 备份为明文快照，Windows 版会自动将快照目录设为当前账户私有 NTFS 权限（禁用继承），但仍建议存放在启用了 BitLocker/FileVault 的个人主目录下，避开云盘同步目录。
- 若 `.mcp.json`、`settings.json` 或 `settings.local.json` 中写有明文 API Key 或 Token，备份会默认中止提示；请改用系统环境变量或钥匙串管理密钥（确需连同密钥备份时才显式附加 `--allow-inline-secrets`）。

## Windows v2rayN 工具

### 1. 只读体检

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Inspect-WindowsProxy.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Inspect-WindowsFirewall.ps1
py -3 .\audit_client_boundary.py
```

体检输出已对个人子目录、自定义网卡名及启动项名称做脱敏遮盖。

### 2. 路由规则生成与校验

```powershell
py -3 .\build_routing.py validate .\routing-template.json
py -3 .\build_routing.py validate .\routing-claude-ecosystem.json --claude-ecosystem
py -3 .\build_routing.py validate .\routing-claude-global.json --global-proxy --claude-ecosystem
py -3 .\build_routing.py generate .\routing-global.json --global-proxy
py -3 .\build_routing.py print-doh-domains
```

- 若同时启用 [Windows 断网保护](WINDOWS-KILL-SWITCH.md)，或访问对 IP 一致性敏感的服务，请使用 `--global-proxy`（推荐叠加 `--claude-ecosystem`，直接使用随包 [routing-claude-global.json](routing-claude-global.json)），并将客户端路由 `domainStrategy` 设为 `AsIs`（同时将 [claude-doh-domains.txt](claude-doh-domains.txt) 绑定到远端加密 DNS），避免触发本地运营商 DNS 解析。
- 若保留国内直连分流，推荐导入 [routing-claude-ecosystem.json](routing-claude-ecosystem.json) 并配套启用 [Manage-WindowsLanDnsGuard.ps1](Manage-WindowsLanDnsGuard.ps1) 封堵物理网卡路由器 53 端口旁路查询。
- 使用 `refresh_allowlists.py` 更新直连名单时，建议指定已审阅的 `--commit <40位SHA>` 及 `--expected-direct-sha256` / `--expected-cidr-sha256`，不要无人值守盲目导入可变分支规则。

### 2.5 物理网卡防路由器 DNS 旁路（适用于保留分流的 Windows）

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Manage-WindowsLanDnsGuard.ps1 -Action Preview -IncludeAllPhysicalAdapters
# 管理员 PowerShell 执行安装与状态检查：
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Manage-WindowsLanDnsGuard.ps1 -Action Install -IncludeAllPhysicalAdapters
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Manage-WindowsLanDnsGuard.ps1 -Action Status -IncludeAllPhysicalAdapters
# 随时精准卸载：
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Manage-WindowsLanDnsGuard.ps1 -Action Remove
```

### 3. 配置目录备份与还原

```powershell
py -3 .\config_snapshot.py backup --config-dir "C:\实际路径\guiConfigs"
py -3 .\config_snapshot.py verify "C:\Users\<你的用户名>\clash-guard-backup\实际备份名"
py -3 .\config_snapshot.py restore "C:\Users\<你的用户名>\clash-guard-backup\实际备份名" --config-dir "C:\实际路径\guiConfigs"
```

快照包含节点订阅与口令，请仅保存在本机加密盘私人目录，切勿外传。

### 4. 用普通用户记录网络状态

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Test-ProxyState.ps1 -Stage normal -AsJson
```

该脚本禁用 `curl` 应用层代理以验证系统 TUN 路由。若本机未检测到活动 TUN 隧道路由（例如只开了系统 HTTP/SOCKS 代理），`-Stage normal` 会默认拒绝发包，防止误用真实 IP 直连测试站点。

## 离线自检

```powershell
py -3 -m unittest -v
```
