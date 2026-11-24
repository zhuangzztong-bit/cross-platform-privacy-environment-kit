# Claude 生态代理环境优化与逆向研究对照指南

本指南将随包附带的完整逆向研究资料 [research-reports/克劳德封号机制与逆向报告完整汇编-含微信原件-2026-11-22/](research-reports/克劳德封号机制与逆向报告完整汇编-含微信原件-2026-11-22/README.md) 中的网络与客户端观察，逐一映射为 `v0.3.5` 工具包中可落地、可校验、可回滚的防护配置。

> 阅读入口：离线综合报告见 [00-克劳德封号机制与逆向研究完整综合报告.html](research-reports/克劳德封号机制与逆向报告完整汇编-含微信原件-2026-11-22/00-克劳德封号机制与逆向研究完整综合报告.html)（Markdown 原稿：[00-克劳德封号机制与逆向研究完整综合报告.md](research-reports/克劳德封号机制与逆向报告完整汇编-含微信原件-2026-11-22/00-克劳德封号机制与逆向研究完整综合报告.md)）。

## 一、核心发现到工具包能力的逐项映射

| 研究报告观察点 | 潜在风险 | 工具包 v0.3.5 落地工具与规则 |
| --- | --- | --- |
| **核心与外围生态分裂出口**<br>遥测、风控、验证、支付、客服与核验流量跨越 23 个域名与官方 IPv4 网段 `160.79.104.0/21`（AS399358），而非仅 `claude.ai` | 仅将主域名走代理时，Sentry / Datadog / Sift / Segment / GrowthBook / Stripe / hCaptcha / Persona 等请求可能走直连或境内 DNS，形成双出口分裂 | 使用 [routing-claude-ecosystem.json](routing-claude-ecosystem.json)（分流模式）或 [routing-claude-global.json](routing-claude-global.json)（全局模式，配断网开关）；也可用 `build_routing.py generate ... --claude-ecosystem` 生成并校验；远程 DoH 域名清单见 [claude-doh-domains.txt](claude-doh-domains.txt) |
| **Anthropic IPv6 引发 502**<br>`2607:6bc0::/48`、`2607:6bc0:11::/48` 在单 IPv4 出口节点上高频返回 502；UDP/443（QUIC）易出现非预期传输路径 | 会话频繁中断、重试或触发异常连接模式 | 上述两套路由模板均置顶阻断 `udp/443` 及 `2607:6bc0::/48`、`2607:6bc0:11::/48` |
| **更换路由器/热点后的物理网卡 DNS 旁路**<br>固定写死旧网关 IP 的规则在切换路由器后失效，绕过系统 DNS 直连局域网 53 端口的程序会泄露域名解析 | 分流模式下仍存在物理网卡明文 DNS 查询旁路风险 | 使用原生 PowerShell 脚本 [Manage-WindowsLanDnsGuard.ps1](Manage-WindowsLanDnsGuard.ps1)（支持 `Preview`/`Install`/`Status`/`Remove`），在所有物理网卡上封堵去往 `10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`、`100.64.0.0/10`、`fc00::/7`、`fe80::/10` 的 TCP/UDP 53，不影响路由后台、DHCP 与 TUN 网卡 |
| **宿主机 vs 隔离浏览器边界**<br>Windows/macOS 宿主机时区、语言与本地 Claude Desktop / CLI（含内置 `claude.exe`、`~/.claude`、MSIX 包、冷启动 3 次外联、CLI `metadata.user_id` 与 `ANTHROPIC_BASE_URL` 上报）独立于浏览器配置 | 宿主机原生客户端与隔离浏览器环境混用，引入不一致的时区/locale 或后台外联信号 | 运行只读脱敏脚本 `py -3 .\audit_client_boundary.py` 核查本机时区、语言与原生客户端数据足迹；坚持宿主机客户端与隔离 Web 浏览器严格分离 |
| **Android 端规则修正与原生 App 边界**<br>旧规则常将 `claudemcpcontent.com` 误拼为 `claudemcpclient.com`；更重要的是 Android 原生 App 可在应用层直接读取 `ANDROID_ID`、经 `NetworkInterface` 枚举物理网卡公网 IPv6、读取 SIM MCC/MNC 与 Play Integrity | 代理/VPN 只能保障网络层路由与 DNS，无法拦截 Android 应用层的本地硬件/接口枚举 | 手机端 `v2rayNG` 导入 [mobile/android-v2rayng-claude-routing.json](mobile/android-v2rayng-claude-routing.json)（或扫 [mobile/android-v2rayng-claude-routing-qr.png](mobile/android-v2rayng-claude-routing-qr.png)），配合 `mobile/validate_android_v2rayng.py` 校验；并开启系统「始终开启 VPN」「阻止未使用 VPN 的连接」与 DoH；高敏感场景优先固定在电脑端隔离浏览器 |
| **邮件远程图片与防火墙第三方直连放行**<br>通知邮件中的远程 1x1 像素图片、以及宿主机防火墙上残留的第三方全地址直连放行规则 | 日常邮件客户端直连拉取追踪图片，或非预期软件绕过防火墙默认阻断 | 邮件客户端关闭「自动加载远程图片」；运行 `Inspect-WindowsFirewall.ps1` 核查 `EnabledOutboundAllowBreakdown` 与 `LanDnsPort53OutboundBlockCount`，按需在本地复核非系统第三方放行项 |

## 二、快速落地顺序（推荐）

1. **先只读体检**：
   ```powershell
   py -3 .\environment_report.py
   py -3 .\audit_client_boundary.py
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Inspect-WindowsFirewall.ps1
   ```
2. **桌面端备份并升级路由与远端加密 DNS**：
   - 先用 `config_snapshot.py backup` 备份现有配置目录；
   - 分流用户导入 [routing-claude-ecosystem.json](routing-claude-ecosystem.json)；启用全局断网开关的用户导入 [routing-claude-global.json](routing-claude-global.json)；
   - 在代理客户端中将 [claude-doh-domains.txt](claude-doh-domains.txt) 内的 23 项域名绑定至远端加密 DoH（如 `https://cloudflare-dns.com/dns-query`），确保优先级高于境内 DNS；路由 `domainStrategy` 保持 `AsIs` 或确保解析仅走远端 DoH。
3. **Windows 物理网卡防 DNS 旁路（分流模式必选；全局模式用 Kill Switch）**：
   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Manage-WindowsLanDnsGuard.ps1 -Action Preview -IncludeAllPhysicalAdapters
   # 管理员 PowerShell 安装（自动先备份 .wfw 并校验 SHA-256）：
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Manage-WindowsLanDnsGuard.ps1 -Action Install -IncludeAllPhysicalAdapters
   ```
4. **移动端同步升级**：
   - **iOS**：按 [mobile/README.md](mobile/README.md) 导入 [mobile/shadowrocket-local-proxy.conf](mobile/shadowrocket-local-proxy.conf)（已开启 `ipv6 = true`、`hijack-dns = *:53`、`IP-CIDR6,::/0,REJECT,no-resolve` 与 `FINAL,PROXY`）；
   - **Android**：按 [mobile/README.md](mobile/README.md) 扫码或剪贴板导入 `v2rayNG` 新版 13 条规则、重连 VPN、配置 DoH 并开启系统防漏开关。
5. **定期做一次受控断线演练**：参考 [WINDOWS-KILL-SWITCH.md](WINDOWS-KILL-SWITCH.md) 使用 `Test-ProxyState.ps1` 核验隧道断开后不会裸连回落。

## 三、清晰边界：网络与环境优化「能解决」vs「不能解决」

| 维度 | 网络与本机环境优化 **能解决** | 网络与本机环境优化 **不能解决** |
| --- | --- | --- |
| **出口与路由** | 消除核心与 23 个外围域名的分裂出口；避免 Anthropic IPv6 引起的 502；统一 DNS 解析路径 | 无法保证第三方共享代理 IP 声誉、历史滥用记录或平台地理合规政策 |
| **防泄漏保护** | 阻断物理网卡路由器 DNS 53 旁路、原生 IPv6 绕过、TUN 断线裸连与 QUIC 绕行 | 无法拦截 Android 等原生 App 通过系统本地 API 读取设备标识、物理网卡列表、SIM 或完整性 attestation |
| **客户端与账户合规** | 帮助盘点本机客户端足迹、提醒隔离宿主机与独立浏览器配置、安全备份工作区并防止内联密钥外泄 | 无法替代官方客户端协议完整性要求、付款方式/账单归属审查、使用政策（AUP）/服务条款（ToS）及官方地区政策要求 |
