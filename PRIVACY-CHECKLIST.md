# 浏览器、邮箱和 Claude 账号隐私检查

这份清单适用于日常使用自己的设备和账号。操作应通过当前客户端界面或官方支持渠道完成。

| 检查项 | 怎么核对 | 结果的范围 |
| --- | --- | --- |
| 网页定位 | 在 Chrome 或 Edge 的站点资料里检查「位置」，平时按需求选询问或阻止 | 控制浏览器定位权限。服务仍可能将连接 IP 用于粗略的地区判断。[Chrome 站点权限](https://support.google.com/chrome/answer/114662) · [Claude 位置说明](https://privacy.claude.com/en/articles/11186740-does-claude-use-my-location) |
| 网页访问局域网和本机服务 | 查看站点的本地网络和本机设备访问权限。对不需要访问打印机、路由器或开发服务的网站可以关掉 | 适用于浏览器内的本地连接。原生应用的网卡枚举由操作系统治理。[Chrome 本地网络访问](https://developer.chrome.com/docs/modern-web-guidance/guides/security/local-network-access) |
| 浏览器数据同步 | 检查浏览器或配置文件的同步开关、同步项目和可访问该配置的人 | 以实际设置为准。部分浏览器的团队同步会将选定数据存到云端。[AdsPower 数据同步](https://help.adspower.com/docs/global_settings) |
| 邮件远程图片 | 核对邮件客户端的加载与跟踪保护选项 | 邮件远程资源和点击登录链接是不同的连接。[Proton 跟踪保护](https://proton.me/support/email-tracker-protection) |
| 路由器 DNS 旁路防护 | Windows 分流模式运行 `Manage-WindowsLanDnsGuard.ps1 -Action Status -IncludeAllPhysicalAdapters` 确认物理网卡端口 53 阻断规则生效 | 防止程序绕过系统 DNS 直查路由器 53 端口；不影响路由器后台管理、DHCP、局域网共享与 TUN 网卡 |
| 宿主机与隔离浏览器边界 | 运行 `py -3 .\audit_client_boundary.py` 核对宿主机时区/语言及本地 Claude Desktop/CLI 足迹 | 宿主机原生客户端直接读取系统时区与语言，且桌面端未登录即会发起冷启动外联；不要与独立隔离浏览器环境混用 |
| 移动端原生 App 限制 | 核对 [mobile/README.md](mobile/README.md) 中的 Android 与 iOS 架构差异 | 代理/VPN 仅管网络层；Android 原生 App 可在应用层直接读取设备标识与物理网卡 IPv6，高敏感场景建议固定在电脑端隔离浏览器 |
| 防火墙第三方放行复核 | 运行 `Inspect-WindowsFirewall.ps1` 查看 `EnabledOutboundAllowBreakdown` 并在本机复核第三方软件直连规则 | 确认无闲置远程控制或第三方客户端长期持有全地址出站放行规则 |
| 模型改进隐私选项 | 按实际偏好从账户隐私界面查看或调整 | Anthropic 说明关闭模型训练选项后，新的聊天和编码会话不会用于后续训练。[模型改进选项](https://privacy.claude.com/en/articles/12109829-how-do-i-change-my-model-improvement-privacy-settings) |
| 登录状态和错误 | 用已安装的官方客户端查看状态。CLI 可运行 `claude auth status --text`，对外汇报只记录是否登录和错误类别 | 不转发邮箱、令牌、验证码或完整配置。[CLI 参考](https://code.claude.com/docs/en/cli-reference) |
| 官方申诉或退款 | 分别使用 Anthropic 申诉、Apple 或购买渠道的退款页面，说明真实情况 | 账号处置与付款渠道分别调查，需等待正式回复。[Claude 申诉](https://support.claude.com/en/articles/8241253-safeguards-warnings-and-appeals) · [Apple 退款](https://support.apple.com/en-us/118223) |

本地网络诊断可验证指定连接和特定故障条件。是否符合 Anthropic 的服务范围按官方地区政策判断，包含用户实际所在地。没有公开依据表明指纹测试评分能预测账号处置。包里的脚本不要求你提供账号凭据。[Anthropic 地区政策](https://www.anthropic.com/legal/supported-regions)

更多基于逆向研究报告的代理层优化与边界说明，见 [CLAUDE-PROXY-OPTIMIZATION-GUIDE.md](CLAUDE-PROXY-OPTIMIZATION-GUIDE.md)。
