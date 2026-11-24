# 手机端网络隐私验收

在自己的手机和有权使用的网络上验收。用同一组普通测试网址，在 Wi-Fi 与蜂窝网络下分别记录结果。保留测试时间、连接状态和是否收到响应即可。出口地址如果需要核对，留在本机记录。

## Android

v2rayNG 是使用 Android VPN 接口的客户端之一。优先沿用自己已验证的连接配置，先确认手机状态栏和系统 VPN 设置都显示连接。若系统里未出现该 VPN，检查客户端是否以 VPN 模式启动。桌面端 v2rayN 的规则文件与备份请在各自客户端的支持范围内使用。[v2rayNG 项目](https://github.com/2dust/v2rayNG)

### 随包 Claude 生态规则包（13 条，已通过 Xray 离线校验）

本目录提供 `android-v2rayng-claude-routing.json`（剪贴板直导单行版）、`android-v2rayng-claude-routing.pretty.json`（可读版）与扫码直导二维码 `android-v2rayng-claude-routing-qr.png`：
- 置顶阻断 `udp/443`（QUIC）及 Anthropic IPv6 前缀 `2607:6bc0::/48`、`2607:6bc0:11::/48`（防单 IPv4 出口 502）；
- 置顶代理 23 个核心与外围生态域名（已修正 `claudemcpcontent.com` 拼写）及 Anthropic 官方 IPv4 网段 `160.79.104.0/21`；
- 合并 `100.64.0.0/10` 至局域网直连规则，未命中的其余公网流量默认走代理。

导入与补强步骤：
1. 打开 `v2rayNG` → 路由设置 → 右上角「从 QRcode 导入规则集」扫描 `android-v2rayng-claude-routing-qr.png`（或复制 `android-v2rayng-claude-routing.json` 选择「从剪贴板导入」）；
2. **导入后手动断开并重新连接 VPN**，确保 Xray 核心加载新规则；
3. 将 `v2rayNG` 远程 DNS 升级为加密 DoH（例如 `https://cloudflare-dns.com/dns-query`），避免明文 DNS 解析；
4. 在桌面可随时离线校验随包规则：
   ```text
   python3 mobile/validate_android_v2rayng.py mobile/android-v2rayng-claude-routing.json
   ```

### Android 系统防漏开关与架构边界提醒

1. 打开系统设置，搜索「VPN」，点已连接应用旁的设置图标。菜单位置、名称和能使用的开关以机型、系统、VPN 应用和工作资料策略为准。[Android 帮助](https://support.google.com/android/answer/9089766)
2. 如有「始终开启 VPN」，先开启并确认正常连接。如还提供「阻止不使用 VPN 的连接」，先记下原值，再开启并测试。被排除的应用在此模式下可能失去网络。某些应用会明确退出对始终开启的支持。[Android VPN 官方文档](https://developer.android.com/develop/connectivity/vpn)
3. 保持 VPN 开启，用一个已知无法建立代理连接的自有测试节点观察故障行为，再恢复原节点。单独检查隧道实际断开时的结果。如果系统一直自动重连，记录「未观察到隧道断开」。各状态按下方表格记录。
4. 恢复时回到同一 VPN 设置页，把刚才改过的开关恢复成原值，再恢复原节点。若原本使用工作资料 VPN，请由管理者核对策略。

> **重要架构边界（Android vs iOS）**：根据随包研究资料（`research-reports/.../sources/01-三端源码级遥测审计-B1anYu/android.md` 与 `02-Web与Android及Persona-KYC动态审计-ImNotDragon`），Android 原生客户端可在应用层直接读取不可重置的 `ANDROID_ID`、通过 `NetworkInterface` 枚举物理网卡上的公网 IPv6 地址（即使 VPN 已连接），以及读取 SIM 卡 MCC/MNC 与 Play Integrity 状态。**任何 VPN 或代理客户端都只能控制网络层路由与 DNS，无法拦截应用层本地系统 API 读取。** 因此，高敏感账户操作仍建议固定在电脑端隔离浏览器环境中进行，不要依赖 Android 原生客户端。

## iPhone 和 iPad

`shadowrocket-local-proxy.conf` 是修复了原生 IPv6 绕过问题的通用分流模板：
- 在 `[General]` 中启用 **`ipv6 = true`** 与 **`hijack-dns = *:53`**，强制虚拟网卡（`utun`）接管手机 4G/5G 蜂窝网络与双栈 Wi-Fi 的 IPv6 路由及 53 端口明文 DNS，防止 iOS 因 `ipv6 = false` 将原生 IPv6 流量直接从物理网卡裸连发出。
- 将回环、`.local` 及私有/链路本地 IPv4 与 IPv6 网段设为直连，在 `FINAL,PROXY` 之前通过 `IP-CIDR6,::/0,REJECT,no-resolve` 在隧道内阻断直接公网 IPv6 连接（域名访问仍经 `FINAL,PROXY` 转发，兼容仅支持 IPv4 出站的节点；若节点已验证支持 IPv6 出站，可按需改为 `PROXY`）。

1. 在 Shadowrocket 里记下当前配置文件、全局路由模式和所选节点，保留原配置作为回滚选项。
2. 导入 `shadowrocket-local-proxy.conf`（建议通过本地 AirDrop 或「文件」App 本机存储导入，避免将含自定义节点的配置长期留在云盘）。在界面里选中并启用导入的配置，将「全局路由」设为「配置」，再选择自己有权使用的已验证节点，并在设置中配置受信任的加密 DNS（DoH/DoT）。[Shadowrocket App Store 页面](https://apps.apple.com/us/app/shadowrocket/id932747118)
3. 分别在 Wi-Fi 与 4G/5G 蜂窝网络下验证局域网、IPv4 与 IPv6 表现。先用自己的局域网测试地址看能否连通并查看客户端规则记录，再用测试站点核对公网请求是否全部进入代理且无真实运营商 IPv6 泄漏。
4. 将「代理节点故障，隧道仍开」和「隧道已关」当成两次独立实验。非设备监督管理（MDM）下的普通 iOS VPN 断开后系统不会自动断网，只有监督模式下的 Apple IKEv2「始终开启 VPN」支持系统级强制阻断。[Apple IKEv2 部署设置](https://support.apple.com/guide/deployment/ikev2-settings-dep4ce9487d/web)
5. 回滚时重新选择原有配置、路由模式和节点，再验证正常连通性。

可在桌面离线检查随包模板：

```text
python3 mobile/validate_shadowrocket.py mobile/shadowrocket-local-proxy.conf
```

校验要求开启 `ipv6 = true` 与 `hijack-dns = *:53`（拒绝会导致原生 IPv6 绕过隧道的 `ipv6 = false`），核对全部 11 条本地 IPv4/IPv6 直连例外、公网 IPv6 兜底处置以及末条 `FINAL,PROXY` 规则。

## 实机记录表

| 状态 | 在 Wi-Fi 上记录 | 在蜂窝网络（4G/5G）上记录 |
| --- | --- | --- |
| 原配置或回滚后 | 公共测试地址是否有响应 | 公共测试地址是否有响应 |
| VPN 正常，节点可用 | 公共请求结果、IPv4/IPv6 是否均未漏真机 IP | 公共请求结果、IPv4/IPv6 是否均未漏真机 IP |
| VPN 仍在，节点故障 | 公共请求是否失败和实际系统状态 | 公共请求是否失败和实际系统状态 |
| VPN 确实断开 | 公共请求是否失败和实际系统状态 | 公共请求是否失败和实际系统状态 |
| VPN 正常，使用自有局域网地址 | 能否连通及直连规则命中 | 有可用的自有局域网目标时再测 |

若预期断网时仍收到公共站点响应，该次测试失败。公共请求失败可能另由 DNS、超时或站点故障造成，可用恢复后的正常基线和客户端记录进一步核对。
