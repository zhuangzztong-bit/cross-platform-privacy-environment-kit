# 克劳德封号机制与逆向报告完整汇编-含微信原件-2026-11-22

本压缩包汇总了截至 **2026-11-22** GitHub 上与 **Claude（Web / Android / Desktop / Claude Code CLI）封号机制、遥测指纹、协议校验及 Persona KYC 风控** 相关的 2 份本地微信 Windows Desktop 逆向原件 + 18 份 GitHub 核心公开逆向与审计文档（共 20 份参考原文），并附带一份结构化综合研究报告（提供 Markdown 与离线 HTML 双版本）。

## 快速阅读建议

1. **优先阅读主报告**：
   - 浏览器直接双击打开：`00-克劳德封号机制与逆向研究完整综合报告.html`（内置完整排版与目录，无需联网）
   - Markdown 原稿：`00-克劳德封号机制与逆向研究完整综合报告.md`
2. **按需查阅 `sources/` 原始一手报告**：所有原文均按证据等级与主题分目录归档，保留完整技术细节与复验锚点。

## 文件清单与来源索引

| 压缩包内路径 | 证据等级 | 说明 | 原始 GitHub 链接 |
|---|---|---|---|
| `00-克劳德封号机制与逆向研究完整综合报告.md` | 综合汇编 | 主研究报告（Markdown 版，含微信两份原件交叉对照） | 本次调研整理 |
| `00-克劳德封号机制与逆向研究完整综合报告.html` | 综合汇编 | 主研究报告（离线 HTML 阅读版） | 本次调研整理 |
| `sources/00-微信原件-Windows-Desktop逆向/逆向国外 AI Cloud · 上篇 结构与组件.md` | 本地原件（静态逆向） | Windows MSIX Claude Desktop `5.11492.5` 结构、Fuse、IPC 与企业策略审计 | 微信本地文件（原名：`逆向国外 AI Cloud · 上篇 结构与组件.md`） |
| `sources/00-微信原件-Windows-Desktop逆向/逆向国外 AI Cloud · 下篇 机制与操作.md` | 本地原件（静态+1项动态） | Windows MSIX 凭据链、未登录探活、`enumerateDevices` 桩化、Cowork 沙箱与边界自评 | 微信本地文件（原名：`72f67a7aa834c192c9dc1d5ee3ec4f47_1894981169724768006_m.md`） |
| `sources/01-三端源码级遥测审计-B1anYu/README.md` | S 级（源码+动态抓包） | B1anYu/claude-telemetry-audit — 三端遥测与隐私审计总报告 | https://github.com/B1anYu/claude-telemetry-audit/blob/main/README.md |
| `sources/01-三端源码级遥测审计-B1anYu/desktop.md` | S 级（源码实证） | B1anYu/claude-telemetry-audit — Claude Desktop 2.9939.2 遥测与身份审计 | https://github.com/B1anYu/claude-telemetry-audit/blob/main/telemetry/desktop.md |
| `sources/01-三端源码级遥测审计-B1anYu/cli.md` | S 级（源码实证） | B1anYu/claude-telemetry-audit — Claude Code CLI 2.1.283 遥测与上行审计 | https://github.com/B1anYu/claude-telemetry-audit/blob/main/telemetry/cli.md |
| `sources/01-三端源码级遥测审计-B1anYu/android.md` | S 级（源码+AVD动态实测） | B1anYu/claude-telemetry-audit — Claude Android 1.260930.20 逆向审计 | https://github.com/B1anYu/claude-telemetry-audit/blob/main/telemetry/android.md |
| `sources/01-三端源码级遥测审计-B1anYu/linked.md` | S 级（源码实证） | B1anYu/claude-telemetry-audit — Desktop 与 CLI 跨端关联分析 | https://github.com/B1anYu/claude-telemetry-audit/blob/main/telemetry/linked.md |
| `sources/02-Web与Android及Persona-KYC动态审计-ImNotDragon/CLAUDE_AND_KYC_RISK_AUDIT_REPORT.md` | S 级（DEX+CDP动态抓包） | benbaobaoshigemi/ImNotDragon — Web/Android/Persona 3D KYC 全景审计 | https://github.com/benbaobaoshigemi/ImNotDragon/blob/2ef76bd69117e23929e326d7b90825b6018f491b/CLAUDE_AND_KYC_RISK_AUDIT_REPORT.md |
| `sources/03-ClaudeCode协议签名与隐写逆向/CCH.md` | A 级（ptrace+反汇编） | BYK/loreai — Claude Code cch 请求完整性哈希逆向实录 | https://github.com/BYK/loreai/blob/29a992a010c92f23c9d3c1f70419e59b27a81743/quality/CCH.md |
| `sources/03-ClaudeCode协议签名与隐写逆向/claude-code-2.1.280-cloaking-audit.md` | A 级（二进制源码审计） | pwguler/pengepul — Claude Code 2.1.280 请求头/Beta/归因块审计 | https://github.com/pwguler/pengepul/blob/02ee7c2790c7c0e8d5717b48579efb75fc88037e/docs/research/claude-code-2.1.280-cloaking-audit.md |
| `sources/03-ClaudeCode协议签名与隐写逆向/research-claude-code-behavior.md` | A 级（逆向+协议对照） | 6Kmfi6HP/opencode2api — Claude Code API 行为与版本漂移研究 | https://github.com/6Kmfi6HP/opencode2api/blob/7a52cf223e7c1a714f6ce0804e0154c40ca2e3d0/docs/research-claude-code-behavior.md |
| `sources/03-ClaudeCode协议签名与隐写逆向/claude-code-steganography.md` | A 级（混淆源码还原） | itwanger/toBeBetterJavaer — Claude Code 3-bit Unicode 隐写术拆解 | https://github.com/itwanger/toBeBetterJavaer/blob/2103ede962c83b8e9133fe4a6eb6707c18dea40a/docs/src/sidebar/itwanger/ai/claude-code-steganography.md |
| `sources/04-硬件锚定与本地状态边界/780-device-registry.md` | B 级（原生绑定逆向） | aaddrick/claude-desktop-debian — Desktop DeviceRegistry 硬件密钥逆向 | https://github.com/aaddrick/claude-desktop-debian/blob/62baae62d49739237c0d9dd458c08ab5a792f39a/docs/upstream-reports/780-device-registry.md |
| `sources/04-硬件锚定与本地状态边界/claude-local-reset-research.md` | B 级（证据边界核查） | ttfake92-lab/skills — 本地残留清理与设备关联证据边界研究 | https://github.com/ttfake92-lab/skills/blob/a146797c01ebfd48c12e4860416b99b6acdaf070/skills/claude-local-reset/references/research.md |
| `sources/05-封号审查汇总与关联域名清单/Claude_Max20x_封号审查因素报告.md` | C 级（官方口径+多源汇总） | aceaura/blog — Claude Max 20x 封号审查因素与申诉数据汇总 | https://github.com/aceaura/blog/blob/c469e45769060f4c4d2e0a9aba92e557ad48d621/Claude_Max20x_封号审查因素报告.md |
| `sources/05-封号审查汇总与关联域名清单/one-exit-claude-rea-routing-telemetry-report.md` | C 级（第三方核查记录） | songshikang0111/awesome-REA-cases — one-exit 与多端遥测模板复核 | https://github.com/songshikang0111/awesome-REA-cases/blob/44eb41e03cb99391130a766971f47a8846a72d2a/cases/one-exit-claude-rea-routing-telemetry-report.md |
| `sources/05-封号审查汇总与关联域名清单/one-exit-README.md` | C 级（关联域名与网络结构） | wquguru/one-exit — 多端关联域名与网络出口一致性说明 | https://github.com/wquguru/one-exit/blob/a34803405f7b4ddabc48081ed83929376e3c6a9d/README.md |
| `sources/05-封号审查汇总与关联域名清单/one-exit-override.yaml` | C 级（域名/IP段参考清单） | wquguru/one-exit — Claude 及遥测/风控/支付/KYC 域名清单 | https://github.com/wquguru/one-exit/blob/main/clash-party/override.yaml |
| `sources/05-封号审查汇总与关联域名清单/claude-ban-strategy.md` | C 级（社区综合分析） | wang-fu/blog — Claude 封号策略与后端四层模型推演 | https://github.com/wang-fu/blog/blob/4414eebac937274329e5a5c7a46424470e331d2e/docs/blog/ai/claude-ban-strategy.md |
| `sources/05-封号审查汇总与关联域名清单/FuckClaude-claude-steganography-and-risk-model.ts` | C 级（社区检测工具文案） | LinXiaoTao/FuckClaude — fuck-claude.vercel.app 风险说明源码 | https://github.com/LinXiaoTao/FuckClaude/blob/082260335ff6cf1d22a5843368cc3689e9a574c9/src/content/guides/claude-steganography-and-risk-model.ts |

## 版权与使用说明

- `sources/` 下的全部文件均为对应 GitHub 公开仓库的原文镜像归档，版权与许可证（如 CC BY 4.0 / MIT 等）归各原作者所有。
- 本资料包仅作隐私审计、安全研究与技术交流参考，不包含任何专有闭源程序或绕过工具。
