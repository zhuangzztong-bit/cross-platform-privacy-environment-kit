# 逆向国外 AI Cloud

**下篇 · 机制与操作**（静态还原为主，动态验证 1 项；每条结论标注硬度）

---

## 目录

1. 凭据与密钥链
2. 认证与登录流
3. 调试入口：`--load-preview-url`
4. 本地 Agent 运行时
5. MCP 与连接器
6. Cowork 沙箱与微虚拟机
7. Computer Use
8. Electron 加固与 patch
9. 动态调试矩阵
10. 暴露面与设计边界
11. 四轮复盘账本
12. 未决项
13. 附录：偏移、脚本、证据

---

## 1. 凭据与密钥链

### 1.1 三层结构

```
应用层   keystore 抽象（available / encrypt / decrypt）
   ↓
框架层   Electron safeStorage
   ↓
系统层   Windows DPAPI（CurrentUser）  ← 主程序直接导入 CryptProtectData / CryptUnprotectData
```

`claude.exe` 导入表实测含 `CryptProtectData` / `CryptUnprotectData` / `CryptProtectMemory` / `CryptUnprotectMemory` → 主程序层就在用 DPAPI，不只是 Electron 包装。

### 1.2 自检逻辑

```js
available: () => safeStorage.isEncryptionAvailable()
// 启动时自检：加密随机串再解回，值变了就报 SafeStorageUnavailableError
```

### 1.3 落盘格式与键空间

统一：`base64( safeStorage.encryptString( JSON.stringify(payload) ) )`

| 键前缀 | 内容 |
|---|---|
| `msal-cache-v1:` | 微软账号缓存（`Account` / `IdToken` / `AccessToken` / `RefreshToken`） |
| `session-accounts-v1:<id>` | 会话账号 |
| `custom-3p:` / `custom3pAnthropic…` | 第三方 MCP 的 OAuth 令牌 / bootstrap token |

令牌对象：
```json
{ "access_token": "…", "refresh_token": "…", "expiresAt": 0,
  "scopeKey": "…", "hosted": true, "urlKey": "…" }
```
- `urlKey` 变化即视为另一份授权
- 解密失败有**非破坏性读取**路径（`nonDestructiveReads`），不会擦除已存凭据
- 存储自检用 `timingSafeEqual` 比较长度与内容

### 1.4 cookie 与跨 profile

```js
JSON.parse(localState).os_crypt.encrypted_key
  → base64 解码 → 前 5 字节 == "DPAPI" ? 取后续 : null
```
三态判定：`same_as_fresh` / `same_as_local_state` / `other`，用于多 profile 复用登录态。

**边界**：DPAPI 是 CurrentUser 作用域，同一 Windows 用户下任意进程都能解出这些载荷 —— 这是设计边界，不是缺陷。

---

## 2. 认证与登录流

### 2.1 三条 OAuth 线

| 线 | 端点 |
|---|---|
| 桌面回跳 | `https://claude.ai/desktop/callback`、`https://claude-ai.staging.ant.dev/desktop/callback` |
| 平台 | `platform.claude.com/oauth/{authorize,code/callback,code/success}` + `/v1/oauth/token` |
| 第三方 | `claude.com/cai/oauth/authorize`、`api.anthropic.com/api/oauth/claude_cli/{create_api_key,roles}` |

### 2.2 认证面深度（渲染层 841 条中的认证子集）

```
/api/auth/login_methods            登录方式枚举
/api/auth/send_magic_link          邮件魔法链
/api/auth/send_phone_code          短信验证码
/api/auth/mfa/challenge/{send,verify}
/api/auth/mfa/sms/enroll/{send,verify}
/api/auth/session_reattest/webauthn{,/challenge}    会话再验证
/api/auth/step_up/webauthn/credentials{,/challenge} 权限升级
/api/auth/trusted_devices
/api/auth/verify_{apple,google,google_mobile}
/api/auth/exchange_nonce_for_code
/api/auth/logout{,/all-sessions,/session}
```

### 2.3 主进程侧调用面

```
Auth_$_doAuthInBrowser(url)      在系统浏览器发起授权
Auth_$_prepareForSignedIn()      登录前置（清理/预热）
Account_$_activeAccountChanged / setAccountDetails
```

### 2.4 登录态与设备绑定

- `DeviceRegistry`（32 方法）：设备注册、会话调用面、注册结果
- `DeviceStorage`（13）/ `DeviceLink*`（Down / ErrorClass / Redial / Transport）：设备互联与重拨策略
- `GrandPrix`（10）：`pair` / `partnerId` / `submitVerificationCode` —— 配对 + 验证码

---

## 3. 调试入口：`--load-preview-url`

### 3.1 逻辑还原（实测）

```js
async function relaunchWithDevUrl(url, reason) {
  switch (gate) {
    case "touchID":       ok = await promptTouchID(reason);                              break;
    case "windows-hello": ok = await native.promptWindowsHello(`Claude will ${reason}.`); break;
    case "none":          return;
  }
  if (!ok) return;

  const payload = JSON.stringify({ url, ts: Date.now() });
  const blob    = safeStorage.encryptString(payload).toString("base64");
  app.relaunch({ args: [`--load-preview-url=${blob}`] });
  app.exit(0);
}
```

要点：
- 通行证是**操作系统生物识别**，不是签名、不是账号
- payload 只有 `{url, ts}`，无签名、无来源绑定
- URL 加密后进命令行，防明文窥探

### 3.2 前端 URL 决策

```js
function frontendUrl() {
  const base = "https://claude.ai";
  if (buildType === "dev") return process.env.CLAUDE_AI_URL || config.claudeAiUrl || base;
  if (globalThis.isDeveloperApprovedDevUrlOverrideEnabled && process.env.CLAUDE_AI_URL)
    return process.env.CLAUDE_AI_URL;
  return base;
}
```

**本包实测 `buildType: "prod"`** → dev 分支不成立；prod 下仅 `isDeveloperApprovedDevUrlOverrideEnabled` 为真时才认环境变量。

### 3.3 Developer 菜单（默认隐藏）

```
Load Remote Claude.ai  → relaunch(args: [])
Load Local  Claude.ai  → relaunchWithDevUrl("http://localhost:4000", "restart and load your local Claude.ai build")
Load Staging Claude.*  → preview 域
```

### 3.4 用法

```
1) 本地起前端：npx serve -l 4000 <WORK>\frontend
2) 让壳加载它：Developer 菜单「Load Local Claude.ai」，Windows Hello 确认一次
3) 判据：窗口加载自己的页面，且 omeletteDesktop* 桥可用（localhost 命中 preload 白名单）
4) 回滚：菜单「Load Remote Claude.ai」
```

---

## 4. 本地 Agent 运行时

### 4.1 身份（提示词原文节选，全文 38,771 字节）

```
<application_details>
Claude is operating as an agent inside the Claude desktop app.
This agent capability is currently a research preview.
Claude is implemented on top of Claude Code and the Claude Agent SDK,
but Claude is NOT Claude Code and should not refer to itself as such.
Claude has file tools (Read, Write, Edit) with access to a workspace
folder on the user's computer, and a sandboxed Linux shell for running code.
```

### 4.2 参数白名单（下发给 SDK 的键）

```js
["cwd","model","permissionMode","settings","additionalDirectories",
 "systemPrompt","env","mcpServers","hooks"]
```

| 键 | 杠杆 |
|---|---|
| `cwd` | 文件作用域 |
| `permissionMode` / `permissionModeProvisional` | 是否逐次批准工具调用 |
| `systemPrompt` / `systemPromptAppend` | 行为最大杠杆 |
| `env` | 环境注入 |
| `mcpServers` / `remoteMcpServers` | 扩展工具面 |
| `hooks` | 拦截/改写工具调用 |
| `additionalDirectories` | 扩大可访问目录 |

### 4.3 令牌环境变量剥离（实测）

```
CLAUDE_CODE_OAUTH_TOKEN
CLAUDE_CODE_SESSION_ACCESS_TOKEN
CLAUDE_CODE_HOST_SESSION_ID
```
这三个键在传给子进程前被剔除，其余 `env` 原样下发。

### 4.4 会话状态指纹

```json
{ "effort": null, "useWorktree": false, "agent": null, "enabledMcpTools": null,
  "mcpServers": null, "remoteMcpServers": null, "withheldConnectorHosts": [],
  "systemPrompt": null, "envScopeId": null, "attributionProject": null,
  "permissionModeProvisional": false, "fastMode": false, "remoteClientLimits": false }
```

### 4.5 Agent 相关命名空间

`LocalSessions` 563 / `LocalAgentModeSessions` 213 / `ClaudeCode` 17 / `LocalSessionEnvironment` 10 / `LocalSessionPresets` 4 / `AgentModeFeedback` 8。

`LocalExecConsent` 只有两个方法：`choice` / `choose` —— 本地执行的一次性同意开关。

---

## 5. MCP 与连接器

### 5.1 配置与传输

- 键：`mcpServers`（用户级）、设备策略同名键（组织级优先）
- 传输：stdio / HTTP / SSE
- 插件化：服务器名前缀 `plugin:`，随插件目录加载
- 动态头：`headersHelper`（运行时取 header）；模板化 URL（含 `${`）直接拒绝
- 隔离：`withheldConnectorHosts`（按主机整体屏蔽）

### 5.2 内置连接器

```
github-mcp-server.exe   Go 1.26.10 · v2.0.2 · 34 依赖（含 github-mcp-server/v2 自身）
office365-mcp           msal-node-runtime.node + msalruntime.dll + stdio.mjs
microsoft365.mcp.claude.com/mcp
```

### 5.3 第三方门控

```json
{ "buildId": "spa-dev",
  "imports": { "cai_vast_rain": {
      "secret": "4bcade45…f52a", "hash": "Dicv6Oqg",
      "css": [], "preload": ["c3d81cec3-DozQrytV.js", "…共 9 个"] } } }
```
「内容哈希 + 随机别名」双键定位，命中门控才预加载。

### 5.4 Chrome 登录态导入（实测，`Launch` 命名空间）

```js
importChromeLogins: async (previewId, ticket, roots, enablePersist) => {
  if (!t.zX()) return { ok: false, error: "gate_off" };      // 功能门
  const r = await runChromeImport(profile, previewId, ticket, roots, enablePersist);
  return r.ok
    ? { ok: true, results: r.results, persistent: r.persistent,
        reloaded: r.reloaded, storagePending: r.storagePending, storageCarried: r.storageCarried }
    : { ok: false, error: r.error };
}
```

- 站点元数据：`cookieCount` / `hostCount` / `lastAccess` / `sensitive` / `suggested`
- 配套方法：`listChromeImportProfiles` / `listChromeImportSites` / `listImportedChromeLogins` / `removeImportedChromeLogins` / `getChromeImportSharedOffer` / `acceptChromeImportSharedOffer`
- 用途：把指定站点的登录态带进内置浏览器预览

### 5.5 预览白名单（实测有交互门）

```js
addPreviewAllowedOrigin: async (origin, schemeless) => {
  if (!t.zX()) return Unavailable;
  const parent = resolveDialogParent();
  const result = await addOrigin(origin, {
    attendedAdd: isAttended(),        // 需人工确认
    schemelessAdd: schemeless === true,
    dialogParent: parent
  });
  telemetry("desktop_launch_preview_allowed_origin_added", { result });
  return result;
}
```

配套：`getPreviewAllowedOrigins` / `removePreviewAllowedOrigin` / `clearPreviewAllowedOrigins` / `getPreviewLocalNetworkAccess` / `setPreviewLocalNetworkAccess` / `clearPreviewLocalNetworkAccessOrigins`。

---

## 6. Cowork 沙箱与微虚拟机

### 6.1 服务

| 项 | 值 |
|---|---|
| 服务名 | `CoworkVMServiceStore` |
| 账号 / 启动 | `localSystem` / `auto` |
| 二进制 | `cowork-svc.exe` 13,727,056 B，Go 1.25.14 静态链接，仅依赖 `kernel32.dll` |
| 模块 | `github.com/anthropics/cowork-win32-service/cmd/cowork-svc` |
| buildinfo 偏移 | `0xC5A400` |

### 6.2 19 个依赖（全量）

| 依赖 | 版本 | 角色 |
|---|---|---|
| `containers/gvisor-tap-vsock` | v0.8.9 | 用户态 TAP 经 vsock 接入虚拟机 |
| `linuxkit/virtsock` | 2022-05-23 | virtio 套接字 |
| `gvisor.dev/gvisor` | 2026-04-13 | netstack 本体 |
| `insomniacslk/dhcp` | 2026-07-19 | VM 地址分配 |
| `miekg/dns` | v1.1.73 | 内置 DNS |
| `inetaf/tcpproxy` | 2026-05-15 | TCP 转发 |
| `anthropics/win-httpproxy` | v0.0.0 | 自家 HTTP 出口代理 |
| `Microsoft/go-winio` | v0.6.2 | 命名管道 |
| `google/gopacket` | v1.1.19 | 抓包/包构造 |
| `google/btree` | v1.1.2 | 索引 |
| `pierrec/lz4/v4` | v4.1.14 | 压缩 |
| `sirupsen/logrus` · `pkg/errors` | 1.10.2 · 0.9.1 | 日志/错误 |
| `u-root/uio` | 2024-02-24 | 用户态 IO |
| `golang.org/x/{crypto,net,sys,time,exp}` | 0.55 / 0.58 / 0.47 / 0.12 / 2023-11 | 标准扩展（含 SSH） |

### 6.3 网络链路

```
虚拟机 Linux
   │ vsock(virtsock)
   ▼
gvisor-tap-vsock ──► gVisor netstack（TCP/UDP/ICMP/分片）
   │                        │
   │ DHCP 分配               │ DNS 解析（miekg/dns）
   ▼                        ▼
tcpproxy / win-httpproxy ──► 宿主出口（受 coworkEgressAllowedHosts 约束）
```

### 6.4 镜像包下载与校验

```js
function arch() { return process.arch === "x64" ? "x64" : "arm64"; }
function url()  { return `https://downloads.claude.ai/vms/linux/${arch()}/${manifest.sha}`; }
```

就绪判定三态：
```
!exists(bundle)                        → missing
!exists(`.${name}.origin`)             → origin_missing
readFile(`.${name}.origin`) !== sha    → version_mismatch
else                                   → ready
```
- `.origin` 是版本凭据文件，内容即期望 sha
- 下载用**流式哈希**（`Transform` + `createHash("sha256")`），边下边算
- 校验失败即丢弃

### 6.5 网络状态机

```
networkStatus   : CONNECTED | NOT_CONNECTED
apiReachability : UNREACHABLE | PROBABLY_UNREACHABLE（探针默认 api.anthropic.com）
断网 30,000 ms 未恢复 → network_connection_failed 上抛界面
```
**即使不登录，壳也持续探测 `api.anthropic.com` 可达性。**

### 6.6 VM 控制面（`ClaudeVM` 15 方法）

```
checkVirtualMachinePlatform / enableVirtualMachinePlatform / restartAfterVMPInstall
startVM / restartVM / download / getDownloadStatus / getRunningStatus
isHostLoopModeEnabled / isHostLoopDevOverrideActive / setForceDisableHostLoop
setYukonSilverConfig / config / options / value
```
`enableVirtualMachinePlatform` = 启用 Windows「虚拟机平台」功能（需管理员 + 重启）。

### 6.7 相关策略键

`coworkEgressAllowedHosts` / `coworkVmIpv6Enabled` / `coworkFileReadCheck` / `coworkEDRIntegration`(+Vendor) / `coworkSessionRetentionDays` / `coworkTabEnabled`。

`coworkFileReadCheck` 的结构：`command`（盘符绝对路径的程序）/ `timeoutSec` / `cacheTtlSec` —— **读文件前先跑该命令**。

---

## 7. Computer Use

IPC 面：
```
CuTeach_$_next / reassertHover
CuWatchRecordPill_$_done / discard / toggleMic / micError
CuWatchRecordChooser_$_choose / setMicPreview / stopMicPreview / inputDevices
ComputerUseTcc（11 方法，macOS TCC 权限）
ComputerUseLivePreview（6 方法）
```
= 屏幕采集 + 输入注入 + 录屏 + 麦克风，全部经 IPC 白名单。

**隐藏细节**：渲染层把 `MediaDevices.prototype.enumerateDevices` 改写成返回**空 deviceId/label 的桩对象**，`getCapabilities()` 返回空对象，防页面侧设备指纹采集。

---

## 8. Electron 加固与 patch

### 8.1 fuse wire（实测）

| 项 | 值 |
|---|---|
| 哨兵 | `dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`（32 B） |
| 偏移 | `0xC11EC18`（202,501,144） |
| 版本 / 数量 | `0x01` @ `0xC11EC38` / `0x09` @ `0xC11EC39` |
| 值区 | `0xC11EC3A`–`0xC11EC42`，ASCII `010011011` |

### 8.2 9 项映射（已由 9 个 `Is*Enabled` 函数证实无第 10 项）

| # | fuse | 值 | 后果 |
|---|---|---|---|
| 1 | RunAsNode | `0` | 不能当 node 跑 |
| 2 | EnableCookieEncryption | `1` | cookie 加密 |
| 3 | EnableNodeOptionsEnvironmentVariable | `0` | 忽略 `NODE_OPTIONS` |
| 4 | EnableNodeCliInspectArguments | `0` | 忽略 `--inspect` |
| 5 | **EnableEmbeddedAsarIntegrityValidation** | `1` | **改 asar 即失败** |
| 6 | OnlyLoadAppFromAsar | `1` | 只从 asar 载入 |
| 7 | LoadBrowserProcessSpecificV8Snapshot | `0` | — |
| 8 | GrantFileProtocolExtraPrivileges | `1` | `file://` 权限放大 |
| 9 | WasmTrapHandlers | `1` | — |

exe 内的 9 个查询函数（证明全集）：
```
0xE62349D IsCookieEncryptionEnabled          0xE62362A IsEmbeddedAsarIntegrityValidationEnabled
0xE62390D IsGrantFileProtocolExtraPrivilegesEnabled  0xE623CEC IsLoadBrowserProcessSpecificV8SnapshotEnabled
0xE623E7B IsNodeCliInspectEnabled            0xE623EAB IsNodeOptionsEnabled
0xE623FFD IsOnlyLoadAppFromAsarEnabled       0xE624170 IsRunAsNodeEnabled
0xE62475E IsWasmTrapHandlersEnabled
```

### 8.3 patch 验证记录（已在副本上真实执行）

```
副本 249,955,664 B
改前 0xC11EC3E = 0x31 '1'   fuse 串 = 010011011
改后 0xC11EC3E = 0x30 '0'   fuse 串 = 010001011
改后 sha256  51cd2e6f54b1c7478bc79aeaae1c34a29c220321b6882a9559bf0df50dd291d3
回滚 sha256  093fb6529006fe5fbe28b61231484734dab78a497dc1b05311f2315590118414  ← 与原件一致
```

### 8.4 三条路线

**A. 副本 + 关完整性（推荐）**
```powershell
Copy-Item -LiteralPath "<APP_ROOT>\app" -Destination "<WORK>\app" -Recurse
$fs = [IO.File]::Open("<WORK>\app\claude.exe",'Open','ReadWrite')
$fs.Position = 0xC11EC3E; $fs.WriteByte(0x30); $fs.Close()
node asar.js extract "<WORK>\app\resources\app.asar" "<WORK>\src"
# …改代码…
Start-Process "<WORK>\app\claude.exe"
```
判据：窗口出现且不闪退。回滚：删 `<WORK>`。
失败改法：`0xC11EC3F` 一并置 0；仍失败走 C。

**B. 只换前端（不改包）**
见第 3 节；注意本包为 prod，环境变量分支受限，走 Developer 菜单最可靠。

**C. 改 asar 完整性哈希（不推荐）**
`claude.exe` 资源段有 `ElectronAsarIntegrity`（asar 路径 → 哈希），可同步改写，但需精确解析 PE 资源树并重算，工作量远大于 A。

---

## 9. 动态调试矩阵

| 目的 | 手段 | 被谁挡 | 判据 |
|---|---|---|---|
| 主进程 JS | `--inspect=9229` | fuse #4 | 端口未监听 → 需先改 fuse |
| 主进程 JS（绕过） | fuse #4 置 0 后加 `--inspect` | — | `curl 127.0.0.1:9229/json` 有返回 |
| 渲染进程 | `--remote-debugging-port=9222` | **不在 9 项 fuse 内** | `curl 127.0.0.1:9222/json/list` 列出页面 |
| 渲染进程（管道） | `--remote-debugging-pipe`（exe 内有该串） | — | 管道可写即通 |
| DevTools | 命中白名单后 `openDevTools` | — | 窗口出现 |
| 原生层 | 断点 `claude-native-binding.node` | Rust 符号未导出 | 需自行还原注册表 |

**已验证**：`claude.exe --version` → `5.11492.5`，正常退出、无残留（3 秒硬超时，隐藏窗口）。

---

## 10. 暴露面与设计边界

| # | 项 | 性质 | 说明 |
|---|---|---|---|
| 1 | preload 白名单对 `file:` 与任意 `localhost` 无条件信任 | 设计缺口 | 主进程 sender 校验更严，两层不一致 |
| 2 | `--load-preview-url` 仅需一次 Windows Hello | 设计边界 | payload `{url, ts}` 无签名、无来源绑定 |
| 3 | fuse #8 `GrantFileProtocolExtraPrivileges=1` | 加固取舍 | 与 #1 叠加放大 `file://` 面 |
| 4 | safeStorage = DPAPI(CurrentUser) | 设计边界 | 同 Windows 用户下任意进程可解 |
| 5 | `coworkFileReadCheck.command` 为可执行路径 | 策略面 | 策略可写即可执行 |
| 6 | 策略含 `inference*` / `egressProxy*` / `entra*` | 企业面 | 策略源被控即全局可控 |
| 7 | `cowork-svc` 以 LocalSystem + go-winio 管道 | 待验证 | 管道 ACL 未实测 |

---

## 11. 四轮复盘账本

### 11.1 工具层踩过的坑

| # | 坑 | 改法 |
|---|---|---|
| 1 | asar 头解析错位 | 头 = 4B + 4B pickle 长 + 4B JSON 长 + JSON；JSON 从 offset 16 起，载荷基址 `8 + pickleSize` |
| 2 | IPC 正则过度匹配（19,744 条噪声） | 只取 `xo()` 注册表，得 107 / 2,142 |
| 3 | PowerShell 扫 238 MB 超时 | 换 node `Buffer.indexOf`，秒级 |
| 4 | grep 在单行 bundle 上截断 | 自写窗口切片器 `dump.js` |
| 5 | `cowork-svc` 字符串搜不到 | 从 manifest 的 `windows.service` 反查 |
| 6 | 策略键只看到 75 个 | 先落盘再统计，得 217 |
| 7 | `argv[1]` 取成脚本名 | 改 `argv[2]` |
| 8 | `node -e @"…"@` 引号被吞导致统计失真 | 改用文件化脚本 + 双实现交叉 |

### 11.2 被推翻的结论（全部已修正）

| 旧 | 新 |
|---|---|
| IPC 13 命名空间 / 1475 方法 | **107 / 2142** |
| preload 命名空间 13 | **22** |
| 端点 46 个 | **162 主机 / 1131 URL** |
| Node ≥22 | **24.22.1** |
| Chromium 未知 | **156.0.8078.75** |
| fuse #9 未知 | **WasmTrapHandlers** |
| `localExecConsent` 0 命中 | **`LocalExecConsent`**, `choice`/`choose` |
| vhdx 36B「指针」 | **36 个 0x00 占位** |
| localhost 无条件可信 | **preload 无条件 / 主进程需 gate** |
| 可能为 dev 构建 | **`buildType: "prod"`** |
| `github-mcp-server` Go+Rust | **纯 Go 1.26.10** |
| ion-dist 4792 条目 / 198.37 MB | **5399 条目 / 206,568,297 B** |

---

## 12. 未决项（带置信度）

| # | 项 | 置信 | 卡点 |
|---|---|---|---|
| 1 | 运行时主流程（登录 / 更新 / VM 启动） | 15% | 只跑过 `--version` |
| 2 | `ion-dist` 深层逻辑（841 条已列，调用链未追） | 80% | 4792 chunk 只做静态抽取 |
| 3 | `manifestSignatureEnforcement: "flag"` 语义 | 75% | 字面为灰度，是否可关未验 |
| 4 | `cowork-svc` 命名管道 ACL | 70% | 需实机 `pipsec` / `accesschk` |
| 5 | 三方门控 `secret` 用途 | 75% | 内容校验还是访问令牌未定 |
| 6 | 副本脱离 MSIX 身份后的行为差异 | 70% | Windows Hello / Toast / 单实例未测 |
| 7 | `claude.exe` 238 MB 内部实现 | 85% | 只做 PE + 字符串 + 导入表，未反汇编 |
| 8 | `smol-bin.x64.vhdx` 真实格式 | 60% | 本地只有 36 字节占位，真镜像运行期下载 |

---

## 13. 附录

### 13.1 偏移速查

```
claude.exe   fuse 哨兵            0xC11EC18
claude.exe   fuse 版本 / 数量     0xC11EC38 / 0xC11EC39
claude.exe   fuse 值区            0xC11EC3A .. 0xC11EC42
claude.exe   asar 完整性 fuse     0xC11EC3E   ('1' → '0')
claude.exe   OnlyLoadAppFromAsar  0xC11EC3F   ('1' → '0')
claude.exe   cowork buildinfo     0xC5A400
github-mcp   buildinfo            0x177A600
app.asar     载荷基址             302,320（随版本变化，需按头重算）
ion-dist     载荷基址             1,433,548
```

### 13.2 脚本

| 脚本 | 用途 |
|---|---|
| `asar.js list/cat/extract/grep` | asar 解析（零依赖） |
| `extract-prompt.js` | 还原模板字符串 |
| `analyze.js` / `ipc2.js` | IPC / 端点统计 |
| `dump.js` | 上下文切片 |
| `policy.js` / `urls.js` | 策略键 / 端点全量 |
| `verify.js fuses\|xo\|pe\|imports` | fuse / IPC 精算 / 版本串 / 导入表 |
| `recheck.js` | 第二套实现交叉复算 |
| `gobi.js` | Go buildinfo 解码 |
| `deep.js tree\|paths\|i18n` | asar 结构 / 路径表 / i18n |

### 13.3 证据文件

```
extract/analysis/ipc-registry.txt      107 命名空间 / 2142 方法
extract/analysis/policy-keys.txt       217 个策略键
extract/analysis/endpoints-full.txt    主进程端点
extract/analysis/ion-apiPath.txt       841 条接口
extract/analysis/ion-route.txt         638 条路由
extract/analysis/ion-event.txt         108 个埋点
extract/prompt-desktop-agent.md        38,771 B 系统提示词
extract/ev/*.txt                       各子系统证据窗口
verify-95.md / audit2-gaps.md          核对记录
```

### 13.4 上篇导读

包身份、组件指纹、架构、启动链、目录画像、IPC 全表、策略全表、端点全表、渲染层、技能包、代号表 —— 见《上篇 · 结构与组件》。
