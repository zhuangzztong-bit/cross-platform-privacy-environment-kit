# 逆向国外 AI Cloud

**上篇 · 结构与组件**（全静态实测，不含运行期依赖；数值以本机安装包为准）

---

## 目录

1. 概览与关键数字
2. 包身份与系统集成
3. 组件清单与二进制指纹
4. 总体架构
5. 启动链
6. 主进程目录画像
7. IPC 面（107 命名空间 / 2142 方法）
8. 企业策略面（217 键）
9. 端点与接口面
10. 渲染层
11. 内置技能包
12. 内部代号表
13. 附录：核对清单与脚本

---

## 1. 概览与关键数字

| 项目 | 值 |
|---|---|
| 产品名 / 包标识 | Claude / `AnthropicPBC.Claude` |
| 包版本 | `5.11492.5.0` |
| 应用版本 | `5.11492.5` |
| 运行时 | Electron `45.2.1` · Chromium `156.0.8078.75` · Node `v24.22.1` |
| 发行形态 | MSIX（x64 / FullTrust） |
| 主程序 | `claude.exe` 249,955,664 B · sha256 `093fb652…0118414` |
| 主进程包 | `app.asar` 88,787,202 B · 1,122 条目 · 解包 133,622,630 B |
| 渲染层包 | `ion-dist.asar` 206,568,297 B · 5,399 条目（4,792 个 `.js`） |
| IPC 面 | **107 个命名空间 / 2,142 个方法** |
| 企业策略 | **217 个 `flatKey`** |
| 后端接口 | **162 个唯一主机 / 1,131 处 URL**；渲染层 **841 条 apiPath / 638 条 route / 108 个埋点事件** |
| 内置技能 | **7 个**（docx / pdf / pdf-reading / pptx / xlsx / frontend-design / draft-design-system） |
| 内嵌系统提示词 | **38,771 字节**（明文） |
| 加固 | 9 项 Electron fuse，其中 asar 完整性校验**开启** |

**一句定位**：界面外包给远端、能力全部留在本地、边界靠 fuse + 签名 + 生物识别 + 企业策略四道锁。

---

## 2. 包身份与系统集成

### 2.1 声明的能力

| 能力 | 含义 |
|---|---|
| `runFullTrust` | 完全信任运行 |
| `localSystemServices` | 可注册 LocalSystem 权限服务 |
| `packagedServices` | 服务随包安装 |
| `unvirtualizedResources` | 不受 MSIX 文件/注册表虚拟化限制 |
| `internetClient` | 出站网络 |

`localSystemServices` + `unvirtualizedResources` 的组合 = 装完即具备系统级写入与服务注册资格。

### 2.2 注册的系统集成点

| 类型 | 细节 |
|---|---|
| Windows 服务 | `CoworkVMServiceStore`，`StartupType=auto`，`StartAccount=localSystem` |
| 协议 | `claude://`，参数模板 `-- "%1"` |
| 执行别名 | AppExecutionAlias（系统应用目录下的 0 字节 stub） |
| 开机启动 | `StartupTask TaskId=ClaudeStartup`，`Enabled=false`（默认关） |
| 防火墙 | `windows.firewallRules` × 2 |

### 2.3 应用事件挂点

```js
app.on("before-quit") / on("will-quit") / on("activate")
app.on("open-url")        // claude:// 深链
app.on("open-file")       // 文件关联
app.on("continue-activity")
app.on("second-instance", (e, argv) => { if (!argv.includes("--startup")) activate() })
session.on("session-end") // Windows 注销/关机 → 干净退出
autoUpdater.on("before-quit-for-update")
```

`second-instance` 收到 `--startup` 不激活窗口 —— 开机自启静默启动的实现。

---

## 3. 组件清单与二进制指纹

`<RES>` = `<APP_ROOT>\app\resources`

| 组件 | 字节 | 格式/语言 | sha256 前 16 | 角色 |
|---|---|---|---|---|
| `claude.exe` | 249,955,664 | PE32+ / C++·Rust | `093fb6529006fe5f` | Electron 宿主 |
| `app.asar` | 88,787,202 | asar | `47433b3c91cdbc81` | 主进程 JS |
| `ion-dist.asar` | 206,568,297（解包） | asar | — | 渲染层 |
| `cowork-svc.exe` | 13,727,056 | PE64 · **Go 1.25.14** | `d56376fdbbb7fda8` | 沙箱服务 |
| `github-mcp-server.exe` | 25,676,624 | PE64 · **Go 1.26.10** | `f415a0ac36c7637d` | GitHub MCP |
| `claude-native-binding.node` | 4,289,872 | PE64 · **Rust/napi** | `ef04dd101e8d044a` | 原生桥 |
| `chrome-native-host.exe` | 1,250,128 | PE64 · **Rust** | `a50823ab69b0c572` | 扩展宿主（命名管道） |
| `claude-ssh-broker.exe` | 2,599,248 | PE64 | — | SSH 通道代理 |
| `claude-ssh-askpass.exe` | 2.54 MB | PE64 | — | SSH 口令回调 |
| `claude-ssh-proxy.exe` | 1.88 MB | PE64 | — | SSH 转发 |
| `claude-make-data-folder.exe` | 1.52 MB | PE64 | — | 数据目录初始化 |
| `conpty.node` / `conpty_console_list.node` | 0.30 / 0.15 MB | PE64 | — | Windows 伪终端 |
| `msal-node-runtime.node` / `msalruntime.dll` | 3.11 / 3.24 MB | PE64 | — | 微软身份库 |
| `smol-bin.x64.vhdx` | **36（全 0x00）** | 占位 | — | 微虚拟机镜像锚点 |
| `resources.pak` | 13,371,551 | Chromium | — | 资源包 |
| `icudtl.dat` | 10,824,576 | ICU | — | 国际化 |
| `snapshot_blob.bin` / `v8_context_snapshot.bin` | 0.36 / 0.72 MB | V8 快照 | — | 启动加速 |

### 3.1 加固矩阵

| 二进制 | ASLR | NX | CFG | HighEntropyVA | Authenticode | 熵 | 加壳 |
|---|---|---|---|---|---|---|---|
| `claude.exe` | ✔ | ✔ | ✔ | ✔ | ✔ | 6.56 | 否 |
| `cowork-svc.exe` | ✔ | ✔ | ✘ | ✔ | ✔ | 6.24 | 否 |
| `github-mcp-server.exe` | ✔ | ✔ | ✘ | ✔ | ✔ | 6.30 | 否 |
| `claude-native-binding.node` | ✔ | ✔ | ✘ | ✔ | ✔ | 6.35 | 否 |
| `chrome-native-host.exe` | ✔ | ✔ | ✘ | ✔ | ✔ | 6.37 | 否 |

### 3.2 `claude.exe` 导入表（7 DLL / 511 函数）

```
KERNEL32.dll 411   WINMM.dll 31   WS2_32.dll 29   CRYPT32.dll 28
ntdll.dll 8        VERSION.dll 3  DWrite.dll 1
```
- 凭据相关：`CryptProtectData` / `CryptUnprotectData`（DPAPI 直调）
- 常规 Chromium 能力：`ReadProcessMemory` / `WriteProcessMemory` / `CreateRemoteThread` / `VirtualAllocEx` / `VirtualProtectEx`（属 V8 快照、crashpad、沙箱管理，不构成注入证据）

### 3.3 Go 二进制 buildinfo（零工具链解码）

| 二进制 | 偏移 | Go | 主模块 |
|---|---|---|---|
| `cowork-svc.exe` | `0xC5A400` | `go1.25.14` | `anthropics/cowork-win32-service/cmd/cowork-svc` |
| `github-mcp-server.exe` | `0x177A600` | `go1.26.10` | `github/github-mcp-server/v2/cmd/github-mcp-server` @ `v2.0.2` |

```js
const magic = Buffer.from([0xff,0x20,0x47,0x6f,0x20,0x62,0x75,0x69,0x6c,0x64,0x69,0x6e,0x66,0x3a]);
const i = buf.indexOf(magic);
const ptrSize = buf[i+14], flags = buf[i+15];        // 8 / 2 → inline strings
const version = buf.slice(i+17, i+17+buf[i+16]).toString();
```

**Rust 指纹**：cargo 路径残留 `index.crates.io-1949cf8c6b5b557f\…` → napi 2.16 / tokio 1.47 / image 0.24.9 / base64 0.21.7 / anyhow 1.0.100（出现于 `.node` 与 `chrome-native-host.exe`）。

---

## 4. 总体架构

```
┌───────────────────────────────────────────────────────────────────┐
│ claude.exe（Electron 45.2.1 / Node 24.22.1）                       │
│  .vite/build/index.pre.js              入口                        │
│  .vite/build/index.chunk-BNzwSkaR.js   7.2 MB 主逻辑单体            │
│  其余 631 个 chunk；compile-cache 2 个 .jsc                        │
│                                                                   │
│  ├ 窗口：main / quick / design / about                             │
│  ├ IPC：contextBridge + 固定 UUID 前缀 + frameToken/origin 双校验    │
│  ├ 凭据：safeStorage(DPAPI) / Chromium os_crypt / MSAL             │
│  ├ Agent：Claude Code + Agent SDK（内嵌 chunk）                     │
│  ├ MCP：stdio / HTTP / SSE / 插件 MCP / 内置 GitHub·Office365       │
│  ├ 沙箱：cowork-svc（Go + gVisor + VHDX）                          │
│  ├ 技能：7 个 bundled .skill（ZIP）                                 │
│  └ 更新 / 遥测 / 远程配置 / 217 策略键                              │
└─────────────┬───────────────────────────┬──────────────────────────┘
              │ loadURL                   │ spawn / Windows Service
              ▼                           ▼
  https://claude.ai（远端前端）      CoworkVMServiceStore(LocalSystem)
  ion-dist.asar（本地前端 206 MB）    └ cowork-svc → 微虚拟机(gVisor)
              │ contextBridge
              ▼
  渲染进程（sandbox 开 / nodeIntegration 关）
```

---

## 5. 启动链

```
AppxManifest → Executable = app\Claude.exe
  → claude.exe（CPU 特征、V8 快照）
     → app.asar → package.json → main: ".vite/build/index.pre.js"
        → index.pre.js（Sentry 版本注入）
           → index.chunk-BNzwSkaR.js（窗口 / IPC / 凭据 / Agent / 更新）
```

版本指纹（全 chunk 一致）：
```js
SENTRY_RELEASE = { id: "1403e2cf44abfb23809c8ae11238d5e9704a41c2" }
```
构建元信息（内嵌 JSON）：
```json
{ "commitHash": "1403e2cf…", "isNestBuild": false,
  "commitTimestamp": "…", "buildType": "prod", "appVersion": "5.11492.5" }
```

> 注意：`buildType` 为 **prod**，dev 分支（`CLAUDE_AI_URL` 直生效）在本包不成立。

---

## 6. 主进程目录画像

```
.vite/build         646    resources/frame      271    .vite/renderer        94
resources/i18n       43    resources/bundled-skills 8  resources/office365-mcp 5
resources/artifact-libs 4  node_modules/ws       19    node_modules/node-pty 16
node_modules/agent-base 7  node_modules/@ant      3    compile-cache          2
```

- `.vite/build`：632 个顶层 `.js` + 子目录（worker / file-index-worker / frame-local-worker 等 9 个）
- `.vite/renderer`：主窗口渲染产物（含 `clawdQuestEngine` 等 1 MB 级 chunk）
- `compile-cache`：V8 字节码缓存（`.jsc`），启动加速用

---

## 7. IPC 面

### 7.1 通道格式

```
$eipc_message$_cbea2145-9be5-45b6-97f1-019bc57a8864_$_<命名空间>_$_<命名空间>_$_<方法>
```
固定 UUID 全 chunk 一致 → 通道指纹。

### 7.2 真实规模（`xo()` 注册表精算）

**107 个命名空间 / 2,142 个方法**。头部：

| 命名空间 | 方法数 |
|---|---|
| `LocalSessions` | 563 |
| `LocalAgentModeSessions` | 213 |
| `Launch` | 166 |
| `Simulator` | 124 |
| `Custom3pSetup` | 51 |
| `CoworkSpaces` | 46 |
| `CoworkArtifacts` | 45 |
| `FileSystem` | 37 |
| `WindowControl` | 35 |
| `LocalPlugins` | 34 |
| `Extensions` | 33 |
| `DeviceRegistry` | 32 |
| `ClaudeAiImport` | 31 |
| `CoworkScheduledTasks` | 29 |
| `PaneExtensions` | 28 |
| `Resources` | 27 |
| `CustomPlugins` | 24 |
| `EngineSurface` | 22 |
| `HistoryImport` / `CCDScheduledTasks` | 20 |
| `Custom3pGatewaySpendLimits` | 19 |
| `CoworkFilePreview` / `FramebufferPreview` | 18 |
| `ClaudeCode` / `DocumentFunnel` | 17 |
| `RemoteControlServing` / `Buddy` / `CoworkArtifactBridge` | 16 |
| `DesktopNotifications` / `ClaudeVM` | 15 |
| `CoworkStorage` / `OfficeAddinFiles` / `SableOtterHud` | 14 |
| `DeviceStorage` / `AutoUpdater` | 13 |
| `McpAppViews` | 12 |
| `ComputerUseTcc` / `CoworkMemory` | 11 |
| `MCP` / `ChromeExtension` / `GrandPrix` | 10 |
| `LocalSessionEnvironment` | 10 |
| `Custom3pHelperRun` / `WindowState` / `Gorse` / `AgentModeFeedback` | 8 |
| `LocalExecConsent` / `ManagedConfig` / `DesignPdf` / `PluginResources` / `McpAppViewBridge` | 2 |
| `ArtifactShellTransport` / `AppFeatures` / `PlanUsage` / `Dictation` | 1 |

完整表：`extract/analysis/ipc-registry.txt`

### 7.3 关键命名空间的方法样本

```
LocalExecConsent : choice / choose
ClaudeVM         : checkVirtualMachinePlatform / enableVirtualMachinePlatform / startVM / restartVM
                   download / getDownloadStatus / getRunningStatus / setYukonSilverConfig
                   isHostLoopModeEnabled / isHostLoopDevOverrideActive / setForceDisableHostLoop
Launch           : importChromeLogins / listChromeImportProfiles / listImportedChromeLogins
                   addPreviewAllowedOrigin / removePreviewAllowedOrigin / getPreviewAllowedOrigins
                   capturePreviewScreenshot / capturePreviewTabIfChanged / loadHtmlPreviewContent
GrandPrix        : pair / partnerId / submitVerificationCode / dismissVerificationCode
Gorse            : exportToFiles / migrateToProject / openExportFallbackFolder / includeHistory
ForgeState       : getForgeStateSnapshot / setForgeStateVisibleKeys / refreshForgeStateRow
ViolinFret       : choice / enableCombinedSwitch / setViolinFretChoice
ClaudeCode       : checkGitAvailable / getLocalSandboxStatus / getPeriodUsage / patchUserSettings
FileSystem       : browseFile(s) / browseFolder(s) / content / cwd / appInfoForExtension
```

### 7.4 双白名单（重要）

两套校验并存，粒度不同：

| 层 | 判断 | 放行范围 |
|---|---|---|
| preload（`mainWindow.js`） | `frameToken/routingId` 等于 top frame **且** origin 命中 | `claude.ai`、`preview.claude.ai`、`claude.com`、`preview.claude.com`、`localhost`（无条件）、`file:`、`app://localhost`、`*.ant.dev` |
| 主进程 sender 校验 | `senderFrame.parent === null` **且** origin 命中 | 同上，但 `localhost` 与 `*.ant.dev` 需 `globalThis.isDeveloperApprovedDevUrlOverrideEnabled` 为真 |

结论：**渲染侧与主进程侧的信任判定不一致**，preload 层对 `file:` 与任意 `localhost` 无条件信任。

---

## 8. 企业策略面（217 个 `flatKey`）

每个键带：`flatKey` / `category` / `group` / `order` / `default` / `failClosedValue` / `support.scopes`（`1p`/`3p`）/ `availableInVersion` / `visibility`（含 `public-undocumented`）/ `selfHosted.execution`。

### 8.1 主题分布

| 主题 | 数量 | 代表 |
|---|---|---|
| artifacts | 8 | `artifactsEnabled` `artifactsDesignEnabled` `artifactsRetentionDays` |
| 浏览器/扩展 | 11 | `builtinBrowserEnabled` `builtinBrowserAllowedDomains` `ExtensionSettings` `NativeMessagingAllowlist` |
| 代码/插件 | 7 | `codeAllowedRepositories` `allowedPluginMarketplaces` `allowManagedHooksOnly` |
| cowork/VM | 7 | `coworkEgressAllowedHosts` `coworkVmIpv6Enabled` `coworkFileReadCheck` `coworkEDRIntegration` |
| 禁用开关 | 16 | `disableAutoUpdates` `disableBypassPermissionsMode` `disableDeepLinkRegistration` `disableWslSessions` |
| 启用开关 | 16 | `autoModeEnabled` `bootstrapUrl` `computerUseEnabled` `claudeCodeSettings` `developerModeEnabled` |
| 部署/品牌 | 11 | `deploymentMode` `deploymentLogo` `desktopHome` `dangerousMaxVersion` `defaultModelEffort` |
| 会话留存 | 5 | `artifactsSessionRetentionDays` / `chat…` / `code…` / `cowork…` / `sessionRetentionHold` |
| 沙箱/读取 | 4 | `blockReadsOutsideWorkingDirectories` `coworkEgressAllowedHosts` |
| 遥测/更新 | 3 | `disableEssentialTelemetry` `allowStandardUserUpdates` `allowOptionalClientAuth` |

### 8.2 可改后端的键（产品内建能力）

```
inferenceAnthropicApiKey
inferenceBedrockAwsCliPath / AwsDir / BaseUrl / BearerToken / Profile / Region
inferenceBedrockServiceTier / SsoAccountId / SsoRegion / SsoRoleName / SsoStartUrl / WebIdentityRoleArn
inferenceCredentialHelper / Args / SilentRefreshEnabled / TimeoutSec / TtlSec
egressProxyUrl / egressProxyPacUrl
entraAzureCloud / entraClientId / enforceConsoleSignInOrgList / forceLoginOrgUUID
importThirdPartyHistoryIntoOrgUUID / endUserAttribution
```

### 8.3 一个策略键的完整定义（样本）

```json
{ "flatKey": "disableDeepLinkRegistration",
  "support": { "enabled": { "scopes": ["3p"], "availableInVersion": "1.6889.0" },
               "selfHosted": { "execution": "client",
                               "why": "Desktop registers claude:// links on the person's computer at launch, before it has signed in to the host" } },
  "failClosedValue": true, "default": false, "category": "sandbox", "order": 9 }
```

### 8.4 策略校验失败分支

```
未启用              → undefined（放行）
配置不可读          → 抛错「组织设置暂时无法读取」
键存在但无值        → "the policy names the key but gives it no usable value"
非机器级策略        → "the key does not come from machine-scoped device policy"
command 非盘符绝对路径 → "the program's path is not a full local path on this system"
移除未确认          → "the key's removal from the device policy is not confirmed"
```

---

## 9. 端点与接口面

### 9.1 主机规模

- 主进程 JS：**162 个唯一主机 / 1,131 处 URL**
- 渲染层：**841 条 apiPath / 638 条 route / 108 个 `desktop_*` 埋点**

### 9.2 主进程侧功能端点（节选）

**OAuth / 身份**
```
/desktop/callback（claude.ai 与 staging 各一）
console.anthropic.com/oauth/code/callback
platform.claude.com/oauth/{authorize,code/callback,code/success}
platform.claude.com/v1/oauth/token
claude.com/cai/oauth/authorize
api.anthropic.com/api/oauth/claude_cli/{create_api_key,roles}
login.microsoftonline.com（MSAL）
```

**发布 / 更新**
```
downloads.claude.ai/claude-code-releases
downloads.claude.ai/claude-ssh-releases
downloads.claude.ai/model-catalog/v1/{catalog.json,schema.json}
downloads.claude.ai/vms/linux/<arch>/<sha>
```

**遥测 / 计费 / 内置 MCP**
```
claude.ai/api/landfill/desktop/v1
platform.claude.com/buy_credits
microsoft365.mcp.claude.com/mcp
```

### 9.3 渲染层接口面（841 条，节选）

```
/api/auth/{login_methods,logout,logout/all-sessions,logout/session}
/api/auth/mfa/{challenge/send,challenge/verify,sms/enroll/send,sms/enroll/verify}
/api/auth/session_reattest/webauthn{,/challenge}
/api/auth/step_up/webauthn/credentials{,/challenge}
/api/auth/{send_magic_link,verify_magic_link,send_phone_code,verify_phone_code}
/api/auth/{trusted_devices,verify_apple,verify_google,verify_google_mobile,exchange_nonce_for_code}
/api/account/{settings,standing,email_consent,export_data,deletion-allowed,enterprise_upgradeable_organizations}
/api/accounts/me/consents{,/check,/revoke}
/api/artifacts/mcp{,/data}
```

完整表：`extract/analysis/ion-apiPath.txt`、`ion-route.txt`、`ion-event.txt`

---

## 10. 渲染层

| 项目 | 值 |
|---|---|
| 解包字节 | 206,568,297 |
| 条目 | 5,399（`assets/v1` 5,255） |
| JS | 4,792 |
| 其它 | svg 379 / png 56 / woff2 42 / json 31 / css 27 / ttf 21 / mp3 9 / html 5 / ico 3 |
| 入口 | `index.html` / `client-shell-v1.html` / `frame-shell.html` / `frame-connect.html` / `frame-manage.html` |
| Worker | highlight 1.58 MB、model 0.61 MB、pierre(+bracket)、rumEncoder、completionGzip、fileFindRegExp、idleWave、wordDocument |
| 构建统计 | `scc.json`：4780 chunks / 69,841 edges / **0 循环强连通** |

**i18n 双套**

| 位置 | 数量 | 体量 |
|---|---|---|
| 主进程 `resources/i18n/*.json` | 43 | en-US 107,033 B |
| 渲染层 `ion-dist/i18n/*.json` | 40+ | de-DE 4,005,141 B / es-419 3,901,583 B / en-US 3,311,042 B |
| 渲染层 `ion-dist/i18n/dynamic/*.json` | 11 | 2,620–5,772 B |

**第三方门控**（`custom-3p-gated-imports.json`）
```json
{ "buildId": "spa-dev",
  "imports": { "cai_vast_rain": {
      "secret": "4bcade45…f52a", "hash": "Dicv6Oqg",
      "preload": ["c3d81cec3-DozQrytV.js", "…共 9 个"] } } }
```

---

## 11. 内置技能包

`resources/bundled-skills/`（8 个文件 = 7 技能 + manifest）

| 文件 | 字节 | 用途 |
|---|---|---|
| `docx.skill` | 172,206 | Word 文档读写改 |
| `pdf.skill` | 24,821 | PDF 创建/合并/表单/加密 |
| `pdf-reading.skill` | 7,997 | PDF 内容抽取与栅格化 |
| `pptx.skill` | 185,613 | 幻灯片读写 |
| `xlsx.skill` | 171,782 | 表格读写与公式 |
| `frontend-design.skill` | 8,125 | 前端视觉方向 |
| `draft-design-system.skill` | 52,928 | 品牌设计系统草拟 |
| `manifest.json` | 5,115 | 技能清单 |

- `.skill` = **ZIP**（`PK\x03\x04`），内部 `<name>/SKILL.md`
- manifest：`agentSkillsRef: "1794592614"`，`tier` 全为 `always`
- `draft-design-system` 另带 `needsDesignSystems: true`

---

## 12. 内部代号表

| 代号 | 出处 | 推断 |
|---|---|---|
| `omelette` | `omeletteDesktopPdf` | 桌面壳代号 |
| `landfill` | `claude.ai/api/landfill/desktop/v1` | 数据上报通道 |
| `CopperHeron` | `CopperHeronFinalizeStatus` | 功能终结状态 |
| `sableOtter` | `claude.internal.sableOtter`、`SableOtterHud` | 内部实验 |
| `fizzyFrost` | `claude.fizzyFrost`、`FizzyFrost` | 内部实验 |
| `ViolinFret` | 命名空间 | 开关组合 |
| `ForgeState` | 命名空间 | 状态面板 |
| `Gorse` | 命名空间 | 导出/迁移 |
| `GrandPrix` | 命名空间 | 配对 + 验证码 |
| `dusty_gondola` | 3 个埋点 | 引导/横幅实验 |
| `lilac_loom` | 埋点 | 实验项 |
| `YukonSilver` | `setYukonSilverConfig`（ClaudeVM） | VM 配置代号 |
| `smol-bin` | `smol-bin.x64.vhdx` | 微虚拟机镜像 |
| `cai` | `claude.com/cai`、`cai_vast_rain` | Claude.ai 简称 |
| `ancientJournal` | `AutoUpdater_$_ancientJournal` | 更新前会话保活 |
| `buddy` | `claude.buddy`、`hardwareBuddyEnabled` | 配套硬件 |

---

## 13. 附录

### 13.1 核对清单（本册涉及的每项都有实测来源）

| 项 | 值 | 来源 |
|---|---|---|
| 包版本 / 应用版本 | 5.11492.5.0 / 5.11492.5 | manifest + `--version` |
| Electron / Chrome / Node | 45.2.1 / 156.0.8078.75 / 24.22.1 | exe 字符串 |
| `app.asar` | 88,787,202 B / 1,122 条目 | 文件属性 + 头解析 |
| 解包字节 | 133,622,630 | 条目求和 |
| `ion-dist.asar` | 206,568,297 B / 5,399 条目 | 同上 |
| IPC | 107 命名空间 / 2,142 方法 | `xo()` 注册表 |
| 策略键 | 217 | `flatKey` 全量 |
| 主机 / URL | 162 / 1,131 | 全量正则 |
| apiPath / route / event | 841 / 638 / 108 | 渲染层扫描 |
| 技能 | 7 + manifest | 文件清单 |
| 提示词 | 38,771 B | 模板还原 |
| fuse 计数 | 9 | wire + 9 个 `Is*Enabled` 函数 |

### 13.2 脚本索引

| 脚本 | 作用 |
|---|---|
| `asar.js list/cat/extract/grep` | 纯 Node asar 解析（零依赖） |
| `extract-prompt.js <chunk> <KEY> <out>` | 还原长模板字符串 |
| `analyze.js` / `ipc2.js` | IPC / 端点 / 能力面统计 |
| `dump.js <file\|dir> <regex> <out> [win] [max]` | 上下文切片器 |
| `policy.js` / `urls.js` | 策略键 / 端点全量 |
| `verify.js fuses\|xo\|pe\|imports` | fuse 名 / IPC 精算 / 版本串 / 导入表 |
| `recheck.js` | 交叉复算（第二套实现） |
| `gobi.js <exe>` | Go buildinfo 解码 |
| `deep.js tree\|paths\|i18n` | asar 结构 / 路径表 / i18n |

### 13.3 下篇导读

凭据链、认证流、调试入口、Agent 运行时、MCP、沙箱、fuse 与 patch、动态调试、暴露面、复盘账本与未决项 —— 见《下篇 · 机制与操作》。
