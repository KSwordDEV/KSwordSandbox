# KSwordSandbox 恶意行为分析沙箱

[![GitStock](https://gitstock.org/KSwordDEV/KSwordSandbox/stock.svg)](https://gitstock.org/KSwordDEV/KSwordSandbox)

KSwordSandbox 是 KSword 项目的 Windows 恶意样本分析沙箱脚手架。v1 设计以
Hyper-V Windows 10 金镜像（golden VM）、干净检查点（clean checkpoint）、
来宾侧采集器（Guest Agent）、可选 KSword R0 驱动事件导出，以及宿主侧
JSON/HTML 报告为主线。

本仓库只保存源码、规则、配置模板和文档。样本、VM 磁盘、报告、构建输出、
签名驱动、符号文件、证书和凭据必须留在 git 仓库之外。

## 项目边界与安全承诺（guardrails）

- **公益安全项目（public-benefit security project）。** KSwordSandbox 面向本地、
  已授权的恶意样本分析研究、教育和防御工程。
- **本地优先（local first）。** 默认情况下，样本和报告只保存在操作者机器的
  runtime root 下，通常是 `D:\Temp\KSwordSandbox`。WebUI 的“上传”只是把可执行
  文件保存到这个本地 runtime 目录，不是上传到外部服务。
- **默认不上传样本。** 可选 VirusTotal（VT）集成是 **hash-only**：只查 SHA-256，
  不上传样本字节。
- **默认安全（safe by default）。** 普通计划（PlanOnly）和 dry-run 只记录意图，
  不启动、不还原、不停止、不修改 VM。Live Hyper-V 必须显式选择 `-Live` 或 WebUI/API
  中的 live 操作。
- **禁止提交运行产物。** 不要提交或推送 VM 镜像、样本、报告、job 目录、payload、
  build output、签名驱动、符号、证书、密钥或其他大文件。仓库策略会拒绝这些类别和
  超过 25 MB 的文件。
- **禁止默认签名驱动。** 正常 build、smoke、E2E、文档任务不调用 `CSignTool.exe`，
  也不使用旧 KSword 签名包装器。真实 R0 验证只在隔离 VM 中使用 Windows test mode
  和本地测试证书。

当前 MVP 状态、文档主次关系、架构、模块边界、最短安装/运行链路、驱动测试签名边界和
Hyper-V live 流程见 `docs/current-architecture-and-operations.md`。完整文档索引和权威
source-of-truth 说明见 `docs/README.md`。

## v1 范围（scope）

- 宿主 Web API，用于规划 sandbox job。
- 为 Windows 10 golden VM 生成 Hyper-V runbook。
- WebUI/API 可显式执行 dry-run 或 live Hyper-V runbook。
- VM 内 Guest Agent 运行样本并输出规范化 JSON 事件。
- 规则引擎把事件映射为行为发现（behavior findings）和初始 MITRE ATT&CK 技术 ID。
- 自包含 HTML 报告渲染。
- 仓库策略脚本阻止大文件、二进制、VM 镜像、报告、样本和 secrets 入库。

## 目录结构（layout）

```text
config/                         仅配置模板
docs/                           操作与开发 runbook
driver/KSword.Sandbox.Driver/   WDK R0 事件驱动源码骨架
guest/KSword.Sandbox.Agent/     VM 内采集器
guest/KSword.Sandbox.R0Collector/
                                驱动 IOCTL 到 JSONL 的用户态桥
rules/                          行为规则与静态规则种子
scripts/                        构建、smoke、仓库策略和 Hyper-V 辅助脚本
src/KSword.Sandbox.Abstractions 共享模型与契约
src/KSword.Sandbox.Core         规划、规则、报告和服务
src/KSword.Sandbox.Web          宿主 WebUI/API
tests/KSword.Sandbox.SmokeTests 控制台 smoke/contract tests
```

## 快速开始（quick start）

### 部署模式选择

- **本地演示 / PlanOnly：** 适合先验证 WebUI、API、规则和报告链路；不启动 VM。
- **Live Hyper-V 实验室：** 需要管理员 PowerShell、已准备的 golden VM、clean checkpoint、
  guest 凭据、Guest Service Interface、PowerShell Direct 和 staged guest payload。
- **真实 R0 驱动实验：** 不属于默认路径。先完成 compile-only，再在隔离 VM 内 test-sign
  并加载；不要把 `.sys`、`.pdb`、证书或签名材料放入仓库。

### 已有 golden VM 的最短路径

```powershell
.\install.ps1 -Mode Install -PromptPassword
.\run.ps1
```

安装完成后，日常启动 WebUI 只需要：

```powershell
.\run.ps1
```

`run.ps1` 默认只启动 WebUI，不会启动或还原 VM。Live Hyper-V 执行仍然必须显式使用
CLI `-Live` 或 WebUI/API 中的 live 选项。

### 安装菜单、凭据和本地配置

```powershell
.\install.ps1
.\run.ps1
dotnet build .\KSwordSandbox.sln
.\scripts\Invoke-SandboxSmokeTest.ps1
```

`install.ps1` 提供交互菜单：安装、修改、卸载、重置 Guest 密码、配置 Hyper-V、配置
VirusTotal（VT）key、检查环境、启动 WebUI 和查看状态。无交互本地实验室安装可使用：

```powershell
.\install.ps1 -Mode Install -GeneratePassword
```

已有 golden VM 时推荐使用人工输入的 guest 密码：

```powershell
.\install.ps1 -Mode Install -PromptPassword
```

安装器会把 `KSWORDBOX_GUEST_PASSWORD` 保存在当前用户环境中（仓库外），可写入
DPAPI 保护的本地备份，并在 `D:\Temp\KSwordSandbox\config\sandbox.local.json` 写本机
sandbox config，同时为 Web/API 设置 `Sandbox__ConfigPath`。

更新 VM 名称、checkpoint 或 guest 路径时，不要改模板，使用本地配置命令：

```powershell
.\install.ps1 -Mode Change -UpdateHyperVConfig `
  -VmName 'KSwordSandbox-Win10-Golden' `
  -CheckpointName 'Clean' `
  -GuestWorkingDirectory 'C:\KSwordSandbox'
```

同步未知 VM `SandboxUser` 密码到宿主 secret（需要 elevated shell）：

```powershell
.\install.ps1 -Mode Change -ResetGuestVmPassword -GeneratePassword -Force
```

### Hyper-V 和 R0 本地实验配置

只记录本地 test-signed `.sys` 路径，不执行签名：

```powershell
.\install.ps1 -Mode Change -UpdateHyperVConfig -DriverHostPath 'D:\Temp\KSwordSandbox\build\r0-driver\Release\KSword.Sandbox.Driver.sys'
.\install.ps1 -Mode Change -QueryGuestTestSigning
.\install.ps1 -Mode Change -EnableGuestTestSigning -RestartGuestAfterTestSigning -Force
```

`-DriverHostPath` 只写本机路径；`install.ps1`/`run.ps1` 不调用 `CSignTool.exe`。
Test-signing 命令只影响配置的 guest VM。验证结束后恢复 clean checkpoint。

### 环境检查和 VirusTotal（VT）配置

不改变状态地检查本机发布/运行就绪状态（readiness）：

```powershell
.\install.ps1 -Mode CheckEnvironment
.\run.ps1 -Mode CheckEnvironment
```

可选 VirusTotal hash-only 查询读取 `KSWORDBOX_VIRUSTOTAL_API_KEY`（Process/User/Machine）。
配置时不会打印 key：

```powershell
.\install.ps1 -Mode ConfigureVTKey -PromptVTKey
```

未配置 VT key 时应保持低噪音：UI/API 返回 `not_configured`，不写 job message、规则证据
或 enrichment event。详见 `docs/virustotal.md`。

### 日常运行与一键分析

`run.ps1` 是安装后的日常入口：它会启动 WebUI，设置 `Sandbox__ConfigPath`，把本机可见的
Guest 密码和可选 VT key 镜像到 WebUI 进程，并按需准备 `guestPayloadRoot` 下的自包含
Guest Agent/R0Collector payload。WebUI payload 准备默认 best-effort；需要失败即退出时使用：

```powershell
.\run.ps1 -RequirePayloadForWebUI
```

内置分析快捷命令：

```powershell
.\run.ps1 -Mode Analyze -SamplePreset Notepad
.\run.ps1 -Mode Analyze -SamplePreset HarmlessSample
.\run.ps1 -Mode Analyze -SamplePreset Notepad -Live
```

中文提示：不加 `-Live` 时 `Analyze` 只生成计划，不启动、不还原、不停止 VM。
`HarmlessSample` 会发布到 `D:\Temp\KSwordSandbox\samples\...` 或配置的 `RuntimeRoot` 下，
始终保持在仓库外。`run.ps1` 不在命令行提示明文密码，只读取并传递本机环境变量中的 secret。

直接规划一个 dry-run job：

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri http://localhost:5000/api/jobs/plan `
  -ContentType 'application/json' `
  -Body '{"samplePath":"D:\\Temp\\sample.exe","durationSeconds":120,"dryRun":true}'
```

报告默认写到：

```text
D:\Temp\KSwordSandbox\jobs\<job-id>\
```

不要把这些 job、report、event、artifact 输出提交到 git。

## 部署产品化说明（productionization notes）

当前项目优先支持单机本地实验室。若要作为团队服务或长期运行环境部署，请至少明确：

- WebUI/API 监听地址、端口和防火墙策略；默认建议只绑定本机或受控内网。
- 访问控制、样本提交权限、报告下载权限和审计日志；不要把 WebUI 直接暴露到公网。
- runtime root 的容量、保留周期和清理策略；样本、报告、PCAP、dump 和 VM 输出可能快速增长。
- Golden VM 生命周期：谁能更新 baseline、何时创建 `Clean` checkpoint、Live 后如何恢复。
- 凭据/密钥轮换：`KSWORDBOX_GUEST_PASSWORD`、`KSWORDBOX_VIRUSTOTAL_API_KEY`、本地证书和
  test-signing 状态都应有所有者。
- 真实 R0 场景应隔离到专用 VM/host；默认业务验证使用 mock collector 或 compile-only。

## 验证命令（verification）

常用安全验证链路：

```powershell
# 文档/仓库策略：不启动 VM，不签名驱动。
.\scripts\Test-RepositoryPolicy.ps1

# 快速离线质量门：不启动 VM，不加载驱动。
.\scripts\Test-QualityGates.ps1

# .NET 构建与全量 smoke。
dotnet build .\KSwordSandbox.sln
dotnet run --project .\tests\KSword.Sandbox.SmokeTests\KSword.Sandbox.SmokeTests.csproj --no-build

# Native compile-only：只验证能编译，不签名、不安装、不启动驱动。
.\scripts\Invoke-NativeBuild.ps1 -Project .\KSwordSandbox.sln -Configuration Debug -Platform x64
```

`Invoke-NativeBuild.ps1` 会规范化子 MSBuild 环境，避免父 shell 同时存在 `PATH` 与 `Path` 时
Visual C++ task 失败。当前 driver validation 应止步于 compile success。不要使用
`CSignTool.exe`；不要提交 `bin/`、`obj/`、`x64/`、`.sys`、`.pdb`、`.obj` 或 native build 输出。

WebUI/API E2E：

```powershell
# Safe：不启动 VM，不修改 VM 状态。
.\scripts\Invoke-WebUIApiE2E.ps1 `
  -BaseUrl 'http://127.0.0.1:18082' `
  -DurationSeconds 3 `
  -StepTimeoutSeconds 120

# Live：会还原/启动配置的 VM 并运行样本，只能在就绪检查（readiness）通过后执行。
.\scripts\Invoke-WebUIApiE2E.ps1 `
  -BaseUrl 'http://127.0.0.1:18082' `
  -Live `
  -DurationSeconds 3 `
  -StepTimeoutSeconds 900
```

已记录的本地 real-R0 WebUI/API 验证证据见 `docs/webui-real-r0-e2e.md`；该记录完成了
17/17 个 Hyper-V runbook step，导入 guest/R0 事件，生成默认/中文/英文 HTML 报告，并且没有
调用 `CSignTool.exe`。

更多命令见 `docs/verification.md`。

## 仓库策略（repository policy）

提交前运行：

```powershell
.\scripts\Test-RepositoryPolicy.ps1
```

可安装本地 pre-commit hook：

```powershell
.\scripts\Install-GitHooks.ps1
```

策略会拒绝 VM 镜像、编译二进制、符号文件、PDF、压缩包、样本、runtime reports、secrets
和超过 25 MB 的文件。本任务/默认流程不 push；只有用户明确要求时才推送远端。

## 发布包装草案（release packaging）

发布包装清单位于 `packaging/source-package.manifest.json` 和
`packaging/runtime-package.manifest.json`。使用本地 portable package 脚本在仓库外 staging
并生成 zip：

```powershell
.\scripts\package-portable.ps1 -PackageKind source -OutputRoot 'D:\Temp\KSwordSandbox\packages'
.\scripts\package-portable.ps1 -PackageKind runtime -RuntimePublishRoot 'D:\Temp\KSwordSandbox\publish' -OutputRoot 'D:\Temp\KSwordSandbox\packages'
```

清单默认排除样本、VM 镜像/检查点、runtime reports、captures、构建中间产物、符号、本机
config/secrets 和私有签名材料。脚本只做本地 staging/zip，不 push、不发布；上传发布仍是
release manager 明确执行的独立步骤。详见 `docs/release.md`。

Open-source MVP 发布前使用 `docs/release.md` 的发布就绪清单（readiness checklist）：确认 Hyper-V live
前置条件、BIOS/UEFI Intel VT-x / AMD-V 设置、可选 VirusTotal 仅哈希（hash-only）配置、artifact（证据/产物）
排除、仓库策略、无 `CSignTool.exe` 默认路径，以及真实 R0 仍受 test-signing/隔离 VM 限制。
真实 5 秒 Notepad 报告的最短 live 验证命令也记录在那里：

```powershell
.\run.ps1 -Mode Analyze -SamplePreset Notepad -DurationSeconds 5 -Live
```

该命令会操作已配置的 Hyper-V golden VM；输出报告保存在 runtime root 的 job 目录中，不要提交到 git。

## Hyper-V 前提（assumptions）

默认配置期望本机存在 golden VM：

- VM 名称：`KSwordSandbox-Win10-Golden`
- Clean checkpoint：`Clean`
- Guest 用户：通常为 `SandboxUser`
- Guest 工作目录：通常为 `C:\KSwordSandbox`
- Runtime root：通常为 `D:\Temp\KSwordSandbox`

主机需要启用 Hyper-V，并在 BIOS/UEFI 中启用硬件虚拟化扩展（Intel VT-x / AMD-V；这里不要
和 VirusTotal 的 VT 简写混淆）。编辑本机 local config，不要提交本机凭据或 VM 路径。

## 驱动集成边界（driver / R0）

R0 driver 默认只作为未签名本地产物编译验证。只有可选真实驱动 VM 验证才应该在仓库外使用
Windows test mode 和本地测试证书 test-sign `.sys`，再复制或 stage 到 guest。Guest Agent 可以
从配置路径读取 driver JSON Lines 事件。v1 scaffold 不复制外部 KSword 源码树，也不提交驱动
二进制或签名材料。

当前 R0 源码路径包含 WDK control-device skeleton：
`driver/KSword.Sandbox.Driver/`，以及用户态 JSONL bridge skeleton：
`guest/KSword.Sandbox.R0Collector/`。这些都是 source-only scaffold；生成的 `.sys`、`.exe`、
符号、证书和 native build output 必须保持 ignored 且不入库。

## 参考资料（references）

设计参考和平台文档见 `docs/research-basis.md`。初始 scaffold 参考 CAPE、Cuckoo、DRAKVUF、
MITRE ATT&CK for Windows、Hyper-V PowerShell Direct、`Copy-VMFile` 和 Windows driver callback
文档。

报告结构、当前实现状态、R0 复用边界和后续工程步骤的简明说明见
`docs/extracted-results-summary.md`。

## 产品化/便携包装起步

中文优先：安装和运行入口已经按“本机状态 + 一键 WebUI + 显式 Live”组织。常用检查：

```powershell
.\install.ps1 -Mode Status
.\install.ps1 -Mode CheckEnvironment
.\run.ps1 -Mode Status
.\run.ps1
```

`Status` 会只读检查 Hyper-V module、VM/checkpoint、VM profile、guest password presence、
host/guest test-signing guidance、driver path/signature/service/minifilter 状态、payload 和 WebUI
启动目标。密码和 API key 只显示是否存在，值不会打印。

便携 runtime 包由 `scripts\package-portable.ps1` 根据 `packaging\runtime-package.manifest.json`
生成；它从仓库复制 docs/config/rules/wrappers，从外部 `RuntimePublishRoot` 复制 `app/host-web`
等发布产物。清单和脚本会排除本机 secret、`sandbox.local.json`、`install-state.json`、DPAPI 备份、
样本、报告、VM 磁盘/快照、仓库 `bin/obj/x64` 二进制和签名材料；脚本只做 staging/zip，
不调用外部发布或签名工具，也不 push。

源码仓库运行时 `run.ps1` 使用 Web 项目；便携包运行时自动使用 `app\host-web\KSword.Sandbox.Web.exe`
或 `.dll`。默认 `.\run.ps1` 仍只启动 WebUI，不启动/还原 VM；Live Hyper-V 必须显式选择。
