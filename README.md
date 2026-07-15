# KSwordSandbox 恶意行为分析沙箱

[![GitStock](https://gitstock.org/KSwordDEV/KSwordSandbox/stock.svg)](https://gitstock.org/KSwordDEV/KSwordSandbox)

KSwordSandbox 是 KSword 项目的 Windows 恶意样本分析沙箱脚手架。v1 设计支持
Hyper-V、VMware 或 QEMU Windows 10 金镜像（golden VM）、干净检查点/快照、
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
  不启动、不还原、不停止、不修改 VM。Hyper-V、VMware 和 QEMU 的 Live 都必须显式选择
  `-Live` 或 WebUI/API 中的 live 操作。
- **禁止提交运行产物。** 不要提交或推送 VM 镜像、样本、报告、job 目录、payload、
  build output、签名驱动、符号、证书、密钥或其他大文件。仓库策略会拒绝这些类别和
  超过 25 MB 的文件。
- **禁止默认签名驱动。** 正常 build、smoke、E2E、文档任务不调用 `CSignTool.exe`，
  也不使用旧 KSword 签名包装器。真实 R0 验证只在隔离 VM 中使用 Windows test mode
  和本地测试证书。

当前 MVP 状态、文档主次关系、架构、模块边界、最短安装/运行链路和驱动测试签名边界见
`docs/current-architecture-and-operations.md`；三种 provider 的入口与等价验收见
`docs/vmware-qemu.md`。完整文档索引和权威 source-of-truth 说明见 `docs/README.md`。

## v1 范围（scope）

- 宿主 Web API，用于规划 sandbox job。
- 为 Windows 10 golden VM 生成 Hyper-V、VMware 或 QEMU runbook。
- 为 VMware `vmrun` 和 QEMU `qemu-system`/`qemu-img` 生成 provider-specific runbook。
- WebUI/API 可显式执行 dry-run 或 live provider-specific runbook。
- VMware/QEMU 来宾操作通过 WinRM PowerShell Remoting 复用相同 Guest Agent 与 artifact 流程；
  VMware 可由 Tools 自动发现恢复后的 IP，QEMU 可由 provider 管理 localhost user-NAT 转发。
- VM 内 Guest Agent 运行样本并输出规范化 JSON 事件。
- 规则引擎把事件映射为行为发现（behavior findings）和初始 MITRE ATT&CK 技术 ID。
- 自包含 HTML 报告渲染。
- 仓库策略脚本阻止大文件、二进制、VM 镜像、报告、样本和 secrets 入库。

虚拟化后端由本机配置的 `virtualization.provider` 选择：`HyperV`（默认）、`VMware` 或
`Qemu`。VMware/QEMU 的 VM 路径、工具路径、WinRM 和 QEMU 设备参数见
`docs/vmware-qemu.md`；默认 profile 路径必须保留在仓库外的 local config 中，WebUI/API/CLI
也可把实际 VMware VMX 或 QEMU 基础磁盘作为单次任务覆盖值，且不会写回配置。
VMware 的完整等价 profile 要求 Workstation Pro 和 `vmware.vmType=ws`；旧 Player profile
会在准备度阶段被拒绝，不会以缺少 full-clone 恢复能力的降级模式进入 Live。
新 VMware/QEMU profile 推荐 `VMwareTools`/`QemuUserNat` 端点模式，只有
`Configured` 模式需要手填 Guest 地址。自动端点固定使用 WinRM HTTPS，golden baseline
需预配 HTTPS listener；实现不会修改宿主机全局 `TrustedHosts`。
`run.ps1 -Mode Analyze`、JobTool、Operator CLI 和 WebUI/API 都使用同一套 provider runbook executor。
QEMU 生命周期使用受管原生 `-pidfile`，状态、桌面验证、baseline 恢复和失败清理都核对同一个
可执行文件/PID 文件/runtime/VM/磁盘身份；外部或歧义进程不会被自动终止。

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

### 先选择操作者路径 / Choose the operator path first

- **路径 A：使用已经配置好的环境。** 适合已经有 `%ProgramData%\KSwordSandbox\install-state.json`、
  仓库外 `sandbox.local.json`、guest password secret、VM profile 和 staged guest payload
  的机器；先跑只读 `Status` / `CheckEnvironment`，再日常启动 WebUI。
- **路径 B：恢复已有 checkpoint/snapshot。** 适合 VM 已存在但需要回到 clean baseline 的实验室；
  先记录 VM/checkpoint 名称和 guest password，准备 payload，再由操作者显式恢复 snapshot。
  恢复 VM 是 lab mutation，不是 packaging/readiness 的默认动作。
- **路径 C：创建或准备新 VM/环境。** 适合第一台电脑或新实验室；先确认 Windows 宿主、
  BIOS/UEFI Intel VT-x / AMD-V、所选 provider 管理工具、Windows guest、`SandboxUser`、
  对应的 PowerShell Direct/WinRM guest transport 和 clean checkpoint/snapshot。

三条路径都不要求 `CSignTool.exe`。VirusTotal（VT）API key 是可选 hash-only enrichment；
缺失时应 quiet-skip。这里的 VT key 不等于 Hyper-V 需要的 Intel VT-x / AMD-V 硬件虚拟化。

### 路径 A：已有配置环境的最短路径

低成本验证（不启动、不还原、不停止 VM；不签名；不生成 fresh live evidence）：

```powershell
.\install.ps1 -Mode Status
.\install.ps1 -Mode CheckEnvironment
.\run.ps1 -Mode Status
.\run.ps1 -Mode CheckEnvironment
.\run.ps1 -Mode Analyze -SamplePreset Notepad
```

日常启动 WebUI：

```powershell
.\run.ps1
```

### 路径 B：已有 VM/checkpoint 的恢复路径

```powershell
.\install.ps1 -Mode Change -UpdateVirtualizationConfig `
  -VirtualizationProvider '<HyperV|VMware|Qemu>' `
  -VmName '<existing VM>' `
  -CheckpointName '<clean checkpoint>' `
  -GuestWorkingDirectory 'C:\KSwordSandbox'
.\install.ps1
.\scripts\Prepare-GuestPayload.ps1 -RepoRoot . -SelfContained
.\install.ps1 -Mode CheckEnvironment
```

只有当操作者明确要恢复 baseline 时才运行 mutating restore：

```powershell
.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -AllowVmMutation -Confirm
```

QEMU per-job overlay 不做原地 restore，也不需要上述变更确认；同一入口会明确返回“干净启动已由
新 overlay 保证”，且不调用 provider stop/restore 命令。QEMU internal snapshot 仍使用上述确认路径。

### 路径 C：新 VM/新环境准备路径

先在所选 provider 中准备 Windows guest、guest 账号、对应 guest transport 和 clean baseline，
再直接运行推荐安装向导；常用设置会在脚本里询问，不需要记推荐参数：

```powershell
.\install.ps1
.\install.ps1 -Mode CheckEnvironment
.\run.ps1 -Mode CheckEnvironment
```

源码仓库运行且缺少 guest payload 时，再按 `CheckEnvironment` 的 “下一步” 提示运行
`.\scripts\Prepare-GuestPayload.ps1 ... -SelfContained`。runtime 便携包默认使用包内
`payload\guest-tools`。

`run.ps1` 默认只启动 WebUI 或生成 PlanOnly runbook，不会启动或还原 VM。三种 provider
的 Live 执行都必须显式使用 CLI `-Live` 或 WebUI/API 中的 live 选项。

同一个根入口可为单次任务覆盖 provider 资源，不写回本机配置：

```powershell
.\run.ps1 -Mode Analyze -SamplePath D:\Temp\sample.exe -Provider VMware `
  -VmName KSword-VMware -BaselineName Clean `
  -MachineDefinitionPath D:\VMs\KSword\KSword.vmx -Live

.\run.ps1 -Mode Analyze -SamplePath D:\Temp\sample.exe -Provider Qemu `
  -VmName KSword-QEMU -MachineDefinitionPath D:\VMs\KSword\base.qcow2 `
  -QemuDiskFormat qcow2 -Live
```

`-BaselineName` 兼容旧 `-SnapshotName`/`-CheckpointName`。QEMU 的默认
per-job overlay profile 会自动使用 `per-job-overlay`，无需传内部 snapshot 名称。

### 安装菜单、凭据和本地配置

```powershell
.\install.ps1
.\run.ps1
```

`install.ps1` 提供交互菜单：安装、修改、卸载、重置 Guest 密码、配置虚拟化 provider、配置
VirusTotal（VT）key、检查环境、启动 WebUI 和查看状态。无参数运行会优先进入推荐安装向导，
逐项询问 runtime root、已有 VM/checkpoint、guest 用户、guest 密码、可选 driver path、
可选 VT key 和是否启动 WebUI。

配置虚拟化环境时，Hyper-V 交互菜单会只读列出本机 VM 和所选 VM 的 checkpoint/snapshot；VMware 会从
当前 VMX 与 `vmrun list` 返回的运行中 VMX 候选中选择，再用 `listSnapshots` 选择 baseline；
QEMU 会对输入的基础磁盘执行 `qemu-img info --output=json`，自动识别格式，并在关闭 per-job
overlay 时列出内部 snapshot。三者都支持编号选择并保存本机配置，查询失败时仍可手动输入。
这些步骤不会启动、停止、还原或修改 VM；provider 命令也不会继承 guest/VT secret 环境变量。

自动化/CI 或无人值守实验室才需要显式参数，例如 `.\install.ps1 -InstallEntrypoint CreateOrPreparePath -PlanOnly`
做只读预览，或用 `.\install.ps1 -Mode Change -UpdateVirtualizationConfig ...` 写入脚本化配置。

安装器会把 `KSWORDBOX_GUEST_PASSWORD` 保存在当前用户环境中（仓库外），可写入
DPAPI 保护的本地备份，并在 `D:\Temp\KSwordSandbox\config\sandbox.local.json` 写本机
sandbox config，同时为 Web/API 设置 `Sandbox__ConfigPath`。

更新 VM 名称、checkpoint 或 guest 路径时，不要改模板，使用本地配置命令：

```powershell
.\install.ps1 -Mode Change -UpdateVirtualizationConfig `
  -VirtualizationProvider '<HyperV|VMware|Qemu>' `
  -VmName 'KSwordSandbox-Win10-Golden' `
  -CheckpointName 'Clean' `
  -GuestWorkingDirectory 'C:\KSwordSandbox'
```

重置实际 VM `SandboxUser` 密码并同步宿主 secret。VMware/QEMU 的普通轮换使用当前 secret
通过 WinRM 改密、验证并创建替换 baseline；Hyper-V、QEMU 与 VMware Workstation Pro 还支持
未知旧密码的离线 VHDX 恢复（VMware 使用隔离 full clone），旧 baseline 均保留：

```powershell
.\install.ps1 -Mode Change -ResetGuestVmPassword -GeneratePassword -Force

# QEMU 当前密码未知
.\install.ps1 -Mode Change -VirtualizationProvider Qemu `
  -ResetGuestVmPassword -RecoverGuestVmPasswordWithoutCurrentSecret `
  -GeneratePassword -Force

# VMware Workstation Pro 当前密码未知
.\install.ps1 -Mode Change -VirtualizationProvider VMware -VMwareVmType ws `
  -ResetGuestVmPassword -RecoverGuestVmPasswordWithoutCurrentSecret `
  -GeneratePassword -Force
```

### 虚拟化和 R0 本地实验配置

只记录本地 test-signed `.sys` 路径，不执行签名：

```powershell
.\install.ps1 -Mode Change -UpdateVirtualizationConfig -DriverHostPath 'D:\Temp\KSwordSandbox\build\r0-driver\Release\KSword.Sandbox.Driver.sys'
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

安装/发布准备的低成本验证链路：

```powershell
# 仓库策略：不启动 VM，不签名驱动。
.\scripts\Test-RepositoryPolicy.ps1

# 安装/运行只读状态：不启动、不还原、不停止 VM。
.\install.ps1 -Mode Status
.\install.ps1 -Mode CheckEnvironment
.\run.ps1 -Mode Status
.\run.ps1 -Mode CheckEnvironment

# PlanOnly 分析：不执行样本，不修改 VM。
.\run.ps1 -Mode Analyze -SamplePreset Notepad

# WebUI 启动预览：不启动 dotnet，不触碰 VM。
.\run.ps1 -Mode StartWebUI -WhatIf
```

构建、native compile、smoke 和 WebUI/API E2E 是更深的开发或实验室验证，不是安装/发布准备
默认步骤；需要时按 `docs/verification.md` 显式执行。当前 driver validation 应止步于
compile success。不要使用 `CSignTool.exe`；不要提交 `bin/`、`obj/`、`x64/`、`.sys`、
`.pdb`、`.obj` 或 native build 输出。

WebUI/API E2E：

脚本默认使用与浏览器相同的后台 runbook runner，并在 summary 中记录
`executionTransport=Background`、`backgroundState`、guest import 三态及终态 provider 资源身份；
`-ExecutionTransport Blocking` 仅保留给旧阻塞 API 兼容检查。

```powershell
# Safe：不启动 VM，不修改 VM 状态。
.\scripts\Invoke-WebUIApiE2E.ps1 `
  -BaseUrl 'http://127.0.0.1:18082' `
  -DurationSeconds 3 `
  -StepTimeoutSeconds 120

# Live：会还原/启动配置的 VM 并运行样本，只能在就绪检查（readiness）通过后执行。
.\scripts\Invoke-WebUIApiE2E.ps1 `
  -BaseUrl 'http://127.0.0.1:18082' `
  -Provider VMware `
  -VmName 'KSword-VMware' `
  -BaselineName 'Clean' `
  -MachineDefinitionPath 'D:\VMs\KSword\KSword.vmx' `
  -Live `
  -DurationSeconds 3 `
  -StepTimeoutSeconds 900
```

`-Provider HyperV|VMware|Qemu` 与 WebUI 的 provider 选择完全相同；QEMU 可再传
`-MachineDefinitionPath <base-disk>` 和 `-QemuDiskFormat qcow2|raw|vhdx|vmdk`。
发布级等价声明还必须让三次 Live 使用同一 commit、同一样本字节和时长，分别保存 summary，
再由只读 `scripts\Test-ProviderParityEvidence.ps1` 生成
`schema=ksword.provider-parity-evidence.v1`、`validated=true` 的聚合证据；完整命令见
`docs/verification.md`。

已记录的本地 real-R0 WebUI/API **历史验证证据**见 `docs/webui-real-r0-e2e.md`；该记录完成了
17/17 个 Hyper-V runbook step，导入 guest/R0 事件，生成默认/中文/英文 HTML 报告，并且没有
调用 `CSignTool.exe`。它不是当前候选版本的 fresh live evidence；如果发布前未重新跑实验室
live job，release notes 必须明确写“本候选未刷新 fresh live evidence”。

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
并生成 zip。`Publish-RuntimePayloads.ps1` 是 release-manager/source checkout 入口；
便携 runtime 包内只消费已发布 payload，不在包内重新构建：

```powershell
.\scripts\Publish-RuntimePayloads.ps1 `
  -RuntimePublishRoot 'D:\Temp\KSwordSandbox\publish'
.\scripts\package-portable.ps1 -PackageKind source -OutputRoot 'D:\Temp\KSwordSandbox\packages'
.\scripts\package-portable.ps1 -PackageKind runtime -RuntimePublishRoot 'D:\Temp\KSwordSandbox\publish' -RequireCompleteRuntimePayloads -OutputRoot 'D:\Temp\KSwordSandbox\packages'
```

清单默认排除样本、VM 镜像/检查点、runtime reports、captures、构建中间产物、符号、本机
config/secrets 和私有签名材料。脚本只做本地 staging/zip，不 push、不发布；上传发布仍是
release manager 明确执行的独立步骤。详见 `docs/release.md`。
`Publish-RuntimePayloads.ps1` 只发布到仓库外 `RuntimePublishRoot`，不启动/还原 VM、
不签名 driver、不调用 `CSignTool.exe`；guest-tools 仍委托现有
`Prepare-GuestPayload.ps1` 生成 Agent/R0Collector payload。Managed host tools
默认按 self-contained 发布，便携包目标机不需要预装 .NET runtime；只有明确接受瘦包依赖时才用
`-FrameworkDependentManaged`。

Open-source MVP 发布前使用 `docs/release.md` 的发布就绪清单（readiness checklist）：确认所选 provider live
前置条件、BIOS/UEFI Intel VT-x / AMD-V 设置、可选 VirusTotal 仅哈希（hash-only）配置、artifact（证据/产物）
排除、仓库策略、无 `CSignTool.exe` 默认路径，以及真实 R0 仍受 test-signing/隔离 VM 限制。
真实 5 秒 Notepad 报告的最短 live 验证命令也记录在那里：

```powershell
.\run.ps1 -Mode Analyze -SamplePreset Notepad -DurationSeconds 5 -Live
```

该命令会操作本机配置所选 provider 的 golden VM；输出报告保存在 runtime root 的 job 目录中，不要提交到 git。

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

`Status` 会按当前 provider 只读检查管理工具、VM 定义/快照、guest password presence、
host/guest test-signing guidance、driver path/signature/service/minifilter 状态、payload 和 WebUI
启动目标。密码和 API key 只显示是否存在，值不会打印。

便携 runtime 包由 `scripts\package-portable.ps1` 根据 `packaging\runtime-package.manifest.json`
生成；它从仓库复制 docs/config/rules/wrappers，从外部 `RuntimePublishRoot` 复制 `app/host-web`
等发布产物。清单和脚本会排除本机 secret、`sandbox.local.json`、`install-state.json`、DPAPI 备份、
样本、报告、VM 磁盘/快照、仓库 `bin/obj/x64` 二进制和签名材料；脚本只做 staging/zip，
不调用外部发布或签名工具，也不 push。

准备完整 runtime handoff 时，先在源码仓库生成外部 publish root；便携 runtime 包内
不会包含源码项目，也不要求操作者重新运行 publish：

```powershell
.\scripts\Publish-RuntimePayloads.ps1 -RuntimePublishRoot 'D:\Temp\KSwordSandbox\publish'
.\scripts\Test-ReleaseReadiness.ps1 -AllowDirtySource -RuntimePublishRoot 'D:\Temp\KSwordSandbox\publish' -RequireCompleteRuntimePackage
```

源码仓库运行时 `run.ps1` 使用 Web 项目；便携包运行时自动使用 `app\host-web\KSword.Sandbox.Web.exe`
或 `.dll`。若操作者直接从 `app\host-web` 启动 WebUI，程序也会向上识别包含
`config\sandbox.example.json` 和 `rules\behavior-rules.json` 的包根目录。默认 `.\run.ps1`
仍只启动 WebUI，不启动/还原 VM；任何 provider 的 Live 都必须显式选择。
