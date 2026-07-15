# 本地安装与凭据处理 / Local install and credential handling

本页中文优先。命令参数名（如 `-Mode`、`-PromptPassword`）和机器可读
JSON key（如 `RecommendedActions`、`SecretValuePrinted`）保持英文，不翻译。

当前安装向导和 `Status`/`CheckEnvironment` 支持 `HyperV`、`VMware`、`Qemu`；通用配置命令是
`-UpdateVirtualizationConfig`。本页后半的 Hyper-V feature、VMConnect、PowerShell Direct 和 guest
transport 细节仍包含 Hyper-V 专项维护说明；三种 provider 共用的 guest test-signing 入口见本页及
[`driver-signing.md`](driver-signing.md)，VMware/QEMU 参数见 [`vmware-qemu.md`](vmware-qemu.md)。

普通用户遇到错误时，先看脚本输出里的“下一步”。常见修复顺序：

1. 新电脑或普通用户直接运行 `.\install.ps1`，按推荐安装向导回答常用设置：
   runtime root、provider/VM/clean baseline、guest 用户、guest 密码、可选 R0 driver path、
   可选 VirusTotal key、是否启动 WebUI。
2. 只想查看缺口时，运行 `.\install.ps1 -Mode CheckEnvironment`；该命令不会启动、
   还原或停止 VM，也不会打印密码/API key。
3. 自动化/CI 才需要显式参数，例如
   `.\install.ps1 -InstallEntrypoint CreateOrPreparePath -PlanOnly` 做只读预览，或
   `.\install.ps1 -Mode Change -UpdateVirtualizationConfig -VirtualizationProvider <HyperV|VMware|Qemu> -VmName <VM> -CheckpointName <CleanBaseline>` 写入脚本化配置。
   QEMU 的加速、网络和设备参数可用
   `-QemuMemoryMegabytes 4096 -QemuAdditionalArguments @('-accel','whpx')` 保存到本机配置。
   VMware 推荐 `-GuestRemotingAddressMode VMwareTools`，QEMU 推荐
   `-GuestRemotingAddressMode QemuUserNat`；只有 `Configured` 模式需要
   `-GuestRemotingAddress`。两种自动模式固定要求 `-GuestRemotingUseSsl`，自签名实验室
   listener 通常还需 `-GuestRemotingSkipCertificateChecks`；baseline 必须预配 WinRM HTTPS，
   安装器不会扩大宿主机全局 `TrustedHosts`。
4. 缺少 Guest Agent/R0Collector payload 时，运行
   `.\scripts\Prepare-GuestPayload.ps1 -RepoRoot . -PayloadRoot <payloadRoot> -GuestWorkingDirectory <guestRoot> -SelfContained`。
5. 真实 R0 采集缺少 driver path 时，运行
   `.\install.ps1 -Mode Change -UpdateVirtualizationConfig -DriverHostPath <test-signed .sys>`；
   只验证链路时可在本机 `sandbox.local.json` 设置
   `driver.useMockCollector=true`。

英文摘要 / English summary：安装器只准备本机操作者状态和本机密钥；它不签名
driver，不使用 GUI signing fallback，不调用 `CSignTool.exe`，也不会把 secret 写进 git。
`Status` / `CheckEnvironment` 只产生中文优先的本机诊断，不启动 live、不生成 `job id`，
也不能作为 release notes 的 fresh live evidence。

`install.ps1` 用于准备 KSwordSandbox 的本机操作者设置，目标环境是实验室宿主机或
贡献者工作站，不是把凭据提交到仓库的入口。

安装器只负责两个本机维度：

1. PowerShell Direct/WinRM 使用的 guest credential 本机存储；
2. host/guest provider 配置，例如 VM 名称、干净 baseline、guest 工作目录、
   runtime root，以及本地 Web/API config 路径。

## 操作者安装路径 / Operator onboarding paths

先选路径，再执行命令。不要把日常启动、恢复 checkpoint/snapshot、首次创建 VM
混成一条“万能安装”流程。下面的验证命令都是低副作用：不启动、不还原、不停止 VM，
不签名 driver，不调用 `CSignTool.exe`，不上传样本，也不会生成 fresh live evidence。

release UX 约定 / release UX contract：

- `.\install.ps1` 和 `.\scripts\install.ps1` 的入口选择菜单只帮助操作者选择语义路径；
  菜单选择“恢复 checkpoint”默认仍只是计划/诊断，不会真实还原 VM。
- 这三种入口是固定 contract：`UseConfiguredEnvironment`、`RestoreCleanCheckpoint`、
  `CreateOrPreparePath`。`scripts\Test-ReleaseReadiness.ps1` 会静态解析根安装器和
  `scripts\` 包装器，检查 `ValidateSet` 是否完整、wrapper 是否转发这些参数、
  `RestoreCleanCheckpoint` 的真实 provider restore 是否同时受 `-AllowVmMutation` 和
  `ShouldProcess` 保护，以及 manifest 的 `operatorModeMatrix` 是否与实现一致；这些检查不执行安装模式。
- `UseConfiguredEnvironment` 是只读状态确认：读取已安装的本机配置、secret presence、
  VM/baseline profile 和 payload 状态，不写本机状态、不提示或保存 secret、不修改
  VM；按当前 provider 执行只读 Hyper-V、`vmrun` 或 `qemu-img` profile 查询。
- `RestoreCleanCheckpoint` 是 rollback 语义：默认 `-PlanOnly`/safe diagnostics；
  真实还原必须在隔离 lab host 上显式使用
  `-AllowVmMutation`，并再加 `-Confirm` 或 `-Force`；`-Force` 只是无人值守确认路径，
  仍必须经过 `ShouldProcess`。QEMU `useOverlayDisk=true` 是明确例外：下一次 Live 本来就从
  未修改基础盘创建新 overlay，入口会返回 `BaselineRestoreSatisfiedWithoutMutation=true`，
  不调用 stop/restore，也不要求 `-AllowVmMutation`/`-Confirm`。
- 安装器参数 `-CheckpointName` 保留给既有脚本，同时接受 provider-neutral
  `-BaselineName` 和 VMware 常用的 `-SnapshotName` 别名；三者写入同一个干净基线字段。
- `CreateOrPreparePath` 是 fresh new-computer 本机准备：只写仓库外目录、local config、
  secret 和可选 payload；它不创建任何 provider VM，也不创建 checkpoint/snapshot。可选 payload
  准备必须落在配置的仓库外 `GuestPayloadRoot` / runtime root，不复制到 git。

### 首台机器前置条件与兼容性 / First-computer prerequisites and compatibility

- Host OS：三种 Live provider 都要求 Windows 宿主。Hyper-V 路径需要支持 Hyper-V 的
  Windows 10/11 Pro、Enterprise、Education 或 Windows Server；Windows Home 不能作为
  Hyper-V host。VMware/QEMU 路径分别要求该 Windows 版本可运行 VMware Workstation Pro
  或 QEMU。
- BIOS/UEFI：必须启用硬件虚拟化 Intel VT-x / AMD-V，并具备 SLAT/EPT/NPT。
  这不是 VirusTotal 的 VT key；VirusTotal key 只是可选 hash-only enrichment。
- Provider 工具：Hyper-V 安装 feature 和 PowerShell module；VMware 安装 `vmrun`；QEMU
  安装 `qemu-system-x86_64` 与 `qemu-img`。Hyper-V live 和部分只读 Hyper-V 查询需要管理员
  PowerShell；VMware/QEMU host shell 默认不要求提权，但必须能管理其启动的 VM 进程。
- Windows 功能：Hyper-V 要求 `Microsoft-Hyper-V-All=Enabled`；QEMU 的等价加速路径固定使用
  WHPX，因此要求 `HypervisorPlatform=Enabled`；VMware 不绑定某个固定 Windows Optional
  Feature。功能状态读取优先使用 `Get-WindowsOptionalFeature`，权限不足或命令不可用时只读回退到
  `Win32_OptionalFeature`，两种方式都无法确认时不会声明 `LiveReady`。
- Runtime 位置：runtime root、payload、样本、job、报告、VM 磁盘/快照、`.sys`、
  `.pdb`、证书、PFX 和本机 config/secret 都必须在 git 仓库外，例如
  `D:\Temp\KSwordSandbox`。
- VM 兼容性：Live 路径需要 Windows guest、`SandboxUser` 或等价本地管理员账号和一个 clean
  checkpoint/snapshot/overlay baseline。Hyper-V 使用 PowerShell Direct 和 Guest Service
  Interface（来宾服务接口）；VMware/QEMU 使用 WinRM。源码仓库运行 WebUI 需要本机 .NET SDK；便携 runtime 包默认使用包内
  self-contained `app\host-web` 发布产物，不要求目标机预装 .NET runtime（除非发布时显式选择
  `-FrameworkDependentManaged`）。

### 路径 A：使用已经配置好的环境 / Use an already configured environment

适用于 `%ProgramData%\KSwordSandbox\install-state.json`、仓库外
`sandbox.local.json`、guest password secret、VM profile 和 payload 已经存在的机器。

```powershell
.\install.ps1 -InstallEntrypoint UseConfiguredEnvironment -PlanOnly
.\install.ps1 -Mode Status
.\install.ps1 -Mode CheckEnvironment
.\run.ps1 -Mode Status
.\run.ps1 -Mode CheckEnvironment
.\run.ps1 -Mode Analyze -SamplePreset Notepad
```

`Analyze` 未加 `-Live` 时只是 PlanOnly，适合作为低成本安装验证。以上检查通过后，
日常只启动 WebUI：

```powershell
.\run.ps1
```

### 路径 B：恢复已有干净基线 / Restore an existing clean baseline

适用于 VM 已存在、但需要回到 clean baseline 的实验室。先只记录/确认要使用的 VM
和 provider baseline 名称，不要修改仓库模板：

```powershell
.\install.ps1 -Mode Change -UpdateVirtualizationConfig `
  -VirtualizationProvider '<HyperV|VMware|Qemu>' `
  -VmName '<existing VM>' `
  -CheckpointName '<clean baseline>' `
  -GuestWorkingDirectory 'C:\KSwordSandbox'
.\install.ps1
.\scripts\Prepare-GuestPayload.ps1 -RepoRoot . -SelfContained
.\install.ps1 -Mode CheckEnvironment
.\run.ps1 -Mode CheckEnvironment
```

如果 VM 已经漂移，实际恢复 Hyper-V checkpoint、VMware snapshot 或 QEMU internal snapshot
是明确的 lab mutation。先预览；
`-WhatIf` 即使带 `-AllowVmMutation` 也不得调用 `Restore-VMSnapshot`、启动、停止或修改 VM。
确认隔离 lab 后，才由操作者显式执行：

```powershell
.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -AllowVmMutation -WhatIf
.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -AllowVmMutation -Confirm
.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -AllowVmMutation -Force
```

QEMU per-job overlay 无需原地恢复；直接运行
`.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -Json` 会返回
`BaselineIsolationMode=qemu-per-job-overlay` 和 `BaselineRestoreSatisfiedWithoutMutation=true`，
不会获取 live lease 或调用 provider VM 命令。

真实 baseline restore、实际 guest 密码重置以及 guest test-signing 查询/修改会与 Web/CLI live
共用 `RuntimeRoot\locks\live-execution.lock`。安装器在确认完成后、第一条 provider VM 命令前取得
跨进程独占句柄，并持有到 provider rollback、replacement baseline、本机 config/secret 同步结束；
竞争失败时不会调用 Hyper-V、`vmrun` 或 QEMU。`PlanOnly`/`WhatIf` 不获取 lease。锁文件可以持续
存在，是否占用只由独占句柄决定，不应通过删除文件绕过正在运行的操作。`Status`/`CheckEnvironment`
只读返回 `LiveExecutionLeasePath`、`LiveExecutionLeaseScope` 和
`LiveExecutionLeaseFilePresenceMeansHeld=false`，不会通过探测性占锁改变并发状态。

恢复后重新运行上面的只读 readiness；不要把恢复动作当作 release packaging 或低成本验证。

### 路径 C：创建或准备新 VM/环境 / Create or prepare a new VM/environment

适用于第一台电脑或全新实验室。普通用户直接运行推荐安装向导；脚本会询问常用设置，
不要求记住“推荐参数”：

```powershell
.\install.ps1
```

向导会询问 provider、runtime root、已有 VM、已有 clean checkpoint/snapshot、guest 用户、
guest 工作目录、guest password secret、可选 R0 driver path、可选 VirusTotal key，
并可在最后启动 WebUI。它不创建/导入 VM、不创建 checkpoint、不还原快照、不签名 driver、
不调用 `CSignTool.exe`。

自动化或审阅需要机器可读预览时，再使用 `PlanOnly`/`WhatIf` 明确安全边界；这些命令只输出
仓库外目录/config/secret/payload 计划，不执行样本：

```powershell
.\install.ps1 -InstallEntrypoint CreateOrPreparePath -PlanOnly
.\install.ps1 -InstallEntrypoint CreateOrPreparePath -WhatIf
```

如果还没有 VM，请先在所选 provider 中创建/导入 Windows guest，建立
`SandboxUser` 或等价本地账号；Hyper-V 启用 Guest Service Interface/PowerShell Direct，
VMware/QEMU 启用可达的 WinRM；VMware 默认由 Tools 自动发现地址，QEMU 默认由 provider
管理 localhost WinRM 转发。创建 clean checkpoint/snapshot（常用名 `Clean`）后，
重新运行 `.\install.ps1` 按提示选择/输入 provider、VM 和 baseline。

如果使用 runtime 便携包且包内存在 `payload\guest-tools\payload-manifest.json`，
`install.ps1` 在没有旧 install-state 且未显式传 `-GuestPayloadRoot` 时会默认记录包内
payload；源码仓库运行仍默认使用仓库外 `D:\Temp\KSwordSandbox\payload\guest-tools`。

源码仓库运行且缺少 guest payload 时，可按向导输出的 “下一步” 运行
`.\scripts\Prepare-GuestPayload.ps1 ... -SelfContained`；runtime 便携包默认使用包内
`payload\guest-tools`，普通用户无需额外准备 payload。

可选项分开处理：

```powershell
# 可选 hash-only enrichment；不配置也不阻止 Plan/WebUI。
.\install.ps1 -Mode ConfigureVTKey -PromptVTKey

# 真实 R0 只是隔离 lab 路径；这里只看 guidance/status，不签名、不加载。
.\install.ps1 -Mode Change -ShowTestSigningGuidance
.\scripts\Manage-SandboxDriver.ps1 -Action Status
```

任何路径都不要使用 `CSignTool.exe` 或旧 KSword GUI/interactive signing fallback。
缺少 VirusTotal key 时应 quiet-skip；缺少 Intel VT-x / AMD-V 或 Hyper-V module
才会阻止 Live VM。

## 交互模式 / Interactive mode

从仓库根目录运行：

```powershell
.\install.ps1
```

便携包兼容的 `scripts\` 目录入口：

```powershell
.\scripts\install.ps1
```

`.\scripts\install.ps1` 面向 release bundle 或习惯从 `scripts\` 目录启动的操作者。
无参数运行时会在同一个 PowerShell 进程里转发到仓库根安装器的推荐安装向导；显式
`-Mode Interactive` 时仍可进入更紧凑的便携包菜单：密码、Hyper-V、guest test-signing、
状态、卸载和 WebUI 工作都委托给根安装器，并额外提供直接的 `Prepare guest payload`
动作来暂存 Guest Agent/R0Collector。
它不会为状态修改再启动第二个进程，因此安装器设置的 Process-scope 环境变量仍能被
当前 PowerShell 会话后续命令看到。

根入口和 `scripts\` 入口都提供 provider 原生的只读资源选择。Hyper-V 先执行 `Get-VM`，
选择 VM 后执行 `Get-VMSnapshot`；VMware 组合当前 VMX 与 `vmrun list` 返回的运行中 VMX
候选，再执行 `listSnapshots`；QEMU 对操作者输入的基础磁盘执行
`qemu-img info --output=json`，自动识别磁盘格式，并仅在 internal-snapshot 模式列出 snapshot。
per-job overlay 模式会明确说明干净基线由新 overlay 保证，不要求选择未使用的内部 snapshot。
三者都可按编号选择并保存到本机配置，查询工具不可用、权限不足或查询失败时回退到手动输入。
该交互不会启动、停止、还原、创建或修改 VM，`vmrun`/`qemu-img` 也不会继承 guest/VT secret。

主菜单提供：

- 安装 / 准备本机设置（Install / prepare local settings）
- 修改设置（Change settings）
- 卸载本机设置（Uninstall local settings）
- 重置 Guest 密码（Reset Guest password）
- 配置虚拟化后端（Configure Hyper-V / VMware / QEMU）
- 配置 VT key（Configure VT key）
- 检查环境（Check environment）
- 启动 WebUI（Start WebUI）
- 查看状态（Status）

修改设置菜单包含：

- 重置宿主保存的密码密钥；
- 重置真实 VM guest 密码；
- 修改 provider / VM / checkpoint/snapshot / guest 路径；
- 修改记录的 guest 用户名；
- 重建 runtime 目录和本地 config；
- 查看 Hyper-V readiness/status；
- 查看 host/guest test-signing 指引并显式修改 guest test-signing；
- 通过 `.\scripts\Prepare-GuestPayload.ps1` 准备 Guest Agent/R0Collector payload；
- 配置可选 VirusTotal API key；
- 检查本机环境。

紧凑入口 `.\scripts\install.ps1 -Mode Change` 直接覆盖 release packaging
所需的子集：重置 host/guest 密码、配置 provider VM 名称/baseline/路径、查询或开启
guest test-signing、显示只读 `ShowTestSigningGuidance`、准备 payload、查看状态。
诊断输出和 `RecommendedActions` 仍可能展示规范的仓库根命令，例如 `.\install.ps1`
和 `.\run.ps1`；这些命令与 `scripts\` 包装器等价且仍然有效。

所有会修改状态的路径都支持 `-WhatIf`，因为 `install.ps1` 使用 PowerShell
`ShouldProcess`。`-WhatIf` 只预览本机 environment/config 写入、Guest 密码重置委托、
guest test-signing 委托和 WebUI 启动；不会提示 secret、启动 dotnet 或触碰 VM。
发布/自动化工具需要机器可读契约时，可在三入口诊断上加 `-Json` 或 `-PassThru`：

```powershell
.\install.ps1 -InstallEntrypoint CreateOrPreparePath -PlanOnly -Json
.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -AllowVmMutation -WhatIf -Json
# QEMU per-job overlay 也可直接输出无变更的 restore-equivalent 结果：
.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -Json
.\install.ps1 -Mode Status -Json
.\install.ps1 -Mode CheckEnvironment -Json
.\scripts\Test-HyperVReadiness.ps1 -Json
```

`InstallEntrypointDiagnostics` 会包含 `ContractVersion`、`MachineReadable`、
`OperatorModeMatrix`、`ReadOnlyAssertions`、`CreateOrPreparePlanActions`、restore
gate 字段和中文 next actions；`Test-HyperVReadiness -Json` 输出单一 envelope：
`{ Checks, Summary }`。
`Status` / `CheckEnvironment` 也会输出机器可读 `ReadinessVerdict`：
`ReadinessOverallStatus`（`ReadyForLive` / `ReadyForNonLive` / `Blocked`）、
`InstallStateReady`、`WebUiReady`、`LiveReady`、`BlockingReasons`、`WarningReasons`
和 `RecommendedActions`。这些诊断不会启动、还原或停止 VM；当 Hyper-V module
或 VMware/QEMU 管理工具可用时，它们可能执行所选 provider 的只读 VM/baseline/profile 查询。
它们还在顶层输出 `QemuUseOverlayDisk`、`BaselineRestoreRequiresVmMutation`、
`BaselineRestoreSatisfiedWithoutMutation`、`BaselineIsolationMode` 和动态的
`RestoreBaseline*Command`；`CheckEnvironment` 直接转发 `Status` 的值。旧
`RestoreCheckpoint*Command` 字段保留为兼容别名。

## 快速本地安装 / Fast local setup

已有 golden VM 时的最短路径：

```powershell
.\install.ps1
.\run.ps1
```

等价的 `scripts\` 目录形式：

```powershell
.\scripts\install.ps1
.\scripts\run.ps1
```

完成一次性设置后，日常启动只需要：

```powershell
.\run.ps1
```

中文速查：

- 首次安装：`.\install.ps1`
- scripts 目录等价入口：`.\scripts\install.ps1`
- 配置 provider/黄金 VM/干净基线：`.\install.ps1 -Mode Change -UpdateVirtualizationConfig -VirtualizationProvider <HyperV|VMware|Qemu> -VmName <VM> -CheckpointName <CleanBaseline>`
- 配置测试签名驱动路径：`.\install.ps1 -Mode Change -UpdateVirtualizationConfig -DriverHostPath <test-signed .sys>`
- 查询/启用来宾 test signing：
  `.\install.ps1 -Mode Change -QueryGuestTestSigning` /
  `.\install.ps1 -Mode Change -EnableGuestTestSigning -RestartGuestAfterTestSigning -Force`
- 日常启动 WebUI：`.\run.ps1`
- 一条命令做计划分析：`.\run.ps1 -Mode Analyze -SamplePreset Notepad`
  或 `.\run.ps1 -Mode Analyze -SamplePreset HarmlessSample`

`Analyze` 默认是 PlanOnly，不启动、不还原、不停止 VM；加 `-Live` 才会执行
实时 provider 分析。所有密码和 API key 都只从本机环境/DPAPI/local state 读取，
脚本和文档示例不要求把明文凭据写进命令行、配置文件、报告或 git。

如果是新的本地实验室，并希望安装器生成密码：

```powershell
.\install.ps1
```

生成的值会写入：

- 当前进程环境；
- 当前 Windows 用户环境，除非指定 `-CurrentProcessOnly`；
- `%ProgramData%\KSwordSandbox\guest-password.dpapi`，作为当前 Windows account 的
  DPAPI-protected backup，除非指定 `-SkipDpapiBackup`。

密码值永不打印 / The password value is never printed。如果只生成本机 secret，
仍然必须把 VM `SandboxUser` account 设置成同一个值，PowerShell Direct 才能认证。

如果已有 golden VM，且 `SandboxUser` 已有已知密码：

```powershell
.\install.ps1
```

## 虚拟化后端本机配置 / Local virtualization config

安装器默认把本机配置写到 git 仓库外：

```text
D:\Temp\KSwordSandbox\config\sandbox.local.json
```

它还会设置 `Sandbox__ConfigPath`，让 `src/KSword.Sandbox.Web` 读取本机 VM 配置，
而不是要求操作者修改 `config/sandbox.example.json` 模板。

无交互更新所选 provider 配置：

```powershell
.\install.ps1 -Mode Change -UpdateVirtualizationConfig `
  -VirtualizationProvider '<HyperV|VMware|Qemu>' `
  -VmName 'KSwordSandbox-Win10-Golden' `
  -CheckpointName 'Clean' `
  -GuestWorkingDirectory 'C:\KSwordSandbox'
```

常用可选参数包括 `-RuntimeRoot`、`-GuestPayloadRoot`、`-GuestUserName`、
`-SecretName`、`-DriverHostPath` 和 `-LocalConfigPath`。省略 `-DriverHostPath`
时，安装器会保留既有本机 `driver.hostDriverPath`，或尝试识别常见的
`KSword.Sandbox.Driver.sys` 构建输出。安装器不签名 driver，且不得调用
`CSignTool.exe`。

发布打包的驱动/测试签名边界 / Release packaging driver and test-signing boundaries：

- `-DriverHostPath` 只记录宿主侧本机构建/测试签名 `.sys` 的位置；它不复制签名密钥，
  也不签名文件。
- 如果只想验证 payload-only R0 plumbing，或完全不启用 R0，只修改仓库外生成的本机
  config（`sandbox.local.json`）并设置 `driver.useMockCollector=true` 或
  `driver.enabled=false`；`install.ps1` 会刻意让 release CLI 聚焦在 driver path
  和 guest test-signing 开关上。
- `-ShowTestSigningGuidance` 只打印只读 host/guest test-signing 指引：host
  test-signing 是隔离实验宿主加载测试签名内核驱动所需的启动设置；guest test-signing
  是真实 R0 分析通常需要的 golden VM 启动设置。
- `-EnableGuestTestSigning`、`-DisableGuestTestSigning` 和
  `-QueryGuestTestSigning` 都委托给 VM 侧 test-signing helper，并且是显式 `Change`
  动作。无交互开启/关闭必须带 `-Force`。
- 使用 `-RestartGuestAfterTestSigning` 时，Hyper-V、VMware、QEMU 都采用同一两阶段确认：
  先保存变更结果，再触发重启；只有重新连通来宾、boot time 已变化且 `bcdedit` 状态符合
  目标时才返回 `RestartCompleted=true`。VMware Tools 地址会在重启后重新发现。
- Test-signing 不等于签名 driver / Test-signing is not driver signing。测试证书 helper
  只在可用时使用普通 Windows SDK `signtool.exe`，找不到时会明确报告“已跳过签名 /
  skipped signing”；不得回退到图形化
  GUI signing fallback、`AuthenticodeVariantGUI.exe` 或旧 KSword 交互签名链。
- 证书、PFX、driver binary 和签名输出都必须留在仓库外。用 status/readiness 输出确认路径存在，
  不要打印 secret。

不改变本机状态的安全环境摘要：

```powershell
.\install.ps1 -Mode CheckEnvironment
```

`CheckEnvironment` 和 `Status` 不会启动、还原或停止 VM。它们会打印
`RecommendedActions`，方便新工作站在尝试 live execution 前先补齐 packaging 缺口：

- provider readiness 入口：`ProviderReadinessCommand`、`ProviderReadinessEntrypoint` 和
  `ReadinessScriptExists` 指向三种 provider 共用的 `run.ps1 -Mode CheckEnvironment`；
  `HyperVReadinessScript` / `HyperVReadinessScriptExists` 只表示额外的 Hyper-V 深度检查，
  不再冒充 VMware/QEMU 的通用 readiness 入口。

- provider 宿主前置条件：`ProviderHostPrerequisites` 对 Hyper-V、VMware、QEMU 使用同一
  `ksword.provider-host-prerequisites.v1` 只读契约，展示 Windows 宿主支持、CIM 查询、
  BIOS/UEFI 虚拟化、SLAT/EPT/NPT、VM monitor extensions、`RequiredWindowsFeature`、
  `RequiredWindowsFeatureState`、`RequiredWindowsFeatureReady`、硬件加速结论和 inspection error。
  只有固件虚拟化（或系统已检测到运行中的 hypervisor）、SLAT 与 provider 所需 Windows 功能都明确满足，才把硬件能力
  判为 ready；`false` 或无法确认都会阻止 `LiveReady` 并给出下一步。`HyperVPrerequisites` 继续保留 Optional Feature、Hyper-V
  PowerShell module、管理员上下文等 Hyper-V 专属兼容字段。
- provider 查询结果：安装状态和 `CheckEnvironment` 对三种 provider 统一输出
  `ProviderQueryAttempted`、`ProviderQuerySucceeded`、`ProviderAccessDenied`、`ProviderDiagnosticCode` 和
  `ProviderDiagnosticMessage`，并在顶层状态与 `ReadinessVerdict` 中保持一致。已启动的查询失败产生 `ProviderQueryFailed`；VMX/磁盘路径
  缺失可在查询前报告为 `MissingConfiguredVm`，baseline 缺失只在 provider 查询成功后报告。
- provider executor：`run.ps1` 额外输出 `ProviderExecutionToolReady`、`Kind`、`Path` 和
  `RequiresDotNet`；统一 JobTool 不可执行时会返回 `MissingProviderExecutionTool` 并阻止
  `LiveReady`，避免三种 provider 之一绕过统一的执行、清理和报告链路。
- runtime root 安全性：`RuntimeRootStatus` / `RuntimeRootUnderRepository`
  会提示运行目录是否错误地放在仓库下。建议始终使用 `D:\Temp\KSwordSandbox`
  或其他仓库外目录，避免 `jobs/`、上传样本、报告、截图、PCAP、dump 被误提交。
- Guest payload 准备度 / guest-payload readiness：`GuestPayloadStatus` 会检查 `agent/KSword.Sandbox.Agent.exe`、
  `r0collector/KSword.Sandbox.R0Collector.exe` 和 `payload-manifest.json` 是否存在，
  以及 manifest 是否包含 contract version、`sourceFingerprint` 和 host file hash；
  runtime 便携包按 manifest 的 `relativePath` 校验包内实际 `GuestAgent`/`R0Collector`
  SHA-256，不依赖构建机上的绝对 `payloadRoot`。
- VirusTotal 静默状态 / VT quiet state：`VirusTotalStatus` 只显示 key 是否存在于
  Process/User/Machine scope，永不打印 key。未配置、未收录或调用失败时，WebUI 应静默跳过
  hash-only enrichment，不写 job/behavior log，不阻断分析。
- 缺少 VM：创建/导入 golden VM，或用以下命令记录真实名称：
  `.\install.ps1 -Mode Change -UpdateVirtualizationConfig -VirtualizationProvider <HyperV|VMware|Qemu> -VmName <existing VM> -CheckpointName <clean-baseline>`;
- 缺少 baseline：创建/记录 Hyper-V clean checkpoint、VMware clean snapshot，或 QEMU overlay/内部 snapshot；
- 缺少 Guest Agent/R0Collector payload 或 `payload-manifest.json`：运行
  `.\scripts\Prepare-GuestPayload.ps1 -RepoRoot . -PayloadRoot <payloadRoot> -GuestWorkingDirectory <guestRoot> -SelfContained`;
- 缺少 guest password secret：运行 `.\install.ps1` 并在推荐安装向导中输入 guest password，
  Hyper-V 还可用 `.\scripts\Test-HyperVReadiness.ps1 -PromptForMissingGuestPassword`
  做 process-only readiness probe；
- 请求 real R0 但缺少 host driver path：通过以下命令设置 `driver.hostDriverPath`，
  `.\install.ps1 -Mode Change -UpdateVirtualizationConfig -DriverHostPath <test-signed .sys>`,
  或开启 `driver.useMockCollector=true`，或设置 `driver.enabled=false`。
- 不确定 host/guest test-signing：使用
  `.\install.ps1 -Mode Change -ShowTestSigningGuidance`；该命令仅显示 guidance，
  不会改变 host 或 guest boot settings。
- 不确定 “VT” 指什么：`VirusTotalStatus` / `ConfigureVTKey` 指可选 hash-only
  VirusTotal API key；Hyper-V 的 Intel VT-x / AMD-V 是 BIOS/UEFI 硬件虚拟化。
  VirusTotal key 缺失只会跳过 enrichment，Intel VT-x / AMD-V 缺失会阻止 Live VM。

预览本机 Hyper-V config 写入：

```powershell
.\install.ps1 -Mode Change -UpdateHyperVConfig -WhatIf `
  -VmName 'KSwordSandbox-Win10-Golden' `
  -CheckpointName 'Clean' `
  -GuestWorkingDirectory 'C:\KSwordSandbox'
```

安装或修改配置后，在管理员 PowerShell 中运行只读就绪预检 / read-only readiness preflight：

```powershell
.\scripts\Test-HyperVReadiness.ps1
```

readiness 脚本会复用已安装的 `Sandbox__ConfigPath` / `install-state.json` 值，
因此通常不需要重新输入 VM name、checkpoint、guest username、guest working directory、
runtime root 或 payload root。它会检查 password secret、target VM、clean checkpoint、
Guest Service Interface、VM 已运行时的 PowerShell Direct、guest working directory 形状、
host payload files、repository secret hygiene，以及 real R0 driver host-path readiness；
这些检查不会启动、还原或停止 VM。摘要会为缺少 VM/checkpoint/payload/secret/driver
的问题给出 `RecommendedActions`。

## 安装后启动 WebUI / Start WebUI after install

release wrapper 的启动路径刻意保持很短：

```powershell
.\install.ps1
.\run.ps1
```

等价的显式启动 wrapper：

```powershell
.\install.ps1 -Mode StartWebUI
.\run.ps1 -Mode StartWebUI
.\scripts\install.ps1 -Mode StartWebUI
.\scripts\run.ps1 -Mode StartWebUI
```

只预览启动流程、不启动 dotnet：

```powershell
.\run.ps1 -Mode StartWebUI -WhatIf
```

只有当你也会把真实 VM `SandboxUser` 密码同步为该生成值时，才使用
`-GeneratePassword`。普通每次启动时，`.\run.ps1` 会读取
`%ProgramData%\KSwordSandbox\install-state.json`，设置 `Sandbox__ConfigPath`，
在 User/Machine 环境可见时把 `KSWORDBOX_GUEST_PASSWORD` 镜像到 WebUI 进程，
并在 `http://127.0.0.1:18080` 或下一个可用 localhost fallback 端口启动 WebUI。

启动 WebUI 前，`run.ps1` 会检查配置的 `paths.guestPayloadRoot`，并尝试通过以下命令
构建自包含 Guest Agent/R0Collector payload：

```powershell
.\scripts\Prepare-GuestPayload.ps1 -SelfContained
```

Payload 就绪门禁 / payload readiness gate：如果缺少 Visual Studio/MSBuild 或 native build
tools，WebUI 模式会打印 warning，但仍然启动，支持上传、规划、dry-run runbook 和配置审阅
（upload / planning / configuration review）。在任何 provider 的 live execution 前必须修复 payload；
如果发布候选需要 payload 准备失败就停止启动，使用 `.\run.ps1 -RequirePayloadForWebUI`。

如果 `run.ps1` 只找到仓库模板 `config\sandbox.example.json`，它会输出中文
“本机配置未就绪”并停止，而不是带着 placeholder VM/checkpoint 值静默启动。
请重新运行安装器菜单，选择 `Install / prepare local settings`（安装/准备本机设置），
再在 `Change settings`（修改设置）中确认 VM/checkpoint/driver path。

## 可选 VirusTotal key / Optional VirusTotal key

VirusTotal 集成是可选且 hash-only 的：WebUI lookup 只检查既有 SHA-256 report，
不会上传样本。使用安装器把 key 存在 git 仓库外：

```powershell
.\install.ps1 -Mode ConfigureVTKey -PromptVTKey
```

该命令会把 `KSWORDBOX_VIRUSTOTAL_API_KEY` 写入当前进程和当前 Windows User
环境，除非指定 `-CurrentProcessOnly`。key 值永不打印，并会被 `.\run.ps1` /
WebUI 进程继承。清除时使用：

```powershell
.\install.ps1 -Mode ConfigureVTKey -ClearVTKey
```

也可以从交互菜单配置或清除 key：`Configure VT key`（配置 VT key）。

## 重置宿主保存的密码密钥 / Reset password secret

这是 host-only 的 secret 存储操作，不会修改 VM 账户。

交互方式：

```powershell
.\install.ps1
# 修改设置 -> 重置宿主密码密钥 / Change settings -> Reset password secret
```

无交互生成新密码：

```powershell
.\install.ps1 -Mode Change -ResetPassword -GeneratePassword
```

无交互提示输入新密码：

```powershell
.\install.ps1 -Mode Change -ResetPassword -PromptPassword
```

## 重置真实 VM 来宾密码 / Reset actual VM guest password

希望一步同步 host secret、VM `SandboxUser` 账户和 clean baseline 时使用。三个 provider 使用
同一个安装器入口，但采用适合各自磁盘/快照模型的安全事务：

- Hyper-V 调用 `scripts/Reset-SandboxGuestPassword.ps1`，支持不知道旧密码时离线修改 VHDX，
  验证 PowerShell Direct 后刷新 checkpoint；需要 elevated host shell。
- VMware/QEMU 调用 `scripts/Reset-RemoteGuestPassword.ps1`。普通轮换使用当前 host secret
  登录旧 baseline，通过 WinRM 改密并验证新凭据，再创建带时间戳的替换 snapshot/基盘。
  `-RecoverGuestVmPasswordWithoutCurrentSecret` 则让 QEMU 使用 replacement disk、让 VMware
  Workstation Pro 使用 full-clone replacement VMX 完成离线 VHDX 注入。旧 snapshot/base image/VMX
  不删除，父安装器最后才事务式切换本机 config、install-state 和 secret。
- QEMU overlay 模式会把改密后的临时 overlay 转换成新的独立基盘并继续使用 per-job overlay；
  内部 snapshot 模式会保留旧 snapshot 并创建一个新 snapshot。VMware 同样创建新 snapshot。

密码值只通过继承的临时 Process 环境变量交给子脚本，不进入命令行或 JSON。Basic WinRM over
HTTP 会被拒绝；请使用 Negotiate/CredSSP，或为 Basic 配置 HTTPS。VMware/QEMU 不允许在该
流程中使用 `-SkipCheckpointRestore`/`-SkipCheckpointRefresh`，以免下次还原后 secret 失配。
子脚本读取当前/新密码后会立即从它自身的 Process 环境中删除两个变量，并清理
`KSWORDBOX_*` 和常见 password/secret/token/API key/credential 变量，因此后续
`vmrun`/`qemu-system`/`qemu-img` 子进程不会继承这些宿主凭据。

交互方式：

```powershell
.\install.ps1
# 修改设置 -> 重置真实 VM 来宾密码 / Change settings -> Reset actual VM guest password
```

无交互生成并重置 VM 密码：

```powershell
.\install.ps1 -Mode Change -ResetGuestVmPassword -GeneratePassword -Force
```

无交互提示输入并重置 VM 密码：

```powershell
.\install.ps1 -Mode Change -ResetGuestVmPassword -PromptPassword -Force
```

成功结果会同时报告 `ActualGuestPasswordResetSupported=true` 和 provider 对应模式：Hyper-V
为 `offline-vhdx-and-checkpoint-refresh`，VMware Workstation Pro 为
`winrm-or-offline-vhdx-full-clone-replacement-vmx`，QEMU 为
`winrm-or-offline-vhdx-and-replacement-baseline`。任何提交阶段失败都会恢复原本机 config/install-state/secret
元数据；新旧 baseline 均不会被静默删除。

`ActualGuestPasswordUnknownOldPasswordRecoverySupported` 单独表示“已不知道旧密码”的
恢复能力：Hyper-V、QEMU 和 VMware Workstation Pro 为 `true`；QEMU 使用
`-RecoverGuestVmPasswordWithoutCurrentSecret` 把 clean baseline 转成临时 VHDX、离线注入，
再创建并验证替代磁盘。Workstation Pro 从 clean snapshot 创建 full clone，仅修改并验证
replacement VMX。旧 `vmType=player` 配置不再进入 provider Live 或密码轮换；安装 Workstation Pro、
设置 `vmware.vmType=ws` 并重新运行 `CheckEnvironment` 后，才会报告完整 VMware 能力。

VMware/QEMU replacement VM 在新凭据首次连通后还会读取一次性服务结果，并确认服务删除命令已执行、
含密码的注入脚本已经不存在；只有随后停止 VM，才会创建并提交新的 clean baseline。

`ActualGuestPasswordUnknownOldPasswordRecoveryReady` 表示当前会话已提权，provider 配置有效、
VM/baseline 查询成功且资源存在，并且宿主 provider 工具、`qemu-img` 与 Storage cmdlet
前置条件已满足；
`ActualGuestPasswordUnknownOldPasswordRecoveryElevationReady` 单独报告当前 PowerShell 是否以管理员运行。
VMware 的 `LayoutValidation=deferred-to-isolated-full-clone`
表示单磁盘/关机 snapshot 检查会在 full clone 创建后、任何 clone 磁盘修改前完成。

```powershell
.\install.ps1 -Mode Change -VirtualizationProvider Qemu `
  -ResetGuestVmPassword -RecoverGuestVmPasswordWithoutCurrentSecret `
  -GeneratePassword -Force

.\install.ps1 -Mode Change -VirtualizationProvider VMware -VMwareVmType ws `
  -ResetGuestVmPassword -RecoverGuestVmPasswordWithoutCurrentSecret `
  -GeneratePassword -Force
```

## 状态查看与卸载 / Status and uninstall

```powershell
.\install.ps1 -Mode Status
.\install.ps1 -Mode Uninstall -Force
```

`Status` 显示 secret 是否存在、runtime folder、本机 config 路径、`Sandbox__ConfigPath`、
Hyper-V module 是否可用、VM/checkpoint 是否存在，以及当前 shell 是否 elevated。
它不会打印密码。

需要更深入的一条命令 readiness 时使用：

```powershell
.\scripts\Test-HyperVReadiness.ps1 -PromptForMissingGuestPassword
```

`-PromptForMissingGuestPassword` 只影响当前进程且不持久化，适合不想写 User
environment 或 DPAPI backup 的单次 elevated shell。需要可重复本机设置时，使用安装器的
password reset 模式。

`Uninstall` 会移除当前 process/User environment secret，以及本机 installer metadata /
DPAPI backup；它不会删除 `D:\Temp\KSwordSandbox` 下的 runtime job outputs。

## 安全边界 / Security boundary

`KSWORDBOX_GUEST_PASSWORD` 不是主要 VM escape boundary。更重要的是 Hyper-V
隔离、禁止敏感 host share、网络控制、checkpoint restore 和清理。这个 secret 存在的原因是
PowerShell Direct 需要 guest Windows credential 来暂存样本、运行 Guest Agent/R0Collector，
并把输出复制回来。

仍然不要把该值写入 git、report、screenshot 或 runbook log。readiness 和 repository-policy
脚本会把当前环境 secret 值与候选仓库文本文件比较；如果可 staged 文件里出现该值，会失败但不打印值。

安装器不签名 driver，也不得使用 GUI signing fallback、调用 `CSignTool.exe` 或旧的
`scripts\Sign-SandboxDriverWithKswordCSignTool.ps1` wrapper。可选 real-driver lab validation
独立于 install/run packaging，应使用本文档记录的仓库外 Windows test-signing 路径。

## 产品化安装/状态检查补充

中文优先：`install.ps1` 的 `Status` 和 `CheckEnvironment` 是只读检查入口，默认不启动、
不还原、不停止 VM，也不打印 guest password 或 VT key 值。建议首次安装或迁移便携包后先运行：

```powershell
.\install.ps1 -Mode Status
.\install.ps1 -Mode CheckEnvironment
```

状态输出会集中展示这些维度：

- Provider：`VirtualizationProvider`、`ProviderManagementAvailable`、`VmExists`、
  `BaselineName`、`BaselineExists`、`BaselineGuidance` 和 `VmProfile`；`CheckpointName`、
  `CheckpointExists`、`CheckpointGuidance` 保留为兼容别名。Hyper-V 另显示 `HyperVModuleAvailable` 与
  `VmGuestServiceInterfaceEnabled`；VMware/QEMU 另显示管理工具、VMX/磁盘、snapshot/overlay
  与 guest remoting profile 的诊断，包括 `GuestRemotingAddressMode`、
  `GuestRemotingAddressSource`、`GuestTransportSecure`、SSL/认证策略和归一后的端口。
- 阻断原因：优先读取 `ProviderNeutralBlockingReasons`；旧 `BlockingReasons` 继续保留
  `MissingConfiguredCheckpoint` / `MissingGuestRemotingAddress` 兼容值。
- VM profile：`VmProfile` 是本机操作者画像，不是 release artifact；它应回答“当前
  shell 会使用哪个 VM、clean baseline、guest working directory、runtime root、guest payload root
  和 driver host path”。如果 profile 仍是示例值，先用 `-UpdateVirtualizationConfig` 修正，不要把
  `sandbox.local.json` 提交或打包。
- 测试签名：`HostTestSigningState` 只读显示宿主 test-signing 状态；guest test-signing 仍必须通过
  `-QueryGuestTestSigning`、`-EnableGuestTestSigning` 或交互菜单显式执行。
- driver：`DriverHostPathExists`、`DriverSignatureStatus`、`DriverServiceStatus`、
  `DriverServiceState`、`DriverMiniFilterLoaded`。普通 WebUI/PlanOnly 不要求加载 driver；真实 R0
  前再按 `DriverServiceStatusCommand` 或 `scripts\Manage-SandboxDriver.ps1 -Action Status` 查看。
- guest password：只显示 `ProcessSecretSet`、`UserSecretSet`、`MachineSecretSet` 和
  `GuestPasswordGuidance`，不会输出、摘要或回显密码值。密码值永不打印 / The password value is never printed.
- VirusTotal：`VirusTotalStatus` 只显示可选 hash-only API key 是否存在、设置来源和缺失时的
  quiet-skip 行为；不会打印 key。VirusTotal key 与 BIOS/UEFI 里的 Intel VT-x / AMD-V
  硬件虚拟化不是同一件事。
- 发布审阅者 / release reviewer：如果来自 portable package，先看包根
  `package-manifest.generated.json` 中生成的 `reviewerChecklist` 和
  `sourceRuntimeSafetyMetadata`、`runtimePublishRootDiagnostics`、
  `runtimeCompletenessDiagnostics`。它们会明确 runtime payload 是否只来自仓库外
  `RuntimePublishRoot`、本包是否只是布局 dry-run、缺哪些 expected leaves/forbidden
  files，以及是否仍满足“不修改 VM / no VM mutation、不签名 / no signing、不包含
  `CSignTool.exe`”安全边界。

常见故障定位顺序 / Troubleshooting order：

1. `ProviderHostPrerequisites` 的 `HardwareAccelerationReady` 不是 `true`：先看
   `RequiredWindowsFeatureState`，确认 Hyper-V 的 `Microsoft-Hyper-V-All` 或 QEMU 的
   `HypervisorPlatform` 已启用，再修复 Windows CIM 查询、BIOS/UEFI virtualization 或 SLAT
   并重启；Hyper-V 还要检查 PowerShell module，然后再看 VM 配置。
2. `VmProfile` 仍是示例值或 VM/baseline 不存在：用 `-UpdateVirtualizationConfig`
   记录真实 provider、golden VM 和 clean baseline；不要编辑仓库模板。
3. `GuestPayloadStatus` missing/stale：重新运行
   `.\scripts\Prepare-GuestPayload.ps1 -RepoRoot . -PayloadRoot <payloadRoot> -SelfContained`，
   确认输出在仓库外。
4. 真实 R0 前 `HostTestSigningState` / guest test-signing 不清楚：先运行
   `-ShowTestSigningGuidance` 或 `-QueryGuestTestSigning`，只在隔离 lab 中显式启用。
5. `VirusTotalStatus` missing：这是可选项；需要 enrichment 时再运行
   `.\install.ps1 -Mode ConfigureVTKey -PromptVTKey`，否则可继续 Plan/WebUI。

VM profile 的来源是本机安装状态和 `sandbox.local.json`，不要修改仓库模板保存本机 VM 名称、
baseline、guest path、driver path 或 secret。需要更新时继续使用：

```powershell
.\install.ps1 -Mode Change -UpdateVirtualizationConfig -VirtualizationProvider <HyperV|VMware|Qemu> -VmName <VM> -CheckpointName <CleanBaseline>
.\install.ps1 -Mode Change -QueryGuestTestSigning
.\install.ps1 -Mode Change -ShowTestSigningGuidance
```

打包/发布边界不变：安装器不签名 driver，不得使用 GUI signing fallback，也不得调用
`CSignTool.exe`；便携包也不应包含本机 `sandbox.local.json`、`install-state.json`、DPAPI 备份、
样本、报告、VM 磁盘/快照或仓库构建二进制。

### 中文修复提示与 handoff JSON / Chinese remediation and handoff JSON

安装阶段只负责本机配置和只读诊断；它不会生成 `componentProgress` 或 `gapAudit`，但 release
打包/readiness 会把安装侧缺口汇总到 `operator-remediation-zh`，并在
`gapAudit.runtimePublishRootCompleteness.remediationZh`、
`gapAudit.selfNoiseGuardReadiness.remediationZh`、`gapAudit.noFreshLiveEvidence.remediationZh`
给出中文下一步。v28 `gapAudit` 还会在 `guardrailResults` 标出 no VM mutation/no signing/
no `CSignTool.exe` 状态，并用 `runtimeCompletenessDiagnostics.summary` 暴露
`missingCount`、`incompleteCount` 和 `forbiddenFileCount`。操作者看到 Hyper-V、VM profile、
guest payload、VT key、runtime root 或
`RuntimePublishRoot` 缺口时，先运行：

```powershell
.\scripts\install.ps1 -Mode CheckEnvironment
.\scripts\run.ps1 -Mode CheckEnvironment
```

然后按输出的 `RecommendedActions` 修复。不要用安装器补 fresh live evidence，也不要把
采集器自噪声、collection-health、VT 静默状态 / VT quiet state 或 `behaviorCounted=false` 行当作样本行为；
没有实验室 `job id` 时，发布说明仍必须写“本候选未刷新 fresh live evidence”。
