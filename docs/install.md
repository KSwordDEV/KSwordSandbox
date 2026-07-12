# 本地安装与凭据处理 / Local install and credential handling

本页中文优先。命令参数名（如 `-Mode`、`-PromptPassword`）和机器可读
JSON key（如 `RecommendedActions`、`SecretValuePrinted`）保持英文，不翻译。

普通用户遇到错误时，先看脚本输出里的“下一步”。常见修复顺序：

1. 先运行 `.\install.ps1 -Mode CheckEnvironment` 查看缺口；该命令不会启动、
   还原或停止 VM，也不会打印密码/API key。
2. 缺少本机配置或密码时，运行
   `.\install.ps1 -Mode Install -PromptPassword`。
3. 缺少 VM/快照时，运行
   `.\install.ps1 -Mode Change -UpdateHyperVConfig -VmName <VM> -CheckpointName <Snapshot>`。
4. 缺少 Guest Agent/R0Collector payload 时，运行
   `.\scripts\Prepare-GuestPayload.ps1 -RepoRoot . -PayloadRoot <payloadRoot> -GuestWorkingDirectory <guestRoot> -SelfContained`。
5. 真实 R0 采集缺少 driver path 时，运行
   `.\install.ps1 -Mode Change -UpdateHyperVConfig -DriverHostPath <test-signed .sys>`；
   只验证链路时可在本机 `sandbox.local.json` 设置
   `driver.useMockCollector=true`。

英文摘要 / English summary：安装器只准备本机操作者状态和本机密钥；它不签名
driver，不使用 GUI signing fallback，不调用 `CSignTool.exe`，也不会把 secret 写进 git。
`Status` / `CheckEnvironment` 只产生中文优先的本机诊断，不启动 live、不生成 `job id`，
也不能作为 release notes 的 fresh live evidence。

`install.ps1` 用于准备 KSwordSandbox 的本机操作者设置，目标环境是实验室宿主机或
贡献者工作站，不是把凭据提交到仓库的入口。

安装器只负责两个本机维度：

1. PowerShell Direct 使用的 guest credential 本机存储；
2. host/guest Hyper-V 配置，例如 VM 名称、干净 checkpoint、guest 工作目录、
   runtime root，以及本地 Web/API config 路径。

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
无交互模式会在同一个 PowerShell 进程里转发到仓库根安装器；交互菜单是更紧凑的
便携包菜单：密码、Hyper-V、guest test-signing、状态、卸载和 WebUI 工作都委托给
根安装器，并额外提供直接的 `Prepare guest payload` 动作来暂存 Guest Agent/R0Collector。
它不会为状态修改再启动第二个进程，因此安装器设置的 Process-scope 环境变量仍能被
当前 PowerShell 会话后续命令看到。

主菜单提供：

- 安装 / 准备本机设置（Install / prepare local settings）
- 修改设置（Change settings）
- 卸载本机设置（Uninstall local settings）
- 重置 Guest 密码（Reset Guest password）
- 配置 Hyper-V（Configure Hyper-V）
- 配置 VT key（Configure VT key）
- 检查环境（Check environment）
- 启动 WebUI（Start WebUI）
- 查看状态（Status）

修改设置菜单包含：

- 重置宿主保存的密码密钥；
- 重置真实 VM guest 密码；
- 修改 Hyper-V VM / checkpoint / guest 路径；
- 修改记录的 guest 用户名；
- 重建 runtime 目录和本地 config；
- 查看 Hyper-V readiness/status；
- 查看 host/guest test-signing 指引并显式修改 guest test-signing；
- 通过 `.\scripts\Prepare-GuestPayload.ps1` 准备 Guest Agent/R0Collector payload；
- 配置可选 VirusTotal API key；
- 检查本机环境。

紧凑入口 `.\scripts\install.ps1 -Mode Change` 直接覆盖 release packaging
所需的子集：重置 host/guest 密码、配置 Hyper-V VM 名称/checkpoint/路径、查询或开启
guest test-signing、显示只读 `ShowTestSigningGuidance`、准备 payload、查看状态。
诊断输出和 `RecommendedActions` 仍可能展示规范的仓库根命令，例如 `.\install.ps1`
和 `.\run.ps1`；这些命令与 `scripts\` 包装器等价且仍然有效。

所有会修改状态的路径都支持 `-WhatIf`，因为 `install.ps1` 使用 PowerShell
`ShouldProcess`。`-WhatIf` 只预览本机 environment/config 写入、Guest 密码重置委托、
guest test-signing 委托和 WebUI 启动；不会提示 secret、启动 dotnet 或触碰 VM。

## 快速本地安装 / Fast local setup

已有 golden VM 时的最短路径：

```powershell
.\install.ps1 -Mode Install -PromptPassword
.\run.ps1
```

等价的 `scripts\` 目录形式：

```powershell
.\scripts\install.ps1 -Mode Install -PromptPassword
.\scripts\run.ps1
```

完成一次性设置后，日常启动只需要：

```powershell
.\run.ps1
```

中文速查：

- 首次安装：`.\install.ps1 -Mode Install -PromptPassword`
- scripts 目录等价入口：`.\scripts\install.ps1 -Mode Install -PromptPassword`
- 配置黄金 VM/干净快照：`.\install.ps1 -Mode Change -UpdateHyperVConfig -VmName <VM> -CheckpointName <Snapshot>`
- 配置测试签名驱动路径：`.\install.ps1 -Mode Change -UpdateHyperVConfig -DriverHostPath <test-signed .sys>`
- 查询/启用来宾 test signing：
  `.\install.ps1 -Mode Change -QueryGuestTestSigning` /
  `.\install.ps1 -Mode Change -EnableGuestTestSigning -RestartGuestAfterTestSigning -Force`
- 日常启动 WebUI：`.\run.ps1`
- 一条命令做计划分析：`.\run.ps1 -Mode Analyze -SamplePreset Notepad`
  或 `.\run.ps1 -Mode Analyze -SamplePreset HarmlessSample`

`Analyze` 默认是 PlanOnly，不启动、不还原、不停止 VM；加 `-Live` 才会执行
实时 Hyper-V 分析。所有密码和 API key 都只从本机环境/DPAPI/local state 读取，
脚本和文档示例不要求把明文凭据写进命令行、配置文件、报告或 git。

如果是新的本地实验室，并希望安装器生成密码：

```powershell
.\install.ps1 -Mode Install -GeneratePassword
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
.\install.ps1 -Mode Install -PromptPassword
```

## Hyper-V 本机配置 / Hyper-V local config

安装器默认把本机配置写到 git 仓库外：

```text
D:\Temp\KSwordSandbox\config\sandbox.local.json
```

它还会设置 `Sandbox__ConfigPath`，让 `src/KSword.Sandbox.Web` 读取本机 VM 配置，
而不是要求操作者修改 `config/sandbox.example.json` 模板。

无交互更新 Hyper-V 配置：

```powershell
.\install.ps1 -Mode Change -UpdateHyperVConfig `
  -VmName 'KSwordSandbox-Win10-Golden' `
  -CheckpointName 'Clean' `
  -GuestWorkingDirectory 'C:\KSwordSandbox'
```

常用可选参数包括 `-RuntimeRoot`、`-GuestPayloadRoot`、`-GuestUserName`、
`-SecretName`、`-DriverHostPath` 和 `-LocalConfigPath`。省略 `-DriverHostPath`
时，安装器会保留既有本机 `driver.hostDriverPath`，或尝试识别常见的
`KSword.Sandbox.Driver.sys` 构建输出。安装器不签名 driver，且不得调用
`CSignTool.exe`。

release packaging 的 driver/test-signing 注意事项：

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
- Test-signing 不等于签名 driver。测试证书 helper 只在可用时使用普通 Windows SDK
  `signtool.exe`，找不到时会明确报告 skipped signing；不得回退到图形化
  GUI signing fallback、`AuthenticodeVariantGUI.exe` 或旧 KSword 交互签名链。
- 证书、PFX、driver binary 和签名输出都必须留在仓库外。用 status/readiness 输出确认路径存在，
  不要打印 secret。

不改变本机状态的安全环境摘要：

```powershell
.\install.ps1 -Mode CheckEnvironment
```

`CheckEnvironment` 和 `Status` 不会启动、还原或停止 VM。它们会打印
`RecommendedActions`，方便新工作站在尝试 live execution 前先补齐 packaging 缺口：

- Hyper-V 前置条件：`HyperVPrerequisites` 会只读展示 Windows Optional Feature、
  Hyper-V PowerShell module、BIOS/UEFI 虚拟化、SLAT/EPT/NPT、管理员上下文和
  inspection error；缺失项会给出下一步启用/重启/换机建议。
- runtime root 安全性：`RuntimeRootStatus` / `RuntimeRootUnderRepository`
  会提示运行目录是否错误地放在仓库下。建议始终使用 `D:\Temp\KSwordSandbox`
  或其他仓库外目录，避免 `jobs/`、上传样本、报告、截图、PCAP、dump 被误提交。
- Guest payload 成熟度：`GuestPayloadStatus` 会检查 `agent/KSword.Sandbox.Agent.exe`、
  `r0collector/KSword.Sandbox.R0Collector.exe` 和 `payload-manifest.json` 是否存在，
  以及 manifest 是否包含 contract version、`sourceFingerprint` 和 host file hash。
- VirusTotal 状态：`VirusTotalStatus` 只显示 key 是否存在于 Process/User/Machine
  scope，永不打印 key。未配置或调用失败时，WebUI 应静默跳过 hash-only enrichment，
  不把失败噪声写入 job log。
- 缺少 VM：创建/导入 golden VM，或用以下命令记录真实名称：
  `.\install.ps1 -Mode Change -UpdateHyperVConfig -VmName <existing VM> -CheckpointName <checkpoint>`;
- 缺少 checkpoint：创建 clean checkpoint，或更新已记录的 checkpoint name；
- 缺少 Guest Agent/R0Collector payload 或 `payload-manifest.json`：运行
  `.\scripts\Prepare-GuestPayload.ps1 -RepoRoot . -PayloadRoot <payloadRoot> -GuestWorkingDirectory <guestRoot> -SelfContained`;
- 缺少 guest password secret：运行 `.\install.ps1 -Mode Install -PromptPassword`，
  或用 `.\scripts\Test-HyperVReadiness.ps1 -PromptForMissingGuestPassword`
  做 process-only readiness probe；
- 请求 real R0 但缺少 host driver path：通过以下命令设置 `driver.hostDriverPath`，
  `.\install.ps1 -Mode Change -UpdateHyperVConfig -DriverHostPath <test-signed .sys>`,
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

安装或修改配置后，在 elevated PowerShell session 中运行只读 readiness preflight：

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
.\install.ps1 -Mode Install -PromptPassword
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

如果缺少 Visual Studio/MSBuild 或 native build tools，WebUI 模式会打印 warning，
但仍然启动，支持 upload、planning、dry-run runbook 和 configuration review。
在 live Hyper-V execution 前修复 payload；如果希望 payload 准备失败就停止启动，
使用 `.\run.ps1 -RequirePayloadForWebUI`。

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

当你不知道当前 guest 密码，或希望一步同步 host secret 与 VM `SandboxUser` 账户时使用。
该流程会调用 `scripts/Reset-SandboxGuestPassword.ps1`，因此必须在 elevated shell 中运行，
并且可能还原或刷新 clean checkpoint。

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

真实重置流程会还原已配置 checkpoint、挂载离线 Windows 磁盘、注入一次性 SYSTEM
service、启动 VM、验证 PowerShell Direct、保存 host secret、停止 VM，并在未指定
`-SkipCheckpointRefresh` 时刷新 clean checkpoint。

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

- Hyper-V：`HyperVModuleAvailable`、`VmExists`、`CheckpointExists`、`VmProfile`、
  `VmGuestServiceInterfaceEnabled`，并在 `RecommendedActions` 给出缺失 VM、missing checkpoint、
  Guest Service Interface 等修复命令。
- VM profile：`VmProfile` 是本机操作者画像，不是 release artifact；它应回答“当前
  shell 会使用哪个 VM、checkpoint、guest working directory、runtime root、guest payload root
  和 driver host path”。如果 profile 仍是示例值，先用 `-UpdateHyperVConfig` 修正，不要把
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
- release reviewer：如果来自 portable package，先看包根
  `package-manifest.generated.json` 的 generated `reviewerChecklist` 和
  `sourceRuntimeSafetyMetadata`。它们会明确 runtime payload 是否只来自仓库外
  `RuntimePublishRoot`、本包是否只是 layout dry-run，以及是否仍满足 no VM mutation /
  no signing / no `CSignTool.exe` 安全边界。

常见故障定位顺序 / Troubleshooting order：

1. `HyperVPrerequisites` 缺 BIOS/UEFI virtualization、SLAT 或 Hyper-V module：
   先修宿主机能力并重启，再看 VM 配置。
2. `VmProfile` 仍是示例值或 VM/checkpoint 不存在：用 `-UpdateHyperVConfig`
   记录真实 golden VM 和 clean checkpoint；不要编辑仓库模板。
3. `GuestPayloadStatus` missing/stale：重新运行
   `.\scripts\Prepare-GuestPayload.ps1 -RepoRoot . -PayloadRoot <payloadRoot> -SelfContained`，
   确认输出在仓库外。
4. 真实 R0 前 `HostTestSigningState` / guest test-signing 不清楚：先运行
   `-ShowTestSigningGuidance` 或 `-QueryGuestTestSigning`，只在隔离 lab 中显式启用。
5. `VirusTotalStatus` missing：这是可选项；需要 enrichment 时再运行
   `.\install.ps1 -Mode ConfigureVTKey -PromptVTKey`，否则可继续 Plan/WebUI。

VM profile 的来源是本机安装状态和 `sandbox.local.json`，不要修改仓库模板保存本机 VM 名称、
checkpoint、guest path、driver path 或 secret。需要更新时继续使用：

```powershell
.\install.ps1 -Mode Change -UpdateHyperVConfig -VmName <VM> -CheckpointName <Checkpoint>
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
给出中文下一步。操作者看到 Hyper-V、VM profile、guest payload、VT key、runtime root 或
`RuntimePublishRoot` 缺口时，先运行：

```powershell
.\scripts\install.ps1 -Mode CheckEnvironment
.\scripts\run.ps1 -Mode CheckEnvironment
```

然后按输出的 `RecommendedActions` 修复。不要用安装器补 fresh live evidence，也不要把
采集器自噪声、collection-health、VT quiet state 或 `behaviorCounted=false` 行当作样本行为；
没有实验室 `job id` 时，发布说明仍必须写“本候选未刷新 fresh live evidence”。
