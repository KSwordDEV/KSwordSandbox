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

English summary: this installer prepares local operator state and secrets only;
it does not sign drivers, does not call `CSignTool.exe`, and does not write
secrets into git.

`install.ps1` prepares local operator settings for KSwordSandbox. It is meant
for a lab host or contributor workstation, not for committing secrets.

The installer now owns two local concerns:

1. guest credential storage for PowerShell Direct; and
2. host/guest Hyper-V configuration such as VM name, clean checkpoint, guest
   working directory, runtime root, and the local Web/API config path.

## Interactive mode

Run from the repository root:

```powershell
.\install.ps1
```

Packaging-compatible script-folder entry point:

```powershell
.\scripts\install.ps1
```

`.\scripts\install.ps1` exists for release bundles or operator habits that
start from the `scripts\` folder. Non-interactive modes forward to the
repository-root installer in the same PowerShell process. Its interactive menu
is a compact packaging menu that delegates password, Hyper-V, guest
test-signing, status, uninstall, and WebUI work to the root installer and adds
a direct `Prepare guest payload` action for Guest Agent/R0Collector staging.
It does not create a second process for installer state changes, so
Process-scope environment values set by the installer remain visible to
commands launched from the current PowerShell session.

The menu provides:

- Install / prepare local settings
- Change settings
- Uninstall local settings
- Reset Guest password
- Configure Hyper-V
- Configure VT key
- Check environment
- Start WebUI
- Status

The Change menu includes:

- reset password secret;
- reset the actual VM guest password;
- change Hyper-V VM/checkpoint/guest paths;
- change the recorded guest username;
- recreate runtime folders and local config;
- show Hyper-V readiness/status;
- manage host/guest test-signing guidance and guest test-signing changes;
- prepare Guest Agent/R0Collector payload through
  `.\scripts\Prepare-GuestPayload.ps1`;
- configure optional VirusTotal API key;
- check local environment.

The compact `.\scripts\install.ps1 -Mode Change` menu covers the release
packaging subset directly: reset host/guest password, configure Hyper-V VM
name/checkpoint/paths, query or enable guest test-signing, prepare payload,
and show status. Diagnostic output and `RecommendedActions` may still show
canonical root commands such as `.\install.ps1` and `.\run.ps1`; those remain
valid and equivalent to the script-folder wrappers.

Every mutating path supports `-WhatIf` because `install.ps1` uses
PowerShell `ShouldProcess`. `-WhatIf` previews local environment/config writes,
Guest password reset delegation, guest test-signing delegation, and WebUI
startup without prompting for secrets, starting dotnet, or touching a VM.

## Fast local setup

Shortest path for an existing golden VM:

```powershell
.\install.ps1 -Mode Install -PromptPassword
.\run.ps1
```

Equivalent script-folder form:

```powershell
.\scripts\install.ps1 -Mode Install -PromptPassword
.\scripts\run.ps1
```

After this one-time setup, the daily startup is just:

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

For a fresh local lab where you want the installer to generate a password:

```powershell
.\install.ps1 -Mode Install -GeneratePassword
```

This writes the generated value to:

- current process environment;
- current Windows user environment, unless `-CurrentProcessOnly` is supplied;
- `%ProgramData%\KSwordSandbox\guest-password.dpapi` as a DPAPI-protected backup
  for this Windows account, unless `-SkipDpapiBackup` is supplied.

The password value is never printed. If you only generate a local secret, the VM
`SandboxUser` account must still be set to the same value before PowerShell
Direct can authenticate.

For an existing golden VM where `SandboxUser` already has a known password:

```powershell
.\install.ps1 -Mode Install -PromptPassword
```

## Hyper-V local config

Install writes a local config file outside git, by default:

```text
D:\Temp\KSwordSandbox\config\sandbox.local.json
```

It also sets `Sandbox__ConfigPath` so `src/KSword.Sandbox.Web` can pick up the
local VM configuration without editing `config/sandbox.example.json`.

Non-interactive Hyper-V config update:

```powershell
.\install.ps1 -Mode Change -UpdateHyperVConfig `
  -VmName 'KSwordSandbox-Win10-Golden' `
  -CheckpointName 'Clean' `
  -GuestWorkingDirectory 'C:\KSwordSandbox'
```

Useful optional parameters are `-RuntimeRoot`, `-GuestPayloadRoot`,
`-GuestUserName`, `-SecretName`, `-DriverHostPath`, and `-LocalConfigPath`.
When `-DriverHostPath` is omitted, the installer preserves an existing local
`driver.hostDriverPath` or auto-detects common built
`KSword.Sandbox.Driver.sys` outputs. It does not sign drivers and must not call
`CSignTool.exe`.

Driver/test-signing notes for release packaging:

- `-DriverHostPath` records where the host can find a locally built/test-signed
  `.sys`; it does not copy signing keys or sign the file.
- If you want a payload-only R0 plumbing test or no R0 at all, edit only the
  generated local config outside git (`sandbox.local.json`) and set
  `driver.useMockCollector=true` or `driver.enabled=false`; `install.ps1`
  intentionally keeps the release CLI focused on the driver path and guest
  test-signing switch.
- `-ShowTestSigningGuidance` prints a read-only host/guest test-signing guide:
  host test-signing is a host boot setting for isolated lab hosts that must
  load a test-signed kernel driver, while guest test-signing is the golden VM
  boot setting normally needed for real R0 analysis.
- `-EnableGuestTestSigning`, `-DisableGuestTestSigning`, and
  `-QueryGuestTestSigning` delegate to the VM-side test-signing helper and are
  explicit `Change` actions. Non-interactive enable/disable requires `-Force`.
- Test-signing does not sign the driver. The test-certificate helper uses
  ordinary Windows SDK `signtool.exe` when available and clearly reports
  skipped signing if `signtool.exe` is missing.
- Keep certificates, PFX files, driver binaries, and signing output outside the
  repository. Use status/readiness output to verify path presence without
  printing secrets.

Safe environment summary without changing local state:

```powershell
.\install.ps1 -Mode CheckEnvironment
```

`CheckEnvironment` and `Status` do not start, restore, or stop a VM. They print
`RecommendedActions` so a fresh workstation can fix packaging gaps before trying
live execution:

- missing VM: create/import the golden VM or record the real name with
  `.\install.ps1 -Mode Change -UpdateHyperVConfig -VmName <existing VM> -CheckpointName <checkpoint>`;
- missing checkpoint: create the clean checkpoint or update the recorded
  checkpoint name;
- missing Guest Agent/R0Collector payload or `payload-manifest.json`: run
  `.\scripts\Prepare-GuestPayload.ps1 -RepoRoot . -PayloadRoot <payloadRoot> -GuestWorkingDirectory <guestRoot> -SelfContained`;
- missing guest password secret: run `.\install.ps1 -Mode Install -PromptPassword`
  or use `.\scripts\Test-HyperVReadiness.ps1 -PromptForMissingGuestPassword` for
  a process-only readiness probe;
- real R0 requested but no host driver path: set
  `driver.hostDriverPath` with
  `.\install.ps1 -Mode Change -UpdateHyperVConfig -DriverHostPath <test-signed .sys>`,
  enable `driver.useMockCollector=true`, or set `driver.enabled=false`.
- unsure about host/guest test-signing: use
  `.\install.ps1 -Mode Change -ShowTestSigningGuidance`; this is guidance-only
  and does not change host or guest boot settings.

Preview local Hyper-V config writes:

```powershell
.\install.ps1 -Mode Change -UpdateHyperVConfig -WhatIf `
  -VmName 'KSwordSandbox-Win10-Golden' `
  -CheckpointName 'Clean' `
  -GuestWorkingDirectory 'C:\KSwordSandbox'
```

After install or config changes, run the read-only readiness preflight from an
elevated PowerShell session:

```powershell
.\scripts\Test-HyperVReadiness.ps1
```

The readiness script reuses the installed `Sandbox__ConfigPath` /
`install-state.json` values, so you normally do not need to retype VM name,
checkpoint, guest username, guest working directory, runtime root, or payload
root. It checks the password secret presence, target VM, clean checkpoint,
Guest Service Interface, PowerShell Direct when the VM is already running,
guest working directory shape, host payload files, and repository secret
hygiene plus real R0 driver host-path readiness without
starting/restoring/stopping a VM. The summary includes
`RecommendedActions` for missing VM/checkpoint/payload/secret/driver problems.

## Start WebUI after install

The release-wrapper path is intentionally short:

```powershell
.\install.ps1 -Mode Install -PromptPassword
.\run.ps1
```

Equivalent explicit startup wrappers:

```powershell
.\install.ps1 -Mode StartWebUI
.\run.ps1 -Mode StartWebUI
.\scripts\install.ps1 -Mode StartWebUI
.\scripts\run.ps1 -Mode StartWebUI
```

Preview startup without launching dotnet:

```powershell
.\run.ps1 -Mode StartWebUI -WhatIf
```

Use `-GeneratePassword` only when you will also synchronize the actual VM
`SandboxUser` password to that generated value. For the normal per-use launch,
`.\run.ps1` loads `%ProgramData%\KSwordSandbox\install-state.json`, sets
`Sandbox__ConfigPath`, mirrors `KSWORDBOX_GUEST_PASSWORD` into the WebUI process
when it exists in User/Machine environment, and starts the WebUI on
`http://127.0.0.1:18080` or the next available fallback localhost port.

Before launching the WebUI, `run.ps1` checks the configured
`paths.guestPayloadRoot` and tries to build a self-contained Guest
Agent/R0Collector payload by calling:

```powershell
.\scripts\Prepare-GuestPayload.ps1 -SelfContained
```

If Visual Studio/MSBuild or native build tools are missing, WebUI mode prints a
warning and still starts for upload, planning, dry-run runbooks, and
configuration review. Fix the payload before live Hyper-V execution, or run
`.\run.ps1 -RequirePayloadForWebUI` when you want payload preparation failure to
stop startup.

If `run.ps1` only finds the repository template `config\sandbox.example.json`,
it stops with a Chinese "本机配置未就绪" message instead of silently starting
with placeholder VM/checkpoint values. Re-run the installer menu, choose
`Install / prepare local settings`, then confirm VM/checkpoint/driver path under
`Change settings`.

## Optional VirusTotal key

VirusTotal integration is optional and hash-only: the WebUI lookup checks an
existing SHA-256 report and does not upload samples. Store the key outside git
with the installer:

```powershell
.\install.ps1 -Mode ConfigureVTKey -PromptVTKey
```

This writes `KSWORDBOX_VIRUSTOTAL_API_KEY` to the current process and to the
current Windows User environment unless `-CurrentProcessOnly` is supplied. The
key value is never printed and is inherited by `.\run.ps1` / the WebUI process.
To clear it:

```powershell
.\install.ps1 -Mode ConfigureVTKey -ClearVTKey
```

You can also configure or clear the key from the interactive menu:
`Configure VT key`.

## Reset password secret

This is host-only secret storage. It does not change the VM account.

Interactive:

```powershell
.\install.ps1
# Change settings -> Reset password secret
```

Non-interactive generated reset:

```powershell
.\install.ps1 -Mode Change -ResetPassword -GeneratePassword
```

Non-interactive prompted reset:

```powershell
.\install.ps1 -Mode Change -ResetPassword -PromptPassword
```

## Reset actual VM guest password

Use this when you do not know the current guest password, or when you want the
host secret and the VM `SandboxUser` account synchronized in one step. It calls
`scripts/Reset-SandboxGuestPassword.ps1`, so it must run elevated and can restore
or refresh the clean checkpoint.

Interactive:

```powershell
.\install.ps1
# Change settings -> Reset actual VM guest password
```

Non-interactive generated VM reset:

```powershell
.\install.ps1 -Mode Change -ResetGuestVmPassword -GeneratePassword -Force
```

Non-interactive prompted VM reset:

```powershell
.\install.ps1 -Mode Change -ResetGuestVmPassword -PromptPassword -Force
```

The actual reset flow restores the configured checkpoint, mounts the offline
Windows disk, injects a one-shot SYSTEM service, boots the VM, validates
PowerShell Direct, stores the host secret, stops the VM, and refreshes the clean
checkpoint unless `-SkipCheckpointRefresh` is supplied.

## Status and uninstall

```powershell
.\install.ps1 -Mode Status
.\install.ps1 -Mode Uninstall -Force
```

Status shows secret presence, runtime folders, local config path,
`Sandbox__ConfigPath`, Hyper-V module availability, VM existence, checkpoint
existence, and whether the shell is elevated. It does not print passwords.

For deeper one-command readiness, use:

```powershell
.\scripts\Test-HyperVReadiness.ps1 -PromptForMissingGuestPassword
```

`-PromptForMissingGuestPassword` is process-only and non-persistent. It is for a
single elevated shell when you do not want to write User environment or DPAPI
backup. Use installer password reset modes for repeatable local setup.

Uninstall removes the current process/User environment secret plus local
installer metadata/DPAPI backup. It does not delete runtime job outputs under
`D:\Temp\KSwordSandbox`.

## Security boundary

`KSWORDBOX_GUEST_PASSWORD` is not the main VM escape boundary. Hyper-V
isolation, no sensitive host shares, network controls, checkpoint restore, and
cleanup are more important. The secret exists because PowerShell Direct needs a
guest Windows credential to stage the sample, run Guest Agent/R0Collector, and
copy outputs back.

Still avoid putting the value in git, reports, screenshots, or runbook logs.
The readiness and repository-policy scripts compare the current environment
secret value against candidate repository text files and fail without printing
the value if it appears in a file that could be staged.

The installer does not sign drivers and must not call `CSignTool.exe` or the
legacy `scripts\Sign-SandboxDriverWithKswordCSignTool.ps1` wrapper. Optional
real-driver lab validation is separate from install/run packaging and should use
the documented Windows test-signing path outside this repository.

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
- 测试签名：`HostTestSigningState` 只读显示宿主 test-signing 状态；guest test-signing 仍必须通过
  `-QueryGuestTestSigning`、`-EnableGuestTestSigning` 或交互菜单显式执行。
- driver：`DriverHostPathExists`、`DriverSignatureStatus`、`DriverServiceStatus`、
  `DriverServiceState`、`DriverMiniFilterLoaded`。普通 WebUI/PlanOnly 不要求加载 driver；真实 R0
  前再按 `DriverServiceStatusCommand` 或 `scripts\Manage-SandboxDriver.ps1 -Action Status` 查看。
- guest password：只显示 `ProcessSecretSet`、`UserSecretSet`、`MachineSecretSet` 和
  `GuestPasswordGuidance`，不会输出、摘要或回显密码值。The password value is never printed.

VM profile 的来源是本机安装状态和 `sandbox.local.json`，不要修改仓库模板保存本机 VM 名称、
checkpoint、guest path、driver path 或 secret。需要更新时继续使用：

```powershell
.\install.ps1 -Mode Change -UpdateHyperVConfig -VmName <VM> -CheckpointName <Checkpoint>
.\install.ps1 -Mode Change -QueryGuestTestSigning
.\install.ps1 -Mode Change -ShowTestSigningGuidance
```

打包/发布边界不变：安装器 does not sign drivers and must not call `CSignTool.exe`；便携包也不应包含
本机 `sandbox.local.json`、`install-state.json`、DPAPI 备份、样本、报告、VM 磁盘/快照或仓库构建二进制。
