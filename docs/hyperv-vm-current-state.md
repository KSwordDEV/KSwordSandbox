# Hyper-V VM 当前状态快照（current state）

生成时间：2026-07-10，Asia/Shanghai。

> 重要：这是一份历史只读观察记录，不是 2026-07-11 之后的 live verification。执行任何 `-Live`
> Hyper-V 分析前，必须在 elevated PowerShell 中重新运行 `Test-HyperVReadiness.ps1`。

范围：

- Repository：`D:\Projects\KswordSandbox`
- Target VM：`KSwordSandbox-Win10-Golden`
- Target checkpoint：`Clean`
- Target runtime root：`D:\Temp\KSwordSandbox`
- 本次记录为 read-only：未启动/停止 VM，未还原/创建 checkpoint，未修改 integration service，未复制文件到
  guest，未 commit，未 push。

## 验证状态（verification status）

本次 session 总体状态：**not ready / current Hyper-V state not directly verifiable**。

原因：

- 当前 PowerShell process 不是 elevated。
- 当前 process 未设置 `KSWORDBOX_GUEST_PASSWORD`。
- 因未 elevated，`Get-VM`、`Get-VMSnapshot`、`Get-VMIntegrationService` 无法读取当前 VM 状态。

已有 runtime 记录显示 VM 在 `2026-07-10T14:34:07+08:00` 曾准备成功，但这是 historical evidence，不是
本 session 的 live verification。

## 只读命令摘要（read-only command summary）

- `git status --short`
  - 结果：写入本文档前无输出；当时仓库看起来 clean。
- `Get-Command Get-VM,Get-VMSnapshot,Get-VMIntegrationService`
  - 结果：三个 cmdlets 均来自 `Hyper-V` module 且可用。
- Administrator/elevation probe
  - User：`WIN-1OMJO6UTCGN\Administrator`
  - Elevated administrator：`False`
  - PowerShell：`7.4.15`
  - OS：`Microsoft Windows 10 Professional Workstation`，version `10.0.19045`
- `Get-Service vmms,vmcompute`
  - 结果：Hyper-V Virtual Machine Management 与 Host Compute services 正在运行。
- `Get-VM -Name 'KSwordSandbox-Win10-Golden'`
  - 结果：因当前 process 未 elevated，authorization error。
- `Get-VMSnapshot -VMName 'KSwordSandbox-Win10-Golden'`
  - 结果：因当前 process 未 elevated，authorization error。
- `Get-VMIntegrationService -VMName 'KSwordSandbox-Win10-Golden'`
  - 结果：因当前 process 未 elevated，authorization error。
- `scripts\Test-HyperVReadiness.ps1 -VmName 'KSwordSandbox-Win10-Golden' -CheckpointName 'Clean' -GuestPasswordSecretName 'KSWORDBOX_GUEST_PASSWORD' -RuntimeRoot 'D:\Temp\KSwordSandbox'`
  - Script exit code：`1`
  - Passed：Hyper-V PowerShell module、runtime root writable（只读 ACL inspection）。
  - Failed：administrator privilege、guest password environment variable。
  - Warning/skipped：target VM、Clean checkpoint、Guest Service Interface；原因是非 elevated session 无法查询 VM state。

## Target readiness items

### VM `KSwordSandbox-Win10-Golden`

当前 live status：**本 session 未验证**。

直接 `Get-VM` 被 authorization policy 阻止。历史 runtime evidence
`D:\Temp\KSwordSandbox\hyperv-vm-checksnap.txt` 曾记录：

- VM name：`KSwordSandbox-Win10-Golden`
- VM state：`Off`
- Checkpoint type：`Standard`
- Automatic checkpoints：`False`
- VM path：`D:\Temp\KSwordSandbox\HyperV\KSwordSandbox-Win10-Golden\KSwordSandbox-Win10-Golden`

### Checkpoint `Clean`

当前 live status：**本 session 未验证**。

直接 `Get-VMSnapshot` 被 authorization policy 阻止。历史 runtime evidence 曾记录：

- Snapshot name：`Clean`
- Snapshot type：`Standard`
- Creation time：`2026-07-10 14:30:54`
- Snapshot id：`587d58c4-530b-404a-b070-38eb0ce4ed3d`

文件系统 evidence 也曾显示 snapshot files 位于：

```text
D:\Temp\KSwordSandbox\HyperV\KSwordSandbox-Win10-Golden\KSwordSandbox-Win10-Golden\Snapshots\587D58C4-530B-404A-B070-38EB0CE4ED3D.*
```

### Guest Service Interface

当前 live status：**本 session 未验证**。

直接 `Get-VMIntegrationService` 被 authorization policy 阻止。历史 runtime evidence
`D:\Temp\KSwordSandbox\hyperv-vm-setup.md` 曾记录：

- Guest Service Interface enabled：`True`
- Heartbeat OK during setup：`True`
- Setup status：`Ready`

中文 Windows 可能显示为 `来宾服务接口`；稳定组件 ID 为
`6C09BB55-D683-4DA0-8931-C9BF705F6480`。

### PowerShell Direct prerequisites

当前 session status：**not ready**。

观察结果：

- Hyper-V module 和 read-only cmdlets 已安装。
- Host OS 是 Windows 10 version `10.0.19045`，满足 PowerShell Direct 场景。
- 当前 process 未 elevated，因此 live Hyper-V operations 与 PowerShell Direct runbook actions 被阻止。
- readiness script 未在 Process/User/Machine scope 看到 `KSWORDBOX_GUEST_PASSWORD`。
- 当前 VM state 无法读取。PowerShell Direct 需要 VM 正在运行才能测试；本次 pass 刻意没有启动 VM。

### Runtime root `D:\Temp\KSwordSandbox`

当前 status：**host-side 只读检查显示存在且可用**。

观察结果：

- Directory exists。
- `Test-HyperVReadiness.ps1` 通过只读 ACL inspection 判断其 appears writable。
- D: free space 约 `81.94 GiB`。
- 关键文件曾存在：
  - `D:\Temp\KSwordSandbox\HyperV\KSwordSandbox-Win10-Golden\Virtual Hard Disks\KSwordSandbox-Win10-Golden.vhdx`
  - `D:\Temp\KSwordSandbox\payload\guest-tools\agent\KSword.Sandbox.Agent.exe`
  - `D:\Temp\KSwordSandbox\payload\guest-tools\r0collector\KSword.Sandbox.R0Collector.exe`
  - `D:\Temp\KSwordSandbox\samples\KSword.Sandbox.HarmlessSample\KSword.Sandbox.HarmlessSample.exe`
  - `D:\Temp\KSwordSandbox\hyperv-vm-setup.md`
  - `D:\Temp\KSwordSandbox\hyperv-live-smoke.md`

这些 runtime files 是本地 evidence，不得提交到 git。

## 缺口（gaps）

1. 需要在 elevated PowerShell process 中重新运行，以直接读取 VM、checkpoint 和 integration service。
2. 在 elevated process 中设置 `KSWORDBOX_GUEST_PASSWORD` 后再做 readiness 或 live runbook check。
3. PowerShell Direct 无法在缺少 credential 且 VM 停止时证明；本次 pass 刻意没有启动 VM。
4. 当前 VM/checkpoint/GSI state 仍未在本 session 直接验证，尽管 2026-07-10 的历史 evidence 显示曾 ready。

## 推荐复验命令（recommended next step）

在 Hyper-V host 的 elevated PowerShell 中：

```powershell
$env:KSWORDBOX_GUEST_PASSWORD = '<SandboxUser password>'

pwsh -NoProfile -ExecutionPolicy Bypass -File D:\Projects\KswordSandbox\scripts\Test-HyperVReadiness.ps1 `
  -VmName 'KSwordSandbox-Win10-Golden' `
  -CheckpointName 'Clean' `
  -GuestUserName 'SandboxUser' `
  -GuestPasswordSecretName 'KSWORDBOX_GUEST_PASSWORD' `
  -GuestPayloadRoot 'D:\Temp\KSwordSandbox\payload\guest-tools' `
  -GuestWorkingDirectory 'C:\KSwordSandbox' `
  -RuntimeRoot 'D:\Temp\KSwordSandbox'
```

Expected readiness result：`OverallStatus = Passed`，且 VM、checkpoint、Guest Service Interface 检查不再 skipped。

只读 Hyper-V 状态查询：

```powershell
Get-Command Get-VM, Get-VMSnapshot, Get-VMIntegrationService
Get-Service vmms, vmcompute
Get-VM -Name 'KSwordSandbox-Win10-Golden'
Get-VMSnapshot -VMName 'KSwordSandbox-Win10-Golden' -Name 'Clean'
Get-VMIntegrationService -VMName 'KSwordSandbox-Win10-Golden'
```

不要把由这些命令或 live run 生成的 JSON、reports、guest outputs、VM files 或 logs 提交到仓库。
