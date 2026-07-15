# KSword Sandbox 操作者 CLI / operator CLI

本页记录不经过 WebUI 的命令循环，用于调试最小 job 链路。命令默认安全，并保持 JSON-friendly，方便脚本和操作者排障。

English summary: this page documents the no-WebUI command loop for the minimum job path.

Canonical command coverage remains in `docs/run.md` and `docs/verification.md`;
this page only covers the JobTool/no-WebUI loop.

This CLI does not install virtualization products, create VMs, restore clean baselines, configure
VirusTotal, sign drivers, or call `CSignTool.exe`. Before using it for a real
operator flow, choose one install path from `docs/install.md`: already configured
environment, restore an existing clean checkpoint/snapshot, or create/prep a new
VM/environment. Low-cost readiness remains:

```powershell
.\install.ps1 -Mode CheckEnvironment
.\run.ps1 -Mode CheckEnvironment
.\scripts\Invoke-OperatorCli.ps1 readiness -Json
.\scripts\Invoke-OperatorCli.ps1 readiness -Provider VMware -Json
```

JobTool reads and writes runtime job files. Keep job folders, reports,
`artifact-index.json`, imported events, samples, payload binaries, VM files,
captures, dumps, and secrets under the runtime root and out of git.

## 入口 / Entry points

直接使用 .NET tool / Use the .NET tool directly:

```powershell
dotnet run --project .\tools\KSword.Sandbox.JobTool\KSword.Sandbox.JobTool.csproj -- <command> --json
```

或使用 PowerShell wrapper / Or use the PowerShell wrapper:

```powershell
.\scripts\Invoke-OperatorCli.ps1 <command> -Json
```

支持的命令 / Supported commands:

- `plan`
- `execute` (`run` alias)
- `import`
- `report`
- `artifacts`
- `list`
- `status`
- `recover`
- `readiness`

JobTool 仍接受 legacy aliases： `list-jobs`, `show-job`,
`rebuild-report`, `import-live`, and `inspect-artifacts`.

## 安全契约 / Safety contract

- `list`, `status`, `artifacts` without `--write-index`, `recover` without
  write switches, and `readiness` are read-only host-side operations.
- `plan` creates a dry-run plan/report only; it does not start, restore, stop,
  or mutate a VM.
- `report` and `import` rebuild local report artifacts from existing files.
- `artifacts --write-index` refreshes `artifact-index.json`.
- `recover --write-state`, `recover --write-index`, and
  `recover --rebuild-report` write only local job files.
- `execute` 默认 dry-run；只有显式 `-Live`/`--live` 才会运行当前 provider 的恢复、
  启动、guest 分析、收集和清理步骤。
- 同一 runtime root 只允许一个 live job 或 installer VM maintenance 操作持有
  `locks\live-execution.lock`。Web、CLI、安装器和三个 provider 使用同一个跨进程 lease；竞争者
  在任何 VM 命令前失败，dry-run、`list`、`status` 和报告重建不受影响。
- 没有持久化 `LiveExecutionLeasePath` 的旧 runbook 必须重新 `plan` 才能 live；其 status/report/artifact
  恢复仍可使用，不会静默切换到另一个锁目录。

All JSON output includes `secretValuePrinted=false`; password/API key/token-like
fields are redacted before printing. Plan and execution JSON expose only counts,
provider identity, aggregate status, and safe step metadata; full runbook commands,
stdout, and stderr remain in host-local plan/execution artifacts and are never copied
to CLI JSON or text output.

## 常用流程 / Common flow

```powershell
# 1. Check host-side operator readiness.
.\scripts\Invoke-OperatorCli.ps1 readiness -Json
.\scripts\Invoke-OperatorCli.ps1 readiness -Provider Qemu -Json

# 2. Create a non-mutating plan.
.\scripts\Invoke-OperatorCli.ps1 plan -SamplePath D:\Temp\sample.exe -Json
.\scripts\Invoke-OperatorCli.ps1 plan -SamplePath D:\Temp\sample.exe -Provider VMware `
  -VmName KSword-VMware -BaselineName Clean `
  -MachineDefinitionPath D:\VMs\KSword\KSword.vmx `
  -PlanPath D:\Temp\KSwordSandbox\plans\vmware-plan.json -Json

# 3. Execute the same provider runbook as a dry-run, then explicitly live.
.\scripts\Invoke-OperatorCli.ps1 execute -SamplePath D:\Temp\sample.exe -Provider VMware -Json
.\scripts\Invoke-OperatorCli.ps1 execute -SamplePath D:\Temp\sample.exe -Provider VMware -Live
.\scripts\Invoke-OperatorCli.ps1 execute -SamplePath D:\Temp\sample.exe -Provider Qemu `
  -VmName KSword-QEMU `
  -MachineDefinitionPath D:\VMs\KSword\base.qcow2 -QemuDiskFormat qcow2 -Live

# 4. List jobs and inspect one job.
.\scripts\Invoke-OperatorCli.ps1 list -Json
.\scripts\Invoke-OperatorCli.ps1 status -JobId <guid> -Json

# 5. After guest outputs exist, import or rebuild reports.
.\scripts\Invoke-OperatorCli.ps1 import -JobId <guid> -SamplePath D:\Temp\sample.exe -EventsPath <events.json> -Json
.\scripts\Invoke-OperatorCli.ps1 report -JobId <guid> -Provider VMware -Json

# 6. Inspect artifacts and optionally persist the index.
.\scripts\Invoke-OperatorCli.ps1 artifacts -JobId <guid> -Json
.\scripts\Invoke-OperatorCli.ps1 artifacts -JobId <guid> -WriteIndex -Json

# 7. Diagnose an interrupted or partial job.
.\scripts\Invoke-OperatorCli.ps1 recover -JobId <guid> -Json
.\scripts\Invoke-OperatorCli.ps1 recover -JobId <guid> -Provider Qemu -RebuildReport -WriteIndex -WriteState -Json
```

## JobTool 命令参考 / command reference

### `plan`

创建 dry-run `AnalysisJob` 和 report artifacts / Creates a dry-run `AnalysisJob` and report artifacts.

```powershell
dotnet run --project .\tools\KSword.Sandbox.JobTool\KSword.Sandbox.JobTool.csproj -- plan --sample <exe> --plan-path <plan.json> --json
```

Use `--provider HyperV|VMware|Qemu` to override the active local config for a
dry-run plan. `--vm` and `--baseline` select the logical VM/baseline for all
three providers. VMware additionally accepts `--machine-definition-path` or
`--vmx-path` for the actual VMX; QEMU accepts `--machine-definition-path` or
`--disk-image-path` plus `--qemu-disk-format qcow2|raw|vhdx|vmdk`. Omitted
values continue to come from the selected provider profile in local config.
Guest remoting, tool paths, headless/display policy, QEMU memory/devices, and
overlay policy remain profile-owned settings.
When QEMU `useOverlayDisk=true`, the effective baseline is `per-job-overlay`;
an explicit different `--baseline` is rejected instead of being silently ignored.
Conflicting generic/provider-specific machine paths and options for the wrong
provider are also rejected before a plan is persisted.
The Core repeats the same provider-resource validation for Web forms, JSON API
submissions, pipeline callers, and first-time offline imports, so invalid
cross-provider fields cannot be silently ignored outside JobTool. Existing
offline jobs continue to use their persisted runbook identity.
`--plan-path <json>`（wrapper 为 `-PlanPath`）可选地把同一个
`KSwordSandbox.PlanResult` 写到指定文件；相对路径以 repository root 为基准。该能力由通用
JobTool 实现，对 Hyper-V、VMware 和 QEMU 语义一致，不会调用 Hyper-V E2E 专用脚本。

重要 JSON 字段 / Important JSON fields: `kind=KSwordSandbox.PlanResult`, `jobId`, `jobRoot`,
`provider`, `vmName`, `baselineName` (with legacy `checkpointName` alias), `machineDefinitionPath`, `qemuDiskFormat`, `planPath`,
`guestReadyTimeoutSeconds`, `jsonReportPath`, `htmlReportPath`, `runbookStepCount`, `vmAction=none`.

### `execute`

对 Hyper-V、VMware 或 QEMU 运行统一 runbook。默认仍是 dry-run；live 成功后默认自动导入
guest events 并生成最终报告。

```powershell
.\scripts\Invoke-OperatorCli.ps1 execute -SamplePath <exe> -Provider HyperV -Json
.\scripts\Invoke-OperatorCli.ps1 execute -SamplePath <exe> -Provider Qemu -Live -NoR0Collector
```

可选项：`-NoOpenVmConsole`、`-SkipGuestImport`、`-GuestReadyTimeoutSeconds`、
`-StepTimeoutSeconds`、`-VmName`、`-BaselineName`（兼容别名 `-SnapshotName`）、`-MachineDefinitionPath` 和
`-QemuDiskFormat`。直接调用 JobTool 时对应
`--guest-ready-timeout-seconds` / `--step-timeout-seconds`。JSON kind 为
`KSwordSandbox.ExecutionResult`，会回显所选 provider、VM/baseline、实际 provider
资源路径、QEMU 格式和两个有效 timeout，且步骤摘要不包含命令、stdout、stderr 或 secret。
`PlanResult` 的 JSON/文本从 runbook 读取 effective identity；`ExecutionResult` 从实际 execution
记录读取同一组字段，不会把 submission 中的逻辑 VM 名误报成 provider 实际 target。
live lease/elevation 等没有 source step index 的 preflight 失败仍会填充 `failedStepId`/`failedStepTitle`，
文本输出同时显示安全的 aggregate `Message`，不要求操作者从空的 stdout/stderr 猜原因。
Web durable progress 同样使用 `CurrentStepId` 标记 preflight，正常 source steps 保持 Pending，失败计数为 1；
重启恢复后仍区分旧 runbook 需重新 plan、lease 竞争和 elevation 缺失。

资源字段语义 / resource semantics:

- Hyper-V：`VmName`/`--vm` 是实际 Hyper-V VM；`MachineDefinitionPath` 不使用。
- VMware：`VmName` 是任务/显示身份，`MachineDefinitionPath` 是实际传给 `vmrun` 的 `.vmx`。
- QEMU：`VmName` 是任务与进程身份，`MachineDefinitionPath` 是实际基础磁盘；
  `QemuDiskFormat` 必须与 `qemu-img info` 返回格式一致。profile 启用
  `useOverlayDisk=true` 时有效 baseline 回显为 `per-job-overlay`，不会把未使用的内部快照名
  当作本次恢复点；关闭 overlay 时 `BaselineName`/`--baseline`（兼容 `SnapshotName`/`--checkpoint`）才选择 qcow2 内部快照。

WebUI、`POST /api/jobs/plan`、JobTool 和 PowerShell wrapper 都使用这组字段；任务详情和
CLI JSON 会回显最终选择，避免界面显示一个 VM、provider 实际启动另一个资源。

### `list`

Scans `<runtimeRoot>\jobs` and returns discovered job summaries.

```powershell
dotnet run --project .\tools\KSword.Sandbox.JobTool\KSword.Sandbox.JobTool.csproj -- list --limit 50 --json
```

JSON kind: `KSwordSandbox.JobList`.
每条 job summary 同时包含持久化的 `provider`、`targetVmName`、`baselineName`、
`machineDefinitionPath` 和 `qemuDiskFormat`；文本输出至少显示实际 VM 与 baseline。

### `status`

Shows one job by `--job-id` or `--job-root`.

```powershell
dotnet run --project .\tools\KSword.Sandbox.JobTool\KSword.Sandbox.JobTool.csproj -- status --job-id <guid> --json
```

JSON kind: `KSwordSandbox.JobDetails`.
文本与 JSON 都显示实际 VM、baseline、VMware VMX 或 QEMU 基础磁盘，以及 QEMU 格式；
这些字段来自任务产物，不随当前本机 profile 切换。

### `report`

报告重建与 `import live` 会优先继承 job 目录中持久化的 provider、实际 VM、baseline、VMX/QEMU
基础磁盘和 QEMU 格式；`--provider`、`--vm`、`--baseline`（兼容 `--checkpoint`）、
`--machine-definition-path`、`--qemu-disk-format` 可在旧任务缺少元数据或导入外部任务时显式指定。
PowerShell wrapper 的同名参数也会转发。它们不会因为当前 `sandbox.local.json` 选择了另一后端
而改写事件前缀或 provider 资源身份。

Rebuilds reports from existing events/runbook files.

```powershell
dotnet run --project .\tools\KSword.Sandbox.JobTool\KSword.Sandbox.JobTool.csproj -- report --job-id <guid> --sample <exe> --events <events.json|jsonl> --json
```

JSON kind: `KSwordSandbox.ReportRebuildResult`.

专用 wrapper `scripts\Rebuild-JobReport.ps1` 同样接受 `-Provider`、`-VmName`、
`-BaselineName`（兼容 `-SnapshotName` / `-CheckpointName`）、`-MachineDefinitionPath` 和
`-QemuDiskFormat`。所有 report/recover 重建入口都会先执行与 plan/execute 相同的 provider
资源冲突校验；`report-rebuild-diagnostics.json` 在成功和失败时都保留最终解析出的资源身份。
显式提供的 `runbook-execution.json` 也必须与同一 job 的 provider、VM、baseline、VMX/磁盘和
QEMU 格式一致；旧文件可缺少资源字段，但不能带入另一任务或另一 provider 的身份。
当已有 job metadata/runbook 可用且资源身份未被显式改写时，重建会复用原始 runbook 与
submission/`CreatedAt`，因此 QEMU per-job overlay 的 target 不会再次追加 job ID，逻辑 VM 名
也不会被有效 overlay target 替换；切换当前本机 profile
也不会改变历史 VM 身份。元数据缺失时则以 `runbook-execution.json` / `report.json` 的身份覆盖
当前配置推导值；如果旧版持久化产物完全没有 provider 字段，则按旧版唯一支持的 Hyper-V
格式恢复，不会因为当前 profile 已切换到 VMware/QEMU 而重新标记。全新的无元数据外部导入仍可用
`--provider` 明确指定后端。

### `import`

Imports an externally collected live run and regenerates reports.

```powershell
dotnet run --project .\tools\KSword.Sandbox.JobTool\KSword.Sandbox.JobTool.csproj -- import --job-id <guid> --sample <exe> --events <events.json|jsonl> --json
```

JSON kind: `KSwordSandbox.ImportLiveResult`.
外部导入可使用与 `report` 相同的 provider 资源参数；已有 job 文件仍优先提供缺省值。

### `artifacts`

Builds the host-visible artifact index. Add `--write-index` to persist it.

```powershell
dotnet run --project .\tools\KSword.Sandbox.JobTool\KSword.Sandbox.JobTool.csproj -- artifacts --job-id <guid> --json
```

JSON kind: `KSwordSandbox.ArtifactInspection`.

### `recover`

Reads provider-neutral recovery files (`runbook-execution.json`, `runbook-progress.json`,
`guest-import-state.json`, reports, and artifact indexes) and returns next actions. Legacy
`hyperv-e2e-start-result.json` / `hyperv-e2e-collect-result.json` files are included when a job
was created by the Hyper-V compatibility helper; VMware/QEMU recovery does not depend on them.
It does not mutate VMs.

```powershell
dotnet run --project .\tools\KSword.Sandbox.JobTool\KSword.Sandbox.JobTool.csproj -- recover --job-id <guid> --json
```

Optional write switches:

- `--write-state`: writes `operator-recovery.json`.
- `--write-index`: writes `artifact-index.json`.
- `--rebuild-report`: re-runs report import from existing events.

`recover --rebuild-report` 使用与 `report` 相同的持久化资源身份恢复顺序，并允许同一组显式
provider/VM/baseline/VMX 或磁盘/格式参数。只读 recover 的 summary 也会返回这些字段。

JSON kind: `KSwordSandbox.RecoveryResult`.

### `readiness`

Without a provider option, runs JobTool path/config checks for operator CLI
commands. It does not start VMs or probe guests.

```powershell
dotnet run --project .\tools\KSword.Sandbox.JobTool\KSword.Sandbox.JobTool.csproj -- readiness --json
```

JSON kind: `KSwordSandbox.OperatorReadiness`.

Pass `-Provider HyperV|VMware|Qemu` to run the same selected-provider
`run.ps1 -Mode CheckEnvironment` contract used by normal runtime diagnostics.
Use `-ProviderReadiness` without `-Provider` to read the provider from the
active local config. Both forms are read-only and report host acceleration,
provider tools, VM/baseline, guest endpoint security, payload, secret presence,
`LiveReady`, and `ActualGuestPasswordUnknownOldPasswordRecovery*` capability fields
without starting, restoring, or stopping a VM:

```powershell
.\scripts\Invoke-OperatorCli.ps1 readiness -Provider VMware -Json
.\scripts\Invoke-OperatorCli.ps1 readiness -Provider Qemu -Json
.\scripts\Invoke-OperatorCli.ps1 readiness -ProviderReadiness -Json
```

For the existing deeper Hyper-V-only guest probe, use the compatibility switch:

```powershell
.\scripts\Invoke-OperatorCli.ps1 readiness -HyperVReadiness -Json
```

## 退出码 / Exit codes

- `0`: command succeeded, or readiness has no failed required checks.
- `1`: invalid command, help-needed usage, or readiness/recover found a
  blocking condition.
- `2`: argument, file, JSON, IO, or configuration failure.
