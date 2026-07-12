# KSword Sandbox 操作者 CLI / operator CLI

本页记录不经过 WebUI 的命令循环，用于调试最小 job 链路。命令默认安全，并保持 JSON-friendly，方便脚本和操作者排障。

English summary: this page documents the no-WebUI command loop for the minimum job path.

Canonical command coverage remains in `docs/run.md` and `docs/verification.md`;
this page only covers the JobTool/no-WebUI loop.

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
- VM-mutating live execution remains outside this operator CLI path and still
  requires the explicit live Hyper-V scripts.

All JSON output includes `secretValuePrinted=false`; password/API key/token-like
fields are redacted before printing.

## 常用流程 / Common flow

```powershell
# 1. Check host-side operator readiness.
.\scripts\Invoke-OperatorCli.ps1 readiness -Json

# 2. Create a non-mutating plan.
.\scripts\Invoke-OperatorCli.ps1 plan -SamplePath D:\Temp\sample.exe -Json

# 3. List jobs and inspect one job.
.\scripts\Invoke-OperatorCli.ps1 list -Json
.\scripts\Invoke-OperatorCli.ps1 status -JobId <guid> -Json

# 4. After guest outputs exist, import or rebuild reports.
.\scripts\Invoke-OperatorCli.ps1 import -JobId <guid> -SamplePath D:\Temp\sample.exe -EventsPath <events.json> -Json
.\scripts\Invoke-OperatorCli.ps1 report -JobId <guid> -Json

# 5. Inspect artifacts and optionally persist the index.
.\scripts\Invoke-OperatorCli.ps1 artifacts -JobId <guid> -Json
.\scripts\Invoke-OperatorCli.ps1 artifacts -JobId <guid> -WriteIndex -Json

# 6. Diagnose an interrupted or partial job.
.\scripts\Invoke-OperatorCli.ps1 recover -JobId <guid> -Json
.\scripts\Invoke-OperatorCli.ps1 recover -JobId <guid> -RebuildReport -WriteIndex -WriteState -Json
```

## JobTool 命令参考 / command reference

### `plan`

创建 dry-run `AnalysisJob` 和 report artifacts / Creates a dry-run `AnalysisJob` and report artifacts.

```powershell
dotnet run --project .\tools\KSword.Sandbox.JobTool\KSword.Sandbox.JobTool.csproj -- plan --sample <exe> --json
```

重要 JSON 字段 / Important JSON fields: `kind=KSwordSandbox.PlanResult`, `jobId`, `jobRoot`,
`jsonReportPath`, `htmlReportPath`, `runbookStepCount`, `vmAction=none`.

### `list`

Scans `<runtimeRoot>\jobs` and returns discovered job summaries.

```powershell
dotnet run --project .\tools\KSword.Sandbox.JobTool\KSword.Sandbox.JobTool.csproj -- list --limit 50 --json
```

JSON kind: `KSwordSandbox.JobList`.

### `status`

Shows one job by `--job-id` or `--job-root`.

```powershell
dotnet run --project .\tools\KSword.Sandbox.JobTool\KSword.Sandbox.JobTool.csproj -- status --job-id <guid> --json
```

JSON kind: `KSwordSandbox.JobDetails`.

### `report`

Rebuilds reports from existing events/runbook files.

```powershell
dotnet run --project .\tools\KSword.Sandbox.JobTool\KSword.Sandbox.JobTool.csproj -- report --job-id <guid> --sample <exe> --events <events.json|jsonl> --json
```

JSON kind: `KSwordSandbox.ReportRebuildResult`.

### `import`

Imports an externally collected live run and regenerates reports.

```powershell
dotnet run --project .\tools\KSword.Sandbox.JobTool\KSword.Sandbox.JobTool.csproj -- import --job-id <guid> --sample <exe> --events <events.json|jsonl> --json
```

JSON kind: `KSwordSandbox.ImportLiveResult`.

### `artifacts`

Builds the host-visible artifact index. Add `--write-index` to persist it.

```powershell
dotnet run --project .\tools\KSword.Sandbox.JobTool\KSword.Sandbox.JobTool.csproj -- artifacts --job-id <guid> --json
```

JSON kind: `KSwordSandbox.ArtifactInspection`.

### `recover`

Reads recovery-related files (`runbook-execution.json`,
`hyperv-e2e-start-result.json`, `hyperv-e2e-collect-result.json`,
`guest-import-state.json`) and returns next actions. It does not mutate VMs.

```powershell
dotnet run --project .\tools\KSword.Sandbox.JobTool\KSword.Sandbox.JobTool.csproj -- recover --job-id <guid> --json
```

Optional write switches:

- `--write-state`: writes `operator-recovery.json`.
- `--write-index`: writes `artifact-index.json`.
- `--rebuild-report`: re-runs report import from existing events.

JSON kind: `KSwordSandbox.RecoveryResult`.

### `readiness`

Runs host-side path/config checks for operator CLI commands. It does not start
VMs or probe guests.

```powershell
dotnet run --project .\tools\KSword.Sandbox.JobTool\KSword.Sandbox.JobTool.csproj -- readiness --json
```

JSON kind: `KSwordSandbox.OperatorReadiness`.

For the existing deeper Hyper-V readiness script, use:

```powershell
.\scripts\Invoke-OperatorCli.ps1 readiness -HyperVReadiness -Json
```

## 退出码 / Exit codes

- `0`: command succeeded, or readiness has no failed required checks.
- `1`: invalid command, help-needed usage, or readiness/recover found a
  blocking condition.
- `2`: argument, file, JSON, IO, or configuration failure.
