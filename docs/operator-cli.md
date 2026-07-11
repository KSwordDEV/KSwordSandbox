# KSword Sandbox operator CLI

This page documents the no-WebUI command loop for debugging the minimum job
path. Commands are designed to be JSON-friendly and safe by default.

Canonical command coverage remains in `docs/run.md` and `docs/verification.md`;
this page only covers the JobTool/no-WebUI loop.

JobTool reads and writes runtime job files. Keep job folders, reports,
`artifact-index.json`, imported events, samples, payload binaries, VM files,
captures, dumps, and secrets under the runtime root and out of git.

## Entry points

Use the .NET tool directly:

```powershell
dotnet run --project .\tools\KSword.Sandbox.JobTool\KSword.Sandbox.JobTool.csproj -- <command> --json
```

Or use the PowerShell wrapper:

```powershell
.\scripts\Invoke-OperatorCli.ps1 <command> -Json
```

Supported commands:

- `plan`
- `import`
- `report`
- `artifacts`
- `list`
- `status`
- `recover`
- `readiness`

Legacy aliases are still accepted by JobTool: `list-jobs`, `show-job`,
`rebuild-report`, `import-live`, and `inspect-artifacts`.

## Safety contract

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

## Common flow

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

## JobTool command reference

### `plan`

Creates a dry-run `AnalysisJob` and report artifacts.

```powershell
dotnet run --project .\tools\KSword.Sandbox.JobTool\KSword.Sandbox.JobTool.csproj -- plan --sample <exe> --json
```

Important JSON fields: `kind=KSwordSandbox.PlanResult`, `jobId`, `jobRoot`,
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

## Exit codes

- `0`: command succeeded, or readiness has no failed required checks.
- `1`: invalid command, help-needed usage, or readiness/recover found a
  blocking condition.
- `2`: argument, file, JSON, IO, or configuration failure.
