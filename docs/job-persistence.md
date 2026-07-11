# Job persistence and restart recovery

KSword Sandbox stores recoverable job state under:

```text
D:\Temp\KSwordSandbox\jobs\{jobId:N}\
```

The runtime root comes from `SandboxConfig.Paths.RuntimeRoot`, so custom
configs use the same `jobs\{jobId}` layout under their configured root.

## Durable files

- `job-metadata.json`
  Compact `AnalysisJob` metadata used to repopulate `SandboxJobService.ListJobs`
  and `GetJob` after a WebHost restart.
- `runbook-execution.json`
  Existing execution result file. It remains the detailed diagnostic record and
  preserves stdout/stderr/commands for local troubleshooting.
- `runbook-progress.json`
  UI-safe progress snapshot derived from the execution result. It excludes
  PowerShell commands, stdout, and stderr.
- `guest-import-state.json`
  Compact import state: source path, imported event count, status, message, and
  update time. Recovery can use this without loading `events.json`.
- `report.json`, `report.html`, `report.zh.html`, `report.en.html`
  Existing report artifacts. Older jobs without `job-metadata.json` are
  recovered from `report.json` when possible.

## Recovery behavior

`SandboxJobService` refreshes the job index during construction and when
`ListJobs()` runs. It enumerates only first-level GUID-named job directories and
does not read guest `events.json` during enumeration.

Recovery order:

1. Prefer `job-metadata.json`.
2. Fall back to `report.json` for older jobs.
3. Recover import state from `guest-import-state.json`; if absent, infer it from
   the report's `guest.events.imported` / `guest.events.empty` marker.
4. Recover runbook progress from `runbook-progress.json`; if absent, derive a
   UI-safe terminal snapshot from `runbook-execution.json`.

This keeps existing APIs compatible: callers still use `ListJobs`, `GetJob`,
`GetLiveEvents`, `ImportGuestEvents`, and `SaveRunbookExecutionResult`.

Compact companion files are read defensively. If `job-metadata.json`,
`runbook-progress.json`, or `guest-import-state.json` is malformed or far larger
than the compact sidecar budget, the reader moves it aside as `*.bad`, skips it,
and continues through the normal fallback path. Recovery backfills a fresh
compact sidecar when enough report or execution data is available.

Companion writes use a unique temporary file in the job directory, flush the JSON
payload, and then replace the destination. This prevents half-written compact
state from being observed after a process crash or restart.

`ListJobs()` returns recovered jobs by persisted creation time, so restart
recovery does not depend on filesystem enumeration order.

## Safe live event enumeration

Live telemetry source discovery scans only expected job guest artifacts:

- `events.json`
- `*.jsonl`
- packet capture files recognized by the artifact layer

Large JSON-array `events.json` files are not loaded by the live monitor. When an
`events.json` file is larger than the bounded live-read threshold, the telemetry
reader returns a `live.events.source_status` event with status `too-large`
instead of parsing the whole file. JSONL remains the preferred streaming format.

Manual guest import still intentionally loads the selected event source because
that action regenerates reports.

## Smoke coverage

Targeted restart-recovery coverage can be run with:

```powershell
dotnet run --project .\tests\KSword.Sandbox.SmokeTests\KSword.Sandbox.SmokeTests.csproj -- --scenario job-persistence.recovery.contract
```

The scenario verifies corrupt compact sidecars are quarantined as `.bad`, report
and runbook fallbacks still recover the job after a service restart,
`ListJobs()` preserves recovered creation-time order, and a huge invalid
`events.json` is reported as `too-large` by live telemetry instead of being
parsed during recovery or live polling.
