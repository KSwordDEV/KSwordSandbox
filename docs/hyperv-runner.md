# Hyper-V runbook runner

The runner adds an execution boundary for `SandboxRunbook` and is registered
behind the WebUI/API. The default mode is dry-run, so normal planning and
operator review do not launch PowerShell or run Hyper-V commands.

## Execution modes

### Dry-run

`SandboxRunbookExecutionOptions.Mode` defaults to
`SandboxRunbookExecutionMode.DryRun`.

Dry-run behavior:

- Records every `SandboxRunbookStep.PowerShell` command.
- Marks each step as skipped and successful.
- Does not start PowerShell.
- Does not mutate VM state.
- Returns an aggregate `SandboxRunbookExecutionResult` with `ExecutedSteps = 0`.

### Live

Live mode must be selected explicitly:

```csharp
var executor = new PowerShellRunbookExecutor();
var result = await executor.ExecuteAsync(
    runbook,
    new SandboxRunbookExecutionOptions
    {
        Mode = SandboxRunbookExecutionMode.Live
    },
    cancellationToken);
```

Live behavior:

- Executes `SandboxRunbookStep.PowerShell` one step at a time.
- Starts a separate non-interactive PowerShell process for each step.
- Captures stdout, stderr, exit code, and duration for each step.
- Stops immediately on the first non-zero exit code, timeout, launch failure, or
  cancellation.
- Returns only the executed step results up to the stopping point.

## Elevation requirement

Hyper-V cmdlets such as `Get-VM`, `Start-VM`, `Restore-VMSnapshot`,
`Copy-VMFile`, and PowerShell Direct require an elevated host process. Run the
future host service or console runner from an elevated PowerShell session before
using live mode.

The executor enforces this by default:

- `SandboxRunbookExecutionOptions.RequireElevatedPowerShell` defaults to `true`.
- If any source step has `RequiresElevation = true` and the current process is
  not Administrator, live mode returns a failed preflight result.
- No VM command is launched when the elevation preflight fails.

Keep this check enabled for Hyper-V runbooks.

## Result data

`SandboxRunbookExecutionResult` contains:

- Job ID and target VM name.
- Execution mode.
- Total source step count.
- Number of launched PowerShell processes.
- Failed step index, when a source step failed.
- Aggregate duration and elevation requirement flag.
- Per-step `SandboxRunbookStepExecutionResult` entries.

Each step result contains:

- Step index, ID, title, and PowerShell command.
- Skipped/success status.
- stdout/stderr.
- PowerShell exit code.
- UTC start time and duration.
- Elevation and VM mutation flags copied from the source step.
- Optional message for dry-run, timeout, cancellation, launch failure, or exit
  failure details.

The Web/API now persists every execution attempt to the job folder:

```text
D:\Temp\KSwordSandbox\jobs\<job-id>\runbook-execution.json
```

After a live runbook succeeds, the host attempts to import guest output from the
collected guest folder. Manual import is also available when testing with
synthetic events or when collection finishes after the API call:

```http
POST /api/jobs/{jobId}/guest-events/import
Content-Type: application/json

{
  "eventsPath": "D:\\Temp\\KSwordSandbox\\jobs\\<job-id>\\guest\\<job-id>\\events.json"
}
```

When `eventsPath` is omitted, the service searches
`D:\Temp\KSwordSandbox\jobs\<job-id>\guest\` recursively for `events.json`, then
for `*.jsonl`. Importing events re-runs behavior rules and regenerates both
`report.json` and `report.html`.

## Web API integration

After creating a job with `/api/jobs/plan`, run or record the planned runbook:

```http
POST /api/jobs/{jobId}/runbook/execute
Content-Type: application/json

{
  "live": false,
  "stepTimeoutSeconds": 1800
}
```

Set `live` to `true` only from an elevated host process after preparing the
golden VM, guest credentials, and guest agent path. If the process is not
elevated, the executor returns a failed preflight result and does not execute
partial VM commands.

## WebUI integration

The job result panel exposes:

- `Record dry-run execution`
- `Execute live runbook`
- `Import guest events / refresh report`

## Runbook execution UX contract

Runbook execution is operator-diagnostics data, not final malware telemetry.
The UI should make failures actionable without requiring the operator to open
`runbook-execution.json` manually.

The execution summary should show:

- mode (`DryRun` or `Live`);
- aggregate success/failure;
- executed step count versus total step count;
- aggregate duration;
- failed step index when one exists;
- top-level error/message text;
- guest import status and error text when automatic import was requested.

Each step row should expose:

- step index, step ID, and title;
- status and skipped state;
- PowerShell exit code;
- step duration;
- error/message text;
- captured stdout;
- captured stderr.

Long stdout/stderr values should be collapsed by default with a copy action so
large command output does not hide the failed step or exit code. Empty output
should render as an explicit empty state. The current persisted model already
stores `standardOutput`, `standardError`, `exitCode`, `duration`, and `message`
for every `SandboxRunbookStepExecutionResult`; QA should treat those fields as
the stable contract even when the visual layout changes.

The live button is the first usable path toward "start VM and report behavior",
but it still depends on local Hyper-V readiness:

- Hyper-V feature and module installed.
- Golden VM registered, for example `KSwordSandbox-Win10-Golden`.
- Clean checkpoint available, for example `Clean`.
- Guest credential secret available through the configured environment variable.
- Guest Service Interface / PowerShell Direct usable.
- Guest agent published to the configured guest path.

For the operator sequence that builds the guest payload, deploys it into the
golden VM, runs `tools/KSword.Sandbox.TestSample`, and refreshes the HTML report
from imported guest events, see `docs/guest-payload-staging.md`.

Minimal live API flow:

```powershell
$job = Invoke-RestMethod -Method Post -Uri 'http://localhost:5000/api/jobs/plan' `
  -ContentType 'application/json' `
  -Body (@{
      samplePath = 'D:\Temp\KSwordSandbox\samples\KSword.Sandbox.TestSample\KSword.Sandbox.TestSample.exe'
      displayName = 'KSword.Sandbox.TestSample.exe'
      durationSeconds = 30
      dryRun = $true
  } | ConvertTo-Json)

$execution = Invoke-RestMethod -Method Post -Uri "http://localhost:5000/api/jobs/$($job.jobId)/runbook/execute" `
  -ContentType 'application/json' `
  -Body (@{
      live = $true
      stepTimeoutSeconds = 1800
      importGuestEvents = $true
  } | ConvertTo-Json)

if (-not $execution.guestImportSucceeded) {
    Invoke-RestMethod -Method Post -Uri "http://localhost:5000/api/jobs/$($job.jobId)/guest-events/import" `
      -ContentType 'application/json' `
      -Body '{}'
}
```

## Live telemetry stream validation

During a live Hyper-V run, the UI-safe event source is still the host-collected
guest output folder. The baseline validation path remains the polling endpoint:

```http
GET /api/jobs/{jobId}/events/live?offset=0&take=100
Accept: application/json
```

The SSE endpoint, when available in the running Web API, is:

```http
GET /api/jobs/{jobId}/events/stream?offset=0
Accept: text/event-stream
```

The stream endpoint also accepts `take=<n>` and `intervalMs=<milliseconds>`.
Current server behavior clamps `take` to `1..500`, defaults it to `100`, clamps
`intervalMs` to `500..10000`, and defaults it to `2000`.

If `/events/stream` is unavailable in a running Web API, a QA probe should
record that as "SSE route unavailable" and then validate polling fallback
instead of failing the whole live telemetry check. The fallback loop is:

1. Keep a client-side `offset`, initially `0`.
2. Call `/api/jobs/{jobId}/events/live?offset=<offset>&take=100`.
3. Verify the response contains `jobId`, `retrievedAt`, `totalEvents`,
   `nextOffset`, `hasMore`, `sources`, and `events`.
4. Render or inspect every returned raw event without applying verdict logic.
5. Replace `offset` with `nextOffset`.
6. If `hasMore=true`, poll again immediately; otherwise wait briefly while the
   runbook is still running.

Lightweight QA commands:

```powershell
# Static expected-contract check; does not start the Web API and writes no
# runtime artifacts.
.\scripts\Test-LiveTelemetryFramework.ps1 -ContractOnly

# Runtime probe against an already-started Web API and an existing job. Keep
# -UsePollingFallback enabled so stream failures or older polling-only builds
# become a documented fallback validation.
.\scripts\Test-LiveTelemetryFramework.ps1 `
  -BaseUrl 'http://localhost:5000' `
  -JobId '<job-guid>' `
  -UsePollingFallback
```
