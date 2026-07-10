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

The live button is the first usable path toward "start VM and report behavior",
but it still depends on local Hyper-V readiness:

- Hyper-V feature and module installed.
- Golden VM registered, for example `KSwordSandbox-Win10-Golden`.
- Clean checkpoint available, for example `Clean`.
- Guest credential secret available through the configured environment variable.
- Guest Service Interface / PowerShell Direct usable.
- Guest agent published to the configured guest path.
