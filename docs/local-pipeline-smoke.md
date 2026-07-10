# Local pipeline smoke

`scripts/Invoke-LocalPipelineSmoke.ps1` is a fast host-only smoke for checking
the Web/Core pipeline without a real Hyper-V VM.

## Purpose

Use this smoke when you want to verify that the local API and Core job/report
services still form a closed loop:

1. create a harmless `.exe`-named file under
   `D:\Temp\KSwordSandbox\pipeline-smoke`;
2. start `KSword.Sandbox.Web` on a random `127.0.0.1` port;
3. call `/health`, `/api/files/scan`, and `/api/jobs/plan`;
4. write synthetic guest `events.json` plus `driver-events.jsonl` into the job
   guest output folder;
5. call `/api/jobs/{jobId}/guest-events/import`;
6. verify that `report.html` contains the expected report sections and rule
   findings.

The smoke does not call `/api/jobs/{jobId}/runbook/execute`, does not require
Hyper-V, and does not require a golden VM.

## Run

From the repository root:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-LocalPipelineSmoke.ps1
```

Useful options:

```powershell
# Use Release build output.
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-LocalPipelineSmoke.ps1 -Configuration Release

# Skip build inside dotnet run after a prior successful build.
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-LocalPipelineSmoke.ps1 -NoBuild

# Use a different runtime artifact root.
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-LocalPipelineSmoke.ps1 -RuntimeRoot D:\Temp\KSwordSandbox\pipeline-smoke-dev
```

## Outputs

On success the script prints:

- run root;
- benign sample path;
- temporary Web URL;
- job ID;
- synthetic guest event paths;
- `report.json`;
- `report.html`;
- Web stdout/stderr logs.

All runtime artifacts are written below the configured runtime root, not into
the repository. Do not commit generated run folders, samples, configs, reports,
or logs.

## Failure handling

The script exits with code `1` on failure and prints the run root plus the Web
stderr tail when available. Inspect the printed `report.html`, `report.json`,
and log paths before deleting the run folder.
