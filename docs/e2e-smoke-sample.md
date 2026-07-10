# E2E smoke test sample

This document describes the harmless Windows sample in
`tools/KSword.Sandbox.TestSample/`. The project is intentionally not added to
`KSwordSandbox.sln` so multiple workers can build or run it without touching the
main solution.

## Behavior

When executed, `KSword.Sandbox.TestSample.exe` performs only safe, visible
actions:

1. Creates `ksword-sandbox-smoke.txt` in the requested output directory.
2. Starts one short-lived child process:
   `cmd.exe /d /c echo KSwordSandbox smoke child process completed`.
3. Optionally, when `--network-probe` is supplied, attempts short TCP probes to:
   - `127.0.0.1:9` for loopback-only telemetry.
   - `192.0.2.1:80`, a TEST-NET documentation address.

The sample does not require administrator privileges, does not modify system
settings, and does not contact arbitrary external hosts.

## Build outside the repository

Do not commit the generated `.exe`, `bin`, or `obj` output. Build into
`D:\Temp\KSwordSandbox\samples\...` and redirect intermediate files away from
the repository:

```powershell
$repo = 'D:\Projects\KswordSandbox'
$project = Join-Path $repo 'tools\KSword.Sandbox.TestSample\KSword.Sandbox.TestSample.csproj'
$sampleOut = 'D:\Temp\KSwordSandbox\samples\KSword.Sandbox.TestSample'
$sampleBuild = 'D:\Temp\KSwordSandbox\build\KSword.Sandbox.TestSample\'
$sampleObj = 'D:\Temp\KSwordSandbox\obj\KSword.Sandbox.TestSample\'

New-Item -ItemType Directory -Force -Path $sampleOut, $sampleBuild, $sampleObj | Out-Null

dotnet publish $project `
  --configuration Release `
  --runtime win-x64 `
  --self-contained false `
  --output $sampleOut `
  /p:BaseOutputPath=$sampleBuild `
  /p:BaseIntermediateOutputPath=$sampleObj
```

Expected publish output includes `KSword.Sandbox.TestSample.exe` under
`D:\Temp\KSwordSandbox\samples\KSword.Sandbox.TestSample\`. That executable is a
local build artifact and must stay out of git.

## Manual run inside a VM

Copy the published sample directory into the test VM, then run:

```powershell
$runOut = 'C:\Temp\KSwordSandboxSampleRun'
New-Item -ItemType Directory -Force -Path $runOut | Out-Null

.\KSword.Sandbox.TestSample.exe --output-dir $runOut
```

For network telemetry that remains safe and deterministic:

```powershell
.\KSword.Sandbox.TestSample.exe --output-dir $runOut --network-probe
```

## E2E validation points

The sandbox runner/report can assert:

- VM launch succeeded and the sample process started.
- `ksword-sandbox-smoke.txt` was created in the configured output directory.
- A short-lived `cmd.exe` child process appeared and exited.
- The sample process returned exit code `0`.
- Optional network telemetry is limited to `127.0.0.1` and `192.0.2.1`.
- The VM cleanup/recovery path ran after the sample finished.

The marker file contains key-value lines for timestamp, machine name, process
IDs, child process output, and optional network-probe statuses.

## Live sandbox runbook

After publishing the sample outside the repository, use
`docs/guest-payload-staging.md` for the full host-to-guest smoke flow:

1. Build and stage Guest Agent plus R0Collector under
   `D:\Temp\KSwordSandbox\payload\guest-tools`.
2. Copy the staged payload into the golden VM before refreshing the `Clean`
   checkpoint.
3. Use the published sample `.exe` as the WebUI/API job input.
4. Execute the Hyper-V runbook live and import guest events to regenerate the
   HTML report.
