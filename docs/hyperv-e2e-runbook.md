# Hyper-V one-command E2E runbook

This runbook covers the script-only E2E path for a prepared KSword Sandbox
Hyper-V golden VM. It is intentionally safe by default: the top-level command
writes a JSON plan and exits unless `-Live` is explicitly supplied from an
elevated host PowerShell session.

## Safety contract

`scripts/Invoke-HyperVE2E.ps1` is the only entry point operators should need.
Its default mode is `PlanOnly`:

- writes a reviewable plan JSON;
- does not restore checkpoints;
- does not start, stop, create, delete, or restore any VM;
- does not copy host files into the guest;
- does not run Guest Agent, R0Collector, driver code, or samples.

`-WhatIf` has the same no-mutation guarantee even when combined with `-Live`.
Live execution requires all of these conditions:

1. `-Live` is present and `-PlanOnly` is absent.
2. The shell is running as Administrator.
3. `-WhatIf` is not present.
4. The guest password environment variable is visible to the process.
5. The sample and staged guest payload files exist outside the repository.
6. The generated `preflightSummary.liveReady` is `true` before any child script
   is launched.

## Generate a plan JSON only

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-HyperVE2E.ps1 `
  -SamplePath 'D:\Temp\KSwordSandbox\samples\KSword.Sandbox.TestSample\KSword.Sandbox.TestSample.exe'
```

The default plan path is outside git:

```text
D:\Temp\KSwordSandbox\plans\hyperv-e2e-<job-id-n>.json
```

Use an explicit path when handing the plan to another worker or archiving local
operator evidence:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-HyperVE2E.ps1 `
  -SamplePath 'D:\Temp\KSwordSandbox\samples\KSword.Sandbox.TestSample\KSword.Sandbox.TestSample.exe' `
  -PlanPath 'D:\Temp\KSwordSandbox\plans\manual-review.json' `
  -PlanOnly
```

The generated JSON includes:

- `safeDefault`, `requestedMode`, `effectiveMode`, and `willMutateVm`;
- VM name and clean checkpoint name;
- host environment checks for Windows, Administrator, Hyper-V cmdlets,
  `Get-VM`, `Get-VMSnapshot`, Guest Service Interface, credential env var, and
  non-mutating PowerShell Direct probes when the VM is already running;
- host sample path and guest sample path;
- host payload root and expected Guest Agent/R0Collector payload files;
- guest output paths for `events.json`, `driver-events.jsonl`, `agent.pid`, and
  `agent.exit`;
- resolved Guest Agent command line and R0Collector mock/live sidecar arguments;
- ordered `steps` with `mutatesVmState` flags;
- preflight summary and live-only failures;
- the planned `runbook-execution.json` path under the job root.

The top-level script also writes `runbook-execution.json` in `PlanOnly` and
`WhatIf` modes. Those records mark all steps as skipped and prove that no child
script or VM command was launched.

## Review live intent without mutation

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-HyperVE2E.ps1 `
  -SamplePath 'D:\Temp\KSwordSandbox\samples\KSword.Sandbox.TestSample\KSword.Sandbox.TestSample.exe' `
  -Live `
  -WhatIf
```

This still writes a plan, but `effectiveMode` is `WhatIf` and
`willMutateVm=false`. It also writes a safe `runbook-execution.json` beside the
planned job output.

## Live execution sequence

Only run live mode on an isolated lab host with the prepared golden VM. Start an
elevated PowerShell session, expose the guest password to that session, then run:

```powershell
$env:KSWORDBOX_GUEST_PASSWORD = '<local guest password>'

pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-HyperVE2E.ps1 `
  -SamplePath 'D:\Temp\KSwordSandbox\samples\KSword.Sandbox.TestSample\KSword.Sandbox.TestSample.exe' `
  -Live
```

Live mode calls two child scripts:

1. `scripts/Start-SandboxHyperVJob.ps1`
   - validates elevation, Hyper-V commands, VM existence, clean checkpoint,
     Guest Service Interface, sample, payload folders/files, and optional
     payload manifest before the first VM mutation;
   - loads the guest credential from `KSWORDBOX_GUEST_PASSWORD` without printing
     the secret value;
   - stops the golden VM if needed;
   - restores the clean checkpoint;
   - enables Guest Service Interface;
   - starts the VM;
   - waits for PowerShell Direct;
   - copies Guest Agent and R0Collector payload with `Copy-Item -ToSession`;
   - copies the sample with `Copy-VMFile`;
   - creates a clean guest output folder;
   - starts Guest Agent asynchronously with `--sample`, `--out`, `--duration`,
     and, when driver collection is enabled, `--driver-events`, `--r0collector`,
     `--driver-device`; `driver.useMockCollector=true` adds `--r0-mock`, which
     makes the agent forward `--mock` to R0Collector.

2. `scripts/Collect-GuestOutputs.ps1`
   - opens a PowerShell Direct session;
   - reads `agent.pid`;
   - repeatedly copies the guest output folder to the host with
     `Copy-Item -FromSession`;
   - requires `agent.exit` and fails on a non-zero Guest Agent exit code;
   - indexes collected events/artifacts with size, kind, and SHA-256 when
     hashing succeeds;
   - requires `events.json`, `agent.pid`, and `agent.exit` on the host; warns
     when driver collection is enabled but `driver-events.jsonl` is absent;
   - stops the VM;
   - restores the clean checkpoint again by default.

After child scripts finish, `Invoke-HyperVE2E.ps1` writes one aggregate
`runbook-execution.json` containing the requested/effective mode, preflight
results, child exit codes, phase result paths, skipped/executed step records,
cleanup errors, and collected artifact paths.

## Output locations

For job `<job-id-n>`, live output is written under:

```text
D:\Temp\KSwordSandbox\jobs\<job-id-n>\
  runbook-execution.json
  hyperv-e2e-start-result.json
  hyperv-e2e-collect-result.json
  guest\<job-id-n>\events.json
  guest\<job-id-n>\driver-events.jsonl
  guest\<job-id-n>\agent.pid
  guest\<job-id-n>\agent.exit
```

Keep these outputs, samples, payload binaries, driver files, VM disks, and build
products out of git.

## Recovery notes

If live execution fails during the start phase after VM mutation,
`Start-SandboxHyperVJob.ps1` attempts stop/restore cleanup. If the collection
phase starts, `Collect-GuestOutputs.ps1` still tries to stop the VM and restore
the clean checkpoint in `finally`. If cleanup reports errors, fix the VM
manually from Hyper-V Manager or an elevated shell, then rerun the read-only
readiness preflight before attempting another live E2E:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-HyperVReadiness.ps1 `
  -VmName 'KSwordSandbox-Win10-Golden' `
  -CheckpointName 'Clean' `
  -GuestUserName 'SandboxUser' `
  -GuestPasswordSecretName 'KSWORDBOX_GUEST_PASSWORD' `
  -GuestPayloadRoot 'D:\Temp\KSwordSandbox\payload\guest-tools' `
  -GuestWorkingDirectory 'C:\KSwordSandbox' `
  -RuntimeRoot 'D:\Temp\KSwordSandbox'
```
