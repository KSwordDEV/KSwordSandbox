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

Before switching from PlanOnly/WhatIf to live, also run the standalone
readiness helper. It is read-only and catches installed-config drift plus local
secret hygiene issues that should be fixed before committing:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-HyperVReadiness.ps1
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-RepositoryPolicy.ps1 -StagedOnly
```

## Current local go/no-go checklist

Use this checklist as the current executable state for the local host. It was
observed on 2026-07-10 from an elevated PowerShell session with non-mutating
Hyper-V/readiness probes.

- [x] Host shell is elevated.
- [x] VM exists: `KSwordSandbox-Win10-Golden`.
- [x] VM currently reads as `Off`.
- [x] Clean checkpoint exists: `Clean`.
- [x] Guest Service Interface is enabled even though the local display name is
  `来宾服务接口`; scripts accept the stable component id
  `6C09BB55-D683-4DA0-8931-C9BF705F6480`, English display name, and localized
  display name.
- [x] Runtime root exists: `D:\Temp\KSwordSandbox`.
- [x] Host payload root exists:
  `D:\Temp\KSwordSandbox\payload\guest-tools`.
- [x] Host payload files exist:
  `payload-manifest.json`, `agent\KSword.Sandbox.Agent.exe`, and
  `r0collector\KSword.Sandbox.R0Collector.exe`.
- [ ] Set `KSWORDBOX_GUEST_PASSWORD` in the same elevated process that will run
  readiness/PlanOnly/live.
- [ ] Confirm PowerShell Direct with `SandboxUser` after the password is set.
  Readiness will still skip the probe while the VM is `Off`; it will not start
  the VM for you.

Current readiness result summary:

```text
Passed: 7
Warnings: 2
Failed: 1
Required failure: KSWORDBOX_GUEST_PASSWORD is missing from the current process.
Warnings: PowerShell Direct and guest payload probes were skipped because the
password secret is missing.
Read-only guarantee: no probe files were written and no VM mutation commands
were executed.
```

## Harmless behavior sample contract

The preferred live smoke input is the harmless behavior sample source project
`tools/KSword.Sandbox.HarmlessSample/KSword.Sandbox.HarmlessSample.csproj`.
If a worker places the project elsewhere, it must still be a same-name
`KSword.Sandbox.HarmlessSample.csproj` project so smoke tests can discover it.

Build and publish the sample through `Prepare-HarmlessSample.ps1`. The script is
expected to keep all build output outside this repository, with publish output
under:

```text
D:\Temp\KSwordSandbox\samples\KSword.Sandbox.HarmlessSample
```

The published `KSword.Sandbox.HarmlessSample.exe`, generated `bin`/`obj`
directories, and any helper `.dll`/`.bin` files are local lab artifacts and must
stay out of git. The repository should contain only source, the preparation
script, docs, and smoke contracts.

For a live Hyper-V run, prepare the sample first, verify the plan, then pass the
published executable to the one-command E2E script:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Prepare-HarmlessSample.ps1 `
  -RepositoryRoot 'D:\Projects\KswordSandbox' `
  -OutputRoot 'D:\Temp\KSwordSandbox\samples\KSword.Sandbox.HarmlessSample'

pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-HyperVE2E.ps1 `
  -SamplePath 'D:\Temp\KSwordSandbox\samples\KSword.Sandbox.HarmlessSample\KSword.Sandbox.HarmlessSample.exe' `
  -PlanOnly

$env:KSWORDBOX_GUEST_PASSWORD = '<local guest password>'
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-HyperVE2E.ps1 `
  -SamplePath 'D:\Temp\KSwordSandbox\samples\KSword.Sandbox.HarmlessSample\KSword.Sandbox.HarmlessSample.exe' `
  -Live
```

If you do not want to persist the password in User scope for a one-off elevated
session, run `Test-HyperVReadiness.ps1 -PromptForMissingGuestPassword` first.
That prompt writes only Process scope and never writes config/report/repository
files.

Use the existing `PlanOnly` and `-WhatIf` review modes before live execution;
the live command is only for the isolated golden VM workflow described below.

## Generate a plan JSON only

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-HyperVE2E.ps1 `
  -SamplePath 'D:\Temp\KSwordSandbox\samples\KSword.Sandbox.HarmlessSample\KSword.Sandbox.HarmlessSample.exe'
```

The default plan path is outside git:

```text
D:\Temp\KSwordSandbox\plans\hyperv-e2e-<job-id-n>.json
```

Use an explicit path when handing the plan to another worker or archiving local
operator evidence:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-HyperVE2E.ps1 `
  -SamplePath 'D:\Temp\KSwordSandbox\samples\KSword.Sandbox.HarmlessSample\KSword.Sandbox.HarmlessSample.exe' `
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
  -SamplePath 'D:\Temp\KSwordSandbox\samples\KSword.Sandbox.HarmlessSample\KSword.Sandbox.HarmlessSample.exe' `
  -Live `
  -WhatIf
```

This still writes a plan, but `effectiveMode` is `WhatIf` and
`willMutateVm=false`. It also writes a safe `runbook-execution.json` beside the
planned job output.

## Mock R0 live flow

Use mock R0 when the live Guest Agent/R0Collector path should be exercised but
no signed kernel driver is loaded. The config must stay outside git:

```powershell
$mockConfigPath = 'D:\Temp\KSwordSandbox\mock-r0.live.json'
$config = Get-Content .\config\sandbox.example.json -Raw | ConvertFrom-Json
$config.driver.enabled = $true
$config.driver.useMockCollector = $true
$config | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $mockConfigPath -Encoding UTF8
```

Review the exact mock intent without touching the VM:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-HyperVE2E.ps1 `
  -ConfigPath $mockConfigPath `
  -SamplePath 'D:\Temp\KSwordSandbox\samples\KSword.Sandbox.HarmlessSample\KSword.Sandbox.HarmlessSample.exe' `
  -PlanOnly
```

Before live execution, inspect the plan JSON and verify:

- `willMutateVm=false` for the review run;
- `driver.collectionMode` is `Mock`;
- `driver.useMockCollector` is `true`;
- `execution.guestAgentArguments` contains `--r0-mock`;
- `execution.r0CollectorArguments` contains `--mock`.

Then set the guest password in the same elevated process and run live:

```powershell
$env:KSWORDBOX_GUEST_PASSWORD = '<local guest password>'

pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-HyperVE2E.ps1 `
  -ConfigPath $mockConfigPath `
  -SamplePath 'D:\Temp\KSwordSandbox\samples\KSword.Sandbox.HarmlessSample\KSword.Sandbox.HarmlessSample.exe' `
  -Live
```

The mock run still restores `Clean`, starts the VM, stages payloads, copies the
sample, runs Guest Agent/R0Collector, collects outputs, stops the VM, and
restores `Clean` again. Only the R0Collector device dependency is mocked.

## Live execution sequence

Only run live mode on an isolated lab host with the prepared golden VM. Start an
elevated PowerShell session, expose the guest password to that session, then run:

```powershell
$env:KSWORDBOX_GUEST_PASSWORD = '<local guest password>'

pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-HyperVE2E.ps1 `
  -SamplePath 'D:\Temp\KSwordSandbox\samples\KSword.Sandbox.HarmlessSample\KSword.Sandbox.HarmlessSample.exe' `
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

## PowerShell Direct confirmation

PowerShell Direct cannot be fully confirmed while the password secret is absent
or the VM is stopped. To confirm it explicitly:

```powershell
$env:KSWORDBOX_GUEST_PASSWORD = '<local guest password>'
$vmName = 'KSwordSandbox-Win10-Golden'
$guestPassword = ConvertTo-SecureString $env:KSWORDBOX_GUEST_PASSWORD -AsPlainText -Force
$guestCredential = [pscredential]::new('SandboxUser', $guestPassword)

# Run this only when the VM is already running, or after intentionally starting
# it for manual validation.
Invoke-Command -VMName $vmName -Credential $guestCredential -ScriptBlock {
  [pscustomobject][ordered]@{
    ComputerName = $env:COMPUTERNAME
    UserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    AgentExists = Test-Path 'C:\KSwordSandbox\agent\KSword.Sandbox.Agent.exe' -PathType Leaf
    R0CollectorExists = Test-Path 'C:\KSwordSandbox\r0collector\KSword.Sandbox.R0Collector.exe' -PathType Leaf
  }
}
```

After manual validation, restore the `Clean` checkpoint before treating
`KSwordSandbox-Win10-Golden` as the golden baseline again.
