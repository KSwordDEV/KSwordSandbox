# Golden VM preparation

## Required baseline

- Windows 10 x64 VM on local Hyper-V.
- VM name matching `config/sandbox.example.json`.
- A clean checkpoint named `Clean`.
- PowerShell Direct usable with a local guest account that has a non-empty
  password. Live runbooks invoke the guest agent through
  `Invoke-Command -VMName ... -Credential ...`.
- Guest Service Interface enabled. Live runbooks use `Copy-VMFile` to copy the
  submitted sample into the guest.
- Host payload prepared outside git under `paths.guestPayloadRoot`, normally
  `D:\Temp\KSwordSandbox\payload\guest-tools`.
- Payload manifest present when possible:
  `D:\Temp\KSwordSandbox\payload\guest-tools\payload-manifest.json`.
- Network isolation appropriate for the malware-analysis lab.

## Suggested guest folders

```text
C:\KSwordSandbox\agent      Guest collector binaries
C:\KSwordSandbox\driver     Signed driver artifacts, if used
C:\KSwordSandbox\incoming   Submitted sample for the current run
C:\KSwordSandbox\out        JSON event output
```

Deploy the host-staged payload before checkpointing:

```text
D:\Temp\KSwordSandbox\payload\guest-tools\agent       -> C:\KSwordSandbox\agent
D:\Temp\KSwordSandbox\payload\guest-tools\r0collector -> C:\KSwordSandbox\r0collector
```

The current live runbook expects the guest agent at:

```text
C:\KSwordSandbox\agent\KSword.Sandbox.Agent.exe
```

See `docs/guest-payload-staging.md` for the MSBuild staging script and
PowerShell Direct copy commands.

## Readiness preflight

Run the non-destructive readiness report before refreshing or using the clean
checkpoint:

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

Expected output is a sequence of `ReadinessCheck` objects plus one
`ReadinessSummary`. Non-admin shells and missing guest passwords are reported
explicitly. Administrator shells additionally check the VM, checkpoint, Guest
Service Interface, host payload files, and, when the VM is already running,
PowerShell Direct plus guest-deployed payload files. The script does not start,
stop, create, delete, or restore any VM.

The one-command E2E script also performs non-mutating preflight while writing
its plan. In `PlanOnly`/`WhatIf` it records Windows/Admin/Hyper-V command
availability, VM/checkpoint/Guest Service state, credential env var presence,
host payload paths, and PowerShell Direct status when the VM is already running.
Live mode refuses to launch child scripts when required checks fail.

## Host credential handling

Store the guest password outside git. The default runbook reads it from the
environment variable named by `Guest.PasswordSecretName`, which defaults to
`KSWORDBOX_GUEST_PASSWORD`.

```powershell
$env:KSWORDBOX_GUEST_PASSWORD = '<local guest password>'
```

Use a local unprivileged guest account for the agent unless driver install or
service start requires elevation inside the VM.

## Integration services and PowerShell Direct

Enable the Guest Service Interface from an elevated host shell:

```powershell
Enable-VMIntegrationService -VMName 'KSwordSandbox-Win10-Golden' -Name 'Guest Service Interface'
```

Verify PowerShell Direct with the same local account that the runbook will use:

```powershell
$guestPassword = ConvertTo-SecureString $env:KSWORDBOX_GUEST_PASSWORD -AsPlainText -Force
$guestCredential = [pscredential]::new('SandboxUser', $guestPassword)
Invoke-Command -VMName 'KSwordSandbox-Win10-Golden' -Credential $guestCredential -ScriptBlock {
    Test-Path 'C:\KSwordSandbox\agent\KSword.Sandbox.Agent.exe'
}
```

Both checks should pass before taking the `Clean` checkpoint.

## Test-signed driver prerequisite

Only enable test signing in isolated analysis VMs that need a test-signed R0
driver. Run inside an elevated guest shell, reboot, and then install/start the
driver from a guest-only path:

```powershell
bcdedit.exe /set testsigning on
shutdown.exe /r /t 0
```

Keep signed `.sys` files, certificates, private keys, symbols, and driver logs
outside git. Do not bake private keys into the golden image.

## Checkpoint mode

Checkpoint mode restores the named golden VM before each run. It is simple and
works well for one job at a time. Do not run concurrent jobs against the same
golden VM.

## One-command Hyper-V E2E script

After the guest payload, local account, Guest Service Interface, PowerShell
Direct, and `Clean` checkpoint are ready, operators can generate a safe E2E
plan without touching the VM:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-HyperVE2E.ps1 `
  -SamplePath 'D:\Temp\KSwordSandbox\samples\KSword.Sandbox.TestSample\KSword.Sandbox.TestSample.exe'
```

Live mode is intentionally separate. Run it only from an elevated host shell,
with `KSWORDBOX_GUEST_PASSWORD` set, and after reviewing the plan JSON:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-HyperVE2E.ps1 `
  -SamplePath 'D:\Temp\KSwordSandbox\samples\KSword.Sandbox.TestSample\KSword.Sandbox.TestSample.exe' `
  -Live
```

The live path restores `Clean`, starts the VM, stages Guest Agent/R0Collector
payloads, copies the sample, runs the Guest Agent, collects `events.json` and
`driver-events.jsonl`, stops the VM, and restores `Clean` again by default. It
also writes `runbook-execution.json` under
`D:\Temp\KSwordSandbox\jobs\<job-id-n>\` with preflight, start, collect, cleanup,
and artifact status. Use `-WhatIf` to verify that the live command line still
performs no VM mutation.
See `docs/hyperv-e2e-runbook.md` for the full operator flow and output paths.

For R0 telemetry demos without a loaded driver, set `driver.useMockCollector` to
`true` in a local config. The Guest Agent will still start the R0Collector
sidecar but adds `--r0-mock`, producing synthetic JSONL rows. For real live R0,
leave mock mode off, stage a signed driver outside git, ensure the driver
service/device path exists in the guest, and expect the collector to emit
`r0collector.deviceUnavailable` if `\\.\KSwordSandboxDriver` cannot be opened.

## Differencing-disk mode

Differencing-disk mode creates a temporary VM from a base VHDX. Set
`HyperV.UseDifferencingDisk` to `true` and configure `HyperV.BaseVhdxPath` in a
local config file. The base disk must stay outside git.
