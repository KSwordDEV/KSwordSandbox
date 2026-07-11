# Golden VM preparation

Canonical scope: this page owns baseline golden-VM preparation. Current
readiness must be checked with `docs/hyperv-readiness.md` /
`scripts/Test-HyperVReadiness.ps1`; dated host observations below are evidence,
not a substitute for a fresh preflight.

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

## Current host live checklist

Observed on the local Hyper-V host on 2026-07-10 from an elevated shell. Keep
this section factual and do not paste guest passwords, VM disks, payload
binaries, or generated run outputs into git.

Historical only: rerun the read-only readiness preflight before any `-Live`
analysis, because VM state, checkpoint state, payload freshness, and process
environment secrets can drift.

- [x] Golden VM exists: `KSwordSandbox-Win10-Golden`.
  - Current observed state: `Off`.
  - Generation/version: `2` / `9.0`.
- [x] Clean checkpoint exists: `Clean`.
  - Current observed creation time: `2026-07-10 14:30:54 +08:00`.
- [x] Guest Service Interface is present and enabled.
  - Current localized display name: `来宾服务接口`.
  - Stable component id:
    `6C09BB55-D683-4DA0-8931-C9BF705F6480`.
  - Treat this as localized OK; scripts match by component id as well as
    `Guest Service Interface` and `来宾服务接口`.
- [x] Host runtime root exists: `D:\Temp\KSwordSandbox`.
- [x] Host payload root exists:
  `D:\Temp\KSwordSandbox\payload\guest-tools`.
  - Current host files are present:
    `payload-manifest.json`,
    `agent\KSword.Sandbox.Agent.exe`, and
    `r0collector\KSword.Sandbox.R0Collector.exe`.
- [ ] `KSWORDBOX_GUEST_PASSWORD` is visible to the current process.
  - Current observed gap: not set in the process, user, or machine environment.
  - This is the only required readiness failure currently observed.
- [ ] PowerShell Direct confirmed for `SandboxUser`.
  - Current observed status: skipped because the password secret is missing; the
    VM is also `Off`, and the readiness script will not start it.
- [ ] Guest-deployed payload files confirmed in the VM.
  - Current observed status: skipped because PowerShell Direct was skipped.
  - Live mode still stages host payload files before execution, so this is a
    useful checkpoint-refresh check rather than a blocker when host payload
    files are present.

## Suggested guest folders

```text
C:\KSwordSandbox\agent      Guest collector binaries
C:\KSwordSandbox\driver     Optional test-signed driver artifacts, if used
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

The current readiness contract also records `CheckId`, `RequiredForLive`,
`LiveReady`, `FailedCheckIds`, host shared path configuration, Hyper-V
feature/service state, and test-signing status. Use those machine-readable
fields for automation instead of scraping localized display text.

The one-command E2E script also performs non-mutating preflight while writing
its plan. In `PlanOnly`/`WhatIf` it records Windows/Admin/Hyper-V command
availability, VM/checkpoint/Guest Service state, credential env var presence,
host payload paths, and PowerShell Direct status when the VM is already running.
Live mode refuses to launch child scripts when required checks fail.

## Host credential handling

Store the guest password outside git. The default runbook reads it from the
environment variable named by `Guest.PasswordSecretName`, which defaults to
`KSWORDBOX_GUEST_PASSWORD`.

For deployment or a new lab workstation, use the local installer menu:

```powershell
.\install.ps1
```

The menu supports install, change, uninstall, and status. Change includes a
password reset option. For a quick generated local value:

```powershell
.\install.ps1 -Mode Install -GeneratePassword
```

For an existing VM account password:

```powershell
.\install.ps1 -Mode Install -PromptPassword
```

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

On localized hosts, prefer the stable component id lookup used by the scripts:

```powershell
$guestServiceComponentId = '6C09BB55-D683-4DA0-8931-C9BF705F6480'
Get-VMIntegrationService -VMName 'KSwordSandbox-Win10-Golden' |
  Where-Object {
    ([string]$_.Id).EndsWith('\' + $guestServiceComponentId, [StringComparison]::OrdinalIgnoreCase) -or
    $_.Name -eq 'Guest Service Interface' -or
    $_.Name -eq '来宾服务接口'
  } |
  Enable-VMIntegrationService
```

Verify PowerShell Direct with the same local account that the runbook will use:

```powershell
$vmName = 'KSwordSandbox-Win10-Golden'
$guestPassword = ConvertTo-SecureString $env:KSWORDBOX_GUEST_PASSWORD -AsPlainText -Force
$guestCredential = [pscredential]::new('SandboxUser', $guestPassword)
Invoke-Command -VMName $vmName -Credential $guestCredential -ScriptBlock {
    [pscustomobject][ordered]@{
        ComputerName = $env:COMPUTERNAME
        UserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        AgentExists = Test-Path 'C:\KSwordSandbox\agent\KSword.Sandbox.Agent.exe' -PathType Leaf
        R0CollectorExists = Test-Path 'C:\KSwordSandbox\r0collector\KSword.Sandbox.R0Collector.exe' -PathType Leaf
    }
}
```

PowerShell Direct requires the VM to be running. The readiness script is
read-only and intentionally skips this probe instead of starting the VM. For a
manual confirmation, set `KSWORDBOX_GUEST_PASSWORD`, start the VM only when you
are ready to touch the lab VM, run the command above, then restore `Clean`
before using the VM as the golden baseline.

Both checks should pass before taking the `Clean` checkpoint.

## Test-signed driver prerequisite

The default golden-VM workflow does not require a signed or loaded driver. Keep
normal validation compile-only and use mock R0 when the E2E path only needs to
exercise Guest Agent/R0Collector wiring. Do not call `CSignTool.exe` or the
legacy signing wrapper during golden image preparation; custom timestamp tooling
can display modal UI and block unattended workers.

Only enable Windows test signing in isolated analysis VMs that explicitly need a
real test-signed R0 driver. Run inside an elevated guest shell, reboot, and then
install/start a driver from a guest-only path:

```powershell
bcdedit.exe /set testsigning on
shutdown.exe /r /t 0
```

Use a local test certificate for optional real-driver validation, and keep signed
`.sys` files, certificates, private keys, symbols, and driver logs outside git.
Do not bake private keys into the golden image.

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
  -SamplePath 'D:\Temp\KSwordSandbox\samples\KSword.Sandbox.HarmlessSample\KSword.Sandbox.HarmlessSample.exe'
```

Live mode is intentionally separate. Run it only from an elevated host shell,
with `KSWORDBOX_GUEST_PASSWORD` set, and after reviewing the plan JSON:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-HyperVE2E.ps1 `
  -SamplePath 'D:\Temp\KSwordSandbox\samples\KSword.Sandbox.HarmlessSample\KSword.Sandbox.HarmlessSample.exe' `
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
leave mock mode off only after staging an optional test-signed driver outside
git with Windows test mode enabled; the current runbooks must not call
`CSignTool.exe`. Ensure the driver service/device path exists in the guest, and
expect the collector to emit `r0collector.deviceUnavailable` if
`\\.\KSwordSandboxDriver` cannot be opened.

Example mock-R0 live config flow, keeping the config outside git:

```powershell
$mockConfigPath = 'D:\Temp\KSwordSandbox\mock-r0.live.json'
$config = Get-Content .\config\sandbox.example.json -Raw | ConvertFrom-Json
$config.driver.enabled = $true
$config.driver.useMockCollector = $true
$config | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $mockConfigPath -Encoding UTF8

# Non-mutating review first. The plan should show collectionMode=Mock,
# useMockCollector=true, Guest Agent --r0-mock, and R0Collector --mock.
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-HyperVE2E.ps1 `
  -ConfigPath $mockConfigPath `
  -SamplePath 'D:\Temp\KSwordSandbox\samples\KSword.Sandbox.HarmlessSample\KSword.Sandbox.HarmlessSample.exe' `
  -PlanOnly

# Live only after reviewing the plan, setting the guest password in this
# elevated process, and confirming the readiness gap is closed.
$env:KSWORDBOX_GUEST_PASSWORD = '<local guest password>'
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-HyperVE2E.ps1 `
  -ConfigPath $mockConfigPath `
  -SamplePath 'D:\Temp\KSwordSandbox\samples\KSword.Sandbox.HarmlessSample\KSword.Sandbox.HarmlessSample.exe' `
  -Live
```

## Differencing-disk mode

Differencing-disk mode creates a temporary VM from a base VHDX. Set
`HyperV.UseDifferencingDisk` to `true` and configure `HyperV.BaseVhdxPath` in a
local config file. The base disk must stay outside git.
