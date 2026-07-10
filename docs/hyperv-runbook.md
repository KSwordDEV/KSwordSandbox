# Hyper-V runbook

The host service currently generates Hyper-V steps without executing them. This
keeps the repository safe to build on machines without administrator rights or a
registered golden VM.

## Planned step groups

1. Verify Hyper-V PowerShell cmdlets.
2. Verify the configured golden VM exists.
3. Load guest credentials from an environment variable.
4. Restore a clean checkpoint or create a temporary differencing-disk VM.
5. Stage prepared Guest Agent and R0Collector payload files from
   `paths.guestPayloadRoot` into the guest through PowerShell Direct.
6. Optionally copy an external driver `.sys` from `driver.hostDriverPath` into
   `driver.driverPathInGuest` when that path is configured.
7. Copy the sample into the guest.
8. Create a job-specific guest output folder such as
   `C:\KSwordSandbox\out\<job-id-n>`.
9. Start `KSword.Sandbox.Agent.exe` asynchronously through PowerShell Direct.
10. Pass `--driver-events C:\KSwordSandbox\out\<job-id-n>\driver-events.jsonl`,
   `--r0collector`, and `--driver-device` when driver collection is enabled.
11. While the guest agent process is running, periodically copy guest output
   back to `D:\Temp\KSwordSandbox\jobs\<job-id-n>\guest`.
12. Copy guest JSON/JSONL output one final time.
13. Stop and optionally remove the temporary VM.

## Execution prerequisites

- Elevated host PowerShell.
- Hyper-V feature installed.
- Golden VM registered and checkpointed.
- Guest credentials available through the configured environment variable.
- Guest Agent and R0Collector host payload prepared under
  `paths.guestPayloadRoot`, normally by `scripts/Prepare-GuestPayload.ps1`.
- Optional test-signed driver kept outside git and referenced by
  `driver.hostDriverPath` only when real driver staging is desired.

Before live execution, run the read-only preflight:

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

The preflight is intentionally safer than the live runbook. It checks module
and command availability, VM existence, checkpoint existence, Guest Service
Interface state, host payload files, PowerShell Direct reachability, and guest
payload file presence when the VM is already running. It does not restore a
checkpoint, start a VM, stage payloads, or create guest folders.

## Current local status

The host now has dry-run and live execution wiring. Non-elevated checks still
cannot enumerate Hyper-V state; commands such as `Get-VM` and
`Get-WindowsOptionalFeature -Online` require elevation. Live execution must be
started from an elevated host process with a prepared golden VM and guest
credential secret.

If `Test-HyperVReadiness.ps1` reports `PowerShell Direct` as `Warning` because
the VM is `Off`, either accept that the preflight stayed read-only or start the
VM manually in an operator-controlled session and re-run the preflight before
capturing a new clean checkpoint.
