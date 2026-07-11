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

## Real R0 driver preflight

Real R0 collection requires three config values to agree:

- `driver.enabled=true`;
- `driver.useMockCollector=false`;
- `driver.hostDriverPath` points to an existing built and test-signed `.sys`.

If `driver.enabled=true` and `driver.useMockCollector=false` but
`driver.hostDriverPath` is empty, the runbook cannot copy a driver into the
guest and does not generate `install-driver-service`. The staging command would
otherwise show `$driverSource = ''`, and R0Collector can later fail opening
`\\.\KSwordSandboxDriver` with `deviceUnavailable` / `win32Error=2`.

The generated runbook now emits an early non-mutating
`check-r0-driver-config` preflight step, and the script E2E plan records a
failed `R0 driver host path configuration` check before any live VM mutation.
Fix the condition by setting `driver.hostDriverPath` in the local config,
switching to `driver.useMockCollector=true` for payload-only R0 validation, or
disabling R0 with `driver.enabled=false` / `-NoR0Collector`.

Before live execution, run the read-only preflight. On an installed host, the
one-command form reuses `Sandbox__ConfigPath` / install state and checks the
configured VM name, checkpoint, Guest Service Interface, PowerShell Direct,
guest working directory, payload roots, and repository secret hygiene:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-HyperVReadiness.ps1
```

Equivalent fully explicit form:

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

If the only missing item is the guest password for the current elevated shell,
use `-PromptForMissingGuestPassword` for a process-only prompt, or rerun
`install.ps1 -Mode Change -ResetPassword -PromptPassword` for persistent local
setup. Neither flow should put password values in repository files.

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
