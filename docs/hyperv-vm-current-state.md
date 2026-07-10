# Hyper-V VM current state

Generated: 2026-07-10, Asia/Shanghai

Scope:

- Repository: `D:\Projects\KswordSandbox`
- Target VM: `KSwordSandbox-Win10-Golden`
- Target checkpoint: `Clean`
- Target runtime root: `D:\Temp\KSwordSandbox`
- This pass was read-only. No VM start/stop, checkpoint restore/create, integration-service change, file copy into guest, commit, or push was performed.

## Verification status

Overall status for this session: **not ready / current Hyper-V state not directly verifiable**.

Reasons:

- Current PowerShell process is not elevated.
- `KSWORDBOX_GUEST_PASSWORD` is not set in the current process.
- Because the session is not elevated, `Get-VM`, `Get-VMSnapshot`, and `Get-VMIntegrationService` cannot read the current VM state.

Last-known evidence from existing runtime records indicates the VM was prepared successfully at `2026-07-10T14:34:07+08:00`, but that is historical evidence, not a live verification from this session.

## Read-only command summary

- `git status --short`
  - Result: no output; the repository appeared clean before this document was written.
- `Get-Command Get-VM,Get-VMSnapshot,Get-VMIntegrationService`
  - Result: all three cmdlets are available from the `Hyper-V` module.
- Administrator/elevation probe
  - User: `WIN-1OMJO6UTCGN\Administrator`
  - Elevated administrator: `False`
  - PowerShell: `7.4.15`
  - OS: `Microsoft Windows 10 Professional Workstation`, version `10.0.19045`
- `Get-Service vmms,vmcompute`
  - Result: Hyper-V Virtual Machine Management and Host Compute services are running.
- `Get-VM -Name 'KSwordSandbox-Win10-Golden'`
  - Result: failed with authorization error because the current process is not elevated.
- `Get-VMSnapshot -VMName 'KSwordSandbox-Win10-Golden'`
  - Result: failed with authorization error because the current process is not elevated.
- `Get-VMIntegrationService -VMName 'KSwordSandbox-Win10-Golden'`
  - Result: failed with authorization error because the current process is not elevated.
- `scripts\Test-HyperVReadiness.ps1 -VmName 'KSwordSandbox-Win10-Golden' -CheckpointName 'Clean' -GuestPasswordSecretName 'KSWORDBOX_GUEST_PASSWORD' -RuntimeRoot 'D:\Temp\KSwordSandbox'`
  - Exit code reported by the script: `1`
  - Passed: Hyper-V PowerShell module, runtime root writable by read-only ACL inspection.
  - Failed: administrator privilege, guest password environment variable.
  - Warning/skipped: target VM, Clean checkpoint, Guest Service Interface, because VM state is not queryable from the non-elevated session.

## Target readiness items

### VM `KSwordSandbox-Win10-Golden`

Current live status: **not verified in this session**.

Direct `Get-VM` was blocked by authorization policy. Existing historical runtime evidence from `D:\Temp\KSwordSandbox\hyperv-vm-checksnap.txt` recorded:

- VM name: `KSwordSandbox-Win10-Golden`
- VM state: `Off`
- Checkpoint type: `Standard`
- Automatic checkpoints: `False`
- VM path: `D:\Temp\KSwordSandbox\HyperV\KSwordSandbox-Win10-Golden\KSwordSandbox-Win10-Golden`

### Checkpoint `Clean`

Current live status: **not verified in this session**.

Direct `Get-VMSnapshot` was blocked by authorization policy. Existing historical runtime evidence from `D:\Temp\KSwordSandbox\hyperv-vm-checksnap.txt` recorded:

- Snapshot name: `Clean`
- Snapshot type: `Standard`
- Creation time: `2026-07-10 14:30:54`
- Snapshot id: `587d58c4-530b-404a-b070-38eb0ce4ed3d`

Filesystem evidence also shows snapshot files under:

`D:\Temp\KSwordSandbox\HyperV\KSwordSandbox-Win10-Golden\KSwordSandbox-Win10-Golden\Snapshots\587D58C4-530B-404A-B070-38EB0CE4ED3D.*`

### Guest Service Interface

Current live status: **not verified in this session**.

Direct `Get-VMIntegrationService` was blocked by authorization policy. Existing historical runtime evidence from `D:\Temp\KSwordSandbox\hyperv-vm-setup.md` recorded:

- Guest Service Interface enabled: `True`
- Heartbeat OK during setup: `True`
- Setup status: `Ready`

### PowerShell Direct prerequisites

Current session status: **not ready**.

Observed:

- Hyper-V module and read-only cmdlets are installed.
- Host OS is Windows 10 version `10.0.19045`, which is compatible with PowerShell Direct scenarios.
- Current process is not elevated, so live Hyper-V operations and PowerShell Direct runbook actions are blocked.
- `KSWORDBOX_GUEST_PASSWORD` is not set in the current process, user scope, or machine scope according to the readiness script.
- VM current state could not be read. PowerShell Direct itself requires the VM to be running when it is tested, but this pass intentionally did not start the VM.

### Runtime root `D:\Temp\KSwordSandbox`

Current status: **present and usable from host-side read-only checks**.

Observed:

- Directory exists.
- Read-only ACL inspection in `Test-HyperVReadiness.ps1` reported it appears writable.
- D: free space: approximately `81.94 GiB`.
- Key files present:
  - `D:\Temp\KSwordSandbox\HyperV\KSwordSandbox-Win10-Golden\Virtual Hard Disks\KSwordSandbox-Win10-Golden.vhdx`
  - `D:\Temp\KSwordSandbox\payload\guest-tools\agent\KSword.Sandbox.Agent.exe`
  - `D:\Temp\KSwordSandbox\payload\guest-tools\r0collector\KSword.Sandbox.R0Collector.exe`
  - `D:\Temp\KSwordSandbox\samples\KSword.Sandbox.TestSample\KSword.Sandbox.TestSample.exe`
  - `D:\Temp\KSwordSandbox\hyperv-vm-setup.md`
  - `D:\Temp\KSwordSandbox\hyperv-live-smoke.md`

## Gaps

1. Re-run from an elevated PowerShell process to allow live reads of the VM, checkpoint, and integration service.
2. Set `KSWORDBOX_GUEST_PASSWORD` in the elevated process before readiness or live runbook checks.
3. Live PowerShell Direct cannot be proven in this pass without credentials and a running VM. This pass intentionally did not start the VM.
4. Current VM/checkpoint/GSI state remains unverified despite historical runtime evidence showing a ready state earlier on 2026-07-10.

## Workspace file status

This worker only wrote this file:

- `D:\Projects\KswordSandbox\docs\hyperv-vm-current-state.md`

Final `git status --short` also showed the following pre-existing or concurrent modified files. They were not edited or reverted by this worker:

- `config/sandbox.example.json`
- `docs/guest-payload-staging.md`
- `docs/hyperv-runbook.md`
- `docs/live-telemetry-pipeline.md`
- `scripts/Prepare-GuestPayload.ps1`
- `src/KSword.Sandbox.Abstractions/ConfigurationModels.cs`
- `src/KSword.Sandbox.Core/Configuration/SandboxConfigLoader.cs`
- `src/KSword.Sandbox.Core/Orchestration/HyperVRunbookBuilder.cs`
- `tests/KSword.Sandbox.SmokeTests/Program.cs`

## Recommended next step

From an elevated PowerShell process on the Hyper-V host:

```powershell
$env:KSWORDBOX_GUEST_PASSWORD = '<SandboxUser password>'
pwsh -NoProfile -ExecutionPolicy Bypass -File D:\Projects\KswordSandbox\scripts\Test-HyperVReadiness.ps1 `
  -VmName 'KSwordSandbox-Win10-Golden' `
  -CheckpointName 'Clean' `
  -GuestPasswordSecretName 'KSWORDBOX_GUEST_PASSWORD' `
  -RuntimeRoot 'D:\Temp\KSwordSandbox'
```

Expected result for readiness is `OverallStatus = Passed` with direct VM, checkpoint, and Guest Service Interface checks no longer skipped.
