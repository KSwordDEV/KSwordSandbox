# Hyper-V readiness preflight

`scripts/Test-HyperVReadiness.ps1` verifies the minimum host and golden-VM
state needed before the live Hyper-V runner starts a VM and imports a behavior
report. The script is intentionally read-only: it does not create runtime probe
files, create or restore checkpoints, start or stop VMs, copy files, or change
integration-service settings.

## Run the check

Run from an elevated PowerShell session on the Hyper-V host:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-HyperVReadiness.ps1
```

Windows PowerShell also works:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-HyperVReadiness.ps1
```

Defaults match `config/sandbox.example.json`:

```powershell
.\scripts\Test-HyperVReadiness.ps1 `
  -VmName 'KSwordSandbox-Win10-Golden' `
  -CheckpointName 'Clean' `
  -GuestPasswordSecretName 'KSWORDBOX_GUEST_PASSWORD' `
  -RuntimeRoot 'D:\Temp\KSwordSandbox'
```

The script writes structured PowerShell objects:

- `ReadinessCheck` objects for each check.
- One `ReadinessSummary` object with `OverallStatus`, counts, and `ExitCode`.

Exit code behavior:

- `0`: no check has `Status = Failed`.
- `1`: at least one check has `Status = Failed`.

Warnings are still printed as objects. A non-administrator run usually emits a
failed Administrator check and warning objects for VM state that cannot be read
reliably from a non-elevated process.

## Checks

### Administrator privilege

Confirms that the current PowerShell process is elevated. Live Hyper-V actions
such as `Restore-VMSnapshot`, `Start-VM`, `Copy-VMFile`, and PowerShell Direct
must run from an elevated host process.

Fix: reopen PowerShell with "Run as administrator" and run the preflight again.

### Hyper-V PowerShell module

Checks that the `Hyper-V` PowerShell module is installed and that the required
read-only cmdlets are available:

- `Get-VM`
- `Get-VMSnapshot`
- `Get-VMIntegrationService`

Fix: enable/install Hyper-V management tools for the host OS, then open a new
PowerShell session.

### Guest password environment variable

Checks that the environment variable named by `-GuestPasswordSecretName` exists
and is non-empty in the current process. The default is
`KSWORDBOX_GUEST_PASSWORD`. The script never prints the secret value.

Fix for the current session:

```powershell
$env:KSWORDBOX_GUEST_PASSWORD = '<local guest password>'
```

If the variable exists at User or Machine scope but not in the current process,
open a new elevated PowerShell session or set `$env:...` in the current session.

### Runtime root writable

Checks that `-RuntimeRoot` exists as a directory and appears writable from
read-only ACL inspection. The check does not create a temporary file, so it is
conservative: if the directory does not exist or ACLs cannot prove write access,
the check fails.

Fix: create the runtime directory outside git and grant the account running the
host service permission to create job folders under it. The default path is:

```text
D:\Temp\KSwordSandbox
```

### Target VM

Checks that `-VmName` exists and is readable through `Get-VM`. The default is:

```text
KSwordSandbox-Win10-Golden
```

Fix: register or rename the golden VM so it matches local configuration, or pass
the correct `-VmName` value.

### Clean checkpoint

Checks that `-CheckpointName` exists on the target VM through `Get-VMSnapshot`.
The default is:

```text
Clean
```

Fix: prepare the VM, shut it down into the desired clean baseline, and create a
checkpoint with the configured name.

### Guest Service Interface

Checks that the target VM has the Hyper-V integration service named
`Guest Service Interface` and that it is enabled. This is required when the
runner uses `Copy-VMFile` to move files between host and guest.

Fix: enable the integration service in Hyper-V Manager or with an elevated
operator command such as:

```powershell
Enable-VMIntegrationService -VMName 'KSwordSandbox-Win10-Golden' -Name 'Guest Service Interface'
```

## Payload staging dependency

This preflight verifies host/VM readiness only. It does not build or copy guest
tools. Before refreshing the golden `Clean` checkpoint for a live run, prepare
the payload outside the repository and deploy it into the guest:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Prepare-GuestPayload.ps1
```

Then follow `docs/guest-payload-staging.md` to copy the staged files into:

```text
C:\KSwordSandbox\agent
C:\KSwordSandbox\r0collector
```

At minimum, the configured guest agent path must exist before a live runbook can
produce `events.json`.

## Reporting and automation

To save machine-readable output while preserving the script exit code:

```powershell
$results = & .\scripts\Test-HyperVReadiness.ps1
$code = $LASTEXITCODE
$results | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 .\hyperv-readiness.json
exit $code
```

Do not commit generated readiness JSON files, runtime job folders, VM images, or
guest output. These are local operator artifacts.
