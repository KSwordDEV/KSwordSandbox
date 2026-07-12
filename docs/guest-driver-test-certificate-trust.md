# Guest driver test-certificate trust helper

Use `scripts\Trust-GuestDriverTestCertificate.ps1` when a driver has already
been test-signed and you have exported the public certificate as `.cer`, `.crt`,
or `.der`. The helper imports that public certificate into the configured
Hyper-V guest:

- `Cert:\LocalMachine\Root`
- `Cert:\LocalMachine\TrustedPublisher`

It does not sign drivers, does not run signing tools, does not run smoke tests,
and does not load the driver.

## Safety model

- Default run is plan-only; it validates the local certificate and prints the
  guest/checkpoint targets.
- Guest/VM/checkpoint mutation requires `-AllowVmMutation`.
- Mutating operations are protected by PowerShell `ShouldProcess`, so `-WhatIf`
  previews and `-Confirm` can be used interactively.
- `-Force` suppresses confirmation prompts only for an already-approved isolated
  lab VM.
- `-RefreshCleanCheckpoint` stops the VM if needed, renames the current clean
  checkpoint to a timestamped backup, then creates a new checkpoint with the
  configured clean checkpoint name.

The script reads `C:\ProgramData\KSwordSandbox\install-state.json` when present
to pick up `VmName`, `CheckpointName`, `GuestUserName`, and `SecretName`.
Command-line parameters override those values.

## Examples

Plan only:

```powershell
.\scripts\Trust-GuestDriverTestCertificate.ps1 `
  -CertificatePath D:\Temp\KSwordSandbox\certs\KSwordSandboxTestDriver.cer `
  -Json
```

Import into a guest that is already running:

```powershell
.\scripts\Trust-GuestDriverTestCertificate.ps1 `
  -CertificatePath D:\Temp\KSwordSandbox\certs\KSwordSandboxTestDriver.cer `
  -AllowVmMutation `
  -Force `
  -Json
```

Start the configured guest if needed, import trust, and refresh the clean
checkpoint after import:

```powershell
.\scripts\Trust-GuestDriverTestCertificate.ps1 `
  -CertificatePath D:\Temp\KSwordSandbox\certs\KSwordSandboxTestDriver.cer `
  -StartVmIfNeeded `
  -RefreshCleanCheckpoint `
  -AllowVmMutation `
  -Force `
  -Json
```

If you want to restore the old baseline before this trust import, use the
existing checkpoint restore path first, then run this helper against the clean
guest state.
