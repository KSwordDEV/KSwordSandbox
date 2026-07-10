# Hyper-V runbook

The host service currently generates Hyper-V steps without executing them. This
keeps the repository safe to build on machines without administrator rights or a
registered golden VM.

## Planned step groups

1. Verify Hyper-V PowerShell cmdlets.
2. Verify the configured golden VM exists.
3. Load guest credentials from an environment variable.
4. Restore a clean checkpoint or create a temporary differencing-disk VM.
5. Copy the sample into the guest.
6. Run `KSword.Sandbox.Agent.exe` through PowerShell Direct.
7. Copy guest JSON output back to the host.
8. Stop and optionally remove the temporary VM.

## Execution prerequisites

- Elevated host PowerShell.
- Hyper-V feature installed.
- Golden VM registered and checkpointed.
- Guest credentials available through the configured environment variable.
- Guest agent published and available at the configured guest path.

## Current local status

Non-elevated checks on this machine cannot enumerate Hyper-V state. Commands
such as `Get-VM` and `Get-WindowsOptionalFeature -Online` require elevation, so
the v1 implementation stops at dry-run planning until a privileged runner is
explicitly wired in.
