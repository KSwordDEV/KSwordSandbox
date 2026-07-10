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
6. Create a job-specific guest output folder such as
   `C:\KSwordSandbox\out\<job-id-n>`.
7. Start `KSword.Sandbox.Agent.exe` asynchronously through PowerShell Direct.
8. Pass `--driver-events C:\KSwordSandbox\out\<job-id-n>\driver-events.jsonl`,
   `--r0collector`, and `--driver-device` when driver collection is enabled.
9. While the guest agent process is running, periodically copy guest output
   back to `D:\Temp\KSwordSandbox\jobs\<job-id-n>\guest`.
10. Copy guest JSON/JSONL output one final time.
11. Stop and optionally remove the temporary VM.

## Execution prerequisites

- Elevated host PowerShell.
- Hyper-V feature installed.
- Golden VM registered and checkpointed.
- Guest credentials available through the configured environment variable.
- Guest agent published and available at the configured guest path.
- R0Collector published to the configured guest path when driver collection is
  enabled, or `driver.useMockCollector` enabled for no-driver smoke demos.

## Current local status

The host now has dry-run and live execution wiring. Non-elevated checks still
cannot enumerate Hyper-V state; commands such as `Get-VM` and
`Get-WindowsOptionalFeature -Online` require elevation. Live execution must be
started from an elevated host process with a prepared golden VM and guest
credential secret.
