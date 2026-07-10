# Golden VM preparation

## Required baseline

- Windows 10 x64 VM on local Hyper-V.
- VM name matching `config/sandbox.example.json`.
- A clean checkpoint named `Clean`.
- PowerShell Direct enabled by using a local guest account.
- Guest Service Interface enabled when using `Copy-VMFile`.
- Network isolation appropriate for the malware-analysis lab.

## Suggested guest folders

```text
C:\KSwordSandbox\agent      Guest collector binaries
C:\KSwordSandbox\driver     Signed driver artifacts, if used
C:\KSwordSandbox\incoming   Submitted sample for the current run
C:\KSwordSandbox\out        JSON event output
```

## Host credential handling

Store the guest password outside git. The default runbook reads it from the
environment variable named by `Guest.PasswordSecretName`, which defaults to
`KSWORDBOX_GUEST_PASSWORD`.

```powershell
$env:KSWORDBOX_GUEST_PASSWORD = '<local guest password>'
```

Use a local unprivileged guest account for the agent unless driver install or
service start requires elevation inside the VM.

## Checkpoint mode

Checkpoint mode restores the named golden VM before each run. It is simple and
works well for one job at a time. Do not run concurrent jobs against the same
golden VM.

## Differencing-disk mode

Differencing-disk mode creates a temporary VM from a base VHDX. Set
`HyperV.UseDifferencingDisk` to `true` and configure `HyperV.BaseVhdxPath` in a
local config file. The base disk must stay outside git.
