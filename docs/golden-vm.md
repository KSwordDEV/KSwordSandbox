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

## Differencing-disk mode

Differencing-disk mode creates a temporary VM from a base VHDX. Set
`HyperV.UseDifferencingDisk` to `true` and configure `HyperV.BaseVhdxPath` in a
local config file. The base disk must stay outside git.
