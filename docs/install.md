# Local install and credential handling

`install.ps1` prepares local operator settings for KSwordSandbox. It is meant
for a lab host or contributor workstation, not for committing secrets.

The installer now owns two local concerns:

1. guest credential storage for PowerShell Direct; and
2. host/guest Hyper-V configuration such as VM name, clean checkpoint, guest
   working directory, runtime root, and the local Web/API config path.

## Interactive mode

Run from the repository root:

```powershell
.\install.ps1
```

The menu provides:

- Install / prepare local settings
- Change settings
- Uninstall local settings
- Reset Guest password
- Configure Hyper-V
- Configure VT key
- Check environment
- Start WebUI
- Status

The Change menu includes:

- reset password secret;
- reset the actual VM guest password;
- change Hyper-V VM/checkpoint/guest paths;
- change the recorded guest username;
- recreate runtime folders and local config;
- show Hyper-V readiness/status;
- manage guest test-signing;
- configure optional VirusTotal API key;
- check local environment.

Every mutating path supports `-WhatIf` because `install.ps1` uses
PowerShell `ShouldProcess`. `-WhatIf` previews local environment/config writes,
Guest password reset delegation, guest test-signing delegation, and WebUI
startup without prompting for secrets, starting dotnet, or touching a VM.

## Fast local setup

Shortest path for an existing golden VM:

```powershell
.\install.ps1 -Mode Install -PromptPassword
.\run.ps1
```

After this one-time setup, the daily startup is just:

```powershell
.\run.ps1
```

For a fresh local lab where you want the installer to generate a password:

```powershell
.\install.ps1 -Mode Install -GeneratePassword
```

This writes the generated value to:

- current process environment;
- current Windows user environment, unless `-CurrentProcessOnly` is supplied;
- `%ProgramData%\KSwordSandbox\guest-password.dpapi` as a DPAPI-protected backup
  for this Windows account, unless `-SkipDpapiBackup` is supplied.

The password value is never printed. If you only generate a local secret, the VM
`SandboxUser` account must still be set to the same value before PowerShell
Direct can authenticate.

For an existing golden VM where `SandboxUser` already has a known password:

```powershell
.\install.ps1 -Mode Install -PromptPassword
```

## Hyper-V local config

Install writes a local config file outside git, by default:

```text
D:\Temp\KSwordSandbox\config\sandbox.local.json
```

It also sets `Sandbox__ConfigPath` so `src/KSword.Sandbox.Web` can pick up the
local VM configuration without editing `config/sandbox.example.json`.

Non-interactive Hyper-V config update:

```powershell
.\install.ps1 -Mode Change -UpdateHyperVConfig `
  -VmName 'KSwordSandbox-Win10-Golden' `
  -CheckpointName 'Clean' `
  -GuestWorkingDirectory 'C:\KSwordSandbox'
```

Useful optional parameters are `-RuntimeRoot`, `-GuestPayloadRoot`,
`-GuestUserName`, `-SecretName`, and `-LocalConfigPath`.

Safe environment summary without changing local state:

```powershell
.\install.ps1 -Mode CheckEnvironment
```

`CheckEnvironment` and `Status` do not start, restore, or stop a VM. They print
`RecommendedActions` so a fresh workstation can fix packaging gaps before trying
live execution:

- missing VM: create/import the golden VM or record the real name with
  `.\install.ps1 -Mode Change -UpdateHyperVConfig -VmName <existing VM> -CheckpointName <checkpoint>`;
- missing checkpoint: create the clean checkpoint or update the recorded
  checkpoint name;
- missing Guest Agent/R0Collector payload or `payload-manifest.json`: run
  `.\scripts\Prepare-GuestPayload.ps1 -RepoRoot . -PayloadRoot <payloadRoot> -GuestWorkingDirectory <guestRoot> -SelfContained`;
- missing guest password secret: run `.\install.ps1 -Mode Install -PromptPassword`
  or use `.\scripts\Test-HyperVReadiness.ps1 -PromptForMissingGuestPassword` for
  a process-only readiness probe.

Preview local Hyper-V config writes:

```powershell
.\install.ps1 -Mode Change -UpdateHyperVConfig -WhatIf `
  -VmName 'KSwordSandbox-Win10-Golden' `
  -CheckpointName 'Clean' `
  -GuestWorkingDirectory 'C:\KSwordSandbox'
```

After install or config changes, run the read-only readiness preflight from an
elevated PowerShell session:

```powershell
.\scripts\Test-HyperVReadiness.ps1
```

The readiness script reuses the installed `Sandbox__ConfigPath` /
`install-state.json` values, so you normally do not need to retype VM name,
checkpoint, guest username, guest working directory, runtime root, or payload
root. It checks the password secret presence, target VM, clean checkpoint,
Guest Service Interface, PowerShell Direct when the VM is already running,
guest working directory shape, host payload files, and repository secret
hygiene without starting/restoring/stopping a VM. The summary includes
`RecommendedActions` for missing VM/checkpoint/payload/secret problems.

## Start WebUI after install

The release-wrapper path is intentionally short:

```powershell
.\install.ps1 -Mode Install -PromptPassword
.\run.ps1
```

Equivalent explicit startup wrappers:

```powershell
.\install.ps1 -Mode StartWebUI
.\run.ps1 -Mode StartWebUI
```

Preview startup without launching dotnet:

```powershell
.\run.ps1 -Mode StartWebUI -WhatIf
```

Use `-GeneratePassword` only when you will also synchronize the actual VM
`SandboxUser` password to that generated value. For the normal per-use launch,
`.\run.ps1` loads `%ProgramData%\KSwordSandbox\install-state.json`, sets
`Sandbox__ConfigPath`, mirrors `KSWORDBOX_GUEST_PASSWORD` into the WebUI process
when it exists in User/Machine environment, and starts the WebUI on
`http://127.0.0.1:18080` or the next available fallback localhost port.

Before launching the WebUI, `run.ps1` checks the configured
`paths.guestPayloadRoot` and tries to build a self-contained Guest
Agent/R0Collector payload by calling:

```powershell
.\scripts\Prepare-GuestPayload.ps1 -SelfContained
```

If Visual Studio/MSBuild or native build tools are missing, WebUI mode prints a
warning and still starts for upload, planning, dry-run runbooks, and
configuration review. Fix the payload before live Hyper-V execution, or run
`.\run.ps1 -RequirePayloadForWebUI` when you want payload preparation failure to
stop startup.

## Optional VirusTotal key

VirusTotal integration is optional and hash-only: the WebUI lookup checks an
existing SHA-256 report and does not upload samples. Store the key outside git
with the installer:

```powershell
.\install.ps1 -Mode ConfigureVTKey -PromptVTKey
```

This writes `KSWORDBOX_VIRUSTOTAL_API_KEY` to the current process and to the
current Windows User environment unless `-CurrentProcessOnly` is supplied. The
key value is never printed and is inherited by `.\run.ps1` / the WebUI process.
To clear it:

```powershell
.\install.ps1 -Mode ConfigureVTKey -ClearVTKey
```

You can also configure or clear the key from the interactive menu:
`Configure VT key`.

## Reset password secret

This is host-only secret storage. It does not change the VM account.

Interactive:

```powershell
.\install.ps1
# Change settings -> Reset password secret
```

Non-interactive generated reset:

```powershell
.\install.ps1 -Mode Change -ResetPassword -GeneratePassword
```

Non-interactive prompted reset:

```powershell
.\install.ps1 -Mode Change -ResetPassword -PromptPassword
```

## Reset actual VM guest password

Use this when you do not know the current guest password, or when you want the
host secret and the VM `SandboxUser` account synchronized in one step. It calls
`scripts/Reset-SandboxGuestPassword.ps1`, so it must run elevated and can restore
or refresh the clean checkpoint.

Interactive:

```powershell
.\install.ps1
# Change settings -> Reset actual VM guest password
```

Non-interactive generated VM reset:

```powershell
.\install.ps1 -Mode Change -ResetGuestVmPassword -GeneratePassword -Force
```

Non-interactive prompted VM reset:

```powershell
.\install.ps1 -Mode Change -ResetGuestVmPassword -PromptPassword -Force
```

The actual reset flow restores the configured checkpoint, mounts the offline
Windows disk, injects a one-shot SYSTEM service, boots the VM, validates
PowerShell Direct, stores the host secret, stops the VM, and refreshes the clean
checkpoint unless `-SkipCheckpointRefresh` is supplied.

## Status and uninstall

```powershell
.\install.ps1 -Mode Status
.\install.ps1 -Mode Uninstall -Force
```

Status shows secret presence, runtime folders, local config path,
`Sandbox__ConfigPath`, Hyper-V module availability, VM existence, checkpoint
existence, and whether the shell is elevated. It does not print passwords.

For deeper one-command readiness, use:

```powershell
.\scripts\Test-HyperVReadiness.ps1 -PromptForMissingGuestPassword
```

`-PromptForMissingGuestPassword` is process-only and non-persistent. It is for a
single elevated shell when you do not want to write User environment or DPAPI
backup. Use installer password reset modes for repeatable local setup.

Uninstall removes the current process/User environment secret plus local
installer metadata/DPAPI backup. It does not delete runtime job outputs under
`D:\Temp\KSwordSandbox`.

## Security boundary

`KSWORDBOX_GUEST_PASSWORD` is not the main VM escape boundary. Hyper-V
isolation, no sensitive host shares, network controls, checkpoint restore, and
cleanup are more important. The secret exists because PowerShell Direct needs a
guest Windows credential to stage the sample, run Guest Agent/R0Collector, and
copy outputs back.

Still avoid putting the value in git, reports, screenshots, or runbook logs.
The readiness and repository-policy scripts compare the current environment
secret value against candidate repository text files and fail without printing
the value if it appears in a file that could be staged.

The installer does not sign drivers and must not call `CSignTool.exe` or the
legacy `scripts\Sign-SandboxDriverWithKswordCSignTool.ps1` wrapper. Optional
real-driver lab validation is separate from install/run packaging and should use
the documented Windows test-signing path outside this repository.
