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
- Status

The Change menu includes:

- reset password secret;
- reset the actual VM guest password;
- change Hyper-V VM/checkpoint/guest paths;
- change the recorded guest username;
- recreate runtime folders and local config;
- show Hyper-V readiness/status.

## Fast local setup

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
