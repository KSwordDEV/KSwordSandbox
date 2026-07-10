# Local install and credential handling

`install.ps1` prepares local operator settings for KSwordSandbox. It is meant
for a lab host or contributor workstation, not for committing secrets.

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
- change the recorded guest username;
- recreate runtime folders;
- show status.

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

The password value is never printed. If you generate a new value, the VM
`SandboxUser` account must be set to the same value before PowerShell Direct can
authenticate.

For an existing golden VM where `SandboxUser` already has a known password:

```powershell
.\install.ps1 -Mode Install -PromptPassword
```

## Reset password secret

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

## Status and uninstall

```powershell
.\install.ps1 -Mode Status
.\install.ps1 -Mode Uninstall -Force
```

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
