# Runtime entry point

Use `run.ps1` after `install.ps1` has prepared local settings.

The intended operator flow is:

```powershell
.\install.ps1   # one-time or when VM/password/config changes
.\run.ps1       # each time you want to use the local WebUI
```

## Start the WebUI

Default mode starts the local WebUI and loads the installed local config:

```powershell
.\run.ps1
```

Equivalent explicit form:

```powershell
.\run.ps1 -Mode WebUI -Url 'http://127.0.0.1:18080' -OpenBrowser
```

`run.ps1` sets these process-scoped values before starting the Web project:

- `Sandbox__ConfigPath` from `%ProgramData%\KSwordSandbox\install-state.json`,
  the current environment, or `D:\Temp\KSwordSandbox\config\sandbox.local.json`;
- `ASPNETCORE_URLS` from `-Url`;
- `KSWORDBOX_GUEST_PASSWORD` in process scope by mirroring the User/Machine
  environment value if one exists.

The password value is never printed.

If the requested localhost port is blocked by Windows/Hyper-V TCP port
exclusions or another process, `run.ps1` automatically falls back to a nearby
safe port and prints the final WebUI URL. Use `-StrictUrl` when you want port
binding failure to stop immediately instead.

## Single EXE plan or live run

For a non-mutating plan check:

```powershell
.\run.ps1 -Mode Plan -SamplePath 'D:\Temp\sample.exe' -DurationSeconds 30
```

For a single live Hyper-V analysis from an elevated shell:

```powershell
.\run.ps1 -Mode Analyze -SamplePath 'D:\Temp\sample.exe' -DurationSeconds 30 -Live
```

If `-Live` is omitted, `Analyze` falls back to PlanOnly and does not mutate the
VM. This keeps accidental sample execution out of the default path while still
making the real live command short.

Before invoking `scripts/Invoke-HyperVE2E.ps1`, `run.ps1` checks the staged Guest
Agent/R0Collector payload under the configured `guestPayloadRoot`. If it is
missing, it calls `scripts/Prepare-GuestPayload.ps1 -SelfContained` so a fresh
machine can reach the Hyper-V path without manually building guest binaries.
Use `-SkipPayloadPreparation` only when intentionally testing planner behavior
without payload files.

## Status

```powershell
.\run.ps1 -Mode Status
```

Status reports repository root, install state, local config, Web URL, runtime
root, secret presence, VM/checkpoint presence, and whether the secret value was
printed (`False`).

## Relationship with install.ps1

- `install.ps1` is for one-time local preparation: folders, Hyper-V VM/checkpoint
  config, local config file, Web/API config env var, and guest password sync.
- `run.ps1` is for each launch: start WebUI, or run/plan one EXE with the
  installed config.

Keep runtime outputs under `D:\Temp\KSwordSandbox`; do not commit generated
reports, samples, payload binaries, VM disks, or local secrets.
