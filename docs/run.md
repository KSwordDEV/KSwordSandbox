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

`StartWebUI` is an alias intended for menus and automation that prefer a verb:

```powershell
.\run.ps1 -Mode StartWebUI
```

Preview startup without building payloads, starting dotnet, opening a browser,
or touching a VM:

```powershell
.\run.ps1 -Mode StartWebUI -WhatIf
```

`run.ps1` sets these process-scoped values before starting the Web project:

- `Sandbox__ConfigPath` from `%ProgramData%\KSwordSandbox\install-state.json`,
  the current environment, or `D:\Temp\KSwordSandbox\config\sandbox.local.json`;
- `ASPNETCORE_URLS` from `-Url`;
- `KSWORDBOX_GUEST_PASSWORD` in process scope by mirroring the User/Machine
  environment value if one exists.
- optional `KSWORDBOX_VIRUSTOTAL_API_KEY` in process scope by mirroring the
  User/Machine environment value if one exists.

The password value is never printed. Optional VT key values are never printed.

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

When `-Live` succeeds, `run.ps1` automatically invokes
`tools/KSword.Sandbox.PostProcess` against the collected job directory. The
single command therefore ends with:

- `runbook-execution.json`
- `guest\<job-id>\events.json`
- `postprocess-result.json`
- `report.json`
- `report.html`

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
root, secret presence, optional VirusTotal key presence, VM/checkpoint
presence, and whether the secret value was printed (`False`).

For a fuller non-mutating preflight summary:

```powershell
.\run.ps1 -Mode CheckEnvironment
```

`CheckEnvironment` prints the daily startup command, whether `dotnet`, the Web
project, payload-preparation script, Hyper-V E2E script, local config, guest
secret, optional VirusTotal key, VM, and checkpoint are visible from this host.

`-WhatIf` is supported on `run.ps1`. In WebUI modes it skips payload
preparation and dotnet startup. In `Plan` / `Analyze` modes it stops before
delegating to `scripts\Invoke-HyperVE2E.ps1`, so no Hyper-V child script is
launched.

## Relationship with install.ps1

- `install.ps1` is for one-time local preparation: folders, Hyper-V VM/checkpoint
  config, local config file, Web/API config env var, and guest password sync.
- `run.ps1` is for each launch: start WebUI, or run/plan one EXE with the
  installed config.

Keep runtime outputs under `D:\Temp\KSwordSandbox`; do not commit generated
reports, samples, payload binaries, VM disks, or local secrets.
