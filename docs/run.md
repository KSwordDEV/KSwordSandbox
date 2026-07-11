# Runtime entry point

Use `run.ps1` after `install.ps1` has prepared local settings.

The intended operator flow is:

```powershell
.\install.ps1   # one-time or when VM/password/config changes
.\run.ps1       # each time you want to use the local WebUI
```

Release bundles may also expose the same entry points from `scripts\`:

```powershell
.\scripts\install.ps1
.\scripts\run.ps1
```

The script-folder wrappers forward to the repository-root wrappers in the same
PowerShell process. They are aliases for packaging convenience, not a second
configuration system. Use either root or `scripts\` form consistently in a
session; both read `%ProgramData%\KSwordSandbox\install-state.json`, use the
same `Sandbox__ConfigPath`, and keep secrets out of command output.
Because the root scripts remain the implementation owner, diagnostic output and
`RecommendedActions` can still show canonical commands such as `.\run.ps1` and
`.\install.ps1`; those commands are expected and are equivalent to the wrapper
form.

## Start the WebUI

Default mode starts the local WebUI and loads the installed local config:

```powershell
.\run.ps1
.\scripts\run.ps1
```

Equivalent explicit form:

```powershell
.\run.ps1 -Mode WebUI -Url 'http://127.0.0.1:18080' -OpenBrowser
```

`StartWebUI` is an alias intended for menus and automation that prefer a verb:

```powershell
.\run.ps1 -Mode StartWebUI
.\scripts\run.ps1 -Mode StartWebUI
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
The WebUI startup path intentionally prints only concise status, the selected
URL, and repair hints. It does not dump a long command sequence to the operator.

If the requested localhost port is blocked by Windows/Hyper-V TCP port
exclusions or another process, `run.ps1` automatically falls back to a nearby
safe port and prints the final WebUI URL. Use `-StrictUrl` when you want port
binding failure to stop immediately instead.

## Single EXE plan or live run

For a non-mutating plan check:

```powershell
.\run.ps1 -Mode Plan -SamplePath 'D:\Temp\sample.exe' -DurationSeconds 30
```

Release shortcuts for built-in samples:

```powershell
# Analyze Notepad in PlanOnly mode; no VM mutation.
.\run.ps1 -Mode Analyze -SamplePreset Notepad

# Equivalent short alias.
.\run.ps1 -Mode Analyze -SamplePath notepad

# Publish the harmless sample outside git, then create a PlanOnly runbook.
.\run.ps1 -Mode Analyze -SamplePreset HarmlessSample

# Equivalent short alias.
.\run.ps1 -Mode Analyze -SamplePath sample
```

中文提示：上面四条命令都是“一条命令 Analyze notepad/sample”的入口；未加
`-Live` 时只生成计划，不启动、不还原、不停止 Hyper-V VM，也不会执行样本。
`HarmlessSample` 会在 `D:\Temp\KSwordSandbox\samples\...` 或已配置的
`RuntimeRoot` 下发布测试 EXE，输出位于仓库外。

`-Mode Plan` is PlanOnly and non-mutating: it does not start, restore, stop, or
copy into a VM, and it now skips guest payload preparation. The generated
Hyper-V plan records missing/stale payload files plus repair suggestions such as
running `.\scripts\Prepare-GuestPayload.ps1 -SelfContained`.

For a single live Hyper-V analysis from an elevated shell:

```powershell
.\run.ps1 -Mode Analyze -SamplePath 'D:\Temp\sample.exe' -DurationSeconds 30 -Live
```

Built-in sample live forms:

```powershell
.\run.ps1 -Mode Analyze -SamplePreset Notepad -Live
.\run.ps1 -Mode Analyze -SamplePreset HarmlessSample -Live
```

Live mode can restore/start/stop the configured VM and requires the installed
golden VM/checkpoint, guest password secret, prepared guest payload, and any
real R0 `driver.hostDriverPath`/guest test-signing setup required by your lab.

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

`run.ps1` also reports the real R0 driver configuration before WebUI or one-shot
analysis. If `driver.enabled=true`, `driver.useMockCollector=false`, and
`driver.hostDriverPath` is empty or missing, it prints an `R0 warning` because
the live runbook cannot stage a `.sys` or generate `install-driver-service`;
R0Collector would otherwise fail later with `deviceUnavailable` /
`win32Error=2`. Fix it by setting
`.\install.ps1 -Mode Change -UpdateHyperVConfig -DriverHostPath <test-signed .sys>`,
using `driver.useMockCollector=true` for payload-only R0 validation, or setting
`driver.enabled=false`.

## Status

```powershell
.\run.ps1 -Mode Status
```

Status reports repository root, install state, local config, Web URL, runtime
root, secret presence, optional VirusTotal key presence, VM/checkpoint
presence, host Guest Agent/R0Collector payload presence, R0 driver host-path
readiness, and whether the secret value was printed (`False`). It also prints
`RecommendedActions` with
human-readable fixes for common setup gaps:

- missing VM: record the real VM with
  `.\install.ps1 -Mode Change -UpdateHyperVConfig -VmName <existing VM> -CheckpointName <checkpoint>`;
- missing checkpoint: create or record the clean checkpoint;
- missing guest payload: run
  `.\scripts\Prepare-GuestPayload.ps1 -RepoRoot . -PayloadRoot <payloadRoot> -SelfContained`;
- missing guest password secret: run `.\install.ps1 -Mode Install -PromptPassword`
  or use `.\scripts\Test-HyperVReadiness.ps1 -PromptForMissingGuestPassword` for
  a process-only check;
- real R0 requested but no `driver.hostDriverPath`: set `-DriverHostPath`,
  enable `driver.useMockCollector=true`, or disable `driver.enabled`.

For a fuller non-mutating preflight summary:

```powershell
.\run.ps1 -Mode CheckEnvironment
```

`CheckEnvironment` prints the daily startup command, `ReadinessCommand`, whether
`dotnet`, the Web project, payload-preparation script, Hyper-V E2E script,
local config, guest secret, optional VirusTotal key, VM, checkpoint, and payload
files are visible from this host. `CheckEnvironmentStartsVm=False` and
`PlanOnlyStartsVm=False`; these paths are meant to be safe on another
developer's computer before they try `-Live`.

`-WhatIf` is supported on `run.ps1`. In WebUI modes it skips payload
preparation and dotnet startup. In `Plan` / `Analyze` modes it stops before
delegating to `scripts\Invoke-HyperVE2E.ps1`, so no Hyper-V child script is
launched.

## Relationship with install.ps1

- `install.ps1` is for one-time local preparation: folders, Hyper-V VM/checkpoint
  config, local config file, Web/API config env var, and guest password sync.
- `run.ps1` is for each launch: start WebUI, or run/plan one EXE with the
  installed config.
- `run.ps1` never asks you to type a password on the command line. It mirrors
  the configured secret from Process/User/Machine environment into the child
  WebUI or Hyper-V process and reports only whether a value exists.

Keep runtime outputs under `D:\Temp\KSwordSandbox`; do not commit generated
reports, samples, payload binaries, VM disks, or local secrets.
