# KSwordSandbox

[![KSwordDEV/KSwordSandbox GitStock K-Line Chart](https://gitstock.org/KSwordDEV/KSwordSandbox/stock.svg)](https://gitstock.org/KSwordDEV/KSwordSandbox)

KSwordSandbox is a Windows malware-analysis sandbox scaffold for the KSword
project. The v1 design uses a Hyper-V Windows 10 golden VM, checkpoint restore
or differencing disks, a guest-side collector, optional KSword R0 driver event
export, and host-side JSON/HTML reports.

The repository intentionally stores only source code, rules, configuration
templates, and documentation. Samples, VM disks, reports, build outputs, signed
drivers, symbols, and credentials stay outside git.

## v1 scope

- Host Web API for planning sandbox jobs.
- Hyper-V runbook generation for a golden Windows 10 VM.
- Explicit dry-run/live Hyper-V runbook execution from the WebUI/API.
- Guest agent that runs inside the VM and emits normalized JSON events.
- Rule engine that maps events to behavior findings and seed MITRE technique
  IDs.
- Self-contained HTML report rendering.
- Repository policy script that blocks large files, binaries, VM images,
  reports, samples, and secrets from being committed.

The host service defaults to dry-run planning and dry-run runbook recording.
Live Hyper-V execution must be selected explicitly from the WebUI/API and
requires an elevated host process plus a prepared golden VM.

## Layout

```text
config/                         Configuration templates only
docs/                           Operator and developer runbooks
driver/KSword.Sandbox.Driver/   WDK R0 event driver skeleton
guest/KSword.Sandbox.Agent/     Guest-side collector
guest/KSword.Sandbox.R0Collector/
                                User-mode bridge from driver IOCTLs to JSONL
rules/                          Behavior and static-rule seeds
scripts/                        Build, smoke-test, and repository checks
src/KSword.Sandbox.Abstractions Shared models
src/KSword.Sandbox.Core         Planning, rules, reports, and services
src/KSword.Sandbox.Web          Host Web API
tests/KSword.Sandbox.SmokeTests Console smoke tests
```

## Quick start

Shortest path on a machine that already has the golden VM:

```powershell
.\install.ps1 -Mode Install -PromptPassword
.\run.ps1
```

After that one-time setup, daily WebUI startup is just `.\run.ps1`. It starts
the WebUI and does not start/restore a VM; live Hyper-V execution still requires
an explicit `-Live` CLI flag or live selection in the WebUI/API.

```powershell
.\install.ps1
.\run.ps1
dotnet build .\KSwordSandbox.sln
.\scripts\Invoke-SandboxSmokeTest.ps1
```

`install.ps1` has an interactive menu for install, change, uninstall, reset
Guest password, configure Hyper-V, configure VT key, check environment, start
WebUI, and status. The Change menu includes host-only password reset, actual VM
guest password reset, Hyper-V VM/checkpoint/guest path config, runtime folder
refresh, optional VirusTotal key setup, and Hyper-V readiness/status. For
unattended local lab setup:

```powershell
.\install.ps1 -Mode Install -GeneratePassword
```

For an existing golden VM, prefer:

```powershell
.\install.ps1 -Mode Install -PromptPassword
```

The installer stores `KSWORDBOX_GUEST_PASSWORD` outside git in the current user
environment, can write a DPAPI-protected local backup, writes a local sandbox
config under `D:\Temp\KSwordSandbox\config\sandbox.local.json`, and sets
`Sandbox__ConfigPath` for the Web/API. To update VM config without editing the
template:

```powershell
.\install.ps1 -Mode Change -UpdateHyperVConfig `
  -VmName 'KSwordSandbox-Win10-Golden' `
  -CheckpointName 'Clean' `
  -GuestWorkingDirectory 'C:\KSwordSandbox'
```

Optional real-R0 lab wiring stays local:

```powershell
.\install.ps1 -Mode Change -UpdateHyperVConfig -DriverHostPath 'D:\Temp\KSwordSandbox\build\r0-driver\Release\KSword.Sandbox.Driver.sys'
.\install.ps1 -Mode Change -QueryGuestTestSigning
.\install.ps1 -Mode Change -EnableGuestTestSigning -RestartGuestAfterTestSigning -Force
```

`-DriverHostPath` records a local test-signed `.sys` path; it does not sign the
driver. Test-signing commands affect only the configured guest VM.

Check another computer's local readiness without changing state:

```powershell
.\install.ps1 -Mode CheckEnvironment
.\run.ps1 -Mode CheckEnvironment
```

Optional VirusTotal hash-only lookups use `KSWORDBOX_VIRUSTOTAL_API_KEY` from
the current process/User/Machine environment. Configure it without printing the
key:

```powershell
.\install.ps1 -Mode ConfigureVTKey -PromptVTKey
```

To synchronize an unknown VM `SandboxUser` password with the host secret from an
elevated shell:

```powershell
.\install.ps1 -Mode Change -ResetGuestVmPassword -GeneratePassword -Force
```

See `docs/install.md`.

After installation, `run.ps1` is the normal per-use entry point. `.\run.ps1`
starts the WebUI with the installed local config, sets `Sandbox__ConfigPath`,
mirrors the guest password secret into the WebUI process when available,
mirrors the optional VirusTotal key into the WebUI process when configured, and
checks/prepares the self-contained guest payload under the configured
`guestPayloadRoot`. `.\run.ps1 -Mode StartWebUI` is the explicit WebUI startup
alias. WebUI launch remains best-effort if local payload build tools are
missing, so upload, planning, dry-run runbooks, and config review can still run;
use `.\run.ps1 -RequirePayloadForWebUI` when payload preparation should be
fatal. `.\run.ps1 -Mode Plan -SamplePath D:\Temp\sample.exe` creates a
non-mutating Hyper-V plan; and `.\run.ps1 -Mode Analyze -SamplePath
D:\Temp\sample.exe -Live` performs a single live Hyper-V analysis from an
elevated shell and automatically post-processes collected guest events into
`report.json` / `report.html`. Use `-WhatIf` on `install.ps1` or `run.ps1` to
preview local writes/startup without prompting for secrets, launching dotnet, or
delegating Hyper-V live execution. See `docs/run.md`.

Built-in one-command analysis shortcuts:

```powershell
.\run.ps1 -Mode Analyze -SamplePreset Notepad
.\run.ps1 -Mode Analyze -SamplePreset HarmlessSample
.\run.ps1 -Mode Analyze -SamplePreset Notepad -Live
```

中文提示：不加 `-Live` 时 `Analyze` 只生成计划，不启动、不还原、不停止 VM。
`HarmlessSample` 会发布到 `D:\Temp\KSwordSandbox\samples\...` 或配置的
`RuntimeRoot` 下，保持在仓库外。`run.ps1` 不在命令行提示明文密码，只镜像本机
Process/User/Machine 环境中的 secret 给子进程。

Build the native x64 collector and driver skeleton from the main solution:

```powershell
.\scripts\Invoke-NativeBuild.ps1 -Project .\KSwordSandbox.sln -Configuration Debug -Platform x64
```

`Invoke-NativeBuild.ps1` normalizes the child MSBuild environment so native
Visual C++ tasks do not fail when the parent shell contains both `PATH` and
`Path`. The driver project defaults to unsigned source builds, and current
validation should stop at compile success. `install.ps1`/`run.ps1` do not call
`CSignTool.exe`; do not use the legacy signing wrapper from normal builds.
Optional real-driver loading should use Windows test mode plus a local test
certificate in an isolated VM.
For that optional lab path, see
`scripts/Sign-SandboxDriverWithTestCertificate.ps1` and
`scripts/Set-GuestTestSigning.ps1`.

Run the current WebUI/API E2E gate:

```powershell
# Safe: starts no VM and mutates no VM state.
.\scripts\Invoke-WebUIApiE2E.ps1 `
  -BaseUrl 'http://127.0.0.1:18082' `
  -DurationSeconds 3 `
  -StepTimeoutSeconds 120

# Live: restores/starts the configured VM and runs the sample.
.\scripts\Invoke-WebUIApiE2E.ps1 `
  -BaseUrl 'http://127.0.0.1:18082' `
  -Live `
  -DurationSeconds 3 `
  -StepTimeoutSeconds 900
```

The latest local real-R0 WebUI/API evidence is documented in
`docs/webui-real-r0-e2e.md`. It completed 17/17 Hyper-V runbook steps, imported
guest/R0 events, generated default/Chinese/English HTML reports, and did not
call `CSignTool.exe`.

Plan a dry-run job:

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri http://localhost:5000/api/jobs/plan `
  -ContentType 'application/json' `
  -Body '{"samplePath":"D:\\Temp\\sample.exe","durationSeconds":120,"dryRun":true}'
```

Reports are written under `D:\Temp\KSwordSandbox\jobs\<job-id>\` by default.

## Repository policy

Run the policy check before committing:

```powershell
.\scripts\Test-RepositoryPolicy.ps1
```

Install the optional local pre-commit hook:

```powershell
.\scripts\Install-GitHooks.ps1
```

The policy rejects VM images, compiled binaries, symbols, PDFs, archives,
samples, runtime reports, secrets, and files over 25 MB.

The repository remote can be configured as `origin`, but the default workflow is
local commits only. Push to GitHub only when explicitly requested.

## Hyper-V assumption

The default configuration expects a local golden VM named
`KSwordSandbox-Win10-Golden` and a clean checkpoint named `Clean`. Edit a local
copy of `config/sandbox.example.json` for your machine. Do not commit local
credentials or VM paths.

## Driver integration assumption

The R0 driver is expected to be built as an unsigned local artifact by default.
Only optional real-driver VM validation should test-sign the `.sys` outside this
repository with Windows test mode and a local test certificate, then copy or
stage it into the guest. The guest agent can ingest driver events from JSON Lines
at the configured path. The v1 scaffold does not copy an external KSword source
tree and does not commit driver binaries or signing material.

The initial R0 source path now contains a WDK control-device skeleton under
`driver/KSword.Sandbox.Driver/` and a user-mode JSONL bridge skeleton under
`guest/KSword.Sandbox.R0Collector/`. These are source-only scaffolds; generated
`.sys`, `.exe`, symbols, certificates, and native build output remain ignored.

## Research references

Design references and platform documentation are tracked in
`docs/research-basis.md`. The initial scaffold uses CAPE, Cuckoo, DRAKVUF,
MITRE ATT&CK for Windows, Hyper-V PowerShell Direct, `Copy-VMFile`, and Windows
driver callback documentation as design inputs.

For a concise explanation-oriented summary of the extracted report structure,
current implementation status, R0 reuse boundary, and next engineering steps,
see `docs/extracted-results-summary.md`.
