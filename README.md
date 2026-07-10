# KSwordSandbox

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
guest/KSword.Sandbox.Agent/     Guest-side collector
rules/                          Behavior and static-rule seeds
scripts/                        Build, smoke-test, and repository checks
src/KSword.Sandbox.Abstractions Shared models
src/KSword.Sandbox.Core         Planning, rules, reports, and services
src/KSword.Sandbox.Web          Host Web API
tests/KSword.Sandbox.SmokeTests Console smoke tests
```

## Quick start

```powershell
dotnet build .\KSwordSandbox.sln
.\scripts\Invoke-SandboxSmokeTest.ps1
dotnet run --project .\src\KSword.Sandbox.Web\KSword.Sandbox.Web.csproj
```

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

The R0 driver is expected to be built and signed outside this repository, then
copied into the guest image or staged by the Hyper-V runner. The guest agent can
ingest driver events from JSON Lines at the configured path. The v1 scaffold
does not copy the full `D:\Projects\Ksword5.1` tree and does not commit driver
binaries.

## Research references

Design references and platform documentation are tracked in
`docs/research-basis.md`. The initial scaffold uses CAPE, Cuckoo, DRAKVUF,
MITRE ATT&CK for Windows, Hyper-V PowerShell Direct, `Copy-VMFile`, and Windows
driver callback documentation as design inputs.

For a concise explanation-oriented summary of the extracted report structure,
current implementation status, R0 reuse boundary, and next engineering steps,
see `docs/extracted-results-summary.md`.
