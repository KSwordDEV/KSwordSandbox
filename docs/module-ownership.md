# Module ownership map

This file exists to reduce collisions between parallel Codex sessions.

For the operator-facing architecture and runbook summary, see
`docs/current-architecture-and-operations.md`.

## Runtime module boundaries

- `src/KSword.Sandbox.Abstractions/**`: shared contracts only. Keep it free of
  host/guest side effects.
- `src/KSword.Sandbox.Core/**`: host orchestration, config, hashing, static
  analysis, runbook building/execution records, event import, rules, artifacts,
  and reports.
- `src/KSword.Sandbox.Web/**`: WebUI/API composition, upload/scan, background
  runbook start, live progress/events, report/artifact serving, and optional
  hash-only enrichment settings.
- `guest/KSword.Sandbox.Agent/**`: code that runs inside the VM to execute the
  sample and write guest outputs.
- `guest/KSword.Sandbox.R0Collector/**`: guest user-mode bridge that emits
  driver/mock telemetry JSONL.
- `driver/KSword.Sandbox.Driver/**`: WDK kernel driver source only; generated
  `.sys`, `.pdb`, certificates, and signing output are never repository
  artifacts.
- `scripts/**`, `install.ps1`, `run.ps1`: operator automation and local
  machine state management. These can touch Hyper-V or environment state only
  when the operator explicitly selects a mutating mode.

Dependency direction should stay `Web -> Core -> Abstractions`. Guest and R0
components communicate with the host through files/events, not direct WebUI
dependencies.

## Primary write scopes

- Core orchestration: `src/KSword.Sandbox.Core/Orchestration/**`,
  `src/KSword.Sandbox.Core/HyperV/**`, `src/KSword.Sandbox.Core/Runbooks/**`
- Core telemetry: `src/KSword.Sandbox.Core/Telemetry/**`,
  `src/KSword.Sandbox.Core/Guest/**`
- Core reporting: `src/KSword.Sandbox.Core/Reporting/**`,
  `src/KSword.Sandbox.Core/Classification/**`,
  `src/KSword.Sandbox.Core/Rules/**`
- WebUI: `src/KSword.Sandbox.Web/**`
- Guest agent: `guest/KSword.Sandbox.Agent/**`
- R0 collector: `guest/KSword.Sandbox.R0Collector/**`
- Kernel driver: `driver/KSword.Sandbox.Driver/**`
- Tests and scripts: `tests/**`, `scripts/**`

## Coordination expectations

Workers should avoid reverting files outside their assigned scope. If a worker
must touch a shared file such as `KSwordSandbox.sln`, a project file, or
`Program.cs`, it should state that clearly in the final report so the main
thread can merge deliberately.

Generated files must stay out of git. This includes `bin`, `obj`, `x64`, VM
disks, driver binaries, reports, samples, and local credentials.
