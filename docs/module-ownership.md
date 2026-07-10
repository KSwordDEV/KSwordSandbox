# Module ownership map

This file exists to reduce collisions between parallel Codex sessions.

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
