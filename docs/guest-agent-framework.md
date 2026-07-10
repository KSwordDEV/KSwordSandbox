# Guest Agent framework

The Guest Agent is still a compact executable, but dynamic collection now flows
through explicit probe boundaries:

- `Collection`: guest probes, probe phases, run context, event sink, process
  tree snapshots, file diffs, TCP diffs, and optional screenshot capture.
- `Execution`: sample launch plans and process execution results.
- `Output`: `events.json`, `agent-summary.json`, and driver JSONL import.
- `Options`: command-line switch constants and parsed option models.
- `Diagnostics`: normalized diagnostic event creation.

`Program.cs` owns the CLI and top-level R0 sidecar orchestration. It creates a
`GuestProbeRunner` and runs these phases:

1. `BeforeStart` - baseline process list, file tree, and TCP connections.
2. `AfterStart` - process deltas, process tree, and optional screenshot.
3. `AfterRun` - final process deltas, file diffs, TCP diffs, and optional
   screenshot.

The CLI remains backward compatible:

```text
--sample <path> --out <directory> --duration <seconds>
--driver-events <jsonl> --r0collector <path> --driver-device <path>
--r0-mock --screenshot
```

The driver sidecar remains optional so VM smoke tests can proceed without a
signed driver.

## Probe contracts

`IGuestProbe.CollectAsync(ProbePhase, GuestProbeContext, CancellationToken)` is
the internal extension point. Probes should:

- avoid administrator-only APIs where a lower-privilege API exists;
- convert expected access failures into missing fields or `probe.failed` events;
- emit `SandboxEvent` records with string values in `Data`;
- keep the existing event names stable when replacing older inline logic.

`GuestProbeContext` carries `SamplePath`, `WorkingDirectory`, `OutputDirectory`,
optional `RootProcessId`, and the `CaptureScreenshots` flag. New process, image,
registry, or WFP collectors can use this context without changing the public
agent CLI.

## Current probes

- `ProcessTreeProbe` uses Toolhelp process snapshots on Windows to capture
  parent process IDs without WMI or elevation. It preserves `process.observed`
  and `process.new`, then adds `process.tree` for the launched sample process
  and visible descendants.
- `FileDiffProbe` compares file size and UTC last-write time below the sample
  working directory and emits `file.created`, `file.modified`, and
  `file.deleted` with relative-path metadata.
- `TcpConnectionDiffProbe` compares `IPGlobalProperties.GetActiveTcpConnections`
  before and after execution. New connections keep the legacy `network.tcp`
  event type with `change=opened`; disappeared baseline connections emit
  `network.tcp.closed` with `change=closed`.
- `ScreenshotProbe` is opt-in through `--screenshot`. `IScreenshotCapture`
  allows replacement capture implementations; the default
  `WindowsDesktopScreenshotCapture` writes BMP files through User32/GDI32 and
  emits `screenshot.skipped` instead of failing in headless sessions.

## Smoke strategy

Smoke coverage should stay synthetic: verify source contracts, run the agent
against benign helper executables where available, and prefer temp directories
over committed artifacts. None of the probes require a real malicious sample,
an installed kernel driver, or administrator rights for their normal path.
