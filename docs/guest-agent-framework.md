# Guest Agent framework

The Guest Agent is still a compact executable, but dynamic collection now flows
through explicit probe boundaries:

- `Collection`: guest probes, probe phases, run context, event sink, process
  tree snapshots, file diffs, TCP diffs, optional screenshot capture, and
  opt-in sample process memory dump capture.
- `Execution`: sample launch plans and process execution results.
- `Output`: `events.json`, `agent-summary.json`, and driver JSONL import.
- `Options`: command-line switch constants and parsed option models.
- `Diagnostics`: normalized diagnostic event creation.

`Program.cs` owns the CLI and top-level R0 sidecar orchestration. It creates a
`GuestProbeRunner` and runs these phases:

1. `BeforeStart` - baseline process list, file tree, TCP connections, DNS cache,
   netstat rows, listeners, services, scheduled tasks, startup items, and
   environment details.
2. `AfterStart` - process deltas, process tree, and optional screenshot.
3. `AfterRun` - final process deltas, file diffs, TCP/DNS/netstat/listener
   diffs, service/task/startup diffs, and optional screenshot.

The CLI remains backward compatible:

```text
--sample <path> --out <directory> --duration <seconds>
--driver-events <jsonl> --r0collector <path> --driver-device <path>
--r0-mock --screenshot --collect-dropped-files --memory-dump
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
optional `RootProcessId`, `CaptureScreenshots`, and `CaptureMemoryDump`. New
process, image, registry, or WFP collectors can use this context without
changing the public agent CLI.

`GuestProbeRunner` enforces a per-probe timeout and turns probe exceptions into
`probe.timeout`, `probe.failed`, or `probe.canceled` events. A timed-out or
faulted collector is isolated from later collectors so live output and final
artifact writing remain stable even when a Windows helper command hangs or a
platform API fails.

`Diagnostics.BoundedProcessRunner` is the shared helper for short-lived Windows
commands. It starts processes without a shell, redirects stdout/stderr, kills
the process tree on timeout, and returns structured command results instead of
throwing for expected launch/exit failures.

## Current probes

- `ProcessTreeProbe` uses Toolhelp process snapshots on Windows to capture
  parent process IDs, image names, thread counts, and base priorities without
  WMI or elevation. It preserves `process.observed` and `process.new`, then adds
  `process.tree` for the launched sample process and visible descendants. It
  also emits `environment.detail`, service diffs, scheduled task diffs, and
  startup item diffs using bounded `sc.exe`, `schtasks.exe`, registry, and
  Startup-folder collection.
- `FileDiffProbe` compares file size and UTC last-write time below the sample
  working directory and emits `file.created`, `file.modified`, and
  `file.deleted` with relative-path metadata.
- `TcpConnectionDiffProbe` compares `IPGlobalProperties.GetActiveTcpConnections`
  before and after execution. New connections keep the legacy `network.tcp`
  event type with `change=opened`; disappeared baseline connections emit
  `network.tcp.closed` with `change=closed`. The same probe also captures
  DNS cache entries through `ipconfig /displaydns`, `netstat -ano` rows, and
  managed TCP/UDP listener snapshots with bounded command timeouts and
  truncation events for high-volume outputs.
- `ScreenshotProbe` is opt-in through `--screenshot`. `IScreenshotCapture`
  allows replacement capture implementations; the default
  `WindowsDesktopScreenshotCapture` writes BMP files through User32/GDI32 and
  emits `screenshot.skipped` instead of failing in headless sessions. Skipped
  events include the failing capture stage and Win32 error code when available.
- `MemoryDumpProbe` is opt-in through `--memory-dump` / `--memory-dumps`. The
  default `WindowsMiniDumpCapture` writes one `MiniDumpNormal` file for the
  launched sample root PID during `AfterStart`; it skips non-Windows, exited, or
  inaccessible targets and emits `memory_dump.skipped` rather than failing the
  run.
- `ProcessSampleExecutor` records `process.start_failed`,
  `process.wait_failed`, and `process.kill_failed` diagnostics for execution
  exceptions while preserving normal cancellation behavior.

## Current output artifact handling

`GuestArtifactWriter` owns `events.json`, `agent-summary.json`, and optional
`artifacts/manifest.json` serialization. With `--collect-dropped-files`, the
top-level agent copies `file.created` paths from the sample working directory to
`artifacts/dropped-files`, skips paths under `--out`, then writes a dropped-file
manifest with SHA-256, MIME type, safe relative link, and original guest path
metadata.

The copy step emits `artifact.dropped_file.copied` or
`artifact.dropped_file.skipped`; manifest output emits
`artifact.manifest.written` or `artifact.manifest.failed`. Dropped-file
extraction is independent from memory dump capture; both remain disabled unless
their explicit CLI flags are supplied.

## Smoke strategy

Smoke coverage should stay synthetic: verify source contracts, run the agent
against benign helper executables where available, and prefer temp directories
over committed artifacts. None of the probes require a real malicious sample,
an installed kernel driver, or administrator rights for their normal path.
