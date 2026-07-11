# Guest Agent framework

The Guest Agent is still a compact executable, but dynamic collection now flows
through explicit probe boundaries:

- `Collection`: guest probes, probe phases, run context, event sink, process
  tree snapshots, file diffs, TCP diffs, optional screenshot capture, opt-in
  sample process memory dump capture, and opt-in packet capture.
- `Execution`: sample launch plans and process execution results.
- `Output`: `events.json`, `agent-summary.json`, and driver JSONL import.
- `Options`: command-line switch constants and parsed option models.
- `Diagnostics`: normalized diagnostic event creation.

`Program.cs` owns the CLI and top-level R0 sidecar orchestration. It creates a
`GuestProbeRunner` and runs these phases:

1. `BeforeStart` - baseline process list, file tree, TCP connections, DNS cache,
   netstat rows, listeners, services, scheduled tasks, startup items,
   environment details, optional before-stage screenshot, and optional pktmon
   packet-capture start.
2. `AfterStart` - process deltas, process tree, optional during-stage
   screenshot, and opt-in memory dump.
3. `AfterRun` - final process deltas, file diffs, TCP/DNS/netstat/listener
   diffs, service/task/startup diffs, optional after-stage screenshot, and
   optional pktmon stop/PCAPNG conversion.

The CLI remains backward compatible:

```text
--sample <path> --out <directory> --duration <seconds>
--driver-events <jsonl> --r0collector <path> --driver-device <path>
--r0-mock --screenshot --screenshot-phases before,during,after
--screenshot-count <1-5> --collect-dropped-files --memory-dump
--packet-capture
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
optional `RootProcessId`, `CaptureScreenshots`, `CaptureMemoryDump`, and
`CapturePacketCapture`. New process, image, registry, or WFP collectors can use
this context without changing the public agent CLI.

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
- `ScreenshotProbe` is opt-in through `--screenshot`. `ScreenshotProbeOptions`
  plans the default `before,during,after` cadence or the operator-selected
  `--screenshot-phases` / `--screenshot-count` configuration without changing
  the shared event model. `IScreenshotCapture` allows replacement capture
  implementations; the default `WindowsDesktopScreenshotCapture` writes BMP
  files through User32/GDI32 and emits `screenshot.skipped` instead of failing
  in headless sessions. Skipped events include the failing capture stage and
  Win32 error code when available.
- `MemoryDumpProbe` is opt-in through `--memory-dump` / `--memory-dumps`. The
  default `WindowsMiniDumpCapture` writes `MiniDumpNormal` files. It captures
  the launched sample root PID during `AfterStart`, then reuses
  `ProcessSnapshotProvider` during `AfterRun` to walk visible root/child
  processes, skip already-captured PIDs, and emit `memory_dump.sweep` summary
  evidence. Non-Windows, exited, or inaccessible targets emit
  `memory_dump.skipped` rather than failing the run.
- `PacketCaptureProbe` is opt-in through `--packet-capture` / `--pcap` /
  `--network-capture`. On Windows it uses bounded `pktmon.exe start`, `pktmon.exe
  stop`, and `pktmon.exe etl2pcap` commands to write
  `packet-captures/*.pcapng`. Missing tools, access denied, active capture
  conflicts, stop failures, and conversion failures emit
  `packet_capture.skipped` or `packet_capture.failed` instead of blocking final
  `events.json` and manifest output.
- `ProcessSampleExecutor` records `process.start_failed`,
  `process.wait_failed`, and `process.kill_failed` diagnostics for execution
  exceptions while preserving normal cancellation behavior.

## Current output artifact handling

`GuestArtifactWriter` owns `events.json`, `agent-summary.json`, and best-effort
`artifacts/manifest.json` serialization. With `--collect-dropped-files`, the
top-level agent copies `file.created` paths from the sample working directory to
`artifacts/dropped-files`, skips paths under `--out`, then writes a dropped-file
manifest with SHA-256, MIME type, safe relative link, and original guest path
metadata.

The copy step emits `artifact.dropped_file.copied` or
`artifact.dropped_file.skipped`; manifest output emits
`artifact.manifest.written` or `artifact.manifest.failed`. Dropped-file
extraction is independent from memory dump and packet capture; all three remain
disabled unless their explicit CLI flags are supplied.

## Smoke strategy

Smoke coverage should stay synthetic: verify source contracts, run the agent
against benign helper executables where available, and prefer temp directories
over committed artifacts. None of the probes require a real malicious sample,
an installed kernel driver, or administrator rights for their normal path.
