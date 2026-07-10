# Guest Agent behavior events

The guest agent runs inside the analysis VM and keeps the existing command-line
contract:

```text
--sample <path> --out <directory> [--duration <seconds>] [--driver-events <path>]
```

Optional R0 sidecar flags extend the contract without changing the existing
arguments:

```text
[--r0collector <path>] [--driver-device <path>] [--r0-mock]
```

Optional screenshot capture is disabled by default and can be enabled with:

```text
[--screenshot]
```

It writes the primary JSON artifacts under `--out`:

- `events.json` - ordered `SandboxEvent` entries collected in the guest.
- `agent-summary.json` - compact run metadata with sample path, event count, and
  generation time.
- `screenshots/*.bmp` - optional desktop screenshots when `--screenshot` is
  supplied and the guest session exposes a capturable desktop.
- `artifacts/manifest.json` - optional dropped-file manifest when the guest
  writer is asked to index files below `--out\artifacts`.

`artifacts/manifest.json` uses `ArtifactManifest` from
`KSword.Sandbox.Abstractions.Artifacts`. Each entry records `kind:
DroppedFile`, `name`, `relativePath`, `sizeBytes`, optional `sha256`, and
metadata such as `origin=guest`, `evidenceRole=dropped-file`, and the original
guest full path. The manifest intentionally uses relative paths so the host can
resolve copied files under its collected guest-output directory without trusting
VM-local absolute paths.

## Event coverage

The current guest collector emits these host-reportable event groups:

- `agent.start` / `agent.stop` for collector lifecycle.
- `environment.snapshot` before sample launch, including OS description, user,
  machine name, current directory, selected sample working directory, and
  process/OS architecture.
- `process.observed` for the pre-launch process list baseline.
- `process.start`, `process.timeout`, and `process.exit` for the launched
  sample process.
- `process.new` for processes visible after sample launch or after the run that
  were not present in the pre-launch baseline.
- `process.tree` for the launched sample process and visible descendants. The
  event includes `ParentProcessId` plus `rootProcessId` and `treeDepth` in
  `Data` so reports can reconstruct a low-privilege process tree without WMI or
  administrator rights.
- `file.created`, `file.modified`, and `file.deleted` for files changed under
  the sample working directory. File delta events include `root`,
  `relativePath`, `sizeBytes`/`lastWriteUtc`, and previous values for modified
  or deleted files when available.
- `network.tcp` for new TCP connections visible in the post-run TCP snapshot.
  Each event keeps the legacy `connection` string and also includes structured
  `local`, `remote`, `state`, `localAddress`, `localPort`, `remoteAddress`, and
  `remotePort` fields in `Data`; `change=opened` marks the delta direction.
- `network.tcp.closed` for baseline TCP connections that disappeared by the
  post-run snapshot. These events use the same endpoint fields with
  `change=closed`.
- `screenshot.captured` when `--screenshot` successfully writes a desktop BMP.
  The event path points at the BMP file and `Data` includes `phase`,
  `widthPixels`, and `heightPixels`.
- `screenshot.skipped` when screenshot capture was requested but the platform or
  guest session cannot expose a desktop surface. This is non-fatal and keeps
  smoke tests usable on headless hosts.
- Driver JSONL events from `--driver-events`, preserving driver-provided fields
  and defaulting missing sources to `driver`.
- `r0collector.start_failed` if the optional sidecar process could not be
  created. This event is emitted by the agent and does not fail the whole run.
- `r0collector.stop_forced` / `r0collector.stop_failed` only when the agent had
  to terminate the sidecar or could not finish sidecar shutdown cleanly.

The event model remains `KSword.Sandbox.Abstractions.SandboxEvent`; additional
details are carried in the existing string `Data` dictionary to avoid changing
shared Core/Web/Abstractions contracts.

Dropped files are represented in the artifact manifest rather than embedded in
`events.json`. File behavior events can still reference the path that triggered
the evidence, while `artifacts/manifest.json` is the durable evidence chain for
the copied bytes, hash, and relative host-collectable location.

## Optional R0Collector sidecar

When both `--r0collector <path>` and `--driver-events <jsonl>` are supplied, the
agent starts `KSword.Sandbox.R0Collector.exe` before launching the sample. The
sidecar is invoked with:

```text
--device <driver-device> --output <driver-events> --duration <duration>
```

`--driver-device` defaults to `\\.\KSwordSandboxDriver` when omitted. Supplying
`--r0-mock` makes the agent forward `--mock` to the sidecar, which allows local
or CI plumbing tests without an installed kernel driver.

After the sample exits or times out, the agent waits briefly for the sidecar to
exit. If it is still running, the agent terminates the sidecar process tree so
the JSONL file can be closed and read. The agent then reads `--driver-events`
and merges those JSONL rows into `events.json`.

If the sidecar executable is missing, cannot be started, or the JSONL parent
directory cannot be prepared, the agent adds `r0collector.start_failed` to the
guest events and continues with normal user-mode collection.

## Optional screenshots

`--screenshot` enables best-effort BMP capture during `after-start` and
`after-run` probe phases. The implementation uses User32/GDI32 APIs directly so
it does not need external packages or administrator rights. In non-interactive
sessions, capture may be unavailable; the agent then emits `screenshot.skipped`
with a reason instead of failing the analysis.

Screenshots are intentionally opt-in because they can contain sensitive desktop
state and can be noisy in automated VM runs. Future host policies should decide
whether to forward `--screenshot` per job.

## Driver JSONL compatibility

Driver sidecars such as `KSword.Sandbox.R0Collector` should write one
`SandboxEvent`-compatible JSON object per line. The guest agent reads these
events case-insensitively, so both `eventType` and `EventType` are accepted.

The current shared model keeps `Data` as `Dictionary<string,string>`. Driver
JSONL producers must therefore serialize values inside `data` as strings, for
example:

```json
{"eventType":"registry.set","source":"driver","processId":4242,"path":"HKCU\\Software\\Run","data":{"value":"C:\\sample.exe","win32Error":"0"}}
```

Top-level numeric fields such as `processId` may remain JSON numbers.
