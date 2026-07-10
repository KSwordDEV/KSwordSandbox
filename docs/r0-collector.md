# R0Collector IOCTL pipeline

`guest/KSword.Sandbox.R0Collector` is the Windows user-mode sidecar that runs
inside the guest VM and drains events from `KSword.Sandbox.Driver`.

Current status:

- Opens the driver Win32 path `\\.\KSwordSandboxDriver` with `CreateFileW`.
- Issues `IOCTL_KSWORD_SANDBOX_GET_HEALTH` once after opening the device.
- Issues `IOCTL_KSWORD_SANDBOX_GET_CAPABILITIES` to record ABI version,
  capability flags, `SupportedProducerMask`, `DefaultProducerMask`, and layout
  limits before draining.
- Optionally issues `IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK` when
  `--enable-mask <mask>` is supplied, then emits the requested/effective mask.
- Issues `IOCTL_KSWORD_SANDBOX_GET_STATUS` before and after draining to capture
  queue depth, `ProducerEnableMask`, supported producer bits, and total counters.
- Issues `IOCTL_KSWORD_SANDBOX_POLL` and `IOCTL_KSWORD_SANDBOX_READ_EVENTS`
  in a one-shot or timed polling loop.
- Converts driver event records into `SandboxEvent` JSON Lines for the Guest
  Agent and Host import path.
- Keeps synthetic self-test mode (`--mock`, `--synthetic`, or `--self-test`) for
  CI/local plumbing when the unsigned/test-signed driver is not installed.
- Emits optional collector progress rows with `--heartbeat`.

## Source layout

`guest/KSword.Sandbox.R0Collector/src` is split by runtime responsibility:

- `main.cpp`: minimal `wmain` entry point.
- `Options.*`: command-line parsing and usage text.
- `JsonWriter.*`: UTF-8 conversion, JSON escaping, `SandboxEvent` JSONL writer,
  and fallback stderr output.
- `EventParser.*`: public driver ABI decoding and typed payload JSON mapping.
- `IoctlClient.*`: device open, `DeviceIoControl` wrappers, health,
  capabilities, status, producer-mask, poll, drain calls, and protocol error
  rows.
- `SyntheticMode.*`: deterministic synthetic driver-category rows for local
  plumbing tests.
- `RuntimeLoop.*`: lifecycle orchestration, heartbeat rows, timed polling loop,
  and exit-code mapping.

## Driver IOCTL contract

The public ABI is owned by:

```text
driver/KSword.Sandbox.Driver/include/KSwordSandboxDriverIoctl.h
```

Initial device names:

- NT device: `\Device\KSwordSandboxDriver`
- DOS link: `\DosDevices\KSwordSandboxDriver`
- Win32 path: `\\.\KSwordSandboxDriver`

Initial IOCTLs:

- `IOCTL_KSWORD_SANDBOX_GET_HEALTH`
  - Input: none.
  - Output: `KSWORD_SANDBOX_HEALTH_REPLY`.
  - Purpose: driver/queue health and ABI sanity check.
- `IOCTL_KSWORD_SANDBOX_POLL`
  - Input: none.
  - Output: `KSWORD_SANDBOX_POLL_REPLY`.
  - Purpose: cheap queue snapshot before drain.
- `IOCTL_KSWORD_SANDBOX_READ_EVENTS`
  - Input: optional `KSWORD_SANDBOX_READ_EVENTS_REQUEST`.
  - Output: `KSWORD_SANDBOX_READ_EVENTS_REPLY` followed by zero or more
    `KSWORD_SANDBOX_EVENT_HEADER + payload` records.
  - Purpose: consume queued R0 events.
- `IOCTL_KSWORD_SANDBOX_GET_CAPABILITIES`
  - Input: none.
  - Output: `KSWORD_SANDBOX_CAPABILITIES_REPLY`.
  - Purpose: Capability negotiation before assuming optional IOCTLs, ABI
    layout sizes, `SupportedProducerMask`, or `DefaultProducerMask`.
- `IOCTL_KSWORD_SANDBOX_GET_STATUS`
  - Input: none.
  - Output: `KSWORD_SANDBOX_STATUS_REPLY`.
  - Purpose: Queue and status counters, lifecycle state, `ProducerEnableMask`,
    `TotalEventsSuppressed`, queue capacity, high watermark, and last NTSTATUS.
- `IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK`
  - Input: `KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK_REQUEST`.
  - Output: `KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK_REPLY`.
  - Purpose: Apply an operator-selected producer mask and record requested,
    previous, effective, and supported masks.

### Capability/status/producer-mask negotiation

`R0Collector` emits `r0collector.driverCapabilities` after
`IOCTL_KSWORD_SANDBOX_GET_CAPABILITIES` succeeds. The row preserves ABI
major/minor, capability flag names, producer-mask support/names, event schema
name/version, event header version, ring capacity, reply sizes, and max payload
size for later diagnostics.

`R0Collector` emits `r0collector.driverStatus` for
`IOCTL_KSWORD_SANDBOX_GET_STATUS` before draining and again after the final drain.
These rows preserve queue depth/capacity, high watermark, `ProducerEnableMask`,
`SupportedProducerMask`, `TotalEventsEnqueued`, `TotalEventsDropped`,
`TotalEventsRead`, `TotalEventsSuppressed`, `NextSequence`, and `LastNtStatus`.

When `--enable-mask <mask>` is supplied, `R0Collector` issues
`IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK` and emits
`r0collector.driverProducerMask`. The row records the requested mask plus the
previous, effective, and supported masks and producer names returned by
`KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK_REPLY`.

When a live driver implements only the earlier health/poll/read-events subset,
newer optional negotiation calls may fail with the Win32 mapping of
`STATUS_INVALID_DEVICE_REQUEST` or `STATUS_NOT_SUPPORTED`.  The collector treats
those specific optional failures as non-fatal, emits
`r0collector.optionalIoctlUnavailable`, and continues with the compatible drain
path.

`IOCTL_KSWORD_SANDBOX_DRAIN_EVENTS` may exist as a compatibility alias in local
driver experiments, but R0Collector issues the public `READ_EVENTS` name.

## Current driver event path

The driver owns a fixed non-paged ring buffer. On load it currently queues one
typed `driver.load` self-test event with
`KSWORD_SANDBOX_EVENT_FLAG_SELF_TEST` and
`KSWORD_SANDBOX_EVENT_FLAG_DRIVER_STARTED`. `READ_EVENTS` consumes complete
records from the ring and reports drop/sequence counters.

Concrete behavior payloads are parsed by event type.  File events use
`KSWORD_SANDBOX_FILE_EVENT_PAYLOAD` and expose fields such as `operationName`,
`filePath`, `pathPresent`, `pathTruncated`, `statusHex`, `majorFunction`, and
`minorFunction`.  Process payloads expose lineage cache/replay flags, parent and
creator identifiers, bounded image paths, and command-line prefixes.  Image
payloads expose process-id/property presence, base, size, image properties, and
bounded paths.  Registry payloads expose key/value provenance, status,
value-type, value-size, and bounded key/value names.

Network events use `KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD` from the WFP/ALE
producer.  R0Collector now parses `protocolName`, `directionName`,
`addressFamilyName`, `localAddress`, `remoteAddress`, `localPort`,
`remotePort`, `processIdPresent`, `flowHandleHex`,
`transportEndpointHandleHex`, `layerIdHex`, `calloutIdHex`, and `filterIdHex`.
Address bytes are also retained as `localAddressHex` and `remoteAddressHex` for
diagnosis.

When a file/process/image/registry payload carries a bounded subject path, the
top-level `SandboxEvent.path` is set to that subject path so the WebUI live
monitor and HTML report show the relevant object instead of only
`\\.\KSwordSandboxDriver`.  Network events currently keep the device path as the
top-level path and put endpoint details under `data`.

## CLI contract

```powershell
KSword.Sandbox.R0Collector.exe `
  --device \\.\KSwordSandboxDriver `
  --out C:\Sandbox\driver-events.jsonl `
  --duration 10 `
  --poll-ms 500 `
  --enable-mask 0xffffffff `
  --heartbeat
```

Supported options:

- `--device`, `-d`: Win32 symbolic-link path for the driver device.
- `--output`, `--out`, `-o`: JSON Lines output path, or `-` for stdout.
- `--duration`, `-t`: Polling duration in seconds. `0` means one-shot open,
  health, poll, and read-events.
- `--poll-ms`, `--poll-interval`, `--poll-interval-ms`, `-p`: poll interval in
  milliseconds.
- `--enable-mask <mask>`: pass an unsigned 32-bit decimal or `0x` hexadecimal
  mask through `IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK`, then record the
  requested/effective mask in `r0collector.driverProducerMask`. The collector
  also includes the requested value in lifecycle rows for reproducibility.
- `--health`: open the live device, emit `r0collector.driverHealth`, and exit
  without polling or draining queued events.
- `--heartbeat`: emit `r0collector.heartbeat` lifecycle rows after startup, at
  each completed poll/read-events iteration, and at synthetic completion.
- `--mock`: emit synthetic process/file/registry-style rows and do not open the
  driver device.
- `--synthetic`: alias for `--mock`.
- `--self-test`: alias for `--mock`; intended for quick operator checks.

Device-unavailable behavior is explicit: the collector writes
`r0collector.deviceUnavailable` to the selected JSONL sink and exits with code
`66`.

Quick self-test without a driver:

```powershell
KSword.Sandbox.R0Collector.exe `
  --self-test `
  --heartbeat `
  --enable-mask 0x3 `
  --out -
```

## VM readiness and one-shot drain

Use `scripts/Test-R0Readiness.ps1` before a real VM run. Its default mode is
non-destructive and does not open `\\.\KSwordSandboxDriver`. It checks source
files, `.sys` git hygiene, driver readability, Authenticode status,
Administrator status, test-signing state, and read-only service state:

```powershell
.\scripts\Test-R0Readiness.ps1 `
  -DriverSysPath C:\KSwordSandbox\driver\KSword.Sandbox.Driver.sys `
  -R0CollectorPath C:\KSwordSandbox\tools\KSword.Sandbox.R0Collector.exe
```

After the signed driver service is explicitly installed and started in the VM,
verify the public health IOCTL:

```powershell
.\scripts\Test-R0Readiness.ps1 `
  -DevicePath \\.\KSwordSandboxDriver `
  -CheckDeviceHealth
```

This check succeeds only if `CreateFileW("\\.\KSwordSandboxDriver", ...)` opens
the device and `IOCTL_KSWORD_SANDBOX_GET_HEALTH` returns the public health
reply.

The readiness script also performs a default static negotiated-IOCTL contract
check before any driver load. That source/docs-only row covers
`IOCTL_KSWORD_SANDBOX_GET_CAPABILITIES`,
`IOCTL_KSWORD_SANDBOX_GET_STATUS`, and
`IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK`; it is intended to catch ABI or
runbook drift even when the signed/test-signed driver cannot be loaded. Treat
live load failures outside an intentionally isolated VM as non-fatal diagnostics
and rely on the static row plus VM logs to decide what changed.

Next verify the collector health-only CLI contract. This invokes
`R0Collector --health --out <jsonl>` and fails unless the output JSONL parses
and contains `r0collector.deviceOpened` plus `r0collector.driverHealth`:

```powershell
New-Item -ItemType Directory -Force C:\KSwordSandbox\out | Out-Null

.\scripts\Test-R0Readiness.ps1 `
  -R0CollectorPath C:\KSwordSandbox\tools\KSword.Sandbox.R0Collector.exe `
  -DevicePath \\.\KSwordSandboxDriver `
  -CheckCollectorHealth `
  -CollectorHealthOutputPath C:\KSwordSandbox\out\r0collector-health.jsonl
```

Then run a collector one-shot drain through the script:

```powershell
.\scripts\Test-R0Readiness.ps1 `
  -R0CollectorPath C:\KSwordSandbox\tools\KSword.Sandbox.R0Collector.exe `
  -DevicePath \\.\KSwordSandboxDriver `
  -DrainWithCollector `
  -CollectorOutputPath C:\KSwordSandbox\out\driver-events.jsonl
```

The drain path invokes R0Collector with `--duration 0`, so it opens the driver,
emits health/capabilities/status/poll/read-events lifecycle rows, drains any
queued driver records, and exits. A first load should normally expose the typed
driver-start heartbeat row (`driver.load`) unless another reader has already
consumed it. Older local builds may still surface the legacy
`driver.event.reserved` heartbeat.

Expected script rows for the live VM path:

- `Driver .sys git hygiene`: no `.sys` file is tracked, staged, modified, or
  unignored as a commit candidate.
- `Windows test-signing boot option`: `Passed` after `bcdedit /set
  testsigning on` and reboot for test-signed drivers.
- `Kernel service state`, `Service install`, and `Service start`: prove SCM
  registration and load when the explicit service-mutation switches are used.
- `Device IOCTL health`: proves the Win32 device can be opened and health IOCTL
  works.
- `R0Collector health`: proves `--health --out` output is valid.
- `R0Collector drain`: proves `--out --duration 0` output includes health,
  `r0collector.driverCapabilities`, at least one `r0collector.driverStatus`,
  poll, read-events, and queued driver rows.
- `r0collector.driverProducerMask`: expected when a VM operator invokes
  R0Collector with `--enable-mask <mask>` to exercise
  `IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK`.

## JSON Lines format

Every output line is a single `SandboxEvent`-compatible JSON object:

```json
{"eventType":"driver.load","source":"driver","timestamp":"2026-07-10T00:00:00.000Z","processId":1234,"path":"\\\\.\\KSwordSandboxDriver","commandLine":"KSword.Sandbox.R0Collector.exe --out C:\\Sandbox\\driver-events.jsonl","data":{"sequence":"1","driverEventTypeName":"driverLoad","flagsHex":"0x00000003","driverLoadEventName":"driver.load"}}
```

Top-level field rules:

- `eventType`: collector lifecycle/error type or normalized driver event type.
- `source`: `r0collector` for lifecycle rows, `driver` for drained R0 rows.
- `timestamp`: collector UTC timestamp for the JSONL row.
- `processId`: driver-supplied process ID when present; otherwise collector PID.
- `path`: device path for lifecycle and network rows; file, process, image,
  and registry rows use subject paths when payloads carry them.
- `commandLine`: collector invocation until process payloads add richer command
  lines.
- `data`: string-valued metadata compatible with the current host model.
  Driver rows include `eventSchemaName`, `eventSchemaVersion`, and
  `payloadSchema` when the payload category is known; mock rows use the same
  schema names so mock/live JSONL remain comparable.

The detailed JSONL contract is documented in
[`docs/r0-jsonl-schema.md`](r0-jsonl-schema.md).

## Guest Agent integration

The Guest Agent treats R0Collector as an optional sidecar:

1. When `--driver-events` is not supplied, no R0 sidecar is started.
2. When `--driver-events <jsonl>` and `--r0collector <exe>` are supplied, the
   agent starts R0Collector with:
   - `--device <driver-device>`
   - `--out <jsonl>` (or the equivalent `--output <jsonl>` alias)
   - `--duration <analysis seconds>`
   - optional `--mock`
3. After sample execution, the agent stops the sidecar and merges JSONL rows into
   `events.json`.
4. Host import then merges `events.json` plus sibling JSONL files, runs rules,
   and regenerates `report.json` / `report.html`.

## Repository hygiene

Do not commit generated native artifacts:

- `.exe`
- `.sys`
- `.pdb`
- `.obj`
- `.ilk`
- `bin/`
- `obj/`
- `x64/`

Runtime output should stay under `D:\Temp\KSwordSandbox\...`.
