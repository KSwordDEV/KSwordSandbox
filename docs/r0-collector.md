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
  queue depth, `ProducerEnableMask`, `ActiveProducerMask`,
  `FailedProducerMask`, supported producer bits, and total counters.
- Supports `--abi-self-check` / `--contract-self-check` for no-device ABI and
  event-quality self-check output. This mode emits `r0collector.abiSelfCheck`,
  records `collectorAbiVersion`, `capabilityFlagsCurrentHex`,
  `producerMaskCurrentHex`, `jsonlNoisePolicy`, `kernelBackpressurePolicy`, and
  `queueLossEvidence`, then exits before `CreateFileW` or `DeviceIoControl`.
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
- `AbiSelfCheck.*`: no-device ABI/event-quality self-check row for CI and
  operator preflight runs before the driver is installed.
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
  - Request `Flags` is reserved and must be zero. Producer selection is not
    accepted on this IOCTL; use `IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK`.
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
    `ActiveProducerMask`, `FailedProducerMask`, `TotalEventsSuppressed`, queue
    capacity, high watermark, and last NTSTATUS.
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
`SupportedProducerMask`, `ActiveProducerMask`, `FailedProducerMask`,
`TotalEventsEnqueued`, `TotalEventsDropped`, `TotalEventsRead`,
`TotalEventsSuppressed`, `NextSequence`, and `LastNtStatus`.  The JSON field
names are `activeProducerMask`, `activeProducerMaskHex`,
`activeProducerMaskNames`, `failedProducerMask`, `failedProducerMaskHex`, and
`failedProducerMaskNames`.

The active/failed producer masks are published without an ABI minor bump by
using the previously unused reserved/alignment space in
`KSWORD_SANDBOX_STATUS_REPLY`; the reply `Size` stays unchanged for ABI 1.0
collectors.  Older drivers that zeroed that reserved space surface both masks as
zero, while newer drivers fill them explicitly.

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
`remotePort`, `localEndpoint`, `remoteEndpoint`, `sourceEndpoint`,
`destinationEndpoint`, `flowKey`, `transportProtocol`, `servicePort`,
`serviceHint`, `semanticCandidate`, DNS/HTTP/TLS candidate booleans,
`processIdPresent`, `flowHandleHex`, `transportEndpointHandleHex`,
`layerIdHex`, `calloutIdHex`, and `filterIdHex`. Address bytes are also
retained as `localAddressHex` and `remoteAddressHex` for diagnosis.

When a file/process/image/registry payload carries a bounded subject path, the
top-level `SandboxEvent.path` is set to that subject path so the WebUI live
monitor and HTML report show the relevant object instead of only
`\\.\KSwordSandboxDriver`.  Network events use a URI-like top-level path such as
`tcp://203.0.113.10:443` when the remote endpoint is decoded, while full
endpoint and flow correlation details stay under `data`.

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
- `--max-events <count>`: cap each `READ_EVENTS` request to 1..1024 events.
  Use small values in synthetic stress checks to prove batching and sequence
  continuity.
- `--max-read-batches <n>`: stop draining after `n` successful READ_EVENTS
  batches; `0` means unlimited until the duration deadline or an empty batch.
  This is the bounded batch limit and stress/backpressure input for safe local
  tests.
- `--abi-self-check`: emit an ABI/event-quality contract row and exit without
  opening `\\.\KSwordSandboxDriver`. The collector does not open the driver
  device and does not call `DeviceIoControl` in this mode.
- `--contract-self-check`: alias for `--abi-self-check`.
- `--enable-mask <mask>`: pass an unsigned 32-bit decimal or `0x` hexadecimal
  mask through `IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK`, then record the
  requested/effective mask in `r0collector.driverProducerMask`. The collector
  also includes the requested value in lifecycle rows for reproducibility. This
  mask is never copied into `KSWORD_SANDBOX_READ_EVENTS_REQUEST.Flags`.
- `--health`: open the live device, emit `r0collector.driverHealth`, and exit
  without polling or draining queued events.
- `--heartbeat`: emit `r0collector.heartbeat` lifecycle rows after startup, at
  each completed poll/read-events iteration, and at synthetic completion.
- `--mock`: emit synthetic process/file/registry-style rows and do not open the
  driver device.
- `--synthetic`: alias for `--mock`.
- `--self-test`: alias for `--mock`; intended for quick operator checks.
- `--stress-count <n>`: emit `n` contiguous synthetic `driver.file` rows with
  `stress=true`, `sequence`, `StressJsonlExpectedDriverRows`,
  `StressJsonlSequenceStart`, `StressJsonlSequenceEnd`,
  `StressJsonlSequenceGapCount`, loss evidence, and backpressure evidence. This
  option implies `--mock`, never opens the driver, and is intended to move the
  event-quality/stress corpus into the shipped collector binary instead of only
  C# fixtures.
- `--inject-jsonl-noise`: in mock/stress mode, append a blank line, malformed
  JSON row, and valid row with an ignored extra top-level field. This proves the
  Host live/import path can tolerate partial JSONL without hiding valid rows.

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

Quick event-quality stress without a driver:

```powershell
KSword.Sandbox.R0Collector.exe `
  --stress-count 32 `
  --inject-jsonl-noise `
  --heartbeat `
  --out C:\Sandbox\r0collector-stress.jsonl
```

Expected stress evidence:

- 32 `driver.file` rows with `stress=true`.
- `sequence` range `1200..1231` and `StressJsonlSequenceGapCount=0`.
- loss/backpressure fields such as `totalEventsDropped`, `queueHighWatermark`,
  `readEventsMaxEvents`, and `maxReadBatches`.
- one blank line, one malformed JSON row, and one valid extra-field row when
  `--inject-jsonl-noise` is supplied.

## ABI self-check mode

Use `--abi-self-check` before a signed/test-signed driver is available, before
VM image bake, or in CI where loading a kernel driver is intentionally forbidden:

```powershell
KSword.Sandbox.R0Collector.exe `
  --abi-self-check `
  --heartbeat `
  --max-events 16 `
  --max-read-batches 4 `
  --enable-mask 0x3f `
  --out C:\Sandbox\r0collector-abi-self-check.jsonl
```

The mode emits normal `r0collector.started` / optional heartbeat rows, then a
single `r0collector.abiSelfCheck` row followed by `r0collector.stopped` with
`reason=abiSelfCheckComplete`. It does not open `\\.\KSwordSandboxDriver`, does
not require Administrator, and does not issue `DeviceIoControl`; it is purely a
collector/header contract check.

Important `r0collector.abiSelfCheck` evidence fields:

- `selfCheckPassed`, `opensDriverDevice`, `ioctlIssued`: prove this was a
  no-device source/ABI self-check instead of a live driver drain.
- `collectorAbiVersion`, `collectorAbiVersionHex`, `abiVersionMajor`,
  `abiVersionMinor`, `eventHeaderVersion`, `eventSchemaName`, and
  `eventSchemaVersion`: prove the collector binary was compiled against the
  expected public ABI/schema version.
- `capabilityFlagsCurrentHex`, `producerMaskCurrentHex`,
  `producerMaskDefaultHex`, and producer/capability name fields: prove the
  collector knows the current process/image/file/registry/network producer
  families and optional IOCTL capability bits.
- `eventHeaderSize`, `healthReplySize`, `capabilitiesReplySize`,
  `statusReplySize`, `readEventsRequestSize`, `readEventsReplyHeaderSize`, and
  payload-size fields: capture fixed structure layout assumptions used by the
  collector parser.
- `requestedMaxEvents`, `readEventsMaxEvents`, `maxEventsBounds`, and
  `maxReadBatches`: capture the batch/backpressure knobs the run will use.
- `readEventsRequestFlagsPolicy`: documents that `READ_EVENTS.Flags` must remain
  zero.
- `producerSelectionPolicy`: documents that producer selection belongs only to
  `IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK`.
- `jsonlNoisePolicy`: documents that blank live rows are ignored, malformed
  imported rows must remain visible as `driver.parse_error`, and valid rows with
  extra fields are tolerated.
- `kernelBackpressurePolicy`: documents the non-blocking kernel ring behavior:
  producers do not wait for the collector; overflow overwrites the oldest unread
  record.
- `queueLossEvidence`: names the diagnostic fields that must be preserved for
  lost-record analysis: `TotalEventsDropped`, `EventsDropped`,
  `TotalEventsSuppressed`, `NextSequence`, per-event `sequence`, and
  `QueueHighWatermark`.

Treat `--abi-self-check` as a cheap preflight. It proves the collector and public
headers agree about ABI/event-quality assumptions, but it does not prove that the
driver service is installed, signed, loaded, or returning live events.

## VM readiness and one-shot drain

Use `scripts/Test-R0Readiness.ps1` before a real VM run. Its default mode is
non-destructive and does not open `\\.\KSwordSandboxDriver`. It checks source
files, `.sys` git hygiene, driver readability, Authenticode status,
Administrator status, test-signing state, read-only service state, and a
no-device `R0Collector ABI self-check` when the collector executable exists:

```powershell
.\scripts\Test-R0Readiness.ps1 `
  -DriverSysPath C:\KSwordSandbox\driver\KSword.Sandbox.Driver.sys `
  -R0CollectorPath C:\KSwordSandbox\tools\KSword.Sandbox.R0Collector.exe
```

The readiness script invokes the collector as
`--abi-self-check --out <CollectorAbiSelfCheckOutputPath>` in default mode. It
does not pass `--device`, does not open the driver object, does not issue
`DeviceIoControl`, does not load the service, and does not call `CSignTool`.
If Windows endpoint policy blocks the unsigned collector executable, the script
reports that row as a `Warning` / non-fatal readiness gap instead of interrupting
the rest of the readiness output.

Use `-CollectorAbiSelfCheckOutputPath <path>` when the VM image bake or CI job
needs the JSONL evidence in a stable location:

```powershell
.\scripts\Test-R0Readiness.ps1 `
  -R0CollectorPath C:\KSwordSandbox\tools\KSword.Sandbox.R0Collector.exe `
  -CollectorAbiSelfCheckOutputPath C:\KSwordSandbox\out\r0collector-abi-self-check.jsonl
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
- `requestedMaxEvents` on `r0collector.driverReadEvents`: records the exact
  `READ_EVENTS` batch cap used for that collector run.
- `drainStoppedAtBatchLimit` on `r0collector.stopped`: indicates the runtime
  loop exited because `--max-read-batches` was reached instead of waiting for
  the duration deadline.

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

## Synthetic event-quality and backpressure contract

R0Collector event quality is validated with synthetic JSONL before any real
driver load. These tests do not call CSignTool, mutate the service, or open
`\\.\KSwordSandboxDriver`; they generate collector-shaped rows and feed them
through host/live JSONL readers.

Required synthetic coverage:

- ABI structure version evidence: capabilities and driver rows preserve
  `version`, `versionHex`, ABI major/minor, `eventHeaderVersion`,
  `eventSchemaName`, `eventSchemaVersion`, `recordSize`, `payloadSize`, and
  `payloadSchema`.
- Producer-mask evidence: lifecycle/status rows include requested, previous,
  effective, supported, active, and failed masks. `READ_EVENTS.Flags` remains
  zero; producer selection belongs to
  `IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK`.
- Queue overflow/loss evidence: status and batch rows include
  `QueueHighWatermark`/`queueHighWatermark`, `TotalEventsDropped`/
  `totalEventsDropped`, `eventsDropped`, `TotalEventsSuppressed`,
  `nextSequence`, and per-driver-row `sequence` so lost records can be
  diagnosed from counters and gaps.
- Noise evidence: blank, truncated, malformed, and extra-field JSONL rows are
  expected in the corpus. Import keeps malformed rows as `driver.parse_error`;
  live display skips or defers bad partial rows without dropping valid rows.
- Mock/stress inputs: use `--self-test`, `--synthetic`, `--mock`,
  `--stress-count`, `--inject-jsonl-noise`, `--abi-self-check`,
  `--max-events`, `--max-read-batches`, `--duration 0`, `--poll-ms`, and
  `--heartbeat` to exercise bounded drains, no-device ABI evidence, JSONL
  tolerance, sequence continuity, and heartbeat evidence.

Backpressure is intentionally non-blocking. Kernel producers should not wait on
collector throughput. If the fixed ring overflows, the oldest unread records can
be overwritten and the collector must surface the loss through
`TotalEventsDropped`, `EventsDropped`, `NextSequence`, and `sequence` gaps.

## R0Collector stress/readiness operator gate

The R0 readiness gate is deliberately split into no-device checks and live-VM
checks.  The default gate must remain safe for developer laptops and CI: it does
not call `CSignTool`, does not load or unload the service, does not mutate SCM
state, and does not open `\\.\KSwordSandboxDriver`.  Live device, collector
health, and one-shot drain checks require explicit operator switches after the
driver has already been installed and started in an isolated VM.

Required no-device gate evidence:

- `R0 capability/status IOCTL static contract`: source/docs-only row proving the
  negotiated IOCTL names, collector JSONL rows, and non-fatal optional-IOCTL
  strategy are still documented.
- `R0Collector event-quality static contract`: source/docs-only row proving the
  mock/stress/noise/backpressure contract is present before any driver load.
- `R0Collector ABI self-check`: optional runtime row produced with
  `--abi-self-check --out <CollectorAbiSelfCheckOutputPath>`.  Missing,
  unsigned, or policy-blocked collector execution is a `Warning` and a
  non-fatal readiness gap, not a hard stop for the rest of the static output.

The operator gate treats the following synthetic stress fields as named
contract evidence.  The exact values can change per scenario, but the names must
stay stable in docs, the readiness script, and smoke tests:

- `StressJsonlExpectedDriverRows`: expected number of generated driver stress
  rows in the mock JSONL corpus.  The current smoke corpus expects 32
  `driver.file` rows.
- `StressJsonlSequenceStart` and `StressJsonlSequenceEnd`: first and last
  driver `sequence` values used to prove the corpus has a bounded expected
  sequence range.
- `StressJsonlSequenceGapCount`: expected gap count inside the synthetic stress
  corpus.  It should be `0` for the clean mock corpus; live VM drains can report
  non-zero gaps when queue-loss counters also prove overflow.
- `StressJsonlLossEvidence`: the loss fields that must be preserved in JSONL:
  `TotalEventsDropped`, `totalEventsDropped`, `EventsDropped`,
  `eventsDropped`, `NextSequence`, `nextSequence`, and per-driver-row
  `sequence`.
- `StressJsonlBackpressureEvidence`: the queue-pressure fields that prove
  non-blocking behavior: `QueueCapacity`, `queueCapacity`,
  `QueueHighWatermark`, `queueHighWatermark`, `drainStoppedAtBatchLimit`,
  `requestedMaxEvents`, `readEventsMaxEvents`, and `maxReadBatches`.
- `ReadinessNoDevicePolicy`: default readiness emits only static/no-device
  evidence and must set `OpensDevice=false`, `LoadsDriver=false`, and
  `CallsCSignTool=false` for the ABI self-check row.
- `ReadinessNonFatalPolicy`: endpoint policy blocks, missing local collector
  binaries, and incomplete ABI self-check JSONL are warnings unless the operator
  requested a live device or live drain check.

When a live VM drain is explicitly requested, the readiness output should record
the JSONL output path, non-blank line count, event types, parse-error count,
driver row count, sequence first/last/gap evidence, and any observed loss or
backpressure fields.  A pass requires parseable JSONL plus the documented
health/capabilities/status/poll/read-events rows; a stress-readiness report is
not allowed to hide malformed rows, loss counters, or backpressure indicators.

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
