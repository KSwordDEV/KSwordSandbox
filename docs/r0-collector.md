# R0Collector IOCTL pipeline

`guest/KSword.Sandbox.R0Collector` is the Windows user-mode sidecar that runs
inside the guest VM and drains events from `KSword.Sandbox.Driver`.

Canonical scope: this page owns collector CLI/runtime/readiness integration.
The kernel/user ABI source of truth is `docs/r0-driver-core.md`, JSONL field
schema is `docs/r0-jsonl-schema.md`, and driver install/test-signing operator
steps live in `docs/driver-install.md`.

中文说明：`R0Collector` 是 guest VM 内的用户态 sidecar，负责通过 public
IOCTL 从内核驱动读取事件并写出 JSONL。所有 `eventType`、JSON key、
`diagnosticCode`、`reason`、`readinessState` 等机器字段保持英文稳定值；
中文只作为附加 `zhMessage`、`zhHint`、`zhNote`、`zh*Policy` 字段出现。

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
- Supports `--diagnose` / `--readiness` / `--readiness-check` for live, non-
  mutating readiness output after the service is expected to be installed and
  started in a VM. This mode emits `r0collector.readinessDiagnostic` and
  `r0collector.readinessSummary` rows with `severity`, `readinessState`,
  `diagnosticStage`, and `diagnosticCode` fields so service missing, device open
  denied/not found, ABI mismatch, READ_EVENTS timeout, and no-event conditions
  are not collapsed into a generic informational unavailable row.
  中文：这些就绪行是“采集健康诊断”，不是样本行为。新增中文字段仅帮助操
  作者理解下一步排查，不能替代稳定 code。
- Issues `IOCTL_KSWORD_SANDBOX_POLL` and `IOCTL_KSWORD_SANDBOX_READ_EVENTS`
  in a one-shot or timed polling loop.
- Converts driver event records into `SandboxEvent` JSON Lines for the Guest
  Agent and Host import path.
- Suppresses narrow collector/GuestAgent self-noise by default before JSONL
  emission: collector PID, the exact collector output JSONL, and documented
  KSword infrastructure paths. Suppressed records stay accountable through
  `r0collector.driverReadEvents.data.collectorSuppressedEvents` and
  `r0collector.stopped.data.collectorSuppressedEvents`.
- Keeps synthetic self-test mode (`--mock`, `--synthetic`, or `--self-test`) for
  CI/local plumbing when the unsigned/test-signed driver is not installed.
- Emits optional collector progress rows with `--heartbeat`.

## Source layout

`guest/KSword.Sandbox.R0Collector/src` is split by runtime responsibility:

中文：源码按职责拆分；中文化只添加显示/诊断文本，不改变 IOCTL 协议、
事件类型或字段名。

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
- `ReadinessDiagnostics.*`: live `--diagnose` orchestration, read-only SCM
  service inspection, device-unavailable classification, ABI compatibility
  probe, bounded overlapped `READ_EVENTS` timeout probe, and readiness summary
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
    `ActiveProducerMask`, `FailedProducerMask`, `EffectiveProducerMask`,
    `TotalEventsSuppressed`, `TotalEventsBackpressured`, producer
    dropped/suppressed/backpressure masks, queue capacity, high watermark,
    `LastNtStatus`, and `LastFailureNtStatus`.
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
size for later diagnostics.  `capabilityFlagNames` covers every current
capability bit including `ProcessCreateExit`, `ImageLoad`, `FileMinifilter`,
`RegistryCallback`, `NetworkWfpAle`, `EventCommonMetadata`,
`ProducerMetadata`, and `SelfNoiseMetadata`; the row also emits boolean
`*Capable` fields for those capabilities.

`R0Collector` emits `r0collector.driverStatus` for
`IOCTL_KSWORD_SANDBOX_GET_STATUS` before draining and again after the final drain.
These rows preserve queue depth/capacity, high watermark, `ProducerEnableMask`,
`SupportedProducerMask`, `ActiveProducerMask`, `FailedProducerMask`,
`EffectiveProducerMask`, `TotalEventsEnqueued`, `TotalEventsDropped`,
`TotalEventsRead`, `TotalEventsSuppressed`, `TotalEventsBackpressured`,
`ProducerDroppedMask`, `ProducerSuppressedMask`, `ProducerBackpressureMask`,
`NextSequence`, `LastNtStatus`, and `LastFailureNtStatus`.  The JSON field names
are `activeProducerMask`,
`activeProducerMaskHex`,
`activeProducerMaskNames`, `failedProducerMask`, `failedProducerMaskHex`, and
`failedProducerMaskNames`; `effectiveProducerMask`, `effectiveProducerMaskHex`,
`effectiveProducerMaskNames`, `lastFailureNtStatus`, and
`lastFailureNtStatusHex` mirror the newly populated status fields. Producer
loss masks also emit decimal, hex, and name forms.

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
Synthetic `driver.network` rows and the valid extra-field JSONL noise row use
the same `sourceEndpoint`, `destinationEndpoint`, and `flowKey` names so
no-device stress runs exercise the report correlation contract before WFP is
loaded.

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

中文：CLI help 现在按英文 / 中文并列输出；flag 名、枚举值和路径参数不翻
译，方便脚本和 smoke tests 继续匹配。

- `--device`, `-d`: Win32 symbolic-link path for the driver device.
- `--output`, `--out`, `-o`: JSON Lines output path, or `-` for stdout.
- `--duration`, `-t`: Polling duration in seconds. `0` means one-shot open,
  health, poll, and read-events.
- `--poll-ms`, `--poll-interval`, `--poll-interval-ms`, `-p`: poll interval in
  milliseconds.
- `--diagnose`, `--readiness`, `--readiness-check`: run a live non-mutating
  readiness diagnostic pass. The collector queries SCM state for `--service-name`,
  opens the device, checks `GET_CAPABILITIES` ABI compatibility, emits
  health/status rows, and runs a bounded `READ_EVENTS` probe without installing,
  starting, stopping, or signing the driver.
- `--service-name <name>`: kernel service name used by `--diagnose` service
  diagnostics. Default is `KSwordSandboxDriver`.
- `--read-timeout-ms <ms>` / `--diagnose-read-timeout-ms <ms>`: timeout for the
  `--diagnose` overlapped `READ_EVENTS` probe. Default is `2000`.
- `--max-events <count>`: cap each `READ_EVENTS` request to 1..1024 events.
  Use small values in synthetic stress checks to prove batching and sequence
  continuity.
- `--max-read-batches <n>`: stop draining after `n` successful READ_EVENTS
  batches; `0` means unlimited until the duration deadline or an empty batch.
  This is the bounded batch limit and stress/backpressure input for safe local
  tests.
- `--driver-event-sample-stride <n>` / `--event-sample-stride <n>`: optional
  collector-side large-stream throttle for live driver rows. The default `1`
  emits every eligible driver row. Values greater than `1` emit the first
  eligible row and every nth eligible row after self-noise suppression; skipped
  rows remain counted in `r0collector.driverReadEvents.data.skipped` and
  `collectorSkippedEvents`.
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
- `--suppress-self-noise`: default live-driver policy. Suppress driver rows for
  the collector PID, the exact collector output JSONL, and known KSword
  infrastructure paths before writing JSONL.
- `--emit-self-noise` / `--no-suppress-self-noise`: diagnostic override that
  emits those rows with `selfNoise=true`, `selfNoiseReason`, and
  `selfNoiseAction=emit`.
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
`66`. The row now includes `severity=error`, `readinessState=blocked`,
`diagnosticStage=openDevice`, and a concrete `diagnosticCode` such as
`open_device_not_found`, `open_device_denied`, `open_device_sharing_violation`,
or `open_device_failed`. It also records `deviceAvailability=unavailable`,
`collectionDiagnostic=true`, `sampleBehavior=false`, `ioctlIssued=false`,
`driverLoadedByCollector=false`, `mutatesDriver=false`,
`sideEffectPolicy=read-only-open-no-driver-load-no-scm-mutation-no-signing`,
and `operatorInterpretation=collection_diagnostic_not_sample_behavior` so a
missing or inaccessible device is clearly a collection/readiness issue rather
than evidence of malicious sample behavior.

中文：设备不可用时，`message`/`hint` 保留英文原文，同时新增
`zhMessage`/`zhHint`。排查顺序通常是服务是否安装并运行、设备符号链接是
否创建、Collector 是否提权、驱动和 Collector ABI 是否匹配。

Live readiness diagnostic after a driver is expected to be installed and
started:

```powershell
KSword.Sandbox.R0Collector.exe `
  --diagnose `
  --service-name KSwordSandboxDriver `
  --device \\.\KSwordSandboxDriver `
  --read-timeout-ms 2000 `
  --out C:\Sandbox\r0collector-readiness.jsonl
```

Expected diagnostic rows:

- `r0collector.readinessDiagnostic` with `diagnosticStage=service`. Codes include
  `missing_service`, `service_not_running`, `service_query_denied`, and
  `service_running`.
- `r0collector.deviceUnavailable` when `CreateFileW` fails. `win32Error` and
  `win32Message` are preserved, and the hint distinguishes service/load/symbolic-
  link problems from permission failures. The row is marked
  `collectionDiagnostic=true` and `sampleBehavior=false`.
- `r0collector.readinessDiagnostic` with `diagnosticStage=abiNegotiation`. Codes
  include `abi_compatible`, `abi_capabilities_unavailable`,
  `abi_ioctl_failed`, and `abi_mismatch`.
- `r0collector.readinessDiagnostic` with `diagnosticStage=readEvents`. Codes
  include `read_timeout`, `read_ioctl_failed`, `read_protocol_error`,
  `driver_no_events`, and `read_events_ready`.
- `r0collector.readinessSummary` with `ready`, `degraded`, `severity`,
  `readinessState`, `failedStage`, `serviceDiagnosticCode`,
  `openDeviceDiagnosticCode`, `abiDiagnosticCode`, and
  `readEventsDiagnosticCode`.

中文：每条 `readinessDiagnostic` 都会保留 `hint` 并附加 `zhHint`；
`readinessSummary` 会附加 `zhMessage`/`zhHint`，提示是否阻塞、降级或可
继续采集。不要翻译 `missing_service`、`abi_mismatch`、`read_timeout` 等
诊断 code。

`driver_no_events` is a warning/degraded condition rather than a protocol
failure: `READ_EVENTS` completed, but the queue was empty. It usually means the
startup heartbeat was already drained or producers have not observed sample
activity. `read_timeout`, `abi_mismatch`, `open_device_denied`, and
`open_device_not_found` are hard blocked readiness states.

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

- `r0collector.started` and `r0collector.mockDriverEvent` rows with
  `stressCount`, `stress=true`, and the `StressJsonl*` field set so automation
  can verify the intended corpus before scanning all rows.
- 32 `driver.file` rows with `stress=true`.
- `sequence` range `1200..1231` and `StressJsonlSequenceGapCount=0`.
- a mock `r0collector.driverReadEvents` summary with
  `recordsProcessed`/`eventsEmitted`, `processed`/`eligible`/`emitted`,
  `suppressed`/`skipped`, `head`/`tail`, `sampling`, `sequenceMeaning`,
  `lostCount`, `lossObserved`, `highWatermark`, `backpressure`,
  `backpressureObserved`, and `backpressureReason`.
- loss/backpressure fields such as `totalEventsDropped`, `queueHighWatermark`,
  `readEventsMaxEvents`, `maxReadBatches`, and `lastEnqueueFailureStatus`.
- one blank line, one malformed JSON row, and one valid extra-field row when
  `--inject-jsonl-noise` is supplied.

Lightweight attribution/self-noise smoke without a driver:

```powershell
$out = Join-Path $env:TEMP 'ksword-r0-self-test-noise.jsonl'
KSword.Sandbox.R0Collector.exe `
  --self-test `
  --heartbeat `
  --emit-self-noise `
  --inject-jsonl-noise `
  --out $out

$rows = Get-Content $out | Where-Object { $_.Trim() } | ForEach-Object {
  try { $_ | ConvertFrom-Json -ErrorAction Stop } catch { $null }
}
$driverRows = $rows | Where-Object source -eq 'driver'
$driverRows | Where-Object { $_.data.eventOrigin -and $_.data.subjectKind } |
  Measure-Object
```

Expected: the process exits `0`, one intentionally malformed line fails JSON
parsing, and every parsed synthetic driver row has `eventOrigin`,
`producerCategory`, `subjectKind`, `processIdSource`, and `selfNoise` fields.

### JSONL quality and noise contract

Every collector-owned row keeps the event-quality fields stable under `data`:

- `schema` mirrors `eventSchemaName` (`ksword.sandbox.r0.event`) for compact
  downstream checks.
- `producer` names the row family (`r0collector`, `file`, `process`, `image`,
  `registry`, or `network`).
- `noise` is `false` for normal rows. It is `true` for the valid synthetic
  extra-field row emitted by `--inject-jsonl-noise` and for self-noise rows only
  when the operator explicitly uses `--emit-self-noise`.
- `selfNoise`, `collectorNoise`, `collectorSelfNoise`, `selfProcess`,
  `selfNoiseReason`, `selfNoiseAction`, `collectorNoisePolicy`, and
  `collectorSuppressed` explain collector/KSword infrastructure attribution.
  With the default suppression policy those noisy driver rows are not emitted;
  counts remain in `collectorSuppressedEvents`.
- `eventOrigin`, `producerCategory`, `subjectKind`, `processIdSource`,
  `actorRole`, and `subjectRole` make driver-row ownership readable without
  relying on report-generation heuristics.
- `sequence` is a concrete driver event sequence on driver rows and a
  `nextSequence` alias on snapshot/summary rows. Snapshot rows set
  `sequenceMeaning=nextSequence` so reports do not confuse a future sequence
  with an already delivered event.
- `lost` is `true` only when the row itself reports drop/loss counters;
  `lostCount` preserves the numeric drop count and `lossObserved` mirrors the
  boolean loss classification. Delivered driver rows keep `lost=false` and use
  `sequence` plus status/read counters for gap analysis.
- `highWatermark` is the stable JSONL alias for
  `QueueHighWatermark`/`queueHighWatermark`; rows without a live queue snapshot
  emit `0` rather than omitting the field in mock/schema smoke output.
- `backpressure` / `backpressureObserved` are set on status/read rows when the
  queue reached capacity, a batch filled the requested cap, or drop counters are
  non-zero. `backpressureReason` carries the machine-readable reason such as
  `events-dropped`, `requested-max-events-reached`, `output-buffer-full`, or
  `none`. Synthetic stress rows keep `backpressure=false` but name the
  `StressJsonlBackpressureEvidence` field set.
- `r0collector.driverReadEvents` keeps both old and concise batch counters near
  the front of `data`: `recordsProcessed`, `eventsEmitted`,
  `collectorSuppressedEvents`, `collectorSkippedEvents`, `eligibleEvents`, plus
  aliases `processed`, `eligible`, `emitted`, `suppressed`, `skipped`,
  `head`, `tail`, `sampling`, `loss`, `lossObserved`,
  `backpressureObserved`, and `backpressureReason`. This order is deliberate so
  host report sampling keeps the important accounting fields even when raw JSONL
  contains many additional diagnostics.
- `collectionDiagnostic=true`, `sampleBehavior=false`, and
  `operatorInterpretation=collection_diagnostic_not_sample_behavior` are used
  on device/readiness/IOCTL diagnostic rows to separate collector health from
  sample activity.

Malformed-line handling is deliberate and bounded. The collector emits only
valid JSONL unless `--inject-jsonl-noise` is explicitly requested in mock/stress
mode. That option appends exactly one blank line, one truncated/malformed JSON
object containing the `sequence=broken` marker, and one valid `driver.network`
row with an ignored extra top-level field plus `noise=true`. Live readers skip
blank/malformed rows so valid telemetry remains visible; host import preserves
malformed rows as `driver.parse_error` evidence rather than hiding them.

Self-noise suppression is also bounded. It is intentionally not a broad process
trust decision: the collector suppresses only the current collector PID, the
exact JSONL file it is writing, and documented KSword infrastructure path
fragments such as `\KSwordSandbox\agent\`, `\KSwordSandbox\r0collector\`,
`\KSwordSandbox\driver\`, and `\KSwordSandbox\out\`. Drain-loop continuation is
based on `recordsProcessed`, not emitted row count, so suppressing a full noisy
batch cannot make the collector stop before the driver queue is empty.
Optional stride sampling is applied only after this self-noise classification;
it is disabled by default and never changes `recordsProcessed`.

## ABI self-check mode

Use `--abi-self-check` before a signed/test-signed driver is available, before
VM image bake, or in CI where loading a kernel driver is intentionally forbidden:

```powershell
KSword.Sandbox.R0Collector.exe `
  --abi-self-check `
  --heartbeat `
  --max-events 16 `
  --max-read-batches 4 `
  --driver-event-sample-stride 1 `
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
- `schema`, `producer`, `noise`, `selfNoise`, `collectorSelfNoise`,
  `selfProcess`, `selfNoiseReason`, `lost`, `backpressure`, and
  `stableJsonlFields`: prove the collector binary knows the stable event-quality
  field names used by live, mock, stress, and noise rows.
- `eventHeaderSize`, `healthReplySize`, `capabilitiesReplySize`,
  `statusReplySize`, `readEventsRequestSize`, `readEventsReplyHeaderSize`, and
  payload-size fields: capture fixed structure layout assumptions used by the
  collector parser.
- `requestedMaxEvents`, `readEventsMaxEvents`, `maxEventsBounds`,
  `maxReadBatches`, `driverEventSampleStride`, and
  `driverEventSamplingPolicy`: capture the batch/backpressure/sampling knobs
  the run will use. The default sample stride is `1`, meaning no collector-side
  driver-row sampling.
- `readEventsRequestFlagsPolicy`: documents that `READ_EVENTS.Flags` must remain
  zero.
- `producerSelectionPolicy`: documents that producer selection belongs only to
  `IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK`.
- `jsonlNoisePolicy`: documents that blank live rows are ignored, malformed
  imported rows must remain visible as `driver.parse_error`, and valid rows with
  extra fields are tolerated.
- `jsonlMalformedPolicy`: documents that malformed output is produced only by
  the explicit noise injector and must remain visible to import as parse-error
  evidence.
- `kernelBackpressurePolicy`: documents the non-blocking kernel ring behavior:
  producers do not wait for the collector; overflow overwrites the oldest unread
  record.
- `queueLossEvidence`: names the diagnostic fields that must be preserved for
  lost-record analysis: `TotalEventsDropped`, `EventsDropped`,
  `TotalEventsSuppressed`, `TotalEventsBackpressured`, `ProducerDroppedMask`,
  `ProducerSuppressedMask`, `ProducerBackpressureMask`, `NextSequence`,
  per-event `sequence`, and `QueueHighWatermark`.

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
- `processed`/`eligible`/`emitted`/`suppressed`/`skipped`,
  `head`/`tail`, `sampling`, `loss`, and `backpressureObserved` on
  `r0collector.driverReadEvents`: preserve batch accounting and sequence
  bounds in both raw JSONL and sampled reports.
- `drainStoppedAtBatchLimit` on `r0collector.stopped`: indicates the runtime
  loop exited because `--max-read-batches` was reached instead of waiting for
  the duration deadline.

## JSON Lines format

Every output line is a single `SandboxEvent`-compatible JSON object:

中文：JSONL 仍保持单行一个 `SandboxEvent`。`data` 里所有值按字符串写出；
新增中文字段也遵守这一规则。Host/Report 可以展示 `zhMessage`/`zhHint`，
但规则匹配和聚合仍应使用英文稳定字段。

```json
{"eventType":"driver.load","source":"driver","timestamp":"2026-07-10T00:00:00.000Z","processId":1234,"processName":"","path":"\\\\.\\KSwordSandboxDriver","commandLine":"","data":{"sequence":"1","driverEventTypeName":"driverLoad","producerCategory":"driver","eventOrigin":"kernel-driver-control-plane","subjectKind":"driver","processIdSource":"eventHeader","selfNoise":"false","flagsHex":"0x00000003","driverLoadEventName":"driver.load","zhDriverLoadEventDescription":"..."}}
```

Top-level field rules:

- `eventType`: collector lifecycle/error type or normalized driver event type.
- `source`: `r0collector` for lifecycle rows, `driver` for drained R0 rows.
- `timestamp`: collector UTC timestamp for the JSONL row.
- `processId`: typed payload subject PID when present; otherwise the driver
  event header PID. `data.processIdSource` names which source won.
- `processName`: populated only when the payload provides a process image. It is
  empty on driver rows that cannot safely name the owning process; lifecycle
  rows still name the collector executable.
- `path`: device path for lifecycle rows. File, process, image, and registry
  rows use subject paths when payloads carry them; network rows use a URI-like
  remote endpoint when decoded.
- `commandLine`: lifecycle rows use the collector invocation. Live driver rows
  keep this empty unless a typed process payload carries a command-line prefix.
- `data`: string-valued metadata compatible with the current host model.
  Driver rows include `eventSchemaName`, `eventSchemaVersion`, and
  `payloadSchema` when the payload category is known; mock rows use the same
  schema names and attribution fields so mock/live JSONL remain comparable.

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
  `TotalEventsBackpressured`/`totalEventsBackpressured`,
  `ProducerDroppedMask`/`producerDroppedMask`,
  `ProducerSuppressedMask`/`producerSuppressedMask`,
  `ProducerBackpressureMask`/`producerBackpressureMask`, `nextSequence`, and
  per-driver-row `sequence` plus read-batch `head`/`tail`, `loss`, and
  `backpressureObserved` so lost records can be diagnosed from counters and
  gaps.
- Noise evidence: blank, truncated, malformed, and extra-field JSONL rows are
  expected in the corpus. Import keeps malformed rows as `driver.parse_error`;
  live display skips or defers bad partial rows without dropping valid rows.
- Attribution/self-noise evidence: mock and ABI self-check rows preserve
  `eventOrigin`, `producerCategory`, `subjectKind`, `processIdSource`,
  `selfNoise`, `collectorSelfNoise`, `selfProcess`, `selfNoiseReason`,
  `collectorNoisePolicy`, and
  `collectorSuppressedEvents` field names so no-device smoke can validate the
  readable ownership contract.
- Mock/stress inputs: use `--self-test`, `--synthetic`, `--mock`,
  `--stress-count`, `--inject-jsonl-noise`, `--abi-self-check`,
  `--max-events`, `--max-read-batches`, `--duration 0`, `--poll-ms`, and
  `--driver-event-sample-stride`, and `--heartbeat` to exercise bounded drains,
  no-device ABI evidence, JSONL tolerance, sequence continuity, optional
  collector sampling, and heartbeat evidence.

Backpressure is intentionally non-blocking. Kernel producers should not wait on
collector throughput. If the fixed ring overflows, the oldest unread records can
be overwritten and the collector must surface the loss through
`TotalEventsDropped`, `EventsDropped`, `ProducerDroppedMask`, `NextSequence`,
and `sequence` gaps. If the ring is merely under pressure but not yet full,
`TotalEventsBackpressured` and `ProducerBackpressureMask` identify the producer
families observed while the queue was above the threshold.

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
  `eventsDropped`, `ProducerDroppedMask`, `producerDroppedMask`,
  `NextSequence`, `nextSequence`, per-driver-row `sequence`, batch `head`,
  batch `tail`, and `loss`.
- `StressJsonlBackpressureEvidence`: the queue-pressure fields that prove
  non-blocking behavior: `QueueCapacity`, `queueCapacity`,
  `QueueHighWatermark`, `queueHighWatermark`, `TotalEventsBackpressured`,
  `totalEventsBackpressured`, `ProducerBackpressureMask`,
  `producerBackpressureMask`, `drainStoppedAtBatchLimit`, `requestedMaxEvents`,
  `readEventsMaxEvents`, `maxReadBatches`, `backpressureObserved`, and
  `sampling`.
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
