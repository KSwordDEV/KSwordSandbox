# R0 driver core IOCTL 与 ABI 契约

中文优先范围：本文定义由 `driver/KSword.Sandbox.Driver/include/KSwordSandboxDriverIoctl.h` 拥有的稳定 kernel/user 边界，是 `KSword.Sandbox.R0Collector` capability negotiation 的事实来源。

保留命令、IOCTL name、struct/field name、flag name 的英文拼写；说明文字优先中文。

## ABI versioning（版本约束）

- Current ABI version: `KSWORD_SANDBOX_ABI_VERSION_MAJOR = 1`,
  `KSWORD_SANDBOX_ABI_VERSION_MINOR = 0`.
- `KSWORD_SANDBOX_INTERFACE_VERSION` and every current reply `Version` field use
  `KSWORD_SANDBOX_ABI_VERSION`.
- Collectors must compare the major version before assuming layout
  compatibility. Minor-version growth must be negotiated with capability flags
  and `Size` fields.
- Every request/reply starts with `Version` and `Size`. Drivers reject malformed
  request headers with `STATUS_INVALID_PARAMETER`.
- Every event record starts with `KSWORD_SANDBOX_EVENT_HEADER.Version` and
  `KSWORD_SANDBOX_EVENT_HEADER.Size`. The collector must reject rows whose
  header version is not `KSWORD_SANDBOX_EVENT_HEADER_VERSION`, whose record size
  is smaller than the header, or whose `PayloadSize` exceeds the record body.
- Every typed payload structure also starts with `Version` and `Size`; payload
  parsers must treat too-small payloads as typed-payload failures while keeping
  the common header, `sequence`, and bounded payload hex evidence.
- Collector driver rows must preserve generic payload-version aliases for every
  record: `payloadVersion`, `payloadVersionHex`, `payloadSchemaVersion`,
  `expectedPayloadVersion`, `payloadVersionStatus`, and
  `producerPayloadVersionFieldSet`. Unknown/header-only records use zero-valued
  aliases rather than omitting the keys.
- `KSWORD_SANDBOX_EVENT_SCHEMA_NAME` and `KSWORD_SANDBOX_EVENT_SCHEMA_VERSION`
  are the JSONL-visible event schema identifiers. Synthetic event-quality tests
  must preserve these fields for mock rows and stress rows so mock/live output
  remains comparable.

## Capability negotiation flow（能力协商流程）

推荐 collector 启动顺序：

1. Open `\\.\KSwordSandboxDriver`.
2. Issue `IOCTL_KSWORD_SANDBOX_GET_CAPABILITIES`.
3. If the IOCTL returns `STATUS_INVALID_DEVICE_REQUEST`, treat the driver as a
   legacy health/poll/read-only build and fall back to
   `IOCTL_KSWORD_SANDBOX_GET_HEALTH`.
4. If capabilities succeed, require ABI major version `1`, then gate optional
   calls on `CapabilityFlags`.
5. Read `SupportedProducerMask` and optionally call
   `IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK` with a subset of that mask.
6. Call `IOCTL_KSWORD_SANDBOX_GET_STATUS` for queue capacity, lifecycle state,
   enable-mask state, and total counters before or after draining events.
7. If `CapabilityFlags` includes
   `KSWORD_SANDBOX_CAPABILITY_FLAG_GET_NETWORK_STATUS`, optionally call
   `IOCTL_KSWORD_SANDBOX_GET_NETWORK_STATUS` to retrieve read-only WFP/ALE
   implementation level, layer masks, TODO mask, classify/event counters, and
   network-specific degrade reason.  This call must not register WFP objects or
   imply DNS/HTTP/TLS packet parsing support.
8. Use `IOCTL_KSWORD_SANDBOX_POLL` and `IOCTL_KSWORD_SANDBOX_READ_EVENTS` for
   the event stream.

## Installation 与 live-load 边界

The ABI contract above starts only after an operator has explicitly loaded the
driver in an isolated test VM. Installation, test-signing, service control, and
minifilter load/unload are documented in `docs/driver-install.md` and use
`scripts/Manage-SandboxDriver.ps1` for JSON status. That path intentionally
does not call CSignTool: a test-signed build must use a trusted local test
certificate, Windows test-signing mode, and a reboot after `bcdedit` changes.

Static readiness and synthetic stress checks remain no-device checks. They must
not mutate SCM state, load or unload the minifilter, open
`\\.\KSwordSandboxDriver`, call DeviceIoControl, or call CSignTool. Live
collector validation may open the device only after the explicit driver
install/start step has succeeded and the JSON status reports the expected
service/minifilter state.

当前 `CapabilityFlags` 包括：

- `KSWORD_SANDBOX_CAPABILITY_FLAG_GET_HEALTH`
- `KSWORD_SANDBOX_CAPABILITY_FLAG_POLL`
- `KSWORD_SANDBOX_CAPABILITY_FLAG_READ_EVENTS`
- `KSWORD_SANDBOX_CAPABILITY_FLAG_GET_CAPABILITIES`
- `KSWORD_SANDBOX_CAPABILITY_FLAG_GET_STATUS`
- `KSWORD_SANDBOX_CAPABILITY_FLAG_SET_PRODUCER_ENABLE_MASK`
- `KSWORD_SANDBOX_CAPABILITY_FLAG_QUEUE_STATUS_COUNTERS`
- `KSWORD_SANDBOX_CAPABILITY_FLAG_PRODUCER_ENABLE_BITS`
- `KSWORD_SANDBOX_CAPABILITY_FLAG_TYPED_EVENT_PAYLOADS`
- `KSWORD_SANDBOX_CAPABILITY_FLAG_EVENT_SCHEMA_NAMES`
- `KSWORD_SANDBOX_CAPABILITY_FLAG_PROCESS_CREATE_EXIT`
- `KSWORD_SANDBOX_CAPABILITY_FLAG_IMAGE_LOAD`
- `KSWORD_SANDBOX_CAPABILITY_FLAG_FILE_MINIFILTER`
- `KSWORD_SANDBOX_CAPABILITY_FLAG_REGISTRY_CALLBACK`
- `KSWORD_SANDBOX_CAPABILITY_FLAG_NETWORK_WFP_ALE`
- `KSWORD_SANDBOX_CAPABILITY_FLAG_EVENT_COMMON_METADATA`
- `KSWORD_SANDBOX_CAPABILITY_FLAG_PRODUCER_METADATA`
- `KSWORD_SANDBOX_CAPABILITY_FLAG_SELF_NOISE_METADATA`
- `KSWORD_SANDBOX_CAPABILITY_FLAG_GET_NETWORK_STATUS`

Draft-only flag `KSWORD_SANDBOX_CAPABILITY_FLAG_PROCESS_HANDLE_ACCESS_DRAFT`
is not included in the shared `KSWORD_SANDBOX_CAPABILITY_FLAGS_CURRENT`
baseline, but the live kernel `GET_CAPABILITIES` reply advertises it when
the process producer is compiled, `KSWORD_SANDBOX_ENABLE_PROCESS_HANDLE_ACCESS=1`,
and the guarded driver build contains the ObRegisterCallbacks producer that emits
`KSWORD_SANDBOX_PROCESS_HANDLE_ACCESS_EVENT_PAYLOAD_V1_DRAFT`. Runtime
registration success/failure is reported through the separate
`KSWORD_SANDBOX_PRODUCER_FLAG_PROCESS_HANDLE_ACCESS` active/failed producer bit
and `LastNtStatus`; the normal process producer bit can still remain active for
process create/exit callbacks.

Draft-only flag `KSWORD_SANDBOX_CAPABILITY_FLAG_TOKEN_PRIVILEGE_DRAFT` remains
reserved and is not advertised by the current driver. Until a signed driver
build advertises that bit with matching payloads, token privilege adjustment is
an ETW/audit fallback lane in the collector contract.

## Producer runtime state 与 payload 版本

Each v1 event producer owns an explicit runtime state structure in the driver
source instead of scattering loose callback globals:

- process: `KSWORD_SANDBOX_PROCESS_MONITOR_RUNTIME`
- image: `KSWORD_SANDBOX_IMAGE_MONITOR_RUNTIME`
- registry: `KSWORD_SANDBOX_REGISTRY_MONITOR_RUNTIME`
- file: `KSWORD_SANDBOX_FILE_FILTER_RUNTIME`
- network: `KSWORD_SANDBOX_NETWORK_WFP_RUNTIME`

Initialization validates the shared device extension signature before a producer
can publish callbacks, stores the v1 payload version in runtime state, and keeps
registration/start status for health diagnostics. Teardown clears `Active` before
unregistering callbacks, uses `Uninitializing` guards for idempotent unload paths,
and drops stale device-extension pointers before the control device is deleted.

Current typed payload versions are fixed at `0x00010000` for process, image,
registry, file, and network v1 layouts. Those values are producer-stamped on
emitted records. The driver and collector both compile-time guard that every
typed payload starts with `Version` at offset 0 and `Size` at offset 4;
`--abi-self-check` emits the matching `*PayloadVersion`, `*PayloadVersionHex`,
`*PayloadVersionOffset`, and `*PayloadSizeOffset` fields so no-device readiness
can detect drift before a live driver is opened. Future field growth must use a
new negotiated version or an explicit draft/successor structure; it must not
silently change the existing v1 layout.

Additional compile-time ABI guards now pin the fixed capability, producer-mask,
and READ_EVENTS negotiation structures (`KSWORD_SANDBOX_CAPABILITIES_REPLY`,
`KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK_*`, and
`KSWORD_SANDBOX_READ_EVENTS_*`) on both the driver and collector sides. The
collector self-check exposes their key offsets (`capabilities*Offset`,
`setProducerEnableMaskReply*Offset`, `readEventsBytesWrittenOffset`,
`readEventsNextSequenceOffset`) as no-device evidence.

The network producer also exposes a separate
`KSWORD_SANDBOX_NETWORK_STATUS_REPLY` through
`IOCTL_KSWORD_SANDBOX_GET_NETWORK_STATUS`.  That reply is status metadata, not
an event payload.  It intentionally keeps network readiness diagnostics outside
`KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD` so the v1 event layout remains stable
while operators can still inspect WFP/ALE setup progress and known gaps.

V1 typed payload checklist:

- file: `KSWORD_SANDBOX_FILE_EVENT_PAYLOAD`,
  `KSWORD_SANDBOX_FILE_EVENT_VERSION`, size 128 bytes.
- process lifecycle: `KSWORD_SANDBOX_PROCESS_EVENT_PAYLOAD`,
  `KSWORD_SANDBOX_PROCESS_EVENT_VERSION`, size 128 bytes.
- process/thread handle access draft:
  `KSWORD_SANDBOX_PROCESS_HANDLE_ACCESS_EVENT_PAYLOAD_V1_DRAFT`,
  `KSWORD_SANDBOX_PROCESS_HANDLE_ACCESS_EVENT_VERSION`, size 128 bytes. This
  payload is emitted only by the guarded ObRegisterCallbacks producer and uses
  process event operations `HandleCreateDraft` / `HandleDuplicateDraft`.
- image: `KSWORD_SANDBOX_IMAGE_EVENT_PAYLOAD`,
  `KSWORD_SANDBOX_IMAGE_EVENT_VERSION`, size 128 bytes.
- registry: `KSWORD_SANDBOX_REGISTRY_EVENT_PAYLOAD`,
  `KSWORD_SANDBOX_REGISTRY_EVENT_VERSION`, size 128 bytes.
- network: `KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD`,
  `KSWORD_SANDBOX_NETWORK_EVENT_VERSION`, size 112 bytes.

Each payload comment in `KSwordSandboxDriverIoctl.h` states that `Version` must
match the corresponding `KSWORD_SANDBOX_*_EVENT_VERSION` constant and `Size`
must match `sizeof(the payload structure)` for the fixed v1 layout.

## `GET_HEALTH` producer-mask snapshot

`IOCTL_KSWORD_SANDBOX_GET_HEALTH` remains the legacy fixed-size probe, but the
ABI 1.0 reserved space now carries a compact producer health snapshot for
collectors that only perform a health check before deciding whether to issue
newer status IOCTLs:

- `ProducerEnableMask`: current event-emission mask.
- `SupportedProducerMask`: mask of producer bits accepted by the driver.
- `ActiveProducerMask`: producers that registered successfully and may emit.
- `FailedProducerMask`: producers that failed initialization and require
  diagnostics through `LastNtStatus` and `IOCTL_KSWORD_SANDBOX_GET_STATUS`.

The driver sets `KSWORD_SANDBOX_HEALTH_FLAG_PRODUCER_MASKS_AVAILABLE` when these
fields are populated. The fields reuse previous `Reserved` bytes, so
`sizeof(KSWORD_SANDBOX_HEALTH_REPLY)` stays stable for older collectors; older
collectors that still ignore the reserved area remain compatible.

## Producer enable mask

`IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK` accepts
`KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK_REQUEST` and returns
`KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK_REPLY`.

当前 producer bits：

- `KSWORD_SANDBOX_PRODUCER_FLAG_DRIVER`
- `KSWORD_SANDBOX_PRODUCER_FLAG_PROCESS`
- `KSWORD_SANDBOX_PRODUCER_FLAG_IMAGE`
- `KSWORD_SANDBOX_PRODUCER_FLAG_FILE`
- `KSWORD_SANDBOX_PRODUCER_FLAG_REGISTRY`
- `KSWORD_SANDBOX_PRODUCER_FLAG_NETWORK`
- `KSWORD_SANDBOX_PRODUCER_FLAG_PROCESS_HANDLE_ACCESS`

`SupportedProducerMask` is now derived from the compiled producer set.  The
normal build includes all producer bits.  A lab build can define
`KSWORD_SANDBOX_ENABLE_NETWORK_WFP_ALE=0`; in that case the network bit and the
`NETWORK_WFP_ALE` capability are intentionally omitted rather than advertised as
a fake/stub success.

The guarded process/thread handle-access producer emits
`KswSandboxEventTypeProcess` records, but it has its own producer bit:
`KSWORD_SANDBOX_PRODUCER_FLAG_PROCESS_HANDLE_ACCESS`. This keeps operator
enable masks and `ActiveProducerMask` / `FailedProducerMask` precise when
process create/exit callbacks succeed but `ObRegisterCallbacks` fails. The
distinct payload contract is still the draft payload version plus
`KSWORD_SANDBOX_CAPABILITY_FLAG_PROCESS_HANDLE_ACCESS_DRAFT` in the live
capability reply.

`KSWORD_SANDBOX_PRODUCER_MASK_DEFAULT` intentionally excludes the draft
`processHandleAccess` bit even when the build supports it. This keeps the MVP
live default from overloading the fixed R0 ring with global handle-open noise.
Operators can still opt in with `SET_PRODUCER_ENABLE_MASK` / R0Collector
`--enable-mask 0x7f`; reports should treat default-disabled handle telemetry as
an explicit R0/ETW coverage boundary, not as proof that no handle access
occurred.

The request `EnableMask` must be a subset of `SupportedProducerMask`. The driver
rejects unsupported bits with `STATUS_INVALID_PARAMETER`. Disabling a producer
suppresses future enqueue attempts for that event type and increments
`TotalEventsSuppressed`; it does not unregister kernel callbacks and does not
remove events that were already queued.

## Queue 与 status counters

`IOCTL_KSWORD_SANDBOX_GET_STATUS` returns `KSWORD_SANDBOX_STATUS_REPLY` with:

- `DriverState`: `KswSandboxDriverStateRunning` or
  `KswSandboxDriverStateStopping`.
- `Flags`: includes `KSWORD_SANDBOX_STATUS_FLAG_HAS_EVENTS`,
  `KSWORD_SANDBOX_STATUS_FLAG_PRODUCERS_PARTIAL`,
  `KSWORD_SANDBOX_STATUS_FLAG_PRODUCERS_ALL_DISABLED`, and
  `KSWORD_SANDBOX_STATUS_FLAG_LAST_STATUS_FAILURE`. Queue pressure and loss are
  surfaced through `KSWORD_SANDBOX_STATUS_FLAG_QUEUE_BACKPRESSURE`,
  `KSWORD_SANDBOX_STATUS_FLAG_EVENTS_DROPPED`, and
  `KSWORD_SANDBOX_STATUS_FLAG_EVENTS_SUPPRESSED`.  Producer registration
  degradation is also surfaced through
  `KSWORD_SANDBOX_STATUS_FLAG_PRODUCERS_DEGRADED`.
- `QueueCapacity`: fixed ring slot capacity.
- `QueueDepth`: currently unread event count.
- `QueueHighWatermark`: highest observed queue depth since load.
- `ProducerEnableMask` and `SupportedProducerMask`.
- `ActiveProducerMask` and `FailedProducerMask`, used to distinguish producers
  that are registered and emitting from producers that failed initialization.
- `EffectiveProducerMask`: active producers after the operator enable mask is
  applied (`ActiveProducerMask & ProducerEnableMask`).
- `LastNtStatus`: public sticky diagnostic status.  A producer failure is not
  hidden by a later successful producer initialization.
- `LastFailureNtStatus`: sticky failure status preserved separately from
  ordinary success paths.
- `TotalEventsEnqueued`: successful enqueue count.
- `TotalEventsDropped`: overwrite count when the ring was full.
- `TotalEventsRead`: records returned through `READ_EVENTS`.
- `TotalEventsSuppressed`: records skipped by disabled producer bits.
- `TotalEventsBackpressured`: records accepted while the queue was at or above
  the backpressure threshold.
- `ProducerDroppedMask`, `ProducerSuppressedMask`, and
  `ProducerBackpressureMask`: producer-family bitmasks that explain which
  producers caused loss, operator suppression, or high queue pressure.
- `NextSequence`: oldest unread event sequence, or the next sequence that will
  be assigned when the queue is empty.

Legacy `GET_HEALTH` and `POLL` remain fixed-size compatibility calls. New queue
capacity and total counters are intentionally exposed through `GET_STATUS` so old
collectors do not need larger health/poll output buffers.

## Network WFP/ALE status diagnostics

`IOCTL_KSWORD_SANDBOX_GET_NETWORK_STATUS` returns
`KSWORD_SANDBOX_NETWORK_STATUS_REPLY` when the control device is loaded.  The
call is read-only and bounded: it does not open a WFP engine transaction, add
filters, change producer enable masks, sign the driver, start a service, or
drain events.

The reply gives readiness gates stronger evidence than the coarse producer masks
alone:

- `ImplementationLevel`: current build scope, presently ALE inspect-only.
- `Flags`: compiled/active/degraded/inspect-only plus queue/payload failure
  bits.
- `SupportedLayerMask`: the supported ALE connect and recv-accept IPv4/IPv6
  layers.
- `LastRegisteredCalloutMask` and `LastAddedFilterMask`: partial WFP setup
  progress retained after a non-fatal initialization failure.
- `ActiveLayerMask`: layers currently active for classify callbacks.
- `TodoMask`: explicit remaining network scope gaps, including packet/stream
  WFP layers, flow contexts, protocol/address filter conditions, and in-driver
  DNS/HTTP/TLS payload parsing.
- `LastDegradeReason`, `LastDegradeNtStatus`, `RegisterNtStatus`, and
  `EngineNtStatus`: setup and runtime diagnostics.
- `ClassifyCount`, `EventCount`, `QueueFailureCount`, and
  `ClassifyPayloadFailureCount`: runtime counters for stress/readiness triage.

This reduces the network readiness blind spot without redefining the v1 R0
network event as a packet sensor.  Reports should still merge richer protocol
semantics from Guest/PCAP imports.

## Synthetic event-quality 与 backpressure 契约

The event ring is bounded and non-blocking. The default capacity is 1024 records,
with build-time guard rails of 64..4096 slots. Producers must not wait on
user-mode collector throughput. When the queue reaches the backpressure
threshold, `TotalEventsBackpressured` and `ProducerBackpressureMask` preserve
pressure evidence. When the ring is full, the oldest unread record may be
overwritten, `TotalEventsDropped` and `ProducerDroppedMask` increase, and
collectors can also derive loss from `EventsDropped`, `NextSequence`, and
per-event `sequence` gaps. This is the R0 backpressure contract: preserve
evidence of pressure/loss instead of blocking kernel callbacks or hiding
overflow.

Synthetic tests and manual stress runs should model all of the following without
loading a real driver:

- ABI evidence: `Version`, `Size`, `KSWORD_SANDBOX_EVENT_HEADER_VERSION`,
  `KSWORD_SANDBOX_EVENT_SCHEMA_VERSION`, `eventSchemaName`,
  `eventSchemaVersion`, `recordSize`, `payloadSize`, `payloadSchema`,
  `payloadVersion`, `payloadVersionHex`, `payloadSchemaVersion`, and the
  `producerPayloadVersionFieldSet` name list.
- Producer-mask evidence: requested/effective/supported masks, including the
  decimal and `0x` forms, plus active/failed masks from `GET_STATUS`.
- Queue pressure evidence: `QueueCapacity`, `QueueDepth`,
  `QueueHighWatermark`, `TotalEventsDropped`, `TotalEventsSuppressed`,
  `TotalEventsBackpressured`, `ProducerDroppedMask`,
  `ProducerSuppressedMask`, `ProducerBackpressureMask`, `EventsDropped`,
  `NextSequence`, and monotonic per-record `sequence` values.
- Noise evidence: malformed JSONL rows must not abort import. Host/guest readers
  should preserve malformed collector lines as `driver.parse_error` evidence for
  report import and should skip or defer partial rows for live display. Stress
  and mock rows name `StressJsonlNoiseEvidence` so importers know which
  `noise*`, `collectorNoise*`, `selfNoise*`, behavior-counting, and
  `sampleBehaviorCandidate` fields must survive noisy corpora.
- Behavior-counting evidence: collector lifecycle, readiness, capabilities,
  batch summary, ABI self-check, IOCTL failure/protocol error, optional-IOCTL,
  and network-status-unavailable rows must explicitly emit
  `behaviorCounted=false` and `nonbehavior=true`. Driver rows that are not
  collector/producer self-noise emit `behaviorCounted=true`; emitted self-noise
  audit rows emit `behaviorCounted=false`.
- Stress-field evidence: live driver rows still emit stable stress keys with
  non-stress defaults (`stress=false`, `stressOrdinal=-1`,
  `stressCorpusRole=live-driver-event`) so live, mock, and counted stress JSONL
  can be compared by field name.
- Stress inputs: use mock JSONL plus bounded collector knobs such as
  `--max-events`, `--max-read-batches`, `--duration 0`, `--poll-ms`, and
  `--heartbeat` to prove high-volume drain behavior without CSignTool, service
  mutation, or loading the driver.

Operator readiness gates should expose the same evidence with stable field
names so stress failures are diagnosable without loading a real driver:

- `StressJsonlExpectedDriverRows`: expected driver-row count in the synthetic
  stress corpus.
- `StressJsonlSequenceStart`, `StressJsonlSequenceEnd`, and
  `StressJsonlSequenceGapCount`: bounded sequence range and gap count for the
  generated JSONL rows.
- `StressJsonlLossEvidence`: `TotalEventsDropped`, `totalEventsDropped`,
  `EventsDropped`, `eventsDropped`, `NextSequence`, `nextSequence`, and
  per-record `sequence`.
- `StressJsonlBackpressureEvidence`: `QueueCapacity`, `queueCapacity`,
  `QueueHighWatermark`, `queueHighWatermark`, `drainStoppedAtBatchLimit`,
  `requestedMaxEvents`, `readEventsMaxEvents`, and `maxReadBatches`.
- `StressJsonlNoiseEvidence`: the noise/self-noise metadata field set that must
  remain present on stress summaries, mock markers, and explicit valid
  extra-field noise rows.
- `ReadinessNoDevicePolicy`: static/no-device checks must not call CSignTool,
  mutate the service, load the driver, or open `\\.\KSwordSandboxDriver`.
- `ReadinessNonFatalPolicy`: blocked unsigned collector execution, missing local
  collector binaries, and incomplete no-device ABI self-check output are warning
  diagnostics unless the operator explicitly requested live VM checks.

## IOCTL error contract

Public handlers 返回标准 NTSTATUS 值：

- `STATUS_SUCCESS`: request completed; `IoStatus.Information` contains the
  number of bytes written.
- `STATUS_INVALID_DEVICE_REQUEST`: unknown IOCTL, including new capability IOCTLs
  on older drivers.
- `STATUS_BUFFER_TOO_SMALL`: required fixed output or input header did not fit.
- `STATUS_INVALID_USER_BUFFER`: METHOD_BUFFERED system buffer was unexpectedly
  unavailable.
- `STATUS_DEVICE_NOT_READY`: the device extension signature was missing or
  invalid.
- `STATUS_INVALID_PARAMETER`: request `Version`, `Size`, reserved `Flags`, or
  producer bits failed contract validation.

`IOCTL_KSWORD_SANDBOX_GET_NETWORK_STATUS` follows the same fixed-buffer rules:
`STATUS_BUFFER_TOO_SMALL` for undersized output, `STATUS_INVALID_USER_BUFFER`
for a missing METHOD_BUFFERED buffer, and `STATUS_DEVICE_NOT_READY` if the
control device extension is not valid.

Internal producer enqueue suppression uses `STATUS_CANCELLED` from `KswPushEvent`
so producer telemetry counters do not count disabled events as queued. The public
enable-mask IOCTL itself still returns `STATUS_SUCCESS` when the mask update is
valid.
