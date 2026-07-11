# R0 driver core IOCTL and ABI contract

This document defines the stable kernel/user boundary owned by
`driver/KSword.Sandbox.Driver/include/KSwordSandboxDriverIoctl.h`. It is the
source of truth for future `KSword.Sandbox.R0Collector` capability negotiation.

## ABI versioning

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
- `KSWORD_SANDBOX_EVENT_SCHEMA_NAME` and `KSWORD_SANDBOX_EVENT_SCHEMA_VERSION`
  are the JSONL-visible event schema identifiers. Synthetic event-quality tests
  must preserve these fields for mock rows and stress rows so mock/live output
  remains comparable.

## Capability negotiation flow

Recommended collector startup:

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
7. Use `IOCTL_KSWORD_SANDBOX_POLL` and `IOCTL_KSWORD_SANDBOX_READ_EVENTS` for
   the event stream.

Current `CapabilityFlags` include:

- `KSWORD_SANDBOX_CAPABILITY_FLAG_GET_HEALTH`
- `KSWORD_SANDBOX_CAPABILITY_FLAG_POLL`
- `KSWORD_SANDBOX_CAPABILITY_FLAG_READ_EVENTS`
- `KSWORD_SANDBOX_CAPABILITY_FLAG_GET_CAPABILITIES`
- `KSWORD_SANDBOX_CAPABILITY_FLAG_GET_STATUS`
- `KSWORD_SANDBOX_CAPABILITY_FLAG_SET_PRODUCER_ENABLE_MASK`
- `KSWORD_SANDBOX_CAPABILITY_FLAG_QUEUE_STATUS_COUNTERS`
- `KSWORD_SANDBOX_CAPABILITY_FLAG_PRODUCER_ENABLE_BITS`
- `KSWORD_SANDBOX_CAPABILITY_FLAG_TYPED_EVENT_PAYLOADS`

## GET_HEALTH producer-mask snapshot

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

Current producer bits:

- `KSWORD_SANDBOX_PRODUCER_FLAG_DRIVER`
- `KSWORD_SANDBOX_PRODUCER_FLAG_PROCESS`
- `KSWORD_SANDBOX_PRODUCER_FLAG_IMAGE`
- `KSWORD_SANDBOX_PRODUCER_FLAG_FILE`
- `KSWORD_SANDBOX_PRODUCER_FLAG_REGISTRY`
- `KSWORD_SANDBOX_PRODUCER_FLAG_NETWORK`

The request `EnableMask` must be a subset of `SupportedProducerMask`. The driver
rejects unsupported bits with `STATUS_INVALID_PARAMETER`. Disabling a producer
suppresses future enqueue attempts for that event type and increments
`TotalEventsSuppressed`; it does not unregister kernel callbacks and does not
remove events that were already queued.

## Queue and status counters

`IOCTL_KSWORD_SANDBOX_GET_STATUS` returns `KSWORD_SANDBOX_STATUS_REPLY` with:

- `DriverState`: `KswSandboxDriverStateRunning` or
  `KswSandboxDriverStateStopping`.
- `Flags`: includes `KSWORD_SANDBOX_STATUS_FLAG_HAS_EVENTS`,
  `KSWORD_SANDBOX_STATUS_FLAG_PRODUCERS_PARTIAL`,
  `KSWORD_SANDBOX_STATUS_FLAG_PRODUCERS_ALL_DISABLED`, and
  `KSWORD_SANDBOX_STATUS_FLAG_LAST_STATUS_FAILURE`. Queue pressure and loss are
  surfaced through `KSWORD_SANDBOX_STATUS_FLAG_QUEUE_BACKPRESSURE`,
  `KSWORD_SANDBOX_STATUS_FLAG_EVENTS_DROPPED`, and
  `KSWORD_SANDBOX_STATUS_FLAG_EVENTS_SUPPRESSED`.
- `QueueCapacity`: fixed ring slot capacity.
- `QueueDepth`: currently unread event count.
- `QueueHighWatermark`: highest observed queue depth since load.
- `ProducerEnableMask` and `SupportedProducerMask`.
- `ActiveProducerMask` and `FailedProducerMask`, used to distinguish producers
  that are registered and emitting from producers that failed initialization.
- `LastNtStatus`: most recent internal initialization/producer status surfaced
  for diagnostics.
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

## Synthetic event-quality and backpressure contract

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
  `eventSchemaVersion`, `recordSize`, `payloadSize`, and payload schema names.
- Producer-mask evidence: requested/effective/supported masks, including the
  decimal and `0x` forms, plus active/failed masks from `GET_STATUS`.
- Queue pressure evidence: `QueueCapacity`, `QueueDepth`,
  `QueueHighWatermark`, `TotalEventsDropped`, `TotalEventsSuppressed`,
  `TotalEventsBackpressured`, `ProducerDroppedMask`,
  `ProducerSuppressedMask`, `ProducerBackpressureMask`, `EventsDropped`,
  `NextSequence`, and monotonic per-record `sequence` values.
- Noise evidence: malformed JSONL rows must not abort import. Host/guest readers
  should preserve malformed collector lines as `driver.parse_error` evidence for
  report import and should skip or defer partial rows for live display.
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
- `ReadinessNoDevicePolicy`: static/no-device checks must not call CSignTool,
  mutate the service, load the driver, or open `\\.\KSwordSandboxDriver`.
- `ReadinessNonFatalPolicy`: blocked unsigned collector execution, missing local
  collector binaries, and incomplete no-device ABI self-check output are warning
  diagnostics unless the operator explicitly requested live VM checks.

## IOCTL error contract

Public handlers return standard NTSTATUS values:

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

Internal producer enqueue suppression uses `STATUS_CANCELLED` from `KswPushEvent`
so producer telemetry counters do not count disabled events as queued. The public
enable-mask IOCTL itself still returns `STATUS_SUCCESS` when the mask update is
valid.
