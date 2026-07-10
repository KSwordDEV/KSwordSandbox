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
  `KSWORD_SANDBOX_STATUS_FLAG_LAST_STATUS_FAILURE`.
- `QueueCapacity`: fixed ring slot capacity.
- `QueueDepth`: currently unread event count.
- `QueueHighWatermark`: highest observed queue depth since load.
- `ProducerEnableMask` and `SupportedProducerMask`.
- `LastNtStatus`: most recent internal initialization/producer status surfaced
  for diagnostics.
- `TotalEventsEnqueued`: successful enqueue count.
- `TotalEventsDropped`: overwrite count when the ring was full.
- `TotalEventsRead`: records returned through `READ_EVENTS`.
- `TotalEventsSuppressed`: records skipped by disabled producer bits.
- `NextSequence`: oldest unread event sequence, or the next sequence that will
  be assigned when the queue is empty.

Legacy `GET_HEALTH` and `POLL` remain fixed-size compatibility calls. New queue
capacity and total counters are intentionally exposed through `GET_STATUS` so old
collectors do not need larger health/poll output buffers.

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
