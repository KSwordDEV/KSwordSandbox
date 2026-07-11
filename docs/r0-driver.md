# R0 Driver producer deepening

Scope: `driver/KSword.Sandbox.Driver/**` only. This note records the R0 producer split and the event metadata contract expected by the collector path.

## Producer layout

The driver now keeps each public producer family in an explicit source/header pair:

- Process: `src/Producers/Process/ProcessMonitor.c` + `ProcessMonitor.h`
- Image: `src/Producers/Image/ImageMonitor.c` + `ImageMonitor.h`
- File: `src/Producers/File/FileFilter.c` + `FileFilter.h`
- Registry: `src/Producers/Registry/RegistryMonitor.c` + `RegistryMonitor.h`
- Network: `src/Producers/Network/NetworkMonitor.c` + `NetworkMonitor.h`

Process create/exit and image-load callbacks are intentionally separate producers. `ActiveProducerMask`/`FailedProducerMask` can therefore report a partial process-vs-image bring-up instead of treating both callbacks as one unit.

## Common event metadata

`KSWORD_SANDBOX_EVENT_HEADER` keeps the original v1.0 prefix through `Reserved` and appends common metadata for all producer families:

- target `ProcessId`, `ParentProcessId`, and current callback `ThreadId`
- `Operation` and `Status`
- `TimestampQpc`, `TimestampSystemTime`, and monotonic `Sequence`
- cumulative `LostEvents` and `BackpressureEvents`
- `ProducerId` and `ProducerMetadataFlags`

Typed payloads still carry source-specific details such as process image path, image path, file path, registry key/value, and network tuple. Header flags mark which common fields are meaningful (`*_PRESENT`) so collectors can tolerate absent status/path data.

Self-noise is reserved in the common metadata contract with `KSWORD_SANDBOX_EVENT_FLAG_SELF_NOISE` and `KSWORD_SANDBOX_EVENT_METADATA_FLAG_SELF_NOISE`. Current file self-noise filtering may suppress known KSword infrastructure paths before enqueue; if a future producer chooses to emit them, the marker is available without another header expansion.

## Event queue stress and backpressure status

The R0 queue remains a fixed, non-blocking ring. Producers never wait for user mode; when the ring is full, enqueue overwrites the oldest unread record and increments the cumulative lost counter. Backpressure is advisory: once depth reaches `KSWORD_SANDBOX_EVENT_RING_BACKPRESSURE_THRESHOLD` (75% of `KSWORD_SANDBOX_EVENT_RING_CAPACITY`), enqueue increments `TotalEventsBackpressured` and marks the producer family in `ProducerBackpressureMask`.

Collectors can query stress/backpressure state through `IOCTL_KSWORD_SANDBOX_GET_STATUS` without changing the v1.0 fixed reply size:

- `TotalEventsDropped` / `TotalEventsLost`: cumulative lost count for overwritten or internally discarded unread records.
- `QueueHighWatermark`: maximum ring depth observed since driver initialization.
- `TotalEventsBackpressured`: number of enqueue operations observed at or above the backpressure threshold.
- `ProducerDroppedMask`, `ProducerSuppressedMask`, `ProducerBackpressureMask`: producer-family evidence for loss, enable-mask suppression, and backpressure.
- `LastFailureNtStatus` / `LastEnqueueFailureNtStatus`: sticky status for the last failed enqueue-related path, including validation failures such as `STATUS_BUFFER_TOO_SMALL` or producer-mask suppression (`STATUS_CANCELLED`). The two names alias the same v1.0 status slot to preserve ABI stability.

Each emitted `KSWORD_SANDBOX_EVENT_HEADER` also snapshots `LostEvents` and `BackpressureEvents` at enqueue time and sets `KSWORD_SANDBOX_EVENT_FLAG_LOST_COUNT_PRESENT` / `KSWORD_SANDBOX_EVENT_FLAG_BACKPRESSURE_COUNT_PRESENT` when those counters are non-zero.

`Sequence` is assigned only after producer enable-mask validation succeeds and immediately before inserting the event into the ring. It is monotonically increasing for successfully enqueued records and is not reused after overflow. Gaps between drained records therefore mean records were lost, skipped by a `StartingSequence` read, or discarded by ring corruption guards; collectors should combine sequence gaps with `LostEvents`, `TotalEventsDropped`/`TotalEventsLost`, and `NextSequence` when reporting loss.

## Enable mask, health, and capabilities

`KSWORD_SANDBOX_COMPILED_PRODUCER_MASK` is derived from per-producer build switches:

- `KSWORD_SANDBOX_ENABLE_PROCESS_CREATE`
- `KSWORD_SANDBOX_ENABLE_IMAGE_LOAD`
- `KSWORD_SANDBOX_ENABLE_FILE_MINIFILTER`
- `KSWORD_SANDBOX_ENABLE_REGISTRY_CALLBACK`
- `KSWORD_SANDBOX_ENABLE_NETWORK_WFP_ALE`

`GET_CAPABILITIES` advertises only compiled producer capability bits plus common metadata capability bits. Runtime registration failures remain visible through `GET_HEALTH`/`GET_STATUS` masks and NTSTATUS fields.

## Verification

Build without signing or CSignTool:

```powershell
& 'D:\Software\VS\MSBuild\Current\Bin\MSBuild.exe' `
  'D:\Projects\KswordSandbox\driver\KSword.Sandbox.Driver\KSword.Sandbox.Driver.vcxproj' `
  /p:Configuration=Debug /p:Platform=x64 /p:SignMode=Off /m:1 /v:minimal
```
