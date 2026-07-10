# Ksword5.1 driver protocol reuse checklist

Date: 2026-07-10

Scope: source/header review only. No binaries, certificates, samples, build
outputs, or whole-repository copies are part of this checklist.

## Current sandbox boundary

Current public ABI lives in:

- `driver/KSword.Sandbox.Driver/include/KSwordSandboxDriverIoctl.h`

Important existing facts:

- Device path is sandbox-specific: `\\.\KSwordSandboxDriver`.
- IOCTL device type is sandbox-specific: `KSWORD_SANDBOX_DEVICE_TYPE` is
  `0x8000U`.
- Existing IOCTLs:
  - `IOCTL_KSWORD_SANDBOX_GET_HEALTH`
  - `IOCTL_KSWORD_SANDBOX_POLL`
  - `IOCTL_KSWORD_SANDBOX_READ_EVENTS`
- Existing event framing:
  - `KSWORD_SANDBOX_EVENT_HEADER`
  - `KSWORD_SANDBOX_READ_EVENTS_REQUEST`
  - `KSWORD_SANDBOX_READ_EVENTS_REPLY`
- The current collector opens the device and issues health, poll, and
  read-events IOCTLs through `KSwordSandboxDriverIoctl.h`.

Implication: reuse Ksword5.1 protocol shapes and parser patterns, but rename
them into the sandbox ABI. Do not import KswordARK device names, IOCTL numbers,
or the full shared header graph.

## Key files read

Ksword5.1 reference files:

- `D:\Projects\Ksword5.1\shared\driver\KswordArkFileMonitorIoctl.h`
- `D:\Projects\Ksword5.1\shared\driver\KswordArkNetworkIoctl.h`
- `D:\Projects\Ksword5.1\shared\driver\KswordArkFileIoctl.h`
- `D:\Projects\Ksword5.1\shared\driver\KswordArkProcessIoctl.h`
- `D:\Projects\Ksword5.1\shared\KswordArkLogProtocol.h`
- `D:\Projects\Ksword5.1\Ksword5.1\Ksword5.1\ArkDriverClient\ArkDriverClient.h`
- `D:\Projects\Ksword5.1\Ksword5.1\Ksword5.1\ArkDriverClient\ArkDriverClient.cpp`
- `D:\Projects\Ksword5.1\Ksword5.1\Ksword5.1\ArkDriverClient\ArkDriverFile.cpp`
- `D:\Projects\Ksword5.1\Ksword5.1\Ksword5.1\ArkDriverClient\ArkDriverAudit.cpp`
- `D:\Projects\Ksword5.1\Ksword5.1\Ksword5.1\ArkDriverClient\ArkDriverTypes.h`
- `D:\Projects\Ksword5.1\KswordARKDriver\include\ark\ark_file_monitor.h`
- `D:\Projects\Ksword5.1\KswordARKDriver\include\ark\ark_driver.h`
- `D:\Projects\Ksword5.1\KswordARKDriver\include\ark\ark_ioctl.h`
- `D:\Projects\Ksword5.1\KswordARKDriver\src\features\file_monitor\file_monitor_internal.h`
- `D:\Projects\Ksword5.1\KswordARKDriver\src\features\file_monitor\file_monitor_ioctl.c`
- `D:\Projects\Ksword5.1\KswordARKDriver\src\features\file_monitor\file_monitor_runtime.c`
- `D:\Projects\Ksword5.1\KswordARKDriver\src\features\file_monitor\file_monitor_operation_map.c`
- `D:\Projects\Ksword5.1\KswordARKDriver\src\features\network\network_ioctl.c`
- `D:\Projects\Ksword5.1\KswordARKDriver\src\dispatch\ioctl_registry.c`
- `D:\Projects\Ksword5.1\KswordARKDriver\src\dispatch\ioctl_dispatch.c`

Current sandbox files read:

- `D:\Projects\KswordSandbox\driver\KSword.Sandbox.Driver\include\KSwordSandboxDriverIoctl.h`
- `D:\Projects\KswordSandbox\driver\KSword.Sandbox.Driver\src\Driver.c`
- `D:\Projects\KswordSandbox\guest\KSword.Sandbox.R0Collector\src\main.cpp`
- `D:\Projects\KswordSandbox\docs\r0-collector.md`
- `D:\Projects\KswordSandbox\docs\report-schema.md`

## Reusable protocol and client boundaries

### File monitor shared ABI

Source: `shared\driver\KswordArkFileMonitorIoctl.h`

Reusable items:

- Protocol version:
  - `KSWORD_ARK_FILE_MONITOR_PROTOCOL_VERSION`
- IOCTL intent:
  - `IOCTL_KSWORD_ARK_FILE_MONITOR_CONTROL`
  - `IOCTL_KSWORD_ARK_FILE_MONITOR_DRAIN`
  - `IOCTL_KSWORD_ARK_FILE_MONITOR_QUERY_STATUS`
- Control actions:
  - `KSWORD_ARK_FILE_MONITOR_ACTION_START`
  - `KSWORD_ARK_FILE_MONITOR_ACTION_STOP`
  - `KSWORD_ARK_FILE_MONITOR_ACTION_CLEAR`
- Operation mask bits:
  - `CREATE`, `READ`, `WRITE`, `SETINFO`, `RENAME`, `DELETE`, `CLEANUP`,
    `CLOSE`, `FSCTL`, and `ALL`.
- Field/runtime flags:
  - `PATH_PRESENT`, `PATH_TRUNCATED`, `RESULT_PRESENT`, `ACCESS_PRESENT`,
    `POST_OPERATION`, `SYSTEM_PROCESS`, `FSCTL_PRESENT`
  - `RUNTIME_REGISTERED`, `RUNTIME_STARTED`, `RUNTIME_DROPPED`
- Structure shapes:
  - `KSWORD_ARK_FILE_MONITOR_CONTROL_REQUEST`
  - `KSWORD_ARK_FILE_MONITOR_STATUS_RESPONSE`
  - `KSWORD_ARK_FILE_MONITOR_EVENT`
  - `KSWORD_ARK_FILE_MONITOR_DRAIN_REQUEST`
  - `KSWORD_ARK_FILE_MONITOR_DRAIN_RESPONSE`
- Constants:
  - `KSWORD_ARK_FILE_MONITOR_PATH_CHARS` is 520.
  - `KSWORD_ARK_FILE_MONITOR_RING_CAPACITY` is 1024.
- Optional display helpers:
  - `KswordARKFileMonitorFsctlCodeToText`
  - `KswordARKFileMonitorFsctlIsOplockRelated`

Reuse mode:

- Migrate the operation bits, field flags, runtime flags, event payload shape,
  and drain response semantics into the sandbox header with
  `KSWORD_SANDBOX_` prefixes.
- Do not migrate the KswordARK IOCTL numbers as-is. The sandbox already owns
  `IOCTL_KSWORD_SANDBOX_READ_EVENTS`; first phase should drain through that
  existing stream instead of adding Ark-specific control codes.

### File monitor R0 runtime and IOCTL handlers

Sources:

- `KswordARKDriver\include\ark\ark_file_monitor.h`
- `KswordARKDriver\src\features\file_monitor\file_monitor_runtime.c`
- `KswordARKDriver\src\features\file_monitor\file_monitor_ioctl.c`
- `KswordARKDriver\src\features\file_monitor\file_monitor_operation_map.c`
- `KswordARKDriver\src\features\file_monitor\file_monitor_internal.h`

Key functions:

- Public R0 boundary:
  - `KswordARKFileMonitorInitialize`
  - `KswordARKFileMonitorUninitialize`
  - `KswordARKFileMonitorControl`
  - `KswordARKFileMonitorQueryStatus`
  - `KswordARKFileMonitorDrain`
- WDF IOCTL handlers:
  - `KswordARKFileMonitorIoctlControl`
  - `KswordARKFileMonitorIoctlDrain`
  - `KswordARKFileMonitorIoctlQueryStatus`
- Event production:
  - `KswordArkMinifilterPreOperation`
  - `KswordArkMinifilterPostOperation`
  - `KswordARKFileMonitorFillCommonEvent`
  - `KswordARKFileMonitorPushEvent`
  - `KswordARKFileMonitorShouldCapture`
- Operation mapping:
  - `KswordARKMinifilterMapMajorToOperation`
  - `KswordARKFileMonitorMapMajorToOperation`
- Minifilter integration:
  - `g_KswordArkFileMonitorOperations`
  - `g_KswordArkFileMonitorRegistration`
  - `FltRegisterFilter`
  - `FltStartFiltering`
  - `FltUnregisterFilter`

Reusable behavior:

- Fixed-size ring buffer with spin lock.
- Overwrite-oldest behavior when full, with `DroppedCount` increment.
- `Drain` consumes events and returns only rows that fit the output buffer.
- Pre/post split:
  - `CREATE`, `SET_INFORMATION`, and `FILE_SYSTEM_CONTROL` use post callback
    so final `NTSTATUS` can be captured.
  - `READ`, `WRITE`, `CLEANUP`, and `CLOSE` are captured in pre callback.
- Path extraction fallback:
  - First `FltGetFileNameInformation`.
  - Then `FileObject->FileName` fallback.
- First version only filters by operation mask and PID.

Reuse mode:

- Reference the minifilter callback logic and operation map.
- For sandbox first phase, keep the public R3 ABI as
  `IOCTL_KSWORD_SANDBOX_READ_EVENTS` and adapt the drain backend to write
  `KSWORD_SANDBOX_EVENT_HEADER` plus a file payload.
- Do not copy WDF queue plumbing if the current sandbox driver remains WDM-style.

### ArkDriverClient boundary

Sources:

- `ArkDriverClient\ArkDriverClient.h`
- `ArkDriverClient\ArkDriverClient.cpp`
- `ArkDriverClient\ArkDriverFile.cpp`
- `ArkDriverClient\ArkDriverAudit.cpp`
- `ArkDriverClient\ArkDriverTypes.h`

Key reusable client patterns:

- `DriverHandle`: move-only RAII wrapper for `HANDLE`.
- `IoResult`: common result carrying `ok`, `win32Error`, `ntStatus`,
  `message`, and `bytesReturned`.
- `DriverClient::open`: wraps `CreateFileW`.
- `DriverClient::deviceIoControl`: single synchronous `DeviceIoControl`
  wrapper, optionally reusing an existing handle.
- `DriverClient::deviceIoControlAsync`: overlapped variant.
- File monitor wrappers:
  - `DriverClient::controlFileMonitor`
  - `DriverClient::queryFileMonitorStatus`
  - `DriverClient::drainFileMonitor`
- File monitor parser helpers:
  - `copyFileMonitorFieldIfPresent`
  - `parseFileMonitorEventRow`
- Variable-row parser patterns:
  - `validateAuditRows`
  - `parseVariableRows`
  - `appendAuditSummary`
  - `markUnsupportedIfNeeded`

Reuse mode:

- Reference these patterns for collector-side robustness:
  - single open handle;
  - exact `bytesReturned` validation;
  - `entrySize` validation before walking rows;
  - tolerate old/unsupported drivers as a distinct state;
  - copy rows out of the IO buffer before further processing.
- Do not copy `DriverClient` as a Qt/UI-facing class. The sandbox collector is a
  small console sidecar and should use local helpers matching its current style.

### Network protocol

Source: `shared\driver\KswordArkNetworkIoctl.h`

Key structures and IOCTLs:

- Mutable rules:
  - `IOCTL_KSWORD_ARK_NETWORK_SET_RULES`
  - `IOCTL_KSWORD_ARK_NETWORK_QUERY_STATUS`
  - `KSWORD_ARK_NETWORK_RULE`
  - `KSWORD_ARK_NETWORK_SET_RULES_REQUEST`
  - `KSWORD_ARK_NETWORK_SET_RULES_RESPONSE`
  - `KSWORD_ARK_NETWORK_STATUS_RESPONSE`
- Read-only audit:
  - `IOCTL_KSWORD_ARK_NETWORK_QUERY_TCP_ENDPOINTS`
  - `IOCTL_KSWORD_ARK_NETWORK_QUERY_UDP_ENDPOINTS`
  - `IOCTL_KSWORD_ARK_NETWORK_QUERY_WFP_INVENTORY`
  - `IOCTL_KSWORD_ARK_NETWORK_QUERY_NDIS_CHAIN`
  - `KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST`
  - `KSWORD_ARK_NETWORK_ENDPOINT_ROW`
  - `KSWORD_ARK_NETWORK_ENDPOINT_RESPONSE`
  - `KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW`
  - `KSWORD_ARK_NETWORK_WFP_INVENTORY_RESPONSE`
  - `KSWORD_ARK_NETWORK_NDIS_CHAIN_ROW`
  - `KSWORD_ARK_NETWORK_NDIS_CHAIN_RESPONSE`

Reuse mode:

- Reference the count-first, bounded-row response design for later network
  audit work.
- Only the read-only audit query/response pattern is suitable for sandbox
  reuse.
- Do not copy `NETWORK_SET_RULES` or port-hide/blocking semantics into sandbox
  first phase.

### Dispatch and registration pattern

Sources:

- `KswordARKDriver\src\dispatch\ioctl_registry.c`
- `KswordARKDriver\src\dispatch\ioctl_dispatch.c`

Key facts:

- File monitor entries are registered as:
  - `IOCTL_KSWORD_ARK_FILE_MONITOR_CONTROL`
  - `IOCTL_KSWORD_ARK_FILE_MONITOR_DRAIN`
  - `IOCTL_KSWORD_ARK_FILE_MONITOR_QUERY_STATUS`
- Network entries are registered as:
  - `IOCTL_KSWORD_ARK_NETWORK_SET_RULES`
  - `IOCTL_KSWORD_ARK_NETWORK_QUERY_STATUS`
  - `IOCTL_KSWORD_ARK_NETWORK_QUERY_TCP_ENDPOINTS`
  - `IOCTL_KSWORD_ARK_NETWORK_QUERY_UDP_ENDPOINTS`
  - `IOCTL_KSWORD_ARK_NETWORK_QUERY_WFP_INVENTORY`
  - `IOCTL_KSWORD_ARK_NETWORK_QUERY_NDIS_CHAIN`
- Dispatch fails closed on unknown IOCTLs.

Reuse mode:

- Reference exact-match dispatch and fail-closed behavior.
- Current sandbox `Driver.c` already has direct IOCTL dispatch for health, poll,
  and read events. Keep that for phase 1 unless the driver is later moved to a
  table-driven dispatch.

## Migration decision matrix

### Migrate into `driver/KSword.Sandbox.Driver/include`

Add only sandbox-renamed definitions to
`driver/KSword.Sandbox.Driver/include/KSwordSandboxDriverIoctl.h`:

- New event type:
  - `KswSandboxEventTypeFile = 2`
- File operation flags, renamed from Ark:
  - `KSWORD_SANDBOX_FILE_OPERATION_CREATE`
  - `KSWORD_SANDBOX_FILE_OPERATION_READ`
  - `KSWORD_SANDBOX_FILE_OPERATION_WRITE`
  - `KSWORD_SANDBOX_FILE_OPERATION_SETINFO`
  - `KSWORD_SANDBOX_FILE_OPERATION_RENAME`
  - `KSWORD_SANDBOX_FILE_OPERATION_DELETE`
  - `KSWORD_SANDBOX_FILE_OPERATION_CLEANUP`
  - `KSWORD_SANDBOX_FILE_OPERATION_CLOSE`
  - `KSWORD_SANDBOX_FILE_OPERATION_FSCTL`
  - `KSWORD_SANDBOX_FILE_OPERATION_ALL`
- File event field flags, renamed from Ark:
  - `PATH_PRESENT`, `PATH_TRUNCATED`, `RESULT_PRESENT`,
    `ACCESS_PRESENT`, `POST_OPERATION`, `SYSTEM_PROCESS`,
    `FSCTL_PRESENT`
- Runtime status bits for health/poll metadata:
  - `FILE_RUNTIME_REGISTERED`
  - `FILE_RUNTIME_STARTED`
  - `FILE_RUNTIME_DROPPED`
- File payload constants:
  - `KSWORD_SANDBOX_FILE_PATH_CHARS` from Ark value 520, unless the sandbox
    driver has a stronger size constraint.
  - A ring capacity constant can live in driver-private source or public header
    if the collector should display it.
- File event payload structure, not the full Ark event structure. Recommended:

```c
typedef struct _KSWORD_SANDBOX_FILE_EVENT_PAYLOAD {
    ULONG Version;
    ULONG Size;
    ULONG OperationType;
    ULONG MajorFunction;
    ULONG MinorFunction;
    ULONG FieldFlags;
    ULONG DesiredAccess;
    ULONG ShareAccess;
    ULONG CreateOptions;
    ULONG FileInformationClass;
    LONG ResultStatus;
    ULONG PathLengthChars;
    ULONGLONG TimeUtc100ns;
    ULONGLONG FileObjectAddress;
    ULONG FsControlCode;
    ULONG FsInputBufferLength;
    ULONG FsOutputBufferLength;
    ULONG Reserved0;
    WCHAR Path[KSWORD_SANDBOX_FILE_PATH_CHARS];
} KSWORD_SANDBOX_FILE_EVENT_PAYLOAD, *PKSWORD_SANDBOX_FILE_EVENT_PAYLOAD;
```

Notes:

- `ProcessId`, `ThreadId`, `Sequence`, and QPC timestamp already belong in
  `KSWORD_SANDBOX_EVENT_HEADER`.
- Keep `TimeUtc100ns` in the payload if JSONL should use driver event time
  instead of collector receive time.
- Use `ULONG`/`ULONGLONG`/`WCHAR` consistently with the existing sandbox header.

### Use as implementation reference only

- Minifilter callback registration and registry instance self-healing in
  `file_monitor_runtime.c`.
- `FltGetFileNameInformation` path extraction and fallback logic.
- Ring buffer drain logic and overwrite-oldest behavior.
- `ArkDriverFile.cpp` parser strategy:
  - validate response header;
  - validate `entrySize`;
  - parse only rows covered by `bytesReturned`;
  - convert fixed `wchar_t` arrays by bounded scan.
- `ArkDriverAudit.cpp` variable-row helpers.
- Read-only network audit count-first response pattern.
- Dispatch registry exact-match design.

### Do not copy

- Any `.sys`, `.pdb`, `.exe`, `.dll`, `.lib`, `.obj`, `.ilk`, certificates,
  signing scripts, test samples, or generated outputs.
- Full `D:\Projects\Ksword5.1` trees or full `shared\driver` tree.
- KswordARK device names:
  - `\\.\KswordARKLog`
  - `\Device\KswordARKLog`
  - `\DosDevices\KswordARKLog`
- KswordARK IOCTL numbers as public sandbox ABI.
- Destructive or mutation-oriented protocols:
  - process terminate/suspend/inject/DKOM;
  - file delete/set-integrity;
  - kernel patch/unload;
  - mutation prepare/commit/rollback;
  - callback removal;
  - network set-rules/block/hide-port.
- PDB/DynData profile protocol unless a later phase explicitly owns that
  dependency.

## Phase 1: shortest file monitor drain path

Goal: deliver driver-originated file events into the existing JSONL sidecar with
minimal ABI churn.

### Driver event structure

Use the existing stream:

- `IOCTL_KSWORD_SANDBOX_POLL`
- `IOCTL_KSWORD_SANDBOX_READ_EVENTS`
- `KSWORD_SANDBOX_EVENT_HEADER`
- `KSWORD_SANDBOX_READ_EVENTS_REPLY`

Append one file payload after each event header:

```c
typedef struct _KSWORD_SANDBOX_FILE_EVENT_RECORD {
    KSWORD_SANDBOX_EVENT_HEADER Header;
    KSWORD_SANDBOX_FILE_EVENT_PAYLOAD Payload;
} KSWORD_SANDBOX_FILE_EVENT_RECORD;
```

Header rules:

- `Header.Version = KSWORD_SANDBOX_EVENT_HEADER_VERSION`
- `Header.Size = sizeof(KSWORD_SANDBOX_FILE_EVENT_RECORD)`
- `Header.Type = KswSandboxEventTypeFile`
- `Header.Sequence = next monotonic sequence`
- `Header.TimestampQpc = KeQueryPerformanceCounter(...)` or equivalent
- `Header.ProcessId = payload source PID`
- `Header.ThreadId = payload source TID`
- `Header.PayloadSize = sizeof(KSWORD_SANDBOX_FILE_EVENT_PAYLOAD)`

Payload rules:

- Fill from the Ark file monitor event subset.
- Path must be NUL-terminated when present.
- Set `PATH_TRUNCATED` when copied path reaches fixed capacity.
- For post-operation events, set `RESULT_PRESENT` and `POST_OPERATION`.
- For create/open, set `ACCESS_PRESENT`, `DesiredAccess`, `ShareAccess`,
  and `CreateOptions`.
- For set-information, set `FileInformationClass`.
- For FSCTL, set `FSCTL_PRESENT`, `FsControlCode`, `FsInputBufferLength`,
  and `FsOutputBufferLength`.

### Driver drain behavior

Shortest implementation:

1. Add a driver-private ring of `KSWORD_SANDBOX_FILE_EVENT_RECORD`.
2. Reuse the current device extension counters:
   - `EventsQueued`
   - `EventsDropped`
   - `NextSequence`
3. Produce file records from a minifilter callback path modeled on
   `KswordArkMinifilterPreOperation` and `KswordArkMinifilterPostOperation`.
4. In `KswHandlePoll`, report `HasEvents` based on the ring count.
5. In `KswHandleReadEvents`, drain records into
   `KSWORD_SANDBOX_READ_EVENTS_REPLY.Events`.
6. Bound every drain by all three limits:
   - output buffer remaining bytes;
   - request `MaxEvents` when supplied;
   - queued count.
7. Consume records only after copying them to the output stream.
8. Increment `EventsDropped` when the ring overwrites the oldest record.

Avoid in phase 1:

- New Ark-style `CONTROL`, `DRAIN`, or `QUERY_STATUS` IOCTLs.
- Path/extension filtering in R0.
- Process command-line enrichment in R0.
- Network or registry protocols.

### Collector call sequence

Current collector path to extend:

- `OpenDriverDevice`
- `RunDeviceSkeleton`
- `EmitEvent`
- JSON helpers in `main.cpp`

Recommended phase-1 loop:

1. Open `\\.\KSwordSandboxDriver` as today.
2. Emit `r0collector.deviceOpened`.
3. Issue `IOCTL_KSWORD_SANDBOX_GET_HEALTH` once and emit a lifecycle row.
4. Until duration expires:
   - issue `IOCTL_KSWORD_SANDBOX_POLL`;
   - if `HasEvents == 0`, sleep `pollIntervalMs`;
   - if events exist, issue `IOCTL_KSWORD_SANDBOX_READ_EVENTS`.
5. Use a fixed output buffer first, for example 1 MiB or 4 MiB.
6. Request:
   - `Version = KSWORD_SANDBOX_INTERFACE_VERSION`
   - `Size = sizeof(KSWORD_SANDBOX_READ_EVENTS_REQUEST)`
   - `MaxEvents = 128` or CLI-configured value later.
7. Validate reply:
   - `bytesReturned >= KSWORD_SANDBOX_READ_EVENTS_REPLY_HEADER_SIZE`
   - `reply.Version == KSWORD_SANDBOX_INTERFACE_VERSION`
   - `reply.Size >= KSWORD_SANDBOX_READ_EVENTS_REPLY_HEADER_SIZE`
   - `reply.BytesWritten <= bytesReturned - headerSize`
8. Walk the event byte stream:
   - every record starts with `KSWORD_SANDBOX_EVENT_HEADER`;
   - `header.Size >= sizeof(KSWORD_SANDBOX_EVENT_HEADER)`;
   - `header.Size <= remaining`;
   - `header.PayloadSize == header.Size - sizeof(header)`;
   - parse only `KswSandboxEventTypeFile` in phase 1.
9. Emit one JSONL row per file event.
10. Preserve `reply.EventsDropped` and sequence gaps in emitted `data` so the
    report can show loss.

### JSONL event mapping

Top-level `SandboxEvent` fields:

- `eventType`: `driver.file.<operation>`
- `source`: `r0collector`
- `timestamp`: driver `TimeUtc100ns` converted to UTC ISO-8601 if available;
  otherwise collector receive time.
- `processId`: `Header.ProcessId`
- `path`: payload `Path` when `PATH_PRESENT`, otherwise empty string.
- `commandLine`: keep collector command line for phase 1; process command-line
  enrichment is a later phase.
- `data`: object with string values for compatibility with current collector
  documentation.

Operation mapping:

| Operation flag | JSON eventType |
| --- | --- |
| `CREATE` | `driver.file.create` |
| `READ` | `driver.file.read` |
| `WRITE` | `driver.file.write` |
| `SETINFO` | `driver.file.setinfo` |
| `RENAME` | `driver.file.rename` |
| `DELETE` | `driver.file.delete` |
| `CLEANUP` | `driver.file.cleanup` |
| `CLOSE` | `driver.file.close` |
| `FSCTL` | `driver.file.fsctl` |
| unknown/zero | `driver.file.unknown` |

Recommended `data` keys:

- `sequence`
- `threadId`
- `operationType`
- `operation`
- `majorFunction`
- `minorFunction`
- `fieldFlags`
- `postOperation`
- `systemProcess`
- `pathPresent`
- `pathTruncated`
- `desiredAccess`
- `shareAccess`
- `createOptions`
- `fileInformationClass`
- `resultStatus`
- `fileObjectAddress`
- `fsControlCode`
- `fsInputBufferLength`
- `fsOutputBufferLength`
- `eventsDropped`
- `nextSequence`

Example row:

```json
{"eventType":"driver.file.create","source":"r0collector","timestamp":"2026-07-10T00:00:00.000Z","processId":4242,"path":"\\Device\\HarddiskVolume3\\Windows\\Temp\\sample.tmp","commandLine":"KSword.Sandbox.R0Collector.exe --driver-events","data":{"sequence":"17","threadId":"4312","operationType":"1","operation":"create","majorFunction":"0","minorFunction":"0","fieldFlags":"0x0000001d","postOperation":"true","systemProcess":"false","pathPresent":"true","pathTruncated":"false","desiredAccess":"0x0012019f","shareAccess":"0x00000007","createOptions":"0x00000020","resultStatus":"0x00000000","fileObjectAddress":"0xffffd40a12345000","eventsDropped":"0","nextSequence":"18"}}
```

## Landing order

1. Update only `KSwordSandboxDriverIoctl.h` with sandbox-renamed file event
   payload and operation flags.
2. Add driver-private ring and drain-through-`READ_EVENTS` implementation.
3. Add minifilter production path using the Ark operation map as reference.
4. Extend collector with `DeviceIoControl` wrappers and bounded event parser.
5. Emit JSONL rows with the mapping above.
6. Keep network protocol and advanced Ark controls out of phase 1.

## Verification checklist for the implementation phase

- Header builds from both kernel and user mode.
- `READ_EVENTS` with zero events still returns only the reply header.
- `POLL` flips `HasEvents` when a file record is queued.
- `READ_EVENTS` respects `MaxEvents` and output-buffer capacity.
- Event parser rejects malformed `Size`/`PayloadSize` without crashing.
- Long paths are truncated with `pathTruncated=true`.
- Dropped events are visible through `EventsDropped` and sequence gaps.
- Collector still supports `--mock`.
- No binaries, certificates, samples, generated native artifacts, or Ksword5.1
  source trees are copied.
