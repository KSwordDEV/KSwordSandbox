# R0 ABI review and next implementation plan

Date: 2026-07-12 (current status note refreshed for local v22+ release-prep baseline `77298d6 / v22`)

中文优先维护说明：本文是历史实施计划，不是当前 ABI 的唯一事实来源。阅读时先以
`docs/r0-driver-core.md`、`docs/r0-collector.md`、`docs/r0-jsonl-schema.md` 和各
producer 专项文档为准；本文件保留早期落地顺序、风险和 patch split 供对照。所有字段名、
ABI 结构名、event type 和 JSON key 继续保持英文稳定值。

> Historical planning note: this file records an earlier R0 landing plan, not
> the current implementation checklist. Use `docs/r0-driver-core.md` for the
> current ABI source of truth, `docs/r0-collector.md` /
> `docs/r0-jsonl-schema.md` for collector status and JSONL, and
> producer-specific docs such as `docs/r0-driver.md`,
> `docs/r0-file-monitor.md`, `docs/r0-process-registry-image.md`, and
> `docs/r0-network.md` for current producer notes.

Scope: documentation-only review of the current working-tree snapshot. This
plan intentionally does not modify `driver/`, `guest/`, `src/`, `tests/`, or
`scripts/`, so it can run in parallel with the main driver ring-buffer and
collector drain work.

判读边界 / interpretation boundary：

- ABI review rows and planned fields are compatibility evidence only. They do
  not assert that a live driver was loaded unless a live readiness/drain row says
  so.
- `noise`、`selfNoise`、producer masks、loss/backpressure counters 和 sequence
  gaps 是采集归因/质量标签，不是 malicious/benign verdict。
- Network planning must preserve the current semantic split: R0 WFP/ALE rows
  provide endpoint/PID/layer evidence, while DNS query、HTTP request metadata、
  TLS SNI/certificate 和 packet bytes come from PCAP-derived rows.

Reviewed files:

- `driver/KSword.Sandbox.Driver/include/KSwordSandboxDriverIoctl.h`
- `driver/KSword.Sandbox.Driver/src/Driver.h`
- `driver/KSword.Sandbox.Driver/src/Driver.c`
- `guest/KSword.Sandbox.R0Collector/src/main.cpp`
- `docs/ksword5-driver-reuse.md`


## Current v22 status correction

As of the local v22+ release-prep batch (baseline `77298d6 / v22`), the project has moved beyond several items in this
historical plan:

- The current ABI source of truth advertises v1 typed payloads for process,
  image, registry, file, and ALE inspect-only network events, plus producer
  masks, queue/loss/backpressure counters, common metadata, and read-only
  `GET_NETWORK_STATUS` diagnostics.
- The current R0 docs describe process/image callbacks, registry callback, file
  minifilter, and WFP/ALE network producer boundaries. Network remains endpoint
  telemetry only; DNS/HTTP/TLS payload facts still come from PCAP/sidecar rows.
- The remaining release gap is not “define the first payloads”; it is fresh lab
  validation: no new Hyper-V live run, real driver load, pressure run,
  unload/reload evidence, or full report handoff was generated during this doc
  refresh.
- Default release language must still say R0 is an optional isolated-lab path.
  Source/readiness/package checks do not sign, load, or query a live driver and
  do not prove current candidate R0 runtime behavior.

The implementation sequence below is retained for history and risk context only.
Do not use it to infer that current producer docs are missing or that live
validation has been refreshed.

## Current ABI and collector review

### What can run now

The current R0/R3 path is enough to validate driver loading, device opening,
basic IOCTL framing, and collector JSONL output inside a VM:

- The driver creates `\Device\KSwordSandboxDriver` and publishes
  `\DosDevices\KSwordSandboxDriver`; the collector opens
  `\\.\KSwordSandboxDriver`.
- Public IOCTLs are already defined and routed:
  - `IOCTL_KSWORD_SANDBOX_GET_HEALTH`
  - `IOCTL_KSWORD_SANDBOX_POLL`
  - `IOCTL_KSWORD_SANDBOX_READ_EVENTS`
- `GET_HEALTH` returns version, state, queue counters, drop count, next readable
  sequence, and the last internal NTSTATUS.
- `POLL` returns a cheap queue snapshot and `HasEvents`.
- `READ_EVENTS` accepts a zero-length request or
  `KSWORD_SANDBOX_READ_EVENTS_REQUEST`, drains complete event records from a
  fixed non-paged ring, and returns
  `KSWORD_SANDBOX_READ_EVENTS_REPLY` followed by event records.
- The driver queues one startup self-test record during `DriverEntry`.
  Today that record is `KswSandboxEventTypeReserved` with
  `KSWORD_SANDBOX_EVENT_FLAG_SELF_TEST` and
  `KSWORD_SANDBOX_EVENT_FLAG_DRIVER_STARTED`.
- The collector already issues all three IOCTLs, validates reply versions and
  sizes, walks the returned event byte stream, emits one JSONL row per event,
  and emits a batch summary row.
- `--mock` remains available for Guest Agent and report-pipeline plumbing when
  the driver is not installed.

This means the next VM smoke can prove:

1. signed/test-signed driver service starts;
2. collector opens the control device;
3. health and poll rows appear in JSONL;
4. startup event drains once through `READ_EVENTS`;
5. report ingestion can show at least R0 lifecycle behavior.

### What is still missing

This section is historical. The current code no longer stops at only the
synthetic startup event: current R0 docs describe typed payloads and producer
runtime state for process, image, file, registry, and ALE inspect-only network
telemetry. Remaining current gaps should be read from the producer-specific docs
and release audit, especially:

- no fresh Hyper-V live evidence was produced in this documentation pass;
- full real-driver load, pressure, unload/reload, and report-ingestion evidence
  must still be refreshed on an isolated lab VM before release notes claim it;
- R0 network remains ALE endpoint telemetry, not packet/DNS/HTTP/TLS parsing;
- runtime package/readiness success does not prove live R0 behavior.

### ABI fields that should be treated as stable now

Do not renumber or reinterpret these without a major ABI bump:

- Device path macros:
  - `KSWORD_SANDBOX_NT_DEVICE_NAME`
  - `KSWORD_SANDBOX_DOS_DEVICE_NAME`
  - `KSWORD_SANDBOX_WIN32_DEVICE_NAME`
- IOCTL names and codes:
  - `IOCTL_KSWORD_SANDBOX_GET_HEALTH`
  - `IOCTL_KSWORD_SANDBOX_POLL`
  - `IOCTL_KSWORD_SANDBOX_READ_EVENTS`
- Version constants:
  - `KSWORD_SANDBOX_INTERFACE_VERSION`
  - `KSWORD_SANDBOX_EVENT_HEADER_VERSION`
- Event stream framing:
  - `KSWORD_SANDBOX_EVENT_HEADER.Version`
  - `Size`
  - `Type`
  - `Flags`
  - `Sequence`
  - `TimestampQpc`
  - `ProcessId`
  - `ThreadId`
  - `PayloadSize`
- Drain reply semantics:
  - fixed reply header first;
  - `BytesWritten` counts only trailing event-stream bytes;
  - `EventsWritten` counts complete event records;
  - `EventsDropped` is monotonic drop count;
  - `NextSequence` is the oldest queued sequence, or the future sequence when
    the queue is empty.
- Event type numbers already declared:
  - `DriverLoad = 1`
  - `Process = 2`
  - `Image = 3`
  - `File = 4`
  - `Registry = 5`
  - `Network = 6`

### ABI items to stabilize before adding high-volume producers

These should be landed before or alongside their first producer callback:

- Per-event payload `Version` and `Size` fields.
- Fixed maximum path/image/registry string lengths and UTF-16 encoding rules.
- Per-type operation enums:
  - process create/exit;
  - image load;
  - file create/read/write/set-information/rename/delete/cleanup/close/fsctl;
  - registry create/open/set/delete/rename/query;
  - network TCP/UDP endpoint row and optional WFP event type.
- Per-type field flags for optional fields, truncation, post-operation status,
  system process, and error/status presence.
- Timestamp rule:
  - keep `TimestampQpc` in the common header for ordering;
  - add UTC 100ns timestamps in payloads only when report timestamps need
    wall-clock time without collector-side approximation.
- Loss reporting:
  - keep monotonic `EventsDropped`;
  - have the collector record sequence gaps and batch-level drop count.
- Forward compatibility rule:
  - collectors must skip unknown event types by `Header.Size`;
  - drivers must never emit records larger than the documented maximum drain
    record size unless the ABI version changes.

## 最小落地顺序 / Minimal landing sequence

最快达成 “start VM, report behavior / 启动 VM 并报告行为” 的路径，是保留现有
`READ_EVENTS` stream，并一次只新增一个 producer class。第一个行为里程碑不要新增
Ark-style control/drain IOCTL。

推荐顺序 / Recommended order:

1. Process callback
2. Image load callback
3. File minifilter
4. Registry callback
5. Network snapshot first, optional WFP eventing later

Each step below lists the intended kernel API surface, main risks, test method,
and expected file changes.

## Step 1: Process callback

Goal: emit process create and exit events. This is the smallest useful behavior
producer and gives reports a root activity timeline.

Kernel APIs:

- `PsSetCreateProcessNotifyRoutineEx` for create/exit notification.
- `PsGetCurrentProcessId` and `PsGetCurrentThreadId` for fallback context.
- `SeLocateProcessImageName` only if image path enrichment is required and
  safely allocated/freed.
- `ExAllocatePool2` or a bounded stack/local buffer only for temporary strings;
  avoid allocation in the ring record itself.
- `RtlUnicodeStringCopyString`, `RtlCopyMemory`, and bounded UTF-16 copies for
  image path/command-line fields.

ABI additions:

- Add `KSWORD_SANDBOX_PROCESS_EVENT_PAYLOAD`.
- Add process operation values:
  - `KSWORD_SANDBOX_PROCESS_OPERATION_CREATE`
  - `KSWORD_SANDBOX_PROCESS_OPERATION_EXIT`
- Add process field flags:
  - image path present/truncated;
  - command line present/truncated;
  - parent process id present;
  - create status present.

Risks:

- Process callback runs at `PASSIVE_LEVEL`, but it is still in a sensitive
  process-create path. Keep work bounded and do not block.
- Command-line and image path pointers may be absent. Treat all optional fields
  as nullable.
- Do not hold the ring spin lock while copying from caller-owned callback
  structures.
- Callback unregister must occur during unload before deleting the device.
- Driver unload can race with callbacks; use a global stopping flag or callback
  registration state before accepting new records.

Tests:

- Driver starts and collector emits startup event as before.
- Launch `notepad.exe` or a small benign sample in the VM.
- Collector emits `driver.process` rows for create and exit.
- Validate parent PID, target PID, sequence monotonicity, and no malformed
  `READ_EVENTS` rows.
- Stop the driver service and verify callback unregister does not bugcheck.

Expected file changes:

- `driver/KSword.Sandbox.Driver/include/KSwordSandboxDriverIoctl.h`
- `driver/KSword.Sandbox.Driver/src/Driver.h`
- `driver/KSword.Sandbox.Driver/src/Driver.c`
- `guest/KSword.Sandbox.R0Collector/src/main.cpp`
- `docs/r0-collector.md` or equivalent collector documentation

## Step 2: Image load callback

Goal: emit image/module load events for executable, DLL, and driver image loads.
This complements process create events and helps report suspicious module
behavior before file and registry volume increases.

Kernel APIs:

- `PsSetLoadImageNotifyRoutine` and `PsRemoveLoadImageNotifyRoutine`.
- `PIMAGE_INFO` fields supplied to the callback:
  - `ImageBase`
  - `ImageSize`
  - `SystemModeImage`
  - image signature flags when available in the target WDK.
- `RtlCopyUnicodeString` or bounded copy from the callback image name.

ABI additions:

- Add `KSWORD_SANDBOX_IMAGE_EVENT_PAYLOAD`.
- Stable fields should include image base, image size, image properties, full
  image name length, and fixed UTF-16 image path buffer.
- Add image field flags:
  - path present/truncated;
  - system-mode image;
  - process id present.

Risks:

- Image load callbacks can be frequent during process startup. Ring drops will
  appear quickly with a 64-record ring.
- Full image name can be null or point to a name that should be copied only
  within the callback.
- Kernel image loads have different process context semantics than user-mode DLL
  loads. Preserve both `ProcessId` from callback and current process/thread from
  the common header when useful.
- Unregister on unload must happen before device teardown.

Tests:

- Start collector with a short duration.
- Launch a process that loads multiple DLLs.
- Confirm `driver.image` or `image.load` rows include at least the EXE and DLL
  paths.
- Confirm unknown or null image names produce valid events with flags showing
  missing path instead of protocol errors.
- Confirm unload removes the image callback cleanly.

Expected file changes:

- `driver/KSword.Sandbox.Driver/include/KSwordSandboxDriverIoctl.h`
- `driver/KSword.Sandbox.Driver/src/Driver.h`
- `driver/KSword.Sandbox.Driver/src/Driver.c`
- `guest/KSword.Sandbox.R0Collector/src/main.cpp`

## Step 3: File minifilter

Goal: emit file behavior events through the existing `READ_EVENTS` stream. This
is higher value but also higher volume and higher integration risk than process
or image callbacks.

Kernel APIs:

- `FltRegisterFilter`
- `FltStartFiltering`
- `FltUnregisterFilter`
- `FLT_OPERATION_REGISTRATION`
- `FLT_REGISTRATION`
- `PFLT_CALLBACK_DATA`
- `FltGetFileNameInformation`
- `FltParseFileNameInformation`
- `FltReleaseFileNameInformation`
- `FltGetRequestorProcessId`
- `FltGetRequestorProcess`
- `IoThreadToProcess` only if a fallback is needed.

Initial operations:

- `IRP_MJ_CREATE`
- `IRP_MJ_READ`
- `IRP_MJ_WRITE`
- `IRP_MJ_SET_INFORMATION`
- `IRP_MJ_CLEANUP`
- `IRP_MJ_CLOSE`
- `IRP_MJ_FILE_SYSTEM_CONTROL`

ABI additions:

- Add sandbox-renamed file operation bits and field flags following
  `docs/ksword5-driver-reuse.md`.
- Add `KSWORD_SANDBOX_FILE_EVENT_PAYLOAD` with bounded UTF-16 path, operation,
  major/minor function, desired access, share access, create options,
  information class, result status, file object address, and FSCTL metadata.

Risks:

- A minifilter needs INF/service configuration and altitude selection; this can
  block VM startup if packaging is wrong.
- File callbacks are high-volume. Increase ring capacity or add filtering before
  enabling broad operations.
- Name resolution can be expensive or fail. Use bounded fallback to
  `FileObject->FileName`.
- Pre/post operation pairing must be minimal. Avoid storing unbounded per-I/O
  context until required.
- Never call pageable code at elevated IRQL; keep callbacks and shared ring code
  in non-paged-safe paths.
- Avoid recursive self-noise from collector/report output paths if possible.

Tests:

- Install/start the minifilter in a disposable VM snapshot.
- Create, write, rename, and delete a temporary file.
- Confirm JSONL rows for create/write/setinfo/delete or cleanup/close.
- Validate long path truncation flags.
- Stress with many small file writes and confirm `EventsDropped` and sequence
  gaps are reported instead of malformed rows.
- Unload/reload the driver and minifilter without a bugcheck.

Expected file changes:

- `driver/KSword.Sandbox.Driver/include/KSwordSandboxDriverIoctl.h`
- `driver/KSword.Sandbox.Driver/src/Driver.h`
- `driver/KSword.Sandbox.Driver/src/Driver.c`
- optionally new driver source files under `driver/KSword.Sandbox.Driver/src/`
  for file monitor code
- `driver/KSword.Sandbox.Driver/KSword.Sandbox.Driver.vcxproj`
- `driver/KSword.Sandbox.Driver/KSword.Sandbox.Driver.vcxproj.filters`
- driver INF/package metadata if not already present
- `guest/KSword.Sandbox.R0Collector/src/main.cpp`

## Step 4: Registry callback

Goal: emit registry create/open/set/delete/rename activity. This is the next
report-relevant data source after file behavior.

Kernel APIs:

- `CmRegisterCallbackEx`
- `CmUnRegisterCallback`
- `REG_NOTIFY_CLASS`
- callback information structures such as:
  - `REG_CREATE_KEY_INFORMATION`
  - `REG_OPEN_KEY_INFORMATION`
  - `REG_SET_VALUE_KEY_INFORMATION`
  - `REG_DELETE_VALUE_KEY_INFORMATION`
  - `REG_DELETE_KEY_INFORMATION`
  - `REG_RENAME_KEY_INFORMATION`
- `CmCallbackGetKeyObjectIDEx` and `CmCallbackReleaseKeyObjectIDEx` when stable
  normalized key names are required.
- `RtlCopyUnicodeString` or bounded UTF-16 copy helpers.

ABI additions:

- Add `KSWORD_SANDBOX_REGISTRY_EVENT_PAYLOAD`.
- Add registry operation enum for create/open/set value/delete value/delete
  key/rename/query.
- Add field flags:
  - key path present/truncated;
  - value name present/truncated;
  - data type present;
  - data size present;
  - status present;
  - post-operation.

Risks:

- Registry callback information differs between pre and post notifications.
  Keep the first version focused on a small set of notify classes.
- Registry paths can be absent or object-relative. Normalize only when safe.
- Registry value data may contain sensitive or large data. First version should
  record type and size, not raw data.
- Callback altitude must be unique. Choose and document a sandbox-specific
  altitude before packaging.
- Unregister must happen before device teardown.

Tests:

- Create and set a value under `HKCU\Software\KSwordSandboxTest`.
- Delete the value and key.
- Confirm JSONL rows include key path, value name, operation, process id, and
  status where available.
- Run with malformed or long value names and confirm truncation flags.
- Stop service and confirm callback unregister is clean.

Expected file changes:

- `driver/KSword.Sandbox.Driver/include/KSwordSandboxDriverIoctl.h`
- `driver/KSword.Sandbox.Driver/src/Driver.h`
- `driver/KSword.Sandbox.Driver/src/Driver.c`
- optionally new registry monitor source file
- `driver/KSword.Sandbox.Driver/KSword.Sandbox.Driver.vcxproj`
- `driver/KSword.Sandbox.Driver/KSword.Sandbox.Driver.vcxproj.filters`
- `guest/KSword.Sandbox.R0Collector/src/main.cpp`

## Step 5: Network snapshot first, WFP later

Goal: provide useful network evidence without making the first VM behavior
milestone depend on a full callout driver. Start with bounded endpoint snapshots,
then add WFP eventing only if needed.

Snapshot-oriented kernel APIs:

- `ZwDeviceIoControlFile` against TCP/IP NSI interfaces only if the team accepts
  the maintenance risk, or prefer a user-mode collector fallback for endpoint
  snapshots.
- Kernel-mode `GetExtendedTcpTable` is not available; if endpoint snapshots stay
  in user mode, use IP Helper APIs in the collector/agent instead.

WFP-oriented kernel APIs for a later phase:

- `FwpmEngineOpen`
- `FwpmSubLayerAdd`
- `FwpmCalloutAdd`
- `FwpsCalloutRegister`
- `FwpmFilterAdd`
- `FwpmFilterDeleteById`
- `FwpsCalloutUnregisterById`
- relevant ALE layers such as `FWPM_LAYER_ALE_AUTH_CONNECT_V4`,
  `FWPM_LAYER_ALE_AUTH_CONNECT_V6`, and receive/accept layers if needed.

ABI additions:

- Add `KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD` for eventing, or a count-first
  snapshot response if network is implemented outside the existing event stream.
- For the first R0 event-stream version, stable fields should include protocol,
  address family, local/remote address bytes, local/remote port, direction,
  process id, and status/action.
- Treat `serviceHint`, `dnsCandidate`, `httpCandidate`, and `tlsCandidate` as
  evidence labels derived from endpoint metadata.  Do not define them as parser
  verdicts; DNS/HTTP/TLS payload facts should remain PCAP-imported facts unless
  a future ABI explicitly carries parsed payload semantics.
- Do not copy KswordARK mutable block/hide/set-rules protocols into the sandbox
  first milestone.

Risks:

- Full WFP callout work has packaging, ordering, and teardown complexity. It is
  not the shortest path to a VM behavior report.
- Network endpoint snapshots may be better delivered from user mode first,
  leaving R0 WFP for later high-fidelity telemetry.
- WFP classify callbacks must be fast and non-blocking.
- Address formatting should be done in user mode; R0 should emit binary fields
  or fixed numeric fields.

Tests:

- Snapshot path: start a TCP connection from the sample or test command, collect
  endpoint rows, and confirm report correlation by PID.
- WFP path: connect to a local test server and a remote test endpoint; verify
  connect events and teardown cleanup.
- Confirm driver unload removes filters/callouts without leaving persistent WFP
  state.
- Confirm IPv4 and IPv6 records parse without collector protocol errors.

Expected file changes:

- If user-mode snapshot first:
  - `guest/KSword.Sandbox.R0Collector/src/main.cpp` or Guest Agent source
  - report/rule mapping docs
- If R0 WFP eventing:
  - `driver/KSword.Sandbox.Driver/include/KSwordSandboxDriverIoctl.h`
  - `driver/KSword.Sandbox.Driver/src/Driver.h`
  - `driver/KSword.Sandbox.Driver/src/Driver.c`
  - optionally new network monitor source file
  - `driver/KSword.Sandbox.Driver/KSword.Sandbox.Driver.vcxproj`
  - `driver/KSword.Sandbox.Driver/KSword.Sandbox.Driver.vcxproj.filters`
  - `guest/KSword.Sandbox.R0Collector/src/main.cpp`

## Collector/parser follow-up

The collector is already structurally ready for typed events because it walks
records by `KSWORD_SANDBOX_EVENT_HEADER.Size`. The next collector patch should:

- keep opaque fallback behavior for unknown event types;
- add typed payload parsing per event type only after that payload ABI lands;
- set top-level `path` from typed payload path fields where available;
- preserve `driverProcessId`, `driverThreadId`, `sequence`, `eventsDropped`,
  `nextSequence`, and any sequence-gap evidence in `data`;
- emit protocol errors without crashing when a driver returns malformed size,
  version, or payload fields;
- preserve ABI/noise/loss/backpressure fields as evidence labels and keep
  verdict generation in host rules/reports rather than in the collector parser;
- keep `--mock` behavior unchanged for CI and pipeline smoke tests.

## Recommended next patch split

Minimal low-conflict patches:

1. ABI-only process payload definitions and collector opaque compatibility test.
2. Process callback producer and unload unregister path.
3. Collector typed process parser and report mapping.
4. ABI-only image payload definitions.
5. Image load callback producer and collector typed image parser.
6. File payload definitions, then minifilter producer as a separate larger
   patch.
7. Registry payload definitions and callback producer.
8. Network snapshot decision: user-mode endpoint snapshot first, or R0 WFP
   eventing if kernel fidelity is required.

For the immediate VM run, step 1 plus the existing startup self-test is enough
to prove the R0 IOCTL path; step 2 is the first patch that proves real sample
behavior from R0.
