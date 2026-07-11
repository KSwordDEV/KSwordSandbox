# R0 process, image, and registry producers

Date: 2026-07-10

This document describes the production contract for the KSword Sandbox R0
process/image/registry producers that write into the shared `READ_EVENTS` ring.
The implementation lives in:

- `driver/KSword.Sandbox.Driver/src/Producers/Process/ProcessMonitor.c`
- `driver/KSword.Sandbox.Driver/src/Producers/Process/ProcessMonitor.h`
- `driver/KSword.Sandbox.Driver/src/Producers/Registry/RegistryMonitor.c`
- `driver/KSword.Sandbox.Driver/src/Producers/Registry/RegistryMonitor.h`

The public payload layouts are the fixed-size ABI structures in
`KSwordSandboxDriverIoctl.h`: `KSWORD_SANDBOX_PROCESS_EVENT_PAYLOAD`,
`KSWORD_SANDBOX_IMAGE_EVENT_PAYLOAD`, and
`KSWORD_SANDBOX_REGISTRY_EVENT_PAYLOAD`.  `guest/KSword.Sandbox.R0Collector`
parses those payloads into `driver.process`, `image.load`, and
`driver.registry` JSONL rows.

## Process producer

Registration uses `PsSetCreateProcessNotifyRoutineEx` first and falls back to
`PsSetCreateProcessNotifyRoutine` when the Ex callback is unavailable in a lab
build.  Unload removes whichever callback form was registered.

Create and exit events use `KswSandboxEventTypeProcess` with
`KSWORD_SANDBOX_PROCESS_EVENT_PAYLOAD`:

- `Operation`: `KswSandboxProcessOperationCreate` or
  `KswSandboxProcessOperationExit`.
- `ProcessId`: target process ID from the callback.
- `ParentProcessId`: parent ID from create callbacks, then replayed on exit from
  the bounded lineage cache when available.
- `CreatingProcessId`: current process ID that caused the create callback, then
  replayed on exit from the bounded lineage cache when available.
- `Status`: create status or exit status when safe to query.
- `ImagePath` and `CommandLine`: bounded UTF-16 prefixes for Ex create events.
- Flags distinguish Ex versus legacy callbacks, present strings, truncation, and
  status presence.  Create failures set
  `KSWORD_SANDBOX_PROCESS_EVENT_FLAG_OPERATION_FAILED`, and Ex callbacks mark
  `KSWORD_SANDBOX_PROCESS_EVENT_FLAG_FILE_OPEN_NAME_AVAILABLE` when Windows says
  the supplied image name is the opened file name.

The lineage cache is fixed-size, non-paged, protected by a spin lock, and uses
round-robin replacement rather than allocating in callback paths.  Entries are
cleared on exit and during monitor teardown to avoid PID reuse leaking stale
parent information.

## Image producer

Image telemetry is registered with `PsSetLoadImageNotifyRoutine` and removed
with `PsRemoveLoadImageNotifyRoutine` during driver unload.  Events use
`KswSandboxEventTypeImage` with `KSWORD_SANDBOX_IMAGE_EVENT_PAYLOAD`:

- `ProcessId`: process ID supplied by the image-load callback.  Kernel image
  loads may report a system or zero process context depending on Windows.
- `ImageBase` and `ImageSize`: numeric image mapping metadata from `PIMAGE_INFO`.
- `ImagePath`: bounded UTF-16 prefix of `FullImageName` when supplied.
- Flags identify path presence, path truncation, system-mode images,
  image-properties presence, images mapped to all PIDs, and extended image-info
  presence.

## Registry producer

Registry telemetry uses `CmRegisterCallbackEx` with the local altitude
`385201.7337`.  Unload disables emission and calls `CmUnRegisterCallback` before
the control device is deleted.

The callback observes post-operation notifications only and emits
`KswSandboxEventTypeRegistry` with `KSWORD_SANDBOX_REGISTRY_EVENT_PAYLOAD` for:

- `RegNtPostCreateKeyEx` -> `KswSandboxRegistryOperationCreateKey`
- `RegNtPostOpenKeyEx` -> `KswSandboxRegistryOperationOpenKey`
- `RegNtPostSetValueKey` -> `KswSandboxRegistryOperationSetValue`
- `RegNtPostDeleteValueKey` -> `KswSandboxRegistryOperationDeleteValue`
- `RegNtPostDeleteKey` -> `KswSandboxRegistryOperationDeleteKey`
- `RegNtPostRenameKey` -> `KswSandboxRegistryOperationRenameKey`

Registry fields:

- `ProcessId`: current process ID in the registry callback context.
- `Status`: final post-operation NTSTATUS.
- `KeyPath`: bounded UTF-16 key path.  Create/open first use the pre-operation
  `CompleteName`, then fall back to `CmCallbackGetKeyObjectIDEx` on the post
  object when available.  Set/delete/rename resolve the object path with
  `CmCallbackGetKeyObjectIDEx` and release it with
  `CmCallbackReleaseKeyObjectIDEx`.
- `ValueName`: bounded UTF-16 value name for set/delete-value.  For rename-key,
  this compact v1 ABI stores the new key name in `ValueName`.
- Flags identify key/value presence, truncation, status presence, failed
  operation status, and empty set-value data.

Value data bytes are intentionally not copied in this version.  The producer
records operation, key, value name, process ID, and status so behavior rules can
match persistence and tampering without moving arbitrary registry data through
callback paths.

## IRQL and string safety

All producer payloads are fixed-size records copied into the existing non-paged
ring.  Callback code does not allocate memory for output records and does not
block the observed operation.

String handling rules:

- `KswPrepareProcessCallbackString` and `KswPrepareRegistryCallbackString` refuse
  callback strings above `APC_LEVEL`.
- `UNICODE_STRING.Length` is clamped to `MaximumLength` when `MaximumLength` is
  present, then rounded down to a full `WCHAR` count.
- `KswCopyUnicodePrefix` copies at most the fixed payload capacity minus one
  terminator and reports the byte count without the trailing NUL.
- Missing strings leave the corresponding present flag unset; long strings set
  the matching truncation flag.

## Unload and failure behavior

Producer initialization failures are non-fatal to the control device.  The
DriverEntry path records the latest producer status in health telemetry and
keeps any successfully registered producer active.

Unload order disables producers before deleting the symbolic link and device:

1. Disable network/file/process/registry emission gates.
2. Remove process and image callbacks.
3. Unregister the registry callback with `CmUnRegisterCallback`.
4. Clear module-local callback state and cached lineage.
5. Delete the DOS symbolic link and control device.

This order ensures callbacks cannot enqueue into a deleted device extension.

## Runtime validation gate

Use `scripts/Test-R0Readiness.ps1` for explicit, opt-in VM validation.  A useful
manual smoke in an isolated test-signed guest is:

1. Install and start `KSword.Sandbox.Driver.sys`.
2. Start `KSword.Sandbox.R0Collector.exe --duration 5 --output driver-events.jsonl`.
3. Launch a short-lived process such as `notepad.exe` or `cmd.exe /c echo ok`.
4. Create, set, rename, delete-value, and delete-key under
   `HKCU\Software\KSwordSandboxTest`.
5. Stop the driver service and confirm unload succeeds.
6. Inspect JSONL rows for `driver.process`, `image.load`, and `driver.registry`
   with `typedPayloadStatus=parsed`.

Known limitations for this compact v1 producer are the small shared ring, bounded
path prefixes, no raw registry value data, and best-effort registry path
normalization.
