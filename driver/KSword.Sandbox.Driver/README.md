# KSword.Sandbox.Driver

Minimal WDK driver skeleton for the KSword sandbox R0 event path.

## Purpose

This project creates the kernel-side control device that the future
`KSword.Sandbox.R0Collector` will open from the Windows 10 guest VM. The current
driver is intentionally small: it validates the load/unload path, exposes a
stable symbolic link, implements health/poll IOCTLs, keeps a bounded non-paged
event ring for `READ_EVENTS`, and starts minimal file plus WFP/ALE network
producers.

## Current ABI

Public names and structures are defined in:

```text
include/KSwordSandboxDriverIoctl.h
```

The driver creates:

- NT device: `\Device\KSwordSandboxDriver`
- DOS device link: `\DosDevices\KSwordSandboxDriver`
- Win32 path for user mode: `\\.\KSwordSandboxDriver`

Initial IOCTLs:

- `IOCTL_KSWORD_SANDBOX_GET_HEALTH`
  - Input: none.
  - Processing: snapshots skeleton state and queue counters.
  - Return: `KSWORD_SANDBOX_HEALTH_REPLY`.
- `IOCTL_KSWORD_SANDBOX_POLL`
  - Input: none.
  - Processing: snapshots the ring counters and reports whether events are
    currently queued.
  - Return: `KSWORD_SANDBOX_POLL_REPLY`.
- `IOCTL_KSWORD_SANDBOX_READ_EVENTS`
  - Input: optional `KSWORD_SANDBOX_READ_EVENTS_REQUEST`.
  - Processing: validates the request, computes how many complete records fit in
    the caller's output buffer, and drains that many records from the fixed
    non-paged ring under the driver spin lock.
  - Return: `KSWORD_SANDBOX_READ_EVENTS_REPLY` with `EventsWritten`,
    `BytesWritten`, `EventsDropped`, and `NextSequence` set. The trailing
    `Events` stream contains zero or more records, each starting with
    `KSWORD_SANDBOX_EVENT_HEADER`.

## Current event behavior

The ring is a fixed-size array in the device extension, so it is allocated with
the WDM device object and remains non-paged. `DriverEntry` queues one typed
`KswSandboxEventTypeDriverLoad` self-test event with
`KSWORD_SANDBOX_EVENT_FLAG_SELF_TEST` and
`KSWORD_SANDBOX_EVENT_FLAG_DRIVER_STARTED`. Collectors can treat this as the
minimal `driver.load` heartbeat to verify the device, IOCTL number, and event
framing before consuming telemetry producers.

The driver also registers a minimal minifilter for `CREATE`, `WRITE`, and
delete-style `SET_INFORMATION` operations. File callbacks emit
`KswSandboxEventTypeFile` records into the same `READ_EVENTS` stream. Each file
payload is bounded to `KSWORD_SANDBOX_EVENT_MAX_PAYLOAD_SIZE` and carries the
operation, requestor PID, final NTSTATUS, IRP major/minor function, path flags,
and a truncated UTF-16 path prefix copied from `FILE_OBJECT.FileName`.

The network producer registers inspect-only WFP/ALE connect and recv-accept
callouts for IPv4 and IPv6. It does not block, absorb, redirect, or modify
traffic; it queues compact `KswSandboxEventTypeNetwork` records into the same
ring for R0Collector to drain.

When the ring is empty, `READ_EVENTS` still succeeds if the fixed reply header
fits and returns `EventsWritten == 0` and `BytesWritten == 0`. If the output
buffer has no room for a complete pending record, the event remains queued and
the call also returns an empty batch rather than writing a partial record.

## Build requirements

Build only on a machine with Visual Studio C++ tooling and WDK installed:

```powershell
& 'D:\Software\VS\MSBuild\Current\Bin\MSBuild.exe' `
  'D:\Projects\KswordSandbox\driver\KSword.Sandbox.Driver\KSword.Sandbox.Driver.vcxproj' `
  /p:Configuration=Debug /p:Platform=x64 /m:1 /v:minimal
```

Driver loading requires the normal Windows driver-signing path. For a lab VM,
use a test certificate and test-signing mode as documented in
`docs/driver-signing.md`. The project defaults to `SignMode=Off` so local source
builds do not try to create or install a certificate automatically. Sign the
generated `.sys` explicitly outside git before loading it in a VM.

## Runtime validation preflight

Before a real VM test, run the non-destructive readiness checks from an elevated
PowerShell session in the guest or staging VM:

```powershell
.\scripts\Test-R0Readiness.ps1 `
  -DriverSysPath C:\KSwordSandbox\driver\KSword.Sandbox.Driver.sys `
  -R0CollectorPath C:\KSwordSandbox\tools\KSword.Sandbox.R0Collector.exe
```

Default mode checks only repository files, driver/collector readability, driver
signature metadata, Administrator status, Windows `testsigning` state, and
read-only SCM service state. It does **not** load the driver, open
`\\.\KSwordSandboxDriver`, write JSONL, or mutate service state.

Service install/load and device checks are explicit opt-in steps for an isolated
test VM:

```powershell
.\scripts\Test-R0Readiness.ps1 `
  -DriverSysPath C:\KSwordSandbox\driver\KSword.Sandbox.Driver.sys `
  -R0CollectorPath C:\KSwordSandbox\tools\KSword.Sandbox.R0Collector.exe `
  -AllowServiceMutation `
  -InstallService `
  -StartService `
  -CheckDeviceHealth `
  -DrainWithCollector `
  -CollectorOutputPath C:\KSwordSandbox\out\driver-events.jsonl
```

Unload and remove the kernel service explicitly when finished:

```powershell
.\scripts\Test-R0Readiness.ps1 `
  -AllowServiceMutation `
  -StopService `
  -DeleteService
```

## Repository hygiene

Commit only source, project files, headers, and documentation. Do not commit:

- `.sys`
- `.pdb`
- `.obj`
- `.lib`
- `.exe`
- generated `bin/` or `obj/` folders
- certificates or private keys

## Next implementation steps

1. Extend file-monitor coverage beyond the current create/write/delete slice
   only after the collector parser and VM load path are validated.
2. Add process, image-load, registry, and network events after the file event
   path is stable.
3. Keep user-mode JSON serialization in `KSword.Sandbox.R0Collector`; the driver
   should return compact typed records, not JSON strings.
