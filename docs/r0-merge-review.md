# R0 Driver Merge Review

Date: 2026-07-10
Project baseline: D:\Projects\KswordSandbox at babd9f95f6f36c98754b0d2e4bc8a4daabb2482b.

## Reviewed candidate worktrees

- process/image: C:\Users\Administrator\.codex\worktrees\6387\KswordSandbox
- file minifilter: C:\Users\Administrator\.codex\worktrees\c3a6\KswordSandbox
- registry callback: C:\Users\Administrator\.codex\worktrees\3435\KswordSandbox

All three candidates are based on the same commit as the main repository.  The
main repository currently has unrelated dirty work, including
`docs/r0-collector.md`; the driver tree itself is clean in main before merging.

## Direct apply status against current main worktree

- process/image: direct `git apply --check` succeeds as a whole patch.
- file minifilter: direct `git apply --check` succeeds as a whole patch.
- registry callback: whole patch does not apply because `docs/r0-collector.md`
  is already modified in main.  The registry driver-only patch applies cleanly
  against current main, but it will not apply cleanly after either driver
  producer patch is merged.

Pairwise dry-run checks show that no candidate can be directly stacked on top of
another candidate without conflicts.  After the first patch is applied, the
remaining driver patches require manual integration.

## Conflict files

- `driver/KSword.Sandbox.Driver/include/KSwordSandboxDriverIoctl.h`
  - All three candidates insert new public payload ABI near the existing event
    definitions and after `KSWORD_SANDBOX_DRIVER_LOAD_PAYLOAD`.
  - file minifilter also wraps the public `ntddk.h` include for `__FLTKERNEL__`
    compatibility.
  - ABI event type numbers do not collide: process/image uses existing Process
    and Image event types, file uses File, registry uses Registry.  The conflict
    is textual placement and payload-layout consolidation, not numeric IOCTL or
    event-header overlap.

- `driver/KSword.Sandbox.Driver/src/Driver.h`
  - file minifilter changes the internal include from `ntddk.h` to
    `fltKernel.h`, adds minifilter instance constants, adds
    `KSWORD_SANDBOX_FILE_FILTER_RUNTIME`, and declares file filter init/uninit.
  - process/image replaces `EventReserved` with `CallbackRegistrationFlags` and
    adds process/image callback bit flags.
  - registry inserts `RegistryCallbackCookie`, `RegistryCallbackRegistered`, and
    padding fields in the same `KSWORD_SANDBOX_DEVICE_EXTENSION` area.
  - Manual merge should keep one combined device extension containing callback
    flags and registry fields; do not preserve `EventReserved` if it has been
    repurposed.

- `driver/KSword.Sandbox.Driver/src/Driver.c`
  - All candidates insert C_ASSERT/global callback state at the top of the file.
  - process/image and file both add `KswSetLastStatus`; keep the file version or
    another version with NULL/signature validation, then use it from all producer
    registration paths.
  - process/image adds `KswMarkDriverStopping`, `KswIsDriverRunning`, a global
    control device pointer, process notify, image notify, and combined
    process/image registration cleanup.
  - file minifilter adds FltMgr operation registration, service-key instance
    self-healing helpers, file path copy, file event queueing, and
    `KswInitializeFileFilter` / `KswUninitializeFileFilter`.
  - registry adds registry payload capture helpers, `CmRegisterCallbackEx`, and
    registry unregister logic.
  - All candidates edit `DriverEntry` and `KswDriverUnload`; the final code must
    sequence all registrations and all unregister paths explicitly.
  - process/image renames `KswDrainEventHeaders` to `KswDrainEvents`; file and
    registry leave the old name.  Pick one name during manual merge.

- `driver/KSword.Sandbox.Driver/README.md`
  - process/image and file both update the same current-event-behavior and next
    steps sections.  Combine text manually.

- `driver/KSword.Sandbox.Driver/KSword.Sandbox.Driver.vcxproj`
  - file minifilter only.  Keep `FltMgr.lib` in Debug and Release linker
    dependencies if the file minifilter is merged.

- `docs/r0-collector.md`
  - registry callback only among candidates, but main already has dirty changes
    in this file.  Merge this documentation manually or defer it; do not apply
    the registry whole patch over current main.

## Duplicate or overlapping helpers

- `KswSetLastStatus`: duplicated by process/image and file.  Use one shared
  helper with validation.
- Bounded Unicode copy helpers:
  - process/image: `KswCopyUnicodeStringToFixedBuffer`
  - file: `KswCopyFilePathToPayload`
  - registry: `KswCopyUnicodePrefix`
  These are similar but have different output metadata.  They can remain local,
  but reviewers should verify each path stays nonblocking and bounded.
- Driver stop handling:
  - process/image adds `KswMarkDriverStopping`.
  - registry keeps inline spin-lock state update.
  Prefer the shared helper in the final tree.
- Producer registration state:
  - process/image stores bit flags in the device extension.
  - file stores state in `g_KswFileFilterRuntime`.
  - registry stores cookie/registered fields in the device extension.
  Keep all three, but ensure unload clears/stops producers before deleting the
  symbolic link and device object.

## ABI consolidation notes

- Preserve `KSWORD_SANDBOX_EVENT_HEADER` and `READ_EVENTS` unchanged.
- Add all payload structs under existing event types; no new IOCTL is needed.
- Keep every payload under `KSWORD_SANDBOX_EVENT_MAX_PAYLOAD_SIZE` and retain
  C_ASSERT coverage for file, process, image, and registry payloads.
- Keep bounded path/name lengths from each candidate unless the collector ABI is
  intentionally revised.
- The current collector can drain unknown payload bytes by `header.Size`, but
  typed JSON decoding will need a later collector update.

## Recommended merge order

1. Merge file minifilter first.
   - It is the only patch that changes the WDK project to link `FltMgr.lib` and
     changes internal headers to `fltKernel.h`.
   - Its direct patch applies cleanly to current main.
   - It provides the more defensive `KswSetLastStatus` helper and keeps the
     control device alive if minifilter registration fails.

2. Manually integrate process/image second.
   - Do not direct-apply on top of file minifilter.
   - Preserve file's `fltKernel.h`, `FltMgr.lib`, file filter runtime, and
     `KswSetLastStatus` helper.
   - Add process/image payload ABI, C_ASSERTs, global control device pointer,
     process/image callbacks, callback flags, and unload unregister path.
   - Reconcile `DriverEntry` so process/image registration does not discard the
     file minifilter cleanup path on failure.

3. Manually integrate registry callback third.
   - Do not direct-apply the whole registry patch while main has
     `docs/r0-collector.md` dirty.
   - Merge driver ABI and callback code after the file and process/image state is
     combined.
   - Decide whether registry registration should be fatal.  The candidate fails
     `DriverEntry` on `CmRegisterCallbackEx` failure; for parity with file
     minifilter and to protect the control device path, consider recording
     `LastStatus` and keeping the driver loaded.

## Suggested commands for the main thread

Check and apply the first direct patch:

```powershell
git -C C:\Users\Administrator\.codex\worktrees\c3a6\KswordSandbox diff --binary HEAD -- |
  git -C D:\Projects\KswordSandbox apply --check -

git -C C:\Users\Administrator\.codex\worktrees\c3a6\KswordSandbox diff --binary HEAD -- |
  git -C D:\Projects\KswordSandbox apply -
```

Use these as review inputs for manual integration of the remaining patches:

```powershell
git -C C:\Users\Administrator\.codex\worktrees\6387\KswordSandbox diff --binary HEAD -- driver\KSword.Sandbox.Driver

git -C C:\Users\Administrator\.codex\worktrees\3435\KswordSandbox diff --binary HEAD -- driver\KSword.Sandbox.Driver

git -C C:\Users\Administrator\.codex\worktrees\3435\KswordSandbox diff --binary HEAD -- docs\r0-collector.md
```

After manual integration, verify source hygiene and build:

```powershell
git -C D:\Projects\KswordSandbox diff --check -- driver\KSword.Sandbox.Driver docs\r0-collector.md

$arguments = @(
  'driver\KSword.Sandbox.Driver\KSword.Sandbox.Driver.vcxproj',
  '/t:Build',
  '/p:Configuration=Debug',
  '/p:Platform=x64',
  '/m:1',
  '/v:minimal'
)
$process = Start-Process -FilePath 'D:\Software\VS\MSBuild\Current\Bin\MSBuild.exe' `
  -ArgumentList $arguments -NoNewWindow -Wait -PassThru -UseNewEnvironment
exit $process.ExitCode
```
