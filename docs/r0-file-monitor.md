# R0 file monitor contract

This note captures the current R0 minifilter file-telemetry contract for the
KSword sandbox driver. It is intentionally narrower than a full DLP/auditing
filter: the driver emits compact evidence into the existing `READ_EVENTS` ring
and does not block or modify user I/O.

## Covered operations

`driver/KSword.Sandbox.Driver/src/Producers/File/FileFilter.c` registers post
callbacks for these major operations:

- `IRP_MJ_CREATE` -> `KswSandboxFileOperationCreate`
- `IRP_MJ_READ` -> `KswSandboxFileOperationRead`
- `IRP_MJ_WRITE` -> `KswSandboxFileOperationWrite`
- `IRP_MJ_SET_INFORMATION` -> one of:
  - `KswSandboxFileOperationRename` for `FileRenameInformation` and
    `FileRenameInformationEx`
  - `KswSandboxFileOperationDelete` for `FileDispositionInformation` and
    `FileDispositionInformationEx`
  - `KswSandboxFileOperationSetInformation` for other metadata updates
- `IRP_MJ_CLEANUP` -> `KswSandboxFileOperationCleanup`
- `IRP_MJ_CLOSE` -> `KswSandboxFileOperationClose`

Every emitted file payload is queued from the post-operation callback and sets
`KSWORD_SANDBOX_FILE_EVENT_FLAG_STATUS_PRESENT` plus
`KSWORD_SANDBOX_FILE_EVENT_FLAG_POST_OPERATION`, so `Status` is the final
operation `NTSTATUS` observed by the minifilter.

## Path normalization and truncation

The payload stays ABI-compatible: `KSWORD_SANDBOX_FILE_EVENT_PAYLOAD` remains a
fixed 128-byte record with the existing inline UTF-16 `Path` buffer.

Path capture order:

1. Prefer `FltGetFileNameInformation` with `FLT_FILE_NAME_NORMALIZED` and the
   default query policy.
2. If that is unsafe or unavailable, retry normalized lookup with
   `FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP`.
3. If no normalized name is available, fall back to `FILE_OBJECT.FileName`.

The producer marks path provenance with compatible flag bits:

- `KSWORD_SANDBOX_FILE_EVENT_FLAG_PATH_PRESENT`: `PathLengthBytes` and `Path`
  contain a bounded UTF-16 path prefix.
- `KSWORD_SANDBOX_FILE_EVENT_FLAG_PATH_TRUNCATED`: the source name exceeded the
  fixed payload buffer.
- `KSWORD_SANDBOX_FILE_EVENT_FLAG_PATH_NORMALIZED`: the path came from FltMgr
  normalized-name resolution.
- `KSWORD_SANDBOX_FILE_EVENT_FLAG_PATH_FALLBACK`: the path came from
  `FILE_OBJECT.FileName` fallback.

Older collectors that do not know the new bits still preserve them in `flagsHex`
and unknown flag diagnostics.

## Sandbox self-path filtering

The filter suppresses known KSword infrastructure noise after path resolution and
before `KswPushEvent`. The decision is made against the full normalized or
fallback source path before the bounded payload path is truncated. The static
policy is intentionally path-based and does not trust process identity as an
authorization boundary.

Suppressed path fragments are case-insensitive:

- `\KSwordSandbox\agent\`
- `\KSwordSandbox\r0collector\`
- `\KSwordSandbox\driver\`
- `\KSwordSandbox\out\`
- `\KSwordSandboxDriver`

The policy keeps `\KSwordSandbox\incoming\` observable so sample staging and
sample-created files can still generate evidence. `out` is reserved for sandbox
telemetry/artifact output; malware drops there may be intentionally hidden by
this self-noise policy and should be revisited if samples are allowed to write
sandbox output paths.

## Drop-file evidence field design

The driver payload is intentionally compact. Drop-file classification should be
performed in the collector/host layer by combining file events with guest file
snapshot/hash evidence rather than expanding the kernel payload.

Recommended string-valued `SandboxEvent.Data` keys for future collector/host
normalization:

- `operationName`: `create`, `write`, `read`, `rename`, `delete`, `setInformation`,
  `cleanup`, or `close`.
- `filePath`: top-level subject path copied from the driver payload.
- `pathPresent`, `pathTruncated`, `pathNormalized`, `pathFallback`.
- `statusHex`, `postOperation`, `majorFunction`, `minorFunction`.
- `dropEvidenceKind`: `create`, `write`, `renameTarget`, `deleteDisposition`, or
  `snapshotOnly`.
- `dropConfidence`: `low`, `medium`, or `high`.
- `dropReason`: short rule-readable reason, for example
  `create-success`, `write-success`, `rename-into-watch-root`, or
  `snapshot-new-file`.
- `firstSeenSequence`, `lastSeenSequence`: R0 event sequence range supporting
  the evidence.
- `firstWriteStatusHex`, `lastWriteStatusHex`: final status evidence for write
  activity.
- `sizeBytes`, `sha256`, `artifactId`: populated by user-mode artifact capture
  when the file can be safely copied and hashed.

Host rules should treat a successful create/write/rename event as behavioral
signal and require artifact hash/size fields only when a concrete dropped-file
artifact is available.
