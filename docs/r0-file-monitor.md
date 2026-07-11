# R0 file monitor contract

中文优先说明：本文描述 R0 file minifilter 当前输出的文件行为证据。Driver 只把紧凑的
post-operation metadata 写入 `READ_EVENTS` ring；它不阻断、不修改用户 I/O，也不在内核中给出
“恶意/良性”结论。`operationName`、`statusHex`、path provenance、drop-file labels 和
self-noise labels 都是 evidence labels，最终 verdict 应由 host rules/report 在合并更多证据后生成。

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
operation `NTSTATUS` observed by the minifilter.  Failed operations also set
`KSWORD_SANDBOX_FILE_EVENT_FLAG_OPERATION_FAILED`, which lets rules distinguish
failed probes from successful writes/deletes without reinterpreting NTSTATUS.

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
- `KSWORD_SANDBOX_FILE_EVENT_FLAG_DELETE_INTENT`: the operation was normalized
  from a disposition-style `SET_INFORMATION`.
- `KSWORD_SANDBOX_FILE_EVENT_FLAG_RENAME_INTENT`: the operation was normalized
  from a rename/link-style `SET_INFORMATION`.
- `KSWORD_SANDBOX_FILE_EVENT_FLAG_OPERATION_FAILED`: the post-operation status
  was a failure.

Older collectors that do not know the new bits still preserve them in `flagsHex`
and unknown flag diagnostics.

中文：path flags 只说明“路径是否存在、是否被截断、来源是 normalized name 还是
`FILE_OBJECT.FileName` fallback”。它们不证明文件内容已复制、hash 已计算，也不证明 drop
成功；需要结合 user-mode snapshot/hash evidence 才能形成 artifact-level 结论。

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

中文：self-path filtering 是降噪策略，不是访问控制或信任判定。被抑制路径说明它匹配
KSword infrastructure 片段；未被抑制的文件事件也只是可观察行为证据，不能单独等同于恶意。

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

中文：`dropEvidenceKind`、`dropConfidence` 和 `dropReason` 是 drop-file 证据标签，
不是最终 verdict。`dropConfidence=high` 仍只表示“规则认为该事件更像落地文件证据”；
它不替代 hash、size、artifact capture、process lineage、registry/network correlation 等后续证据。
如果 `READ_EVENTS` ring 出现 loss/backpressure，host 应同时展示 common queue counters 和
sequence gap 证据，避免把缺失事件误解释为样本没有文件行为。
