# Guest artifacts

Canonical scope: this page describes guest artifact lanes, host discovery, and
operator import behavior. The manifest/index schema source of truth is
`docs/artifact-manifest.md`; report rendering and UX are covered by
`docs/report-schema.md` and `docs/report-ux.md`.

Generated artifacts are runtime evidence. Do not commit guest output folders,
`artifacts/manifest.json`, `artifact-index.json`, screenshots, memory dumps,
packet captures, dropped files, reports, samples, payload binaries, or VM
outputs.

Guest artifact collection is intentionally opt-in for high-sensitivity evidence.
The stable guest output root is the directory passed with `--out`.

中文说明：高敏证据默认安全关闭，需要显式 opt-in。本文中的
`relativePath`、`safeLink`、`importPath`、`collectionName`、`captureState`、
`status`、`reason` 等都是稳定 schema 字段/值，不翻译；中文提示通过事件或
manifest metadata 中的 `zhMessage`、`zhHint`、`zhStatus`、`zhReason` 表达。

## Layout

- `events.json` and `agent-summary.json` are always written.
- `artifacts/manifest.json` is always written as a safe evidence index. It can
  contain zero file artifacts when every sensitive collection lane is disabled.
- `screenshots/*.bmp` is written only when `--screenshot` is supplied and the
  guest desktop can be captured. The default screenshot cadence is
  `before,during,after`; `--screenshot-phases` and `--screenshot-count` can
  narrow stages or capture multiple images per stage.
- `memory-dumps/*.dmp` is written only when `--memory-dump` or
  `--memory-dumps` is supplied. The current guest agent captures the sample
  root process early and then performs a final visible root/child process sweep
  so child processes can also produce dump artifacts.
- `artifacts/dropped-files/**` is written only when `--collect-dropped-files`
  or `--dropped-files` is supplied.
- `packet-captures/*.pcapng` is written only when `--packet-capture`, `--pcap`,
  or `--network-capture` is explicitly supplied and Windows `pktmon` can start
  capture inside the guest. Existing external `.pcap` / `.pcapng` files remain
  consumable by the host importer.

中文：截图、内存转储、掉落文件复制和抓包都可能包含敏感内容，因此默认不
采集。禁用通道会写出 disabled 状态或 manifest metadata，方便区分“未请求”
和“请求了但失败/跳过”。

## Host discovery contract

Host-side discovery treats the collected guest output root as the only link
root. `GuestOutputLocator.EnumerateArtifacts` and `HostArtifactIndexBuilder`
classify the same stable lanes:

- `events.json`: `kind=GuestEventsJson`, `category=telemetry`,
  `evidenceRole=guest-events`, `collectionName=guest-events`,
  `telemetryFormat=json`.
- `driver-events.jsonl` and driver-named JSONL fallbacks:
  `kind=DriverEventsJsonLines`, `category=telemetry`,
  `evidenceRole=driver-events`, `collectionName=driver-events`,
  `telemetryFormat=jsonl`.
- `artifacts/manifest.json`: `kind=ArtifactManifest`,
  `evidenceRole=artifact-manifest`, `collectionName=artifact-manifests`.
- `screenshots/**`: `kind=Screenshot`, `evidenceRole=screenshot`,
  `collectionName=screenshots`, with phase inferred from file names such as
  `before-start`, `after-start`, or `after-run`.
- `memory-dumps/**`: `kind=MemoryDump`, `evidenceRole=memory-dump`,
  `collectionName=memory-dumps`, MIME type
  `application/vnd.microsoft.minidump`.
- `packet-captures/**/*.pcap` and `*.pcapng`: `kind=PacketCapture`,
  `evidenceRole=packet-capture`, `collectionName=packet-captures`,
  `captureSource=external`, `hostCaptureStarted=false`, and
  `importMode=external-artifact`.
- `artifacts/dropped-files/**` and other non-manifest files under
  `artifacts/**`: `kind=DroppedFile`, `evidenceRole=dropped-file`,
  `collectionName=dropped-files`.

Descriptors expose `relativePath`, URL-segment encoded `safeLink`, and
`importPath` as browser/download selectors. `fullPath`, `guestPath`,
`indexRoot`, and event source paths are metadata or copy-only diagnostics; they
must never be placed directly in `href` or `src` attributes. Manifest and
collection normalization rejects absolute, drive-qualified, or traversal
`safeLink` values and rebuilds links from safe paths under the collected guest
output root.

中文：Host 只把 guest 输出根目录下的相对 selector 作为下载链接依据；
`fullPath`、`guestPath`、源事件路径等仅是诊断元数据，不能直接进入 href/src。

## Host import and downloadable index

The host writes `artifact-index.json` as the downloadable artifact index. Each
downloadable artifact entry carries host-computed `sizeBytes`, `sha256`,
`hashes.sha256`, `kind`, `collectionName`, `evidenceRole`, `relativePath`,
`safeLink`, `importPath`, and source-event metadata when guest telemetry or a
manifest pointed at the file. Download clients must use `relativePath`,
`safeLink`, or `importPath` as selectors; absolute host and guest paths remain
diagnostic metadata only.

For WebUI download UX, host descriptors also carry presentation and safety
metadata: `previewLabel`, `previewLabelZh`, `contentType`,
`downloadContentType`, `downloadFileName`, `downloadSelector`,
`downloadSafeLink`, `sizeDisplay`, `sha256Short`, `isDownloadable`, and the
`downloadSecurityPolicy=server-indexed-relative-selector` /
`downloadRejectionPolicy=reject-empty-absolute-traversal-unindexed-missing`
contract. These fields are derived from the host-side index and are safe for
browser DTOs; they are not new filesystem authority.

Duplicate artifacts are grouped by host-computed SHA-256 plus byte size. Index
metadata records `duplicateGroupKey`, `duplicateGroupId`,
`duplicateGroupCount`, `duplicateOrdinal`, `duplicateRole`,
`duplicatePrimarySelector`, `duplicatePrimarySafeLink`,
`duplicateOfArtifactRelativePath`, and `duplicateGroupMemberSelectors`. The
first stable relative path in the group is the primary; later entries remain
downloadable but are marked as duplicates so UI/report surfaces can collapse or
label repeated dropped files, screenshots, dumps, or captures.

If a guest manifest declares an unsafe, absolute, traversal, missing, or
otherwise non-downloadable artifact reference, the host does not turn it into a
link. Instead, collection metadata records `rejectionDiagnosticsAvailable`,
`rejectedArtifactCount`, `lastRejectedArtifactReason`,
`lastRejectedArtifactName`, `lastRejectedArtifactSelector`,
`lastRejectedArtifactKind`, `artifactRejectionReasons`, and `zhRejectionHint`.
This keeps operator diagnostics visible while preserving the invariant that
only existing files under the job output root can be streamed.

During report import, the host also emits `artifact.host_imported` rows for
downloadable dropped files, screenshots, memory dumps, and packet captures.
Those rows record `sourceArtifactKind`, `sourceArtifactRelativePath`,
`sourceArtifactSizeBytes`, `sourceArtifactSha256`, `collectionName`,
`sourceEventType`, `sourceEventPath`, `importMode=host-artifact-index`, and
`behaviorCounted=false`. These rows are evidence-chain / download metadata and
must not be interpreted as sample behavior by rules or UI behavior counts.

When a requested or guest-declared sensitive collection has no downloadable
file, host import emits a `collection.health` diagnostic instead of fabricating
behavior. The diagnostic keeps stable English machine fields such as
`collectionName`, `artifactKind`, `status`, `reason`, `healthStatus`, and
`artifactMissing=true`, plus Chinese operator fields `zhMessage` and `zhHint`.
This makes missing dropped-files/screenshots/pcap/memory-dump evidence visible
without turning collection gaps into malicious behavior.

中文：Host 导入会把可下载的掉落文件、截图、内存转储和抓包写入
`artifact-index.json`，并在报告事件中补充 `artifact.host_imported` 溯源行。
这些行包含大小、SHA-256、类型、集合名和来源事件，但 `behaviorCounted=false`；
它们用于下载和审计，不算样本行为。若请求或清单声明了某个敏感集合但没有产物，
Host 会生成 `collection.health` 中文健康诊断（含 `zhMessage`/`zhHint`），提示
采集缺口，同样不算行为。

## Dropped-files manifest

When dropped-file collection is enabled, newly-created files under the sample
working directory are copied to `artifacts/dropped-files/**`. The guest then
writes `artifacts/manifest.json` using `ArtifactManifest` /
`ArtifactDescriptor` entries with `kind=DroppedFile`, `category=dropped-file`,
`evidenceRole=dropped-file`, `collectionName=dropped-files`, safe relative
links, `importPath`, file size, MIME type, SHA-256, and metadata preserving the
original VM-local path.

Copied dropped-file artifact descriptors always carry
`artifactRelativePath`, `relativePath`, `collectionName=dropped-files`,
`evidenceRole=dropped-file`, and `captureState=captured`. Copied and skipped
copy-attempt events use the same status shape: `captureEnabled`,
`implemented`, `captureState`, `status`, `nonfatal`, `collectionName`, and
`evidenceRole`. Captured dropped-file events include copied artifact
`sha256`/`artifactSha256`, `copiedSha256`, `sourceSha256` when readable,
source/copied sizes, source/copied mtimes, `copiedAtUtc`,
`phase`/`capturePhase`, `processRole`, `rootProcessId`, root `treeLineage`,
and `zhMessage`/`zhHint` for report copy. Skipped and disabled rows keep the
same phase/process/localized diagnostic shape even when no artifact file is
created.

Skipped copy attempts are nonfatal and keep a compact `reason` such as
`sourcePathMissing`, `sourcePathInvalid`, `sourceFileMissing`,
`outsideWorkingDirectory`, `underOutputDirectory`, `destinationPathInvalid`,
or `copyFailed`. When available, skipped events preserve `sourceExists`,
source size/mtime, source-event size/mtime, and best-effort hash status such
as `sourceHashStatus=failed` without failing the run. Collection metadata
keeps `lastReason` and last source/hash diagnostics so a run with no copied
files is diagnosable. When dropped-file collection is not requested, the guest
emits `artifact.dropped_file.disabled`.

中文：掉落文件复制事件保留机器可解析 `reason`，同时可带 `zhHint` 说明跳过
原因，例如源文件已消失、越出工作目录、位于输出目录或复制失败。

The manifest never trusts VM-local absolute paths for links. The host resolves
`relativePath` under the collected guest-output directory and keeps original
paths as metadata only.

## User-mode behavior snapshots

Several no-R0 evidence sources are represented as `events.json` rows rather
than separate files. They still use stable field names so host reports can link
findings back to raw guest telemetry:

- Process snapshots emit `process.snapshot` rows for each sampled visible
  process at `before-start`, `after-start`, and `after-run`. Rows preserve
  `snapshotKey`, `processId`, `parentProcessId`, `processName`,
  `commandLine`, `imagePath` / `processImagePath`, `startTimeUtc`,
  parent snapshot metadata, and root-relative `treeDepth` / `treeLineage`
  when the process belongs to the sample tree. Tracked root/tree/new
  processes that disappear from later snapshots are represented by
  `process.snapshot` rows with `snapshotState=status=captureState=missing`,
  `processMissing=true`, `exitMissing=true`, `missingAtUtc`, and
  first/last-seen phase metadata.
- Process tree snapshots still emit `process.tree` rows for the sample root
  and visible descendants, with `rootProcessId`, `parentProcessId`,
  `treeDepth`, `treeLineage`, and `childProcessCount` metadata. If the root
  has already exited, the guest keeps `process.tree_unavailable` and can still
  emit visible orphan child rows whose parent PID is the root process.
- Each root sweep emits `process.tree.summary` with stable aggregate fields
  such as `rootProcessId`, `rootVisible`, `visibleProcessCount`,
  `directChildProcessCount`, `maxTreeDepth`, `orphanedChildProcessCount`,
  `missingProcessCount`, root image/command-line metadata, and
  `summaryEvent=true` for report process-tree rendering.
- Persistence diffs emit `service.*`, `scheduled_task.*`,
  `startup_item.*`, and `registry.run.*` rows. Service rows include registry
  configuration metadata such as `imagePath`, `startType`, `serviceType`,
  `objectName`, and `serviceDll` when readable.
- DNS/proxy context emits `dns.cache.*`, `network.hosts.*`, and
  `network.proxy.*` rows. Hosts snapshots keep source path, existence,
  line/entry counts, content-change state, and bounded address/hostname row
  deltas. Proxy snapshots cover process environment variables, HKCU Internet
  Settings, and WinHTTP proxy state with stable `source|scope|settingName`
  keys and value hashes.

## Driver JSONL and R0 sidecar logs

When `--driver-events <path>` is supplied, `driver-events.jsonl` is treated as
durable telemetry, not just an input used to enrich `events.json`. R0 sidecar
supervision events record both absolute diagnostic paths for evidence and
output-relative selectors such as `driverEventsRelativePath`,
`jsonlRelativePath`, `stdoutRelativePath`, and `stderrRelativePath`. The guest
manifest and host index use those relative selectors to attach metadata to
`driver-events.jsonl` and `r0collector.*.log` without ever turning VM-local or
host-local absolute paths into browser hrefs.

The host classifies `driver-events.jsonl` as
`kind=DriverEventsJsonLines`, `category=telemetry`,
`evidenceRole=driver-events`, `collectionName=driver-events`, and
`telemetryFormat=jsonl`. R0 diagnostic files named `r0collector.*.log` are
classified as `kind=Log`, `evidenceRole=diagnostic-log`, and
`collectionName=r0-logs`. Both file types receive host-computed `sizeBytes`,
MIME type, SHA-256, and `hashes.sha256`.

中文：R0 sidecar 的 stdout/stderr 日志和 `driver-events.jsonl` 都是证据文件。
启动失败时 stderr 可能包含英文原因与 `zhMessage`/`zhHint` 双语提示。

## Screenshot artifacts

Screenshots are opt-in because they can contain desktop contents unrelated to
the sample. They are best-effort BMP files captured during the configured
`before,during,after` stages, which map to `before-start`, `after-start`, and
`after-run` probe phases. Unsupported or headless sessions emit
`screenshot.skipped` instead of failing the run. Screenshot events carry
`screenshotStage`, `screenshotIndex`, and `screenshotCount` metadata so the
manifest can preserve the configured cadence. The guest manifest and host
artifact index classify files under `screenshots/` as `kind=Screenshot`,
`category=screenshot`, `evidenceRole=screenshot`, and
`collectionName=screenshots`.

Screenshot events also carry `phase`/`capturePhase`, `captureState`,
`status`, `nonfatal`, `expectedRelativePath=screenshots/*.bmp`,
`artifactRelativePath` when a file is created, event-level `sizeBytes` and
`sha256` for captured BMP files, plus `processRole`, `rootProcessId`,
`processId`, and root `treeLineage` when the sample process identity is known.
Captured and skipped rows include `zhMessage`/`zhHint` for report text.
Skipped screenshots preserve `reason`, `diagnosticStage`, optional
`exceptionType`, and optional `win32Error` without failing the run. When
screenshots are not requested, the guest emits one `screenshot.disabled` event with
`captureEnabled=false`, `captureState=status=disabled`,
`implemented=true`, `nonfatal=true`, `collectionName=screenshots`, and
`reason=screenshotNotRequested`.

中文：截图失败或跳过时保留原始 `reason`、`diagnosticStage` 和 `win32Error`；
中文 `zhHint` 用于提示是否是无头会话、GDI 调用失败、权限或输出路径问题。

## Memory dump artifacts

Memory dump capture is **off by default** and requires explicit opt-in with
`--memory-dump` or `--memory-dumps`. The current implementation captures a
`MiniDumpNormal` for the launched sample process during `after-start`, then
captures any still-visible child processes during an `after-run` process-tree
sweep. Dump attempts write under `memory-dumps/*.dmp`.

Dump files can contain credentials or document fragments. Host policy should
enable this option only for jobs where that evidence is required. Capture
failures emit `memory_dump.skipped`; they do not block event, screenshot,
packet-capture, or dropped-file artifact writing. The final
`memory_dump.sweep` event records visible/attempted/captured/skipped counts so
missing dump artifacts are explainable.

The guest manifest and host artifact index classify `memory-dumps/**` files as
`kind=MemoryDump`, `category=memory-dump`, `evidenceRole=memory-dump`, and
`collectionName=memory-dumps`.

Memory dump attempt events carry `phase`/`capturePhase`, `captureState`,
`status`, `nonfatal`, `artifactRelativePath`, event-level `sizeBytes` and
`sha256` for captured dumps, and process identity fields: `processId`,
`rootProcessId`, `parentProcessId`,
`targetProcessName`, `targetProcessPath`, `processRole`, `treeDepth`,
`treeLineage`, `snapshotKey`, and `dumpType`. Skipped attempts preserve
`reason`, `diagnosticStage`, optional `exceptionType`, and optional
`win32Error`; captured/skipped/disabled rows include `zhMessage`/`zhHint`.
Probe timeouts or exceptions are mapped to the `memory-dumps`
collection as nonfatal failed status instead of becoming `enabled-empty`.
When memory dumps are not requested, the guest emits one
`memory_dump.disabled` event with the same disabled status shape. The
`memory_dump.sweep` event remains a summary (`summaryEvent=true`) and is not
counted as captured/skipped/failed collection status.

中文：内存转储失败/跳过不会阻止其他证据写出。中文提示用于区分目标进程已退
出、PID 不可见、`MiniDumpWriteDump` 失败、权限不足或未显式启用。

## Collection lanes and import paths

`artifacts/manifest.json` includes `collections` entries for:

- `dropped-files`
- `screenshots`
- `memory-dumps`
- `driver-events`
- `r0-logs`
- `packet-captures`

Each collection records `enabled`, `implemented`, `status`, `reason`,
`relativePath`, `safeLink`, and `importPath`. Disabled lanes are explicit, so a
host importer can distinguish "not requested" from "requested but unavailable."
Collection metadata also records normalized `requested`/`captureEnabled`,
`capturedCount`, `skippedCount`, `disabledCount`, `failedCount`, and the
corresponding event counters. Disabled lanes have a synthetic
`disabledCount>=1` even when no disabled event was emitted by older agents.
`packet-captures` is an implemented opt-in lane for KSword's guest collector.
When capture is requested but `pktmon` is unavailable, access is denied, or ETL
conversion fails, the lane is marked `skipped` or `failed` and the run
continues. If a manifest or collected folder contains an externally supplied
`.pcap` or `.pcapng`, the host can still import and report it as
`kind=PacketCapture`.

When the host builds `artifact-index.json`, it merges the guest
`artifacts/manifest.json` and nearby `events.json` back into the filesystem
scan. The index keeps host-safe paths, host-computed size, and host-computed
SHA-256 as authoritative link fields, while preserving guest collection
`status`/`reason`, concrete skipped or failed reasons, command diagnostics,
original guest paths, process identity, and memory-dump root/child sweep
metadata in descriptor or collection `metadata`.

Collection metadata preserves nonfatal diagnostics consistently across
dropped files, screenshots, memory dumps, and packet captures. The guest
manifest records counts plus `lastReason`, `lastDiagnosticStage`,
`lastExceptionType`, `lastCommandMessage`, `lastArtifactRelativePath`,
`lastPhase` / `lastCapturePhase`, and `lastProcessId` / `lastRootProcessId`
plus `lastProcessRole`, `lastTreeDepth`, `lastTreeLineage`, and
`lastChildProcessCount` when those values were present on related events.
Last collection state
metadata prefers concrete captured/skipped/disabled/failed events over
ancillary diagnostic summaries. Diagnostic metadata still keeps later nonfatal
details such as dropped-file source hash failures or packet protocol-summary
diagnostics so operators can explain collection health without treating those
diagnostics as sample behavior. For packet captures, concrete evidence is
anchored by `lastArtifactRelativePath` plus
`lastDiagnosticPcapngRelativePath`, `lastDiagnosticPcapngSizeBytes`,
`lastDiagnosticPcapngSha256`, `lastDiagnosticPacketCount`, and
`lastDiagnosticPcapngBlockCount` when those fields are present. Host indexes
also retain guest status aliases such as `guestManifestStatus` /
`guestManifestReason` and `guestCollectionStatus` /
`guestCollectionReason`.

中文：collection metadata 会补充 `zhStatus`、`zhReason`、`zhHint`，并把事件
中的 `zhMessage`/`zhHint` 汇总为 `lastZh*` / `lastDiagnosticZh*`。抓包诊断请
优先看 `lastArtifactRelativePath`、`lastDiagnosticPcapngRelativePath`、
`lastDiagnosticPacketCountStatus`/`lastDiagnosticPacketCount`、
`lastDiagnosticPcapngBlockCount`、`lastDiagnosticPcapngSha256` 等字段；它们
证明具体 PCAPNG 证据或诊断状态，`protocolSummary*` 只说明协议解析是否可用。
这些字段仅用于 UI/报告解释，不参与机器规则判断。

Each file descriptor also carries `evidenceRole`, `capturePhase`,
`captureState`, `guestPath`, `importPath`, and `collectionName` alongside size,
MIME type, and hashes. `guestPath` is evidence only; clickable links and import
paths are derived from safe paths under the collected guest output root.

WebUI download selectors are intentionally redundant and relative:
`relativePath`, `safeLink`, and `importPath` all point under the job output
root. The guarded download endpoint accepts any of those selectors after URL
decoding, but rejects empty, absolute, traversal, missing, or unindexed paths.
`safeLink` URL-encodes path segments for report anchors; API download hrefs use
that selector text as a query value rather than embedding `fullPath`.

The `/api/jobs/{jobId}/artifacts` DTO keeps `fullPath` and other host-local
paths out of the browser response. Each artifact exposes a `Download` block
with `available`, safe selector, guarded href, sanitized filename, content
type, size, SHA-256, short hash, and a rejection code/message when no safe
selector exists. Collection DTOs expose rejection diagnostics separately so
operators can see why a manifest entry was ignored without receiving a
clickable unsafe path.

## Optional packet capture and external import

`--packet-capture`, `--pcap`, and `--network-capture` are explicit opt-in
switches. They start Windows `pktmon` before the sample runs, stop it after the
run, convert the ETL trace with `pktmon etl2pcap`, and write
`packet-captures/*.pcapng` when conversion succeeds. Raw ETL diagnostics stay
under `packet-capture-diagnostics/` and are not treated as packet-capture
artifacts.

Packet capture is still safe-by-default: no sniffer is started unless one of
the opt-in switches is present. Missing `pktmon`, insufficient rights, active
system capture conflicts, stop failures, or conversion failures emit
`packet_capture.skipped` or `packet_capture.failed`; they do not prevent
`events.json`, dropped files, screenshots, memory dumps, or the artifact
manifest from being written. Successful runs emit `packet_capture.started`,
`packet_capture.stopped`, and `packet_capture.captured`.

Packet capture lifecycle events carry `collectionName=packet-captures`,
`evidenceRole=packet-capture`, `phase`/`capturePhase`, `status`,
`captureState`, `nonfatal`, `expectedRelativePath=packet-captures/*.pcapng`,
and `artifactRelativePath` for the final PCAPNG path. Captured PCAPNG rows
also carry event-level `sizeBytes`, `sha256`, `processRole`, `rootProcessId`,
root `treeLineage`, and `zhMessage`/`zhHint`. ETL diagnostics are separate
from the packet artifact and use `etlRelativePath` /
`diagnosticRelativePath`. Events also include explicit `pcapngPath`,
`pcapngRelativePath`, `packetCaptureRelativePath`, and
`sourceArtifactRelativePath` when a PCAPNG path is known. Start/stop/convert
command failures retain `reason`, command exit/timeout details, and
`commandMessage`; a failed `pktmon start` is reported as
`packet_capture.failed`, while unavailable or not-started cases remain
`packet_capture.skipped`. When packet capture is not requested, the guest emits
one `packet_capture.disabled` event with
`captureEnabled=false`, `captureState=status=disabled`, and
`reason=packetCaptureNotRequested`.

中文优先提示：`packet_capture.protocol_summary` 是抓包诊断摘要，不是
DNS/HTTP/TLS 行为证据。看到 `protocolSummaryAvailable=false`、
`protocolSummaryState=capture-metadata-only`、
`protocolSummaryReason=protocolParserNotImplemented` 时，表示 PCAPNG 已采集，
但内置协议摘要解析尚未接入；请用 `artifactRelativePath` 下载 PCAPNG，并用
`sizeBytes`/`pcapngSizeBytes`、`sha256`/`pcapngSha256`、`packetCount`、
`packetCountStatus`、`pcapngBlockCount`、`pcapngEnhancedPacketBlockCount`、
`pcapngSimplePacketBlockCount`、`pcapngSectionHeaderCount` 校验证据是否具体。

After a successful PCAPNG conversion, the guest also emits
`packet_capture.protocol_summary` as a capture-metadata diagnostic row. The
row remains for schema/report compatibility with protocol-summary consumers
until inline protocol parsing is integrated. It is tied to concrete PCAPNG/ETL
paths with `protocolSummaryAvailable=false`,
`protocolSummaryState=capture-metadata-only`,
`protocolSummaryStatus=skipped`,
`protocolSummaryReason=protocolParserNotImplemented`,
`protocolSummaryFormat=capture-metadata`, and
`protocolsObserved=not-parsed`; it does not fabricate protocol findings,
change the packet-capture collection from `captured`, or count as sample
behavior.

中文：抓包通道默认不启动。`pktmon` 启动/停止/转换失败会保持英文 reason code
并附加中文 `zhHint`；协议摘要诊断只说明解析能力和文件健康状态，具体证据由
路径、大小、哈希和 PCAPNG packet/block 计数字段证明。

For import/report purposes, existing packet captures are regular artifacts:

- guest manifests can reference `packet-captures/*.pcap` or
  `packet-captures/*.pcapng` with `kind=PacketCapture`;
- host indexing also classifies any discovered `.pcap` or `.pcapng` file as
  packet-capture evidence, even when it was generated outside KSwordSandbox;
- descriptors expose MIME type (`application/vnd.tcpdump.pcap` or
  `application/x-pcapng`), `sizeBytes`, `sha256`, `hashes.sha256`,
  `collectionName=packet-captures`, and safe `importPath`;
- collection metadata records `captureSource=external`,
  `hostCaptureStarted=false`, `importMode=external-artifact`, artifact count,
  total bytes, and MIME types.

`ImportGuestEvents` parses discovered `.pcap` / `.pcapng` files into bounded
`pcap.*` events. Those imported events carry `collectionName=packet-captures`,
`importMode=external-artifact`, `sourceArtifactRelativePath`,
`sourceArtifactSizeBytes`, and `sourceArtifactSha256` so report findings remain
traceable back to the capture artifact.
