# 来宾证据产物 / Guest artifacts

本文说明 guest artifact 通道、host 发现流程和操作者导入行为。Manifest/index schema 的权威说明是
`docs/artifact-manifest.md`；报告渲染与 UX 见 `docs/report-schema.md` 和 `docs/report-ux.md`。

生成的 artifact 都是 runtime evidence。不要提交 guest output folders、`artifacts/manifest.json`、
`artifact-index.json`、screenshots、memory dumps、packet captures、dropped files、reports、samples、
payload binaries 或 VM outputs。

高敏证据默认 opt-in。稳定的 guest output root 是传给 Guest Agent 的 `--out` 目录。本文中的
`relativePath`、`safeLink`、`importPath`、`collectionName`、`captureState`、`status`、`reason` 等都是稳定
schema 字段/值，不翻译；中文提示通过事件或 manifest metadata 中的 `zhMessage`、`zhHint`、`zhStatus`、
`zhReason` 表达。

## 布局 / Layout

- `events.json` 和 `agent-summary.json` 始终写出。
- `artifacts/manifest.json` 始终作为安全证据索引写出；当所有敏感 collection lane 都禁用时，它可以不包含文件 artifact。
  In other words, `manifest.json` is always written best-effort as the guest artifact index.
- `screenshots/*.bmp` 只有在传入 `--screenshot` 且 guest desktop 可捕获时写出。默认 screenshot cadence 是
  `before,during,after`；`--screenshot-phases` 和 `--screenshot-count` 可缩小阶段或每阶段采集多张图。
- `memory-dumps/*.dmp` 只有在传入 `--memory-dump` 或 `--memory-dumps` 时写出。当前 Guest Agent 会在
  `after-start` 早期捕获样本 root process，并在最终 visible root/child process sweep 中尝试捕获仍可见的子进程。
- `artifacts/dropped-files/**` 只有在传入 `--collect-dropped-files` 或 `--dropped-files` 时写出。
- `packet-captures/*.pcapng` 只有在显式传入 `--packet-capture`、`--pcap` 或 `--network-capture`，且 Windows
  `pktmon` 能在 guest 内启动并转换成功时写出。宿主 importer 仍可消费已有的外部 `.pcap` / `.pcapng` 文件。

截图、内存转储、掉落文件复制和抓包都可能包含敏感内容，因此默认不采集。禁用通道会写出 `disabled` 状态或 manifest metadata，
方便区分“未请求”和“请求了但失败/跳过”。

## Host 发现契约 / Host discovery contract

Host-side discovery 只把收集到的 guest output root 作为链接根目录。`GuestOutputLocator.EnumerateArtifacts` 和
`HostArtifactIndexBuilder` 使用同一组稳定 lanes：

- `events.json`: `kind=GuestEventsJson`, `category=telemetry`,
  `evidenceRole=guest-events`, `collectionName=guest-events`,
  `telemetryFormat=json`。
- `driver-events.jsonl` 和 driver-named JSONL fallbacks:
  `kind=DriverEventsJsonLines`, `category=telemetry`,
  `evidenceRole=driver-events`, `collectionName=driver-events`,
  `telemetryFormat=jsonl`。
- `artifacts/manifest.json`: `kind=ArtifactManifest`,
  `evidenceRole=artifact-manifest`, `collectionName=artifact-manifests`。
- `screenshots/**`: `kind=Screenshot`, `evidenceRole=screenshot`,
  `collectionName=screenshots`；phase 从 `before-start`、`after-start`、`after-run` 等文件名推断。Host 也会把
  job output root 下截图命名的 BMP/PNG/JPEG（例如包含 `screen`、`screenshot`、`desktop`、`capture`）归入截图证据，
  但不会把 `artifacts/dropped-files` 中的图片误归类为 screenshot。
- `memory-dumps/**`: `kind=MemoryDump`, `evidenceRole=memory-dump`,
  `collectionName=memory-dumps`, MIME type `application/vnd.microsoft.minidump`。Host 也会把 job output root 下松散的
  `.dmp` 文件归入 memory-dump collection，以支持外部导入的 dump artifact。
- `packet-captures/**/*.pcap` 和 `*.pcapng`: `kind=PacketCapture`,
  `evidenceRole=packet-capture`, `collectionName=packet-captures`,
  `captureSource=external`, `hostCaptureStarted=false`, `importMode=external-artifact`。
- `artifacts/dropped-files/**` 以及 `artifacts/**` 下除 manifest 外的文件:
  `kind=DroppedFile`, `evidenceRole=dropped-file`, `collectionName=dropped-files`。

Descriptor 暴露 `relativePath`、URL-segment encoded `safeLink` 和 `importPath` 作为 browser/download selector。
`fullPath`、`guestPath`、`indexRoot` 和 event source paths 只作为 metadata 或 copy-only diagnostics；它们不能直接写入
`href` 或 `src`。Manifest 和 collection normalization 会拒绝 absolute、drive-qualified 或 traversal `safeLink`，并从
collected guest output root 下的安全路径重建链接。

中文提示：Host 只把 guest 输出根目录下的相对 selector 作为下载链接依据；`fullPath`、`guestPath`、源事件路径等仅是诊断元数据，
不能直接进入 `href` / `src`。

## Host 导入与可下载索引 / Host import and downloadable index

Host 写出 `artifact-index.json` 作为可下载 artifact index。每个 downloadable artifact entry 都带 host-computed
`sizeBytes`、`sha256`、`hashes.sha256`、`kind`、`collectionName`、`evidenceRole`、`relativePath`、`safeLink`、
`importPath`，以及 guest telemetry 或 manifest 指向该文件时的 source-event metadata。下载客户端必须使用
`relativePath`、`safeLink` 或 `importPath` 作为 selector；absolute host/guest paths 只保留为诊断 metadata。

WebUI 下载 UX 还使用这些 host descriptor presentation/safety metadata：`previewLabel`、`previewLabelZh`、
`contentType`、`downloadContentType`、`downloadFileName`、`downloadSelector`、`downloadSafeLink`、`sizeDisplay`、
`sha256Short`、`isDownloadable`、`downloadAvailable`、`downloadResolutionState=available`、
`downloadReadiness=host-file-present`、`downloadRejectionCode=none`、`downloadSelectorKind=relativePath`、
`selectorSafety=normalized-relative-indexed`、`streamAuthority=host-artifact-index`、
`apiMetadataVersion=artifact-descriptor-v1`、`selectorEncoding` 和 `selectorFields`，以及
`downloadSecurityPolicy=server-indexed-relative-selector` /
`downloadRejectionPolicy=reject-empty-absolute-traversal-unindexed-missing` contract。这些字段都从 host-side index
派生，适合放入 browser DTO；它们不是新的 filesystem authority。

重复 artifact 按 host-computed SHA-256 加 byte size 分组。Index metadata 记录 `duplicateGroupKey`、
`duplicateGroupId`、`duplicateGroupCount`、`duplicateOrdinal`、`duplicateRole`、`duplicatePrimarySelector`、
`duplicatePrimarySafeLink`、`duplicatePrimaryImportPath`、`duplicateOfArtifactRelativePath`、
`duplicateGroupMemberSelectors` 和 machine-readable `duplicateGroupMemberSelectorsJson`。组内第一个稳定
relative path 是 primary；后续 entry 仍可下载，但标记为 duplicate，方便 UI/report 折叠或标注重复的 dropped files、
screenshots、dumps 或 captures。

Collection metadata 也汇总重复诊断：`duplicateDiagnosticsAvailable`、`duplicateGroupCount`、
`hasDuplicateArtifacts`、`duplicateGroupIds`、`duplicatePrimarySelectors` 和 structured
`duplicateGroupSummariesJson`。这样 API/报告即使不展开每个 descriptor，也能提示操作者某个 collection 内存在可折叠的重复证据。

如果 guest manifest 声明 unsafe、absolute、traversal、missing 或其他 non-downloadable artifact reference，Host 不会生成链接。
相应 collection metadata 会记录 `rejectionDiagnosticsAvailable`、`rejectedArtifactCount`、
`lastRejectedArtifactReason`、`lastRejectedArtifactName`、`lastRejectedArtifactSelector`、`lastRejectedArtifactKind`、
`artifactRejectionReasons`、machine-readable `artifactRejectionsJson` 和 `zhRejectionHint`。这样既能保留操作者诊断，
又能保持“只有 job output root 下已存在文件可被 stream”的不变式。
当同一 guest manifest 重复引用同一个 host-resolved artifact 时，Host 保留第一次稳定 selector，后续引用记为
`duplicateGuestArtifactReference` 诊断，不让后写 metadata 覆盖 primary selector。

Collection descriptors 也带 API-ready metadata：`apiMetadataVersion=artifact-collection-v1`、`collectionDisplayName`、
`collectionDisplayNameZh`、`downloadableArtifactCount`、`hasDownloadableArtifacts`、`sensitiveCollection`、
`downloadSelectorPolicy`、`safeSelectorFields`、`zhStatus`、`zhReason` 和 `zhHint`。这些字段汇总
dropped-files、screenshots、memory-dumps、packet-captures 的采集状态与下载策略，供 API/客户端展示；
真正的 stream authority 仍然只是 Host index 中已存在文件的相对 selector。

报告导入阶段，Host 还会为 downloadable dropped files、screenshots、memory dumps 和 packet captures 写出
`artifact.host_imported` rows。这些 rows 记录 `sourceArtifactKind`、`sourceArtifactRelativePath`、
`sourceArtifactSizeBytes`、`sourceArtifactSha256`、`collectionName`、`sourceEventType`、`sourceEventPath`、
`importMode=host-artifact-index` 和 `behaviorCounted=false`。这些是 evidence-chain / download metadata，规则或 UI
behavior counts 不应把它们当作样本行为。

同一阶段还会写出 `artifact.import_summary`，汇总 `artifactCount`、`downloadableArtifactCount`、
`sensitiveArtifactCount`、`importedSensitiveArtifactCount`、`duplicateArtifactCount`、`duplicateGroupCount`、
`rejectedArtifactCount`、`downloadPolicy` 和 `rootPathPolicy`，并标记 `behaviorCounted=false` / `nonbehavior=true`。
存在 manifest 拒绝时，Host 会额外写出 `artifact.import_rejected` rows，把 `rejectedArtifactCount`、
`artifactRejectionReasons`、`lastRejectedArtifact*` 和 `artifactRejectionsJson` 放进报告状态；这些 rows 是导入诊断，
不参与样本行为计数。

当已请求或 guest-declared 的敏感 collection 没有 downloadable file 时，Host 导入写出 `collection.health` 诊断，而不是伪造行为。
诊断保留稳定英文机器字段 `collectionName`、`artifactKind`、`status`、`reason`、`healthStatus`、
`artifactMissing=true`，并补充中文操作者字段 `zhMessage` 和 `zhHint`。这能让 dropped-files/screenshots/pcap/memory-dump
证据缺口可见，同时不把采集缺口算成恶意行为。

## 掉落文件 manifest / Dropped-files manifest

启用 dropped-file collection 后，样本工作目录下新创建的文件会复制到 `artifacts/dropped-files/**`。随后 Guest 写出
`artifacts/manifest.json`，使用 `ArtifactManifest` / `ArtifactDescriptor` entries，并设置 `kind=DroppedFile`、
`category=dropped-file`、`evidenceRole=dropped-file`、`collectionName=dropped-files`、safe relative links、`importPath`、
file size、MIME type、SHA-256，以及保留原始 VM-local path 的 metadata。

复制成功的 dropped-file artifact descriptor 始终带 `artifactRelativePath`、`relativePath`、
`collectionName=dropped-files`、`evidenceRole=dropped-file` 和 `captureState=captured`。Copied 与 skipped copy-attempt
事件使用同一组 status shape：`captureEnabled`、`implemented`、`captureState`、`status`、`nonfatal`、
`collectionName`、`evidenceRole`。Captured dropped-file events 包含 copied artifact `sha256` / `artifactSha256`、
`copiedSha256`、可读时的 `sourceSha256`、source/copied sizes、source/copied mtimes、`copiedAtUtc`、
`phase` / `capturePhase`、`artifactIntegrityState`、`sourceCopiedSha256Match`、
`artifactSelector` / `downloadSelector`、`reasonTaxonomy`、`processRole`、`rootProcessId`、root
`treeLineage`、`behaviorCounted=false` / `nonbehavior=true`，以及用于报告文案的
`zhMessage` / `zhHint`。Skipped 和 disabled rows 即使没有创建 artifact file，也保持相同的 phase/process/localized
诊断形状。

Skipped copy attempts 是 nonfatal，`reason` 使用 compact code，例如 `sourcePathMissing`、`sourcePathInvalid`、
`sourceFileMissing`、`outsideWorkingDirectory`、`underOutputDirectory`、`destinationPathInvalid` 或 `copyFailed`。
同时保留稳定 `reasonCode`、`reasonCategory` 与 `zhReason`，方便 UI 不解析英文 message。
可用时，skipped events 还保留 `sourceExists`、source size/mtime、source-event size/mtime，以及 best-effort hash 状态
（例如 `sourceHashStatus=failed`），但不会让整次运行失败。`artifact.dropped_file.summary` 汇总
`reasonCountsJson`、`skippedReasonCounts` / `skippedReasonCountsJson`、`copiedHashComputedCount`、`copiedHashFailedCount`、
`sourceHashComputedCount`、`sourceHashFailedCount`，以及 `firstArtifactSelector` /
`lastArtifactSelector` / `largestArtifactSelector`。Collection metadata 保留 `lastReason` 和最后一次
source/hash diagnostics，使没有 copied files 的 run 也可诊断。未请求 dropped-file collection 时，Guest 写出
`artifact.dropped_file.disabled`。

Manifest 从不信任 VM-local absolute paths 来生成链接。Host 只在 collected guest-output directory 下解析 `relativePath`，
原始路径仅作为 metadata 保存。

## 用户态行为快照 / User-mode behavior snapshots

多个无 R0 的证据源以 `events.json` rows 表示，而不是单独文件。它们仍使用稳定字段名，方便 host reports 把 findings
链接回 raw guest telemetry：

- Process snapshots 在 `before-start`、`after-start` 和 `after-run` 为每个 sampled visible process 写出
  `process.snapshot` rows。Rows 保留 `snapshotKey`、`processId`、`parentProcessId`、`processName`、
  `commandLine`、`imagePath` / `processImagePath`、`startTimeUtc`、parent snapshot metadata，以及属于样本树时的
  root-relative `treeDepth` / `treeLineage`、`processTreeRole` / `treeNodeRole`、
  `rootAncestorProcessId`、`rootRelativeDepth` 和 `isDirectChildOfRoot`。Tracked root/tree/new processes 如果在后续 snapshot 中消失，会以
  `snapshotState=status=captureState=missing`、`processMissing=true`、`exitMissing=true`、`missingAtUtc` 和
  first/last-seen phase metadata 表示。
- Process tree snapshots 仍为样本 root 和 visible descendants 写出 `process.tree` rows，包含 `rootProcessId`、
  `parentProcessId`、`treeDepth`、`treeLineage` 和 `childProcessCount` metadata。若 root 已退出，Guest 保留
  `process.tree_unavailable`，并可继续写出 parent PID 指向 root process 的 visible orphan child rows。
- 每次 root sweep 写出 `process.tree.summary`，包含 `rootProcessId`、`rootVisible`、`visibleProcessCount`、
  `directChildProcessCount`、`maxTreeDepth`、`orphanedChildProcessCount`、`missingProcessCount`、root image/command-line
  metadata，以及用于 report process-tree rendering 的 `summaryEvent=true`。Process-tree missing/summary rows
  carry `reasonCode` / `reasonCategory` / `reasonTaxonomy` and
  `behaviorCounted=false` / `nonbehavior=true` so exited-process diagnostics do
  not inflate behavior counts.
- Persistence diffs 写出 `service.*`、`scheduled_task.*`、`startup_item.*` 和 `registry.run.*` rows。Service rows
  在可读时包含 `imagePath`、`startType`、`serviceType`、`objectName`、`serviceDll` 等 registry configuration metadata。
- DNS/proxy context 写出 `dns.cache.*`、`network.hosts.*` 和 `network.proxy.*` rows。Hosts snapshots 保留 source path、
  existence、line/entry counts、content-change state，以及有界 address/hostname row deltas。Proxy snapshots 覆盖
  process environment variables、HKCU Internet Settings 和 WinHTTP proxy state，并使用稳定的 `source|scope|settingName` keys
  与 value hashes。

## Driver JSONL 与 R0 sidecar 日志 / Driver JSONL and R0 sidecar logs

当传入 `--driver-events <path>` 时，`driver-events.jsonl` 被视为 durable telemetry，而不只是用于 enrich `events.json` 的输入。
R0 sidecar supervision events 同时记录用于取证的 absolute diagnostic paths，以及 output-relative selectors：
`driverEventsRelativePath`、`jsonlRelativePath`、`stdoutRelativePath`、`stderrRelativePath`。Guest manifest 和 host index
使用这些 relative selectors 为 `driver-events.jsonl` 与 `r0collector.*.log` 附加 metadata，不会把 VM-local 或 host-local
absolute paths 变成 browser href。

Host 将 `driver-events.jsonl` 分类为 `kind=DriverEventsJsonLines`、`category=telemetry`、
`evidenceRole=driver-events`、`collectionName=driver-events` 和 `telemetryFormat=jsonl`。名为 `r0collector.*.log` 的 R0
诊断文件分类为 `kind=Log`、`evidenceRole=diagnostic-log` 和 `collectionName=r0-logs`。两类文件都获得 host-computed
`sizeBytes`、MIME type、SHA-256 和 `hashes.sha256`。

中文提示：R0 sidecar 的 stdout/stderr 日志和 `driver-events.jsonl` 都是证据文件。启动失败时 stderr 可能包含英文原因与
`zhMessage`/`zhHint` 双语提示。

## 截图 artifact / Screenshot artifacts

截图是 opt-in，因为它可能包含与样本无关的桌面内容。截图是 best-effort BMP 文件，按配置的 `before,during,after` 阶段采集，
这些阶段映射到 `before-start`、`after-start` 和 `after-run` probe phases。不支持或 headless session 会写出
`screenshot.skipped`，而不是让 run 失败。Screenshot events 带 `screenshotStage`、`screenshotIndex` 和
`screenshotCount` metadata，使 manifest 能保留配置的 cadence。Guest manifest 和 host artifact index 将 `screenshots/`
下的文件分类为 `kind=Screenshot`、`category=screenshot`、`evidenceRole=screenshot` 和 `collectionName=screenshots`。

Screenshot events 还带 `phase` / `capturePhase`、`captureState`、`status`、`nonfatal`、
`expectedRelativePath=screenshots/*.bmp`、创建文件时的 `artifactRelativePath`、captured BMP 的 event-level `sizeBytes` 与
`sha256`、`artifactSelector` / `downloadSelector`、`artifactIntegrityState=verified`，以及样本进程身份已知时的
`processRole`、`rootProcessId`、`processId` 和 root `treeLineage`。Captured 与 skipped
rows 都包含 `behaviorCounted=false` / `nonbehavior=true` 和 `zhMessage` / `zhHint`。Skipped screenshots 保留 `reason`、`diagnosticStage`、可选 `exceptionType` 和可选
`win32Error`，并补充稳定的 `reasonCode` / `reasonCategory` / `reasonTaxonomy` / `zhReason`，但不让 run 失败。
每个执行的截图阶段还写出 `screenshot.phase.summary`，汇总 `reasonCountsJson` 以及
`firstArtifactSelector` / `lastArtifactSelector` / `largestArtifactSelector`。未请求截图时，Guest 写出一个 `screenshot.disabled` event，字段包括
`captureEnabled=false`、`captureState=status=disabled`、`implemented=true`、`nonfatal=true`、
`collectionName=screenshots` 和 `reason=screenshotNotRequested`。

中文提示：截图失败或跳过时保留原始 `reason`、`diagnosticStage` 和 `win32Error`；`zhHint` 用于提示是否是无头会话、
GDI 调用失败、权限或输出路径问题。

## 内存转储 artifact / Memory dump artifacts

Memory dump 默认关闭，必须通过 `--memory-dump` 或 `--memory-dumps` 显式启用。当前实现会在 `after-start` 为启动的样本进程
捕获一个 `MiniDumpNormal`，随后在 `after-run` process-tree sweep 中为仍可见的 child processes 尝试捕获 dump。
Dump attempts 写入 `memory-dumps/*.dmp`。

Dump files 可能包含凭据或文档片段；Host policy 只应在确实需要该证据的 job 中启用。Capture failures 写出
`memory_dump.skipped`，不会阻止 event、screenshot、packet-capture 或 dropped-file artifact 写出。最终
`memory_dump.sweep` event 记录 visible/attempted/captured/skipped counts，使缺失 dump artifact 可解释。它还记录 root/child
split counters（`rootTargetCount`、`childTargetCount`、`rootCapturedCount`、`childSkippedCount` 及相关 attempted/already-captured
字段），并进一步拆分 `directChild*` 与 `deeperDescendant*` counters。Sweep metadata 包含
`memoryDumpCoverageState`、`rootProcessCoverageState`、`childProcessCoverageState`、
`directChildCoverageState`、`deeperDescendantCoverageState` 和
`descendantCoverageCompleteness`，供报告卡片使用。

Guest manifest 和 host artifact index 将 `memory-dumps/**` 文件分类为 `kind=MemoryDump`、`category=memory-dump`、
`evidenceRole=memory-dump` 和 `collectionName=memory-dumps`。

Memory dump attempt events 带 `phase` / `capturePhase`、`captureState`、`status`、`nonfatal`、`artifactRelativePath`、
`artifactSelector` / `downloadSelector`、
captured dumps 的 event-level `sizeBytes` 与 `sha256`，以及进程身份字段：`processId`、`rootProcessId`、
`parentProcessId`、`targetProcessName`、`targetProcessPath`、`processRole`、`treeDepth`、`treeLineage`、`snapshotKey` 和
`dumpType`。Captured dumps 带 `artifactIntegrityState=verified`（或 `hash-failed` 诊断）；
root/descendant targeting 还带 `targetProcessRole`、`targetTreeDepth`、`targetTreeLineage`、
`rootAncestorProcessId`、`directChildProcessDumpTarget`、`deeperDescendantProcessDumpTarget`
和 `isDirectChildOfRoot`。Skipped attempts 保留 `reason`、稳定
`reasonCode` / `reasonCategory` / `reasonTaxonomy`、`diagnosticStage`、可选 `exceptionType` 和可选 `win32Error`；captured/skipped/disabled
rows 均包含 `zhMessage` / `zhHint`。Probe timeouts 或 exceptions 映射为 `memory-dumps` collection 的 nonfatal failed status，
而不是变成 `enabled-empty`。未请求 memory dumps 时，Guest 写出一个同形状的 `memory_dump.disabled` event。
`memory_dump.sweep` event 是 summary（`summaryEvent=true`），带 `coverageTaxonomy`，
并标记 `behaviorCounted=false` / `nonbehavior=true`，不计入 captured/skipped/failed collection status。

中文提示：内存转储失败/跳过不会阻止其他证据写出。中文提示用于区分目标进程已退出、PID 不可见、
`MiniDumpWriteDump` 失败、权限不足或未显式启用。

## Collection lanes 与导入路径 / Collection lanes and import paths

`artifacts/manifest.json` 的 `collections` entries 包括：

- `dropped-files`
- `screenshots`
- `memory-dumps`
- `driver-events`
- `r0-logs`
- `packet-captures`

每个 collection 记录 `enabled`、`implemented`、`status`、`reason`、`relativePath`、`safeLink` 和 `importPath`。Disabled lanes
显式存在，host importer 因而能区分 “not requested” 与 “requested but unavailable”。Collection metadata 还记录 normalized
`requested` / `captureEnabled`、`capturedCount`、`skippedCount`、`disabledCount`、`failedCount` 以及对应 event counters。
Disabled lanes 即使旧 agent 没写 disabled event，也会有 synthetic `disabledCount>=1`。

`packet-captures` 是已实现的 opt-in lane，用于 KSword guest collector。请求抓包但 `pktmon` 不可用、权限不足或 ETL 转换失败时，
lane 标记为 `skipped` 或 `failed`，run 继续。如果 manifest 或 collected folder 中包含外部提供的 `.pcap` 或 `.pcapng`，Host
仍可按 `kind=PacketCapture` 导入和报告。

Host 构建 `artifact-index.json` 时，会把 guest `artifacts/manifest.json` 和相邻 `events.json` 合并回 filesystem scan。Index
以 host-safe paths、host-computed size 和 host-computed SHA-256 作为权威链接字段，同时在 descriptor 或 collection `metadata` 中
保留 guest collection `status` / `reason`、具体 skipped/failed reason、command diagnostics、original guest paths、process identity
和 memory-dump root/child sweep metadata。

Collection metadata 在 dropped files、screenshots、memory dumps 和 packet captures 间一致保留 nonfatal diagnostics。Guest manifest
记录 counts 以及 `lastReason`、`lastDiagnosticStage`、`lastExceptionType`、`lastCommandMessage`、
`lastArtifactRelativePath`、`lastPhase` / `lastCapturePhase`、`lastProcessId` / `lastRootProcessId`，以及存在时的
`lastProcessRole`、`lastTreeDepth`、`lastTreeLineage` 和 `lastChildProcessCount`。Last collection state metadata 优先使用具体
captured/skipped/disabled/failed events，而不是 ancillary diagnostic summaries。Diagnostic metadata 仍保留后续 nonfatal details，
例如 dropped-file source hash failures 或 packet protocol-summary diagnostics，使操作者能解释 collection health，而不把这些诊断当作样本行为。
Guest collection summaries also expose `collectionSummaryVersion=artifact-collection-summary-v2`,
`capturedArtifactCount`、`downloadableArtifactCount`、`artifactTotalBytes`、
`artifactHashComputedCount`、`artifactHashFailedCount`、`artifactIntegrityState`、
`reasonCounts` / `reasonCountsJson`、`artifactSelectorVersion=artifact-selectors-v1`，
以及可用时的 `firstArtifactSelector` / `lastArtifactSelector` /
`largestArtifactSelector` selector triplets（relative path、safe link、size、sha256）。

对 packet captures，具体证据由 `lastArtifactRelativePath` 以及存在时的 `lastDiagnosticPcapngRelativePath`、
`lastDiagnosticPcapngSizeBytes`、`lastDiagnosticPcapngSha256`、`lastDiagnosticPacketCount`、
`lastDiagnosticPcapngBlockCount` 锚定。Host indexes 也保留 guest status aliases，例如 `guestManifestStatus` /
`guestManifestReason` 和 `guestCollectionStatus` / `guestCollectionReason`。

中文提示：collection metadata 会补充 `zhStatus`、`zhReason`、`zhHint`，并把事件中的 `zhMessage` / `zhHint` 汇总为
`lastZh*` / `lastDiagnosticZh*`。抓包诊断请优先看 `lastArtifactRelativePath`、`lastDiagnosticPcapngRelativePath`、
`lastDiagnosticPacketCountStatus` / `lastDiagnosticPacketCount`、`lastDiagnosticPcapngBlockCount`、
`lastDiagnosticPcapngSha256` 等字段；它们证明具体 PCAPNG 证据或诊断状态，`protocolSummary*` 只说明协议解析是否可用。
这些字段仅用于 UI/报告解释，不参与机器规则判断。

每个 file descriptor 还携带 `evidenceRole`、`capturePhase`、`captureState`、`guestPath`、`importPath` 和
`collectionName`，以及 size、MIME type 和 hashes。`guestPath` 仅是 evidence；clickable links 和 import paths 都从 collected guest
output root 下的安全路径派生。

WebUI download selectors 有意保持冗余且相对：`relativePath`、`safeLink` 和 `importPath` 都指向 job output root 下方。Guarded
download endpoint（下载端点）在 URL decoding 后接受这些 selector，但拒绝 empty、absolute、traversal、missing 或 unindexed paths。
`safeLink` 为 report anchors 做 path segment URL encoding；API download hrefs 把 selector text 作为 query value，而不是嵌入
`fullPath`。

`/api/jobs/{jobId}/artifacts` DTO 不把 `fullPath` 和其他 host-local paths 放进 browser response。每个 artifact 暴露一个
`Download` block，包含 `available`、safe selector、guarded href、sanitized filename、content type、size、SHA-256、short hash，
以及没有 safe selector 时的 rejection code/message。Collection DTOs 单独暴露 rejection diagnostics，让操作者看到 manifest entry
为何被忽略，同时不会收到 clickable unsafe path。

## 可选抓包与外部导入 / Optional packet capture and external import

`--packet-capture`、`--pcap` 和 `--network-capture` 是显式 opt-in switches。它们在样本运行前启动 Windows `pktmon`，运行后停止，
用 `pktmon etl2pcap` 转换 ETL trace，并在成功时写出 `packet-captures/*.pcapng`。Raw ETL diagnostics 保留在
`packet-capture-diagnostics/` 下，不视为 packet-capture artifacts。

抓包仍然 safe-by-default：除非出现上述 opt-in switch，否则不会启动 sniffer。`pktmon` 缺失、权限不足、系统已有 active capture
冲突、停止失败或转换失败时，Guest 写出 `packet_capture.skipped` 或 `packet_capture.failed`；这些状态不会阻止 `events.json`、
dropped files、screenshots、memory dumps 或 artifact manifest 写出。成功运行会写出 `packet_capture.started`、
`packet_capture.stopped` 和 `packet_capture.captured`。

Packet capture lifecycle events 带 `collectionName=packet-captures`、`evidenceRole=packet-capture`、`phase` /
`capturePhase`、`status`、`captureState`、`nonfatal`、`expectedRelativePath=packet-captures/*.pcapng`，以及最终 PCAPNG path 的
`artifactRelativePath`。Captured PCAPNG rows 还带 event-level `sizeBytes`、`sha256`、`processRole`、`rootProcessId`、root
`treeLineage` 和 `zhMessage` / `zhHint`。ETL diagnostics 与 packet artifact 分离，使用 `etlRelativePath` /
`diagnosticRelativePath`。当 PCAPNG path 已知时，events 还包含显式 `pcapngPath`、`pcapngRelativePath`、
`packetCaptureRelativePath` 和 `sourceArtifactRelativePath`。

Start/stop/convert command failures 保留 `reason`、command exit/timeout details 和 `commandMessage`；失败的 `pktmon start` 记为
`packet_capture.failed`，unavailable 或 not-started cases 保持 `packet_capture.skipped`。未请求抓包时，Guest 写出一个
`packet_capture.disabled` event，包含 `captureEnabled=false`、`captureState=status=disabled` 和
`reason=packetCaptureNotRequested`。Lifecycle rows 还保留 `sourceTool=pktmon.exe`、`artifactSourceTool=pktmon.exe`、
`packetCaptureSourceTool=pktmon.exe` 和 `packetCaptureSource=guest-pktmon`，使 Host 即使在最终文件 pending、missing 或 failed 时也能归因
PCAP artifacts。

中文优先提示：`packet_capture.protocol_summary` 是抓包诊断摘要，不是 DNS/HTTP/TLS 行为证据。看到
`protocolSummaryAvailable=false`、`protocolSummaryState=capture-metadata-only`、
`protocolSummaryReason=protocolParserNotImplemented` 时，表示 PCAPNG 已采集，但内置协议摘要解析尚未接入；请用
`artifactRelativePath` 下载 PCAPNG，并用 `sizeBytes` / `pcapngSizeBytes`、`sha256` / `pcapngSha256`、`packetCount`、
`packetCountStatus`、`pcapngBlockCount`、`pcapngEnhancedPacketBlockCount`、`pcapngSimplePacketBlockCount`、
`pcapngSectionHeaderCount` 校验证据是否具体。

成功转换 PCAPNG 后，Guest 还会写出 `packet_capture.protocol_summary` 作为 capture-metadata diagnostic row。该 row 保留给
schema/report compatibility，直到接入 inline protocol parsing。它通过 `protocolSummaryAvailable=false`、
`protocolSummaryState=capture-metadata-only`、`protocolSummaryStatus=skipped`、
`protocolSummaryReason=protocolParserNotImplemented`、`protocolSummaryFormat=capture-metadata` 和
`protocolsObserved=not-parsed` 绑定到具体 PCAPNG/ETL paths；它不会伪造 protocol findings，不会把 packet-capture collection 从
`captured` 改掉，也不计作样本行为。

中文提示：抓包通道默认不启动。`pktmon` 启动/停止/转换失败会保持英文 `reason` code，并附加中文 `zhHint`；协议摘要诊断只说明解析能力和文件健康状态，
具体证据由路径、大小、哈希和 PCAPNG packet/block 计数字段证明。

对 import/report 来说，已有 packet captures 是普通 artifacts：

- guest manifests 可以用 `kind=PacketCapture` 引用 `packet-captures/*.pcap` 或 `packet-captures/*.pcapng`；
- host indexing 也会把发现的任何 `.pcap` 或 `.pcapng` 文件分类为 packet-capture evidence，即使它不是 KSwordSandbox 生成的；
- descriptors 暴露 MIME type（`application/vnd.tcpdump.pcap` 或 `application/x-pcapng`）、`sizeBytes`、`sha256`、
  `hashes.sha256`、`collectionName=packet-captures` 和 safe `importPath`；
- collection metadata 记录 `captureSource=external`、`hostCaptureStarted=false`、`importMode=external-artifact`、artifact count、
  total bytes 和 MIME types。

`ImportGuestEvents` 会把发现的 `.pcap` / `.pcapng` 文件解析成有界 `pcap.*` events。这些 imported events 带
`collectionName=packet-captures`、`importMode=external-artifact`、`sourceArtifactRelativePath`、`sourceArtifactSizeBytes` 和
`sourceArtifactSha256`，让 report findings 能回溯到 capture artifact。
