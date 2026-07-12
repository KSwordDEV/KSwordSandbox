# Guest Agent 行为事件 / Guest Agent behavior events

Guest Agent 运行在 analysis VM 内，负责按限定时间启动样本、采集用户态证据、
合并可选 R0Collector JSONL，并把结构化事件/产物写入 `--out`。命令参数名保持英文，
方便脚本和 WebUI 继续稳定调用；操作者说明优先使用中文。

现有命令行契约保持不变：

```text
--sample <path> --out <directory> [--duration <seconds>] [--driver-events <path>]
```

释放文件提取默认关闭，需要显式打开：

```text
[--collect-dropped-files | --dropped-files]
```

可选 R0 sidecar 参数会扩展采集能力，但不改变既有参数含义：

```text
[--r0collector <path>] [--driver-device <path>] [--r0-mock]
```

截图采集默认关闭，需要显式打开：

```text
[--screenshot | --screenshots]
[--screenshot-phases before,during,after]
[--screenshot-count <1-5>]
```

`--screenshot` 仍是 opt-in gate。`--screenshot-phases` 接受 `before`、`during`
和 `after`（别名：`before-start`、`after-start`、`after-run`）。省略时默认节奏是
`before,during,after`。`--screenshot-count` 控制每个阶段 best-effort 截图次数，
并限制在 1-5。

内存转储默认关闭，只能通过显式 opt-in 打开；memory dumps are off by default：

```text
[--memory-dump | --memory-dumps]
```

网络抓包默认关闭，只能通过显式 opt-in 打开：

```text
[--packet-capture | --pcap | --network-capture]
```

在 Windows 中启用后，Agent 会在样本执行前后使用 `pktmon`，并把 trace 转为
PCAPNG。缺少工具或权限不足会记录为非致命 `packet_capture.*` 事件，不会让整次分析失败。

主要 JSON 和证据输出写到 `--out` 下：

- `events.json` - guest 内采集到的有序 `SandboxEvent` 事件。
- `agent-summary.json` - 运行摘要，包含 sample path、event count 和生成时间。
- `screenshots/*.bmp` - 显式传入 `--screenshot` 且 guest session 有可捕获桌面时的可选截图。
- `memory-dumps/*.dmp` - 显式传入 `--memory-dump` / `--memory-dumps` 时的
  `MiniDumpNormal` 进程转储；Agent 会先捕获 root process，再在结束阶段扫 root/child 进程树。
- `packet-captures/*.pcapng` - 显式传入 `--packet-capture`、`--pcap` 或
  `--network-capture` 且转换成功时，由 Windows `pktmon` 生成的可选抓包。
- `artifacts/dropped-files/**` - 显式传入 `--collect-dropped-files` 或
  `--dropped-files` 时，样本工作目录下新增文件的可选副本。
- `artifacts/manifest.json` - best-effort artifact manifest；即使敏感采集通道关闭，
  也会作为安全证据索引写出。

`artifacts/manifest.json` 使用 `KSword.Sandbox.Abstractions.Artifacts` 中的
`ArtifactManifest`。每个 entry 记录 `kind:DroppedFile`、`name`、`relativePath`、
`sizeBytes`、可选 `sha256`，以及 `origin=guest`、`evidenceRole=dropped-file`、
原始 guest full path 等 metadata。manifest 有意使用相对路径，方便 host 在已收集的
guest-output 目录下解析文件，而不是信任 VM 内绝对路径。

## 事件覆盖范围 / Event coverage

当前 guest collector 会输出以下 host 可报告事件组。事件类型保持英文稳定值；报告和 WebUI
可以优先展示 `zhMessage` / `zhHint` 等中文辅助字段：

- `agent.start` / `agent.stop` for collector lifecycle.
- `environment.snapshot` before sample launch, including OS description, user,
  machine name, current directory, selected sample working directory, and
  process/OS architecture.
- `process.observed` for the pre-launch process list baseline.
- `process.start`, `process.timeout`, and `process.exit` for the launched
  sample process.
- `process.new` for processes visible after sample launch or after the run that
  were not present in the pre-launch baseline.
- `process.tree` for the launched sample process and visible descendants. The
  event includes `ParentProcessId` plus `rootProcessId` and `treeDepth` in
  `Data` so reports can reconstruct a low-privilege process tree without WMI or
  administrator rights. Tree events also include `childProcessCount`,
  `treeLineage`, `processTreeRole` / `treeNodeRole`, `rootAncestorProcessId`,
  `rootRelativeDepth`, `isDirectChildOfRoot`, `sessionId`, `threadCount`, and
  Toolhelp image metadata when available. These fields are stable even when a
  descendant is seen after the root has exited. Missing rows add
  `missingTreeLineageStatus` / `missingLineageSource`, while summaries split
  `visibleDirectChildProcessCount` from `visibleDeeperDescendantProcessCount`
  and mark `rootOrphanedTreeRecovered` when only child/deeper descendant rows
  remain visible.
- `process.tree_unavailable` when the root PID has already exited or is not
  visible in the current low-privilege snapshot.
- `environment.detail` for additional runtime and guest context, including
  .NET framework description, runtime identifier, elevation estimate,
  interactive-session flag, time-zone metadata, temp/user profile paths, and
  selected environment-derived fields without dumping the full environment
  block.
- `file.created`, `file.modified`, and `file.deleted` for files changed under
  the sample working directory. File delta events include `root`,
  `relativePath`, `sizeBytes`/`lastWriteUtc`, and previous values for modified
  or deleted files when available.
- `network.tcp` for new TCP connections visible in the post-run TCP snapshot.
  Each event keeps the legacy `connection` string and also includes structured
  `local`, `remote`, `state`, `localAddress`, `localPort`, `remoteAddress`, and
  `remotePort` fields in `Data`; `change=opened` marks the delta direction.
- `network.tcp.closed` for baseline TCP connections that disappeared by the
  post-run snapshot. These events use the same endpoint fields with
  `change=closed`.
- `dns.cache.snapshot`, `dns.cache.added`, and `dns.cache.removed` from a
  bounded `ipconfig /displaydns` query. DNS entries include parsed
  `name`/`recordType`/`data`/`timeToLive` when English labels are present and a
  hash plus `rawSummary` fallback when output is localized. Snapshot and diff
  events also carry `snapshotHash` / `beforeSnapshotHash` /
  `afterSnapshotHash`; the stable key excludes TTL so normal resolver-cache
  countdowns do not create false add/remove noise. `dns.cache.diff` summarizes
  added/removed counts before bounded row-level events are emitted.
- `network.hosts.snapshot`, `network.hosts.diff`,
  `network.hosts.added`, and `network.hosts.removed` for the local hosts file.
  The agent records the source path, existence flag, line/entry counts, content
  change state, and stable entry hashes while row events expose bounded
  `address` / `hostName` pairs instead of dumping the entire file.
- `network.proxy.snapshot`, `network.proxy.diff`,
  `network.proxy.added`, `network.proxy.removed`, and
  `network.proxy.modified` for process environment proxy variables, HKCU
  Internet Settings, and machine WinHTTP proxy state from bounded
  `netsh winhttp show proxy`. Proxy row events use the stable
  `source|scope|settingName` key, value hashes, and truncated setting values so
  reports can explain proxy/PAC changes without blocking collection.
- `network.netstat.snapshot`, `network.netstat`,
  `network.netstat.added`, and `network.netstat.removed` from bounded
  `netstat -ano` collection. Rows include protocol, local/remote endpoints,
  state, and owning PID when present. Large row sets are capped and emit
  `network.netstat.truncated` rather than blocking live output.
  `network.netstat.diff` records before/after row counts, added/removed counts,
  and snapshot hashes for stable report summaries even when row output is
  truncated.
- `network.tcp.listener.snapshot`, `network.udp.listener.snapshot`,
  `network.tcp.listener.opened` / `.closed`, and
  `network.udp.listener.opened` / `.closed` for managed listener diffs.
- `service.snapshot`, `service.created`, `service.modified`, and
  `service.deleted` from bounded `sc queryex state= all` inventory. When the
  service registry key is readable, service diff events also include
  `imagePath`, `startType`, `serviceType`, `objectName`, and `serviceDll`
  metadata so user-mode collection can explain service persistence without R0.
- `scheduled_task.snapshot`, `scheduled_task.created`,
  `scheduled_task.modified`, and `scheduled_task.deleted` from bounded
  `schtasks /query /fo csv /v` inventory.
- `startup_item.snapshot`, `startup_item.created`,
  `startup_item.modified`, and `startup_item.deleted` for common Run/RunOnce
  registry values and Startup folder entries. Registry and folder access errors
  become `startup_item.capture_failed` diagnostics instead of failing the run.
- `registry.run.snapshot`, `registry.run.created`,
  `registry.run.modified`, and `registry.run.deleted` for dedicated HKCU/HKLM
  Run/RunOnce registry value diffs across 32-bit and 64-bit views where
  available. Events include `hive`, `keyPath`, `keyName`, `view`, `valueName`,
  `value`, optional `expandedValue`, and `valueKind`. Registry access errors
  become `registry.run.capture_failed` diagnostics.
- `screenshot.captured` when `--screenshot` successfully writes a desktop BMP.
  The event path points at the BMP file and `Data` includes `phase`,
  `screenshotStage`, `screenshotIndex`, `screenshotCount`, `widthPixels`, and
  `heightPixels`, `artifactRelativePath`, `sizeBytes`, `sha256`,
  `artifactSelector` / `downloadSelector`, `processRole`, `rootProcessId`,
  `treeLineage`, `behaviorCounted=false`, `nonbehavior=true`, and
  `notSampleBehavior=true`, plus `zhMessage`/`zhHint` when those values are
  available.
- `screenshot.skipped` when screenshot capture was requested but the platform or
  guest session cannot expose a desktop surface. This is non-fatal and includes
  structured `reason`, stable `reasonCode` / `reasonCategory`, `diagnosticStage`,
  `exceptionType`, `win32Error`, `reasonTaxonomy`, and
  `artifactIntegrityState=skipped` when available, keeping smoke tests usable on
  headless hosts.
- `screenshot.phase.summary` after each configured screenshot phase. This
  summary is marked `summaryEvent=true`, `collectionHealth=true`,
  `behaviorCounted=false`, `nonbehavior=true`, and
  `notSampleBehavior=true`; it records captured/skipped counts, reason-count
  JSON, and first/last/largest artifact selectors when screenshots were
  produced.
- `memory_dump.captured` when `--memory-dump` successfully writes a
  `memory-dumps/*.dmp` minidump for the launched sample process or a visible
  descendant process. The event path points at the `.dmp` file and `Data`
  includes `phase`, `capturePhase`, `dumpType`, `sizeBytes`, `sha256`,
  `relativePath`, `artifactRelativePath`, `artifactRelativePathStatus`,
  `artifactSelector` / `downloadSelector`, `capturePolicy`, `processRole`,
  `rootProcessId`, `treeDepth`, `treeLineage`, direct-child/deeper-descendant
  targeting fields, `behaviorCounted=false`, `nonbehavior=true`,
  `notSampleBehavior=true`, and `zhMessage`/`zhHint` when available.
- `memory_dump.skipped` when memory dump capture was requested but the platform,
  process state, or access rights prevent capture. This is non-fatal and
  includes structured `reason`, stable `reasonCode` / `reasonCategory`,
  `diagnosticStage`, `exceptionType`, and `win32Error` when available.
  Duplicate/already-captured targets, PID reuse
  protection, missing root PID, and empty visible-tree cases are explicit
  skipped events with `artifactRelativePathStatus` and Chinese `zhHint`.
- `memory_dump.sweep` after the final `after-run` process-tree sweep. It records
  visible target count, attempted count, captured count, skipped count, and
  already-captured count, plus visible root/child, direct-child,
  deeper-descendant, and root/descendant split counters and
  `memoryDumpCoverageState` / `rootProcessCoverageState` /
  `childProcessCoverageState` / `directChildCoverageState` /
  `deeperDescendantCoverageState` / `descendantCoverageCompleteness` so the
  report can explain why a run has fewer dump files than process-tree nodes.
  It carries `coverageTaxonomy` and is marked `behaviorCounted=false`,
  `nonbehavior=true`, and `notSampleBehavior=true`. Timeout runs can also emit a `cleanup`
  pre-kill sweep before `Kill(entireProcessTree:true)` so live descendants are
  dumped before the agent terminates the process tree.
- `packet_capture.started`, `packet_capture.stopped`, and
  `packet_capture.captured` when `--packet-capture` / `--pcap` /
  `--network-capture` starts `pktmon`, stops it after the run, converts ETL to
  `packet-captures/*.pcapng`, and records size/path metadata for host PCAP
  import. Captured PCAPNG events also include `sha256`, `processRole`,
  `rootProcessId`, `treeLineage`, `sourceTool`/`artifactSourceTool`, and
  `behaviorCounted=false`, `nonbehavior=true`, `notSampleBehavior=true`, and
  `zhMessage`/`zhHint` when available.
- `packet_capture.skipped` and `packet_capture.failed` when packet capture was
  requested but Windows, rights, an existing capture session, `pktmon start`,
  `pktmon stop`, or `pktmon etl2pcap` prevents usable output. These events are
  non-fatal and keep stdout/stderr suppressed while recording exit code,
  timeout, and reason fields.
- `probe.timeout`, `probe.failed`, and `probe.canceled` for per-probe isolation.
  A slow DNS/netstat/service/task query is bounded and converted to an event so
  later probes and final JSON artifact writing can continue. These diagnostic
  rows are explicitly marked `collectionHealth=true`,
  `behaviorCounted=false`, `nonbehavior=true`, and `notSampleBehavior=true` so
  reports do not treat collection failures as sample behavior.
- `probe.summary` after each probe and `probe.phase.summary` after each phase.
  These events are marked with `collectionHealth=true`,
  `behaviorCounted=false`, `nonbehavior=true`, and `notSampleBehavior=true`;
  they explain which collection channel ran, how long it took, how many events
  it emitted, and whether it completed, failed, timed out, or was canceled.
  They are intentionally health/progress evidence, not sample behavior.
- `process.start_failed`, `process.kill_failed`, and
  `process.execution_failed` for sample-launch, timeout-kill, or execution
  orchestration exceptions. These are non-fatal diagnostics with exception
  details in `Data`; the agent still runs final probes, merges driver JSONL when
  configured, and writes artifacts where possible.
- Driver JSONL events from `--driver-events`, preserving driver-provided fields
  and defaulting missing sources to `driver`.
- `r0collector.start_failed` if the optional sidecar process could not be
  created. This event is emitted by the agent and does not fail the whole run.
- `r0collector.stop_forced` / `r0collector.stop_failed` only when the agent had
  to terminate the sidecar or could not finish sidecar shutdown cleanly.
- Agent self-noise and collection-noise rows (`agent.*`, `r0collector.*`,
  `probe.*`, `screenshot.*`, `memory_dump.*`, `packet_capture.*`, manifest
  health rows, and capture diagnostics) are normalized with
  `behaviorCounted=false`, `nonbehavior=true`, `notSampleBehavior=true`, and
  Chinese operator fields. This does not change sample behavior events such as
  `process.*`, `file.*`, TCP, service, scheduled task, startup item, or
  registry behavior diffs.

事件模型仍然是 `KSword.Sandbox.Abstractions.SandboxEvent`；附加细节放在既有字符串
`Data` dictionary 中，避免修改 Core/Web/Abstractions 共享契约。

释放文件通过 artifact manifest 表达，而不是把文件内容嵌入 `events.json`。
file behavior 事件仍可引用触发证据的路径；`artifacts/manifest.json` 则是复制字节、
hash 和 host 可回收相对位置的持久证据链。

启用释放文件提取时，Agent 会额外输出：

- `artifact.dropped_file.copied` for each copied `file.created` path. The event
  path points at the copied artifact under `--out\artifacts\dropped-files`, and
  `Data` includes `phase`/`capturePhase`, the original guest path,
  guest-relative path, `artifactRelativePath`, copied/source sizes,
  source creation/last-write time, copy time, source/copied SHA-256 values
  when readable, hash status fields, `artifactIntegrityState`,
  `artifactSelector` / `downloadSelector`, `reasonTaxonomy`,
  `sourceCopiedSha256Match`, `processRole`, `rootProcessId`, root
  `treeLineage`, `rootProcessIdStatus`, `treeLineageStatus`,
  `behaviorCounted=false`, `nonbehavior=true`, `zhMessage`/`zhHint`, and
  `evidenceRole=dropped-file`.
- `artifact.dropped_file.skipped` when a candidate path disappeared, is outside
  the sample working directory, is under `--out`, or cannot be copied. Skipped
  rows preserve the same `phase`/`capturePhase`, process attribution,
  machine-readable `reason` / `reasonCode` / `reasonCategory`,
  `reasonTaxonomy`, `collectionHealth=true`, `nonbehavior=true`, `zhReason`, and
  `zhMessage`/`zhHint` shape for report explanations. The summary row also
  includes all reason counts, skipped reason counts, copied/source hash outcome
  counters, and first/last/largest copied-artifact selectors.
- `artifact.manifest.written` after `artifacts/manifest.json` is written. The
  event records the manifest-relative path, manifest artifact count, and copied
  dropped-file count. Manifest success/failure rows are collection-health
  metadata and carry `behaviorCounted=false` / `nonbehavior=true`.
- `artifact.manifest.failed` if manifest writing fails; events and summary
  writing still continue best-effort.

## 可选 R0Collector sidecar / Optional R0Collector sidecar

同时提供 `--r0collector <path>` 和 `--driver-events <jsonl>` 时，Agent 会在启动样本前
启动 `KSword.Sandbox.R0Collector.exe`。sidecar 调用方式如下：

```text
--device <driver-device> --output <driver-events> --duration <duration>
```

省略 `--driver-device` 时默认使用 `\\.\KSwordSandboxDriver`。传入 `--r0-mock`
会让 Agent 把 `--mock` 转发给 sidecar，用于未安装 kernel driver 的本地或 CI plumbing
测试。

样本退出或超时后，Agent 会短暂等待 sidecar 退出；若仍在运行，则终止 sidecar 进程树，
确保 JSONL 文件可关闭并读取。随后 Agent 读取 `--driver-events` 并把这些 JSONL 行合并进
`events.json`。

如果 sidecar 可执行文件缺失、无法启动，或 JSONL 父目录无法准备，Agent 会向 guest
events 添加 `r0collector.start_failed`，并继续正常 user-mode 采集。

## 可选截图采集 / Optional screenshots

`--screenshot` 默认启用 best-effort BMP 截图，节奏是 `before,during,after`。
这些阶段映射到 `before-start`、`after-start` 和 `after-run` probe phase；也可以用
`--screenshot-phases before,during,after` 缩小或重排。`--screenshot-count <1-5>`
会在每个选中阶段捕获多张图片，并向 `screenshot.captured` / `screenshot.skipped`
事件加入 `screenshotIndex` / `screenshotCount` metadata。每个实际执行的截图阶段还会
输出 `screenshot.phase.summary`，用 `reasonCountsJson`、`firstArtifactSelector`、
`lastArtifactSelector` 和 `largestArtifactSelector` 汇总该阶段证据质量。

实现直接使用 User32/GDI32 API，不依赖外部包或管理员权限。非交互 session 中截图可能不可用；
此时 Agent 会输出带 reason 的 `screenshot.skipped`，而不是让分析失败。manifest 仍会根据事件
把 `screenshots` 采集通道记录为 enabled 后 skipped 或 empty。

截图有意保持 opt-in，因为它可能包含敏感桌面状态，并且在自动化 VM run 中容易产生噪音。
后续 host policy 应按 job 决定是否转发 `--screenshot`。

## 可选释放文件提取 / Optional dropped-file extraction

`--collect-dropped-files`（别名 `--dropped-files`）会把 sample working directory 下
由 `file.created` 观察到的文件复制到 `--out\artifacts\dropped-files`。Agent 会跳过
`--out` 下的文件，避免递归收集自身输出；跳过原因会作为 diagnostics 记录，而不是让 run 失败。

manifest 会对复制出的 artifact bytes 计算 hash，并在 descriptor metadata 中保留原始
VM-local path（`guestFullPath`）。它还携带 `guestRelativePath`、`sourceEventType`、
原始 source size/timestamps、`sourceEventTimestampUtc`、`copiedAtUtc`、
`sourceSha256`、`originalSha256` 和 `copiedSha256`，让报告区分“guest 中观察到的文件”
和“复制回来的 artifact”。该选项不收集 memory dump；内存转储仍是单独的显式 opt-in。
`file.created`/`file.modified` 候选 rows、`artifact.dropped_file.copied` 和
`artifact.dropped_file.skipped` 共享 artifact 列族：`rootProcessId`、`treeLineage`、
`processRole`、`artifactRelativePath`、`sizeBytes`、`sha256` 以及对应 status 字段；没有产出文件时
这些值为空并由 `artifactRelativePathStatus`、`sizeBytesStatus`、`sha256Status` 解释原因。

## 可选内存转储 / Optional memory dumps

`--memory-dump`（别名 `--memory-dumps`）为启动的样本进程及其可见子孙进程启用
best-effort `MiniDumpNormal` 采集。probe 先在 `after-start` 捕获 root process 作为兜底；
然后使用与 `ProcessTreeProbe` 相同的低权限 process snapshot 模型遍历可见
root/descendant tree，并转储尚未捕获的子进程。正常退出/早退时 sweep 发生在
`after-run`；超时样本会先在 `cleanup` 阶段（调用 `Kill(entireProcessTree:true)` 之前）
做一次 memory-dump-only sweep，尽量在子孙进程仍存活时写出 dump。dump 写到
`--out\memory-dumps\*.dmp`；
host artifact index 将这些文件分类为 `memory-dump`，不新增共享 artifact enum。

内存转储有意默认关闭，因为 dump 文件可能包含凭据、token、文档片段或其他敏感内存。
操作者或 host policy 必须按 job 显式 opt in。如果样本退出太快、session 不是 Windows，
或 process access 被拒绝，Agent 会输出 `memory_dump.skipped` 并继续正常事件/artifact 写入。
最终 `memory_dump.sweep` 只是 summary evidence；即使所有可见目标已捕获或没有仍可见的子进程，
也会输出。该 summary 会拆分 root/descendant attempted/captured/skipped/already-captured
计数，并进一步拆分 `directChild*` 与 `deeperDescendant*` 计数，给出 coverage state，
便于审阅者判断“未生成 dump”是已在 after-start
捕获、目标退出、权限失败、PID 复用保护，还是没有可见子进程。每条 dump captured/skipped
事件都会尽量保留 `rootProcessId`、`treeLineage`、`capturePolicy`、
`artifactRelativePathStatus`、`artifactAttemptEvent`、`childProcessArtifactEvent`、
`childProcessDumpOutcome`、`directChildProcessDumpEnabled`、`deeperDescendantProcessDumpEnabled`、
`descendantDumpOptInScope` 和 `zhHint`；如果 root PID 本身不可用，则用
`rootProcessIdStatus` / `treeLineageStatus` 明确标记不可用。

## 可选网络抓包 / Optional packet capture

`--packet-capture`（别名 `--pcap`、`--network-capture`）会围绕样本执行窗口启用一次
best-effort Windows `pktmon` 抓包。probe 在 `BeforeStart` 阶段启动，在 `AfterRun` 停止，
使用 `pktmon etl2pcap` 转换 ETL，并把 `packet-captures/*.pcapng` 写到 `--out`。

网络抓包有意默认关闭，因为它可能捕获 guest 内无关网络流量；不同镜像策略下也可能需要
elevated guest 权限。缺少 `pktmon`、access denied、已有 active capture 冲突、stop 失败或
conversion 失败都会输出 `packet_capture.skipped` 或 `packet_capture.failed`，不会让分析失败。
host PCAP importer 会消费成功的 `.pcapng` 文件，并在 guest output import 阶段把
DNS/HTTP/TLS/flow 证据转换为规范化 `pcap.*` 事件。
所有 packet-capture 生命周期事件都会保留 `sourceTool=pktmon.exe`、
`artifactSourceTool=pktmon.exe` 和 `packetCaptureSource=guest-pktmon`；成功捕获时再补
`sizeBytes`、`sha256` 和 PCAPNG block counters。started/stopped/skipped/failed/captured rows 都会带
`artifactRelativePath`、`artifactRelativePathStatus`、`sizeBytesStatus` 与 `sha256Status`，使 pending、skipped
和 captured rows 可以统一渲染。

## 驱动 JSONL 兼容性 / Driver JSONL compatibility

`KSword.Sandbox.R0Collector` 这类 driver sidecar 应每行写一个与 `SandboxEvent`
兼容的 JSON object。Guest Agent 读取这些事件时大小写不敏感，因此 `eventType` 和
`EventType` 都可接受。

当前共享模型把 `Data` 保持为 `Dictionary<string,string>`。因此 driver JSONL producer
应把 `data` 内的值序列化为字符串，例如：

```json
{"eventType":"registry.set","source":"driver","processId":4242,"path":"HKCU\\Software\\Run","data":{"value":"C:\\sample.exe","win32Error":"0"}}
```

`processId` 等 top-level numeric field 可以继续是 JSON number。为了 MVP robustness，
guest import path 会把 `data` 下的非字符串 JSON scalar 或 object/array coercion 成字符串，
而不是让整次 run 失败；malformed JSONL 行会变成 `driver.parse_error` 事件，并在 `Data`
中保留有界 line text 和 parse diagnostics。
