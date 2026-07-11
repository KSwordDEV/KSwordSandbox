# KSword.Sandbox.R0Collector

Windows user-mode sidecar for draining events from the KSword sandbox kernel
driver and writing `SandboxEvent` JSON Lines.

中文：这是运行在 Windows guest 内的 R0 sidecar，用于从 KSword sandbox
kernel driver 拉取事件并写出 `SandboxEvent` JSONL。所有 `eventType`、JSON
key、diagnostic code 和 reason code 都保持英文稳定值；面向操作者的中文提示
使用附加的 `zhMessage` / `zhHint` / `zhNote` 字段。

## Build

The project is included in `KSwordSandbox.sln` for `Debug|x64` and `Release|x64`.
Use the repository helper because it normalizes the local Visual Studio/MSBuild
environment:

```powershell
.\scripts\Invoke-NativeBuild.ps1 `
  -Project .\KSwordSandbox.sln `
  -Configuration Debug `
  -Platform x64 `
  -Verbosity minimal
```

Do not commit generated `.exe`, `.pdb`, `.obj`, `.ilk`, `.sys`, `bin/`, `obj/`,
or `x64/` outputs.

中文：构建产物不要提交；本 README 只描述如何本地构建和诊断。

## Usage

```powershell
.\KSword.Sandbox.R0Collector.exe `
  --device \\.\KSwordSandboxDriver `
  --out C:\Sandbox\driver-events.jsonl `
  --duration 10 `
  --poll-ms 500 `
  --heartbeat
```

Options:

- `--device`, `-d`: Win32 device path. Default: `\\.\KSwordSandboxDriver`.
  中文：驱动控制设备路径。
- `--output`, `--out`, `-o`: JSONL output path, or `-` for stdout. Default: `-`.
  中文：JSONL 输出路径；`-` 表示标准输出。
- `--duration`, `-t`: Poll duration in seconds. `0` performs one health/poll/read-events pass.
  中文：轮询持续秒数；`0` 表示只执行一次 health/poll/read-events。
- `--poll-ms`, `--poll-interval`, `--poll-interval-ms`, `-p`: poll interval in milliseconds.
  中文：轮询间隔，单位毫秒。
- `--diagnose`, `--readiness`, `--readiness-check`: emit live non-mutating
  readiness diagnostics for service state, device open, ABI negotiation, and a
  bounded `READ_EVENTS` probe.
  中文：只读就绪诊断；不会安装、启动、停止、签名驱动，也不会修改 BCD。
- `--service-name <name>`: driver service name used by `--diagnose`. Default:
  `KSwordSandboxDriver`.
  中文：`--diagnose` 查询的驱动服务名。
- `--read-timeout-ms <ms>`, `--diagnose-read-timeout-ms <ms>`: timeout for the
  `--diagnose` `READ_EVENTS` probe. Default: `2000`.
  中文：就绪诊断里 `READ_EVENTS` 探测的超时时间。
- `--enable-mask <mask>`: pass a decimal or `0x` 32-bit mask through
  `IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK` before draining events and
  record requested/effective producer masks in lifecycle JSONL. `READ_EVENTS`
  reserved request flags stay zero.
  中文：设置 producer enable mask；`READ_EVENTS` 的保留 flags 仍保持 0。
- `--health`: open the live device, emit `r0collector.driverHealth`, and exit
  without polling or draining queued events.
  中文：只做 GET_HEALTH，不消费事件队列。
- `--heartbeat`: emit `r0collector.heartbeat` progress rows.
  中文：输出进度心跳行。
- `--suppress-self-noise`: suppress known collector/KSword infrastructure
  driver rows before writing JSONL. This is the default.
  中文：默认抑制 Collector/KSword 基础设施自身噪声。
- `--emit-self-noise`: keep those rows for diagnosis and mark them with
  `data.selfNoise=true` plus `data.selfNoiseReason`.
  中文：保留自身噪声并显式标记，便于诊断抑制策略。
- `--mock`: emit synthetic process/image/file/registry/network driver-category rows
  without opening a device.
  中文：不打开设备，输出合成 driver-category 行。
- `--synthetic`: alias for `--mock`.
- `--self-test`: alias for `--mock`.
- `--help`, `-h`: show CLI help.

## Current behavior

- `--mock`, `--synthetic`, and `--self-test` emit:
  - `r0collector.started`
  - optional `r0collector.heartbeat`
  - `r0collector.mockDriverEvent`
  - `driver.process`
  - `image.load`
  - `driver.file`
  - `driver.registry`
  - `driver.network`
  - optional `r0collector.heartbeat`
  - `r0collector.stopped`
- If the device cannot be opened, the collector emits
  `r0collector.deviceUnavailable` with `severity=error`,
  `readinessState=blocked`, `diagnosticStage=openDevice`, and a concrete
  `diagnosticCode` such as `open_device_not_found` or `open_device_denied`, then
  exits with code `66`.
  中文：设备打不开时会额外带 `zhMessage`/`zhHint`，用于说明服务、权限、
  符号链接或 ABI 方向的排查建议；`diagnosticCode` 不翻译。
- `--diagnose` additionally emits `r0collector.readinessDiagnostic` rows and a
  final `r0collector.readinessSummary`. These rows distinguish
  `missing_service`, `service_not_running`, `open_device_not_found`,
  `open_device_denied`, `abi_mismatch`, `read_timeout`, and
  `driver_no_events` so readiness failures do not collapse into an
  informational message.
  中文：`readinessDiagnostic` 和 `readinessSummary` 是采集健康诊断，不代表
  样本行为；请优先看 `diagnosticStage`、`diagnosticCode` 和 `zhHint`。
- If the device opens, the collector emits:
  - `r0collector.deviceOpened`
  - `r0collector.driverHealth`
  - unless `--health` was requested, `r0collector.driverCapabilities`
  - unless `--health` was requested and `--enable-mask` was supplied,
    `r0collector.driverProducerMask`
  - unless `--health` was requested, `r0collector.driverStatus` before draining
  - unless `--health` was requested, `r0collector.driverPoll`
  - unless `--health` was requested, stable driver rows from `IOCTL_KSWORD_SANDBOX_READ_EVENTS`
    (`driver.process`, `image.load`, `driver.file`, `driver.registry`,
    `driver.network`, `driver.event.reserved`, or fallback `driver.event`)
  - unless `--health` was requested, `r0collector.driverReadEvents`
    (`data.recordsProcessed`, `data.eventsEmitted`, and
    `data.collectorSuppressedEvents` distinguish consumed driver records from
    rows hidden by the collector self-noise policy; `data.processed`,
    `data.eligible`, `data.emitted`, `data.suppressed`, `data.skipped`,
    `data.head`, `data.tail`, and `data.sampling` are short aliases for
    sampling/noise diagnostics)
  - unless `--health` was requested, final `r0collector.driverStatus`
  - optional `r0collector.heartbeat`
  - `r0collector.stopped`

## JSONL contract

Every line is a `SandboxEvent` object with stable top-level fields:

```json
{"timestamp":"2026-07-10T00:00:00.000Z","eventType":"r0collector.deviceUnavailable","source":"r0collector","processId":1234,"processName":"KSword.Sandbox.R0Collector.exe","path":"\\\\.\\KSwordSandboxDriver","commandLine":"KSword.Sandbox.R0Collector.exe --out -","data":{"severity":"error","readinessState":"blocked","diagnosticStage":"openDevice","diagnosticCode":"open_device_not_found","message":"...","zhMessage":"...","win32Error":"2","hint":"...","zhHint":"..."}}
```

The `data` object is string-valued because the shared host model currently uses
`Dictionary<string,string>`.

中文：`data` 中的所有值仍按字符串写出。中文字段只作为附加显示/诊断辅助，
不会替代 `message`、`hint`、`diagnosticCode`、`reason` 等机器字段。

Driver-origin rows include additive attribution fields:

- `eventOrigin`, `producerCategory`, `subjectKind`, `processIdSource`
- `actorRole`, `subjectRole`
- `selfNoise`, `collectorNoise`, `collectorSelfNoise`, `selfProcess`,
  `selfNoiseReason`, `selfNoiseAction`, `collectorNoisePolicy`
- typed payload semantics used by reports/rules:
  - file rows: `artifactCandidateKind`, `dropLocationFamily`,
    `droppedFileCandidate`, `startupFolderCandidate`
  - registry rows: `persistenceFamily`, `servicePersistenceCandidate`,
    `ifeoPersistenceCandidate`, `startupRegistryCandidate`
  - image rows: `imageLoadFamily`, `injectionCandidate`,
    `userWritableImageCandidate`
  - network rows: `networkEvidenceKind`, `externalAddressCandidate`,
    `lateralMovementCandidate`, `downloadExecuteCandidate`, `smbCandidate`,
    `rpcCandidate`, `rdpCandidate`, `winrmCandidate`

中文：这些字段只是“证据语义化”标签，方便报告展开、行为规则消费和人工复核；
它们不是最终恶意 verdict。尤其是 `injectionCandidate`、`lateralMovementCandidate`
和 `downloadExecuteCandidate` 需要与进程树、命令行、PCAP/HTTP/TLS、dropped files
等证据组合判断。

Queue, loss, sequence, and backpressure diagnostics are intentionally repeated
with stable aliases across live rows:

- `sequence` plus `sequenceMeaning` distinguishes a concrete driver-event
  sequence from a snapshot `nextSequence`.
- `lost`, `lostCount`, `lossObserved`, and `loss` preserve driver drop evidence.
- `queueHighWatermark`/`highWatermark`, `backpressure`,
  `backpressureObserved`, `backpressureReason`, and
  `lastEnqueueFailureStatusHex` preserve pressure evidence without treating it
  as sample behavior.
- `producerRuntimeState`, `zhProducerRuntimeHint`, and the
  `*ProducerMaskHex`/`*ProducerMaskNames` fields summarize enabled, active,
  failed, and effective R0 producer state.

中文：队列丢失、序列号、背压和 producer 运行状态会使用稳定英文机器字段；
`zhProducerRuntimeHint` 和 readiness 的 `zhHint` 只用于辅助人工排查。

Normal live rows use `selfNoise=false`. With the default
`--suppress-self-noise` policy, rows for the collector PID, the exact collector
output JSONL, and known `\KSwordSandbox\agent\`, `\KSwordSandbox\r0collector\`,
`\KSwordSandbox\driver\`, and `\KSwordSandbox\out\` paths are not emitted; the
batch summary records the count in `collectorSuppressedEvents`. When
`--emit-self-noise` is active those rows are emitted with
`collectorSelfNoise=true`; rows attributed to the collector executable/PID also
carry `selfProcess=true`. Use `--emit-self-noise` when debugging the suppression
decision itself.

### `r0collector.driverHealth` producer masks

`IOCTL_KSWORD_SANDBOX_GET_HEALTH` rows decode
`KSWORD_SANDBOX_HEALTH_FLAG_PRODUCER_MASKS_AVAILABLE` as
`ProducerMasksAvailable` in `flagNames`. When the flag is set and the returned
reply size covers the producer-mask fields, `data.producerMasksAvailable` is
`true` and the row includes `producerEnableMaskHex`,
`supportedProducerMaskHex`, `activeProducerMaskHex`, and
`failedProducerMaskHex` plus `*Names` variants.

Older ABI drivers that do not advertise the flag remain accepted. In that path
`producerMasksAvailable=false`, `producerMaskFieldsReturned` records whether the
bytes were present, and the mask fields are emitted as zero-valued compatibility
diagnostics rather than failing the health check.

### `r0collector.driverNetworkStatus` WFP/ALE diagnostics

Live collection and `--diagnose` now attempt the optional read-only
`IOCTL_KSWORD_SANDBOX_GET_NETWORK_STATUS`.  When available, the collector emits
`r0collector.driverNetworkStatus` with `diagnosticStage=networkStatus`,
`networkStatusAvailable=true`, WFP/ALE layer masks (`supportedLayerMask*`,
`lastRegisteredCalloutMask*`, `lastAddedFilterMask*`, `activeLayerMask*`),
`todoMask*`, `implementationLevelName`, `classifyCount`, `eventCount`,
`queueFailureCount`, `classifyPayloadFailureCount`, `lastDegradeReasonName`,
and NTSTATUS hex fields such as `registerNtStatusHex`, `engineNtStatusHex`, and
`lastQueueFailureNtStatusHex`.

Older drivers that do not expose the IOCTL are non-fatal.  The same event type
is emitted with `networkStatusAvailable=false`,
`diagnosticCode=network_status_ioctl_unavailable`,
`readinessState=degraded`, zero-valued mask/counter fields, and
`zhMessage`/`zhHint`; collection continues for health/status/poll/read-events
and other producer families.

## Exit codes

- `0`: success.
- `64`: invalid command-line arguments.
- `65`: output JSONL file could not be opened.
- `66`: driver device could not be opened.
- `70`: runtime write failure or IOCTL/protocol failure.

中文退出码说明：`64` 是参数错误，`65` 是输出文件不可用，`66` 是驱动设备打
不开，`70` 是运行时写入、IOCTL 或协议错误。错误 JSONL 会尽量包含
`zhMessage`/`zhHint`。
