# R0Collector IOCTL 管线 / R0Collector IOCTL pipeline

`guest/KSword.Sandbox.R0Collector` 是运行在 guest VM 内的 Windows user-mode
sidecar，负责从 `KSword.Sandbox.Driver` drain 事件并写成 JSONL。

权威范围 / canonical scope：本文负责 collector CLI、runtime 和 readiness
集成说明。kernel/user ABI 的权威来源是 `docs/r0-driver-core.md`，JSONL 字段 schema
见 `docs/r0-jsonl-schema.md`，driver install/test-signing 操作者步骤见
`docs/driver-install.md`。

中文说明：`R0Collector` 是 guest VM 内的用户态 sidecar，负责通过 public
IOCTL 从内核驱动读取事件并写出 JSONL。所有 `eventType`、JSON key、
`diagnosticCode`、`reason`、`readinessState` 等机器字段保持英文稳定值；
中文只作为附加 `zhMessage`、`zhHint`、`zhNote`、`zh*Policy` 字段出现。

判读总则 / interpretation guardrails：

- ABI/version/size/capability/mask 字段用于证明 collector 与 driver 对同一 public
  wire contract 的理解是否一致；它们是兼容性 evidence，不是样本行为 verdict。
- `noise`、`selfNoise`、`collectorSelfNoise`、`collectorSuppressedEvents` 和
  `collectorSkippedEvents` 是采集噪声/采样标签。它们帮助 operator 区分 KSword
  infrastructure 与样本证据，但不能被解释成“可信进程”或“恶意进程”的最终判定。
- `lost`、`lossObserved`、`backpressure`、`backpressureObserved`、
  `backpressureReason`、`highWatermark` 和 sequence gaps 是 non-blocking ring 的
  queue-quality evidence。Driver 不因为这些字段等待、阻断或修改样本 I/O；collector/report
  只据此说明采集完整性。
- R0 `driver.network` 只提供 WFP/ALE endpoint metadata。`serviceHint`、
  `semanticCandidate`、`dnsCandidate`、`httpCandidate`、`tlsCandidate` 只是
  port/protocol correlation labels；DNS query、HTTP method/host/URI、TLS SNI 和 packet
  details 必须来自 PCAP import rows（如 `pcap.flow`、`pcap.dns`、`pcap.http`、
  `pcap.tls`），不能从 R0 candidate 字段反推。

当前状态：

- 使用 `CreateFileW` 打开 driver Win32 path `\\.\KSwordSandboxDriver`。
- 打开 device 后执行一次 `IOCTL_KSWORD_SANDBOX_GET_HEALTH`。
- 在 drain 前执行 `IOCTL_KSWORD_SANDBOX_GET_CAPABILITIES`，记录 ABI version、
  capability flags、`SupportedProducerMask`、`DefaultProducerMask` 和 layout limits。
- 当传入 `--enable-mask <mask>` 时，可选执行
  `IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK`，并输出 requested/effective mask。
- drain 前后执行 `IOCTL_KSWORD_SANDBOX_GET_STATUS`，捕获 queue depth、
  `ProducerEnableMask`、`ActiveProducerMask`、`FailedProducerMask`、supported producer bits
  和 total counters。
- drain 前执行可选 `IOCTL_KSWORD_SANDBOX_GET_NETWORK_STATUS`，输出
  `r0collector.driverNetworkStatus`，记录 WFP/ALE implementation level、layer masks、
  TODO gaps、classify/event counters、queue/classify failure counters、NTSTATUS/error
  字段和中文 `zhMessage`/`zhHint`。旧驱动不支持该 IOCTL 时，该行会以
  `diagnosticCode=network_status_ioctl_unavailable`、`readinessState=degraded`
  降级输出，并继续采集其他 producer。
- 支持 `--abi-self-check` / `--contract-self-check`，用于 no-device ABI 和 event-quality
  自检输出。该模式输出 `r0collector.abiSelfCheck`，记录 `collectorAbiVersion`、
  `capabilityFlagsCurrentHex`、`producerMaskCurrentHex`、`jsonlNoisePolicy`、
  `kernelBackpressurePolicy` 和 `queueLossEvidence`，随后在 `CreateFileW` /
  `DeviceIoControl` 前退出。
- 支持 `--diagnose` / `--readiness` / `--readiness-check`，用于在 VM 中预期服务已安装并启动后，
  生成 live 但 non-mutating 的 readiness 输出。该模式输出
  `r0collector.readinessDiagnostic` 和 `r0collector.readinessSummary` 行，包含
  `severity`、`readinessState`、`diagnosticStage`、`diagnosticCode` 字段，避免把 service
  missing、device open denied/not found、ABI mismatch、READ_EVENTS timeout、no-event
  情况压扁成泛泛的 unavailable 信息。
  中文：这些就绪行是“采集健康诊断”，不是样本行为。新增中文字段仅帮助操
  作者理解下一步排查，不能替代稳定 code。
- 在 one-shot 或 timed polling loop 中执行 `IOCTL_KSWORD_SANDBOX_POLL` 和
  `IOCTL_KSWORD_SANDBOX_READ_EVENTS`。
- 把 driver event records 转换为 `SandboxEvent` JSON Lines，供 Guest Agent 和 Host import
  path 消费。
- JSONL emission 前默认抑制狭义 collector/GuestAgent self-noise：collector PID、准确的
  collector output JSONL，以及文档化 KSword infrastructure path。被抑制记录仍通过
  `r0collector.driverReadEvents.data.collectorSuppressedEvents` 和
  `r0collector.stopped.data.collectorSuppressedEvents` 可审计。
- 保留 synthetic self-test mode（`--mock`、`--synthetic`、`--self-test`），用于未安装
  unsigned/test-signed driver 时的 CI/local plumbing。该模式现在固定附加 6 条
  semantic companion rows：`process-lineage`、`dns`、`http`、`tls`、
  `lateral-movement` 和 `download-execute`，用于 no-device 验证报告字段、
  flowKey、下载执行关联和中文 operator hints。
- 使用 `--heartbeat` 可输出可选 collector progress rows。

## 源码布局 / Source layout

`guest/KSword.Sandbox.R0Collector/src` 按 runtime responsibility 拆分：

中文：源码按职责拆分；中文化只添加显示/诊断文本，不改变 IOCTL 协议、
事件类型或字段名。

- `main.cpp`：最小 `wmain` entry point。
- `AbiSelfCheck.*`：no-device ABI/event-quality 自检行，用于 driver 安装前的 CI 和 operator preflight。
- `Options.*`：命令行解析与 usage text。
- `JsonWriter.*`：UTF-8 conversion、JSON escaping、`SandboxEvent` JSONL writer 和 fallback stderr 输出。
- `EventParser.*`：public driver ABI decoding 与 typed payload JSON mapping。
- `IoctlClient.*`：device open、`DeviceIoControl` wrapper、health/capabilities/status、
  producer-mask、poll、drain call 和 protocol error rows。
- `ReadinessDiagnostics.*`：live `--diagnose` orchestration、read-only SCM service inspection、
  device-unavailable classification、ABI compatibility probe、有界 overlapped `READ_EVENTS`
  timeout probe 和 readiness summary rows。
- `SyntheticMode.*`：用于本地 plumbing tests 的 deterministic synthetic driver-category rows；
  包含基础 mock rows、计数 `driver.file` stress corpus、JSONL noise rows，以及
  DNS/HTTP/TLS/横向移动/下载执行/进程血缘 semantic companion rows。
- `RuntimeLoop.*`：lifecycle orchestration、heartbeat rows、timed polling loop 和 exit-code mapping。

## 驱动 IOCTL 契约 / Driver IOCTL contract

public ABI 由以下头文件拥有：

```text
driver/KSword.Sandbox.Driver/include/KSwordSandboxDriverIoctl.h
```

初始 device name：

- NT device: `\Device\KSwordSandboxDriver`
- DOS link: `\DosDevices\KSwordSandboxDriver`
- Win32 path: `\\.\KSwordSandboxDriver`

初始 IOCTL：

- `IOCTL_KSWORD_SANDBOX_GET_HEALTH`
  - Input：none。
  - Output：`KSWORD_SANDBOX_HEALTH_REPLY`。
  - Purpose：driver/queue health 和 ABI sanity check。
- `IOCTL_KSWORD_SANDBOX_POLL`
  - Input：none。
  - Output：`KSWORD_SANDBOX_POLL_REPLY`。
  - Purpose：drain 前的低成本 queue snapshot。
- `IOCTL_KSWORD_SANDBOX_READ_EVENTS`
  - Input：可选 `KSWORD_SANDBOX_READ_EVENTS_REQUEST`。
  - Request `Flags` 保留且必须为 zero。此 IOCTL 不接受 producer selection；
    请使用 `IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK`。
  - Output：`KSWORD_SANDBOX_READ_EVENTS_REPLY`，后接零条或多条
    `KSWORD_SANDBOX_EVENT_HEADER + payload` records。
  - Purpose：消费排队的 R0 events。
- `IOCTL_KSWORD_SANDBOX_GET_CAPABILITIES`
  - Input：none。
  - Output：`KSWORD_SANDBOX_CAPABILITIES_REPLY`。
  - Purpose：在假设 optional IOCTL、ABI layout sizes、`SupportedProducerMask` 或
    `DefaultProducerMask` 前进行 capability negotiation。
- `IOCTL_KSWORD_SANDBOX_GET_STATUS`
  - Input：none。
  - Output：`KSWORD_SANDBOX_STATUS_REPLY`。
  - Purpose：queue/status counters、lifecycle state、`ProducerEnableMask`,
    `ActiveProducerMask`, `FailedProducerMask`, `EffectiveProducerMask`,
    `TotalEventsSuppressed`, `TotalEventsBackpressured`, producer
    dropped/suppressed/backpressure masks, queue capacity, high watermark,
    `LastNtStatus`, and `LastFailureNtStatus`.
- `IOCTL_KSWORD_SANDBOX_GET_NETWORK_STATUS`
  - Input：none。
  - Output：`KSWORD_SANDBOX_NETWORK_STATUS_REPLY`。
  - Purpose：read-only WFP/ALE runtime diagnostics。Collector 输出
    `r0collector.driverNetworkStatus`，字段包括 `supportedLayerMask*`,
    `lastRegisteredCalloutMask*`, `lastAddedFilterMask*`, `activeLayerMask*`,
    `todoMask*`, `implementationLevelName`, `classifyCount`, `eventCount`,
    `queueFailureCount`, `classifyPayloadFailureCount`, `lastDegradeReasonName`,
    `registerNtStatusHex`, `engineNtStatusHex`, and
    `lastQueueFailureNtStatusHex`。该行是 collector/readiness diagnostic，不是样本行为。
- `IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK`
  - Input：`KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK_REQUEST`。
  - Output：`KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK_REPLY`。
  - Purpose：应用操作者选择的 producer mask，并记录 requested、previous、effective
    和 supported masks。

### 能力、状态与 producer-mask 协商 / Capability/status/producer-mask negotiation

`IOCTL_KSWORD_SANDBOX_GET_CAPABILITIES` 成功后，`R0Collector` 输出
`r0collector.driverCapabilities`。该行保留 ABI major/minor、capability flag names、
producer-mask support/names、event schema name/version、event header version、ring
capacity、reply sizes 和 max payload size，供后续诊断使用。`capabilityFlagNames`
覆盖当前每个 capability bit，包括 `ProcessCreateExit`、`ImageLoad`、`FileMinifilter`、
`RegistryCallback`、`NetworkWfpAle`、`GetNetworkStatus`、`EventCommonMetadata`、
`ProducerMetadata` 和 `SelfNoiseMetadata`；同时为这些能力输出 boolean
`*Capable` 字段，包括 `getNetworkStatusCapable`。

`R0Collector` 会在 drain 前和 final drain 后，为
`IOCTL_KSWORD_SANDBOX_GET_STATUS` 输出 `r0collector.driverStatus`。这些行保留
queue depth/capacity、high watermark、`ProducerEnableMask`、`SupportedProducerMask`、
`ActiveProducerMask`、`FailedProducerMask`、`EffectiveProducerMask`、
`TotalEventsEnqueued`、`TotalEventsDropped`、`TotalEventsRead`、
`TotalEventsSuppressed`、`TotalEventsBackpressured`、`ProducerDroppedMask`、
`ProducerSuppressedMask`、`ProducerBackpressureMask`、`NextSequence`、
`LastNtStatus` 和 `LastFailureNtStatus`。JSON field names 包括
`activeProducerMask`、`activeProducerMaskHex`、`activeProducerMaskNames`、
`failedProducerMask`、`failedProducerMaskHex`、`failedProducerMaskNames`；
`effectiveProducerMask`、`effectiveProducerMaskHex`、`effectiveProducerMaskNames`、
`lastFailureNtStatus` 和 `lastFailureNtStatusHex` 镜像新增 status fields。Producer
loss masks 也输出 decimal、hex 和 name forms。

active/failed producer masks 通过此前未使用的 reserved/alignment space 发布，不需要
ABI minor bump；`KSWORD_SANDBOX_STATUS_REPLY` 的 reply `Size` 对 ABI 1.0 collectors
保持不变。旧 driver 若把 reserved space 置零，会看到两个 mask 都是 zero；新 driver 会显式填充。

传入 `--enable-mask <mask>` 时，`R0Collector` 执行
`IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK` 并输出
`r0collector.driverProducerMask`。该行记录 requested mask，以及
`KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK_REPLY` 返回的 previous、effective、supported
masks 和 producer names。

`R0Collector` 还会在 drain 前尝试 `IOCTL_KSWORD_SANDBOX_GET_NETWORK_STATUS`。
成功时输出 `r0collector.driverNetworkStatus`，用于向 WebUI/report/readiness 暴露
WFP/ALE 覆盖面：`networkStatusAvailable=true`、`networkWfpAleActive`、
`networkWfpAleDegraded`、`supportedLayerMaskNames`、`activeLayerMaskNames`、
`todoMaskNames`、`classifyCount`、`eventCount`、`queueFailureCount`、
`classifyPayloadFailureCount`、`lastDegradeReasonName` 和相关 NTSTATUS hex 字段。
不支持该可选 IOCTL 的旧驱动会输出同一 event type 的 unavailable/degraded 行，
保留 zero-valued mask/counter 字段，并继续 normal collection。

当 live driver 只实现早期 health/poll/read-events 子集时，新的 optional negotiation
调用可能以 `STATUS_INVALID_DEVICE_REQUEST` 或 `STATUS_NOT_SUPPORTED` 的 Win32 映射失败。
Collector 会把这类特定 optional failure 视为非致命，输出
`r0collector.optionalIoctlUnavailable`，并继续使用兼容 drain path。

`IOCTL_KSWORD_SANDBOX_DRAIN_EVENTS` 可能作为本地 driver 实验中的兼容 alias 存在，
但 R0Collector 使用公开的 `READ_EVENTS` 名称。

## 当前驱动事件路径 / Current driver event path

driver 拥有固定 non-paged ring buffer。加载时当前会排入一条 typed `driver.load`
self-test 事件，带 `KSWORD_SANDBOX_EVENT_FLAG_SELF_TEST` 和
`KSWORD_SANDBOX_EVENT_FLAG_DRIVER_STARTED`。`READ_EVENTS` 从 ring 消费完整 records，
并报告 drop/sequence counters。

concrete behavior payload 按 event type 解析。File events 使用
`KSWORD_SANDBOX_FILE_EVENT_PAYLOAD`，暴露 `operationName`、`filePath`、
`pathPresent`、`pathTruncated`、`statusHex`、`majorFunction`、`minorFunction` 等字段。
Process payloads 暴露 lineage cache/replay flags、parent/creator identifiers、
bounded image paths 和 command-line prefixes。Image payloads 暴露 process-id/property
presence、base、size、image properties 和 bounded paths。Registry payloads 暴露
key/value provenance、status、value-type、value-size 和 bounded key/value names。

Network events 使用 WFP/ALE producer 的 `KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD`。
R0Collector 现在解析 `protocolName`、`directionName`、`addressFamilyName`、
`localAddress`、`remoteAddress`、`localPort`、`remotePort`、`localEndpoint`、
`remoteEndpoint`、`sourceEndpoint`、`destinationEndpoint`、`flowKey`、
`transportProtocol`、`servicePort`、`serviceHint`、`semanticCandidate`、
DNS/HTTP/TLS candidate booleans、`processIdPresent`、`flowHandleHex`、
`transportEndpointHandleHex`、`layerIdHex`、`calloutIdHex` 和 `filterIdHex`。
address bytes 也以 `localAddressHex` 和 `remoteAddressHex` 保留用于 diagnosis。
Synthetic `driver.network` rows 与 valid extra-field JSONL noise row 使用相同的
`sourceEndpoint`、`destinationEndpoint`、`flowKey` 名称，使 no-device stress runs
能在 WFP 加载前覆盖 report correlation contract。mock/stress semantic companion
rows additionally cover DNS/HTTP/TLS port hints and SMB/445 lateral movement
with `protocolPayloadParsed=false` and `pcapCorrelationRequired=true`, so the
field shape is testable without pretending that R0 parsed packet payloads.

网络语义注意：`serviceHint` 和 DNS/HTTP/TLS candidate booleans 是 evidence labels，
不是协议解析 verdict。R0Collector 不从 ALE payload 中解析 DNS name、HTTP Host/URI 或 TLS
SNI；它只保留 endpoint/PID/layer/callout/filter 信息，让 Host import 可以把这些行与
PCAP-derived rows 关联。

当 file/process/image/registry payload 携带 bounded subject path 时，top-level
`SandboxEvent.path` 会设置为该 subject path，让 WebUI live monitor 和 HTML report
显示相关对象，而不是只显示 `\\.\KSwordSandboxDriver`。Network events 在 remote endpoint
可解析时使用类似 URI 的 top-level path（如 `tcp://203.0.113.10:443`），完整 endpoint 和
flow correlation details 保留在 `data` 中。

## CLI 契约 / CLI contract

```powershell
KSword.Sandbox.R0Collector.exe `
  --device \\.\KSwordSandboxDriver `
  --out C:\Sandbox\driver-events.jsonl `
  --duration 10 `
  --poll-ms 500 `
  --enable-mask 0xffffffff `
  --heartbeat
```

支持的选项（flag 名保持英文，中文说明用于操作者理解）：

中文：CLI help 现在按英文 / 中文并列输出；flag 名、枚举值和路径参数不翻
译，方便脚本和 smoke tests 继续匹配。

- `--device`, `-d`：driver device 的 Win32 symbolic-link path。
- `--output`, `--out`, `-o`：JSON Lines 输出路径；`-` 表示 stdout。
- `--duration`, `-t`：polling duration（秒）。`0` 表示 one-shot open、health、poll、
  read-events。
- `--poll-ms`, `--poll-interval`, `--poll-interval-ms`, `-p`：poll interval（毫秒）。
- `--diagnose`, `--readiness`, `--readiness-check`：运行 live 但 non-mutating 的 readiness
  diagnostic pass。Collector 会查询 `--service-name` 的 SCM state、打开 device、检查
  `GET_CAPABILITIES` ABI compatibility、输出 health/status rows，并执行有界 `READ_EVENTS`
  probe；不会 install/start/stop/sign driver。
- `--service-name <name>`：`--diagnose` service diagnostics 使用的 kernel service name；
  默认 `KSwordSandboxDriver`。
- `--read-timeout-ms <ms>` / `--diagnose-read-timeout-ms <ms>`：`--diagnose` overlapped
  `READ_EVENTS` probe timeout；默认 `2000`。
- `--max-events <count>`：每个 `READ_EVENTS` request 限制在 1..1024 events。synthetic
  stress check 中用小值证明 batching 和 sequence continuity。
- `--max-read-batches <n>`：成功 drain `n` 个 READ_EVENTS batch 后停止；`0` 表示直到 duration
  deadline 或 empty batch 前不限。这是安全本地测试的 bounded batch limit 和
  stress/backpressure 输入。
- `--driver-event-sample-stride <n>` / `--event-sample-stride <n>`: optional
  collector-side large-stream throttle for live driver rows. The default `1`
  emits every eligible driver row. Values greater than `1` emit the first
  eligible row and every nth eligible row after self-noise suppression; skipped
  rows remain counted in `r0collector.driverReadEvents.data.skipped` and
  `collectorSkippedEvents`.
- `--abi-self-check`: emit an ABI/event-quality contract row and exit without
  opening `\\.\KSwordSandboxDriver`. The collector does not open the driver
  device and does not call `DeviceIoControl` in this mode.
- `--contract-self-check`: alias for `--abi-self-check`.
- `--enable-mask <mask>`: pass an unsigned 32-bit decimal or `0x` hexadecimal
  mask through `IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK`, then record the
  requested/effective mask in `r0collector.driverProducerMask`. The collector
  also includes the requested value in lifecycle rows for reproducibility. This
  mask is never copied into `KSWORD_SANDBOX_READ_EVENTS_REQUEST.Flags`.
- `--health`: open the live device, emit `r0collector.driverHealth`, and exit
  without polling or draining queued events.
- `--heartbeat`: emit `r0collector.heartbeat` lifecycle rows after startup, at
  each completed poll/read-events iteration, and at synthetic completion.
- `--suppress-self-noise`: default live-driver policy. Suppress driver rows for
  the collector PID, the exact collector output JSONL, and known KSword
  infrastructure paths before writing JSONL.
- `--emit-self-noise` / `--no-suppress-self-noise`: diagnostic override that
  emits those rows with `selfNoise=true`, `selfNoiseReason`, and
  `selfNoiseAction=emit`.
- `--mock`: emit synthetic process/image/file/registry/network rows and the
  semantic companion corpus (`process-lineage|dns|http|tls|lateral-movement|download-execute`);
  do not open the driver device.
- `--synthetic`: alias for `--mock`.
- `--self-test`: alias for `--mock`; intended for quick operator checks.
- `--stress-count <n>`: emit `n` contiguous synthetic `driver.file` rows with
  `stress=true`, `sequence`, `StressJsonlExpectedDriverRows`,
  `StressJsonlSequenceStart`, `StressJsonlSequenceEnd`,
  `StressJsonlSequenceGapCount`, loss evidence, and backpressure evidence. This
  option implies `--mock`, never opens the driver, and is intended to move the
  event-quality/stress corpus into the shipped collector binary instead of only
  C# fixtures. The counted stress corpus remains `driver.file` for compatibility;
  semantic companion rows are emitted separately and are announced by
  `semanticSelfCheckScenarios` / `semanticSelfCheckRows`.
- `--inject-jsonl-noise`: in mock/stress mode, append a blank line, malformed
  JSON row, and valid row with an ignored extra top-level field. This proves the
  Host live/import path can tolerate partial JSONL without hiding valid rows.

device unavailable 行为是显式的：collector 会把 `r0collector.deviceUnavailable`
写入选定 JSONL sink，并以 exit code `66` 退出。该行包含 `severity=error`、
`readinessState=blocked`、`diagnosticStage=openDevice`，以及具体 `diagnosticCode`，
例如 `open_device_not_found`、`open_device_denied`、`open_device_sharing_violation`
或 `open_device_failed`。它还记录 `deviceAvailability=unavailable`、
`collectionDiagnostic=true`、`sampleBehavior=false`、`ioctlIssued=false`、
`driverLoadedByCollector=false`、`mutatesDriver=false`、
`sideEffectPolicy=read-only-open-no-driver-load-no-scm-mutation-no-signing` 和
`operatorInterpretation=collection_diagnostic_not_sample_behavior`，明确说明缺失或不可访问
device 是采集/readiness 问题，不是样本恶意行为证据。

中文：设备不可用时，`message`/`hint` 保留英文原文，同时新增
`zhMessage`/`zhHint`。排查顺序通常是服务是否安装并运行、设备符号链接是
否创建、Collector 是否提权、驱动和 Collector ABI 是否匹配。

当 driver 预期已经在 VM 中安装并启动后，可运行 live readiness diagnostic：

```powershell
KSword.Sandbox.R0Collector.exe `
  --diagnose `
  --service-name KSwordSandboxDriver `
  --device \\.\KSwordSandboxDriver `
  --read-timeout-ms 2000 `
  --out C:\Sandbox\r0collector-readiness.jsonl
```

预期诊断行 / Expected diagnostic rows：

- `r0collector.readinessDiagnostic` with `diagnosticStage=service`. Codes include
  `missing_service`, `service_not_running`, `service_query_denied`, and
  `service_running`.
- `r0collector.deviceUnavailable` when `CreateFileW` fails. `win32Error` and
  `win32Message` are preserved, and the hint distinguishes service/load/symbolic-
  link problems from permission failures. The row is marked
  `collectionDiagnostic=true` and `sampleBehavior=false`.
- `r0collector.readinessDiagnostic` with `diagnosticStage=abiNegotiation`. Codes
  include `abi_compatible`, `abi_capabilities_unavailable`,
  `abi_ioctl_failed`, and `abi_mismatch`.
- `r0collector.driverNetworkStatus` when the device opens far enough to issue
  GET_NETWORK_STATUS. Successful rows include WFP/ALE masks/counters and
  `diagnosticStage=networkStatus`; unsupported older drivers produce
  `network_status_ioctl_unavailable` with `readinessState=degraded` and do not
  block READ_EVENTS diagnostics.
- `r0collector.readinessDiagnostic` with `diagnosticStage=readEvents`. Codes
  include `read_timeout`, `read_ioctl_failed`, `read_protocol_error`,
  `driver_no_events`, and `read_events_ready`.
- `r0collector.readinessSummary` with `ready`, `degraded`, `severity`,
  `readinessState`, `failedStage`, `serviceDiagnosticCode`,
  `openDeviceDiagnosticCode`, `abiDiagnosticCode`, and
  `readEventsDiagnosticCode`.

中文：每条 `readinessDiagnostic` 都会保留 `hint` 并附加 `zhHint`；
`readinessSummary` 会附加 `zhMessage`/`zhHint`，提示是否阻塞、降级或可
继续采集。不要翻译 `missing_service`、`abi_mismatch`、`read_timeout` 等
诊断 code。

`driver_no_events` 是 warning/degraded condition，不是 protocol failure：
`READ_EVENTS` 已完成但 queue 为空。它通常表示 startup heartbeat 已被 drain，
或 producer 尚未观察到样本活动。`read_timeout`、`abi_mismatch`、
`open_device_denied` 和 `open_device_not_found` 是 hard blocked readiness states。

无 driver 快速自检 / Quick self-test without a driver：

```powershell
KSword.Sandbox.R0Collector.exe `
  --self-test `
  --heartbeat `
  --enable-mask 0x3 `
  --out -
```

无 driver 事件质量压力检查 / Quick event-quality stress without a driver：

```powershell
KSword.Sandbox.R0Collector.exe `
  --stress-count 32 `
  --inject-jsonl-noise `
  --heartbeat `
  --out C:\Sandbox\r0collector-stress.jsonl
```

预期压力证据 / Expected stress evidence：

- `r0collector.started` and `r0collector.mockDriverEvent` rows with
  `stressCount`, `stress=true`, and the `StressJsonl*` field set so automation
  can verify the intended corpus before scanning all rows.
- 32 `driver.file` rows with `stress=true`; these remain the counted stress
  corpus for compatibility with existing smoke tests.
- 6 semantic companion rows with concrete sequence values outside the stress
  range (`1100..1105`) and `semanticSelfCheck=true`: process lineage, DNS
  egress, HTTP egress/download, TLS egress/download, SMB lateral movement, and
  downloaded executable file creation. They are listed in
  `semanticSelfCheckScenarios` and do not change `StressJsonlExpectedDriverRows`.
- `sequence` range `1200..1231` and `StressJsonlSequenceGapCount=0`.
- a mock `r0collector.driverReadEvents` summary with
  `recordsProcessed`/`eventsEmitted`, `processed`/`eligible`/`emitted`,
  `suppressed`/`skipped`, `head`/`tail`, `sampling`, `sequenceMeaning`,
  `lostCount`, `lossObserved`, `highWatermark`, `backpressure`,
  `backpressureObserved`, and `backpressureReason`.
- loss/backpressure fields such as `totalEventsDropped`, `queueHighWatermark`,
  `readEventsMaxEvents`, `maxReadBatches`, and `lastEnqueueFailureStatus`.
- one blank line, one malformed JSON row, and one valid extra-field row when
  `--inject-jsonl-noise` is supplied. The valid extra-field row keeps TLS
  endpoint/flowKey candidate fields plus `protocolPayloadParsed=false` so noise
  tolerance does not imply protocol payload parsing.

无 driver 轻量 attribution/self-noise smoke：

```powershell
$out = Join-Path $env:TEMP 'ksword-r0-self-test-noise.jsonl'
KSword.Sandbox.R0Collector.exe `
  --self-test `
  --heartbeat `
  --emit-self-noise `
  --inject-jsonl-noise `
  --out $out

$rows = Get-Content $out | Where-Object { $_.Trim() } | ForEach-Object {
  try { $_ | ConvertFrom-Json -ErrorAction Stop } catch { $null }
}
$driverRows = $rows | Where-Object source -eq 'driver'
$driverRows | Where-Object { $_.data.eventOrigin -and $_.data.subjectKind } |
  Measure-Object
```

Expected: the process exits `0`, one intentionally malformed line fails JSON
parsing, and every parsed synthetic driver row has `eventOrigin`,
`producerCategory`, `subjectKind`, `processIdSource`, and `selfNoise` fields.

### JSONL 质量与噪声契约 / JSONL quality and noise contract

中文：本节列出的字段全部是“证据质量、归因或采集状态”标签。它们帮助 operator 判断
JSONL 是否完整、哪些行被抑制、是否存在 queue pressure；它们不是 malicious/benign verdict，
也不是 block/allow decision。

Every collector-owned row keeps the event-quality fields stable under `data`:

- `schema` mirrors `eventSchemaName` (`ksword.sandbox.r0.event`) for compact
  downstream checks.
- `producer` names the row family (`r0collector`, `file`, `process`, `image`,
  `registry`, or `network`).
- `noise` is `false` for normal rows. It is `true` for the valid synthetic
  extra-field row emitted by `--inject-jsonl-noise` and for self-noise rows only
  when the operator explicitly uses `--emit-self-noise`.
- `selfNoise`, `collectorNoise`, `collectorSelfNoise`, `selfProcess`,
  `selfNoiseReason`, `selfNoiseAction`, `collectorNoisePolicy`, and
  `collectorSuppressed` explain collector/KSword infrastructure attribution.
  With the default suppression policy those noisy driver rows are not emitted;
  counts remain in `collectorSuppressedEvents`.
- `eventOrigin`, `producerCategory`, `subjectKind`, `processIdSource`,
  `actorRole`, and `subjectRole` make driver-row ownership readable without
  relying on report-generation heuristics.
- `semanticScenario`, `semanticSelfCheck`, `semanticSelfCheckScenarios`,
  `semanticSelfCheckRows`, `semanticEvidenceKind`, and `zhSemanticHint` are
  stable no-device semantic smoke fields. They identify companion rows for
  process lineage, DNS/HTTP/TLS endpoint candidates, lateral movement ports, and
  download-execute correlation without changing live ABI or stress row counts.
- Protocol parser boundary fields are explicit on synthetic network/noise rows:
  `protocolPayloadParsed=false`, `protocolParserSource=r0-ale-endpoint-only`,
  `pcapCorrelationRequired=true`, `dnsQueryNameAvailable=false`,
  `httpHostAvailable=false`, `httpUriAvailable=false`, and
  `tlsSniAvailable=false`. 中文：这些字段提醒 operator，R0 网络行只证明
  WFP/ALE 端点和端口语义；DNS name、HTTP Host/URI、TLS SNI 必须由 PCAP/
  浏览器/sidecar 证据补齐。
- `sequence` is a concrete driver event sequence on driver rows and a
  `nextSequence` alias on snapshot/summary rows. Snapshot rows set
  `sequenceMeaning=nextSequence` so reports do not confuse a future sequence
  with an already delivered event.
- `lost` is `true` only when the row itself reports drop/loss counters;
  `lostCount` preserves the numeric drop count and `lossObserved` mirrors the
  boolean loss classification. Delivered driver rows keep `lost=false` and use
  `sequence` plus status/read counters for gap analysis.
- `highWatermark` is the stable JSONL alias for
  `QueueHighWatermark`/`queueHighWatermark`; rows without a live queue snapshot
  emit `0` rather than omitting the field in mock/schema smoke output.
- `backpressure` / `backpressureObserved` are set on status/read rows when the
  queue reached capacity, a batch filled the requested cap, or drop counters are
  non-zero. `backpressureReason` carries the machine-readable reason such as
  `events-dropped`, `requested-max-events-reached`, `output-buffer-full`, or
  `none`. Synthetic stress rows keep `backpressure=false` but name the
  `StressJsonlBackpressureEvidence` field set.
- `r0collector.driverReadEvents` keeps both old and concise batch counters near
  the front of `data`: `recordsProcessed`, `eventsEmitted`,
  `collectorSuppressedEvents`, `collectorSkippedEvents`, `eligibleEvents`, plus
  aliases `processed`, `eligible`, `emitted`, `suppressed`, `skipped`,
  `head`, `tail`, `sampling`, `loss`, `lossObserved`,
  `backpressureObserved`, and `backpressureReason`. This order is deliberate so
  host report sampling keeps the important accounting fields even when raw JSONL
  contains many additional diagnostics.
- `collectionDiagnostic=true`, `sampleBehavior=false`, and
  `operatorInterpretation=collection_diagnostic_not_sample_behavior` are used
  on device/readiness/IOCTL diagnostic rows to separate collector health from
  sample activity.

malformed line 处理是刻意且有界的。除非在 mock/stress mode 中显式请求
`--inject-jsonl-noise`，collector 只输出 valid JSONL。该选项会追加一条 blank line、
一条带 `sequence=broken` marker 的 truncated/malformed JSON object，以及一条带 ignored
extra top-level field 和 `noise=true` 的 valid `driver.network` row。该合法噪声行也保留
TLS candidate、flowKey、`semanticScenario=jsonl-extra-field-tls-noise` 和中文
`zhSemanticHint`，用于验证 extra fields 不会破坏导入。live reader 会跳过
blank/malformed rows，保证 valid telemetry 仍可见；host import 会把 malformed rows 保留为
`driver.parse_error` 证据，而不是隐藏它们。

self-noise suppression 同样有界。它不是宽泛的 process trust decision：collector 只抑制
当前 collector PID、自己正在写的准确 JSONL 文件，以及文档化 KSword infrastructure path
片段，例如 `\KSwordSandbox\agent\`、`\KSwordSandbox\r0collector\`、
`\KSwordSandbox\driver\`、`\KSwordSandbox\out\`。drain-loop continuation 基于
`recordsProcessed` 而不是 emitted row count，因此即使一个 noisy batch 全部被抑制，
collector 也不会在 driver queue 清空前停止。Optional stride sampling 只在该 self-noise
classification 之后应用；默认关闭，并且不会改变 `recordsProcessed`。

## ABI 自检模式 / ABI self-check mode

在 signed/test-signed driver 可用前、VM image bake 前，或 CI 中故意禁止加载 kernel driver
时，使用 `--abi-self-check`：

```powershell
KSword.Sandbox.R0Collector.exe `
  --abi-self-check `
  --heartbeat `
  --max-events 16 `
  --max-read-batches 4 `
  --driver-event-sample-stride 1 `
  --enable-mask 0x3f `
  --out C:\Sandbox\r0collector-abi-self-check.jsonl
```

该模式先输出正常 `r0collector.started` / 可选 heartbeat rows，然后输出单条
`r0collector.abiSelfCheck`，最后输出带 `reason=abiSelfCheckComplete` 的
`r0collector.stopped`。它不打开 `\\.\KSwordSandboxDriver`，不要求 Administrator，
也不发出 `DeviceIoControl`；它纯粹是 collector/header contract check。

重要 `r0collector.abiSelfCheck` 证据字段：

- `selfCheckPassed`, `opensDriverDevice`, `ioctlIssued`: prove this was a
  no-device source/ABI self-check instead of a live driver drain.
- `collectorAbiVersion`, `collectorAbiVersionHex`, `abiVersionMajor`,
  `abiVersionMinor`, `eventHeaderVersion`, `eventSchemaName`, and
  `eventSchemaVersion`: prove the collector binary was compiled against the
  expected public ABI/schema version.
- `capabilityFlagsCurrentHex`, `producerMaskCurrentHex`,
  `producerMaskDefaultHex`, and producer/capability name fields: prove the
  collector knows the current process/image/file/registry/network producer
  families and optional IOCTL capability bits.
- `schema`, `producer`, `noise`, `selfNoise`, `collectorSelfNoise`,
  `selfProcess`, `selfNoiseReason`, `lost`, `backpressure`, and
  `stableJsonlFields`: prove the collector binary knows the stable event-quality
  field names used by live, mock, stress, and noise rows.
- `semanticSelfCheckScenarios`, `semanticSelfCheckRows`,
  `semanticSelfCheckSequenceStart`, `semanticSelfCheckSequenceEnd`,
  `semanticSelfCheckPolicy`, and `networkProtocolParserBoundary`: prove the
  no-device semantic companion corpus and R0/PCAP parser boundary are compiled
  into the collector binary.
- `eventHeaderSize`, `healthReplySize`, `capabilitiesReplySize`,
  `statusReplySize`, `networkStatusReplySize`, `readEventsRequestSize`,
  `readEventsReplyHeaderSize`, network-status offset fields, and payload-size
  fields: capture fixed structure layout assumptions used by the collector parser.
- `requestedMaxEvents`, `readEventsMaxEvents`, `maxEventsBounds`,
  `maxReadBatches`, `driverEventSampleStride`, and
  `driverEventSamplingPolicy`: capture the batch/backpressure/sampling knobs
  the run will use. The default sample stride is `1`, meaning no collector-side
  driver-row sampling.
- `readEventsRequestFlagsPolicy`: documents that `READ_EVENTS.Flags` must remain
  zero.
- `producerSelectionPolicy`: documents that producer selection belongs only to
  `IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK`.
- `jsonlNoisePolicy`: documents that blank live rows are ignored, malformed
  imported rows must remain visible as `driver.parse_error`, and valid rows with
  extra fields are tolerated.
- `jsonlMalformedPolicy`: documents that malformed output is produced only by
  the explicit noise injector and must remain visible to import as parse-error
  evidence.
- `kernelBackpressurePolicy`: documents the non-blocking kernel ring behavior:
  producers do not wait for the collector; overflow overwrites the oldest unread
  record.
- `queueLossEvidence`: names the diagnostic fields that must be preserved for
  lost-record analysis: `TotalEventsDropped`, `EventsDropped`,
  `TotalEventsSuppressed`, `TotalEventsBackpressured`, `ProducerDroppedMask`,
  `ProducerSuppressedMask`, `ProducerBackpressureMask`, `NextSequence`,
  per-event `sequence`, and `QueueHighWatermark`.

把 `--abi-self-check` 当作低成本 preflight：它证明 collector 和 public headers 在
ABI/event-quality assumptions 上一致，但不证明 driver service 已安装、已签名、已加载或正在返回
live events。

### 稳定 ABI/layout evidence fields / Stable ABI/layout evidence fields

`--abi-self-check` 输出以下 collector-owned field names，并在编译期用
`static_assert` 守护关键结构大小/偏移。它们是 release/readiness contract evidence，
不是样本行为字段；下游应按字段名消费，不要依赖中文提示文本。

- Event header: `eventHeaderSize`, `eventHeaderSequenceOffset`,
  `eventHeaderLostEventsOffset`, `eventHeaderBackpressureEventsOffset`,
  `eventHeaderOperationOffset`, `eventHeaderStatusOffset`, and
  `eventHeaderProducerMetadataFlagsOffset`.
- Status/queue: `statusReplySize`, `statusQueueHighWatermarkOffset`,
  `statusTotalEventsDroppedOffset`, `statusTotalEventsBackpressuredOffset`, and
  `statusLastEnqueueFailureOffset`.
- READ_EVENTS: `readEventsRequestSize`, `readEventsReplyHeaderSize`,
  `readEventsEventsDroppedOffset`, and `readEventsEventsOffset`.
- Network status: `networkStatusReplySize`, `networkStatusTodoMaskOffset`,
  `networkStatusPayloadVersionOffset`, `networkStatusLastDegradeReasonOffset`,
  `networkStatusClassifyCountOffset`, `networkStatusEventCountOffset`,
  `networkStatusQueueFailureCountOffset`, and `networkStatusLastQueueFailureOffset`.
- Typed payload sizes: `driverLoadPayloadSize`, `processPayloadSize`,
  `imagePayloadSize`, `filePayloadSize`, `registryPayloadSize`,
  `networkPayloadSize`, and `eventMaxPayloadSize`.
- Stable semantic/noise fields: `stableJsonlFields`,
  `typedPayloadSemanticFields`, `selfNoiseClassificationFields`,
  `stressBackpressureDiagnostics`, and `queueLossEvidence`.

中文：如果这些字段消失、改名或 offset/size 变化，readiness 应视为 ABI/schema
drift，需要同步 public header、collector parser、docs 和 smoke tests。中文
`zhAbiGuardPolicy`、`zhNetworkProtocolParserBoundary`、`zhSemanticSelfCheckPolicy`
只帮助人工理解，不替代英文机器字段。

## VM 就绪检查与一次性 drain / VM readiness and one-shot drain

real VM run 前使用 `scripts/Test-R0Readiness.ps1`。默认模式是 non-destructive，
不会打开 `\\.\KSwordSandboxDriver`。它检查 source files、`.sys` git hygiene、
driver readability、Authenticode status、Administrator status、test-signing state、
read-only service state，并在 collector executable 存在时执行 no-device
`R0Collector ABI self-check`：

```powershell
.\scripts\Test-R0Readiness.ps1 `
  -DriverSysPath C:\KSwordSandbox\driver\KSword.Sandbox.Driver.sys `
  -R0CollectorPath C:\KSwordSandbox\tools\KSword.Sandbox.R0Collector.exe
```

readiness 脚本在 default mode 中按以下方式调用 collector：
`--abi-self-check --out <CollectorAbiSelfCheckOutputPath>`。它不会传入 `--device`，
不会打开 driver object，不会发出 `DeviceIoControl`，不会加载 service，也不会调用
`CSignTool`。如果 Windows endpoint policy 阻止未签名 collector executable，脚本会把该行报告为
`Warning` / non-fatal readiness gap，而不是中断其余 readiness output。

当 VM image bake 或 CI job 需要把 JSONL evidence 放在稳定位置时，使用
`-CollectorAbiSelfCheckOutputPath <path>`：

```powershell
.\scripts\Test-R0Readiness.ps1 `
  -R0CollectorPath C:\KSwordSandbox\tools\KSword.Sandbox.R0Collector.exe `
  -CollectorAbiSelfCheckOutputPath C:\KSwordSandbox\out\r0collector-abi-self-check.jsonl
```

在 VM 中显式安装并启动已签名 driver service 后，
验证 public health IOCTL：

```powershell
.\scripts\Test-R0Readiness.ps1 `
  -DevicePath \\.\KSwordSandboxDriver `
  -CheckDeviceHealth
```

只有当 `CreateFileW("\\.\KSwordSandboxDriver", ...)` 成功打开 device，且
`IOCTL_KSWORD_SANDBOX_GET_HEALTH` 返回 public health reply 时，该检查才会成功。

readiness 脚本还会在任何 driver load 前执行默认 static negotiated-IOCTL contract check。
该 source/docs-only 行覆盖 `IOCTL_KSWORD_SANDBOX_GET_CAPABILITIES`、
`IOCTL_KSWORD_SANDBOX_GET_STATUS` 和
`IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK`；即使 signed/test-signed driver
无法加载，也用于捕获 ABI 或 runbook drift。在刻意隔离的 VM 之外，把 live load failure
视为 non-fatal diagnostics，并结合 static row 与 VM logs 判断变化点。

接着验证 collector health-only CLI contract；它会调用
`R0Collector --health --out <jsonl>`；只有输出 JSONL 可解析，并包含
`r0collector.deviceOpened` 和 `r0collector.driverHealth` 时才通过：

```powershell
New-Item -ItemType Directory -Force C:\KSwordSandbox\out | Out-Null

.\scripts\Test-R0Readiness.ps1 `
  -R0CollectorPath C:\KSwordSandbox\tools\KSword.Sandbox.R0Collector.exe `
  -DevicePath \\.\KSwordSandboxDriver `
  -CheckCollectorHealth `
  -CollectorHealthOutputPath C:\KSwordSandbox\out\r0collector-health.jsonl
```

然后通过脚本运行 collector one-shot drain：

```powershell
.\scripts\Test-R0Readiness.ps1 `
  -R0CollectorPath C:\KSwordSandbox\tools\KSword.Sandbox.R0Collector.exe `
  -DevicePath \\.\KSwordSandboxDriver `
  -DrainWithCollector `
  -CollectorOutputPath C:\KSwordSandbox\out\driver-events.jsonl
```

drain path 使用 `--duration 0` 调用 R0Collector，因此它会打开 driver，输出
health/capabilities/status/network-status/poll/read-events lifecycle rows，drain 所有 queued driver records
并退出。首次 load 通常应暴露 typed driver-start heartbeat row（`driver.load`），除非已被其他
reader 消费。较旧本地 build 仍可能显示 legacy `driver.event.reserved` heartbeat。

live VM 路径的预期脚本行 / Expected script rows for the live VM path：

- `Driver .sys git hygiene`: no `.sys` file is tracked, staged, modified, or
  unignored as a commit candidate.
- `Windows test-signing boot option`: `Passed` after `bcdedit /set
  testsigning on` and reboot for test-signed drivers.
- `Kernel service state`, `Service install`, and `Service start`: prove SCM
  registration and load when the explicit service-mutation switches are used.
- `Device IOCTL health`: proves the Win32 device can be opened and health IOCTL
  works.
- `R0Collector health`: proves `--health --out` output is valid.
- `R0Collector drain`: proves `--out --duration 0` output includes health,
  `r0collector.driverCapabilities`, at least one `r0collector.driverStatus`,
  `r0collector.driverNetworkStatus`, poll, read-events, and queued driver rows.
- `r0collector.driverProducerMask`: expected when a VM operator invokes
  R0Collector with `--enable-mask <mask>` to exercise
  `IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK`.
- `requestedMaxEvents` on `r0collector.driverReadEvents`: records the exact
  `READ_EVENTS` batch cap used for that collector run.
- `processed`/`eligible`/`emitted`/`suppressed`/`skipped`,
  `head`/`tail`, `sampling`, `loss`, and `backpressureObserved` on
  `r0collector.driverReadEvents`: preserve batch accounting and sequence
  bounds in both raw JSONL and sampled reports.
- `drainStoppedAtBatchLimit` on `r0collector.stopped`: indicates the runtime
  loop exited because `--max-read-batches` was reached instead of waiting for
  the duration deadline.

## JSON Lines 格式 / JSON Lines format

Every output line is a single `SandboxEvent`-compatible JSON object:

中文：JSONL 仍保持单行一个 `SandboxEvent`。`data` 里所有值按字符串写出；
新增中文字段也遵守这一规则。Host/Report 可以展示 `zhMessage`/`zhHint`，
但规则匹配和聚合仍应使用英文稳定字段。

```json
{"eventType":"driver.load","source":"driver","timestamp":"2026-07-10T00:00:00.000Z","processId":1234,"processName":"","path":"\\\\.\\KSwordSandboxDriver","commandLine":"","data":{"sequence":"1","driverEventTypeName":"driverLoad","producerCategory":"driver","eventOrigin":"kernel-driver-control-plane","subjectKind":"driver","processIdSource":"eventHeader","selfNoise":"false","flagsHex":"0x00000003","driverLoadEventName":"driver.load","zhDriverLoadEventDescription":"..."}}
```

顶层字段规则 / Top-level field rules：

- `eventType`: collector lifecycle/error type or normalized driver event type.
- `source`: `r0collector` for lifecycle rows, `driver` for drained R0 rows.
- `timestamp`: collector UTC timestamp for the JSONL row.
- `processId`: typed payload subject PID when present; otherwise the driver
  event header PID. `data.processIdSource` names which source won.
- `processName`: populated only when the payload provides a process image. It is
  empty on driver rows that cannot safely name the owning process; lifecycle
  rows still name the collector executable.
- `path`: device path for lifecycle rows. File, process, image, and registry
  rows use subject paths when payloads carry them; network rows use a URI-like
  remote endpoint when decoded.
- `commandLine`: lifecycle rows use the collector invocation. Live driver rows
  keep this empty unless a typed process payload carries a command-line prefix.
- `data`: string-valued metadata compatible with the current host model.
  Driver rows include `eventSchemaName`, `eventSchemaVersion`, and
  `payloadSchema` when the payload category is known; mock rows use the same
  schema names and attribution fields so mock/live JSONL remain comparable.

详细 JSONL contract 见 [`docs/r0-jsonl-schema.md`](r0-jsonl-schema.md)。

## 合成事件质量与背压契约 / Synthetic event-quality and backpressure contract

任何 real driver load 之前，R0Collector event quality 都先用 synthetic JSONL 验证。
这些测试不调用 CSignTool、不修改 service、不打开 `\\.\KSwordSandboxDriver`；它们生成
collector-shaped rows，并通过 host/live JSONL readers 消费。

必需合成覆盖 / Required synthetic coverage：

- ABI structure version evidence: capabilities and driver rows preserve
  `version`, `versionHex`, ABI major/minor, `eventHeaderVersion`,
  `eventSchemaName`, `eventSchemaVersion`, `recordSize`, `payloadSize`, and
  `payloadSchema`.
- Producer-mask evidence: lifecycle/status rows include requested, previous,
  effective, supported, active, and failed masks. `READ_EVENTS.Flags` remains
  zero; producer selection belongs to
  `IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK`.
- Queue overflow/loss evidence: status and batch rows include
  `QueueHighWatermark`/`queueHighWatermark`, `TotalEventsDropped`/
  `totalEventsDropped`, `eventsDropped`, `TotalEventsSuppressed`,
  `TotalEventsBackpressured`/`totalEventsBackpressured`,
  `ProducerDroppedMask`/`producerDroppedMask`,
  `ProducerSuppressedMask`/`producerSuppressedMask`,
  `ProducerBackpressureMask`/`producerBackpressureMask`, `nextSequence`, and
  per-driver-row `sequence` plus read-batch `head`/`tail`, `loss`, and
  `backpressureObserved` so lost records can be diagnosed from counters and
  gaps.
- Noise evidence: blank, truncated, malformed, and extra-field JSONL rows are
  expected in the corpus. Import keeps malformed rows as `driver.parse_error`;
  live display skips or defers bad partial rows without dropping valid rows.
- Attribution/self-noise evidence: mock and ABI self-check rows preserve
  `eventOrigin`, `producerCategory`, `subjectKind`, `processIdSource`,
  `selfNoise`, `collectorSelfNoise`, `selfProcess`, `selfNoiseReason`,
  `collectorNoisePolicy`, and
  `collectorSuppressedEvents` field names so no-device smoke can validate the
  readable ownership contract.
- Semantic companion evidence: mock/stress runs preserve
  `semanticScenario`, `semanticSelfCheck`, `semanticSelfCheckScenarios`,
  `semanticSelfCheckRows`, `semanticEvidenceKind`, `zhSemanticHint`,
  process-lineage fields (`parentProcessId`, `creatingProcessId`,
  `lineageConfidence`, `capturedCommandLine`), network candidate fields
  (`dnsCandidate`, `httpCandidate`, `tlsCandidate`, `lateralMovementCandidate`,
  `downloadExecuteCandidate`, `flowKey`), and parser-boundary fields
  (`protocolPayloadParsed`, `pcapCorrelationRequired`) without opening a driver.
- Mock/stress inputs: use `--self-test`, `--synthetic`, `--mock`,
  `--stress-count`, `--inject-jsonl-noise`, `--abi-self-check`,
  `--max-events`, `--max-read-batches`, `--duration 0`, `--poll-ms`, and
  `--driver-event-sample-stride`, and `--heartbeat` to exercise bounded drains,
  no-device ABI evidence, JSONL tolerance, sequence continuity, optional
  collector sampling, and heartbeat evidence.

backpressure 有意保持 non-blocking。kernel producers 不应等待 collector throughput。
如果 fixed ring overflow，最旧的未读 records 可能被覆盖，collector 必须通过
`TotalEventsDropped`、`EventsDropped`、`ProducerDroppedMask`、`NextSequence` 和
`sequence` gaps 暴露 loss。如果 ring 只是有压力但尚未满，`TotalEventsBackpressured` 和
`ProducerBackpressureMask` 标识 queue 超过阈值时观察到的 producer families。这些字段只说明
采集队列质量，不说明 kernel producer 阻断了文件、注册表、进程或网络操作。

## R0Collector 压力/就绪操作者门禁 / R0Collector stress/readiness operator gate

R0 readiness gate 有意拆分为 no-device checks 和 live-VM checks。默认 gate 必须对开发者
laptop 和 CI 保持安全：不调用 `CSignTool`，不 load/unload service，不修改 SCM state，
也不打开 `\\.\KSwordSandboxDriver`。live device、collector health 和 one-shot drain
检查必须在 driver 已经安装并在隔离 VM 中启动后，由操作者显式开关触发。

必需 no-device 门禁证据 / Required no-device gate evidence：

- `R0 capability/status IOCTL static contract`: source/docs-only row proving the
  negotiated IOCTL names, collector JSONL rows, and non-fatal optional-IOCTL
  strategy are still documented.
- `R0Collector event-quality static contract`: source/docs-only row proving the
  mock/stress/noise/backpressure contract is present before any driver load.
- `R0Collector ABI self-check`: optional runtime row produced with
  `--abi-self-check --out <CollectorAbiSelfCheckOutputPath>`.  Missing,
  unsigned, or policy-blocked collector execution is a `Warning` and a
  non-fatal readiness gap, not a hard stop for the rest of the static output.

operator gate 把以下 synthetic stress fields 视为命名 contract evidence。具体值可随场景变化，
但字段名必须在 docs、readiness script 和 smoke tests 中保持稳定：

- `StressJsonlExpectedDriverRows`: expected number of generated driver stress
  rows in the mock JSONL corpus.  The current smoke corpus expects 32
  `driver.file` rows. Semantic companion rows are separate and announced by
  `semanticSelfCheckRows=6`; they must not be added to this count.
- `semanticSelfCheckScenarios` / `semanticSelfCheckRows`: stable no-device
  semantic corpus evidence for `process-lineage|dns|http|tls|lateral-movement|download-execute`.
  These rows should keep concrete sequence values outside the stress range and
  include Chinese `zhSemanticHint` fields for operator interpretation.
- `StressJsonlSequenceStart` and `StressJsonlSequenceEnd`: first and last
  driver `sequence` values used to prove the corpus has a bounded expected
  sequence range.
- `StressJsonlSequenceGapCount`: expected gap count inside the synthetic stress
  corpus.  It should be `0` for the clean mock corpus; live VM drains can report
  non-zero gaps when queue-loss counters also prove overflow.
- `StressJsonlLossEvidence`: the loss fields that must be preserved in JSONL:
  `TotalEventsDropped`, `totalEventsDropped`, `EventsDropped`,
  `eventsDropped`, `ProducerDroppedMask`, `producerDroppedMask`,
  `NextSequence`, `nextSequence`, per-driver-row `sequence`, batch `head`,
  batch `tail`, and `loss`.
- `StressJsonlBackpressureEvidence`: the queue-pressure fields that prove
  non-blocking behavior: `QueueCapacity`, `queueCapacity`,
  `QueueHighWatermark`, `queueHighWatermark`, `TotalEventsBackpressured`,
  `totalEventsBackpressured`, `ProducerBackpressureMask`,
  `producerBackpressureMask`, `drainStoppedAtBatchLimit`, `requestedMaxEvents`,
  `readEventsMaxEvents`, `maxReadBatches`, `backpressureObserved`, and
  `sampling`.
- `ReadinessNoDevicePolicy`: default readiness emits only static/no-device
  evidence and must set `OpensDevice=false`, `LoadsDriver=false`, and
  `CallsCSignTool=false` for the ABI self-check row.
- `ReadinessNonFatalPolicy`: endpoint policy blocks, missing local collector
  binaries, and incomplete ABI self-check JSONL are warnings unless the operator
  requested a live device or live drain check.

显式请求 live VM drain 时，readiness output 应记录 JSONL output path、non-blank line count、
event types、parse-error count、driver row count、sequence first/last/gap evidence，以及所有
observed loss/backpressure fields。通过条件是 parseable JSONL 加上文档化的
health/capabilities/status/poll/read-events rows；stress-readiness report 不允许隐藏
malformed rows、loss counters 或 backpressure indicators。

## Guest Agent 集成 / Guest Agent integration

Guest Agent 把 R0Collector 当作可选 sidecar：

1. 未提供 `--driver-events` 时，不启动 R0 sidecar。
2. 同时提供 `--driver-events <jsonl>` 和 `--r0collector <exe>` 时，Agent 使用以下参数启动
   R0Collector：
   - `--device <driver-device>`
   - `--out <jsonl>` (or the equivalent `--output <jsonl>` alias)
   - `--duration <analysis seconds>`
   - 可选 `--mock`
3. 样本执行后，Agent 停止 sidecar，并把 JSONL rows 合并进 `events.json`。
4. Host import 随后合并 `events.json` 与 sibling JSONL files，运行 rules，并重新生成
   `report.json` / `report.html`。

## 仓库卫生 / Repository hygiene

不要提交生成的 native artifacts：

- `.exe`
- `.sys`
- `.pdb`
- `.obj`
- `.ilk`
- `bin/`
- `obj/`
- `x64/`

Runtime output 应保留在 `D:\Temp\KSwordSandbox\...` 下。
