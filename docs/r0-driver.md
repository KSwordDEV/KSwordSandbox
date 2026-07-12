# R0 Driver producer deepening

中文优先说明：本文记录 R0 driver producer 拆分、公共 metadata、queue/backpressure
语义，以及 collector 读取这些字段时应采用的证据解释方式。机器字段、ABI 结构名和
JSON key 继续保持英文稳定值；中文只解释语义，不重新命名协议。

Scope: `driver/KSword.Sandbox.Driver/**` only. This note records the R0 producer split and the event metadata contract expected by the collector path.

## 判读原则 / Interpretation rules

- **ABI 是兼容性契约，不是行为判定。** `Version`、`Size`、capability flags、
  producer masks、payload sizes 和 reserved-space 扩展只说明 user/kernel 双方如何安全
  解析字节流。它们不能单独证明样本行为，也不能当作 malicious/benign verdict。
- **producer/status 字段是运行状态证据。** `ActiveProducerMask` 表示 producer 当前可用，
  `FailedProducerMask` 表示初始化或运行诊断失败，`ProducerDroppedMask` /
  `ProducerBackpressureMask` 表示哪个 producer family 观察到 loss/pressure。这些都是
  evidence labels，不是“样本触发了恶意动作”的结论。
- **noise/self-noise 是归因标签，不是信任边界。** `SELF_NOISE` 相关 flag 或 metadata
  只表示事件匹配 KSword collector/agent/output path 等基础设施条件。默认策略可以抑制这些
  行以降低噪声，但不能把“非 self-noise”理解为样本恶意，也不能把“self-noise”理解为安全放行。
- **backpressure 是非阻塞队列压力证据。** kernel producer 不等待 user-mode collector。
  ring 达到阈值或溢出时，driver 通过 counters、masks、`LostEvents`、
  `BackpressureEvents` 和 sequence gaps 暴露压力/丢失；它不通过这些字段表达阻断、
  拦截或流量/文件操作失败。
- **协议语义边界保持清晰。** R0 network producer 只提供 WFP/ALE endpoint metadata；
  DNS/HTTP/TLS payload facts 和 PCAP packet details 的权威语义见
  `docs/r0-network.md` 与 `docs/r0-jsonl-schema.md`。

## Producer layout

The driver now keeps each public producer family in an explicit source/header pair:

- Process: `src/Producers/Process/ProcessMonitor.c` + `ProcessMonitor.h`
- Image: `src/Producers/Image/ImageMonitor.c` + `ImageMonitor.h`
- File: `src/Producers/File/FileFilter.c` + `FileFilter.h`
- Registry: `src/Producers/Registry/RegistryMonitor.c` + `RegistryMonitor.h`
- Network: `src/Producers/Network/NetworkMonitor.c` + `NetworkMonitor.h`

Process create/exit and image-load callbacks are intentionally separate producers. `ActiveProducerMask`/`FailedProducerMask` can therefore report a partial process-vs-image bring-up instead of treating both callbacks as one unit.

## Common event metadata

`KSWORD_SANDBOX_EVENT_HEADER` keeps the original v1.0 prefix through `Reserved` and appends common metadata for all producer families:

- target `ProcessId`, `ParentProcessId`, and current callback `ThreadId`
- `Operation` and `Status`
- `TimestampQpc`, `TimestampSystemTime`, and monotonic `Sequence`
- cumulative `LostEvents` and `BackpressureEvents`
- `ProducerId` and `ProducerMetadataFlags`

Typed payloads still carry source-specific details such as process image path, image path, file path, registry key/value, and network tuple. Header flags mark which common fields are meaningful (`*_PRESENT`) so collectors can tolerate absent status/path data.

自噪声语义：`KSWORD_SANDBOX_EVENT_FLAG_SELF_NOISE` 和
`KSWORD_SANDBOX_EVENT_METADATA_FLAG_SELF_NOISE` 在 common metadata contract 中预留。
当前 file self-noise filtering 可能在 enqueue 前抑制已知 KSword infrastructure paths；
如果未来 producer 选择 emit 这些记录，marker 已经可用，无需再次扩展 header。该 marker
仍然只是采集归因 evidence label，不是安全 verdict 或访问控制结果。

## Event queue stress and backpressure status

R0 queue 仍是固定大小、非阻塞 ring。Producers never wait for user mode；当 ring
已满时，enqueue 会覆盖最旧的未读 record，并递增 cumulative lost counter。
Backpressure 是 advisory evidence label：一旦 depth 达到
`KSWORD_SANDBOX_EVENT_RING_BACKPRESSURE_THRESHOLD`（当前为
`KSWORD_SANDBOX_EVENT_RING_CAPACITY` 的 75%），enqueue 会递增
`TotalEventsBackpressured`，并在 `ProducerBackpressureMask` 中标记 producer
family。该字段只说明“采集队列有压力”，不说明 driver 阻止了样本动作，也不说明网络/文件 I/O
被 backpressure 改写。

Collectors can query stress/backpressure state through `IOCTL_KSWORD_SANDBOX_GET_STATUS` without changing the v1.0 fixed reply size:

- `TotalEventsDropped` / `TotalEventsLost`: cumulative lost count for overwritten or internally discarded unread records.
- `QueueHighWatermark`: maximum ring depth observed since driver initialization.
- `TotalEventsBackpressured`: number of enqueue operations observed at or above the backpressure threshold.
- `ProducerDroppedMask`, `ProducerSuppressedMask`, `ProducerBackpressureMask`: producer-family evidence for loss, enable-mask suppression, and backpressure.
- `LastFailureNtStatus` / `LastEnqueueFailureNtStatus`: sticky status for the last failed enqueue-related path, including validation failures such as `STATUS_BUFFER_TOO_SMALL` or producer-mask suppression (`STATUS_CANCELLED`). The two names alias the same v1.0 status slot to preserve ABI stability.

Each emitted `KSWORD_SANDBOX_EVENT_HEADER` also snapshots `LostEvents` and `BackpressureEvents` at enqueue time and sets `KSWORD_SANDBOX_EVENT_FLAG_LOST_COUNT_PRESENT` / `KSWORD_SANDBOX_EVENT_FLAG_BACKPRESSURE_COUNT_PRESENT` when those counters are non-zero.

`Sequence` is assigned only after producer enable-mask validation succeeds and immediately before inserting the event into the ring. It is monotonically increasing for successfully enqueued records and is not reused after overflow. Gaps between drained records therefore mean records were lost, skipped by a `StartingSequence` read, or discarded by ring corruption guards; collectors should combine sequence gaps with `LostEvents`, `TotalEventsDropped`/`TotalEventsLost`, and `NextSequence` when reporting loss.

## Enable mask, health, and capabilities

`KSWORD_SANDBOX_COMPILED_PRODUCER_MASK` is derived from per-producer build switches:

- `KSWORD_SANDBOX_ENABLE_PROCESS_CREATE`
- `KSWORD_SANDBOX_ENABLE_IMAGE_LOAD`
- `KSWORD_SANDBOX_ENABLE_FILE_MINIFILTER`
- `KSWORD_SANDBOX_ENABLE_REGISTRY_CALLBACK`
- `KSWORD_SANDBOX_ENABLE_NETWORK_WFP_ALE`

`GET_CAPABILITIES` advertises only compiled producer capability bits plus common metadata capability bits. Runtime registration failures remain visible through `GET_HEALTH`/`GET_STATUS` masks and NTSTATUS fields.

R0/ETW coverage is explicit in collector JSONL. `processCreateExit`,
`imageLoad`, `fileActivity`, `registryActivity`, and WFP/ALE
`networkActivity` are R0-direct only when the corresponding capability and
producer mask are advertised/active. `handleAccess` and
`tokenPrivilegeAdjustment` are current R0 gaps; they remain ETW/audit fallback
lanes unless future draft capability bits are advertised with versioned payloads.

## Verification

Build without signing or CSignTool:

```powershell
& 'D:\Software\VS\MSBuild\Current\Bin\MSBuild.exe' `
  'D:\Projects\KswordSandbox\driver\KSword.Sandbox.Driver\KSword.Sandbox.Driver.vcxproj' `
  /p:Configuration=Debug /p:Platform=x64 /p:SignMode=Off /m:1 /v:minimal
```
