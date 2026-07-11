# R0 network/WFP event producer

中文优先说明：本文描述 R0 network producer 的当前证据边界。当前实现是 WFP/ALE
inspect-only endpoint telemetry；它给出“某进程/endpoint/端口/方向被 ALE classify
观察到”的证据，不给出 DNS/HTTP/TLS payload verdict，也不等价于 PCAP。

`driver/KSword.Sandbox.Driver/src/Producers/Network/NetworkMonitor.c` owns the modular R0 network producer.  It registers inspect-only Windows Filtering Platform (WFP) Application Layer Enforcement (ALE) callouts and filters for:

- `ALE_AUTH_CONNECT_V4`
- `ALE_AUTH_RECV_ACCEPT_V4`
- `ALE_AUTH_CONNECT_V6`
- `ALE_AUTH_RECV_ACCEPT_V6`

The classify callback is telemetry-only.  It returns `FWP_ACTION_CONTINUE` when WFP grants action-write rights, and it does not block, absorb, redirect, or modify traffic.

Current scope is intentionally **ALE inspect-only**, not a complete WFP network
sensor.  The driver does not register packet/stream/datagram layers, does not
parse DNS/HTTP/TLS payloads, does not maintain WFP flow contexts, and does not
install protocol/address conditions.  Those items are explicit TODOs rather
than hidden implementation claims.

## 语义边界 / Semantic boundary

- **R0 network row 是 endpoint evidence，不是 packet evidence。**
  `driver.network` 行描述 ALE authorization/classify 处可见的 protocol、address、
  port、direction、PID 和 WFP layer/callout/filter correlation。它不包含 packet bytes、
  DNS query name、HTTP method/host/URI、TLS SNI/certificate 或完整流重组结果。
- **DNS/HTTP/TLS 字段是 candidate labels，不是 verdict。** `serviceHint`、
  `semanticCandidate`、`dnsCandidate`、`httpCandidate` 和 `tlsCandidate` 来自端口、
  transport protocol 和 endpoint 方向等轻量启发式。它们只帮助 report/rules 做关联和展示，
  不能证明应用实际完成了 DNS、HTTP 或 TLS 语义，也不能单独触发 malicious/benign 结论。
- **PCAP rows 承载 payload-derived facts。** `pcap.flow`、`pcap.dns`、
  `pcap.http` 和 `pcap.tls` 行来自 user/guest packet capture import，才是 DNS query、
  HTTP request metadata、TLS SNI 和 packet-level details 的来源。R0 `flowKey` /
  endpoint/PID/time fields 用于把 ALE metadata 与 PCAP evidence 关联；缺少 PCAP 不会否定
  R0 endpoint evidence，R0 candidate 也不会凭空生成 PCAP fact。
- **backpressure/loss 是采集队列状态。** network producer 遇到 queue pressure 时只通过
  `queueFailureCount`、`LastQueueFailureNtStatus`、common loss/backpressure counters 和
  producer masks 暴露采集丢失/压力；这些字段不表示 WFP 阻断、限速或修改了网络连接。

## Code layout and build guards

The network producer is still compiled as one MSBuild translation unit
(`NetworkMonitor.c`) so the driver project file does not need additional source
entries.  The implementation is split into network-local headers:

- `NetworkInternal.h`: compile-time feature guard, v1 payload size/offset
  asserts, draft payload guard, and `KSWORD_SANDBOX_NETWORK_WFP_RUNTIME`
  internal runtime state, including `Initialized`, `Uninitializing`, and
  `PayloadVersion`.
- `NetworkWfpBindings.h`: WFP/ALE layer contract asserts plus the descriptor
  table for the four supported ALE bindings.
- `NetworkMonitor.h`: public-in-driver initialization/uninitialization entry
  points used by `DriverEntry.c`.

Compile-time guardrails:

- `KSWORD_SANDBOX_ENABLE_NETWORK_WFP_ALE` must be exactly `0` or `1`.
- The enabled WFP path references the specific ALE layer and field identifiers
  at compile time, so an unsupported WDK header set fails the build instead of
  silently producing a fake no-op WFP producer.
- `KSWORD_SANDBOX_NETWORK_WFP_IMPLEMENTATION_ALE_INSPECT_ONLY` documents the
  current implementation level.
- `KSWORD_SANDBOX_NETWORK_WFP_TODO_FULL_PACKET_LAYERS`,
  `KSWORD_SANDBOX_NETWORK_WFP_TODO_FLOW_CONTEXTS`, and
  `KSWORD_SANDBOX_NETWORK_WFP_TODO_FILTER_CONDITIONS` intentionally remain set
  as compile-time TODO markers.
- `IOCTL_KSWORD_SANDBOX_GET_NETWORK_STATUS` exposes those remaining gaps as a
  public `TodoMask` instead of leaving the operator to infer them from comments.
  The current mask names packet/stream/datagram layers, flow contexts, protocol
  filter conditions, and in-driver DNS/HTTP/TLS payload parsing as not yet
  implemented.

The normal Debug/Release build compiles this WFP/ALE producer.  A lab build may
set `KSWORD_SANDBOX_ENABLE_NETWORK_WFP_ALE=0`; that is an explicit unsupported
network build, not a fake success path.  In that mode `GET_CAPABILITIES` omits
`KSWORD_SANDBOX_CAPABILITY_FLAG_NETWORK_WFP_ALE` and the network producer bit is
not included in `SupportedProducerMask`.

## Driver integration

`DriverEntry.c` calls `KswInitializeNetworkMonitor(deviceObject, deviceExtension)` after the file, process, and registry producers are initialized.  Failures are non-fatal: the control device remains available, and `GET_HEALTH.LastNtStatus` records the last producer status.

`KswDriverUnload` calls `KswUninitializeNetworkMonitor()` before the control device is deleted.  Cleanup disables classify emission first, uses the runtime `Uninitializing` guard for idempotent unload, deletes FWPM filters/callouts/sublayer, closes the dynamic FWPM engine session, unregisters FWPS callouts, clears the v1 `PayloadVersion`, and clears runtime pointers.

The driver project links `Fwpkclnt.lib` in both Debug and Release configurations.

## Event payload

Network events use `KswSandboxEventTypeNetwork` and `KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD` from `include/KSwordSandboxDriverIoctl.h`.  The emitted v1 payload version is `KSWORD_SANDBOX_NETWORK_EVENT_VERSION` (`0x00010000`) and `Size` remains 112 bytes; future growth must negotiate a new version/capability or use an explicit draft/successor structure.

Collector-facing fields include:

- `Protocol`: IANA protocol number, with constants for any, ICMP, TCP, UDP, and ICMPv6.
- `Direction`: normalized ALE direction.  Connect layers are outbound; recv-accept layers are inbound.
- `AddressFamily`: `4` for IPv4, `6` for IPv6, `0` when unknown.
- `LocalAddress[16]` and `RemoteAddress[16]`: IPv4 uses bytes `[0..3]`; IPv6 uses all 16 bytes.
- `LocalPort` and `RemotePort`: host-order port values.
- `ProcessId`: copied from WFP metadata when `PROCESS_ID_PRESENT` is set.
- `LayerId`, `CalloutId`, and `FilterId`: WFP diagnostic correlation values.
- `FlowHandle` and `TransportEndpointHandle`: optional WFP metadata handles when their flags are set.
- `Operation`: currently `KswSandboxNetworkOperationAleAuthorize` for emitted
  ALE authorization records.
- `Status`: currently `STATUS_SUCCESS` for a successfully built inspect-only
  network event.  Registration/queue failures are status diagnostics, not
  synthetic network traffic events.

Presence flags distinguish absent values from zero-valued metadata:

- `KSWORD_SANDBOX_NETWORK_EVENT_FLAG_LOCAL_ADDRESS_PRESENT`
- `KSWORD_SANDBOX_NETWORK_EVENT_FLAG_REMOTE_ADDRESS_PRESENT`
- `KSWORD_SANDBOX_NETWORK_EVENT_FLAG_PROCESS_ID_PRESENT`
- `KSWORD_SANDBOX_NETWORK_EVENT_FLAG_FLOW_HANDLE_PRESENT`
- `KSWORD_SANDBOX_NETWORK_EVENT_FLAG_ENDPOINT_HANDLE_PRESENT`
- `KSWORD_SANDBOX_NETWORK_EVENT_FLAG_INSPECTION_ONLY`

`AbiGuards.c` keeps `sizeof(KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD) <= KSWORD_SANDBOX_EVENT_MAX_PAYLOAD_SIZE`.

### Typed payload draft and degrade reasons

`KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD` remains the emitted v1 payload.  Its size
is still guarded at 112 bytes, with `Operation` and `Status` at the end of the
record.

The ABI header also contains a **draft-only** future layout,
`KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD_V2_DRAFT`, with:

- `V1`: the current `KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD`.
- `StatusDegradeReason`: one value from
  `KSWORD_SANDBOX_NETWORK_STATUS_DEGRADE_REASON`.
- `Reserved0`: alignment/reserved space.

This draft is not emitted by the current driver, has no advertised capability
bit, and must not be parsed as if it were implemented.  It exists so driver and
collector work can converge on a typed status-degradation field without
pretending the current event stream already carries it.

Current internal degradation reasons include:

- `CompileTimeDisabled`
- `FwpsCalloutRegister`
- `FwpmEngineOpen`
- `FwpmTransaction`
- `FwpmSublayer`
- `FwpmManagementCallout`
- `FwpmInspectionFilter`
- `ClassifyPayload`
- `QueuePush`

The WFP runtime stores the last internal degrade reason/status for future
diagnostics.  `GET_STATUS` still exposes coarse producer degradation through
`FailedProducerMask`, `ActiveProducerMask`, `EffectiveProducerMask`,
`LastNtStatus`, and `LastFailureNtStatus`; the dedicated
`IOCTL_KSWORD_SANDBOX_GET_NETWORK_STATUS` now exposes the network-specific
degrade reason/status without changing the v1 event payload.

### Read-only network status IOCTL

`IOCTL_KSWORD_SANDBOX_GET_NETWORK_STATUS` returns
`KSWORD_SANDBOX_NETWORK_STATUS_REPLY`.  It is a read-only diagnostics call: it
does not register callouts, start packet capture, mutate WFP, sign the driver, or
load the service by itself.  Operators can query it after a live driver load, and
static readiness checks can verify the ABI without requiring a signed driver.

Stable fields:

- `ImplementationLevel`: `KSWORD_SANDBOX_NETWORK_WFP_IMPLEMENTATION_ALE_INSPECT_ONLY`
  for the current enabled build, or `NONE` when the network producer is compiled
  out.
- `SupportedLayerMask`: the four ALE v1 layers:
  `ALE_CONNECT_V4`, `ALE_RECV_ACCEPT_V4`, `ALE_CONNECT_V6`, and
  `ALE_RECV_ACCEPT_V6`.
- `LastRegisteredCalloutMask`: the last FWPS callout registration progress,
  preserved even after non-fatal partial initialization cleanup.
- `LastAddedFilterMask`: the last FWPM inspect-filter creation progress.
- `ActiveLayerMask`: non-zero only while the WFP classify path is currently
  active.
- `TodoMask`: machine-readable scope gaps for packet/stream/datagram layers,
  flow contexts, protocol/address filter conditions, and DNS/HTTP/TLS payload
  parsing in the driver.
- `LastDegradeReason` / `LastDegradeNtStatus`: network-specific setup or
  enqueue failure cause.
- `RegisterNtStatus` / `EngineNtStatus`: coarse FWPS registration and FWPM
  engine-open status.
- `ClassifyCount` / `EventCount`: classify invocations observed and events
  successfully queued.
- `QueueFailureCount`, `ClassifyPayloadFailureCount`,
  `LastQueueFailureNtStatus`, `LastQueueFailureLayerId`, and
  `LastClassifyPayloadFailureLayerId`: counters and context for lossy queue or
  payload-build diagnostics.

The status reply reduces the old "internal diagnostics only" gap while keeping
the evidence contract honest: DNS query names, HTTP request metadata, TLS SNI,
and PCAP packet details still come from user/guest packet capture imports, not
from the R0 ALE authorization payload.

## Collector output

`guest/KSword.Sandbox.R0Collector` parses network payloads into string-valued JSON `data` fields, including:

- `protocolName`
- `transportProtocol`
- `directionName`
- `addressFamilyName`
- `localAddress` / `remoteAddress` when decodable
- `localAddressHex` / `remoteAddressHex`
- `localPort` / `remotePort`
- `localEndpoint` / `remoteEndpoint`
- `sourceEndpoint` / `destinationEndpoint`
- `flowKey`
- `servicePort`
- `serviceHint` and `semanticCandidate`
- `dnsCandidate`, `httpCandidate`, and `tlsCandidate`
- `processIdPresent`
- `flowHandleHex`
- `transportEndpointHandleHex`
- `filterIdHex`

`serviceHint` 是轻量 port/protocol semantic label（`dns`、`http`、`tls`、
`web` 或 `unknown`）。It does not parse packet payloads；DNS query names、
HTTP methods/hosts/URIs 和 TLS SNI 继续来自 imported PCAP events。The shared
`flowKey` / endpoint fields are intended to let reports group R0 WFP metadata
with `pcap.flow`, `pcap.dns`, `pcap.http`, and `pcap.tls` rows。报告层应把这些字段当作
evidence labels，而不是协议解析 verdict。

### Flow correlation field semantics

R0Collector emits endpoint fields deterministically from the decoded payload:

- `localEndpoint` is `localAddress:localPort` and `remoteEndpoint` is
  `remoteAddress:remotePort` when the corresponding address bytes decode.
- For outbound ALE connect events, `sourceEndpoint=localEndpoint` and
  `destinationEndpoint=remoteEndpoint`.
- For inbound ALE recv-accept events, `sourceEndpoint=remoteEndpoint` and
  `destinationEndpoint=localEndpoint`.
- `flowKey` is `protocolName|sourceEndpoint|destinationEndpoint`; for the
  controlled outbound TCP/443 smoke this is
  `tcp|192.0.2.10:51515|203.0.113.10:443`.
- IPv4 addresses use dotted decimal. IPv6 addresses are emitted in the
  collector's deterministic eight-hextet form before the port is appended. If an
  address is absent or cannot be decoded, the corresponding endpoint is empty
  and low-level `localAddressHex` / `remoteAddressHex` remain available.

These fields are correlation keys only. They do not imply packet payload parsing
and they do not replace richer DNS, HTTP, or TLS evidence imported from PCAP.
Synthetic collector rows and the valid JSONL noise row use the same field names
so no-device stress runs can validate report grouping before the WFP producer is
loaded.

中文：`flowKey`、`sourceEndpoint`、`destinationEndpoint` 和 top-level `path`
只帮助同一 flow 的多来源证据对齐。若 PCAP import 中没有对应 `pcap.dns` /
`pcap.http` / `pcap.tls` 行，report 不应从 R0 `serviceHint` 反推出 query、Host header
或 SNI；若 PCAP 有 payload-derived row，则应把它作为协议事实来源，并把 R0 row 作为
kernel-side endpoint attribution。

When the remote endpoint is decoded, top-level `SandboxEvent.path` is now a
URI-like string such as `tcp://203.0.113.10:443` instead of only
`\\.\KSwordSandboxDriver`, improving the live monitor and report path columns.

The opaque `payloadHex` fallback remains present on every driver event for low-level diagnosis.

## Build command

Use an output directory outside the repository when validating locally, for example:

```powershell
& 'D:\Software\VS\MSBuild\Current\Bin\MSBuild.exe' `
  driver\KSword.Sandbox.Driver\KSword.Sandbox.Driver.vcxproj `
  /p:Configuration=Debug `
  /p:Platform=x64 `
  /p:SignMode=Off `
  /p:OutDir=D:\Temp\KSwordSandbox\build\r0-driver\Debug\ `
  /p:IntDir=D:\Temp\KSwordSandbox\build\r0-driver\Debug\obj\ `
  /m `
  /v:minimal
```

Do not place `.sys`, `.pdb`, `.obj`, or other native build outputs under the repository tree.

## Operational notes

- The filters have no protocol conditions.  This maximizes early telemetry but can produce high event volume on active hosts.
- The TODO markers for flow contexts, packet/stream layers, and filter
  conditions are intentional.  Do not treat ALE inspect-only telemetry as full
  packet capture or complete WFP coverage.
- `serviceHint` and DNS/HTTP/TLS candidate booleans remain evidence labels for
  correlation.  They are not parser results, not block/allow decisions, and not
  malicious/benign verdicts.
- Runtime validation should be performed in a test-signed VM by loading the driver, generating outbound and inbound TCP/UDP activity, draining `READ_EVENTS`, and checking PID, address, port, layer, callout, and filter fields.
- `GET_STATUS` exposes `ActiveProducerMask`, `FailedProducerMask`,
  `EffectiveProducerMask`, `LastNtStatus`, and `LastFailureNtStatus`.
  `GET_NETWORK_STATUS` adds network-specific classify/event counters, partial
  callout/filter registration masks, and the last network degrade reason without
  changing `GET_STATUS` size or the v1 event payload.

## Runtime validation gate

Before generating traffic, verify the VM can safely load the test-signed driver:

```powershell
.\scripts\Test-R0Readiness.ps1 `
  -DriverSysPath C:\KSwordSandbox\driver\KSword.Sandbox.Driver.sys `
  -R0CollectorPath C:\KSwordSandbox\tools\KSword.Sandbox.R0Collector.exe
```

Default readiness is read-only. It checks file readability, Authenticode
signature metadata, Administrator status, `bcdedit` test-signing state, and
read-only service state. It does not load WFP callouts.

After signing is trusted and `testsigning` is enabled, explicitly install and
start the service in the isolated VM:

```powershell
.\scripts\Test-R0Readiness.ps1 `
  -DriverSysPath C:\KSwordSandbox\driver\KSword.Sandbox.Driver.sys `
  -AllowServiceMutation `
  -InstallService `
  -StartService `
  -CheckDeviceHealth
```

Generate controlled network activity only after the health check passes. Keep
the first smoke simple:

```powershell
Test-NetConnection 1.1.1.1 -Port 443
```

Drain queued events:

```powershell
.\scripts\Test-R0Readiness.ps1 `
  -R0CollectorPath C:\KSwordSandbox\tools\KSword.Sandbox.R0Collector.exe `
  -DrainWithCollector `
  -CollectorOutputPath C:\KSwordSandbox\out\r0-network-events.jsonl
```

Expected network evidence in the JSONL `data` object:

- `typedPayloadKind` is `network`.
- `protocolName` is usually `tcp` for the `Test-NetConnection` smoke.
- `serviceHint` is usually `tls` for port 443 traffic.
- `flowKey`, `sourceEndpoint`, and `destinationEndpoint` are present when
  addresses are decoded.
- `directionName` is `outbound` for connect authorization events.
- `addressFamilyName` is `ipv4` or `ipv6`.
- `remoteAddress`, `remotePort`, `layerIdHex`, `calloutIdHex`, and
  `filterIdHex` are present when WFP supplied those fields.

Unload and delete the service when finished:

```powershell
.\scripts\Test-R0Readiness.ps1 `
  -AllowServiceMutation `
  -StopService `
  -DeleteService
```
