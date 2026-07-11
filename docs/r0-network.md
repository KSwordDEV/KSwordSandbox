# R0 network/WFP event producer

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
diagnostics, but today `GET_STATUS` only exposes coarse degradation through
`FailedProducerMask`, `ActiveProducerMask`, `EffectiveProducerMask`,
`LastNtStatus`, and `LastFailureNtStatus`.

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

`serviceHint` is a lightweight port/protocol semantic label (`dns`, `http`,
`tls`, `web`, or `unknown`). It does not parse packet payloads; DNS query names,
HTTP methods/hosts/URIs, and TLS SNI continue to come from imported PCAP events.
The shared `flowKey` / endpoint fields are intended to let reports group R0
WFP metadata with `pcap.flow`, `pcap.dns`, `pcap.http`, and `pcap.tls` rows.

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
- Runtime validation should be performed in a test-signed VM by loading the driver, generating outbound and inbound TCP/UDP activity, draining `READ_EVENTS`, and checking PID, address, port, layer, callout, and filter fields.
- `GET_STATUS` exposes `ActiveProducerMask`, `FailedProducerMask`,
  `EffectiveProducerMask`, `LastNtStatus`, and `LastFailureNtStatus`.  It does
  not yet expose WFP classify/event counters, per-callout registration statuses,
  or the draft network degrade reason; those remain internal runtime
  diagnostics.

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
