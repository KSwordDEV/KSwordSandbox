# R0 network/WFP event producer

`driver/KSword.Sandbox.Driver/src/Producers/Network/NetworkMonitor.c` owns the modular R0 network producer.  It registers inspect-only Windows Filtering Platform (WFP) Application Layer Enforcement (ALE) callouts and filters for:

- `ALE_AUTH_CONNECT_V4`
- `ALE_AUTH_RECV_ACCEPT_V4`
- `ALE_AUTH_CONNECT_V6`
- `ALE_AUTH_RECV_ACCEPT_V6`

The classify callback is telemetry-only.  It returns `FWP_ACTION_CONTINUE` when WFP grants action-write rights, and it does not block, absorb, redirect, or modify traffic.

## Driver integration

`DriverEntry.c` calls `KswInitializeNetworkMonitor(deviceObject, deviceExtension)` after the file, process, and registry producers are initialized.  Failures are non-fatal: the control device remains available, and `GET_HEALTH.LastNtStatus` records the last producer status.

`KswDriverUnload` calls `KswUninitializeNetworkMonitor()` before the control device is deleted.  Cleanup disables classify emission first, deletes FWPM filters/callouts/sublayer, closes the dynamic FWPM engine session, unregisters FWPS callouts, and clears runtime pointers.

The driver project links `Fwpkclnt.lib` in both Debug and Release configurations.

## Event payload

Network events use `KswSandboxEventTypeNetwork` and `KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD` from `include/KSwordSandboxDriverIoctl.h`.

Collector-facing fields include:

- `Protocol`: IANA protocol number, with constants for any, ICMP, TCP, UDP, and ICMPv6.
- `Direction`: normalized ALE direction.  Connect layers are outbound; recv-accept layers are inbound.
- `AddressFamily`: `4` for IPv4, `6` for IPv6, `0` when unknown.
- `LocalAddress[16]` and `RemoteAddress[16]`: IPv4 uses bytes `[0..3]`; IPv6 uses all 16 bytes.
- `LocalPort` and `RemotePort`: host-order port values.
- `ProcessId`: copied from WFP metadata when `PROCESS_ID_PRESENT` is set.
- `LayerId`, `CalloutId`, and `FilterId`: WFP diagnostic correlation values.
- `FlowHandle` and `TransportEndpointHandle`: optional WFP metadata handles when their flags are set.

Presence flags distinguish absent values from zero-valued metadata:

- `KSWORD_SANDBOX_NETWORK_EVENT_FLAG_LOCAL_ADDRESS_PRESENT`
- `KSWORD_SANDBOX_NETWORK_EVENT_FLAG_REMOTE_ADDRESS_PRESENT`
- `KSWORD_SANDBOX_NETWORK_EVENT_FLAG_PROCESS_ID_PRESENT`
- `KSWORD_SANDBOX_NETWORK_EVENT_FLAG_FLOW_HANDLE_PRESENT`
- `KSWORD_SANDBOX_NETWORK_EVENT_FLAG_ENDPOINT_HANDLE_PRESENT`

`AbiGuards.c` keeps `sizeof(KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD) <= KSWORD_SANDBOX_EVENT_MAX_PAYLOAD_SIZE`.

## Collector output

`guest/KSword.Sandbox.R0Collector` parses network payloads into string-valued JSON `data` fields, including:

- `protocolName`
- `directionName`
- `addressFamilyName`
- `localAddress` / `remoteAddress` when decodable
- `localAddressHex` / `remoteAddressHex`
- `localPort` / `remotePort`
- `processIdPresent`
- `flowHandleHex`
- `transportEndpointHandleHex`
- `filterIdHex`

The opaque `payloadHex` fallback remains present on every driver event for low-level diagnosis.

## Build command

Use an output directory outside the repository when validating locally, for example:

```powershell
& 'D:\Software\VS\MSBuild\Current\Bin\MSBuild.exe' `
  driver\KSword.Sandbox.Driver\KSword.Sandbox.Driver.vcxproj `
  /p:Configuration=Debug `
  /p:Platform=x64 `
  /p:OutDir=D:\Temp\KSwordSandbox\build\r0-driver\Debug\ `
  /p:IntDir=D:\Temp\KSwordSandbox\build\r0-driver\Debug\obj\ `
  /m `
  /v:minimal
```

Do not place `.sys`, `.pdb`, `.obj`, or other native build outputs under the repository tree.

## Operational notes

- The filters have no protocol conditions.  This maximizes early telemetry but can produce high event volume on active hosts.
- Runtime validation should be performed in a test-signed VM by loading the driver, generating outbound and inbound TCP/UDP activity, draining `READ_EVENTS`, and checking PID, address, port, layer, callout, and filter fields.
- The health IOCTL still exposes a single `LastNtStatus`; it does not yet expose separate per-producer status or WFP classify/event counters.
