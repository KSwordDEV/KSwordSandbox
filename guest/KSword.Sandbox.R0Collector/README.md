# KSword.Sandbox.R0Collector

Windows user-mode sidecar for draining events from the KSword sandbox kernel
driver and writing `SandboxEvent` JSON Lines.

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
- `--output`, `--out`, `-o`: JSONL output path, or `-` for stdout. Default: `-`.
- `--duration`, `-t`: Poll duration in seconds. `0` performs one health/poll/read-events pass.
- `--poll-ms`, `--poll-interval`, `--poll-interval-ms`, `-p`: poll interval in milliseconds.
- `--diagnose`, `--readiness`, `--readiness-check`: emit live non-mutating
  readiness diagnostics for service state, device open, ABI negotiation, and a
  bounded `READ_EVENTS` probe.
- `--service-name <name>`: driver service name used by `--diagnose`. Default:
  `KSwordSandboxDriver`.
- `--read-timeout-ms <ms>`, `--diagnose-read-timeout-ms <ms>`: timeout for the
  `--diagnose` `READ_EVENTS` probe. Default: `2000`.
- `--enable-mask <mask>`: pass a decimal or `0x` 32-bit mask through
  `IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK` before draining events and
  record requested/effective producer masks in lifecycle JSONL. `READ_EVENTS`
  reserved request flags stay zero.
- `--health`: open the live device, emit `r0collector.driverHealth`, and exit
  without polling or draining queued events.
- `--heartbeat`: emit `r0collector.heartbeat` progress rows.
- `--suppress-self-noise`: suppress known collector/KSword infrastructure
  driver rows before writing JSONL. This is the default.
- `--emit-self-noise`: keep those rows for diagnosis and mark them with
  `data.selfNoise=true` plus `data.selfNoiseReason`.
- `--mock`: emit synthetic process/image/file/registry/network driver-category rows
  without opening a device.
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
- `--diagnose` additionally emits `r0collector.readinessDiagnostic` rows and a
  final `r0collector.readinessSummary`. These rows distinguish
  `missing_service`, `service_not_running`, `open_device_not_found`,
  `open_device_denied`, `abi_mismatch`, `read_timeout`, and
  `driver_no_events` so readiness failures do not collapse into an
  informational message.
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
    rows hidden by the collector self-noise policy)
  - unless `--health` was requested, final `r0collector.driverStatus`
  - optional `r0collector.heartbeat`
  - `r0collector.stopped`

## JSONL contract

Every line is a `SandboxEvent` object with stable top-level fields:

```json
{"timestamp":"2026-07-10T00:00:00.000Z","eventType":"r0collector.deviceUnavailable","source":"r0collector","processId":1234,"processName":"KSword.Sandbox.R0Collector.exe","path":"\\\\.\\KSwordSandboxDriver","commandLine":"KSword.Sandbox.R0Collector.exe --out -","data":{"severity":"error","readinessState":"blocked","diagnosticStage":"openDevice","diagnosticCode":"open_device_not_found","message":"...","win32Error":"2","hint":"..."}}
```

The `data` object is string-valued because the shared host model currently uses
`Dictionary<string,string>`.

Driver-origin rows include additive attribution fields:

- `eventOrigin`, `producerCategory`, `subjectKind`, `processIdSource`
- `actorRole`, `subjectRole`
- `selfNoise`, `selfNoiseReason`, `selfNoiseAction`, `collectorNoisePolicy`

Normal live rows use `selfNoise=false`. With the default
`--suppress-self-noise` policy, rows for the collector PID, the exact collector
output JSONL, and known `\KSwordSandbox\agent\`, `\KSwordSandbox\r0collector\`,
`\KSwordSandbox\driver\`, and `\KSwordSandbox\out\` paths are not emitted; the
batch summary records the count in `collectorSuppressedEvents`. Use
`--emit-self-noise` when debugging the suppression decision itself.

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

## Exit codes

- `0`: success.
- `64`: invalid command-line arguments.
- `65`: output JSONL file could not be opened.
- `66`: driver device could not be opened.
- `70`: runtime write failure or IOCTL/protocol failure.
