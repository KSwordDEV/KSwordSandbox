# R0Collector IOCTL pipeline

`guest/KSword.Sandbox.R0Collector` is the Windows user-mode sidecar that runs
inside the guest VM and drains events from `KSword.Sandbox.Driver`.

Current status:

- Opens the driver Win32 path `\\.\KSwordSandboxDriver` with `CreateFileW`.
- Issues `IOCTL_KSWORD_SANDBOX_GET_HEALTH` once after opening the device.
- Issues `IOCTL_KSWORD_SANDBOX_POLL` and `IOCTL_KSWORD_SANDBOX_READ_EVENTS`
  in a one-shot or timed polling loop.
- Converts driver event records into `SandboxEvent` JSON Lines for the Guest
  Agent and Host import path.
- Keeps `--mock` mode for CI/local plumbing when the unsigned/test-signed driver
  is not installed.

## Driver IOCTL contract

The public ABI is owned by:

```text
driver/KSword.Sandbox.Driver/include/KSwordSandboxDriverIoctl.h
```

Initial device names:

- NT device: `\Device\KSwordSandboxDriver`
- DOS link: `\DosDevices\KSwordSandboxDriver`
- Win32 path: `\\.\KSwordSandboxDriver`

Initial IOCTLs:

- `IOCTL_KSWORD_SANDBOX_GET_HEALTH`
  - Input: none.
  - Output: `KSWORD_SANDBOX_HEALTH_REPLY`.
  - Purpose: driver/queue health and ABI sanity check.
- `IOCTL_KSWORD_SANDBOX_POLL`
  - Input: none.
  - Output: `KSWORD_SANDBOX_POLL_REPLY`.
  - Purpose: cheap queue snapshot before drain.
- `IOCTL_KSWORD_SANDBOX_READ_EVENTS`
  - Input: optional `KSWORD_SANDBOX_READ_EVENTS_REQUEST`.
  - Output: `KSWORD_SANDBOX_READ_EVENTS_REPLY` followed by zero or more
    `KSWORD_SANDBOX_EVENT_HEADER + payload` records.
  - Purpose: consume queued R0 events.

`IOCTL_KSWORD_SANDBOX_DRAIN_EVENTS` may exist as a compatibility alias in local
driver experiments, but R0Collector issues the public `READ_EVENTS` name.

## Current driver event path

The driver owns a fixed non-paged ring buffer. On load it queues a
`KswSandboxEventTypeDriverLoad` heartbeat event with a compact
`KSWORD_SANDBOX_DRIVER_LOAD_PAYLOAD` payload. `READ_EVENTS` consumes complete
records from the ring and reports drop/sequence counters.

Reserved event categories already exist in the ABI for the next increments:

1. `KswSandboxEventTypeFile`
2. `KswSandboxEventTypeProcess`
3. `KswSandboxEventTypeImage`
4. `KswSandboxEventTypeRegistry`
5. `KswSandboxEventTypeNetwork`

## CLI contract

```powershell
KSword.Sandbox.R0Collector.exe `
  --device \\.\KSwordSandboxDriver `
  --output C:\Sandbox\driver-events.jsonl `
  --duration 10 `
  --poll-interval-ms 500
```

Supported options:

- `--device`, `-d`: Win32 symbolic-link path for the driver device.
- `--output`, `-o`: JSON Lines output path, or `-` for stdout.
- `--duration`, `-t`: Polling duration in seconds. `0` means one-shot open,
  health, poll, and read-events.
- `--poll-ms`, `--poll-interval`, `--poll-interval-ms`, `-p`: poll interval in
  milliseconds.
- `--mock`: emit synthetic process/file/registry-style rows and do not open the
  driver device.

Device-unavailable behavior is explicit: the collector writes
`r0collector.deviceUnavailable` to the selected JSONL sink and exits with code
`66`.

## JSON Lines format

Every output line is a single `SandboxEvent`-compatible JSON object:

```json
{"eventType":"driver.load","source":"driver","timestamp":"2026-07-10T00:00:00.000Z","processId":1234,"path":"\\\\.\\KSwordSandboxDriver","commandLine":"KSword.Sandbox.R0Collector.exe --output C:\\Sandbox\\driver-events.jsonl","data":{"sequence":"1","driverEventTypeName":"driverLoad","buildTag":"ksword-r0-driver-load"}}
```

Top-level field rules:

- `eventType`: collector lifecycle/error type or normalized driver event type.
- `source`: `r0collector` for lifecycle rows, `driver` for drained R0 rows.
- `timestamp`: collector UTC timestamp for the JSONL row.
- `processId`: driver-supplied process ID when present; otherwise collector PID.
- `path`: device path for lifecycle rows; future file/registry rows should use
  subject paths when payloads carry them.
- `commandLine`: collector invocation until process payloads add richer command
  lines.
- `data`: string-valued metadata compatible with the current host model.

## Guest Agent integration

The Guest Agent treats R0Collector as an optional sidecar:

1. When `--driver-events` is not supplied, no R0 sidecar is started.
2. When `--driver-events <jsonl>` and `--r0collector <exe>` are supplied, the
   agent starts R0Collector with:
   - `--device <driver-device>`
   - `--output <jsonl>`
   - `--duration <analysis seconds>`
   - optional `--mock`
3. After sample execution, the agent stops the sidecar and merges JSONL rows into
   `events.json`.
4. Host import then merges `events.json` plus sibling JSONL files, runs rules,
   and regenerates `report.json` / `report.html`.

## Repository hygiene

Do not commit generated native artifacts:

- `.exe`
- `.sys`
- `.pdb`
- `.obj`
- `.ilk`
- `bin/`
- `obj/`
- `x64/`

Runtime output should stay under `D:\Temp\KSwordSandbox\...`.
