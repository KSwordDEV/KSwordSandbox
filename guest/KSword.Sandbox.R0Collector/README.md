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
  --output C:\Sandbox\driver-events.jsonl `
  --duration 10 `
  --poll-interval-ms 500
```

Options:

- `--device`, `-d`: Win32 device path. Default: `\\.\KSwordSandboxDriver`.
- `--output`, `-o`: JSONL output path, or `-` for stdout. Default: `-`.
- `--duration`, `-t`: Poll duration in seconds. `0` performs one health/poll/read-events pass.
- `--poll-ms`, `--poll-interval`, `--poll-interval-ms`, `-p`: poll interval in milliseconds.
- `--mock`: emit synthetic process/image/file/registry driver-category rows
  without opening a device.
- `--help`, `-h`: show CLI help.

## Current behavior

- `--mock` emits:
  - `r0collector.started`
  - `r0collector.mockDriverEvent`
  - `driver.process`
  - `image.load`
  - `driver.file`
  - `driver.registry`
  - `r0collector.stopped`
- If the device cannot be opened, the collector emits
  `r0collector.deviceUnavailable` and exits with code `66`.
- If the device opens, the collector emits:
  - `r0collector.deviceOpened`
  - `r0collector.driverHealth`
  - `r0collector.driverPoll`
  - stable driver rows from `IOCTL_KSWORD_SANDBOX_READ_EVENTS`
    (`driver.process`, `image.load`, `driver.file`, `driver.registry`,
    `driver.network`, `driver.event.reserved`, or fallback `driver.event`)
  - `r0collector.driverReadEvents`
  - `r0collector.stopped`

## JSONL contract

Every line is a `SandboxEvent` object with stable top-level fields:

```json
{"eventType":"r0collector.deviceUnavailable","source":"r0collector","timestamp":"2026-07-10T00:00:00.000Z","processId":1234,"path":"\\\\.\\KSwordSandboxDriver","commandLine":"KSword.Sandbox.R0Collector.exe --output -","data":{"message":"...","win32Error":"2","hint":"..."}}
```

The `data` object is string-valued because the shared host model currently uses
`Dictionary<string,string>`.

## Exit codes

- `0`: success.
- `64`: invalid command-line arguments.
- `65`: output JSONL file could not be opened.
- `66`: driver device could not be opened.
- `70`: runtime write failure or IOCTL/protocol failure.
