# Driver signing and R0 event export

## Scope

The sandbox repository does not store driver binaries, certificates, private
keys, PDB files, or WDK build outputs. It only documents the integration point
for the KSword driver family.

`scripts/Test-R0Readiness.ps1` includes a `Driver .sys git hygiene` check that
fails if any `.sys` file is tracked, staged, modified, or otherwise visible to
git as a commit candidate. Keep the signed driver in VM-local scratch/payload
storage, or in an ignored local path only for the duration of a disposable VM
test. Never stage it.

## Expected event bridge

The guest agent can ingest driver events from JSON Lines:

```json
{"eventType":"registry.set","source":"driver","processId":1234,"path":"HKCU\\Software\\Example","data":{"value":"Run"}}
{"eventType":"file.created","source":"driver","processId":1234,"path":"C:\\Users\\SandboxUser\\AppData\\Local\\drop.bin"}
```

Each line should deserialize to the shared `SandboxEvent` shape. Invalid lines
are preserved as `driver.parse_error` events so the report exposes integration
problems instead of silently losing data.

## Signing notes

- Use a test-signed driver only in an isolated test VM.
- Keep test certificates and private keys outside this repository.
- Record the driver service name in local config through `Driver.ServiceName`.
- Record the guest output path through `Driver.EventJsonLinesPath`.

## Test-signing runbook for VM validation

The repository does not generate or store certificates. Build output should be
placed under a scratch or payload directory outside git, then signed there.

Example VM-only workflow:

```powershell
$driver = 'C:\KSwordSandbox\driver\KSword.Sandbox.Driver.sys'
$cert = New-SelfSignedCertificate `
  -Type CodeSigningCert `
  -Subject 'CN=KSword Sandbox Test Driver' `
  -CertStoreLocation Cert:\LocalMachine\My `
  -KeyExportPolicy NonExportable

Export-Certificate `
  -Cert $cert `
  -FilePath C:\KSwordSandbox\certs\KSwordSandboxTestDriver.cer

Import-Certificate `
  -FilePath C:\KSwordSandbox\certs\KSwordSandboxTestDriver.cer `
  -CertStoreLocation Cert:\LocalMachine\TrustedRoot

Import-Certificate `
  -FilePath C:\KSwordSandbox\certs\KSwordSandboxTestDriver.cer `
  -CertStoreLocation Cert:\LocalMachine\TrustedPublisher

Set-AuthenticodeSignature `
  -FilePath $driver `
  -Certificate $cert `
  -HashAlgorithm SHA256
```

Enable Windows test-signing inside the disposable VM, then reboot the VM:

```powershell
bcdedit /set testsigning on
Restart-Computer
```

After reboot, run the non-mutating readiness pass from an elevated shell. This
checks repository source files, `.sys` git hygiene, driver readability,
Authenticode status, Administrator status, test-signing state, and read-only SCM
state. It does not install/start the service, open `\\.\KSwordSandboxDriver`, or
run R0Collector:

```powershell
.\scripts\Test-R0Readiness.ps1 `
  -DriverSysPath C:\KSwordSandbox\driver\KSword.Sandbox.Driver.sys `
  -R0CollectorPath C:\KSwordSandbox\tools\KSword.Sandbox.R0Collector.exe
```

Required first-pass rows before loading:

- `Driver .sys git hygiene`: `Passed`; no driver `.sys` is in the commit path.
- `Driver binary readable`: `Passed`.
- `Driver Authenticode signature`: `Passed` for a trusted test certificate, or
  investigate any non-`Valid` status before loading.
- `Administrator privilege`: `Passed`.
- `Windows test-signing boot option`: `Passed` unless
  `-SkipTestSigningRequirement` is deliberately used for a production-signed
  validation path.

## Kernel service install/load/unload

Use the readiness script for service actions so each mutating step is explicit.
The script requires `-AllowServiceMutation` in addition to the requested
operation.

Install and start in an isolated test VM:

```powershell
.\scripts\Test-R0Readiness.ps1 `
  -DriverSysPath C:\KSwordSandbox\driver\KSword.Sandbox.Driver.sys `
  -R0CollectorPath C:\KSwordSandbox\tools\KSword.Sandbox.R0Collector.exe `
  -ServiceName KSwordSandboxDriver `
  -AllowServiceMutation `
  -InstallService `
  -StartService
```

Equivalent raw SCM commands, if troubleshooting outside the script:

```powershell
sc.exe create KSwordSandboxDriver type= kernel start= demand binPath= C:\KSwordSandbox\driver\KSword.Sandbox.Driver.sys
sc.exe start KSwordSandboxDriver
```

Unload and remove after validation:

```powershell
.\scripts\Test-R0Readiness.ps1 `
  -ServiceName KSwordSandboxDriver `
  -AllowServiceMutation `
  -StopService `
  -DeleteService
```

Equivalent raw SCM commands:

```powershell
sc.exe stop KSwordSandboxDriver
sc.exe delete KSwordSandboxDriver
```

The service name should match `Driver.ServiceName` in local configuration. The
Win32 device path remains `\\.\KSwordSandboxDriver`.

## Device open, collector health, and event drain checks

After the service is started, the readiness script can issue the public
`IOCTL_KSWORD_SANDBOX_GET_HEALTH` directly. This proves that
`\\.\KSwordSandboxDriver` can be opened and that the loaded driver answers the
public health IOCTL:

```powershell
.\scripts\Test-R0Readiness.ps1 `
  -CheckDeviceHealth `
  -DevicePath \\.\KSwordSandboxDriver
```

Then verify the collector health-only path without consuming queued telemetry.
This runs `R0Collector --health --out <jsonl>` and validates that the JSONL file
contains `r0collector.deviceOpened` and `r0collector.driverHealth` rows:

```powershell
New-Item -ItemType Directory -Force C:\KSwordSandbox\out | Out-Null

.\scripts\Test-R0Readiness.ps1 `
  -R0CollectorPath C:\KSwordSandbox\tools\KSword.Sandbox.R0Collector.exe `
  -DevicePath \\.\KSwordSandboxDriver `
  -CheckCollectorHealth `
  -CollectorHealthOutputPath C:\KSwordSandbox\out\r0collector-health.jsonl
```

To verify the full collector path, run a one-shot R0Collector drain. This writes
JSON Lines only to the explicit output path and uses the collector `--out`
option:

```powershell
.\scripts\Test-R0Readiness.ps1 `
  -R0CollectorPath C:\KSwordSandbox\tools\KSword.Sandbox.R0Collector.exe `
  -DevicePath \\.\KSwordSandboxDriver `
  -DrainWithCollector `
  -CollectorOutputPath C:\KSwordSandbox\out\driver-events.jsonl
```

Expected first-pass evidence:

- `Device IOCTL health` returns `Passed`.
- `R0Collector health` returns exit code `0` and writes a JSONL file with
  `r0collector.started`, `r0collector.deviceOpened`,
  `r0collector.driverHealth`, and `r0collector.stopped`.
- `R0Collector drain` returns exit code `0` and writes a JSONL file with
  `r0collector.driverHealth`, `r0collector.driverPoll`,
  `r0collector.driverReadEvents`, and any queued driver rows.
- The first drain normally contains at least the header-only
  `driver.event.reserved` / driver-start heartbeat when the ring has not already
  been consumed.

## Full VM validation sequence

Run this sequence only inside an isolated VM checkpoint/snapshot:

1. Copy the signed driver and R0Collector into VM-local paths. Do not stage the
   `.sys` file in git.
2. Enable test-signing with `bcdedit /set testsigning on`, reboot, and confirm
   the non-mutating readiness pass is clean.
3. Install and start the kernel service with `-AllowServiceMutation
   -InstallService -StartService`.
4. Create the guest output directory, for example `C:\KSwordSandbox\out`.
5. Run `-CheckDeviceHealth` to prove `\\.\KSwordSandboxDriver` opens.
6. Run `-CheckCollectorHealth` to prove `R0Collector --health --out` writes
   health JSONL.
7. Run `-DrainWithCollector` to prove health/poll/read-events JSONL and queued
   driver rows are emitted.
8. Stop/delete the service and restore the VM checkpoint.

## Reuse boundary from KSword5.1

Prefer reusing protocol definitions and driver-client boundaries from
`D:\Projects\Ksword5.1\shared\driver`, `KswordARKDriver`, and `ArkDriverClient`
as source references. Do not copy the full source tree, generated binaries,
certificates, or `APIMonitor_x64` into this repository.
