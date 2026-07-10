# Driver signing and R0 event export

## Scope

The sandbox repository does not store driver binaries, certificates, private
keys, PDB files, or WDK build outputs. It only documents the integration point
for the KSword driver family.

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

Check readiness without loading the driver:

```powershell
.\scripts\Test-R0Readiness.ps1 `
  -DriverSysPath C:\KSwordSandbox\driver\KSword.Sandbox.Driver.sys `
  -R0CollectorPath C:\KSwordSandbox\tools\KSword.Sandbox.R0Collector.exe
```

## Kernel service install/load/unload

Use the readiness script for service actions so each mutating step is explicit.
The script requires `-AllowServiceMutation` in addition to the requested
operation.

Install and start in an isolated test VM:

```powershell
.\scripts\Test-R0Readiness.ps1 `
  -DriverSysPath C:\KSwordSandbox\driver\KSword.Sandbox.Driver.sys `
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

## Device health and event drain checks

After the service is started, the readiness script can issue the public
`IOCTL_KSWORD_SANDBOX_GET_HEALTH` directly:

```powershell
.\scripts\Test-R0Readiness.ps1 `
  -CheckDeviceHealth `
  -DevicePath \\.\KSwordSandboxDriver
```

To verify the full collector path, run a one-shot R0Collector drain. This writes
JSON Lines only to the explicit output path:

```powershell
.\scripts\Test-R0Readiness.ps1 `
  -R0CollectorPath C:\KSwordSandbox\tools\KSword.Sandbox.R0Collector.exe `
  -DevicePath \\.\KSwordSandboxDriver `
  -DrainWithCollector `
  -CollectorOutputPath C:\KSwordSandbox\out\driver-events.jsonl
```

Expected first-pass evidence:

- `Device IOCTL health` returns `Passed`.
- `R0Collector drain` returns exit code `0`.
- The JSONL file contains `r0collector.opened`, health/poll/read-events rows,
  and at least the header-only `driver.started` heartbeat when the ring has not
  already been drained.

## Reuse boundary from KSword5.1

Prefer reusing protocol definitions and driver-client boundaries from
`D:\Projects\Ksword5.1\shared\driver`, `KswordARKDriver`, and `ArkDriverClient`
as source references. Do not copy the full source tree, generated binaries,
certificates, or `APIMonitor_x64` into this repository.
