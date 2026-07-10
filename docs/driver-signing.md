# Driver signing and R0 event export

## Scope

The sandbox repository does not store driver binaries, certificates, private
keys, PDB files, or WDK build outputs. It only documents the integration point
for the KSword driver family and the safe validation boundary for local lab
work.

The current default worker/build policy is **compile-only**. Do not add driver
signing or driver loading to normal builds, smoke checks, or Hyper-V E2E plan
validation. Real driver loading is an optional, explicit VM-only step after the
operator has enabled Windows test mode and supplied a local test certificate.

`scripts/Test-R0Readiness.ps1` includes a `Driver .sys git hygiene` check that
fails if any `.sys` file is tracked, staged, modified, or otherwise visible to
git as a commit candidate. Keep any generated or signed driver in VM-local
scratch/payload storage, or in an ignored local path only for the duration of a
disposable VM test. Never stage it.

## Expected event bridge

The guest agent can ingest driver events from JSON Lines:

```json
{"eventType":"registry.set","source":"driver","processId":1234,"path":"HKCU\\Software\\Example","data":{"value":"Run"}}
{"eventType":"file.created","source":"driver","processId":1234,"path":"C:\\Users\\SandboxUser\\AppData\\Local\\drop.bin"}
```

Each line should deserialize to the shared `SandboxEvent` shape. Invalid lines
are preserved as `driver.parse_error` events so the report exposes integration
problems instead of silently losing data.

## Signing policy and guardrails

- Default validation is compile-only: build the native projects and confirm the
  `.sys` output is produced, but do not sign, install, start, or open the driver
  unless a real R0 VM validation was explicitly requested.
- Do **not** call `CSignTool.exe`, and do **not** run the legacy
  `scripts\Sign-SandboxDriverWithKswordCSignTool.ps1` wrapper from unattended
  builds, validation scripts, or worker runbooks. The custom timestamp/
  Authenticode-variant tooling can show modal UI and block automation.
- A local `/.cert/` directory may still exist on some machines from older
  KswordARKDriver handoff work. It remains ignored by git through `/.cert/`, but
  it is not part of the current default signing path.
- Never stage or commit `/.cert/`, private keys, certificates, signing tools,
  signed `.sys` files, or WDK output.
- Use a test-signed driver only in an isolated test VM.
- Record the driver service name in local config through `Driver.ServiceName`.
- Record the guest output path through `Driver.EventJsonLinesPath`.

## Compile-only default validation

For the default repository validation path, build only:

```powershell
.\scripts\Invoke-NativeBuild.ps1 -Project .\KSwordSandbox.sln -Configuration Debug -Platform x64
```

Expected result:

- MSBuild/native compilation succeeds.
- Generated `.sys`, `.exe`, `.pdb`, `x64\...`, `bin\...`, and `obj\...` outputs
  remain ignored/local artifacts.
- No signing helper, timestamp tool, SCM service action, device open, or
  R0Collector live drain is executed.

For Hyper-V E2E demonstrations while signing is deferred, prefer mock R0 mode
(`driver.useMockCollector=true`) so the Guest Agent and R0Collector sidecar path
is exercised without loading a kernel driver.

## Test-signing runbook for optional VM validation

The repository does not generate committed certificates. If a real R0 driver
load is explicitly required, build output should be placed under an ignored
build directory or scratch/payload directory, then test-signed there or inside
the disposable VM. This path uses Windows test mode and a local test
certificate; it intentionally avoids `CSignTool.exe` and custom timestamp tools.

Example VM-only workflow:

```powershell
$driver = 'C:\KSwordSandbox\driver\KSword.Sandbox.Driver.sys'
New-Item -ItemType Directory -Force C:\KSwordSandbox\certs | Out-Null

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
  -CertStoreLocation Cert:\LocalMachine\Root

Import-Certificate `
  -FilePath C:\KSwordSandbox\certs\KSwordSandboxTestDriver.cer `
  -CertStoreLocation Cert:\LocalMachine\TrustedPublisher

Set-AuthenticodeSignature `
  -FilePath $driver `
  -Certificate $cert `
  -HashAlgorithm SHA256

Get-AuthenticodeSignature -FilePath $driver | Format-List Status,SignerCertificate
```

Host/guest lab helper for the same non-CSignTool path:

```powershell
# Run in an elevated isolated VM or against a VM-local driver path.
.\scripts\Sign-SandboxDriverWithTestCertificate.ps1 `
  -DriverPath C:\KSwordSandbox\driver\KSword.Sandbox.Driver.sys `
  -TrustCertificateForLocalMachine `
  -EnableLocalTestSigning
```

If you need to toggle test-signing inside the configured Hyper-V guest from the
host, use the installer or direct helper. Both read the guest credential from
`KSWORDBOX_GUEST_PASSWORD` and do not call CSignTool:

```powershell
.\install.ps1 -Mode Change -QueryGuestTestSigning
.\install.ps1 -Mode Change -EnableGuestTestSigning -RestartGuestAfterTestSigning -Force

.\scripts\Set-GuestTestSigning.ps1 `
  -VmName KSwordSandbox-Win10-Golden `
  -GuestUserName SandboxUser `
  -Mode Enable `
  -RestartGuest `
  -Force
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
- `R0 capability/status IOCTL static contract`: `Passed`; this is a
  source/docs-only check for `IOCTL_KSWORD_SANDBOX_GET_CAPABILITIES`,
  `IOCTL_KSWORD_SANDBOX_GET_STATUS`, and
  `IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK`. It proves the public header,
  driver dispatch source, R0Collector source, and operator docs still describe
  the same negotiated ABI without opening `\\.\KSwordSandboxDriver`.
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
operation. Run these commands only in an isolated VM checkpoint/snapshot after
the compile-only path has succeeded and the optional test-signed driver is
trusted by that VM.

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

The default static readiness pass already checks that the negotiated ABI is
documented and wired for `IOCTL_KSWORD_SANDBOX_GET_CAPABILITIES`,
`IOCTL_KSWORD_SANDBOX_GET_STATUS`, and
`IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK`. Keep failed live driver loads
outside an isolated VM as non-fatal diagnostics: use the static row to catch
contract drift, and reserve live IOCTL failures for VM logs where the service
was intentionally loaded.

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
  `r0collector.driverHealth`, `r0collector.driverCapabilities`,
  `r0collector.driverStatus`, `r0collector.driverPoll`,
  `r0collector.driverReadEvents`, and any queued driver rows.
- `r0collector.driverProducerMask` is expected when the collector is run with
  `--enable-mask <mask>` so it can issue
  `IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK` and record requested,
  previous, effective, and supported producer masks.
- The first drain normally contains at least the typed `driver.load`
  driver-start heartbeat when the ring has not already been consumed.

## Full VM validation sequence

Run this sequence only inside an isolated VM checkpoint/snapshot, and only when
real R0 loading was explicitly requested:

1. Build the driver and R0Collector, then copy the optional test-signed driver
   and R0Collector into VM-local paths. Do not stage the `.sys` file in git.
2. Enable test-signing with `bcdedit /set testsigning on`, reboot, and confirm
   the non-mutating readiness pass is clean.
3. Install and start the kernel service with `-AllowServiceMutation
   -InstallService -StartService`.
4. Create the guest output directory, for example `C:\KSwordSandbox\out`.
5. Run `-CheckDeviceHealth` to prove `\\.\KSwordSandboxDriver` opens.
6. Run `-CheckCollectorHealth` to prove `R0Collector --health --out` writes
   health JSONL.
7. Run `-DrainWithCollector` to prove health/capabilities/status/poll/read-events
   JSONL and queued driver rows are emitted. For producer-mask negotiation,
   additionally run R0Collector with `--enable-mask <mask>` in the same VM and
   confirm `r0collector.driverProducerMask`.
8. Stop/delete the service and restore the VM checkpoint.

## Reuse boundary from KSword5.1

Prefer reusing protocol definitions and driver-client boundaries from
`D:\Projects\Ksword5.1\shared\driver`, `KswordARKDriver`, and `ArkDriverClient`
as source references. Do not copy the full source tree, generated binaries,
certificates, private keys, signing tools, or `APIMonitor_x64` into this
repository. The legacy CSignTool handoff remains frozen for unattended
KSwordSandbox builds until it is explicitly re-enabled by the project owner.
