# Host-to-Guest payload staging and live VM smoke

This runbook documents the shortest local path to a useful "start a VM, run a
harmless sample, import guest behavior, and refresh the HTML report" check.
It keeps every generated binary, report, sample publish output, and VM artifact
under `D:\Temp\KSwordSandbox` by default. Do not commit anything from that
runtime tree.

Canonical scope: this page owns Guest Agent/R0Collector payload staging and
manifest freshness. Golden VM baseline details live in `docs/golden-vm.md`;
current read-only preflight details live in `docs/hyperv-readiness.md`; full
PlanOnly/WhatIf/Live script flow lives in `docs/hyperv-e2e-runbook.md`.

## 1. Build and stage guest tools on the host

Use `scripts/Prepare-GuestPayload.ps1` from the repository root. The script uses
MSBuild for both guest-side projects:

- publishes `guest/KSword.Sandbox.Agent/KSword.Sandbox.Agent.csproj`;
- builds `guest/KSword.Sandbox.R0Collector/KSword.Sandbox.R0Collector.vcxproj`;
- copies runtime files into `D:\Temp\KSwordSandbox\payload\guest-tools`.

Default command:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Prepare-GuestPayload.ps1
```

Useful explicit command:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Prepare-GuestPayload.ps1 `
  -MSBuildPath 'D:\Software\VS\MSBuild\Current\Bin\MSBuild.exe' `
  -Configuration Release `
  -PayloadRoot 'D:\Temp\KSwordSandbox\payload\guest-tools' `
  -BuildRoot 'D:\Temp\KSwordSandbox\payload-build' `
  -GuestWorkingDirectory 'C:\KSwordSandbox' `
  -GuestAgentExecutableName 'KSword.Sandbox.Agent.exe' `
  -R0CollectorExecutableName 'KSword.Sandbox.R0Collector.exe'
```

Expected staged layout:

```text
D:\Temp\KSwordSandbox\payload\guest-tools\
  agent\
    KSword.Sandbox.Agent.exe
    KSword.Sandbox.Agent.dll
    KSword.Sandbox.Agent.deps.json
    KSword.Sandbox.Agent.runtimeconfig.json
    ...
  r0collector\
    KSword.Sandbox.R0Collector.exe
  payload-manifest.json
```

The default script skips `.pdb` files. Add `-IncludeSymbols` only for local
debugging. The script writes the manifest into the payload directory so the VM
operator can see when and how the payload was prepared. The manifest now also
records a payload contract version, required host files, and expected guest
paths consumed by the Hyper-V readiness preflight.

### Payload manifest freshness

`payload-manifest.json` is the operator's freshness record for the staged
Guest Agent and R0Collector payload. For contract version 2, check these fields
before refreshing a golden checkpoint or starting a live run:

- `payloadContractVersion`: should be `2` for the current manifest shape.
- `generatedAtUtc`: when the payload was last prepared.
- `repositoryHead`: git commit or working tree head used during staging.
- `sourceFingerprint`: compact hash over the guest payload source inputs.
- `sourceLatestWriteUtc`: newest source-file timestamp included in that
  fingerprint.
- `requiredHostFiles`: absolute staged paths that readiness expects, including
  `PayloadManifest`, `GuestAgent`, and `R0Collector`.
- `expectedGuestAgentPath` and `expectedR0CollectorPath`: guest paths the live
  runbook validates after staging.

Freshness rule: if the repository head, guest source inputs, build settings, or
expected guest paths changed after `generatedAtUtc` / `sourceLatestWriteUtc`,
rerun `scripts/Prepare-GuestPayload.ps1` and keep the new payload under the
external runtime tree. Do not copy an old payload into the golden VM just
because the required files still exist.

You can validate only the staged host files, without building or copying
anything, by running:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-HyperVReadiness.ps1 `
  -GuestPayloadRoot 'D:\Temp\KSwordSandbox\payload\guest-tools' `
  -GuestWorkingDirectory 'C:\KSwordSandbox'
```

## 2. Guest payload deployment model

The live Hyper-V runbook now stages the prepared tools automatically before it
runs the sample. It copies from the host payload root:

```text
D:\Temp\KSwordSandbox\payload\guest-tools
```

into the configured guest folders:

```text
C:\KSwordSandbox\agent\KSword.Sandbox.Agent.exe
C:\KSwordSandbox\r0collector\KSword.Sandbox.R0Collector.exe
```

The host payload root is controlled by:

```json
{
  "paths": {
    "guestPayloadRoot": "D:\\Temp\\KSwordSandbox\\payload\\guest-tools"
  }
}
```

Manual deployment is still useful when refreshing the golden checkpoint or
debugging PowerShell Direct. A practical PowerShell Direct deployment flow is:

```powershell
$vmName = 'KSwordSandbox-Win10-Golden'
$payloadRoot = 'D:\Temp\KSwordSandbox\payload\guest-tools'
$guestUser = 'SandboxUser'
$guestPassword = ConvertTo-SecureString $env:KSWORDBOX_GUEST_PASSWORD -AsPlainText -Force
$guestCredential = [pscredential]::new($guestUser, $guestPassword)

Start-VM -Name $vmName
$session = New-PSSession -VMName $vmName -Credential $guestCredential

Invoke-Command -Session $session -ScriptBlock {
    New-Item -ItemType Directory -Force -Path `
      'C:\KSwordSandbox\agent', `
      'C:\KSwordSandbox\r0collector', `
      'C:\KSwordSandbox\incoming', `
      'C:\KSwordSandbox\out' | Out-Null
}

Copy-Item -ToSession $session -Path (Join-Path $payloadRoot 'agent\*') `
  -Destination 'C:\KSwordSandbox\agent' -Recurse -Force
Copy-Item -ToSession $session -Path (Join-Path $payloadRoot 'r0collector\*') `
  -Destination 'C:\KSwordSandbox\r0collector' -Recurse -Force

Invoke-Command -Session $session -ScriptBlock {
    Test-Path 'C:\KSwordSandbox\agent\KSword.Sandbox.Agent.exe'
    Test-Path 'C:\KSwordSandbox\r0collector\KSword.Sandbox.R0Collector.exe'
}

Remove-PSSession $session
```

If the VM image will be reused, shut down the VM and create or refresh the clean
checkpoint only after the payload and prerequisites are in place.

## 3. Golden VM prerequisites

Prepare these before running a live runbook:

1. **Elevated host process.** Start the Web API or operator shell as
   Administrator. Hyper-V cmdlets, `Copy-VMFile`, and PowerShell Direct need an
   elevated host process for reliable live execution.
2. **Guest Service Interface enabled.** The runbook uses `Copy-VMFile` to copy
   the submitted sample from host to guest.

   ```powershell
   Enable-VMIntegrationService -VMName 'KSwordSandbox-Win10-Golden' -Name 'Guest Service Interface'
   ```

3. **PowerShell Direct usable.** The runbook stages guest tools with
   `Copy-Item -ToSession` and invokes the guest agent through
   `Invoke-Command -VMName ... -Credential ...`. Use a local guest account with
   a non-empty password, store that password outside git, and expose it to the
   host process through the configured environment variable:

   ```powershell
   $env:KSWORDBOX_GUEST_PASSWORD = '<local guest password>'
   $guestPassword = ConvertTo-SecureString $env:KSWORDBOX_GUEST_PASSWORD -AsPlainText -Force
   $guestCredential = [pscredential]::new('SandboxUser', $guestPassword)
   Invoke-Command -VMName 'KSwordSandbox-Win10-Golden' -Credential $guestCredential -ScriptBlock {
       $PSVersionTable.PSVersion
       New-Item -ItemType Directory -Force -Path 'C:\KSwordSandbox' | Out-Null
       Test-Path 'C:\KSwordSandbox'
   }
   ```

4. **Test signing only for isolated driver tests.** If a test-signed kernel
   driver is used for R0 telemetry, enable test signing inside the guest, reboot
   the guest, import only the public test certificate into the appropriate trust
   stores, and keep the private key outside the repository.

   ```powershell
   bcdedit.exe /set testsigning on
   shutdown.exe /r /t 0
   ```

   After reboot, copy the signed `.sys` into a guest-only path such as
   `C:\KSwordSandbox\driver\`, create/start the driver service from an elevated
   guest shell, and never commit the signed driver, certificate, private key,
   PDB, or service logs.

5. **Clean checkpoint.** After the guest folders, agent, optional R0Collector,
   optional driver prerequisites, and local user account are ready, create the
   checkpoint named by local config, normally `Clean`.

Run the read-only host preflight before attempting live execution:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-HyperVReadiness.ps1 `
  -VmName 'KSwordSandbox-Win10-Golden' `
  -CheckpointName 'Clean' `
  -GuestUserName 'SandboxUser' `
  -GuestPasswordSecretName 'KSWORDBOX_GUEST_PASSWORD' `
  -GuestPayloadRoot 'D:\Temp\KSwordSandbox\payload\guest-tools' `
  -GuestWorkingDirectory 'C:\KSwordSandbox' `
  -RuntimeRoot 'D:\Temp\KSwordSandbox'
```

The preflight checks host payload files immediately. When running as
Administrator and the VM is already on, it also checks PowerShell Direct and the
guest-deployed payload files with read-only `Invoke-Command`/`Test-Path`
probes. If the VM is off, those probes are reported as warnings because the
preflight will not start the VM.

## 4. Build the harmless sample outside the repository

Publish the benign sample under `D:\Temp\KSwordSandbox\samples`:

```powershell
$repo = 'D:\Projects\KswordSandbox'
$sampleProject = Join-Path $repo 'tools\KSword.Sandbox.HarmlessSample\KSword.Sandbox.HarmlessSample.csproj'
$sampleOut = 'D:\Temp\KSwordSandbox\samples\KSword.Sandbox.HarmlessSample'
$sampleBuild = 'D:\Temp\KSwordSandbox\build\KSword.Sandbox.HarmlessSample\'
$sampleObj = 'D:\Temp\KSwordSandbox\obj\KSword.Sandbox.HarmlessSample\'

New-Item -ItemType Directory -Force -Path $sampleOut, $sampleBuild, $sampleObj | Out-Null

dotnet publish $sampleProject `
  --configuration Release `
  --runtime win-x64 `
  --self-contained false `
  --output $sampleOut `
  /p:BaseOutputPath=$sampleBuild `
  /p:BaseIntermediateOutputPath=$sampleObj
```

Use this sample path for the live job:

```text
D:\Temp\KSwordSandbox\samples\KSword.Sandbox.HarmlessSample\KSword.Sandbox.HarmlessSample.exe
```

The sample only creates a marker file, launches a short-lived `cmd.exe`, and
optionally probes loopback and TEST-NET addresses. It is intended for safe
pipeline validation, not for malware behavior coverage.

## 5. Run one live runbook and refresh the report

Start the host Web API from an elevated PowerShell session so the live executor
can run Hyper-V cmdlets:

```powershell
dotnet run --project .\src\KSword.Sandbox.Web\KSword.Sandbox.Web.csproj --no-launch-profile
```

In another elevated shell, create a plan for the harmless sample:

```powershell
$baseUrl = 'http://localhost:5000'
$sampleExe = 'D:\Temp\KSwordSandbox\samples\KSword.Sandbox.HarmlessSample\KSword.Sandbox.HarmlessSample.exe'

$job = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/jobs/plan" `
  -ContentType 'application/json' `
  -Body (@{
      samplePath = $sampleExe
      displayName = 'KSword.Sandbox.HarmlessSample.exe'
      durationSeconds = 30
      dryRun = $true
  } | ConvertTo-Json)

$job.jobId
```

Execute the runbook live and request automatic guest-event import:

```powershell
$execution = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/jobs/$($job.jobId)/runbook/execute" `
  -ContentType 'application/json' `
  -Body (@{
      live = $true
      stepTimeoutSeconds = 1800
      importGuestEvents = $true
  } | ConvertTo-Json)

$execution.execution.success
$execution.guestImportSucceeded
$execution.guestImportMessage
$execution.job.htmlReportPath
```

If automatic import did not happen or you want to force a report refresh after
checking copied guest artifacts, call the import endpoint. Omitting `eventsPath`
lets the service search under the job's `guest` folder for `events.json` and
then `*.jsonl`:

```powershell
$refreshed = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/jobs/$($job.jobId)/guest-events/import" `
  -ContentType 'application/json' `
  -Body '{}'

$refreshed.status
$refreshed.guestEventsPath
$refreshed.htmlReportPath
```

Expected host output locations:

```text
D:\Temp\KSwordSandbox\jobs\<job-id-n>\runbook-execution.json
D:\Temp\KSwordSandbox\jobs\<job-id-n>\guest\<job-id-n>\events.json
D:\Temp\KSwordSandbox\jobs\<job-id-n>\guest\<job-id-n>\driver-events.jsonl
D:\Temp\KSwordSandbox\jobs\<job-id-n>\report.json
D:\Temp\KSwordSandbox\jobs\<job-id-n>\report.html
```

Open the printed `report.html` locally and confirm that it includes guest
process, file, optional network, and import marker events. Keep the whole
`D:\Temp\KSwordSandbox\jobs\...` tree out of git.

## Current R0Collector note

`Prepare-GuestPayload.ps1` stages `KSword.Sandbox.R0Collector.exe` so the VM has
the user-mode bridge available. The generated runbook copies that staged bridge
into the guest, then passes
`--driver-events C:\KSwordSandbox\out\<job-id-n>\driver-events.jsonl`,
`--r0collector`, and `--driver-device` to the Guest Agent when driver collection
is enabled. Use `driver.useMockCollector=true` for no-driver demos, or prepare a
test-signed driver in the guest before expecting real R0 JSONL rows.

`KSword.Sandbox.R0Collector.vcxproj` links the collector with the static MSVC
runtime (`/MT`) for both Debug and Release. This is intentional: a clean Win10
golden VM should not need the Visual C++ Redistributable just to run the mock or
driver JSONL bridge. If the collector exits with `0xC0000135`, rebuild and
restage the payload because that indicates a missing runtime dependency in the
guest.
