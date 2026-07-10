# Host-to-Guest payload staging and live VM smoke

This runbook documents the shortest local path to a useful "start a VM, run a
harmless sample, import guest behavior, and refresh the HTML report" check.
It keeps every generated binary, report, sample publish output, and VM artifact
under `D:\Temp\KSwordSandbox` by default. Do not commit anything from that
runtime tree.

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
  -BuildRoot 'D:\Temp\KSwordSandbox\payload-build'
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
operator can see when and how the payload was prepared.

## 2. Deploy staged tools into the golden VM

The current live Hyper-V runbook assumes the guest agent is already present at:

```text
C:\KSwordSandbox\agent\KSword.Sandbox.Agent.exe
```

Deploy tools before creating or refreshing the `Clean` checkpoint. A practical
PowerShell Direct deployment flow is:

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

3. **PowerShell Direct usable.** The runbook invokes the guest agent through
   `Invoke-Command -VMName ... -Credential ...`. Use a local guest account with
   a non-empty password, store that password outside git, and expose it to the
   host process through the configured environment variable:

   ```powershell
   $env:KSWORDBOX_GUEST_PASSWORD = '<local guest password>'
   $guestPassword = ConvertTo-SecureString $env:KSWORDBOX_GUEST_PASSWORD -AsPlainText -Force
   $guestCredential = [pscredential]::new('SandboxUser', $guestPassword)
   Invoke-Command -VMName 'KSwordSandbox-Win10-Golden' -Credential $guestCredential -ScriptBlock {
       $PSVersionTable.PSVersion
       Test-Path 'C:\KSwordSandbox\agent\KSword.Sandbox.Agent.exe'
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
  -GuestPasswordSecretName 'KSWORDBOX_GUEST_PASSWORD' `
  -RuntimeRoot 'D:\Temp\KSwordSandbox'
```

## 4. Build the harmless sample outside the repository

Publish the benign sample under `D:\Temp\KSwordSandbox\samples`:

```powershell
$repo = 'D:\Projects\KswordSandbox'
$sampleProject = Join-Path $repo 'tools\KSword.Sandbox.TestSample\KSword.Sandbox.TestSample.csproj'
$sampleOut = 'D:\Temp\KSwordSandbox\samples\KSword.Sandbox.TestSample'
$sampleBuild = 'D:\Temp\KSwordSandbox\build\KSword.Sandbox.TestSample\'
$sampleObj = 'D:\Temp\KSwordSandbox\obj\KSword.Sandbox.TestSample\'

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
D:\Temp\KSwordSandbox\samples\KSword.Sandbox.TestSample\KSword.Sandbox.TestSample.exe
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
$sampleExe = 'D:\Temp\KSwordSandbox\samples\KSword.Sandbox.TestSample\KSword.Sandbox.TestSample.exe'

$job = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/jobs/plan" `
  -ContentType 'application/json' `
  -Body (@{
      samplePath = $sampleExe
      displayName = 'KSword.Sandbox.TestSample.exe'
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
the user-mode bridge available. The generated runbook now passes
`--driver-events C:\KSwordSandbox\out\<job-id-n>\driver-events.jsonl`,
`--r0collector`, and `--driver-device` to the Guest Agent when driver collection
is enabled. Use `driver.useMockCollector=true` for no-driver demos, or prepare a
test-signed driver in the guest before expecting real R0 JSONL rows.
