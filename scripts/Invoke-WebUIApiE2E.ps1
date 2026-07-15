<#
.SYNOPSIS
Runs an API-level KSwordSandbox WebUI end-to-end validation.

.DESCRIPTION
Inputs are a WebUI URL, sample path, optional config path, and safe/live mode
switches. Processing optionally starts the WebUI through run.ps1, waits for
/health, creates a job through /api/jobs/plan, executes the runbook through
the preferred background /api/jobs/{jobId}/runbook/start path (or the legacy
blocking endpoint when explicitly requested), verifies live-event and report
endpoints, and writes a JSON summary under D:\Temp by default.

The default mode is safe: it does not start, restore, or mutate a VM. Real
Hyper-V, VMware, or QEMU execution requires -Live. This script never calls
CSignTool or the legacy KSword signing wrapper.
#>
[CmdletBinding()]
param(
    [string]$BaseUrl = 'http://127.0.0.1:18082',

    [string]$ConfigPath,

    [string]$SamplePath,

    [ValidateRange(1, 900)]
    [int]$DurationSeconds = 5,

    [ValidateRange(1, 7200)]
    [int]$StepTimeoutSeconds = 1800,

    [switch]$Live,

    [ValidateSet('Background', 'Blocking')]
    [string]$ExecutionTransport = 'Background',

    [ValidateRange(5, 21600)]
    [int]$BackgroundTimeoutSeconds = 7200,

    [switch]$StartWebUI,

    [switch]$StopWebUIOnExit,

    [switch]$SkipPayloadPreparation,

    [switch]$UseMockCollector,

    [string]$DisplayName = 'KSword WebUI/API E2E validation',

    [ValidateSet('', 'HyperV', 'VMware', 'Qemu')]
    [string]$Provider = '',

    [Alias('VmName')]
    [string]$GoldenVmName,

    [Alias('BaselineName', 'CheckpointName')]
    [string]$GoldenSnapshotName,

    [string]$MachineDefinitionPath,

    [ValidateSet('', 'qcow2', 'raw', 'vhdx', 'vmdk')]
    [string]$QemuDiskFormat = '',

    [string]$GuestUserName,

    [string]$GuestWorkingDirectory,

    [string]$GuestPayloadRoot,

    [string]$DotNetPath = 'dotnet',

    [string]$PowerShellPath = 'powershell.exe',

    [ValidateRange(5, 300)]
    [int]$StartupTimeoutSeconds = 90,

    [string]$GitCommit = '',

    [switch]$RequireCleanSource,

    [string]$SummaryPath = 'D:\Temp\KSwordSandbox\webui-api-e2e\last-summary.json'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$script:StartedWebUIProcess = $null

function Write-E2EStep {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "[webui-api-e2e] $Message"
}

function Assert-E2ECondition {
    param(
        [Parameter(Mandatory)][bool]$Condition,
        [Parameter(Mandatory)][string]$Message
    )

    if (-not $Condition) {
        throw [InvalidOperationException]::new($Message)
    }
}

function Get-E2EGitProvenance {
    param(
        [AllowEmptyString()][string]$RequestedCommit,
        [Parameter(Mandatory)][bool]$RequireCommit,
        [Parameter(Mandatory)][bool]$RequireClean
    )

    $commit = $RequestedCommit.Trim()
    $commitSource = if ([string]::IsNullOrWhiteSpace($commit)) { 'unavailable' } else { 'parameter' }
    $dirty = $null
    $changedFileCount = $null
    $gitDiagnostic = ''
    $provenancePath = $null
    $gitCommand = Get-Command git -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $gitCommand -and -not [string]::IsNullOrWhiteSpace([string]$gitCommand.Source)) {
        $headOutput = @(& $gitCommand.Source -C $repoRoot rev-parse HEAD 2>&1)
        $headExitCode = $LASTEXITCODE
        $headCommit = if ($headExitCode -eq 0) { ([string]($headOutput | Select-Object -First 1)).Trim() } else { '' }
        if (-not [string]::IsNullOrWhiteSpace($headCommit)) {
            if (-not [string]::IsNullOrWhiteSpace($commit) -and
                -not $commit.Equals($headCommit, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "Requested Git commit '$commit' does not match checkout HEAD '$headCommit'."
            }
            $commit = $headCommit
            $commitSource = 'checkout-head'
            $provenancePath = Join-Path $repoRoot '.git'
        }
        elseif ($headOutput.Count -gt 0) {
            $gitDiagnostic = ($headOutput -join ' ').Trim()
        }

        $statusOutput = @(& $gitCommand.Source -C $repoRoot status --porcelain --untracked-files=all 2>&1)
        if ($LASTEXITCODE -eq 0) {
            $changedFileCount = @($statusOutput).Count
            $dirty = $changedFileCount -gt 0
        }
        elseif ([string]::IsNullOrWhiteSpace($gitDiagnostic)) {
            $gitDiagnostic = ($statusOutput -join ' ').Trim()
        }
    }
    else {
        $gitDiagnostic = 'git executable was not found'
    }

    if ($commitSource -ne 'checkout-head') {
        $packageManifestPath = Join-Path $repoRoot 'package-manifest.generated.json'
        if (Test-Path -LiteralPath $packageManifestPath -PathType Leaf) {
            try {
                $packageManifest = Get-Content -LiteralPath $packageManifestPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                $manifestGit = $packageManifest.gitMetadata
                $manifestCommit = ([string]$manifestGit.commit).Trim()
                if ($manifestCommit -match '^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$') {
                    if (-not [string]::IsNullOrWhiteSpace($commit) -and
                        -not $commit.Equals($manifestCommit, [System.StringComparison]::OrdinalIgnoreCase)) {
                        throw "Requested Git commit '$commit' does not match package manifest commit '$manifestCommit'."
                    }
                    $commit = $manifestCommit
                    $commitSource = 'package-manifest'
                    $provenancePath = (Resolve-Path -LiteralPath $packageManifestPath).ProviderPath
                    $dirtyProperty = $manifestGit.PSObject.Properties['isDirty']
                    if ($null -eq $dirtyProperty) { $dirtyProperty = $manifestGit.PSObject.Properties['dirty'] }
                    if ($null -ne $dirtyProperty -and $dirtyProperty.Value -is [bool]) {
                        $dirty = [bool]$dirtyProperty.Value
                    }
                    $statusCountProperty = $manifestGit.PSObject.Properties['statusCount']
                    $parsedStatusCount = 0
                    if ($null -ne $statusCountProperty -and
                        [int]::TryParse([string]$statusCountProperty.Value, [ref]$parsedStatusCount) -and
                        $parsedStatusCount -ge 0) {
                        $changedFileCount = $parsedStatusCount
                    }
                    $gitDiagnostic = ''
                }
                elseif ([string]::IsNullOrWhiteSpace($gitDiagnostic)) {
                    $gitDiagnostic = "package manifest does not contain a full gitMetadata.commit: $packageManifestPath"
                }
            }
            catch {
                if ($_.Exception.Message -like 'Requested Git commit*') { throw }
                $gitDiagnostic = "package provenance could not be read: $($_.Exception.Message)"
            }
        }
    }

    $commitValid = $commit -match '^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$'
    if ($RequireCommit -and -not $commitValid) {
        throw "Live parity evidence requires a full Git commit (40 or 64 hex characters). Pass -GitCommit when running from a package without checkout metadata. Diagnostic: $gitDiagnostic"
    }
    if ($RequireClean -and ($dirty -ne $false -or $changedFileCount -ne 0)) {
        throw "Clean-source parity evidence requires gitDirty=false and gitChangedFileCount=0 before VM mutation. commitSource=$commitSource dirty=$dirty changedFileCount=$changedFileCount provenancePath=$provenancePath diagnostic=$gitDiagnostic"
    }

    return [pscustomobject][ordered]@{
        commit          = if ($commitValid) { $commit.ToLowerInvariant() } else { $null }
        commitSource    = $commitSource
        dirty           = $dirty
        changedFileCount = $changedFileCount
        provenancePath  = $provenancePath
        diagnostic      = $gitDiagnostic
    }
}

function ConvertTo-E2EProcessArgument {
    param([AllowNull()][string]$Argument)

    if ($null -eq $Argument -or $Argument.Length -eq 0) {
        return '""'
    }

    if ($Argument -notmatch '[\s"]') {
        return $Argument
    }

    return '"' + ($Argument -replace '"', '\"') + '"'
}

function Get-E2EFileSha256 {
    param([Parameter(Mandatory)][string]$Path)

    $stream = [System.IO.File]::Open(
        $Path,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        return -join ($sha256.ComputeHash($stream) | ForEach-Object { $_.ToString('x2') })
    }
    finally {
        $sha256.Dispose()
        $stream.Dispose()
    }
}

function Resolve-E2EPath {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Description,
        [switch]$Leaf
    )

    $candidate = if ([System.IO.Path]::IsPathRooted($Path)) {
        $Path
    }
    else {
        Join-Path (Get-Location).Path $Path
    }

    if ($Leaf) {
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            throw "$Description was not found: $candidate"
        }
    }
    elseif (-not (Test-Path -LiteralPath $candidate)) {
        throw "$Description was not found: $candidate"
    }

    return (Resolve-Path -LiteralPath $candidate).Path
}

function Resolve-E2ESamplePath {
    param([string]$RequestedPath)

    if (-not [string]::IsNullOrWhiteSpace($RequestedPath)) {
        return Resolve-E2EPath -Path $RequestedPath -Description 'Sample executable' -Leaf
    }

    $defaultSample = Join-Path $repoRoot 'tools\KSword.Sandbox.HarmlessSample\bin\Debug\net9.0\KSword.Sandbox.HarmlessSample.exe'
    if (-not (Test-Path -LiteralPath $defaultSample -PathType Leaf)) {
        $sampleProject = Join-Path $repoRoot 'tools\KSword.Sandbox.HarmlessSample\KSword.Sandbox.HarmlessSample.csproj'
        Write-E2EStep "Default harmless sample is missing; building $sampleProject"
        & $DotNetPath build $sampleProject --nologo /v:minimal
        if ($LASTEXITCODE -ne 0) {
            throw "dotnet build failed for harmless sample with exit code $LASTEXITCODE."
        }
    }

    return Resolve-E2EPath -Path $defaultSample -Description 'Default harmless sample executable' -Leaf
}

function Get-E2EFileTail {
    param(
        [string]$Path,
        [int]$LineCount = 80
    )

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return ''
    }

    return (Get-Content -LiteralPath $Path -Tail $LineCount -ErrorAction SilentlyContinue) -join [Environment]::NewLine
}

function Start-E2EWebUI {
    param(
        [Parameter(Mandatory)][string]$Url,
        [string]$SandboxConfigPath,
        [switch]$SkipPayload
    )

    $runScript = Join-Path $repoRoot 'run.ps1'
    if (-not (Test-Path -LiteralPath $runScript -PathType Leaf)) {
        throw "run.ps1 was not found: $runScript"
    }

    $logRoot = Join-Path ([System.IO.Path]::GetDirectoryName($SummaryPath)) 'webui'
    New-Item -ItemType Directory -Path $logRoot -Force | Out-Null
    $stdout = Join-Path $logRoot 'webui.stdout.log'
    $stderr = Join-Path $logRoot 'webui.stderr.log'
    Remove-Item -LiteralPath $stdout, $stderr -Force -ErrorAction SilentlyContinue

    $arguments = @(
        '-NoProfile',
        '-ExecutionPolicy',
        'Bypass',
        '-File',
        $runScript,
        '-Mode',
        'WebUI',
        '-Url',
        $Url
    )

    if (-not [string]::IsNullOrWhiteSpace($SandboxConfigPath)) {
        $arguments += @('-ConfigPath', $SandboxConfigPath)
    }

    if ($SkipPayload) {
        $arguments += '-SkipPayloadPreparation'
    }

    Write-E2EStep "Starting WebUI: $Url"
    $script:StartedWebUIProcess = Start-Process `
        -FilePath $PowerShellPath `
        -ArgumentList ($arguments | ForEach-Object { ConvertTo-E2EProcessArgument $_ }) `
        -WorkingDirectory $repoRoot `
        -RedirectStandardOutput $stdout `
        -RedirectStandardError $stderr `
        -WindowStyle Hidden `
        -PassThru

    return [pscustomobject]@{
        Process = $script:StartedWebUIProcess
        Stdout  = $stdout
        Stderr  = $stderr
    }
}

function Wait-E2EWebUI {
    param(
        [Parameter(Mandatory)][string]$Url,
        [int]$TimeoutSeconds,
        [object]$StartedHost
    )

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    $healthUri = "$Url/health"
    do {
        if ($StartedHost -and $StartedHost.Process -and $StartedHost.Process.HasExited) {
            $stdoutTail = Get-E2EFileTail -Path $StartedHost.Stdout
            $stderrTail = Get-E2EFileTail -Path $StartedHost.Stderr
            throw "WebUI exited before /health succeeded. ExitCode=$($StartedHost.Process.ExitCode).`nSTDOUT:`n$stdoutTail`nSTDERR:`n$stderrTail"
        }

        try {
            $health = Invoke-RestMethod -Method Get -Uri $healthUri -TimeoutSec 3
            if ($health.status -eq 'ok') {
                Write-E2EStep "WebUI health OK: $healthUri"
                return $health
            }
        }
        catch {
            Start-Sleep -Milliseconds 700
        }
    } while ([DateTimeOffset]::UtcNow -lt $deadline)

    throw "Timed out waiting $TimeoutSeconds second(s) for $healthUri."
}

function Invoke-E2EJsonPost {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][object]$Body,
        [int]$TimeoutSeconds = 60
    )

    $json = $Body | ConvertTo-Json -Depth 12
    return Invoke-RestMethod -Method Post -Uri $Uri -ContentType 'application/json' -Body $json -TimeoutSec $TimeoutSeconds
}

function Get-E2EProviderReadiness {
    param(
        [Parameter(Mandatory)][string]$Url,
        [AllowEmptyString()][string]$RequestedProvider,
        [Parameter(Mandatory)][bool]$HasResourceOverride,
        [Parameter(Mandatory)][bool]$LiveMode
    )

    $readinessUri = "$Url/api/host/readiness?refresh=true"
    if (-not [string]::IsNullOrWhiteSpace($RequestedProvider)) {
        $readinessUri += "&provider=$([Uri]::EscapeDataString($RequestedProvider))"
    }

    Write-E2EStep "Reading selected-provider readiness: $readinessUri"
    $readiness = Invoke-RestMethod -Method Get -Uri $readinessUri -TimeoutSec 120
    Assert-E2ECondition -Condition ([bool]$readiness.readOnly) -Message 'Host readiness did not declare readOnly=true.'
    Assert-E2ECondition -Condition ($null -ne $readiness.hostVirtualization) -Message 'Host readiness is missing provider-neutral acceleration facts.'
    Assert-E2ECondition -Condition ($null -ne $readiness.virtualization) -Message 'Host readiness is missing selected-provider facts.'
    Assert-E2ECondition -Condition ($null -ne $readiness.paths -and $null -ne $readiness.paths.runtimeRoot) -Message 'Host readiness is missing runtime-root facts.'
    Assert-E2ECondition -Condition (-not [string]::IsNullOrWhiteSpace([string]$readiness.paths.runtimeRoot.path)) -Message 'Host readiness did not identify the runtime root.'

    $readinessProvider = [string]$readiness.virtualization.provider
    Assert-E2ECondition -Condition (-not [string]::IsNullOrWhiteSpace($readinessProvider)) -Message 'Host readiness did not identify the selected provider.'
    Assert-E2ECondition -Condition ([string]$readiness.hostVirtualization.provider -eq $readinessProvider) -Message 'Host acceleration and provider readiness identities do not match.'
    if (-not [string]::IsNullOrWhiteSpace($RequestedProvider)) {
        Assert-E2ECondition -Condition ($readinessProvider -eq $RequestedProvider) -Message "Readiness provider '$readinessProvider' does not match requested provider '$RequestedProvider'."
    }

    if ($LiveMode) {
        Assert-E2ECondition -Condition ([bool]$readiness.hostVirtualization.operatingSystemSupported) -Message "$readinessProvider Live requires a supported Windows host."
        Assert-E2ECondition -Condition ($readiness.hostVirtualization.hardwareAccelerationReady -eq $true) -Message "$readinessProvider hardware acceleration is not confirmed ready. code=$($readiness.hostVirtualization.diagnosticCode) message=$($readiness.hostVirtualization.diagnosticMessage)"
        Assert-E2ECondition -Condition ([bool]$readiness.virtualization.managementAvailable) -Message "$readinessProvider management tools are unavailable. code=$($readiness.virtualization.diagnosticCode) message=$($readiness.virtualization.diagnosticMessage)"
        Assert-E2ECondition -Condition ([bool]$readiness.virtualization.guestTransportSecure) -Message "$readinessProvider guest transport is not secure."
        Assert-E2ECondition -Condition ([bool]$readiness.virtualization.guestEndpointReady) -Message "$readinessProvider guest endpoint configuration is not ready. code=$($readiness.virtualization.diagnosticCode) message=$($readiness.virtualization.diagnosticMessage)"

        if (-not $HasResourceOverride) {
            Assert-E2ECondition -Condition ([bool]$readiness.virtualization.querySucceeded) -Message "$readinessProvider inventory query failed. code=$($readiness.virtualization.diagnosticCode) message=$($readiness.virtualization.diagnosticMessage)"
            Assert-E2ECondition -Condition ([bool]$readiness.virtualization.vmExists) -Message "$readinessProvider configured VM resource was not detected."
            Assert-E2ECondition -Condition ([bool]$readiness.virtualization.baselineExists) -Message "$readinessProvider configured clean baseline was not detected."
        }
    }

    return $readiness
}

function Wait-E2EBackgroundExecution {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$JobId,
        [Parameter(Mandatory)][int]$TimeoutSeconds
    )

    $backgroundUri = "$Url/api/jobs/$JobId/runbook/background"
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    $lastState = ''
    do {
        $snapshot = Invoke-RestMethod -Method Get -Uri $backgroundUri -TimeoutSec 30
        $state = ([string]$snapshot.state).Trim().ToLowerInvariant()
        if (-not $state.Equals($lastState, [StringComparison]::Ordinal)) {
            Write-E2EStep "Background execution state: $state"
            $lastState = $state
        }
        if ($state -in @('completed', 'failed', 'canceled')) {
            return $snapshot
        }
        Start-Sleep -Seconds 1
    } while ([DateTimeOffset]::UtcNow -lt $deadline)

    throw "Timed out waiting $TimeoutSeconds second(s) for background runbook execution at $backgroundUri. Last state: $lastState"
}

function Test-E2EReportEndpoint {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$Name
    )

    $response = Invoke-WebRequest -UseBasicParsing -Method Get -Uri $Uri -TimeoutSec 120
    Assert-E2ECondition -Condition ($response.StatusCode -eq 200) -Message "$Name report endpoint returned HTTP $($response.StatusCode)."
    Assert-E2ECondition -Condition ($response.Content.Length -gt 1000) -Message "$Name report endpoint returned an unexpectedly small body."
    return [pscustomobject]@{
        name       = $Name
        uri        = $Uri
        statusCode = $response.StatusCode
        bytes      = $response.Content.Length
    }
}

function Stop-E2EStartedWebUI {
    if ($script:StartedWebUIProcess -and -not $script:StartedWebUIProcess.HasExited) {
        Write-E2EStep "Stopping WebUI PID $($script:StartedWebUIProcess.Id)"
        Stop-Process -Id $script:StartedWebUIProcess.Id -Force -ErrorAction SilentlyContinue
    }
}

try {
    $resolvedSummaryDirectory = [System.IO.Path]::GetDirectoryName([System.IO.Path]::GetFullPath($SummaryPath))
    if (-not [string]::IsNullOrWhiteSpace($resolvedSummaryDirectory)) {
        New-Item -ItemType Directory -Path $resolvedSummaryDirectory -Force | Out-Null
    }

    if (-not [string]::IsNullOrWhiteSpace($ConfigPath)) {
        $ConfigPath = Resolve-E2EPath -Path $ConfigPath -Description 'Sandbox config' -Leaf
    }

    $resolvedSamplePath = Resolve-E2ESamplePath -RequestedPath $SamplePath
    $sampleFile = Get-Item -LiteralPath $resolvedSamplePath -ErrorAction Stop
    $sampleSha256 = Get-E2EFileSha256 -Path $resolvedSamplePath
    $modeName = if ($Live) { 'Live' } else { 'DryRun' }
    $gitProvenance = Get-E2EGitProvenance `
        -RequestedCommit $GitCommit `
        -RequireCommit ([bool]$Live -or [bool]$RequireCleanSource) `
        -RequireClean ([bool]$RequireCleanSource)
    Write-E2EStep "Mode: $modeName"
    Write-E2EStep "Execution transport: $ExecutionTransport"
    Write-E2EStep "Sample: $resolvedSamplePath"

    $startedHost = $null
    if ($StartWebUI) {
        $startedHost = Start-E2EWebUI -Url $BaseUrl -SandboxConfigPath $ConfigPath -SkipPayload:$SkipPayloadPreparation
    }

    $health = Wait-E2EWebUI -Url $BaseUrl -TimeoutSeconds $StartupTimeoutSeconds -StartedHost $startedHost
    $hasProviderResourceOverride = (
        -not [string]::IsNullOrWhiteSpace($GoldenVmName) -or
        -not [string]::IsNullOrWhiteSpace($GoldenSnapshotName) -or
        -not [string]::IsNullOrWhiteSpace($MachineDefinitionPath) -or
        -not [string]::IsNullOrWhiteSpace($QemuDiskFormat)
    )
    $providerReadiness = Get-E2EProviderReadiness `
        -Url $BaseUrl `
        -RequestedProvider $Provider `
        -HasResourceOverride $hasProviderResourceOverride `
        -LiveMode ([bool]$Live)

    $planBody = [ordered]@{
        samplePath      = $resolvedSamplePath
        displayName     = $DisplayName
        durationSeconds = $DurationSeconds
        dryRun          = (-not [bool]$Live)
    }

    if ($UseMockCollector) {
        $planBody.useMockCollector = $true
    }

    if (-not [string]::IsNullOrWhiteSpace($Provider)) {
        $planBody.provider = $Provider
    }

    if (-not [string]::IsNullOrWhiteSpace($GoldenVmName)) {
        $planBody.goldenVmName = $GoldenVmName
    }

    if (-not [string]::IsNullOrWhiteSpace($GoldenSnapshotName)) {
        $planBody.goldenSnapshotName = $GoldenSnapshotName
    }

    if (-not [string]::IsNullOrWhiteSpace($MachineDefinitionPath)) {
        $planBody.machineDefinitionPath = $MachineDefinitionPath
    }

    if (-not [string]::IsNullOrWhiteSpace($QemuDiskFormat)) {
        $planBody.qemuDiskFormat = $QemuDiskFormat.ToLowerInvariant()
    }

    if (-not [string]::IsNullOrWhiteSpace($GuestUserName)) {
        $planBody.guestUserName = $GuestUserName
    }

    if (-not [string]::IsNullOrWhiteSpace($GuestWorkingDirectory)) {
        $planBody.guestWorkingDirectory = $GuestWorkingDirectory
    }

    if (-not [string]::IsNullOrWhiteSpace($GuestPayloadRoot)) {
        $planBody.guestPayloadRoot = $GuestPayloadRoot
    }

    Write-E2EStep 'Planning job through /api/jobs/plan'
    $job = Invoke-E2EJsonPost -Uri "$BaseUrl/api/jobs/plan" -Body $planBody -TimeoutSeconds 120
    $jobId = [string]$job.jobId
    Assert-E2ECondition -Condition (-not [string]::IsNullOrWhiteSpace($jobId)) -Message 'Plan response did not include jobId.'
    Assert-E2ECondition -Condition ($null -ne $job.runbook) -Message 'Plan response did not include the effective provider runbook.'
    $effectiveProvider = [string]$job.runbook.provider
    $effectiveLogicalVmName = [string]$job.submission.goldenVmName
    $effectiveTargetVmName = [string]$job.runbook.targetVmName
    $effectiveBaselineName = [string]$job.runbook.baselineName
    $effectiveMachineDefinitionPath = [string]$job.runbook.machineDefinitionPath
    $effectiveQemuDiskFormat = [string]$job.runbook.qemuDiskFormat
    Assert-E2ECondition -Condition (-not [string]::IsNullOrWhiteSpace($effectiveProvider)) -Message 'Planned runbook did not expose provider identity.'
    if (-not [string]::IsNullOrWhiteSpace($Provider)) {
        Assert-E2ECondition -Condition ($effectiveProvider -eq $Provider) -Message "Planned provider '$effectiveProvider' does not match requested provider '$Provider'."
    }
    Assert-E2ECondition -Condition ([string]$providerReadiness.virtualization.provider -eq $effectiveProvider) -Message "Readiness provider '$($providerReadiness.virtualization.provider)' does not match planned provider '$effectiveProvider'."
    if (-not [string]::IsNullOrWhiteSpace($GoldenVmName)) {
        Assert-E2ECondition -Condition ($effectiveLogicalVmName -eq $GoldenVmName) -Message "Planned logical VM '$effectiveLogicalVmName' does not match requested VM '$GoldenVmName'."
    }
    if (-not [string]::IsNullOrWhiteSpace($MachineDefinitionPath)) {
        Assert-E2ECondition -Condition ($effectiveMachineDefinitionPath -eq $MachineDefinitionPath) -Message "Planned machine definition '$effectiveMachineDefinitionPath' does not match the requested VMX/disk path."
    }
    if (-not [string]::IsNullOrWhiteSpace($QemuDiskFormat)) {
        Assert-E2ECondition -Condition ($effectiveQemuDiskFormat -eq $QemuDiskFormat.ToLowerInvariant()) -Message "Planned QEMU disk format '$effectiveQemuDiskFormat' does not match '$QemuDiskFormat'."
    }
    Write-E2EStep "Planned job: $jobId"
    Write-E2EStep "Provider: $effectiveProvider; VM: $effectiveTargetVmName; baseline: $effectiveBaselineName"

    $executeBody = [ordered]@{
        live               = [bool]$Live
        stepTimeoutSeconds = $StepTimeoutSeconds
        importGuestEvents  = $true
    }

    $startedAt = [DateTimeOffset]::UtcNow
    $background = $null
    if ($ExecutionTransport -eq 'Background') {
        Write-E2EStep "Starting runbook through /api/jobs/$jobId/runbook/start"
        $startSnapshot = Invoke-E2EJsonPost -Uri "$BaseUrl/api/jobs/$jobId/runbook/start" -Body $executeBody -TimeoutSeconds 120
        Assert-E2ECondition -Condition ([bool]$startSnapshot.accepted) -Message "Background runner did not accept job $jobId. state=$($startSnapshot.state) message=$($startSnapshot.message)"
        Assert-E2ECondition -Condition ([string]$startSnapshot.provider -eq $effectiveProvider) -Message "Background start provider '$($startSnapshot.provider)' does not match planned provider '$effectiveProvider'."

        $background = Wait-E2EBackgroundExecution -Url $BaseUrl -JobId $jobId -TimeoutSeconds $BackgroundTimeoutSeconds
        Assert-E2ECondition -Condition ([string]$background.state -eq 'completed') -Message "Background runbook did not complete successfully. state=$($background.state) message=$($background.message)"
        Assert-E2ECondition -Condition ([bool]$background.success) -Message "Background runbook terminal snapshot reported success=false. message=$($background.message)"
        Assert-E2ECondition -Condition ([string]$background.provider -eq $effectiveProvider) -Message "Background terminal provider '$($background.provider)' does not match planned provider '$effectiveProvider'."
        Assert-E2ECondition -Condition ($null -ne $background.job) -Message 'Background terminal snapshot did not include its safe job summary.'

        $updatedJob = $background.job
        Assert-E2ECondition -Condition ([string]$updatedJob.provider -eq $effectiveProvider) -Message "Background terminal job provider '$($updatedJob.provider)' does not match planned provider '$effectiveProvider'."
        Assert-E2ECondition -Condition ([string]$updatedJob.runbook.provider -eq $effectiveProvider) -Message "Background terminal runbook provider '$($updatedJob.runbook.provider)' does not match planned provider '$effectiveProvider'."
        Assert-E2ECondition -Condition ([string]$updatedJob.runbook.targetVmName -eq $effectiveTargetVmName) -Message "Background terminal VM '$($updatedJob.runbook.targetVmName)' does not match planned VM '$effectiveTargetVmName'."
        Assert-E2ECondition -Condition ([string]$updatedJob.runbook.baselineName -eq $effectiveBaselineName) -Message "Background terminal baseline '$($updatedJob.runbook.baselineName)' does not match planned baseline '$effectiveBaselineName'."
        Assert-E2ECondition -Condition ([string]$updatedJob.runbook.machineDefinitionPath -eq $effectiveMachineDefinitionPath) -Message 'Background terminal VMX/base-disk identity does not match the planned runbook.'
        Assert-E2ECondition -Condition ([string]$updatedJob.runbook.qemuDiskFormat -eq $effectiveQemuDiskFormat) -Message 'Background terminal QEMU disk format does not match the planned runbook.'
        $executionPath = [string]$updatedJob.runbookExecutionResultPath
        Assert-E2ECondition -Condition (-not [string]::IsNullOrWhiteSpace($executionPath)) -Message 'Background terminal job is missing runbookExecutionResultPath.'
        Assert-E2ECondition -Condition (Test-Path -LiteralPath $executionPath -PathType Leaf) -Message "runbook-execution.json was not written: $executionPath"
        $execution = Get-Content -LiteralPath $executionPath -Raw -ErrorAction Stop | ConvertFrom-Json
        $payload = [pscustomobject][ordered]@{
            execution = $execution
            job = $updatedJob
            guestImportSucceeded = [bool]$background.guestImportSucceeded
            guestImportSkipped = [bool]$background.guestImportSkipped
            guestImportFailed = [bool]$background.guestImportFailed
            guestImportMessage = [string]$background.guestImportMessage
        }
    }
    else {
        Write-E2EStep "Executing runbook through legacy /api/jobs/$jobId/runbook/execute"
        $payload = Invoke-E2EJsonPost -Uri "$BaseUrl/api/jobs/$jobId/runbook/execute" -Body $executeBody -TimeoutSeconds ([Math]::Max($StepTimeoutSeconds + 120, 300))
        $execution = $payload.execution
        $updatedJob = $payload.job
    }
    $duration = [DateTimeOffset]::UtcNow - $startedAt

    Assert-E2ECondition -Condition ($null -ne $execution) -Message 'Runbook result did not include execution.'
    Assert-E2ECondition -Condition ($null -ne $updatedJob) -Message 'Runbook result did not include updated job.'
    Assert-E2ECondition -Condition ([bool]$execution.success) -Message "Runbook execution failed. failedStepIndex=$($execution.failedStepIndex) message=$($execution.message)"
    Assert-E2ECondition -Condition ([string]$execution.provider -eq $effectiveProvider) -Message "Execution provider '$($execution.provider)' does not match planned provider '$effectiveProvider'."
    Assert-E2ECondition -Condition ([string]$execution.targetVmName -eq $effectiveTargetVmName) -Message "Execution VM '$($execution.targetVmName)' does not match planned VM '$effectiveTargetVmName'."
    Assert-E2ECondition -Condition (-not [string]::IsNullOrWhiteSpace([string]$updatedJob.runbookExecutionResultPath)) -Message 'Updated job is missing runbookExecutionResultPath.'
    Assert-E2ECondition -Condition (Test-Path -LiteralPath ([string]$updatedJob.runbookExecutionResultPath) -PathType Leaf) -Message "runbook-execution.json was not written: $($updatedJob.runbookExecutionResultPath)"

    if ($Live) {
        Assert-E2ECondition -Condition ([bool]$payload.guestImportSucceeded) -Message "Live execution succeeded but guest import did not: $($payload.guestImportMessage)"
        Assert-E2ECondition -Condition (-not [string]::IsNullOrWhiteSpace([string]$updatedJob.guestEventsPath)) -Message 'Live updated job is missing guestEventsPath.'
    }

    Write-E2EStep "Execution succeeded in $([Math]::Round($duration.TotalSeconds, 3))s; steps=$($execution.executedSteps)/$($execution.totalSteps)"

    $liveSnapshot = Invoke-RestMethod -Method Get -Uri "$BaseUrl/api/jobs/$jobId/events/live?offset=0&take=25" -TimeoutSec 120
    Assert-E2ECondition -Condition ([int]$liveSnapshot.totalEvents -gt 0) -Message 'Live raw-event endpoint returned zero events.'

    $reportChecks = @()
    if (-not [string]::IsNullOrWhiteSpace([string]$updatedJob.htmlReportPath)) {
        Assert-E2ECondition -Condition (Test-Path -LiteralPath ([string]$updatedJob.htmlReportPath) -PathType Leaf) -Message "HTML report file was not written: $($updatedJob.htmlReportPath)"
        $reportChecks += Test-E2EReportEndpoint -Uri "$BaseUrl/api/jobs/$jobId/report/html" -Name 'default'
        $reportChecks += Test-E2EReportEndpoint -Uri "$BaseUrl/api/jobs/$jobId/report/html?lang=zh" -Name 'zh'
        $reportChecks += Test-E2EReportEndpoint -Uri "$BaseUrl/api/jobs/$jobId/report/html?lang=en" -Name 'en'
    }
    else {
        throw 'Updated job is missing htmlReportPath after execution.'
    }

    $jsonReportPath = [string]$updatedJob.jsonReportPath
    Assert-E2ECondition -Condition (-not [string]::IsNullOrWhiteSpace($jsonReportPath)) -Message 'Updated job is missing jsonReportPath after execution.'
    Assert-E2ECondition -Condition (Test-Path -LiteralPath $jsonReportPath -PathType Leaf) -Message "JSON report file was not written: $jsonReportPath"
    $report = Get-Content -LiteralPath $jsonReportPath -Raw -ErrorAction Stop | ConvertFrom-Json
    Assert-E2ECondition -Condition ([string]$report.provider -eq $effectiveProvider) -Message "Report provider '$($report.provider)' does not match planned provider '$effectiveProvider'."
    Assert-E2ECondition -Condition ([string]$report.targetVmName -eq $effectiveTargetVmName) -Message "Report VM '$($report.targetVmName)' does not match execution VM '$effectiveTargetVmName'."
    Assert-E2ECondition -Condition ([string]$report.baselineName -eq $effectiveBaselineName) -Message "Report baseline '$($report.baselineName)' does not match planned baseline '$effectiveBaselineName'."
    Assert-E2ECondition -Condition ([string]$report.machineDefinitionPath -eq $effectiveMachineDefinitionPath) -Message 'Report VMX/base-disk identity does not match the planned runbook.'
    Assert-E2ECondition -Condition ([string]$report.qemuDiskFormat -eq $effectiveQemuDiskFormat) -Message 'Report QEMU disk format does not match the planned runbook.'
    Assert-E2ECondition -Condition ([string]$report.sample.sha256 -ceq $sampleSha256) -Message 'Report sample SHA-256 does not match the bytes hashed before planning.'
    Assert-E2ECondition -Condition ([long]$report.sample.sizeBytes -eq [long]$sampleFile.Length) -Message 'Report sample size does not match the file inspected before planning.'
    $sampleAfterExecution = Get-Item -LiteralPath $resolvedSamplePath -ErrorAction Stop
    $sampleSha256AfterExecution = Get-E2EFileSha256 -Path $resolvedSamplePath
    Assert-E2ECondition -Condition ($sampleSha256AfterExecution -ceq $sampleSha256) -Message 'Sample bytes changed between planning and completed report generation.'
    Assert-E2ECondition -Condition ([long]$sampleAfterExecution.Length -eq [long]$sampleFile.Length) -Message 'Sample size changed between planning and completed report generation.'

    $backgroundState = if ($null -ne $background) { [string]$background.state } else { $null }
    $generatedAt = [DateTimeOffset]::Now
    $summary = [ordered]@{
        generatedAtUtc       = $generatedAt.UtcDateTime.ToString('O')
        generatedAtLocal     = $generatedAt.ToString('O')
        gitCommit            = $gitProvenance.commit
        gitCommitSource      = $gitProvenance.commitSource
        gitDirty             = $gitProvenance.dirty
        gitChangedFileCount  = $gitProvenance.changedFileCount
        gitProvenancePath    = $gitProvenance.provenancePath
        gitDiagnostic        = $gitProvenance.diagnostic
        mode                 = $modeName
        executionTransport   = $ExecutionTransport
        backgroundState      = $backgroundState
        baseUrl              = $BaseUrl
        health               = $health
        jobId                = $jobId
        provider             = $effectiveProvider
        readinessProvider    = [string]$providerReadiness.virtualization.provider
        readinessReadOnly    = [bool]$providerReadiness.readOnly
        runtimeRoot          = [string]$providerReadiness.paths.runtimeRoot.path
        hostAccelerationReady = $providerReadiness.hostVirtualization.hardwareAccelerationReady
        requiredWindowsFeature = [string]$providerReadiness.hostVirtualization.requiredWindowsFeature
        requiredWindowsFeatureReady = $providerReadiness.hostVirtualization.requiredWindowsFeatureReady
        providerManagementAvailable = [bool]$providerReadiness.virtualization.managementAvailable
        providerQuerySucceeded = [bool]$providerReadiness.virtualization.querySucceeded
        providerVmExists     = [bool]$providerReadiness.virtualization.vmExists
        providerBaselineExists = [bool]$providerReadiness.virtualization.baselineExists
        providerGuestTransportSecure = [bool]$providerReadiness.virtualization.guestTransportSecure
        providerGuestEndpointReady = [bool]$providerReadiness.virtualization.guestEndpointReady
        providerDiagnosticCode = [string]$providerReadiness.virtualization.diagnosticCode
        providerDiagnosticMessage = [string]$providerReadiness.virtualization.diagnosticMessage
        providerResourceOverrideUsed = $hasProviderResourceOverride
        logicalVmName        = $effectiveLogicalVmName
        targetVmName         = $effectiveTargetVmName
        baselineName         = $effectiveBaselineName
        machineDefinitionPath = $effectiveMachineDefinitionPath
        qemuDiskFormat       = $effectiveQemuDiskFormat
        samplePath           = $resolvedSamplePath
        sampleSha256         = $sampleSha256
        sampleSizeBytes      = [long]$sampleFile.Length
        requestedDurationSeconds = $DurationSeconds
        success              = [bool]$execution.success
        guestImportSucceeded = [bool]$payload.guestImportSucceeded
        guestImportSkipped   = [bool]$payload.guestImportSkipped
        guestImportFailed    = [bool]$payload.guestImportFailed
        guestImportMessage   = [string]$payload.guestImportMessage
        executedSteps        = [int]$execution.executedSteps
        totalSteps           = [int]$execution.totalSteps
        durationSeconds      = [Math]::Round($duration.TotalSeconds, 3)
        liveTotalEvents      = [int]$liveSnapshot.totalEvents
        liveSources          = @($liveSnapshot.sources)
        reportJsonPath       = $jsonReportPath
        reportHtmlPath       = [string]$updatedJob.htmlReportPath
        reportZhHtmlPath     = [string]$updatedJob.htmlReportZhPath
        reportEnHtmlPath     = [string]$updatedJob.htmlReportEnPath
        guestEventsPath      = [string]$updatedJob.guestEventsPath
        runbookExecutionPath = [string]$updatedJob.runbookExecutionResultPath
        reportEndpointChecks = @($reportChecks)
        cSignToolUsed        = $false
    }

    $summary | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $SummaryPath -Encoding UTF8
    Write-E2EStep "Summary written: $SummaryPath"
    Write-Output ([pscustomobject]$summary)
}
finally {
    if ($StopWebUIOnExit) {
        Stop-E2EStartedWebUI
    }
}
