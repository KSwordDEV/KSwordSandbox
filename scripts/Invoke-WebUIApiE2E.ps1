<#
.SYNOPSIS
Runs an API-level KSwordSandbox WebUI end-to-end validation.

.DESCRIPTION
Inputs are a WebUI URL, sample path, optional config path, and safe/live mode
switches. Processing optionally starts the WebUI through run.ps1, waits for
/health, creates a job through /api/jobs/plan, executes the runbook through
/api/jobs/{jobId}/runbook/execute, verifies live-event and report endpoints,
and writes a JSON summary under D:\Temp by default.

The default mode is safe: it does not start, restore, or mutate a VM. Real
Hyper-V execution requires -Live. This script never calls CSignTool or the
legacy KSword signing wrapper.
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

    [switch]$StartWebUI,

    [switch]$StopWebUIOnExit,

    [switch]$SkipPayloadPreparation,

    [switch]$UseMockCollector,

    [string]$DisplayName = 'KSword WebUI/API E2E validation',

    [string]$GoldenVmName,

    [string]$GoldenSnapshotName,

    [string]$GuestUserName,

    [string]$GuestWorkingDirectory,

    [string]$GuestPayloadRoot,

    [string]$DotNetPath = 'dotnet',

    [string]$PowerShellPath = 'powershell.exe',

    [ValidateRange(5, 300)]
    [int]$StartupTimeoutSeconds = 90,

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
    $modeName = if ($Live) { 'Live' } else { 'DryRun' }
    Write-E2EStep "Mode: $modeName"
    Write-E2EStep "Sample: $resolvedSamplePath"

    $startedHost = $null
    if ($StartWebUI) {
        $startedHost = Start-E2EWebUI -Url $BaseUrl -SandboxConfigPath $ConfigPath -SkipPayload:$SkipPayloadPreparation
    }

    $health = Wait-E2EWebUI -Url $BaseUrl -TimeoutSeconds $StartupTimeoutSeconds -StartedHost $startedHost

    $planBody = [ordered]@{
        samplePath      = $resolvedSamplePath
        displayName     = $DisplayName
        durationSeconds = $DurationSeconds
        dryRun          = (-not [bool]$Live)
    }

    if ($UseMockCollector) {
        $planBody.useMockCollector = $true
    }

    if (-not [string]::IsNullOrWhiteSpace($GoldenVmName)) {
        $planBody.goldenVmName = $GoldenVmName
    }

    if (-not [string]::IsNullOrWhiteSpace($GoldenSnapshotName)) {
        $planBody.goldenSnapshotName = $GoldenSnapshotName
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
    Write-E2EStep "Planned job: $jobId"

    $executeBody = [ordered]@{
        live               = [bool]$Live
        stepTimeoutSeconds = $StepTimeoutSeconds
        importGuestEvents  = $true
    }

    Write-E2EStep "Executing runbook through /api/jobs/$jobId/runbook/execute"
    $startedAt = [DateTimeOffset]::UtcNow
    $payload = Invoke-E2EJsonPost -Uri "$BaseUrl/api/jobs/$jobId/runbook/execute" -Body $executeBody -TimeoutSeconds ([Math]::Max($StepTimeoutSeconds + 120, 300))
    $duration = [DateTimeOffset]::UtcNow - $startedAt

    $execution = $payload.execution
    $updatedJob = $payload.job
    Assert-E2ECondition -Condition ($null -ne $execution) -Message 'Execute response did not include execution.'
    Assert-E2ECondition -Condition ($null -ne $updatedJob) -Message 'Execute response did not include updated job.'
    Assert-E2ECondition -Condition ([bool]$execution.success) -Message "Runbook execution failed. failedStepIndex=$($execution.failedStepIndex) message=$($execution.message)"
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

    $summary = [ordered]@{
        generatedAtUtc       = [DateTimeOffset]::UtcNow.ToString('O')
        mode                 = $modeName
        baseUrl              = $BaseUrl
        health               = $health
        jobId                = $jobId
        samplePath           = $resolvedSamplePath
        success              = [bool]$execution.success
        guestImportSucceeded = [bool]$payload.guestImportSucceeded
        guestImportMessage   = [string]$payload.guestImportMessage
        executedSteps        = [int]$execution.executedSteps
        totalSteps           = [int]$execution.totalSteps
        durationSeconds      = [Math]::Round($duration.TotalSeconds, 3)
        liveTotalEvents      = [int]$liveSnapshot.totalEvents
        liveSources          = @($liveSnapshot.sources)
        reportJsonPath       = [string]$updatedJob.jsonReportPath
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
