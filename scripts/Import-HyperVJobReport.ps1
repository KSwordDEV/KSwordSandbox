<#
.SYNOPSIS
Imports a collected Hyper-V live job and regenerates report artifacts.

.DESCRIPTION
This wrapper is for CLI/live Hyper-V runs that produced guest\<jobId>\events.json
and driver-events.jsonl without going through the WebUI in-memory job service.
It does not start or mutate VMs. It only calls the local JobTool to classify
collected events and write report.json/report.html/report.zh.html/report.en.html
plus report-rebuild-diagnostics.json for operator recovery.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$JobId,
    [Parameter(Mandatory)][string]$SamplePath,
    [string]$EventsPath = '',
    [string]$RunbookExecutionPath = '',
    [string]$ConfigPath = 'D:\Temp\KSwordSandbox\config\sandbox.local.json',
    [string]$RepoRoot = '',
    [string]$RuntimeRoot = '',
    [int]$DurationSeconds = 120,
    [switch]$Json
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
    $RepoRoot = Split-Path -Parent $PSScriptRoot
}

$jobIdNoDash = $JobId -replace '-', ''
if ([string]::IsNullOrWhiteSpace($RuntimeRoot)) {
    $RuntimeRoot = 'D:\Temp\KSwordSandbox'
}

$jobRoot = Join-Path (Join-Path $RuntimeRoot 'jobs') $jobIdNoDash
if ([string]::IsNullOrWhiteSpace($EventsPath)) {
    $EventsPath = Join-Path $jobRoot ("guest\{0}\events.json" -f $jobIdNoDash)
}
if ([string]::IsNullOrWhiteSpace($RunbookExecutionPath)) {
    $RunbookExecutionPath = Join-Path $jobRoot 'runbook-execution.json'
}

function ConvertTo-ImportSkeletonDataValue {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return ''
    }

    $text = [string]$Value
    if ($text.Length -gt 1000) {
        return $text.Substring(0, 1000) + '...'
    }

    return $text
}

function Write-ImportGuestOutputSkeleton {
    param(
        [Parameter(Mandatory)][string]$JobId,
        [Parameter(Mandatory)][string]$JobRoot,
        [Parameter(Mandatory)][string]$EventsPath,
        [Parameter(Mandatory)][string]$RunbookExecutionPath,
        [Parameter(Mandatory)][string]$Message
    )

    $guestOutputDirectory = Split-Path -Parent $EventsPath
    if ([string]::IsNullOrWhiteSpace($guestOutputDirectory)) {
        $guestOutputDirectory = Join-Path (Join-Path $JobRoot 'guest') ($JobId -replace '-', '')
        $EventsPath = Join-Path $guestOutputDirectory 'events.json'
    }

    New-Item -ItemType Directory -Path $guestOutputDirectory -Force | Out-Null
    $agentPidPath = Join-Path $guestOutputDirectory 'agent.pid'
    $agentExitPath = Join-Path $guestOutputDirectory 'agent.exit'
    $agentStdoutPath = Join-Path $guestOutputDirectory 'agent.stdout.log'
    $agentStderrPath = Join-Path $guestOutputDirectory 'agent.stderr.log'
    $metadataPath = Join-Path $guestOutputDirectory 'guest-output-skeleton.json'

    if (-not (Test-Path -LiteralPath $agentPidPath -PathType Leaf)) {
        Set-Content -LiteralPath $agentPidPath -Value '0' -Encoding ASCII
    }
    if (-not (Test-Path -LiteralPath $agentExitPath -PathType Leaf)) {
        Set-Content -LiteralPath $agentExitPath -Value '-1' -Encoding ASCII
    }
    if (-not (Test-Path -LiteralPath $agentStdoutPath -PathType Leaf)) {
        Set-Content -LiteralPath $agentStdoutPath -Value '' -Encoding UTF8
    }
    if (-not (Test-Path -LiteralPath $agentStderrPath -PathType Leaf)) {
        Set-Content -LiteralPath $agentStderrPath -Value (ConvertTo-ImportSkeletonDataValue $Message) -Encoding UTF8
    }

    $now = [DateTimeOffset]::UtcNow
    $events = @(
        [ordered]@{
            eventType   = 'hyperv.e2e.failure_skeleton'
            timestamp   = $now.ToString('O')
            source      = 'host'
            processName = 'Import-HyperVJobReport.ps1'
            processId   = $PID
            path        = $JobRoot
            commandLine = 'Import wrapper generated a guest-output skeleton because events.json was missing.'
            data        = [ordered]@{
                jobId                = ConvertTo-ImportSkeletonDataValue $JobId
                jobRoot              = ConvertTo-ImportSkeletonDataValue $JobRoot
                failureReason        = ConvertTo-ImportSkeletonDataValue $Message
                runbookExecutionPath = ConvertTo-ImportSkeletonDataValue $RunbookExecutionPath
                generatedBy          = 'Import-HyperVJobReport.ps1'
                importable           = 'True'
                skeleton             = 'True'
                secretValuePrinted   = 'False'
            }
        }
    )
    ConvertTo-Json -InputObject @($events) -Depth 8 | Set-Content -LiteralPath $EventsPath -Encoding UTF8

    $metadata = [ordered]@{
        contractVersion    = 1
        kind               = 'KSwordSandbox.GuestOutputSkeleton'
        generatedAtUtc     = $now.ToString('O')
        generatedBy        = 'Import-HyperVJobReport.ps1'
        importable         = $true
        jobId              = $JobId
        jobRoot            = $JobRoot
        reason             = $Message
        secretValuePrinted = $false
        paths              = [ordered]@{
            guestOutputDirectory = $guestOutputDirectory
            eventsJsonPath       = $EventsPath
            agentPidPath         = $agentPidPath
            agentExitPath        = $agentExitPath
            agentStdoutPath      = $agentStdoutPath
            agentStderrPath      = $agentStderrPath
            runbookExecutionPath = $RunbookExecutionPath
        }
        note               = '该 skeleton 仅用于导入失败诊断，不代表 Guest Agent 已成功运行。'
    }
    $metadata | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $metadataPath -Encoding UTF8
    if (-not $Json) {
        Write-Host "[ksword-import] 已生成可导入 guest-output skeleton: $EventsPath"
    }
}

if (-not (Test-Path -LiteralPath $EventsPath -PathType Leaf)) {
    if (Test-Path -LiteralPath $RunbookExecutionPath -PathType Leaf) {
        Write-Warning "中文提示：未找到 events.json：$EventsPath；将根据 runbook-execution.json 生成可导入 guest-output skeleton。"
        Write-ImportGuestOutputSkeleton `
            -JobId $JobId `
            -JobRoot $jobRoot `
            -EventsPath $EventsPath `
            -RunbookExecutionPath $RunbookExecutionPath `
            -Message "events.json missing; generated importable failure skeleton from runbook-execution.json."
    }
    else {
        throw "错误：未找到 events.json：$EventsPath，且 runbook-execution.json 也不存在：$RunbookExecutionPath。下一步：先运行 Invoke-HyperVE2E.ps1 生成失败 skeleton，或传入有效 -EventsPath。"
    }
}

$project = Join-Path $RepoRoot 'tools\KSword.Sandbox.JobTool\KSword.Sandbox.JobTool.csproj'
$args = @(
    'run', '--project', $project, '--', 'import-live',
    '--repo-root', $RepoRoot,
    '--config', $ConfigPath,
    '--runtime-root', $RuntimeRoot,
    '--job-id', $JobId,
    '--sample', $SamplePath,
    '--events', $EventsPath,
    '--duration', ([string]$DurationSeconds)
)
if (Test-Path -LiteralPath $RunbookExecutionPath -PathType Leaf) {
    $args += @('--runbook-execution', $RunbookExecutionPath)
}
if ($Json) {
    $args += '--json'
}

if (-not $Json) {
    Write-Host "[ksword-import] Importing guest events from $EventsPath"
}
& dotnet @args
if ($LASTEXITCODE -ne 0) {
    $diagnosticsPath = Join-Path $jobRoot 'report-rebuild-diagnostics.json'
    $diagnosticsHint = if (Test-Path -LiteralPath $diagnosticsPath -PathType Leaf) { " Diagnostics: $diagnosticsPath" } else { '' }
    throw "KSword.Sandbox.JobTool failed with exit code $LASTEXITCODE.$diagnosticsHint"
}

if (-not $Json) {
    $diagnosticsPath = Join-Path $jobRoot 'report-rebuild-diagnostics.json'
    if (Test-Path -LiteralPath $diagnosticsPath -PathType Leaf) {
        Write-Host "[ksword-import] Report rebuild diagnostics: $diagnosticsPath"
    }
}
