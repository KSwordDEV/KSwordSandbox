<#
.SYNOPSIS
Imports a collected Hyper-V live job and regenerates report artifacts.

.DESCRIPTION
This wrapper is for CLI/live Hyper-V runs that produced guest\<jobId>\events.json
and driver-events.jsonl without going through the WebUI in-memory job service.
It does not start or mutate VMs. It only calls the local JobTool to classify
collected events and write report.json/report.html/report.zh.html/report.en.html.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$JobId,
    [Parameter(Mandatory)][string]$SamplePath,
    [string]$EventsPath = '',
    [string]$RunbookExecutionPath = '',
    [string]$ConfigPath = 'D:\Temp\KSwordSandbox\config\sandbox.local.json',
    [string]$RepoRoot = '',
    [int]$DurationSeconds = 120
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
    $RepoRoot = Split-Path -Parent $PSScriptRoot
}

$jobIdNoDash = $JobId -replace '-', ''
$jobRoot = Join-Path 'D:\Temp\KSwordSandbox\jobs' $jobIdNoDash
if ([string]::IsNullOrWhiteSpace($EventsPath)) {
    $EventsPath = Join-Path $jobRoot ("guest\{0}\events.json" -f $jobIdNoDash)
}
if ([string]::IsNullOrWhiteSpace($RunbookExecutionPath)) {
    $RunbookExecutionPath = Join-Path $jobRoot 'runbook-execution.json'
}

$project = Join-Path $RepoRoot 'tools\KSword.Sandbox.JobTool\KSword.Sandbox.JobTool.csproj'
$args = @(
    'run', '--project', $project, '--', 'import-live',
    '--repo-root', $RepoRoot,
    '--config', $ConfigPath,
    '--job-id', $JobId,
    '--sample', $SamplePath,
    '--events', $EventsPath,
    '--duration', ([string]$DurationSeconds)
)
if (Test-Path -LiteralPath $RunbookExecutionPath -PathType Leaf) {
    $args += @('--runbook-execution', $RunbookExecutionPath)
}

Write-Host "[ksword-import] Importing guest events from $EventsPath"
& dotnet @args
if ($LASTEXITCODE -ne 0) {
    throw "KSword.Sandbox.JobTool failed with exit code $LASTEXITCODE."
}
