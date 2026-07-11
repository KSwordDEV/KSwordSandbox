<#
.SYNOPSIS
Regenerates report artifacts for an existing KSword Sandbox job without rerunning a VM.

.DESCRIPTION
This operator wrapper calls KSword.Sandbox.JobTool rebuild-report. It reuses
existing job artifacts such as events.json, driver-events.jsonl, packet captures,
and runbook-execution.json. It does not start, restore, stop, or otherwise mutate
Hyper-V VMs.
#>
[CmdletBinding()]
param(
    [string]$JobId = '',
    [string]$JobRoot = '',
    [string]$SamplePath = '',
    [string]$EventsPath = '',
    [string]$RunbookExecutionPath = '',
    [string]$ConfigPath = '',
    [string]$RepoRoot = '',
    [string]$RuntimeRoot = '',
    [int]$DurationSeconds = 120,
    [switch]$NoBuild,
    [switch]$Json
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
    $RepoRoot = Split-Path -Parent $PSScriptRoot
}

if ([string]::IsNullOrWhiteSpace($JobId) -and [string]::IsNullOrWhiteSpace($JobRoot)) {
    throw 'Missing -JobId or -JobRoot. / 缺少 -JobId 或 -JobRoot。'
}

$project = Join-Path $RepoRoot 'tools\KSword.Sandbox.JobTool\KSword.Sandbox.JobTool.csproj'
if (-not (Test-Path -LiteralPath $project -PathType Leaf)) {
    throw "JobTool project not found / 未找到 JobTool 项目: $project"
}

$dotnetArgs = @('run')
if ($NoBuild) {
    $dotnetArgs += '--no-build'
}

$dotnetArgs += @(
    '--project', $project, '--',
    'rebuild-report',
    '--repo-root', $RepoRoot,
    '--duration', ([string]$DurationSeconds)
)

if (-not [string]::IsNullOrWhiteSpace($ConfigPath)) {
    $dotnetArgs += @('--config', $ConfigPath)
}
if (-not [string]::IsNullOrWhiteSpace($RuntimeRoot)) {
    $dotnetArgs += @('--runtime-root', $RuntimeRoot)
}
if (-not [string]::IsNullOrWhiteSpace($JobId)) {
    $dotnetArgs += @('--job-id', $JobId)
}
if (-not [string]::IsNullOrWhiteSpace($JobRoot)) {
    $dotnetArgs += @('--job-root', $JobRoot)
}
if (-not [string]::IsNullOrWhiteSpace($SamplePath)) {
    $dotnetArgs += @('--sample', $SamplePath)
}
if (-not [string]::IsNullOrWhiteSpace($EventsPath)) {
    $dotnetArgs += @('--events', $EventsPath)
}
if (-not [string]::IsNullOrWhiteSpace($RunbookExecutionPath)) {
    $dotnetArgs += @('--runbook-execution', $RunbookExecutionPath)
}
if ($Json) {
    $dotnetArgs += '--json'
}

if (-not $Json) {
    Write-Host '[ksword-rebuild] Rebuilding report from existing artifacts only. / 仅从现有产物重建报告。'
    Write-Host '[ksword-rebuild] VM action: none. / VM 操作：无。'
}
& dotnet @dotnetArgs
if ($LASTEXITCODE -ne 0) {
    throw "KSword.Sandbox.JobTool rebuild-report failed with exit code $LASTEXITCODE."
}
