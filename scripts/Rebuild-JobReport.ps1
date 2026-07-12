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

$resolver = Join-Path $PSScriptRoot 'Resolve-PortableTool.ps1'
if (-not (Test-Path -LiteralPath $resolver -PathType Leaf)) {
    throw "错误：找不到 portable tool resolver：$resolver。下一步：确认 scripts\Resolve-PortableTool.ps1 已随源码/便携包提供。"
}
. $resolver

if ([string]::IsNullOrWhiteSpace($JobId) -and [string]::IsNullOrWhiteSpace($JobRoot)) {
    throw 'Missing -JobId or -JobRoot. / 缺少 -JobId 或 -JobRoot。'
}

$jobToolTarget = Resolve-KSwordPortableTool -RepoRoot $RepoRoot -Tool JobTool -ThrowIfMissing
$toolArgs = @(
    'rebuild-report',
    '--repo-root', $RepoRoot,
    '--duration', ([string]$DurationSeconds)
)

if (-not [string]::IsNullOrWhiteSpace($ConfigPath)) {
    $toolArgs += @('--config', $ConfigPath)
}
if (-not [string]::IsNullOrWhiteSpace($RuntimeRoot)) {
    $toolArgs += @('--runtime-root', $RuntimeRoot)
}
if (-not [string]::IsNullOrWhiteSpace($JobId)) {
    $toolArgs += @('--job-id', $JobId)
}
if (-not [string]::IsNullOrWhiteSpace($JobRoot)) {
    $toolArgs += @('--job-root', $JobRoot)
}
if (-not [string]::IsNullOrWhiteSpace($SamplePath)) {
    $toolArgs += @('--sample', $SamplePath)
}
if (-not [string]::IsNullOrWhiteSpace($EventsPath)) {
    $toolArgs += @('--events', $EventsPath)
}
if (-not [string]::IsNullOrWhiteSpace($RunbookExecutionPath)) {
    $toolArgs += @('--runbook-execution', $RunbookExecutionPath)
}
if ($Json) {
    $toolArgs += '--json'
}

if (-not $Json) {
    Write-Host '[ksword-rebuild] Rebuilding report from existing artifacts only. / 仅从现有产物重建报告。'
    Write-Host '[ksword-rebuild] VM action: none. / VM 操作：无。'
    Write-Host "[ksword-rebuild] JobTool target: $($jobToolTarget.Kind)"
}
$exitCode = Invoke-KSwordPortableTool -Target $jobToolTarget -Arguments $toolArgs -NoBuild:$NoBuild
if ($exitCode -ne 0) {
    throw "KSword.Sandbox.JobTool rebuild-report failed with exit code $exitCode."
}
