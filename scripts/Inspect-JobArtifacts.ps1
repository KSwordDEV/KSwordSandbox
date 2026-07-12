<#
.SYNOPSIS
Inspects host-visible artifacts for an existing KSword Sandbox job without rerunning a VM.

.DESCRIPTION
This operator wrapper calls KSword.Sandbox.JobTool inspect-artifacts. By default
it builds an in-memory artifact index and prints a bilingual summary. Use
-WriteIndex only when you explicitly want to refresh artifact-index.json on disk.
#>
[CmdletBinding()]
param(
    [string]$JobId = '',
    [string]$JobRoot = '',
    [string]$ConfigPath = '',
    [string]$RepoRoot = '',
    [string]$RuntimeRoot = '',
    [ValidateRange(1, 1000)][int]$Limit = 50,
    [switch]$WriteIndex,
    [switch]$IncludeMetadata,
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
    'inspect-artifacts',
    '--repo-root', $RepoRoot,
    '--limit', ([string]$Limit)
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
if ($WriteIndex) {
    $toolArgs += '--write-index'
}
if ($IncludeMetadata) {
    $toolArgs += '--include-metadata'
}
if ($Json) {
    $toolArgs += '--json'
}

if (-not $Json) {
    Write-Host '[ksword-artifacts] Inspecting existing artifacts only. / 仅检查现有产物。'
    Write-Host '[ksword-artifacts] VM action: none. / VM 操作：无。'
    Write-Host "[ksword-artifacts] JobTool target: $($jobToolTarget.Kind)"
}
$exitCode = Invoke-KSwordPortableTool -Target $jobToolTarget -Arguments $toolArgs -NoBuild:$NoBuild
if ($exitCode -ne 0) {
    throw "KSword.Sandbox.JobTool inspect-artifacts failed with exit code $exitCode."
}
