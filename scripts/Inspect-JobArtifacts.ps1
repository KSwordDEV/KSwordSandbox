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
    'inspect-artifacts',
    '--repo-root', $RepoRoot,
    '--limit', ([string]$Limit)
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
if ($WriteIndex) {
    $dotnetArgs += '--write-index'
}
if ($IncludeMetadata) {
    $dotnetArgs += '--include-metadata'
}
if ($Json) {
    $dotnetArgs += '--json'
}

if (-not $Json) {
    Write-Host '[ksword-artifacts] Inspecting existing artifacts only. / 仅检查现有产物。'
    Write-Host '[ksword-artifacts] VM action: none. / VM 操作：无。'
}
& dotnet @dotnetArgs
if ($LASTEXITCODE -ne 0) {
    throw "KSword.Sandbox.JobTool inspect-artifacts failed with exit code $LASTEXITCODE."
}
