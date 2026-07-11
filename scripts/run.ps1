<#
.SYNOPSIS
Compatibility entry point for starting KSwordSandbox after installation.

.DESCRIPTION
This script lives under scripts/ for packaging layouts that expose operational
helpers from one folder. It forwards parameters to the repository-root run.ps1
in the same PowerShell process so WebUI startup, one-shot Plan/Analyze modes,
environment import, payload checks, -WhatIf behavior, and exit-code behavior
remain identical to the primary root runtime wrapper.

Default behavior is still a single WebUI launch path. Live Hyper-V execution is
never implicit; it requires an explicit -Live option passed through to the root
runtime wrapper.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [ValidateSet('WebUI', 'StartWebUI', 'Analyze', 'Plan', 'Status', 'CheckEnvironment')]
    [string]$Mode = 'WebUI',

    [string]$SamplePath = '',

    [ValidateSet('', 'Notepad', 'Sample', 'HarmlessSample')]
    [string]$SamplePreset = '',

    [int]$DurationSeconds = 120,

    [string]$Url = 'http://127.0.0.1:18080',

    [string]$ConfigPath = '',

    [string]$RuntimeRoot = '',

    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    [int]$GuestReadyTimeoutSeconds = 180,

    [int]$ExecutionTimeoutSeconds = 240,

    [switch]$Live,

    [switch]$PlanOnly,

    [switch]$NoBuild,

    [switch]$SkipPayloadPreparation,

    [switch]$ForcePayloadPreparation,

    [switch]$OpenBrowser,

    [switch]$StrictUrl,

    [switch]$RequirePayloadForWebUI
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Get-RepositoryRootFromScriptFolder {
    if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        return (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).ProviderPath
    }

    return (Get-Location).ProviderPath
}

$repositoryRoot = Get-RepositoryRootFromScriptFolder
$rootRunner = Join-Path $repositoryRoot 'run.ps1'

if (-not (Test-Path -LiteralPath $rootRunner -PathType Leaf)) {
    throw "错误：找不到仓库根目录 run.ps1：$rootRunner。下一步：请从完整仓库/发行包运行，或使用根目录 .\run.ps1。"
}

& $rootRunner @PSBoundParameters
