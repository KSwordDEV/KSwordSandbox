<#
.SYNOPSIS
Builds the solution and runs the console smoke tests.

.DESCRIPTION
Inputs are optional configuration values. Processing restores/builds the .NET
solution under the Any CPU platform and executes KSword.Sandbox.SmokeTests.
Native x64 driver and collector projects are verified separately through
Invoke-NativeBuild.ps1. Optional scenario filters are passed through to the
console smoke harness for focused gates such as the VM-free synthetic E2E
contract. The script returns the dotnet exit code.
#>
[CmdletBinding()]
param(
    [string]$Configuration = 'Debug',
    [string]$MSBuildPath = 'D:\Software\VS\MSBuild\Current\Bin\MSBuild.exe',
    [string[]]$Scenario = @(),
    [string[]]$ScenarioPrefix = @(),
    [switch]$ListScenarios,
    [switch]$NoBuild
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$solution = Join-Path $repoRoot 'KSwordSandbox.sln'
$smokeProject = Join-Path $repoRoot 'tests/KSword.Sandbox.SmokeTests/KSword.Sandbox.SmokeTests.csproj'

if (-not $NoBuild.IsPresent) {
    Write-Host "Building $solution"
    if (Test-Path -LiteralPath $MSBuildPath -PathType Leaf) {
        & $MSBuildPath $solution /m:1 /p:Configuration=$Configuration "/p:Platform=Any CPU" /v:m
    }
    else {
        Write-Warning "MSBuild was not found at '$MSBuildPath'; falling back to dotnet build."
        dotnet build $solution --configuration $Configuration --nologo /p:UseSharedCompilation=false
    }

    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}

Write-Host "Running smoke tests"
$smokeArguments = @(
    'run',
    '--project',
    $smokeProject,
    '--configuration',
    $Configuration,
    '--no-build',
    '--'
)

if ($ListScenarios.IsPresent) {
    $smokeArguments += '--list-scenarios'
}

foreach ($scenarioId in $Scenario) {
    if (-not [string]::IsNullOrWhiteSpace($scenarioId)) {
        $smokeArguments += @('--scenario', $scenarioId)
    }
}

foreach ($prefix in $ScenarioPrefix) {
    if (-not [string]::IsNullOrWhiteSpace($prefix)) {
        $smokeArguments += @('--scenario-prefix', $prefix)
    }
}

dotnet @smokeArguments
exit $LASTEXITCODE
