<#
.SYNOPSIS
Runs fast synthetic quality gates without starting Hyper-V or loading a driver.

.DESCRIPTION
Inputs are an optional repository root, build configuration, and smoke scenario
IDs. Processing builds the smoke-test executable, then runs only the selected
offline scenarios through the smoke-test scenario filter. The script returns a
non-zero exit code if build or scenario execution fails.
#>
[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path,
    [string]$Configuration = 'Debug',
    [string[]]$Scenarios = @(
        'report.r0collector-self-noise.contract',
        'artifacts.manifest.contract',
        'rules.schema-collection-health.guard'
    ),
    [switch]$NoDependencies,
    [switch]$NoBuild
)

$ErrorActionPreference = 'Stop'

$projectPath = Join-Path $RepositoryRoot 'tests\KSword.Sandbox.SmokeTests\KSword.Sandbox.SmokeTests.csproj'
if (-not (Test-Path -LiteralPath $projectPath -PathType Leaf)) {
    throw "Smoke test project is missing: $projectPath"
}

Push-Location $RepositoryRoot
try {
    if (-not $NoBuild.IsPresent) {
        $buildArgs = @(
            'build',
            $projectPath,
            '--configuration',
            $Configuration,
            '--nologo'
        )
        if ($NoDependencies.IsPresent) {
            $buildArgs += '--no-dependencies'
        }

        & dotnet @buildArgs
        if ($LASTEXITCODE -ne 0) {
            exit $LASTEXITCODE
        }
    }

    $runArgs = @(
        'run',
        '--project',
        $projectPath,
        '--configuration',
        $Configuration,
        '--no-build',
        '--'
    )

    foreach ($scenario in $Scenarios) {
        if ([string]::IsNullOrWhiteSpace($scenario)) {
            continue
        }

        $runArgs += @('--scenario', $scenario)
    }

    & dotnet @runArgs
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }

    Write-Host "Fast quality gates passed: $($Scenarios -join ', ')"
}
finally {
    Pop-Location
}
