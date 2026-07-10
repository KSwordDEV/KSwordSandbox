<#
.SYNOPSIS
Builds the solution and runs the console smoke tests.

.DESCRIPTION
Inputs are optional configuration values. Processing restores/builds the .NET
solution and executes KSword.Sandbox.SmokeTests. The script returns the dotnet
exit code.
#>
[CmdletBinding()]
param(
    [string]$Configuration = 'Debug'
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$solution = Join-Path $repoRoot 'KSwordSandbox.sln'

Write-Host "Building $solution"
dotnet build $solution --configuration $Configuration
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Write-Host "Running smoke tests"
dotnet run --project (Join-Path $repoRoot 'tests/KSword.Sandbox.SmokeTests/KSword.Sandbox.SmokeTests.csproj') --configuration $Configuration --no-build
exit $LASTEXITCODE
