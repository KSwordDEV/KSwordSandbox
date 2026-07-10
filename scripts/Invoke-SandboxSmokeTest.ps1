<#
.SYNOPSIS
Builds the solution and runs the console smoke tests.

.DESCRIPTION
Inputs are optional configuration values. Processing restores/builds the .NET
solution under the Any CPU platform and executes KSword.Sandbox.SmokeTests.
Native x64 driver and collector projects are verified separately through
Invoke-NativeBuild.ps1. The script returns the dotnet exit code.
#>
[CmdletBinding()]
param(
    [string]$Configuration = 'Debug',
    [string]$MSBuildPath = 'D:\Software\VS\MSBuild\Current\Bin\MSBuild.exe'
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$solution = Join-Path $repoRoot 'KSwordSandbox.sln'

Write-Host "Building $solution"
& $MSBuildPath $solution /m:1 /p:Configuration=$Configuration "/p:Platform=Any CPU" /v:m
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Write-Host "Running smoke tests"
dotnet run --project (Join-Path $repoRoot 'tests/KSword.Sandbox.SmokeTests/KSword.Sandbox.SmokeTests.csproj') --configuration $Configuration --no-build
exit $LASTEXITCODE
