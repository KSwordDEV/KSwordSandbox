param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
)

$ErrorActionPreference = 'Stop'
$required = @(
    'src\KSword.Sandbox.Abstractions',
    'src\KSword.Sandbox.Core',
    'src\KSword.Sandbox.Web',
    'guest\KSword.Sandbox.Agent',
    'driver\KSword.Sandbox.Driver',
    'tests\KSword.Sandbox.SmokeTests',
    'docs'
)

foreach ($relative in $required) {
    $path = Join-Path $RepositoryRoot $relative
    if (-not (Test-Path $path)) {
        throw "Required framework path is missing: $path"
    }
}

Write-Host "Project framework paths are present under $RepositoryRoot"
