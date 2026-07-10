<#
.SYNOPSIS
Runs the KSwordSandbox source, smoke, native, and repository policy gates.

.DESCRIPTION
Inputs are optional switches that let an operator skip expensive native builds
or readiness probes. Processing executes the same gates used by the Codex
workers without pushing or mutating Hyper-V by default. The script returns zero
only when every selected gate succeeds.
#>
[CmdletBinding()]
param(
    [string]$Configuration = 'Debug',
    [string]$Platform = 'x64',
    [string]$MSBuildPath = 'D:\Software\VS\MSBuild\Current\Bin\MSBuild.exe',
    [switch]$SkipDotNet,
    [switch]$SkipNative,
    [switch]$SkipRepositoryPolicy,
    [switch]$SkipReadiness,
    [switch]$SkipLocalPipelineSmoke,
    [switch]$StagedPolicyOnly
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$solution = Join-Path $repoRoot 'KSwordSandbox.sln'
$results = New-Object System.Collections.Generic.List[object]

# Invoke-Step executes one validation command and records the result.
# Inputs are a step name and script block; processing captures duration and
# process exceptions; the function returns no value but throws at the end when a
# step fails.
function Invoke-Step {
    param(
        [string]$Name,
        [scriptblock]$Script
    )

    Write-Host "==> $Name" -ForegroundColor Cyan
    $started = Get-Date
    $success = $false
    $exitCode = 0
    $message = ''

    try {
        & $Script
        $exitCode = if ($LASTEXITCODE -is [int]) { $LASTEXITCODE } else { 0 }
        if ($exitCode -ne 0) {
            throw "$Name failed with exit code $exitCode"
        }

        $success = $true
        $message = 'passed'
    }
    catch {
        $message = $_.Exception.Message
        $exitCode = if ($exitCode -ne 0) { $exitCode } else { 1 }
        Write-Error $message
    }
    finally {
        $results.Add([pscustomobject]@{
            name = $Name
            success = $success
            exitCode = $exitCode
            durationSeconds = [math]::Round(((Get-Date) - $started).TotalSeconds, 3)
            message = $message
        })
    }
}

# Invoke-PowerShellFile runs a PowerShell script in a child process.
# Inputs are a script path and optional argument list; processing isolates
# scripts that call exit; the function returns the child process exit code.
function Invoke-PowerShellFile {
    param(
        [string]$Path,
        [string[]]$Arguments = @()
    )

    $argumentList = @(
        '-NoProfile',
        '-ExecutionPolicy',
        'Bypass',
        '-File',
        $Path
    ) + $Arguments

    $output = @(& powershell.exe @argumentList 2>&1)
    $exitCode = if ($LASTEXITCODE -is [int]) { $LASTEXITCODE } else { 0 }
    foreach ($line in $output) {
        Write-Host $line
    }

    return $exitCode
}

Push-Location $repoRoot
try {
    if (-not $SkipDotNet) {
        Invoke-Step -Name 'dotnet solution build' -Script {
            dotnet build $solution --nologo /p:UseSharedCompilation=false /p:Configuration=$Configuration
        }

        Invoke-Step -Name 'smoke tests' -Script {
            dotnet run --project (Join-Path $repoRoot 'tests/KSword.Sandbox.SmokeTests/KSword.Sandbox.SmokeTests.csproj') --configuration $Configuration --no-build
        }
    }

    Invoke-Step -Name 'live telemetry framework contract' -Script {
        $exitCode = Invoke-PowerShellFile -Path (Join-Path $repoRoot 'scripts/Test-LiveTelemetryFramework.ps1') -Arguments @('-ContractOnly', '-RequireImplementedStream')
        if ($exitCode -ne 0) {
            throw "Live telemetry framework contract failed with exit code $exitCode"
        }

        $global:LASTEXITCODE = 0
    }

    if (-not $SkipLocalPipelineSmoke) {
        Invoke-Step -Name 'local WebUI/API pipeline smoke' -Script {
            $localSmokeArguments = @('-Configuration', $Configuration)
            if (-not $SkipDotNet) {
                $localSmokeArguments += '-NoBuild'
            }

            $exitCode = Invoke-PowerShellFile -Path (Join-Path $repoRoot 'scripts/Invoke-LocalPipelineSmoke.ps1') -Arguments $localSmokeArguments
            if ($exitCode -ne 0) {
                throw "Local WebUI/API pipeline smoke failed with exit code $exitCode"
            }

            $global:LASTEXITCODE = 0
        }
    }

    Invoke-Step -Name 'Hyper-V E2E PlanOnly contract' -Script {
        $contractRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('ksword-hyperv-e2e-planonly-{0}' -f ([guid]::NewGuid().ToString('N')))
        $planPath = Join-Path $contractRoot 'hyperv-e2e-plan.json'
        $configPath = Join-Path $contractRoot 'sandbox.planonly.json'
        try {
            New-Item -ItemType Directory -Path $contractRoot -Force | Out-Null
            $config = Get-Content -LiteralPath (Join-Path $repoRoot 'config/sandbox.example.json') -Raw | ConvertFrom-Json
            $config.paths.runtimeRoot = Join-Path $contractRoot 'runtime'
            $config.paths.guestPayloadRoot = Join-Path $contractRoot 'payload\guest-tools'
            $config | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $configPath -Encoding UTF8

            $exitCode = Invoke-PowerShellFile -Path (Join-Path $repoRoot 'scripts/Invoke-HyperVE2E.ps1') -Arguments @(
                '-RepoRoot',
                $repoRoot,
                '-ConfigPath',
                $configPath,
                '-PlanOnly',
                '-PlanPath',
                $planPath,
                '-WhatIf'
            )
            if ($exitCode -ne 0) {
                throw "Hyper-V E2E PlanOnly contract failed with exit code $exitCode"
            }

            if (-not (Test-Path -LiteralPath $planPath -PathType Leaf)) {
                throw "Hyper-V E2E PlanOnly contract did not write a review plan: $planPath"
            }

            $plan = Get-Content -LiteralPath $planPath -Raw | ConvertFrom-Json
            if ([bool]$plan.willMutateVm) {
                throw 'Hyper-V E2E PlanOnly contract unexpectedly indicates VM mutation.'
            }

            if (-not [bool]$plan.safeDefault) {
                throw 'Hyper-V E2E PlanOnly contract did not preserve safeDefault=true.'
            }

            if (-not [bool]$plan.safety.noVmMutationWhenPlanOnly) {
                throw 'Hyper-V E2E PlanOnly contract did not preserve noVmMutationWhenPlanOnly=true.'
            }

            if (@($plan.steps).Count -eq 0) {
                throw 'Hyper-V E2E PlanOnly contract produced no reviewable steps.'
            }

            $global:LASTEXITCODE = 0
        }
        finally {
            Remove-Item -LiteralPath $contractRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    if (-not $SkipNative) {
        Invoke-Step -Name 'native x64 build' -Script {
            & (Join-Path $repoRoot 'scripts/Invoke-NativeBuild.ps1') -Project $solution -Configuration $Configuration -Platform $Platform -Verbosity minimal -MSBuildPath $MSBuildPath
        }
    }

    if (-not $SkipReadiness) {
        Invoke-Step -Name 'Hyper-V readiness contract' -Script {
            $exitCode = Invoke-PowerShellFile -Path (Join-Path $repoRoot 'scripts/Test-HyperVReadiness.ps1')
            if ($exitCode -ne 0) {
                Write-Host 'Hyper-V readiness reported environment gaps; this is non-fatal in non-admin/source validation mode.' -ForegroundColor Yellow
                $global:LASTEXITCODE = 0
            }
        }

        Invoke-Step -Name 'R0 readiness contract' -Script {
            $exitCode = Invoke-PowerShellFile -Path (Join-Path $repoRoot 'scripts/Test-R0Readiness.ps1') -Arguments @('-SkipTestSigningRequirement')
            if ($exitCode -ne 0) {
                Write-Host 'R0 readiness reported environment gaps; this is non-fatal before signed driver deployment.' -ForegroundColor Yellow
                $global:LASTEXITCODE = 0
            }
        }
    }

    if (-not $SkipRepositoryPolicy) {
        Invoke-Step -Name 'repository policy' -Script {
            $policy = Join-Path $repoRoot 'scripts/Test-RepositoryPolicy.ps1'
            if ($StagedPolicyOnly) {
                & $policy -StagedOnly
            }
            else {
                & $policy
            }
        }
    }
}
finally {
    Pop-Location
}

$failed = @($results | Where-Object { -not $_.success })
$summaryPath = Join-Path $env:TEMP ('ksword-full-validation-{0}.json' -f ([guid]::NewGuid().ToString('N')))
$results | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $summaryPath -Encoding UTF8
Write-Host "Validation summary: $summaryPath"

if ($failed.Count -gt 0) {
    Write-Error ("Validation failed: {0}" -f (($failed | ForEach-Object { $_.name }) -join ', '))
    exit 1
}

Write-Host 'Full validation passed.'
exit 0
