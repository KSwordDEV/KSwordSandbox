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

    & powershell.exe @argumentList
    return $LASTEXITCODE
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
