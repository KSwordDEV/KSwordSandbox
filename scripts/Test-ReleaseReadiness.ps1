<#
.SYNOPSIS
Runs lightweight release-readiness gates for KSwordSandbox.

.DESCRIPTION
This script is intentionally source/release oriented. It does not start,
restore, stop, or mutate Hyper-V VMs; it does not sign drivers; it does not
call CSignTool.exe; and it does not run heavyweight smoke suites by default.

Inputs are the repository root plus opt-in switches for build and source-package
staging. Processing checks git hygiene, repository policy, package manifest
shape, PowerShell syntax for operational scripts, and accidental CSignTool
references in normal release paths. Return behavior is exit code 0 when all
required checks pass, otherwise exit code 1. Warnings are printed but do not
fail unless -TreatWarningsAsErrors is supplied.
#>
[CmdletBinding()]
param(
    [string]$RepositoryRoot,

    [string]$OutputRoot = 'D:\Temp\KSwordSandbox\release-readiness',

    [switch]$AllowDirtySource,

    [switch]$StageSourcePackage,

    [switch]$IncludeBuild,

    [switch]$TreatWarningsAsErrors
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$scriptRoot = if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
    $PSScriptRoot
}
elseif (-not [string]::IsNullOrWhiteSpace($PSCommandPath)) {
    Split-Path -Parent $PSCommandPath
}
else {
    Split-Path -Parent $MyInvocation.MyCommand.Path
}

if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = Join-Path $scriptRoot '..'
}

$RepositoryRoot = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$OutputRoot = [System.IO.Path]::GetFullPath($OutputRoot)
$script:Results = New-Object System.Collections.Generic.List[object]

function Add-ReleaseCheckResult {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][ValidateSet('Passed', 'Warning', 'Failed', 'Skipped')]
        [string]$Status,
        [string]$Message = '',
        [string[]]$Remediation = @(),
        [hashtable]$Details = @{}
    )

    [void]$script:Results.Add([pscustomobject][ordered]@{
            id          = $Id
            title       = $Title
            status      = $Status
            message     = $Message
            remediation = @($Remediation)
            details     = $Details
        })
}

function Invoke-ReleaseCommand {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$Arguments = @(),
        [string[]]$Remediation = @()
    )

    $stdoutPath = Join-Path $OutputRoot "$Id.stdout.log"
    $stderrPath = Join-Path $OutputRoot "$Id.stderr.log"
    $process = Start-Process `
        -FilePath $FilePath `
        -ArgumentList $Arguments `
        -WorkingDirectory $RepositoryRoot `
        -NoNewWindow `
        -Wait `
        -PassThru `
        -RedirectStandardOutput $stdoutPath `
        -RedirectStandardError $stderrPath

    if ($process.ExitCode -eq 0) {
        Add-ReleaseCheckResult `
            -Id $Id `
            -Title $Title `
            -Status Passed `
            -Message "Command completed successfully. Logs: $stdoutPath ; $stderrPath" `
            -Details @{ exitCode = $process.ExitCode; stdout = $stdoutPath; stderr = $stderrPath }
        return
    }

    Add-ReleaseCheckResult `
        -Id $Id `
        -Title $Title `
        -Status Failed `
        -Message "Command failed with exit code $($process.ExitCode). Logs: $stdoutPath ; $stderrPath" `
        -Remediation $Remediation `
        -Details @{ exitCode = $process.ExitCode; stdout = $stdoutPath; stderr = $stderrPath }
}

function Test-GitAvailable {
    $git = Get-Command git -ErrorAction SilentlyContinue
    if ($null -eq $git) {
        Add-ReleaseCheckResult `
            -Id 'git-available' `
            -Title 'Git available / Git 可用' `
            -Status Failed `
            -Message 'git was not found in PATH.' `
            -Remediation @('Install Git or run release readiness from a shell where git is available.')
        return $false
    }

    Add-ReleaseCheckResult `
        -Id 'git-available' `
        -Title 'Git available / Git 可用' `
        -Status Passed `
        -Message "git found at $($git.Source)."
    return $true
}

function Test-GitClean {
    $status = @(git -C $RepositoryRoot status --porcelain)
    if ($status.Count -eq 0) {
        Add-ReleaseCheckResult `
            -Id 'git-clean' `
            -Title 'Clean worktree / 工作树干净' `
            -Status Passed `
            -Message 'Worktree has no uncommitted tracked/untracked candidate changes.'
        return
    }

    $preview = @($status | Select-Object -First 20)
    $message = "Worktree has $($status.Count) changed/untracked item(s)."
    if ($AllowDirtySource) {
        Add-ReleaseCheckResult `
            -Id 'git-clean' `
            -Title 'Clean worktree / 工作树干净' `
            -Status Warning `
            -Message "$message AllowDirtySource is set." `
            -Remediation @('Do not cut a public source package from dirty source unless release notes explicitly document it.') `
            -Details @{ preview = $preview }
        return
    }

    Add-ReleaseCheckResult `
        -Id 'git-clean' `
        -Title 'Clean worktree / 工作树干净' `
        -Status Failed `
        -Message $message `
        -Remediation @('Commit or stash intended source changes before release packaging, or rerun with -AllowDirtySource for a documented internal draft.') `
        -Details @{ preview = $preview }
}

function Test-PowerShellScriptSyntax {
    $scripts = @(
        'run.ps1',
        'install.ps1',
        'scripts/run.ps1',
        'scripts/install.ps1',
        'scripts/package-portable.ps1',
        'scripts/Test-RepositoryPolicy.ps1',
        'scripts/Invoke-HyperVE2E.ps1',
        'scripts/Start-SandboxHyperVJob.ps1',
        'scripts/Collect-GuestOutputs.ps1',
        'scripts/Import-HyperVJobReport.ps1',
        'scripts/Test-HyperVReadiness.ps1',
        'scripts/Test-ReleaseReadiness.ps1'
    )

    $errors = New-Object System.Collections.Generic.List[object]
    foreach ($relative in $scripts) {
        $path = Join-Path $RepositoryRoot $relative
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            [void]$errors.Add([pscustomobject]@{ script = $relative; error = 'missing' })
            continue
        }

        $tokens = $null
        $parseErrors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$parseErrors) | Out-Null
        foreach ($parseError in @($parseErrors)) {
            [void]$errors.Add([pscustomobject]@{
                    script  = $relative
                    message = $parseError.Message
                    extent  = [string]$parseError.Extent
                })
        }
    }

    if ($errors.Count -eq 0) {
        Add-ReleaseCheckResult `
            -Id 'powershell-syntax' `
            -Title 'PowerShell syntax / PowerShell 语法' `
            -Status Passed `
            -Message "Parsed $($scripts.Count) operational PowerShell script(s)."
        return
    }

    Add-ReleaseCheckResult `
        -Id 'powershell-syntax' `
        -Title 'PowerShell syntax / PowerShell 语法' `
        -Status Failed `
        -Message "PowerShell parser found $($errors.Count) issue(s)." `
        -Remediation @('Fix parser errors before packaging or tagging a release.') `
        -Details @{ errors = @($errors.ToArray()) }
}

function Test-PackageManifests {
    $manifestPaths = @(
        'packaging/source-package.manifest.json',
        'packaging/runtime-package.manifest.json'
    )

    $issues = New-Object System.Collections.Generic.List[string]
    foreach ($relative in $manifestPaths) {
        $path = Join-Path $RepositoryRoot $relative
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            [void]$issues.Add("Missing manifest: $relative")
            continue
        }

        try {
            $manifest = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -ErrorAction Stop
            if ([int]$manifest.manifestVersion -lt 1) {
                [void]$issues.Add("manifestVersion is invalid: $relative")
            }

            if ([string]::IsNullOrWhiteSpace([string]$manifest.packageKind)) {
                [void]$issues.Add("packageKind is missing: $relative")
            }

            $raw = Get-Content -LiteralPath $path -Raw
            foreach ($requiredExclusion in @('*.vhdx', '*.sys', '*.pdb', '*.pcap', '*.dmp', 'sandbox.local.json', 'guest-password.dpapi')) {
                if ($raw.IndexOf($requiredExclusion, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
                    [void]$issues.Add("Manifest does not mention required exclusion '$requiredExclusion': $relative")
                }
            }
        }
        catch {
            [void]$issues.Add("Invalid JSON in ${relative}: $($_.Exception.Message)")
        }
    }

    if ($issues.Count -eq 0) {
        Add-ReleaseCheckResult `
            -Id 'package-manifests' `
            -Title 'Package manifests / 打包清单' `
            -Status Passed `
            -Message 'Source and runtime manifests parsed and include high-risk exclusions.'
        return
    }

    Add-ReleaseCheckResult `
        -Id 'package-manifests' `
        -Title 'Package manifests / 打包清单' `
        -Status Failed `
        -Message "Package manifest checks found $($issues.Count) issue(s)." `
        -Remediation @('Update packaging manifests before release packaging.') `
        -Details @{ issues = @($issues.ToArray()) }
}

function Test-CSignToolNotInReleasePath {
    $matches = @(Get-ChildItem -LiteralPath $RepositoryRoot -Recurse -File -Filter '*.ps1' |
        Where-Object {
            $_.FullName -notmatch '\\\.git\\' -and
            $_.FullName -notmatch '\\bin\\|\\obj\\|\\x64\\' -and
            $_.Name -ne 'Test-ReleaseReadiness.ps1' -and
            $_.Name -notlike 'Sign-SandboxDriverWithKswordCSignTool.ps1'
        } |
        Select-String -Pattern 'CSignTool\.exe|Sign-SandboxDriverWithKswordCSignTool' -SimpleMatch -ErrorAction SilentlyContinue)

    if ($matches.Count -eq 0) {
        Add-ReleaseCheckResult `
            -Id 'no-csigntool-release-path' `
            -Title 'No CSignTool in release path / 发布链路不调用 CSignTool' `
            -Status Passed `
            -Message 'Operational PowerShell scripts do not call CSignTool.exe or the legacy KSword signing wrapper.'
        return
    }

    Add-ReleaseCheckResult `
        -Id 'no-csigntool-release-path' `
        -Title 'No CSignTool in release path / 发布链路不调用 CSignTool' `
        -Status Failed `
        -Message "Found $($matches.Count) CSignTool reference(s) in normal release scripts." `
        -Remediation @('Keep CSignTool usage out of normal install/run/package/readiness paths; use ordinary signtool/test-signing docs only when explicitly requested.') `
        -Details @{ matches = @($matches | Select-Object Path, LineNumber, Line) }
}

function Invoke-RepositoryPolicy {
    $scriptPath = Join-Path $RepositoryRoot 'scripts\Test-RepositoryPolicy.ps1'
    Invoke-ReleaseCommand `
        -Id 'repository-policy' `
        -Title 'Repository policy / 仓库策略' `
        -FilePath 'powershell.exe' `
        -Arguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $scriptPath, '-RepositoryRoot', $RepositoryRoot) `
        -Remediation @('Remove generated binaries, samples, VM artifacts, reports, captures, signing material, or secrets from the repository candidate set.')
}

function Invoke-SourcePackageStage {
    if (-not $StageSourcePackage) {
        Add-ReleaseCheckResult `
            -Id 'source-package-stage' `
            -Title 'Source package stage / 源码包预暂存' `
            -Status Skipped `
            -Message 'Skipped by default. Rerun with -StageSourcePackage for a local source-package dry run.'
        return
    }

    $packageScript = Join-Path $RepositoryRoot 'scripts\package-portable.ps1'
    $arguments = @(
        '-NoProfile',
        '-ExecutionPolicy',
        'Bypass',
        '-File',
        $packageScript,
        '-PackageKind',
        'source',
        '-RepositoryRoot',
        $RepositoryRoot,
        '-OutputRoot',
        (Join-Path $OutputRoot 'packages'),
        '-StageOnly',
        '-Force'
    )

    if ($AllowDirtySource) {
        $arguments += '-AllowDirtySource'
    }

    Invoke-ReleaseCommand `
        -Id 'source-package-stage' `
        -Title 'Source package stage / 源码包预暂存' `
        -FilePath 'powershell.exe' `
        -Arguments $arguments `
        -Remediation @('Inspect package-manifest.generated.json and remove any unintended runtime/build artifacts.')
}

function Invoke-LightBuild {
    if (-not $IncludeBuild) {
        Add-ReleaseCheckResult `
            -Id 'light-build' `
            -Title 'Light build / 轻量构建' `
            -Status Skipped `
            -Message 'Skipped by default to keep release-readiness cheap. Rerun with -IncludeBuild before final tag or handoff.'
        return
    }

    $buildOutput = Join-Path $OutputRoot 'verify\web'
    Invoke-ReleaseCommand `
        -Id 'light-build' `
        -Title 'Light build / 轻量构建' `
        -FilePath 'dotnet' `
        -Arguments @('build', (Join-Path $RepositoryRoot 'src\KSword.Sandbox.Web\KSword.Sandbox.Web.csproj'), '-c', 'Verify', '-p:UseSharedCompilation=false', "-p:OutDir=$buildOutput\") `
        -Remediation @('Fix compile errors before release handoff.')
}

if (-not (Test-Path -LiteralPath $OutputRoot -PathType Container)) {
    [void](New-Item -ItemType Directory -Force -Path $OutputRoot)
}

$gitAvailable = Test-GitAvailable
if ($gitAvailable) {
    Test-GitClean
}

Test-PackageManifests
Test-PowerShellScriptSyntax
Test-CSignToolNotInReleasePath
Invoke-RepositoryPolicy
Invoke-SourcePackageStage
Invoke-LightBuild

$failed = @($script:Results | Where-Object { $_.status -eq 'Failed' })
$warnings = @($script:Results | Where-Object { $_.status -eq 'Warning' })
$exitCode = if ($failed.Count -gt 0 -or ($TreatWarningsAsErrors -and $warnings.Count -gt 0)) { 1 } else { 0 }

$summary = [pscustomobject][ordered]@{
    contractVersion       = 1
    kind                  = 'KSwordSandbox.ReleaseReadiness'
    generatedAtUtc        = [DateTimeOffset]::UtcNow.ToString('O')
    repositoryRoot        = $RepositoryRoot
    outputRoot            = $OutputRoot
    exitCode              = $exitCode
    failedCount           = $failed.Count
    warningCount          = $warnings.Count
    skippedCount          = @($script:Results | Where-Object { $_.status -eq 'Skipped' }).Count
    passedCount           = @($script:Results | Where-Object { $_.status -eq 'Passed' }).Count
    allowDirtySource      = [bool]$AllowDirtySource
    stageSourcePackage    = [bool]$StageSourcePackage
    includeBuild          = [bool]$IncludeBuild
    noVmMutation          = $true
    noDriverSigning       = $true
    csignToolNotCalled    = $true
    results               = @($script:Results.ToArray())
}

$summaryPath = Join-Path $OutputRoot 'release-readiness.json'
$summary | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $summaryPath -Encoding UTF8

foreach ($result in $script:Results) {
    $prefix = switch ($result.status) {
        'Passed' { '[pass]' }
        'Warning' { '[warn]' }
        'Failed' { '[fail]' }
        default { '[skip]' }
    }

    Write-Host "$prefix $($result.id): $($result.message)"
}

Write-Host "Release readiness summary written: $summaryPath"
exit $exitCode
