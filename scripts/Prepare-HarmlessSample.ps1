<#
.SYNOPSIS
Publishes the harmless E2E sample outside the repository.

.DESCRIPTION
Inputs are the repository root, sample project path, and output/build roots.
Processing runs `dotnet publish` with redirected output/intermediate roots so
no `bin`, `obj`, `.exe`, `.dll`, or `.deps.json` files are generated under the
source tree. The script writes a small manifest next to the published sample.
Return behavior is exit code 0 when the executable and manifest are produced,
or a non-zero exit code when safety checks or publishing fail.
#>
[CmdletBinding()]
param(
    # Repository root that contains KSwordSandbox.sln and tools/.
    [string]$RepositoryRoot = '',

    # Harmless sample project. Defaults under tools/KSword.Sandbox.HarmlessSample.
    [string]$ProjectPath = '',

    # Publish output root. Must stay outside the repository.
    [string]$OutputRoot = 'D:\Temp\KSwordSandbox\samples\KSword.Sandbox.HarmlessSample',

    # Build output root. Must stay outside the repository.
    [string]$BuildRoot = 'D:\Temp\KSwordSandbox\build\KSword.Sandbox.HarmlessSample',

    # Intermediate output root. Must stay outside the repository.
    [string]$IntermediateRoot = 'D:\Temp\KSwordSandbox\obj\KSword.Sandbox.HarmlessSample',

    # Build configuration for the sample executable.
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    # Runtime identifier used by dotnet publish.
    [string]$RuntimeIdentifier = 'win-x64',

    # Publish as self-contained instead of framework-dependent.
    [switch]$SelfContained,

    # Removes an existing publish output directory before publishing.
    [switch]$Clean
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

# Write-SamplePrepStep prints a stable progress prefix.
# Inputs: one short operator-facing message.
# Processing: writes the message to stdout.
# Return behavior: no return value.
function Write-SamplePrepStep {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "[prepare-harmless-sample] $Message"
}

# Resolve-DefaultRepositoryRoot finds the repository root from this script path.
# Inputs are PowerShell script location variables.
# Processing falls back from PSScriptRoot to MyInvocation for Windows PowerShell.
# Return behavior is a full candidate repository path.
function Resolve-DefaultRepositoryRoot {
    if (-not [string]::IsNullOrWhiteSpace($script:PSScriptRoot)) {
        return (Split-Path -Parent $script:PSScriptRoot)
    }

    $scriptPath = $MyInvocation.MyCommand.Path
    if (-not [string]::IsNullOrWhiteSpace($scriptPath)) {
        return (Split-Path -Parent (Split-Path -Parent $scriptPath))
    }

    return (Get-Location).Path
}

# Get-NormalizedFullPath resolves a path without requiring it to exist.
# Inputs: any local path string.
# Processing: expands relative syntax through System.IO.Path.
# Return behavior: normalized full path.
function Get-NormalizedFullPath {
    param([Parameter(Mandatory)][string]$Path)
    return [System.IO.Path]::GetFullPath($Path)
}

# Test-PathUnderRoot checks whether a path is the root or a descendant.
# Inputs: candidate path and root path.
# Processing: normalizes both paths and compares as Windows paths.
# Return behavior: true when the candidate is under the root.
function Test-PathUnderRoot {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root
    )

    $fullPath = (Get-NormalizedFullPath -Path $Path).TrimEnd('\', '/')
    $fullRoot = (Get-NormalizedFullPath -Path $Root).TrimEnd('\', '/')

    if ([StringComparer]::OrdinalIgnoreCase.Equals($fullPath, $fullRoot)) {
        return $true
    }

    $rootWithSeparator = $fullRoot + [System.IO.Path]::DirectorySeparatorChar
    return $fullPath.StartsWith($rootWithSeparator, [StringComparison]::OrdinalIgnoreCase)
}

# Assert-OutsideRepository rejects output paths that would place binaries in git.
# Inputs: output path, repository root, and friendly label.
# Processing throws when the output path is inside the repository.
# Return behavior: no return value when safe.
function Assert-OutsideRepository {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$RepositoryRoot,
        [Parameter(Mandatory)][string]$Name
    )

    if (Test-PathUnderRoot -Path $Path -Root $RepositoryRoot) {
        throw "$Name must stay outside the repository. Refusing path: $Path"
    }
}

# Add-TrailingDirectorySeparator normalizes MSBuild directory properties.
# Inputs: a path string.
# Processing: appends a trailing separator when absent.
# Return behavior: path string ending in slash or backslash.
function Add-TrailingDirectorySeparator {
    param([Parameter(Mandatory)][string]$Path)

    if ($Path.EndsWith('\') -or $Path.EndsWith('/')) {
        return $Path
    }

    return $Path + [System.IO.Path]::DirectorySeparatorChar
}

# Invoke-DotNetPublish runs dotnet publish and throws on failure.
# Inputs: project path and publish arguments.
# Processing: starts a child process through dotnet CLI.
# Return behavior: no return value when publish succeeds.
function Invoke-DotNetPublish {
    param(
        [Parameter(Mandatory)][string]$Project,
        [Parameter(Mandatory)][string]$PublishDirectory,
        [Parameter(Mandatory)][string]$BaseOutputDirectory,
        [Parameter(Mandatory)][string]$BaseIntermediateDirectory
    )

    $selfContainedValue = if ($SelfContained) { 'true' } else { 'false' }
    $arguments = @(
        'publish',
        $Project,
        '--configuration',
        $Configuration,
        '--runtime',
        $RuntimeIdentifier,
        '--self-contained',
        $selfContainedValue,
        '--output',
        $PublishDirectory,
        "/p:BaseOutputPath=$(Add-TrailingDirectorySeparator -Path $BaseOutputDirectory)",
        "/p:BaseIntermediateOutputPath=$(Add-TrailingDirectorySeparator -Path $BaseIntermediateDirectory)"
    )

    Write-SamplePrepStep "dotnet $($arguments -join ' ')"
    & dotnet @arguments
    $exitCode = if ($LASTEXITCODE -is [int]) { $LASTEXITCODE } else { 0 }
    if ($exitCode -ne 0) {
        throw "dotnet publish failed with exit code $exitCode."
    }
}

# Write-SampleManifest writes an operator-readable manifest beside the sample.
# Inputs: resolved paths and the published executable path.
# Processing: serializes JSON metadata.
# Return behavior: manifest path.
function Write-SampleManifest {
    param(
        [Parameter(Mandatory)][string]$ManifestPath,
        [Parameter(Mandatory)][string]$ExecutablePath,
        [Parameter(Mandatory)][string]$ResolvedProjectPath
    )

    $manifest = [ordered]@{
        sampleContractVersion = 1
        generatedAtUtc        = [DateTimeOffset]::UtcNow.ToString('O')
        repositoryRoot        = (Get-NormalizedFullPath -Path $RepositoryRoot)
        projectPath           = $ResolvedProjectPath
        configuration         = $Configuration
        runtimeIdentifier     = $RuntimeIdentifier
        selfContained         = [bool]$SelfContained
        outputRoot            = (Get-NormalizedFullPath -Path $OutputRoot)
        buildRoot             = (Get-NormalizedFullPath -Path $BuildRoot)
        intermediateRoot      = (Get-NormalizedFullPath -Path $IntermediateRoot)
        executablePath        = $ExecutablePath
        expectedBehaviors     = @(
            'write-marker-file',
            'launch-short-lived-cmd-child',
            'optional-loopback-and-test-net-tcp-probes'
        )
        safetyNotes           = @(
            'No arbitrary external network target is accepted.',
            'Published files are runtime artifacts and must stay out of git.',
            'Use this executable for Hyper-V E2E smoke only.'
        )
    }

    $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ManifestPath -Encoding UTF8
    return $ManifestPath
}

try {
    if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
        $RepositoryRoot = Resolve-DefaultRepositoryRoot
    }

    $RepositoryRoot = Get-NormalizedFullPath -Path $RepositoryRoot
    if ([string]::IsNullOrWhiteSpace($ProjectPath)) {
        $ProjectPath = Join-Path $RepositoryRoot 'tools\KSword.Sandbox.HarmlessSample\KSword.Sandbox.HarmlessSample.csproj'
    }

    $resolvedProject = Get-NormalizedFullPath -Path $ProjectPath
    $resolvedOutput = Get-NormalizedFullPath -Path $OutputRoot
    $resolvedBuild = Get-NormalizedFullPath -Path $BuildRoot
    $resolvedIntermediate = Get-NormalizedFullPath -Path $IntermediateRoot

    if (-not (Test-Path -LiteralPath (Join-Path $RepositoryRoot 'KSwordSandbox.sln') -PathType Leaf)) {
        throw "Repository root does not contain KSwordSandbox.sln: $RepositoryRoot"
    }

    if (-not (Test-Path -LiteralPath $resolvedProject -PathType Leaf)) {
        throw "Harmless sample project was not found: $resolvedProject"
    }

    Assert-OutsideRepository -Path $resolvedOutput -RepositoryRoot $RepositoryRoot -Name 'OutputRoot'
    Assert-OutsideRepository -Path $resolvedBuild -RepositoryRoot $RepositoryRoot -Name 'BuildRoot'
    Assert-OutsideRepository -Path $resolvedIntermediate -RepositoryRoot $RepositoryRoot -Name 'IntermediateRoot'

    if ($Clean) {
        foreach ($pathToClean in @($resolvedOutput, $resolvedBuild, $resolvedIntermediate)) {
            if (Test-Path -LiteralPath $pathToClean) {
                Write-SamplePrepStep "Cleaning $pathToClean"
                Remove-Item -LiteralPath $pathToClean -Recurse -Force
            }
        }
    }

    New-Item -ItemType Directory -Path $resolvedOutput, $resolvedBuild, $resolvedIntermediate -Force | Out-Null

    Invoke-DotNetPublish `
        -Project $resolvedProject `
        -PublishDirectory $resolvedOutput `
        -BaseOutputDirectory $resolvedBuild `
        -BaseIntermediateDirectory $resolvedIntermediate

    $sampleExe = Join-Path $resolvedOutput 'KSword.Sandbox.HarmlessSample.exe'
    if (-not (Test-Path -LiteralPath $sampleExe -PathType Leaf)) {
        throw "Published harmless sample executable was not produced: $sampleExe"
    }

    $manifestPath = Join-Path $resolvedOutput 'harmless-sample-manifest.json'
    $manifestPath = Write-SampleManifest `
        -ManifestPath $manifestPath `
        -ExecutablePath $sampleExe `
        -ResolvedProjectPath $resolvedProject

    Write-Host ''
    Write-Host 'PASS: harmless sample prepared.'
    Write-Host "  Project:      $resolvedProject"
    Write-Host "  Output root:  $resolvedOutput"
    Write-Host "  Executable:   $sampleExe"
    Write-Host "  Manifest:     $manifestPath"
    Write-Host "  Plan check:   pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-HyperVE2E.ps1 -SamplePath '$sampleExe' -PlanOnly"
    Write-Host '  Git hygiene:  published files are outside the repository; do not commit copied binaries.'
    exit 0
}
catch {
    Write-Host ''
    Write-Error "FAIL: harmless sample preparation failed. $($_.Exception.Message)"
    exit 1
}
