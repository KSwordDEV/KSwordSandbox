<#
.SYNOPSIS
Builds guest-side tools and stages them outside the repository.

.DESCRIPTION
Inputs are local build paths, an MSBuild path, and output directories.
Processing publishes the .NET Guest Agent with MSBuild, using ArtifactsPath so
project-reference bin/obj output stays separated, builds the native R0Collector
with MSBuild, and copies the runtime files into
D:\Temp\KSwordSandbox\payload\guest-tools by default. The script returns exit
code 0 when staging succeeds and a non-zero exit code when a build or copy step
fails. It never writes payload binaries into git-tracked folders unless the
operator overrides safety checks by editing the script.
#>
[CmdletBinding()]
param(
    # Repository root that contains KSwordSandbox.sln, guest/, and scripts/.
    [string]$RepoRoot = '',

    # Visual Studio MSBuild used for both SDK-style .NET publish and native VC++ build.
    [string]$MSBuildPath = 'D:\Software\VS\MSBuild\Current\Bin\MSBuild.exe',

    # Final host-side payload directory copied into or from the Hyper-V guest.
    [string]$PayloadRoot = 'D:\Temp\KSwordSandbox\payload\guest-tools',

    # Temporary build/publish root outside the repository.
    [string]$BuildRoot = 'D:\Temp\KSwordSandbox\payload-build',

    # Build configuration for both Guest Agent and R0Collector.
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    # Native platform for R0Collector.
    [ValidateSet('x64')]
    [string]$Platform = 'x64',

    # Runtime identifier used by the SDK-style Guest Agent publish target.
    [string]$RuntimeIdentifier = 'win-x64',

    # Guest root path that receives payload folders during Hyper-V staging.
    [string]$GuestWorkingDirectory = 'C:\KSwordSandbox',

    # Expected Guest Agent executable name in the staged agent folder.
    [string]$GuestAgentExecutableName = 'KSword.Sandbox.Agent.exe',

    # Expected R0Collector executable name in the staged r0collector folder.
    [string]$R0CollectorExecutableName = 'KSword.Sandbox.R0Collector.exe',

    # Includes .pdb files in the payload when local debugging needs symbols.
    [switch]$IncludeSymbols,

    # Publishes the Guest Agent as self-contained. This is the default for
    # Hyper-V live runs because a clean Win10 guest usually does not have the
    # exact .NET runtime installed.
    [switch]$SelfContained,

    # Opts into a smaller framework-dependent Guest Agent payload. Use only when
    # the golden VM is known to contain the matching .NET runtime.
    [switch]$FrameworkDependent
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

# Write-PrepStep prints a stable progress prefix.
# Inputs: one short operator-facing message.
# Processing: writes the message to stdout with a fixed tag.
# Return behavior: no return value.
function Write-PrepStep {
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )

    Write-Host "[prepare-guest-payload] $Message"
}

# ConvertTo-ProcessArgument quotes one command-line argument for CreateProcess.
# Inputs: an unquoted argument string.
# Processing: preserves simple tokens and quotes tokens with whitespace or
# embedded quotes while keeping trailing backslashes valid.
# Return behavior: the safely escaped argument string.
function ConvertTo-ProcessArgument {
    param(
        [Parameter(Mandatory)]
        [string]$Argument
    )

    if ($Argument -notmatch '[\s"]') {
        return $Argument
    }

    $escaped = $Argument -replace '(\\*)"', '$1$1\"'
    $escaped = $escaped -replace '(\\+)$', '$1$1'
    return '"' + $escaped + '"'
}

# Add-TrailingDirectorySeparator normalizes MSBuild directory properties.
# Inputs: a directory path string.
# Processing: trims quotes and appends the platform directory separator only
# when one is not already present.
# Return behavior: the directory path with a trailing slash or backslash.
function Add-TrailingDirectorySeparator {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if ($Path.EndsWith('\') -or $Path.EndsWith('/')) {
        return $Path
    }

    return $Path + [System.IO.Path]::DirectorySeparatorChar
}

# Get-NormalizedFullPath resolves a path string without requiring it to exist.
# Inputs: a path that may be relative.
# Processing: expands it through System.IO.Path.GetFullPath.
# Return behavior: a full local filesystem path.
function Get-NormalizedFullPath {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    return [System.IO.Path]::GetFullPath($Path)
}

# Get-RelativeRepositoryPath returns a stable slash-separated path used in
# source fingerprints. Inputs are the repository root and an existing file path;
# processing removes the root prefix without requiring .NET Core-only APIs; the
# returned string is stable across Windows PowerShell and PowerShell 7.
function Get-RelativeRepositoryPath {
    param(
        [Parameter(Mandatory)]
        [string]$RepositoryRoot,

        [Parameter(Mandatory)]
        [string]$Path
    )

    $fullRoot = (Get-NormalizedFullPath -Path $RepositoryRoot).TrimEnd('\', '/') + '\'
    $fullPath = Get-NormalizedFullPath -Path $Path
    if ($fullPath.StartsWith($fullRoot, [StringComparison]::OrdinalIgnoreCase)) {
        return $fullPath.Substring($fullRoot.Length).Replace('\', '/')
    }

    return $fullPath.Replace('\', '/')
}

# Get-GuestPayloadSourceFiles lists source inputs that affect the staged Guest
# Agent/R0Collector payload. Inputs are the repository root; processing excludes
# generated build folders; return behavior is a sorted file list.
function Get-GuestPayloadSourceFiles {
    param(
        [Parameter(Mandatory)]
        [string]$RepositoryRoot
    )

    $sourceRoots = @(
        'guest\KSword.Sandbox.Agent',
        'guest\KSword.Sandbox.R0Collector',
        'src\KSword.Sandbox.Abstractions'
    )
    $extensions = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($extension in @('.cs', '.csproj', '.props', '.targets', '.cpp', '.c', '.h', '.hpp', '.vcxproj', '.filters', '.json')) {
        [void]$extensions.Add($extension)
    }

    $files = New-Object System.Collections.Generic.List[System.IO.FileInfo]
    foreach ($relativeRoot in $sourceRoots) {
        $candidateRoot = Join-Path $RepositoryRoot $relativeRoot
        if (-not (Test-Path -LiteralPath $candidateRoot -PathType Container)) {
            continue
        }

        foreach ($file in Get-ChildItem -LiteralPath $candidateRoot -Recurse -File) {
            $normalized = $file.FullName.Replace('/', '\')
            if ($normalized -match '\\(bin|obj|x64|\.vs)\\') {
                continue
            }

            if ($extensions.Contains($file.Extension)) {
                $files.Add($file)
            }
        }
    }

    return @($files | Sort-Object FullName)
}

# Get-FileSha256Hex calculates SHA256 without depending on Get-FileHash, which
# can be unavailable in stripped-down Windows PowerShell hosts.
# Inputs: existing file path. Processing: opens with sharing and hashes bytes.
# Return behavior: lowercase hexadecimal SHA256.
function Get-FileSha256Hex {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete)
    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            return ([System.BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
        }
        finally {
            $sha.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
}

# Get-GuestPayloadSourceFingerprint hashes the relevant source file hashes into
# one compact manifest value. Inputs are the repository root; processing hashes
# stable relative paths, file content hashes, and sizes; return behavior is a
# small metadata object.
function Get-GuestPayloadSourceFingerprint {
    param(
        [Parameter(Mandatory)]
        [string]$RepositoryRoot
    )

    $files = @(Get-GuestPayloadSourceFiles -RepositoryRoot $RepositoryRoot)
    $builder = [System.Text.StringBuilder]::new()
    foreach ($file in $files) {
        $relative = Get-RelativeRepositoryPath -RepositoryRoot $RepositoryRoot -Path $file.FullName
        $hash = Get-FileSha256Hex -Path $file.FullName
        [void]$builder.AppendLine("$relative|$hash|$($file.Length)")
    }

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($builder.ToString())
        $fingerprint = ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }

    $latestWriteUtc = $null
    if ($files.Count -gt 0) {
        $latestWriteUtc = ($files | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1).LastWriteTimeUtc.ToString('O')
    }

    return [pscustomobject][ordered]@{
        Algorithm = 'sha256(relative-path|file-sha256|length)'
        Fingerprint = $fingerprint
        SourceInputCount = $files.Count
        SourceLatestWriteUtc = if ($null -eq $latestWriteUtc) { '' } else { $latestWriteUtc }
    }
}

# Get-GitHeadOrEmpty reads the current repository commit when git is available.
# Inputs are the repository root; processing suppresses errors; return behavior
# is a commit hash or an empty string.
function Get-GitHeadOrEmpty {
    param(
        [Parameter(Mandatory)]
        [string]$RepositoryRoot
    )

    try {
        $head = & git -C $RepositoryRoot rev-parse HEAD 2>$null
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace([string]$head)) {
            return [string]$head
        }
    }
    catch {
    }

    return ''
}

# Get-PayloadFileDescriptor records integrity metadata for one staged file.
# Inputs are a friendly name and existing path; processing calculates SHA256,
# size, and timestamp; return behavior is a manifest object.
function Get-PayloadFileDescriptor {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Path
    )

    $item = Get-Item -LiteralPath $Path
    return [ordered]@{
        name = $Name
        path = (Get-NormalizedFullPath -Path $Path)
        length = $item.Length
        lastWriteUtc = $item.LastWriteTimeUtc.ToString('O')
        sha256 = Get-FileSha256Hex -Path $Path
    }
}

# Test-PathUnderRoot checks whether a path is inside a root directory.
# Inputs: a candidate path and root path.
# Processing: normalizes both paths, appends a trailing separator to the root,
# and performs an ordinal-insensitive Windows path prefix comparison.
# Return behavior: true when the candidate is the root or a descendant.
function Test-PathUnderRoot {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Root
    )

    $fullPath = Get-NormalizedFullPath -Path $Path
    $fullRoot = (Get-NormalizedFullPath -Path $Root).TrimEnd('\', '/')

    if ([StringComparer]::OrdinalIgnoreCase.Equals($fullPath.TrimEnd('\', '/'), $fullRoot)) {
        return $true
    }

    $rootWithSeparator = $fullRoot + [System.IO.Path]::DirectorySeparatorChar
    return $fullPath.StartsWith($rootWithSeparator, [StringComparison]::OrdinalIgnoreCase)
}

# Join-GuestPath joins Windows guest path fragments without accessing the VM.
# Inputs are a guest root path and child segments. Processing trims separators
# and joins with backslashes. Return behavior is one guest-style path string.
function Join-GuestPath {
    param(
        [Parameter(Mandatory)]
        [string]$Root,

        [Parameter(Mandatory)]
        [string[]]$Segments
    )

    $current = $Root.TrimEnd('\', '/')
    foreach ($segment in $Segments) {
        if ([string]::IsNullOrWhiteSpace($segment)) {
            continue
        }

        $current = $current + '\' + $segment.TrimStart('\', '/')
    }

    return $current
}

# Assert-OutsideRepository rejects output paths that would place binaries in git.
# Inputs: an output path, repository root, and friendly path label.
# Processing: throws when the output path is inside the repository.
# Return behavior: no return value when the path is safe.
function Assert-OutsideRepository {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$RepositoryRoot,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if (Test-PathUnderRoot -Path $Path -Root $RepositoryRoot) {
        throw "$Name must stay outside the repository. Refusing path: $Path"
    }
}

# Invoke-NormalizedMSBuild runs MSBuild with one canonical Path variable.
# Inputs: MSBuild path and an array of command-line arguments.
# Processing: starts a child process with redirected output and removes
# duplicate PATH/Path entries that can break Visual C++ ToolTask startup.
# Return behavior: the integer MSBuild process exit code.
function Invoke-NormalizedMSBuild {
    param(
        [Parameter(Mandatory)]
        [string]$FileName,

        [Parameter(Mandatory)]
        [string[]]$Arguments
    )

    $processInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $processInfo.FileName = $FileName
    $processInfo.Arguments = ($Arguments | ForEach-Object { ConvertTo-ProcessArgument $_ }) -join ' '
    $processInfo.UseShellExecute = $false
    $processInfo.RedirectStandardOutput = $true
    $processInfo.RedirectStandardError = $true

    $pathValue = [Environment]::GetEnvironmentVariable('PATH')
    foreach ($key in @($processInfo.EnvironmentVariables.Keys)) {
        if ($key -ieq 'PATH') {
            $processInfo.EnvironmentVariables.Remove($key)
        }
    }

    if (-not [string]::IsNullOrEmpty($pathValue)) {
        $processInfo.EnvironmentVariables['Path'] = $pathValue
    }

    Write-PrepStep "MSBuild $($processInfo.Arguments)"
    $process = [System.Diagnostics.Process]::Start($processInfo)
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()

    if (-not [string]::IsNullOrWhiteSpace($stdout)) {
        Write-Host $stdout
    }

    if (-not [string]::IsNullOrWhiteSpace($stderr)) {
        Write-Error $stderr
    }

    return $process.ExitCode
}

# Copy-DirectoryContents copies one staged publish directory into the payload.
# Inputs: source directory, destination directory, and IncludeSymbols flag.
# Processing: copies files recursively, creates parent folders, and skips .pdb
# files unless symbols are explicitly requested.
# Return behavior: the number of copied files.
function Copy-DirectoryContents {
    param(
        [Parameter(Mandatory)]
        [string]$SourceDirectory,

        [Parameter(Mandatory)]
        [string]$DestinationDirectory,

        [Parameter(Mandatory)]
        [bool]$CopySymbols
    )

    $sourceRoot = (Get-Item -LiteralPath $SourceDirectory).FullName.TrimEnd('\', '/') + '\'
    New-Item -ItemType Directory -Path $DestinationDirectory -Force | Out-Null

    $copied = 0
    foreach ($file in Get-ChildItem -LiteralPath $SourceDirectory -Recurse -File) {
        if ((-not $CopySymbols) -and [StringComparer]::OrdinalIgnoreCase.Equals($file.Extension, '.pdb')) {
            continue
        }

        $relativePath = $file.FullName.Substring($sourceRoot.Length)
        $targetPath = Join-Path $DestinationDirectory $relativePath
        $targetParent = Split-Path -Parent $targetPath
        New-Item -ItemType Directory -Path $targetParent -Force | Out-Null
        Copy-Item -LiteralPath $file.FullName -Destination $targetPath -Force
        $copied++
    }

    return $copied
}

# Assert-StagedPayloadFile verifies one required payload output file.
# Inputs: the file path and friendly name. Processing uses Test-Path only after
# staging. Return behavior: throws when the expected file is missing.
function Assert-StagedPayloadFile {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Name was not staged at expected path: $Path"
    }
}

# Write-PayloadManifest writes a small operator-readable manifest next to tools.
# Inputs: payload paths, build settings, and copied file counts.
# Processing: serializes metadata as JSON into the payload root.
# Return behavior: the manifest file path.
function Write-PayloadManifest {
    param(
        [Parameter(Mandatory)]
        [string]$DestinationRoot,

        [Parameter(Mandatory)]
        [string]$AgentDirectory,

        [Parameter(Mandatory)]
        [string]$CollectorDirectory,

        [Parameter(Mandatory)]
        [int]$AgentFileCount,

        [Parameter(Mandatory)]
        [int]$CollectorFileCount
    )

    $manifestPath = Join-Path $DestinationRoot 'payload-manifest.json'
    $agentExecutablePath = Join-Path $AgentDirectory $GuestAgentExecutableName
    $collectorExecutablePath = Join-Path $CollectorDirectory $R0CollectorExecutableName
    $guestAgentPath = Join-GuestPath -Root $GuestWorkingDirectory -Segments @('agent', $GuestAgentExecutableName)
    $guestCollectorPath = Join-GuestPath -Root $GuestWorkingDirectory -Segments @('r0collector', $R0CollectorExecutableName)
    $sourceFingerprint = Get-GuestPayloadSourceFingerprint -RepositoryRoot $RepoRoot
    $manifest = [ordered]@{
        payloadContractVersion = 2
        generatedAtUtc      = [DateTimeOffset]::UtcNow.ToString('O')
        repositoryRoot      = (Get-NormalizedFullPath -Path $RepoRoot)
        repositoryHead      = Get-GitHeadOrEmpty -RepositoryRoot $RepoRoot
        sourceFingerprintAlgorithm = $sourceFingerprint.Algorithm
        sourceFingerprint = $sourceFingerprint.Fingerprint
        sourceInputCount  = $sourceFingerprint.SourceInputCount
        sourceLatestWriteUtc = $sourceFingerprint.SourceLatestWriteUtc
        configuration       = $Configuration
        platform            = $Platform
        runtimeIdentifier   = $RuntimeIdentifier
        selfContained       = [bool]$script:EffectiveSelfContained
        frameworkDependent  = -not [bool]$script:EffectiveSelfContained
        symbolsIncluded     = [bool]$IncludeSymbols
        payloadRoot         = (Get-NormalizedFullPath -Path $DestinationRoot)
        guestWorkingDirectory = $GuestWorkingDirectory
        expectedGuestAgentPath = $guestAgentPath
        expectedR0CollectorPath = $guestCollectorPath
        guestAgentDirectory = (Get-NormalizedFullPath -Path $AgentDirectory)
        r0CollectorDirectory = (Get-NormalizedFullPath -Path $CollectorDirectory)
        agentFileCount      = $AgentFileCount
        collectorFileCount  = $CollectorFileCount
        requiredHostFiles   = @(
            (Get-PayloadFileDescriptor -Name 'GuestAgent' -Path $agentExecutablePath),
            (Get-PayloadFileDescriptor -Name 'R0Collector' -Path $collectorExecutablePath),
            [ordered]@{
                name = 'PayloadManifest'
                path = (Get-NormalizedFullPath -Path $manifestPath)
            }
        )
    }

    $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
    return $manifestPath
}

try {
    # Resolve-DefaultRepoRoot finds the repository root when -RepoRoot was not
    # supplied. Inputs are the script location variables supplied by PowerShell;
    # processing falls back from $PSScriptRoot to $MyInvocation for Windows
    # PowerShell compatibility; return behavior is a full candidate repo path.
    function Resolve-DefaultRepoRoot {
        if (-not [string]::IsNullOrWhiteSpace($script:PSScriptRoot)) {
            return (Split-Path -Parent $script:PSScriptRoot)
        }

        $scriptPath = $MyInvocation.MyCommand.Path
        if (-not [string]::IsNullOrWhiteSpace($scriptPath)) {
            return (Split-Path -Parent (Split-Path -Parent $scriptPath))
        }

        return (Get-Location).Path
    }

    if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
        $RepoRoot = Resolve-DefaultRepoRoot
    }

    $resolvedRepo = Get-NormalizedFullPath -Path $RepoRoot
    $resolvedPayload = Get-NormalizedFullPath -Path $PayloadRoot
    $resolvedBuild = Get-NormalizedFullPath -Path $BuildRoot
    $script:EffectiveSelfContained = (-not [bool]$FrameworkDependent) -or [bool]$SelfContained
    $agentProject = Join-Path $resolvedRepo 'guest\KSword.Sandbox.Agent\KSword.Sandbox.Agent.csproj'
    $collectorProject = Join-Path $resolvedRepo 'guest\KSword.Sandbox.R0Collector\KSword.Sandbox.R0Collector.vcxproj'

    if (-not (Test-Path -LiteralPath $MSBuildPath -PathType Leaf)) {
        throw "MSBuild was not found: $MSBuildPath"
    }

    if (-not (Test-Path -LiteralPath $agentProject -PathType Leaf)) {
        throw "Guest Agent project was not found: $agentProject"
    }

    if (-not (Test-Path -LiteralPath $collectorProject -PathType Leaf)) {
        throw "R0Collector project was not found: $collectorProject"
    }

    Assert-OutsideRepository -Path $resolvedPayload -RepositoryRoot $resolvedRepo -Name 'PayloadRoot'
    Assert-OutsideRepository -Path $resolvedBuild -RepositoryRoot $resolvedRepo -Name 'BuildRoot'

    $agentPublishRoot = Join-Path $resolvedBuild 'agent-publish'
    $agentArtifacts = Add-TrailingDirectorySeparator -Path (Join-Path $resolvedBuild 'agent-artifacts')
    $collectorOutDir = Add-TrailingDirectorySeparator -Path (Join-Path $resolvedBuild 'r0collector-bin')
    $collectorIntDir = Add-TrailingDirectorySeparator -Path (Join-Path $resolvedBuild 'r0collector-obj')
    $agentPayloadDir = Join-Path $resolvedPayload 'agent'
    $collectorPayloadDir = Join-Path $resolvedPayload 'r0collector'

    New-Item -ItemType Directory -Path $agentPublishRoot, $agentArtifacts, $collectorOutDir, $collectorIntDir, $agentPayloadDir, $collectorPayloadDir -Force | Out-Null

    Write-PrepStep "Publishing Guest Agent into $agentPublishRoot"
    $agentExit = Invoke-NormalizedMSBuild -FileName $MSBuildPath -Arguments @(
        $agentProject,
        '/restore',
        '/t:Publish',
        "/p:Configuration=$Configuration",
        "/p:RuntimeIdentifier=$RuntimeIdentifier",
        "/p:SelfContained=$([bool]$script:EffectiveSelfContained)",
        '/p:UseAppHost=true',
        "/p:PublishDir=$(Add-TrailingDirectorySeparator -Path $agentPublishRoot)",
        "/p:ArtifactsPath=$agentArtifacts",
        '/m:1',
        '/v:minimal'
    )
    if ($agentExit -ne 0) {
        throw "Guest Agent publish failed with exit code $agentExit."
    }

    Write-PrepStep "Building R0Collector into $collectorOutDir"
    $collectorExit = Invoke-NormalizedMSBuild -FileName $MSBuildPath -Arguments @(
        $collectorProject,
        '/t:Build',
        "/p:Configuration=$Configuration",
        "/p:Platform=$Platform",
        "/p:OutDir=$collectorOutDir",
        "/p:IntDir=$collectorIntDir",
        '/m:1',
        '/v:minimal'
    )
    if ($collectorExit -ne 0) {
        throw "R0Collector build failed with exit code $collectorExit."
    }

    $collectorExe = Join-Path $collectorOutDir 'KSword.Sandbox.R0Collector.exe'
    if (-not (Test-Path -LiteralPath $collectorExe -PathType Leaf)) {
        throw "R0Collector executable was not produced at expected path: $collectorExe"
    }

    Write-PrepStep "Copying Guest Agent runtime files into $agentPayloadDir"
    $agentFileCount = Copy-DirectoryContents -SourceDirectory $agentPublishRoot -DestinationDirectory $agentPayloadDir -CopySymbols ([bool]$IncludeSymbols)
    $agentExecutablePath = Join-Path $agentPayloadDir $GuestAgentExecutableName
    Assert-StagedPayloadFile -Path $agentExecutablePath -Name 'Guest Agent executable'

    Write-PrepStep "Copying R0Collector executable into $collectorPayloadDir"
    $collectorPayloadExecutable = Join-Path $collectorPayloadDir $R0CollectorExecutableName
    Copy-Item -LiteralPath $collectorExe -Destination $collectorPayloadExecutable -Force
    Assert-StagedPayloadFile -Path $collectorPayloadExecutable -Name 'R0Collector executable'
    $collectorFileCount = 1

    if ($IncludeSymbols) {
        $collectorPdb = Join-Path $collectorOutDir 'KSword.Sandbox.R0Collector.pdb'
        if (Test-Path -LiteralPath $collectorPdb -PathType Leaf) {
            Copy-Item -LiteralPath $collectorPdb -Destination (Join-Path $collectorPayloadDir 'KSword.Sandbox.R0Collector.pdb') -Force
            $collectorFileCount++
        }
    }

    $manifestPath = Write-PayloadManifest `
        -DestinationRoot $resolvedPayload `
        -AgentDirectory $agentPayloadDir `
        -CollectorDirectory $collectorPayloadDir `
        -AgentFileCount $agentFileCount `
        -CollectorFileCount $collectorFileCount

    Write-Host ''
    Write-Host 'PASS: guest payload prepared.'
    Write-Host "  Payload root:  $resolvedPayload"
    Write-Host "  Guest Agent:   $agentPayloadDir"
    Write-Host "  R0Collector:   $collectorPayloadDir"
    Write-Host "  Manifest:      $manifestPath"
    Write-Host "  Readiness:     pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-HyperVReadiness.ps1 -GuestPayloadRoot '$resolvedPayload' -GuestWorkingDirectory '$GuestWorkingDirectory'"
    Write-Host '  Git hygiene:   payload files are outside the repository; do not commit copied binaries.'
    exit 0
}
catch {
    Write-Host ''
    Write-Error "FAIL: guest payload preparation failed. $($_.Exception.Message)"
    exit 1
}
