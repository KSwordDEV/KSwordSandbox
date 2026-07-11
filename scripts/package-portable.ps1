<#
.SYNOPSIS
Stages a draft KSwordSandbox source or runtime portable package and creates a zip.

.DESCRIPTION
Inputs are a package kind, repository root, optional runtime publish root, and
output directory. Processing reads the matching packaging/*.manifest.json file,
copies allowed files into a staging tree outside the repository, writes generated
package metadata, and creates a local zip unless -StageOnly is specified.

The script is local-only: it does not push, publish, sign, or build. Runtime
binaries must be supplied through an external RuntimePublishRoot; source packages
are source-only and reject generated binaries, samples, VM state, private signing
material, and local runtime artifacts.
#>
[CmdletBinding()]
param(
    [ValidateSet('source', 'runtime')]
    [string]$PackageKind = 'runtime',

    [string]$RepositoryRoot,

    [string]$ManifestPath,

    [string]$RuntimePublishRoot,

    [string]$OutputRoot = 'D:\Temp\KSwordSandbox\packages',

    [string]$Version,

    [switch]$IncludeUntracked,

    [switch]$AllowDirtySource,

    [switch]$StageOnly,

    [switch]$Force
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

if ([string]::IsNullOrWhiteSpace($ManifestPath)) {
    $ManifestPath = Join-Path $RepositoryRoot (Join-Path 'packaging' "$PackageKind-package.manifest.json")
}

if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
    throw "Package manifest was not found: $ManifestPath"
}

$ManifestPath = (Resolve-Path -LiteralPath $ManifestPath).Path

# ConvertTo-NormalizedRelativePath converts separators and removes leading ./.
# Inputs: a relative path string. Return behavior: a slash-separated relative path.
function ConvertTo-NormalizedRelativePath {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $normalized = $Path.Replace('\', '/')
    while ($normalized.StartsWith('./', [StringComparison]::Ordinal)) {
        $normalized = $normalized.Substring(2)
    }

    return $normalized.TrimStart('/')
}

# Get-FullPathNoRequire resolves a path without requiring it to exist.
function Get-FullPathNoRequire {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    return [System.IO.Path]::GetFullPath($Path)
}

# Join-SafePath combines a root and relative path and rejects path traversal.
function Join-SafePath {
    param(
        [Parameter(Mandatory)]
        [string]$Root,

        [Parameter(Mandatory)]
        [string]$RelativePath
    )

    $rootFull = Get-FullPathNoRequire -Path $Root
    $combined = Get-FullPathNoRequire -Path (Join-Path $rootFull $RelativePath)
    $rootPrefix = $rootFull.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    if (($combined -ne $rootFull) -and (-not $combined.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase))) {
        throw "Path escapes root '$Root': $RelativePath"
    }

    return $combined
}

# Get-RelativePathFromRoot returns a slash-separated path under an existing root.
function Get-RelativePathFromRoot {
    param(
        [Parameter(Mandatory)]
        [string]$Root,

        [Parameter(Mandatory)]
        [string]$Path
    )

    $rootFull = (Get-FullPathNoRequire -Path $Root).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    $pathFull = Get-FullPathNoRequire -Path $Path
    if (-not $pathFull.StartsWith($rootFull, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Path is not under root '$Root': $Path"
    }

    return ConvertTo-NormalizedRelativePath -Path $pathFull.Substring($rootFull.Length)
}

# Get-ObjectPropertyValue reads a PSCustomObject property without breaking strict mode.
function Get-ObjectPropertyValue {
    param(
        [Parameter(Mandatory)]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Name,

        [object]$DefaultValue = $null
    )

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $DefaultValue
    }

    return $property.Value
}

# Get-ObjectArrayProperty returns a property value as an array.
function Get-ObjectArrayProperty {
    param(
        [Parameter(Mandatory)]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Name
    )

    $value = Get-ObjectPropertyValue -InputObject $InputObject -Name $Name -DefaultValue @()
    if ($null -eq $value) {
        return @()
    }

    return @($value)
}

# Test-WildcardMatch checks path against manifest wildcard patterns.
function Test-WildcardMatch {
    param(
        [Parameter(Mandatory)]
        [string]$RelativePath,

        [Parameter(Mandatory)]
        [object[]]$Patterns
    )

    $normalizedPath = ConvertTo-NormalizedRelativePath -Path $RelativePath
    foreach ($patternValue in $Patterns) {
        if ($null -eq $patternValue) {
            continue
        }

        $pattern = ConvertTo-NormalizedRelativePath -Path ([string]$patternValue)
        if ([string]::IsNullOrWhiteSpace($pattern)) {
            continue
        }

        if ($normalizedPath -like $pattern) {
            return $true
        }
    }

    return $false
}

# Assert-OutputRootOutsideRepository prevents release artifacts from landing in git.
function Assert-OutputRootOutsideRepository {
    param(
        [Parameter(Mandatory)]
        [string]$RepoRoot,

        [Parameter(Mandatory)]
        [string]$OutRoot
    )

    $repoFull = (Get-FullPathNoRequire -Path $RepoRoot).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    $outFull = Get-FullPathNoRequire -Path $OutRoot
    if ($outFull.StartsWith($repoFull, [StringComparison]::OrdinalIgnoreCase)) {
        throw "OutputRoot must be outside the repository so packages are not accidentally committed: $OutRoot"
    }
}

# Assert-PathAllowed applies package-level hard exclusions in addition to manifest globs.
function Assert-PathAllowed {
    param(
        [Parameter(Mandatory)]
        [string]$Kind,

        [Parameter(Mandatory)]
        [string]$RelativePath,

        [Parameter(Mandatory)]
        [string]$SourceType
    )

    $normalized = ConvertTo-NormalizedRelativePath -Path $RelativePath
    $segments = @($normalized -split '/' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $forbiddenSegments = @(
        '.agents',
        '.cert',
        '.git',
        '.idea',
        '.vs',
        '.vscode',
        'artifacts',
        'bin',
        'captures',
        'coverage',
        'logs',
        'obj',
        'reports',
        'runtime',
        'samples',
        'checkpoints',
        'snapshots',
        'TestResults',
        'vm-state',
        'vms',
        'virtual-machines',
        'x64'
    )

    foreach ($segment in $segments) {
        # Use exact-case segment checks so source namespaces such as
        # src/KSword.Sandbox.Abstractions/Artifacts are not mistaken for the
        # lower-case runtime artifact-output folder "artifacts/".
        if ($forbiddenSegments -ccontains $segment) {
            throw "Forbidden package path segment '$segment' in '$normalized'."
        }
    }

    $fileName = [System.IO.Path]::GetFileName($normalized)
    $extension = [System.IO.Path]::GetExtension($normalized).ToLowerInvariant()
    $blockedAlways = @(
        '.7z',
        '.avhd',
        '.avhdx',
        '.bmp',
        '.cer',
        '.crt',
        '.csr',
        '.der',
        '.dmp',
        '.doc',
        '.docx',
        '.dpapi',
        '.esd',
        '.etl',
        '.evtx',
        '.gz',
        '.iso',
        '.key',
        '.kdbx',
        '.lib',
        '.log',
        '.mrt',
        '.nvram',
        '.obj',
        '.ova',
        '.ovf',
        '.p12',
        '.pcap',
        '.pcapng',
        '.pdb',
        '.pdf',
        '.pem',
        '.pfx',
        '.rar',
        '.snk',
        '.sys',
        '.tar',
        '.vmcx',
        '.vmgs',
        '.vmrs',
        '.vsv',
        '.vhd',
        '.vhdpmem',
        '.vhdset',
        '.vhdx',
        '.wim',
        '.xls',
        '.xlsx',
        '.zip'
    )

    if ($blockedAlways -contains $extension) {
        throw "Forbidden package file extension '$extension' in '$normalized'."
    }

    if ($Kind -eq 'source') {
        $sourceBlockedExtensions = @('.appx', '.cab', '.dll', '.exe', '.exp', '.ilk', '.msi', '.msix')
        if ($sourceBlockedExtensions -contains $extension) {
            throw "Source package cannot include generated/runtime binary '$normalized'."
        }
    }

    if ($Kind -eq 'runtime' -and $SourceType -eq 'repository') {
        $repositoryRuntimeBlockedExtensions = @('.appx', '.cab', '.dll', '.exe', '.exp', '.ilk', '.msi', '.msix')
        if ($repositoryRuntimeBlockedExtensions -contains $extension) {
            throw "Runtime package cannot copy binaries from the repository worktree: $normalized"
        }
    }

    if ($fileName -ieq 'install-state.json' -or $fileName -ieq 'guest-password.dpapi') {
        throw "Forbidden local state file in package: $normalized"
    }

    $lowerFileName = $fileName.ToLowerInvariant()
    $blockedFileNames = @(
        'sandbox.local.json',
        'appsettings.local.json',
        'secrets.json',
        'user-secrets.json',
        'usersecrets.json',
        'id_rsa',
        'id_dsa',
        'id_ecdsa',
        'id_ed25519'
    )
    if ($blockedFileNames -contains $lowerFileName) {
        throw "Forbidden local secret/config file in package: $normalized"
    }

    if ($normalized -like '*.local.json' -or $normalized -like '*.secret.json' -or $normalized -like '.env' -or $normalized -like '.env.*') {
        throw "Forbidden local config or environment file in package: $normalized"
    }
}

# Get-GitOutput runs git and returns stdout lines.
function Get-GitOutput {
    param(
        [Parameter(Mandatory)]
        [string[]]$Arguments
    )

    $output = @(git -C $RepositoryRoot @Arguments)
    if ($LASTEXITCODE -ne 0) {
        throw "git $($Arguments -join ' ') failed with exit code $LASTEXITCODE."
    }

    return @($output)
}

# Get-GitRevision returns a compact source revision string for package metadata.
function Get-GitRevision {
    $gitCommand = Get-Command git -ErrorAction SilentlyContinue
    if ($null -eq $gitCommand) {
        return 'unknown'
    }

    try {
        $revision = @(git -C $RepositoryRoot rev-parse --short HEAD)
        if ($LASTEXITCODE -eq 0 -and $revision.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($revision[0])) {
            return [string]$revision[0]
        }
    }
    catch {
        return 'unknown'
    }

    return 'unknown'
}

# Get-DefaultPackageVersion returns a git-derived version or timestamp fallback.
function Get-DefaultPackageVersion {
    $gitCommand = Get-Command git -ErrorAction SilentlyContinue
    if ($null -ne $gitCommand) {
        try {
            $describe = @(git -C $RepositoryRoot describe --tags --always --dirty)
            if ($LASTEXITCODE -eq 0 -and $describe.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($describe[0])) {
                return ([string]$describe[0]) -replace '[^A-Za-z0-9._-]', '-'
            }
        }
        catch {
            # Fall through to timestamp fallback.
        }
    }

    return 'dev-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
}

# Assert-CleanSourcePackage enforces clean source releases unless explicitly bypassed.
function Assert-CleanSourcePackage {
    if ($PackageKind -ne 'source' -or $AllowDirtySource.IsPresent) {
        return
    }

    $gitCommand = Get-Command git -ErrorAction SilentlyContinue
    if ($null -eq $gitCommand) {
        Write-Warning 'git was not found; skipping source worktree cleanliness check.'
        return
    }

    $status = @(git -C $RepositoryRoot status --porcelain)
    if ($LASTEXITCODE -ne 0) {
        throw "git status failed with exit code $LASTEXITCODE."
    }

    if ($status.Count -gt 0) {
        throw "Source package requires a clean worktree. Commit/stash local changes or pass -AllowDirtySource with a documented release reason."
    }
}

# Copy-PackageFile copies one file into the staging tree and records it.
function Copy-PackageFile {
    param(
        [Parameter(Mandatory)]
        [string]$SourcePath,

        [Parameter(Mandatory)]
        [string]$TargetRelativePath
    )

    $targetRelative = ConvertTo-NormalizedRelativePath -Path $TargetRelativePath
    $targetPath = Join-SafePath -Root $stageRoot -RelativePath $targetRelative
    $targetDirectory = Split-Path -Parent $targetPath
    if (-not (Test-Path -LiteralPath $targetDirectory -PathType Container)) {
        [void](New-Item -ItemType Directory -Path $targetDirectory -Force)
    }

    Copy-Item -LiteralPath $SourcePath -Destination $targetPath -Force
    [void]$script:copiedFiles.Add($targetRelative)
}

# Copy-SourcePackage copies git-indexed source files using manifest include/exclude rules.
function Copy-SourcePackage {
    param(
        [Parameter(Mandatory)]
        [object]$Manifest
    )

    $includePatterns = Get-ObjectArrayProperty -InputObject $Manifest -Name 'includePatterns'
    $excludePatterns = Get-ObjectArrayProperty -InputObject $Manifest -Name 'excludePatterns'
    $files = New-Object System.Collections.Generic.List[string]
    foreach ($file in (Get-GitOutput -Arguments @('ls-files', '--cached'))) {
        [void]$files.Add($file)
    }

    if ($IncludeUntracked.IsPresent) {
        foreach ($file in (Get-GitOutput -Arguments @('ls-files', '--others', '--exclude-standard'))) {
            [void]$files.Add($file)
        }
    }

    foreach ($file in ($files | Sort-Object -Unique)) {
        if ([string]::IsNullOrWhiteSpace($file)) {
            continue
        }

        $relative = ConvertTo-NormalizedRelativePath -Path $file
        if ($includePatterns.Count -gt 0 -and -not (Test-WildcardMatch -RelativePath $relative -Patterns $includePatterns)) {
            continue
        }

        if (Test-WildcardMatch -RelativePath $relative -Patterns $excludePatterns) {
            continue
        }

        Assert-PathAllowed -Kind $PackageKind -RelativePath $relative -SourceType 'repository'
        $sourcePath = Join-SafePath -Root $RepositoryRoot -RelativePath $relative
        if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
            continue
        }

        Copy-PackageFile -SourcePath $sourcePath -TargetRelativePath $relative
    }
}

# Get-EntryTargetRelativePath returns the target path for a manifest entry.
function Get-EntryTargetRelativePath {
    param(
        [Parameter(Mandatory)]
        [object]$Entry,

        [Parameter(Mandatory)]
        [string]$Source
    )

    $target = [string](Get-ObjectPropertyValue -InputObject $Entry -Name 'target' -DefaultValue $Source)
    if ([string]::IsNullOrWhiteSpace($target)) {
        $target = $Source
    }

    return ConvertTo-NormalizedRelativePath -Path $target
}

# Copy-RuntimeManifestEntry copies one file/directory from repository or runtime publish root.
function Copy-RuntimeManifestEntry {
    param(
        [Parameter(Mandatory)]
        [object]$Entry,

        [Parameter(Mandatory)]
        [object[]]$ExcludePatterns
    )

    $sourceType = [string](Get-ObjectPropertyValue -InputObject $Entry -Name 'sourceType' -DefaultValue 'repository')
    $source = [string](Get-ObjectPropertyValue -InputObject $Entry -Name 'source' -DefaultValue '')
    $required = [bool](Get-ObjectPropertyValue -InputObject $Entry -Name 'required' -DefaultValue $true)
    if ([string]::IsNullOrWhiteSpace($source)) {
        throw 'Runtime manifest entry is missing source.'
    }

    $baseRoot = $RepositoryRoot
    if ($sourceType -eq 'runtimePublish') {
        if ([string]::IsNullOrWhiteSpace($RuntimePublishRoot)) {
            if ($required) {
                throw "RuntimePublishRoot is required for manifest entry '$source'."
            }

            Write-Warning "Skipping optional runtime publish entry '$source' because RuntimePublishRoot was not provided."
            return
        }

        $baseRoot = (Resolve-Path -LiteralPath $RuntimePublishRoot).Path
    }
    elseif ($sourceType -ne 'repository') {
        throw "Unsupported runtime manifest sourceType '$sourceType' for '$source'."
    }

    $sourceRelative = ConvertTo-NormalizedRelativePath -Path $source
    $targetRelative = Get-EntryTargetRelativePath -Entry $Entry -Source $sourceRelative
    $sourcePath = Join-SafePath -Root $baseRoot -RelativePath $sourceRelative
    if (-not (Test-Path -LiteralPath $sourcePath)) {
        if ($required) {
            throw "Required package input was not found: $sourcePath"
        }

        Write-Warning "Skipping optional package input that was not found: $sourcePath"
        return
    }

    if (Test-Path -LiteralPath $sourcePath -PathType Leaf) {
        if (Test-WildcardMatch -RelativePath $targetRelative -Patterns $ExcludePatterns) {
            return
        }

        Assert-PathAllowed -Kind $PackageKind -RelativePath $targetRelative -SourceType $sourceType
        Copy-PackageFile -SourcePath $sourcePath -TargetRelativePath $targetRelative
        return
    }

    foreach ($file in Get-ChildItem -LiteralPath $sourcePath -Recurse -File -Force) {
        $relativeUnderSource = Get-RelativePathFromRoot -Root $sourcePath -Path $file.FullName
        $targetFileRelative = ConvertTo-NormalizedRelativePath -Path (Join-Path $targetRelative $relativeUnderSource)
        if (Test-WildcardMatch -RelativePath $targetFileRelative -Patterns $ExcludePatterns) {
            continue
        }

        Assert-PathAllowed -Kind $PackageKind -RelativePath $targetFileRelative -SourceType $sourceType
        Copy-PackageFile -SourcePath $file.FullName -TargetRelativePath $targetFileRelative
    }
}

# Copy-RuntimePackage copies entries declared in runtime-package.manifest.json.
function Copy-RuntimePackage {
    param(
        [Parameter(Mandatory)]
        [object]$Manifest
    )

    $excludePatterns = Get-ObjectArrayProperty -InputObject $Manifest -Name 'excludePatterns'
    foreach ($entry in (Get-ObjectArrayProperty -InputObject $Manifest -Name 'include')) {
        Copy-RuntimeManifestEntry -Entry $entry -ExcludePatterns $excludePatterns
    }
}

# Write-GeneratedPackageManifest writes file inventory/provenance inside staging.
function Write-GeneratedPackageManifest {
    param(
        [Parameter(Mandatory)]
        [object]$Manifest,

        [Parameter(Mandatory)]
        [string]$PackageDirectoryName
    )

    $metadata = [ordered]@{
        manifestVersion = 1
        packageName = [string](Get-ObjectPropertyValue -InputObject $Manifest -Name 'packageName' -DefaultValue "KSwordSandbox-$PackageKind")
        packageKind = $PackageKind
        version = $Version
        sourceRevision = Get-GitRevision
        generatedAtUtc = [DateTime]::UtcNow.ToString('o')
        packageDirectory = $PackageDirectoryName
        fileCount = $script:copiedFiles.Count
        files = @($script:copiedFiles | Sort-Object)
        exclusionSummary = [ordered]@{
            samples = 'excluded'
            virtualMachines = 'excluded'
            hyperVCheckpoints = 'excluded'
            buildIntermediates = 'excluded'
            runtimeEvidence = 'excluded'
            localSecrets = 'excluded'
            privateSigningMaterial = 'excluded'
            repositoryBinaries = if ($PackageKind -eq 'runtime') { 'allowed only from RuntimePublishRoot' } else { 'excluded' }
        }
        safetyContract = [ordered]@{
            Chinese = '中文提示：package-portable.ps1 已按 manifest 和硬性扩展/路径规则排除 secrets、本机状态、VM 磁盘/快照、样本、报告和仓库二进制；脚本不发布、不推送。'
            SensitiveMaterial = 'not packaged'
            VmState = 'not packaged'
            RepositoryBuildOutput = 'not packaged'
            RuntimeBinariesSource = if ($PackageKind -eq 'runtime') { 'external RuntimePublishRoot only' } else { 'not packaged' }
            NetworkPublish = 'not performed'
        }
    }

    $metadataPath = Join-SafePath -Root $stageRoot -RelativePath 'package-manifest.generated.json'
    $metadata | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $metadataPath -Encoding UTF8
    [void]$script:copiedFiles.Add('package-manifest.generated.json')
}

Assert-OutputRootOutsideRepository -RepoRoot $RepositoryRoot -OutRoot $OutputRoot
Assert-CleanSourcePackage

if ([string]::IsNullOrWhiteSpace($Version)) {
    $Version = Get-DefaultPackageVersion
}
else {
    $Version = $Version -replace '[^A-Za-z0-9._-]', '-'
}

$manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
$manifestKind = [string](Get-ObjectPropertyValue -InputObject $manifest -Name 'packageKind' -DefaultValue $PackageKind)
if ($manifestKind -ne $PackageKind) {
    throw "Manifest packageKind '$manifestKind' does not match requested PackageKind '$PackageKind'."
}

$packageName = [string](Get-ObjectPropertyValue -InputObject $manifest -Name 'packageName' -DefaultValue "KSwordSandbox-$PackageKind")
$packageDirectoryName = "$packageName-$Version"
$OutputRoot = Get-FullPathNoRequire -Path $OutputRoot
$stagingRoot = Join-SafePath -Root $OutputRoot -RelativePath 'staging'
$stageRoot = Join-SafePath -Root $stagingRoot -RelativePath $packageDirectoryName
$script:copiedFiles = [System.Collections.Generic.List[string]]::new()

if (Test-Path -LiteralPath $stageRoot) {
    if (-not $Force.IsPresent) {
        throw "Staging directory already exists. Use -Force to replace it: $stageRoot"
    }

    $stagingPrefix = (Get-FullPathNoRequire -Path $stagingRoot).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    $stageFull = Get-FullPathNoRequire -Path $stageRoot
    if (-not $stageFull.StartsWith($stagingPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove staging directory outside staging root: $stageRoot"
    }

    Remove-Item -LiteralPath $stageRoot -Recurse -Force
}

[void](New-Item -ItemType Directory -Path $stageRoot -Force)

if ($PackageKind -eq 'source') {
    Copy-SourcePackage -Manifest $manifest
}
else {
    Copy-RuntimePackage -Manifest $manifest
}

Write-GeneratedPackageManifest -Manifest $manifest -PackageDirectoryName $packageDirectoryName

$archivePath = Join-SafePath -Root $OutputRoot -RelativePath "$packageDirectoryName.zip"
if (-not $StageOnly.IsPresent) {
    if ((Test-Path -LiteralPath $archivePath -PathType Leaf) -and -not $Force.IsPresent) {
        throw "Archive already exists. Use -Force to replace it: $archivePath"
    }

    if (Test-Path -LiteralPath $archivePath -PathType Leaf) {
        Remove-Item -LiteralPath $archivePath -Force
    }

    Compress-Archive -Path $stageRoot -DestinationPath $archivePath -CompressionLevel Optimal
}

Write-Host "[package] Kind: $PackageKind"
Write-Host "[package] Version: $Version"
Write-Host "[package] Files: $($script:copiedFiles.Count)"
Write-Host "[package] Stage: $stageRoot"
Write-Host '[package] 中文提示：已排除本机 secret、install-state、DPAPI 备份、样本、报告、VM 磁盘/快照、仓库二进制和签名材料。'
if ($StageOnly.IsPresent) {
    Write-Host '[package] Archive: skipped (-StageOnly)'
}
else {
    Write-Host "[package] Archive: $archivePath"
}
Write-Host '[package] Network publish/push: not performed'
