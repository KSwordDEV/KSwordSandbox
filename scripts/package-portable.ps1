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

# Assert-RuntimePublishRootOutsideRepository prevents runtime payloads from
# being sourced from repository bin/obj/x64 by accident. Inputs are the repo
# root and a resolved runtime publish root. Return behavior: throws on unsafe
# placement, otherwise returns nothing.
function Assert-RuntimePublishRootOutsideRepository {
    param(
        [Parameter(Mandatory)]
        [string]$RepoRoot,

        [Parameter(Mandatory)]
        [string]$PublishRoot
    )

    $repoFull = (Get-FullPathNoRequire -Path $RepoRoot).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    $publishFull = (Get-FullPathNoRequire -Path $PublishRoot).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    if ($publishFull.StartsWith($repoFull, [StringComparison]::OrdinalIgnoreCase)) {
        throw "RuntimePublishRoot must be outside the repository. Publish host/guest/tool payloads to D:\Temp\KSwordSandbox\publish or another external folder: $PublishRoot"
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
        'dumps',
        'jobs',
        'logs',
        'memory-dumps',
        'obj',
        'packet-captures',
        'pcaps',
        'reports',
        'runtime',
        'samples',
        'checkpoints',
        'screenshots',
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
    if ($fileName -ieq 'CSignTool.exe' -or $fileName -like 'Sign-SandboxDriverWithKsword*.ps1') {
        throw "Forbidden legacy signing tool path in package: $normalized"
    }

    $blockedAlways = @(
        '.7z',
        '.avhd',
        '.avhdx',
        '.bin',
        '.bmp',
        '.cap',
        '.cer',
        '.crt',
        '.csr',
        '.crash',
        '.db',
        '.der',
        '.dmp',
        '.doc',
        '.docx',
        '.dpapi',
        '.dump',
        '.esd',
        '.etl',
        '.evtx',
        '.gif',
        '.gz',
        '.har',
        '.heapsnapshot',
        '.hprof',
        '.iso',
        '.jpeg',
        '.jpg',
        '.jsonl',
        '.key',
        '.kdbx',
        '.lib',
        '.log',
        '.mdmp',
        '.mem',
        '.mrt',
        '.nettrace',
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
        '.png',
        '.rar',
        '.raw',
        '.snk',
        '.sqlite',
        '.sqlite3',
        '.sys',
        '.tar',
        '.trace',
        '.vmcx',
        '.vmgs',
        '.vmrs',
        '.vsv',
        '.vhd',
        '.vhdpmem',
        '.vhdset',
        '.vhdx',
        '.wim',
        '.wer',
        '.webp',
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

# Get-GitBranch returns the current branch name when git is available.
function Get-GitBranch {
    $gitCommand = Get-Command git -ErrorAction SilentlyContinue
    if ($null -eq $gitCommand) {
        return 'unknown'
    }

    try {
        $branch = @(git -C $RepositoryRoot rev-parse --abbrev-ref HEAD)
        if ($LASTEXITCODE -eq 0 -and $branch.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($branch[0])) {
            return [string]$branch[0]
        }
    }
    catch {
        return 'unknown'
    }

    return 'unknown'
}

# Get-GitStatusSnapshot returns compact dirty-state metadata for generated
# package provenance. It never changes repository state.
function Get-GitStatusSnapshot {
    $gitCommand = Get-Command git -ErrorAction SilentlyContinue
    if ($null -eq $gitCommand) {
        return [ordered]@{
            available   = $false
            isDirty     = $null
            changeCount = $null
            preview     = @()
        }
    }

    try {
        $status = @(git -C $RepositoryRoot status --porcelain)
        return [ordered]@{
            available   = $true
            isDirty     = ($status.Count -gt 0)
            changeCount = $status.Count
            preview     = @($status | Select-Object -First 25)
        }
    }
    catch {
        return [ordered]@{
            available   = $true
            isDirty     = $null
            changeCount = $null
            preview     = @("git status failed: $($_.Exception.Message)")
        }
    }
}

# Get-FileSha256Hex computes a lowercase SHA-256 without depending on the
# Get-FileHash cmdlet, so package staging works in restricted/older host shells.
function Get-FileSha256Hex {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $stream = [System.IO.File]::OpenRead($Path)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hashBytes = $sha256.ComputeHash($stream)
        return -join ($hashBytes | ForEach-Object { $_.ToString('x2') })
    }
    finally {
        $stream.Dispose()
        $sha256.Dispose()
    }
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

# Add-PackageDiagnostic records operator-facing packaging warnings/notes in
# generated metadata and console output.
function Add-PackageDiagnostic {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Info', 'Warning')]
        [string]$Severity,

        [Parameter(Mandatory)]
        [string]$Message,

        [hashtable]$Details = @{}
    )

    [void]$script:packageDiagnostics.Add([pscustomobject][ordered]@{
            severity = $Severity
            message  = $Message
            details  = $Details
    })
}

function Get-RuntimePublishEntryDiagnostics {
    param([Parameter(Mandatory)][object]$Manifest)

    $entries = New-Object System.Collections.Generic.List[object]
    foreach ($entry in (Get-ObjectArrayProperty -InputObject $Manifest -Name 'include')) {
        $sourceType = [string](Get-ObjectPropertyValue -InputObject $entry -Name 'sourceType' -DefaultValue 'repository')
        if ($sourceType -ne 'runtimePublish') {
            continue
        }

        $source = [string](Get-ObjectPropertyValue -InputObject $entry -Name 'source' -DefaultValue '')
        $target = Get-EntryTargetRelativePath -Entry $entry -Source $source
        $required = [bool](Get-ObjectPropertyValue -InputObject $entry -Name 'required' -DefaultValue $true)
        $note = [string](Get-ObjectPropertyValue -InputObject $entry -Name 'note' -DefaultValue '')
        $sourcePath = $null
        $exists = $false
        if (-not [string]::IsNullOrWhiteSpace($RuntimePublishRoot) -and -not [string]::IsNullOrWhiteSpace($source)) {
            $sourcePath = Join-SafePath -Root $RuntimePublishRoot -RelativePath $source
            $exists = Test-Path -LiteralPath $sourcePath
        }

        [void]$entries.Add([pscustomobject][ordered]@{
                source = $source
                target = $target
                required = $required
                sourcePath = $sourcePath
                exists = $exists
                note = $note
                remediation = if ($exists) {
                    ''
                }
                elseif ([string]::IsNullOrWhiteSpace($RuntimePublishRoot)) {
                    "Provide -RuntimePublishRoot outside the repository when building a runtime package if this payload should be included: $source"
                }
                else {
                    "Publish or copy '$source' under RuntimePublishRoot before cutting a portable runtime package."
                }
            })
    }

    return @($entries.ToArray())
}

function Update-PackageOperatorDiagnostics {
    param([Parameter(Mandatory)][object]$Manifest)

    $runtimeEntries = @(Get-RuntimePublishEntryDiagnostics -Manifest $Manifest)
    $missingRuntimeEntries = @($runtimeEntries | Where-Object { -not [bool]$_.exists })
    $script:operatorDiagnostics = [ordered]@{
        packageKind = $PackageKind
        runtimePublishRootProvided = -not [string]::IsNullOrWhiteSpace($RuntimePublishRoot)
        runtimePublishRoot = if ([string]::IsNullOrWhiteSpace($RuntimePublishRoot)) { $null } else { $RuntimePublishRoot }
        runtimePublishRootRequiredForCompleteRuntime = ($PackageKind -eq 'runtime')
        runtimePublishRootMustBeOutsideRepository = $true
        runtimePublishEntries = @($runtimeEntries)
        missingRuntimePublishEntries = @($missingRuntimeEntries | ForEach-Object { $_.source })
        runtimePublishReady = if ($PackageKind -ne 'runtime') { $true } else { $missingRuntimeEntries.Count -eq 0 }
        nonMutating = [ordered]@{
            vmMutation = $false
            driverSigning = $false
            csignTool = $false
            gitPush = $false
            networkPublish = $false
        }
        operatorGuidance = @(
            'RuntimePublishRoot must point to external published payloads such as host-web, guest-tools, tools/job-tool, and tools/postprocess.',
            'The package script stages and zips locally only; it does not build, sign, push, publish, start Hyper-V, or copy files into a VM.',
            'Inspect package-manifest.generated.json before handoff; verify fileInventory sha256/sizeBytes and packageDiagnostics.'
        )
        chineseGuidance = '中文提示：runtime 便携包如果没有 RuntimePublishRoot 也可做 layout dry-run，但完整交付前必须把 host-web/guest-tools/tools payload 发布到仓库外目录。'
    }
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
        [string]$TargetRelativePath,

        [string]$SourceType = 'repository',

        [string]$SourceRelativePath = ''
    )

    $targetRelative = ConvertTo-NormalizedRelativePath -Path $TargetRelativePath
    $targetPath = Join-SafePath -Root $stageRoot -RelativePath $targetRelative
    $targetDirectory = Split-Path -Parent $targetPath
    if (-not (Test-Path -LiteralPath $targetDirectory -PathType Container)) {
        [void](New-Item -ItemType Directory -Path $targetDirectory -Force)
    }

    Copy-Item -LiteralPath $SourcePath -Destination $targetPath -Force
    [void]$script:copiedFiles.Add($targetRelative)
    $targetItem = Get-Item -LiteralPath $targetPath
    [void]$script:copiedFileRecords.Add([pscustomobject][ordered]@{
            path               = $targetRelative
            sourceType         = $SourceType
            sourceRelativePath = if ([string]::IsNullOrWhiteSpace($SourceRelativePath)) { $null } else { ConvertTo-NormalizedRelativePath -Path $SourceRelativePath }
            sizeBytes          = [Int64]$targetItem.Length
            sha256             = Get-FileSha256Hex -Path $targetPath
        })
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

        Copy-PackageFile -SourcePath $sourcePath -TargetRelativePath $relative -SourceType 'repository' -SourceRelativePath $relative
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

    $sourceRelative = ConvertTo-NormalizedRelativePath -Path $source
    $targetRelative = Get-EntryTargetRelativePath -Entry $Entry -Source $sourceRelative
    $baseRoot = $RepositoryRoot
    if ($sourceType -eq 'runtimePublish') {
        if ([string]::IsNullOrWhiteSpace($RuntimePublishRoot)) {
            if ($required) {
                throw "RuntimePublishRoot is required for manifest entry '$source'."
            }

            Write-Warning "Skipping optional runtime publish entry '$source' because RuntimePublishRoot was not provided."
            Add-PackageDiagnostic `
                -Severity Warning `
                -Message "Optional runtime publish entry skipped because RuntimePublishRoot was not provided: $source" `
                -Details @{ sourceType = $sourceType; source = $source; target = $targetRelative }
            return
        }

        $baseRoot = (Resolve-Path -LiteralPath $RuntimePublishRoot).Path
    }
    elseif ($sourceType -ne 'repository') {
        throw "Unsupported runtime manifest sourceType '$sourceType' for '$source'."
    }

    $sourcePath = Join-SafePath -Root $baseRoot -RelativePath $sourceRelative
    if (-not (Test-Path -LiteralPath $sourcePath)) {
        if ($required) {
            throw "Required package input was not found: $sourcePath"
        }

        Write-Warning "Skipping optional package input that was not found: $sourcePath"
        Add-PackageDiagnostic `
            -Severity Warning `
            -Message "Optional package input skipped because it was not found: $source" `
            -Details @{ sourceType = $sourceType; source = $source; target = $targetRelative; sourcePath = $sourcePath }
        return
    }

    if (Test-Path -LiteralPath $sourcePath -PathType Leaf) {
        if (Test-WildcardMatch -RelativePath $targetRelative -Patterns $ExcludePatterns) {
            return
        }

        Assert-PathAllowed -Kind $PackageKind -RelativePath $targetRelative -SourceType $sourceType
        Copy-PackageFile -SourcePath $sourcePath -TargetRelativePath $targetRelative -SourceType $sourceType -SourceRelativePath $sourceRelative
        return
    }

    foreach ($file in Get-ChildItem -LiteralPath $sourcePath -Recurse -File -Force) {
        $relativeUnderSource = Get-RelativePathFromRoot -Root $sourcePath -Path $file.FullName
        $targetFileRelative = ConvertTo-NormalizedRelativePath -Path (Join-Path $targetRelative $relativeUnderSource)
        if (Test-WildcardMatch -RelativePath $targetFileRelative -Patterns $ExcludePatterns) {
            continue
        }

        Assert-PathAllowed -Kind $PackageKind -RelativePath $targetFileRelative -SourceType $sourceType
        $sourceFileRelative = ConvertTo-NormalizedRelativePath -Path (Join-Path $sourceRelative $relativeUnderSource)
        Copy-PackageFile -SourcePath $file.FullName -TargetRelativePath $targetFileRelative -SourceType $sourceType -SourceRelativePath $sourceFileRelative
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

    $manifestDisplayPath = try {
        Get-RelativePathFromRoot -Root $RepositoryRoot -Path $ManifestPath
    }
    catch {
        $ManifestPath
    }

    $metadata = [ordered]@{
        manifestVersion = 1
        packageName = [string](Get-ObjectPropertyValue -InputObject $Manifest -Name 'packageName' -DefaultValue "KSwordSandbox-$PackageKind")
        packageKind = $PackageKind
        version = $Version
        sourceRevision = Get-GitRevision
        sourceBranch = Get-GitBranch
        gitStatus = Get-GitStatusSnapshot
        generatedAtUtc = [DateTime]::UtcNow.ToString('o')
        repositoryRoot = $RepositoryRoot
        manifestPath = $manifestDisplayPath
        runtimePublishRoot = if ([string]::IsNullOrWhiteSpace($RuntimePublishRoot)) { $null } else { $RuntimePublishRoot }
        packageDirectory = $PackageDirectoryName
        stageRoot = $stageRoot
        archivePlanned = -not $StageOnly.IsPresent
        archivePath = if ($StageOnly.IsPresent) { $null } else { $archivePath }
        fileCount = $script:copiedFiles.Count + 1
        payloadFileCount = $script:copiedFiles.Count
        payloadTotalBytes = [Int64](($script:copiedFileRecords | ForEach-Object { $_.sizeBytes } | Measure-Object -Sum).Sum)
        files = @(($script:copiedFiles + @('package-manifest.generated.json')) | Sort-Object)
        fileInventory = @($script:copiedFileRecords | Sort-Object path)
        generatedMetadata = [ordered]@{
            path = 'package-manifest.generated.json'
            includesSelfInFilesList = $true
            includesSelfInFileInventory = $false
            reason = 'Avoid recursive self-hash; all payload files include sizeBytes and sha256.'
        }
        manifestRequiredChecks = @(Get-ObjectArrayProperty -InputObject $Manifest -Name 'requiredChecks')
        packageDiagnostics = @($script:packageDiagnostics.ToArray())
        operatorDiagnostics = $script:operatorDiagnostics
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
            Chinese = '中文提示：package-portable.ps1 已按 manifest 和硬性扩展/路径规则排除 secrets、本机状态、VM 磁盘/快照、样本、报告、截图、PCAP、dump、仓库二进制和 legacy signing tool；脚本不发布、不推送、不签名、不操作 VM。'
            SensitiveMaterial = 'not packaged'
            VmState = 'not packaged'
            VmMutation = 'not performed'
            RepositoryBuildOutput = 'not packaged'
            RuntimeBinariesSource = if ($PackageKind -eq 'runtime') { 'external RuntimePublishRoot only' } else { 'not packaged' }
            NetworkPublish = 'not performed'
            GitPush = 'not performed'
            DriverSigning = 'not performed'
            CSignTool = 'not called and forbidden from package contents'
        }
    }

    $metadataPath = Join-SafePath -Root $stageRoot -RelativePath 'package-manifest.generated.json'
    $metadata | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $metadataPath -Encoding UTF8
    [void]$script:copiedFiles.Add('package-manifest.generated.json')
    $metadataItem = Get-Item -LiteralPath $metadataPath
    [void]$script:copiedFileRecords.Add([pscustomobject][ordered]@{
            path               = 'package-manifest.generated.json'
            sourceType         = 'generated'
            sourceRelativePath = $null
            sizeBytes          = [Int64]$metadataItem.Length
            sha256             = Get-FileSha256Hex -Path $metadataPath
        })
}

Assert-OutputRootOutsideRepository -RepoRoot $RepositoryRoot -OutRoot $OutputRoot
Assert-CleanSourcePackage

if ($PackageKind -eq 'runtime' -and -not [string]::IsNullOrWhiteSpace($RuntimePublishRoot)) {
    $RuntimePublishRoot = (Resolve-Path -LiteralPath $RuntimePublishRoot).Path
    Assert-RuntimePublishRootOutsideRepository -RepoRoot $RepositoryRoot -PublishRoot $RuntimePublishRoot
}

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
$script:copiedFileRecords = [System.Collections.Generic.List[object]]::new()
$script:packageDiagnostics = [System.Collections.Generic.List[object]]::new()
$script:operatorDiagnostics = [ordered]@{}

Update-PackageOperatorDiagnostics -Manifest $manifest

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

$archivePath = Join-SafePath -Root $OutputRoot -RelativePath "$packageDirectoryName.zip"
Write-GeneratedPackageManifest -Manifest $manifest -PackageDirectoryName $packageDirectoryName

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
Write-Host "[package] Metadata: $(Join-SafePath -Root $stageRoot -RelativePath 'package-manifest.generated.json')"
Write-Host "[package] Payload bytes: $([Int64](($script:copiedFileRecords | Where-Object { $_.sourceType -ne 'generated' } | ForEach-Object { $_.sizeBytes } | Measure-Object -Sum).Sum))"
Write-Host "[package] Optional/skipped entries: $($script:packageDiagnostics.Count)"
if ($PackageKind -eq 'runtime') {
    $runtimeRootDisplay = if ([string]::IsNullOrWhiteSpace($RuntimePublishRoot)) { '<not provided>' } else { $RuntimePublishRoot }
    Write-Host "[package] RuntimePublishRoot: $runtimeRootDisplay"
    foreach ($entry in @($script:operatorDiagnostics.runtimePublishEntries)) {
        $entryState = if ([bool]$entry.exists) { 'present' } elseif ([bool]$entry.required) { 'missing-required' } else { 'missing-optional' }
        Write-Host "[package] Runtime entry: $entryState source=$($entry.source) target=$($entry.target)"
    }
    if (-not [bool]$script:operatorDiagnostics.runtimePublishReady) {
        Write-Host '[package] 中文提示：runtime 包存在缺失的 published payload；本次可作为 layout/safety dry-run，完整交付前请补齐 RuntimePublishRoot。'
    }
}
Write-Host '[package] 中文提示：已排除本机 secret、install-state、DPAPI 备份、样本、报告、VM 磁盘/快照、仓库二进制和签名材料。'
Write-Host '[package] Safety: no VM mutation, no driver signing, no CSignTool, no git push/publish.'
if ($StageOnly.IsPresent) {
    Write-Host '[package] Archive: skipped (-StageOnly)'
}
else {
    Write-Host "[package] Archive: $archivePath"
    $archiveHash = Get-FileSha256Hex -Path $archivePath
    Write-Host "[package] Archive SHA256: $archiveHash"
}
Write-Host '[package] Network publish/push: not performed'
