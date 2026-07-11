<#
.SYNOPSIS
Stages a draft KSwordSandbox source or runtime portable package and creates a zip.

.DESCRIPTION
Inputs are a package kind, repository root, optional runtime publish root, and
output directory. Processing reads the matching packaging/*.manifest.json file,
copies allowed files into a staging tree outside the repository, writes generated
package metadata, and creates a local zip unless -StageOnly is specified.

The script is local-only: it does not push, publish, sign, or build. Runtime
binaries must be supplied through an external RuntimePublishRoot; use
-RequireCompleteRuntimePayloads for handoff packages and omit it only for
explicit layout/safety dry-runs. Source packages are source-only and reject
generated binaries, samples, VM state, private signing material, and local
runtime artifacts. GUI signing fallback and CSignTool are forbidden.
#>
[CmdletBinding()]
param(
    [ValidateSet('source', 'runtime')]
    [string]$PackageKind = 'runtime',

    [string]$RepositoryRoot,

    [string]$ManifestPath,

    [string]$RuntimePublishRoot,

    [switch]$RequireCompleteRuntimePayloads,

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
    throw "错误：找不到 package manifest：$ManifestPath。下一步：请从仓库/便携包根目录运行，或显式传入 -ManifestPath；脚本不会构建、签名、push 或操作 VM。"
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
        throw "错误：OutputRoot 位于仓库内，拒绝打包以避免误提交产物：$OutRoot。下一步：改用 D:\Temp\KSwordSandbox\packages 或其他仓库外目录；本脚本不会 push、发布或操作 VM。"
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
        throw "错误：RuntimePublishRoot 位于仓库内，拒绝从 bin/obj/x64 或源码树复制 runtime payload：$PublishRoot。下一步：先把 host-web、guest-tools、tools/job-tool、tools/postprocess 发布到 D:\Temp\KSwordSandbox\publish 或其他仓库外目录。"
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
    $caseInsensitiveForbiddenSegments = @(
        '.agents',
        '.cert',
        '.git',
        '.idea',
        '.vs',
        '.vscode',
        'bin',
        'captures',
        'coverage',
        'dist',
        'dumps',
        'logs',
        'memory-dumps',
        'obj',
        'packet-captures',
        'pcaps',
        'reports',
        'runtime',
        'checkpoints',
        'screenshots',
        'snapshots',
        'TestResults',
        'vm-state',
        'vms',
        'virtual-machines',
        'x64'
    )
    $sourceNamespaceSegments = @('artifacts', 'jobs', 'samples')
    $sourceNamespaceAllowList = @(
        'src/ksword.sandbox.abstractions/artifacts/',
        'src/ksword.sandbox.core/artifacts/',
        'src/ksword.sandbox.core/jobs/',
        'src/ksword.sandbox.core/samples/'
    )
    $normalizedLower = $normalized.ToLowerInvariant()

    foreach ($segment in $segments) {
        $segmentLower = $segment.ToLowerInvariant()
        if ($caseInsensitiveForbiddenSegments -contains $segmentLower) {
            throw "Forbidden package path segment '$segment' in '$normalized'."
        }

        if ($sourceNamespaceSegments -contains $segmentLower) {
            $isAllowedSourceNamespace = $false
            foreach ($allowedPrefix in $sourceNamespaceAllowList) {
                if ($normalizedLower.StartsWith($allowedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
                    $isAllowedSourceNamespace = $true
                    break
                }
            }

            if (-not $isAllowedSourceNamespace) {
                throw "Forbidden package path segment '$segment' in '$normalized'."
            }
        }
    }

    $fileName = [System.IO.Path]::GetFileName($normalized)
    $extension = [System.IO.Path]::GetExtension($normalized).ToLowerInvariant()
    if ($fileName -ieq 'CSignTool.exe' -or
        $fileName -ieq 'AuthenticodeVariantGUI.exe' -or
        $fileName -ieq 'signtool.exe' -or
        $fileName -ieq 'outer_display_info.dat' -or
        $fileName -like 'Sign-SandboxDriverWithKsword*.ps1') {
        throw "Forbidden signing tool or GUI signing fallback path in package: $normalized"
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

    $expectedRuntimePayloadLeaves = @{
        'host-web' = @('KSword.Sandbox.Web.exe|KSword.Sandbox.Web.dll')
        'guest-tools' = @('payload-manifest.json', 'agent/KSword.Sandbox.Agent.exe|agent/KSword.Sandbox.Agent.dll', 'r0collector/KSword.Sandbox.R0Collector.exe')
        'tools/job-tool' = @('KSword.Sandbox.JobTool.exe|KSword.Sandbox.JobTool.dll')
        'tools/postprocess' = @('KSword.Sandbox.PostProcess.exe|KSword.Sandbox.PostProcess.dll')
    }
    $forbiddenRuntimePublishExtensions = @('.pdb', '.sys', '.pcap', '.pcapng', '.dmp', '.mdmp', '.vhd', '.vhdx', '.avhd', '.avhdx', '.pfx', '.pem', '.key', '.dpapi', '.jsonl', '.sqlite', '.db', '.zip')
    $forbiddenRuntimePublishNames = @('sandbox.local.json', 'install-state.json', 'guest-password.dpapi', '.env', 'CSignTool.exe', 'AuthenticodeVariantGUI.exe', 'signtool.exe')

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
        $fileCount = 0
        $totalBytes = [Int64]0
        $missingExpectedLeaves = @()
        $forbiddenFilePreview = @()
        if (-not [string]::IsNullOrWhiteSpace($RuntimePublishRoot) -and -not [string]::IsNullOrWhiteSpace($source)) {
            $sourcePath = Join-SafePath -Root $RuntimePublishRoot -RelativePath $source
            $exists = Test-Path -LiteralPath $sourcePath -PathType Container
            if ($exists) {
                $files = @(Get-ChildItem -LiteralPath $sourcePath -Recurse -File -Force)
                $fileCount = $files.Count
                $totalBytes = [Int64](($files | ForEach-Object { $_.Length } | Measure-Object -Sum).Sum)
                $relativeFiles = @($files | ForEach-Object {
                        $fullName = [System.IO.Path]::GetFullPath($_.FullName)
                        $fullName.Substring($sourcePath.TrimEnd('\', '/').Length + 1).Replace('\', '/')
                    })
                $missingExpectedLeaves = @($expectedRuntimePayloadLeaves[$source] | Where-Object {
                        $leafAlternatives = @($_ -split '\|' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
                        $matched = $false
                        foreach ($leafAlternative in $leafAlternatives) {
                            if ($relativeFiles -contains $leafAlternative) {
                                $matched = $true
                                break
                            }
                        }
                        -not $matched
                    })
                $forbiddenFilePreview = @($files | Where-Object {
                        ($forbiddenRuntimePublishExtensions -contains $_.Extension.ToLowerInvariant()) -or ($forbiddenRuntimePublishNames -contains $_.Name)
                    } | ForEach-Object {
                        $_.FullName.Substring($sourcePath.TrimEnd('\', '/').Length + 1).Replace('\', '/')
                    } | Select-Object -First 20)
            }
        }

        [void]$entries.Add([pscustomobject][ordered]@{
                source = $source
                target = $target
                required = $required
                sourcePath = $sourcePath
                exists = $exists
                fileCount = $fileCount
                totalBytes = $totalBytes
                expectedLeaves = @($expectedRuntimePayloadLeaves[$source])
                missingExpectedLeaves = @($missingExpectedLeaves)
                forbiddenFilePreview = @($forbiddenFilePreview)
                note = $note
                remediation = if ($exists -and @($missingExpectedLeaves).Count -eq 0 -and @($forbiddenFilePreview).Count -eq 0) {
                    ''
                }
                elseif ([string]::IsNullOrWhiteSpace($RuntimePublishRoot)) {
                    "Provide -RuntimePublishRoot outside the repository when building a runtime package if this payload should be included: $source"
                }
                elseif (-not $exists) {
                    "Publish or copy '$source' under RuntimePublishRoot before cutting a portable runtime package."
                }
                elseif (@($missingExpectedLeaves).Count -gt 0) {
                    "Republish '$source'; expected leaf file(s) missing: $(@($missingExpectedLeaves) -join ', ')."
                }
                else {
                    "Remove forbidden/sensitive file(s) from '$source' before packaging: $(@($forbiddenFilePreview) -join ', ')."
                }
            })
    }

    return @($entries.ToArray())
}

function Get-PackageRuntimePublishSummary {
    param([object[]]$RuntimeEntries)

    $present = @($RuntimeEntries | Where-Object { [bool]$_.exists })
    $missing = @($RuntimeEntries | Where-Object { -not [bool]$_.exists })
    $incomplete = @($RuntimeEntries | Where-Object { [bool]$_.exists -and (@($_.missingExpectedLeaves).Count -gt 0 -or @($_.forbiddenFilePreview).Count -gt 0 -or [int]$_.fileCount -eq 0) })
    $missingRequired = @($missing | Where-Object { [bool]$_.required })
    $missingOptional = @($missing | Where-Object { -not [bool]$_.required })

    return [ordered]@{
        expectedCount = @($RuntimeEntries).Count
        presentCount = $present.Count
        missingCount = $missing.Count
        missingRequiredCount = $missingRequired.Count
        missingOptionalCount = $missingOptional.Count
        incompleteCount = $incomplete.Count
        missingRequiredSources = @($missingRequired | ForEach-Object { $_.source })
        missingOptionalSources = @($missingOptional | ForEach-Object { $_.source })
        incompleteSources = @($incomplete | ForEach-Object { $_.source })
        missingExpectedLeaves = @($RuntimeEntries | Where-Object { @($_.missingExpectedLeaves).Count -gt 0 } | ForEach-Object { [ordered]@{ source = $_.source; missing = @($_.missingExpectedLeaves) } })
        forbiddenFilePreviews = @($RuntimeEntries | Where-Object { @($_.forbiddenFilePreview).Count -gt 0 } | ForEach-Object { [ordered]@{ source = $_.source; forbidden = @($_.forbiddenFilePreview) } })
        completeRuntimePackageReady = if ($PackageKind -ne 'runtime') { $true } else { $missing.Count -eq 0 -and $incomplete.Count -eq 0 }
        layoutDryRun = ($PackageKind -eq 'runtime' -and ($missing.Count -gt 0 -or $incomplete.Count -gt 0))
        failureMode = if ($PackageKind -ne 'runtime') {
            'notApplicable'
        }
        elseif ([string]::IsNullOrWhiteSpace($RuntimePublishRoot)) {
            'runtimePublishRootNotProvided'
        }
        elseif ($missingRequired.Count -gt 0) {
            'missingRequiredRuntimePayload'
        }
        elseif ($missingOptional.Count -gt 0) {
            'missingOptionalRuntimePayload'
        }
        elseif ($incomplete.Count -gt 0) {
            'incompleteRuntimePayloadContents'
        }
        else {
            'ready'
        }
    }
}

function Get-PackageOperatorRecommendedActions {
    param(
        [object[]]$RuntimeEntries,
        [object]$RuntimeSummary
    )

    $actions = New-Object System.Collections.Generic.List[string]

    if ($PackageKind -eq 'runtime') {
        if ([string]::IsNullOrWhiteSpace($RuntimePublishRoot)) {
            [void]$actions.Add('下一步：如需完整 runtime 便携包，请先把 host-web、guest-tools、tools/job-tool、tools/postprocess 发布到仓库外目录，然后重跑 package-portable.ps1 -PackageKind runtime -RuntimePublishRoot <external-publish-root> -RequireCompleteRuntimePayloads。')
            [void]$actions.Add('下一步：仅做 layout/safety dry-run 时保留 -StageOnly 并检查 package-manifest.generated.json；正式 handoff 必须提供仓库外 RuntimePublishRoot 和 -RequireCompleteRuntimePayloads。')
        }
        elseif ([int]$RuntimeSummary.missingCount -gt 0) {
            [void]$actions.Add("下一步：补齐 RuntimePublishRoot 下缺失 payload：$(([string[]]@($RuntimeSummary.missingRequiredSources + $RuntimeSummary.missingOptionalSources)) -join ', ')。")
            [void]$actions.Add('下一步：补齐缺失 runtime folders 后重跑 package-portable.ps1；打包脚本本身不会构建，也不会复制文件进 VM。')
        }
        elseif ([int]$RuntimeSummary.incompleteCount -gt 0) {
            [void]$actions.Add("下一步：重新发布不完整 runtime payload：$(([string[]]@($RuntimeSummary.incompleteSources)) -join ', ')；确认预期 exe/dll/payload-manifest 存在，且没有 .pdb/.sys/pcap/dump/VM/secret/signing 文件。")
        }
        else {
            [void]$actions.Add('下一步：RuntimePublishRoot payload 已齐备；handoff 前检查 package-manifest.generated.json 的 fileInventory、operatorDiagnostics 和 safetyContract。')
        }
    }
    else {
        [void]$actions.Add('下一步：source package 必须保持 source-only；不要加入 runtime payload、报告、样本、VM state 或 build output。')
    }

    [void]$actions.Add('发布前只读检查：.\scripts\Test-ReleaseReadiness.ps1 -AllowDirtySource；该命令默认执行 source package StageOnly dry-run，不启动/还原 VM，不签名，不调用 CSignTool.exe。')
    [void]$actions.Add('Hyper-V/VM profile/guest payload/VT key 缺口请用 .\scripts\install.ps1 -Mode CheckEnvironment 或 .\scripts\run.ps1 -Mode CheckEnvironment 查看；这些状态检查不打印 secret，不执行 live。')
    [void]$actions.Add('fresh live 证据护栏：package/readiness 不会生成新的 Notepad 5s job；release notes 若要声明当前候选已有 fresh live evidence，必须在实验室主机显式运行 live 并记录 commit、job id、runtime root 和报告路径。')
    [void]$actions.Add('缺少 guest payload 时运行 .\scripts\Prepare-GuestPayload.ps1 -RepoRoot . -PayloadRoot <external-payload-root> -SelfContained；输出必须在仓库外。')
    [void]$actions.Add('可选 VirusTotal key 用 .\scripts\install.ps1 -Mode ConfigureVTKey -PromptVTKey 配置；未配置或查询失败应静默跳过 hash-only enrichment。')

    return @($actions.ToArray())
}

function Write-PackageOperatorDiagnostic {
    param(
        [Parameter(Mandatory)]
        [string]$Chinese,

        [string]$English = ''
    )

    if ([string]::IsNullOrWhiteSpace($English)) {
        Write-Host "[package] $Chinese"
        return
    }

    Write-Host "[package] $Chinese / $English"
}

function Update-PackageOperatorDiagnostics {
    param([Parameter(Mandatory)][object]$Manifest)

    $runtimeEntries = @(Get-RuntimePublishEntryDiagnostics -Manifest $Manifest)
    $missingRuntimeEntries = @($runtimeEntries | Where-Object { -not [bool]$_.exists })
    $runtimeSummary = Get-PackageRuntimePublishSummary -RuntimeEntries $runtimeEntries
    $recommendedActions = Get-PackageOperatorRecommendedActions -RuntimeEntries $runtimeEntries -RuntimeSummary $runtimeSummary
    $script:operatorDiagnostics = [ordered]@{
        packageKind = $PackageKind
        runtimePublishRootProvided = -not [string]::IsNullOrWhiteSpace($RuntimePublishRoot)
        runtimePublishRoot = if ([string]::IsNullOrWhiteSpace($RuntimePublishRoot)) { $null } else { $RuntimePublishRoot }
        runtimePublishRootRequiredForCompleteRuntime = ($PackageKind -eq 'runtime')
        runtimePublishRootMustBeOutsideRepository = $true
        runtimePublishEntries = @($runtimeEntries)
        runtimePublishSummary = $runtimeSummary
        missingRuntimePublishEntries = @($missingRuntimeEntries | ForEach-Object { $_.source })
        incompleteRuntimePublishEntries = @($runtimeEntries | Where-Object { [bool]$_.exists -and (@($_.missingExpectedLeaves).Count -gt 0 -or @($_.forbiddenFilePreview).Count -gt 0 -or [int]$_.fileCount -eq 0) } | ForEach-Object { $_.source })
        runtimePublishReady = if ($PackageKind -ne 'runtime') { $true } else { $missingRuntimeEntries.Count -eq 0 -and [int]$runtimeSummary.incompleteCount -eq 0 }
        completeRuntimePayloadsRequired = [bool]$RequireCompleteRuntimePayloads
        runtimeArchiveRequiresCompleteRuntimePayloads = ($PackageKind -eq 'runtime')
        runtimeArchiveMode = if ($PackageKind -ne 'runtime') {
            'sourceArchive'
        }
        elseif ($StageOnly.IsPresent) {
            'layoutDryRunStageOnly'
        }
        elseif ($RequireCompleteRuntimePayloads.IsPresent) {
            'completeRuntimeHandoffArchive'
        }
        else {
            'blockedIncompleteRuntimeArchive'
        }
        runtimeDryRunGuardrail = [ordered]@{
            isLayoutDryRun = ($PackageKind -eq 'runtime' -and ($StageOnly.IsPresent -or -not [bool]$RequireCompleteRuntimePayloads -or $missingRuntimeEntries.Count -gt 0 -or [int]$runtimeSummary.incompleteCount -gt 0))
            handoffAllowed = ($PackageKind -ne 'runtime' -or ((-not $StageOnly.IsPresent) -and [bool]$RequireCompleteRuntimePayloads -and $missingRuntimeEntries.Count -eq 0 -and [int]$runtimeSummary.incompleteCount -eq 0 -and -not [string]::IsNullOrWhiteSpace($RuntimePublishRoot)))
            handoffRequires = @(
                '仓库外 RuntimePublishRoot / external RuntimePublishRoot',
                '-RequireCompleteRuntimePayloads',
                'runtimePublishSummary.missingCount = 0',
                'runtimePublishSummary.incompleteCount = 0',
                'payload folders contain expected exe/dll/manifest leaves and no forbidden VM/secret/signing/evidence files',
                'not -StageOnly'
            )
            chinese = '中文提示：runtime layout dry-run 只用于审阅目录和安全合约，不能作为可运行 handoff；完整 runtime zip 必须满足 handoffRequires。'
        }
        runtimePublishRootMissingRecommendedActions = @($recommendedActions | Where-Object { $_ -match 'RuntimePublishRoot|runtime 便携包|payload' })
        preflightCommands = [ordered]@{
            releaseReadiness = '.\scripts\Test-ReleaseReadiness.ps1 -AllowDirtySource'
            completeRuntimeReadiness = '.\scripts\Test-ReleaseReadiness.ps1 -AllowDirtySource -RuntimePublishRoot <external-publish-root> -RequireCompleteRuntimePackage'
            installCheckEnvironment = '.\scripts\install.ps1 -Mode CheckEnvironment'
            runCheckEnvironment = '.\scripts\run.ps1 -Mode CheckEnvironment'
            prepareGuestPayload = '.\scripts\Prepare-GuestPayload.ps1 -RepoRoot . -PayloadRoot <external-payload-root> -SelfContained'
            configureVirusTotalKey = '.\scripts\install.ps1 -Mode ConfigureVTKey -PromptVTKey'
            runtimePackage = '.\scripts\package-portable.ps1 -PackageKind runtime -RuntimePublishRoot <external-publish-root> -RequireCompleteRuntimePayloads -OutputRoot <external-output-root> -Force'
        }
        externalStateDiagnostics = [ordered]@{
            HyperV = 'not checked or mutated by packaging; run install/run CheckEnvironment for read-only prerequisite diagnostics including Hyper-V module, elevation, hardware virtualization hints, VM/checkpoint presence, and Guest Service Interface'
            VmProfile = 'local VM name, checkpoint, guest working directory, driver host path, and runtime roots are operator-local profile values; they are diagnosed by install/run status and are not packaged as sandbox.local.json'
            GuestPayload = 'runtime payload is copied only from RuntimePublishRoot or prepared explicitly under an external PayloadRoot; packaging records present/missing/incomplete payload folders, expected exe/dll/manifest leaves, and forbidden file previews but does not build them'
            VirusTotal = 'optional hash-only VirusTotal API key is never packaged or printed; configure in process/user environment or installer local state; this is unrelated to Intel VT-x/AMD-V virtualization'
            RuntimeRoot = 'job outputs, reports, screenshots, PCAP, dumps, samples, and secrets must remain outside the repository and package source tree'
        }
        safeExclusionCategories = @(
            'local secrets and environment files',
            'install-state and DPAPI backups',
            'submitted samples and generated harmless samples',
            'runtime job outputs, reports, events, screenshots, PCAP/captures, dumps, traces, and databases',
            'Hyper-V disks, checkpoints, snapshots, and VM export/state files',
            'repository build outputs, symbols, packages, archives, and native intermediates',
            'driver binaries, certificates, private keys, signing material, GUI signing fallback, and CSignTool'
        )
        nonMutating = [ordered]@{
            vmMutation = $false
            driverSigning = $false
            guiSigningFallback = $false
            csignTool = $false
            gitPush = $false
            networkPublish = $false
        }
        freshLiveEvidenceGuardrail = [ordered]@{
            packagingCreatesFreshLiveEvidence = $false
            releaseReadinessCreatesFreshLiveEvidence = $false
            freshNotepad5sClaimRequiresLabRun = $true
            liveCommand = '.\run.ps1 -Mode Analyze -SamplePreset Notepad -DurationSeconds 5 -Live'
            requiredReleaseNoteFields = @('commit', 'jobId', 'runtimeRoot', 'generatedAtUtc/localTime', 'report.json/report.zh.html/report.en.html paths')
            chinese = '中文提示：本脚本只做本机 staging/zip，不启动 Hyper-V live；没有记录 live job id 时，release notes 必须写“本候选未刷新 fresh live evidence”。'
        }
        recommendedActions = @($recommendedActions)
        operatorGuidance = @(
            '中文：先看 runtimePublishSummary、runtimeDryRunGuardrail、safeExclusionCategories、externalStateDiagnostics、freshLiveEvidenceGuardrail；这些字段告诉审阅者本包是否可 handoff，以及是否不能声称 fresh live。',
            '中文：完整 runtime handoff 必须提供仓库外 RuntimePublishRoot、传入 -RequireCompleteRuntimePayloads，并确保所有 runtime publish entries 存在。',
            'RuntimePublishRoot must point to external published payloads such as host-web, guest-tools, tools/job-tool, and tools/postprocess.',
            'Use -RequireCompleteRuntimePayloads for handoff builds; omit it only for explicit layout/safety dry-runs.',
            'The package script stages and zips locally only; it does not build, sign, push, publish, start Hyper-V, or copy files into a VM.',
            'Inspect package-manifest.generated.json before handoff; verify fileInventory sha256/sizeBytes and packageDiagnostics.'
        )
        chineseGuidance = '中文提示：runtime 便携包如果没有 RuntimePublishRoot 也可做 layout dry-run；完整交付必须传入仓库外 RuntimePublishRoot 并使用 -RequireCompleteRuntimePayloads。package/readiness 不会生成 fresh live evidence。'
    }
}

# Assert-RuntimePackageArchiveRequiresCompletePayloads prevents accidental
# portable-runtime archives that contain docs/scripts but no published WebUI,
# guest tools, or JobTool payloads. Layout inspection is still available through
# -StageOnly; a zip/archive handoff must be explicit and complete.
function Assert-RuntimePackageArchiveRequiresCompletePayloads {
    if ($PackageKind -ne 'runtime' -or $StageOnly.IsPresent) {
        return
    }

    if (-not $RequireCompleteRuntimePayloads.IsPresent) {
        throw "错误：runtime 便携包生成 zip 时必须显式传入 -RequireCompleteRuntimePayloads，避免把 layout dry-run 误交付为可运行包。下一步：完整交付请提供仓库外 -RuntimePublishRoot 并加 -RequireCompleteRuntimePayloads；只审阅 layout/safety 时请加 -StageOnly。"
    }

    if ([string]::IsNullOrWhiteSpace($RuntimePublishRoot)) {
        throw "错误：完整 runtime 便携包要求仓库外 -RuntimePublishRoot。下一步：先发布 host-web、guest-tools、tools/job-tool、tools/postprocess 到 D:\Temp\KSwordSandbox\publish 或其他仓库外目录，再重跑 package-portable.ps1。"
    }

    $summary = $script:operatorDiagnostics.runtimePublishSummary
    if ($null -ne $summary -and [int]$summary.missingCount -gt 0) {
        $missing = @([string[]]@($summary.missingRequiredSources + $summary.missingOptionalSources)) -join ', '
        throw "错误：完整 runtime 便携包缺少 published payload：$missing。下一步：补齐 RuntimePublishRoot 后重跑；package-portable.ps1 不会从仓库 bin/obj/x64 兜底复制，也不会构建、签名或操作 VM。"
    }

    if ($null -ne $summary -and [int]$summary.incompleteCount -gt 0) {
        $incomplete = @([string[]]@($summary.incompleteSources)) -join ', '
        throw "错误：完整 runtime 便携包存在不完整或不安全的 payload：$incomplete。下一步：重新发布这些目录，确认预期 exe/dll/payload-manifest 存在且不含 .pdb/.sys/pcap/dump/VM/secret/signing 文件。"
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
            if ($required -or $RequireCompleteRuntimePayloads.IsPresent) {
                throw "错误：完整 runtime 便携包要求 RuntimePublishRoot，且必须包含 runtime payload：$source。下一步：把 host-web、guest-tools、tools/job-tool、tools/postprocess 发布到仓库外目录后，重跑 package-portable.ps1 -PackageKind runtime -RuntimePublishRoot <external-publish-root> -RequireCompleteRuntimePayloads。"
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
        if ($required -or ($sourceType -eq 'runtimePublish' -and $RequireCompleteRuntimePayloads.IsPresent)) {
            throw "错误：完整 runtime 便携包缺少 payload：$sourcePath。下一步：先发布/复制 '$source' 到仓库外 RuntimePublishRoot；本脚本不会从仓库 bin/obj/x64 兜底复制，也不会构建、签名或操作 VM。"
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
            runtimeCompleteness = if ($PackageKind -ne 'runtime') { 'not applicable' } elseif ($RequireCompleteRuntimePayloads.IsPresent) { 'required' } else { 'layout dry-run allowed' }
        }
        safetyContract = [ordered]@{
            Chinese = '中文提示：package-portable.ps1 已按 manifest 和硬性扩展/路径规则排除 secrets、本机状态、VM 磁盘/快照、样本、报告、截图、PCAP、dump、仓库二进制、legacy signing tool 和 GUI signing fallback；脚本不发布、不推送、不签名、不操作 VM。'
            SensitiveMaterial = 'not packaged'
            VmState = 'not packaged'
            VmMutation = 'not performed'
            RepositoryBuildOutput = 'not packaged'
            RuntimeBinariesSource = if ($PackageKind -eq 'runtime') { 'external RuntimePublishRoot only' } else { 'not packaged' }
            RuntimeArchivePolicy = if ($PackageKind -eq 'runtime') { 'non-StageOnly runtime archives require -RequireCompleteRuntimePayloads and a complete external RuntimePublishRoot' } else { 'source package is source-only' }
            NetworkPublish = 'not performed'
            GitPush = 'not performed'
            DriverSigning = 'not performed'
            GuiSigningFallback = 'not called and forbidden from package contents'
            CSignTool = 'not called and forbidden from package contents'
            FreshLiveEvidence = 'not generated by packaging; release notes must record an explicit lab job id before claiming current live validation'
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
    if (-not (Test-Path -LiteralPath $RuntimePublishRoot -PathType Container)) {
        throw "错误：RuntimePublishRoot 不存在或不是目录：$RuntimePublishRoot。下一步：先把 host-web、guest-tools、tools/job-tool、tools/postprocess 发布/复制到仓库外目录，或不传 -RuntimePublishRoot 并使用 -StageOnly 做 layout dry-run；本脚本不会替你构建、签名或操作 VM。"
    }

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
Assert-RuntimePackageArchiveRequiresCompletePayloads

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

Write-PackageOperatorDiagnostic -Chinese "包类型：$PackageKind" -English "Kind: $PackageKind"
Write-PackageOperatorDiagnostic -Chinese "版本：$Version" -English "Version: $Version"
Write-PackageOperatorDiagnostic -Chinese "文件数：$($script:copiedFiles.Count)" -English "Files: $($script:copiedFiles.Count)"
Write-PackageOperatorDiagnostic -Chinese "暂存目录：$stageRoot" -English "Stage: $stageRoot"
Write-PackageOperatorDiagnostic -Chinese "生成元数据：$(Join-SafePath -Root $stageRoot -RelativePath 'package-manifest.generated.json')" -English 'Metadata: package-manifest.generated.json'
$payloadByteCount = [Int64](($script:copiedFileRecords | Where-Object { $_.sourceType -ne 'generated' } | ForEach-Object { $_.sizeBytes } | Measure-Object -Sum).Sum)
Write-PackageOperatorDiagnostic -Chinese "payload 字节数：$payloadByteCount" -English "Payload bytes: $payloadByteCount"
Write-PackageOperatorDiagnostic -Chinese "可选/跳过条目：$($script:packageDiagnostics.Count)" -English "Optional/skipped entries: $($script:packageDiagnostics.Count)"
if ($PackageKind -eq 'runtime') {
    $runtimeRootDisplay = if ([string]::IsNullOrWhiteSpace($RuntimePublishRoot)) { '<not provided>' } else { $RuntimePublishRoot }
    Write-PackageOperatorDiagnostic -Chinese "RuntimePublishRoot：$runtimeRootDisplay" -English "RuntimePublishRoot: $runtimeRootDisplay"
    Write-PackageOperatorDiagnostic -Chinese "完整 runtime payload 要求：$([bool]$RequireCompleteRuntimePayloads)" -English "RequireCompleteRuntimePayloads: $([bool]$RequireCompleteRuntimePayloads)"
    foreach ($entry in @($script:operatorDiagnostics.runtimePublishEntries)) {
        $entryState = if ([bool]$entry.exists) { 'present' } elseif ([bool]$entry.required) { 'missing-required' } else { 'missing-optional' }
        $entryChineseState = switch ($entryState) {
            'present' { '存在' }
            'missing-required' { '缺少-必需' }
            default { '缺少-可选' }
        }
        Write-PackageOperatorDiagnostic -Chinese "runtime 条目：$entryChineseState source=$($entry.source) target=$($entry.target) files=$($entry.fileCount) bytes=$($entry.totalBytes) missingLeaves=$(@($entry.missingExpectedLeaves).Count) forbidden=$(@($entry.forbiddenFilePreview).Count)" -English "Runtime entry: $entryState source=$($entry.source) target=$($entry.target) files=$($entry.fileCount) bytes=$($entry.totalBytes) missingLeaves=$(@($entry.missingExpectedLeaves).Count) forbidden=$(@($entry.forbiddenFilePreview).Count)"
    }
    if (-not [bool]$script:operatorDiagnostics.runtimePublishReady) {
        Write-PackageOperatorDiagnostic -Chinese '中文提示：runtime 包存在缺失的 published payload；本次仅可作为 layout/safety dry-run。完整交付请补齐 RuntimePublishRoot 并传入 -RequireCompleteRuntimePayloads。'
    }
    $summary = $script:operatorDiagnostics.runtimePublishSummary
    Write-PackageOperatorDiagnostic -Chinese "runtime 摘要：存在=$($summary.presentCount) 缺失=$($summary.missingCount) 不完整=$($summary.incompleteCount) 必需缺失=$($summary.missingRequiredCount) 可选缺失=$($summary.missingOptionalCount) 模式=$($summary.failureMode)" -English "Runtime summary: present=$($summary.presentCount) missing=$($summary.missingCount) incomplete=$($summary.incompleteCount) missingRequired=$($summary.missingRequiredCount) missingOptional=$($summary.missingOptionalCount) mode=$($summary.failureMode)"
    Write-PackageOperatorDiagnostic -Chinese "runtime handoff 允许：$($script:operatorDiagnostics.runtimeDryRunGuardrail.handoffAllowed)" -English "Runtime handoff allowed: $($script:operatorDiagnostics.runtimeDryRunGuardrail.handoffAllowed)"
    foreach ($action in @($script:operatorDiagnostics.recommendedActions | Select-Object -First 4)) {
        $actionLine = if ($action -match '^(下一步：|Next:)') { $action } else { "下一步：$action" }
        Write-PackageOperatorDiagnostic -Chinese $actionLine -English 'Next'
    }
}
Write-PackageOperatorDiagnostic -Chinese '中文提示：已排除本机 secret、install-state、DPAPI 备份、样本、报告、VM 磁盘/快照、仓库二进制、签名材料和 GUI signing fallback。'
Write-PackageOperatorDiagnostic -Chinese 'fresh live 证据：未生成；若发布说明要声称当前候选已刷新真实 Notepad 5s，请先在实验室主机运行 live 并记录 job id。' -English 'Fresh live evidence: not generated by packaging.'
Write-PackageOperatorDiagnostic -Chinese '安全合约：不修改 VM、不签名 driver、不使用 GUI signing fallback、不调用 CSignTool、不 git push/publish。' -English 'Safety: no VM mutation, no driver signing, no GUI signing fallback, no CSignTool, no git push/publish.'
if ($StageOnly.IsPresent) {
    Write-PackageOperatorDiagnostic -Chinese '压缩包：已跳过（-StageOnly，仅 layout/safety dry-run）' -English 'Archive: skipped (-StageOnly)'
}
else {
    Write-PackageOperatorDiagnostic -Chinese "压缩包：$archivePath" -English "Archive: $archivePath"
    $archiveHash = Get-FileSha256Hex -Path $archivePath
    Write-PackageOperatorDiagnostic -Chinese "压缩包 SHA256：$archiveHash" -English "Archive SHA256: $archiveHash"
}
Write-PackageOperatorDiagnostic -Chinese '网络发布/git push：未执行' -English 'Network publish/push: not performed'
