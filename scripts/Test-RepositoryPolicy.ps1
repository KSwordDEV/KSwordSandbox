<#
.SYNOPSIS
Checks that tracked or candidate files are safe for the source repository.

.DESCRIPTION
Inputs are git-index files or untracked source files. Processing rejects large
files, VM images, binaries, samples, reports, and build outputs. The script
returns exit code 0 when policy passes and 1 when violations are found.
#>
[CmdletBinding()]
param(
    [string]$RepositoryRoot,
    [int64]$MaxBytes = 25000000,
    [switch]$StagedOnly,
    [string[]]$SecretEnvironmentNames = @('KSWORDBOX_GUEST_PASSWORD'),
    [int]$MinSecretValueLength = 8,
    [switch]$SkipSecretValueScan
)

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

# Get-CandidateFiles gathers either staged files or all addable files.
# Inputs are the StagedOnly switch; processing calls git without modifying the
# worktree; the function returns repository-relative file paths.
function Get-CandidateFiles {
    param([bool]$OnlyStaged)

    if ($OnlyStaged) {
        return @(git -C $RepositoryRoot diff --cached --name-only --diff-filter=ACMR)
    }

    return @(git -C $RepositoryRoot ls-files --cached --others --exclude-standard)
}

# Test-ForbiddenPath checks whether a path should never enter git.
# Inputs are one repository-relative path; processing checks extension and
# directory fragments; the function returns $true for policy violations.
function Test-ForbiddenPath {
    param([string]$Path)

    $normalized = $Path -replace '\\', '/'
    $extension = [System.IO.Path]::GetExtension($normalized).ToLowerInvariant()
    $forbiddenExtensions = @(
        '.vhd', '.vhdx', '.avhd', '.avhdx', '.iso', '.wim', '.esd',
        '.exe', '.dll', '.sys', '.pdb', '.lib', '.obj', '.ilk', '.exp',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.zip', '.7z', '.rar',
        '.pfx', '.p12', '.cer', '.key', '.dpapi',
        '.msi', '.msix', '.appx', '.cab', '.ova', '.ovf', '.tar', '.gz',
        '.crt', '.pem', '.der', '.csr', '.snk',
        '.etl', '.dmp', '.evtx', '.pcap', '.pcapng', '.bmp'
    )
    $forbiddenFragments = @('/bin/', '/obj/', '/x64/', '/.vs/', '/dist/')
    $forbiddenRootPrefixes = @('runtime/', 'reports/', 'samples/', 'captures/', 'logs/')
    $forbiddenFileNames = @('install-state.json', 'guest-password.dpapi')

    if ($forbiddenExtensions -contains $extension) {
        return $true
    }

    if ($forbiddenFileNames -contains ([System.IO.Path]::GetFileName($normalized).ToLowerInvariant())) {
        return $true
    }

    foreach ($fragment in $forbiddenFragments) {
        if ("/$normalized" -like "*$fragment*") {
            return $true
        }
    }

    foreach ($prefix in $forbiddenRootPrefixes) {
        if ($normalized -like "$prefix*") {
            return $true
        }
    }

    return $false
}

# Get-SecretValuesForPolicy returns current environment secret values that are
# long enough to scan without noisy matches. Inputs are variable names and the
# minimum length. Processing checks Process, User, and Machine scopes; return
# behavior never prints secret values.
function Get-SecretValuesForPolicy {
    param(
        [string[]]$Names,
        [int]$MinimumLength
    )

    $values = New-Object System.Collections.Generic.List[object]
    foreach ($name in $Names) {
        if ([string]::IsNullOrWhiteSpace($name)) {
            continue
        }

        foreach ($scope in @('Process', 'User', 'Machine')) {
            $value = [Environment]::GetEnvironmentVariable($name, $scope)
            if ([string]::IsNullOrEmpty($value) -or $value.Length -lt $MinimumLength) {
                continue
            }

            [void]$values.Add([pscustomobject][ordered]@{
                    Name  = $name
                    Scope = $scope
                    Value = $value
                })
            break
        }
    }

    return @($values.ToArray())
}

# Test-SecretScanCandidate checks whether a file is safe to read as text for
# secret scanning. Inputs are a repository-relative path and item metadata.
# Return behavior is $true only for reasonably small text-like files.
function Test-SecretScanCandidate {
    param(
        [string]$Path,
        [System.IO.FileInfo]$Item
    )

    if ($null -eq $Item) {
        return $false
    }

    if ($Item.Length -gt $MaxBytes) {
        return $false
    }

    $extension = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()
    $binaryExtensions = @(
        '.vhd', '.vhdx', '.avhd', '.avhdx', '.iso', '.wim', '.esd',
        '.exe', '.dll', '.sys', '.pdb', '.lib', '.obj', '.ilk', '.exp',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.zip', '.7z', '.rar',
        '.pfx', '.p12', '.cer', '.key', '.dpapi', '.png', '.jpg', '.jpeg',
        '.gif', '.ico', '.bmp', '.snk', '.pcap', '.pcapng', '.etl', '.dmp',
        '.evtx'
    )

    return ($binaryExtensions -notcontains $extension)
}

$secretValues = @()
if (-not $SkipSecretValueScan) {
    $secretValues = @(Get-SecretValuesForPolicy -Names $SecretEnvironmentNames -MinimumLength $MinSecretValueLength)
}

$violations = New-Object System.Collections.Generic.List[string]
foreach ($file in Get-CandidateFiles -OnlyStaged:$StagedOnly.IsPresent) {
    if ([string]::IsNullOrWhiteSpace($file)) {
        continue
    }

    if (Test-ForbiddenPath -Path $file) {
        $violations.Add("Forbidden path or extension: $file")
        continue
    }

    $fullPath = Join-Path $RepositoryRoot $file
    if (Test-Path -LiteralPath $fullPath -PathType Leaf) {
        $item = Get-Item -LiteralPath $fullPath
        $length = $item.Length
        if ($length -gt $MaxBytes) {
            $violations.Add("File exceeds $MaxBytes bytes: $file ($length)")
        }

        if ($secretValues.Count -gt 0 -and (Test-SecretScanCandidate -Path $file -Item $item)) {
            try {
                $content = Get-Content -LiteralPath $fullPath -Raw -ErrorAction Stop
                foreach ($secret in $secretValues) {
                    if ($content.IndexOf([string]$secret.Value, [System.StringComparison]::Ordinal) -ge 0) {
                        $violations.Add("Secret value from environment variable '$($secret.Name)' appears in candidate file: $file. Value was not printed.")
                    }
                }
            }
            catch {
                # Ignore unreadable text candidates here; forbidden path/size
                # checks above still protect the repository from large/binary
                # artifacts.
            }
        }
    }
}

if ($violations.Count -gt 0) {
    $violations | ForEach-Object { Write-Error $_ }
    exit 1
}

Write-Host "Repository policy passed."
exit 0
