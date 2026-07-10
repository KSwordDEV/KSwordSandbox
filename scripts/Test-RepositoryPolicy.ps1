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
    [int64]$MaxBytes = 25000000,
    [switch]$StagedOnly
)

$ErrorActionPreference = 'Stop'

# Get-CandidateFiles gathers either staged files or all addable files.
# Inputs are the StagedOnly switch; processing calls git without modifying the
# worktree; the function returns repository-relative file paths.
function Get-CandidateFiles {
    param([bool]$OnlyStaged)

    if ($OnlyStaged) {
        return @(git diff --cached --name-only --diff-filter=ACMR)
    }

    return @(git ls-files --cached --others --exclude-standard)
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
        '.pfx', '.p12', '.cer', '.key'
    )
    $forbiddenFragments = @('/bin/', '/obj/', '/x64/', '/.vs/', '/dist/')
    $forbiddenRootPrefixes = @('runtime/', 'reports/', 'samples/', 'captures/', 'logs/')

    if ($forbiddenExtensions -contains $extension) {
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

$violations = New-Object System.Collections.Generic.List[string]
foreach ($file in Get-CandidateFiles -OnlyStaged:$StagedOnly.IsPresent) {
    if ([string]::IsNullOrWhiteSpace($file)) {
        continue
    }

    if (Test-ForbiddenPath -Path $file) {
        $violations.Add("Forbidden path or extension: $file")
        continue
    }

    if (Test-Path -LiteralPath $file -PathType Leaf) {
        $length = (Get-Item -LiteralPath $file).Length
        if ($length -gt $MaxBytes) {
            $violations.Add("File exceeds $MaxBytes bytes: $file ($length)")
        }
    }
}

if ($violations.Count -gt 0) {
    $violations | ForEach-Object { Write-Error $_ }
    exit 1
}

Write-Host "Repository policy passed."
exit 0
