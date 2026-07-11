<#
.SYNOPSIS
Checks that tracked or candidate files are safe for the source repository.

.DESCRIPTION
Inputs are git-index files or untracked source files. Processing rejects large
files, VM images/checkpoints, build binaries, runtime evidence, samples,
reports, signing material, local state, and generated package metadata. The
script returns exit code 0 when policy passes and 1 when violations are found.
#>
[CmdletBinding()]
param(
    [string]$RepositoryRoot,
    [int64]$MaxBytes = 25000000,
    [switch]$StagedOnly,
    [string[]]$SecretEnvironmentNames = @('KSWORDBOX_GUEST_PASSWORD', 'KSWORDBOX_VIRUSTOTAL_API_KEY'),
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
    $fileName = [System.IO.Path]::GetFileName($normalized).ToLowerInvariant()
    $segments = @($normalized -split '/' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $normalizedLower = $normalized.ToLowerInvariant()
    $forbiddenExtensions = @(
        '.7z', '.a', '.appx', '.avhd', '.avhdx', '.bin', '.bmp', '.cab',
        '.cap', '.cer', '.crt', '.crash', '.csr', '.db', '.der', '.dll',
        '.dmp', '.doc', '.docx', '.dpapi', '.dump', '.esd', '.etl', '.evtx',
        '.exe', '.exp', '.gif', '.gz', '.har', '.heapsnapshot', '.hprof',
        '.ilk', '.iso', '.jpeg', '.jpg', '.jsonl', '.key', '.kdbx', '.lib',
        '.log', '.mdmp', '.mem', '.mrt', '.msi', '.msix', '.nettrace',
        '.nvram', '.o', '.obj', '.ova', '.ovf', '.p12', '.pcap', '.pcapng',
        '.pdb', '.pdf', '.pem', '.pfx', '.png', '.rar', '.raw', '.snk',
        '.sqlite', '.sqlite3', '.sys', '.tar', '.trace', '.vhd', '.vhdpmem',
        '.vhdset', '.vhdx', '.vmcx', '.vmgs', '.vmrs', '.vsv', '.webp',
        '.wer', '.wim', '.xls', '.xlsx', '.zip'
    )
    $caseInsensitiveForbiddenSegments = @(
        '.agents', '.cert', '.vs', 'bin', 'captures', 'checkpoints',
        'coverage', 'dist', 'dumps', 'logs', 'memory-dumps', 'obj',
        'packet-captures', 'pcaps', 'reports', 'runtime', 'screenshots',
        'snapshots', 'TestResults', 'virtual-machines', 'vm-state', 'vms',
        'x64'
    )
    $sourceNamespaceSegments = @('artifacts', 'jobs', 'samples')
    $sourceNamespaceAllowList = @(
        'src/ksword.sandbox.abstractions/artifacts/',
        'src/ksword.sandbox.core/artifacts/',
        'src/ksword.sandbox.core/jobs/',
        'src/ksword.sandbox.core/samples/'
    )
    $forbiddenRootPrefixes = @(
        'app/host-web/',
        'payload/guest-tools/',
        'packages/',
        'staging/'
    )
    $forbiddenFileNames = @(
        '.env',
        'appsettings.local.json',
        'authenticodevariantgui.exe',
        'csigntool.exe',
        'guest-password.dpapi',
        'id_dsa',
        'id_ecdsa',
        'id_ed25519',
        'id_rsa',
        'install-state.json',
        'outer_display_info.dat',
        'package-manifest.generated.json',
        'sandbox.local.json',
        'secrets.json',
        'signtool.exe',
        'user-secrets.json',
        'usersecrets.json'
    )
    $forbiddenFileNamePatterns = @(
        '*.deps.json',
        '*.local.json',
        '*.runtimeconfig.json',
        '*.secret.json',
        '*.staticwebassets.runtime.json',
        '.env.*'
    )

    if ($forbiddenExtensions -contains $extension) {
        return $true
    }

    if ($forbiddenFileNames -contains $fileName) {
        return $true
    }

    foreach ($pattern in $forbiddenFileNamePatterns) {
        if ($fileName -like $pattern) {
            return $true
        }
    }

    foreach ($segment in $segments) {
        $segmentLower = $segment.ToLowerInvariant()
        if ($caseInsensitiveForbiddenSegments -contains $segmentLower) {
            return $true
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
                return $true
            }
        }
    }

    foreach ($prefix in $forbiddenRootPrefixes) {
        if ($normalized -clike "$prefix*") {
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
        '.7z', '.a', '.appx', '.avhd', '.avhdx', '.bin', '.bmp', '.cab',
        '.cap', '.cer', '.crt', '.crash', '.csr', '.db', '.der', '.dll',
        '.dmp', '.doc', '.docx', '.dpapi', '.dump', '.esd', '.etl', '.evtx',
        '.exe', '.exp', '.gif', '.gz', '.har', '.heapsnapshot', '.hprof',
        '.ico', '.ilk', '.iso', '.jpeg', '.jpg', '.jsonl', '.key', '.kdbx',
        '.lib', '.log', '.mdmp', '.mem', '.mrt', '.msi', '.msix',
        '.nettrace', '.nvram', '.o', '.obj', '.ova', '.ovf', '.p12',
        '.pcap', '.pcapng', '.pdb', '.pdf', '.pem', '.pfx', '.png', '.rar',
        '.raw', '.snk', '.sqlite', '.sqlite3', '.sys', '.tar', '.trace',
        '.vhd', '.vhdpmem', '.vhdset', '.vhdx', '.vmcx', '.vmgs', '.vmrs',
        '.vsv', '.webp', '.wer', '.wim', '.xls', '.xlsx', '.zip'
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
    $violations | ForEach-Object { Write-Error $_ -ErrorAction Continue }
    Write-Host '中文提示：仓库策略拒绝二进制、runtime/job 产物、VM 状态、签名材料、本机 secret 和生成的 package manifest。下一步：把这些文件移到 D:\Temp\KSwordSandbox 或其他仓库外 runtime/publish 目录。'
    exit 1
}

Write-Host "Repository policy passed."
exit 0
