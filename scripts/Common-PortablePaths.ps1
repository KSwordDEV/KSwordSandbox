<#
.SYNOPSIS
Shared portable-path resolution for KSwordSandbox operational scripts.

.DESCRIPTION
Every operational PowerShell script historically defaulted its runtime /
payload / output paths to the original lab machine's D:\Temp\KSwordSandbox.
A machine without a D: drive therefore failed at parameter binding or, worse,
silently looked for configuration in a directory that does not exist.

Dot-source this module and use the resolvers instead of hardcoding a default:

    . (Join-Path $PSScriptRoot 'Common-PortablePaths.ps1')
    $runtime = Get-PortableRuntimeRoot -Explicit $RuntimeRoot
    $payload = Get-PortableGuestPayloadRoot -Explicit $GuestPayloadRoot -RuntimeRoot $runtime

Resolution order for the runtime root is identical everywhere:
  1. an explicit caller-supplied path;
  2. the recorded local config path, when its drive still exists;
  3. the historical D:\Temp\KSwordSandbox, only when D: is present;
  4. %LOCALAPPDATA%\KSwordSandbox.

Step 2 is what keeps a copied install-state or a copied package from pointing a
new operator at a drive that only existed on the authoring machine.
#>

Set-StrictMode -Version 3.0

$script:PortablePathHistoricalDefault = 'D:\Temp\KSwordSandbox'

function Test-PortableDriveAvailable {
    <#
    .SYNOPSIS
    Returns true when a path's root drive exists as a directory.
    #>
    param([AllowNull()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    try {
        $root = [System.IO.Path]::GetPathRoot([System.IO.Path]::GetFullPath($Path))
    }
    catch {
        return $false
    }

    if ([string]::IsNullOrWhiteSpace($root)) { return $false }
    return (Test-Path -LiteralPath $root -PathType Container)
}

function Get-PortableLocalAppDataRoot {
    <#
    .SYNOPSIS
    Returns %LOCALAPPDATA%, falling back to %USERPROFILE% then the system temp.
    #>
    $localAppData = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
    if (-not [string]::IsNullOrWhiteSpace($localAppData)) { return $localAppData }
    if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) { return $env:USERPROFILE }
    return [System.IO.Path]::GetTempPath()
}

function Get-PortableRecordedConfigPath {
    <#
    .SYNOPSIS
    Returns the localConfigPath recorded by a previous install, if readable.
    #>
    param([AllowNull()][string]$InstallStatePath)

    if ([string]::IsNullOrWhiteSpace($InstallStatePath)) { return '' }
    if (-not (Test-Path -LiteralPath $InstallStatePath -PathType Leaf)) { return '' }

    try {
        $state = Get-Content -LiteralPath $InstallStatePath -Raw | ConvertFrom-Json -ErrorAction Stop
        return [string]$state.localConfigPath
    }
    catch {
        # A malformed or unreadable install-state must never block install; the
        # caller simply falls through to the next candidate.
        return ''
    }
}

function Get-PortableRuntimeRoot {
    <#
    .SYNOPSIS
    Resolves the host runtime root without assuming a particular drive.
    .OUTPUTS
    An absolute path that is guaranteed not to be a bare relative fragment.
    #>
    param(
        [AllowNull()][string]$Explicit,
        [AllowNull()][string]$InstallStatePath
    )

    $resolved = $Explicit
    if ([string]::IsNullOrWhiteSpace($resolved)) {
        $recorded = Get-PortableRecordedConfigPath -InstallStatePath $InstallStatePath
        if (-not [string]::IsNullOrWhiteSpace($recorded) -and (Test-PortableDriveAvailable -Path $recorded)) {
            $resolved = Split-Path -Parent $recorded
        }
    }

    if ([string]::IsNullOrWhiteSpace($resolved) -and
        (Test-PortableDriveAvailable -Path $script:PortablePathHistoricalDefault)) {
        $resolved = $script:PortablePathHistoricalDefault
    }

    if ([string]::IsNullOrWhiteSpace($resolved)) {
        $resolved = Join-Path (Get-PortableLocalAppDataRoot) 'KSwordSandbox'
    }

    return [System.IO.Path]::GetFullPath($resolved)
}

function Get-PortableGuestPayloadRoot {
    <#
    .SYNOPSIS
    Resolves the host guest-payload root, defaulting under the runtime root so
    a fallback machine never splits payload and jobs across two locations.
    #>
    param(
        [AllowNull()][string]$Explicit,
        [Parameter(Mandatory)][string]$RuntimeRoot
    )

    if (-not [string]::IsNullOrWhiteSpace($Explicit)) {
        return [System.IO.Path]::GetFullPath($Explicit)
    }

    return [System.IO.Path]::GetFullPath((Join-Path $RuntimeRoot 'payload\guest-tools'))
}

function Get-PortableDerivedPath {
    <#
    .SYNOPSIS
    Resolves a named subdirectory of the runtime root (publish, packages, ...).
    #>
    param(
        [Parameter(Mandatory)][string]$RuntimeRoot,
        [Parameter(Mandatory)][string]$RelativePath
    )

    return [System.IO.Path]::GetFullPath((Join-Path $RuntimeRoot $RelativePath))
}