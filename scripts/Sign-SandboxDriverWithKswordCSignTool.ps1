<#
.SYNOPSIS
Legacy manual-only signer for the local Ksword CSignTool chain.

.DESCRIPTION
This script intentionally mirrors the loadable KswordARKDriver signing path,
but it is disabled by default for unattended KSwordSandbox automation because
the custom timestamp / Authenticode variant tooling can display UI and block a
long-running build or Hyper-V test.

Default builds must compile only. To run this legacy path manually, pass
-AllowInteractiveCSignTool after confirming a human is available to handle any
tool UI. Prefer scripts\Sign-SandboxDriverWithTestCertificate.ps1 for isolated
test-mode VM validation.

1. Run .cert\CSignTool.exe sign /r 1 /f <driver.sys>
2. Run .cert\CSignTool.exe sign /r 1 /f <driver.sys> /ac
3. Optionally run .cert\AuthenticodeVariantGUI.exe generate ...

The .cert directory is expected to be copied into the working tree from
D:\Projects\Ksword5.1\.cert, but it is ignored by git and must never be staged.
The target .sys should also stay under ignored build/payload output.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string]$DriverPath,

    [string]$CertificateDirectory,

    [string]$SignToolPath,

    [switch]$SkipAuthenticodeVariant,

    [switch]$AllowInteractiveCSignTool,

    [switch]$NonFatal
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Resolve-RepositoryRoot {
    return (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
}

function Resolve-RequiredFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Description not found: $Path"
    }

    return (Resolve-Path -LiteralPath $Path).Path
}

function Resolve-RequiredDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "$Description not found: $Path"
    }

    return (Resolve-Path -LiteralPath $Path).Path
}

function Resolve-DriverSysPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepositoryRoot,

        [Parameter(Mandatory = $true)]
        [string]$RequestedPath
    )

    $candidate = if ([System.IO.Path]::IsPathRooted($RequestedPath)) {
        $RequestedPath
    }
    else {
        Join-Path $RepositoryRoot $RequestedPath
    }

    $resolved = Resolve-RequiredFile -Path $candidate -Description 'Driver .sys'
    if ([System.IO.Path]::GetExtension($resolved) -ine '.sys') {
        throw "DriverPath must point to a .sys file: $resolved"
    }

    return $resolved
}

function Get-WindowsKitSignToolCandidates {
    $candidateRoots = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin",
        "${env:ProgramFiles}\Windows Kits\10\bin"
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Container) }

    foreach ($root in $candidateRoots) {
        Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue |
            ForEach-Object {
                $x64Tool = Join-Path $_.FullName 'x64\signtool.exe'
                if (Test-Path -LiteralPath $x64Tool -PathType Leaf) {
                    Get-Item -LiteralPath $x64Tool
                }
            }
    }
}

function Resolve-SignTool {
    param(
        [string]$ExplicitPath,

        [Parameter(Mandatory = $true)]
        [string]$CertificateDirectory
    )

    if (-not [string]::IsNullOrWhiteSpace($ExplicitPath)) {
        return Resolve-RequiredFile -Path $ExplicitPath -Description 'Explicit signtool.exe'
    }

    if (-not [string]::IsNullOrWhiteSpace($env:KSWORDBOX_SIGNTOOL)) {
        return Resolve-RequiredFile -Path $env:KSWORDBOX_SIGNTOOL -Description 'KSWORDBOX_SIGNTOOL signtool.exe'
    }

    $kitTool = Get-WindowsKitSignToolCandidates |
        Sort-Object -Property FullName -Descending |
        Select-Object -First 1
    if ($kitTool) {
        return $kitTool.FullName
    }

    $pathTool = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($pathTool -and (Test-Path -LiteralPath $pathTool.Source -PathType Leaf)) {
        return $pathTool.Source
    }

    return Resolve-RequiredFile -Path (Join-Path $CertificateDirectory 'signtool.exe') -Description 'Bundled signtool.exe'
}

function Invoke-NativeTool {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [Parameter(Mandatory = $true)]
        [string]$WorkingDirectory
    )

    $previousLocation = Get-Location
    try {
        Set-Location -LiteralPath $WorkingDirectory
        $output = & $FilePath @Arguments 2>&1
        $exitCode = $LASTEXITCODE
    }
    finally {
        Set-Location -LiteralPath $previousLocation
    }

    $output | ForEach-Object { Write-Host $_ }
    if ($exitCode -ne 0) {
        throw "Command failed with exit code $exitCode`: $FilePath $($Arguments -join ' ')"
    }
}

function Write-SignatureSummary {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Label,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    try {
        $signature = Get-AuthenticodeSignature -FilePath $Path
        $subject = if ($signature.SignerCertificate) {
            $signature.SignerCertificate.Subject
        }
        else {
            '<none>'
        }

        Write-Host "$Label signature status: $($signature.Status); subject: $subject"
    }
    catch {
        Write-Warning "$Label signature summary skipped: $($_.Exception.Message)"
    }
}

function Test-CertificateDirectoryIgnored {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepositoryRoot,

        [Parameter(Mandatory = $true)]
        [string]$CertificateDirectory
    )

    $relative = [System.IO.Path]::GetRelativePath($RepositoryRoot, $CertificateDirectory)
    if ($relative.StartsWith('..', [System.StringComparison]::Ordinal) -or [System.IO.Path]::IsPathRooted($relative)) {
        return
    }

    $ignoreOutput = & git -C $RepositoryRoot check-ignore -q -- $relative 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "CertificateDirectory is inside the repo but not ignored by git: $CertificateDirectory"
    }
}

function Invoke-SandboxDriverSigning {
    if (-not $AllowInteractiveCSignTool) {
        throw 'CSignTool signing is disabled by default for unattended builds because it may display timestamp/AuthentiCode UI. Default driver validation is compile-only. If a human is present and you intentionally want the legacy path, rerun with -AllowInteractiveCSignTool; otherwise use scripts\Sign-SandboxDriverWithTestCertificate.ps1 inside an isolated test VM.'
    }

    $repositoryRoot = Resolve-RepositoryRoot
    $driver = Resolve-DriverSysPath -RepositoryRoot $repositoryRoot -RequestedPath $DriverPath
    $certDirectory = if ([string]::IsNullOrWhiteSpace($CertificateDirectory)) {
        Join-Path $repositoryRoot '.cert'
    }
    elseif ([System.IO.Path]::IsPathRooted($CertificateDirectory)) {
        $CertificateDirectory
    }
    else {
        Join-Path $repositoryRoot $CertificateDirectory
    }

    $certDirectory = Resolve-RequiredDirectory -Path $certDirectory -Description 'CSignTool certificate/tool directory'
    Test-CertificateDirectoryIgnored -RepositoryRoot $repositoryRoot -CertificateDirectory $certDirectory

    $csignTool = Resolve-RequiredFile -Path (Join-Path $certDirectory 'CSignTool.exe') -Description 'CSignTool.exe'
    $authVariantTool = Join-Path $certDirectory 'AuthenticodeVariantGUI.exe'
    $displayInfo = Join-Path $certDirectory 'outer_display_info.dat'
    $driverDirectory = Split-Path -Parent $driver
    $driverBaseName = [System.IO.Path]::GetFileNameWithoutExtension($driver)
    $driverExtension = [System.IO.Path]::GetExtension($driver)
    $backup = Join-Path $driverDirectory "$driverBaseName.presign.tmp$driverExtension"
    $variantOutput = Join-Path $driverDirectory "$driverBaseName.authvariant.tmp$driverExtension"

    Write-Host "Repository: $repositoryRoot"
    Write-Host "Driver: $driver"
    Write-Host "CertificateDirectory: $certDirectory"
    Write-Host "CSignTool: $csignTool"

    if (-not $PSCmdlet.ShouldProcess($driver, 'Sign driver with CSignTool two-pass chain')) {
        return
    }

    try {
        Copy-Item -LiteralPath $driver -Destination $backup -Force

        Invoke-NativeTool `
            -FilePath $csignTool `
            -Arguments @('sign', '/r', '1', '/f', $driver) `
            -WorkingDirectory $certDirectory
        Write-SignatureSummary -Label 'After CSignTool' -Path $driver

        Invoke-NativeTool `
            -FilePath $csignTool `
            -Arguments @('sign', '/r', '1', '/f', $driver, '/ac') `
            -WorkingDirectory $certDirectory
        Write-SignatureSummary -Label 'After CSignTool /ac' -Path $driver

        if (-not $SkipAuthenticodeVariant) {
            if ((Test-Path -LiteralPath $authVariantTool -PathType Leaf) -and
                (Test-Path -LiteralPath $displayInfo -PathType Leaf)) {
                $resolvedSignTool = Resolve-SignTool -ExplicitPath $SignToolPath -CertificateDirectory $certDirectory
                Write-Host "AuthenticodeVariantGUI: $authVariantTool"
                Write-Host "Display info: $displayInfo"
                Write-Host "signtool: $resolvedSignTool"

                Invoke-NativeTool `
                    -FilePath $authVariantTool `
                    -Arguments @(
                        'generate',
                        '--source', $driver,
                        '--output', $variantOutput,
                        '--display-file', $displayInfo,
                        '--signtool', $resolvedSignTool) `
                    -WorkingDirectory $certDirectory

                if (-not (Test-Path -LiteralPath $variantOutput -PathType Leaf)) {
                    throw "AuthenticodeVariantGUI did not create expected output: $variantOutput"
                }

                Move-Item -LiteralPath $variantOutput -Destination $driver -Force
                Write-SignatureSummary -Label 'Final Authenticode variant' -Path $driver
            }
            else {
                Write-Warning 'AuthenticodeVariantGUI.exe or outer_display_info.dat is missing; CSignTool two-pass signature was left in place.'
            }
        }
        else {
            Write-Host 'Skipped AuthenticodeVariantGUI by request.'
        }
    }
    catch {
        $failure = $_.Exception.Message
        if (Test-Path -LiteralPath $backup -PathType Leaf) {
            Copy-Item -LiteralPath $backup -Destination $driver -Force
            Write-Warning "Restored pre-signing driver after failure: $driver"
        }

        throw $failure
    }
    finally {
        if (Test-Path -LiteralPath $backup) {
            Remove-Item -LiteralPath $backup -Force
        }
        if (Test-Path -LiteralPath $variantOutput) {
            Remove-Item -LiteralPath $variantOutput -Force
        }
    }
}

try {
    Invoke-SandboxDriverSigning
}
catch {
    if ($NonFatal) {
        Write-Warning "Sandbox driver signing failed, but NonFatal was requested: $($_.Exception.Message)"
        exit 0
    }

    throw
}
