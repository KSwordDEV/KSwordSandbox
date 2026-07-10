<#
.SYNOPSIS
Signs a local KSwordSandbox driver build with a non-interactive test certificate.

.DESCRIPTION
Inputs are a .sys path and optional certificate settings. Processing creates or
reuses a local code-signing certificate, signs the driver with
Set-AuthenticodeSignature, optionally trusts the public certificate on the local
machine, and optionally enables Windows test-signing for the current boot entry.

This script intentionally does not call CSignTool, AuthenticodeVariantGUI, or a
timestamp service. It is meant for isolated lab VMs where test-signing is
acceptable. Generated driver binaries and certificates must remain outside git.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string]$DriverPath,

    [string]$Subject = 'CN=KSword Sandbox Test Driver',

    [ValidateSet('LocalMachine', 'CurrentUser')]
    [string]$StoreScope = 'LocalMachine',

    [switch]$CreateNewCertificate,

    [switch]$TrustCertificateForLocalMachine,

    [string]$ExportCertificatePath,

    [switch]$EnableLocalTestSigning,

    [switch]$RebootIfTestSigningChanged,

    [switch]$NonFatal
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Resolve-DriverSysPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    if ([System.IO.Path]::GetExtension($resolved) -ine '.sys') {
        throw "DriverPath must point to a .sys file: $resolved"
    }

    return $resolved
}

function Get-CodeSigningCertificate {
    param(
        [Parameter(Mandatory = $true)][string]$CertificateSubject,
        [Parameter(Mandatory = $true)][string]$CertificateStorePath,
        [bool]$AlwaysCreateNew
    )

    if (-not $AlwaysCreateNew) {
        $existing = Get-ChildItem -LiteralPath $CertificateStorePath -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Subject -eq $CertificateSubject -and
                $_.HasPrivateKey -and
                $_.NotAfter -gt (Get-Date).AddDays(7)
            } |
            Sort-Object -Property NotAfter -Descending |
            Select-Object -First 1

        if ($existing) {
            return $existing
        }
    }

    if ($PSCmdlet.ShouldProcess($CertificateStorePath, "Create test code-signing certificate '$CertificateSubject'")) {
        return New-SelfSignedCertificate `
            -Type CodeSigningCert `
            -Subject $CertificateSubject `
            -CertStoreLocation $CertificateStorePath `
            -KeyAlgorithm RSA `
            -KeyLength 2048 `
            -HashAlgorithm SHA256 `
            -KeyExportPolicy NonExportable `
            -NotAfter (Get-Date).AddYears(3)
    }

    throw 'Certificate creation was skipped by ShouldProcess.'
}

function Export-TestCertificate {
    param(
        [Parameter(Mandatory = $true)]$Certificate,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $parent = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    if ($PSCmdlet.ShouldProcess($Path, 'Export public test certificate')) {
        Export-Certificate -Cert $Certificate -FilePath $Path -Force | Out-Null
    }
}

function Trust-TestCertificateForLocalMachine {
    param(
        [Parameter(Mandatory = $true)]$Certificate,
        [Parameter(Mandatory = $true)][string]$ScratchDirectory
    )

    if (-not (Test-IsAdministrator)) {
        throw 'TrustCertificateForLocalMachine requires an elevated PowerShell session.'
    }

    $temporaryCertificate = Join-Path $ScratchDirectory ('ksword-sandbox-test-driver-{0}.cer' -f $Certificate.Thumbprint)
    Export-TestCertificate -Certificate $Certificate -Path $temporaryCertificate

    foreach ($store in @('Cert:\LocalMachine\TrustedRoot', 'Cert:\LocalMachine\TrustedPublisher')) {
        if ($PSCmdlet.ShouldProcess($store, "Import public test certificate $($Certificate.Thumbprint)")) {
            Import-Certificate -FilePath $temporaryCertificate -CertStoreLocation $store | Out-Null
        }
    }
}

function Enable-LocalTestSigning {
    if (-not (Test-IsAdministrator)) {
        throw 'EnableLocalTestSigning requires an elevated PowerShell session.'
    }

    $before = @(& bcdedit.exe /enum 2>&1)
    $wasEnabled = (($before -join "`n") -match '(?im)^\s*testsigning\s+(Yes|On|True)\s*$')

    if ($PSCmdlet.ShouldProcess('current Windows boot entry', 'Enable test-signing')) {
        $output = @(& bcdedit.exe /set testsigning on 2>&1)
        $exitCode = $LASTEXITCODE
        $output | ForEach-Object { Write-Host $_ }
        if ($exitCode -ne 0) {
            throw "bcdedit.exe /set testsigning on failed with exit code $exitCode."
        }
    }

    if (-not $wasEnabled) {
        Write-Warning 'Windows test-signing was changed. Reboot is required before a test-signed kernel driver can load.'
        if ($RebootIfTestSigningChanged) {
            if ($PSCmdlet.ShouldProcess('local machine', 'Reboot for test-signing')) {
                Restart-Computer -Force
            }
        }
    }
}

function Invoke-TestCertificateSigning {
    $driver = Resolve-DriverSysPath -Path $DriverPath
    $storePath = "Cert:\$StoreScope\My"
    if ($StoreScope -eq 'LocalMachine' -and -not (Test-IsAdministrator)) {
        throw 'LocalMachine certificate store requires an elevated PowerShell session. Use -StoreScope CurrentUser for compile-only signing experiments, or rerun elevated in the isolated VM.'
    }

    $certificate = Get-CodeSigningCertificate `
        -CertificateSubject $Subject `
        -CertificateStorePath $storePath `
        -AlwaysCreateNew ([bool]$CreateNewCertificate)

    if (-not [string]::IsNullOrWhiteSpace($ExportCertificatePath)) {
        Export-TestCertificate -Certificate $certificate -Path $ExportCertificatePath
    }

    if ($TrustCertificateForLocalMachine) {
        $scratch = Split-Path -Parent $driver
        Trust-TestCertificateForLocalMachine -Certificate $certificate -ScratchDirectory $scratch
    }

    if ($PSCmdlet.ShouldProcess($driver, "Sign with test certificate $($certificate.Thumbprint)")) {
        $signature = Set-AuthenticodeSignature `
            -FilePath $driver `
            -Certificate $certificate `
            -HashAlgorithm SHA256

        if ($signature.Status -ne 'Valid') {
            Write-Warning "Signature status after signing is '$($signature.Status)': $($signature.StatusMessage)"
        }
    }

    if ($EnableLocalTestSigning) {
        Enable-LocalTestSigning
    }

    $finalSignature = Get-AuthenticodeSignature -FilePath $driver
    [pscustomobject][ordered]@{
        DriverPath = $driver
        Subject = $certificate.Subject
        Thumbprint = $certificate.Thumbprint
        StoreScope = $StoreScope
        TrustedForLocalMachine = [bool]$TrustCertificateForLocalMachine
        LocalTestSigningRequested = [bool]$EnableLocalTestSigning
        SignatureStatus = [string]$finalSignature.Status
        SignatureStatusMessage = [string]$finalSignature.StatusMessage
        CSignToolUsed = $false
    }
}

try {
    Invoke-TestCertificateSigning
}
catch {
    if ($NonFatal) {
        Write-Warning "Test-certificate driver signing failed, but NonFatal was requested: $($_.Exception.Message)"
        exit 0
    }

    throw
}
