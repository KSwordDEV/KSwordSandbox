<#
.SYNOPSIS
Signs a local KSwordSandbox driver build with a non-interactive test certificate.

.DESCRIPTION
Inputs are a .sys path and optional certificate settings. Processing creates or
reuses a local code-signing certificate, signs the driver with ordinary
Windows SDK signtool.exe when available, optionally trusts the public
certificate on the local machine, and optionally enables Windows test-signing
for the current boot entry. If signtool.exe is absent, signing is clearly
skipped and the result reports SignatureAttempted=false and Skipped=true.

This script intentionally does not call the legacy interactive signing chain,
GUI signing tools, or a timestamp service. It is meant for isolated lab VMs
where test-signing is acceptable. Generated driver binaries and certificates
must remain outside git.
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

    [string]$SignToolPath,

    [string]$ExportCertificatePath,

    [switch]$EnableLocalTestSigning,

    [switch]$RebootIfTestSigningChanged,

    [switch]$NonFatal,

    [switch]$Json
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
        throw "错误：DriverPath 必须指向 .sys 文件：$resolved。下一步：请传入 KSword.Sandbox.Driver.sys 的完整路径。"
    }

    return $resolved
}

function Get-WindowsKitSignToolCandidates {
    $roots = @()
    if (-not [string]::IsNullOrWhiteSpace(${env:ProgramFiles(x86)})) {
        $roots += (Join-Path ${env:ProgramFiles(x86)} 'Windows Kits')
    }
    if (-not [string]::IsNullOrWhiteSpace($env:ProgramFiles)) {
        $roots += (Join-Path $env:ProgramFiles 'Windows Kits')
    }

    foreach ($root in ($roots | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $root -PathType Container)) {
            continue
        }

        Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue |
            ForEach-Object {
                $bin = Join-Path $_.FullName 'bin'
                if (Test-Path -LiteralPath $bin -PathType Container) {
                    Get-ChildItem -LiteralPath $bin -Directory -ErrorAction SilentlyContinue |
                        Sort-Object -Property Name -Descending |
                        ForEach-Object {
                            foreach ($architecture in @('x64', 'x86')) {
                                $candidate = Join-Path $_.FullName (Join-Path $architecture 'signtool.exe')
                                if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                                    $candidate
                                }
                            }
                        }
                }
            }
    }
}

function Resolve-SignTool {
    param([AllowNull()][string]$ExplicitPath)

    $candidates = New-Object System.Collections.Generic.List[string]
    if (-not [string]::IsNullOrWhiteSpace($ExplicitPath)) {
        [void]$candidates.Add($ExplicitPath)
    }
    if (-not [string]::IsNullOrWhiteSpace($env:KSWORDBOX_SIGNTOOL)) {
        [void]$candidates.Add($env:KSWORDBOX_SIGNTOOL)
    }
    foreach ($candidate in @(Get-WindowsKitSignToolCandidates)) {
        [void]$candidates.Add([string]$candidate)
    }
    $pathTool = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($null -ne $pathTool) {
        [void]$candidates.Add($pathTool.Source)
    }

    foreach ($candidate in @($candidates.ToArray())) {
        if ([string]::IsNullOrWhiteSpace($candidate)) {
            continue
        }

        try {
            $resolved = (Resolve-Path -LiteralPath $candidate -ErrorAction Stop).Path
            if (([System.IO.Path]::GetFileName($resolved)) -ine 'signtool.exe') {
                if (-not [string]::IsNullOrWhiteSpace($ExplicitPath) -and
                    [System.StringComparer]::OrdinalIgnoreCase.Equals($candidate, $ExplicitPath)) {
                    throw "Driver signing requires signtool.exe. Received: $resolved"
                }

                continue
            }

            return $resolved
        }
        catch {
            if (-not [string]::IsNullOrWhiteSpace($ExplicitPath) -and
                [System.StringComparer]::OrdinalIgnoreCase.Equals($candidate, $ExplicitPath)) {
                throw
            }
        }
    }

    return $null
}

function Invoke-SignToolWithTestCertificate {
    param(
        [Parameter(Mandatory = $true)][string]$ToolPath,
        [Parameter(Mandatory = $true)][string]$Driver,
        [Parameter(Mandatory = $true)]$Certificate,
        [Parameter(Mandatory = $true)][string]$Scope
    )

    $arguments = @(
        'sign',
        '/fd', 'SHA256',
        '/sha1', $Certificate.Thumbprint,
        '/s', 'My'
    )
    if ($Scope -eq 'LocalMachine') {
        $arguments += '/sm'
    }
    $arguments += $Driver

    if (-not $PSCmdlet.ShouldProcess($Driver, "使用 signtool.exe 和测试证书 $($Certificate.Thumbprint) 签名 / Sign with signtool.exe test certificate")) {
        return [pscustomobject][ordered]@{
            ExitCode = $null
            Output = @()
            SkippedByShouldProcess = $true
        }
    }

    $output = @(& $ToolPath @arguments 2>&1)
    $exitCode = $LASTEXITCODE
    $output | ForEach-Object { Write-Host $_ }
    if ($exitCode -ne 0) {
        throw "错误：signtool.exe 签名失败，退出码 $exitCode。下一步：确认 Windows SDK signtool.exe、证书私钥和 driver 路径可用。"
    }

    [pscustomobject][ordered]@{
        ExitCode = $exitCode
        Output = @($output)
        SkippedByShouldProcess = $false
    }
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

    if ($PSCmdlet.ShouldProcess($CertificateStorePath, "创建测试代码签名证书 '$CertificateSubject' / Create test code-signing certificate")) {
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

    throw '错误：证书创建被 ShouldProcess/WhatIf 跳过。下一步：如需实际签名，请去掉 -WhatIf 并确认操作。'
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

    if ($PSCmdlet.ShouldProcess($Path, '导出公共测试证书 / Export public test certificate')) {
        Export-Certificate -Cert $Certificate -FilePath $Path -Force | Out-Null
    }
}

function Trust-TestCertificateForLocalMachine {
    param(
        [Parameter(Mandatory = $true)]$Certificate,
        [Parameter(Mandatory = $true)][string]$ScratchDirectory
    )

    if (-not (Test-IsAdministrator)) {
        throw '错误：-TrustCertificateForLocalMachine 需要管理员 PowerShell。下一步：以管理员身份在隔离 VM 中重试，或去掉该参数只完成签名。'
    }

    $temporaryCertificate = Join-Path $ScratchDirectory ('ksword-sandbox-test-driver-{0}.cer' -f $Certificate.Thumbprint)
    Export-TestCertificate -Certificate $Certificate -Path $temporaryCertificate

    foreach ($store in @('Cert:\LocalMachine\Root', 'Cert:\LocalMachine\TrustedPublisher')) {
        if ($PSCmdlet.ShouldProcess($store, "导入公共测试证书 $($Certificate.Thumbprint) / Import public test certificate")) {
            Import-Certificate -FilePath $temporaryCertificate -CertStoreLocation $store | Out-Null
        }
    }
}

function Enable-LocalTestSigning {
    if (-not (Test-IsAdministrator)) {
        throw '错误：-EnableLocalTestSigning 需要管理员 PowerShell。下一步：以管理员身份在隔离 VM 中重试，或手动运行 bcdedit /set testsigning on 后重启。'
    }

    $before = @(& bcdedit.exe /enum 2>&1)
    $wasEnabled = (($before -join "`n") -match '(?im)^\s*testsigning\s+(Yes|On|True)\s*$')
    $commandOutput = @()
    $changed = -not $wasEnabled

    if ($PSCmdlet.ShouldProcess('current Windows boot entry', '启用 test-signing / Enable test-signing')) {
        $commandOutput = @(& bcdedit.exe /set testsigning on 2>&1)
        $exitCode = $LASTEXITCODE
        $commandOutput | ForEach-Object { Write-Host $_ }
        if ($exitCode -ne 0) {
            throw "错误：bcdedit.exe /set testsigning on 失败，退出码 $exitCode。下一步：确认当前是管理员 PowerShell，并在隔离 VM 中重试。"
        }
    }

    if (-not $wasEnabled) {
        Write-Warning '中文提示：Windows test-signing 已更改；加载测试签名 kernel driver 前必须重启。 / Reboot is required before loading a test-signed driver.'
        if ($RebootIfTestSigningChanged) {
            if ($PSCmdlet.ShouldProcess('local machine', '为 test-signing 重启 / Reboot for test-signing')) {
                Restart-Computer -Force
            }
        }
    }

    return [pscustomobject][ordered]@{
        WasEnabled = $wasEnabled
        Changed = $changed
        RestartRequired = $changed
        RebootRequested = [bool]$RebootIfTestSigningChanged
        CommandOutput = $commandOutput
    }
}

function Invoke-TestCertificateSigning {
    $driver = Resolve-DriverSysPath -Path $DriverPath
    $storePath = "Cert:\$StoreScope\My"
    if ($StoreScope -eq 'LocalMachine' -and -not (Test-IsAdministrator)) {
        throw '错误：LocalMachine 证书存储需要管理员 PowerShell。下一步：只做编译/签名实验可用 -StoreScope CurrentUser；要信任并加载 driver 请在隔离 VM 中以管理员身份重试。'
    }

    $resolvedSignTool = Resolve-SignTool -ExplicitPath $SignToolPath
    if ([string]::IsNullOrWhiteSpace($resolvedSignTool)) {
        Write-Warning '中文提示：未找到普通 Windows SDK signtool.exe；已明确跳过 driver 测试签名，且不会回退到旧签名工具。'
        $testSigningResult = $null
        if ($EnableLocalTestSigning) {
            $testSigningResult = Enable-LocalTestSigning
        }

        $currentSignature = Get-AuthenticodeSignature -FilePath $driver
        return [pscustomobject][ordered]@{
            Kind = 'KSwordSandbox.DriverTestCertificateSigning'
            DriverPath = $driver
            Subject = ''
            Thumbprint = ''
            StoreScope = $StoreScope
            SignToolPath = ''
            SignatureAttempted = $false
            Skipped = $true
            SkipReason = 'signtool.exe was not found; signing skipped explicitly and no legacy interactive signing tool was called.'
            TrustCertificateForLocalMachineRequested = [bool]$TrustCertificateForLocalMachine
            TrustedForLocalMachine = $false
            LocalTestSigningRequested = [bool]$EnableLocalTestSigning
            TestSigning = $testSigningResult
            RequiresReboot = ($null -ne $testSigningResult -and [bool]$testSigningResult.RestartRequired)
            SignatureStatus = [string]$currentSignature.Status
            SignatureStatusMessage = [string]$currentSignature.StatusMessage
            CSignToolUsed = $false
        }
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

    $signToolResult = Invoke-SignToolWithTestCertificate `
        -ToolPath $resolvedSignTool `
        -Driver $driver `
        -Certificate $certificate `
        -Scope $StoreScope

    $testSigningResult = $null
    if ($EnableLocalTestSigning) {
        $testSigningResult = Enable-LocalTestSigning
    }

    $finalSignature = Get-AuthenticodeSignature -FilePath $driver
    [pscustomobject][ordered]@{
        Kind = 'KSwordSandbox.DriverTestCertificateSigning'
        DriverPath = $driver
        Subject = $certificate.Subject
        Thumbprint = $certificate.Thumbprint
        StoreScope = $StoreScope
        SignToolPath = $resolvedSignTool
        SignatureAttempted = -not [bool]$signToolResult.SkippedByShouldProcess
        Skipped = [bool]$signToolResult.SkippedByShouldProcess
        SkipReason = if ([bool]$signToolResult.SkippedByShouldProcess) { 'Signing skipped by ShouldProcess/WhatIf.' } else { '' }
        TrustCertificateForLocalMachineRequested = [bool]$TrustCertificateForLocalMachine
        TrustedForLocalMachine = [bool]$TrustCertificateForLocalMachine
        LocalTestSigningRequested = [bool]$EnableLocalTestSigning
        TestSigning = $testSigningResult
        RequiresReboot = ($null -ne $testSigningResult -and [bool]$testSigningResult.RestartRequired)
        SignatureStatus = [string]$finalSignature.Status
        SignatureStatusMessage = [string]$finalSignature.StatusMessage
        SignToolExitCode = $signToolResult.ExitCode
        CSignToolUsed = $false
    }
}

try {
    $result = Invoke-TestCertificateSigning
    if ($Json) {
        $result | ConvertTo-Json -Depth 8
    }
    else {
        $result
    }
}
catch {
    if ($NonFatal) {
        Write-Warning "中文提示：测试证书签名失败，但已请求 NonFatal，因此返回 0。下一步：查看错误并修复证书/权限/路径。英文详情：$($_.Exception.Message)"
        exit 0
    }

    throw
}
