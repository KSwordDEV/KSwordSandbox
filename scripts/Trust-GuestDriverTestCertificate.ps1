<#
.SYNOPSIS
Imports an exported driver test-signing public certificate into a Hyper-V guest.

.DESCRIPTION
This host-side helper uses PowerShell Direct to import an already exported
public certificate into the configured guest's LocalMachine Root and
TrustedPublisher stores. It does not sign drivers and does not run signing
tools.

By default the script is plan-only. Any guest, VM, or checkpoint mutation
requires -AllowVmMutation and is still guarded by SupportsShouldProcess
(-WhatIf/-Confirm). Use -Force only for an already-approved isolated lab VM.

When -RefreshCleanCheckpoint is supplied after a successful import, the helper
stops the VM if needed, renames the existing clean checkpoint to a timestamped
backup, and creates a replacement checkpoint with the configured clean
checkpoint name.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [string]$CertificatePath,

    [string]$VmName = '',

    [string]$CheckpointName = '',

    [string]$GuestUserName = '',

    [string]$SecretName = '',

    [string]$InstallStatePath = $(if ([string]::IsNullOrWhiteSpace($env:ProgramData)) { '' } else { Join-Path $env:ProgramData 'KSwordSandbox\install-state.json' }),

    [switch]$AllowVmMutation,

    [switch]$StartVmIfNeeded,

    [switch]$RefreshCleanCheckpoint,

    [string]$BackupCheckpointName = '',

    [switch]$Force,

    [switch]$Json,

    [ValidateRange(30, 1800)]
    [int]$PowerShellDirectTimeoutSeconds = 240
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$script:TrustBoundParameters = @{}
foreach ($parameterName in $PSBoundParameters.Keys) {
    $script:TrustBoundParameters[$parameterName] = $PSBoundParameters[$parameterName]
}

function Write-TrustInfo {
    param([Parameter(Mandatory = $true)][string]$Message)
    if ($Json) {
        Write-Verbose $Message
        return
    }

    Write-Host "[guest-cert-trust] $Message"
}

function Read-InstallState {
    param([AllowNull()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }

    try {
        return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    }
    catch {
        Write-Warning "中文提示：无法读取安装状态 '$Path'，将使用命令行参数或默认值。英文详情：$($_.Exception.Message)"
        return $null
    }
}

function Get-ObjectPropertyString {
    param(
        [AllowNull()]$Object,
        [Parameter(Mandatory = $true)][string]$Name,
        [string]$DefaultValue = ''
    )

    if ($null -eq $Object) {
        return $DefaultValue
    }

    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) {
        return $DefaultValue
    }

    $value = [string]$property.Value
    if ([string]::IsNullOrWhiteSpace($value)) {
        return $DefaultValue
    }

    return $value
}

function Resolve-EffectiveSettings {
    $state = Read-InstallState -Path $InstallStatePath

    $effectiveVmName = if ($script:TrustBoundParameters.ContainsKey('VmName') -and -not [string]::IsNullOrWhiteSpace($VmName)) {
        $VmName
    }
    else {
        Get-ObjectPropertyString -Object $state -Name 'vmName' -DefaultValue 'KSwordSandbox-Win10-Golden'
    }

    $effectiveCheckpointName = if ($script:TrustBoundParameters.ContainsKey('CheckpointName') -and -not [string]::IsNullOrWhiteSpace($CheckpointName)) {
        $CheckpointName
    }
    else {
        Get-ObjectPropertyString -Object $state -Name 'checkpointName' -DefaultValue 'Clean'
    }

    $effectiveGuestUserName = if ($script:TrustBoundParameters.ContainsKey('GuestUserName') -and -not [string]::IsNullOrWhiteSpace($GuestUserName)) {
        $GuestUserName
    }
    else {
        Get-ObjectPropertyString -Object $state -Name 'guestUserName' -DefaultValue 'SandboxUser'
    }

    $effectiveSecretName = if ($script:TrustBoundParameters.ContainsKey('SecretName') -and -not [string]::IsNullOrWhiteSpace($SecretName)) {
        $SecretName
    }
    else {
        Get-ObjectPropertyString -Object $state -Name 'secretName' -DefaultValue 'KSWORDBOX_GUEST_PASSWORD'
    }

    [pscustomobject][ordered]@{
        VmName = $effectiveVmName
        CheckpointName = $effectiveCheckpointName
        GuestUserName = $effectiveGuestUserName
        SecretName = $effectiveSecretName
        InstallStatePath = $InstallStatePath
        InstallStateLoaded = ($null -ne $state)
    }
}

function Resolve-PublicCertificate {
    param([Parameter(Mandatory = $true)][string]$Path)

    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    $extension = [System.IO.Path]::GetExtension($resolved)
    if ($extension -in @('.pfx', '.p12')) {
        throw "错误：CertificatePath 必须是导出的公钥证书，不能是私钥容器：$resolved。下一步：导出 .cer/.crt/.der 公钥证书后重试。"
    }

    try {
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($resolved)
    }
    catch {
        throw "错误：无法读取公钥证书 '$resolved'。下一步：确认文件是 DER/Base64 编码的 .cer/.crt/.der 证书。英文详情：$($_.Exception.Message)"
    }

    if ($certificate.HasPrivateKey) {
        throw "错误：CertificatePath 包含私钥；此 helper 只接受导出的公钥证书。下一步：重新导出不含私钥的 public certificate。"
    }

    $thumbprint = ([string]$certificate.Thumbprint) -replace '\s', ''
    if ([string]::IsNullOrWhiteSpace($thumbprint)) {
        throw "错误：无法解析证书 thumbprint：$resolved。下一步：重新导出证书后重试。"
    }

    [pscustomobject][ordered]@{
        Path = $resolved
        Subject = [string]$certificate.Subject
        Issuer = [string]$certificate.Issuer
        Thumbprint = $thumbprint.ToUpperInvariant()
        NotBefore = $certificate.NotBefore
        NotAfter = $certificate.NotAfter
        RawData = [System.IO.File]::ReadAllBytes($resolved)
    }
}

function Test-IsAdministrator {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Assert-CommandAvailable {
    param([Parameter(Mandatory = $true)][string[]]$Names)

    $missing = @()
    foreach ($name in $Names) {
        if ($null -eq (Get-Command -Name $name -ErrorAction SilentlyContinue)) {
            $missing += $name
        }
    }

    if ($missing.Count -gt 0) {
        throw "错误：当前 PowerShell 缺少必需命令：$($missing -join ', ')。下一步：启用 Hyper-V PowerShell 工具，并以管理员 PowerShell 重试。"
    }
}

function Get-GuestPasswordSecretValue {
    param([Parameter(Mandatory = $true)][string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) {
        throw '错误：SecretName 不能为空。下一步：传入 -SecretName，或修复安装状态中的 guest password secret 名称。'
    }

    foreach ($scope in @('Process', 'User', 'Machine')) {
        $value = [Environment]::GetEnvironmentVariable($Name, $scope)
        if (-not [string]::IsNullOrEmpty($value)) {
            return [pscustomobject][ordered]@{
                Value = $value
                Scope = $scope
            }
        }
    }

    throw "错误：未在 Process/User/Machine 环境中找到 guest password secret '$Name'。下一步：运行 .\install.ps1 -InstallEntrypoint CreateOrPreparePath -PromptPassword，或在当前管理员 PowerShell 中设置该变量；secret 值不要打印到日志。"
}

function New-GuestCredential {
    param(
        [Parameter(Mandatory = $true)][string]$UserName,
        [Parameter(Mandatory = $true)][string]$Password
    )

    if ([string]::IsNullOrWhiteSpace($UserName)) {
        throw '错误：GuestUserName 不能为空。下一步：传入 -GuestUserName，或修复安装状态。'
    }

    $securePassword = [System.Security.SecureString]::new()
    foreach ($passwordCharacter in $Password.ToCharArray()) {
        $securePassword.AppendChar($passwordCharacter)
    }
    $securePassword.MakeReadOnly()
    [pscredential]::new($UserName, $securePassword)
}

function Test-TrustShouldProcess {
    param(
        [Parameter(Mandatory = $true)][string]$Target,
        [Parameter(Mandatory = $true)][string]$Action
    )

    $previousConfirmPreference = $ConfirmPreference
    try {
        if ($Force -and (-not [bool]$WhatIfPreference)) {
            $ConfirmPreference = 'None'
        }

        return $PSCmdlet.ShouldProcess($Target, $Action)
    }
    finally {
        $ConfirmPreference = $previousConfirmPreference
    }
}

function Wait-VMRunning {
    param(
        [Parameter(Mandatory = $true)][string]$TargetVmName,
        [int]$TimeoutSeconds = 120
    )

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $vm = Get-VM -Name $TargetVmName -ErrorAction Stop
        if ($vm.State -eq 'Running') {
            return
        }

        Start-Sleep -Seconds 2
    } while ([DateTimeOffset]::UtcNow -lt $deadline)

    throw "错误：VM '$TargetVmName' 未在 $TimeoutSeconds 秒内进入 Running 状态。下一步：检查 Hyper-V VM 状态后重试。"
}

function Wait-PowerShellDirect {
    param(
        [Parameter(Mandatory = $true)][string]$TargetVmName,
        [Parameter(Mandatory = $true)][pscredential]$Credential,
        [int]$TimeoutSeconds = 240
    )

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    $attempt = 0
    $lastError = ''
    do {
        $attempt++
        try {
            $probe = Invoke-Command -VMName $TargetVmName -Credential $Credential -ScriptBlock {
                [pscustomobject][ordered]@{
                    ComputerName = $env:COMPUTERNAME
                    UserName = [Security.Principal.WindowsIdentity]::GetCurrent().Name
                    Is64BitOperatingSystem = [Environment]::Is64BitOperatingSystem
                }
            } -ErrorAction Stop
            Write-TrustInfo "PowerShell Direct 已就绪：VM='$TargetVmName'，attempt=$attempt，guest='$($probe.UserName)'。"
            return $probe
        }
        catch {
            $lastError = $_.Exception.Message
            Start-Sleep -Seconds 3
        }
    } while ([DateTimeOffset]::UtcNow -lt $deadline)

    throw "错误：PowerShell Direct 未在 $TimeoutSeconds 秒内对 VM '$TargetVmName' 就绪。下一步：确认 VM 正在运行、guest 用户/secret 正确、PowerShell Direct 可用。英文详情：$lastError"
}

function Import-GuestCertificateTrust {
    param(
        [Parameter(Mandatory = $true)][string]$TargetVmName,
        [Parameter(Mandatory = $true)][pscredential]$Credential,
        [Parameter(Mandatory = $true)]$Certificate
    )

    $scriptBlock = {
        param(
            [byte[]]$CertificateBytes,
            [string]$Thumbprint,
            [string]$Subject
        )

        Set-StrictMode -Version 3.0
        $ErrorActionPreference = 'Stop'

        function Test-GuestAdministrator {
            $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
            $principal = [Security.Principal.WindowsPrincipal]::new($identity)
            return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        }

        if (-not (Test-GuestAdministrator)) {
            throw "Guest user '$([Security.Principal.WindowsIdentity]::GetCurrent().Name)' is not an administrator; LocalMachine certificate stores cannot be updated."
        }

        $scratchRoot = Join-Path $env:ProgramData 'KSwordSandbox\cert-trust'
        New-Item -ItemType Directory -Path $scratchRoot -Force | Out-Null
        $temporaryCertificate = Join-Path $scratchRoot ("driver-test-{0}.cer" -f $Thumbprint)
        [System.IO.File]::WriteAllBytes($temporaryCertificate, $CertificateBytes)

        try {
            $stores = @(
                [pscustomobject]@{ Name = 'Root'; Path = 'Cert:\LocalMachine\Root' },
                [pscustomobject]@{ Name = 'TrustedPublisher'; Path = 'Cert:\LocalMachine\TrustedPublisher' }
            )

            $storeResults = foreach ($store in $stores) {
                $certificateStorePath = Join-Path $store.Path $Thumbprint
                $wasPresent = Test-Path -LiteralPath $certificateStorePath
                if (-not $wasPresent) {
                    Import-Certificate -FilePath $temporaryCertificate -CertStoreLocation $store.Path | Out-Null
                }

                $present = Test-Path -LiteralPath $certificateStorePath
                [pscustomobject][ordered]@{
                    Store = $store.Name
                    StorePath = $store.Path
                    WasPresent = [bool]$wasPresent
                    Present = [bool]$present
                    Imported = ((-not [bool]$wasPresent) -and [bool]$present)
                }
            }

            [pscustomobject][ordered]@{
                ComputerName = $env:COMPUTERNAME
                UserName = [Security.Principal.WindowsIdentity]::GetCurrent().Name
                CertificateSubject = $Subject
                CertificateThumbprint = $Thumbprint
                Stores = @($storeResults)
                Succeeded = -not (@($storeResults | Where-Object { -not $_.Present }).Count -gt 0)
            }
        }
        finally {
            Remove-Item -LiteralPath $temporaryCertificate -Force -ErrorAction SilentlyContinue
        }
    }

    Invoke-Command `
        -VMName $TargetVmName `
        -Credential $Credential `
        -ScriptBlock $scriptBlock `
        -ArgumentList ([byte[]]$Certificate.RawData), $Certificate.Thumbprint, $Certificate.Subject `
        -ErrorAction Stop
}

function Wait-VMOff {
    param(
        [Parameter(Mandatory = $true)][string]$TargetVmName,
        [int]$TimeoutSeconds = 120
    )

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $vm = Get-VM -Name $TargetVmName -ErrorAction Stop
        if ($vm.State -eq 'Off') {
            return
        }

        Start-Sleep -Seconds 2
    } while ([DateTimeOffset]::UtcNow -lt $deadline)

    throw "错误：VM '$TargetVmName' 未在 $TimeoutSeconds 秒内停止。下一步：检查 Hyper-V 状态，避免在非预期状态刷新 clean checkpoint。"
}

function Update-CleanCheckpoint {
    param(
        [Parameter(Mandatory = $true)][string]$TargetVmName,
        [Parameter(Mandatory = $true)][string]$TargetCheckpointName,
        [string]$RequestedBackupName = ''
    )

    $checkpointResult = [ordered]@{
        Requested = $true
        StoppedVm = $false
        ExistingCheckpointRenamed = $false
        BackupCheckpointName = ''
        CreatedCheckpoint = $false
    }

    $vm = Get-VM -Name $TargetVmName -ErrorAction Stop
    if ($vm.State -ne 'Off') {
        if (Test-TrustShouldProcess -Target $TargetVmName -Action 'Stop VM before refreshing clean checkpoint') {
            Stop-VM -Name $TargetVmName -TurnOff -Force -ErrorAction Stop
            Wait-VMOff -TargetVmName $TargetVmName
            $checkpointResult.StoppedVm = $true
        }
        else {
            throw "错误：刷新 checkpoint 前停止 VM 的操作被拒绝。下一步：去掉 -RefreshCleanCheckpoint，或显式确认 VM mutation。"
        }
    }

    $existing = Get-VMSnapshot -VMName $TargetVmName -Name $TargetCheckpointName -ErrorAction SilentlyContinue
    if ($null -ne $existing) {
        $backupName = if ([string]::IsNullOrWhiteSpace($RequestedBackupName)) {
            '{0}-before-cert-trust-{1}' -f $TargetCheckpointName, (Get-Date -Format 'yyyyMMdd-HHmmss')
        }
        else {
            $RequestedBackupName
        }

        if (Test-TrustShouldProcess -Target "$TargetVmName::$TargetCheckpointName" -Action "Rename existing clean checkpoint to '$backupName'") {
            Rename-VMSnapshot -VMName $TargetVmName -Name $TargetCheckpointName -NewName $backupName -ErrorAction Stop
            $checkpointResult.ExistingCheckpointRenamed = $true
            $checkpointResult.BackupCheckpointName = $backupName
        }
        else {
            throw "错误：重命名旧 checkpoint 的操作被拒绝。下一步：去掉 -RefreshCleanCheckpoint，或显式确认 checkpoint mutation。"
        }
    }

    if (Test-TrustShouldProcess -Target "$TargetVmName::$TargetCheckpointName" -Action 'Create refreshed clean checkpoint after guest certificate trust import') {
        Checkpoint-VM -Name $TargetVmName -SnapshotName $TargetCheckpointName -ErrorAction Stop | Out-Null
        $checkpointResult.CreatedCheckpoint = $true
    }
    else {
        throw "错误：创建刷新后的 clean checkpoint 被拒绝。下一步：手动检查 VM/checkpoint 状态后重试。"
    }

    [pscustomobject]$checkpointResult
}

$settings = Resolve-EffectiveSettings
$certificateInfo = Resolve-PublicCertificate -Path $CertificatePath

$plannedActions = New-Object System.Collections.Generic.List[string]
[void]$plannedActions.Add("Import public certificate thumbprint '$($certificateInfo.Thumbprint)' into guest Cert:\LocalMachine\Root.")
[void]$plannedActions.Add("Import public certificate thumbprint '$($certificateInfo.Thumbprint)' into guest Cert:\LocalMachine\TrustedPublisher.")
if ($StartVmIfNeeded) {
    [void]$plannedActions.Add("Start VM '$($settings.VmName)' if it is not already running.")
}
if ($RefreshCleanCheckpoint) {
    [void]$plannedActions.Add("Stop VM '$($settings.VmName)', rename existing checkpoint '$($settings.CheckpointName)' to a backup name, and create a refreshed checkpoint.")
}

$result = [pscustomobject][ordered]@{
    Kind = 'KSwordSandbox.GuestDriverTestCertificateTrust'
    CertificatePath = $certificateInfo.Path
    CertificateSubject = $certificateInfo.Subject
    CertificateIssuer = $certificateInfo.Issuer
    CertificateThumbprint = $certificateInfo.Thumbprint
    CertificateNotBefore = $certificateInfo.NotBefore
    CertificateNotAfter = $certificateInfo.NotAfter
    VmName = $settings.VmName
    CheckpointName = $settings.CheckpointName
    GuestUserName = $settings.GuestUserName
    SecretName = $settings.SecretName
    SecretValuePrinted = $false
    InstallStatePath = $settings.InstallStatePath
    InstallStateLoaded = [bool]$settings.InstallStateLoaded
    AllowVmMutation = [bool]$AllowVmMutation
    StartVmIfNeeded = [bool]$StartVmIfNeeded
    RefreshCleanCheckpoint = [bool]$RefreshCleanCheckpoint
    WhatIf = [bool]$WhatIfPreference
    PlannedActions = @($plannedActions.ToArray())
    GuestImport = $null
    CheckpointRefresh = $null
    MutationExecuted = $false
    SigningToolInvoked = $false
    PlanOnly = $false
    Message = ''
}

if (-not $AllowVmMutation) {
    $result.PlanOnly = $true
    $result.Message = 'Plan only: pass -AllowVmMutation plus normal ShouldProcess confirmation, or -Force for an already-approved lab VM, to import into the guest.'
    if ($Json) {
        [pscustomobject]$result | ConvertTo-Json -Depth 8
    }
    else {
        [pscustomobject]$result
    }
    return
}

if (-not (Test-IsAdministrator)) {
    throw '错误：修改 Hyper-V guest trust store 需要宿主机管理员 PowerShell。下一步：以管理员身份打开 PowerShell，先用 -WhatIf 预览，再显式确认。'
}

$requiredCommands = @('Get-VM', 'Invoke-Command')
if ($StartVmIfNeeded) {
    $requiredCommands += 'Start-VM'
}
if ($RefreshCleanCheckpoint) {
    $requiredCommands += @('Get-VMSnapshot', 'Stop-VM', 'Rename-VMSnapshot', 'Checkpoint-VM')
}
Assert-CommandAvailable -Names $requiredCommands

$vm = Get-VM -Name $settings.VmName -ErrorAction Stop
if ($vm.State -ne 'Running') {
    if (-not $StartVmIfNeeded) {
        throw "错误：VM '$($settings.VmName)' 当前状态为 '$($vm.State)'，PowerShell Direct 导入需要 VM Running。下一步：手动启动 VM，或传入 -StartVmIfNeeded（仍需 -AllowVmMutation/ShouldProcess）。"
    }

    if (Test-TrustShouldProcess -Target $settings.VmName -Action 'Start VM for PowerShell Direct certificate trust import') {
        Start-VM -Name $settings.VmName -ErrorAction Stop
        $result.MutationExecuted = $true
        Wait-VMRunning -TargetVmName $settings.VmName
    }
    else {
        $result.PlanOnly = $true
        $result.Message = 'VM start declined by ShouldProcess; no guest trust import was attempted.'
        if ($Json) {
            [pscustomobject]$result | ConvertTo-Json -Depth 8
        }
        else {
            [pscustomobject]$result
        }
        return
    }
}

$secretValue = Get-GuestPasswordSecretValue -Name $settings.SecretName
$credential = New-GuestCredential -UserName $settings.GuestUserName -Password $secretValue.Value
[void](Wait-PowerShellDirect -TargetVmName $settings.VmName -Credential $credential -TimeoutSeconds $PowerShellDirectTimeoutSeconds)

if (Test-TrustShouldProcess -Target "$($settings.VmName) guest LocalMachine certificate stores" -Action "Import public certificate '$($certificateInfo.Thumbprint)' into Root and TrustedPublisher") {
    $result.GuestImport = Import-GuestCertificateTrust -TargetVmName $settings.VmName -Credential $credential -Certificate $certificateInfo
    $result.MutationExecuted = $true
}
else {
    $result.PlanOnly = $true
    $result.Message = 'Guest certificate import declined by ShouldProcess.'
    if ($Json) {
        [pscustomobject]$result | ConvertTo-Json -Depth 8
    }
    else {
        [pscustomobject]$result
    }
    return
}

if ($RefreshCleanCheckpoint) {
    $result.CheckpointRefresh = Update-CleanCheckpoint `
        -TargetVmName $settings.VmName `
        -TargetCheckpointName $settings.CheckpointName `
        -RequestedBackupName $BackupCheckpointName
    $result.MutationExecuted = $true
}
else {
    $result.CheckpointRefresh = [pscustomobject][ordered]@{
        Requested = $false
        Message = 'Checkpoint refresh not requested.'
    }
}

$result.PlanOnly = $false
$result.Message = 'Guest driver test-certificate trust import completed.'

if ($Json) {
    [pscustomobject]$result | ConvertTo-Json -Depth 10
}
else {
    [pscustomobject]$result
}
