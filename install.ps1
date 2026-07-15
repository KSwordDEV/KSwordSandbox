<#
.SYNOPSIS
Installs, changes, or uninstalls local KSwordSandbox operator settings.

.DESCRIPTION
The installer is intentionally local-only. It prepares runtime folders and
stores the guest credential secret outside git so provider live scripts can read
KSWORDBOX_GUEST_PASSWORD without embedding passwords in config files.
It can also record the optional VirusTotal API key in the current user's
environment so the WebUI can perform hash-only lookups without committing a key.

Default mode is the guided first-run setup; it asks common settings after launch:

  .\install.ps1

Automation/advanced examples:

  .\install.ps1 -InstallEntrypoint CreateOrPreparePath -PlanOnly
  .\install.ps1 -Mode Change -ResetPassword -PromptPassword
  .\install.ps1 -Mode Change -UpdateHyperVConfig -VmName KSwordSandbox-Win10-Golden -CheckpointName Clean
  .\install.ps1 -Mode Change -UpdateVirtualizationConfig -DriverHostPath D:\Temp\KSwordSandbox\build\r0-driver\Release\KSword.Sandbox.Driver.sys
  .\install.ps1 -Mode ConfigureVTKey -PromptVTKey
  .\install.ps1 -Mode CheckEnvironment
  .\install.ps1 -Mode StartWebUI
  .\install.ps1 -InstallEntrypoint UseConfiguredEnvironment -PlanOnly
  .\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -PlanOnly
  .\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -AllowVmMutation -Confirm
  .\install.ps1 -InstallEntrypoint CreateOrPreparePath -PlanOnly
  .\install.ps1 -Mode Change -ResetGuestVmPassword -GeneratePassword -Force
  .\install.ps1 -Mode Change -ShowTestSigningGuidance
  .\install.ps1 -Mode Change -EnableGuestTestSigning -Force
  .\install.ps1 -Mode Uninstall

The script never prints the password value. By default it writes the configured
secret to the current user's environment and mirrors it into the current process
so commands launched from this PowerShell session can run immediately.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [ValidateSet('Interactive', 'Install', 'Change', 'Uninstall', 'Status', 'CheckEnvironment', 'ConfigureVTKey', 'StartWebUI')]
    [string]$Mode = 'Interactive',

    [string]$GuestUserName = 'SandboxUser',

    [string]$SecretName = 'KSWORDBOX_GUEST_PASSWORD',

    [string]$VirusTotalSecretName = 'KSWORDBOX_VIRUSTOTAL_API_KEY',

    [string]$RuntimeRoot = 'D:\Temp\KSwordSandbox',

    [string]$GuestPayloadRoot = 'D:\Temp\KSwordSandbox\payload\guest-tools',

    [string]$DriverHostPath = '',

    [ValidateSet('HyperV', 'VMware', 'Qemu')]
    [string]$VirtualizationProvider = 'HyperV',

    [string]$VmName = 'KSwordSandbox-Win10-Golden',

    [Alias('BaselineName', 'SnapshotName')]
    [string]$CheckpointName = 'Clean',

    [string]$VMwareVmxPath = '',

    [string]$VMwareVmrunPath = 'vmrun.exe',

    [ValidateSet('ws')]
    [string]$VMwareVmType = 'ws',

    [bool]$VMwareHeadless = $false,

    [string]$QemuDiskImagePath = '',

    [string]$QemuSystemPath = 'qemu-system-x86_64.exe',

    [string]$QemuImgPath = 'qemu-img.exe',

    [string[]]$QemuAdditionalArguments = @('-accel', 'whpx'),

    [ValidateSet('qcow2', 'raw', 'vhdx', 'vmdk')]
    [string]$QemuDiskFormat = 'qcow2',

    [ValidateSet('virtio', 'ide', 'scsi')]
    [string]$QemuDiskInterface = 'virtio',

    [bool]$QemuUseOverlayDisk = $true,

    [ValidateRange(256, 1048576)]
    [int]$QemuMemoryMegabytes = 4096,

    [bool]$QemuHeadless = $false,

    [string]$GuestRemotingAddress = '',

    [ValidateSet('Configured', 'VMwareTools', 'QemuUserNat')]
    [string]$GuestRemotingAddressMode = 'Configured',

    [ValidateRange(0, 65535)]
    [int]$GuestRemotingPort = 0,

    [switch]$GuestRemotingUseSsl,

    [switch]$GuestRemotingSkipCertificateChecks,

    [ValidateSet('Negotiate', 'Basic', 'CredSSP')]
    [string]$GuestRemotingAuthentication = 'Negotiate',

    [string]$GuestWorkingDirectory = 'C:\KSwordSandbox',

    [string]$LocalConfigPath = '',

    [string]$VirusTotalSettingsPath = '',

    [string]$WebUiUrl = 'http://127.0.0.1:18080',

    [ValidateSet('UseConfiguredEnvironment', 'RestoreCleanCheckpoint', 'CreateOrPreparePath')]
    [string]$InstallEntrypoint = 'UseConfiguredEnvironment',

    [switch]$GeneratePassword,

    [switch]$PromptPassword,

    [switch]$ResetPassword,

    [switch]$ResetGuestVmPassword,

    [switch]$RecoverGuestVmPasswordWithoutCurrentSecret,

    [switch]$UpdateHyperVConfig,

    [switch]$UpdateVirtualizationConfig,

    [switch]$ConfigureVTKey,

    [switch]$PromptVTKey,

    [switch]$ClearVTKey,

    [switch]$CheckEnvironment,

    [switch]$StartWebUI,

    [switch]$RunHyperVReadiness,

    [switch]$EnableGuestTestSigning,

    [switch]$DisableGuestTestSigning,

    [switch]$QueryGuestTestSigning,

    [switch]$ShowTestSigningGuidance,

    [switch]$RestartGuestAfterTestSigning,

    [switch]$CurrentProcessOnly,

    [switch]$SkipDpapiBackup,

    [switch]$SkipWebConfigEnvironment,

    [switch]$SkipCheckpointRefresh,

    [switch]$SkipCheckpointRestore,

    [int]$BootTimeoutSeconds = 240,

    [Alias('GuestReadyTimeoutSeconds')]
    [int]$PowerShellDirectTimeoutSeconds = 240,

    [switch]$OpenBrowser,

    [switch]$PlanOnly,

    [switch]$AllowVmMutation,

    [switch]$PrepareGuestPayload,

    [switch]$PassThru,

    [switch]$Json,

    [ValidateRange(4, 32)]
    [int]$JsonDepth = 12,

    [switch]$Force
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$script:InstallStateDirectory = Join-Path $env:ProgramData 'KSwordSandbox'
$script:InstallStatePath = Join-Path $script:InstallStateDirectory 'install-state.json'
$script:SecretBackupPath = Join-Path $script:InstallStateDirectory 'guest-password.dpapi'
$script:WebConfigPathEnvironmentName = 'Sandbox__ConfigPath'

function Write-InstallInfo {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "[install] $Message"
}

function Enter-InstallLiveExecutionLease {
    param([Parameter(Mandatory)][string]$Operation)

    $leasePath = [System.IO.Path]::GetFullPath((Join-Path $RuntimeRoot 'locks\live-execution.lock'))
    $leaseDirectory = Split-Path -Parent $leasePath
    try {
        New-Item -ItemType Directory -Path $leaseDirectory -Force | Out-Null
        return [System.IO.File]::Open(
            $leasePath,
            [System.IO.FileMode]::OpenOrCreate,
            [System.IO.FileAccess]::ReadWrite,
            [System.IO.FileShare]::None)
    }
    catch {
        throw "错误：无法为 '$Operation' 获取独占 live execution lease。另一个 Web/CLI/installer live 操作可能仍在运行，或 runtime root 的 locks 目录不可用；尚未执行任何 provider VM 命令。下一步：等待当前操作完成；若确认没有操作运行，请检查 '$leaseDirectory' 权限后重试。锁文件存在本身不代表占用，不要通过删除文件绕过 lease。"
    }
}

function Exit-InstallLiveExecutionLease {
    param([AllowNull()]$Lease)

    if ($null -ne $Lease) {
        $Lease.Dispose()
    }
}

$script:InitialRootBoundParameters = @{}
foreach ($parameterName in $PSBoundParameters.Keys) {
    $script:InitialRootBoundParameters[$parameterName] = $PSBoundParameters[$parameterName]
}

if ($PlanOnly -and -not $WhatIfPreference) {
    $WhatIfPreference = $true
    if (-not $Json) {
        Write-InstallInfo 'PlanOnly 已启用：本次只输出计划/诊断，不写入本机状态、不启动或还原 VM。 / PlanOnly enabled: diagnostics only.'
    }
}

function Read-MenuChoice {
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [Parameter(Mandatory)][string[]]$Allowed
    )

    do {
        $choice = (Read-Host $Prompt).Trim()
    } while ($Allowed -notcontains $choice)

    return $choice
}

function Read-YesNoChoice {
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [bool]$DefaultYes = $true
    )

    $suffix = if ($DefaultYes) { '[Y/n]' } else { '[y/N]' }
    while ($true) {
        $answer = (Read-Host "$Prompt $suffix").Trim()
        if ([string]::IsNullOrWhiteSpace($answer)) {
            return $DefaultYes
        }

        if ($answer -in @('y', 'Y', 'yes', 'YES', 'Yes')) {
            return $true
        }

        if ($answer -in @('n', 'N', 'no', 'NO', 'No')) {
            return $false
        }
    }
}

function Set-ScriptSwitchValue {
    param(
        [Parameter(Mandatory)][string]$Name,
        [bool]$Value
    )

    Set-Variable -Name $Name -Scope Script -Value ([System.Management.Automation.SwitchParameter]$Value) -WhatIf:$false
}

function Read-InstallState {
    if (-not (Test-Path -LiteralPath $script:InstallStatePath -PathType Leaf)) {
        return $null
    }

    try {
        return Get-Content -LiteralPath $script:InstallStatePath -Raw | ConvertFrom-Json
    }
    catch {
        if (-not $Json) {
            Write-InstallInfo "中文提示：无法读取安装状态文件 '$script:InstallStatePath'，将忽略它并继续。下一步：如状态异常，普通用户请重新运行 .\install.ps1 并按推荐安装向导修复；自动化可使用 CreateOrPreparePath 参数。英文详情：$($_.Exception.Message)"
        }
        return $null
    }
}

function Get-StateString {
    param(
        [AllowNull()]$State,
        [Parameter(Mandatory)][string]$Name,
        [AllowNull()][string]$DefaultValue
    )

    if ($null -ne $State) {
        $property = $State.PSObject.Properties[$Name]
        if ($null -ne $property -and -not [string]::IsNullOrWhiteSpace([string]$property.Value)) {
            return [string]$property.Value
        }
    }

    return $DefaultValue
}

function Get-JsonPropertyValue {
    param(
        [AllowNull()]$InputObject,
        [Parameter(Mandatory)][string]$Name
    )

    if ($null -eq $InputObject) {
        return $null
    }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}

function Get-FileSha256Hex {
    param([Parameter(Mandatory)][string]$Path)

    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete)
    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            return ([System.BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
        }
        finally {
            $sha.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
}

function Get-RelativePayloadPath {
    param(
        [Parameter(Mandatory)][string]$PayloadRoot,
        [Parameter(Mandatory)][string]$Path
    )

    $fullRoot = [System.IO.Path]::GetFullPath($PayloadRoot).TrimEnd('\', '/') + '\'
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    if ($fullPath.StartsWith($fullRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $fullPath.Substring($fullRoot.Length).Replace('\', '/')
    }

    return $fullPath.Replace('\', '/')
}

function Get-PackagedGuestPayloadRoot {
    $candidate = Join-Path $PSScriptRoot 'payload\guest-tools'
    $manifest = Join-Path $candidate 'payload-manifest.json'
    if (Test-Path -LiteralPath $manifest -PathType Leaf) {
        return [System.IO.Path]::GetFullPath($candidate)
    }

    return ''
}

function Initialize-EffectiveParameters {
    param(
        [AllowNull()]$State,
        [Parameter(Mandatory)][System.Collections.IDictionary]$BoundParameters
    )

    $bindings = @{
        GuestUserName = 'guestUserName'
        SecretName = 'secretName'
        VirusTotalSecretName = 'virusTotalSecretName'
        RuntimeRoot = 'runtimeRoot'
        GuestPayloadRoot = 'guestPayloadRoot'
        DriverHostPath = 'driverHostPath'
        VirtualizationProvider = 'virtualizationProvider'
        VmName = 'vmName'
        CheckpointName = 'checkpointName'
        VMwareVmxPath = 'vmwareVmxPath'
        VMwareVmrunPath = 'vmwareVmrunPath'
        VMwareVmType = 'vmwareVmType'
        QemuDiskImagePath = 'qemuDiskImagePath'
        QemuSystemPath = 'qemuSystemPath'
        QemuImgPath = 'qemuImgPath'
        QemuDiskFormat = 'qemuDiskFormat'
        QemuDiskInterface = 'qemuDiskInterface'
        GuestRemotingAddress = 'guestRemotingAddress'
        GuestRemotingAddressMode = 'guestRemotingAddressMode'
        GuestRemotingAuthentication = 'guestRemotingAuthentication'
        GuestWorkingDirectory = 'guestWorkingDirectory'
        LocalConfigPath = 'localConfigPath'
    }

    foreach ($entry in $bindings.GetEnumerator()) {
        if ($BoundParameters.ContainsKey($entry.Key)) {
            continue
        }

        $current = (Get-Variable -Name $entry.Key -Scope Script -ValueOnly)
        $value = Get-StateString -State $State -Name $entry.Value -DefaultValue $current
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            Set-Variable -Name $entry.Key -Value $value -Scope Script -WhatIf:$false
        }
    }

    $automaticGuestRemotingMigrated = $false
    if (-not $BoundParameters.ContainsKey('GuestRemotingAddressMode') -and
        $VirtualizationProvider -ne 'HyperV' -and
        [string]::IsNullOrWhiteSpace($GuestRemotingAddress) -and
        ($null -eq $State -or
         $null -eq $State.PSObject.Properties['guestRemotingAddressMode'] -or
         [string]::IsNullOrWhiteSpace([string]$State.PSObject.Properties['guestRemotingAddressMode'].Value))) {
        $script:GuestRemotingAddressMode = if ($VirtualizationProvider -eq 'VMware') { 'VMwareTools' } else { 'QemuUserNat' }
        $automaticGuestRemotingMigrated = $true
    }

    foreach ($booleanBinding in @{
            VMwareHeadless = 'vmwareHeadless'
            QemuUseOverlayDisk = 'qemuUseOverlayDisk'
            QemuHeadless = 'qemuHeadless'
            GuestRemotingUseSsl = 'guestRemotingUseSsl'
            GuestRemotingSkipCertificateChecks = 'guestRemotingSkipCertificateChecks'
        }.GetEnumerator()) {
        if ($BoundParameters.ContainsKey($booleanBinding.Key) -or $null -eq $State) {
            continue
        }

        $property = $State.PSObject.Properties[$booleanBinding.Value]
        if ($null -ne $property) {
            Set-Variable -Name $booleanBinding.Key -Value ([bool]$property.Value) -Scope Script -WhatIf:$false
        }
    }

    $automaticGuestEndpointSelected = $VirtualizationProvider -ne 'HyperV' -and $GuestRemotingAddressMode -ne 'Configured'
    $sslStateMissing = $null -eq $State -or $null -eq $State.PSObject.Properties['guestRemotingUseSsl']
    $skipCertificateStateMissing = $null -eq $State -or $null -eq $State.PSObject.Properties['guestRemotingSkipCertificateChecks']
    if ($automaticGuestRemotingMigrated -or $automaticGuestEndpointSelected) {
        if (-not $BoundParameters.ContainsKey('GuestRemotingUseSsl') -and ($automaticGuestRemotingMigrated -or $sslStateMissing)) {
            Set-ScriptSwitchValue -Name 'GuestRemotingUseSsl' -Value $true
        }
        if (-not $BoundParameters.ContainsKey('GuestRemotingSkipCertificateChecks') -and
            ($automaticGuestRemotingMigrated -or $skipCertificateStateMissing) -and
            [bool]$GuestRemotingUseSsl) {
            Set-ScriptSwitchValue -Name 'GuestRemotingSkipCertificateChecks' -Value $true
        }
    }

    if (-not $BoundParameters.ContainsKey('QemuAdditionalArguments') -and $null -ne $State) {
        $argumentsProperty = $State.PSObject.Properties['qemuAdditionalArguments']
        if ($null -ne $argumentsProperty) {
            $restoredArguments = @()
            if ($null -ne $argumentsProperty.Value) {
                $restoredArguments = @($argumentsProperty.Value | ForEach-Object { [string]$_ })
            }
            $script:QemuAdditionalArguments = $restoredArguments
        }
    }

    if (-not $BoundParameters.ContainsKey('GuestRemotingPort') -and $null -ne $State) {
        $portProperty = $State.PSObject.Properties['guestRemotingPort']
        if ($null -ne $portProperty) {
            $script:GuestRemotingPort = [int]$portProperty.Value
        }
    }

    if (-not $BoundParameters.ContainsKey('QemuMemoryMegabytes') -and $null -ne $State) {
        $memoryProperty = $State.PSObject.Properties['qemuMemoryMegabytes']
        if ($null -ne $memoryProperty) {
            $script:QemuMemoryMegabytes = [int]$memoryProperty.Value
        }
    }
}

function Initialize-PackagedPayloadDefault {
    param(
        [AllowNull()]$State,
        [Parameter(Mandatory)][System.Collections.IDictionary]$BoundParameters
    )

    if ($BoundParameters.ContainsKey('GuestPayloadRoot')) {
        return
    }

    if ($null -ne $State) {
        $property = $State.PSObject.Properties['guestPayloadRoot']
        if ($null -ne $property -and -not [string]::IsNullOrWhiteSpace([string]$property.Value)) {
            return
        }
    }

    $packagedPayloadRoot = Get-PackagedGuestPayloadRoot
    if (-not [string]::IsNullOrWhiteSpace($packagedPayloadRoot)) {
        $script:GuestPayloadRoot = $packagedPayloadRoot
    }
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function New-RandomPassword {
    param([int]$Length = 24)

    $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%_-+='
    $bytes = [byte[]]::new($Length)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    }
    finally {
        if ($null -ne $rng) {
            $rng.Dispose()
        }
    }
    $chars = for ($index = 0; $index -lt $Length; $index++) {
        $alphabet[$bytes[$index] % $alphabet.Length]
    }

    return -join $chars
}

function ConvertFrom-SecureStringToPlainText {
    param([Parameter(Mandatory)][securestring]$SecureString)

    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringUni($bstr)
    }
    finally {
        if ($bstr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }
}

function Read-GuestPassword {
    param(
        [bool]$UseGenerated,
        [bool]$UsePrompt,
        [string]$ExistingSecretName
    )

    if ($UseGenerated) {
        return [pscustomobject]@{
            Password = New-RandomPassword
            Source = 'generated'
        }
    }

    if ($UsePrompt) {
        $secure = Read-Host "请输入来宾密码（secret: $ExistingSecretName；不会回显） / Enter guest password" -AsSecureString
        return [pscustomobject]@{
            Password = ConvertFrom-SecureStringToPlainText -SecureString $secure
            Source = 'prompt'
        }
    }

    if ($Mode -ne 'Interactive') {
        throw '错误：非交互安装/更改在设置或重置密码时需要 -GeneratePassword 或 -PromptPassword。下一步：普通用户请直接运行 .\install.ps1 并按提示输入密码；自动化请明确使用 -PromptPassword 或 -GeneratePassword。'
    }

    Write-Host ''
    Write-Host '来宾密码选项 / Guest password options:'
    Write-Host '  1) 生成随机密码并仅保存在本机 / Generate a new random password locally'
    Write-Host '  2) 输入 VM 中现有 SandboxUser 密码 / Type the existing VM SandboxUser password'
    $choice = Read-MenuChoice -Prompt '请选择 [1-2] / Choose [1-2]' -Allowed @('1', '2')
    if ($choice -eq '1') {
        return [pscustomobject]@{
            Password = New-RandomPassword
            Source = 'generated'
        }
    }

    $secure = Read-Host "请输入来宾密码（secret: $ExistingSecretName；不会回显） / Enter guest password" -AsSecureString
    return [pscustomobject]@{
        Password = ConvertFrom-SecureStringToPlainText -SecureString $secure
        Source = 'prompt'
    }
}

function Read-NewGuestPassword {
    if ($GeneratePassword) {
        return [pscustomobject]@{ Password = New-RandomPassword; Source = 'generated' }
    }
    if ($PromptPassword) {
        $secure = Read-Host "请输入新的来宾密码（secret: $SecretName；不会回显） / Enter the new guest password" -AsSecureString
        return [pscustomobject]@{ Password = ConvertFrom-SecureStringToPlainText -SecureString $secure; Source = 'prompt' }
    }
    if ($Mode -ne 'Interactive') {
        throw '错误：非交互实际 VM 密码重置需要 -GeneratePassword 或 -PromptPassword。'
    }

    Write-Host ''
    Write-Host '新的 VM 来宾密码 / New VM guest password:'
    Write-Host '  1) 生成随机新密码 / Generate a random new password'
    Write-Host '  2) 输入新密码 / Enter a new password'
    $choice = Read-MenuChoice -Prompt '请选择 [1-2] / Choose [1-2]' -Allowed @('1', '2')
    if ($choice -eq '1') {
        return [pscustomobject]@{ Password = New-RandomPassword; Source = 'generated' }
    }

    $secure = Read-Host "请输入新的来宾密码（secret: $SecretName；不会回显） / Enter the new guest password" -AsSecureString
    return [pscustomobject]@{ Password = ConvertFrom-SecureStringToPlainText -SecureString $secure; Source = 'prompt' }
}

function Save-DpapiSecretBackup {
    param(
        [Parameter(Mandatory)][string]$Password,
        [Parameter(Mandatory)][string]$Path
    )

    if (-not $PSCmdlet.ShouldProcess($Path, 'Write DPAPI-protected guest password backup')) {
        Write-InstallInfo "预览：会为当前 Windows 帐户写入 DPAPI 备份：$Path / WhatIf: DPAPI backup would be written."
        return
    }

    $parent = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    $secure = ConvertTo-SecureString $Password -AsPlainText -Force
    $secure | ConvertFrom-SecureString | Set-Content -LiteralPath $Path -Encoding ASCII
}

function Get-LocalSandboxConfigPath {
    if (-not [string]::IsNullOrWhiteSpace($LocalConfigPath)) {
        return [System.IO.Path]::GetFullPath($LocalConfigPath)
    }

    return [System.IO.Path]::GetFullPath((Join-Path $RuntimeRoot 'config\sandbox.local.json'))
}

function Resolve-RepositoryRelativePath {
    param([Parameter(Mandatory)][string]$Path)

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot $Path))
}

function Resolve-DriverHostPath {
    if (-not [string]::IsNullOrWhiteSpace($DriverHostPath)) {
        return Resolve-RepositoryRelativePath -Path $DriverHostPath
    }

    $existingConfigPath = Get-LocalSandboxConfigPath
    if (Test-Path -LiteralPath $existingConfigPath -PathType Leaf) {
        try {
            $existingConfig = Get-Content -LiteralPath $existingConfigPath -Raw | ConvertFrom-Json
            $existingHostDriverPathProperty = $existingConfig.PSObject.Properties['driver']
            if ($null -ne $existingHostDriverPathProperty -and $null -ne $existingHostDriverPathProperty.Value) {
                $driverObject = $existingHostDriverPathProperty.Value
                $hostDriverPathProperty = $driverObject.PSObject.Properties['hostDriverPath']
                if ($null -ne $hostDriverPathProperty -and -not [string]::IsNullOrWhiteSpace([string]$hostDriverPathProperty.Value)) {
                    return Resolve-RepositoryRelativePath -Path ([string]$hostDriverPathProperty.Value)
                }
            }
        }
        catch {
            Write-InstallInfo "中文提示：无法读取现有 driver.hostDriverPath，将继续自动检测。下一步：如需真实 R0，请稍后用 -DriverHostPath 明确配置。路径：$existingConfigPath；英文详情：$($_.Exception.Message)"
        }
    }

    foreach ($candidate in @(
            (Join-Path $RuntimeRoot 'build\r0-driver\Release\KSword.Sandbox.Driver.sys'),
            (Join-Path $RuntimeRoot 'build\r0-driver\Debug\KSword.Sandbox.Driver.sys'),
            (Join-Path $PSScriptRoot 'x64\Release\KSword.Sandbox.Driver.sys'),
            (Join-Path $PSScriptRoot 'x64\Debug\KSword.Sandbox.Driver.sys'),
            (Join-Path $PSScriptRoot 'driver\KSword.Sandbox.Driver\x64\Release\KSword.Sandbox.Driver.sys'),
            (Join-Path $PSScriptRoot 'driver\KSword.Sandbox.Driver\x64\Debug\KSword.Sandbox.Driver.sys'))) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return [System.IO.Path]::GetFullPath($candidate)
        }
    }

    return $null
}

function Add-MissingSandboxConfigProperties {
    param(
        [Parameter(Mandatory)][pscustomobject]$Target,
        [Parameter(Mandatory)][pscustomobject]$Defaults
    )

    foreach ($defaultProperty in $Defaults.PSObject.Properties) {
        $targetProperty = $Target.PSObject.Properties[$defaultProperty.Name]
        if ($null -eq $targetProperty) {
            $Target | Add-Member -NotePropertyName $defaultProperty.Name -NotePropertyValue $defaultProperty.Value
            continue
        }

        if ($targetProperty.Value -is [pscustomobject] -and $defaultProperty.Value -is [pscustomobject]) {
            Add-MissingSandboxConfigProperties -Target $targetProperty.Value -Defaults $defaultProperty.Value
        }
    }
}

function Initialize-LegacyGuestRemotingAddressModes {
    param(
        [Parameter(Mandatory)][pscustomobject]$Config,
        [Parameter(Mandatory)][pscustomobject]$Defaults
    )

    $legacyAddress = if ($null -ne $Config.PSObject.Properties['guest'] -and
        $null -ne $Config.guest -and
        $null -ne $Config.guest.PSObject.Properties['powerShellRemotingAddress']) {
        [string]$Config.guest.powerShellRemotingAddress
    }
    else {
        ''
    }
    $guest = if ($null -ne $Config.PSObject.Properties['guest']) { $Config.guest } else { $null }
    $defaultGuest = $Defaults.guest
    foreach ($sectionName in @('vmware', 'qemu')) {
        $sectionProperty = $Config.PSObject.Properties[$sectionName]
        $defaultSectionProperty = $Defaults.PSObject.Properties[$sectionName]
        if ($null -eq $sectionProperty -or $null -eq $sectionProperty.Value -or $null -eq $defaultSectionProperty) {
            continue
        }

        $section = $sectionProperty.Value
        $legacyRemoting = if ([string]::IsNullOrWhiteSpace($legacyAddress)) {
            $null
        }
        else {
            [pscustomobject][ordered]@{
                addressMode = 'Configured'
                address = $legacyAddress
                authentication = if ($null -ne $guest -and $null -ne $guest.PSObject.Properties['powerShellRemotingAuthentication']) { [string]$guest.powerShellRemotingAuthentication } else { [string]$defaultGuest.powerShellRemotingAuthentication }
                useSsl = if ($null -ne $guest -and $null -ne $guest.PSObject.Properties['powerShellRemotingUseSsl']) { [bool]$guest.powerShellRemotingUseSsl } else { [bool]$defaultGuest.powerShellRemotingUseSsl }
                port = if ($null -ne $guest -and $null -ne $guest.PSObject.Properties['powerShellRemotingPort']) { [int]$guest.powerShellRemotingPort } else { [int]$defaultGuest.powerShellRemotingPort }
                skipCertificateChecks = if ($null -ne $guest -and $null -ne $guest.PSObject.Properties['powerShellRemotingSkipCertificateChecks']) { [bool]$guest.powerShellRemotingSkipCertificateChecks } else { [bool]$defaultGuest.powerShellRemotingSkipCertificateChecks }
            }
        }
        $remotingProperty = $section.PSObject.Properties['guestRemoting']
        if ($null -eq $remotingProperty) {
            if ($null -ne $legacyRemoting) {
                $section | Add-Member -NotePropertyName 'guestRemoting' -NotePropertyValue $legacyRemoting
            }
            continue
        }
        if ($null -eq $remotingProperty.Value) {
            if ($null -eq $legacyRemoting) {
                $remotingProperty.Value = $defaultSectionProperty.Value.guestRemoting
            }
            else {
                $remotingProperty.Value = $legacyRemoting
            }
            continue
        }
        if ($null -eq $remotingProperty.Value.PSObject.Properties['addressMode']) {
            $remotingProperty.Value | Add-Member -NotePropertyName 'addressMode' -NotePropertyValue 'Configured'
        }
    }
}

function Write-LocalSandboxConfig {
    $targetPath = Get-LocalSandboxConfigPath
    $templatePath = Join-Path $PSScriptRoot 'config\sandbox.example.json'
    if (-not (Test-Path -LiteralPath $templatePath -PathType Leaf)) {
        throw "错误：找不到 sandbox 配置模板：$templatePath。下一步：请确认在仓库根目录运行，或重新获取缺失的 config\sandbox.example.json。"
    }

    $defaults = Get-Content -LiteralPath $templatePath -Raw | ConvertFrom-Json
    $config = if (Test-Path -LiteralPath $targetPath -PathType Leaf) {
        Get-Content -LiteralPath $targetPath -Raw | ConvertFrom-Json -ErrorAction Stop
    }
    else {
        Get-Content -LiteralPath $templatePath -Raw | ConvertFrom-Json -ErrorAction Stop
    }
    Initialize-LegacyGuestRemotingAddressModes -Config $config -Defaults $defaults
    Add-MissingSandboxConfigProperties -Target $config -Defaults $defaults
    $config.virtualization.provider = $VirtualizationProvider
    switch ($VirtualizationProvider) {
        'HyperV' {
            $config.hyperV.goldenVmName = $VmName
            $config.hyperV.goldenSnapshotName = $CheckpointName
        }
        'VMware' {
            $config.vmware.vmName = $VmName
            $config.vmware.vmxPath = $VMwareVmxPath
            $config.vmware.snapshotName = $CheckpointName
            $config.vmware.vmrunPath = $VMwareVmrunPath
            $config.vmware.vmType = $VMwareVmType
            $config.vmware.headless = [bool]$VMwareHeadless
            $config.vmware.guestRemoting.address = if ([string]::IsNullOrWhiteSpace($GuestRemotingAddress)) { $null } else { $GuestRemotingAddress.Trim() }
            $config.vmware.guestRemoting.addressMode = $GuestRemotingAddressMode
            $config.vmware.guestRemoting.port = [int]$GuestRemotingPort
            $config.vmware.guestRemoting.useSsl = [bool]$GuestRemotingUseSsl
            $config.vmware.guestRemoting.authentication = $GuestRemotingAuthentication
            $config.vmware.guestRemoting.skipCertificateChecks = [bool]$GuestRemotingSkipCertificateChecks
        }
        'Qemu' {
            $config.qemu.vmName = $VmName
            $config.qemu.diskImagePath = $QemuDiskImagePath
            $config.qemu.qemuSystemPath = $QemuSystemPath
            $config.qemu.qemuImgPath = $QemuImgPath
            $config.qemu.additionalArguments = @($QemuAdditionalArguments)
            $config.qemu.diskFormat = $QemuDiskFormat
            $config.qemu.diskInterface = $QemuDiskInterface
            $config.qemu.snapshotName = $CheckpointName
            $config.qemu.useOverlayDisk = [bool]$QemuUseOverlayDisk
            $config.qemu.memoryMegabytes = [int]$QemuMemoryMegabytes
            $config.qemu.headless = [bool]$QemuHeadless
            $config.qemu.guestRemoting.address = if ([string]::IsNullOrWhiteSpace($GuestRemotingAddress)) { $null } else { $GuestRemotingAddress.Trim() }
            $config.qemu.guestRemoting.addressMode = $GuestRemotingAddressMode
            $config.qemu.guestRemoting.port = [int]$GuestRemotingPort
            $config.qemu.guestRemoting.useSsl = [bool]$GuestRemotingUseSsl
            $config.qemu.guestRemoting.authentication = $GuestRemotingAuthentication
            $config.qemu.guestRemoting.skipCertificateChecks = [bool]$GuestRemotingSkipCertificateChecks
        }
    }
    $config.guest.userName = $GuestUserName
    $config.guest.passwordSecretName = $SecretName
    $config.guest.workingDirectory = $GuestWorkingDirectory
    $config.guest.enablePowerShellDirect = $VirtualizationProvider -eq 'HyperV'
    if ($VirtualizationProvider -ne 'HyperV') {
        $config.guest.powerShellRemotingAddress = if ([string]::IsNullOrWhiteSpace($GuestRemotingAddress)) { $null } else { $GuestRemotingAddress.Trim() }
        $config.guest.powerShellRemotingPort = [int]$GuestRemotingPort
        $config.guest.powerShellRemotingUseSsl = [bool]$GuestRemotingUseSsl
        $config.guest.powerShellRemotingAuthentication = $GuestRemotingAuthentication
        $config.guest.powerShellRemotingSkipCertificateChecks = [bool]$GuestRemotingSkipCertificateChecks
    }
    $config.paths.runtimeRoot = $RuntimeRoot
    $config.paths.guestPayloadRoot = $GuestPayloadRoot
    $config.driver.hostDriverPath = Resolve-DriverHostPath

    $driverEventsFileName = Split-Path -Leaf $config.driver.eventJsonLinesPath
    $r0CollectorFileName = Split-Path -Leaf $config.driver.r0CollectorPathInGuest
    $driverFileName = Split-Path -Leaf $config.driver.driverPathInGuest
    if (-not [string]::IsNullOrWhiteSpace($driverEventsFileName)) {
        $config.driver.eventJsonLinesPath = Join-Path (Join-Path $GuestWorkingDirectory 'out') $driverEventsFileName
    }
    if (-not [string]::IsNullOrWhiteSpace($r0CollectorFileName)) {
        $config.driver.r0CollectorPathInGuest = Join-Path (Join-Path $GuestWorkingDirectory 'r0collector') $r0CollectorFileName
    }
    if (-not [string]::IsNullOrWhiteSpace($driverFileName)) {
        $config.driver.driverPathInGuest = Join-Path (Join-Path $GuestWorkingDirectory 'driver') $driverFileName
    }

    if ($PSCmdlet.ShouldProcess($targetPath, 'Write local sandbox config')) {
        $parent = Split-Path -Parent $targetPath
        if (-not [string]::IsNullOrWhiteSpace($parent)) {
            New-Item -ItemType Directory -Path $parent -Force | Out-Null
        }

        $config | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $targetPath -Encoding UTF8
        Write-InstallInfo "本机 sandbox 配置已写入：$targetPath / Local sandbox config written."
        if ([string]::IsNullOrWhiteSpace([string]$config.driver.hostDriverPath)) {
            Write-InstallInfo 'R0 警告：真实 R0 采集需要 driver.hostDriverPath，但未自动发现已构建的 .sys。下一步：用 -DriverHostPath 指向测试签名 .sys，或在本机配置中启用 driver.useMockCollector=true/driver.enabled=false。 / R0 warning: driver.hostDriverPath is missing.'
        }
        else {
            Write-InstallInfo "已配置 driver.hostDriverPath：$($config.driver.hostDriverPath) / Configured driver.hostDriverPath."
        }
    }
    else {
        Write-InstallInfo "预览：会写入本机 sandbox 配置：$targetPath / WhatIf: local sandbox config would be written."
    }

    return $targetPath
}

function Set-WebConfigPathEnvironment {
    param([Parameter(Mandatory)][string]$ConfigPath)

    if ($SkipWebConfigEnvironment) {
        Write-InstallInfo "已按请求跳过 '$script:WebConfigPathEnvironmentName' 环境变量更新。下一步：如 WebUI 找不到配置，请手动设置该变量或去掉 -SkipWebConfigEnvironment。 / Skipped environment update."
        return
    }

    if (-not $PSCmdlet.ShouldProcess($script:WebConfigPathEnvironmentName, "Set Web/API config path environment variable to '$ConfigPath'")) {
        Write-InstallInfo "预览：'$script:WebConfigPathEnvironmentName' 会指向 '$ConfigPath'。 / WhatIf: environment variable would be set."
        return
    }

    [Environment]::SetEnvironmentVariable($script:WebConfigPathEnvironmentName, $ConfigPath, 'Process')
    if (-not $CurrentProcessOnly) {
        [Environment]::SetEnvironmentVariable($script:WebConfigPathEnvironmentName, $ConfigPath, 'User')
        Write-InstallInfo "已把 User 环境变量 '$script:WebConfigPathEnvironmentName' 指向本机 sandbox 配置。下一步：新开的 PowerShell 也能继承该配置。 / User environment set."
    }
    else {
        Write-InstallInfo "已把当前 PowerShell 进程的 '$script:WebConfigPathEnvironmentName' 指向本机 sandbox 配置。 / Current process environment set."
    }
}

function Read-VirusTotalApiKey {
    if ($ClearVTKey) {
        return ''
    }

    if (-not $PromptVTKey -and $Mode -notin @('Interactive', 'ConfigureVTKey') -and -not $ConfigureVTKey) {
        throw '错误：非交互配置 VirusTotal key 需要 -PromptVTKey 或 -ClearVTKey。下一步：要保存 key 请加 -PromptVTKey；要清除本机设置请加 -ClearVTKey。'
    }

    $secure = Read-Host "请输入可选 VirusTotal API key（secret: $VirusTotalSecretName；不会回显） / Enter optional VirusTotal API key" -AsSecureString
    return ConvertFrom-SecureStringToPlainText -SecureString $secure
}

function Set-VirusTotalApiKeySecret {
    param([AllowNull()][string]$ApiKey)

    if ([string]::IsNullOrWhiteSpace($VirusTotalSecretName)) {
        throw '错误：VirusTotal secret 环境变量名不能为空。下一步：请保留默认 -VirusTotalSecretName，或传入非空名称。'
    }

    if ($ClearVTKey) {
        if (-not $PSCmdlet.ShouldProcess($VirusTotalSecretName, 'Clear optional VirusTotal API key from process/User environment')) {
            Write-InstallInfo "预览：会从 Process/User 环境清除可选 VirusTotal API key '$VirusTotalSecretName'。 / WhatIf: optional VT key would be cleared."
            return
        }

        [Environment]::SetEnvironmentVariable($VirusTotalSecretName, $null, 'Process')
        [Environment]::SetEnvironmentVariable($VirusTotalSecretName, $null, 'User')
        Write-InstallInfo "已从 Process/User 环境清除可选 VirusTotal API key '$VirusTotalSecretName'。 / Optional VT key cleared."
        return
    }

    if ([string]::IsNullOrWhiteSpace($ApiKey)) {
        throw '错误：VirusTotal API key 不能为空。下一步：要移除本机设置请使用 -ClearVTKey；要保存 key 请重新运行并输入有效值。'
    }

    if (-not $PSCmdlet.ShouldProcess($VirusTotalSecretName, 'Store optional VirusTotal API key in local environment without printing it')) {
        Write-InstallInfo "预览：会在本机保存可选 VirusTotal API key '$VirusTotalSecretName'，不会打印值。 / WhatIf: optional VT key would be stored."
        return
    }

    $trimmed = $ApiKey.Trim()
    [Environment]::SetEnvironmentVariable($VirusTotalSecretName, $trimmed, 'Process')
    if (-not $CurrentProcessOnly) {
        [Environment]::SetEnvironmentVariable($VirusTotalSecretName, $trimmed, 'User')
        Write-InstallInfo "可选 VirusTotal API key '$VirusTotalSecretName' 已保存到当前 User 环境，值未打印。下一步：重新启动 WebUI 后会继承该值。 / Optional VT key stored in User environment."
    }
    else {
        Write-InstallInfo "可选 VirusTotal API key '$VirusTotalSecretName' 仅保存到当前进程，值未打印。下一步：只在当前 PowerShell 启动 WebUI 时有效。 / Optional VT key stored only in current process."
    }
}

function Invoke-VirusTotalKeyConfiguration {
    if ($WhatIfPreference) {
        [void]$PSCmdlet.ShouldProcess($VirusTotalSecretName, 'Configure optional VirusTotal API key')
        Write-InstallInfo "预览：会配置或清除可选 VirusTotal API key '$VirusTotalSecretName'，不会打印值。 / WhatIf: optional VT key would be configured or cleared."
        return
    }

    $effectiveClear = [bool]$ClearVTKey
    if ($Mode -eq 'Interactive' -and -not $PromptVTKey -and -not $ClearVTKey) {
        Write-Host ''
        Write-Host 'VirusTotal API key 选项 / VirusTotal API key options:'
        Write-Host '  1) 提示输入并保存可选 key 到本机环境 / Prompt and store optional key locally'
        Write-Host '  2) 从 Process/User 环境清除本机 key / Clear local key'
        Write-Host '  3) 返回 / Back'
        $choice = Read-MenuChoice -Prompt '请选择 [1-3] / Choose [1-3]' -Allowed @('1', '2', '3')
        if ($choice -eq '3') {
            Write-InstallInfo '已取消 VirusTotal key 配置。 / VirusTotal key configuration cancelled.'
            return
        }

        $effectiveClear = ($choice -eq '2')
        $script:ClearVTKey = $effectiveClear
    }

    if ($effectiveClear) {
        Set-VirusTotalApiKeySecret -ApiKey ''
        return
    }

    $apiKey = Read-VirusTotalApiKey
    Set-VirusTotalApiKeySecret -ApiKey $apiKey
}

function Save-InstallState {
    param(
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][string]$GuestUser,
        [Parameter(Mandatory)][string]$Secret,
        [Parameter(Mandatory)][string]$Runtime,
        [Parameter(Mandatory)][string]$PayloadRoot,
        [Parameter(Mandatory)][string]$PasswordSource,
        [bool]$PersistedToUser,
        [bool]$PersistedToProcess,
        [bool]$DpapiBackup,
        [string]$Vm = $VmName,
        [string]$Checkpoint = $CheckpointName,
        [string]$GuestWorking = $GuestWorkingDirectory,
        [AllowNull()][string]$DriverHost = (Resolve-DriverHostPath),
        [string]$LocalConfig = ''
    )

    if ([string]::IsNullOrWhiteSpace($LocalConfig)) {
        $LocalConfig = Get-LocalSandboxConfigPath
    }

    $state = [ordered]@{
        installStateVersion = 3
        action = $Action
        updatedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
        guestUserName = $GuestUser
        secretName = $Secret
        virusTotalSecretName = $VirusTotalSecretName
        runtimeRoot = $Runtime
        guestPayloadRoot = $PayloadRoot
        passwordSource = $PasswordSource
        persistedToUserEnvironment = $PersistedToUser
        persistedToCurrentProcess = $PersistedToProcess
        dpapiBackupPath = if ($DpapiBackup) { $script:SecretBackupPath } else { $null }
        vmName = $Vm
        checkpointName = $Checkpoint
        virtualizationProvider = $VirtualizationProvider
        vmwareVmxPath = $VMwareVmxPath
        vmwareVmrunPath = $VMwareVmrunPath
        vmwareVmType = $VMwareVmType
        vmwareHeadless = [bool]$VMwareHeadless
        qemuDiskImagePath = $QemuDiskImagePath
        qemuSystemPath = $QemuSystemPath
        qemuImgPath = $QemuImgPath
        qemuAdditionalArguments = @($QemuAdditionalArguments)
        qemuDiskFormat = $QemuDiskFormat
        qemuDiskInterface = $QemuDiskInterface
        qemuUseOverlayDisk = [bool]$QemuUseOverlayDisk
        qemuMemoryMegabytes = [int]$QemuMemoryMegabytes
        qemuHeadless = [bool]$QemuHeadless
        guestRemotingAddress = $GuestRemotingAddress
        guestRemotingAddressMode = $GuestRemotingAddressMode
        guestRemotingPort = [int]$GuestRemotingPort
        guestRemotingUseSsl = [bool]$GuestRemotingUseSsl
        guestRemotingSkipCertificateChecks = [bool]$GuestRemotingSkipCertificateChecks
        guestRemotingAuthentication = $GuestRemotingAuthentication
        guestWorkingDirectory = $GuestWorking
        driverHostPath = $DriverHost
        localConfigPath = $LocalConfig
        webConfigPathEnvironmentName = $script:WebConfigPathEnvironmentName
        secretValuePrinted = $false
    }

    if (-not $PSCmdlet.ShouldProcess($script:InstallStatePath, "Write install state for action '$Action'")) {
        Write-InstallInfo "预览：会写入安装状态：$script:InstallStatePath / WhatIf: install state would be written."
        return
    }

    New-Item -ItemType Directory -Path $script:InstallStateDirectory -Force | Out-Null
    $state | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $script:InstallStatePath -Encoding UTF8
}

function Set-GuestPasswordSecret {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Password,
        [string]$PasswordSource = 'unknown'
    )

    if ([string]::IsNullOrWhiteSpace($Name)) {
        throw '错误：SecretName 不能为空。下一步：请保留默认 KSWORDBOX_GUEST_PASSWORD，或传入非空 -SecretName。'
    }

    if ([string]::IsNullOrEmpty($Password)) {
        throw '错误：来宾密码不能为空。下一步：请重新运行 -PromptPassword 并输入 VM 中 SandboxUser 的密码，或使用 -GeneratePassword 后同步 VM 密码。'
    }

    if (-not $PSCmdlet.ShouldProcess($Name, "Store guest password secret from source '$PasswordSource'")) {
        Write-InstallInfo "预览：会在本机保存 guest password secret '$Name'，不会打印值。 / WhatIf: guest password secret would be stored."
        return
    }

    [Environment]::SetEnvironmentVariable($Name, $Password, 'Process')
    $persistedUser = $false
    if (-not $CurrentProcessOnly) {
        [Environment]::SetEnvironmentVariable($Name, $Password, 'User')
        $persistedUser = $true
    }

    $dpapiBackup = $false
    if (-not $SkipDpapiBackup) {
        Save-DpapiSecretBackup -Password $Password -Path $script:SecretBackupPath
        $dpapiBackup = $true
    }

    Save-InstallState `
        -Action 'credential-set' `
        -GuestUser $GuestUserName `
        -Secret $Name `
        -Runtime $RuntimeRoot `
        -PayloadRoot $GuestPayloadRoot `
        -PasswordSource $PasswordSource `
        -PersistedToUser $persistedUser `
        -PersistedToProcess $true `
        -DpapiBackup $dpapiBackup

    Write-InstallInfo "guest password secret '$Name' 已保存，值未打印。 / Guest password secret stored."
    Write-InstallInfo 'Value was not printed. / 密码值未打印。'
    if ($persistedUser) {
        Write-InstallInfo '已保存到当前 User 环境；新开的 PowerShell/Codex session 可继承。 / Stored in current User environment.'
    }
    else {
        Write-InstallInfo '仅保存到当前 PowerShell 进程；关闭窗口后不会保留。 / Stored only in current process.'
    }

    if ($dpapiBackup) {
        Write-InstallInfo "已为当前 Windows 帐户写入 DPAPI 备份：$script:SecretBackupPath / DPAPI backup written."
    }
}

function Initialize-KSwordSandboxRuntimeFolders {
    $directories = @(
        $RuntimeRoot,
        (Join-Path $RuntimeRoot 'jobs'),
        (Join-Path $RuntimeRoot 'plans'),
        (Join-Path $RuntimeRoot 'uploads'),
        (Join-Path $RuntimeRoot 'config'),
        $GuestPayloadRoot
    )

    foreach ($directory in $directories) {
        if ($PSCmdlet.ShouldProcess($directory, 'Create or verify local runtime directory')) {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
        }
    }
}

function Test-QemuWhpxAdditionalArguments {
    param(
        [AllowEmptyCollection()][string[]]$Arguments = @(),
        [ValidateSet('Configured', 'VMwareTools', 'QemuUserNat')][string]$GuestAddressMode = 'Configured'
    )

    Assert-QemuManagedAdditionalArguments -Arguments $Arguments -GuestAddressMode $GuestAddressMode
    $acceleratorConfigured = $false
    for ($index = 0; $index -lt @($Arguments).Count; $index++) {
        $argument = ([string]$Arguments[$index]).Trim()
        $acceleratorValue = $null
        if ($argument.Equals('-accel', [System.StringComparison]::OrdinalIgnoreCase)) {
            $index++
            if ($index -ge @($Arguments).Count) {
                throw "错误：QEMU additionalArguments 中 '-accel' 缺少值；Hyper-V 等价模式必须使用 '-accel','whpx'。"
            }
            $acceleratorValue = [string]$Arguments[$index]
        }
        elseif ($argument.StartsWith('-accel=', [System.StringComparison]::OrdinalIgnoreCase)) {
            $acceleratorValue = $argument.Substring('-accel='.Length)
        }
        else {
            $machineValue = $null
            if ($argument.Equals('-machine', [System.StringComparison]::OrdinalIgnoreCase) -or
                $argument.Equals('-M', [System.StringComparison]::Ordinal)) {
                if ($index + 1 -ge @($Arguments).Count) {
                    throw "错误：QEMU additionalArguments '$argument' 缺少 machine 值。"
                }
                $machineValue = [string]$Arguments[$index + 1]
            }
            elseif ($argument.StartsWith('-machine=', [System.StringComparison]::OrdinalIgnoreCase)) {
                $machineValue = $argument.Substring('-machine='.Length)
            }
            elseif ($argument.StartsWith('-M=', [System.StringComparison]::Ordinal)) {
                $machineValue = $argument.Substring('-M='.Length)
            }
            if (-not [string]::IsNullOrWhiteSpace($machineValue)) {
                $acceleratorPart = @($machineValue -split ',' | Where-Object { ([string]$_).Trim().StartsWith('accel=', [System.StringComparison]::OrdinalIgnoreCase) } | Select-Object -First 1)
                if ($acceleratorPart.Count -gt 0) {
                    $acceleratorValue = ([string]$acceleratorPart[0]).Trim().Substring('accel='.Length)
                }
            }
            elseif ($argument.StartsWith('-machine=', [System.StringComparison]::OrdinalIgnoreCase) -or
                $argument.StartsWith('-M=', [System.StringComparison]::Ordinal)) {
                throw "错误：QEMU additionalArguments '$argument' 缺少 machine 值。"
            }
        }

        if ($null -eq $acceleratorValue) {
            continue
        }
        $accelerator = @(([string]$acceleratorValue) -split ',', 2)[0].Trim()
        if (-not $accelerator.Equals('whpx', [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "错误：QEMU accelerator '$accelerator' 不支持 Hyper-V 等价的 Windows Live；请使用 '-accel','whpx'。TCG 软件模拟不计作 provider parity。"
        }
        $acceleratorConfigured = $true
    }

    return $acceleratorConfigured
}

function Assert-QemuManagedAdditionalArguments {
    param(
        [AllowEmptyCollection()][string[]]$Arguments = @(),
        [ValidateSet('Configured', 'VMwareTools', 'QemuUserNat')][string]$GuestAddressMode = 'Configured'
    )

    for ($index = 0; $index -lt @($Arguments).Count; $index++) {
        $argument = ([string]$Arguments[$index]).Trim()
        $option = @($argument -split '=', 2)[0].Trim()
        if ($option -cin @('-name', '-m', '-memory', '-pidfile', '-display')) {
            throw "错误：QEMU additionalArguments 不能设置 '$option'；VM 名称、内存、PID 归属和显示模式由 provider profile 统一管理。"
        }
        if ($argument -cin @('-daemonize', '-snapshot', '-nographic', '-curses', '-S')) {
            throw "错误：QEMU additionalArguments 不能包含 '$argument'；该参数会绕过 provider 的生命周期、baseline 或交互控制台保证。"
        }

        $driveValue = $null
        if ($argument -ceq '-drive') {
            if ($index + 1 -ge @($Arguments).Count -or [string]::IsNullOrWhiteSpace([string]$Arguments[$index + 1])) {
                throw "错误：QEMU additionalArguments '-drive' 缺少非空 drive 值。"
            }
            $driveValue = [string]$Arguments[$index + 1]
        }
        elseif ($argument.StartsWith('-drive=', [System.StringComparison]::Ordinal)) {
            $driveValue = $argument.Substring('-drive='.Length)
        }
        if ($null -ne $driveValue -and @($driveValue -split ',' | Where-Object {
                    ([string]$_).Trim().Equals('id=ksword-disk', [System.StringComparison]::OrdinalIgnoreCase)
                }).Count -gt 0) {
            throw '错误：QEMU additionalArguments 不能定义第二个 id=ksword-disk；该稳定磁盘标识由 provider 管理。'
        }
        if ($argument.IndexOf('id=ksword-scsi', [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -or
            $argument.IndexOf('bus=ksword-scsi.0', [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -or
            $argument.IndexOf('drive=ksword-disk', [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            throw '错误：QEMU additionalArguments 不能复用 id=ksword-scsi、bus=ksword-scsi.0 或 drive=ksword-disk；受管 SCSI 拓扑由 provider 保留。'
        }
        if ($GuestAddressMode -eq 'QemuUserNat' -and
            ($argument.IndexOf('id=ksword-net', [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -or
             $argument.IndexOf('netdev=ksword-net', [System.StringComparison]::OrdinalIgnoreCase) -ge 0)) {
            throw '错误：QemuUserNat 模式下不能复用 id/netdev=ksword-net；该网卡与 WinRM 转发由 provider 管理。'
        }
    }
}

function Set-VirtualizationConfigState {
    param([string]$Action = 'virtualization-config-updated')

    $automaticGuestEndpoint = $VirtualizationProvider -ne 'HyperV' -and $GuestRemotingAddressMode -ne 'Configured'
    if ($automaticGuestEndpoint -and -not $script:InitialRootBoundParameters.ContainsKey('GuestRemotingUseSsl')) {
        Set-ScriptSwitchValue -Name 'GuestRemotingUseSsl' -Value $true
        if (-not $script:InitialRootBoundParameters.ContainsKey('GuestRemotingSkipCertificateChecks')) {
            Set-ScriptSwitchValue -Name 'GuestRemotingSkipCertificateChecks' -Value $true
        }
    }

    if ([string]::IsNullOrWhiteSpace($VmName)) {
        throw "错误：$VirtualizationProvider VM 名称不能为空。下一步：请用 -VmName 指定现有分析 VM。"
    }
    if ($VirtualizationProvider -in @('HyperV', 'VMware') -and [string]::IsNullOrWhiteSpace($CheckpointName)) {
        throw "错误：$VirtualizationProvider 快照名称不能为空。下一步：请用 -CheckpointName 指定干净快照。"
    }
    if ($VirtualizationProvider -eq 'VMware' -and [string]::IsNullOrWhiteSpace($VMwareVmxPath)) {
        throw '错误：VMware 需要 -VMwareVmxPath 指向现有 .vmx 文件。'
    }
    if ($VirtualizationProvider -eq 'VMware' -and $VMwareVmType -ne 'ws') {
        throw "错误：完整 VMware 适配要求 Workstation Pro 与 VMwareVmType=ws；不再支持 Player 配置。请安装 Workstation Pro 并重新运行虚拟化配置。"
    }
    if ($VirtualizationProvider -eq 'Qemu' -and [string]::IsNullOrWhiteSpace($QemuDiskImagePath)) {
        throw '错误：QEMU 需要 -QemuDiskImagePath 指向现有基础磁盘镜像。'
    }
    if ($VirtualizationProvider -eq 'Qemu' -and -not [bool]$QemuUseOverlayDisk -and [string]::IsNullOrWhiteSpace($CheckpointName)) {
        throw '错误：QEMU 未启用 overlay 时需要 -CheckpointName 指定内部快照。'
    }
    if ($VirtualizationProvider -eq 'Qemu' -and -not [bool]$QemuUseOverlayDisk -and $QemuDiskFormat -ne 'qcow2') {
        throw '错误：QEMU 内部快照模式仅支持 qcow2；raw、vhdx 或 vmdk 基础镜像请启用 -QemuUseOverlayDisk $true。'
    }
    if ($VirtualizationProvider -eq 'Qemu' -and @($QemuAdditionalArguments | Where-Object { [string]::IsNullOrWhiteSpace([string]$_) }).Count -gt 0) {
        throw '错误：QEMU additional arguments 不能包含空参数。请移除空字符串后重试。'
    }
    if ($VirtualizationProvider -eq 'Qemu' -and -not (Test-QemuWhpxAdditionalArguments -Arguments $QemuAdditionalArguments -GuestAddressMode $GuestRemotingAddressMode)) {
        $script:QemuAdditionalArguments = @('-accel', 'whpx') + @($QemuAdditionalArguments)
    }
    if ($VirtualizationProvider -eq 'Qemu' -and $QemuDiskFormat -notin @('qcow2', 'raw', 'vhdx', 'vmdk')) {
        throw "错误：QemuDiskFormat='$QemuDiskFormat' 无效；应为 qcow2、raw、vhdx 或 vmdk。"
    }
    if ($VirtualizationProvider -eq 'Qemu' -and $QemuDiskInterface -notin @('virtio', 'ide', 'scsi')) {
        throw "错误：QemuDiskInterface='$QemuDiskInterface' 无效；应为 virtio、ide 或 scsi。if=none 不会把 provider 管理的磁盘连接到可启动设备。"
    }
    if ($VirtualizationProvider -eq 'Qemu' -and ($QemuMemoryMegabytes -lt 256 -or $QemuMemoryMegabytes -gt 1048576)) {
        throw "错误：QemuMemoryMegabytes='$QemuMemoryMegabytes' 无效；应在 256 到 1048576 之间。"
    }
    if ($VirtualizationProvider -eq 'VMware' -and $GuestRemotingAddressMode -notin @('Configured', 'VMwareTools')) {
        throw "错误：VMware GuestRemotingAddressMode 应为 Configured 或 VMwareTools。"
    }
    if ($VirtualizationProvider -eq 'Qemu' -and $GuestRemotingAddressMode -notin @('Configured', 'QemuUserNat')) {
        throw "错误：QEMU GuestRemotingAddressMode 应为 Configured 或 QemuUserNat。"
    }
    if ($VirtualizationProvider -ne 'HyperV' -and $GuestRemotingAddressMode -eq 'Configured' -and [string]::IsNullOrWhiteSpace($GuestRemotingAddress)) {
        throw "错误：$VirtualizationProvider 在 Configured 模式下需要 -GuestRemotingAddress；也可选择 provider 自动模式。"
    }
    if ($automaticGuestEndpoint -and -not $GuestRemotingUseSsl) {
        throw '错误：VMwareTools/QemuUserNat 自动端点模式要求 -GuestRemotingUseSsl；IP/loopback WinRM 不应依赖宿主机全局 TrustedHosts。'
    }
    if ($VirtualizationProvider -ne 'HyperV' -and ($GuestRemotingPort -lt 0 -or $GuestRemotingPort -gt 65535)) {
        throw "错误：GuestRemotingPort='$GuestRemotingPort' 无效；应为 0 到 65535。"
    }
    if ($VirtualizationProvider -ne 'HyperV' -and $GuestRemotingAuthentication -notin @('Negotiate', 'Basic', 'CredSSP')) {
        throw "错误：GuestRemotingAuthentication='$GuestRemotingAuthentication' 无效；应为 Negotiate、Basic 或 CredSSP。"
    }
    if ($VirtualizationProvider -ne 'HyperV' -and $GuestRemotingAuthentication -eq 'Basic' -and -not $GuestRemotingUseSsl) {
        throw '错误：拒绝通过 HTTP 使用 Basic WinRM；请启用 -GuestRemotingUseSsl，或改用 Negotiate/CredSSP。'
    }
    if ($VirtualizationProvider -ne 'HyperV' -and $GuestRemotingSkipCertificateChecks -and -not $GuestRemotingUseSsl) {
        throw '错误：-GuestRemotingSkipCertificateChecks 仅在启用 HTTPS (-GuestRemotingUseSsl) 时有效。'
    }
    if ([string]::IsNullOrWhiteSpace($GuestWorkingDirectory)) {
        throw '错误：来宾工作目录不能为空。下一步：请保留默认 C:\KSwordSandbox 或用 -GuestWorkingDirectory 指定。'
    }

    Initialize-KSwordSandboxRuntimeFolders
    $configPath = Write-LocalSandboxConfig
    Set-WebConfigPathEnvironment -ConfigPath $configPath

    Save-InstallState `
        -Action $Action `
        -GuestUser $GuestUserName `
        -Secret $SecretName `
        -Runtime $RuntimeRoot `
        -PayloadRoot $GuestPayloadRoot `
        -PasswordSource 'unchanged' `
        -PersistedToUser (-not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($SecretName, 'User'))) `
        -PersistedToProcess (-not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($SecretName, 'Process'))) `
        -DpapiBackup (Test-Path -LiteralPath $script:SecretBackupPath -PathType Leaf) `
        -LocalConfig $configPath

    Write-InstallInfo "已记录 $VirtualizationProvider 配置：VM='$VmName'，snapshot='$CheckpointName'，guestRoot='$GuestWorkingDirectory'。 / Virtualization config recorded."
    Write-InstallInfo "Web/API 可通过 '$script:WebConfigPathEnvironmentName=$configPath' 使用该配置。 / Web/API config path ready."
}

function Set-HyperVConfigState {
    param([string]$Action = 'hyperv-config-updated')
    $script:VirtualizationProvider = 'HyperV'
    Set-VirtualizationConfigState -Action $Action
}

function Test-InstallBaselineRestoreRequiresVmMutation {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('HyperV', 'VMware', 'Qemu')]
        [string]$Provider,

        [Parameter(Mandatory)]
        [bool]$UseQemuOverlayDisk
    )

    return $Provider -ne 'Qemu' -or -not $UseQemuOverlayDisk
}

function Get-InstallEntrypointNextSteps {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('UseConfiguredEnvironment', 'RestoreCleanCheckpoint', 'CreateOrPreparePath')]
        [string]$SelectedEntrypoint
    )

    $steps = [System.Collections.Generic.List[string]]::new()
    switch ($SelectedEntrypoint) {
        'UseConfiguredEnvironment' {
            [void]$steps.Add('下一步：确认 RecommendedActions 为空或只包含可接受项；该入口只读，不写 install-state/sandbox.local.json/secret，也不启动、停止或还原 VM。')
            [void]$steps.Add('下一步：运行 .\run.ps1 -Mode Plan -SamplePath <sample.exe> 做非变更计划检查；不要在发布低成本验证中加 -Live。')
            [void]$steps.Add('下一步：需要真实 Live 分析时，显式运行 .\run.ps1 -Mode Analyze -SamplePath <sample.exe> -Live；install 入口本身不会启动或还原 VM。')
        }
        'RestoreCleanCheckpoint' {
            $restoreRequiresMutation = Test-InstallBaselineRestoreRequiresVmMutation -Provider $VirtualizationProvider -UseQemuOverlayDisk ([bool]$QemuUseOverlayDisk)
            if ($restoreRequiresMutation) {
                [void]$steps.Add("下一步：先运行 .\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -PlanOnly 或 -WhatIf 检查 VM='$VmName' 和 baseline='$CheckpointName'。")
                [void]$steps.Add("下一步：确认是隔离实验 VM 后，加 -AllowVmMutation，并让 ShouldProcess/-Confirm 或 -Force 决定是否真实还原；Hyper-V 需管理员 PowerShell，VMware/QEMU 需当前账户有 provider 管理权限。")
                [void]$steps.Add('下一步：-Force 只是无人值守确认路径；仍必须与 -AllowVmMutation 同时出现，且仍经过 ShouldProcess 保护。')
            }
            else {
                [void]$steps.Add('下一步：当前 QEMU profile 使用 per-job overlay；基础盘保持只读语义，每次 Live 自动创建新的干净 overlay，因此无需执行原地 snapshot restore。')
                [void]$steps.Add('下一步：运行 .\install.ps1 -Mode CheckEnvironment 确认基础盘、QEMU 工具和 WHPX 就绪；随后可直接 Plan 或显式 Live，不需要 -AllowVmMutation/-Confirm。')
            }
        }
        'CreateOrPreparePath' {
            [void]$steps.Add("下一步：首台机器先运行 .\install.ps1 -InstallEntrypoint CreateOrPreparePath -PlanOnly 查看计划，再运行 -WhatIf 预览；两者都不会写文件、提示 secret、构建 payload 或修改 VM。输出路径：$RuntimeRoot。")
            [void]$steps.Add('下一步：普通用户直接运行 .\install.ps1，按推荐安装向导创建/刷新仓库外运行目录、sandbox.local.json、secret 和 install-state；仍不会创建任何 provider VM。')
            [void]$steps.Add('下一步：如果还没有黄金 VM，请先在所选虚拟化产品中创建/导入隔离 Windows VM 和干净 baseline，再运行 .\install.ps1 -Mode Change -UpdateVirtualizationConfig -VirtualizationProvider <HyperV|VMware|Qemu> 记录对应 profile。')
            [void]$steps.Add('下一步：需要 self-contained Guest Agent/R0Collector payload 时，显式加 -PrepareGuestPayload；PlanOnly/WhatIf 只显示将要执行的准备动作，目标必须是仓库外 GuestPayloadRoot/runtime root。')
        }
    }

    return @($steps.ToArray())
}

function Get-InstallOperatorModeMatrix {
    $configuredCommand = '.\install.ps1 -InstallEntrypoint UseConfiguredEnvironment -PlanOnly'
    $restoreRequiresMutation = Test-InstallBaselineRestoreRequiresVmMutation -Provider $VirtualizationProvider -UseQemuOverlayDisk ([bool]$QemuUseOverlayDisk)
    $restorePlanCommand = '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -PlanOnly'
    $restoreWhatIfCommand = if ($restoreRequiresMutation) { '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -AllowVmMutation -WhatIf' } else { '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -WhatIf' }
    $restoreCommand = if ($restoreRequiresMutation) { '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -AllowVmMutation -Confirm' } else { '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint' }
    $createCommand = '.\install.ps1'

    return @(
        [pscustomobject][ordered]@{
            ModeId = 'use-configured-environment'
            Entrypoint = 'UseConfiguredEnvironment'
            TitleZh = '使用已配置环境'
            TitleEn = 'Use already configured environment'
            IntentZh = '读取已有 install-state、sandbox.local.json、guest secret、VM/clean baseline profile 和 payload 状态。'
            DefaultCommand = $configuredCommand
            SafeDiagnostics = @('.\install.ps1 -Mode Status', '.\install.ps1 -Mode CheckEnvironment', '.\run.ps1 -Mode Status', '.\run.ps1 -Mode CheckEnvironment')
            MutationBoundary = 'read-only diagnostics only; no local write and no VM mutation'
            SafeBoundaryZh = '只读：不写本机状态、不改环境变量、不提示或保存 secret、不启动/停止/还原 VM。'
            StartsVm = $false
            RestoresCheckpoint = $false
            CreatesVm = $false
            CreatesLocalConfig = $false
            NextStepsZh = @(
                '下一步：如果 RecommendedActions 为空或只剩可接受警告，运行 .\run.ps1 启动 WebUI，或运行 .\run.ps1 -Mode Analyze -SamplePreset Notepad 做 PlanOnly。',
                '下一步：如果缺本机配置、secret、payload、VM 或 clean baseline，请切换到 fresh-create-new-computer 或 rollback-restore-snapshot 对应流程。'
            )
        },
        [pscustomobject][ordered]@{
            ModeId = 'rollback-restore-snapshot'
            Entrypoint = 'RestoreCleanCheckpoint'
            TitleZh = if ($restoreRequiresMutation) { '回退/恢复已有干净快照' } else { '确认 QEMU overlay 干净启动' }
            TitleEn = if ($restoreRequiresMutation) { 'Rollback or restore existing clean checkpoint/snapshot' } else { 'Confirm clean QEMU per-job overlay start' }
            IntentZh = if ($restoreRequiresMutation) { '只针对已经存在的 VM 和 clean checkpoint/snapshot；默认 PlanOnly/WhatIf 只展示计划。' } else { '确认基础盘保持不变且下一次 Live 创建新 overlay；不执行原地恢复或 VM 变更。' }
            DefaultCommand = $restorePlanCommand
            SafeDiagnostics = @($restorePlanCommand, $restoreWhatIfCommand, '.\install.ps1 -Mode CheckEnvironment')
            MutationBoundary = if ($restoreRequiresMutation) { 'actual restore requires -AllowVmMutation plus explicit -Confirm or -Force on an isolated lab host' } else { 'QEMU per-job overlay already guarantees a clean next-run disk; no in-place restore or VM mutation is required' }
            SafeBoundaryZh = if ($restoreRequiresMutation) { '默认只预览：-PlanOnly/-WhatIf 不调用 provider restore；真实还原必须 -AllowVmMutation，并显式 -Confirm 或 -Force。' } else { 'QEMU per-job overlay 无需原地恢复：基础盘不修改，每次 Live 创建新的干净 overlay。' }
            StartsVm = $false
            RestoresCheckpoint = $restoreRequiresMutation
            BaselineRestoreSatisfiedWithoutMutation = -not $restoreRequiresMutation
            BaselineIsolationMode = if ($restoreRequiresMutation) { 'provider-snapshot-restore' } else { 'qemu-per-job-overlay' }
            CreatesVm = $false
            CreatesLocalConfig = $false
            MutatingCommand = if ($restoreRequiresMutation) { $restoreCommand } else { $null }
            UnattendedMutatingCommand = if ($restoreRequiresMutation) { '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -AllowVmMutation -Force' } else { $null }
            NextStepsZh = if ($restoreRequiresMutation) {
                @(
                    '下一步：先用 -PlanOnly 或 -WhatIf 确认 VM/baseline 名称；readiness/package 不会执行恢复。',
                    '下一步：确认隔离实验 VM 可被回退后，显式使用 -AllowVmMutation -Confirm；Hyper-V 需管理员 PowerShell，VMware/QEMU 需 provider 管理权限，无人值守 lab 才使用 -Force。'
                )
            }
            else {
                @(
                    '下一步：运行 CheckEnvironment 确认 QEMU 基础盘和 WHPX 就绪；per-job overlay 已提供干净启动语义。',
                    '下一步：无需 -AllowVmMutation/-Confirm；每次 Analyze -Live 会创建新的隔离 overlay。'
                )
            }
        },
        [pscustomobject][ordered]@{
            ModeId = 'fresh-create-new-computer'
            Entrypoint = 'CreateOrPreparePath'
            TitleZh = '全新创建/新电脑准备'
            TitleEn = 'Fresh create or new-computer preparation'
            IntentZh = '准备仓库外 runtime root、本机 sandbox.local.json、guest secret，可选准备 payload；不会创建任何 provider VM 或 baseline。'
            DefaultCommand = $createCommand
            SafeDiagnostics = @('.\install.ps1 -InstallEntrypoint CreateOrPreparePath -PlanOnly', '.\install.ps1 -InstallEntrypoint CreateOrPreparePath -WhatIf', '.\install.ps1 -Mode CheckEnvironment')
            MutationBoundary = 'local filesystem/config/secret writes only through ShouldProcess; VM creation and baseline creation remain manual provider-operator tasks'
            SafeBoundaryZh = '只准备本机：PlanOnly/WhatIf 不写文件；真实执行也只写仓库外 runtime/config/secret/payload，不创建 VM/clean baseline。'
            StartsVm = $false
            RestoresCheckpoint = $false
            CreatesVm = $false
            CreatesLocalConfig = $true
            NextStepsZh = @(
                '下一步：首台机器先确认 Windows、所选 provider 管理工具和硬件虚拟化能力，再创建或导入 golden VM 并创建 clean baseline。',
                '下一步：普通用户运行 .\install.ps1 推荐安装向导保存本机配置/secret，并在向导中选择或输入真实 VM/clean baseline。'
            )
        }
    )
}

function New-InstallEntrypointDiagnostics {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('UseConfiguredEnvironment', 'RestoreCleanCheckpoint', 'CreateOrPreparePath')]
        [string]$SelectedEntrypoint
    )

    $localConfig = Get-LocalSandboxConfigPath
    $checkpointMutationRequested = $SelectedEntrypoint -eq 'RestoreCleanCheckpoint'
    $diagnosticWhatIf = [bool]$WhatIfPreference
    $createOrPrepareRequested = $SelectedEntrypoint -eq 'CreateOrPreparePath'
    $restoreRequiresVmMutation = $checkpointMutationRequested -and (Test-InstallBaselineRestoreRequiresVmMutation -Provider $VirtualizationProvider -UseQemuOverlayDisk ([bool]$QemuUseOverlayDisk))
    $baselineRestoreSatisfiedWithoutMutation = $checkpointMutationRequested -and -not $restoreRequiresVmMutation
    $confirmExplicitlyRequested = $script:InitialRootBoundParameters.Contains('Confirm') -and [System.Convert]::ToBoolean($script:InitialRootBoundParameters['Confirm'])
    $allowVmMutationGateSatisfied = $checkpointMutationRequested -and ($baselineRestoreSatisfiedWithoutMutation -or [bool]$AllowVmMutation)
    $confirmOrForceGateSatisfied = $checkpointMutationRequested -and ($baselineRestoreSatisfiedWithoutMutation -or $confirmExplicitlyRequested -or [bool]$Force)
    $restoreConfirmationSatisfied = $checkpointMutationRequested -and ($baselineRestoreSatisfiedWithoutMutation -or ([bool]$AllowVmMutation -and ($confirmExplicitlyRequested -or [bool]$Force)))
    $restoreWillExecute = $restoreRequiresVmMutation -and $restoreConfirmationSatisfied -and -not [bool]$PlanOnly -and -not $diagnosticWhatIf
    $createPlanActions = @(
        [pscustomobject][ordered]@{ Action = 'CreateRuntimeRoot'; Target = [System.IO.Path]::GetFullPath($RuntimeRoot); WouldWrite = $createOrPrepareRequested -and -not $diagnosticWhatIf; RequiresShouldProcess = $true; VmMutation = $false },
        [pscustomobject][ordered]@{ Action = 'WriteLocalConfig'; Target = $localConfig; WouldWrite = $createOrPrepareRequested -and -not $diagnosticWhatIf; RequiresShouldProcess = $true; VmMutation = $false },
        [pscustomobject][ordered]@{ Action = 'SetWebConfigEnvironment'; Target = $script:WebConfigPathEnvironmentName; WouldWrite = $createOrPrepareRequested -and -not $diagnosticWhatIf -and -not [bool]$SkipWebConfigEnvironment; RequiresShouldProcess = $true; VmMutation = $false },
        [pscustomobject][ordered]@{ Action = 'WriteInstallState'; Target = $script:InstallStatePath; WouldWrite = $createOrPrepareRequested -and -not $diagnosticWhatIf; RequiresShouldProcess = $true; VmMutation = $false },
        [pscustomobject][ordered]@{ Action = 'StoreGuestPasswordSecret'; Target = $SecretName; WouldWrite = $createOrPrepareRequested -and ([bool]$GeneratePassword -or [bool]$PromptPassword -or [bool]$ResetPassword) -and -not $diagnosticWhatIf; RequiresShouldProcess = $true; VmMutation = $false },
        [pscustomobject][ordered]@{ Action = 'PrepareGuestPayload'; Target = [System.IO.Path]::GetFullPath($GuestPayloadRoot); WouldWrite = $createOrPrepareRequested -and [bool]$PrepareGuestPayload -and -not $diagnosticWhatIf; RequiresShouldProcess = $true; VmMutation = $false }
    )
    if ($Json) {
        $status = [pscustomobject][ordered]@{
            Omitted = $true
            Reason = 'Use -PassThru or non-Json diagnostics for full install status; JSON entrypoint diagnostics avoids module autoload WhatIf noise.'
            StatusCommand = '.\install.ps1 -Mode Status'
            CheckEnvironmentCommand = '.\install.ps1 -Mode CheckEnvironment'
        }
    }
    else {
        $status = Show-KSwordSandboxInstallStatus
    }

    [pscustomobject][ordered]@{
        ContractVersion = 2
        Kind = 'KSwordSandbox.InstallEntrypointDiagnostics'
        ResultType = 'InstallEntrypointDiagnostics'
        GeneratedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
        InstallEntrypoint = $SelectedEntrypoint
        ContractSchema = 'ksword.install.entrypoint-diagnostics.v2'
        MachineReadable = $true
        OperatorModeMatrix = @(Get-InstallOperatorModeMatrix)
        UseConfiguredEnvironment = $SelectedEntrypoint -eq 'UseConfiguredEnvironment'
        RestoreCleanBaselineRequested = $checkpointMutationRequested
        ProviderSnapshotRestoreRequested = $restoreRequiresVmMutation
        RestoreExistingCleanCheckpointSnapshot = $checkpointMutationRequested
        CreateOrPrepareNewPath = $createOrPrepareRequested
        PlanOnly = [bool]$PlanOnly
        WhatIf = $diagnosticWhatIf
        ShouldProcessRequired = $restoreRequiresVmMutation -or $createOrPrepareRequested
        VmMutationNeeded = $restoreRequiresVmMutation
        VmMutationAllowed = [bool]$AllowVmMutation
        RestoreRequiresAllowVmMutation = $restoreRequiresVmMutation
        RestoreRequiresExplicitConfirmOrForce = $restoreRequiresVmMutation
        RestoreAllowVmMutationGateSatisfied = $allowVmMutationGateSatisfied
        RestoreConfirmOrForceGateSatisfied = $confirmOrForceGateSatisfied
        RestoreShouldProcessGateReached = $restoreWillExecute
        RestoreConfirmExplicitlyRequested = $confirmExplicitlyRequested
        RestoreForceExplicitlyRequested = [bool]$Force
        RestoreConfirmationGateSatisfied = $restoreConfirmationSatisfied
        BaselineRestoreSatisfiedWithoutMutation = $baselineRestoreSatisfiedWithoutMutation
        BaselineIsolationMode = if (-not $checkpointMutationRequested) { 'not-requested' } elseif ($baselineRestoreSatisfiedWithoutMutation) { 'qemu-per-job-overlay' } else { 'provider-snapshot-restore' }
        StartsVm = $false
        StopsVm = $false
        RestoresCheckpointSnapshot = $restoreWillExecute
        WritesLocalConfig = $createOrPrepareRequested -and -not $diagnosticWhatIf
        WritesInstallState = $createOrPrepareRequested -and -not $diagnosticWhatIf
        WritesSecrets = $createOrPrepareRequested -and ([bool]$GeneratePassword -or [bool]$PromptPassword -or [bool]$ResetPassword) -and -not $diagnosticWhatIf
        PreparesGuestPayload = $createOrPrepareRequested -and [bool]$PrepareGuestPayload -and -not $diagnosticWhatIf
        CreatesOrImportsVm = $false
        CreatesCheckpointSnapshot = $false
        CallsCSignTool = $false
        ExecutesSample = $false
        CreateOrPreparePlanActions = @($createPlanActions)
        ReadOnlyAssertions = [pscustomobject][ordered]@{
            NoVmMutationCommandsExecuted = -not $restoreWillExecute
            DidNotStartVm = $true
            DidNotStopVm = $true
            DidNotRestoreCheckpoint = -not $restoreWillExecute
            DidNotCreateVm = $true
            DidNotCreateCheckpoint = $true
            DidNotSignDriver = $true
            DidNotCallCSignTool = $true
            DidNotExecuteSample = $true
            SecretValuePrinted = $false
        }
        SafetyAssertions = [pscustomobject][ordered]@{
            UseConfiguredEnvironmentReadOnly = $SelectedEntrypoint -ne 'UseConfiguredEnvironment' -or (-not $restoreWillExecute -and -not $createOrPrepareRequested)
            PlanOnlyDoesNotMutate = -not [bool]$PlanOnly -or (-not $restoreWillExecute -and -not ($createOrPrepareRequested -and -not $diagnosticWhatIf))
            WhatIfDoesNotMutate = -not $diagnosticWhatIf -or (-not $restoreWillExecute -and -not ($createOrPrepareRequested -and -not $diagnosticWhatIf))
            RestoreRequiresAllowVmMutation = $restoreRequiresVmMutation
            RestoreRequiresShouldProcess = $restoreRequiresVmMutation
            QemuOverlayRestoreDoesNotMutate = -not ($checkpointMutationRequested -and $VirtualizationProvider -eq 'Qemu' -and [bool]$QemuUseOverlayDisk) -or $baselineRestoreSatisfiedWithoutMutation
            CreateOrPrepareNeverCreatesVm = $true
            CreateOrPrepareWritesOnlyLocalConfiguredPaths = $createOrPrepareRequested
        }
        VmName = $VmName
        CheckpointName = $CheckpointName
        RuntimeRoot = [System.IO.Path]::GetFullPath($RuntimeRoot)
        GuestPayloadRoot = [System.IO.Path]::GetFullPath($GuestPayloadRoot)
        LocalConfigPath = $localConfig
        UseConfiguredEnvironmentCommand = '.\install.ps1 -InstallEntrypoint UseConfiguredEnvironment -PlanOnly'
        RestoreCheckpointPlanCommand = '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -PlanOnly'
        RestoreBaselineWhatIfCommand = if ($restoreRequiresVmMutation) { '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -AllowVmMutation -WhatIf' } else { '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -WhatIf' }
        RestoreBaselineCommand = if ($restoreRequiresVmMutation) { '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -AllowVmMutation -Confirm' } else { '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint' }
        RestoreCheckpointWhatIfCommand = if ($restoreRequiresVmMutation) { '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -AllowVmMutation -WhatIf' } else { '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -WhatIf' }
        RestoreCheckpointCommand = if ($restoreRequiresVmMutation) { '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -AllowVmMutation -Confirm' } else { '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint' }
        RestoreCheckpointUnattendedCommand = if ($restoreRequiresVmMutation) { '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -AllowVmMutation -Force' } else { $null }
        CreateOrPreparePlanCommand = '.\install.ps1 -InstallEntrypoint CreateOrPreparePath -PlanOnly'
        CreateOrPrepareWhatIfCommand = '.\install.ps1 -InstallEntrypoint CreateOrPreparePath -WhatIf'
        CreateOrPrepareConfirmCommand = '.\install.ps1 -InstallEntrypoint CreateOrPreparePath -Confirm'
        CreateOrPrepareCommand = '.\install.ps1 -InstallEntrypoint CreateOrPreparePath'
        PrepareGuestPayloadCommand = '.\install.ps1 -InstallEntrypoint CreateOrPreparePath -PrepareGuestPayload'
        PrepareGuestPayloadWhatIfCommand = '.\install.ps1 -InstallEntrypoint CreateOrPreparePath -PrepareGuestPayload -WhatIf'
        ChineseGuidance = '中文提示：安装入口需要显式选择使用已配置环境、还原已有干净快照，或创建/准备新路径；PlanOnly/WhatIf 不会启动、停止、还原或修改 VM。'
        NextSteps = @(Get-InstallEntrypointNextSteps -SelectedEntrypoint $SelectedEntrypoint)
        FreshComputerNextActionsZh = if ($VirtualizationProvider -eq 'HyperV') {
            @(
                '下一步：首台机器先确认 Windows edition、Hyper-V feature/module、BIOS/UEFI 虚拟化和 SLAT；不满足时只运行 PlanOnly/WhatIf/WebUI/打包检查。',
                '下一步：在 Hyper-V 中手工创建/导入 Windows golden VM，启用 Guest Service Interface 和 PowerShell Direct，创建 clean checkpoint。',
                '下一步：普通用户直接运行 .\install.ps1 推荐安装向导；自动化可用 CreateOrPreparePath -PlanOnly/-WhatIf 预览，再用 -PromptPassword 写仓库外本机配置和 secret；不要修改 config\sandbox.example.json。'
            )
        }
        else {
            @(
                "下一步：首台机器先确认 Windows、$VirtualizationProvider 管理工具和硬件虚拟化能力；不满足时只运行 PlanOnly/WhatIf/WebUI/打包检查。",
                "下一步：在 $VirtualizationProvider 中手工创建/导入 Windows golden VM，启用 WinRM 和交互用户自动登录，创建 clean snapshot/base image。",
                '下一步：普通用户直接运行 .\install.ps1 推荐安装向导；自动化可用 CreateOrPreparePath -PlanOnly/-WhatIf 预览，再用 -PromptPassword 写仓库外本机配置和 secret；不要修改 config\sandbox.example.json。'
            )
        }
        InstallStatus = $status
        SecretValuePrinted = $false
    }
}

function Show-InstallEntrypointDiagnostics {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('UseConfiguredEnvironment', 'RestoreCleanCheckpoint', 'CreateOrPreparePath')]
        [string]$SelectedEntrypoint
    )

    $diagnostics = New-InstallEntrypointDiagnostics -SelectedEntrypoint $SelectedEntrypoint
    if ($Json) {
        $savedWhatIfPreference = $WhatIfPreference
        try {
            $WhatIfPreference = $false
            $diagnostics | ConvertTo-Json -Depth $JsonDepth
        }
        finally {
            $WhatIfPreference = $savedWhatIfPreference
        }
        return
    }

    if ($PassThru) {
        Write-Output $diagnostics
        return
    }

    $diagnostics | Format-List
}

function Write-InstallDiagnosticObject {
    param([Parameter(Mandatory)][object]$InputObject)

    if ($Json) {
        $InputObject | ConvertTo-Json -Depth $JsonDepth
        return
    }

    if ($PassThru) {
        Write-Output $InputObject
        return
    }

    $InputObject | Format-List
}

function New-InstallReadinessVerdict {
    param(
        [ValidateSet('HyperV', 'VMware', 'Qemu')]
        [string]$VirtualizationProvider = 'HyperV',
        [bool]$LocalConfigExists,
        [bool]$RuntimeRootExists,
        [bool]$RuntimeRootUnderRepository,
        [bool]$GuestPayloadReadyForLiveCopy,
        [bool]$GuestSecretSet,
        [bool]$GuestTransportReady = $true,
        [bool]$ProviderManagementAvailable,
        [bool]$ProviderQueryAttempted = $false,
        [bool]$ProviderQuerySucceeded = $true,
        [bool]$ProviderAccessDenied = $false,
        [string]$ProviderDiagnosticCode = '',
        [string]$ProviderDiagnosticMessage = '',
        [bool]$ProviderHostHardwareReady = $true,
        [bool]$ProviderConfigurationReady = $true,
        [bool]$RestoreCleanBaselineRequiresVmMutation = $true,
        [bool]$VmExists,
        [bool]$CheckpointExists,
        [bool]$DriverHostPathConfigured,
        [bool]$DriverHostPathExists,
        [AllowNull()][string]$DriverSignatureStatus,
        [string[]]$RecommendedActions = @()
    )

    $blocking = New-Object System.Collections.Generic.List[string]
    $warnings = New-Object System.Collections.Generic.List[string]

    if (-not $LocalConfigExists) { [void]$blocking.Add('MissingLocalConfig') }
    if (-not $RuntimeRootExists) { [void]$warnings.Add('RuntimeRootMissing') }
    if ($RuntimeRootUnderRepository) { [void]$blocking.Add('RuntimeRootUnderRepository') }
    if (-not $GuestPayloadReadyForLiveCopy) { [void]$blocking.Add('GuestPayloadNotReadyForLiveCopy') }
    if (-not $GuestSecretSet) { [void]$blocking.Add('MissingGuestPasswordSecret') }
    if (-not $GuestTransportReady) { [void]$blocking.Add('MissingGuestRemotingAddress') }
    if (-not $ProviderManagementAvailable) {
        [void]$blocking.Add($(if ($VirtualizationProvider -eq 'HyperV') { 'MissingHyperVPowerShellModule' } else { "Missing$($VirtualizationProvider)ManagementTool" }))
    }
    if (-not $ProviderHostHardwareReady) { [void]$blocking.Add('HostHardwareVirtualizationNotReadyOrUnconfirmed') }
    if (-not $ProviderConfigurationReady) { [void]$blocking.Add('InvalidProviderConfiguration') }
    if ($ProviderManagementAvailable -and $ProviderConfigurationReady -and $ProviderQueryAttempted -and -not $ProviderQuerySucceeded) { [void]$blocking.Add('ProviderQueryFailed') }
    if ($ProviderManagementAvailable -and -not $VmExists -and (-not $ProviderQueryAttempted -or $ProviderQuerySucceeded)) { [void]$blocking.Add('MissingConfiguredVm') }
    if ($ProviderManagementAvailable -and $ProviderQuerySucceeded -and $VmExists -and -not $CheckpointExists) { [void]$blocking.Add('MissingConfiguredCheckpoint') }
    if (-not $DriverHostPathConfigured) {
        [void]$warnings.Add('DriverHostPathNotConfigured')
    }
    elseif (-not $DriverHostPathExists) {
        [void]$blocking.Add('DriverHostPathMissing')
    }
    elseif ($DriverSignatureStatus -eq 'NotSigned') {
        [void]$warnings.Add('DriverNotSigned')
    }

    $webUiReady = $LocalConfigExists -and (-not $RuntimeRootUnderRepository)
    $installStateReady = $LocalConfigExists -and $RuntimeRootExists -and $GuestSecretSet
    $liveReady = $installStateReady -and
        $GuestPayloadReadyForLiveCopy -and
        $GuestTransportReady -and
        $ProviderManagementAvailable -and
        $ProviderQuerySucceeded -and
        $ProviderHostHardwareReady -and
        $ProviderConfigurationReady -and
        $VmExists -and
        $CheckpointExists -and
        ((-not $DriverHostPathConfigured) -or ($DriverHostPathExists -and $DriverSignatureStatus -ne 'NotSigned'))
    $overallStatus = if ($liveReady) {
        'ReadyForLive'
    }
    elseif ($webUiReady -or $installStateReady) {
        'ReadyForNonLive'
    }
    else {
        'Blocked'
    }

    [pscustomobject][ordered]@{
        Schema = 'ksword.install.readiness-verdict.v1'
        VirtualizationProvider = $VirtualizationProvider
        ProviderManagementAvailable = $ProviderManagementAvailable
        ProviderQueryAttempted = $ProviderQueryAttempted
        ProviderQuerySucceeded = $ProviderQuerySucceeded
        ProviderAccessDenied = $ProviderAccessDenied
        ProviderDiagnosticCode = $ProviderDiagnosticCode
        ProviderDiagnosticMessage = $ProviderDiagnosticMessage
        ProviderHostHardwareReady = $ProviderHostHardwareReady
        ProviderConfigurationReady = $ProviderConfigurationReady
        GeneratedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
        MachineReadable = $true
        OverallStatus = $overallStatus
        InstallStateReady = $installStateReady
        WebUiReady = $webUiReady
        LiveReady = $liveReady
        BaselineExists = $CheckpointExists
        StatusMutatesVm = $false
        CheckEnvironmentMutatesVm = $false
        InstallEntrypointChoices = @('UseConfiguredEnvironment', 'RestoreCleanCheckpoint', 'CreateOrPreparePath')
        UseConfiguredEnvironmentMutatesVm = $false
        RestoreCleanBaselineMayMutateVm = $RestoreCleanBaselineRequiresVmMutation
        RestoreBaselineRequiresAllowVmMutation = $RestoreCleanBaselineRequiresVmMutation
        RestoreCheckpointRequiresAllowVmMutation = $RestoreCleanBaselineRequiresVmMutation
        BaselineRestoreSatisfiedWithoutMutation = -not $RestoreCleanBaselineRequiresVmMutation
        BaselineIsolationMode = if ($RestoreCleanBaselineRequiresVmMutation) { 'provider-snapshot-restore' } else { 'qemu-per-job-overlay' }
        CreateOrPreparePathCreatesVm = $false
        CreateOrPreparePathCreatesBaseline = $false
        CreateOrPreparePathCreatesCheckpoint = $false
        ProviderNeutralBlockingReasons = @($blocking.ToArray() | ForEach-Object {
            if ($_ -eq 'MissingConfiguredCheckpoint') { 'MissingConfiguredBaseline' }
            elseif ($_ -eq 'MissingGuestRemotingAddress') { 'MissingGuestTransportEndpoint' }
            else { $_ }
        } | Select-Object -Unique)
        BlockingReasons = @($blocking.ToArray() | Select-Object -Unique)
        WarningReasons = @($warnings.ToArray() | Select-Object -Unique)
        RecommendedActionCount = @($RecommendedActions).Count
        RecommendedActions = @($RecommendedActions)
    }
}

function Invoke-InstallerGuestPayloadPreparation {
    $prepareScript = Join-Path $PSScriptRoot 'scripts\Prepare-GuestPayload.ps1'
    if (-not (Test-Path -LiteralPath $prepareScript -PathType Leaf)) {
        throw "错误：找不到 guest payload 准备脚本：$prepareScript。下一步：请确认 scripts\Prepare-GuestPayload.ps1 存在，或去掉 -PrepareGuestPayload 只准备本机配置。"
    }

    $target = [System.IO.Path]::GetFullPath($GuestPayloadRoot)
    if ($WhatIfPreference) {
        [void]$PSCmdlet.ShouldProcess($target, "Prepare self-contained guest payload with '$prepareScript'")
        Write-InstallInfo "预览：会在 $target 准备 self-contained guest payload；当前未构建或复制任何文件。 / WhatIf: guest payload would be prepared."
        return
    }

    if (-not $PSCmdlet.ShouldProcess($target, "Prepare self-contained guest payload with '$prepareScript'")) {
        Write-InstallInfo '已通过 ShouldProcess/Confirm 取消 guest payload 准备。下一步：需要 Live 前请重新运行并确认。 / Guest payload preparation declined.'
        return
    }

    $arguments = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $prepareScript,
        '-RepoRoot', $PSScriptRoot,
        '-PayloadRoot', $GuestPayloadRoot,
        '-GuestWorkingDirectory', $GuestWorkingDirectory,
        '-SelfContained'
    )

    Write-InstallInfo "正在 $GuestPayloadRoot 下准备 guest payload；构建输出保留在 git 仓库外。 / Preparing guest payload outside git."
    & powershell @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "错误：guest payload 准备失败，退出码 $LASTEXITCODE。下一步：确认 .NET SDK/MSBuild/WDK 可用，并查看上方输出。"
    }
}

function Invoke-UseConfiguredEnvironmentEntrypoint {
    if (-not $Json) {
        Write-InstallInfo '使用已配置环境入口：只显示状态和下一步；不会写入本机状态，不会启动、停止或还原 VM。 / Using configured environment diagnostics only.'
    }
    Show-InstallEntrypointDiagnostics -SelectedEntrypoint 'UseConfiguredEnvironment'
}

function Invoke-CreateOrPreparePathEntrypoint {
    if ($PlanOnly -or $WhatIfPreference) {
        if (-not $Json) {
            Write-InstallInfo '预览：创建/准备路径入口只输出将写入的本机目录/config/payload 动作；当前不会修改文件系统。 / Previewing create/prepare path.'
        }
        Show-InstallEntrypointDiagnostics -SelectedEntrypoint 'CreateOrPreparePath'
        return
    }

    $shouldSetPassword = [bool]$GeneratePassword -or [bool]$PromptPassword -or [bool]$ResetPassword
    Write-InstallInfo '创建/准备路径入口：准备本机目录和 sandbox.local.json；不会创建任何 provider VM，也不会还原 baseline。 / Creating/preparing local path only.'
    Install-KSwordSandboxLocal -SetPassword:$shouldSetPassword

    if ($PrepareGuestPayload) {
        Invoke-InstallerGuestPayloadPreparation
    }

    Write-InstallInfo '创建/准备路径完成。下一步：运行 .\install.ps1 -InstallEntrypoint UseConfiguredEnvironment -PlanOnly 查看剩余缺口。 / Create/prepare path completed.'
}

function Stop-ConfiguredQemuProcesses {
    $qemuSystem = Resolve-InstallExecutablePath -ConfiguredPath $QemuSystemPath
    if ([string]::IsNullOrWhiteSpace($qemuSystem)) {
        throw '错误：安全恢复 QEMU snapshot 前需要可用 qemu-system；请先运行 CheckEnvironment。'
    }

    $baseDisk = if (Test-Path -LiteralPath $QemuDiskImagePath -PathType Leaf) {
        (Resolve-Path -LiteralPath $QemuDiskImagePath).ProviderPath
    }
    else {
        [System.IO.Path]::GetFullPath($QemuDiskImagePath)
    }
    $baseDiskArgument = $baseDisk.Replace(',', ',,')
    $vmsRoot = [System.IO.Path]::GetFullPath((Join-Path $RuntimeRoot 'vms'))
    $qemuExecutableName = [System.IO.Path]::GetFileName($qemuSystem)
    $qemuExecutablePath = [System.IO.Path]::GetFullPath($qemuSystem)
    $qemuProcesses = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
            ([string]$_.Name).Equals($qemuExecutableName, [System.StringComparison]::OrdinalIgnoreCase)
        })
    $stoppedPids = [System.Collections.Generic.HashSet[int]]::new()

    if (Test-Path -LiteralPath $vmsRoot -PathType Container) {
        foreach ($pidFile in @(Get-ChildItem -LiteralPath $vmsRoot -Filter 'qemu.pid' -File -Recurse -ErrorAction SilentlyContinue)) {
            $pidText = ([string](Get-Content -LiteralPath $pidFile.FullName -Raw -ErrorAction SilentlyContinue)).Trim()
            $qemuPid = 0
            if (-not [int]::TryParse($pidText, [ref]$qemuPid)) {
                throw "错误：QEMU PID 标记 '$($pidFile.FullName)' 无效，无法确认进程归属，已停止 baseline 恢复。"
            }

            $jobRoot = Split-Path -Parent $pidFile.FullName
            $candidate = $qemuProcesses | Where-Object { [int]$_.ProcessId -eq $qemuPid } | Select-Object -First 1
            if ($null -eq $candidate) {
                Remove-Item -LiteralPath $jobRoot -Recurse -Force -ErrorAction SilentlyContinue
                continue
            }

            $markerWrittenUtc = (Get-Item -LiteralPath $pidFile.FullName -ErrorAction Stop).LastWriteTimeUtc
            $processStartedUtc = ([datetime]$candidate.CreationDate).ToUniversalTime()
            if ($processStartedUtc -lt $markerWrittenUtc.AddSeconds(-5) -or
                $processStartedUtc -gt $markerWrittenUtc.AddSeconds(5)) {
                throw "错误：QEMU PID 标记 '$($pidFile.FullName)' 指向已复用的 PID $qemuPid，进程启动时间与标记不匹配，已停止 baseline 恢复。"
            }

            $commandLine = [string]$candidate.CommandLine
            if ([string]::IsNullOrWhiteSpace($commandLine)) {
                throw "错误：无法读取 QEMU 进程 $qemuPid 的命令行，无法确认进程归属，已停止 baseline 恢复。请使用可查询 Win32_Process.CommandLine 的权限重试。"
            }
            $candidateExecutablePath = [string]$candidate.ExecutablePath
            $owned = -not [string]::IsNullOrWhiteSpace($candidateExecutablePath) -and
                $candidateExecutablePath.Equals($qemuExecutablePath, [System.StringComparison]::OrdinalIgnoreCase) -and
                $commandLine.IndexOf($pidFile.FullName, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -and
                $commandLine.IndexOf($jobRoot, [System.StringComparison]::OrdinalIgnoreCase) -ge 0
            if (-not $owned) {
                throw "错误：QEMU PID 标记 '$($pidFile.FullName)' 指向进程 $qemuPid，但其 executable/pidfile/runtime 归属与 KSword provider job 不匹配，已停止 baseline 恢复。"
            }

            Stop-Process -Id $qemuPid -Force -ErrorAction Stop
            $deadline = (Get-Date).AddSeconds(30)
            while ((Get-Process -Id $qemuPid -ErrorAction SilentlyContinue) -and (Get-Date) -lt $deadline) {
                Start-Sleep -Milliseconds 200
            }
            if (Get-Process -Id $qemuPid -ErrorAction SilentlyContinue) {
                throw "错误：QEMU 进程 $qemuPid 在 30 秒内未退出，已停止 snapshot 恢复。"
            }
            [void]$stoppedPids.Add($qemuPid)
            Remove-Item -LiteralPath $jobRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    foreach ($candidate in $qemuProcesses) {
        $candidatePid = [int]$candidate.ProcessId
        if ($stoppedPids.Contains($candidatePid)) { continue }
        $commandLine = [string]$candidate.CommandLine
        if ([string]::IsNullOrWhiteSpace($commandLine)) {
            throw "错误：无法读取 QEMU 进程 $candidatePid 的命令行，无法排除其正在使用配置磁盘，已停止 baseline 恢复。请使用可查询 Win32_Process.CommandLine 的权限重试。"
        }
        $usesRuntimeRoot = $commandLine.IndexOf($vmsRoot, [System.StringComparison]::OrdinalIgnoreCase) -ge 0
        $usesBaseDisk = $commandLine.IndexOf($baseDisk, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -or
            $commandLine.IndexOf($baseDiskArgument, [System.StringComparison]::OrdinalIgnoreCase) -ge 0
        if (-not $usesRuntimeRoot -and -not $usesBaseDisk) { continue }
        throw "错误：QEMU baseline 恢复发现没有有效原生 qemu.pid 归属标记的进程 $candidatePid 正在使用受管 runtime/基础磁盘，已拒绝自动终止。请手动关闭该进程后重试。"
    }

    Write-InstallInfo "QEMU baseline 恢复前已停止 $($stoppedPids.Count) 个可确认属于 KSword provider 的进程。"
}

function Get-ConfiguredQemuExpectedProcessVmName {
    param([Parameter(Mandatory)][string]$PidFilePath)

    $configuredVmName = ([string]$VmName).Trim()
    if (-not [bool]$QemuUseOverlayDisk) {
        return $configuredVmName
    }

    $jobIdentity = Split-Path -Leaf (Split-Path -Parent $PidFilePath)
    if ($jobIdentity -notmatch '^[0-9a-fA-F]{32}$') {
        return ''
    }

    $suffix = "-$($jobIdentity.ToLowerInvariant())"
    $maximumPrefixLength = 64 - $suffix.Length
    $normalizedPrefix = $configuredVmName
    if ($normalizedPrefix.EndsWith($suffix, [System.StringComparison]::OrdinalIgnoreCase)) {
        $normalizedPrefix = $normalizedPrefix.Substring(0, $normalizedPrefix.Length - $suffix.Length).TrimEnd('-')
    }
    if ($normalizedPrefix.Length -gt $maximumPrefixLength) {
        $normalizedPrefix = $normalizedPrefix.Substring(0, $maximumPrefixLength)
    }

    return "$normalizedPrefix$suffix"
}

function Test-ConfiguredQemuCommandLineVmName {
    param(
        [Parameter(Mandatory)][string]$CommandLine,
        [Parameter(Mandatory)][string]$ExpectedVmName
    )

    if ([string]::IsNullOrWhiteSpace($ExpectedVmName)) { return $false }
    $escapedVmName = [System.Text.RegularExpressions.Regex]::Escape($ExpectedVmName)
    $pattern = '(?i)(?:^|\s)-name(?:\s+|=)(?:"' + $escapedVmName + '"|' + $escapedVmName + ')(?=\s|$)'
    return [System.Text.RegularExpressions.Regex]::IsMatch(
        $CommandLine,
        $pattern,
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)
}

function Get-ConfiguredQemuActivePids {
    $qemuSystem = Resolve-InstallExecutablePath -ConfiguredPath $QemuSystemPath
    if ([string]::IsNullOrWhiteSpace($qemuSystem)) { return @() }

    $expectedProcessName = [System.IO.Path]::GetFileName($qemuSystem)
    $expectedExecutablePath = [System.IO.Path]::GetFullPath($qemuSystem)
    $vmsRoot = [System.IO.Path]::GetFullPath((Join-Path $RuntimeRoot 'vms'))
    if (-not (Test-Path -LiteralPath $vmsRoot -PathType Container)) { return @() }

    $activePids = [System.Collections.Generic.List[int]]::new()
    foreach ($pidFile in @(Get-ChildItem -LiteralPath $vmsRoot -Filter 'qemu.pid' -File -Recurse -ErrorAction SilentlyContinue)) {
        $qemuPid = 0
        $pidText = ([string](Get-Content -LiteralPath $pidFile.FullName -Raw -ErrorAction SilentlyContinue)).Trim()
        if (-not [int]::TryParse($pidText, [ref]$qemuPid) -or $qemuPid -le 0) { continue }
        $processInfo = Get-CimInstance Win32_Process -Filter "ProcessId = $qemuPid" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -eq $processInfo -or -not ([string]$processInfo.Name).Equals($expectedProcessName, [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        $markerItem = Get-Item -LiteralPath $pidFile.FullName -ErrorAction SilentlyContinue
        if ($null -eq $markerItem) { continue }
        $markerWrittenUtc = $markerItem.LastWriteTimeUtc
        $processStartedUtc = ([datetime]$processInfo.CreationDate).ToUniversalTime()
        if ($processStartedUtc -lt $markerWrittenUtc.AddSeconds(-5) -or
            $processStartedUtc -gt $markerWrittenUtc.AddSeconds(5)) { continue }
        $commandLine = [string]$processInfo.CommandLine
        $candidateExecutablePath = [string]$processInfo.ExecutablePath
        $jobRoot = Split-Path -Parent $pidFile.FullName
        $expectedProcessVmName = Get-ConfiguredQemuExpectedProcessVmName -PidFilePath $pidFile.FullName
        if (-not [string]::IsNullOrWhiteSpace($candidateExecutablePath) -and
            $candidateExecutablePath.Equals($expectedExecutablePath, [System.StringComparison]::OrdinalIgnoreCase) -and
            -not [string]::IsNullOrWhiteSpace($commandLine) -and
            $commandLine.IndexOf($pidFile.FullName, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -and
            $commandLine.IndexOf($jobRoot, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -and
            (Test-ConfiguredQemuCommandLineVmName -CommandLine $commandLine -ExpectedVmName $expectedProcessVmName)) {
            [void]$activePids.Add($qemuPid)
        }
    }

    return @($activePids.ToArray())
}

function Test-ConfiguredQemuProcessOwnsUserNatPort {
    param(
        [Parameter(Mandatory)][int]$ProcessId,
        [Parameter(Mandatory)][int]$Port
    )

    $processInfo = Get-CimInstance Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $processInfo -or [string]::IsNullOrWhiteSpace([string]$processInfo.CommandLine)) { return $false }
    return ([string]$processInfo.CommandLine).IndexOf(
        "hostfwd=tcp:127.0.0.1:$Port-:",
        [System.StringComparison]::OrdinalIgnoreCase) -ge 0
}

function Invoke-RestoreCleanCheckpointEntrypoint {
    $restoreRequiresVmMutation = Test-InstallBaselineRestoreRequiresVmMutation -Provider $VirtualizationProvider -UseQemuOverlayDisk ([bool]$QemuUseOverlayDisk)
    if ($PlanOnly -or $WhatIfPreference) {
        if ($restoreRequiresVmMutation -and -not $Json) {
            [void]$PSCmdlet.ShouldProcess("${VmName}::$CheckpointName", 'Restore existing clean checkpoint/snapshot')
        }
        if (-not $Json) {
            if ($restoreRequiresVmMutation) {
                Write-InstallInfo '预览：还原已有干净 baseline 入口不会执行任何 provider VM 变更。 / Previewing clean-baseline restore only.'
            }
            else {
                Write-InstallInfo 'QEMU per-job overlay 已提供干净启动语义：预览不会声称执行 snapshot restore，也不需要 VM 变更。 / The clean baseline is already satisfied by a fresh per-job overlay.'
            }
        }
        Show-InstallEntrypointDiagnostics -SelectedEntrypoint 'RestoreCleanCheckpoint'
        return
    }

    if (-not $restoreRequiresVmMutation) {
        Write-InstallInfo 'QEMU per-job overlay 已保证下次 Live 从未修改的基础盘创建新隔离层；无需 -AllowVmMutation/-Confirm，且未调用任何 provider stop/restore 命令。 / Clean-baseline intent is satisfied without VM mutation.'
        Show-InstallEntrypointDiagnostics -SelectedEntrypoint 'RestoreCleanCheckpoint'
        return
    }

    if (-not $AllowVmMutation) {
        if (-not $Json) {
            Write-InstallInfo '默认安全计划：还原 checkpoint/snapshot 入口未加 -AllowVmMutation 时只显示计划和诊断；可能做只读状态查询，但不会启动、停止、还原或修改 VM。 / Safe default: restore entrypoint is plan-only unless VM mutation is explicitly allowed.'
        }
        Show-InstallEntrypointDiagnostics -SelectedEntrypoint 'RestoreCleanCheckpoint'
        return
    }

    $confirmExplicitlyRequested = $script:InitialRootBoundParameters.Contains('Confirm') -and [System.Convert]::ToBoolean($script:InitialRootBoundParameters['Confirm'])
    if (-not $confirmExplicitlyRequested -and -not $Force) {
        if (-not $Json) {
            Write-InstallInfo '已拒绝真实 VM 变更：还原 checkpoint/snapshot 除了 -AllowVmMutation，还需要显式 -Confirm 交互确认；无人值守实验室脚本可改用 -Force 表示已外部确认。 / Checkpoint restore requires -Confirm or -Force.'
        }
        Show-InstallEntrypointDiagnostics -SelectedEntrypoint 'RestoreCleanCheckpoint'
        return
    }

    if ($VirtualizationProvider -eq 'HyperV' -and -not (Test-IsAdministrator)) {
        throw '错误：还原 Hyper-V checkpoint/snapshot 需要管理员 PowerShell。下一步：以管理员身份打开 PowerShell，先运行 -PlanOnly/-WhatIf，再加 -AllowVmMutation 重试。'
    }

    if (-not $PSCmdlet.ShouldProcess("${VirtualizationProvider}::${VmName}::$CheckpointName", 'Restore existing clean checkpoint/snapshot')) {
        Write-InstallInfo '已通过 ShouldProcess/Confirm 取消 checkpoint/snapshot 还原。 / Checkpoint restore declined.'
        return
    }

    $liveExecutionLease = Enter-InstallLiveExecutionLease -Operation "restore $VirtualizationProvider baseline"
    try {
        switch ($VirtualizationProvider) {
            'HyperV' {
                if ($null -eq (Get-Command Get-VMSnapshot -ErrorAction SilentlyContinue) -or $null -eq (Get-Command Restore-VMSnapshot -ErrorAction SilentlyContinue)) {
                    throw '错误：Hyper-V PowerShell snapshot 命令不可用。下一步：启用 Hyper-V PowerShell 管理工具后重试。'
                }
                $snapshot = Get-VMSnapshot -VMName $VmName -Name $CheckpointName -ErrorAction SilentlyContinue
                if ($null -eq $snapshot) {
                    throw "错误：找不到 Hyper-V VM '$VmName' 的干净 checkpoint '$CheckpointName'。"
                }
                Restore-VMSnapshot -VMSnapshot $snapshot -Confirm:$false
            }
            'VMware' {
                if ($VMwareVmType -ne 'ws') {
                    throw '错误：恢复 VMware snapshot 需要 Workstation Pro (vmType=ws)；旧 Player profile 不会调用 vmrun。请先迁移 VM 并更新本机配置。'
                }
                $vmrun = Resolve-InstallExecutablePath -ConfiguredPath $VMwareVmrunPath
                if ([string]::IsNullOrWhiteSpace($vmrun) -or -not (Test-Path -LiteralPath $VMwareVmxPath -PathType Leaf)) {
                    throw '错误：VMware restore 需要可用 vmrun 和现有 VMX；请先运行 CheckEnvironment。'
                }
                $resolvedVmxPath = (Resolve-Path -LiteralPath $VMwareVmxPath).ProviderPath
                $snapshotResult = Invoke-InstallProviderCommand -FilePath $vmrun -ArgumentList @('-T', $VMwareVmType, 'listSnapshots', $resolvedVmxPath)
                $snapshotOutput = @($snapshotResult.Output)
                if ($snapshotResult.ExitCode -ne 0) {
                    throw "错误：vmrun listSnapshots 失败，无法安全确认 baseline。详情：$($snapshotOutput -join ' ')"
                }
                if (@($snapshotOutput | ForEach-Object { ([string]$_).Trim() }) -notcontains $CheckpointName) {
                    throw "错误：VMware VM '$resolvedVmxPath' 中找不到 snapshot '$CheckpointName'；尚未停止或修改 VM。"
                }
                $runningResult = Invoke-InstallProviderCommand -FilePath $vmrun -ArgumentList @('-T', $VMwareVmType, 'list')
                $runningOutput = @($runningResult.Output)
                if ($runningResult.ExitCode -ne 0) {
                    throw "错误：vmrun list 失败，无法确认 VM 状态。详情：$($runningOutput -join ' ')"
                }
                if (@($runningOutput | ForEach-Object { ([string]$_).Trim() }) -contains $resolvedVmxPath) {
                    $stopResult = Invoke-InstallProviderCommand -FilePath $vmrun -ArgumentList @('-T', $VMwareVmType, 'stop', $resolvedVmxPath, 'hard')
                    $stopOutput = @($stopResult.Output)
                    if ($stopResult.ExitCode -ne 0) {
                        throw "错误：vmrun stop 失败，退出码 $($stopResult.ExitCode)。详情：$($stopOutput -join ' ')"
                    }
                    Wait-InstallVMwarePowerState -VmrunPath $vmrun -VmxPath $resolvedVmxPath -ExpectedRunning $false
                }
                $restoreResult = Invoke-InstallProviderCommand -FilePath $vmrun -ArgumentList @('-T', $VMwareVmType, 'revertToSnapshot', $resolvedVmxPath, $CheckpointName)
                if ($restoreResult.ExitCode -ne 0) {
                    throw "错误：vmrun revertToSnapshot 失败，退出码 $($restoreResult.ExitCode)。"
                }
            }
            'Qemu' {
                $qemuImg = Resolve-InstallExecutablePath -ConfiguredPath $QemuImgPath
                if ([string]::IsNullOrWhiteSpace($qemuImg) -or -not (Test-Path -LiteralPath $QemuDiskImagePath -PathType Leaf)) {
                    throw '错误：QEMU restore 需要可用 qemu-img 和现有磁盘镜像；请先运行 CheckEnvironment。'
                }
                $snapshotResult = Invoke-InstallProviderCommand -FilePath $qemuImg -ArgumentList @('info', '--output=json', $QemuDiskImagePath)
                $snapshotOutput = @($snapshotResult.Output)
                if ($snapshotResult.ExitCode -ne 0) {
                    throw "错误：qemu-img info 失败，无法确认内部 snapshot。详情：$($snapshotOutput -join ' ')"
                }
                $snapshotInfo = ($snapshotOutput -join "`n") | ConvertFrom-Json -ErrorAction Stop
                $actualFormat = [string]$snapshotInfo.format
                if (-not $actualFormat.Equals($QemuDiskFormat, [System.StringComparison]::OrdinalIgnoreCase)) {
                    throw "错误：配置磁盘格式 '$QemuDiskFormat' 与 qemu-img 检测格式 '$actualFormat' 不一致；尚未停止进程或修改镜像。"
                }
                $snapshotProperty = $snapshotInfo.PSObject.Properties['snapshots']
                $snapshotNames = if ($null -eq $snapshotProperty) {
                    @()
                }
                else {
                    @($snapshotProperty.Value | ForEach-Object {
                        $nameProperty = $_.PSObject.Properties['name']
                        if ($null -ne $nameProperty) { [string]$nameProperty.Value }
                    })
                }
                if ($snapshotNames -cnotcontains $CheckpointName) {
                    throw "错误：QEMU 磁盘中找不到内部 snapshot '$CheckpointName'；尚未停止进程或修改镜像。"
                }
                Stop-ConfiguredQemuProcesses
                $restoreResult = Invoke-InstallProviderCommand -FilePath $qemuImg -ArgumentList @('snapshot', '-a', $CheckpointName, $QemuDiskImagePath)
                if ($restoreResult.ExitCode -ne 0) {
                    throw "错误：qemu-img snapshot apply 失败，退出码 $($restoreResult.ExitCode)。请确认 VM 已停止且内部 snapshot 存在。"
                }
            }
        }
        Write-InstallInfo "已通过 $VirtualizationProvider 把 VM '$VmName' 恢复到 '$CheckpointName'。下一步：运行 .\install.ps1 -InstallEntrypoint UseConfiguredEnvironment -PlanOnly 或 .\run.ps1 -Mode Plan。 / Restore completed."
    }
    finally {
        Exit-InstallLiveExecutionLease -Lease $liveExecutionLease
    }
}

function Test-BoundSwitchTruthy {
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$BoundParameters,
        [Parameter(Mandatory)][string]$Name
    )

    return $BoundParameters.Contains($Name) -and [System.Convert]::ToBoolean($BoundParameters[$Name])
}

function Assert-InstallEntrypointContract {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('UseConfiguredEnvironment', 'RestoreCleanCheckpoint', 'CreateOrPreparePath')]
        [string]$SelectedEntrypoint,

        [Parameter(Mandatory)][System.Collections.IDictionary]$BoundParameters
    )

    $modeActionSwitches = @(
        'ResetGuestVmPassword',
        'UpdateHyperVConfig',
        'UpdateVirtualizationConfig',
        'ConfigureVTKey',
        'PromptVTKey',
        'ClearVTKey',
        'CheckEnvironment',
        'StartWebUI',
        'RunHyperVReadiness',
        'EnableGuestTestSigning',
        'DisableGuestTestSigning',
        'QueryGuestTestSigning',
        'ShowTestSigningGuidance',
        'OpenBrowser'
    )

    if ($BoundParameters.ContainsKey('Mode') -and [string]$BoundParameters['Mode'] -ne 'Interactive') {
        throw "错误：-InstallEntrypoint $SelectedEntrypoint 不能和 -Mode $($BoundParameters['Mode']) 混用，否则安装语义不封闭。下一步：三选一运行 install entrypoint；或去掉 -InstallEntrypoint，单独使用 -Mode Status/-Mode Change。"
    }

    foreach ($switchName in $modeActionSwitches) {
        if (Test-BoundSwitchTruthy -BoundParameters $BoundParameters -Name $switchName) {
            throw "错误：-InstallEntrypoint $SelectedEntrypoint 不能和 -$switchName 混用，否则安装模式语义不封闭。下一步：三选一运行 install entrypoint；或去掉 -InstallEntrypoint，改用 -Mode Change/-Mode CheckEnvironment 的对应动作。"
        }
    }

    $entrypointSpecificSwitches = switch ($SelectedEntrypoint) {
        'UseConfiguredEnvironment' { @('AllowVmMutation', 'PrepareGuestPayload', 'GeneratePassword', 'PromptPassword', 'ResetPassword', 'SkipCheckpointRefresh', 'SkipCheckpointRestore', 'Force') }
        'RestoreCleanCheckpoint' { @('PrepareGuestPayload', 'GeneratePassword', 'PromptPassword', 'ResetPassword', 'SkipCheckpointRefresh', 'SkipCheckpointRestore') }
        'CreateOrPreparePath' { @('AllowVmMutation', 'SkipCheckpointRefresh', 'SkipCheckpointRestore', 'Force') }
    }

    foreach ($switchName in $entrypointSpecificSwitches) {
        if (Test-BoundSwitchTruthy -BoundParameters $BoundParameters -Name $switchName) {
            throw "错误：-InstallEntrypoint $SelectedEntrypoint 不接受 -$switchName；该参数属于其他安装路径或 VM 变更路径。下一步：UseConfiguredEnvironment 只诊断；RestoreCleanCheckpoint 只还原已有快照；CreateOrPreparePath 只准备本机目录/config/payload。"
        }
    }

    $restoreRequiresVmMutation = Test-InstallBaselineRestoreRequiresVmMutation -Provider $VirtualizationProvider -UseQemuOverlayDisk ([bool]$QemuUseOverlayDisk)
    if (($Json -or $PassThru) -and
        $SelectedEntrypoint -ne 'UseConfiguredEnvironment' -and
        ($SelectedEntrypoint -ne 'RestoreCleanCheckpoint' -or $restoreRequiresVmMutation) -and
        -not $PlanOnly -and
        -not $WhatIfPreference) {
        throw "错误：-Json/-PassThru 只支持诊断路径：UseConfiguredEnvironment，或任意入口加 -PlanOnly/-WhatIf。下一步：真实写入/还原时去掉 -Json/-PassThru，或先运行 -PlanOnly -Json。"
    }
}

function Invoke-InstallEntrypoint {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('UseConfiguredEnvironment', 'RestoreCleanCheckpoint', 'CreateOrPreparePath')]
        [string]$SelectedEntrypoint
    )

    Assert-InstallEntrypointContract -SelectedEntrypoint $SelectedEntrypoint -BoundParameters $script:InitialRootBoundParameters
    $script:InstallEntrypoint = $SelectedEntrypoint

    switch ($SelectedEntrypoint) {
        'UseConfiguredEnvironment' { Invoke-UseConfiguredEnvironmentEntrypoint }
        'RestoreCleanCheckpoint' { Invoke-RestoreCleanCheckpointEntrypoint }
        'CreateOrPreparePath' { Invoke-CreateOrPreparePathEntrypoint }
    }
}

function Invoke-InstallEntrypointMenu {
    Write-Host ''
    Write-Host '安装入口选择 / Install entrypoint selection:'
    Write-Host '  1) 使用已配置环境（只诊断，不写本机状态，不修改 VM） / Use already configured environment'
    Write-Host '  2) 回退/恢复已有 clean baseline（Hyper-V checkpoint / VMware snapshot / QEMU internal snapshot；overlay 只确认干净启动） / Plan rollback/restore existing clean baseline'
    Write-Host '  3) 全新/新电脑本机准备（目录/config/secret，可选 payload；不创建 VM） / Fresh new-computer local preparation'
    $choice = Read-MenuChoice -Prompt '请选择 [1-3] / Choose [1-3]' -Allowed @('1', '2', '3')
    switch ($choice) {
        '1' { Invoke-InstallEntrypoint -SelectedEntrypoint 'UseConfiguredEnvironment' }
        '2' { Invoke-InstallEntrypoint -SelectedEntrypoint 'RestoreCleanCheckpoint' }
        '3' { Invoke-InstallEntrypoint -SelectedEntrypoint 'CreateOrPreparePath' }
    }
}

function Install-KSwordSandboxLocal {
    param([bool]$SetPassword)

    Initialize-KSwordSandboxRuntimeFolders

    Write-InstallInfo "运行目录已就绪：$RuntimeRoot / Runtime root ready."
    Write-InstallInfo "Guest payload 目录已就绪：$GuestPayloadRoot / Guest payload root ready."
    $configPath = Write-LocalSandboxConfig
    Set-WebConfigPathEnvironment -ConfigPath $configPath

    if ($SetPassword) {
        if ($WhatIfPreference) {
            [void]$PSCmdlet.ShouldProcess($SecretName, 'Store guest password secret')
            Write-InstallInfo "预览：会设置 guest password secret '$SecretName'，不会打印值。 / WhatIf: guest password secret would be set."
            return
        }

        $credential = Read-GuestPassword -UseGenerated ([bool]$GeneratePassword) -UsePrompt ([bool]$PromptPassword) -ExistingSecretName $SecretName
        Set-GuestPasswordSecret -Name $SecretName -Password $credential.Password -PasswordSource $credential.Source
    }
    else {
        Save-InstallState `
            -Action 'install-no-credential-change' `
            -GuestUser $GuestUserName `
            -Secret $SecretName `
            -Runtime $RuntimeRoot `
            -PayloadRoot $GuestPayloadRoot `
            -PasswordSource 'unchanged' `
            -PersistedToUser (-not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($SecretName, 'User'))) `
            -PersistedToProcess (-not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($SecretName, 'Process'))) `
            -DpapiBackup (Test-Path -LiteralPath $script:SecretBackupPath -PathType Leaf) `
            -LocalConfig $configPath
    }
}

function Reset-GuestPasswordSecret {
    if ($WhatIfPreference) {
        [void]$PSCmdlet.ShouldProcess($SecretName, 'Reset host-side guest password secret')
        Write-InstallInfo "预览：会在本机重置 host-side guest password secret '$SecretName'，不会打印值。 / WhatIf: password secret would be reset locally."
        return
    }

    $credential = Read-GuestPassword -UseGenerated ([bool]$GeneratePassword) -UsePrompt ([bool]$PromptPassword) -ExistingSecretName $SecretName
    Set-GuestPasswordSecret -Name $SecretName -Password $credential.Password -PasswordSource "reset-$($credential.Source)"
    Write-InstallInfo "密码 secret 已在本机重置。下一步：如果刚生成了新密码，请先把 $VirtualizationProvider VM 中 '$GuestUserName' 帐户和干净 baseline 更新为同一个值，再运行 Live。 / Password secret reset locally."
}

function Read-OptionalText {
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [AllowNull()][string]$CurrentValue
    )

    $answer = Read-Host "$Prompt [$CurrentValue]"
    if ([string]::IsNullOrWhiteSpace($answer)) {
        return $CurrentValue
    }

    return $answer.Trim()
}

function Read-QemuAdditionalArgumentsInteractive {
    $currentJson = ConvertTo-Json -InputObject @($QemuAdditionalArguments) -Compress
    $answer = Read-Host "QEMU 额外参数 JSON 数组 / Additional arguments JSON array [$currentJson]"
    if ([string]::IsNullOrWhiteSpace($answer)) {
        return
    }

    $trimmed = $answer.Trim()
    if (-not $trimmed.StartsWith('[')) {
        throw '错误：QEMU 额外参数必须使用 JSON 数组，例如 ["-accel","whpx"]；内存请使用 QemuMemoryMegabytes。'
    }

    try {
        $parsed = @($trimmed | ConvertFrom-Json -ErrorAction Stop)
    }
    catch {
        throw "错误：QEMU 额外参数不是有效 JSON 数组：$($_.Exception.Message)"
    }

    if (@($parsed | Where-Object { $null -eq $_ -or $_ -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$_) }).Count -gt 0) {
        throw '错误：QEMU 额外参数数组只能包含非空字符串。'
    }

    $script:QemuAdditionalArguments = @($parsed | ForEach-Object { [string]$_ })
}

function Select-HyperVVmAndCheckpointInteractive {
    Write-Host ''
    Write-Host 'Hyper-V VM/检查点选择 / Hyper-V VM/checkpoint selection'
    Write-Host '中文提示：这里只执行只读 Get-VM/Get-VMSnapshot；不会启动、停止、还原或修改 VM。 / Read-only selection only.'

    $getVmCommand = Get-Command Get-VM -ErrorAction SilentlyContinue
    if ($null -eq $getVmCommand) {
        Write-InstallInfo '未找到 Hyper-V PowerShell 模块；将回退到手动输入 VM/checkpoint。 / Hyper-V module unavailable; falling back to manual entry.'
        return
    }

    $vms = @()
    try {
        $vms = @(Get-VM -ErrorAction Stop | Sort-Object -Property Name)
    }
    catch {
        Write-InstallInfo "无法列出 Hyper-V VM；将回退到手动输入。详情：$($_.Exception.Message)"
        return
    }

    if ($vms.Count -eq 0) {
        Write-InstallInfo '未发现 Hyper-V VM；请手动输入现有黄金 VM 名称。 / No Hyper-V VMs found; please enter the existing golden VM name manually.'
        return
    }

    Write-Host '可用 VM / Available VMs:'
    for ($i = 0; $i -lt $vms.Count; $i++) {
        $vm = $vms[$i]
        Write-Host ("  {0}) {1}  状态/State={2}" -f ($i + 1), $vm.Name, $vm.State)
    }
    Write-Host '  0) 保留当前值/手动输入 / Keep current or enter manually'

    $allowed = @('0') + @(1..$vms.Count | ForEach-Object { [string]$_ })
    $choice = Read-MenuChoice -Prompt '请选择 VM [0-N] / Choose VM [0-N]' -Allowed $allowed
    if ($choice -eq '0') {
        return
    }

    $selectedVm = $vms[[int]$choice - 1]
    $script:VmName = $selectedVm.Name
    Write-InstallInfo "已选择 VM：$VmName / Selected VM."

    $getSnapshotCommand = Get-Command Get-VMSnapshot -ErrorAction SilentlyContinue
    if ($null -eq $getSnapshotCommand) {
        Write-InstallInfo '未找到 Get-VMSnapshot；checkpoint 将手动输入。 / Get-VMSnapshot unavailable; checkpoint will be entered manually.'
        return
    }

    $snapshots = @()
    try {
        $snapshots = @(Get-VMSnapshot -VMName $VmName -ErrorAction Stop | Sort-Object -Property CreationTime -Descending)
    }
    catch {
        Write-InstallInfo "无法列出 VM '$VmName' 的 checkpoint/snapshot；将回退到手动输入。详情：$($_.Exception.Message)"
        return
    }

    if ($snapshots.Count -eq 0) {
        Write-InstallInfo "VM '$VmName' 没有可选 checkpoint/snapshot；请手动输入或先创建 clean checkpoint。"
        return
    }

    Write-Host "VM '$VmName' 的 checkpoint/snapshot:"
    for ($i = 0; $i -lt $snapshots.Count; $i++) {
        $snapshot = $snapshots[$i]
        Write-Host ("  {0}) {1}  创建/Create={2:u}" -f ($i + 1), $snapshot.Name, $snapshot.CreationTime)
    }
    Write-Host '  0) 保留当前值/手动输入 / Keep current or enter manually'

    $checkpointAllowed = @('0') + @(1..$snapshots.Count | ForEach-Object { [string]$_ })
    $checkpointChoice = Read-MenuChoice -Prompt '请选择 clean checkpoint [0-N] / Choose clean checkpoint [0-N]' -Allowed $checkpointAllowed
    if ($checkpointChoice -eq '0') {
        return
    }

    $script:CheckpointName = $snapshots[[int]$checkpointChoice - 1].Name
    Write-InstallInfo "已选择 checkpoint：$CheckpointName / Selected checkpoint."
}

function Select-VMwareVmxAndSnapshotInteractive {
    Write-Host ''
    Write-Host 'VMware VMX/快照选择 / VMware VMX/snapshot selection'
    Write-Host '中文提示：这里只执行只读 vmrun list/listSnapshots；不会启动、停止、还原或修改 VM。 / Read-only selection only.'

    $vmrun = Resolve-InstallExecutablePath -ConfiguredPath $VMwareVmrunPath
    if ([string]::IsNullOrWhiteSpace($vmrun)) {
        Write-InstallInfo '未找到 vmrun；将回退到手动输入 VMX/snapshot。 / vmrun unavailable; falling back to manual entry.'
        return
    }

    $candidatePaths = [System.Collections.Generic.List[string]]::new()
    if (Test-Path -LiteralPath $VMwareVmxPath -PathType Leaf) {
        [void]$candidatePaths.Add((Resolve-Path -LiteralPath $VMwareVmxPath).ProviderPath)
    }

    try {
        $runningResult = Invoke-InstallProviderCommand -FilePath $vmrun -ArgumentList @('-T', 'ws', 'list')
        if ($runningResult.ExitCode -eq 0) {
            foreach ($line in @($runningResult.Output)) {
                $candidate = ([string]$line).Trim().Trim('"')
                if ($candidate.EndsWith('.vmx', [System.StringComparison]::OrdinalIgnoreCase) -and
                    (Test-Path -LiteralPath $candidate -PathType Leaf)) {
                    [void]$candidatePaths.Add((Resolve-Path -LiteralPath $candidate).ProviderPath)
                }
            }
        }
        else {
            Write-InstallInfo "vmrun list 返回退出码 $($runningResult.ExitCode)；仍可使用当前 VMX 或手动输入。"
        }
    }
    catch {
        Write-InstallInfo "无法列出运行中的 VMware VM；仍可使用当前 VMX 或手动输入。详情：$($_.Exception.Message)"
    }

    $vmxCandidates = @($candidatePaths | Sort-Object -Unique)
    if ($vmxCandidates.Count -gt 0) {
        Write-Host '可用 VMX / Available VMX files:'
        for ($i = 0; $i -lt $vmxCandidates.Count; $i++) {
            Write-Host ("  {0}) {1}" -f ($i + 1), $vmxCandidates[$i])
        }
        Write-Host '  0) 保留当前值/手动输入 / Keep current or enter manually'
        $vmxAllowed = @('0') + @(1..$vmxCandidates.Count | ForEach-Object { [string]$_ })
        $vmxChoice = Read-MenuChoice -Prompt '请选择 VMX [0-N] / Choose VMX [0-N]' -Allowed $vmxAllowed
        if ($vmxChoice -ne '0') {
            $script:VMwareVmxPath = $vmxCandidates[[int]$vmxChoice - 1]
            Write-InstallInfo "已选择 VMX：$VMwareVmxPath / Selected VMX."
        }
    }
    else {
        Write-InstallInfo '没有发现当前或运行中的 VMX；请手动输入现有 Workstation Pro VMX 路径。 / No current or running VMX candidate was found.'
    }

    if (-not (Test-Path -LiteralPath $VMwareVmxPath -PathType Leaf)) {
        return
    }

    try {
        $resolvedVmxPath = (Resolve-Path -LiteralPath $VMwareVmxPath).ProviderPath
        $snapshotResult = Invoke-InstallProviderCommand -FilePath $vmrun -ArgumentList @('-T', 'ws', 'listSnapshots', $resolvedVmxPath)
        if ($snapshotResult.ExitCode -ne 0) {
            Write-InstallInfo "vmrun listSnapshots 返回退出码 $($snapshotResult.ExitCode)；snapshot 将手动输入。"
            return
        }
        $snapshots = @($snapshotResult.Output |
            ForEach-Object { ([string]$_).Trim() } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and $_ -notmatch '^Total snapshots:\s*\d+$' } |
            Select-Object -Unique)
    }
    catch {
        Write-InstallInfo "无法列出 VMX '$VMwareVmxPath' 的 snapshot；将回退到手动输入。详情：$($_.Exception.Message)"
        return
    }

    if ($snapshots.Count -eq 0) {
        Write-InstallInfo "VMX '$VMwareVmxPath' 没有可选 snapshot；请手动输入或先创建 clean snapshot。"
        return
    }

    Write-Host "VMX '$VMwareVmxPath' 的 snapshot:"
    for ($i = 0; $i -lt $snapshots.Count; $i++) {
        Write-Host ("  {0}) {1}" -f ($i + 1), $snapshots[$i])
    }
    Write-Host '  0) 保留当前值/手动输入 / Keep current or enter manually'
    $snapshotAllowed = @('0') + @(1..$snapshots.Count | ForEach-Object { [string]$_ })
    $snapshotChoice = Read-MenuChoice -Prompt '请选择 clean snapshot [0-N] / Choose clean snapshot [0-N]' -Allowed $snapshotAllowed
    if ($snapshotChoice -ne '0') {
        $script:CheckpointName = $snapshots[[int]$snapshotChoice - 1]
        Write-InstallInfo "已选择 snapshot：$CheckpointName / Selected snapshot."
    }
}

function Select-QemuDiskMetadataAndSnapshotInteractive {
    Write-Host ''
    Write-Host 'QEMU 磁盘/基线选择 / QEMU disk/baseline selection'
    Write-Host '中文提示：这里只执行只读 qemu-img info --output=json；不会创建 overlay、还原 snapshot 或启动 VM。 / Read-only selection only.'

    $qemuImg = Resolve-InstallExecutablePath -ConfiguredPath $QemuImgPath
    if ([string]::IsNullOrWhiteSpace($qemuImg) -or -not (Test-Path -LiteralPath $QemuDiskImagePath -PathType Leaf)) {
        Write-InstallInfo 'qemu-img 或基础磁盘不可用；磁盘格式/baseline 将手动输入。 / qemu-img or base disk unavailable; falling back to manual entry.'
        return
    }

    try {
        $imageResult = Invoke-InstallProviderCommand -FilePath $qemuImg -ArgumentList @('info', '--output=json', $QemuDiskImagePath)
        if ($imageResult.ExitCode -ne 0) {
            Write-InstallInfo "qemu-img info 返回退出码 $($imageResult.ExitCode)；磁盘格式/baseline 将手动输入。"
            return
        }
        $imageInfo = ($imageResult.Output -join "`n") | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        Write-InstallInfo "无法读取 QEMU 磁盘 metadata；将回退到手动输入。详情：$($_.Exception.Message)"
        return
    }

    $actualFormat = [string]$imageInfo.format
    if ($actualFormat -in @('qcow2', 'raw', 'vhdx', 'vmdk')) {
        $script:QemuDiskFormat = $actualFormat
        Write-InstallInfo "已检测磁盘格式：$QemuDiskFormat / Detected disk format."
    }

    if ([bool]$QemuUseOverlayDisk) {
        Write-InstallInfo '当前使用 per-job overlay；干净基线由每次新建 overlay 保证，无需选择内部 snapshot。 / Per-job overlay supplies the clean baseline.'
        return
    }

    $snapshotProperty = $imageInfo.PSObject.Properties['snapshots']
    $snapshots = if ($null -eq $snapshotProperty) {
        @()
    }
    else {
        @($snapshotProperty.Value |
            ForEach-Object { $nameProperty = $_.PSObject.Properties['name']; if ($null -ne $nameProperty) { [string]$nameProperty.Value } } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Select-Object -Unique)
    }
    if ($snapshots.Count -eq 0) {
        Write-InstallInfo "磁盘 '$QemuDiskImagePath' 没有可选内部 snapshot；请手动输入或先创建 clean snapshot。"
        return
    }

    Write-Host "磁盘 '$QemuDiskImagePath' 的内部 snapshot:"
    for ($i = 0; $i -lt $snapshots.Count; $i++) {
        Write-Host ("  {0}) {1}" -f ($i + 1), $snapshots[$i])
    }
    Write-Host '  0) 保留当前值/手动输入 / Keep current or enter manually'
    $snapshotAllowed = @('0') + @(1..$snapshots.Count | ForEach-Object { [string]$_ })
    $snapshotChoice = Read-MenuChoice -Prompt '请选择 clean internal snapshot [0-N] / Choose clean internal snapshot [0-N]' -Allowed $snapshotAllowed
    if ($snapshotChoice -ne '0') {
        $script:CheckpointName = $snapshots[[int]$snapshotChoice - 1]
        Write-InstallInfo "已选择内部 snapshot：$CheckpointName / Selected internal snapshot."
    }
}

function Select-VirtualizationProviderInteractive {
    Write-Host ''
    Write-Host "虚拟化后端 / Virtualization provider (current: $VirtualizationProvider):"
    Write-Host '  1) Hyper-V'
    Write-Host '  2) VMware Workstation Pro'
    Write-Host '  3) QEMU'
    $choice = Read-MenuChoice -Prompt '请选择 [1-3] / Choose [1-3]' -Allowed @('1', '2', '3')
    $script:VirtualizationProvider = @{
        '1' = 'HyperV'
        '2' = 'VMware'
        '3' = 'Qemu'
    }[$choice]
}

function Import-SelectedVirtualizationProfileFromLocalConfig {
    $configPath = Get-LocalSandboxConfigPath
    if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
        return
    }

    try {
        $localConfig = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json -ErrorAction Stop
        switch ($VirtualizationProvider) {
            'HyperV' {
                $sectionProperty = $localConfig.PSObject.Properties['hyperV']
                $section = if ($null -eq $sectionProperty) { $null } else { $sectionProperty.Value }
                if ($null -ne $section) {
                    if ($null -ne $section.PSObject.Properties['goldenVmName']) { $script:VmName = [string]$section.goldenVmName }
                    if ($null -ne $section.PSObject.Properties['goldenSnapshotName']) { $script:CheckpointName = [string]$section.goldenSnapshotName }
                }
            }
            'VMware' {
                $sectionProperty = $localConfig.PSObject.Properties['vmware']
                $section = if ($null -eq $sectionProperty) { $null } else { $sectionProperty.Value }
                if ($null -ne $section) {
                    if ($null -ne $section.PSObject.Properties['vmName']) { $script:VmName = [string]$section.vmName }
                    if ($null -ne $section.PSObject.Properties['vmxPath']) { $script:VMwareVmxPath = [string]$section.vmxPath }
                    if ($null -ne $section.PSObject.Properties['snapshotName']) { $script:CheckpointName = [string]$section.snapshotName }
                    if ($null -ne $section.PSObject.Properties['vmrunPath']) { $script:VMwareVmrunPath = [string]$section.vmrunPath }
                    if ($null -ne $section.PSObject.Properties['vmType']) { $script:VMwareVmType = [string]$section.vmType }
                    if ($null -ne $section.PSObject.Properties['headless']) { $script:VMwareHeadless = [bool]$section.headless }
                }
            }
            'Qemu' {
                $sectionProperty = $localConfig.PSObject.Properties['qemu']
                $section = if ($null -eq $sectionProperty) { $null } else { $sectionProperty.Value }
                if ($null -ne $section) {
                    if ($null -ne $section.PSObject.Properties['vmName']) { $script:VmName = [string]$section.vmName }
                    if ($null -ne $section.PSObject.Properties['diskImagePath']) { $script:QemuDiskImagePath = [string]$section.diskImagePath }
                    if ($null -ne $section.PSObject.Properties['snapshotName']) { $script:CheckpointName = [string]$section.snapshotName }
                    if ($null -ne $section.PSObject.Properties['qemuSystemPath']) { $script:QemuSystemPath = [string]$section.qemuSystemPath }
                    if ($null -ne $section.PSObject.Properties['qemuImgPath']) { $script:QemuImgPath = [string]$section.qemuImgPath }
                    if ($null -ne $section.PSObject.Properties['diskFormat']) { $script:QemuDiskFormat = [string]$section.diskFormat }
                    if ($null -ne $section.PSObject.Properties['diskInterface']) { $script:QemuDiskInterface = [string]$section.diskInterface }
                    if ($null -ne $section.PSObject.Properties['useOverlayDisk']) { $script:QemuUseOverlayDisk = [bool]$section.useOverlayDisk }
                    if ($null -ne $section.PSObject.Properties['memoryMegabytes']) { $script:QemuMemoryMegabytes = [int]$section.memoryMegabytes }
                    if ($null -ne $section.PSObject.Properties['headless']) { $script:QemuHeadless = [bool]$section.headless }
                    if ($null -ne $section.PSObject.Properties['additionalArguments']) { $script:QemuAdditionalArguments = @($section.additionalArguments | ForEach-Object { [string]$_ }) }
                }
            }
        }

        if ($VirtualizationProvider -ne 'HyperV') {
            $guestProperty = $localConfig.PSObject.Properties['guest']
            $guest = if ($null -eq $guestProperty) { $null } else { $guestProperty.Value }
            $remotingProperty = if ($null -eq $section) { $null } else { $section.PSObject.Properties['guestRemoting'] }
            $remoting = if ($null -eq $remotingProperty) { $null } else { $remotingProperty.Value }
            $addressModeProperty = if ($null -eq $remoting) { $null } else { $remoting.PSObject.Properties['addressMode'] }
            $legacyAddressProperty = if ($null -eq $guest) { $null } else { $guest.PSObject.Properties['powerShellRemotingAddress'] }
            $legacyAddress = if ($null -eq $legacyAddressProperty) { '' } else { [string]$legacyAddressProperty.Value }
            $automaticGuestRemotingMigrated = $null -eq $remoting -and [string]::IsNullOrWhiteSpace($legacyAddress)
            $loadedAddressMode = if ($null -ne $addressModeProperty) {
                [string]$addressModeProperty.Value
            }
            elseif ($automaticGuestRemotingMigrated) {
                if ($VirtualizationProvider -eq 'VMware') { 'VMwareTools' } else { 'QemuUserNat' }
            }
            else {
                'Configured'
            }
            $script:GuestRemotingAddressMode = $loadedAddressMode
            $remotingAddressProperty = if ($null -eq $remoting) { $null } else { $remoting.PSObject.Properties['address'] }
            if ($loadedAddressMode -eq 'Configured' -and
                ($null -eq $remotingAddressProperty -or [string]::IsNullOrWhiteSpace([string]$remotingAddressProperty.Value))) {
                $remoting = $guest
                $addressName = 'powerShellRemotingAddress'
                $portName = 'powerShellRemotingPort'
                $sslName = 'powerShellRemotingUseSsl'
                $authenticationName = 'powerShellRemotingAuthentication'
                $skipCertificateName = 'powerShellRemotingSkipCertificateChecks'
            }
            else {
                $addressName = 'address'
                $portName = 'port'
                $sslName = 'useSsl'
                $authenticationName = 'authentication'
                $skipCertificateName = 'skipCertificateChecks'
            }
            $sslPropertyPresent = $null -ne $remoting -and $null -ne $remoting.PSObject.Properties[$sslName]
            $skipCertificatePropertyPresent = $null -ne $remoting -and $null -ne $remoting.PSObject.Properties[$skipCertificateName]
            if ($null -ne $remoting) {
                if ($null -ne $remoting.PSObject.Properties[$addressName]) { $script:GuestRemotingAddress = [string]$remoting.PSObject.Properties[$addressName].Value }
                if ($null -ne $remoting.PSObject.Properties[$portName]) { $script:GuestRemotingPort = [int]$remoting.PSObject.Properties[$portName].Value }
                if ($null -ne $remoting.PSObject.Properties[$sslName]) { Set-ScriptSwitchValue -Name 'GuestRemotingUseSsl' -Value ([bool]$remoting.PSObject.Properties[$sslName].Value) }
                if ($null -ne $remoting.PSObject.Properties[$authenticationName]) { $script:GuestRemotingAuthentication = [string]$remoting.PSObject.Properties[$authenticationName].Value }
                if ($null -ne $remoting.PSObject.Properties[$skipCertificateName]) { Set-ScriptSwitchValue -Name 'GuestRemotingSkipCertificateChecks' -Value ([bool]$remoting.PSObject.Properties[$skipCertificateName].Value) }
            }
            if ($automaticGuestRemotingMigrated) {
                Set-ScriptSwitchValue -Name 'GuestRemotingUseSsl' -Value $true
                Set-ScriptSwitchValue -Name 'GuestRemotingSkipCertificateChecks' -Value $true
            }
            elseif ($loadedAddressMode -ne 'Configured') {
                if (-not $sslPropertyPresent) { Set-ScriptSwitchValue -Name 'GuestRemotingUseSsl' -Value $true }
                if (-not $skipCertificatePropertyPresent -and [bool]$GuestRemotingUseSsl) { Set-ScriptSwitchValue -Name 'GuestRemotingSkipCertificateChecks' -Value $true }
            }
        }
    }
    catch {
        Write-InstallInfo "无法载入已有 $VirtualizationProvider 本机 profile，将保留当前值。详情：$($_.Exception.Message)"
    }
}

function Read-VirtualizationProfileInteractive {
    switch ($VirtualizationProvider) {
        'HyperV' {
            Select-HyperVVmAndCheckpointInteractive
            $script:VmName = Read-OptionalText -Prompt 'Hyper-V 黄金 VM 名称 / Hyper-V golden VM name' -CurrentValue $VmName
            $script:CheckpointName = Read-OptionalText -Prompt '干净 checkpoint 名称 / Clean checkpoint name' -CurrentValue $CheckpointName
        }
        'VMware' {
            $script:VMwareVmrunPath = Read-OptionalText -Prompt 'vmrun.exe 路径或命令名 / vmrun path or command' -CurrentValue $VMwareVmrunPath
            $script:VMwareVmType = 'ws'
            $script:VMwareVmxPath = Read-OptionalText -Prompt 'VMX 文件路径 / VMX file path' -CurrentValue $VMwareVmxPath
            Select-VMwareVmxAndSnapshotInteractive
            $script:VmName = Read-OptionalText -Prompt 'VMware VM 显示名称 / VMware VM display name' -CurrentValue $VmName
            $script:CheckpointName = Read-OptionalText -Prompt '干净 snapshot 名称 / Clean snapshot name' -CurrentValue $CheckpointName
            $script:VMwareHeadless = Read-YesNoChoice -Prompt 'VMware 使用无头 nogui 模式？ / Start VMware without a console?' -DefaultYes ([bool]$VMwareHeadless)
        }
        'Qemu' {
            $script:VmName = Read-OptionalText -Prompt 'QEMU VM 名称 / QEMU VM name' -CurrentValue $VmName
            $script:QemuDiskImagePath = Read-OptionalText -Prompt '基础磁盘镜像路径 / Base disk image path' -CurrentValue $QemuDiskImagePath
            $script:QemuSystemPath = Read-OptionalText -Prompt 'qemu-system 路径或命令名 / qemu-system path or command' -CurrentValue $QemuSystemPath
            $script:QemuImgPath = Read-OptionalText -Prompt 'qemu-img 路径或命令名 / qemu-img path or command' -CurrentValue $QemuImgPath
            Read-QemuAdditionalArgumentsInteractive
            $script:QemuUseOverlayDisk = Read-YesNoChoice -Prompt '每个 job 使用一次性 overlay 磁盘？ / Use a disposable overlay per job?' -DefaultYes ([bool]$QemuUseOverlayDisk)
            Select-QemuDiskMetadataAndSnapshotInteractive
            $script:QemuDiskFormat = Read-OptionalText -Prompt '磁盘格式 (qcow2/raw/vhdx/vmdk) / Disk format' -CurrentValue $QemuDiskFormat
            $script:QemuDiskInterface = Read-OptionalText -Prompt '磁盘接口 (virtio/ide/scsi) / Disk interface' -CurrentValue $QemuDiskInterface
            $memoryText = Read-OptionalText -Prompt 'QEMU 内存 MB / QEMU memory in MB' -CurrentValue ([string]$QemuMemoryMegabytes)
            $parsedMemory = 0
            if (-not [int]::TryParse($memoryText, [ref]$parsedMemory) -or $parsedMemory -lt 256 -or $parsedMemory -gt 1048576) {
                throw "错误：QEMU 内存无效：$memoryText；应在 256 到 1048576 MB 之间。"
            }
            $script:QemuMemoryMegabytes = $parsedMemory
            $script:QemuHeadless = Read-YesNoChoice -Prompt 'QEMU 使用无头模式？ / Start QEMU without a display?' -DefaultYes ([bool]$QemuHeadless)
            if (-not [bool]$QemuUseOverlayDisk) {
                $script:CheckpointName = Read-OptionalText -Prompt '内部干净 snapshot 名称 / Internal clean snapshot name' -CurrentValue $CheckpointName
            }
        }
    }

    if ($VirtualizationProvider -ne 'HyperV') {
        if ($GuestRemotingAddressMode -eq 'Configured' -and [string]::IsNullOrWhiteSpace($GuestRemotingAddress)) {
            $script:GuestRemotingAddressMode = if ($VirtualizationProvider -eq 'VMware') { 'VMwareTools' } else { 'QemuUserNat' }
        }
        $script:GuestRemotingAddressMode = Read-OptionalText -Prompt 'Guest 端点模式 (Configured/VMwareTools/QemuUserNat) / Guest endpoint mode' -CurrentValue $GuestRemotingAddressMode
        $allowedModes = if ($VirtualizationProvider -eq 'VMware') { @('Configured', 'VMwareTools') } else { @('Configured', 'QemuUserNat') }
        if ($GuestRemotingAddressMode -notin $allowedModes) {
            throw "错误：$VirtualizationProvider 不支持 Guest 端点模式 '$GuestRemotingAddressMode'；可选：$($allowedModes -join ', ')。"
        }
        if ($GuestRemotingAddressMode -eq 'Configured') {
            $script:GuestRemotingAddress = Read-OptionalText -Prompt '来宾 WinRM 地址或主机名 / Guest WinRM address or host' -CurrentValue $GuestRemotingAddress
        }
        else {
            $script:GuestRemotingAddress = ''
            $modeDescription = if ($GuestRemotingAddressMode -eq 'VMwareTools') { 'VMware Tools 会在每次恢复后自动发现 Guest IP。' } else { 'QEMU 会管理 localhost user-NAT WinRM 端口转发。' }
            Write-InstallInfo "$modeDescription / Provider-managed guest endpoint enabled."
        }
        $automaticGuestEndpoint = $GuestRemotingAddressMode -ne 'Configured'
        if ($automaticGuestEndpoint) {
            $upgradingAutomaticHttp = -not [bool]$GuestRemotingUseSsl
            Set-ScriptSwitchValue -Name 'GuestRemotingUseSsl' -Value $true
            if ($upgradingAutomaticHttp) {
                Set-ScriptSwitchValue -Name 'GuestRemotingSkipCertificateChecks' -Value $true
            }
            Write-InstallInfo '自动端点模式固定使用 HTTPS，避免依赖宿主机全局 TrustedHosts。 / Automatic endpoints require HTTPS.'
        }
        $portPrompt = if ($GuestRemotingAddressMode -eq 'QemuUserNat') {
            '宿主 WinRM HTTPS 转发端口（0=55986 -> Guest 5986） / Host HTTPS forwarding port'
        }
        elseif ($automaticGuestEndpoint) {
            'WinRM HTTPS 端口（0=5986） / WinRM HTTPS port'
        }
        else {
            'WinRM 端口（0=按 SSL 自动选择 5985/5986） / WinRM port'
        }
        $portText = Read-OptionalText -Prompt $portPrompt -CurrentValue ([string]$GuestRemotingPort)
        $parsedPort = 0
        if (-not [int]::TryParse($portText, [ref]$parsedPort) -or $parsedPort -lt 0 -or $parsedPort -gt 65535) {
            throw "错误：WinRM 端口无效：$portText。"
        }
        $script:GuestRemotingPort = $parsedPort
        if (-not $automaticGuestEndpoint) {
            Set-ScriptSwitchValue -Name 'GuestRemotingUseSsl' -Value (Read-YesNoChoice -Prompt 'WinRM 使用 HTTPS/SSL？ / Use HTTPS/SSL for WinRM?' -DefaultYes ([bool]$GuestRemotingUseSsl))
        }
        Set-ScriptSwitchValue -Name 'GuestRemotingSkipCertificateChecks' -Value (Read-YesNoChoice -Prompt '跳过 WinRM 证书 CA/CN/吊销检查？ / Skip WinRM certificate checks?' -DefaultYes ([bool]$GuestRemotingSkipCertificateChecks))
        $script:GuestRemotingAuthentication = Read-OptionalText -Prompt 'WinRM 认证 (Negotiate/Basic/CredSSP) / Authentication' -CurrentValue $GuestRemotingAuthentication
    }
}

function Invoke-VirtualizationConfigPrompt {
    Write-InstallInfo '中文提示：配置只写入本机状态和本机 sandbox.local.json；不会把 VM 名称、密码或本机路径写入 git。'
    Select-VirtualizationProviderInteractive
    Import-SelectedVirtualizationProfileFromLocalConfig
    Read-VirtualizationProfileInteractive
    $script:GuestUserName = Read-OptionalText -Prompt '来宾用户名 / Guest username' -CurrentValue $GuestUserName
    $script:GuestWorkingDirectory = Read-OptionalText -Prompt '来宾工作目录 / Guest working directory' -CurrentValue $GuestWorkingDirectory
    $script:RuntimeRoot = Read-OptionalText -Prompt '宿主机运行目录 / Host runtime root' -CurrentValue $RuntimeRoot
    $script:GuestPayloadRoot = Read-OptionalText -Prompt '宿主机 guest payload 目录 / Host guest payload root' -CurrentValue $GuestPayloadRoot
    $script:DriverHostPath = Read-OptionalText -Prompt '宿主机 R0 驱动 .sys 路径（留空=自动检测/不配置） / Host R0 driver .sys path (blank=auto-detect/none)' -CurrentValue (Resolve-DriverHostPath)
    $script:LocalConfigPath = Read-OptionalText -Prompt '本机 sandbox 配置路径 / Local sandbox config path' -CurrentValue (Get-LocalSandboxConfigPath)
    Set-VirtualizationConfigState
}

function Invoke-HyperVConfigPrompt {
    $script:VirtualizationProvider = 'HyperV'
    Invoke-VirtualizationConfigPrompt
}

function Get-GuestPasswordSecretValue {
    param([Parameter(Mandatory)][string]$Name)

    foreach ($scope in @('Process', 'User', 'Machine')) {
        $value = [Environment]::GetEnvironmentVariable($Name, $scope)
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            return $value
        }
    }

    throw "错误：未在 Process/User/Machine 环境中找到当前 guest password secret '$Name'。下一步：先用 Reset password secret 保存与旧 baseline 一致的当前密码，再重试实际 VM 改密；密码值不会打印。"
}

function Get-OptionalFileSnapshot {
    param([Parameter(Mandatory)][string]$Path)

    $existed = Test-Path -LiteralPath $Path -PathType Leaf
    [byte[]]$bytes = $null
    if ($existed) {
        $bytes = [IO.File]::ReadAllBytes($Path)
    }

    return [pscustomobject][ordered]@{
        Path = $Path
        Existed = $existed
        Bytes = $bytes
    }
}

function Restore-OptionalFileSnapshot {
    param([Parameter(Mandatory)]$Snapshot)

    if ([bool]$Snapshot.Existed) {
        $parent = Split-Path -Parent ([string]$Snapshot.Path)
        if (-not [string]::IsNullOrWhiteSpace($parent)) {
            New-Item -ItemType Directory -Path $parent -Force | Out-Null
        }
        [IO.File]::WriteAllBytes([string]$Snapshot.Path, [byte[]]$Snapshot.Bytes)
    }
    else {
        Remove-Item -LiteralPath ([string]$Snapshot.Path) -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-RemoteGuestVmPasswordReset {
    param([bool]$OfflineRecovery = [bool]$RecoverGuestVmPasswordWithoutCurrentSecret)

    if ($VirtualizationProvider -eq 'VMware' -and $VMwareVmType -ne 'ws') {
        throw '错误：VMware 密码维护要求 Workstation Pro 与 vmType=ws；Player profile 不属于完整适配范围。请迁移并重新运行 CheckEnvironment。'
    }
    if ($SkipCheckpointRefresh) {
        throw "错误：$VirtualizationProvider 密码重置必须创建并切换到新的干净 baseline，不能使用 -SkipCheckpointRefresh；否则下次还原旧 baseline 后 host secret 会失配。"
    }
    if ($SkipCheckpointRestore) {
        throw "错误：$VirtualizationProvider 密码重置必须先从已记录的干净 baseline 开始，不能使用 -SkipCheckpointRestore。"
    }
    if ($GuestRemotingAuthentication -eq 'Basic' -and -not $GuestRemotingUseSsl) {
        throw '错误：密码轮换拒绝 Basic WinRM over HTTP。下一步：启用 WinRM HTTPS/SSL，或改用 Negotiate/CredSSP。'
    }

    if ($WhatIfPreference) {
        [void]$PSCmdlet.ShouldProcess("${VirtualizationProvider}::${VmName}::$CheckpointName", 'Rotate guest password and create a replacement clean baseline')
        $previewMode = if ($OfflineRecovery) { '把 clean baseline 转为临时 VHDX、注入一次性 LocalSystem 改密服务并验证新凭据' } else { '使用当前 secret 通过 WinRM 改密并验证' }
        Write-InstallInfo "预览：会从现有 '$CheckpointName' 开始，$previewMode，再创建新的 snapshot/基盘；旧 baseline 保留，当前不修改 VM、配置或 secret。"
        return
    }

    if ($OfflineRecovery -and [string]::IsNullOrWhiteSpace((Resolve-InstallExecutablePath -ConfiguredPath $QemuImgPath))) {
        throw "错误：$VirtualizationProvider 无旧密码离线恢复需要 qemu-img 做 VHDX 转换，但当前不可用：$QemuImgPath。下一步：安装 QEMU 或用 -QemuImgPath 指向 qemu-img.exe 后重试。"
    }
    if ($OfflineRecovery -and ($null -eq (Get-Command Mount-DiskImage -ErrorAction SilentlyContinue) -or $null -eq (Get-Command Dismount-DiskImage -ErrorAction SilentlyContinue))) {
        throw '错误：无旧密码离线恢复需要 Windows Storage 模块的 Mount-DiskImage/Dismount-DiskImage。下一步：在完整 Windows PowerShell 中启用 Storage 模块后重试。'
    }
    if ($OfflineRecovery -and -not (Test-IsAdministrator)) {
        throw "错误：$VirtualizationProvider 无旧密码离线恢复需要管理员 PowerShell 挂载临时 VHDX。下一步：以管理员身份重新打开 PowerShell 后重试。"
    }

    if ($Mode -ne 'Interactive' -and -not $Force) {
        throw "错误：非交互 $VirtualizationProvider 实际密码重置需要 -Force。下一步：确认是隔离分析 VM 且允许创建新 baseline 后重试。"
    }

    if ($Mode -eq 'Interactive') {
        Write-Host ''
        $interactiveWorkflow = if ($OfflineRecovery) { "离线注入一次性改密服务，启动 replacement VM 并通过 WinRM 验证 '$GuestUserName'" } else { "通过 WinRM 修改 '$GuestUserName' 密码并验证" }
        Write-Host "中文提示：将从 '$CheckpointName' 开始，$interactiveWorkflow，然后创建新的干净 baseline；旧 baseline 不删除。"
        $continue = Read-MenuChoice -Prompt 'Continue actual VM password reset? [y/n] / 继续重置 VM 来宾密码？[y/n]' -Allowed @('y', 'Y', 'n', 'N')
        if ($continue -in @('n', 'N')) {
            Write-InstallInfo '已取消 VM 实际密码重置。 / Actual VM password reset cancelled.'
            return
        }
    }

    $currentPassword = if ($OfflineRecovery) { $null } else { Get-GuestPasswordSecretValue -Name $SecretName }
    $credential = Read-NewGuestPassword
    if (-not $OfflineRecovery -and $currentPassword -ceq $credential.Password) {
        throw '错误：新密码必须与当前 guest password 不同。下一步：重新输入或使用 -GeneratePassword。'
    }

    $resetScript = Join-Path $PSScriptRoot 'scripts\Reset-RemoteGuestPassword.ps1'
    if (-not (Test-Path -LiteralPath $resetScript -PathType Leaf)) {
        throw "错误：找不到远程 guest 密码重置脚本：$resetScript。"
    }
    $confirmedAction = if ($OfflineRecovery) { 'Recover unknown guest password offline, verify the new credential, and create a replacement clean baseline' } else { 'Rotate guest password, verify the new credential, and create a replacement clean baseline' }
    if (-not $PSCmdlet.ShouldProcess("${VirtualizationProvider}::${VmName}::$CheckpointName", $confirmedAction)) {
        Write-InstallInfo '已通过 ShouldProcess/Confirm 取消 VM 实际密码重置。 / Actual VM password reset declined.'
        return
    }

    $configPath = Get-LocalSandboxConfigPath
    $snapshots = @(
        Get-OptionalFileSnapshot -Path $configPath
        Get-OptionalFileSnapshot -Path $script:InstallStatePath
        Get-OptionalFileSnapshot -Path $script:SecretBackupPath
    )
    $oldProcessSecret = [Environment]::GetEnvironmentVariable($SecretName, 'Process')
    $oldUserSecret = [Environment]::GetEnvironmentVariable($SecretName, 'User')
    $oldProcessWebConfigPath = [Environment]::GetEnvironmentVariable($script:WebConfigPathEnvironmentName, 'Process')
    $oldUserWebConfigPath = [Environment]::GetEnvironmentVariable($script:WebConfigPathEnvironmentName, 'User')
    $oldVmName = $VmName
    $oldCheckpointName = $CheckpointName
    $oldVMwareVmxPath = $VMwareVmxPath
    $oldQemuDiskImagePath = $QemuDiskImagePath
    $oldQemuUseOverlayDisk = [bool]$QemuUseOverlayDisk
    $temporaryNewSecretName = "KSWORDBOX_PASSWORD_RESET_$([Guid]::NewGuid().ToString('N'))"
    $qemuArgumentsJson = ConvertTo-Json -InputObject @($QemuAdditionalArguments) -Compress
    $qemuArgumentsBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($qemuArgumentsJson))

    $liveExecutionLease = Enter-InstallLiveExecutionLease -Operation "$VirtualizationProvider guest password reset"
    try {
        if (-not $OfflineRecovery) {
            [Environment]::SetEnvironmentVariable($SecretName, $currentPassword, 'Process')
        }
        [Environment]::SetEnvironmentVariable($temporaryNewSecretName, $credential.Password, 'Process')

        $arguments = @(
            '-NoProfile',
            '-ExecutionPolicy', 'Bypass',
            '-File', $resetScript,
            '-VirtualizationProvider', $VirtualizationProvider,
            '-VmName', $VmName,
            '-CheckpointName', $CheckpointName,
            '-GuestUserName', $GuestUserName,
            '-NewPasswordSecretName', $temporaryNewSecretName,
            '-GuestRemotingAddressMode', $GuestRemotingAddressMode,
            '-GuestRemotingPort', ([string]$GuestRemotingPort),
            '-GuestRemotingAuthentication', $GuestRemotingAuthentication,
            '-GuestReadyTimeoutSeconds', ([string]$PowerShellDirectTimeoutSeconds),
            '-RuntimeRoot', $RuntimeRoot,
            '-Force',
            '-Json',
            '-Confirm:$false'
        )
        if ($OfflineRecovery) {
            $arguments += '-OfflineRecovery'
        }
        else {
            $arguments += @('-CurrentPasswordSecretName', $SecretName)
        }
        if (-not [string]::IsNullOrWhiteSpace($GuestRemotingAddress)) {
            $arguments += @('-GuestRemotingAddress', $GuestRemotingAddress)
        }
        if ($GuestRemotingUseSsl) { $arguments += '-GuestRemotingUseSsl' }
        if ($GuestRemotingSkipCertificateChecks) { $arguments += '-GuestRemotingSkipCertificateChecks' }
        if ($VirtualizationProvider -eq 'VMware') {
            $arguments += @(
                '-VMwareVmxPath', $VMwareVmxPath,
                '-VMwareVmrunPath', $VMwareVmrunPath,
                '-VMwareVmType', $VMwareVmType
            )
            if ($OfflineRecovery) {
                $arguments += @('-QemuImgPath', $QemuImgPath)
            }
            if ($VMwareHeadless) { $arguments += '-VMwareHeadless' }
        }
        else {
            $arguments += @(
                '-QemuDiskImagePath', $QemuDiskImagePath,
                '-QemuSystemPath', $QemuSystemPath,
                '-QemuImgPath', $QemuImgPath,
                '-QemuDiskFormat', $QemuDiskFormat,
                '-QemuDiskInterface', $QemuDiskInterface,
                '-QemuMemoryMegabytes', ([string]$QemuMemoryMegabytes),
                '-QemuAdditionalArgumentsBase64', $qemuArgumentsBase64
            )
            if ($QemuUseOverlayDisk) { $arguments += '-QemuUseOverlayDisk' }
            if ($QemuHeadless) { $arguments += '-QemuHeadless' }
        }

        $resetTransport = if ($OfflineRecovery) { "$VirtualizationProvider offline VHDX injection + WinRM verification" } else { "$VirtualizationProvider/WinRM" }
        Write-InstallInfo "正在通过 $resetTransport 重置实际 VM 密码并创建替换 baseline；密码值不会打印，旧 baseline 保留。"
        $resetOutput = @(& powershell @arguments 2>&1 | ForEach-Object { [string]$_ })
        $resetExitCode = $LASTEXITCODE
        if ($resetExitCode -ne 0) {
            throw "provider guest 密码重置失败，退出码 $resetExitCode。详情：$($resetOutput -join ' ')"
        }
        try {
            $result = ($resetOutput -join [Environment]::NewLine) | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            throw "provider guest 密码重置返回了无效 JSON；本机配置和 secret 尚未切换。详情：$($_.Exception.Message)"
        }
        if (-not [bool]$result.PasswordChanged -or
            -not [bool]$result.CredentialVerified -or
            -not [bool]$result.BaselineRefreshed -or
            -not [bool]$result.OldBaselinePreserved -or
            -not [bool]$result.ProviderChildSecretEnvironmentCleared -or
            [bool]$result.SecretValuePrinted) {
            throw '远程 guest 密码重置结果未满足 password/credential/baseline/secret 安全契约；本机配置和 secret 尚未切换。'
        }
        if ([bool]$result.OfflineRecovery -ne $OfflineRecovery) {
            throw 'guest 密码重置返回的 offline/remote 模式与请求不一致；本机配置和 secret 尚未切换。'
        }
        if ($OfflineRecovery -and -not [bool]$result.OfflineTemporaryWorkspaceRemoved) {
            throw 'offline guest 密码恢复未确认临时 secret-bearing workspace 已删除；本机配置和 secret 尚未切换。'
        }
        if ($OfflineRecovery -and -not [bool]$result.OfflineGuestServiceCleanupConfirmed) {
            throw 'offline guest 密码恢复未确认来宾一次性服务和注入脚本已清理；本机配置和 secret 尚未切换。'
        }

        if ($VirtualizationProvider -eq 'VMware') {
            if ([string]::IsNullOrWhiteSpace([string]$result.NewSnapshotName)) {
                throw 'VMware 密码重置未返回新的 snapshot 名称；本机配置和 secret 尚未切换。'
            }
            if ($OfflineRecovery) {
                if ([string]::IsNullOrWhiteSpace([string]$result.NewVmxPath)) {
                    throw 'VMware 离线恢复未返回 replacement VMX 路径；本机配置和 secret 尚未切换。'
                }
                if ([string]::IsNullOrWhiteSpace([string]$result.NewVmName)) {
                    throw 'VMware 离线恢复未返回 replacement VM 名称；本机配置和 secret 尚未切换。'
                }
                $script:VMwareVmxPath = [string]$result.NewVmxPath
                $script:VmName = [string]$result.NewVmName
            }
            $script:CheckpointName = [string]$result.NewSnapshotName
        }
        else {
            if ([bool]$QemuUseOverlayDisk -or $OfflineRecovery) {
                if ([string]::IsNullOrWhiteSpace([string]$result.NewDiskImagePath)) {
                    throw 'QEMU 密码重置未返回新的独立基盘路径；本机配置和 secret 尚未切换。'
                }
                $script:QemuDiskImagePath = [string]$result.NewDiskImagePath
            }
            if (-not [bool]$QemuUseOverlayDisk) {
                if ([string]::IsNullOrWhiteSpace([string]$result.NewSnapshotName)) {
                    throw 'QEMU 内部 snapshot 密码重置未返回新的 snapshot 名称；本机配置和 secret 尚未切换。'
                }
                $script:CheckpointName = [string]$result.NewSnapshotName
            }
        }

        $updatedConfigPath = Write-LocalSandboxConfig
        Set-WebConfigPathEnvironment -ConfigPath $updatedConfigPath
        $passwordSource = if ($OfflineRecovery) { "offline-recovery-$($credential.Source)" } else { "remote-reset-$($credential.Source)" }
        Set-GuestPasswordSecret -Name $SecretName -Password $credential.Password -PasswordSource $passwordSource
        Write-InstallInfo "VM 实际密码重置完成：$VirtualizationProvider 已切换到新的干净 baseline，旧 baseline 保留；宿主 secret 与本机配置已同步。"
    }
    catch {
        $primaryError = $_
        $rollbackErrors = [System.Collections.Generic.List[string]]::new()
        $script:VmName = $oldVmName
        $script:CheckpointName = $oldCheckpointName
        $script:VMwareVmxPath = $oldVMwareVmxPath
        $script:QemuDiskImagePath = $oldQemuDiskImagePath
        $script:QemuUseOverlayDisk = $oldQemuUseOverlayDisk
        $environmentSnapshots = @(
            [pscustomobject]@{ Name = $SecretName; Scope = 'Process'; Value = $oldProcessSecret }
            [pscustomobject]@{ Name = $SecretName; Scope = 'User'; Value = $oldUserSecret }
            [pscustomobject]@{ Name = $script:WebConfigPathEnvironmentName; Scope = 'Process'; Value = $oldProcessWebConfigPath }
            [pscustomobject]@{ Name = $script:WebConfigPathEnvironmentName; Scope = 'User'; Value = $oldUserWebConfigPath }
        )
        foreach ($environmentSnapshot in $environmentSnapshots) {
            try {
                [Environment]::SetEnvironmentVariable(
                    [string]$environmentSnapshot.Name,
                    $environmentSnapshot.Value,
                    [EnvironmentVariableTarget]$environmentSnapshot.Scope)
            }
            catch {
                [void]$rollbackErrors.Add("environment '$($environmentSnapshot.Name)' ($($environmentSnapshot.Scope)): $($_.Exception.Message)")
            }
        }
        foreach ($snapshot in $snapshots) {
            try {
                Restore-OptionalFileSnapshot -Snapshot $snapshot
            }
            catch {
                [void]$rollbackErrors.Add("file '$($snapshot.Path)': $($_.Exception.Message)")
            }
        }
        if ($rollbackErrors.Count -gt 0) {
            throw "错误：$($primaryError.Exception.Message) 本机回滚不完整：$($rollbackErrors -join ' | ')；旧 provider baseline 仍保留，请先核对 config/install-state/secret 后再运行 VM。"
        }
        throw "错误：$($primaryError.Exception.Message) 已恢复原本机 config/install-state/secret 元数据；旧 provider baseline 仍保留。"
    }
    finally {
        try {
            [Environment]::SetEnvironmentVariable($temporaryNewSecretName, $null, 'Process')
            if ($null -ne $credential) { $credential.Password = $null }
            $currentPassword = $null
        }
        finally {
            Exit-InstallLiveExecutionLease -Lease $liveExecutionLease
        }
    }
}

function Invoke-GuidedFirstRunSetup {
    Write-Host ''
    Write-Host 'KSwordSandbox 推荐安装向导 / Recommended setup wizard'
    Write-Host '中文提示：直接运行 install.ps1 会在这里询问常用设置；不需要记命令行参数。'
    Write-Host '边界：本向导只写本机 runtime/config/secret，不创建 VM、不创建 clean baseline、不还原快照、不签名 driver、不调用 CSignTool。'
    Write-Host ''

    Select-VirtualizationProviderInteractive
    Read-VirtualizationProfileInteractive
    $script:GuestUserName = Read-OptionalText -Prompt '来宾用户名 / Guest username' -CurrentValue $GuestUserName
    $script:GuestWorkingDirectory = Read-OptionalText -Prompt '来宾工作目录 / Guest working directory' -CurrentValue $GuestWorkingDirectory
    $script:RuntimeRoot = Read-OptionalText -Prompt '宿主机运行目录（仓库/包外） / Host runtime root' -CurrentValue $RuntimeRoot
    $script:GuestPayloadRoot = Read-OptionalText -Prompt 'Guest payload 目录（默认包内 payload） / Guest payload root' -CurrentValue $GuestPayloadRoot
    $script:LocalConfigPath = Read-OptionalText -Prompt '本机 sandbox 配置路径 / Local sandbox config path' -CurrentValue (Get-LocalSandboxConfigPath)
    $driverDefault = Resolve-DriverHostPath
    if ($null -eq $driverDefault) {
        $driverDefault = ''
    }
    $script:DriverHostPath = Read-OptionalText -Prompt 'R0 driver .sys 路径（可留空，真实 R0 后续再配） / R0 driver .sys path (blank OK)' -CurrentValue $driverDefault

    $updateWebEnvironment = Read-YesNoChoice -Prompt "是否设置 '$script:WebConfigPathEnvironmentName' 让 WebUI 自动找到配置？ / Set WebUI config environment variable?" -DefaultYes $true
    Set-ScriptSwitchValue -Name 'SkipWebConfigEnvironment' -Value (-not $updateWebEnvironment)

    Write-Host ''
    Write-Host '来宾密码 secret / Guest password secret:'
    Write-Host '  1) 输入 VM 中现有 guest 密码（推荐） / Enter existing guest password (recommended)'
    Write-Host '  2) 生成并保存一个新 secret（之后需同步 VM 密码） / Generate new local secret'
    Write-Host '  3) 暂不设置密码 secret / Skip password secret for now'
    $passwordChoice = Read-MenuChoice -Prompt '请选择 [1-3] / Choose [1-3]' -Allowed @('1', '2', '3')
    $setPassword = $passwordChoice -ne '3'
    Set-ScriptSwitchValue -Name 'PromptPassword' -Value ($passwordChoice -eq '1')
    Set-ScriptSwitchValue -Name 'GeneratePassword' -Value ($passwordChoice -eq '2')

    if ($setPassword) {
        $credential = Read-GuestPassword -UseGenerated ([bool]$GeneratePassword) -UsePrompt ([bool]$PromptPassword) -ExistingSecretName $SecretName
        Set-GuestPasswordSecret -Name $SecretName -Password $credential.Password -PasswordSource $credential.Source
    }

    Set-VirtualizationConfigState -Action 'guided-setup-completed'

    if (Read-YesNoChoice -Prompt '是否现在配置可选 VirusTotal hash-only API key？ / Configure optional VirusTotal hash-only API key now?' -DefaultYes $false) {
        Invoke-VirusTotalKeyConfiguration
    }

    Write-Host ''
    Write-InstallInfo '推荐安装向导完成。下面是当前环境检查；如有缺口，请按 RecommendedActions 处理。 / Guided setup completed.'
    Invoke-KSwordSandboxEnvironmentCheck

    if (Read-YesNoChoice -Prompt '是否现在启动 WebUI？ / Start WebUI now?' -DefaultYes $false) {
        Invoke-KSwordSandboxWebUi
    }
}

function Invoke-GuestVmPasswordReset {
    param([bool]$OfflineRecovery = [bool]$RecoverGuestVmPasswordWithoutCurrentSecret)

    if ($VirtualizationProvider -ne 'HyperV') {
        Invoke-RemoteGuestVmPasswordReset -OfflineRecovery $OfflineRecovery
        return
    }

    $resetScript = Join-Path $PSScriptRoot 'scripts\Reset-SandboxGuestPassword.ps1'
    if (-not (Test-Path -LiteralPath $resetScript -PathType Leaf)) {
        throw "错误：找不到 VM 来宾密码重置脚本：$resetScript。下一步：请确认 scripts\Reset-SandboxGuestPassword.ps1 存在，并从仓库根目录运行。"
    }

    if ($WhatIfPreference) {
        [void]$PSCmdlet.ShouldProcess($VmName, "Reset actual VM guest password for '$GuestUserName'")
        Write-InstallInfo "预览：会委托 '$resetScript' 重置 VM 内实际密码；当前不会还原快照、挂载磁盘、启动 VM 或刷新快照。 / WhatIf: actual VM password reset would be delegated."
        return
    }

    if (-not (Test-IsAdministrator)) {
        throw '错误：重置 VM 内实际密码需要管理员 PowerShell，因为会还原快照并挂载 VM 磁盘。下一步：请以管理员身份打开 PowerShell 后重试；只想保存本机 secret 时请选择 Reset password secret。'
    }

    $usePromptPassword = [bool]$PromptPassword
    if ($Mode -eq 'Interactive') {
        Write-Host ''
        Write-Host "中文提示：将还原快照 '$CheckpointName'、挂载 VM 磁盘、启动 '$VmName'、重置 '$GuestUserName'、验证 PowerShell Direct，并刷新快照。 / This will restore checkpoint, mount disk, boot VM, reset password, validate PowerShell Direct, and refresh the checkpoint."
        Write-Host "中文提示：这会操作 Hyper-V VM 和快照；密码值不会显示，完成后宿主机 secret 与 VM 来宾密码保持一致。"
        $continue = Read-MenuChoice -Prompt 'Continue actual VM password reset? [y/n] / 继续重置 VM 来宾密码？[y/n]' -Allowed @('y', 'Y', 'n', 'N')
        if ($continue -in @('n', 'N')) {
            Write-InstallInfo '已取消 VM 实际密码重置。 / Actual VM password reset cancelled.'
            return
        }

        Write-Host ''
        Write-Host 'VM 实际密码选项 / Actual VM password options:'
        Write-Host '  1) 在重置脚本中生成随机密码 / Generate a new random password inside the reset script'
        Write-Host '  2) 在重置脚本中提示输入新密码 / Prompt for a new VM password inside the reset script'
        $passwordChoice = Read-MenuChoice -Prompt '请选择 [1-2] / Choose [1-2]' -Allowed @('1', '2')
        $usePromptPassword = ($passwordChoice -eq '2')
    }
    elseif (-not $Force) {
        throw '错误：非交互重置 VM 实际密码需要 -Force，避免停在 Hyper-V 确认提示。下一步：确认这是隔离实验 VM 后，加 -Force 重试。'
    }

    $arguments = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $resetScript,
        '-VmName', $VmName,
        '-CheckpointName', $CheckpointName,
        '-GuestUserName', $GuestUserName,
        '-SecretName', $SecretName,
        '-RuntimeRoot', $RuntimeRoot,
        '-GuestWorkingDirectory', $GuestWorkingDirectory,
        '-BootTimeoutSeconds', ([string]$BootTimeoutSeconds),
        '-PowerShellDirectTimeoutSeconds', ([string]$PowerShellDirectTimeoutSeconds),
        '-Force'
    )
    if ($usePromptPassword) {
        $arguments += '-PromptPassword'
    }
    if ($SkipCheckpointRefresh) {
        $arguments += '-SkipCheckpointRefresh'
    }
    if ($SkipCheckpointRestore) {
        $arguments += '-SkipCheckpointRestore'
    }

    if (-not $PSCmdlet.ShouldProcess($VmName, "Launch actual VM password reset for '$GuestUserName'")) {
        Write-InstallInfo '已通过 ShouldProcess/Confirm 拒绝 VM 实际密码重置。 / Actual VM password reset declined.'
        return
    }

    $liveExecutionLease = Enter-InstallLiveExecutionLease -Operation 'Hyper-V guest password reset'
    try {
        Write-InstallInfo "正在为 '$VmName' 启动 VM 实际密码重置；secret 值不会打印。 / Launching actual VM password reset."
        & powershell @arguments
        if ($LASTEXITCODE -ne 0) {
            throw "错误：VM 实际密码重置失败，退出码 $LASTEXITCODE。下一步：查看上方 Reset-SandboxGuestPassword 输出，确认管理员权限、VM 名称、快照和 PowerShell Direct 后重试。"
        }

        $userSecret = [Environment]::GetEnvironmentVariable($SecretName, 'User')
        if (-not [string]::IsNullOrWhiteSpace($userSecret)) {
            [Environment]::SetEnvironmentVariable($SecretName, $userSecret, 'Process')
        }

        $configPath = Write-LocalSandboxConfig
        Set-WebConfigPathEnvironment -ConfigPath $configPath
        Write-InstallInfo 'VM 实际密码重置完成；宿主机 secret 与本机 sandbox 配置已同步。 / Actual VM password reset completed.'
    }
    finally {
        Exit-InstallLiveExecutionLease -Lease $liveExecutionLease
    }
}

function Set-GuestUserNameState {
    param([string]$NewGuestUserName)

    if ([string]::IsNullOrWhiteSpace($NewGuestUserName)) {
        throw '错误：来宾用户名不能为空。下一步：请传入 -GuestUserName <name>，通常为 SandboxUser。'
    }

    $script:GuestUserName = $NewGuestUserName

    Save-InstallState `
        -Action 'guest-user-changed' `
        -GuestUser $NewGuestUserName `
        -Secret $SecretName `
        -Runtime $RuntimeRoot `
        -PayloadRoot $GuestPayloadRoot `
        -PasswordSource 'unchanged' `
        -PersistedToUser (-not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($SecretName, 'User'))) `
        -PersistedToProcess (-not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($SecretName, 'Process'))) `
        -DpapiBackup (Test-Path -LiteralPath $script:SecretBackupPath -PathType Leaf)

    Write-InstallInfo "已在安装状态中记录来宾用户名：$NewGuestUserName / Recorded guest user name."
    Set-VirtualizationConfigState -Action 'guest-user-changed'
}

function Test-InstallPathUnderRoot {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root
    )

    try {
        $fullPath = [System.IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
        $fullRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
        $rootPrefix = $fullRoot + [System.IO.Path]::DirectorySeparatorChar
        return $fullPath.Equals($fullRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
            $fullPath.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)
    }
    catch {
        return $false
    }
}

function Get-InstallWindowsFeatureState {
    param([Parameter(Mandatory)][string]$FeatureName)

    $errors = [System.Collections.Generic.List[string]]::new()
    $optionalFeatureCommand = Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue
    if ($null -ne $optionalFeatureCommand) {
        try {
            $feature = Get-WindowsOptionalFeature -Online -FeatureName $FeatureName -ErrorAction Stop
            return [pscustomobject][ordered]@{
                State = [string]$feature.State
                QueryMethod = 'Get-WindowsOptionalFeature'
                Error = ''
            }
        }
        catch {
            [void]$errors.Add("Get-WindowsOptionalFeature: $($_.Exception.Message)")
        }
    }
    else {
        [void]$errors.Add('Get-WindowsOptionalFeature is unavailable.')
    }

    if ($null -ne (Get-Command Get-CimInstance -ErrorAction SilentlyContinue)) {
        try {
            $escapedFeatureName = $FeatureName.Replace("'", "''")
            $feature = Get-CimInstance -ClassName Win32_OptionalFeature -Filter "Name='$escapedFeatureName'" -ErrorAction Stop | Select-Object -First 1
            if ($null -eq $feature) {
                throw "Win32_OptionalFeature did not return '$FeatureName'."
            }

            $state = switch ([int]$feature.InstallState) {
                1 { 'Enabled' }
                2 { 'Disabled' }
                3 { 'Absent' }
                default { 'Unknown' }
            }
            return [pscustomobject][ordered]@{
                State = $state
                QueryMethod = 'Win32_OptionalFeature'
                Error = if ($state -eq 'Unknown') { "Win32_OptionalFeature reported an unknown state for '$FeatureName'." } else { '' }
            }
        }
        catch {
            [void]$errors.Add("Win32_OptionalFeature: $($_.Exception.Message)")
        }
    }
    else {
        [void]$errors.Add('Get-CimInstance is unavailable.')
    }

    [pscustomobject][ordered]@{
        State = 'Unknown'
        QueryMethod = 'Unavailable'
        Error = $errors -join ' '
    }
}

function Get-InstallHyperVPrerequisiteStatus {
    $actions = [System.Collections.Generic.List[string]]::new()
    $featureStates = [ordered]@{}
    $osIsWindows = [System.StringComparer]::OrdinalIgnoreCase.Equals([string]$env:OS, 'Windows_NT')
    $isAdministrator = Test-IsAdministrator
    $operatingSystemCaption = ''
    $operatingSystemSku = $null
    $windowsEditionLikelySupportsClientHyperV = $null
    $freshComputerCompatibility = 'Unknown'
    $powerShellModuleAvailable = $null -ne (Get-Command Get-VM -ErrorAction SilentlyContinue)
    $optionalFeatureCommandAvailable = $null -ne (Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue)
    $cimAvailable = $null -ne (Get-Command Get-CimInstance -ErrorAction SilentlyContinue)
    $hypervisorPresent = $null
    $virtualizationFirmwareEnabled = $null
    $slatSupported = $null
    $vmMonitorModeExtensions = $null
    $inspectionErrors = [System.Collections.Generic.List[string]]::new()

    if (-not $osIsWindows) {
        [void]$actions.Add('下一步：Hyper-V live 模式需要 Windows 宿主机；非 Windows 环境只能做源码/打包/报告查看。')
    }

    if (-not $isAdministrator) {
        [void]$actions.Add('下一步：请用管理员 PowerShell 重新运行 CheckEnvironment/Test-HyperVReadiness；Status 仍只读，不会启动或还原 VM。')
    }

    if (-not $powerShellModuleAvailable) {
        [void]$actions.Add('下一步：启用 Windows 功能 Hyper-V 与 Hyper-V PowerShell 管理工具后重新运行 CheckEnvironment；readiness/status 只读，不会启动 VM。')
    }

    if ($osIsWindows) {
        foreach ($featureName in @('Microsoft-Hyper-V-All', 'Microsoft-Hyper-V-Management-PowerShell')) {
            $featureResult = Get-InstallWindowsFeatureState -FeatureName $featureName
            $featureStates[$featureName] = [string]$featureResult.State
            if ($featureResult.State -ne 'Enabled' -and $featureResult.State -ne 'Unknown') {
                [void]$actions.Add("下一步：启用 Windows Optional Feature '$featureName'（需要管理员权限和重启），然后重新运行 .\install.ps1 -Mode CheckEnvironment。")
            }
            elseif ($featureResult.State -eq 'Unknown') {
                [void]$inspectionErrors.Add("无法读取 Windows feature $featureName：$($featureResult.Error)")
                [void]$actions.Add("下一步：以管理员身份确认 Windows Optional Feature '$featureName'；未确认前不把 Hyper-V 视为 Live-ready。")
            }
        }
    }

    if ($cimAvailable) {
        try {
            $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
            $operatingSystemCaption = [string]$operatingSystem.Caption
            $operatingSystemSku = $operatingSystem.OperatingSystemSKU
            if ($osIsWindows) {
                $isServer = [int]$operatingSystem.ProductType -ne 1
                $looksHomeEdition = $operatingSystemCaption -match '(?i)\bHome\b|CoreSingleLanguage|CoreCountrySpecific'
                $windowsEditionLikelySupportsClientHyperV = $isServer -or (-not $looksHomeEdition)
                if (-not $windowsEditionLikelySupportsClientHyperV) {
                    $freshComputerCompatibility = 'BlockedWindowsHomeOrCoreEdition'
                    [void]$actions.Add('下一步：Windows Home/Core 不能作为默认 Hyper-V live host；请使用 Windows Pro/Enterprise/Education 或 Windows Server，或只运行 PlanOnly/WhatIf。')
                }
                else {
                    $freshComputerCompatibility = 'LikelyCompatibleWindowsEdition'
                }
            }
        }
        catch {
            [void]$inspectionErrors.Add("无法读取 Windows edition/SKU：$($_.Exception.Message)")
        }

        try {
            $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
            $hypervisorPresent = [bool]$computerSystem.HypervisorPresent
        }
        catch {
            [void]$inspectionErrors.Add("无法读取 Win32_ComputerSystem.HypervisorPresent：$($_.Exception.Message)")
        }

        try {
            $processor = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1
            if ($null -ne $processor) {
                $virtualizationFirmwareEnabledProperty = $processor.PSObject.Properties['VirtualizationFirmwareEnabled']
                if ($null -ne $virtualizationFirmwareEnabledProperty) {
                    $virtualizationFirmwareEnabled = [bool]$virtualizationFirmwareEnabledProperty.Value
                    if (-not $virtualizationFirmwareEnabled -and $hypervisorPresent -ne $true) {
                        [void]$actions.Add('下一步：在 BIOS/UEFI 启用 Intel VT-x/AMD-V（虚拟化技术），冷重启后重新检查 Hyper-V readiness。')
                    }
                }

                $slatProperty = $processor.PSObject.Properties['SecondLevelAddressTranslationExtensions']
                if ($null -ne $slatProperty) {
                    $slatSupported = [bool]$slatProperty.Value
                    if (-not $slatSupported) {
                        [void]$actions.Add('下一步：Hyper-V 需要 SLAT/EPT/NPT 支持；请换用支持二级地址转换的宿主机 CPU。')
                    }
                }

                $vmMonitorProperty = $processor.PSObject.Properties['VMMonitorModeExtensions']
                if ($null -ne $vmMonitorProperty) {
                    $vmMonitorModeExtensions = [bool]$vmMonitorProperty.Value
                }
            }
        }
        catch {
            [void]$inspectionErrors.Add("无法读取 CPU virtualization readiness：$($_.Exception.Message)")
        }
    }
    else {
        [void]$inspectionErrors.Add('Get-CimInstance 不可用；无法读取 BIOS/CPU 虚拟化状态。')
    }

    [pscustomobject][ordered]@{
        OsIsWindows = $osIsWindows
        IsAdministrator = $isAdministrator
        OperatingSystemCaption = $operatingSystemCaption
        OperatingSystemSKU = $operatingSystemSku
        WindowsEditionLikelySupportsClientHyperV = $windowsEditionLikelySupportsClientHyperV
        FreshComputerCompatibility = $freshComputerCompatibility
        PowerShellModuleAvailable = $powerShellModuleAvailable
        OptionalFeatureCommandAvailable = $optionalFeatureCommandAvailable
        CimAvailable = $cimAvailable
        FeatureStates = [pscustomobject]$featureStates
        HypervisorPresent = $hypervisorPresent
        VirtualizationFirmwareEnabled = $virtualizationFirmwareEnabled
        SecondLevelAddressTranslationSupported = $slatSupported
        VmMonitorModeExtensions = $vmMonitorModeExtensions
        InspectionErrors = @($inspectionErrors.ToArray())
        RecommendedActions = @($actions.ToArray())
        StartsOrMutatesVm = $false
        ChineseGuidance = '中文提示：这些 Hyper-V 前置检查只读；不会启动、还原、停止或修改 VM。'
    }
}

function Get-InstallProviderHostPrerequisiteStatus {
    param(
        [Parameter(Mandatory)][ValidateSet('HyperV', 'VMware', 'Qemu')][string]$Provider,
        [Parameter(Mandatory)][object]$HyperVPrerequisites
    )

    if ($Provider -eq 'HyperV') {
        $requiredWindowsFeature = 'Microsoft-Hyper-V-All'
        $requiredWindowsFeatureProperty = $HyperVPrerequisites.FeatureStates.PSObject.Properties[$requiredWindowsFeature]
        $requiredWindowsFeatureState = if ($null -eq $requiredWindowsFeatureProperty) { 'Unknown' } else { [string]$requiredWindowsFeatureProperty.Value }
        $requiredWindowsFeatureReady = if ($requiredWindowsFeatureState -eq 'Enabled') { $true } elseif ($requiredWindowsFeatureState -eq 'Unknown') { $null } else { $false }
        $hardwareReady = if (-not [bool]$HyperVPrerequisites.OsIsWindows) {
            $false
        }
        elseif (($HyperVPrerequisites.VirtualizationFirmwareEnabled -eq $false -and $HyperVPrerequisites.HypervisorPresent -ne $true) -or
            $HyperVPrerequisites.SecondLevelAddressTranslationSupported -eq $false -or
            $requiredWindowsFeatureReady -eq $false) {
            $false
        }
        elseif (($HyperVPrerequisites.VirtualizationFirmwareEnabled -eq $true -or $HyperVPrerequisites.HypervisorPresent -eq $true) -and
            $HyperVPrerequisites.SecondLevelAddressTranslationSupported -eq $true -and
            $requiredWindowsFeatureReady -eq $true) {
            $true
        }
        else {
            $null
        }

        return [pscustomobject][ordered]@{
            Schema = 'ksword.provider-host-prerequisites.v1'
            Provider = $Provider
            OperatingSystemSupported = [bool]$HyperVPrerequisites.OsIsWindows
            CimAvailable = [bool]$HyperVPrerequisites.CimAvailable
            QuerySucceeded = [bool]$HyperVPrerequisites.OsIsWindows -and
                [bool]$HyperVPrerequisites.CimAvailable -and
                ($HyperVPrerequisites.VirtualizationFirmwareEnabled -ne $null -or
                    $HyperVPrerequisites.SecondLevelAddressTranslationSupported -ne $null -or
                    $HyperVPrerequisites.VmMonitorModeExtensions -ne $null) -and
                ($requiredWindowsFeatureReady -ne $null)
            HypervisorPresent = $HyperVPrerequisites.HypervisorPresent
            VirtualizationFirmwareEnabled = $HyperVPrerequisites.VirtualizationFirmwareEnabled
            SecondLevelAddressTranslationSupported = $HyperVPrerequisites.SecondLevelAddressTranslationSupported
            VmMonitorModeExtensions = $HyperVPrerequisites.VmMonitorModeExtensions
            HardwareAccelerationReady = $hardwareReady
            AcceleratorExpectation = 'Hyper-V hardware acceleration'
            RequiredWindowsFeature = $requiredWindowsFeature
            RequiredWindowsFeatureState = $requiredWindowsFeatureState
            RequiredWindowsFeatureReady = $requiredWindowsFeatureReady
            InspectionErrors = @($HyperVPrerequisites.InspectionErrors)
            RecommendedActions = @($HyperVPrerequisites.RecommendedActions)
            StartsOrMutatesVm = $false
            ChineseGuidance = '中文提示：宿主硬件虚拟化检查只读；不会启动、还原、停止或修改 VM。'
        }
    }

    $actions = [System.Collections.Generic.List[string]]::new()
    $inspectionErrors = [System.Collections.Generic.List[string]]::new()
    $osIsWindows = [System.StringComparer]::OrdinalIgnoreCase.Equals([string]$env:OS, 'Windows_NT')
    $cimAvailable = $null -ne (Get-Command Get-CimInstance -ErrorAction SilentlyContinue)
    $querySucceeded = $false
    $hypervisorPresent = $null
    $virtualizationFirmwareEnabled = $null
    $slatSupported = $null
    $vmMonitorModeExtensions = $null
    $requiredWindowsFeature = if ($Provider -eq 'Qemu') { 'HypervisorPlatform' } else { '' }
    $requiredWindowsFeatureState = if ($Provider -eq 'Qemu') { 'Unknown' } else { 'NotRequired' }
    $requiredWindowsFeatureReady = if ($Provider -eq 'Qemu') { $null } else { $true }

    if (-not $osIsWindows) {
        [void]$actions.Add("下一步：KSwordSandbox $Provider Live 需要 Windows 宿主机；当前环境只能做源码、报告、打包或 PlanOnly。")
    }

    if ($cimAvailable) {
        try {
            $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
            $hypervisorPresent = [bool]$computerSystem.HypervisorPresent
        }
        catch {
            [void]$inspectionErrors.Add("无法读取 Win32_ComputerSystem.HypervisorPresent：$($_.Exception.Message)")
        }

        try {
            $processor = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1
            if ($null -eq $processor) {
                [void]$inspectionErrors.Add('Win32_Processor 未返回 CPU 记录。')
            }
            else {
                $virtualizationProperty = $processor.PSObject.Properties['VirtualizationFirmwareEnabled']
                $slatProperty = $processor.PSObject.Properties['SecondLevelAddressTranslationExtensions']
                $vmMonitorProperty = $processor.PSObject.Properties['VMMonitorModeExtensions']
                if ($null -ne $virtualizationProperty) { $virtualizationFirmwareEnabled = [bool]$virtualizationProperty.Value }
                if ($null -ne $slatProperty) { $slatSupported = [bool]$slatProperty.Value }
                if ($null -ne $vmMonitorProperty) { $vmMonitorModeExtensions = [bool]$vmMonitorProperty.Value }
                $querySucceeded = $true
            }
        }
        catch {
            [void]$inspectionErrors.Add("无法读取 CPU virtualization readiness：$($_.Exception.Message)")
        }
    }
    else {
        [void]$inspectionErrors.Add('Get-CimInstance 不可用；无法读取 BIOS/CPU 虚拟化状态。')
    }

    if ($Provider -eq 'Qemu' -and $osIsWindows) {
        $requiredFeatureResult = Get-InstallWindowsFeatureState -FeatureName $requiredWindowsFeature
        $requiredWindowsFeatureState = [string]$requiredFeatureResult.State
        $requiredWindowsFeatureReady = if ($requiredWindowsFeatureState -eq 'Enabled') { $true } elseif ($requiredWindowsFeatureState -eq 'Unknown') { $null } else { $false }
        if ($requiredWindowsFeatureReady -eq $false) {
            [void]$actions.Add("下一步：启用 Windows Hypervisor Platform ('$requiredWindowsFeature') 并重启，再运行 QEMU WHPX Live。")
        }
        elseif ($null -eq $requiredWindowsFeatureReady) {
            [void]$inspectionErrors.Add("无法读取 Windows feature $requiredWindowsFeature：$($requiredFeatureResult.Error)")
            [void]$actions.Add("下一步：以管理员身份确认 Windows Hypervisor Platform ('$requiredWindowsFeature') 状态；未确认前不把 QEMU 视为 Live-ready。")
        }
    }

    if ($virtualizationFirmwareEnabled -eq $false -and $hypervisorPresent -ne $true) {
        [void]$actions.Add("下一步：在 BIOS/UEFI 启用 Intel VT-x/AMD-V；$Provider 的硬件加速未就绪，冷重启后重新运行 CheckEnvironment。")
    }
    if ($slatSupported -eq $false) {
        [void]$actions.Add("下一步：$Provider 的 Hyper-V 等级体验需要 SLAT/EPT/NPT；请使用支持二级地址转换的宿主 CPU。")
    }
    if (-not $querySucceeded -and $osIsWindows) {
        [void]$actions.Add("下一步：修复 Win32_Processor/CIM 查询权限后重新运行 CheckEnvironment；在能力未确认前不要把 $Provider 视为 Live-ready。")
    }

    $hardwareReady = if (-not $osIsWindows) {
        $false
    }
    elseif (($virtualizationFirmwareEnabled -eq $false -and $hypervisorPresent -ne $true) -or
        $slatSupported -eq $false -or
        $requiredWindowsFeatureReady -eq $false) {
        $false
    }
    elseif ($querySucceeded -and
        ($virtualizationFirmwareEnabled -eq $true -or $hypervisorPresent -eq $true) -and
        $slatSupported -eq $true -and
        $requiredWindowsFeatureReady -eq $true) {
        $true
    }
    else {
        $null
    }
    $acceleratorExpectation = if ($Provider -eq 'VMware') {
        'VMware hardware acceleration'
    }
    else {
        'QEMU WHPX hardware acceleration'
    }

    [pscustomobject][ordered]@{
        Schema = 'ksword.provider-host-prerequisites.v1'
        Provider = $Provider
        OperatingSystemSupported = $osIsWindows
        CimAvailable = $cimAvailable
        QuerySucceeded = $querySucceeded -and ($requiredWindowsFeatureReady -ne $null)
        HypervisorPresent = $hypervisorPresent
        VirtualizationFirmwareEnabled = $virtualizationFirmwareEnabled
        SecondLevelAddressTranslationSupported = $slatSupported
        VmMonitorModeExtensions = $vmMonitorModeExtensions
        HardwareAccelerationReady = $hardwareReady
        AcceleratorExpectation = $acceleratorExpectation
        RequiredWindowsFeature = $requiredWindowsFeature
        RequiredWindowsFeatureState = $requiredWindowsFeatureState
        RequiredWindowsFeatureReady = $requiredWindowsFeatureReady
        InspectionErrors = @($inspectionErrors.ToArray())
        RecommendedActions = @($actions.ToArray())
        StartsOrMutatesVm = $false
        ChineseGuidance = "中文提示：$Provider 宿主硬件虚拟化检查只读；不会启动、还原、停止或修改 VM。"
    }
}

function Get-InstallVmProfileStatus {
    param([bool]$HyperVModuleAvailable)

    $actions = [System.Collections.Generic.List[string]]::new()
    $profile = [ordered]@{
        VmName = $VmName
        ExpectedBaselineName = $CheckpointName
        ExpectedCheckpointName = $CheckpointName
        Exists = $false
        State = $null
        Generation = $null
        ProcessorCount = $null
        MemoryStartupBytes = $null
        DynamicMemoryEnabled = $null
        GuestServiceInterfaceEnabled = $null
        BaselineExists = $false
        CheckpointExists = $false
        BaselineGuidance = 'Hyper-V checkpoint'
        QueryAttempted = $false
        QuerySucceeded = $false
        AccessDenied = $false
        DiagnosticCode = if ($HyperVModuleAvailable) { 'HYPERV_NOT_QUERIED' } else { 'HYPERV_CMDLET_MISSING' }
        DiagnosticMessage = if ($HyperVModuleAvailable) { 'Hyper-V profile has not been queried.' } else { 'Hyper-V PowerShell management cmdlets were not found.' }
        Error = $null
        RecommendedActions = @()
    }

    if (-not $HyperVModuleAvailable) {
        [void]$actions.Add('下一步：启用/安装 Hyper-V PowerShell 模块后重新运行 .\install.ps1 -Mode CheckEnvironment；该检查不会启动或还原 VM。')
        $profile.RecommendedActions = @($actions.ToArray())
        return [pscustomobject]$profile
    }

    try {
        $profile.QueryAttempted = $true
        $vm = @(Get-VM -ErrorAction Stop) |
            Where-Object { ([string]$_.Name).Equals($VmName, [System.StringComparison]::OrdinalIgnoreCase) } |
            Select-Object -First 1
        $profile.QuerySucceeded = $true
        if ($null -eq $vm) {
            $profile.DiagnosticCode = 'HYPERV_VM_NOT_FOUND'
            $profile.DiagnosticMessage = "Configured Hyper-V VM '$VmName' was not found."
            [void]$actions.Add("下一步：确认 Hyper-V VM '$VmName' 已创建/导入，或运行 .\install.ps1 -Mode Change -UpdateHyperVConfig -VmName <existing VM> -CheckpointName <checkpoint> 记录正确 profile。")
        }
        else {
        $profile.Exists = $true
        $profile.State = [string]$vm.State

        foreach ($propertyName in @('Generation', 'ProcessorCount', 'MemoryStartup', 'DynamicMemoryEnabled')) {
            $property = $vm.PSObject.Properties[$propertyName]
            if ($null -eq $property) {
                continue
            }

            switch ($propertyName) {
                'MemoryStartup' { $profile.MemoryStartupBytes = $property.Value }
                default { $profile[$propertyName] = $property.Value }
            }
        }

        $snapshot = @(Get-VMSnapshot -VMName $VmName -ErrorAction Stop) |
            Where-Object { ([string]$_.Name).Equals($CheckpointName, [System.StringComparison]::OrdinalIgnoreCase) } |
            Select-Object -First 1
        $profile.CheckpointExists = $null -ne $snapshot
        $profile.DiagnosticCode = if ($profile.CheckpointExists) { 'HYPERV_QUERY_OK' } else { 'HYPERV_CHECKPOINT_NOT_FOUND' }
        $profile.DiagnosticMessage = if ($profile.CheckpointExists) { 'Hyper-V VM and configured checkpoint were detected.' } else { "Configured Hyper-V checkpoint '$CheckpointName' was not found." }
        if (-not $profile.CheckpointExists) {
            [void]$actions.Add("下一步：为 VM '$VmName' 创建或选择干净 checkpoint '$CheckpointName'，然后运行 .\install.ps1 -Mode Change -UpdateHyperVConfig -VmName '$VmName' -CheckpointName <checkpoint>。")
        }

        $guestServiceCommand = Get-Command Get-VMIntegrationService -ErrorAction SilentlyContinue
        if ($null -ne $guestServiceCommand) {
            $guestService = Get-VMIntegrationService -VMName $VmName -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -in @('Guest Service Interface', '来宾服务接口') -or $_.Name -match '(?i)Guest\s+Service|来宾服务' } |
                Select-Object -First 1
            if ($null -ne $guestService) {
                $profile.GuestServiceInterfaceEnabled = [bool]$guestService.Enabled
                if (-not $profile.GuestServiceInterfaceEnabled) {
                    [void]$actions.Add("下一步：如需 Live Hyper-V 文件复制/Guest Service Interface，请在管理员 PowerShell 执行 Enable-VMIntegrationService -VMName '$VmName' -Name 'Guest Service Interface'。")
                }
            }
        }
        }
    }
    catch {
        $profile.Error = $_.Exception.Message
        $profile.AccessDenied = Test-InstallProviderAccessDenied -Message $profile.Error
        $profile.DiagnosticCode = if ($profile.AccessDenied) { 'HYPERV_ACCESS_DENIED' } else { 'HYPERV_QUERY_FAILED' }
        $profile.DiagnosticMessage = $profile.Error
        [void]$actions.Add($(if ($profile.AccessDenied) {
            '下一步：使用有权查询 Hyper-V 的账号运行，或把当前账号加入 Hyper-V Administrators 后重新登录，再运行 CheckEnvironment。'
        }
        else {
            "下一步：检查 Hyper-V 管理服务与 VM '$VmName'，然后重新运行 CheckEnvironment。"
        }))
    }

    $profile.BaselineExists = [bool]$profile.CheckpointExists
    $profile.RecommendedActions = @($actions.ToArray())
    return [pscustomobject]$profile
}

function Resolve-InstallExecutablePath {
    param([AllowNull()][string]$ConfiguredPath)

    if ([string]::IsNullOrWhiteSpace($ConfiguredPath)) {
        return $null
    }
    if (Test-Path -LiteralPath $ConfiguredPath -PathType Leaf) {
        return [System.IO.Path]::GetFullPath($ConfiguredPath)
    }

    $command = Get-Command -Name $ConfiguredPath -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $command) {
        return $null
    }
    return [string]$command.Source
}

function Test-InstallProviderAccessDenied {
    param([AllowNull()][string]$Message)

    if ([string]::IsNullOrWhiteSpace($Message)) { return $false }
    return $Message -match '(?i)(access denied|access is denied|permission denied|unauthorized|eacces|0x80070005|拒绝访问|访问被拒绝)'
}

function Invoke-InstallProviderCommand {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [AllowEmptyCollection()][string[]]$ArgumentList = @()
    )

    $savedEnvironment = [ordered]@{}
    $environment = [Environment]::GetEnvironmentVariables('Process')
    foreach ($nameValue in @($environment.Keys)) {
        $name = [string]$nameValue
        if ($name.Equals($SecretName, [System.StringComparison]::OrdinalIgnoreCase) -or
            $name.Equals($VirusTotalSecretName, [System.StringComparison]::OrdinalIgnoreCase) -or
            $name.StartsWith('KSWORDBOX_', [System.StringComparison]::OrdinalIgnoreCase) -or
            $name -match '(?i)(PASSWORD|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIAL)') {
            $savedEnvironment[$name] = [string]$environment[$nameValue]
            [Environment]::SetEnvironmentVariable($name, $null, 'Process')
        }
    }

    try {
        $output = @(& $FilePath @ArgumentList 2>&1)
        $exitCode = $LASTEXITCODE
        return [pscustomobject][ordered]@{
            Output = @($output)
            ExitCode = $exitCode
            SensitiveEnvironmentCleared = $true
        }
    }
    finally {
        foreach ($item in $savedEnvironment.GetEnumerator()) {
            [Environment]::SetEnvironmentVariable([string]$item.Key, [string]$item.Value, 'Process')
        }
    }
}

function Wait-InstallVMwarePowerState {
    param(
        [Parameter(Mandatory)][string]$VmrunPath,
        [Parameter(Mandatory)][string]$VmxPath,
        [Parameter(Mandatory)][bool]$ExpectedRunning,
        [ValidateRange(1, 600)][int]$TimeoutSeconds = 60
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $lastResult = $null
    do {
        $lastResult = Invoke-InstallProviderCommand -FilePath $VmrunPath -ArgumentList @('-T', 'ws', 'list')
        if ($lastResult.ExitCode -eq 0) {
            $running = @($lastResult.Output | ForEach-Object { ([string]$_).Trim() }) -contains $VmxPath
            if ($running -eq $ExpectedRunning) {
                return
            }
        }
        Start-Sleep -Seconds 1
    } while ((Get-Date) -lt $deadline)

    $expectedState = if ($ExpectedRunning) { 'running' } else { 'stopped' }
    $lastExitCode = if ($null -eq $lastResult) { 'not-run' } else { [string]$lastResult.ExitCode }
    $lastOutput = if ($null -eq $lastResult) { '' } else { @($lastResult.Output) -join ' ' }
    throw "VMware VM 未在 $TimeoutSeconds 秒内达到 $expectedState 状态。最后 vmrun list 退出码：$lastExitCode。详情：$lastOutput"
}

function Test-InstallCanBindLoopbackPort {
    param([Parameter(Mandatory)][ValidateRange(1, 65535)][int]$Port)

    $listener = $null
    try {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
        $listener.ExclusiveAddressUse = $true
        $listener.Start()
        return [pscustomobject]@{ CanBind = $true; Error = '' }
    }
    catch {
        $message = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
        return [pscustomobject]@{ CanBind = $false; Error = $message }
    }
    finally {
        if ($null -ne $listener) { $listener.Stop() }
    }
}

function Get-InstallProviderProfileStatus {
    $actions = [System.Collections.Generic.List[string]]::new()
    $effectiveGuestRemotingAddress = $GuestRemotingAddress
    $effectiveGuestRemotingPort = [int]$GuestRemotingPort
    $guestRemotingAddressSource = 'configured'
    $guestRemotingPortAvailable = $null
    $guestAddressModeValid = $VirtualizationProvider -eq 'HyperV' -or
        ($VirtualizationProvider -eq 'VMware' -and $GuestRemotingAddressMode -in @('Configured', 'VMwareTools')) -or
        ($VirtualizationProvider -eq 'Qemu' -and $GuestRemotingAddressMode -in @('Configured', 'QemuUserNat'))
    $guestTransportReady = $VirtualizationProvider -eq 'HyperV'
    if ($VirtualizationProvider -eq 'VMware' -and $GuestRemotingAddressMode -eq 'VMwareTools') {
        $effectiveGuestRemotingAddress = ''
        $guestRemotingAddressSource = 'vmware-tools-auto-discovery'
        $guestTransportReady = $true
    }
    elseif ($VirtualizationProvider -eq 'Qemu' -and $GuestRemotingAddressMode -eq 'QemuUserNat') {
        $effectiveGuestRemotingAddress = '127.0.0.1'
        if ($effectiveGuestRemotingPort -le 0) { $effectiveGuestRemotingPort = if ($GuestRemotingUseSsl) { 55986 } else { 55985 } }
        $guestRemotingAddressSource = 'provider-managed-user-nat'
        $guestTransportReady = $true
    }
    elseif ($VirtualizationProvider -ne 'HyperV') {
        $guestTransportReady = $guestAddressModeValid -and -not [string]::IsNullOrWhiteSpace($effectiveGuestRemotingAddress)
    }
    $guestTransportSecure = $VirtualizationProvider -eq 'HyperV' -or
        (($GuestRemotingAddressMode -eq 'Configured' -or $GuestRemotingUseSsl) -and
         ($GuestRemotingAuthentication -ne 'Basic' -or $GuestRemotingUseSsl) -and
         (-not $GuestRemotingSkipCertificateChecks -or $GuestRemotingUseSsl))
    $profile = [ordered]@{
        Provider = $VirtualizationProvider
        ManagementAvailable = $false
        VmName = $VmName
        ExpectedBaselineName = $CheckpointName
        ExpectedCheckpointName = $CheckpointName
        Exists = $false
        State = $null
        BaselineExists = $false
        CheckpointExists = $false
        BaselineGuidance = if ($VirtualizationProvider -eq 'HyperV') { 'Hyper-V checkpoint' } elseif ($VirtualizationProvider -eq 'VMware') { 'VMware snapshot' } else { 'QEMU per-job overlay or internal snapshot' }
        Generation = $null
        ProcessorCount = $null
        MemoryStartupBytes = $null
        MemoryMegabytes = $null
        Headless = $null
        Accelerator = $null
        AcceleratorSource = $null
        GuestServiceInterfaceEnabled = $null
        GuestTransportReady = $guestTransportReady
        GuestTransportSecure = $guestTransportSecure
        GuestRemotingAddressMode = if ($VirtualizationProvider -eq 'HyperV') { 'PowerShellDirect' } else { $GuestRemotingAddressMode }
        GuestRemotingAddress = $effectiveGuestRemotingAddress
        GuestRemotingAddressSource = if ($VirtualizationProvider -eq 'HyperV') { 'vm-name' } else { $guestRemotingAddressSource }
        GuestRemotingPort = $effectiveGuestRemotingPort
        GuestRemotingPortAvailable = $guestRemotingPortAvailable
        ActiveQemuOwnsGuestRemotingPort = $null
        GuestRemotingUseSsl = if ($VirtualizationProvider -eq 'HyperV') { $null } else { [bool]$GuestRemotingUseSsl }
        GuestRemotingAuthentication = if ($VirtualizationProvider -eq 'HyperV') { 'PowerShellDirect' } else { $GuestRemotingAuthentication }
        GuestRemotingSkipCertificateChecks = if ($VirtualizationProvider -eq 'HyperV') { $null } else { [bool]$GuestRemotingSkipCertificateChecks }
        ConfigurationReady = $true
        QueryAttempted = $false
        QuerySucceeded = $false
        AccessDenied = $false
        DiagnosticCode = "$($VirtualizationProvider.ToUpperInvariant())_NOT_QUERIED"
        DiagnosticMessage = "$VirtualizationProvider profile has not been queried."
        PrimaryToolPath = $null
        SecondaryToolPath = $null
        MachineDefinitionPath = $null
        Error = $null
        RecommendedActions = @()
        StartsOrMutatesVm = $false
    }

    if ($VirtualizationProvider -eq 'HyperV') {
        $available = $null -ne (Get-Command Get-VM -ErrorAction SilentlyContinue)
        $hyperVProfile = Get-InstallVmProfileStatus -HyperVModuleAvailable $available
        $profile.ManagementAvailable = $available
        $profile.Exists = [bool]$hyperVProfile.Exists
        $profile.State = $hyperVProfile.State
        $profile.CheckpointExists = [bool]$hyperVProfile.CheckpointExists
        $profile.BaselineExists = [bool]$hyperVProfile.CheckpointExists
        $profile.Generation = $hyperVProfile.Generation
        $profile.ProcessorCount = $hyperVProfile.ProcessorCount
        $profile.MemoryStartupBytes = $hyperVProfile.MemoryStartupBytes
        $profile.GuestServiceInterfaceEnabled = $hyperVProfile.GuestServiceInterfaceEnabled
        $profile.QueryAttempted = [bool]$hyperVProfile.QueryAttempted
        $profile.QuerySucceeded = [bool]$hyperVProfile.QuerySucceeded
        $profile.AccessDenied = [bool]$hyperVProfile.AccessDenied
        $profile.DiagnosticCode = [string]$hyperVProfile.DiagnosticCode
        $profile.DiagnosticMessage = [string]$hyperVProfile.DiagnosticMessage
        $profile.PrimaryToolPath = 'Get-VM'
        $profile.SecondaryToolPath = 'Get-VMSnapshot'
        $profile.Error = $hyperVProfile.Error
        $profile.RecommendedActions = @($hyperVProfile.RecommendedActions)
        return [pscustomobject]$profile
    }

    if (-not $guestAddressModeValid) {
        $profile.ConfigurationReady = $false
        $profile.Error = "$VirtualizationProvider GuestRemotingAddressMode '$GuestRemotingAddressMode' 无效。"
        [void]$actions.Add('下一步：VMware 使用 Configured/VMwareTools；QEMU 使用 Configured/QemuUserNat。')
    }
    if ($VirtualizationProvider -ne 'HyperV' -and $GuestRemotingAddressMode -ne 'Configured' -and -not $GuestRemotingUseSsl) {
        $profile.ConfigurationReady = $false
        $profile.Error = if ([string]::IsNullOrWhiteSpace([string]$profile.Error)) { 'Automatic guest endpoint modes require WinRM HTTPS.' } else { "$($profile.Error) | Automatic guest endpoint modes require WinRM HTTPS." }
        [void]$actions.Add('下一步：为 VMwareTools/QemuUserNat 启用 GuestRemotingUseSsl；自动 IP/loopback 端点不依赖宿主机全局 TrustedHosts。')
    }

    if ($VirtualizationProvider -eq 'VMware') {
        $profile.Headless = [bool]$VMwareHeadless
        if ($VMwareVmType -ne 'ws') {
            $profile.ConfigurationReady = $false
            $vmwareTypeError = "完整 VMware 适配要求 Workstation Pro 与 vmType=ws；当前值为 '$VMwareVmType'。"
            $profile.Error = if ([string]::IsNullOrWhiteSpace([string]$profile.Error)) { $vmwareTypeError } else { "$($profile.Error) | $vmwareTypeError" }
            [void]$actions.Add('下一步：安装 VMware Workstation Pro，把 vmware.vmType 改为 ws，再重新运行 CheckEnvironment；Player profile 不会调用 vmrun。')
        }
        $vmrun = Resolve-InstallExecutablePath -ConfiguredPath $VMwareVmrunPath
        $profile.PrimaryToolPath = $vmrun
        $profile.MachineDefinitionPath = $VMwareVmxPath
        $profile.ManagementAvailable = -not [string]::IsNullOrWhiteSpace($vmrun)
        $profile.Exists = -not [string]::IsNullOrWhiteSpace($VMwareVmxPath) -and (Test-Path -LiteralPath $VMwareVmxPath -PathType Leaf)
        if (-not $profile.ManagementAvailable) {
            $profile.DiagnosticCode = 'VMWARE_VMRUN_MISSING'
            $profile.DiagnosticMessage = "VMware vmrun was not found: $VMwareVmrunPath"
            [void]$actions.Add("下一步：安装 VMware VIX/vmrun，或用 -VMwareVmrunPath 指向 vmrun.exe：$VMwareVmrunPath。")
        }
        if (-not $profile.Exists) {
            if ($profile.ManagementAvailable) {
                $profile.DiagnosticCode = 'VMWARE_VMX_MISSING'
                $profile.DiagnosticMessage = "Configured VMware VMX was not found: $VMwareVmxPath"
            }
            [void]$actions.Add("下一步：用 -VMwareVmxPath 指向现有隔离分析 VM 的 .vmx：$VMwareVmxPath。")
        }
        if ($profile.ManagementAvailable -and $profile.Exists -and $VMwareVmType -eq 'ws') {
            $profile.QueryAttempted = $true
            try {
                $resolvedVmxPath = (Resolve-Path -LiteralPath $VMwareVmxPath).ProviderPath
                $snapshotResult = Invoke-InstallProviderCommand -FilePath $vmrun -ArgumentList @('-T', $VMwareVmType, 'listSnapshots', $resolvedVmxPath)
                $snapshotOutput = @($snapshotResult.Output)
                $snapshotExitCode = $snapshotResult.ExitCode
                if ($snapshotExitCode -ne 0) {
                    throw "vmrun listSnapshots 失败，退出码 $snapshotExitCode：$($snapshotOutput -join ' ')"
                }
                $profile.CheckpointExists = @($snapshotOutput | ForEach-Object { ([string]$_).Trim() }) -contains $CheckpointName
                $runningResult = Invoke-InstallProviderCommand -FilePath $vmrun -ArgumentList @('-T', $VMwareVmType, 'list')
                $runningOutput = @($runningResult.Output)
                $runningExitCode = $runningResult.ExitCode
                if ($runningExitCode -ne 0) {
                    throw "vmrun list 失败，退出码 $runningExitCode：$($runningOutput -join ' ')"
                }
                $profile.State = if (@($runningOutput | ForEach-Object { ([string]$_).Trim() }) -contains $resolvedVmxPath) { 'Running' } else { 'Stopped' }
                $profile.QuerySucceeded = $true
                $profile.DiagnosticCode = if ($profile.CheckpointExists) { 'VMWARE_QUERY_OK' } else { 'VMWARE_SNAPSHOT_NOT_FOUND' }
                $profile.DiagnosticMessage = if ($profile.CheckpointExists) { 'VMware VMX and configured snapshot were detected.' } else { "Configured VMware snapshot '$CheckpointName' was not found." }
                if (-not $profile.CheckpointExists) {
                    [void]$actions.Add("下一步：在 VMware 中创建 snapshot '$CheckpointName'，或用 -CheckpointName 记录已有干净 snapshot。")
                }
            }
            catch {
                $profile.Error = $_.Exception.Message
                $profile.AccessDenied = Test-InstallProviderAccessDenied -Message $profile.Error
                $profile.DiagnosticCode = if ($profile.AccessDenied) { 'VMWARE_ACCESS_DENIED' } else { 'VMWARE_QUERY_FAILED' }
                $profile.DiagnosticMessage = $profile.Error
                [void]$actions.Add($(if ($profile.AccessDenied) {
                    '下一步：授予当前账号读取 VMX 和调用 VMware Workstation Pro vmrun 的权限，然后重新运行 CheckEnvironment。'
                }
                else {
                    '下一步：确认 vmrun 类型、VMX 路径和 snapshot 后重新运行 CheckEnvironment。'
                }))
            }
        }
    }
    else {
        $profile.MemoryMegabytes = [int]$QemuMemoryMegabytes
        $profile.Headless = [bool]$QemuHeadless
        if ($QemuDiskInterface -notin @('virtio', 'ide', 'scsi')) {
            $profile.ConfigurationReady = $false
            $profile.Error = if ([string]::IsNullOrWhiteSpace([string]$profile.Error)) { "QemuDiskInterface='$QemuDiskInterface' 无效；if=none 不会连接 provider 管理的启动磁盘。" } else { "$($profile.Error) | QemuDiskInterface='$QemuDiskInterface' 无效。" }
            [void]$actions.Add('下一步：把 qemu.diskInterface 改为 virtio、ide 或 scsi；来宾必须包含所选控制器驱动。')
        }
        try {
            $profile.Accelerator = 'whpx'
            $profile.AcceleratorSource = if (Test-QemuWhpxAdditionalArguments -Arguments $QemuAdditionalArguments -GuestAddressMode $GuestRemotingAddressMode) { 'configured' } else { 'core-default' }
        }
        catch {
            $profile.ConfigurationReady = $false
            $profile.Accelerator = 'unsupported'
            $profile.AcceleratorSource = 'invalid-config'
            $profile.Error = if ([string]::IsNullOrWhiteSpace([string]$profile.Error)) { $_.Exception.Message } else { "$($profile.Error) | $($_.Exception.Message)" }
            [void]$actions.Add('下一步：把 QEMU additionalArguments 的 accelerator 改为 ["-accel","whpx"]；TCG 不计作与 Hyper-V 等价的 Live。')
        }
        $qemuSystem = Resolve-InstallExecutablePath -ConfiguredPath $QemuSystemPath
        $qemuImg = Resolve-InstallExecutablePath -ConfiguredPath $QemuImgPath
        $profile.PrimaryToolPath = $qemuSystem
        $profile.SecondaryToolPath = $qemuImg
        $profile.MachineDefinitionPath = $QemuDiskImagePath
        $profile.ManagementAvailable = -not [string]::IsNullOrWhiteSpace($qemuSystem) -and -not [string]::IsNullOrWhiteSpace($qemuImg)
        $profile.Exists = -not [string]::IsNullOrWhiteSpace($QemuDiskImagePath) -and (Test-Path -LiteralPath $QemuDiskImagePath -PathType Leaf)
        $activeQemuPids = @(Get-ConfiguredQemuActivePids)
        $activeQemuProcessAmbiguous = $activeQemuPids.Count -gt 1
        $activeQemuPid = if ($activeQemuPids.Count -eq 1) { [int]$activeQemuPids[0] } else { $null }
        $profile.State = if ($activeQemuProcessAmbiguous) { 'Ambiguous' } elseif ($null -ne $activeQemuPid) { 'Running' } elseif ($profile.Exists) { 'Configured' } else { $null }
        if ([string]::IsNullOrWhiteSpace($qemuSystem)) {
            $profile.DiagnosticCode = 'QEMU_SYSTEM_MISSING'
            $profile.DiagnosticMessage = "QEMU system executable was not found: $QemuSystemPath"
            [void]$actions.Add("下一步：安装 QEMU，或用 -QemuSystemPath 指向 qemu-system executable：$QemuSystemPath。")
        }
        if ([string]::IsNullOrWhiteSpace($qemuImg)) {
            $profile.DiagnosticCode = 'QEMU_IMG_MISSING'
            $profile.DiagnosticMessage = "qemu-img executable was not found: $QemuImgPath"
            [void]$actions.Add("下一步：安装 qemu-img，或用 -QemuImgPath 指向 executable：$QemuImgPath。")
        }
        if (-not $profile.Exists) {
            if ($profile.ManagementAvailable) {
                $profile.DiagnosticCode = 'QEMU_DISK_MISSING'
                $profile.DiagnosticMessage = "Configured QEMU disk image was not found: $QemuDiskImagePath"
            }
            [void]$actions.Add("下一步：用 -QemuDiskImagePath 指向现有隔离分析 VM 的基础磁盘：$QemuDiskImagePath。")
        }
        if ($profile.ManagementAvailable -and $profile.Exists) {
            $profile.QueryAttempted = $true
            try {
                $snapshotResult = Invoke-InstallProviderCommand -FilePath $qemuImg -ArgumentList @('info', '--output=json', $QemuDiskImagePath)
                $snapshotOutput = @($snapshotResult.Output)
                if ($snapshotResult.ExitCode -ne 0) {
                    throw "qemu-img info 失败，退出码 $($snapshotResult.ExitCode)：$($snapshotOutput -join ' ')"
                }
                $snapshotInfo = ($snapshotOutput -join "`n") | ConvertFrom-Json -ErrorAction Stop
                $actualFormat = [string]$snapshotInfo.format
                if (-not $actualFormat.Equals($QemuDiskFormat, [System.StringComparison]::OrdinalIgnoreCase)) {
                    throw "配置磁盘格式 '$QemuDiskFormat' 与 qemu-img 检测格式 '$actualFormat' 不一致。"
                }
                if (-not [bool]$QemuUseOverlayDisk -and -not $actualFormat.Equals('qcow2', [System.StringComparison]::OrdinalIgnoreCase)) {
                    throw "QEMU 内部快照模式仅支持 qcow2；检测到 '$actualFormat'。请启用 per-job overlay。"
                }

                if ([bool]$QemuUseOverlayDisk) {
                    $profile.CheckpointExists = $true
                }
                else {
                    $snapshotProperty = $snapshotInfo.PSObject.Properties['snapshots']
                    $snapshotNames = if ($null -eq $snapshotProperty) {
                        @()
                    }
                    else {
                        @($snapshotProperty.Value | ForEach-Object {
                            $nameProperty = $_.PSObject.Properties['name']
                            if ($null -ne $nameProperty) { [string]$nameProperty.Value }
                        })
                    }
                    $profile.CheckpointExists = $snapshotNames -ccontains $CheckpointName
                    if (-not $profile.CheckpointExists) {
                        [void]$actions.Add("下一步：在 QEMU 镜像中创建内部 snapshot '$CheckpointName'，或启用 -QemuUseOverlayDisk `$true。")
                    }
                }
                $profile.QuerySucceeded = $true
                $profile.DiagnosticCode = if ($profile.CheckpointExists) {
                    if ([bool]$QemuUseOverlayDisk) { 'QEMU_OVERLAY_READY' } else { 'QEMU_QUERY_OK' }
                }
                else { 'QEMU_SNAPSHOT_NOT_FOUND' }
                $profile.DiagnosticMessage = if ($profile.CheckpointExists) {
                    if ([bool]$QemuUseOverlayDisk) { 'QEMU tools and base disk were detected; each job will use a disposable overlay.' } else { 'QEMU disk and configured internal snapshot were detected.' }
                }
                else { "Configured QEMU internal snapshot '$CheckpointName' was not found." }
                if ($activeQemuProcessAmbiguous) {
                    $profile.GuestTransportReady = $false
                    $profile.ActiveQemuOwnsGuestRemotingPort = $false
                    $profile.GuestRemotingPortAvailable = $false
                    $profile.DiagnosticCode = 'QEMU_PROCESS_IDENTITY_AMBIGUOUS'
                    $profile.DiagnosticMessage = "$($activeQemuPids.Count) active KSword QEMU processes match VM '$VmName'. Stop duplicate runs before restoring or starting this provider profile."
                    [void]$actions.Add("下一步：停止 VM '$VmName' 的重复 QEMU 实例，只保留一个由 KSword 原生 qemu.pid 标记的进程后重试。")
                }
                elseif ($GuestRemotingAddressMode -eq 'QemuUserNat') {
                    $profile.ActiveQemuOwnsGuestRemotingPort = $null -ne $activeQemuPid -and
                        (Test-ConfiguredQemuProcessOwnsUserNatPort -ProcessId ([int]$activeQemuPid) -Port $effectiveGuestRemotingPort)
                    if ($null -ne $activeQemuPid -and -not $profile.ActiveQemuOwnsGuestRemotingPort) {
                        $profile.State = 'Configured'
                    }
                    if ($profile.ActiveQemuOwnsGuestRemotingPort) {
                        $profile.GuestRemotingPortAvailable = $true
                    }
                    else {
                        $portProbe = Test-InstallCanBindLoopbackPort -Port $effectiveGuestRemotingPort
                        $profile.GuestRemotingPortAvailable = [bool]$portProbe.CanBind
                    }
                    if (-not $profile.GuestRemotingPortAvailable) {
                        $profile.GuestTransportReady = $false
                        $profile.DiagnosticCode = 'QEMU_USER_NAT_PORT_UNAVAILABLE'
                        $missingBaselineDetail = if ($profile.CheckpointExists) { '' } else { " Configured QEMU internal snapshot '$CheckpointName' was also not found." }
                        $profile.DiagnosticMessage = "QEMU user-NAT WinRM host-forward port $effectiveGuestRemotingPort on 127.0.0.1 is unavailable. Stop the conflicting listener or configure another GuestRemotingPort. $($portProbe.Error)$missingBaselineDetail"
                        [void]$actions.Add("下一步：停止占用 127.0.0.1:$effectiveGuestRemotingPort 的非 KSword 监听器，或用 -GuestRemotingPort 配置其他空闲端口。")
                    }
                }
            }
            catch {
                $profile.Error = if ([string]::IsNullOrWhiteSpace([string]$profile.Error)) { $_.Exception.Message } else { "$($profile.Error) | $($_.Exception.Message)" }
                $profile.CheckpointExists = $false
                $profile.AccessDenied = Test-InstallProviderAccessDenied -Message $_.Exception.Message
                $profile.DiagnosticCode = if ($profile.AccessDenied) { 'QEMU_ACCESS_DENIED' } else { 'QEMU_QUERY_FAILED' }
                $profile.DiagnosticMessage = $_.Exception.Message
                [void]$actions.Add($(if ($profile.AccessDenied) {
                    '下一步：授予当前账号读取 QEMU 基础磁盘并调用 qemu-img 的权限，然后重新运行 CheckEnvironment。'
                }
                else {
                    '下一步：确认 qemu-img、基础磁盘格式和内部 snapshot/overlay 配置后重新运行 CheckEnvironment。'
                }))
            }
        }
    }

    if (-not [bool]$profile.GuestTransportReady -and $profile.GuestRemotingPortAvailable -ne $false) {
        [void]$actions.Add("下一步：为 $VirtualizationProvider 选择有效 GuestRemotingAddressMode；Configured 模式还需填写 GuestRemotingAddress。")
    }
    if ($VirtualizationProvider -ne 'HyperV' -and $GuestRemotingAuthentication -eq 'Basic' -and -not $GuestRemotingUseSsl) {
        $profile.ConfigurationReady = $false
        $profile.Error = if ([string]::IsNullOrWhiteSpace([string]$profile.Error)) { 'Basic WinRM over HTTP is refused.' } else { "$($profile.Error) | Basic WinRM over HTTP is refused." }
        [void]$actions.Add('下一步：为 Basic WinRM 启用 HTTPS，或改用 Negotiate/CredSSP。')
    }
    if ($VirtualizationProvider -ne 'HyperV' -and $GuestRemotingSkipCertificateChecks -and -not $GuestRemotingUseSsl) {
        $profile.ConfigurationReady = $false
        $profile.Error = if ([string]::IsNullOrWhiteSpace([string]$profile.Error)) { 'GuestRemotingSkipCertificateChecks requires HTTPS.' } else { "$($profile.Error) | GuestRemotingSkipCertificateChecks requires HTTPS." }
        [void]$actions.Add('下一步：只在启用 GuestRemotingUseSsl 时使用 SkipCertificateChecks。')
    }
    $profile.BaselineExists = [bool]$profile.CheckpointExists
    $profile.RecommendedActions = @($actions.ToArray())
    return [pscustomobject]$profile
}

function Get-InstallDriverServiceStatusSnapshot {
    param([AllowNull()][string]$ResolvedDriverPath)

    $driverScript = Join-Path $PSScriptRoot 'scripts\Manage-SandboxDriver.ps1'
    $summary = [ordered]@{
        Command = '.\scripts\Manage-SandboxDriver.ps1 -Action Status'
        ScriptExists = Test-Path -LiteralPath $driverScript -PathType Leaf
        Queried = $false
        Success = $null
        ServiceExists = $null
        ServiceState = $null
        MiniFilterLoaded = $null
        TestSigningEnabled = $null
        DriverFileExists = $null
        DriverSignatureStatus = $null
        Error = $null
    }

    if (-not $summary.ScriptExists) {
        $summary.Error = "错误：找不到 driver 状态脚本：$driverScript。下一步：确认 scripts\Manage-SandboxDriver.ps1 存在。"
        return [pscustomobject]$summary
    }

    $arguments = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $driverScript,
        '-Action', 'Status',
        '-JsonDepth', '8'
    )

    if (-not [string]::IsNullOrWhiteSpace($ResolvedDriverPath)) {
        $arguments += @('-DriverPath', $ResolvedDriverPath)
    }

    try {
        $output = @(& powershell @arguments)
        $lines = @($output | ForEach-Object { [string]$_ })
        $startIndex = -1
        $endIndex = -1
        for ($index = 0; $index -lt $lines.Count; $index++) {
            if ($startIndex -lt 0 -and $lines[$index].TrimStart().StartsWith('{', [StringComparison]::Ordinal)) {
                $startIndex = $index
            }
            if ($lines[$index].TrimEnd().EndsWith('}', [StringComparison]::Ordinal)) {
                $endIndex = $index
            }
        }

        if ($startIndex -lt 0 -or $endIndex -lt $startIndex) {
            throw 'driver status JSON was not found in child process output.'
        }

        $parsed = ($lines[$startIndex..$endIndex] -join "`n") | ConvertFrom-Json
        $summary.Queried = $true
        $summary.Success = [bool]$parsed.Success
        $summary.ServiceExists = [bool]$parsed.After.Service.Exists
        $summary.ServiceState = $parsed.After.Service.State
        $summary.MiniFilterLoaded = $parsed.After.MiniFilter.Loaded
        $summary.TestSigningEnabled = $parsed.After.TestSigning.Enabled
        $summary.DriverFileExists = [bool]$parsed.After.DriverFile.Exists
        $summary.DriverSignatureStatus = $parsed.After.DriverFile.Signature.Status
    }
    catch {
        $summary.Error = "错误：driver 状态检查失败。下一步：可直接运行 .\scripts\Manage-SandboxDriver.ps1 -Action Status 查看 JSON 详情。英文详情：$($_.Exception.Message)"
    }

    return [pscustomobject]$summary
}

function Get-InstallRuntimeRootStatus {
    $fullRuntimeRoot = [System.IO.Path]::GetFullPath($RuntimeRoot)
    $repositoryRoot = if ([string]::IsNullOrWhiteSpace($PSScriptRoot)) { (Get-Location).ProviderPath } else { $PSScriptRoot }
    $requiredDirectories = @(
        $fullRuntimeRoot,
        (Join-Path $fullRuntimeRoot 'jobs'),
        (Join-Path $fullRuntimeRoot 'plans'),
        (Join-Path $fullRuntimeRoot 'uploads'),
        (Join-Path $fullRuntimeRoot 'config'),
        ([System.IO.Path]::GetFullPath($GuestPayloadRoot))
    )

    $directoryRows = foreach ($directory in $requiredDirectories) {
        [pscustomobject][ordered]@{
            Path = $directory
            Exists = Test-Path -LiteralPath $directory -PathType Container
        }
    }

    $underRepository = Test-InstallPathUnderRoot -Path $fullRuntimeRoot -Root $repositoryRoot
    $actions = [System.Collections.Generic.List[string]]::new()
    if ($underRepository) {
        [void]$actions.Add("下一步：把 RuntimeRoot 移到仓库外，例如 D:\Temp\KSwordSandbox；运行 .\install.ps1 -Mode Change -UpdateHyperVConfig -RuntimeRoot D:\Temp\KSwordSandbox。")
    }

    foreach ($row in @($directoryRows)) {
        if (-not [bool]$row.Exists) {
            [void]$actions.Add("下一步：运行 .\install.ps1 -InstallEntrypoint CreateOrPreparePath 创建运行目录：$($row.Path)。")
        }
    }

    [pscustomobject][ordered]@{
        RuntimeRoot = $fullRuntimeRoot
        RuntimeRootExists = Test-Path -LiteralPath $fullRuntimeRoot -PathType Container
        RuntimeRootUnderRepository = $underRepository
        GuestPayloadRoot = [System.IO.Path]::GetFullPath($GuestPayloadRoot)
        DirectoryReadiness = @($directoryRows)
        RecommendedActions = @($actions.ToArray())
        ChineseGuidance = '中文提示：运行目录应在仓库外；jobs/uploads/reports/PCAP/dump 不应进入 git 或源码包。'
    }
}

function Test-InstallPayloadManifestFileHash {
    param(
        [Parameter(Mandatory)]$Manifest,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$PayloadRoot,
        [Parameter(Mandatory)][string]$ExpectedPath,
        [AllowEmptyCollection()]
        [Parameter(Mandatory)][System.Collections.Generic.List[string]]$Actions
    )

    $entryPresent = $false
    $sha256Present = $false
    $relativePathMatches = $false
    $hashMatches = $false
    $relativePath = ''
    $expectedSha256 = ''
    $actualSha256 = ''

    if (-not (Test-Path -LiteralPath $ExpectedPath -PathType Leaf)) {
        [void]$Actions.Add("下一步：$Name 文件缺失：$ExpectedPath；重新准备 guest payload。")
        return [pscustomobject][ordered]@{
            Name                = $Name
            EntryPresent        = $entryPresent
            Sha256Present       = $sha256Present
            RelativePath        = $relativePath
            RelativePathMatches = $relativePathMatches
            ExpectedPath        = $ExpectedPath
            ExpectedSha256      = $expectedSha256
            ActualSha256        = $actualSha256
            HashMatches         = $hashMatches
        }
    }

    $requiredHostFiles = @(Get-JsonPropertyValue -InputObject $Manifest -Name 'requiredHostFiles')
    if ($requiredHostFiles.Count -eq 0) {
        [void]$Actions.Add('下一步：payload-manifest.json 缺少 requiredHostFiles 元数据；重新准备 guest payload。')
        return [pscustomobject][ordered]@{
            Name                = $Name
            EntryPresent        = $entryPresent
            Sha256Present       = $sha256Present
            RelativePath        = $relativePath
            RelativePathMatches = $relativePathMatches
            ExpectedPath        = $ExpectedPath
            ExpectedSha256      = $expectedSha256
            ActualSha256        = $actualSha256
            HashMatches         = $hashMatches
        }
    }

    $entry = @($requiredHostFiles | Where-Object {
        $entryName = Get-JsonPropertyValue -InputObject $_ -Name 'name'
        [System.StringComparer]::OrdinalIgnoreCase.Equals([string]$entryName, $Name)
    } | Select-Object -First 1)
    if ($entry.Count -eq 0) {
        [void]$Actions.Add("下一步：payload-manifest.json 缺少 $Name hash 元数据；重新准备 guest payload。")
        return [pscustomobject][ordered]@{
            Name                = $Name
            EntryPresent        = $entryPresent
            Sha256Present       = $sha256Present
            RelativePath        = $relativePath
            RelativePathMatches = $relativePathMatches
            ExpectedPath        = $ExpectedPath
            ExpectedSha256      = $expectedSha256
            ActualSha256        = $actualSha256
            HashMatches         = $hashMatches
        }
    }

    $entryPresent = $true
    $relativePath = [string](Get-JsonPropertyValue -InputObject $entry[0] -Name 'relativePath')
    if (-not [string]::IsNullOrWhiteSpace($relativePath)) {
        $expectedRelativePath = Get-RelativePayloadPath -PayloadRoot $PayloadRoot -Path $ExpectedPath
        $relativePathMatches = [System.StringComparer]::OrdinalIgnoreCase.Equals($relativePath.Replace('\', '/'), $expectedRelativePath)
        if (-not $relativePathMatches) {
            [void]$Actions.Add("下一步：payload-manifest.json 中 $Name relativePath='$relativePath'，预期 '$expectedRelativePath'；重新发布 runtime payload。")
        }
    }
    else {
        # Older manifests may contain only absolute build-machine paths. Do not
        # treat those paths as portable package authority; the explicit
        # ExpectedPath under the current GuestPayloadRoot plus sha256 is enough.
        $relativePathMatches = $true
    }

    $expectedSha256 = [string](Get-JsonPropertyValue -InputObject $entry[0] -Name 'sha256')
    $sha256Present = -not [string]::IsNullOrWhiteSpace($expectedSha256)
    if (-not $sha256Present) {
        [void]$Actions.Add("下一步：payload-manifest.json 缺少 $Name sha256；重新准备 guest payload。")
        return [pscustomobject][ordered]@{
            Name                = $Name
            EntryPresent        = $entryPresent
            Sha256Present       = $sha256Present
            RelativePath        = $relativePath
            RelativePathMatches = $relativePathMatches
            ExpectedPath        = $ExpectedPath
            ExpectedSha256      = $expectedSha256
            ActualSha256        = $actualSha256
            HashMatches         = $hashMatches
        }
    }

    $actualSha256 = Get-FileSha256Hex -Path $ExpectedPath
    $hashMatches = [System.StringComparer]::OrdinalIgnoreCase.Equals($expectedSha256, $actualSha256)
    if (-not $hashMatches) {
        [void]$Actions.Add("下一步：$Name hash 与 payload-manifest.json 不一致；已暂存 payload 可能被部分覆盖，请重新准备 guest payload。")
    }

    return [pscustomobject][ordered]@{
        Name                = $Name
        EntryPresent        = $entryPresent
        Sha256Present       = $sha256Present
        RelativePath        = $relativePath
        RelativePathMatches = $relativePathMatches
        ExpectedPath        = $ExpectedPath
        ExpectedSha256      = $expectedSha256
        ActualSha256        = $actualSha256
        HashMatches         = $hashMatches
    }
}

function Get-InstallGuestPayloadStatus {
    param(
        [Parameter(Mandatory)][string]$AgentPath,
        [Parameter(Mandatory)][string]$CollectorPath,
        [Parameter(Mandatory)][string]$ManifestPath
    )

    $actions = [System.Collections.Generic.List[string]]::new()
    $manifestContractVersion = $null
    $manifestConfiguration = $null
    $sourceFingerprintPresent = $false
    $requiredHostFileNames = @()
    $requiredHostFilesHaveSha256 = $false
    $requiredPayloadFileHashesMatch = $false
    $requiredPayloadFileChecks = @()
    $manifestError = $null
    $manifestReadable = $false

    $agentExists = Test-Path -LiteralPath $AgentPath -PathType Leaf
    $collectorExists = Test-Path -LiteralPath $CollectorPath -PathType Leaf
    $manifestExists = Test-Path -LiteralPath $ManifestPath -PathType Leaf

    if (-not $agentExists) {
        [void]$actions.Add("下一步：Guest Agent payload 缺失，运行 .\scripts\Prepare-GuestPayload.ps1 -RepoRoot . -PayloadRoot '$GuestPayloadRoot' -GuestWorkingDirectory '$GuestWorkingDirectory' -SelfContained。")
    }
    if (-not $collectorExists) {
        [void]$actions.Add("下一步：R0Collector payload 缺失，重新准备 guest payload；如暂不使用 R0，可在本机配置中设置 driver.useMockCollector=true 或 driver.enabled=false。")
    }
    if (-not $manifestExists) {
        [void]$actions.Add("下一步：payload-manifest.json 缺失，重新准备 guest payload：$GuestPayloadRoot。")
    }

    if ($manifestExists) {
        try {
            $manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json -ErrorAction Stop
            $manifestReadable = $true
            $manifestContractVersion = Get-JsonPropertyValue -InputObject $manifest -Name 'payloadContractVersion'
            $manifestConfiguration = Get-JsonPropertyValue -InputObject $manifest -Name 'configuration'
            $sourceFingerprintPresent = -not [string]::IsNullOrWhiteSpace([string](Get-JsonPropertyValue -InputObject $manifest -Name 'sourceFingerprint'))
            $requiredHostFiles = @(Get-JsonPropertyValue -InputObject $manifest -Name 'requiredHostFiles')
            $requiredHostFileNames = @($requiredHostFiles | ForEach-Object { [string](Get-JsonPropertyValue -InputObject $_ -Name 'name') } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            $requiredPayloadFileChecks = @(
                Test-InstallPayloadManifestFileHash -Manifest $manifest -Name 'GuestAgent' -PayloadRoot $GuestPayloadRoot -ExpectedPath $AgentPath -Actions $actions
                Test-InstallPayloadManifestFileHash -Manifest $manifest -Name 'R0Collector' -PayloadRoot $GuestPayloadRoot -ExpectedPath $CollectorPath -Actions $actions
            )
            $requiredHostFilesHaveSha256 = ($requiredPayloadFileChecks.Count -gt 0) -and (@($requiredPayloadFileChecks | Where-Object { -not [bool]$_.Sha256Present }).Count -eq 0)
            $requiredPayloadFileHashesMatch = ($requiredPayloadFileChecks.Count -gt 0) -and (@($requiredPayloadFileChecks | Where-Object { -not [bool]$_.HashMatches }).Count -eq 0)
            if ([int]$manifestContractVersion -lt 2) {
                [void]$actions.Add('下一步：payload-manifest.json contract version 过旧；重新准备 guest payload 以获得 freshness/hash 诊断。')
            }
            if (-not $sourceFingerprintPresent) {
                [void]$actions.Add('下一步：payload manifest 缺少 sourceFingerprint；重新准备 payload，避免 WebUI Live 使用过期二进制。')
            }
        }
        catch {
            $manifestError = $_.Exception.Message
            [void]$actions.Add("下一步：payload-manifest.json 无法解析；删除损坏 payload 目录后重新准备。英文详情：$manifestError")
        }
    }

    $ready = $agentExists -and $collectorExists -and $manifestExists -and $manifestReadable -and $sourceFingerprintPresent -and $requiredHostFilesHaveSha256 -and $requiredPayloadFileHashesMatch
    [pscustomobject][ordered]@{
        PayloadRoot = [System.IO.Path]::GetFullPath($GuestPayloadRoot)
        ReadyForLiveCopy = $ready
        AgentPath = $AgentPath
        AgentExists = $agentExists
        CollectorPath = $CollectorPath
        CollectorExists = $collectorExists
        ManifestPath = $ManifestPath
        ManifestExists = $manifestExists
        ManifestReadable = $manifestReadable
        ManifestContractVersion = $manifestContractVersion
        ManifestConfiguration = $manifestConfiguration
        SourceFingerprintPresent = $sourceFingerprintPresent
        RequiredHostFileNames = @($requiredHostFileNames)
        RequiredHostFilesHaveSha256 = $requiredHostFilesHaveSha256
        RequiredPayloadFileHashesMatch = $requiredPayloadFileHashesMatch
        RequiredPayloadFileChecks = @($requiredPayloadFileChecks)
        ManifestError = $manifestError
        RecommendedActions = @($actions.ToArray())
        ChineseGuidance = '中文提示：payload 状态只检查宿主机文件和 manifest，不复制文件、不启动 VM。'
    }
}

function Get-InstallVirusTotalStatus {
    $processValue = [Environment]::GetEnvironmentVariable($VirusTotalSecretName, 'Process')
    $userValue = [Environment]::GetEnvironmentVariable($VirusTotalSecretName, 'User')
    $machineValue = [Environment]::GetEnvironmentVariable($VirusTotalSecretName, 'Machine')
    $configuredScopes = @()
    if (-not [string]::IsNullOrWhiteSpace($processValue)) { $configuredScopes += 'Process' }
    if (-not [string]::IsNullOrWhiteSpace($userValue)) { $configuredScopes += 'User' }
    if (-not [string]::IsNullOrWhiteSpace($machineValue)) { $configuredScopes += 'Machine' }

    [pscustomobject][ordered]@{
        SecretName = $VirusTotalSecretName
        Configured = $configuredScopes.Count -gt 0
        ConfiguredScopes = @($configuredScopes)
        ProcessSecretSet = -not [string]::IsNullOrWhiteSpace($processValue)
        UserSecretSet = -not [string]::IsNullOrWhiteSpace($userValue)
        MachineSecretSet = -not [string]::IsNullOrWhiteSpace($machineValue)
        HashOnlyEnrichment = $true
        MissingKeyBehavior = 'skip quietly; do not write failed VT lookup noise into job logs'
        FailureLoggingPolicy = 'quiet operator status only; no secret value printed'
        ConfigureCommand = '.\install.ps1 -Mode ConfigureVTKey -PromptVTKey'
        ClearCommand = '.\install.ps1 -Mode ConfigureVTKey -ClearVTKey'
        SecretValuePrinted = $false
        ChineseGuidance = '中文提示：VirusTotal 是可选 hash-only enrichment；未配置或调用失败时应静默跳过，不把 API key 或失败噪声写进分析日志。'
    }
}

function Show-KSwordSandboxInstallStatus {
    $processValue = [Environment]::GetEnvironmentVariable($SecretName, 'Process')
    $userValue = [Environment]::GetEnvironmentVariable($SecretName, 'User')
    $machineValue = [Environment]::GetEnvironmentVariable($SecretName, 'Machine')
    $vtProcessValue = [Environment]::GetEnvironmentVariable($VirusTotalSecretName, 'Process')
    $vtUserValue = [Environment]::GetEnvironmentVariable($VirusTotalSecretName, 'User')
    $vtMachineValue = [Environment]::GetEnvironmentVariable($VirusTotalSecretName, 'Machine')
    $localConfig = Get-LocalSandboxConfigPath
    $hyperVPrerequisites = if ($VirtualizationProvider -eq 'HyperV') {
        Get-InstallHyperVPrerequisiteStatus
    }
    else {
        [pscustomobject][ordered]@{
            OsIsWindows = [System.StringComparer]::OrdinalIgnoreCase.Equals([string]$env:OS, 'Windows_NT')
            PowerShellModuleAvailable = $false
            CimAvailable = $null -ne (Get-Command Get-CimInstance -ErrorAction SilentlyContinue)
            FeatureStates = [pscustomobject]@{}
            HypervisorPresent = $null
            VirtualizationFirmwareEnabled = $null
            SecondLevelAddressTranslationSupported = $null
            VmMonitorModeExtensions = $null
            RecommendedActions = @()
            InspectionErrors = @()
            StartsOrMutatesVm = $false
            ChineseGuidance = "当前选择 $VirtualizationProvider；已跳过 Hyper-V 专属前置检查。"
        }
    }
    $providerHostPrerequisites = Get-InstallProviderHostPrerequisiteStatus `
        -Provider $VirtualizationProvider `
        -HyperVPrerequisites $hyperVPrerequisites
    $runtimeStatus = Get-InstallRuntimeRootStatus
    $virusTotalStatus = Get-InstallVirusTotalStatus
    $hyperVModuleAvailable = [bool]$hyperVPrerequisites.PowerShellModuleAvailable
    $vmExists = $false
    $vmState = $null
    $checkpointExists = $false
    $providerStatusError = $null
    $vmProfile = Get-InstallProviderProfileStatus
    $offlineRecoveryQemuImgPath = if ($VirtualizationProvider -in @('VMware', 'Qemu')) { Resolve-InstallExecutablePath -ConfiguredPath $QemuImgPath } else { $null }
    $offlineRecoveryStorageCmdletsReady = $null -ne (Get-Command Mount-DiskImage -ErrorAction SilentlyContinue) -and $null -ne (Get-Command Dismount-DiskImage -ErrorAction SilentlyContinue)
    $offlineRecoveryElevationReady = Test-IsAdministrator
    $unknownPasswordRecoverySupported = $VirtualizationProvider -ne 'VMware' -or $VMwareVmType -eq 'ws'
    $unknownPasswordRecoveryReady = $unknownPasswordRecoverySupported -and
        $offlineRecoveryElevationReady -and
        [bool]$vmProfile.ManagementAvailable -and
        [bool]$vmProfile.ConfigurationReady -and
        [bool]$vmProfile.QuerySucceeded -and
        [bool]$vmProfile.Exists -and
        [bool]$vmProfile.CheckpointExists -and
        ($VirtualizationProvider -eq 'HyperV' -or (-not [string]::IsNullOrWhiteSpace($offlineRecoveryQemuImgPath) -and $offlineRecoveryStorageCmdletsReady))
    $providerManagementAvailable = [bool]$vmProfile.ManagementAvailable
    $providerQueryAttempted = [bool]$vmProfile.QueryAttempted
    $providerQuerySucceeded = [bool]$vmProfile.QuerySucceeded
    $providerAccessDenied = [bool]$vmProfile.AccessDenied
    $providerDiagnosticCode = [string]$vmProfile.DiagnosticCode
    $providerDiagnosticMessage = [string]$vmProfile.DiagnosticMessage
    $guestTransportReady = [bool]$vmProfile.GuestTransportReady
    $vmExists = [bool]$vmProfile.Exists
    $vmState = $vmProfile.State
    $checkpointExists = [bool]$vmProfile.CheckpointExists
    $providerStatusError = $vmProfile.Error
    $hostTestSigningStatus = Get-HostTestSigningStatus
    $guestAgentPayload = Join-Path (Join-Path $GuestPayloadRoot 'agent') 'KSword.Sandbox.Agent.exe'
    $r0CollectorPayload = Join-Path (Join-Path $GuestPayloadRoot 'r0collector') 'KSword.Sandbox.R0Collector.exe'
    $payloadManifest = Join-Path $GuestPayloadRoot 'payload-manifest.json'
    $payloadStatus = Get-InstallGuestPayloadStatus -AgentPath $guestAgentPayload -CollectorPath $r0CollectorPayload -ManifestPath $payloadManifest
    $driverHost = Resolve-DriverHostPath
    $driverHostExists = -not [string]::IsNullOrWhiteSpace($driverHost) -and (Test-Path -LiteralPath $driverHost -PathType Leaf)
    $driverServiceStatus = Get-InstallDriverServiceStatusSnapshot -ResolvedDriverPath $driverHost
    $driverSignatureStatus = $null
    if ($driverHostExists) {
        try {
            $driverSignatureStatus = [string](Get-AuthenticodeSignature -FilePath $driverHost).Status
        }
        catch {
            $driverSignatureStatus = "Error: $($_.Exception.Message)"
        }
    }

    $recommendedActions = New-Object System.Collections.Generic.List[string]
    foreach ($prereqAction in @($providerHostPrerequisites.RecommendedActions)) {
        [void]$recommendedActions.Add([string]$prereqAction)
    }
    foreach ($runtimeAction in @($runtimeStatus.RecommendedActions)) {
        [void]$recommendedActions.Add([string]$runtimeAction)
    }
    foreach ($payloadAction in @($payloadStatus.RecommendedActions)) {
        [void]$recommendedActions.Add([string]$payloadAction)
    }
    foreach ($profileAction in @($vmProfile.RecommendedActions)) {
        [void]$recommendedActions.Add([string]$profileAction)
    }
    if ($unknownPasswordRecoverySupported -and -not $unknownPasswordRecoveryReady) {
        $offlineRecoveryAction = if ($VirtualizationProvider -eq 'HyperV') {
            '下一步：如需 Hyper-V 无旧密码离线恢复，请以管理员 PowerShell 运行，并确认 Hyper-V 管理工具可用。'
        }
        else {
            "下一步：如需 $VirtualizationProvider 无旧密码离线恢复，请以管理员 PowerShell 运行，确认 qemu-img 可用，并在完整 Windows PowerShell 中提供 Storage 模块的 Mount-DiskImage/Dismount-DiskImage；普通已知凭据 WinRM 轮换不受影响。"
        }
        [void]$recommendedActions.Add($offlineRecoveryAction)
    }
    if (-not (Test-Path -LiteralPath $RuntimeRoot -PathType Container)) {
        [void]$recommendedActions.Add("下一步：普通用户运行 .\install.ps1 并按推荐安装向导，在 '$RuntimeRoot' 下创建运行目录；自动化可使用 CreateOrPreparePath 参数。 / Run guided install to create runtime folders.")
    }
    if (-not (Test-Path -LiteralPath $localConfig -PathType Leaf)) {
        [void]$recommendedActions.Add("下一步：普通用户运行 .\install.ps1 推荐安装向导创建本机配置并记录 provider/VM/baseline；自动化可使用 CreateOrPreparePath 或 -Mode Change -UpdateVirtualizationConfig。")
    }
    if (-not (Test-Path -LiteralPath $GuestPayloadRoot -PathType Container) -or
        -not (Test-Path -LiteralPath $guestAgentPayload -PathType Leaf) -or
        -not (Test-Path -LiteralPath $r0CollectorPayload -PathType Leaf) -or
        -not (Test-Path -LiteralPath $payloadManifest -PathType Leaf)) {
        [void]$recommendedActions.Add("下一步：运行 .\scripts\Prepare-GuestPayload.ps1 -RepoRoot . -PayloadRoot '$GuestPayloadRoot' -GuestWorkingDirectory '$GuestWorkingDirectory' -SelfContained 准备 Guest Agent/R0Collector payload。")
    }
    if ([string]::IsNullOrWhiteSpace($processValue) -and [string]::IsNullOrWhiteSpace($userValue) -and [string]::IsNullOrWhiteSpace($machineValue)) {
        $secretAction = if ($VirtualizationProvider -eq 'HyperV') {
            '下一步：普通用户运行 .\install.ps1 并在推荐安装向导中输入 guest password secret；如果只做本进程检查，可运行 .\scripts\Test-HyperVReadiness.ps1 -PromptForMissingGuestPassword。'
        }
        else {
            "下一步：普通用户运行 .\install.ps1 并在推荐安装向导中输入 guest password secret，然后运行 .\install.ps1 -Mode CheckEnvironment 检查 $VirtualizationProvider profile。"
        }
        [void]$recommendedActions.Add($secretAction)
    }
    if ([string]::IsNullOrWhiteSpace($driverHost)) {
        [void]$recommendedActions.Add("下一步：运行 .\install.ps1 -Mode Change -UpdateVirtualizationConfig -DriverHostPath <path-to-test-signed-KSword.Sandbox.Driver.sys>；仅验证链路时可在本机配置中设置 driver.useMockCollector=true。")
    }
    elseif (-not $driverHostExists) {
        [void]$recommendedActions.Add("下一步：构建 R0 driver，或修正 DriverHostPath：$driverHost。")
    }
    elseif ($driverSignatureStatus -eq 'NotSigned') {
        [void]$recommendedActions.Add("下一步：在隔离 VM 中对已配置 driver 做测试签名，并启用 guest test-signing 后再运行真实 R0 采集：$driverHost。")
    }
    if ($driverServiceStatus.ScriptExists -and $driverServiceStatus.Queried -and $driverHostExists -and -not $driverServiceStatus.ServiceExists) {
        [void]$recommendedActions.Add('下一步：如需在宿主加载 driver/minifilter，请先确认测试签名和管理员权限，再运行 .\scripts\Manage-SandboxDriver.ps1 -Action Install；普通 WebUI/PlanOnly 不需要加载 driver。')
    }
    if (-not $providerManagementAvailable) {
        [void]$recommendedActions.Add("下一步：安装或配置 $VirtualizationProvider 管理工具，然后重新运行 .\install.ps1 -Mode CheckEnvironment。")
    }
    elseif ($providerQuerySucceeded -and -not $vmExists) {
        [void]$recommendedActions.Add("下一步：运行 .\install.ps1 -Mode Change -UpdateVirtualizationConfig -VirtualizationProvider $VirtualizationProvider -VmName <existing VM> -CheckpointName <clean-baseline> 记录现有 VM，或先创建/导入 VM '$VmName'。")
    }
    elseif ($providerQuerySucceeded -and -not $checkpointExists) {
        [void]$recommendedActions.Add("下一步：运行 .\install.ps1 -Mode Change -UpdateVirtualizationConfig -VirtualizationProvider $VirtualizationProvider -VmName '$VmName' -CheckpointName <clean-baseline> 记录干净基线，或先创建 provider 对应的 baseline '$CheckpointName'。")
    }

    $runtimeRootExists = Test-Path -LiteralPath $RuntimeRoot -PathType Container
    $localConfigExists = Test-Path -LiteralPath $localConfig -PathType Leaf
    $guestSecretSet = (-not [string]::IsNullOrWhiteSpace($processValue)) -or
        (-not [string]::IsNullOrWhiteSpace($userValue)) -or
        (-not [string]::IsNullOrWhiteSpace($machineValue))
    $recommendedActionArray = @($recommendedActions.ToArray() | Select-Object -Unique)
    $restoreCleanBaselineRequiresVmMutation = Test-InstallBaselineRestoreRequiresVmMutation -Provider $VirtualizationProvider -UseQemuOverlayDisk ([bool]$QemuUseOverlayDisk)
    $readinessVerdict = New-InstallReadinessVerdict `
        -VirtualizationProvider $VirtualizationProvider `
        -LocalConfigExists $localConfigExists `
        -RuntimeRootExists $runtimeRootExists `
        -RuntimeRootUnderRepository ([bool]$runtimeStatus.RuntimeRootUnderRepository) `
        -GuestPayloadReadyForLiveCopy ([bool]$payloadStatus.ReadyForLiveCopy) `
        -GuestSecretSet $guestSecretSet `
        -GuestTransportReady $guestTransportReady `
        -ProviderManagementAvailable $providerManagementAvailable `
        -ProviderQueryAttempted $providerQueryAttempted `
        -ProviderQuerySucceeded $providerQuerySucceeded `
        -ProviderAccessDenied $providerAccessDenied `
        -ProviderDiagnosticCode $providerDiagnosticCode `
        -ProviderDiagnosticMessage $providerDiagnosticMessage `
        -ProviderHostHardwareReady ([bool]($providerHostPrerequisites.HardwareAccelerationReady -eq $true)) `
        -ProviderConfigurationReady ([bool]$vmProfile.ConfigurationReady) `
        -RestoreCleanBaselineRequiresVmMutation $restoreCleanBaselineRequiresVmMutation `
        -VmExists $vmExists `
        -CheckpointExists $checkpointExists `
        -DriverHostPathConfigured (-not [string]::IsNullOrWhiteSpace($driverHost)) `
        -DriverHostPathExists $driverHostExists `
        -DriverSignatureStatus $driverSignatureStatus `
        -RecommendedActions $recommendedActionArray

    [pscustomobject][ordered]@{
        Kind = 'KSwordSandbox.InstallStatus'
        ContractVersion = 2
        MachineReadable = $true
        VirtualizationProvider = $VirtualizationProvider
        ProviderManagementAvailable = $providerManagementAvailable
        ProviderQueryAttempted = $providerQueryAttempted
        ProviderQuerySucceeded = $providerQuerySucceeded
        ProviderAccessDenied = $providerAccessDenied
        ProviderDiagnosticCode = $providerDiagnosticCode
        ProviderDiagnosticMessage = $providerDiagnosticMessage
        ProviderConfigurationReady = [bool]$vmProfile.ConfigurationReady
        ProviderHostPrerequisiteSchema = 'ksword.provider-host-prerequisites.v1'
        ProviderHostPrerequisites = $providerHostPrerequisites
        ProviderHostHardwareReady = $providerHostPrerequisites.HardwareAccelerationReady
        RequiredWindowsFeature = $providerHostPrerequisites.RequiredWindowsFeature
        RequiredWindowsFeatureState = $providerHostPrerequisites.RequiredWindowsFeatureState
        RequiredWindowsFeatureReady = $providerHostPrerequisites.RequiredWindowsFeatureReady
        GuestTransportReady = $guestTransportReady
        GuestRemotingAddressMode = $vmProfile.GuestRemotingAddressMode
        GuestRemotingAddressSource = $vmProfile.GuestRemotingAddressSource
        GuestRemotingAddress = $vmProfile.GuestRemotingAddress
        GuestRemotingPort = $vmProfile.GuestRemotingPort
        ActualGuestPasswordUnknownOldPasswordRecoverySupported = $unknownPasswordRecoverySupported
        ActualGuestPasswordUnknownOldPasswordRecoveryReady = $unknownPasswordRecoveryReady
        ActualGuestPasswordUnknownOldPasswordRecoveryRequiresElevation = $unknownPasswordRecoverySupported
        ActualGuestPasswordUnknownOldPasswordRecoveryElevationReady = $offlineRecoveryElevationReady
        ActualGuestPasswordUnknownOldPasswordRecoveryToolPath = $offlineRecoveryQemuImgPath
        ActualGuestPasswordUnknownOldPasswordRecoveryStorageCmdletsReady = $offlineRecoveryStorageCmdletsReady
        ActualGuestPasswordUnknownOldPasswordRecoveryLayoutValidation = if ($VirtualizationProvider -eq 'VMware' -and $VMwareVmType -eq 'ws') { 'deferred-to-isolated-full-clone' } elseif ($VirtualizationProvider -eq 'Qemu') { 'qemu-img-source-info-and-snapshot-preflight' } else { 'provider-native' }
        ActualGuestPasswordUnknownOldPasswordRecoveryMode = if ($VirtualizationProvider -eq 'HyperV') { 'offline-vhdx' } elseif ($VirtualizationProvider -eq 'Qemu') { 'offline-vhdx-and-replacement-disk' } elseif ($VMwareVmType -eq 'ws') { 'offline-vhdx-full-clone-replacement-vmx' } else { 'requires-current-winrm-credential' }
        ReadinessVerdictSchema = 'ksword.install.readiness-verdict.v1'
        ReadinessVerdict = $readinessVerdict
        ReadinessOverallStatus = $readinessVerdict.OverallStatus
        InstallStateReady = $readinessVerdict.InstallStateReady
        WebUiReady = $readinessVerdict.WebUiReady
        LiveReady = $readinessVerdict.LiveReady
        StatusMutatesVm = $false
        CheckEnvironmentMutatesVm = $false
        QemuUseOverlayDisk = $VirtualizationProvider -eq 'Qemu' -and [bool]$QemuUseOverlayDisk
        BaselineRestoreRequiresVmMutation = $restoreCleanBaselineRequiresVmMutation
        BaselineRestoreSatisfiedWithoutMutation = -not $restoreCleanBaselineRequiresVmMutation
        BaselineIsolationMode = if ($restoreCleanBaselineRequiresVmMutation) { 'provider-snapshot-restore' } else { 'qemu-per-job-overlay' }
        VmMutationPolicy = [pscustomobject][ordered]@{
            Schema = 'ksword.install.vm-mutation-policy.v1'
            StatusMutatesVm = $false
            CheckEnvironmentMutatesVm = $false
            UseConfiguredEnvironmentMutatesVm = $false
            RestoreCleanBaselineMayMutateVm = $restoreCleanBaselineRequiresVmMutation
            RestoreCleanCheckpointMayMutateVm = $restoreCleanBaselineRequiresVmMutation
            RestoreBaselineRequiresAllowVmMutation = $restoreCleanBaselineRequiresVmMutation
            RestoreCheckpointRequiresAllowVmMutation = $restoreCleanBaselineRequiresVmMutation
            RestoreBaselineRequiresExplicitConfirmOrForce = $restoreCleanBaselineRequiresVmMutation
            RestoreCheckpointRequiresExplicitConfirmOrForce = $restoreCleanBaselineRequiresVmMutation
            BaselineRestoreSatisfiedWithoutMutation = -not $restoreCleanBaselineRequiresVmMutation
            BaselineIsolationMode = if ($restoreCleanBaselineRequiresVmMutation) { 'provider-snapshot-restore' } else { 'qemu-per-job-overlay' }
            CreateOrPreparePathCreatesVm = $false
            CreateOrPreparePathCreatesBaseline = $false
            CreateOrPreparePathCreatesCheckpoint = $false
            CreateOrPreparePathMutatesVm = $false
            MachineReadable = $true
        }
        SecretName = $SecretName
        ProcessSecretSet = -not [string]::IsNullOrWhiteSpace($processValue)
        UserSecretSet = -not [string]::IsNullOrWhiteSpace($userValue)
        MachineSecretSet = -not [string]::IsNullOrWhiteSpace($machineValue)
        GuestSecretSet = $guestSecretSet
        VirusTotalSecretName = $VirusTotalSecretName
        VirusTotalProcessSecretSet = -not [string]::IsNullOrWhiteSpace($vtProcessValue)
        VirusTotalUserSecretSet = -not [string]::IsNullOrWhiteSpace($vtUserValue)
        VirusTotalMachineSecretSet = -not [string]::IsNullOrWhiteSpace($vtMachineValue)
        VirusTotalStatus = $virusTotalStatus
        VirusTotalConfigured = [bool]$virusTotalStatus.Configured
        VirusTotalMissingKeyBehavior = $virusTotalStatus.MissingKeyBehavior
        GuestUserName = $GuestUserName
        RuntimeRoot = [System.IO.Path]::GetFullPath($RuntimeRoot)
        LiveExecutionLeasePath = [System.IO.Path]::GetFullPath((Join-Path $RuntimeRoot 'locks\live-execution.lock'))
        LiveExecutionLeaseCrossProcess = $true
        LiveExecutionLeaseScope = 'web-cli-installer-provider-maintenance'
        LiveExecutionLeaseFilePresenceMeansHeld = $false
        RuntimeRootExists = $runtimeRootExists
        RuntimeRootStatus = $runtimeStatus
        RuntimeRootUnderRepository = [bool]$runtimeStatus.RuntimeRootUnderRepository
        GuestPayloadRoot = [System.IO.Path]::GetFullPath($GuestPayloadRoot)
        GuestPayloadRootExists = Test-Path -LiteralPath $GuestPayloadRoot -PathType Container
        GuestPayloadStatus = $payloadStatus
        GuestPayloadReadyForLiveCopy = [bool]$payloadStatus.ReadyForLiveCopy
        GuestAgentPayload = $guestAgentPayload
        GuestAgentPayloadExists = Test-Path -LiteralPath $guestAgentPayload -PathType Leaf
        R0CollectorPayload = $r0CollectorPayload
        R0CollectorPayloadExists = Test-Path -LiteralPath $r0CollectorPayload -PathType Leaf
        GuestPayloadManifest = $payloadManifest
        GuestPayloadManifestExists = Test-Path -LiteralPath $payloadManifest -PathType Leaf
        DriverHostPath = $driverHost
        DriverHostPathExists = $driverHostExists
        DriverSignatureStatus = $driverSignatureStatus
        DriverServiceStatusCommand = $driverServiceStatus.Command
        DriverServiceStatus = $driverServiceStatus
        DriverServiceExists = $driverServiceStatus.ServiceExists
        DriverServiceState = $driverServiceStatus.ServiceState
        DriverMiniFilterLoaded = $driverServiceStatus.MiniFilterLoaded
        DriverServiceTestSigningEnabled = $driverServiceStatus.TestSigningEnabled
        VmName = $VmName
        BaselineName = $CheckpointName
        CheckpointName = $CheckpointName
        GuestWorkingDirectory = $GuestWorkingDirectory
        HyperVModuleAvailable = $hyperVModuleAvailable
        HyperVPrerequisites = $hyperVPrerequisites
        HyperVFeatureStates = $hyperVPrerequisites.FeatureStates
        HyperVVirtualizationFirmwareEnabled = $hyperVPrerequisites.VirtualizationFirmwareEnabled
        HyperVSecondLevelAddressTranslationSupported = $hyperVPrerequisites.SecondLevelAddressTranslationSupported
        IsAdministrator = Test-IsAdministrator
        VmExists = $vmExists
        VmState = $vmState
        BaselineExists = $checkpointExists
        CheckpointExists = $checkpointExists
        ProviderStatusError = $providerStatusError
        HyperVStatusError = if ($VirtualizationProvider -eq 'HyperV') { $providerStatusError } else { $null }
        VmProfile = $vmProfile
        ProviderProfile = $vmProfile
        VmProfileHealthy = ([bool]$vmProfile.ConfigurationReady -and $providerQuerySucceeded -and $guestTransportReady -and $vmExists -and $checkpointExists)
        VmGeneration = $vmProfile.Generation
        VmProcessorCount = $vmProfile.ProcessorCount
        VmMemoryStartupBytes = $vmProfile.MemoryStartupBytes
        VmMemoryMegabytes = $vmProfile.MemoryMegabytes
        VmHeadless = $vmProfile.Headless
        VmAccelerator = $vmProfile.Accelerator
        VmAcceleratorSource = $vmProfile.AcceleratorSource
        VmGuestServiceInterfaceEnabled = $vmProfile.GuestServiceInterfaceEnabled
        HostTestSigningState = $hostTestSigningStatus.State
        HostTestSigningMessage = $hostTestSigningStatus.Message
        LocalConfigPath = $localConfig
        LocalConfigExists = $localConfigExists
        WebConfigPathProcess = [Environment]::GetEnvironmentVariable($script:WebConfigPathEnvironmentName, 'Process')
        WebConfigPathUser = [Environment]::GetEnvironmentVariable($script:WebConfigPathEnvironmentName, 'User')
        InstallStatePath = $script:InstallStatePath
        InstallStateExists = Test-Path -LiteralPath $script:InstallStatePath -PathType Leaf
        DpapiBackupPath = $script:SecretBackupPath
        DpapiBackupExists = Test-Path -LiteralPath $script:SecretBackupPath -PathType Leaf
        PayloadGuidance = ".\scripts\Prepare-GuestPayload.ps1 -RepoRoot . -PayloadRoot '$GuestPayloadRoot' -GuestWorkingDirectory '$GuestWorkingDirectory' -SelfContained"
        VmGuidance = ".\install.ps1 -Mode Change -UpdateVirtualizationConfig -VirtualizationProvider $VirtualizationProvider -VmName <existing VM> -CheckpointName <clean-baseline>"
        BaselineGuidance = ".\install.ps1 -Mode Change -UpdateVirtualizationConfig -VirtualizationProvider $VirtualizationProvider -VmName '$VmName' -CheckpointName <clean-baseline>"
        CheckpointGuidance = ".\install.ps1 -Mode Change -UpdateVirtualizationConfig -VirtualizationProvider $VirtualizationProvider -VmName '$VmName' -CheckpointName <clean-baseline>"
        DriverHostPathGuidance = '.\install.ps1 -Mode Change -UpdateVirtualizationConfig -DriverHostPath <test-signed .sys>'
        GuestTestSigningGuidance = '.\install.ps1 -Mode Change -QueryGuestTestSigning; .\install.ps1 -Mode Change -EnableGuestTestSigning -RestartGuestAfterTestSigning -Force'
        InstallEntrypoint = $InstallEntrypoint
        InstallEntrypointChoices = @('UseConfiguredEnvironment', 'RestoreCleanCheckpoint', 'CreateOrPreparePath')
        OperatorModeMatrix = @(Get-InstallOperatorModeMatrix)
        OperatorModeMatrixSchema = 'ksword.install.operator-mode-matrix.v1'
        OperatorModeGuidanceZh = if ($restoreCleanBaselineRequiresVmMutation) { '中文提示：三种操作者模式互斥选择：使用已配置环境只诊断；恢复干净基线按 provider 映射为 Hyper-V checkpoint、VMware snapshot 或 QEMU internal snapshot，真实变更必须显式确认；全新准备只写本机目录/config/secret/payload。' } else { '中文提示：当前 QEMU per-job overlay 已提供干净启动语义，恢复入口无需原地 VM 变更；使用已配置环境只诊断，全新准备只写本机目录/config/secret/payload。' }
        UseConfiguredEnvironmentCommand = '.\install.ps1 -InstallEntrypoint UseConfiguredEnvironment -PlanOnly'
        RestoreBaselinePlanCommand = '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -PlanOnly'
        RestoreCheckpointPlanCommand = '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -PlanOnly'
        RestoreBaselineWhatIfCommand = if ($restoreCleanBaselineRequiresVmMutation) { '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -AllowVmMutation -WhatIf' } else { '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -WhatIf' }
        RestoreBaselineCommand = if ($restoreCleanBaselineRequiresVmMutation) { '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -AllowVmMutation -Confirm' } else { '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint' }
        RestoreCheckpointWhatIfCommand = if ($restoreCleanBaselineRequiresVmMutation) { '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -AllowVmMutation -WhatIf' } else { '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -WhatIf' }
        RestoreCheckpointCommand = if ($restoreCleanBaselineRequiresVmMutation) { '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -AllowVmMutation -Confirm' } else { '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint' }
        RestoreCheckpointUnattendedCommand = if ($restoreCleanBaselineRequiresVmMutation) { '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -AllowVmMutation -Force' } else { $null }
        CreateOrPreparePathCommand = '.\install.ps1 -InstallEntrypoint CreateOrPreparePath'
        CreateOrPrepareWhatIfCommand = '.\install.ps1 -InstallEntrypoint CreateOrPreparePath -WhatIf'
        CreateOrPrepareConfirmCommand = '.\install.ps1 -InstallEntrypoint CreateOrPreparePath -Confirm'
        InstallEntrypointGuidance = if ($restoreCleanBaselineRequiresVmMutation) { 'Choose exactly one install entrypoint: use the configured environment, restore the selected provider clean baseline, or prepare local folders/config/payload. A mutating restore requires RestoreCleanCheckpoint + AllowVmMutation + ShouldProcess.' } else { 'Choose exactly one install entrypoint: use the configured environment, confirm QEMU per-job-overlay clean-start semantics without mutation, or prepare local folders/config/payload.' }
        HostTestSigningGuidance = 'Host test-signing is a host boot setting for isolated lab hosts that load test-signed kernel drivers; use the Change menu guidance before enabling it and reboot after changes.'
        TestSigningGuidance = 'Guest test-signing is managed from the Change menu; host test-signing is guidance-only here and is needed only when the host itself loads a test-signed driver.'
        ReadinessGuidance = '.\install.ps1 -Mode CheckEnvironment'
        ChineseGuidance = '中文提示：Status/CheckEnvironment 不打印密码值，不启动/还原 VM；安装入口可显式选择 UseConfiguredEnvironment、RestoreCleanCheckpoint 或 CreateOrPreparePath；RecommendedActions 给出下一步修复命令。'
        RecommendedActions = $recommendedActionArray
        SecretValuePrinted = $false
    }
}

function Test-CommandAvailable {
    param([Parameter(Mandatory)][string]$Name)
    return $null -ne (Get-Command -Name $Name -ErrorAction SilentlyContinue)
}

function Show-KSwordSandboxEnvironmentCheck {
    $runScript = Join-Path $PSScriptRoot 'run.ps1'
    $hyperVReadinessScript = Join-Path $PSScriptRoot 'scripts\Test-HyperVReadiness.ps1'
    $webProject = Join-Path $PSScriptRoot 'src\KSword.Sandbox.Web\KSword.Sandbox.Web.csproj'
    $installStatus = Show-KSwordSandboxInstallStatus
    $offlineRecoveryQemuImgPath = $installStatus.ActualGuestPasswordUnknownOldPasswordRecoveryToolPath
    $offlineRecoveryStorageCmdletsReady = [bool]$installStatus.ActualGuestPasswordUnknownOldPasswordRecoveryStorageCmdletsReady
    $offlineRecoveryElevationReady = [bool]$installStatus.ActualGuestPasswordUnknownOldPasswordRecoveryElevationReady
    $unknownPasswordRecoverySupported = [bool]$installStatus.ActualGuestPasswordUnknownOldPasswordRecoverySupported
    $unknownPasswordRecoveryReady = [bool]$installStatus.ActualGuestPasswordUnknownOldPasswordRecoveryReady

    [pscustomobject][ordered]@{
        Kind = 'KSwordSandbox.InstallEnvironmentCheck'
        ContractVersion = 2
        MachineReadable = $true
        VirtualizationProvider = $VirtualizationProvider
        ReadinessVerdictSchema = $installStatus.ReadinessVerdictSchema
        ReadinessVerdict = $installStatus.ReadinessVerdict
        ReadinessOverallStatus = $installStatus.ReadinessOverallStatus
        InstallStateReady = $installStatus.InstallStateReady
        WebUiReady = $installStatus.WebUiReady
        LiveReady = $installStatus.LiveReady
        ProviderManagementAvailable = $installStatus.ProviderManagementAvailable
        ProviderQueryAttempted = $installStatus.ProviderQueryAttempted
        ProviderQuerySucceeded = $installStatus.ProviderQuerySucceeded
        ProviderAccessDenied = $installStatus.ProviderAccessDenied
        ProviderDiagnosticCode = $installStatus.ProviderDiagnosticCode
        ProviderDiagnosticMessage = $installStatus.ProviderDiagnosticMessage
        VmMutationPolicy = $installStatus.VmMutationPolicy
        QemuUseOverlayDisk = $installStatus.QemuUseOverlayDisk
        BaselineRestoreRequiresVmMutation = $installStatus.BaselineRestoreRequiresVmMutation
        BaselineRestoreSatisfiedWithoutMutation = $installStatus.BaselineRestoreSatisfiedWithoutMutation
        BaselineIsolationMode = $installStatus.BaselineIsolationMode
        StartupCommand = '.\run.ps1'
        InstallCommand = '.\install.ps1'
        UseConfiguredEnvironmentCommand = '.\install.ps1 -InstallEntrypoint UseConfiguredEnvironment -PlanOnly'
        RestoreBaselinePlanCommand = $installStatus.RestoreBaselinePlanCommand
        RestoreBaselineWhatIfCommand = $installStatus.RestoreBaselineWhatIfCommand
        RestoreBaselineCommand = $installStatus.RestoreBaselineCommand
        RestoreCheckpointPlanCommand = $installStatus.RestoreCheckpointPlanCommand
        RestoreCheckpointWhatIfCommand = $installStatus.RestoreCheckpointWhatIfCommand
        RestoreCheckpointCommand = $installStatus.RestoreCheckpointCommand
        RestoreCheckpointUnattendedCommand = $installStatus.RestoreCheckpointUnattendedCommand
        CreateOrPreparePathCommand = '.\install.ps1 -InstallEntrypoint CreateOrPreparePath'
        CreateOrPrepareWhatIfCommand = '.\install.ps1 -InstallEntrypoint CreateOrPreparePath -WhatIf'
        CreateOrPrepareConfirmCommand = '.\install.ps1 -InstallEntrypoint CreateOrPreparePath -Confirm'
        ConfigureVirtualizationCommand = '.\install.ps1 -Mode Change -UpdateVirtualizationConfig -VirtualizationProvider <HyperV|VMware|Qemu> -VmName <VM> -CheckpointName <CleanBaseline>'
        ConfigureHyperVCommand = '.\install.ps1 -Mode Change -UpdateHyperVConfig -VmName <VM> -CheckpointName <Checkpoint>'
        ConfigureGuestPasswordCommand = '.\install.ps1'
        ResetGuestPasswordCommand = '.\install.ps1 -Mode Change -ResetGuestVmPassword -PromptPassword -Force'
        ActualGuestPasswordResetSupported = $VirtualizationProvider -ne 'VMware' -or $VMwareVmType -eq 'ws'
        ActualGuestPasswordResetMode = switch ($VirtualizationProvider) {
            'HyperV' { 'offline-vhdx-and-checkpoint-refresh' }
            'Qemu' { 'winrm-or-offline-vhdx-and-replacement-baseline' }
            default { if ($VMwareVmType -eq 'ws') { 'winrm-or-offline-vhdx-full-clone-replacement-vmx' } else { 'unsupported-player-migrate-to-workstation-pro' } }
        }
        ActualGuestPasswordResetGuidance = if ($VirtualizationProvider -eq 'HyperV') { 'Offline VHDX reset is available.' } elseif ($VirtualizationProvider -eq 'Qemu') { 'Known credentials use WinRM rotation; an unknown password uses detached VHDX injection and a replacement QEMU disk. Both preserve the old baseline and commit local config/secret metadata only after new-credential verification.' } elseif ($VMwareVmType -eq 'ws') { 'Known credentials use WinRM rotation; unknown-password recovery creates a Workstation Pro full clone from the clean snapshot, injects only the clone disk, validates it, and commits the replacement VMX/snapshot without modifying the source VM.' } else { 'VMware Player is not a supported parity profile. Migrate to Workstation Pro and set vmware.vmType=ws before password maintenance.' }
        ActualGuestPasswordUnknownOldPasswordRecoverySupported = $unknownPasswordRecoverySupported
        ActualGuestPasswordUnknownOldPasswordRecoveryReady = $unknownPasswordRecoveryReady
        ActualGuestPasswordUnknownOldPasswordRecoveryRequiresElevation = $unknownPasswordRecoverySupported
        ActualGuestPasswordUnknownOldPasswordRecoveryElevationReady = $offlineRecoveryElevationReady
        ActualGuestPasswordUnknownOldPasswordRecoveryToolPath = $offlineRecoveryQemuImgPath
        ActualGuestPasswordUnknownOldPasswordRecoveryStorageCmdletsReady = $offlineRecoveryStorageCmdletsReady
        ActualGuestPasswordUnknownOldPasswordRecoveryLayoutValidation = $installStatus.ActualGuestPasswordUnknownOldPasswordRecoveryLayoutValidation
        ActualGuestPasswordUnknownOldPasswordRecoveryMode = if ($VirtualizationProvider -eq 'HyperV') { 'offline-vhdx' } elseif ($VirtualizationProvider -eq 'Qemu') { 'offline-vhdx-and-replacement-disk' } elseif ($VMwareVmType -eq 'ws') { 'offline-vhdx-full-clone-replacement-vmx' } else { 'requires-current-winrm-credential' }
        ActualGuestPasswordUnknownOldPasswordRecoveryGuidance = if ($VirtualizationProvider -eq 'HyperV') { 'The offline VHDX workflow does not require the old guest password.' } elseif ($VirtualizationProvider -eq 'Qemu') { 'Use -ResetGuestVmPassword -RecoverGuestVmPasswordWithoutCurrentSecret; the clean baseline is materialized as a detached VHDX, injected offline, converted to a replacement disk, booted, and verified before config/secret commit.' } elseif ($VMwareVmType -eq 'ws') { 'Use -ResetGuestVmPassword -RecoverGuestVmPasswordWithoutCurrentSecret with Workstation Pro and qemu-img; vmrun creates a full clone from the clean snapshot, only the clone VMDK is injected, and the replacement VMX is committed after credential verification.' } else { 'VMware Player is not a supported parity profile. Install Workstation Pro, set vmware.vmType=ws, and rerun readiness before password rotation.' }
        ConfigureVTKeyCommand = '.\install.ps1 -Mode ConfigureVTKey -PromptVTKey'
        CheckEnvironmentCommand = '.\install.ps1 -Mode CheckEnvironment'
        ReadinessCommand = '.\install.ps1 -Mode CheckEnvironment'
        ProviderReadinessCommand = '.\run.ps1 -Mode CheckEnvironment'
        ProviderReadinessEntrypoint = '.\run.ps1'
        PlanOnlyCommand = '.\run.ps1 -Mode Plan -SamplePath <sample.exe>'
        AnalyzeNotepadCommand = '.\run.ps1 -Mode Analyze -SamplePreset Notepad'
        AnalyzeHarmlessSampleCommand = '.\run.ps1 -Mode Analyze -SamplePreset HarmlessSample'
        ConfigureDriverHostPathCommand = '.\install.ps1 -Mode Change -UpdateVirtualizationConfig -DriverHostPath <test-signed .sys>'
        GuestTestSigningQueryCommand = '.\install.ps1 -Mode Change -QueryGuestTestSigning'
        GuestTestSigningEnableCommand = '.\install.ps1 -Mode Change -EnableGuestTestSigning -RestartGuestAfterTestSigning -Force'
        TestSigningGuidanceCommand = '.\install.ps1 -Mode Change -ShowTestSigningGuidance'
        WebUiUrl = $WebUiUrl
        RunScriptExists = Test-Path -LiteralPath $runScript -PathType Leaf
        ReadinessScriptExists = Test-Path -LiteralPath $runScript -PathType Leaf
        ProviderReadinessEntrypointExists = Test-Path -LiteralPath $runScript -PathType Leaf
        HyperVReadinessScript = '.\scripts\Test-HyperVReadiness.ps1'
        HyperVReadinessScriptExists = Test-Path -LiteralPath $hyperVReadinessScript -PathType Leaf
        WebProjectExists = Test-Path -LiteralPath $webProject -PathType Leaf
        DotNetAvailable = Test-CommandAvailable -Name 'dotnet'
        PowerShellAvailable = Test-CommandAvailable -Name 'powershell'
        HyperVGetVmAvailable = Test-CommandAvailable -Name 'Get-VM'
        HyperVGetVmSnapshotAvailable = Test-CommandAvailable -Name 'Get-VMSnapshot'
        WhatIfSupported = $true
        DefaultStartsVm = $false
        DefaultMutatesVm = $false
        StartWebUiStartsVm = $false
        StartWebUiMutatesVm = $false
        CheckEnvironmentStartsVm = $false
        CheckEnvironmentMutatesVm = $false
        PlanOnlyStartsVm = $false
        PlanOnlyMutatesVm = $false
        InstallEntrypointChoices = @('UseConfiguredEnvironment', 'RestoreCleanCheckpoint', 'CreateOrPreparePath')
        OperatorModeMatrix = @(Get-InstallOperatorModeMatrix)
        InstallEntrypointVmMutationRequiresAllowVmMutation = $true
        RestoreBaselineRequiresExplicitConfirmOrForce = $true
        RestoreCheckpointRequiresExplicitConfirmOrForce = $true
        ReadinessPackageExecutesInstallerModes = $false
        LiveVmExecutionRequiresExplicitLive = $true
        SecretValuePrinted = $false
        ChineseGuidance = '中文提示：先用本命令查看缺口；普通用户直接运行 .\install.ps1 推荐安装向导配置 provider/VM/干净基线/guest 密码/driver path；高级用户仍可显式选择 UseConfiguredEnvironment、RestoreCleanCheckpoint 或 CreateOrPreparePath。'
        InstallStatus = $installStatus
    }
}

function Invoke-KSwordSandboxEnvironmentCheck {
    Write-InstallDiagnosticObject -InputObject (Show-KSwordSandboxEnvironmentCheck)

    if ($RunHyperVReadiness) {
        $readinessScript = Join-Path $PSScriptRoot 'scripts\Test-HyperVReadiness.ps1'
        if (-not (Test-Path -LiteralPath $readinessScript -PathType Leaf)) {
            throw "错误：找不到 Hyper-V readiness 脚本：$readinessScript。下一步：请确认 scripts\Test-HyperVReadiness.ps1 存在，并从仓库根目录运行。"
        }

        if (-not $PSCmdlet.ShouldProcess($readinessScript, 'Run read-only Hyper-V readiness preflight')) {
            Write-InstallInfo "预览：会运行只读 Hyper-V readiness 预检：$readinessScript。 / WhatIf: readiness preflight would run."
            return
        }

        Write-InstallInfo '正在运行只读 Hyper-V readiness 预检；它不得还原/启动/停止 VM。 / Running read-only readiness preflight.'
        & powershell -NoProfile -ExecutionPolicy Bypass -File $readinessScript
        if ($LASTEXITCODE -ne 0) {
            throw "错误：Hyper-V readiness 预检失败，退出码 $LASTEXITCODE。下一步：查看上方 RecommendedActions，先修复第一个失败项后重试。"
        }
    }
}

function Invoke-KSwordSandboxWebUi {
    $runScript = Join-Path $PSScriptRoot 'run.ps1'
    if (-not (Test-Path -LiteralPath $runScript -PathType Leaf)) {
        throw "错误：找不到 run.ps1：$runScript。下一步：请从完整仓库/发行包根目录运行，确认 run.ps1 存在。"
    }

    if (-not $PSCmdlet.ShouldProcess($WebUiUrl, 'Start KSwordSandbox WebUI without starting or restoring a VM')) {
        Write-InstallInfo "预览：会通过 '$runScript -Mode WebUI -Url $WebUiUrl' 启动 WebUI；此包装器不会启动 VM。 / WhatIf: WebUI would start, no VM."
        return
    }

    $arguments = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $runScript,
        '-Mode', 'WebUI',
        '-Url', $WebUiUrl
    )

    if ($OpenBrowser) {
        $arguments += '-OpenBrowser'
    }

    Write-InstallInfo "正在通过 run.ps1 启动 WebUI：$WebUiUrl；此包装器不会启动或还原 VM。 / Starting WebUI through run.ps1."
    & powershell @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "错误：run.ps1 启动 WebUI 失败，退出码 $LASTEXITCODE。下一步：确认已安装 .NET SDK、端口未被占用，然后运行 .\run.ps1 -Mode CheckEnvironment。"
    }
}

function Get-HostTestSigningStatus {
    $rawOutput = @()
    $state = 'Unavailable'
    $message = ''

    if ($null -eq (Get-Command bcdedit.exe -ErrorAction SilentlyContinue)) {
        return [pscustomobject][ordered]@{
            State = $state
            Message = 'bcdedit.exe is not available on this host.'
            RawOutput = @()
        }
    }

    try {
        $rawOutput = @(& bcdedit.exe /enum '{current}' 2>&1)
        $joined = $rawOutput -join "`n"
        if ($joined -match '(?im)^\s*testsigning\s+(Yes|On|True)\s*$') {
            $state = 'Enabled'
        }
        elseif ($joined -match '(?im)^\s*testsigning\s+(No|Off|False)\s*$') {
            $state = 'Disabled'
        }
        else {
            $state = 'Disabled'
            $message = 'testsigning entry was not present in bcdedit output; treating as disabled.'
        }
    }
    catch {
        $state = 'Unknown'
        $message = $_.Exception.Message
    }

    [pscustomobject][ordered]@{
        State = $state
        Message = $message
        RawOutput = @($rawOutput)
    }
}

function Show-TestSigningGuidance {
    $hostStatus = Get-HostTestSigningStatus
    Write-Host ''
    Write-Host 'host/guest test-signing 指引 / host and guest test-signing guidance:'
    Write-Host "  Host test-signing state: $($hostStatus.State)"
    if (-not [string]::IsNullOrWhiteSpace([string]$hostStatus.Message)) {
        Write-Host "  Host query note: $($hostStatus.Message)"
    }
    Write-Host '  1) Host test-signing 是宿主 Windows boot 设置；只在隔离 lab 宿主需要加载测试签名 kernel driver 时启用，变更后需要重启宿主。'
    Write-Host '  2) Guest test-signing 是黄金 VM 内部 Windows boot 设置；真实 R0 分析通常需要在 guest 中启用，变更后需要重启 guest。'
    Write-Host '  3) test-signing 只允许加载测试签名 driver，不会替你签名 driver；测试签名请使用普通 Windows SDK signtool.exe helper，或改用 mock/disabled R0。'
    Write-Host '  4) 普通发布路径：安装/更改只记录 driver path 和指导 test-signing，不在无人值守流程中运行会弹窗的旧签名工具。'

    [pscustomobject][ordered]@{
        HostTestSigningState = $hostStatus.State
        HostTestSigningGuidance = 'Enable host Windows test mode only on an isolated lab host that must load a test-signed kernel driver; reboot after changing it and disable it after validation.'
        GuestTestSigningGuidance = 'Use the Change menu to query or enable guest test-signing for the configured golden VM; enable/disable changes are explicit and require confirmation or -Force.'
        DriverSigningGuidance = 'Use scripts\Sign-SandboxDriverWithTestCertificate.ps1, which uses ordinary signtool.exe when available or clearly skips signing when signtool.exe is absent.'
        ChangesDriverFile = $false
        ChangesHostBootEntry = $false
        ChangesGuestBootEntry = $false
    } | Format-List
}

function Uninstall-KSwordSandboxLocal {
    if (-not $Force -and $Mode -eq 'Interactive') {
        Write-Host ''
        Write-Host "中文提示：这会移除本机 credential 元数据 '$SecretName'；不会删除 '$RuntimeRoot' 下的运行 job 输出。 / This removes local credential metadata only."
        $choice = Read-MenuChoice -Prompt '继续卸载？[y/n] / Continue uninstall? [y/n]' -Allowed @('y', 'Y', 'n', 'N')
        if ($choice -in @('n', 'N')) {
            Write-InstallInfo '已取消卸载。 / Uninstall cancelled.'
            return
        }
    }

    if (-not $PSCmdlet.ShouldProcess($script:InstallStateDirectory, "Uninstall local KSwordSandbox settings and clear '$SecretName' from process/User environment")) {
        Write-InstallInfo "预览：会移除本机安装器元数据和 '$SecretName' 的 Process/User 环境项。 / WhatIf: local installer metadata and secret env entries would be removed."
        Write-InstallInfo '运行输出目录会保留不删除。 / Runtime output folders would be left intact.'
        return
    }

    [Environment]::SetEnvironmentVariable($SecretName, $null, 'Process')
    [Environment]::SetEnvironmentVariable($SecretName, $null, 'User')
    Remove-Item -LiteralPath $script:SecretBackupPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $script:InstallStatePath -Force -ErrorAction SilentlyContinue
    Write-InstallInfo "已移除当前 Process/User 环境 secret '$SecretName'，并删除本机 DPAPI 备份（如存在）。 / Removed local secret metadata."
    Write-InstallInfo '运行输出目录已保留不删除。 / Runtime output folders were left intact.'
}

function Invoke-GuestTestSigningMode {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Enable', 'Disable', 'Query')]
        [string]$TestSigningMode,

        [bool]$RestartAfterChange = $false
    )

    if ($VirtualizationProvider -eq 'VMware' -and $VMwareVmType -ne 'ws') {
        throw '错误：VMware guest test-signing 管理要求 Workstation Pro 与 vmType=ws。请先迁移 Player profile 并重新运行 CheckEnvironment。'
    }

    $testSigningScript = Join-Path $PSScriptRoot 'scripts\Set-GuestTestSigning.ps1'
    if (-not (Test-Path -LiteralPath $testSigningScript -PathType Leaf)) {
        throw "错误：找不到 guest test-signing 脚本：$testSigningScript。下一步：请确认 scripts\Set-GuestTestSigning.ps1 存在。"
    }

    $testSigningTarget = if ($VirtualizationProvider -eq 'HyperV') { $VmName } elseif ($GuestRemotingAddressMode -eq 'Configured') { $GuestRemotingAddress } else { "${VirtualizationProvider}::${GuestRemotingAddressMode}::${VmName}" }

    if ($WhatIfPreference) {
        [void]$PSCmdlet.ShouldProcess($testSigningTarget, "Run guest test-signing '$TestSigningMode'")
        Write-InstallInfo "预览：guest test-signing '$TestSigningMode' 会委托给 '$testSigningScript'；当前不会执行来宾命令或重启。 / WhatIf: guest test-signing would be delegated."
        return
    }

    if ($TestSigningMode -ne 'Query' -and -not $Force -and $Mode -ne 'Interactive') {
        throw '错误：非交互修改 guest test-signing 需要 -Force。下一步：确认这是隔离实验 VM 后，加 -Force 重试；只查询状态可用 -QueryGuestTestSigning。'
    }

    if ($TestSigningMode -ne 'Query' -and $Mode -eq 'Interactive') {
        Write-Host ''
        Write-Host "中文提示：将在 '$VmName' 来宾系统内运行 bcdedit /set testsigning $($TestSigningMode.ToLowerInvariant())。 / This will change guest test-signing state."
        Write-Host '中文提示：test signing 是 VM 内部开关，仅用于隔离实验环境中的测试签名驱动；不会签名驱动文件。'
        if ($RestartAfterChange) {
            Write-Host '如果状态变化，来宾系统可能会重启。 / The guest may reboot if the state changes.'
        }

        $continue = Read-MenuChoice -Prompt 'Continue guest test-signing change? [y/n] / 继续修改来宾 test signing？[y/n]' -Allowed @('y', 'Y', 'n', 'N')
        if ($continue -in @('n', 'N')) {
            Write-InstallInfo '已取消 guest test-signing 修改。 / Guest test-signing change cancelled.'
            return
        }
    }

    $arguments = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $testSigningScript,
        '-VirtualizationProvider', $VirtualizationProvider,
        '-VmName', $VmName,
        '-GuestUserName', $GuestUserName,
        '-SecretName', $SecretName,
        '-Mode', $TestSigningMode
    )

    if ($VirtualizationProvider -ne 'HyperV') {
        $arguments += @(
            '-GuestRemotingAddressMode', $GuestRemotingAddressMode,
            '-GuestRemotingPort', ([string]$GuestRemotingPort),
            '-GuestRemotingAuthentication', $GuestRemotingAuthentication,
            '-GuestReadyTimeoutSeconds', ([string]$PowerShellDirectTimeoutSeconds)
        )
        if (-not [string]::IsNullOrWhiteSpace($GuestRemotingAddress)) {
            $arguments += @('-GuestRemotingAddress', $GuestRemotingAddress)
        }
        if ($VirtualizationProvider -eq 'VMware') {
            $arguments += @(
                '-VMwareVmxPath', $VMwareVmxPath,
                '-VMwareVmrunPath', $VMwareVmrunPath,
                '-VMwareVmType', $VMwareVmType
            )
        }
        else {
            $arguments += @(
                '-QemuSystemPath', $QemuSystemPath,
                '-QemuDiskImagePath', $QemuDiskImagePath,
                '-RuntimeRoot', $RuntimeRoot
            )
            if (-not [bool]$QemuUseOverlayDisk) {
                $arguments += '-QemuInternalSnapshot'
            }
        }
        if ($GuestRemotingUseSsl) {
            $arguments += '-GuestRemotingUseSsl'
        }
        if ($GuestRemotingSkipCertificateChecks) {
            $arguments += '-GuestRemotingSkipCertificateChecks'
        }
    }

    if ($RestartAfterChange) {
        $arguments += '-RestartGuest'
    }

    if ($Force -or $Mode -eq 'Interactive') {
        $arguments += '-Force'
    }

    if (-not $PSCmdlet.ShouldProcess($testSigningTarget, "Run guest test-signing '$TestSigningMode'")) {
        Write-InstallInfo "guest test-signing '$TestSigningMode' 已通过 ShouldProcess/Confirm 拒绝。 / Guest test-signing declined."
        return
    }

    $liveExecutionLease = Enter-InstallLiveExecutionLease -Operation "$VirtualizationProvider guest test-signing $TestSigningMode"
    try {
        Write-InstallInfo "正在通过 $VirtualizationProvider 对来宾 '$testSigningTarget' 执行 guest test-signing '$TestSigningMode'。 / Running guest test-signing."
        & powershell @arguments
        if ($LASTEXITCODE -ne 0) {
            throw "错误：$VirtualizationProvider guest test-signing '$TestSigningMode' 失败，退出码 $LASTEXITCODE。下一步：Hyper-V 确认宿主提权；VMware/QEMU 确认来宾账号是管理员；并检查来宾传输和 guest password secret。"
        }
    }
    finally {
        Exit-InstallLiveExecutionLease -Lease $liveExecutionLease
    }
}

function Invoke-GuestTestSigningMenu {
    while ($true) {
        Write-Host ''
        Write-Host 'host/guest test-signing 选项 / Host and guest test-signing options:'
        Write-Host '  1) 查询当前 guest test-signing 状态 / Query current guest test-signing state'
        Write-Host '  2) 启用 guest test-signing / Enable guest test-signing'
        Write-Host '  3) 启用 guest test-signing，并在状态变化时重启来宾 / Enable and reboot if changed'
        Write-Host '  4) 禁用 guest test-signing / Disable guest test-signing'
        Write-Host '  5) 查看 host/guest test-signing 指引 / Show host/guest test-signing guidance'
        Write-Host '  6) 返回 / Back'
        $choice = Read-MenuChoice -Prompt '请选择 [1-6] / Choose [1-6]' -Allowed @('1', '2', '3', '4', '5', '6')
        switch ($choice) {
            '1' { Invoke-GuestTestSigningMode -TestSigningMode Query }
            '2' { Invoke-GuestTestSigningMode -TestSigningMode Enable }
            '3' { Invoke-GuestTestSigningMode -TestSigningMode Enable -RestartAfterChange $true }
            '4' { Invoke-GuestTestSigningMode -TestSigningMode Disable }
            '5' { Show-TestSigningGuidance }
            '6' { return }
        }
    }
}

function Invoke-GuestPasswordMenu {
    while ($true) {
        Write-Host ''
        Write-Host '来宾密码选项 / Guest password options:'
        Write-Host '  1) 仅重置宿主机保存的 password secret / Reset host-side password secret only'
        $actualResetLabel = if ($VirtualizationProvider -eq 'HyperV') { '离线重置并刷新 checkpoint / offline reset' } elseif ($VirtualizationProvider -eq 'Qemu') { 'WinRM 轮换或无旧密码离线 VHDX recovery / WinRM or offline recovery' } elseif ($VMwareVmType -eq 'ws') { 'VMware WinRM 或 full-clone 离线 recovery / WinRM or offline recovery' } else { '需先迁移到 Workstation Pro / migrate to Workstation Pro first' }
        Write-Host "  2) 重置 VM 内实际密码（$actualResetLabel） / Reset actual VM guest password"
        $providerOfflineRecoveryAvailable = $VirtualizationProvider -eq 'Qemu' -or ($VirtualizationProvider -eq 'VMware' -and $VMwareVmType -eq 'ws')
        if ($providerOfflineRecoveryAvailable) {
            $offlineTarget = if ($VirtualizationProvider -eq 'VMware') { 'full clone replacement VMX' } else { 'replacement disk' }
            Write-Host "  3) 不知道旧密码：离线 VHDX recovery 并创建 $offlineTarget / Unknown old password: offline recovery"
            Write-Host '  4) 返回 / Back'
            $allowedChoices = @('1', '2', '3', '4')
        }
        else {
            Write-Host '  3) 返回 / Back'
            $allowedChoices = @('1', '2', '3')
        }
        $choice = Read-MenuChoice -Prompt "请选择 [$($allowedChoices -join '/')] / Choose [$($allowedChoices -join '/')]" -Allowed $allowedChoices
        switch ($choice) {
            '1' { Reset-GuestPasswordSecret }
            '2' { Invoke-GuestVmPasswordReset -OfflineRecovery $false }
            '3' {
                if ($providerOfflineRecoveryAvailable) {
                    Invoke-GuestVmPasswordReset -OfflineRecovery $true
                }
                else {
                    return
                }
            }
            '4' { return }
        }
    }
}

function Invoke-ChangeMenu {
    while ($true) {
        Write-Host ''
        Write-Host '更改选项 / Change options:'
        Write-Host '  1) 重置宿主机 guest password secret / Reset password secret'
        $actualResetLabel = if ($VirtualizationProvider -eq 'HyperV') { '自动离线重置 / automated offline reset' } elseif ($VirtualizationProvider -eq 'Qemu') { 'WinRM 或离线 VHDX/新 baseline / WinRM or offline recovery' } elseif ($VMwareVmType -eq 'ws') { 'WinRM 或 full-clone 离线 recovery / WinRM or offline recovery' } else { '需先迁移到 Workstation Pro / migrate to Workstation Pro first' }
        Write-Host "  2) 重置 VM 中实际来宾密码（$actualResetLabel） / Reset actual VM guest password"
        Write-Host '  3) 配置虚拟化后端、VM、干净快照和来宾路径 / Change provider/VM/snapshot/guest paths'
        Write-Host '  4) 更改记录的来宾用户名 / Change recorded guest username'
        Write-Host '  5) 重建运行目录和本机配置 / Recreate runtime folders and local config'
        Write-Host '  6) 查看当前虚拟化后端 readiness/status / Show provider readiness/status'
        Write-Host '  7) 管理 host/guest test-signing 指引 / Manage host/guest test-signing guidance'
        Write-Host '  8) 配置可选 VirusTotal API key / Configure optional VT key'
        Write-Host '  9) 检查本机环境 / Check local environment'
        Write-Host '  10) 返回 / Back'
        $choice = Read-MenuChoice -Prompt '请选择 [1-10] / Choose [1-10]' -Allowed @('1', '2', '3', '4', '5', '6', '7', '8', '9', '10')
        switch ($choice) {
            '1' { Reset-GuestPasswordSecret }
            '2' { Invoke-GuestPasswordMenu }
            '3' { Invoke-VirtualizationConfigPrompt }
            '4' {
                $name = Read-Host '来宾用户名 / Guest username'
                Set-GuestUserNameState -NewGuestUserName $name
            }
            '5' { Set-VirtualizationConfigState -Action 'runtime-folders-and-config-refreshed' }
            '6' { Show-KSwordSandboxInstallStatus | Format-List }
            '7' { Invoke-GuestTestSigningMenu }
            '8' { Invoke-VirusTotalKeyConfiguration }
            '9' { Invoke-KSwordSandboxEnvironmentCheck }
            '10' { return }
        }
    }
}

function Invoke-InteractiveInstaller {
    while ($true) {
        Write-Host ''
        Write-Host 'KSwordSandbox local installer / 本地安装向导'
        Write-Host '  0) Recommended setup wizard / 推荐安装向导'
        Write-Host '  1) Install / prepare local settings / 安装/准备本机设置'
        Write-Host '  2) Change settings / 更改设置'
        Write-Host '  3) Uninstall local settings / 卸载本机设置'
        Write-Host '  4) Reset Guest password/secret / 重置来宾密码/secret'
        Write-Host '  5) Configure virtualization / 配置 Hyper-V、VMware 或 QEMU'
        Write-Host '  6) Configure VT key / 配置可选 VirusTotal key'
        Write-Host '  7) Check environment / 检查环境'
        Write-Host '  8) Start WebUI / 启动 WebUI'
        Write-Host '  9) Status / 状态'
        Write-Host '  10) Advanced install entrypoint selector / 高级安装入口选择'
        Write-Host '  11) Exit / 退出'
        $choice = Read-MenuChoice -Prompt '请选择 [0-11] / Choose [0-11]' -Allowed @('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11')
        switch ($choice) {
            '0' { Invoke-GuidedFirstRunSetup }
            '1' {
                Write-Host ''
                Write-Host '安装时密码处理 / Install password handling:'
                Write-Host '  1) 现在设置/重置 guest password secret / Set or reset password now'
                Write-Host '  2) 仅准备目录和本机配置 / Prepare folders only'
                $installChoice = Read-MenuChoice -Prompt '请选择 [1-2] / Choose [1-2]' -Allowed @('1', '2')
                Install-KSwordSandboxLocal -SetPassword:($installChoice -eq '1')
            }
            '2' { Invoke-ChangeMenu }
            '3' { Uninstall-KSwordSandboxLocal }
            '4' { Invoke-GuestPasswordMenu }
            '5' { Invoke-VirtualizationConfigPrompt }
            '6' { Invoke-VirusTotalKeyConfiguration }
            '7' { Invoke-KSwordSandboxEnvironmentCheck }
            '8' { Invoke-KSwordSandboxWebUi }
            '9' { Show-KSwordSandboxInstallStatus | Format-List }
            '10' { Invoke-InstallEntrypointMenu }
            '11' { return }
        }
    }
}

$script:InitialInstallState = Read-InstallState
Initialize-EffectiveParameters -State $script:InitialInstallState -BoundParameters $PSBoundParameters
Initialize-PackagedPayloadDefault -State $script:InitialInstallState -BoundParameters $PSBoundParameters

if ($script:InitialRootBoundParameters.Count -eq 0 -and $Mode -eq 'Interactive') {
    Invoke-GuidedFirstRunSetup
    return
}

if ($PSBoundParameters.ContainsKey('InstallEntrypoint')) {
    Invoke-InstallEntrypoint -SelectedEntrypoint $InstallEntrypoint
    return
}

if ($PrepareGuestPayload) {
    if (-not $Json) {
        Write-InstallInfo '中文提示：-PrepareGuestPayload 属于 CreateOrPreparePath 安装入口；将按创建/准备路径模式执行。 / PrepareGuestPayload routes through CreateOrPreparePath.'
    }
    Invoke-InstallEntrypoint -SelectedEntrypoint 'CreateOrPreparePath'
    return
}

if ($RecoverGuestVmPasswordWithoutCurrentSecret -and -not $ResetGuestVmPassword) {
    throw '错误：-RecoverGuestVmPasswordWithoutCurrentSecret 必须与 -ResetGuestVmPassword 一起使用。'
}
if ($RunHyperVReadiness -and $VirtualizationProvider -ne 'HyperV') {
    throw "错误：-RunHyperVReadiness 是 Hyper-V 专项深度检查，当前 provider 为 '$VirtualizationProvider'。VMware/QEMU 请使用 .\run.ps1 -Mode CheckEnvironment -Provider $VirtualizationProvider，或 .\install.ps1 -Mode CheckEnvironment。"
}

if ($PlanOnly -and $Mode -eq 'Interactive') {
    Invoke-UseConfiguredEnvironmentEntrypoint
    return
}

$hasRootChangeAction = [bool]$StartWebUI -or
    [bool]$CheckEnvironment -or
    [bool]$RunHyperVReadiness -or
    [bool]$ConfigureVTKey -or
    [bool]$PromptVTKey -or
    [bool]$ClearVTKey -or
    [bool]$ResetGuestVmPassword -or
    [bool]$ShowTestSigningGuidance -or
    [bool]$EnableGuestTestSigning -or
    [bool]$DisableGuestTestSigning -or
    [bool]$QueryGuestTestSigning -or
    [bool]$UpdateHyperVConfig -or
    [bool]$UpdateVirtualizationConfig -or
    [bool]$ResetPassword -or
    [bool]$GeneratePassword -or
    [bool]$PromptPassword

if ($PlanOnly -and $Mode -eq 'Change' -and -not $hasRootChangeAction) {
    Invoke-UseConfiguredEnvironmentEntrypoint
    return
}

switch ($Mode) {
    'Interactive' {
        Invoke-InteractiveInstaller
    }
    'Install' {
        $shouldSetPassword = [bool]$GeneratePassword -or [bool]$PromptPassword -or [bool]$ResetPassword
        Install-KSwordSandboxLocal -SetPassword:$shouldSetPassword
    }
    'Change' {
        if ($StartWebUI) {
            Invoke-KSwordSandboxWebUi
        }
        elseif ($CheckEnvironment -or $RunHyperVReadiness) {
            Invoke-KSwordSandboxEnvironmentCheck
        }
        elseif ($ConfigureVTKey -or $PromptVTKey -or $ClearVTKey) {
            Invoke-VirusTotalKeyConfiguration
        }
        elseif ($ResetGuestVmPassword) {
            Invoke-GuestVmPasswordReset -OfflineRecovery ([bool]$RecoverGuestVmPasswordWithoutCurrentSecret)
        }
        elseif ($ShowTestSigningGuidance) {
            Show-TestSigningGuidance
        }
        elseif ($EnableGuestTestSigning) {
            Invoke-GuestTestSigningMode -TestSigningMode Enable -RestartAfterChange ([bool]$RestartGuestAfterTestSigning)
        }
        elseif ($DisableGuestTestSigning) {
            Invoke-GuestTestSigningMode -TestSigningMode Disable -RestartAfterChange ([bool]$RestartGuestAfterTestSigning)
        }
        elseif ($QueryGuestTestSigning) {
            Invoke-GuestTestSigningMode -TestSigningMode Query
        }
        elseif ($UpdateHyperVConfig -or $UpdateVirtualizationConfig) {
            if ($UpdateHyperVConfig -and -not $script:InitialRootBoundParameters.ContainsKey('VirtualizationProvider')) {
                $script:VirtualizationProvider = 'HyperV'
            }
            Set-VirtualizationConfigState
        }
        elseif ($ResetPassword -or $GeneratePassword -or $PromptPassword) {
            Reset-GuestPasswordSecret
        }
        else {
            Invoke-ChangeMenu
        }
    }
    'Uninstall' {
        Uninstall-KSwordSandboxLocal
    }
    'Status' {
        Write-InstallDiagnosticObject -InputObject (Show-KSwordSandboxInstallStatus)
    }
    'CheckEnvironment' {
        Invoke-KSwordSandboxEnvironmentCheck
    }
    'ConfigureVTKey' {
        Invoke-VirusTotalKeyConfiguration
    }
    'StartWebUI' {
        Invoke-KSwordSandboxWebUi
    }
}
