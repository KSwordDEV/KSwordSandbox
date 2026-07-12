<#
.SYNOPSIS
Installs, changes, or uninstalls local KSwordSandbox operator settings.

.DESCRIPTION
The installer is intentionally local-only. It prepares runtime folders and
stores the guest credential secret outside git so Hyper-V live scripts can read
KSWORDBOX_GUEST_PASSWORD without embedding passwords in config files.
It can also record the optional VirusTotal API key in the current user's
environment so the WebUI can perform hash-only lookups without committing a key.

Default mode is interactive:

  .\install.ps1

Automation examples:

  .\install.ps1 -InstallEntrypoint CreateOrPreparePath -GeneratePassword
  .\install.ps1 -Mode Change -ResetPassword -PromptPassword
  .\install.ps1 -Mode Change -UpdateHyperVConfig -VmName KSwordSandbox-Win10-Golden -CheckpointName Clean
  .\install.ps1 -Mode Change -UpdateHyperVConfig -DriverHostPath D:\Temp\KSwordSandbox\build\r0-driver\Release\KSword.Sandbox.Driver.sys
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

    [string]$VmName = 'KSwordSandbox-Win10-Golden',

    [string]$CheckpointName = 'Clean',

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

    [switch]$UpdateHyperVConfig,

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

function Read-InstallState {
    if (-not (Test-Path -LiteralPath $script:InstallStatePath -PathType Leaf)) {
        return $null
    }

    try {
        return Get-Content -LiteralPath $script:InstallStatePath -Raw | ConvertFrom-Json
    }
    catch {
        if (-not $Json) {
            Write-InstallInfo "中文提示：无法读取安装状态文件 '$script:InstallStatePath'，将忽略它并继续。下一步：如状态异常，请重新运行 .\install.ps1 -InstallEntrypoint CreateOrPreparePath -PromptPassword。英文详情：$($_.Exception.Message)"
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
        VmName = 'vmName'
        CheckpointName = 'checkpointName'
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
        throw '错误：非交互安装/更改在设置或重置密码时需要 -GeneratePassword 或 -PromptPassword。下一步：普通用户请运行 .\install.ps1 -InstallEntrypoint CreateOrPreparePath -PromptPassword，或明确使用 -GeneratePassword。'
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

function Write-LocalSandboxConfig {
    $targetPath = Get-LocalSandboxConfigPath
    $templatePath = Join-Path $PSScriptRoot 'config\sandbox.example.json'
    if (-not (Test-Path -LiteralPath $templatePath -PathType Leaf)) {
        throw "错误：找不到 sandbox 配置模板：$templatePath。下一步：请确认在仓库根目录运行，或重新获取缺失的 config\sandbox.example.json。"
    }

    $config = Get-Content -LiteralPath $templatePath -Raw | ConvertFrom-Json
    $config.hyperV.goldenVmName = $VmName
    $config.hyperV.goldenSnapshotName = $CheckpointName
    $config.guest.userName = $GuestUserName
    $config.guest.passwordSecretName = $SecretName
    $config.guest.workingDirectory = $GuestWorkingDirectory
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
        installStateVersion = 2
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

function Set-HyperVConfigState {
    param([string]$Action = 'hyperv-config-updated')

    if ([string]::IsNullOrWhiteSpace($VmName)) {
        throw '错误：Hyper-V VM 名称不能为空。下一步：请用 -VmName <existing VM> 指定现有黄金 VM。'
    }
    if ([string]::IsNullOrWhiteSpace($CheckpointName)) {
        throw '错误：Hyper-V checkpoint 名称不能为空。下一步：请用 -CheckpointName <checkpoint> 指定干净快照。'
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

    Write-InstallInfo "已记录 Hyper-V 配置：VM='$VmName'，checkpoint='$CheckpointName'，guestRoot='$GuestWorkingDirectory'。 / Hyper-V VM config recorded."
    Write-InstallInfo "Web/API 可通过 '$script:WebConfigPathEnvironmentName=$configPath' 使用该配置。 / Web/API config path ready."
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
            [void]$steps.Add("下一步：先运行 .\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -PlanOnly 或 -WhatIf 检查 VM='$VmName' 和 checkpoint='$CheckpointName'。")
            [void]$steps.Add('下一步：确认是隔离实验 VM 后，才在管理员 PowerShell 中加 -AllowVmMutation，并让 ShouldProcess/-Confirm 或 -Force 决定是否真实还原。')
            [void]$steps.Add('下一步：-Force 只是无人值守确认路径；仍必须与 -AllowVmMutation 同时出现，且仍经过 ShouldProcess 保护。')
        }
        'CreateOrPreparePath' {
            [void]$steps.Add("下一步：首台机器先运行 .\install.ps1 -InstallEntrypoint CreateOrPreparePath -PlanOnly 查看计划，再运行 -WhatIf 预览；两者都不会写文件、提示 secret、构建 payload 或修改 VM。输出路径：$RuntimeRoot。")
            [void]$steps.Add('下一步：确认计划后，运行 .\install.ps1 -InstallEntrypoint CreateOrPreparePath -PromptPassword 创建/刷新仓库外运行目录、sandbox.local.json、secret 和 install-state；仍不会创建 Hyper-V VM。')
            [void]$steps.Add("下一步：如果还没有黄金 VM，请先在 Hyper-V 中创建/导入 VM 和干净 checkpoint，然后运行 .\install.ps1 -Mode Change -UpdateHyperVConfig -VmName <existing VM> -CheckpointName <checkpoint>。")
            [void]$steps.Add('下一步：需要 self-contained Guest Agent/R0Collector payload 时，显式加 -PrepareGuestPayload；PlanOnly/WhatIf 只显示将要执行的准备动作，目标必须是仓库外 GuestPayloadRoot/runtime root。')
        }
    }

    return @($steps.ToArray())
}

function Get-InstallOperatorModeMatrix {
    $configuredCommand = '.\install.ps1 -InstallEntrypoint UseConfiguredEnvironment -PlanOnly'
    $restorePlanCommand = '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -PlanOnly'
    $restoreWhatIfCommand = '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -AllowVmMutation -WhatIf'
    $restoreCommand = '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -AllowVmMutation -Confirm'
    $createCommand = '.\install.ps1 -InstallEntrypoint CreateOrPreparePath -PromptPassword'

    return @(
        [pscustomobject][ordered]@{
            ModeId = 'use-configured-environment'
            Entrypoint = 'UseConfiguredEnvironment'
            TitleZh = '使用已配置环境'
            TitleEn = 'Use already configured environment'
            IntentZh = '读取已有 install-state、sandbox.local.json、guest secret、VM/checkpoint profile 和 payload 状态。'
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
                '下一步：如果缺本机配置、secret、payload、VM 或 checkpoint，请切换到 fresh-create-new-computer 或 rollback-restore-snapshot 对应流程。'
            )
        },
        [pscustomobject][ordered]@{
            ModeId = 'rollback-restore-snapshot'
            Entrypoint = 'RestoreCleanCheckpoint'
            TitleZh = '回退/恢复已有干净快照'
            TitleEn = 'Rollback or restore existing clean checkpoint/snapshot'
            IntentZh = '只针对已经存在的 VM 和 clean checkpoint/snapshot；默认 PlanOnly/WhatIf 只展示计划。'
            DefaultCommand = $restorePlanCommand
            SafeDiagnostics = @($restorePlanCommand, $restoreWhatIfCommand, '.\scripts\Test-HyperVReadiness.ps1')
            MutationBoundary = 'actual restore requires -AllowVmMutation plus explicit -Confirm or -Force on an isolated lab host'
            SafeBoundaryZh = '默认只预览：-PlanOnly/-WhatIf 不调用 Restore-VMSnapshot；真实还原必须 -AllowVmMutation，并显式 -Confirm 或 -Force。'
            StartsVm = $false
            RestoresCheckpoint = $true
            CreatesVm = $false
            CreatesLocalConfig = $false
            MutatingCommand = $restoreCommand
            UnattendedMutatingCommand = '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -AllowVmMutation -Force'
            NextStepsZh = @(
                '下一步：先用 -PlanOnly 或 -WhatIf 确认 VM/checkpoint 名称；readiness/package 不会执行恢复。',
                '下一步：确认隔离实验 VM 可被回退后，管理员 PowerShell 中显式使用 -AllowVmMutation -Confirm；无人值守 lab 才使用 -Force。'
            )
        },
        [pscustomobject][ordered]@{
            ModeId = 'fresh-create-new-computer'
            Entrypoint = 'CreateOrPreparePath'
            TitleZh = '全新创建/新电脑准备'
            TitleEn = 'Fresh create or new-computer preparation'
            IntentZh = '准备仓库外 runtime root、本机 sandbox.local.json、guest secret，可选准备 payload；不会创建 Hyper-V VM 或 checkpoint。'
            DefaultCommand = $createCommand
            SafeDiagnostics = @('.\install.ps1 -InstallEntrypoint CreateOrPreparePath -PlanOnly', '.\install.ps1 -InstallEntrypoint CreateOrPreparePath -WhatIf', '.\install.ps1 -Mode CheckEnvironment')
            MutationBoundary = 'local filesystem/config/secret writes only through ShouldProcess; VM creation/checkpoint creation remains a manual Hyper-V operator task'
            SafeBoundaryZh = '只准备本机：PlanOnly/WhatIf 不写文件；真实执行也只写仓库外 runtime/config/secret/payload，不创建 VM/checkpoint。'
            StartsVm = $false
            RestoresCheckpoint = $false
            CreatesVm = $false
            CreatesLocalConfig = $true
            NextStepsZh = @(
                '下一步：首台机器先确认 Windows/Hyper-V/BIOS 虚拟化/SLAT/管理员 shell，再创建或导入 golden VM 并创建 clean checkpoint。',
                '下一步：运行 CreateOrPreparePath 保存本机配置/secret，再用 -Mode Change -UpdateHyperVConfig 记录真实 VM/checkpoint。'
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
    $confirmExplicitlyRequested = $script:InitialRootBoundParameters.Contains('Confirm') -and [System.Convert]::ToBoolean($script:InitialRootBoundParameters['Confirm'])
    $allowVmMutationGateSatisfied = $checkpointMutationRequested -and [bool]$AllowVmMutation
    $confirmOrForceGateSatisfied = $checkpointMutationRequested -and ($confirmExplicitlyRequested -or [bool]$Force)
    $restoreConfirmationSatisfied = $checkpointMutationRequested -and [bool]$AllowVmMutation -and ($confirmExplicitlyRequested -or [bool]$Force)
    $restoreWillExecute = $restoreConfirmationSatisfied -and -not [bool]$PlanOnly -and -not $diagnosticWhatIf
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
        RestoreExistingCleanCheckpointSnapshot = $checkpointMutationRequested
        CreateOrPrepareNewPath = $createOrPrepareRequested
        PlanOnly = [bool]$PlanOnly
        WhatIf = $diagnosticWhatIf
        ShouldProcessRequired = $checkpointMutationRequested -or $createOrPrepareRequested
        VmMutationNeeded = $checkpointMutationRequested
        VmMutationAllowed = [bool]$AllowVmMutation
        RestoreRequiresAllowVmMutation = $checkpointMutationRequested
        RestoreRequiresExplicitConfirmOrForce = $checkpointMutationRequested
        RestoreAllowVmMutationGateSatisfied = $allowVmMutationGateSatisfied
        RestoreConfirmOrForceGateSatisfied = $confirmOrForceGateSatisfied
        RestoreShouldProcessGateReached = $restoreWillExecute
        RestoreConfirmExplicitlyRequested = $confirmExplicitlyRequested
        RestoreForceExplicitlyRequested = [bool]$Force
        RestoreConfirmationGateSatisfied = $restoreConfirmationSatisfied
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
            RestoreRequiresAllowVmMutation = $checkpointMutationRequested
            RestoreRequiresShouldProcess = $checkpointMutationRequested
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
        RestoreCheckpointWhatIfCommand = '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -AllowVmMutation -WhatIf'
        RestoreCheckpointCommand = '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -AllowVmMutation -Confirm'
        RestoreCheckpointUnattendedCommand = '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -AllowVmMutation -Force'
        CreateOrPreparePlanCommand = '.\install.ps1 -InstallEntrypoint CreateOrPreparePath -PlanOnly'
        CreateOrPrepareWhatIfCommand = '.\install.ps1 -InstallEntrypoint CreateOrPreparePath -WhatIf'
        CreateOrPrepareConfirmCommand = '.\install.ps1 -InstallEntrypoint CreateOrPreparePath -Confirm'
        CreateOrPrepareCommand = '.\install.ps1 -InstallEntrypoint CreateOrPreparePath'
        PrepareGuestPayloadCommand = '.\install.ps1 -InstallEntrypoint CreateOrPreparePath -PrepareGuestPayload'
        PrepareGuestPayloadWhatIfCommand = '.\install.ps1 -InstallEntrypoint CreateOrPreparePath -PrepareGuestPayload -WhatIf'
        ChineseGuidance = '中文提示：安装入口需要显式选择使用已配置环境、还原已有干净快照，或创建/准备新路径；PlanOnly/WhatIf 不会启动、停止、还原或修改 VM。'
        NextSteps = @(Get-InstallEntrypointNextSteps -SelectedEntrypoint $SelectedEntrypoint)
        FreshComputerNextActionsZh = @(
            '下一步：首台机器先确认 Windows edition、Hyper-V feature/module、BIOS/UEFI 虚拟化和 SLAT；不满足时只运行 PlanOnly/WhatIf/WebUI/打包检查。',
            '下一步：在 Hyper-V 外部手工创建/导入 Windows golden VM，启用 Guest Service Interface 和 PowerShell Direct，创建 clean checkpoint。',
            '下一步：用 CreateOrPreparePath -PlanOnly/-WhatIf 预览，再用 -PromptPassword 写仓库外本机配置和 secret；不要修改 config\sandbox.example.json。'
        )
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
    Write-InstallInfo '创建/准备路径入口：准备本机目录和 sandbox.local.json；不会创建 Hyper-V VM，也不会还原 checkpoint。 / Creating/preparing local path only.'
    Install-KSwordSandboxLocal -SetPassword:$shouldSetPassword

    if ($PrepareGuestPayload) {
        Invoke-InstallerGuestPayloadPreparation
    }

    Write-InstallInfo '创建/准备路径完成。下一步：运行 .\install.ps1 -InstallEntrypoint UseConfiguredEnvironment -PlanOnly 查看剩余缺口。 / Create/prepare path completed.'
}

function Invoke-RestoreCleanCheckpointEntrypoint {
    if ($PlanOnly -or $WhatIfPreference) {
        if (-not $Json) {
            [void]$PSCmdlet.ShouldProcess("${VmName}::$CheckpointName", 'Restore existing clean checkpoint/snapshot')
        }
        if (-not $Json) {
            Write-InstallInfo '预览：还原已有干净 checkpoint/snapshot 入口不会执行 Hyper-V 变更。 / Previewing checkpoint restore only.'
        }
        Show-InstallEntrypointDiagnostics -SelectedEntrypoint 'RestoreCleanCheckpoint'
        return
    }

    if (-not $AllowVmMutation) {
        if (-not $Json) {
            Write-InstallInfo '默认安全计划：还原 checkpoint/snapshot 入口未加 -AllowVmMutation 时只显示计划和诊断；不会查询、启动、停止或还原 VM。 / Safe default: restore entrypoint is plan-only unless VM mutation is explicitly allowed.'
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

    if (-not (Test-IsAdministrator)) {
        throw '错误：还原 Hyper-V checkpoint/snapshot 需要管理员 PowerShell。下一步：以管理员身份打开 PowerShell，先运行 -PlanOnly/-WhatIf，再加 -AllowVmMutation 重试。'
    }

    $getSnapshotCommand = Get-Command Get-VMSnapshot -ErrorAction SilentlyContinue
    $restoreSnapshotCommand = Get-Command Restore-VMSnapshot -ErrorAction SilentlyContinue
    if ($null -eq $getSnapshotCommand -or $null -eq $restoreSnapshotCommand) {
        throw '错误：Hyper-V PowerShell checkpoint/snapshot 命令不可用。下一步：启用 Hyper-V PowerShell 管理工具后运行 .\install.ps1 -Mode CheckEnvironment。'
    }

    $snapshot = Get-VMSnapshot -VMName $VmName -Name $CheckpointName -ErrorAction SilentlyContinue
    if ($null -eq $snapshot) {
        throw "错误：找不到 VM '$VmName' 的干净 checkpoint/snapshot '$CheckpointName'。下一步：创建/选择现有干净快照后运行 .\install.ps1 -Mode Change -UpdateHyperVConfig -VmName '$VmName' -CheckpointName <checkpoint>。"
    }

    if (-not $PSCmdlet.ShouldProcess("${VmName}::$CheckpointName", 'Restore existing clean checkpoint/snapshot')) {
        Write-InstallInfo '已通过 ShouldProcess/Confirm 取消 checkpoint/snapshot 还原。 / Checkpoint restore declined.'
        return
    }

    Write-InstallInfo "正在还原 VM '$VmName' 的已有干净 checkpoint/snapshot '$CheckpointName'；不会创建新 VM。 / Restoring existing clean checkpoint."
    Restore-VMSnapshot -VMSnapshot $snapshot -Confirm:$false
    Write-InstallInfo "已还原 VM '$VmName' 到 checkpoint/snapshot '$CheckpointName'。下一步：运行 .\install.ps1 -InstallEntrypoint UseConfiguredEnvironment -PlanOnly 或 .\run.ps1 -Mode Plan。 / Restore completed."
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

    if (($Json -or $PassThru) -and
        $SelectedEntrypoint -ne 'UseConfiguredEnvironment' -and
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
    Write-Host '  2) 回退/恢复已有 clean checkpoint（菜单默认只给计划；真实还原需命令行 -AllowVmMutation -Confirm/-Force） / Plan rollback/restore existing clean checkpoint'
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
    Write-InstallInfo '密码 secret 已在本机重置。下一步：如果刚生成了新密码，请先把 VM 中 SandboxUser 帐户改成同一个值，再运行 Live Hyper-V。 / Password secret reset locally.'
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

function Invoke-HyperVConfigPrompt {
    Write-InstallInfo '中文提示：配置只写入本机状态和本机 sandbox.local.json；不会把 VM 名称、密码或本机路径写入 git。'
    $script:VmName = Read-OptionalText -Prompt 'Hyper-V 黄金 VM 名称 / Hyper-V golden VM name' -CurrentValue $VmName
    $script:CheckpointName = Read-OptionalText -Prompt '干净快照名称 / Clean checkpoint name' -CurrentValue $CheckpointName
    $script:GuestUserName = Read-OptionalText -Prompt '来宾用户名 / Guest username' -CurrentValue $GuestUserName
    $script:GuestWorkingDirectory = Read-OptionalText -Prompt '来宾工作目录 / Guest working directory' -CurrentValue $GuestWorkingDirectory
    $script:RuntimeRoot = Read-OptionalText -Prompt '宿主机运行目录 / Host runtime root' -CurrentValue $RuntimeRoot
    $script:GuestPayloadRoot = Read-OptionalText -Prompt '宿主机 guest payload 目录 / Host guest payload root' -CurrentValue $GuestPayloadRoot
    $script:DriverHostPath = Read-OptionalText -Prompt '宿主机 R0 驱动 .sys 路径（留空=自动检测/不配置） / Host R0 driver .sys path (blank=auto-detect/none)' -CurrentValue (Resolve-DriverHostPath)
    $script:LocalConfigPath = Read-OptionalText -Prompt '本机 sandbox 配置路径 / Local sandbox config path' -CurrentValue (Get-LocalSandboxConfigPath)
    Set-HyperVConfigState
}

function Invoke-GuestVmPasswordReset {
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
    Set-HyperVConfigState -Action 'guest-user-changed'
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

    if ($optionalFeatureCommandAvailable) {
        foreach ($featureName in @('Microsoft-Hyper-V-All', 'Microsoft-Hyper-V-Management-PowerShell')) {
            try {
                $feature = Get-WindowsOptionalFeature -Online -FeatureName $featureName -ErrorAction Stop
                $featureStates[$featureName] = [string]$feature.State
                if ([string]$feature.State -ne 'Enabled') {
                    [void]$actions.Add("下一步：启用 Windows Optional Feature '$featureName'（需要管理员权限和重启），然后重新运行 .\install.ps1 -Mode CheckEnvironment。")
                }
            }
            catch {
                $featureStates[$featureName] = 'Unknown'
                [void]$inspectionErrors.Add("无法读取 Windows feature $featureName：$($_.Exception.Message)")
            }
        }
    }
    else {
        [void]$inspectionErrors.Add('Get-WindowsOptionalFeature 不可用；无法直接读取 Hyper-V Windows Feature 状态。')
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
                    if (-not $virtualizationFirmwareEnabled) {
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

function Get-InstallVmProfileStatus {
    param([bool]$HyperVModuleAvailable)

    $actions = [System.Collections.Generic.List[string]]::new()
    $profile = [ordered]@{
        VmName = $VmName
        ExpectedCheckpointName = $CheckpointName
        Exists = $false
        State = $null
        Generation = $null
        ProcessorCount = $null
        MemoryStartupBytes = $null
        DynamicMemoryEnabled = $null
        GuestServiceInterfaceEnabled = $null
        CheckpointExists = $false
        Error = $null
        RecommendedActions = @()
    }

    if (-not $HyperVModuleAvailable) {
        [void]$actions.Add('下一步：启用/安装 Hyper-V PowerShell 模块后重新运行 .\install.ps1 -Mode CheckEnvironment；该检查不会启动或还原 VM。')
        $profile.RecommendedActions = @($actions.ToArray())
        return [pscustomobject]$profile
    }

    try {
        $vm = Get-VM -Name $VmName -ErrorAction Stop
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

        $snapshot = Get-VMSnapshot -VMName $VmName -Name $CheckpointName -ErrorAction SilentlyContinue
        $profile.CheckpointExists = $null -ne $snapshot
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
    catch {
        $profile.Error = $_.Exception.Message
        [void]$actions.Add("下一步：确认 Hyper-V VM '$VmName' 已创建/导入，或运行 .\install.ps1 -Mode Change -UpdateHyperVConfig -VmName <existing VM> -CheckpointName <checkpoint> 记录正确 profile。")
    }

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
            $manifestContractVersion = $manifest.payloadContractVersion
            $manifestConfiguration = $manifest.configuration
            $sourceFingerprintPresent = -not [string]::IsNullOrWhiteSpace([string]$manifest.sourceFingerprint)
            $requiredHostFiles = @($manifest.requiredHostFiles)
            $requiredHostFileNames = @($requiredHostFiles | ForEach-Object { [string]$_.name } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            $requiredHostFilesHaveSha256 = ($requiredHostFiles.Count -gt 0) -and (@($requiredHostFiles | Where-Object { [string]::IsNullOrWhiteSpace([string]$_.sha256) }).Count -eq 0)
            if ([int]$manifestContractVersion -lt 2) {
                [void]$actions.Add('下一步：payload-manifest.json contract version 过旧；重新准备 guest payload 以获得 freshness/hash 诊断。')
            }
            if (-not $sourceFingerprintPresent -or -not $requiredHostFilesHaveSha256) {
                [void]$actions.Add('下一步：payload manifest 缺少 sourceFingerprint 或 requiredHostFiles sha256；重新准备 payload，避免 WebUI Live 使用过期二进制。')
            }
        }
        catch {
            $manifestError = $_.Exception.Message
            [void]$actions.Add("下一步：payload-manifest.json 无法解析；删除损坏 payload 目录后重新准备。英文详情：$manifestError")
        }
    }

    $ready = $agentExists -and $collectorExists -and $manifestExists -and $manifestReadable -and $sourceFingerprintPresent -and $requiredHostFilesHaveSha256
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
    $hyperVPrerequisites = Get-InstallHyperVPrerequisiteStatus
    $runtimeStatus = Get-InstallRuntimeRootStatus
    $virusTotalStatus = Get-InstallVirusTotalStatus
    $hyperVModuleAvailable = [bool]$hyperVPrerequisites.PowerShellModuleAvailable
    $vmExists = $false
    $vmState = $null
    $checkpointExists = $false
    $hyperVStatusError = $null
    $vmProfile = Get-InstallVmProfileStatus -HyperVModuleAvailable $hyperVModuleAvailable
    $vmExists = [bool]$vmProfile.Exists
    $vmState = $vmProfile.State
    $checkpointExists = [bool]$vmProfile.CheckpointExists
    $hyperVStatusError = $vmProfile.Error
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
    foreach ($prereqAction in @($hyperVPrerequisites.RecommendedActions)) {
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
    if (-not (Test-Path -LiteralPath $RuntimeRoot -PathType Container)) {
        [void]$recommendedActions.Add("下一步：运行 .\install.ps1 -InstallEntrypoint CreateOrPreparePath -PromptPassword，在 '$RuntimeRoot' 下创建运行目录。 / Run install to create runtime folders.")
    }
    if (-not (Test-Path -LiteralPath $localConfig -PathType Leaf)) {
        [void]$recommendedActions.Add("下一步：运行 .\install.ps1 -InstallEntrypoint CreateOrPreparePath -PromptPassword 创建本机配置，或运行 .\install.ps1 -Mode Change -UpdateHyperVConfig 记录 VM/checkpoint 路径。")
    }
    if (-not (Test-Path -LiteralPath $GuestPayloadRoot -PathType Container) -or
        -not (Test-Path -LiteralPath $guestAgentPayload -PathType Leaf) -or
        -not (Test-Path -LiteralPath $r0CollectorPayload -PathType Leaf) -or
        -not (Test-Path -LiteralPath $payloadManifest -PathType Leaf)) {
        [void]$recommendedActions.Add("下一步：运行 .\scripts\Prepare-GuestPayload.ps1 -RepoRoot . -PayloadRoot '$GuestPayloadRoot' -GuestWorkingDirectory '$GuestWorkingDirectory' -SelfContained 准备 Guest Agent/R0Collector payload。")
    }
    if ([string]::IsNullOrWhiteSpace($processValue) -and [string]::IsNullOrWhiteSpace($userValue) -and [string]::IsNullOrWhiteSpace($machineValue)) {
        [void]$recommendedActions.Add("下一步：运行 .\install.ps1 -InstallEntrypoint CreateOrPreparePath -PromptPassword 保存 guest password secret；如果只做本进程检查，可运行 .\scripts\Test-HyperVReadiness.ps1 -PromptForMissingGuestPassword。")
    }
    if ([string]::IsNullOrWhiteSpace($driverHost)) {
        [void]$recommendedActions.Add("下一步：运行 .\install.ps1 -Mode Change -UpdateHyperVConfig -DriverHostPath <path-to-test-signed-KSword.Sandbox.Driver.sys>；仅验证链路时可在本机配置中设置 driver.useMockCollector=true。")
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
    if (-not $hyperVModuleAvailable) {
        [void]$recommendedActions.Add('下一步：启用/安装 Hyper-V PowerShell 工具，然后重新运行 .\install.ps1 -Mode CheckEnvironment。')
    }
    elseif (-not $vmExists) {
        [void]$recommendedActions.Add("下一步：运行 .\install.ps1 -Mode Change -UpdateHyperVConfig -VmName <existing VM> -CheckpointName <checkpoint> 记录现有 VM，或先创建/导入 VM '$VmName'。")
    }
    elseif (-not $checkpointExists) {
        [void]$recommendedActions.Add("下一步：运行 .\install.ps1 -Mode Change -UpdateHyperVConfig -VmName '$VmName' -CheckpointName <checkpoint> 记录快照，或先创建 checkpoint '$CheckpointName'。")
    }

    [pscustomobject][ordered]@{
        SecretName = $SecretName
        ProcessSecretSet = -not [string]::IsNullOrWhiteSpace($processValue)
        UserSecretSet = -not [string]::IsNullOrWhiteSpace($userValue)
        MachineSecretSet = -not [string]::IsNullOrWhiteSpace($machineValue)
        VirusTotalSecretName = $VirusTotalSecretName
        VirusTotalProcessSecretSet = -not [string]::IsNullOrWhiteSpace($vtProcessValue)
        VirusTotalUserSecretSet = -not [string]::IsNullOrWhiteSpace($vtUserValue)
        VirusTotalMachineSecretSet = -not [string]::IsNullOrWhiteSpace($vtMachineValue)
        VirusTotalStatus = $virusTotalStatus
        VirusTotalConfigured = [bool]$virusTotalStatus.Configured
        VirusTotalMissingKeyBehavior = $virusTotalStatus.MissingKeyBehavior
        GuestUserName = $GuestUserName
        RuntimeRoot = [System.IO.Path]::GetFullPath($RuntimeRoot)
        RuntimeRootExists = Test-Path -LiteralPath $RuntimeRoot -PathType Container
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
        CheckpointExists = $checkpointExists
        HyperVStatusError = $hyperVStatusError
        VmProfile = $vmProfile
        VmProfileHealthy = ($vmExists -and $checkpointExists)
        VmGeneration = $vmProfile.Generation
        VmProcessorCount = $vmProfile.ProcessorCount
        VmMemoryStartupBytes = $vmProfile.MemoryStartupBytes
        VmGuestServiceInterfaceEnabled = $vmProfile.GuestServiceInterfaceEnabled
        HostTestSigningState = $hostTestSigningStatus.State
        HostTestSigningMessage = $hostTestSigningStatus.Message
        LocalConfigPath = $localConfig
        LocalConfigExists = Test-Path -LiteralPath $localConfig -PathType Leaf
        WebConfigPathProcess = [Environment]::GetEnvironmentVariable($script:WebConfigPathEnvironmentName, 'Process')
        WebConfigPathUser = [Environment]::GetEnvironmentVariable($script:WebConfigPathEnvironmentName, 'User')
        InstallStatePath = $script:InstallStatePath
        InstallStateExists = Test-Path -LiteralPath $script:InstallStatePath -PathType Leaf
        DpapiBackupPath = $script:SecretBackupPath
        DpapiBackupExists = Test-Path -LiteralPath $script:SecretBackupPath -PathType Leaf
        PayloadGuidance = ".\scripts\Prepare-GuestPayload.ps1 -RepoRoot . -PayloadRoot '$GuestPayloadRoot' -GuestWorkingDirectory '$GuestWorkingDirectory' -SelfContained"
        VmGuidance = ".\install.ps1 -Mode Change -UpdateHyperVConfig -VmName <existing VM> -CheckpointName <checkpoint>"
        CheckpointGuidance = ".\install.ps1 -Mode Change -UpdateHyperVConfig -VmName '$VmName' -CheckpointName <checkpoint>"
        DriverHostPathGuidance = '.\install.ps1 -Mode Change -UpdateHyperVConfig -DriverHostPath <test-signed .sys>'
        GuestTestSigningGuidance = '.\install.ps1 -Mode Change -QueryGuestTestSigning; .\install.ps1 -Mode Change -EnableGuestTestSigning -RestartGuestAfterTestSigning -Force'
        InstallEntrypoint = $InstallEntrypoint
        InstallEntrypointChoices = @('UseConfiguredEnvironment', 'RestoreCleanCheckpoint', 'CreateOrPreparePath')
        OperatorModeMatrix = @(Get-InstallOperatorModeMatrix)
        OperatorModeMatrixSchema = 'ksword.install.operator-mode-matrix.v1'
        OperatorModeGuidanceZh = '中文提示：三种操作者模式互斥选择：使用已配置环境只诊断；回退/恢复快照只针对已有 clean checkpoint 且必须显式确认；全新创建/新电脑准备只写本机目录/config/secret/payload，不创建 VM。'
        UseConfiguredEnvironmentCommand = '.\install.ps1 -InstallEntrypoint UseConfiguredEnvironment -PlanOnly'
        RestoreCheckpointPlanCommand = '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -PlanOnly'
        RestoreCheckpointWhatIfCommand = '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -AllowVmMutation -WhatIf'
        RestoreCheckpointCommand = '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -AllowVmMutation -Confirm'
        RestoreCheckpointUnattendedCommand = '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -AllowVmMutation -Force'
        CreateOrPreparePathCommand = '.\install.ps1 -InstallEntrypoint CreateOrPreparePath'
        CreateOrPrepareWhatIfCommand = '.\install.ps1 -InstallEntrypoint CreateOrPreparePath -WhatIf'
        CreateOrPrepareConfirmCommand = '.\install.ps1 -InstallEntrypoint CreateOrPreparePath -Confirm'
        InstallEntrypointGuidance = 'Choose exactly one install entrypoint: use configured environment, restore an existing clean checkpoint/snapshot, or use the create/new prepare path for local folders/config/payload. VM mutation requires RestoreCleanCheckpoint + AllowVmMutation + ShouldProcess.'
        HostTestSigningGuidance = 'Host test-signing is a host boot setting for isolated lab hosts that load test-signed kernel drivers; use the Change menu guidance before enabling it and reboot after changes.'
        TestSigningGuidance = 'Guest test-signing is managed from the Change menu; host test-signing is guidance-only here and is needed only when the host itself loads a test-signed driver.'
        ReadinessGuidance = '.\scripts\Test-HyperVReadiness.ps1'
        ChineseGuidance = '中文提示：Status/CheckEnvironment 不打印密码值，不启动/还原 VM；安装入口可显式选择 UseConfiguredEnvironment、RestoreCleanCheckpoint 或 CreateOrPreparePath；RecommendedActions 给出下一步修复命令。'
        RecommendedActions = @($recommendedActions.ToArray() | Select-Object -Unique)
        SecretValuePrinted = $false
    }
}

function Test-CommandAvailable {
    param([Parameter(Mandatory)][string]$Name)
    return $null -ne (Get-Command -Name $Name -ErrorAction SilentlyContinue)
}

function Show-KSwordSandboxEnvironmentCheck {
    $runScript = Join-Path $PSScriptRoot 'run.ps1'
    $readinessScript = Join-Path $PSScriptRoot 'scripts\Test-HyperVReadiness.ps1'
    $webProject = Join-Path $PSScriptRoot 'src\KSword.Sandbox.Web\KSword.Sandbox.Web.csproj'
    $installStatus = Show-KSwordSandboxInstallStatus

    [pscustomobject][ordered]@{
        StartupCommand = '.\run.ps1'
        InstallCommand = '.\install.ps1'
        UseConfiguredEnvironmentCommand = '.\install.ps1 -InstallEntrypoint UseConfiguredEnvironment -PlanOnly'
        RestoreCheckpointPlanCommand = '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -PlanOnly'
        RestoreCheckpointWhatIfCommand = '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -AllowVmMutation -WhatIf'
        CreateOrPreparePathCommand = '.\install.ps1 -InstallEntrypoint CreateOrPreparePath'
        CreateOrPrepareWhatIfCommand = '.\install.ps1 -InstallEntrypoint CreateOrPreparePath -WhatIf'
        CreateOrPrepareConfirmCommand = '.\install.ps1 -InstallEntrypoint CreateOrPreparePath -Confirm'
        ConfigureHyperVCommand = '.\install.ps1 -Mode Change -UpdateHyperVConfig -VmName <VM> -CheckpointName <Checkpoint>'
        ConfigureGuestPasswordCommand = '.\install.ps1 -InstallEntrypoint CreateOrPreparePath -PromptPassword'
        ResetGuestPasswordCommand = '.\install.ps1 -Mode Change -ResetGuestVmPassword -PromptPassword -Force'
        ConfigureVTKeyCommand = '.\install.ps1 -Mode ConfigureVTKey -PromptVTKey'
        CheckEnvironmentCommand = '.\install.ps1 -Mode CheckEnvironment'
        ReadinessCommand = '.\scripts\Test-HyperVReadiness.ps1'
        PlanOnlyCommand = '.\run.ps1 -Mode Plan -SamplePath <sample.exe>'
        AnalyzeNotepadCommand = '.\run.ps1 -Mode Analyze -SamplePreset Notepad'
        AnalyzeHarmlessSampleCommand = '.\run.ps1 -Mode Analyze -SamplePreset HarmlessSample'
        ConfigureDriverHostPathCommand = '.\install.ps1 -Mode Change -UpdateHyperVConfig -DriverHostPath <test-signed .sys>'
        GuestTestSigningQueryCommand = '.\install.ps1 -Mode Change -QueryGuestTestSigning'
        GuestTestSigningEnableCommand = '.\install.ps1 -Mode Change -EnableGuestTestSigning -RestartGuestAfterTestSigning -Force'
        TestSigningGuidanceCommand = '.\install.ps1 -Mode Change -ShowTestSigningGuidance'
        WebUiUrl = $WebUiUrl
        RunScriptExists = Test-Path -LiteralPath $runScript -PathType Leaf
        ReadinessScriptExists = Test-Path -LiteralPath $readinessScript -PathType Leaf
        WebProjectExists = Test-Path -LiteralPath $webProject -PathType Leaf
        DotNetAvailable = Test-CommandAvailable -Name 'dotnet'
        PowerShellAvailable = Test-CommandAvailable -Name 'powershell'
        HyperVGetVmAvailable = Test-CommandAvailable -Name 'Get-VM'
        HyperVGetVmSnapshotAvailable = Test-CommandAvailable -Name 'Get-VMSnapshot'
        WhatIfSupported = $true
        DefaultStartsVm = $false
        StartWebUiStartsVm = $false
        CheckEnvironmentStartsVm = $false
        PlanOnlyStartsVm = $false
        InstallEntrypointChoices = @('UseConfiguredEnvironment', 'RestoreCleanCheckpoint', 'CreateOrPreparePath')
        OperatorModeMatrix = @(Get-InstallOperatorModeMatrix)
        InstallEntrypointVmMutationRequiresAllowVmMutation = $true
        RestoreCheckpointRequiresExplicitConfirmOrForce = $true
        ReadinessPackageExecutesInstallerModes = $false
        LiveVmExecutionRequiresExplicitLive = $true
        SecretValuePrinted = $false
        ChineseGuidance = '中文提示：先用本命令查看缺口；安装入口先三选一：使用已配置环境、还原已有干净快照、或创建/准备新路径；配置 VM/快照/guest 密码/driver path/test signing 后，再用 run.ps1 的 Analyze 命令。'
        InstallStatus = $installStatus
    }
}

function Invoke-KSwordSandboxEnvironmentCheck {
    Show-KSwordSandboxEnvironmentCheck | Format-List

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

    $testSigningScript = Join-Path $PSScriptRoot 'scripts\Set-GuestTestSigning.ps1'
    if (-not (Test-Path -LiteralPath $testSigningScript -PathType Leaf)) {
        throw "错误：找不到 guest test-signing 脚本：$testSigningScript。下一步：请确认 scripts\Set-GuestTestSigning.ps1 存在。"
    }

    if ($WhatIfPreference) {
        [void]$PSCmdlet.ShouldProcess($VmName, "Run guest test-signing '$TestSigningMode'")
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
        '-VmName', $VmName,
        '-GuestUserName', $GuestUserName,
        '-SecretName', $SecretName,
        '-Mode', $TestSigningMode
    )

    if ($RestartAfterChange) {
        $arguments += '-RestartGuest'
    }

    if ($Force -or $Mode -eq 'Interactive') {
        $arguments += '-Force'
    }

    if (-not $PSCmdlet.ShouldProcess($VmName, "Run guest test-signing '$TestSigningMode'")) {
        Write-InstallInfo "guest test-signing '$TestSigningMode' 已通过 ShouldProcess/Confirm 拒绝。 / Guest test-signing declined."
        return
    }

    Write-InstallInfo "正在对 VM '$VmName' 执行 guest test-signing '$TestSigningMode'。 / Running guest test-signing."
    & powershell @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "错误：guest test-signing '$TestSigningMode' 失败，退出码 $LASTEXITCODE。下一步：确认管理员权限、VM 正在可访问、guest password secret 正确后重试。"
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
        Write-Host '  2) 重置 VM 内实际密码（需要管理员和确认） / Reset actual VM guest password'
        Write-Host '  3) 返回 / Back'
        $choice = Read-MenuChoice -Prompt '请选择 [1-3] / Choose [1-3]' -Allowed @('1', '2', '3')
        switch ($choice) {
            '1' { Reset-GuestPasswordSecret }
            '2' { Invoke-GuestVmPasswordReset }
            '3' { return }
        }
    }
}

function Invoke-ChangeMenu {
    while ($true) {
        Write-Host ''
        Write-Host '更改选项 / Change options:'
        Write-Host '  1) 重置宿主机 guest password secret / Reset password secret'
        Write-Host '  2) 重置 VM 中实际来宾密码 / Reset actual VM guest password'
        Write-Host '  3) 配置黄金 VM、干净快照和来宾路径 / Change Hyper-V VM/checkpoint/guest paths'
        Write-Host '  4) 更改记录的来宾用户名 / Change recorded guest username'
        Write-Host '  5) 重建运行目录和本机配置 / Recreate runtime folders and local config'
        Write-Host '  6) 查看 Hyper-V readiness/status / Show Hyper-V readiness/status'
        Write-Host '  7) 管理 host/guest test-signing 指引 / Manage host/guest test-signing guidance'
        Write-Host '  8) 配置可选 VirusTotal API key / Configure optional VT key'
        Write-Host '  9) 检查本机环境 / Check local environment'
        Write-Host '  10) 返回 / Back'
        $choice = Read-MenuChoice -Prompt '请选择 [1-10] / Choose [1-10]' -Allowed @('1', '2', '3', '4', '5', '6', '7', '8', '9', '10')
        switch ($choice) {
            '1' { Reset-GuestPasswordSecret }
            '2' { Invoke-GuestVmPasswordReset }
            '3' { Invoke-HyperVConfigPrompt }
            '4' {
                $name = Read-Host '来宾用户名 / Guest username'
                Set-GuestUserNameState -NewGuestUserName $name
            }
            '5' { Set-HyperVConfigState -Action 'runtime-folders-and-config-refreshed' }
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
        Write-Host '  0) Install entrypoint selector / 安装入口选择'
        Write-Host '  1) Install / prepare local settings / 安装/准备本机设置'
        Write-Host '  2) Change settings / 更改设置'
        Write-Host '  3) Uninstall local settings / 卸载本机设置'
        Write-Host '  4) Reset Guest password/secret / 重置来宾密码/secret'
        Write-Host '  5) Configure Hyper-V / 配置 Hyper-V 黄金 VM/快照'
        Write-Host '  6) Configure VT key / 配置可选 VirusTotal key'
        Write-Host '  7) Check environment / 检查环境'
        Write-Host '  8) Start WebUI / 启动 WebUI'
        Write-Host '  9) Status / 状态'
        Write-Host '  10) Exit / 退出'
        $choice = Read-MenuChoice -Prompt '请选择 [0-10] / Choose [0-10]' -Allowed @('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10')
        switch ($choice) {
            '0' { Invoke-InstallEntrypointMenu }
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
            '5' { Invoke-HyperVConfigPrompt }
            '6' { Invoke-VirusTotalKeyConfiguration }
            '7' { Invoke-KSwordSandboxEnvironmentCheck }
            '8' { Invoke-KSwordSandboxWebUi }
            '9' { Show-KSwordSandboxInstallStatus | Format-List }
            '10' { return }
        }
    }
}

$script:InitialInstallState = Read-InstallState
Initialize-EffectiveParameters -State $script:InitialInstallState -BoundParameters $PSBoundParameters

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

if ($PlanOnly -and $Mode -eq 'Interactive') {
    Invoke-UseConfiguredEnvironmentEntrypoint
    return
}

$hasRootChangeAction = [bool]$StartWebUI -or
    [bool]$CheckEnvironment -or
    [bool]$ConfigureVTKey -or
    [bool]$PromptVTKey -or
    [bool]$ClearVTKey -or
    [bool]$ResetGuestVmPassword -or
    [bool]$ShowTestSigningGuidance -or
    [bool]$EnableGuestTestSigning -or
    [bool]$DisableGuestTestSigning -or
    [bool]$QueryGuestTestSigning -or
    [bool]$UpdateHyperVConfig -or
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
        elseif ($CheckEnvironment) {
            Invoke-KSwordSandboxEnvironmentCheck
        }
        elseif ($ConfigureVTKey -or $PromptVTKey -or $ClearVTKey) {
            Invoke-VirusTotalKeyConfiguration
        }
        elseif ($ResetGuestVmPassword) {
            Invoke-GuestVmPasswordReset
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
        elseif ($UpdateHyperVConfig) {
            Set-HyperVConfigState
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
        Show-KSwordSandboxInstallStatus | Format-List
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
