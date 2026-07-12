<#
.SYNOPSIS
Compatibility entry point for the KSwordSandbox local installer.

.DESCRIPTION
This script lives under scripts/ for packaging layouts that expose operational
helpers from one folder. It forwards parameters to the repository-root
install.ps1 in the same PowerShell process so local Process-scope environment
updates, ShouldProcess/-WhatIf behavior, DPAPI/user-environment secret handling,
Hyper-V configuration, guest-password reset delegation, guest test-signing
delegation, payload preparation, and WebUI startup behavior stay identical to
the primary release wrapper.

The wrapper does not print secret values, does not sign drivers, and does not
start a VM by itself. Install-entrypoint selection can explicitly choose
already configured environment diagnostics, existing clean checkpoint restore
planning, or create/prepare-new-path behavior.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [ValidateSet('Interactive', 'Install', 'Change', 'Uninstall', 'Status', 'CheckEnvironment', 'ConfigureVTKey', 'StartWebUI', 'Driver')]
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

    [ValidateSet('Status', 'Install', 'Start', 'Stop', 'Restart', 'Uninstall')]
    [string]$DriverAction = 'Status',

    [string]$DriverServiceName = 'KSwordSandboxDriver',

    [string]$DriverPath = '',

    [string]$DriverInfPath = '',

    [ValidateSet('Auto', 'Kernel', 'MiniFilter')]
    [string]$DriverKind = 'MiniFilter',

    [string]$MiniFilterAltitude = '385201',

    [string]$MiniFilterInstanceName = '',

    [string]$DriverPublishedName = '',

    [switch]$SkipDriverTestSigningCheck,

    [switch]$CurrentProcessOnly,

    [switch]$SkipDpapiBackup,

    [switch]$SkipWebConfigEnvironment,

    [switch]$SkipCheckpointRefresh,

    [switch]$SkipCheckpointRestore,

    [int]$BootTimeoutSeconds = 240,

    [int]$PowerShellDirectTimeoutSeconds = 240,

    [switch]$OpenBrowser,

    [switch]$PreparePayload,

    [switch]$PlanOnly,

    [switch]$AllowVmMutation,

    [switch]$PrepareGuestPayload,

    [switch]$Force
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Get-RepositoryRootFromScriptFolder {
    if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        return (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).ProviderPath
    }

    return (Get-Location).ProviderPath
}

$repositoryRoot = Get-RepositoryRootFromScriptFolder
$rootInstaller = Join-Path $repositoryRoot 'install.ps1'

if (-not (Test-Path -LiteralPath $rootInstaller -PathType Leaf)) {
    throw "错误：找不到仓库根目录 install.ps1：$rootInstaller。下一步：请从完整仓库/发行包运行，或使用根目录 .\install.ps1。"
}

$script:InitialWrapperBoundParameters = @{}
foreach ($parameterName in $PSBoundParameters.Keys) {
    $script:InitialWrapperBoundParameters[$parameterName] = $PSBoundParameters[$parameterName]
}

$script:DriverWrapperParameterNames = @(
    'DriverAction',
    'DriverServiceName',
    'DriverPath',
    'DriverInfPath',
    'DriverKind',
    'MiniFilterAltitude',
    'MiniFilterInstanceName',
    'DriverPublishedName',
    'SkipDriverTestSigningCheck'
)

function Write-ScriptInstallInfo {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "[scripts/install] $Message"
}

if ($PlanOnly -and -not $WhatIfPreference) {
    $WhatIfPreference = $true
    Write-ScriptInstallInfo 'PlanOnly 已启用：本次只输出计划/诊断，不写入本机状态、不启动或还原 VM。 / PlanOnly enabled: diagnostics only.'
}

function Read-ScriptMenuChoice {
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [Parameter(Mandatory)][string[]]$Allowed
    )

    do {
        $choice = (Read-Host $Prompt).Trim()
    } while ($Allowed -notcontains $choice)

    return $choice
}

function Read-ScriptOptionalText {
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

function Read-ScriptInstallState {
    $statePath = if ([string]::IsNullOrWhiteSpace($env:ProgramData)) {
        ''
    }
    else {
        Join-Path $env:ProgramData 'KSwordSandbox\install-state.json'
    }

    if ([string]::IsNullOrWhiteSpace($statePath) -or -not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
        return $null
    }

    try {
        return Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    }
    catch {
        Write-ScriptInstallInfo "中文提示：无法读取安装状态 '$statePath'，将忽略并继续。下一步：如配置异常，请重新运行 .\scripts\install.ps1 -InstallEntrypoint CreateOrPreparePath -PromptPassword。英文详情：$($_.Exception.Message)"
        return $null
    }
}

function Get-ScriptStateString {
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

function Initialize-ScriptEffectiveParameters {
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

        $current = Get-Variable -Name $entry.Key -Scope Script -ValueOnly
        $value = Get-ScriptStateString -State $State -Name $entry.Value -DefaultValue $current
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            Set-Variable -Name $entry.Key -Value $value -Scope Script -WhatIf:$false
        }
    }
}

function New-RootInstallerParameterTable {
    param(
        [string]$RootMode = '',
        [hashtable]$Additional = @{}
    )

    $parameters = @{}
    foreach ($key in $script:InitialWrapperBoundParameters.Keys) {
        if ($key -eq 'PreparePayload') {
            continue
        }

        if ($script:DriverWrapperParameterNames -contains $key) {
            continue
        }

        $parameters[$key] = $script:InitialWrapperBoundParameters[$key]
    }

    if (-not [string]::IsNullOrWhiteSpace($RootMode)) {
        $parameters['Mode'] = $RootMode
    }

    foreach ($entry in $Additional.GetEnumerator()) {
        $parameters[$entry.Key] = $entry.Value
    }

    return $parameters
}

function Invoke-RootInstaller {
    param([hashtable]$Parameters)
    & $rootInstaller @Parameters
}

function Invoke-ScriptDriverAction {
    $driverScript = Join-Path $PSScriptRoot 'Manage-SandboxDriver.ps1'
    if (-not (Test-Path -LiteralPath $driverScript -PathType Leaf)) {
        throw "错误：找不到驱动 service 管理脚本：$driverScript。下一步：请确认 scripts\Manage-SandboxDriver.ps1 存在。"
    }

    $parameters = @{
        Action = $DriverAction
        ServiceName = $DriverServiceName
        DriverKind = $DriverKind
        MiniFilterAltitude = $MiniFilterAltitude
    }

    if (-not [string]::IsNullOrWhiteSpace($DriverPath)) {
        $parameters['DriverPath'] = $DriverPath
    }

    if (-not [string]::IsNullOrWhiteSpace($DriverInfPath)) {
        $parameters['InfPath'] = $DriverInfPath
    }

    if (-not [string]::IsNullOrWhiteSpace($MiniFilterInstanceName)) {
        $parameters['MiniFilterInstanceName'] = $MiniFilterInstanceName
    }

    if (-not [string]::IsNullOrWhiteSpace($DriverPublishedName)) {
        $parameters['PublishedName'] = $DriverPublishedName
    }

    if ($SkipDriverTestSigningCheck) {
        $parameters['SkipTestSigningCheck'] = $true
    }

    if ($Force) {
        $parameters['Force'] = $true
    }

    if ($WhatIfPreference) {
        $parameters['WhatIf'] = $true
    }

    & $driverScript @parameters
}

function Invoke-ScriptPayloadPreparation {
    $prepareScript = Join-Path $PSScriptRoot 'Prepare-GuestPayload.ps1'
    if (-not (Test-Path -LiteralPath $prepareScript -PathType Leaf)) {
        throw "错误：找不到 guest payload 准备脚本：$prepareScript。下一步：请确认 scripts\Prepare-GuestPayload.ps1 存在。"
    }

    $target = [System.IO.Path]::GetFullPath($GuestPayloadRoot)
    if ($WhatIfPreference) {
        [void]$PSCmdlet.ShouldProcess($target, "Prepare self-contained guest payload with '$prepareScript'")
        Write-ScriptInstallInfo "预览：会在 $target 准备 guest payload；当前未构建或复制任何文件。 / WhatIf: guest payload would be prepared."
        return
    }

    if (-not $PSCmdlet.ShouldProcess($target, "Prepare self-contained guest payload with '$prepareScript'")) {
        Write-ScriptInstallInfo '已通过 ShouldProcess/Confirm 取消 guest payload 准备。下一步：需要 Live 前请重新运行并确认。 / Guest payload preparation declined.'
        return
    }

    $arguments = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $prepareScript,
        '-RepoRoot', $repositoryRoot,
        '-PayloadRoot', $GuestPayloadRoot,
        '-GuestWorkingDirectory', $GuestWorkingDirectory,
        '-SelfContained'
    )

    Write-ScriptInstallInfo "正在 $GuestPayloadRoot 下准备 guest payload；构建输出保留在 git 仓库外。 / Preparing guest payload outside git."
    & powershell @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "错误：guest payload 准备失败，退出码 $LASTEXITCODE。下一步：确认 .NET SDK/MSBuild/WDK 可用，并查看上方输出。"
    }
}

function Read-ScriptPasswordMode {
    Write-Host ''
    Write-Host '密码处理 / Password handling:'
    Write-Host '  1) 交互输入密码 / Prompt for password'
    Write-Host '  2) 生成本机随机密码 / Generate password locally'
    $choice = Read-ScriptMenuChoice -Prompt '请选择 [1-2] / Choose [1-2]' -Allowed @('1', '2')
    return @{
        PromptPassword = ($choice -eq '1')
        GeneratePassword = ($choice -eq '2')
    }
}

function Invoke-ScriptHyperVConfigPrompt {
    Write-ScriptInstallInfo '仅配置本机 Hyper-V 元数据；不会启动或还原 VM。 / Configuring local Hyper-V metadata only.'
    $script:VmName = Read-ScriptOptionalText -Prompt 'Hyper-V 黄金 VM 名称 / Hyper-V golden VM name' -CurrentValue $VmName
    $script:CheckpointName = Read-ScriptOptionalText -Prompt '干净快照名称 / Clean checkpoint name' -CurrentValue $CheckpointName
    $script:GuestUserName = Read-ScriptOptionalText -Prompt '来宾用户名 / Guest username' -CurrentValue $GuestUserName
    $script:GuestWorkingDirectory = Read-ScriptOptionalText -Prompt '来宾工作目录 / Guest working directory' -CurrentValue $GuestWorkingDirectory
    $script:RuntimeRoot = Read-ScriptOptionalText -Prompt '宿主机运行目录 / Host runtime root' -CurrentValue $RuntimeRoot
    $script:GuestPayloadRoot = Read-ScriptOptionalText -Prompt '宿主机 guest payload 目录 / Host guest payload root' -CurrentValue $GuestPayloadRoot
    $script:DriverHostPath = Read-ScriptOptionalText -Prompt '宿主机测试签名 R0 driver .sys 路径（留空=保留/不配置） / Host test-signed R0 driver path' -CurrentValue $DriverHostPath
    $script:LocalConfigPath = Read-ScriptOptionalText -Prompt '本机 sandbox 配置路径 / Local sandbox config path' -CurrentValue $LocalConfigPath

    Invoke-RootInstaller -Parameters (New-RootInstallerParameterTable -RootMode 'Change' -Additional @{
        UpdateHyperVConfig = $true
        VmName = $VmName
        CheckpointName = $CheckpointName
        GuestUserName = $GuestUserName
        GuestWorkingDirectory = $GuestWorkingDirectory
        RuntimeRoot = $RuntimeRoot
        GuestPayloadRoot = $GuestPayloadRoot
        DriverHostPath = $DriverHostPath
        LocalConfigPath = $LocalConfigPath
    })
}

function Confirm-ScriptGuestTestSigningMutation {
    param([Parameter(Mandatory)][string]$ActionDescription)

    Write-Host ''
    Write-Host "中文提示：$ActionDescription 会修改 VM 内 Windows test-signing boot setting；仅用于隔离实验 VM，且不会签名 driver。 / This mutates guest boot settings only."
    $continue = Read-ScriptMenuChoice -Prompt '是否继续？[y/n] / Continue? [y/n]' -Allowed @('y', 'Y', 'n', 'N')
    return $continue -in @('y', 'Y')
}

function Invoke-ScriptGuestTestSigningMenu {
    while ($true) {
        Write-Host ''
        Write-Host '来宾 test-signing 选项 / Guest test-signing options:'
        Write-Host '  1) 显示只读 test-signing 指引 / Show read-only guidance'
        Write-Host '  2) 查询当前 guest test-signing 状态 / Query current state'
        Write-Host '  3) 启用 guest test-signing / Enable guest test-signing'
        Write-Host '  4) 启用 guest test-signing，并在状态变化时重启 / Enable and reboot if changed'
        Write-Host '  5) 禁用 guest test-signing / Disable guest test-signing'
        Write-Host '  6) 返回 / Back'
        $choice = Read-ScriptMenuChoice -Prompt '请选择 [1-6] / Choose [1-6]' -Allowed @('1', '2', '3', '4', '5', '6')
        switch ($choice) {
            '1' { Invoke-RootInstaller -Parameters (New-RootInstallerParameterTable -RootMode 'Change' -Additional @{ ShowTestSigningGuidance = $true }) }
            '2' { Invoke-RootInstaller -Parameters (New-RootInstallerParameterTable -RootMode 'Change' -Additional @{ QueryGuestTestSigning = $true }) }
            '3' {
                if (Confirm-ScriptGuestTestSigningMutation -ActionDescription '启用 guest test-signing') {
                    Invoke-RootInstaller -Parameters (New-RootInstallerParameterTable -RootMode 'Change' -Additional @{ EnableGuestTestSigning = $true; Force = $true })
                }
            }
            '4' {
                if (Confirm-ScriptGuestTestSigningMutation -ActionDescription '启用 guest test-signing 并在状态变化时重启') {
                    Invoke-RootInstaller -Parameters (New-RootInstallerParameterTable -RootMode 'Change' -Additional @{ EnableGuestTestSigning = $true; RestartGuestAfterTestSigning = $true; Force = $true })
                }
            }
            '5' {
                if (Confirm-ScriptGuestTestSigningMutation -ActionDescription '禁用 guest test-signing') {
                    Invoke-RootInstaller -Parameters (New-RootInstallerParameterTable -RootMode 'Change' -Additional @{ DisableGuestTestSigning = $true; Force = $true })
                }
            }
            '6' { return }
        }
    }
}

function Invoke-ScriptChangeMenu {
    while ($true) {
        Write-Host ''
        Write-Host '更改选项 / Change options:'
        Write-Host '  1) 重置宿主机 guest password secret / Reset password secret'
        Write-Host '  2) 重置 VM 中实际来宾密码 / Reset actual VM guest password'
        Write-Host '  3) 配置 Hyper-V VM 名称、快照和路径 / Configure Hyper-V VM/checkpoint/paths'
        Write-Host '  4) 管理 guest test-signing（指引/查询/启用/禁用） / Manage guest test-signing'
        Write-Host '  5) 准备 Guest Agent/R0Collector payload / Prepare guest payload'
        Write-Host '  6) 查看驱动 service/minifilter JSON 状态 / Driver JSON status'
        Write-Host '  7) 显示状态和就绪修复建议 / Show status/readiness guidance'
        Write-Host '  8) 返回 / Back'
        $choice = Read-ScriptMenuChoice -Prompt '请选择 [1-8] / Choose [1-8]' -Allowed @('1', '2', '3', '4', '5', '6', '7', '8')
        switch ($choice) {
            '1' {
                $passwordMode = Read-ScriptPasswordMode
                Invoke-RootInstaller -Parameters (New-RootInstallerParameterTable -RootMode 'Change' -Additional @{
                    ResetPassword = $true
                    PromptPassword = $passwordMode.PromptPassword
                    GeneratePassword = $passwordMode.GeneratePassword
                })
            }
            '2' {
                $passwordMode = Read-ScriptPasswordMode
                Write-Host ''
                Write-Host '中文提示：此操作可能还原/启动/停止已配置 VM；请只在隔离实验宿主机的管理员 PowerShell 中继续。 / This can restore/start/stop the configured VM.'
                $continue = Read-ScriptMenuChoice -Prompt '是否继续重置 VM 实际来宾密码？[y/n] / Continue actual VM guest password reset? [y/n]' -Allowed @('y', 'Y', 'n', 'N')
                if ($continue -in @('y', 'Y')) {
                    Invoke-RootInstaller -Parameters (New-RootInstallerParameterTable -RootMode 'Change' -Additional @{
                        ResetGuestVmPassword = $true
                        PromptPassword = $passwordMode.PromptPassword
                        GeneratePassword = $passwordMode.GeneratePassword
                        Force = $true
                    })
                }
            }
            '3' { Invoke-ScriptHyperVConfigPrompt }
            '4' { Invoke-ScriptGuestTestSigningMenu }
            '5' { Invoke-ScriptPayloadPreparation }
            '6' {
                $script:DriverAction = 'Status'
                Invoke-ScriptDriverAction
            }
            '7' { Invoke-RootInstaller -Parameters (New-RootInstallerParameterTable -RootMode 'Status') }
            '8' { return }
        }
    }
}

function Invoke-ScriptInstallEntrypointMenu {
    Write-Host ''
    Write-Host '安装入口选择 / Install entrypoint selection:'
    Write-Host '  1) 使用已配置环境（只诊断，不修改 VM） / Use already configured environment'
    Write-Host '  2) 还原已有干净 checkpoint/snapshot（默认只给计划；真实还原需 -AllowVmMutation） / Restore existing clean checkpoint'
    Write-Host '  3) 创建/准备新的本机路径（目录/config，可选 payload；不创建 VM） / Create or prepare new local path'
    $choice = Read-ScriptMenuChoice -Prompt '请选择 [1-3] / Choose [1-3]' -Allowed @('1', '2', '3')
    $selectedEntrypoint = switch ($choice) {
        '1' { 'UseConfiguredEnvironment' }
        '2' { 'RestoreCleanCheckpoint' }
        '3' { 'CreateOrPreparePath' }
    }

    Invoke-RootInstaller -Parameters (New-RootInstallerParameterTable -Additional @{
        InstallEntrypoint = $selectedEntrypoint
    })
}

function Invoke-ScriptInstallerMenu {
    while ($true) {
        Write-Host ''
        Write-Host 'KSwordSandbox scripts 目录安装向导 / script-folder installer'
        Write-Host '  0) 安装入口选择 / Install entrypoint selector'
        Write-Host '  1) 安装/准备本机设置 / Install or prepare local settings'
        Write-Host '  2) 更改设置 / Change settings'
        Write-Host '  3) 卸载本机设置 / Uninstall local settings'
        Write-Host '  4) 检查环境 / Check environment'
        Write-Host '  5) 启动 WebUI / Start WebUI'
        Write-Host '  6) 状态 / Status'
        Write-Host '  7) 退出 / Exit'
        $choice = Read-ScriptMenuChoice -Prompt '请选择 [0-7] / Choose [0-7]' -Allowed @('0', '1', '2', '3', '4', '5', '6', '7')
        switch ($choice) {
            '0' { Invoke-ScriptInstallEntrypointMenu }
            '1' {
                Write-Host ''
                Write-Host '安装密码处理 / Install password handling:'
                Write-Host '  1) 现在输入 guest password secret / Prompt for guest password now'
                Write-Host '  2) 生成本机随机密码 / Generate password locally'
                Write-Host '  3) 仅准备目录和配置 / Prepare folders/config only'
                $installChoice = Read-ScriptMenuChoice -Prompt '请选择 [1-3] / Choose [1-3]' -Allowed @('1', '2', '3')
                $extra = @{}
                if ($installChoice -eq '1') { $extra['PromptPassword'] = $true }
                if ($installChoice -eq '2') { $extra['GeneratePassword'] = $true }
                Invoke-RootInstaller -Parameters (New-RootInstallerParameterTable -RootMode 'Install' -Additional $extra)
            }
            '2' { Invoke-ScriptChangeMenu }
            '3' {
                $continue = Read-ScriptMenuChoice -Prompt '继续卸载本机设置？[y/n] / Continue uninstall local settings? [y/n]' -Allowed @('y', 'Y', 'n', 'N')
                if ($continue -in @('y', 'Y')) {
                    Invoke-RootInstaller -Parameters (New-RootInstallerParameterTable -RootMode 'Uninstall' -Additional @{ Force = $true })
                }
            }
            '4' { Invoke-RootInstaller -Parameters (New-RootInstallerParameterTable -RootMode 'CheckEnvironment') }
            '5' { Invoke-RootInstaller -Parameters (New-RootInstallerParameterTable -RootMode 'StartWebUI') }
            '6' { Invoke-RootInstaller -Parameters (New-RootInstallerParameterTable -RootMode 'Status') }
            '7' { return }
        }
    }
}

$scriptInstallState = Read-ScriptInstallState
Initialize-ScriptEffectiveParameters -State $scriptInstallState -BoundParameters $PSBoundParameters

if ($PreparePayload) {
    Write-ScriptInstallInfo '中文提示：-PreparePayload 属于 CreateOrPreparePath 安装入口；将委托根安装器按创建/准备路径模式执行。 / PreparePayload routes through CreateOrPreparePath.'
    Invoke-RootInstaller -Parameters (New-RootInstallerParameterTable -Additional @{
        InstallEntrypoint = 'CreateOrPreparePath'
        PrepareGuestPayload = $true
    })
    return
}

if ($PSBoundParameters.ContainsKey('InstallEntrypoint') -or
    $PrepareGuestPayload -or
    ($PlanOnly -and $Mode -eq 'Interactive')) {
    Invoke-RootInstaller -Parameters (New-RootInstallerParameterTable -RootMode 'Interactive')
    return
}

if ($Mode -eq 'Driver' -or
    $PSBoundParameters.ContainsKey('DriverAction') -or
    $PSBoundParameters.ContainsKey('DriverPath') -or
    $PSBoundParameters.ContainsKey('DriverInfPath') -or
    $PSBoundParameters.ContainsKey('DriverPublishedName') -or
    $PSBoundParameters.ContainsKey('SkipDriverTestSigningCheck')) {
    Invoke-ScriptDriverAction
    return
}

if ($Mode -eq 'Interactive') {
    Invoke-ScriptInstallerMenu
    return
}

$hasChangeAction = [bool]$ResetPassword -or
    [bool]$ResetGuestVmPassword -or
    [bool]$UpdateHyperVConfig -or
    [bool]$ConfigureVTKey -or
    [bool]$PromptVTKey -or
    [bool]$ClearVTKey -or
    [bool]$CheckEnvironment -or
    [bool]$StartWebUI -or
    [bool]$RunHyperVReadiness -or
    [bool]$EnableGuestTestSigning -or
    [bool]$DisableGuestTestSigning -or
    [bool]$QueryGuestTestSigning -or
    [bool]$ShowTestSigningGuidance -or
    [bool]$GeneratePassword -or
    [bool]$PromptPassword -or
    [bool]$PlanOnly -or
    [bool]$PrepareGuestPayload

if ($Mode -eq 'Change' -and -not $hasChangeAction) {
    Invoke-ScriptChangeMenu
    return
}

Invoke-RootInstaller -Parameters (New-RootInstallerParameterTable)
