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
start a VM by itself.
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

    [switch]$RestartGuestAfterTestSigning,

    [switch]$CurrentProcessOnly,

    [switch]$SkipDpapiBackup,

    [switch]$SkipWebConfigEnvironment,

    [switch]$SkipCheckpointRefresh,

    [switch]$SkipCheckpointRestore,

    [int]$BootTimeoutSeconds = 240,

    [int]$PowerShellDirectTimeoutSeconds = 240,

    [switch]$OpenBrowser,

    [switch]$PreparePayload,

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
    throw "Repository-root installer was not found: $rootInstaller"
}

$script:InitialWrapperBoundParameters = @{}
foreach ($parameterName in $PSBoundParameters.Keys) {
    $script:InitialWrapperBoundParameters[$parameterName] = $PSBoundParameters[$parameterName]
}

function Write-ScriptInstallInfo {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "[scripts/install] $Message"
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
        Write-ScriptInstallInfo "Ignoring unreadable install state '$statePath': $($_.Exception.Message)"
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

function Invoke-ScriptPayloadPreparation {
    $prepareScript = Join-Path $PSScriptRoot 'Prepare-GuestPayload.ps1'
    if (-not (Test-Path -LiteralPath $prepareScript -PathType Leaf)) {
        throw "Guest payload preparation script was not found: $prepareScript"
    }

    $target = [System.IO.Path]::GetFullPath($GuestPayloadRoot)
    if ($WhatIfPreference) {
        [void]$PSCmdlet.ShouldProcess($target, "Prepare self-contained guest payload with '$prepareScript'")
        Write-ScriptInstallInfo "WhatIf: guest payload would be prepared at $target. No build or copy was executed."
        return
    }

    if (-not $PSCmdlet.ShouldProcess($target, "Prepare self-contained guest payload with '$prepareScript'")) {
        Write-ScriptInstallInfo 'Guest payload preparation declined by ShouldProcess/Confirm.'
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

    Write-ScriptInstallInfo "Preparing guest payload under $GuestPayloadRoot. Build output remains outside git."
    & powershell @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Guest payload preparation failed with exit code $LASTEXITCODE."
    }
}

function Read-ScriptPasswordMode {
    Write-Host ''
    Write-Host 'Password handling / 密码处理:'
    Write-Host '  1) Prompt for password（交互输入密码）'
    Write-Host '  2) Generate password locally（生成本机随机密码）'
    $choice = Read-ScriptMenuChoice -Prompt 'Choose [1-2] / 请选择 [1-2]' -Allowed @('1', '2')
    return @{
        PromptPassword = ($choice -eq '1')
        GeneratePassword = ($choice -eq '2')
    }
}

function Invoke-ScriptHyperVConfigPrompt {
    Write-ScriptInstallInfo 'Configuring local Hyper-V metadata only; no VM is started or restored.'
    $script:VmName = Read-ScriptOptionalText -Prompt 'Hyper-V golden VM name / Hyper-V 黄金 VM 名称' -CurrentValue $VmName
    $script:CheckpointName = Read-ScriptOptionalText -Prompt 'Clean checkpoint name / 干净快照名称' -CurrentValue $CheckpointName
    $script:GuestUserName = Read-ScriptOptionalText -Prompt 'Guest username / 来宾用户名' -CurrentValue $GuestUserName
    $script:GuestWorkingDirectory = Read-ScriptOptionalText -Prompt 'Guest working directory / 来宾工作目录' -CurrentValue $GuestWorkingDirectory
    $script:RuntimeRoot = Read-ScriptOptionalText -Prompt 'Host runtime root / 宿主机运行目录' -CurrentValue $RuntimeRoot
    $script:GuestPayloadRoot = Read-ScriptOptionalText -Prompt 'Host guest payload root / 宿主机 guest payload 目录' -CurrentValue $GuestPayloadRoot
    $script:DriverHostPath = Read-ScriptOptionalText -Prompt 'Host test-signed R0 driver .sys path (blank = preserve/none) / 宿主机测试签名驱动路径（留空=保留/不配置）' -CurrentValue $DriverHostPath
    $script:LocalConfigPath = Read-ScriptOptionalText -Prompt 'Local sandbox config path / 本机配置路径' -CurrentValue $LocalConfigPath

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

function Invoke-ScriptGuestTestSigningMenu {
    while ($true) {
        Write-Host ''
        Write-Host 'Guest test-signing options / 来宾 test signing 选项:'
        Write-Host '  1) Query current guest test-signing state（查询当前状态）'
        Write-Host '  2) Enable guest test-signing（启用）'
        Write-Host '  3) Enable guest test-signing and reboot guest if changed（启用并在变化时重启）'
        Write-Host '  4) Disable guest test-signing（禁用）'
        Write-Host '  5) Back（返回）'
        $choice = Read-ScriptMenuChoice -Prompt 'Choose [1-5] / 请选择 [1-5]' -Allowed @('1', '2', '3', '4', '5')
        switch ($choice) {
            '1' { Invoke-RootInstaller -Parameters (New-RootInstallerParameterTable -RootMode 'Change' -Additional @{ QueryGuestTestSigning = $true }) }
            '2' { Invoke-RootInstaller -Parameters (New-RootInstallerParameterTable -RootMode 'Change' -Additional @{ EnableGuestTestSigning = $true; Force = $true }) }
            '3' { Invoke-RootInstaller -Parameters (New-RootInstallerParameterTable -RootMode 'Change' -Additional @{ EnableGuestTestSigning = $true; RestartGuestAfterTestSigning = $true; Force = $true }) }
            '4' { Invoke-RootInstaller -Parameters (New-RootInstallerParameterTable -RootMode 'Change' -Additional @{ DisableGuestTestSigning = $true; Force = $true }) }
            '5' { return }
        }
    }
}

function Invoke-ScriptChangeMenu {
    while ($true) {
        Write-Host ''
        Write-Host 'Change options: / 更改选项:'
        Write-Host '  1) Reset password secret（重置宿主机 guest 密码 secret）'
        Write-Host '  2) Reset actual VM guest password（重置 VM 中实际来宾密码）'
        Write-Host '  3) Configure Hyper-V VM/checkpoint/guest paths（配置 Hyper-V VM 名称/快照/路径）'
        Write-Host '  4) Manage guest test-signing（查询/启用/提示来宾 test signing）'
        Write-Host '  5) Prepare guest payload（准备 Guest Agent/R0Collector payload）'
        Write-Host '  6) Show status/readiness guidance（显示状态/就绪提示）'
        Write-Host '  7) Back（返回）'
        $choice = Read-ScriptMenuChoice -Prompt 'Choose [1-7] / 请选择 [1-7]' -Allowed @('1', '2', '3', '4', '5', '6', '7')
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
                Write-Host 'This can restore/start/stop the configured VM. Continue only from an elevated lab host shell.'
                $continue = Read-ScriptMenuChoice -Prompt 'Continue actual VM guest password reset? [y/n] / 是否继续？[y/n]' -Allowed @('y', 'Y', 'n', 'N')
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
            '6' { Invoke-RootInstaller -Parameters (New-RootInstallerParameterTable -RootMode 'Status') }
            '7' { return }
        }
    }
}

function Invoke-ScriptInstallerMenu {
    while ($true) {
        Write-Host ''
        Write-Host 'KSwordSandbox script-folder installer / scripts 目录安装向导'
        Write-Host '  1) Install / prepare local settings（安装/准备本机设置）'
        Write-Host '  2) Change settings（更改设置）'
        Write-Host '  3) Uninstall local settings（卸载本机设置）'
        Write-Host '  4) Check environment（检查环境）'
        Write-Host '  5) Start WebUI（启动 WebUI）'
        Write-Host '  6) Status（状态）'
        Write-Host '  7) Exit（退出）'
        $choice = Read-ScriptMenuChoice -Prompt 'Choose [1-7] / 请选择 [1-7]' -Allowed @('1', '2', '3', '4', '5', '6', '7')
        switch ($choice) {
            '1' {
                Write-Host ''
                Write-Host 'Install password handling / 安装密码处理:'
                Write-Host '  1) Prompt for guest password now（现在输入 guest password secret）'
                Write-Host '  2) Generate password locally（生成本机随机密码）'
                Write-Host '  3) Prepare folders/config only（仅准备目录和配置）'
                $installChoice = Read-ScriptMenuChoice -Prompt 'Choose [1-3] / 请选择 [1-3]' -Allowed @('1', '2', '3')
                $extra = @{}
                if ($installChoice -eq '1') { $extra['PromptPassword'] = $true }
                if ($installChoice -eq '2') { $extra['GeneratePassword'] = $true }
                Invoke-RootInstaller -Parameters (New-RootInstallerParameterTable -RootMode 'Install' -Additional $extra)
            }
            '2' { Invoke-ScriptChangeMenu }
            '3' {
                $continue = Read-ScriptMenuChoice -Prompt 'Continue uninstall local settings? [y/n] / 继续卸载本机设置？[y/n]' -Allowed @('y', 'Y', 'n', 'N')
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
    Invoke-ScriptPayloadPreparation
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
    [bool]$GeneratePassword -or
    [bool]$PromptPassword

if ($Mode -eq 'Change' -and -not $hasChangeAction) {
    Invoke-ScriptChangeMenu
    return
}

Invoke-RootInstaller -Parameters (New-RootInstallerParameterTable)
