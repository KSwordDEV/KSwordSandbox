<#
.SYNOPSIS
Compatibility entry point for the KSwordSandbox local installer.

.DESCRIPTION
This script lives under scripts/ for packaging layouts that expose operational
helpers from one folder. It forwards parameters to the repository-root
install.ps1 in the same PowerShell process so local Process-scope environment
updates, ShouldProcess/-WhatIf behavior, DPAPI/user-environment secret handling,
provider configuration, guest-password reset delegation, guest test-signing
delegation, payload preparation, and WebUI startup behavior stay identical to
the primary release wrapper.

The wrapper does not print secret values, does not sign drivers, and does not
start a VM by itself. Install-entrypoint selection explicitly maps to the
three release-supported operator modes: use an already configured environment,
rollback/restore an existing clean baseline, or fresh create /
new-computer local preparation.
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

    [Alias('GuestReadyTimeoutSeconds')]
    [int]$PowerShellDirectTimeoutSeconds = 240,

    [switch]$OpenBrowser,

    [switch]$PreparePayload,

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
    if (-not $Json) {
        Write-ScriptInstallInfo 'PlanOnly 已启用：本次只输出计划/诊断，不写入本机状态、不启动或还原 VM。 / PlanOnly enabled: diagnostics only.'
    }
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

function Read-ScriptQemuAdditionalArguments {
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

function Get-ScriptObjectPropertyValue {
    param(
        [AllowNull()]$Object,
        [Parameter(Mandatory)][string]$Name,
        [AllowNull()]$DefaultValue = $null
    )

    if ($null -eq $Object) { return $DefaultValue }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $DefaultValue }
    return $property.Value
}

function Import-ScriptSelectedVirtualizationProfile {
    $configPath = if (-not [string]::IsNullOrWhiteSpace($LocalConfigPath)) {
        [System.IO.Path]::GetFullPath($LocalConfigPath)
    }
    else {
        [System.IO.Path]::GetFullPath((Join-Path $RuntimeRoot 'config\sandbox.local.json'))
    }
    if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) { return }

    try {
        $localConfig = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json -ErrorAction Stop
        switch ($VirtualizationProvider) {
            'HyperV' {
                $section = Get-ScriptObjectPropertyValue -Object $localConfig -Name 'hyperV'
                $script:VmName = [string](Get-ScriptObjectPropertyValue -Object $section -Name 'goldenVmName' -DefaultValue $VmName)
                $script:CheckpointName = [string](Get-ScriptObjectPropertyValue -Object $section -Name 'goldenSnapshotName' -DefaultValue $CheckpointName)
            }
            'VMware' {
                $section = Get-ScriptObjectPropertyValue -Object $localConfig -Name 'vmware'
                $script:VmName = [string](Get-ScriptObjectPropertyValue -Object $section -Name 'vmName' -DefaultValue $VmName)
                $script:VMwareVmxPath = [string](Get-ScriptObjectPropertyValue -Object $section -Name 'vmxPath' -DefaultValue $VMwareVmxPath)
                $script:CheckpointName = [string](Get-ScriptObjectPropertyValue -Object $section -Name 'snapshotName' -DefaultValue $CheckpointName)
                $script:VMwareVmrunPath = [string](Get-ScriptObjectPropertyValue -Object $section -Name 'vmrunPath' -DefaultValue $VMwareVmrunPath)
                $script:VMwareVmType = [string](Get-ScriptObjectPropertyValue -Object $section -Name 'vmType' -DefaultValue $VMwareVmType)
                $script:VMwareHeadless = [bool](Get-ScriptObjectPropertyValue -Object $section -Name 'headless' -DefaultValue $VMwareHeadless)
            }
            'Qemu' {
                $section = Get-ScriptObjectPropertyValue -Object $localConfig -Name 'qemu'
                $script:VmName = [string](Get-ScriptObjectPropertyValue -Object $section -Name 'vmName' -DefaultValue $VmName)
                $script:QemuDiskImagePath = [string](Get-ScriptObjectPropertyValue -Object $section -Name 'diskImagePath' -DefaultValue $QemuDiskImagePath)
                $script:CheckpointName = [string](Get-ScriptObjectPropertyValue -Object $section -Name 'snapshotName' -DefaultValue $CheckpointName)
                $script:QemuSystemPath = [string](Get-ScriptObjectPropertyValue -Object $section -Name 'qemuSystemPath' -DefaultValue $QemuSystemPath)
                $script:QemuImgPath = [string](Get-ScriptObjectPropertyValue -Object $section -Name 'qemuImgPath' -DefaultValue $QemuImgPath)
                $script:QemuDiskFormat = [string](Get-ScriptObjectPropertyValue -Object $section -Name 'diskFormat' -DefaultValue $QemuDiskFormat)
                $script:QemuDiskInterface = [string](Get-ScriptObjectPropertyValue -Object $section -Name 'diskInterface' -DefaultValue $QemuDiskInterface)
                $script:QemuUseOverlayDisk = [bool](Get-ScriptObjectPropertyValue -Object $section -Name 'useOverlayDisk' -DefaultValue $QemuUseOverlayDisk)
                $script:QemuMemoryMegabytes = [int](Get-ScriptObjectPropertyValue -Object $section -Name 'memoryMegabytes' -DefaultValue $QemuMemoryMegabytes)
                $script:QemuHeadless = [bool](Get-ScriptObjectPropertyValue -Object $section -Name 'headless' -DefaultValue $QemuHeadless)
                $additionalProperty = if ($null -eq $section) { $null } else { $section.PSObject.Properties['additionalArguments'] }
                if ($null -ne $additionalProperty) { $script:QemuAdditionalArguments = @($additionalProperty.Value | ForEach-Object { [string]$_ }) }
            }
        }

        if ($VirtualizationProvider -ne 'HyperV') {
            $guest = Get-ScriptObjectPropertyValue -Object $localConfig -Name 'guest'
            $remoting = Get-ScriptObjectPropertyValue -Object $section -Name 'guestRemoting'
            $legacyAddress = [string](Get-ScriptObjectPropertyValue -Object $guest -Name 'powerShellRemotingAddress' -DefaultValue '')
            $automaticGuestRemotingMigrated = $null -eq $remoting -and [string]::IsNullOrWhiteSpace($legacyAddress)
            $defaultAddressMode = if ($automaticGuestRemotingMigrated) {
                if ($VirtualizationProvider -eq 'VMware') { 'VMwareTools' } else { 'QemuUserNat' }
            }
            else {
                'Configured'
            }
            $loadedAddressMode = [string](Get-ScriptObjectPropertyValue -Object $remoting -Name 'addressMode' -DefaultValue $defaultAddressMode)
            $script:GuestRemotingAddressMode = $loadedAddressMode
            $providerAddress = [string](Get-ScriptObjectPropertyValue -Object $remoting -Name 'address' -DefaultValue '')
            if ($loadedAddressMode -eq 'Configured' -and [string]::IsNullOrWhiteSpace($providerAddress)) {
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
            $script:GuestRemotingAddress = [string](Get-ScriptObjectPropertyValue -Object $remoting -Name $addressName -DefaultValue $GuestRemotingAddress)
            $script:GuestRemotingPort = [int](Get-ScriptObjectPropertyValue -Object $remoting -Name $portName -DefaultValue $GuestRemotingPort)
            $script:GuestRemotingUseSsl = [bool](Get-ScriptObjectPropertyValue -Object $remoting -Name $sslName -DefaultValue $GuestRemotingUseSsl)
            $script:GuestRemotingAuthentication = [string](Get-ScriptObjectPropertyValue -Object $remoting -Name $authenticationName -DefaultValue $GuestRemotingAuthentication)
            $script:GuestRemotingSkipCertificateChecks = [bool](Get-ScriptObjectPropertyValue -Object $remoting -Name $skipCertificateName -DefaultValue $GuestRemotingSkipCertificateChecks)
            if ($automaticGuestRemotingMigrated) {
                $script:GuestRemotingUseSsl = $true
                $script:GuestRemotingSkipCertificateChecks = $true
            }
            elseif ($loadedAddressMode -ne 'Configured') {
                if (-not $sslPropertyPresent) { $script:GuestRemotingUseSsl = $true }
                if (-not $skipCertificatePropertyPresent -and [bool]$GuestRemotingUseSsl) { $script:GuestRemotingSkipCertificateChecks = $true }
            }
        }
    }
    catch {
        Write-ScriptInstallInfo "无法载入已有 $VirtualizationProvider 本机 profile，将保留当前值。详情：$($_.Exception.Message)"
    }
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
        if (-not $Json) {
            Write-ScriptInstallInfo "中文提示：无法读取安装状态 '$statePath'，将忽略并继续。下一步：如配置异常，普通用户请重新运行 .\scripts\install.ps1 并按推荐安装向导修复；自动化可使用 CreateOrPreparePath 参数。英文详情：$($_.Exception.Message)"
        }
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

        $current = Get-Variable -Name $entry.Key -Scope Script -ValueOnly
        $value = Get-ScriptStateString -State $State -Name $entry.Value -DefaultValue $current
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
            $script:GuestRemotingUseSsl = $true
        }
        if (-not $BoundParameters.ContainsKey('GuestRemotingSkipCertificateChecks') -and
            ($automaticGuestRemotingMigrated -or $skipCertificateStateMissing) -and
            [bool]$GuestRemotingUseSsl) {
            $script:GuestRemotingSkipCertificateChecks = $true
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

function Resolve-ScriptExecutablePath {
    param([AllowNull()][string]$ConfiguredPath)

    if ([string]::IsNullOrWhiteSpace($ConfiguredPath)) { return $null }
    if (Test-Path -LiteralPath $ConfiguredPath -PathType Leaf) {
        return [System.IO.Path]::GetFullPath($ConfiguredPath)
    }
    $command = Get-Command -Name $ConfiguredPath -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $command) { return $null }
    return [string]$command.Source
}

function Invoke-ScriptReadOnlyProviderCommand {
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
        return [pscustomobject][ordered]@{ Output = @($output); ExitCode = $LASTEXITCODE }
    }
    finally {
        foreach ($item in $savedEnvironment.GetEnumerator()) {
            [Environment]::SetEnvironmentVariable([string]$item.Key, [string]$item.Value, 'Process')
        }
    }
}

function Select-ScriptHyperVVmAndCheckpointInteractive {
    Write-Host ''
    Write-Host 'Hyper-V VM/快照选择 / Hyper-V VM/checkpoint selection'
    Write-Host '中文提示：这里只执行只读 Get-VM/Get-VMSnapshot；不会启动、停止、还原或修改 VM。 / Read-only selection only.'

    $getVmCommand = Get-Command Get-VM -ErrorAction SilentlyContinue
    if ($null -eq $getVmCommand) {
        Write-ScriptInstallInfo '未找到 Hyper-V PowerShell 模块；将回退到手动输入 VM/checkpoint。 / Hyper-V module unavailable; falling back to manual entry.'
        return
    }

    $vms = @()
    try {
        $vms = @(Get-VM -ErrorAction Stop | Sort-Object -Property Name)
    }
    catch {
        Write-ScriptInstallInfo "无法列出 Hyper-V VM；将回退到手动输入。详情：$($_.Exception.Message)"
        return
    }

    if ($vms.Count -eq 0) {
        Write-ScriptInstallInfo '未发现 Hyper-V VM；请手动输入现有黄金 VM 名称。 / No Hyper-V VMs found; please enter the existing golden VM name manually.'
        return
    }

    Write-Host '可用 VM / Available VMs:'
    for ($i = 0; $i -lt $vms.Count; $i++) {
        $vm = $vms[$i]
        Write-Host ("  {0}) {1}  状态/State={2}" -f ($i + 1), $vm.Name, $vm.State)
    }
    Write-Host '  0) 保留当前值/手动输入 / Keep current or enter manually'

    $allowed = @('0') + @(1..$vms.Count | ForEach-Object { [string]$_ })
    $choice = Read-ScriptMenuChoice -Prompt '请选择 VM [0-N] / Choose VM [0-N]' -Allowed $allowed
    if ($choice -eq '0') {
        return
    }

    $selectedVm = $vms[[int]$choice - 1]
    $script:VmName = $selectedVm.Name
    Write-ScriptInstallInfo "已选择 VM：$VmName / Selected VM."

    $getSnapshotCommand = Get-Command Get-VMSnapshot -ErrorAction SilentlyContinue
    if ($null -eq $getSnapshotCommand) {
        Write-ScriptInstallInfo '未找到 Get-VMSnapshot；checkpoint 将手动输入。 / Get-VMSnapshot unavailable; checkpoint will be entered manually.'
        return
    }

    $snapshots = @()
    try {
        $snapshots = @(Get-VMSnapshot -VMName $VmName -ErrorAction Stop | Sort-Object -Property CreationTime -Descending)
    }
    catch {
        Write-ScriptInstallInfo "无法列出 VM '$VmName' 的 checkpoint/snapshot；将回退到手动输入。详情：$($_.Exception.Message)"
        return
    }

    if ($snapshots.Count -eq 0) {
        Write-ScriptInstallInfo "VM '$VmName' 没有可选 checkpoint/snapshot；请手动输入或先创建 clean checkpoint。"
        return
    }

    Write-Host "VM '$VmName' 的 checkpoint/snapshot:"
    for ($i = 0; $i -lt $snapshots.Count; $i++) {
        $snapshot = $snapshots[$i]
        Write-Host ("  {0}) {1}  创建/Create={2:u}" -f ($i + 1), $snapshot.Name, $snapshot.CreationTime)
    }
    Write-Host '  0) 保留当前值/手动输入 / Keep current or enter manually'

    $checkpointAllowed = @('0') + @(1..$snapshots.Count | ForEach-Object { [string]$_ })
    $checkpointChoice = Read-ScriptMenuChoice -Prompt '请选择 clean checkpoint [0-N] / Choose clean checkpoint [0-N]' -Allowed $checkpointAllowed
    if ($checkpointChoice -eq '0') {
        return
    }

    $script:CheckpointName = $snapshots[[int]$checkpointChoice - 1].Name
    Write-ScriptInstallInfo "已选择 checkpoint：$CheckpointName / Selected checkpoint."
}

function Select-ScriptVMwareVmxAndSnapshotInteractive {
    Write-Host ''
    Write-Host 'VMware VMX/快照选择 / VMware VMX/snapshot selection'
    Write-Host '中文提示：这里只执行只读 vmrun list/listSnapshots；不会启动、停止、还原或修改 VM。 / Read-only selection only.'

    $vmrun = Resolve-ScriptExecutablePath -ConfiguredPath $VMwareVmrunPath
    if ([string]::IsNullOrWhiteSpace($vmrun)) {
        Write-ScriptInstallInfo '未找到 vmrun；将回退到手动输入 VMX/snapshot。 / vmrun unavailable; falling back to manual entry.'
        return
    }

    $candidatePaths = [System.Collections.Generic.List[string]]::new()
    if (Test-Path -LiteralPath $VMwareVmxPath -PathType Leaf) {
        [void]$candidatePaths.Add((Resolve-Path -LiteralPath $VMwareVmxPath).ProviderPath)
    }
    try {
        $runningResult = Invoke-ScriptReadOnlyProviderCommand -FilePath $vmrun -ArgumentList @('-T', 'ws', 'list')
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
            Write-ScriptInstallInfo "vmrun list 返回退出码 $($runningResult.ExitCode)；仍可使用当前 VMX 或手动输入。"
        }
    }
    catch {
        Write-ScriptInstallInfo "无法列出运行中的 VMware VM；仍可使用当前 VMX 或手动输入。详情：$($_.Exception.Message)"
    }

    $vmxCandidates = @($candidatePaths | Sort-Object -Unique)
    if ($vmxCandidates.Count -gt 0) {
        Write-Host '可用 VMX / Available VMX files:'
        for ($i = 0; $i -lt $vmxCandidates.Count; $i++) {
            Write-Host ("  {0}) {1}" -f ($i + 1), $vmxCandidates[$i])
        }
        Write-Host '  0) 保留当前值/手动输入 / Keep current or enter manually'
        $vmxAllowed = @('0') + @(1..$vmxCandidates.Count | ForEach-Object { [string]$_ })
        $vmxChoice = Read-ScriptMenuChoice -Prompt '请选择 VMX [0-N] / Choose VMX [0-N]' -Allowed $vmxAllowed
        if ($vmxChoice -ne '0') {
            $script:VMwareVmxPath = $vmxCandidates[[int]$vmxChoice - 1]
            Write-ScriptInstallInfo "已选择 VMX：$VMwareVmxPath / Selected VMX."
        }
    }
    else {
        Write-ScriptInstallInfo '没有发现当前或运行中的 VMX；请手动输入现有 Workstation Pro VMX 路径。 / No current or running VMX candidate was found.'
    }

    if (-not (Test-Path -LiteralPath $VMwareVmxPath -PathType Leaf)) { return }
    try {
        $resolvedVmxPath = (Resolve-Path -LiteralPath $VMwareVmxPath).ProviderPath
        $snapshotResult = Invoke-ScriptReadOnlyProviderCommand -FilePath $vmrun -ArgumentList @('-T', 'ws', 'listSnapshots', $resolvedVmxPath)
        if ($snapshotResult.ExitCode -ne 0) {
            Write-ScriptInstallInfo "vmrun listSnapshots 返回退出码 $($snapshotResult.ExitCode)；snapshot 将手动输入。"
            return
        }
        $snapshots = @($snapshotResult.Output |
            ForEach-Object { ([string]$_).Trim() } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and $_ -notmatch '^Total snapshots:\s*\d+$' } |
            Select-Object -Unique)
    }
    catch {
        Write-ScriptInstallInfo "无法列出 VMX '$VMwareVmxPath' 的 snapshot；将回退到手动输入。详情：$($_.Exception.Message)"
        return
    }

    if ($snapshots.Count -eq 0) {
        Write-ScriptInstallInfo "VMX '$VMwareVmxPath' 没有可选 snapshot；请手动输入或先创建 clean snapshot。"
        return
    }
    Write-Host "VMX '$VMwareVmxPath' 的 snapshot:"
    for ($i = 0; $i -lt $snapshots.Count; $i++) {
        Write-Host ("  {0}) {1}" -f ($i + 1), $snapshots[$i])
    }
    Write-Host '  0) 保留当前值/手动输入 / Keep current or enter manually'
    $snapshotAllowed = @('0') + @(1..$snapshots.Count | ForEach-Object { [string]$_ })
    $snapshotChoice = Read-ScriptMenuChoice -Prompt '请选择 clean snapshot [0-N] / Choose clean snapshot [0-N]' -Allowed $snapshotAllowed
    if ($snapshotChoice -ne '0') {
        $script:CheckpointName = $snapshots[[int]$snapshotChoice - 1]
        Write-ScriptInstallInfo "已选择 snapshot：$CheckpointName / Selected snapshot."
    }
}

function Select-ScriptQemuDiskMetadataAndSnapshotInteractive {
    Write-Host ''
    Write-Host 'QEMU 磁盘/基线选择 / QEMU disk/baseline selection'
    Write-Host '中文提示：这里只执行只读 qemu-img info --output=json；不会创建 overlay、还原 snapshot 或启动 VM。 / Read-only selection only.'

    $qemuImg = Resolve-ScriptExecutablePath -ConfiguredPath $QemuImgPath
    if ([string]::IsNullOrWhiteSpace($qemuImg) -or -not (Test-Path -LiteralPath $QemuDiskImagePath -PathType Leaf)) {
        Write-ScriptInstallInfo 'qemu-img 或基础磁盘不可用；磁盘格式/baseline 将手动输入。 / qemu-img or base disk unavailable; falling back to manual entry.'
        return
    }
    try {
        $imageResult = Invoke-ScriptReadOnlyProviderCommand -FilePath $qemuImg -ArgumentList @('info', '--output=json', $QemuDiskImagePath)
        if ($imageResult.ExitCode -ne 0) {
            Write-ScriptInstallInfo "qemu-img info 返回退出码 $($imageResult.ExitCode)；磁盘格式/baseline 将手动输入。"
            return
        }
        $imageInfo = ($imageResult.Output -join "`n") | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        Write-ScriptInstallInfo "无法读取 QEMU 磁盘 metadata；将回退到手动输入。详情：$($_.Exception.Message)"
        return
    }

    $actualFormat = [string]$imageInfo.format
    if ($actualFormat -in @('qcow2', 'raw', 'vhdx', 'vmdk')) {
        $script:QemuDiskFormat = $actualFormat
        Write-ScriptInstallInfo "已检测磁盘格式：$QemuDiskFormat / Detected disk format."
    }
    if ([bool]$QemuUseOverlayDisk) {
        Write-ScriptInstallInfo '当前使用 per-job overlay；干净基线由每次新建 overlay 保证，无需选择内部 snapshot。 / Per-job overlay supplies the clean baseline.'
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
        Write-ScriptInstallInfo "磁盘 '$QemuDiskImagePath' 没有可选内部 snapshot；请手动输入或先创建 clean snapshot。"
        return
    }
    Write-Host "磁盘 '$QemuDiskImagePath' 的内部 snapshot:"
    for ($i = 0; $i -lt $snapshots.Count; $i++) {
        Write-Host ("  {0}) {1}" -f ($i + 1), $snapshots[$i])
    }
    Write-Host '  0) 保留当前值/手动输入 / Keep current or enter manually'
    $snapshotAllowed = @('0') + @(1..$snapshots.Count | ForEach-Object { [string]$_ })
    $snapshotChoice = Read-ScriptMenuChoice -Prompt '请选择 clean internal snapshot [0-N] / Choose clean internal snapshot [0-N]' -Allowed $snapshotAllowed
    if ($snapshotChoice -ne '0') {
        $script:CheckpointName = $snapshots[[int]$snapshotChoice - 1]
        Write-ScriptInstallInfo "已选择内部 snapshot：$CheckpointName / Selected internal snapshot."
    }
}

function Invoke-ScriptVirtualizationConfigPrompt {
    Write-ScriptInstallInfo '仅配置本机虚拟化元数据；不会启动或还原 VM。 / Configuring local virtualization metadata only.'
    Write-Host '  1) Hyper-V'
    Write-Host '  2) VMware Workstation Pro'
    Write-Host '  3) QEMU'
    $providerChoice = Read-ScriptMenuChoice -Prompt '请选择虚拟化后端 [1-3] / Choose provider [1-3]' -Allowed @('1', '2', '3')
    $script:VirtualizationProvider = @{ '1' = 'HyperV'; '2' = 'VMware'; '3' = 'Qemu' }[$providerChoice]
    Import-ScriptSelectedVirtualizationProfile

    if ($VirtualizationProvider -eq 'HyperV') {
        Select-ScriptHyperVVmAndCheckpointInteractive
        $script:VmName = Read-ScriptOptionalText -Prompt 'Hyper-V 黄金 VM 名称 / Hyper-V golden VM name' -CurrentValue $VmName
        $script:CheckpointName = Read-ScriptOptionalText -Prompt '干净 checkpoint 名称 / Clean checkpoint name' -CurrentValue $CheckpointName
    }
    elseif ($VirtualizationProvider -eq 'VMware') {
        $script:VMwareVmrunPath = Read-ScriptOptionalText -Prompt 'vmrun.exe 路径或命令名 / vmrun path or command' -CurrentValue $VMwareVmrunPath
        $script:VMwareVmType = 'ws'
        $script:VMwareVmxPath = Read-ScriptOptionalText -Prompt 'VMX 文件路径 / VMX file path' -CurrentValue $VMwareVmxPath
        Select-ScriptVMwareVmxAndSnapshotInteractive
        $script:VmName = Read-ScriptOptionalText -Prompt 'VMware VM 显示名称 / VMware VM display name' -CurrentValue $VmName
        $script:CheckpointName = Read-ScriptOptionalText -Prompt '干净 snapshot 名称 / Clean snapshot name' -CurrentValue $CheckpointName
        $vmwareHeadlessChoice = Read-ScriptMenuChoice -Prompt 'VMware 使用无头 nogui 模式？[y/n] / Start VMware without a console? [y/n]' -Allowed @('y', 'Y', 'n', 'N')
        $script:VMwareHeadless = $vmwareHeadlessChoice -in @('y', 'Y')
    }
    else {
        $script:VmName = Read-ScriptOptionalText -Prompt 'QEMU VM 名称 / QEMU VM name' -CurrentValue $VmName
        $script:QemuDiskImagePath = Read-ScriptOptionalText -Prompt '基础磁盘镜像路径 / Base disk image path' -CurrentValue $QemuDiskImagePath
        $script:QemuSystemPath = Read-ScriptOptionalText -Prompt 'qemu-system 路径或命令名 / qemu-system path or command' -CurrentValue $QemuSystemPath
        $script:QemuImgPath = Read-ScriptOptionalText -Prompt 'qemu-img 路径或命令名 / qemu-img path or command' -CurrentValue $QemuImgPath
        Read-ScriptQemuAdditionalArguments
        $overlayChoice = Read-ScriptMenuChoice -Prompt '每个 job 使用一次性 overlay？[y/n] / Use disposable overlay? [y/n]' -Allowed @('y', 'Y', 'n', 'N')
        $script:QemuUseOverlayDisk = $overlayChoice -in @('y', 'Y')
        Select-ScriptQemuDiskMetadataAndSnapshotInteractive
        $script:QemuDiskFormat = Read-ScriptOptionalText -Prompt '磁盘格式 / Disk format' -CurrentValue $QemuDiskFormat
        $script:QemuDiskInterface = Read-ScriptOptionalText -Prompt '磁盘接口 (virtio/ide/scsi) / Disk interface' -CurrentValue $QemuDiskInterface
        $memoryText = Read-ScriptOptionalText -Prompt 'QEMU 内存 MB / QEMU memory in MB' -CurrentValue ([string]$QemuMemoryMegabytes)
        $parsedMemory = 0
        if (-not [int]::TryParse($memoryText, [ref]$parsedMemory) -or $parsedMemory -lt 256 -or $parsedMemory -gt 1048576) {
            throw "错误：QEMU 内存无效：$memoryText；应在 256 到 1048576 MB 之间。"
        }
        $script:QemuMemoryMegabytes = $parsedMemory
        $qemuHeadlessChoice = Read-ScriptMenuChoice -Prompt 'QEMU 使用无头模式？[y/n] / Start QEMU without a display? [y/n]' -Allowed @('y', 'Y', 'n', 'N')
        $script:QemuHeadless = $qemuHeadlessChoice -in @('y', 'Y')
        if (-not $QemuUseOverlayDisk) {
            $script:CheckpointName = Read-ScriptOptionalText -Prompt '内部干净 snapshot 名称 / Internal snapshot name' -CurrentValue $CheckpointName
        }
    }

    if ($VirtualizationProvider -ne 'HyperV') {
        if ($GuestRemotingAddressMode -eq 'Configured' -and [string]::IsNullOrWhiteSpace($GuestRemotingAddress)) {
            $script:GuestRemotingAddressMode = if ($VirtualizationProvider -eq 'VMware') { 'VMwareTools' } else { 'QemuUserNat' }
        }
        $script:GuestRemotingAddressMode = Read-ScriptOptionalText -Prompt 'Guest 端点模式 (Configured/VMwareTools/QemuUserNat) / Guest endpoint mode' -CurrentValue $GuestRemotingAddressMode
        $allowedModes = if ($VirtualizationProvider -eq 'VMware') { @('Configured', 'VMwareTools') } else { @('Configured', 'QemuUserNat') }
        if ($GuestRemotingAddressMode -notin $allowedModes) {
            throw "错误：$VirtualizationProvider 不支持 Guest 端点模式 '$GuestRemotingAddressMode'；可选：$($allowedModes -join ', ')。"
        }
        if ($GuestRemotingAddressMode -eq 'Configured') {
            $script:GuestRemotingAddress = Read-ScriptOptionalText -Prompt '来宾 WinRM 地址或主机名 / Guest WinRM address or host' -CurrentValue $GuestRemotingAddress
        }
        else {
            $script:GuestRemotingAddress = ''
            $modeDescription = if ($GuestRemotingAddressMode -eq 'VMwareTools') { 'VMware Tools 会在每次恢复后自动发现 Guest IP。' } else { 'QEMU 会管理 localhost user-NAT WinRM 端口转发。' }
            Write-ScriptInstallInfo $modeDescription
        }
        $automaticGuestEndpoint = $GuestRemotingAddressMode -ne 'Configured'
        if ($automaticGuestEndpoint) {
            $upgradingAutomaticHttp = -not [bool]$GuestRemotingUseSsl
            $script:GuestRemotingUseSsl = $true
            if ($upgradingAutomaticHttp) {
                $script:GuestRemotingSkipCertificateChecks = $true
            }
            Write-ScriptInstallInfo '自动端点模式固定使用 HTTPS，避免依赖宿主机全局 TrustedHosts。 / Automatic endpoints require HTTPS.'
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
        $portText = Read-ScriptOptionalText -Prompt $portPrompt -CurrentValue ([string]$GuestRemotingPort)
        $parsedPort = 0
        if (-not [int]::TryParse($portText, [ref]$parsedPort) -or $parsedPort -lt 0 -or $parsedPort -gt 65535) {
            throw "错误：WinRM 端口无效：$portText。"
        }
        $script:GuestRemotingPort = $parsedPort
        if (-not $automaticGuestEndpoint) {
            $sslChoice = Read-ScriptMenuChoice -Prompt 'WinRM 使用 HTTPS/SSL？[y/n] / Use HTTPS/SSL? [y/n]' -Allowed @('y', 'Y', 'n', 'N')
            $script:GuestRemotingUseSsl = $sslChoice -in @('y', 'Y')
        }
        $skipCertificateChoice = Read-ScriptMenuChoice -Prompt '跳过 WinRM 证书检查？[y/n] / Skip WinRM certificate checks? [y/n]' -Allowed @('y', 'Y', 'n', 'N')
        $script:GuestRemotingSkipCertificateChecks = $skipCertificateChoice -in @('y', 'Y')
        $script:GuestRemotingAuthentication = Read-ScriptOptionalText -Prompt 'WinRM 认证 / WinRM authentication' -CurrentValue $GuestRemotingAuthentication
    }

    $script:GuestUserName = Read-ScriptOptionalText -Prompt '来宾用户名 / Guest username' -CurrentValue $GuestUserName
    $script:GuestWorkingDirectory = Read-ScriptOptionalText -Prompt '来宾工作目录 / Guest working directory' -CurrentValue $GuestWorkingDirectory
    $script:RuntimeRoot = Read-ScriptOptionalText -Prompt '宿主机运行目录 / Host runtime root' -CurrentValue $RuntimeRoot
    $script:GuestPayloadRoot = Read-ScriptOptionalText -Prompt '宿主机 guest payload 目录 / Host guest payload root' -CurrentValue $GuestPayloadRoot
    $script:DriverHostPath = Read-ScriptOptionalText -Prompt '宿主机测试签名 R0 driver .sys 路径（留空=保留/不配置） / Host test-signed R0 driver path' -CurrentValue $DriverHostPath
    $script:LocalConfigPath = Read-ScriptOptionalText -Prompt '本机 sandbox 配置路径 / Local sandbox config path' -CurrentValue $LocalConfigPath

    Invoke-RootInstaller -Parameters (New-RootInstallerParameterTable -RootMode 'Change' -Additional @{
        UpdateVirtualizationConfig = $true
        VirtualizationProvider = $VirtualizationProvider
        VmName = $VmName
        CheckpointName = $CheckpointName
        VMwareVmxPath = $VMwareVmxPath
        VMwareVmrunPath = $VMwareVmrunPath
        VMwareVmType = $VMwareVmType
        VMwareHeadless = [bool]$VMwareHeadless
        QemuDiskImagePath = $QemuDiskImagePath
        QemuSystemPath = $QemuSystemPath
        QemuImgPath = $QemuImgPath
        QemuAdditionalArguments = @($QemuAdditionalArguments)
        QemuDiskFormat = $QemuDiskFormat
        QemuDiskInterface = $QemuDiskInterface
        QemuUseOverlayDisk = [bool]$QemuUseOverlayDisk
        QemuMemoryMegabytes = [int]$QemuMemoryMegabytes
        QemuHeadless = [bool]$QemuHeadless
        GuestRemotingAddress = $GuestRemotingAddress
        GuestRemotingAddressMode = $GuestRemotingAddressMode
        GuestRemotingPort = $GuestRemotingPort
        GuestRemotingUseSsl = [bool]$GuestRemotingUseSsl
        GuestRemotingSkipCertificateChecks = [bool]$GuestRemotingSkipCertificateChecks
        GuestRemotingAuthentication = $GuestRemotingAuthentication
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
        $actualResetLabel = if ($VirtualizationProvider -eq 'HyperV') { '自动离线重置 / automated offline reset' } elseif ($VirtualizationProvider -eq 'Qemu') { 'WinRM 或离线 VHDX/新 baseline / WinRM or offline recovery' } elseif ($VMwareVmType -eq 'ws') { 'WinRM 或 full-clone 离线 recovery / WinRM or offline recovery' } else { '需先迁移到 Workstation Pro / migrate to Workstation Pro first' }
        Write-Host "  2) 重置 VM 中实际来宾密码（$actualResetLabel） / Reset actual VM guest password"
        Write-Host '  3) 配置 Hyper-V、VMware 或 QEMU / Configure virtualization provider'
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
                $offlineRecovery = $false
                if ($VirtualizationProvider -eq 'Qemu' -or ($VirtualizationProvider -eq 'VMware' -and $VMwareVmType -eq 'ws')) {
                    Write-Host '  1) 知道当前密码：WinRM 轮换 / Current password known: WinRM rotation'
                    Write-Host '  2) 不知道当前密码：离线 VHDX recovery / Current password unknown: offline VHDX recovery'
                    $recoveryChoice = Read-ScriptMenuChoice -Prompt '请选择 [1-2] / Choose [1-2]' -Allowed @('1', '2')
                    $offlineRecovery = $recoveryChoice -eq '2'
                }
                $resetPermissionGuidance = if ($VirtualizationProvider -eq 'HyperV' -or $offlineRecovery) { '需管理员 PowerShell / requires elevated PowerShell' } else { '需当前账户具有 provider 和 WinRM 权限 / requires provider and WinRM permissions' }
                Write-Host "中文提示：此操作可能还原/启动/停止已配置 VM；请只在隔离实验宿主机继续，$resetPermissionGuidance。 / This can restore/start/stop the configured VM."
                $continue = Read-ScriptMenuChoice -Prompt '是否继续重置 VM 实际来宾密码？[y/n] / Continue actual VM guest password reset? [y/n]' -Allowed @('y', 'Y', 'n', 'N')
                if ($continue -in @('y', 'Y')) {
                    Invoke-RootInstaller -Parameters (New-RootInstallerParameterTable -RootMode 'Change' -Additional @{
                        ResetGuestVmPassword = $true
                        RecoverGuestVmPasswordWithoutCurrentSecret = $offlineRecovery
                        PromptPassword = $passwordMode.PromptPassword
                        GeneratePassword = $passwordMode.GeneratePassword
                        Force = $true
                    })
                }
            }
            '3' { Invoke-ScriptVirtualizationConfigPrompt }
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
    Write-Host '  1) 使用已配置环境（只诊断，不写本机状态，不修改 VM） / Use already configured environment'
    Write-Host '  2) 回退/恢复已有 clean baseline（Hyper-V checkpoint / VMware snapshot / QEMU internal snapshot；overlay 只确认干净启动） / Plan rollback/restore existing clean baseline'
    Write-Host '  3) 全新/新电脑本机准备（目录/config/secret，可选 payload；不创建 VM） / Fresh new-computer local preparation'
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

if ($script:InitialWrapperBoundParameters.Count -eq 0 -and $Mode -eq 'Interactive') {
    Invoke-RootInstaller -Parameters @{}
    return
}

if ($PreparePayload) {
    if (-not $Json) {
        Write-ScriptInstallInfo '中文提示：-PreparePayload 属于 CreateOrPreparePath 安装入口；将委托根安装器按创建/准备路径模式执行。 / PreparePayload routes through CreateOrPreparePath.'
    }
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
    [bool]$RecoverGuestVmPasswordWithoutCurrentSecret -or
    [bool]$UpdateHyperVConfig -or
    [bool]$UpdateVirtualizationConfig -or
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
