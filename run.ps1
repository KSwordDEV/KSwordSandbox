<#
.SYNOPSIS
Starts KSwordSandbox after local installation.

.DESCRIPTION
This is the operator-facing runtime entry point. Run install.ps1 once to prepare
local folders, virtualization provider config, and guest credentials; then run this script each
time you want to use the sandbox.

Default mode starts the local WebUI with the installed config:

  .\run.ps1

Single-sample CLI and environment-check modes are also available:

  .\run.ps1 -Mode Plan -SamplePath D:\Temp\sample.exe
  .\run.ps1 -Mode Analyze -SamplePath D:\Temp\sample.exe -Live
  .\run.ps1 -Mode Analyze -SamplePreset Notepad -Live -NoR0Collector
  .\run.ps1 -Mode Analyze -SamplePath D:\Temp\sample.exe -Live -NoOpenVmConsole
  .\run.ps1 -Mode Analyze -SamplePreset Notepad
  .\run.ps1 -Mode Analyze -SamplePreset HarmlessSample -Live
  .\run.ps1 -Mode CheckEnvironment

Passing -WhatIf previews WebUI/analysis launch decisions without preparing
payloads, starting dotnet, or delegating live provider execution.

The script loads C:\ProgramData\KSwordSandbox\install-state.json when present,
sets Sandbox__ConfigPath for the Web/API, mirrors the guest password from User
or Machine environment into the current process when available, and never prints
secret values. WebUI mode attempts self-contained guest payload preparation but
keeps the UI launchable when local build tools are not installed; use
-RequirePayloadForWebUI when payload preparation must be fatal.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [ValidateSet('WebUI', 'StartWebUI', 'Analyze', 'Plan', 'Status', 'CheckEnvironment')]
    [string]$Mode = 'WebUI',

    [string]$SamplePath = '',

    [ValidateSet('', 'Notepad', 'Sample', 'HarmlessSample')]
    [string]$SamplePreset = '',

    [int]$DurationSeconds = 120,

    [string]$Url = 'http://127.0.0.1:18080',

    [string]$ConfigPath = '',

    [string]$RuntimeRoot = '',

    [ValidateSet('', 'HyperV', 'VMware', 'Qemu')]
    [string]$Provider = '',

    [string]$VmName = '',

    [Alias('SnapshotName', 'CheckpointName')]
    [string]$BaselineName = '',

    [string]$MachineDefinitionPath = '',

    [ValidateSet('', 'qcow2', 'raw', 'vhdx', 'vmdk')]
    [string]$QemuDiskFormat = '',

    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    [int]$GuestReadyTimeoutSeconds = 180,

    [int]$ExecutionTimeoutSeconds = 240,

    [switch]$Live,

    # Disable Guest R0Collector sidecar for this one-shot Analyze/Plan run
    # without editing sandbox.local.json. Useful when the VM is otherwise ready
    # but the real driver is unsigned or test-signing is not configured.
    [switch]$NoR0Collector,

    # By default live analysis opens the selected provider's VM display.
    # Hyper-V uses VMConnect/RDP, VMware uses GUI mode, and QEMU keeps its
    # display enabled. Use this switch only for headless automation.
    [switch]$NoOpenVmConsole,

    [switch]$PlanOnly,

    [switch]$NoBuild,

    [switch]$SkipPayloadPreparation,

    [switch]$ForcePayloadPreparation,

    [switch]$OpenBrowser,

    [switch]$StrictUrl,

    [switch]$RequirePayloadForWebUI,

    [switch]$PassThru,

    [switch]$Json,

    [ValidateRange(4, 32)]
    [int]$JsonDepth = 12
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$script:RepositoryRoot = if ([string]::IsNullOrWhiteSpace($PSScriptRoot)) { (Get-Location).ProviderPath } else { $PSScriptRoot }
$script:InstallStatePath = Join-Path $env:ProgramData 'KSwordSandbox\install-state.json'
$script:WebConfigPathEnvironmentName = 'Sandbox__ConfigPath'
$script:ConfigPathWasExplicit = $PSBoundParameters.ContainsKey('ConfigPath')
$script:RequestedRunMode = $Mode
$script:EffectiveRunMode = $Mode
$script:RunModeCoerced = $false
$script:RunModeCoercionReason = ''
$script:RunModeCoercionTriggerParameter = ''
$script:RunModeCoercionOriginalMode = $Mode
$script:OriginalRunBoundParameters = [hashtable]$PSBoundParameters
$script:RunScriptPath = if ([string]::IsNullOrWhiteSpace($PSCommandPath)) { Join-Path $script:RepositoryRoot 'run.ps1' } else { $PSCommandPath }

function Write-RunInfo {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "[run] $Message"
}

function Read-InstallState {
    if (-not (Test-Path -LiteralPath $script:InstallStatePath -PathType Leaf)) {
        return $null
    }

    try {
        return Get-Content -LiteralPath $script:InstallStatePath -Raw | ConvertFrom-Json
    }
    catch {
        Write-RunInfo "中文提示：无法读取安装状态 '$script:InstallStatePath'，将忽略并继续。下一步：如配置异常，请重新运行 .\install.ps1 -InstallEntrypoint CreateOrPreparePath -PromptPassword。英文详情：$($_.Exception.Message)"
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

function Get-PackagedGuestPayloadRoot {
    $candidate = Join-Path $script:RepositoryRoot 'payload\guest-tools'
    $manifest = Join-Path $candidate 'payload-manifest.json'
    if (Test-Path -LiteralPath $manifest -PathType Leaf) {
        return [System.IO.Path]::GetFullPath($candidate)
    }

    return ''
}

function Get-DefaultGuestPayloadRoot {
    param([Parameter(Mandatory)][string]$EffectiveRuntimeRoot)

    $packagedPayloadRoot = Get-PackagedGuestPayloadRoot
    if (-not [string]::IsNullOrWhiteSpace($packagedPayloadRoot)) {
        return $packagedPayloadRoot
    }

    return [System.IO.Path]::GetFullPath((Join-Path $EffectiveRuntimeRoot 'payload\guest-tools'))
}

function Resolve-FullPathIfPresent {
    param([Parameter(Mandatory)][string]$Path)

    if (Test-Path -LiteralPath $Path) {
        return (Resolve-Path -LiteralPath $Path).ProviderPath
    }

    return [System.IO.Path]::GetFullPath($Path)
}

function Resolve-NotepadSamplePath {
    $candidates = New-Object System.Collections.Generic.List[string]
    foreach ($root in @($env:SystemRoot, $env:WINDIR)) {
        if ([string]::IsNullOrWhiteSpace($root)) {
            continue
        }

        [void]$candidates.Add((Join-Path $root 'System32\notepad.exe'))
        [void]$candidates.Add((Join-Path $root 'Sysnative\notepad.exe'))
        [void]$candidates.Add((Join-Path $root 'notepad.exe'))
    }

    $command = Get-Command notepad.exe -ErrorAction SilentlyContinue
    if ($null -ne $command -and -not [string]::IsNullOrWhiteSpace([string]$command.Source)) {
        [void]$candidates.Add([string]$command.Source)
    }

    foreach ($candidate in @($candidates.ToArray() | Select-Object -Unique)) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return (Resolve-Path -LiteralPath $candidate).ProviderPath
        }
    }

    throw '错误：找不到系统内置 Notepad 样本。下一步：请改用 -SamplePath <sample.exe> 指定一个 .exe，或检查 Windows 系统目录。'
}

function Resolve-HarmlessSamplePath {
    param([Parameter(Mandatory)][string]$EffectiveRuntimeRoot)

    $sampleRoot = Join-Path $EffectiveRuntimeRoot 'samples\KSword.Sandbox.HarmlessSample'
    $buildRoot = Join-Path $EffectiveRuntimeRoot 'build\KSword.Sandbox.HarmlessSample'
    $intermediateRoot = Join-Path $EffectiveRuntimeRoot 'obj\KSword.Sandbox.HarmlessSample'
    $sampleExe = Join-Path $sampleRoot 'KSword.Sandbox.HarmlessSample.exe'

    if (-not $ForcePayloadPreparation -and (Test-Path -LiteralPath $sampleExe -PathType Leaf)) {
        Write-RunInfo "使用内置 harmless sample：$sampleExe / Using built-in harmless sample."
        Write-RunInfo "中文提示：使用已准备好的 harmless sample；如需重新发布样本，请加 -ForcePayloadPreparation。"
        return (Resolve-Path -LiteralPath $sampleExe).ProviderPath
    }

    $prepareScript = Join-Path $script:RepositoryRoot 'scripts\Prepare-HarmlessSample.ps1'
    if (-not (Test-Path -LiteralPath $prepareScript -PathType Leaf)) {
        throw "错误：找不到 harmless sample 准备脚本：$prepareScript。下一步：请确认 scripts\Prepare-HarmlessSample.ps1 存在，并从仓库根目录运行。"
    }

    if ($WhatIfPreference) {
        [void]$PSCmdlet.ShouldProcess($sampleExe, "Prepare built-in harmless sample through '$prepareScript'")
        Write-RunInfo "预览：内置 harmless sample 会发布到仓库外：$sampleRoot。 / WhatIf: harmless sample would be published outside git."
        Write-RunInfo "中文提示：预览模式不会生成样本；实际 Analyze harmless sample 时会发布到运行目录，不写入仓库。"
        return [System.IO.Path]::GetFullPath($sampleExe)
    }

    if (-not $PSCmdlet.ShouldProcess($sampleExe, "Prepare built-in harmless sample through '$prepareScript'")) {
        throw '错误：内置 harmless sample 准备被取消。下一步：请提供 -SamplePath <sample.exe>，或重新运行并在确认提示中选择继续。'
    }

    Write-RunInfo "正在把内置 harmless sample 发布到仓库外：$sampleRoot / Preparing harmless sample outside git."
    Write-RunInfo "中文提示：正在发布内置 harmless sample，输出位于运行目录，不会写入仓库或打印凭据。"
    & powershell `
        -NoProfile `
        -ExecutionPolicy Bypass `
        -File $prepareScript `
        -RepositoryRoot $script:RepositoryRoot `
        -OutputRoot $sampleRoot `
        -BuildRoot $buildRoot `
        -IntermediateRoot $intermediateRoot `
        -Configuration $Configuration
    if ($LASTEXITCODE -ne 0) {
        throw "错误：harmless sample 准备失败，退出码 $LASTEXITCODE。下一步：确认已安装 .NET SDK，然后运行 .\scripts\Prepare-HarmlessSample.ps1 查看详细错误。"
    }
    if (-not (Test-Path -LiteralPath $sampleExe -PathType Leaf)) {
        throw "错误：harmless sample 可执行文件未生成：$sampleExe。下一步：检查上方 dotnet publish 输出，修复后重试。"
    }

    return (Resolve-Path -LiteralPath $sampleExe).ProviderPath
}

function Get-AnalysisSamplePreset {
    if (-not [string]::IsNullOrWhiteSpace($SamplePreset)) {
        return $SamplePreset
    }

    if ([string]::IsNullOrWhiteSpace($SamplePath)) {
        return ''
    }

    switch -Regex ($SamplePath.Trim()) {
        '^(notepad|notepad\.exe)$' { return 'Notepad' }
        '^(sample|harmlesssample|harmless-sample)$' { return 'HarmlessSample' }
        default { return '' }
    }
}

function Resolve-AnalysisSamplePath {
    param([Parameter(Mandatory)][string]$EffectiveRuntimeRoot)

    $preset = Get-AnalysisSamplePreset
    if (-not [string]::IsNullOrWhiteSpace($preset)) {
        switch ($preset.ToLowerInvariant()) {
            'notepad' {
                $notepadPath = Resolve-NotepadSamplePath
                Write-RunInfo "使用系统 Notepad 样本：$notepadPath / Using built-in Notepad sample."
                Write-RunInfo '中文提示：Analyze Notepad 使用系统 notepad.exe；不加 -Live 时只生成计划，不会启动/还原 VM。'
                return $notepadPath
            }
            { $_ -in @('sample', 'harmlesssample') } {
                return Resolve-HarmlessSamplePath -EffectiveRuntimeRoot $EffectiveRuntimeRoot
            }
        }
    }

    if ([string]::IsNullOrWhiteSpace($SamplePath)) {
        throw '错误：Analyze/Plan 模式需要 -SamplePath，或 -SamplePreset Notepad|HarmlessSample。下一步：例如运行 .\run.ps1 -Mode Analyze -SamplePreset Notepad。'
    }

    return Resolve-FullPathIfPresent -Path $SamplePath
}

function Get-EffectiveRuntimeRoot {
    param([AllowNull()]$State)

    if (-not [string]::IsNullOrWhiteSpace($RuntimeRoot)) {
        return [System.IO.Path]::GetFullPath($RuntimeRoot)
    }

    return [System.IO.Path]::GetFullPath((Get-StateString -State $State -Name 'runtimeRoot' -DefaultValue 'D:\Temp\KSwordSandbox'))
}

function Get-EffectiveConfigPath {
    param(
        [AllowNull()]$State,
        [Parameter(Mandatory)][string]$EffectiveRuntimeRoot
    )

    if (-not [string]::IsNullOrWhiteSpace($ConfigPath)) {
        return Resolve-FullPathIfPresent -Path $ConfigPath
    }

    $stateConfig = Get-StateString -State $State -Name 'localConfigPath' -DefaultValue ''
    if (-not [string]::IsNullOrWhiteSpace($stateConfig)) {
        return Resolve-FullPathIfPresent -Path $stateConfig
    }

    $envConfig = [Environment]::GetEnvironmentVariable($script:WebConfigPathEnvironmentName, 'Process')
    if ([string]::IsNullOrWhiteSpace($envConfig)) {
        $envConfig = [Environment]::GetEnvironmentVariable($script:WebConfigPathEnvironmentName, 'User')
    }
    if (-not [string]::IsNullOrWhiteSpace($envConfig)) {
        return Resolve-FullPathIfPresent -Path $envConfig
    }

    $runtimeConfig = Join-Path $EffectiveRuntimeRoot 'config\sandbox.local.json'
    if (Test-Path -LiteralPath $runtimeConfig -PathType Leaf) {
        return (Resolve-Path -LiteralPath $runtimeConfig).ProviderPath
    }

    return [System.IO.Path]::GetFullPath((Join-Path $script:RepositoryRoot 'config\sandbox.example.json'))
}

function Test-UsingRepositoryExampleConfigFallback {
    param([Parameter(Mandatory)][string]$EffectiveConfigPath)

    if ($script:ConfigPathWasExplicit) {
        return $false
    }

    $exampleConfigPath = [System.IO.Path]::GetFullPath((Join-Path $script:RepositoryRoot 'config\sandbox.example.json'))
    $effectiveFullPath = [System.IO.Path]::GetFullPath($EffectiveConfigPath)
    return [System.StringComparer]::OrdinalIgnoreCase.Equals($effectiveFullPath, $exampleConfigPath)
}

function Assert-RunLocalConfigReadyForInteractiveStartup {
    param(
        [Parameter(Mandatory)][string]$EffectiveConfigPath,
        [Parameter(Mandatory)][string]$ModeName
    )

    if ($script:ConfigPathWasExplicit) {
        return
    }

    $usesExampleFallback = Test-UsingRepositoryExampleConfigFallback -EffectiveConfigPath $EffectiveConfigPath
    $configExists = Test-Path -LiteralPath $EffectiveConfigPath -PathType Leaf
    if ($configExists -and -not $usesExampleFallback) {
        return
    }

    $reason = if ($usesExampleFallback) {
        '尚未找到本机 sandbox.local.json；当前只剩仓库模板 config\sandbox.example.json。'
    }
    else {
        "配置文件不存在：$EffectiveConfigPath"
    }

    Write-RunInfo '中文提示：本机配置未就绪，已停止启动，避免 WebUI/分析误用仓库模板。'
    Write-RunInfo '下一步：新电脑/缺配置时运行 .\install.ps1 -InstallEntrypoint CreateOrPreparePath -PromptPassword；已有 VM 时再运行 .\install.ps1 -Mode Change -UpdateVirtualizationConfig -VirtualizationProvider <HyperV|VMware|Qemu> 并填写对应 VM profile。'
    Write-RunInfo '下一步：若你以为已经配置完成，先运行 .\install.ps1 -InstallEntrypoint UseConfiguredEnvironment -PlanOnly 查看本机状态和 RecommendedActions。'
    Write-RunInfo '完成后重新运行 run.ps1；高级排障可使用 CheckEnvironment 模式。'
    throw "错误：$ModeName 需要本机 sandbox.local.json。$reason"
}

function Test-RunBaselineRestoreRequiresVmMutation {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('HyperV', 'VMware', 'Qemu')]
        [string]$Provider,

        [Parameter(Mandatory)]
        [bool]$UseQemuOverlayDisk
    )

    return $Provider -ne 'Qemu' -or -not $UseQemuOverlayDisk
}

function Get-RunOperatorModeMatrix {
    param(
        [ValidateSet('HyperV', 'VMware', 'Qemu')]
        [string]$Provider = 'HyperV',

        [bool]$UseQemuOverlayDisk = $false
    )

    $restoreRequiresMutation = Test-RunBaselineRestoreRequiresVmMutation -Provider $Provider -UseQemuOverlayDisk $UseQemuOverlayDisk
    $restoreWhatIfCommand = if ($restoreRequiresMutation) { '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -AllowVmMutation -WhatIf' } else { '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -WhatIf' }
    return @(
        [pscustomobject][ordered]@{
            ModeId = 'use-configured-environment'
            Entrypoint = 'UseConfiguredEnvironment'
            TitleZh = '使用已配置环境'
            RuntimeBehaviorZh = 'run.ps1 只读取已有本机配置/secret/payload/VM profile；默认启动 WebUI 或生成 PlanOnly。'
            SafeDiagnostics = @('.\install.ps1 -Mode Status', '.\install.ps1 -Mode CheckEnvironment', '.\run.ps1 -Mode Status', '.\run.ps1 -Mode CheckEnvironment')
            PrimaryRunCommand = '.\run.ps1'
            StartsVmByDefault = $false
            MutatesVmByDefault = $false
            RequiresLiveSwitchForVmMutation = $true
            NextStepsZh = @('下一步：确认 RecommendedActions 后运行 .\run.ps1；需要真实执行样本时才显式加 -Live。')
        },
        [pscustomobject][ordered]@{
            ModeId = 'rollback-restore-snapshot'
            Entrypoint = 'RestoreCleanCheckpoint'
            TitleZh = if ($restoreRequiresMutation) { '回退/恢复已有干净快照' } else { '确认 QEMU overlay 干净启动' }
            RuntimeBehaviorZh = if ($restoreRequiresMutation) { 'run.ps1 不直接恢复 snapshot；Analyze -Live 的 provider runbook 会在执行前恢复干净基线。' } else { 'QEMU per-job overlay 无需原地恢复；Analyze -Live 会从未修改基础盘创建新隔离层。' }
            SafeDiagnostics = @('.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -PlanOnly', $restoreWhatIfCommand, '.\install.ps1 -Mode CheckEnvironment')
            PrimaryRunCommand = '.\run.ps1 -Mode Analyze -SamplePath <sample.exe> -Live'
            StartsVmByDefault = $false
            MutatesVmByDefault = $false
            RequiresLiveSwitchForVmMutation = $true
            BaselineRestoreSatisfiedWithoutMutation = -not $restoreRequiresMutation
            BaselineIsolationMode = if ($restoreRequiresMutation) { 'provider-snapshot-restore' } else { 'qemu-per-job-overlay' }
            NextStepsZh = if ($restoreRequiresMutation) { @('下一步：恢复 baseline 请回到 install.ps1 的 RestoreCleanCheckpoint 入口；run.ps1 默认不会回退 VM。') } else { @('下一步：运行 CheckEnvironment 确认基础盘、QEMU 工具与 WHPX 就绪；无需先做原地 restore。') }
        },
        [pscustomobject][ordered]@{
            ModeId = 'fresh-create-new-computer'
            Entrypoint = 'CreateOrPreparePath'
            TitleZh = '全新创建/新电脑准备'
            RuntimeBehaviorZh = 'run.ps1 不是创建 VM 向导；缺配置时会 fail fast 并指向 CreateOrPreparePath。'
            SafeDiagnostics = @('.\install.ps1 -InstallEntrypoint CreateOrPreparePath -PlanOnly', '.\install.ps1 -InstallEntrypoint CreateOrPreparePath -WhatIf', '.\run.ps1 -Mode CheckEnvironment')
            PrimaryRunCommand = '.\run.ps1 -Mode Analyze -SamplePreset Notepad'
            StartsVmByDefault = $false
            MutatesVmByDefault = $false
            RequiresLiveSwitchForVmMutation = $true
            NextStepsZh = @('下一步：先完成 install.ps1 CreateOrPreparePath、本机 VM/clean baseline profile 和 payload；再用 run.ps1 做 WebUI/PlanOnly。')
        }
    )
}

function Get-RunModeResolution {
    [pscustomobject][ordered]@{
        Schema = 'ksword.run.mode-coercion.v1'
        RequestedMode = $script:RequestedRunMode
        EffectiveMode = $script:EffectiveRunMode
        ModeCoerced = [bool]$script:RunModeCoerced
        ModeCoercionReason = $script:RunModeCoercionReason
        ModeCoercionTriggerParameter = $script:RunModeCoercionTriggerParameter
        ModeCoercionOriginalMode = $script:RunModeCoercionOriginalMode
        MachineReadable = $true
    }
}

function Get-RunVmMutationPolicy {
    param(
        [ValidateSet('HyperV', 'VMware', 'Qemu')][string]$VirtualizationProvider = 'HyperV',
        [bool]$InteractiveConsoleEnabled = $true
    )

    $liveRequiresAdministrator = $VirtualizationProvider -eq 'HyperV'
    $interactiveConsoleRequested = $InteractiveConsoleEnabled -and (-not [bool]$NoOpenVmConsole)
    [pscustomobject][ordered]@{
        Schema = 'ksword.run.vm-mutation-policy.v1'
        VirtualizationProvider = $VirtualizationProvider
        DefaultMutatesVm = $false
        StatusMutatesVm = $false
        CheckEnvironmentMutatesVm = $false
        WebUiLaunchMutatesVm = $false
        WebUiDefaultMutatesVm = $false
        PlanMutatesVm = $false
        AnalyzePlanMutatesVm = $false
        AnalyzeWithoutLiveMutatesVm = $false
        AnalyzeLiveMayMutateVm = $true
        AnalyzeLiveMutationOperations = @('RestoreCleanBaseline', 'StartVm', 'CopyPayloadAndSampleIntoGuest', 'RunGuestAgent', 'StopVm', 'OptionalRestoreCleanBaselineAfterRun')
        LegacyAnalyzeLiveMutationOperations = @('RestoreCheckpoint', 'StartVm', 'CopyPayloadAndSampleIntoGuest', 'RunGuestAgent', 'StopVm', 'OptionalRestoreCheckpointAfterRun')
        RequiresExplicitLiveForVmMutation = $true
        LiveRequiresAdministrator = $liveRequiresAdministrator
        ProviderStepsRequireElevation = $liveRequiresAdministrator
        OpenVmConsoleOnLiveStartDefault = $InteractiveConsoleEnabled
        OpenVmConnectOnLiveStartDefault = $InteractiveConsoleEnabled
        OpenVmConsoleRequestedForThisInvocation = $interactiveConsoleRequested
        OpenVmConnectOnLiveStart = $interactiveConsoleRequested
        OpenVmConsoleIsBestEffort = $false
        OpenVmConsoleFailureBlocksHeadless = $interactiveConsoleRequested
        VmConsoleRequiredUnlessNoOpenVmConsole = $InteractiveConsoleEnabled
        DisableVmConsoleCommand = '.\run.ps1 -Mode Analyze -SamplePath <sample.exe> -Live -NoOpenVmConsole'
        MachineReadable = $true
    }
}

function New-RunReadinessVerdict {
    param(
        [ValidateSet('HyperV', 'VMware', 'Qemu')][string]$VirtualizationProvider = 'HyperV',
        [bool]$ConfigExists,
        [bool]$RuntimeRootExists,
        [bool]$RuntimeRootUnderRepository,
        [bool]$WebUiLaunchTargetReady,
        [bool]$ProviderExecutionToolReady = $true,
        [bool]$GuestPayloadRootExists,
        [bool]$GuestAgentPayloadExists,
        [bool]$R0CollectorPayloadExists,
        [bool]$GuestPayloadManifestExists,
        [bool]$GuestPayloadFresh,
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
        [bool]$VmExists,
        [bool]$CheckpointExists,
        [bool]$InteractiveConsoleEnabled = $true,
        [AllowNull()][object]$DriverStatus,
        [string[]]$RecommendedActions = @()
    )

    $blocking = New-Object System.Collections.Generic.List[string]
    $warnings = New-Object System.Collections.Generic.List[string]

    if (-not $ConfigExists) { [void]$blocking.Add('MissingLocalConfig') }
    if (-not $RuntimeRootExists) { [void]$warnings.Add('RuntimeRootMissing') }
    if ($RuntimeRootUnderRepository) { [void]$blocking.Add('RuntimeRootUnderRepository') }
    if (-not $WebUiLaunchTargetReady) { [void]$blocking.Add('MissingWebUiLaunchTarget') }
    if (-not $ProviderExecutionToolReady) { [void]$blocking.Add('MissingProviderExecutionTool') }
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

    $payloadFilesPresent = $GuestPayloadRootExists -and $GuestAgentPayloadExists -and $R0CollectorPayloadExists -and $GuestPayloadManifestExists
    if (-not $payloadFilesPresent) {
        [void]$blocking.Add('MissingGuestPayload')
    }
    elseif (-not $GuestPayloadFresh) {
        [void]$warnings.Add('GuestPayloadStaleOrUnverified')
    }

    $driverStatusName = if ($null -eq $DriverStatus) { '' } else { [string]$DriverStatus.Status }
    $driverLiveReady = $driverStatusName -in @('Ready', 'Mock', 'Disabled')
    if (-not $driverLiveReady) {
        [void]$blocking.Add("R0DriverConfiguration:$driverStatusName")
    }

    $webUiReady = $ConfigExists -and $WebUiLaunchTargetReady -and (-not $RuntimeRootUnderRepository)
    $planOnlyReady = $ConfigExists -and (-not $RuntimeRootUnderRepository)
    $liveReady = $planOnlyReady -and
        $ProviderExecutionToolReady -and
        $payloadFilesPresent -and
        $GuestPayloadFresh -and
        $GuestSecretSet -and
        $GuestTransportReady -and
        $ProviderManagementAvailable -and
        $ProviderQuerySucceeded -and
        $ProviderHostHardwareReady -and
        $ProviderConfigurationReady -and
        $VmExists -and
        $CheckpointExists -and
        $driverLiveReady
    $overallStatus = if ($liveReady) {
        'ReadyForLive'
    }
    elseif ($webUiReady -or $planOnlyReady) {
        'ReadyForNonLive'
    }
    else {
        'Blocked'
    }

    [pscustomobject][ordered]@{
        Schema = 'ksword.run.readiness-verdict.v1'
        VirtualizationProvider = $VirtualizationProvider
        ProviderManagementAvailable = $ProviderManagementAvailable
        ProviderQueryAttempted = $ProviderQueryAttempted
        ProviderQuerySucceeded = $ProviderQuerySucceeded
        ProviderAccessDenied = $ProviderAccessDenied
        ProviderDiagnosticCode = $ProviderDiagnosticCode
        ProviderDiagnosticMessage = $ProviderDiagnosticMessage
        ProviderHostHardwareReady = $ProviderHostHardwareReady
        ProviderConfigurationReady = $ProviderConfigurationReady
        ProviderExecutionToolReady = $ProviderExecutionToolReady
        GeneratedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
        MachineReadable = $true
        OverallStatus = $overallStatus
        WebUiReady = $webUiReady
        PlanOnlyReady = $planOnlyReady
        LiveReady = $liveReady
        BaselineExists = $CheckpointExists
        DefaultPathMutatesVm = $false
        WebUiMutatesVm = $false
        StatusMutatesVm = $false
        CheckEnvironmentMutatesVm = $false
        AnalyzeWithoutLiveMutatesVm = $false
        AnalyzeLiveMayMutateVm = $true
        RequiresExplicitLiveForVmMutation = $true
        OpenVmConsoleOnLiveStartDefault = $InteractiveConsoleEnabled
        OpenVmConnectOnLiveStart = ($InteractiveConsoleEnabled -and (-not [bool]$NoOpenVmConsole))
        OpenVmConsoleFailureBlocksHeadless = ($InteractiveConsoleEnabled -and (-not [bool]$NoOpenVmConsole))
        VmConsoleRequiredUnlessNoOpenVmConsole = $InteractiveConsoleEnabled
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

function Write-RunDiagnosticObject {
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

function Get-SecretName {
    param([AllowNull()]$State)
    return Get-StateString -State $State -Name 'secretName' -DefaultValue 'KSWORDBOX_GUEST_PASSWORD'
}

function Get-VirusTotalSecretName {
    param([AllowNull()]$State)
    return Get-StateString -State $State -Name 'virusTotalSecretName' -DefaultValue 'KSWORDBOX_VIRUSTOTAL_API_KEY'
}

function Import-UserOrMachineEnvironmentSecret {
    param([Parameter(Mandatory)][string]$Name)

    $processSecret = [Environment]::GetEnvironmentVariable($Name, 'Process')
    if (-not [string]::IsNullOrEmpty($processSecret)) {
        return
    }

    $candidate = [Environment]::GetEnvironmentVariable($Name, 'User')
    if ([string]::IsNullOrEmpty($candidate)) {
        $candidate = [Environment]::GetEnvironmentVariable($Name, 'Machine')
    }

    if (-not [string]::IsNullOrEmpty($candidate)) {
        [Environment]::SetEnvironmentVariable($Name, $candidate, 'Process')
        Set-Item -Path "Env:\$Name" -Value $candidate
    }
}

function Import-InstalledEnvironment {
    param(
        [AllowNull()]$State,
        [Parameter(Mandatory)][string]$EffectiveConfigPath
    )

    [Environment]::SetEnvironmentVariable($script:WebConfigPathEnvironmentName, $EffectiveConfigPath, 'Process')
    $env:Sandbox__ConfigPath = $EffectiveConfigPath

    $secretName = Get-SecretName -State $State
    Import-UserOrMachineEnvironmentSecret -Name $secretName
    Import-UserOrMachineEnvironmentSecret -Name (Get-VirusTotalSecretName -State $State)
}

function Read-SandboxConfig {
    param([Parameter(Mandatory)][string]$EffectiveConfigPath)

    if (-not (Test-Path -LiteralPath $EffectiveConfigPath -PathType Leaf)) {
        throw "错误：找不到 sandbox 配置：$EffectiveConfigPath。下一步：请先打开安装向导完成本机初始化；如果已经安装，请在更改设置里重新记录 VM 名称和干净快照。"
    }

    return Get-Content -LiteralPath $EffectiveConfigPath -Raw | ConvertFrom-Json
}

function Get-RunObjectPropertyValue {
    param(
        [AllowNull()]$Object,
        [Parameter(Mandatory)][string]$Name,
        [object]$DefaultValue = $null
    )

    if ($null -eq $Object) {
        return $DefaultValue
    }

    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) {
        return $DefaultValue
    }

    return $property.Value
}

function Get-RunBooleanOrDefault {
    param(
        [object]$Value,
        [bool]$DefaultValue
    )

    if ($null -eq $Value) {
        return $DefaultValue
    }

    return [System.Convert]::ToBoolean($Value)
}

function Resolve-RunConfigPath {
    param([AllowNull()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath((Join-Path $script:RepositoryRoot $Path))
}

function Import-PortableToolResolver {
    $resolver = Join-Path $script:RepositoryRoot 'scripts\Resolve-PortableTool.ps1'
    if (-not (Test-Path -LiteralPath $resolver -PathType Leaf)) {
        throw "错误：找不到 portable tool resolver：$resolver。下一步：请确认 scripts\Resolve-PortableTool.ps1 已随源码/便携包提供。"
    }

    . $resolver
}

function Get-WebUiLaunchTarget {
    param([bool]$ThrowIfMissing = $true)

    $projectPath = Join-Path $script:RepositoryRoot 'src\KSword.Sandbox.Web\KSword.Sandbox.Web.csproj'
    $publishedRoot = Join-Path $script:RepositoryRoot 'app\host-web'
    $publishedExe = Join-Path $publishedRoot 'KSword.Sandbox.Web.exe'
    $publishedDll = Join-Path $publishedRoot 'KSword.Sandbox.Web.dll'
    $projectExists = Test-Path -LiteralPath $projectPath -PathType Leaf
    $publishedExeExists = Test-Path -LiteralPath $publishedExe -PathType Leaf
    $publishedDllExists = Test-Path -LiteralPath $publishedDll -PathType Leaf

    if ($projectExists) {
        return [pscustomobject][ordered]@{
            Kind = 'SourceProject'
            Path = $projectPath
            SourceProjectPath = $projectPath
            SourceProjectExists = $true
            PublishedWebRoot = $publishedRoot
            PublishedExeExists = $publishedExeExists
            PublishedDllExists = $publishedDllExists
            RequiresDotNet = $true
            SupportsNoBuild = $true
            RecommendedAction = ''
        }
    }

    if ($publishedExeExists) {
        return [pscustomobject][ordered]@{
            Kind = 'PublishedExe'
            Path = $publishedExe
            SourceProjectPath = $projectPath
            SourceProjectExists = $false
            PublishedWebRoot = $publishedRoot
            PublishedExeExists = $true
            PublishedDllExists = $publishedDllExists
            RequiresDotNet = $false
            SupportsNoBuild = $false
            RecommendedAction = ''
        }
    }

    if ($publishedDllExists) {
        return [pscustomobject][ordered]@{
            Kind = 'PublishedDll'
            Path = $publishedDll
            SourceProjectPath = $projectPath
            SourceProjectExists = $false
            PublishedWebRoot = $publishedRoot
            PublishedExeExists = $false
            PublishedDllExists = $true
            RequiresDotNet = $true
            SupportsNoBuild = $false
            RecommendedAction = '下一步：如这是便携包，请确认 app\host-web 来自发布流水线；如这是源码仓库，请确认 src\KSword.Sandbox.Web 项目存在。'
        }
    }

    $missing = [pscustomobject][ordered]@{
        Kind = 'Missing'
        Path = $null
        SourceProjectPath = $projectPath
        SourceProjectExists = $false
        PublishedWebRoot = $publishedRoot
        PublishedExeExists = $false
        PublishedDllExists = $false
        RequiresDotNet = $null
        SupportsNoBuild = $false
        RecommendedAction = '下一步：源码运行请保留 src\KSword.Sandbox.Web；便携运行请把发布输出放在 app\host-web 后再执行 .\run.ps1。'
    }

    if ($ThrowIfMissing) {
        throw "错误：找不到 WebUI 启动目标。源码项目缺失：$projectPath；便携发布目录缺失：$publishedRoot。$($missing.RecommendedAction)"
    }

    return $missing
}

function Test-RunIsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function ConvertTo-RunNativeArgument {
    param([AllowNull()][string]$Argument)

    if ($null -eq $Argument) {
        return '""'
    }

    if ($Argument -notmatch '[\s"]') {
        return $Argument
    }

    $escaped = $Argument -replace '(\\*)"', '$1$1\"'
    $escaped = $escaped -replace '(\\+)$', '$1$1'
    return '"' + $escaped + '"'
}

function Add-RunRelaunchStringArgument {
    param(
        [Parameter(Mandatory)][System.Collections.Generic.List[string]]$Arguments,
        [Parameter(Mandatory)][string]$Name,
        [AllowNull()][string]$Value,
        [bool]$IncludeWhenEmpty = $false
    )

    if ($IncludeWhenEmpty -or -not [string]::IsNullOrWhiteSpace([string]$Value)) {
        [void]$Arguments.Add("-$Name")
        [void]$Arguments.Add([string]$Value)
    }
}

function Add-RunRelaunchSwitchArgument {
    param(
        [Parameter(Mandatory)][System.Collections.Generic.List[string]]$Arguments,
        [Parameter(Mandatory)][string]$Name,
        [bool]$Enabled
    )

    if ($Enabled) {
        [void]$Arguments.Add("-$Name")
    }
}

function Invoke-RunSelfElevatedForLive {
    param([Parameter(Mandatory)][string]$ResolvedSamplePath)

    $powershellPath = (Get-Command -Name 'powershell.exe' -ErrorAction Stop | Select-Object -First 1).Source
    $arguments = [System.Collections.Generic.List[string]]::new()
    [void]$arguments.Add('-NoProfile')
    [void]$arguments.Add('-ExecutionPolicy')
    [void]$arguments.Add('Bypass')
    [void]$arguments.Add('-File')
    [void]$arguments.Add($script:RunScriptPath)
    Add-RunRelaunchStringArgument -Arguments $arguments -Name 'Mode' -Value $Mode -IncludeWhenEmpty $true
    Add-RunRelaunchStringArgument -Arguments $arguments -Name 'SamplePath' -Value $ResolvedSamplePath -IncludeWhenEmpty $true
    Add-RunRelaunchStringArgument -Arguments $arguments -Name 'DurationSeconds' -Value ([string]$DurationSeconds) -IncludeWhenEmpty $true
    Add-RunRelaunchStringArgument -Arguments $arguments -Name 'GuestReadyTimeoutSeconds' -Value ([string]$GuestReadyTimeoutSeconds) -IncludeWhenEmpty $true
    Add-RunRelaunchStringArgument -Arguments $arguments -Name 'ExecutionTimeoutSeconds' -Value ([string]$ExecutionTimeoutSeconds) -IncludeWhenEmpty $true
    Add-RunRelaunchStringArgument -Arguments $arguments -Name 'Configuration' -Value $Configuration -IncludeWhenEmpty $true
    Add-RunRelaunchStringArgument -Arguments $arguments -Name 'Provider' -Value $Provider -IncludeWhenEmpty $false
    Add-RunRelaunchStringArgument -Arguments $arguments -Name 'VmName' -Value $VmName -IncludeWhenEmpty $false
    Add-RunRelaunchStringArgument -Arguments $arguments -Name 'BaselineName' -Value $BaselineName -IncludeWhenEmpty $false
    Add-RunRelaunchStringArgument -Arguments $arguments -Name 'MachineDefinitionPath' -Value $MachineDefinitionPath -IncludeWhenEmpty $false
    Add-RunRelaunchStringArgument -Arguments $arguments -Name 'QemuDiskFormat' -Value $QemuDiskFormat -IncludeWhenEmpty $false

    if ($script:OriginalRunBoundParameters.ContainsKey('SamplePreset')) {
        Add-RunRelaunchStringArgument -Arguments $arguments -Name 'SamplePreset' -Value $SamplePreset -IncludeWhenEmpty $true
    }

    if ($script:OriginalRunBoundParameters.ContainsKey('Url')) {
        Add-RunRelaunchStringArgument -Arguments $arguments -Name 'Url' -Value $Url -IncludeWhenEmpty $true
    }

    if ($script:OriginalRunBoundParameters.ContainsKey('ConfigPath')) {
        Add-RunRelaunchStringArgument -Arguments $arguments -Name 'ConfigPath' -Value $ConfigPath -IncludeWhenEmpty $true
    }

    if ($script:OriginalRunBoundParameters.ContainsKey('RuntimeRoot')) {
        Add-RunRelaunchStringArgument -Arguments $arguments -Name 'RuntimeRoot' -Value $RuntimeRoot -IncludeWhenEmpty $true
    }

    Add-RunRelaunchSwitchArgument -Arguments $arguments -Name 'Live' -Enabled ([bool]$Live)
    Add-RunRelaunchSwitchArgument -Arguments $arguments -Name 'NoR0Collector' -Enabled ([bool]$NoR0Collector)
    Add-RunRelaunchSwitchArgument -Arguments $arguments -Name 'NoOpenVmConsole' -Enabled ([bool]$NoOpenVmConsole)
    Add-RunRelaunchSwitchArgument -Arguments $arguments -Name 'NoBuild' -Enabled ([bool]$NoBuild)
    Add-RunRelaunchSwitchArgument -Arguments $arguments -Name 'SkipPayloadPreparation' -Enabled ([bool]$SkipPayloadPreparation)
    Add-RunRelaunchSwitchArgument -Arguments $arguments -Name 'ForcePayloadPreparation' -Enabled ([bool]$ForcePayloadPreparation)
    Add-RunRelaunchSwitchArgument -Arguments $arguments -Name 'OpenBrowser' -Enabled ([bool]$OpenBrowser)
    Add-RunRelaunchSwitchArgument -Arguments $arguments -Name 'StrictUrl' -Enabled ([bool]$StrictUrl)
    Add-RunRelaunchSwitchArgument -Arguments $arguments -Name 'RequirePayloadForWebUI' -Enabled ([bool]$RequirePayloadForWebUI)

    $argumentLine = ($arguments.ToArray() | ForEach-Object { ConvertTo-RunNativeArgument -Argument $_ }) -join ' '
    Write-RunInfo 'Live Hyper-V 需要管理员权限；正在触发 UAC 提权并重新启动同一命令。 / Requesting administrator via UAC for Live Hyper-V.'
    Write-RunInfo "UAC 通过后，新管理员窗口会继续运行，并在样本执行前打开 VM 桌面：$ResolvedSamplePath"

    try {
        $process = Start-Process -FilePath $powershellPath -ArgumentList $argumentLine -Verb RunAs -WorkingDirectory $script:RepositoryRoot -WindowStyle Normal -PassThru -Wait
    }
    catch {
        throw "错误：UAC 提权启动失败或被取消；样本尚未启动。下一步：批准 UAC 或手动以管理员身份运行同一命令。英文详情：$($_.Exception.Message)"
    }

    if ($null -ne $process) {
        Write-RunInfo "管理员子进程已退出，ExitCode=$($process.ExitCode)。 / Elevated child process exited."
        exit $process.ExitCode
    }

    exit 0
}

function Test-RunPathUnderRoot {
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

function Get-RunWindowsFeatureState {
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

function Get-RunHyperVPrerequisiteStatus {
    $actions = [System.Collections.Generic.List[string]]::new()
    $featureStates = [ordered]@{}
    $inspectionErrors = [System.Collections.Generic.List[string]]::new()
    $osIsWindows = [System.StringComparer]::OrdinalIgnoreCase.Equals([string]$env:OS, 'Windows_NT')
    $powerShellModuleAvailable = $null -ne (Get-Command Get-VM -ErrorAction SilentlyContinue)
    $optionalFeatureCommandAvailable = $null -ne (Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue)
    $cimAvailable = $null -ne (Get-Command Get-CimInstance -ErrorAction SilentlyContinue)
    $hypervisorPresent = $null
    $virtualizationFirmwareEnabled = $null
    $slatSupported = $null
    $vmMonitorModeExtensions = $null

    if (-not $osIsWindows) {
        [void]$actions.Add('下一步：Live Hyper-V 需要 Windows 宿主机；当前环境只能做 WebUI/报告/打包/PlanOnly。')
    }
    if (-not $powerShellModuleAvailable) {
        [void]$actions.Add('下一步：启用 Hyper-V PowerShell 管理工具，然后运行 .\run.ps1 -Mode CheckEnvironment；本检查不会启动或还原 VM。')
    }

    if ($osIsWindows) {
        foreach ($featureName in @('Microsoft-Hyper-V-All', 'Microsoft-Hyper-V-Management-PowerShell')) {
            $featureResult = Get-RunWindowsFeatureState -FeatureName $featureName
            $featureStates[$featureName] = [string]$featureResult.State
            if ($featureResult.State -ne 'Enabled' -and $featureResult.State -ne 'Unknown') {
                [void]$actions.Add("下一步：启用 Windows Optional Feature '$featureName'（管理员权限/重启），再重新检查。")
            }
            elseif ($featureResult.State -eq 'Unknown') {
                [void]$inspectionErrors.Add("无法读取 Windows feature $featureName：$($featureResult.Error)")
                [void]$actions.Add("下一步：以管理员身份确认 Windows Optional Feature '$featureName'；未确认前不把 Hyper-V 视为 Live-ready。")
            }
        }
    }

    if ($cimAvailable) {
        try {
            $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
            $hypervisorPresent = [bool]$computerSystem.HypervisorPresent
        }
        catch {
            [void]$inspectionErrors.Add("无法读取 HypervisorPresent：$($_.Exception.Message)")
        }

        try {
            $processor = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1
            if ($null -ne $processor) {
                $virtualizationProperty = $processor.PSObject.Properties['VirtualizationFirmwareEnabled']
                if ($null -ne $virtualizationProperty) {
                    $virtualizationFirmwareEnabled = [bool]$virtualizationProperty.Value
                    if (-not $virtualizationFirmwareEnabled -and $hypervisorPresent -ne $true) {
                        [void]$actions.Add('下一步：在 BIOS/UEFI 启用 Intel VT-x/AMD-V 虚拟化，冷重启后再运行 CheckEnvironment。')
                    }
                }

                $slatProperty = $processor.PSObject.Properties['SecondLevelAddressTranslationExtensions']
                if ($null -ne $slatProperty) {
                    $slatSupported = [bool]$slatProperty.Value
                    if (-not $slatSupported) {
                        [void]$actions.Add('下一步：Hyper-V 需要 SLAT/EPT/NPT；请换用支持二级地址转换的宿主 CPU。')
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
        IsAdministrator = Test-RunIsAdministrator
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
        ChineseGuidance = '中文提示：运行时 Hyper-V 前置诊断只读；不会启动、还原、停止或修改 VM。'
    }
}

function Get-RunProviderHostPrerequisiteStatus {
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
        [void]$actions.Add("下一步：KSwordSandbox $Provider Live 需要 Windows 宿主机；当前环境只能做 WebUI、报告、打包或 PlanOnly。")
    }

    if ($cimAvailable) {
        try {
            $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
            $hypervisorPresent = [bool]$computerSystem.HypervisorPresent
        }
        catch {
            [void]$inspectionErrors.Add("无法读取 HypervisorPresent：$($_.Exception.Message)")
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
        $requiredFeatureResult = Get-RunWindowsFeatureState -FeatureName $requiredWindowsFeature
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
        AcceleratorExpectation = if ($Provider -eq 'VMware') { 'VMware hardware acceleration' } else { 'QEMU WHPX hardware acceleration' }
        RequiredWindowsFeature = $requiredWindowsFeature
        RequiredWindowsFeatureState = $requiredWindowsFeatureState
        RequiredWindowsFeatureReady = $requiredWindowsFeatureReady
        InspectionErrors = @($inspectionErrors.ToArray())
        RecommendedActions = @($actions.ToArray())
        StartsOrMutatesVm = $false
        ChineseGuidance = "中文提示：$Provider 宿主硬件虚拟化检查只读；不会启动、还原、停止或修改 VM。"
    }
}

function Get-RunHostTestSigningStatus {
    $status = [ordered]@{
        State = 'Unavailable'
        Message = ''
        RawOutput = @()
    }

    if ($null -eq (Get-Command bcdedit.exe -ErrorAction SilentlyContinue)) {
        $status.Message = 'bcdedit.exe is not available on this host.'
        return [pscustomobject]$status
    }

    try {
        $rawOutput = @(& bcdedit.exe /enum '{current}' 2>&1)
        $status.RawOutput = @($rawOutput)
        $joined = $rawOutput -join "`n"
        if ($joined -match '(?im)^\s*testsigning\s+(Yes|On|True)\s*$') {
            $status.State = 'Enabled'
        }
        elseif ($joined -match '(?im)^\s*testsigning\s+(No|Off|False)\s*$') {
            $status.State = 'Disabled'
        }
        else {
            $status.State = 'Disabled'
            $status.Message = 'testsigning entry was not present in bcdedit output; treating as disabled.'
        }
    }
    catch {
        $status.State = 'Unknown'
        $status.Message = $_.Exception.Message
    }

    return [pscustomobject]$status
}

function Get-RunVmProfileStatus {
    param(
        [Parameter(Mandatory)][string]$VmName,
        [Parameter(Mandatory)][string]$CheckpointName
    )

    $hyperVModuleAvailable = $null -ne (Get-Command Get-VM -ErrorAction SilentlyContinue)
    $actions = [System.Collections.Generic.List[string]]::new()
    $profile = [ordered]@{
        Provider = 'HyperV'
        VmName = $VmName
        ExpectedBaselineName = $CheckpointName
        ExpectedCheckpointName = $CheckpointName
        HyperVModuleAvailable = $hyperVModuleAvailable
        ManagementAvailable = $hyperVModuleAvailable
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
        DiagnosticCode = if ($hyperVModuleAvailable) { 'HYPERV_NOT_QUERIED' } else { 'HYPERV_CMDLET_MISSING' }
        DiagnosticMessage = if ($hyperVModuleAvailable) { 'Hyper-V profile has not been queried.' } else { 'Hyper-V PowerShell management cmdlets were not found.' }
        Error = $null
        RecommendedActions = @()
    }

    if (-not $hyperVModuleAvailable) {
        [void]$actions.Add('下一步：启用/安装 Hyper-V PowerShell 工具，然后重新运行 .\run.ps1 -Mode CheckEnvironment；该命令不会启动或还原 VM。')
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
            [void]$actions.Add("下一步：确认 VM '$VmName' 存在，或运行 .\install.ps1 -Mode Change -UpdateHyperVConfig -VmName <existing VM> -CheckpointName <checkpoint> 更新本机 VM profile。")
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
            [void]$actions.Add("下一步：运行 .\install.ps1 -Mode Change -UpdateHyperVConfig -VmName '$VmName' -CheckpointName <checkpoint> 记录正确 clean checkpoint，或先在 Hyper-V 中创建 checkpoint '$CheckpointName'。")
        }

        if ($null -ne (Get-Command Get-VMIntegrationService -ErrorAction SilentlyContinue)) {
            $guestService = Get-VMIntegrationService -VMName $VmName -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -in @('Guest Service Interface', '来宾服务接口') -or $_.Name -match '(?i)Guest\s+Service|来宾服务' } |
                Select-Object -First 1
            if ($null -ne $guestService) {
                $profile.GuestServiceInterfaceEnabled = [bool]$guestService.Enabled
                if (-not $profile.GuestServiceInterfaceEnabled) {
                    [void]$actions.Add("下一步：Live 前建议启用 Guest Service Interface：Enable-VMIntegrationService -VMName '$VmName' -Name 'Guest Service Interface'。")
                }
            }
        }
        }
    }
    catch {
        $profile.Error = $_.Exception.Message
        $profile.AccessDenied = Test-RunProviderAccessDenied -Message $profile.Error
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

function Resolve-RunExecutablePath {
    param([AllowNull()][string]$ConfiguredPath)

    if ([string]::IsNullOrWhiteSpace($ConfiguredPath)) { return $null }
    if (Test-Path -LiteralPath $ConfiguredPath -PathType Leaf) {
        return [System.IO.Path]::GetFullPath($ConfiguredPath)
    }
    $command = Get-Command -Name $ConfiguredPath -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $command) { return $null }
    return [string]$command.Source
}

function Test-RunProviderAccessDenied {
    param([AllowNull()][string]$Message)

    if ([string]::IsNullOrWhiteSpace($Message)) { return $false }
    return $Message -match '(?i)(access denied|access is denied|permission denied|unauthorized|eacces|0x80070005|拒绝访问|访问被拒绝)'
}

function Get-RunExpectedQemuProcessVmName {
    param(
        [Parameter(Mandatory)][string]$ConfiguredVmName,
        [Parameter(Mandatory)][string]$PidFilePath,
        [Parameter(Mandatory)][bool]$UseOverlayDisk
    )

    $normalizedPrefix = $ConfiguredVmName.Trim()
    if (-not $UseOverlayDisk) {
        return $normalizedPrefix
    }

    $jobIdentity = Split-Path -Leaf (Split-Path -Parent $PidFilePath)
    if ($jobIdentity -notmatch '^[0-9a-fA-F]{32}$') {
        return ''
    }

    $suffix = "-$($jobIdentity.ToLowerInvariant())"
    $maximumPrefixLength = 64 - $suffix.Length
    if ($normalizedPrefix.EndsWith($suffix, [System.StringComparison]::OrdinalIgnoreCase)) {
        $normalizedPrefix = $normalizedPrefix.Substring(0, $normalizedPrefix.Length - $suffix.Length).TrimEnd('-')
    }
    if ($normalizedPrefix.Length -gt $maximumPrefixLength) {
        $normalizedPrefix = $normalizedPrefix.Substring(0, $maximumPrefixLength)
    }

    return "$normalizedPrefix$suffix"
}

function Test-RunQemuCommandLineVmName {
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

function Get-RunActiveQemuPids {
    param(
        [Parameter(Mandatory)][object]$Config,
        [AllowNull()][string]$ResolvedQemuSystemPath
    )

    if ([string]::IsNullOrWhiteSpace($ResolvedQemuSystemPath)) { return @() }
    $expectedProcessName = [System.IO.Path]::GetFileName($ResolvedQemuSystemPath)
    $expectedExecutablePath = [System.IO.Path]::GetFullPath($ResolvedQemuSystemPath)
    $qemuConfig = Get-RunObjectPropertyValue -Object $Config -Name 'qemu' -DefaultValue $null
    $configuredVmName = ([string](Get-RunObjectPropertyValue -Object $qemuConfig -Name 'vmName' -DefaultValue '')).Trim()
    $useOverlayDisk = [bool](Get-RunObjectPropertyValue -Object $qemuConfig -Name 'useOverlayDisk' -DefaultValue $true)
    $vmsRoot = [System.IO.Path]::GetFullPath((Join-Path ([string]$Config.paths.runtimeRoot) 'vms'))
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
        $expectedProcessVmName = Get-RunExpectedQemuProcessVmName -ConfiguredVmName $configuredVmName -PidFilePath $pidFile.FullName -UseOverlayDisk $useOverlayDisk
        if (-not [string]::IsNullOrWhiteSpace($candidateExecutablePath) -and
            $candidateExecutablePath.Equals($expectedExecutablePath, [System.StringComparison]::OrdinalIgnoreCase) -and
            -not [string]::IsNullOrWhiteSpace($commandLine) -and
            $commandLine.IndexOf($pidFile.FullName, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -and
            $commandLine.IndexOf($jobRoot, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -and
            (Test-RunQemuCommandLineVmName -CommandLine $commandLine -ExpectedVmName $expectedProcessVmName)) {
            [void]$activePids.Add($qemuPid)
        }
    }

    return @($activePids.ToArray())
}

function Test-RunQemuProcessOwnsUserNatPort {
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

function Invoke-RunProviderReadOnlyCommand {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [AllowEmptyCollection()][string[]]$ArgumentList = @(),
        [AllowEmptyCollection()][string[]]$ExplicitSecretNames = @()
    )

    $savedEnvironment = [ordered]@{}
    $environment = [Environment]::GetEnvironmentVariables('Process')
    foreach ($nameValue in @($environment.Keys)) {
        $name = [string]$nameValue
        $isExplicitSecret = @($ExplicitSecretNames | Where-Object { $name.Equals([string]$_, [System.StringComparison]::OrdinalIgnoreCase) }).Count -gt 0
        if ($isExplicitSecret -or
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

function Test-RunQemuWhpxAdditionalArguments {
    param(
        [AllowEmptyCollection()][object[]]$Arguments = @(),
        [ValidateSet('Configured', 'VMwareTools', 'QemuUserNat')][string]$GuestAddressMode = 'Configured'
    )

    Assert-RunQemuManagedAdditionalArguments -Arguments $Arguments -GuestAddressMode $GuestAddressMode
    $acceleratorConfigured = $false
    for ($index = 0; $index -lt @($Arguments).Count; $index++) {
        $argument = ([string]$Arguments[$index]).Trim()
        $acceleratorValue = $null
        if ($argument.Equals('-accel', [System.StringComparison]::OrdinalIgnoreCase)) {
            $index++
            if ($index -ge @($Arguments).Count) {
                throw "QEMU additionalArguments '-accel' requires 'whpx'."
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
                    throw "QEMU additionalArguments '$argument' requires a machine value."
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
                throw "QEMU additionalArguments '$argument' requires a machine value."
            }
        }

        if ($null -eq $acceleratorValue) {
            continue
        }
        $accelerator = @(([string]$acceleratorValue) -split ',', 2)[0].Trim()
        if (-not $accelerator.Equals('whpx', [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "QEMU accelerator '$accelerator' is not supported for Hyper-V-equivalent Windows live execution; use '-accel whpx'. TCG software emulation is not provider parity."
        }
        $acceleratorConfigured = $true
    }

    return $acceleratorConfigured
}

function Assert-RunQemuManagedAdditionalArguments {
    param(
        [AllowEmptyCollection()][object[]]$Arguments = @(),
        [ValidateSet('Configured', 'VMwareTools', 'QemuUserNat')][string]$GuestAddressMode = 'Configured'
    )

    for ($index = 0; $index -lt @($Arguments).Count; $index++) {
        $argument = ([string]$Arguments[$index]).Trim()
        $option = @($argument -split '=', 2)[0].Trim()
        if ($option -cin @('-name', '-m', '-memory', '-pidfile', '-display')) {
            throw "QEMU additionalArguments cannot set '$option'; VM identity, memory, PID ownership, and display mode are managed by the provider profile."
        }
        if ($argument -cin @('-daemonize', '-snapshot', '-nographic', '-curses', '-S')) {
            throw "QEMU additionalArguments cannot contain '$argument' because it bypasses provider lifecycle, baseline, or interactive-console guarantees."
        }

        $driveValue = $null
        if ($argument -ceq '-drive') {
            if ($index + 1 -ge @($Arguments).Count -or [string]::IsNullOrWhiteSpace([string]$Arguments[$index + 1])) {
                throw "QEMU additionalArguments '-drive' requires a non-empty drive value."
            }
            $driveValue = [string]$Arguments[$index + 1]
        }
        elseif ($argument.StartsWith('-drive=', [System.StringComparison]::Ordinal)) {
            $driveValue = $argument.Substring('-drive='.Length)
        }
        if ($null -ne $driveValue -and @($driveValue -split ',' | Where-Object {
                    ([string]$_).Trim().Equals('id=ksword-disk', [System.StringComparison]::OrdinalIgnoreCase)
                }).Count -gt 0) {
            throw 'QEMU additionalArguments cannot define a second drive with id=ksword-disk; that disk identity is provider-managed.'
        }
        if ($argument.IndexOf('id=ksword-scsi', [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -or
            $argument.IndexOf('bus=ksword-scsi.0', [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -or
            $argument.IndexOf('drive=ksword-disk', [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            throw 'QEMU additionalArguments cannot reuse id=ksword-scsi, bus=ksword-scsi.0, or drive=ksword-disk; the managed SCSI topology is provider-owned.'
        }
        if ($GuestAddressMode -eq 'QemuUserNat' -and
            ($argument.IndexOf('id=ksword-net', [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -or
             $argument.IndexOf('netdev=ksword-net', [System.StringComparison]::OrdinalIgnoreCase) -ge 0)) {
            throw 'QEMU additionalArguments cannot reuse id/netdev=ksword-net in QemuUserNat mode; the provider owns that NIC and WinRM forwarding rule.'
        }
    }
}

function Get-RunProviderProfileStatus {
    param(
        [Parameter(Mandatory)][object]$Config,
        [Parameter(Mandatory)][ValidateSet('HyperV', 'VMware', 'Qemu')][string]$Provider
    )

    if ($Provider -eq 'HyperV') {
        return Get-RunVmProfileStatus -VmName ([string]$Config.hyperV.goldenVmName) -CheckpointName ([string]$Config.hyperV.goldenSnapshotName)
    }

    $actions = [System.Collections.Generic.List[string]]::new()
    $isVmware = $Provider -eq 'VMware'
    $sectionName = if ($isVmware) { 'vmware' } else { 'qemu' }
    $providerConfig = Get-RunObjectPropertyValue -Object $Config -Name $sectionName
    $guestConfig = Get-RunObjectPropertyValue -Object $Config -Name 'guest'
    $guestSecretName = [string](Get-RunObjectPropertyValue -Object $guestConfig -Name 'passwordSecretName' -DefaultValue 'KSWORDBOX_GUEST_PASSWORD')
    $vmName = [string](Get-RunObjectPropertyValue -Object $providerConfig -Name 'vmName' -DefaultValue 'KSwordSandbox-Win10-Golden')
    $snapshotName = [string](Get-RunObjectPropertyValue -Object $providerConfig -Name 'snapshotName' -DefaultValue 'Clean')
    $machineProperty = if ($isVmware) { 'vmxPath' } else { 'diskImagePath' }
    $machinePath = [string](Get-RunObjectPropertyValue -Object $providerConfig -Name $machineProperty -DefaultValue '')
    $primaryConfigured = if ($isVmware) {
        [string](Get-RunObjectPropertyValue -Object $providerConfig -Name 'vmrunPath' -DefaultValue 'vmrun.exe')
    }
    else {
        [string](Get-RunObjectPropertyValue -Object $providerConfig -Name 'qemuSystemPath' -DefaultValue 'qemu-system-x86_64.exe')
    }
    $primaryTool = Resolve-RunExecutablePath -ConfiguredPath $primaryConfigured
    $secondaryTool = if ($isVmware) {
        $null
    }
    else {
        Resolve-RunExecutablePath -ConfiguredPath ([string](Get-RunObjectPropertyValue -Object $providerConfig -Name 'qemuImgPath' -DefaultValue 'qemu-img.exe'))
    }
    $managementAvailable = -not [string]::IsNullOrWhiteSpace($primaryTool) -and ($isVmware -or -not [string]::IsNullOrWhiteSpace($secondaryTool))
    $exists = -not [string]::IsNullOrWhiteSpace($machinePath) -and (Test-Path -LiteralPath $machinePath -PathType Leaf)
    $providerRemoting = Get-RunObjectPropertyValue -Object $providerConfig -Name 'guestRemoting' -DefaultValue $null
    $legacyGuestAddress = [string](Get-RunObjectPropertyValue -Object $guestConfig -Name 'powerShellRemotingAddress' -DefaultValue '')
    $automaticGuestRemotingMigrated = $null -eq $providerRemoting -and [string]::IsNullOrWhiteSpace($legacyGuestAddress)
    $defaultAddressMode = if ($automaticGuestRemotingMigrated) {
        if ($isVmware) { 'VMwareTools' } else { 'QemuUserNat' }
    }
    else {
        'Configured'
    }
    $guestRemotingAddressMode = [string](Get-RunObjectPropertyValue -Object $providerRemoting -Name 'addressMode' -DefaultValue $defaultAddressMode)
    $automaticGuestEndpoint = $guestRemotingAddressMode -ne 'Configured'
    $guestRemotingSslConfigured = $null -ne $providerRemoting -and $null -ne $providerRemoting.PSObject.Properties['useSsl']
    $guestRemotingSkipCertificateChecksConfigured = $null -ne $providerRemoting -and $null -ne $providerRemoting.PSObject.Properties['skipCertificateChecks']
    $guestRemotingAddress = [string](Get-RunObjectPropertyValue -Object $providerRemoting -Name 'address' -DefaultValue '')
    if ($guestRemotingAddressMode -eq 'Configured' -and [string]::IsNullOrWhiteSpace($guestRemotingAddress)) {
        $providerRemoting = $guestConfig
        $guestRemotingAddress = $legacyGuestAddress
        $guestRemotingPort = [int](Get-RunObjectPropertyValue -Object $guestConfig -Name 'powerShellRemotingPort' -DefaultValue 0)
        $guestRemotingUseSsl = [bool](Get-RunObjectPropertyValue -Object $guestConfig -Name 'powerShellRemotingUseSsl' -DefaultValue $false)
        $guestRemotingAuthentication = [string](Get-RunObjectPropertyValue -Object $guestConfig -Name 'powerShellRemotingAuthentication' -DefaultValue 'Negotiate')
        $guestRemotingSkipCertificateChecks = [bool](Get-RunObjectPropertyValue -Object $guestConfig -Name 'powerShellRemotingSkipCertificateChecks' -DefaultValue $false)
    }
    else {
        $guestRemotingPort = [int](Get-RunObjectPropertyValue -Object $providerRemoting -Name 'port' -DefaultValue 0)
        $guestRemotingUseSsl = [bool](Get-RunObjectPropertyValue -Object $providerRemoting -Name 'useSsl' -DefaultValue ($automaticGuestEndpoint -and -not $guestRemotingSslConfigured))
        $guestRemotingAuthentication = [string](Get-RunObjectPropertyValue -Object $providerRemoting -Name 'authentication' -DefaultValue 'Negotiate')
        $guestRemotingSkipCertificateChecks = [bool](Get-RunObjectPropertyValue -Object $providerRemoting -Name 'skipCertificateChecks' -DefaultValue ($automaticGuestEndpoint -and $guestRemotingUseSsl -and -not $guestRemotingSkipCertificateChecksConfigured))
    }
    $guestRemotingAddressSource = 'configured'
    $guestAddressModeValid = ($isVmware -and $guestRemotingAddressMode -in @('Configured', 'VMwareTools')) -or
        ((-not $isVmware) -and $guestRemotingAddressMode -in @('Configured', 'QemuUserNat'))
    switch ($guestRemotingAddressMode) {
        'VMwareTools' {
            $guestRemotingAddress = ''
            $guestRemotingAddressSource = 'vmware-tools-auto-discovery'
            $guestTransportReady = $isVmware
        }
        'QemuUserNat' {
            $guestRemotingAddress = '127.0.0.1'
            if ($guestRemotingPort -le 0) { $guestRemotingPort = if ($guestRemotingUseSsl) { 55986 } else { 55985 } }
            $guestRemotingAddressSource = 'provider-managed-user-nat'
            $guestTransportReady = -not $isVmware
        }
        default {
            $guestTransportReady = $guestAddressModeValid -and -not [string]::IsNullOrWhiteSpace($guestRemotingAddress)
        }
    }
    $headless = [bool](Get-RunObjectPropertyValue -Object $providerConfig -Name 'headless' -DefaultValue $false)
    $memoryMegabytes = if ($isVmware) { $null } else { [int](Get-RunObjectPropertyValue -Object $providerConfig -Name 'memoryMegabytes' -DefaultValue 4096) }
    $checkpointExists = $false
    $state = if ($exists) { 'Configured' } else { $null }
    $errorMessage = $null
    $queryAttempted = $false
    $querySucceeded = $false
    $accessDenied = $false
    $diagnosticCode = if (-not $managementAvailable) {
        if ($isVmware) { 'VMWARE_VMRUN_MISSING' } else { 'QEMU_MANAGEMENT_TOOLS_MISSING' }
    }
    elseif (-not $exists) {
        if ($isVmware) { 'VMWARE_VMX_MISSING' } else { 'QEMU_DISK_MISSING' }
    }
    else {
        if ($isVmware) { 'VMWARE_NOT_QUERIED' } else { 'QEMU_NOT_QUERIED' }
    }
    $diagnosticMessage = if (-not $managementAvailable) {
        "$Provider management tools were not found."
    }
    elseif (-not $exists) {
        "Configured $Provider machine definition was not found: $machinePath"
    }
    else {
        "$Provider profile has not been queried."
    }
    $configurationReady = $true
    $guestRemotingPortAvailable = $null
    $activeQemuOwnsGuestRemotingPort = $null
    $accelerator = $null
    $acceleratorSource = $null
    $vmType = if ($isVmware) {
        ([string](Get-RunObjectPropertyValue -Object $providerConfig -Name 'vmType' -DefaultValue 'ws')).Trim().ToLowerInvariant()
    }
    else { $null }
    $qemuDiskInterface = if (-not $isVmware) {
        ([string](Get-RunObjectPropertyValue -Object $providerConfig -Name 'diskInterface' -DefaultValue 'virtio')).Trim().ToLowerInvariant()
    }
    else { $null }

    if ($isVmware -and $vmType -ne 'ws') {
        $configurationReady = $false
        $errorMessage = "Full VMware parity requires Workstation Pro with vmware.vmType=ws; configured value is '$vmType'."
        [void]$actions.Add('下一步：安装 VMware Workstation Pro，把 vmware.vmType 改为 ws，然后重新运行 CheckEnvironment；Player 配置不能进入 Live。')
    }
    if (-not $isVmware -and $qemuDiskInterface -notin @('virtio', 'ide', 'scsi')) {
        $configurationReady = $false
        $qemuInterfaceError = "qemu.diskInterface '$qemuDiskInterface' is invalid; use virtio, ide, or scsi. if=none leaves the provider-managed disk unattached."
        $errorMessage = if ([string]::IsNullOrWhiteSpace($errorMessage)) { $qemuInterfaceError } else { "$errorMessage | $qemuInterfaceError" }
        [void]$actions.Add('下一步：把 qemu.diskInterface 改为 virtio、ide 或 scsi，并确认 Windows guest 已安装对应存储控制器驱动。')
    }

    if (-not $guestAddressModeValid) {
        $configurationReady = $false
        $errorMessage = "$Provider guestRemoting.addressMode '$guestRemotingAddressMode' is invalid for this provider."
        [void]$actions.Add("下一步：VMware 使用 Configured/VMwareTools；QEMU 使用 Configured/QemuUserNat。")
    }
    if ($guestRemotingAddressMode -ne 'Configured' -and -not $guestRemotingUseSsl) {
        $configurationReady = $false
        $errorMessage = if ([string]::IsNullOrWhiteSpace($errorMessage)) { 'Automatic guest endpoint modes require WinRM HTTPS.' } else { "$errorMessage | Automatic guest endpoint modes require WinRM HTTPS." }
        [void]$actions.Add('下一步：为 VMwareTools/QemuUserNat 设置 guestRemoting.useSsl=true；自动 IP/loopback 端点不依赖宿主机全局 TrustedHosts。')
    }

    if (-not $isVmware) {
        try {
            $additionalArguments = @(Get-RunObjectPropertyValue -Object $providerConfig -Name 'additionalArguments' -DefaultValue @())
            $accelerator = 'whpx'
            $acceleratorSource = if (Test-RunQemuWhpxAdditionalArguments -Arguments $additionalArguments -GuestAddressMode $guestRemotingAddressMode) { 'configured' } else { 'core-default' }
        }
        catch {
            $configurationReady = $false
            $accelerator = 'unsupported'
            $acceleratorSource = 'invalid-config'
            $errorMessage = if ([string]::IsNullOrWhiteSpace($errorMessage)) { $_.Exception.Message } else { "$errorMessage | $($_.Exception.Message)" }
            [void]$actions.Add('下一步：把 qemu.additionalArguments accelerator 改为 ["-accel","whpx"]；TCG 不计作与 Hyper-V 等价的 Live。')
        }
    }
    if ($guestRemotingAuthentication -eq 'Basic' -and -not $guestRemotingUseSsl) {
        $configurationReady = $false
        $errorMessage = if ([string]::IsNullOrWhiteSpace($errorMessage)) { 'Basic WinRM over HTTP is refused.' } else { "$errorMessage | Basic WinRM over HTTP is refused." }
        [void]$actions.Add('下一步：为 Basic WinRM 启用 HTTPS，或改用 Negotiate/CredSSP。')
    }
    if ($guestRemotingSkipCertificateChecks -and -not $guestRemotingUseSsl) {
        $configurationReady = $false
        $errorMessage = if ([string]::IsNullOrWhiteSpace($errorMessage)) { 'guestRemoting.skipCertificateChecks requires HTTPS.' } else { "$errorMessage | guestRemoting.skipCertificateChecks requires HTTPS." }
        [void]$actions.Add('下一步：只在 guestRemoting.useSsl=true 时启用 skipCertificateChecks。')
    }

    if (-not $managementAvailable) { [void]$actions.Add("下一步：安装或配置 $Provider 管理工具，然后重新运行 CheckEnvironment。") }
    if (-not $exists) { [void]$actions.Add("下一步：在 install.ps1 中配置现有 $Provider VM 定义/磁盘路径：$machinePath。") }
    if (-not $guestTransportReady) { [void]$actions.Add("下一步：为 $Provider 选择有效 guestRemoting.addressMode；Configured 模式还需填写 address。") }

    if ($managementAvailable -and $exists -and (-not $isVmware -or $vmType -eq 'ws')) {
        $queryAttempted = $true
        try {
            if ($isVmware) {
                $resolvedMachinePath = (Resolve-Path -LiteralPath $machinePath).ProviderPath
                $snapshotResult = Invoke-RunProviderReadOnlyCommand -FilePath $primaryTool -ArgumentList @('-T', $vmType, 'listSnapshots', $resolvedMachinePath) -ExplicitSecretNames @($guestSecretName)
                $snapshotOutput = @($snapshotResult.Output)
                $snapshotExitCode = $snapshotResult.ExitCode
                if ($snapshotExitCode -ne 0) {
                    throw "vmrun listSnapshots failed with exit code $snapshotExitCode. $($snapshotOutput -join ' ')"
                }
                $checkpointExists = @($snapshotOutput | ForEach-Object { ([string]$_).Trim() }) -contains $snapshotName
                $runningResult = Invoke-RunProviderReadOnlyCommand -FilePath $primaryTool -ArgumentList @('-T', $vmType, 'list') -ExplicitSecretNames @($guestSecretName)
                $runningOutput = @($runningResult.Output)
                $runningExitCode = $runningResult.ExitCode
                if ($runningExitCode -ne 0) {
                    throw "vmrun list failed with exit code $runningExitCode. $($runningOutput -join ' ')"
                }
                $state = if (@($runningOutput | ForEach-Object { ([string]$_).Trim() }) -contains $resolvedMachinePath) { 'Running' } else { 'Stopped' }
                $querySucceeded = $true
                $diagnosticCode = if ($checkpointExists) { 'VMWARE_QUERY_OK' } else { 'VMWARE_SNAPSHOT_NOT_FOUND' }
                $diagnosticMessage = if ($checkpointExists) { 'VMware VMX and configured snapshot were detected.' } else { "Configured VMware snapshot '$snapshotName' was not found." }
            }
            else {
                $activeQemuPids = @(Get-RunActiveQemuPids -Config $Config -ResolvedQemuSystemPath $primaryTool)
                $activeQemuProcessAmbiguous = $activeQemuPids.Count -gt 1
                $activeQemuPid = if ($activeQemuPids.Count -eq 1) { [int]$activeQemuPids[0] } else { $null }
                $state = if ($activeQemuProcessAmbiguous) { 'Ambiguous' } elseif ($null -ne $activeQemuPid) { 'Running' } else { 'Configured' }
                $snapshotResult = Invoke-RunProviderReadOnlyCommand -FilePath $secondaryTool -ArgumentList @('info', '--output=json', $machinePath) -ExplicitSecretNames @($guestSecretName)
                $snapshotOutput = @($snapshotResult.Output)
                if ($snapshotResult.ExitCode -ne 0) {
                    throw "qemu-img info failed with exit code $($snapshotResult.ExitCode). $($snapshotOutput -join ' ')"
                }
                $snapshotInfo = ($snapshotOutput -join "`n") | ConvertFrom-Json -ErrorAction Stop
                $actualFormat = [string](Get-RunObjectPropertyValue -Object $snapshotInfo -Name 'format' -DefaultValue '')
                $configuredFormat = [string](Get-RunObjectPropertyValue -Object $providerConfig -Name 'diskFormat' -DefaultValue 'qcow2')
                if (-not $actualFormat.Equals($configuredFormat, [System.StringComparison]::OrdinalIgnoreCase)) {
                    throw "Configured QEMU disk format '$configuredFormat' does not match qemu-img format '$actualFormat'."
                }
                $useOverlayDisk = [bool](Get-RunObjectPropertyValue -Object $providerConfig -Name 'useOverlayDisk' -DefaultValue $true)
                if (-not $useOverlayDisk -and -not $actualFormat.Equals('qcow2', [System.StringComparison]::OrdinalIgnoreCase)) {
                    throw "QEMU internal snapshot mode requires qcow2; detected '$actualFormat'. Enable per-job overlay mode for this base image."
                }
                if ($useOverlayDisk) {
                    $checkpointExists = $true
                }
                else {
                    $snapshotProperty = $snapshotInfo.PSObject.Properties['snapshots']
                    $snapshotNames = if ($null -eq $snapshotProperty) { @() } else { @($snapshotProperty.Value | ForEach-Object {
                                $nameProperty = $_.PSObject.Properties['name']
                                if ($null -ne $nameProperty) { [string]$nameProperty.Value }
                            }) }
                    $checkpointExists = $snapshotNames -ccontains $snapshotName
                }
                $querySucceeded = $true
                $diagnosticCode = if ($checkpointExists) {
                    if ($useOverlayDisk) { 'QEMU_OVERLAY_READY' } else { 'QEMU_QUERY_OK' }
                }
                else { 'QEMU_SNAPSHOT_NOT_FOUND' }
                $diagnosticMessage = if ($checkpointExists) {
                    if ($useOverlayDisk) { 'QEMU tools and base disk were detected; each job will use a disposable overlay.' } else { 'QEMU disk and configured internal snapshot were detected.' }
                }
                else { "Configured QEMU internal snapshot '$snapshotName' was not found." }
                if ($activeQemuProcessAmbiguous) {
                    $guestTransportReady = $false
                    $activeQemuOwnsGuestRemotingPort = $false
                    $guestRemotingPortAvailable = $false
                    $diagnosticCode = 'QEMU_PROCESS_IDENTITY_AMBIGUOUS'
                    $diagnosticMessage = "$($activeQemuPids.Count) active KSword QEMU processes match VM '$vmName'. Stop duplicate runs before restoring or starting this provider profile."
                    [void]$actions.Add("下一步：停止 VM '$vmName' 的重复 QEMU 实例，只保留一个由 KSword 原生 qemu.pid 标记的进程后重试。")
                }
                elseif ($guestRemotingAddressMode -eq 'QemuUserNat') {
                    $activeQemuOwnsGuestRemotingPort = $null -ne $activeQemuPid -and
                        (Test-RunQemuProcessOwnsUserNatPort -ProcessId ([int]$activeQemuPid) -Port $guestRemotingPort)
                    if ($null -ne $activeQemuPid -and -not $activeQemuOwnsGuestRemotingPort) {
                        $state = 'Configured'
                    }
                    if ($activeQemuOwnsGuestRemotingPort) {
                        $guestRemotingPortAvailable = $true
                    }
                    else {
                        $portProbe = Test-CanBindTcpPort -HostName '127.0.0.1' -Port $guestRemotingPort
                        $guestRemotingPortAvailable = [bool]$portProbe.CanBind
                    }
                    if (-not $guestRemotingPortAvailable) {
                        $guestTransportReady = $false
                        $diagnosticCode = 'QEMU_USER_NAT_PORT_UNAVAILABLE'
                        $missingBaselineDetail = if ($checkpointExists) { '' } else { " Configured QEMU internal snapshot '$snapshotName' was also not found." }
                        $diagnosticMessage = "QEMU user-NAT WinRM host-forward port $guestRemotingPort on 127.0.0.1 is unavailable. Stop the conflicting listener or configure another guestRemoting.port. $($portProbe.Error)$missingBaselineDetail"
                        [void]$actions.Add("下一步：停止占用 127.0.0.1:$guestRemotingPort 的非 KSword 监听器，或为 qemu.guestRemoting.port 配置其他空闲端口。")
                    }
                }
            }
        }
        catch {
            $providerQueryError = $_.Exception.Message
            $errorMessage = if ([string]::IsNullOrWhiteSpace($errorMessage)) { $providerQueryError } else { "$errorMessage | $providerQueryError" }
            $accessDenied = Test-RunProviderAccessDenied -Message $providerQueryError
            $diagnosticCode = if ($accessDenied) {
                if ($isVmware) { 'VMWARE_ACCESS_DENIED' } else { 'QEMU_ACCESS_DENIED' }
            }
            else {
                if ($isVmware) { 'VMWARE_QUERY_FAILED' } else { 'QEMU_QUERY_FAILED' }
            }
            $diagnosticMessage = $providerQueryError
            [void]$actions.Add($(if ($accessDenied) {
                "下一步：授予当前用户查询 $Provider 管理接口和 VM 进程的权限，然后重新运行 CheckEnvironment。"
            }
            else {
                "下一步：检查 $Provider 管理工具输出、VM 定义路径与 baseline 配置，然后重新运行 CheckEnvironment。"
            }))
        }
    }
    if ($querySucceeded -and -not $checkpointExists) { [void]$actions.Add("下一步：为 $Provider 配置干净 snapshot，或为 QEMU 启用 per-job overlay。") }

    return [pscustomobject][ordered]@{
        Provider = $Provider
        VmName = $vmName
        ExpectedBaselineName = $snapshotName
        ExpectedCheckpointName = $snapshotName
        HyperVModuleAvailable = $false
        ManagementAvailable = $managementAvailable
        GuestTransportReady = $guestTransportReady
        ConfigurationReady = $configurationReady
        GuestRemotingAddressMode = $guestRemotingAddressMode
        GuestRemotingAddress = $guestRemotingAddress
        GuestRemotingAddressSource = $guestRemotingAddressSource
        GuestRemotingPort = $guestRemotingPort
        GuestRemotingPortAvailable = $guestRemotingPortAvailable
        ActiveQemuOwnsGuestRemotingPort = $activeQemuOwnsGuestRemotingPort
        GuestRemotingUseSsl = $guestRemotingUseSsl
        GuestRemotingAuthentication = $guestRemotingAuthentication
        GuestRemotingSkipCertificateChecks = $guestRemotingSkipCertificateChecks
        Exists = $exists
        State = $state
        Generation = $null
        ProcessorCount = $null
        MemoryStartupBytes = $null
        MemoryMegabytes = $memoryMegabytes
        Headless = $headless
        Accelerator = $accelerator
        AcceleratorSource = $acceleratorSource
        DynamicMemoryEnabled = $null
        GuestServiceInterfaceEnabled = $null
        BaselineExists = $checkpointExists
        CheckpointExists = $checkpointExists
        BaselineGuidance = if ($Provider -eq 'VMware') { 'VMware snapshot' } else { 'QEMU per-job overlay or internal snapshot' }
        QueryAttempted = $queryAttempted
        QuerySucceeded = $querySucceeded
        AccessDenied = $accessDenied
        DiagnosticCode = $diagnosticCode
        DiagnosticMessage = $diagnosticMessage
        PrimaryToolPath = $primaryTool
        SecondaryToolPath = $secondaryTool
        MachineDefinitionPath = $machinePath
        Error = $errorMessage
        RecommendedActions = @($actions.ToArray())
    }
}

function Get-R0DriverConfigurationStatus {
    param([AllowNull()]$Config)

    $driver = Get-RunObjectPropertyValue -Object $Config -Name 'driver' -DefaultValue $null
    $driverEnabled = Get-RunBooleanOrDefault -Value (Get-RunObjectPropertyValue -Object $driver -Name 'enabled' -DefaultValue $true) -DefaultValue $true
    $useMockCollector = Get-RunBooleanOrDefault -Value (Get-RunObjectPropertyValue -Object $driver -Name 'useMockCollector' -DefaultValue $false) -DefaultValue $false
    $hostDriverPathValue = Get-RunObjectPropertyValue -Object $driver -Name 'hostDriverPath' -DefaultValue ''
    $hostDriverPathRaw = if ($null -eq $hostDriverPathValue) { '' } else { [string]$hostDriverPathValue }
    $hostDriverPath = Resolve-RunConfigPath -Path $hostDriverPathRaw
    $hostDriverPathExists = -not [string]::IsNullOrWhiteSpace($hostDriverPath) -and (Test-Path -LiteralPath $hostDriverPath -PathType Leaf)
    $requiresHostDriver = $driverEnabled -and (-not $useMockCollector)
    $warning = ''
    $status = 'Ready'
    $recommendedActions = New-Object System.Collections.Generic.List[string]

    if (-not $driverEnabled) {
        $status = 'Disabled'
    }
    elseif ($useMockCollector) {
        $status = 'Mock'
    }
    elseif ([string]::IsNullOrWhiteSpace($hostDriverPath)) {
        $status = 'MissingHostDriverPath'
        $warning = 'R0 提示：已启用真实 R0 采集，但 driver.hostDriverPath 为空。WebUI 仍可用于上传/计划；Live real R0 前请在安装向导中配置 driver path，或临时使用 mock/disabled R0。'
        [void]$recommendedActions.Add("下一步：运行 .\install.ps1 -Mode Change -UpdateVirtualizationConfig -DriverHostPath <path-to-test-signed-KSword.Sandbox.Driver.sys> 配置测试签名 driver 路径。")
        [void]$recommendedActions.Add("下一步：仅验证 payload/R0 链路时设置 driver.useMockCollector=true；不需要 R0 时设置 driver.enabled=false。")
        [void]$recommendedActions.Add("下一步：如需构建原生 driver，可运行 .\scripts\Invoke-NativeBuild.ps1 -Configuration Release -Platform x64；签名/test-signing 需显式处理，禁止调用 legacy interactive signing tools。")
    }
    elseif (-not $hostDriverPathExists) {
        $status = 'MissingHostDriverFile'
        $warning = "R0 警告：已启用真实 R0 采集，但配置的 driver.hostDriverPath 不存在：$hostDriverPath。下一步：修正路径或改用 driver.useMockCollector=true。"
        [void]$recommendedActions.Add("下一步：构建 R0 driver，或修正 driver.hostDriverPath：$hostDriverPath。")
        [void]$recommendedActions.Add("下一步：仅做 payload/R0 链路验证时设置 driver.useMockCollector=true。")
    }

    return [pscustomobject][ordered]@{
        Status = $status
        DriverEnabled = $driverEnabled
        UseMockCollector = $useMockCollector
        RequiresHostDriverPath = $requiresHostDriver
        HostDriverPath = $hostDriverPath
        HostDriverPathConfigured = -not [string]::IsNullOrWhiteSpace($hostDriverPath)
        HostDriverPathExists = $hostDriverPathExists
        Warning = $warning
        RecommendedActions = @($recommendedActions.ToArray())
    }
}

function Write-R0DriverConfigurationWarning {
    param([AllowNull()]$Config)

    $driverStatus = Get-R0DriverConfigurationStatus -Config $Config
    if (-not [string]::IsNullOrWhiteSpace([string]$driverStatus.Warning)) {
        Write-RunInfo "R0 配置提示：$($driverStatus.Warning)"
        Write-RunInfo '普通启动不需要立即修复 R0；如需 Live real R0，请先在安装向导里配置 driver path，或暂时使用 mock/disabled R0。高级排障请使用 CheckEnvironment 模式。'
        foreach ($action in @($driverStatus.RecommendedActions)) {
            Write-Verbose "R0 detailed remediation: $action"
        }
    }
}

function Get-GuestPayloadRoot {
    param(
        [AllowNull()]$State,
        [Parameter(Mandatory)][object]$Config,
        [Parameter(Mandatory)][string]$EffectiveRuntimeRoot
    )

    $fromConfig = ''
    if ($null -ne $Config.paths -and $null -ne $Config.paths.PSObject.Properties['guestPayloadRoot']) {
        $fromConfig = [string]$Config.paths.guestPayloadRoot
    }

    if ([string]::IsNullOrWhiteSpace($fromConfig)) {
        $fromConfig = Get-StateString -State $State -Name 'guestPayloadRoot' -DefaultValue (Get-DefaultGuestPayloadRoot -EffectiveRuntimeRoot $EffectiveRuntimeRoot)
    }

    return [System.IO.Path]::GetFullPath($fromConfig)
}

function Get-RelativeRepositoryPath {
    param(
        [Parameter(Mandatory)][string]$RepositoryRoot,
        [Parameter(Mandatory)][string]$Path
    )

    $fullRoot = [System.IO.Path]::GetFullPath($RepositoryRoot).TrimEnd('\', '/') + '\'
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    if ($fullPath.StartsWith($fullRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $fullPath.Substring($fullRoot.Length).Replace('\', '/')
    }

    return $fullPath.Replace('\', '/')
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

function Get-GuestPayloadSourceFiles {
    $sourceRoots = @(
        'guest\KSword.Sandbox.Agent',
        'guest\KSword.Sandbox.R0Collector',
        'src\KSword.Sandbox.Abstractions'
    )
    $extensions = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($extension in @('.cs', '.csproj', '.props', '.targets', '.cpp', '.c', '.h', '.hpp', '.vcxproj', '.filters', '.json')) {
        [void]$extensions.Add($extension)
    }

    $files = New-Object System.Collections.Generic.List[System.IO.FileInfo]
    foreach ($relativeRoot in $sourceRoots) {
        $candidateRoot = Join-Path $script:RepositoryRoot $relativeRoot
        if (-not (Test-Path -LiteralPath $candidateRoot -PathType Container)) {
            continue
        }

        foreach ($file in Get-ChildItem -LiteralPath $candidateRoot -Recurse -File) {
            $normalized = $file.FullName.Replace('/', '\')
            if ($normalized -match '\\(bin|obj|x64|\.vs)\\') {
                continue
            }

            if ($extensions.Contains($file.Extension)) {
                $files.Add($file)
            }
        }
    }

    return @($files | Sort-Object FullName)
}

function Test-GuestPayloadSourceTreeAvailable {
    foreach ($relativeRoot in @('guest\KSword.Sandbox.Agent', 'guest\KSword.Sandbox.R0Collector', 'src\KSword.Sandbox.Abstractions')) {
        if (-not (Test-Path -LiteralPath (Join-Path $script:RepositoryRoot $relativeRoot) -PathType Container)) {
            return $false
        }
    }

    return $true
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

function Get-GuestPayloadSourceFingerprint {
    $files = @(Get-GuestPayloadSourceFiles)
    $builder = [System.Text.StringBuilder]::new()
    foreach ($file in $files) {
        $relative = Get-RelativeRepositoryPath -RepositoryRoot $script:RepositoryRoot -Path $file.FullName
        $hash = Get-FileSha256Hex -Path $file.FullName
        [void]$builder.AppendLine("$relative|$hash|$($file.Length)")
    }

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($builder.ToString())
        return ([System.BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function Get-PayloadManifestProperty {
    param(
        [AllowNull()]$Manifest,
        [Parameter(Mandatory)][string]$Name
    )

    if ($null -eq $Manifest) {
        return $null
    }

    $property = $Manifest.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}

function Test-GuestPayloadManifestFileHash {
    param(
        [Parameter(Mandatory)]$Manifest,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$PayloadRoot,
        [Parameter(Mandatory)][string]$ExpectedPath,
        [AllowEmptyCollection()]
        [Parameter(Mandatory)][System.Collections.Generic.List[string]]$Reasons
    )

    if (-not (Test-Path -LiteralPath $ExpectedPath -PathType Leaf)) {
        $Reasons.Add("$Name 文件缺失：$ExpectedPath。下一步：重新运行 .\scripts\Prepare-GuestPayload.ps1 -SelfContained。")
        return
    }

    $requiredFiles = Get-PayloadManifestProperty -Manifest $Manifest -Name 'requiredHostFiles'
    if ($null -eq $requiredFiles) {
        $Reasons.Add('payload-manifest.json 缺少 requiredHostFiles 元数据。下一步：重新准备 guest payload。')
        return
    }

    $entry = @($requiredFiles | Where-Object {
        $entryName = Get-PayloadManifestProperty -Manifest $_ -Name 'name'
        [System.StringComparer]::OrdinalIgnoreCase.Equals([string]$entryName, $Name)
    } | Select-Object -First 1)
    if ($entry.Count -eq 0) {
        $Reasons.Add("payload-manifest.json 缺少 $Name hash 元数据。下一步：重新准备 guest payload。")
        return
    }

    $relativePath = [string](Get-PayloadManifestProperty -Manifest $entry[0] -Name 'relativePath')
    if (-not [string]::IsNullOrWhiteSpace($relativePath)) {
        $expectedRelativePath = Get-RelativePayloadPath -PayloadRoot $PayloadRoot -Path $ExpectedPath
        if (-not [System.StringComparer]::OrdinalIgnoreCase.Equals($relativePath.Replace('\', '/'), $expectedRelativePath)) {
            $Reasons.Add("payload-manifest.json 中 $Name relativePath='$relativePath'，预期 '$expectedRelativePath'。下一步：重新发布 runtime payload。")
        }
    }

    $manifestPath = [string](Get-PayloadManifestProperty -Manifest $entry[0] -Name 'path')
    if ([string]::IsNullOrWhiteSpace($relativePath) -and -not [string]::IsNullOrWhiteSpace($manifestPath) -and -not [System.IO.Path]::IsPathRooted($manifestPath)) {
        try {
            $manifestFull = [System.IO.Path]::GetFullPath((Join-Path $PayloadRoot $manifestPath))
            if (-not [System.StringComparer]::OrdinalIgnoreCase.Equals($manifestFull, [System.IO.Path]::GetFullPath($ExpectedPath))) {
                $Reasons.Add("payload-manifest.json 中 $Name 相对路径指向 '$manifestPath'，不是预期文件。下一步：重新发布 runtime payload。")
            }
        }
        catch {
            $Reasons.Add("payload-manifest.json 中 $Name 路径无效：$manifestPath。下一步：重新准备 guest payload。")
        }
    }

    $expectedHash = [string](Get-PayloadManifestProperty -Manifest $entry[0] -Name 'sha256')
    if ([string]::IsNullOrWhiteSpace($expectedHash)) {
        $Reasons.Add("payload-manifest.json 缺少 $Name hash。下一步：重新准备 guest payload。")
        return
    }

    $actualHash = Get-FileSha256Hex -Path $ExpectedPath
    if (-not [System.StringComparer]::OrdinalIgnoreCase.Equals($expectedHash, $actualHash)) {
        $Reasons.Add("$Name hash 与 payload-manifest.json 不一致；已暂存 payload 可能被部分覆盖。下一步：重新运行 .\scripts\Prepare-GuestPayload.ps1 -SelfContained。")
    }
}

function Test-GuestPayloadFresh {
    param(
        [Parameter(Mandatory)][string]$PayloadRoot,
        [Parameter(Mandatory)][string]$AgentExe,
        [Parameter(Mandatory)][string]$CollectorExe,
        [Parameter(Mandatory)][string]$ManifestPath
    )

    $reasons = [System.Collections.Generic.List[string]]::new()
    if (-not (Test-Path -LiteralPath $AgentExe -PathType Leaf)) {
        $reasons.Add("Guest Agent 可执行文件缺失：$AgentExe。下一步：重新准备 guest payload。")
    }
    if (-not (Test-Path -LiteralPath $CollectorExe -PathType Leaf)) {
        $reasons.Add("R0Collector 可执行文件缺失：$CollectorExe。下一步：重新准备 guest payload。")
    }
    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
        $reasons.Add("payload-manifest.json 缺失：$ManifestPath。下一步：重新准备 guest payload。")
        return [pscustomobject]@{ Fresh = $false; Reasons = @($reasons) }
    }

    try {
        $manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
    }
    catch {
        $reasons.Add("payload-manifest.json 无法读取。下一步：删除损坏的 payload 目录并重新准备。英文详情：$($_.Exception.Message)")
        return [pscustomobject]@{ Fresh = $false; Reasons = @($reasons) }
    }

    $contractVersionValue = Get-PayloadManifestProperty -Manifest $manifest -Name 'payloadContractVersion'
    $contractVersion = if ($null -eq $contractVersionValue) { 0 } else { [int]$contractVersionValue }
    if ($contractVersion -lt 2) {
        $reasons.Add("payload-manifest.json contract version 为 $contractVersion；freshness 检查需要 version 2+。下一步：重新准备 guest payload。")
    }

    $manifestConfiguration = [string](Get-PayloadManifestProperty -Manifest $manifest -Name 'configuration')
    if (-not [System.StringComparer]::OrdinalIgnoreCase.Equals($manifestConfiguration, $Configuration)) {
        $reasons.Add("payload configuration '$manifestConfiguration' 与请求的 '$Configuration' 不一致。下一步：用 -Configuration $Configuration 重新准备 payload。")
    }

    $sourceFingerprint = [string](Get-PayloadManifestProperty -Manifest $manifest -Name 'sourceFingerprint')
    $sourceTreeAvailable = Test-GuestPayloadSourceTreeAvailable
    if ([string]::IsNullOrWhiteSpace($sourceFingerprint) -and $sourceTreeAvailable) {
        $reasons.Add('payload-manifest.json 缺少 sourceFingerprint。下一步：重新准备 guest payload。')
    }
    elseif (-not [string]::IsNullOrWhiteSpace($sourceFingerprint) -and $sourceTreeAvailable) {
        $currentFingerprint = Get-GuestPayloadSourceFingerprint
        if (-not [System.StringComparer]::OrdinalIgnoreCase.Equals($sourceFingerprint, $currentFingerprint)) {
            $reasons.Add('guest payload source fingerprint 已过期；Guest Agent/R0Collector 源码在暂存后发生变化。下一步：重新准备 guest payload。')
        }
    }

    Test-GuestPayloadManifestFileHash -Manifest $manifest -Name 'GuestAgent' -PayloadRoot $PayloadRoot -ExpectedPath $AgentExe -Reasons $reasons
    Test-GuestPayloadManifestFileHash -Manifest $manifest -Name 'R0Collector' -PayloadRoot $PayloadRoot -ExpectedPath $CollectorExe -Reasons $reasons

    return [pscustomobject]@{ Fresh = $reasons.Count -eq 0; Reasons = @($reasons) }
}

function Ensure-GuestPayload {
    param(
        [Parameter(Mandatory)][string]$PayloadRoot,
        [Parameter(Mandatory)][object]$Config
    )

    if ($SkipPayloadPreparation) {
        Write-RunInfo '已按请求跳过 guest payload 准备。下一步：Live 前请确认 payload 已存在且最新。 / Skipped guest payload preparation by request.'
        return
    }

    if ($WhatIfPreference) {
        [void]$PSCmdlet.ShouldProcess($PayloadRoot, 'Prepare self-contained guest payload if missing or stale')
        Write-RunInfo "预览：会检查/准备 guest payload：$PayloadRoot。 / WhatIf: guest payload preparation would be checked/prepared."
        return
    }

    $agentName = 'KSword.Sandbox.Agent.exe'
    if ($null -ne $Config.guest -and $null -ne $Config.guest.PSObject.Properties['agentExecutableName'] -and -not [string]::IsNullOrWhiteSpace([string]$Config.guest.agentExecutableName)) {
        $agentName = [string]$Config.guest.agentExecutableName
    }

    $collectorName = 'KSword.Sandbox.R0Collector.exe'
    if ($null -ne $Config.driver -and $null -ne $Config.driver.PSObject.Properties['r0CollectorPathInGuest']) {
        $leaf = Split-Path -Leaf ([string]$Config.driver.r0CollectorPathInGuest)
        if (-not [string]::IsNullOrWhiteSpace($leaf)) {
            $collectorName = $leaf
        }
    }

    $agentExe = Join-Path (Join-Path $PayloadRoot 'agent') $agentName
    $collectorExe = Join-Path (Join-Path $PayloadRoot 'r0collector') $collectorName
    $manifest = Join-Path $PayloadRoot 'payload-manifest.json'
    if (-not $ForcePayloadPreparation) {
        $freshness = Test-GuestPayloadFresh -PayloadRoot $PayloadRoot -AgentExe $agentExe -CollectorExe $collectorExe -ManifestPath $manifest
        if ($freshness.Fresh) {
            Write-RunInfo "guest payload 已就绪且最新：$PayloadRoot / Guest payload ready and fresh."
            return
        }

        Write-RunInfo "guest payload 将重建，原因：$($freshness.Reasons -join '; ') / Guest payload will be rebuilt."
    }
    else {
        Write-RunInfo '已通过 -ForcePayloadPreparation 强制重建 guest payload。 / Guest payload rebuild forced.'
    }

    if (-not (Test-GuestPayloadSourceTreeAvailable)) {
        throw "错误：guest payload 缺失或过期，但当前目录不是完整源码树，无法重建 payload。下一步：从源码仓库运行 .\scripts\Publish-RuntimePayloads.ps1 重新生成 RuntimePublishRoot，或把完整 guest-tools 放入便携包 payload\guest-tools。"
    }

    $prepareScript = Join-Path $script:RepositoryRoot 'scripts\Prepare-GuestPayload.ps1'
    if (-not (Test-Path -LiteralPath $prepareScript -PathType Leaf)) {
        throw "错误：找不到 guest payload 准备脚本：$prepareScript。下一步：请确认 scripts\Prepare-GuestPayload.ps1 存在，并从仓库根目录运行。"
    }

    $guestRoot = 'C:\KSwordSandbox'
    if ($null -ne $Config.guest -and $null -ne $Config.guest.PSObject.Properties['workingDirectory'] -and -not [string]::IsNullOrWhiteSpace([string]$Config.guest.workingDirectory)) {
        $guestRoot = [string]$Config.guest.workingDirectory
    }

    Write-RunInfo "正在准备 self-contained guest payload：$PayloadRoot / Preparing self-contained guest payload."
    $arguments = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $prepareScript,
        '-RepoRoot', $script:RepositoryRoot,
        '-PayloadRoot', $PayloadRoot,
        '-Configuration', $Configuration,
        '-GuestWorkingDirectory', $guestRoot,
        '-SelfContained'
    )
    & powershell @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "错误：guest payload 准备失败，退出码 $LASTEXITCODE。下一步：确认 .NET SDK、MSBuild/WDK 可用，然后运行 .\scripts\Prepare-GuestPayload.ps1 -SelfContained 查看详细错误。"
    }

    $freshnessAfterPrepare = Test-GuestPayloadFresh -PayloadRoot $PayloadRoot -AgentExe $agentExe -CollectorExe $collectorExe -ManifestPath $manifest
    if (-not $freshnessAfterPrepare.Fresh) {
        throw "错误：guest payload 准备完成但 freshness 检查失败：$($freshnessAfterPrepare.Reasons -join '; ')。下一步：删除 payload 目录后重新运行 .\scripts\Prepare-GuestPayload.ps1 -SelfContained。"
    }
}

function Ensure-GuestPayloadForWebUi {
    param(
        [Parameter(Mandatory)][string]$PayloadRoot,
        [Parameter(Mandatory)][object]$Config
    )

    Write-RunInfo "启动 WebUI 前检查 self-contained guest payload：$PayloadRoot / Checking guest payload before WebUI launch."
    try {
        Ensure-GuestPayload -PayloadRoot $PayloadRoot -Config $Config
    }
    catch {
        if ($RequirePayloadForWebUI) {
            throw
        }

        Write-RunInfo "中文提示：WebUI 启动前 guest payload 准备失败。下一步：如果只上传/规划可继续；Live 前请修复 payload。英文详情：$($_.Exception.Message)"
        Write-RunInfo 'WebUI 仍会启动，可用于上传、计划、dry-run runbook 和配置检查。 / WebUI will still start for non-live work.'
        Write-RunInfo '下一步：任何 provider 的 Live 前都要修复 payload；若希望 payload 失败时阻止 WebUI 启动，请加 -RequirePayloadForWebUI。 / Fix payload before live execution.'
    }
}

function Show-RunStatus {
    param(
        [AllowNull()]$State,
        [Parameter(Mandatory)][string]$EffectiveRuntimeRoot,
        [Parameter(Mandatory)][string]$EffectiveConfigPath
    )

    $secretName = Get-SecretName -State $State
    $virusTotalSecretName = Get-VirusTotalSecretName -State $State
    $configExists = Test-Path -LiteralPath $EffectiveConfigPath -PathType Leaf
    $hyperVPrerequisites = $null
    $runtimeRootUnderRepository = Test-RunPathUnderRoot -Path $EffectiveRuntimeRoot -Root $script:RepositoryRoot
    $payloadRoot = [System.IO.Path]::GetFullPath((Get-StateString -State $State -Name 'guestPayloadRoot' -DefaultValue (Get-DefaultGuestPayloadRoot -EffectiveRuntimeRoot $EffectiveRuntimeRoot)))
    $agentName = 'KSword.Sandbox.Agent.exe'
    $collectorName = 'KSword.Sandbox.R0Collector.exe'
    $statusConfig = $null
    if ($configExists) {
        try {
            $statusConfig = Get-Content -LiteralPath $EffectiveConfigPath -Raw | ConvertFrom-Json
            if ($null -ne $statusConfig.paths -and $null -ne $statusConfig.paths.PSObject.Properties['guestPayloadRoot'] -and -not [string]::IsNullOrWhiteSpace([string]$statusConfig.paths.guestPayloadRoot)) {
                $payloadRoot = [System.IO.Path]::GetFullPath([string]$statusConfig.paths.guestPayloadRoot)
            }
            if ($null -ne $statusConfig.guest -and $null -ne $statusConfig.guest.PSObject.Properties['agentExecutableName'] -and -not [string]::IsNullOrWhiteSpace([string]$statusConfig.guest.agentExecutableName)) {
                $agentName = [string]$statusConfig.guest.agentExecutableName
            }
            if ($null -ne $statusConfig.driver -and $null -ne $statusConfig.driver.PSObject.Properties['r0CollectorPathInGuest']) {
                $collectorLeaf = Split-Path -Leaf ([string]$statusConfig.driver.r0CollectorPathInGuest)
                if (-not [string]::IsNullOrWhiteSpace($collectorLeaf)) {
                    $collectorName = $collectorLeaf
                }
            }
        }
        catch {
            Write-RunInfo "中文提示：Status 无法从配置读取 payload root，将使用默认/安装状态值。配置：$EffectiveConfigPath；英文详情：$($_.Exception.Message)"
        }
    }
    $provider = if ($null -eq $statusConfig) { 'HyperV' } else { Get-RunVirtualizationProvider -Config $statusConfig }
    $qemuUseOverlayDisk = $false
    if ($provider -eq 'Qemu') {
        $qemuConfig = Get-RunObjectPropertyValue -Object $statusConfig -Name 'qemu' -DefaultValue $null
        $qemuUseOverlayDisk = Get-RunBooleanOrDefault `
            -Value (Get-RunObjectPropertyValue -Object $qemuConfig -Name 'useOverlayDisk' -DefaultValue $true) `
            -DefaultValue $true
    }
    $restoreBaselineRequiresVmMutation = Test-RunBaselineRestoreRequiresVmMutation `
        -Provider $provider `
        -UseQemuOverlayDisk $qemuUseOverlayDisk
    $restoreBaselineWhatIfCommand = if ($restoreBaselineRequiresVmMutation) {
        '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -AllowVmMutation -WhatIf'
    }
    else {
        '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -WhatIf'
    }
    $restoreBaselineCommand = if ($restoreBaselineRequiresVmMutation) {
        '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -AllowVmMutation -Confirm'
    }
    else {
        '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -Json'
    }
    $baselineIsolationMode = if ($restoreBaselineRequiresVmMutation) { 'provider-snapshot-restore' } else { 'qemu-per-job-overlay' }
    $hyperVPrerequisites = if ($provider -eq 'HyperV') {
        Get-RunHyperVPrerequisiteStatus
    }
    else {
        [pscustomobject][ordered]@{
            OsIsWindows = [System.StringComparer]::OrdinalIgnoreCase.Equals([string]$env:OS, 'Windows_NT')
            CimAvailable = $null -ne (Get-Command Get-CimInstance -ErrorAction SilentlyContinue)
            FeatureStates = [pscustomobject]@{}
            HypervisorPresent = $null
            VirtualizationFirmwareEnabled = $null
            SecondLevelAddressTranslationSupported = $null
            VmMonitorModeExtensions = $null
            RecommendedActions = @()
            InspectionErrors = @()
            StartsOrMutatesVm = $false
        }
    }
    $providerHostPrerequisites = Get-RunProviderHostPrerequisiteStatus `
        -Provider $provider `
        -HyperVPrerequisites $hyperVPrerequisites
    $driverStatus = Get-R0DriverConfigurationStatus -Config $statusConfig

    $payloadManifest = Join-Path $payloadRoot 'payload-manifest.json'
    $agentPayload = Join-Path (Join-Path $payloadRoot 'agent') $agentName
    $collectorPayload = Join-Path (Join-Path $payloadRoot 'r0collector') $collectorName
    $payloadFreshness = $null
    if ((Test-Path -LiteralPath $agentPayload -PathType Leaf) -and
        (Test-Path -LiteralPath $collectorPayload -PathType Leaf) -and
        (Test-Path -LiteralPath $payloadManifest -PathType Leaf)) {
        try {
            $payloadFreshness = Test-GuestPayloadFresh -PayloadRoot $payloadRoot -AgentExe $agentPayload -CollectorExe $collectorPayload -ManifestPath $payloadManifest
        }
        catch {
            $payloadFreshness = [pscustomobject]@{
                Fresh = $false
                Reasons = @("payload freshness 检查异常：$($_.Exception.Message)")
            }
        }
    }
    $vmName = Get-StateString -State $State -Name 'vmName' -DefaultValue 'KSwordSandbox-Win10-Golden'
    $checkpointName = Get-StateString -State $State -Name 'checkpointName' -DefaultValue 'Clean'
    $vmProfile = if ($null -eq $statusConfig) {
        Get-RunVmProfileStatus -VmName $vmName -CheckpointName $checkpointName
    }
    else {
        Get-RunProviderProfileStatus -Config $statusConfig -Provider $provider
    }
    $vmName = [string]$vmProfile.VmName
    $checkpointName = [string]$vmProfile.ExpectedCheckpointName
    $providerManagementAvailable = if ($null -ne $vmProfile.PSObject.Properties['ManagementAvailable']) {
        [bool]$vmProfile.ManagementAvailable
    }
    else {
        [bool]$vmProfile.HyperVModuleAvailable
    }
    $providerQueryAttempted = [bool](Get-RunObjectPropertyValue -Object $vmProfile -Name 'QueryAttempted' -DefaultValue $false)
    $providerQuerySucceeded = [bool](Get-RunObjectPropertyValue -Object $vmProfile -Name 'QuerySucceeded' -DefaultValue $false)
    $providerAccessDenied = [bool](Get-RunObjectPropertyValue -Object $vmProfile -Name 'AccessDenied' -DefaultValue $false)
    $providerDiagnosticCode = [string](Get-RunObjectPropertyValue -Object $vmProfile -Name 'DiagnosticCode' -DefaultValue '')
    $providerDiagnosticMessage = [string](Get-RunObjectPropertyValue -Object $vmProfile -Name 'DiagnosticMessage' -DefaultValue '')
    $hyperVModuleAvailable = $provider -eq 'HyperV' -and [bool]$vmProfile.HyperVModuleAvailable
    $guestTransportReady = $provider -eq 'HyperV' -or [bool]$vmProfile.GuestTransportReady
    $providerConfigurationReady = if ($null -eq $vmProfile.PSObject.Properties['ConfigurationReady']) { $true } else { [bool]$vmProfile.ConfigurationReady }
    $vmAccelerator = Get-RunObjectPropertyValue -Object $vmProfile -Name 'Accelerator' -DefaultValue $null
    $vmAcceleratorSource = Get-RunObjectPropertyValue -Object $vmProfile -Name 'AcceleratorSource' -DefaultValue $null
    $vmExists = [bool]$vmProfile.Exists
    $checkpointExists = [bool]$vmProfile.CheckpointExists
    $vmState = $vmProfile.State
    $providerStatusError = $vmProfile.Error
    $hostTestSigningStatus = Get-RunHostTestSigningStatus
    $webLaunchTarget = Get-WebUiLaunchTarget -ThrowIfMissing $false
    $dotNetAvailable = $null -ne (Get-Command dotnet -ErrorAction SilentlyContinue)
    $webUiLaunchTargetReady = $webLaunchTarget.Kind -ne 'Missing' -and
        (-not [bool]$webLaunchTarget.RequiresDotNet -or $dotNetAvailable)
    $providerExecutionTarget = try {
        Import-PortableToolResolver
        Resolve-KSwordPortableTool -RepoRoot $script:RepositoryRoot -Tool JobTool
    }
    catch {
        [pscustomobject][ordered]@{
            Tool = 'JobTool'
            Kind = 'Missing'
            Path = $null
            RequiresDotNet = $null
            RecommendedAction = "下一步：恢复 scripts\Resolve-PortableTool.ps1 和 JobTool 启动目标。$($_.Exception.Message)"
        }
    }
    $providerExecutionToolReady = $providerExecutionTarget.Kind -ne 'Missing' -and
        (-not [bool]$providerExecutionTarget.RequiresDotNet -or $dotNetAvailable)
    $vmwareVmType = if ($provider -eq 'VMware' -and $null -ne $statusConfig) {
        $vmwareConfig = Get-RunObjectPropertyValue -Object $statusConfig -Name 'vmware' -DefaultValue $null
        [string](Get-RunObjectPropertyValue -Object $vmwareConfig -Name 'vmType' -DefaultValue 'ws')
    }
    else { $null }
    $offlineRecoveryToolPath = if ($provider -eq 'Qemu') {
        [string](Get-RunObjectPropertyValue -Object $vmProfile -Name 'SecondaryToolPath' -DefaultValue '')
    }
    elseif ($provider -eq 'VMware' -and $null -ne $statusConfig) {
        $qemuConfig = Get-RunObjectPropertyValue -Object $statusConfig -Name 'qemu' -DefaultValue $null
        Resolve-RunExecutablePath -ConfiguredPath ([string](Get-RunObjectPropertyValue -Object $qemuConfig -Name 'qemuImgPath' -DefaultValue 'qemu-img.exe'))
    }
    else { $null }
    $offlineRecoveryStorageCmdletsReady = $null -ne (Get-Command Mount-DiskImage -ErrorAction SilentlyContinue) -and $null -ne (Get-Command Dismount-DiskImage -ErrorAction SilentlyContinue)
    $offlineRecoveryElevationReady = Test-RunIsAdministrator
    $unknownPasswordRecoverySupported = $provider -ne 'VMware' -or $vmwareVmType -eq 'ws'
    $unknownPasswordRecoveryReady = $unknownPasswordRecoverySupported -and
        $offlineRecoveryElevationReady -and
        $providerManagementAvailable -and
        $providerConfigurationReady -and
        $providerQuerySucceeded -and
        $vmExists -and
        $checkpointExists -and
        ($provider -eq 'HyperV' -or (-not [string]::IsNullOrWhiteSpace($offlineRecoveryToolPath) -and $offlineRecoveryStorageCmdletsReady))

    $recommendedActions = New-Object System.Collections.Generic.List[string]
    foreach ($prereqAction in @($providerHostPrerequisites.RecommendedActions)) {
        [void]$recommendedActions.Add([string]$prereqAction)
    }
    foreach ($profileAction in @($vmProfile.RecommendedActions)) {
        [void]$recommendedActions.Add([string]$profileAction)
    }
    if ($unknownPasswordRecoverySupported -and -not $unknownPasswordRecoveryReady) {
        $offlineRecoveryAction = if ($provider -eq 'HyperV') {
            '下一步：如需 Hyper-V 无旧密码离线恢复，请以管理员 PowerShell 运行，并确认 Hyper-V 管理工具可用。'
        }
        else {
            "下一步：如需 $provider 无旧密码离线恢复，请以管理员 PowerShell 运行，并确认 provider 管理工具、qemu-img 和 Windows Storage Mount-DiskImage/Dismount-DiskImage 可用；已知凭据 WinRM 轮换不受影响。"
        }
        [void]$recommendedActions.Add($offlineRecoveryAction)
    }
    if (-not $webUiLaunchTargetReady) {
        $webUiAction = if ($webLaunchTarget.Kind -eq 'Missing') {
            [string]$webLaunchTarget.RecommendedAction
        }
        else {
            '下一步：安装可运行 WebUI 启动目标的 .NET SDK/runtime，或使用包含 self-contained WebUI exe 的 runtime package。'
        }
        [void]$recommendedActions.Add($webUiAction)
    }
    if (-not $providerExecutionToolReady) {
        $providerExecutionAction = if ($providerExecutionTarget.Kind -eq 'Missing') {
            "下一步：恢复 JobTool 启动目标。$($providerExecutionTarget.RecommendedAction)"
        }
        else {
            '下一步：安装可运行 JobTool 的 .NET runtime/SDK，或使用包含 self-contained JobTool exe 的 runtime package。'
        }
        [void]$recommendedActions.Add($providerExecutionAction)
    }
    if (-not $configExists) {
        [void]$recommendedActions.Add("下一步：运行 .\install.ps1 -InstallEntrypoint CreateOrPreparePath -PromptPassword 创建本机配置；或运行 .\install.ps1 -Mode Change -UpdateVirtualizationConfig 记录 provider/VM/snapshot。")
    }
    if (-not (Test-Path -LiteralPath $EffectiveRuntimeRoot -PathType Container)) {
        [void]$recommendedActions.Add("下一步：运行 .\install.ps1 -InstallEntrypoint CreateOrPreparePath，在 '$EffectiveRuntimeRoot' 下创建运行目录。")
    }
    if ($runtimeRootUnderRepository) {
        [void]$recommendedActions.Add("下一步：RuntimeRoot 当前位于仓库下，建议移到 D:\Temp\KSwordSandbox 或其他仓库外目录，避免 job/report/capture 误提交。")
    }
    if (-not (Test-Path -LiteralPath $payloadRoot -PathType Container) -or
        -not (Test-Path -LiteralPath $agentPayload -PathType Leaf) -or
        -not (Test-Path -LiteralPath $collectorPayload -PathType Leaf) -or
        -not (Test-Path -LiteralPath $payloadManifest -PathType Leaf)) {
        [void]$recommendedActions.Add("下一步：运行 .\scripts\Prepare-GuestPayload.ps1 -RepoRoot . -PayloadRoot '$payloadRoot' -Configuration $Configuration -SelfContained 准备 Guest Agent/R0Collector payload。")
        [void]$recommendedActions.Add("下一步：运行 .\run.ps1 -Mode CheckEnvironment 重新检查 payload readiness；该命令不会启动或还原 VM。")
    }
    elseif ($null -ne $payloadFreshness -and -not [bool]$payloadFreshness.Fresh) {
        foreach ($reason in @($payloadFreshness.Reasons)) {
            [void]$recommendedActions.Add([string]$reason)
        }
    }
    if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($secretName, 'Process')) -and
        [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($secretName, 'User')) -and
        [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($secretName, 'Machine'))) {
        $secretAction = if ($provider -eq 'HyperV') {
            '下一步：运行 .\install.ps1 -InstallEntrypoint CreateOrPreparePath -PromptPassword 保存 guest password secret；如果只做本进程检查，可运行 .\scripts\Test-HyperVReadiness.ps1 -PromptForMissingGuestPassword。'
        }
        else {
            "下一步：运行 .\install.ps1 -InstallEntrypoint CreateOrPreparePath -PromptPassword 保存 guest password secret，然后运行 .\run.ps1 -Mode CheckEnvironment 检查 $provider profile。"
        }
        [void]$recommendedActions.Add($secretAction)
    }
    foreach ($driverAction in @($driverStatus.RecommendedActions)) {
        [void]$recommendedActions.Add([string]$driverAction)
    }
    if (-not $providerManagementAvailable) {
        [void]$recommendedActions.Add("下一步：安装或配置 $provider 管理工具，然后重新运行 .\run.ps1 -Mode CheckEnvironment。")
    }
    elseif ($providerQuerySucceeded -and -not $vmExists) {
        [void]$recommendedActions.Add("下一步：运行 .\install.ps1 -Mode Change -UpdateVirtualizationConfig -VirtualizationProvider $provider -VmName <existing VM> -CheckpointName <clean-baseline> 记录现有 VM，或先创建/导入 VM '$vmName'。")
    }
    elseif ($providerQuerySucceeded -and -not $checkpointExists) {
        [void]$recommendedActions.Add("下一步：运行 .\install.ps1 -Mode Change -UpdateVirtualizationConfig -VirtualizationProvider $provider -VmName '$vmName' -CheckpointName <clean-baseline> 记录干净基线，或先创建 provider 对应的 baseline '$checkpointName'。")
    }

    $runtimeRootExists = Test-Path -LiteralPath $EffectiveRuntimeRoot -PathType Container
    $guestPayloadRootExists = Test-Path -LiteralPath $payloadRoot -PathType Container
    $guestAgentPayloadExists = Test-Path -LiteralPath $agentPayload -PathType Leaf
    $r0CollectorPayloadExists = Test-Path -LiteralPath $collectorPayload -PathType Leaf
    $guestPayloadManifestExists = Test-Path -LiteralPath $payloadManifest -PathType Leaf
    $guestPayloadFresh = if ($null -eq $payloadFreshness) { $false } else { [bool]$payloadFreshness.Fresh }
    $guestSecretSet = (-not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($secretName, 'Process'))) -or
        (-not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($secretName, 'User'))) -or
        (-not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($secretName, 'Machine')))
    $recommendedActionArray = @($recommendedActions.ToArray() | Select-Object -Unique)
    $modeResolution = Get-RunModeResolution
    $interactiveConsoleEnabled = $true
    if ($null -ne $statusConfig) {
        $sectionName = switch ($provider) { 'HyperV' { 'hyperV' } 'VMware' { 'vmware' } 'Qemu' { 'qemu' } }
        $sectionProperty = $statusConfig.PSObject.Properties[$sectionName]
        if ($null -ne $sectionProperty -and $null -ne $sectionProperty.Value) {
            $consolePropertyName = if ($provider -eq 'HyperV') { 'openVmConsoleOnLiveStart' } else { 'headless' }
            $consoleProperty = $sectionProperty.Value.PSObject.Properties[$consolePropertyName]
            if ($null -ne $consoleProperty) {
                $interactiveConsoleEnabled = if ($provider -eq 'HyperV') { [bool]$consoleProperty.Value } else { -not [bool]$consoleProperty.Value }
            }
        }
    }
    $vmMutationPolicy = Get-RunVmMutationPolicy -VirtualizationProvider $provider -InteractiveConsoleEnabled $interactiveConsoleEnabled
    $readinessVerdict = New-RunReadinessVerdict `
        -VirtualizationProvider $provider `
        -ConfigExists $configExists `
        -RuntimeRootExists $runtimeRootExists `
        -RuntimeRootUnderRepository $runtimeRootUnderRepository `
        -WebUiLaunchTargetReady $webUiLaunchTargetReady `
        -ProviderExecutionToolReady $providerExecutionToolReady `
        -GuestPayloadRootExists $guestPayloadRootExists `
        -GuestAgentPayloadExists $guestAgentPayloadExists `
        -R0CollectorPayloadExists $r0CollectorPayloadExists `
        -GuestPayloadManifestExists $guestPayloadManifestExists `
        -GuestPayloadFresh $guestPayloadFresh `
        -GuestSecretSet $guestSecretSet `
        -GuestTransportReady $guestTransportReady `
        -ProviderManagementAvailable $providerManagementAvailable `
        -ProviderQueryAttempted $providerQueryAttempted `
        -ProviderQuerySucceeded $providerQuerySucceeded `
        -ProviderAccessDenied $providerAccessDenied `
        -ProviderDiagnosticCode $providerDiagnosticCode `
        -ProviderDiagnosticMessage $providerDiagnosticMessage `
        -ProviderHostHardwareReady ([bool]($providerHostPrerequisites.HardwareAccelerationReady -eq $true)) `
        -ProviderConfigurationReady $providerConfigurationReady `
        -VmExists $vmExists `
        -CheckpointExists $checkpointExists `
        -InteractiveConsoleEnabled $interactiveConsoleEnabled `
        -DriverStatus $driverStatus `
        -RecommendedActions $recommendedActionArray

    [pscustomobject][ordered]@{
        Kind = 'KSwordSandbox.RunStatus'
        ContractVersion = 2
        MachineReadable = $true
        VirtualizationProvider = $provider
        ProviderManagementAvailable = $providerManagementAvailable
        ProviderQueryAttempted = $providerQueryAttempted
        ProviderQuerySucceeded = $providerQuerySucceeded
        ProviderAccessDenied = $providerAccessDenied
        ProviderDiagnosticCode = $providerDiagnosticCode
        ProviderDiagnosticMessage = $providerDiagnosticMessage
        ProviderConfigurationReady = $providerConfigurationReady
        ProviderExecutionToolReady = $providerExecutionToolReady
        ProviderExecutionToolKind = $providerExecutionTarget.Kind
        ProviderExecutionToolPath = $providerExecutionTarget.Path
        ProviderExecutionToolRequiresDotNet = $providerExecutionTarget.RequiresDotNet
        WebUiLaunchTargetReady = $webUiLaunchTargetReady
        ProviderHostPrerequisiteSchema = 'ksword.provider-host-prerequisites.v1'
        ProviderHostPrerequisites = $providerHostPrerequisites
        ProviderHostHardwareReady = $providerHostPrerequisites.HardwareAccelerationReady
        RequiredWindowsFeature = $providerHostPrerequisites.RequiredWindowsFeature
        RequiredWindowsFeatureState = $providerHostPrerequisites.RequiredWindowsFeatureState
        RequiredWindowsFeatureReady = $providerHostPrerequisites.RequiredWindowsFeatureReady
        GuestTransportReady = $guestTransportReady
        GuestRemotingAddressMode = Get-RunObjectPropertyValue -Object $vmProfile -Name 'GuestRemotingAddressMode' -DefaultValue $(if ($provider -eq 'HyperV') { 'PowerShellDirect' } else { 'Configured' })
        GuestRemotingAddressSource = Get-RunObjectPropertyValue -Object $vmProfile -Name 'GuestRemotingAddressSource' -DefaultValue $(if ($provider -eq 'HyperV') { 'vm-name' } else { 'configured' })
        GuestRemotingAddress = Get-RunObjectPropertyValue -Object $vmProfile -Name 'GuestRemotingAddress' -DefaultValue $null
        GuestRemotingPort = Get-RunObjectPropertyValue -Object $vmProfile -Name 'GuestRemotingPort' -DefaultValue 0
        ActualGuestPasswordUnknownOldPasswordRecoverySupported = $unknownPasswordRecoverySupported
        ActualGuestPasswordUnknownOldPasswordRecoveryReady = $unknownPasswordRecoveryReady
        ActualGuestPasswordUnknownOldPasswordRecoveryRequiresElevation = $unknownPasswordRecoverySupported
        ActualGuestPasswordUnknownOldPasswordRecoveryElevationReady = $offlineRecoveryElevationReady
        ActualGuestPasswordUnknownOldPasswordRecoveryToolPath = $offlineRecoveryToolPath
        ActualGuestPasswordUnknownOldPasswordRecoveryStorageCmdletsReady = $offlineRecoveryStorageCmdletsReady
        ActualGuestPasswordUnknownOldPasswordRecoveryLayoutValidation = if ($provider -eq 'VMware' -and $vmwareVmType -eq 'ws') { 'deferred-to-isolated-full-clone' } elseif ($provider -eq 'Qemu') { 'qemu-img-source-info-and-snapshot-preflight' } else { 'provider-native' }
        ActualGuestPasswordUnknownOldPasswordRecoveryMode = if ($provider -eq 'HyperV') { 'offline-vhdx' } elseif ($provider -eq 'Qemu') { 'offline-vhdx-and-replacement-disk' } elseif ($vmwareVmType -eq 'ws') { 'offline-vhdx-full-clone-replacement-vmx' } else { 'requires-current-winrm-credential' }
        ReadinessVerdictSchema = 'ksword.run.readiness-verdict.v1'
        ReadinessVerdict = $readinessVerdict
        ReadinessOverallStatus = $readinessVerdict.OverallStatus
        WebUiReady = $readinessVerdict.WebUiReady
        PlanOnlyReady = $readinessVerdict.PlanOnlyReady
        LiveReady = $readinessVerdict.LiveReady
        VmMutationPolicySchema = 'ksword.run.vm-mutation-policy.v1'
        VmMutationPolicy = $vmMutationPolicy
        ModeCoercionMetadataSchema = 'ksword.run.mode-coercion.v1'
        ModeCoercionMetadata = $modeResolution
        RequestedMode = $modeResolution.RequestedMode
        EffectiveMode = $modeResolution.EffectiveMode
        ModeCoerced = $modeResolution.ModeCoerced
        ModeCoercionReason = $modeResolution.ModeCoercionReason
        OpenVmConsoleOnLiveStartDefault = $vmMutationPolicy.OpenVmConsoleOnLiveStartDefault
        OpenVmConnectOnLiveStart = $vmMutationPolicy.OpenVmConnectOnLiveStart
        OpenVmConsoleFailureBlocksHeadless = $vmMutationPolicy.OpenVmConsoleFailureBlocksHeadless
        VmConsoleRequiredUnlessNoOpenVmConsole = $vmMutationPolicy.VmConsoleRequiredUnlessNoOpenVmConsole
        RepositoryRoot = $script:RepositoryRoot
        InstallStatePath = $script:InstallStatePath
        InstallStateExists = Test-Path -LiteralPath $script:InstallStatePath -PathType Leaf
        ConfigPath = $EffectiveConfigPath
        ConfigExists = $configExists
        WebUrl = $Url
        WebUiCommand = '.\run.ps1'
        OperatorModeMatrixSchema = 'ksword.run.operator-mode-matrix.v1'
        OperatorModeMatrix = @(Get-RunOperatorModeMatrix -Provider $provider -UseQemuOverlayDisk $qemuUseOverlayDisk)
        UseConfiguredEnvironmentCommand = '.\install.ps1 -InstallEntrypoint UseConfiguredEnvironment -PlanOnly'
        QemuUseOverlayDisk = $qemuUseOverlayDisk
        BaselineRestoreRequiresVmMutation = $restoreBaselineRequiresVmMutation
        BaselineRestoreSatisfiedWithoutMutation = -not $restoreBaselineRequiresVmMutation
        BaselineIsolationMode = $baselineIsolationMode
        RestoreBaselinePlanCommand = '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -PlanOnly'
        RestoreBaselineWhatIfCommand = $restoreBaselineWhatIfCommand
        RestoreBaselineCommand = $restoreBaselineCommand
        RestoreCheckpointPlanCommand = '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -PlanOnly'
        RestoreCheckpointWhatIfCommand = $restoreBaselineWhatIfCommand
        RestoreCheckpointCommand = $restoreBaselineCommand
        CreateOrPreparePathCommand = '.\install.ps1 -InstallEntrypoint CreateOrPreparePath -PromptPassword'
        OperatorModeGuidanceZh = if ($restoreBaselineRequiresVmMutation) {
            '中文提示：run.ps1 消费已安装配置；默认 WebUI/PlanOnly 不启动/还原 VM。回退/恢复快照请使用 install.ps1 RestoreCleanCheckpoint 并显式批准 VM 变更；新电脑准备请使用 install.ps1 CreateOrPreparePath。'
        }
        else {
            '中文提示：run.ps1 消费已安装配置；默认 WebUI/PlanOnly 不启动 VM。当前 QEMU per-job overlay 已保证每次 Live 从干净基础盘创建隔离层，无需原地恢复或批准 VM 变更；新电脑准备请使用 install.ps1 CreateOrPreparePath。'
        }
        WebUiLaunchKind = $webLaunchTarget.Kind
        WebUiLaunchPath = $webLaunchTarget.Path
        WebUiSourceProjectExists = $webLaunchTarget.SourceProjectExists
        PublishedWebRoot = $webLaunchTarget.PublishedWebRoot
        PublishedWebExeExists = $webLaunchTarget.PublishedExeExists
        PublishedWebDllExists = $webLaunchTarget.PublishedDllExists
        RuntimeRoot = $EffectiveRuntimeRoot
        RuntimeRootExists = $runtimeRootExists
        RuntimeRootUnderRepository = $runtimeRootUnderRepository
        RuntimeRootGuidance = '运行目录建议放在仓库外，例如 D:\Temp\KSwordSandbox；jobs/uploads/reports/PCAP/dump 不应进入 git。'
        GuestPayloadRoot = $payloadRoot
        GuestPayloadRootExists = $guestPayloadRootExists
        GuestPayloadManifest = $payloadManifest
        GuestPayloadManifestExists = $guestPayloadManifestExists
        GuestAgentPayload = $agentPayload
        GuestAgentPayloadExists = $guestAgentPayloadExists
        R0CollectorPayload = $collectorPayload
        R0CollectorPayloadExists = $r0CollectorPayloadExists
        GuestPayloadFresh = $guestPayloadFresh
        GuestPayloadFreshnessReasons = if ($null -eq $payloadFreshness) { @('payload freshness 未检查：缺少 Agent/R0Collector/payload-manifest.json 中至少一个文件。') } else { @($payloadFreshness.Reasons) }
        R0DriverConfigurationStatus = $driverStatus.Status
        R0DriverConfigurationWarning = $driverStatus.Warning
        DriverEnabled = $driverStatus.DriverEnabled
        DriverUseMockCollector = $driverStatus.UseMockCollector
        DriverHostPath = $driverStatus.HostDriverPath
        DriverHostPathConfigured = $driverStatus.HostDriverPathConfigured
        DriverHostPathExists = $driverStatus.HostDriverPathExists
        SecretName = $secretName
        ProcessSecretSet = -not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($secretName, 'Process'))
        UserSecretSet = -not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($secretName, 'User'))
        MachineSecretSet = -not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($secretName, 'Machine'))
        GuestSecretSet = $guestSecretSet
        VirusTotalSecretName = $virusTotalSecretName
        VirusTotalProcessSecretSet = -not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($virusTotalSecretName, 'Process'))
        VirusTotalUserSecretSet = -not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($virusTotalSecretName, 'User'))
        VirusTotalConfigured = (-not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($virusTotalSecretName, 'Process'))) -or (-not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($virusTotalSecretName, 'User'))) -or (-not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($virusTotalSecretName, 'Machine')))
        VirusTotalMissingKeyBehavior = 'optional hash-only enrichment is skipped quietly when key is absent or lookup fails'
        GuestPasswordGuidance = "下一步：运行 .\install.ps1 -InstallEntrypoint CreateOrPreparePath -PromptPassword；如果需要同步 VM 实际密码，可运行 .\install.ps1 -Mode Change -ResetGuestVmPassword -GeneratePassword -Force"
        VirusTotalGuidance = "下一步：运行 .\install.ps1 -Mode ConfigureVTKey -PromptVTKey，或在 User 环境中设置 $virusTotalSecretName。"
        VmName = $vmName
        BaselineName = $checkpointName
        CheckpointName = $checkpointName
        HyperVPrerequisites = $hyperVPrerequisites
        HyperVFeatureStates = $hyperVPrerequisites.FeatureStates
        HyperVVirtualizationFirmwareEnabled = $hyperVPrerequisites.VirtualizationFirmwareEnabled
        HyperVSecondLevelAddressTranslationSupported = $hyperVPrerequisites.SecondLevelAddressTranslationSupported
        HyperVModuleAvailable = $hyperVModuleAvailable
        VmExists = $vmExists
        VmState = $vmState
        BaselineExists = $checkpointExists
        CheckpointExists = $checkpointExists
        ProviderStatusError = $providerStatusError
        HyperVStatusError = if ($provider -eq 'HyperV') { $providerStatusError } else { $null }
        VmProfile = $vmProfile
        VmProfileHealthy = ($providerConfigurationReady -and $providerQuerySucceeded -and $guestTransportReady -and $vmExists -and $checkpointExists)
        VmGeneration = $vmProfile.Generation
        VmProcessorCount = $vmProfile.ProcessorCount
        VmMemoryStartupBytes = $vmProfile.MemoryStartupBytes
        VmAccelerator = $vmAccelerator
        VmAcceleratorSource = $vmAcceleratorSource
        VmGuestServiceInterfaceEnabled = $vmProfile.GuestServiceInterfaceEnabled
        HostTestSigningState = $hostTestSigningStatus.State
        HostTestSigningMessage = $hostTestSigningStatus.Message
        PayloadGuidance = ".\scripts\Prepare-GuestPayload.ps1 -RepoRoot . -PayloadRoot '$payloadRoot' -Configuration $Configuration -SelfContained"
        VmGuidance = ".\install.ps1 -Mode Change -UpdateVirtualizationConfig -VirtualizationProvider $provider -VmName <existing VM> -CheckpointName <clean-baseline>"
        BaselineGuidance = ".\install.ps1 -Mode Change -UpdateVirtualizationConfig -VirtualizationProvider $provider -VmName '$vmName' -CheckpointName <clean-baseline>"
        CheckpointGuidance = ".\install.ps1 -Mode Change -UpdateVirtualizationConfig -VirtualizationProvider $provider -VmName '$vmName' -CheckpointName <clean-baseline>"
        ReadinessGuidance = '.\run.ps1 -Mode CheckEnvironment'
        RecommendedActions = $recommendedActionArray
        SecretValuePrinted = $false
    }
}

function Show-RunEnvironmentCheck {
    param(
        [AllowNull()]$State,
        [Parameter(Mandatory)][string]$EffectiveRuntimeRoot,
        [Parameter(Mandatory)][string]$EffectiveConfigPath
    )

    $runStatus = Show-RunStatus -State $State -EffectiveRuntimeRoot $EffectiveRuntimeRoot -EffectiveConfigPath $EffectiveConfigPath
    $webProject = Join-Path $script:RepositoryRoot 'src\KSword.Sandbox.Web\KSword.Sandbox.Web.csproj'
    $hyperVScript = Join-Path $script:RepositoryRoot 'scripts\Invoke-HyperVE2E.ps1'
    $payloadScript = Join-Path $script:RepositoryRoot 'scripts\Prepare-GuestPayload.ps1'
    $webLaunchTarget = Get-WebUiLaunchTarget -ThrowIfMissing $false

    [pscustomobject][ordered]@{
        Kind = 'KSwordSandbox.RunEnvironmentCheck'
        ContractVersion = 2
        MachineReadable = $true
        ReadinessVerdictSchema = $runStatus.ReadinessVerdictSchema
        ReadinessVerdict = $runStatus.ReadinessVerdict
        ReadinessOverallStatus = $runStatus.ReadinessOverallStatus
        WebUiReady = $runStatus.WebUiReady
        PlanOnlyReady = $runStatus.PlanOnlyReady
        LiveReady = $runStatus.LiveReady
        ProviderManagementAvailable = $runStatus.ProviderManagementAvailable
        ProviderQueryAttempted = $runStatus.ProviderQueryAttempted
        ProviderQuerySucceeded = $runStatus.ProviderQuerySucceeded
        ProviderAccessDenied = $runStatus.ProviderAccessDenied
        ProviderDiagnosticCode = $runStatus.ProviderDiagnosticCode
        ProviderDiagnosticMessage = $runStatus.ProviderDiagnosticMessage
        VmMutationPolicySchema = $runStatus.VmMutationPolicySchema
        VmMutationPolicy = $runStatus.VmMutationPolicy
        ModeCoercionMetadataSchema = $runStatus.ModeCoercionMetadataSchema
        ModeCoercionMetadata = $runStatus.ModeCoercionMetadata
        RequestedMode = $runStatus.RequestedMode
        EffectiveMode = $runStatus.EffectiveMode
        ModeCoerced = $runStatus.ModeCoerced
        DailyStartupCommand = '.\run.ps1'
        StartWebUiCommand = '.\run.ps1 -Mode StartWebUI'
        CheckEnvironmentCommand = '.\run.ps1 -Mode CheckEnvironment'
        OperatorModeMatrix = @($runStatus.OperatorModeMatrix)
        UseConfiguredEnvironmentCommand = '.\install.ps1 -InstallEntrypoint UseConfiguredEnvironment -PlanOnly'
        QemuUseOverlayDisk = $runStatus.QemuUseOverlayDisk
        BaselineRestoreRequiresVmMutation = $runStatus.BaselineRestoreRequiresVmMutation
        BaselineRestoreSatisfiedWithoutMutation = $runStatus.BaselineRestoreSatisfiedWithoutMutation
        BaselineIsolationMode = $runStatus.BaselineIsolationMode
        RestoreBaselinePlanCommand = $runStatus.RestoreBaselinePlanCommand
        RestoreBaselineWhatIfCommand = $runStatus.RestoreBaselineWhatIfCommand
        RestoreBaselineCommand = $runStatus.RestoreBaselineCommand
        RestoreCheckpointPlanCommand = $runStatus.RestoreCheckpointPlanCommand
        RestoreCheckpointWhatIfCommand = $runStatus.RestoreCheckpointWhatIfCommand
        RestoreCheckpointCommand = $runStatus.RestoreCheckpointCommand
        CreateOrPreparePathCommand = '.\install.ps1 -InstallEntrypoint CreateOrPreparePath -PromptPassword'
        PlanCommand = '.\run.ps1 -Mode Plan -SamplePath <sample.exe>'
        LiveCommand = '.\run.ps1 -Mode Analyze -SamplePath <sample.exe> -Live'
        LiveNoVmConsoleCommand = '.\run.ps1 -Mode Analyze -SamplePath <sample.exe> -Live -NoOpenVmConsole'
        AnalyzeNotepadPlanCommand = '.\run.ps1 -Mode Analyze -SamplePreset Notepad'
        AnalyzeNotepadLiveCommand = '.\run.ps1 -Mode Analyze -SamplePreset Notepad -Live'
        AnalyzeHarmlessSamplePlanCommand = '.\run.ps1 -Mode Analyze -SamplePreset HarmlessSample'
        AnalyzeHarmlessSampleLiveCommand = '.\run.ps1 -Mode Analyze -SamplePreset HarmlessSample -Live'
        ReadinessCommand = '.\run.ps1 -Mode CheckEnvironment'
        ChineseGuidance = '中文提示：默认 .\run.ps1 只启动 WebUI，不修改 VM；Analyze/Plan 不加 -Live 时不会启动、还原或停止 VM；Analyze -Live 才可能修改已配置 VM。所有凭据只读取环境变量且不打印值。'
        WhatIfSupported = $true
        DefaultStartsVm = $false
        DefaultMutatesVm = $false
        WebUiStartsVm = $false
        WebUiMutatesVm = $false
        LiveRequiresExplicitSwitch = $true
        AnalyzeLiveMayMutateVm = $true
        AnalyzeLiveMutationOperations = @('RestoreCleanBaseline', 'StartVm', 'CopyPayloadAndSampleIntoGuest', 'RunGuestAgent', 'StopVm', 'OptionalRestoreCleanBaselineAfterRun')
        LegacyAnalyzeLiveMutationOperations = @('RestoreCheckpoint', 'StartVm', 'CopyPayloadAndSampleIntoGuest', 'RunGuestAgent', 'StopVm', 'OptionalRestoreCheckpointAfterRun')
        CheckEnvironmentStartsVm = $false
        CheckEnvironmentMutatesVm = $false
        PlanOnlyStartsVm = $false
        PlanOnlyMutatesVm = $false
        OpenVmConsoleOnLiveStartDefault = $runStatus.VmMutationPolicy.OpenVmConsoleOnLiveStartDefault
        OpenVmConnectOnLiveStart = $runStatus.VmMutationPolicy.OpenVmConnectOnLiveStart
        OpenVmConsoleIsBestEffort = $false
        OpenVmConsoleFailureBlocksHeadless = $runStatus.VmMutationPolicy.OpenVmConsoleFailureBlocksHeadless
        VmConsoleRequiredUnlessNoOpenVmConsole = $runStatus.VmMutationPolicy.VmConsoleRequiredUnlessNoOpenVmConsole
        DotNetAvailable = $null -ne (Get-Command dotnet -ErrorAction SilentlyContinue)
        WebProjectExists = Test-Path -LiteralPath $webProject -PathType Leaf
        WebUiLaunchKind = $webLaunchTarget.Kind
        WebUiLaunchPath = $webLaunchTarget.Path
        PublishedWebAppExists = ($webLaunchTarget.PublishedExeExists -or $webLaunchTarget.PublishedDllExists)
        PortableWebUiReady = ($webLaunchTarget.Kind -in @('PublishedExe', 'PublishedDll'))
        ProviderExecutionToolReady = $runStatus.ProviderExecutionToolReady
        ProviderExecutionToolKind = $runStatus.ProviderExecutionToolKind
        ProviderExecutionToolPath = $runStatus.ProviderExecutionToolPath
        ProviderExecutionToolRequiresDotNet = $runStatus.ProviderExecutionToolRequiresDotNet
        ActualGuestPasswordUnknownOldPasswordRecoverySupported = $runStatus.ActualGuestPasswordUnknownOldPasswordRecoverySupported
        ActualGuestPasswordUnknownOldPasswordRecoveryReady = $runStatus.ActualGuestPasswordUnknownOldPasswordRecoveryReady
        ActualGuestPasswordUnknownOldPasswordRecoveryRequiresElevation = $runStatus.ActualGuestPasswordUnknownOldPasswordRecoveryRequiresElevation
        ActualGuestPasswordUnknownOldPasswordRecoveryElevationReady = $runStatus.ActualGuestPasswordUnknownOldPasswordRecoveryElevationReady
        ActualGuestPasswordUnknownOldPasswordRecoveryToolPath = $runStatus.ActualGuestPasswordUnknownOldPasswordRecoveryToolPath
        ActualGuestPasswordUnknownOldPasswordRecoveryStorageCmdletsReady = $runStatus.ActualGuestPasswordUnknownOldPasswordRecoveryStorageCmdletsReady
        ActualGuestPasswordUnknownOldPasswordRecoveryLayoutValidation = $runStatus.ActualGuestPasswordUnknownOldPasswordRecoveryLayoutValidation
        ActualGuestPasswordUnknownOldPasswordRecoveryMode = $runStatus.ActualGuestPasswordUnknownOldPasswordRecoveryMode
        HyperVE2EScriptExists = Test-Path -LiteralPath $hyperVScript -PathType Leaf
        LegacyHyperVE2EScriptExists = Test-Path -LiteralPath $hyperVScript -PathType Leaf
        PayloadPreparationScriptExists = Test-Path -LiteralPath $payloadScript -PathType Leaf
        SecretValuePrinted = $false
        Status = $runStatus
    }
}

function Test-CanBindTcpPort {
    param(
        [Parameter(Mandatory)][string]$HostName,
        [Parameter(Mandatory)][int]$Port
    )

    $listener = $null
    try {
        $address = if ($HostName -in @('localhost', '+', '*')) {
            [System.Net.IPAddress]::Loopback
        }
        else {
            [System.Net.IPAddress]::Parse($HostName)
        }

        $listener = [System.Net.Sockets.TcpListener]::new($address, $Port)
        $listener.ExclusiveAddressUse = $true
        $listener.Start()
        return [pscustomobject]@{ CanBind = $true; Error = '' }
    }
    catch {
        $message = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
        return [pscustomobject]@{ CanBind = $false; Error = $message }
    }
    finally {
        if ($null -ne $listener) {
            $listener.Stop()
        }
    }
}

function Resolve-WebListenUrl {
    param([Parameter(Mandatory)][string]$RequestedUrl)

    $uri = [Uri]$RequestedUrl
    if ($uri.Scheme -ne 'http') {
        return $RequestedUrl
    }

    $hostName = if ([string]::IsNullOrWhiteSpace($uri.Host)) { '127.0.0.1' } else { $uri.Host }
    $port = if ($uri.IsDefaultPort) { 80 } else { $uri.Port }
    $probe = Test-CanBindTcpPort -HostName $hostName -Port $port
    if ($probe.CanBind) {
        return $RequestedUrl
    }

    if ($StrictUrl) {
        throw "错误：请求的 WebUI URL '$RequestedUrl' 无法绑定：$($probe.Error)。下一步：换一个 -Url 端口，或关闭占用该端口的进程；也可去掉 -StrictUrl 让脚本自动选备用端口。"
    }

    Write-RunInfo "中文提示：请求的 WebUI URL '$RequestedUrl' 无法绑定，将尝试备用端口。英文详情：$($probe.Error)"
    $candidatePorts = @($port, 18080, 18081, 18082, 18083, 28080, 28081, 38080, 49152, 52123, 55000) | Select-Object -Unique
    foreach ($candidatePort in $candidatePorts) {
        if ($candidatePort -eq $port) {
            continue
        }

        $candidateProbe = Test-CanBindTcpPort -HostName $hostName -Port ([int]$candidatePort)
        if ($candidateProbe.CanBind) {
            $builder = [UriBuilder]::new($uri)
            $builder.Port = [int]$candidatePort
            $fallbackUrl = $builder.Uri.GetLeftPart([UriPartial]::Authority)
            Write-RunInfo "已切换到备用 WebUI URL：$fallbackUrl / Falling back to WebUI URL."
            return $fallbackUrl
        }
    }

    throw "错误：没有找到可用的 localhost WebUI 端口。'$RequestedUrl' 的最后错误：$($probe.Error)。下一步：关闭占用端口的程序，或用 -Url http://127.0.0.1:<free-port> 指定空闲端口。"
}

function Invoke-WebUi {
    param([Parameter(Mandatory)][string]$EffectiveConfigPath)

    $launchTarget = Get-WebUiLaunchTarget

    $effectiveUrl = Resolve-WebListenUrl -RequestedUrl $Url
    $script:Url = $effectiveUrl
    Write-RunInfo "正在启动 WebUI：$effectiveUrl / Starting WebUI."
    Write-RunInfo "WebUI 启动目标：$($launchTarget.Kind) -> $($launchTarget.Path) / WebUI launch target."
    Write-RunInfo "配置文件：$EffectiveConfigPath / Config."
    Write-RunInfo "Live 前置条件：已配置 provider/VM/baseline、已准备 self-contained guest payload、已设置 guest password secret，且 guest transport 可用。 / Provider live prerequisites."
    $vtSecretName = 'KSWORDBOX_VIRUSTOTAL_API_KEY'
    if ($null -ne (Get-Variable -Name state -Scope Script -ErrorAction SilentlyContinue)) {
        $vtSecretName = Get-VirusTotalSecretName -State $script:state
    }
    $vtConfigured = (-not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($vtSecretName, 'Process'))) -or
        (-not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($vtSecretName, 'User'))) -or
        (-not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($vtSecretName, 'Machine')))
    if ($vtConfigured) {
        Write-RunInfo "VirusTotal：已检测到可选 hash-only enrichment key（值不打印）。 / VT optional key configured."
    }
    else {
        Write-RunInfo "VirusTotal：未配置可选 key；WebUI 会静默跳过 hash 查询，不把失败噪声写入 job log。 / VT optional key missing; skipped quietly."
    }
    Write-RunInfo '中文提示：默认启动 WebUI 不会启动或还原 VM；任何 provider 的实时执行都必须在 WebUI/API 或 CLI 中显式选择 Live。'
    Write-RunInfo '按 Ctrl+C 停止 WebUI。 / Press Ctrl+C to stop the WebUI.'

    if (-not $PSCmdlet.ShouldProcess($effectiveUrl, "Start WebUI with '$($launchTarget.Path)'")) {
        Write-RunInfo "预览：WebUI 会以配置 '$EffectiveConfigPath' 启动在 $effectiveUrl；当前不会启动 dotnet 或浏览器。 / WhatIf: WebUI would start."
        return
    }

    $env:ASPNETCORE_URLS = $effectiveUrl

    if ($OpenBrowser) {
        Write-RunInfo "将自动打开浏览器：$effectiveUrl / Browser will open automatically."
        Start-Job -ScriptBlock {
            param([string]$TargetUrl)
            Start-Sleep -Seconds 2
            Start-Process $TargetUrl
        } -ArgumentList $effectiveUrl | Out-Null
    }

    if ($launchTarget.RequiresDotNet -and $null -eq (Get-Command dotnet -ErrorAction SilentlyContinue)) {
        throw "错误：WebUI 启动目标 '$($launchTarget.Kind)' 需要 dotnet，但当前 PATH 找不到 dotnet。下一步：安装 .NET SDK/Runtime，或使用包含 self-contained exe 的便携包。"
    }

    if ($NoBuild -and -not $launchTarget.SupportsNoBuild) {
        Write-RunInfo '中文提示：当前是已发布 WebUI 目标，-NoBuild 无需生效；将直接启动发布产物。 / -NoBuild is ignored for published WebUI.'
    }

    Set-Location -LiteralPath $script:RepositoryRoot

    if ($launchTarget.Kind -eq 'SourceProject') {
        $arguments = @('run', '--no-launch-profile', '--project', $launchTarget.Path)
        if ($NoBuild) {
            $arguments += '--no-build'
        }

        & dotnet @arguments
        exit $LASTEXITCODE
    }

    if ($launchTarget.Kind -eq 'PublishedDll') {
        & dotnet $launchTarget.Path
        exit $LASTEXITCODE
    }

    & $launchTarget.Path
    exit $LASTEXITCODE
}

function Invoke-OneShotAnalysis {
    param(
        [Parameter(Mandatory)][string]$EffectiveConfigPath,
        [Parameter(Mandatory)][object]$Config,
        [Parameter(Mandatory)][string]$EffectiveRuntimeRoot,
        [AllowNull()]$State
    )

    $resolvedSample = Resolve-AnalysisSamplePath -EffectiveRuntimeRoot $EffectiveRuntimeRoot
    if (-not (Test-Path -LiteralPath $resolvedSample -PathType Leaf)) {
        if ($WhatIfPreference) {
            Write-RunInfo "预览：样本可执行文件暂不存在，但真实运行前会准备/解析：$resolvedSample。 / WhatIf: sample would be prepared/resolved."
        }
        else {
            throw "错误：找不到样本可执行文件：$resolvedSample。下一步：请检查 -SamplePath，或改用 -SamplePreset Notepad/HarmlessSample。"
        }
    }
    if ([System.IO.Path]::GetExtension($resolvedSample) -ine '.exe') {
        throw "错误：v1 单次分析只接受 .exe 样本：$resolvedSample。下一步：请选择 Windows .exe 文件。"
    }

    $provider = Get-RunVirtualizationProvider -Config $Config
    Assert-RunProviderResourceOverrides -Provider $provider -Config $Config
    $runLive = [bool]$Live -and (-not [bool]$PlanOnly) -and ($Mode -ne 'Plan')
    if ($runLive -and $provider -eq 'HyperV' -and (-not (Test-RunIsAdministrator)) -and (-not $WhatIfPreference)) {
        Invoke-RunSelfElevatedForLive -ResolvedSamplePath $resolvedSample
    }

    $payloadRoot = Get-GuestPayloadRoot -State $State -Config $Config -EffectiveRuntimeRoot $EffectiveRuntimeRoot
    if ($NoR0Collector) {
        Write-RunInfo 'R0Collector: 本次 Analyze/Plan 已通过 -NoR0Collector 禁用 R0 sidecar；不会修改配置文件。'
        Write-RunInfo '中文提示：这适合 unsigned driver/test-signing 未就绪时验证真实 VM/Guest/ETW/artifact/report 主链路；该运行不能证明真实 R0 覆盖。'
    }
    else {
        Write-R0DriverConfigurationWarning -Config $Config
    }
    if ($runLive) {
        Ensure-GuestPayload -PayloadRoot $payloadRoot -Config $Config
    }
    else {
        Write-RunInfo "PlanOnly: guest payload preparation skipped：$payloadRoot。 / Guest payload preparation skipped."
        Write-RunInfo "生成的 $provider 计划会报告缺失/过期 payload 文件和修复建议，但不会构建、复制 payload 或修改 VM。 / Plan reports readiness issues without VM mutation."
    }

    $analysisAction = if ($runLive) {
        "委托 Live $provider 分析；可能还原/启动/停止已配置 VM。 / Delegate live $provider analysis."
    }
    else {
        "创建不修改 VM 的 $provider 分析计划 / Create a non-mutating $provider analysis plan"
    }
    if (-not $PSCmdlet.ShouldProcess($resolvedSample, $analysisAction)) {
        Write-RunInfo "预览：将对 '$resolvedSample' 执行：$analysisAction；当前不会启动 JobTool。 / WhatIf: JobTool was not launched."
        return
    }

    Import-PortableToolResolver
    $jobToolTarget = Resolve-KSwordPortableTool -RepoRoot $script:RepositoryRoot -Tool JobTool -ThrowIfMissing
    $arguments = @(
        'execute',
        '--repo-root', $script:RepositoryRoot,
        '--config', $EffectiveConfigPath,
        '--runtime-root', $EffectiveRuntimeRoot,
        '--sample', $resolvedSample,
        '--duration', ([string]$DurationSeconds),
        '--guest-ready-timeout-seconds', ([string]$GuestReadyTimeoutSeconds),
        '--step-timeout-seconds', ([string]$ExecutionTimeoutSeconds),
        '--provider', $provider
    )

    if (-not [string]::IsNullOrWhiteSpace($VmName)) {
        $arguments += @('--vm', $VmName.Trim())
    }
    if (-not [string]::IsNullOrWhiteSpace($BaselineName)) {
        $arguments += @('--baseline', $BaselineName.Trim())
    }
    if (-not [string]::IsNullOrWhiteSpace($MachineDefinitionPath)) {
        $arguments += @('--machine-definition-path', $MachineDefinitionPath.Trim())
    }
    if (-not [string]::IsNullOrWhiteSpace($QemuDiskFormat)) {
        $arguments += @('--qemu-disk-format', $QemuDiskFormat.Trim().ToLowerInvariant())
    }

    if ($runLive) {
        $arguments += '--live'
        Write-RunInfo "正在启动 Live $provider 分析：$resolvedSample / Starting live $provider analysis."
        Write-RunInfo "中文提示：这是 Live 模式，可能还原/启动/停止配置的 $provider VM；凭据值不会打印。"
    }
    else {
        Write-RunInfo "仅生成计划，不修改 VM：$resolvedSample / Planning only, no VM mutation."
        Write-RunInfo "下一步：如需在配置的 $provider VM 中真实执行样本，请追加 -Live。 / Add -Live for live execution."
        Write-RunInfo '中文提示：当前为计划模式，不会执行样本或改变 VM。'
    }
    if ($NoR0Collector) {
        $arguments += '--no-r0-collector'
    }
    if ($NoOpenVmConsole) {
        $arguments += '--no-open-vm-console'
    }

    $toolInvocation = Invoke-RunJobToolCaptured -Target $jobToolTarget -Arguments $arguments
    foreach ($line in @($toolInvocation.Output)) {
        Write-Host ([string]$line)
    }

    if ([int]$toolInvocation.ExitCode -ne 0) {
        exit ([int]$toolInvocation.ExitCode)
    }

    exit 0
}

function Assert-RunProviderResourceOverrides {
    param(
        [Parameter(Mandatory)][ValidateSet('HyperV', 'VMware', 'Qemu')][string]$Provider,
        [Parameter(Mandatory)][object]$Config
    )

    if ($Provider -eq 'HyperV' -and -not [string]::IsNullOrWhiteSpace($MachineDefinitionPath)) {
        throw '错误：HyperV 不接受 -MachineDefinitionPath；VM 定义由 Hyper-V inventory 中的 -VmName 选择。 / HyperV does not accept a machine-definition path override.'
    }
    if ($Provider -ne 'Qemu' -and -not [string]::IsNullOrWhiteSpace($QemuDiskFormat)) {
        throw "错误：-QemuDiskFormat 只适用于 Qemu，当前 provider 为 $Provider。 / QemuDiskFormat is valid only for Qemu."
    }
    if ($Provider -eq 'Qemu' -and -not [string]::IsNullOrWhiteSpace($BaselineName)) {
        $qemuConfig = Get-RunObjectPropertyValue -Object $Config -Name 'qemu' -DefaultValue $null
        $useOverlayDisk = Get-RunBooleanOrDefault -Value (Get-RunObjectPropertyValue -Object $qemuConfig -Name 'useOverlayDisk' -DefaultValue $true) -DefaultValue $true
        if ($useOverlayDisk -and -not $BaselineName.Trim().Equals('per-job-overlay', [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "错误：当前 QEMU profile 使用 per-job overlay，-BaselineName '$BaselineName' 不会对应内部 snapshot。请去掉该参数、使用 per-job-overlay，或先把 qemu.useOverlayDisk 设为 false。 / The QEMU overlay profile does not accept an internal snapshot baseline override."
        }
    }
}

function Get-RunVirtualizationProvider {
    param([Parameter(Mandatory)][object]$Config)

    $selectedProvider = $script:Provider
    if ([string]::IsNullOrWhiteSpace($selectedProvider)) {
        $selectedProvider = 'HyperV'
        $virtualizationProperty = $Config.PSObject.Properties['virtualization']
        if ($null -ne $virtualizationProperty -and $null -ne $virtualizationProperty.Value) {
            $providerProperty = $virtualizationProperty.Value.PSObject.Properties['provider']
            if ($null -ne $providerProperty -and -not [string]::IsNullOrWhiteSpace([string]$providerProperty.Value)) {
                $selectedProvider = [string]$providerProperty.Value
            }
        }
    }

    switch -Regex ($selectedProvider.Trim()) {
        '^(?i:hyper-?v)$' { return 'HyperV' }
        '^(?i:vmware)$' { return 'VMware' }
        '^(?i:qemu)$' { return 'Qemu' }
        default { throw "错误：不支持 provider='$selectedProvider'；应为 HyperV、VMware 或 Qemu。" }
    }
}

function Invoke-RunJobToolCaptured {
    param(
        [Parameter(Mandatory)]$Target,
        [Parameter(Mandatory)][string[]]$Arguments
    )

    if ($Target.RequiresDotNet -and $null -eq (Get-Command dotnet -ErrorAction SilentlyContinue)) {
        throw "错误：JobTool 启动目标 '$($Target.Kind)' 需要 dotnet，但当前 PATH 找不到 dotnet。$($Target.RecommendedAction)"
    }

    $output = @()
    $exitCode = 1
    if ($Target.Kind -eq 'SourceProject') {
        $dotnetArguments = @('run')
        if ($NoBuild) {
            $dotnetArguments += '--no-build'
        }
        $dotnetArguments += @('--project', [string]$Target.Path, '--')
        $dotnetArguments += $Arguments
        $output = @(& dotnet @dotnetArguments 2>&1)
        $exitCode = $LASTEXITCODE
    }
    elseif ($Target.Kind -eq 'PublishedDll') {
        $output = @(& dotnet ([string]$Target.Path) @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
    }
    elseif ($Target.Kind -eq 'PublishedExe') {
        $output = @(& ([string]$Target.Path) @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
    }
    else {
        throw "错误：无法启动 JobTool：目标类型为 $($Target.Kind)。"
    }

    return [pscustomobject][ordered]@{
        ExitCode = [int]$exitCode
        Output = @($output)
    }
}

$state = Read-InstallState
$effectiveRuntimeRoot = Get-EffectiveRuntimeRoot -State $state
$effectiveConfigPath = Get-EffectiveConfigPath -State $state -EffectiveRuntimeRoot $effectiveRuntimeRoot
Import-InstalledEnvironment -State $state -EffectiveConfigPath $effectiveConfigPath

if ($Mode -in @('WebUI', 'StartWebUI') -and -not [string]::IsNullOrWhiteSpace($SamplePath)) {
    $script:RunModeCoerced = $true
    $script:RunModeCoercionReason = 'SamplePath supplied with WebUI/StartWebUI; routing to Analyze so the sample is handled by the one-shot analysis path.'
    $script:RunModeCoercionTriggerParameter = 'SamplePath'
    $script:RunModeCoercionOriginalMode = $Mode
    if (-not $Json) {
        Write-RunInfo "ModeCoercion：检测到 -SamplePath，已从 $Mode 切换到 Analyze；默认仍不修改 VM，除非显式加 -Live。 / Mode coerced to Analyze."
    }
    $Mode = 'Analyze'
}
$script:EffectiveRunMode = $Mode

$hasOneShotResourceOverride = -not [string]::IsNullOrWhiteSpace($VmName) -or
    -not [string]::IsNullOrWhiteSpace($BaselineName) -or
    -not [string]::IsNullOrWhiteSpace($MachineDefinitionPath) -or
    -not [string]::IsNullOrWhiteSpace($QemuDiskFormat)
if ($hasOneShotResourceOverride -and $Mode -notin @('Plan', 'Analyze')) {
    throw "错误：-VmName/-BaselineName/-MachineDefinitionPath/-QemuDiskFormat 只适用于单次 Plan/Analyze；当前模式为 $Mode，参数未被执行。 / Provider resource overrides are valid only for one-shot Plan or Analyze."
}

$hasProviderOverride = -not [string]::IsNullOrWhiteSpace($Provider)
if ($hasProviderOverride -and $Mode -notin @('Status', 'CheckEnvironment', 'Plan', 'Analyze')) {
    throw "错误：-Provider 只适用于 Status/CheckEnvironment/Plan/Analyze；纯 WebUI 启动从本机 config 读取 provider，不能静默应用单次覆盖。 / Provider override is valid only for diagnostics or one-shot planning/execution; WebUI reads the local config."
}

if (($Json -or $PassThru) -and $Mode -notin @('Status', 'CheckEnvironment')) {
    throw '错误：-Json/-PassThru 只支持 run.ps1 的 Status/CheckEnvironment 诊断输出，避免启动 WebUI、执行样本或委托 Live 时混入非 JSON 输出。下一步：改用 .\run.ps1 -Mode CheckEnvironment -Json。'
}

switch ($Mode) {
    'Status' {
        Write-RunDiagnosticObject -InputObject (Show-RunStatus -State $state -EffectiveRuntimeRoot $effectiveRuntimeRoot -EffectiveConfigPath $effectiveConfigPath)
    }
    'CheckEnvironment' {
        Write-RunDiagnosticObject -InputObject (Show-RunEnvironmentCheck -State $state -EffectiveRuntimeRoot $effectiveRuntimeRoot -EffectiveConfigPath $effectiveConfigPath)
    }
    'WebUI' {
        Assert-RunLocalConfigReadyForInteractiveStartup -EffectiveConfigPath $effectiveConfigPath -ModeName 'WebUI'
        $config = Read-SandboxConfig -EffectiveConfigPath $effectiveConfigPath
        Write-R0DriverConfigurationWarning -Config $config
        $payloadRoot = Get-GuestPayloadRoot -State $state -Config $config -EffectiveRuntimeRoot $effectiveRuntimeRoot
        Ensure-GuestPayloadForWebUi -PayloadRoot $payloadRoot -Config $config
        Invoke-WebUi -EffectiveConfigPath $effectiveConfigPath
    }
    'StartWebUI' {
        Assert-RunLocalConfigReadyForInteractiveStartup -EffectiveConfigPath $effectiveConfigPath -ModeName 'StartWebUI'
        if (-not $PSBoundParameters.ContainsKey('OpenBrowser')) {
            $script:OpenBrowser = $true
            Write-RunInfo 'StartWebUI 模式会自动打开浏览器；如需无浏览器自动化，请使用 WebUI 模式或传入 -OpenBrowser:$false。'
        }
        $config = Read-SandboxConfig -EffectiveConfigPath $effectiveConfigPath
        Write-R0DriverConfigurationWarning -Config $config
        $payloadRoot = Get-GuestPayloadRoot -State $state -Config $config -EffectiveRuntimeRoot $effectiveRuntimeRoot
        Ensure-GuestPayloadForWebUi -PayloadRoot $payloadRoot -Config $config
        Invoke-WebUi -EffectiveConfigPath $effectiveConfigPath
    }
    'Plan' {
        Assert-RunLocalConfigReadyForInteractiveStartup -EffectiveConfigPath $effectiveConfigPath -ModeName 'Plan'
        $config = Read-SandboxConfig -EffectiveConfigPath $effectiveConfigPath
        Invoke-OneShotAnalysis -EffectiveConfigPath $effectiveConfigPath -Config $config -EffectiveRuntimeRoot $effectiveRuntimeRoot -State $state
    }
    'Analyze' {
        Assert-RunLocalConfigReadyForInteractiveStartup -EffectiveConfigPath $effectiveConfigPath -ModeName 'Analyze'
        $config = Read-SandboxConfig -EffectiveConfigPath $effectiveConfigPath
        Invoke-OneShotAnalysis -EffectiveConfigPath $effectiveConfigPath -Config $config -EffectiveRuntimeRoot $effectiveRuntimeRoot -State $state
    }
}
