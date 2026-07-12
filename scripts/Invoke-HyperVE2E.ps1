<#
.SYNOPSIS
Builds or executes the KSword Sandbox Hyper-V E2E plan.

.DESCRIPTION
The default behavior is intentionally safe: the script writes a reviewable JSON
plan and exits without restoring checkpoints, starting VMs, copying files, or
running guest code. Live VM execution requires -Live from an elevated shell.
Passing -WhatIf also prevents all VM mutation even when -Live is present.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    # Repository root. Defaults to the parent of this script directory.
    [string]$RepoRoot = '',

    # Sandbox JSON config. Defaults to config/sandbox.example.json under RepoRoot.
    [string]$ConfigPath = '',

    # Optional runtime root override. Defaults to paths.runtimeRoot from config.
    [string]$RuntimeRoot = '',

    # Host sample executable to copy into the guest during live execution.
    [string]$SamplePath = 'D:\Temp\KSwordSandbox\samples\KSword.Sandbox.HarmlessSample\KSword.Sandbox.HarmlessSample.exe',

    # Output plan JSON path. Defaults outside the repo under runtimeRoot\plans.
    [string]$PlanPath = '',

    # Optional fixed job id. Defaults to a new GUID.
    [string]$JobId = '',

    # Forces plan-only mode even if -Live is also supplied.
    [switch]$PlanOnly,

    # Enables live VM execution. Without this switch, only a plan is written.
    [switch]$Live,

    # Analysis duration in seconds. 0 means use config.analysis.defaultDurationSeconds.
    [int]$DurationSeconds = 0,

    # Timeout for the VM to reach Running after Start-VM.
    [int]$StartupTimeoutSeconds = 180,

    # Timeout for PowerShell Direct readiness after the VM starts.
    [int]$GuestReadyTimeoutSeconds = 300,

    # Timeout while waiting for Guest Agent completion. 0 means duration + 120 seconds.
    [int]$ExecutionTimeoutSeconds = 0,

    # Restores the clean checkpoint again after stopping the VM at the end.
    [bool]$RestoreCheckpointAfterRun = $true,

    # Optional overrides for config values.
    [string]$VmName = '',
    [string]$CheckpointName = '',
    [string]$GuestUserName = '',
    [string]$GuestPasswordSecretName = '',
    [string]$GuestWorkingDirectory = '',
    [string]$GuestPayloadRoot = '',

    # Disables R0Collector arguments for this E2E plan without editing config.
    [switch]$NoR0Collector,

    # Disables interactive desktop launch when live analysis starts.
    # Live mode opens the VM desktop by default so samples that need manual UI
    # interaction can be observed/interacted with. The start phase first tries
    # Hyper-V VMConnect, then mstsc/RDP fallback when available.
    [switch]$NoOpenVmConsole
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$script:GuestServiceInterfaceComponentId = '6C09BB55-D683-4DA0-8931-C9BF705F6480'
$script:LastHyperVE2EPlan = $null

function Write-HyperVE2EStep {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "[hyperv-e2e] $Message"
}

function Resolve-DefaultRepoRoot {
    if (-not [string]::IsNullOrWhiteSpace($script:PSScriptRoot)) {
        return (Split-Path -Parent $script:PSScriptRoot)
    }

    $scriptPath = $MyInvocation.MyCommand.Path
    if (-not [string]::IsNullOrWhiteSpace($scriptPath)) {
        return (Split-Path -Parent (Split-Path -Parent $scriptPath))
    }

    return (Get-Location).Path
}

function Resolve-ConfiguredPath {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$BasePath
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $Path
    }

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath((Join-Path $BasePath $Path))
}

function Get-ObjectPropertyValue {
    param(
        [object]$Object,
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

function Get-StringOrDefault {
    param(
        [string]$Value,
        [Parameter(Mandatory)][string]$DefaultValue
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $DefaultValue
    }

    return $Value
}

function Get-BooleanOrDefault {
    param(
        [object]$Value,
        [bool]$DefaultValue
    )

    if ($null -eq $Value) {
        return $DefaultValue
    }

    return [System.Convert]::ToBoolean($Value)
}

function Get-IntOrDefault {
    param(
        [object]$Value,
        [int]$DefaultValue
    )

    if ($null -eq $Value) {
        return $DefaultValue
    }

    return [System.Convert]::ToInt32($Value, [Globalization.CultureInfo]::InvariantCulture)
}

function Get-GuestPasswordSecretValue {
    param([Parameter(Mandatory)][string]$SecretName)

    foreach ($scope in @('Process', 'User', 'Machine')) {
        $value = [Environment]::GetEnvironmentVariable($SecretName, $scope)
        if (-not [string]::IsNullOrEmpty($value)) {
            return [pscustomobject]@{
                Value = $value
                Scope = $scope
                IsSet = $true
            }
        }
    }

    return [pscustomobject]@{
        Value = $null
        Scope = ''
        IsSet = $false
    }
}

function Join-GuestPath {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string[]]$Segments
    )

    $current = $Root.TrimEnd('\', '/')
    foreach ($segment in $Segments) {
        if ([string]::IsNullOrWhiteSpace($segment)) {
            continue
        }

        $current = $current + '\' + $segment.TrimStart('\', '/')
    }

    return $current
}

function Quote-PowerShellString {
    param([string]$Text)
    if ($null -eq $Text) {
        $Text = ''
    }

    return "'" + ($Text -replace "'", "''") + "'"
}

function Test-IsAdministrator {
    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function ConvertTo-PlanCheckId {
    param([AllowNull()][string]$Name)

    $value = if ([string]::IsNullOrWhiteSpace($Name)) { 'plan-check' } else { $Name.Trim() }
    $slug = [regex]::Replace($value.ToLowerInvariant(), '[^a-z0-9]+', '-').Trim('-')
    if ([string]::IsNullOrWhiteSpace($slug)) {
        return 'plan-check'
    }

    return $slug
}

function New-PlanCheck {
    param(
        [Parameter(Mandatory)][string]$Name,
        [ValidateSet('Passed', 'Warning', 'Failed')][string]$Status,
        [bool]$RequiredForLive,
        [Parameter(Mandatory)][string]$Message,
        [System.Collections.IDictionary]$Details = @{},
        [string[]]$Remediation = @(),
        [string]$Category = 'general'
    )

    $orderedDetails = [ordered]@{}
    foreach ($key in $Details.Keys) {
        $orderedDetails[$key] = $Details[$key]
    }

    return [ordered]@{
        checkId         = ConvertTo-PlanCheckId -Name $Name
        category        = $Category
        name            = $Name
        status          = $Status
        requiredForLive = $RequiredForLive
        machineReadable = $true
        message         = $Message
        remediation     = @($Remediation)
        details         = $orderedDetails
    }
}

function New-FilePresenceCheck {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Path,
        [bool]$RequiredForLive,
        [string[]]$Remediation = @()
    )

    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        return New-PlanCheck `
            -Name $Name `
            -Status 'Passed' `
            -RequiredForLive $RequiredForLive `
            -Message "File exists: $Path" `
            -Details @{ path = $Path; exists = $true }
    }

    $missingStatus = if ($RequiredForLive) { 'Failed' } else { 'Warning' }
    $missingMessage = if ($RequiredForLive) {
        "File is not present yet; live mode will fail until it exists: $Path"
    }
    else {
        "Optional file is not present: $Path"
    }
    $effectiveRemediation = @($Remediation)
    if ($effectiveRemediation.Count -eq 0) {
        $effectiveRemediation = @("Create or configure the expected file, then rerun .\scripts\Invoke-HyperVE2E.ps1 -PlanOnly: $Path")
    }

    return New-PlanCheck `
        -Name $Name `
        -Status $missingStatus `
        -RequiredForLive $RequiredForLive `
        -Message $missingMessage `
        -Details @{ path = $Path; exists = $false } `
        -Remediation $effectiveRemediation
}

function New-DirectoryPresenceCheck {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Path,
        [bool]$RequiredForLive,
        [string[]]$Remediation = @()
    )

    if (Test-Path -LiteralPath $Path -PathType Container) {
        return New-PlanCheck `
            -Name $Name `
            -Status 'Passed' `
            -RequiredForLive $RequiredForLive `
            -Message "Directory exists: $Path" `
            -Details @{ path = $Path; exists = $true }
    }

    $missingStatus = if ($RequiredForLive) { 'Failed' } else { 'Warning' }
    $missingMessage = if ($RequiredForLive) {
        "Directory is not present yet; live mode will fail until it exists: $Path"
    }
    else {
        "Optional directory is not present: $Path"
    }
    $effectiveRemediation = @($Remediation)
    if ($effectiveRemediation.Count -eq 0) {
        $effectiveRemediation = @("Create or configure the expected directory, then rerun .\scripts\Invoke-HyperVE2E.ps1 -PlanOnly: $Path")
    }

    return New-PlanCheck `
        -Name $Name `
        -Status $missingStatus `
        -RequiredForLive $RequiredForLive `
        -Message $missingMessage `
        -Details @{ path = $Path; exists = $false } `
        -Remediation $effectiveRemediation
}

function Test-IsPlanPathUnderRoot {
    param(
        [AllowNull()][string]$Path,
        [AllowNull()][string]$Root
    )

    if ([string]::IsNullOrWhiteSpace($Path) -or [string]::IsNullOrWhiteSpace($Root)) {
        return $false
    }

    try {
        $fullPath = [System.IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
        $fullRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
        return $fullPath.Equals($fullRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
            $fullPath.StartsWith($fullRoot + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)
    }
    catch {
        return $false
    }
}

function New-HostSharedPathCheck {
    param(
        [Parameter(Mandatory)][string]$RuntimeRoot,
        [Parameter(Mandatory)][string]$GuestPayloadRoot,
        [Parameter(Mandatory)][string]$RepositoryRoot
    )

    $runtimeIsAbsolute = [System.IO.Path]::IsPathRooted($RuntimeRoot)
    $payloadIsAbsolute = [System.IO.Path]::IsPathRooted($GuestPayloadRoot)
    $runtimeUnderRepo = Test-IsPlanPathUnderRoot -Path $RuntimeRoot -Root $RepositoryRoot
    $payloadUnderRepo = Test-IsPlanPathUnderRoot -Path $GuestPayloadRoot -Root $RepositoryRoot
    $details = @{
        runtimeRoot = $RuntimeRoot
        runtimeRootIsAbsolute = $runtimeIsAbsolute
        runtimeRootExists = (Test-Path -LiteralPath $RuntimeRoot -PathType Container)
        runtimeRootUnderRepository = $runtimeUnderRepo
        guestPayloadRoot = $GuestPayloadRoot
        guestPayloadRootIsAbsolute = $payloadIsAbsolute
        guestPayloadRootExists = (Test-Path -LiteralPath $GuestPayloadRoot -PathType Container)
        guestPayloadRootUnderRepository = $payloadUnderRepo
        repositoryRoot = $RepositoryRoot
        copyMechanisms = @('Copy-VMFile', 'PowerShell Direct Copy-Item -ToSession', 'PowerShell Direct Copy-Item -FromSession')
        readOnly = $true
    }

    if ((-not $runtimeIsAbsolute) -or (-not $payloadIsAbsolute) -or $runtimeUnderRepo -or $payloadUnderRepo) {
        return New-PlanCheck `
            -Name 'Host shared path configuration' `
            -Category 'paths' `
            -Status 'Failed' `
            -RequiredForLive $true `
            -Message 'Runtime and payload exchange paths must be absolute host paths outside the repository.' `
            -Details $details `
            -Remediation @('Move runtimeRoot and guestPayloadRoot outside the git checkout, rerun payload preparation, then rerun the non-mutating plan/readiness checks.')
    }

    return New-PlanCheck `
        -Name 'Host shared path configuration' `
        -Category 'paths' `
        -Status 'Passed' `
        -RequiredForLive $true `
        -Message 'Host runtime and guest payload exchange paths are absolute and outside the repository.' `
        -Details $details
}

function New-HostTestSigningCheck {
    param(
        [bool]$DriverEnabled,
        [bool]$UseMockCollector
    )

    $realDriverMode = $DriverEnabled -and (-not $UseMockCollector)
    $bcdedit = Get-Command -Name 'bcdedit.exe' -ErrorAction SilentlyContinue
    if ($null -eq $bcdedit) {
        return New-PlanCheck `
            -Name 'Test signing status' `
            -Category 'driver' `
            -Status 'Warning' `
            -RequiredForLive $false `
            -Message 'bcdedit.exe is not available; test-signing state was not recorded.' `
            -Details @{ realDriverMode = $realDriverMode; bcdEditAvailable = $false; guestTestSigningVerified = $false; readOnly = $true } `
            -Remediation @('下一步：真实 R0 采集前，请在隔离 guest VM 中确认 test-signing；或使用 driver.useMockCollector=true。')
    }

    $testSigningValue = ''
    $exitCode = $null
    try {
        $output = & $bcdedit.Source /enum '{current}' 2>&1
        $exitCode = $LASTEXITCODE
        $text = (@($output) | ForEach-Object { [string]$_ }) -join [Environment]::NewLine
        if ($text -match '(?im)^\s*testsigning\s+(?<value>\S+)\s*$') {
            $testSigningValue = $Matches['value']
        }
    }
    catch {
        return New-PlanCheck `
            -Name 'Test signing status' `
            -Category 'driver' `
            -Status 'Warning' `
            -RequiredForLive $false `
            -Message "Unable to query host test-signing state: $($_.Exception.Message)" `
            -Details @{ realDriverMode = $realDriverMode; bcdEditAvailable = $true; error = $_.Exception.Message; guestTestSigningVerified = $false; readOnly = $true } `
            -Remediation @('下一步：真实 R0 采集前，请手动确认 guest test-signing；或使用 mock R0 collection。')
    }

    $testSigningEnabled = $testSigningValue -match '^(?i:yes|on|true|1)$'
    $status = if ($realDriverMode -and (-not $testSigningEnabled)) { 'Warning' } else { 'Passed' }
    $message = if ($testSigningEnabled) {
        '宿主机 test-signing 已启用；真实 R0 采集仍需手动确认 guest test-signing。 / Host test-signing is enabled.'
    }
    elseif ($realDriverMode) {
        '宿主机 test-signing 看起来未启用；真实 R0 采集还需要 guest test-signing。 / Host test-signing does not appear enabled.'
    }
    else {
        'Host test-signing is not enabled; mock/no-driver E2E does not require it.'
    }

    return New-PlanCheck `
        -Name 'Test signing status' `
        -Category 'driver' `
        -Status $status `
        -RequiredForLive $false `
        -Message $message `
        -Details @{ realDriverMode = $realDriverMode; bcdEditAvailable = $true; bcdEditExitCode = $exitCode; testSigningValue = $testSigningValue; testSigningEnabled = $testSigningEnabled; guestTestSigningVerified = $false; readOnly = $true } `
        -Remediation $(if ($realDriverMode -and (-not $testSigningEnabled)) { @('下一步：未签名 driver smoke test 请使用 mock R0；真实 R0 live collection 前，请在隔离 guest 中启用 Windows test-signing 并刷新 Clean checkpoint。') } else { @() })
}

function New-R0DriverHostPathCheck {
    param(
        [bool]$DriverEnabled,
        [bool]$UseMockCollector,
        [AllowNull()][string]$HostDriverPath,
        [Parameter(Mandatory)][string]$DriverPathInGuest,
        [Parameter(Mandatory)][string]$DevicePath
    )

    if (-not $DriverEnabled) {
        return New-PlanCheck `
            -Name 'R0 driver host path configuration' `
            -Status 'Passed' `
            -RequiredForLive $false `
            -Message 'R0 driver collection 已禁用，不需要宿主机 driver .sys。 / No host driver .sys required.' `
            -Details @{
                driverEnabled = $false
                useMockCollector = $UseMockCollector
                hostDriverPath = $HostDriverPath
                driverPathInGuest = $DriverPathInGuest
                devicePath = $DevicePath
            }
    }

    if ($UseMockCollector) {
        return New-PlanCheck `
            -Name 'R0 driver host path configuration' `
            -Status 'Passed' `
            -RequiredForLive $false `
            -Message 'R0 mock collector 已启用，不需要暂存 live driver .sys。 / Live driver staging not required.' `
            -Details @{
                driverEnabled = $DriverEnabled
                useMockCollector = $true
                hostDriverPath = $HostDriverPath
                driverPathInGuest = $DriverPathInGuest
                devicePath = $DevicePath
            }
    }

    if ([string]::IsNullOrWhiteSpace($HostDriverPath)) {
        return New-PlanCheck `
            -Name 'R0 driver host path configuration' `
            -Status 'Failed' `
            -RequiredForLive $true `
            -Message '真实 R0 driver collection 已启用，但 driver.hostDriverPath 为空；plan 无法暂存 .sys 或生成 install-driver-service，R0Collector 可能以 deviceUnavailable/win32Error=2 失败。下一步：配置 -DriverHostPath 或启用 driver.useMockCollector=true。' `
            -Details @{
                driverEnabled = $DriverEnabled
                useMockCollector = $UseMockCollector
                hostDriverPath = $null
                driverPathInGuest = $DriverPathInGuest
                devicePath = $DevicePath
                expectedRunbookImpact = 'stage-guest-payload uses empty driverSource and install-driver-service is omitted'
            } `
            -Remediation @(
                "下一步：Live R0 collection 前，在本机 sandbox 配置中把 driver.hostDriverPath 指向已构建且测试签名的 driver .sys。",
                "下一步：仅做 payload 验证时，设置 driver.useMockCollector=true 或运行时加 -NoR0Collector。",
                "下一步：如需完全禁用 R0 collection，设置 driver.enabled=false。"
            )
    }

    return New-FilePresenceCheck `
        -Name 'R0 driver host path configuration' `
        -Path $HostDriverPath `
        -RequiredForLive $true `
        -Remediation @(
            "下一步：构建 native driver 并把 driver.hostDriverPath 指向生成的 .sys，或修正当前路径：$HostDriverPath",
            "下一步：仅做 payload 验证时，设置 driver.useMockCollector=true 或运行时加 -NoR0Collector。"
        )
}

function Test-CommandListAvailable {
    param([Parameter(Mandatory)][string[]]$Names)

    $missing = New-Object System.Collections.Generic.List[string]
    foreach ($name in $Names) {
        if ($null -eq (Get-Command -Name $name -ErrorAction SilentlyContinue)) {
            [void]$missing.Add($name)
        }
    }

    return @($missing.ToArray())
}

function New-CommandAvailabilityCheck {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string[]]$Commands,
        [bool]$RequiredForLive
    )

    $missing = @(Test-CommandListAvailable -Names $Commands)
    if ($missing.Count -eq 0) {
        return New-PlanCheck `
            -Name $Name `
            -Status 'Passed' `
            -RequiredForLive $RequiredForLive `
            -Message "Required command(s) are available: $($Commands -join ', ')" `
            -Details @{ commands = @($Commands); missing = @() }
    }

    return New-PlanCheck `
        -Name $Name `
        -Status 'Failed' `
        -RequiredForLive $RequiredForLive `
        -Message "缺少必需命令：$($missing -join ', ')。下一步：安装/启用 Hyper-V PowerShell 工具后重试。" `
        -Details @{ commands = @($Commands); missing = @($missing) } `
        -Remediation @(
            "Install or enable the Windows Hyper-V PowerShell management tools, then open a new elevated PowerShell session.",
            "Run .\run.ps1 -Mode CheckEnvironment or .\scripts\Test-HyperVReadiness.ps1 to verify the host without starting a VM."
        )
}

function Get-HyperVVmProfileCandidates {
    param(
        [ValidateRange(1, 100)]
        [int]$Limit = 20,
        [switch]$IncludeCheckpoints
    )

    $profiles = New-Object System.Collections.Generic.List[object]
    try {
        $allVms = @(Get-VM -ErrorAction Stop | Sort-Object -Property Name)
        foreach ($vm in @($allVms | Select-Object -First $Limit)) {
            $checkpoints = New-Object System.Collections.Generic.List[object]
            $checkpointQuerySucceeded = $false
            $checkpointQueryError = ''

            if ($IncludeCheckpoints) {
                try {
                    $snapshotObjects = @(Get-VMSnapshot -VMName $vm.Name -ErrorAction Stop |
                        Sort-Object -Property CreationTime -Descending)
                    $checkpointQuerySucceeded = $true
                    foreach ($snapshot in @($snapshotObjects | Select-Object -First $Limit)) {
                        [void]$checkpoints.Add([ordered]@{
                                checkpointName = [string]$snapshot.Name
                                checkpointId   = [string]$snapshot.Id
                                creationTime   = $snapshot.CreationTime
                            })
                    }
                }
                catch {
                    $checkpointQueryError = $_.Exception.Message
                }
            }

            [void]$profiles.Add([ordered]@{
                    vmName                   = [string]$vm.Name
                    vmId                     = [string]$vm.Id
                    state                    = [string]$vm.State
                    generation               = $vm.Generation
                    checkpointQueryAttempted = [bool]$IncludeCheckpoints
                    checkpointQuerySucceeded = $checkpointQuerySucceeded
                    checkpointQueryError     = $checkpointQueryError
                    checkpoints              = @($checkpoints.ToArray())
                })
        }

        return [pscustomobject][ordered]@{
            querySucceeded     = $true
            queryError         = ''
            returnedVmCount    = $profiles.Count
            totalVmCount       = $allVms.Count
            limit              = $Limit
            includeCheckpoints = [bool]$IncludeCheckpoints
            profiles           = @($profiles.ToArray())
        }
    }
    catch {
        return [pscustomobject][ordered]@{
            querySucceeded     = $false
            queryError         = $_.Exception.Message
            returnedVmCount    = 0
            totalVmCount       = 0
            limit              = $Limit
            includeCheckpoints = [bool]$IncludeCheckpoints
            profiles           = @()
        }
    }
}

function New-GuestSecretCheck {
    param([Parameter(Mandatory)][string]$SecretName)

    if ([string]::IsNullOrWhiteSpace($SecretName)) {
        return New-PlanCheck `
            -Name 'Guest credential secret name' `
            -Status 'Failed' `
            -RequiredForLive $true `
            -Message '凭据诊断：guest password secret 名称为空；不会打印或猜测密码值。下一步：在本机 sandbox 配置中设置 guest.passwordSecretName。' `
            -Details @{ secretName = ''; isSet = $false; secretNameConfigured = $false; scopesChecked = @('Process', 'User', 'Machine'); valuePrinted = $false } `
            -Remediation @(
                "Set guest.passwordSecretName in the sandbox config, or rerun .\install.ps1 -Mode Change -UpdateHyperVConfig with the intended -SecretName.",
                "推荐使用 KSWORDBOX_GUEST_PASSWORD，并确认启动 WebUI/runner 的同一个 PowerShell 进程能读取该环境变量。"
            )
    }

    $secretValue = Get-GuestPasswordSecretValue -SecretName $SecretName
    if (-not [bool]$secretValue.IsSet) {
        return New-PlanCheck `
            -Name 'Guest credential environment variable' `
            -Status 'Failed' `
            -RequiredForLive $true `
            -Message "凭据诊断：未在 Process/User/Machine 环境中找到 guest password secret '$SecretName'；值未打印。下一步：在运行 Live 的同一个管理员 PowerShell 中设置该环境变量，或运行安装向导保存/重置密码。" `
            -Details @{ secretName = $SecretName; isSet = $false; scope = ''; scopesChecked = @('Process', 'User', 'Machine'); valuePrinted = $false; sameProcessRequiredForLive = $true } `
            -Remediation @(
                ".\install.ps1 -InstallEntrypoint CreateOrPreparePath -PromptPassword",
                ".\install.ps1 -Mode Change -ResetPassword -PromptPassword",
                "如果环境变量已设置但仍失败，请在同一个 elevated PowerShell 中运行 `[Environment]::GetEnvironmentVariable('$SecretName','Process') -ne `$null` 确认 runner 进程可见；不要打印真实密码值。",
                "If the host secret and actual VM account are out of sync, use .\install.ps1 -Mode Change -ResetGuestVmPassword -PromptPassword -Force from an elevated shell."
            )
    }

    return New-PlanCheck `
        -Name 'Guest credential environment variable' `
        -Status 'Passed' `
        -RequiredForLive $true `
        -Message "凭据诊断：guest password secret '$SecretName' 已在 $($secretValue.Scope) scope 设置；值未打印。 / Secret is set; value was not printed." `
        -Details @{ secretName = $SecretName; isSet = $true; scope = $secretValue.Scope; scopesChecked = @('Process', 'User', 'Machine'); valuePrinted = $false }
}

function New-HostOsCheck {
    try {
        $hostIsWindows = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)
    }
    catch {
        $hostIsWindows = $false
    }

    if ($hostIsWindows) {
        return New-PlanCheck `
            -Name 'Host operating system' `
            -Status 'Passed' `
            -RequiredForLive $true `
            -Message 'Host OS is Windows.' `
            -Details @{ isWindows = $true }
    }

    return New-PlanCheck `
        -Name 'Host operating system' `
        -Status 'Failed' `
        -RequiredForLive $true `
        -Message 'Live Hyper-V E2E 需要 Windows 宿主机。下一步：请在带 Hyper-V 的 Windows 主机上运行，或使用 PlanOnly。' `
        -Details @{ isWindows = $false } `
        -Remediation @("Run live Hyper-V analysis on a Windows Pro/Enterprise/Education host with Hyper-V enabled; use -PlanOnly on non-Windows hosts.")
}

function New-HyperVFeatureCheck {
    try {
        $hostIsWindows = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)
    }
    catch {
        $hostIsWindows = $false
    }

    if (-not $hostIsWindows) {
        return New-PlanCheck `
            -Name 'Hyper-V feature enabled' `
            -Category 'host' `
            -Status 'Failed' `
            -RequiredForLive $true `
            -Message 'Hyper-V feature state is unavailable because the host is not Windows.' `
            -Details @{ isWindows = $false; readOnly = $true } `
            -Remediation @("Run live Hyper-V analysis on a Windows host with Hyper-V enabled; keep this command in -PlanOnly on non-Windows hosts.")
    }

    $vmmsServiceExists = $false
    $vmmsServiceStatus = ''
    $featureQueryAttempted = $false
    $anyFeatureEnabled = $false
    $featureStates = New-Object System.Collections.Generic.List[object]

    if ($null -ne (Get-Command -Name Get-WindowsOptionalFeature -ErrorAction SilentlyContinue)) {
        $featureQueryAttempted = $true
        foreach ($featureName in @('Microsoft-Hyper-V-All', 'Microsoft-Hyper-V', 'Microsoft-Hyper-V-Hypervisor')) {
            try {
                $feature = Get-WindowsOptionalFeature -Online -FeatureName $featureName -ErrorAction Stop
                $state = [string]$feature.State
                if ($state -eq 'Enabled') {
                    $anyFeatureEnabled = $true
                }

                [void]$featureStates.Add([ordered]@{ featureName = $featureName; state = $state; querySucceeded = $true })
            }
            catch {
                [void]$featureStates.Add([ordered]@{ featureName = $featureName; state = ''; querySucceeded = $false; error = $_.Exception.Message })
            }
        }
    }

    try {
        $service = Get-Service -Name 'vmms' -ErrorAction Stop
        $vmmsServiceExists = $true
        $vmmsServiceStatus = [string]$service.Status
    }
    catch {
        $vmmsServiceExists = $false
    }

    if ($anyFeatureEnabled -or $vmmsServiceExists) {
        return New-PlanCheck `
            -Name 'Hyper-V feature enabled' `
            -Category 'host' `
            -Status 'Passed' `
            -RequiredForLive $true `
            -Message 'Hyper-V feature/service state appears available for live execution.' `
            -Details @{ featureQueryAttempted = $featureQueryAttempted; anyFeatureEnabled = $anyFeatureEnabled; featureStates = @($featureStates.ToArray()); vmmsServiceExists = $vmmsServiceExists; vmmsServiceStatus = $vmmsServiceStatus; readOnly = $true }
    }

    return New-PlanCheck `
        -Name 'Hyper-V feature enabled' `
        -Category 'host' `
        -Status 'Failed' `
        -RequiredForLive $true `
        -Message 'Hyper-V feature/service state was not detected; live VM execution is not ready.' `
        -Details @{ featureQueryAttempted = $featureQueryAttempted; anyFeatureEnabled = $anyFeatureEnabled; featureStates = @($featureStates.ToArray()); vmmsServiceExists = $vmmsServiceExists; vmmsServiceStatus = $vmmsServiceStatus; readOnly = $true } `
        -Remediation @("Enable Hyper-V and Hyper-V management tools, reboot if required, then rerun .\scripts\Test-HyperVReadiness.ps1.")
}

function New-AdministratorCheck {
    $isAdmin = Test-IsAdministrator
    if ($isAdmin) {
        return New-PlanCheck `
            -Name 'Elevated host process' `
            -Status 'Passed' `
            -RequiredForLive $true `
            -Message 'Current PowerShell process is elevated.' `
            -Details @{ isAdministrator = $true }
    }

    return New-PlanCheck `
        -Name 'Elevated host process' `
        -Status 'Failed' `
        -RequiredForLive $true `
        -Message 'Live Hyper-V E2E 需要管理员 PowerShell。下一步：以管理员身份重新打开 PowerShell，或使用 -PlanOnly/-WhatIf。' `
        -Details @{ isAdministrator = $false } `
        -Remediation @("下一步：-Live 请以管理员身份打开 PowerShell；普通 shell 只做不修改 VM 的 review 时使用 -PlanOnly 或 -WhatIf。")
}

function New-HyperVVmCheck {
    param([Parameter(Mandatory)][string]$VmName)

    if ($null -eq (Get-Command -Name Get-VM -ErrorAction SilentlyContinue)) {
        return New-PlanCheck `
            -Name 'Golden VM exists' `
            -Status 'Warning' `
            -RequiredForLive $true `
            -Message 'VM 诊断：Get-VM 不可用，无法只读确认 golden VM 是否存在；Live 会在 VM mutation 前被 Hyper-V command preflight 阻止。' `
            -Details @{ vmName = $VmName; checked = $false; readOnly = $true; requiredCommand = 'Get-VM' } `
            -Remediation @(
                "Enable/install Hyper-V PowerShell tools, then rerun .\scripts\Test-HyperVReadiness.ps1.",
                "Use .\install.ps1 -Mode Change -UpdateHyperVConfig -VmName <existing VM> -CheckpointName <checkpoint> to record the local VM name."
            )
    }

    try {
        $vm = Get-VM -Name $VmName -ErrorAction Stop
        return New-PlanCheck `
            -Name 'Golden VM exists' `
            -Status 'Passed' `
            -RequiredForLive $true `
            -Message "VM 诊断：已找到 golden VM '$VmName'，当前状态 $($vm.State)；PlanOnly 不会启动或还原它。" `
            -Details @{ vmName = $VmName; exists = $true; state = $vm.State.ToString(); id = [string]$vm.Id; readOnly = $true }
    }
    catch {
        $inventory = Get-HyperVVmProfileCandidates -Limit 20
        return New-PlanCheck `
            -Name 'Golden VM exists' `
            -Status 'Failed' `
            -RequiredForLive $true `
            -Message "VM 诊断：找不到或无法查询 golden VM '$VmName'。下一步：确认 VM 名称、Hyper-V 权限和宿主机环境。英文详情：$($_.Exception.Message)" `
            -Details @{ vmName = $VmName; exists = $false; readOnly = $true; error = $_.Exception.Message; candidateQuerySucceeded = [bool]$inventory.querySucceeded; candidateQueryError = $inventory.queryError; candidateLimit = 20; availableVmProfiles = @($inventory.profiles) } `
            -Remediation @(
                "Create or import a golden Hyper-V VM named '$VmName', or record the actual VM name with .\install.ps1 -Mode Change -UpdateHyperVConfig -VmName <existing VM> -CheckpointName <checkpoint>.",
                "List read-only local VM/checkpoint candidates with .\scripts\Test-HyperVReadiness.ps1 -ListAvailableVmProfiles from an elevated shell.",
                "Run .\scripts\Test-HyperVReadiness.ps1 after updating the VM name; it is read-only and will not start or restore the VM."
            )
    }
}

function New-HyperVCheckpointCheck {
    param(
        [Parameter(Mandatory)][string]$VmName,
        [Parameter(Mandatory)][string]$CheckpointName
    )

    if ($null -eq (Get-Command -Name Get-VMSnapshot -ErrorAction SilentlyContinue)) {
        return New-PlanCheck `
            -Name 'Clean checkpoint exists' `
            -Status 'Warning' `
            -RequiredForLive $true `
            -Message 'Checkpoint 诊断：Get-VMSnapshot 不可用，无法只读确认 clean checkpoint；Live 会在 VM mutation 前被 Hyper-V command preflight 阻止。' `
            -Details @{ vmName = $VmName; checkpointName = $CheckpointName; checked = $false; readOnly = $true; requiredCommand = 'Get-VMSnapshot' } `
            -Remediation @("Enable/install Hyper-V PowerShell tools, then rerun .\scripts\Test-HyperVReadiness.ps1 without starting the VM.")
    }

    try {
        $snapshot = Get-VMSnapshot -VMName $VmName -Name $CheckpointName -ErrorAction Stop
        return New-PlanCheck `
            -Name 'Clean checkpoint exists' `
            -Status 'Passed' `
            -RequiredForLive $true `
            -Message "Checkpoint 诊断：已找到 clean checkpoint '$CheckpointName'（VM '$VmName'），创建时间 $($snapshot.CreationTime)。" `
            -Details @{ vmName = $VmName; checkpointName = $CheckpointName; exists = $true; creationTime = $snapshot.CreationTime; readOnly = $true }
    }
    catch {
        $outerError = $_
        $availableSnapshots = @()
        $candidateQueryError = ''
        try {
            $availableSnapshots = @(Get-VMSnapshot -VMName $VmName -ErrorAction Stop |
                Sort-Object -Property CreationTime -Descending |
                Select-Object -First 20 |
                ForEach-Object {
                    [ordered]@{
                        checkpointName = [string]$_.Name
                        checkpointId   = [string]$_.Id
                        creationTime   = $_.CreationTime
                    }
                })
        }
        catch {
            $availableSnapshots = @()
            $candidateQueryError = $_.Exception.Message
        }

        return New-PlanCheck `
            -Name 'Clean checkpoint exists' `
            -Status 'Failed' `
            -RequiredForLive $true `
            -Message "Checkpoint 诊断：找不到或无法查询 clean checkpoint '$CheckpointName'（VM '$VmName'）。下一步：创建干净快照或更新 -CheckpointName。英文详情：$($outerError.Exception.Message)" `
            -Details @{ vmName = $VmName; checkpointName = $CheckpointName; exists = $false; readOnly = $true; availableCheckpoints = @($availableSnapshots); candidateLimit = 20; candidateQueryError = $candidateQueryError; error = $outerError.Exception.Message } `
            -Remediation @(
                "Create a clean checkpoint named '$CheckpointName' on VM '$VmName', or record the correct checkpoint with .\install.ps1 -Mode Change -UpdateHyperVConfig -VmName '$VmName' -CheckpointName <checkpoint>.",
                "List read-only local VM/checkpoint candidates with .\scripts\Test-HyperVReadiness.ps1 -ListAvailableVmProfiles -VmName '$VmName' from an elevated shell.",
                "Rerun .\scripts\Test-HyperVReadiness.ps1 to confirm the checkpoint exists; the check is read-only."
            )
    }
}

function New-GuestServiceCheck {
    param([Parameter(Mandatory)][string]$VmName)

    if ($null -eq (Get-Command -Name Get-VMIntegrationService -ErrorAction SilentlyContinue)) {
        return New-PlanCheck `
            -Name 'Guest Service Interface' `
            -Status 'Warning' `
            -RequiredForLive $true `
            -Message 'Guest Service Interface 诊断：Get-VMIntegrationService 不可用，无法只读确认来宾服务接口；Live 会在 VM mutation 前被 Hyper-V command preflight 阻止。' `
            -Details @{ vmName = $VmName; checked = $false; componentId = $script:GuestServiceInterfaceComponentId; readOnly = $true } `
            -Remediation @("Enable/install Hyper-V PowerShell tools. The live start phase can enable Guest Service Interface when the VM is queryable.")
    }

    try {
        $componentSuffix = '\' + $script:GuestServiceInterfaceComponentId
        $services = @(Get-VMIntegrationService -VMName $VmName -ErrorAction Stop)
        $service = @($services |
            Where-Object {
                $id = [string]$_.Id
                $name = [string]$_.Name
                $id.EndsWith($componentSuffix, [System.StringComparison]::OrdinalIgnoreCase) -or
                $name -eq 'Guest Service Interface' -or
                $name -eq '来宾服务接口'
            } |
            Select-Object -First 1)[0]
        if ($null -eq $service) {
            $availableServices = @($services | ForEach-Object { [string]$_.Name } | Select-Object -First 20)
            throw "错误：VM '$VmName' 未找到 Guest Service Interface integration service（组件 ID $script:GuestServiceInterfaceComponentId）。已发现 integration services：$($availableServices -join ', ')。下一步：在 Hyper-V 设置中启用 Guest Service Interface，或确认 VM 支持该集成服务。"
        }
        $enabled = [bool]$service.Enabled
        $status = if ($enabled) { 'Passed' } else { 'Warning' }
        $message = if ($enabled) {
            "Guest Service Interface 诊断：VM '$VmName' 的来宾服务接口已启用，可用于 Copy-VMFile。"
        }
        else {
            "Guest Service Interface 诊断：VM '$VmName' 存在来宾服务接口但当前禁用；Live start 会在 Copy-VMFile 前尝试启用。"
        }

        return New-PlanCheck `
            -Name 'Guest Service Interface' `
            -Status $status `
            -RequiredForLive $true `
            -Message $message `
            -Details @{ vmName = $VmName; exists = $true; enabled = $enabled; componentId = $script:GuestServiceInterfaceComponentId; serviceName = [string]$service.Name; primaryStatus = $service.PrimaryStatusDescription; readOnly = $true } `
            -Remediation $(if ($enabled) { @() } else { @("No manual VM start is required for planning. For live runs, the start phase attempts to enable Guest Service Interface before Copy-VMFile; you can also enable it in Hyper-V VM settings.") })
    }
    catch {
        return New-PlanCheck `
            -Name 'Guest Service Interface' `
            -Status 'Failed' `
            -RequiredForLive $true `
            -Message "Guest Service Interface 诊断：无法查询 VM '$VmName' 的来宾服务接口。下一步：确认 VM 名称、Hyper-V 权限和 integration services。英文详情：$($_.Exception.Message)" `
            -Details @{ vmName = $VmName; exists = $false; componentId = $script:GuestServiceInterfaceComponentId; readOnly = $true; error = $_.Exception.Message } `
            -Remediation @("Verify the VM name and Hyper-V integration services, then rerun .\scripts\Test-HyperVReadiness.ps1. The readiness check does not start the VM.")
    }
}

function New-PowerShellDirectCheck {
    param(
        [Parameter(Mandatory)][string]$VmName,
        [Parameter(Mandatory)][string]$UserName,
        [Parameter(Mandatory)][string]$SecretName,
        [Parameter(Mandatory)][string[]]$GuestPathsToProbe
    )

    if ($null -eq (Get-Command -Name Invoke-Command -ErrorAction SilentlyContinue)) {
        return New-PlanCheck `
            -Name 'PowerShell Direct readiness' `
            -Status 'Warning' `
            -RequiredForLive $true `
            -Message 'PowerShell Direct 诊断：Invoke-Command 不可用，无法执行只读 probe。下一步：使用支持 Hyper-V PowerShell Direct 的 Windows PowerShell/PowerShell。' `
            -Details @{ vmName = $VmName; userName = $UserName; checked = $false; readOnly = $true; requiredCommand = 'Invoke-Command'; valuePrinted = $false } `
            -Remediation @("下一步：使用支持 Hyper-V PowerShell Direct 的 Windows PowerShell/PowerShell，然后重新运行只读 readiness check。")
    }

    if ($null -eq (Get-Command -Name Get-VM -ErrorAction SilentlyContinue)) {
        return New-PlanCheck `
            -Name 'PowerShell Direct readiness' `
            -Status 'Warning' `
            -RequiredForLive $true `
            -Message 'PowerShell Direct 诊断：Get-VM 不可用，无法在 probe 前确认 VM 状态。下一步：安装 Hyper-V PowerShell 工具。' `
            -Details @{ vmName = $VmName; userName = $UserName; checked = $false; readOnly = $true; requiredCommand = 'Get-VM'; valuePrinted = $false } `
            -Remediation @("Enable/install Hyper-V PowerShell tools so the readiness check can confirm whether the VM is already running.")
    }

    if ([string]::IsNullOrWhiteSpace($SecretName)) {
        return New-PlanCheck `
            -Name 'PowerShell Direct readiness' `
            -Status 'Warning' `
            -RequiredForLive $true `
            -Message 'PowerShell Direct 诊断：已跳过只读 probe，因为 guest password secret 名称为空；不会启动 VM，也不会打印 secret 值。' `
            -Details @{ vmName = $VmName; userName = $UserName; checked = $false; reason = 'emptyCredentialSecretName'; readOnly = $true; valuePrinted = $false } `
            -Remediation @('下一步：在本机 sandbox 配置中设置 guest.passwordSecretName，然后重跑只读 readiness 或 PlanOnly。')
    }

    $secretValue = Get-GuestPasswordSecretValue -SecretName $SecretName
    if (-not [bool]$secretValue.IsSet) {
        return New-PlanCheck `
            -Name 'PowerShell Direct readiness' `
            -Status 'Warning' `
            -RequiredForLive $true `
            -Message "PowerShell Direct 诊断：已跳过只读 probe，因为未设置 guest password secret '$SecretName'；不会启动 VM，也不会打印 secret 值。下一步：运行 .\install.ps1 -InstallEntrypoint CreateOrPreparePath -PromptPassword 或在当前进程设置环境变量。" `
            -Details @{ vmName = $VmName; userName = $UserName; checked = $false; reason = 'missingCredentialSecret'; secretName = $SecretName; scopesChecked = @('Process', 'User', 'Machine'); readOnly = $true; valuePrinted = $false } `
            -Remediation @("Set the guest password secret with .\install.ps1 -InstallEntrypoint CreateOrPreparePath -PromptPassword or use .\scripts\Test-HyperVReadiness.ps1 -PromptForMissingGuestPassword for a process-only read-only probe.")
    }

    try {
        $vm = Get-VM -Name $VmName -ErrorAction Stop
        if ($vm.State.ToString() -ne 'Running') {
            return New-PlanCheck `
                -Name 'PowerShell Direct readiness' `
                -Status 'Warning' `
                -RequiredForLive $true `
                -Message "PowerShell Direct 诊断：已跳过只读 probe，因为 VM '$VmName' 当前为 $($vm.State)；PlanOnly/WhatIf 不会启动 VM。Live start 会在还原 checkpoint 后等待 PowerShell Direct。 / Probe skipped because VM is not running." `
                -Details @{ vmName = $VmName; userName = $UserName; checked = $false; vmState = $vm.State.ToString(); reason = 'vmNotRunning'; secretName = $SecretName; secretScope = $secretValue.Scope; readOnly = $true; valuePrinted = $false } `
                -Remediation @("说明：PlanOnly/WhatIf 不修改 VM 时这是预期行为。只有想在 Live 前做只读 PowerShell Direct probe，才需要手动启动 VM；否则直接修复其他 preflight 后让 Live start 阶段等待。")
        }

        $securePassword = [System.Security.SecureString]::new()
        foreach ($passwordCharacter in ([string]$secretValue.Value).ToCharArray()) {
            $securePassword.AppendChar($passwordCharacter)
        }
        $securePassword.MakeReadOnly()
        $credential = [pscredential]::new($UserName, $securePassword)
        $probe = Invoke-Command -VMName $VmName -Credential $credential -ScriptBlock {
            param([string[]]$Paths)
            $pathResults = @{}
            foreach ($path in $Paths) {
                $pathResults[$path] = [bool](Test-Path -LiteralPath $path)
            }

            [pscustomobject][ordered]@{
                ComputerName = $env:COMPUTERNAME
                UserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                PathResults = $pathResults
            }
        } -ArgumentList (,$GuestPathsToProbe) -ErrorAction Stop

        $firstProbe = @($probe | Select-Object -First 1)[0]
        return New-PlanCheck `
            -Name 'PowerShell Direct readiness' `
            -Status 'Passed' `
            -RequiredForLive $true `
            -Message "PowerShell Direct 诊断：只读 probe 对 VM '$VmName' 成功；credential 可用，guest path probe 已记录。 / PowerShell Direct probe succeeded." `
            -Details @{ vmName = $VmName; configuredUserName = $UserName; checked = $true; computerName = $firstProbe.ComputerName; userName = $firstProbe.UserName; guestPathResults = $firstProbe.PathResults; secretName = $SecretName; secretScope = $secretValue.Scope; readOnly = $true; valuePrinted = $false }
    }
    catch {
        return New-PlanCheck `
            -Name 'PowerShell Direct readiness' `
            -Status 'Failed' `
            -RequiredForLive $true `
            -Message "PowerShell Direct 诊断：只读 probe 对 VM '$VmName' 失败。下一步：检查 VM 是否运行、来宾用户 '$UserName' 是否存在、secret 是否与 VM 内密码一致、PowerShell Direct 是否可用。英文详情：$($_.Exception.Message)" `
            -Details @{ vmName = $VmName; userName = $UserName; checked = $true; secretName = $SecretName; secretScope = $secretValue.Scope; readOnly = $true; error = $_.Exception.Message; valuePrinted = $false } `
            -Remediation @("Confirm the VM is running, the guest user '$UserName' exists, and the host secret '$SecretName' matches the guest password. Use .\install.ps1 -Mode Change -ResetGuestVmPassword -PromptPassword -Force if they are out of sync.")
    }
}

function New-PreflightSummary {
    param([Parameter(Mandatory)][object[]]$Checks)

    $required = @($Checks | Where-Object { [bool]$_.requiredForLive })
    $failedRequired = @($required | Where-Object { $_.status -eq 'Failed' })
    $warnings = @($Checks | Where-Object { $_.status -eq 'Warning' })
    $repairSuggestions = New-Object System.Collections.Generic.List[string]
    foreach ($check in $Checks) {
        $status = ''
        $remediation = @()
        if ($check -is [System.Collections.IDictionary]) {
            if ($check.Contains('status')) {
                $status = [string]$check['status']
            }
            if ($check.Contains('remediation')) {
                $remediation = @($check['remediation'])
            }
        }
        else {
            $statusProperty = $check.PSObject.Properties['status']
            if ($null -ne $statusProperty) {
                $status = [string]$statusProperty.Value
            }

            $remediationProperty = $check.PSObject.Properties['remediation']
            if ($null -ne $remediationProperty) {
                $remediation = @($remediationProperty.Value)
            }
        }

        if ($status -eq 'Passed') {
            continue
        }

        foreach ($item in $remediation) {
            $text = [string]$item
            if (-not [string]::IsNullOrWhiteSpace($text) -and -not $repairSuggestions.Contains($text)) {
                [void]$repairSuggestions.Add($text)
            }
        }
    }

    return [ordered]@{
        totalChecks = @($Checks).Count
        requiredForLive = $required.Count
        failedRequired = $failedRequired.Count
        warnings = $warnings.Count
        liveReady = ($failedRequired.Count -eq 0)
        failedRequiredNames = @($failedRequired | ForEach-Object { $_.name })
        failedRequiredCheckIds = @($failedRequired | ForEach-Object { $_.checkId })
        warningNames = @($warnings | ForEach-Object { $_.name })
        warningCheckIds = @($warnings | ForEach-Object { $_.checkId })
        repairSuggestionCount = $repairSuggestions.Count
        repairSuggestions = @($repairSuggestions.ToArray())
    }
}

function Write-PreflightRepairSuggestions {
    param([AllowEmptyCollection()][string[]]$Suggestions)

    $items = @($Suggestions | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)
    if ($items.Count -eq 0) {
        return
    }

    Write-HyperVE2EStep 'Preflight repair suggestions:'
    foreach ($item in @($items | Select-Object -First 8)) {
        Write-HyperVE2EStep "  - $item"
    }

    if ($items.Count -gt 8) {
        Write-HyperVE2EStep "  - ... $($items.Count - 8) more suggestion(s) are recorded in plan.preflightSummary.repairSuggestions."
    }
}

function New-GuestAgentArgumentList {
    param(
        [Parameter(Mandatory)][string]$SampleGuestPath,
        [Parameter(Mandatory)][string]$GuestOut,
        [int]$Duration,
        [bool]$DriverEnabled,
        [Parameter(Mandatory)][string]$DriverEventsPath,
        [Parameter(Mandatory)][string]$R0CollectorPath,
        [Parameter(Mandatory)][string]$DevicePath,
        [bool]$UseMockCollector
    )

    $arguments = New-Object System.Collections.Generic.List[string]
    [void]$arguments.Add('--sample')
    [void]$arguments.Add((Quote-PowerShellString $SampleGuestPath))
    [void]$arguments.Add('--out')
    [void]$arguments.Add((Quote-PowerShellString $GuestOut))
    [void]$arguments.Add('--duration')
    [void]$arguments.Add([string]$Duration)

    if ($DriverEnabled) {
        [void]$arguments.Add('--driver-events')
        [void]$arguments.Add((Quote-PowerShellString $DriverEventsPath))
        [void]$arguments.Add('--r0collector')
        [void]$arguments.Add((Quote-PowerShellString $R0CollectorPath))
        [void]$arguments.Add('--driver-device')
        [void]$arguments.Add((Quote-PowerShellString $DevicePath))

        if ($UseMockCollector) {
            [void]$arguments.Add('--r0-mock')
        }
    }

    return @($arguments.ToArray())
}

function New-R0CollectorArgumentList {
    param(
        [bool]$DriverEnabled,
        [Parameter(Mandatory)][string]$DriverEventsPath,
        [Parameter(Mandatory)][string]$DevicePath,
        [int]$Duration,
        [bool]$UseMockCollector
    )

    if (-not $DriverEnabled) {
        return @()
    }

    $arguments = New-Object System.Collections.Generic.List[string]
    [void]$arguments.Add('--device')
    [void]$arguments.Add((Quote-PowerShellString $DevicePath))
    [void]$arguments.Add('--output')
    [void]$arguments.Add((Quote-PowerShellString $DriverEventsPath))
    [void]$arguments.Add('--duration')
    [void]$arguments.Add([string]$Duration)

    if ($UseMockCollector) {
        [void]$arguments.Add('--mock')
    }

    return @($arguments.ToArray())
}

function Read-JsonFileIfPresent {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }

    return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json)
}


function ConvertTo-NativeCommandLineArgument {
    param([AllowNull()][string]$Argument)

    if ($null -eq $Argument) {
        return '""'
    }

    if ($Argument -notmatch '[\s"]') {
        return $Argument
    }

    $escaped = $Argument.Replace('"', '\"')
    if ($escaped.EndsWith('\')) {
        $escaped += '\'
    }

    return '"' + $escaped + '"'
}

function Join-NativeCommandLineArguments {
    param([string[]]$Arguments)

    return (@($Arguments) | ForEach-Object { ConvertTo-NativeCommandLineArgument -Argument $_ }) -join ' '
}

function Invoke-ChildPowerShellScript {
    param(
        [Parameter(Mandatory)][string]$PhaseName,
        [Parameter(Mandatory)][string]$ScriptPath,
        [string[]]$Arguments = @(),
        [int]$TimeoutSeconds = 900,
        [string]$LogDirectory = ''
    )

    $startedAtUtc = [DateTimeOffset]::UtcNow
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $powerShellCommand = Get-Command powershell.exe -ErrorAction SilentlyContinue
    $powerShellExe = if ($null -ne $powerShellCommand -and -not [string]::IsNullOrWhiteSpace($powerShellCommand.Source)) {
        $powerShellCommand.Source
    }
    else {
        'powershell.exe'
    }

    $nativeArguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $ScriptPath) + @($Arguments)
    $exitCode = 1
    $launchError = $null
    $stdout = ''
    $stderr = ''
    $timedOut = $false
    $process = $null

    try {
        $startInfo = [Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = $powerShellExe
        $startInfo.Arguments = Join-NativeCommandLineArguments -Arguments $nativeArguments
        $startInfo.UseShellExecute = $false
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $startInfo.CreateNoWindow = $true
        $startInfo.WorkingDirectory = $resolvedRepoRoot

        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $startInfo
        if (-not $process.Start()) {
            throw '错误：Process.Start 返回 false。下一步：确认 powershell 可执行文件和子脚本路径有效。'
        }

        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $effectiveTimeoutSeconds = [Math]::Max(1, $TimeoutSeconds)
        $deadlineUtc = [DateTimeOffset]::UtcNow.AddSeconds($effectiveTimeoutSeconds)
        $nextHeartbeatUtc = [DateTimeOffset]::UtcNow.AddSeconds(30)
        while (-not $process.HasExited -and [DateTimeOffset]::UtcNow -lt $deadlineUtc) {
            if ($process.WaitForExit(1000)) {
                break
            }

            if ([DateTimeOffset]::UtcNow -ge $nextHeartbeatUtc) {
                $elapsedSeconds = [int]$timer.Elapsed.TotalSeconds
                Write-HyperVE2EStep "Child $PhaseName phase is still running after ${elapsedSeconds}s (timeout ${effectiveTimeoutSeconds}s)."
                $nextHeartbeatUtc = [DateTimeOffset]::UtcNow.AddSeconds(30)
            }
        }

        if (-not $process.HasExited) {
            $timedOut = $true
            try {
                $process.Kill()
            }
            catch {
                $exitCode = 124
                $launchError = "子进程超时 $effectiveTimeoutSeconds 秒，且 Kill 失败。下一步：手动检查/结束残留 powershell 进程。英文详情：$($_.Exception.Message)"
            }
            $process.WaitForExit()
        }

        $stdout = [string]$stdoutTask.GetAwaiter().GetResult()
        $stderr = [string]$stderrTask.GetAwaiter().GetResult()
        if ($timedOut) {
            $exitCode = 124
            $timeoutMessage = "子阶段 $PhaseName 超时：$effectiveTimeoutSeconds 秒。下一步：提高超时或查看该阶段日志。"
            $stderr = (($stderr, $timeoutMessage) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join [Environment]::NewLine
        }
        else {
            $exitCode = [int]$process.ExitCode
        }
    }
    catch {
        $launchError = $_.Exception.Message
        $exitCode = 1
    }
    finally {
        if ($null -ne $process) {
            $process.Dispose()
        }
        $timer.Stop()
    }

    if (-not [string]::IsNullOrWhiteSpace($launchError)) {
        $stderr = (($stderr, "Launcher error: $launchError") | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join [Environment]::NewLine
    }

    $stdoutLogPath = ''
    $stderrLogPath = ''
    if (-not [string]::IsNullOrWhiteSpace($LogDirectory)) {
        try {
            New-Item -ItemType Directory -Path $LogDirectory -Force -WhatIf:$false | Out-Null
            $safePhase = [regex]::Replace($PhaseName.ToLowerInvariant(), '[^a-z0-9]+', '-').Trim('-')
            if ([string]::IsNullOrWhiteSpace($safePhase)) {
                $safePhase = 'child'
            }

            $stdoutLogPath = Join-Path $LogDirectory ("hyperv-e2e-{0}.stdout.log" -f $safePhase)
            $stderrLogPath = Join-Path $LogDirectory ("hyperv-e2e-{0}.stderr.log" -f $safePhase)
            Set-Content -LiteralPath $stdoutLogPath -Value $stdout -Encoding UTF8 -WhatIf:$false
            Set-Content -LiteralPath $stderrLogPath -Value $stderr -Encoding UTF8 -WhatIf:$false
            Write-HyperVE2EStep "Child $PhaseName full stdout/stderr logs written: $stdoutLogPath ; $stderrLogPath"
        }
        catch {
            $stderr = (($stderr, "Unable to persist child $PhaseName logs: $($_.Exception.Message)") | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join [Environment]::NewLine
            $stdoutLogPath = ''
            $stderrLogPath = ''
        }
    }

    $maxCapturedOutputChars = 65536
    $stdoutWasTruncated = $false
    $stderrWasTruncated = $false
    if ($stdout.Length -gt $maxCapturedOutputChars) {
        $stdout = $stdout.Substring(0, $maxCapturedOutputChars) + [Environment]::NewLine + '[truncated]'
        $stdoutWasTruncated = $true
    }

    if ($stderr.Length -gt $maxCapturedOutputChars) {
        $stderr = $stderr.Substring(0, $maxCapturedOutputChars) + [Environment]::NewLine + '[truncated]'
        $stderrWasTruncated = $true
    }

    if (-not [string]::IsNullOrWhiteSpace($stdout)) {
        Write-HyperVE2EStep "Child $PhaseName stdout captured ($($stdout.Length) chars; truncated=$stdoutWasTruncated)."
    }

    if (-not [string]::IsNullOrWhiteSpace($stderr)) {
        Write-HyperVE2EStep "Child $PhaseName stderr captured ($($stderr.Length) chars; truncated=$stderrWasTruncated)."
    }

    return [pscustomobject][ordered]@{
        phaseName = $PhaseName
        powerShell = $powerShellExe
        scriptPath = $ScriptPath
        arguments = @($Arguments)
        exitCode = $exitCode
        standardOutput = $stdout
        standardError = $stderr
        standardOutputLogPath = $stdoutLogPath
        standardErrorLogPath = $stderrLogPath
        standardOutputTruncated = $stdoutWasTruncated
        standardErrorTruncated = $stderrWasTruncated
        startedAtUtc = $startedAtUtc.ToString('O')
        duration = $timer.Elapsed.ToString('c')
        launchedOutOfProcess = $true
        timedOut = $timedOut
        timeoutSeconds = $TimeoutSeconds
    }
}

function Get-RecordPropertyValue {
    param(
        [AllowNull()][object]$Object,
        [Parameter(Mandatory)][string]$Name,
        [object]$DefaultValue = $null
    )

    if ($null -eq $Object) {
        return $DefaultValue
    }

    if ($Object -is [System.Collections.IDictionary] -and $Object.Contains($Name)) {
        return $Object[$Name]
    }

    $property = $Object.PSObject.Properties[$Name]
    if ($null -ne $property) {
        return $property.Value
    }

    return $DefaultValue
}

function Add-UniqueHint {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$Hints,
        [AllowNull()][string]$Hint
    )

    if ([string]::IsNullOrWhiteSpace($Hint)) {
        return
    }

    if (-not $Hints.Contains($Hint)) {
        [void]$Hints.Add($Hint)
    }
}

function Get-StepResultState {
    param([AllowNull()][object]$StepResult)

    if ($null -eq $StepResult) {
        return 'pending'
    }

    $existingState = [string](Get-RecordPropertyValue -Object $StepResult -Name 'State' -DefaultValue '')
    if (-not [string]::IsNullOrWhiteSpace($existingState)) {
        return $existingState.ToLowerInvariant()
    }

    $skipped = [System.Convert]::ToBoolean((Get-RecordPropertyValue -Object $StepResult -Name 'Skipped' -DefaultValue $false))
    $success = [System.Convert]::ToBoolean((Get-RecordPropertyValue -Object $StepResult -Name 'Success' -DefaultValue $false))
    if ($skipped) {
        return 'skipped'
    }

    if ($success) {
        return 'completed'
    }

    return 'failed'
}

function Get-RunbookFailureReason {
    param(
        [AllowNull()][object]$FailedStep,
        [AllowNull()][string]$Message,
        [AllowNull()][object]$StartInvocation,
        [AllowNull()][object]$CollectInvocation
    )

    $parts = New-Object System.Collections.Generic.List[string]
    if ($null -ne $FailedStep) {
        $title = [string](Get-RecordPropertyValue -Object $FailedStep -Name 'Title' -DefaultValue '')
        $stepMessage = [string](Get-RecordPropertyValue -Object $FailedStep -Name 'Message' -DefaultValue '')
        if (-not [string]::IsNullOrWhiteSpace($title)) {
            [void]$parts.Add("步骤失败：$title")
        }
        if (-not [string]::IsNullOrWhiteSpace($stepMessage)) {
            [void]$parts.Add($stepMessage)
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($Message)) {
        [void]$parts.Add($Message)
    }

    foreach ($invocation in @($StartInvocation, $CollectInvocation)) {
        if ($null -eq $invocation) {
            continue
        }

        $phase = [string](Get-RecordPropertyValue -Object $invocation -Name 'phaseName' -DefaultValue 'child')
        $exitCode = Get-RecordPropertyValue -Object $invocation -Name 'exitCode' -DefaultValue $null
        $timedOut = [System.Convert]::ToBoolean((Get-RecordPropertyValue -Object $invocation -Name 'timedOut' -DefaultValue $false))
        $timeoutSeconds = Get-RecordPropertyValue -Object $invocation -Name 'timeoutSeconds' -DefaultValue $null
        $stderr = [string](Get-RecordPropertyValue -Object $invocation -Name 'standardError' -DefaultValue '')
        if ($timedOut) {
            [void]$parts.Add("$phase 阶段在 $timeoutSeconds 秒后超时")
        }

        if ($null -ne $exitCode -and [int]$exitCode -ne 0) {
            [void]$parts.Add("$phase 阶段退出码 $exitCode")
        }
        if (-not [string]::IsNullOrWhiteSpace($stderr)) {
            $line = @($stderr -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1)
            if ($line.Count -gt 0) {
                [void]$parts.Add([string]$line[0])
            }
        }
    }

    $reason = ($parts | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique) -join ' | '
    if ($reason.Length -gt 1200) {
        return $reason.Substring(0, 1200) + '...'
    }

    return $reason
}

function Get-FirstOutputLine {
    param([AllowNull()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    $line = @($Text -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -First 1)
    if ($line.Count -eq 0) {
        return ''
    }

    $value = [string]$line[0]
    if ($value.Length -gt 400) {
        return $value.Substring(0, 400) + '...'
    }

    return $value
}

function Get-ChildPhaseFailureMessage {
    param(
        [Parameter(Mandatory)][string]$PhaseName,
        [AllowNull()][object]$Invocation,
        [string]$Fallback = ''
    )

    if ($null -eq $Invocation) {
        if ([string]::IsNullOrWhiteSpace($Fallback)) {
            return "$PhaseName 阶段没有产生 invocation result。下一步：查看子脚本是否启动成功。"
        }

        return $Fallback
    }

    $exitCode = Get-RecordPropertyValue -Object $Invocation -Name 'exitCode' -DefaultValue $null
    $timedOut = [System.Convert]::ToBoolean((Get-RecordPropertyValue -Object $Invocation -Name 'timedOut' -DefaultValue $false))
    $timeoutSeconds = Get-RecordPropertyValue -Object $Invocation -Name 'timeoutSeconds' -DefaultValue $null
    $stderr = [string](Get-RecordPropertyValue -Object $Invocation -Name 'standardError' -DefaultValue '')
    $stdout = [string](Get-RecordPropertyValue -Object $Invocation -Name 'standardOutput' -DefaultValue '')
    $firstLine = Get-FirstOutputLine -Text $stderr
    if ([string]::IsNullOrWhiteSpace($firstLine)) {
        $firstLine = Get-FirstOutputLine -Text $stdout
    }

    $prefix = if ($timedOut) {
        "$PhaseName 阶段在 $timeoutSeconds 秒后超时"
    }
    elseif ($null -ne $exitCode) {
        "$PhaseName 阶段失败，退出码 $exitCode"
    }
    elseif (-not [string]::IsNullOrWhiteSpace($Fallback)) {
        $Fallback
    }
    else {
        "$PhaseName 阶段失败"
    }

    if ([string]::IsNullOrWhiteSpace($firstLine)) {
        return "$prefix."
    }

    return "$prefix。首条捕获输出：$firstLine"
}

function Get-RunbookRemediationHints {
    param(
        [Parameter(Mandatory)][object]$Plan,
        [AllowNull()][string]$FailureReason,
        [AllowNull()][object]$FailedStep
    )

    $hints = New-Object System.Collections.Generic.List[string]
    foreach ($suggestion in @($Plan.preflightSummary.repairSuggestions)) {
        Add-UniqueHint -Hints $hints -Hint ([string]$suggestion)
    }

    $failedStepMessage = if ($null -eq $FailedStep) { '' } else { [string](Get-RecordPropertyValue -Object $FailedStep -Name 'Message' -DefaultValue '') }
    $text = (($FailureReason, $failedStepMessage) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }) -join ' '
    if ($text -match "Guest password environment variable '([^']+)' is not set") {
        $secretName = $Matches[1]
        Add-UniqueHint -Hints $hints -Hint "下一步：在运行 live analysis 的同一个管理员 PowerShell 中设置 $secretName，或运行 .\install.ps1 -Mode Change -ResetPassword -PromptPassword 后重启 WebUI/runner。"
    }
    elseif ($text -match 'missingCredentialSecret|guest password|credential secret') {
        Add-UniqueHint -Hints $hints -Hint '下一步：Live 前设置已配置的 guest password 环境变量；不要把密码值粘贴到配置、文档或报告中。'
    }

    if ($text -match 'VM was not found|cannot find.*VM|Get-VM|Hyper-V.*not.*available') {
        Add-UniqueHint -Hints $hints -Hint "下一步：确认 Hyper-V 宿主机上存在 VM '$($Plan.vm.name)'，并已安装 Hyper-V PowerShell 工具。"
    }

    if ($text -match 'checkpoint|VMSnapshot|Restore-VMSnapshot') {
        Add-UniqueHint -Hints $hints -Hint "下一步：确认 VM '$($Plan.vm.name)' 上存在 checkpoint '$($Plan.vm.cleanCheckpointName)'，然后重新运行只读 readiness preflight。"
    }

    if ($text -match 'Guest Service Interface|Copy-VMFile') {
        Add-UniqueHint -Hints $hints -Hint "下一步：在 Hyper-V 设置中为 VM '$($Plan.vm.name)' 启用 Guest Service Interface，或让 live start 阶段在 VM/checkpoint 预检成功后启用。"
    }

    if ($text -match 'PowerShell Direct|New-PSSession|Invoke-Command') {
        Add-UniqueHint -Hints $hints -Hint "下一步：确认 VM '$($Plan.vm.name)' 可用来宾用户 '$($Plan.guest.userName)' 运行 PowerShell Direct，且宿主机 secret 与来宾密码一致。"
    }

    if ($text -match 'driver\.hostDriverPath|R0Collector|deviceUnavailable|win32Error=2') {
        Add-UniqueHint -Hints $hints -Hint '下一步：最小可执行文件分析可设置 driver.useMockCollector=true；真实 R0 采集前请配置已构建/测试签名 driver.hostDriverPath。'
    }

    if ($text -match 'Start script was not found|Collect script was not found|Start-SandboxHyperVJob\.ps1|Collect-GuestOutputs\.ps1') {
        Add-UniqueHint -Hints $hints -Hint '下一步：确认仓库包含 Hyper-V 子脚本，并从仓库根目录重跑；不要继续使用不完整脚本拷贝。'
    }

    if ($hints.Count -eq 0 -and -not [string]::IsNullOrWhiteSpace($FailureReason)) {
        Add-UniqueHint -Hints $hints -Hint '下一步：在管理员 PowerShell 重新运行 .\scripts\Test-HyperVReadiness.ps1，并先修复第一个失败必需检查后再尝试 Live。'
    }

    return @($hints.ToArray())
}

function New-RunbookUiProgress {
    param(
        [Parameter(Mandatory)][object]$Plan,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$StepResults,
        [Parameter(Mandatory)][string]$State,
        [int]$CompletedSteps,
        [int]$ExecutedSteps,
        [int]$ProgressPercent,
        [AllowNull()][string]$FailureReason,
        [AllowEmptyCollection()][string[]]$RemediationHints
    )

    $resultByIndex = @{}
    foreach ($result in @($StepResults)) {
        $index = [int](Get-RecordPropertyValue -Object $result -Name 'StepIndex' -DefaultValue -1)
        if ($index -ge 0) {
            $resultByIndex[$index] = $result
        }
    }

    $stepRows = New-Object System.Collections.Generic.List[object]
    $currentStepIndex = $null
    $currentStepId = $null
    $currentStepTitle = $null
    $index = 0
    foreach ($step in @($Plan.steps)) {
        $result = $null
        if ($resultByIndex.ContainsKey($index)) {
            $result = $resultByIndex[$index]
        }

        $stepState = Get-StepResultState -StepResult $result
        if ($stepState -eq 'failed' -and $null -eq $currentStepIndex) {
            $currentStepIndex = $index
            $currentStepId = [string]$step.id
            $currentStepTitle = [string]$step.title
        }

        [void]$stepRows.Add([ordered]@{
                stepIndex = $index
                stepId = [string]$step.id
                title = [string]$step.title
                phase = [string]$step.phase
                state = $stepState
                mutatesVmState = [bool]$step.mutatesVmState
                message = if ($null -ne $result) { [string](Get-RecordPropertyValue -Object $result -Name 'Message' -DefaultValue '') } else { '' }
            })
        $index++
    }

    return [ordered]@{
        state = $State
        progressPercent = $ProgressPercent
        completedSteps = $CompletedSteps
        executedSteps = $ExecutedSteps
        totalSteps = @($Plan.steps).Count
        currentStepIndex = $currentStepIndex
        currentStepId = $currentStepId
        currentStepTitle = $currentStepTitle
        failureReason = $FailureReason
        remediationHints = @($RemediationHints)
        commandTextOmitted = $true
        steps = @($stepRows.ToArray())
    }
}

function ConvertTo-SkeletonDataValue {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return ''
    }

    $text = [string]$Value
    if ($text.Length -gt 1000) {
        return $text.Substring(0, 1000) + '...'
    }

    return $text
}

function New-RunbookProgressSnapshot {
    param(
        [Parameter(Mandatory)][object]$Plan,
        [Parameter(Mandatory)][string]$ModeName,
        [Parameter(Mandatory)][string]$State,
        [bool]$Success,
        [AllowNull()][string]$Message,
        [DateTimeOffset]$StartedAtUtc,
        [TimeSpan]$Duration,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$StepResults,
        [AllowNull()][string]$FailureReason,
        [AllowEmptyCollection()][string[]]$RemediationHints = @()
    )

    $resultByIndex = @{}
    foreach ($result in @($StepResults)) {
        $index = [int](Get-RecordPropertyValue -Object $result -Name 'StepIndex' -DefaultValue -1)
        if ($index -ge 0) {
            $resultByIndex[$index] = $result
        }
    }

    $steps = New-Object System.Collections.Generic.List[object]
    $currentStepIndex = $null
    $currentStepId = $null
    $currentStepTitle = $null
    $completedSteps = 0
    $executedSteps = 0
    $index = 0
    foreach ($step in @($Plan.steps)) {
        $result = $null
        if ($resultByIndex.ContainsKey($index)) {
            $result = $resultByIndex[$index]
        }

        $stepState = Get-StepResultState -StepResult $result
        if ($stepState -eq 'completed' -or $stepState -eq 'skipped') {
            $completedSteps++
        }

        if ($null -ne $result -and (-not [System.Convert]::ToBoolean((Get-RecordPropertyValue -Object $result -Name 'Skipped' -DefaultValue $false)))) {
            $executedSteps++
        }

        if ($stepState -eq 'failed' -and $null -eq $currentStepIndex) {
            $currentStepIndex = $index
            $currentStepId = [string]$step.id
            $currentStepTitle = [string]$step.title
        }

        $startedValue = if ($null -ne $result) { Get-RecordPropertyValue -Object $result -Name 'StartedAtUtc' -DefaultValue $null } else { $null }
        $durationValue = if ($null -ne $result) { Get-RecordPropertyValue -Object $result -Name 'Duration' -DefaultValue $null } else { $null }
        $exitCodeValue = if ($null -ne $result) { Get-RecordPropertyValue -Object $result -Name 'ExitCode' -DefaultValue $null } else { $null }
        $messageValue = if ($null -ne $result) { [string](Get-RecordPropertyValue -Object $result -Name 'Message' -DefaultValue '') } else { '' }

        [void]$steps.Add([ordered]@{
                StepIndex        = $index
                StepId           = [string]$step.id
                Title            = [string]$step.title
                State            = $stepState
                RequiresElevation = [bool]$step.requiresLive
                MutatesVmState   = [bool]$step.mutatesVmState
                StartedAtUtc     = if ($null -ne $startedValue -and -not [string]::IsNullOrWhiteSpace([string]$startedValue)) { [string]$startedValue } else { $null }
                Duration         = if ($durationValue -is [TimeSpan]) { $durationValue.ToString('c') } elseif ($null -ne $durationValue -and -not [string]::IsNullOrWhiteSpace([string]$durationValue)) { [string]$durationValue } else { $null }
                ExitCode         = if ($null -ne $exitCodeValue) { [int]$exitCodeValue } else { $null }
                Message          = $messageValue
            })
        $index++
    }

    if ((-not $Success) -and $null -eq $currentStepIndex -and @($Plan.steps).Count -gt 0) {
        $currentStepIndex = 0
        $currentStepId = [string]$Plan.steps[0].id
        $currentStepTitle = [string]$Plan.steps[0].title
    }

    $modeValue = if ($ModeName -eq 'Live') { 1 } else { 0 }
    $effectiveMessage = if (-not [string]::IsNullOrWhiteSpace($Message)) { $Message } elseif ($Success) { 'Runbook execution completed.' } else { $FailureReason }
    return [ordered]@{
        JobId            = [string]$Plan.job.jobId
        TargetVmName     = [string]$Plan.vm.name
        Mode             = $modeValue
        ModeName         = $ModeName
        State            = $State
        TotalSteps       = @($Plan.steps).Count
        CompletedSteps   = $completedSteps
        ExecutedSteps    = $executedSteps
        CurrentStepIndex = $currentStepIndex
        CurrentStepId    = $currentStepId
        CurrentStepTitle = $currentStepTitle
        Success          = $Success
        Message          = $effectiveMessage
        FailureReason    = $FailureReason
        RemediationHints = @($RemediationHints)
        StartedAtUtc     = $StartedAtUtc.ToString('O')
        UpdatedAtUtc     = [DateTimeOffset]::UtcNow.ToString('O')
        Duration         = $Duration.ToString('c')
        Steps            = @($steps.ToArray())
    }
}

function Save-RunbookProgressSnapshot {
    param(
        [Parameter(Mandatory)][object]$Plan,
        [Parameter(Mandatory)][object]$Snapshot
    )

    $jobRoot = [string]$Plan.host.jobRoot
    New-Item -ItemType Directory -Path $jobRoot -Force -WhatIf:$false | Out-Null
    $progressPath = Join-Path $jobRoot 'runbook-progress.json'
    $Snapshot | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $progressPath -Encoding UTF8 -WhatIf:$false
    Write-HyperVE2EStep "Runbook progress snapshot written: $progressPath"
    return $progressPath
}

function Test-ExistingEventsContainRealRows {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $false
    }

    try {
        $item = Get-Item -LiteralPath $Path
        if ($item.Length -le 0) {
            return $false
        }

        $content = (Get-Content -LiteralPath $Path -Raw).Trim()
        if ([string]::IsNullOrWhiteSpace($content) -or $content -eq '[]') {
            return $false
        }

        try {
            $parsed = $content | ConvertFrom-Json -ErrorAction Stop
            return @($parsed).Count -gt 0
        }
        catch {
            Write-Warning "中文提示：现有 events.json 无法解析，将写入 failure skeleton 以保证报告可导入。英文详情：$($_.Exception.Message)"
            return $false
        }
    }
    catch {
        return $false
    }
}

function Save-GuestOutputSkeleton {
    param(
        [Parameter(Mandatory)][object]$Plan,
        [AllowNull()][string]$FailureReason,
        [AllowNull()][string]$Message,
        [AllowNull()][string]$RunbookExecutionPath,
        [AllowNull()][string]$RunbookProgressPath,
        [string]$GeneratedBy = 'Invoke-HyperVE2E.ps1'
    )

    $guestOutputDirectory = [string]$Plan.host.guestOutputDirectory
    if ([string]::IsNullOrWhiteSpace($guestOutputDirectory)) {
        $jobIdN = ([string]$Plan.job.jobId) -replace '-', ''
        $guestOutputDirectory = Join-Path ([string]$Plan.host.outputRoot) $jobIdN
    }

    New-Item -ItemType Directory -Path $guestOutputDirectory -Force -WhatIf:$false | Out-Null
    $eventsPath = [string]$Plan.host.eventsJsonPath
    if ([string]::IsNullOrWhiteSpace($eventsPath)) {
        $eventsPath = Join-Path $guestOutputDirectory 'events.json'
    }

    $agentPidPath = Join-Path $guestOutputDirectory 'agent.pid'
    $agentExitPath = Join-Path $guestOutputDirectory 'agent.exit'
    $agentStdoutPath = Join-Path $guestOutputDirectory 'agent.stdout.log'
    $agentStderrPath = Join-Path $guestOutputDirectory 'agent.stderr.log'
    $metadataPath = Join-Path $guestOutputDirectory 'guest-output-skeleton.json'
    $driverEventsPath = [string]$Plan.host.driverEventsJsonlPath
    if ([string]::IsNullOrWhiteSpace($driverEventsPath)) {
        $driverEventsPath = Join-Path $guestOutputDirectory 'driver-events.jsonl'
    }

    if (-not (Test-Path -LiteralPath $agentPidPath -PathType Leaf)) {
        Set-Content -LiteralPath $agentPidPath -Value '0' -Encoding ASCII -WhatIf:$false
    }

    if (-not (Test-Path -LiteralPath $agentExitPath -PathType Leaf)) {
        Set-Content -LiteralPath $agentExitPath -Value '-1' -Encoding ASCII -WhatIf:$false
    }

    if (-not (Test-Path -LiteralPath $agentStdoutPath -PathType Leaf)) {
        Set-Content -LiteralPath $agentStdoutPath -Value '' -Encoding UTF8 -WhatIf:$false
    }

    if (-not (Test-Path -LiteralPath $agentStderrPath -PathType Leaf)) {
        Set-Content -LiteralPath $agentStderrPath -Value (ConvertTo-SkeletonDataValue (($FailureReason, $Message) -join ' | ')) -Encoding UTF8 -WhatIf:$false
    }

    $now = [DateTimeOffset]::UtcNow
    $eventsAlreadyPresent = Test-ExistingEventsContainRealRows -Path $eventsPath
    if (-not $eventsAlreadyPresent) {
        $skeletonEvents = @(
            [ordered]@{
                eventType   = 'hyperv.e2e.failure_skeleton'
                timestamp   = $now.ToString('O')
                source      = 'host'
                processName = $GeneratedBy
                processId   = $PID
                path        = [string]$Plan.vm.name
                commandLine = 'Hyper-V E2E failed before complete guest events were collected.'
                data        = [ordered]@{
                    jobId                = ConvertTo-SkeletonDataValue $Plan.job.jobId
                    vmName               = ConvertTo-SkeletonDataValue $Plan.vm.name
                    checkpointName       = ConvertTo-SkeletonDataValue $Plan.vm.cleanCheckpointName
                    guestUserName        = ConvertTo-SkeletonDataValue $Plan.guest.userName
                    secretName           = ConvertTo-SkeletonDataValue $Plan.guest.passwordSecretName
                    secretValuePrinted   = 'False'
                    failureReason        = ConvertTo-SkeletonDataValue $FailureReason
                    message              = ConvertTo-SkeletonDataValue $Message
                    runbookExecutionPath = ConvertTo-SkeletonDataValue $RunbookExecutionPath
                    runbookProgressPath  = ConvertTo-SkeletonDataValue $RunbookProgressPath
                    guestOutputDirectory = ConvertTo-SkeletonDataValue $guestOutputDirectory
                    generatedBy          = $GeneratedBy
                    importable           = 'True'
                    skeleton             = 'True'
                }
            }
        )
        ConvertTo-Json -InputObject @($skeletonEvents) -Depth 8 | Set-Content -LiteralPath $eventsPath -Encoding UTF8 -WhatIf:$false
    }

    if ([System.Convert]::ToBoolean($Plan.driver.enabled) -and -not (Test-Path -LiteralPath $driverEventsPath -PathType Leaf)) {
        $driverSkeletonEvent = [ordered]@{
            eventType   = 'r0collector.not_started'
            timestamp   = $now.ToString('O')
            source      = 'host'
            processName = $GeneratedBy
            path        = ConvertTo-SkeletonDataValue $Plan.driver.devicePath
            data        = [ordered]@{
                jobId              = ConvertTo-SkeletonDataValue $Plan.job.jobId
                collectionMode     = ConvertTo-SkeletonDataValue $Plan.driver.collectionMode
                failureReason      = ConvertTo-SkeletonDataValue $FailureReason
                generatedBy        = $GeneratedBy
                skeleton           = 'True'
                secretValuePrinted = 'False'
            }
        }
        ($driverSkeletonEvent | ConvertTo-Json -Depth 8 -Compress) | Set-Content -LiteralPath $driverEventsPath -Encoding UTF8 -WhatIf:$false
    }

    $metadata = [ordered]@{
        contractVersion     = 1
        kind                = 'KSwordSandbox.GuestOutputSkeleton'
        generatedAtUtc      = $now.ToString('O')
        generatedBy         = $GeneratedBy
        importable          = $true
        preservedRealEvents = $eventsAlreadyPresent
        reason              = 'Hyper-V E2E failed before a complete guest output set was collected.'
        jobId               = [string]$Plan.job.jobId
        targetVmName        = [string]$Plan.vm.name
        cleanCheckpointName = [string]$Plan.vm.cleanCheckpointName
        secretValuePrinted  = $false
        failureReason       = $FailureReason
        message             = $Message
        paths               = [ordered]@{
            guestOutputDirectory = $guestOutputDirectory
            eventsJsonPath       = $eventsPath
            driverEventsJsonlPath = $driverEventsPath
            agentPidPath         = $agentPidPath
            agentExitPath        = $agentExitPath
            agentStdoutPath      = $agentStdoutPath
            agentStderrPath      = $agentStderrPath
            runbookExecutionPath = $RunbookExecutionPath
            runbookProgressPath  = $RunbookProgressPath
        }
        importCommand       = ".\scripts\Import-HyperVJobReport.ps1 -JobId '$($Plan.job.jobId)' -SamplePath '$($Plan.sample.hostPath)' -EventsPath '$eventsPath' -RunbookExecutionPath '$RunbookExecutionPath'"
        note                = '该 skeleton 仅用于恢复/导入失败诊断，不代表 Guest Agent 已成功运行。'
    }
    $metadata | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $metadataPath -Encoding UTF8 -WhatIf:$false
    Write-HyperVE2EStep "Importable guest output skeleton ready: $eventsPath"
    Write-HyperVE2EStep "Guest output skeleton metadata written: $metadataPath"
    return $metadataPath
}

function Invoke-FailureReportImport {
    param(
        [Parameter(Mandatory)][object]$Plan,
        [Parameter(Mandatory)][string]$ImportReportScript,
        [AllowNull()][string]$Reason
    )

    $jobRoot = [string]$Plan.host.jobRoot
    New-Item -ItemType Directory -Path $jobRoot -Force -WhatIf:$false | Out-Null
    $resultPath = Join-Path $jobRoot 'hyperv-e2e-failure-report-import.json'
    $samplePath = [string]$Plan.sample.hostPath
    $eventsPath = [string]$Plan.host.eventsJsonPath
    $runbookExecutionPath = [string]$Plan.host.runbookExecutionPath
    $diagnosticsPath = Join-Path $jobRoot 'report-rebuild-diagnostics.json'

    $skipReasons = New-Object System.Collections.Generic.List[string]
    if (-not (Test-Path -LiteralPath $ImportReportScript -PathType Leaf)) {
        [void]$skipReasons.Add("Report import script missing: $ImportReportScript")
    }
    if ([string]::IsNullOrWhiteSpace($samplePath) -or -not (Test-Path -LiteralPath $samplePath -PathType Leaf)) {
        [void]$skipReasons.Add("Sample file missing; cannot rebuild report without the original sample path: $samplePath")
    }
    if ([string]::IsNullOrWhiteSpace($eventsPath) -or -not (Test-Path -LiteralPath $eventsPath -PathType Leaf)) {
        [void]$skipReasons.Add("Events/skeleton file missing before import: $eventsPath")
    }
    if ([string]::IsNullOrWhiteSpace($runbookExecutionPath) -or -not (Test-Path -LiteralPath $runbookExecutionPath -PathType Leaf)) {
        [void]$skipReasons.Add("Runbook execution record missing before import: $runbookExecutionPath")
    }

    if ($skipReasons.Count -gt 0) {
        $result = [ordered]@{
            contractVersion = 1
            kind = 'KSwordSandbox.FailureReportImportResult'
            success = $false
            state = 'skipped'
            reason = $Reason
            jobId = [string]$Plan.job.jobId
            jobRoot = $jobRoot
            eventsJsonPath = $eventsPath
            runbookExecutionPath = $runbookExecutionPath
            reportRebuildDiagnosticsPath = $diagnosticsPath
            skipReasons = @($skipReasons.ToArray())
            remediationHints = @(
                '下一步：确认 sample/events/runbook-execution 都存在后运行 .\scripts\Import-HyperVJobReport.ps1 或 .\scripts\Invoke-OperatorCli.ps1 recover -RebuildReport。',
                '下一步：若 events.json 缺失，先查看 guest-output-skeleton.json 是否生成；可用 Import-HyperVJobReport 根据 runbook-execution.json 自动生成 skeleton。'
            )
            vmAction = 'none'
            secretValuePrinted = $false
            completedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
        }
        $result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $resultPath -Encoding UTF8 -WhatIf:$false
        Write-HyperVE2EStep "Failure report import skipped; diagnostics written: $resultPath"
        return [pscustomobject]$result
    }

    Write-HyperVE2EStep 'Live failure detected; attempting best-effort report import from failure skeleton without VM mutation.'
    $arguments = @(
        '-JobId', ([string]$Plan.job.jobId),
        '-SamplePath', $samplePath,
        '-EventsPath', $eventsPath,
        '-RunbookExecutionPath', $runbookExecutionPath,
        '-ConfigPath', ([string]$Plan.configPath),
        '-RepoRoot', ([string]$Plan.repositoryRoot),
        '-RuntimeRoot', ([string]$Plan.host.runtimeRoot),
        '-DurationSeconds', ([string]$Plan.job.durationSeconds),
        '-Json'
    )
    $invocation = Invoke-ChildPowerShellScript `
        -PhaseName 'failure-report-import' `
        -ScriptPath $ImportReportScript `
        -Arguments $arguments `
        -TimeoutSeconds 300 `
        -LogDirectory $jobRoot
    $success = ([int]$invocation.exitCode -eq 0)
    $result = [ordered]@{
        contractVersion = 1
        kind = 'KSwordSandbox.FailureReportImportResult'
        success = $success
        state = if ($success) { 'completed' } else { 'failed' }
        reason = $Reason
        jobId = [string]$Plan.job.jobId
        jobRoot = $jobRoot
        eventsJsonPath = $eventsPath
        runbookExecutionPath = $runbookExecutionPath
        reportRebuildDiagnosticsPath = $diagnosticsPath
        jsonReportPath = [string]$Plan.host.jsonReportPath
        htmlReportPath = [string]$Plan.host.htmlReportPath
        invocation = $invocation
        remediationHints = if ($success) {
            @('下一步：打开 report.html/report.json 查看失败 skeleton 和 runbook 失败原因；修复后重新运行 Live。')
        }
        else {
            @('下一步：查看 hyperv-e2e-failure-report-import.json、failure-report-import stdout/stderr log、report-rebuild-diagnostics.json 后，使用 Invoke-OperatorCli recover -RebuildReport 重试。')
        }
        vmAction = 'none'
        secretValuePrinted = $false
        completedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
    }
    $result | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $resultPath -Encoding UTF8 -WhatIf:$false
    Write-HyperVE2EStep "Failure report import result written: $resultPath"
    return [pscustomobject]$result
}

function New-RunbookStepExecutionResult {
    param(
        [int]$StepIndex,
        [Parameter(Mandatory)][string]$StepId,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$PowerShell,
        [bool]$Skipped,
        [bool]$Success,
        [Nullable[int]]$ExitCode = $null,
        [string]$StandardOutput = '',
        [string]$StandardError = '',
        [DateTimeOffset]$StartedAtUtc = [DateTimeOffset]::UtcNow,
        [TimeSpan]$Duration = [TimeSpan]::Zero,
        [bool]$RequiresElevation = $true,
        [bool]$MutatesVmState = $false,
        [string]$Message = $null,
        [string]$State = '',
        [string[]]$RemediationHints = @()
    )

    $effectiveState = if (-not [string]::IsNullOrWhiteSpace($State)) {
        $State.ToLowerInvariant()
    }
    elseif ($Skipped) {
        'skipped'
    }
    elseif ($Success) {
        'completed'
    }
    else {
        'failed'
    }
    $failureReason = if ((-not $Success) -and (-not $Skipped)) { $Message } else { $null }
    $displayMessage = $Message
    if (-not [string]::IsNullOrWhiteSpace($displayMessage) -and $displayMessage.Length -gt 600) {
        $displayMessage = $displayMessage.Substring(0, 600) + '...'
    }

    return [pscustomobject][ordered]@{
        StepIndex = $StepIndex
        StepId = $StepId
        Title = $Title
        State = $effectiveState
        PowerShell = $PowerShell
        Skipped = $Skipped
        Success = $Success
        ExitCode = $ExitCode
        StandardOutput = $StandardOutput
        StandardError = $StandardError
        StartedAtUtc = $StartedAtUtc.ToString('O')
        Duration = $Duration.ToString('c')
        RequiresElevation = $RequiresElevation
        MutatesVmState = $MutatesVmState
        Message = $Message
        DisplayMessage = $displayMessage
        FailureReason = $failureReason
        RemediationHints = @($RemediationHints)
    }
}

function New-SafeModeStepResults {
    param(
        [Parameter(Mandatory)][object]$Plan,
        [Parameter(Mandatory)][string]$Message
    )

    $results = New-Object System.Collections.Generic.List[object]
    $index = 0
    foreach ($step in @($Plan.steps)) {
        [void]$results.Add((New-RunbookStepExecutionResult `
                    -StepIndex $index `
                    -StepId ([string]$step.id) `
                    -Title ([string]$step.title) `
                    -PowerShell ([string]$step.powerShell) `
                    -Skipped $true `
                    -Success $true `
                    -StartedAtUtc ([DateTimeOffset]::UtcNow) `
                    -Duration ([TimeSpan]::Zero) `
                    -RequiresElevation ([bool]$step.requiresLive) `
                    -MutatesVmState ([bool]$step.mutatesVmState) `
                    -Message $Message))
        $index++
    }

    return @($results.ToArray())
}

function Convert-PhaseStepsToRunbookStepResults {
    param(
        [Parameter(Mandatory)][object]$Plan,
        [object]$StartResult,
        [object]$CollectResult,
        [object]$StartInvocation = $null,
        [object]$CollectInvocation = $null
    )

    $stepMap = @{}
    $stepIndexMap = @{}
    $index = 0
    foreach ($step in @($Plan.steps)) {
        $stepMap[[string]$step.id] = $step
        $stepIndexMap[[string]$step.id] = $index
        $index++
    }

    $results = New-Object System.Collections.Generic.List[object]
    $recordedStepIds = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([StringComparer]::OrdinalIgnoreCase)
    foreach ($phaseResult in @($StartResult, $CollectResult)) {
        if ($null -eq $phaseResult) {
            continue
        }

        foreach ($childStep in @($phaseResult.steps)) {
            $stepId = [string]$childStep.id
            [void]$recordedStepIds.Add($stepId)
            $planStep = $stepMap[$stepId]
            $stepIndex = if ($stepIndexMap.ContainsKey($stepId)) { [int]$stepIndexMap[$stepId] } else { -1 }
            $title = if ($null -ne $planStep) { [string]$planStep.title } else { [string]$childStep.title }
            $powerShell = if ($null -ne $planStep) { [string]$planStep.powerShell } else { '' }
            $duration = [TimeSpan]::Zero
            if ($null -ne $childStep.durationSeconds) {
                $duration = [TimeSpan]::FromSeconds([double]$childStep.durationSeconds)
            }

            $started = [DateTimeOffset]::UtcNow
            if (-not [string]::IsNullOrWhiteSpace([string]$childStep.startedAtUtc)) {
                $started = [DateTimeOffset]::Parse([string]$childStep.startedAtUtc, [Globalization.CultureInfo]::InvariantCulture)
            }

            [void]$results.Add((New-RunbookStepExecutionResult `
                        -StepIndex $stepIndex `
                        -StepId $stepId `
                        -Title $title `
                        -PowerShell $powerShell `
                        -Skipped ([bool]$childStep.skipped) `
                        -Success ([bool]$childStep.success) `
                        -StartedAtUtc $started `
                        -Duration $duration `
                        -RequiresElevation $true `
                        -MutatesVmState ($(if ($null -ne $planStep) { [bool]$planStep.mutatesVmState } else { $false })) `
                        -Message ([string]$childStep.message) `
                        -RemediationHints @($childStep.remediationHints)))
        }
    }

    Add-SyntheticPhaseFailureStep `
        -Plan $Plan `
        -Results $results `
        -RecordedStepIds $recordedStepIds `
        -StepMap $stepMap `
        -StepIndexMap $stepIndexMap `
        -Phase 'start' `
        -Invocation $StartInvocation `
        -PhaseResult $StartResult

    Add-SyntheticPhaseFailureStep `
        -Plan $Plan `
        -Results $results `
        -RecordedStepIds $recordedStepIds `
        -StepMap $stepMap `
        -StepIndexMap $stepIndexMap `
        -Phase 'collect' `
        -Invocation $CollectInvocation `
        -PhaseResult $CollectResult

    return @($results.ToArray())
}

function Add-SyntheticPhaseFailureStep {
    param(
        [Parameter(Mandatory)][object]$Plan,
        [Parameter(Mandatory)][System.Collections.Generic.List[object]]$Results,
        [Parameter(Mandatory)][System.Collections.Generic.HashSet[string]]$RecordedStepIds,
        [Parameter(Mandatory)][hashtable]$StepMap,
        [Parameter(Mandatory)][hashtable]$StepIndexMap,
        [Parameter(Mandatory)][string]$Phase,
        [AllowNull()][object]$Invocation,
        [AllowNull()][object]$PhaseResult
    )

    if ($null -eq $Invocation) {
        return
    }

    $exitCodeValue = Get-RecordPropertyValue -Object $Invocation -Name 'exitCode' -DefaultValue $null
    if ($null -eq $exitCodeValue -or [int]$exitCodeValue -eq 0) {
        return
    }

    $hasRecordedFailure = $false
    if ($null -ne $PhaseResult) {
        foreach ($step in @($PhaseResult.steps)) {
            if (-not [bool]$step.success) {
                $hasRecordedFailure = $true
                break
            }
        }
    }

    if ($hasRecordedFailure) {
        return
    }

    $planStep = @($Plan.steps | Where-Object { [string]$_.phase -eq $Phase } | Select-Object -First 1)
    if ($planStep.Count -eq 0) {
        return
    }

    $step = $planStep[0]
    $stepId = [string]$step.id
    if ($RecordedStepIds.Contains($stepId)) {
        return
    }

    $stepIndex = if ($StepIndexMap.ContainsKey($stepId)) { [int]$StepIndexMap[$stepId] } else { -1 }
    $message = Get-ChildPhaseFailureMessage -PhaseName $Phase -Invocation $Invocation
    [void]$Results.Add((New-RunbookStepExecutionResult `
                -StepIndex $stepIndex `
                -StepId $stepId `
                -Title ([string]$step.title) `
                -PowerShell ([string]$step.powerShell) `
                -Skipped $false `
                -Success $false `
                -ExitCode ([int]$exitCodeValue) `
                -StartedAtUtc ([DateTimeOffset]::UtcNow) `
                -Duration ([TimeSpan]::Zero) `
                -RequiresElevation ([bool]$step.requiresLive) `
                -MutatesVmState ([bool]$step.mutatesVmState) `
                -Message $message `
                -State 'failed'))
}

function Save-RunbookExecutionRecord {
    param(
        [Parameter(Mandatory)][object]$Plan,
        [Parameter(Mandatory)][string]$ModeName,
        [bool]$Success,
        [string]$Message = $null,
        [DateTimeOffset]$StartedAtUtc = [DateTimeOffset]::UtcNow,
        [TimeSpan]$Duration = [TimeSpan]::Zero,
        [AllowEmptyCollection()][object[]]$StepResults = @(),
        [object]$StartResult = $null,
        [object]$CollectResult = $null,
        [object]$StartInvocation = $null,
        [object]$CollectInvocation = $null,
        [Nullable[int]]$StartExitCode = $null,
        [Nullable[int]]$CollectExitCode = $null,
        [bool]$WhatIf = $false
    )

    $jobRoot = [string]$Plan.host.jobRoot
    New-Item -ItemType Directory -Path $jobRoot -Force -WhatIf:$false | Out-Null
    $executionPath = [string]$Plan.host.runbookExecutionPath
    if ([string]::IsNullOrWhiteSpace($executionPath)) {
        $executionPath = Join-Path $jobRoot 'runbook-execution.json'
    }

    $modeValue = if ($ModeName -eq 'Live') { 1 } else { 0 }
    $failedStep = @($StepResults | Where-Object { -not [bool]$_.Success } | Select-Object -First 1)
    $failedStepIndex = if ($failedStep.Count -gt 0) { [int]$failedStep[0].StepIndex } else { $null }
    $executedSteps = @($StepResults | Where-Object { (-not [bool]$_.Skipped) -and [int]$_.StepIndex -ge 0 }).Count
    $completedSteps = @($StepResults | Where-Object {
            $state = Get-StepResultState -StepResult $_
            $state -eq 'completed' -or $state -eq 'skipped'
        }).Count
    $totalSteps = @($Plan.steps).Count
    $progressPercent = if ($totalSteps -le 0) {
        if ($Success) { 100 } else { 0 }
    }
    else {
        [int][Math]::Max(0, [Math]::Min(100, [Math]::Round(($completedSteps / [double]$totalSteps) * 100)))
    }
    if ($Success -and $progressPercent -lt 100) {
        $progressPercent = 100
    }

    $state = if ($Success) { 'completed' } elseif ($ModeName -eq 'WhatIf') { 'completed' } else { 'failed' }
    $failureReason = if ($Success) { $null } else { Get-RunbookFailureReason -FailedStep ($(if ($failedStep.Count -gt 0) { $failedStep[0] } else { $null })) -Message $Message -StartInvocation $StartInvocation -CollectInvocation $CollectInvocation }
    $remediationHints = if ($Success) { @() } else { @(Get-RunbookRemediationHints -Plan $Plan -FailureReason $failureReason -FailedStep ($(if ($failedStep.Count -gt 0) { $failedStep[0] } else { $null }))) }
    $uiSafeProgress = New-RunbookUiProgress `
        -Plan $Plan `
        -StepResults @($StepResults) `
        -State $state `
        -CompletedSteps $completedSteps `
        -ExecutedSteps $executedSteps `
        -ProgressPercent $progressPercent `
        -FailureReason $failureReason `
        -RemediationHints @($remediationHints)
    $runbookProgressPath = Join-Path $jobRoot 'runbook-progress.json'
    $guestOutputSkeletonMetadataPath = Join-Path ([string]$Plan.host.guestOutputDirectory) 'guest-output-skeleton.json'

    $record = [ordered]@{
        contractVersion = 1
        kind = 'KSwordSandbox.RunbookExecution'
        JobId = [string]$Plan.job.jobId
        TargetVmName = [string]$Plan.vm.name
        Mode = $modeValue
        ModeName = $ModeName
        Success = $Success
        State = $state
        TotalSteps = $totalSteps
        CompletedSteps = $completedSteps
        ExecutedSteps = $executedSteps
        ProgressPercent = $progressPercent
        FailedStepIndex = $failedStepIndex
        StartedAtUtc = $StartedAtUtc.ToString('O')
        Duration = $Duration.ToString('c')
        RequiresElevation = $true
        StepResults = @($StepResults)
        Message = $Message
        FailureReason = $failureReason
        RemediationHints = @($remediationHints)
        UiSafeProgress = $uiSafeProgress
        failure = [ordered]@{
            reason = $failureReason
            failedStepIndex = $failedStepIndex
            failedStepId = if ($failedStep.Count -gt 0) { [string]$failedStep[0].StepId } else { $null }
            failedStepTitle = if ($failedStep.Count -gt 0) { [string]$failedStep[0].Title } else { $null }
            remediationHints = @($remediationHints)
        }
        planPath = [string]$Plan.planPath
        requestedMode = [string]$Plan.requestedMode
        effectiveMode = [string]$Plan.effectiveMode
        willMutateVm = [bool]$Plan.willMutateVm
        whatIf = $WhatIf
        safeModeProof = [ordered]@{
            planOnlyDefault = [bool]$Plan.safety.planOnlyDefault
            whatIfPreventsMutation = [bool]$Plan.safety.whatIfPreventsMutation
            liveRequiresExplicitSwitch = [bool]$Plan.safety.liveRequiresExplicitSwitch
            noVmMutationWhenPlanOnly = (-not [bool]$Plan.willMutateVm)
            secretValuePrinted = $false
        }
        preflight = [ordered]@{
            summary = $Plan.preflightSummary
            checks = @($Plan.preflight)
        }
        childScripts = [ordered]@{
            startScript = [string]$Plan.scripts.startJob
            collectScript = [string]$Plan.scripts.collectOutputs
            startExitCode = $StartExitCode
            collectExitCode = $CollectExitCode
            startResultPath = (Join-Path ([string]$Plan.host.jobRoot) 'hyperv-e2e-start-result.json')
            collectResultPath = (Join-Path ([string]$Plan.host.jobRoot) 'hyperv-e2e-collect-result.json')
            startInvocation = $StartInvocation
            collectInvocation = $CollectInvocation
        }
        phaseResults = [ordered]@{
            start = $StartResult
            collect = $CollectResult
        }
        artifacts = [ordered]@{
            hostOutputRoot = [string]$Plan.host.outputRoot
            hostGuestOutputDirectory = [string]$Plan.host.guestOutputDirectory
            eventsJsonPath = [string]$Plan.host.eventsJsonPath
            driverEventsJsonlPath = [string]$Plan.host.driverEventsJsonlPath
            runbookExecutionPath = $executionPath
            runbookProgressPath = $runbookProgressPath
            guestOutputSkeletonMetadataPath = $guestOutputSkeletonMetadataPath
            collectedFiles = if ($null -ne $CollectResult) { @($CollectResult.collectedFiles) } else { @() }
        }
        completedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
    }

    $record | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $executionPath -Encoding UTF8 -WhatIf:$false
    Write-HyperVE2EStep "Runbook execution record written: $executionPath"

    try {
        $progressSnapshot = New-RunbookProgressSnapshot `
            -Plan $Plan `
            -ModeName $ModeName `
            -State $state `
            -Success $Success `
            -Message $Message `
            -StartedAtUtc $StartedAtUtc `
            -Duration $Duration `
            -StepResults @($StepResults) `
            -FailureReason $failureReason `
            -RemediationHints @($remediationHints)
        $runbookProgressPath = Save-RunbookProgressSnapshot -Plan $Plan -Snapshot $progressSnapshot
    }
    catch {
        Write-Warning "中文提示：无法写入 runbook-progress.json；runbook-execution.json 已保留。英文详情：$($_.Exception.Message)"
    }

    if (-not $Success) {
        try {
            [void](Save-GuestOutputSkeleton `
                    -Plan $Plan `
                    -FailureReason $failureReason `
                    -Message $Message `
                    -RunbookExecutionPath $executionPath `
                    -RunbookProgressPath $runbookProgressPath `
                    -GeneratedBy 'Invoke-HyperVE2E.ps1')
        }
        catch {
            Write-Warning "中文提示：无法写入可导入 guest-output skeleton；请查看 runbook-execution.json 后手动重建。英文详情：$($_.Exception.Message)"
        }
    }
}

function New-HyperVE2EStep {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Phase,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$PowerShell,
        [bool]$MutatesVmState,
        [bool]$RequiresLive = $true
    )

    return [ordered]@{
        id             = $Id
        phase          = $Phase
        title          = $Title
        powerShell     = $PowerShell
        mutatesVmState = $MutatesVmState
        requiresLive   = $RequiresLive
    }
}

function Get-EnableGuestServicePowerShell {
    param([Parameter(Mandatory)][string]$Vm)

    $quotedVm = Quote-PowerShellString $Vm
    return "`$guestServiceComponentId = '6C09BB55-D683-4DA0-8931-C9BF705F6480'; " +
        "`$guestService = Get-VMIntegrationService -VMName $quotedVm | Where-Object { ([string]`$_.Id).EndsWith('\' + `$guestServiceComponentId, [System.StringComparison]::OrdinalIgnoreCase) -or `$_.Name -eq 'Guest Service Interface' -or `$_.Name -eq '来宾服务接口' } | Select-Object -First 1; " +
        "if (`$null -eq `$guestService) { throw 'Guest Service Interface integration service was not found.' }; " +
        "Enable-VMIntegrationService -VMIntegrationService `$guestService"
}

function New-HyperVE2ESteps {
    param(
        [Parameter(Mandatory)][string]$Vm,
        [Parameter(Mandatory)][string]$Snapshot,
        [Parameter(Mandatory)][string]$PayloadRoot,
        [Parameter(Mandatory)][string]$SampleHostPath,
        [Parameter(Mandatory)][string]$SampleGuestPath,
        [Parameter(Mandatory)][string]$GuestOut,
        [Parameter(Mandatory)][string]$HostOut,
        [Parameter(Mandatory)][string]$AgentPath,
        [Parameter(Mandatory)][string]$AgentPidPath,
        [Parameter(Mandatory)][string]$AgentExitPath,
        [Parameter(Mandatory)][string]$DriverEventsPath,
        [bool]$DriverEnabled,
        [bool]$UseMockCollector,
        [string]$DriverHostPath = '',
        [string]$DriverServiceName = '',
        [string]$DriverPathInGuest = '',
        [Parameter(Mandatory)][string]$SecretName,
        [Parameter(Mandatory)][string]$GuestAgentCommandLine,
        [string]$R0CollectorCommandLine = '',
        [bool]$OpenVmConsoleOnLiveStart,
        [string]$VmConsoleServerName = 'localhost',
        [bool]$RdpFallbackEnabled,
        [string]$RdpTarget = '',
        [bool]$RestoreAfterRun
    )

    $steps = New-Object System.Collections.Generic.List[object]
    [void]$steps.Add((New-HyperVE2EStep -Id 'write-plan' -Phase 'plan' -Title 'Write reviewable Hyper-V E2E plan JSON' -PowerShell 'ConvertTo-Json -Depth 12 | Set-Content <planPath>' -MutatesVmState $false -RequiresLive $false))
    [void]$steps.Add((New-HyperVE2EStep -Id 'load-guest-credential' -Phase 'start' -Title 'Load guest credential from environment secret' -PowerShell ('$guestPassword = [System.Security.SecureString]::new(); foreach ($ch in $env:' + $SecretName + '.ToCharArray()) { $guestPassword.AppendChar($ch) }; $guestPassword.MakeReadOnly()') -MutatesVmState $false))
    [void]$steps.Add((New-HyperVE2EStep -Id 'stop-before-restore' -Phase 'start' -Title 'Stop golden VM before checkpoint restore' -PowerShell ("Stop-VM -Name {0} -TurnOff -Force -ErrorAction SilentlyContinue" -f (Quote-PowerShellString $Vm)) -MutatesVmState $true))
    [void]$steps.Add((New-HyperVE2EStep -Id 'restore-checkpoint' -Phase 'start' -Title 'Restore clean checkpoint' -PowerShell ("Restore-VMSnapshot -VMName {0} -Name {1} -Confirm:`$false" -f (Quote-PowerShellString $Vm), (Quote-PowerShellString $Snapshot)) -MutatesVmState $true))
    [void]$steps.Add((New-HyperVE2EStep -Id 'enable-guest-service' -Phase 'start' -Title 'Enable Guest Service Interface' -PowerShell (Get-EnableGuestServicePowerShell -Vm $Vm) -MutatesVmState $true))
    $quotedVmForStart = Quote-PowerShellString $Vm
    $startVmIfNeededPowerShell = "`$vm = Get-VM -Name $quotedVmForStart; " +
        "if (`$vm.State -eq 'Running') { 'already-running' } " +
        "elseif (`$vm.State -eq 'Paused') { Resume-VM -Name $quotedVmForStart } " +
        "else { Start-VM -Name $quotedVmForStart }"
    [void]$steps.Add((New-HyperVE2EStep -Id 'start-vm' -Phase 'start' -Title 'Start or resume restored golden VM if needed' -PowerShell $startVmIfNeededPowerShell -MutatesVmState $true))
    if ($OpenVmConsoleOnLiveStart) {
        $rdpHint = if ($RdpFallbackEnabled) {
            if ([string]::IsNullOrWhiteSpace($RdpTarget)) { 'fallback: discover VM IP and run mstsc.exe /v:<ip>' } else { "fallback: mstsc.exe /v:$RdpTarget" }
        }
        else {
            'fallback: disabled'
        }
        [void]$steps.Add((New-HyperVE2EStep -Id 'open-vm-console' -Phase 'start' -Title 'Open interactive VM desktop for operator interaction' -PowerShell (("Set-VMHost -EnableEnhancedSessionMode false when opening local VMConnect basic console; vmconnect.exe {0} {1}; {2}" -f (Quote-PowerShellString $VmConsoleServerName), (Quote-PowerShellString $Vm), $rdpHint)) -MutatesVmState $false))
    }
    [void]$steps.Add((New-HyperVE2EStep -Id 'wait-powershell-direct' -Phase 'start' -Title 'Wait for PowerShell Direct in the guest' -PowerShell ("Invoke-Command -VMName {0} -Credential `$guestCredential -ScriptBlock {{ `$env:COMPUTERNAME }}" -f (Quote-PowerShellString $Vm)) -MutatesVmState $false))
    [void]$steps.Add((New-HyperVE2EStep -Id 'stage-guest-payload' -Phase 'start' -Title 'Copy Guest Agent and R0Collector payload into guest' -PowerShell ("Copy-Item -ToSession <PSSession> -Path {0}\agent\* -Destination <guestAgentDirectory> -Recurse -Force" -f $PayloadRoot) -MutatesVmState $true))
    [void]$steps.Add((New-HyperVE2EStep -Id 'copy-sample' -Phase 'start' -Title 'Copy submitted sample into guest' -PowerShell ("Copy-VMFile -VMName {0} -SourcePath {1} -DestinationPath {2} -FileSource Host -CreateFullPath -Force" -f (Quote-PowerShellString $Vm), (Quote-PowerShellString $SampleHostPath), (Quote-PowerShellString $SampleGuestPath)) -MutatesVmState $true))
    [void]$steps.Add((New-HyperVE2EStep -Id 'prepare-guest-output' -Phase 'start' -Title 'Create clean guest output folder' -PowerShell ("Invoke-Command -VMName {0} -Credential `$guestCredential -ScriptBlock {{ New-Item -ItemType Directory -Force -Path {1} | Out-Null }}" -f (Quote-PowerShellString $Vm), (Quote-PowerShellString $GuestOut)) -MutatesVmState $true))
    if ($DriverEnabled -and -not $UseMockCollector -and [string]::IsNullOrWhiteSpace($DriverHostPath)) {
        [void]$steps.Add((New-HyperVE2EStep -Id 'diagnose-r0-driver-config' -Phase 'start' -Title 'Diagnose missing real R0 driver host path' -PowerShell 'Real R0 collection has no driver.hostDriverPath; stage-guest-payload would have empty driverSource and install-driver-service is omitted. Configure a built/test-signed .sys or enable driver.useMockCollector.' -MutatesVmState $false -RequiresLive $false))
    }

    if (-not [string]::IsNullOrWhiteSpace($DriverHostPath)) {
        $installDriverPowerShell = "Invoke-Command -VMName {0} -Credential `$guestCredential -ScriptBlock {{ sc.exe create {1} type= kernel start= demand binPath= {2}; sc.exe start {1} }}" -f (Quote-PowerShellString $Vm), (Quote-PowerShellString $DriverServiceName), (Quote-PowerShellString $DriverPathInGuest)
        [void]$steps.Add((New-HyperVE2EStep -Id 'install-driver-service' -Phase 'start' -Title 'Install and start guest R0 driver service' -PowerShell $installDriverPowerShell -MutatesVmState $true))
    }

    $runAgentPowerShell = "Start-Process powershell.exe -ArgumentList <agent wrapper: $GuestAgentCommandLine>; pid -> $AgentPidPath; exit -> $AgentExitPath; driver events -> $DriverEventsPath"
    if (-not [string]::IsNullOrWhiteSpace($R0CollectorCommandLine)) {
        $runAgentPowerShell += "; R0Collector sidecar args: $R0CollectorCommandLine"
    }

    [void]$steps.Add((New-HyperVE2EStep -Id 'run-guest-agent' -Phase 'start' -Title 'Start Guest Agent with optional R0Collector sidecar arguments' -PowerShell $runAgentPowerShell -MutatesVmState $true))
    [void]$steps.Add((New-HyperVE2EStep -Id 'sync-guest-output' -Phase 'collect' -Title 'Copy guest output while Guest Agent runs' -PowerShell ("Copy-Item -FromSession <PSSession> -Path {0} -Destination {1} -Recurse -Force" -f (Quote-PowerShellString $GuestOut), (Quote-PowerShellString $HostOut)) -MutatesVmState $false))
    [void]$steps.Add((New-HyperVE2EStep -Id 'collect-final-output' -Phase 'collect' -Title 'Copy final events and artifacts from guest' -PowerShell ("Copy-Item -FromSession <PSSession> -Path {0} -Destination {1} -Recurse -Force" -f (Quote-PowerShellString $GuestOut), (Quote-PowerShellString $HostOut)) -MutatesVmState $false))
    [void]$steps.Add((New-HyperVE2EStep -Id 'stop-vm-after-run' -Phase 'cleanup' -Title 'Power off analysis VM after collection' -PowerShell ("Stop-VM -Name {0} -TurnOff -Force" -f (Quote-PowerShellString $Vm)) -MutatesVmState $true))

    if ($RestoreAfterRun) {
        [void]$steps.Add((New-HyperVE2EStep -Id 'restore-checkpoint-after-run' -Phase 'cleanup' -Title 'Restore clean checkpoint again after run' -PowerShell ("Restore-VMSnapshot -VMName {0} -Name {1} -Confirm:`$false" -f (Quote-PowerShellString $Vm), (Quote-PowerShellString $Snapshot)) -MutatesVmState $true))
    }

    return @($steps.ToArray())
}

function Read-SandboxConfig {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [pscustomobject]@{}
    }

    return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json)
}

try {
    if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
        $RepoRoot = Resolve-DefaultRepoRoot
    }

    $resolvedRepoRoot = Resolve-ConfiguredPath -Path $RepoRoot -BasePath (Get-Location).Path
    if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
        $ConfigPath = Join-Path $resolvedRepoRoot 'config\sandbox.example.json'
    }
    else {
        $ConfigPath = Resolve-ConfiguredPath -Path $ConfigPath -BasePath $resolvedRepoRoot
    }

    $config = Read-SandboxConfig -Path $ConfigPath
    $hyperV = Get-ObjectPropertyValue -Object $config -Name 'hyperV' -DefaultValue ([pscustomobject]@{})
    $guest = Get-ObjectPropertyValue -Object $config -Name 'guest' -DefaultValue ([pscustomobject]@{})
    $analysis = Get-ObjectPropertyValue -Object $config -Name 'analysis' -DefaultValue ([pscustomobject]@{})
    $paths = Get-ObjectPropertyValue -Object $config -Name 'paths' -DefaultValue ([pscustomobject]@{})
    $driver = Get-ObjectPropertyValue -Object $config -Name 'driver' -DefaultValue ([pscustomobject]@{})

    $effectiveVmName = Get-StringOrDefault -Value $VmName -DefaultValue (Get-ObjectPropertyValue -Object $hyperV -Name 'goldenVmName' -DefaultValue 'KSwordSandbox-Win10-Golden')
    $effectiveCheckpointName = Get-StringOrDefault -Value $CheckpointName -DefaultValue (Get-ObjectPropertyValue -Object $hyperV -Name 'goldenSnapshotName' -DefaultValue 'Clean')
    $effectiveGuestUserName = Get-StringOrDefault -Value $GuestUserName -DefaultValue (Get-ObjectPropertyValue -Object $guest -Name 'userName' -DefaultValue 'SandboxUser')
    $effectiveGuestSecretName = Get-StringOrDefault -Value $GuestPasswordSecretName -DefaultValue (Get-ObjectPropertyValue -Object $guest -Name 'passwordSecretName' -DefaultValue 'KSWORDBOX_GUEST_PASSWORD')
    $effectiveGuestRoot = Get-StringOrDefault -Value $GuestWorkingDirectory -DefaultValue (Get-ObjectPropertyValue -Object $guest -Name 'workingDirectory' -DefaultValue 'C:\KSwordSandbox')
    $agentExecutableName = Get-ObjectPropertyValue -Object $guest -Name 'agentExecutableName' -DefaultValue 'KSword.Sandbox.Agent.exe'
    $openVmConsoleFromConfig = Get-BooleanOrDefault -Value (Get-ObjectPropertyValue -Object $hyperV -Name 'openVmConsoleOnLiveStart' -DefaultValue $true) -DefaultValue $true
    if ((-not $openVmConsoleFromConfig) -and (-not [bool]$NoOpenVmConsole)) {
        Write-Warning 'hyperV.openVmConsoleOnLiveStart=false is ignored for Live safety: interactive VM desktop opening is required unless -NoOpenVmConsole is supplied explicitly.'
    }
    $openVmConsoleOnLiveStart = (-not [bool]$NoOpenVmConsole)
    $vmConsoleServerName = Get-StringOrDefault -Value (Get-ObjectPropertyValue -Object $hyperV -Name 'vmConsoleServerName' -DefaultValue 'localhost') -DefaultValue 'localhost'
    $rdpFallbackEnabled = Get-BooleanOrDefault -Value (Get-ObjectPropertyValue -Object $hyperV -Name 'rdpFallbackEnabled' -DefaultValue $true) -DefaultValue $true
    $rdpTargetValue = Get-ObjectPropertyValue -Object $hyperV -Name 'rdpTarget' -DefaultValue $null
    $rdpTarget = if ([string]::IsNullOrWhiteSpace([string]$rdpTargetValue)) { '' } else { [string]$rdpTargetValue }
    $defaultDuration = Get-IntOrDefault -Value (Get-ObjectPropertyValue -Object $analysis -Name 'defaultDurationSeconds' -DefaultValue 120) -DefaultValue 120
    $effectiveDurationSeconds = if ($DurationSeconds -gt 0) { $DurationSeconds } else { $defaultDuration }
    $effectiveExecutionTimeoutSeconds = if ($ExecutionTimeoutSeconds -gt 0) { $ExecutionTimeoutSeconds } else { [Math]::Max($effectiveDurationSeconds + 120, 180) }

    $runtimeRootConfig = Get-StringOrDefault -Value $RuntimeRoot -DefaultValue (Get-ObjectPropertyValue -Object $paths -Name 'runtimeRoot' -DefaultValue 'D:\Temp\KSwordSandbox')
    $runtimeRoot = Resolve-ConfiguredPath -Path $runtimeRootConfig -BasePath $resolvedRepoRoot
    $payloadRootConfig = Get-StringOrDefault -Value $GuestPayloadRoot -DefaultValue (Get-ObjectPropertyValue -Object $paths -Name 'guestPayloadRoot' -DefaultValue 'D:\Temp\KSwordSandbox\payload\guest-tools')
    $resolvedPayloadRoot = Resolve-ConfiguredPath -Path $payloadRootConfig -BasePath $resolvedRepoRoot
    $resolvedSamplePath = Resolve-ConfiguredPath -Path $SamplePath -BasePath $resolvedRepoRoot

    $driverEnabledFromConfig = Get-BooleanOrDefault -Value (Get-ObjectPropertyValue -Object $driver -Name 'enabled' -DefaultValue $true) -DefaultValue $true
    $driverEnabled = $driverEnabledFromConfig -and (-not [bool]$NoR0Collector)
    $serviceName = Get-ObjectPropertyValue -Object $driver -Name 'serviceName' -DefaultValue 'KSwordSandboxDriver'
    $driverPathInGuest = Get-ObjectPropertyValue -Object $driver -Name 'driverPathInGuest' -DefaultValue 'C:\KSwordSandbox\driver\KSword.Sandbox.Driver.sys'
    $r0CollectorPathInGuest = Get-ObjectPropertyValue -Object $driver -Name 'r0CollectorPathInGuest' -DefaultValue 'C:\KSwordSandbox\r0collector\KSword.Sandbox.R0Collector.exe'
    $devicePath = Get-ObjectPropertyValue -Object $driver -Name 'devicePath' -DefaultValue '\\.\KSwordSandboxDriver'
    $useMockCollector = Get-BooleanOrDefault -Value (Get-ObjectPropertyValue -Object $driver -Name 'useMockCollector' -DefaultValue $false) -DefaultValue $false
    $hostDriverPathValue = Get-ObjectPropertyValue -Object $driver -Name 'hostDriverPath' -DefaultValue $null
    $hostDriverPath = if ([string]::IsNullOrWhiteSpace([string]$hostDriverPathValue)) { $null } else { Resolve-ConfiguredPath -Path ([string]$hostDriverPathValue) -BasePath $resolvedRepoRoot }

    $jobGuid = if ([string]::IsNullOrWhiteSpace($JobId)) { [Guid]::NewGuid() } else { [Guid]::Parse($JobId) }
    $jobIdN = $jobGuid.ToString('N')
    $sampleFileName = [System.IO.Path]::GetFileName($resolvedSamplePath)
    if ([string]::IsNullOrWhiteSpace($sampleFileName)) {
        throw '错误：SamplePath 必须包含文件名。下一步：请传入完整 .exe 路径，例如 D:\Temp\sample.exe。'
    }

    $guestRoot = $effectiveGuestRoot.TrimEnd('\', '/')
    $guestAgentDirectory = Join-GuestPath -Root $guestRoot -Segments @('agent')
    $guestCollectorDirectory = Join-GuestPath -Root $guestRoot -Segments @('r0collector')
    $guestDriverDirectory = [System.IO.Path]::GetDirectoryName($driverPathInGuest)
    if ([string]::IsNullOrWhiteSpace($guestDriverDirectory)) {
        $guestDriverDirectory = Join-GuestPath -Root $guestRoot -Segments @('driver')
    }
    $guestIncomingDirectory = Join-GuestPath -Root $guestRoot -Segments @('incoming')
    $guestOutRoot = Join-GuestPath -Root $guestRoot -Segments @('out')
    $guestOutputDirectory = Join-GuestPath -Root $guestOutRoot -Segments @($jobIdN)
    $guestSamplePath = Join-GuestPath -Root $guestIncomingDirectory -Segments @($sampleFileName)
    $agentPathInGuest = Join-GuestPath -Root $guestAgentDirectory -Segments @($agentExecutableName)
    $driverEventsPath = Join-GuestPath -Root $guestOutputDirectory -Segments @('driver-events.jsonl')
    $agentPidPath = Join-GuestPath -Root $guestOutputDirectory -Segments @('agent.pid')
    $agentExitPath = Join-GuestPath -Root $guestOutputDirectory -Segments @('agent.exit')
    $guestEventsPath = Join-GuestPath -Root $guestOutputDirectory -Segments @('events.json')
    $guestAgentSummaryPath = Join-GuestPath -Root $guestOutputDirectory -Segments @('agent-summary.json')
    $jobRoot = Join-Path (Join-Path $runtimeRoot 'jobs') $jobIdN
    $hostOutputRoot = Join-Path $jobRoot 'guest'
    $hostGuestOutputDirectory = Join-Path $hostOutputRoot $jobIdN
    $hostEventsPath = Join-Path $hostGuestOutputDirectory 'events.json'
    $hostDriverEventsPath = Join-Path $hostGuestOutputDirectory 'driver-events.jsonl'
    $runbookExecutionPath = Join-Path $jobRoot 'runbook-execution.json'
    $agentHostPath = Join-Path (Join-Path $resolvedPayloadRoot 'agent') $agentExecutableName
    $collectorHostPath = Join-Path (Join-Path $resolvedPayloadRoot 'r0collector') 'KSword.Sandbox.R0Collector.exe'
    $payloadManifestPath = Join-Path $resolvedPayloadRoot 'payload-manifest.json'
    $driverCollectionMode = if (-not $driverEnabled) { 'Disabled' } elseif ($useMockCollector) { 'Mock' } else { 'Live' }
    $guestAgentArguments = New-GuestAgentArgumentList `
        -SampleGuestPath $guestSamplePath `
        -GuestOut $guestOutputDirectory `
        -Duration $effectiveDurationSeconds `
        -DriverEnabled $driverEnabled `
        -DriverEventsPath $driverEventsPath `
        -R0CollectorPath $r0CollectorPathInGuest `
        -DevicePath $devicePath `
        -UseMockCollector $useMockCollector
    $guestAgentCommandLine = '& ' + (Quote-PowerShellString $agentPathInGuest) + ' ' + (($guestAgentArguments | ForEach-Object { [string]$_ }) -join ' ')
    $r0CollectorArguments = New-R0CollectorArgumentList `
        -DriverEnabled $driverEnabled `
        -DriverEventsPath $driverEventsPath `
        -DevicePath $devicePath `
        -Duration $effectiveDurationSeconds `
        -UseMockCollector $useMockCollector
    $r0CollectorCommandLine = if ($driverEnabled) { '& ' + (Quote-PowerShellString $r0CollectorPathInGuest) + ' ' + (($r0CollectorArguments | ForEach-Object { [string]$_ }) -join ' ') } else { '' }

    if ([string]::IsNullOrWhiteSpace($PlanPath)) {
        $PlanPath = Join-Path (Join-Path $runtimeRoot 'plans') ("hyperv-e2e-$jobIdN.json")
    }
    else {
        $PlanPath = Resolve-ConfiguredPath -Path $PlanPath -BasePath $resolvedRepoRoot
    }

    $willRunLive = [bool]$Live -and (-not [bool]$PlanOnly) -and (-not [bool]$WhatIfPreference)
    $effectiveMode = if ($willRunLive) { 'Live' } elseif ($WhatIfPreference) { 'WhatIf' } else { 'PlanOnly' }
    $requestedMode = if ($Live) { 'Live' } else { 'PlanOnly' }
    $payloadBuildConfiguration = 'Release'
    $payloadPrepareCommand = ".\scripts\Prepare-GuestPayload.ps1 -RepoRoot . -PayloadRoot '$resolvedPayloadRoot' -Configuration $payloadBuildConfiguration -GuestWorkingDirectory '$guestRoot' -SelfContained"
    $payloadRepairSuggestions = @(
        "Prepare the self-contained guest payload: $payloadPrepareCommand",
        "Then rerun .\scripts\Test-HyperVReadiness.ps1 or .\run.ps1 -Mode CheckEnvironment; neither command starts or restores the VM."
    )

    $checks = New-Object System.Collections.Generic.List[object]
    [void]$checks.Add((New-PlanCheck -Name 'Live execution is explicit' -Status 'Passed' -RequiredForLive $true -Message 'No VM mutation is possible unless -Live is supplied and -WhatIf is not supplied.' -Details @{ liveSwitchPresent = [bool]$Live; planOnlySwitchPresent = [bool]$PlanOnly; whatIf = [bool]$WhatIfPreference; willMutateVm = $willRunLive }))
    [void]$checks.Add((New-HostOsCheck))
    [void]$checks.Add((New-AdministratorCheck))
    [void]$checks.Add((New-HyperVFeatureCheck))
    [void]$checks.Add((New-CommandAvailabilityCheck -Name 'PowerShell Direct commands' -Commands @('New-PSSession', 'Invoke-Command', 'Copy-Item') -RequiredForLive $true))
    [void]$checks.Add((New-CommandAvailabilityCheck -Name 'Hyper-V commands' -Commands @('Get-VM', 'Get-VMHost', 'Get-VMSnapshot', 'Get-VMIntegrationService', 'Enable-VMIntegrationService', 'Set-VMHost', 'Start-VM', 'Resume-VM', 'Stop-VM', 'Restore-VMSnapshot', 'Copy-VMFile') -RequiredForLive $true))
    if ($openVmConsoleOnLiveStart) {
        [void]$checks.Add((New-CommandAvailabilityCheck -Name 'Hyper-V VM console command' -Commands @('vmconnect.exe') -RequiredForLive $false))
    }
    else {
        [void]$checks.Add((New-PlanCheck `
                    -Name 'Hyper-V VM console command' `
                    -Status 'Passed' `
                    -RequiredForLive $false `
                    -Message 'VM console auto-open is disabled only because -NoOpenVmConsole was supplied; headless live analysis is otherwise blocked before sample execution.' `
                    -Details @{ openVmConsoleOnLiveStart = $false; openVmConnectOnLiveStart = $false; disabledByNoOpenVmConsole = [bool]$NoOpenVmConsole } `
                    -Category 'operator-ui'))
    }
    if ($openVmConsoleOnLiveStart -and $rdpFallbackEnabled) {
        [void]$checks.Add((New-CommandAvailabilityCheck -Name 'Remote Desktop fallback command' -Commands @('mstsc.exe') -RequiredForLive $false))
    }
    [void]$checks.Add((New-GuestSecretCheck -SecretName $effectiveGuestSecretName))
    [void]$checks.Add((New-HostSharedPathCheck -RuntimeRoot $runtimeRoot -GuestPayloadRoot $resolvedPayloadRoot -RepositoryRoot $resolvedRepoRoot))
    [void]$checks.Add((New-HostTestSigningCheck -DriverEnabled $driverEnabled -UseMockCollector $useMockCollector))
    [void]$checks.Add((New-HyperVVmCheck -VmName $effectiveVmName))
    [void]$checks.Add((New-HyperVCheckpointCheck -VmName $effectiveVmName -CheckpointName $effectiveCheckpointName))
    [void]$checks.Add((New-GuestServiceCheck -VmName $effectiveVmName))
    [void]$checks.Add((New-PowerShellDirectCheck -VmName $effectiveVmName -UserName $effectiveGuestUserName -SecretName $effectiveGuestSecretName -GuestPathsToProbe @($guestRoot, $agentPathInGuest, $r0CollectorPathInGuest)))
    [void]$checks.Add((New-DirectoryPresenceCheck -Name 'Guest payload root' -Path $resolvedPayloadRoot -RequiredForLive $true -Remediation $payloadRepairSuggestions))
    [void]$checks.Add((New-DirectoryPresenceCheck -Name 'Guest Agent payload directory' -Path (Join-Path $resolvedPayloadRoot 'agent') -RequiredForLive $true -Remediation $payloadRepairSuggestions))
    [void]$checks.Add((New-FilePresenceCheck -Name 'Sample file' -Path $resolvedSamplePath -RequiredForLive $true -Remediation @("Pass an existing .exe sample path, for example: .\run.ps1 -Mode Plan -SamplePath <sample.exe>")))
    [void]$checks.Add((New-FilePresenceCheck -Name 'Guest Agent payload' -Path $agentHostPath -RequiredForLive $true -Remediation $payloadRepairSuggestions))
    [void]$checks.Add((New-FilePresenceCheck -Name 'Payload manifest' -Path $payloadManifestPath -RequiredForLive $false -Remediation $payloadRepairSuggestions))
    if ($driverEnabled) {
        [void]$checks.Add((New-DirectoryPresenceCheck -Name 'R0Collector payload directory' -Path (Join-Path $resolvedPayloadRoot 'r0collector') -RequiredForLive $true -Remediation $payloadRepairSuggestions))
        [void]$checks.Add((New-FilePresenceCheck -Name 'R0Collector payload' -Path $collectorHostPath -RequiredForLive $true -Remediation $payloadRepairSuggestions))
    }
    [void]$checks.Add((New-R0DriverHostPathCheck `
                -DriverEnabled $driverEnabled `
                -UseMockCollector $useMockCollector `
                -HostDriverPath $hostDriverPath `
                -DriverPathInGuest $driverPathInGuest `
                -DevicePath $devicePath))
    $preflightArray = @($checks.ToArray())
    $preflightSummary = New-PreflightSummary -Checks $preflightArray

    $startScript = Join-Path $resolvedRepoRoot 'scripts\Start-SandboxHyperVJob.ps1'
    $collectScript = Join-Path $resolvedRepoRoot 'scripts\Collect-GuestOutputs.ps1'
    $importReportScript = Join-Path $resolvedRepoRoot 'scripts\Import-HyperVJobReport.ps1'
    $vmConsoleCommand = if ($openVmConsoleOnLiveStart) { "vmconnect.exe $vmConsoleServerName `"$effectiveVmName`"" } else { '' }
    $plan = [ordered]@{
        contractVersion = 1
        kind = 'KSwordSandbox.HyperVE2EPlan'
        generatedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
        safeDefault = $true
        requestedMode = $requestedMode
        effectiveMode = $effectiveMode
        willMutateVm = $willRunLive
        repositoryRoot = $resolvedRepoRoot
        configPath = $ConfigPath
        planPath = $PlanPath
        scripts = [ordered]@{
            orchestrator = $MyInvocation.MyCommand.Path
            startJob = $startScript
            collectOutputs = $collectScript
            importReport = $importReportScript
        }
        job = [ordered]@{
            jobId = $jobGuid.ToString('D')
            jobIdN = $jobIdN
            durationSeconds = $effectiveDurationSeconds
            restoreCheckpointAfterRun = $RestoreCheckpointAfterRun
        }
        vm = [ordered]@{
            name = $effectiveVmName
            cleanCheckpointName = $effectiveCheckpointName
            openVmConsoleOnLiveStart = $openVmConsoleOnLiveStart
            openVmConnectOnLiveStart = $openVmConsoleOnLiveStart
            openConsoleOnLiveStart = $openVmConsoleOnLiveStart
            requireConsoleOnLiveStart = $openVmConsoleOnLiveStart
            consoleDisabledByNoOpenVmConsole = [bool]$NoOpenVmConsole
            consoleServerName = $vmConsoleServerName
            consoleCommand = $vmConsoleCommand
            consoleDisableSwitch = '-NoOpenVmConsole'
            consoleBestEffort = $false
            consoleFailureBlocksHeadless = $openVmConsoleOnLiveStart
            desktopStrategies = @('HyperV.VMConnect', 'RDP.Mstsc')
            rdpFallbackEnabled = $rdpFallbackEnabled
            rdpTarget = $rdpTarget
        }
        guest = [ordered]@{
            userName = $effectiveGuestUserName
            passwordSecretName = $effectiveGuestSecretName
            workingDirectory = $guestRoot
            agentDirectory = $guestAgentDirectory
            collectorDirectory = $guestCollectorDirectory
            driverDirectory = $guestDriverDirectory
            incomingDirectory = $guestIncomingDirectory
            outputRoot = $guestOutRoot
            outputDirectory = $guestOutputDirectory
            eventsPath = $guestEventsPath
            agentSummaryPath = $guestAgentSummaryPath
            agentPath = $agentPathInGuest
            agentPidPath = $agentPidPath
            agentExitPath = $agentExitPath
        }
        host = [ordered]@{
            runtimeRoot = $runtimeRoot
            guestPayloadRoot = $resolvedPayloadRoot
            jobRoot = $jobRoot
            outputRoot = $hostOutputRoot
            guestOutputDirectory = $hostGuestOutputDirectory
            eventsJsonPath = $hostEventsPath
            driverEventsJsonlPath = $hostDriverEventsPath
            runbookExecutionPath = $runbookExecutionPath
            jsonReportPath = (Join-Path $jobRoot 'report.json')
            htmlReportPath = (Join-Path $jobRoot 'report.html')
            htmlReportZhPath = (Join-Path $jobRoot 'report.zh.html')
            htmlReportEnPath = (Join-Path $jobRoot 'report.en.html')
            agentPayloadPath = $agentHostPath
            r0CollectorPayloadPath = $collectorHostPath
            payloadManifestPath = $payloadManifestPath
        }
        sample = [ordered]@{
            hostPath = $resolvedSamplePath
            fileName = $sampleFileName
            guestPath = $guestSamplePath
        }
        driver = [ordered]@{
            enabled = $driverEnabled
            serviceName = $serviceName
            r0CollectorPathInGuest = $r0CollectorPathInGuest
            devicePath = $devicePath
            useMockCollector = $useMockCollector
            collectionMode = $driverCollectionMode
            hostDriverPath = $hostDriverPath
            hostDriverPathConfigured = (-not [string]::IsNullOrWhiteSpace($hostDriverPath))
            hostDriverPathExists = if ([string]::IsNullOrWhiteSpace($hostDriverPath)) { $false } else { Test-Path -LiteralPath $hostDriverPath -PathType Leaf }
            willStageDriver = (-not [string]::IsNullOrWhiteSpace($hostDriverPath))
            willInstallDriverService = (-not [string]::IsNullOrWhiteSpace($hostDriverPath))
            configurationWarning = if ($driverEnabled -and (-not $useMockCollector) -and [string]::IsNullOrWhiteSpace($hostDriverPath)) { '真实 R0 collection 已启用但 driver.hostDriverPath 为空；stage-guest-payload 将没有 driverSource，install-driver-service 会被省略，R0Collector 可能以 deviceUnavailable/win32Error=2 失败。下一步：配置 -DriverHostPath 或启用 driver.useMockCollector=true。' } else { $null }
            driverPathInGuest = $driverPathInGuest
            eventJsonLinesPath = $driverEventsPath
        }
        execution = [ordered]@{
            guestAgentCommandLine = $guestAgentCommandLine
            guestAgentArguments = @($guestAgentArguments)
            r0CollectorCommandLine = $r0CollectorCommandLine
            r0CollectorArguments = @($r0CollectorArguments)
            r0CollectorMode = $driverCollectionMode
        }
        timeouts = [ordered]@{
            startupSeconds = $StartupTimeoutSeconds
            guestReadySeconds = $GuestReadyTimeoutSeconds
            executionSeconds = $effectiveExecutionTimeoutSeconds
            syncIntervalSeconds = 2
        }
        safety = [ordered]@{
            planOnlyDefault = $true
            whatIfPreventsMutation = $true
            liveRequiresAdministrator = $true
            liveRequiresExplicitSwitch = $true
            openVmConsoleOnLiveStartDefault = $true
            openVmConnectOnLiveStart = $openVmConsoleOnLiveStart
            vmConsoleRequiredUnlessNoOpenVmConsole = $true
            vmConsoleOpenIsBestEffort = $false
            openVmConnectFailureBlocksHeadless = $openVmConsoleOnLiveStart
            headlessLiveRequiresNoOpenVmConsole = $true
            noVmConsoleWhenPlanOnlyOrWhatIf = (-not $willRunLive)
            secretValuePrinted = $false
            noVmMutationWhenPlanOnly = (-not $willRunLive)
        }
        operatorGuidance = [ordered]@{
            checkEnvironmentCommand = '.\run.ps1 -Mode CheckEnvironment'
            readinessCommand = '.\scripts\Test-HyperVReadiness.ps1'
            vmProfileInventoryCommand = '.\scripts\Test-HyperVReadiness.ps1 -ListAvailableVmProfiles'
            planOnlyCommand = '.\run.ps1 -Mode Plan -SamplePath <sample.exe>'
            whatIfCommand = '.\run.ps1 -Mode Analyze -SamplePath <sample.exe> -Live -WhatIf'
            payloadPreparationCommand = $payloadPrepareCommand
            disableVmConsoleCommand = '.\run.ps1 -Mode Analyze -SamplePath <sample.exe> -Live -NoOpenVmConsole'
            noVmMutationForPlanOnlyOrWhatIf = $true
            repairSuggestions = @($preflightSummary['repairSuggestions'])
        }
        preflightSummary = $preflightSummary
        preflight = $preflightArray
        steps = New-HyperVE2ESteps `
            -Vm $effectiveVmName `
            -Snapshot $effectiveCheckpointName `
            -PayloadRoot $resolvedPayloadRoot `
            -SampleHostPath $resolvedSamplePath `
            -SampleGuestPath $guestSamplePath `
            -GuestOut $guestOutputDirectory `
            -HostOut $hostOutputRoot `
            -AgentPath $agentPathInGuest `
            -AgentPidPath $agentPidPath `
            -AgentExitPath $agentExitPath `
            -DriverEventsPath $driverEventsPath `
            -DriverEnabled $driverEnabled `
            -UseMockCollector $useMockCollector `
            -DriverHostPath ([string]$hostDriverPath) `
            -DriverServiceName ([string]$serviceName) `
            -DriverPathInGuest ([string]$driverPathInGuest) `
            -SecretName $effectiveGuestSecretName `
            -GuestAgentCommandLine $guestAgentCommandLine `
            -R0CollectorCommandLine $r0CollectorCommandLine `
            -OpenVmConsoleOnLiveStart $openVmConsoleOnLiveStart `
            -VmConsoleServerName $vmConsoleServerName `
            -RdpFallbackEnabled $rdpFallbackEnabled `
            -RdpTarget $rdpTarget `
            -RestoreAfterRun $RestoreCheckpointAfterRun
    }

    $planParent = Split-Path -Parent $PlanPath
    if (-not [string]::IsNullOrWhiteSpace($planParent)) {
        New-Item -ItemType Directory -Path $planParent -Force -WhatIf:$false | Out-Null
    }

    $plan | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $PlanPath -Encoding UTF8 -WhatIf:$false
    Write-HyperVE2EStep "Plan JSON written: $PlanPath"
    $planFromDisk = Read-JsonFileIfPresent -Path $PlanPath
    if ($null -ne $planFromDisk) {
        $plan = $planFromDisk
    }

    $script:LastHyperVE2EPlan = $plan

    if (-not $willRunLive) {
        $safeStartedAtUtc = [DateTimeOffset]::UtcNow
        $safeStepResults = New-SafeModeStepResults -Plan $plan -Message "Safe $effectiveMode mode recorded the plan without launching child scripts or VM commands."
        Save-RunbookExecutionRecord `
            -Plan $plan `
            -ModeName $effectiveMode `
            -Success $true `
            -Message "Safe $effectiveMode mode: no checkpoint restore, VM start, file copy, guest command, shutdown, or restore was executed." `
            -StartedAtUtc $safeStartedAtUtc `
            -Duration ([DateTimeOffset]::UtcNow - $safeStartedAtUtc) `
            -StepResults $safeStepResults `
            -WhatIf ([bool]$WhatIfPreference)
        Write-HyperVE2EStep "Safe $effectiveMode mode: no checkpoint restore, VM start, file copy, guest command, shutdown, or restore was executed."
        if ([int]$plan.preflightSummary.failedRequired -gt 0 -or [int]$plan.preflightSummary.warnings -gt 0) {
            Write-HyperVE2EStep "Plan 记录了 $($plan.preflightSummary.failedRequired) 个失败的必需检查和 $($plan.preflightSummary.warnings) 个警告；在 $effectiveMode 模式下这不是致命错误。 / Preflight gaps recorded."
            Write-PreflightRepairSuggestions -Suggestions @($plan.preflightSummary.repairSuggestions)
        }

        Write-Output ([pscustomobject][ordered]@{
                PlanPath = $PlanPath
                RunbookExecutionPath = $runbookExecutionPath
                RunbookProgressPath = (Join-Path $jobRoot 'runbook-progress.json')
                Mode = $effectiveMode
                LiveExecuted = $false
                TargetVmName = $effectiveVmName
                JobId = $jobGuid
            })
        exit 0
    }

    if ([int]$plan.preflightSummary.failedRequired -gt 0) {
        $failedNames = @($plan.preflightSummary.failedRequiredNames) -join ', '
        $failedDetails = @(
            $plan.preflight |
                Where-Object { ([bool]$_.requiredForLive) -and ([string]$_.status -eq 'Failed') } |
                ForEach-Object { "$($_.name): $($_.message)" }
        )
        $detailText = if ($failedDetails.Count -gt 0) { ' Details: ' + ($failedDetails -join ' | ') } else { '' }
        $message = "错误：Live Hyper-V E2E preflight 在 VM mutation 前失败。失败的必需检查：$failedNames.$detailText。下一步：按 ReviewPlan/RemediationHints 修复第一个失败项后重试。"
        Write-PreflightRepairSuggestions -Suggestions @($plan.preflightSummary.repairSuggestions)
        Save-RunbookExecutionRecord `
            -Plan $plan `
            -ModeName 'Live' `
            -Success $false `
            -Message $message `
            -StartedAtUtc ([DateTimeOffset]::UtcNow) `
            -Duration ([TimeSpan]::Zero) `
            -StepResults @() `
            -WhatIf $false
        try {
            [void](Invoke-FailureReportImport -Plan $plan -ImportReportScript $importReportScript -Reason $message)
        }
        catch {
            Write-Warning "中文提示：Live preflight 失败后无法自动重建 failure report。英文详情：$($_.Exception.Message)"
        }
        throw $message
    }

    if (-not (Test-Path -LiteralPath $startScript -PathType Leaf)) {
        $message = "错误：找不到 Start 脚本：$startScript。下一步：确认 scripts\Start-SandboxHyperVJob.ps1 存在，并从仓库根目录运行。"
        Save-RunbookExecutionRecord -Plan $plan -ModeName 'Live' -Success $false -Message $message -StartedAtUtc ([DateTimeOffset]::UtcNow) -Duration ([TimeSpan]::Zero) -StepResults @()
        throw $message
    }

    if (-not (Test-Path -LiteralPath $collectScript -PathType Leaf)) {
        $message = "错误：找不到 Collect 脚本：$collectScript。下一步：确认 scripts\Collect-GuestOutputs.ps1 存在，并从仓库根目录运行。"
        Save-RunbookExecutionRecord -Plan $plan -ModeName 'Live' -Success $false -Message $message -StartedAtUtc ([DateTimeOffset]::UtcNow) -Duration ([TimeSpan]::Zero) -StepResults @()
        throw $message
    }

    if (-not (Test-Path -LiteralPath $importReportScript -PathType Leaf)) {
        $message = "错误：找不到 Report import 脚本：$importReportScript。下一步：确认 scripts\Import-HyperVJobReport.ps1 存在。"
        Save-RunbookExecutionRecord -Plan $plan -ModeName 'Live' -Success $false -Message $message -StartedAtUtc ([DateTimeOffset]::UtcNow) -Duration ([TimeSpan]::Zero) -StepResults @()
        throw $message
    }

    if ($PSCmdlet.ShouldProcess($effectiveVmName, "Execute live Hyper-V E2E plan $PlanPath")) {
        $liveStartedAtUtc = [DateTimeOffset]::UtcNow
        $timer = [Diagnostics.Stopwatch]::StartNew()
        $startExitCode = $null
        $collectExitCode = $null
        $startResult = $null
        $collectResult = $null
        $startInvocation = $null
        $collectInvocation = $null
        $liveSuccess = $false
        $liveMessage = ''
        $startChildTimeoutSeconds = [Math]::Max(
            900,
            [int]$plan.timeouts.startupSeconds + [int]$plan.timeouts.guestReadySeconds + 300)
        $collectChildTimeoutSeconds = [Math]::Max(
            900,
            [int]$plan.timeouts.executionSeconds + 300)

        Write-HyperVE2EStep "Starting live VM phase (child timeout ${startChildTimeoutSeconds}s)."
        $startInvocation = Invoke-ChildPowerShellScript -PhaseName 'start' -ScriptPath $startScript -Arguments @('-PlanPath', $PlanPath, '-Live') -TimeoutSeconds $startChildTimeoutSeconds -LogDirectory $jobRoot
        $startExitCode = [int]$startInvocation.exitCode
        $startResult = Read-JsonFileIfPresent -Path (Join-Path $jobRoot 'hyperv-e2e-start-result.json')
        if ($startExitCode -ne 0) {
            $liveMessage = (Get-ChildPhaseFailureMessage -PhaseName 'Start' -Invocation $startInvocation -Fallback "Start 阶段失败，退出码 $startExitCode") + ' Collection 阶段未启动。'
        }
        else {
            Write-HyperVE2EStep "Starting live collection/cleanup phase (child timeout ${collectChildTimeoutSeconds}s)."
            $restoreCheckpointArgument = if ($RestoreCheckpointAfterRun) { '1' } else { '0' }
            $collectInvocation = Invoke-ChildPowerShellScript -PhaseName 'collect' -ScriptPath $collectScript -Arguments @('-PlanPath', $PlanPath, '-Live', '-RestoreCheckpointAfterRun', $restoreCheckpointArgument) -TimeoutSeconds $collectChildTimeoutSeconds -LogDirectory $jobRoot
            $collectExitCode = [int]$collectInvocation.exitCode
            $collectResult = Read-JsonFileIfPresent -Path (Join-Path $jobRoot 'hyperv-e2e-collect-result.json')
            if ($collectExitCode -ne 0) {
                $liveMessage = Get-ChildPhaseFailureMessage -PhaseName 'Collection' -Invocation $collectInvocation -Fallback "Collection 阶段失败，退出码 $collectExitCode。"
            }
            else {
                $liveSuccess = $true
            }
        }

        $timer.Stop()
        $liveStepResults = Convert-PhaseStepsToRunbookStepResults `
            -Plan $plan `
            -StartResult $startResult `
            -CollectResult $collectResult `
            -StartInvocation $startInvocation `
            -CollectInvocation $collectInvocation
        Save-RunbookExecutionRecord `
            -Plan $plan `
            -ModeName 'Live' `
            -Success $liveSuccess `
            -Message $liveMessage `
            -StartedAtUtc $liveStartedAtUtc `
            -Duration $timer.Elapsed `
            -StepResults $liveStepResults `
            -StartResult $startResult `
            -CollectResult $collectResult `
            -StartInvocation $startInvocation `
            -CollectInvocation $collectInvocation `
            -StartExitCode $startExitCode `
            -CollectExitCode $collectExitCode `
            -WhatIf $false

        if ($liveSuccess) {
            Write-HyperVE2EStep 'Importing collected guest events and regenerating report artifacts.'
            try {
                & $importReportScript `
                    -JobId ([string]$plan.job.jobId) `
                    -SamplePath ([string]$plan.sample.hostPath) `
                    -EventsPath ([string]$plan.host.eventsJsonPath) `
                    -RunbookExecutionPath ([string]$plan.host.runbookExecutionPath) `
                    -ConfigPath ([string]$plan.configPath) `
                    -RepoRoot ([string]$plan.repositoryRoot) `
                    -DurationSeconds ([int]$plan.job.durationSeconds)
            }
            catch {
                Write-Error "失败：Hyper-V E2E Live 执行已成功，但报告导入失败。下一步：可用 Rebuild-JobReport 重建报告。英文详情：$($_.Exception.Message)"
                exit 1
            }

            Write-HyperVE2EStep "Report artifacts ready: $($plan.host.htmlReportPath)"
            exit 0
        }

        try {
            [void](Invoke-FailureReportImport -Plan $plan -ImportReportScript $importReportScript -Reason $liveMessage)
        }
        catch {
            Write-Warning "中文提示：Live 失败后无法自动重建 failure report。英文详情：$($_.Exception.Message)"
        }
        Write-Error "失败：Hyper-V E2E Live 执行失败。下一步：查看 runbook-execution.json 的 RemediationHints、failure report import result 和 report-rebuild-diagnostics.json，修复后重试。英文详情：$liveMessage"
        exit 1
    }

    Write-HyperVE2EStep 'Live execution was declined by ShouldProcess/Confirm; no child script was launched.'
    $declinedStartedAtUtc = [DateTimeOffset]::UtcNow
    $declinedSteps = New-SafeModeStepResults -Plan $plan -Message 'Live execution was declined by ShouldProcess/Confirm; no child script was launched.'
    Save-RunbookExecutionRecord `
        -Plan $plan `
        -ModeName 'WhatIf' `
        -Success $true `
        -Message 'Live execution was declined by ShouldProcess/Confirm; no child script was launched.' `
        -StartedAtUtc $declinedStartedAtUtc `
        -Duration ([DateTimeOffset]::UtcNow - $declinedStartedAtUtc) `
        -StepResults $declinedSteps `
        -WhatIf $true
    exit 0
}
catch {
    $failureMessage = "失败：Hyper-V E2E 编排失败。下一步：查看生成的 fallback runbook execution record 和 RemediationHints。英文详情：$($_.Exception.Message)"
    if ($null -ne $script:LastHyperVE2EPlan) {
        try {
            $fallbackExecutionPath = [string]$script:LastHyperVE2EPlan.host.runbookExecutionPath
            if ([string]::IsNullOrWhiteSpace($fallbackExecutionPath)) {
                $fallbackExecutionPath = Join-Path ([string]$script:LastHyperVE2EPlan.host.jobRoot) 'runbook-execution.json'
            }

            if (-not (Test-Path -LiteralPath $fallbackExecutionPath -PathType Leaf)) {
                $fallbackModeName = [string]$script:LastHyperVE2EPlan.effectiveMode
                if ([string]::IsNullOrWhiteSpace($fallbackModeName)) {
                    $fallbackModeName = 'Live'
                }

                Save-RunbookExecutionRecord `
                    -Plan $script:LastHyperVE2EPlan `
                    -ModeName $fallbackModeName `
                    -Success $false `
                    -Message $failureMessage `
                    -StartedAtUtc ([DateTimeOffset]::UtcNow) `
                    -Duration ([TimeSpan]::Zero) `
                    -StepResults @() `
                    -WhatIf ([bool]$WhatIfPreference)
            }
        }
        catch {
            Write-Warning "中文提示：无法写入 fallback runbook execution record。英文详情：$($_.Exception.Message)"
        }
    }

    Write-Error $failureMessage
    exit 1
}
