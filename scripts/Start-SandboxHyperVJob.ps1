<#
.SYNOPSIS
Starts a KSword Sandbox Hyper-V E2E job from a generated plan.

.DESCRIPTION
This script is normally called by Invoke-HyperVE2E.ps1. It does nothing by
default unless -Live is supplied. In live mode it requires an Administrator host
process, restores the clean checkpoint, starts the VM, stages payloads, copies
the sample, prepares output paths, and starts the Guest Agent with optional
R0Collector arguments. Passing -WhatIf prevents all VM mutation.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory)]
    [string]$PlanPath,

    [switch]$Live
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$script:StepResults = New-Object System.Collections.Generic.List[object]
$script:CleanupErrors = New-Object System.Collections.Generic.List[string]
$script:GuestAgentProcessId = $null
$script:GuestAgentCommandLine = ''
$script:GuestAgentArguments = @()
$script:R0CollectorCommandLine = ''
$script:R0CollectorArguments = @()
$script:R0CollectorMode = 'Disabled'
$script:VmMutationStarted = $false
$script:VmConsoleOpenAttempted = $false
$script:VmConsoleOpenSucceeded = $false
$script:VmConsoleOpenMessage = ''
$script:VmConsoleProcessId = $null
$script:VmConsoleOpenStrategy = ''
$script:VmConsoleRdpTarget = ''
$script:Cmdlet = $PSCmdlet
$script:GuestServiceInterfaceComponentId = '6C09BB55-D683-4DA0-8931-C9BF705F6480'

function Write-HyperVJobStep {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "[hyperv-e2e:start] $Message"
}

function Read-HyperVE2EPlan {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "错误：找不到 Plan JSON：$Path。下一步：请先运行 .\run.ps1 -Mode Plan 或检查 -PlanPath。"
    }

    $plan = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if ($plan.kind -ne 'KSwordSandbox.HyperVE2EPlan') {
        throw "错误：Plan JSON 类型不是 KSwordSandbox.HyperVE2EPlan：$Path。下一步：请重新生成 Hyper-V E2E plan。"
    }

    return $plan
}

function ConvertTo-BooleanValue {
    param([object]$Value)

    if ($null -eq $Value) {
        return $false
    }

    return [System.Convert]::ToBoolean($Value)
}

function Quote-PowerShellString {
    param([string]$Text)
    if ($null -eq $Text) {
        $Text = ''
    }

    return "'" + ($Text -replace "'", "''") + "'"
}

function Get-GuestServiceInterface {
    param([Parameter(Mandatory)][string]$VmName)

    $componentSuffix = '\' + $script:GuestServiceInterfaceComponentId
    try {
        $services = @(Get-VMIntegrationService -VMName $VmName -ErrorAction Stop)
    }
    catch {
        throw "错误：无法查询 VM '$VmName' 的 integration services。下一步：确认 VM 名称、Hyper-V 权限和管理员 PowerShell。英文详情：$($_.Exception.Message)"
    }

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
        throw "错误：VM '$VmName' 未找到 Guest Service Interface integration service（组件 ID $script:GuestServiceInterfaceComponentId）。已发现 services：$($availableServices -join ', ')。下一步：在 Hyper-V 设置中启用 Guest Service Interface，或确认该 VM 是受支持的 Windows 来宾。"
    }

    return $service
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

function Assert-CommandAvailable {
    param([Parameter(Mandatory)][string[]]$Names)

    $missing = @()
    foreach ($name in $Names) {
        if ($null -eq (Get-Command -Name $name -ErrorAction SilentlyContinue)) {
            $missing += $name
        }
    }

    if ($missing.Count -gt 0) {
        throw "错误：当前 PowerShell 缺少必需命令：$($missing -join ', ')。下一步：安装/启用 Hyper-V PowerShell 工具，并以管理员 PowerShell 重试。"
    }
}

function Assert-FileForLive {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "错误：找不到 $Name：$Path。下一步：确认路径存在，或重新运行安装/Prepare-GuestPayload。"
    }
}

function Assert-DirectoryForLive {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "错误：找不到 $Name：$Path。下一步：确认路径存在，或重新运行安装/Prepare-GuestPayload。"
    }
}

function Get-HyperVVmNameCandidates {
    param([int]$Limit = 20)

    try {
        return @(Get-VM -ErrorAction Stop |
            Sort-Object -Property Name |
            Select-Object -First $Limit |
            ForEach-Object { [string]$_.Name })
    }
    catch {
        return @()
    }
}

function Assert-VmCheckpointForLive {
    param([Parameter(Mandatory)][object]$Plan)

    try {
        $vm = Get-VM -Name $Plan.vm.name -ErrorAction Stop
    }
    catch {
        $availableVms = @(Get-HyperVVmNameCandidates -Limit 20)
        $availableText = if ($availableVms.Count -gt 0) { $availableVms -join ', ' } else { '<none or unavailable>' }
        throw "错误：VM 诊断失败，无法查询 golden VM '$($Plan.vm.name)'；尚未执行 VM mutation。已看到 VMs：$availableText。下一步：确认 VM 名称与 Hyper-V 权限，运行 .\scripts\Test-HyperVReadiness.ps1 -ListAvailableVmProfiles 列出只读候选，或运行 .\install.ps1 -Mode Change -UpdateHyperVConfig。英文详情：$($_.Exception.Message)"
    }

    try {
        $snapshot = Get-VMSnapshot -VMName $Plan.vm.name -Name $Plan.vm.cleanCheckpointName -ErrorAction Stop
    }
    catch {
        $availableSnapshots = @()
        try {
            $availableSnapshots = @(Get-VMSnapshot -VMName $Plan.vm.name -ErrorAction Stop | ForEach-Object { [string]$_.Name } | Select-Object -First 20)
        }
        catch {
            $availableSnapshots = @()
        }

        $availableText = if ($availableSnapshots.Count -gt 0) { $availableSnapshots -join ', ' } else { '<none or unavailable>' }
        throw "错误：Checkpoint 诊断失败，VM '$($Plan.vm.name)' 上找不到 clean checkpoint '$($Plan.vm.cleanCheckpointName)'；尚未执行 VM mutation。已看到 checkpoints：$availableText。下一步：创建/刷新干净快照，或更新 -CheckpointName。英文详情：$($_.Exception.Message)"
    }

    Write-HyperVJobStep ("VM/checkpoint 诊断通过：VM '{0}' 当前状态 '{1}'，checkpoint '{2}' 创建时间 {3}。" -f $Plan.vm.name, $vm.State, $Plan.vm.cleanCheckpointName, $snapshot.CreationTime)
}

function Assert-GuestServiceForLive {
    param([Parameter(Mandatory)][object]$Plan)

    $guestService = Get-GuestServiceInterface -VmName $Plan.vm.name
    if ([bool]$guestService.Enabled) {
        Write-HyperVJobStep "Guest Service Interface is already enabled."
    }
    else {
        Write-HyperVJobStep "Guest Service Interface is currently disabled; live start will enable it before Copy-VMFile."
    }
}

function Get-GuestCredential {
    param(
        [Parameter(Mandatory)][string]$UserName,
        [Parameter(Mandatory)][string]$SecretName
    )

    if ([string]::IsNullOrWhiteSpace($UserName)) {
        throw '错误：guest userName 为空。下一步：在本机 sandbox 配置中设置 guest.userName；secret 值未打印。'
    }

    if ([string]::IsNullOrWhiteSpace($SecretName)) {
        throw '错误：guest password secret 名称为空。下一步：在本机 sandbox 配置中设置 guest.passwordSecretName，通常为 KSWORDBOX_GUEST_PASSWORD；secret 值未打印。'
    }

    $password = $null
    $scope = ''
    foreach ($candidateScope in @('Process', 'User', 'Machine')) {
        $candidate = [Environment]::GetEnvironmentVariable($SecretName, $candidateScope)
        if (-not [string]::IsNullOrEmpty($candidate)) {
            $password = $candidate
            $scope = $candidateScope
            break
        }
    }

    if ([string]::IsNullOrEmpty($password)) {
        throw "错误：Guest password environment variable '$SecretName' 未在 Process/User/Machine 中设置；secret 值未打印。下一步：在启动 Live Hyper-V 的同一个管理员 PowerShell 中设置该变量，或运行 .\install.ps1 -InstallEntrypoint CreateOrPreparePath -PromptPassword；若使用生成密码，请确保 VM 内账号密码也同步。"
    }

    Write-HyperVJobStep "凭据诊断：已从 $scope scope 读取 guest credential secret '$SecretName'，用户 '$UserName'；secret 值未打印。"
    $securePassword = [System.Security.SecureString]::new()
    foreach ($passwordCharacter in $password.ToCharArray()) {
        $securePassword.AppendChar($passwordCharacter)
    }
    $securePassword.MakeReadOnly()
    return [pscredential]::new($UserName, $securePassword)
}

function Add-UniqueRemediationHint {
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

function Get-StartRemediationHints {
    param(
        [AllowNull()][string]$Message,
        [AllowNull()][object]$Plan
    )

    $hints = New-Object System.Collections.Generic.List[string]
    if ([string]::IsNullOrWhiteSpace($Message)) {
        return @()
    }

    if ($Message -match "Guest password environment variable '([^']+)' is not set" -or
        $Message -match "guest password secret '([^']+)'.*未在 Process/User/Machine" -or
        $Message -match "未在 Process/User/Machine 环境中找到 guest password secret '([^']+)'") {
        Add-UniqueRemediationHint -Hints $hints -Hint "下一步：在启动 Live Hyper-V 的同一个管理员 PowerShell 中让 $($Matches[1]) 可见；普通用户请回到安装向导重置本机 password secret。若 VM 实际密码未知，请选择重置 VM 中实际来宾密码。"
    }
    elseif ($Message -match 'Guest password secret name is empty') {
        Add-UniqueRemediationHint -Hints $hints -Hint '下一步：Live 前在本机 sandbox 配置中配置 guest.passwordSecretName。'
    }

    if ($Message -match 'Guest Service Interface|Copy-VMFile') {
        Add-UniqueRemediationHint -Hints $hints -Hint "下一步：为 VM '$($Plan.vm.name)' 启用 Guest Service Interface，或修复 VM integration services 后重试 Live。"
    }

    if ($Message -match 'Get-VM|VM .*not.*found|cannot find.*VM') {
        Add-UniqueRemediationHint -Hints $hints -Hint "下一步：确认 Hyper-V 宿主机上存在 VM '$($Plan.vm.name)'，然后重新运行只读 readiness preflight。"
    }

    if ($Message -match 'checkpoint|VMSnapshot|Restore-VMSnapshot') {
        Add-UniqueRemediationHint -Hints $hints -Hint "下一步：Live 前确认 VM '$($Plan.vm.name)' 上存在 checkpoint '$($Plan.vm.cleanCheckpointName)'。"
    }

    if ($Message -match 'PowerShell Direct|New-PSSession|Invoke-Command') {
        Add-UniqueRemediationHint -Hints $hints -Hint "下一步：确认 VM '$($Plan.vm.name)' 可用来宾用户 '$($Plan.guest.userName)' 和已配置 password secret 运行 PowerShell Direct。"
    }

    if ($Message -match 'driver\.hostDriverPath|R0Collector|deviceUnavailable|win32Error=2') {
        Add-UniqueRemediationHint -Hints $hints -Hint '下一步：最小 E2E 可设置 driver.useMockCollector=true；真实 R0 采集前请配置已构建/测试签名的 driver.hostDriverPath。'
    }

    if ($hints.Count -eq 0) {
        Add-UniqueRemediationHint -Hints $hints -Hint '下一步：在管理员 PowerShell 重新运行只读 readiness preflight，并先修复第一个失败的必需检查后再重试 Live。'
    }

    return @($hints.ToArray())
}

function New-StepResult {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Title,
        [bool]$Success,
        [bool]$Skipped,
        [DateTimeOffset]$StartedAtUtc,
        [TimeSpan]$Duration,
        [string]$Message = '',
        [string[]]$RemediationHints = @()
    )

    $state = if ($Skipped) { 'skipped' } elseif ($Success) { 'completed' } else { 'failed' }
    return [ordered]@{
        id = $Id
        title = $Title
        state = $state
        success = $Success
        skipped = $Skipped
        startedAtUtc = $StartedAtUtc.ToString('O')
        durationSeconds = [Math]::Round($Duration.TotalSeconds, 3)
        message = $Message
        failureReason = if ((-not $Success) -and (-not $Skipped)) { $Message } else { '' }
        remediationHints = @($RemediationHints)
    }
}

function Invoke-RecordedStep {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock
    )

    $started = [DateTimeOffset]::UtcNow
    $timer = [Diagnostics.Stopwatch]::StartNew()
    Write-HyperVJobStep $Title

    try {
        & $ScriptBlock
        $timer.Stop()
        [void]$script:StepResults.Add((New-StepResult -Id $Id -Title $Title -Success $true -Skipped $false -StartedAtUtc $started -Duration $timer.Elapsed))
    }
    catch {
        $timer.Stop()
        $hints = @(Get-StartRemediationHints -Message $_.Exception.Message -Plan $plan)
        [void]$script:StepResults.Add((New-StepResult -Id $Id -Title $Title -Success $false -Skipped $false -StartedAtUtc $started -Duration $timer.Elapsed -Message $_.Exception.Message -RemediationHints $hints))
        throw
    }
}

function Wait-VMRunning {
    param(
        [Parameter(Mandatory)][string]$VmName,
        [int]$TimeoutSeconds
    )

    $started = Get-Date
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $nextHeartbeat = (Get-Date).AddSeconds(10)
    $lastState = ''
    Write-HyperVJobStep "Waiting up to $TimeoutSeconds second(s) for VM '$VmName' to report Running."
    do {
        $vm = Get-VM -Name $VmName -ErrorAction Stop
        $state = $vm.State.ToString()
        if ($state -ne $lastState -or (Get-Date) -ge $nextHeartbeat) {
            $elapsed = [int]((Get-Date) - $started).TotalSeconds
            Write-HyperVJobStep "VM '$VmName' state is '$state' after ${elapsed}s."
            $lastState = $state
            $nextHeartbeat = (Get-Date).AddSeconds(10)
        }

        if ($state -eq 'Running') {
            return
        }

        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $deadline)

    throw "错误：VM '$VmName' 未在 $TimeoutSeconds 秒内进入 Running 状态；最后状态：$lastState。下一步：在 Hyper-V 管理器检查 VM 启动错误后重试。"
}

function Start-VMIfNeededAndWait {
    param(
        [Parameter(Mandatory)][string]$VmName,
        [int]$TimeoutSeconds
    )

    $vm = Get-VM -Name $VmName -ErrorAction Stop
    $state = $vm.State.ToString()
    if ($state -eq 'Running') {
        Write-HyperVJobStep "VM '$VmName' is already Running after checkpoint restore; skipping Start-VM."
        Wait-VMRunning -VmName $VmName -TimeoutSeconds $TimeoutSeconds
        return
    }

    if ($state -eq 'Paused') {
        Write-HyperVJobStep "VM '$VmName' is Paused after checkpoint restore; resuming VM."
        Resume-VM -Name $VmName -ErrorAction Stop
    }
    else {
        Write-HyperVJobStep "VM '$VmName' state is '$state' after checkpoint restore; starting VM."
        Start-VM -Name $VmName -ErrorAction Stop
    }

    Wait-VMRunning -VmName $VmName -TimeoutSeconds $TimeoutSeconds
}

function Get-OptionalPlanBoolean {
    param(
        [AllowNull()]$Object,
        [Parameter(Mandatory)][string]$Name,
        [bool]$DefaultValue
    )

    if ($null -eq $Object) {
        return $DefaultValue
    }

    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) {
        return $DefaultValue
    }

    try {
        return [System.Convert]::ToBoolean($property.Value)
    }
    catch {
        return $DefaultValue
    }
}

function Get-OptionalPlanString {
    param(
        [AllowNull()]$Object,
        [Parameter(Mandatory)][string]$Name,
        [AllowNull()][string]$DefaultValue
    )

    if ($null -eq $Object) {
        return $DefaultValue
    }

    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property -or [string]::IsNullOrWhiteSpace([string]$property.Value)) {
        return $DefaultValue
    }

    return [string]$property.Value
}

function Quote-NativeProcessArgument {
    param([AllowNull()][string]$Value)

    if ($null -eq $Value) {
        $Value = ''
    }

    if ($Value -notmatch '[\s"]') {
        return $Value
    }

    return '"' + ($Value -replace '"', '\"') + '"'
}

function Resolve-NativeCommandPath {
    param(
        [Parameter(Mandatory)][string]$Name,
        [string[]]$AdditionalCandidates = @()
    )

    $command = Get-Command -Name $Name -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $command -and -not [string]::IsNullOrWhiteSpace([string]$command.Source)) {
        return [string]$command.Source
    }

    foreach ($candidate in $AdditionalCandidates) {
        if (-not [string]::IsNullOrWhiteSpace($candidate) -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            return (Resolve-Path -LiteralPath $candidate).ProviderPath
        }
    }

    return ''
}

function Test-DesktopLauncherStillPresent {
    param(
        [AllowNull()][System.Diagnostics.Process]$Process,
        [Parameter(Mandatory)][string]$LauncherName
    )

    $processName = [System.IO.Path]::GetFileNameWithoutExtension($LauncherName)
    if ($null -ne $Process -and -not [string]::IsNullOrWhiteSpace($Process.ProcessName)) {
        $processName = $Process.ProcessName
    }

    Start-Sleep -Milliseconds 1200

    if ($null -ne $Process) {
        try {
            $Process.Refresh()
            if (-not $Process.HasExited) {
                return [pscustomobject]@{ Success = $true; Message = "$LauncherName is still running after launch check." }
            }
        }
        catch {
            return [pscustomobject]@{ Success = $false; Message = "$LauncherName launch verification failed: $($_.Exception.Message)" }
        }
    }

    $windowProcess = Get-Process -Name $processName -ErrorAction SilentlyContinue |
        Where-Object { $_.MainWindowHandle -ne [IntPtr]::Zero } |
        Select-Object -First 1
    if ($null -ne $windowProcess) {
        return [pscustomobject]@{ Success = $true; Message = "$LauncherName desktop window is present in process '$($windowProcess.ProcessName)' (PID $($windowProcess.Id))." }
    }

    if ($null -eq $Process) {
        return [pscustomobject]@{ Success = $false; Message = "$LauncherName did not return a process handle and no desktop window was observed." }
    }

    if ($Process.HasExited) {
        return [pscustomobject]@{ Success = $false; Message = "$LauncherName exited immediately with code $($Process.ExitCode); no durable interactive desktop window was observed." }
    }

    return [pscustomobject]@{ Success = $false; Message = "$LauncherName launch verification did not observe a running process or desktop window." }
}

function Get-VmRdpTarget {
    param([Parameter(Mandatory)][object]$Plan)

    $configured = Get-OptionalPlanString -Object $Plan.vm -Name 'rdpTarget' -DefaultValue ''
    if (-not [string]::IsNullOrWhiteSpace($configured)) {
        return $configured
    }

    try {
        $adapterCommand = Get-Command -Name 'Get-VMNetworkAdapter' -ErrorAction SilentlyContinue
        if ($null -eq $adapterCommand) {
            return ''
        }

        $addresses = @(Get-VMNetworkAdapter -VMName ([string]$Plan.vm.name) -ErrorAction Stop |
            ForEach-Object { $_.IPAddresses } |
            Where-Object {
                $text = [string]$_
                $text -match '^(\d{1,3}\.){3}\d{1,3}$' -and
                (-not $text.StartsWith('169.254.')) -and
                $text -ne '0.0.0.0'
            } |
            Select-Object -Unique)
        if ($addresses.Count -gt 0) {
            return [string]$addresses[0]
        }
    }
    catch {
        return ''
    }

    return ''
}

function Start-HyperVVmConnectDesktop {
    param(
        [Parameter(Mandatory)][string]$ServerName,
        [Parameter(Mandatory)][string]$VmName
    )

    $systemRoot = if ([string]::IsNullOrWhiteSpace($env:SystemRoot)) { 'C:\Windows' } else { $env:SystemRoot }
    $vmConnectPath = Resolve-NativeCommandPath -Name 'vmconnect.exe' -AdditionalCandidates @(
        (Join-Path $systemRoot 'System32\vmconnect.exe'),
        (Join-Path $systemRoot 'Sysnative\vmconnect.exe')
    )
    if ([string]::IsNullOrWhiteSpace($vmConnectPath)) {
        return [pscustomobject]@{ Success = $false; ProcessId = $null; Message = 'vmconnect.exe was not found.' }
    }

    try {
        $basicConsoleMessage = ''
        try {
            if ($ServerName -eq 'localhost' -or $ServerName -eq '.' -or $ServerName -ieq $env:COMPUTERNAME) {
                $vmHost = Get-VMHost -ErrorAction Stop
                if ([bool]$vmHost.EnableEnhancedSessionMode) {
                    Set-VMHost -EnableEnhancedSessionMode $false -ErrorAction Stop
                    $basicConsoleMessage = 'Host Enhanced Session Mode was enabled and was disabled before vmconnect.exe launch so VMConnect uses the basic console instead of prompting for enhanced-session credentials.'
                }
                else {
                    $basicConsoleMessage = 'Host Enhanced Session Mode was already disabled; VMConnect should use the basic console.'
                }
            }
        }
        catch {
            $basicConsoleMessage = "Could not disable Host Enhanced Session Mode before VMConnect launch: $($_.Exception.Message)"
        }

        $argumentList = @(
            (Quote-NativeProcessArgument -Value $ServerName),
            (Quote-NativeProcessArgument -Value $VmName)
        )
        $process = Start-Process -FilePath $vmConnectPath -ArgumentList $argumentList -PassThru -WindowStyle Normal -ErrorAction Stop
        $verification = Test-DesktopLauncherStillPresent -Process $process -LauncherName 'vmconnect.exe'
        if (-not [bool]$verification.Success) {
            return [pscustomobject]@{ Success = $false; ProcessId = $process.Id; Message = "vmconnect.exe launch did not produce a durable desktop window for VM '$VmName' on '$ServerName' (PID $($process.Id)): $($verification.Message) $basicConsoleMessage" }
        }

        return [pscustomobject]@{ Success = $true; ProcessId = $process.Id; Message = "vmconnect.exe started and remained open for VM '$VmName' on '$ServerName' (PID $($process.Id)). $basicConsoleMessage" }
    }
    catch {
        return [pscustomobject]@{ Success = $false; ProcessId = $null; Message = "vmconnect.exe launch failed: $($_.Exception.Message)" }
    }
}

function Start-RdpDesktop {
    param([Parameter(Mandatory)][string]$Target)

    $systemRoot = if ([string]::IsNullOrWhiteSpace($env:SystemRoot)) { 'C:\Windows' } else { $env:SystemRoot }
    $mstscPath = Resolve-NativeCommandPath -Name 'mstsc.exe' -AdditionalCandidates @(
        (Join-Path $systemRoot 'System32\mstsc.exe'),
        (Join-Path $systemRoot 'Sysnative\mstsc.exe')
    )
    if ([string]::IsNullOrWhiteSpace($mstscPath)) {
        return [pscustomobject]@{ Success = $false; ProcessId = $null; Message = 'mstsc.exe was not found.' }
    }

    try {
        $argumentList = @('/v:' + (Quote-NativeProcessArgument -Value $Target))
        $process = Start-Process -FilePath $mstscPath -ArgumentList $argumentList -PassThru -WindowStyle Normal -ErrorAction Stop
        $verification = Test-DesktopLauncherStillPresent -Process $process -LauncherName 'mstsc.exe'
        if (-not [bool]$verification.Success) {
            return [pscustomobject]@{ Success = $false; ProcessId = $process.Id; Message = "mstsc.exe launch did not produce a durable desktop window for RDP target '$Target' (PID $($process.Id)): $($verification.Message)" }
        }

        return [pscustomobject]@{ Success = $true; ProcessId = $process.Id; Message = "mstsc.exe started and remained open for RDP target '$Target' (PID $($process.Id))." }
    }
    catch {
        return [pscustomobject]@{ Success = $false; ProcessId = $null; Message = "mstsc.exe launch failed for '$Target': $($_.Exception.Message)" }
    }
}

function Open-HyperVVmConsole {
    param([Parameter(Mandatory)][object]$Plan)

    $enabled = Get-OptionalPlanBoolean -Object $Plan.vm -Name 'openVmConsoleOnLiveStart' -DefaultValue (Get-OptionalPlanBoolean -Object $Plan.vm -Name 'openConsoleOnLiveStart' -DefaultValue $true)
    $disabledByNoOpenVmConsole = Get-OptionalPlanBoolean -Object $Plan.vm -Name 'consoleDisabledByNoOpenVmConsole' -DefaultValue $false
    $required = $enabled -and (-not $disabledByNoOpenVmConsole)
    if (-not $enabled) {
        if (-not $disabledByNoOpenVmConsole) {
            throw 'Live analysis would run headless because the plan disabled VM desktop opening, but headless live execution is allowed only when the operator supplies -NoOpenVmConsole explicitly.'
        }

        $script:VmConsoleOpenMessage = 'VM console auto-open disabled by -NoOpenVmConsole.'
        Write-HyperVJobStep 'Hyper-V VM console auto-open disabled by -NoOpenVmConsole; continuing headless by explicit operator request. / 仅因显式 -NoOpenVmConsole 才允许不打开 VM 桌面。'
        return
    }

    $script:VmConsoleOpenAttempted = $true
    $serverName = Get-OptionalPlanString -Object $Plan.vm -Name 'consoleServerName' -DefaultValue 'localhost'
    $vmName = [string]$Plan.vm.name
    $messages = New-Object System.Collections.Generic.List[string]

    $vmConnectResult = Start-HyperVVmConnectDesktop -ServerName $serverName -VmName $vmName
    [void]$messages.Add([string]$vmConnectResult.Message)
    if ([bool]$vmConnectResult.Success) {
        $script:VmConsoleOpenSucceeded = $true
        $script:VmConsoleOpenStrategy = 'HyperV.VMConnect'
        $script:VmConsoleProcessId = $vmConnectResult.ProcessId
        $script:VmConsoleOpenMessage = [string]$vmConnectResult.Message
        Write-HyperVJobStep "已打开 Hyper-V VM 桌面/控制台：$vmName；可手动交互观察样本。 / Opened Hyper-V VM console via vmconnect.exe."
        return
    }

    $rdpEnabled = Get-OptionalPlanBoolean -Object $Plan.vm -Name 'rdpFallbackEnabled' -DefaultValue $true
    if ($rdpEnabled) {
        $rdpTarget = Get-VmRdpTarget -Plan $Plan
        $script:VmConsoleRdpTarget = $rdpTarget
        if (-not [string]::IsNullOrWhiteSpace($rdpTarget)) {
            $rdpResult = Start-RdpDesktop -Target $rdpTarget
            [void]$messages.Add([string]$rdpResult.Message)
            if ([bool]$rdpResult.Success) {
                $script:VmConsoleOpenSucceeded = $true
                $script:VmConsoleOpenStrategy = 'RDP.Mstsc'
                $script:VmConsoleProcessId = $rdpResult.ProcessId
                $script:VmConsoleOpenMessage = [string]$rdpResult.Message
                Write-HyperVJobStep "已通过 mstsc/RDP 打开 VM 桌面：$rdpTarget；可手动交互观察样本。 / Opened VM desktop via mstsc.exe."
                return
            }
        }
        else {
            [void]$messages.Add('RDP fallback skipped: no hyperV.rdpTarget configured and no VM IPv4 address was discoverable from Get-VMNetworkAdapter.')
        }
    }
    else {
        [void]$messages.Add('RDP fallback disabled by plan.')
    }

    $script:VmConsoleOpenSucceeded = $false
    $script:VmConsoleOpenMessage = ($messages.ToArray() -join ' | ')
    $manualHints = @(
        "vmconnect.exe $serverName '$vmName'",
        "mstsc.exe /v:<hyperV.rdpTarget 或 VM IP/反代地址>"
    )
    $message = if ($required) {
        "错误：Live 分析被配置为必须打开可交互 VM 桌面，但 VMConnect/RDP 都未成功启动；尚未启动样本。下一步：安装 Hyper-V 管理工具/确认 vmconnect.exe 可用，或在 config hyperV.rdpTarget 配置 RDP/反代地址，或确认来宾 RDP 已启用。尝试详情：$script:VmConsoleOpenMessage。手动命令：$($manualHints -join ' ; ')"
    }
    else {
        "自动打开 VM 桌面失败；只有显式 -NoOpenVmConsole/consoleDisabledByNoOpenVmConsole 才允许 headless 继续。下一步：如需交互观察，可手动安装 Hyper-V 管理工具/运行 vmconnect.exe，或配置 hyperV.rdpTarget 后重试。尝试详情：$script:VmConsoleOpenMessage。手动命令：$($manualHints -join ' ; ')"
    }
    if ($required) {
        throw $message
    }

    Write-Warning ("中文提示：" + $message)
}

function Get-PowerShellDirectDiagnosticHint {
    param(
        [AllowNull()][string]$ErrorMessage,
        [Parameter(Mandatory)][string]$VmName,
        [Parameter(Mandatory)][string]$UserName,
        [AllowNull()][string]$SecretName
    )

    $text = [string]$ErrorMessage
    if ($text -match '(?i)access is denied|logon failure|user name or password|credentials|身份验证|拒绝访问|登录失败') {
        return "凭据诊断：请确认来宾用户 '$UserName' 存在、secret '$SecretName' 与 VM 内密码一致，且 runner 进程可见该环境变量；secret 值未打印。"
    }

    if ($text -match '(?i)cannot find|not found|Get-VM|Hyper-V') {
        return "VM 诊断：请确认 VM '$VmName' 存在且 Hyper-V PowerShell 工具/权限可用。"
    }

    if ($text -match '(?i)not running|state|boot|服务|service') {
        return "VM 诊断：请确认 VM '$VmName' 已进入 Running，guest OS 已完成启动，且 Hyper-V PowerShell Direct 服务可用。"
    }

    return "PowerShell Direct 诊断：请确认 VM '$VmName' 正在运行、来宾凭据正确、集成服务健康；必要时先运行只读 Test-HyperVReadiness。"
}

function Wait-PowerShellDirect {
    param(
        [Parameter(Mandatory)][string]$VmName,
        [Parameter(Mandatory)][pscredential]$Credential,
        [int]$TimeoutSeconds,
        [AllowNull()][string]$SecretName = ''
    )

    $started = Get-Date
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $nextHeartbeat = (Get-Date).AddSeconds(15)
    $lastError = ''
    $lastVmState = ''
    $attempt = 0
    Write-HyperVJobStep "正在等待 VM '$VmName' 的 PowerShell Direct，最长 $TimeoutSeconds 秒。 / Waiting for PowerShell Direct."
    do {
        $attempt++
        try {
            Invoke-Command -VMName $VmName -Credential $Credential -ScriptBlock {
                [pscustomobject][ordered]@{
                    ComputerName = $env:COMPUTERNAME
                    UserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                }
            } -ErrorAction Stop | Out-Null
            $elapsed = [int]((Get-Date) - $started).TotalSeconds
            Write-HyperVJobStep "VM '$VmName' 的 PowerShell Direct 已就绪，耗时 ${elapsed}s，尝试 $attempt 次。 / PowerShell Direct is ready."
            return
        }
        catch {
            $lastError = $_.Exception.Message
            if ((Get-Date) -ge $nextHeartbeat) {
                $elapsed = [int]((Get-Date) - $started).TotalSeconds
                try {
                    $lastVmState = (Get-VM -Name $VmName -ErrorAction Stop).State.ToString()
                }
                catch {
                    $lastVmState = 'unknown'
                }

                $hint = Get-PowerShellDirectDiagnosticHint -ErrorMessage $lastError -VmName $VmName -UserName $Credential.UserName -SecretName $SecretName
                Write-HyperVJobStep "PowerShell Direct 在 ${elapsed}s、$attempt 次尝试后仍未就绪；VM 状态：$lastVmState。$hint 英文详情：$lastError"
                $nextHeartbeat = (Get-Date).AddSeconds(15)
            }

            Start-Sleep -Seconds 3
        }
    } while ((Get-Date) -lt $deadline)

    $finalHint = Get-PowerShellDirectDiagnosticHint -ErrorMessage $lastError -VmName $VmName -UserName $Credential.UserName -SecretName $SecretName
    throw "错误：PowerShell Direct 未在 $TimeoutSeconds 秒内就绪，尝试 $attempt 次，最后 VM 状态：$lastVmState。$finalHint 英文详情：$lastError"
}

function Copy-GuestPayload {
    param(
        [Parameter(Mandatory)][object]$Plan,
        [Parameter(Mandatory)][pscredential]$Credential
    )

    $session = $null
    $driverEnabled = ConvertTo-BooleanValue $Plan.driver.enabled
    $requiredGuestPaths = @([string]$Plan.guest.agentPath)
    $guestDirectories = @(
        [string]$Plan.guest.agentDirectory,
        [string]$Plan.guest.collectorDirectory,
        [string]$Plan.guest.driverDirectory,
        [string]$Plan.guest.incomingDirectory,
        [string]$Plan.guest.outputRoot
    )

    if ($driverEnabled) {
        $requiredGuestPaths += [string]$Plan.driver.r0CollectorPathInGuest
    }

    if (-not [string]::IsNullOrWhiteSpace([string]$Plan.driver.hostDriverPath)) {
        $requiredGuestPaths += [string]$Plan.driver.driverPathInGuest
    }

    try {
        $session = New-PSSession -VMName $Plan.vm.name -Credential $Credential
        Invoke-Command -Session $session -ScriptBlock {
            param([string[]]$Directories)
            foreach ($directory in $Directories) {
                New-Item -ItemType Directory -Force -Path $directory | Out-Null
            }
        } -ArgumentList (,$guestDirectories)

        $agentSource = Join-Path $Plan.host.guestPayloadRoot 'agent\*'
        Copy-Item -ToSession $session -Path $agentSource -Destination $Plan.guest.agentDirectory -Recurse -Force

        if ($driverEnabled -and
            -not (ConvertTo-BooleanValue $Plan.driver.useMockCollector) -and
            [string]::IsNullOrWhiteSpace([string]$Plan.driver.hostDriverPath)) {
            Write-Warning '中文提示：已启用 R0 live driver collection，但 plan.driver.hostDriverPath 为空；不会暂存 driver .sys，R0Collector 可能以 deviceUnavailable/win32Error=2 失败。下一步：配置 -DriverHostPath 或启用 driver.useMockCollector=true。'
        }

        if ($driverEnabled) {
            $collectorSource = Join-Path $Plan.host.guestPayloadRoot 'r0collector\*'
            Copy-Item -ToSession $session -Path $collectorSource -Destination $Plan.guest.collectorDirectory -Recurse -Force
        }

        if (-not [string]::IsNullOrWhiteSpace([string]$Plan.driver.hostDriverPath)) {
            Copy-Item -ToSession $session -Path $Plan.driver.hostDriverPath -Destination $Plan.driver.driverPathInGuest -Force
        }

        Invoke-Command -Session $session -ScriptBlock {
            param([string[]]$Paths)
            foreach ($path in $Paths) {
                if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
                    throw "错误：缺少必需 guest payload 文件：$path。下一步：运行 .\scripts\Prepare-GuestPayload.ps1 -SelfContained 后重试。"
                }
            }
        } -ArgumentList (,$requiredGuestPaths)
    }
    finally {
        if ($null -ne $session) {
            try {
                Remove-PSSession $session -ErrorAction Stop
            }
            catch {
                Write-Warning "中文提示：payload staging 后 PowerShell Direct session 清理失败；主步骤状态已保留。英文详情：$($_.Exception.Message)"
            }
        }
    }
}

function Copy-SampleIntoGuest {
    param([Parameter(Mandatory)][object]$Plan)

    Copy-VMFile `
        -VMName $Plan.vm.name `
        -SourcePath $Plan.sample.hostPath `
        -DestinationPath $Plan.sample.guestPath `
        -FileSource Host `
        -CreateFullPath `
        -Force
}

function Initialize-GuestOutputDirectory {
    param(
        [Parameter(Mandatory)][object]$Plan,
        [Parameter(Mandatory)][pscredential]$Credential
    )

    $eventsPath = ([string]$Plan.guest.outputDirectory).TrimEnd('\', '/') + '\events.json'
    $agentStdoutPath = ([string]$Plan.guest.outputDirectory).TrimEnd('\', '/') + '\agent.stdout.log'
    $agentStderrPath = ([string]$Plan.guest.outputDirectory).TrimEnd('\', '/') + '\agent.stderr.log'
    $stalePaths = @(
        [string]$Plan.guest.agentPidPath,
        [string]$Plan.guest.agentExitPath,
        [string]$Plan.driver.eventJsonLinesPath,
        [string]$Plan.guest.agentSummaryPath,
        $agentStdoutPath,
        $agentStderrPath,
        $eventsPath
    )

    Invoke-Command -VMName $Plan.vm.name -Credential $Credential -ScriptBlock {
        param([string]$OutputDirectory, [string[]]$StalePaths)
        New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
        foreach ($path in $StalePaths) {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        }
    } -ArgumentList $Plan.guest.outputDirectory, (,$stalePaths)
}

function Install-GuestDriverService {
    param(
        [Parameter(Mandatory)][object]$Plan,
        [Parameter(Mandatory)][pscredential]$Credential
    )

    if (-not (ConvertTo-BooleanValue $Plan.driver.enabled) -or
        [string]::IsNullOrWhiteSpace([string]$Plan.driver.hostDriverPath)) {
        Write-HyperVJobStep 'Driver host path is not configured; skipping guest kernel service install.'
        return
    }

    Invoke-Command -VMName $Plan.vm.name -Credential $Credential -ScriptBlock {
        param(
            [string]$ServiceName,
            [string]$DriverPath
        )

        if ([string]::IsNullOrWhiteSpace($ServiceName)) {
            throw '错误：driver service name 为空。下一步：检查本机 sandbox 配置中的 driver.serviceName。'
        }

        if (-not (Test-Path -LiteralPath $DriverPath -PathType Leaf)) {
            throw "错误：driver .sys 未暂存到来宾路径：$DriverPath。下一步：确认 driver.hostDriverPath 存在并重新 staging payload。"
        }

        $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            & sc.exe stop $ServiceName | Out-Null
            Start-Sleep -Milliseconds 500
            & sc.exe delete $ServiceName | Out-Null
            Start-Sleep -Milliseconds 500
        }

        $createOutput = @(& sc.exe create $ServiceName type= kernel start= demand binPath= $DriverPath 2>&1)
        if ($LASTEXITCODE -ne 0) {
            throw "错误：sc.exe create $ServiceName 失败，退出码 $LASTEXITCODE。下一步：确认管理员权限、driver 签名信任和路径。英文输出：$($createOutput -join ' ')"
        }

        $startOutput = @(& sc.exe start $ServiceName 2>&1)
        $startExitCode = $LASTEXITCODE
        if ($startExitCode -ne 0 -and $startExitCode -ne 1056) {
            throw "错误：sc.exe start $ServiceName 失败，退出码 $startExitCode。下一步：确认 test-signing、证书信任、driver 架构和服务类型。英文输出：$($startOutput -join ' ')"
        }

        [pscustomobject][ordered]@{
            ServiceName = $ServiceName
            DriverPath = $DriverPath
            Started = $true
            StartExitCode = $startExitCode
        }
    } -ArgumentList ([string]$Plan.driver.serviceName), ([string]$Plan.driver.driverPathInGuest) | Out-Null
}

function Start-GuestAgent {
    param(
        [Parameter(Mandatory)][object]$Plan,
        [Parameter(Mandatory)][pscredential]$Credential
    )

    $agentStdoutPath = ([string]$Plan.guest.outputDirectory).TrimEnd('\', '/') + '\agent.stdout.log'
    $agentStderrPath = ([string]$Plan.guest.outputDirectory).TrimEnd('\', '/') + '\agent.stderr.log'
    $arguments = New-Object System.Collections.Generic.List[string]
    [void]$arguments.Add('--sample')
    [void]$arguments.Add((Quote-PowerShellString $Plan.sample.guestPath))
    [void]$arguments.Add('--out')
    [void]$arguments.Add((Quote-PowerShellString $Plan.guest.outputDirectory))
    [void]$arguments.Add('--duration')
    [void]$arguments.Add([string]$Plan.job.durationSeconds)

    if (ConvertTo-BooleanValue $Plan.driver.enabled) {
        [void]$arguments.Add('--driver-events')
        [void]$arguments.Add((Quote-PowerShellString $Plan.driver.eventJsonLinesPath))
        [void]$arguments.Add('--r0collector')
        [void]$arguments.Add((Quote-PowerShellString $Plan.driver.r0CollectorPathInGuest))
        [void]$arguments.Add('--driver-device')
        [void]$arguments.Add((Quote-PowerShellString $Plan.driver.devicePath))

        if (ConvertTo-BooleanValue $Plan.driver.useMockCollector) {
            [void]$arguments.Add('--r0-mock')
        }
    }

    $launchLine = '& ' + (Quote-PowerShellString $Plan.guest.agentPath) + ' ' + (($arguments.ToArray()) -join ' ')
    $script:GuestAgentArguments = @($arguments.ToArray())
    $script:GuestAgentCommandLine = $launchLine
    $script:R0CollectorMode = if (-not (ConvertTo-BooleanValue $Plan.driver.enabled)) {
        'Disabled'
    }
    elseif (ConvertTo-BooleanValue $Plan.driver.useMockCollector) {
        'Mock'
    }
    else {
        'Live'
    }

    if (ConvertTo-BooleanValue $Plan.driver.enabled) {
        $collectorArguments = New-Object System.Collections.Generic.List[string]
        [void]$collectorArguments.Add('--device')
        [void]$collectorArguments.Add((Quote-PowerShellString $Plan.driver.devicePath))
        [void]$collectorArguments.Add('--output')
        [void]$collectorArguments.Add((Quote-PowerShellString $Plan.driver.eventJsonLinesPath))
        [void]$collectorArguments.Add('--duration')
        [void]$collectorArguments.Add([string]$Plan.job.durationSeconds)
        if (ConvertTo-BooleanValue $Plan.driver.useMockCollector) {
            [void]$collectorArguments.Add('--mock')
        }

        $script:R0CollectorArguments = @($collectorArguments.ToArray())
        $script:R0CollectorCommandLine = '& ' + (Quote-PowerShellString $Plan.driver.r0CollectorPathInGuest) + ' ' + (($collectorArguments.ToArray()) -join ' ')
    }

    $agentCommand = @(
        $launchLine,
        '$exitCode = if ($global:LASTEXITCODE -is [int]) { $global:LASTEXITCODE } else { 0 }',
        ('Set-Content -Path {0} -Value $exitCode -Encoding ASCII' -f (Quote-PowerShellString $Plan.guest.agentExitPath)),
        'exit $exitCode'
    ) -join '; '

    $launch = Invoke-Command -VMName $Plan.vm.name -Credential $Credential -ScriptBlock {
        param(
            [string]$GuestRoot,
            [string]$AgentCommand,
            [string]$PidPath,
            [string]$StdoutPath,
            [string]$StderrPath
        )

        $process = Start-Process `
            -FilePath 'powershell.exe' `
            -ArgumentList @('-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', $AgentCommand) `
            -WorkingDirectory $GuestRoot `
            -RedirectStandardOutput $StdoutPath `
            -RedirectStandardError $StderrPath `
            -PassThru
        $process.Id | Set-Content -Path $PidPath -Encoding ASCII
        [pscustomobject][ordered]@{
            ProcessId = $process.Id
            PidPath = $PidPath
            StdoutPath = $StdoutPath
            StderrPath = $StderrPath
        }
    } -ArgumentList $Plan.guest.workingDirectory, $agentCommand, $Plan.guest.agentPidPath, $agentStdoutPath, $agentStderrPath

    $script:GuestAgentProcessId = @($launch | Select-Object -First 1)[0].ProcessId
}

function Assert-LivePreconditions {
    param([Parameter(Mandatory)][object]$Plan)

    if (-not (Test-IsAdministrator)) {
        throw '错误：Live Hyper-V E2E start 需要管理员权限；尚未执行 VM 命令。下一步：以管理员身份运行，或使用 -PlanOnly/-WhatIf。'
    }

    Assert-CommandAvailable -Names @(
        'Get-VM',
        'Get-VMHost',
        'Get-VMSnapshot',
        'Get-VMIntegrationService',
        'Restore-VMSnapshot',
        'Enable-VMIntegrationService',
        'Set-VMHost',
        'Start-VM',
        'Resume-VM',
        'Stop-VM',
        'Copy-VMFile',
        'Invoke-Command',
        'New-PSSession',
        'Copy-Item'
    )

    Assert-VmCheckpointForLive -Plan $Plan
    Assert-GuestServiceForLive -Plan $Plan
    Assert-DirectoryForLive -Name 'Guest payload root' -Path $Plan.host.guestPayloadRoot
    Assert-DirectoryForLive -Name 'Guest Agent payload directory' -Path (Join-Path $Plan.host.guestPayloadRoot 'agent')
    Assert-FileForLive -Name 'Sample file' -Path $Plan.sample.hostPath
    Assert-FileForLive -Name 'Guest Agent payload' -Path $Plan.host.agentPayloadPath
    if (-not [string]::IsNullOrWhiteSpace([string]$Plan.host.payloadManifestPath) -and
        -not (Test-Path -LiteralPath $Plan.host.payloadManifestPath -PathType Leaf)) {
        Write-HyperVJobStep "未找到 payload manifest：$($Plan.host.payloadManifestPath)。将继续，因为 Live 只需要已暂存的二进制文件。 / Payload manifest is absent; continuing."
    }

    if (ConvertTo-BooleanValue $Plan.driver.enabled) {
        Assert-DirectoryForLive -Name 'R0Collector payload directory' -Path (Join-Path $Plan.host.guestPayloadRoot 'r0collector')
        Assert-FileForLive -Name 'R0Collector payload' -Path $Plan.host.r0CollectorPayloadPath
        if (-not (ConvertTo-BooleanValue $Plan.driver.useMockCollector) -and
            [string]::IsNullOrWhiteSpace([string]$Plan.driver.hostDriverPath)) {
            throw '错误：已启用真实 R0 driver collection，但 driver.hostDriverPath 为空；已在 VM mutation 前中止。下一步：配置已构建/测试签名的 KSword.Sandbox.Driver.sys，或设置 driver.useMockCollector=true 做 mock/plumbing 测试，或禁用 driver.enabled。'
        }

        if (-not [string]::IsNullOrWhiteSpace([string]$Plan.driver.hostDriverPath)) {
            Assert-FileForLive -Name 'Host R0 driver' -Path $Plan.driver.hostDriverPath
        }
    }
}

function Invoke-StartFailureCleanup {
    param([Parameter(Mandatory)][object]$Plan)

    if (-not $script:VmMutationStarted) {
        return
    }

    Write-HyperVJobStep 'Start 阶段在 VM mutation 后失败；正在尝试 stop/restore 清理。 / Start phase failed after VM mutation; attempting stop/restore cleanup.'

    try {
        if ($script:Cmdlet.ShouldProcess($Plan.vm.name, 'Start 阶段失败后停止 VM / Stop VM after failed start phase')) {
            Stop-VM -Name $Plan.vm.name -TurnOff -Force -ErrorAction SilentlyContinue
        }
    }
    catch {
        [void]$script:CleanupErrors.Add("Start 阶段失败后 Stop-VM 清理失败。英文详情：$($_.Exception.Message)")
    }

    try {
        if ($script:Cmdlet.ShouldProcess($Plan.vm.name, "Start 阶段失败后还原 checkpoint '$($Plan.vm.cleanCheckpointName)' / Restore checkpoint after failed start phase")) {
            Restore-VMSnapshot -VMName $Plan.vm.name -Name $Plan.vm.cleanCheckpointName -Confirm:$false
        }
    }
    catch {
        [void]$script:CleanupErrors.Add("Start 阶段失败后 Restore-VMSnapshot 清理失败。英文详情：$($_.Exception.Message)")
    }
}

function Save-StartResult {
    param(
        [Parameter(Mandatory)][object]$Plan,
        [bool]$Success,
        [string]$Message = ''
    )

    $jobRoot = [string]$Plan.host.jobRoot
    New-Item -ItemType Directory -Path $jobRoot -Force -WhatIf:$false | Out-Null
    $resultPath = Join-Path $jobRoot 'hyperv-e2e-start-result.json'
    $remediationHints = if ($Success) { @() } else { @(Get-StartRemediationHints -Message $Message -Plan $Plan) }
    $result = [ordered]@{
        contractVersion = 1
        phase = 'start'
        planPath = (Resolve-Path -LiteralPath $PlanPath).Path
        jobId = $Plan.job.jobId
        targetVmName = $Plan.vm.name
        success = $Success
        state = if ($Success) { 'completed' } else { 'failed' }
        message = $Message
        failureReason = if ($Success) { '' } else { $Message }
        remediationHints = @($remediationHints)
        guestAgentProcessId = $script:GuestAgentProcessId
        guestAgentCommandLine = $script:GuestAgentCommandLine
        guestAgentArguments = @($script:GuestAgentArguments)
        r0CollectorMode = $script:R0CollectorMode
        r0CollectorCommandLine = $script:R0CollectorCommandLine
        r0CollectorArguments = @($script:R0CollectorArguments)
        driverEventsPath = $Plan.driver.eventJsonLinesPath
        diagnostics = [ordered]@{
            vmName = $Plan.vm.name
            cleanCheckpointName = $Plan.vm.cleanCheckpointName
            openVmConsoleOnLiveStart = Get-OptionalPlanBoolean -Object $Plan.vm -Name 'openVmConsoleOnLiveStart' -DefaultValue (Get-OptionalPlanBoolean -Object $Plan.vm -Name 'openConsoleOnLiveStart' -DefaultValue $true)
            openVmConnectOnLiveStart = Get-OptionalPlanBoolean -Object $Plan.vm -Name 'openVmConnectOnLiveStart' -DefaultValue (Get-OptionalPlanBoolean -Object $Plan.vm -Name 'openConsoleOnLiveStart' -DefaultValue $true)
            openConsoleOnLiveStart = Get-OptionalPlanBoolean -Object $Plan.vm -Name 'openConsoleOnLiveStart' -DefaultValue $true
            consoleDisabledByNoOpenVmConsole = Get-OptionalPlanBoolean -Object $Plan.vm -Name 'consoleDisabledByNoOpenVmConsole' -DefaultValue $false
            consoleFailureBlocksHeadless = (Get-OptionalPlanBoolean -Object $Plan.vm -Name 'openVmConsoleOnLiveStart' -DefaultValue (Get-OptionalPlanBoolean -Object $Plan.vm -Name 'openConsoleOnLiveStart' -DefaultValue $true)) -and (-not (Get-OptionalPlanBoolean -Object $Plan.vm -Name 'consoleDisabledByNoOpenVmConsole' -DefaultValue $false))
            consoleServerName = Get-OptionalPlanString -Object $Plan.vm -Name 'consoleServerName' -DefaultValue 'localhost'
            consoleOpenAttempted = $script:VmConsoleOpenAttempted
            consoleOpenSucceeded = $script:VmConsoleOpenSucceeded
            consoleOpenMessage = $script:VmConsoleOpenMessage
            consoleProcessId = $script:VmConsoleProcessId
            consoleOpenStrategy = $script:VmConsoleOpenStrategy
            consoleRdpTarget = $script:VmConsoleRdpTarget
            guestUserName = $Plan.guest.userName
            guestPasswordSecretName = $Plan.guest.passwordSecretName
            secretValuePrinted = $false
            guestServiceInterfaceComponentId = $script:GuestServiceInterfaceComponentId
            powershellDirectTimeoutSeconds = $Plan.timeouts.guestReadySeconds
            startupTimeoutSeconds = $Plan.timeouts.startupSeconds
        }
        payload = [ordered]@{
            root = $Plan.host.guestPayloadRoot
            manifestPath = $Plan.host.payloadManifestPath
            agentPayloadPath = $Plan.host.agentPayloadPath
            r0CollectorPayloadPath = $Plan.host.r0CollectorPayloadPath
        }
        completedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
        cleanupErrors = @($script:CleanupErrors.ToArray())
        steps = @($script:StepResults.ToArray())
    }

    $result | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $resultPath -Encoding UTF8 -WhatIf:$false
    Write-HyperVJobStep "Start result written: $resultPath"
}

function ConvertTo-StartSkeletonDataValue {
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

function Test-StartSkeletonEventsPresent {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $false
    }

    try {
        $content = (Get-Content -LiteralPath $Path -Raw).Trim()
        if ([string]::IsNullOrWhiteSpace($content) -or $content -eq '[]') {
            return $false
        }

        try {
            $parsed = $content | ConvertFrom-Json -ErrorAction Stop
            return @($parsed).Count -gt 0
        }
        catch {
            Write-Warning "中文提示：现有 events.json 无法解析，将由 start failure skeleton 覆盖以保证可导入。英文详情：$($_.Exception.Message)"
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
        [Parameter(Mandatory)][string]$FailureMessage
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
        Set-Content -LiteralPath $agentStderrPath -Value (ConvertTo-StartSkeletonDataValue $FailureMessage) -Encoding UTF8 -WhatIf:$false
    }

    $eventsAlreadyPresent = Test-StartSkeletonEventsPresent -Path $eventsPath
    $now = [DateTimeOffset]::UtcNow
    if (-not $eventsAlreadyPresent) {
        $events = @(
            [ordered]@{
                eventType   = 'hyperv.e2e.failure_skeleton'
                timestamp   = $now.ToString('O')
                source      = 'host'
                processName = 'Start-SandboxHyperVJob.ps1'
                processId   = $PID
                path        = [string]$Plan.vm.name
                commandLine = 'Start phase failed before complete guest events were collected.'
                data        = [ordered]@{
                    jobId                = ConvertTo-StartSkeletonDataValue $Plan.job.jobId
                    vmName               = ConvertTo-StartSkeletonDataValue $Plan.vm.name
                    checkpointName       = ConvertTo-StartSkeletonDataValue $Plan.vm.cleanCheckpointName
                    guestUserName        = ConvertTo-StartSkeletonDataValue $Plan.guest.userName
                    secretName           = ConvertTo-StartSkeletonDataValue $Plan.guest.passwordSecretName
                    failureReason        = ConvertTo-StartSkeletonDataValue $FailureMessage
                    runbookExecutionPath = ConvertTo-StartSkeletonDataValue $Plan.host.runbookExecutionPath
                    generatedBy          = 'Start-SandboxHyperVJob.ps1'
                    importable           = 'True'
                    skeleton             = 'True'
                    secretValuePrinted   = 'False'
                }
            }
        )
        ConvertTo-Json -InputObject @($events) -Depth 8 | Set-Content -LiteralPath $eventsPath -Encoding UTF8 -WhatIf:$false
    }

    $metadata = [ordered]@{
        contractVersion    = 1
        kind               = 'KSwordSandbox.GuestOutputSkeleton'
        generatedAtUtc     = $now.ToString('O')
        generatedBy        = 'Start-SandboxHyperVJob.ps1'
        importable         = $true
        preservedRealEvents = $eventsAlreadyPresent
        jobId              = [string]$Plan.job.jobId
        targetVmName       = [string]$Plan.vm.name
        failureReason      = $FailureMessage
        secretValuePrinted = $false
        paths              = [ordered]@{
            guestOutputDirectory = $guestOutputDirectory
            eventsJsonPath       = $eventsPath
            agentPidPath         = $agentPidPath
            agentExitPath        = $agentExitPath
            agentStdoutPath      = $agentStdoutPath
            agentStderrPath      = $agentStderrPath
            runbookExecutionPath = [string]$Plan.host.runbookExecutionPath
        }
        note               = '该 skeleton 仅用于恢复/导入 start 阶段失败诊断，不代表 Guest Agent 已成功运行。'
    }
    $metadata | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $metadataPath -Encoding UTF8 -WhatIf:$false
    Write-HyperVJobStep "Importable guest output skeleton ready: $eventsPath"
}

$plan = Read-HyperVE2EPlan -Path $PlanPath

if ((-not [bool]$Live) -or [bool]$WhatIfPreference) {
    $mode = if ($WhatIfPreference) { 'WhatIf' } else { 'PlanOnly' }
    Write-HyperVJobStep "Safe $mode mode: start phase would restore checkpoint, start VM, stage payload/sample, and start Guest Agent. No VM command was executed."
    foreach ($step in @($plan.steps | Where-Object { $_.phase -eq 'start' })) {
        Write-HyperVJobStep ("PLAN {0}: {1}" -f $step.id, $step.title)
        [void]$script:StepResults.Add((New-StepResult `
                    -Id ([string]$step.id) `
                    -Title ([string]$step.title) `
                    -Success $true `
                    -Skipped $true `
                    -StartedAtUtc ([DateTimeOffset]::UtcNow) `
                    -Duration ([TimeSpan]::Zero) `
                    -Message "Safe $mode mode. No VM command was executed."))
    }
    Save-StartResult -Plan $plan -Success $true -Message "Safe $mode mode. No VM command was executed."
    exit 0
}

try {
    Assert-LivePreconditions -Plan $plan
    $credential = Get-GuestCredential -UserName $plan.guest.userName -SecretName $plan.guest.passwordSecretName

    Invoke-RecordedStep -Id 'stop-before-restore' -Title 'Stop golden VM before restoring checkpoint' -ScriptBlock {
        if ($script:Cmdlet.ShouldProcess($plan.vm.name, 'Stop VM before checkpoint restore')) {
            $script:VmMutationStarted = $true
            Stop-VM -Name $plan.vm.name -TurnOff -Force -ErrorAction SilentlyContinue
        }
    }

    Invoke-RecordedStep -Id 'restore-checkpoint' -Title 'Restore clean checkpoint' -ScriptBlock {
        if ($script:Cmdlet.ShouldProcess($plan.vm.name, "Restore checkpoint '$($plan.vm.cleanCheckpointName)'")) {
            $script:VmMutationStarted = $true
            Restore-VMSnapshot -VMName $plan.vm.name -Name $plan.vm.cleanCheckpointName -Confirm:$false
        }
    }

    Invoke-RecordedStep -Id 'enable-guest-service' -Title 'Enable Guest Service Interface' -ScriptBlock {
        if ($script:Cmdlet.ShouldProcess($plan.vm.name, 'Enable Guest Service Interface')) {
            $script:VmMutationStarted = $true
            $guestService = Get-GuestServiceInterface -VmName $plan.vm.name
            Enable-VMIntegrationService -VMIntegrationService $guestService
        }
    }

    Invoke-RecordedStep -Id 'start-vm' -Title 'Start VM and wait for Running state' -ScriptBlock {
        if ($script:Cmdlet.ShouldProcess($plan.vm.name, 'Start VM')) {
            $script:VmMutationStarted = $true
            Start-VMIfNeededAndWait -VmName $plan.vm.name -TimeoutSeconds ([int]$plan.timeouts.startupSeconds)
        }
    }

    Invoke-RecordedStep -Id 'open-vm-console' -Title 'Open Hyper-V VM console/desktop for operator interaction' -ScriptBlock {
        Open-HyperVVmConsole -Plan $plan
    }

    Invoke-RecordedStep -Id 'wait-powershell-direct' -Title 'Wait for PowerShell Direct readiness' -ScriptBlock {
        Wait-PowerShellDirect -VmName $plan.vm.name -Credential $credential -TimeoutSeconds ([int]$plan.timeouts.guestReadySeconds) -SecretName ([string]$plan.guest.passwordSecretName)
    }

    Invoke-RecordedStep -Id 'stage-guest-payload' -Title 'Stage Guest Agent and R0Collector payload into guest' -ScriptBlock {
        if ($script:Cmdlet.ShouldProcess($plan.vm.name, 'Copy guest payload into VM')) {
            $script:VmMutationStarted = $true
            Copy-GuestPayload -Plan $plan -Credential $credential
        }
    }

    Invoke-RecordedStep -Id 'copy-sample' -Title 'Copy sample into guest' -ScriptBlock {
        if ($script:Cmdlet.ShouldProcess($plan.vm.name, 'Copy sample into VM')) {
            $script:VmMutationStarted = $true
            Copy-SampleIntoGuest -Plan $plan
        }
    }

    Invoke-RecordedStep -Id 'prepare-guest-output' -Title 'Prepare guest output directory' -ScriptBlock {
        if ($script:Cmdlet.ShouldProcess($plan.vm.name, 'Create clean guest output directory')) {
            $script:VmMutationStarted = $true
            Initialize-GuestOutputDirectory -Plan $plan -Credential $credential
        }
    }

    if (-not [string]::IsNullOrWhiteSpace([string]$plan.driver.hostDriverPath)) {
        Invoke-RecordedStep -Id 'install-driver-service' -Title 'Install and start guest R0 driver service' -ScriptBlock {
            if ($script:Cmdlet.ShouldProcess($plan.vm.name, 'Install/start guest R0 driver service')) {
                $script:VmMutationStarted = $true
                Install-GuestDriverService -Plan $plan -Credential $credential
            }
        }
    }

    Invoke-RecordedStep -Id 'run-guest-agent' -Title 'Start Guest Agent and optional R0Collector sidecar' -ScriptBlock {
        if ($script:Cmdlet.ShouldProcess($plan.vm.name, 'Start Guest Agent in VM')) {
            $script:VmMutationStarted = $true
            Start-GuestAgent -Plan $plan -Credential $credential
        }
    }

    Save-StartResult -Plan $plan -Success $true
    Write-HyperVJobStep "Guest Agent process id: $script:GuestAgentProcessId"
    exit 0
}
catch {
    $primaryErrorMessage = $_.Exception.Message
    try {
        Invoke-StartFailureCleanup -Plan $plan
    }
    catch {
        [void]$script:CleanupErrors.Add("Start failure cleanup handler 失败。英文详情：$($_.Exception.Message)")
    }

    try {
        Save-StartResult -Plan $plan -Success $false -Message $primaryErrorMessage
    }
    catch {
        Write-Warning "中文提示：主失败后无法写入 start result。英文详情：$($_.Exception.Message)"
    }

    try {
        Save-GuestOutputSkeleton -Plan $plan -FailureMessage $primaryErrorMessage
    }
    catch {
        Write-Warning "中文提示：start 阶段无法写入可导入 guest-output skeleton。英文详情：$($_.Exception.Message)"
    }

    Write-Error "失败：Hyper-V E2E start 阶段失败。下一步：查看 start result/remediationHints，修复 VM、payload、凭据或 driver 配置后重试。英文详情：$primaryErrorMessage"
    exit 1
}
