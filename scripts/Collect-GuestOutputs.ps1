<#
.SYNOPSIS
Collects guest outputs and performs cleanup for a KSword Sandbox Hyper-V E2E job.

.DESCRIPTION
This script is normally called by Invoke-HyperVE2E.ps1 after
Start-SandboxHyperVJob.ps1. It does nothing by default unless -Live is supplied.
In live mode it waits for the Guest Agent `agent.pid` marker, repeatedly copies
guest events and artifacts to the host output folder, verifies the `agent.exit`
marker and exit code, powers off the VM, and optionally restores the clean
checkpoint again. Passing -WhatIf prevents all VM mutation and guest collection.
The collected guest output includes events.json and driver-events.jsonl when
the Guest Agent/R0Collector sidecar emits them.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory)]
    [string]$PlanPath,

    [switch]$Live,

    [object]$RestoreCheckpointAfterRun = $true
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$script:StepResults = New-Object System.Collections.Generic.List[object]
$script:CollectedFiles = New-Object System.Collections.Generic.List[object]
$script:CleanupErrors = New-Object System.Collections.Generic.List[string]
$script:CollectionWarnings = New-Object System.Collections.Generic.List[string]
$script:RequiredArtifacts = New-Object System.Collections.Generic.List[object]
$script:Cmdlet = $PSCmdlet

function ConvertTo-GuestCollectBoolean {
    param(
        [object]$Value,
        [bool]$DefaultValue = $true
    )

    if ($null -eq $Value) {
        return $DefaultValue
    }

    if ($Value -is [bool]) {
        return [bool]$Value
    }

    $text = ([string]$Value).Trim()
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $DefaultValue
    }

    switch -Regex ($text) {
        '^(?i:true|1|yes|y)$' { return $true }
        '^(?i:false|0|no|n)$' { return $false }
        default { throw "错误：无法把 '$text' 转换为 Boolean。下一步：检查 plan JSON 中 true/false 配置值。" }
    }
}

function Write-GuestCollectStep {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "[hyperv-e2e:collect] $Message"
}

function Read-HyperVE2EPlan {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "错误：找不到 Plan JSON：$Path。下一步：请先生成 plan 或检查 -PlanPath。"
    }

    $plan = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if ($plan.kind -ne 'KSwordSandbox.HyperVE2EPlan') {
        throw "错误：Plan JSON 类型不是 KSwordSandbox.HyperVE2EPlan：$Path。下一步：请重新生成 Hyper-V E2E plan。"
    }

    return $plan
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
        throw "错误：当前 PowerShell 缺少必需命令：$($missing -join ', ')。下一步：安装/启用 Hyper-V PowerShell 工具并重试。"
    }
}

function Get-GuestCredential {
    param(
        [Parameter(Mandatory)][string]$UserName,
        [Parameter(Mandatory)][string]$SecretName
    )

    if ([string]::IsNullOrWhiteSpace($UserName)) {
        throw '错误：guest userName 为空。下一步：检查 plan.guest.userName；secret 值未打印。'
    }

    if ([string]::IsNullOrWhiteSpace($SecretName)) {
        throw '错误：guest password secret 名称为空。下一步：检查 plan.guest.passwordSecretName；secret 值未打印。'
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
        throw "错误：Guest password environment variable '$SecretName' 未在 Process/User/Machine 中设置；secret 值未打印。下一步：在启动 Live Hyper-V 的同一个管理员 PowerShell 中设置该变量，或运行 .\install.ps1 -InstallEntrypoint CreateOrPreparePath -PromptPassword；若使用 -GeneratePassword，请同步 VM 内密码。"
    }

    Write-GuestCollectStep "凭据诊断：已从 $scope scope 读取 guest credential secret '$SecretName'，用户 '$UserName'；secret 值未打印。"
    $securePassword = [System.Security.SecureString]::new()
    foreach ($passwordCharacter in $password.ToCharArray()) {
        $securePassword.AppendChar($passwordCharacter)
    }
    $securePassword.MakeReadOnly()
    return [pscredential]::new($UserName, $securePassword)
}

function Add-CollectHint {
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

function Get-CollectRemediationHints {
    param(
        [AllowNull()][string]$Message,
        [AllowNull()][object]$Plan
    )

    $hints = New-Object System.Collections.Generic.List[string]
    $text = [string]$Message
    if ($text -match 'Guest password|credential|secret|Access is denied|logon failure|登录失败|拒绝访问') {
        Add-CollectHint -Hints $hints -Hint "下一步：确认 runner 进程可见 guest password secret '$($Plan.guest.passwordSecretName)'，且该 secret 与 VM 内用户 '$($Plan.guest.userName)' 密码一致；secret 值不要写入文件。"
    }

    if ($text -match 'PowerShell Direct|New-PSSession|Invoke-Command') {
        Add-CollectHint -Hints $hints -Hint "下一步：确认 VM '$($Plan.vm.name)' 仍在运行且 PowerShell Direct 可建立 session；如果 VM 已被关闭，请重新从 start 阶段运行。"
    }

    if ($text -match 'agent\.pid|pid marker|Guest Agent') {
        Add-CollectHint -Hints $hints -Hint '下一步：查看 hyperv-e2e-start-result.json，确认 Guest Agent 已启动并写出 agent.pid；必要时检查 agent.stdout.log/agent.stderr.log。'
    }

    if ($text -match 'agent\.exit|exit marker|退出码') {
        Add-CollectHint -Hints $hints -Hint '下一步：检查 Guest Agent 是否崩溃、是否超时，以及 host guest output 下的 agent stdout/stderr。'
    }

    if ($text -match 'events\.json|driver-events\.jsonl|采集产物') {
        Add-CollectHint -Hints $hints -Hint '下一步：确认 Guest Agent 写入 events.json；若 collection 已失败，可导入生成的 guest-output skeleton 先查看 runbook 失败报告。'
    }

    if ($text -match 'Stop-VM|Restore-VMSnapshot|checkpoint') {
        Add-CollectHint -Hints $hints -Hint "下一步：手动检查 VM '$($Plan.vm.name)' 状态和 checkpoint '$($Plan.vm.cleanCheckpointName)'，必要时在 Hyper-V 管理器中恢复干净快照。"
    }

    if ($hints.Count -eq 0) {
        Add-CollectHint -Hints $hints -Hint '下一步：查看 hyperv-e2e-collect-result.json、runbook-execution.json 和 guest-output skeleton；先修复第一个失败步骤。'
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
    Write-GuestCollectStep $Title

    try {
        & $ScriptBlock
        $timer.Stop()
        [void]$script:StepResults.Add((New-StepResult -Id $Id -Title $Title -Success $true -Skipped $false -StartedAtUtc $started -Duration $timer.Elapsed))
    }
    catch {
        $timer.Stop()
        $hints = @(Get-CollectRemediationHints -Message $_.Exception.Message -Plan $plan)
        [void]$script:StepResults.Add((New-StepResult -Id $Id -Title $Title -Success $false -Skipped $false -StartedAtUtc $started -Duration $timer.Elapsed -Message $_.Exception.Message -RemediationHints $hints))
        throw
    }
}

function Copy-GuestOutputOnce {
    param(
        [Parameter(Mandatory)][System.Management.Automation.Runspaces.PSSession]$Session,
        [Parameter(Mandatory)][string]$GuestOutputDirectory,
        [Parameter(Mandatory)][string]$HostOutputRoot,
        [bool]$Required
    )

    New-Item -ItemType Directory -Path $HostOutputRoot -Force | Out-Null
    $guestOutputExists = Invoke-Command -Session $Session -ScriptBlock {
        param([string]$Path)
        Test-Path -LiteralPath $Path -PathType Container
    } -ArgumentList $GuestOutputDirectory

    if (-not [bool]$guestOutputExists) {
        $message = "Guest output directory is not available yet: $GuestOutputDirectory"
        if ($Required) {
            throw $message
        }

        [void]$script:CollectionWarnings.Add($message)
        return
    }

    try {
        if ($Required) {
            Copy-Item -FromSession $Session -Path $GuestOutputDirectory -Destination $HostOutputRoot -Recurse -Force -ErrorAction Stop
        }
        else {
            $destinationDirectory = Join-Path $HostOutputRoot (Split-Path -Leaf $GuestOutputDirectory)
            New-Item -ItemType Directory -Path $destinationDirectory -Force | Out-Null
            $guestContentPath = ([string]$GuestOutputDirectory).TrimEnd('\', '/') + '\*'
            Copy-Item `
                -FromSession $Session `
                -Path $guestContentPath `
                -Destination $destinationDirectory `
                -Recurse `
                -Force `
                -Exclude @('*.log', 'driver-events.jsonl') `
                -ErrorAction Stop
        }
    }
    catch {
        $message = "错误：从来宾复制输出失败：'$GuestOutputDirectory' -> '$HostOutputRoot'。下一步：确认 PowerShell Direct 可用、来宾输出目录存在。英文详情：$($_.Exception.Message)"
        if ($Required) {
            throw $message
        }

        [void]$script:CollectionWarnings.Add($message)
    }
}

function Get-HostFileSha256Hex {
    param([Parameter(Mandatory)][string]$Path)

    $getFileHash = Get-Command -Name Get-FileHash -ErrorAction SilentlyContinue
    if ($null -ne $getFileHash) {
        return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
    }

    $stream = [System.IO.File]::Open(
        $Path,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete)
    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            return ([System.BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToUpperInvariant()
        }
        finally {
            $sha.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
}

function Get-GuestAgentPid {
    param(
        [Parameter(Mandatory)][System.Management.Automation.Runspaces.PSSession]$Session,
        [Parameter(Mandatory)][string]$PidPath
    )

    $pidText = Invoke-Command -Session $Session -ScriptBlock {
        param([string]$Path)
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            return ''
        }

        return (Get-Content -LiteralPath $Path -Raw).Trim()
    } -ArgumentList $PidPath

    if ([string]::IsNullOrWhiteSpace([string]$pidText)) {
        throw "错误：找不到 Guest Agent pid marker：$PidPath。下一步：查看 start 阶段输出，确认 Guest Agent 已启动。"
    }

    return [int]$pidText
}

function Test-GuestProcessRunning {
    param(
        [Parameter(Mandatory)][System.Management.Automation.Runspaces.PSSession]$Session,
        [int]$ProcessId
    )

    $running = Invoke-Command -Session $Session -ScriptBlock {
        param([int]$PidToCheck)
        if ($PidToCheck -le 0) {
            return $false
        }

        return [bool](Get-Process -Id $PidToCheck -ErrorAction SilentlyContinue)
    } -ArgumentList $ProcessId

    return [bool]$running
}

function Read-GuestAgentExitCode {
    param(
        [Parameter(Mandatory)][System.Management.Automation.Runspaces.PSSession]$Session,
        [Parameter(Mandatory)][string]$ExitPath
    )

    $exitText = Invoke-Command -Session $Session -ScriptBlock {
        param([string]$Path)
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            throw "错误：找不到 Guest Agent exit marker：$Path。下一步：等待更久或检查 Guest Agent 是否崩溃/未写出 marker。"
        }

        return (Get-Content -LiteralPath $Path -Raw).Trim()
    } -ArgumentList $ExitPath

    return [int]$exitText
}

function Wait-AndCollectGuestOutput {
    param(
        [Parameter(Mandatory)][object]$Plan,
        [Parameter(Mandatory)][pscredential]$Credential
    )

    $session = $null
    try {
        try {
            $session = New-PSSession -VMName $Plan.vm.name -Credential $Credential -ErrorAction Stop
        }
        catch {
            throw "错误：PowerShell Direct 诊断失败，无法为 VM '$($Plan.vm.name)' 建立 New-PSSession。下一步：确认 VM 仍在 Running、来宾用户 '$($Plan.guest.userName)' 可登录、secret '$($Plan.guest.passwordSecretName)' 与 VM 内密码一致；secret 值未打印。英文详情：$($_.Exception.Message)"
        }

        $guestPid = Get-GuestAgentPid -Session $session -PidPath $Plan.guest.agentPidPath
        $deadline = (Get-Date).AddSeconds([int]$Plan.timeouts.executionSeconds)
        $syncInterval = [Math]::Max([int]$Plan.timeouts.syncIntervalSeconds, 1)
        $running = $true

        do {
            Copy-GuestOutputOnce -Session $session -GuestOutputDirectory $Plan.guest.outputDirectory -HostOutputRoot $Plan.host.outputRoot -Required $false
            $running = Test-GuestProcessRunning -Session $session -ProcessId $guestPid
            if ($running) {
                Start-Sleep -Seconds $syncInterval
            }
        } while ($running -and (Get-Date) -lt $deadline)

        try {
            Copy-GuestOutputOnce -Session $session -GuestOutputDirectory $Plan.guest.outputDirectory -HostOutputRoot $Plan.host.outputRoot -Required $true

            if ($running) {
                throw "错误：Guest Agent 进程 $guestPid 未在 $($Plan.timeouts.executionSeconds) 秒内退出。下一步：提高 -ExecutionTimeoutSeconds 或检查样本/Agent 卡住原因。"
            }

            $exitCode = Read-GuestAgentExitCode -Session $session -ExitPath $Plan.guest.agentExitPath
            if ($exitCode -ne 0) {
                throw "错误：Guest Agent 退出码 $exitCode。下一步：查看 events.json、agent stdout/stderr 和来宾日志。"
            }
        }
        catch {
            try {
                Copy-GuestOutputOnce -Session $session -GuestOutputDirectory $Plan.guest.outputDirectory -HostOutputRoot $Plan.host.outputRoot -Required $false
            }
            catch {
                [void]$script:CollectionWarnings.Add("best-effort 失败输出复制失败。英文详情：$($_.Exception.Message)")
            }

            throw
        }
    }
    finally {
        if ($null -ne $session) {
            Remove-PSSession $session
        }
    }
}

function Index-CollectedFiles {
    param([Parameter(Mandatory)][object]$Plan)

    $hostOutputRoot = [string]$Plan.host.outputRoot
    if (-not (Test-Path -LiteralPath $hostOutputRoot -PathType Container)) {
        return
    }

    $rootWithSeparator = (Get-Item -LiteralPath $hostOutputRoot).FullName.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    foreach ($file in Get-ChildItem -LiteralPath $hostOutputRoot -Recurse -File) {
        $relative = $file.FullName
        if ($relative.StartsWith($rootWithSeparator, [StringComparison]::OrdinalIgnoreCase)) {
            $relative = $relative.Substring($rootWithSeparator.Length)
        }

        $hash = $null
        try {
            $hash = Get-HostFileSha256Hex -Path $file.FullName
        }
        catch {
            [void]$script:CollectionWarnings.Add("Unable to hash collected file '$($file.FullName)': $($_.Exception.Message)")
        }

        $kind = switch -Regex ([System.IO.Path]::GetFileName($file.FullName)) {
            '^events\.json$' { 'GuestEventsJson'; break }
            '^driver-events\.jsonl$' { 'DriverEventsJsonLines'; break }
            '^agent\.pid$' { 'AgentPid'; break }
            '^agent\.exit$' { 'AgentExit'; break }
            '^agent\.stdout\.log$' { 'AgentStdoutLog'; break }
            '^agent\.stderr\.log$' { 'AgentStderrLog'; break }
            '^agent-summary\.json$' { 'AgentSummary'; break }
            default { 'GuestArtifact' }
        }

        [void]$script:CollectedFiles.Add([ordered]@{
                path = $file.FullName
                relativePath = $relative
                length = $file.Length
                sha256 = $hash
                kind = $kind
            })
    }
}

function Get-HostGuestOutputDirectory {
    param([Parameter(Mandatory)][object]$Plan)

    if ($null -ne $Plan.host.guestOutputDirectory -and -not [string]::IsNullOrWhiteSpace([string]$Plan.host.guestOutputDirectory)) {
        return [string]$Plan.host.guestOutputDirectory
    }

    return Join-Path ([string]$Plan.host.outputRoot) (Split-Path -Leaf ([string]$Plan.guest.outputDirectory))
}

function Add-RequiredArtifactStatus {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Path,
        [bool]$Required
    )

    $exists = Test-Path -LiteralPath $Path -PathType Leaf
    $length = $null
    $validJson = $null
    $eventCount = $null
    $validationMessage = ''
    if ($exists) {
        $length = (Get-Item -LiteralPath $Path).Length
        if ($Name -eq 'events.json') {
            try {
                $content = Get-Content -LiteralPath $Path -Raw
                $parsed = $content | ConvertFrom-Json -ErrorAction Stop
                $eventCount = @($parsed).Count
                $validJson = $true
                if ($eventCount -le 0) {
                    $validationMessage = 'events.json parsed but contained no event rows.'
                }
            }
            catch {
                $validJson = $false
                $validationMessage = $_.Exception.Message
            }
        }
    }

    [void]$script:RequiredArtifacts.Add([ordered]@{
            name = $Name
            path = $Path
            required = $Required
            exists = $exists
            length = $length
            validJson = $validJson
            eventCount = $eventCount
            validationMessage = $validationMessage
        })

    if ($Required -and -not $exists) {
        throw "错误：缺少必需采集产物：$Name ($Path)。下一步：检查 Guest Agent/R0Collector 是否运行并写出该文件。"
    }

    if ($Required -and $Name -eq 'events.json' -and ($validJson -ne $true -or [int]$eventCount -le 0)) {
        throw "错误：events.json 不可导入或为空：$Path。下一步：查看 agent stdout/stderr；collection 失败路径会生成 failure skeleton 供报告重建。英文详情：$validationMessage"
    }
}

function Assert-CollectedArtifacts {
    param([Parameter(Mandatory)][object]$Plan)

    $hostGuestOutputDirectory = Get-HostGuestOutputDirectory -Plan $Plan
    $eventsPath = if ($null -ne $Plan.host.eventsJsonPath -and -not [string]::IsNullOrWhiteSpace([string]$Plan.host.eventsJsonPath)) {
        [string]$Plan.host.eventsJsonPath
    }
    else {
        Join-Path $hostGuestOutputDirectory 'events.json'
    }

    $driverEventsPath = if ($null -ne $Plan.host.driverEventsJsonlPath -and -not [string]::IsNullOrWhiteSpace([string]$Plan.host.driverEventsJsonlPath)) {
        [string]$Plan.host.driverEventsJsonlPath
    }
    else {
        Join-Path $hostGuestOutputDirectory 'driver-events.jsonl'
    }

    Add-RequiredArtifactStatus -Name 'events.json' -Path $eventsPath -Required $true
    Add-RequiredArtifactStatus -Name 'agent.exit' -Path (Join-Path $hostGuestOutputDirectory 'agent.exit') -Required $true
    Add-RequiredArtifactStatus -Name 'agent.pid' -Path (Join-Path $hostGuestOutputDirectory 'agent.pid') -Required $true
    Add-RequiredArtifactStatus -Name 'agent.stdout.log' -Path (Join-Path $hostGuestOutputDirectory 'agent.stdout.log') -Required $false
    Add-RequiredArtifactStatus -Name 'agent.stderr.log' -Path (Join-Path $hostGuestOutputDirectory 'agent.stderr.log') -Required $false

    if ([System.Convert]::ToBoolean($Plan.driver.enabled)) {
        Add-RequiredArtifactStatus -Name 'driver-events.jsonl' -Path $driverEventsPath -Required $false
        if (-not (Test-Path -LiteralPath $driverEventsPath -PathType Leaf)) {
            [void]$script:CollectionWarnings.Add("已启用 driver collection，但未采集到 driver-events.jsonl。下一步：检查 events.json 中是否有 r0collector.start_failed，并确认 driver.hostDriverPath/test-signing。")
        }
    }
}

function Invoke-Cleanup {
    param(
        [Parameter(Mandatory)][object]$Plan,
        [bool]$RestoreAfterRun
    )

    try {
        Invoke-RecordedStep -Id 'stop-vm-after-run' -Title 'Stop VM after collection' -ScriptBlock {
            if ($script:Cmdlet.ShouldProcess($Plan.vm.name, 'Stop VM after Hyper-V E2E collection')) {
                Stop-VM -Name $Plan.vm.name -TurnOff -Force -ErrorAction SilentlyContinue
            }
        }
    }
    catch {
        [void]$script:CleanupErrors.Add("Stop-VM 清理失败。英文详情：$($_.Exception.Message)")
    }

    if ($RestoreAfterRun) {
        try {
            Invoke-RecordedStep -Id 'restore-checkpoint-after-run' -Title 'Restore clean checkpoint after run' -ScriptBlock {
                if ($script:Cmdlet.ShouldProcess($Plan.vm.name, "Restore checkpoint '$($Plan.vm.cleanCheckpointName)' after run")) {
                    Restore-VMSnapshot -VMName $Plan.vm.name -Name $Plan.vm.cleanCheckpointName -Confirm:$false
                }
            }
        }
        catch {
            [void]$script:CleanupErrors.Add("Restore-VMSnapshot 清理失败。英文详情：$($_.Exception.Message)")
        }
    }
}

function Save-CollectResult {
    param(
        [Parameter(Mandatory)][object]$Plan,
        [bool]$Success,
        [string]$Message = ''
    )

    $jobRoot = [string]$Plan.host.jobRoot
    New-Item -ItemType Directory -Path $jobRoot -Force -WhatIf:$false | Out-Null
    $resultPath = Join-Path $jobRoot 'hyperv-e2e-collect-result.json'
    $remediationHints = if ($Success) { @() } else { @(Get-CollectRemediationHints -Message $Message -Plan $Plan) }
    $result = [ordered]@{
        contractVersion = 1
        phase = 'collect'
        planPath = (Resolve-Path -LiteralPath $PlanPath).Path
        jobId = $Plan.job.jobId
        targetVmName = $Plan.vm.name
        success = $Success
        state = if ($Success) { 'completed' } else { 'failed' }
        message = $Message
        failureReason = if ($Success) { '' } else { $Message }
        remediationHints = @($remediationHints)
        hostOutputRoot = $Plan.host.outputRoot
        hostGuestOutputDirectory = (Get-HostGuestOutputDirectory -Plan $Plan)
        eventsJsonPath = $Plan.host.eventsJsonPath
        driverEventsJsonlPath = $Plan.host.driverEventsJsonlPath
        diagnostics = [ordered]@{
            vmName = $Plan.vm.name
            cleanCheckpointName = $Plan.vm.cleanCheckpointName
            guestUserName = $Plan.guest.userName
            guestPasswordSecretName = $Plan.guest.passwordSecretName
            secretValuePrinted = $false
            executionTimeoutSeconds = $Plan.timeouts.executionSeconds
            syncIntervalSeconds = $Plan.timeouts.syncIntervalSeconds
        }
        completedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
        warnings = @($script:CollectionWarnings.ToArray())
        requiredArtifacts = @($script:RequiredArtifacts.ToArray())
        cleanupErrors = @($script:CleanupErrors.ToArray())
        collectedFiles = @($script:CollectedFiles.ToArray())
        steps = @($script:StepResults.ToArray())
    }

    $result | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $resultPath -Encoding UTF8 -WhatIf:$false
    Write-GuestCollectStep "Collect result written: $resultPath"
}

function ConvertTo-CollectSkeletonDataValue {
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

function Test-CollectSkeletonEventsPresent {
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
            Write-Warning "中文提示：现有 events.json 无法解析，将由 collect failure skeleton 覆盖以保证可导入。英文详情：$($_.Exception.Message)"
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

    $guestOutputDirectory = Get-HostGuestOutputDirectory -Plan $Plan
    New-Item -ItemType Directory -Path $guestOutputDirectory -Force -WhatIf:$false | Out-Null
    $eventsPath = if ($null -ne $Plan.host.eventsJsonPath -and -not [string]::IsNullOrWhiteSpace([string]$Plan.host.eventsJsonPath)) {
        [string]$Plan.host.eventsJsonPath
    }
    else {
        Join-Path $guestOutputDirectory 'events.json'
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
        Set-Content -LiteralPath $agentStderrPath -Value (ConvertTo-CollectSkeletonDataValue $FailureMessage) -Encoding UTF8 -WhatIf:$false
    }

    $eventsAlreadyPresent = Test-CollectSkeletonEventsPresent -Path $eventsPath
    $now = [DateTimeOffset]::UtcNow
    if (-not $eventsAlreadyPresent) {
        $events = @(
            [ordered]@{
                eventType   = 'hyperv.e2e.failure_skeleton'
                timestamp   = $now.ToString('O')
                source      = 'host'
                processName = 'Collect-GuestOutputs.ps1'
                processId   = $PID
                path        = [string]$Plan.vm.name
                commandLine = 'Collect phase failed before complete guest events were collected.'
                data        = [ordered]@{
                    jobId                = ConvertTo-CollectSkeletonDataValue $Plan.job.jobId
                    vmName               = ConvertTo-CollectSkeletonDataValue $Plan.vm.name
                    checkpointName       = ConvertTo-CollectSkeletonDataValue $Plan.vm.cleanCheckpointName
                    guestUserName        = ConvertTo-CollectSkeletonDataValue $Plan.guest.userName
                    secretName           = ConvertTo-CollectSkeletonDataValue $Plan.guest.passwordSecretName
                    failureReason        = ConvertTo-CollectSkeletonDataValue $FailureMessage
                    runbookExecutionPath = ConvertTo-CollectSkeletonDataValue $Plan.host.runbookExecutionPath
                    generatedBy          = 'Collect-GuestOutputs.ps1'
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
        generatedBy        = 'Collect-GuestOutputs.ps1'
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
        note               = '该 skeleton 仅用于恢复/导入 collect 阶段失败诊断，不代表 Guest Agent 已成功运行。'
    }
    $metadata | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $metadataPath -Encoding UTF8 -WhatIf:$false
    Write-GuestCollectStep "Importable guest output skeleton ready: $eventsPath"
}

function Assert-LivePreconditions {
    if (-not (Test-IsAdministrator)) {
        throw '错误：Live Hyper-V E2E collection 需要管理员权限；尚未执行 VM 命令。下一步：以管理员身份运行，或使用 PlanOnly/WhatIf。'
    }

    Assert-CommandAvailable -Names @(
        'New-PSSession',
        'Invoke-Command',
        'Copy-Item',
        'Stop-VM',
        'Restore-VMSnapshot'
    )
}

$plan = Read-HyperVE2EPlan -Path $PlanPath

if ((-not [bool]$Live) -or [bool]$WhatIfPreference) {
    $mode = if ($WhatIfPreference) { 'WhatIf' } else { 'PlanOnly' }
    Write-GuestCollectStep "Safe $mode mode: collection would wait for Guest Agent, copy artifacts, stop VM, and optionally restore checkpoint; No VM command was executed."
    foreach ($step in @($plan.steps | Where-Object { $_.phase -eq 'collect' -or $_.phase -eq 'cleanup' })) {
        Write-GuestCollectStep ("PLAN {0}: {1}" -f $step.id, $step.title)
        [void]$script:StepResults.Add((New-StepResult `
                    -Id ([string]$step.id) `
                    -Title ([string]$step.title) `
                    -Success $true `
                    -Skipped $true `
                    -StartedAtUtc ([DateTimeOffset]::UtcNow) `
                    -Duration ([TimeSpan]::Zero) `
                    -Message "Safe $mode mode; No VM command was executed."))
    }
    Save-CollectResult -Plan $plan -Success $true -Message "Safe $mode mode; No VM command was executed."
    exit 0
}

$success = $false
$message = ''
try {
    Assert-LivePreconditions
    $credential = Get-GuestCredential -UserName $plan.guest.userName -SecretName $plan.guest.passwordSecretName

    try {
        Invoke-RecordedStep -Id 'sync-guest-output' -Title 'Wait for Guest Agent and copy live/final output' -ScriptBlock {
            Wait-AndCollectGuestOutput -Plan $plan -Credential $credential
        }

        Invoke-RecordedStep -Id 'collect-final-output' -Title 'Index collected events and artifacts on host' -ScriptBlock {
            Index-CollectedFiles -Plan $plan
            Assert-CollectedArtifacts -Plan $plan
        }

        $success = $true
    }
    catch {
        $message = $_.Exception.Message
        try {
            Index-CollectedFiles -Plan $plan
        }
        catch {
            [void]$script:CollectionWarnings.Add("Unable to index failure artifacts: $($_.Exception.Message)")
        }
        throw
    }
    finally {
        Invoke-Cleanup -Plan $plan -RestoreAfterRun (ConvertTo-GuestCollectBoolean -Value $RestoreCheckpointAfterRun -DefaultValue $true)
    }

    if ($script:CleanupErrors.Count -gt 0) {
        $success = $false
        $message = 'Collection finished, but cleanup reported errors: ' + ($script:CleanupErrors.ToArray() -join '; ')
    }

    Save-CollectResult -Plan $plan -Success $success -Message $message
    if ($success) {
        Write-GuestCollectStep "Collected guest output under: $($plan.host.outputRoot)"
        exit 0
    }

    Write-Error "失败：Hyper-V E2E collection 清理失败。下一步：手动检查 VM 状态/快照，再根据错误修复。英文详情：$message"
    exit 1
}
catch {
    if ([string]::IsNullOrWhiteSpace($message)) {
        $message = $_.Exception.Message
    }

    try {
        Save-GuestOutputSkeleton -Plan $plan -FailureMessage $message
    }
    catch {
        Write-Warning "中文提示：collection 阶段无法写入可导入 guest-output skeleton。英文详情：$($_.Exception.Message)"
    }

    Save-CollectResult -Plan $plan -Success $false -Message $message
    Write-Error "失败：Hyper-V E2E collection 阶段失败。下一步：查看 collection result/remediationHints，确认 PowerShell Direct、Guest Agent 输出和 VM 清理状态。英文详情：$message"
    exit 1
}
