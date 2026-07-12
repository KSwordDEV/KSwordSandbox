<#
.SYNOPSIS
Creates a warm Hyper-V sandbox checkpoint from a booted, auto-logged-in guest.

.DESCRIPTION
This operator script restores the configured clean checkpoint, starts or resumes
the golden VM, waits for PowerShell Direct and an interactive desktop signal,
then creates a Hyper-V Standard checkpoint while the VM is running. A running
Standard checkpoint captures memory/device state, so future restore/start cycles
can begin much closer to an already logged-in desktop than an off-state clean
checkpoint.

The script can update the local sandbox config to point at the new warm
checkpoint. It never prints the guest password value. Use this only for local
lab VMs; warm checkpoints are host-local state and are intentionally excluded
from source/runtime packages.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]$ConfigPath = '',
    [string]$VmName = '',
    [string]$SourceCheckpointName = '',
    [string]$WarmCheckpointName = '',
    [string]$GuestUserName = '',
    [string]$GuestPasswordSecretName = '',
    [int]$StartupTimeoutSeconds = 180,
    [int]$GuestReadyTimeoutSeconds = 180,
    [int]$DesktopReadyTimeoutSeconds = 180,
    [switch]$SetAsActiveConfig,
    [switch]$Force,
    [switch]$NoSelfElevate,
    [string]$ResultPath = ''
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$script:RepositoryRoot = Split-Path -Parent $PSScriptRoot
$script:InstallStatePath = Join-Path $env:ProgramData 'KSwordSandbox\install-state.json'
$script:ScriptPath = if ([string]::IsNullOrWhiteSpace($PSCommandPath)) { $MyInvocation.MyCommand.Path } else { $PSCommandPath }

function Write-WarmInfo {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "[warm-checkpoint] $Message"
}

function Test-WarmIsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function ConvertTo-WarmNativeArgument {
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

function Add-WarmStringArgument {
    param(
        [Parameter(Mandatory)][System.Collections.Generic.List[string]]$Arguments,
        [Parameter(Mandatory)][string]$Name,
        [AllowNull()][string]$Value
    )

    if (-not [string]::IsNullOrWhiteSpace([string]$Value)) {
        [void]$Arguments.Add("-$Name")
        [void]$Arguments.Add([string]$Value)
    }
}

function Add-WarmSwitchArgument {
    param(
        [Parameter(Mandatory)][System.Collections.Generic.List[string]]$Arguments,
        [Parameter(Mandatory)][string]$Name,
        [bool]$Enabled
    )

    if ($Enabled) {
        [void]$Arguments.Add("-$Name")
    }
}

function Invoke-WarmSelfElevated {
    $powershellPath = (Get-Command -Name powershell.exe -ErrorAction Stop | Select-Object -First 1).Source
    $arguments = [System.Collections.Generic.List[string]]::new()
    [void]$arguments.Add('-NoProfile')
    [void]$arguments.Add('-ExecutionPolicy')
    [void]$arguments.Add('Bypass')
    [void]$arguments.Add('-File')
    [void]$arguments.Add($script:ScriptPath)
    Add-WarmStringArgument -Arguments $arguments -Name 'ConfigPath' -Value $ConfigPath
    Add-WarmStringArgument -Arguments $arguments -Name 'VmName' -Value $VmName
    Add-WarmStringArgument -Arguments $arguments -Name 'SourceCheckpointName' -Value $SourceCheckpointName
    Add-WarmStringArgument -Arguments $arguments -Name 'WarmCheckpointName' -Value $WarmCheckpointName
    Add-WarmStringArgument -Arguments $arguments -Name 'GuestUserName' -Value $GuestUserName
    Add-WarmStringArgument -Arguments $arguments -Name 'GuestPasswordSecretName' -Value $GuestPasswordSecretName
    Add-WarmStringArgument -Arguments $arguments -Name 'StartupTimeoutSeconds' -Value ([string]$StartupTimeoutSeconds)
    Add-WarmStringArgument -Arguments $arguments -Name 'GuestReadyTimeoutSeconds' -Value ([string]$GuestReadyTimeoutSeconds)
    Add-WarmStringArgument -Arguments $arguments -Name 'DesktopReadyTimeoutSeconds' -Value ([string]$DesktopReadyTimeoutSeconds)
    Add-WarmStringArgument -Arguments $arguments -Name 'ResultPath' -Value $ResultPath
    Add-WarmSwitchArgument -Arguments $arguments -Name 'SetAsActiveConfig' -Enabled ([bool]$SetAsActiveConfig)
    Add-WarmSwitchArgument -Arguments $arguments -Name 'Force' -Enabled ([bool]$Force)
    Add-WarmSwitchArgument -Arguments $arguments -Name 'NoSelfElevate' -Enabled $true

    $argumentLine = ($arguments.ToArray() | ForEach-Object { ConvertTo-WarmNativeArgument -Argument $_ }) -join ' '
    Write-WarmInfo '需要管理员权限访问 Hyper-V；正在触发 UAC。 / Requesting administrator via UAC.'
    $process = Start-Process -FilePath $powershellPath -ArgumentList $argumentLine -Verb RunAs -WorkingDirectory $script:RepositoryRoot -WindowStyle Normal -PassThru -Wait
    exit $process.ExitCode
}

function Get-WarmObjectProperty {
    param(
        [AllowNull()]$Object,
        [Parameter(Mandatory)][string]$Name,
        [AllowNull()]$DefaultValue = $null
    )

    if ($null -eq $Object) {
        return $DefaultValue
    }

    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $DefaultValue
    }

    return $property.Value
}

function Set-WarmObjectProperty {
    param(
        [Parameter(Mandatory)]$Object,
        [Parameter(Mandatory)][string]$Name,
        [AllowNull()]$Value
    )

    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        $Object | Add-Member -NotePropertyName $Name -NotePropertyValue $Value
    }
    else {
        $property.Value = $Value
    }
}

function Resolve-WarmConfigPath {
    if (-not [string]::IsNullOrWhiteSpace($ConfigPath)) {
        return (Resolve-Path -LiteralPath $ConfigPath).ProviderPath
    }

    $envConfigPath = [Environment]::GetEnvironmentVariable('Sandbox__ConfigPath', 'Process')
    if (-not [string]::IsNullOrWhiteSpace($envConfigPath) -and (Test-Path -LiteralPath $envConfigPath -PathType Leaf)) {
        return (Resolve-Path -LiteralPath $envConfigPath).ProviderPath
    }

    if (Test-Path -LiteralPath $script:InstallStatePath -PathType Leaf) {
        $state = Get-Content -LiteralPath $script:InstallStatePath -Raw | ConvertFrom-Json
        $stateConfigPath = [string](Get-WarmObjectProperty -Object $state -Name 'localConfigPath' -DefaultValue '')
        if (-not [string]::IsNullOrWhiteSpace($stateConfigPath) -and (Test-Path -LiteralPath $stateConfigPath -PathType Leaf)) {
            return (Resolve-Path -LiteralPath $stateConfigPath).ProviderPath
        }
    }

    return (Resolve-Path -LiteralPath (Join-Path $script:RepositoryRoot 'config\sandbox.example.json')).ProviderPath
}

function Get-WarmSecret {
    param([Parameter(Mandatory)][string]$Name)

    foreach ($target in @('Process', 'User', 'Machine')) {
        $value = [Environment]::GetEnvironmentVariable($Name, $target)
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            return [pscustomobject][ordered]@{
                Value = $value
                Scope = $target
            }
        }
    }

    throw "错误：找不到 guest password secret '$Name'。下一步：先运行 .\install.ps1 -Mode Change -ResetPassword -PromptPassword，或在当前用户环境设置该 secret。"
}

function Wait-WarmVMRunning {
    param(
        [Parameter(Mandatory)][string]$TargetVmName,
        [int]$TimeoutSeconds
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $state = (Get-VM -Name $TargetVmName -ErrorAction Stop).State.ToString()
        if ($state -eq 'Running') {
            return
        }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $deadline)

    throw "错误：VM '$TargetVmName' 未在 $TimeoutSeconds 秒内进入 Running。"
}

function Start-WarmVMIfNeeded {
    param(
        [Parameter(Mandatory)][string]$TargetVmName,
        [int]$TimeoutSeconds
    )

    $vm = Get-VM -Name $TargetVmName -ErrorAction Stop
    $state = $vm.State.ToString()
    if ($state -eq 'Paused') {
        Resume-VM -Name $TargetVmName -ErrorAction Stop
    }
    elseif ($state -ne 'Running') {
        Start-VM -Name $TargetVmName -ErrorAction Stop
    }

    Wait-WarmVMRunning -TargetVmName $TargetVmName -TimeoutSeconds $TimeoutSeconds
}

function Wait-WarmPowerShellDirect {
    param(
        [Parameter(Mandatory)][string]$TargetVmName,
        [Parameter(Mandatory)][pscredential]$Credential,
        [int]$TimeoutSeconds
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $lastError = ''
    do {
        try {
            Invoke-Command -VMName $TargetVmName -Credential $Credential -ScriptBlock { $env:COMPUTERNAME } -ErrorAction Stop | Out-Null
            return
        }
        catch {
            $lastError = $_.Exception.Message
            Start-Sleep -Seconds 5
        }
    } while ((Get-Date) -lt $deadline)

    throw "错误：PowerShell Direct 未在 $TimeoutSeconds 秒内就绪。英文详情：$lastError"
}

function Wait-WarmGuestDesktop {
    param(
        [Parameter(Mandatory)][string]$TargetVmName,
        [Parameter(Mandatory)][pscredential]$Credential,
        [Parameter(Mandatory)][string]$TargetGuestUserName,
        [int]$TimeoutSeconds
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $lastProbe = $null
    do {
        $lastProbe = Invoke-Command -VMName $TargetVmName -Credential $Credential -ScriptBlock {
            param([string]$UserName)

            $explorer = @(Get-Process -Name explorer -ErrorAction SilentlyContinue | Select-Object -First 1)
            $shellReady = $explorer.Count -gt 0
            $sessionText = ''
            try {
                $sessionText = (& quser.exe 2>$null) -join "`n"
            }
            catch {
                $sessionText = ''
            }

            [pscustomobject][ordered]@{
                ShellReady = $shellReady
                ExplorerProcessCount = $explorer.Count
                SessionTextPresent = -not [string]::IsNullOrWhiteSpace($sessionText)
                UserName = $UserName
            }
        } -ArgumentList $TargetGuestUserName -ErrorAction Stop

        $probe = @($lastProbe | Select-Object -First 1)[0]
        if ([bool]$probe.ShellReady) {
            return $probe
        }

        Start-Sleep -Seconds 3
    } while ((Get-Date) -lt $deadline)

    $probeText = if ($null -eq $lastProbe) { '<no probe>' } else { ($lastProbe | ConvertTo-Json -Depth 4 -Compress) }
    throw "错误：Guest 桌面 shell 未在 $TimeoutSeconds 秒内就绪；未创建 warm checkpoint。最后 probe：$probeText"
}

function Save-WarmResult {
    param(
        [Parameter(Mandatory)][hashtable]$Result,
        [Parameter(Mandatory)][string]$Path
    )

    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Path) | Out-Null
    $Result.completedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
    $Result | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $Path -Encoding UTF8
}

if ((-not (Test-WarmIsAdministrator)) -and (-not [bool]$NoSelfElevate)) {
    Invoke-WarmSelfElevated
}

$result = [ordered]@{
    success = $false
    configPath = $null
    vmName = $null
    sourceCheckpointName = $null
    warmCheckpointName = $null
    setAsActiveConfig = [bool]$SetAsActiveConfig
    guestUserName = $null
    guestPasswordSecretName = $null
    guestPasswordSecretScope = $null
    secretValuePrinted = $false
    checkpointTypeBefore = $null
    checkpointTypeDuringCreate = 'Standard'
    checkpointTypeRestoredTo = $null
    updatedInstallState = $false
    steps = @()
    warnings = @()
    error = $null
    completedAtUtc = $null
}

function Add-WarmStep {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$State,
        [string]$Message = ''
    )

    $result.steps += [ordered]@{
        id = $Id
        state = $State
        message = $Message
        atUtc = [DateTimeOffset]::UtcNow.ToString('O')
    }
    Write-WarmInfo "${Id}: $State $Message"
}

try {
    $resolvedConfigPath = Resolve-WarmConfigPath
    $config = Get-Content -LiteralPath $resolvedConfigPath -Raw | ConvertFrom-Json
    $hyperV = Get-WarmObjectProperty -Object $config -Name 'hyperV' -DefaultValue ([pscustomobject]@{})
    $guest = Get-WarmObjectProperty -Object $config -Name 'guest' -DefaultValue ([pscustomobject]@{})

    $effectiveVmName = if ([string]::IsNullOrWhiteSpace($VmName)) { [string](Get-WarmObjectProperty -Object $hyperV -Name 'goldenVmName' -DefaultValue 'KSwordSandbox-Win10-Golden') } else { $VmName }
    $effectiveSourceCheckpointName = if ([string]::IsNullOrWhiteSpace($SourceCheckpointName)) { [string](Get-WarmObjectProperty -Object $hyperV -Name 'goldenSnapshotName' -DefaultValue 'Clean') } else { $SourceCheckpointName }
    $effectiveGuestUserName = if ([string]::IsNullOrWhiteSpace($GuestUserName)) { [string](Get-WarmObjectProperty -Object $guest -Name 'userName' -DefaultValue 'SandboxUser') } else { $GuestUserName }
    $effectiveSecretName = if ([string]::IsNullOrWhiteSpace($GuestPasswordSecretName)) { [string](Get-WarmObjectProperty -Object $guest -Name 'passwordSecretName' -DefaultValue 'KSWORDBOX_GUEST_PASSWORD') } else { $GuestPasswordSecretName }
    $effectiveWarmCheckpointName = if ([string]::IsNullOrWhiteSpace($WarmCheckpointName)) { '{0}-Warm-{1}' -f $effectiveSourceCheckpointName, (Get-Date -Format 'yyyyMMdd-HHmmss') } else { $WarmCheckpointName }
    $effectiveResultPath = if ([string]::IsNullOrWhiteSpace($ResultPath)) {
        Join-Path ([System.IO.Path]::GetTempPath()) ('KSwordSandbox\warm-checkpoint-{0}.json' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    } else {
        $ResultPath
    }

    $result.configPath = $resolvedConfigPath
    $result.vmName = $effectiveVmName
    $result.sourceCheckpointName = $effectiveSourceCheckpointName
    $result.warmCheckpointName = $effectiveWarmCheckpointName
    $result.guestUserName = $effectiveGuestUserName
    $result.guestPasswordSecretName = $effectiveSecretName

    Import-Module Hyper-V -ErrorAction Stop
    $secret = Get-WarmSecret -Name $effectiveSecretName
    $result.guestPasswordSecretScope = $secret.Scope
    $credential = [pscredential]::new($effectiveGuestUserName, (ConvertTo-SecureString $secret.Value -AsPlainText -Force))

    if (-not (Get-VM -Name $effectiveVmName -ErrorAction SilentlyContinue)) {
        throw "错误：找不到 VM '$effectiveVmName'。"
    }
    if (-not (Get-VMSnapshot -VMName $effectiveVmName -Name $effectiveSourceCheckpointName -ErrorAction SilentlyContinue)) {
        throw "错误：找不到 source checkpoint '$effectiveSourceCheckpointName'。"
    }
    if (Get-VMSnapshot -VMName $effectiveVmName -Name $effectiveWarmCheckpointName -ErrorAction SilentlyContinue) {
        if (-not [bool]$Force) {
            throw "错误：warm checkpoint '$effectiveWarmCheckpointName' 已存在。下一步：换一个 -WarmCheckpointName，或追加 -Force 自动重命名旧 checkpoint。"
        }

        $backupName = '{0}-before-warm-refresh-{1}' -f $effectiveWarmCheckpointName, (Get-Date -Format 'yyyyMMdd-HHmmss')
        if ($PSCmdlet.ShouldProcess($effectiveVmName, "Rename existing checkpoint '$effectiveWarmCheckpointName' to '$backupName'")) {
            Add-WarmStep -Id 'rename-existing-warm-checkpoint' -State 'start' -Message $backupName
            Rename-VMSnapshot -VMName $effectiveVmName -Name $effectiveWarmCheckpointName -NewName $backupName -ErrorAction Stop
            Add-WarmStep -Id 'rename-existing-warm-checkpoint' -State 'done' -Message $backupName
        }
    }

    if ($PSCmdlet.ShouldProcess($effectiveVmName, "Restore source checkpoint '$effectiveSourceCheckpointName' and create running warm checkpoint '$effectiveWarmCheckpointName'")) {
        Add-WarmStep -Id 'stop-before-restore' -State 'start'
        Stop-VM -Name $effectiveVmName -TurnOff -Force -ErrorAction SilentlyContinue
        Add-WarmStep -Id 'stop-before-restore' -State 'done'

        Add-WarmStep -Id 'restore-source-checkpoint' -State 'start' -Message $effectiveSourceCheckpointName
        Restore-VMSnapshot -VMName $effectiveVmName -Name $effectiveSourceCheckpointName -Confirm:$false -ErrorAction Stop
        Add-WarmStep -Id 'restore-source-checkpoint' -State 'done'

        Add-WarmStep -Id 'start-or-resume-vm' -State 'start'
        Start-WarmVMIfNeeded -TargetVmName $effectiveVmName -TimeoutSeconds $StartupTimeoutSeconds
        Add-WarmStep -Id 'start-or-resume-vm' -State 'done'

        Add-WarmStep -Id 'wait-powershell-direct' -State 'start'
        Wait-WarmPowerShellDirect -TargetVmName $effectiveVmName -Credential $credential -TimeoutSeconds $GuestReadyTimeoutSeconds
        Add-WarmStep -Id 'wait-powershell-direct' -State 'done'

        Add-WarmStep -Id 'wait-guest-desktop' -State 'start'
        $desktopProbe = Wait-WarmGuestDesktop -TargetVmName $effectiveVmName -Credential $credential -TargetGuestUserName $effectiveGuestUserName -TimeoutSeconds $DesktopReadyTimeoutSeconds
        Add-WarmStep -Id 'wait-guest-desktop' -State 'done' -Message ("explorerCount={0}" -f $desktopProbe.ExplorerProcessCount)

        $vmBeforeCheckpoint = Get-VM -Name $effectiveVmName -ErrorAction Stop
        $result.checkpointTypeBefore = [string]$vmBeforeCheckpoint.CheckpointType
        if ([string]$vmBeforeCheckpoint.CheckpointType -ne 'Standard') {
            Add-WarmStep -Id 'set-standard-checkpoint-type' -State 'start' -Message ([string]$vmBeforeCheckpoint.CheckpointType)
            Set-VM -Name $effectiveVmName -CheckpointType Standard -ErrorAction Stop
            Add-WarmStep -Id 'set-standard-checkpoint-type' -State 'done'
        }

        Add-WarmStep -Id 'create-running-warm-checkpoint' -State 'start' -Message $effectiveWarmCheckpointName
        Checkpoint-VM -Name $effectiveVmName -SnapshotName $effectiveWarmCheckpointName -ErrorAction Stop | Out-Null
        Add-WarmStep -Id 'create-running-warm-checkpoint' -State 'done'

        if ($result.checkpointTypeBefore -and $result.checkpointTypeBefore -ne 'Standard') {
            try {
                Add-WarmStep -Id 'restore-checkpoint-type' -State 'start' -Message $result.checkpointTypeBefore
                Set-VM -Name $effectiveVmName -CheckpointType $result.checkpointTypeBefore -ErrorAction Stop
                $result.checkpointTypeRestoredTo = $result.checkpointTypeBefore
                Add-WarmStep -Id 'restore-checkpoint-type' -State 'done'
            }
            catch {
                $result.warnings += "无法恢复 VM CheckpointType 到 '$($result.checkpointTypeBefore)'。英文详情：$($_.Exception.Message)"
                Add-WarmStep -Id 'restore-checkpoint-type' -State 'warning' -Message $_.Exception.Message
            }
        }

        if ([bool]$SetAsActiveConfig) {
            Add-WarmStep -Id 'update-local-config' -State 'start'
            Set-WarmObjectProperty -Object $hyperV -Name 'goldenSnapshotName' -Value $effectiveWarmCheckpointName
            Set-WarmObjectProperty -Object $config -Name 'hyperV' -Value $hyperV
            $config | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $resolvedConfigPath -Encoding UTF8
            Add-WarmStep -Id 'update-local-config' -State 'done' -Message $resolvedConfigPath

            if (Test-Path -LiteralPath $script:InstallStatePath -PathType Leaf) {
                try {
                    $state = Get-Content -LiteralPath $script:InstallStatePath -Raw | ConvertFrom-Json
                    Set-WarmObjectProperty -Object $state -Name 'checkpointName' -Value $effectiveWarmCheckpointName
                    Set-WarmObjectProperty -Object $state -Name 'action' -Value 'warm-checkpoint-created'
                    Set-WarmObjectProperty -Object $state -Name 'updatedAtUtc' -Value ([DateTimeOffset]::UtcNow.ToString('O'))
                    $state | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $script:InstallStatePath -Encoding UTF8
                    $result.updatedInstallState = $true
                }
                catch {
                    $result.warnings += "无法更新 install-state checkpointName。英文详情：$($_.Exception.Message)"
                }
            }
        }
    }

    $result.success = $true
    Save-WarmResult -Result $result -Path $effectiveResultPath
    Write-WarmInfo "result: $effectiveResultPath"
    Write-WarmInfo "warm checkpoint ready: $effectiveWarmCheckpointName"
}
catch {
    $result.error = $_.Exception.Message
    $effectiveResultPathForFailure = if ([string]::IsNullOrWhiteSpace($ResultPath)) {
        Join-Path ([System.IO.Path]::GetTempPath()) ('KSwordSandbox\warm-checkpoint-failed-{0}.json' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    } else {
        $ResultPath
    }
    Save-WarmResult -Result $result -Path $effectiveResultPathForFailure
    Write-WarmInfo "result: $effectiveResultPathForFailure"
    Write-Error $_
    exit 1
}
