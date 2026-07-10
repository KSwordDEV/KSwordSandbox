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

    # Host sample executable to copy into the guest during live execution.
    [string]$SamplePath = 'D:\Temp\KSwordSandbox\samples\KSword.Sandbox.TestSample\KSword.Sandbox.TestSample.exe',

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
    [switch]$NoR0Collector
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

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

function New-PlanCheck {
    param(
        [Parameter(Mandatory)][string]$Name,
        [ValidateSet('Passed', 'Warning', 'Failed')][string]$Status,
        [bool]$RequiredForLive,
        [Parameter(Mandatory)][string]$Message,
        [System.Collections.IDictionary]$Details = @{}
    )

    $orderedDetails = [ordered]@{}
    foreach ($key in $Details.Keys) {
        $orderedDetails[$key] = $Details[$key]
    }

    return [ordered]@{
        name            = $Name
        status          = $Status
        requiredForLive = $RequiredForLive
        message         = $Message
        details         = $orderedDetails
    }
}

function New-FilePresenceCheck {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Path,
        [bool]$RequiredForLive
    )

    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        return New-PlanCheck `
            -Name $Name `
            -Status 'Passed' `
            -RequiredForLive $RequiredForLive `
            -Message "File exists: $Path" `
            -Details @{ path = $Path; exists = $true }
    }

    return New-PlanCheck `
        -Name $Name `
        -Status 'Warning' `
        -RequiredForLive $RequiredForLive `
        -Message "File is not present yet; live mode will fail until it exists: $Path" `
        -Details @{ path = $Path; exists = $false }
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
        [Parameter(Mandatory)][string]$SecretName,
        [bool]$RestoreAfterRun
    )

    $steps = New-Object System.Collections.Generic.List[object]
    [void]$steps.Add((New-HyperVE2EStep -Id 'write-plan' -Phase 'plan' -Title 'Write reviewable Hyper-V E2E plan JSON' -PowerShell 'ConvertTo-Json -Depth 12 | Set-Content <planPath>' -MutatesVmState $false -RequiresLive $false))
    [void]$steps.Add((New-HyperVE2EStep -Id 'load-guest-credential' -Phase 'start' -Title 'Load guest credential from environment secret' -PowerShell ('$guestPassword = ConvertTo-SecureString $env:' + $SecretName + ' -AsPlainText -Force') -MutatesVmState $false))
    [void]$steps.Add((New-HyperVE2EStep -Id 'stop-before-restore' -Phase 'start' -Title 'Stop golden VM before checkpoint restore' -PowerShell ("Stop-VM -Name {0} -TurnOff -Force -ErrorAction SilentlyContinue" -f (Quote-PowerShellString $Vm)) -MutatesVmState $true))
    [void]$steps.Add((New-HyperVE2EStep -Id 'restore-checkpoint' -Phase 'start' -Title 'Restore clean checkpoint' -PowerShell ("Restore-VMSnapshot -VMName {0} -Name {1} -Confirm:`$false" -f (Quote-PowerShellString $Vm), (Quote-PowerShellString $Snapshot)) -MutatesVmState $true))
    [void]$steps.Add((New-HyperVE2EStep -Id 'enable-guest-service' -Phase 'start' -Title 'Enable Guest Service Interface' -PowerShell ("Enable-VMIntegrationService -VMName {0} -Name 'Guest Service Interface'" -f (Quote-PowerShellString $Vm)) -MutatesVmState $true))
    [void]$steps.Add((New-HyperVE2EStep -Id 'start-vm' -Phase 'start' -Title 'Start restored golden VM' -PowerShell ("Start-VM -Name {0}" -f (Quote-PowerShellString $Vm)) -MutatesVmState $true))
    [void]$steps.Add((New-HyperVE2EStep -Id 'wait-powershell-direct' -Phase 'start' -Title 'Wait for PowerShell Direct in the guest' -PowerShell ("Invoke-Command -VMName {0} -Credential `$guestCredential -ScriptBlock {{ `$env:COMPUTERNAME }}" -f (Quote-PowerShellString $Vm)) -MutatesVmState $false))
    [void]$steps.Add((New-HyperVE2EStep -Id 'stage-guest-payload' -Phase 'start' -Title 'Copy Guest Agent and R0Collector payload into guest' -PowerShell ("Copy-Item -ToSession <PSSession> -Path {0}\agent\* -Destination <guestAgentDirectory> -Recurse -Force" -f $PayloadRoot) -MutatesVmState $true))
    [void]$steps.Add((New-HyperVE2EStep -Id 'copy-sample' -Phase 'start' -Title 'Copy submitted sample into guest' -PowerShell ("Copy-VMFile -VMName {0} -SourcePath {1} -DestinationPath {2} -FileSource Host -CreateFullPath -Force" -f (Quote-PowerShellString $Vm), (Quote-PowerShellString $SampleHostPath), (Quote-PowerShellString $SampleGuestPath)) -MutatesVmState $true))
    [void]$steps.Add((New-HyperVE2EStep -Id 'prepare-guest-output' -Phase 'start' -Title 'Create clean guest output folder' -PowerShell ("Invoke-Command -VMName {0} -Credential `$guestCredential -ScriptBlock {{ New-Item -ItemType Directory -Force -Path {1} | Out-Null }}" -f (Quote-PowerShellString $Vm), (Quote-PowerShellString $GuestOut)) -MutatesVmState $true))
    [void]$steps.Add((New-HyperVE2EStep -Id 'run-guest-agent' -Phase 'start' -Title 'Start Guest Agent with optional R0Collector sidecar arguments' -PowerShell ("Start-Process powershell.exe -ArgumentList <agent wrapper>; pid -> {0}; exit -> {1}; driver events -> {2}" -f $AgentPidPath, $AgentExitPath, $DriverEventsPath) -MutatesVmState $true))
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
    $defaultDuration = Get-IntOrDefault -Value (Get-ObjectPropertyValue -Object $analysis -Name 'defaultDurationSeconds' -DefaultValue 120) -DefaultValue 120
    $effectiveDurationSeconds = if ($DurationSeconds -gt 0) { $DurationSeconds } else { $defaultDuration }
    $effectiveExecutionTimeoutSeconds = if ($ExecutionTimeoutSeconds -gt 0) { $ExecutionTimeoutSeconds } else { [Math]::Max($effectiveDurationSeconds + 120, 180) }

    $runtimeRootConfig = Get-ObjectPropertyValue -Object $paths -Name 'runtimeRoot' -DefaultValue 'D:\Temp\KSwordSandbox'
    $runtimeRoot = Resolve-ConfiguredPath -Path $runtimeRootConfig -BasePath $resolvedRepoRoot
    $payloadRootConfig = Get-StringOrDefault -Value $GuestPayloadRoot -DefaultValue (Get-ObjectPropertyValue -Object $paths -Name 'guestPayloadRoot' -DefaultValue 'D:\Temp\KSwordSandbox\payload\guest-tools')
    $resolvedPayloadRoot = Resolve-ConfiguredPath -Path $payloadRootConfig -BasePath $resolvedRepoRoot
    $resolvedSamplePath = Resolve-ConfiguredPath -Path $SamplePath -BasePath $resolvedRepoRoot

    $driverEnabledFromConfig = Get-BooleanOrDefault -Value (Get-ObjectPropertyValue -Object $driver -Name 'enabled' -DefaultValue $true) -DefaultValue $true
    $driverEnabled = $driverEnabledFromConfig -and (-not [bool]$NoR0Collector)
    $driverPathInGuest = Get-ObjectPropertyValue -Object $driver -Name 'driverPathInGuest' -DefaultValue 'C:\KSwordSandbox\driver\KSwordARKDriver.sys'
    $r0CollectorPathInGuest = Get-ObjectPropertyValue -Object $driver -Name 'r0CollectorPathInGuest' -DefaultValue 'C:\KSwordSandbox\r0collector\KSword.Sandbox.R0Collector.exe'
    $devicePath = Get-ObjectPropertyValue -Object $driver -Name 'devicePath' -DefaultValue '\\.\KSwordSandboxDriver'
    $useMockCollector = Get-BooleanOrDefault -Value (Get-ObjectPropertyValue -Object $driver -Name 'useMockCollector' -DefaultValue $false) -DefaultValue $false
    $hostDriverPathValue = Get-ObjectPropertyValue -Object $driver -Name 'hostDriverPath' -DefaultValue $null
    $hostDriverPath = if ([string]::IsNullOrWhiteSpace([string]$hostDriverPathValue)) { $null } else { Resolve-ConfiguredPath -Path ([string]$hostDriverPathValue) -BasePath $resolvedRepoRoot }

    $jobGuid = if ([string]::IsNullOrWhiteSpace($JobId)) { [Guid]::NewGuid() } else { [Guid]::Parse($JobId) }
    $jobIdN = $jobGuid.ToString('N')
    $sampleFileName = [System.IO.Path]::GetFileName($resolvedSamplePath)
    if ([string]::IsNullOrWhiteSpace($sampleFileName)) {
        throw 'SamplePath must include a file name.'
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
    $jobRoot = Join-Path (Join-Path $runtimeRoot 'jobs') $jobIdN
    $hostOutputRoot = Join-Path $jobRoot 'guest'
    $agentHostPath = Join-Path (Join-Path $resolvedPayloadRoot 'agent') $agentExecutableName
    $collectorHostPath = Join-Path (Join-Path $resolvedPayloadRoot 'r0collector') 'KSword.Sandbox.R0Collector.exe'

    if ([string]::IsNullOrWhiteSpace($PlanPath)) {
        $PlanPath = Join-Path (Join-Path $runtimeRoot 'plans') ("hyperv-e2e-$jobIdN.json")
    }
    else {
        $PlanPath = Resolve-ConfiguredPath -Path $PlanPath -BasePath $resolvedRepoRoot
    }

    $willRunLive = [bool]$Live -and (-not [bool]$PlanOnly) -and (-not [bool]$WhatIfPreference)
    $effectiveMode = if ($willRunLive) { 'Live' } elseif ($WhatIfPreference) { 'WhatIf' } else { 'PlanOnly' }
    $requestedMode = if ($Live) { 'Live' } else { 'PlanOnly' }

    $checks = New-Object System.Collections.Generic.List[object]
    [void]$checks.Add((New-PlanCheck -Name 'Live execution is explicit' -Status 'Passed' -RequiredForLive $true -Message 'No VM mutation is possible unless -Live is supplied and -WhatIf is not supplied.' -Details @{ liveSwitchPresent = [bool]$Live; planOnlySwitchPresent = [bool]$PlanOnly; whatIf = [bool]$WhatIfPreference; willMutateVm = $willRunLive }))
    [void]$checks.Add((New-FilePresenceCheck -Name 'Sample file' -Path $resolvedSamplePath -RequiredForLive $true))
    [void]$checks.Add((New-FilePresenceCheck -Name 'Guest Agent payload' -Path $agentHostPath -RequiredForLive $true))
    if ($driverEnabled) {
        [void]$checks.Add((New-FilePresenceCheck -Name 'R0Collector payload' -Path $collectorHostPath -RequiredForLive $true))
    }
    if (-not [string]::IsNullOrWhiteSpace($hostDriverPath)) {
        [void]$checks.Add((New-FilePresenceCheck -Name 'Optional host driver' -Path $hostDriverPath -RequiredForLive $true))
    }

    $startScript = Join-Path $resolvedRepoRoot 'scripts\Start-SandboxHyperVJob.ps1'
    $collectScript = Join-Path $resolvedRepoRoot 'scripts\Collect-GuestOutputs.ps1'
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
            agentPath = $agentPathInGuest
            agentPidPath = $agentPidPath
            agentExitPath = $agentExitPath
        }
        host = [ordered]@{
            runtimeRoot = $runtimeRoot
            guestPayloadRoot = $resolvedPayloadRoot
            jobRoot = $jobRoot
            outputRoot = $hostOutputRoot
            agentPayloadPath = $agentHostPath
            r0CollectorPayloadPath = $collectorHostPath
        }
        sample = [ordered]@{
            hostPath = $resolvedSamplePath
            fileName = $sampleFileName
            guestPath = $guestSamplePath
        }
        driver = [ordered]@{
            enabled = $driverEnabled
            r0CollectorPathInGuest = $r0CollectorPathInGuest
            devicePath = $devicePath
            useMockCollector = $useMockCollector
            hostDriverPath = $hostDriverPath
            driverPathInGuest = $driverPathInGuest
            eventJsonLinesPath = $driverEventsPath
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
            secretValuePrinted = $false
            noVmMutationWhenPlanOnly = (-not $willRunLive)
        }
        preflight = @($checks.ToArray())
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
            -SecretName $effectiveGuestSecretName `
            -RestoreAfterRun $RestoreCheckpointAfterRun
    }

    $planParent = Split-Path -Parent $PlanPath
    if (-not [string]::IsNullOrWhiteSpace($planParent)) {
        New-Item -ItemType Directory -Path $planParent -Force -WhatIf:$false | Out-Null
    }

    $plan | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $PlanPath -Encoding UTF8 -WhatIf:$false
    Write-HyperVE2EStep "Plan JSON written: $PlanPath"

    if (-not $willRunLive) {
        Write-HyperVE2EStep "Safe $effectiveMode mode: no checkpoint restore, VM start, file copy, guest command, shutdown, or restore was executed."
        Write-Output ([pscustomobject][ordered]@{
                PlanPath = $PlanPath
                Mode = $effectiveMode
                LiveExecuted = $false
                TargetVmName = $effectiveVmName
                JobId = $jobGuid
            })
        exit 0
    }

    if (-not (Test-IsAdministrator)) {
        throw 'Live Hyper-V E2E requires an elevated Administrator PowerShell session. No VM command was executed.'
    }

    if (-not (Test-Path -LiteralPath $startScript -PathType Leaf)) {
        throw "Start script was not found: $startScript"
    }

    if (-not (Test-Path -LiteralPath $collectScript -PathType Leaf)) {
        throw "Collect script was not found: $collectScript"
    }

    if ($PSCmdlet.ShouldProcess($effectiveVmName, "Execute live Hyper-V E2E plan $PlanPath")) {
        Write-HyperVE2EStep 'Starting live VM phase.'
        & $startScript -PlanPath $PlanPath -Live
        if ($LASTEXITCODE -ne 0) {
            exit $LASTEXITCODE
        }

        Write-HyperVE2EStep 'Starting live collection/cleanup phase.'
        & $collectScript -PlanPath $PlanPath -Live -RestoreCheckpointAfterRun:$RestoreCheckpointAfterRun
        exit $LASTEXITCODE
    }

    Write-HyperVE2EStep 'Live execution was declined by ShouldProcess/Confirm; no child script was launched.'
    exit 0
}
catch {
    Write-Error "FAIL: Hyper-V E2E orchestration failed. $($_.Exception.Message)"
    exit 1
}
