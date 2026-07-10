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
$script:GuestServiceInterfaceComponentId = '6C09BB55-D683-4DA0-8931-C9BF705F6480'

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

    $missingStatus = if ($RequiredForLive) { 'Failed' } else { 'Warning' }
    $missingMessage = if ($RequiredForLive) {
        "File is not present yet; live mode will fail until it exists: $Path"
    }
    else {
        "Optional file is not present: $Path"
    }

    return New-PlanCheck `
        -Name $Name `
        -Status $missingStatus `
        -RequiredForLive $RequiredForLive `
        -Message $missingMessage `
        -Details @{ path = $Path; exists = $false }
}

function New-DirectoryPresenceCheck {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Path,
        [bool]$RequiredForLive
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

    return New-PlanCheck `
        -Name $Name `
        -Status $missingStatus `
        -RequiredForLive $RequiredForLive `
        -Message $missingMessage `
        -Details @{ path = $Path; exists = $false }
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
        -Message "Required command(s) are missing: $($missing -join ', ')" `
        -Details @{ commands = @($Commands); missing = @($missing) }
}

function New-GuestSecretCheck {
    param([Parameter(Mandatory)][string]$SecretName)

    if ([string]::IsNullOrWhiteSpace($SecretName)) {
        return New-PlanCheck `
            -Name 'Guest credential secret name' `
            -Status 'Failed' `
            -RequiredForLive $true `
            -Message 'Guest password secret name is empty.' `
            -Details @{ secretName = ''; isSet = $false; valuePrinted = $false }
    }

    $secretValue = [Environment]::GetEnvironmentVariable($SecretName, 'Process')
    if ([string]::IsNullOrEmpty($secretValue)) {
        return New-PlanCheck `
            -Name 'Guest credential environment variable' `
            -Status 'Failed' `
            -RequiredForLive $true `
            -Message "Guest password environment variable '$SecretName' is not set in the current process." `
            -Details @{ secretName = $SecretName; isSet = $false; valuePrinted = $false }
    }

    return New-PlanCheck `
        -Name 'Guest credential environment variable' `
        -Status 'Passed' `
        -RequiredForLive $true `
        -Message "Guest password environment variable '$SecretName' is set; value was not printed." `
        -Details @{ secretName = $SecretName; isSet = $true; valuePrinted = $false }
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
        -Message 'Live Hyper-V E2E requires a Windows host.' `
        -Details @{ isWindows = $false }
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
        -Message 'Live Hyper-V E2E requires an elevated Administrator PowerShell session.' `
        -Details @{ isAdministrator = $false }
}

function New-HyperVVmCheck {
    param([Parameter(Mandatory)][string]$VmName)

    if ($null -eq (Get-Command -Name Get-VM -ErrorAction SilentlyContinue)) {
        return New-PlanCheck `
            -Name 'Golden VM exists' `
            -Status 'Warning' `
            -RequiredForLive $true `
            -Message 'Get-VM is not available; VM existence could not be checked.' `
            -Details @{ vmName = $VmName; checked = $false }
    }

    try {
        $vm = Get-VM -Name $VmName -ErrorAction Stop
        return New-PlanCheck `
            -Name 'Golden VM exists' `
            -Status 'Passed' `
            -RequiredForLive $true `
            -Message "VM exists: $VmName (state: $($vm.State))" `
            -Details @{ vmName = $VmName; exists = $true; state = $vm.State.ToString() }
    }
    catch {
        return New-PlanCheck `
            -Name 'Golden VM exists' `
            -Status 'Failed' `
            -RequiredForLive $true `
            -Message "VM was not found or could not be queried: $VmName. $($_.Exception.Message)" `
            -Details @{ vmName = $VmName; exists = $false; error = $_.Exception.Message }
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
            -Message 'Get-VMSnapshot is not available; checkpoint existence could not be checked.' `
            -Details @{ vmName = $VmName; checkpointName = $CheckpointName; checked = $false }
    }

    try {
        $snapshot = Get-VMSnapshot -VMName $VmName -Name $CheckpointName -ErrorAction Stop
        return New-PlanCheck `
            -Name 'Clean checkpoint exists' `
            -Status 'Passed' `
            -RequiredForLive $true `
            -Message "Checkpoint exists: $VmName / $CheckpointName" `
            -Details @{ vmName = $VmName; checkpointName = $CheckpointName; exists = $true; creationTime = $snapshot.CreationTime }
    }
    catch {
        return New-PlanCheck `
            -Name 'Clean checkpoint exists' `
            -Status 'Failed' `
            -RequiredForLive $true `
            -Message "Checkpoint was not found or could not be queried: $VmName / $CheckpointName. $($_.Exception.Message)" `
            -Details @{ vmName = $VmName; checkpointName = $CheckpointName; exists = $false; error = $_.Exception.Message }
    }
}

function New-GuestServiceCheck {
    param([Parameter(Mandatory)][string]$VmName)

    if ($null -eq (Get-Command -Name Get-VMIntegrationService -ErrorAction SilentlyContinue)) {
        return New-PlanCheck `
            -Name 'Guest Service Interface' `
            -Status 'Warning' `
            -RequiredForLive $true `
            -Message 'Get-VMIntegrationService is not available; Guest Service Interface could not be checked.' `
            -Details @{ vmName = $VmName; checked = $false }
    }

    try {
        $componentSuffix = '\' + $script:GuestServiceInterfaceComponentId
        $service = @(Get-VMIntegrationService -VMName $VmName -ErrorAction Stop |
            Where-Object {
                $id = [string]$_.Id
                $name = [string]$_.Name
                $id.EndsWith($componentSuffix, [System.StringComparison]::OrdinalIgnoreCase) -or
                $name -eq 'Guest Service Interface' -or
                $name -eq '来宾服务接口'
            } |
            Select-Object -First 1)[0]
        if ($null -eq $service) {
            throw "Guest Service Interface integration service was not found on VM '$VmName'. Checked localized names and component id '$script:GuestServiceInterfaceComponentId'."
        }
        $enabled = [bool]$service.Enabled
        $status = if ($enabled) { 'Passed' } else { 'Warning' }
        $message = if ($enabled) {
            "Guest Service Interface is enabled for $VmName."
        }
        else {
            "Guest Service Interface exists but is disabled; live start will enable it before Copy-VMFile."
        }

        return New-PlanCheck `
            -Name 'Guest Service Interface' `
            -Status $status `
            -RequiredForLive $true `
            -Message $message `
            -Details @{ vmName = $VmName; exists = $true; enabled = $enabled; primaryStatus = $service.PrimaryStatusDescription }
    }
    catch {
        return New-PlanCheck `
            -Name 'Guest Service Interface' `
            -Status 'Failed' `
            -RequiredForLive $true `
            -Message "Guest Service Interface could not be queried for $VmName. $($_.Exception.Message)" `
            -Details @{ vmName = $VmName; exists = $false; error = $_.Exception.Message }
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
            -Message 'Invoke-Command is not available; PowerShell Direct could not be checked.' `
            -Details @{ vmName = $VmName; checked = $false }
    }

    if ($null -eq (Get-Command -Name Get-VM -ErrorAction SilentlyContinue)) {
        return New-PlanCheck `
            -Name 'PowerShell Direct readiness' `
            -Status 'Warning' `
            -RequiredForLive $true `
            -Message 'Get-VM is not available; VM state could not be checked before PowerShell Direct probe.' `
            -Details @{ vmName = $VmName; checked = $false }
    }

    $password = [Environment]::GetEnvironmentVariable($SecretName, 'Process')
    if ([string]::IsNullOrEmpty($password)) {
        return New-PlanCheck `
            -Name 'PowerShell Direct readiness' `
            -Status 'Warning' `
            -RequiredForLive $true `
            -Message "PowerShell Direct probe skipped because guest password environment variable '$SecretName' is not set." `
            -Details @{ vmName = $VmName; checked = $false; reason = 'missingCredentialSecret'; secretName = $SecretName; valuePrinted = $false }
    }

    try {
        $vm = Get-VM -Name $VmName -ErrorAction Stop
        if ($vm.State.ToString() -ne 'Running') {
            return New-PlanCheck `
                -Name 'PowerShell Direct readiness' `
                -Status 'Warning' `
                -RequiredForLive $true `
                -Message "PowerShell Direct probe skipped because VM is $($vm.State); plan-only mode will not start it." `
                -Details @{ vmName = $VmName; checked = $false; vmState = $vm.State.ToString(); reason = 'vmNotRunning' }
        }

        $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
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
            -Message "PowerShell Direct read-only probe succeeded for $VmName." `
            -Details @{ vmName = $VmName; checked = $true; computerName = $firstProbe.ComputerName; userName = $firstProbe.UserName; guestPathResults = $firstProbe.PathResults; valuePrinted = $false }
    }
    catch {
        return New-PlanCheck `
            -Name 'PowerShell Direct readiness' `
            -Status 'Failed' `
            -RequiredForLive $true `
            -Message "PowerShell Direct read-only probe failed for $VmName. $($_.Exception.Message)" `
            -Details @{ vmName = $VmName; checked = $true; error = $_.Exception.Message; valuePrinted = $false }
    }
}

function New-PreflightSummary {
    param([Parameter(Mandatory)][object[]]$Checks)

    $required = @($Checks | Where-Object { [bool]$_.requiredForLive })
    $failedRequired = @($required | Where-Object { $_.status -eq 'Failed' })
    $warnings = @($Checks | Where-Object { $_.status -eq 'Warning' })

    return [ordered]@{
        totalChecks = @($Checks).Count
        requiredForLive = $required.Count
        failedRequired = $failedRequired.Count
        warnings = $warnings.Count
        liveReady = ($failedRequired.Count -eq 0)
        failedRequiredNames = @($failedRequired | ForEach-Object { $_.name })
        warningNames = @($warnings | ForEach-Object { $_.name })
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
        [string]$Message = $null
    )

    return [ordered]@{
        StepIndex = $StepIndex
        StepId = $StepId
        Title = $Title
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
        [object]$CollectResult
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
    foreach ($phaseResult in @($StartResult, $CollectResult)) {
        if ($null -eq $phaseResult) {
            continue
        }

        foreach ($childStep in @($phaseResult.steps)) {
            $stepId = [string]$childStep.id
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
                        -Message ([string]$childStep.message)))
        }
    }

    return @($results.ToArray())
}

function Save-RunbookExecutionRecord {
    param(
        [Parameter(Mandatory)][object]$Plan,
        [Parameter(Mandatory)][string]$ModeName,
        [bool]$Success,
        [string]$Message = $null,
        [DateTimeOffset]$StartedAtUtc = [DateTimeOffset]::UtcNow,
        [TimeSpan]$Duration = [TimeSpan]::Zero,
        [object[]]$StepResults = @(),
        [object]$StartResult = $null,
        [object]$CollectResult = $null,
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

    $record = [ordered]@{
        contractVersion = 1
        kind = 'KSwordSandbox.RunbookExecution'
        JobId = [string]$Plan.job.jobId
        TargetVmName = [string]$Plan.vm.name
        Mode = $modeValue
        ModeName = $ModeName
        Success = $Success
        TotalSteps = @($Plan.steps).Count
        ExecutedSteps = $executedSteps
        FailedStepIndex = $failedStepIndex
        StartedAtUtc = $StartedAtUtc.ToString('O')
        Duration = $Duration.ToString('c')
        RequiresElevation = $true
        StepResults = @($StepResults)
        Message = $Message
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
            collectedFiles = if ($null -ne $CollectResult) { @($CollectResult.collectedFiles) } else { @() }
        }
        completedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
    }

    $record | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $executionPath -Encoding UTF8 -WhatIf:$false
    Write-HyperVE2EStep "Runbook execution record written: $executionPath"
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
        [Parameter(Mandatory)][string]$SecretName,
        [Parameter(Mandatory)][string]$GuestAgentCommandLine,
        [string]$R0CollectorCommandLine = '',
        [bool]$RestoreAfterRun
    )

    $steps = New-Object System.Collections.Generic.List[object]
    [void]$steps.Add((New-HyperVE2EStep -Id 'write-plan' -Phase 'plan' -Title 'Write reviewable Hyper-V E2E plan JSON' -PowerShell 'ConvertTo-Json -Depth 12 | Set-Content <planPath>' -MutatesVmState $false -RequiresLive $false))
    [void]$steps.Add((New-HyperVE2EStep -Id 'load-guest-credential' -Phase 'start' -Title 'Load guest credential from environment secret' -PowerShell ('$guestPassword = ConvertTo-SecureString $env:' + $SecretName + ' -AsPlainText -Force') -MutatesVmState $false))
    [void]$steps.Add((New-HyperVE2EStep -Id 'stop-before-restore' -Phase 'start' -Title 'Stop golden VM before checkpoint restore' -PowerShell ("Stop-VM -Name {0} -TurnOff -Force -ErrorAction SilentlyContinue" -f (Quote-PowerShellString $Vm)) -MutatesVmState $true))
    [void]$steps.Add((New-HyperVE2EStep -Id 'restore-checkpoint' -Phase 'start' -Title 'Restore clean checkpoint' -PowerShell ("Restore-VMSnapshot -VMName {0} -Name {1} -Confirm:`$false" -f (Quote-PowerShellString $Vm), (Quote-PowerShellString $Snapshot)) -MutatesVmState $true))
    [void]$steps.Add((New-HyperVE2EStep -Id 'enable-guest-service' -Phase 'start' -Title 'Enable Guest Service Interface' -PowerShell (Get-EnableGuestServicePowerShell -Vm $Vm) -MutatesVmState $true))
    [void]$steps.Add((New-HyperVE2EStep -Id 'start-vm' -Phase 'start' -Title 'Start restored golden VM' -PowerShell ("Start-VM -Name {0}" -f (Quote-PowerShellString $Vm)) -MutatesVmState $true))
    [void]$steps.Add((New-HyperVE2EStep -Id 'wait-powershell-direct' -Phase 'start' -Title 'Wait for PowerShell Direct in the guest' -PowerShell ("Invoke-Command -VMName {0} -Credential `$guestCredential -ScriptBlock {{ `$env:COMPUTERNAME }}" -f (Quote-PowerShellString $Vm)) -MutatesVmState $false))
    [void]$steps.Add((New-HyperVE2EStep -Id 'stage-guest-payload' -Phase 'start' -Title 'Copy Guest Agent and R0Collector payload into guest' -PowerShell ("Copy-Item -ToSession <PSSession> -Path {0}\agent\* -Destination <guestAgentDirectory> -Recurse -Force" -f $PayloadRoot) -MutatesVmState $true))
    [void]$steps.Add((New-HyperVE2EStep -Id 'copy-sample' -Phase 'start' -Title 'Copy submitted sample into guest' -PowerShell ("Copy-VMFile -VMName {0} -SourcePath {1} -DestinationPath {2} -FileSource Host -CreateFullPath -Force" -f (Quote-PowerShellString $Vm), (Quote-PowerShellString $SampleHostPath), (Quote-PowerShellString $SampleGuestPath)) -MutatesVmState $true))
    [void]$steps.Add((New-HyperVE2EStep -Id 'prepare-guest-output' -Phase 'start' -Title 'Create clean guest output folder' -PowerShell ("Invoke-Command -VMName {0} -Credential `$guestCredential -ScriptBlock {{ New-Item -ItemType Directory -Force -Path {1} | Out-Null }}" -f (Quote-PowerShellString $Vm), (Quote-PowerShellString $GuestOut)) -MutatesVmState $true))
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

    $checks = New-Object System.Collections.Generic.List[object]
    [void]$checks.Add((New-PlanCheck -Name 'Live execution is explicit' -Status 'Passed' -RequiredForLive $true -Message 'No VM mutation is possible unless -Live is supplied and -WhatIf is not supplied.' -Details @{ liveSwitchPresent = [bool]$Live; planOnlySwitchPresent = [bool]$PlanOnly; whatIf = [bool]$WhatIfPreference; willMutateVm = $willRunLive }))
    [void]$checks.Add((New-HostOsCheck))
    [void]$checks.Add((New-AdministratorCheck))
    [void]$checks.Add((New-CommandAvailabilityCheck -Name 'PowerShell Direct commands' -Commands @('New-PSSession', 'Invoke-Command', 'Copy-Item') -RequiredForLive $true))
    [void]$checks.Add((New-CommandAvailabilityCheck -Name 'Hyper-V commands' -Commands @('Get-VM', 'Get-VMSnapshot', 'Get-VMIntegrationService', 'Enable-VMIntegrationService', 'Start-VM', 'Stop-VM', 'Restore-VMSnapshot', 'Copy-VMFile') -RequiredForLive $true))
    [void]$checks.Add((New-GuestSecretCheck -SecretName $effectiveGuestSecretName))
    [void]$checks.Add((New-HyperVVmCheck -VmName $effectiveVmName))
    [void]$checks.Add((New-HyperVCheckpointCheck -VmName $effectiveVmName -CheckpointName $effectiveCheckpointName))
    [void]$checks.Add((New-GuestServiceCheck -VmName $effectiveVmName))
    [void]$checks.Add((New-PowerShellDirectCheck -VmName $effectiveVmName -UserName $effectiveGuestUserName -SecretName $effectiveGuestSecretName -GuestPathsToProbe @($guestRoot, $agentPathInGuest, $r0CollectorPathInGuest)))
    [void]$checks.Add((New-DirectoryPresenceCheck -Name 'Guest payload root' -Path $resolvedPayloadRoot -RequiredForLive $true))
    [void]$checks.Add((New-DirectoryPresenceCheck -Name 'Guest Agent payload directory' -Path (Join-Path $resolvedPayloadRoot 'agent') -RequiredForLive $true))
    [void]$checks.Add((New-FilePresenceCheck -Name 'Sample file' -Path $resolvedSamplePath -RequiredForLive $true))
    [void]$checks.Add((New-FilePresenceCheck -Name 'Guest Agent payload' -Path $agentHostPath -RequiredForLive $true))
    [void]$checks.Add((New-FilePresenceCheck -Name 'Payload manifest' -Path $payloadManifestPath -RequiredForLive $false))
    if ($driverEnabled) {
        [void]$checks.Add((New-DirectoryPresenceCheck -Name 'R0Collector payload directory' -Path (Join-Path $resolvedPayloadRoot 'r0collector') -RequiredForLive $true))
        [void]$checks.Add((New-FilePresenceCheck -Name 'R0Collector payload' -Path $collectorHostPath -RequiredForLive $true))
    }
    if (-not [string]::IsNullOrWhiteSpace($hostDriverPath)) {
        [void]$checks.Add((New-FilePresenceCheck -Name 'Optional host driver' -Path $hostDriverPath -RequiredForLive $true))
    }
    $preflightArray = @($checks.ToArray())
    $preflightSummary = New-PreflightSummary -Checks $preflightArray

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
            r0CollectorPathInGuest = $r0CollectorPathInGuest
            devicePath = $devicePath
            useMockCollector = $useMockCollector
            collectionMode = $driverCollectionMode
            hostDriverPath = $hostDriverPath
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
            secretValuePrinted = $false
            noVmMutationWhenPlanOnly = (-not $willRunLive)
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
            -SecretName $effectiveGuestSecretName `
            -GuestAgentCommandLine $guestAgentCommandLine `
            -R0CollectorCommandLine $r0CollectorCommandLine `
            -RestoreAfterRun $RestoreCheckpointAfterRun
    }

    $planParent = Split-Path -Parent $PlanPath
    if (-not [string]::IsNullOrWhiteSpace($planParent)) {
        New-Item -ItemType Directory -Path $planParent -Force -WhatIf:$false | Out-Null
    }

    $plan | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $PlanPath -Encoding UTF8 -WhatIf:$false
    Write-HyperVE2EStep "Plan JSON written: $PlanPath"

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
        Write-Output ([pscustomobject][ordered]@{
                PlanPath = $PlanPath
                RunbookExecutionPath = $runbookExecutionPath
                Mode = $effectiveMode
                LiveExecuted = $false
                TargetVmName = $effectiveVmName
                JobId = $jobGuid
            })
        exit 0
    }

    if ([int]$plan.preflightSummary.failedRequired -gt 0) {
        $failedNames = @($plan.preflightSummary.failedRequiredNames) -join ', '
        $message = "Live Hyper-V E2E preflight failed before VM mutation. Failed required check(s): $failedNames"
        Save-RunbookExecutionRecord `
            -Plan $plan `
            -ModeName 'Live' `
            -Success $false `
            -Message $message `
            -StartedAtUtc ([DateTimeOffset]::UtcNow) `
            -Duration ([TimeSpan]::Zero) `
            -StepResults @() `
            -WhatIf $false
        throw $message
    }

    if (-not (Test-Path -LiteralPath $startScript -PathType Leaf)) {
        $message = "Start script was not found: $startScript"
        Save-RunbookExecutionRecord -Plan $plan -ModeName 'Live' -Success $false -Message $message -StartedAtUtc ([DateTimeOffset]::UtcNow) -Duration ([TimeSpan]::Zero) -StepResults @()
        throw $message
    }

    if (-not (Test-Path -LiteralPath $collectScript -PathType Leaf)) {
        $message = "Collect script was not found: $collectScript"
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
        $liveSuccess = $false
        $liveMessage = ''

        Write-HyperVE2EStep 'Starting live VM phase.'
        & $startScript -PlanPath $PlanPath -Live
        $startExitCode = $LASTEXITCODE
        $startResult = Read-JsonFileIfPresent -Path (Join-Path $jobRoot 'hyperv-e2e-start-result.json')
        if ($startExitCode -ne 0) {
            $liveMessage = "Start phase failed with exit code $startExitCode; collection phase was not launched."
        }
        else {
            Write-HyperVE2EStep 'Starting live collection/cleanup phase.'
            & $collectScript -PlanPath $PlanPath -Live -RestoreCheckpointAfterRun:$RestoreCheckpointAfterRun
            $collectExitCode = $LASTEXITCODE
            $collectResult = Read-JsonFileIfPresent -Path (Join-Path $jobRoot 'hyperv-e2e-collect-result.json')
            if ($collectExitCode -ne 0) {
                $liveMessage = "Collection phase failed with exit code $collectExitCode."
            }
            else {
                $liveSuccess = $true
            }
        }

        $timer.Stop()
        $liveStepResults = Convert-PhaseStepsToRunbookStepResults -Plan $plan -StartResult $startResult -CollectResult $collectResult
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
            -StartExitCode $startExitCode `
            -CollectExitCode $collectExitCode `
            -WhatIf $false

        if ($liveSuccess) {
            exit 0
        }

        Write-Error "FAIL: Hyper-V E2E live execution failed. $liveMessage"
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
    Write-Error "FAIL: Hyper-V E2E orchestration failed. $($_.Exception.Message)"
    exit 1
}
