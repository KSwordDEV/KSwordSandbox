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
$script:Cmdlet = $PSCmdlet
$script:GuestServiceInterfaceComponentId = '6C09BB55-D683-4DA0-8931-C9BF705F6480'

function Write-HyperVJobStep {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "[hyperv-e2e:start] $Message"
}

function Read-HyperVE2EPlan {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Plan JSON was not found: $Path"
    }

    $plan = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if ($plan.kind -ne 'KSwordSandbox.HyperVE2EPlan') {
        throw "Plan JSON kind is not KSwordSandbox.HyperVE2EPlan: $Path"
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
        throw "Required command(s) not available in this PowerShell session: $($missing -join ', ')"
    }
}

function Assert-FileForLive {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Name was not found: $Path"
    }
}

function Assert-DirectoryForLive {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "$Name was not found: $Path"
    }
}

function Assert-VmCheckpointForLive {
    param([Parameter(Mandatory)][object]$Plan)

    $vm = Get-VM -Name $Plan.vm.name -ErrorAction Stop
    $snapshot = Get-VMSnapshot -VMName $Plan.vm.name -Name $Plan.vm.cleanCheckpointName -ErrorAction Stop
    Write-HyperVJobStep ("Verified VM '{0}' in state '{1}' and checkpoint '{2}' from {3}." -f $Plan.vm.name, $vm.State, $Plan.vm.cleanCheckpointName, $snapshot.CreationTime)
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

    if ([string]::IsNullOrWhiteSpace($SecretName)) {
        throw 'Guest password secret name is empty.'
    }

    $password = [Environment]::GetEnvironmentVariable($SecretName, 'Process')
    if ([string]::IsNullOrEmpty($password)) {
        $password = [Environment]::GetEnvironmentVariable($SecretName, 'User')
    }
    if ([string]::IsNullOrEmpty($password)) {
        $password = [Environment]::GetEnvironmentVariable($SecretName, 'Machine')
    }

    if ([string]::IsNullOrEmpty($password)) {
        throw "Guest password environment variable '$SecretName' is not set in Process, User, or Machine scope. Run .\install.ps1 -Mode Install -PromptPassword or -GeneratePassword."
    }

    $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
    return [pscredential]::new($UserName, $securePassword)
}

function New-StepResult {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Title,
        [bool]$Success,
        [bool]$Skipped,
        [DateTimeOffset]$StartedAtUtc,
        [TimeSpan]$Duration,
        [string]$Message = ''
    )

    return [ordered]@{
        id = $Id
        title = $Title
        success = $Success
        skipped = $Skipped
        startedAtUtc = $StartedAtUtc.ToString('O')
        durationSeconds = [Math]::Round($Duration.TotalSeconds, 3)
        message = $Message
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
        [void]$script:StepResults.Add((New-StepResult -Id $Id -Title $Title -Success $false -Skipped $false -StartedAtUtc $started -Duration $timer.Elapsed -Message $_.Exception.Message))
        throw
    }
}

function Wait-VMRunning {
    param(
        [Parameter(Mandatory)][string]$VmName,
        [int]$TimeoutSeconds
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $vm = Get-VM -Name $VmName -ErrorAction Stop
        if ($vm.State.ToString() -eq 'Running') {
            return
        }

        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $deadline)

    throw "VM '$VmName' did not reach Running state within $TimeoutSeconds seconds."
}

function Wait-PowerShellDirect {
    param(
        [Parameter(Mandatory)][string]$VmName,
        [Parameter(Mandatory)][pscredential]$Credential,
        [int]$TimeoutSeconds
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $lastError = ''
    do {
        try {
            Invoke-Command -VMName $VmName -Credential $Credential -ScriptBlock {
                [pscustomobject][ordered]@{
                    ComputerName = $env:COMPUTERNAME
                    UserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                }
            } -ErrorAction Stop | Out-Null
            return
        }
        catch {
            $lastError = $_.Exception.Message
            Start-Sleep -Seconds 3
        }
    } while ((Get-Date) -lt $deadline)

    throw "PowerShell Direct did not become ready within $TimeoutSeconds seconds. Last error: $lastError"
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
                    throw "Required guest payload file is missing: $path"
                }
            }
        } -ArgumentList (,$requiredGuestPaths)
    }
    finally {
        if ($null -ne $session) {
            Remove-PSSession $session
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
    $stalePaths = @(
        [string]$Plan.guest.agentPidPath,
        [string]$Plan.guest.agentExitPath,
        [string]$Plan.driver.eventJsonLinesPath,
        [string]$Plan.guest.agentSummaryPath,
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

function Start-GuestAgent {
    param(
        [Parameter(Mandatory)][object]$Plan,
        [Parameter(Mandatory)][pscredential]$Credential
    )

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
            [string]$PidPath
        )

        $process = Start-Process `
            -FilePath 'powershell.exe' `
            -ArgumentList @('-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', $AgentCommand) `
            -WorkingDirectory $GuestRoot `
            -PassThru
        $process.Id | Set-Content -Path $PidPath -Encoding ASCII
        [pscustomobject][ordered]@{
            ProcessId = $process.Id
            PidPath = $PidPath
        }
    } -ArgumentList $Plan.guest.workingDirectory, $agentCommand, $Plan.guest.agentPidPath

    $script:GuestAgentProcessId = @($launch | Select-Object -First 1)[0].ProcessId
}

function Assert-LivePreconditions {
    param([Parameter(Mandatory)][object]$Plan)

    if (-not (Test-IsAdministrator)) {
        throw 'Live Hyper-V E2E start requires Administrator rights. No VM command was executed.'
    }

    Assert-CommandAvailable -Names @(
        'Get-VM',
        'Get-VMSnapshot',
        'Get-VMIntegrationService',
        'Restore-VMSnapshot',
        'Enable-VMIntegrationService',
        'Start-VM',
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
        Write-HyperVJobStep "Payload manifest is not present: $($Plan.host.payloadManifestPath). Continuing because live execution only requires the staged binaries."
    }

    if (ConvertTo-BooleanValue $Plan.driver.enabled) {
        Assert-DirectoryForLive -Name 'R0Collector payload directory' -Path (Join-Path $Plan.host.guestPayloadRoot 'r0collector')
        Assert-FileForLive -Name 'R0Collector payload' -Path $Plan.host.r0CollectorPayloadPath
    }

    if (-not [string]::IsNullOrWhiteSpace([string]$Plan.driver.hostDriverPath)) {
        Assert-FileForLive -Name 'Optional host driver' -Path $Plan.driver.hostDriverPath
    }
}

function Invoke-StartFailureCleanup {
    param([Parameter(Mandatory)][object]$Plan)

    if (-not $script:VmMutationStarted) {
        return
    }

    Write-HyperVJobStep 'Start phase failed after VM mutation; attempting stop/restore cleanup.'

    try {
        if ($script:Cmdlet.ShouldProcess($Plan.vm.name, 'Stop VM after failed start phase')) {
            Stop-VM -Name $Plan.vm.name -TurnOff -Force -ErrorAction SilentlyContinue
        }
    }
    catch {
        [void]$script:CleanupErrors.Add("Stop-VM after failed start phase failed: $($_.Exception.Message)")
    }

    try {
        if ($script:Cmdlet.ShouldProcess($Plan.vm.name, "Restore checkpoint '$($Plan.vm.cleanCheckpointName)' after failed start phase")) {
            Restore-VMSnapshot -VMName $Plan.vm.name -Name $Plan.vm.cleanCheckpointName -Confirm:$false
        }
    }
    catch {
        [void]$script:CleanupErrors.Add("Restore-VMSnapshot after failed start phase failed: $($_.Exception.Message)")
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
    $result = [ordered]@{
        contractVersion = 1
        phase = 'start'
        planPath = (Resolve-Path -LiteralPath $PlanPath).Path
        jobId = $Plan.job.jobId
        targetVmName = $Plan.vm.name
        success = $Success
        message = $Message
        guestAgentProcessId = $script:GuestAgentProcessId
        guestAgentCommandLine = $script:GuestAgentCommandLine
        guestAgentArguments = @($script:GuestAgentArguments)
        r0CollectorMode = $script:R0CollectorMode
        r0CollectorCommandLine = $script:R0CollectorCommandLine
        r0CollectorArguments = @($script:R0CollectorArguments)
        driverEventsPath = $Plan.driver.eventJsonLinesPath
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

$plan = Read-HyperVE2EPlan -Path $PlanPath

if ((-not [bool]$Live) -or [bool]$WhatIfPreference) {
    $mode = if ($WhatIfPreference) { 'WhatIf' } else { 'PlanOnly' }
    Write-HyperVJobStep "Safe $mode mode: start phase would restore checkpoint, start VM, stage payload/sample, and start Guest Agent; no VM command was executed."
    foreach ($step in @($plan.steps | Where-Object { $_.phase -eq 'start' })) {
        Write-HyperVJobStep ("PLAN {0}: {1}" -f $step.id, $step.title)
        [void]$script:StepResults.Add((New-StepResult `
                    -Id ([string]$step.id) `
                    -Title ([string]$step.title) `
                    -Success $true `
                    -Skipped $true `
                    -StartedAtUtc ([DateTimeOffset]::UtcNow) `
                    -Duration ([TimeSpan]::Zero) `
                    -Message "Safe $mode mode; no VM command was executed."))
    }
    Save-StartResult -Plan $plan -Success $true -Message "Safe $mode mode; no VM command was executed."
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
            Start-VM -Name $plan.vm.name
            Wait-VMRunning -VmName $plan.vm.name -TimeoutSeconds ([int]$plan.timeouts.startupSeconds)
        }
    }

    Invoke-RecordedStep -Id 'wait-powershell-direct' -Title 'Wait for PowerShell Direct readiness' -ScriptBlock {
        Wait-PowerShellDirect -VmName $plan.vm.name -Credential $credential -TimeoutSeconds ([int]$plan.timeouts.guestReadySeconds)
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
    Invoke-StartFailureCleanup -Plan $plan
    Save-StartResult -Plan $plan -Success $false -Message $_.Exception.Message
    Write-Error "FAIL: Hyper-V E2E start phase failed. $($_.Exception.Message)"
    exit 1
}
