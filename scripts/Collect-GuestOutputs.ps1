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

    [bool]$RestoreCheckpointAfterRun = $true
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$script:StepResults = New-Object System.Collections.Generic.List[object]
$script:CollectedFiles = New-Object System.Collections.Generic.List[object]
$script:CleanupErrors = New-Object System.Collections.Generic.List[string]
$script:CollectionWarnings = New-Object System.Collections.Generic.List[string]
$script:RequiredArtifacts = New-Object System.Collections.Generic.List[object]
$script:Cmdlet = $PSCmdlet

function Write-GuestCollectStep {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "[hyperv-e2e:collect] $Message"
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

function Get-GuestCredential {
    param(
        [Parameter(Mandatory)][string]$UserName,
        [Parameter(Mandatory)][string]$SecretName
    )

    $password = [Environment]::GetEnvironmentVariable($SecretName, 'Process')
    if ([string]::IsNullOrEmpty($password)) {
        throw "Guest password environment variable '$SecretName' is not set in the current process."
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
    Write-GuestCollectStep $Title

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
        Copy-Item -FromSession $Session -Path $GuestOutputDirectory -Destination $HostOutputRoot -Recurse -Force -ErrorAction Stop
    }
    catch {
        $message = "Copy-Item -FromSession failed for '$GuestOutputDirectory' -> '$HostOutputRoot': $($_.Exception.Message)"
        if ($Required) {
            throw $message
        }

        [void]$script:CollectionWarnings.Add($message)
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
        throw "Guest Agent pid marker was not found: $PidPath"
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
            throw "Guest Agent exit marker was not found: $Path"
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
        $session = New-PSSession -VMName $Plan.vm.name -Credential $Credential
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

        Copy-GuestOutputOnce -Session $session -GuestOutputDirectory $Plan.guest.outputDirectory -HostOutputRoot $Plan.host.outputRoot -Required $true

        if ($running) {
            throw "Guest Agent process $guestPid did not exit within $($Plan.timeouts.executionSeconds) seconds."
        }

        $exitCode = Read-GuestAgentExitCode -Session $session -ExitPath $Plan.guest.agentExitPath
        if ($exitCode -ne 0) {
            throw "Guest Agent exited with code $exitCode."
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
            $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
        }
        catch {
            [void]$script:CollectionWarnings.Add("Unable to hash collected file '$($file.FullName)': $($_.Exception.Message)")
        }

        $kind = switch -Regex ([System.IO.Path]::GetFileName($file.FullName)) {
            '^events\.json$' { 'GuestEventsJson'; break }
            '^driver-events\.jsonl$' { 'DriverEventsJsonLines'; break }
            '^agent\.pid$' { 'AgentPid'; break }
            '^agent\.exit$' { 'AgentExit'; break }
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
    if ($exists) {
        $length = (Get-Item -LiteralPath $Path).Length
    }

    [void]$script:RequiredArtifacts.Add([ordered]@{
            name = $Name
            path = $Path
            required = $Required
            exists = $exists
            length = $length
        })

    if ($Required -and -not $exists) {
        throw "Required collected artifact is missing: $Name ($Path)"
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

    if ([System.Convert]::ToBoolean($Plan.driver.enabled)) {
        Add-RequiredArtifactStatus -Name 'driver-events.jsonl' -Path $driverEventsPath -Required $false
        if (-not (Test-Path -LiteralPath $driverEventsPath -PathType Leaf)) {
            [void]$script:CollectionWarnings.Add("Driver collection is enabled but driver-events.jsonl was not collected. Guest Agent may have recorded r0collector.start_failed in events.json.")
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
        [void]$script:CleanupErrors.Add("Stop-VM cleanup failed: $($_.Exception.Message)")
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
            [void]$script:CleanupErrors.Add("Restore-VMSnapshot cleanup failed: $($_.Exception.Message)")
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
    $result = [ordered]@{
        contractVersion = 1
        phase = 'collect'
        planPath = (Resolve-Path -LiteralPath $PlanPath).Path
        jobId = $Plan.job.jobId
        targetVmName = $Plan.vm.name
        success = $Success
        message = $Message
        hostOutputRoot = $Plan.host.outputRoot
        hostGuestOutputDirectory = (Get-HostGuestOutputDirectory -Plan $Plan)
        eventsJsonPath = $Plan.host.eventsJsonPath
        driverEventsJsonlPath = $Plan.host.driverEventsJsonlPath
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

function Assert-LivePreconditions {
    if (-not (Test-IsAdministrator)) {
        throw 'Live Hyper-V E2E collection requires Administrator rights. No VM command was executed.'
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
    Write-GuestCollectStep "Safe $mode mode: collection would wait for Guest Agent, copy artifacts, stop VM, and optionally restore checkpoint; no VM command was executed."
    foreach ($step in @($plan.steps | Where-Object { $_.phase -eq 'collect' -or $_.phase -eq 'cleanup' })) {
        Write-GuestCollectStep ("PLAN {0}: {1}" -f $step.id, $step.title)
        [void]$script:StepResults.Add((New-StepResult `
                    -Id ([string]$step.id) `
                    -Title ([string]$step.title) `
                    -Success $true `
                    -Skipped $true `
                    -StartedAtUtc ([DateTimeOffset]::UtcNow) `
                    -Duration ([TimeSpan]::Zero) `
                    -Message "Safe $mode mode; no VM command was executed."))
    }
    Save-CollectResult -Plan $plan -Success $true -Message "Safe $mode mode; no VM command was executed."
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
        throw
    }
    finally {
        Invoke-Cleanup -Plan $plan -RestoreAfterRun $RestoreCheckpointAfterRun
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

    Write-Error "FAIL: Hyper-V E2E collection cleanup failed. $message"
    exit 1
}
catch {
    if ([string]::IsNullOrWhiteSpace($message)) {
        $message = $_.Exception.Message
    }

    Save-CollectResult -Plan $plan -Success $false -Message $message
    Write-Error "FAIL: Hyper-V E2E collection phase failed. $message"
    exit 1
}
