<#
.SYNOPSIS
Runs read-only Hyper-V readiness checks for KSword Sandbox live VM runs.

.DESCRIPTION
Inputs are the golden VM name, checkpoint name, guest password environment
variable name, and host runtime root path. Processing validates local host and
golden-VM prerequisites without creating probe files and without creating,
starting, restoring, stopping, or deleting any VM. The script emits structured
PowerShell objects for each check plus a summary object. It returns exit code 0
when no check failed, or exit code 1 when at least one check failed.
#>
[CmdletBinding()]
param(
    # Input: golden VM name from config/sandbox.example.json.
    # Processing: read-only lookup through Get-VM when Hyper-V is queryable.
    # Return behavior: a failed result is emitted when the VM is missing or
    # unreadable; the script never creates or starts the VM.
    [string]$VmName = 'KSwordSandbox-Win10-Golden',

    # Input: clean checkpoint name from config/sandbox.example.json.
    # Processing: read-only lookup through Get-VMSnapshot when the VM is
    # queryable. Return behavior: a failed result is emitted when the snapshot
    # is missing or unreadable; the script never creates/restores checkpoints.
    [string]$CheckpointName = 'Clean',

    # Input: environment variable name that should contain the guest password.
    # Processing: checks only whether the current process can see a non-empty
    # value. Return behavior: the value is never printed or returned.
    [string]$GuestPasswordSecretName = 'KSWORDBOX_GUEST_PASSWORD',

    # Input: host runtime root from config/sandbox.example.json.
    # Processing: checks existence and ACLs only; no write probe file is made.
    # Return behavior: a failed result is emitted when writability cannot be
    # inferred from read-only ACL inspection.
    [string]$RuntimeRoot = 'D:\Temp\KSwordSandbox'
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

# New-ReadinessResult builds one structured result row.
# Inputs are the check name, status, requirement flag, operator-facing message,
# and optional machine-readable details. Processing copies details into a
# PSCustomObject so callers can pipe results to ConvertTo-Json. Return behavior
# is one PSCustomObject; this function has no side effects.
function New-ReadinessResult {
    param(
        [string]$Name,
        [ValidateSet('Passed', 'Warning', 'Failed')]
        [string]$Status,
        [bool]$Required,
        [string]$Message,
        [System.Collections.IDictionary]$Details = @{}
    )

    $orderedDetails = [ordered]@{}
    foreach ($key in $Details.Keys) {
        $orderedDetails[$key] = $Details[$key]
    }

    return [pscustomobject][ordered]@{
        ResultType = 'ReadinessCheck'
        Name       = $Name
        Status     = $Status
        Required   = $Required
        Message    = $Message
        Details    = [pscustomobject]$orderedDetails
    }
}

# Test-AdministratorPrivilege checks the current host token.
# Inputs are none; processing evaluates the current Windows principal for the
# built-in Administrator role. Return behavior is a readiness object; failure
# means live Hyper-V runner commands should not be attempted from this process.
function Test-AdministratorPrivilege {
    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
        $isAdministrator = $principal.IsInRole(
            [System.Security.Principal.WindowsBuiltInRole]::Administrator)

        if ($isAdministrator) {
            return New-ReadinessResult `
                -Name 'Administrator privilege' `
                -Status 'Passed' `
                -Required $true `
                -Message 'Current PowerShell process is elevated.' `
                -Details @{
                    UserName        = $identity.Name
                    IsAdministrator = $true
                }
        }

        return New-ReadinessResult `
            -Name 'Administrator privilege' `
            -Status 'Failed' `
            -Required $true `
            -Message 'Current PowerShell process is not elevated; live Hyper-V runs require Administrator rights.' `
            -Details @{
                UserName        = $identity.Name
                IsAdministrator = $false
            }
    }
    catch {
        return New-ReadinessResult `
            -Name 'Administrator privilege' `
            -Status 'Failed' `
            -Required $true `
            -Message "Unable to determine Administrator status: $($_.Exception.Message)" `
            -Details @{
                ErrorType = $_.Exception.GetType().FullName
            }
    }
}

# Test-HyperVModule checks for the management module and read-only commands.
# Inputs are none; processing uses Get-Module/Get-Command only. Return behavior
# is a readiness object; failure means VM/checkpoint/integration-service checks
# cannot be trusted from this session.
function Test-HyperVModule {
    $requiredCommands = @('Get-VM', 'Get-VMSnapshot', 'Get-VMIntegrationService')

    try {
        $module = @(Get-Module -ListAvailable -Name Hyper-V |
            Sort-Object -Property Version -Descending |
            Select-Object -First 1)

        if ($module.Count -eq 0) {
            return New-ReadinessResult `
                -Name 'Hyper-V PowerShell module' `
                -Status 'Failed' `
                -Required $true `
                -Message 'Hyper-V PowerShell module is not available in this PowerShell session.' `
                -Details @{
                    ModuleName       = 'Hyper-V'
                    RequiredCommands = $requiredCommands
                    MissingCommands  = $requiredCommands
                }
        }

        $missingCommands = New-Object System.Collections.Generic.List[string]
        foreach ($commandName in $requiredCommands) {
            if ($null -eq (Get-Command -Name $commandName -ErrorAction SilentlyContinue)) {
                [void]$missingCommands.Add($commandName)
            }
        }

        if ($missingCommands.Count -gt 0) {
            return New-ReadinessResult `
                -Name 'Hyper-V PowerShell module' `
                -Status 'Failed' `
                -Required $true `
                -Message 'Hyper-V module was found, but one or more required read-only cmdlets are unavailable.' `
                -Details @{
                    ModuleName       = $module[0].Name
                    ModuleVersion    = $module[0].Version.ToString()
                    ModulePath       = $module[0].Path
                    RequiredCommands = $requiredCommands
                    MissingCommands  = @($missingCommands.ToArray())
                }
        }

        return New-ReadinessResult `
            -Name 'Hyper-V PowerShell module' `
            -Status 'Passed' `
            -Required $true `
            -Message 'Hyper-V PowerShell module and required read-only cmdlets are available.' `
            -Details @{
                ModuleName       = $module[0].Name
                ModuleVersion    = $module[0].Version.ToString()
                ModulePath       = $module[0].Path
                RequiredCommands = $requiredCommands
            }
    }
    catch {
        return New-ReadinessResult `
            -Name 'Hyper-V PowerShell module' `
            -Status 'Failed' `
            -Required $true `
            -Message "Unable to inspect Hyper-V PowerShell module: $($_.Exception.Message)" `
            -Details @{
                ErrorType = $_.Exception.GetType().FullName
            }
    }
}

# Test-GuestPasswordSecret checks only the presence of the configured secret.
# Inputs are the environment variable name. Processing checks the current
# process environment first because that is what the runner inherits; User and
# Machine scopes are inspected only to improve the diagnostic. Return behavior
# is a readiness object that never exposes the secret value.
function Test-GuestPasswordSecret {
    param([string]$SecretName)

    if ([string]::IsNullOrWhiteSpace($SecretName)) {
        return New-ReadinessResult `
            -Name 'Guest password environment variable' `
            -Status 'Failed' `
            -Required $true `
            -Message 'Guest password environment variable name is empty.' `
            -Details @{
                SecretName = $SecretName
            }
    }

    if ($SecretName.Contains('=')) {
        return New-ReadinessResult `
            -Name 'Guest password environment variable' `
            -Status 'Failed' `
            -Required $true `
            -Message 'Environment variable names cannot contain "=".' `
            -Details @{
                SecretName = $SecretName
            }
    }

    $processValue = [Environment]::GetEnvironmentVariable($SecretName, 'Process')
    $userValue = [Environment]::GetEnvironmentVariable($SecretName, 'User')
    $machineValue = [Environment]::GetEnvironmentVariable($SecretName, 'Machine')
    $isProcessVisible = -not [string]::IsNullOrEmpty($processValue)
    $isUserConfigured = -not [string]::IsNullOrEmpty($userValue)
    $isMachineConfigured = -not [string]::IsNullOrEmpty($machineValue)

    if ($isProcessVisible) {
        return New-ReadinessResult `
            -Name 'Guest password environment variable' `
            -Status 'Passed' `
            -Required $true `
            -Message "Environment variable '$SecretName' is visible to the current process." `
            -Details @{
                SecretName         = $SecretName
                VisibleInProcess   = $true
                ConfiguredForUser  = $isUserConfigured
                ConfiguredForHost  = $isMachineConfigured
                SecretValuePrinted = $false
            }
    }

    return New-ReadinessResult `
        -Name 'Guest password environment variable' `
        -Status 'Failed' `
        -Required $true `
        -Message "Environment variable '$SecretName' is not set or is empty in the current process." `
        -Details @{
            SecretName         = $SecretName
            VisibleInProcess   = $false
            ConfiguredForUser  = $isUserConfigured
            ConfiguredForHost  = $isMachineConfigured
            SecretValuePrinted = $false
        }
}

# Get-CurrentTokenSidValues returns SIDs that should apply to the current token.
# Inputs are none; processing collects the user SID, group SIDs, and common
# well-known SIDs used by Windows ACLs. Return behavior is a string array.
function Get-CurrentTokenSidValues {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $sidValues = New-Object System.Collections.Generic.List[string]

    if ($null -ne $identity.User) {
        [void]$sidValues.Add($identity.User.Value)
    }

    if ($null -ne $identity.Groups) {
        foreach ($group in $identity.Groups) {
            if (($null -ne $group) -and (-not $sidValues.Contains($group.Value))) {
                [void]$sidValues.Add($group.Value)
            }
        }
    }

    $worldSid = [System.Security.Principal.SecurityIdentifier]::new(
        [System.Security.Principal.WellKnownSidType]::WorldSid,
        $null)
    if (-not $sidValues.Contains($worldSid.Value)) {
        [void]$sidValues.Add($worldSid.Value)
    }

    if ($identity.IsAuthenticated) {
        $authenticatedUsersSid = [System.Security.Principal.SecurityIdentifier]::new(
            [System.Security.Principal.WellKnownSidType]::AuthenticatedUserSid,
            $null)
        if (-not $sidValues.Contains($authenticatedUsersSid.Value)) {
            [void]$sidValues.Add($authenticatedUsersSid.Value)
        }
    }

    return @($sidValues.ToArray())
}

# Test-FileSystemRightsIncludeWrite checks whether an ACL right can create or
# modify files under a directory. Inputs are FileSystemRights flags. Processing
# uses a conservative write-capable mask. Return behavior is $true when the
# rights include write-like permissions; otherwise $false.
function Test-FileSystemRightsIncludeWrite {
    param([System.Security.AccessControl.FileSystemRights]$Rights)

    $writeMask = [System.Security.AccessControl.FileSystemRights]::Write `
        -bor [System.Security.AccessControl.FileSystemRights]::Modify `
        -bor [System.Security.AccessControl.FileSystemRights]::FullControl `
        -bor [System.Security.AccessControl.FileSystemRights]::CreateFiles `
        -bor [System.Security.AccessControl.FileSystemRights]::CreateDirectories `
        -bor [System.Security.AccessControl.FileSystemRights]::WriteAttributes `
        -bor [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes

    return (($Rights -band $writeMask) -ne 0)
}

# Test-RuntimeRootWritableReadOnly checks runtime-root usability without writing.
# Inputs are the runtime root path. Processing verifies that the path exists as
# a directory and inspects ACL rules for the current token. Return behavior is a
# readiness object; failure means the runner should not assume it can create job
# folders there. This function intentionally does not create a probe file.
function Test-RuntimeRootWritableReadOnly {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return New-ReadinessResult `
            -Name 'Runtime root writable' `
            -Status 'Failed' `
            -Required $true `
            -Message 'Runtime root path is empty.' `
            -Details @{
                RuntimeRoot       = $Path
                WriteProbeCreated = $false
            }
    }

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        return New-ReadinessResult `
            -Name 'Runtime root writable' `
            -Status 'Failed' `
            -Required $true `
            -Message "Runtime root '$Path' does not exist as a directory; read-only preflight cannot verify writability." `
            -Details @{
                RuntimeRoot       = $Path
                Exists            = $false
                WriteProbeCreated = $false
            }
    }

    try {
        $item = Get-Item -LiteralPath $Path -ErrorAction Stop
        $acl = Get-Acl -LiteralPath $item.FullName -ErrorAction Stop
        $rules = $acl.GetAccessRules(
            $true,
            $true,
            [System.Security.Principal.SecurityIdentifier])
        $currentSidValues = @(Get-CurrentTokenSidValues)
    }
    catch {
        return New-ReadinessResult `
            -Name 'Runtime root writable' `
            -Status 'Failed' `
            -Required $true `
            -Message "Unable to inspect runtime root ACLs without writing a probe file: $($_.Exception.Message)" `
            -Details @{
                RuntimeRoot       = $Path
                ErrorType         = $_.Exception.GetType().FullName
                WriteProbeCreated = $false
            }
    }

    $matchingAllowRules = 0
    $matchingDenyRules = 0
    foreach ($rule in $rules) {
        if ($currentSidValues -notcontains $rule.IdentityReference.Value) {
            continue
        }

        if (-not (Test-FileSystemRightsIncludeWrite -Rights $rule.FileSystemRights)) {
            continue
        }

        if ($rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny) {
            $matchingDenyRules++
            continue
        }

        if ($rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow) {
            $matchingAllowRules++
        }
    }

    if ($matchingDenyRules -gt 0) {
        return New-ReadinessResult `
            -Name 'Runtime root writable' `
            -Status 'Failed' `
            -Required $true `
            -Message "Runtime root '$($item.FullName)' has write-capable deny ACL entries for the current token." `
            -Details @{
                RuntimeRoot            = $item.FullName
                MatchingAllowRuleCount = $matchingAllowRules
                MatchingDenyRuleCount  = $matchingDenyRules
                WriteProbeCreated      = $false
            }
    }

    if ($matchingAllowRules -gt 0) {
        return New-ReadinessResult `
            -Name 'Runtime root writable' `
            -Status 'Passed' `
            -Required $true `
            -Message "Runtime root '$($item.FullName)' appears writable based on read-only ACL inspection." `
            -Details @{
                RuntimeRoot            = $item.FullName
                MatchingAllowRuleCount = $matchingAllowRules
                MatchingDenyRuleCount  = $matchingDenyRules
                WriteProbeCreated      = $false
            }
    }

    return New-ReadinessResult `
        -Name 'Runtime root writable' `
        -Status 'Failed' `
        -Required $true `
        -Message "Runtime root '$($item.FullName)' has no write-capable allow ACL entry for the current token." `
        -Details @{
            RuntimeRoot            = $item.FullName
            MatchingAllowRuleCount = $matchingAllowRules
            MatchingDenyRuleCount  = $matchingDenyRules
            WriteProbeCreated      = $false
        }
}

# Test-HyperVVm checks that the requested golden VM can be read.
# Inputs are the VM name plus precomputed module/admin readiness. Processing
# skips Get-VM when the current process cannot reliably query Hyper-V. Return
# behavior is a readiness object; non-admin unreadability is surfaced as a
# warning because the Administrator check is the primary failure.
function Test-HyperVVm {
    param(
        [string]$Name,
        [bool]$HyperVAvailable,
        [bool]$IsAdministrator
    )

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return New-ReadinessResult `
            -Name 'Target VM' `
            -Status 'Failed' `
            -Required $true `
            -Message 'Target VM name is empty.' `
            -Details @{
                VmName = $Name
            }
    }

    if (-not $HyperVAvailable) {
        return New-ReadinessResult `
            -Name 'Target VM' `
            -Status 'Warning' `
            -Required $true `
            -Message "Skipped VM lookup for '$Name' because Hyper-V module readiness failed." `
            -Details @{
                VmName  = $Name
                Skipped = $true
                Reason  = 'Hyper-V module or required cmdlets unavailable'
            }
    }

    if (-not $IsAdministrator) {
        return New-ReadinessResult `
            -Name 'Target VM' `
            -Status 'Warning' `
            -Required $true `
            -Message "Skipped VM lookup for '$Name' because the current process is not Administrator." `
            -Details @{
                VmName  = $Name
                Skipped = $true
                Reason  = 'Non-administrator process cannot reliably enumerate Hyper-V state'
            }
    }

    try {
        $vmMatches = @(Get-VM -Name $Name -ErrorAction Stop |
            Where-Object { $_.Name -eq $Name })

        if ($vmMatches.Count -eq 0) {
            return New-ReadinessResult `
                -Name 'Target VM' `
                -Status 'Failed' `
                -Required $true `
                -Message "No exact VM named '$Name' was found." `
                -Details @{
                    VmName = $Name
                }
        }

        $vm = $vmMatches[0]
        return New-ReadinessResult `
            -Name 'Target VM' `
            -Status 'Passed' `
            -Required $true `
            -Message "Target VM '$Name' exists and is readable." `
            -Details @{
                VmName     = $vm.Name
                VmId       = $vm.Id.ToString()
                State      = $vm.State.ToString()
                Generation = $vm.Generation
            }
    }
    catch {
        return New-ReadinessResult `
            -Name 'Target VM' `
            -Status 'Failed' `
            -Required $true `
            -Message "Unable to read target VM '$Name': $($_.Exception.Message)" `
            -Details @{
                VmName    = $Name
                ErrorType = $_.Exception.GetType().FullName
            }
    }
}

# Test-HyperVCheckpoint checks that the configured clean checkpoint exists.
# Inputs are VM/checkpoint names plus precomputed query readiness. Processing
# uses Get-VMSnapshot only when it is safe to query Hyper-V. Return behavior is
# a readiness object; the script never creates or restores the checkpoint.
function Test-HyperVCheckpoint {
    param(
        [string]$Name,
        [string]$Vm,
        [bool]$CanQueryVmState
    )

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return New-ReadinessResult `
            -Name 'Clean checkpoint' `
            -Status 'Failed' `
            -Required $true `
            -Message 'Checkpoint name is empty.' `
            -Details @{
                VmName         = $Vm
                CheckpointName = $Name
            }
    }

    if (-not $CanQueryVmState) {
        return New-ReadinessResult `
            -Name 'Clean checkpoint' `
            -Status 'Warning' `
            -Required $true `
            -Message "Skipped checkpoint lookup for '$Name' because VM state is not queryable in this session." `
            -Details @{
                VmName         = $Vm
                CheckpointName = $Name
                Skipped        = $true
            }
    }

    try {
        $snapshots = @(Get-VMSnapshot -VMName $Vm -Name $Name -ErrorAction Stop |
            Where-Object { $_.Name -eq $Name })

        if ($snapshots.Count -eq 0) {
            return New-ReadinessResult `
                -Name 'Clean checkpoint' `
                -Status 'Failed' `
                -Required $true `
                -Message "No exact checkpoint named '$Name' was found on VM '$Vm'." `
                -Details @{
                    VmName         = $Vm
                    CheckpointName = $Name
                }
        }

        $snapshot = $snapshots[0]
        return New-ReadinessResult `
            -Name 'Clean checkpoint' `
            -Status 'Passed' `
            -Required $true `
            -Message "Checkpoint '$Name' exists on VM '$Vm'." `
            -Details @{
                VmName         = $Vm
                CheckpointName = $snapshot.Name
                CheckpointId   = $snapshot.Id.ToString()
                CreationTime   = $snapshot.CreationTime
            }
    }
    catch {
        return New-ReadinessResult `
            -Name 'Clean checkpoint' `
            -Status 'Failed' `
            -Required $true `
            -Message "Unable to read checkpoint '$Name' on VM '$Vm': $($_.Exception.Message)" `
            -Details @{
                VmName         = $Vm
                CheckpointName = $Name
                ErrorType      = $_.Exception.GetType().FullName
            }
    }
}

# Test-GuestServiceInterface checks that Copy-VMFile support is enabled.
# Inputs are the VM name and query readiness. Processing reads Hyper-V
# integration services only. Return behavior is a readiness object; the script
# never enables/disables services or copies files into the VM.
function Test-GuestServiceInterface {
    param(
        [string]$Vm,
        [bool]$CanQueryVmState
    )

    $serviceName = 'Guest Service Interface'

    if (-not $CanQueryVmState) {
        return New-ReadinessResult `
            -Name 'Guest Service Interface' `
            -Status 'Warning' `
            -Required $true `
            -Message "Skipped Guest Service Interface lookup because VM state is not queryable in this session." `
            -Details @{
                VmName      = $Vm
                ServiceName = $serviceName
                Skipped     = $true
            }
    }

    try {
        $services = @(Get-VMIntegrationService -VMName $Vm -ErrorAction Stop |
            Where-Object { $_.Name -eq $serviceName })

        if ($services.Count -eq 0) {
            return New-ReadinessResult `
                -Name 'Guest Service Interface' `
                -Status 'Failed' `
                -Required $true `
                -Message "Integration service '$serviceName' was not found on VM '$Vm'." `
                -Details @{
                    VmName      = $Vm
                    ServiceName = $serviceName
                }
        }

        $service = $services[0]
        if ([bool]$service.Enabled) {
            return New-ReadinessResult `
                -Name 'Guest Service Interface' `
                -Status 'Passed' `
                -Required $true `
                -Message "Integration service '$serviceName' is enabled on VM '$Vm'." `
                -Details @{
                    VmName      = $Vm
                    ServiceName = $service.Name
                    Enabled     = [bool]$service.Enabled
                }
        }

        return New-ReadinessResult `
            -Name 'Guest Service Interface' `
            -Status 'Failed' `
            -Required $true `
            -Message "Integration service '$serviceName' is disabled on VM '$Vm'." `
            -Details @{
                VmName      = $Vm
                ServiceName = $service.Name
                Enabled     = [bool]$service.Enabled
            }
    }
    catch {
        return New-ReadinessResult `
            -Name 'Guest Service Interface' `
            -Status 'Failed' `
            -Required $true `
            -Message "Unable to read Guest Service Interface state on VM '$Vm': $($_.Exception.Message)" `
            -Details @{
                VmName      = $Vm
                ServiceName = $serviceName
                ErrorType   = $_.Exception.GetType().FullName
            }
    }
}

$results = New-Object System.Collections.Generic.List[object]

$administratorResult = Test-AdministratorPrivilege
[void]$results.Add($administratorResult)

$hyperVModuleResult = Test-HyperVModule
[void]$results.Add($hyperVModuleResult)

$guestSecretResult = Test-GuestPasswordSecret -SecretName $GuestPasswordSecretName
[void]$results.Add($guestSecretResult)

$runtimeRootResult = Test-RuntimeRootWritableReadOnly -Path $RuntimeRoot
[void]$results.Add($runtimeRootResult)

$isAdministrator = $administratorResult.Status -eq 'Passed'
$isHyperVAvailable = $hyperVModuleResult.Status -eq 'Passed'

$vmResult = Test-HyperVVm `
    -Name $VmName `
    -HyperVAvailable $isHyperVAvailable `
    -IsAdministrator $isAdministrator
[void]$results.Add($vmResult)

$canQueryVmState = $isAdministrator `
    -and $isHyperVAvailable `
    -and ($vmResult.Status -eq 'Passed')

$checkpointResult = Test-HyperVCheckpoint `
    -Name $CheckpointName `
    -Vm $VmName `
    -CanQueryVmState $canQueryVmState
[void]$results.Add($checkpointResult)

$guestServiceResult = Test-GuestServiceInterface `
    -Vm $VmName `
    -CanQueryVmState $canQueryVmState
[void]$results.Add($guestServiceResult)

$failedCount = @($results | Where-Object { $_.Status -eq 'Failed' }).Count
$warningCount = @($results | Where-Object { $_.Status -eq 'Warning' }).Count
$passedCount = @($results | Where-Object { $_.Status -eq 'Passed' }).Count
$exitCode = if ($failedCount -gt 0) { 1 } else { 0 }
$overallStatus = if ($failedCount -gt 0) {
    'Failed'
}
elseif ($warningCount -gt 0) {
    'Warning'
}
else {
    'Passed'
}

foreach ($result in $results) {
    Write-Output $result
}

Write-Output ([pscustomobject][ordered]@{
        ResultType     = 'ReadinessSummary'
        OverallStatus  = $overallStatus
        ExitCode       = $exitCode
        PassedCount    = $passedCount
        WarningCount   = $warningCount
        FailedCount    = $failedCount
        VmName         = $VmName
        CheckpointName = $CheckpointName
        RuntimeRoot    = $RuntimeRoot
        ReadOnly       = $true
        Note           = 'No probe files were written and no VM mutation commands were executed.'
    })

exit $exitCode
