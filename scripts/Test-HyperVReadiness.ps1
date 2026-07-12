<#
.SYNOPSIS
Runs read-only Hyper-V readiness checks for KSword Sandbox live VM runs.

.DESCRIPTION
Inputs are the golden VM name, checkpoint name, guest credential metadata, host
payload root, and host runtime root path. Processing validates local host and
golden-VM prerequisites without creating probe files and without creating,
starting, restoring, stopping, or deleting any VM. The script emits structured
PowerShell objects for each check plus a summary object. It returns exit code 0
when no check failed, or exit code 1 when at least one check failed.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
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

    # Input: local guest account name used for PowerShell Direct.
    # Processing: used only to construct an in-memory PSCredential when the
    # password secret is visible; the script never prints the password.
    # Return behavior: a failed or skipped PowerShell Direct result identifies
    # missing credential metadata without mutating the VM.
    [string]$GuestUserName = 'SandboxUser',

    # Input: guest root path from config/sandbox.example.json.
    # Processing: used to build expected guest payload file paths for read-only
    # Test-Path probes through PowerShell Direct when the VM is already running.
    # Return behavior: guest path checks are skipped with diagnostics when
    # PowerShell Direct cannot be safely attempted.
    [string]$GuestWorkingDirectory = 'C:\KSwordSandbox',

    # Input: expected guest agent executable name under the agent payload folder.
    # Processing: used for host and guest payload file checks only.
    # Return behavior: the file is never executed by this readiness script.
    [string]$GuestAgentExecutableName = 'KSword.Sandbox.Agent.exe',

    # Input: host-staged guest payload root from config/sandbox.example.json.
    # Processing: checks required payload files with Test-Path only.
    # Return behavior: no payload files are built, copied, or deleted.
    [string]$GuestPayloadRoot = 'D:\Temp\KSwordSandbox\payload\guest-tools',

    # Input: expected R0Collector executable name under the r0collector payload
    # folder. Processing uses it for host and guest payload file checks only.
    # Return behavior: the file is never executed by this readiness script.
    [string]$R0CollectorExecutableName = 'KSword.Sandbox.R0Collector.exe',

    # Input: host runtime root from config/sandbox.example.json.
    # Processing: checks existence and ACLs only; no write probe file is made.
    # Return behavior: a failed result is emitted when writability cannot be
    # inferred from read-only ACL inspection.
    [string]$RuntimeRoot = 'D:\Temp\KSwordSandbox',

    # Input: optional sandbox config path. When omitted, the script attempts to
    # reuse the installed local config path from Sandbox__ConfigPath or
    # %ProgramData%\KSwordSandbox\install-state.json before falling back to the
    # repository example config.
    [string]$ConfigPath = '',

    # Input: optional install state path written by install.ps1. Processing is
    # read-only and never writes local install metadata.
    [string]$InstallStatePath = $(if ([string]::IsNullOrWhiteSpace($env:ProgramData)) { '' } else { Join-Path $env:ProgramData 'KSwordSandbox\install-state.json' }),

    # Input: repository root for config fallback and local secret-hygiene scan.
    # Processing is read-only. Leave empty to infer the parent of scripts/.
    [string]$RepositoryRoot = '',

    # Input: ignore installed state/env config and use only explicit parameters
    # plus the repository example config fallback.
    [switch]$IgnoreInstalledConfig,

    # Input: if the password is missing, prompt once and put it in Process scope
    # only. The value is never printed, persisted, or written to disk.
    [switch]$PromptForMissingGuestPassword,

    # Input: skip the read-only scan that prevents the current guest password
    # value from being committed in tracked/untracked repository text files.
    [switch]$SkipRepositorySecretScan,

    # Input: include a read-only inventory of available Hyper-V VM/checkpoint
    # profile candidates. Processing uses Get-VM/Get-VMSnapshot only and never
    # starts, restores, or changes a VM. Return behavior adds one optional
    # readiness row operators can use to choose -VmName/-CheckpointName.
    [switch]$ListAvailableVmProfiles,

    # Input: maximum VM/checkpoint candidates to include in the optional
    # profile inventory and failure diagnostics.
    [ValidateRange(1, 100)]
    [int]$VmProfileListLimit = 20
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$script:GuestServiceInterfaceComponentId = '6C09BB55-D683-4DA0-8931-C9BF705F6480'
$script:InitialBoundParameters = @{}
foreach ($parameterName in $PSBoundParameters.Keys) {
    $script:InitialBoundParameters[$parameterName] = $true
}
$script:ReadinessInputMetadata = $null

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

# ConvertFrom-SecureStringToPlainText converts a prompt-only secure string into
# a transient process environment value. Inputs are a SecureString from
# Read-Host -AsSecureString. Processing zeroes the unmanaged buffer. Return
# behavior is one plaintext string kept in memory only long enough to set the
# process environment variable.
function ConvertFrom-SecureStringToPlainText {
    param([Parameter(Mandatory)][securestring]$SecureString)

    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringUni($bstr)
    }
    finally {
        if ($bstr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }
}

# Get-DefaultRepositoryRoot infers the repository root from this script path.
# Inputs are none; processing resolves the parent directory of scripts/.
# Return behavior is an absolute path string.
function Get-DefaultRepositoryRoot {
    if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        return (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).ProviderPath
    }

    return (Get-Location).ProviderPath
}

# Get-ObjectPropertyString safely reads a string property from a PSCustomObject.
# Inputs are an object, property name, and default value. Processing performs no
# mutation. Return behavior is the non-empty string value or the default.
function Get-ObjectPropertyString {
    param(
        [AllowNull()]$Object,
        [Parameter(Mandatory)][string]$Name,
        [string]$DefaultValue = ''
    )

    if ($null -eq $Object) {
        return $DefaultValue
    }

    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) {
        return $DefaultValue
    }

    $value = [string]$property.Value
    if ([string]::IsNullOrWhiteSpace($value)) {
        return $DefaultValue
    }

    return $value
}

# Get-ObjectPropertyBoolean safely reads a Boolean config property from a
# PSCustomObject. Inputs are an object, property name, and default. Processing
# tolerates absent/null properties. Return behavior is a Boolean.
function Get-ObjectPropertyBoolean {
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

    return [System.Convert]::ToBoolean($property.Value)
}

# Resolve-ConfigRelativePath expands a config path relative to the repository.
# Inputs are a possibly empty path and base root. Processing is read-only.
# Return behavior is null for absent values, otherwise a full path string.
function Resolve-ConfigRelativePath {
    param(
        [AllowNull()][string]$Path,
        [Parameter(Mandatory)][string]$BasePath
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $null
    }

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath((Join-Path $BasePath $Path))
}

# Get-ObjectPropertyObject safely reads a nested object property from a
# PSCustomObject under StrictMode. Inputs are the object and property name.
# Return behavior is the property value or $null.
function Get-ObjectPropertyObject {
    param(
        [AllowNull()]$Object,
        [Parameter(Mandatory)][string]$Name
    )

    if ($null -eq $Object) {
        return $null
    }

    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}

# Read-JsonObjectIfPresent reads a JSON object if the file exists. Inputs are a
# path and logical name. Processing is read-only. Return behavior includes the
# parsed object and a diagnostic string.
function Read-JsonObjectIfPresent {
    param(
        [string]$Path,
        [string]$Name
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return [pscustomobject][ordered]@{
            Path   = ''
            Exists = $false
            Object = $null
            Error  = ''
            Name   = $Name
        }
    }

    try {
        $resolved = if (Test-Path -LiteralPath $Path -PathType Leaf) {
            (Resolve-Path -LiteralPath $Path).ProviderPath
        }
        else {
            [System.IO.Path]::GetFullPath($Path)
        }

        if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
            return [pscustomobject][ordered]@{
                Path   = $resolved
                Exists = $false
                Object = $null
                Error  = ''
                Name   = $Name
            }
        }

        return [pscustomobject][ordered]@{
            Path   = $resolved
            Exists = $true
            Object = (Get-Content -LiteralPath $resolved -Raw | ConvertFrom-Json)
            Error  = ''
            Name   = $Name
        }
    }
    catch {
        return [pscustomobject][ordered]@{
            Path   = $Path
            Exists = $false
            Object = $null
            Error  = $_.Exception.Message
            Name   = $Name
        }
    }
}

# Get-EnvironmentValueByScope returns the first non-empty variable value from
# Process, User, then Machine scope. Inputs are the variable name. Return
# behavior includes value presence without printing the value.
function Get-EnvironmentValueByScope {
    param([Parameter(Mandatory)][string]$Name)

    foreach ($scope in @('Process', 'User', 'Machine')) {
        $value = [Environment]::GetEnvironmentVariable($Name, $scope)
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            return [pscustomobject][ordered]@{
                Value = $value
                Scope = $scope
                IsSet = $true
            }
        }
    }

    return [pscustomobject][ordered]@{
        Value = ''
        Scope = ''
        IsSet = $false
    }
}

# Set-ReadinessParameterDefault updates a script parameter only when the caller
# did not explicitly bind that parameter. Inputs are the variable/parameter name
# and candidate values ordered by precedence. Processing mutates script-scope
# parameter variables only. Return behavior is none.
function Set-ReadinessParameterDefault {
    param(
        [Parameter(Mandatory)][string]$VariableName,
        [Parameter(Mandatory)][string]$ParameterName,
        [string[]]$Candidates
    )

    if ($script:InitialBoundParameters.ContainsKey($ParameterName)) {
        return
    }

    foreach ($candidate in $Candidates) {
        if (-not [string]::IsNullOrWhiteSpace($candidate)) {
            Set-Variable -Name $VariableName -Scope Script -Value $candidate
            return
        }
    }
}

# Resolve-ReadinessInputConfiguration aligns Test-HyperVReadiness.ps1 with the
# install.ps1/run.ps1 local config flow. Inputs are explicit parameter values,
# optional install state, and optional sandbox config. Processing reads only
# local JSON metadata and updates unbound parameters. Return behavior is a
# metadata object included in the summary.
function Resolve-ReadinessInputConfiguration {
    $resolvedRepositoryRoot = if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
        Get-DefaultRepositoryRoot
    }
    else {
        [System.IO.Path]::GetFullPath($RepositoryRoot)
    }
    $script:RepositoryRoot = $resolvedRepositoryRoot

    $stateInfo = [pscustomobject][ordered]@{
        Path   = ''
        Exists = $false
        Object = $null
        Error  = ''
        Name   = 'install-state'
    }
    if (-not [bool]$IgnoreInstalledConfig) {
        $stateInfo = Read-JsonObjectIfPresent -Path $InstallStatePath -Name 'install-state'
    }

    $effectiveConfigPath = $ConfigPath
    $configSource = 'explicit'
    if ([string]::IsNullOrWhiteSpace($effectiveConfigPath) -and (-not [bool]$IgnoreInstalledConfig)) {
        $envConfig = Get-EnvironmentValueByScope -Name 'Sandbox__ConfigPath'
        if ([bool]$envConfig.IsSet) {
            $effectiveConfigPath = [string]$envConfig.Value
            $configSource = "Sandbox__ConfigPath:$($envConfig.Scope)"
        }
    }

    if ([string]::IsNullOrWhiteSpace($effectiveConfigPath) -and $null -ne $stateInfo.Object) {
        $stateConfig = Get-ObjectPropertyString -Object $stateInfo.Object -Name 'localConfigPath'
        if (-not [string]::IsNullOrWhiteSpace($stateConfig)) {
            $effectiveConfigPath = $stateConfig
            $configSource = 'install-state.localConfigPath'
        }
    }

    if ([string]::IsNullOrWhiteSpace($effectiveConfigPath)) {
        $effectiveConfigPath = Join-Path $resolvedRepositoryRoot 'config\sandbox.example.json'
        $configSource = 'repository-example'
    }

    $configInfo = Read-JsonObjectIfPresent -Path $effectiveConfigPath -Name 'sandbox-config'
    $config = $configInfo.Object
    $state = $stateInfo.Object
    $hyperV = Get-ObjectPropertyObject -Object $config -Name 'hyperV'
    $guest = Get-ObjectPropertyObject -Object $config -Name 'guest'
    $paths = Get-ObjectPropertyObject -Object $config -Name 'paths'
    $driver = Get-ObjectPropertyObject -Object $config -Name 'driver'
    $driverEnabled = Get-ObjectPropertyBoolean -Object $driver -Name 'enabled' -DefaultValue $true
    $driverUseMockCollector = Get-ObjectPropertyBoolean -Object $driver -Name 'useMockCollector' -DefaultValue $false
    $driverHostPath = Resolve-ConfigRelativePath `
        -Path (Get-ObjectPropertyString -Object $driver -Name 'hostDriverPath') `
        -BasePath $resolvedRepositoryRoot
    $driverPathInGuest = Get-ObjectPropertyString -Object $driver -Name 'driverPathInGuest' -DefaultValue 'C:\KSwordSandbox\driver\KSwordARKDriver.sys'
    $driverDevicePath = Get-ObjectPropertyString -Object $driver -Name 'devicePath' -DefaultValue '\\.\KSwordSandboxDriver'

    $collectorLeaf = ''
    $collectorPath = Get-ObjectPropertyString -Object $driver -Name 'r0CollectorPathInGuest'
    if (-not [string]::IsNullOrWhiteSpace($collectorPath)) {
        $collectorLeaf = Split-Path -Leaf $collectorPath
    }

    Set-ReadinessParameterDefault -VariableName 'VmName' -ParameterName 'VmName' -Candidates @(
        (Get-ObjectPropertyString -Object $state -Name 'vmName'),
        (Get-ObjectPropertyString -Object $hyperV -Name 'goldenVmName'))
    Set-ReadinessParameterDefault -VariableName 'CheckpointName' -ParameterName 'CheckpointName' -Candidates @(
        (Get-ObjectPropertyString -Object $state -Name 'checkpointName'),
        (Get-ObjectPropertyString -Object $hyperV -Name 'goldenSnapshotName'))
    Set-ReadinessParameterDefault -VariableName 'GuestPasswordSecretName' -ParameterName 'GuestPasswordSecretName' -Candidates @(
        (Get-ObjectPropertyString -Object $state -Name 'secretName'),
        (Get-ObjectPropertyString -Object $guest -Name 'passwordSecretName'))
    Set-ReadinessParameterDefault -VariableName 'GuestUserName' -ParameterName 'GuestUserName' -Candidates @(
        (Get-ObjectPropertyString -Object $state -Name 'guestUserName'),
        (Get-ObjectPropertyString -Object $guest -Name 'userName'))
    Set-ReadinessParameterDefault -VariableName 'GuestWorkingDirectory' -ParameterName 'GuestWorkingDirectory' -Candidates @(
        (Get-ObjectPropertyString -Object $state -Name 'guestWorkingDirectory'),
        (Get-ObjectPropertyString -Object $guest -Name 'workingDirectory'))
    Set-ReadinessParameterDefault -VariableName 'GuestAgentExecutableName' -ParameterName 'GuestAgentExecutableName' -Candidates @(
        (Get-ObjectPropertyString -Object $guest -Name 'agentExecutableName'))
    Set-ReadinessParameterDefault -VariableName 'GuestPayloadRoot' -ParameterName 'GuestPayloadRoot' -Candidates @(
        (Get-ObjectPropertyString -Object $state -Name 'guestPayloadRoot'),
        (Get-ObjectPropertyString -Object $paths -Name 'guestPayloadRoot'))
    Set-ReadinessParameterDefault -VariableName 'R0CollectorExecutableName' -ParameterName 'R0CollectorExecutableName' -Candidates @($collectorLeaf)
    Set-ReadinessParameterDefault -VariableName 'RuntimeRoot' -ParameterName 'RuntimeRoot' -Candidates @(
        (Get-ObjectPropertyString -Object $state -Name 'runtimeRoot'),
        (Get-ObjectPropertyString -Object $paths -Name 'runtimeRoot'))

    return [pscustomobject][ordered]@{
        RepositoryRoot        = $resolvedRepositoryRoot
        ConfigPath            = $configInfo.Path
        ConfigSource          = $configSource
        ConfigLoaded          = [bool]$configInfo.Exists
        ConfigReadError       = $configInfo.Error
        InstallStatePath      = $stateInfo.Path
        InstallStateLoaded    = [bool]$stateInfo.Exists
        InstallStateReadError = $stateInfo.Error
        IgnoredInstalledConfig = [bool]$IgnoreInstalledConfig
        DriverEnabled = $driverEnabled
        DriverUseMockCollector = $driverUseMockCollector
        DriverHostPath = $driverHostPath
        DriverPathInGuest = $driverPathInGuest
        DriverDevicePath = $driverDevicePath
        ExplicitParameters    = @($script:InitialBoundParameters.Keys | Sort-Object)
        SecretValuePrinted    = $false
        WroteFiles            = $false
    }
}

# Import-GuestPasswordFromPrompt optionally fills the current process secret
# only. Inputs are the secret name and the opt-in switch. Processing prompts
# with Read-Host -AsSecureString and writes only Process scope. Return behavior
# is metadata; no secret value is printed or persisted.
function Import-GuestPasswordFromPrompt {
    param(
        [Parameter(Mandatory)][string]$SecretName,
        [bool]$Prompt
    )

    if (-not $Prompt) {
        return [pscustomobject][ordered]@{
            PromptAttempted      = $false
            PromptSucceeded      = $false
            ProcessSecretUpdated = $false
            SecretValuePrinted   = $false
        }
    }

    if ([string]::IsNullOrWhiteSpace($SecretName) -or $SecretName.Contains('=')) {
        return [pscustomobject][ordered]@{
            PromptAttempted      = $false
            PromptSucceeded      = $false
            ProcessSecretUpdated = $false
            SecretValuePrinted   = $false
        }
    }

    $current = Get-GuestPasswordSecretValue -SecretName $SecretName
    if ([bool]$current.IsSet) {
        return [pscustomobject][ordered]@{
            PromptAttempted      = $false
            PromptSucceeded      = $false
            ProcessSecretUpdated = $false
            SecretValuePrinted   = $false
        }
    }

    if (-not $PSCmdlet.ShouldProcess($SecretName, 'Set process-only guest password secret for readiness probe')) {
        return [pscustomobject][ordered]@{
            PromptAttempted      = $false
            PromptSucceeded      = $false
            ProcessSecretUpdated = $false
            SecretValuePrinted   = $false
            WhatIfSkipped        = $true
        }
    }

    $secure = Read-Host "Enter guest password for $SecretName (stored in this PowerShell process only)" -AsSecureString
    $plainText = ConvertFrom-SecureStringToPlainText -SecureString $secure
    try {
        if ([string]::IsNullOrEmpty($plainText)) {
            return [pscustomobject][ordered]@{
                PromptAttempted      = $true
                PromptSucceeded      = $false
                ProcessSecretUpdated = $false
                SecretValuePrinted   = $false
            }
        }

        [Environment]::SetEnvironmentVariable($SecretName, $plainText, 'Process')
        Set-Item -Path "Env:\$SecretName" -Value $plainText
        return [pscustomobject][ordered]@{
            PromptAttempted      = $true
            PromptSucceeded      = $true
            ProcessSecretUpdated = $true
            SecretValuePrinted   = $false
        }
    }
    finally {
        $plainText = $null
    }
}

# ConvertTo-ReadinessCheckId converts a display name into a stable machine id.
# Inputs are a human-readable check name; processing lowercases and replaces
# non-alphanumeric runs with hyphens. Return behavior is one short string for
# JSON consumers that should not key off localized/user-facing text.
function ConvertTo-ReadinessCheckId {
    param([AllowNull()][string]$Name)

    $value = if ([string]::IsNullOrWhiteSpace($Name)) { 'readiness-check' } else { $Name.Trim() }
    $slug = [regex]::Replace($value.ToLowerInvariant(), '[^a-z0-9]+', '-').Trim('-')
    if ([string]::IsNullOrWhiteSpace($slug)) {
        return 'readiness-check'
    }

    return $slug
}

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
        [System.Collections.IDictionary]$Details = @{},
        [string[]]$Remediation = @(),
        [string]$Category = 'general'
    )

    $orderedDetails = [ordered]@{}
    foreach ($key in $Details.Keys) {
        $orderedDetails[$key] = $Details[$key]
    }

    return [pscustomobject][ordered]@{
        ResultType      = 'ReadinessCheck'
        CheckId         = ConvertTo-ReadinessCheckId -Name $Name
        Category        = $Category
        Name            = $Name
        Status          = $Status
        Required        = $Required
        RequiredForLive = $Required
        MachineReadable = $true
        Message         = $Message
        Remediation = @($Remediation)
        Details         = [pscustomobject]$orderedDetails
    }
}

# Get-ReadinessRecommendedActions collapses remediation text from all failing
# or warning checks into a short unique operator action list. Inputs are emitted
# readiness result objects; processing is read-only. Return behavior is an
# ordered string array suitable for the final summary and human-readable output.
function Get-ReadinessRecommendedActions {
    param([Parameter(Mandatory)][object[]]$Results)

    $actions = New-Object System.Collections.Generic.List[string]
    foreach ($result in $Results) {
        if ($null -eq $result -or $result.Status -eq 'Passed') {
            continue
        }

        $remediationProperty = $result.PSObject.Properties['Remediation']
        if ($null -eq $remediationProperty) {
            continue
        }

        foreach ($item in @($remediationProperty.Value)) {
            $text = [string]$item
            if (-not [string]::IsNullOrWhiteSpace($text) -and -not $actions.Contains($text)) {
                [void]$actions.Add($text)
            }
        }
    }

    return @($actions.ToArray())
}

# Test-ReadinessInputResolution reports which local install/run configuration
# source supplied effective readiness inputs. Inputs are the metadata object from
# Resolve-ReadinessInputConfiguration and prompt metadata. Processing is
# read-only. Return behavior is a non-failing readiness object for operators and
# automation.
function Test-ReadinessInputResolution {
    param(
        [Parameter(Mandatory)][object]$Metadata,
        [Parameter(Mandatory)][object]$PromptMetadata
    )

    $status = 'Passed'
    $message = "Readiness inputs resolved from $($Metadata.ConfigSource)."
    $remediation = @()
    if ([string]$Metadata.ConfigSource -eq 'repository-example') {
        $status = 'Warning'
        $message = 'Readiness is using repository example config; fresh computers should create local config outside git before live execution.'
        $remediation = @(
            'Run .\install.ps1 -InstallEntrypoint CreateOrPreparePath -PromptPassword, then use -UpdateHyperVConfig to record the real VM/checkpoint; do not edit config\sandbox.example.json.',
            '下一步：运行 .\install.ps1 -InstallEntrypoint CreateOrPreparePath -PromptPassword，然后用 -UpdateHyperVConfig 记录真实 VM/checkpoint；不要编辑 config\sandbox.example.json。'
        )
    }
    elseif (-not [bool]$Metadata.ConfigLoaded) {
        $status = 'Warning'
        $message = "Sandbox config was not loaded from '$($Metadata.ConfigPath)'; explicit/default parameters are in use."
        $remediation = @('Create local config with .\install.ps1 -InstallEntrypoint CreateOrPreparePath before live execution.')
    }

    return New-ReadinessResult `
        -Name 'Readiness input resolution' `
        -Status $status `
        -Required $false `
        -Message $message `
        -Remediation $remediation `
        -Details @{
            RepositoryRoot         = $Metadata.RepositoryRoot
            ConfigPath             = $Metadata.ConfigPath
            ConfigSource           = $Metadata.ConfigSource
            ConfigLoaded           = [bool]$Metadata.ConfigLoaded
            ConfigReadError        = $Metadata.ConfigReadError
            InstallStatePath       = $Metadata.InstallStatePath
            InstallStateLoaded     = [bool]$Metadata.InstallStateLoaded
            InstallStateReadError  = $Metadata.InstallStateReadError
            IgnoredInstalledConfig = [bool]$Metadata.IgnoredInstalledConfig
            ExplicitParameters     = @($Metadata.ExplicitParameters)
            PromptAttempted        = [bool]$PromptMetadata.PromptAttempted
            PromptSucceeded        = [bool]$PromptMetadata.PromptSucceeded
            ProcessSecretUpdated   = [bool]$PromptMetadata.ProcessSecretUpdated
            SecretValuePrinted     = $false
            WroteFiles             = $false
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
            } `
            -Remediation @('Open PowerShell as Administrator for live Hyper-V readiness, or use .\run.ps1 -Mode CheckEnvironment / .\run.ps1 -Mode Plan for non-mutating checks from a normal shell.')
    }
    catch {
        return New-ReadinessResult `
            -Name 'Administrator privilege' `
            -Status 'Failed' `
            -Required $true `
            -Message "Unable to determine Administrator status: $($_.Exception.Message)" `
            -Details @{
                ErrorType = $_.Exception.GetType().FullName
                ErrorMessage = $_.Exception.Message
            } `
            -Remediation @('Open a new PowerShell session and rerun .\scripts\Test-HyperVReadiness.ps1; live VM operations require an elevated Windows shell.')
    }
}

# Test-HyperVFeatureState checks whether the host appears to have Hyper-V
# installed/enabled without changing Windows optional features or services.
# Inputs are none; processing queries Windows optional-feature metadata and the
# VMMS service when available. Return behavior is one machine-readable readiness
# object; no service start or feature enable action is attempted.
function Test-HyperVFeatureState {
    try {
        $hostIsWindows = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
            [System.Runtime.InteropServices.OSPlatform]::Windows)
    }
    catch {
        $hostIsWindows = $false
    }

    if (-not $hostIsWindows) {
        return New-ReadinessResult `
            -Name 'Hyper-V feature enabled' `
            -Category 'host' `
            -Status 'Failed' `
            -Required $true `
            -Message 'Live Hyper-V runs require a Windows host with Hyper-V enabled.' `
            -Details @{
                IsWindows = $false
                FeatureQueryAttempted = $false
                VmmsServiceQueryAttempted = $false
                ReadOnly = $true
            } `
            -Remediation @('Run live Hyper-V analysis on a Windows Pro/Enterprise/Education host with Hyper-V enabled; use PlanOnly/WhatIf on non-Windows hosts.')
    }

    $featureNames = @('Microsoft-Hyper-V-All', 'Microsoft-Hyper-V', 'Microsoft-Hyper-V-Hypervisor')
    $featureStates = New-Object System.Collections.Generic.List[object]
    $featureQueryAttempted = $false
    $featureQueryError = ''
    $anyFeatureEnabled = $false

    if ($null -ne (Get-Command -Name Get-WindowsOptionalFeature -ErrorAction SilentlyContinue)) {
        $featureQueryAttempted = $true
        foreach ($featureName in $featureNames) {
            try {
                $feature = Get-WindowsOptionalFeature -Online -FeatureName $featureName -ErrorAction Stop
                $stateText = [string]$feature.State
                if ($stateText -eq 'Enabled') {
                    $anyFeatureEnabled = $true
                }

                [void]$featureStates.Add([pscustomobject][ordered]@{
                        FeatureName = $featureName
                        State = $stateText
                        QuerySucceeded = $true
                    })
            }
            catch {
                $featureQueryError = $_.Exception.Message
                [void]$featureStates.Add([pscustomobject][ordered]@{
                        FeatureName = $featureName
                        State = ''
                        QuerySucceeded = $false
                        ErrorMessage = $_.Exception.Message
                    })
            }
        }
    }

    $vmmsServiceExists = $false
    $vmmsServiceStatus = ''
    $vmmsServiceStartType = ''
    $vmmsQueryError = ''
    try {
        $service = Get-Service -Name 'vmms' -ErrorAction Stop
        $vmmsServiceExists = $true
        $vmmsServiceStatus = [string]$service.Status
        $vmmsServiceStartType = [string]$service.StartType
    }
    catch {
        $vmmsQueryError = $_.Exception.Message
    }

    $details = @{
        IsWindows = $true
        FeatureNames = $featureNames
        FeatureQueryAttempted = $featureQueryAttempted
        FeatureStates = @($featureStates.ToArray())
        FeatureQueryError = $featureQueryError
        AnyFeatureEnabled = $anyFeatureEnabled
        VmmsServiceName = 'vmms'
        VmmsServiceExists = $vmmsServiceExists
        VmmsServiceStatus = $vmmsServiceStatus
        VmmsServiceStartType = $vmmsServiceStartType
        VmmsQueryError = $vmmsQueryError
        ReadOnly = $true
    }

    if ($anyFeatureEnabled -or $vmmsServiceExists) {
        $message = if ($anyFeatureEnabled) {
            'Hyper-V optional feature appears enabled.'
        }
        else {
            "Hyper-V optional-feature state was not conclusive, but the VMMS service exists with status '$vmmsServiceStatus'."
        }

        return New-ReadinessResult `
            -Name 'Hyper-V feature enabled' `
            -Category 'host' `
            -Status 'Passed' `
            -Required $true `
            -Message $message `
            -Details $details
    }

    if ($featureQueryAttempted -and @($featureStates | Where-Object { $_.QuerySucceeded }).Count -gt 0) {
        return New-ReadinessResult `
            -Name 'Hyper-V feature enabled' `
            -Category 'host' `
            -Status 'Failed' `
            -Required $true `
            -Message 'Hyper-V optional feature was queryable but does not appear enabled, and the VMMS service was not found.' `
            -Details $details `
            -Remediation @('Enable the Hyper-V Windows optional feature and Hyper-V management tools, reboot if required, then rerun the read-only readiness check.')
    }

    return New-ReadinessResult `
        -Name 'Hyper-V feature enabled' `
        -Category 'host' `
        -Status 'Warning' `
        -Required $true `
        -Message 'Hyper-V feature/service state could not be proven from this session.' `
        -Details $details `
        -Remediation @('Open an elevated Windows PowerShell session and rerun .\scripts\Test-HyperVReadiness.ps1 so Hyper-V feature and VMMS service state can be queried.')
}

# Test-HyperVHostCompatibility checks fresh-computer host compatibility that is
# not fully covered by Hyper-V feature/module lookup. Inputs are none; processing
# uses read-only CIM queries for Windows edition, hypervisor presence, firmware
# virtualization, SLAT/EPT/NPT, and VM monitor extensions. Return behavior is a
# readiness row with Chinese-first next actions for new hosts.
function Test-HyperVHostCompatibility {
    try {
        $hostIsWindows = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
            [System.Runtime.InteropServices.OSPlatform]::Windows)
    }
    catch {
        $hostIsWindows = $false
    }

    $details = @{
        IsWindows = $hostIsWindows
        OperatingSystemCaption = ''
        OperatingSystemSKU = $null
        ProductType = $null
        WindowsEditionLikelySupportsClientHyperV = $null
        HypervisorPresent = $null
        VirtualizationFirmwareEnabled = $null
        SecondLevelAddressTranslationSupported = $null
        VmMonitorModeExtensions = $null
        InspectionErrors = @()
        ReadOnly = $true
        MutatedVm = $false
    }
    $actions = [System.Collections.Generic.List[string]]::new()
    $errors = [System.Collections.Generic.List[string]]::new()

    if (-not $hostIsWindows) {
        return New-ReadinessResult `
            -Name 'Fresh computer host compatibility' `
            -Category 'host' `
            -Status 'Failed' `
            -Required $true `
            -Message 'Live Hyper-V execution requires a Windows host.' `
            -Details $details `
            -Remediation @('下一步：Hyper-V live 模式需要 Windows Pro/Enterprise/Education 或 Windows Server；非 Windows host 只能运行 PlanOnly/WhatIf/WebUI/打包检查。')
    }

    if ($null -eq (Get-Command -Name Get-CimInstance -ErrorAction SilentlyContinue)) {
        $details['InspectionErrors'] = @('Get-CimInstance is unavailable.')
        return New-ReadinessResult `
            -Name 'Fresh computer host compatibility' `
            -Category 'host' `
            -Status 'Warning' `
            -Required $true `
            -Message 'Unable to inspect Windows edition and CPU virtualization settings because Get-CimInstance is unavailable.' `
            -Details $details `
            -Remediation @('下一步：在完整 Windows PowerShell/PowerShell 环境中重新运行 readiness，以便读取 Windows edition、BIOS 虚拟化和 SLAT。')
    }

    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $details['OperatingSystemCaption'] = [string]$os.Caption
        $details['OperatingSystemSKU'] = $os.OperatingSystemSKU
        $details['ProductType'] = $os.ProductType
        $isServer = [int]$os.ProductType -ne 1
        $looksHomeEdition = [string]$os.Caption -match '(?i)\bHome\b|CoreSingleLanguage|CoreCountrySpecific'
        $details['WindowsEditionLikelySupportsClientHyperV'] = ($isServer -or (-not $looksHomeEdition))
        if (-not [bool]$details['WindowsEditionLikelySupportsClientHyperV']) {
            [void]$actions.Add('下一步：Windows Home/Core 不能作为默认 Hyper-V live host；请使用 Windows Pro/Enterprise/Education 或 Windows Server，或只运行 PlanOnly/WhatIf。')
        }
    }
    catch {
        [void]$errors.Add("Unable to read Win32_OperatingSystem: $($_.Exception.Message)")
    }

    try {
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $hypervisorProperty = $computerSystem.PSObject.Properties['HypervisorPresent']
        if ($null -ne $hypervisorProperty) {
            $details['HypervisorPresent'] = [bool]$hypervisorProperty.Value
        }
    }
    catch {
        [void]$errors.Add("Unable to read Win32_ComputerSystem.HypervisorPresent: $($_.Exception.Message)")
    }

    try {
        $processor = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1
        if ($null -ne $processor) {
            $firmwareProperty = $processor.PSObject.Properties['VirtualizationFirmwareEnabled']
            if ($null -ne $firmwareProperty) {
                $details['VirtualizationFirmwareEnabled'] = [bool]$firmwareProperty.Value
                if (-not [bool]$details['VirtualizationFirmwareEnabled']) {
                    [void]$actions.Add('下一步：在 BIOS/UEFI 启用 Intel VT-x/AMD-V（虚拟化技术），冷重启后重新运行 readiness。')
                }
            }

            $slatProperty = $processor.PSObject.Properties['SecondLevelAddressTranslationExtensions']
            if ($null -ne $slatProperty) {
                $details['SecondLevelAddressTranslationSupported'] = [bool]$slatProperty.Value
                if (-not [bool]$details['SecondLevelAddressTranslationSupported']) {
                    [void]$actions.Add('下一步：Hyper-V 需要 SLAT/EPT/NPT；请换用支持二级地址转换的宿主机 CPU。')
                }
            }

            $vmMonitorProperty = $processor.PSObject.Properties['VMMonitorModeExtensions']
            if ($null -ne $vmMonitorProperty) {
                $details['VmMonitorModeExtensions'] = [bool]$vmMonitorProperty.Value
            }
        }
    }
    catch {
        [void]$errors.Add("Unable to read Win32_Processor virtualization state: $($_.Exception.Message)")
    }

    $details['InspectionErrors'] = @($errors.ToArray())
    if ($actions.Count -gt 0) {
        return New-ReadinessResult `
            -Name 'Fresh computer host compatibility' `
            -Category 'host' `
            -Status 'Failed' `
            -Required $true `
            -Message 'Fresh-computer Hyper-V host compatibility has blocking gaps.' `
            -Details $details `
            -Remediation @($actions.ToArray())
    }

    if ($errors.Count -gt 0) {
        return New-ReadinessResult `
            -Name 'Fresh computer host compatibility' `
            -Category 'host' `
            -Status 'Warning' `
            -Required $true `
            -Message 'Fresh-computer Hyper-V host compatibility could not be fully proven from this session.' `
            -Details $details `
            -Remediation @('下一步：用管理员 PowerShell 重新运行 readiness；若仍无法读取，请手动确认 Windows edition、BIOS 虚拟化和 SLAT/EPT/NPT。')
    }

    return New-ReadinessResult `
        -Name 'Fresh computer host compatibility' `
        -Category 'host' `
        -Status 'Passed' `
        -Required $true `
        -Message 'Windows edition and CPU virtualization compatibility look suitable for Hyper-V live execution.' `
        -Details $details
}

# Test-HyperVModule checks for the management module and required commands.
# Inputs are none; processing uses Get-Module/Get-Command only and never calls
# mutation-capable cmdlets. Return behavior is a readiness object; failure means
# VM/checkpoint/integration-service checks cannot be trusted from this session.
function Test-HyperVModule {
    $requiredCommands = @('Get-VM', 'Get-VMSnapshot', 'Get-VMIntegrationService', 'Copy-VMFile')

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
                } `
                -Remediation @(
                    'Enable Hyper-V and the Hyper-V PowerShell management tools, then open a new elevated PowerShell session.',
                    'After installing the module, rerun .\scripts\Test-HyperVReadiness.ps1; it remains read-only and will not start or restore the VM.'
                )
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
                } `
                -Remediation @('Repair/reinstall the Hyper-V PowerShell feature so Get-VM, Get-VMSnapshot, Get-VMIntegrationService, and Copy-VMFile are available.')
        }

        return New-ReadinessResult `
            -Name 'Hyper-V PowerShell module' `
            -Status 'Passed' `
            -Required $true `
            -Message 'Hyper-V PowerShell module and required cmdlets are available.' `
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
                ErrorMessage = $_.Exception.Message
            } `
            -Remediation @('Open an elevated Windows PowerShell session and rerun the read-only preflight; verify the Hyper-V optional feature is installed.')
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
            } `
            -Remediation @('Set guest.passwordSecretName in the sandbox config, or rerun .\install.ps1 -Mode Change -UpdateHyperVConfig with the intended -SecretName.')
    }

    if ($SecretName.Contains('=')) {
        return New-ReadinessResult `
            -Name 'Guest password environment variable' `
            -Status 'Failed' `
            -Required $true `
            -Message 'Environment variable names cannot contain "=".' `
            -Details @{
                SecretName = $SecretName
            } `
            -Remediation @('Choose a normal environment variable name such as KSWORDBOX_GUEST_PASSWORD, then rerun install.ps1 with that -SecretName.')
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
                EffectiveScope     = 'Process'
                SecretValuePrinted = $false
            }
    }

    if ($isUserConfigured -or $isMachineConfigured) {
        $scope = if ($isUserConfigured) { 'User' } else { 'Machine' }
        return New-ReadinessResult `
            -Name 'Guest password environment variable' `
            -Status 'Passed' `
            -Required $true `
            -Message "Environment variable '$SecretName' is configured in $scope scope. Secret value was not printed." `
            -Details @{
                SecretName         = $SecretName
                VisibleInProcess   = $false
                ConfiguredForUser  = $isUserConfigured
                ConfiguredForHost  = $isMachineConfigured
                EffectiveScope     = $scope
                SecretValuePrinted = $false
            }
    }

    return New-ReadinessResult `
        -Name 'Guest password environment variable' `
        -Status 'Failed' `
        -Required $true `
        -Message "Environment variable '$SecretName' is not set or is empty in Process, User, or Machine scope." `
        -Details @{
            SecretName         = $SecretName
            VisibleInProcess   = $false
            ConfiguredForUser  = $isUserConfigured
            ConfiguredForHost  = $isMachineConfigured
            SecretValuePrinted = $false
        } `
        -Remediation @(
            ".\install.ps1 -InstallEntrypoint CreateOrPreparePath -PromptPassword",
            ".\install.ps1 -Mode Change -ResetPassword -PromptPassword",
            ".\scripts\Test-HyperVReadiness.ps1 -PromptForMissingGuestPassword for a process-only one-shot readiness probe"
        )
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

# Test-IsPathUnderRoot checks whether one full path is nested under a root.
# Inputs are candidate/root paths; processing normalizes full paths and performs
# ordinal-ignore-case prefix comparison with a trailing separator. Return
# behavior is false for invalid or empty paths.
function Test-IsPathUnderRoot {
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
        $rootWithSeparator = $fullRoot + [System.IO.Path]::DirectorySeparatorChar
        return $fullPath.Equals($fullRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
            $fullPath.StartsWith($rootWithSeparator, [System.StringComparison]::OrdinalIgnoreCase)
    }
    catch {
        return $false
    }
}

# Test-HostSharedPathConfiguration validates host-side paths used to exchange
# plans, payloads, samples, and output with the VM. Inputs are resolved runtime,
# payload, and repository roots. Processing is read-only; it checks path shape
# and whether local artifact paths accidentally point inside the git checkout.
# Return behavior is one readiness object with copy mechanisms for automation.
function Test-HostSharedPathConfiguration {
    param(
        [AllowNull()][string]$RuntimeRootPath,
        [AllowNull()][string]$GuestPayloadRootPath,
        [AllowNull()][string]$RepositoryRootPath
    )

    $runtimeRootIsAbsolute = -not [string]::IsNullOrWhiteSpace($RuntimeRootPath) -and [System.IO.Path]::IsPathRooted($RuntimeRootPath)
    $payloadRootIsAbsolute = -not [string]::IsNullOrWhiteSpace($GuestPayloadRootPath) -and [System.IO.Path]::IsPathRooted($GuestPayloadRootPath)
    $runtimeUnderRepo = Test-IsPathUnderRoot -Path $RuntimeRootPath -Root $RepositoryRootPath
    $payloadUnderRepo = Test-IsPathUnderRoot -Path $GuestPayloadRootPath -Root $RepositoryRootPath
    $runtimeExists = -not [string]::IsNullOrWhiteSpace($RuntimeRootPath) -and (Test-Path -LiteralPath $RuntimeRootPath -PathType Container)
    $payloadExists = -not [string]::IsNullOrWhiteSpace($GuestPayloadRootPath) -and (Test-Path -LiteralPath $GuestPayloadRootPath -PathType Container)
    $details = @{
        RuntimeRoot = $RuntimeRootPath
        RuntimeRootIsAbsolute = $runtimeRootIsAbsolute
        RuntimeRootExists = $runtimeExists
        RuntimeRootUnderRepository = $runtimeUnderRepo
        GuestPayloadRoot = $GuestPayloadRootPath
        GuestPayloadRootIsAbsolute = $payloadRootIsAbsolute
        GuestPayloadRootExists = $payloadExists
        GuestPayloadRootUnderRepository = $payloadUnderRepo
        RepositoryRoot = $RepositoryRootPath
        CopyMechanisms = @('Copy-VMFile for submitted sample', 'PowerShell Direct Copy-Item -ToSession/-FromSession for guest tools and outputs')
        WriteProbeCreated = $false
        MutatedVm = $false
        ReadOnly = $true
    }

    if (-not $runtimeRootIsAbsolute -or -not $payloadRootIsAbsolute) {
        return New-ReadinessResult `
            -Name 'Host shared path configuration' `
            -Category 'paths' `
            -Status 'Failed' `
            -Required $true `
            -Message 'Runtime root and guest payload root must be absolute host paths for repeatable Hyper-V live runs.' `
            -Details $details `
            -Remediation @('Set paths.runtimeRoot and paths.guestPayloadRoot to absolute paths outside the repository, for example D:\Temp\KSwordSandbox and D:\Temp\KSwordSandbox\payload\guest-tools.')
    }

    if ($runtimeUnderRepo -or $payloadUnderRepo) {
        return New-ReadinessResult `
            -Name 'Host shared path configuration' `
            -Category 'paths' `
            -Status 'Failed' `
            -Required $true `
            -Message 'Runtime and payload exchange paths must stay outside the repository so samples, reports, payload binaries, and VM outputs are not committed.' `
            -Details $details `
            -Remediation @('Move runtimeRoot/guestPayloadRoot outside the git checkout, rerun payload preparation, and keep generated run outputs out of source control.')
    }

    $status = if ($runtimeExists -and $payloadExists) { 'Passed' } else { 'Warning' }
    $message = if ($status -eq 'Passed') {
        'Host runtime and payload exchange paths are absolute, outside the repository, and currently exist.'
    }
    else {
        'Host exchange paths are absolute and outside the repository, but one or more directories do not exist yet.'
    }

    return New-ReadinessResult `
        -Name 'Host shared path configuration' `
        -Category 'paths' `
        -Status $status `
        -Required $true `
        -Message $message `
        -Details $details `
        -Remediation $(if ($status -eq 'Passed') { @() } else { @('Create the runtime root and prepare the guest payload root before live execution; the readiness check does not create directories.') })
}

# Join-GuestPath joins Windows guest path fragments without touching the guest.
# Inputs are a root path and child segments. Processing trims separators and
# joins with backslashes. Return behavior is one guest-style path string.
function Join-GuestPath {
    param(
        [Parameter(Mandatory)]
        [string]$Root,

        [Parameter(Mandatory)]
        [string[]]$Segments
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

# Test-GuestWorkingDirectoryPath validates the configured guest root before any
# Hyper-V calls. Inputs are the guest working directory and expected executable
# names. Processing validates the string form only; it does not connect to or
# create folders in the VM. Return behavior is a readiness object.
function Test-GuestWorkingDirectoryPath {
    param(
        [string]$GuestRoot,
        [string]$AgentExecutableName,
        [string]$CollectorExecutableName
    )

    if ([string]::IsNullOrWhiteSpace($GuestRoot)) {
        return New-ReadinessResult `
            -Name 'Guest working directory' `
            -Status 'Failed' `
            -Required $true `
            -Message 'Guest working directory is empty.' `
            -Details @{
                GuestRoot = $GuestRoot
            }
    }

    $trimmed = $GuestRoot.Trim()
    $isDriveAbsolute = $trimmed -match '^[A-Za-z]:[\\/][^*?"<>|]*$'
    $isUncAbsolute = $trimmed -match '^[\\/]{2}[^\\/]+[\\/][^\\/]+'
    if (-not ($isDriveAbsolute -or $isUncAbsolute)) {
        return New-ReadinessResult `
            -Name 'Guest working directory' `
            -Status 'Failed' `
            -Required $true `
            -Message "Guest working directory '$trimmed' is not an absolute Windows path." `
            -Details @{
                GuestRoot          = $trimmed
                ExpectedForm       = 'C:\KSwordSandbox'
                MutatedVm          = $false
                SecretValuePrinted = $false
            }
    }

    $expectedDirectories = @(
        (Join-GuestPath -Root $trimmed -Segments @('agent')),
        (Join-GuestPath -Root $trimmed -Segments @('r0collector')),
        (Join-GuestPath -Root $trimmed -Segments @('incoming')),
        (Join-GuestPath -Root $trimmed -Segments @('out'))
    )
    $expectedFiles = @(
        (Join-GuestPath -Root $trimmed -Segments @('agent', $AgentExecutableName)),
        (Join-GuestPath -Root $trimmed -Segments @('r0collector', $CollectorExecutableName))
    )

    return New-ReadinessResult `
        -Name 'Guest working directory' `
        -Status 'Passed' `
        -Required $true `
        -Message "Guest working directory path is valid: $trimmed" `
        -Details @{
            GuestRoot             = $trimmed
            ExpectedDirectories   = $expectedDirectories
            ExpectedPayloadFiles  = $expectedFiles
            CheckedSyntaxOnly     = $true
            MutatedVm             = $false
            SecretValuePrinted    = $false
        }
}

# Get-RequiredPayloadFileMap returns the host and guest payload contract.
# Inputs are the host payload root, guest root, and executable names.
# Processing only builds strings.
# Return behavior is an ordered map of logical names to host and guest paths.
function Get-RequiredPayloadFileMap {
    param(
        [string]$PayloadRoot,
        [string]$GuestRoot,
        [string]$AgentExecutableName,
        [string]$CollectorExecutableName
    )

    return [ordered]@{
        GuestAgent = [pscustomobject][ordered]@{
            HostPath  = Join-Path (Join-Path $PayloadRoot 'agent') $AgentExecutableName
            GuestPath = Join-GuestPath -Root $GuestRoot -Segments @('agent', $AgentExecutableName)
            Required  = $true
        }
        R0Collector = [pscustomobject][ordered]@{
            HostPath  = Join-Path (Join-Path $PayloadRoot 'r0collector') $CollectorExecutableName
            GuestPath = Join-GuestPath -Root $GuestRoot -Segments @('r0collector', $CollectorExecutableName)
            Required  = $true
        }
        PayloadManifest = [pscustomobject][ordered]@{
            HostPath  = Join-Path $PayloadRoot 'payload-manifest.json'
            GuestPath = $null
            Required  = $true
        }
    }
}

# Test-HostPayloadFiles checks the staged host payload without building it.
# Inputs are the payload root and expected executable names. Processing uses
# Test-Path only. Return behavior is a readiness object; failure means the live
# runbook cannot stage tools into the VM from the configured host payload root.
function Test-HostPayloadFiles {
    param(
        [string]$PayloadRoot,
        [string]$GuestRoot,
        [string]$AgentExecutableName,
        [string]$CollectorExecutableName
    )

    if ([string]::IsNullOrWhiteSpace($PayloadRoot)) {
        return New-ReadinessResult `
            -Name 'Host payload files' `
            -Status 'Failed' `
            -Required $true `
            -Message 'Guest payload root path is empty.' `
            -Details @{
                GuestPayloadRoot = $PayloadRoot
                CheckedHostOnly  = $true
            } `
            -Remediation @('Set paths.guestPayloadRoot in the sandbox config, or rerun .\install.ps1 -Mode Change -UpdateHyperVConfig with the intended -GuestPayloadRoot.')
    }

    $fileMap = Get-RequiredPayloadFileMap `
        -PayloadRoot $PayloadRoot `
        -GuestRoot $GuestRoot `
        -AgentExecutableName $AgentExecutableName `
        -CollectorExecutableName $CollectorExecutableName
    $checkedFiles = New-Object System.Collections.Generic.List[object]
    $checkedDirectories = New-Object System.Collections.Generic.List[object]
    $missingFiles = New-Object System.Collections.Generic.List[string]
    $missingDirectories = New-Object System.Collections.Generic.List[string]

    foreach ($directoryPath in @($PayloadRoot, (Join-Path $PayloadRoot 'agent'), (Join-Path $PayloadRoot 'r0collector'))) {
        $exists = Test-Path -LiteralPath $directoryPath -PathType Container
        [void]$checkedDirectories.Add([pscustomobject][ordered]@{
                Path   = $directoryPath
                Exists = $exists
            })
        if (-not $exists) {
            [void]$missingDirectories.Add($directoryPath)
        }
    }

    foreach ($key in $fileMap.Keys) {
        $entry = $fileMap[$key]
        $exists = Test-Path -LiteralPath $entry.HostPath -PathType Leaf
        [void]$checkedFiles.Add([pscustomobject][ordered]@{
                Name     = $key
                Path     = $entry.HostPath
                Exists   = $exists
                Required = [bool]$entry.Required
            })

        if (([bool]$entry.Required) -and (-not $exists)) {
            [void]$missingFiles.Add($entry.HostPath)
        }
    }

    if ($missingFiles.Count -gt 0 -or $missingDirectories.Count -gt 0) {
        return New-ReadinessResult `
            -Name 'Host payload files' `
            -Status 'Failed' `
            -Required $true `
            -Message "Host payload root '$PayloadRoot' is missing required directories or files. Run scripts/Prepare-GuestPayload.ps1 -SelfContained before live Hyper-V execution." `
            -Details @{
                GuestPayloadRoot    = $PayloadRoot
                CheckedDirectories  = @($checkedDirectories.ToArray())
                MissingDirectories  = @($missingDirectories.ToArray())
                CheckedFiles        = @($checkedFiles.ToArray())
                MissingFiles        = @($missingFiles.ToArray())
                MutatedFiles        = $false
            } `
            -Remediation @(
                ".\scripts\Prepare-GuestPayload.ps1 -RepoRoot . -PayloadRoot '$PayloadRoot' -GuestWorkingDirectory '$GuestRoot' -SelfContained",
                ".\run.ps1 -Mode CheckEnvironment after payload preparation to re-check without starting or restoring a VM."
            )
    }

    return New-ReadinessResult `
        -Name 'Host payload files' `
        -Status 'Passed' `
        -Required $true `
        -Message "Host payload root '$PayloadRoot' contains required Guest Agent and R0Collector files." `
        -Details @{
            GuestPayloadRoot   = $PayloadRoot
            CheckedDirectories = @($checkedDirectories.ToArray())
            CheckedFiles       = @($checkedFiles.ToArray())
            MutatedFiles       = $false
    }
}

# Get-HyperVVmProfileCandidates enumerates VM/checkpoint profile choices without
# changing Hyper-V state. Inputs are an item limit and a flag that controls
# whether checkpoint names are included. Processing uses only Get-VM and
# Get-VMSnapshot. Return behavior is one object with query metadata and a bounded
# Profiles array suitable for Details output.
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
            $checkpointQuerySucceeded = $false
            $checkpointQueryError = ''
            $checkpoints = New-Object System.Collections.Generic.List[object]

            if ($IncludeCheckpoints) {
                try {
                    $snapshotObjects = @(Get-VMSnapshot -VMName $vm.Name -ErrorAction Stop |
                        Sort-Object -Property CreationTime -Descending)
                    $checkpointQuerySucceeded = $true
                    foreach ($snapshot in @($snapshotObjects | Select-Object -First $Limit)) {
                        [void]$checkpoints.Add([pscustomobject][ordered]@{
                                CheckpointName = [string]$snapshot.Name
                                CheckpointId   = [string]$snapshot.Id
                                CreationTime   = $snapshot.CreationTime
                            })
                    }
                }
                catch {
                    $checkpointQueryError = $_.Exception.Message
                }
            }

            [void]$profiles.Add([pscustomobject][ordered]@{
                    VmName                   = [string]$vm.Name
                    VmId                     = [string]$vm.Id
                    State                    = [string]$vm.State
                    Generation               = $vm.Generation
                    CheckpointQueryAttempted = [bool]$IncludeCheckpoints
                    CheckpointQuerySucceeded = $checkpointQuerySucceeded
                    CheckpointQueryError     = $checkpointQueryError
                    Checkpoints              = @($checkpoints.ToArray())
                })
        }

        return [pscustomobject][ordered]@{
            QuerySucceeded     = $true
            QueryError         = ''
            ReturnedVmCount    = $profiles.Count
            TotalVmCount       = $allVms.Count
            Limit              = $Limit
            IncludeCheckpoints = [bool]$IncludeCheckpoints
            Profiles           = @($profiles.ToArray())
        }
    }
    catch {
        return [pscustomobject][ordered]@{
            QuerySucceeded     = $false
            QueryError         = $_.Exception.Message
            ReturnedVmCount    = 0
            TotalVmCount       = 0
            Limit              = $Limit
            IncludeCheckpoints = [bool]$IncludeCheckpoints
            Profiles           = @()
        }
    }
}

# Test-HyperVProfileInventory emits an optional read-only helper row for
# selecting an existing VM/checkpoint profile. Inputs are precomputed host
# readiness plus configured target names. Processing intentionally skips the
# inventory unless -ListAvailableVmProfiles was requested.
function Test-HyperVProfileInventory {
    param(
        [string]$TargetVmName,
        [string]$TargetCheckpointName,
        [bool]$Requested,
        [bool]$HyperVAvailable,
        [bool]$IsAdministrator,
        [ValidateRange(1, 100)]
        [int]$Limit = 20
    )

    if (-not $Requested) {
        return $null
    }

    if (-not $HyperVAvailable) {
        return New-ReadinessResult `
            -Name 'Available VM profile inventory' `
            -Category 'hyperv-profile' `
            -Status 'Warning' `
            -Required $false `
            -Message 'Skipped VM profile inventory because Hyper-V feature/module readiness failed.' `
            -Details @{
                Requested = $true
                Skipped   = $true
                Reason    = 'Hyper-V module or feature unavailable'
                ReadOnly  = $true
            } `
            -Remediation @('Enable Hyper-V and the Hyper-V PowerShell tools, then rerun .\scripts\Test-HyperVReadiness.ps1 -ListAvailableVmProfiles from an elevated shell.')
    }

    if (-not $IsAdministrator) {
        return New-ReadinessResult `
            -Name 'Available VM profile inventory' `
            -Category 'hyperv-profile' `
            -Status 'Warning' `
            -Required $false `
            -Message 'Skipped VM profile inventory because the current process is not Administrator.' `
            -Details @{
                Requested = $true
                Skipped   = $true
                Reason    = 'Administrator required for reliable Hyper-V enumeration'
                ReadOnly  = $true
            } `
            -Remediation @('Open PowerShell as Administrator and rerun .\scripts\Test-HyperVReadiness.ps1 -ListAvailableVmProfiles; the inventory is read-only.')
    }

    $inventory = Get-HyperVVmProfileCandidates -Limit $Limit -IncludeCheckpoints
    if (-not [bool]$inventory.QuerySucceeded) {
        return New-ReadinessResult `
            -Name 'Available VM profile inventory' `
            -Category 'hyperv-profile' `
            -Status 'Warning' `
            -Required $false `
            -Message "Unable to enumerate available Hyper-V VM profiles: $($inventory.QueryError)" `
            -Details @{
                Requested            = $true
                TargetVmName         = $TargetVmName
                TargetCheckpointName = $TargetCheckpointName
                QuerySucceeded       = $false
                QueryError           = $inventory.QueryError
                Limit                = $Limit
                ReadOnly             = $true
            } `
            -Remediation @('Verify Hyper-V service health and permissions, then rerun the read-only profile inventory.')
    }

    $status = if ([int]$inventory.TotalVmCount -gt 0) { 'Passed' } else { 'Warning' }
    $message = if ([int]$inventory.TotalVmCount -gt 0) {
        "Listed $($inventory.ReturnedVmCount) of $($inventory.TotalVmCount) Hyper-V VM profile candidate(s) with checkpoint names."
    }
    else {
        'No Hyper-V VMs were found to use as a KSword Sandbox profile.'
    }

    return New-ReadinessResult `
        -Name 'Available VM profile inventory' `
        -Category 'hyperv-profile' `
        -Status $status `
        -Required $false `
        -Message $message `
        -Details @{
            Requested            = $true
            TargetVmName         = $TargetVmName
            TargetCheckpointName = $TargetCheckpointName
            QuerySucceeded       = $true
            ReturnedVmCount      = [int]$inventory.ReturnedVmCount
            TotalVmCount         = [int]$inventory.TotalVmCount
            Limit                = $Limit
            ReadOnly             = $true
            Profiles             = @($inventory.Profiles)
            ConfigureCommand     = '.\install.ps1 -Mode Change -UpdateHyperVConfig -VmName <existing VM> -CheckpointName <checkpoint>'
        } `
        -Remediation $(if ([int]$inventory.TotalVmCount -eq 0) { @('Create or import a golden VM and create a clean checkpoint before recording the profile.') } else { @("Choose an exact VmName and checkpoint from this inventory, then run .\install.ps1 -Mode Change -UpdateHyperVConfig -VmName <existing VM> -CheckpointName <checkpoint>.") })
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
        [bool]$IsAdministrator,
        [ValidateRange(1, 100)]
        [int]$CandidateLimit = 20
    )

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return New-ReadinessResult `
            -Name 'Target VM' `
            -Status 'Failed' `
            -Required $true `
            -Message 'Target VM name is empty.' `
            -Details @{
                VmName = $Name
            } `
            -Remediation @('Record a Hyper-V VM name with .\install.ps1 -Mode Change -UpdateHyperVConfig -VmName <existing VM> -CheckpointName <checkpoint>.')
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
            } `
            -Remediation @('Enable/install Hyper-V PowerShell tools, then rerun .\scripts\Test-HyperVReadiness.ps1. This check is read-only.')
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
            } `
            -Remediation @('Open PowerShell as Administrator for VM/checkpoint readiness, or use .\run.ps1 -Mode Plan for non-mutating planning without VM enumeration.')
    }

    try {
        $vmMatches = @(Get-VM -Name $Name -ErrorAction Stop |
            Where-Object { $_.Name -eq $Name })

        if ($vmMatches.Count -eq 0) {
            $inventory = Get-HyperVVmProfileCandidates -Limit $CandidateLimit
            return New-ReadinessResult `
                -Name 'Target VM' `
                -Status 'Failed' `
                -Required $true `
                -Message "No exact VM named '$Name' was found." `
                -Details @{
                    VmName                  = $Name
                    CandidateQuerySucceeded = [bool]$inventory.QuerySucceeded
                    CandidateQueryError     = $inventory.QueryError
                    CandidateLimit          = $CandidateLimit
                    AvailableVmProfiles     = @($inventory.Profiles)
                } `
                -Remediation @(
                    "Create or import a golden VM named '$Name', or record the existing VM with .\install.ps1 -Mode Change -UpdateHyperVConfig -VmName <existing VM> -CheckpointName <checkpoint>.",
                    'To list read-only VM/checkpoint candidates, run .\scripts\Test-HyperVReadiness.ps1 -ListAvailableVmProfiles from an elevated shell.',
                    'After updating config, rerun .\scripts\Test-HyperVReadiness.ps1; it does not start or restore the VM.'
                )
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
        $inventory = Get-HyperVVmProfileCandidates -Limit $CandidateLimit
        return New-ReadinessResult `
            -Name 'Target VM' `
            -Status 'Failed' `
            -Required $true `
            -Message "Unable to read target VM '$Name': $($_.Exception.Message)" `
            -Details @{
                VmName                  = $Name
                ErrorType               = $_.Exception.GetType().FullName
                ErrorMessage            = $_.Exception.Message
                CandidateQuerySucceeded = [bool]$inventory.QuerySucceeded
                CandidateQueryError     = $inventory.QueryError
                CandidateLimit          = $CandidateLimit
                AvailableVmProfiles     = @($inventory.Profiles)
            } `
            -Remediation @(
                "Verify Hyper-V service health and the configured VM name '$Name', then rerun the read-only readiness preflight from an elevated shell.",
                'To list read-only VM/checkpoint candidates, run .\scripts\Test-HyperVReadiness.ps1 -ListAvailableVmProfiles from an elevated shell.'
            )
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
        [bool]$CanQueryVmState,
        [ValidateRange(1, 100)]
        [int]$CandidateLimit = 20
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
            } `
            -Remediation @("Record the clean checkpoint with .\install.ps1 -Mode Change -UpdateHyperVConfig -VmName '$Vm' -CheckpointName <checkpoint>.")
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
            } `
            -Remediation @('Fix the VM/module/admin readiness item above first; this script intentionally does not start or restore a VM just to query checkpoints.')
    }

    try {
        $snapshots = @(Get-VMSnapshot -VMName $Vm -Name $Name -ErrorAction Stop |
            Where-Object { $_.Name -eq $Name })

        if ($snapshots.Count -eq 0) {
            $availableSnapshots = @(Get-VMSnapshot -VMName $Vm -ErrorAction SilentlyContinue |
                Sort-Object -Property CreationTime -Descending |
                Select-Object -First $CandidateLimit |
                ForEach-Object {
                    [pscustomobject][ordered]@{
                        CheckpointName = [string]$_.Name
                        CheckpointId   = [string]$_.Id
                        CreationTime   = $_.CreationTime
                    }
                })
            return New-ReadinessResult `
                -Name 'Clean checkpoint' `
                -Status 'Failed' `
                -Required $true `
                -Message "No exact checkpoint named '$Name' was found on VM '$Vm'." `
                -Details @{
                    VmName               = $Vm
                    CheckpointName       = $Name
                    CandidateLimit       = $CandidateLimit
                    AvailableCheckpoints = @($availableSnapshots)
                } `
                -Remediation @(
                    "Create a clean checkpoint named '$Name' on VM '$Vm', or record the existing checkpoint with .\install.ps1 -Mode Change -UpdateHyperVConfig -VmName '$Vm' -CheckpointName <checkpoint>.",
                    "To list read-only checkpoint candidates for existing VMs, run .\scripts\Test-HyperVReadiness.ps1 -ListAvailableVmProfiles -VmName '$Vm'.",
                    'Rerun .\scripts\Test-HyperVReadiness.ps1 after updating the checkpoint; no VM mutation is performed by the check.'
                )
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
        $outerError = $_
        $availableSnapshots = @()
        $candidateQueryError = ''
        try {
            $availableSnapshots = @(Get-VMSnapshot -VMName $Vm -ErrorAction Stop |
                Sort-Object -Property CreationTime -Descending |
                Select-Object -First $CandidateLimit |
                ForEach-Object {
                    [pscustomobject][ordered]@{
                        CheckpointName = [string]$_.Name
                        CheckpointId   = [string]$_.Id
                        CreationTime   = $_.CreationTime
                    }
                })
        }
        catch {
            $candidateQueryError = $_.Exception.Message
        }

        return New-ReadinessResult `
            -Name 'Clean checkpoint' `
            -Status 'Failed' `
            -Required $true `
            -Message "Unable to read checkpoint '$Name' on VM '$Vm': $($outerError.Exception.Message)" `
            -Details @{
                VmName                  = $Vm
                CheckpointName          = $Name
                ErrorType               = $outerError.Exception.GetType().FullName
                ErrorMessage            = $outerError.Exception.Message
                CandidateQueryError     = $candidateQueryError
                CandidateLimit          = $CandidateLimit
                AvailableCheckpoints    = @($availableSnapshots)
            } `
            -Remediation @(
                "Verify VM '$Vm' and checkpoint '$Name' in Hyper-V Manager, then rerun the read-only readiness preflight from an elevated shell.",
                "To list read-only checkpoint candidates for existing VMs, run .\scripts\Test-HyperVReadiness.ps1 -ListAvailableVmProfiles -VmName '$Vm'."
            )
    }
}

# Select-GuestServiceInterface returns the Hyper-V Guest Service Interface
# integration component by stable component GUID instead of display name only.
# Inputs are VMIntegrationService objects. Processing tolerates localized
# Windows display names such as "来宾服务接口". Return behavior is the first
# matching service or $null.
function Select-GuestServiceInterface {
    param([object[]]$Services)

    $componentSuffix = '\' + $script:GuestServiceInterfaceComponentId
    return @($Services | Where-Object {
            $id = [string]$_.Id
            $name = [string]$_.Name
            $id.EndsWith($componentSuffix, [System.StringComparison]::OrdinalIgnoreCase) -or
            $name -eq 'Guest Service Interface' -or
            $name -eq '来宾服务接口'
        } | Select-Object -First 1)[0]
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
            } `
            -Remediation @('Fix VM/module/admin readiness first. This preflight will not start the VM; live start can enable Guest Service Interface before Copy-VMFile.')
    }

    try {
        $services = @(Get-VMIntegrationService -VMName $Vm -ErrorAction Stop)
        $service = Select-GuestServiceInterface -Services $services

        if ($null -eq $service) {
            return New-ReadinessResult `
                -Name 'Guest Service Interface' `
                -Status 'Failed' `
                -Required $true `
                -Message "Guest Service Interface integration service was not found on VM '$Vm'. Checked localized names and component id '$script:GuestServiceInterfaceComponentId'." `
                -Details @{
                    VmName            = $Vm
                    ServiceName       = $serviceName
                    StableComponentId = $script:GuestServiceInterfaceComponentId
                    AvailableServices = @($services | ForEach-Object { $_.Name })
                } `
                -Remediation @("Verify the VM '$Vm' has Hyper-V integration services installed and that Guest Service Interface is available in VM settings.")
        }

        if ([bool]$service.Enabled) {
            return New-ReadinessResult `
                -Name 'Guest Service Interface' `
                -Status 'Passed' `
                -Required $true `
                -Message "Guest Service Interface integration service '$($service.Name)' is enabled on VM '$Vm'." `
                -Details @{
                    VmName            = $Vm
                    ServiceName       = $service.Name
                    StableComponentId = $script:GuestServiceInterfaceComponentId
                    ServiceId         = [string]$service.Id
                    Enabled           = [bool]$service.Enabled
                }
        }

        return New-ReadinessResult `
            -Name 'Guest Service Interface' `
            -Status 'Failed' `
            -Required $true `
            -Message "Guest Service Interface integration service '$($service.Name)' is disabled on VM '$Vm'." `
            -Details @{
                VmName            = $Vm
                ServiceName       = $service.Name
                StableComponentId = $script:GuestServiceInterfaceComponentId
                ServiceId         = [string]$service.Id
                Enabled           = [bool]$service.Enabled
            } `
            -Remediation @('Enable Guest Service Interface in Hyper-V VM settings, or let the live start phase enable it; this readiness script will not mutate that setting.')
    }
    catch {
        return New-ReadinessResult `
            -Name 'Guest Service Interface' `
            -Status 'Failed' `
            -Required $true `
            -Message "Unable to read Guest Service Interface state on VM '$Vm': $($_.Exception.Message)" `
            -Details @{
                VmName       = $Vm
                ServiceName  = $serviceName
                ErrorType    = $_.Exception.GetType().FullName
                ErrorMessage = $_.Exception.Message
            } `
            -Remediation @("Verify VM '$Vm' and Hyper-V integration services, then rerun the read-only preflight from an elevated shell.")
    }
}

# Test-PowerShellDirectReadOnly checks whether a running VM accepts a no-op
# PowerShell Direct command with the configured guest credential. Inputs are VM
# state, guest user, and secret name. Processing never starts or changes the VM.
# Return behavior is Passed when a read-only command returns, Warning when the
# probe is intentionally skipped, or Failed when an attempted probe fails.
function Test-PowerShellDirectReadOnly {
    param(
        [string]$Vm,
        [string]$VmState,
        [bool]$CanQueryVmState,
        [string]$GuestUser,
        [string]$SecretName
    )

    if (-not $CanQueryVmState) {
        return New-ReadinessResult `
            -Name 'PowerShell Direct' `
            -Status 'Warning' `
            -Required $true `
            -Message 'Skipped PowerShell Direct probe because VM state is not queryable in this session.' `
            -Details @{
                VmName  = $Vm
                Skipped = $true
                Reason  = 'VM state is not queryable'
            } `
            -Remediation @('Fix VM/module/admin readiness first. This preflight intentionally does not start the VM to make PowerShell Direct queryable.')
    }

    if ([string]::IsNullOrWhiteSpace($GuestUser)) {
        return New-ReadinessResult `
            -Name 'PowerShell Direct' `
            -Status 'Failed' `
            -Required $true `
            -Message 'Guest user name is empty; PowerShell Direct cannot build a credential.' `
            -Details @{
                VmName        = $Vm
                GuestUserName = $GuestUser
            } `
            -Remediation @('Record the guest username with .\install.ps1 -Mode Change -UpdateHyperVConfig -GuestUserName <user> or update guest.userName in the local config.')
    }

    $secretValue = Get-GuestPasswordSecretValue -SecretName $SecretName
    if (-not [bool]$secretValue.IsSet) {
        return New-ReadinessResult `
            -Name 'PowerShell Direct' `
            -Status 'Warning' `
            -Required $true `
            -Message "Skipped PowerShell Direct probe because '$SecretName' is not set in Process, User, or Machine scope." `
            -Details @{
                VmName        = $Vm
                GuestUserName = $GuestUser
                SecretName    = $SecretName
                Skipped       = $true
                Reason        = 'Guest password secret missing from Process, User, or Machine scope'
            } `
            -Remediation @(
                ".\install.ps1 -InstallEntrypoint CreateOrPreparePath -PromptPassword",
                ".\scripts\Test-HyperVReadiness.ps1 -PromptForMissingGuestPassword for a process-only probe without persisting the password"
            )
    }

    if (-not [StringComparer]::OrdinalIgnoreCase.Equals($VmState, 'Running')) {
        return New-ReadinessResult `
            -Name 'PowerShell Direct' `
            -Status 'Warning' `
            -Required $true `
            -Message "Skipped PowerShell Direct probe because VM '$Vm' is '$VmState'; read-only preflight will not start it." `
            -Details @{
                VmName          = $Vm
                VmState         = $VmState
                GuestUserName   = $GuestUser
                Skipped         = $true
                RequiresRunning = $true
                MutatedVm       = $false
            } `
            -Remediation @('This is expected when the golden VM is Off. Start the VM manually only if you want this read-only probe before live execution; the preflight will not start it for you.')
    }

    $invokeCommand = Get-Command -Name Invoke-Command -ErrorAction SilentlyContinue
    if ($null -eq $invokeCommand -or -not $invokeCommand.Parameters.ContainsKey('VMName')) {
        return New-ReadinessResult `
            -Name 'PowerShell Direct' `
            -Status 'Failed' `
            -Required $true `
            -Message 'Invoke-Command does not expose the VMName parameter needed for PowerShell Direct.' `
            -Details @{
                VmName        = $Vm
                GuestUserName = $GuestUser
                CommandFound  = $null -ne $invokeCommand
            }
    }

    try {
        $securePassword = [System.Security.SecureString]::new()
        foreach ($passwordCharacter in ([string]$secretValue.Value).ToCharArray()) {
            $securePassword.AppendChar($passwordCharacter)
        }
        $securePassword.MakeReadOnly()
        $credential = [pscredential]::new($GuestUser, $securePassword)
        $probe = Invoke-Command `
            -VMName $Vm `
            -Credential $credential `
            -ScriptBlock {
                [pscustomobject][ordered]@{
                    ComputerName      = $env:COMPUTERNAME
                    PowerShellVersion = $PSVersionTable.PSVersion.ToString()
                    UserName          = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                }
            } `
            -ErrorAction Stop

        $firstProbe = @($probe | Select-Object -First 1)[0]
        return New-ReadinessResult `
            -Name 'PowerShell Direct' `
            -Status 'Passed' `
            -Required $true `
            -Message "PowerShell Direct returned from VM '$Vm' using guest user '$GuestUser'." `
            -Details @{
                VmName             = $Vm
                VmState            = $VmState
                GuestUserName      = $GuestUser
                GuestComputerName  = $firstProbe.ComputerName
                GuestPowerShell    = $firstProbe.PowerShellVersion
                GuestEffectiveUser = $firstProbe.UserName
                SecretValuePrinted = $false
                MutatedVm          = $false
            }
    }
    catch {
        return New-ReadinessResult `
            -Name 'PowerShell Direct' `
            -Status 'Failed' `
            -Required $true `
            -Message "PowerShell Direct probe failed for VM '$Vm': $($_.Exception.Message)" `
            -Details @{
                VmName             = $Vm
                VmState            = $VmState
                GuestUserName      = $GuestUser
                ErrorType          = $_.Exception.GetType().FullName
                ErrorMessage       = $_.Exception.Message
                SecretValuePrinted = $false
                MutatedVm          = $false
            } `
            -Remediation @("Confirm VM '$Vm' is running, guest user '$GuestUser' exists, and '$SecretName' matches the guest password. If out of sync, use .\install.ps1 -Mode Change -ResetGuestVmPassword -PromptPassword -Force.")
    }
}

# Test-GuestPayloadFilesReadOnly checks expected files already deployed in the
# guest. Inputs are the VM, credential metadata, guest root, executable names,
# and prior PowerShell Direct result. Processing uses Test-Path in the guest
# only when PowerShell Direct already passed. Return behavior is Passed when all
# files exist, Warning when skipped or missing, and no VM mutation occurs.
function Test-GuestPayloadFilesReadOnly {
    param(
        [string]$Vm,
        [string]$GuestUser,
        [string]$SecretName,
        [string]$PayloadRoot,
        [string]$GuestRoot,
        [string]$AgentExecutableName,
        [string]$CollectorExecutableName,
        [object]$PowerShellDirectResult
    )

    $fileMap = Get-RequiredPayloadFileMap `
        -PayloadRoot $PayloadRoot `
        -GuestRoot $GuestRoot `
        -AgentExecutableName $AgentExecutableName `
        -CollectorExecutableName $CollectorExecutableName
    $guestPaths = @(
        $fileMap['GuestAgent'].GuestPath,
        $fileMap['R0Collector'].GuestPath
    )

    if ($PowerShellDirectResult.Status -ne 'Passed') {
        return New-ReadinessResult `
            -Name 'Guest deployed payload files' `
            -Status 'Warning' `
            -Required $false `
            -Message "Skipped guest payload file probe because PowerShell Direct status is '$($PowerShellDirectResult.Status)'." `
            -Details @{
                VmName        = $Vm
                GuestRoot     = $GuestRoot
                ExpectedFiles = $guestPaths
                Skipped       = $true
                Reason        = $PowerShellDirectResult.Message
                MutatedVm     = $false
            } `
            -Remediation @('Fix the PowerShell Direct readiness item first if you need an in-guest payload probe. This script will not start the VM just to check guest files.')
    }

    try {
        $secretValue = Get-GuestPasswordSecretValue -SecretName $SecretName
        $securePassword = [System.Security.SecureString]::new()
        foreach ($passwordCharacter in ([string]$secretValue.Value).ToCharArray()) {
            $securePassword.AppendChar($passwordCharacter)
        }
        $securePassword.MakeReadOnly()
        $credential = [pscredential]::new($GuestUser, $securePassword)
        $probe = Invoke-Command `
            -VMName $Vm `
            -Credential $credential `
            -ScriptBlock {
                param([string[]]$Paths)

                foreach ($path in $Paths) {
                    [pscustomobject][ordered]@{
                        Path   = $path
                        Exists = Test-Path -LiteralPath $path -PathType Leaf
                    }
                }
            } `
            -ArgumentList (,$guestPaths) `
            -ErrorAction Stop

        $checked = @($probe | ForEach-Object {
                [pscustomobject][ordered]@{
                    Path   = $_.Path
                    Exists = [bool]$_.Exists
                }
            })
        $missing = @($checked | Where-Object { -not $_.Exists } | ForEach-Object { $_.Path })

        if ($missing.Count -gt 0) {
            return New-ReadinessResult `
                -Name 'Guest deployed payload files' `
                -Status 'Warning' `
                -Required $false `
                -Message "Guest VM '$Vm' is missing one or more pre-deployed payload files. This is acceptable only when the live runbook stages host payload files before execution." `
                -Details @{
                    VmName       = $Vm
                    GuestRoot    = $GuestRoot
                    CheckedFiles = $checked
                    MissingFiles = $missing
                    MutatedVm    = $false
                } `
                -Remediation @("Prepare host payload files with .\scripts\Prepare-GuestPayload.ps1 -RepoRoot . -PayloadRoot '$PayloadRoot' -GuestWorkingDirectory '$GuestRoot' -SelfContained. The live runbook will stage them into the guest before execution.")
        }

        return New-ReadinessResult `
            -Name 'Guest deployed payload files' `
            -Status 'Passed' `
            -Required $false `
            -Message "Guest VM '$Vm' already contains the expected Guest Agent and R0Collector files." `
            -Details @{
                VmName       = $Vm
                GuestRoot    = $GuestRoot
                CheckedFiles = $checked
                MutatedVm    = $false
            }
    }
    catch {
        return New-ReadinessResult `
            -Name 'Guest deployed payload files' `
            -Status 'Warning' `
            -Required $false `
            -Message "Unable to read guest payload file state on VM '$Vm': $($_.Exception.Message)" `
            -Details @{
                VmName        = $Vm
                GuestRoot     = $GuestRoot
                ExpectedFiles = $guestPaths
                ErrorType     = $_.Exception.GetType().FullName
                ErrorMessage  = $_.Exception.Message
                MutatedVm     = $false
            } `
            -Remediation @('Rerun readiness after PowerShell Direct is healthy, or rely on host payload staging during live execution if host payload files pass.')
    }
}

# Test-RepositorySecretHygiene checks whether the currently visible guest
# password value appears in repository candidate text files. Inputs are the
# repository root, secret name, and skip switch. Processing reads only git
# tracked/untracked candidate files and never prints the secret value. Return
# behavior is a readiness object that fails if the secret value appears in a
# candidate file.
function Test-RepositorySecretHygiene {
    param(
        [string]$RepoRoot,
        [string]$SecretName,
        [bool]$Skip
    )

    if ($Skip) {
        return New-ReadinessResult `
            -Name 'Repository secret hygiene' `
            -Status 'Warning' `
            -Required $false `
            -Message 'Skipped repository secret scan by request.' `
            -Details @{
                RepositoryRoot     = $RepoRoot
                SecretName         = $SecretName
                Skipped            = $true
                SecretValuePrinted = $false
            }
    }

    $secretValue = Get-GuestPasswordSecretValue -SecretName $SecretName
    if (-not [bool]$secretValue.IsSet) {
        return New-ReadinessResult `
            -Name 'Repository secret hygiene' `
            -Status 'Warning' `
            -Required $false `
            -Message "Skipped repository secret scan because '$SecretName' is not set in Process, User, or Machine scope." `
            -Details @{
                RepositoryRoot     = $RepoRoot
                SecretName         = $SecretName
                Skipped            = $true
                Reason             = 'missingCredentialSecret'
                SecretValuePrinted = $false
            }
    }

    $secretText = [string]$secretValue.Value
    if ($secretText.Length -lt 8) {
        return New-ReadinessResult `
            -Name 'Repository secret hygiene' `
            -Status 'Warning' `
            -Required $false `
            -Message "Skipped repository secret scan because '$SecretName' is shorter than 8 characters; refusing noisy content matching." `
            -Details @{
                RepositoryRoot     = $RepoRoot
                SecretName         = $SecretName
                Skipped            = $true
                Reason             = 'secretTooShortForReliableScan'
                SecretValuePrinted = $false
            }
    }

    if ([string]::IsNullOrWhiteSpace($RepoRoot) -or -not (Test-Path -LiteralPath $RepoRoot -PathType Container)) {
        return New-ReadinessResult `
            -Name 'Repository secret hygiene' `
            -Status 'Warning' `
            -Required $false `
            -Message "Repository root '$RepoRoot' is not a directory; secret scan skipped." `
            -Details @{
                RepositoryRoot     = $RepoRoot
                SecretName         = $SecretName
                Skipped            = $true
                Reason             = 'repositoryRootMissing'
                SecretValuePrinted = $false
            }
    }

    if ($null -eq (Get-Command -Name git -ErrorAction SilentlyContinue)) {
        return New-ReadinessResult `
            -Name 'Repository secret hygiene' `
            -Status 'Warning' `
            -Required $false `
            -Message 'git is not available; repository candidate secret scan skipped.' `
            -Details @{
                RepositoryRoot     = $RepoRoot
                SecretName         = $SecretName
                Skipped            = $true
                Reason             = 'gitUnavailable'
                SecretValuePrinted = $false
            }
    }

    $binaryExtensions = @(
        '.7z', '.avhd', '.avhdx', '.bin', '.bmp', '.cer', '.dll', '.doc',
        '.docx', '.esd', '.exe', '.exp', '.gif', '.ico', '.ilk', '.iso',
        '.jpg', '.jpeg', '.key', '.lib', '.obj', '.p12', '.pdb', '.pdf',
        '.pfx', '.png', '.rar', '.snk', '.sys', '.vhd', '.vhdx', '.wim',
        '.xls', '.xlsx', '.zip'
    )
    $files = @(git -C $RepoRoot ls-files --cached --others --exclude-standard 2>$null)
    $scannedCount = 0
    $skippedCount = 0
    $leakingFiles = New-Object System.Collections.Generic.List[string]

    foreach ($relativePath in $files) {
        if ([string]::IsNullOrWhiteSpace($relativePath)) {
            continue
        }

        $normalized = $relativePath -replace '/', [System.IO.Path]::DirectorySeparatorChar
        $fullPath = Join-Path $RepoRoot $normalized
        if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
            $skippedCount++
            continue
        }

        $extension = [System.IO.Path]::GetExtension($relativePath).ToLowerInvariant()
        $item = Get-Item -LiteralPath $fullPath -ErrorAction SilentlyContinue
        if ($null -eq $item -or $binaryExtensions -contains $extension -or $item.Length -gt 1048576) {
            $skippedCount++
            continue
        }

        try {
            $content = Get-Content -LiteralPath $fullPath -Raw -ErrorAction Stop
            $scannedCount++
            if ($content.IndexOf($secretText, [System.StringComparison]::Ordinal) -ge 0) {
                [void]$leakingFiles.Add($relativePath)
            }
        }
        catch {
            $skippedCount++
        }
    }

    if ($leakingFiles.Count -gt 0) {
        return New-ReadinessResult `
            -Name 'Repository secret hygiene' `
            -Status 'Failed' `
            -Required $true `
            -Message "Current guest password value for '$SecretName' appears in repository candidate file(s). Remove it before staging or committing." `
            -Details @{
                RepositoryRoot       = $RepoRoot
                SecretName           = $SecretName
                SecretScope          = $secretValue.Scope
                CandidateFileCount   = @($files).Count
                ScannedTextFileCount = $scannedCount
                SkippedFileCount     = $skippedCount
                LeakingFiles         = @($leakingFiles.ToArray())
                SecretValuePrinted   = $false
            }
    }

    return New-ReadinessResult `
        -Name 'Repository secret hygiene' `
        -Status 'Passed' `
        -Required $false `
        -Message "Current guest password value for '$SecretName' was not found in repository candidate text files." `
        -Details @{
            RepositoryRoot       = $RepoRoot
            SecretName           = $SecretName
            SecretScope          = $secretValue.Scope
            CandidateFileCount   = @($files).Count
            ScannedTextFileCount = $scannedCount
            SkippedFileCount     = $skippedCount
            SecretValuePrinted   = $false
        }
}

# Test-R0DriverHostPathConfiguration validates the config state that controls
# whether the live runbook can stage/install the kernel driver. Inputs are
# metadata resolved from the local sandbox config. Processing only checks host
# path presence. Return behavior is a readiness row with remediation.
function Test-R0DriverHostPathConfiguration {
    param([Parameter(Mandatory)][object]$Metadata)

    $driverEnabled = [System.Convert]::ToBoolean($Metadata.DriverEnabled)
    $useMockCollector = [System.Convert]::ToBoolean($Metadata.DriverUseMockCollector)
    $hostDriverPath = [string]$Metadata.DriverHostPath
    $driverPathInGuest = [string]$Metadata.DriverPathInGuest
    $devicePath = [string]$Metadata.DriverDevicePath

    if (-not $driverEnabled) {
        return New-ReadinessResult `
            -Name 'R0 driver host path configuration' `
            -Status 'Passed' `
            -Required $false `
            -Message 'driver.enabled=false; R0 driver host .sys staging is not required.' `
            -Details @{
                DriverEnabled = $driverEnabled
                UseMockCollector = $useMockCollector
                HostDriverPath = $hostDriverPath
                DriverPathInGuest = $driverPathInGuest
                DevicePath = $devicePath
            }
    }

    if ($useMockCollector) {
        return New-ReadinessResult `
            -Name 'R0 driver host path configuration' `
            -Status 'Passed' `
            -Required $false `
            -Message 'driver.useMockCollector=true; real driver .sys staging is not required for this readiness mode.' `
            -Details @{
                DriverEnabled = $driverEnabled
                UseMockCollector = $useMockCollector
                HostDriverPath = $hostDriverPath
                DriverPathInGuest = $driverPathInGuest
                DevicePath = $devicePath
            }
    }

    if ([string]::IsNullOrWhiteSpace($hostDriverPath)) {
        return New-ReadinessResult `
            -Name 'R0 driver host path configuration' `
            -Status 'Failed' `
            -Required $true `
            -Message 'Real R0 collection is enabled, but driver.hostDriverPath is empty. Live runbooks will not stage a .sys or generate install-driver-service, and R0Collector can fail with deviceUnavailable/win32Error=2.' `
            -Details @{
                DriverEnabled = $driverEnabled
                UseMockCollector = $useMockCollector
                HostDriverPath = $null
                DriverPathInGuest = $driverPathInGuest
                DevicePath = $devicePath
                ExpectedRunbookImpact = 'empty driverSource and omitted install-driver-service'
            } `
            -Remediation @(
                ".\install.ps1 -Mode Change -UpdateHyperVConfig -DriverHostPath <path-to-test-signed-KSword.Sandbox.Driver.sys>",
                "Set driver.useMockCollector=true for payload-only R0 plumbing validation.",
                "Set driver.enabled=false if R0 collection is not part of this run."
            )
    }

    if (-not (Test-Path -LiteralPath $hostDriverPath -PathType Leaf)) {
        return New-ReadinessResult `
            -Name 'R0 driver host path configuration' `
            -Status 'Failed' `
            -Required $true `
            -Message "Configured driver.hostDriverPath does not exist: $hostDriverPath" `
            -Details @{
                DriverEnabled = $driverEnabled
                UseMockCollector = $useMockCollector
                HostDriverPath = $hostDriverPath
                HostDriverPathExists = $false
                DriverPathInGuest = $driverPathInGuest
                DevicePath = $devicePath
            } `
            -Remediation @(
                "Build the R0 driver and correct driver.hostDriverPath, or rerun .\install.ps1 -Mode Change -UpdateHyperVConfig -DriverHostPath <path-to-sys>.",
                "Set driver.useMockCollector=true for payload-only validation."
            )
    }

    $signatureStatus = ''
    try {
        $signatureStatus = [string](Get-AuthenticodeSignature -FilePath $hostDriverPath).Status
    }
    catch {
        $signatureStatus = "Unknown: $($_.Exception.Message)"
    }

    $status = if ($signatureStatus -eq 'NotSigned') { 'Warning' } else { 'Passed' }
    $message = if ($signatureStatus -eq 'NotSigned') {
        "Configured driver.hostDriverPath exists, but Authenticode status is NotSigned: $hostDriverPath"
    }
    else {
        "Configured driver.hostDriverPath exists: $hostDriverPath"
    }

    return New-ReadinessResult `
        -Name 'R0 driver host path configuration' `
        -Status $status `
        -Required $true `
        -Message $message `
        -Details @{
            DriverEnabled = $driverEnabled
            UseMockCollector = $useMockCollector
            HostDriverPath = $hostDriverPath
            HostDriverPathExists = $true
            DriverPathInGuest = $driverPathInGuest
            DevicePath = $devicePath
            AuthenticodeStatus = $signatureStatus
        } `
        -Remediation $(if ($signatureStatus -eq 'NotSigned') { @("Test-sign the driver and enable guest test-signing before live R0 collection.") } else { @() })
}

# Test-HostTestSigningStatus records the host boot test-signing state with a
# read-only bcdedit query. Inputs are driver mode flags so the result can state
# whether the value is relevant to the current run. Processing never changes
# boot configuration. Return behavior is a readiness row; guest test-signing is
# explicitly not verified unless the VM is deliberately inspected elsewhere.
function Test-HostTestSigningStatus {
    param(
        [bool]$DriverEnabled,
        [bool]$UseMockCollector
    )

    $realDriverMode = $DriverEnabled -and (-not $UseMockCollector)
    $bcdedit = Get-Command -Name 'bcdedit.exe' -ErrorAction SilentlyContinue
    if ($null -eq $bcdedit) {
        return New-ReadinessResult `
            -Name 'Test signing status' `
            -Category 'driver' `
            -Status 'Warning' `
            -Required $false `
            -Message 'bcdedit.exe is not available, so host test-signing state could not be recorded.' `
            -Details @{
                DriverEnabled = $DriverEnabled
                UseMockCollector = $UseMockCollector
                RealDriverMode = $realDriverMode
                BcdEditAvailable = $false
                TestSigningEnabled = $null
                GuestTestSigningVerified = $false
                Scope = 'host-current-boot-entry'
                ReadOnly = $true
            } `
            -Remediation @('For real R0 collection, verify Windows test-signing inside the isolated guest VM manually; the readiness script does not start the VM to inspect guest boot state.')
    }

    $outputText = ''
    $exitCode = $null
    try {
        $output = & $bcdedit.Source /enum '{current}' 2>&1
        $exitCode = $LASTEXITCODE
        $outputText = (@($output) | ForEach-Object { [string]$_ }) -join [Environment]::NewLine
    }
    catch {
        return New-ReadinessResult `
            -Name 'Test signing status' `
            -Category 'driver' `
            -Status 'Warning' `
            -Required $false `
            -Message "Unable to query host test-signing state with bcdedit.exe: $($_.Exception.Message)" `
            -Details @{
                DriverEnabled = $DriverEnabled
                UseMockCollector = $UseMockCollector
                RealDriverMode = $realDriverMode
                BcdEditAvailable = $true
                ErrorType = $_.Exception.GetType().FullName
                ErrorMessage = $_.Exception.Message
                TestSigningEnabled = $null
                GuestTestSigningVerified = $false
                Scope = 'host-current-boot-entry'
                ReadOnly = $true
            } `
            -Remediation @('Open an elevated shell if you need to inspect host boot configuration; for real R0 collection, verify guest test-signing manually before live execution.')
    }

    $testSigningValue = ''
    if ($outputText -match '(?im)^\s*testsigning\s+(?<value>\S+)\s*$') {
        $testSigningValue = $Matches['value']
    }

    $testSigningEnabled = $testSigningValue -match '^(?i:yes|on|true|1)$'
    $status = if ($realDriverMode -and (-not $testSigningEnabled)) { 'Warning' } else { 'Passed' }
    $message = if ($testSigningEnabled) {
        'Host current boot entry has test-signing enabled. Guest test-signing still must be verified inside the golden VM for real R0 driver runs.'
    }
    elseif ($realDriverMode) {
        'Host current boot entry does not show test-signing enabled. Real R0 collection also requires guest test-signing to be enabled and verified manually.'
    }
    else {
        'Host current boot entry does not show test-signing enabled; this is acceptable for mock/no-driver readiness.'
    }

    return New-ReadinessResult `
        -Name 'Test signing status' `
        -Category 'driver' `
        -Status $status `
        -Required $false `
        -Message $message `
        -Details @{
            DriverEnabled = $DriverEnabled
            UseMockCollector = $UseMockCollector
            RealDriverMode = $realDriverMode
            BcdEditAvailable = $true
            BcdEditExitCode = $exitCode
            TestSigningValue = $testSigningValue
            TestSigningEnabled = $testSigningEnabled
            GuestTestSigningVerified = $false
            Scope = 'host-current-boot-entry'
            ReadOnly = $true
        } `
        -Remediation $(if ($realDriverMode -and (-not $testSigningEnabled)) { @('For real R0 collection, enable Windows test-signing inside the isolated guest VM, reboot it, and recreate/restore the Clean checkpoint; use mock R0 when signing is not in scope.') } else { @() })
}


# Get-ReadinessChineseNextActions distills common fresh-computer and portable
# package blockers into Chinese-first operator actions. Inputs are existing
# readiness rows and resolved metadata. Processing is read-only and only formats
# guidance. Return behavior is a de-duplicated string array for the summary.
function Get-ReadinessChineseNextActions {
    param(
        [Parameter(Mandatory)][object[]]$Results,
        [Parameter(Mandatory)][object]$Metadata
    )

    $actions = [System.Collections.Generic.List[string]]::new()

    if ([string]$Metadata.ConfigSource -eq 'repository-example' -or -not [bool]$Metadata.InstallStateLoaded) {
        [void]$actions.Add('下一步：这看起来像首台机器/新便携包环境；先运行 .\install.ps1 -InstallEntrypoint CreateOrPreparePath -PlanOnly 查看将创建的仓库外目录和本机 config。')
        [void]$actions.Add('下一步：不要修改 config\sandbox.example.json；用 .\install.ps1 -Mode Change -UpdateHyperVConfig -VmName <existing VM> -CheckpointName <checkpoint> 记录本机 VM profile。')
    }

    foreach ($result in $Results) {
        $status = [string]$result.Status
        if ($status -notin @('Failed', 'Warning')) {
            continue
        }

        switch ([string]$result.Name) {
            'Readiness input resolution' {
                [void]$actions.Add('下一步：如果本机 config 未加载，运行 .\install.ps1 -InstallEntrypoint CreateOrPreparePath 创建 sandbox.local.json，并确认 Sandbox__ConfigPath 指向仓库外路径。')
            }
            'Fresh computer host compatibility' {
                [void]$actions.Add('下一步：首台机器先确认 Windows edition 支持 Hyper-V，BIOS/UEFI 已启用 Intel VT-x/AMD-V，CPU 支持 SLAT/EPT/NPT；否则只能做 PlanOnly/WhatIf/WebUI/打包检查。')
            }
            'Hyper-V feature enabled' {
                [void]$actions.Add('下一步：确认宿主机是 Windows Pro/Enterprise/Education/Server，启用 Hyper-V Windows 功能和管理工具，按提示重启后重跑 readiness。')
            }
            'Hyper-V PowerShell module' {
                [void]$actions.Add('下一步：安装/启用 Hyper-V PowerShell module；普通 Windows Home 或未启用 Hyper-V 的机器只能做 Plan/WebUI/打包检查，不能跑 Live VM。')
            }
            'Administrator privilege' {
                [void]$actions.Add('下一步：需要查询 VM/checkpoint 或执行 Live 时，用管理员 PowerShell 重跑；只做 Plan/WhatIf/状态检查可以继续用普通 shell。')
            }
            'Runtime root writable' {
                [void]$actions.Add("下一步：创建并授权 runtime root '$RuntimeRoot'，推荐放在 D:\Temp\KSwordSandbox 或其他仓库外目录。")
            }
            'Host shared path configuration' {
                [void]$actions.Add('下一步：确保 runtimeRoot 和 guestPayloadRoot 是绝对路径且在 git 仓库外；样本、报告、payload、VM 输出不能进入源码树。')
            }
            'Guest password secret' {
                [void]$actions.Add("下一步：运行 .\install.ps1 -InstallEntrypoint CreateOrPreparePath -PromptPassword 保存 '$GuestPasswordSecretName'；临时检查可用 .\scripts\Test-HyperVReadiness.ps1 -PromptForMissingGuestPassword。")
            }
            'Target VM' {
                [void]$actions.Add("下一步：创建/导入 golden VM，或运行 .\install.ps1 -Mode Change -UpdateHyperVConfig -VmName <existing VM> -CheckpointName <checkpoint> 记录真实 VM；可加 -ListAvailableVmProfiles 只读列出候选。")
            }
            'Clean checkpoint' {
                [void]$actions.Add("下一步：在现有 VM 上创建 clean checkpoint，或用 .\install.ps1 -Mode Change -UpdateHyperVConfig -VmName '$VmName' -CheckpointName <checkpoint> 记录正确名称。")
            }
            'Guest Service Interface' {
                [void]$actions.Add("下一步：在 Hyper-V Manager 或管理员 PowerShell 中为 VM '$VmName' 启用 Guest Service Interface（来宾服务接口），然后重跑只读 readiness。")
            }
            'Host payload files' {
                [void]$actions.Add("下一步：运行 .\scripts\Prepare-GuestPayload.ps1 -RepoRoot . -PayloadRoot '$GuestPayloadRoot' -GuestWorkingDirectory '$GuestWorkingDirectory' -SelfContained 准备 Guest Agent/R0Collector payload。")
            }
            'R0 driver host path configuration' {
                [void]$actions.Add('下一步：真实 R0 需要仓库外 test-signed .sys 路径；只验证链路可在 sandbox.local.json 设置 driver.useMockCollector=true 或 driver.enabled=false。')
            }
            'Test signing status' {
                [void]$actions.Add('下一步：test-signing 只用于隔离实验 VM/宿主机的测试签名驱动路径；本 readiness 不签名 driver，也不会调用 CSignTool.exe。')
            }
        }
    }

    [void]$actions.Add('下一步：三种安装入口保持互斥：UseConfiguredEnvironment 只诊断；RestoreCleanCheckpoint 只还原已有 clean checkpoint 且需要 -AllowVmMutation + -Confirm/-Force；CreateOrPreparePath 只准备本机路径/config/payload。')

    return @($actions.ToArray() | Select-Object -Unique)
}

function Get-ReadinessOperatorModeMatrix {
    return @(
        [pscustomobject][ordered]@{
            ModeId = 'use-configured-environment'
            Entrypoint = 'UseConfiguredEnvironment'
            TitleZh = '使用已配置环境'
            ReadinessRoleZh = '只读确认本机 config/secret/payload/VM/checkpoint 是否已经满足 Live 前置条件。'
            DiagnosticCommands = @('.\install.ps1 -InstallEntrypoint UseConfiguredEnvironment -PlanOnly', '.\install.ps1 -Mode CheckEnvironment', '.\run.ps1 -Mode CheckEnvironment')
            MutatesVm = $false
            SignsDriver = $false
            PushesOrPublishes = $false
            NextActionsZh = @('下一步：如果本 readiness 失败，按 RecommendedActionsZh 修复；不要通过 readiness 自动创建 VM 或还原 checkpoint。')
        },
        [pscustomobject][ordered]@{
            ModeId = 'rollback-restore-snapshot'
            Entrypoint = 'RestoreCleanCheckpoint'
            TitleZh = '回退/恢复已有干净快照'
            ReadinessRoleZh = '验证 VM/checkpoint 名称存在性和 PowerShell Direct/Guest Service 前置条件；不执行恢复。'
            DiagnosticCommands = @('.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -PlanOnly', '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -AllowVmMutation -WhatIf', '.\scripts\Test-HyperVReadiness.ps1 -ListAvailableVmProfiles')
            MutatingCommand = '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -AllowVmMutation -Confirm'
            MutatesVm = $false
            SignsDriver = $false
            PushesOrPublishes = $false
            NextActionsZh = @('下一步：只有隔离 lab 操作者确认后，才在 readiness 之外使用 -AllowVmMutation -Confirm 或 -Force 恢复已有 clean checkpoint。')
        },
        [pscustomobject][ordered]@{
            ModeId = 'fresh-create-new-computer'
            Entrypoint = 'CreateOrPreparePath'
            TitleZh = '全新创建/新电脑准备'
            ReadinessRoleZh = '识别首台机器缺口：Windows/Hyper-V/BIOS 虚拟化/SLAT/管理员 shell、VM、checkpoint、secret、payload、runtime root。'
            DiagnosticCommands = @('.\install.ps1 -InstallEntrypoint CreateOrPreparePath -PlanOnly', '.\install.ps1 -InstallEntrypoint CreateOrPreparePath -WhatIf', '.\install.ps1 -Mode CheckEnvironment')
            MutatesVm = $false
            SignsDriver = $false
            PushesOrPublishes = $false
            NextActionsZh = @('下一步：先在 Hyper-V/宿主机上手工完成兼容性和 golden VM 准备，再运行 CreateOrPreparePath 写本机目录/config/secret。')
        }
    )
}

$script:ReadinessInputMetadata = Resolve-ReadinessInputConfiguration
$promptMetadata = Import-GuestPasswordFromPrompt `
    -SecretName $GuestPasswordSecretName `
    -Prompt ([bool]$PromptForMissingGuestPassword)

$results = New-Object System.Collections.Generic.List[object]

$inputResolutionResult = Test-ReadinessInputResolution `
    -Metadata $script:ReadinessInputMetadata `
    -PromptMetadata $promptMetadata
[void]$results.Add($inputResolutionResult)

$r0DriverHostPathResult = Test-R0DriverHostPathConfiguration `
    -Metadata $script:ReadinessInputMetadata
[void]$results.Add($r0DriverHostPathResult)

$testSigningResult = Test-HostTestSigningStatus `
    -DriverEnabled ([bool]$script:ReadinessInputMetadata.DriverEnabled) `
    -UseMockCollector ([bool]$script:ReadinessInputMetadata.DriverUseMockCollector)
[void]$results.Add($testSigningResult)

$administratorResult = Test-AdministratorPrivilege
[void]$results.Add($administratorResult)

$hyperVFeatureResult = Test-HyperVFeatureState
[void]$results.Add($hyperVFeatureResult)

$hostCompatibilityResult = Test-HyperVHostCompatibility
[void]$results.Add($hostCompatibilityResult)

$hyperVModuleResult = Test-HyperVModule
[void]$results.Add($hyperVModuleResult)

$guestSecretResult = Test-GuestPasswordSecret -SecretName $GuestPasswordSecretName
[void]$results.Add($guestSecretResult)

$runtimeRootResult = Test-RuntimeRootWritableReadOnly -Path $RuntimeRoot
[void]$results.Add($runtimeRootResult)

$sharedPathResult = Test-HostSharedPathConfiguration `
    -RuntimeRootPath $RuntimeRoot `
    -GuestPayloadRootPath $GuestPayloadRoot `
    -RepositoryRootPath $script:ReadinessInputMetadata.RepositoryRoot
[void]$results.Add($sharedPathResult)

$guestWorkingDirectoryResult = Test-GuestWorkingDirectoryPath `
    -GuestRoot $GuestWorkingDirectory `
    -AgentExecutableName $GuestAgentExecutableName `
    -CollectorExecutableName $R0CollectorExecutableName
[void]$results.Add($guestWorkingDirectoryResult)

$hostPayloadResult = Test-HostPayloadFiles `
    -PayloadRoot $GuestPayloadRoot `
    -GuestRoot $GuestWorkingDirectory `
    -AgentExecutableName $GuestAgentExecutableName `
    -CollectorExecutableName $R0CollectorExecutableName
[void]$results.Add($hostPayloadResult)

$isAdministrator = $administratorResult.Status -eq 'Passed'
$isHyperVAvailable = ($hyperVModuleResult.Status -eq 'Passed') -and ($hyperVFeatureResult.Status -ne 'Failed')

$profileInventoryResult = Test-HyperVProfileInventory `
    -TargetVmName $VmName `
    -TargetCheckpointName $CheckpointName `
    -Requested ([bool]$ListAvailableVmProfiles) `
    -HyperVAvailable $isHyperVAvailable `
    -IsAdministrator $isAdministrator `
    -Limit $VmProfileListLimit
if ($null -ne $profileInventoryResult) {
    [void]$results.Add($profileInventoryResult)
}

$vmResult = Test-HyperVVm `
    -Name $VmName `
    -HyperVAvailable $isHyperVAvailable `
    -IsAdministrator $isAdministrator `
    -CandidateLimit $VmProfileListLimit
[void]$results.Add($vmResult)

$canQueryVmState = $isAdministrator `
    -and $isHyperVAvailable `
    -and ($vmResult.Status -eq 'Passed')

$checkpointResult = Test-HyperVCheckpoint `
    -Name $CheckpointName `
    -Vm $VmName `
    -CanQueryVmState $canQueryVmState `
    -CandidateLimit $VmProfileListLimit
[void]$results.Add($checkpointResult)

$guestServiceResult = Test-GuestServiceInterface `
    -Vm $VmName `
    -CanQueryVmState $canQueryVmState
[void]$results.Add($guestServiceResult)

$vmState = ''
$vmDetails = $vmResult.Details
if ($vmResult.Status -eq 'Passed' -and
    $vmDetails -is [System.Collections.IDictionary] -and
    $vmDetails.Contains('State')) {
    $vmState = [string]$vmDetails['State']
}
elseif ($vmResult.Status -eq 'Passed' -and
    $null -ne $vmDetails -and
    $null -ne $vmDetails.PSObject.Properties['State']) {
    $vmState = [string]$vmDetails.State
}

$powerShellDirectResult = Test-PowerShellDirectReadOnly `
    -Vm $VmName `
    -VmState $vmState `
    -CanQueryVmState $canQueryVmState `
    -GuestUser $GuestUserName `
    -SecretName $GuestPasswordSecretName
[void]$results.Add($powerShellDirectResult)

$guestPayloadResult = Test-GuestPayloadFilesReadOnly `
    -Vm $VmName `
    -GuestUser $GuestUserName `
    -SecretName $GuestPasswordSecretName `
    -PayloadRoot $GuestPayloadRoot `
    -GuestRoot $GuestWorkingDirectory `
    -AgentExecutableName $GuestAgentExecutableName `
    -CollectorExecutableName $R0CollectorExecutableName `
    -PowerShellDirectResult $powerShellDirectResult
[void]$results.Add($guestPayloadResult)

$secretHygieneResult = Test-RepositorySecretHygiene `
    -RepoRoot $script:ReadinessInputMetadata.RepositoryRoot `
    -SecretName $GuestPasswordSecretName `
    -Skip ([bool]$SkipRepositorySecretScan)
[void]$results.Add($secretHygieneResult)

$failedCount = @($results | Where-Object { $_.Status -eq 'Failed' }).Count
$warningCount = @($results | Where-Object { $_.Status -eq 'Warning' }).Count
$passedCount = @($results | Where-Object { $_.Status -eq 'Passed' }).Count
$failedRequiredCount = @($results | Where-Object { $_.Status -eq 'Failed' -and [bool]$_.RequiredForLive }).Count
$failedCheckIds = @($results | Where-Object { $_.Status -eq 'Failed' } | ForEach-Object { [string]$_.CheckId })
$warningCheckIds = @($results | Where-Object { $_.Status -eq 'Warning' } | ForEach-Object { [string]$_.CheckId })
$recommendedActions = @(Get-ReadinessRecommendedActions -Results @($results.ToArray()))
$chineseNextActions = @(Get-ReadinessChineseNextActions -Results @($results.ToArray()) -Metadata $script:ReadinessInputMetadata)
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
        ContractVersion = 2
        Kind           = 'KSwordSandbox.HyperVReadiness'
        ResultType     = 'ReadinessSummary'
        MachineReadable = $true
        GeneratedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
        OverallStatus  = $overallStatus
        ExitCode       = $exitCode
        PassedCount    = $passedCount
        WarningCount   = $warningCount
        FailedCount    = $failedCount
        FailedRequiredCount = $failedRequiredCount
        FailedCheckIds = $failedCheckIds
        WarningCheckIds = $warningCheckIds
        LiveReady      = ($failedRequiredCount -eq 0)
        ConfigPath     = $script:ReadinessInputMetadata.ConfigPath
        ConfigSource   = $script:ReadinessInputMetadata.ConfigSource
        InstallStatePath = $script:ReadinessInputMetadata.InstallStatePath
        VmName         = $VmName
        CheckpointName = $CheckpointName
        RuntimeRoot    = $RuntimeRoot
        GuestPayloadRoot = $GuestPayloadRoot
        GuestUserName  = $GuestUserName
        GuestRoot      = $GuestWorkingDirectory
        DriverEnabled  = $script:ReadinessInputMetadata.DriverEnabled
        DriverUseMockCollector = $script:ReadinessInputMetadata.DriverUseMockCollector
        DriverHostPath = $script:ReadinessInputMetadata.DriverHostPath
        VmProfileInventoryIncluded = [bool]$ListAvailableVmProfiles
        VmProfileListLimit = $VmProfileListLimit
        InstallEntrypointChoices = @('UseConfiguredEnvironment', 'RestoreCleanCheckpoint', 'CreateOrPreparePath')
        OperatorModeMatrixSchema = 'ksword.readiness.operator-mode-matrix.v1'
        OperatorModeMatrix = @(Get-ReadinessOperatorModeMatrix)
        UseConfiguredEnvironmentCommand = '.\install.ps1 -InstallEntrypoint UseConfiguredEnvironment -PlanOnly'
        RestoreCheckpointPlanCommand = '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -PlanOnly'
        RestoreCheckpointWhatIfCommand = '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -AllowVmMutation -WhatIf'
        RestoreCheckpointCommand = '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -AllowVmMutation -Confirm'
        CreateOrPreparePathCommand = '.\install.ps1 -InstallEntrypoint CreateOrPreparePath'
        FreshComputerCompatibilityGuidance = '中文提示：首台机器先确认 Windows/Hyper-V/BIOS 虚拟化/SLAT/管理员 shell，再创建或导入 Windows golden VM、启用 Guest Service Interface、配置 guest secret、准备 payload，并创建 clean checkpoint。'
        ChineseNextActions = $chineseNextActions
        ReadOnly       = $true
        ReadOnlyAssertions = [pscustomobject][ordered]@{
            NoProbeFilesWritten = $true
            NoVmMutationCommandsExecuted = $true
            DidNotStartVm = $true
            DidNotRestoreCheckpoint = $true
            DidNotEnableGuestService = $true
            DidNotSignDriver = $true
            DidNotCallCSignTool = $true
            DidNotPushOrPublish = $true
            SecretValuePrinted = $false
        }
        RecommendedActions = $recommendedActions
        RemediationHints = $recommendedActions
        RecommendedActionsZh = $chineseNextActions
        RemediationHintsZh = $chineseNextActions
        Checks = @($results | ForEach-Object {
                [pscustomobject][ordered]@{
                    CheckId = [string]$_.CheckId
                    Name = [string]$_.Name
                    Category = [string]$_.Category
                    Status = [string]$_.Status
                    RequiredForLive = [bool]$_.RequiredForLive
                }
            })
        Note           = 'No probe files were written and no VM mutation commands were executed; PowerShell Direct and guest payload probes run only when the VM is already running and credentials are visible.'
    })

exit $exitCode
