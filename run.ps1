<#
.SYNOPSIS
Starts KSwordSandbox after local installation.

.DESCRIPTION
This is the operator-facing runtime entry point. Run install.ps1 once to prepare
local folders, Hyper-V config, and guest credentials; then run this script each
time you want to use the sandbox.

Default mode starts the local WebUI with the installed config:

  .\run.ps1

Single-sample CLI and environment-check modes are also available:

  .\run.ps1 -Mode Plan -SamplePath D:\Temp\sample.exe
  .\run.ps1 -Mode Analyze -SamplePath D:\Temp\sample.exe -Live
  .\run.ps1 -Mode CheckEnvironment

Passing -WhatIf previews WebUI/analysis launch decisions without preparing
payloads, starting dotnet, or delegating live Hyper-V execution.

The script loads C:\ProgramData\KSwordSandbox\install-state.json when present,
sets Sandbox__ConfigPath for the Web/API, mirrors the guest password from User
or Machine environment into the current process when available, and never prints
secret values. WebUI mode attempts self-contained guest payload preparation but
keeps the UI launchable when local build tools are not installed; use
-RequirePayloadForWebUI when payload preparation must be fatal.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [ValidateSet('WebUI', 'StartWebUI', 'Analyze', 'Plan', 'Status', 'CheckEnvironment')]
    [string]$Mode = 'WebUI',

    [string]$SamplePath = '',

    [int]$DurationSeconds = 120,

    [string]$Url = 'http://127.0.0.1:18080',

    [string]$ConfigPath = '',

    [string]$RuntimeRoot = '',

    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    [int]$GuestReadyTimeoutSeconds = 180,

    [int]$ExecutionTimeoutSeconds = 240,

    [switch]$Live,

    [switch]$PlanOnly,

    [switch]$NoBuild,

    [switch]$SkipPayloadPreparation,

    [switch]$ForcePayloadPreparation,

    [switch]$OpenBrowser,

    [switch]$StrictUrl,

    [switch]$RequirePayloadForWebUI
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$script:RepositoryRoot = if ([string]::IsNullOrWhiteSpace($PSScriptRoot)) { (Get-Location).ProviderPath } else { $PSScriptRoot }
$script:InstallStatePath = Join-Path $env:ProgramData 'KSwordSandbox\install-state.json'
$script:WebConfigPathEnvironmentName = 'Sandbox__ConfigPath'

function Write-RunInfo {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "[run] $Message"
}

function Read-InstallState {
    if (-not (Test-Path -LiteralPath $script:InstallStatePath -PathType Leaf)) {
        return $null
    }

    try {
        return Get-Content -LiteralPath $script:InstallStatePath -Raw | ConvertFrom-Json
    }
    catch {
        Write-RunInfo "Ignoring unreadable install state '$script:InstallStatePath': $($_.Exception.Message)"
        return $null
    }
}

function Get-StateString {
    param(
        [AllowNull()]$State,
        [Parameter(Mandatory)][string]$Name,
        [AllowNull()][string]$DefaultValue
    )

    if ($null -ne $State) {
        $property = $State.PSObject.Properties[$Name]
        if ($null -ne $property -and -not [string]::IsNullOrWhiteSpace([string]$property.Value)) {
            return [string]$property.Value
        }
    }

    return $DefaultValue
}

function Resolve-FullPathIfPresent {
    param([Parameter(Mandatory)][string]$Path)

    if (Test-Path -LiteralPath $Path) {
        return (Resolve-Path -LiteralPath $Path).ProviderPath
    }

    return [System.IO.Path]::GetFullPath($Path)
}

function Get-EffectiveRuntimeRoot {
    param([AllowNull()]$State)

    if (-not [string]::IsNullOrWhiteSpace($RuntimeRoot)) {
        return [System.IO.Path]::GetFullPath($RuntimeRoot)
    }

    return [System.IO.Path]::GetFullPath((Get-StateString -State $State -Name 'runtimeRoot' -DefaultValue 'D:\Temp\KSwordSandbox'))
}

function Get-EffectiveConfigPath {
    param(
        [AllowNull()]$State,
        [Parameter(Mandatory)][string]$EffectiveRuntimeRoot
    )

    if (-not [string]::IsNullOrWhiteSpace($ConfigPath)) {
        return Resolve-FullPathIfPresent -Path $ConfigPath
    }

    $stateConfig = Get-StateString -State $State -Name 'localConfigPath' -DefaultValue ''
    if (-not [string]::IsNullOrWhiteSpace($stateConfig)) {
        return Resolve-FullPathIfPresent -Path $stateConfig
    }

    $envConfig = [Environment]::GetEnvironmentVariable($script:WebConfigPathEnvironmentName, 'Process')
    if ([string]::IsNullOrWhiteSpace($envConfig)) {
        $envConfig = [Environment]::GetEnvironmentVariable($script:WebConfigPathEnvironmentName, 'User')
    }
    if (-not [string]::IsNullOrWhiteSpace($envConfig)) {
        return Resolve-FullPathIfPresent -Path $envConfig
    }

    $runtimeConfig = Join-Path $EffectiveRuntimeRoot 'config\sandbox.local.json'
    if (Test-Path -LiteralPath $runtimeConfig -PathType Leaf) {
        return (Resolve-Path -LiteralPath $runtimeConfig).ProviderPath
    }

    return [System.IO.Path]::GetFullPath((Join-Path $script:RepositoryRoot 'config\sandbox.example.json'))
}

function Get-SecretName {
    param([AllowNull()]$State)
    return Get-StateString -State $State -Name 'secretName' -DefaultValue 'KSWORDBOX_GUEST_PASSWORD'
}

function Get-VirusTotalSecretName {
    param([AllowNull()]$State)
    return Get-StateString -State $State -Name 'virusTotalSecretName' -DefaultValue 'KSWORDBOX_VIRUSTOTAL_API_KEY'
}

function Import-UserOrMachineEnvironmentSecret {
    param([Parameter(Mandatory)][string]$Name)

    $processSecret = [Environment]::GetEnvironmentVariable($Name, 'Process')
    if (-not [string]::IsNullOrEmpty($processSecret)) {
        return
    }

    $candidate = [Environment]::GetEnvironmentVariable($Name, 'User')
    if ([string]::IsNullOrEmpty($candidate)) {
        $candidate = [Environment]::GetEnvironmentVariable($Name, 'Machine')
    }

    if (-not [string]::IsNullOrEmpty($candidate)) {
        [Environment]::SetEnvironmentVariable($Name, $candidate, 'Process')
        Set-Item -Path "Env:\$Name" -Value $candidate
    }
}

function Import-InstalledEnvironment {
    param(
        [AllowNull()]$State,
        [Parameter(Mandatory)][string]$EffectiveConfigPath
    )

    [Environment]::SetEnvironmentVariable($script:WebConfigPathEnvironmentName, $EffectiveConfigPath, 'Process')
    $env:Sandbox__ConfigPath = $EffectiveConfigPath

    $secretName = Get-SecretName -State $State
    Import-UserOrMachineEnvironmentSecret -Name $secretName
    Import-UserOrMachineEnvironmentSecret -Name (Get-VirusTotalSecretName -State $State)
}

function Read-SandboxConfig {
    param([Parameter(Mandatory)][string]$EffectiveConfigPath)

    if (-not (Test-Path -LiteralPath $EffectiveConfigPath -PathType Leaf)) {
        throw "Sandbox config was not found: $EffectiveConfigPath. Run .\install.ps1 -Mode Change -UpdateHyperVConfig first."
    }

    return Get-Content -LiteralPath $EffectiveConfigPath -Raw | ConvertFrom-Json
}

function Get-GuestPayloadRoot {
    param(
        [AllowNull()]$State,
        [Parameter(Mandatory)][object]$Config,
        [Parameter(Mandatory)][string]$EffectiveRuntimeRoot
    )

    $fromConfig = ''
    if ($null -ne $Config.paths -and $null -ne $Config.paths.PSObject.Properties['guestPayloadRoot']) {
        $fromConfig = [string]$Config.paths.guestPayloadRoot
    }

    if ([string]::IsNullOrWhiteSpace($fromConfig)) {
        $fromConfig = Get-StateString -State $State -Name 'guestPayloadRoot' -DefaultValue (Join-Path $EffectiveRuntimeRoot 'payload\guest-tools')
    }

    return [System.IO.Path]::GetFullPath($fromConfig)
}

function Get-RelativeRepositoryPath {
    param(
        [Parameter(Mandatory)][string]$RepositoryRoot,
        [Parameter(Mandatory)][string]$Path
    )

    $fullRoot = [System.IO.Path]::GetFullPath($RepositoryRoot).TrimEnd('\', '/') + '\'
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    if ($fullPath.StartsWith($fullRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $fullPath.Substring($fullRoot.Length).Replace('\', '/')
    }

    return $fullPath.Replace('\', '/')
}

function Get-GuestPayloadSourceFiles {
    $sourceRoots = @(
        'guest\KSword.Sandbox.Agent',
        'guest\KSword.Sandbox.R0Collector',
        'src\KSword.Sandbox.Abstractions'
    )
    $extensions = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($extension in @('.cs', '.csproj', '.props', '.targets', '.cpp', '.c', '.h', '.hpp', '.vcxproj', '.filters', '.json')) {
        [void]$extensions.Add($extension)
    }

    $files = New-Object System.Collections.Generic.List[System.IO.FileInfo]
    foreach ($relativeRoot in $sourceRoots) {
        $candidateRoot = Join-Path $script:RepositoryRoot $relativeRoot
        if (-not (Test-Path -LiteralPath $candidateRoot -PathType Container)) {
            continue
        }

        foreach ($file in Get-ChildItem -LiteralPath $candidateRoot -Recurse -File) {
            $normalized = $file.FullName.Replace('/', '\')
            if ($normalized -match '\\(bin|obj|x64|\.vs)\\') {
                continue
            }

            if ($extensions.Contains($file.Extension)) {
                $files.Add($file)
            }
        }
    }

    return @($files | Sort-Object FullName)
}

function Get-FileSha256Hex {
    param([Parameter(Mandatory)][string]$Path)

    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete)
    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            return ([System.BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
        }
        finally {
            $sha.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
}

function Get-GuestPayloadSourceFingerprint {
    $files = @(Get-GuestPayloadSourceFiles)
    $builder = [System.Text.StringBuilder]::new()
    foreach ($file in $files) {
        $relative = Get-RelativeRepositoryPath -RepositoryRoot $script:RepositoryRoot -Path $file.FullName
        $hash = Get-FileSha256Hex -Path $file.FullName
        [void]$builder.AppendLine("$relative|$hash|$($file.Length)")
    }

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($builder.ToString())
        return ([System.BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function Get-PayloadManifestProperty {
    param(
        [AllowNull()]$Manifest,
        [Parameter(Mandatory)][string]$Name
    )

    if ($null -eq $Manifest) {
        return $null
    }

    $property = $Manifest.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}

function Test-GuestPayloadManifestFileHash {
    param(
        [Parameter(Mandatory)]$Manifest,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$ExpectedPath,
        [AllowEmptyCollection()]
        [Parameter(Mandatory)][System.Collections.Generic.List[string]]$Reasons
    )

    if (-not (Test-Path -LiteralPath $ExpectedPath -PathType Leaf)) {
        $Reasons.Add("$Name file is missing: $ExpectedPath")
        return
    }

    $requiredFiles = Get-PayloadManifestProperty -Manifest $Manifest -Name 'requiredHostFiles'
    if ($null -eq $requiredFiles) {
        $Reasons.Add('payload-manifest.json is missing requiredHostFiles metadata.')
        return
    }

    $entry = @($requiredFiles | Where-Object {
        $entryName = Get-PayloadManifestProperty -Manifest $_ -Name 'name'
        [System.StringComparer]::OrdinalIgnoreCase.Equals([string]$entryName, $Name)
    } | Select-Object -First 1)
    if ($entry.Count -eq 0) {
        $Reasons.Add("payload-manifest.json is missing $Name hash metadata.")
        return
    }

    $manifestPath = [string](Get-PayloadManifestProperty -Manifest $entry[0] -Name 'path')
    if (-not [string]::IsNullOrWhiteSpace($manifestPath)) {
        try {
            $samePath = [System.StringComparer]::OrdinalIgnoreCase.Equals(
                [System.IO.Path]::GetFullPath($manifestPath),
                [System.IO.Path]::GetFullPath($ExpectedPath))
            if (-not $samePath) {
                $Reasons.Add("$Name path in payload-manifest.json points to '$manifestPath' instead of '$ExpectedPath'.")
            }
        }
        catch {
            $Reasons.Add("$Name path in payload-manifest.json is invalid: $manifestPath")
        }
    }

    $expectedHash = [string](Get-PayloadManifestProperty -Manifest $entry[0] -Name 'sha256')
    if ([string]::IsNullOrWhiteSpace($expectedHash)) {
        $Reasons.Add("$Name hash is absent from payload-manifest.json.")
        return
    }

    $actualHash = Get-FileSha256Hex -Path $ExpectedPath
    if (-not [System.StringComparer]::OrdinalIgnoreCase.Equals($expectedHash, $actualHash)) {
        $Reasons.Add("$Name hash differs from payload-manifest.json; staged payload may be partially overwritten.")
    }
}

function Test-GuestPayloadFresh {
    param(
        [Parameter(Mandatory)][string]$PayloadRoot,
        [Parameter(Mandatory)][string]$AgentExe,
        [Parameter(Mandatory)][string]$CollectorExe,
        [Parameter(Mandatory)][string]$ManifestPath
    )

    $reasons = [System.Collections.Generic.List[string]]::new()
    if (-not (Test-Path -LiteralPath $AgentExe -PathType Leaf)) {
        $reasons.Add("Guest Agent executable is missing: $AgentExe")
    }
    if (-not (Test-Path -LiteralPath $CollectorExe -PathType Leaf)) {
        $reasons.Add("R0Collector executable is missing: $CollectorExe")
    }
    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
        $reasons.Add("payload-manifest.json is missing: $ManifestPath")
        return [pscustomobject]@{ Fresh = $false; Reasons = @($reasons) }
    }

    try {
        $manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
    }
    catch {
        $reasons.Add("payload-manifest.json is unreadable: $($_.Exception.Message)")
        return [pscustomobject]@{ Fresh = $false; Reasons = @($reasons) }
    }

    $contractVersionValue = Get-PayloadManifestProperty -Manifest $manifest -Name 'payloadContractVersion'
    $contractVersion = if ($null -eq $contractVersionValue) { 0 } else { [int]$contractVersionValue }
    if ($contractVersion -lt 2) {
        $reasons.Add("payload-manifest.json contract version is $contractVersion; version 2+ is required for freshness checks.")
    }

    $manifestConfiguration = [string](Get-PayloadManifestProperty -Manifest $manifest -Name 'configuration')
    if (-not [System.StringComparer]::OrdinalIgnoreCase.Equals($manifestConfiguration, $Configuration)) {
        $reasons.Add("payload configuration '$manifestConfiguration' does not match requested '$Configuration'.")
    }

    $sourceFingerprint = [string](Get-PayloadManifestProperty -Manifest $manifest -Name 'sourceFingerprint')
    if ([string]::IsNullOrWhiteSpace($sourceFingerprint)) {
        $reasons.Add('payload-manifest.json is missing sourceFingerprint.')
    }
    else {
        $currentFingerprint = Get-GuestPayloadSourceFingerprint
        if (-not [System.StringComparer]::OrdinalIgnoreCase.Equals($sourceFingerprint, $currentFingerprint)) {
            $reasons.Add('guest payload source fingerprint is stale; Guest Agent/R0Collector sources changed after staging.')
        }
    }

    Test-GuestPayloadManifestFileHash -Manifest $manifest -Name 'GuestAgent' -ExpectedPath $AgentExe -Reasons $reasons
    Test-GuestPayloadManifestFileHash -Manifest $manifest -Name 'R0Collector' -ExpectedPath $CollectorExe -Reasons $reasons

    return [pscustomobject]@{ Fresh = $reasons.Count -eq 0; Reasons = @($reasons) }
}

function Ensure-GuestPayload {
    param(
        [Parameter(Mandatory)][string]$PayloadRoot,
        [Parameter(Mandatory)][object]$Config
    )

    if ($SkipPayloadPreparation) {
        Write-RunInfo 'Skipped guest payload preparation by request.'
        return
    }

    if ($WhatIfPreference) {
        [void]$PSCmdlet.ShouldProcess($PayloadRoot, 'Prepare self-contained guest payload if missing or stale')
        Write-RunInfo "WhatIf: guest payload preparation would be checked/prepared at $PayloadRoot."
        return
    }

    $agentName = 'KSword.Sandbox.Agent.exe'
    if ($null -ne $Config.guest -and $null -ne $Config.guest.PSObject.Properties['agentExecutableName'] -and -not [string]::IsNullOrWhiteSpace([string]$Config.guest.agentExecutableName)) {
        $agentName = [string]$Config.guest.agentExecutableName
    }

    $collectorName = 'KSword.Sandbox.R0Collector.exe'
    if ($null -ne $Config.driver -and $null -ne $Config.driver.PSObject.Properties['r0CollectorPathInGuest']) {
        $leaf = Split-Path -Leaf ([string]$Config.driver.r0CollectorPathInGuest)
        if (-not [string]::IsNullOrWhiteSpace($leaf)) {
            $collectorName = $leaf
        }
    }

    $agentExe = Join-Path (Join-Path $PayloadRoot 'agent') $agentName
    $collectorExe = Join-Path (Join-Path $PayloadRoot 'r0collector') $collectorName
    $manifest = Join-Path $PayloadRoot 'payload-manifest.json'
    if (-not $ForcePayloadPreparation) {
        $freshness = Test-GuestPayloadFresh -PayloadRoot $PayloadRoot -AgentExe $agentExe -CollectorExe $collectorExe -ManifestPath $manifest
        if ($freshness.Fresh) {
            Write-RunInfo "Guest payload ready and fresh: $PayloadRoot"
            return
        }

        Write-RunInfo "Guest payload will be rebuilt: $($freshness.Reasons -join '; ')"
    }
    else {
        Write-RunInfo 'Guest payload rebuild forced by -ForcePayloadPreparation.'
    }

    $prepareScript = Join-Path $script:RepositoryRoot 'scripts\Prepare-GuestPayload.ps1'
    if (-not (Test-Path -LiteralPath $prepareScript -PathType Leaf)) {
        throw "Guest payload preparation script is missing: $prepareScript"
    }

    $guestRoot = 'C:\KSwordSandbox'
    if ($null -ne $Config.guest -and $null -ne $Config.guest.PSObject.Properties['workingDirectory'] -and -not [string]::IsNullOrWhiteSpace([string]$Config.guest.workingDirectory)) {
        $guestRoot = [string]$Config.guest.workingDirectory
    }

    Write-RunInfo "Preparing self-contained guest payload: $PayloadRoot"
    $arguments = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $prepareScript,
        '-RepoRoot', $script:RepositoryRoot,
        '-PayloadRoot', $PayloadRoot,
        '-Configuration', $Configuration,
        '-GuestWorkingDirectory', $guestRoot,
        '-SelfContained'
    )
    & powershell @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Guest payload preparation failed with exit code $LASTEXITCODE."
    }

    $freshnessAfterPrepare = Test-GuestPayloadFresh -PayloadRoot $PayloadRoot -AgentExe $agentExe -CollectorExe $collectorExe -ManifestPath $manifest
    if (-not $freshnessAfterPrepare.Fresh) {
        throw "Guest payload preparation finished but freshness checks failed: $($freshnessAfterPrepare.Reasons -join '; ')"
    }
}

function Ensure-GuestPayloadForWebUi {
    param(
        [Parameter(Mandatory)][string]$PayloadRoot,
        [Parameter(Mandatory)][object]$Config
    )

    Write-RunInfo "Checking self-contained guest payload before WebUI launch: $PayloadRoot"
    try {
        Ensure-GuestPayload -PayloadRoot $PayloadRoot -Config $Config
    }
    catch {
        if ($RequirePayloadForWebUI) {
            throw
        }

        Write-RunInfo "Guest payload preparation failed before WebUI startup: $($_.Exception.Message)"
        Write-RunInfo 'WebUI will still start for upload, planning, dry-run runbooks, and configuration review.'
        Write-RunInfo 'Fix the payload before live Hyper-V execution, or rerun with -RequirePayloadForWebUI to make this fatal.'
    }
}

function Show-RunStatus {
    param(
        [AllowNull()]$State,
        [Parameter(Mandatory)][string]$EffectiveRuntimeRoot,
        [Parameter(Mandatory)][string]$EffectiveConfigPath
    )

    $secretName = Get-SecretName -State $State
    $virusTotalSecretName = Get-VirusTotalSecretName -State $State
    $configExists = Test-Path -LiteralPath $EffectiveConfigPath -PathType Leaf
    $payloadRoot = [System.IO.Path]::GetFullPath((Get-StateString -State $State -Name 'guestPayloadRoot' -DefaultValue (Join-Path $EffectiveRuntimeRoot 'payload\guest-tools')))
    $agentName = 'KSword.Sandbox.Agent.exe'
    $collectorName = 'KSword.Sandbox.R0Collector.exe'
    if ($configExists) {
        try {
            $statusConfig = Get-Content -LiteralPath $EffectiveConfigPath -Raw | ConvertFrom-Json
            if ($null -ne $statusConfig.paths -and $null -ne $statusConfig.paths.PSObject.Properties['guestPayloadRoot'] -and -not [string]::IsNullOrWhiteSpace([string]$statusConfig.paths.guestPayloadRoot)) {
                $payloadRoot = [System.IO.Path]::GetFullPath([string]$statusConfig.paths.guestPayloadRoot)
            }
            if ($null -ne $statusConfig.guest -and $null -ne $statusConfig.guest.PSObject.Properties['agentExecutableName'] -and -not [string]::IsNullOrWhiteSpace([string]$statusConfig.guest.agentExecutableName)) {
                $agentName = [string]$statusConfig.guest.agentExecutableName
            }
            if ($null -ne $statusConfig.driver -and $null -ne $statusConfig.driver.PSObject.Properties['r0CollectorPathInGuest']) {
                $collectorLeaf = Split-Path -Leaf ([string]$statusConfig.driver.r0CollectorPathInGuest)
                if (-not [string]::IsNullOrWhiteSpace($collectorLeaf)) {
                    $collectorName = $collectorLeaf
                }
            }
        }
        catch {
            Write-RunInfo "Status could not read payload root from config '$EffectiveConfigPath': $($_.Exception.Message)"
        }
    }

    $payloadManifest = Join-Path $payloadRoot 'payload-manifest.json'
    $agentPayload = Join-Path (Join-Path $payloadRoot 'agent') $agentName
    $collectorPayload = Join-Path (Join-Path $payloadRoot 'r0collector') $collectorName
    $hyperVModuleAvailable = $null -ne (Get-Command Get-VM -ErrorAction SilentlyContinue)
    $vmName = Get-StateString -State $State -Name 'vmName' -DefaultValue 'KSwordSandbox-Win10-Golden'
    $checkpointName = Get-StateString -State $State -Name 'checkpointName' -DefaultValue 'Clean'
    $vmExists = $false
    $checkpointExists = $false
    $vmState = $null
    $hyperVStatusError = $null

    if ($hyperVModuleAvailable) {
        try {
            $vm = Get-VM -Name $vmName -ErrorAction Stop
            $vmExists = $true
            $vmState = [string]$vm.State
            $snapshot = Get-VMSnapshot -VMName $vmName -Name $checkpointName -ErrorAction SilentlyContinue
            $checkpointExists = $null -ne $snapshot
        }
        catch {
            $hyperVStatusError = $_.Exception.Message
        }
    }

    $recommendedActions = New-Object System.Collections.Generic.List[string]
    if (-not $configExists) {
        [void]$recommendedActions.Add(".\install.ps1 -Mode Install -PromptPassword to create the local config, or .\install.ps1 -Mode Change -UpdateHyperVConfig to record VM/checkpoint paths.")
    }
    if (-not (Test-Path -LiteralPath $EffectiveRuntimeRoot -PathType Container)) {
        [void]$recommendedActions.Add(".\install.ps1 -Mode Install to create runtime folders under '$EffectiveRuntimeRoot'.")
    }
    if (-not (Test-Path -LiteralPath $payloadRoot -PathType Container) -or
        -not (Test-Path -LiteralPath $agentPayload -PathType Leaf) -or
        -not (Test-Path -LiteralPath $collectorPayload -PathType Leaf) -or
        -not (Test-Path -LiteralPath $payloadManifest -PathType Leaf)) {
        [void]$recommendedActions.Add(".\scripts\Prepare-GuestPayload.ps1 -RepoRoot . -PayloadRoot '$payloadRoot' -Configuration $Configuration -SelfContained")
        [void]$recommendedActions.Add(".\run.ps1 -Mode CheckEnvironment to re-check payload readiness without starting or restoring a VM.")
    }
    if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($secretName, 'Process')) -and
        [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($secretName, 'User')) -and
        [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($secretName, 'Machine'))) {
        [void]$recommendedActions.Add(".\install.ps1 -Mode Install -PromptPassword, or .\scripts\Test-HyperVReadiness.ps1 -PromptForMissingGuestPassword for a process-only check.")
    }
    if (-not $hyperVModuleAvailable) {
        [void]$recommendedActions.Add('Enable/install Hyper-V PowerShell tools, then rerun .\run.ps1 -Mode CheckEnvironment.')
    }
    elseif (-not $vmExists) {
        [void]$recommendedActions.Add(".\install.ps1 -Mode Change -UpdateHyperVConfig -VmName <existing VM> -CheckpointName <checkpoint>, or create/import VM '$vmName'.")
    }
    elseif (-not $checkpointExists) {
        [void]$recommendedActions.Add(".\install.ps1 -Mode Change -UpdateHyperVConfig -VmName '$vmName' -CheckpointName <checkpoint>, or create checkpoint '$checkpointName'.")
    }

    [pscustomobject][ordered]@{
        RepositoryRoot = $script:RepositoryRoot
        InstallStatePath = $script:InstallStatePath
        InstallStateExists = Test-Path -LiteralPath $script:InstallStatePath -PathType Leaf
        ConfigPath = $EffectiveConfigPath
        ConfigExists = $configExists
        WebUrl = $Url
        WebUiCommand = '.\run.ps1'
        RuntimeRoot = $EffectiveRuntimeRoot
        RuntimeRootExists = Test-Path -LiteralPath $EffectiveRuntimeRoot -PathType Container
        GuestPayloadRoot = $payloadRoot
        GuestPayloadRootExists = Test-Path -LiteralPath $payloadRoot -PathType Container
        GuestPayloadManifest = $payloadManifest
        GuestPayloadManifestExists = Test-Path -LiteralPath $payloadManifest -PathType Leaf
        GuestAgentPayload = $agentPayload
        GuestAgentPayloadExists = Test-Path -LiteralPath $agentPayload -PathType Leaf
        R0CollectorPayload = $collectorPayload
        R0CollectorPayloadExists = Test-Path -LiteralPath $collectorPayload -PathType Leaf
        SecretName = $secretName
        ProcessSecretSet = -not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($secretName, 'Process'))
        UserSecretSet = -not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($secretName, 'User'))
        VirusTotalSecretName = $virusTotalSecretName
        VirusTotalProcessSecretSet = -not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($virusTotalSecretName, 'Process'))
        VirusTotalUserSecretSet = -not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($virusTotalSecretName, 'User'))
        GuestPasswordGuidance = ".\install.ps1 -Mode Install -PromptPassword, or .\install.ps1 -Mode Change -ResetGuestVmPassword -GeneratePassword -Force"
        VirusTotalGuidance = ".\install.ps1 -Mode ConfigureVTKey -PromptVTKey, or set $virusTotalSecretName in User environment"
        VmName = $vmName
        CheckpointName = $checkpointName
        HyperVModuleAvailable = $hyperVModuleAvailable
        VmExists = $vmExists
        VmState = $vmState
        CheckpointExists = $checkpointExists
        HyperVStatusError = $hyperVStatusError
        PayloadGuidance = ".\scripts\Prepare-GuestPayload.ps1 -RepoRoot . -PayloadRoot '$payloadRoot' -Configuration $Configuration -SelfContained"
        VmGuidance = ".\install.ps1 -Mode Change -UpdateHyperVConfig -VmName <existing VM> -CheckpointName <checkpoint>"
        CheckpointGuidance = ".\install.ps1 -Mode Change -UpdateHyperVConfig -VmName '$vmName' -CheckpointName <checkpoint>"
        ReadinessGuidance = '.\scripts\Test-HyperVReadiness.ps1'
        RecommendedActions = @($recommendedActions.ToArray())
        SecretValuePrinted = $false
    }
}

function Show-RunEnvironmentCheck {
    param(
        [AllowNull()]$State,
        [Parameter(Mandatory)][string]$EffectiveRuntimeRoot,
        [Parameter(Mandatory)][string]$EffectiveConfigPath
    )

    $runStatus = Show-RunStatus -State $State -EffectiveRuntimeRoot $EffectiveRuntimeRoot -EffectiveConfigPath $EffectiveConfigPath
    $webProject = Join-Path $script:RepositoryRoot 'src\KSword.Sandbox.Web\KSword.Sandbox.Web.csproj'
    $hyperVScript = Join-Path $script:RepositoryRoot 'scripts\Invoke-HyperVE2E.ps1'
    $payloadScript = Join-Path $script:RepositoryRoot 'scripts\Prepare-GuestPayload.ps1'

    [pscustomobject][ordered]@{
        DailyStartupCommand = '.\run.ps1'
        StartWebUiCommand = '.\run.ps1 -Mode StartWebUI'
        CheckEnvironmentCommand = '.\run.ps1 -Mode CheckEnvironment'
        PlanCommand = '.\run.ps1 -Mode Plan -SamplePath <sample.exe>'
        LiveCommand = '.\run.ps1 -Mode Analyze -SamplePath <sample.exe> -Live'
        ReadinessCommand = '.\scripts\Test-HyperVReadiness.ps1'
        WhatIfSupported = $true
        DefaultStartsVm = $false
        WebUiStartsVm = $false
        LiveRequiresExplicitSwitch = $true
        CheckEnvironmentStartsVm = $false
        PlanOnlyStartsVm = $false
        DotNetAvailable = $null -ne (Get-Command dotnet -ErrorAction SilentlyContinue)
        WebProjectExists = Test-Path -LiteralPath $webProject -PathType Leaf
        HyperVE2EScriptExists = Test-Path -LiteralPath $hyperVScript -PathType Leaf
        PayloadPreparationScriptExists = Test-Path -LiteralPath $payloadScript -PathType Leaf
        SecretValuePrinted = $false
        Status = $runStatus
    }
}

function Test-CanBindTcpPort {
    param(
        [Parameter(Mandatory)][string]$HostName,
        [Parameter(Mandatory)][int]$Port
    )

    $listener = $null
    try {
        $address = if ($HostName -in @('localhost', '+', '*')) {
            [System.Net.IPAddress]::Loopback
        }
        else {
            [System.Net.IPAddress]::Parse($HostName)
        }

        $listener = [System.Net.Sockets.TcpListener]::new($address, $Port)
        $listener.Start()
        return [pscustomobject]@{ CanBind = $true; Error = '' }
    }
    catch {
        $message = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
        return [pscustomobject]@{ CanBind = $false; Error = $message }
    }
    finally {
        if ($null -ne $listener) {
            $listener.Stop()
        }
    }
}

function Resolve-WebListenUrl {
    param([Parameter(Mandatory)][string]$RequestedUrl)

    $uri = [Uri]$RequestedUrl
    if ($uri.Scheme -ne 'http') {
        return $RequestedUrl
    }

    $hostName = if ([string]::IsNullOrWhiteSpace($uri.Host)) { '127.0.0.1' } else { $uri.Host }
    $port = if ($uri.IsDefaultPort) { 80 } else { $uri.Port }
    $probe = Test-CanBindTcpPort -HostName $hostName -Port $port
    if ($probe.CanBind) {
        return $RequestedUrl
    }

    if ($StrictUrl) {
        throw "Requested WebUI URL '$RequestedUrl' cannot be bound: $($probe.Error)"
    }

    Write-RunInfo "Requested WebUI URL '$RequestedUrl' cannot be bound: $($probe.Error)"
    $candidatePorts = @($port, 18080, 18081, 18082, 18083, 28080, 28081, 38080, 49152, 52123, 55000) | Select-Object -Unique
    foreach ($candidatePort in $candidatePorts) {
        if ($candidatePort -eq $port) {
            continue
        }

        $candidateProbe = Test-CanBindTcpPort -HostName $hostName -Port ([int]$candidatePort)
        if ($candidateProbe.CanBind) {
            $builder = [UriBuilder]::new($uri)
            $builder.Port = [int]$candidatePort
            $fallbackUrl = $builder.Uri.GetLeftPart([UriPartial]::Authority)
            Write-RunInfo "Falling back to WebUI URL: $fallbackUrl"
            return $fallbackUrl
        }
    }

    throw "No usable WebUI localhost port was found. Last error for '$RequestedUrl': $($probe.Error)"
}

function Invoke-WebUi {
    param([Parameter(Mandatory)][string]$EffectiveConfigPath)

    $projectPath = Join-Path $script:RepositoryRoot 'src\KSword.Sandbox.Web\KSword.Sandbox.Web.csproj'
    if (-not (Test-Path -LiteralPath $projectPath -PathType Leaf)) {
        throw "Web project is missing: $projectPath"
    }

    $effectiveUrl = Resolve-WebListenUrl -RequestedUrl $Url
    $script:Url = $effectiveUrl
    Write-RunInfo "Starting WebUI: $effectiveUrl"
    Write-RunInfo "Config: $EffectiveConfigPath"
    Write-RunInfo "Hyper-V live prerequisites: configured VM/checkpoint, prepared self-contained guest payload, and guest password secret."
    Write-RunInfo 'Press Ctrl+C to stop the WebUI.'

    if (-not $PSCmdlet.ShouldProcess($effectiveUrl, "Start WebUI with '$projectPath'")) {
        Write-RunInfo "WhatIf: WebUI would start at $effectiveUrl with config '$EffectiveConfigPath'. No dotnet process or browser was started."
        return
    }

    $env:ASPNETCORE_URLS = $effectiveUrl

    if ($OpenBrowser) {
        Start-Job -ScriptBlock {
            param([string]$TargetUrl)
            Start-Sleep -Seconds 2
            Start-Process $TargetUrl
        } -ArgumentList $effectiveUrl | Out-Null
    }

    $arguments = @('run', '--no-launch-profile', '--project', $projectPath)
    if ($NoBuild) {
        $arguments += '--no-build'
    }

    & dotnet @arguments
    exit $LASTEXITCODE
}

function Invoke-OneShotAnalysis {
    param(
        [Parameter(Mandatory)][string]$EffectiveConfigPath,
        [Parameter(Mandatory)][object]$Config,
        [Parameter(Mandatory)][string]$EffectiveRuntimeRoot,
        [AllowNull()]$State
    )

    if ([string]::IsNullOrWhiteSpace($SamplePath)) {
        throw 'Analyze/Plan mode requires -SamplePath.'
    }

    $resolvedSample = Resolve-FullPathIfPresent -Path $SamplePath
    if (-not (Test-Path -LiteralPath $resolvedSample -PathType Leaf)) {
        throw "Sample executable was not found: $resolvedSample"
    }
    if ([System.IO.Path]::GetExtension($resolvedSample) -ine '.exe') {
        throw "v1 one-shot analysis only accepts .exe samples: $resolvedSample"
    }

    $invokeScript = Join-Path $script:RepositoryRoot 'scripts\Invoke-HyperVE2E.ps1'
    if (-not (Test-Path -LiteralPath $invokeScript -PathType Leaf)) {
        throw "Hyper-V E2E script is missing: $invokeScript"
    }

    $runLive = [bool]$Live -and (-not [bool]$PlanOnly) -and ($Mode -ne 'Plan')
    $payloadRoot = Get-GuestPayloadRoot -State $State -Config $Config -EffectiveRuntimeRoot $EffectiveRuntimeRoot
    if ($runLive) {
        Ensure-GuestPayload -PayloadRoot $payloadRoot -Config $Config
    }
    else {
        Write-RunInfo "PlanOnly: guest payload preparation skipped at $payloadRoot."
        Write-RunInfo 'The generated Hyper-V plan will report missing/stale payload files and repair suggestions without building or copying payloads.'
    }

    $analysisAction = if ($runLive) {
        'Delegate live Hyper-V analysis. This can restore/start/stop the configured VM.'
    }
    else {
        'Create a non-mutating Hyper-V analysis plan'
    }
    if (-not $PSCmdlet.ShouldProcess($resolvedSample, $analysisAction)) {
        Write-RunInfo "WhatIf: $analysisAction for '$resolvedSample'. No Hyper-V child script was launched."
        return
    }

    $arguments = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $invokeScript,
        '-ConfigPath', $EffectiveConfigPath,
        '-SamplePath', $resolvedSample,
        '-DurationSeconds', ([string]$DurationSeconds),
        '-GuestReadyTimeoutSeconds', ([string]$GuestReadyTimeoutSeconds),
        '-ExecutionTimeoutSeconds', ([string]$ExecutionTimeoutSeconds)
    )

    if ($runLive) {
        $arguments += '-Live'
        Write-RunInfo "Starting live Hyper-V analysis for: $resolvedSample"
    }
    else {
        $arguments += '-PlanOnly'
        Write-RunInfo "Planning only, no VM mutation, for: $resolvedSample"
        Write-RunInfo 'Add -Live to run the sample in the configured Hyper-V VM.'
    }

    $hyperVOutput = @(& powershell @arguments 2>&1)
    $hyperVExitCode = $LASTEXITCODE
    foreach ($line in $hyperVOutput) {
        Write-Host ([string]$line)
    }

    if ($hyperVExitCode -ne 0) {
        exit $hyperVExitCode
    }

    if ($runLive) {
        $jobRoot = Resolve-JobRootFromHyperVOutput -OutputLines $hyperVOutput -EffectiveRuntimeRoot $EffectiveRuntimeRoot
        Invoke-PostProcessJob -JobRoot $jobRoot -EffectiveConfigPath $EffectiveConfigPath -ResolvedSamplePath $resolvedSample
    }

    exit 0
}

function Resolve-JobRootFromHyperVOutput {
    param(
        [Parameter(Mandatory)][object[]]$OutputLines,
        [Parameter(Mandatory)][string]$EffectiveRuntimeRoot
    )

    foreach ($entry in $OutputLines) {
        $line = [string]$entry
        if ($line -match 'Runbook execution record written:\s*(?<path>.+?runbook-execution\.json)\s*$') {
            return (Split-Path -Parent $Matches['path'])
        }
        if ($line -match 'RunbookExecutionPath\s*:\s*(?<path>.+?runbook-execution\.json)\s*$') {
            return (Split-Path -Parent $Matches['path'])
        }
        if ($line -match 'JobId\s*:\s*(?<jobId>[0-9a-fA-F-]{36})') {
            $compact = ([guid]$Matches['jobId']).ToString('N')
            $candidate = Join-Path (Join-Path $EffectiveRuntimeRoot 'jobs') $compact
            if (Test-Path -LiteralPath $candidate -PathType Container) {
                return $candidate
            }
        }
    }

    $latest = Get-ChildItem -LiteralPath (Join-Path $EffectiveRuntimeRoot 'jobs') -Directory -ErrorAction SilentlyContinue |
        Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'runbook-execution.json') -PathType Leaf } |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1
    if ($null -ne $latest) {
        Write-RunInfo "Could not parse job root from Hyper-V output; falling back to latest job root: $($latest.FullName)"
        return $latest.FullName
    }

    throw 'Could not resolve live job root from Hyper-V output.'
}

function Invoke-PostProcessJob {
    param(
        [Parameter(Mandatory)][string]$JobRoot,
        [Parameter(Mandatory)][string]$EffectiveConfigPath,
        [Parameter(Mandatory)][string]$ResolvedSamplePath
    )

    $postProcessProject = Join-Path $script:RepositoryRoot 'tools\KSword.Sandbox.PostProcess\KSword.Sandbox.PostProcess.csproj'
    if (-not (Test-Path -LiteralPath $postProcessProject -PathType Leaf)) {
        throw "PostProcess project is missing: $postProcessProject"
    }

    Write-RunInfo "Post-processing live artifacts into report: $JobRoot"
    $arguments = @('run', '--project', $postProcessProject)
    if ($NoBuild) {
        $arguments += '--no-build'
    }
    $arguments += @(
        '--',
        '--repo-root', $script:RepositoryRoot,
        '--config-path', $EffectiveConfigPath,
        '--job-root', $JobRoot,
        '--sample-path', $ResolvedSamplePath
    )

    & dotnet @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Post-processing failed with exit code $LASTEXITCODE."
    }
}

$state = Read-InstallState
$effectiveRuntimeRoot = Get-EffectiveRuntimeRoot -State $state
$effectiveConfigPath = Get-EffectiveConfigPath -State $state -EffectiveRuntimeRoot $effectiveRuntimeRoot
Import-InstalledEnvironment -State $state -EffectiveConfigPath $effectiveConfigPath

if ($Mode -in @('WebUI', 'StartWebUI') -and -not [string]::IsNullOrWhiteSpace($SamplePath)) {
    $Mode = 'Analyze'
}

switch ($Mode) {
    'Status' {
        Show-RunStatus -State $state -EffectiveRuntimeRoot $effectiveRuntimeRoot -EffectiveConfigPath $effectiveConfigPath | Format-List
    }
    'CheckEnvironment' {
        Show-RunEnvironmentCheck -State $state -EffectiveRuntimeRoot $effectiveRuntimeRoot -EffectiveConfigPath $effectiveConfigPath | Format-List
    }
    'WebUI' {
        $config = Read-SandboxConfig -EffectiveConfigPath $effectiveConfigPath
        $payloadRoot = Get-GuestPayloadRoot -State $state -Config $config -EffectiveRuntimeRoot $effectiveRuntimeRoot
        Ensure-GuestPayloadForWebUi -PayloadRoot $payloadRoot -Config $config
        Invoke-WebUi -EffectiveConfigPath $effectiveConfigPath
    }
    'StartWebUI' {
        $config = Read-SandboxConfig -EffectiveConfigPath $effectiveConfigPath
        $payloadRoot = Get-GuestPayloadRoot -State $state -Config $config -EffectiveRuntimeRoot $effectiveRuntimeRoot
        Ensure-GuestPayloadForWebUi -PayloadRoot $payloadRoot -Config $config
        Invoke-WebUi -EffectiveConfigPath $effectiveConfigPath
    }
    'Plan' {
        $config = Read-SandboxConfig -EffectiveConfigPath $effectiveConfigPath
        Invoke-OneShotAnalysis -EffectiveConfigPath $effectiveConfigPath -Config $config -EffectiveRuntimeRoot $effectiveRuntimeRoot -State $state
    }
    'Analyze' {
        $config = Read-SandboxConfig -EffectiveConfigPath $effectiveConfigPath
        Invoke-OneShotAnalysis -EffectiveConfigPath $effectiveConfigPath -Config $config -EffectiveRuntimeRoot $effectiveRuntimeRoot -State $state
    }
}
