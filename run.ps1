<#
.SYNOPSIS
Starts KSwordSandbox after local installation.

.DESCRIPTION
This is the operator-facing runtime entry point. Run install.ps1 once to prepare
local folders, Hyper-V config, and guest credentials; then run this script each
time you want to use the sandbox.

Default mode starts the local WebUI with the installed config:

  .\run.ps1

Single-sample CLI modes are also available:

  .\run.ps1 -Mode Plan -SamplePath D:\Temp\sample.exe
  .\run.ps1 -Mode Analyze -SamplePath D:\Temp\sample.exe -Live

The script loads C:\ProgramData\KSwordSandbox\install-state.json when present,
sets Sandbox__ConfigPath for the Web/API, mirrors the guest password from User
or Machine environment into the current process when available, and never prints
secret values.
#>
[CmdletBinding()]
param(
    [ValidateSet('WebUI', 'Analyze', 'Plan', 'Status')]
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

    [switch]$StrictUrl
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

function Import-InstalledEnvironment {
    param(
        [AllowNull()]$State,
        [Parameter(Mandatory)][string]$EffectiveConfigPath
    )

    [Environment]::SetEnvironmentVariable($script:WebConfigPathEnvironmentName, $EffectiveConfigPath, 'Process')
    $env:Sandbox__ConfigPath = $EffectiveConfigPath

    $secretName = Get-SecretName -State $State
    $processSecret = [Environment]::GetEnvironmentVariable($secretName, 'Process')
    if ([string]::IsNullOrEmpty($processSecret)) {
        $userSecret = [Environment]::GetEnvironmentVariable($secretName, 'User')
        if ([string]::IsNullOrEmpty($userSecret)) {
            $userSecret = [Environment]::GetEnvironmentVariable($secretName, 'Machine')
        }
        if (-not [string]::IsNullOrEmpty($userSecret)) {
            [Environment]::SetEnvironmentVariable($secretName, $userSecret, 'Process')
            Set-Item -Path "Env:\$secretName" -Value $userSecret
        }
    }
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

function Ensure-GuestPayload {
    param(
        [Parameter(Mandatory)][string]$PayloadRoot,
        [Parameter(Mandatory)][object]$Config
    )

    if ($SkipPayloadPreparation) {
        Write-RunInfo 'Skipped guest payload preparation by request.'
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
    $payloadReady = (Test-Path -LiteralPath $agentExe -PathType Leaf) -and (Test-Path -LiteralPath $collectorExe -PathType Leaf) -and (Test-Path -LiteralPath $manifest -PathType Leaf)

    if ($payloadReady -and -not $ForcePayloadPreparation) {
        Write-RunInfo "Guest payload ready: $PayloadRoot"
        return
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
}

function Show-RunStatus {
    param(
        [AllowNull()]$State,
        [Parameter(Mandatory)][string]$EffectiveRuntimeRoot,
        [Parameter(Mandatory)][string]$EffectiveConfigPath
    )

    $secretName = Get-SecretName -State $State
    $configExists = Test-Path -LiteralPath $EffectiveConfigPath -PathType Leaf
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

    [pscustomobject][ordered]@{
        RepositoryRoot = $script:RepositoryRoot
        InstallStatePath = $script:InstallStatePath
        InstallStateExists = Test-Path -LiteralPath $script:InstallStatePath -PathType Leaf
        ConfigPath = $EffectiveConfigPath
        ConfigExists = $configExists
        WebUrl = $Url
        RuntimeRoot = $EffectiveRuntimeRoot
        RuntimeRootExists = Test-Path -LiteralPath $EffectiveRuntimeRoot -PathType Container
        SecretName = $secretName
        ProcessSecretSet = -not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($secretName, 'Process'))
        UserSecretSet = -not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($secretName, 'User'))
        VmName = $vmName
        CheckpointName = $checkpointName
        HyperVModuleAvailable = $hyperVModuleAvailable
        VmExists = $vmExists
        VmState = $vmState
        CheckpointExists = $checkpointExists
        HyperVStatusError = $hyperVStatusError
        SecretValuePrinted = $false
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
    $env:ASPNETCORE_URLS = $effectiveUrl
    Write-RunInfo "Starting WebUI: $effectiveUrl"
    Write-RunInfo "Config: $EffectiveConfigPath"
    Write-RunInfo 'Press Ctrl+C to stop the WebUI.'

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

    $payloadRoot = Get-GuestPayloadRoot -State $State -Config $Config -EffectiveRuntimeRoot $EffectiveRuntimeRoot
    Ensure-GuestPayload -PayloadRoot $payloadRoot -Config $Config

    $invokeScript = Join-Path $script:RepositoryRoot 'scripts\Invoke-HyperVE2E.ps1'
    if (-not (Test-Path -LiteralPath $invokeScript -PathType Leaf)) {
        throw "Hyper-V E2E script is missing: $invokeScript"
    }

    $runLive = [bool]$Live -and (-not [bool]$PlanOnly) -and ($Mode -ne 'Plan')
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

if ($Mode -eq 'WebUI' -and -not [string]::IsNullOrWhiteSpace($SamplePath)) {
    $Mode = 'Analyze'
}

switch ($Mode) {
    'Status' {
        Show-RunStatus -State $state -EffectiveRuntimeRoot $effectiveRuntimeRoot -EffectiveConfigPath $effectiveConfigPath | Format-List
    }
    'WebUI' {
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
