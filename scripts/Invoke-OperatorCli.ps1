<#
.SYNOPSIS
Unified operator CLI wrapper for KSword Sandbox jobs.

.DESCRIPTION
Provides JSON-friendly plan/import/report/artifacts/list/status/recover/readiness
entry points for debugging the minimal host-side chain without WebUI. The
default operations do not start, restore, stop, or mutate Hyper-V VMs. The
plan command wraps Invoke-HyperVE2E.ps1 in PlanOnly mode; other commands call
KSword.Sandbox.JobTool.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateSet('plan', 'import', 'report', 'artifacts', 'list', 'status', 'recover', 'readiness')]
    [string]$Command,

    [string]$RepoRoot = '',
    [string]$ConfigPath = '',
    [string]$RuntimeRoot = '',
    [string]$JobId = '',
    [string]$JobRoot = '',
    [string]$SamplePath = '',
    [string]$EventsPath = '',
    [string]$RunbookExecutionPath = '',
    [string]$PlanPath = '',
    [int]$DurationSeconds = 120,
    [ValidateRange(1, 1000)][int]$Limit = 100,
    [switch]$WriteIndex,
    [switch]$WriteState,
    [switch]$RebuildReport,
    [switch]$IncludeMetadata,
    [switch]$Json,
    [switch]$NoBuild,
    [switch]$HyperVReadiness
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Resolve-OperatorRepoRoot {
    param([string]$Value)

    if (-not [string]::IsNullOrWhiteSpace($Value)) {
        return [System.IO.Path]::GetFullPath($Value)
    }

    return (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).ProviderPath
}

function Read-OperatorJsonFile {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }

    try {
        return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    }
    catch {
        return $null
    }
}

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

function Resolve-OperatorConfigPath {
    param(
        [string]$RepoRoot,
        [string]$Value
    )

    if (-not [string]::IsNullOrWhiteSpace($Value)) {
        if ([System.IO.Path]::IsPathRooted($Value)) {
            return [System.IO.Path]::GetFullPath($Value)
        }

        return [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $Value))
    }

    $envConfig = [Environment]::GetEnvironmentVariable('Sandbox__ConfigPath', 'Process')
    if ([string]::IsNullOrWhiteSpace($envConfig)) {
        $envConfig = [Environment]::GetEnvironmentVariable('Sandbox__ConfigPath', 'User')
    }
    if ([string]::IsNullOrWhiteSpace($envConfig)) {
        $envConfig = [Environment]::GetEnvironmentVariable('Sandbox__ConfigPath', 'Machine')
    }
    if (-not [string]::IsNullOrWhiteSpace($envConfig)) {
        return $envConfig
    }

    return Join-Path $RepoRoot 'config\sandbox.example.json'
}

function Resolve-OperatorRuntimeRoot {
    param(
        [string]$RepoRoot,
        [string]$ConfigPath,
        [string]$Value
    )

    if (-not [string]::IsNullOrWhiteSpace($Value)) {
        return [System.IO.Path]::GetFullPath($Value)
    }

    $config = Read-OperatorJsonFile -Path $ConfigPath
    $paths = if ($null -eq $config) {
        $null
    }
    else {
        $pathsProperty = $config.PSObject.Properties['paths']
        if ($null -eq $pathsProperty) { $null } else { $pathsProperty.Value }
    }
    $runtime = Get-ObjectPropertyString -Object $paths -Name 'runtimeRoot' -DefaultValue 'D:\Temp\KSwordSandbox'
    if ([System.IO.Path]::IsPathRooted($runtime)) {
        return [System.IO.Path]::GetFullPath($runtime)
    }

    return [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $runtime))
}

function Get-OperatorPowerShellExecutable {
    $currentProcess = Get-Process -Id $PID
    if (-not [string]::IsNullOrWhiteSpace($currentProcess.Path) -and
        (Test-Path -LiteralPath $currentProcess.Path -PathType Leaf)) {
        return $currentProcess.Path
    }

    $pwsh = Join-Path $PSHOME 'pwsh.exe'
    if (Test-Path -LiteralPath $pwsh -PathType Leaf) {
        return $pwsh
    }

    $powershell = Join-Path $PSHOME 'powershell.exe'
    if (Test-Path -LiteralPath $powershell -PathType Leaf) {
        return $powershell
    }

    return 'powershell.exe'
}

function Write-OperatorObject {
    param(
        [Parameter(Mandatory)]$Object,
        [bool]$AsJson
    )

    if ($AsJson) {
        $Object | ConvertTo-Json -Depth 24
        return
    }

    $Object
}

function Invoke-JobToolCommand {
    param(
        [string]$JobToolCommand,
        [string[]]$ExtraArgs = @()
    )

    $resolver = Join-Path $PSScriptRoot 'Resolve-PortableTool.ps1'
    if (-not (Test-Path -LiteralPath $resolver -PathType Leaf)) {
        throw "Portable tool resolver not found: $resolver"
    }
    . $resolver

    $target = Resolve-KSwordPortableTool -RepoRoot $script:ResolvedRepoRoot -Tool JobTool -ThrowIfMissing
    if ($target.RequiresDotNet -and $null -eq (Get-Command dotnet -ErrorAction SilentlyContinue)) {
        throw "JobTool target '$($target.Kind)' requires dotnet, but dotnet was not found in PATH. $($target.RecommendedAction)"
    }

    $toolArgs = @($JobToolCommand, '--repo-root', $script:ResolvedRepoRoot)
    if (-not [string]::IsNullOrWhiteSpace($script:ResolvedConfigPath)) {
        $toolArgs += @('--config', $script:ResolvedConfigPath)
    }
    if (-not [string]::IsNullOrWhiteSpace($script:ResolvedRuntimeRoot)) {
        $toolArgs += @('--runtime-root', $script:ResolvedRuntimeRoot)
    }
    if ($Json) {
        $toolArgs += '--json'
    }

    $toolArgs += $ExtraArgs

    if ($target.Kind -eq 'SourceProject') {
        $launcher = 'dotnet'
        $launcherArgs = @('run')
        if ($NoBuild) {
            $launcherArgs += '--no-build'
        }

        $launcherArgs += @('--project', [string]$target.Path, '--')
        $launcherArgs += $toolArgs
    }
    elseif ($target.Kind -eq 'PublishedDll') {
        $launcher = 'dotnet'
        $launcherArgs = @([string]$target.Path)
        $launcherArgs += $toolArgs
    }
    elseif ($target.Kind -eq 'PublishedExe') {
        $launcher = [string]$target.Path
        $launcherArgs = $toolArgs
    }
    else {
        throw "JobTool target is not runnable: $($target.Kind)"
    }

    if (-not $Json) {
        Write-Host "[ksword-operator] JobTool $JobToolCommand via $($target.Kind)"
    }

    $startedAtUtc = [DateTimeOffset]::UtcNow
    $output = @()
    $exitCode = 1
    try {
        $output = @(& $launcher @launcherArgs 2>&1 | ForEach-Object { [string]$_ })
        $exitCode = $LASTEXITCODE
    }
    catch {
        $output = @("JobTool launch failed: $($_.Exception.Message)")
        $exitCode = 127
    }

    if ($exitCode -ne 0 -and $Json) {
        [pscustomobject][ordered]@{
            contractVersion = 1
            kind = 'KSwordSandbox.OperatorCliResult'
            command = $JobToolCommand
            success = $false
            exitCode = $exitCode
            startedAtUtc = $startedAtUtc.ToString('O')
            completedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
            repoRoot = $script:ResolvedRepoRoot
            configPath = $script:ResolvedConfigPath
            runtimeRoot = $script:ResolvedRuntimeRoot
            jobId = $JobId
            jobRoot = $JobRoot
            vmAction = 'none'
            willMutateVm = $false
            noBuild = [bool]$NoBuild
            rawOutput = @($output)
            remediationHints = @(
                '下一步：查看 rawOutput 的第一条错误；若是 build/SDK 问题，先运行 dotnet --info 并确认安装 net9.0 SDK。',
                '下一步：若是缺少 events/report/job 产物，运行 plan/status/recover 或传入 -EventsPath/-JobRoot 后重试。',
                '下一步：本 wrapper 不启动或修改 VM；Live Hyper-V 仍只能通过显式 -Live 的 E2E/run 路径触发。'
            )
            secretValuePrinted = $false
        } | ConvertTo-Json -Depth 24
        exit $exitCode
    }

    if ($output.Count -gt 0) {
        $output | ForEach-Object {
            if ($Json) {
                Write-Output $_
            }
            else {
                Write-Host $_
            }
        }
    }

    exit $exitCode
}

function Invoke-OperatorPlan {
    $scriptPath = Join-Path $script:ResolvedRepoRoot 'scripts\Invoke-HyperVE2E.ps1'
    if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
        throw "Invoke-HyperVE2E.ps1 was not found: $scriptPath"
    }

    $effectiveJobId = if ([string]::IsNullOrWhiteSpace($JobId)) { [Guid]::NewGuid().ToString('D') } else { [Guid]::Parse($JobId).ToString('D') }
    $jobIdN = ([Guid]::Parse($effectiveJobId)).ToString('N')
    $effectivePlanPath = $PlanPath
    if ([string]::IsNullOrWhiteSpace($effectivePlanPath)) {
        $effectivePlanPath = Join-Path (Join-Path $script:ResolvedRuntimeRoot 'plans') "hyperv-e2e-$jobIdN.json"
    }
    elseif (-not [System.IO.Path]::IsPathRooted($effectivePlanPath)) {
        $effectivePlanPath = [System.IO.Path]::GetFullPath((Join-Path $script:ResolvedRepoRoot $effectivePlanPath))
    }

    $childArgs = @(
        '-NoLogo',
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $scriptPath,
        '-RepoRoot', $script:ResolvedRepoRoot,
        '-ConfigPath', $script:ResolvedConfigPath,
        '-RuntimeRoot', $script:ResolvedRuntimeRoot,
        '-JobId', $effectiveJobId,
        '-PlanPath', $effectivePlanPath,
        '-DurationSeconds', ([string]$DurationSeconds),
        '-PlanOnly'
    )
    if (-not [string]::IsNullOrWhiteSpace($SamplePath)) {
        $childArgs += @('-SamplePath', $SamplePath)
    }

    $powerShell = Get-OperatorPowerShellExecutable
    $childOutput = @(& $powerShell @childArgs 2>&1 | ForEach-Object { [string]$_ })
    $exitCode = $LASTEXITCODE
    $plan = Read-OperatorJsonFile -Path $effectivePlanPath
    $runbookExecutionPath = if ($null -ne $plan) { Get-ObjectPropertyString -Object $plan.host -Name 'runbookExecutionPath' } else { '' }
    $runbook = Read-OperatorJsonFile -Path $runbookExecutionPath
    $jobRoot = if ($null -ne $plan) { Get-ObjectPropertyString -Object $plan.host -Name 'jobRoot' } else { Join-Path (Join-Path $script:ResolvedRuntimeRoot 'jobs') $jobIdN }

    $result = [pscustomobject][ordered]@{
        contractVersion = 1
        kind = 'KSwordSandbox.OperatorCliResult'
        command = 'plan'
        success = ($exitCode -eq 0)
        exitCode = $exitCode
        jobId = $effectiveJobId
        jobRoot = $jobRoot
        planPath = $effectivePlanPath
        runbookExecutionPath = $runbookExecutionPath
        willMutateVm = if ($null -ne $plan) { [bool]$plan.willMutateVm } else { $false }
        vmAction = 'none'
        mode = if ($null -ne $plan) { [string]$plan.effectiveMode } else { 'PlanOnly' }
        preflightSummary = if ($null -ne $plan) { $plan.preflightSummary } else { $null }
        runbookExecution = $runbook
        childOutput = if ($exitCode -eq 0) { @() } else { @($childOutput) }
        secretValuePrinted = $false
    }

    if ((-not $Json) -and $childOutput.Count -gt 0) {
        $childOutput | ForEach-Object { Write-Host $_ }
    }
    Write-OperatorObject -Object $result -AsJson ([bool]$Json)
    exit $exitCode
}

$script:ResolvedRepoRoot = Resolve-OperatorRepoRoot -Value $RepoRoot
$script:ResolvedConfigPath = Resolve-OperatorConfigPath -RepoRoot $script:ResolvedRepoRoot -Value $ConfigPath
$script:ResolvedRuntimeRoot = Resolve-OperatorRuntimeRoot -RepoRoot $script:ResolvedRepoRoot -ConfigPath $script:ResolvedConfigPath -Value $RuntimeRoot

switch ($Command) {
    'plan' {
        Invoke-OperatorPlan
    }
    'list' {
        Invoke-JobToolCommand -JobToolCommand 'list' -ExtraArgs @('--limit', ([string]$Limit))
    }
    'status' {
        $extra = @()
        if (-not [string]::IsNullOrWhiteSpace($JobId)) { $extra += @('--job-id', $JobId) }
        if (-not [string]::IsNullOrWhiteSpace($JobRoot)) { $extra += @('--job-root', $JobRoot) }
        Invoke-JobToolCommand -JobToolCommand 'status' -ExtraArgs $extra
    }
    'report' {
        $extra = @('--duration', ([string]$DurationSeconds))
        if (-not [string]::IsNullOrWhiteSpace($JobId)) { $extra += @('--job-id', $JobId) }
        if (-not [string]::IsNullOrWhiteSpace($JobRoot)) { $extra += @('--job-root', $JobRoot) }
        if (-not [string]::IsNullOrWhiteSpace($SamplePath)) { $extra += @('--sample', $SamplePath) }
        if (-not [string]::IsNullOrWhiteSpace($EventsPath)) { $extra += @('--events', $EventsPath) }
        if (-not [string]::IsNullOrWhiteSpace($RunbookExecutionPath)) { $extra += @('--runbook-execution', $RunbookExecutionPath) }
        Invoke-JobToolCommand -JobToolCommand 'report' -ExtraArgs $extra
    }
    'import' {
        $extra = @('--duration', ([string]$DurationSeconds))
        if (-not [string]::IsNullOrWhiteSpace($JobId)) { $extra += @('--job-id', $JobId) }
        if (-not [string]::IsNullOrWhiteSpace($JobRoot)) { $extra += @('--job-root', $JobRoot) }
        if (-not [string]::IsNullOrWhiteSpace($SamplePath)) { $extra += @('--sample', $SamplePath) }
        if (-not [string]::IsNullOrWhiteSpace($EventsPath)) { $extra += @('--events', $EventsPath) }
        if (-not [string]::IsNullOrWhiteSpace($RunbookExecutionPath)) { $extra += @('--runbook-execution', $RunbookExecutionPath) }
        Invoke-JobToolCommand -JobToolCommand 'import' -ExtraArgs $extra
    }
    'artifacts' {
        $extra = @('--limit', ([string]$Limit))
        if (-not [string]::IsNullOrWhiteSpace($JobId)) { $extra += @('--job-id', $JobId) }
        if (-not [string]::IsNullOrWhiteSpace($JobRoot)) { $extra += @('--job-root', $JobRoot) }
        if ($WriteIndex) { $extra += '--write-index' }
        if ($IncludeMetadata) { $extra += '--include-metadata' }
        Invoke-JobToolCommand -JobToolCommand 'artifacts' -ExtraArgs $extra
    }
    'recover' {
        $extra = @()
        if (-not [string]::IsNullOrWhiteSpace($JobId)) { $extra += @('--job-id', $JobId) }
        if (-not [string]::IsNullOrWhiteSpace($JobRoot)) { $extra += @('--job-root', $JobRoot) }
        if (-not [string]::IsNullOrWhiteSpace($SamplePath)) { $extra += @('--sample', $SamplePath) }
        if (-not [string]::IsNullOrWhiteSpace($EventsPath)) { $extra += @('--events', $EventsPath) }
        if (-not [string]::IsNullOrWhiteSpace($RunbookExecutionPath)) { $extra += @('--runbook-execution', $RunbookExecutionPath) }
        if ($WriteIndex) { $extra += '--write-index' }
        if ($WriteState) { $extra += '--write-state' }
        if ($RebuildReport) { $extra += '--rebuild-report' }
        Invoke-JobToolCommand -JobToolCommand 'recover' -ExtraArgs $extra
    }
    'readiness' {
        if ($HyperVReadiness) {
            $readinessScript = Join-Path $script:ResolvedRepoRoot 'scripts\Test-HyperVReadiness.ps1'
            if (-not (Test-Path -LiteralPath $readinessScript -PathType Leaf)) {
                throw "Test-HyperVReadiness.ps1 was not found: $readinessScript"
            }

            $powerShell = Get-OperatorPowerShellExecutable
            $readinessArgs = @(
                '-NoLogo',
                '-NoProfile',
                '-ExecutionPolicy', 'Bypass',
                '-Command',
                "& '$readinessScript' -RepositoryRoot '$($script:ResolvedRepoRoot.Replace("'", "''"))' -ConfigPath '$($script:ResolvedConfigPath.Replace("'", "''"))' | ConvertTo-Json -Depth 24"
            )
            $output = @(& $powerShell @readinessArgs 2>&1 | ForEach-Object { [string]$_ })
            $exitCode = $LASTEXITCODE
            if ($Json) {
                $parsed = $null
                try { $parsed = ($output -join [Environment]::NewLine) | ConvertFrom-Json } catch { $parsed = $null }
                [pscustomobject][ordered]@{
                    contractVersion = 1
                    kind = 'KSwordSandbox.OperatorCliResult'
                    command = 'readiness'
                    mode = 'hyperv'
                    success = ($exitCode -eq 0)
                    exitCode = $exitCode
                    result = $parsed
                    rawOutput = if ($null -eq $parsed) { @($output) } else { @() }
                    secretValuePrinted = $false
                } | ConvertTo-Json -Depth 28
            }
            else {
                $output
            }
            exit $exitCode
        }

        $extra = @()
        if (-not [string]::IsNullOrWhiteSpace($JobId)) { $extra += @('--job-id', $JobId) }
        if (-not [string]::IsNullOrWhiteSpace($JobRoot)) { $extra += @('--job-root', $JobRoot) }
        if (-not [string]::IsNullOrWhiteSpace($SamplePath)) { $extra += @('--sample', $SamplePath) }
        Invoke-JobToolCommand -JobToolCommand 'readiness' -ExtraArgs $extra
    }
}
