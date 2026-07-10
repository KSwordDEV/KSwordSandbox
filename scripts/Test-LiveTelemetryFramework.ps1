<#
.SYNOPSIS
Runs lightweight live-telemetry framework checks without Hyper-V.

.DESCRIPTION
The default mode performs static source and documentation checks for the WebUI
live telemetry contract. Optional runtime mode probes an already-running Web API
and an existing job ID; the script never starts a VM, never requires
Administrator, and never launches Hyper-V cmdlets.

.PARAMETER ContractOnly
Skips runtime HTTP probing even when BaseUrl and JobId are supplied.

.PARAMETER BaseUrl
Optional Web API base URL for runtime probes, for example http://localhost:5000.

.PARAMETER JobId
Optional existing job ID for runtime probes.

.PARAMETER UsePollingFallback
Allows polling fallback validation when the SSE stream route is unavailable or
not usable in the current test harness.

.PARAMETER RequireImplementedStream
Requires the Web source to contain the SSE stream endpoint during static
contract checks. Leave this off when validating an expected-only endpoint.

.PARAMETER Offset
Initial event offset used by runtime probes.

.PARAMETER Take
Requested page size used by runtime probes.

.PARAMETER IntervalMs
Requested SSE polling interval used by runtime probes.
#>
[CmdletBinding()]
param(
    [switch]$ContractOnly,
    [string]$BaseUrl,
    [Guid]$JobId = [Guid]::Empty,
    [switch]$UsePollingFallback,
    [switch]$RequireImplementedStream,
    [int]$Offset = 0,
    [int]$Take = 100,
    [int]$IntervalMs = 2000
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$script:Results = New-Object System.Collections.Generic.List[object]
$script:FailureCount = 0

<#
Inputs: a start directory that may be inside the repository.
Processing: walks upward until the solution file is found.
Return: absolute repository root path, or throws when the root is unavailable.
#>
function Get-RepositoryRoot {
    param(
        [Parameter(Mandatory = $true)]
        [string]$StartPath
    )

    $directory = Get-Item -LiteralPath $StartPath
    if (-not $directory.PSIsContainer) {
        $directory = $directory.Directory
    }

    while ($null -ne $directory) {
        $solutionPath = Join-Path $directory.FullName 'KSwordSandbox.sln'
        if (Test-Path -LiteralPath $solutionPath) {
            return $directory.FullName
        }

        $directory = $directory.Parent
    }

    throw 'Could not locate KSwordSandbox.sln from script path.'
}

<#
Inputs: a check name, pass/fail value, and optional diagnostic detail.
Processing: records a machine-readable result and increments the failure count
when the condition failed.
Return: no return value.
#>
function Add-CheckResult {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [bool]$Passed,

        [string]$Detail = ''
    )

    if (-not $Passed) {
        $script:FailureCount++
    }

    $script:Results.Add([pscustomobject]@{
        Name   = $Name
        Passed = $Passed
        Detail = $Detail
    }) | Out-Null
}

<#
Inputs: repository root and a relative file path.
Processing: validates the file exists and reads it as one string.
Return: UTF-8/Unicode text content from the requested file.
#>
function Get-RepositoryText {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepositoryRoot,

        [Parameter(Mandatory = $true)]
        [string]$RelativePath
    )

    $path = Join-Path $RepositoryRoot $RelativePath
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Required file is missing: $RelativePath"
    }

    return Get-Content -LiteralPath $path -Raw
}

<#
Inputs: text content, expected literal text, and a check name.
Processing: performs an ordinal substring check and records the result.
Return: no return value.
#>
function Test-LiteralText {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Content,

        [Parameter(Mandatory = $true)]
        [string]$Expected,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    Add-CheckResult -Name $Name -Passed ($Content.Contains($Expected)) -Detail $Expected
}

<#
Inputs: text content, regular expression pattern, and a check name.
Processing: performs a regex check and records the result.
Return: no return value.
#>
function Test-RegexText {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Content,

        [Parameter(Mandatory = $true)]
        [string]$Pattern,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    Add-CheckResult -Name $Name -Passed ($Content -match $Pattern) -Detail $Pattern
}

<#
Inputs: source text, expected literal text, check name, and required flag.
Processing: records the check as passed when the literal is present, or when the
literal is expected-only and the caller did not require implementation.
Return: no return value.
#>
function Test-OptionalImplementationText {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Content,

        [Parameter(Mandatory = $true)]
        [string]$Expected,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [bool]$Required
    )

    $present = $Content.Contains($Expected)
    $detailPrefix = if ($present) { 'present' } else { 'expected-only' }
    Add-CheckResult -Name $Name -Passed ($present -or -not $Required) -Detail "${detailPrefix}: $Expected"
}

<#
Inputs: repository root.
Processing: checks Web source, core model source, docs, and scenario files for
the routes and fields required by live telemetry QA.
Return: no return value; failures are accumulated in script state.
#>
function Invoke-StaticContractChecks {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepositoryRoot,

        [Parameter(Mandatory = $true)]
        [bool]$RequireStreamImplementation
    )

    $program = Get-RepositoryText -RepositoryRoot $RepositoryRoot -RelativePath 'src\KSword.Sandbox.Web\Program.cs'
    $executionModels = Get-RepositoryText -RepositoryRoot $RepositoryRoot -RelativePath 'src\KSword.Sandbox.Abstractions\ExecutionModels.cs'
    $liveDoc = Get-RepositoryText -RepositoryRoot $RepositoryRoot -RelativePath 'docs\live-telemetry-pipeline.md'
    $runnerDoc = Get-RepositoryText -RepositoryRoot $RepositoryRoot -RelativePath 'docs\hyperv-runner.md'

    Test-LiteralText -Content $program -Expected '"/api/jobs/{jobId:guid}/events/live"' -Name 'Web source maps polling live-events route'
    Test-LiteralText -Content $program -Expected 'int? offset' -Name 'SSE/polling source accepts offset'
    Test-LiteralText -Content $program -Expected 'int? take' -Name 'SSE/polling source accepts take'
    Test-OptionalImplementationText -Content $program -Expected '"/api/jobs/{jobId:guid}/events/stream"' -Name 'Web source maps SSE live-events route' -Required $RequireStreamImplementation
    Test-OptionalImplementationText -Content $program -Expected 'int? intervalMs' -Name 'SSE source accepts intervalMs' -Required $RequireStreamImplementation
    Test-OptionalImplementationText -Content $program -Expected 'text/event-stream' -Name 'SSE source sets event-stream content type' -Required $RequireStreamImplementation
    Test-OptionalImplementationText -Content $program -Expected 'event: snapshot' -Name 'SSE source writes snapshot frames' -Required $RequireStreamImplementation
    Test-OptionalImplementationText -Content $program -Expected 'Math.Clamp(take ?? 100, 1, 500)' -Name 'SSE source clamps take' -Required $RequireStreamImplementation
    Test-OptionalImplementationText -Content $program -Expected 'Math.Clamp(intervalMs ?? 2000, 500, 10000)' -Name 'SSE source clamps intervalMs' -Required $RequireStreamImplementation
    Test-RegexText -Content $program -Pattern 'events/live\?offset=\$\{offset\}&take=100' -Name 'WebUI polling fallback uses offset and take'
    Test-LiteralText -Content $program -Expected '/runbook/execute' -Name 'WebUI source calls runbook execution endpoint'
    Test-LiteralText -Content $program -Expected 'step.exitCode' -Name 'WebUI source exposes runbook exit code'
    Test-LiteralText -Content $program -Expected 'step.message' -Name 'WebUI source exposes runbook step message'

    Test-LiteralText -Content $executionModels -Expected 'StandardOutput' -Name 'Runbook model stores stdout'
    Test-LiteralText -Content $executionModels -Expected 'StandardError' -Name 'Runbook model stores stderr'
    Test-LiteralText -Content $executionModels -Expected 'ExitCode' -Name 'Runbook model stores exit code'
    Test-LiteralText -Content $executionModels -Expected 'Duration' -Name 'Runbook model stores duration'
    Test-LiteralText -Content $executionModels -Expected 'Message' -Name 'Runbook model stores error/message'

    Test-LiteralText -Content $liveDoc -Expected '/api/jobs/{jobId}/events/stream' -Name 'Live telemetry doc covers SSE route'
    Test-LiteralText -Content $liveDoc -Expected '/api/jobs/{jobId}/events/live' -Name 'Live telemetry doc covers polling fallback route'
    Test-LiteralText -Content $liveDoc -Expected 'offset' -Name 'Live telemetry doc covers offset'
    Test-LiteralText -Content $liveDoc -Expected 'take' -Name 'Live telemetry doc covers take'
    Test-LiteralText -Content $liveDoc -Expected 'intervalMs' -Name 'Live telemetry doc covers intervalMs'
    Test-LiteralText -Content $liveDoc -Expected 'event: snapshot' -Name 'Live telemetry doc describes snapshot SSE frames'

    Test-LiteralText -Content $runnerDoc -Expected 'stdout' -Name 'Hyper-V runner doc covers stdout UX'
    Test-LiteralText -Content $runnerDoc -Expected 'stderr' -Name 'Hyper-V runner doc covers stderr UX'
    Test-LiteralText -Content $runnerDoc -Expected 'exit code' -Name 'Hyper-V runner doc covers exit code UX'
    Test-LiteralText -Content $runnerDoc -Expected 'duration' -Name 'Hyper-V runner doc covers duration UX'
    Test-LiteralText -Content $runnerDoc -Expected 'error' -Name 'Hyper-V runner doc covers error UX'

    $scenarioPath = Join-Path $RepositoryRoot 'tests\KSword.Sandbox.SmokeTests\Scenarios\LiveTelemetryContractScenario.cs'
    Add-CheckResult -Name 'Live telemetry smoke scenario exists' -Passed (Test-Path -LiteralPath $scenarioPath) -Detail $scenarioPath
}

<#
Inputs: base URL, job ID, offset, take, and interval.
Processing: opens the SSE endpoint only until response headers are available and
validates status/content type without waiting for VM activity.
Return: true when SSE is usable; false when fallback may be attempted.
#>
function Test-SseEndpoint {
    param(
        [Parameter(Mandatory = $true)]
        [string]$NormalizedBaseUrl,

        [Parameter(Mandatory = $true)]
        [Guid]$RuntimeJobId,

        [int]$RuntimeOffset,
        [int]$RuntimeTake,
        [int]$RuntimeIntervalMs,
        [switch]$AllowFallback
    )

    Add-Type -AssemblyName System.Net.Http

    $uri = '{0}/api/jobs/{1}/events/stream?offset={2}&take={3}&intervalMs={4}' -f $NormalizedBaseUrl, $RuntimeJobId, $RuntimeOffset, $RuntimeTake, $RuntimeIntervalMs
    $client = [System.Net.Http.HttpClient]::new()
    $request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get, $uri)
    $request.Headers.Accept.ParseAdd('text/event-stream')
    $cancellation = [System.Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(8))

    try {
        $response = $client.SendAsync(
            $request,
            [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead,
            $cancellation.Token).GetAwaiter().GetResult()
        try {
            $statusCode = [int]$response.StatusCode
            $mediaType = ''
            if ($null -ne $response.Content.Headers.ContentType) {
                $mediaType = $response.Content.Headers.ContentType.MediaType
            }

            if ($statusCode -eq 200 -and $mediaType -like 'text/event-stream*') {
                Add-CheckResult -Name 'Runtime SSE stream returns event-stream headers' -Passed $true -Detail $uri
                return $true
            }

            $fallbackStatus = $statusCode -in 404, 405, 501
            $fallbackContentType = $mediaType -notlike 'text/event-stream*'
            Add-CheckResult -Name 'Runtime SSE stream unavailable only by fallback-safe status/content type' -Passed ($AllowFallback -and ($fallbackStatus -or $fallbackContentType)) -Detail "status=$statusCode contentType=$mediaType"
            return $false
        }
        finally {
            $response.Dispose()
        }
    }
    catch {
        Add-CheckResult -Name 'Runtime SSE stream connection' -Passed $AllowFallback.IsPresent -Detail $_.Exception.Message
        return $false
    }
    finally {
        $cancellation.Dispose()
        $request.Dispose()
        $client.Dispose()
    }
}

<#
Inputs: base URL, job ID, offset, and take.
Processing: calls the polling endpoint and validates the LiveEventSnapshot JSON
shape without requiring VM execution.
Return: no return value; failures are accumulated in script state.
#>
function Test-PollingEndpoint {
    param(
        [Parameter(Mandatory = $true)]
        [string]$NormalizedBaseUrl,

        [Parameter(Mandatory = $true)]
        [Guid]$RuntimeJobId,

        [int]$RuntimeOffset,
        [int]$RuntimeTake
    )

    $uri = '{0}/api/jobs/{1}/events/live?offset={2}&take={3}' -f $NormalizedBaseUrl, $RuntimeJobId, $RuntimeOffset, $RuntimeTake

    try {
        $snapshot = Invoke-RestMethod -Method Get -Uri $uri -TimeoutSec 10
        $properties = @('jobId', 'retrievedAt', 'totalEvents', 'nextOffset', 'hasMore', 'sources', 'events')
        foreach ($property in $properties) {
            Add-CheckResult -Name "Runtime polling snapshot has $property" -Passed ($null -ne $snapshot.PSObject.Properties[$property]) -Detail $uri
        }
    }
    catch {
        Add-CheckResult -Name 'Runtime polling fallback request succeeds' -Passed $false -Detail $_.Exception.Message
    }
}

<#
Inputs: optional base URL and job ID from script parameters.
Processing: runs static checks, then optional SSE and polling probes when a
runtime target was supplied.
Return: process exit code 0 on pass, 1 on failure.
#>
function Invoke-Main {
    $repositoryRoot = Get-RepositoryRoot -StartPath $PSScriptRoot
    Invoke-StaticContractChecks -RepositoryRoot $repositoryRoot -RequireStreamImplementation ([bool]$RequireImplementedStream)

    $hasRuntimeTarget = -not [string]::IsNullOrWhiteSpace($BaseUrl) -and $JobId -ne [Guid]::Empty
    if (-not $ContractOnly -and $hasRuntimeTarget) {
        $normalizedBaseUrl = $BaseUrl.TrimEnd('/')
        $sseUsable = Test-SseEndpoint `
            -NormalizedBaseUrl $normalizedBaseUrl `
            -RuntimeJobId $JobId `
            -RuntimeOffset $Offset `
            -RuntimeTake $Take `
            -RuntimeIntervalMs $IntervalMs `
            -AllowFallback:$UsePollingFallback

        if ($UsePollingFallback -or -not $sseUsable) {
            Test-PollingEndpoint `
                -NormalizedBaseUrl $normalizedBaseUrl `
                -RuntimeJobId $JobId `
                -RuntimeOffset $Offset `
                -RuntimeTake $Take
        }
    }
    else {
        Add-CheckResult -Name 'Runtime probe skipped' -Passed $true -Detail 'Provide -BaseUrl and -JobId without -ContractOnly to probe a running Web API.'
    }

    $script:Results | Format-Table -AutoSize

    if ($script:FailureCount -gt 0) {
        Write-Error "$($script:FailureCount) live telemetry framework check(s) failed."
        return 1
    }

    Write-Host 'Live telemetry framework checks passed.'
    return 0
}

exit (Invoke-Main)
