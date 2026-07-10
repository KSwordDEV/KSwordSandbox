<#
.SYNOPSIS
Runs lightweight live-telemetry framework checks without Hyper-V.

.DESCRIPTION
The default mode performs static source and documentation checks for the WebUI
live telemetry contract. Optional runtime mode probes an already-running Web API
and an existing job ID; the script never starts a VM, never requires
Administrator, and never launches Hyper-V cmdlets. When -BaseUrl or -JobId are
omitted, runtime mode reads KSWORD_SMOKE_BASE_URL and KSWORD_SMOKE_JOB_ID.

.PARAMETER ContractOnly
Skips runtime HTTP probing even when BaseUrl and JobId are supplied.

.PARAMETER BaseUrl
Optional Web API base URL for runtime probes, for example http://localhost:5000.
Defaults to KSWORD_SMOKE_BASE_URL when omitted.

.PARAMETER JobId
Optional existing job ID for runtime probes. Defaults to KSWORD_SMOKE_JOB_ID
when omitted.

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
    $dashboard = Get-RepositoryText -RepositoryRoot $RepositoryRoot -RelativePath 'src\KSword.Sandbox.Web\Dashboard\DashboardExperiencePage.cs'
    $liveEventsPage = Get-RepositoryText -RepositoryRoot $RepositoryRoot -RelativePath 'src\KSword.Sandbox.Web\Dashboard\LiveEventsPage.cs'
    $executionFlowPage = Get-RepositoryText -RepositoryRoot $RepositoryRoot -RelativePath 'src\KSword.Sandbox.Web\Dashboard\RunbookExecutionFlowPage.cs'
    $executionModels = Get-RepositoryText -RepositoryRoot $RepositoryRoot -RelativePath 'src\KSword.Sandbox.Abstractions\ExecutionModels.cs'
    $liveDoc = Get-RepositoryText -RepositoryRoot $RepositoryRoot -RelativePath 'docs\live-telemetry-pipeline.md'
    $runnerDoc = Get-RepositoryText -RepositoryRoot $RepositoryRoot -RelativePath 'docs\hyperv-runner.md'
    $webuiDoc = Get-RepositoryText -RepositoryRoot $RepositoryRoot -RelativePath 'docs\webui-framework.md'
    $webUiSources = "$program`n$dashboard`n$liveEventsPage`n$executionFlowPage"

    Test-LiteralText -Content $program -Expected '"/api/jobs/{jobId:guid}/events/live"' -Name 'Web source maps polling live-events route'
    Test-LiteralText -Content $program -Expected '"/api/jobs/{jobId:guid}/report/html"' -Name 'Web source maps served report route'
    Test-LiteralText -Content $program -Expected '"/api/jobs/{jobId:guid}/guest-events/import"' -Name 'Web source maps manual guest import route'
    Test-LiteralText -Content $program -Expected 'GuestEventImportRequest' -Name 'Web source keeps typed guest import request'
    Test-LiteralText -Content $program -Expected 'EventsPath' -Name 'Web source accepts optional guest import events path'
    Test-LiteralText -Content $program -Expected 'int? offset' -Name 'SSE/polling source accepts offset'
    Test-LiteralText -Content $program -Expected 'int? take' -Name 'SSE/polling source accepts take'
    Test-OptionalImplementationText -Content $program -Expected '"/api/jobs/{jobId:guid}/events/stream"' -Name 'Web source maps SSE live-events route' -Required $RequireStreamImplementation
    Test-OptionalImplementationText -Content $program -Expected 'int? intervalMs' -Name 'SSE source accepts intervalMs' -Required $RequireStreamImplementation
    Test-OptionalImplementationText -Content $program -Expected 'text/event-stream' -Name 'SSE source sets event-stream content type' -Required $RequireStreamImplementation
    Test-OptionalImplementationText -Content $program -Expected 'event: snapshot' -Name 'SSE source writes snapshot frames' -Required $RequireStreamImplementation
    Test-OptionalImplementationText -Content $program -Expected 'Math.Clamp(take ?? 100, 1, 500)' -Name 'SSE source clamps take' -Required $RequireStreamImplementation
    Test-OptionalImplementationText -Content $program -Expected 'Math.Clamp(intervalMs ?? 2000, 500, 10000)' -Name 'SSE source clamps intervalMs' -Required $RequireStreamImplementation
    Test-RegexText -Content $webUiSources -Pattern 'events/live\?offset=\$\{(?:offset|eventOffset)\}&take=100' -Name 'WebUI polling fallback uses offset and take'
    Test-LiteralText -Content $program -Expected '/runbook/execute' -Name 'WebUI source calls runbook execution endpoint'
    Test-LiteralText -Content $executionFlowPage -Expected 'result?.ExitCode' -Name 'Execution-flow page exposes runbook exit code'
    Test-LiteralText -Content $executionFlowPage -Expected 'result.Message' -Name 'Execution-flow page exposes runbook step message'

    Test-LiteralText -Content $dashboard -Expected 'Open served report' -Name 'Dashboard renders served report link'
    Test-LiteralText -Content $dashboard -Expected 'Open local file' -Name 'Dashboard renders local report fallback link'
    Test-LiteralText -Content $dashboard -Expected 'guestImportPath' -Name 'Dashboard renders manual guest import path input'
    Test-LiteralText -Content $dashboard -Expected 'guest-events/import' -Name 'Dashboard calls manual guest import endpoint'
    Test-LiteralText -Content $dashboard -Expected 'JSON.stringify(explicitPath ? { eventsPath: explicitPath } : {})' -Name 'Dashboard sends optional manual guest import path JSON'

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

    Test-LiteralText -Content $webuiDoc -Expected 'KSWORD_SMOKE_BASE_URL' -Name 'WebUI doc covers runtime smoke base URL environment variable'
    Test-LiteralText -Content $webuiDoc -Expected 'KSWORD_SMOKE_JOB_ID' -Name 'WebUI doc covers runtime smoke job ID environment variable'
    Test-LiteralText -Content $webuiDoc -Expected '/api/jobs/{jobId}/events/live' -Name 'WebUI doc covers runtime live endpoint probe'
    Test-LiteralText -Content $webuiDoc -Expected '/api/jobs/{jobId}/report/html' -Name 'WebUI doc covers runtime report endpoint probe'
    Test-LiteralText -Content $webuiDoc -Expected '/api/jobs/{jobId}/guest-events/import' -Name 'WebUI doc covers runtime manual guest import endpoint probe'
    Test-LiteralText -Content $webuiDoc -Expected 'static gate' -Name 'WebUI doc covers static gate fallback'

    $scenarioPath = Join-Path $RepositoryRoot 'tests\KSword.Sandbox.SmokeTests\Scenarios\LiveTelemetryContractScenario.cs'
    Add-CheckResult -Name 'Live telemetry smoke scenario exists' -Passed (Test-Path -LiteralPath $scenarioPath) -Detail $scenarioPath

    $runtimeScenarioPath = Join-Path $RepositoryRoot 'tests\KSword.Sandbox.SmokeTests\Scenarios\WebUiRuntimeSmokeContractScenario.cs'
    Add-CheckResult -Name 'WebUI runtime smoke scenario exists' -Passed (Test-Path -LiteralPath $runtimeScenarioPath) -Detail $runtimeScenarioPath
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
Inputs: base URL and job ID.
Processing: requests the server-owned report.html endpoint and validates that
the safe dashboard report link can return an HTML response.
Return: no return value; failures are accumulated in script state.
#>
function Test-ReportHtmlEndpoint {
    param(
        [Parameter(Mandatory = $true)]
        [string]$NormalizedBaseUrl,

        [Parameter(Mandatory = $true)]
        [Guid]$RuntimeJobId
    )

    Add-Type -AssemblyName System.Net.Http

    $uri = '{0}/api/jobs/{1}/report/html' -f $NormalizedBaseUrl, $RuntimeJobId
    $client = [System.Net.Http.HttpClient]::new()
    $request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get, $uri)
    $request.Headers.Accept.ParseAdd('text/html')

    try {
        $response = $client.SendAsync($request).GetAwaiter().GetResult()
        try {
            $statusCode = [int]$response.StatusCode
            $mediaType = ''
            if ($null -ne $response.Content.Headers.ContentType) {
                $mediaType = $response.Content.Headers.ContentType.MediaType
            }

            $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            Add-CheckResult -Name 'Runtime served report link returns success' -Passed ($statusCode -ge 200 -and $statusCode -lt 300) -Detail "status=$statusCode uri=$uri"
            Add-CheckResult -Name 'Runtime served report link returns text/html' -Passed ($mediaType -like 'text/html*') -Detail "contentType=$mediaType"
            Add-CheckResult -Name 'Runtime served report link returns HTML body' -Passed ($body -match '<html') -Detail $uri
        }
        finally {
            $response.Dispose()
        }
    }
    catch {
        Add-CheckResult -Name 'Runtime served report link request succeeds' -Passed $false -Detail $_.Exception.Message
    }
    finally {
        $request.Dispose()
        $client.Dispose()
    }
}

<#
Inputs: base URL and job ID.
Processing: posts a deliberately missing explicit events path to the manual
guest import endpoint and expects a controlled validation failure. This proves
the endpoint exists and accepts the manual payload without importing artifacts.
Return: no return value; failures are accumulated in script state.
#>
function Test-ManualGuestImportEndpoint {
    param(
        [Parameter(Mandatory = $true)]
        [string]$NormalizedBaseUrl,

        [Parameter(Mandatory = $true)]
        [Guid]$RuntimeJobId
    )

    Add-Type -AssemblyName System.Net.Http

    $uri = '{0}/api/jobs/{1}/guest-events/import' -f $NormalizedBaseUrl, $RuntimeJobId
    $missingEventsPath = Join-Path ([System.IO.Path]::GetTempPath()) ('ksword-smoke-missing-{0}.events.json' -f [Guid]::NewGuid().ToString('N'))
    $body = @{ eventsPath = $missingEventsPath } | ConvertTo-Json -Compress
    $client = [System.Net.Http.HttpClient]::new()
    $content = [System.Net.Http.StringContent]::new($body, [System.Text.Encoding]::UTF8, 'application/json')

    try {
        $response = $client.PostAsync($uri, $content).GetAwaiter().GetResult()
        try {
            $statusCode = [int]$response.StatusCode
            $responseBody = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            Add-CheckResult -Name 'Runtime manual guest import endpoint rejects missing explicit path with HTTP 400' -Passed ($statusCode -eq 400) -Detail "status=$statusCode uri=$uri"
            Add-CheckResult -Name 'Runtime manual guest import endpoint returns validation message' -Passed (($responseBody -match 'Guest event import failed') -or ($responseBody -match 'Guest events file was not found')) -Detail $responseBody
        }
        finally {
            $response.Dispose()
        }
    }
    catch {
        Add-CheckResult -Name 'Runtime manual guest import endpoint request succeeds' -Passed $false -Detail $_.Exception.Message
    }
    finally {
        $content.Dispose()
        $client.Dispose()
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

    $runtimeBaseUrl = $BaseUrl
    if ([string]::IsNullOrWhiteSpace($runtimeBaseUrl)) {
        $runtimeBaseUrl = $env:KSWORD_SMOKE_BASE_URL
    }

    [Guid]$runtimeJobId = $JobId
    $invalidEnvironmentJobId = $false
    if ($runtimeJobId -eq [Guid]::Empty -and -not [string]::IsNullOrWhiteSpace($env:KSWORD_SMOKE_JOB_ID)) {
        [Guid]$parsedJobId = [Guid]::Empty
        if ([Guid]::TryParse($env:KSWORD_SMOKE_JOB_ID, [ref]$parsedJobId)) {
            $runtimeJobId = $parsedJobId
        }
        else {
            $invalidEnvironmentJobId = $true
            Add-CheckResult -Name 'Runtime environment job id is valid GUID' -Passed $false -Detail 'KSWORD_SMOKE_JOB_ID'
        }
    }

    $hasRuntimeTarget = -not [string]::IsNullOrWhiteSpace($runtimeBaseUrl) -and $runtimeJobId -ne [Guid]::Empty
    $hasPartialRuntimeTarget = -not [string]::IsNullOrWhiteSpace($runtimeBaseUrl) -or $runtimeJobId -ne [Guid]::Empty -or $invalidEnvironmentJobId
    if (-not $ContractOnly -and $hasRuntimeTarget) {
        $normalizedBaseUrl = $runtimeBaseUrl.TrimEnd('/')
        $sseUsable = Test-SseEndpoint `
            -NormalizedBaseUrl $normalizedBaseUrl `
            -RuntimeJobId $runtimeJobId `
            -RuntimeOffset $Offset `
            -RuntimeTake $Take `
            -RuntimeIntervalMs $IntervalMs `
            -AllowFallback:$UsePollingFallback

        if ($UsePollingFallback -or -not $sseUsable) {
            Test-PollingEndpoint `
                -NormalizedBaseUrl $normalizedBaseUrl `
                -RuntimeJobId $runtimeJobId `
                -RuntimeOffset $Offset `
                -RuntimeTake $Take
        }

        Test-ReportHtmlEndpoint `
            -NormalizedBaseUrl $normalizedBaseUrl `
            -RuntimeJobId $runtimeJobId

        Test-ManualGuestImportEndpoint `
            -NormalizedBaseUrl $normalizedBaseUrl `
            -RuntimeJobId $runtimeJobId
    }
    elseif (-not $ContractOnly -and $hasPartialRuntimeTarget) {
        if (-not $invalidEnvironmentJobId) {
            Add-CheckResult -Name 'Runtime probe target is complete' -Passed $false -Detail 'Provide both BaseUrl/KSWORD_SMOKE_BASE_URL and JobId/KSWORD_SMOKE_JOB_ID.'
        }
    }
    else {
        Add-CheckResult -Name 'Runtime probe skipped' -Passed $true -Detail 'Provide -BaseUrl/-JobId or KSWORD_SMOKE_BASE_URL/KSWORD_SMOKE_JOB_ID without -ContractOnly to probe a running Web API.'
    }

    $script:Results | Format-Table -AutoSize

    if ($script:FailureCount -gt 0) {
        Write-Host "$($script:FailureCount) live telemetry framework check(s) failed." -ForegroundColor Red
        $script:Results | Where-Object { -not $_.Passed } | Format-List
        return 1
    }

    Write-Host 'Live telemetry framework checks passed.'
    return 0
}

exit (Invoke-Main)
