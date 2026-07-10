<#
.SYNOPSIS
Runs a local API-level pipeline smoke without requiring Hyper-V or a VM.

.DESCRIPTION
Inputs are optional local paths, build settings, and startup timing values.
Processing creates a benign .exe-named sample under the pipeline smoke temp
root, starts the Web API on a random localhost port, plans a dry-run job,
executes the runbook in dry-run mode, writes synthetic guest events into the job
guest folder, verifies the live raw-event endpoint, imports those events through
the Web API, and validates that report.html contains the expected sections.
The script returns process exit code 0 on pass and 1 on failure.

.PARAMETER RuntimeRoot
Base directory for all runtime smoke artifacts. The default intentionally lives
outside the repository so generated samples, configs, jobs, and logs are not
committed.

.PARAMETER Configuration
.NET build configuration used by dotnet run for the Web project.

.PARAMETER NoBuild
Passes --no-build to dotnet run. Use this after a successful local build when a
faster API smoke is desired.

.PARAMETER StartupTimeoutSeconds
Maximum time to wait for the local Web API /health endpoint before failing.

.PARAMETER DotNetPath
Path or command name for the dotnet host.
#>
[CmdletBinding()]
param(
    [string]$RuntimeRoot = 'D:\Temp\KSwordSandbox\pipeline-smoke',

    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',

    [switch]$NoBuild,

    [ValidateRange(5, 300)]
    [int]$StartupTimeoutSeconds = 60,

    [string]$DotNetPath = 'dotnet'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Resolve the repository once so every generated path is explicit and all
# runtime output can be printed at the end of the smoke.
$repoRoot = Split-Path -Parent $PSScriptRoot
$webProject = Join-Path $repoRoot 'src\KSword.Sandbox.Web\KSword.Sandbox.Web.csproj'
$script:WebProcess = $null
$script:WebLogs = $null
$script:SmokeContext = $null

function Write-SmokeStep {
    <#
    .SYNOPSIS
    Prints one progress line for the smoke runner.

    .DESCRIPTION
    The input is a short human-readable message. Processing prefixes it with a
    stable tag so logs are easy to scan. The function returns no value.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )

    Write-Host "[local-pipeline-smoke] $Message"
}

function Assert-SmokeCondition {
    <#
    .SYNOPSIS
    Fails the smoke when a required condition is false.

    .DESCRIPTION
    Inputs are a Boolean condition and a failure message. Processing throws an
    InvalidOperationException when the condition is false. The function returns
    no value when the condition is true.
    #>
    param(
        [Parameter(Mandatory)]
        [bool]$Condition,

        [Parameter(Mandatory)]
        [string]$Message
    )

    if (-not $Condition) {
        throw [InvalidOperationException]::new($Message)
    }
}

function ConvertTo-SmokeProcessArgument {
    <#
    .SYNOPSIS
    Quotes a process argument for Start-Process.

    .DESCRIPTION
    The input is one command-line argument. Processing preserves simple tokens
    and quotes tokens containing whitespace or quotes. The function returns the
    escaped argument string used in the dotnet command line.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Argument
    )

    if ($Argument -notmatch '[\s"]') {
        return $Argument
    }

    return '"' + ($Argument -replace '\\(?=")', '\' -replace '"', '\"') + '"'
}

function New-SmokeRunContext {
    <#
    .SYNOPSIS
    Creates the isolated runtime folder set for one smoke run.

    .DESCRIPTION
    Inputs are the base runtime root and repository root. Processing creates a
    unique run directory with samples and logs subfolders. The function returns
    a PSCustomObject containing all paths needed by later smoke steps.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$BaseRuntimeRoot,

        [Parameter(Mandatory)]
        [string]$RepositoryRoot
    )

    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $runName = "run-$timestamp-$([Guid]::NewGuid().ToString('N').Substring(0, 8))"
    $resolvedBase = [System.IO.Path]::GetFullPath($BaseRuntimeRoot)
    $runRoot = Join-Path $resolvedBase $runName
    $sampleRoot = Join-Path $runRoot 'samples'
    $logRoot = Join-Path $runRoot 'logs'

    New-Item -ItemType Directory -Path $sampleRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $logRoot -Force | Out-Null

    return [pscustomobject]@{
        RepositoryRoot = $RepositoryRoot
        RuntimeRoot    = $resolvedBase
        RunRoot        = $runRoot
        SampleRoot     = $sampleRoot
        LogRoot        = $logRoot
        ConfigPath     = Join-Path $runRoot 'sandbox.local-pipeline-smoke.json'
        SamplePath     = Join-Path $sampleRoot 'local-pipeline-smoke.exe'
        StdoutLog      = Join-Path $logRoot 'web.stdout.log'
        StderrLog      = Join-Path $logRoot 'web.stderr.log'
    }
}

function New-BenignExeNamedFile {
    <#
    .SYNOPSIS
    Writes the harmless .exe-named file used by API planning.

    .DESCRIPTION
    The input is the target sample path. Processing writes plain text with an
    .exe extension so the file scanner and planner exercise executable-path
    plumbing without producing a runnable program. The function returns the
    sample path.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$SamplePath
    )

    $content = @(
        'KSword local pipeline smoke sample.'
        'This file is intentionally harmless plain text with an .exe suffix.'
        "GeneratedAtUtc=$([DateTimeOffset]::UtcNow.ToString('O'))"
    )
    Set-Content -LiteralPath $SamplePath -Value $content -Encoding UTF8
    return $SamplePath
}

function New-SmokeConfigFile {
    <#
    .SYNOPSIS
    Writes a temporary sandbox config for the local smoke.

    .DESCRIPTION
    Inputs are the run context, repository root, and requested duration.
    Processing writes JSON that redirects runtime output into the smoke run
    folder while keeping the repository rules directory. The function returns
    the config file path.
    #>
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context,

        [Parameter(Mandatory)]
        [string]$RepositoryRoot
    )

    $config = [ordered]@{
        analysis = [ordered]@{
            defaultDurationSeconds = 5
            maxDurationSeconds     = 900
            maxSampleBytes         = 209715200
        }
        paths = [ordered]@{
            runtimeRoot    = $Context.RunRoot
            rulesDirectory = Join-Path $RepositoryRoot 'rules'
        }
    }

    $json = $config | ConvertTo-Json -Depth 8
    Set-Content -LiteralPath $Context.ConfigPath -Value $json -Encoding UTF8
    return $Context.ConfigPath
}

function Get-SmokeRandomLocalUrl {
    <#
    .SYNOPSIS
    Allocates a random localhost HTTP URL for Kestrel.

    .DESCRIPTION
    There are no inputs. Processing binds a loopback TcpListener to port 0,
    reads the selected port, and releases it before Web startup. The function
    returns an http://127.0.0.1:<port> URL.
    #>
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    try {
        $listener.Start()
        $port = $listener.LocalEndpoint.Port
    }
    finally {
        $listener.Stop()
    }

    return "http://127.0.0.1:$port"
}

function Start-SmokeWebApi {
    <#
    .SYNOPSIS
    Starts the KSword Web API for the smoke run.

    .DESCRIPTION
    Inputs are the dotnet path, Web project, repository root, config path, URL,
    build configuration, no-build flag, and log paths. Processing starts
    dotnet run with environment variables that isolate runtime output and bind
    Kestrel to the random localhost URL. The function returns the started
    Process object.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$DotNet,

        [Parameter(Mandatory)]
        [string]$ProjectPath,

        [Parameter(Mandatory)]
        [string]$RepositoryRoot,

        [Parameter(Mandatory)]
        [string]$ConfigPath,

        [Parameter(Mandatory)]
        [string]$Url,

        [Parameter(Mandatory)]
        [string]$BuildConfiguration,

        [Parameter(Mandatory)]
        [bool]$UseNoBuild,

        [Parameter(Mandatory)]
        [string]$StdoutLog,

        [Parameter(Mandatory)]
        [string]$StderrLog
    )

    $arguments = @('run', '--project', $ProjectPath, '--configuration', $BuildConfiguration, '--no-launch-profile')
    if ($UseNoBuild) {
        $arguments += '--no-build'
    }

    $argumentLine = ($arguments | ForEach-Object { ConvertTo-SmokeProcessArgument $_ }) -join ' '
    $savedAspNetCoreUrls = $env:ASPNETCORE_URLS
    $savedSandboxConfig = $env:Sandbox__ConfigPath
    $savedDotNetEnvironment = $env:DOTNET_ENVIRONMENT

    try {
        $env:ASPNETCORE_URLS = $Url
        $env:Sandbox__ConfigPath = $ConfigPath
        $env:DOTNET_ENVIRONMENT = 'Development'

        $process = Start-Process `
            -FilePath $DotNet `
            -ArgumentList $argumentLine `
            -WorkingDirectory $RepositoryRoot `
            -RedirectStandardOutput $StdoutLog `
            -RedirectStandardError $StderrLog `
            -WindowStyle Hidden `
            -PassThru

        return $process
    }
    finally {
        $env:ASPNETCORE_URLS = $savedAspNetCoreUrls
        $env:Sandbox__ConfigPath = $savedSandboxConfig
        $env:DOTNET_ENVIRONMENT = $savedDotNetEnvironment
    }
}

function Wait-SmokeWebApi {
    <#
    .SYNOPSIS
    Waits until the smoke Web API is healthy.

    .DESCRIPTION
    Inputs are the started process, base URL, timeout, and stderr log path.
    Processing polls /health until it returns status=ok, the process exits, or
    the timeout elapses. The function returns the health payload on success.
    #>
    param(
        [Parameter(Mandatory)]
        [System.Diagnostics.Process]$Process,

        [Parameter(Mandatory)]
        [string]$Url,

        [Parameter(Mandatory)]
        [int]$TimeoutSeconds,

        [Parameter(Mandatory)]
        [string]$StderrLog
    )

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    $healthUri = "$Url/health"

    while ([DateTimeOffset]::UtcNow -lt $deadline) {
        if ($Process.HasExited) {
            $tail = Get-SmokeFileTail -Path $StderrLog -LineCount 40
            throw "Web API exited before health check succeeded. ExitCode=$($Process.ExitCode). Stderr tail:`n$tail"
        }

        try {
            $health = Invoke-RestMethod -Method Get -Uri $healthUri -TimeoutSec 2
            if ($health.status -eq 'ok') {
                return $health
            }
        }
        catch {
            Start-Sleep -Milliseconds 500
        }
    }

    throw "Timed out waiting $TimeoutSeconds second(s) for $healthUri."
}

function Invoke-SmokeJsonPost {
    <#
    .SYNOPSIS
    Sends one JSON POST request to the local smoke API.

    .DESCRIPTION
    Inputs are a URI and serializable body. Processing converts the body to
    JSON, sends application/json to the API, and returns the deserialized JSON
    response from Invoke-RestMethod.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter(Mandatory)]
        [object]$Body
    )

    $json = $Body | ConvertTo-Json -Depth 12
    return Invoke-RestMethod -Method Post -Uri $Uri -ContentType 'application/json' -Body $json -TimeoutSec 30
}

function Invoke-SmokeDryRunRunbook {
    <#
    .SYNOPSIS
    Executes the planned runbook through the Web API in dry-run mode.

    .DESCRIPTION
    Inputs are the API base URL and planned job. Processing calls
    /api/jobs/{jobId}/runbook/execute with live=false, validates that the
    execution result was persisted, and returns the updated job object from the
    API response.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$BaseUrl,

        [Parameter(Mandatory)]
        [pscustomobject]$Job
    )

    $jobId = [string]$Job.jobId
    $payload = Invoke-SmokeJsonPost -Uri "$BaseUrl/api/jobs/$jobId/runbook/execute" -Body @{
        live              = $false
        stepTimeoutSeconds = 60
        importGuestEvents = $false
    }

    Assert-SmokeCondition -Condition ($null -ne $payload.execution) -Message 'Dry-run runbook response is missing execution.'
    Assert-SmokeCondition -Condition ($null -ne $payload.job) -Message 'Dry-run runbook response is missing updated job.'

    $execution = $payload.execution
    Assert-SmokeCondition -Condition ([bool]$execution.success) -Message 'Dry-run runbook execution should succeed.'
    Assert-SmokeCondition -Condition (@('0', 'DryRun') -contains [string]$execution.mode) -Message "Dry-run runbook mode was unexpected: $($execution.mode)"
    Assert-SmokeCondition -Condition ([int]$execution.totalSteps -gt 0) -Message 'Dry-run runbook did not contain any steps.'
    Assert-SmokeCondition -Condition (@($execution.stepResults).Count -eq [int]$execution.totalSteps) -Message 'Dry-run runbook did not return one result per step.'
    Assert-SmokeCondition -Condition ([int]$execution.executedSteps -eq 0) -Message 'Dry-run runbook should not execute live steps.'

    $updatedJob = $payload.job
    Assert-SmokeCondition -Condition (-not [string]::IsNullOrWhiteSpace([string]$updatedJob.runbookExecutionResultPath)) -Message 'Updated job is missing runbookExecutionResultPath.'
    Assert-SmokeCondition -Condition (Test-Path -LiteralPath ([string]$updatedJob.runbookExecutionResultPath) -PathType Leaf) -Message "runbook-execution.json was not written: $($updatedJob.runbookExecutionResultPath)"

    $resultText = Get-Content -LiteralPath ([string]$updatedJob.runbookExecutionResultPath) -Raw
    $resultJson = $resultText | ConvertFrom-Json
    Assert-SmokeCondition -Condition (@('0', 'DryRun') -contains [string]$resultJson.Mode) -Message "runbook-execution.json does not record DryRun mode. Actual: $($resultJson.Mode)"
    Assert-SmokeCondition -Condition ($resultText.Contains('Dry-run mode recorded the command without launching PowerShell.')) -Message 'runbook-execution.json does not record dry-run step messages.'
    Assert-SmokeCondition -Condition ($resultText.Contains('sync-live-output')) -Message 'runbook-execution.json does not include the live sync step.'

    return $updatedJob
}

function Write-SmokeGuestEvents {
    <#
    .SYNOPSIS
    Writes synthetic guest output into the planned job folder.

    .DESCRIPTION
    Inputs are the planned job object. Processing derives the job guest output
    directory from report.json, writes events.json plus driver-events.jsonl,
    and returns a PSCustomObject with the generated event paths.
    #>
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Job
    )

    $jobGuid = [Guid]::Parse([string]$Job.jobId)
    $jobRoot = Split-Path -Parent ([string]$Job.jsonReportPath)
    $guestRoot = Join-Path (Join-Path $jobRoot 'guest') $jobGuid.ToString('N')
    New-Item -ItemType Directory -Path $guestRoot -Force | Out-Null

    $eventsPath = Join-Path $guestRoot 'events.json'
    $driverEventsPath = Join-Path $guestRoot 'driver-events.jsonl'
    $guestSamplePath = 'C:\KSwordSandbox\incoming\local-pipeline-smoke.exe'

    $events = @(
        [ordered]@{
            eventType   = 'process.start'
            source      = 'guest'
            processName = 'powershell'
            processId   = 4242
            path        = $guestSamplePath
            commandLine = 'powershell -NoProfile -ExecutionPolicy Bypass -File C:\KSwordSandbox\probe.ps1'
            data        = [ordered]@{}
        },
        [ordered]@{
            eventType = 'file.created'
            source    = 'guest'
            processId = 4242
            path      = 'C:\KSwordSandbox\out\drop.bin'
            data      = [ordered]@{}
        },
        [ordered]@{
            eventType = 'network.tcp'
            source    = 'guest'
            processId = 4242
            data      = [ordered]@{
                remoteAddress = '203.0.113.10'
                remotePort    = '443'
                state         = 'Established'
            }
        }
    )

    $events | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $eventsPath -Encoding UTF8

    $driverEvent = [ordered]@{
        eventType = 'registry.set'
        source    = 'driver'
        processId = 4242
        path      = 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run\PipelineSmoke'
        data      = [ordered]@{
            value = $guestSamplePath
        }
    }
    $r0CollectorEvent = [ordered]@{
        eventType = 'r0collector.mockDriverEvent'
        source    = 'r0collector'
        processId = 4242
        path      = '\\.\KSwordSandboxDriver'
        data      = [ordered]@{
            mock            = 'true'
            driverEventPath = 'driver-events.jsonl'
        }
    }
    $driverLines = @(
        ($driverEvent | ConvertTo-Json -Depth 12 -Compress)
        ($r0CollectorEvent | ConvertTo-Json -Depth 12 -Compress)
    )
    Set-Content -LiteralPath $driverEventsPath -Value $driverLines -Encoding UTF8

    return [pscustomobject]@{
        GuestRoot        = $guestRoot
        EventsPath       = $eventsPath
        DriverEventsPath = $driverEventsPath
    }
}

function Test-SmokeLiveEventsEndpoint {
    <#
    .SYNOPSIS
    Validates the live event polling endpoint shape.

    .DESCRIPTION
    Inputs are the API base URL, planned job, and synthetic guest artifact
    paths. Processing calls /api/jobs/{jobId}/events/live with a small page and
    a full page, validates camelCase metadata fields, source paths, event rows,
    and synthetic JSONL merge behavior. The function returns no value on
    success.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$BaseUrl,

        [Parameter(Mandatory)]
        [pscustomobject]$Job,

        [Parameter(Mandatory)]
        [pscustomobject]$GuestArtifacts
    )

    $jobId = [string]$Job.jobId
    $page = Invoke-RestMethod -Method Get -Uri "$BaseUrl/api/jobs/$jobId/events/live?offset=0&take=2" -TimeoutSec 30
    Assert-SmokeCondition -Condition ([string]$page.jobId -eq $jobId) -Message "Live events response jobId mismatch."
    Assert-SmokeCondition -Condition ([int]$page.totalEvents -ge 5) -Message "Live events response should include events.json plus two JSONL rows."
    Assert-SmokeCondition -Condition (@($page.events).Count -eq 2) -Message "Live events endpoint did not honor take=2."
    Assert-SmokeCondition -Condition ([int]$page.nextOffset -eq 2) -Message "Live events endpoint returned unexpected nextOffset."
    Assert-SmokeCondition -Condition ([bool]$page.hasMore) -Message "Live events endpoint should report hasMore for a truncated page."
    Assert-SmokeCondition -Condition (-not [string]::IsNullOrWhiteSpace([string]$page.retrievedAt)) -Message "Live events endpoint did not return retrievedAt."

    $full = Invoke-RestMethod -Method Get -Uri "$BaseUrl/api/jobs/$jobId/events/live?offset=0&take=100" -TimeoutSec 30
    $sources = @($full.sources | ForEach-Object { [string]$_ })
    Assert-SmokeCondition -Condition (@($sources | Where-Object { [StringComparer]::OrdinalIgnoreCase.Equals($_, [string]$GuestArtifacts.EventsPath) }).Count -gt 0) -Message "Live events sources missing events.json."
    Assert-SmokeCondition -Condition (@($sources | Where-Object { [StringComparer]::OrdinalIgnoreCase.Equals($_, [string]$GuestArtifacts.DriverEventsPath) }).Count -gt 0) -Message "Live events sources missing driver-events.jsonl."

    $events = @($full.events)
    $eventTypes = @($events | ForEach-Object { [string]$_.eventType })
    foreach ($expectedType in @('process.start', 'file.created', 'network.tcp', 'registry.set', 'r0collector.mockDriverEvent')) {
        Assert-SmokeCondition -Condition ($eventTypes -contains $expectedType) -Message "Live events endpoint missing event type: $expectedType"
    }

    $firstEvent = $events | Select-Object -First 1
    Assert-SmokeCondition -Condition (-not [string]::IsNullOrWhiteSpace([string]$firstEvent.eventType)) -Message "Live event row missing eventType."
    Assert-SmokeCondition -Condition (-not [string]::IsNullOrWhiteSpace([string]$firstEvent.timestamp)) -Message "Live event row missing timestamp."
    Assert-SmokeCondition -Condition (-not [string]::IsNullOrWhiteSpace([string]$firstEvent.source)) -Message "Live event row missing source."
    Assert-SmokeCondition -Condition ($null -ne $firstEvent.data) -Message "Live event row missing data object."
}

function Test-SmokeReportHtml {
    <#
    .SYNOPSIS
    Validates key report sections and findings in report.html.

    .DESCRIPTION
    The input is the generated HTML report path. Processing reads the file and
    checks for stable section headings plus rule titles produced by the
    synthetic guest events. The function returns no value on success.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$HtmlReportPath
    )

    Assert-SmokeCondition -Condition (Test-Path -LiteralPath $HtmlReportPath -PathType Leaf) -Message "HTML report was not found: $HtmlReportPath"
    $html = Get-Content -LiteralPath $HtmlReportPath -Raw
    $requiredSnippets = @(
        'Risk summary',
        'Static analysis',
        'CRC32',
        'PE sections',
        'Process details',
        'Dropped files',
        'Network behavior',
        'Command and scripting interpreter',
        'Dropped or modified file',
        'Outbound TCP activity observed',
        'Registry modification observed',
        'R0 collector mock driver event',
        'r0collector.mockDriverEvent',
        'Raw normalized events'
    )

    foreach ($snippet in $requiredSnippets) {
        Assert-SmokeCondition -Condition ($html.Contains($snippet)) -Message "HTML report is missing expected text: $snippet"
    }
}

function Get-SmokeFileTail {
    <#
    .SYNOPSIS
    Reads the final lines from a log file for diagnostics.

    .DESCRIPTION
    Inputs are a file path and line count. Processing tolerates missing files
    and returns the requested tail text when available. The function returns a
    string suitable for failure output.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [int]$LineCount = 30
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return "<missing log: $Path>"
    }

    return (Get-Content -LiteralPath $Path -Tail $LineCount) -join [Environment]::NewLine
}

function Stop-SmokeWebApi {
    <#
    .SYNOPSIS
    Stops the background Web API process.

    .DESCRIPTION
    The input is an optional Process object. Processing attempts a graceful
    close and then force-stops the process if it is still running. The function
    returns no value.
    #>
    param(
        [System.Diagnostics.Process]$Process
    )

    if ($null -eq $Process) {
        return
    }

    try {
        if (-not $Process.HasExited) {
            [void]$Process.CloseMainWindow()
            if (-not $Process.WaitForExit(3000)) {
                Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
                $Process.WaitForExit(3000) | Out-Null
            }
        }
    }
    catch {
        Write-Warning "Failed to stop Web API process $($Process.Id): $($_.Exception.Message)"
    }
}

try {
    Assert-SmokeCondition -Condition (Test-Path -LiteralPath $webProject -PathType Leaf) -Message "Web project was not found: $webProject"

    $script:SmokeContext = New-SmokeRunContext -BaseRuntimeRoot $RuntimeRoot -RepositoryRoot $repoRoot
    Write-SmokeStep "Runtime root: $($script:SmokeContext.RunRoot)"

    $samplePath = New-BenignExeNamedFile -SamplePath $script:SmokeContext.SamplePath
    Write-SmokeStep "Created benign .exe-named sample: $samplePath"

    $configPath = New-SmokeConfigFile -Context $script:SmokeContext -RepositoryRoot $repoRoot
    Write-SmokeStep "Wrote smoke config: $configPath"

    $url = Get-SmokeRandomLocalUrl
    Write-SmokeStep "Starting Web API at $url"
    $script:WebLogs = [pscustomobject]@{
        Stdout = $script:SmokeContext.StdoutLog
        Stderr = $script:SmokeContext.StderrLog
    }
    $script:WebProcess = Start-SmokeWebApi `
        -DotNet $DotNetPath `
        -ProjectPath $webProject `
        -RepositoryRoot $repoRoot `
        -ConfigPath $configPath `
        -Url $url `
        -BuildConfiguration $Configuration `
        -UseNoBuild ([bool]$NoBuild) `
        -StdoutLog $script:SmokeContext.StdoutLog `
        -StderrLog $script:SmokeContext.StderrLog

    [void](Wait-SmokeWebApi -Process $script:WebProcess -Url $url -TimeoutSeconds $StartupTimeoutSeconds -StderrLog $script:SmokeContext.StderrLog)
    Write-SmokeStep "Web API health check passed."

    $scan = Invoke-SmokeJsonPost -Uri "$url/api/files/scan" -Body @{
        path       = $script:SmokeContext.SampleRoot
        maxDepth   = 1
        maxResults = 20
    }
    $scannerFoundSample = $false
    foreach ($candidate in @($scan.candidates)) {
        if ([StringComparer]::OrdinalIgnoreCase.Equals([string]$candidate.fullPath, [string]$samplePath)) {
            $scannerFoundSample = $true
            break
        }
    }
    Assert-SmokeCondition -Condition $scannerFoundSample -Message "File scan did not return the smoke sample."
    Write-SmokeStep "File scan endpoint found the smoke sample."

    $job = Invoke-SmokeJsonPost -Uri "$url/api/jobs/plan" -Body @{
        samplePath       = $samplePath
        displayName      = 'local-pipeline-smoke.exe'
        durationSeconds  = 5
        dryRun           = $true
    }
    Assert-SmokeCondition -Condition (@('2', 'Planned') -contains [string]$job.status) -Message "Expected planned job status; actual status was $($job.status)."
    Assert-SmokeCondition -Condition (Test-Path -LiteralPath ([string]$job.jsonReportPath) -PathType Leaf) -Message "JSON report was not created."
    Assert-SmokeCondition -Condition (Test-Path -LiteralPath ([string]$job.htmlReportPath) -PathType Leaf) -Message "HTML report was not created."
    Write-SmokeStep "Planned job $($job.jobId)."

    $job = Invoke-SmokeDryRunRunbook -BaseUrl $url -Job $job
    Write-SmokeStep "Dry-run runbook execution persisted: $($job.runbookExecutionResultPath)"

    $guestArtifacts = Write-SmokeGuestEvents -Job $job
    Write-SmokeStep "Wrote synthetic guest events: $($guestArtifacts.EventsPath)"
    Write-SmokeStep "Wrote synthetic driver events: $($guestArtifacts.DriverEventsPath)"

    Test-SmokeLiveEventsEndpoint -BaseUrl $url -Job $job -GuestArtifacts $guestArtifacts
    Write-SmokeStep "Live events endpoint shape validation passed."

    $importedJob = Invoke-SmokeJsonPost -Uri "$url/api/jobs/$($job.jobId)/guest-events/import" -Body @{
        eventsPath = $guestArtifacts.EventsPath
    }
    Assert-SmokeCondition -Condition (@('4', 'Completed') -contains [string]$importedJob.status) -Message "Expected completed job status after import; actual status was $($importedJob.status)."

    Test-SmokeReportHtml -HtmlReportPath ([string]$importedJob.htmlReportPath)
    Write-SmokeStep "Report validation passed: $($importedJob.htmlReportPath)"

    Write-Host ''
    Write-Host 'PASS: local pipeline smoke completed.'
    Write-Host "  Run root:       $($script:SmokeContext.RunRoot)"
    Write-Host "  Sample:         $samplePath"
    Write-Host "  Web URL:        $url"
    Write-Host "  Job ID:         $($importedJob.jobId)"
    Write-Host "  Guest events:   $($guestArtifacts.EventsPath)"
    Write-Host "  JSON report:    $($importedJob.jsonReportPath)"
    Write-Host "  HTML report:    $($importedJob.htmlReportPath)"
    Write-Host "  Web stdout log: $($script:SmokeContext.StdoutLog)"
    Write-Host "  Web stderr log: $($script:SmokeContext.StderrLog)"
    exit 0
}
catch {
    Write-Host ''
    Write-Error "FAIL: local pipeline smoke failed. $($_.Exception.Message)"
    if ($null -ne $script:SmokeContext) {
        Write-Host "  Run root:       $($script:SmokeContext.RunRoot)"
        Write-Host "  Sample:         $($script:SmokeContext.SamplePath)"
        Write-Host "  Web stdout log: $($script:SmokeContext.StdoutLog)"
        Write-Host "  Web stderr log: $($script:SmokeContext.StderrLog)"
    }

    if ($null -ne $script:WebLogs) {
        Write-Host ''
        Write-Host 'Web stderr tail:'
        Write-Host (Get-SmokeFileTail -Path $script:WebLogs.Stderr -LineCount 40)
    }

    exit 1
}
finally {
    Stop-SmokeWebApi -Process $script:WebProcess
}
