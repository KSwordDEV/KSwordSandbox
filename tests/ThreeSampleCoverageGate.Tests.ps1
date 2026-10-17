[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptPath = Join-Path $PSScriptRoot '..\scripts\Test-ThreeSampleCoverage.ps1'
$root = Join-Path ([IO.Path]::GetTempPath()) "ksword-three-sample-coverage-$PID"
New-Item -ItemType Directory -Path $root -Force | Out-Null

function New-Fixture {
    param(
        [string]$Name,
        [switch]$MissingHealth,
        [switch]$MissingDriverPath,
        [switch]$ZeroEtwParsed,
        [switch]$ParserNotImplemented,
        [switch]$SampleExitFailure,
        [switch]$BrokenDynamicDecomposition,
        [switch]$ProcessTreeUnavailable
    )

    $job = Join-Path $root $Name
    $guest = Join-Path $job 'guest'
    New-Item -ItemType Directory -Path $guest -Force | Out-Null
    $rawPath = Join-Path $guest 'events.jsonl'
    $driverPath = Join-Path $guest 'driver-events.jsonl'
    Set-Content -LiteralPath $rawPath -Value '{"event":"raw"}' -Encoding UTF8
    if (-not $MissingDriverPath) { Set-Content -LiteralPath $driverPath -Value '{"event":"driver"}' -Encoding UTF8 }

    $dynamicRaw = 4
    $dynamicAttributed = if ($BrokenDynamicDecomposition) { 2 } else { 3 }
    $dynamicUnknown = 1
    $dynamicReport = 4
    $dynamicAttributedReport = 3
    $dynamicUnknownReport = 1
    $events = @(
        [pscustomobject]@{ EventType = 'driver.file'; Source = 'driver'; ProcessName = 'sample.exe'; ProcessId = 100; Data = [pscustomobject]@{ behaviorCounted = 'true'; sampleCorrelation = 'confirmed'; rawEventsPath = $rawPath; driverEventsPath = $(if ($MissingDriverPath) { Join-Path $guest 'missing-driver.jsonl' } else { $driverPath }) } },
        [pscustomobject]@{ EventType = 'etw_live.captured'; Source = 'etwLive'; ProcessName = 'EtwLiveTraceProbe'; Data = [pscustomobject]@{ parsedEventCount = $(if ($ZeroEtwParsed) { '0' } else { '2' }); etlDecodeRequired = 'false' } },
        [pscustomobject]@{ EventType = 'process.exit'; Source = 'guest'; ProcessName = 'sample'; Data = [pscustomobject]@{ behaviorCounted = 'true'; sampleCorrelation = 'confirmed'; status = $(if ($SampleExitFailure) { '0x80131700' } else { '0' }) } },
        [pscustomobject]@{ EventType = 'packet_capture.protocol_summary'; Source = 'guest'; Data = [pscustomobject]@{ protocolSummaryReason = $(if ($ParserNotImplemented) { 'protocolParserNotImplemented' } else { 'parsed' }) } }
    )
    if ($ProcessTreeUnavailable) {
        # Health and metric values intentionally remain zero so this fixture
        # proves event rows cannot be masked by a stale summary.
        $events += [pscustomobject]@{ EventType = 'process.tree_unavailable'; Source = 'guest'; ProcessName = 'sample'; ProcessId = 100; Data = [pscustomobject]@{} }
    }
    $metrics = [ordered]@{
        'events.total' = 4; 'events.raw' = 4; 'events.report' = 4
        'events.r0.driver.raw' = 1; 'events.r0.driver.lostCount' = 0
        'events.sources.driver' = 1
        'events.dynamicAction.raw' = $dynamicRaw; 'events.dynamicAction.attributedRaw' = $dynamicAttributed; 'events.dynamicAction.rawUnknown' = $dynamicUnknown
        'events.dynamicAction.report' = $dynamicReport; 'events.dynamicAction.attributedReport' = $dynamicAttributedReport; 'events.dynamicAction.unattributedReport' = $dynamicUnknownReport; 'events.dynamicAction.attributedOmitted' = 0
        'events.etw.parsedEventCount' = $(if ($ZeroEtwParsed) { 0 } else { 2 }); 'events.etw.etlDecodeRequired' = $false
        'collectionHealth.driver.lossRows' = 0; 'collectionHealth.driver.lostCount' = 0
        'collectionHealth.etw.eventsLost' = 0; 'collectionHealth.etw.eventsLostRows' = 0; 'collectionHealth.etw.decodeFailed' = 0
        'collectionHealth.losses' = 0; 'collectionHealth.failures' = 0
        'collectionHealth.process.treeUnavailable' = 0; 'collectionHealth.scheduledTask.captureFailed' = 0; 'collectionHealth.pktmon.stopFailed' = 0
        'events.r0.driver.backpressureObserved' = 0
        'events.persistence.raw' = 1; 'events.file.raw' = 1; 'events.networkTcp.raw' = 1
    }
    $report = [ordered]@{
        Status = 4
        Sample = [pscustomobject]@{ FileName = 'sample.exe' }
        Metrics = [pscustomobject]$metrics
        Events = $events
    }
    if (-not $MissingHealth) {
        $report.CollectionHealth = [pscustomobject]@{
            FailureRows = 0; LossRows = 0; EtwEventsLost = 0; EtwEventsLostRows = 0; DriverLossRows = 0; DriverLostCount = 0
            ProcessTreeUnavailable = 0; ScheduledTaskCaptureFailed = 0; PktmonStopFailed = 0; EtwDecodeFailed = 0; StateReasons = @()
        }
    }
    $report | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $job 'report.json') -Encoding UTF8
    return $job
}

function Invoke-Gate {
    param([string]$Job)
    $output = (& pwsh -NoLogo -NoProfile -File $scriptPath -JobRoot $Job -MinimumSamples 1 2>&1 | Out-String)
    return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $output }
}

try {
    $valid = New-Fixture 'valid'
    $result = Invoke-Gate $valid
    if ($result.ExitCode -ne 0) { throw "valid fixture unexpectedly failed: $($result.Output)" }

    $treeUnavailable = New-Fixture 'tree-unavailable' -ProcessTreeUnavailable
    $result = Invoke-Gate $treeUnavailable
    if ($result.ExitCode -ne 2 -or $result.Output -notmatch 'process.tree_unavailable.*1') { throw "process.tree_unavailable event was masked by zero health: $($result.Output)" }

    $missingHealth = New-Fixture 'missing-health' -MissingHealth
    $result = Invoke-Gate $missingHealth
    if ($result.ExitCode -ne 2 -or $result.Output -notmatch '缺少 CollectionHealth') { throw "missing CollectionHealth was not a FAIL: $($result.Output)" }

    $missingDriver = New-Fixture 'missing-driver' -MissingDriverPath
    $result = Invoke-Gate $missingDriver
    if ($result.ExitCode -ne 2 -or $result.Output -notmatch 'driverEventsPath') { throw "missing driver path was not independently rejected: $($result.Output)" }

    $zeroEtw = New-Fixture 'zero-etw' -ZeroEtwParsed
    $result = Invoke-Gate $zeroEtw
    if ($result.ExitCode -ne 2 -or $result.Output -notmatch 'parsedEventCount') { throw "zero ETW parsed count was not rejected: $($result.Output)" }

    $parser = New-Fixture 'parser-gap' -ParserNotImplemented
    $result = Invoke-Gate $parser
    if ($result.ExitCode -ne 2 -or $result.Output -notmatch 'protocolParserNotImplemented') { throw "protocol parser gap was not rejected: $($result.Output)" }

    $exitFailure = New-Fixture 'sample-exit-failure' -SampleExitFailure
    $result = Invoke-Gate $exitFailure
    if ($result.ExitCode -ne 2 -or $result.Output -notmatch 'process.exit') { throw "sample process exit failure was not rejected: $($result.Output)" }

    $decomposition = New-Fixture 'dynamic-decomposition' -BrokenDynamicDecomposition
    $result = Invoke-Gate $decomposition
    if ($result.ExitCode -ne 2 -or $result.Output -notmatch '动态动作分解') { throw "dynamic decomposition gap was not rejected: $($result.Output)" }

    Write-Host 'ThreeSampleCoverageGate.Tests: PASS'
    exit 0
}
finally {
    if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
}
