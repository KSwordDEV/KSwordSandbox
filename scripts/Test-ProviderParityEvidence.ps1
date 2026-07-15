<#
.SYNOPSIS
Validates three independent Hyper-V, VMware, and QEMU Web API Live evidence summaries.

.DESCRIPTION
This command reads summary JSON and referenced evidence files, then writes one
aggregate validation JSON. It never starts, stops, restores, or otherwise mutates a
virtual machine. A successful result proves
that all three summaries were produced from the same clean source commit and sample,
used the background Web execution path, retained provider/resource identity, and
completed the same evidence contract.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$HyperVSummaryPath,
    [Parameter(Mandatory)][string]$VMwareSummaryPath,
    [Parameter(Mandatory)][string]$QemuSummaryPath,
    [string]$OutputPath = 'D:\Temp\KSwordSandbox\parity\provider-parity-validation.json'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-ParityEvidence {
    param(
        [Parameter(Mandatory)][bool]$Condition,
        [Parameter(Mandatory)][string]$Message
    )

    if (-not $Condition) {
        throw [System.IO.InvalidDataException]::new($Message)
    }
}

function Get-ParityProperty {
    param(
        [Parameter(Mandatory)][object]$Object,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Context
    )

    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        throw [System.IO.InvalidDataException]::new("$Context is missing required field '$Name'.")
    }
    return $property.Value
}

function Get-ParityOptionalProperty {
    param(
        [Parameter(Mandatory)][object]$Object,
        [Parameter(Mandatory)][string]$Name
    )

    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }
    return $property.Value
}

function Read-ParityJsonFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Context
    )

    $resolvedPath = [System.IO.Path]::GetFullPath($Path)
    Assert-ParityEvidence -Condition (Test-Path -LiteralPath $resolvedPath -PathType Leaf) -Message "$Context was not found: $resolvedPath"
    try {
        $value = Get-Content -LiteralPath $resolvedPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw [System.IO.InvalidDataException]::new("$Context is not valid JSON: $($_.Exception.Message)")
    }

    return [pscustomobject][ordered]@{
        Path = $resolvedPath
        Value = $value
    }
}

function Read-ParitySummary {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$ExpectedProvider
    )

    $document = Read-ParityJsonFile -Path $Path -Context "$ExpectedProvider summary"
    $summary = $document.Value

    $provider = [string](Get-ParityProperty -Object $summary -Name 'provider' -Context $ExpectedProvider)
    Assert-ParityEvidence -Condition ($provider -ceq $ExpectedProvider) -Message "Expected $ExpectedProvider summary but '$provider' was recorded: $($document.Path)"
    return [pscustomobject][ordered]@{
        Path = $document.Path
        Provider = $provider
        Summary = $summary
    }
}

function Get-ParityFileSha256 {
    param([Parameter(Mandatory)][string]$Path)

    $stream = [System.IO.File]::Open(
        $Path,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        return -join ($sha256.ComputeHash($stream) | ForEach-Object { $_.ToString('x2') })
    }
    finally {
        $sha256.Dispose()
        $stream.Dispose()
    }
}

function Get-ParityBoolean {
    param(
        [Parameter(Mandatory)][object]$Summary,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Provider
    )

    $value = Get-ParityProperty -Object $Summary -Name $Name -Context $Provider
    Assert-ParityEvidence -Condition ($value -is [bool]) -Message "$Provider field '$Name' must be a JSON boolean."
    return [bool]$value
}

function Assert-ParityBoolean {
    param(
        [Parameter(Mandatory)][object]$Summary,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][bool]$Expected,
        [Parameter(Mandatory)][string]$Provider
    )

    $value = Get-ParityBoolean -Summary $Summary -Name $Name -Provider $Provider
    Assert-ParityEvidence -Condition ([bool]$value -eq $Expected) -Message "$Provider field '$Name' must be $Expected but was $value."
}

function Get-ParityInt64 {
    param(
        [Parameter(Mandatory)][object]$Summary,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Provider,
        [long]$Minimum = [long]::MinValue,
        [long]$Maximum = [long]::MaxValue
    )

    $value = Get-ParityProperty -Object $Summary -Name $Name -Context $Provider
    $isInteger = (
        $value -is [byte] -or $value -is [sbyte] -or
        $value -is [int16] -or $value -is [uint16] -or
        $value -is [int32] -or $value -is [uint32] -or
        $value -is [int64]
    )
    Assert-ParityEvidence -Condition $isInteger -Message "$Provider field '$Name' must be a JSON integer."
    $parsed = [long]$value
    Assert-ParityEvidence -Condition ($parsed -ge $Minimum -and $parsed -le $Maximum) -Message "$Provider field '$Name' must be between $Minimum and $Maximum but was $parsed."
    return $parsed
}

function Assert-ParityTimestamp {
    param(
        [Parameter(Mandatory)][object]$Summary,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Provider
    )

    $text = [string](Get-ParityProperty -Object $Summary -Name $Name -Context $Provider)
    $parsed = [DateTimeOffset]::MinValue
    Assert-ParityEvidence -Condition ($text -match '(?:Z|[+-]\d{2}:\d{2})$') -Message "$Provider field '$Name' must include a UTC or numeric offset: '$text'."
    Assert-ParityEvidence -Condition ([DateTimeOffset]::TryParse($text, [ref]$parsed)) -Message "$Provider field '$Name' is not an offset-aware timestamp: '$text'."
}

function Resolve-ParityEvidenceFile {
    param(
        [Parameter(Mandatory)][object]$Summary,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Provider,
        [Parameter(Mandatory)][string]$RuntimeRoot
    )

    $path = [string](Get-ParityProperty -Object $Summary -Name $Name -Context $Provider)
    Assert-ParityEvidence -Condition (-not [string]::IsNullOrWhiteSpace($path)) -Message "$Provider field '$Name' is empty."
    $fullPath = [System.IO.Path]::GetFullPath($path)
    $trimCharacters = [char[]]@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    $fullRuntimeRoot = [System.IO.Path]::GetFullPath($RuntimeRoot).TrimEnd($trimCharacters)
    $runtimePrefix = $fullRuntimeRoot + [System.IO.Path]::DirectorySeparatorChar
    Assert-ParityEvidence -Condition ($fullPath.StartsWith($runtimePrefix, [System.StringComparison]::OrdinalIgnoreCase)) -Message "$Provider evidence '$Name' is outside runtimeRoot: $fullPath"
    Assert-ParityEvidence -Condition (Test-Path -LiteralPath $fullPath -PathType Leaf) -Message "$Provider evidence '$Name' was not found: $fullPath"
    return $fullPath
}

function Test-ParityProviderRecord {
    param([Parameter(Mandatory)][object]$Record)

    $provider = [string]$Record.Provider
    $summary = $Record.Summary
    $mode = [string](Get-ParityProperty -Object $summary -Name 'mode' -Context $provider)
    Assert-ParityEvidence -Condition ($mode -ceq 'Live') -Message "$provider evidence must use mode=Live."
    Assert-ParityBoolean -Summary $summary -Name 'success' -Expected $true -Provider $provider
    Assert-ParityBoolean -Summary $summary -Name 'readinessReadOnly' -Expected $true -Provider $provider
    Assert-ParityBoolean -Summary $summary -Name 'hostAccelerationReady' -Expected $true -Provider $provider
    Assert-ParityBoolean -Summary $summary -Name 'requiredWindowsFeatureReady' -Expected $true -Provider $provider
    Assert-ParityBoolean -Summary $summary -Name 'providerManagementAvailable' -Expected $true -Provider $provider
    Assert-ParityBoolean -Summary $summary -Name 'providerGuestTransportSecure' -Expected $true -Provider $provider
    Assert-ParityBoolean -Summary $summary -Name 'providerGuestEndpointReady' -Expected $true -Provider $provider
    Assert-ParityBoolean -Summary $summary -Name 'guestImportSucceeded' -Expected $true -Provider $provider
    Assert-ParityBoolean -Summary $summary -Name 'guestImportSkipped' -Expected $false -Provider $provider
    Assert-ParityBoolean -Summary $summary -Name 'guestImportFailed' -Expected $false -Provider $provider
    Assert-ParityBoolean -Summary $summary -Name 'cSignToolUsed' -Expected $false -Provider $provider
    Assert-ParityBoolean -Summary $summary -Name 'gitDirty' -Expected $false -Provider $provider

    $requiredWindowsFeature = [string](Get-ParityProperty -Object $summary -Name 'requiredWindowsFeature' -Context $provider)
    $expectedWindowsFeature = switch ($provider) {
        'HyperV' { 'Microsoft-Hyper-V-All' }
        'Qemu' { 'HypervisorPlatform' }
        default { '' }
    }
    Assert-ParityEvidence -Condition ($requiredWindowsFeature -ceq $expectedWindowsFeature) -Message "$provider requiredWindowsFeature '$requiredWindowsFeature' does not match '$expectedWindowsFeature'."

    $readinessProvider = [string](Get-ParityProperty -Object $summary -Name 'readinessProvider' -Context $provider)
    Assert-ParityEvidence -Condition ($readinessProvider -ceq $provider) -Message "$provider readinessProvider mismatch: '$readinessProvider'."
    $transport = [string](Get-ParityProperty -Object $summary -Name 'executionTransport' -Context $provider)
    Assert-ParityEvidence -Condition ($transport -ceq 'Background') -Message "$provider must use executionTransport=Background."
    $backgroundState = [string](Get-ParityProperty -Object $summary -Name 'backgroundState' -Context $provider)
    Assert-ParityEvidence -Condition ($backgroundState -ceq 'completed') -Message "$provider backgroundState must be completed."

    $commit = [string](Get-ParityProperty -Object $summary -Name 'gitCommit' -Context $provider)
    Assert-ParityEvidence -Condition ($commit -match '^(?:[0-9a-f]{40}|[0-9a-f]{64})$') -Message "$provider gitCommit must be a lowercase full commit hash."
    $commitSource = [string](Get-ParityProperty -Object $summary -Name 'gitCommitSource' -Context $provider)
    Assert-ParityEvidence -Condition ($commitSource -in @('checkout-head', 'package-manifest')) -Message "$provider gitCommitSource '$commitSource' is not release-grade provenance."
    $provenancePath = [string](Get-ParityProperty -Object $summary -Name 'gitProvenancePath' -Context $provider)
    Assert-ParityEvidence -Condition (-not [string]::IsNullOrWhiteSpace($provenancePath)) -Message "$provider gitProvenancePath is empty."
    $changedFileCount = Get-ParityInt64 -Summary $summary -Name 'gitChangedFileCount' -Provider $provider -Minimum 0
    Assert-ParityEvidence -Condition ($changedFileCount -eq 0) -Message "$provider gitChangedFileCount must be 0."

    $jobIdText = [string](Get-ParityProperty -Object $summary -Name 'jobId' -Context $provider)
    $jobId = [Guid]::Empty
    Assert-ParityEvidence -Condition ([Guid]::TryParse($jobIdText, [ref]$jobId) -and $jobId -ne [Guid]::Empty) -Message "$provider jobId is invalid: '$jobIdText'."
    $sampleSha256 = [string](Get-ParityProperty -Object $summary -Name 'sampleSha256' -Context $provider)
    Assert-ParityEvidence -Condition ($sampleSha256 -match '^[0-9a-f]{64}$') -Message "$provider sampleSha256 is invalid."
    $sampleSizeBytes = Get-ParityInt64 -Summary $summary -Name 'sampleSizeBytes' -Provider $provider -Minimum 1
    $requestedDuration = Get-ParityInt64 -Summary $summary -Name 'requestedDurationSeconds' -Provider $provider -Minimum 1 -Maximum ([int]::MaxValue)
    Assert-ParityTimestamp -Summary $summary -Name 'generatedAtUtc' -Provider $provider
    Assert-ParityTimestamp -Summary $summary -Name 'generatedAtLocal' -Provider $provider
    $generatedAtUtc = [string](Get-ParityProperty -Object $summary -Name 'generatedAtUtc' -Context $provider)
    $generatedAtLocal = [string](Get-ParityProperty -Object $summary -Name 'generatedAtLocal' -Context $provider)

    $resourceOverrideUsed = Get-ParityBoolean -Summary $summary -Name 'providerResourceOverrideUsed' -Provider $provider
    $providerQuerySucceeded = Get-ParityBoolean -Summary $summary -Name 'providerQuerySucceeded' -Provider $provider
    $providerVmExists = Get-ParityBoolean -Summary $summary -Name 'providerVmExists' -Provider $provider
    $providerBaselineExists = Get-ParityBoolean -Summary $summary -Name 'providerBaselineExists' -Provider $provider
    if (-not [bool]$resourceOverrideUsed) {
        Assert-ParityEvidence -Condition $providerQuerySucceeded -Message "$provider providerQuerySucceeded must be true when no resource override is used."
        Assert-ParityEvidence -Condition $providerVmExists -Message "$provider providerVmExists must be true when no resource override is used."
        Assert-ParityEvidence -Condition $providerBaselineExists -Message "$provider providerBaselineExists must be true when no resource override is used."
    }
    $providerDiagnosticCode = [string](Get-ParityProperty -Object $summary -Name 'providerDiagnosticCode' -Context $provider)
    Assert-ParityEvidence -Condition (-not [string]::IsNullOrWhiteSpace($providerDiagnosticCode)) -Message "$provider providerDiagnosticCode is empty."

    $targetVmName = [string](Get-ParityProperty -Object $summary -Name 'targetVmName' -Context $provider)
    $baselineName = [string](Get-ParityProperty -Object $summary -Name 'baselineName' -Context $provider)
    Assert-ParityEvidence -Condition (-not [string]::IsNullOrWhiteSpace($targetVmName)) -Message "$provider targetVmName is empty."
    Assert-ParityEvidence -Condition (-not [string]::IsNullOrWhiteSpace($baselineName)) -Message "$provider baselineName is empty."
    $machineDefinitionPath = [string](Get-ParityProperty -Object $summary -Name 'machineDefinitionPath' -Context $provider)
    if ($provider -in @('VMware', 'Qemu')) {
        Assert-ParityEvidence -Condition (-not [string]::IsNullOrWhiteSpace($machineDefinitionPath)) -Message "$provider machineDefinitionPath is empty."
    }
    if ($provider -ceq 'Qemu') {
        $qemuDiskFormat = [string](Get-ParityProperty -Object $summary -Name 'qemuDiskFormat' -Context $provider)
        Assert-ParityEvidence -Condition ($qemuDiskFormat -in @('qcow2', 'raw', 'vhdx', 'vmdk')) -Message "Qemu qemuDiskFormat '$qemuDiskFormat' is invalid."
    }

    $executedSteps = Get-ParityInt64 -Summary $summary -Name 'executedSteps' -Provider $provider -Minimum 1 -Maximum ([int]::MaxValue)
    $totalSteps = Get-ParityInt64 -Summary $summary -Name 'totalSteps' -Provider $provider -Minimum 1 -Maximum ([int]::MaxValue)
    Assert-ParityEvidence -Condition ($totalSteps -gt 0 -and $executedSteps -eq $totalSteps) -Message "$provider did not execute every runbook step ($executedSteps/$totalSteps)."
    $liveTotalEvents = Get-ParityInt64 -Summary $summary -Name 'liveTotalEvents' -Provider $provider -Minimum 1 -Maximum ([int]::MaxValue)
    $reportEndpointChecks = @((Get-ParityProperty -Object $summary -Name 'reportEndpointChecks' -Context $provider))
    Assert-ParityEvidence -Condition ($reportEndpointChecks.Count -eq 3) -Message "$provider must retain exactly three report endpoint checks."
    $reportEndpointNames = New-Object System.Collections.Generic.List[string]
    foreach ($endpointCheck in $reportEndpointChecks) {
        $endpointName = [string](Get-ParityProperty -Object $endpointCheck -Name 'name' -Context "$provider report endpoint")
        Assert-ParityEvidence -Condition (-not [string]::IsNullOrWhiteSpace($endpointName)) -Message "$provider report endpoint name is empty."
        [void]$reportEndpointNames.Add($endpointName)
        $endpointStatus = Get-ParityInt64 -Summary $endpointCheck -Name 'statusCode' -Provider "$provider report endpoint $endpointName" -Minimum 100 -Maximum 599
        Assert-ParityEvidence -Condition ($endpointStatus -eq 200) -Message "$provider report endpoint '$endpointName' did not return HTTP 200."
        $endpointBytes = Get-ParityInt64 -Summary $endpointCheck -Name 'bytes' -Provider "$provider report endpoint $endpointName" -Minimum 1001
    }
    $uniqueReportEndpointNames = @($reportEndpointNames | Select-Object -Unique)
    Assert-ParityEvidence -Condition ($uniqueReportEndpointNames.Count -eq 3) -Message "$provider report endpoint checks contain duplicate names."
    foreach ($requiredEndpointName in @('default', 'zh', 'en')) {
        Assert-ParityEvidence -Condition ($requiredEndpointName -in $uniqueReportEndpointNames) -Message "$provider is missing the '$requiredEndpointName' report endpoint check."
    }

    $runtimeRoot = [string](Get-ParityProperty -Object $summary -Name 'runtimeRoot' -Context $provider)
    Assert-ParityEvidence -Condition (-not [string]::IsNullOrWhiteSpace($runtimeRoot)) -Message "$provider runtimeRoot is empty."
    $evidencePaths = [ordered]@{
        runbookExecutionPath = Resolve-ParityEvidenceFile -Summary $summary -Name 'runbookExecutionPath' -Provider $provider -RuntimeRoot $runtimeRoot
        guestEventsPath = Resolve-ParityEvidenceFile -Summary $summary -Name 'guestEventsPath' -Provider $provider -RuntimeRoot $runtimeRoot
        reportJsonPath = Resolve-ParityEvidenceFile -Summary $summary -Name 'reportJsonPath' -Provider $provider -RuntimeRoot $runtimeRoot
        reportHtmlPath = Resolve-ParityEvidenceFile -Summary $summary -Name 'reportHtmlPath' -Provider $provider -RuntimeRoot $runtimeRoot
        reportZhHtmlPath = Resolve-ParityEvidenceFile -Summary $summary -Name 'reportZhHtmlPath' -Provider $provider -RuntimeRoot $runtimeRoot
        reportEnHtmlPath = Resolve-ParityEvidenceFile -Summary $summary -Name 'reportEnHtmlPath' -Provider $provider -RuntimeRoot $runtimeRoot
    }
    foreach ($htmlPath in @($evidencePaths.reportHtmlPath, $evidencePaths.reportZhHtmlPath, $evidencePaths.reportEnHtmlPath)) {
        $htmlFile = Get-Item -LiteralPath $htmlPath -ErrorAction Stop
        Assert-ParityEvidence -Condition ($htmlFile.Length -gt 1000) -Message "$provider report HTML is unexpectedly small: $htmlPath"
    }

    $guestEventsDocument = Read-ParityJsonFile -Path $evidencePaths.guestEventsPath -Context "$provider guest events evidence"
    $guestEventCount = @($guestEventsDocument.Value).Count
    Assert-ParityEvidence -Condition ($guestEventCount -gt 0) -Message "$provider guest events evidence contains no rows."

    $executionDocument = Read-ParityJsonFile -Path $evidencePaths.runbookExecutionPath -Context "$provider runbook execution evidence"
    $execution = $executionDocument.Value
    Assert-ParityBoolean -Summary $execution -Name 'success' -Expected $true -Provider "$provider runbook execution"
    $executionJobId = [string](Get-ParityProperty -Object $execution -Name 'jobId' -Context "$provider runbook execution")
    Assert-ParityEvidence -Condition ($executionJobId -eq $jobIdText) -Message "$provider runbook execution jobId does not match its summary."
    $executionProvider = [string](Get-ParityProperty -Object $execution -Name 'provider' -Context "$provider runbook execution")
    Assert-ParityEvidence -Condition ($executionProvider -ceq $provider) -Message "$provider runbook execution provider mismatch: '$executionProvider'."
    $executionMode = [string](Get-ParityProperty -Object $execution -Name 'mode' -Context "$provider runbook execution")
    Assert-ParityEvidence -Condition ($executionMode -in @('1', 'Live')) -Message "$provider runbook execution mode must be Live but was '$executionMode'."
    Assert-ParityEvidence -Condition ([string](Get-ParityProperty -Object $execution -Name 'targetVmName' -Context "$provider runbook execution") -eq $targetVmName) -Message "$provider runbook execution targetVmName does not match its summary."
    Assert-ParityEvidence -Condition ([string](Get-ParityProperty -Object $execution -Name 'baselineName' -Context "$provider runbook execution") -eq $baselineName) -Message "$provider runbook execution baselineName does not match its summary."
    $executionMachineDefinition = [string](Get-ParityOptionalProperty -Object $execution -Name 'machineDefinitionPath')
    Assert-ParityEvidence -Condition ($executionMachineDefinition -eq $machineDefinitionPath) -Message "$provider runbook execution machineDefinitionPath does not match its summary."
    $executionDiskFormat = [string](Get-ParityOptionalProperty -Object $execution -Name 'qemuDiskFormat')
    $expectedDiskFormat = if ($provider -ceq 'Qemu') { $qemuDiskFormat } else { '' }
    Assert-ParityEvidence -Condition ($executionDiskFormat -eq $expectedDiskFormat) -Message "$provider runbook execution qemuDiskFormat does not match its summary."
    $executionExecutedSteps = Get-ParityInt64 -Summary $execution -Name 'executedSteps' -Provider "$provider runbook execution" -Minimum 1 -Maximum ([int]::MaxValue)
    $executionTotalSteps = Get-ParityInt64 -Summary $execution -Name 'totalSteps' -Provider "$provider runbook execution" -Minimum 1 -Maximum ([int]::MaxValue)
    Assert-ParityEvidence -Condition ($executionExecutedSteps -eq $executedSteps -and $executionTotalSteps -eq $totalSteps) -Message "$provider runbook execution step counts do not match its summary."

    $reportDocument = Read-ParityJsonFile -Path $evidencePaths.reportJsonPath -Context "$provider report evidence"
    $report = $reportDocument.Value
    $reportJobId = [string](Get-ParityProperty -Object $report -Name 'jobId' -Context "$provider report evidence")
    Assert-ParityEvidence -Condition ($reportJobId -eq $jobIdText) -Message "$provider report jobId does not match its summary."
    $reportProvider = [string](Get-ParityProperty -Object $report -Name 'provider' -Context "$provider report evidence")
    Assert-ParityEvidence -Condition ($reportProvider -ceq $provider) -Message "$provider report provider mismatch: '$reportProvider'."
    $reportStatus = [string](Get-ParityProperty -Object $report -Name 'status' -Context "$provider report evidence")
    Assert-ParityEvidence -Condition ($reportStatus -in @('4', 'Completed')) -Message "$provider report status must be Completed but was '$reportStatus'."
    Assert-ParityEvidence -Condition ([string](Get-ParityProperty -Object $report -Name 'targetVmName' -Context "$provider report evidence") -eq $targetVmName) -Message "$provider report targetVmName does not match its summary."
    Assert-ParityEvidence -Condition ([string](Get-ParityProperty -Object $report -Name 'baselineName' -Context "$provider report evidence") -eq $baselineName) -Message "$provider report baselineName does not match its summary."
    $reportMachineDefinition = [string](Get-ParityOptionalProperty -Object $report -Name 'machineDefinitionPath')
    Assert-ParityEvidence -Condition ($reportMachineDefinition -eq $machineDefinitionPath) -Message "$provider report machineDefinitionPath does not match its summary."
    $reportDiskFormat = [string](Get-ParityOptionalProperty -Object $report -Name 'qemuDiskFormat')
    Assert-ParityEvidence -Condition ($reportDiskFormat -eq $expectedDiskFormat) -Message "$provider report qemuDiskFormat does not match its summary."
    $reportSample = Get-ParityProperty -Object $report -Name 'sample' -Context "$provider report evidence"
    $reportSampleSha256 = [string](Get-ParityProperty -Object $reportSample -Name 'sha256' -Context "$provider report sample")
    Assert-ParityEvidence -Condition ($reportSampleSha256 -ceq $sampleSha256) -Message "$provider report sample SHA-256 does not match its summary."
    $reportSampleSize = Get-ParityInt64 -Summary $reportSample -Name 'sizeBytes' -Provider "$provider report sample" -Minimum 1
    Assert-ParityEvidence -Condition ($reportSampleSize -eq $sampleSizeBytes) -Message "$provider report sample size does not match its summary."

    $evidenceSha256 = [ordered]@{}
    foreach ($evidenceName in $evidencePaths.Keys) {
        $evidenceSha256[$evidenceName] = Get-ParityFileSha256 -Path ([string]$evidencePaths[$evidenceName])
    }

    return [pscustomobject][ordered]@{
        provider = $provider
        summaryPath = $Record.Path
        summarySha256 = Get-ParityFileSha256 -Path $Record.Path
        mode = $mode
        success = $true
        jobId = $jobId.ToString('D')
        gitCommit = $commit
        gitCommitSource = $commitSource
        gitProvenancePath = $provenancePath
        gitDirty = $false
        gitChangedFileCount = $changedFileCount
        generatedAtUtc = $generatedAtUtc
        generatedAtLocal = $generatedAtLocal
        sampleSha256 = $sampleSha256
        sampleSizeBytes = $sampleSizeBytes
        requestedDurationSeconds = $requestedDuration
        readinessProvider = $readinessProvider
        readinessReadOnly = $true
        hostAccelerationReady = $true
        requiredWindowsFeatureReady = $true
        providerManagementAvailable = $true
        providerQuerySucceeded = $providerQuerySucceeded
        providerVmExists = $providerVmExists
        providerBaselineExists = $providerBaselineExists
        providerGuestTransportSecure = $true
        providerGuestEndpointReady = $true
        executionTransport = $transport
        backgroundState = $backgroundState
        providerDiagnosticCode = $providerDiagnosticCode
        providerResourceOverrideUsed = $resourceOverrideUsed
        requiredWindowsFeature = $requiredWindowsFeature
        guestImportSucceeded = $true
        guestImportSkipped = $false
        guestImportFailed = $false
        cSignToolUsed = $false
        executedSteps = $executedSteps
        totalSteps = $totalSteps
        liveTotalEvents = $liveTotalEvents
        guestEventCount = $guestEventCount
        reportEndpointCheckCount = $reportEndpointChecks.Count
        runtimeRoot = [System.IO.Path]::GetFullPath($runtimeRoot)
        targetVmName = $targetVmName
        baselineName = $baselineName
        machineDefinitionPath = $machineDefinitionPath
        qemuDiskFormat = $expectedDiskFormat
        evidencePaths = $evidencePaths
        evidenceSha256 = $evidenceSha256
    }
}

$records = @(
    Read-ParitySummary -Path $HyperVSummaryPath -ExpectedProvider 'HyperV'
    Read-ParitySummary -Path $VMwareSummaryPath -ExpectedProvider 'VMware'
    Read-ParitySummary -Path $QemuSummaryPath -ExpectedProvider 'Qemu'
)
$validatedRecords = @($records | ForEach-Object { Test-ParityProviderRecord -Record $_ })
$commits = @($validatedRecords | Select-Object -ExpandProperty gitCommit -Unique)
$sampleHashes = @($validatedRecords | Select-Object -ExpandProperty sampleSha256 -Unique)
$sampleSizes = @($validatedRecords | Select-Object -ExpandProperty sampleSizeBytes -Unique)
$durations = @($validatedRecords | Select-Object -ExpandProperty requestedDurationSeconds -Unique)
$jobIds = @($validatedRecords | Select-Object -ExpandProperty jobId -Unique)
Assert-ParityEvidence -Condition ($commits.Count -eq 1) -Message "Provider summaries do not share one gitCommit: $($commits -join ', ')"
Assert-ParityEvidence -Condition ($sampleHashes.Count -eq 1 -and $sampleSizes.Count -eq 1) -Message 'Provider summaries did not execute the same sample bytes.'
Assert-ParityEvidence -Condition ($durations.Count -eq 1) -Message "Provider summaries do not share one requestedDurationSeconds value: $($durations -join ', ')"
Assert-ParityEvidence -Condition ($jobIds.Count -eq 3) -Message 'Each provider must retain a distinct jobId.'

$resolvedOutputPath = [System.IO.Path]::GetFullPath($OutputPath)
$protectedEvidencePaths = @(
    $records | ForEach-Object { $_.Path }
    $validatedRecords | ForEach-Object { $_.evidencePaths.Values }
)
$outputOverwritesEvidence = @($protectedEvidencePaths | Where-Object {
        $resolvedOutputPath.Equals([string]$_, [System.StringComparison]::OrdinalIgnoreCase)
    }).Count -gt 0
Assert-ParityEvidence -Condition (-not $outputOverwritesEvidence) -Message "OutputPath must not overwrite an input summary or referenced evidence file: $resolvedOutputPath"
$result = [pscustomobject][ordered]@{
    schema = 'ksword.provider-parity-evidence.v1'
    validated = $true
    validatedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
    validationPath = $resolvedOutputPath
    gitCommit = $commits[0]
    sampleSha256 = $sampleHashes[0]
    sampleSizeBytes = $sampleSizes[0]
    requestedDurationSeconds = $durations[0]
    requiredProviders = @('HyperV', 'VMware', 'Qemu')
    records = $validatedRecords
}

$outputDirectory = [System.IO.Path]::GetDirectoryName($resolvedOutputPath)
if (-not [string]::IsNullOrWhiteSpace($outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}
$result | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $resolvedOutputPath -Encoding UTF8
Write-Host "[provider-parity] Validated HyperV, VMware, and Qemu evidence from commit $($commits[0])."
Write-Host "[provider-parity] Result: $resolvedOutputPath"
Write-Output $result
