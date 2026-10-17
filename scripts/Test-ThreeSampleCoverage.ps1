[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)] [string[]]$JobRoot,
    [string]$OutputPath,
    [int]$MinimumSamples = 3
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-Value([object]$Object, [string[]]$Names) {
    if ($null -eq $Object) { return $null }
    foreach ($name in $Names) {
        $property = $Object.PSObject.Properties[$name]
        if ($null -ne $property -and $null -ne $property.Value -and -not [string]::IsNullOrWhiteSpace([string]$property.Value)) { return $property.Value }
    }
    return $null
}
function Get-Count([object]$Object, [string[]]$Names) {
    $value = Get-Value $Object $Names
    if ($null -eq $value) { return $null }
    try { return [int64]$value } catch { return $null }
}
function Get-Boolean([object]$Object, [string[]]$Names) {
    $value = Get-Value $Object $Names
    if ($null -eq $value) { return $null }
    $text = ([string]$value).Trim()
    if ($text -match '^(?i:true|yes|1|on|required)$') { return $true }
    if ($text -match '^(?i:false|no|0|off|not-required)$') { return $false }
    return $null
}
function Test-NonZeroExitCode([object]$Value) {
    if ($null -eq $Value) { return $false }
    $text = ([string]$Value).Trim()
    if ([string]::IsNullOrWhiteSpace($text) -or $text -match '^(?i:success|succeeded|ok)$') { return $false }
    if ($text -match '^0x([0-9a-fA-F]+)$') {
        try { return ([Convert]::ToUInt64($Matches[1], 16) -ne 0) } catch { return $true }
    }
    $number = 0L
    if ([long]::TryParse($text, [Globalization.NumberStyles]::Integer, [Globalization.CultureInfo]::InvariantCulture, [ref]$number)) { return $number -ne 0 }
    return $true
}
function Test-TrueValue([object]$Value) {
    if ($null -eq $Value) { return $false }
    return ([string]$Value).Trim() -match '^(?i:true|yes|1|required)$'
}
function Get-EventDataCount([object[]]$Events, [string]$EventType, [string[]]$Names) {
    $sum = 0L; $found = $false
    foreach ($event in @($Events)) {
        if ($null -eq $event -or [string]$event.EventType -ine $EventType) { continue }
        $data = Get-Value $event @('Data')
        $value = Get-Count $data $Names
        if ($null -ne $value) { $sum += $value; $found = $true }
    }
    if ($found) { return $sum }
    return $null
}
function Get-EventDataFlag([object[]]$Events, [string[]]$EventTypes, [string[]]$Names) {
    foreach ($event in @($Events)) {
        if ($null -eq $event) { continue }
        if ($EventTypes -notcontains ([string]$event.EventType)) { continue }
        $data = Get-Value $event @('Data')
        $value = Get-Value $data $Names
        if ($null -ne $value) { return $value }
    }
    return $null
}
function Get-ExitValue([object]$Event) {
    $data = Get-Value $Event @('Data')
    $value = Get-Value $data @('exitCode','status','exitStatus','code')
    if ($null -ne $value) { return $value }
    return Get-Value $Event @('ExitCode','Status','ExitStatus')
}
function Test-ArtifactPath([string]$Path, [string]$ReportRoot) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $candidate = $Path
    if (-not [IO.Path]::IsPathRooted($candidate)) {
        $candidate = Join-Path $ReportRoot $candidate
    }
    return Test-Path -LiteralPath $candidate -PathType Leaf
}
function Test-SampleProcessExit([object]$Event, [object]$Sample) {
    if ($null -eq $Event -or [string]$Event.EventType -ine 'process.exit') { return $false }
    $data = Get-Value $Event @('Data')
    $correlation = [string](Get-Value $data @('sampleCorrelation','sampleCorrelationStatus'))
    $counted = Get-Boolean $data @('behaviorCounted','sampleBehaviorCandidate')
    if ($correlation -match '^(?i:confirmed|probable)$' -or $counted -eq $true) { return $true }
    $sampleName = [IO.Path]::GetFileNameWithoutExtension([string](Get-Value $Sample @('FileName')))
    $processName = [string](Get-Value $Event @('ProcessName'))
    if (-not [string]::IsNullOrWhiteSpace($sampleName) -and $processName -ieq $sampleName) { return $true }
    return $false
}
function F([object]$Value) {
    if ($null -eq $Value) { return '—' }
    return ([int64]$Value).ToString('N0', [Globalization.CultureInfo]::InvariantCulture)
}
function StatusName([object]$Report) {
    $status = Get-Value $Report @('Status')
    switch ([int]$status) { 2 { 'planned'; break } 3 { 'running/failed'; break } 4 { 'completed-with-evidence'; break } 5 { 'rejected/failed'; break } default { [string]$status } }
}

$rows = @()
# A script invoked through `pwsh -File` receives a comma-separated list as
# one argument. Expand that form here while still accepting a native string[]
# when the script is called from another PowerShell script.
$jobRoots = @($JobRoot | ForEach-Object { ([string]$_).Split(',', [StringSplitOptions]::RemoveEmptyEntries) } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
foreach ($root in $jobRoots) {
    $resolved = (Resolve-Path -LiteralPath $root -ErrorAction Stop).ProviderPath
    $reportPath = Join-Path $resolved 'report.json'
    if (-not (Test-Path -LiteralPath $reportPath -PathType Leaf)) { throw "report.json not found: $resolved" }
    $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    $metrics = Get-Value $report @('Metrics')
    $health = Get-Value $report @('CollectionHealth')
    $sample = Get-Value $report @('Sample')
    $events = @($report.Events)
    $total = Get-Count $metrics @('events.total','events')
    $raw = Get-Count $metrics @('events.raw','rawEvents')
    $inline = Get-Count $metrics @('events.report','reportEvents')
    $r0raw = Get-Count $metrics @('events.r0.driver.raw')
    $lost = Get-Count $metrics @('events.r0.driver.lostCount','driverLostCount'); if ($null -eq $lost) { $lost = Get-Count $health @('DriverLostCount') }
    $lossRows = Get-Count $health @('LossRows'); if ($null -eq $lossRows) { $lossRows = Get-Count $metrics @('collectionHealth.losses','events.collectionHealth.losses') }
    $failures = Get-Count $health @('FailureRows'); if ($null -eq $failures) { $failures = Get-Count $metrics @('collectionHealth.failures','events.collectionHealth.failures') }
    $etwLost = Get-Count $health @('EtwEventsLost'); if ($null -eq $etwLost) { $etwLost = Get-Count $metrics @('collectionHealth.etw.eventsLost','events.collectionHealth.etw.eventsLost') }
    $etwLostRows = Get-Count $health @('EtwEventsLostRows'); if ($null -eq $etwLostRows) { $etwLostRows = Get-Count $metrics @('collectionHealth.etw.eventsLostRows','events.collectionHealth.etw.eventsLostRows') }
    $driverLossRows = Get-Count $health @('DriverLossRows'); if ($null -eq $driverLossRows) { $driverLossRows = Get-Count $metrics @('collectionHealth.driver.lossRows','events.collectionHealth.driver.lossRows') }
    $treeUnavailable = Get-Count $health @('ProcessTreeUnavailable'); if ($null -eq $treeUnavailable) { $treeUnavailable = Get-Count $metrics @('collectionHealth.process.treeUnavailable','events.collectionHealth.process.treeUnavailable') }
    $scheduledTaskFailures = Get-Count $health @('ScheduledTaskCaptureFailed'); if ($null -eq $scheduledTaskFailures) { $scheduledTaskFailures = Get-Count $metrics @('collectionHealth.scheduledTask.captureFailed','events.collectionHealth.scheduledTask.captureFailed') }
    $pktmonFailures = Get-Count $health @('PktmonStopFailed'); if ($null -eq $pktmonFailures) { $pktmonFailures = Get-Count $metrics @('collectionHealth.pktmon.stopFailed','events.collectionHealth.pktmon.stopFailed') }
    $etwDecodeFailures = Get-Count $health @('EtwDecodeFailed'); if ($null -eq $etwDecodeFailures) { $etwDecodeFailures = Get-Count $metrics @('collectionHealth.etw.decodeFailed','events.collectionHealth.etw.decodeFailed') }
    $backpressure = Get-Count $metrics @('events.r0.driver.backpressureObserved')
    $suppressed = Get-Count $metrics @('events.r0.driver.eventsSuppressed','driverEventsSuppressed')
    $dynamic = Get-Count $metrics @('events.dynamicAction.raw')
    $dynamicAttributedRaw = Get-Count $metrics @('events.dynamicAction.attributedRaw')
    $dynamicUnknownRaw = Get-Count $metrics @('events.dynamicAction.rawUnknown','events.dynamicAction.unattributedRaw')
    $dynamicReport = Get-Count $metrics @('events.dynamicAction.report')
    $dynamicAttributedReport = Get-Count $metrics @('events.dynamicAction.attributedReport')
    $dynamicUnattributedReport = Get-Count $metrics @('events.dynamicAction.unattributedReport','events.dynamicAction.unknownReport')
    $dynamicAttributedOmitted = Get-Count $metrics @('events.dynamicAction.attributedOmitted')
    $persistence = Get-Count $metrics @('events.persistence.raw')
    $file = Get-Count $metrics @('events.file.raw')
    $network = Get-Count $metrics @('events.networkTcp.raw')
    $rawPath = $null; $driverPath = $null
    foreach ($event in $events) {
        $data = Get-Value $event @('Data')
        if ($null -eq $data) { continue }
        if (-not $rawPath) { $rawPath = [string](Get-Value $data @('rawEventsPath')) }
        if (-not $driverPath) { $driverPath = [string](Get-Value $data @('driverEventsPath')) }
        if ($rawPath -and $driverPath) { break }
    }
    $rawPathOk = Test-ArtifactPath $rawPath $resolved
    $driverPathOk = Test-ArtifactPath $driverPath $resolved
    $driverSourceMetric = Get-Count $metrics @('events.sources.driver','events.sources.driverEvents','events.r0.driver.raw')
    $driverSourceRows = @($events | Where-Object { [string]$_.Source -ieq 'driver' }).Count
    $driverSourceOk = (($null -ne $driverSourceMetric -and $driverSourceMetric -gt 0) -or $driverSourceRows -gt 0)
    $etwParsedCount = Get-Count $metrics @('events.etw.parsedEventCount','etw.parsedEventCount','collectionHealth.etw.parsedEventCount')
    if ($null -eq $etwParsedCount) { $etwParsedCount = Get-EventDataCount $events 'etw_live.captured' @('parsedEventCount') }
    $etlDecodeRequired = Get-Boolean $metrics @('events.etw.etlDecodeRequired','etw.etlDecodeRequired','collectionHealth.etw.etlDecodeRequired')
    if ($null -eq $etlDecodeRequired) { $etlDecodeRequired = Test-TrueValue (Get-EventDataFlag $events @('etw_live.captured','etw_live.decode_failed') @('etlDecodeRequired')) }
    $protocolParserNotImplemented = Get-Boolean $metrics @('events.packetCapture.protocolParserNotImplemented','packet_capture.protocolParserNotImplemented')
    $protocolReason = Get-Value $metrics @('events.packetCapture.protocolSummaryReason','packet_capture.protocolSummaryReason')
    $packetCaptureEventTypes = @('packet_capture.failed','packet_capture.summary','packet_capture.protocol_summary','pcap.summary','pcap.flow','network.flow')
    if ($null -eq $protocolReason) { $protocolReason = Get-EventDataFlag $events $packetCaptureEventTypes @('protocolSummaryReason') }
    if ($null -eq $protocolParserNotImplemented) {
        $protocolFlag = Get-EventDataFlag $events $packetCaptureEventTypes @('protocolParserNotImplemented')
        $protocolParserNotImplemented = (Test-TrueValue $protocolFlag) -or ([string]$protocolReason -ieq 'protocolParserNotImplemented')
    }
    $sampleProcessExitErrors = @($events | Where-Object { (Test-SampleProcessExit $_ $sample) -and (Test-NonZeroExitCode (Get-ExitValue $_)) }).Count
    $treeEventCount = @($events | Where-Object { [string]$_.EventType -ieq 'process.tree_unavailable' }).Count
    if ($null -eq $treeUnavailable) { $treeUnavailable = [int64]$treeEventCount }
    $reasonsValue = Get-Value $health @('StateReasons')
    $reasons = @(@($reasonsValue) | ForEach-Object { [string]$_ } | Where-Object { $_ })
    $gate = 'PASS'; $why = [System.Collections.Generic.List[string]]::new()
    if ($null -eq $health) { $gate = 'FAIL'; [void]$why.Add('缺少 CollectionHealth，不能证明采集健康') }
    if ($null -eq $total -or $total -le 0) { $gate = 'FAIL'; [void]$why.Add('没有动态事件') }
    if ($null -eq $inline -or $inline -le 0) { $gate = 'FAIL'; [void]$why.Add('报告没有可展示事件') }
    if ($null -eq $lost -or $lost -ne 0 -or $null -eq $driverLossRows -or $driverLossRows -ne 0 -or $null -eq $lossRows -or $lossRows -ne 0 -or $null -eq $etwLost -or $etwLost -ne 0 -or $null -eq $etwLostRows -or $etwLostRows -ne 0) { $gate = 'FAIL'; [void]$why.Add("采集丢失必须明确为 0：R0=$(F $lost) R0行=$(F $driverLossRows) 行=$(F $lossRows) ETW=$(F $etwLost) ETW行=$(F $etwLostRows)") }
    if ($null -eq $failures -or $failures -ne 0 -or $null -eq $etwDecodeFailures -or $etwDecodeFailures -ne 0 -or $null -eq $scheduledTaskFailures -or $scheduledTaskFailures -ne 0 -or $null -eq $pktmonFailures -or $pktmonFailures -ne 0) { $gate = 'FAIL'; [void]$why.Add("采集失败指标必须明确为 0：失败行=$(F $failures) ETW解码=$(F $etwDecodeFailures) 计划任务=$(F $scheduledTaskFailures) pktmon=$(F $pktmonFailures)") }
    if (-not $rawPathOk) { $gate = 'FAIL'; [void]$why.Add('rawEventsPath 缺失或文件不存在') }
    if (-not $driverPathOk) { $gate = 'FAIL'; [void]$why.Add('driverEventsPath 缺失或文件不存在') }
    if (-not $driverSourceOk) { $gate = 'FAIL'; [void]$why.Add('缺少 driver source 事件/指标') }
    if ($null -eq $etwParsedCount -or $etwParsedCount -le 0) { $gate = 'FAIL'; [void]$why.Add("ETW parsedEventCount 必须大于 0，当前 $(F $etwParsedCount)") }
    if ($etlDecodeRequired -eq $true) { $gate = 'FAIL'; [void]$why.Add('etlDecodeRequired=true，ETL 解码仍是必需缺口') }
    if ($protocolParserNotImplemented -eq $true) { $gate = 'FAIL'; [void]$why.Add('packet_capture protocolParserNotImplemented=true') }
    if ($treeUnavailable -ne 0) { $gate = 'FAIL'; [void]$why.Add("process.tree_unavailable 必须为 0，当前 $(F $treeUnavailable)") }
    if ($sampleProcessExitErrors -gt 0) { $gate = 'FAIL'; [void]$why.Add("样本 process.exit 非零：$sampleProcessExitErrors 行") }
    if ($null -eq $dynamic -or $null -eq $dynamicAttributedRaw -or $null -eq $dynamicUnknownRaw -or ($dynamicAttributedRaw + $dynamicUnknownRaw) -ne $dynamic) { $gate = 'FAIL'; [void]$why.Add("动态动作分解不完整：raw=$(F $dynamic) attributed=$(F $dynamicAttributedRaw) unknown=$(F $dynamicUnknownRaw)") }
    if ($null -eq $dynamicReport -or $null -eq $dynamicAttributedReport -or $null -eq $dynamicUnattributedReport -or ($dynamicAttributedReport + $dynamicUnattributedReport) -ne $dynamicReport) { $gate = 'FAIL'; [void]$why.Add("动态报告分解不完整：report=$(F $dynamicReport) attributed=$(F $dynamicAttributedReport) unknown=$(F $dynamicUnattributedReport)") }
    if ($null -eq $dynamicAttributedOmitted -or $dynamicAttributedOmitted -ne 0 -or ($null -ne $dynamic -and $null -ne $dynamicReport -and $dynamic -ne $dynamicReport)) { $gate = 'FAIL'; [void]$why.Add("动态行为不能在报告采样中丢失：attributedOmitted=$(F $dynamicAttributedOmitted) raw/report=$(F $dynamic)/$(F $dynamicReport)") }
    if ($gate -eq 'PASS' -and (($null -ne $backpressure -and $backpressure -gt 0) -or ($null -ne $suppressed -and $suppressed -gt 0) -or $reasons.Count -gt 0)) { $gate = 'WARN'; [void]$why.Add('存在回压、抑制或降级标记') }
    if ($why.Count -eq 0) { [void]$why.Add('基础事件、报告和采集健康指标齐全') }
    $rows += [pscustomobject]@{ Job=(Split-Path $resolved -Leaf); Sample=[string](Get-Value $sample @('FileName')); Status=(StatusName $report); Gate=$gate; Why=($why -join '；'); Total=$total; Raw=$raw; Inline=$inline; R0Raw=$r0raw; Lost=$lost; DriverLossRows=$driverLossRows; LossRows=$lossRows; ETWLost=$etwLost; ETWLostRows=$etwLostRows; ETWParsed=$etwParsedCount; Failures=$failures; ETWDecodeFailures=$etwDecodeFailures; Backpressure=$backpressure; Dynamic=$dynamic; DynamicAttributed=$dynamicAttributedRaw; DynamicUnknown=$dynamicUnknownRaw; DynamicReport=$dynamicReport; TreeUnavailable=$treeUnavailable; ProtocolParserNotImplemented=$protocolParserNotImplemented; SampleProcessExitErrors=$sampleProcessExitErrors; DriverSource=$driverSourceMetric; Persistence=$persistence; File=$file; Network=$network; Suppressed=$suppressed; StateReasons=($reasons -join ','); RawPath=$rawPath; DriverPath=$driverPath; RawPathOk=$rawPathOk; DriverPathOk=$driverPathOk; ReportPath=$reportPath }
}
if ($rows.Count -lt $MinimumSamples) { throw "需要至少 $MinimumSamples 份报告，当前只有 $($rows.Count) 份。" }

$lines = [System.Collections.Generic.List[string]]::new()
[void]$lines.Add('# 三样本动态报告回归核对'); [void]$lines.Add('')
[void]$lines.Add("生成时间：$([DateTime]::UtcNow.ToString('u'))；报告数：$($rows.Count)"); [void]$lines.Add('')
[void]$lines.Add('此核对只读取现有 report.json，不启动样本、不连接虚拟机。`FAIL` 表示报告不能证明没有采集缺口；`WARN` 表示有回压、抑制或降级，需要继续修复。'); [void]$lines.Add('')
[void]$lines.Add('| 样本 | 状态 | 门禁 | 总事件 | 报告事件 | 动态 raw/归因/未知 | R0 丢失/行 | ETW 解析/丢失 | 失败/树不可用 | driver source | 回压 | 持久化 | 文件 | 网络 |'); [void]$lines.Add('|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|')
foreach ($row in $rows) { [void]$lines.Add("| $($row.Sample) | $($row.Status) | **$($row.Gate)** | $(F $row.Total) | $(F $row.Inline) | $(F $row.Dynamic)/$(F $row.DynamicAttributed)/$(F $row.DynamicUnknown) | $(F $row.Lost)/$(F $row.DriverLossRows) | $(F $row.ETWParsed)/$(F $row.ETWLost) | $(F $row.Failures)/$(F $row.TreeUnavailable) | $(F $row.DriverSource) | $(F $row.Backpressure) | $(F $row.Persistence) | $(F $row.File) | $(F $row.Network) |") }
[void]$lines.Add(''); [void]$lines.Add('## 每份报告必须继续核对'); [void]$lines.Add('')
foreach ($row in $rows) { [void]$lines.Add("- **$($row.Sample)**：$($row.Gate)；$($row.Why)"); if ($row.StateReasons) { [void]$lines.Add("  - 状态原因：$($row.StateReasons)") }; [void]$lines.Add("  - 原始报告：$($row.ReportPath)"); [void]$lines.Add("  - rawEventsPath：$(if ($row.RawPathOk) { '可追溯' } else { '缺失' })；$($row.RawPath)"); [void]$lines.Add("  - driverEventsPath：$(if ($row.DriverPathOk) { '可追溯' } else { '缺失' })；$($row.DriverPath)") }
[void]$lines.Add(''); [void]$lines.Add('## 三样本最短验收矩阵'); [void]$lines.Add(''); [void]$lines.Add('| 核对项 | 通过条件 | 失败含义 |'); [void]$lines.Add('|---|---|---|')
[void]$lines.Add('| 进程链 | 总事件、动态动作、进程事件均大于 0，并能定位样本进程 | 样本可能未启动或归因丢失 |')
[void]$lines.Add('| 文件/注册表 | 文件事件与持久化事件有原始计数，报告中存在对应证据 | 行为被采集但可能被矩阵或展示层丢弃 |')
[void]$lines.Add('| 网络 | 网络原始事件有计数；报告中的网络证据可追溯到原始路径 | 网络采集链或归因链缺口 |')
[void]$lines.Add('| R0/ETW 完整性 | R0 丢失、ETW 丢失、失败行均为 0 | 驱动环形缓冲或 ETW 已明确丢失 |')
[void]$lines.Add('| 报告保真 | 原始事件路径存在，动态动作未因内联采样而减少 | 需要继续检查报告筛选和来源合并 |')
if (-not [string]::IsNullOrWhiteSpace($OutputPath)) { $parent = Split-Path -Parent $OutputPath; if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }; Set-Content -LiteralPath $OutputPath -Value ($lines -join [Environment]::NewLine) -Encoding UTF8; Write-Host "Wrote $OutputPath" }
$lines -join [Environment]::NewLine
if (@($rows | Where-Object Gate -eq 'FAIL').Count -gt 0) { exit 2 }
if (@($rows | Where-Object Gate -eq 'WARN').Count -gt 0) { exit 1 }
exit 0
