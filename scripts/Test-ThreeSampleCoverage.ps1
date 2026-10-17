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
function F([object]$Value) {
    if ($null -eq $Value) { return '—' }
    return ([int64]$Value).ToString('N0', [Globalization.CultureInfo]::InvariantCulture)
}
function StatusName([object]$Report) {
    $status = Get-Value $Report @('Status')
    switch ([int]$status) { 2 { 'planned'; break } 3 { 'running/failed'; break } 4 { 'completed-with-evidence'; break } 5 { 'rejected/failed'; break } default { [string]$status } }
}

$rows = @()
foreach ($root in $JobRoot) {
    $resolved = (Resolve-Path -LiteralPath $root -ErrorAction Stop).ProviderPath
    $reportPath = Join-Path $resolved 'report.json'
    if (-not (Test-Path -LiteralPath $reportPath -PathType Leaf)) { throw "report.json not found: $resolved" }
    $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    $metrics = $report.Metrics
    $health = $report.CollectionHealth
    $sample = $report.Sample
    $total = Get-Count $metrics @('events.total','events')
    $raw = Get-Count $metrics @('events.raw','rawEvents')
    $inline = Get-Count $metrics @('events.report','reportEvents')
    $r0raw = Get-Count $metrics @('events.r0.driver.raw')
    $lost = Get-Count $metrics @('events.r0.driver.lostCount','driverLostCount'); if ($null -eq $lost) { $lost = Get-Count $health @('DriverLostCount') }
    $lossRows = Get-Count $health @('LossRows')
    $failures = Get-Count $health @('FailureRows')
    $etwLost = Get-Count $health @('EtwEventsLost')
    $backpressure = Get-Count $metrics @('events.r0.driver.backpressureObserved')
    $suppressed = Get-Count $metrics @('events.r0.driver.eventsSuppressed','driverEventsSuppressed')
    $dynamic = Get-Count $metrics @('events.dynamicAction.raw')
    $persistence = Get-Count $metrics @('events.persistence.raw')
    $file = Get-Count $metrics @('events.file.raw')
    $network = Get-Count $metrics @('events.networkTcp.raw')
    $rawPath = $null; $driverPath = $null
    foreach ($event in @($report.Events)) {
        $data = Get-Value $event @('Data')
        if ($null -eq $data) { continue }
        if (-not $rawPath) { $rawPath = [string](Get-Value $data @('rawEventsPath')) }
        if (-not $driverPath) { $driverPath = [string](Get-Value $data @('driverEventsPath')) }
        if ($rawPath -and $driverPath) { break }
    }
    $rawPathOk = ($rawPath -and (Test-Path -LiteralPath $rawPath -PathType Leaf)) -or ($driverPath -and (Test-Path -LiteralPath $driverPath -PathType Leaf))
    $reasonsValue = Get-Value $health @('StateReasons')
    $reasons = @($reasonsValue) | ForEach-Object { [string]$_ } | Where-Object { $_ }
    $gate = 'PASS'; $why = [System.Collections.Generic.List[string]]::new()
    if ($null -eq $total -or $total -le 0) { $gate = 'FAIL'; [void]$why.Add('没有动态事件') }
    if ($null -eq $inline -or $inline -le 0) { $gate = 'FAIL'; [void]$why.Add('报告没有可展示事件') }
    if (($null -ne $lost -and $lost -gt 0) -or ($null -ne $lossRows -and $lossRows -gt 0) -or ($null -ne $etwLost -and $etwLost -gt 0)) { $gate = 'FAIL'; [void]$why.Add("采集丢失 R0=$(F $lost) 行=$(F $lossRows) ETW=$(F $etwLost)") }
    if ($null -ne $failures -and $failures -gt 0) { $gate = 'FAIL'; [void]$why.Add("采集失败行 $(F $failures)") }
    if (-not $rawPathOk) { $gate = 'FAIL'; [void]$why.Add('原始事件路径不存在') }
    if ($gate -eq 'PASS' -and (($null -ne $backpressure -and $backpressure -gt 0) -or ($null -ne $suppressed -and $suppressed -gt 0) -or $reasons.Count -gt 0)) { $gate = 'WARN'; [void]$why.Add('存在回压、抑制或降级标记') }
    if ($why.Count -eq 0) { [void]$why.Add('基础事件、报告和采集健康指标齐全') }
    $rows += [pscustomobject]@{ Job=(Split-Path $resolved -Leaf); Sample=[string]$sample.FileName; Status=(StatusName $report); Gate=$gate; Why=($why -join '；'); Total=$total; Raw=$raw; Inline=$inline; R0Raw=$r0raw; Lost=$lost; LossRows=$lossRows; ETWLost=$etwLost; Failures=$failures; Backpressure=$backpressure; Dynamic=$dynamic; Persistence=$persistence; File=$file; Network=$network; Suppressed=$suppressed; StateReasons=($reasons -join ','); RawPath=$rawPath; DriverPath=$driverPath; RawPathOk=$rawPathOk; ReportPath=$reportPath }
}
if ($rows.Count -lt $MinimumSamples) { throw "需要至少 $MinimumSamples 份报告，当前只有 $($rows.Count) 份。" }

$lines = [System.Collections.Generic.List[string]]::new()
[void]$lines.Add('# 三样本动态报告回归核对'); [void]$lines.Add('')
[void]$lines.Add("生成时间：$([DateTime]::UtcNow.ToString('u'))；报告数：$($rows.Count)"); [void]$lines.Add('')
[void]$lines.Add('此核对只读取现有 report.json，不启动样本、不连接虚拟机。`FAIL` 表示报告不能证明没有采集缺口；`WARN` 表示有回压、抑制或降级，需要继续修复。'); [void]$lines.Add('')
[void]$lines.Add('| 样本 | 状态 | 门禁 | 总事件 | 报告事件 | R0 原始 | R0 丢失 | ETW 丢失 | 失败行 | 回压 | 动态动作 | 持久化 | 文件 | 网络 |'); [void]$lines.Add('|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|')
foreach ($row in $rows) { [void]$lines.Add("| $($row.Sample) | $($row.Status) | **$($row.Gate)** | $(F $row.Total) | $(F $row.Inline) | $(F $row.R0Raw) | $(F $row.Lost) | $(F $row.ETWLost) | $(F $row.Failures) | $(F $row.Backpressure) | $(F $row.Dynamic) | $(F $row.Persistence) | $(F $row.File) | $(F $row.Network) |") }
[void]$lines.Add(''); [void]$lines.Add('## 每份报告必须继续核对'); [void]$lines.Add('')
foreach ($row in $rows) { [void]$lines.Add("- **$($row.Sample)**：$($row.Gate)；$($row.Why)"); if ($row.StateReasons) { [void]$lines.Add("  - 状态原因：$($row.StateReasons)") }; [void]$lines.Add("  - 原始报告：$($row.ReportPath)"); [void]$lines.Add("  - 原始事件：$(if ($row.RawPathOk) { '可追溯' } else { '缺失' })；raw=$($row.RawPath)；driver=$($row.DriverPath)") }
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
