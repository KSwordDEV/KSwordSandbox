using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Abstractions.Artifacts;
using KSword.Sandbox.Core.Reporting;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies that the HTML report renderer and UX documentation expose the
/// operator-facing sections needed for a live sandbox demo. Inputs are source
/// and docs files; processing performs static contract checks; the scenario
/// returns pass/fail metadata.
/// </summary>
internal sealed class ReportUxContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "report.ux.contract";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var rendererPath = Path.Combine(context.RepositoryRoot, "src", "KSword.Sandbox.Core", "Reporting", "HtmlReportRenderer.cs");
        var reportStagePath = Path.Combine(context.RepositoryRoot, "src", "KSword.Sandbox.Core", "Pipeline", "Stages", "ReportArtifactStage.cs");
        var analysisModelsPath = Path.Combine(context.RepositoryRoot, "src", "KSword.Sandbox.Abstractions", "AnalysisModels.cs");
        var docPath = Path.Combine(context.RepositoryRoot, "docs", "report-ux.md");

        SmokeAssert.True(File.Exists(rendererPath), "HTML report renderer is missing.");
        SmokeAssert.True(File.Exists(reportStagePath), "Report artifact stage is missing.");
        SmokeAssert.True(File.Exists(analysisModelsPath), "Analysis job model is missing.");
        SmokeAssert.True(File.Exists(docPath), "Report UX documentation is missing.");

        var rendererSource = File.ReadAllText(rendererPath);
        var reportStage = File.ReadAllText(reportStagePath);
        var analysisModels = File.ReadAllText(analysisModelsPath);
        var doc = File.ReadAllText(docPath);

        RequireContains(rendererSource, "AppendTimeline", "Report renderer should include a timeline section.");
        RequireContains(rendererSource, "BuildTimelineGroups", "Report renderer should group timeline events for stable visual scanning.");
        RequireContains(rendererSource, "timeline-group", "Report renderer should render grouped timeline buckets.");
        RequireContains(rendererSource, "TimelineEventInlineLimit = 120", "Report renderer should cap timeline rendering separately from raw events.");
        RequireContains(rendererSource, "EventFamilyLabel", "Report renderer should summarize timeline groups by event family.");
        RequireContains(rendererSource, "AppendProcessTree", "Report renderer should include a process tree.");
        RequireContains(rendererSource, "process-tree", "Report renderer should render a bounded stable process tree.");
        RequireContains(rendererSource, "Process relationship tree", "Report renderer should explain the process relationship tree.");
        RequireContains(rendererSource, "Process tree default expansion", "Report renderer should explain process tree default expansion.");
        RequireContains(rendererSource, "Process tree nodes", "Report renderer should expose process tree overview cards.");
        RequireContains(rendererSource, "Self-noise excluded", "Report renderer should explain process-tree self-noise exclusion.");
        RequireContains(rendererSource, "overview-strip", "Report renderer should expose flat overview panels for dense evidence.");
        RequireContains(rendererSource, "ProcessLookupKeys", "Report renderer should resolve process relationships with stable lookup keys.");
        RequireContains(rendererSource, "ParentProcessLookupKeys", "Report renderer should resolve parent process relationships with stable lookup keys.");
        RequireContains(rendererSource, "AppendBehaviorGraph", "Report renderer should include a behavior graph and IOC summary section.");
        RequireContains(rendererSource, "Behavior graph / IOC summary", "Report renderer should expose a graph/IOC section title.");
        RequireContains(rendererSource, "Evidence graph edges", "Report renderer should expose graph edge evidence.");
        RequireContains(rendererSource, "AppendEvidenceSummaryCards", "Report renderer should expose evidence summary cards.");
        RequireContains(rendererSource, "Evidence summary cards", "Report renderer should expose evidence summary cards title.");
        RequireContains(rendererSource, "AppendEvidenceStoryBoard", "Report renderer should expose a narrative evidence story board.");
        RequireContains(rendererSource, "Evidence story board", "Report renderer should expose the evidence story board title.");
        RequireContains(rendererSource, "Dropped-file evidence", "Report renderer should keep dropped-file story evidence visible.");
        RequireContains(rendererSource, "Screenshot evidence", "Report renderer should keep screenshot story evidence visible.");
        RequireContains(rendererSource, "Memory dump evidence", "Report renderer should keep memory dump story evidence visible.");
        RequireContains(rendererSource, "Network and PCAP evidence", "Report renderer should keep PCAP/network story evidence visible.");
        RequireContains(rendererSource, "R0 health/noise boundary", "Report renderer should keep R0 health/noise context visible.");
        RequireContains(rendererSource, "AppendArtifactCollectionStatusCards", "Report renderer should expose artifact collection status cards.");
        RequireContains(rendererSource, "Artifact collection status", "Report renderer should expose artifact collection status title.");
        RequireContains(rendererSource, "Dropped files", "Report renderer should summarize dropped-file collection status.");
        RequireContains(rendererSource, "Screenshots", "Report renderer should summarize screenshot collection status.");
        RequireContains(rendererSource, "Memory dumps", "Report renderer should summarize memory-dump collection status.");
        RequireContains(rendererSource, "Packet captures", "Report renderer should summarize packet-capture collection status.");
        RequireContains(rendererSource, "AppendTopBehaviorChain", "Report renderer should expose a bounded top behavior chain.");
        RequireContains(rendererSource, "Top behavior chain", "Report renderer should expose the top behavior chain title.");
        RequireContains(rendererSource, "behavior-chain", "Report renderer should style the top behavior chain as a bounded panel.");
        RequireContains(rendererSource, "IOC summary", "Report renderer should expose IOC summary cards.");
        RequireContains(rendererSource, "AppendProcessRelationshipCards", "Report renderer should expose process relationship cards.");
        RequireContains(rendererSource, "Process relationship cards", "Report renderer should expose process relationship card title.");
        RequireContains(rendererSource, "Stable relationship map", "Report renderer should expose a stable process relationship map.");
        RequireContains(rendererSource, "parentProcess=", "Report renderer should include parent process evidence in process cards.");
        RequireContains(rendererSource, "AppendNetworkRelationshipCards", "Report renderer should expose network relationship cards.");
        RequireContains(rendererSource, "Network relationship cards", "Report renderer should expose network relationship card title.");
        RequireContains(rendererSource, "Endpoint groups", "Report renderer should summarize endpoint relationship groups.");
        RequireContains(rendererSource, "Network category view", "Report renderer should explain DNS/HTTP/TLS/flow network lanes.");
        RequireContains(rendererSource, "relationship-details", "Report renderer should use bounded expandable evidence cards.");
        RequireContains(rendererSource, "Copy process card", "Report renderer should expose copyable process relationship cards.");
        RequireContains(rendererSource, "Copy network card", "Report renderer should expose copyable network relationship cards.");
        RequireContains(rendererSource, "tls.", "Report renderer should classify TLS events as network behavior.");
        RequireContains(rendererSource, "pcap.", "Report renderer should classify PCAP-derived events as network behavior.");
        RequireContains(rendererSource, "AppendRegistryBehavior", "Report renderer should include registry behavior.");
        RequireContains(rendererSource, "data-copy", "Report renderer should expose copyable evidence fields.");
        RequireContains(rendererSource, "contextmenu", "Report renderer should support right-click copy.");
        RequireContains(rendererSource, "Copy event", "Report renderer should provide explicit copy buttons.");
        RequireContains(rendererSource, "Raw normalized events", "Report renderer should include raw event evidence.");
        RequireContains(rendererSource, "RawEventInlineLimit = 75", "Report renderer should cap inline raw event rendering to a slim release-ready sample.");
        RequireContains(rendererSource, "RawEventPageSize = 25", "Report renderer should page inline raw events into compact bounded chunks.");
        RequireContains(rendererSource, "AppendRawEventPages", "Report renderer should render native raw event pages.");
        RequireContains(rendererSource, "raw-events-shell", "Report renderer should collapse raw events with native HTML.");
        RequireContains(rendererSource, "raw-events-panel", "Report renderer should bound expanded raw event height.");
        RequireContains(rendererSource, "Raw evidence height limit: 58vh", "Report renderer should state the raw evidence panel height limit.");
        RequireContains(rendererSource, "raw-event-page", "Report renderer should split expanded raw events into page panels.");
        RequireContains(rendererSource, "Raw event page index", "Report renderer should expose a static raw event page index.");
        RequireContains(rendererSource, "AppendRawEventPageIndex", "Report renderer should build a raw event page index.");
        RequireContains(rendererSource, "Index by event type", "Raw event index should group by event type.");
        RequireContains(rendererSource, "Index by source", "Raw event index should group by source.");
        RequireContains(rendererSource, "Index by event family", "Raw event index should group by event family.");
        RequireContains(rendererSource, "report.json only", "Raw event index should identify rows outside the inline cap.");
        RequireContains(rendererSource, "raw-technical-field", "Report renderer should hide long raw technical fields behind nested details.");
        RequireContains(rendererSource, "Command/stdout/stderr/PowerShell fields hidden by default", "Report renderer should collapse long command/output/script fields.");
        RequireContains(rendererSource, "Hidden raw events", "Report renderer should expose hidden raw event counts.");
        RequireContains(rendererSource, "report.json", "Report renderer should point operators to report.json.");
        RequireContains(rendererSource, "raw source artifacts", "Report renderer should point operators to raw source artifacts.");
        RequireContains(rendererSource, "#43A0FF", "Report renderer should use the required primary accent color.");
        RequireAnyContains(
            rendererSource,
            ["modern sandbox report", "modern-sandbox-report", "report-shell", "dashboard"],
            "Report renderer should expose a modern sandbox report layout.");
        RequireContainsNormalized(rendererSource, "max-height:75vh", "Major report sections should be bounded to around 75vh.");
        RequireContainsNormalized(rendererSource, "overflow:auto", "Major report sections should scroll overflowing evidence.");
        RequireContains(rendererSource, "section.card>h2", "Major report sections should expose sticky section headers.");
        RequireContains(rendererSource, "position:sticky", "Major report section headers should remain sticky while scrolling.");
        RequireContains(rendererSource, "artifact-btn", "Artifact links should render as operator-facing buttons.");
        RequireContains(rendererSource, "RenderSafeLinkActions", "Artifact links should share safe open/download button rendering.");
        RequireContains(rendererSource, "IsSafeReportRelativeHref", "Artifact hrefs should reject absolute paths and unsafe links.");
        RequireContains(rendererSource, "download=", "Artifact links should expose download buttons.");
        RequireAnyContains(
            rendererSource,
            ["report.zh.html", "report.en.html", "RenderChinese", "RenderEnglish", "zh-CN", "en-US"],
            "Report renderer should support Chinese and English report rendering entrypoints.");
        RequireContains(rendererSource, "report.zh.html", "Report renderer should include the report.zh.html output clue.");
        RequireContains(rendererSource, "report.en.html", "Report renderer should include the report.en.html output clue.");
        RequireContains(rendererSource, "RenderBilingualReports", "Report renderer should provide a bilingual report generation entrypoint.");
        RequireContains(rendererSource, "AppendLanguageEntrypoints", "Report renderer should expose in-report bilingual navigation links.");
        RequireContains(rendererSource, "Report language", "Report renderer should label the bilingual report entry bar.");
        RequireContains(rendererSource, "Default report.html uses Simplified Chinese", "Report renderer should explain the default Chinese compatibility report.");
        RequireContains(rendererSource, "R0 noise policy", "Report renderer should explain R0 health/self-noise separation.");
        RequireContains(rendererSource, "R0 availability", "Report renderer should summarize R0 health availability.");
        RequireContains(rendererSource, "R0 health evidence examples", "Report renderer should fold R0 health evidence examples.");
        RequireContains(rendererSource, "Driver network status / WFP-ALE", "Report renderer should surface R0 network status diagnostics.");
        RequireContains(rendererSource, "r0collector.driverNetworkStatus", "Report renderer should narrate R0 network status evidence.");
        RequireContains(rendererSource, "Static PE resource story", "Report renderer should expose structured PE resource evidence.");
        RequireContains(rendererSource, "resourceRole", "Report renderer should render static resource roles.");
        RequireContains(rendererSource, "Artifact index evidence", "Report renderer should explain artifact selector/duplicate/rejection diagnostics.");
        RequireContains(rendererSource, "Download selector / duplicate / rejection diagnostics", "Report renderer should expose artifact index row evidence.");
        RequireContains(rendererSource, "VirusTotal official evidence", "Report renderer should summarize VT official file-object fields.");
        RequireContains(rendererSource, "VT reputation/community", "Report renderer should expose VT reputation/community score.");
        RequireContains(rendererSource, "id=\\\"cover\\\"", "Report renderer should expose a cover anchor.");
        RequireContains(rendererSource, "id=\\\"toc\\\"", "Report renderer should expose a table-of-contents anchor.");
        RequireContains(analysisModels, "HtmlReportZhPath", "Analysis job model should have a Chinese HTML report path for automatic report links.");
        RequireContains(analysisModels, "HtmlReportEnPath", "Analysis job model should have an English HTML report path for automatic report links.");
        RequireContains(reportStage, "report.artifacts.write", "Report stage should expose a stable progress stage id.");
        RequireContains(reportStage, "Write report artifacts", "Report stage should expose an operator-facing progress title.");
        RequireContains(reportStage, "report.html", "Report stage should keep writing the default report.html artifact.");

        RequireContains(doc, "Timeline", "Report UX doc should list the timeline section.");
        RequireContains(doc, "timeline grouping", "Report UX doc should require timeline grouping.");
        RequireContains(doc, "bounded timeline", "Report UX doc should require bounded timeline rendering.");
        RequireContains(doc, "Behavior graph / IOC summary", "Report UX doc should list the behavior graph section.");
        RequireContains(doc, "Evidence story board", "Report UX doc should require evidence storytelling lanes.");
        RequireContains(doc, "Evidence graph edges", "Report UX doc should require graph edge evidence.");
        RequireContains(doc, "Artifact collection status", "Report UX doc should require artifact collection status cards.");
        RequireContains(doc, "Top behavior chain", "Report UX doc should require a top behavior chain.");
        RequireContains(doc, "IOC summary", "Report UX doc should require IOC summary cards.");
        RequireContains(doc, "Process tree", "Report UX doc should list the process tree.");
        RequireContains(doc, "process relationship tree", "Report UX doc should require a stable process relationship tree.");
        RequireContains(doc, "stable process key", "Report UX doc should require stable process key fallback behavior.");
        RequireContains(doc, "Process tree overview", "Report UX doc should require process tree overview panels.");
        RequireContains(doc, "self-noise excluded", "Report UX doc should document process tree self-noise exclusion.");
        RequireContains(doc, "Registry behavior", "Report UX doc should list registry behavior.");
        RequireContains(doc, "Right-click", "Report UX doc should describe right-click copy.");
        RequireContains(doc, "raw events only", "Report UX doc should distinguish live raw events from final classification.");
        RequireContains(doc, "first 75 raw events", "Report UX doc should require a slim raw event inline limit.");
        RequireContains(doc, "25-row native pages", "Report UX doc should require compact bounded raw event pages.");
        RequireContains(doc, "Raw evidence height limit", "Report UX doc should require a raw evidence height limit.");
        RequireContains(doc, "Raw event page index", "Report UX doc should require a static raw event page index.");
        RequireContains(doc, "copyable row ranges", "Report UX doc should require copyable row ranges.");
        RequireContains(doc, "hidden raw events", "Report UX doc should require hidden raw event counts.");
        RequireContains(doc, "report.json", "Report UX doc should require report.json source hints.");
        RequireContains(doc, "raw source artifact path hints", "Report UX doc should require raw source path hints.");
        RequireContains(doc, "native HTML/CSS", "Report UX doc should keep raw event expansion independent of JavaScript.");
        RequireContains(doc, "#43A0FF", "Report UX doc should specify the report primary accent color.");
        RequireContains(doc, "modern sandbox report layout", "Report UX doc should require the modern sandbox report layout.");
        RequireContains(doc, "75vh", "Report UX doc should specify bounded major report section height.");
        RequireContains(doc, "overflow:auto", "Report UX doc should specify scrolling major report sections.");
        RequireContains(doc, "sticky section header", "Report UX doc should require sticky section headers.");
        RequireContains(doc, "Open/Download", "Report UX doc should require artifact open/download buttons.");
        RequireContains(doc, "must not be used as `href`", "Report UX doc should forbid absolute local paths as href values.");
        RequireContains(doc, "command/stdout/stderr/PowerShell", "Report UX doc should require long technical raw fields to stay folded.");
        RequireContains(doc, "Chinese and English", "Report UX doc should require Chinese and English report rendering support.");
        RequireContains(doc, "bilingual entry bar", "Report UX doc should require stable in-report bilingual entry links.");
        RequireContains(doc, "default Simplified Chinese compatibility report", "Report UX doc should describe report.html default language.");
        RequireContains(doc, "R0 availability", "Report UX doc should require R0 availability summaries.");
        RequireContains(doc, "Network category view", "Report UX doc should require network category summaries.");
        RequireContains(doc, "report.zh.html", "Report UX doc should mention report.zh.html.");
        RequireContains(doc, "report.en.html", "Report UX doc should mention report.en.html.");
        RequireContains(doc, "/api/jobs/{jobId}/report/html?lang=zh", "Report UX doc should describe the Chinese served report endpoint validation.");
        RequireContains(doc, "/api/jobs/{jobId}/report/html?lang=en", "Report UX doc should describe the English served report endpoint validation.");
        RequireContains(doc, "Cover / 封面", "Report UX doc should list the cover section.");
        RequireContains(doc, "Table of contents / 目录", "Report UX doc should list the table of contents section.");
        RequireContains(doc, "Behavior detections / 行为命中", "Report UX doc should list behavior hits.");
        RequireContains(doc, "R0 / driver events", "Report UX doc should list R0 driver events.");
        RequireContains(doc, "Raw normalized events / 原始事件", "Report UX doc should list raw events.");

        RequireRenderedReportContract();

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Report UX sections and copyable evidence contracts are present."
        });
    }

    /// <summary>
    /// Requires a text fragment to be present. Inputs are content, expected
    /// text, and failure message; processing throws on absence; return value is
    /// none.
    /// </summary>
    private static void RequireContains(string content, string expected, string message)
    {
        SmokeAssert.True(content.Contains(expected, StringComparison.Ordinal), message);
    }

    /// <summary>
    /// Requires a text fragment to be absent. Inputs are content, unexpected
    /// text, and failure message; processing throws on presence; return value
    /// is none.
    /// </summary>
    private static void RequireNotContains(string content, string unexpected, string message)
    {
        SmokeAssert.True(!content.Contains(unexpected, StringComparison.Ordinal), message);
    }

    /// <summary>
    /// Requires one of several text fragments to be present. Inputs are content,
    /// expected alternatives, and failure message; processing throws on absence;
    /// return value is none.
    /// </summary>
    private static void RequireAnyContains(string content, IReadOnlyCollection<string> expectedAny, string message)
    {
        SmokeAssert.True(expectedAny.Any(expected => content.Contains(expected, StringComparison.Ordinal)), message);
    }

    /// <summary>
    /// Requires a CSS-like fragment to be present after whitespace removal.
    /// Inputs are content, expected normalized text, and failure message;
    /// processing throws on absence; return value is none.
    /// </summary>
    private static void RequireContainsNormalized(string content, string expected, string message)
    {
        var normalized = new string(content.Where(c => !char.IsWhiteSpace(c)).ToArray());
        SmokeAssert.True(normalized.Contains(expected, StringComparison.Ordinal), message);
    }

    /// <summary>
    /// Requires one fragment to appear before another. Inputs are rendered HTML
    /// and two stable fragments; processing compares ordinal positions; return
    /// value is none.
    /// </summary>
    private static void RequireBefore(string content, string first, string second, string message)
    {
        var firstIndex = content.IndexOf(first, StringComparison.Ordinal);
        var secondIndex = content.IndexOf(second, StringComparison.Ordinal);
        SmokeAssert.True(firstIndex >= 0 && secondIndex >= 0 && firstIndex < secondIndex, message);
    }

    /// <summary>
    /// Renders synthetic English and Chinese reports to verify the UX contract
    /// against emitted HTML rather than source strings only. Inputs are none;
    /// processing builds a deterministic report model and checks required
    /// section anchors, bilingual filenames, accent color, bounded cards, and
    /// localized labels; the method returns no value on success.
    /// </summary>
    private static void RequireRenderedReportContract()
    {
        var report = BuildContractReport();
        var artifacts = BuildContractArtifacts();
        var renderer = new HtmlReportRenderer();
        var defaultHtml = renderer.Render(report, artifacts);
        var englishHtml = renderer.RenderEnglish(report, artifacts);
        var chineseHtml = renderer.RenderChinese(report, artifacts);
        var documents = renderer.RenderBilingualReports(report, artifacts);
        var totalRawEvents = report.Events.Count;
        var hiddenRawEvents = Math.Max(0, totalRawEvents - 75);

        RequireContains(defaultHtml, "<html lang=\"zh-CN\">", "Default rendered HTML should use the Simplified Chinese compatibility report.");
        RequireContains(defaultHtml, "href=\"report.zh.html\"", "Default rendered HTML should link to report.zh.html.");
        RequireContains(defaultHtml, "href=\"report.en.html\"", "Default rendered HTML should link to report.en.html.");
        RequireContains(englishHtml, "#43A0FF", "Rendered HTML should include the required bright-blue accent color.");
        RequireContainsNormalized(englishHtml, "max-height:75vh", "Rendered major sections should be bounded to around 75vh.");
        RequireContainsNormalized(englishHtml, "overflow:auto", "Rendered major sections should scroll overflowing evidence.");
        RequireContains(englishHtml, "section.card>h2", "Rendered CSS should include sticky section header selectors.");
        RequireContains(englishHtml, "position:sticky", "Rendered major section headers should be sticky.");
        RequireContains(englishHtml, "href=\"report.zh.html\"", "Rendered HTML should link to report.zh.html.");
        RequireContains(englishHtml, "href=\"report.en.html\"", "Rendered HTML should link to report.en.html.");
        RequireContains(englishHtml, $"<details class=\"raw-events-shell\"><summary>Show inline raw events (75/{totalRawEvents}; {hiddenRawEvents} hidden)</summary>", "Rendered raw events should be collapsed and capped.");
        RequireContains(englishHtml, "Inline pages", "Rendered raw event overview should show page counts.");
        RequireContains(englishHtml, $"Raw event page 1: rows 1-25 of {totalRawEvents}", "Rendered raw event panel should show the first native page.");
        RequireContains(englishHtml, $"Raw event page 3: rows 51-75 of {totalRawEvents}", "Rendered raw event panel should show the final inline page.");
        RequireContains(englishHtml, "raw-event-page", "Rendered raw event panel should use bounded page containers.");
        RequireContains(englishHtml, "Raw event page index", "Rendered raw event overview should include a static page index.");
        RequireContains(englishHtml, "Index by event type", "Rendered raw event index should include event type grouping.");
        RequireContains(englishHtml, "Index by source", "Rendered raw event index should include source grouping.");
        RequireContains(englishHtml, "Index by event family", "Rendered raw event index should include family grouping.");
        RequireContains(englishHtml, "report.json only", "Rendered raw event index should point beyond inline rows to report.json.");
        RequireContains(englishHtml, "Total events", "Rendered raw event overview should show the total count label.");
        RequireContains(englishHtml, "Hidden raw events", "Rendered raw event overview should show the hidden count label.");
        RequireContains(englishHtml, "Raw source paths", "Rendered raw event section should show source path hints.");
        RequireContains(englishHtml, "report.json", "Rendered raw event section should link or hint report.json.");
        RequireContains(englishHtml, "No raw source artifacts were indexed; report.json remains the complete normalized source.", "Rendered raw source hints should explain missing raw artifacts.");
        RequireContains(englishHtml, "class=\"artifact-btn artifact-open\" href=\"artifacts/contract-drop.bin\"", "Rendered artifact links should expose a safe Open button.");
        RequireContains(englishHtml, "class=\"artifact-btn download\" href=\"artifacts/contract-drop.bin\" download=\"contract-drop.bin\"", "Rendered artifact links should expose a safe Download button.");
        RequireContains(englishHtml, "Host/local path (copy only)", "Rendered artifact full paths should be copy-only text evidence.");
        RequireNotContains(englishHtml, "href=\"D:\\", "Rendered HTML must not expose local absolute Windows paths as href values.");
        RequireNotContains(englishHtml, "href=\"C:\\", "Rendered HTML must not expose guest/local absolute Windows paths as href values.");
        RequireNotContains(englishHtml, "file://", "Rendered HTML must not expose file:// artifact hrefs.");
        RequireContains(englishHtml, "Command line hidden by default", "Rendered event rows should fold command lines by default.");
        RequireContains(englishHtml, "Command/stdout/stderr/PowerShell fields hidden by default", "Rendered raw event details should fold long technical fields.");
        RequireContains(englishHtml, "Hidden technical field: stdout", "Rendered raw event details should hide stdout fields.");
        RequireContains(englishHtml, "Hidden technical field: powershellCommand", "Rendered raw event details should hide PowerShell fields.");
        RequireContains(englishHtml, "<details class=\"raw-technical-field\"><summary>Hidden technical field: stderr", "Rendered raw event details should keep stderr in copyable details.");
        RequireNotContains(englishHtml, "<br><span class=\"muted\">cmd.exe /c whoami</span>", "Rendered event tables should not inline command lines directly.");
        RequireContains(englishHtml, "<section id=\"graph\" class=\"card\"><h2>Behavior graph / IOC summary</h2>", "Rendered HTML should include the behavior graph section.");
        RequireContains(englishHtml, "Evidence graph edges", "Rendered HTML should include graph edge evidence.");
        RequireContains(englishHtml, "Top behavior chain", "Rendered HTML should include the top behavior chain.");
        RequireContains(englishHtml, "behavior-chain", "Rendered HTML should style the top behavior chain.");
        RequireContains(englishHtml, "contract-sample.exe pid:4242 --network--&gt; 203.0.113.10:443", "Rendered behavior chain should include the sample network edge.");
        RequireContains(englishHtml, "id=\"evidence-summary-cards\"", "Rendered HTML should include evidence summary card anchor.");
        RequireContains(englishHtml, "Evidence summary cards", "Rendered HTML should include evidence summary cards.");
        RequireContains(englishHtml, "id=\"evidence-story-board\"", "Rendered HTML should include evidence story board anchor.");
        RequireContains(englishHtml, "Evidence story board", "Rendered HTML should include evidence story board.");
        RequireContains(englishHtml, "Dropped-file evidence", "Rendered HTML should include dropped-file story evidence.");
        RequireContains(englishHtml, "Screenshot evidence", "Rendered HTML should include screenshot story evidence.");
        RequireContains(englishHtml, "Memory dump evidence", "Rendered HTML should include memory dump story evidence.");
        RequireContains(englishHtml, "Network and PCAP evidence", "Rendered HTML should include network/PCAP story evidence.");
        RequireContains(englishHtml, "R0 health/noise boundary", "Rendered HTML should include R0 health/noise story evidence.");
        RequireContains(englishHtml, "Driver network status / WFP-ALE", "Rendered HTML should include R0 WFP/ALE network status.");
        RequireContains(englishHtml, "Network status availability", "Rendered HTML should include R0 network availability cards.");
        RequireContains(englishHtml, "r0collector.driverNetworkStatus", "Rendered HTML should expose copyable R0 network status evidence.");
        RequireContains(englishHtml, "Static PE resource story", "Rendered HTML should include structured static resource story.");
        RequireContains(englishHtml, "embedded-pe", "Rendered HTML should include static resourceRole evidence.");
        RequireContains(englishHtml, "Artifact index evidence", "Rendered HTML should include artifact selector/duplicate/rejection cards.");
        RequireContains(englishHtml, "Download selector / duplicate / rejection diagnostics", "Rendered artifact rows should expose index diagnostics.");
        RequireContains(englishHtml, "Rejected artifact references", "Rendered artifact index story should summarize rejection diagnostics.");
        RequireContains(englishHtml, "VirusTotal official evidence", "Rendered HTML should include VT official evidence cards.");
        RequireContains(englishHtml, "VT reputation/community", "Rendered HTML should include VT reputation/community fields.");
        RequireContains(englishHtml, "https://www.virustotal.com/gui/file/", "Rendered HTML should include copyable VT permalink evidence.");
        RequireContains(englishHtml, "Artifact collection status", "Rendered HTML should include artifact collection status cards.");
        RequireContains(englishHtml, "Dropped files", "Rendered HTML should include dropped-file status card.");
        RequireContains(englishHtml, "Screenshots", "Rendered HTML should include screenshot status card.");
        RequireContains(englishHtml, "Memory dumps", "Rendered HTML should include memory-dump status card.");
        RequireContains(englishHtml, "Packet captures", "Rendered HTML should include packet-capture status card.");
        RequireContains(englishHtml, "IOC summary", "Rendered HTML should include IOC summary cards.");
        RequireContains(englishHtml, "Network IOCs", "Rendered HTML should include network IOC cards.");
        RequireContains(englishHtml, "id=\"process-relationship-cards\"", "Rendered HTML should include process relationship card anchor.");
        RequireContains(englishHtml, "Process relationship cards", "Rendered HTML should include process relationship cards.");
        RequireContains(englishHtml, "Copy process card", "Rendered HTML should include copyable process relationship cards.");
        RequireContains(englishHtml, "id=\"network-relationship-cards\"", "Rendered HTML should include network relationship card anchor.");
        RequireContains(englishHtml, "Network relationship cards", "Rendered HTML should include network relationship cards.");
        RequireContains(englishHtml, "Copy network card", "Rendered HTML should include copyable network relationship cards.");
        RequireContains(englishHtml, "Endpoint-centric view.", "Rendered HTML should include cloud-sandbox-style network relationship guidance.");
        RequireContains(englishHtml, "Network category view.", "Rendered HTML should include network category guidance.");
        RequireContains(englishHtml, "Endpoint groups", "Rendered HTML should include endpoint overview cards.");
        RequireContains(englishHtml, "DNS / HTTP / TLS", "Rendered HTML should include protocol category counts.");
        RequireContains(englishHtml, "<section id=\"timeline\" class=\"card\"><h2>Timeline</h2>", "Rendered HTML should include the timeline section.");
        RequireContains(englishHtml, "Timeline grouping.", "Rendered HTML should explain timeline grouping.");
        RequireContains(englishHtml, "timeline-group", "Rendered HTML should include grouped timeline buckets.");
        RequireContains(englishHtml, "Event families:", "Rendered timeline groups should summarize event families.");
        RequireContains(englishHtml, "Process relationship tree.", "Rendered HTML should explain stable process tree rendering.");
        RequireContains(englishHtml, "Process tree nodes", "Rendered HTML should include process-tree overview cards.");
        RequireContains(englishHtml, "High-signal nodes", "Rendered HTML should include high-signal process overview cards.");
        RequireContains(englishHtml, "Self-noise excluded", "Rendered HTML should include process self-noise exclusion summary.");
        RequireContains(englishHtml, "process-tree-node", "Rendered HTML should include expandable process tree nodes.");
        RequireContains(englishHtml, "launcher.exe pid:4100 ppid:-", "Rendered process tree should include the launcher root.");
        RequireContains(englishHtml, "contract-sample.exe pid:4242 ppid:4100", "Rendered process tree should include the sample child.");
        RequireContains(englishHtml, "cmd.exe pid:4243 ppid:4242", "Rendered process tree should include the command child.");
        RequireContains(englishHtml, "Children: 1", "Rendered process relationship card should aggregate child count.");
        RequireContains(englishHtml, "Files: 1", "Rendered process relationship card should aggregate file count.");
        RequireContains(englishHtml, "Registry: 1", "Rendered process relationship card should aggregate registry count.");
        RequireContains(englishHtml, "Network: 1", "Rendered process relationship card should aggregate network count.");
        RequireContains(englishHtml, "Stable relationship map", "Rendered process relationship card should include stable relationship map details.");
        RequireContains(englishHtml, "parentProcess=launcher.exe pid:4100", "Rendered process card copy text should include parent process evidence.");
        RequireContains(englishHtml, "child=cmd.exe pid:4243", "Rendered process card relationship map should include child process evidence.");
        RequireBefore(englishHtml, "launcher.exe pid:4100 ppid:-", "contract-sample.exe pid:4242 ppid:4100", "Rendered process lineage should show parent before child.");
        RequireBefore(englishHtml, "contract-sample.exe pid:4242 ppid:4100", "cmd.exe pid:4243 ppid:4242", "Rendered process lineage should show sample before spawned child.");
        RequireContains(englishHtml, "R0 noise policy.", "Rendered R0 section should explain health/self-noise separation.");
        RequireContains(englishHtml, "R0 availability", "Rendered R0 section should include availability overview.");
        RequireContains(englishHtml, "No R0 health rows", "Rendered R0 section should distinguish absent health rows from driver telemetry.");
        RequireContains(englishHtml, "Raw evidence height limit: 58vh", "Rendered raw section should state the raw evidence height limit.");
        RequireContains(englishHtml, "Default report.html uses Simplified Chinese", "Rendered language bar should explain the default compatibility report.");

        foreach (var expected in RequiredEnglishSectionFragments())
        {
            RequireContains(englishHtml, expected, $"Rendered English report should include {expected}.");
        }

        RequireContains(chineseHtml, "<html lang=\"zh-CN\">", "Chinese HTML should set the zh-CN language metadata.");
        RequireContains(chineseHtml, "时间线分组", "Chinese HTML should localize timeline grouping guidance.");
        RequireContains(chineseHtml, "进程关系树", "Chinese HTML should localize process relationship tree guidance.");
        RequireContains(chineseHtml, "进程树节点", "Chinese HTML should localize process-tree overview cards.");
        RequireContains(chineseHtml, "R0 可用性", "Chinese HTML should localize R0 availability.");
        RequireContains(chineseHtml, "端点分组", "Chinese HTML should localize network endpoint overview cards.");
        RequireContains(chineseHtml, "证据故事板", "Chinese HTML should localize evidence story board.");
        RequireContains(chineseHtml, "落地文件证据", "Chinese HTML should localize dropped-file story evidence.");
        RequireContains(chineseHtml, "截图证据", "Chinese HTML should localize screenshot story evidence.");
        RequireContains(chineseHtml, "内存转储证据", "Chinese HTML should localize memory dump story evidence.");
        RequireContains(chineseHtml, "网络与 PCAP 证据", "Chinese HTML should localize network/PCAP story evidence.");
        RequireContains(chineseHtml, "原始证据高度限制", "Chinese HTML should localize raw evidence height guidance.");
        RequireContains(chineseHtml, "默认 report.html 使用简体中文", "Chinese HTML should localize the bilingual default-report hint.");
        RequireContains(chineseHtml, "打开", "Chinese HTML should localize artifact open buttons.");
        RequireContains(chineseHtml, "下载", "Chinese HTML should localize artifact download buttons.");
        RequireContains(chineseHtml, "命令行默认隐藏", "Chinese HTML should localize folded command-line details.");
        foreach (var expected in RequiredChineseSectionLabels())
        {
            RequireContains(chineseHtml, expected, $"Rendered Chinese report should include {expected}.");
        }

        SmokeAssert.True(
            documents.Any(document =>
                string.Equals(document.FileName, "report.en.html", StringComparison.OrdinalIgnoreCase) &&
                document.Language == HtmlReportLanguage.English &&
                string.Equals(document.CultureName, "en-US", StringComparison.Ordinal)),
            "Bilingual render output should include report.en.html with en-US metadata.");
        SmokeAssert.True(
            documents.Any(document =>
                string.Equals(document.FileName, "report.zh.html", StringComparison.OrdinalIgnoreCase) &&
                document.Language == HtmlReportLanguage.ChineseSimplified &&
                string.Equals(document.CultureName, "zh-CN", StringComparison.Ordinal)),
            "Bilingual render output should include report.zh.html with zh-CN metadata.");
    }

    /// <summary>
    /// Returns exact emitted English section fragments that represent the
    /// report's required major chapters. Inputs are none; processing returns
    /// stable substrings from rendered HTML; the caller checks each fragment.
    /// </summary>
    private static IReadOnlyList<string> RequiredEnglishSectionFragments() =>
    [
        "<header id=\"cover\">",
        "<nav id=\"toc\" class=\"card toc\"><h2>Table of contents</h2>",
        "<section id=\"risk\" class=\"card\"><h2>Risk summary</h2>",
        "<section id=\"behavior\" class=\"card\"><h2>Behavior detections</h2>",
        "<section id=\"mitre\" class=\"card\"><h2>Multi-dimensional / MITRE detections</h2>",
        "<section id=\"static\" class=\"card\"><h2>Static analysis</h2>",
        "<section id=\"dynamic\" class=\"card\"><h2>Dynamic analysis</h2>",
        "<section id=\"graph\" class=\"card\"><h2>Behavior graph / IOC summary</h2>",
        "<section id=\"artifacts\" class=\"card\"><h2>Artifact links</h2>",
        "<section id=\"timeline\" class=\"card\"><h2>Timeline</h2>",
        "<section id=\"process\" class=\"card\"><h2>Process details</h2>",
        "<section id=\"files\" class=\"card\"><h2>File system activity</h2>",
        "<section id=\"registry\" class=\"card\"><h2>Registry behavior</h2>",
        "<section id=\"network\" class=\"card\"><h2>Network behavior</h2>",
        "<section id=\"r0\" class=\"card\"><h2>R0 / driver events</h2>",
        "<section id=\"failure\" class=\"card\"><h2>Failure reasons</h2>",
        "<section id=\"events\" class=\"card\"><h2>Raw normalized events</h2>"
    ];

    /// <summary>
    /// Returns localized labels required in the Chinese report. Inputs are
    /// none; processing returns stable shell labels that should appear after
    /// localization; the caller checks each label.
    /// </summary>
    private static IReadOnlyList<string> RequiredChineseSectionLabels() =>
    [
        "封面",
        "目录",
        "风险摘要",
        "行为命中",
        "多维 / MITRE 检测",
        "静态分析",
        "动态分析",
        "行为图谱 / IOC 摘要",
        "证据故事板",
        "时间线",
        "关键行为链",
        "证据摘要卡",
        "证据采集状态",
        "进程详情",
        "进程关系卡",
        "文件系统活动",
        "落地文件",
        "注册表行为",
        "网络行为",
        "网络关系卡",
        "R0 / 驱动事件",
        "失败原因",
        "原始事件",
        "原始事件页"
    ];

    /// <summary>
    /// Builds deterministic artifact descriptors for rendered UX checks.
    /// Inputs are none; processing includes an unsafe absolute safeLink with a
    /// safe relative path fallback; the method returns artifact descriptors
    /// used to prove buttons never href local absolute paths.
    /// </summary>
    private static IReadOnlyList<ArtifactDescriptor> BuildContractArtifacts() =>
    [
        new ArtifactDescriptor
        {
            Kind = ArtifactKind.DroppedFile,
            Category = "dropped-file",
            Name = "contract-drop.bin",
            RelativePath = "artifacts/contract-drop.bin",
            FullPath = @"D:\Jobs\11111111222233334444555555555555\artifacts\contract-drop.bin",
            SafeLink = @"D:\Jobs\11111111222233334444555555555555\artifacts\contract-drop.bin",
            MimeType = "application/octet-stream",
            SizeBytes = 128,
            Sha256 = new string('d', 64),
            Metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["evidenceRole"] = "dropped-file",
                ["downloadSelector"] = "artifacts/contract-drop.bin",
                ["safeRelativeSelector"] = "artifacts/contract-drop.bin",
                ["duplicateGroupKey"] = "sha256:" + new string('d', 64),
                ["duplicateGroupId"] = "duplicate-contract-drop",
                ["duplicateGroupCount"] = "2",
                ["duplicateOrdinal"] = "1",
                ["isDuplicate"] = "true",
                ["duplicatePrimarySelector"] = "artifacts/primary-contract-drop.bin",
                ["duplicateOfArtifactRelativePath"] = "artifacts/primary-contract-drop.bin",
                ["rejectionDiagnosticsAvailable"] = "true",
                ["rejectedArtifactCount"] = "1",
                ["lastRejectedArtifactSelector"] = "../unsafe.bin",
                ["artifactRejectionReasons"] = "unsafeGuestArtifactPath"
            }
        }
    ];

    /// <summary>
    /// Builds a deterministic report with one event in every dynamic chapter.
    /// Inputs are none; processing creates synthetic sample, static, finding,
    /// process, file, registry, network, R0, and failure evidence; the method
    /// returns the report model for HTML rendering checks.
    /// </summary>
    private static AnalysisReport BuildContractReport()
    {
        var timestamp = new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero);
        var launcherEvent = new SandboxEvent
        {
            EventType = "process.start",
            Timestamp = timestamp.AddSeconds(-2),
            Source = "guest",
            ProcessName = "launcher.exe",
            ProcessId = 4100,
            Path = @"C:\Windows\explorer.exe",
            CommandLine = @"C:\Windows\explorer.exe"
        };
        var processEvent = new SandboxEvent
        {
            EventType = "process.start",
            Timestamp = timestamp,
            Source = "guest",
            ProcessName = "contract-sample.exe",
            ProcessId = 4242,
            ParentProcessId = 4100,
            Path = @"C:\Samples\contract-sample.exe",
            CommandLine = @"C:\Samples\contract-sample.exe --contract"
        };
        var childProcessEvent = new SandboxEvent
        {
            EventType = "process.start",
            Timestamp = timestamp.AddMilliseconds(500),
            Source = "guest",
            ProcessName = "cmd.exe",
            ProcessId = 4243,
            ParentProcessId = 4242,
            Path = @"C:\Windows\System32\cmd.exe",
            CommandLine = @"cmd.exe /c whoami",
            Data =
            {
                ["powershellCommand"] = "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand SQBFAFgA",
                ["stdout"] = "contract-user output that should stay folded instead of filling the main report",
                ["stderr"] = "synthetic stderr that should stay folded"
            }
        };
        var fileEvent = new SandboxEvent
        {
            EventType = "file.created",
            Timestamp = timestamp.AddSeconds(1),
            Source = "guest",
            ProcessName = "contract-sample.exe",
            ProcessId = 4242,
            Path = @"C:\Users\Public\drop.bin"
        };
        var registryEvent = new SandboxEvent
        {
            EventType = "registry.set",
            Timestamp = timestamp.AddSeconds(2),
            Source = "guest",
            ProcessName = "contract-sample.exe",
            ProcessId = 4242,
            Path = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Contract"
        };
        var networkEvent = new SandboxEvent
        {
            EventType = "network.tcp",
            Timestamp = timestamp.AddSeconds(3),
            Source = "guest",
            ProcessName = "contract-sample.exe",
            ProcessId = 4242,
            Data =
            {
                ["remoteAddress"] = "203.0.113.10",
                ["remotePort"] = "443"
            }
        };
        var r0Event = new SandboxEvent
        {
            EventType = "driver.file.create",
            Timestamp = timestamp.AddSeconds(4),
            Source = "driver",
            Path = @"C:\Users\Public\r0-drop.bin",
            Data =
            {
                ["driverEventPath"] = "driver-events.jsonl"
            }
        };
        var r0NetworkStatusEvent = new SandboxEvent
        {
            EventType = "r0collector.driverNetworkStatus",
            Timestamp = timestamp.AddSeconds(4.5),
            Source = "r0collector",
            Data =
            {
                ["networkStatusAvailable"] = "true",
                ["readinessState"] = "available",
                ["supportedLayerMaskHex"] = "0x0000000F",
                ["activeLayerMaskHex"] = "0x00000007",
                ["lastRegisteredCalloutMaskHex"] = "0x00000007",
                ["lastAddedFilterMaskHex"] = "0x00000007",
                ["todoMaskHex"] = "0x00000008",
                ["classifyCount"] = "12",
                ["eventCount"] = "6",
                ["queueFailureCount"] = "0",
                ["classifyPayloadFailureCount"] = "0",
                ["lastDegradeReasonName"] = "wfpAleConnectTodo"
            }
        };
        var staticResourceEvent = new SandboxEvent
        {
            EventType = "static.pe.resource",
            Timestamp = timestamp.AddSeconds(4.6),
            Source = "host",
            Path = @"D:\Samples\contract-sample.exe",
            Data =
            {
                ["resourceType"] = "RCDATA",
                ["resourceRole"] = "embedded-pe",
                ["isEmbeddedPe"] = "True",
                ["isPayloadCandidate"] = "True",
                ["entropy"] = "7.850",
                ["entropyLabel"] = "high",
                ["size"] = "4096"
            }
        };
        var vtEvent = new SandboxEvent
        {
            EventType = "enrichment.virustotal.lookup",
            Timestamp = timestamp.AddSeconds(4.7),
            Source = "virustotal",
            Path = "https://www.virustotal.com/gui/file/" + new string('a', 64),
            Data =
            {
                ["vtStatus"] = "found",
                ["status"] = "found",
                ["vtVerdict"] = "malicious",
                ["verdict"] = "malicious",
                ["vtMalicious"] = "3",
                ["vtSuspicious"] = "1",
                ["vtHarmless"] = "59",
                ["vtUndetected"] = "8",
                ["vtEngineCount"] = "71",
                ["vtReputation"] = "-12",
                ["vtCommunityScore"] = "-2",
                ["communityScoreSource"] = "reputation",
                ["vtCommunityHarmlessVotes"] = "1",
                ["vtCommunityMaliciousVotes"] = "3",
                ["vtCommunityVoteCount"] = "4",
                ["lastAnalysisDateUtc"] = "2026-01-01T00:00:00.0000000Z",
                ["permalink"] = "https://www.virustotal.com/gui/file/" + new string('a', 64)
            }
        };
        var failureEvent = new SandboxEvent
        {
            EventType = "analysis.timeout",
            Timestamp = timestamp.AddSeconds(5),
            Source = "host",
            Data =
            {
                ["reason"] = "contract timeout evidence"
            }
        };
        var events = new List<SandboxEvent> { launcherEvent, processEvent, childProcessEvent, fileEvent, registryEvent, networkEvent, r0Event, r0NetworkStatusEvent, staticResourceEvent, vtEvent, failureEvent };
        for (var index = 0; index < 205; index++)
        {
            events.Add(new SandboxEvent
            {
                EventType = $"contract.raw.{index:D3}",
                Timestamp = timestamp.AddSeconds(10 + index),
                Source = "guest",
                ProcessName = "contract-sample.exe",
                ProcessId = 4242,
                Data =
                {
                    ["index"] = index.ToString(),
                    ["rawSource"] = "events.json"
                }
            });
        }

        return new AnalysisReport
        {
            JobId = Guid.Parse("11111111-2222-3333-4444-555555555555"),
            GeneratedAt = timestamp,
            Status = AnalysisStatus.Failed,
            Sample = new SampleIdentity
            {
                FileName = "contract-sample.exe",
                FullPath = @"D:\Samples\contract-sample.exe",
                Sha256 = new string('a', 64),
                Sha1 = new string('b', 40),
                Md5 = new string('c', 32),
                Crc32 = "1234abcd",
                SizeBytes = 4096
            },
            StaticAnalysis = new StaticAnalysisResult
            {
                FileFormat = "PE32+",
                Magic = "MZ",
                IsPe = true,
                Architecture = "x64",
                Subsystem = "Windows GUI",
                EntryPointRva = "0x1000",
                SectionCount = 1,
                Sections =
                [
                    new PeSectionInfo
                    {
                        Name = ".text",
                        VirtualAddress = "0x1000",
                        VirtualSize = 4096,
                        RawDataSize = 2048,
                        Entropy = 6.2
                    }
                ],
                Resources =
                [
                    new PeResourceInfo
                    {
                        ResourceType = "RCDATA",
                        DataRva = "0x00004000",
                        DataFileOffset = "0x00002000",
                        Size = 4096,
                        Entropy = 7.85,
                        EntropyLabel = "high",
                        IsPayloadCandidate = true,
                        IsEmbeddedPe = true,
                        IsLarge = true,
                        Tags = ["resource_high_entropy_data", "resource_embedded_pe"]
                    }
                ],
                Tags = ["contract-tag"],
                Urls = ["https://example.invalid/contract"],
                InterestingStrings =
                [
                    "import:kernel32.dll!CreateFileW",
                    @"registry-path:HKCU\Software\Contract"
                ],
                Warnings = ["synthetic warning"]
            },
            Events = events,
            Findings =
            [
                new BehaviorFinding
                {
                    RuleId = "contract-behavior-hit",
                    Title = "Synthetic behavior hit",
                    Severity = "medium",
                    MitreTechniqueId = "T1059",
                    MitreTechniqueName = "Command and Scripting Interpreter",
                    Summary = "Synthetic behavior evidence for report UX contract.",
                    Evidence = [processEvent]
                }
            ],
            Metrics = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
            {
                ["events.total"] = events.Count
            }
        };
    }
}
