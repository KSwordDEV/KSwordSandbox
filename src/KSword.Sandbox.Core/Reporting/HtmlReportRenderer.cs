using System.Net;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Abstractions.Artifacts;
using KSword.Sandbox.Core.Artifacts;

namespace KSword.Sandbox.Core.Reporting;

/// <summary>
/// Defines the localized HTML report variants supported by the renderer.
/// Inputs are selected by callers before rendering; processing uses the value
/// to emit language-specific chrome; the generated evidence remains unchanged.
/// </summary>
public enum HtmlReportLanguage
{
    English,
    ChineseSimplified
}

/// <summary>
/// Represents one generated localized report document.
/// Inputs are a target filename, language, culture name, and HTML payload;
/// processing is performed by <see cref="HtmlReportRenderer"/>; the value is
/// returned to callers that want to write report.en.html/report.zh.html pairs.
/// </summary>
public sealed record HtmlReportDocument(string FileName, HtmlReportLanguage Language, string CultureName, string Html);

/// <summary>
/// Renders a local, self-contained HTML report from normalized analysis data.
/// Inputs are report models, processing groups findings and events into a
/// Microstep-style report layout, and the method returns a complete HTML
/// document string.
/// </summary>
public sealed class HtmlReportRenderer
{
    private const int ArtifactPreviewCharacterLimit = 8_000;
    private const long ArtifactPreviewImageByteLimit = 2 * 1024 * 1024;
    private const int ProcessTreeDefaultOpenDepth = 1;
    private const int TimelineEventInlineLimit = 120;
    private const int TimelineGroupEventInlineLimit = 12;
    private const int EventTableInlineLimit = 80;
    private const int StaticStringInlineLimit = 200;
    private const int RawEventInlineLimit = 75;
    private const int RawEventPageSize = 25;
    private const int RawEventIndexGroupInlineLimit = 16;
    private const int R0HealthEvidenceInlineLimit = 12;
    private const int R0SelfNoiseExampleLimit = 8;
    private const int EventCompactFieldInlineLimit = 28;
    private const int EventCompactFieldValueLimit = 220;
    private const int FindingEvidenceDataPairLimit = 16;
    private const int FindingEvidenceValueLimit = 180;
    private const int RelationshipCardInlineLimit = 24;
    private const int RelationshipArtifactInlineLimit = 6;
    private const int EvidenceStoryInlineLimit = 12;

    private sealed record TimelineGroup(
        string Window,
        string Summary,
        int TotalEventCount,
        IReadOnlyList<SandboxEvent> Events,
        string CopyText);

    private sealed record BehaviorGraphEdge(string From, string Relation, string To, string Evidence, IReadOnlyList<ArtifactDescriptor> RelatedArtifacts);

    private sealed record ProcessGraphNode(string Label, string Detail, string CopyText);

    private sealed record ProcessTreeActivity(int EventCount, int FileCount, int RegistryCount, int NetworkCount);

    private sealed record BehaviorFactCard(
        string Title,
        string Value,
        string Css,
        string WhatHappened,
        string WhySuspicious,
        IReadOnlyList<string> EvidenceLines);

    private sealed record EvidenceSummaryCard(string Title, string Value, string Detail, string Css, string CopyText);

    private sealed record BehaviorRoutingStats(
        int TotalEvents,
        int SampleBehaviorEvents,
        int ExcludedFromBehaviorStory,
        int BehaviorCountedFalse,
        int NonBehavior,
        int NotSampleBehavior,
        int CollectorSelfNoise,
        int CollectorNoise,
        int CollectionHealthRows,
        int VtQuietStates,
        int R0HealthRows,
        int CorrelationConfirmed,
        int CorrelationProbable,
        int CorrelationEnvironment,
        int CorrelationUnknown,
        int RetainedNotPromoted,
        int NormalInteractiveGuiBaseline,
        int EvidenceDispositionRetainedNotPromoted);

    private sealed record EvidenceNarrativeCard(
        string Step,
        string Title,
        string Value,
        string Detail,
        string Css,
        string CopyText);

    private sealed record EvidenceStoryCard(
        string Title,
        string Status,
        string Css,
        string Lead,
        IReadOnlyList<string> Metrics,
        IReadOnlyList<string> EvidenceLines,
        int SourceEvidenceCount,
        string CopyText);

    private sealed record ArtifactCollectionStatusCard(
        string Name,
        string Status,
        string Css,
        int ArtifactCount,
        int EventCount,
        string Detail,
        string CopyText);

    private sealed record ArtifactEvidenceMatrixRow(
        string CollectionName,
        ArtifactKind Kind,
        int Count,
        string State,
        long Bytes,
        string Source,
        string Selectors);

    private sealed record ProcessRelationshipCard(
        string Label,
        string RiskCss,
        int EventCount,
        int ChildCount,
        int FileCount,
        int RegistryCount,
        int NetworkCount,
        string FirstSeen,
        string LastSeen,
        string ParentLabel,
        string Path,
        string CommandLine,
        IReadOnlyList<string> ChildLabels,
        IReadOnlyList<string> RelationshipLines,
        IReadOnlyList<string> EvidenceLines,
        IReadOnlyList<ArtifactDescriptor> RelatedArtifacts,
        string CompactSummary,
        string CopyText);

    private sealed record NetworkRelationshipCard(
        string Target,
        string RiskCss,
        int EventCount,
        string Protocols,
        IReadOnlyList<string> Categories,
        int DnsCount,
        int HttpCount,
        int TlsCount,
        int FlowCount,
        string FirstSeen,
        string LastSeen,
        IReadOnlyList<string> Processes,
        IReadOnlyList<string> EventTypes,
        IReadOnlyList<string> EvidenceLines,
        IReadOnlyList<ArtifactDescriptor> RelatedArtifacts,
        string CompactSummary,
        string CopyText);

    private static readonly JsonSerializerOptions ArtifactJsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter() }
    };

    private static readonly Regex ChineseRawEvidenceFragmentRegex = new(
        "<style\\b[^>]*>.*?</style>|<(?:code|pre)\\b[^>]*>.*?</(?:code|pre)>|\\sdata-copy=\"[^\"]*\"",
        RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.CultureInvariant,
        TimeSpan.FromSeconds(2));

    private static readonly Regex ChineseVisibleEventCountRegex = new(
        "(?<=\\d) events(?=</span>)",
        RegexOptions.CultureInvariant,
        TimeSpan.FromSeconds(2));

    /// <summary>
    /// Converts one AnalysisReport to HTML.
    /// The input is a completed or planned report, processing writes cover,
    /// summary, detection, static, dynamic, network, and failure sections, and
    /// the method returns HTML text.
    /// </summary>
    public string Render(AnalysisReport report) => Render(report, []);

    /// <summary>
    /// Converts one AnalysisReport to localized HTML.
    /// Inputs are a completed or planned report and language; processing writes
    /// report chrome in that language while preserving normalized evidence;
    /// the method returns HTML text.
    /// </summary>
    public string Render(AnalysisReport report, HtmlReportLanguage language) => Render(report, [], language);

    /// <summary>
    /// Converts one AnalysisReport plus optional artifact descriptors to the
    /// default Simplified Chinese HTML.
    /// Inputs are a report and host/guest artifact index entries; processing
    /// renders artifact links before behavior timelines; the method returns a
    /// complete HTML document string.
    /// </summary>
    public string Render(AnalysisReport report, IEnumerable<ArtifactDescriptor>? artifacts) =>
        Render(report, artifacts, HtmlReportLanguage.ChineseSimplified);

    /// <summary>
    /// Converts one AnalysisReport plus optional artifact descriptors to
    /// localized HTML.
    /// Inputs are a report, host/guest artifact index entries, and language;
    /// processing renders artifact links before behavior timelines and then
    /// localizes the report shell; the method returns a complete HTML document.
    /// </summary>
    public string Render(AnalysisReport report, IEnumerable<ArtifactDescriptor>? artifacts, HtmlReportLanguage language)
    {
        var html = RenderEnglishCore(report, artifacts);
        return language == HtmlReportLanguage.ChineseSimplified
            ? LocalizeChineseHtml(html, report)
            : html;
    }

    /// <summary>
    /// Converts one AnalysisReport to the English HTML variant.
    /// Inputs are a completed or planned report; processing delegates to the
    /// localized render entry point; the method returns HTML text.
    /// </summary>
    public string RenderEnglish(AnalysisReport report) => Render(report, HtmlReportLanguage.English);

    /// <summary>
    /// Converts one AnalysisReport plus artifact descriptors to the English
    /// HTML variant.
    /// </summary>
    public string RenderEnglish(AnalysisReport report, IEnumerable<ArtifactDescriptor>? artifacts) =>
        Render(report, artifacts, HtmlReportLanguage.English);

    /// <summary>
    /// Converts one AnalysisReport to the Simplified Chinese HTML variant.
    /// Inputs are a completed or planned report; processing delegates to the
    /// localized render entry point; the method returns HTML text.
    /// </summary>
    public string RenderChinese(AnalysisReport report) => Render(report, HtmlReportLanguage.ChineseSimplified);

    /// <summary>
    /// Converts one AnalysisReport plus artifact descriptors to the Simplified
    /// Chinese HTML variant.
    /// </summary>
    public string RenderChinese(AnalysisReport report, IEnumerable<ArtifactDescriptor>? artifacts) =>
        Render(report, artifacts, HtmlReportLanguage.ChineseSimplified);

    /// <summary>
    /// Renders the pair of localized report documents expected by operators.
    /// Inputs are a completed report; processing returns in-memory HTML payloads
    /// for report.en.html and report.zh.html; callers decide whether and where
    /// to write the files.
    /// </summary>
    public IReadOnlyList<HtmlReportDocument> RenderBilingualReports(AnalysisReport report) =>
        RenderBilingualReports(report, []);

    /// <summary>
    /// Renders report.en.html and report.zh.html document payloads with shared
    /// artifact descriptors.
    /// </summary>
    public IReadOnlyList<HtmlReportDocument> RenderBilingualReports(AnalysisReport report, IEnumerable<ArtifactDescriptor>? artifacts)
    {
        var artifactList = artifacts?.ToList();
        return
        [
            new HtmlReportDocument("report.en.html", HtmlReportLanguage.English, "en-US", RenderEnglish(report, artifactList)),
            new HtmlReportDocument("report.zh.html", HtmlReportLanguage.ChineseSimplified, "zh-CN", RenderChinese(report, artifactList))
        ];
    }

    private static string RenderEnglishCore(AnalysisReport report, IEnumerable<ArtifactDescriptor>? artifacts)
    {
        var artifactLinks = BuildReportArtifactList(report, artifacts);
        var artifactLookup = BuildArtifactLookup(artifactLinks);
        var html = new StringBuilder();
        html.AppendLine("<!doctype html>");
        html.AppendLine("<html lang=\"en\">");
        AppendHead(html);
        html.AppendLine("<body class=\"modern-sandbox-report\">");
        AppendCover(html, report);
        AppendLanguageEntrypoints(html);
        AppendNoScriptFallback(html);
        html.AppendLine("<div class=\"report-layout\">");
        html.AppendLine("<aside class=\"report-sidebar\" aria-label=\"Report navigation\">");
        html.AppendLine("<div class=\"sidebar-heading\"><div><strong>KSword Sandbox Report</strong><span>Report navigation</span></div><button type=\"button\" class=\"sidebar-toggle\" aria-controls=\"sidebar-navigation\" aria-expanded=\"false\"><span aria-hidden=\"true\">&#9776;</span><span>Sections</span></button></div>");
        html.AppendLine("<div id=\"sidebar-navigation\" class=\"sidebar-navigation\">");
        AppendQuickNavigation(html, report, artifactLinks);
        AppendTableOfContents(html);
        html.AppendLine("</div></aside>");
        html.AppendLine("<main class=\"report-content\">");
        AppendRiskSummary(html, report);
        AppendBehaviorDetections(html, report);
        AppendAggregatedBehaviorFacts(html, report, artifactLinks);
        AppendMitreDetections(html, report);
        AppendRuleHits(html, report);
        AppendStaticAnalysis(html, report);
        AppendDynamicAnalysis(html, report);
        AppendVirusTotalSummary(html, report, artifactLookup, artifactLinks);
        AppendBehaviorGraph(html, report, artifactLookup, artifactLinks);
        AppendArtifactLinks(html, report, artifactLinks);
        AppendTimeline(html, report, artifactLookup, artifactLinks);
        AppendProcessDetails(html, report, artifactLookup, artifactLinks);
        AppendSecurityPrivilegeTelemetry(html, report, artifactLookup, artifactLinks);
        AppendDroppedFiles(html, report, artifactLookup, artifactLinks);
        AppendStartupPersistence(html, report, artifactLookup, artifactLinks);
        AppendRegistryBehavior(html, report, artifactLookup, artifactLinks);
        AppendNetworkBehavior(html, report, artifactLookup, artifactLinks);
        AppendR0Events(html, report, artifactLookup, artifactLinks);
        AppendFailureReasons(html, report, artifactLookup, artifactLinks);
        AppendRawEvents(html, report, artifactLookup, artifactLinks);
        html.AppendLine("</main></div>");
        AppendReportScripts(html);
        html.AppendLine("</body></html>");
        return html.ToString();
    }

    /// <summary>
    /// Appends CSS and document metadata.
    /// Inputs are a StringBuilder, processing writes static style rules, and
    /// the method returns no value.
    /// </summary>
    private static void AppendHead(StringBuilder html)
    {
        html.AppendLine("<head><meta charset=\"utf-8\"><title>KSword Sandbox Report</title>");
        html.AppendLine("<style>");
        html.AppendLine("""
:root{--primary:#43A0FF;--primary-deep:#0969c9;--primary-soft:#e7f3ff;--ink:#0f172a;--muted:#64748b;--line:#dce8f5;--panel:#ffffff;--section-max:75vh;--subsection-max:52vh;--detail-max:32vh;--raw-evidence-max:58vh;--artifact-preview-img-max:260px}
*{box-sizing:border-box}html{scroll-behavior:smooth}
body{margin:0;background:linear-gradient(180deg,#f4f9ff 0,#f8fafc 52%,#eef6ff 100%);color:var(--ink);font-family:Segoe UI,Arial,sans-serif}
body.modern-sandbox-report:before{background:var(--primary);content:'';display:block;height:4px;width:100%}
header{background:linear-gradient(135deg,#08111f,#123d66 62%,#0d5fa8);border-bottom:4px solid var(--primary);color:white;padding:34px 48px;position:relative;overflow:hidden}
header:after{display:none}header h1{font-size:34px;letter-spacing:-.03em;margin:0 0 8px}header .muted{color:#dbeafe}
header table{background:rgba(8,17,31,.32);border:1px solid rgba(255,255,255,.22);border-collapse:collapse;border-radius:2px;overflow:hidden}header td,header th{border-bottom:1px solid rgba(255,255,255,.18);color:white}header th{background:rgba(255,255,255,.08);position:static}
.card.language-entry,.card.no-js-fallback{max-width:1560px;margin:18px auto}.report-layout{align-items:start;display:grid;gap:28px;grid-template-columns:minmax(248px,280px) minmax(0,1fr);margin:24px auto;max-width:1600px;padding:0 24px}.report-sidebar{background:#fff;border:1px solid var(--line);border-left:3px solid var(--primary);max-height:calc(100vh - 32px);overflow:auto;position:sticky;scrollbar-color:var(--primary) #eaf4ff;scrollbar-width:thin;top:16px}.sidebar-heading{align-items:center;border-bottom:1px solid var(--line);display:flex;gap:12px;justify-content:space-between;padding:18px 16px}.sidebar-heading strong{display:block;font-size:15px}.sidebar-heading div>span{color:var(--muted);display:block;font-size:12px;font-weight:700;margin-top:4px}.sidebar-toggle{align-items:center;background:#fff;border:1px solid #bfdbfe;border-radius:2px;color:#075985;cursor:pointer;display:none;font-size:12px;font-weight:800;gap:6px;min-height:34px;padding:6px 9px}.sidebar-toggle:hover{background:#eef7ff;border-color:var(--primary)}.sidebar-toggle span[aria-hidden=true]{font-size:16px;line-height:1}.sidebar-navigation{display:block}.sidebar-section{padding:14px 12px}.sidebar-section+.sidebar-section{border-top:1px solid var(--line)}.sidebar-section h2{color:#334155;font-size:12px;margin:0 6px 8px;text-transform:uppercase}.report-content{counter-reset:report-section;min-width:0}.card{background:#fff;border:1px solid var(--line);border-radius:2px;box-shadow:none;margin:18px 0;padding:22px;position:relative}
section.card{contain:layout paint;counter-increment:report-section;isolation:isolate;max-height:75vh;max-height:var(--section-max);overflow:auto;overscroll-behavior:contain;scrollbar-color:var(--primary) #eaf4ff;scrollbar-width:thin}.card:before{background:var(--primary);border-radius:0;content:'';height:100%;left:0;opacity:.9;position:absolute;top:0;width:3px}
.language-entry{align-items:center;display:flex;flex-wrap:wrap;gap:10px}.language-entry strong{color:#075985}.language-entry .hint{color:var(--muted);font-size:13px}.language-entry a{background:var(--primary);border-radius:2px;color:white;font-weight:800;padding:8px 12px;text-decoration:none}.language-entry a.secondary{background:#334155}.language-entry a:hover{outline:2px solid rgba(67,160,255,.18)}
.quick-links,.toc-links{display:grid;gap:2px}.quick-link,.toc-link{align-items:center;border-left:3px solid transparent;color:#334155;display:grid;gap:8px;grid-template-columns:minmax(0,1fr) auto;min-height:34px;padding:7px 8px;text-decoration:none}.quick-link strong{font-size:12px;overflow-wrap:anywhere}.quick-link small{background:#eef7ff;color:#075985;font-size:11px;font-weight:900;min-width:24px;padding:3px 6px;text-align:center}.toc-link{display:block;font-size:12px;font-weight:650;line-height:1.35}.quick-link:hover,.toc-link:hover{background:#f8fbff;border-left-color:#93c5fd;color:#075985}.quick-link.is-active,.toc-link.is-active{background:#eaf4ff;border-left-color:var(--primary);color:#075985}.quick-link[aria-current=location],.toc-link[aria-current=location]{font-weight:900}
.card h2{align-items:center;display:flex;gap:10px;margin:0 0 14px}.card h2:before{background:var(--primary);border-radius:0;content:'';display:inline-block;height:12px;width:12px}section.card>h2{backdrop-filter:none;background:#fff;border-bottom:1px solid #dbeafe;margin:-22px -22px 16px;padding:16px 22px;position:sticky;top:-22px;z-index:3}section.card>h2:after{background:var(--primary);border-radius:2px;color:white;content:'Step ' counter(report-section);font-size:11px;font-weight:900;margin-left:auto;padding:5px 9px;text-transform:uppercase}
.grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(170px,1fr))}.metric{background:#fff;border:1px solid var(--line);border-left:3px solid var(--primary);border-radius:2px;padding:14px}.metric b{display:block;font-size:26px;margin-top:4px}
.muted{color:var(--muted)}.risk-critical{color:#7f1d1d}.risk-high{color:#b91c1c}.risk-medium{color:#b45309}.risk-low{color:#047857}.risk-info{color:var(--primary-deep)}
.badge,.chip,.evidence-count{border:1px solid transparent;border-radius:2px;display:inline-block;font-weight:700;padding:5px 9px}.chip{font-size:12px;margin:2px 4px 2px 0;padding:3px 7px}.evidence-count{background:#f8fbff;border-color:#cfe6fb;color:#075985;font-size:12px;margin:2px 6px 2px 0}
.badge-critical,.chip-critical{background:#fecaca;color:#7f1d1d}.badge-high,.chip-high{background:#fee2e2;color:#991b1b}.badge-medium,.chip-medium{background:#fef3c7;color:#92400e}.badge-low,.chip-low{background:#dcfce7;color:#166534}.badge-info,.chip-info{background:var(--primary-soft);color:#075985}
.section-note{background:#f7fbff;border:1px solid #dbeafe;border-left:4px solid var(--primary);border-radius:2px;color:#475569;margin:10px 0;padding:10px 12px}
table{border-collapse:collapse;border-spacing:0;width:100%;margin-top:14px}td,th{border-bottom:1px solid #e5edf6;padding:10px;text-align:left;vertical-align:top}th{background:#f8fbff;color:#475569;font-size:12px;position:static;text-transform:uppercase}
code{background:#f1f7ff;border-radius:2px;padding:2px 5px;word-break:break-all}
.empty{background:#fff;border:1px dashed #b9d7f3;border-radius:2px;color:var(--muted);padding:14px}
.copy-btn{background:#fff;border:1px solid rgba(67,160,255,.55);border-radius:2px;color:#075985;cursor:pointer;font-size:12px;font-weight:700;margin:2px 6px 2px 0;padding:4px 8px}.copyable{cursor:copy}.copy-hint{color:var(--muted);font-size:12px;margin-top:8px}.no-js-fallback{border-color:#b9ddff}.no-js-fallback:before{background:#38bdf8}.fold-label{background:#f8fbff;border:1px solid #cfe6fb;color:#075985;display:inline-block;font-size:12px;font-weight:800;margin:2px 6px 2px 0;padding:3px 7px}
.toolbar,.inline-actions{align-items:center;display:inline-flex;flex-wrap:wrap;gap:6px;justify-content:flex-start;margin:0 0 4px}.event-table-wrap{border:1px solid var(--line);border-radius:2px;margin-top:14px;max-height:var(--subsection-max);overflow:auto}.event-table-wrap table{margin-top:0}.event-table-wrap th,.raw-events-panel th,.raw-event-page th{position:sticky;top:0;z-index:1}.bounded-list{max-height:var(--subsection-max);overflow:auto}
.event-table td:first-child{white-space:nowrap}.event-table td:nth-child(2){min-width:140px}.event-table td:nth-child(4){min-width:140px}.event-table td:nth-child(5){min-width:260px}.event-table .evidence{min-width:280px}
.timeline-groups{display:grid;gap:10px;margin-top:14px}.timeline-group{background:#fff;border:1px solid var(--line);border-radius:2px;overflow:hidden}.timeline-group>summary{align-items:flex-start;cursor:pointer;display:flex;gap:10px;justify-content:space-between;list-style:none;padding:12px 14px}.timeline-group>summary::-webkit-details-marker{display:none}.timeline-group>summary:before{color:var(--primary-deep);content:'▶';font-weight:900;margin-top:2px}.timeline-group[open]>summary:before{content:'▼'}.timeline-group small{color:var(--muted);display:block;line-height:1.4;margin-top:3px}.timeline{border-left:3px solid rgba(67,160,255,.45);margin:0 14px 14px 20px;padding:12px 0 0 18px}.timeline-item{background:#fff;border:1px solid var(--line);border-radius:2px;margin:0 0 10px;padding:10px 12px;position:relative}.timeline-item:before{background:var(--primary);border:2px solid var(--primary-soft);border-radius:2px;content:'';height:10px;left:-25px;position:absolute;top:13px;width:10px}.timeline-overflow{background:#f1f7ff;border:1px dashed #b9d7f3;border-radius:2px;color:var(--muted);margin:0 0 12px;padding:9px 11px}
.graph-map{display:grid;gap:10px;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));margin-top:12px}.graph-node{background:#fff;border:1px solid var(--line);border-left:4px solid var(--primary);border-radius:2px;padding:12px}.graph-node strong{display:block;margin-bottom:4px}.graph-node small{color:var(--muted);display:block;line-height:1.4}.behavior-chain{background:#fff;border:1px solid var(--line);border-radius:2px;counter-reset:chain;margin:12px 0;max-height:var(--subsection-max);overflow:auto;padding:8px 10px}.behavior-chain li{align-items:flex-start;background:#fff;border-bottom:1px solid #dbeafe;border-radius:0;counter-increment:chain;display:grid;gap:8px;grid-template-columns:auto 1fr;margin:0;padding:10px}.behavior-chain li:last-child{border-bottom:0}.behavior-chain li:before{align-items:center;background:var(--primary);border-radius:2px;color:white;content:counter(chain);display:inline-flex;font-weight:900;height:24px;justify-content:center;width:24px}.behavior-chain details{grid-column:2}.behavior-chain pre{max-height:var(--detail-max);overflow:auto;white-space:pre-wrap;word-break:break-word}.edge-table td:nth-child(1),.edge-table td:nth-child(3){min-width:170px}.ioc-grid{display:grid;gap:10px;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));margin-top:14px}.ioc-card{background:#fff;border:1px solid var(--line);border-radius:2px;padding:12px}.ioc-card h3{font-size:15px;margin:0 0 8px}.ioc-card ul{margin:0;padding-left:18px}.ioc-card li{margin:5px 0;word-break:break-word}
.evidence-summary-grid,.relation-grid,.overview-strip,.evidence-story-board,.narrative-spine{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));margin-top:14px}.evidence-summary-card,.relation-card,.overview-item,.evidence-story-lane,.narrative-step{background:#fff;border:1px solid var(--line);border-left:4px solid var(--primary);border-radius:2px;box-shadow:none;max-height:var(--subsection-max);min-width:0;overflow:auto;overflow-wrap:anywhere;padding:14px;position:relative}.narrative-spine{counter-reset:narrative-step}.narrative-spine-lead{align-items:flex-start;background:#f8fbff;border:1px solid #cfe6fb;border-left:4px solid var(--primary);display:flex;flex-wrap:wrap;gap:8px;margin:10px 0 0;padding:10px 12px}.narrative-spine-lead strong{color:#075985}.narrative-step{contain:layout paint;display:grid;grid-template-columns:auto 1fr;gap:8px 10px;max-height:none;overflow:hidden}.narrative-step-index{align-items:center;background:var(--primary);color:#fff;display:inline-flex;font-weight:900;height:26px;justify-content:center;width:26px}.narrative-step h3{grid-column:2;margin:2px 0 0}.narrative-step .overview-value{grid-column:1/3}.narrative-step p{grid-column:1/3;color:var(--muted);font-size:13px;line-height:1.45;margin:0}.narrative-step .toolbar{grid-column:1/3}.evidence-summary-card:before,.relation-card:before,.overview-item:before,.evidence-story-lane:before,.narrative-step:before{display:none}.evidence-summary-card h3,.relation-card h3,.overview-item h3,.evidence-story-lane h3{font-size:15px;margin:0 0 8px;padding-left:0}.summary-value,.overview-value{color:#075985;display:block;font-size:26px;font-weight:900;letter-spacing:-.04em}.overview-value.risk-medium{color:#b45309}.overview-value.risk-high{color:#b91c1c}.overview-value.risk-low{color:#047857}.overview-value.risk-info{color:var(--primary-deep)}.overview-item p,.story-lead{color:var(--muted);font-size:13px;line-height:1.45;margin:6px 0 0}.compact-evidence-summary{background:#f8fbff;border:1px solid #cfe6fb;border-left:3px solid var(--primary);color:#334155;font-size:13px;line-height:1.45;margin:8px 0;padding:8px 10px;word-break:break-word}.compact-evidence-summary strong{color:#075985}.story-metrics{display:flex;flex-wrap:wrap;gap:6px;margin:10px 0}.story-metrics span{background:#f8fbff;border:1px solid #cfe6fb;border-radius:2px;color:#075985;font-size:12px;font-weight:800;padding:6px 8px}.story-evidence-list{font-family:Consolas,monospace;font-size:12px;line-height:1.45;margin:8px 0 0;padding-left:18px}.story-evidence-list li{margin:3px 0;word-break:break-word}.relationship-meta{display:grid;gap:6px;grid-template-columns:repeat(2,minmax(0,1fr));margin:10px 0}.relationship-meta span{background:#f8fbff;border:1px solid #cfe6fb;border-radius:2px;color:#075985;font-size:12px;font-weight:700;padding:7px}.relationship-tags,.artifact-badge-row{display:flex;flex-wrap:wrap;gap:6px;margin:8px 0}.relationship-tags .chip,.artifact-badge-row .chip{margin:0}.artifact-badge-row{background:#f8fbff;border:1px solid #cfe6fb;border-left:3px solid #60a5fa;padding:7px 8px}.artifact-badge-row strong{color:#075985;font-size:12px;margin-right:2px}.evidence-expansion-card{background:#f8fbff;border:1px solid #cfe6fb;border-left:3px solid var(--primary);margin-top:10px;padding:8px 10px}.evidence-expansion-card[open]{background:#fff}.relationship-details,.flat-details,.event-evidence-fields,.technical-field,.raw-technical-fields,.raw-technical-field{background:transparent;border:0;border-left:2px solid #cfe6fb;border-radius:0;margin-top:8px;padding:4px 0 4px 8px}.relationship-details summary,.flat-details summary,.event-evidence-fields summary,.technical-field summary,.raw-technical-fields summary,.raw-technical-field summary,.evidence-expansion-card summary{cursor:pointer;font-weight:800}.relationship-details pre,.flat-details pre,.event-evidence-fields pre,.technical-field pre,.raw-technical-field pre,.evidence-expansion-card pre{max-height:var(--detail-max);overflow:auto;white-space:pre-wrap;word-break:break-word}.relationship-title{display:flex;align-items:flex-start;gap:8px;justify-content:space-between}.relationship-title code{max-width:100%;overflow-wrap:anywhere}.anchor-offset{scroll-margin-top:18px}.mono-list{font-family:Consolas,monospace;font-size:12px;line-height:1.45;margin:6px 0 0 0;padding-left:18px}.mono-list li{margin:3px 0;word-break:break-word}
.tree{font-family:Consolas,monospace;line-height:1.5;margin:12px 0}.tree ul{border-left:1px dashed #b9d7f3;list-style:none;margin:0 0 0 18px;padding-left:14px}.tree li{margin:5px 0}.process-tree{background:#fff;border:1px solid var(--line);border-radius:2px;max-height:var(--subsection-max);overflow:auto;padding:12px}.process-tree details.process-tree-node{margin:4px 0}.process-tree summary,.process-tree-leaf{align-items:flex-start;cursor:pointer;display:flex;flex-wrap:wrap;gap:8px;list-style:none}.process-tree summary::-webkit-details-marker{display:none}.process-tree summary:before{color:var(--primary-deep);content:'▶';font-weight:900;margin-top:2px}.process-tree details[open]>summary:before{content:'▼'}.process-tree-line{display:flex;flex-wrap:wrap;gap:6px;min-width:0}.process-tree-label{font-weight:900}.process-tree-path{color:var(--muted);font-family:Segoe UI,Arial,sans-serif;font-size:12px;max-width:58ch;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.tree-badges{display:inline-flex;flex-wrap:wrap;gap:5px}.tree-badge{background:#eef7ff;border:1px solid #cfe6fb;border-radius:2px;color:#075985;font-family:Segoe UI,Arial,sans-serif;font-size:11px;font-weight:800;padding:2px 7px}.process-tree-sparkline{align-items:center;display:inline-grid;gap:2px;grid-template-columns:repeat(4,20px);height:14px;margin-top:3px}.process-tree-sparkline span{background:#dbeafe;border:1px solid #bfdbfe;display:block;height:12px}.process-tree-sparkline .hot{background:#43A0FF;border-color:#0969c9}.process-tree-sparkline-label{color:#64748b;font-family:Segoe UI,Arial,sans-serif;font-size:11px;margin-left:2px}
.evidence{max-width:560px}.evidence summary{cursor:pointer;font-weight:700}.evidence pre{white-space:pre-wrap;word-break:break-word}
.columns{display:grid;gap:14px;grid-template-columns:1fr 1fr}.compact-list{margin:8px 0 0 0;padding-left:18px}.compact-list li{margin:4px 0}
.artifact-ref{font-weight:700}.artifact-location{display:grid;gap:6px}.artifact-actions{align-items:center;display:inline-flex;flex-wrap:wrap;gap:6px;margin-top:4px}.artifact-actions-inline{display:inline-flex;margin-left:6px;margin-top:0;vertical-align:middle}.artifact-btn{background:#fff;border:1px solid rgba(67,160,255,.72);border-radius:2px;box-shadow:none;color:#075985;display:inline-block;font-size:12px;font-weight:900;padding:4px 8px;text-decoration:none}.artifact-btn.download{background:#eef7ff;color:#075985}.artifact-btn:hover{outline:2px solid rgba(67,160,255,.14)}.artifact-no-link{background:#fff;border:1px dashed #cbd5e1;border-radius:2px;color:var(--muted);display:inline-block;font-size:12px;font-weight:800;padding:4px 8px}.artifact-copy-path{background:#fff;border:1px solid var(--line);border-radius:2px;padding:8px}.artifact-list{list-style:none;margin:8px 0 0 0;padding:0}.artifact-list li{border-top:1px solid #e2e8f0;margin-top:8px;padding-top:8px}.artifact-preview{max-height:var(--subsection-max);overflow:auto}.artifact-preview img{border:1px solid #cbd5e1;border-radius:2px;max-height:var(--artifact-preview-img-max);max-width:100%;object-fit:contain}
.raw-field-list{margin:6px 0 0 0;padding-left:18px}.raw-field-list li{margin:4px 0;word-break:break-word}.raw-events-shell{background:#fff;border:1px solid var(--line);border-radius:2px;margin-top:14px;overflow:hidden}.raw-events-shell>summary{cursor:pointer;font-weight:800;list-style:none;padding:12px 14px}.raw-events-shell>summary::-webkit-details-marker{display:none}.raw-events-shell>summary:before{color:var(--primary-deep);content:'▶';display:inline-block;margin-right:8px}.raw-events-shell[open]>summary:before{content:'▼'}.raw-events-panel{border-top:1px solid var(--line);max-height:58vh;overflow:auto;padding:12px}.raw-events-panel .event-table-wrap{max-height:32vh}.raw-event-pages{display:grid;gap:10px}.raw-event-page{background:#fff;border:1px solid #dbeafe;border-radius:2px;overflow:hidden;scroll-margin-top:18px}.raw-event-page>summary{background:#eef7ff;color:#075985;cursor:pointer;font-weight:900;list-style:none;padding:10px 12px}.raw-event-page>summary::-webkit-details-marker{display:none}.raw-event-page>summary:before{content:'▶';display:inline-block;margin-right:8px}.raw-event-page[open]>summary:before{content:'▼'}.raw-event-page table{margin:0}.raw-page-nav,.health-narrative-grid{display:flex;flex-wrap:wrap;gap:6px;margin:8px 0}.raw-page-nav a,.health-pill,.relation-flow{background:#f8fbff;border:1px solid #cfe6fb;color:#075985;display:inline-block;font-size:12px;font-weight:800;padding:5px 8px;text-decoration:none}.relation-flow{border-left:3px solid var(--primary);font-weight:700;line-height:1.45;margin:8px 0;max-width:100%;overflow-wrap:anywhere}.raw-source-hints{background:#fff;border:1px solid var(--line);border-radius:2px;margin-top:12px;padding:12px}.raw-source-hints ul{list-style:none;margin:8px 0 0 0;padding:0}.raw-source-hints li{border-top:1px solid #e2e8f0;margin-top:8px;padding-top:8px}.raw-source-hints li:first-child{border-top:0;margin-top:0;padding-top:0}.raw-source-hints .hint-label{font-weight:800}

/* Square, flat operator theme: no pill/card nesting beyond one visual layer. */
.modern-sandbox-report header:after{display:none}.modern-sandbox-report .card,.modern-sandbox-report section.card,.modern-sandbox-report .metric,.modern-sandbox-report .quick-link,.modern-sandbox-report .language-entry a,.modern-sandbox-report .badge,.modern-sandbox-report .chip,.modern-sandbox-report .section-note,.modern-sandbox-report code,.modern-sandbox-report .toc a,.modern-sandbox-report .empty,.modern-sandbox-report .copy-btn,.modern-sandbox-report .event-table-wrap,.modern-sandbox-report .timeline-group,.modern-sandbox-report .timeline-item,.modern-sandbox-report .timeline-overflow,.modern-sandbox-report .graph-node,.modern-sandbox-report .behavior-chain,.modern-sandbox-report .behavior-chain li,.modern-sandbox-report .behavior-chain details,.modern-sandbox-report .ioc-card,.modern-sandbox-report .evidence-summary-card,.modern-sandbox-report .evidence-story-lane,.modern-sandbox-report .narrative-step,.modern-sandbox-report .relation-card,.modern-sandbox-report .overview-item,.modern-sandbox-report .relationship-meta span,.modern-sandbox-report .relationship-details,.modern-sandbox-report .evidence-expansion-card,.modern-sandbox-report .process-tree,.modern-sandbox-report .tree-badge,.modern-sandbox-report .evidence details,.modern-sandbox-report .artifact-btn,.modern-sandbox-report .artifact-no-link,.modern-sandbox-report .artifact-copy-path,.modern-sandbox-report .artifact-preview img,.modern-sandbox-report .technical-field,.modern-sandbox-report .raw-technical-fields,.modern-sandbox-report .raw-technical-field,.modern-sandbox-report .raw-events-shell,.modern-sandbox-report .raw-event-page,.modern-sandbox-report .raw-source-hints{border-radius:0!important}.modern-sandbox-report .card:before,.modern-sandbox-report .evidence-summary-card:before,.modern-sandbox-report .evidence-story-lane:before,.modern-sandbox-report .narrative-step:before,.modern-sandbox-report .relation-card:before,.modern-sandbox-report .overview-item:before{border-radius:0!important}.modern-sandbox-report .badge,.modern-sandbox-report .chip,.modern-sandbox-report .copy-btn,.modern-sandbox-report .artifact-btn,.modern-sandbox-report .artifact-no-link{box-shadow:none!important}.modern-sandbox-report .event-evidence-fields,.modern-sandbox-report .flat-technical-fields,.modern-sandbox-report .related-artifacts-flat{background:transparent;border:0;border-radius:0;padding:0}.modern-sandbox-report .flat-technical-fields{border-top:1px solid var(--line);margin-top:8px;padding-top:8px}.modern-sandbox-report .related-artifacts-flat ul{border-top:1px solid var(--line);list-style:none;margin:6px 0 0 0;padding:0}.modern-sandbox-report .related-artifacts-flat li{border-top:1px solid #e2e8f0;margin-top:6px;padding-top:6px}.modern-sandbox-report .related-artifacts-flat li:first-child{border-top:0}.modern-sandbox-report .event-table-wrap,.modern-sandbox-report .raw-events-panel,.modern-sandbox-report .process-tree,.modern-sandbox-report .behavior-chain,.modern-sandbox-report .relation-card,.modern-sandbox-report .evidence-story-lane{overscroll-behavior:contain}.modern-sandbox-report .event-table td,.modern-sandbox-report .edge-table td{overflow-wrap:anywhere}.modern-sandbox-report .self-noise-note{background:#f8fafc;border-left:4px solid #94a3b8;color:#475569;margin:10px 0;padding:10px 12px}
@media print{html{scroll-behavior:auto}body{background:#fff;color:#000}header,.language-entry,.no-js-fallback{max-width:none;margin:0;padding:12px}.report-layout{display:block;margin:0;max-width:none;padding:0 12px}.report-sidebar{max-height:none;overflow:visible;position:static}.report-content{min-width:0}.copy-btn{display:none!important}section.card,.card,.event-table-wrap,.raw-events-panel,.process-tree,.behavior-chain,.relation-card,.evidence-story-lane,.evidence-summary-card,.raw-event-page{break-inside:avoid;max-height:none!important;overflow:visible!important}section.card>h2,th{position:static!important}.process-tree-path{white-space:normal}.raw-events-shell>summary:after,.raw-event-page>summary:after,.event-evidence-fields>summary:after,.technical-field>summary:after,.raw-technical-fields>summary:after{color:#64748b;content:' (folded in screen view; expand in browser for full evidence)';font-weight:400}}
@media(max-width:1000px){.report-layout{display:block}.report-sidebar{display:grid;grid-template-columns:1fr 1fr;max-height:none;position:static}.sidebar-heading{grid-column:1/-1}.sidebar-navigation{display:contents}.sidebar-section+.sidebar-section{border-left:1px solid var(--line);border-top:0}.grid,.columns{grid-template-columns:1fr 1fr}table{display:block;overflow-x:auto}}@media(max-width:640px){header{padding:28px 24px}.language-entry,.no-js-fallback{margin:14px}.report-layout{padding:0 14px}.report-sidebar{display:block}.sidebar-navigation{display:block}.report-js .sidebar-toggle{display:inline-flex}.report-js .report-sidebar:not(.is-open) .sidebar-navigation{display:none}.sidebar-section+.sidebar-section{border-left:0;border-top:1px solid var(--line)}.grid,.columns{grid-template-columns:1fr}.process-tree-path{white-space:normal}}

""");
        html.AppendLine("</style></head>");
    }

    /// <summary>
    /// Appends the cover section with sample identity and verdict.
    /// Inputs are a StringBuilder and report, processing derives a verdict
    /// from findings and status, and the method returns no value.
    /// </summary>
    private static void AppendCover(StringBuilder html, AnalysisReport report)
    {
        var verdict = DetermineVerdict(report);
        html.AppendLine("<header id=\"cover\">");
        html.AppendLine("<h1>KSword Sandbox Report</h1>");
        html.AppendLine($"<p class=\"muted\">Job {E(report.JobId.ToString())} generated at {E(report.GeneratedAt.ToString("u"))}</p>");
        html.AppendLine($"<p><span class=\"badge badge-{E(verdict.Css)}\">{E(verdict.Label)}</span></p>");
        html.AppendLine("<table><tbody>");
        Row(html, "Sample", report.Sample.FileName);
        Row(html, "SHA-256", report.Sample.Sha256);
        Row(html, "Size", FormatBytes(report.Sample.SizeBytes));
        Row(html, "Status", report.Status.ToString());
        Row(html, "Virtualization provider", report.Provider?.ToString() ?? "Unknown");
        if (!string.IsNullOrWhiteSpace(report.TargetVmName))
        {
            Row(html, "Target VM", report.TargetVmName);
        }

        if (!string.IsNullOrWhiteSpace(report.BaselineName))
        {
            Row(html, "Clean baseline", report.BaselineName);
        }

        if (!string.IsNullOrWhiteSpace(report.MachineDefinitionPath))
        {
            var resourceLabel = report.Provider switch
            {
                VirtualizationProvider.VMware => "VMX path",
                VirtualizationProvider.Qemu => "QEMU base disk",
                _ => "Provider machine definition"
            };
            Row(html, resourceLabel, report.MachineDefinitionPath);
        }

        if (report.Provider is VirtualizationProvider.Qemu &&
            !string.IsNullOrWhiteSpace(report.QemuDiskFormat))
        {
            Row(html, "QEMU disk format", report.QemuDiskFormat);
        }

        html.AppendLine("</tbody></table>");
        html.AppendLine("</header>");
    }

    /// <summary>
    /// Appends local bilingual report entry points.
    /// Inputs are none because report files use stable sibling names;
    /// processing writes links for report.zh.html and report.en.html; the
    /// method returns no value.
    /// </summary>
    private static void AppendLanguageEntrypoints(StringBuilder html)
    {
        html.AppendLine("<nav class=\"card language-entry\" data-copy=\"report.html&#10;report.zh.html&#10;report.en.html\">");
        html.AppendLine("<strong>Report language</strong>");
        html.AppendLine("<a href=\"report.zh.html\">中文报告</a>");
        html.AppendLine("<a class=\"secondary\" href=\"report.en.html\">English report</a>");
        html.AppendLine("<a class=\"secondary\" href=\"report.html\">Default report</a>");
        html.AppendLine("<span class=\"hint\">Default report.html uses Simplified Chinese; report.en.html keeps English operator chrome. Evidence values stay original in both reports. The WebUI also serves these through /api/jobs/{jobId}/report/html?lang=zh and ?lang=en.</span>");
        html.AppendLine("</nav>");
    }

    /// <summary>
    /// Adds a static no-JavaScript/print fallback note. Inputs are the report
    /// shell builder; processing writes text-only guidance; return is none.
    /// </summary>
    private static void AppendNoScriptFallback(StringBuilder html)
    {
        html.AppendLine("<noscript><nav class=\"card no-js-fallback\">");
        html.AppendLine("<strong>Print/no-JS fallback</strong>");
        html.AppendLine("<span class=\"hint\">No JavaScript required for report navigation: native details, table scrolling, safe Open/Download artifact links, and the print stylesheet remain usable. Copy buttons require JavaScript; without it, select visible evidence text or use report.json/raw source hints.</span>");
        html.AppendLine("</nav></noscript>");
    }

    /// <summary>
    /// Appends fixed report navigation.
    /// Inputs are a StringBuilder, processing writes anchor links matching the
    /// target report structure, and the method returns no value.
    /// </summary>
    private static void AppendTableOfContents(StringBuilder html)
    {
        html.AppendLine("<nav id=\"toc\" class=\"sidebar-section toc\" aria-labelledby=\"toc-title\"><h2 id=\"toc-title\">Table of contents</h2><div class=\"toc-links\">");
        foreach (var (href, title) in new[]
        {
            ("cover", "Cover"),
            ("risk", "Risk summary"),
            ("behavior", "Behavior detections"),
            ("facts", "Aggregated behavior facts"),
            ("mitre", "Multi-dimensional / MITRE"),
            ("rules", "Engine and rule hits"),
            ("static", "Static analysis"),
            ("dynamic", "Dynamic analysis"),
            ("vt", "VirusTotal / reputation"),
            ("graph", "Behavior graph / IOC summary"),
            ("artifacts", "Artifact links"),
            ("timeline", "Timeline"),
            ("process", "Process details"),
            ("security", "Security / privilege telemetry"),
            ("files", "File system activity"),
            ("startup", "Startup / persistence diff"),
            ("registry", "Registry behavior"),
            ("network", "Network behavior"),
            ("r0", "R0 / driver events"),
            ("failure", "Failure reasons"),
            ("events", "Raw normalized events")
        })
        {
            html.AppendLine($"<a class=\"toc-link\" href=\"#{href}\">{E(title)}</a>");
        }

        html.AppendLine("</div></nav>");
    }

    /// <summary>
    /// Appends compact high-traffic shortcuts inside the report sidebar.
    /// Inputs are report counts and indexed artifacts; processing writes quick
    /// Process / Files / Network / R0 / VT / Artifacts quick navigation links;
    /// the method returns no value.
    /// </summary>
    private static void AppendQuickNavigation(StringBuilder html, AnalysisReport report, IReadOnlyCollection<ArtifactDescriptor> artifacts)
    {
        html.AppendLine("<nav id=\"quick-nav\" class=\"sidebar-section quick-nav\" aria-labelledby=\"quick-nav-title\">");
        html.AppendLine("<h2 id=\"quick-nav-title\">Quick navigation</h2>");
        html.AppendLine("<div class=\"quick-links\">");
        QuickLink(html, "risk", "Risk summary", PrimaryBehaviorFindings(report).Count().ToString());
        QuickLink(html, "facts", "Behavior facts", BuildBehaviorFactCards(report, artifacts).Count(card => card.EvidenceLines.Count > 0).ToString());
        QuickLink(html, "process", "Process details", report.Events.Count(IsSampleBehaviorProcessEvent).ToString());
        QuickLink(html, "security", "Security / privilege", report.Events.Count(IsSampleBehaviorSecurityPrivilegeEvent).ToString());
        QuickLink(html, "files", "File system activity", report.Events.Count(IsSampleBehaviorFileEvent).ToString());
        QuickLink(html, "startup", "Startup diff", report.Events.Count(IsSampleBehaviorStartupEvent).ToString());
        QuickLink(html, "network", "Network behavior", report.Events.Count(IsSampleBehaviorNetworkEvent).ToString());
        QuickLink(html, "r0", "R0 sample/health", report.Events.Count(IsR0Event).ToString());
        QuickLink(html, "vt", "VT lookups", report.Events.Count(IsVirusTotalEvent).ToString());
        QuickLink(html, "artifacts", "Artifact links", artifacts.Count.ToString());
        QuickLink(html, "events", "Raw normalized events", report.Events.Count.ToString());
        html.AppendLine("</div>");
        html.AppendLine("</nav>");
    }

    private static void QuickLink(StringBuilder html, string href, string label, string count)
    {
        html.AppendLine($"<a class=\"quick-link\" href=\"#{E(href)}\"><strong>{E(label)}</strong><small>{E(count)}</small></a>");
    }

    /// <summary>
    /// Appends high-level metrics similar to cloud sandbox summary cards.
    /// Inputs are a report, processing counts findings, MITRE hits, and event
    /// classes, and the method returns no value.
    /// </summary>
    private static void AppendRiskSummary(StringBuilder html, AnalysisReport report)
    {
        var primaryFindings = PrimaryBehaviorFindings(report).ToList();
        var staticFindings = StaticTriageFindings(report).ToList();
        var diagnosticFindings = DiagnosticFindings(report).ToList();
        html.AppendLine("<section id=\"risk\" class=\"card\"><h2>Risk summary</h2><div class=\"grid\">");
        Metric(html, "Critical / high risk", (CountSeverity(primaryFindings, "critical") + CountSeverity(primaryFindings, "high")).ToString(), "risk-high");
        Metric(html, "Suspicious", CountSeverity(primaryFindings, "medium").ToString(), "risk-medium");
        Metric(html, "General / info", (CountSeverity(primaryFindings, "low") + CountSeverity(primaryFindings, "info")).ToString(), "risk-info");
        Metric(html, "Static triage", staticFindings.Count.ToString(), staticFindings.Any(f => SeverityRank(f.Severity) <= SeverityRank("medium")) ? "risk-medium" : "risk-info");
        Metric(html, "Collection diagnostics", diagnosticFindings.Count.ToString(), diagnosticFindings.Count > 0 ? "risk-info" : "risk-low");
        Metric(html, "Collection health", report.Events.Count(IsCollectionHealthEvent).ToString(), report.Events.Any(IsCollectionHealthAlertEvent) ? "risk-medium" : "risk-info");
        Metric(html, "MITRE techniques", primaryFindings.Where(f => !string.IsNullOrWhiteSpace(f.MitreTechniqueId)).Select(f => f.MitreTechniqueId).Distinct().Count().ToString(), "risk-low");
        Metric(html, "Events", report.Events.Count.ToString(), "risk-info");
        Metric(html, "Rule hits", report.Findings.Count.ToString(), "risk-info");
        Metric(html, "VT lookups", report.Events.Count(IsVirusTotalEvent).ToString(), "risk-info");
        Metric(html, "Static tags", (report.StaticAnalysis?.Tags.Count ?? 0).ToString(), "risk-info");
        Metric(html, "Static URL refs", (report.StaticAnalysis?.Urls.Count ?? 0).ToString(), "risk-info");
        Metric(html, "File events", report.Events.Count(IsSampleBehaviorFileEvent).ToString(), "risk-medium");
        Metric(html, "Network events", report.Events.Count(IsSampleBehaviorNetworkEvent).ToString(), "risk-medium");
        Metric(html, "Registry events", report.Events.Count(IsSampleBehaviorRegistryEvent).ToString(), "risk-medium");
        Metric(html, "R0 sample telemetry", report.Events.Count(IsSampleBehaviorR0Event).ToString(), "risk-info");
        Metric(html, "R0 health/readiness", report.Events.Count(IsR0CollectionHealthEvent).ToString(), "risk-info");
        html.AppendLine("</div>");
        AppendCollectionSelfNoisePolicySummary(html, report);
        html.AppendLine("</section>");
    }


    private static BehaviorRoutingStats BuildBehaviorRoutingStats(IReadOnlyCollection<SandboxEvent> events)
    {
        var correlationConfirmed = events.Count(evt => TextEqualsAny(FirstEventDataValue(evt, "sampleCorrelation", "sample_correlation") ?? string.Empty, "confirmed"));
        var correlationProbable = events.Count(evt => TextEqualsAny(FirstEventDataValue(evt, "sampleCorrelation", "sample_correlation") ?? string.Empty, "probable"));
        var correlationEnvironment = events.Count(evt => TextEqualsAny(FirstEventDataValue(evt, "sampleCorrelation", "sample_correlation") ?? string.Empty, "environment"));
        var correlationUnknown = events.Count(evt => TextEqualsAny(FirstEventDataValue(evt, "sampleCorrelation", "sample_correlation") ?? string.Empty, "unknown", "uncorrelated"));
        var evidenceDispositionRetained = events.Count(evt => TextEqualsAny(FirstEventDataValue(evt, "evidenceDisposition", "evidence_disposition") ?? string.Empty, "retained-not-promoted", "retained_not_promoted"));
        var weakCorrelation = events.Count(IsWeakOrEnvironmentalSampleCorrelationEvent);
        var nonBehavior = events.Count(IsNonBehaviorEvent);
        var notSample = events.Count(IsNotSampleBehaviorMarkerEvent);
        var sampleCandidateFalse = events.Count(IsSampleBehaviorCandidateFalseEvent);
        var behaviorCountedFalse = events.Count(IsBehaviorCountedFalseEvent);
        return new BehaviorRoutingStats(
            events.Count,
            events.Count(IsSampleBehaviorEvent),
            events.Count(IsExcludedFromBehaviorStoryEvent),
            behaviorCountedFalse,
            nonBehavior,
            notSample,
            events.Count(IsCollectorSelfNoiseEvent),
            events.Count(evt => EventDataBoolTrue(evt, "collectorNoise", "collectionNoise", "noise")),
            events.Count(IsCollectionHealthEvent),
            events.Count(IsVirusTotalQuietStateEvent),
            events.Count(IsR0CollectionHealthEvent),
            correlationConfirmed,
            correlationProbable,
            correlationEnvironment,
            correlationUnknown,
            events.Count(evt => IsWeakOrEnvironmentalSampleCorrelationEvent(evt) || IsNonBehaviorEvent(evt) || IsNotSampleBehaviorMarkerEvent(evt) || IsSampleBehaviorCandidateFalseEvent(evt) || TextEqualsAny(FirstEventDataValue(evt, "evidenceDisposition", "evidence_disposition") ?? string.Empty, "retained-not-promoted", "retained_not_promoted")),
            events.Count(evt => TextEqualsAny(FirstEventDataValue(evt, "normalBehaviorBoundary", "sampleCorrelationBoundary") ?? string.Empty, "normal-interactive-gui-baseline")),
            evidenceDispositionRetained);
    }

    private static object BuildBehaviorRoutingStatsPayload(BehaviorRoutingStats stats) => new
    {
        schema = "ksword.report.behavior-routing-stats.v1",
        policy = "retained_not_promoted",
        stats.TotalEvents,
        stats.SampleBehaviorEvents,
        stats.ExcludedFromBehaviorStory,
        stats.BehaviorCountedFalse,
        stats.NonBehavior,
        stats.NotSampleBehavior,
        stats.CollectorSelfNoise,
        stats.CollectorNoise,
        stats.CollectionHealthRows,
        stats.VtQuietStates,
        stats.R0HealthRows,
        stats.RetainedNotPromoted,
        stats.NormalInteractiveGuiBaseline,
        stats.EvidenceDispositionRetainedNotPromoted,
        correlation = new
        {
            confirmed = stats.CorrelationConfirmed,
            probable = stats.CorrelationProbable,
            environment = stats.CorrelationEnvironment,
            unknown = stats.CorrelationUnknown
        },
        conclusionBoundary = "environment/unknown/nonbehavior/readiness evidence is retained in raw evidence but not promoted to primary sample conclusions"
    };

    /// <summary>
    /// Appends an early, compact evidence-quality policy card. Inputs are all
    /// normalized events; processing counts rows intentionally excluded from
    /// behavior storytelling while preserving raw evidence; return is none.
    /// </summary>
    private static void AppendCollectionSelfNoisePolicySummary(StringBuilder html, AnalysisReport report)
    {
        var stats = BuildBehaviorRoutingStats(report.Events);
        var behaviorCountedFalse = stats.BehaviorCountedFalse;
        var nonBehavior = stats.NonBehavior;
        var notSampleBehavior = stats.NotSampleBehavior;
        var collectorSelfNoise = stats.CollectorSelfNoise;
        var vtQuiet = stats.VtQuietStates;
        var r0Health = stats.R0HealthRows;
        var excludedUnion = stats.ExcludedFromBehaviorStory;
        var sampleBehavior = stats.SampleBehaviorEvents;
        var machineStats = BuildBehaviorRoutingStatsPayload(stats);
        var statsJson = JsonSerializer.Serialize(machineStats, ArtifactJsonOptions);
        var copy = string.Join(
            Environment.NewLine,
            [
                "Collection/self-noise policy",
                $"sampleBehaviorEvents={sampleBehavior}",
                $"excludedFromBehaviorStory={excludedUnion}",
                $"behaviorCountedFalse={behaviorCountedFalse}",
                $"nonbehavior={nonBehavior}",
                $"notSampleBehavior={notSampleBehavior}",
                $"collectorSelfNoise={collectorSelfNoise}",
                $"collectorNoise={stats.CollectorNoise}",
                $"collectionHealthRows={stats.CollectionHealthRows}",
                $"vtQuietStates={vtQuiet}",
                $"r0HealthRows={r0Health}",
                $"correlationConfirmed={stats.CorrelationConfirmed}",
                $"correlationProbable={stats.CorrelationProbable}",
                $"correlationEnvironment={stats.CorrelationEnvironment}",
                $"correlationUnknown={stats.CorrelationUnknown}",
                $"retainedNotPromoted={stats.RetainedNotPromoted}",
                $"normalInteractiveGuiBaseline={stats.NormalInteractiveGuiBaseline}",
                "policy=Excluded rows are collection/reputation/health evidence, not sample behavior. Raw normalized events and source artifacts remain complete when indexed; report.json is a sampled normalized report view.",
                "machineReadableJson:",
                statsJson
            ]);

        html.AppendLine("<h3>Collection/self-noise policy</h3>");
        html.AppendLine("<div class=\"compact-evidence-summary copyable\" data-copy=\"" + A(copy) + "\"><strong>Collection/self-noise policy.</strong><br>");
        html.AppendLine("Behavior story counts exclude rows marked <code>behaviorCounted=false</code>, <code>nonbehavior</code>, <code>notSampleBehavior</code>, collector self-noise, VT quiet states, and R0 health/readiness diagnostics. These rows remain visible in their dedicated sections and in Raw normalized events/report.json; raw pagination and folded evidence are unchanged.");
        html.AppendLine("<div class=\"story-metrics\">");
        html.AppendLine($"<span>sample behavior {E(sampleBehavior.ToString(CultureInfo.InvariantCulture))}</span>");
        html.AppendLine($"<span>excluded union {E(excludedUnion.ToString(CultureInfo.InvariantCulture))}</span>");
        html.AppendLine($"<span>behaviorCounted=false {E(behaviorCountedFalse.ToString(CultureInfo.InvariantCulture))}</span>");
        html.AppendLine($"<span>nonbehavior {E(nonBehavior.ToString(CultureInfo.InvariantCulture))}</span>");
        html.AppendLine($"<span>notSampleBehavior {E(notSampleBehavior.ToString(CultureInfo.InvariantCulture))}</span>");
        html.AppendLine($"<span>collectorSelfNoise {E(collectorSelfNoise.ToString(CultureInfo.InvariantCulture))}</span>");
        html.AppendLine($"<span>VT quiet {E(vtQuiet.ToString(CultureInfo.InvariantCulture))}</span>");
        html.AppendLine($"<span>R0 health {E(r0Health.ToString(CultureInfo.InvariantCulture))}</span>");
        html.AppendLine("</div>");
        html.AppendLine($"<div class=\"toolbar\">{CopyButton("Copy collection policy", copy)}</div></div>");
    }

    /// <summary>
    /// Appends behavior detections grouped by severity.
    /// Inputs are a report and output builder, processing orders findings by
    /// severity and evidence count, and the method returns no value.
    /// </summary>
    private static void AppendBehaviorDetections(StringBuilder html, AnalysisReport report)
    {
        html.AppendLine("<section id=\"behavior\" class=\"card\"><h2>Behavior detections</h2>");
        var findings = PrimaryBehaviorFindings(report)
            .OrderBy(f => SeverityRank(f.Severity))
            .ThenBy(f => f.Title)
            .ToList();
        var staticFindings = StaticTriageFindings(report).OrderBy(f => SeverityRank(f.Severity)).ThenBy(f => f.Title).ToList();
        var diagnosticFindings = DiagnosticFindings(report).OrderBy(f => f.Title).ToList();
        if (findings.Count == 0)
        {
            Empty(html, "No primary sample behavior rules matched. Static triage and collection diagnostics are separated below so operational health does not inflate the verdict.");
        }
        else
        {
            html.AppendLine("<table><thead><tr><th>Severity</th><th>Behavior</th><th>Evidence</th></tr></thead><tbody>");
            foreach (var finding in findings)
            {
                html.AppendLine($"<tr><td class=\"risk-{E(NormalizeSeverity(finding.Severity))}\">{E(finding.Severity)}</td><td><strong>{E(finding.Title)}</strong><br><span class=\"muted\">{E(finding.Summary)}</span></td><td>{RenderFindingEvidence(finding.Evidence)}</td></tr>");
            }

            html.AppendLine("</tbody></table>");
        }

        AppendSecondaryFindingGroup(
            html,
            "Static triage indicators",
            "Static-only findings are useful triage signals, but they do not by themselves prove runtime malicious behavior.",
            staticFindings);
        AppendSecondaryFindingGroup(
            html,
            "Collection and pipeline diagnostics",
            "Collector health, runbook, import, and timing diagnostics explain evidence quality and are not sample behavior.",
            diagnosticFindings);
        html.AppendLine("</section>");
    }

    /// <summary>
    /// Appends a high-signal fact view ahead of raw timelines/tables.
    /// Inputs are normalized report events and indexed artifacts; processing
    /// groups sample-behavior rows into operator statements that explain what
    /// happened, the supporting evidence, and why the behavior deserves review.
    /// </summary>
    private static void AppendAggregatedBehaviorFacts(
        StringBuilder html,
        AnalysisReport report,
        IReadOnlyCollection<ArtifactDescriptor> artifacts)
    {
        var cards = BuildBehaviorFactCards(report, artifacts).ToList();
        html.AppendLine("<section id=\"facts\" class=\"card\"><h2>Aggregated behavior facts</h2>");
        html.AppendLine("<div class=\"section-note\"><strong>Behavior facts before raw events.</strong> This section groups normalized events into reviewer-facing facts. It does not remove evidence: raw normalized events, source JSON/JSONL, and artifact links remain available later in the report.</div>");

        if (report.Events.Count == 0)
        {
            Empty(html, "No dynamic events were imported, so no aggregated behavior facts can be derived. This is an evidence gap, not proof of benign behavior.");
            html.AppendLine("</section>");
            return;
        }

        html.AppendLine("<div class=\"evidence-story-board\">");
        foreach (var card in cards)
        {
            var evidenceText = card.EvidenceLines.Count == 0
                ? "No supporting sample-behavior evidence rows were collected for this lane."
                : string.Join(Environment.NewLine, card.EvidenceLines);
            var copy = string.Join(
                Environment.NewLine,
                [
                    card.Title,
                    $"value={card.Value}",
                    $"whatHappened={card.WhatHappened}",
                    $"whyReview={card.WhySuspicious}",
                    "evidence:",
                    evidenceText
                ]);

            html.AppendLine($"<article class=\"evidence-story-lane copyable\" data-copy=\"{A(copy)}\">");
            html.AppendLine($"<h3>{E(card.Title)}</h3>");
            html.AppendLine($"<span class=\"overview-value {E(card.Css)}\">{E(card.Value)}</span>");
            html.AppendLine($"<p><strong>What happened:</strong> {E(card.WhatHappened)}</p>");
            html.AppendLine($"<p><strong>Why review:</strong> {E(card.WhySuspicious)}</p>");
            if (card.EvidenceLines.Count == 0)
            {
                Empty(html, "No sample-attributed evidence for this lane.");
            }
            else
            {
                html.AppendLine("<ol class=\"story-evidence-list\">");
                foreach (var line in card.EvidenceLines.Take(EvidenceStoryInlineLimit))
                {
                    html.AppendLine($"<li><code>{E(line)}</code></li>");
                }

                html.AppendLine("</ol>");
            }

            html.AppendLine($"<div class=\"toolbar\">{CopyButton("Copy behavior fact", copy)}</div>");
            html.AppendLine("</article>");
        }

        html.AppendLine("</div></section>");
    }

    private static IReadOnlyList<BehaviorFactCard> BuildBehaviorFactCards(
        AnalysisReport report,
        IReadOnlyCollection<ArtifactDescriptor> artifacts)
    {
        var sampleEvents = report.Events
            .Where(IsSampleBehaviorEvent)
            .OrderBy(evt => evt.Timestamp)
            .ToList();
        var processEvents = sampleEvents
            .Where(evt => IsSampleBehaviorProcessEvent(evt) || IsProcessAccessStyleEvent(evt))
            .ToList();
        var startupEvents = sampleEvents.Where(IsStartupEvent).ToList();
        var networkEvents = sampleEvents.Where(IsNetworkEvent).ToList();
        var fileEvents = sampleEvents.Where(IsFileEvent).ToList();
        var registryEvents = sampleEvents.Where(IsRegistryEvent).ToList();
        var securityEvents = sampleEvents.Where(IsSecurityPrivilegeFallbackEvent).ToList();
        var r0Events = sampleEvents.Where(evt => IsR0Event(evt) && !IsR0CollectionHealthEvent(evt)).ToList();
        var droppedArtifacts = artifacts
            .Where(artifact => artifact.Kind == ArtifactKind.DroppedFile && !IsCollectorSelfNoiseArtifact(artifact))
            .ToList();
        var screenshots = artifacts
            .Where(artifact => artifact.Kind == ArtifactKind.Screenshot && !IsCollectorSelfNoiseArtifact(artifact))
            .ToList();
        var memoryDumps = artifacts
            .Where(artifact => artifact.Kind == ArtifactKind.MemoryDump && !IsCollectorSelfNoiseArtifact(artifact))
            .ToList();
        var pcaps = artifacts
            .Where(artifact => artifact.Kind == ArtifactKind.PacketCapture && !IsCollectorSelfNoiseArtifact(artifact))
            .ToList();

        var processIdentities = processEvents
            .Select(ProcessDisplayName)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(6)
            .ToList();
        var startupSurfaces = startupEvents
            .Select(evt => FirstNonEmpty(FirstEventDataValue(evt, "startupSurface"), FirstEventDataValue(evt, "startupCategory"), evt.EventType))
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(8)
            .ToList();
        var networkTargets = ExtractNetworkIocs(report).Take(8).ToList();
        var fileTargets = ExtractFileIocs(report).Take(8).ToList();
        var registryTargets = ExtractRegistryIocs(report).Take(8).ToList();
        var artifactNames = artifacts
            .Where(artifact => !IsCollectorSelfNoiseArtifact(artifact))
            .Select(ArtifactDisplayName)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(8)
            .ToList();

        return
        [
            new BehaviorFactCard(
                "Execution and parent/child activity",
                processEvents.Count == 0 ? "0 rows" : $"{processIdentities.Count} actors",
                processEvents.Count > 0 ? "risk-info" : "risk-low",
                processEvents.Count == 0
                    ? "No sample-attributed process or process-access rows were embedded in this report view."
                    : $"Observed {processEvents.Count} process/process-access rows across {processIdentities.Count} visible actor identity/identities: {FirstNonEmpty(string.Join(", ", processIdentities), "-")}.",
                "Execution lineage is the anchor for attributing file, registry, network, startup, and artifact evidence to the sample instead of to sandbox plumbing.",
                TopEvidenceLines(processEvents, 8)),
            new BehaviorFactCard(
                "Startup persistence before/after diff",
                $"{startupEvents.Count} rows",
                startupEvents.Count(evt => TextEqualsAny(FirstEventDataValue(evt, "change") ?? string.Empty, "created", "modified") || StartupEventHasUserWritableTarget(evt)) > 0 ? "risk-high" : startupEvents.Count > 0 ? "risk-medium" : "risk-low",
                startupEvents.Count == 0
                    ? "No startup.* or legacy startup diff rows were collected or imported."
                    : $"Observed startup inventory changes on {startupSurfaces.Count} surface(s): {FirstNonEmpty(string.Join(", ", startupSurfaces), "-")}. Created/modified rows={startupEvents.Count(evt => TextEqualsAny(FirstEventDataValue(evt, "change") ?? string.Empty, "created", "modified"))}; deleted rows={startupEvents.Count(evt => TextEqualsAny(FirstEventDataValue(evt, "change") ?? string.Empty, "deleted"))}.",
                "New or modified autostart entries are high signal because they can survive reboot. User-writable targets, WMI subscriptions, drivers, services, IFEO, Winlogon, LSA, AppInit, Winsock, and shell-extension surfaces deserve priority review.",
                TopEvidenceLines(startupEvents, 8)),
            new BehaviorFactCard(
                "Network communication scope",
                networkEvents.Count == 0 ? "0 rows" : $"{networkTargets.Count} IOCs",
                networkEvents.Count > 0 ? "risk-medium" : "risk-low",
                networkEvents.Count == 0
                    ? "No sample-attributed DNS/HTTP/TLS/flow rows were embedded in this report view."
                    : $"Observed {networkEvents.Count} network rows. Top normalized targets: {FirstNonEmpty(string.Join(", ", networkTargets), "-")}.",
                "Network facts are grouped by endpoint/protocol so DNS, HTTP, TLS, PCAP, and R0 network rows do not overwhelm the reviewer as independent raw events.",
                TopEvidenceLines(networkEvents, 8)),
            new BehaviorFactCard(
                "File and dropped-artifact activity",
                $"{fileEvents.Count + droppedArtifacts.Count} items",
                fileEvents.Count + droppedArtifacts.Count > 0 ? "risk-medium" : "risk-low",
                fileEvents.Count + droppedArtifacts.Count == 0
                    ? "No sample-attributed file writes or dropped-file artifacts were collected."
                    : $"Observed {fileEvents.Count} file rows and {droppedArtifacts.Count} dropped-file artifact(s). Top paths: {FirstNonEmpty(string.Join(", ", fileTargets), "-")}.",
                "Dropped files and user-writable writes are stronger evidence when paired with hashes, safe download selectors, or later execution/startup references.",
                TopEvidenceLines(fileEvents, 6)
                    .Concat(droppedArtifacts.Take(4).Select(ArtifactFactLine))
                    .ToList()),
            new BehaviorFactCard(
                "Registry mutation scope",
                $"{registryEvents.Count} rows",
                registryEvents.Count > 0 ? "risk-medium" : "risk-low",
                registryEvents.Count == 0
                    ? "No sample-attributed registry mutation rows were embedded in this report view."
                    : $"Observed {registryEvents.Count} registry rows. Top keys/values: {FirstNonEmpty(string.Join(", ", registryTargets), "-")}.",
                "Registry writes become more suspicious when they map to persistence, credential access, policy weakening, COM hijack, IFEO, LSA, AppInit, or other startup surfaces.",
                TopEvidenceLines(registryEvents, 8)),
            new BehaviorFactCard(
                "R0/security gap-filling telemetry",
                $"{r0Events.Count + securityEvents.Count} rows",
                r0Events.Count + securityEvents.Count > 0 ? "risk-info" : "risk-low",
                r0Events.Count + securityEvents.Count == 0
                    ? "No sample-attributed R0/security privilege rows were embedded in this report view."
                    : $"Observed {r0Events.Count} R0/driver rows and {securityEvents.Count} security/privilege rows. Health/readiness rows remain outside this fact count.",
                "R0 is treated as the primary source for process/image/kernel events; Windows Security/ETW-style rows fill privilege, service, task, object-access, and auxiliary gaps without being mixed with collector health.",
                TopEvidenceLines(r0Events.Concat(securityEvents).OrderBy(evt => evt.Timestamp).ToList(), 8)),
            new BehaviorFactCard(
                "Artifact evidence readiness",
                $"{artifacts.Count} indexed",
                artifacts.Count > 0 ? "risk-info" : "risk-low",
                artifacts.Count == 0
                    ? "No report artifact index entries were supplied or inferred."
                    : $"Indexed artifacts include dropped files={droppedArtifacts.Count}, screenshots={screenshots.Count}, memory dumps={memoryDumps.Count}, packet captures={pcaps.Count}. Top selectors: {FirstNonEmpty(string.Join(", ", artifactNames), "-")}.",
                "Artifacts turn event claims into reviewable evidence. Missing artifacts should be reported honestly as collection gaps rather than fabricated behavior.",
                artifacts
                    .Where(artifact => !IsCollectorSelfNoiseArtifact(artifact))
                    .Take(8)
                    .Select(ArtifactFactLine)
                    .ToList())
        ];
    }

    private static IReadOnlyList<string> TopEvidenceLines(IEnumerable<SandboxEvent> events, int limit)
    {
        return events
            .OrderBy(evt => evt.Timestamp)
            .Take(limit)
            .Select(EventOneLine)
            .ToList();
    }

    private static string ArtifactFactLine(ArtifactDescriptor artifact)
    {
        var selector = FirstNonEmpty(MetadataValue(artifact.Metadata, "downloadSelector", "safeRelativeSelector"), artifact.SafeLink, artifact.RelativePath, artifact.ImportPath, "-");
        var hash = FirstNonEmpty(artifact.Sha256, artifact.Hashes.GetValueOrDefault("sha256"), "-");
        return $"artifact={ArtifactDisplayName(artifact)} | kind={artifact.Kind} | selector={selector} | size={FormatBytes(Math.Max(0, artifact.SizeBytes))} | sha256={hash}";
    }

    private static void AppendSecondaryFindingGroup(
        StringBuilder html,
        string title,
        string note,
        IReadOnlyCollection<BehaviorFinding> findings)
    {
        html.AppendLine($"<details class=\"relationship-details\"><summary>{E(title)} ({E(findings.Count.ToString())})</summary>");
        html.AppendLine($"<p class=\"muted\">{E(note)}</p>");
        if (findings.Count == 0)
        {
            Empty(html, "None.");
            html.AppendLine("</details>");
            return;
        }

        html.AppendLine("<table><thead><tr><th>Severity</th><th>Indicator</th><th>Evidence</th></tr></thead><tbody>");
        foreach (var finding in findings)
        {
            html.AppendLine($"<tr><td class=\"risk-{E(NormalizeSeverity(finding.Severity))}\">{E(finding.Severity)}</td><td><strong>{E(finding.Title)}</strong><br><span class=\"muted\">{E(finding.Summary)}</span></td><td>{RenderFindingEvidence(finding.Evidence)}</td></tr>");
        }

        html.AppendLine("</tbody></table></details>");
    }

    /// <summary>
    /// Renders top evidence directly under one behavior finding.
    /// Inputs are the normalized events attached by the rule engine; processing
    /// keeps the row compact but expandable; the method returns encoded HTML.
    /// </summary>
    private static string RenderFindingEvidence(IReadOnlyCollection<SandboxEvent> evidence)
    {
        if (evidence.Count == 0)
        {
            return "<span class=\"muted\">0 evidence events</span>";
        }

        const int inlineLimit = 5;
        var topEvidence = evidence.Take(inlineLimit).ToList();
        var hidden = Math.Max(0, evidence.Count - topEvidence.Count);
        var summary = $"{evidence.Count} evidence events";
        var compact = string.Join(Environment.NewLine, topEvidence.Select(EventOneLine));
        var full = string.Join(
            Environment.NewLine + Environment.NewLine,
            topEvidence.Select(evt => EventToBoundedPlainText(evt, FindingEvidenceDataPairLimit, FindingEvidenceValueLimit)));
        if (hidden > 0)
        {
            compact += Environment.NewLine + $"... {hidden} more evidence events hidden in raw events/report.json";
            full += Environment.NewLine + Environment.NewLine + $"... {hidden} more evidence events hidden in raw events/report.json";
        }

        return
            $"<span class=\"inline-actions\">{CopyButton("Copy behavior evidence", full)}<span class=\"evidence-count copyable\" data-copy=\"{A(summary)}\">{E(summary)}</span></span>" +
            $"<details class=\"flat-details\"><summary>Top evidence summary</summary><pre class=\"copyable\" data-copy=\"{A(full)}\">{E(compact)}</pre></details>";
    }

    /// <summary>
    /// Appends ATT&CK mapping rows for findings with technique metadata.
    /// Inputs are a report and output builder, processing groups findings by
    /// MITRE technique, and the method returns no value.
    /// </summary>
    private static void AppendMitreDetections(StringBuilder html, AnalysisReport report)
    {
        html.AppendLine("<section id=\"mitre\" class=\"card\"><h2>Multi-dimensional / MITRE detections</h2>");
        var groups = PrimaryBehaviorFindings(report)
            .Where(f => !string.IsNullOrWhiteSpace(f.MitreTechniqueId))
            .GroupBy(f => new { f.MitreTechniqueId, f.MitreTechniqueName })
            .OrderBy(g => g.Key.MitreTechniqueId)
            .ToList();
        if (groups.Count == 0)
        {
            Empty(html, "No MITRE ATT&CK techniques mapped yet.");
        }
        else
        {
            html.AppendLine("<table><thead><tr><th>Technique</th><th>Name</th><th>Rules</th><th>Evidence</th></tr></thead><tbody>");
            foreach (var group in groups)
            {
                html.AppendLine($"<tr><td>{E(group.Key.MitreTechniqueId ?? "-")}</td><td>{E(group.Key.MitreTechniqueName ?? "-")}</td><td>{E(string.Join(", ", group.Select(f => f.RuleId)))}</td><td>{group.Sum(f => f.Evidence.Count)}</td></tr>");
            }

            html.AppendLine("</tbody></table>");
        }

        html.AppendLine("</section>");
    }

    /// <summary>
    /// Appends local engine and rule-hit details.
    /// Inputs are a report and output builder, processing lists rule metadata,
    /// and the method returns no value.
    /// </summary>
    private static void AppendRuleHits(StringBuilder html, AnalysisReport report)
    {
        html.AppendLine("<section id=\"rules\" class=\"card\"><h2>Engine and rule hits</h2>");
        if (report.Findings.Count == 0)
        {
            Empty(html, "No local behavior, YARA, or static rules matched in this artifact.");
        }
        else
        {
            html.AppendLine("<table><thead><tr><th>Engine</th><th>Rule ID</th><th>Title</th><th>Severity</th></tr></thead><tbody>");
            foreach (var finding in report.Findings.OrderBy(f => f.RuleId))
            {
                html.AppendLine($"<tr><td>KSword behavior rules</td><td><code>{E(finding.RuleId)}</code></td><td>{E(finding.Title)}</td><td>{E(finding.Severity)}</td></tr>");
            }

            html.AppendLine("</tbody></table>");
        }

        html.AppendLine("</section>");
    }

    /// <summary>
    /// Appends static sample identity fields.
    /// Inputs are a report and output builder, processing writes hash and file
    /// metadata available in v1, and the method returns no value.
    /// </summary>
    private static void AppendStaticAnalysis(StringBuilder html, AnalysisReport report)
    {
        var staticAnalysis = report.StaticAnalysis;
        html.AppendLine("<section id=\"static\" class=\"card\"><h2>Static analysis</h2><table><tbody>");
        Row(html, "File name", report.Sample.FileName);
        Row(html, "Full path", report.Sample.FullPath);
        Row(html, "File size", FormatBytes(report.Sample.SizeBytes));
        Row(html, "SHA-256", report.Sample.Sha256);
        Row(html, "SHA-1", report.Sample.Sha1);
        Row(html, "MD5", report.Sample.Md5);
        Row(html, "CRC32", report.Sample.Crc32);
        Row(html, "File format", staticAnalysis?.FileFormat ?? "unknown");
        Row(html, "Magic", staticAnalysis?.Magic ?? "unknown");
        Row(html, "Architecture", staticAnalysis?.Architecture ?? "-");
        Row(html, "Subsystem", staticAnalysis?.Subsystem ?? "-");
        Row(html, "Entry point RVA", staticAnalysis?.EntryPointRva ?? "-");
        Row(html, "Tags", staticAnalysis is null || staticAnalysis.Tags.Count == 0 ? "-" : string.Join(", ", staticAnalysis.Tags));
        html.AppendLine("</tbody></table>");

        if (staticAnalysis is null)
        {
            Empty(html, "Static analyzer did not run.");
            html.AppendLine("</section>");
            return;
        }

        AppendSectionTable(html, staticAnalysis);
        AppendStaticResourceStory(html, staticAnalysis, report.Events);
        AppendStaticEvidenceGroups(html, staticAnalysis);
        AppendStringList(html, "Interesting strings", staticAnalysis.InterestingStrings);
        AppendStringList(html, "Static warnings", staticAnalysis.Warnings);
        html.AppendLine("</section>");
    }

    /// <summary>
    /// Appends PE section metadata.
    /// Inputs are static-analysis results, processing writes section rows or an
    /// empty state, and the method returns no value.
    /// </summary>
    private static void AppendSectionTable(StringBuilder html, StaticAnalysisResult staticAnalysis)
    {
        html.AppendLine("<h3>PE sections</h3>");
        if (staticAnalysis.Sections.Count == 0)
        {
            Empty(html, "No PE sections parsed.");
            return;
        }

        html.AppendLine("<table><thead><tr><th>Name</th><th>VA</th><th>Virtual size</th><th>Raw size</th><th>Entropy</th><th>Signal</th></tr></thead><tbody>");
        foreach (var section in staticAnalysis.Sections)
        {
            var signal = DescribeSectionSignal(section);
            html.AppendLine($"<tr class=\"copyable\" data-copy=\"{A(SectionToPlainText(section, signal))}\"><td>{E(section.Name)}</td><td><code>{E(section.VirtualAddress)}</code></td><td>{section.VirtualSize}</td><td>{section.RawDataSize}</td><td>{section.Entropy:F3}</td><td>{E(signal)}</td></tr>");
        }

        html.AppendLine("</tbody></table>");
    }

    /// <summary>
    /// Appends a resource-oriented static payload story before the legacy
    /// string map. Inputs are structured PE resources and matching
    /// static.pe.resource events; processing highlights embedded PE,
    /// high-entropy, large, and payload-candidate resources as copyable rows
    /// while keeping the report schema unchanged.
    /// </summary>
    private static void AppendStaticResourceStory(
        StringBuilder html,
        StaticAnalysisResult staticAnalysis,
        IReadOnlyCollection<SandboxEvent> events)
    {
        var resourceEvents = events
            .Where(evt => string.Equals(evt.EventType, "static.pe.resource", StringComparison.OrdinalIgnoreCase))
            .OrderBy(evt => evt.Timestamp)
            .ToList();
        var resources = staticAnalysis.Resources
            .OrderByDescending(resource => resource.IsEmbeddedPe)
            .ThenByDescending(resource => resource.IsPayloadCandidate)
            .ThenByDescending(resource => resource.Entropy ?? -1)
            .ThenBy(resource => resource.ResourceType, StringComparer.OrdinalIgnoreCase)
            .Take(40)
            .ToList();

        html.AppendLine("<h3>Static PE resource story</h3>");
        html.AppendLine("<div class=\"section-note\"><strong>Resource payload triage.</strong> Structured <code>static.pe.resource</code> evidence highlights resourceRole, embedded-PE markers, entropy, and size so payload candidates are visible before opening raw static events.</div>");
        html.AppendLine("<div class=\"overview-strip static-resource-overview\">");
        AppendOverviewItem(
            html,
            "Resource entries",
            staticAnalysis.Resources.Count.ToString(CultureInfo.InvariantCulture),
            $"Embedded PE: {staticAnalysis.Resources.Count(resource => resource.IsEmbeddedPe)}; payload candidates: {staticAnalysis.Resources.Count(resource => resource.IsPayloadCandidate)}.",
            staticAnalysis.Resources.Any(resource => resource.IsEmbeddedPe || resource.IsPayloadCandidate) ? "risk-medium" : "risk-info");
        AppendOverviewItem(
            html,
            "High-entropy resources",
            staticAnalysis.Resources.Count(resource => resource.Entropy >= 7.2).ToString(CultureInfo.InvariantCulture),
            "High entropy can indicate compressed/encrypted payload bytes; correlate with dropped files and runtime execution.",
            staticAnalysis.Resources.Any(resource => resource.Entropy >= 7.2) ? "risk-medium" : "risk-low");
        AppendOverviewItem(
            html,
            "Resource events",
            resourceEvents.Count.ToString(CultureInfo.InvariantCulture),
            "Normalized static.pe.resource rows are preserved for behavior rules and raw evidence expansion.",
            resourceEvents.Count > 0 ? "risk-info" : "risk-low");
        html.AppendLine("</div>");

        if (resources.Count == 0 && resourceEvents.Count == 0)
        {
            Empty(html, "No structured PE resource entries or static.pe.resource events were recorded.");
            return;
        }

        if (resources.Count > 0)
        {
            html.AppendLine("<table><thead><tr><th>Type</th><th>Role</th><th>RVA / file offset</th><th>Size</th><th>Entropy</th><th>Flags</th></tr></thead><tbody>");
            foreach (var resource in resources)
            {
                var role = DescribeReportResourceRole(resource);
                var flags = StaticResourceFlags(resource);
                var copy = StaticResourceToPlainText(resource, role, flags);
                html.AppendLine($"<tr class=\"copyable\" data-copy=\"{A(copy)}\"><td><code>{E(resource.ResourceType)}</code></td><td><span class=\"chip chip-info\">{E(role)}</span></td><td><code>{E(resource.DataRva)}</code><br><span class=\"muted\">{E(resource.DataFileOffset ?? "-")}</span></td><td>{E(FormatBytes(resource.Size))}</td><td>{E(resource.Entropy?.ToString("F3", CultureInfo.InvariantCulture) ?? "-")}<br><span class=\"muted\">{E(resource.EntropyLabel)}</span></td><td>{E(flags)}</td></tr>");
            }

            html.AppendLine("</tbody></table>");
        }

        if (resourceEvents.Count > 0)
        {
            var evidenceText = string.Join(Environment.NewLine, resourceEvents.Take(12).Select(EventOneLine));
            html.AppendLine($"<details class=\"evidence-expansion-card\"><summary>static.pe.resource normalized evidence ({E(Math.Min(resourceEvents.Count, 12).ToString(CultureInfo.InvariantCulture))}/{E(resourceEvents.Count.ToString(CultureInfo.InvariantCulture))})</summary><pre class=\"copyable\" data-copy=\"{A(evidenceText)}\">{E(evidenceText)}</pre></details>");
        }
    }

    private static string DescribeReportResourceRole(PeResourceInfo resource)
    {
        if (resource.IsEmbeddedPe)
        {
            return "embedded-pe";
        }

        if (resource.IsPayloadCandidate)
        {
            return "payload-candidate";
        }

        if (resource.Entropy >= 7.8)
        {
            return "very-high-entropy-resource";
        }

        if (resource.Entropy >= 7.2)
        {
            return "high-entropy-resource";
        }

        if (resource.IsLarge)
        {
            return "large-resource";
        }

        return resource.ResourceType.Contains("manifest", StringComparison.OrdinalIgnoreCase)
            ? "manifest"
            : "metadata-resource";
    }

    private static string StaticResourceFlags(PeResourceInfo resource)
    {
        var flags = new List<string>();
        if (resource.IsEmbeddedPe)
        {
            flags.Add("embedded PE");
        }

        if (resource.IsPayloadCandidate)
        {
            flags.Add("payload candidate");
        }

        if (resource.IsLarge)
        {
            flags.Add("large");
        }

        if (resource.Entropy >= 7.8)
        {
            flags.Add("very high entropy");
        }
        else if (resource.Entropy >= 7.2)
        {
            flags.Add("high entropy");
        }

        foreach (var tag in resource.Tags.Take(6))
        {
            if (!flags.Contains(tag, StringComparer.OrdinalIgnoreCase))
            {
                flags.Add(tag);
            }
        }

        return flags.Count == 0 ? "-" : string.Join(", ", flags);
    }

    private static string StaticResourceToPlainText(PeResourceInfo resource, string role, string flags)
    {
        return string.Join(
            Environment.NewLine,
            [
                $"resourceType={resource.ResourceType}",
                $"resourceRole={role}",
                $"dataRva={resource.DataRva}",
                $"dataFileOffset={resource.DataFileOffset ?? "-"}",
                $"size={resource.Size}",
                $"entropy={resource.Entropy?.ToString("F3", CultureInfo.InvariantCulture) ?? "-"}",
                $"entropyLabel={resource.EntropyLabel}",
                $"isPayloadCandidate={resource.IsPayloadCandidate}",
                $"isEmbeddedPe={resource.IsEmbeddedPe}",
                $"isLarge={resource.IsLarge}",
                $"flags={flags}",
                $"tags={string.Join(",", resource.Tags)}"
            ]);
    }

    /// <summary>
    /// Appends grouped static evidence without changing the public report model.
    /// Inputs are static-analysis tags, URLs, and interesting string prefixes;
    /// processing splits imports, exports, URLs/IPs, registry paths, file paths,
    /// resource/TLS hints, and other indicators; the method returns no value.
    /// </summary>
    private static void AppendStaticEvidenceGroups(StringBuilder html, StaticAnalysisResult staticAnalysis)
    {
        html.AppendLine("<h3>Static evidence map</h3>");
        html.AppendLine("<div class=\"section-note\">Imports, exports, resources, TLS, and indicators are grouped from <code>StaticAnalysisResult.Tags</code>, <code>Urls</code>, and prefixed <code>InterestingStrings</code> evidence so report JSON stays backward-compatible.</div>");

        html.AppendLine("<div class=\"columns\">");
        html.AppendLine("<div>");
        AppendEvidenceList(html, "PE imports", SelectEvidence(staticAnalysis.InterestingStrings, "import:"), "No PE imports were parsed.");
        AppendEvidenceList(html, "PE exports", SelectEvidence(staticAnalysis.InterestingStrings, "export-module:", "export:"), "No PE exports were parsed.");
        AppendEvidenceList(html, "Resources and TLS", SelectEvidence(staticAnalysis.InterestingStrings, "resource", "tls:"), "No resource or TLS evidence was recorded.");
        html.AppendLine("</div>");
        html.AppendLine("<div>");
        AppendEvidenceList(html, "URL indicators", staticAnalysis.Urls.Select(url => $"url:{url}"), "No URL indicators were extracted.");
        AppendEvidenceList(html, "IP indicators", SelectEvidence(staticAnalysis.InterestingStrings, "ip:"), "No IP indicators were extracted.");
        AppendEvidenceList(html, "Registry indicators", SelectEvidence(staticAnalysis.InterestingStrings, "registry-path:"), "No registry path indicators were extracted.");
        AppendEvidenceList(html, "File/path indicators", SelectEvidence(staticAnalysis.InterestingStrings, "path:"), "No filesystem path indicators were extracted.");
        html.AppendLine("</div>");
        html.AppendLine("</div>");

        html.AppendLine("<h3>Static rule tags</h3>");
        if (staticAnalysis.Tags.Count == 0)
        {
            Empty(html, "No static tags were emitted.");
            return;
        }

        foreach (var tag in staticAnalysis.Tags.OrderBy(tag => tag, StringComparer.OrdinalIgnoreCase))
        {
            html.AppendLine($"<span class=\"chip chip-info copyable\" data-copy=\"{A(tag)}\">{E(tag)}</span>");
        }
    }

    /// <summary>
    /// Appends a compact list of grouped static evidence.
    /// Inputs are a title and bounded evidence values; processing writes a
    /// copyable unordered list or an empty state; the method returns no value.
    /// </summary>
    private static void AppendEvidenceList(StringBuilder html, string title, IEnumerable<string> values, string emptyMessage)
    {
        var items = values
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
            .Take(80)
            .ToList();
        html.AppendLine($"<h4>{E(title)}</h4>");
        if (items.Count == 0)
        {
            Empty(html, emptyMessage);
            return;
        }

        html.AppendLine("<ul class=\"compact-list\">");
        foreach (var value in items)
        {
            html.AppendLine($"<li><code class=\"copyable\" data-copy=\"{A(value)}\">{E(value)}</code></li>");
        }

        html.AppendLine("</ul>");
    }

    /// <summary>
    /// Appends a bounded list of static string evidence.
    /// Inputs are a title and string values, processing writes an empty state or
    /// list, and the method returns no value.
    /// </summary>
    private static void AppendStringList(StringBuilder html, string title, IReadOnlyCollection<string> values)
    {
        html.AppendLine($"<h3>{E(title)}</h3>");
        if (values.Count == 0)
        {
            Empty(html, $"No {title.ToLowerInvariant()} recorded.");
            return;
        }

        var nonEmptyValues = values
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .ToList();
        if (nonEmptyValues.Count == 0)
        {
            Empty(html, $"No {title.ToLowerInvariant()} recorded.");
            return;
        }

        var inlineValues = nonEmptyValues
            .Take(StaticStringInlineLimit)
            .ToList();
        var hiddenCount = Math.Max(0, nonEmptyValues.Count - inlineValues.Count);
        if (hiddenCount > 0)
        {
            html.AppendLine($"<div class=\"section-note\"><strong>Static list capped for readability.</strong> Inline entries: {E(inlineValues.Count.ToString())}/{E(nonEmptyValues.Count.ToString())}. Hidden entries: {E(hiddenCount.ToString())}. Open report.json for complete static evidence.</div>");
        }

        html.AppendLine("<ul class=\"bounded-list compact-list\">");
        foreach (var value in inlineValues)
        {
            html.AppendLine($"<li><code class=\"copyable\" data-copy=\"{A(value)}\">{E(value)}</code></li>");
        }

        html.AppendLine("</ul>");
    }

    /// <summary>
    /// Appends dynamic event overview.
    /// Inputs are a report and output builder, processing counts common dynamic
    /// event classes, and the method returns no value.
    /// </summary>
    private static void AppendDynamicAnalysis(StringBuilder html, AnalysisReport report)
    {
        html.AppendLine("<section id=\"dynamic\" class=\"card\"><h2>Dynamic analysis</h2><div class=\"grid\">");
        Metric(html, "Process starts", CountSampleBehaviorEvents(report, "process.start").ToString(), "risk-info");
        Metric(html, "Process exits", CountSampleBehaviorEvents(report, "process.exit").ToString(), "risk-info");
        Metric(html, "Registry events", report.Events.Count(IsSampleBehaviorRegistryEvent).ToString(), "risk-medium");
        Metric(html, "File events", report.Events.Count(IsSampleBehaviorFileEvent).ToString(), "risk-medium");
        Metric(html, "Startup diff events", report.Events.Count(IsSampleBehaviorStartupEvent).ToString(), "risk-medium");
        Metric(html, "Network events", report.Events.Count(IsSampleBehaviorNetworkEvent).ToString(), "risk-medium");
        Metric(html, "R0 sample telemetry", report.Events.Count(IsSampleBehaviorR0Event).ToString(), "risk-info");
        Metric(html, "R0 health/readiness", report.Events.Count(IsR0CollectionHealthEvent).ToString(), "risk-info");
        Metric(html, "Collection health", report.Events.Count(IsCollectionHealthEvent).ToString(), "risk-info");
        Metric(html, "VT lookups", report.Events.Count(IsVirusTotalEvent).ToString(), "risk-info");
        Metric(html, "Failure markers", report.Events.Count(IsOperationalFailureEvent).ToString(), "risk-high");
        html.AppendLine("</div>");
        if (report.Events.Count == 0)
        {
            Empty(html, "No dynamic events were collected. Zero counters mean telemetry was not collected or imported for this section; they are not proof that the sample had no behavior.");
        }

        html.AppendLine("</section>");
    }

    /// <summary>
    /// Appends optional VirusTotal hash-reputation enrichment separately from
    /// sandbox behavior. Inputs are normalized VT events/findings; processing
    /// summarizes verdict/status quality and renders bounded evidence rows.
    /// </summary>
    private static void AppendVirusTotalSummary(
        StringBuilder html,
        AnalysisReport report,
        IReadOnlyDictionary<string, List<ArtifactDescriptor>> artifactLookup,
        IReadOnlyCollection<ArtifactDescriptor> artifacts)
    {
        var vtEvents = report.Events
            .Where(IsVirusTotalEvent)
            .OrderBy(evt => evt.Timestamp)
            .ToList();
        var vtFindings = report.Findings
            .Where(IsVirusTotalFinding)
            .OrderBy(finding => SeverityRank(finding.Severity))
            .ThenBy(finding => finding.RuleId, StringComparer.OrdinalIgnoreCase)
            .ToList();

        html.AppendLine("<section id=\"vt\" class=\"card\"><h2>VirusTotal / reputation</h2>");
        html.AppendLine("<div class=\"section-note\"><strong>Hash-only enrichment.</strong> VirusTotal (VT) results are optional reputation evidence and are separated from sandbox behavior. Missing keys, rate limits, or not-found responses are enrichment status, not malicious sample behavior.</div>");
        html.AppendLine("<div class=\"grid\">");
        Metric(html, "VT lookups", vtEvents.Count.ToString(), "risk-info");
        Metric(html, "VT malicious", vtEvents.Count(evt => EventDataEqualsAny(evt, "vtVerdict", "verdict", "malicious")).ToString(), "risk-high");
        Metric(html, "VT suspicious", vtEvents.Count(evt => EventDataEqualsAny(evt, "vtVerdict", "verdict", "suspicious")).ToString(), "risk-medium");
        Metric(html, "VT status issues", vtEvents.Count(IsVirusTotalStatusIssue).ToString(), "risk-info");
        Metric(html, "VT rule hits", vtFindings.Count.ToString(), vtFindings.Any(finding => SeverityRank(finding.Severity) <= SeverityRank("high")) ? "risk-high" : "risk-info");
        html.AppendLine("</div>");
        AppendVirusTotalReputationStory(html, vtEvents);

        if (vtFindings.Count > 0)
        {
            AppendSecondaryFindingGroup(
                html,
                "VirusTotal rule hits",
                "External reputation rules are shown here so VT quality does not get mixed into local behavior evidence.",
                vtFindings);
        }

        if (vtEvents.Count == 0)
        {
            Empty(html, "No VirusTotal enrichment events were recorded. VT is optional, hash-only, and does not upload samples.");
        }
        else
        {
            AppendEventRows(html, vtEvents, artifactLookup, artifacts);
        }

        html.AppendLine("</section>");
    }

    /// <summary>
    /// Appends a compact VT reputation story. Inputs are persisted VT lookup
    /// events; processing surfaces official file-object fields such as
    /// reputation/community score, engine stats, last analysis time, and
    /// permalink in copyable cards without mixing them into local behavior.
    /// </summary>
    private static void AppendVirusTotalReputationStory(StringBuilder html, IReadOnlyCollection<SandboxEvent> vtEvents)
    {
        if (vtEvents.Count == 0)
        {
            return;
        }

        var latest = vtEvents
            .OrderBy(evt => evt.Timestamp)
            .Last();
        var verdict = FirstEventDataValue(latest, "vtVerdict", "verdict", "status", "vtStatus") ?? "-";
        var reputation = FirstEventDataValue(latest, "vtReputation", "reputation", "vtCommunityScore", "communityScore") ?? "-";
        var scoreSource = FirstEventDataValue(latest, "communityScoreSource") ?? "-";
        var engineStats = FormatVirusTotalEngineStats(latest);
        var community = FormatVirusTotalCommunity(latest);
        var lastAnalysis = FirstEventDataValue(latest, "lastAnalysisDateUtc", "lastAnalysisDate", "analysisDate") ?? "-";
        var permalink = FirstEventDataValue(latest, "permalink", "detectionPermalink", "officialApiSelfLink") ?? "-";
        var copy = string.Join(
            Environment.NewLine,
            [
                "VirusTotal official hash reputation",
                $"verdict={verdict}",
                $"reputation={reputation}",
                $"communityScoreSource={scoreSource}",
                engineStats,
                community,
                $"lastAnalysisDateUtc={lastAnalysis}",
                $"permalink={permalink}",
                EventDataToText(latest)
            ]);

        html.AppendLine("<h3>VirusTotal official evidence</h3>");
        html.AppendLine("<div class=\"section-note\"><strong>Official file-object fields.</strong> Engine stats, reputation/community score, last analysis date, and permalink are displayed as external hash reputation only; VT never uploads the sample from this report path.</div>");
        html.AppendLine("<div class=\"overview-strip vt-reputation-overview\">");
        AppendOverviewItem(
            html,
            "VT verdict",
            verdict,
            $"{engineStats}; last analysis: {lastAnalysis}.",
            TextEqualsAny(verdict, "malicious") ? "risk-high" : TextEqualsAny(verdict, "suspicious") ? "risk-medium" : "risk-info");
        AppendOverviewItem(
            html,
            "VT reputation/community",
            reputation,
            $"{community}; source: {scoreSource}.",
            TryParseSignedInt(reputation, out var reputationValue) && reputationValue < 0 ? "risk-medium" : "risk-info");
        AppendOverviewItem(
            html,
            "VT permalink",
            ShortenMiddle(permalink, 64),
            "Copy-only external VirusTotal GUI/API link; use it for analyst pivoting outside the local report.",
            string.Equals(permalink, "-", StringComparison.Ordinal) ? "risk-low" : "risk-info");
        html.AppendLine("</div>");
        html.AppendLine($"<details class=\"evidence-expansion-card\"><summary>Copy VirusTotal official evidence</summary><pre class=\"copyable\" data-copy=\"{A(copy)}\">{E(copy)}</pre></details>");
    }

    private static string FormatVirusTotalEngineStats(SandboxEvent evt)
    {
        return string.Join(
            "; ",
            [
                $"vtMalicious={FirstEventDataValue(evt, "vtMalicious", "malicious") ?? "-"}",
                $"vtSuspicious={FirstEventDataValue(evt, "vtSuspicious", "suspicious") ?? "-"}",
                $"vtHarmless={FirstEventDataValue(evt, "vtHarmless", "harmless") ?? "-"}",
                $"vtUndetected={FirstEventDataValue(evt, "vtUndetected", "undetected") ?? "-"}",
                $"vtEngineCount={FirstEventDataValue(evt, "vtEngineCount", "engineCount") ?? "-"}"
            ]);
    }

    private static string FormatVirusTotalCommunity(SandboxEvent evt)
    {
        return string.Join(
            "; ",
            [
                $"communityScore={FirstEventDataValue(evt, "vtCommunityScore", "communityScore") ?? "-"}",
                $"harmlessVotes={FirstEventDataValue(evt, "vtCommunityHarmlessVotes") ?? "-"}",
                $"maliciousVotes={FirstEventDataValue(evt, "vtCommunityMaliciousVotes") ?? "-"}",
                $"voteCount={FirstEventDataValue(evt, "vtCommunityVoteCount") ?? "-"}"
            ]);
    }

    private static bool TryParseSignedInt(string value, out int parsed)
    {
        return int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out parsed);
    }

    private static string ShortenMiddle(string value, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length <= maxLength)
        {
            return value;
        }

        var keep = Math.Max(8, (maxLength - 1) / 2);
        return value[..keep] + "…" + value[^keep..];
    }

    /// <summary>
    /// Appends a weak-interaction behavior graph and IOC summary.
    /// Inputs are normalized events and artifacts; processing derives
    /// process-to-file/registry/network/artifact edges without changing the
    /// public report schema; the method returns no value.
    /// </summary>
    private static void AppendBehaviorGraph(
        StringBuilder html,
        AnalysisReport report,
        IReadOnlyDictionary<string, List<ArtifactDescriptor>> artifactLookup,
        IReadOnlyCollection<ArtifactDescriptor> artifacts)
    {
        var processNodes = BuildProcessGraphNodes(report).Take(16).ToList();
        var edges = BuildBehaviorGraphEdges(report, artifactLookup, artifacts).Take(96).ToList();
        var fileIocs = ExtractFileIocs(report).Take(40).ToList();
        var registryIocs = ExtractRegistryIocs(report).Take(40).ToList();
        var networkIocs = ExtractNetworkIocs(report).Take(40).ToList();
        var artifactIocs = artifacts
            .Where(artifact => !IsCollectorSelfNoiseArtifact(artifact))
            .Select(ArtifactDisplayName)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(40)
            .ToList();

        html.AppendLine("<section id=\"graph\" class=\"card\"><h2>Behavior graph / IOC summary</h2>");
        if (report.Events.Count == 0)
        {
            Empty(html, "No behavior graph could be derived because no normalized events were collected.");
            html.AppendLine("</section>");
            return;
        }

        html.AppendLine("<div class=\"section-note\"><strong>Weak-interaction graph / 弱交互图谱.</strong> This section summarizes process, file, registry, network, security/privilege, and artifact relationships from normalized telemetry so the report remains stable without client-side graph libraries. Hint / 提示: artifact badges show indexed evidence already present in report.json/artifact-index; self-noise stays in raw evidence, not sample behavior.</div>");
        html.AppendLine("<div class=\"grid\">");
        Metric(html, "Graph processes", processNodes.Count.ToString(), "risk-info");
        Metric(html, "Graph edges", edges.Count.ToString(), "risk-info");
        Metric(html, "Network IOCs", networkIocs.Count.ToString(), "risk-medium");
        Metric(html, "File IOCs", fileIocs.Count.ToString(), "risk-medium");
        Metric(html, "Registry IOCs", registryIocs.Count.ToString(), "risk-medium");
        Metric(html, "Artifact IOCs", artifactIocs.Count.ToString(), "risk-info");
        html.AppendLine("</div>");
        AppendGraphNoiseBoundaryCard(html, report);
        AppendBehaviorStoryRouting(html, report);

        AppendEvidenceNarrativeSpine(html, report, processNodes, edges, fileIocs, registryIocs, networkIocs, artifactIocs, artifacts);
        AppendEvidenceSummaryCards(html, report, processNodes, edges, fileIocs, registryIocs, networkIocs, artifactIocs);
        AppendEvidenceStoryBoard(html, report, artifacts);
        AppendEvidenceHealthNarrative(html, report, artifacts);
        AppendStableRelationshipLanes(html, edges);
        AppendTopBehaviorChain(html, edges);

        if (processNodes.Count > 0)
        {
            html.AppendLine("<h3>Process graph nodes</h3><div class=\"graph-map\">");
            foreach (var node in processNodes)
            {
                html.AppendLine($"<div class=\"graph-node copyable\" data-copy=\"{A(node.CopyText)}\"><strong>{E(node.Label)}</strong><small>{E(node.Detail)}</small></div>");
            }

            html.AppendLine("</div>");
        }

        if (edges.Count == 0)
        {
            Empty(html, "No process-to-object graph edges were derived yet.");
        }
        else
        {
            html.AppendLine("<h3>Evidence graph edges</h3>");
            html.AppendLine("<table class=\"edge-table\"><thead><tr><th>From</th><th>Relation</th><th>To</th><th>Evidence</th></tr></thead><tbody>");
            foreach (var edge in edges)
            {
                var copy = string.Join(
                    Environment.NewLine,
                    [
                        $"from={edge.From}",
                        $"relation={edge.Relation}",
                        $"to={edge.To}",
                        edge.Evidence
                    ]);
                html.AppendLine("<tr>");
                html.AppendLine($"<td class=\"copyable\" data-copy=\"{A(edge.From)}\"><code>{E(edge.From)}</code></td>");
                html.AppendLine($"<td><span class=\"badge badge-info\">{E(edge.Relation)}</span></td>");
                html.AppendLine($"<td class=\"copyable\" data-copy=\"{A(edge.To)}\"><code>{E(edge.To)}</code></td>");
                html.AppendLine($"<td class=\"evidence\"><span class=\"inline-actions\">{CopyButton("Copy graph edge", copy)}</span><details class=\"evidence-expansion-card\"><summary>Expand edge evidence</summary><pre class=\"copyable\" data-copy=\"{A(copy)}\">{E(copy)}</pre></details></td>");
                html.AppendLine("</tr>");
            }

            html.AppendLine("</tbody></table>");
        }

        html.AppendLine("<h3>IOC summary</h3><div class=\"ioc-grid\">");
        AppendIocCard(html, "Network IOCs", networkIocs, "No DNS, HTTP, TLS, PCAP, or TCP/IP indicators were extracted from events.");
        AppendIocCard(html, "File/path IOCs", fileIocs, "No file/path indicators were extracted from dynamic events.");
        AppendIocCard(html, "Registry IOCs", registryIocs, "No registry indicators were extracted from dynamic events.");
        AppendIocCard(html, "Artifact IOCs", artifactIocs, "No linked artifacts were indexed for this report.");
        html.AppendLine("</div>");
        html.AppendLine("</section>");
    }

    /// <summary>
    /// Appends a copyable graph-boundary card that explains sample behavior
    /// versus collection/self-noise without changing raw event pagination.
    /// </summary>
    private static void AppendGraphNoiseBoundaryCard(StringBuilder html, AnalysisReport report)
    {
        var sampleBehavior = report.Events.Count(IsSampleBehaviorEvent);
        var behaviorCountedFalse = report.Events.Count(IsBehaviorCountedFalseEvent);
        var nonBehavior = report.Events.Count(IsNonBehaviorEvent);
        var notSampleBehavior = report.Events.Count(IsNotSampleBehaviorMarkerEvent);
        var collectorSelfNoise = report.Events.Count(IsCollectorSelfNoiseEvent);
        var healthRows = report.Events.Count(IsCollectionHealthEvent);
        var vtQuiet = report.Events.Count(IsVirusTotalQuietStateEvent);
        var excluded = report.Events.Count(IsExcludedFromBehaviorStoryEvent);
        var examples = report.Events
            .Where(IsExcludedFromBehaviorStoryEvent)
            .Take(4)
            .Select(EventOneLine)
            .ToList();
        var copy = string.Join(
            Environment.NewLine,
            [
                "graphSelfNoiseBoundary=sample-behavior-vs-collection-metadata",
                $"sampleBehaviorRows={sampleBehavior}",
                $"excludedRows={excluded}",
                $"behaviorCountedFalse={behaviorCountedFalse}",
                $"nonBehavior={nonBehavior}",
                $"notSampleBehavior={notSampleBehavior}",
                $"collectorSelfNoise={collectorSelfNoise}",
                $"collectionHealthRows={healthRows}",
                $"vtQuietRows={vtQuiet}",
                "completeSource=Raw normalized events/report.json; pagination/folding unchanged",
                .. examples
            ]);

        html.AppendLine($"<div class=\"compact-evidence-summary copyable\" data-copy=\"{A(copy)}\"><strong>Graph self-noise boundary / 图谱自噪声边界</strong><br>");
        html.AppendLine($"Sample behavior rows / 样本行为行: <b>{E(sampleBehavior.ToString(CultureInfo.InvariantCulture))}</b>; excluded collection/reputation rows / 已分离采集与信誉行: <b>{E(excluded.ToString(CultureInfo.InvariantCulture))}</b>.");
        html.AppendLine("<br><span class=\"muted\">Hint / 提示: these rows remain copyable in R0/VT/Raw sections and report.json; graph cards do not promote them into sample behavior.</span>");
        html.AppendLine($"<div class=\"story-metrics\"><span>behaviorCounted=false {E(behaviorCountedFalse.ToString(CultureInfo.InvariantCulture))}</span><span>nonbehavior {E(nonBehavior.ToString(CultureInfo.InvariantCulture))}</span><span>notSampleBehavior {E(notSampleBehavior.ToString(CultureInfo.InvariantCulture))}</span><span>collector {E(collectorSelfNoise.ToString(CultureInfo.InvariantCulture))}</span><span>health {E(healthRows.ToString(CultureInfo.InvariantCulture))}</span><span>VT quiet {E(vtQuiet.ToString(CultureInfo.InvariantCulture))}</span></div>{CopyButton("Copy graph boundary", copy)}</div>");
    }

    /// <summary>
    /// Appends a copyable route map that makes the behavior/nonbehavior split
    /// visible before dense graph cards. Inputs are all report events; processing
    /// counts sample behavior, excluded evidence, and top exclusion reasons.
    /// </summary>
    private static void AppendBehaviorStoryRouting(StringBuilder html, AnalysisReport report)
    {
        if (report.Events.Count == 0)
        {
            return;
        }

        var sampleEvents = report.Events.Where(IsSampleBehaviorEvent).OrderBy(evt => evt.Timestamp).ToList();
        var excludedEvents = report.Events.Where(IsExcludedFromBehaviorStoryEvent).OrderBy(evt => evt.Timestamp).ToList();
        var reasonCounts = BuildBehaviorExclusionReasonCounts(report.Events);
        var sampleFamilies = sampleEvents
            .Select(EventFamilyLabel)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
            .Take(6)
            .ToList();
        var excludedFamilies = excludedEvents
            .Select(EventFamilyLabel)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
            .Take(6)
            .ToList();
        var reasonSummary = FormatReasonCounts(reasonCounts.Take(6).ToList());
        var copy = string.Join(
            Environment.NewLine,
            [
                "Behavior story routing",
                $"totalEvents={report.Events.Count}",
                $"sampleBehaviorRows={sampleEvents.Count}",
                $"excludedRows={excludedEvents.Count}",
                $"sampleFamilies={string.Join(",", sampleFamilies)}",
                $"excludedFamilies={string.Join(",", excludedFamilies)}",
                "excludedReasonHits:",
                .. reasonCounts.Select(reason => $"{reason.Label}={reason.Count}"),
                "sampleExamples:",
                .. sampleEvents.Take(5).Select(EventOneLine),
                "excludedExamples:",
                .. excludedEvents.Take(5).Select(EventOneLine)
            ]);

        html.AppendLine("<h3>Behavior story routing</h3>");
        html.AppendLine("<div class=\"section-note\"><strong>Behavior story routing.</strong> The graph, process tree, network cards, file table, and registry table use only sample-behavior rows. Collection metadata, <code>nonbehavior</code>, <code>notSampleBehavior</code>, collector self-noise, VT quiet states, and R0 health remain visible in their own lanes and raw events.</div>");
        html.AppendLine($"<div class=\"overview-strip behavior-routing-overview copyable\" data-copy=\"{A(copy)}\">");
        AppendOverviewItem(
            html,
            "Sample behavior route",
            sampleEvents.Count.ToString(CultureInfo.InvariantCulture),
            sampleFamilies.Count == 0 ? "No runtime behavior rows were promoted into graph/process/network sections." : $"Families promoted: {string.Join(", ", sampleFamilies)}.",
            sampleEvents.Count > 0 ? "risk-info" : "risk-low");
        AppendOverviewItem(
            html,
            "Excluded evidence route",
            excludedEvents.Count.ToString(CultureInfo.InvariantCulture),
            excludedFamilies.Count == 0 ? "No explicit nonbehavior/self-noise rows were observed." : $"Families kept out of sample behavior: {string.Join(", ", excludedFamilies)}.",
            excludedEvents.Count > 0 ? "risk-info" : "risk-low");
        AppendOverviewItem(
            html,
            "Top excluded reasons",
            reasonCounts.Count.ToString(CultureInfo.InvariantCulture),
            string.IsNullOrWhiteSpace(reasonSummary) ? "No exclusion markers were observed." : reasonSummary,
            reasonCounts.Count > 0 ? "risk-info" : "risk-low");
        html.AppendLine($"<div class=\"toolbar\">{CopyButton("Copy behavior routing", copy)}</div>");
        html.AppendLine("</div>");
        html.AppendLine($"<details class=\"relationship-details\"><summary>Behavior routing evidence examples</summary><pre class=\"copyable\" data-copy=\"{A(copy)}\">{E(copy)}</pre></details>");
    }

    private static IReadOnlyList<(string Label, int Count)> BuildBehaviorExclusionReasonCounts(IEnumerable<SandboxEvent> events)
    {
        var counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var evt in events)
        {
            if (IsBehaviorCountedFalseEvent(evt))
            {
                IncrementReasonCount(counts, "behaviorCounted=false");
            }

            if (IsNonBehaviorEvent(evt))
            {
                IncrementReasonCount(counts, "nonbehavior");
            }

            if (IsNotSampleBehaviorMarkerEvent(evt))
            {
                IncrementReasonCount(counts, "notSampleBehavior");
            }

            if (IsCollectorSelfNoiseEvent(evt))
            {
                IncrementReasonCount(counts, "collectorSelfNoise");
            }

            if (IsCollectionHealthEvent(evt))
            {
                IncrementReasonCount(counts, "collectionHealth");
            }

            if (IsVirusTotalQuietStateEvent(evt))
            {
                IncrementReasonCount(counts, "vtQuiet");
            }
        }

        return counts
            .OrderByDescending(pair => pair.Value)
            .ThenBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase)
            .Select(pair => (pair.Key, pair.Value))
            .ToList();
    }

    private static void IncrementReasonCount(IDictionary<string, int> counts, string reason)
    {
        counts.TryGetValue(reason, out var current);
        counts[reason] = current + 1;
    }

    private static string FormatReasonCounts(IReadOnlyCollection<(string Label, int Count)> reasonCounts)
    {
        return reasonCounts.Count == 0
            ? string.Empty
            : string.Join("; ", reasonCounts.Select(reason => $"{reason.Label}: {reason.Count}"));
    }

    /// <summary>
    /// Appends a compact left-to-right narrative before the heavier graph
    /// widgets. Inputs are already-derived graph, IOC, and artifact summaries;
    /// processing emits four bounded copyable cards that answer what happened,
    /// what it touched, what it contacted, and what proof was collected.
    /// </summary>
    private static void AppendEvidenceNarrativeSpine(
        StringBuilder html,
        AnalysisReport report,
        IReadOnlyCollection<ProcessGraphNode> processNodes,
        IReadOnlyCollection<BehaviorGraphEdge> edges,
        IReadOnlyCollection<string> fileIocs,
        IReadOnlyCollection<string> registryIocs,
        IReadOnlyCollection<string> networkIocs,
        IReadOnlyCollection<string> artifactIocs,
        IReadOnlyCollection<ArtifactDescriptor> artifacts)
    {
        var cards = BuildEvidenceNarrativeCards(report, processNodes, edges, fileIocs, registryIocs, networkIocs, artifactIocs, artifacts);
        var spineCopy = BuildNarrativeSpineCopyText(cards);
        html.AppendLine("<h3 id=\"narrative-spine\" class=\"anchor-offset\">Narrative spine</h3>");
        html.AppendLine("<div class=\"section-note\"><strong>Compact evidence narrative.</strong> Read left to right: process tree root, behavior graph edges, network endpoint scope, and collected artifact proof. Each step stays bounded and copyable so the report explains the evidence before dense tables or raw rows.</div>");
        html.AppendLine($"<div class=\"narrative-spine-lead copyable\" data-copy=\"{A(spineCopy)}\"><strong>Narrative spine summary</strong><span>Execution → storage → network → artifact proof, with copyable bounded evidence and no raw event wall.</span>{CopyButton("Copy narrative spine", spineCopy)}</div>");
        html.AppendLine("<div class=\"narrative-spine\">");
        foreach (var card in cards)
        {
            html.AppendLine($"<article class=\"narrative-step copyable\" data-copy=\"{A(card.CopyText)}\">");
            html.AppendLine($"<span class=\"narrative-step-index\">{E(card.Step)}</span>");
            html.AppendLine($"<h3>{E(card.Title)}</h3>");
            html.AppendLine($"<span class=\"overview-value {E(card.Css)}\">{E(card.Value)}</span>");
            html.AppendLine($"<p>{E(card.Detail)}</p>");
            html.AppendLine($"<div class=\"toolbar\">{CopyButton("Copy narrative step", card.CopyText)}</div>");
            html.AppendLine("</article>");
        }

        html.AppendLine("</div>");
    }

    private static string BuildNarrativeSpineCopyText(IReadOnlyList<EvidenceNarrativeCard> cards)
    {
        return string.Join(
            Environment.NewLine,
            ["Narrative spine summary", .. cards.Select(card => $"{card.Step}. {card.Title}: value={card.Value}; detail={card.Detail}")]);
    }

    private static IReadOnlyList<EvidenceNarrativeCard> BuildEvidenceNarrativeCards(
        AnalysisReport report,
        IReadOnlyCollection<ProcessGraphNode> processNodes,
        IReadOnlyCollection<BehaviorGraphEdge> edges,
        IReadOnlyCollection<string> fileIocs,
        IReadOnlyCollection<string> registryIocs,
        IReadOnlyCollection<string> networkIocs,
        IReadOnlyCollection<string> artifactIocs,
        IReadOnlyCollection<ArtifactDescriptor> artifacts)
    {
        var topProcess = processNodes.FirstOrDefault()?.Label ?? "-";
        var spawnEdges = edges.Count(edge => string.Equals(edge.Relation, "spawn", StringComparison.OrdinalIgnoreCase));
        var fileEdges = edges.Count(edge => string.Equals(edge.Relation, "file", StringComparison.OrdinalIgnoreCase));
        var registryEdges = edges.Count(edge => string.Equals(edge.Relation, "registry", StringComparison.OrdinalIgnoreCase));
        var networkEdges = edges.Count(edge => string.Equals(edge.Relation, "network", StringComparison.OrdinalIgnoreCase));
        var artifactEdges = edges.Count(edge => string.Equals(edge.Relation, "artifact", StringComparison.OrdinalIgnoreCase));
        var storageIocCount = fileIocs.Count + registryIocs.Count;
        var artifactCounts = ArtifactKindNarrativeSummary(artifacts);
        var highestFinding = PrimaryBehaviorFindings(report)
            .OrderBy(finding => SeverityRank(finding.Severity))
            .Select(finding => $"{finding.Severity}: {finding.Title}")
            .FirstOrDefault() ?? "No behavior finding";

        return
        [
            new EvidenceNarrativeCard(
                "1",
                "Execution root",
                processNodes.Count.ToString(CultureInfo.InvariantCulture),
                $"Root candidate: {topProcess}. Spawn edges: {spawnEdges}. Highest behavior finding: {highestFinding}.",
                processNodes.Count > 0 ? "risk-info" : "risk-low",
                string.Join(Environment.NewLine, ["Narrative step: Execution root", $"topProcess={topProcess}", $"processNodes={processNodes.Count}", $"spawnEdges={spawnEdges}", $"highestFinding={highestFinding}", .. processNodes.Take(6).Select(node => node.CopyText)])),
            new EvidenceNarrativeCard(
                "2",
                "Storage changes",
                storageIocCount.ToString(CultureInfo.InvariantCulture),
                $"Storage signal: {fileIocs.Count} file IOC(s), {registryIocs.Count} registry IOC(s), graph edges file/registry {fileEdges}/{registryEdges}.",
                storageIocCount > 0 ? "risk-medium" : "risk-low",
                string.Join(Environment.NewLine, ["Narrative step: Storage changes", $"fileIocs={fileIocs.Count}", $"registryIocs={registryIocs.Count}", $"fileEdges={fileEdges}", $"registryEdges={registryEdges}", .. fileIocs.Take(5), .. registryIocs.Take(5)])),
            new EvidenceNarrativeCard(
                "3",
                "Network scope",
                networkIocs.Count.ToString(CultureInfo.InvariantCulture),
                networkIocs.Count == 0 ? $"No endpoint IOC extracted; network graph edges: {networkEdges}." : $"Network scope: {string.Join(", ", networkIocs.Take(4))}; graph edges: {networkEdges}.",
                networkIocs.Count + networkEdges > 0 ? "risk-medium" : "risk-low",
                string.Join(Environment.NewLine, ["Narrative step: Network scope", $"networkIocs={networkIocs.Count}", $"networkEdges={networkEdges}", .. networkIocs.Take(8)])),
            new EvidenceNarrativeCard(
                "4",
                "Artifact proof",
                artifactIocs.Count.ToString(CultureInfo.InvariantCulture),
                $"Artifact proof: {artifactEdges} graph edge(s); indexed evidence types: {artifactCounts}.",
                artifactIocs.Count + artifactEdges > 0 ? "risk-info" : "risk-low",
                string.Join(Environment.NewLine, ["Narrative step: Artifact proof", $"artifactIocs={artifactIocs.Count}", $"artifactEdges={artifactEdges}", $"artifactKinds={artifactCounts}", .. artifactIocs.Take(8)]))
        ];
    }

    private static string ArtifactKindNarrativeSummary(IReadOnlyCollection<ArtifactDescriptor> artifacts)
    {
        var summary = artifacts
            .Where(artifact => IsEvidenceArtifactKind(artifact) && !IsCollectorSelfNoiseArtifact(artifact))
            .GroupBy(artifact => artifact.Kind)
            .OrderBy(group => ArtifactKindRank(group.Key))
            .Select(group => $"{group.Key}={group.Count()}")
            .Take(6)
            .ToList();
        return summary.Count == 0 ? "none" : string.Join(", ", summary);
    }

    /// <summary>
    /// Appends a static relationship lane map before dense graph tables.
    /// Inputs are derived graph edges; processing summarizes process-to-object
    /// lane counts and representative paths with native copy/fold controls so
    /// the graph remains stable without canvas or JavaScript libraries.
    /// </summary>
    private static void AppendStableRelationshipLanes(StringBuilder html, IReadOnlyCollection<BehaviorGraphEdge> edges)
    {
        var lanes = new[]
        {
            (Relation: "spawn", Title: "Process lineage lane", Detail: "Process-to-process execution relationships from stable process keys and PID/PPID fallback."),
            (Relation: "file", Title: "File path lane", Detail: "Process-to-file writes, drops, reads, and path indicators."),
            (Relation: "registry", Title: "Registry path lane", Detail: "Process-to-registry key/value relationships."),
            (Relation: "network", Title: "Network path lane", Detail: "Process-to-endpoint DNS/HTTP/TLS/flow relationships."),
            (Relation: "artifact", Title: "Artifact proof lane", Detail: "Process-to-artifact proof such as screenshots, dropped files, memory dumps, and PCAP."),
        };
        var edgeList = edges
            .Where(edge => !BehaviorGraphEdgeLooksLikeCollectorSelfNoise(edge))
            .ToList();
        var copy = string.Join(
            Environment.NewLine,
            [
                "Stable relationship lanes",
                .. lanes.Select(lane => $"{lane.Title}: relation={lane.Relation}; edges={edgeList.Count(edge => string.Equals(edge.Relation, lane.Relation, StringComparison.OrdinalIgnoreCase))}"),
                "representativePaths:",
                .. edgeList
                    .OrderBy(edge => BehaviorChainRelationRank(edge.Relation))
                    .ThenBy(edge => edge.From, StringComparer.OrdinalIgnoreCase)
                    .Take(24)
                    .Select(edge => $"{edge.From} -> {edge.Relation} -> {edge.To}")
            ]);

        html.AppendLine("<h3>Stable relationship lanes</h3>");
        html.AppendLine("<div class=\"section-note\"><strong>Stable relationship lanes.</strong> Weak-interaction lane map for process lineage, file paths, registry paths, network paths, and artifact proof. Counts and representative paths are visible before the dense edge table; complete edge evidence remains bounded below.</div>");
        html.AppendLine("<div class=\"overview-strip relationship-lane-overview\">");
        foreach (var lane in lanes)
        {
            var laneEdges = edgeList
                .Where(edge => string.Equals(edge.Relation, lane.Relation, StringComparison.OrdinalIgnoreCase))
                .Take(3)
                .Select(edge => $"{edge.From} → {edge.To}")
                .ToList();
            var count = edgeList.Count(edge => string.Equals(edge.Relation, lane.Relation, StringComparison.OrdinalIgnoreCase));
            var detail = laneEdges.Count == 0 ? lane.Detail : $"{lane.Detail} Examples: {string.Join("; ", laneEdges)}.";
            AppendOverviewItem(html, lane.Title, count.ToString(CultureInfo.InvariantCulture), detail, count > 0 ? "risk-info" : "risk-low");
        }

        html.AppendLine("</div>");
        html.AppendLine($"<details class=\"relationship-details\"><summary>Stable relationship lane copy map</summary><div class=\"toolbar\">{CopyButton("Copy stable relationship lanes", copy)}</div><pre class=\"copyable\" data-copy=\"{A(copy)}\">{E(copy)}</pre></details>");
    }

    private static bool BehaviorGraphEdgeLooksLikeCollectorSelfNoise(BehaviorGraphEdge edge)
    {
        return TextLooksLikeCollectorSelfNoise(edge.From) ||
            TextLooksLikeCollectorSelfNoise(edge.To) ||
            TextLooksLikeCollectorSelfNoise(edge.Evidence);
    }

    private static bool TextLooksLikeCollectorSelfNoise(string? value)
    {
        return !string.IsNullOrWhiteSpace(value) &&
            (value.Contains("KSword.Sandbox.R0Collector", StringComparison.OrdinalIgnoreCase) ||
                value.Contains("collector-self-noise", StringComparison.OrdinalIgnoreCase) ||
                value.Contains("127.0.0.1:18080", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Appends a bounded static behavior chain before the edge table.
    /// Inputs are derived graph edges; processing ranks lineage/network/storage
    /// evidence for stable weak-interaction rendering; return is none.
    /// </summary>
    private static void AppendTopBehaviorChain(StringBuilder html, IReadOnlyCollection<BehaviorGraphEdge> edges)
    {
        if (edges.Count == 0)
        {
            return;
        }

        var chain = edges
            .OrderBy(edge => BehaviorChainRelationRank(edge.Relation))
            .ThenBy(edge => edge.From, StringComparer.OrdinalIgnoreCase)
            .ThenBy(edge => edge.To, StringComparer.OrdinalIgnoreCase)
            .Take(18)
            .ToList();
        if (chain.Count == 0)
        {
            return;
        }

        var copy = string.Join(Environment.NewLine, chain.Select(edge => $"{edge.From} --{edge.Relation}--> {edge.To}"));
        html.AppendLine("<h3>Top behavior chain</h3>");
        html.AppendLine("<div class=\"section-note\"><strong>Top behavior chain.</strong> Static lineage-first chain ranked for analyst reading; expand the edge table below for full bounded evidence.</div>");
        html.AppendLine($"<ol class=\"timeline-list behavior-chain copyable\" data-copy=\"{A(copy)}\">");
        foreach (var edge in chain)
        {
            html.AppendLine("<li>");
            html.AppendLine($"<code>{E(edge.From)}</code> <span class=\"badge badge-info\">{E(edge.Relation)}</span> <code>{E(edge.To)}</code>");
            html.AppendLine($"<details class=\"evidence-expansion-card\"><summary>Expand edge evidence</summary><pre class=\"copyable\" data-copy=\"{A(edge.Evidence)}\">{E(edge.Evidence)}</pre></details>");
            html.AppendLine("</li>");
        }

        html.AppendLine("</ol>");
    }

    private static int BehaviorChainRelationRank(string relation)
    {
        return relation.ToLowerInvariant() switch
        {
            "spawn" => 0,
            "network" => 1,
            "registry" => 2,
            "file" => 3,
            "artifact" => 4,
            _ => 9
        };
    }

    /// <summary>
    /// Appends operator-facing evidence summary cards for fast triage.
    /// Inputs are graph nodes, edges, IOC lists, and artifacts already derived
    /// for the graph; processing emits bounded copyable cards; return is none.
    /// </summary>
    private static void AppendEvidenceSummaryCards(
        StringBuilder html,
        AnalysisReport report,
        IReadOnlyCollection<ProcessGraphNode> processNodes,
        IReadOnlyCollection<BehaviorGraphEdge> edges,
        IReadOnlyCollection<string> fileIocs,
        IReadOnlyCollection<string> registryIocs,
        IReadOnlyCollection<string> networkIocs,
        IReadOnlyCollection<string> artifactIocs)
    {
        var cards = BuildEvidenceSummaryCards(report, processNodes, edges, fileIocs, registryIocs, networkIocs, artifactIocs);
        html.AppendLine("<h3 id=\"evidence-summary-cards\" class=\"anchor-offset\">Evidence summary cards</h3>");
        html.AppendLine("<div class=\"evidence-summary-grid\">");
        foreach (var card in cards)
        {
            html.AppendLine($"<article class=\"evidence-summary-card copyable\" data-copy=\"{A(card.CopyText)}\">");
            html.AppendLine("<div class=\"relationship-title\">");
            html.AppendLine($"<h3>{E(card.Title)}</h3><span class=\"badge badge-{E(card.Css)}\">{E(card.Value)}</span>");
            html.AppendLine("</div>");
            html.AppendLine($"<span class=\"summary-value\">{E(card.Value)}</span>");
            html.AppendLine($"<p class=\"muted\">{E(card.Detail)}</p>");
            html.AppendLine($"<div class=\"toolbar\">{CopyButton("Copy evidence summary", card.CopyText)}</div>");
            html.AppendLine($"<details class=\"evidence-expansion-card\"><summary>Expand evidence card details</summary><pre class=\"copyable\" data-copy=\"{A(card.CopyText)}\">{E(card.CopyText)}</pre></details>");
            html.AppendLine("</article>");
        }

        html.AppendLine("</div>");
    }

    /// <summary>
    /// Builds high-level evidence summary cards without changing report schema.
    /// Inputs are derived graph and IOC values; processing turns counts and top
    /// evidence into copyable card payloads; return is a stable card list.
    /// </summary>
    private static IReadOnlyList<EvidenceSummaryCard> BuildEvidenceSummaryCards(
        AnalysisReport report,
        IReadOnlyCollection<ProcessGraphNode> processNodes,
        IReadOnlyCollection<BehaviorGraphEdge> edges,
        IReadOnlyCollection<string> fileIocs,
        IReadOnlyCollection<string> registryIocs,
        IReadOnlyCollection<string> networkIocs,
        IReadOnlyCollection<string> artifactIocs)
    {
        var highestSeverity = PrimaryBehaviorFindings(report)
            .OrderBy(finding => SeverityRank(finding.Severity))
            .Select(finding => $"{finding.Severity}: {finding.Title}")
            .FirstOrDefault() ?? "No behavior rules matched";
        var topNetwork = networkIocs.Take(5).ToList();
        var topStorage = fileIocs.Concat(registryIocs).Take(5).ToList();
        var topArtifacts = artifactIocs.Take(5).ToList();

        return
        [
            new EvidenceSummaryCard(
                "Process evidence",
                processNodes.Count.ToString(),
                $"Process nodes and {edges.Count(edge => string.Equals(edge.Relation, "spawn", StringComparison.OrdinalIgnoreCase))} spawn edges. Highest finding: {highestSeverity}.",
                processNodes.Count > 0 ? "info" : "low",
                string.Join(Environment.NewLine, ["Process evidence", $"nodes={processNodes.Count}", $"spawnEdges={edges.Count(edge => string.Equals(edge.Relation, "spawn", StringComparison.OrdinalIgnoreCase))}", $"highestFinding={highestSeverity}", .. processNodes.Take(8).Select(node => node.CopyText)])),
            new EvidenceSummaryCard(
                "Network evidence",
                networkIocs.Count.ToString(),
                topNetwork.Count == 0 ? "No network indicators were extracted." : $"Top endpoints: {string.Join(", ", topNetwork)}",
                networkIocs.Count > 0 ? "medium" : "low",
                string.Join(Environment.NewLine, ["Network evidence", $"iocCount={networkIocs.Count}", .. topNetwork])),
            new EvidenceSummaryCard(
                "File and registry evidence",
                (fileIocs.Count + registryIocs.Count).ToString(),
                topStorage.Count == 0 ? "No file or registry indicators were extracted." : $"Top paths: {string.Join(", ", topStorage)}",
                fileIocs.Count + registryIocs.Count > 0 ? "medium" : "low",
                string.Join(Environment.NewLine, ["File and registry evidence", $"fileIocCount={fileIocs.Count}", $"registryIocCount={registryIocs.Count}", .. topStorage])),
            new EvidenceSummaryCard(
                "Artifact evidence",
                artifactIocs.Count.ToString(),
                topArtifacts.Count == 0 ? "No report artifact indicators were indexed." : $"Top artifacts: {string.Join(", ", topArtifacts)}",
                artifactIocs.Count > 0 ? "info" : "low",
                string.Join(Environment.NewLine, ["Artifact evidence", $"artifactIocCount={artifactIocs.Count}", .. topArtifacts]))
        ];
    }

    /// <summary>
    /// Appends a narrative evidence board before dense graph/table sections.
    /// Inputs are normalized report events plus artifact descriptors; processing
    /// groups the evidence into analyst-facing lanes for lineage, released
    /// files, screenshots, memory dumps, packet capture/network, and R0 health;
    /// the method returns no value.
    /// </summary>
    private static void AppendEvidenceStoryBoard(
        StringBuilder html,
        AnalysisReport report,
        IReadOnlyCollection<ArtifactDescriptor> artifacts)
    {
        var cards = BuildEvidenceStoryCards(report, artifacts);
        html.AppendLine("<h3 id=\"evidence-story-board\" class=\"anchor-offset\">Evidence story board</h3>");
        html.AppendLine("<div class=\"section-note\"><strong>Evidence story lanes.</strong> These stable weak-interaction lanes keep the analyst narrative visible before dense tables: process lineage, released files, screenshots, memory dumps, PCAP/network, and R0 collection quality. Each lane shows a short explanation, metric chips, and a bounded native-details evidence sample; complete rows stay in Raw normalized events/report.json and Artifact links.</div>");
        html.AppendLine("<div class=\"evidence-story-board\">");
        foreach (var card in cards)
        {
            var evidenceText = string.Join(Environment.NewLine, card.EvidenceLines);
            var observedEvidenceCount = card.SourceEvidenceCount;
            var shownEvidenceCount = observedEvidenceCount == 0
                ? 0
                : Math.Min(card.EvidenceLines.Count, observedEvidenceCount);
            var evidenceScope = observedEvidenceCount == 0
                ? "Evidence examples shown: 0 observed; lane includes guidance only."
                : $"Evidence examples shown: {shownEvidenceCount}/{observedEvidenceCount}; expand stays bounded and full source remains in Raw normalized events/report.json.";
            html.AppendLine($"<article class=\"evidence-story-lane copyable\" data-copy=\"{A(card.CopyText)}\">");
            html.AppendLine("<div class=\"relationship-title\">");
            html.AppendLine($"<h3>{E(card.Title)}</h3><span class=\"badge badge-{E(card.Css)}\">{E(card.Status)}</span>");
            html.AppendLine("</div>");
            html.AppendLine($"<p class=\"story-lead\">{E(card.Lead)}</p>");
            html.AppendLine($"<p class=\"copy-hint\">{E(evidenceScope)}</p>");
            html.AppendLine("<div class=\"story-metrics\">");
            foreach (var metric in card.Metrics.Take(8))
            {
                html.AppendLine($"<span class=\"copyable\" data-copy=\"{A(metric)}\">{E(metric)}</span>");
            }

            html.AppendLine("</div>");
            html.AppendLine("<div class=\"toolbar\">");
            html.AppendLine(CopyButton("Copy story lane", card.CopyText));
            html.AppendLine("</div>");
            html.AppendLine($"<details class=\"evidence-expansion-card\"><summary>Expand bounded story evidence ({E(shownEvidenceCount.ToString(CultureInfo.InvariantCulture))}/{E(observedEvidenceCount.ToString(CultureInfo.InvariantCulture))} observed rows)</summary>");
            AppendEvidenceExpansionSummary(html, "Story evidence expansion summary", shownEvidenceCount, observedEvidenceCount, "Raw normalized events/report.json and Artifact links", card.EvidenceLines);
            html.AppendLine("<ol class=\"story-evidence-list\">");
            foreach (var line in card.EvidenceLines.Take(12))
            {
                html.AppendLine($"<li><code class=\"copyable\" data-copy=\"{A(line)}\">{E(line)}</code></li>");
            }

            html.AppendLine("</ol>");
            html.AppendLine($"<pre class=\"copyable\" data-copy=\"{A(evidenceText)}\">{E(evidenceText)}</pre>");
            html.AppendLine("</details>");
            html.AppendLine("</article>");
        }

        html.AppendLine("</div>");
    }

    /// <summary>
    /// Builds stable story lanes from existing report evidence without changing
    /// the report schema. Inputs are report events and indexed artifacts;
    /// processing extracts counts, top examples, and copy payloads for the
    /// final static HTML report; return is a bounded card list.
    /// </summary>
    private static IReadOnlyList<EvidenceStoryCard> BuildEvidenceStoryCards(
        AnalysisReport report,
        IReadOnlyCollection<ArtifactDescriptor> artifacts)
    {
        var sampleEvents = report.Events.Where(IsSampleBehaviorEvent).OrderBy(evt => evt.Timestamp).ToList();
        var artifactMatrixRows = BuildArtifactEvidenceMatrixRows(report.Events, artifacts);
        var droppedMatrix = FindArtifactEvidenceMatrixRow(artifactMatrixRows, "dropped-files");
        var screenshotMatrix = FindArtifactEvidenceMatrixRow(artifactMatrixRows, "screenshots");
        var memoryMatrix = FindArtifactEvidenceMatrixRow(artifactMatrixRows, "memory-dumps");
        var packetMatrix = FindArtifactEvidenceMatrixRow(artifactMatrixRows, "packet-captures");
        var processEvents = sampleEvents.Where(IsProcessTreeCandidate).ToList();
        var processNodes = BuildProcessGraphNodes(report).Take(8).ToList();
        var processChildHints = processEvents.Count(HasParentProcessEvidence);
        var processEvidence = processEvents.Take(8).Select(EventOneLine).ToList();
        if (processEvidence.Count == 0)
        {
            processEvidence.AddRange(processNodes.Take(8).Select(node => node.CopyText));
        }

        var matrixOverviewLine = ArtifactEvidenceMatrixOverviewLine(artifactMatrixRows);
        if (!string.IsNullOrWhiteSpace(matrixOverviewLine))
        {
            processEvidence.Add(matrixOverviewLine);
        }

        var droppedArtifacts = StoryArtifactsByKind(artifacts, ArtifactKind.DroppedFile);
        var droppedEvents = sampleEvents.Where(IsDroppedFileEvidenceEvent).ToList();
        var fileEvents = sampleEvents.Where(IsFileEvent).ToList();
        var droppedEvidence = AddArtifactMatrixEvidence(
            BuildStoryEvidenceLines(droppedArtifacts, droppedEvents.Count > 0 ? droppedEvents : fileEvents),
            "Dropped-file artifactEvidenceMatrix",
            droppedMatrix);
        var startupEvents = sampleEvents.Where(IsStartupEvent).ToList();
        var startupSurfaces = startupEvents
            .Select(evt => FirstEventDataValue(evt, "startupSurface") ?? evt.EventType)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
            .Take(8)
            .ToList();
        var startupEvidence = startupEvents.Take(8).Select(EventOneLine).ToList();

        var screenshotArtifacts = StoryArtifactsByKind(artifacts, ArtifactKind.Screenshot);
        var screenshotEvents = report.Events.Where(IsScreenshotEvidenceEvent).OrderBy(evt => evt.Timestamp).ToList();
        var screenshotEvidence = AddArtifactMatrixEvidence(
            BuildStoryEvidenceLines(screenshotArtifacts, screenshotEvents),
            "Screenshot artifactEvidenceMatrix",
            screenshotMatrix);

        var memoryArtifacts = StoryArtifactsByKind(artifacts, ArtifactKind.MemoryDump);
        var memoryEvents = report.Events.Where(IsMemoryDumpEvidenceEvent).OrderBy(evt => evt.Timestamp).ToList();
        var childDumpEvents = memoryEvents.Count(evt => TextEqualsAny(FirstEventDataValue(evt, "childProcessDumpEnabled", "includeChildProcesses", "childDumpEnabled") ?? string.Empty, "true", "enabled", "yes"));
        var memoryEvidence = AddArtifactMatrixEvidence(
            BuildStoryEvidenceLines(memoryArtifacts, memoryEvents),
            "Memory dump artifactEvidenceMatrix",
            memoryMatrix);

        var packetArtifacts = StoryArtifactsByKind(artifacts, ArtifactKind.PacketCapture);
        var packetEvents = report.Events.Where(IsPacketCaptureEvidenceEvent).OrderBy(evt => evt.Timestamp).ToList();
        var networkEvents = sampleEvents.Where(IsNetworkEvent).ToList();
        var networkEvidence = AddArtifactMatrixEvidence(
            BuildStoryEvidenceLines(packetArtifacts, packetEvents.Concat(networkEvents).OrderBy(evt => evt.Timestamp).ToList()),
            "PCAP artifactEvidenceMatrix",
            packetMatrix);
        var dnsCount = networkEvents.Count(evt => string.Equals(NetworkCategoryLabel(evt), "DNS", StringComparison.OrdinalIgnoreCase));
        var httpCount = networkEvents.Count(evt => string.Equals(NetworkCategoryLabel(evt), "HTTP", StringComparison.OrdinalIgnoreCase));
        var tlsCount = networkEvents.Count(evt => string.Equals(NetworkCategoryLabel(evt), "TLS", StringComparison.OrdinalIgnoreCase));
        var flowCount = Math.Max(0, networkEvents.Count - dnsCount - httpCount - tlsCount);

        var r0Events = report.Events.Where(IsR0Event).OrderBy(evt => evt.Timestamp).ToList();
        var r0NetworkStatusEvents = r0Events.Where(IsR0DriverNetworkStatusEvent).ToList();
        var r0HealthEvents = r0Events.Where(IsR0HealthRowEvent).ToList();
        var r0SelfNoiseEvents = r0Events.Where(evt => !IsR0HealthRowEvent(evt) && !IsR0DriverNetworkStatusEvent(evt) && IsCollectorSelfNoiseEvent(evt)).ToList();
        var r0TelemetryEvents = r0Events.Where(evt => !IsR0HealthRowEvent(evt) && !IsR0DriverNetworkStatusEvent(evt) && !IsCollectorSelfNoiseEvent(evt)).ToList();
        var r0State = R0AvailabilityStoryState(r0HealthEvents);
        var r0Evidence = r0NetworkStatusEvents
            .Take(3)
            .Select(R0NetworkStatusStoryLine)
            .Concat(r0HealthEvents
            .Take(6)
            .Concat(r0TelemetryEvents.Take(4))
            .Select(EventOneLine))
            .Append($"R0 self-noise events hidden from behavior graph: {r0SelfNoiseEvents.Count}")
            .ToList();

        return
        [
            CreateEvidenceStoryCard(
                "Execution lineage",
                $"{processEvents.Count} nodes",
                processEvents.Count > 0 ? "info" : "low",
                "Process tree rows are shown as the first story lane so parent/child execution is understandable before opening raw telemetry.",
                [
                    $"Process candidates: {processEvents.Count}",
                    $"Child/parent hints: {processChildHints}",
                    $"Graph nodes: {processNodes.Count}",
                    $"Artifact matrix lanes ready: {artifactMatrixRows.Count(row => string.Equals(row.State, "ready", StringComparison.OrdinalIgnoreCase))}/{artifactMatrixRows.Count}",
                    $"Collector/health excluded: {report.Events.Count(evt => IsCollectorSelfNoiseEvent(evt) || IsCollectionHealthEvent(evt))}"
                ],
                processEvidence),
            CreateEvidenceStoryCard(
                "Dropped-file evidence",
                $"{droppedArtifacts.Count} artifacts",
                droppedArtifacts.Count + droppedEvents.Count > 0 ? "medium" : "low",
                "Released or modified files are surfaced as artifact-first evidence with hashes and safe relative paths when available.",
                [
                    $"Dropped artifacts: {droppedArtifacts.Count}",
                    $"Dropped-file events: {droppedEvents.Count}",
                    $"File rows: {fileEvents.Count}",
                    $"Unique file targets: {fileEvents.Select(ExtractReadableEventTarget).Where(value => !string.IsNullOrWhiteSpace(value)).Distinct(StringComparer.OrdinalIgnoreCase).Count()}",
                    ArtifactEvidenceMatrixMetric(droppedMatrix)
                ],
                droppedEvidence),
            CreateEvidenceStoryCard(
                "Startup persistence diff",
                $"{startupEvents.Count} rows",
                startupEvents.Count > 0 ? "high" : "low",
                "Before/after startup inventory facts are summarized before raw rows so services, tasks, Run keys, WMI, IFEO, Winlogon, LSA, AppInit, Winsock, and shell-extension persistence stay explainable.",
                [
                    $"Startup diff rows: {startupEvents.Count}",
                    $"Created/modified: {startupEvents.Count(evt => TextEqualsAny(FirstEventDataValue(evt, "change") ?? string.Empty, "created", "modified"))}",
                    $"Deleted: {startupEvents.Count(evt => TextEqualsAny(FirstEventDataValue(evt, "change") ?? string.Empty, "deleted"))}",
                    $"User-writable targets: {startupEvents.Count(StartupEventHasUserWritableTarget)}",
                    $"Surfaces: {string.Join(", ", startupSurfaces)}"
                ],
                startupEvidence),
            CreateEvidenceStoryCard(
                "Screenshot evidence",
                $"{screenshotArtifacts.Count} captures",
                screenshotArtifacts.Count + screenshotEvents.Count > 0 ? "info" : "low",
                "Screenshot capture is kept visible as visual evidence; previews remain collapsible and safe links are handled in Artifact links.",
                [
                    $"Screenshot artifacts: {screenshotArtifacts.Count}",
                    $"Screenshot events: {screenshotEvents.Count}",
                    $"Captured bytes: {screenshotArtifacts.Sum(artifact => Math.Max(0, artifact.SizeBytes))}",
                    $"Latest capture: {LatestEventTime(screenshotEvents)}",
                    ArtifactEvidenceMatrixMetric(screenshotMatrix)
                ],
                screenshotEvidence),
            CreateEvidenceStoryCard(
                "Memory dump evidence",
                $"{memoryArtifacts.Count} dumps",
                memoryArtifacts.Count + memoryEvents.Count > 0 ? "info" : "low",
                "Opt-in root and child-process memory dumps are summarized separately so large dump artifacts do not disappear inside raw rows.",
                [
                    $"Memory dump artifacts: {memoryArtifacts.Count}",
                    $"Memory dump events: {memoryEvents.Count}",
                    $"Child dump enabled rows: {childDumpEvents}",
                    $"Captured bytes: {memoryArtifacts.Sum(artifact => Math.Max(0, artifact.SizeBytes))}",
                    ArtifactEvidenceMatrixMetric(memoryMatrix)
                ],
                memoryEvidence),
            CreateEvidenceStoryCard(
                "Network and PCAP evidence",
                $"{networkEvents.Count} rows",
                networkEvents.Count + packetArtifacts.Count + packetEvents.Count > 0 ? "medium" : "low",
                "DNS/HTTP/TLS/flow telemetry and packet-capture artifacts share one story lane before endpoint cards and raw packet rows.",
                [
                    $"Network rows: {networkEvents.Count}",
                    $"Packet artifacts: {packetArtifacts.Count}",
                    $"Packet capture events: {packetEvents.Count}",
                    $"DNS/HTTP/TLS/flow: {dnsCount}/{httpCount}/{tlsCount}/{flowCount}",
                    ArtifactEvidenceMatrixMetric(packetMatrix)
                ],
                networkEvidence),
            CreateEvidenceStoryCard(
                "R0 health/noise boundary",
                r0State,
                r0HealthEvents.Any(IsCollectionHealthAlertEvent) || r0HealthEvents.Any(IsDeviceUnavailableHealthEvent) ? "medium" : "info",
                "R0 availability, queue loss, and collector self-noise are called out as evidence-quality context, not sample behavior.",
                [
                    $"R0 health rows: {r0HealthEvents.Count}",
                    $"R0 network status rows: {r0NetworkStatusEvents.Count}",
                    $"R0 telemetry rows: {r0TelemetryEvents.Count}",
                    $"Self-noise hidden: {r0SelfNoiseEvents.Count}",
                    $"Health alerts: {r0HealthEvents.Count(IsCollectionHealthAlertEvent)}"
                ],
                r0Evidence)
        ];
    }

    private static EvidenceStoryCard CreateEvidenceStoryCard(
        string title,
        string status,
        string css,
        string lead,
        IReadOnlyList<string> metrics,
        IReadOnlyCollection<string> evidenceLines)
    {
        var sourceLines = evidenceLines
            .Where(line => !string.IsNullOrWhiteSpace(line))
            .ToList();
        var sourceEvidenceCount = sourceLines.Count;
        var lines = sourceLines
            .Take(EvidenceStoryInlineLimit)
            .ToList();
        if (lines.Count == 0)
        {
            lines.Add("No inline evidence observed in this lane; check Raw normalized events/report.json and Artifact links for complete source data.");
        }

        var shownEvidenceCount = sourceEvidenceCount == 0
            ? 0
            : Math.Min(lines.Count, sourceEvidenceCount);
        var copy = string.Join(
            Environment.NewLine,
            [
                title,
                $"status={status}",
                lead,
                $"evidenceExamplesShown={shownEvidenceCount}/{sourceEvidenceCount}",
                "metrics:",
                .. metrics,
                "evidence:",
                .. lines
            ]);
        return new EvidenceStoryCard(title, status, css, lead, metrics, lines, sourceEvidenceCount, copy);
    }

    /// <summary>
    /// Appends a compact visible summary at the top of an evidence expansion.
    /// Inputs are rendered/source counts, a complete-source hint, and sample
    /// evidence lines; processing emits copyable chips before dense pre/list
    /// payloads so collapsed details have an immediately readable story.
    /// </summary>
    private static void AppendEvidenceExpansionSummary(
        StringBuilder html,
        string title,
        int renderedCount,
        int sourceCount,
        string completeSource,
        IReadOnlyCollection<string> evidenceLines)
    {
        var hiddenCount = Math.Max(0, sourceCount - renderedCount);
        var firstEvidence = evidenceLines.FirstOrDefault(line => !string.IsNullOrWhiteSpace(line)) ?? "-";
        var previewLines = evidenceLines
            .Where(line => !string.IsNullOrWhiteSpace(line))
            .Take(3)
            .ToList();
        var copy = string.Join(
            Environment.NewLine,
            [
                title,
                $"renderedEvidence={renderedCount}",
                $"sourceEvidence={sourceCount}",
                $"hiddenEvidence={hiddenCount}",
                $"completeSource={completeSource}",
                $"firstEvidence={firstEvidence}",
                "previewEvidence:",
                .. previewLines
            ]);
        html.AppendLine($"<div class=\"evidence-expansion-summary copyable\" data-copy=\"{A(copy)}\">");
        html.AppendLine($"<strong>{E(title)}</strong>");
        html.AppendLine("<div class=\"relationship-tags\">");
        html.AppendLine($"<span class=\"chip chip-info\">shown {E(renderedCount.ToString(CultureInfo.InvariantCulture))}/{E(sourceCount.ToString(CultureInfo.InvariantCulture))}</span>");
        html.AppendLine($"<span class=\"chip chip-medium\">hidden {E(hiddenCount.ToString(CultureInfo.InvariantCulture))}</span>");
        html.AppendLine($"<span class=\"chip chip-low\">complete source: {E(completeSource)}</span>");
        html.AppendLine("</div>");
        html.AppendLine($"<div class=\"copy-hint\">First evidence: <code>{E(firstEvidence)}</code></div>");
        if (previewLines.Count > 0)
        {
            html.AppendLine("<ol class=\"compact-list evidence-preview-list\">");
            foreach (var line in previewLines)
            {
                html.AppendLine($"<li><code class=\"copyable\" data-copy=\"{A(line)}\">{E(line)}</code></li>");
            }

            html.AppendLine("</ol>");
        }

        html.AppendLine($"<div class=\"toolbar\">{CopyButton("Copy evidence expansion summary", copy)}</div>");
        html.AppendLine("</div>");
    }

    private static IReadOnlyList<string> BuildStoryEvidenceLines(
        IReadOnlyCollection<ArtifactDescriptor> artifacts,
        IReadOnlyCollection<SandboxEvent> events)
    {
        return artifacts
            .Take(5)
            .Select(ArtifactStoryLine)
            .Concat(events.Take(7).Select(EventOneLine))
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Take(EvidenceStoryInlineLimit)
            .ToList();
    }

    private static IReadOnlyList<string> AddArtifactMatrixEvidence(
        IReadOnlyList<string> evidenceLines,
        string label,
        ArtifactEvidenceMatrixRow? matrixRow)
    {
        var lines = new List<string>();
        if (matrixRow is not null)
        {
            lines.Add(ArtifactEvidenceMatrixEvidenceLine(label, matrixRow));
        }

        lines.AddRange(evidenceLines);
        return lines
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Take(EvidenceStoryInlineLimit)
            .ToList();
    }

    private static ArtifactEvidenceMatrixRow? FindArtifactEvidenceMatrixRow(
        IReadOnlyCollection<ArtifactEvidenceMatrixRow> rows,
        string collectionName)
    {
        return rows.FirstOrDefault(row => string.Equals(row.CollectionName, collectionName, StringComparison.OrdinalIgnoreCase));
    }

    private static string ArtifactEvidenceMatrixMetric(ArtifactEvidenceMatrixRow? row)
    {
        return row is null
            ? "artifactEvidenceMatrix: not reported"
            : $"artifactEvidenceMatrix: {row.CollectionName}={row.Count}:{row.State}:{row.Bytes} bytes";
    }

    private static string ArtifactEvidenceMatrixEvidenceLine(string label, ArtifactEvidenceMatrixRow row)
    {
        var selectors = string.IsNullOrWhiteSpace(row.Selectors) ? "-" : row.Selectors;
        return $"{label}: collection={row.CollectionName} | kind={row.Kind} | count={row.Count} | state={row.State} | bytes={row.Bytes} | selectors={selectors} | source={row.Source}";
    }

    private static string ArtifactEvidenceMatrixOverviewLine(IReadOnlyCollection<ArtifactEvidenceMatrixRow> rows)
    {
        if (rows.Count == 0)
        {
            return string.Empty;
        }

        return "artifactEvidenceMatrix overview: " + string.Join("; ", rows.Select(row => $"{row.CollectionName}={row.Count}:{row.State}:{row.Bytes}"));
    }

    private static IReadOnlyList<ArtifactEvidenceMatrixRow> BuildArtifactEvidenceMatrixRows(
        IReadOnlyCollection<SandboxEvent> events,
        IReadOnlyCollection<ArtifactDescriptor> artifacts)
    {
        var rows = new Dictionary<string, ArtifactEvidenceMatrixRow>(StringComparer.OrdinalIgnoreCase);
        foreach (var evt in events.OrderBy(evt => evt.Timestamp))
        {
            var matrix = FirstEventDataValue(evt, "artifactEvidenceMatrix");
            foreach (var row in ParseArtifactEvidenceMatrix(matrix, evt.EventType))
            {
                rows[row.CollectionName] = row;
            }

            MergeEventMatrixCount(rows, evt, "dropped-files", ArtifactKind.DroppedFile, "droppedFileArtifactCount", "droppedFileBytes");
            MergeEventMatrixCount(rows, evt, "screenshots", ArtifactKind.Screenshot, "screenshotArtifactCount", "screenshotBytes");
            MergeEventMatrixCount(rows, evt, "memory-dumps", ArtifactKind.MemoryDump, "memoryDumpArtifactCount", "memoryDumpBytes");
            MergeEventMatrixCount(rows, evt, "packet-captures", ArtifactKind.PacketCapture, "packetCaptureArtifactCount", "packetCaptureBytes");
        }

        foreach (var evt in events.OrderBy(evt => evt.Timestamp))
        {
            MergeDisabledArtifactCollectionState(rows, evt);
        }

        MergeArtifactMatrixFallback(rows, artifacts, "dropped-files", ArtifactKind.DroppedFile);
        MergeArtifactMatrixFallback(rows, artifacts, "screenshots", ArtifactKind.Screenshot);
        MergeArtifactMatrixFallback(rows, artifacts, "memory-dumps", ArtifactKind.MemoryDump);
        MergeArtifactMatrixFallback(rows, artifacts, "packet-captures", ArtifactKind.PacketCapture);

        return rows.Values
            .OrderBy(row => ArtifactEvidenceMatrixRank(row.CollectionName))
            .ThenBy(row => row.CollectionName, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static IEnumerable<ArtifactEvidenceMatrixRow> ParseArtifactEvidenceMatrix(string? matrix, string source)
    {
        if (string.IsNullOrWhiteSpace(matrix))
        {
            yield break;
        }

        foreach (var token in matrix.Split([';', ',', '|'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var parts = token.Split('=', 2, StringSplitOptions.TrimEntries);
            if (parts.Length != 2 || string.IsNullOrWhiteSpace(parts[0]))
            {
                continue;
            }

            var valueParts = parts[1].Split(':', StringSplitOptions.TrimEntries);
            var count = valueParts.Length > 0 && int.TryParse(valueParts[0], NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsedCount)
                ? parsedCount
                : 0;
            var state = valueParts.Length > 1 && !string.IsNullOrWhiteSpace(valueParts[1]) ? valueParts[1] : InferMatrixState(count);
            var bytes = valueParts.Length > 2 && long.TryParse(valueParts[2], NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsedBytes)
                ? parsedBytes
                : 0;
            var collectionName = NormalizeArtifactEvidenceCollectionName(parts[0]);
            yield return new ArtifactEvidenceMatrixRow(collectionName, ArtifactKindForMatrixCollection(collectionName), count, state, bytes, source, string.Empty);
        }
    }

    private static void MergeEventMatrixCount(
        IDictionary<string, ArtifactEvidenceMatrixRow> rows,
        SandboxEvent evt,
        string collectionName,
        ArtifactKind kind,
        string countKey,
        string bytesKey)
    {
        var countValue = FirstEventDataValue(evt, countKey);
        if (!int.TryParse(countValue, NumberStyles.Integer, CultureInfo.InvariantCulture, out var count))
        {
            return;
        }

        var bytes = long.TryParse(FirstEventDataValue(evt, bytesKey), NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsedBytes)
            ? parsedBytes
            : 0;
        var state = count > 0 ? "ready" : "missing";
        rows[collectionName] = new ArtifactEvidenceMatrixRow(collectionName, kind, count, state, bytes, evt.EventType, FirstEventDataValue(evt, "primaryArtifactSelectors") ?? string.Empty);
    }

    private static void MergeDisabledArtifactCollectionState(
        IDictionary<string, ArtifactEvidenceMatrixRow> rows,
        SandboxEvent evt)
    {
        if (!TryGetDisabledArtifactCollection(evt, out var collectionName, out var kind))
        {
            return;
        }

        if (rows.TryGetValue(collectionName, out var existing) &&
            existing.Count > 0 &&
            string.Equals(existing.State, "ready", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var selectors = rows.TryGetValue(collectionName, out existing) ? existing.Selectors : string.Empty;
        rows[collectionName] = new ArtifactEvidenceMatrixRow(
            collectionName,
            kind,
            existing?.Count ?? 0,
            "disabled",
            existing?.Bytes ?? 0,
            evt.EventType,
            selectors);
    }

    private static void MergeArtifactMatrixFallback(
        IDictionary<string, ArtifactEvidenceMatrixRow> rows,
        IReadOnlyCollection<ArtifactDescriptor> artifacts,
        string collectionName,
        ArtifactKind kind)
    {
        if (rows.ContainsKey(collectionName))
        {
            return;
        }

        var laneArtifacts = artifacts
            .Where(artifact => artifact.Kind == kind && !IsCollectorSelfNoiseArtifact(artifact))
            .ToList();
        if (laneArtifacts.Count == 0)
        {
            return;
        }

        var selectors = string.Join(",", laneArtifacts
            .Select(artifact => FirstNonEmpty(MetadataValue(artifact.Metadata, "downloadSelector", "safeRelativeSelector"), artifact.SafeLink, artifact.RelativePath))
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(4));
        rows[collectionName] = new ArtifactEvidenceMatrixRow(
            collectionName,
            kind,
            laneArtifacts.Count,
            "ready",
            laneArtifacts.Sum(artifact => Math.Max(0, artifact.SizeBytes)),
            "artifact-index-fallback",
            selectors);
    }

    private static string NormalizeArtifactEvidenceCollectionName(string value)
    {
        var normalized = value.Trim().ToLowerInvariant().Replace('_', '-');
        return normalized switch
        {
            "dropped-file" or "dropped-files" or "droppedfiles" => "dropped-files",
            "screenshot" or "screenshots" => "screenshots",
            "memory-dump" or "memory-dumps" or "memorydumps" => "memory-dumps",
            "packet-capture" or "packet-captures" or "pcap" or "pcapng" => "packet-captures",
            _ => normalized
        };
    }

    private static ArtifactKind ArtifactKindForMatrixCollection(string collectionName)
    {
        return collectionName switch
        {
            "dropped-files" => ArtifactKind.DroppedFile,
            "screenshots" => ArtifactKind.Screenshot,
            "memory-dumps" => ArtifactKind.MemoryDump,
            "packet-captures" => ArtifactKind.PacketCapture,
            _ => ArtifactKind.Unknown
        };
    }

    private static int ArtifactEvidenceMatrixRank(string collectionName)
    {
        return collectionName switch
        {
            "dropped-files" => 0,
            "screenshots" => 1,
            "memory-dumps" => 2,
            "packet-captures" => 3,
            _ => 100
        };
    }

    private static string InferMatrixState(int count)
    {
        return count > 0 ? "ready" : "missing";
    }

    private static List<ArtifactDescriptor> StoryArtifactsByKind(
        IReadOnlyCollection<ArtifactDescriptor> artifacts,
        ArtifactKind kind)
    {
        return artifacts
            .Where(artifact => artifact.Kind == kind && !IsCollectorSelfNoiseArtifact(artifact))
            .OrderBy(artifact => ArtifactKindRank(artifact.Kind))
            .ThenBy(artifact => artifact.RelativePath, StringComparer.OrdinalIgnoreCase)
            .ThenBy(artifact => artifact.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static string ArtifactStoryLine(ArtifactDescriptor artifact)
    {
        var display = ArtifactDisplayName(artifact);
        var hash = ArtifactSha256(artifact);
        var size = FormatArtifactSize(artifact.SizeBytes);
        var role = string.IsNullOrWhiteSpace(artifact.Category) ? artifact.Kind.ToString() : artifact.Category;
        return $"artifact={display} | role={role} | size={size} | sha256={hash} | path={artifact.RelativePath} | selector={FirstNonEmpty(MetadataValue(artifact.Metadata, "downloadSelector"), artifact.RelativePath, "-")} | duplicate={DuplicateArtifactLabel(artifact) ?? "false"} | rejection={ArtifactRejectionLabel(artifact) ?? "none"}";
    }

    private static bool HasParentProcessEvidence(SandboxEvent evt)
    {
        return evt.ParentProcessId.HasValue ||
            !string.IsNullOrWhiteSpace(FirstEventDataValue(
                evt,
                "parentProcessId",
                "parentPid",
                "ppid",
                "parentProcessKey",
                "parentProcessGuid",
                "parentProcessName",
                "parentImageName"));
    }

    private static string LatestEventTime(IReadOnlyCollection<SandboxEvent> events)
    {
        return events.Count == 0
            ? "-"
            : events.Max(evt => evt.Timestamp).ToString("u");
    }

    private static string R0AvailabilityStoryState(IReadOnlyCollection<SandboxEvent> healthEvents)
    {
        if (healthEvents.Count == 0)
        {
            return "no health rows";
        }

        if (healthEvents.Any(IsDeviceUnavailableHealthEvent))
        {
            return "unavailable/degraded";
        }

        return healthEvents.Any(IsCollectionHealthAlertEvent)
            ? "attention needed"
            : "available";
    }

    /// <summary>
    /// Appends a health narrative across evidence-quality lanes.
    /// Inputs are the rendered report and indexed artifacts; processing writes
    /// static copyable pills for R0 health, VT enrichment, and artifact index
    /// quality so operators can separate collection status from sample behavior
    /// before reading dense event tables.
    /// </summary>
    private static void AppendEvidenceHealthNarrative(
        StringBuilder html,
        AnalysisReport report,
        IReadOnlyCollection<ArtifactDescriptor> artifacts)
    {
        var r0HealthEvents = report.Events.Where(IsR0HealthRowEvent).ToList();
        var vtEvents = report.Events.Where(IsVirusTotalEvent).ToList();
        var downloadable = artifacts.Count(artifact => !string.IsNullOrWhiteSpace(ArtifactHref(artifact)));
        var rejectedReferences = artifacts.Where(HasArtifactRejectionDiagnostics).Sum(ArtifactRejectedCount);
        var duplicateMembers = artifacts.Count(IsDuplicateArtifactDescriptor);
        var vtIssueCount = vtEvents.Count(IsVirusTotalStatusIssue);
        var copy = string.Join(
            Environment.NewLine,
            [
                "Evidence health narrative",
                $"r0State={R0AvailabilityStoryState(r0HealthEvents)}",
                $"r0HealthRows={r0HealthEvents.Count}",
                $"vtLookups={vtEvents.Count}",
                $"vtStatusIssues={vtIssueCount}",
                $"artifactCount={artifacts.Count}",
                $"downloadableArtifacts={downloadable}",
                $"duplicateArtifactMembers={duplicateMembers}",
                $"rejectedArtifactReferences={rejectedReferences}",
                "policy=R0/VT/artifact health affects evidence confidence and is not counted as primary sample behavior"
            ]);

        html.AppendLine("<h3>Evidence health narrative</h3>");
        html.AppendLine("<div class=\"section-note\"><strong>R0 / VT / Artifact health narrative.</strong> These health lanes explain evidence confidence separately from behavioral risk: R0 readiness, VT enrichment quality, and artifact selector/index integrity are visible, copyable, and bounded.</div>");
        html.AppendLine($"<div class=\"health-narrative-grid copyable\" data-copy=\"{A(copy)}\">");
        AppendHealthPill(
            html,
            "R0 health",
            R0AvailabilityStoryState(r0HealthEvents),
            $"rows={r0HealthEvents.Count}; alerts={r0HealthEvents.Count(IsCollectionHealthAlertEvent)}");
        AppendHealthPill(
            html,
            "VT enrichment",
            vtEvents.Count == 0 ? "not recorded" : vtIssueCount > 0 ? "status issues" : "lookup evidence",
            $"lookups={vtEvents.Count}; statusIssues={vtIssueCount}");
        AppendHealthPill(
            html,
            "Artifact index",
            artifacts.Count == 0 ? "not indexed" : rejectedReferences > 0 ? "rejections explained" : "selectors ready",
            $"downloadable={downloadable}/{artifacts.Count}; duplicates={duplicateMembers}; rejected={rejectedReferences}");
        html.AppendLine(CopyButton("Copy health narrative", copy));
        html.AppendLine("</div>");
    }

    private static void AppendHealthPill(StringBuilder html, string label, string state, string detail)
    {
        var copy = $"{label}: {state}; {detail}";
        html.AppendLine($"<span class=\"health-pill copyable\" data-copy=\"{A(copy)}\"><strong>{E(label)}</strong> · {E(state)}<br><small>{E(detail)}</small></span>");
    }

    private static bool IsDroppedFileEvidenceEvent(SandboxEvent evt)
    {
        if (IsDisabledArtifactCollectionEvent(evt))
        {
            return false;
        }

        var role = FirstEventDataValue(evt, "evidenceRole", "artifactKind", "kind", "collectionName") ?? string.Empty;
        return evt.EventType.StartsWith("artifact.dropped_file.", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("dropped_file.", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("dropped-file.", StringComparison.OrdinalIgnoreCase) ||
            TextContainsAny(role, "dropped-file", "dropped_file", "dropped-files") ||
            string.Equals(FirstEventDataValue(evt, "collectionName"), "dropped-files", StringComparison.OrdinalIgnoreCase) ||
            (IsFileEvent(evt) && EventTextContainsAny(evt, "dropped-files", "dropped_file", "dropped-file"));
    }

    private static bool IsScreenshotEvidenceEvent(SandboxEvent evt)
    {
        if (IsDisabledArtifactCollectionEvent(evt))
        {
            return false;
        }

        return evt.EventType.StartsWith("screenshot.", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(FirstEventDataValue(evt, "collectionName"), "screenshots", StringComparison.OrdinalIgnoreCase) ||
            EventTextContainsAny(evt, "screenshotRelativePath", "screenshotPath", "screenshots");
    }

    private static bool IsMemoryDumpEvidenceEvent(SandboxEvent evt)
    {
        if (IsDisabledArtifactCollectionEvent(evt))
        {
            return false;
        }

        return evt.EventType.StartsWith("memory_dump.", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("memory-dump.", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(FirstEventDataValue(evt, "collectionName"), "memory-dumps", StringComparison.OrdinalIgnoreCase) ||
            EventTextContainsAny(evt, "memoryDumpRelativePath", "memoryDumpPath", "memory-dumps", ".dmp");
    }

    private static bool IsPacketCaptureEvidenceEvent(SandboxEvent evt)
    {
        if (IsDisabledArtifactCollectionEvent(evt))
        {
            return false;
        }

        return evt.EventType.StartsWith("packet_capture.", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("packet-capture.", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("pcap.", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(FirstEventDataValue(evt, "collectionName"), "packet-captures", StringComparison.OrdinalIgnoreCase) ||
            EventTextContainsAny(evt, "packetCaptureRelativePath", "pcapRelativePath", "pcapngRelativePath", "pktmon", ".pcap", ".pcapng", ".etl");
    }

    private static bool IsDisabledArtifactCollectionEvent(SandboxEvent evt)
    {
        return TryGetDisabledArtifactCollection(evt, out _, out _);
    }

    private static bool TryGetDisabledArtifactCollection(SandboxEvent evt, out string collectionName, out ArtifactKind kind)
    {
        var eventType = evt.EventType ?? string.Empty;
        var state = FirstEventDataValue(evt, "captureState", "status", "collectionState", "state") ?? string.Empty;
        var disabled = eventType.EndsWith(".disabled", StringComparison.OrdinalIgnoreCase) ||
            TextEqualsAny(state, "disabled", "not-enabled", "not_enabled", "off");

        if (!disabled)
        {
            collectionName = string.Empty;
            kind = ArtifactKind.Unknown;
            return false;
        }

        var collection = FirstEventDataValue(evt, "collectionName", "artifactKind", "kind", "evidenceRole") ?? eventType;
        if (TextContainsAny(eventType, "packet_capture", "packet-capture", "pcap") ||
            TextContainsAny(collection, "packet-capture", "packet_capture", "packet-captures", "pcap"))
        {
            collectionName = "packet-captures";
            kind = ArtifactKind.PacketCapture;
            return true;
        }

        if (TextContainsAny(eventType, "screenshot") || TextContainsAny(collection, "screenshot", "screenshots"))
        {
            collectionName = "screenshots";
            kind = ArtifactKind.Screenshot;
            return true;
        }

        if (TextContainsAny(eventType, "memory_dump", "memory-dump") ||
            TextContainsAny(collection, "memory-dump", "memory_dump", "memory-dumps"))
        {
            collectionName = "memory-dumps";
            kind = ArtifactKind.MemoryDump;
            return true;
        }

        if (TextContainsAny(eventType, "dropped_file", "dropped-file") ||
            TextContainsAny(collection, "dropped-file", "dropped_file", "dropped-files"))
        {
            collectionName = "dropped-files";
            kind = ArtifactKind.DroppedFile;
            return true;
        }

        collectionName = string.Empty;
        kind = ArtifactKind.Unknown;
        return false;
    }

    /// <summary>
    /// Appends host-safe artifact links and paths.
    /// Inputs are normalized artifact descriptors; processing renders links for
    /// safe relative paths and plain text for guest-local or unsafe paths; the
    /// method returns no value.
    /// </summary>
    private static void AppendArtifactLinks(StringBuilder html, AnalysisReport report, IReadOnlyCollection<ArtifactDescriptor> artifacts)
    {
        html.AppendLine("<section id=\"artifacts\" class=\"card\"><h2>Artifact links</h2>");
        html.AppendLine("<div class=\"section-note\"><strong>Artifact evidence cards.</strong> Collection status, safe download selectors, duplicate grouping, and rejection diagnostics are summarized before the dense artifact table. Safe report-relative links can open or download; absolute host/guest paths remain copy-only evidence.</div>");
        AppendArtifactCollectionStatusCards(html, report, artifacts);
        AppendArtifactEvidenceMatrixNarrative(html, report, artifacts);
        AppendArtifactIndexStory(html, artifacts);
        if (artifacts.Count == 0)
        {
            Empty(html, "No events.json, driver-events.jsonl, screenshot, or dropped-file artifacts were indexed.");
            html.AppendLine("</section>");
            return;
        }

        html.AppendLine("<table><thead><tr><th>Category</th><th>Artifact</th><th>Path / safe link</th><th>Size</th><th>SHA-256</th><th>MIME</th><th>Evidence</th></tr></thead><tbody>");
        foreach (var artifact in artifacts)
        {
            var plain = ArtifactToPlainText(artifact);
            html.AppendLine("<tr>");
            html.AppendLine($"<td class=\"copyable\" data-copy=\"{A(artifact.Category)}\">{E(artifact.Category)}</td>");
            html.AppendLine($"<td class=\"copyable\" data-copy=\"{A(artifact.Name)}\"><strong>{E(artifact.Name)}</strong><br><span class=\"muted\">{E(artifact.Kind.ToString())}</span></td>");
            html.AppendLine($"<td class=\"copyable\" data-copy=\"{A(plain)}\">{RenderArtifactLocation(artifact)}</td>");
            html.AppendLine($"<td>{E(FormatArtifactSize(artifact.SizeBytes))}</td>");
            html.AppendLine($"<td><code>{E(ArtifactSha256(artifact))}</code></td>");
            html.AppendLine($"<td>{E(string.IsNullOrWhiteSpace(artifact.MimeType) ? "-" : artifact.MimeType)}</td>");
            html.AppendLine($"<td class=\"evidence\"><span class=\"inline-actions\">{CopyButton("Copy artifact", plain)}</span>{RenderArtifactIndexEvidence(artifact)}<details class=\"evidence-expansion-card\"><summary>Expand artifact evidence</summary><pre class=\"copyable\" data-copy=\"{A(plain)}\">{E(plain)}</pre></details>{RenderArtifactPreview(artifact)}</td>");
            html.AppendLine("</tr>");
        }

        html.AppendLine("</tbody></table>");
        html.AppendLine("<div class=\"copy-hint\">Safe links are relative to the report artifact root; unsafe or guest-local paths are shown as copyable text only.</div>");
        html.AppendLine("</section>");
    }

    /// <summary>
    /// Appends a compact artifact-evidence matrix narrative before the dense
    /// artifact table. Inputs are normalized events and indexed artifacts;
    /// processing merges artifactEvidenceMatrix events with artifact-index
    /// fallback counts; return is none.
    /// </summary>
    private static void AppendArtifactEvidenceMatrixNarrative(
        StringBuilder html,
        AnalysisReport report,
        IReadOnlyCollection<ArtifactDescriptor> artifacts)
    {
        var rows = BuildArtifactEvidenceMatrixRows(report.Events, artifacts);
        if (rows.Count == 0)
        {
            return;
        }

        var readyRows = rows.Count(row => IsReadyArtifactMatrixState(row.State));
        var totalArtifacts = rows.Sum(row => Math.Max(0, row.Count));
        var totalBytes = rows.Sum(row => Math.Max(0, row.Bytes));
        var matrixLines = rows
            .Select(row => ArtifactEvidenceMatrixEvidenceLine("artifactEvidenceMatrix narrative", row))
            .ToList();
        var copy = string.Join(
            Environment.NewLine,
            [
                "Artifact evidence matrix narrative",
                $"lanes={rows.Count}",
                $"readyLanes={readyRows}",
                $"artifactReferences={totalArtifacts}",
                $"totalBytes={totalBytes}",
                "lanes:",
                .. matrixLines
            ]);

        html.AppendLine("<h3>Artifact evidence matrix narrative</h3>");
        html.AppendLine("<div class=\"section-note\"><strong>Artifact evidence matrix narrative.</strong> Matrix lanes summarize dropped files, screenshots, memory dumps, and packet captures before the artifact table. Counts come from normalized <code>artifactEvidenceMatrix</code> rows when present and fall back to the artifact index, so missing lanes stay explicit without expanding raw rows.</div>");
        html.AppendLine($"<div class=\"overview-strip artifact-matrix-narrative copyable\" data-copy=\"{A(copy)}\">");
        AppendOverviewItem(
            html,
            "Matrix lanes",
            rows.Count.ToString(CultureInfo.InvariantCulture),
            $"Ready lanes: {readyRows}; bounded lane cards summarize collection state before dense artifacts.",
            readyRows > 0 ? "risk-info" : "risk-low");
        AppendOverviewItem(
            html,
            "Artifact references",
            totalArtifacts.ToString(CultureInfo.InvariantCulture),
            $"Total bytes represented by matrix lanes: {FormatBytes(totalBytes)}.",
            totalArtifacts > 0 ? "risk-info" : "risk-low");
        AppendOverviewItem(
            html,
            "Selector coverage",
            rows.Count(row => !string.IsNullOrWhiteSpace(row.Selectors)).ToString(CultureInfo.InvariantCulture),
            "Rows with selectors can be copied directly; safe Open/Download actions remain in the artifact table.",
            rows.Any(row => !string.IsNullOrWhiteSpace(row.Selectors)) ? "risk-info" : "risk-low");
        html.AppendLine($"<div class=\"toolbar\">{CopyButton("Copy artifact matrix narrative", copy)}</div>");
        html.AppendLine("</div>");
        html.AppendLine("<details class=\"evidence-expansion-card\"><summary>Artifact evidence matrix narrative rows</summary>");
        AppendEvidenceExpansionSummary(html, "Artifact matrix expansion summary", rows.Count, rows.Count, "Artifact links and Raw normalized events/report.json", matrixLines);
        html.AppendLine("<ol class=\"compact-list\">");
        foreach (var line in matrixLines.Take(EvidenceStoryInlineLimit))
        {
            html.AppendLine($"<li><code class=\"copyable\" data-copy=\"{A(line)}\">{E(line)}</code></li>");
        }

        html.AppendLine("</ol></details>");
    }

    private static bool IsReadyArtifactMatrixState(string state)
    {
        return TextEqualsAny(state, "ready", "captured", "observed", "available", "complete");
    }

    /// <summary>
    /// Appends host artifact-index safety and duplicate diagnostics before the
    /// dense artifact table. Inputs are normalized artifact descriptors;
    /// processing summarizes safe download selectors, duplicate groups, and
    /// manifest rejection diagnostics in copyable square cards.
    /// </summary>
    private static void AppendArtifactIndexStory(StringBuilder html, IReadOnlyCollection<ArtifactDescriptor> artifacts)
    {
        var downloadable = artifacts.Count(artifact => !string.IsNullOrWhiteSpace(ArtifactHref(artifact)));
        var selectorCount = artifacts.Count(HasDownloadSelectorEvidence);
        var duplicateMembers = artifacts.Count(IsDuplicateArtifactDescriptor);
        var duplicateGroups = artifacts
            .Select(artifact => MetadataValue(artifact.Metadata, "duplicateGroupId", "duplicateGroupKey"))
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Count();
        var rejectionArtifacts = artifacts
            .Where(HasArtifactRejectionDiagnostics)
            .OrderBy(artifact => artifact.CollectionName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(artifact => artifact.RelativePath, StringComparer.OrdinalIgnoreCase)
            .ToList();
        var rejectedCount = rejectionArtifacts.Sum(ArtifactRejectedCount);
        var copy = string.Join(
            Environment.NewLine,
            [
                "Artifact index evidence",
                $"artifactCount={artifacts.Count}",
                $"downloadableArtifacts={downloadable}",
                $"selectorEvidenceArtifacts={selectorCount}",
                $"duplicateGroups={duplicateGroups}",
                $"duplicateMembers={duplicateMembers}",
                $"rejectedArtifactReferences={rejectedCount}",
                .. artifacts.Take(12).Select(ArtifactIndexEvidenceLine)
            ]);

        html.AppendLine("<h3>Artifact index evidence</h3>");
        html.AppendLine("<div class=\"section-note\"><strong>Host artifact index.</strong> Download buttons use safe report-relative selectors only; duplicate grouping and rejection diagnostics explain why guest manifest references were accepted, deduplicated, or rejected.</div>");
        html.AppendLine("<div class=\"overview-strip artifact-index-overview\">");
        AppendOverviewItem(
            html,
            "Safe download selectors",
            $"{downloadable}/{artifacts.Count}",
            $"Artifacts with explicit selector evidence: {selectorCount}. Unsafe or guest-local paths remain copy-only.",
            downloadable == artifacts.Count && artifacts.Count > 0 ? "risk-low" : "risk-info");
        AppendOverviewItem(
            html,
            "Duplicate artifact groups",
            duplicateGroups.ToString(CultureInfo.InvariantCulture),
            $"Duplicate members: {duplicateMembers}; primary selectors are preserved in each artifact evidence block.",
            duplicateGroups > 0 ? "risk-info" : "risk-low");
        AppendOverviewItem(
            html,
            "Rejected artifact references",
            rejectedCount.ToString(CultureInfo.InvariantCulture),
            rejectionArtifacts.Count == 0 ? "No host-side manifest rejection diagnostics are attached to indexed artifacts." : $"Collections with rejection diagnostics: {rejectionArtifacts.Count}.",
            rejectedCount > 0 ? "risk-medium" : "risk-low");
        html.AppendLine("</div>");
        html.AppendLine($"<details class=\"evidence-expansion-card\"><summary>Artifact index selector/duplicate/rejection evidence</summary><pre class=\"copyable\" data-copy=\"{A(copy)}\">{E(copy)}</pre></details>");
    }

    /// <summary>
    /// Appends collection-lane status cards for operator triage.
    /// Inputs are normalized events and indexed artifacts; processing derives
    /// captured/failed/skipped/disabled status for key evidence lanes; return
    /// value is none.
    /// </summary>
    private static void AppendArtifactCollectionStatusCards(
        StringBuilder html,
        AnalysisReport report,
        IReadOnlyCollection<ArtifactDescriptor> artifacts)
    {
        var matrixRows = BuildArtifactEvidenceMatrixRows(report.Events, artifacts);
        var cards = BuildArtifactCollectionStatusCards(report, artifacts, matrixRows);
        html.AppendLine("<h3>Artifact collection status</h3>");
        html.AppendLine("<div class=\"evidence-summary-grid artifact-status-grid\">");
        foreach (var card in cards)
        {
            html.AppendLine($"<article class=\"evidence-summary-card copyable\" data-copy=\"{A(card.CopyText)}\">");
            html.AppendLine("<div class=\"relationship-title\">");
            html.AppendLine($"<h3>{E(card.Name)}</h3><span class=\"badge badge-{E(card.Css)}\">{E(card.Status)}</span>");
            html.AppendLine("</div>");
            html.AppendLine("<div class=\"relationship-meta\">");
            html.AppendLine($"<span>Artifacts: {E(card.ArtifactCount.ToString())}</span><span>Events: {E(card.EventCount.ToString())}</span>");
            html.AppendLine("</div>");
            html.AppendLine($"<p class=\"muted\">{E(card.Detail)}</p>");
            AppendCompactEvidenceSummary(
                html,
                $"Artifact lane health: collection={card.Name}; status={card.Status}; artifacts={card.ArtifactCount}; events={card.EventCount}; detail={card.Detail}",
                "Copy compact summary");
            html.AppendLine($"<details class=\"evidence-expansion-card\"><summary>Expand collection evidence</summary><pre class=\"copyable\" data-copy=\"{A(card.CopyText)}\">{E(card.CopyText)}</pre></details>");
            html.AppendLine("</article>");
        }

        html.AppendLine("</div>");
    }

    private static IReadOnlyList<ArtifactCollectionStatusCard> BuildArtifactCollectionStatusCards(
        AnalysisReport report,
        IReadOnlyCollection<ArtifactDescriptor> artifacts,
        IReadOnlyCollection<ArtifactEvidenceMatrixRow> matrixRows)
    {
        return
        [
            BuildArtifactCollectionStatusCard(
                "Dropped files",
                "dropped-files",
                ArtifactKind.DroppedFile,
                artifacts,
                report.Events,
                evt => evt.EventType.StartsWith("artifact.dropped_file.", StringComparison.OrdinalIgnoreCase),
                "Copied files released or modified by the sample when collection was enabled.",
                FindArtifactEvidenceMatrixRow(matrixRows, "dropped-files")),
            BuildArtifactCollectionStatusCard(
                "Screenshots",
                "screenshots",
                ArtifactKind.Screenshot,
                artifacts,
                report.Events,
                evt => evt.EventType.StartsWith("screenshot.", StringComparison.OrdinalIgnoreCase),
                "Desktop screenshots captured around sample execution when enabled.",
                FindArtifactEvidenceMatrixRow(matrixRows, "screenshots")),
            BuildArtifactCollectionStatusCard(
                "Memory dumps",
                "memory-dumps",
                ArtifactKind.MemoryDump,
                artifacts,
                report.Events,
                evt => evt.EventType.StartsWith("memory_dump.", StringComparison.OrdinalIgnoreCase),
                "Opt-in process and child-process memory dump artifacts.",
                FindArtifactEvidenceMatrixRow(matrixRows, "memory-dumps")),
            BuildArtifactCollectionStatusCard(
                "Packet captures",
                "packet-captures",
                ArtifactKind.PacketCapture,
                artifacts,
                report.Events,
                evt => evt.EventType.StartsWith("packet_capture.", StringComparison.OrdinalIgnoreCase) || evt.EventType.StartsWith("pcap.", StringComparison.OrdinalIgnoreCase),
                "Opt-in pktmon/PCAP artifacts and imported DNS/HTTP/TLS/flow rows.",
                FindArtifactEvidenceMatrixRow(matrixRows, "packet-captures")),
            BuildArtifactCollectionStatusCard(
                "Driver events",
                "driver-events",
                ArtifactKind.DriverEventsJsonLines,
                artifacts,
                report.Events,
                IsR0Event,
                "R0Collector JSONL and driver-originated telemetry.",
                null)
        ];
    }

    private static ArtifactCollectionStatusCard BuildArtifactCollectionStatusCard(
        string name,
        string collectionName,
        ArtifactKind kind,
        IReadOnlyCollection<ArtifactDescriptor> artifacts,
        IReadOnlyCollection<SandboxEvent> events,
        Func<SandboxEvent, bool> eventPredicate,
        string defaultDetail,
        ArtifactEvidenceMatrixRow? matrixRow)
    {
        var collectionArtifacts = artifacts
            .Where(artifact => artifact.Kind == kind ||
                string.Equals(artifact.CollectionName, collectionName, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(MetadataValue(artifact.Metadata, "collectionName"), collectionName, StringComparison.OrdinalIgnoreCase))
            .ToList();
        var collectionEvents = events.Where(eventPredicate).OrderBy(evt => evt.Timestamp).ToList();
        var status = InferArtifactCollectionStatus(collectionArtifacts, collectionEvents);
        var css = status switch
        {
            "captured" => "low",
            "failed" => "high",
            "disabled" => "info",
            "skipped" => "medium",
            "partial" => "medium",
            "observed" => "info",
            _ => "info"
        };
        var reason = collectionEvents
            .Select(evt => FirstEventDataValue(evt, "reason", "captureState", "status", "diagnosticStage", "commandMessage"))
            .FirstOrDefault(value => !string.IsNullOrWhiteSpace(value));
        var phases = collectionArtifacts
            .Select(artifact => artifact.CapturePhase)
            .Concat(collectionEvents.Select(evt => FirstEventDataValue(evt, "capturePhase", "phase", "screenshotStage", "memoryDumpPhase", "packetCapturePhase")))
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(8)
            .ToList();
        var detail = defaultDetail;
        if (!string.IsNullOrWhiteSpace(reason))
        {
            detail += $" Latest diagnostic: {reason}.";
        }

        if (phases.Count > 0)
        {
            detail += $" Phases: {string.Join(", ", phases)}.";
        }

        if (matrixRow is not null)
        {
            detail += $" artifactEvidenceMatrix: {matrixRow.CollectionName}={matrixRow.Count}:{matrixRow.State}:{matrixRow.Bytes}.";
        }

        var copy = string.Join(
            Environment.NewLine,
            [
                $"collection={name}",
                $"collectionName={collectionName}",
                $"status={status}",
                $"artifactCount={collectionArtifacts.Count}",
                $"eventCount={collectionEvents.Count}",
                $"latestReason={reason ?? "-"}",
                $"phases={string.Join(",", phases)}",
                matrixRow is null ? "artifactEvidenceMatrix=-" : ArtifactEvidenceMatrixEvidenceLine("artifactEvidenceMatrix", matrixRow),
                .. collectionArtifacts.Take(8).Select(ArtifactToPlainText),
                .. collectionEvents.Take(8).Select(EventOneLine)
            ]);
        return new ArtifactCollectionStatusCard(name, status, css, collectionArtifacts.Count, collectionEvents.Count, detail, copy);
    }

    private static string InferArtifactCollectionStatus(
        IReadOnlyCollection<ArtifactDescriptor> artifacts,
        IReadOnlyCollection<SandboxEvent> events)
    {
        if (artifacts.Count == 0 &&
            events.Any(IsDisabledArtifactCollectionEvent))
        {
            return "disabled";
        }

        if (artifacts.Any(artifact =>
                string.Equals(artifact.CaptureState, "failed", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(MetadataValue(artifact.Metadata, "captureState"), "failed", StringComparison.OrdinalIgnoreCase)) ||
            events.Any(evt => evt.EventType.Contains("failed", StringComparison.OrdinalIgnoreCase)))
        {
            return artifacts.Count > 0 ? "partial" : "failed";
        }

        if (artifacts.Count > 0 ||
            events.Any(evt => evt.EventType.Contains("captured", StringComparison.OrdinalIgnoreCase) ||
                evt.EventType.Contains("copied", StringComparison.OrdinalIgnoreCase)))
        {
            return "captured";
        }

        if (events.Any(evt => evt.EventType.Contains("skipped", StringComparison.OrdinalIgnoreCase)))
        {
            return "skipped";
        }

        return events.Count > 0 ? "observed" : "not observed";
    }

    /// <summary>
    /// Appends a chronological timeline for the most important dynamic events.
    /// Inputs are report events, processing orders and limits them for readable
    /// evidence flow, and the method returns no value.
    /// </summary>
    private static void AppendTimeline(
        StringBuilder html,
        AnalysisReport report,
        IReadOnlyDictionary<string, List<ArtifactDescriptor>> artifactLookup,
        IReadOnlyCollection<ArtifactDescriptor> artifacts)
    {
        html.AppendLine("<section id=\"timeline\" class=\"card\"><h2>Timeline</h2>");
        var events = report.Events
            .OrderBy(e => e.Timestamp)
            .Take(TimelineEventInlineLimit)
            .ToList();
        if (events.Count == 0)
        {
            Empty(html, "No timeline events were collected.");
            html.AppendLine("</section>");
            return;
        }

        var hiddenEvents = Math.Max(0, report.Events.Count - events.Count);
        var groups = BuildTimelineGroups(events);
        html.AppendLine("<div class=\"section-note\"><strong>Timeline grouping.</strong> Grouped by UTC minute with process/type summaries; large buckets show representative events first.</div>");
        if (hiddenEvents > 0)
        {
            html.AppendLine($"<div class=\"copy-hint\">Timeline is capped for readability; open Raw normalized events or report.json for complete evidence. {E(hiddenEvents.ToString())} additional timeline events are hidden.</div>");
        }

        html.AppendLine("<div class=\"timeline-groups\">");
        for (var index = 0; index < groups.Count; index++)
        {
            var group = groups[index];
            var open = index < 3 ? " open" : string.Empty;
            html.AppendLine($"<details class=\"timeline-group\"{open}>");
            html.AppendLine($"<summary class=\"timeline-group-summary copyable\" data-copy=\"{A(group.CopyText)}\"><span><strong>{E(group.Window)}</strong><small>{E(group.Summary)}</small></span><span class=\"badge badge-info\">{E(group.TotalEventCount.ToString())} events</span></summary>");
            html.AppendLine("<div class=\"timeline\">");
            foreach (var evt in group.Events.Take(TimelineGroupEventInlineLimit))
            {
                var copy = EventToPlainText(evt);
                var relatedArtifacts = FindRelatedArtifacts(evt, artifactLookup, artifacts);
                html.AppendLine($"<div class=\"timeline-item copyable\" data-copy=\"{A(copy)}\"><strong>{E(evt.Timestamp.ToString("u"))}</strong> <span class=\"badge badge-info\">{E(evt.EventType)}</span> <span class=\"chip chip-info\">{E(EventFamilyLabel(evt))}</span><br><span class=\"muted\">{E(evt.ProcessName ?? evt.Source)} {RenderInlineEventLocation(evt, relatedArtifacts)}</span></div>");
            }

            var groupHidden = group.TotalEventCount - Math.Min(group.TotalEventCount, TimelineGroupEventInlineLimit);
            if (groupHidden > 0)
            {
                html.AppendLine($"<div class=\"timeline-overflow\">{E(groupHidden.ToString())} additional events in this group are hidden; open Raw normalized events or report.json for complete evidence.</div>");
            }

            html.AppendLine("</div></details>");
        }

        html.AppendLine("</div><div class=\"copy-hint\">Right-click timeline entries, table cells, or evidence blocks to copy their contents.</div></section>");
    }

    /// <summary>
    /// Groups timeline events by UTC minute for stable native-HTML expansion.
    /// Inputs are already ordered/capped events; processing builds summary and
    /// copy text per bucket; the method returns chronological timeline groups.
    /// </summary>
    private static IReadOnlyList<TimelineGroup> BuildTimelineGroups(IReadOnlyCollection<SandboxEvent> events)
    {
        return events
            .GroupBy(evt => TimelineGroupWindow(evt.Timestamp), StringComparer.Ordinal)
            .Select(group =>
            {
                var ordered = group.OrderBy(evt => evt.Timestamp).ToList();
                var processes = ordered
                    .Select(ProcessDisplayName)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Take(6)
                    .ToList();
                var families = ordered
                    .Select(EventFamilyLabel)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
                    .Take(6)
                    .ToList();
                var eventTypes = ordered
                    .Select(evt => evt.EventType)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
                    .Take(8)
                    .ToList();
                var summary = $"Processes: {FormatLimitedList(processes)} | Event families: {FormatLimitedList(families)} | Event types: {FormatLimitedList(eventTypes)}";
                var copyText = string.Join(
                    Environment.NewLine,
                    [
                        $"Timeline group: {group.Key}",
                        $"events={ordered.Count}",
                        $"processes={string.Join(", ", processes)}",
                        $"eventFamilies={string.Join(", ", families)}",
                        $"eventTypes={string.Join(", ", eventTypes)}",
                        "evidence:",
                        .. ordered.Take(TimelineGroupEventInlineLimit).Select(EventOneLine)
                    ]);
                return new TimelineGroup(group.Key, summary, ordered.Count, ordered, copyText);
            })
            .OrderBy(group => group.Window, StringComparer.Ordinal)
            .ToList();
    }

    /// <summary>
    /// Formats one event timestamp as a minute-resolution UTC timeline bucket.
    /// </summary>
    private static string TimelineGroupWindow(DateTimeOffset timestamp) =>
        timestamp.ToUniversalTime().ToString("yyyy-MM-dd HH:mm 'UTC'");

    /// <summary>
    /// Formats a bounded list for group summaries.
    /// </summary>
    private static string FormatLimitedList(IReadOnlyCollection<string> values) =>
        values.Count == 0 ? "-" : string.Join(", ", values);

    /// <summary>
    /// Appends process-related event rows.
    /// Inputs are a report and output builder, processing filters process
    /// events, and the method returns no value.
    /// </summary>
    private static void AppendProcessDetails(
        StringBuilder html,
        AnalysisReport report,
        IReadOnlyDictionary<string, List<ArtifactDescriptor>> artifactLookup,
        IReadOnlyCollection<ArtifactDescriptor> artifacts)
    {
        html.AppendLine("<section id=\"process\" class=\"card\"><h2>Process details</h2>");
        AppendProcessTree(html, report);
        AppendProcessRelationshipCards(html, report, artifactLookup, artifacts);
        AppendEventRows(html, report.Events.Where(IsSampleBehaviorProcessEvent).ToList(), artifactLookup, artifacts);
        html.AppendLine("</section>");
    }

    /// <summary>
    /// Appends Windows Security/ETW privilege and process-access telemetry
    /// without treating every row as malicious. Inputs are normalized events;
    /// processing preserves the shared self-noise boundary and surfaces
    /// target/right fields for analyst correlation; the method returns no value.
    /// </summary>
    private static void AppendSecurityPrivilegeTelemetry(
        StringBuilder html,
        AnalysisReport report,
        IReadOnlyDictionary<string, List<ArtifactDescriptor>> artifactLookup,
        IReadOnlyCollection<ArtifactDescriptor> artifacts)
    {
        var candidateEvents = report.Events
            .Where(IsSecurityPrivilegeFallbackEvent)
            .OrderBy(evt => evt.Timestamp)
            .ToList();
        var telemetryEvents = candidateEvents
            .Where(IsSampleBehaviorEvent)
            .ToList();
        var excludedEvents = candidateEvents
            .Where(IsExcludedFromBehaviorStoryEvent)
            .ToList();
        var securityOrEtwRows = telemetryEvents.Count(evt =>
            evt.EventType.StartsWith("security.", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("etw.", StringComparison.OrdinalIgnoreCase));
        var processAccessRows = telemetryEvents.Count(IsProcessAccessStyleEvent);
        var privilegeRows = telemetryEvents.Count(IsPrivilegeTelemetryEvent);
        var sensitivePrivilegeNames = telemetryEvents
            .Select(evt => FirstEventDataValue(
                evt,
                "privilege",
                "privilegeName",
                "privilegeDisplayName",
                "privilegeList",
                "enabledPrivilegeList",
                "eventData.PrivilegeList",
                "eventData.EnabledPrivilegeList"))
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Cast<string>()
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
            .Take(8)
            .ToList();
        var targetSummary = telemetryEvents
            .Select(ExtractSecurityPrivilegeTarget)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Cast<string>()
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(6)
            .ToList();
        var copy = string.Join(
            Environment.NewLine,
            [
                "Security / privilege telemetry",
                $"candidateRows={candidateEvents.Count}",
                $"sampleBehaviorRows={telemetryEvents.Count}",
                $"excludedSelfNoiseOrNonbehaviorRows={excludedEvents.Count}",
                $"securityOrEtwRows={securityOrEtwRows}",
                $"processAccessRows={processAccessRows}",
                $"privilegeRows={privilegeRows}",
                $"privileges={string.Join(", ", sensitivePrivilegeNames)}",
                $"targets={string.Join(", ", targetSummary)}",
                "note=Rows are supporting telemetry; requested rights or privilege names require correlation with rule hits and target context.",
                "sampleEvidence:",
                .. telemetryEvents.Take(8).Select(EventOneLine)
            ]);

        html.AppendLine("<section id=\"security\" class=\"card\"><h2>Security / privilege telemetry</h2>");
        html.AppendLine("<div class=\"section-note\"><strong>Security and privilege telemetry.</strong> Windows Security/ETW privilege rows and process-access style rows are shown as supporting evidence for sensitive access, token, privilege, or handle activity. This section does not label a row malicious by itself; correlate requested rights, target process/object, rule hits, and self-noise markers before drawing conclusions.</div>");
        html.AppendLine("<div class=\"overview-strip security-privilege-overview copyable\" data-copy=\"" + A(copy) + "\">");
        AppendOverviewItem(
            html,
            "Security/privilege rows",
            telemetryEvents.Count.ToString(CultureInfo.InvariantCulture),
            $"Security/ETW rows: {securityOrEtwRows}; process-access style rows: {processAccessRows}; privilege rows: {privilegeRows}.",
            telemetryEvents.Count > 0 ? "risk-info" : "risk-low");
        AppendOverviewItem(
            html,
            "Targets summarized",
            targetSummary.Count.ToString(CultureInfo.InvariantCulture),
            targetSummary.Count == 0 ? "No target process/object fields were available." : string.Join("; ", targetSummary),
            targetSummary.Count > 0 ? "risk-info" : "risk-low");
        AppendOverviewItem(
            html,
            "Privilege names",
            sensitivePrivilegeNames.Count.ToString(CultureInfo.InvariantCulture),
            sensitivePrivilegeNames.Count == 0 ? "No privilege-name field was available." : string.Join("; ", sensitivePrivilegeNames),
            sensitivePrivilegeNames.Count > 0 ? "risk-medium" : "risk-low");
        AppendOverviewItem(
            html,
            "Self-noise excluded",
            excludedEvents.Count.ToString(CultureInfo.InvariantCulture),
            "Rows marked collector/self-noise, nonbehavior, or collection health remain outside this table and stay available in Raw normalized events/report.json.",
            excludedEvents.Count > 0 ? "risk-info" : "risk-low");
        html.AppendLine("<div class=\"toolbar\">" + CopyButton("Copy security/privilege telemetry summary", copy) + "</div>");
        html.AppendLine("</div>");

        if (telemetryEvents.Count == 0)
        {
            Empty(html, "No Windows Security, ETW privilege, or process-access telemetry rows were imported as sample behavior.");
        }
        else
        {
            AppendEventRows(html, telemetryEvents, artifactLookup, artifacts);
        }

        html.AppendLine("</section>");
    }

    /// <summary>
    /// Appends file creation and modification events.
    /// Inputs are a report and output builder, processing filters file events,
    /// and the method returns no value.
    /// </summary>
    private static void AppendDroppedFiles(
        StringBuilder html,
        AnalysisReport report,
        IReadOnlyDictionary<string, List<ArtifactDescriptor>> artifactLookup,
        IReadOnlyCollection<ArtifactDescriptor> artifacts)
    {
        AppendEventTable(html, "files", "File system activity", report.Events.Where(IsSampleBehaviorFileEvent), artifactLookup, artifacts);
    }

    /// <summary>
    /// Appends before/after startup and persistence inventory diffs.
    /// Inputs are normalized startup.* events projected from services,
    /// scheduled tasks, Run keys, WMI, Winlogon, IFEO, LSA, AppInit, Winsock,
    /// and shell-extension snapshots; processing summarizes surfaces first and
    /// then renders bounded evidence rows; the method returns no value.
    /// </summary>
    private static void AppendStartupPersistence(
        StringBuilder html,
        AnalysisReport report,
        IReadOnlyDictionary<string, List<ArtifactDescriptor>> artifactLookup,
        IReadOnlyCollection<ArtifactDescriptor> artifacts)
    {
        var startupEvents = report.Events
            .Where(IsSampleBehaviorStartupEvent)
            .OrderBy(evt => evt.Timestamp)
            .ToList();
        html.AppendLine("<section id=\"startup\" class=\"card\"><h2>Startup / persistence diff</h2>");
        html.AppendLine("<div class=\"section-note\"><strong>Before/after startup diff.</strong> This section shows aggregated startup facts projected from services, drivers, scheduled tasks, Run keys, Startup folders, WMI subscriptions, Winlogon, IFEO/SilentProcessExit, LSA, AppInit/AppCert, Winsock, shell extensions, Active Setup, time providers, print monitors, and Netsh helpers. If a surface is absent, the report says no rows were collected instead of inventing behavior.</div>");

        if (startupEvents.Count == 0)
        {
            Empty(html, "No startup.* before/after diff rows were collected. This means the startup inventory did not observe created/modified/deleted entries in the inline report window, not that the sample cannot persist.");
            html.AppendLine("</section>");
            return;
        }

        var createdOrModified = startupEvents.Count(evt => TextEqualsAny(FirstEventDataValue(evt, "change") ?? string.Empty, "created", "modified"));
        var deleted = startupEvents.Count(evt => TextEqualsAny(FirstEventDataValue(evt, "change") ?? string.Empty, "deleted"));
        var userWritableTargets = startupEvents.Count(StartupEventHasUserWritableTarget);
        var surfaces = startupEvents
            .Select(evt => FirstEventDataValue(evt, "startupSurface") ?? "(unknown)")
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
            .ToList();
        var categories = startupEvents
            .GroupBy(evt => FirstEventDataValue(evt, "startupCategory") ?? "(unknown)", StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(group => group.Count())
            .ThenBy(group => group.Key, StringComparer.OrdinalIgnoreCase)
            .Take(8)
            .Select(group => $"{group.Key}={group.Count()}")
            .ToList();
        var copy = string.Join(
            Environment.NewLine,
            [
                "Startup / persistence diff",
                $"startupRows={startupEvents.Count}",
                $"createdOrModified={createdOrModified}",
                $"deleted={deleted}",
                $"userWritableTargets={userWritableTargets}",
                $"surfaces={string.Join(", ", surfaces)}",
                $"categories={string.Join(", ", categories)}",
                .. startupEvents.Take(12).Select(EventOneLine)
            ]);

        html.AppendLine("<div class=\"overview-strip\">");
        AppendOverviewItem(html, "Startup rows", startupEvents.Count.ToString(CultureInfo.InvariantCulture), "Unified startup.* facts retained from before/after inventory diffs.", startupEvents.Count > 0 ? "risk-medium" : "risk-low");
        AppendOverviewItem(html, "Created/modified", createdOrModified.ToString(CultureInfo.InvariantCulture), "Persistence surfaces that appeared or changed after launch.", createdOrModified > 0 ? "risk-high" : "risk-low");
        AppendOverviewItem(html, "Deleted", deleted.ToString(CultureInfo.InvariantCulture), "Deleted startup inventory rows can indicate cleanup or rollback behavior.", deleted > 0 ? "risk-medium" : "risk-low");
        AppendOverviewItem(html, "User-writable targets", userWritableTargets.ToString(CultureInfo.InvariantCulture), "Startup values pointing at Temp/AppData/Public/Downloads/ProgramData or script/executable payloads.", userWritableTargets > 0 ? "risk-high" : "risk-info");
        html.AppendLine("</div>");
        html.AppendLine($"<div class=\"toolbar\">{CopyButton("Copy startup diff summary", copy)}</div>");
        html.AppendLine("<div class=\"relationship-tags\">");
        foreach (var surface in surfaces.Take(20))
        {
            html.AppendLine($"<span class=\"chip chip-info copyable\" data-copy=\"{A(surface)}\">{E(surface)}</span>");
        }

        foreach (var category in categories)
        {
            html.AppendLine($"<span class=\"chip chip-muted copyable\" data-copy=\"{A(category)}\">{E(category)}</span>");
        }

        html.AppendLine("</div>");
        AppendEventRows(html, startupEvents, artifactLookup, artifacts);
        html.AppendLine("</section>");
    }

    /// <summary>
    /// Appends registry behavior events.
    /// Inputs are a report and output builder, processing filters registry
    /// events, and the method returns no value.
    /// </summary>
    private static void AppendRegistryBehavior(
        StringBuilder html,
        AnalysisReport report,
        IReadOnlyDictionary<string, List<ArtifactDescriptor>> artifactLookup,
        IReadOnlyCollection<ArtifactDescriptor> artifacts)
    {
        AppendEventTable(html, "registry", "Registry behavior", report.Events.Where(IsSampleBehaviorRegistryEvent), artifactLookup, artifacts);
    }

    /// <summary>
    /// Appends network behavior events.
    /// Inputs are a report and output builder, processing filters network
    /// events, and the method returns no value.
    /// </summary>
    private static void AppendNetworkBehavior(
        StringBuilder html,
        AnalysisReport report,
        IReadOnlyDictionary<string, List<ArtifactDescriptor>> artifactLookup,
        IReadOnlyCollection<ArtifactDescriptor> artifacts)
    {
        var networkEvents = report.Events.Where(IsSampleBehaviorNetworkEvent).ToList();
        html.AppendLine("<section id=\"network\" class=\"card\"><h2>Network behavior</h2>");
        AppendNetworkRelationshipCards(html, networkEvents, artifactLookup, artifacts);
        AppendEventRows(html, networkEvents, artifactLookup, artifacts);
        html.AppendLine("</section>");
    }

    /// <summary>
    /// Appends R0Collector and driver-originated telemetry separately from raw
    /// events. Inputs are normalized events; processing filters by source and
    /// driver/r0 event-type prefixes; the method returns no value.
    /// </summary>
    private static void AppendR0Events(
        StringBuilder html,
        AnalysisReport report,
        IReadOnlyDictionary<string, List<ArtifactDescriptor>> artifactLookup,
        IReadOnlyCollection<ArtifactDescriptor> artifacts)
    {
        var r0Events = report.Events.Where(IsR0Event).ToList();
        var networkStatusEvents = r0Events.Where(IsR0DriverNetworkStatusEvent).ToList();
        var healthEvents = r0Events.Where(IsR0HealthRowEvent).ToList();
        var selfNoiseEvents = r0Events.Where(evt => !IsR0HealthRowEvent(evt) && !IsR0DriverNetworkStatusEvent(evt) && IsCollectorSelfNoiseEvent(evt)).ToList();
        var telemetryEvents = r0Events.Where(evt => !IsR0HealthRowEvent(evt) && !IsR0DriverNetworkStatusEvent(evt) && !IsCollectorSelfNoiseEvent(evt)).ToList();
        html.AppendLine("<section id=\"r0\" class=\"card\"><h2>R0 / driver events</h2>");
        if (r0Events.Count == 0)
        {
            Empty(html, "No R0Collector or driver-originated events were imported.");
            html.AppendLine("</section>");
            return;
        }

        html.AppendLine("<div class=\"grid\">");
        Metric(html, "Collector lifecycle", r0Events.Count(e => e.EventType.StartsWith("r0collector.", StringComparison.OrdinalIgnoreCase)).ToString(), "risk-info");
        Metric(html, "Collection health rows", healthEvents.Count.ToString(), healthEvents.Any(IsCollectionHealthAlertEvent) ? "risk-medium" : "risk-info");
        Metric(html, "R0 network status rows", networkStatusEvents.Count.ToString(), networkStatusEvents.Count > 0 ? "risk-info" : "risk-low");
        Metric(html, "Driver telemetry rows", telemetryEvents.Count.ToString(), "risk-info");
        Metric(html, "Collector self-noise hidden", selfNoiseEvents.Count.ToString(), selfNoiseEvents.Count > 0 ? "risk-info" : "risk-low");
        Metric(html, "Kernel file rows", telemetryEvents.Count(IsFileEvent).ToString(), "risk-medium");
        Metric(html, "Kernel registry rows", telemetryEvents.Count(IsRegistryEvent).ToString(), "risk-medium");
        Metric(html, "Kernel network rows", telemetryEvents.Count(IsNetworkEvent).ToString(), "risk-medium");
        Metric(html, "Health alerts", healthEvents.Count(IsCollectionHealthAlertEvent).ToString(), healthEvents.Any(IsCollectionHealthAlertEvent) ? "risk-medium" : "risk-info");
        html.AppendLine("</div>");
        html.AppendLine("<div class=\"section-note\"><strong>R0 noise policy.</strong> Collection health, device unavailable, and collector self-noise rows are evidence-quality lanes. They stay out of behavior counts, process trees, network cards, and file/registry/network behavior tables.</div>");

        AppendR0CollectionHealthStatus(html, healthEvents, networkStatusEvents, artifactLookup, artifacts);
        AppendR0SelfNoiseSummary(html, selfNoiseEvents);

        html.AppendLine("<h3>Driver telemetry evidence</h3>");
        if (telemetryEvents.Count == 0)
        {
            Empty(html, "No non-health R0 driver telemetry rows were imported. Collection health rows above describe evidence quality rather than sample behavior.");
        }
        else
        {
            AppendEventRows(html, telemetryEvents, artifactLookup, artifacts);
        }

        html.AppendLine("</section>");
    }

    /// <summary>
    /// Appends a compact note for driver rows produced by the collector itself.
    /// Inputs are self-noise events; processing keeps them out of behavior
    /// sections while preserving a count for evidence-quality auditability.
    /// </summary>
    private static void AppendR0SelfNoiseSummary(StringBuilder html, IReadOnlyCollection<SandboxEvent> selfNoiseEvents)
    {
        if (selfNoiseEvents.Count == 0)
        {
            return;
        }

        var sample = selfNoiseEvents
            .Take(R0SelfNoiseExampleLimit)
            .Select(evt => $"{evt.EventType} · {evt.ProcessName ?? "-"} ({evt.ProcessId?.ToString() ?? "-"}) · {evt.Path ?? "-"}")
            .ToList();
        html.AppendLine("<div class=\"self-noise-note\"><strong>Collector self-noise hidden from behavior sections.</strong> Driver rows attributed to KSword.Sandbox.R0Collector.exe are collection-side noise, not sample behavior. They remain available in raw events/report.json.</div>");
        html.AppendLine("<details class=\"relationship-details\"><summary>Collector self-noise examples (" + E(selfNoiseEvents.Count.ToString()) + ")</summary><ul class=\"mono-list\">");
        foreach (var line in sample)
        {
            html.AppendLine($"<li><code class=\"copyable\" data-copy=\"{A(line)}\">{E(line)}</code></li>");
        }

        html.AppendLine("</ul>");
        if (selfNoiseEvents.Count > sample.Count)
        {
            html.AppendLine($"<div class=\"copy-hint\">{E((selfNoiseEvents.Count - sample.Count).ToString())} additional self-noise rows remain only in Raw normalized events/report.json.</div>");
        }

        html.AppendLine("</details>");
    }

    /// <summary>
    /// Appends R0 collection health separately from driver telemetry so
    /// unavailable devices, driver health, backpressure, and dropped counters
    /// are not presented as malicious behavior.
    /// </summary>
    private static void AppendR0CollectionHealthStatus(
        StringBuilder html,
        IReadOnlyCollection<SandboxEvent> healthEvents,
        IReadOnlyCollection<SandboxEvent> networkStatusEvents,
        IReadOnlyDictionary<string, List<ArtifactDescriptor>> artifactLookup,
        IReadOnlyCollection<ArtifactDescriptor> artifacts)
    {
        html.AppendLine("<h3 id=\"collection-health\" class=\"anchor-offset\">Collection health status</h3>");
        html.AppendLine("<div class=\"section-note\"><strong>Collection health status.</strong> R0 unavailable, driver health, queue backpressure, and dropped-event counters describe collection quality and are not malicious sample behavior.</div>");
        html.AppendLine("<div class=\"grid\">");
        Metric(html, "Health/status rows", healthEvents.Count.ToString(), "risk-info");
        Metric(html, "Device unavailable", healthEvents.Count(IsDeviceUnavailableHealthEvent).ToString(), healthEvents.Any(IsDeviceUnavailableHealthEvent) ? "risk-medium" : "risk-info");
        Metric(html, "Backpressure/drop", healthEvents.Count(IsBackpressureOrDropHealthEvent).ToString(), healthEvents.Any(IsBackpressureOrDropHealthEvent) ? "risk-medium" : "risk-info");
        Metric(html, "Driver health polls", healthEvents.Count(IsDriverHealthPollEvent).ToString(), "risk-info");
        html.AppendLine("</div>");
        AppendR0DriverNetworkStatusStory(html, networkStatusEvents);
        AppendR0HealthAvailabilityOverview(html, healthEvents);

        if (healthEvents.Count == 0)
        {
            Empty(html, "No R0 collection health rows were imported.");
            return;
        }

        var inlineHealthEvents = healthEvents
            .OrderBy(evt => evt.Timestamp)
            .Take(R0HealthEvidenceInlineLimit)
            .ToList();
        var hiddenHealthEvents = Math.Max(0, healthEvents.Count - inlineHealthEvents.Count);
        html.AppendLine($"<details class=\"relationship-details r0-health-evidence\"><summary>R0 health evidence examples ({E(inlineHealthEvents.Count.ToString())}/{E(healthEvents.Count.ToString())}; {E(hiddenHealthEvents.ToString())} hidden)</summary>");
        html.AppendLine("<div class=\"section-note\"><strong>R0 health rows are folded by default.</strong> Open this evidence only when diagnosing driver readiness, queue loss, or unavailable device state.</div>");
        AppendEventRows(html, inlineHealthEvents, artifactLookup, artifacts);
        html.AppendLine("</details>");
    }

    /// <summary>
    /// Appends a WFP/ALE network-status story for the newest R0Collector
    /// diagnostics. Inputs are R0 collection-health events; processing extracts
    /// networkStatusAvailable, layer masks, counters, and degrade reasons into
    /// copyable cards that remain separate from sample network behavior.
    /// </summary>
    private static void AppendR0DriverNetworkStatusStory(StringBuilder html, IReadOnlyCollection<SandboxEvent> healthEvents)
    {
        var statusEvents = healthEvents
            .Where(IsR0DriverNetworkStatusEvent)
            .OrderBy(evt => evt.Timestamp)
            .ToList();
        if (statusEvents.Count == 0)
        {
            return;
        }

        var latest = statusEvents[^1];
        var available = FirstEventDataValue(latest, "networkStatusAvailable") ?? "-";
        var readiness = FirstEventDataValue(latest, "readinessState", "driverStateName", "status") ?? "-";
        var degradeReason = FirstEventDataValue(latest, "lastDegradeReasonName", "diagnosticCode", "diagnosticStage") ?? "-";
        var activeMask = FirstEventDataValue(latest, "activeLayerMaskHex", "activeLayerMask", "activeLayerMaskSummary") ?? "-";
        var supportedMask = FirstEventDataValue(latest, "supportedLayerMaskHex", "supportedLayerMask", "supportedLayerMaskSummary") ?? "-";
        var todoMask = FirstEventDataValue(latest, "todoMaskHex", "todoMask") ?? "-";
        var counters = FormatR0NetworkStatusCounters(latest);
        var copy = string.Join(
            Environment.NewLine,
            [
                "r0collector.driverNetworkStatus",
                $"networkStatusAvailable={available}",
                $"readinessState={readiness}",
                $"lastDegradeReasonName={degradeReason}",
                $"supportedLayerMask={supportedMask}",
                $"activeLayerMask={activeMask}",
                $"todoMask={todoMask}",
                counters,
                EventDataToText(latest)
            ]);

        html.AppendLine("<h4>Driver network status / WFP-ALE</h4>");
        html.AppendLine("<div class=\"section-note\"><strong>R0 network readiness.</strong> <code>r0collector.driverNetworkStatus</code> is an evidence-quality snapshot for WFP/ALE registration, masks, counters, and degrade reasons; it does not count as malicious network behavior.</div>");
        html.AppendLine("<div class=\"overview-strip r0-network-status-overview\">");
        AppendOverviewItem(
            html,
            "Network status availability",
            available,
            $"Readiness: {readiness}; degrade reason: {degradeReason}.",
            TextEqualsAny(available, "true", "1", "yes") ? "risk-info" : "risk-medium");
        AppendOverviewItem(
            html,
            "WFP/ALE masks",
            activeMask,
            $"Supported: {supportedMask}; TODO gap: {todoMask}; last registered: {FirstEventDataValue(latest, "lastRegisteredCalloutMaskHex", "lastRegisteredCalloutMask") ?? "-"}; filters: {FirstEventDataValue(latest, "lastAddedFilterMaskHex", "lastAddedFilterMask") ?? "-"}.",
            TextEqualsAny(todoMask, "0", "0x0", "0x00000000") ? "risk-info" : "risk-medium");
        AppendOverviewItem(
            html,
            "R0 network counters",
            FirstEventDataValue(latest, "eventCount", "classifyCount") ?? "-",
            counters,
            HasR0NetworkFailureCounters(latest) ? "risk-medium" : "risk-info");
        html.AppendLine("</div>");
        html.AppendLine($"<details class=\"evidence-expansion-card\"><summary>Copy WFP/ALE network status evidence ({E(statusEvents.Count.ToString(CultureInfo.InvariantCulture))})</summary><pre class=\"copyable\" data-copy=\"{A(copy)}\">{E(copy)}</pre></details>");
    }

    /// <summary>
    /// Appends availability-focused R0 health summary panels.
    /// Inputs are collection-health rows; processing separates unavailable
    /// devices, queue loss, poll noise, and folded evidence counts from sample
    /// behavior so the R0 section is useful but low-noise.
    /// </summary>
    private static void AppendR0HealthAvailabilityOverview(StringBuilder html, IReadOnlyCollection<SandboxEvent> healthEvents)
    {
        var unavailableCount = healthEvents.Count(IsDeviceUnavailableHealthEvent);
        var backpressureCount = healthEvents.Count(IsBackpressureOrDropHealthEvent);
        var pollCount = healthEvents.Count(IsDriverHealthPollEvent);
        var alertCount = healthEvents.Count(IsCollectionHealthAlertEvent);
        var state = healthEvents.Count == 0
            ? "No R0 health rows"
            : unavailableCount > 0
                ? "Unavailable / degraded"
                : alertCount > 0
                    ? "Attention needed"
                    : "Available / no alerts";
        var stateCss = unavailableCount > 0 || backpressureCount > 0
            ? "risk-medium"
            : healthEvents.Count == 0
                ? "risk-low"
                : "risk-info";

        html.AppendLine("<div class=\"overview-strip r0-health-overview\">");
        AppendOverviewItem(
            html,
            "R0 availability",
            state,
            $"Device unavailable: {unavailableCount}; backpressure/drop: {backpressureCount}; health polls: {pollCount}.",
            stateCss);
        AppendOverviewItem(
            html,
            "Health rows folded",
            $"{Math.Min(R0HealthEvidenceInlineLimit, healthEvents.Count)}/{healthEvents.Count}",
            "R0 health evidence is capped and collapsed here; complete rows remain in Raw normalized events/report.json.",
            healthEvents.Count > R0HealthEvidenceInlineLimit ? "risk-medium" : "risk-info");
        AppendOverviewItem(
            html,
            "Behavior impact",
            "0",
            "Unavailable/health rows affect evidence quality only and do not raise sample behavior counts.",
            "risk-low");
        html.AppendLine("</div>");
    }

    /// <summary>
    /// Appends explicit failure and timeout information.
    /// Inputs are a report and output builder, processing filters failed status
    /// and timeout/error events, and the method returns no value.
    /// </summary>
    private static void AppendFailureReasons(
        StringBuilder html,
        AnalysisReport report,
        IReadOnlyDictionary<string, List<ArtifactDescriptor>> artifactLookup,
        IReadOnlyCollection<ArtifactDescriptor> artifacts)
    {
        var failures = report.Events.Where(IsOperationalFailureEvent).ToList();
        html.AppendLine("<section id=\"failure\" class=\"card\"><h2>Failure reasons</h2>");
        if (report.Status != AnalysisStatus.Failed && failures.Count == 0)
        {
            Empty(html, "No operational failure markers were collected for this job.");
        }
        else if (failures.Count == 0)
        {
            Empty(html, "Analysis status is Failed, but no timeout/error/failure event was recorded in normalized telemetry.");
        }
        else
        {
            AppendEventRows(html, failures, artifactLookup, artifacts);
        }

        html.AppendLine("</section>");
    }

    /// <summary>
    /// Appends all normalized events for auditability.
    /// Inputs are a report and output builder, processing orders events by time,
    /// and the method returns no value.
    /// </summary>
    private static void AppendRawEvents(
        StringBuilder html,
        AnalysisReport report,
        IReadOnlyDictionary<string, List<ArtifactDescriptor>> artifactLookup,
        IReadOnlyCollection<ArtifactDescriptor> artifacts)
    {
        var orderedEvents = report.Events
            .OrderBy(e => e.Timestamp)
            .ToList();
        var inlineEvents = orderedEvents
            .Take(RawEventInlineLimit)
            .ToList();
        var hiddenCount = Math.Max(0, orderedEvents.Count - inlineEvents.Count);

        html.AppendLine("<section id=\"events\" class=\"card\"><h2>Raw normalized events</h2>");
        html.AppendLine("<div class=\"grid\">");
        Metric(html, "Total events", orderedEvents.Count.ToString(), "risk-info");
        Metric(html, "Inline rendered", inlineEvents.Count.ToString(), "risk-low");
        Metric(html, "Inline pages", RawEventPageCount(inlineEvents.Count).ToString(), "risk-info");
        Metric(html, "Hidden raw events", hiddenCount.ToString(), hiddenCount > 0 ? "risk-medium" : "risk-info");
        html.AppendLine("</div>");
        html.AppendLine($"<div class=\"section-note\"><strong>Slim raw event sample.</strong> Raw events are collapsed by default. Raw events shown inline: {inlineEvents.Count}/{orderedEvents.Count}. Inline page size: {RawEventPageSize}. Raw evidence height limit: 58vh. Hidden raw events: {hiddenCount}. Inline raw pages use native details; command, stdout, stderr, PowerShell, script blocks, and oversized payloads stay folded in every row. Open report.json or raw source artifacts for complete evidence. Native details work without JavaScript and print labels call out folded evidence.</div>");
        AppendRawEventReadingGuide(html, orderedEvents, inlineEvents.Count, hiddenCount);
        AppendRawEventSlimmingCards(html, orderedEvents, inlineEvents.Count, hiddenCount);
        AppendRawSourceHints(html, report, artifacts);
        AppendRawEventDistribution(html, orderedEvents);
        AppendRawEventPageIndex(html, orderedEvents);

        if (orderedEvents.Count == 0)
        {
            Empty(html, "No events were collected for this section.");
        }
        else
        {
            html.AppendLine($"<details class=\"raw-events-shell\"><summary><span class=\"fold-label\">Closed by default</span> Show inline raw events ({inlineEvents.Count}/{orderedEvents.Count}; {hiddenCount} hidden; {RawEventPageCount(inlineEvents.Count)} native pages)</summary>");
            html.AppendLine("<div class=\"raw-events-panel\">");
            AppendRawPageNavigation(html, inlineEvents.Count);
            AppendRawEventPages(html, inlineEvents, orderedEvents.Count, artifactLookup, artifacts);
            html.AppendLine("</div>");
            html.AppendLine("</details>");
        }

        html.AppendLine("</section>");
    }

    /// <summary>
    /// Appends a static reading guide for the raw-event section.
    /// Inputs are ordered events plus inline/hidden counts; processing writes
    /// weak-interaction hints so analysts know which native details block to
    /// open and where complete evidence remains; return is none.
    /// </summary>
    private static void AppendRawEventReadingGuide(
        StringBuilder html,
        IReadOnlyCollection<SandboxEvent> orderedEvents,
        int inlineEventCount,
        int hiddenCount)
    {
        if (orderedEvents.Count == 0)
        {
            return;
        }

        var eventTypeCount = orderedEvents
            .Select(evt => string.IsNullOrWhiteSpace(evt.EventType) ? "(empty)" : evt.EventType)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Count();
        var familyCount = orderedEvents
            .Select(EventFamilyLabel)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Count();
        var pageCount = RawEventPageCount(inlineEventCount);

        html.AppendLine("<h3>Raw event reading guide</h3>");
        html.AppendLine("<div class=\"overview-strip raw-reading-guide\">");
        AppendOverviewItem(
            html,
            "1. Read distribution",
            $"{eventTypeCount} types / {familyCount} families",
            "Start with top event types, sources, and families before opening rows.",
            "risk-info");
        AppendOverviewItem(
            html,
            "2. Open a 25-row page",
            $"{pageCount} inline pages",
            "Inline rows are split into native details pages; the first page opens after you expand the raw-event shell.",
            "risk-low");
        AppendOverviewItem(
            html,
            "3. Keep heavy fields folded",
            "folded",
            "Command, stdout, stderr, PowerShell, script blocks, and oversized payloads stay behind nested details.",
            "risk-info");
        AppendOverviewItem(
            html,
            "4. Use report.json for hidden rows",
            hiddenCount.ToString(CultureInfo.InvariantCulture),
            "Rows beyond the inline cap stay out of HTML tables; the page index shows report.json-only row ranges.",
            hiddenCount > 0 ? "risk-medium" : "risk-low");
        html.AppendLine("</div>");
    }

    /// <summary>
    /// Appends low-interaction raw-event slimming cards.
    /// Inputs are all ordered events plus inline/hidden counts; processing
    /// summarizes what is visible, folded, report-only, and artifact-backed so
    /// analysts can understand evidence coverage before expanding raw pages.
    /// </summary>
    private static void AppendRawEventSlimmingCards(
        StringBuilder html,
        IReadOnlyList<SandboxEvent> orderedEvents,
        int inlineEventCount,
        int hiddenCount)
    {
        if (orderedEvents.Count == 0)
        {
            return;
        }

        var inlineEvents = orderedEvents.Take(inlineEventCount).ToList();
        var foldedTechnicalFields = inlineEvents.Sum(RawEventFoldedTechnicalFieldCount);
        var artifactReferenceCount = orderedEvents.Count(EventHasArtifactReference);
        var networkCount = orderedEvents.Count(IsNetworkEvent);
        var r0Count = orderedEvents.Count(IsR0Event);
        var sampleBehaviorCount = orderedEvents.Count(IsSampleBehaviorEvent);
        var excludedBehaviorCount = orderedEvents.Count(IsExcludedFromBehaviorStoryEvent);
        var excludedReasonSummary = FormatReasonCounts(BuildBehaviorExclusionReasonCounts(orderedEvents).Take(4).ToList());
        var hiddenRange = hiddenCount == 0
            ? "none"
            : $"{inlineEventCount + 1}-{orderedEvents.Count}";
        var copy = string.Join(
            Environment.NewLine,
            [
                "Raw event slimming story",
                $"totalEvents={orderedEvents.Count}",
                $"inlineRendered={inlineEventCount}",
                $"hiddenReportJsonOnly={hiddenCount}",
                $"hiddenRowRange={hiddenRange}",
                $"inlineFoldedTechnicalFields={foldedTechnicalFields}",
                $"artifactReferencedEvents={artifactReferenceCount}",
                $"networkEvents={networkCount}",
                $"r0Events={r0Count}",
                $"sampleBehaviorRows={sampleBehaviorCount}",
                $"excludedBehaviorStoryRows={excludedBehaviorCount}",
                $"excludedReasonSummary={excludedReasonSummary}",
                "policy=HTML keeps bounded representative rows; report.json and source artifacts remain complete evidence."
            ]);

        html.AppendLine("<h3>Raw event slimming story</h3>");
        html.AppendLine("<div class=\"section-note\"><strong>Raw event slimming story.</strong> These cards explain the renderer's weak-interaction policy before any dense row expansion: visible pages are bounded, long technical payloads stay folded, and report.json/source artifacts remain the complete record.</div>");
        html.AppendLine("<div class=\"overview-strip raw-slimming-story\">");
        AppendOverviewItem(
            html,
            "Visible HTML rows",
            $"{inlineEventCount}/{orderedEvents.Count}",
            $"Rows are split into {RawEventPageCount(inlineEventCount)} native page(s), {RawEventPageSize} rows per page.",
            "risk-info");
        AppendOverviewItem(
            html,
            "Folded technical payloads",
            foldedTechnicalFields.ToString(CultureInfo.InvariantCulture),
            "Command lines, stdout/stderr, PowerShell, script blocks, and bulky values stay behind nested details.",
            foldedTechnicalFields > 0 ? "risk-medium" : "risk-low");
        AppendOverviewItem(
            html,
            "Report-only tail",
            hiddenCount.ToString(CultureInfo.InvariantCulture),
            hiddenCount == 0 ? "No raw rows exceed the inline cap." : $"Rows {hiddenRange} are intentionally kept in report.json/source artifacts only.",
            hiddenCount > 0 ? "risk-medium" : "risk-low");
        AppendOverviewItem(
            html,
            "Artifact / network / R0 anchors",
            $"{artifactReferenceCount} / {networkCount} / {r0Count}",
            "Counts expose evidence anchors before opening raw pages: artifact references, network rows, and R0/driver rows.",
            artifactReferenceCount + networkCount + r0Count > 0 ? "risk-info" : "risk-low");
        AppendOverviewItem(
            html,
            "Behavior routing",
            $"{sampleBehaviorCount}/{excludedBehaviorCount}",
            string.IsNullOrWhiteSpace(excludedReasonSummary) ? "All raw rows currently route as sample behavior or neutral evidence." : $"Sample/excluded raw rows; top excluded markers: {excludedReasonSummary}.",
            excludedBehaviorCount > 0 ? "risk-info" : "risk-low");
        html.AppendLine("</div>");
        html.AppendLine($"<div class=\"toolbar\">{CopyButton("Copy raw slimming story", copy)}</div>");
    }

    /// <summary>
    /// Appends native paged raw-event tables to keep evidence readable.
    /// Inputs are already-capped raw events and total event count; processing
    /// groups inline rows into deterministic native details panels; return is
    /// none.
    /// </summary>
    private static void AppendRawEventPages(
        StringBuilder html,
        IReadOnlyList<SandboxEvent> inlineEvents,
        int totalEventCount,
        IReadOnlyDictionary<string, List<ArtifactDescriptor>> artifactLookup,
        IReadOnlyCollection<ArtifactDescriptor> artifacts)
    {
        if (inlineEvents.Count == 0)
        {
            Empty(html, "No events were collected for this section.");
            return;
        }

        html.AppendLine("<div class=\"raw-event-pages\">");
        var pageNumber = 1;
        for (var index = 0; index < inlineEvents.Count; index += RawEventPageSize)
        {
            var pageEvents = inlineEvents
                .Skip(index)
                .Take(RawEventPageSize)
                .ToList();
            var first = index + 1;
            var last = index + pageEvents.Count;
            var pageCount = RawEventPageCount(inlineEvents.Count);
            var open = pageNumber == 1 ? " open" : string.Empty;
            var copy = string.Join(Environment.NewLine, pageEvents.Select(EventOneLine));
            var foldedTechnicalCount = pageEvents.Sum(RawEventFoldedTechnicalFieldCount);
            var pageFamilies = string.Join(
                ", ",
                pageEvents.Select(EventFamilyLabel).Distinct(StringComparer.OrdinalIgnoreCase).Take(3));
            var pageTypes = string.Join(
                ", ",
                pageEvents
                    .Select(evt => string.IsNullOrWhiteSpace(evt.EventType) ? "(empty)" : evt.EventType)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Take(3));
            html.AppendLine($"<details id=\"raw-page-{pageNumber}\" class=\"raw-event-page copyable\" data-copy=\"{A(copy)}\"{open}><summary>Raw event page {pageNumber}/{pageCount}: rows {first}-{last} of {totalEventCount}; folded technical fields {foldedTechnicalCount}; families {E(FirstNonEmpty(pageFamilies, "-"))}; top types {E(FirstNonEmpty(pageTypes, "-"))}</summary>");
            html.AppendLine($"<div class=\"toolbar\">{CopyButton("Copy raw page", copy)}</div>");
            html.AppendLine("<div class=\"copy-hint\">Page evidence sample. This page is a bounded native-details chunk; long command/output/script fields remain folded. Use the copy button or right-click to copy this inline page; open report.json/events.json for complete row payloads.</div>");
            AppendEventRows(html, pageEvents, artifactLookup, artifacts);
            html.AppendLine("</details>");
            pageNumber++;
        }

        html.AppendLine("</div>");
    }

    /// <summary>
    /// Appends a native anchor strip for inline raw-event pages.
    /// Inputs are the inline raw-event count; processing emits page anchors
    /// only, keeping interaction weak and stable without JavaScript.
    /// </summary>
    private static void AppendRawPageNavigation(StringBuilder html, int inlineEventCount)
    {
        var pageCount = RawEventPageCount(inlineEventCount);
        if (pageCount <= 1)
        {
            return;
        }

        html.AppendLine("<div class=\"raw-page-nav\" aria-label=\"Raw event inline page shortcuts\">");
        for (var pageNumber = 1; pageNumber <= pageCount; pageNumber++)
        {
            var first = ((pageNumber - 1) * RawEventPageSize) + 1;
            var last = Math.Min(pageNumber * RawEventPageSize, inlineEventCount);
            html.AppendLine($"<a href=\"#raw-page-{pageNumber}\" class=\"copyable\" data-copy=\"rawPage={pageNumber};rows={first}-{last}\">Page {pageNumber}<small> rows {first}-{last}</small></a>");
        }

        html.AppendLine("</div>");
    }

    private static int RawEventPageCount(int inlineEventCount)
    {
        return inlineEventCount == 0
            ? 0
            : (int)Math.Ceiling(inlineEventCount / (double)RawEventPageSize);
    }

    private static int RawEventFoldedTechnicalFieldCount(SandboxEvent evt)
    {
        var count = evt.Data.Count(pair => IsLongTechnicalEventField(pair.Key, pair.Value));
        if (!string.IsNullOrWhiteSpace(evt.CommandLine))
        {
            count++;
        }

        return count;
    }

    /// <summary>
    /// Appends a compact raw event distribution summary before the collapsed
    /// raw table. Inputs are ordered report events; processing groups by event
    /// type, source, and family; the method writes static cards only.
    /// </summary>
    private static void AppendRawEventDistribution(StringBuilder html, IReadOnlyCollection<SandboxEvent> events)
    {
        if (events.Count == 0)
        {
            return;
        }

        html.AppendLine("<h3>Raw event distribution</h3>");
        html.AppendLine("<div class=\"evidence-summary-grid\">");
        AppendDistributionCard(
            html,
            "Top event types",
            events
                .GroupBy(evt => string.IsNullOrWhiteSpace(evt.EventType) ? "(empty)" : evt.EventType)
                .OrderByDescending(group => group.Count())
                .ThenBy(group => group.Key, StringComparer.OrdinalIgnoreCase)
                .Take(10)
                .Select(group => (Label: group.Key, Count: group.Count()))
                .ToList());
        AppendDistributionCard(
            html,
            "Sources",
            events
                .GroupBy(evt => string.IsNullOrWhiteSpace(evt.Source) ? "(empty)" : evt.Source)
                .OrderByDescending(group => group.Count())
                .ThenBy(group => group.Key, StringComparer.OrdinalIgnoreCase)
                .Take(10)
                .Select(group => (Label: group.Key, Count: group.Count()))
                .ToList());
        AppendDistributionCard(
            html,
            "Event families",
            events
                .GroupBy(EventFamilyLabel)
                .OrderByDescending(group => group.Count())
                .ThenBy(group => group.Key, StringComparer.OrdinalIgnoreCase)
                .Take(10)
                .Select(group => (Label: group.Key, Count: group.Count()))
                .ToList());
        html.AppendLine("</div>");
    }

    /// <summary>
    /// Appends a static index for all raw rows so analysts can navigate dense
    /// report.json evidence without expanding every page.
    /// </summary>
    private static void AppendRawEventPageIndex(StringBuilder html, IReadOnlyList<SandboxEvent> orderedEvents)
    {
        if (orderedEvents.Count == 0)
        {
            return;
        }

        var indexed = orderedEvents
            .Select((evt, index) => new RawEventIndexRow(index + 1, evt))
            .ToList();

        html.AppendLine("<details class=\"raw-event-index\"><summary>Raw event page index / 原始事件页索引</summary>");
        html.AppendLine("<div class=\"section-note\"><strong>Raw event page index.</strong> This static index covers every normalized event, even rows hidden from inline rendering. Use event type, source, or family rows to decide whether to open inline pages, report.json, or original source artifacts. Row ranges are copyable; groups beyond the card cap are folded into an other-groups row instead of being dropped.</div>");
        html.AppendLine("<div class=\"evidence-summary-grid\">");
        AppendRawIndexCard(html, "Index by event type", BuildRawIndexGroups(indexed, row => string.IsNullOrWhiteSpace(row.Event.EventType) ? "(empty)" : row.Event.EventType));
        AppendRawIndexCard(html, "Index by source", BuildRawIndexGroups(indexed, row => string.IsNullOrWhiteSpace(row.Event.Source) ? "(empty)" : row.Event.Source));
        AppendRawIndexCard(html, "Index by event family", BuildRawIndexGroups(indexed, row => EventFamilyLabel(row.Event)));
        html.AppendLine("</div>");
        if (orderedEvents.Count > RawEventInlineLimit)
        {
            html.AppendLine($"<div class=\"section-note copyable\" data-copy=\"Rows {RawEventInlineLimit + 1}-{orderedEvents.Count}: report.json only\">Rows {RawEventInlineLimit + 1}-{orderedEvents.Count}: report.json only. These raw rows are intentionally outside the inline cap; use report.json or raw source artifacts for complete copyable row ranges.</div>");
        }

        html.AppendLine("</details>");
    }

    private static IReadOnlyList<RawEventIndexGroup> BuildRawIndexGroups(
        IReadOnlyCollection<RawEventIndexRow> rows,
        Func<RawEventIndexRow, string> keySelector)
    {
        var groups = rows
            .GroupBy(keySelector, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(group => group.Count())
            .ThenBy(group => group.Key, StringComparer.OrdinalIgnoreCase)
            .Select(group => new
            {
                Label = group.Key,
                Ordinals = group.Select(row => row.Ordinal).OrderBy(value => value).ToList()
            })
            .ToList();

        var visibleLimit = groups.Count > RawEventIndexGroupInlineLimit
            ? Math.Max(1, RawEventIndexGroupInlineLimit - 1)
            : RawEventIndexGroupInlineLimit;
        var result = groups
            .Take(visibleLimit)
            .Select(group => BuildRawEventIndexGroup(group.Label, group.Ordinals))
            .ToList();
        if (groups.Count > visibleLimit)
        {
            var otherGroups = groups.Skip(visibleLimit).ToList();
            var otherOrdinals = otherGroups
                .SelectMany(group => group.Ordinals)
                .OrderBy(value => value)
                .ToList();
            result.Add(BuildRawEventIndexGroup($"[other raw groups: {otherGroups.Count}]", otherOrdinals));
        }

        return result;
    }

    private static RawEventIndexGroup BuildRawEventIndexGroup(string label, IReadOnlyList<int> ordinals)
    {
        return new RawEventIndexGroup(
            label,
            ordinals.Count,
            ordinals.Count == 0 ? 0 : ordinals[0],
            ordinals.Count == 0 ? 0 : RawEventPageNumber(ordinals[0]),
            CompactOrdinalRanges(ordinals));
    }

    private static void AppendRawIndexCard(StringBuilder html, string title, IReadOnlyCollection<RawEventIndexGroup> groups)
    {
        var copy = title + Environment.NewLine + string.Join(Environment.NewLine, groups.Select(group =>
        {
            var firstLocation = group.FirstRow <= RawEventInlineLimit
                ? $"inline page {group.FirstInlinePage}"
                : "report.json only";
            return $"{group.Label}: count={group.Count}; firstRow={group.FirstRow}; firstLocation={firstLocation}; rows={group.RowRanges}";
        }));
        html.AppendLine($"<article class=\"evidence-summary-card copyable\" data-copy=\"{A(copy)}\">");
        html.AppendLine($"<h3>{E(title)}</h3>");
        html.AppendLine($"<span class=\"summary-value\">{E(groups.Sum(group => group.Count).ToString())}</span>");
        html.AppendLine("<p class=\"copy-hint\">Top groups stay visible; any remaining groups are folded into a copyable other-groups row so every raw event remains indexed.</p>");
        html.AppendLine($"<div class=\"toolbar\">{CopyButton("Copy raw index summary", copy)}</div>");
        html.AppendLine("<ol class=\"compact-list raw-index-list\">");
        foreach (var group in groups)
        {
            var inlinePage = group.FirstRow <= RawEventInlineLimit
                ? $"inline page {group.FirstInlinePage}"
                : "report.json only";
            html.AppendLine($"<li><span class=\"chip chip-info copyable\" data-copy=\"{A(group.Label)}\">{E(group.Label)}</span> <strong>{E(group.Count.ToString())}</strong> <span class=\"muted\">first row {E(group.FirstRow.ToString())}; {E(inlinePage)}; rows {E(group.RowRanges)}</span></li>");
        }

        html.AppendLine("</ol>");
        html.AppendLine("</article>");
    }

    private static int RawEventPageNumber(int oneBasedRow)
    {
        return oneBasedRow <= 0
            ? 0
            : (int)Math.Ceiling(oneBasedRow / (double)RawEventPageSize);
    }

    private static string CompactOrdinalRanges(IReadOnlyList<int> ordinals)
    {
        if (ordinals.Count == 0)
        {
            return string.Empty;
        }

        var ranges = new List<string>();
        var start = ordinals[0];
        var previous = ordinals[0];
        foreach (var ordinal in ordinals.Skip(1))
        {
            if (ordinal == previous + 1)
            {
                previous = ordinal;
                continue;
            }

            ranges.Add(FormatRange(start, previous));
            start = ordinal;
            previous = ordinal;
        }

        ranges.Add(FormatRange(start, previous));
        return string.Join(", ", ranges.Take(12)) + (ranges.Count > 12 ? ", ..." : string.Empty);
    }

    private static string FormatRange(int start, int end)
    {
        return start == end
            ? start.ToString(CultureInfo.InvariantCulture)
            : $"{start.ToString(CultureInfo.InvariantCulture)}-{end.ToString(CultureInfo.InvariantCulture)}";
    }

    private static void AppendDistributionCard(StringBuilder html, string title, IReadOnlyCollection<(string Label, int Count)> rows)
    {
        var copy = title + Environment.NewLine + string.Join(Environment.NewLine, rows.Select(row => $"{row.Label}: {row.Count}"));
        html.AppendLine($"<article class=\"evidence-summary-card copyable\" data-copy=\"{A(copy)}\">");
        html.AppendLine($"<h3>{E(title)}</h3>");
        html.AppendLine($"<span class=\"summary-value\">{E(rows.Sum(row => row.Count).ToString())}</span>");
        html.AppendLine($"<div class=\"toolbar\">{CopyButton("Copy distribution summary", copy)}</div>");
        html.AppendLine("<ol class=\"compact-list\">");
        foreach (var row in rows)
        {
            html.AppendLine($"<li><span class=\"chip chip-info copyable\" data-copy=\"{A(row.Label)}\">{E(row.Label)}</span> <strong>{E(row.Count.ToString())}</strong></li>");
        }

        html.AppendLine("</ol>");
        html.AppendLine("</article>");
    }

    private sealed record RawEventIndexRow(int Ordinal, SandboxEvent Event);

    private sealed record RawEventIndexGroup(
        string Label,
        int Count,
        int FirstRow,
        int FirstInlinePage,
        string RowRanges);

    /// <summary>
    /// Appends a standard event table section.
    /// Inputs are a section id, title, and events, processing renders rows or
    /// an empty-state block, and the method returns no value.
    /// </summary>
    private static void AppendEventTable(
        StringBuilder html,
        string id,
        string title,
        IEnumerable<SandboxEvent> events,
        IReadOnlyDictionary<string, List<ArtifactDescriptor>> artifactLookup,
        IReadOnlyCollection<ArtifactDescriptor> artifacts)
    {
        html.AppendLine($"<section id=\"{E(id)}\" class=\"card\"><h2>{E(title)}</h2>");
        AppendEventRows(html, events.ToList(), artifactLookup, artifacts);
        html.AppendLine("</section>");
    }

    /// <summary>
    /// Appends event rows without opening a section.
    /// Inputs are event records, processing encodes row fields and data, and
    /// the method returns no value.
    /// </summary>
    private static void AppendEventRows(
        StringBuilder html,
        IReadOnlyCollection<SandboxEvent> events,
        IReadOnlyDictionary<string, List<ArtifactDescriptor>> artifactLookup,
        IReadOnlyCollection<ArtifactDescriptor> artifacts)
    {
        if (events.Count == 0)
        {
            Empty(html, "No events were collected for this section.");
            return;
        }

        var orderedEvents = events
            .OrderBy(e => e.Timestamp)
            .ToList();
        var inlineEvents = orderedEvents
            .Take(EventTableInlineLimit)
            .ToList();
        var hiddenCount = Math.Max(0, orderedEvents.Count - inlineEvents.Count);
        if (hiddenCount > 0)
        {
            html.AppendLine($"<div class=\"section-note\"><strong>Event table capped for readability.</strong> Inline rows: {E(inlineEvents.Count.ToString())}/{E(orderedEvents.Count.ToString())}. Hidden rows: {E(hiddenCount.ToString())}. Open Raw normalized events or report.json for complete evidence.</div>");
        }

        html.AppendLine("<div class=\"event-table-wrap\">");
        html.AppendLine("<table class=\"event-table\"><thead><tr><th>Time</th><th>Type</th><th>Source</th><th>Process</th><th>Path / Target</th><th>Data</th></tr></thead><tbody>");
        foreach (var evt in inlineEvents)
        {
            var plain = EventToBoundedPlainText(evt, maxDataPairs: 40, maxValueLength: 300);
            var relatedArtifacts = FindRelatedArtifacts(evt, artifactLookup, artifacts);
            html.AppendLine("<tr>");
            html.AppendLine($"<td class=\"copyable\" data-copy=\"{A(evt.Timestamp.ToString("u"))}\">{E(evt.Timestamp.ToString("u"))}</td>");
            html.AppendLine($"<td class=\"copyable\" data-copy=\"{A(evt.EventType)}\">{E(evt.EventType)}</td>");
            html.AppendLine($"<td class=\"copyable\" data-copy=\"{A(evt.Source)}\">{E(evt.Source)}</td>");
            html.AppendLine($"<td class=\"copyable\" data-copy=\"{A((evt.ProcessName ?? "-") + " (" + (evt.ProcessId?.ToString() ?? "-") + ")")}\">{E(evt.ProcessName ?? "-")} ({E(evt.ProcessId?.ToString() ?? "-")})</td>");
            html.AppendLine($"<td class=\"copyable\" data-copy=\"{A(ExtractReadableEventTarget(evt))}\">{RenderEventPathAndCommand(evt, relatedArtifacts)}</td>");
            html.AppendLine($"<td class=\"evidence\"><span class=\"inline-actions\">{CopyButton("Copy event", plain)}{RenderCopyArtifactsButton(relatedArtifacts)}</span>{RenderEventEvidenceDetails(evt)}{RenderRelatedArtifacts(relatedArtifacts)}</td>");
            html.AppendLine("</tr>");
        }

        html.AppendLine("</tbody></table>");
        html.AppendLine("</div>");
    }

    /// <summary>
    /// Appends compact source-path hints for raw/source evidence.
    /// Inputs are the report and indexed artifacts; processing lists the
    /// co-located sampled report JSON plus raw guest/driver source artifacts, and the
    /// method returns no value.
    /// </summary>
    private static void AppendRawSourceHints(StringBuilder html, AnalysisReport report, IReadOnlyCollection<ArtifactDescriptor> artifacts)
    {
        var reportJsonHint = ResolveReportJsonHint(report, artifacts);
        var rawArtifacts = artifacts
            .Where(artifact => artifact.Kind is ArtifactKind.GuestEventsJson or ArtifactKind.DriverEventsJsonLines or ArtifactKind.ArtifactManifest)
            .OrderBy(artifact => ArtifactKindRank(artifact.Kind))
            .ThenBy(artifact => artifact.RelativePath, StringComparer.OrdinalIgnoreCase)
            .ThenBy(artifact => artifact.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

        html.AppendLine("<div class=\"raw-source-hints\"><strong>Raw source paths</strong>");
        html.AppendLine("<p class=\"muted\"><strong>Raw source guide.</strong> report.json is a sampled normalized report view with findings and representative events; guest events, driver JSONL, and manifests are the complete original source artifacts when indexed. Safe report-relative paths get Open/Download buttons; host or guest absolute paths remain copy-only.</p><ul>");
        var reportJsonCopy = string.Join(
            Environment.NewLine,
            [
                "report.json",
                $"locationHint={reportJsonHint}",
                "description=Sampled normalized report view with findings and representative events; use guest events/driver JSONL for complete raw telemetry."
            ]);
        AppendRawSourceHint(
            html,
            "Sampled normalized report JSON (representative events)",
            "report.json",
            $"Sampled normalized report view with findings and representative events. Expected location: {reportJsonHint}",
            "report.json",
            reportJsonCopy);

        if (rawArtifacts.Count == 0)
        {
            html.AppendLine("<li class=\"muted\">No raw source artifacts were indexed; report.json remains the sampled normalized report view, not proof that no additional raw telemetry existed.</li>");
        }
        else
        {
            foreach (var artifact in rawArtifacts.Take(12))
            {
                var label = artifact.Kind switch
                {
                    ArtifactKind.GuestEventsJson => "Guest events JSON",
                    ArtifactKind.DriverEventsJsonLines => "Driver events JSONL",
                    ArtifactKind.ArtifactManifest => "Artifact manifest",
                    _ => "Raw source artifact"
                };
                var display = ArtifactDisplayName(artifact);
                var note = "Original source: " + RawSourceArtifactNote(artifact);
                var copy = ArtifactToPlainText(artifact);
                AppendRawSourceHint(
                    html,
                    label,
                    display,
                    note,
                    ArtifactHref(artifact),
                    copy);
            }

            var hiddenArtifacts = rawArtifacts.Count - Math.Min(rawArtifacts.Count, 12);
            if (hiddenArtifacts > 0)
            {
                html.AppendLine($"<li class=\"muted\">{hiddenArtifacts} additional raw source artifacts are listed in the Artifact links section.</li>");
            }
        }

        html.AppendLine("</ul></div>");
    }

    /// <summary>
    /// Appends one copyable raw-source hint row.
    /// Inputs are display label, visible path, optional link, and copy text;
    /// processing keeps links local and copy payloads complete; return is none.
    /// </summary>
    private static void AppendRawSourceHint(
        StringBuilder html,
        string label,
        string display,
        string note,
        string? link,
        string copyText)
    {
        html.Append($"<li class=\"copyable\" data-copy=\"{A(copyText)}\"><span class=\"hint-label\">{E(label)}</span><br>");
        if (string.IsNullOrWhiteSpace(link))
        {
            html.Append($"<code>{E(display)}</code>");
        }
        else
        {
            html.Append($"<code>{E(display)}</code>{RenderSafeLinkActions(link, display)}");
        }

        if (!string.IsNullOrWhiteSpace(note))
        {
            html.Append($"<br><span class=\"muted\">{E(note)}</span>");
        }

        html.AppendLine("</li>");
    }

    /// <summary>
    /// Resolves the likely report.json path without requiring caller-provided
    /// job metadata. Inputs are report id and artifacts; processing infers the
    /// job root from indexed artifact paths when possible; return is a hint.
    /// </summary>
    private static string ResolveReportJsonHint(AnalysisReport report, IReadOnlyCollection<ArtifactDescriptor> artifacts)
    {
        foreach (var artifact in artifacts)
        {
            if (string.IsNullOrWhiteSpace(artifact.FullPath))
            {
                continue;
            }

            var reportRoot = TryResolveReportRoot(report.JobId, artifact.FullPath);
            if (!string.IsNullOrWhiteSpace(reportRoot))
            {
                return Path.Combine(reportRoot, "report.json");
            }
        }

        return $"same directory as report.html/report.en.html/report.zh.html; job folder {report.JobId:N}";
    }

    /// <summary>
    /// Builds a short raw-source artifact note.
    /// Inputs are one artifact descriptor; processing prefers full paths and
    /// includes safe links when useful; returns operator-readable text.
    /// </summary>
    private static string RawSourceArtifactNote(ArtifactDescriptor artifact)
    {
        var parts = new List<string>
        {
            $"{artifact.Kind} / {artifact.Category}"
        };

        if (!string.IsNullOrWhiteSpace(artifact.FullPath))
        {
            parts.Add(artifact.FullPath);
        }

        if (!string.IsNullOrWhiteSpace(artifact.SafeLink) &&
            !string.Equals(artifact.SafeLink, artifact.RelativePath, StringComparison.OrdinalIgnoreCase))
        {
            parts.Add($"safe link: {artifact.SafeLink}");
        }

        return string.Join(" | ", parts);
    }

    /// <summary>
    /// Appends a lightweight process tree from process start/tree events.
    /// Inputs are normalized process events, processing groups by PID/PPID, and
    /// the method returns no value.
    /// </summary>
    private static void AppendProcessTree(StringBuilder html, AnalysisReport report)
    {
        var starts = report.Events
            .Where(e => IsSampleBehaviorEvent(e) && IsProcessTreeCandidate(e) && e.ProcessId.HasValue)
            .GroupBy(ProcessIdentityKey, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.OrderBy(ProcessTreeSortKey).ThenBy(e => e.Timestamp).First())
            .OrderBy(ProcessTreeSortKey)
            .ThenBy(e => e.Timestamp)
            .ToList();
        if (starts.Count == 0)
        {
            Empty(html, "No process start/tree events were available to build a process tree.");
            return;
        }

        var known = starts
            .SelectMany(ProcessLookupKeys)
            .Where(key => !string.IsNullOrWhiteSpace(key))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var children = starts
            .Select(evt => new { Event = evt, ParentKey = ResolveParentProcessKey(evt, known) })
            .Where(item => !string.IsNullOrWhiteSpace(item.ParentKey))
            .GroupBy(item => item.ParentKey!, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.Select(item => item.Event).ToList(), StringComparer.OrdinalIgnoreCase);
        var canonicalKeys = BuildProcessCanonicalKeyLookup(report);
        var activityByProcess = BuildProcessTreeActivityLookup(report, canonicalKeys);
        var roots = starts
            .Where(e => !ParentProcessLookupKeys(e).Any(known.Contains))
            .ToList();

        html.AppendLine("<h3>Process tree</h3>");
        html.AppendLine("<div class=\"section-note\"><strong>Process relationship tree.</strong> Native expandable process tree grouped by stable process key when available, with PID/PPID fallback; compact row labels, depth/key badges, activity sparklines, and path hints keep lineage readable.</div>");
        html.AppendLine("<div class=\"section-note\"><strong>Process tree default expansion.</strong> Key process nodes are open by default: roots, high-signal nodes, and the first relationship levels. Expand remaining nodes for full lineage.</div>");
        AppendProcessTreeOverview(html, starts.Count, children, roots.Count, activityByProcess, report.Events.Count(IsCollectorSelfNoiseEvent), report.Events.Count(IsCollectionHealthEvent));
        if (roots.Count == 0)
        {
            roots = starts
                .OrderBy(ProcessTreeSortKey)
                .ThenBy(evt => evt.Timestamp)
                .Take(8)
                .ToList();
            html.AppendLine("<div class=\"section-note\">No root process was resolved from parent keys; showing earliest/deepest process tree candidates as bounded fallback roots.</div>");
        }

        html.AppendLine("<div class=\"tree process-tree\"><ul>");
        foreach (var root in roots)
        {
            AppendProcessTreeNode(html, root, children, activityByProcess, new HashSet<string>(StringComparer.OrdinalIgnoreCase), depth: 0);
        }

        html.AppendLine("</ul></div>");
    }

    /// <summary>
    /// Appends a compact process-tree overview before the expandable lineage.
    /// Inputs are process starts, resolved child edges, activity counters, and
    /// noise counts; processing writes flat summary panels so operators can
    /// understand what is included or deliberately excluded before expanding
    /// raw process evidence.
    /// </summary>
    private static void AppendProcessTreeOverview(
        StringBuilder html,
        int nodeCount,
        IReadOnlyDictionary<string, List<SandboxEvent>> children,
        int rootCount,
        IReadOnlyDictionary<string, ProcessTreeActivity> activityByProcess,
        int collectorNoiseCount,
        int healthRowCount)
    {
        var edgeCount = children.Sum(pair => pair.Value
            .GroupBy(ProcessIdentityKey, StringComparer.OrdinalIgnoreCase)
            .Count());
        var highSignalNodeCount = activityByProcess.Values.Count(activity =>
            activity.FileCount > 0 ||
            activity.RegistryCount > 0 ||
            activity.NetworkCount > 0);
        html.AppendLine("<div class=\"overview-strip process-tree-overview\">");
        AppendOverviewItem(
            html,
            "Process tree nodes",
            nodeCount.ToString(),
            $"Roots: {rootCount}; resolved parent-child edges: {edgeCount}.",
            "risk-info");
        AppendOverviewItem(
            html,
            "High-signal nodes",
            highSignalNodeCount.ToString(),
            "Nodes with file, registry, or network activity open by default for readable triage.",
            highSignalNodeCount > 0 ? "risk-medium" : "risk-low");
        AppendOverviewItem(
            html,
            "Self-noise excluded",
            collectorNoiseCount.ToString(),
            $"Collector/health rows excluded from process tree evidence: {collectorNoiseCount + healthRowCount}.",
            collectorNoiseCount > 0 ? "risk-info" : "risk-low");
        html.AppendLine("</div>");
    }

    /// <summary>
    /// Appends one process tree node recursively.
    /// Inputs are a process event, child lookup, and visited set; processing
    /// prevents cycles; the method returns no value.
    /// </summary>
    private static void AppendProcessTreeNode(
        StringBuilder html,
        SandboxEvent evt,
        IReadOnlyDictionary<string, List<SandboxEvent>> children,
        IReadOnlyDictionary<string, ProcessTreeActivity> activityByProcess,
        HashSet<string> visited,
        int depth)
    {
        var processKey = ProcessIdentityKey(evt);
        var label = ProcessTreeLabel(evt);
        var childEvents = ProcessLookupKeys(evt)
            .Where(children.ContainsKey)
            .SelectMany(key => children[key])
            .GroupBy(ProcessIdentityKey, StringComparer.OrdinalIgnoreCase)
            .Select(group => group.OrderBy(ProcessTreeSortKey).ThenBy(child => child.Timestamp).First())
            .OrderBy(ProcessTreeSortKey)
            .ThenBy(child => child.Timestamp)
            .ToList();
        var activity = ResolveProcessTreeActivity(evt, activityByProcess);
        var badges = ProcessTreeBadges(evt, childEvents.Count, activity, depth);
        var nodeContent = RenderProcessTreeNodeContent(evt, label, badges, activity);
        if (childEvents.Count > 0)
        {
            var open = ShouldOpenProcessTreeNode(depth, activity) ? " open" : string.Empty;
            html.AppendLine($"<li><details class=\"process-tree-node\"{open}><summary class=\"copyable\" data-copy=\"{A(EventToPlainText(evt))}\">{nodeContent}</summary>");
            if (!visited.Add(processKey))
            {
                html.AppendLine("<ul><li><span class=\"muted\">Cycle suppressed for stable rendering.</span></li></ul>");
                html.AppendLine("</details></li>");
                return;
            }

            html.AppendLine("<ul>");
            foreach (var child in childEvents)
            {
                AppendProcessTreeNode(html, child, children, activityByProcess, new HashSet<string>(visited, StringComparer.OrdinalIgnoreCase), depth + 1);
            }

            html.AppendLine("</ul>");
            html.AppendLine("</details></li>");
            return;
        }

        html.AppendLine($"<li><div class=\"process-tree-leaf copyable\" data-copy=\"{A(EventToPlainText(evt))}\">{nodeContent}</div></li>");
    }

    /// <summary>
    /// Aggregates per-process activity so the static tree can expand high-signal
    /// nodes by default without JavaScript.
    /// </summary>
    private static IReadOnlyDictionary<string, ProcessTreeActivity> BuildProcessTreeActivityLookup(
        AnalysisReport report,
        IReadOnlyDictionary<string, string> canonicalKeys)
    {
        var counts = new Dictionary<string, int[]>(StringComparer.OrdinalIgnoreCase);
        foreach (var evt in report.Events.Where(IsSampleBehaviorEvent))
        {
            if (!evt.ProcessId.HasValue && string.IsNullOrWhiteSpace(evt.ProcessName) && string.IsNullOrWhiteSpace(evt.Path))
            {
                continue;
            }

            var key = ResolveProcessGroupKey(evt, canonicalKeys);
            if (!counts.TryGetValue(key, out var bucket))
            {
                bucket = new int[4];
                counts[key] = bucket;
            }

            bucket[0]++;
            if (IsFileEvent(evt))
            {
                bucket[1]++;
            }

            if (IsRegistryEvent(evt))
            {
                bucket[2]++;
            }

            if (IsNetworkEvent(evt))
            {
                bucket[3]++;
            }
        }

        return counts.ToDictionary(
            pair => pair.Key,
            pair => new ProcessTreeActivity(pair.Value[0], pair.Value[1], pair.Value[2], pair.Value[3]),
            StringComparer.OrdinalIgnoreCase);
    }

    private static ProcessTreeActivity ResolveProcessTreeActivity(SandboxEvent evt, IReadOnlyDictionary<string, ProcessTreeActivity> activityByProcess)
    {
        foreach (var key in ProcessLookupKeys(evt))
        {
            if (activityByProcess.TryGetValue(key, out var activity))
            {
                return activity;
            }
        }

        return new ProcessTreeActivity(0, 0, 0, 0);
    }

    private static bool ShouldOpenProcessTreeNode(int depth, ProcessTreeActivity activity)
    {
        return depth <= ProcessTreeDefaultOpenDepth ||
            activity.NetworkCount > 0 ||
            activity.RegistryCount > 0 ||
            activity.FileCount > 0;
    }

    private static string ProcessTreeLabel(SandboxEvent evt)
    {
        return $"{ProcessGraphLabel(evt)} ppid:{ResolveParentProcessId(evt)?.ToString() ?? "-"}".Trim();
    }

    private static bool IsProcessTreeCandidate(SandboxEvent evt)
    {
        return string.Equals(evt.EventType, "process.start", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(evt.EventType, "process.tree", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(evt.EventType, "process.new", StringComparison.OrdinalIgnoreCase);
    }

    private static int ProcessTreeSortKey(SandboxEvent evt)
    {
        var depth = FirstEventDataValue(evt, "treeDepth", "depth");
        return int.TryParse(depth, out var parsedDepth) ? parsedDepth : int.MaxValue;
    }

    private static string ProcessTreeBadges(SandboxEvent evt, int childCount, ProcessTreeActivity activity, int depth)
    {
        var stableKey = FirstEventDataValue(evt, "processKey", "processGuid", "processUniqueId", "snapshotKey", "processSnapshotKey");
        var keyLabel = string.IsNullOrWhiteSpace(stableKey) ? $"pid:{evt.ProcessId?.ToString() ?? "-"}" : stableKey;
        var badges = new StringBuilder();
        badges.Append("<span class=\"tree-badges\">");
        badges.Append($"<span class=\"tree-badge\" title=\"{A(keyLabel)}\">key {E(AbbreviateEvidenceValue(keyLabel, 48))}</span>");
        badges.Append($"<span class=\"tree-badge\">depth {E(depth.ToString(CultureInfo.InvariantCulture))}</span>");
        badges.Append($"<span class=\"tree-badge\">children {E(childCount.ToString())}</span>");
        if (activity.EventCount > 0)
        {
            badges.Append($"<span class=\"tree-badge\">events {E(activity.EventCount.ToString())}</span>");
        }

        if (activity.FileCount > 0)
        {
            badges.Append($"<span class=\"tree-badge\">files {E(activity.FileCount.ToString())}</span>");
        }

        if (activity.RegistryCount > 0)
        {
            badges.Append($"<span class=\"tree-badge\">registry {E(activity.RegistryCount.ToString())}</span>");
        }

        if (activity.NetworkCount > 0)
        {
            badges.Append($"<span class=\"tree-badge\">network {E(activity.NetworkCount.ToString())}</span>");
        }

        badges.Append($"<span class=\"tree-badge\">start {E(evt.Timestamp.ToString("HH:mm:ss"))}</span>");
        badges.Append("</span>");
        return badges.ToString();
    }

    private static string RenderProcessTreeNodeContent(SandboxEvent evt, string label, string badges, ProcessTreeActivity activity)
    {
        var image = FirstNonEmpty(evt.Path, evt.CommandLine);
        var imageHint = string.IsNullOrWhiteSpace(image)
            ? string.Empty
            : $"<span class=\"process-tree-path\" title=\"{A(image)}\">image {E(AbbreviateEvidenceValue(image, 96))}</span>";
        return $"<span class=\"process-tree-line\"><code class=\"process-tree-label\">{E(label)}</code>{badges}{ProcessTreeSparkline(activity)}{imageHint}</span>";
    }

    /// <summary>
    /// Renders a tiny static activity sparkline for a process-tree row.
    /// Inputs are per-process event/file/registry/network counters; processing
    /// emits four native spans without JavaScript so analysts can scan hot
    /// process nodes before expanding relationship cards.
    /// </summary>
    private static string ProcessTreeSparkline(ProcessTreeActivity activity)
    {
        var copy = $"processTreeActivity=events:{activity.EventCount};files:{activity.FileCount};registry:{activity.RegistryCount};network:{activity.NetworkCount}";
        static string Cell(int value, string label) => value > 0
            ? $"<span class=\"hot\" title=\"{label}: {value}\"></span>"
            : $"<span title=\"{label}: 0\"></span>";
        return $"<span class=\"process-tree-sparkline copyable\" data-copy=\"{A(copy)}\" aria-label=\"{A(copy)}\">{Cell(activity.EventCount, "events")}{Cell(activity.FileCount, "files")}{Cell(activity.RegistryCount, "registry")}{Cell(activity.NetworkCount, "network")}</span><span class=\"process-tree-sparkline-label\">E/F/R/N</span>";
    }

    /// <summary>
    /// Appends bounded process relationship cards for cloud-sandbox-like triage.
    /// Inputs are normalized process-related events; processing groups by
    /// process identity and summarizes child/file/registry/network evidence;
    /// return is none.
    /// </summary>
    private static void AppendProcessRelationshipCards(
        StringBuilder html,
        AnalysisReport report,
        IReadOnlyDictionary<string, List<ArtifactDescriptor>> artifactLookup,
        IReadOnlyCollection<ArtifactDescriptor> artifacts)
    {
        var allCards = BuildProcessRelationshipCards(report, artifactLookup, artifacts);
        var cards = allCards.Take(RelationshipCardInlineLimit).ToList();
        var hiddenCardCount = Math.Max(0, allCards.Count - cards.Count);
        html.AppendLine("<h3 id=\"process-relationship-cards\" class=\"anchor-offset\">Process relationship cards</h3>");
        html.AppendLine("<div class=\"section-note\"><strong>Process relationship evidence / 进程关系证据.</strong> Cards summarize child, file, registry, network, and linked artifact evidence per stable process identity; long command lines stay folded and collector self-noise is excluded. Hint / 提示: artifact badges are compact proof anchors, while full descriptors remain in Artifact links and raw events.</div>");
        if (cards.Count == 0)
        {
            Empty(html, "No process relationship cards could be derived from normalized telemetry.");
            return;
        }

        html.AppendLine("<div class=\"relation-grid\">");
        foreach (var card in cards)
        {
            html.AppendLine($"<article class=\"relation-card copyable\" data-copy=\"{A(card.CopyText)}\">");
            html.AppendLine("<div class=\"relationship-title\">");
            html.AppendLine($"<h3><code>{E(card.Label)}</code></h3><span class=\"badge badge-{E(card.RiskCss)}\">{E(card.EventCount.ToString())} events</span>");
            html.AppendLine("</div>");
            html.AppendLine("<div class=\"relationship-meta\">");
            html.AppendLine($"<span>Children: {E(card.ChildCount.ToString())}</span><span>Files: {E(card.FileCount.ToString())}</span>");
            html.AppendLine($"<span>Registry: {E(card.RegistryCount.ToString())}</span><span>Network: {E(card.NetworkCount.ToString())}</span>");
            html.AppendLine($"<span>First seen: {E(card.FirstSeen)}</span><span>Last seen: {E(card.LastSeen)}</span>");
            html.AppendLine($"<span>Parent: {E(card.ParentLabel)}</span><span>Relationship lines: {E(card.RelationshipLines.Count.ToString())}</span>");
            html.AppendLine($"<span>Artifacts: {E(card.RelatedArtifacts.Count.ToString())}</span><span>Evidence lines: {E(card.EvidenceLines.Count.ToString())}</span>");
            html.AppendLine("</div>");
            AppendProcessRelationFlow(html, card);
            html.AppendLine(RenderInlineArtifactBadges(card.RelatedArtifacts, "Process artifacts / 进程证据"));
            AppendCompactEvidenceSummary(html, card.CompactSummary, "Copy compact summary");
            AppendRelationshipArtifactLinks(html, card.RelatedArtifacts, "Linked artifacts for this process", "Copy linked process artifacts");
            if (!string.IsNullOrWhiteSpace(card.Path) || !string.IsNullOrWhiteSpace(card.CommandLine))
            {
                html.AppendLine("<div class=\"section-note\">");
                if (!string.IsNullOrWhiteSpace(card.Path))
                {
                    html.AppendLine($"<strong>Path</strong><br><code class=\"copyable\" data-copy=\"{A(card.Path)}\">{E(card.Path)}</code><br>");
                }

                if (!string.IsNullOrWhiteSpace(card.CommandLine))
                {
                    html.AppendLine($"<strong>Command line</strong>{RenderTechnicalField("Command line", card.CommandLine)}");
                }

                html.AppendLine("</div>");
            }

            if (card.ChildLabels.Count > 0)
            {
                html.AppendLine("<details class=\"relationship-details\"><summary>Child processes</summary><ul class=\"mono-list\">");
                foreach (var child in card.ChildLabels.Take(12))
                {
                    html.AppendLine($"<li><code class=\"copyable\" data-copy=\"{A(child)}\">{E(child)}</code></li>");
                }

                html.AppendLine("</ul></details>");
            }

            if (card.RelationshipLines.Count > 0)
            {
                var relationships = string.Join(Environment.NewLine, card.RelationshipLines);
                html.AppendLine($"<details class=\"relationship-details\"><summary>Stable relationship map</summary><pre class=\"copyable\" data-copy=\"{A(relationships)}\">{E(relationships)}</pre></details>");
            }

            html.AppendLine("<div class=\"toolbar\">");
            html.AppendLine(CopyButton("Copy process card", card.CopyText));
            html.AppendLine("</div>");
            html.AppendLine("<details class=\"evidence-expansion-card\"><summary>Expand top process evidence</summary>");
            AppendEvidenceExpansionSummary(html, "Process evidence expansion summary", card.EvidenceLines.Count, card.EventCount, "Raw normalized events/report.json", card.EvidenceLines);
            html.AppendLine($"<pre class=\"copyable\" data-copy=\"{A(string.Join(Environment.NewLine, card.EvidenceLines))}\">{E(string.Join(Environment.NewLine, card.EvidenceLines))}</pre></details>");
            html.AppendLine("</article>");
        }

        html.AppendLine("</div>");
        if (hiddenCardCount > 0)
        {
            var copy = $"hiddenProcessRelationshipCards={hiddenCardCount}; renderedProcessRelationshipCards={cards.Count}; completeSource=Raw normalized events/report.json";
            html.AppendLine($"<div class=\"section-note copyable\" data-copy=\"{A(copy)}\">{E(hiddenCardCount.ToString(CultureInfo.InvariantCulture))} additional process relationship cards are hidden from inline cards; use Raw normalized events/report.json for complete process relationships.</div>");
        }
    }

    /// <summary>
    /// Builds process relationship cards from normalized events.
    /// Inputs are an analysis report and artifact lookup data; processing
    /// groups by stable process key and computes child/event/artifact counters;
    /// returns copyable cards.
    /// </summary>
    private static IReadOnlyList<ProcessRelationshipCard> BuildProcessRelationshipCards(
        AnalysisReport report,
        IReadOnlyDictionary<string, List<ArtifactDescriptor>> artifactLookup,
        IReadOnlyCollection<ArtifactDescriptor> artifacts)
    {
        var behaviorEvents = report.Events.Where(IsSampleBehaviorEvent).ToList();
        var starts = behaviorEvents
            .Where(evt => IsProcessTreeCandidate(evt) && evt.ProcessId.HasValue)
            .GroupBy(ProcessIdentityKey, StringComparer.OrdinalIgnoreCase)
            .Select(group => group.OrderBy(ProcessTreeSortKey).ThenBy(evt => evt.Timestamp).First())
            .ToList();
        var known = starts
            .SelectMany(ProcessLookupKeys)
            .Where(key => !string.IsNullOrWhiteSpace(key))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var processLabels = BuildProcessLabelLookup(report);
        var canonicalKeys = BuildProcessCanonicalKeyLookup(report);
        var childrenByParent = starts
            .Select(evt => new { Event = evt, ParentKey = ResolveParentProcessKey(evt, known) })
            .Where(item => !string.IsNullOrWhiteSpace(item.ParentKey))
            .GroupBy(item => item.ParentKey!, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(
                group => group.Key,
                group => group
                    .OrderBy(item => item.Event.Timestamp)
                    .Select(item => ResolveProcessLabel(item.Event, processLabels))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList(),
                StringComparer.OrdinalIgnoreCase);

        return behaviorEvents
            .Where(evt => evt.ProcessId.HasValue || !string.IsNullOrWhiteSpace(evt.ProcessName))
            .GroupBy(evt => ResolveProcessGroupKey(evt, canonicalKeys), StringComparer.OrdinalIgnoreCase)
            .Select(group =>
            {
                var events = group.OrderBy(evt => evt.Timestamp).ToList();
                var first = events.First();
                var last = events.Last();
                var childLabels = ProcessLookupKeys(first)
                    .Where(childrenByParent.ContainsKey)
                    .SelectMany(key => childrenByParent[key])
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(label => label, StringComparer.OrdinalIgnoreCase)
                    .ToList();
                var fileCount = events.Count(IsFileEvent);
                var registryCount = events.Count(IsRegistryEvent);
                var networkCount = events.Count(IsNetworkEvent);
                var label = ResolveProcessLabel(first, processLabels);
                var parentLabel = ResolveParentProcessLabel(first, processLabels);
                var path = events.Select(evt => evt.Path).FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty;
                var commandLine = events.Select(evt => evt.CommandLine).FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty;
                var evidenceLines = events.Take(12).Select(EventOneLine).ToList();
                var relatedArtifacts = FindProcessRelatedArtifacts(events, artifactLookup, artifacts);
                var relationshipLines = new List<string>
                {
                    $"process={label}",
                    $"processKey={ProcessIdentityKey(first)}",
                    $"parentProcess={parentLabel}",
                    $"parentProcessKey={string.Join(",", ParentProcessLookupKeys(first))}"
                };
                relationshipLines.AddRange(childLabels.Take(12).Select(child => $"child={child}"));
                relationshipLines.Add($"files={fileCount}");
                relationshipLines.Add($"registry={registryCount}");
                relationshipLines.Add($"network={networkCount}");
                relationshipLines.Add($"relatedArtifacts={relatedArtifacts.Count}");
                relationshipLines.AddRange(relatedArtifacts.Take(RelationshipArtifactInlineLimit).Select(ArtifactCompactLine));
                var compactSummary = BuildProcessCompactSummary(
                    label,
                    events.Count,
                    childLabels.Count,
                    fileCount,
                    registryCount,
                    networkCount,
                    relatedArtifacts,
                    first,
                    last);
                var copyText = string.Join(
                    Environment.NewLine,
                    [
                        compactSummary,
                        $"process={label}",
                        $"processKey={ProcessIdentityKey(first)}",
                        $"parentProcess={parentLabel}",
                        $"events={events.Count}",
                        $"children={childLabels.Count}",
                        $"files={fileCount}",
                        $"registry={registryCount}",
                        $"network={networkCount}",
                        $"firstSeen={first.Timestamp:u}",
                        $"lastSeen={last.Timestamp:u}",
                        $"path={path}",
                        $"commandLine={commandLine}",
                        $"relatedArtifacts={relatedArtifacts.Count}",
                        "linkedArtifacts:",
                        .. relatedArtifacts.Take(RelationshipArtifactInlineLimit).Select(ArtifactCompactLine),
                        "childProcesses:",
                        .. childLabels.Take(12),
                        "evidence:",
                        .. evidenceLines
                    ]);
                return new ProcessRelationshipCard(
                    label,
                    ProcessCardRisk(fileCount, registryCount, networkCount, childLabels.Count),
                    events.Count,
                    childLabels.Count,
                    fileCount,
                    registryCount,
                    networkCount,
                    first.Timestamp.ToString("u"),
                    last.Timestamp.ToString("u"),
                    parentLabel,
                    path,
                    commandLine,
                    childLabels,
                    relationshipLines,
                    evidenceLines,
                    relatedArtifacts,
                    compactSummary,
                    copyText);
            })
            .OrderByDescending(card => card.NetworkCount + card.FileCount + card.RegistryCount + card.ChildCount)
            .ThenBy(card => card.Label, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>
    /// Appends network relationship cards before the detailed event table.
    /// Inputs are network events; processing groups by endpoint/domain/SNI and
    /// emits protocol/process/evidence cards; return is none.
    /// </summary>
    private static void AppendNetworkRelationshipCards(
        StringBuilder html,
        IReadOnlyCollection<SandboxEvent> networkEvents,
        IReadOnlyDictionary<string, List<ArtifactDescriptor>> artifactLookup,
        IReadOnlyCollection<ArtifactDescriptor> artifacts)
    {
        var allCards = BuildNetworkRelationshipCards(networkEvents, artifactLookup, artifacts);
        var cards = allCards.Take(RelationshipCardInlineLimit).ToList();
        var hiddenCardCount = Math.Max(0, allCards.Count - cards.Count);
        html.AppendLine("<h3 id=\"network-relationship-cards\" class=\"anchor-offset\">Network relationship cards</h3>");
        if (cards.Count == 0)
        {
            Empty(html, "No network relationship cards could be derived from DNS, HTTP, TLS, PCAP, TCP, or UDP telemetry.");
            return;
        }

        AppendNetworkRelationshipOverview(html, allCards, cards.Count, networkEvents.Count);
        html.AppendLine("<div class=\"section-note\"><strong>Endpoint-centric view.</strong> Network events are grouped by domain, SNI, URL, IP, or endpoint so analysts can read the relationship map without opening raw events first.</div>");
        html.AppendLine("<div class=\"section-note\"><strong>Observed-only / 仅真实采集.</strong> Relationship cards require an observed DNS/HTTP/TLS/flow target; rows without a target remain in raw evidence and do not create placeholder endpoint cards.</div>");
        html.AppendLine("<div class=\"section-note\"><strong>Network category view / 网络分类视图.</strong> Cards split DNS, HTTP, TLS, flow, and linked PCAP/source artifacts so endpoint relationships stay readable without opening raw rows. Hint / 提示: PCAP/source artifact badges only appear when current indexed data links them to the endpoint.</div>");
        html.AppendLine("<div class=\"relation-grid\">");
        foreach (var card in cards)
        {
            html.AppendLine($"<article class=\"relation-card copyable\" data-copy=\"{A(card.CopyText)}\">");
            html.AppendLine("<div class=\"relationship-title\">");
            html.AppendLine($"<h3><code>{E(card.Target)}</code></h3><span class=\"badge badge-{E(card.RiskCss)}\">{E(card.Protocols)}</span>");
            html.AppendLine("</div>");
            html.AppendLine("<div class=\"relationship-meta\">");
            html.AppendLine($"<span>Events: {E(card.EventCount.ToString())}</span><span>Processes: {E(card.Processes.Count.ToString())}</span>");
            html.AppendLine($"<span>First seen: {E(card.FirstSeen)}</span><span>Last seen: {E(card.LastSeen)}</span>");
            html.AppendLine($"<span>Categories: {E(string.Join(" / ", card.Categories))}</span><span>DNS: {E(card.DnsCount.ToString())}</span>");
            html.AppendLine($"<span>HTTP: {E(card.HttpCount.ToString())}</span><span>TLS: {E(card.TlsCount.ToString())}</span>");
            html.AppendLine($"<span>Flow/other: {E(card.FlowCount.ToString())}</span><span>Event types: {E(card.EventTypes.Count.ToString())}</span>");
            html.AppendLine($"<span>Artifacts: {E(card.RelatedArtifacts.Count.ToString())}</span><span>Evidence lines: {E(card.EvidenceLines.Count.ToString())}</span>");
            html.AppendLine("</div>");
            AppendCompactEvidenceSummary(html, card.CompactSummary, "Copy compact summary");
            AppendNetworkRelationFlow(html, card);
            html.AppendLine(RenderInlineArtifactBadges(card.RelatedArtifacts, "Network artifacts / 网络证据"));
            html.AppendLine("<div class=\"relationship-tags\">");
            foreach (var category in card.Categories.Take(6))
            {
                html.AppendLine($"<span class=\"chip chip-low copyable\" data-copy=\"{A(category)}\">{E(category)}</span>");
            }

            foreach (var process in card.Processes.Take(8))
            {
                html.AppendLine($"<span class=\"chip chip-info copyable\" data-copy=\"{A(process)}\">{E(process)}</span>");
            }

            foreach (var eventType in card.EventTypes.Take(8))
            {
                html.AppendLine($"<span class=\"chip chip-medium copyable\" data-copy=\"{A(eventType)}\">{E(eventType)}</span>");
            }

            html.AppendLine("</div>");
            AppendRelationshipArtifactLinks(html, card.RelatedArtifacts, "Linked network / PCAP artifacts", "Copy linked network artifacts");
            html.AppendLine("<div class=\"toolbar\">");
            html.AppendLine(CopyButton("Copy network card", card.CopyText));
            html.AppendLine("</div>");
            html.AppendLine("<details class=\"evidence-expansion-card\"><summary>Expand top network evidence</summary>");
            AppendEvidenceExpansionSummary(html, "Network evidence expansion summary", card.EvidenceLines.Count, card.EventCount, "Raw normalized events/report.json and packet artifacts", card.EvidenceLines);
            html.AppendLine($"<pre class=\"copyable\" data-copy=\"{A(string.Join(Environment.NewLine, card.EvidenceLines))}\">{E(string.Join(Environment.NewLine, card.EvidenceLines))}</pre></details>");
            html.AppendLine("</article>");
        }

        html.AppendLine("</div>");
        if (hiddenCardCount > 0)
        {
            var copy = $"hiddenNetworkRelationshipCards={hiddenCardCount}; renderedNetworkRelationshipCards={cards.Count}; completeSource=Raw normalized events/report.json";
            html.AppendLine($"<div class=\"section-note copyable\" data-copy=\"{A(copy)}\">{E(hiddenCardCount.ToString(CultureInfo.InvariantCulture))} additional network relationship cards are hidden from inline cards; use Raw normalized events/report.json for complete endpoint evidence.</div>");
        }
    }

    /// <summary>
    /// Appends a compact aggregate view for endpoint relationship cards.
    /// Inputs are all endpoint cards plus rendered-card count and source-event
    /// count; processing writes DNS/HTTP/TLS/flow counters before bounded card
    /// details so analysts can understand network scope without opening rows.
    /// </summary>
    private static void AppendNetworkRelationshipOverview(
        StringBuilder html,
        IReadOnlyCollection<NetworkRelationshipCard> allCards,
        int renderedCardCount,
        int eventCount)
    {
        var dnsCount = allCards.Sum(card => card.DnsCount);
        var httpCount = allCards.Sum(card => card.HttpCount);
        var tlsCount = allCards.Sum(card => card.TlsCount);
        var flowCount = allCards.Sum(card => card.FlowCount);
        var linkedArtifacts = allCards
            .SelectMany(card => card.RelatedArtifacts)
            .GroupBy(ArtifactKey, StringComparer.OrdinalIgnoreCase)
            .Select(group => group.First())
            .ToList();
        var pcapCount = linkedArtifacts.Count(artifact => artifact.Kind == ArtifactKind.PacketCapture);
        html.AppendLine("<div class=\"overview-strip network-relationship-overview\">");
        AppendOverviewItem(
            html,
            "Endpoint groups",
            allCards.Count.ToString(),
            $"Rendered cards: {renderedCardCount}; source network events: {eventCount}.",
            allCards.Count > 0 ? "risk-info" : "risk-low");
        AppendOverviewItem(
            html,
            "DNS / HTTP / TLS",
            $"{dnsCount} / {httpCount} / {tlsCount}",
            "Protocol categories are counted before raw rows so relationship cards stay readable.",
            dnsCount + httpCount + tlsCount > 0 ? "risk-medium" : "risk-info");
        AppendOverviewItem(
            html,
            "Flow / other",
            flowCount.ToString(),
            "TCP/UDP/PCAP flow rows are grouped by endpoint and kept out of collector self-noise.",
            flowCount > 0 ? "risk-info" : "risk-low");
        AppendOverviewItem(
            html,
            "Linked PCAP/artifacts",
            linkedArtifacts.Count.ToString(CultureInfo.InvariantCulture),
            $"Packet captures: {pcapCount}; related artifacts are surfaced on endpoint cards as compact copyable evidence.",
            linkedArtifacts.Count > 0 ? "risk-info" : "risk-low");
        html.AppendLine("</div>");
    }

    /// <summary>
    /// Builds endpoint-centric network relationship cards.
    /// Inputs are network events and artifact lookup data; processing groups by
    /// extracted target and summarizes protocols/process actors plus PCAP/source
    /// artifact links; returns copyable cards.
    /// </summary>
    private static IReadOnlyList<NetworkRelationshipCard> BuildNetworkRelationshipCards(
        IReadOnlyCollection<SandboxEvent> networkEvents,
        IReadOnlyDictionary<string, List<ArtifactDescriptor>> artifactLookup,
        IReadOnlyCollection<ArtifactDescriptor> artifacts)
    {
        return networkEvents
            .Select(evt => new
            {
                Event = evt,
                Target = ExtractNetworkTarget(evt) ?? string.Empty
            })
            .Where(item => !string.IsNullOrWhiteSpace(item.Target))
            .GroupBy(item => item.Target, StringComparer.OrdinalIgnoreCase)
            .Select(group =>
            {
                var events = group.Select(item => item.Event).OrderBy(evt => evt.Timestamp).ToList();
                var first = events.First();
                var last = events.Last();
                var protocols = events.Select(NetworkProtocolLabel).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(value => value, StringComparer.OrdinalIgnoreCase).ToList();
                var dnsCount = events.Count(evt => string.Equals(NetworkCategoryLabel(evt), "DNS", StringComparison.OrdinalIgnoreCase));
                var httpCount = events.Count(evt => string.Equals(NetworkCategoryLabel(evt), "HTTP", StringComparison.OrdinalIgnoreCase));
                var tlsCount = events.Count(evt => string.Equals(NetworkCategoryLabel(evt), "TLS", StringComparison.OrdinalIgnoreCase));
                var flowCount = events.Count - dnsCount - httpCount - tlsCount;
                var categories = BuildNetworkCategoryDisplay(dnsCount, httpCount, tlsCount, flowCount);
                var processes = events.Select(ProcessDisplayName).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(value => value, StringComparer.OrdinalIgnoreCase).ToList();
                var eventTypes = events.Select(evt => evt.EventType).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(value => value, StringComparer.OrdinalIgnoreCase).ToList();
                var evidenceLines = events.Take(12).Select(EventOneLine).ToList();
                var relatedArtifacts = FindNetworkRelatedArtifacts(events, artifactLookup, artifacts);
                var compactSummary = BuildNetworkCompactSummary(
                    group.Key,
                    events.Count,
                    dnsCount,
                    httpCount,
                    tlsCount,
                    flowCount,
                    processes,
                    relatedArtifacts,
                    first,
                    last);
                var copyText = string.Join(
                    Environment.NewLine,
                    [
                        compactSummary,
                        $"target={group.Key}",
                        $"events={events.Count}",
                        $"protocols={string.Join(",", protocols)}",
                        $"categories={string.Join(",", categories)}",
                        $"dnsEvents={dnsCount}",
                        $"httpEvents={httpCount}",
                        $"tlsEvents={tlsCount}",
                        $"flowOrOtherEvents={flowCount}",
                        $"firstSeen={first.Timestamp:u}",
                        $"lastSeen={last.Timestamp:u}",
                        $"relatedArtifacts={relatedArtifacts.Count}",
                        "linkedArtifacts:",
                        .. relatedArtifacts.Take(RelationshipArtifactInlineLimit).Select(ArtifactCompactLine),
                        "processes:",
                        .. processes.Take(12),
                        "eventTypes:",
                        .. eventTypes.Take(12),
                        "evidence:",
                        .. evidenceLines
                    ]);
                return new NetworkRelationshipCard(
                    group.Key,
                    NetworkCardRisk(events),
                    events.Count,
                    protocols.Count == 0 ? "network" : string.Join(" / ", protocols),
                    categories,
                    dnsCount,
                    httpCount,
                    tlsCount,
                    flowCount,
                    first.Timestamp.ToString("u"),
                    last.Timestamp.ToString("u"),
                    processes,
                    eventTypes,
                    evidenceLines,
                    relatedArtifacts,
                    compactSummary,
                    copyText);
            })
            .OrderByDescending(card => card.EventCount)
            .ThenBy(card => card.Target, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>
    /// Appends a one-line parent-to-process relationship path for a process card.
    /// Inputs are a summarized process card; processing emits a visible static
    /// path so analysts can scan lineage and artifact proof without opening the
    /// full relationship-map details block.
    /// </summary>
    private static void AppendProcessRelationFlow(StringBuilder html, ProcessRelationshipCard card)
    {
        var children = card.ChildLabels.Count == 0
            ? "no child process"
            : string.Join(" + ", card.ChildLabels.Take(3));
        var artifact = card.RelatedArtifacts.Count == 0
            ? "no linked artifact"
            : string.Join(" + ", card.RelatedArtifacts.Take(2).Select(ArtifactDisplayName));
        var flow = $"Process relation path: {card.ParentLabel} -> {card.Label} -> {children} -> {artifact}; files={card.FileCount}; registry={card.RegistryCount}; network={card.NetworkCount}";
        html.AppendLine($"<div class=\"relation-flow copyable\" data-copy=\"{A(flow)}\"><strong>Process relation path</strong><br>{E(card.ParentLabel)} → <code>{E(card.Label)}</code> → {E(children)} → {E(artifact)}<br><span class=\"muted\">Files {E(card.FileCount.ToString(CultureInfo.InvariantCulture))} / Registry {E(card.RegistryCount.ToString(CultureInfo.InvariantCulture))} / Network {E(card.NetworkCount.ToString(CultureInfo.InvariantCulture))}</span></div>");
    }

    /// <summary>
    /// Appends a one-line process-to-endpoint relation path for a network card.
    /// Inputs are an already summarized endpoint card; processing emits a
    /// static copyable flow, avoiding graph libraries while making the network
    /// relationship visually scannable.
    /// </summary>
    private static void AppendNetworkRelationFlow(StringBuilder html, NetworkRelationshipCard card)
    {
        var actor = card.Processes.Count == 0 ? "unknown process" : string.Join(" + ", card.Processes.Take(3));
        var artifact = card.RelatedArtifacts.Count == 0
            ? "no linked artifact"
            : string.Join(" + ", card.RelatedArtifacts.Take(2).Select(ArtifactDisplayName));
        var flow = $"Network relation path: {actor} -> {card.Target} -> {string.Join("/", card.Categories)} -> {artifact}; DNS/HTTP/TLS/flow={card.DnsCount}/{card.HttpCount}/{card.TlsCount}/{card.FlowCount}";
        html.AppendLine($"<div class=\"relation-flow copyable\" data-copy=\"{A(flow)}\"><strong>Network relation path</strong><br>{E(actor)} → <code>{E(card.Target)}</code> → {E(string.Join(" / ", card.Categories))} → {E(artifact)}<br><span class=\"muted\">DNS/HTTP/TLS/flow {E(card.DnsCount.ToString(CultureInfo.InvariantCulture))}/{E(card.HttpCount.ToString(CultureInfo.InvariantCulture))}/{E(card.TlsCount.ToString(CultureInfo.InvariantCulture))}/{E(card.FlowCount.ToString(CultureInfo.InvariantCulture))}</span></div>");
    }

    /// <summary>
    /// Finds artifacts related to a process-card event group.
    /// Inputs are all events in one process card plus artifact indexes; processing
    /// matches explicit event references and process metadata hints; returns
    /// sorted descriptors for card-level evidence links.
    /// </summary>
    private static IReadOnlyList<ArtifactDescriptor> FindProcessRelatedArtifacts(
        IReadOnlyCollection<SandboxEvent> events,
        IReadOnlyDictionary<string, List<ArtifactDescriptor>> artifactLookup,
        IReadOnlyCollection<ArtifactDescriptor> artifacts)
    {
        var related = FindRelatedArtifactsForEvents(events, artifactLookup, artifacts);
        var processIds = events
            .Where(evt => evt.ProcessId.HasValue)
            .Select(evt => evt.ProcessId!.Value)
            .ToHashSet();
        var processNames = events
            .Select(evt => evt.ProcessName)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Cast<string>()
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var artifact in artifacts.Where(IsEvidenceArtifactKind))
        {
            if (ArtifactMatchesAnyProcess(artifact, processIds, processNames))
            {
                AddRelatedArtifact(related, artifact);
            }
        }

        return SortRelatedArtifacts(related.Values);
    }

    /// <summary>
    /// Finds artifacts related to an endpoint-card event group.
    /// Inputs are all events in one network card plus artifact indexes;
    /// processing matches sourceArtifact* references and PCAP collection hints;
    /// returns sorted descriptors for compact card-level links.
    /// </summary>
    private static IReadOnlyList<ArtifactDescriptor> FindNetworkRelatedArtifacts(
        IReadOnlyCollection<SandboxEvent> events,
        IReadOnlyDictionary<string, List<ArtifactDescriptor>> artifactLookup,
        IReadOnlyCollection<ArtifactDescriptor> artifacts)
    {
        var related = FindRelatedArtifactsForEvents(events, artifactLookup, artifacts);
        var hasExplicitPacketCaptureLink = related.Values.Any(artifact => artifact.Kind == ArtifactKind.PacketCapture);
        if (!hasExplicitPacketCaptureLink && NetworkEventsShouldLinkPacketCapture(events))
        {
            foreach (var artifact in artifacts.Where(artifact => artifact.Kind == ArtifactKind.PacketCapture))
            {
                AddRelatedArtifact(related, artifact);
            }
        }

        return SortRelatedArtifacts(related.Values);
    }

    private static Dictionary<string, ArtifactDescriptor> FindRelatedArtifactsForEvents(
        IEnumerable<SandboxEvent> events,
        IReadOnlyDictionary<string, List<ArtifactDescriptor>> artifactLookup,
        IReadOnlyCollection<ArtifactDescriptor> artifacts)
    {
        var related = new Dictionary<string, ArtifactDescriptor>(StringComparer.OrdinalIgnoreCase);
        foreach (var evt in events)
        {
            foreach (var artifact in FindRelatedArtifacts(evt, artifactLookup, artifacts))
            {
                AddRelatedArtifact(related, artifact);
            }
        }

        return related;
    }

    private static void AddRelatedArtifact(Dictionary<string, ArtifactDescriptor> related, ArtifactDescriptor artifact)
    {
        if (IsReportArtifactKind(artifact.Kind) && !IsCollectorSelfNoiseArtifact(artifact))
        {
            related[ArtifactKey(artifact)] = artifact;
        }
    }

    private static IReadOnlyList<ArtifactDescriptor> SortRelatedArtifacts(IEnumerable<ArtifactDescriptor> artifacts)
    {
        return artifacts
            .OrderBy(artifact => ArtifactKindRank(artifact.Kind))
            .ThenBy(artifact => artifact.RelativePath, StringComparer.OrdinalIgnoreCase)
            .ThenBy(artifact => artifact.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static bool IsEvidenceArtifactKind(ArtifactDescriptor artifact)
    {
        return artifact.Kind is ArtifactKind.DroppedFile or
            ArtifactKind.Screenshot or
            ArtifactKind.MemoryDump or
            ArtifactKind.PacketCapture;
    }

    private static bool ArtifactMatchesAnyProcess(
        ArtifactDescriptor artifact,
        IReadOnlySet<int> processIds,
        IReadOnlySet<string> processNames)
    {
        if (processIds.Count > 0)
        {
            var processId = MetadataValue(
                artifact.Metadata,
                "processId",
                "pid",
                "sourceProcessId",
                "targetProcessId",
                "rootProcessId",
                "dumpProcessId",
                "screenshotProcessId",
                "packetCaptureProcessId");
            if (int.TryParse(processId, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsedProcessId) &&
                processIds.Contains(parsedProcessId))
            {
                return true;
            }
        }

        if (processNames.Count > 0)
        {
            var processName = MetadataValue(
                artifact.Metadata,
                "processName",
                "imageName",
                "sourceProcessName",
                "targetProcessName",
                "rootProcessName",
                "dumpProcessName",
                "screenshotProcessName");
            if (!string.IsNullOrWhiteSpace(processName) &&
                processNames.Contains(processName))
            {
                return true;
            }
        }

        return false;
    }

    private static bool NetworkEventsShouldLinkPacketCapture(IReadOnlyCollection<SandboxEvent> events)
    {
        return events.Any(evt =>
            IsPacketCaptureEvidenceEvent(evt) ||
            TextEqualsAny(FirstEventDataValue(evt, "sourceArtifactKind", "artifactKind", "kind") ?? string.Empty, nameof(ArtifactKind.PacketCapture), "packet-capture", "pcap", "pcapng") ||
            string.Equals(FirstEventDataValue(evt, "collectionName"), "packet-captures", StringComparison.OrdinalIgnoreCase) ||
            EventTextContainsAny(evt, "packetCaptureRelativePath", "pcapRelativePath", "pcapngRelativePath", ".pcap", ".pcapng"));
    }

    private static string BuildProcessCompactSummary(
        string label,
        int eventCount,
        int childCount,
        int fileCount,
        int registryCount,
        int networkCount,
        IReadOnlyCollection<ArtifactDescriptor> relatedArtifacts,
        SandboxEvent first,
        SandboxEvent last)
    {
        return $"Process compact summary: process={label}; events={eventCount}; children={childCount}; files={fileCount}; registry={registryCount}; network={networkCount}; linkedArtifacts={relatedArtifacts.Count} ({ArtifactKindSummary(relatedArtifacts)}); window={first.Timestamp:u}..{last.Timestamp:u}";
    }

    private static string BuildNetworkCompactSummary(
        string target,
        int eventCount,
        int dnsCount,
        int httpCount,
        int tlsCount,
        int flowCount,
        IReadOnlyCollection<string> processes,
        IReadOnlyCollection<ArtifactDescriptor> relatedArtifacts,
        SandboxEvent first,
        SandboxEvent last)
    {
        var processSummary = processes.Count == 0 ? "-" : string.Join(", ", processes.Take(4));
        return $"Network compact summary: target={target}; events={eventCount}; DNS/HTTP/TLS/flow={dnsCount}/{httpCount}/{tlsCount}/{flowCount}; processes={processSummary}; linkedArtifacts={relatedArtifacts.Count} ({ArtifactKindSummary(relatedArtifacts)}); window={first.Timestamp:u}..{last.Timestamp:u}";
    }

    private static string ArtifactKindSummary(IReadOnlyCollection<ArtifactDescriptor> artifacts)
    {
        var groups = artifacts
            .GroupBy(artifact => artifact.Kind)
            .OrderBy(group => ArtifactKindRank(group.Key))
            .Select(group => $"{group.Key} {group.Count()}")
            .Take(6)
            .ToList();
        return groups.Count == 0 ? "none" : string.Join(", ", groups);
    }

    private static string ArtifactCompactLine(ArtifactDescriptor artifact)
    {
        return string.Join(
            " | ",
            [
                $"artifact={ArtifactDisplayName(artifact)}",
                $"kind={artifact.Kind}",
                $"category={artifact.Category}",
                $"size={FormatArtifactSize(artifact.SizeBytes)}",
                $"sha256={ArtifactSha256(artifact)}",
                $"selector={FirstNonEmpty(MetadataValue(artifact.Metadata, "downloadSelector"), artifact.RelativePath, "-")}",
                $"href={FirstNonEmpty(ArtifactHref(artifact), "-")}"
            ]);
    }

    /// <summary>
    /// Renders compact artifact badges for cards and graph edges when related
    /// descriptors already exist in current report/index data.
    /// </summary>
    private static string RenderInlineArtifactBadges(IReadOnlyCollection<ArtifactDescriptor> artifacts, string label)
    {
        if (artifacts.Count == 0)
        {
            return string.Empty;
        }

        var shown = artifacts.Take(RelationshipArtifactInlineLimit).ToList();
        var hidden = Math.Max(0, artifacts.Count - shown.Count);
        var copy = string.Join(Environment.NewLine, artifacts.Select(ArtifactCompactLine));
        var html = new StringBuilder();
        html.Append($"<div class=\"artifact-badge-row copyable\" data-copy=\"{A(copy)}\"><strong>{E(label)}</strong>");
        foreach (var artifact in shown)
        {
            var compact = ArtifactCompactLine(artifact);
            var badge = $"{artifact.Kind}:{ArtifactDisplayName(artifact)}";
            html.Append($"<span class=\"chip chip-info copyable\" data-copy=\"{A(compact)}\" title=\"{A(compact)}\">{E(AbbreviateEvidenceValue(badge, 64))}</span>");
        }

        if (hidden > 0)
        {
            html.Append($"<span class=\"chip chip-medium\">+{E(hidden.ToString(CultureInfo.InvariantCulture))}</span>");
        }

        html.Append("</div>");
        return html.ToString();
    }

    /// <summary>
    /// Appends one compact, copyable analyst summary inside a relationship card.
    /// Inputs are pre-built summary text and a copy label; processing writes a
    /// short visible paragraph plus an explicit copy button; return is none.
    /// </summary>
    private static void AppendCompactEvidenceSummary(StringBuilder html, string compactSummary, string copyLabel)
    {
        if (string.IsNullOrWhiteSpace(compactSummary))
        {
            return;
        }

        html.AppendLine($"<div class=\"compact-evidence-summary copyable\" data-copy=\"{A(compactSummary)}\"><strong>Compact evidence summary</strong><br>{E(compactSummary)}<div class=\"toolbar\">{CopyButton(copyLabel, compactSummary)}</div></div>");
    }

    /// <summary>
    /// Appends bounded related-artifact links for process/network cards.
    /// Inputs are artifact descriptors already associated to a card; processing
    /// emits compact one-line evidence and safe Open/Download actions; return is
    /// none and large descriptor walls are deliberately avoided.
    /// </summary>
    private static void AppendRelationshipArtifactLinks(
        StringBuilder html,
        IReadOnlyCollection<ArtifactDescriptor> artifacts,
        string title,
        string copyLabel)
    {
        if (artifacts.Count == 0)
        {
            return;
        }

        var shown = artifacts.Take(RelationshipArtifactInlineLimit).ToList();
        var hidden = Math.Max(0, artifacts.Count - shown.Count);
        var copy = string.Join(Environment.NewLine, shown.Select(ArtifactCompactLine));
        html.AppendLine($"<details class=\"relationship-details related-artifacts-flat\"><summary>{E(title)} ({E(shown.Count.ToString(CultureInfo.InvariantCulture))}/{E(artifacts.Count.ToString(CultureInfo.InvariantCulture))})</summary>");
        html.AppendLine("<ul class=\"artifact-list\">");
        foreach (var artifact in shown)
        {
            var compact = ArtifactCompactLine(artifact);
            html.Append("<li>");
            html.Append($"<code class=\"copyable\" data-copy=\"{A(compact)}\">{E(ArtifactDisplayName(artifact))}</code>");
            html.Append(RenderArtifactActionButtons(artifact, inline: true));
            html.Append($"<br><span class=\"muted\">{E(artifact.Kind.ToString())} / {E(artifact.Category)} / {E(FormatArtifactSize(artifact.SizeBytes))} / sha256 {E(ArtifactSha256(artifact))}</span>");
            html.AppendLine("</li>");
        }

        html.AppendLine("</ul>");
        if (hidden > 0)
        {
            html.AppendLine($"<div class=\"copy-hint\">{E(hidden.ToString(CultureInfo.InvariantCulture))} additional linked artifacts are hidden from this compact card; use Artifact links or report.json for complete evidence.</div>");
        }

        html.AppendLine($"<div class=\"toolbar\">{CopyButton(copyLabel, copy)}</div>");
        html.AppendLine("</details>");
    }

    /// <summary>
    /// Chooses a process-card visual severity from relationship counts.
    /// </summary>
    private static string ProcessCardRisk(int fileCount, int registryCount, int networkCount, int childCount)
    {
        if (networkCount > 0 || registryCount > 0)
        {
            return "medium";
        }

        if (fileCount > 0 || childCount > 0)
        {
            return "info";
        }

        return "low";
    }

    /// <summary>
    /// Chooses a network-card visual severity from protocol/error events.
    /// </summary>
    private static string NetworkCardRisk(IReadOnlyCollection<SandboxEvent> events)
    {
        if (events.Any(evt => IsFailureEvent(evt) || evt.EventType.Contains("parse_error", StringComparison.OrdinalIgnoreCase)))
        {
            return "high";
        }

        if (events.Any(evt => evt.EventType.Contains("http", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.Contains("dns", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.Contains("tls", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.Contains("pcap", StringComparison.OrdinalIgnoreCase)))
        {
            return "medium";
        }

        return "info";
    }

    /// <summary>
    /// Returns a compact process display label for relationship cards.
    /// </summary>
    private static string ProcessDisplayName(SandboxEvent evt)
    {
        if (!string.IsNullOrWhiteSpace(evt.ProcessName) && evt.ProcessId.HasValue)
        {
            return $"{evt.ProcessName} ({evt.ProcessId.Value})";
        }

        if (!string.IsNullOrWhiteSpace(evt.ProcessName))
        {
            return evt.ProcessName!;
        }

        return evt.ProcessId.HasValue ? $"pid:{evt.ProcessId.Value}" : evt.Source;
    }

    /// <summary>
    /// Returns a compact protocol label for a network event.
    /// </summary>
    private static string NetworkProtocolLabel(SandboxEvent evt)
    {
        var applicationProtocol = FirstEventDataValue(evt, "applicationProtocol", "serviceHint", "serviceName");
        if (IsTrustedApplicationProtocol(evt, applicationProtocol) &&
            !string.Equals(applicationProtocol, "unknown", StringComparison.OrdinalIgnoreCase))
        {
            return applicationProtocol!.ToUpperInvariant();
        }

        if (evt.Data.TryGetValue("protocol", out var protocol) && !string.IsNullOrWhiteSpace(protocol))
        {
            return protocol.ToUpperInvariant();
        }

        if (evt.EventType.Contains("dns", StringComparison.OrdinalIgnoreCase))
        {
            return "DNS";
        }

        if (evt.EventType.Contains("http", StringComparison.OrdinalIgnoreCase))
        {
            return "HTTP";
        }

        if (evt.EventType.Contains("tls", StringComparison.OrdinalIgnoreCase))
        {
            return "TLS";
        }

        if (evt.EventType.Contains("pcap", StringComparison.OrdinalIgnoreCase))
        {
            return "PCAP";
        }

        if (evt.EventType.Contains("udp", StringComparison.OrdinalIgnoreCase))
        {
            return "UDP";
        }

        if (evt.EventType.Contains("tcp", StringComparison.OrdinalIgnoreCase))
        {
            return "TCP";
        }

        return "NET";
    }

    private static IReadOnlyList<string> BuildNetworkCategoryDisplay(int dnsCount, int httpCount, int tlsCount, int flowCount)
    {
        var categories = new List<string>();
        if (dnsCount > 0)
        {
            categories.Add($"DNS {dnsCount}");
        }

        if (httpCount > 0)
        {
            categories.Add($"HTTP {httpCount}");
        }

        if (tlsCount > 0)
        {
            categories.Add($"TLS {tlsCount}");
        }

        if (flowCount > 0 || categories.Count == 0)
        {
            categories.Add($"Flow/other {flowCount}");
        }

        return categories;
    }

    /// <summary>
    /// Classifies one network row into operator-facing DNS/HTTP/TLS/flow lanes.
    /// </summary>
    private static string NetworkCategoryLabel(SandboxEvent evt)
    {
        var applicationProtocol = FirstEventDataValue(evt, "applicationProtocol", "appProtocol", "serviceHint", "serviceName");
        var protocol = FirstEventDataValue(evt, "protocol", "transportProtocol", "networkProtocol", "ipProtocol");
        var trustedApplicationProtocol = IsTrustedApplicationProtocol(evt, applicationProtocol) ? applicationProtocol : string.Empty;
        if (ContainsProtocolOrType(trustedApplicationProtocol, "dns") ||
            ContainsProtocolOrType(protocol, "dns") ||
            evt.EventType.Contains("dns", StringComparison.OrdinalIgnoreCase) ||
            HasEventDataKeyContaining(evt, "dns", "queryName", "queryType", "answers"))
        {
            return "DNS";
        }

        if (ContainsProtocolOrType(trustedApplicationProtocol, "http") ||
            ContainsProtocolOrType(protocol, "http") ||
            evt.EventType.Contains("http", StringComparison.OrdinalIgnoreCase) ||
            HasEventDataKeyContaining(evt, "http", "url", "uri", "userAgent", "statusCode", "method"))
        {
            return "HTTP";
        }

        if (ContainsProtocolOrType(trustedApplicationProtocol, "tls") ||
            ContainsProtocolOrType(trustedApplicationProtocol, "ssl") ||
            ContainsProtocolOrType(protocol, "tls") ||
            ContainsProtocolOrType(protocol, "ssl") ||
            evt.EventType.Contains("tls", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.Contains("ssl", StringComparison.OrdinalIgnoreCase) ||
            HasEventDataKeyContaining(evt, "tls", "ssl", "sni", "serverName", "ja3", "certificate", "certSubject"))
        {
            return "TLS";
        }

        return "Flow";
    }

    private static bool IsTrustedApplicationProtocol(SandboxEvent evt, string? applicationProtocol)
    {
        if (string.IsNullOrWhiteSpace(applicationProtocol))
        {
            return false;
        }

        var eventKind = FirstEventDataValue(evt, "eventKind");
        if (!string.Equals(eventKind, "connection", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var source = FirstEventDataValue(evt, "applicationProtocolSource", "appProtocolSource", "serviceSource");
        if (!string.IsNullOrWhiteSpace(source))
        {
            return true;
        }

        return !string.Equals(FirstEventDataValue(evt, "serviceHintSource"), "port-or-protocol", StringComparison.OrdinalIgnoreCase);
    }

    private static bool ContainsProtocolOrType(string? value, string token) =>
        !string.IsNullOrWhiteSpace(value) && value.Contains(token, StringComparison.OrdinalIgnoreCase);

    private static bool HasEventDataKeyContaining(SandboxEvent evt, params string[] tokens)
    {
        return evt.Data.Keys.Any(key => tokens.Any(token => key.Contains(token, StringComparison.OrdinalIgnoreCase)));
    }

    /// <summary>
    /// Converts one event to a terse relationship-card evidence line.
    /// </summary>
    private static string EventOneLine(SandboxEvent evt)
    {
        var location = ExtractReadableEventTarget(evt);
        return $"{evt.Timestamp:u} | {evt.EventType} | {ProcessDisplayName(evt)} | {location}";
    }

    /// <summary>
    /// Appends one metric card.
    /// Inputs are label, value, and CSS class, processing writes encoded HTML,
    /// and the method returns no value.
    /// </summary>
    private static void Metric(StringBuilder html, string label, string value, string css)
    {
        html.AppendLine($"<div class=\"metric\"><span class=\"muted\">{E(label)}</span><b class=\"{E(css)}\">{E(value)}</b></div>");
    }

    /// <summary>
    /// Appends one flat overview panel.
    /// Inputs are title, value, detail, and CSS class; processing writes a
    /// copyable square panel that matches the report's blue theme.
    /// </summary>
    private static void AppendOverviewItem(StringBuilder html, string title, string value, string detail, string css)
    {
        var copyText = string.Join(
            Environment.NewLine,
            [
                title,
                $"value={value}",
                $"detail={detail}"
            ]);
        html.AppendLine($"<article class=\"overview-item copyable\" data-copy=\"{A(copyText)}\"><h3>{E(title)}</h3><span class=\"overview-value {E(css)}\">{E(value)}</span><p>{E(detail)}</p></article>");
    }

    /// <summary>
    /// Appends one key-value row to a table body.
    /// Inputs are a StringBuilder, label, and value; processing encodes text;
    /// the method returns no value.
    /// </summary>
    private static void Row(StringBuilder html, string label, string value)
    {
        html.AppendLine($"<tr><th>{E(label)}</th><td class=\"copyable\" data-copy=\"{A(value)}\">{E(value)}</td></tr>");
    }

    /// <summary>
    /// Appends an empty-state message.
    /// Inputs are a StringBuilder and message, processing writes encoded text,
    /// and the method returns no value.
    /// </summary>
    private static void Empty(StringBuilder html, string message)
    {
        html.AppendLine($"<div class=\"empty\">{E(message)}</div>");
    }

    /// <summary>
    /// Appends one IOC card with copy support.
    /// Inputs are a title and bounded indicators; processing writes a compact
    /// list or an empty state; the method returns no value.
    /// </summary>
    private static void AppendIocCard(StringBuilder html, string title, IReadOnlyCollection<string> values, string emptyMessage)
    {
        html.AppendLine("<div class=\"ioc-card\">");
        var copy = values.Count == 0 ? string.Empty : string.Join(Environment.NewLine, values);
        html.AppendLine($"<h3>{E(title)}</h3>");
        if (values.Count > 0)
        {
            html.AppendLine($"<div class=\"toolbar\">{CopyButton("Copy IOCs", copy)}</div>");
        }

        if (values.Count == 0)
        {
            Empty(html, emptyMessage);
        }
        else
        {
            html.AppendLine("<ul>");
            foreach (var value in values)
            {
                html.AppendLine($"<li><code class=\"copyable\" data-copy=\"{A(value)}\">{E(value)}</code></li>");
            }

            html.AppendLine("</ul>");
        }

        html.AppendLine("</div>");
    }

    /// <summary>
    /// Builds compact process graph nodes from normalized events.
    /// Inputs are a report; processing groups by PID/name/path and derives
    /// child/event counts; the method returns copyable graph nodes.
    /// </summary>
    private static IReadOnlyList<ProcessGraphNode> BuildProcessGraphNodes(AnalysisReport report)
    {
        var behaviorEvents = report.Events.Where(IsSampleBehaviorEvent).ToList();
        var canonicalKeys = BuildProcessCanonicalKeyLookup(report);
        var eventsByProcess = behaviorEvents
            .Where(evt => evt.ProcessId.HasValue || !string.IsNullOrWhiteSpace(evt.ProcessName) || !string.IsNullOrWhiteSpace(evt.Path))
            .GroupBy(evt => ResolveProcessGroupKey(evt, canonicalKeys), StringComparer.OrdinalIgnoreCase)
            .ToList();
        var processLabels = BuildProcessLabelLookup(report);
        var known = behaviorEvents
            .Where(evt => IsProcessTreeCandidate(evt) && evt.ProcessId.HasValue)
            .SelectMany(ProcessLookupKeys)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var childCounts = behaviorEvents
            .Where(evt => evt.ProcessId.HasValue && evt.ParentProcessId.HasValue)
            .Select(evt => new { Event = evt, ParentKey = ResolveParentProcessKey(evt, known) ?? (evt.ParentProcessId.HasValue ? $"pid:{evt.ParentProcessId.Value}" : string.Empty) })
            .Where(item => !string.IsNullOrWhiteSpace(item.ParentKey))
            .GroupBy(item => item.ParentKey, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.Select(item => ResolveProcessGroupKey(item.Event, canonicalKeys)).Distinct(StringComparer.OrdinalIgnoreCase).Count(), StringComparer.OrdinalIgnoreCase);

        return eventsByProcess
            .Select(group =>
            {
                var first = group.OrderBy(evt => evt.Timestamp).First();
                var label = ResolveProcessLabel(first, processLabels);
                var childCount = ProcessLookupKeys(first)
                    .Where(childCounts.ContainsKey)
                    .Sum(key => childCounts[key]);
                if (childCount == 0 && first.ProcessId.HasValue && childCounts.TryGetValue($"pid:{first.ProcessId.Value}", out var pidChildren))
                {
                    childCount = pidChildren;
                }

                var detail = $"pid={first.ProcessId?.ToString() ?? "-"} ppid={first.ParentProcessId?.ToString() ?? "-"} events={group.Count()} children={childCount} firstSeen={first.Timestamp:u}";
                return new ProcessGraphNode(
                    label,
                    detail,
                    string.Join(Environment.NewLine, [$"process={label}", $"processKey={ProcessIdentityKey(first)}", detail, $"path={first.Path ?? "-"}", $"commandLine={first.CommandLine ?? "-"}"]));
            })
            .OrderBy(node => node.Label, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>
    /// Builds behavior graph edges from normalized events.
    /// Inputs are report events and artifact lookup data; processing derives
    /// relationships between processes and files/registry/network/artifacts;
    /// the method returns bounded edge evidence.
    /// </summary>
    private static IReadOnlyList<BehaviorGraphEdge> BuildBehaviorGraphEdges(
        AnalysisReport report,
        IReadOnlyDictionary<string, List<ArtifactDescriptor>> artifactLookup,
        IReadOnlyCollection<ArtifactDescriptor> artifacts)
    {
        var edges = new List<BehaviorGraphEdge>();
        var processLabels = BuildProcessLabelLookup(report);
        foreach (var matrixRow in BuildArtifactEvidenceMatrixRows(report.Events, artifacts))
        {
            edges.Add(new BehaviorGraphEdge("artifactEvidenceMatrix", "artifact", matrixRow.CollectionName, ArtifactEvidenceMatrixEvidenceLine("artifactEvidenceMatrix lane", matrixRow), []));
        }

        foreach (var evt in report.Events.OrderBy(evt => evt.Timestamp))
        {
            if (!IsSampleBehaviorEvent(evt))
            {
                continue;
            }

            var from = EventProcessActor(evt);
            var relatedArtifacts = FindRelatedArtifacts(evt, artifactLookup, artifacts).Take(3).ToList();
            if (processLabels.Count > 0 && (evt.ProcessId.HasValue || !string.IsNullOrWhiteSpace(evt.ProcessName)))
            {
                from = ResolveProcessLabel(evt, processLabels);
            }

            if (IsProcessTreeCandidate(evt) && evt.ProcessId.HasValue)
            {
                var parent = ResolveParentProcessLabel(evt, processLabels);
                if (string.Equals(parent, "-", StringComparison.Ordinal))
                {
                    parent = from;
                }

                edges.Add(new BehaviorGraphEdge(parent, "spawn", ResolveProcessLabel(evt, processLabels), EventToPlainText(evt), relatedArtifacts));
            }

            if (IsFileEvent(evt) && !string.IsNullOrWhiteSpace(evt.Path))
            {
                edges.Add(new BehaviorGraphEdge(from, "file", evt.Path!, EventToPlainText(evt), relatedArtifacts));
            }

            if (IsRegistryEvent(evt) && !string.IsNullOrWhiteSpace(evt.Path))
            {
                edges.Add(new BehaviorGraphEdge(from, "registry", evt.Path!, EventToPlainText(evt), relatedArtifacts));
            }

            var networkTarget = ExtractNetworkTarget(evt);
            if (!string.IsNullOrWhiteSpace(networkTarget))
            {
                edges.Add(new BehaviorGraphEdge(from, "network", networkTarget, EventToPlainText(evt), relatedArtifacts));
            }

            var securityTarget = ExtractSecurityPrivilegeTarget(evt);
            if (IsSecurityPrivilegeFallbackEvent(evt) && !string.IsNullOrWhiteSpace(securityTarget))
            {
                edges.Add(new BehaviorGraphEdge(from, "security/privilege", securityTarget, EventToPlainText(evt), relatedArtifacts));
            }

            foreach (var artifact in relatedArtifacts)
            {
                edges.Add(new BehaviorGraphEdge(from, "artifact", ArtifactDisplayName(artifact), ArtifactToPlainText(artifact), [artifact]));
            }
        }

        return edges
            .GroupBy(edge => $"{edge.From}|{edge.Relation}|{edge.To}", StringComparer.OrdinalIgnoreCase)
            .Select(group => group.First())
            .ToList();
    }

    /// <summary>
    /// Extracts dynamic file/path indicators from file events.
    /// </summary>
    private static IReadOnlyList<string> ExtractFileIocs(AnalysisReport report)
    {
        return report.Events
            .Where(IsSampleBehaviorFileEvent)
            .Select(evt => evt.Path)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Cast<string>()
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>
    /// Extracts dynamic registry indicators from registry events.
    /// </summary>
    private static IReadOnlyList<string> ExtractRegistryIocs(AnalysisReport report)
    {
        return report.Events
            .Where(IsSampleBehaviorRegistryEvent)
            .Select(evt => evt.Path)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Cast<string>()
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>
    /// Extracts network indicators from DNS/HTTP/TLS/PCAP/TCP events.
    /// </summary>
    private static IReadOnlyList<string> ExtractNetworkIocs(AnalysisReport report)
    {
        return report.Events
            .Where(IsSampleBehaviorEvent)
            .Select(ExtractNetworkTarget)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Cast<string>()
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>
    /// Returns the best actor label for a graph edge.
    /// </summary>
    private static string EventProcessActor(SandboxEvent evt)
    {
        if (evt.ProcessId.HasValue)
        {
            return ProcessGraphLabel(evt);
        }

        if (!string.IsNullOrWhiteSpace(evt.ProcessName))
        {
            return evt.ProcessName!;
        }

        return evt.Source;
    }

    /// <summary>
    /// Returns a stable process label.
    /// </summary>
    private static string ProcessGraphLabel(SandboxEvent evt)
    {
        var name = !string.IsNullOrWhiteSpace(evt.ProcessName)
            ? evt.ProcessName
            : !string.IsNullOrWhiteSpace(evt.Path)
                ? Path.GetFileName(evt.Path)
                : "process";
        return evt.ProcessId.HasValue ? $"{name} pid:{evt.ProcessId.Value}" : name ?? "process";
    }

    /// <summary>
    /// Returns a stable grouping key for process-related events.
    /// </summary>
    private static string ProcessIdentityKey(SandboxEvent evt)
    {
        var stableKey = FirstEventDataValue(evt, "processKey", "processGuid", "processUniqueId", "snapshotKey", "processSnapshotKey");
        if (!string.IsNullOrWhiteSpace(stableKey))
        {
            return $"key:{stableKey}";
        }

        if (evt.ProcessId.HasValue)
        {
            var startTime = FirstEventDataValue(evt, "processCreateTime", "processStartTime", "createTime", "startTime", "startTimeUtc", "processStartTimeUtc", "createTimeUtc", "processCreateTimeUtc");
            if (!string.IsNullOrWhiteSpace(startTime))
            {
                return $"pid:{evt.ProcessId.Value}|start:{startTime}";
            }

            return $"pid:{evt.ProcessId.Value}";
        }

        if (!string.IsNullOrWhiteSpace(evt.ProcessName))
        {
            return $"name:{evt.ProcessName}";
        }

        return $"path:{evt.Path ?? evt.Source}";
    }

    /// <summary>
    /// Returns all process lookup keys that can identify one event actor.
    /// </summary>
    private static IReadOnlyList<string> ProcessLookupKeys(SandboxEvent evt)
    {
        var keys = new List<string>();
        AddProcessLookupKey(keys, ProcessIdentityKey(evt));
        var stableKey = FirstEventDataValue(evt, "processKey", "processGuid", "processUniqueId", "snapshotKey", "processSnapshotKey");
        if (!string.IsNullOrWhiteSpace(stableKey))
        {
            AddProcessLookupKey(keys, $"key:{stableKey}");
        }

        if (evt.ProcessId.HasValue)
        {
            var startTime = FirstEventDataValue(evt, "processCreateTime", "processStartTime", "createTime", "startTime", "startTimeUtc", "processStartTimeUtc", "createTimeUtc", "processCreateTimeUtc");
            if (!string.IsNullOrWhiteSpace(startTime))
            {
                AddProcessLookupKey(keys, $"pid:{evt.ProcessId.Value}|start:{startTime}");
            }

            AddProcessLookupKey(keys, $"pid:{evt.ProcessId.Value}");
        }

        if (!string.IsNullOrWhiteSpace(evt.ProcessName))
        {
            AddProcessLookupKey(keys, $"name:{evt.ProcessName}");
        }

        if (!string.IsNullOrWhiteSpace(evt.Path))
        {
            AddProcessLookupKey(keys, $"path:{evt.Path}");
        }

        return keys;
    }

    /// <summary>
    /// Returns parent process lookup keys for spawn-tree resolution.
    /// </summary>
    private static IReadOnlyList<string> ParentProcessLookupKeys(SandboxEvent evt)
    {
        var keys = new List<string>();
        var stableKey = FirstEventDataValue(evt, "parentProcessKey", "parentProcessGuid", "parentProcessUniqueId", "parentSnapshotKey", "parentProcessSnapshotKey");
        if (!string.IsNullOrWhiteSpace(stableKey))
        {
            AddProcessLookupKey(keys, $"key:{stableKey}");
        }

        var parentProcessId = ResolveParentProcessId(evt);
        if (parentProcessId.HasValue)
        {
            var startTime = FirstEventDataValue(evt, "parentProcessCreateTime", "parentProcessStartTime", "parentStartTimeUtc", "parentProcessStartTimeUtc", "parentCreateTimeUtc", "parentProcessCreateTimeUtc");
            if (!string.IsNullOrWhiteSpace(startTime))
            {
                AddProcessLookupKey(keys, $"pid:{parentProcessId.Value}|start:{startTime}");
            }

            AddProcessLookupKey(keys, $"pid:{parentProcessId.Value}");
        }

        var parentName = FirstEventDataValue(evt, "parentProcessName", "parentImageName");
        if (!string.IsNullOrWhiteSpace(parentName))
        {
            AddProcessLookupKey(keys, $"name:{parentName}");
        }

        var parentImage = FirstEventDataValue(evt, "parentProcessImage", "parentImage", "parentPath");
        if (!string.IsNullOrWhiteSpace(parentImage))
        {
            AddProcessLookupKey(keys, $"path:{parentImage}");
        }

        return keys;
    }

    private static int? ResolveParentProcessId(SandboxEvent evt)
    {
        if (evt.ParentProcessId.HasValue)
        {
            return evt.ParentProcessId.Value;
        }

        var parentPid = FirstEventDataValue(evt, "parentProcessId", "parentPid", "ppid", "ParentProcessId");
        return int.TryParse(parentPid, out var parsed) ? parsed : null;
    }

    private static void AddProcessLookupKey(List<string> keys, string? key)
    {
        if (!string.IsNullOrWhiteSpace(key) &&
            !keys.Contains(key, StringComparer.OrdinalIgnoreCase))
        {
            keys.Add(key);
        }
    }

    private static string? ResolveParentProcessKey(SandboxEvent evt, IReadOnlySet<string> knownKeys)
    {
        return ParentProcessLookupKeys(evt).FirstOrDefault(knownKeys.Contains);
    }

    private static IReadOnlyDictionary<string, string> BuildProcessLabelLookup(AnalysisReport report)
    {
        var lookup = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var start in report.Events
            .Where(evt => IsSampleBehaviorEvent(evt) && IsProcessTreeCandidate(evt) && evt.ProcessId.HasValue)
            .GroupBy(ProcessIdentityKey, StringComparer.OrdinalIgnoreCase)
            .Select(group => group.OrderBy(ProcessTreeSortKey).ThenBy(evt => evt.Timestamp).First()))
        {
            var label = ProcessGraphLabel(start);
            foreach (var key in ProcessLookupKeys(start))
            {
                lookup.TryAdd(key, label);
            }
        }

        return lookup;
    }

    private static IReadOnlyDictionary<string, string> BuildProcessCanonicalKeyLookup(AnalysisReport report)
    {
        var lookup = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var start in report.Events
            .Where(evt => IsSampleBehaviorEvent(evt) && IsProcessTreeCandidate(evt) && evt.ProcessId.HasValue)
            .GroupBy(ProcessIdentityKey, StringComparer.OrdinalIgnoreCase)
            .Select(group => group.OrderBy(ProcessTreeSortKey).ThenBy(evt => evt.Timestamp).First()))
        {
            var canonicalKey = ProcessIdentityKey(start);
            foreach (var key in ProcessLookupKeys(start))
            {
                lookup.TryAdd(key, canonicalKey);
            }
        }

        return lookup;
    }

    private static string ResolveProcessGroupKey(SandboxEvent evt, IReadOnlyDictionary<string, string> canonicalKeys)
    {
        foreach (var key in ProcessLookupKeys(evt))
        {
            if (canonicalKeys.TryGetValue(key, out var canonicalKey))
            {
                return canonicalKey;
            }
        }

        return ProcessIdentityKey(evt);
    }

    private static string ResolveProcessLabel(SandboxEvent evt, IReadOnlyDictionary<string, string> processLabels)
    {
        foreach (var key in ProcessLookupKeys(evt))
        {
            if (processLabels.TryGetValue(key, out var label))
            {
                return label;
            }
        }

        return ProcessGraphLabel(evt);
    }

    private static string ResolveParentProcessLabel(SandboxEvent evt, IReadOnlyDictionary<string, string> processLabels)
    {
        foreach (var key in ParentProcessLookupKeys(evt))
        {
            if (processLabels.TryGetValue(key, out var label))
            {
                return label;
            }
        }

        var parentProcessId = ResolveParentProcessId(evt);
        return parentProcessId.HasValue ? $"pid:{parentProcessId.Value}" : "-";
    }

    /// <summary>
    /// Returns an operator-readable event family for grouped timelines.
    /// </summary>
    private static string EventFamilyLabel(SandboxEvent evt)
    {
        if (IsSecurityPrivilegeFallbackEvent(evt))
        {
            return "security/privilege";
        }

        if (evt.EventType.StartsWith("process.", StringComparison.OrdinalIgnoreCase))
        {
            return "process";
        }

        if (IsFileEvent(evt))
        {
            return "file";
        }

        if (IsRegistryEvent(evt))
        {
            return "registry";
        }

        if (IsNetworkEvent(evt))
        {
            return "network";
        }

        if (IsR0Event(evt))
        {
            return "r0";
        }

        if (IsFailureEvent(evt))
        {
            return "failure";
        }

        return "other";
    }

    /// <summary>
    /// Extracts the best displayable network target from one event.
    /// </summary>
    private static string? ExtractNetworkTarget(SandboxEvent evt)
    {
        if (!IsNetworkEvent(evt) &&
            !evt.EventType.Contains("dns", StringComparison.OrdinalIgnoreCase) &&
            !evt.EventType.Contains("http", StringComparison.OrdinalIgnoreCase) &&
            !evt.EventType.Contains("tls", StringComparison.OrdinalIgnoreCase) &&
            !evt.EventType.Contains("pcap", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var canonicalTarget = FirstEventDataValue(
            evt,
            "networkTarget",
            "relationshipCardTarget",
            "networkRelationshipTarget",
            "relationshipTarget");
        if (!string.IsNullOrWhiteSpace(canonicalTarget))
        {
            return canonicalTarget;
        }

        var preferred = FirstEventDataValue(
            evt,
            "queryName",
            "query",
            "domain",
            "dnsName",
            "sni",
            "serverName",
            "host",
            "hostname",
            "url",
            "uri",
            "remoteEndpoint",
            "remoteAddress",
            "destinationEndpoint",
            "destinationAddress",
            "ip");
        if (string.IsNullOrWhiteSpace(preferred))
        {
            preferred = evt.Data
                .Where(pair => LooksLikeNetworkIndicatorKey(pair.Key) && !string.IsNullOrWhiteSpace(pair.Value))
                .Select(pair => pair.Value)
                .FirstOrDefault();
        }

        if (string.IsNullOrWhiteSpace(preferred) &&
            !string.IsNullOrWhiteSpace(evt.Path) &&
            (evt.Path.Contains("://", StringComparison.Ordinal) || evt.Path.Contains('.', StringComparison.Ordinal)))
        {
            preferred = evt.Path;
        }

        if (string.IsNullOrWhiteSpace(preferred))
        {
            return null;
        }

        var port = FirstEventDataValue(evt, "networkTargetPort", "remotePort", "destinationPort", "port");
        return string.IsNullOrWhiteSpace(port) ||
            preferred.Contains(':', StringComparison.Ordinal) ||
            preferred.Contains("://", StringComparison.Ordinal)
            ? preferred
            : $"{preferred}:{port}";
    }

    /// <summary>
    /// Extracts the best one-line target from normalized event fields.
    /// Inputs are one event; processing prefers network indicators, explicit
    /// path/target fields, then common Data payload keys emitted by Guest/R0/PCAP
    /// collectors; return is a stable analyst-readable target.
    /// </summary>
    private static string ExtractReadableEventTarget(SandboxEvent evt)
    {
        var networkTarget = ExtractNetworkTarget(evt);
        if (!string.IsNullOrWhiteSpace(networkTarget))
        {
            return networkTarget;
        }

        if (!string.IsNullOrWhiteSpace(evt.Path))
        {
            return evt.Path!;
        }

        var preferred = FirstEventDataValue(
            evt,
            "target",
            "targetPath",
            "targetProcessName",
            "targetProcess",
            "targetProcessId",
            "targetImage",
            "targetObject",
            "objectName",
            "objectPath",
            "subjectUserName",
            "filePath",
            "fullPath",
            "registryPath",
            "keyPath",
            "valueName",
            "imagePath",
            "modulePath",
            "processPath",
            "artifactPath",
            "droppedFilePath",
            "guestPath",
            "importPath",
            "flowKey",
            "sourceEndpoint",
            "destinationEndpoint",
            "operation",
            "name");
        return string.IsNullOrWhiteSpace(preferred) ? "-" : preferred;
    }

    private static string? FirstEventDataValue(SandboxEvent evt, params string[] keys)
    {
        foreach (var key in keys)
        {
            if (evt.Data.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return null;
    }

    /// <summary>
    /// Reads the first non-empty artifact metadata value from a set of keys.
    /// Inputs are optional artifact metadata and preferred key names;
    /// processing performs case-insensitive dictionary lookup when possible;
    /// the method returns the first non-empty value or null.
    /// </summary>
    private static string? MetadataValue(IReadOnlyDictionary<string, string>? metadata, params string[] keys)
    {
        if (metadata is null || metadata.Count == 0)
        {
            return null;
        }

        foreach (var key in keys)
        {
            if (metadata.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        foreach (var key in keys)
        {
            var pair = metadata.FirstOrDefault(item => string.Equals(item.Key, key, StringComparison.OrdinalIgnoreCase));
            if (!string.IsNullOrWhiteSpace(pair.Value))
            {
                return pair.Value;
            }
        }

        return null;
    }

    private static string FirstNonEmpty(params string?[] values)
    {
        foreach (var value in values)
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return string.Empty;
    }

    private static bool LooksLikeNetworkIndicatorKey(string key)
    {
        return key.Contains("address", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("host", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("domain", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("query", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("url", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("sni", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("ja3", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Counts findings with a specific severity.
    /// Inputs are a report and severity, processing compares case-insensitive
    /// severity strings, and the method returns the count.
    /// </summary>
    private static int CountSeverity(AnalysisReport report, string severity)
    {
        return CountSeverity(PrimaryBehaviorFindings(report), severity);
    }

    private static int CountSeverity(IEnumerable<BehaviorFinding> findings, string severity)
    {
        return findings.Count(f => string.Equals(f.Severity, severity, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Counts events matching any event type.
    /// Inputs are a report and event names, processing compares event types
    /// case-insensitively, and the method returns the count.
    /// </summary>
    private static int CountEvents(AnalysisReport report, params string[] eventTypes)
    {
        return report.Events.Count(e => eventTypes.Any(type => string.Equals(type, e.EventType, StringComparison.OrdinalIgnoreCase)));
    }

    private static int CountSampleBehaviorEvents(AnalysisReport report, params string[] eventTypes)
    {
        return report.Events.Count(e =>
            IsSampleBehaviorEvent(e) &&
            eventTypes.Any(type => string.Equals(type, e.EventType, StringComparison.OrdinalIgnoreCase)));
    }

    /// <summary>
    /// Counts events with a specific event-type prefix.
    /// Inputs are a report and prefix, processing compares case-insensitively,
    /// and the method returns the count.
    /// </summary>
    private static int CountEventsByPrefix(AnalysisReport report, string eventTypePrefix)
    {
        return report.Events.Count(e => e.EventType.StartsWith(eventTypePrefix, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Selects static evidence entries by prefix.
    /// Inputs are interesting strings and accepted prefixes; processing keeps
    /// matching values in original form; the method returns matching entries.
    /// </summary>
    private static IEnumerable<string> SelectEvidence(IEnumerable<string> values, params string[] prefixes)
    {
        return values.Where(value => prefixes.Any(prefix => value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)));
    }

    /// <summary>
    /// Describes PE section risk signals from display metadata.
    /// Inputs are section size and entropy values; processing emits concise
    /// labels for report triage; the method returns a display string.
    /// </summary>
    private static string DescribeSectionSignal(PeSectionInfo section)
    {
        var signals = new List<string>();
        if (section.Entropy >= 7.2)
        {
            signals.Add(section.Entropy >= 7.8 ? "very high entropy" : "high entropy");
        }
        else if (section.RawDataSize > 0 && section.Entropy <= 1.0)
        {
            signals.Add("low entropy");
        }

        if (section.RawDataSize == 0 && section.VirtualSize > 0)
        {
            signals.Add("virtual only");
        }
        else if (section.VirtualSize > section.RawDataSize * 4 && section.VirtualSize > 4096)
        {
            signals.Add("large virtual/raw gap");
        }

        if (section.Name.Contains("UPX", StringComparison.OrdinalIgnoreCase))
        {
            signals.Add("UPX-like");
        }

        return signals.Count == 0 ? "normal" : string.Join(", ", signals);
    }

    /// <summary>
    /// Converts one PE section row to copyable text.
    /// Inputs are section metadata and signal text; processing serializes a
    /// stable multiline block; the method returns clipboard text.
    /// </summary>
    private static string SectionToPlainText(PeSectionInfo section, string signal)
    {
        return string.Join(
            Environment.NewLine,
            [
                $"name={section.Name}",
                $"virtualAddress={section.VirtualAddress}",
                $"virtualSize={section.VirtualSize}",
                $"rawDataSize={section.RawDataSize}",
                $"entropy={section.Entropy:F3}",
                $"signal={signal}"
            ]);
    }

    /// <summary>
    /// Determines whether an event should be displayed as sample behavior.
    /// Inputs are normalized events; processing excludes collection health,
    /// optional reputation status, and sandbox collector self-noise so R0/agent
    /// plumbing does not appear as registry/file/network behavior.
    /// </summary>
    private static bool IsSampleBehaviorEvent(SandboxEvent evt)
    {
        return !IsExcludedFromBehaviorStoryEvent(evt) &&
            !IsCollectionHealthEvent(evt) &&
            !IsVirusTotalEvent(evt);
    }

    private static bool IsSampleBehaviorFileEvent(SandboxEvent evt) => IsSampleBehaviorEvent(evt) && IsFileEvent(evt);

    private static bool IsSampleBehaviorRegistryEvent(SandboxEvent evt) => IsSampleBehaviorEvent(evt) && IsRegistryEvent(evt);

    private static bool IsSampleBehaviorStartupEvent(SandboxEvent evt) => IsSampleBehaviorEvent(evt) && IsStartupEvent(evt);

    private static bool IsSampleBehaviorNetworkEvent(SandboxEvent evt) => IsSampleBehaviorEvent(evt) && IsNetworkEvent(evt);

    private static bool IsSampleBehaviorProcessEvent(SandboxEvent evt) =>
        IsSampleBehaviorEvent(evt) && evt.EventType.StartsWith("process.", StringComparison.OrdinalIgnoreCase);

    private static bool IsSampleBehaviorSecurityPrivilegeEvent(SandboxEvent evt) =>
        IsSampleBehaviorEvent(evt) && IsSecurityPrivilegeFallbackEvent(evt);

    private static bool IsSampleBehaviorR0Event(SandboxEvent evt) =>
        IsSampleBehaviorEvent(evt) && IsR0Event(evt) && !IsR0CollectionHealthEvent(evt);

    /// <summary>
    /// Identifies normalized Windows Security/ETW privilege and process-access rows.
    /// Inputs are one normalized event; processing uses event-type prefixes and
    /// high-signal access/privilege fields only, and the method returns true
    /// when the row belongs in the security/privilege presentation lane.
    /// </summary>
    private static bool IsSecurityPrivilegeEvent(SandboxEvent evt)
    {
        if (evt.EventType.StartsWith("security.", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("etw.security", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("etw.privilege", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (IsProcessAccessStyleEvent(evt) || IsPrivilegeTelemetryEvent(evt))
        {
            return true;
        }

        var eventFamily = FirstEventDataValue(evt, "eventFamily", "family", "category") ?? string.Empty;
        return TextEqualsAny(eventFamily, "security", "security/privilege", "security-privilege", "privilege", "process-access", "process_access") &&
            EventTextContainsAny(evt, "security", "etw", "privilege", "accessMask", "desiredAccess", "targetProcess", "handle", "token");
    }

    private static bool IsSecurityPrivilegeFallbackEvent(SandboxEvent evt) =>
        IsSecurityPrivilegeEvent(evt) && !IsR0GenericProcessAccessEvent(evt);

    private static bool IsR0GenericProcessAccessEvent(SandboxEvent evt) =>
        IsR0Event(evt) &&
        IsProcessAccessStyleEvent(evt) &&
        !evt.EventType.StartsWith("security.", StringComparison.OrdinalIgnoreCase) &&
        !evt.EventType.StartsWith("etw.", StringComparison.OrdinalIgnoreCase);

    private static bool IsProcessAccessStyleEvent(SandboxEvent evt)
    {
        if (TextEqualsAny(evt.EventType, "process.access", "process.open", "process.handle", "handle.opened") ||
            evt.EventType.StartsWith("process.access.", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("process.open.", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if ((evt.EventType.StartsWith("security.privilege.object_operation", StringComparison.OrdinalIgnoreCase) ||
                evt.EventType.StartsWith("security.process", StringComparison.OrdinalIgnoreCase) ||
                evt.EventType.StartsWith("security.token", StringComparison.OrdinalIgnoreCase) ||
                evt.EventType.StartsWith("security.", StringComparison.OrdinalIgnoreCase) ||
                evt.EventType.StartsWith("etw.security", StringComparison.OrdinalIgnoreCase)) &&
            EventDataHasAnyKey(
                evt,
                "desiredAccess",
                "requestedAccess",
                "accessMask",
                "grantedAccess",
                "targetProcessName",
                "targetProcessId",
                "handleId",
                "objectType",
                "eventData.AccessMask",
                "eventData.ObjectName",
                "eventData.ObjectType",
                "eventData.ProcessName"))
        {
            return true;
        }

        return evt.EventType.Contains("process", StringComparison.OrdinalIgnoreCase) &&
            EventDataHasAnyKey(evt, "desiredAccess", "requestedAccess", "accessMask", "grantedAccess") &&
            EventDataHasAnyKey(evt, "targetProcessName", "targetProcess", "targetProcessId", "targetImage");
    }

    private static bool IsPrivilegeTelemetryEvent(SandboxEvent evt)
    {
        if (evt.EventType.StartsWith("security.privilege", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("security.token", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("etw.privilege", StringComparison.OrdinalIgnoreCase) ||
            TextEqualsAny(evt.EventType, "privilege.enabled", "privilege.adjusted", "process.token", "token.privilege"))
        {
            return true;
        }

        return EventDataHasAnyKey(
                evt,
                "privilege",
                "privilegeName",
                "privilegeDisplayName",
                "privilegeList",
                "enabledPrivilegeList",
                "eventData.PrivilegeList",
                "eventData.EnabledPrivilegeList",
                "eventData.DisabledPrivilegeList") &&
            EventTextContainsAny(evt, "privilege", "AdjustTokenPrivileges", "SeDebugPrivilege", "SeBackupPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege");
    }

    private static string? ExtractSecurityPrivilegeTarget(SandboxEvent evt)
    {
        var target = FirstEventDataValue(
            evt,
            "targetProcessName",
            "targetProcess",
            "targetImage",
            "targetPath",
            "targetObject",
            "objectName",
            "objectPath",
            "eventData.ObjectName",
            "eventData.ObjectType",
            "eventData.ProcessName",
            "serviceName",
            "privilege",
            "privilegeName",
            "privilegeList",
            "enabledPrivilegeList",
            "eventData.PrivilegeList",
            "eventData.EnabledPrivilegeList");
        if (string.IsNullOrWhiteSpace(target))
        {
            return null;
        }

        var access = FirstEventDataValue(evt, "desiredAccess", "requestedAccess", "accessMask", "grantedAccess", "accesses", "eventData.AccessMask");
        return string.IsNullOrWhiteSpace(access)
            ? target
            : $"{target} · {access}";
    }

    private static bool IsExcludedFromBehaviorStoryEvent(SandboxEvent evt)
    {
        return IsBehaviorCountedFalseEvent(evt) ||
            IsNonBehaviorEvent(evt) ||
            IsNotSampleBehaviorMarkerEvent(evt) ||
            IsSampleBehaviorCandidateFalseEvent(evt) ||
            IsWeakOrEnvironmentalSampleCorrelationEvent(evt) ||
            IsCollectorSelfNoiseEvent(evt) ||
            IsVirusTotalQuietStateEvent(evt) ||
            IsR0CollectionHealthEvent(evt);
    }

    private static bool IsBehaviorCountedFalseEvent(SandboxEvent evt)
    {
        return EventDataBoolFalse(evt, "behaviorCounted", "behavior_counted", "countsAsBehavior", "countedAsBehavior");
    }

    private static bool IsSampleBehaviorCandidateFalseEvent(SandboxEvent evt)
    {
        return EventDataBoolFalse(evt, "sampleBehaviorCandidate", "sample_behavior_candidate");
    }

    private static bool IsWeakOrEnvironmentalSampleCorrelationEvent(SandboxEvent evt)
    {
        if (EventDataBoolTrue(evt, "strongSampleCorrelation"))
        {
            return false;
        }

        var label = FirstEventDataValue(evt, "sampleCorrelation", "sample_correlation");
        if (TextEqualsAny(label ?? string.Empty, "environment", "unknown", "uncorrelated", "nonbehavior", "not-sample", "not_sample"))
        {
            return true;
        }

        var status = FirstEventDataValue(evt, "sampleCorrelationStatus", "sample_correlation_status");
        if (TextEqualsAny(status ?? string.Empty, "environment", "unknown", "uncorrelated", "session-related", "session-only", "not-correlated", "not_correlated"))
        {
            return true;
        }

        var strength = FirstEventDataValue(evt, "sampleCorrelationStrength", "sample_correlation_strength");
        return TextEqualsAny(strength ?? string.Empty, "none", "weak", "session-only", "unattributed");
    }

    private static bool IsNotSampleBehaviorMarkerEvent(SandboxEvent evt)
    {
        if (EventDataBoolTrue(
                evt,
                "notSampleBehavior",
                "not_sample_behavior",
                "notBehaviorCandidate",
                "not_behavior_candidate",
                "hostImportSelfNoise",
                "operationalEvent",
                "reportOnly",
                "report_only"))
        {
            return true;
        }

        if (IsSampleBehaviorCandidateFalseEvent(evt) ||
            EventDataBoolFalse(evt, "sampleBehavior", "sample_behavior", "behaviorEvent", "behavior_event"))
        {
            return true;
        }

        var scope = FirstEventDataValue(
            evt,
            "behaviorScope",
            "sampleBehaviorScope",
            "eventScope",
            "scope",
            "classification",
            "eventRole");
        return TextEqualsAny(
            scope ?? string.Empty,
            "nonbehavior",
            "non-behavior",
            "not-sample",
            "not_sample",
            "collection",
            "collector",
            "self-noise",
            "self_noise",
            "metadata",
            "diagnostic",
            "health",
            "status",
            "readiness",
            "evidence-health",
            "evidence-quality",
            "collection-health",
            "collection-status",
            "enrichment-status",
            "report-only",
            "report_only",
            "artifact-index",
            "reputation");
    }

    private static bool IsNonBehaviorEvent(SandboxEvent evt)
    {
        if (EventDataBoolTrue(
                evt,
                "nonbehavior",
                "nonBehavior",
                "non_behavior",
                "notBehavior",
                "not_behavior",
                "metadataOnly",
                "metadata_only",
                "readinessOnly",
                "readiness_only",
                "statusOnly",
                "status_only",
                "healthEvent",
                "health_event",
                "diagnosticEvent",
                "diagnostic_event",
                "qualityEvent",
                "quality_event",
                "telemetryHealth",
                "telemetry_health",
                "telemetryDegraded",
                "telemetry_degraded",
                "backpressure",
                "backpressureObserved",
                "backpressure_observed",
                "lossObserved",
                "loss_observed",
                "enrichmentStatus",
                "enrichment_status",
                "vtQuietState",
                "vt_quiet_state"))
        {
            return true;
        }

        var eventKind = FirstEventDataValue(evt, "eventKind", "eventRole", "evidenceRole", "classification");
        return !string.IsNullOrWhiteSpace(eventKind) &&
            TextEqualsAny(
                eventKind,
                "nonbehavior",
                "non-behavior",
                "metadata",
                "diagnostic",
                "health",
                "status",
                "summary",
                "readiness",
                "collection-status",
                "evidence-quality",
                "quiet-state",
                "enrichment-status");
    }

    /// <summary>
    /// Detects rows produced by KSword's own collector/agent plumbing.
    /// Inputs are one event; processing checks process identity, R0Collector
    /// staging paths, device paths, and source tokens; the method returns true
    /// when the row should be treated as collection metadata rather than sample
    /// behavior.
    /// </summary>
    private static bool IsCollectorSelfNoiseEvent(SandboxEvent evt)
    {
        if (EventDataBoolTrue(evt, "collectorSelfNoise", "collector_self_noise", "selfNoise", "self_noise"))
        {
            return true;
        }

        if (TextContainsAny(evt.ProcessName ?? string.Empty, "KSword.Sandbox.R0Collector", "KSword.Sandbox.Agent"))
        {
            return true;
        }

        if (EventTextContainsAny(
                evt,
                "KSword.Sandbox.R0Collector.exe",
                "KSword.Sandbox.Agent.exe",
                @"\\.\KSwordSandboxDriver",
                @"\\.\Global\KSwordSandboxDriver",
                @"\KSwordSandbox\r0collector",
                @"\KSwordSandbox\agent",
                "eventOrigin=synthetic-r0collector"))
        {
            return true;
        }

        var producer = FirstEventDataValue(evt, "producer", "telemetrySource", "eventOrigin", "collectorName", "collectorProcessName");
        return !string.IsNullOrWhiteSpace(producer) &&
            TextContainsAny(producer, "r0collector", "KSword.Sandbox.R0Collector", "KSword.Sandbox.Agent");
    }

    private static bool IsCollectorSelfNoiseArtifact(ArtifactDescriptor artifact)
    {
        if (TextContainsAny(
                string.Join(
                    '\n',
                    artifact.Name,
                    artifact.RelativePath,
                    artifact.FullPath,
                    artifact.SafeLink,
                    artifact.Category),
                "KSword.Sandbox.R0Collector",
                "KSword.Sandbox.Agent",
                "/KSwordSandbox/r0collector",
                @"\KSwordSandbox\r0collector",
                "/KSwordSandbox/agent",
                @"\KSwordSandbox\agent"))
        {
            return true;
        }

        return artifact.Metadata.Any(pair =>
            TextContainsAny(pair.Key, "collectorProcessName", "collectorName", "eventOrigin") ||
            TextContainsAny(pair.Value, "r0collector", "KSword.Sandbox.R0Collector", "KSword.Sandbox.Agent"));
    }

    /// <summary>
    /// Determines whether an event belongs to file behavior.
    /// Inputs are normalized events; processing includes guest-normalized and
    /// driver-prefixed file rows; the method returns true on file evidence.
    /// </summary>
    private static bool IsFileEvent(SandboxEvent evt)
    {
        return evt.EventType.StartsWith("file.", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("driver.file", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Determines whether an event belongs to registry behavior.
    /// Inputs are normalized events; processing includes guest-normalized and
    /// driver-prefixed registry rows; the method returns true on registry evidence.
    /// </summary>
    private static bool IsRegistryEvent(SandboxEvent evt)
    {
        return evt.EventType.StartsWith("registry.", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("driver.registry", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsStartupEvent(SandboxEvent evt)
    {
        return evt.EventType.StartsWith("startup.", StringComparison.OrdinalIgnoreCase) ||
            TextEqualsAny(
                evt.EventType,
                "startup_item.created",
                "startup_item.modified",
                "startup_item.deleted",
                "startup_item.diff_truncated",
                "registry.run.created",
                "registry.run.modified",
                "registry.run.deleted",
                "registry.run.diff_truncated",
                "service.created",
                "service.modified",
                "service.deleted",
                "service.diff_truncated",
                "scheduled_task.created",
                "scheduled_task.modified",
                "scheduled_task.deleted",
                "scheduled_task.diff_truncated");
    }

    private static bool StartupEventHasUserWritableTarget(SandboxEvent evt)
    {
        var target = string.Join(
            "\n",
            evt.Path,
            evt.CommandLine,
            FirstEventDataValue(evt, "target"),
            FirstEventDataValue(evt, "value"),
            FirstEventDataValue(evt, "imagePath"),
            FirstEventDataValue(evt, "serviceDll"),
            FirstEventDataValue(evt, "taskToRun"),
            FirstEventDataValue(evt, "rawSummary"));
        return TextContainsAny(
            target,
            @"\Temp\",
            @"\AppData\",
            @"\Users\Public\",
            @"\Downloads\",
            @"\ProgramData\",
            ".ps1",
            ".vbs",
            ".js",
            ".hta",
            ".scr",
            ".dll",
            ".exe");
    }

    /// <summary>
    /// Determines whether an event belongs to network behavior.
    /// Inputs are normalized events; processing includes protocol-specific
    /// guest rows and driver network rows; the method returns true on network evidence.
    /// </summary>
    private static bool IsNetworkEvent(SandboxEvent evt)
    {
        return evt.EventType.StartsWith("network.", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("http.", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("dns.", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("tls.", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("pcap.", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("driver.network", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Determines whether an event came from R0Collector or driver telemetry.
    /// Inputs are normalized events; processing checks source names and event
    /// prefixes; the method returns true for R0/driver evidence.
    /// </summary>
    private static bool IsR0Event(SandboxEvent evt)
    {
        return evt.Source.Contains("driver", StringComparison.OrdinalIgnoreCase) ||
            evt.Source.Contains("r0", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("driver.", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("r0.", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("r0collector.", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Determines whether an event represents an operational failure.
    /// Inputs are one event, processing checks common failure tokens, and the
    /// method returns true when it should appear in the failure section.
    /// </summary>
    private static bool IsFailureEvent(SandboxEvent evt)
    {
        return evt.EventType.Contains("fail", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.Contains("timeout", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.Contains("error", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Determines whether an event belongs to VirusTotal hash-reputation
    /// enrichment. Inputs are normalized events; processing checks VT-specific
    /// event/source tokens and well-known enrichment data keys; the method
    /// returns true for reputation evidence rather than sandbox behavior.
    /// </summary>
    private static bool IsVirusTotalEvent(SandboxEvent evt)
    {
        if (TextContainsAny(evt.EventType, "virustotal", "virus-total") ||
            TextContainsAny(evt.Source, "virustotal", "virus-total", "threat-intel", "reputation"))
        {
            return true;
        }

        return evt.Data.Keys.Any(key =>
            string.Equals(key, "vtStatus", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(key, "vtVerdict", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(key, "virusTotalStatus", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(key, "virusTotalVerdict", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(key, "positives", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(key, "malicious", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(key, "suspicious", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(key, "harmless", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(key, "undetected", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(key, "permalink", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("virustotal", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Determines whether a finding came from VirusTotal/reputation enrichment.
    /// Inputs are one finding; processing checks rule id, title, summary, and
    /// tags; the method returns true when the finding should be shown in the
    /// dedicated reputation section.
    /// </summary>
    private static bool IsVirusTotalFinding(BehaviorFinding finding)
    {
        if (TextContainsAny(finding.RuleId, "virustotal", "virus-total", "vt-") ||
            TextContainsAny(finding.Title, "virustotal", "VirusTotal") ||
            TextContainsAny(finding.Summary, "virustotal", "VirusTotal"))
        {
            return true;
        }

        return finding.Tags.Any(tag =>
            TextContainsAny(tag, "virustotal", "virus-total", "threat-intel", "reputation", "vt"));
    }

    /// <summary>
    /// Checks whether any event data key equals an expected value.
    /// Inputs are an event plus one or more key names followed by the expected
    /// value; processing performs case-insensitive exact comparison; the
    /// method returns true when any key matches.
    /// </summary>
    private static bool EventDataEqualsAny(SandboxEvent evt, params string[] keysAndExpectedValue)
    {
        if (keysAndExpectedValue.Length < 2)
        {
            return false;
        }

        var expected = keysAndExpectedValue[^1];
        foreach (var key in keysAndExpectedValue.Take(keysAndExpectedValue.Length - 1))
        {
            if (evt.Data.TryGetValue(key, out var value) &&
                string.Equals(value, expected, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Determines whether a VirusTotal lookup row describes lookup health rather
    /// than a usable verdict. Inputs are one event; processing treats found and
    /// not_found as normal and flags auth/rate/transport/config failures.
    /// </summary>
    private static bool IsVirusTotalStatusIssue(SandboxEvent evt)
    {
        if (!IsVirusTotalEvent(evt))
        {
            return false;
        }

        var status = FirstEventDataValue(
            evt,
            "vtStatus",
            "virusTotalStatus",
            "lookupStatus",
            "status",
            "resultStatus",
            "enrichmentStatus");
        if (string.IsNullOrWhiteSpace(status))
        {
            return EventTextContainsAny(
                evt,
                "rate_limited",
                "authentication_failed",
                "lookup_failed",
                "not_configured",
                "quota_exceeded");
        }

        if (TextEqualsAny(status, "found", "not_found", "not-found", "ok", "success", "completed"))
        {
            return false;
        }

        return true;
    }

    private static bool IsVirusTotalQuietStateEvent(SandboxEvent evt)
    {
        if (!IsVirusTotalEvent(evt))
        {
            return false;
        }

        var verdict = FirstEventDataValue(evt, "vtVerdict", "virusTotalVerdict", "verdict");
        if (TextEqualsAny(verdict ?? string.Empty, "malicious", "suspicious"))
        {
            return false;
        }

        var status = FirstEventDataValue(
            evt,
            "vtStatus",
            "virusTotalStatus",
            "lookupStatus",
            "status",
            "resultStatus",
            "enrichmentStatus");
        if (TextEqualsAny(status ?? string.Empty, "found", "not_found", "not-found", "notfound", "clean", "ok", "success", "completed"))
        {
            return true;
        }

        if (TextEqualsAny(verdict ?? string.Empty, "clean", "harmless", "undetected", "benign", "not_found", "not-found", "unknown", "none"))
        {
            return true;
        }

        return !IsVirusTotalStatusIssue(evt) &&
            !EventDataLongGreaterThanZero(evt, "vtMalicious", "malicious", "vtSuspicious", "suspicious", "positives");
    }

    /// <summary>
    /// Determines whether an event describes telemetry collection quality.
    /// Inputs are normalized events; processing recognizes R0 health rows,
    /// runbook/collector diagnostics, queue counters, and readiness rows; the
    /// method returns true for plumbing quality evidence.
    /// </summary>
    private static bool IsCollectionHealthEvent(SandboxEvent evt)
    {
        if (IsR0CollectionHealthEvent(evt))
        {
            return true;
        }

        if (IsR0Event(evt))
        {
            return false;
        }

        if (IsNetworkImportHealthEvent(evt))
        {
            return true;
        }

        if (EventTextContainsAny(
                evt,
                "collection.health",
                "collector.health",
                "collector.status",
                "diagnostic",
                "readiness",
                "unavailable",
                "ioctlFailure",
                "protocolError",
                "driverHealth",
                "driverPoll",
                "driverReadEvents"))
        {
            return true;
        }

        return EventDataHasAnyKey(
            evt,
            "driverStateName",
            "queueDepth",
            "queueCapacity",
            "queueHighWatermark",
            "eventsDropped",
            "totalEventsDropped",
            "totalEventsBackpressured",
            "backpressureObserved",
            "captureState",
            "diagnosticStage",
            "readinessState");
    }

    private static bool IsNetworkImportHealthEvent(SandboxEvent evt)
    {
        if (TextEqualsAny(
                evt.EventType,
                "network.import.summary",
                "pcap.summary",
                "pcap.parse_error",
                "network.sidecar.parse_error"))
        {
            return true;
        }

        var eventFamily = FirstEventDataValue(evt, "eventFamily");
        var eventKind = FirstEventDataValue(evt, "eventKind") ?? string.Empty;
        return string.Equals(eventFamily, "network", StringComparison.OrdinalIgnoreCase) &&
            TextEqualsAny(eventKind, "summary", "parse_error");
    }

    /// <summary>
    /// Determines whether a collection-health row should be highlighted.
    /// Inputs are one event; processing flags unavailable devices, failures,
    /// protocol errors, queue backpressure, and dropped counters.
    /// </summary>
    private static bool IsCollectionHealthAlertEvent(SandboxEvent evt)
    {
        if (IsDeviceUnavailableHealthEvent(evt) || IsBackpressureOrDropHealthEvent(evt))
        {
            return true;
        }

        return IsCollectionHealthEvent(evt) &&
            (IsFailureEvent(evt) ||
                EventTextContainsAny(
                    evt,
                    "failed",
                    "failure",
                    "error",
                    "denied",
                    "missing",
                    "mismatch",
                    "unhealthy",
                    "protocolError"));
    }

    /// <summary>
    /// Determines whether an event should count as an operator-visible failure
    /// marker. Inputs are one event; processing excludes benign VT lookup
    /// status rows and only highlights collection health when an alert is
    /// present; the method returns true for actionable failures.
    /// </summary>
    private static bool IsOperationalFailureEvent(SandboxEvent evt)
    {
        if (IsVirusTotalStatusIssue(evt))
        {
            return false;
        }

        if (IsCollectionHealthEvent(evt))
        {
            return IsCollectionHealthAlertEvent(evt);
        }

        return IsFailureEvent(evt);
    }

    /// <summary>
    /// Determines whether an R0 event is collection health rather than sample
    /// telemetry. Inputs are R0/driver rows; processing recognizes IOCTL health
    /// events, batch status, readiness, protocol errors, and queue counters.
    /// </summary>
    private static bool IsR0CollectionHealthEvent(SandboxEvent evt)
    {
        if (!IsR0Event(evt))
        {
            return false;
        }

        if (evt.EventType.StartsWith("r0collector.driverHealth", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("r0collector.driverCapabilities", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("r0collector.driverNetworkStatus", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("r0collector.driverStatus", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("r0collector.driverPoll", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("r0collector.driverReadEvents", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("r0collector.ioctlFailure", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("r0collector.driverProtocolError", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (!evt.EventType.StartsWith("r0collector.", StringComparison.OrdinalIgnoreCase) &&
            !TextEqualsAny(evt.Source, "r0collector", "collection-health") &&
            !EventDataBoolTrue(evt, "collectionHealth", "collectionDiagnostic", "collectorDiagnostic"))
        {
            return false;
        }

        return EventDataHasAnyKey(
            evt,
            "driverState",
            "driverStateName",
            "queueDepth",
            "queueCapacity",
            "queueHighWatermark",
            "producerEnableMask",
            "supportedProducerMask",
            "networkStatusAvailable",
            "activeLayerMask",
            "activeLayerMaskHex",
            "supportedLayerMask",
            "supportedLayerMaskHex",
            "lastDegradeReasonName",
            "totalEventsDropped",
            "totalEventsBackpressured",
            "backpressureObserved");
    }

    /// <summary>
    /// Determines whether an R0 diagnostic is a health row rather than a WFP/ALE
    /// network-status snapshot. Inputs are normalized events; processing keeps
    /// driverNetworkStatus in its own readiness lane so reports can say
    /// "No R0 health rows" even when network-status diagnostics exist.
    /// </summary>
    private static bool IsR0HealthRowEvent(SandboxEvent evt)
    {
        return IsR0CollectionHealthEvent(evt) && !IsR0DriverNetworkStatusEvent(evt);
    }

    private static bool IsR0DriverNetworkStatusEvent(SandboxEvent evt)
    {
        return evt.EventType.StartsWith("r0collector.driverNetworkStatus", StringComparison.OrdinalIgnoreCase) ||
            EventDataHasAnyKey(
                evt,
                "networkStatusAvailable",
                "activeLayerMask",
                "activeLayerMaskHex",
                "supportedLayerMask",
                "supportedLayerMaskHex",
                "lastRegisteredCalloutMask",
                "lastAddedFilterMask");
    }

    private static string FormatR0NetworkStatusCounters(SandboxEvent evt)
    {
        return string.Join(
            "; ",
            [
                $"classifyCount={FirstEventDataValue(evt, "classifyCount") ?? "-"}",
                $"eventCount={FirstEventDataValue(evt, "eventCount") ?? "-"}",
                $"queueFailureCount={FirstEventDataValue(evt, "queueFailureCount") ?? "-"}",
                $"classifyPayloadFailureCount={FirstEventDataValue(evt, "classifyPayloadFailureCount") ?? "-"}",
                $"registerNtStatusHex={FirstEventDataValue(evt, "registerNtStatusHex") ?? "-"}",
                $"engineNtStatusHex={FirstEventDataValue(evt, "engineNtStatusHex") ?? "-"}",
                $"lastQueueFailureNtStatusHex={FirstEventDataValue(evt, "lastQueueFailureNtStatusHex") ?? "-"}"
            ]);
    }

    private static string R0NetworkStatusStoryLine(SandboxEvent evt)
    {
        return string.Join(
            " | ",
            [
                $"{evt.Timestamp:u}",
                "r0collector.driverNetworkStatus",
                $"available={FirstEventDataValue(evt, "networkStatusAvailable") ?? "-"}",
                $"readiness={FirstEventDataValue(evt, "readinessState", "status") ?? "-"}",
                $"activeMask={FirstEventDataValue(evt, "activeLayerMaskHex", "activeLayerMask") ?? "-"}",
                $"supportedMask={FirstEventDataValue(evt, "supportedLayerMaskHex", "supportedLayerMask") ?? "-"}",
                $"degrade={FirstEventDataValue(evt, "lastDegradeReasonName", "diagnosticCode") ?? "-"}",
                FormatR0NetworkStatusCounters(evt)
            ]);
    }

    private static bool HasR0NetworkFailureCounters(SandboxEvent evt)
    {
        return EventDataLongGreaterThanZero(evt, "queueFailureCount", "classifyPayloadFailureCount") ||
            !TextEqualsAny(FirstEventDataValue(evt, "lastDegradeReasonName") ?? string.Empty, string.Empty, "-", "none", "ok", "success");
    }

    /// <summary>
    /// Determines whether a collection-health event says the driver service or
    /// device endpoint was unavailable. Inputs are one event; processing checks
    /// event text and selected diagnostic fields.
    /// </summary>
    private static bool IsDeviceUnavailableHealthEvent(SandboxEvent evt)
    {
        if (!IsCollectionHealthEvent(evt) && !IsR0Event(evt))
        {
            return false;
        }

        return EventTextContainsAny(
            evt,
            "unavailable",
            "missing_service",
            "open_device_not_found",
            "open_device_denied",
            "device_not_found",
            "service_not_found",
            "driver_not_loaded",
            "not found",
            "denied",
            "not loaded");
    }

    /// <summary>
    /// Determines whether queue backpressure or dropped events were observed.
    /// Inputs are one event; processing checks boolean flags, counters, producer
    /// masks, and flag names; the method returns true on evidence loss.
    /// </summary>
    private static bool IsBackpressureOrDropHealthEvent(SandboxEvent evt)
    {
        if (EventTextContainsAny(evt, "QueueBackpressure", "EventsDropped", "backpressure", "dropped"))
        {
            return true;
        }

        if (EventDataBoolTrue(evt, "backpressureObserved", "backpressure", "lost"))
        {
            return true;
        }

        return EventDataLongGreaterThanZero(
            evt,
            "eventsDropped",
            "totalEventsDropped",
            "eventsBackpressured",
            "totalEventsBackpressured",
            "producerDroppedMask",
            "producerBackpressureMask");
    }

    /// <summary>
    /// Determines whether an R0 health row is a poll/status/read batch marker.
    /// Inputs are one event; processing checks high-frequency health event
    /// names; the method returns true for driver lifecycle snapshots.
    /// </summary>
    private static bool IsDriverHealthPollEvent(SandboxEvent evt)
    {
        return IsR0Event(evt) &&
            EventTextContainsAny(evt, "driverHealth", "driverPoll", "driverStatus", "driverReadEvents");
    }

    private static bool EventDataHasAnyKey(SandboxEvent evt, params string[] keys)
    {
        return keys.Any(key => evt.Data.ContainsKey(key));
    }

    private static bool EventDataBoolTrue(SandboxEvent evt, params string[] keys)
    {
        foreach (var key in keys)
        {
            if (evt.Data.TryGetValue(key, out var value) &&
                TextEqualsAny(value, "true", "1", "yes", "y"))
            {
                return true;
            }
        }

        return false;
    }

    private static bool EventDataBoolFalse(SandboxEvent evt, params string[] keys)
    {
        foreach (var key in keys)
        {
            if (evt.Data.TryGetValue(key, out var value) &&
                TextEqualsAny(value, "false", "0", "no", "n"))
            {
                return true;
            }
        }

        return false;
    }

    private static bool EventDataLongGreaterThanZero(SandboxEvent evt, params string[] keys)
    {
        foreach (var key in keys)
        {
            if (!evt.Data.TryGetValue(key, out var value) || string.IsNullOrWhiteSpace(value))
            {
                continue;
            }

            var trimmed = value.Trim();
            if (trimmed.StartsWith("0x", StringComparison.OrdinalIgnoreCase) &&
                long.TryParse(trimmed[2..], System.Globalization.NumberStyles.HexNumber, null, out var hexValue) &&
                hexValue > 0)
            {
                return true;
            }

            if (long.TryParse(trimmed, out var decimalValue) && decimalValue > 0)
            {
                return true;
            }
        }

        return false;
    }

    private static bool EventTextContainsAny(SandboxEvent evt, params string[] tokens)
    {
        if (TextContainsAny(evt.EventType, tokens) ||
            TextContainsAny(evt.Source, tokens) ||
            TextContainsAny(evt.Path ?? string.Empty, tokens) ||
            TextContainsAny(evt.CommandLine ?? string.Empty, tokens))
        {
            return true;
        }

        foreach (var pair in evt.Data)
        {
            if (TextContainsAny(pair.Key, tokens) || TextContainsAny(pair.Value, tokens))
            {
                return true;
            }
        }

        return false;
    }

    private static bool TextContainsAny(string value, params string[] tokens)
    {
        return tokens.Any(token => value.Contains(token, StringComparison.OrdinalIgnoreCase));
    }

    private static bool TextEqualsAny(string value, params string[] candidates)
    {
        return candidates.Any(candidate => string.Equals(value, candidate, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Determines the overall report verdict.
    /// Inputs are report status and findings, processing prioritizes failure
    /// and higher severities, and the method returns label and CSS key.
    /// </summary>
    private static (string Label, string Css) DetermineVerdict(AnalysisReport report)
    {
        if (report.Status == AnalysisStatus.Failed)
        {
            return ("Analysis failed", "high");
        }

        var primaryFindings = PrimaryBehaviorFindings(report).ToList();
        if (CountSeverity(primaryFindings, "critical") > 0)
        {
            return ("Critical risk", "critical");
        }

        if (CountSeverity(primaryFindings, "high") > 0)
        {
            return ("High risk", "high");
        }

        if (CountSeverity(primaryFindings, "medium") > 0)
        {
            return ("Suspicious", "medium");
        }

        return ("No high-risk behavior", "info");
    }

    private static IEnumerable<BehaviorFinding> PrimaryBehaviorFindings(AnalysisReport report)
    {
        return report.Findings.Where(finding =>
            !IsDiagnosticFinding(finding) &&
            !IsStaticTriageFinding(finding) &&
            !IsVirusTotalFinding(finding));
    }

    private static IEnumerable<BehaviorFinding> StaticTriageFindings(AnalysisReport report)
    {
        return report.Findings.Where(IsStaticTriageFinding);
    }

    private static IEnumerable<BehaviorFinding> DiagnosticFindings(AnalysisReport report)
    {
        return report.Findings.Where(IsDiagnosticFinding);
    }

    private static bool IsStaticTriageFinding(BehaviorFinding finding)
    {
        return finding.RuleId.StartsWith("static-", StringComparison.OrdinalIgnoreCase) ||
            finding.Tags.Any(tag => string.Equals(tag, "static", StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsDiagnosticFinding(BehaviorFinding finding)
    {
        if (finding.Evidence.Count > 0 &&
            finding.Evidence.All(evt =>
                IsCollectionHealthEvent(evt) ||
                IsR0CollectionHealthEvent(evt) ||
                IsCollectorSelfNoiseEvent(evt) ||
                IsNonBehaviorEvent(evt) ||
                IsNotSampleBehaviorMarkerEvent(evt) ||
                IsVirusTotalQuietStateEvent(evt) ||
                IsWeakOrEnvironmentalSampleCorrelationEvent(evt) ||
                IsBehaviorCountedFalseEvent(evt) ||
                IsSampleBehaviorCandidateFalseEvent(evt)))
        {
            return true;
        }

        if (finding.Tags.Any(tag =>
                string.Equals(tag, "plumbing", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(tag, "driver-health", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(tag, "collection", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(tag, "diagnostic", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(tag, "metadata", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(tag, "telemetry-context", StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        if (FindingTextSuggestsDiagnostic(finding))
        {
            return true;
        }

        return finding.RuleId.StartsWith("host-", StringComparison.OrdinalIgnoreCase) ||
            finding.RuleId.StartsWith("runbook-", StringComparison.OrdinalIgnoreCase) ||
            finding.RuleId.StartsWith("r0collector-", StringComparison.OrdinalIgnoreCase) ||
            finding.RuleId.Contains("unavailable", StringComparison.OrdinalIgnoreCase);
    }

    private static bool FindingTextSuggestsDiagnostic(BehaviorFinding finding)
    {
        return TextContainsAny(
                finding.RuleId,
                "health",
                "status",
                "readiness",
                "diagnostic",
                "self-noise",
                "self_noise",
                "collector-noise",
                "collector_noise",
                "quiet-state",
                "quiet_state",
                "collection-health",
                "collection-status")
            || TextContainsAny(
                finding.Title,
                "health",
                "status",
                "readiness",
                "diagnostic",
                "self-noise",
                "collector noise",
                "quiet state",
                "collection health",
                "collection status")
            || TextContainsAny(
                finding.Summary,
                "not sample behavior",
                "not malicious sample behavior",
                "collection health",
                "evidence quality",
                "readiness",
                "self-noise",
                "quiet state");
    }

    /// <summary>
    /// Maps severity to sort rank.
    /// Inputs are severity text, processing normalizes known values, and the
    /// method returns a lower number for higher priority.
    /// </summary>
    private static int SeverityRank(string severity)
    {
        return NormalizeSeverity(severity) switch
        {
            "critical" => 0,
            "high" => 1,
            "medium" => 2,
            "low" => 3,
            _ => 4
        };
    }

    /// <summary>
    /// Normalizes severity to a CSS-safe key.
    /// The input is severity text, processing maps unknown values to info, and
    /// the method returns a stable lowercase key.
    /// </summary>
    private static string NormalizeSeverity(string severity)
    {
        var value = severity.ToLowerInvariant();
        return value is "critical" or "high" or "medium" or "low" ? value : "info";
    }

    /// <summary>
    /// Formats bytes for report display.
    /// The input is a byte count, processing chooses a readable unit, and the
    /// method returns display text.
    /// </summary>
    private static string FormatBytes(long bytes)
    {
        if (bytes < 1024)
        {
            return $"{bytes} B";
        }

        if (bytes < 1024 * 1024)
        {
            return $"{bytes / 1024.0:F1} KiB";
        }

        return $"{bytes / 1024.0 / 1024.0:F2} MiB";
    }

    /// <summary>
    /// Encodes dynamic text for safe HTML output.
    /// The input is arbitrary text, processing applies WebUtility.HtmlEncode,
    /// and the method returns encoded text.
    /// </summary>
    private static string E(string value)
    {
        return WebUtility.HtmlEncode(value);
    }

    /// <summary>
    /// Encodes dynamic text for safe HTML attributes.
    /// The input is arbitrary text, processing applies HTML encoding, and the
    /// method returns encoded text for quoted attributes.
    /// </summary>
    private static string A(string value)
    {
        return WebUtility.HtmlEncode(value);
    }

    /// <summary>
    /// Builds a copy button for report evidence.
    /// Inputs are a label and copy text, processing encodes both values, and
    /// the method returns a trusted local HTML fragment.
    /// </summary>
    private static string CopyButton(string label, string copyText)
    {
        return $"<button type=\"button\" class=\"copy-btn\" data-copy-button=\"true\" data-copy=\"{A(copyText)}\">{E(label)}</button>";
    }

    /// <summary>
    /// Renders report-local open/download controls for a safe artifact link.
    /// Inputs are an artifact descriptor and display mode; processing validates
    /// the href as report-relative before writing anchors; the method returns
    /// an empty-state chip when only copyable paths are available.
    /// </summary>
    private static string RenderArtifactActionButtons(ArtifactDescriptor artifact, bool inline = false)
    {
        var href = ArtifactHref(artifact);
        if (string.IsNullOrWhiteSpace(href))
        {
            return inline
                ? "<span class=\"artifact-no-link\">Copy path only</span>"
                : "<span class=\"artifact-no-link\">Copy path only</span>";
        }

        return RenderSafeLinkActions(href, ArtifactDisplayName(artifact), inline);
    }

    /// <summary>
    /// Renders open/download buttons for one already-safe report-relative link.
    /// Inputs are href, download label, and display mode; processing re-checks
    /// link safety and emits no absolute filesystem href; returns HTML.
    /// </summary>
    private static string RenderSafeLinkActions(string href, string downloadName, bool inline = false)
    {
        if (!IsSafeReportRelativeHref(href))
        {
            return inline
                ? "<span class=\"artifact-no-link\">Copy path only</span>"
                : "<span class=\"artifact-no-link\">Copy path only</span>";
        }

        var css = inline ? " artifact-actions-inline" : string.Empty;
        var safeName = SafeDownloadFileName(downloadName);
        return $"<span class=\"artifact-actions{css}\"><a class=\"artifact-btn artifact-open\" href=\"{A(href)}\">Open</a><a class=\"artifact-btn download\" href=\"{A(href)}\" download=\"{A(safeName)}\">Download</a></span>";
    }

    /// <summary>
    /// Returns a report-relative artifact href, preferring a validated safeLink
    /// and falling back to a safe relative path. Inputs are one descriptor;
    /// processing rejects absolute paths, schemes, and traversal; returns an
    /// empty string when no safe local href exists.
    /// </summary>
    private static string ArtifactHref(ArtifactDescriptor artifact)
    {
        if (IsSafeReportRelativeHref(artifact.SafeLink))
        {
            return artifact.SafeLink;
        }

        var fallback = ArtifactDescriptorFactory.BuildSafeLink(artifact.RelativePath);
        return IsSafeReportRelativeHref(fallback) ? fallback : string.Empty;
    }

    /// <summary>
    /// Validates links before placing them in href/src attributes.
    /// Inputs are arbitrary descriptor links; processing rejects absolute
    /// filesystem paths, URL schemes, rooted paths, and decoded traversal; the
    /// method returns true only for report-local relative links.
    /// </summary>
    private static bool IsSafeReportRelativeHref(string? href)
    {
        if (string.IsNullOrWhiteSpace(href))
        {
            return false;
        }

        var trimmed = href.Trim();
        if (Uri.TryCreate(trimmed, UriKind.Absolute, out _))
        {
            return false;
        }

        var unified = trimmed.Replace('\\', '/');
        if (unified.StartsWith("/", StringComparison.Ordinal))
        {
            return false;
        }

        string decoded;
        try
        {
            decoded = Uri.UnescapeDataString(unified);
        }
        catch (UriFormatException)
        {
            return false;
        }

        if (decoded.StartsWith("/", StringComparison.Ordinal) ||
            decoded.Contains(':', StringComparison.Ordinal))
        {
            return false;
        }

        try
        {
            if (Path.IsPathFullyQualified(decoded))
            {
                return false;
            }
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }

        return !string.IsNullOrWhiteSpace(ArtifactDescriptorFactory.NormalizeRelativePath(decoded));
    }

    /// <summary>
    /// Builds a conservative download filename.
    /// Inputs are artifact display text; processing keeps only a file name
    /// segment when present; return is safe text for the download attribute.
    /// </summary>
    private static string SafeDownloadFileName(string displayName)
    {
        try
        {
            var normalized = displayName.Replace('\\', '/');
            var name = Path.GetFileName(normalized);
            return string.IsNullOrWhiteSpace(name) ? "artifact" : name;
        }
        catch (ArgumentException)
        {
            return "artifact";
        }
    }

    /// <summary>
    /// Renders a long technical field as a collapsed block.
    /// Inputs are a label and value; processing keeps command/output text out
    /// of the main table flow while preserving copyable detail; returns HTML.
    /// </summary>
    private static string RenderTechnicalField(string label, string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        return $"<details class=\"technical-field\"><summary>{E(label)} hidden by default ({E(value.Length.ToString())} chars)</summary><pre class=\"copyable\" data-copy=\"{A(value)}\">{E(value)}</pre></details>";
    }

    /// <summary>
    /// Renders event data with long command/stdout/stderr/PowerShell payloads
    /// hidden in nested details. Inputs are one event; processing keeps compact
    /// keys visible and technical payloads closed by default; returns HTML.
    /// </summary>
    private static string RenderEventEvidenceDetails(SandboxEvent evt)
    {
        var compactFields = evt.Data
            .Where(pair => !IsLongTechnicalEventField(pair.Key, pair.Value))
            .OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase)
            .ToList();
        var technicalFields = evt.Data
            .Where(pair => IsLongTechnicalEventField(pair.Key, pair.Value))
            .OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase)
            .Select(pair => (Label: pair.Key, Value: pair.Value))
            .ToList();

        if (!string.IsNullOrWhiteSpace(evt.CommandLine))
        {
            technicalFields.Insert(0, ("commandLine", evt.CommandLine!));
        }

        var html = new StringBuilder();
        html.Append($"<details class=\"event-evidence-fields\" data-copy=\"{A(EventToBoundedPlainText(evt, maxDataPairs: 40, maxValueLength: 300))}\"><summary>Evidence fields ({compactFields.Count} compact / {technicalFields.Count} folded technical)</summary>");
        if (compactFields.Count == 0 && technicalFields.Count == 0)
        {
            html.Append("<pre>-</pre>");
        }
        else
        {
            if (compactFields.Count > 0)
            {
                var inlineCompactFields = compactFields
                    .Take(EventCompactFieldInlineLimit)
                    .ToList();
                var hiddenCompactFields = Math.Max(0, compactFields.Count - inlineCompactFields.Count);

                html.Append("<ul class=\"raw-field-list\">");
                foreach (var pair in inlineCompactFields)
                {
                    var copy = $"{pair.Key}={pair.Value}";
                    var displayValue = FormatBoundedEvidenceFieldValue(pair.Key, pair.Value, EventCompactFieldValueLimit);
                    html.Append($"<li><code class=\"copyable\" data-copy=\"{A(copy)}\">{E(pair.Key)}={E(displayValue)}</code></li>");
                }

                if (hiddenCompactFields > 0)
                {
                    html.Append($"<li><span class=\"muted\">... {E(hiddenCompactFields.ToString())} additional fields hidden; open report.json/events.json for the full record.</span></li>");
                }

                html.Append("</ul>");
            }

            if (technicalFields.Count > 0)
            {
                html.Append($"<details class=\"raw-technical-fields\"><summary>Command/stdout/stderr/PowerShell fields hidden by default ({technicalFields.Count})</summary>");
                foreach (var field in technicalFields)
                {
                    var boundedValue = FormatBoundedEvidenceFieldValue(field.Label, field.Value, 1_200);
                    var copy = $"{field.Label}={boundedValue}";
                    html.Append($"<details class=\"raw-technical-field\"><summary>Hidden technical field: {E(field.Label)} ({E(field.Value.Length.ToString())} chars)</summary><pre class=\"copyable\" data-copy=\"{A(copy)}\">{E(copy)}</pre></details>");
                }

                html.Append("</details>");
            }
        }

        html.Append("</details>");
        return html.ToString();
    }

    /// <summary>
    /// Classifies raw event fields that should not be expanded inline.
    /// Inputs are one key/value pair; processing matches command/output/script
    /// field names plus long PowerShell payloads; returns true when nested
    /// collapse is required.
    /// </summary>
    private static bool IsLongTechnicalEventField(string key, string value)
    {
        var normalizedKey = key.Replace("_", string.Empty, StringComparison.Ordinal)
            .Replace("-", string.Empty, StringComparison.Ordinal)
            .Replace(".", string.Empty, StringComparison.Ordinal);
        return normalizedKey.Contains("command", StringComparison.OrdinalIgnoreCase) ||
            normalizedKey.Contains("cmdline", StringComparison.OrdinalIgnoreCase) ||
            normalizedKey.Contains("stdout", StringComparison.OrdinalIgnoreCase) ||
            normalizedKey.Contains("stderr", StringComparison.OrdinalIgnoreCase) ||
            normalizedKey.Contains("powershell", StringComparison.OrdinalIgnoreCase) ||
            normalizedKey.Contains("scriptblock", StringComparison.OrdinalIgnoreCase) ||
            normalizedKey.Contains("encodedcommand", StringComparison.OrdinalIgnoreCase) ||
            IsBulkyEvidenceFieldKey(key) ||
            (value.Length > 80 && value.Contains("powershell", StringComparison.OrdinalIgnoreCase)) ||
            value.Length > 500;
    }

    private static bool IsBulkyEvidenceFieldKey(string key)
    {
        var normalizedKey = key.Replace("_", string.Empty, StringComparison.Ordinal)
            .Replace("-", string.Empty, StringComparison.Ordinal)
            .Replace(".", string.Empty, StringComparison.Ordinal);
        return string.Equals(key, "tags", StringComparison.OrdinalIgnoreCase) ||
            normalizedKey.Contains("interestingstrings", StringComparison.OrdinalIgnoreCase) ||
            normalizedKey.Contains("imports", StringComparison.OrdinalIgnoreCase) ||
            normalizedKey.Contains("exports", StringComparison.OrdinalIgnoreCase) ||
            normalizedKey.Contains("sections", StringComparison.OrdinalIgnoreCase) ||
            normalizedKey.Contains("resources", StringComparison.OrdinalIgnoreCase) ||
            normalizedKey.Contains("warnings", StringComparison.OrdinalIgnoreCase) ||
            normalizedKey.Contains("urls", StringComparison.OrdinalIgnoreCase) ||
            normalizedKey.Contains("strings", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Localizes the static report shell to Simplified Chinese.
    /// Inputs are renderer-owned English HTML; processing replaces only known
    /// report chrome strings and language metadata; the method returns the
    /// localized document while leaving normalized telemetry values intact.
    /// </summary>
    private static string LocalizeChineseHtml(string html, AnalysisReport report)
    {
        var protectedFragments = new List<string>();
        html = ProtectChineseRawEvidenceFragments(html, protectedFragments);

        foreach (var (english, chinese) in ChineseHtmlTranslations
            .Concat(GetReportFindingHtmlTranslations(report))
            .Concat(ChineseRuleHtmlTranslations)
            .OrderByDescending(pair => pair.English.Length))
        {
            html = html.Replace(english, chinese, StringComparison.Ordinal);
        }

        html = ChineseVisibleEventCountRegex.Replace(html, " 个事件");
        html = RestoreChineseRawEvidenceFragments(html, protectedFragments);
        foreach (var (english, chinese) in ChineseCssTranslations)
        {
            html = html.Replace(english, chinese, StringComparison.Ordinal);
        }

        return html;
    }

    private static IEnumerable<(string English, string Chinese)> GetReportFindingHtmlTranslations(AnalysisReport report)
    {
        foreach (var finding in report.Findings)
        {
            if (!string.IsNullOrWhiteSpace(finding.TitleZh))
            {
                yield return (E(finding.Title), E(finding.TitleZh));
            }

            if (!string.IsNullOrWhiteSpace(finding.SummaryZh))
            {
                yield return (E(finding.Summary), E(finding.SummaryZh));
            }
        }
    }

    private static string ProtectChineseRawEvidenceFragments(string html, List<string> protectedFragments)
    {
        return ChineseRawEvidenceFragmentRegex.Replace(
            html,
            match =>
            {
                var token = $"__KSWORD_RAW_FRAGMENT_{protectedFragments.Count}__";
                protectedFragments.Add(match.Value);
                return token;
            });
    }

    private static string RestoreChineseRawEvidenceFragments(string html, IReadOnlyList<string> protectedFragments)
    {
        for (var index = 0; index < protectedFragments.Count; index++)
        {
            html = html.Replace($"__KSWORD_RAW_FRAGMENT_{index}__", protectedFragments[index], StringComparison.Ordinal);
        }

        return html;
    }

    private static readonly IReadOnlyList<(string English, string Chinese)> ChineseCssTranslations =
    [
        ("content:'Step ' counter(report-section)", "content:'步骤 ' counter(report-section)"),
        (" (folded in screen view; expand in browser for full evidence)", "（屏幕视图中折叠；在浏览器中展开查看完整证据）")
    ];

    private static readonly IReadOnlyList<(string English, string Chinese)> ChineseHtmlTranslations =
    [
        ("<html lang=\"en\">", "<html lang=\"zh-CN\">"),
        ("<title>KSword Sandbox Report</title>", "<title>KSword 沙箱分析报告</title>"),
        ("KSword Sandbox Report", "KSword 沙箱分析报告"),
        ("content:'Step ' counter(report-section)", "content:'步骤 ' counter(report-section)"),
        ("<p class=\"muted\">Job ", "<p class=\"muted\">作业 "),
        (" generated at ", " 生成于 "),
        ("Analysis failed", "分析失败"),
        ("No high-risk behavior", "未发现高风险行为"),
        ("Critical risk", "严重风险"),
        ("High risk", "高风险"),
        ("Suspicious", "可疑行为"),
        (">Queued<", ">已排队<"),
        (">Planning<", ">规划中<"),
        (">Planned<", ">已规划<"),
        (">Running<", ">运行中<"),
        (">Completed<", ">已完成<"),
        (">Failed<", ">失败<"),
        (">high<", ">高<"),
        (">critical<", ">严重<"),
        (">medium<", ">中<"),
        (">low<", ">低<"),
        (">info<", ">信息<"),
        ("critical:", "严重："),
        ("high:", "高："),
        ("medium:", "中："),
        ("low:", "低："),
        ("info:", "信息："),
        ("Table of contents", "目录"),
        ("Cover", "封面"),
        ("Report language", "报告语言"),
        ("English report", "英文报告"),
        ("Default report", "默认报告"),
        ("Default report.html uses Simplified Chinese; report.en.html keeps English operator chrome. Evidence values stay original in both reports. The WebUI also serves these through /api/jobs/{jobId}/report/html?lang=zh and ?lang=en.", "默认 report.html 使用简体中文；report.en.html 保留英文操作界面。两份报告中的证据值保持原文。WebUI 也通过 /api/jobs/{jobId}/report/html?lang=zh 和 ?lang=en 提供这些报告。"),
        ("The WebUI also serves these through /api/jobs/{jobId}/report/html?lang=zh and ?lang=en.", "WebUI 也通过 /api/jobs/{jobId}/report/html?lang=zh 和 ?lang=en 提供这些报告。"),
        ("Print/no-JS fallback", "打印 / 无 JS 兜底"),
        ("No JavaScript required for report navigation: native details, table scrolling, safe Open/Download artifact links, and the print stylesheet remain usable. Copy buttons require JavaScript; without it, select visible evidence text or use report.json/raw source hints.", "报告导航不依赖 JavaScript：原生 details、表格滚动、安全打开/下载证据链接和打印样式仍可使用。复制按钮需要 JavaScript；无 JS 时请选中可见证据文本，或使用 report.json/原始来源提示。"),
        (" (folded in screen view; expand in browser for full evidence)", "（屏幕视图中折叠；在浏览器中展开查看完整证据）"),
        ("Quick navigation", "快速导航"),
        ("Report navigation", "报告导航"),
        (">Sections<", ">章节<"),
        ("Sticky subnav", "固定子导航"),
        ("Sticky subnav for Process / Files / Network / R0 / VT / Artifacts quick navigation; counts show currently embedded representative evidence. R0 health, collector self-noise, and VT status rows are counted in their own lanes rather than primary behavior.", "固定子导航用于快速跳转进程 / 文件 / 网络 / R0 / VT / 证据文件；计数表示当前内联的代表性证据。R0 健康、采集器自噪声和 VT 状态行会计入各自通道，而不是主要行为。"),
        ("Sticky subnav for Process / Files / Network / R0 / VT / Artifacts quick navigation; counts show currently embedded representative evidence.", "固定子导航用于快速跳转进程 / 文件 / 网络 / R0 / VT / 证据文件；计数表示当前内联的代表性证据。"),
        ("Security / privilege telemetry", "安全 / 权限遥测"),
        ("Security / privilege", "安全 / 权限"),
        ("Security and privilege telemetry.", "安全与权限遥测。"),
        ("Windows Security/ETW privilege rows and process-access style rows are shown as supporting evidence for sensitive access, token, privilege, or handle activity. This section does not label a row malicious by itself; correlate requested rights, target process/object, rule hits, and self-noise markers before drawing conclusions.", "Windows Security/ETW 权限行和进程访问样式行会作为敏感访问、令牌、权限或句柄活动的辅助证据展示。本节不会单独将某一行标记为恶意；请结合请求权限、目标进程/对象、规则命中和自噪声标记再下结论。"),
        ("Security/privilege rows", "安全/权限行"),
        ("Security/ETW rows:", "Security/ETW 行："),
        ("process-access style rows:", "进程访问样式行："),
        ("privilege rows:", "权限行："),
        ("Targets summarized", "已汇总目标"),
        ("No target process/object fields were available.", "未提供目标进程/对象字段。"),
        ("Privilege names", "权限名称"),
        ("No privilege-name field was available.", "未提供权限名称字段。"),
        ("Rows marked collector/self-noise, nonbehavior, or collection health remain outside this table and stay available in Raw normalized events/report.json.", "标记为采集器/自噪声、非行为或采集健康的行不会进入此表，但仍保留在原始规范化事件/report.json 中。"),
        ("Copy security/privilege telemetry summary", "复制安全/权限遥测摘要"),
        ("No Windows Security, ETW privilege, or process-access telemetry rows were imported as sample behavior.", "未将 Windows Security、ETW 权限或进程访问遥测行作为样本行为导入。"),
        ("security/privilege", "安全/权限"),
        ("R0 health", "R0 健康状态"),
        ("R0 health/readiness", "R0 健康/就绪"),
        ("R0 sample/health", "R0 样本/健康"),
        ("R0 sample telemetry", "R0 样本遥测"),
        ("Critical / high risk", "严重/高风险"),
        ("VT lookups", "VT 查询"),
        ("Risk summary", "风险摘要"),
        ("Behavior detections", "行为命中"),
        ("Collection/self-noise policy", "采集/自噪声策略"),
        ("Collection/self-noise policy.", "采集/自噪声策略。"),
        ("Behavior story counts exclude rows marked <code>behaviorCounted=false</code>, <code>nonbehavior</code>, <code>notSampleBehavior</code>, collector self-noise, VT quiet states, and R0 health/readiness diagnostics. These rows remain visible in their dedicated sections and in Raw normalized events/report.json; raw pagination and folded evidence are unchanged.", "行为叙事计数会排除标记为 <code>behaviorCounted=false</code>、<code>nonbehavior</code>、<code>notSampleBehavior</code>、采集器自噪声、VT 安静状态以及 R0 健康/就绪诊断的行。这些行仍会在各自专用章节和原始规范化事件/report.json 中可见；原始分页和折叠证据保持不变。"),
        ("Behavior story counts exclude rows marked <code>behaviorCounted=false</code>, <code>nonbehavior</code>, collector self-noise, VT quiet states, and R0 health/readiness diagnostics. These rows remain visible in their dedicated sections and in Raw normalized events/report.json; raw pagination and folded evidence are unchanged.", "行为叙事计数会排除标记为 <code>behaviorCounted=false</code>、<code>nonbehavior</code>、采集器自噪声、VT 安静状态以及 R0 健康/就绪诊断的行。这些行仍会在各自专用章节和原始规范化事件/report.json 中可见；原始分页和折叠证据保持不变。"),
        ("Copy collection policy", "复制采集策略"),
        ("sample behavior", "样本行为"),
        ("excluded union", "排除并集"),
        ("behaviorCounted=false", "behaviorCounted=false"),
        ("nonbehavior", "nonbehavior"),
        ("notSampleBehavior", "notSampleBehavior"),
        ("collectorSelfNoise", "collectorSelfNoise"),
        ("VT quiet", "VT 安静"),
        ("R0 health", "R0 健康"),
        ("Static triage", "静态分诊"),
        ("Collection diagnostics", "采集诊断"),
        ("Collection health", "采集健康状态"),
        (">Events<", ">事件<"),
        ("No primary sample behavior rules matched. Static triage and collection diagnostics are separated below so operational health does not inflate the verdict.", "未命中主要样本行为规则。静态分诊和采集诊断已在下方分离展示，避免运行健康状态抬高判定。"),
        ("Static triage indicators", "静态分诊指标"),
        ("Static-only findings are useful triage signals, but they do not by themselves prove runtime malicious behavior.", "仅静态发现可作为有用分诊信号，但本身不能证明运行时恶意行为。"),
        ("Collection and pipeline diagnostics", "采集与流水线诊断"),
        ("Collector health, runbook, import, and timing diagnostics explain evidence quality and are not sample behavior.", "采集器健康、运行手册、导入和时序诊断用于说明证据质量，不属于样本行为。"),
        ("Copy behavior evidence", "复制行为证据"),
        ("Expand evidence card details", "展开证据卡详情"),
        ("Expand edge evidence", "展开边证据"),
        ("Expand artifact evidence", "展开证据文件详情"),
        ("Expand collection evidence", "展开采集证据"),
        ("Expand top process evidence", "展开关键进程证据"),
        ("Expand top network evidence", "展开关键网络证据"),
        ("Top evidence summary", "关键证据摘要"),
        ("KSword behavior rules", "KSword 行为规则"),
        ("None.", "无。"),
        ("Multi-dimensional / MITRE detections", "多维 / MITRE 检测"),
        ("Multi-dimensional / MITRE", "多维 / MITRE"),
        ("Engine and rule hits", "引擎和规则命中"),
        ("Static analysis", "静态分析"),
        ("Static rule tags", "静态规则标签"),
        ("Static list capped for readability.", "静态列表已为可读性限制数量。"),
        ("Inline entries:", "内联条目："),
        ("Hidden entries:", "隐藏条目："),
        ("Open report.json for complete static evidence.", "打开 report.json 查看完整静态证据。"),
        ("No static tags were emitted.", "未输出静态标签。"),
        ("No interesting strings recorded.", "未记录可疑字符串。"),
        ("No static warnings recorded.", "未记录静态警告。"),
        ("Static PE resource story", "静态 PE 资源故事"),
        ("Resource payload triage.", "资源载荷分诊。"),
        ("Structured <code>static.pe.resource</code> evidence highlights resourceRole, embedded-PE markers, entropy, and size so payload candidates are visible before opening raw static events.", "结构化 <code>static.pe.resource</code> 证据会突出 resourceRole、内嵌 PE 标记、熵值和大小，让候选载荷在打开原始静态事件前可见。"),
        ("Resource entries", "资源条目"),
        ("High-entropy resources", "高熵资源"),
        ("Resource events", "资源事件"),
        ("Embedded PE:", "内嵌 PE："),
        ("payload candidates:", "候选载荷："),
        ("High entropy can indicate compressed/encrypted payload bytes; correlate with dropped files and runtime execution.", "高熵可能表示压缩/加密载荷字节；请与落地文件和运行时执行交叉验证。"),
        ("Normalized static.pe.resource rows are preserved for behavior rules and raw evidence expansion.", "规范化 static.pe.resource 行会保留给行为规则和原始证据展开。"),
        ("No structured PE resource entries or static.pe.resource events were recorded.", "未记录结构化 PE 资源条目或 static.pe.resource 事件。"),
        ("static.pe.resource normalized evidence", "static.pe.resource 规范化证据"),
        ("Resource payload triage", "资源载荷分诊"),
        ("embedded PE", "内嵌 PE"),
        ("payload candidate", "候选载荷"),
        ("large-resource", "大型资源"),
        ("metadata-resource", "元数据资源"),
        ("very-high-entropy-resource", "极高熵资源"),
        ("high-entropy-resource", "高熵资源"),
        ("Dynamic analysis", "动态分析"),
        ("No dynamic events were collected. Zero counters mean telemetry was not collected or imported for this section; they are not proof that the sample had no behavior.", "未采集到动态事件。本节的 0 计数表示遥测未采集或未导入，不代表样本没有行为。"),
        ("VirusTotal / reputation", "VirusTotal / 信誉"),
        ("Hash-only enrichment.", "仅哈希增强。"),
        ("VirusTotal (VT) results are optional reputation evidence and are separated from sandbox behavior. Missing keys, rate limits, or not-found responses are enrichment status, not malicious sample behavior.", "VirusTotal (VT) 结果是可选信誉证据，已与沙箱行为分离。缺少密钥、限速或未找到响应属于增强状态，不是恶意样本行为。"),
        ("VT malicious", "VT 恶意"),
        ("VT suspicious", "VT 可疑"),
        ("VT status issues", "VT 状态问题"),
        ("VT rule hits", "VT 规则命中"),
        ("VirusTotal rule hits", "VirusTotal 规则命中"),
        ("External reputation rules are shown here so VT quality does not get mixed into local behavior evidence.", "外部信誉规则在此单独展示，避免 VT 质量状态混入本地行为证据。"),
        ("No VirusTotal enrichment events were recorded. VT is optional, hash-only, and does not upload samples.", "未记录 VirusTotal 增强事件。VT 为可选哈希查询，不上传样本。"),
        ("VirusTotal official evidence", "VirusTotal 官方证据"),
        ("Official file-object fields.", "官方文件对象字段。"),
        ("Engine stats, reputation/community score, last analysis date, and permalink are displayed as external hash reputation only; VT never uploads the sample from this report path.", "引擎统计、信誉/社区分数、最近分析时间和永久链接仅作为外部哈希信誉展示；VT 不会从此报告路径上传样本。"),
        ("VT verdict", "VT 判定"),
        ("VT reputation/community", "VT 信誉/社区"),
        ("VT permalink", "VT 永久链接"),
        ("Copy-only external VirusTotal GUI/API link; use it for analyst pivoting outside the local report.", "仅复制的外部 VirusTotal GUI/API 链接；用于在本地报告外进行分析跳转。"),
        ("Copy VirusTotal official evidence", "复制 VirusTotal 官方证据"),
        ("Behavior graph / IOC summary", "行为图谱 / IOC 摘要"),
        ("Narrative spine", "叙事主线"),
        ("Narrative spine summary", "叙事主线摘要"),
        ("Compact evidence narrative.", "紧凑证据叙事。"),
        ("Read left to right: process tree root, behavior graph edges, network endpoint scope, and collected artifact proof. Each step stays bounded and copyable so the report explains the evidence before dense tables or raw rows.", "从左到右阅读：进程树根、行为图谱边、网络端点范围和已采集证据文件。每一步都保持有界且可复制，让报告先解释证据，再进入密集表格或原始行。"),
        ("Execution → storage → network → artifact proof, with copyable bounded evidence and no raw event wall.", "执行 → 存储 → 网络 → 证据文件证明；证据有界且可复制，不形成原始事件墙。"),
        ("Execution root", "执行根节点"),
        ("Storage changes", "存储变更"),
        ("Network scope", "网络范围"),
        ("Artifact proof", "证据文件证明"),
        ("Copy narrative spine", "复制叙事主线"),
        ("Copy narrative step", "复制叙事步骤"),
        ("Root candidate:", "根候选："),
        ("Spawn edges:", "启动边："),
        ("Highest behavior finding:", "最高行为命中："),
        ("Storage signal:", "存储信号："),
        ("file IOC(s)", "文件 IOC"),
        ("registry IOC(s)", "注册表 IOC"),
        ("graph edges file/registry", "图谱文件/注册表边"),
        ("Network scope:", "网络范围："),
        ("graph edges:", "图谱边："),
        ("Artifact proof:", "证据文件证明："),
        ("graph edge(s)", "图谱边"),
        ("Top process:", "主要进程："),
        ("spawn edges:", "启动边："),
        ("highest finding:", "最高命中："),
        ("File IOCs:", "文件 IOC："),
        ("registry IOCs:", "注册表 IOC："),
        ("graph edges file/registry:", "图谱文件/注册表边："),
        ("No endpoint IOC extracted; network graph edges:", "未提取端点 IOC；网络图谱边："),
        ("network graph edges:", "网络图谱边："),
        ("Artifact edges:", "证据文件边："),
        ("indexed evidence types:", "已索引证据类型："),
        ("No behavior finding", "无行为命中"),
        ("Evidence story board", "证据故事板"),
        ("Evidence health narrative", "证据健康叙事"),
        ("R0 / VT / Artifact health narrative.", "R0 / VT / 证据文件健康叙事。"),
        ("R0 / VT / Artifact health narrative", "R0 / VT / 证据文件健康叙事"),
        ("Copy health narrative", "复制健康叙事"),
        ("Network relation path", "网络关系路径"),
        ("DNS/HTTP/TLS/flow", "DNS/HTTP/TLS/流"),
        ("Evidence story.", "证据故事。"),
        ("Evidence story lanes.", "证据故事通道。"),
        ("These stable weak-interaction lanes keep the analyst narrative visible before dense tables: process lineage, released files, screenshots, memory dumps, PCAP/network, and R0 collection quality. Each lane shows a short explanation, metric chips, and a bounded native-details evidence sample; complete rows stay in Raw normalized events/report.json and Artifact links.", "这些稳定的弱交互通道会在密集表格前保留分析叙事：进程链路、释放文件、截图、内存转储、PCAP/网络以及 R0 采集质量。每个通道都会显示简短说明、指标标签和有界的原生 details 证据样例；完整行保留在原始事件/report.json 和证据文件链接中。"),
        ("These weak-interaction lanes keep the analyst narrative visible before dense tables: process lineage, released files, screenshots, memory dumps, PCAP/network, and R0 collection quality. Expand a lane for bounded copyable evidence; complete rows stay in Raw normalized events/report.json.", "这些弱交互通道会在密集表格前保留分析叙事：进程链路、释放文件、截图、内存转储、PCAP/网络以及 R0 采集质量。展开通道可查看有界且可复制的证据；完整行保留在原始事件/report.json 中。"),
        ("Execution lineage", "执行链路"),
        ("Process tree rows are shown as the first story lane so parent/child execution is understandable before opening raw telemetry.", "进程树行作为第一条故事通道展示，让父子进程执行关系在打开原始遥测前即可理解。"),
        ("Dropped-file evidence", "落地文件证据"),
        ("Released or modified files are surfaced as artifact-first evidence with hashes and safe relative paths when available.", "释放或修改的文件以证据文件优先方式展示；可用时显示哈希和安全相对路径。"),
        ("Screenshot evidence", "截图证据"),
        ("Screenshot capture is kept visible as visual evidence; previews remain collapsible and safe links are handled in Artifact links.", "截图采集作为可视证据保持可见；预览保持可折叠，安全链接由证据文件链接章节处理。"),
        ("Memory dump evidence", "内存转储证据"),
        ("Opt-in root and child-process memory dumps are summarized separately so large dump artifacts do not disappear inside raw rows.", "按需启用的根进程和子进程内存转储会单独汇总，避免大型 dump 证据淹没在原始行里。"),
        ("Network and PCAP evidence", "网络与 PCAP 证据"),
        ("DNS/HTTP/TLS/flow telemetry and packet-capture artifacts share one story lane before endpoint cards and raw packet rows.", "DNS/HTTP/TLS/流量遥测和抓包证据会在端点卡与原始包行之前共用一条故事通道。"),
        ("R0 health/noise boundary", "R0 健康/噪声边界"),
        ("R0 availability, queue loss, and collector self-noise are called out as evidence-quality context, not sample behavior.", "R0 可用性、队列丢失和采集器自噪声会作为证据质量上下文呈现，而不是样本行为。"),
        ("Copy story lane", "复制故事通道"),
        ("Expand story evidence", "展开故事证据"),
        ("Expand bounded story evidence", "展开有界故事证据"),
        ("Story evidence expansion summary", "故事证据展开摘要"),
        ("Process evidence expansion summary", "进程证据展开摘要"),
        ("Network evidence expansion summary", "网络证据展开摘要"),
        ("Copy evidence expansion summary", "复制证据展开摘要"),
        ("complete source:", "完整来源："),
        ("First evidence:", "首条证据："),
        ("Evidence examples shown:", "已显示证据示例："),
        ("observed; lane includes guidance only.", "条已观察；此通道仅包含指引。"),
        ("observed; expand stays bounded and full source remains in Raw normalized events/report.json.", "条已观察；展开内容保持有界，完整来源保留在原始事件/report.json 中。"),
        (" observed rows)", " 条已观察行)"),
        ("No inline evidence observed in this lane; check Raw normalized events/report.json and Artifact links for complete source data.", "此通道未观察到内联证据；请查看原始事件/report.json 和证据文件链接以获取完整源数据。"),
        ("Process candidates:", "候选进程："),
        ("Child/parent hints:", "父子线索："),
        ("Graph nodes:", "图谱节点："),
        ("Collector/health excluded:", "已排除采集器/健康行："),
        ("Dropped artifacts:", "落地证据文件："),
        ("Dropped-file events:", "落地文件事件："),
        ("File rows:", "文件行："),
        ("Unique file targets:", "唯一文件目标："),
        ("Screenshot artifacts:", "截图证据文件："),
        ("Screenshot events:", "截图事件："),
        ("Captured bytes:", "采集字节："),
        ("Latest capture:", "最新采集："),
        ("Memory dump artifacts:", "内存转储证据文件："),
        ("Memory dump events:", "内存转储事件："),
        ("Child dump enabled rows:", "启用子进程 dump 行："),
        ("Network rows:", "网络行："),
        ("Packet artifacts:", "抓包证据文件："),
        ("Packet capture events:", "抓包事件："),
        ("DNS/HTTP/TLS/flow:", "DNS/HTTP/TLS/流："),
        ("R0 health rows:", "R0 健康行："),
        ("R0 telemetry rows:", "R0 遥测行："),
        ("Self-noise hidden:", "已隐藏自噪声："),
        ("R0 self-noise events hidden from behavior graph:", "已从行为图谱隐藏的 R0 自噪声事件："),

        ("Health alerts:", "健康告警："),
        ("no health rows", "无健康行"),
        ("unavailable/degraded", "不可用/降级"),
        ("attention needed", "需要关注"),
        ("available", "可用"),
        ("Stable relationship lanes", "稳定关系通道"),
        ("Stable relationship lanes.", "稳定关系通道。"),
        ("Weak-interaction lane map for process lineage, file paths, registry paths, network paths, and artifact proof. Counts and representative paths are visible before the dense edge table; complete edge evidence remains bounded below.", "用于进程链路、文件路径、注册表路径、网络路径和证据文件证明的弱交互通道图。计数和代表路径会先于密集边表可见；完整边证据仍在下方保持有界。"),
        ("Process lineage lane", "进程链路通道"),
        ("File path lane", "文件路径通道"),
        ("Registry path lane", "注册表路径通道"),
        ("Network path lane", "网络路径通道"),
        ("Artifact proof lane", "证据文件证明通道"),
        ("Process-to-process execution relationships from stable process keys and PID/PPID fallback.", "来自稳定进程键和 PID/PPID 回退的进程到进程执行关系。"),
        ("Process-to-file writes, drops, reads, and path indicators.", "进程到文件写入、落地、读取和路径指标。"),
        ("Process-to-registry key/value relationships.", "进程到注册表键/值关系。"),
        ("Process-to-endpoint DNS/HTTP/TLS/flow relationships.", "进程到端点的 DNS/HTTP/TLS/流量关系。"),
        ("Process-to-artifact proof such as screenshots, dropped files, memory dumps, and PCAP.", "进程到证据文件证明，例如截图、落地文件、内存转储和 PCAP。"),
        ("Stable relationship lane copy map", "稳定关系通道复制图"),
        ("Copy stable relationship lanes", "复制稳定关系通道"),
        ("representativePaths:", "代表路径："),
        ("Behavior story routing", "行为故事路由"),
        ("Behavior story routing.", "行为故事路由。"),
        ("Sample behavior route", "样本行为路由"),
        ("Excluded evidence route", "已排除证据路由"),
        ("Top excluded reasons", "主要排除原因"),
        ("Copy behavior routing", "复制行为路由"),
        ("Behavior routing evidence examples", "行为路由证据示例"),
        ("Evidence lane health", "证据通道健康状态"),
        ("Artifact lane health:", "证据文件通道健康："),
        ("Process relation path", "进程关系路径"),
        ("Process relation path:", "进程关系路径："),
        ("Artifact links", "证据文件链接"),
        ("Artifact evidence cards.", "证据文件证据卡。"),
        ("Evidence lane health for dropped files, screenshots, memory dumps, packet captures, and driver events is summarized before the dense artifact table. Collection status, safe download selectors, duplicate grouping, and rejection diagnostics stay visible; safe report-relative links can open or download, while absolute host/guest paths remain copy-only evidence.", "落地文件、截图、内存转储、抓包和驱动事件的证据通道健康状态会先于密集证据文件表汇总。采集状态、安全下载选择器、重复分组和拒绝诊断保持可见；安全的报告相对链接可以打开或下载，主机/guest 绝对路径保持为仅复制证据。"),
        ("Artifact collection status", "证据采集状态"),
        ("Artifact evidence matrix narrative", "证据文件矩阵叙事"),
        ("Artifact evidence matrix narrative.", "证据文件矩阵叙事。"),
        ("Matrix lanes summarize dropped files, screenshots, memory dumps, and packet captures before the artifact table. Counts come from normalized <code>artifactEvidenceMatrix</code> rows when present and fall back to the artifact index, so missing lanes stay explicit without expanding raw rows.", "矩阵通道会在证据文件表之前汇总落地文件、截图、内存转储和抓包。计数优先来自规范化 <code>artifactEvidenceMatrix</code> 行；缺失时回退到证据文件索引，因此缺失通道会保持显式可见，而不是展开原始行假填充。"),
        ("Matrix lanes", "矩阵通道"),
        ("Artifact references", "证据文件引用"),
        ("Selector coverage", "选择器覆盖"),
        ("Ready lanes:", "就绪通道："),
        ("bounded lane cards summarize collection state before dense artifacts.", "有界通道卡会在密集证据文件表前汇总采集状态。"),
        ("Total bytes represented by matrix lanes:", "矩阵通道代表的总字节数："),
        ("Rows with selectors can be copied directly; safe Open/Download actions remain in the artifact table.", "带选择器的行可直接复制；安全打开/下载操作仍保留在证据文件表中。"),
        ("Copy artifact matrix narrative", "复制证据文件矩阵叙事"),
        ("Artifact evidence matrix narrative rows", "证据文件矩阵叙事行"),
        ("Artifact matrix expansion summary", "证据文件矩阵展开摘要"),
        ("Artifact index evidence", "证据文件索引证据"),
        ("Host artifact index.", "主机证据文件索引。"),
        ("Download buttons use safe report-relative selectors only; duplicate grouping and rejection diagnostics explain why guest manifest references were accepted, deduplicated, or rejected.", "下载按钮只使用安全的报告相对选择器；重复分组和拒绝诊断说明 guest manifest 引用为何被接受、去重或拒绝。"),
        ("Safe download selectors", "安全下载选择器"),
        ("Duplicate artifact groups", "重复证据文件组"),
        ("Rejected artifact references", "已拒绝证据文件引用"),
        ("Artifacts with explicit selector evidence:", "带显式选择器证据的证据文件："),
        ("Unsafe or guest-local paths remain copy-only.", "不安全或 guest 本地路径保持仅复制。"),
        ("Duplicate members:", "重复成员："),
        ("primary selectors are preserved in each artifact evidence block.", "主选择器会保留在每个证据文件证据块中。"),
        ("No host-side manifest rejection diagnostics are attached to indexed artifacts.", "索引证据文件未附带主机侧 manifest 拒绝诊断。"),
        ("Collections with rejection diagnostics:", "带拒绝诊断的采集集合："),
        ("Artifact index selector/duplicate/rejection evidence", "证据文件索引选择器/重复/拒绝证据"),
        ("Collection evidence", "采集证据"),
        ("Copied files released or modified by the sample when collection was enabled.", "启用采集时，样本释放或修改并被复制的文件。"),
        ("Desktop screenshots captured around sample execution when enabled.", "启用时在样本执行前后捕获的桌面截图。"),
        ("Opt-in process and child-process memory dump artifacts.", "按需启用的进程及子进程内存转储证据。"),
        ("Opt-in pktmon/PCAP artifacts and imported DNS/HTTP/TLS/flow rows.", "按需启用的 pktmon/PCAP 证据及导入的 DNS/HTTP/TLS/流量行。"),
        ("R0Collector JSONL and driver-originated telemetry.", "R0Collector JSONL 与驱动来源遥测。"),
        ("Latest diagnostic:", "最新诊断："),
        ("Phases:", "阶段："),
        (">captured<", ">已采集<"),
        (">failed<", ">失败<"),
        (">disabled<", ">已禁用<"),
        (">skipped<", ">已跳过<"),
        (">partial<", ">部分采集<"),
        (">observed<", ">已观察<"),
        (">not observed<", ">未观察<"),
        ("Dropped files", "落地文件"),
        ("File system activity", "文件系统活动"),
        ("Screenshots", "截图"),
        ("Memory dumps", "内存转储"),
        ("Packet captures", "网络抓包"),
        ("Driver events", "驱动事件"),
        ("Artifacts:", "证据文件："),
        ("Timeline", "时间线"),
        ("Process details", "进程详情"),
        ("Dropped files", "落地文件"),
        ("File system activity", "文件系统活动"),
        ("Registry behavior", "注册表行为"),
        ("Network behavior", "网络行为"),
        ("R0 / driver events", "R0 / 驱动事件"),
        ("Collection health rows", "采集健康行"),
        ("Driver telemetry rows", "驱动遥测行"),
        ("Health alerts", "健康告警"),
        ("Collection health status", "采集健康状态"),
        ("Collection health status.", "采集健康状态。"),
        ("R0 unavailable, driver health, queue backpressure, and dropped-event counters describe collection quality and are not malicious sample behavior.", "R0 不可用、驱动健康、队列背压和丢弃事件计数描述采集质量，不是恶意样本行为。"),
        ("Health/status rows", "健康/状态行"),
        ("Device unavailable", "设备不可用"),
        ("Backpressure/drop", "背压/丢弃"),
        ("Driver health polls", "驱动健康轮询"),
        ("Driver telemetry evidence", "驱动遥测证据"),
        ("R0 noise policy.", "R0 降噪策略。"),
        ("Collection health, device unavailable, and collector self-noise rows are evidence-quality lanes. They stay out of behavior counts, process trees, network cards, and file/registry/network behavior tables.", "采集健康、设备不可用和采集器自噪声行属于证据质量通道。它们不会进入行为计数、进程树、网络卡片以及文件/注册表/网络行为表。"),
        ("R0 availability", "R0 可用性"),
        ("Driver network status / WFP-ALE", "驱动网络状态 / WFP-ALE"),
        ("R0 network readiness.", "R0 网络就绪度。"),
        ("<code>r0collector.driverNetworkStatus</code> is an evidence-quality snapshot for WFP/ALE registration, masks, counters, and degrade reasons; it does not count as malicious network behavior.", "<code>r0collector.driverNetworkStatus</code> 是 WFP/ALE 注册、掩码、计数器和降级原因的证据质量快照；不会计为恶意网络行为。"),
        ("Network status availability", "网络状态可用性"),
        ("WFP/ALE masks", "WFP/ALE 掩码"),
        ("R0 network counters", "R0 网络计数器"),
        ("Readiness:", "就绪度："),
        ("degrade reason:", "降级原因："),
        ("Supported:", "支持："),
        ("TODO gap:", "待补缺口："),
        ("last registered:", "最近注册："),
        ("filters:", "过滤器："),
        ("Copy WFP/ALE network status evidence", "复制 WFP/ALE 网络状态证据"),
        ("No R0 health rows", "无 R0 健康行"),
        ("Unavailable / degraded", "不可用 / 降级"),
        ("Attention needed", "需要关注"),
        ("Available / no alerts", "可用 / 无告警"),
        ("Health rows folded", "健康行已折叠"),
        ("Behavior impact", "行为影响"),
        ("R0 health evidence examples", "R0 健康证据示例"),
        ("R0 health rows are folded by default.", "R0 健康行默认折叠。"),
        ("Open this evidence only when diagnosing driver readiness, queue loss, or unavailable device state.", "仅在诊断驱动就绪、队列丢失或设备不可用状态时展开此证据。"),
        ("Device unavailable:", "设备不可用："),
        ("backpressure/drop:", "背压/丢弃："),
        ("health polls:", "健康轮询："),
        ("R0 health evidence is capped and collapsed here; complete rows remain in Raw normalized events/report.json.", "此处 R0 健康证据已限量并折叠；完整行保留在原始事件/report.json 中。"),
        ("Unavailable/health rows affect evidence quality only and do not raise sample behavior counts.", "不可用/健康行只影响证据质量，不会抬高样本行为计数。"),
        ("Collector self-noise hidden", "采集器自噪声已隐藏"),
        ("Collector self-noise hidden from behavior sections.", "采集器自噪声已从行为章节隐藏。"),
        ("Driver rows attributed to KSword.Sandbox.R0Collector.exe are collection-side noise, not sample behavior. They remain available in raw events/report.json.", "归因到 KSword.Sandbox.R0Collector.exe 的驱动行属于采集侧噪声，不是样本行为。它们仍保留在原始事件/report.json 中。"),
        ("Collector self-noise examples", "采集器自噪声示例"),
        ("additional self-noise rows remain only in Raw normalized events/report.json.", "条额外自噪声行仅保留在原始事件/report.json 中。"),
        ("No non-health R0 driver telemetry rows were imported. Collection health rows above describe evidence quality rather than sample behavior.", "未导入非健康类 R0 驱动遥测行。上方采集健康行描述证据质量，而不是样本行为。"),
        ("No R0 collection health rows were imported.", "未导入 R0 采集健康行。"),
        ("Failure reasons", "失败原因"),
        ("No operational failure markers were collected for this job.", "本作业未采集到运行失败标记。"),
        ("Raw normalized events", "原始事件"),
        ("Slim raw event sample.", "精简原始事件样本。"),
        ("Inline raw pages use native details; command, stdout, stderr, PowerShell, script blocks, and oversized payloads stay folded in every row.", "内联原始事件页使用原生 details；command、stdout、stderr、PowerShell、script block 和超大载荷会在每行中保持折叠。"),
        ("Raw event reading guide", "原始事件阅读指南"),
        ("1. Read distribution", "1. 先读分布"),
        ("2. Open a 25-row page", "2. 打开 25 行分页"),
        ("3. Keep heavy fields folded", "3. 保持大字段折叠"),
        ("4. Use report.json for hidden rows", "4. 用 report.json 查看隐藏行"),
        ("Start with top event types, sources, and families before opening rows.", "先查看主要事件类型、来源和事件族，再展开具体行。"),
        ("Inline rows are split into native details pages; the first page opens after you expand the raw-event shell.", "内联行会拆成原生 details 分页；展开原始事件外壳后第一页会默认打开。"),
        ("Command, stdout, stderr, PowerShell, script blocks, and oversized payloads stay behind nested details.", "command、stdout、stderr、PowerShell、script block 和超大载荷会保留在嵌套 details 中。"),
        ("Rows beyond the inline cap stay out of HTML tables; the page index shows report.json-only row ranges.", "超过内联上限的行不会进入 HTML 表；页索引会显示仅在 report.json 中的行范围。"),
        (" inline pages", " 个内联页"),
        (">folded<", ">已折叠<"),
        (" types / ", " 类 / "),
        (" families", " 事件族"),
        ("Event table capped for readability.", "事件表已为可读性限制行数。"),
        ("Inline rows:", "内联行："),
        ("Hidden rows:", "隐藏行："),
        ("Open Raw normalized events or report.json for complete evidence.", "打开原始事件或 report.json 查看完整证据。"),
        ("Total events", "事件总数"),
        ("Inline rendered", "内联渲染"),
        ("Inline pages", "内联分页"),
        ("Inline page size:", "内联分页大小："),
        ("Raw event page", "原始事件页"),
        ("rows", "行"),
        (" of ", " / "),
        ("Hidden raw events", "隐藏原始事件"),
        ("Raw source paths", "原始来源路径"),
        ("Raw event slimming story", "原始事件瘦身叙事"),
        ("These cards explain the renderer's weak-interaction policy before any dense row expansion: visible pages are bounded, long technical payloads stay folded, and report.json/source artifacts remain the complete record.", "这些卡片会在展开密集行之前解释渲染器的弱交互策略：可见分页有界，长技术载荷保持折叠，report.json/来源证据仍是完整记录。"),
        ("Visible HTML rows", "可见 HTML 行"),
        ("Folded technical payloads", "已折叠技术载荷"),
        ("Report-only tail", "仅报告 JSON 尾部"),
        ("Artifact / network / R0 anchors", "证据文件 / 网络 / R0 锚点"),
        ("Copy raw slimming story", "复制原始事件瘦身叙事"),
        ("Counts expose evidence anchors before opening raw pages: artifact references, network rows, and R0/driver rows.", "计数会在打开原始分页前暴露证据锚点：证据文件引用、网络行和 R0/驱动行。"),
        ("No raw rows exceed the inline cap.", "没有原始行超过内联上限。"),
        ("Complete normalized report JSON", "完整规范化报告 JSON"),
        ("Sampled normalized report JSON", "采样规范化报告 JSON"),
        ("representative events", "代表性事件"),
        ("sampled normalized report view", "采样规范化报告视图"),
        ("raw guest events, driver JSONL, and manifests are the complete original source artifacts when indexed", "索引存在时，原始 guest events、driver JSONL 和 manifest 才是完整原始来源证据"),
        ("(all events)", "（全部事件）"),
        ("(representative events)", "（代表性事件）"),
        ("Raw source guide.", "原始来源指南。"),
        ("Complete normalized event and finding source.", "完整的规范化事件和命中来源。"),
        ("Expected location:", "预计位置："),
        ("Original source:", "原始来源："),
        ("Guest events JSON", "来宾事件 JSON"),
        ("Driver events JSONL", "驱动事件 JSONL"),
        ("Artifact manifest", "证据清单"),
        ("Raw source artifact", "原始来源证据"),
        ("Raw events are collapsed by default.", "原始事件默认折叠。"),
        ("Raw events shown inline", "原始事件内联显示"),
        ("Raw evidence height limit:", "原始证据高度限制："),
        ("Open report.json or raw source artifacts for complete evidence.", "打开 report.json 或原始来源证据查看完整证据。"),
        ("Native details work without JavaScript and print labels call out folded evidence.", "原生 details 不依赖 JavaScript；打印标签会标注已折叠证据。"),
        ("Closed by default", "默认折叠"),
        ("native pages", "原生分页"),
        ("folded technical fields", "已折叠技术字段"),
        ("Show inline raw events", "显示内联原始事件"),
        ("Copy raw page", "复制原始事件页"),
        ("Page evidence sample.", "分页证据样例。"),
        ("This page is a bounded native-details chunk; long command/output/script fields remain folded. Use the copy button or right-click to copy this inline page; open report.json/events.json for complete row payloads.", "此页是有界的原生 details 分块；长 command/output/script 字段保持折叠。使用复制按钮或右键可复制此内联页；打开 report.json/events.json 查看完整行载荷。"),
        ("; families ", "；事件族 "),
        ("; top types ", "；主要类型 "),
        ("Raw event distribution", "原始事件分布"),
        ("Raw event page index / 原始事件页索引", "原始事件页索引"),
        ("Raw event page index.", "原始事件页索引。"),
        ("Raw event page index", "原始事件页索引"),
        ("This static index covers every normalized event, even rows hidden from inline rendering. Use event type, source, or family rows to decide whether to open inline pages, report.json, or original source artifacts. Row ranges are copyable; groups beyond the card cap are folded into an other-groups row instead of being dropped.", "此静态索引覆盖每一条规范化事件，包括未内联渲染的隐藏行。可按事件类型、来源或事件族判断应打开内联页、report.json 还是原始来源证据。行范围可复制；超过卡片上限的分组会折叠到其他分组行，而不是被丢弃。"),
        ("Top groups stay visible; any remaining groups are folded into a copyable other-groups row so every raw event remains indexed.", "主要分组保持可见；其余分组会折叠到可复制的其他分组行，确保每条原始事件仍被索引。"),
        ("[other raw groups:", "[其他原始事件组："),
        ("Index by event type", "按事件类型索引"),
        ("Index by source", "按来源索引"),
        ("Index by event family", "按事件族索引"),
        ("first row", "首行"),
        ("inline page", "内联页"),
        ("report.json only", "仅 report.json"),
        ("Top event types", "主要事件类型"),
        ("Event families", "事件族"),
        ("Sources", "来源"),
        ("Top evidence", "关键证据"),
        ("evidence events", "条证据事件"),
        ("more evidence events hidden in raw events/report.json", "条更多证据事件隐藏在原始事件/report.json 中"),
        ("hidden)", "隐藏)"),
        ("same directory as report.html/report.en.html/report.zh.html; job folder", "与 report.html/report.en.html/report.zh.html 位于同一目录；作业目录"),
        ("No raw source artifacts were indexed; report.json remains the sampled normalized report view, not proof that no additional raw telemetry existed.", "未索引原始来源证据；report.json 仍只是采样规范化报告视图，不能证明不存在额外原始遥测。"),
        ("No raw source artifacts were indexed; report.json remains the sampled normalized report view, not proof that no additional raw telemetry existed.", "未索引原始来源证据；report.json 仍只是采样规范化报告视图，不能证明不存在额外原始遥测。"),
        ("additional raw source artifacts are listed in the Artifact links section.", "个额外原始来源证据已列在证据文件链接章节。"),
        ("safe link:", "安全链接："),
        ("General / info", "常规 / 信息"),
        ("MITRE techniques", "MITRE 技术"),
        ("Rule hits", "规则命中"),
        ("Static tags", "静态标签"),
        ("Static URLs", "静态 URL"),
        ("Static URL refs", "静态 URL 引用"),
        ("File events", "文件事件"),
        ("Network events", "网络事件"),
        ("Registry events", "注册表事件"),
        ("File events", "文件事件"),
        ("Process starts", "进程启动"),
        ("Process exits", "进程退出"),
        ("Failure markers", "失败标记"),
        ("Collector lifecycle", "采集器生命周期"),
        ("Driver payloads", "驱动载荷"),
        ("Kernel file rows", "内核文件行"),
        ("Kernel registry rows", "内核注册表行"),
        ("Kernel network rows", "内核网络行"),
        ("R0 failures", "R0 失败"),
        ("Graph processes", "图谱进程"),
        ("Graph edges", "图谱边"),
        ("Network IOCs", "网络 IOC"),
        ("File IOCs", "文件 IOC"),
        ("Registry IOCs", "注册表 IOC"),
        ("Artifact IOCs", "证据文件 IOC"),
        ("Weak-interaction graph.", "弱交互图谱。"),
        ("This section summarizes process, file, registry, network, security/privilege, and artifact relationships from normalized telemetry so the report remains stable without client-side graph libraries.", "本节从规范化遥测汇总进程、文件、注册表、网络、安全/权限和证据文件关系，不依赖客户端图谱库也能稳定呈现。"),
        ("This section summarizes process, file, registry, network, and artifact relationships from normalized telemetry so the report remains stable without client-side graph libraries.", "本节从规范化遥测汇总进程、文件、注册表、网络和证据文件关系，不依赖客户端图谱库也能稳定呈现。"),
        ("Top behavior chain", "关键行为链"),
        ("Static lineage-first chain ranked for analyst reading; expand the edge table below for full bounded evidence.", "按分析阅读顺序优先展示进程谱系链；展开下方边表可查看完整限量证据。"),
        ("Edge evidence", "边证据"),
        ("Evidence summary", "证据摘要"),
        ("Timeline grouping.", "时间线分组。"),
        ("Grouped by UTC minute with process/type summaries; large buckets show representative events first.", "按 UTC 分钟分组并显示进程/类型摘要；较大的分组优先展示代表性事件。"),
        ("Timeline is capped for readability; open Raw normalized events or report.json for complete evidence.", "时间线为保证可读性已限制数量；打开原始事件或 report.json 查看完整证据。"),
        ("additional timeline events are hidden.", "条额外时间线事件已隐藏。"),
        ("additional fields hidden; open report.json/events.json for the full record.", "个额外字段已隐藏；打开 report.json/events.json 查看完整记录。"),
        ("Processes:", "进程："),
        ("Event families:", "事件族："),
        ("Event types:", "事件类型："),
        ("additional events in this group are hidden; open Raw normalized events or report.json for complete evidence.", "条此分组内的额外事件已隐藏；打开原始事件或 report.json 查看完整证据。"),
        ("Evidence summary cards", "证据摘要卡"),
        ("Process evidence", "进程证据"),
        ("Network evidence", "网络证据"),
        ("File and registry evidence", "文件和注册表证据"),
        ("Artifact evidence", "证据文件证据"),
        ("Process nodes and", "进程节点和"),
        ("spawn edges. Highest finding:", "条启动边。最高命中："),
        ("Highest finding:", "最高命中："),
        ("No behavior rules matched", "未命中行为规则"),
        ("No network indicators were extracted.", "未提取网络指标。"),
        ("No file or registry indicators were extracted.", "未提取文件或注册表指标。"),
        ("No report artifact indicators were indexed.", "未索引报告证据文件指标。"),
        ("Top endpoints:", "主要端点："),
        ("Top paths:", "主要路径："),
        ("Top artifacts:", "主要证据文件："),
        ("Process graph nodes", "进程图谱节点"),
        ("Evidence graph edges", "证据图谱边"),
        ("IOC summary", "IOC 摘要"),
        ("From", "来源"),
        ("Relation", "关系"),
        ("To", "目标"),
        ("Copy graph edge", "复制图谱边"),
        ("Copy IOCs", "复制 IOC"),
        ("File/path IOCs", "文件/路径 IOC"),
        ("Behavior", "行为"),
        ("Evidence fields", "证据字段"),
        ("Evidence fields (", "证据字段（"),
        (" compact / ", " 个简要字段 / "),
        (" folded technical)", " 个折叠技术字段）"),
        ("Artifact evidence", "证据文件详情"),
        ("Related artifacts", "相关证据文件"),
        ("Open", "打开"),
        ("Download", "下载"),
        ("Copy path only", "仅复制路径"),
        ("Host/local path (copy only)", "主机/本地路径（仅复制）"),
        ("Screenshot preview", "截图预览"),
        ("Driver JSONL preview", "驱动 JSONL 预览"),
        ("Manifest preview", "清单预览"),
        ("Events JSON preview", "事件 JSON 预览"),
        ("Text preview", "文本预览"),
        ("Copy artifact evidence", "复制证据文件详情"),
        ("Copy artifact", "复制证据文件"),
        ("Copy artifacts", "复制证据文件"),
        ("Download selector / duplicate / rejection diagnostics", "下载选择器 / 重复 / 拒绝诊断"),
        ("Copy evidence summary", "复制证据摘要"),
        ("Copy raw index summary", "复制原始索引摘要"),
        ("Copy distribution summary", "复制分布摘要"),
        ("Copy event", "复制事件"),
        ("Copy process card", "复制进程卡"),
        ("Copy network card", "复制网络卡"),
        ("Copied", "已复制"),
        ("Command line hidden by default", "命令行默认隐藏"),
        ("Command/stdout/stderr/PowerShell fields hidden by default", "command/stdout/stderr/PowerShell 字段默认隐藏"),
        ("Hidden technical field", "隐藏技术字段"),
        ("chars", "字符"),
        ("Process tree", "进程树"),
        ("Process tree nodes", "进程树节点"),
        ("High-signal nodes", "高信号节点"),
        ("Self-noise excluded", "自噪声已排除"),
        ("Roots:", "根节点："),
        ("resolved parent-child edges:", "已解析父子边："),
        ("Nodes with file, registry, or network activity open by default for readable triage.", "包含文件、注册表或网络活动的节点默认展开，便于可读分诊。"),
        ("Collector/health rows excluded from process tree evidence:", "已从进程树证据排除的采集器/健康行："),
        ("Process relationship tree.", "进程关系树。"),
        ("Native expandable process tree grouped by stable process key when available, with PID/PPID fallback; compact row labels, depth/key badges, activity sparklines, and path hints keep lineage readable.", "使用原生可展开进程树；有稳定进程键时按键分组，否则回退到 PID/PPID；紧凑行标签、深度/键徽标、活动火花线和路径提示会保持链路可读。"),
        ("Process tree default expansion.", "进程树默认展开。"),
        ("Key process nodes are open by default: roots, high-signal nodes, and the first relationship levels. Expand remaining nodes for full lineage.", "关键进程节点默认展开：根节点、高信号节点和前几层关系。展开其余节点可查看完整谱系。"),
        ("Process relationship evidence.", "进程关系证据。"),
        ("Cards summarize child, file, registry, network, and linked artifact evidence per stable process identity; long command lines stay folded and collector self-noise is excluded.", "卡片按稳定进程身份汇总子进程、文件、注册表、网络和关联证据文件；长命令行保持折叠，采集器自噪声已排除。"),
        ("Cards summarize child, file, registry, and network activity per stable process identity; long command lines stay folded and collector self-noise is excluded.", "卡片按稳定进程身份汇总子进程、文件、注册表和网络活动；长命令行保持折叠，采集器自噪声已排除。"),
        ("Compact evidence summary", "简要证据摘要"),
        ("Copy compact summary", "复制简要摘要"),
        ("Process compact summary:", "进程简要摘要："),
        ("Network compact summary:", "网络简要摘要："),
        ("Artifact compact summary:", "证据文件简要摘要："),
        ("collection=", "证据通道="),
        ("processes=", "进程="),
        ("process=", "进程="),
        ("target=", "目标="),
        ("status=", "状态="),
        ("events=", "事件="),
        ("children=", "子进程="),
        ("files=", "文件="),
        ("registry=", "注册表="),
        ("network=", "网络="),
        ("artifacts=", "证据文件="),
        ("linkedArtifacts=", "关联证据文件="),
        ("window=", "时间窗="),
        ("detail=", "详情="),
        ("Linked artifacts for this process", "此进程关联证据文件"),
        ("Copy linked process artifacts", "复制进程关联证据文件"),
        ("Linked network / PCAP artifacts", "关联网络 / PCAP 证据文件"),
        ("Copy linked network artifacts", "复制网络关联证据文件"),
        ("Summary lines:", "摘要行："),
        ("Evidence lines:", "证据行："),
        ("Cycle suppressed for stable rendering.", "已抑制循环以保持稳定渲染。"),
        ("Stable relationship map", "稳定关系图"),
        ("Relationship lines:", "关系行："),
        ("Parent:", "父进程："),
        ("Process relationship cards", "进程关系卡"),
        ("Network relationship cards", "网络关系卡"),
        ("No process relationship cards could be derived from normalized telemetry.", "无法从规范化遥测生成进程关系卡。"),
        ("No network relationship cards could be derived from DNS, HTTP, TLS, PCAP, TCP, or UDP telemetry.", "无法从 DNS、HTTP、TLS、PCAP、TCP 或 UDP 遥测生成网络关系卡。"),
        ("additional process relationship cards are hidden from inline cards; use Raw normalized events/report.json for complete process relationships.", "个额外进程关系卡已从内联卡片中隐藏；请使用原始事件/report.json 查看完整进程关系。"),
        ("additional network relationship cards are hidden from inline cards; use Raw normalized events/report.json for complete endpoint evidence.", "个额外网络关系卡已从内联卡片中隐藏；请使用原始事件/report.json 查看完整端点证据。"),
        ("No root process was resolved from parent keys; showing earliest/deepest process tree candidates as bounded fallback roots.", "未能从父进程键解析根进程；改为限量显示最早/最深的进程树候选作为回退根节点。"),
        ("Endpoint-centric view.", "端点中心视图。"),
        ("Network events are grouped by domain, SNI, URL, IP, or endpoint so analysts can read the relationship map without opening raw events first.", "网络事件按域名、SNI、URL、IP 或端点分组，分析人员无需先打开原始事件即可阅读关系图。"),
        ("Network category view.", "网络类别视图。"),
        ("Cards split DNS, HTTP, TLS, flow, and linked PCAP/source artifacts so endpoint relationships stay readable without opening raw rows.", "卡片拆分 DNS、HTTP、TLS、流量和关联 PCAP/来源证据文件，使端点关系无需打开原始行也保持可读。"),
        ("Cards split DNS, HTTP, TLS, and flow counts so endpoint relationships stay readable without opening raw rows.", "卡片拆分 DNS、HTTP、TLS 和流量计数，使端点关系无需打开原始行也保持可读。"),
        ("Endpoint groups", "端点分组"),
        ("Rendered cards:", "已渲染卡片："),
        ("source network events:", "来源网络事件："),
        ("DNS / HTTP / TLS", "DNS / HTTP / TLS"),
        ("Protocol categories are counted before raw rows so relationship cards stay readable.", "协议类别先于原始行计数，使关系卡保持可读。"),
        ("Flow / other", "流量 / 其他"),
        ("TCP/UDP/PCAP flow rows are grouped by endpoint and kept out of collector self-noise.", "TCP/UDP/PCAP 流量行按端点分组，并排除采集器自噪声。"),
        ("Linked PCAP/artifacts", "关联 PCAP/证据文件"),
        ("Packet captures:", "抓包文件："),
        ("related artifacts are surfaced on endpoint cards as compact copyable evidence.", "关联证据文件会以简洁可复制证据显示在端点卡上。"),
        ("additional linked artifacts are hidden from this compact card; use Artifact links or report.json for complete evidence.", "个额外关联证据文件已从此简要卡隐藏；请使用证据文件链接或 report.json 查看完整证据。"),
        ("Artifacts:", "证据文件："),
        ("Categories:", "类别："),
        ("DNS:", "DNS："),
        ("HTTP:", "HTTP："),
        ("TLS:", "TLS："),
        ("Flow/other:", "流量/其他："),
        ("Event types:", "事件类型："),
        ("Children:", "子进程："),
        ("Files:", "文件："),
        ("Registry:", "注册表："),
        ("Network:", "网络："),
        ("Events:", "事件："),
        ("Processes:", "进程："),
        ("First seen:", "首次出现："),
        ("Last seen:", "最后出现："),
        ("<span class=\"tree-badge\">children ", "<span class=\"tree-badge\">子进程 "),
        ("<span class=\"tree-badge\">events ", "<span class=\"tree-badge\">事件 "),
        ("<span class=\"tree-badge\">files ", "<span class=\"tree-badge\">文件 "),
        ("<span class=\"tree-badge\">registry ", "<span class=\"tree-badge\">注册表 "),
        ("<span class=\"tree-badge\">network ", "<span class=\"tree-badge\">网络 "),
        ("<span class=\"tree-badge\">start ", "<span class=\"tree-badge\">启动 "),
        ("<span class=\"tree-badge\">key ", "<span class=\"tree-badge\">键 "),
        ("<strong>Path</strong>", "<strong>路径</strong>"),
        ("Command line", "命令行"),
        ("Child processes", "子进程"),
        ("Top evidence", "关键证据"),
        ("PE sections", "PE 节区"),
        ("Static evidence map", "静态证据图"),
        ("Interesting strings", "可疑字符串"),
        ("Static warnings", "静态警告"),
        ("PE imports", "PE 导入"),
        ("PE exports", "PE 导出"),
        ("Resources and TLS", "资源与 TLS"),
        ("URL indicators", "URL 指标"),
        ("IP indicators", "IP 指标"),
        ("Registry indicators", "注册表指标"),
        ("File/path indicators", "文件/路径指标"),
        ("Severity", "严重级别"),
        ("Technique", "技术"),
        ("<th>Name</th>", "<th>名称</th>"),
        ("<th>Title</th>", "<th>标题</th>"),
        ("<th>Type</th>", "<th>类型</th>"),
        ("<th>Process</th>", "<th>进程</th>"),
        ("<th>Data</th>", "<th>数据</th>"),
        ("<th>Evidence</th>", "<th>证据</th>"),
        ("<th>Indicator</th>", "<th>指标</th>"),
        ("<th>VA</th>", "<th>VA</th>"),
        ("<th>Virtual size</th>", "<th>虚拟大小</th>"),
        ("<th>Raw size</th>", "<th>原始大小</th>"),
        ("<th>Entropy</th>", "<th>熵</th>"),
        ("<th>Signal</th>", "<th>信号</th>"),
        ("Rules", "规则"),
        ("Rule ID", "规则 ID"),
        ("Engine", "引擎"),
        ("Category", "类别"),
        ("Artifact", "证据文件"),
        ("MemoryDump", "内存转储"),
        ("PacketCapture", "网络抓包"),
        (">artifact-index<", ">证据索引<"),
        (">artifact-manifest<", ">证据清单<"),
        (">dropped-file<", ">落地文件<"),
        (">static-analysis<", ">静态分析<"),
        (">screenshot<", ">截图<"),
        ("memory-dump", "内存转储"),
        ("packet-capture", "网络抓包"),
        (">telemetry<", ">遥测<"),
        (">runbook<", ">运行手册<"),
        (">log<", ">日志<"),
        (">bundle<", ">打包<"),
        (">artifact<", ">证据文件<"),
        ("Process execution", "进程执行"),
        ("File creation or modification", "文件创建或修改"),
        ("Network connection", "网络连接"),
        ("Command and Control", "命令与控制"),
        ("File system", "文件系统"),
        (">Execution<", ">执行<"),
        ("Path / safe link", "路径 / 安全链接"),
        ("MIME", "MIME"),
        ("Time", "时间"),
        ("Source", "来源"),
        ("Path / Target", "路径 / 目标"),
        ("File name", "文件名"),
        ("Full path", "完整路径"),
        ("File size", "文件大小"),
        ("File format", "文件格式"),
        ("Architecture", "架构"),
        ("Subsystem", "子系统"),
        ("Entry point RVA", "入口点 RVA"),
        ("Tags", "标签"),
        ("Magic", "魔数"),
        ("Sample", "样本"),
        ("Size", "大小"),
        ("Status", "状态"),
        ("Virtualization provider", "虚拟化后端"),
        ("Target VM", "目标虚拟机"),
        ("Clean baseline", "干净基线"),
        ("VMX path", "VMX 路径"),
        ("QEMU base disk", "QEMU 基础磁盘"),
        ("Provider machine definition", "虚拟机定义"),
        ("QEMU disk format", "QEMU 磁盘格式"),
        ("Right-click timeline entries, table cells, or evidence blocks to copy their contents.", "右键时间线条目、表格单元格或证据块即可复制内容。"),
        ("Safe links are relative to the report artifact root; unsafe or guest-local paths are shown as copyable text only.", "安全链接相对于报告证据根目录；不安全或来宾本地路径仅显示为可复制文本。"),
        ("Imports, exports, resources, TLS, and indicators are grouped from <code>StaticAnalysisResult.Tags</code>, <code>Urls</code>, and prefixed <code>InterestingStrings</code> evidence so report JSON stays backward-compatible.", "导入、导出、资源、TLS 和指标会从 <code>StaticAnalysisResult.Tags</code>、<code>Urls</code> 以及带前缀的 <code>InterestingStrings</code> 证据中分组，以保持 report JSON 向后兼容。"),
        ("No behavior rules matched.", "未命中行为规则。"),
        ("No MITRE ATT&CK techniques mapped yet.", "尚未映射 MITRE ATT&CK 技术。"),
        ("No local behavior, YARA, or static rules matched in this artifact.", "此样本未命中本地行为、YARA 或静态规则。"),
        ("Static analyzer did not run.", "静态分析器未运行。"),
        ("No PE sections parsed.", "未解析到 PE 节区。"),
        ("No PE imports were parsed.", "未解析到 PE 导入。"),
        ("No PE exports were parsed.", "未解析到 PE 导出。"),
        ("No resource or TLS evidence was recorded.", "未记录资源或 TLS 证据。"),
        ("No URL indicators were extracted.", "未提取 URL 指标。"),
        ("No IP indicators were extracted.", "未提取 IP 指标。"),
        ("No registry path indicators were extracted.", "未提取注册表路径指标。"),
        ("No filesystem path indicators were extracted.", "未提取文件系统路径指标。"),
        ("No events.json, driver-events.jsonl, screenshot, or dropped-file artifacts were indexed.", "未索引 events.json、driver-events.jsonl、截图或落地文件证据。"),
        ("No timeline events were collected.", "未采集到时间线事件。"),
        ("No behavior graph could be derived because no normalized events were collected.", "未采集到规范化事件，因此无法生成行为图谱。"),
        ("No process-to-object graph edges were derived yet.", "尚未生成进程到对象的图谱边。"),
        ("No DNS, HTTP, TLS, PCAP, or TCP/IP indicators were extracted from events.", "未从事件中提取 DNS、HTTP、TLS、PCAP 或 TCP/IP 指标。"),
        ("No file/path indicators were extracted from dynamic events.", "未从动态事件中提取文件/路径指标。"),
        ("No registry indicators were extracted from dynamic events.", "未从动态事件中提取注册表指标。"),
        ("No linked artifacts were indexed for this report.", "此报告未索引关联证据文件。"),
        ("No R0Collector or driver-originated events were imported.", "未导入 R0Collector 或驱动来源事件。"),
        ("No failure reason was recorded.", "未记录失败原因。"),
        ("Analysis status is Failed, but no timeout/error/failure event was recorded in normalized telemetry.", "分析状态为失败，但规范化遥测中未记录超时、错误或失败事件。"),
        ("No events were collected for this section.", "此章节未采集到事件。"),
        ("No process start/tree events were available to build a process tree.", "没有可用于构建进程树的进程启动/树事件。"),
        ("No process start events were available to build a process tree.", "没有可用于构建进程树的进程启动事件。"),
        ("Evidence shown:", "已显示证据："),
        ("matching events.", "条匹配事件。"),
        ("very high entropy", "熵值非常高"),
        ("high entropy", "熵值高"),
        ("low entropy", "熵值低"),
        ("virtual only", "仅虚拟节区"),
        ("large virtual/raw gap", "虚拟/原始大小差距大"),
        ("UPX-like", "疑似 UPX")
    ];

    private static readonly IReadOnlyList<(string English, string Chinese)> ChineseRuleHtmlTranslations =
    [
        // Exact rule title/summary mappings for the Simplified Chinese report path.
        // The rule engine currently emits English BehaviorFinding fields, so keep
        // this renderer-owned table data-only instead of changing report schema.
        ("Security or privilege telemetry observed", "观察到安全或权限遥测"),
        ("Windows Security/ETW privilege or process-access telemetry was imported as supporting context. This rule does not by itself indicate malicious behavior; review target object/process, requested rights, privilege name, and correlated higher-signal rules.", "已导入 Windows Security/ETW 权限或进程访问遥测作为辅助上下文。该规则本身不表示恶意行为；请结合目标对象/进程、请求权限、权限名称以及更高信号规则排查。"),
        ("A bcdedit command configured bootstatuspolicy ignoreallfailures, a common recovery-inhibition companion to destructive or ransomware behavior.", "bcdedit 命令配置 bootstatuspolicy ignoreallfailures，常见于破坏或勒索行为中的恢复抑制。"),
        ("A BITS job or qmgr registry row configured NotifyCmdLine/notify command execution from a user-writable executable or script path.", "BITS 作业或 qmgr 注册表行将 NotifyCmdLine/通知命令配置为用户可写可执行或脚本路径。"),
        ("A BITSAdmin or BITS PowerShell command configured a notification command line or completed transfer that points to a user-writable executable or script.", "BITSAdmin 或 BITS PowerShell 命令配置 notify command line，或完成后指向用户可写可执行/脚本载荷；排查 BITS 任务名、远程 URL 和本地路径。"),
        ("A browser policy registry write configured forced extension installation, extension settings, update URLs, or CRX-related metadata.", "浏览器策略注册表写入配置强制扩展安装、扩展设置、update URL 或 CRX 相关元数据。"),
        ("A certutil -urlcache command fetched remote content and wrote it into a user-writable staging path.", "certutil -urlcache 命令获取远程内容并写入用户可写暂存路径。"),
        ("A command line attempted to add or import a certificate into LocalMachine or CurrentUser Root certificate stores.", "命令行尝试向 LocalMachine 或 CurrentUser Root 根证书存储添加或导入证书。"),
        ("A command line attempted to clear Windows event logs or PowerShell logs.", "命令行尝试清除 Windows 事件日志或 PowerShell 日志。"),
        ("A command line attempted to disable Defender features, add exclusions, stop services, or remove definitions.", "命令行尝试禁用 Defender 功能、添加排除项、停止服务或移除定义。"),
        ("A command line copied Chromium or Edge credential stores such as Login Data, Cookies, Web Data, or Local State into a staging path.", "命令行复制 Chromium/Edge 的 Login Data、Cookies、Web Data 或 Local State 到暂存路径；这是浏览器凭据/会话数据访问的高优先级证据。"),
        ("A command line created or configured a remote service via sc.exe while the service binary path references an admin-share, UNC, or user-writable payload.", "命令行通过 sc.exe 创建或配置远程服务，服务二进制路径引用管理共享、UNC 或用户可写载荷；排查服务名、目标主机和投放文件。"),
        ("A command line disabled firewall profiles, disabled rules, or broadly opened network access.", "命令行禁用防火墙配置文件、禁用规则或广泛放开网络访问。"),
        ("A command line disabled Windows recovery, deleted backup catalogs, resized shadow storage to a tiny value, or disabled recovery tooling.", "命令行禁用 Windows 恢复、删除备份目录、将卷影存储缩小到极低值，或禁用恢复工具。"),
        ("A command line enabled or invoked RDP shadowing, RestrictedAdmin, or mstsc remote desktop connection behavior.", "命令行启用或调用 RDP Shadow、RestrictedAdmin 或 mstsc 远程桌面连接行为。"),
        ("A command line enumerated running processes, loaded modules, or drivers, which samples often use to look for analysis tools.", "命令行枚举运行进程、已加载模块或驱动，样本常用其查找分析工具。"),
        ("A command line explicitly enabled PowerShell remoting or WinRM remote management, often preparatory to lateral movement.", "命令行明确启用 PowerShell Remoting 或 WinRM 远程管理，常作为横向移动准备步骤。"),
        ("A command line invoked cmstp.exe with INF/profile installation flags commonly abused for signed binary proxy execution and UAC bypass chains.", "命令行调用 cmstp.exe 及 INF/配置文件安装参数，常被用于签名二进制代理执行和 UAC 绕过链。"),
        ("A command line invoked control.exe, rundll32 shell32 Control_RunDLL, or a CPL payload path, which can proxy execution through Control Panel components.", "命令行调用 control.exe、rundll32 shell32 Control_RunDLL 或 CPL 载荷路径，可能通过控制面板组件代理执行。"),
        ("A command line invoked DCOM/COM object creation against a remote host using Excel.Application or related Office automation to start code remotely.", "命令行通过远程主机上的 DCOM/COM Excel.Application 或 Office 自动化对象启动代码。"),
        ("A command line invoked HTML Help with HTTP(S), ms-its, mk:@MSITStore, or script content, a constrained LOLBin script proxy-execution pattern.", "命令行使用 HTML Help 搭配 HTTP(S)、ms-its、mk:@MSITStore 或脚本内容，是受约束的 LOLBin 脚本代理执行模式。"),
        ("A command line invoked msxsl with a remote HTTP(S) XSL or script reference, indicating constrained script proxy execution.", "命令行使用 msxsl 搭配远程 HTTP(S) XSL 或脚本引用，指示受约束的脚本代理执行。"),
        ("A command line invoked sleep, timeout, ping-delay, or wait primitives that can stall short sandbox windows.", "命令行调用 sleep、timeout、ping-delay 或 wait 原语，可拖延较短沙箱窗口。"),
        ("A command line invoked WinRM, Enter-PSSession, Invoke-Command, or PowerShell remoting with an explicit remote computer name.", "命令行调用 WinRM、Enter-PSSession、Invoke-Command 或 PowerShell Remoting，并指定远程计算机名。"),
        ("A command line launched auto-elevating Windows binaries commonly paired with registry hijacks for UAC bypass.", "命令行启动常与注册表劫持配合绕过 UAC 的自动提权 Windows 二进制。"),
        ("A command line launched mshta or regsvr32 with an HTTP(S) URL or scriptlet directive, enabling download-and-execute without writing a conventional executable first.", "命令行使用 HTTP(S) URL 或 scriptlet 指令启动 mshta/regsvr32，可在不先写入常规可执行文件的情况下下载并执行。"),
        ("A command line matched wevtutil log clearing syntax for Security, System, Application, or Windows provider logs.", "命令行匹配 wevtutil 清除 Security、System、Application 或 Windows provider 日志的语法。"),
        ("A command line queried NIC, MAC address, disk, volume, or device inventory commonly used to identify virtualized environments.", "命令行查询 NIC、MAC 地址、磁盘、卷或设备清单，常用于识别虚拟化环境。"),
        ("A command line queried OS, BIOS, computer-system, or hardware inventory data commonly used before sandbox or VM checks.", "命令行查询 OS、BIOS、计算机系统或硬件清单数据，这些常在沙箱或 VM 检查前使用。"),
        ("A command line referenced built-in download helpers or script web-request primitives often used to stage payloads.", "命令行引用内置下载辅助程序或脚本 Web 请求原语，常用于暂存载荷。"),
        ("A command line referenced common AMSI or ETW bypass tokens used to reduce script and telemetry visibility.", "命令行引用常见 AMSI 或 ETW 绕过标记，用于降低脚本和遥测可见性。"),
        ("A command line referenced common LSASS dumping utilities, MiniDump exports, or credential-dumping command tokens.", "命令行引用常见 LSASS 转储工具、MiniDump 导出或凭据转储命令标记。"),
        ("A command line referenced explicit Kerberos ticket dump or export tokens such as sekurlsa tickets, kerberos::list /export, or Rubeus dump/triage.", "命令行引用明确的 Kerberos 票据转储或导出令牌，如 sekurlsa tickets、kerberos::list /export 或 Rubeus dump/triage。"),
        ("A command line referenced scheduled task creation or execution against a remote system.", "命令行引用针对远程系统的计划任务创建或执行。"),
        ("A command line referenced stopping or killing common Windows security, logging, or EDR-related services and processes.", "命令行引用停止或终止常见 Windows 安全、日志或 EDR 相关服务和进程。"),
        ("A command line used archive tooling over user-profile or public paths while referencing credential, wallet, token, browser, SSH key, or certificate filenames.", "命令行使用压缩工具处理用户目录或公共目录，并引用 credential、wallet、token、browser、SSH key 或证书类文件名；排查是否准备外传。"),
        ("A command line used bitsadmin transfer, create, addfile, or resume to fetch content from HTTP or HTTPS.", "命令行使用 bitsadmin transfer、create、addfile 或 resume 从 HTTP/HTTPS 获取内容。"),
        ("A command line used certutil URL cache or split options to download a remote payload.", "命令行使用 certutil URL cache 或 split 参数下载远程载荷。"),
        ("A command line used copy, xcopy, robocopy, or PowerShell copy semantics to stage an executable/script payload into a remote ADMIN$, C$, or IPC$ style share.", "命令行使用 copy、xcopy、robocopy 或 PowerShell Copy-Item 将可执行/脚本载荷投放到远程 ADMIN$、C$ 或 IPC$ 管理共享；排查目标主机和后续服务/计划任务执行。"),
        ("A command line used esentutl or copy-style helpers against ntds.dit, a focused Active Directory credential extraction pattern.", "命令行使用 esentutl 或复制类辅助工具操作 ntds.dit，是聚焦的 Active Directory 凭据提取模式。"),
        ("A command line used ntdsutil IFM create commands that can stage Active Directory credential material for offline extraction.", "命令行使用 ntdsutil IFM create 命令，可暂存 Active Directory 凭据材料供离线提取。"),
        ("A command line used sc.exe against a remote host to start, stop, delete, configure, or otherwise control a service.", "命令行使用 sc.exe 面向远程主机启动、停止、删除、配置或控制服务；属于远程服务管理和横向移动排查线索，需结合投放/认证证据判断。"),
        ("A command line used WMIC process call create or PowerShell CIM/WMI invocation against a remote node.", "命令行使用 WMIC process call create 或 PowerShell CIM/WMI 调用远程节点。"),
        ("A command line uses a Windows LOLBin to execute or load content from an http(s) WebDAV path or davwwwroot UNC path.", "命令行使用 Windows LOLBin 从 http(s) WebDAV 路径或 davwwwroot UNC 路径执行或加载内容。"),
        ("A command lists running processes and filters for security, EDR, packet-capture, VM, or analysis-tool process names in the same command line.", "命令行在列举运行进程的同时筛选安全、EDR、抓包、虚拟机或分析工具进程名。"),
        ("A command or normalized WMI event invokes Win32_Process Create against a named remote target, matching WMI remote execution semantics without relying on port-only evidence.", "命令或规范化 WMI 事件对命名远程目标调用 Win32_Process Create，符合 WMI 远程执行语义，且不依赖单纯端口证据。"),
        ("A command probes BIOS, computer-system, baseboard, or SMBIOS WMI classes for VM vendor strings while the event records exit, sleep, or gate behavior.", "命令探测 BIOS、ComputerSystem、BaseBoard 或 SMBIOS WMI 类中的虚拟机厂商字符串，同时事件记录退出、睡眠或门控行为。"),
        ("A created or copied artifact path looked like an LSASS/comsvcs memory dump outside sandbox collection paths.", "创建或复制的工件路径看起来像 LSASS/comsvcs 内存转储，并排除沙箱采集路径。"),
        ("A curl command fetched an HTTP/HTTPS resource and wrote it with -o/-output into a user-writable staging path.", "curl 命令获取 HTTP/HTTPS 资源，并通过 -o/--output 写入用户可写暂存路径。"),
        ("A curl or wget command downloaded remote content into a user-writable executable or script path and chained to shell execution in the same command line.", "curl/wget 命令将远程内容下载到用户可写的可执行或脚本路径，并在同一命令行中链式执行。"),
        ("A Defender exclusion registry write targeted Temp, AppData, Public, ProgramData, Downloads, or equivalent user-writable staging paths.", "Defender 排除项注册表写入指向 Temp、AppData、Public、ProgramData、Downloads 或等价用户可写暂存路径。"),
        ("A Defender exclusion registry write targets a user-writable payload path and includes dropped-file or download-execute correlation evidence.", "Defender 排除项注册表写入指向用户可写负载路径，并包含投放文件或下载执行关联证据。"),
        ("A Defender policy registry write set protection-disable values to enabled/true, reducing real-time, behavior, IOAV, or script scanning coverage.", "Defender 策略注册表写入将禁用防护类值设置为启用/true，降低实时、行为、IOAV 或脚本扫描覆盖。"),
        ("A DNS event referenced dynamic DNS, disposable, or commonly abused top-level domain fragments for triage.", "DNS 事件引用动态 DNS、一次性域名或常被滥用的顶级域片段，用于分诊。"),
        ("A download-execute correlation row included both paths, the executed path was user-writable, and browser/referrer context was absent.", "下载执行关联行同时包含下载与执行路径，执行路径位于用户可写目录且缺少浏览器/referrer 上下文。"),
        ("A driver or agent event reported a registry write.", "驱动或 Agent 事件报告了注册表写入。"),
        ("A driver.network typed payload referenced DNS protocol or port 53 traffic.", "driver.network 类型化载荷引用 DNS 协议或 53 端口流量。"),
        ("A driver.network typed payload referenced HTTP/HTTPS protocol labels or common web ports beyond normalized user-mode network rows.", "driver.network 类型化载荷引用 HTTP/HTTPS 协议标签或常见 Web 端口，补充规范化用户态网络行。"),
        ("A driver.network typed payload reported outbound or connect-style network activity from the kernel event stream.", "driver.network 类型化载荷从内核事件流报告出站或连接类网络活动。"),
        ("A driver.registry typed payload reported a key path below a Windows service configuration hive.", "driver.registry 类型化载荷报告 Windows 服务配置 hive 下的键路径。"),
        ("A driver.registry typed payload reported a key path under Run, RunOnce, RunOnceEx, or policy Run autostart locations.", "driver.registry 类型化载荷报告 Run、RunOnce、RunOnceEx 或策略 Run 自启动位置下的键路径。"),
        ("A driver.registry typed payload reported Task Scheduler cache key activity.", "driver.registry 类型化载荷报告 Task Scheduler 缓存键活动。"),
        ("A dropped-file artifact copy candidate was skipped because it was missing, outside scope, invalid, under the output tree, or failed to copy.", "落地文件证据复制候选因缺失、超出范围、无效、位于输出树下或复制失败而被跳过。"),
        ("A file creation or artifact copy used an LSASS-oriented dump filename, complementing process-access and command-line LSASS dumping evidence.", "文件创建或证据复制使用了面向 LSASS 的转储文件名，可补充进程访问和命令行 LSASS 转储证据。"),
        ("A file creation or modification event targeted a Windows Startup folder path.", "文件创建或修改事件命中 Windows Startup 启动文件夹路径。"),
        ("A file creation or modification event wrote a script-like file extension that may be launched by command interpreters or LOLBins.", "文件创建或修改事件写入脚本类扩展名，可能后续由命令解释器或 LOLBin 启动。"),
        ("A file creation or modification event wrote an executable, driver, library, or script-like path.", "文件创建或修改事件写入了可执行文件、驱动、库或脚本类路径。"),
        ("A file event created or modified a path with common ransom-note naming patterns. This requires a concrete filesystem path and excludes sandbox collection paths.", "文件事件创建或修改了包含常见勒索说明命名模式的路径。该规则要求明确文件路径，并排除沙箱采集目录。"),
        ("A file event path matched Chromium-family Network\\Cookies databases while common browser process names were excluded.", "文件事件路径匹配 Chromium 系 Network\\Cookies 数据库，同时排除了常见浏览器进程名。"),
        ("A file event path matched the domain controller NTDS.dit credential database path.", "文件事件路径匹配域控 NTDS.dit 凭据数据库路径。"),
        ("A file event referenced PSEXESVC-style service binaries under an ADMIN$ path, a concrete lateral tool-transfer artifact.", "文件事件引用 ADMIN$ 路径下的 PSEXESVC 风格服务二进制，是明确的横向工具传输痕迹。"),
        ("A file event touched common Chromium or Firefox credential database files.", "文件事件触及常见 Chromium 或 Firefox 凭据数据库文件。"),
        ("A file or driver event carried explicit ransomware/encryption classification on a concrete file path; bare encrypted-looking extensions alone are not enough for this rule.", "文件或驱动事件在明确文件路径上携带勒索/加密分类；单纯类似加密的扩展名不足以命中该规则。"),
        ("A file or registry event referenced Windows SAM, SECURITY, or SYSTEM hive material used for offline credential extraction.", "文件或注册表事件引用用于离线凭据提取的 Windows SAM、SECURITY 或 SYSTEM hive 材料。"),
        ("A file or registry event referenced Windows Vault, DPAPI Protect directories, credential files, or policy secrets.", "文件或注册表事件引用 Windows Vault、DPAPI Protect 目录、凭据文件或策略机密。"),
        ("A file was created or modified in a common browser download, cache, or user download location used for staged payloads.", "文件在常见浏览器下载、缓存或用户下载位置创建或修改，这些位置常用于暂存载荷。"),
        ("A file write created or modified a Native Messaging Host manifest outside sandbox plumbing paths.", "文件写入创建或修改 Native Messaging Host 清单，且不位于沙箱管道路径。"),
        ("A file write referenced Zone.Identifier or mark-of-the-web metadata that can indicate content downloaded from an untrusted zone.", "文件写入引用 Zone.Identifier 或 Mark-of-the-Web 元数据，可能表示内容来自不受信任区域。"),
        ("A file write targeted a user PowerShell profile script under Documents\\WindowsPowerShell or Documents\\PowerShell, an autostart surface for interactive shells.", "文件写入指向用户 Documents 下的 PowerShell profile 脚本，这是交互式 PowerShell 启动时会加载的持久化面。"),
        ("A file write targeted Temp/AppData or used an executable, library, driver, or script extension; the current rule schema treats path fragments as OR conditions.", "文件写入命中 Temp/AppData，或使用可执行、库、驱动、脚本扩展名；当前规则 schema 将路径片段作为 OR 条件处理。"),
        ("A file write targeted the Windows Scheduled Tasks folder, which can indicate task-based persistence outside command-line creation telemetry.", "文件写入命中 Windows Scheduled Tasks 文件夹，可能表示命令行创建遥测之外的任务持久化。"),
        ("A file write targets an ADMIN$, C$, or IPC-adjacent administrative share path with an executable or script payload extension.", "文件写入指向 ADMIN$、C$ 等管理共享路径，且具有可执行或脚本载荷扩展名。"),
        ("A file write touched Windows system directories or executable-like extensions; inspect evidence to distinguish benign installers from payload placement.", "文件写入触及 Windows 系统目录或可执行类扩展名；请检查证据以区分良性安装器与载荷投放。"),
        ("A file-search command combines a user-profile scope with credential, secret, token, wallet, key, or KeePass-like filename terms.", "文件搜索命令同时包含用户配置文件范围以及凭据、密钥、令牌、钱包、私钥或 KeePass 类文件名关键词。"),
        ("A forfiles command used /c to launch cmd, PowerShell, WSH, mshta, or rundll32, separating proxy execution from benign file enumeration.", "forfiles 命令使用 /c 启动 cmd、PowerShell、WSH、mshta 或 rundll32，区别于普通文件枚举。"),
        ("A host-indexed dropped-file artifact links an executable, script, library, driver, or archive payload under artifacts/dropped-files to the original file event, hash, and safe download selector.", "Host 索引的释放文件产物将 artifacts/dropped-files 下的可执行、脚本、库、驱动或归档载荷与原始文件事件、哈希和安全下载选择器关联。"),
        ("A host-indexed memory dump artifact preserves a captured memory-dump source event, process identity, size, hash, and safe relative artifact selector for analyst correlation. This is artifact evidence, not a credential-dumping verdict by itself.", "Host 索引的内存转储产物保留了已捕获的内存转储来源事件、进程身份、大小、哈希和安全相对产物选择器，便于分析关联；它本身不是凭据转储判定。"),
        ("A host-indexed screenshot artifact preserves the captured screenshot source event, phase, size, hash, and safe relative artifact selector for report review. This records sandbox collection evidence rather than sample screen-capture behavior.", "Host 索引的截图产物保留截图来源事件、阶段、大小、哈希和安全相对产物选择器用于报告审阅；这记录的是沙箱采集证据，而不是样本截图行为。"),
        ("A kernel process callback row was imported from driver telemetry and should be inspected with the raw event payload.", "已从驱动遥测导入内核进程回调行，应结合原始事件载荷检查。"),
        ("A legacy R0Collector build opened the driver device without issuing the read-events IOCTL; current builds should emit driverHealth, driverPoll, and driverReadEvents rows instead. The rule ID is retained only for compatibility with older reports and smoke contracts.", "旧版 R0Collector 已打开驱动设备但尚未发出 read-events IOCTL；当前版本应改为产生 driverHealth、driverPoll 和 driverReadEvents 行。该规则 ID 仅为兼容旧报告和 smoke 契约保留。"),
        ("A memory event referenced RWX or executable memory protection changes that can precede injected code execution.", "内存事件引用 RWX 或可执行内存保护变更，可能先于注入代码执行。"),
        ("A msiexec command line installed or executed a remote MSI/MSP/CAB package over HTTP or HTTPS.", "msiexec 命令行通过 HTTP/HTTPS 安装或执行远程 MSI/MSP/CAB 包。"),
        ("A net use command connected to ADMIN$, C$, IPC$, or another UNC share while supplying explicit credentials.", "net use 命令连接 ADMIN$、C$、IPC$ 或其他 UNC 共享，并提供显式凭据。"),
        ("A network event included a remote address field, preserving IP literal evidence for triage.", "网络事件包含远程地址字段，保留 IP 字面量证据用于分诊。"),
        ("A network or driver event referenced SMB port 445 or legacy NetBIOS file-sharing ports.", "网络或驱动事件引用 SMB 445 端口或旧式 NetBIOS 文件共享端口。"),
        ("A network, driver, or PCAP event referenced WinRM ports 5985 or 5986.", "网络、驱动或 PCAP 事件引用 WinRM 5985 或 5986 端口。"),
        ("A newly written file used an archive, disk image, script, or shortcut extension often seen in download-and-execute chains.", "新写入文件使用归档、磁盘镜像、脚本或快捷方式扩展名，常见于下载并执行链。"),
        ("A non-browser process opened or modified Chromium-family Local State files that can contain encrypted key metadata for browser credential stores.", "非浏览器进程打开或修改 Chromium 系 Local State 文件，其中可能包含浏览器凭据库加密密钥元数据。"),
        ("A non-browser process touched Chromium-family Cookie database paths that can contain reusable web session tokens.", "非浏览器进程触及 Chromium 系 Cookie 数据库路径，其中可能包含可复用 Web 会话令牌。"),
        ("A normalized anti-analysis event reported a debugger, sandbox, or timing check.", "规范化反分析事件报告调试器、沙箱或计时检查。"),
        ("A normalized anti-analysis event reports low CPU, memory, or disk thresholds coupled with an exit, sleep, or delay action.", "规范化反分析事件报告低 CPU、内存或磁盘阈值，并伴随退出、睡眠或延迟动作。"),
        ("A normalized collector emitted an explicit command-and-control or beacon event.", "规范化采集器输出了明确的命令与控制或 Beacon 事件。"),
        ("A normalized DNS or PCAP DNS event included endpoint, query, or response-code metadata.", "规范化 DNS 或 PCAP DNS 事件包含端点、查询或响应码元数据。"),
        ("A normalized DNS query event was observed during execution.", "执行期间观察到规范化 DNS 查询事件。"),
        ("A normalized download-execute correlation row included both downloaded and executed path fields, avoiding inference from static URLs or standalone file writes.", "规范化下载执行关联事件同时包含下载路径和执行路径字段，避免从静态 URL 或孤立文件写入进行推断。"),
        ("A normalized download-execute correlation row tied an HTTP(S) source URL to a launched user-writable artifact with matching hash metadata.", "归一化下载执行关联行将 HTTP(S) 来源 URL、用户可写执行路径和匹配哈希元数据关联起来；比单独 URL 或文件写入更适合作为报告主证据。"),
        ("A normalized download-execute correlation row tied an HTTP(S) source URL, MZ/PE payload magic, and a user-writable executed path.", "规范化下载执行关联行将 HTTP(S) 来源 URL、MZ/PE 载荷魔数与用户可写执行路径关联。"),
        ("A normalized download-execute row ties a user-downloaded ISO/IMG/VHD/archive container to execution of an LNK, executable, or script payload.", "规范化 download-execute 行将用户下载的 ISO/IMG/VHD/压缩包容器与 LNK、可执行文件或脚本载荷的执行关联起来。"),
        ("A normalized higher-level event reported that a downloaded or staged artifact was executed during the same analysis window. The rule requires an executed path plus at least one download/source path field.", "规范化高层事件报告下载或暂存产物在同一分析窗口内被执行。规则要求存在执行路径以及至少一个下载/来源路径字段。"),
        ("A normalized HTTP or PCAP HTTP event included endpoint, host, URI, method, content-type, user-agent, or payload metadata.", "规范化 HTTP 或 PCAP HTTP 事件包含端点、Host、URI、方法、内容类型、User-Agent 或载荷元数据。"),
        ("A normalized HTTP request event was observed during execution.", "执行期间观察到规范化 HTTP 请求事件。"),
        ("A normalized injection sequence shows WriteProcessMemory into another process followed by executable memory protection.", "规范化注入序列显示对其他进程 WriteProcessMemory 后设置可执行内存保护。"),
        ("A normalized network event or driver payload referenced TLS/HTTPS or remote port 443.", "规范化网络事件或驱动载荷引用 TLS/HTTPS 或远程 443 端口。"),
        ("A normalized PCAP flow row included endpoint, port, or protocol metadata for report correlation.", "规范化 PCAP flow 行包含端点、端口或协议元数据，用于报告关联。"),
        ("A normalized process/thread event indicated remote thread creation or cross-process injection-style activity.", "规范化进程/线程事件指示远程线程创建或跨进程注入类活动。"),
        ("A normalized staging row correlates hidden/script attributes in a user-writable location with a LOLBin or script host launch in the same analysis window.", "规范化暂存行将用户可写位置中的隐藏脚本属性与同一分析窗口内 LOLBin 或脚本宿主启动关联起来。"),
        ("A normalized TLS or PCAP TLS event included endpoint, SNI, JA3, ALPN, or TLS version metadata.", "规范化 TLS 或 PCAP TLS 事件包含端点、SNI、JA3、ALPN 或 TLS 版本元数据。"),
        ("A normalized UDP network event was collected during sample execution.", "样本执行期间采集到规范化 UDP 网络事件。"),
        ("A packet-capture summary, packet, or capture-artifact row was imported with bounded parser metadata for report visibility.", "已导入 packet-capture 摘要、数据包或抓包证据行，并携带有界解析器元数据供报告展示。"),
        ("A packet-derived flow, DNS, HTTP, TLS, or summary row carries packet-capture artifact path, hash, collection, and protocol metadata so protocol evidence can be traced back to a concrete PCAP/PCAPNG file.", "包解析得到的流、DNS、HTTP、TLS 或摘要行携带抓包产物路径、哈希、collection 和协议元数据，使协议证据可追溯到具体 PCAP/PCAPNG 文件。"),
        ("A parsed file row includes both droppedFileCandidate=true and downloadExecuteCandidate=true, indicating the collector correlated or projected a web-transfer/drop context on one row.", "解析后的文件行同时包含 droppedFileCandidate=true 和 downloadExecuteCandidate=true，表示采集器在同一行关联或投射了 Web 传输/落地上下文。"),
        ("A path-bearing registry, file, or process query referenced VM, sandbox, debugger, or analysis-tool artifacts.", "带路径的注册表、文件或进程查询引用了 VM、沙箱、调试器或分析工具痕迹。"),
        ("A PCAP summary or native import rollup reported DNS, HTTP, TLS, TCP, or UDP protocol metadata. This is diagnostic/report evidence; prefer protocol-specific pcap.dns, pcap.http, pcap.tls, pcap.flow, or network.* rows for behavior scoring. The legacy rule ID is retained for compatibility.", "PCAP 摘要或本地导入汇总报告了 DNS、HTTP、TLS、TCP 或 UDP 协议元数据。该命中属于诊断/报告证据；行为评分应优先查看更具体的 pcap.dns、pcap.http、pcap.tls、pcap.flow 或 network.* 行。旧规则 ID 为兼容保留。"),
        ("A PowerShell command copied an executable or script to a remote ADMIN$ or C$ share, a common staging step before remote service, task, or WMI execution.", "PowerShell 命令将可执行/脚本复制到远程 ADMIN$ 或 C$ 管理共享，常见于远程服务、计划任务或 WMI 执行前的投放阶段。"),
        ("A PowerShell command downloaded content with -OutFile into Temp, Downloads, Public, ProgramData, or another user-writable staging path.", "PowerShell 命令使用 -OutFile 将内容下载到 Temp、Downloads、Public、ProgramData 或其他用户可写暂存路径。"),
        ("A PowerShell command downloaded remote content and referenced AppData, Temp, ProgramData, Public, or Downloads as a staging path.", "PowerShell 命令下载远程内容，并引用 AppData、Temp、ProgramData、Public 或 Downloads 作为暂存路径。"),
        ("A PowerShell command downloads content, expands or extracts it into a user-writable location, and launches a payload in one chained execution flow.", "PowerShell 命令在同一执行链中下载内容、解压到用户可写位置并启动载荷。"),
        ("A PowerShell command line referenced reflection, shellcode, PE injection, or memory-protection primitives used for in-memory execution.", "PowerShell 命令行引用反射、shellcode、PE 注入或内存保护原语，常用于内存执行。"),
        ("A PowerShell command line used bypass, hidden-window, expression-evaluation, or web-download primitives commonly seen in script abuse.", "PowerShell 命令行使用 bypass、隐藏窗口、表达式求值或 Web 下载原语，常见于脚本滥用。"),
        ("A PowerShell command used Invoke-WebRequest, iwr, wget, curl, or WebClient download syntax, wrote into a user-writable path, and invoked Start-Process, Invoke-Item, or direct execution.", "PowerShell 命令使用 Invoke-WebRequest/iwr/wget/curl/WebClient 下载到用户可写路径，并通过 Start-Process、Invoke-Item 或直接调用执行；排查下载 URL、落地路径和父进程。"),
        ("A Print Processors registry Driver value references a DLL under a user-writable directory, reducing false positives from normal print configuration enumeration.", "Print Processors 注册表 Driver 值引用用户可写目录下的 DLL，可减少正常打印配置枚举造成的误报。"),
        ("A process access or API event requested VM-write, VM-operation, create-thread, or all-access rights commonly needed before process injection.", "进程访问或 API 事件请求了注入前常见的 VM 写入、VM 操作、创建线程或全访问权限；需结合目标进程和后续行为确认。"),
        ("A process command line attempted to delete Volume Shadow Copies or WMI shadow-copy objects, a common ransomware recovery-inhibition step.", "进程命令行尝试删除卷影副本或 WMI ShadowCopy 对象，这是勒索软件常见的恢复抑制步骤。"),
        ("A process command line attempted to terminate common analysis, monitoring, debugger, or packet-capture tools.", "进程命令行尝试终止常见分析、监控、调试器或抓包工具。"),
        ("A process command line invoked mshta with URL, HTA, JScript, or VBScript content for living-off-the-land script execution.", "进程命令行调用 mshta 并携带 URL、HTA、JScript 或 VBScript 内容，用于 LOL 脚本执行。"),
        ("A process command line invoked Windows Script Host or launched script extensions handled by WSH.", "进程命令行调用 Windows Script Host，或启动由 WSH 处理的脚本扩展名。"),
        ("A process command line launched mmc.exe with an .msc file under a user-writable path, a constrained System Binary Proxy Execution signal.", "进程命令行启动 mmc.exe 并加载用户可写路径下的 .msc 文件，是受约束的系统二进制代理执行信号。"),
        ("A process command line matched a timeout-bounded regex for PowerShell or pwsh EncodedCommand with a base64-looking payload.", "进程命令行匹配 PowerShell 或 pwsh EncodedCommand 与类似 Base64 负载的正则特征。"),
        ("A process command line referenced a script-like file extension.", "进程命令行引用了脚本类文件扩展名。"),
        ("A process command line referenced administrative shares or copy tools commonly used to stage payloads on remote Windows hosts.", "进程命令行引用管理共享或复制工具，常用于向远程 Windows 主机暂存载荷。"),
        ("A process command line referenced credential dumping tool names or command tokens such as sekurlsa, lsadump, DCSync, Kerberoast, or browser/vault dump modes.", "进程命令行引用 sekurlsa、lsadump、DCSync、Kerberoast 或浏览器/Vault dump 模式等凭据转储工具名或命令标记。"),
        ("A process command line referenced LSASS dump tooling, MiniDump paths, or common dump utilities used for credential theft triage.", "进程命令行引用 LSASS 转储工具、MiniDump 路径或常见转储工具，用于凭据窃取分诊。"),
        ("A process command line referenced PowerShell remoting or WinRM execution primitives that can run commands on remote systems.", "进程命令行引用 PowerShell Remoting 或 WinRM 执行原语，可在远程系统上运行命令。"),
        ("A process command line referenced PsExec-like tools or Service Control Manager syntax that can create or start services on remote hosts.", "进程命令行引用 PsExec 类工具或 Service Control Manager 语法，可在远程主机上创建或启动服务。"),
        ("A process command line referenced recent-document, user-assist, session, mouse, keyboard, or idle-time checks commonly used to detect automated sandboxes.", "进程命令行引用最近文档、UserAssist、会话、鼠标、键盘或空闲时间检查，常用于检测自动化沙箱。"),
        ("A process command line referenced scheduled-task creation or registration primitives.", "进程命令行引用了计划任务创建或注册原语。"),
        ("A process command line referenced VM, sandbox, debugger, or analysis-tool process names commonly queried before changing behavior.", "进程命令行引用 VM、沙箱、调试器或分析工具进程名，这些常在改变行为前被查询。"),
        ("A process command line referenced Windows service creation or service-control primitives.", "进程命令行引用 Windows 服务创建或服务控制原语。"),
        ("A process command line referenced WMI or CIM remote execution and discovery switches for another host.", "进程命令行引用面向另一主机的 WMI 或 CIM 远程执行和发现开关。"),
        ("A process command line referenced WMI permanent event subscription creation primitives.", "进程命令行引用 WMI 永久事件订阅创建原语。"),
        ("A process command line references a common Windows scripting interpreter.", "进程命令行引用了常见 Windows 脚本解释器。"),
        ("A process command line used DCOM-style MMC20/ShellWindows automation with a remote target and command interpreter payload.", "进程命令行使用 DCOM MMC20/ShellWindows 自动化、远程目标和命令解释器载荷；用于补强无文件远程管理/横向移动证据。"),
        ("A process command line used odbcconf.exe REGSVR syntax with a DLL under a user-writable path, matching a constrained LOLBin proxy-execution pattern.", "进程命令行使用 odbcconf.exe REGSVR 语法并指向用户可写路径下的 DLL，是受约束的 LOLBin 代理执行模式。"),
        ("A process command line used PowerShell encoded-command switches or short aliases frequently used to conceal script payloads.", "进程命令行使用 PowerShell encoded-command 开关或短别名，这些常用于隐藏脚本载荷。"),
        ("A process command line used reg save or shadow-copy helpers against credential-bearing registry hives.", "进程命令行对承载凭据的注册表 hive 使用 reg save 或卷影副本辅助工具。"),
        ("A process command line used regsvr32 scriptlet-loading patterns such as scrobj.dll or remote /i: URLs.", "进程命令行使用 scrobj.dll 或远程 /i: URL 等 regsvr32 scriptlet 加载模式。"),
        ("A process launch references an executable or script while event data records Zone.Identifier Mark-of-the-Web evidence.", "进程启动引用可执行文件或脚本，同时事件数据记录 Zone.Identifier Mark-of-the-Web 证据。"),
        ("A process launched from a user download, temporary, public, or ProgramData staging path commonly used after payload transfer.", "进程从用户下载、临时、Public 或 ProgramData 暂存路径启动，这常见于载荷传输后执行。"),
        ("A process start command line launched from Temp, AppData, Downloads, ProgramData, Public, or Recycle Bin style staging locations.", "进程启动命令行来自 Temp、AppData、Downloads、ProgramData、Public 或回收站等暂存位置。"),
        ("A process, driver, or API event referenced opening or reading lsass.exe, a common precursor to credential dumping.", "进程、驱动或 API 事件引用打开或读取 lsass.exe，这是凭据转储的常见前置行为。"),
        ("A process-tree node carried child-count metadata for triage of unusually broad sample lineage fan-out.", "进程树节点携带 child-count 元数据，用于分诊异常宽的样本谱系扇出。"),
        ("A process-tree row shows a descendant process executing from a user-writable payload path with root, parent, depth, and lineage fields present, reducing ambiguity compared with a standalone process path.", "进程树行显示子孙进程从用户可写载荷路径执行，并包含 root、parent、depth 和 lineage 字段，相比单独进程路径更少歧义。"),
        ("A reg.exe command modified a remote registry path under Run/RunOnce or Services, combining remote administration with persistence evidence.", "reg.exe 命令修改远程 Run/RunOnce 或 Services 注册表路径，结合了远程管理和持久化证据。"),
        ("A registry creation or update targeted a Windows Run or RunOnce autostart key.", "注册表创建或更新命中了 Windows Run/RunOnce 自启动键。"),
        ("A registry event modified Windows Defender policy values associated with disabled protections or exclusions.", "注册表事件修改与禁用保护或排除项相关的 Windows Defender 策略值。"),
        ("A registry event targeted a Windows service configuration path, which can indicate service-based persistence or privilege escalation setup.", "注册表事件命中 Windows 服务配置路径，可能表示基于服务的持久化或提权准备。"),
        ("A registry event targeted COM class registration locations that can redirect execution through InprocServer32, LocalServer32, TreatAs, or ScriptletURL values.", "注册表事件命中可通过 InprocServer32、LocalServer32、TreatAs 或 ScriptletURL 重定向执行的 COM 类注册位置。"),
        ("A registry event targeted Image File Execution Options debugger configuration, a common event-triggered persistence and hijack location.", "注册表事件命中 Image File Execution Options 调试器配置，这是常见的事件触发持久化和劫持位置。"),
        ("A registry event targeted LSA authentication, security, or notification package values that can load credential-facing providers at boot or logon.", "注册表事件命中 LSA 身份验证、安全或通知包值，可在启动或登录时加载面向凭据的提供程序。"),
        ("A registry event targeted Task Scheduler cache keys used to register or hide scheduled-task persistence.", "注册表事件命中用于注册或隐藏计划任务持久化的 Task Scheduler 缓存键。"),
        ("A registry event targeted Windows AppInit DLL loading values used for event-triggered DLL persistence.", "注册表事件命中用于事件触发 DLL 持久化的 Windows AppInit DLL 加载值。"),
        ("A registry event targeted Winlogon Shell, Userinit, Notify, or helper DLL values used for logon persistence.", "注册表事件命中 Winlogon Shell、Userinit、Notify 或用于登录持久化的辅助 DLL 值。"),
        ("A registry event touched ms-settings, mscfile, exefile runas, or shell open command paths used by auto-elevate UAC bypass chains.", "注册表事件触及 ms-settings、mscfile、exefile runas 或 shell open command 等自动提权 UAC 绕过链常用路径。"),
        ("A registry event touched StartupApproved Run/Run32 state, which can re-enable disabled autostart entries or hide Run-key state changes.", "注册表事件触及 StartupApproved Run/Run32 状态，可能重新启用被禁用的自启动项或隐藏 Run 键状态变化。"),
        ("A registry modification targeted AppCertDlls, which can force DLL loading into processes that call CreateProcess-family APIs.", "注册表修改指向 AppCertDlls，可在进程调用 CreateProcess 系列 API 时强制加载 DLL。"),
        ("A registry modification targeted LSA Authentication Packages, Security Packages, or Notification Packages, which can load attacker-controlled DLLs during logon.", "注册表修改指向 LSA Authentication Packages、Security Packages 或 Notification Packages，可能在登录期间加载攻击者控制的 DLL。"),
        ("A registry modification targeted W32Time TimeProviders DLL or Enabled values, a service-loaded DLL persistence mechanism.", "注册表修改指向 W32Time TimeProviders 的 DLL 或 Enabled 值，这是由服务加载 DLL 的持久化机制。"),
        ("A registry or driver registry event configured a Windows Time Provider DLL under W32Time to a user-writable DLL path, a durable service-hosted persistence point.", "注册表事件将 W32Time 时间提供程序 DLL 指向用户可写路径，属于服务宿主持久化入口。"),
        ("A registry or driver registry event referenced WMI permanent event subscription artifacts such as filters, consumers, or bindings.", "注册表或驱动注册表事件引用 WMI 永久事件订阅痕迹，例如过滤器、消费者或绑定。"),
        ("A registry or file event touched Windows Root/SystemCertificates certificate store paths.", "注册表或文件事件触及 Windows Root/SystemCertificates 证书存储路径。"),
        ("A registry query or driver registry event touched hardware, BIOS, ACPI, PCI, or hypervisor-identifying registry paths.", "注册表查询或驱动注册表事件触及硬件、BIOS、ACPI、PCI 或可识别虚拟机管理器的注册表路径。"),
        ("A registry write changed SCRNSAVE.EXE or nearby desktop screensaver settings to a user-writable SCR/EXE path.", "注册表写入将 SCRNSAVE.EXE 或相邻屏保设置改为用户可写目录中的 SCR/EXE 路径。"),
        ("A registry write disabled PowerShell ScriptBlock, Module, or Transcription logging through policy values.", "注册表写入通过策略值禁用 PowerShell ScriptBlock、Module 或 Transcription 日志。"),
        ("A registry write enabled LocalAccountTokenFilterPolicy, allowing local administrator accounts to receive full tokens over remote connections.", "注册表写入启用 LocalAccountTokenFilterPolicy，使本地管理员账户可通过远程连接获得完整令牌。"),
        ("A registry write enables IFEO GlobalFlag silent-exit monitoring, often paired with SilentProcessExit MonitorProcess persistence.", "注册表写入启用 IFEO GlobalFlag 静默退出监控，常与 SilentProcessExit MonitorProcess 持久化配合使用。"),
        ("A registry write registered a browser Native Messaging Host manifest pointing at user-writable script or executable content.", "注册表写入注册浏览器 Native Messaging Host 清单，并指向用户可写脚本或可执行内容。"),
        ("A registry write registered a Netsh helper DLL, especially when the DLL path is user-writable or newly dropped.", "注册表写入注册了 Netsh helper DLL，尤其是 DLL 位于用户可写或新投放路径；排查 DLL 来源、签名和关联进程。"),
        ("A registry write set the user windir environment value to a shell, script interpreter, LOLBin, or executable payload used by SilentCleanup UAC bypass chains.", "注册表写入将用户 windir 环境变量设置为 shell、脚本解释器、LOLBin 或可执行载荷，可用于 SilentCleanup UAC 绕过链。"),
        ("A registry write set WinDefend, WdNisSvc, or Sense service Start values to the disabled service-start value.", "注册表写入将 WinDefend、WdNisSvc 或 Sense 服务的 Start 值设置为禁用服务启动值。"),
        ("A registry write targeted Active Setup StubPath, which can run commands when users log on.", "注册表写入指向 Active Setup StubPath，可能在用户登录时运行命令。"),
        ("A registry write targeted AppInit_DLLs or LoadAppInit_DLLs, an application initialization DLL loading persistence mechanism.", "注册表写入指向 AppInit_DLLs 或 LoadAppInit_DLLs，这是应用初始化 DLL 加载类持久化机制。"),
        ("A registry write targeted Print Monitors Driver values, which can load a monitor DLL through the print spooler service.", "注册表写入指向 Print Monitors Driver 值，可通过打印后台处理程序服务加载监视器 DLL。"),
        ("A registry write targeted Session Manager BootExecute, which can execute native images during boot before normal user-mode startup.", "注册表写入指向 Session Manager BootExecute，可能在正常用户态启动前的引导阶段执行原生映像。"),
        ("A registry write targets a RunOnceEx Depend value that can load a DLL during legacy logon/install processing.", "注册表写入指向 RunOnceEx Depend 值，该值可在旧版登录或安装处理期间加载 DLL。"),
        ("A registry write touched Browser Helper Object, toolbar, or URLSearchHooks paths with user-writable or script-capable payload evidence.", "注册表写入触及 BHO、工具栏或 URLSearchHooks 路径，并包含用户可写或脚本型载荷证据。"),
        ("A registry write under CLSID InprocServer32 points a COM server DLL to AppData, Temp, ProgramData, Public, or Downloads.", "CLSID InprocServer32 下的注册表写入将 COM 服务端 DLL 指向 AppData、Temp、ProgramData、Public 或 Downloads。"),
        ("A registry write under Microsoft Windows CurrentVersion App Paths points an executable resolution entry to a user-writable path.", "Microsoft Windows CurrentVersion App Paths 下的注册表写入把可执行解析项指向用户可写路径；排查是否通过应用路径劫持实现持久化或代理执行。"),
        ("A registry write weakened UAC prompts or secure desktop behavior by setting known risky Policies\\System values.", "注册表写入设置已知高风险的 Policies\\System 值，削弱 UAC 提示或安全桌面行为。"),
        ("A remote thread, API, or image-load event referenced LoadLibrary/LdrLoadDll style DLL loading often used for DLL injection.", "远程线程、API 或镜像加载事件引用 LoadLibrary/LdrLoadDll 风格 DLL 加载，常用于 DLL 注入。"),
        ("A Run or RunOnce registry write points to a user-writable executable/script payload and carries dropped-file or download-execute correlation context.", "Run 或 RunOnce 注册表写入指向用户可写位置的可执行/脚本负载，并带有投放文件或下载执行关联上下文。"),
        ("A Run/RunOnce autostart registry value points at Temp, AppData, ProgramData, Public, Downloads, or another user-writable staging path.", "Run/RunOnce 自启动注册表值指向 Temp、AppData、ProgramData、Public、Downloads 或其他用户可写暂存路径。"),
        ("A Run/RunOnce autostart value launches PowerShell, Windows Script Host, mshta, rundll32, regsvr32, cmd, or another proxy-execution utility.", "Run/RunOnce 自启动值启动 PowerShell、Windows Script Host、mshta、rundll32、regsvr32、cmd 或其他代理执行工具。"),
        ("A rundll32 command line referenced an HTTP(S) URL, INetCache, Content.IE5, or a user-writable DLL path.", "rundll32 命令行引用 HTTP(S) URL、INetCache、Content.IE5 或用户可写 DLL 路径。"),
        ("A rundll32 command referenced HTTP/HTTPS script, mshtml, JavaScript, or URL execution patterns rather than a local benign DLL invocation.", "rundll32 命令引用 HTTP/HTTPS 脚本、mshtml、JavaScript 或 URL 执行模式，而非本地良性 DLL 调用。"),
        ("A scheduled-task file, registry, or inventory event references a task target under Temp, AppData, ProgramData, Public, or Downloads.", "计划任务文件、注册表或清单事件引用 Temp、AppData、ProgramData、Public 或 Downloads 下的任务目标。"),
        ("A scheduled-task registry or inventory event referenced a COM handler action or CLSID-backed task execution path.", "计划任务注册表或清单事件引用 COM handler 动作或基于 CLSID 的任务执行路径。"),
        ("A schtasks command created a logon, startup, idle, minute, or daily task whose action points to an executable or script in a user-writable staging path.", "schtasks 命令创建登录、启动、空闲、分钟或每日触发的任务，动作指向用户可写可执行/脚本载荷；排查任务名、触发器和目标路径。"),
        ("A schtasks command targeted a remote host with /S plus /U or /P and created, changed, or ran a task.", "schtasks 命令使用 /S 指向远程主机，并带有 /U 或 /P 创建、修改或运行任务。"),
        ("A schtasks command used a remote /S target together with create/run/change switches.", "schtasks 命令同时使用远程 /S 目标以及创建、运行或修改开关。"),
        ("A screen-saver registry value was configured to launch an executable or script from a user-writable location.", "屏保注册表值被设置为从用户可写位置启动可执行文件或脚本。"),
        ("A script interpreter or LOLBin command executes a user-downloaded script/HTA/LNK with Zone.Identifier evidence instead of relying on a bare command substring.", "脚本解释器或 LOLBin 命令执行带 Zone.Identifier 证据的用户下载脚本/HTA/LNK，而不是仅依赖宽泛命令子串。"),
        ("A service configuration path references an executable or DLL under Temp, AppData, ProgramData, Public, or Downloads, indicating service persistence or hijack risk.", "服务配置路径引用 Temp、AppData、ProgramData、Public 或 Downloads 下的 EXE/DLL，提示服务持久化或劫持风险。"),
        ("A service ImagePath-like value references Program Files style paths; analysts should verify quoting because unquoted service paths enable path interception.", "服务 ImagePath 类值引用 Program Files 风格路径；分析员应确认是否正确加引号，因为未加引号服务路径可能导致路径拦截。"),
        ("A service Parameters\\ServiceDll registry value points at a user-writable path, a pattern used by service DLL persistence.", "服务 Parameters\\ServiceDll 注册表值指向用户可写路径，这是服务 DLL 持久化常见模式。"),
        ("A service registry change used a user-writable executable/script path in ImagePath or value data, matched by regex.", "服务注册表变更在 ImagePath 或 value 数据中使用用户可写的可执行/脚本路径，由正则匹配。"),
        ("A service registry ImagePath value referenced common PsExec or remote execution service names and staging paths.", "服务注册表 ImagePath 值引用了常见 PsExec 或远程执行服务名称和暂存路径。"),
        ("A service registry or inventory event modified failure-command settings, which can execute attacker-controlled commands when a service fails.", "服务注册表或清单事件修改失败命令设置，服务失败时可能执行攻击者控制的命令。"),
        ("A service registry path changed executable, DLL, or failure-command values commonly used to install or hijack Windows services.", "服务注册表路径修改了常用于安装或劫持 Windows 服务的可执行文件、DLL 或失败命令值。"),
        ("A SilentProcessExit MonitorProcess registry value was written with an executable or script path in a user-writable location, a constrained IFEO persistence pattern.", "SilentProcessExit 的 MonitorProcess 注册表值被写入用户可写位置中的可执行或脚本路径，这是受约束的 IFEO 持久化模式。"),
        ("A sleep, timeout, or anti-analysis event carried duration fields used to triage time-based evasion evidence.", "sleep、timeout 或反分析事件携带用于分诊时间规避证据的时长字段。"),
        ("A Startup folder file event also referenced executable, shortcut, script, HTA, URL, or PowerShell payload extensions.", "Startup 文件夹文件事件同时引用可执行文件、快捷方式、脚本、HTA、URL 或 PowerShell 载荷扩展名。"),
        ("A summarized runtime row recorded SuspendThread/GetThreadContext/SetThreadContext/ResumeThread against a target process or thread.", "汇总运行时行记录了对目标进程或线程的 SuspendThread/GetThreadContext/SetThreadContext/ResumeThread 序列。"),
        ("A system-fingerprint or sandbox-check event exposed CPU, memory, disk, uptime, display, or user fields commonly inspected by sandbox-evasion logic. Treat this as low-confidence context unless paired with anti-analysis-low-resource-classification or an explicit API/check string.", "系统指纹或沙箱检查事件暴露了 CPU、内存、磁盘、运行时间、显示器或用户字段，这些字段常被反沙箱逻辑检查。除非同时出现 anti-analysis-low-resource-classification 或明确 API/检查字符串，否则按低置信上下文处理。"),
        ("A tscon command switches a numbered session to console or rdp-tcp from an elevated or SYSTEM-like context, a constrained RDP session hijack indicator.", "tscon 命令在高权限或 SYSTEM 类上下文中将编号会话切换到 console/rdp-tcp，是受约束的 RDP 会话劫持指标。"),
        ("A web protocol event referenced literal-IP hosts or nonstandard web ports worth surfacing in sandbox reports. This broad compatibility rule is triage metadata; prefer constrained rules such as http-direct-ip-missing-user-agent, pcap-http-host-header-ip-or-suspicious-tld, or explicit C2 labels when present.", "Web 协议事件引用了 IP 字面量主机或非常规 Web 端口，值得在沙箱报告中展示。该兼容规则属于宽泛分诊元数据；若存在 http-direct-ip-missing-user-agent、pcap-http-host-header-ip-or-suspicious-tld 或明确 C2 标签，应优先采用这些更强证据。"),
        ("A Windows Script Host process executed or staged a script from an HTTP(S) URL or web cache path.", "Windows Script Host 进程从 HTTP(S) URL 或 Web 缓存路径执行/暂存脚本；常见于下载执行和脚本化载荷启动链。"),
        ("A Windows service failure action command is configured to run an executable or script from a user-writable path, a persistence surface that is more specific than generic service edits.", "Windows 服务失败恢复动作被配置为从用户可写路径运行可执行文件或脚本，这是比普通服务修改更具体的持久化面。"),
        ("A Winsock provider catalog write carries a provider/library path under a user-writable directory, a constrained network-triggered persistence signal.", "Winsock provider catalog 写入携带用户可写目录下的 provider/library 路径，是受约束的网络触发持久化信号。"),
        ("A WMIC command used /node targeting together with process creation syntax, indicating remote command execution rather than local WMI inventory.", "WMIC 命令同时使用 /node 目标和进程创建语法，表示远程命令执行而非本地 WMI 盘点。"),
        ("A WMIC command used remote node and credential switches with process call create, indicating remote execution setup rather than local discovery.", "WMIC 命令同时使用远程节点、凭据开关和 process call create，表示远程执行准备，而非本地发现。"),
        ("Active Setup StubPath persistence", "Active Setup StubPath 持久化"),
        ("Admin share or remote copy command", "管理共享或远程复制命令"),
        ("All-access handle to sensitive process", "获取敏感进程全访问句柄"),
        ("AMSI or ETW bypass command string", "AMSI 或 ETW 绕过命令字符串"),
        ("An anti-analysis row combines debugger-detection API or PEB checks with an exit, sleep, or delayed-execution action.", "反分析事件将调试器检测 API 或 PEB 检查与退出、睡眠或延迟执行动作组合出现。"),
        ("An API event referenced window, process, module, or debugger enumeration primitives often used to detect analysis tools.", "API 事件引用窗口、进程、模块或调试器枚举原语，这些常用于检测分析工具。"),
        ("An API or anti-analysis event referenced CPU, hypervisor, or native system information checks used for sandbox fingerprinting.", "API 或反分析事件引用用于沙箱指纹识别的 CPU、虚拟机管理器或原生系统信息检查。"),
        ("An archive extraction command or normalized staging event writes script-like content to a user-writable directory, useful as staging evidence but lower severity without immediate execution correlation.", "归档解压命令或规范化暂存事件将脚本类内容写入用户可写目录；若缺少立即执行关联，则作为较低严重度的暂存证据。"),
        ("An event referenced cross-process allocation or memory-write APIs frequently used for process injection.", "事件引用常用于进程注入的跨进程分配或内存写入 API。"),
        ("An event referenced remote-thread, APC, or Windows hook primitives frequently used to execute code in another process.", "事件引用常用于在另一进程中执行代码的远程线程、APC 或 Windows Hook 原语。"),
        ("An event referenced suspended process creation, image unmapping, context manipulation, or resume patterns associated with process hollowing.", "事件引用挂起进程创建、映像解除映射、上下文操纵或恢复执行等与进程空洞化相关的模式。"),
        ("An Image File Execution Options verifier DLL registry value was written to a user-writable DLL path, a constrained IFEO persistence and abuse surface.", "Image File Execution Options 的 VerifierDll 注册表值被写入为用户可写 DLL 路径，是受约束的 IFEO 持久化/滥用信号。"),
        ("An Office Security registry write enabled risky macro, VBA object model, or Protected View bypass settings.", "Office Security 注册表写入启用高风险宏、VBA 对象模型访问或 Protected View 绕过设置。"),
        ("An Outlook registry write referenced custom forms, web views, home pages, or script-capable URLs used for Office persistence.", "Outlook 注册表写入引用自定义表单、Web View、主页或可执行脚本的 URL，可用于 Office 持久化。"),
        ("An R0 image-load callback row included image or module path metadata for report correlation with process and driver activity.", "R0 镜像加载回调行包含镜像或模块路径元数据，可用于关联进程和驱动活动。"),
        ("Analysis or security tool termination command", "分析或安全工具终止命令"),
        ("Analysis tool process discovery", "分析工具进程发现"),
        ("Analysis tool window or process check API", "分析工具窗口或进程检查 API"),
        ("Analysis window-title check gates execution", "分析工具窗口标题检查控制执行"),
        ("Anti-analysis API imports or strings", "反分析 API 导入或字符串"),
        ("Anti-analysis evidence reported mouse, keyboard, click, cursor, or foreground-window checks tied to an exit or delayed-execution gate.", "反分析证据报告鼠标、键盘、点击、光标或前台窗口检查，并与退出或延迟执行门控相关。"),
        ("Anti-analysis telemetry combined debugger-check APIs or labels with an exit, terminate, sleep, or gate action.", "反分析遥测将调试器检测 API 或标签与退出、终止、休眠或门控动作结合。"),
        ("Anti-analysis telemetry combined low CPU and memory thresholds with an explicit exit, delay, or gate action.", "反分析遥测同时包含低 CPU/内存阈值和明确的退出、延迟或门控动作；避免把普通系统信息采集直接提升为高危行为。"),
        ("Anti-analysis telemetry combines VM/sandbox check text with a long sleep duration, indicating a sandbox gate rather than a standalone timeout.", "反分析遥测同时包含 VM/沙箱检查文本和长时间休眠，表明这是沙箱门控而非单独超时。"),
        ("Anti-analysis telemetry records an uptime check below ten minutes combined with exit, terminate, sleep, delay, or gate behavior.", "反分析遥测记录低于十分钟的 uptime 检查，并伴随退出、终止、睡眠、延迟或门控行为。"),
        ("Anti-analysis telemetry reports device or driver object probing for virtualization/sandbox artifacts tied to an exit, abort, or suppression gate.", "反分析遥测报告针对虚拟化/沙箱设备或驱动对象的探测，并与退出、中止或抑制门控关联。"),
        ("Anti-analysis telemetry shows enumeration of VM/sandbox tools, services, drivers, or processes tied to an exit/sleep/abort gate.", "反分析遥测显示枚举 VM/沙箱工具、服务、驱动或进程，并与退出/休眠/中止门控关联。"),
        ("Anti-analysis telemetry shows window or desktop enumeration matching analysis-tool names and driving an exit, sleep, or suppression gate.", "反分析遥测显示窗口或桌面枚举命中分析工具名称，并触发退出、休眠或抑制门控。"),
        ("Anti-sandbox evidence checked VMware, VirtualBox, QEMU, Hyper-V, or sandbox service/registry artifacts and used the result to exit or gate behavior.", "反沙箱证据检查 VMware、VirtualBox、QEMU、Hyper-V 或沙箱服务/注册表痕迹，并据此退出或门控行为。"),
        ("Anti-sandbox or debugger string", "反沙箱或调试器字符串"),
        ("Anti-sandbox telemetry combined VM/vendor artifact checks with a long requested sleep or delay gate.", "反沙箱遥测将 VM/厂商痕迹检查与长时间请求休眠或延迟门控结合。"),
        ("API or memory telemetry reported transacted file/section primitives such as NtCreateTransaction, CreateFileTransacted, TxF, rollback, or doppelgänging labels.", "API 或内存遥测报告 NtCreateTransaction、CreateFileTransacted、TxF、rollback 或 doppelgänging 等事务文件/Section 原语；排查是否随后创建挂起进程或映射可执行 Section。"),
        ("API or named-pipe telemetry reported ImpersonateNamedPipeClient/RpcImpersonateClient with a pipe name, a high-signal token impersonation pattern when emitted by API monitors.", "API 或命名管道遥测报告 ImpersonateNamedPipeClient/RpcImpersonateClient 且包含管道名；当由 API 监控产生时，这是高信号的令牌模拟模式。"),
        ("API or normalized injection evidence contained transactional file creation plus section creation and process creation context consistent with process doppelgänging-style execution.", "API 或注入证据同时包含事务文件、节创建和进程创建上下文，符合 Process Doppelgänging 类执行链。"),
        ("API or thread telemetry referenced QueueUserAPC/NtQueueApcThread with target-process context, consistent with APC or early-bird injection chains.", "API 或线程遥测在目标进程上下文中引用 QueueUserAPC/NtQueueApcThread，符合 APC 或 early-bird 注入链。"),
        ("API or thread telemetry reported QueueUserAPC/NtQueueApcThread against another process or thread, a common APC injection primitive.", "API 或线程遥测报告对其他进程或线程调用 QueueUserAPC/NtQueueApcThread，这是常见 APC 注入原语。"),
        ("API telemetry records atom-table writes paired with APC or remote thread execution primitives, a defensive signal for AtomBombing-style injection.", "API 遥测记录 Atom 表写入并伴随 APC 或远程线程执行原语，是 AtomBombing 风格注入的防御信号。"),
        ("API telemetry referenced ProcessDebugPort, ProcessDebugObjectHandle, ProcessDebugFlags, or ThreadHideFromDebugger checks.", "API 遥测引用 ProcessDebugPort、ProcessDebugObjectHandle、ProcessDebugFlags 或 ThreadHideFromDebugger 检查。"),
        ("API telemetry referenced thread context, debug registers, hardware breakpoints, or trap flag checks used to detect debuggers.", "API 遥测引用线程上下文、调试寄存器、硬件断点或陷阱标志检查，用于检测调试器。"),
        ("API telemetry referenced token duplication, impersonation, or token-based process creation primitives used for privilege escalation and lateral movement.", "API 遥测引用令牌复制、模拟或基于令牌创建进程的原语，可用于提权和横向移动。"),
        ("API telemetry reported MiniDumpWriteDump, RtlCaptureContext, or dump creation targeting lsass.exe or an LSASS-like process context.", "API 遥测报告 MiniDumpWriteDump、RtlCaptureContext 或 dump 创建目标为 lsass.exe/LSASS 语境；排查 dump 文件路径、调用进程和是否随后压缩/上传。"),
        ("API, memory, or driver process telemetry reported direct-syscall, syscall-stub, SysWhispers, HellsGate/HalosGate, or NTDLL unhooking evidence used to bypass user-mode monitoring before injection.", "API、内存或驱动进程遥测报告 direct syscall、syscall stub、SysWhispers、HellsGate/HalosGate 或 NTDLL 反 Hook 证据，常用于绕过用户态监控后执行注入；优先查看目标进程和后续远程写/线程事件。"),
        ("API, R0, or anti-analysis telemetry reported CPUID hypervisor bit or VM vendor checks.", "API、R0 或反分析遥测报告 CPUID hypervisor 位或虚拟机厂商检查。"),
        ("API-sequence or injection telemetry links remote process allocation/write/thread creation to LoadLibrary of a user-writable DLL.", "API 序列或注入遥测将远程进程分配/写入/建线程与加载用户可写 DLL 关联。"),
        ("API-sequence telemetry reports a suspended process hollowing chain with image unmap, remote allocation/write, thread-context update, and resume.", "API 序列遥测报告挂起进程空洞化链，包含映像解除映射、远程分配/写入、线程上下文更新和恢复执行。"),
        ("App Paths registry hijack to user-writable executable", "App Paths 注册表劫持到用户可写可执行文件"),
        ("AppCert DLLs registry persistence", "AppCert DLLs 注册表持久化"),
        ("AppInit DLLs persistence path", "AppInit DLLs 持久化路径"),
        ("AppInit DLLs persistence registry value", "AppInit DLLs 持久化注册表值"),
        ("Archive extraction stages executable script in user-writable path", "归档解压在用户可写路径落地可执行脚本"),
        ("Archive or installer spawned user-writable payload", "压缩包或安装器衍生用户可写载荷进程"),
        ("Artifact evidence matrix includes downloadable selectors", "证据矩阵包含可下载选择器"),
        ("AtomBombing-style APC atom API sequence", "AtomBombing 风格 APC/Atom API 序列"),
        ("Auto-elevate UAC bypass LOLBin launched", "启动自动提权 UAC 绕过 LOLBin"),
        ("Auto-elevate UAC bypass registry path", "自动提权 UAC 绕过注册表路径"),
        ("Beacon timing tied to SNI, JA3, and user-writable process", "Beacon 周期与 SNI、JA3、用户可写进程关联"),
        ("Behavior metadata indicates execution was gated on a low mouse, keyboard, or foreground-window interaction count.", "行为元数据显示执行受到低鼠标、键盘或前台窗口交互计数的门控。"),
        ("BITS job NotifyCmdLine user-writable payload", "BITS NotifyCmdLine 指向用户可写载荷"),
        ("BITS notify command executes staged payload", "BITS notify 命令执行暂存载荷"),
        ("BITSAdmin transfer download command", "BITSAdmin 传输下载命令"),
        ("Boot recovery policy disables recovery prompts", "启动恢复策略禁用恢复提示"),
        ("BootExecute registry persistence modified", "BootExecute 注册表持久化被修改"),
        ("Browser credential database copied by command line", "命令行复制浏览器凭据数据库"),
        ("Browser credential store access", "浏览器凭据存储访问"),
        ("Browser extension force-install policy", "浏览器扩展强制安装策略"),
        ("Browser native messaging host manifest file", "浏览器 Native Messaging Host 清单文件"),
        ("Browser native messaging host registry", "浏览器 Native Messaging Host 注册表"),
        ("Browser or download cache file write", "浏览器或下载缓存文件写入"),
        ("C2 indicator fields in network telemetry", "网络遥测中的 C2 指示字段"),
        ("Certutil URL cache download command", "Certutil URL cache 下载命令"),
        ("Certutil URL cache download followed by user-writable launch", "Certutil URL 缓存下载后启动用户可写载荷"),
        ("Certutil URL cache download to staging path", "Certutil URL 缓存下载到暂存路径"),
        ("Chromium cookie database accessed by non-browser process", "非浏览器进程访问 Chromium Cookie 数据库"),
        ("Cmstp is launched with quiet/install style switches and a remote or user-writable INF path, indicating signed-binary proxy execution rather than normal connection-manager administration.", "cmstp 以静默或安装类参数加载远程或用户可写 INF，偏向签名二进制代理执行，而不是常规连接管理配置。"),
        ("CMSTP profile proxy execution command", "CMSTP 配置文件代理执行命令"),
        ("CMSTP remote or user-writable INF proxy execution", "CMSTP 远程或用户可写 INF 代理执行"),
        ("COM class hijack persistence path", "COM 类劫持持久化路径"),
        ("COM CLSID ScriptletURL or scrobj hijack points remote code", "COM CLSID ScriptletURL 或 scrobj 劫持指向远程代码"),
        ("COM InprocServer32 hijack points to user-writable path", "COM InprocServer32 劫持指向用户可写路径"),
        ("COM registration export entry point", "COM 注册导出入口点"),
        ("Command and Scripting Interpreter", "命令与脚本解释器"),
        ("Command and scripting interpreter", "命令或脚本解释器"),
        ("Command-line sandbox or analysis artifact lookup", "命令行沙箱或分析痕迹查找"),
        ("Command-line sleep or delay for anti-analysis", "反分析命令行睡眠或延迟"),
        ("Control Panel item proxy execution command", "控制面板项代理执行命令"),
        ("CPU or hypervisor check API observed", "观察到 CPU 或虚拟机管理器检查 API"),
        ("CPUID hypervisor or vendor check observed", "检测到 CPUID Hypervisor 或厂商检查"),
        ("CreateRemoteThread LoadLibrary user-writable DLL injection", "CreateRemoteThread LoadLibrary 用户可写 DLL 注入"),
        ("Credential dumping tool command", "凭据转储工具命令"),
        ("Credential store access observed", "观察到凭据存储访问"),
        ("Credential-access API imports", "凭据访问 API 导入"),
        ("Credential-themed file search in user profile", "在用户配置文件中搜索凭据相关文件"),
        ("Credential-themed files archived for staging", "凭据主题文件被压缩暂存"),
        ("Cross-process memory injection primitive", "跨进程内存注入原语"),
        ("Curl download to user-writable path", "Curl 下载到用户可写路径"),
        ("Curl or Wget download chained to execution", "Curl/Wget 下载后链式执行"),
        ("DCOM activation telemetry names a remote host and ShellWindows/ShellBrowserWindow class used to launch a script interpreter or user-writable payload.", "DCOM 激活遥测包含远程主机，并使用 ShellWindows/ShellBrowserWindow 类启动脚本解释器或用户可写载荷。"),
        ("DCOM MMC20 remote command execution", "DCOM MMC20 远程命令执行"),
        ("DCOM ShellWindows remote script launch", "DCOM ShellWindows 远程脚本启动"),
        ("Debug object or debug flag query", "查询调试对象或调试标志"),
        ("Debug register or breakpoint check API", "调试寄存器或断点检查 API"),
        ("Debugger check gates exit or delayed execution", "调试器检查触发退出或延迟执行"),
        ("Debugger detected before exit or delay gate", "检测到调试器后退出或延迟门控"),
        ("Debugger or sandbox check observed", "观察到调试器或沙箱检查"),
        ("Defender exclusion added for dropped payload path", "为投放负载路径添加 Defender 排除项"),
        ("Defender exclusion for user-writable path", "Defender 用户可写路径排除项"),
        ("Defender policy registry disable setting", "Defender 策略注册表禁用设置"),
        ("Defender real-time protection disabled value", "Defender 实时防护禁用值"),
        ("Defender service disabled in registry", "注册表禁用 Defender 服务"),
        ("Defense-evasion API imports", "防御规避 API 导入"),
        ("Delete-pending image mutation before process creation", "进程创建前出现 delete-pending 镜像变形"),
        ("Direct syscall or NTDLL unhooking injection evidence", "Direct syscall 或 NTDLL 反 Hook 注入证据"),
        ("DLL image loaded from user-writable path", "从用户可写路径加载 DLL 镜像"),
        ("DNS answer resolves to private or loopback scope", "DNS 应答解析到私有或回环范围"),
        ("DNS answer scope suggests fast-flux style rotation", "DNS 应答范围提示 fast-flux 式轮转"),
        ("DNS base64-like high-entropy label exfiltration", "DNS Base64 风格高熵标签外传"),
        ("DNS fast-flux style low-TTL multi-answer response", "DNS fast-flux 风格低 TTL 多应答"),
        ("DNS high-entropy subdomain metadata", "DNS 高熵子域名元数据"),
        ("DNS metadata reported a very long query name with NXDOMAIN or DGA/tunnel classification using numeric and regex predicates.", "DNS 元数据通过数值与正则谓词报告超长查询名以及 NXDOMAIN 或 DGA/隧道分类。"),
        ("DNS or PCAP metadata reported fast-flux classification or many answers together with low TTL values.", "DNS 或 PCAP 元数据报告 fast-flux 分类，或多应答并伴随低 TTL 值。"),
        ("DNS or PCAP rows show many public or multi-ASN answers with a low TTL for one queried name, a bounded semantic-field signal for rotating command infrastructure.", "DNS 或 PCAP 行显示单个查询名存在多个 public/multi-ASN 应答且 TTL 较低，这是轮转型命令基础设施的有界语义字段信号。"),
        ("DNS or PCAP telemetry reported a long base64/base32-like query label together with high entropy or long-query metadata, consistent with DNS tunneling or exfiltration.", "DNS 或 PCAP 遥测报告长 Base64/Base32 风格查询标签，并伴随高熵或长查询元数据，符合 DNS 隧道/外传形态；排查查询域、标签长度和请求频率。"),
        ("DNS or PCAP telemetry reported TXT queries or long encoded labels commonly associated with DNS tunneling or exfiltration.", "DNS 或 PCAP 遥测报告 TXT 查询或长编码标签，常见于 DNS 隧道或外传。"),
        ("DNS query observed", "观察到 DNS 查询"),
        ("DNS query to dynamic or disposable domain pattern", "DNS 查询命中动态或一次性域名模式"),
        ("DNS query to reputation-risk domain", "DNS 查询命中信誉风险域名"),
        ("DNS telemetry carried reputation labels for newly registered, suspicious, DGA, malware, or C2 domains.", "DNS 遥测携带新注册、可疑、DGA、恶意软件或 C2 域名信誉标签。"),
        ("DNS telemetry combined TXT/NULL-style record evidence with high-entropy, base64, encoded, long-label, tunnel, or DGA classification metadata.", "DNS 遥测同时包含 TXT/NULL 记录证据以及高熵、base64、编码、长标签、隧道或 DGA 分类元数据。"),
        ("DNS telemetry contained TXT/NULL/CNAME records, tunnel labels, DGA classification, or known DNS tunneling tool labels.", "DNS 遥测包含 TXT/NULL/CNAME 记录、隧道标签、DGA 分类或已知 DNS 隧道工具标签。"),
        ("DNS telemetry included label entropy, long-label, or query-length fields used to triage DGA or DNS-tunnel behavior.", "DNS 遥测包含标签熵、长标签或查询长度字段，可用于排查 DGA 或 DNS 隧道行为。"),
        ("DNS telemetry reported NXDOMAIN responses, DGA classification, high entropy, or an elevated unique-domain count.", "DNS 遥测报告 NXDOMAIN 响应、DGA 分类、高熵或较高唯一域名数量。"),
        ("DNS telemetry reports an answer scope such as RFC1918, loopback, link-local, or multicast for a queried name, which can indicate internal pivoting, rebinding, or sandbox-aware resolution when paired with process and PCAP evidence.", "DNS 遥测报告查询名的应答范围为 RFC1918、回环、链路本地或组播；与进程和 PCAP 证据结合时，可提示内网跳转、重绑定或沙箱感知解析。"),
        ("DNS tunnel or DGA indicator", "DNS 隧道或 DGA 指示"),
        ("DNS TXT/NULL high-entropy label", "DNS TXT/NULL 高熵标签"),
        ("DoH POST carrying high-entropy DNS query payload", "DoH POST 携带高熵 DNS 查询载荷"),
        ("DoH request carries high-entropy DNS query metadata", "DoH 请求携带高熵 DNS 查询元数据"),
        ("Domain-fronting TLS/HTTP correlation with risky JA3", "Domain fronting 与高风险 JA3 关联"),
        ("Download-capable API imports", "下载能力 API 导入"),
        ("Download-execute metadata ties a CAB/MSI/MSP package in a user temp or download cache path to package execution.", "download-execute 元数据将用户临时或下载缓存路径中的 CAB/MSI/MSP 包与包执行关联。"),
        ("Downloaded archive or script staged on disk", "下载的归档或脚本落盘暂存"),
        ("Downloaded artifact execution chain observed", "观察到下载产物执行链"),
        ("Downloaded artifact hash launched", "下载产物哈希随后被执行"),
        ("Downloaded CAB or MSI launched from temp staging", "从临时目录启动下载的 CAB/MSI 暂存文件"),
        ("Downloaded disk image or archive launches LNK/script payload", "下载的磁盘镜像或压缩包启动 LNK/脚本载荷"),
        ("Downloaded file executed from user-writable path without referrer", "无 Referrer 的用户可写路径下载执行"),
        ("Downloaded file executed with path correlation", "下载文件执行路径关联"),
        ("Downloaded file mark-of-the-web metadata", "下载文件 Mark-of-the-Web 元数据"),
        ("Driver or filesystem metadata reported a rename/set-information operation to common ransomware-style encrypted extensions.", "驱动或文件系统元数据报告将文件重命名/设置为常见勒索式加密扩展名。"),
        ("Driver telemetry reported a kernel network event, preserving WFP-style evidence for network triage.", "驱动遥测报告内核网络事件，保留 WFP 类网络分诊证据。"),
        ("Driver telemetry reported file write/set-information/rename/delete style operations outside known sandbox output paths and registry hive backing files. Treat this as R0 filesystem telemetry; confirm process attribution before escalating.", "驱动遥测报告已知沙箱输出路径和注册表 hive 后备文件之外的文件写入、设置信息、重命名或删除类操作。请作为 R0 文件系统遥测处理，并在升级前确认进程归属。"),
        ("Driver telemetry reported registry create, set, delete, or rename operations from kernel callback evidence.", "驱动遥测从内核回调证据报告注册表创建、设置、删除或重命名操作。"),
        ("Dropped executable artifact tied to source event", "释放的可执行产物关联到来源事件"),
        ("Dropped file artifact copied", "已复制落地文件证据"),
        ("Dropped file artifact copy skipped", "落地文件证据复制已跳过"),
        ("Dropped or modified file", "文件落地或修改"),
        ("Dropped-file artifact from script download", "脚本下载产生的投放文件工件"),
        ("Dropped-file artifact metadata ties a user-writable executable/script source path to a script or LOLBin downloader process and an HTTP(S) source URL.", "投放文件工件元数据将用户可写的可执行/脚本源路径与脚本或 LOLBin 下载进程以及 HTTP(S) 来源 URL 关联起来。"),
        ("Dynamic code loading or memory protection APIs", "动态代码加载或内存保护 API"),
        ("Dynamic DNS domain string", "动态 DNS 域名字符串"),
        ("Early-bird APC injection primitive", "Early-bird APC 注入原语"),
        ("Early-bird APC sequence into suspended target process", "面向挂起目标进程的 Early-bird APC 序列"),
        ("ECH/ESNI TLS with risky JA3 and no SNI", "无 SNI 且 JA3 高风险的 ECH/ESNI TLS"),
        ("Embedded credential-access string", "内嵌凭据访问字符串"),
        ("Embedded defense-evasion string", "内嵌防御规避字符串"),
        ("Embedded domain string observed", "观察到内嵌域名字符串"),
        ("Embedded download command string", "内嵌下载命令字符串"),
        ("Embedded IP-like string observed", "内嵌 IP 类字符串"),
        ("Embedded PE in resources", "资源中嵌入 PE"),
        ("Embedded persistence path or command string", "内嵌持久化路径或命令字符串"),
        ("Embedded registry path string", "内嵌注册表路径字符串"),
        ("Embedded script or interpreter command string", "内嵌脚本或解释器命令字符串"),
        ("Embedded upload or exfil command string", "内嵌上传或外传命令字符串"),
        ("Embedded URL string observed", "观察到内嵌 URL 字符串"),
        ("Embedded Windows path string", "内嵌 Windows 路径字符串"),
        ("Encoded PowerShell or script command string", "编码 PowerShell 或脚本命令字符串"),
        ("Encrypted-extension file rename", "重命名为加密扩展名"),
        ("Esentutl NTDS database copy command", "Esentutl 复制 NTDS 数据库命令"),
        ("Executable copied to administrative share", "可执行文件复制到管理共享"),
        ("Executable copied to remote admin share", "可执行文件复制到远程管理共享"),
        ("Executable dropped-file artifact copied", "已复制可执行落地文件证据"),
        ("Executable launched from user-writable staging path", "从用户可写暂存路径启动可执行文件"),
        ("Executable or script file written", "写入可执行或脚本文件"),
        ("Executable section mapped into remote process", "可执行节映射到远程进程"),
        ("Executable unbacked section mapped into process", "可执行匿名 Section 映射到进程"),
        ("Executable with Zone.Identifier alternate stream launched", "启动带 Zone.Identifier 备用流的可执行文件"),
        ("Executable writable memory protection change", "可执行可写内存保护变更"),
        ("Executable written to SMB administrative share", "可执行文件写入 SMB 管理共享"),
        ("Execution from download or staging path", "从下载或暂存路径执行"),
        ("Explicit C2 beacon event", "明确的 C2 Beacon 事件"),
        ("File activity metadata reported at least 100 writes plus ransomware/encryption classification or encrypted extension evidence.", "文件活动元数据报告至少 100 次写入，并带有勒索/加密分类或加密扩展名证据。"),
        ("File creation or dropper API imports", "文件创建或投放器 API 导入"),
        ("File deletion observed", "观察到文件删除"),
        ("File event classified as ransomware encryption", "文件事件被标记为勒索加密"),
        ("File telemetry reported creation of an executable, DLL, script, or service binary on an administrative share path such as ADMIN$, C$, or IPC$.", "文件遥测报告在 ADMIN$、C$ 或 IPC$ 等管理共享路径上创建可执行文件、DLL、脚本或服务二进制。"),
        ("File, registry, or driver telemetry touched Windows hives, domain database, browser stores, vaults, or password manager paths containing credential material.", "文件、注册表或驱动遥测触及包含凭据材料的 Windows hive、域数据库、浏览器存储、Vault 或密码管理器路径。"),
        ("File/process telemetry correlates image overwrite or delete-pending mutation with process creation from a user-writable image path.", "文件/进程遥测将镜像覆盖或 delete-pending 变形与来自用户可写镜像路径的进程创建关联起来。"),
        ("Firmware WMI VM check gates execution", "固件 WMI 虚拟机检查控制执行路径"),
        ("Flow metadata included beacon interval, jitter, or periodicity fields. Without explicit C2 classification or stronger constrained rules, this remains low-confidence timing context rather than primary C2 behavior.", "流量元数据包含信标间隔、抖动或周期性字段。若没有明确 C2 分类或更严格的关联规则，该命中仅作为低置信时间上下文，而不是主要 C2 行为。"),
        ("Flow or HTTP metadata carried periodicity fields plus explicit beacon/check-in/C2 classification, avoiding a match on timing fields alone.", "Flow 或 HTTP 元数据同时携带周期性字段以及明确的 beacon/check-in/C2 分类，避免仅凭时间字段命中。"),
        ("Flow or TLS metadata tied periodic C2/beacon timing, risky JA3 reputation, SNI, and a user-writable process path into one correlation row.", "流量或 TLS 元数据在同一关联行中包含周期性 C2/beacon 时间、风险 JA3 信誉、SNI 和用户可写进程路径；这是报告中可直接展开的强 C2 证据。"),
        ("Forfiles proxy execution with script child", "Forfiles 代理执行脚本子命令"),
        ("Granular static anti-debug capability", "结构化静态反调试能力"),
        ("Granular static download-execute capability", "结构化静态下载执行能力"),
        ("Granular static import, string, or YARA-like rows flagged download-execute capability fields. This remains static triage until runtime transfer or launch evidence appears.", "结构化静态导入、字符串或 YARA-like 行标记下载执行能力字段；在出现运行时传输或启动证据前仅作为静态分诊。"),
        ("Granular static process-injection capability", "结构化静态进程注入能力"),
        ("Granular static rows flagged anti-debug or anti-analysis capability fields. This is static triage and should not be promoted without runtime gating evidence.", "结构化静态行标记反调试或反分析能力字段；这是静态分诊，没有运行时门控证据时不应提升。"),
        ("Granular static rows flagged process-injection API clusters or capability fields. This is import/string triage, not observed injection.", "结构化静态行标记进程注入 API 集群或能力字段；这是导入/字符串分诊，不代表已观察到注入。"),
        ("Guest artifact manifest written", "已写入来宾证据清单"),
        ("Hardware or VM registry fingerprint query", "硬件或 VM 注册表指纹查询"),
        ("Hidden scheduled task with user-writable target", "隐藏计划任务指向用户可写目标"),
        ("Hidden staged script is launched by a LOLBin", "隐藏暂存脚本随后由 LOLBin 启动"),
        ("High access handle opened to LSASS", "对 LSASS 打开高权限句柄"),
        ("High entropy or abnormal PE sections", "高熵或异常 PE 节"),
        ("High-entropy PE overlay data", "高熵 PE Overlay 数据"),
        ("High-entropy resource data", "高熵资源数据"),
        ("Host identity sandbox check", "主机身份沙箱检查"),
        ("HTML Help remote script proxy execution", "HTML Help 远程脚本代理执行"),
        ("HTTP CONNECT tunnel with C2 or proxy classification", "带 C2/代理分类的 HTTP CONNECT 隧道"),
        ("HTTP direct-IP or nonstandard-port triage", "HTTP 直连 IP 或非常规端口线索"),
        ("HTTP executable download by content metadata", "基于内容元数据的 HTTP 可执行下载"),
        ("HTTP Host header IP literal or suspicious TLD", "HTTP Host 头为 IP 字面量或可疑 TLD"),
        ("HTTP host header mismatch indicator", "HTTP Host 头不匹配指示"),
        ("HTTP JSON tasking or gate URI", "HTTP JSON 任务或 Gate URI"),
        ("HTTP metadata combined POST with a large upload/request-body byte count using numeric ranges, a constrained exfiltration indicator.", "HTTP 元数据同时包含 POST 与较大上传/请求体字节数，是受约束的外传指标。"),
        ("HTTP metadata combined POST with authorization, cookie, bearer token, password, or session-token fields, a constrained web credential exfiltration signal.", "HTTP 元数据同时包含 POST 与 authorization、cookie、bearer token、password 或 session-token 字段，是受约束的 Web 凭据外传信号。"),
        ("HTTP metadata combines upload direction, transfer encoding or compression hints, and authentication/cookie material, indicating possible exfiltration or check-in upload activity.", "HTTP 元数据同时包含上传方向、传输编码或压缩提示，以及认证/Cookie 材料，提示可能的外传或 check-in 上传活动。"),
        ("HTTP metadata indicated Host/header, SNI, absolute URI, or upstream destination mismatch, useful for proxy, fronting, or evasive C2 triage.", "HTTP 元数据指示 Host/header、SNI、绝对 URI 或上游目的地不匹配，可用于代理、域前置或规避型 C2 排查。"),
        ("HTTP metadata referenced tasking, gate, panel, check-in, command, or polling URI/behavior patterns often seen in C2 protocols. JSON content type alone is handled by constrained companion rules and no longer matches this rule.", "HTTP 元数据引用 tasking、gate、panel、check-in、command 或 polling URI/行为模式，常见于 C2 协议。单独 JSON content-type 由受约束的配套规则处理，不再命中此规则。"),
        ("HTTP metadata reported a Host header using an IP literal, dynamic DNS provider, or suspicious low-reputation TLD.", "HTTP 元数据报告 Host 头使用 IP 字面量、动态 DNS 提供商或可疑低信誉 TLD。"),
        ("HTTP metadata shows a WebSocket upgrade to a concrete host/URI from a scripting, CLI, or automation user agent often used by implants.", "HTTP 元数据显示来自脚本、CLI 或自动化 User-Agent 的 WebSocket upgrade，且包含具体 host/URI，常见于植入体通信。"),
        ("HTTP metadata used an IPv4 literal host and omitted userAgent, combining regex and not-exists predicates for suspicious automation.", "HTTP 元数据使用 IPv4 字面量主机且缺少 userAgent，结合正则与不存在谓词识别可疑自动化流量。"),
        ("HTTP MZ payload launch correlation", "HTTP MZ 载荷启动关联"),
        ("HTTP or HTTPS activity observed", "观察到 HTTP 或 HTTPS 活动"),
        ("HTTP or PCAP metadata reported a CONNECT tunnel with proxy, tunnel, or C2 classification fields.", "HTTP 或 PCAP 元数据报告 CONNECT 隧道，并包含代理、隧道或 C2 分类字段。"),
        ("HTTP or PCAP metadata reported POST requests with beacon, periodicity, small body, or C2 classification fields.", "HTTP 或 PCAP 元数据报告 POST 请求，并带有 beacon、周期性、小请求体或 C2 分类字段。"),
        ("HTTP or PCAP metadata reported POST/PUT upload traffic with authorization, cookie, bearer token, password, or explicit exfil labels and a large outbound body size.", "HTTP 或 PCAP 元数据报告 POST/PUT 上传，包含 Authorization、Cookie、Bearer token、password 或 exfil 标签，并带有较大出站 body；排查目标域名、路径和载荷大小。"),
        ("HTTP or PCAP metadata shows a WinRM WSMan CreateShell action over a remote management endpoint.", "HTTP 或 PCAP 元数据展示通过远程管理端点执行 WinRM WSMan CreateShell 动作。"),
        ("HTTP or PCAP telemetry reported executable, DLL, script, MSI, or PE magic content in an HTTP response.", "HTTP 或 PCAP 遥测在 HTTP 响应中报告可执行文件、DLL、脚本、MSI 或 PE 魔数内容。"),
        ("HTTP POST beacon with periodic small payload metadata", "HTTP POST 周期性小载荷 Beacon 元数据"),
        ("HTTP POST JSON tasking pattern", "HTTP POST JSON 任务下发模式"),
        ("HTTP POST with credential or token material", "HTTP POST 携带凭据或令牌材料"),
        ("HTTP request to direct IP without User-Agent", "无 User-Agent 的直连 IP HTTP 请求"),
        ("HTTP telemetry carries transfer metadata indicating an executable, script, archive, or DLL payload, using structured content type, disposition, extension, or magic hints rather than raw packet text.", "HTTP 遥测携带内容类型、Content-Disposition、扩展名或 magic 等结构化传输元数据，指向 EXE、脚本、归档或 DLL 载荷，而非依赖原始包文本。"),
        ("HTTP telemetry combined a script/library user agent with explicit beacon, gate, tasking, panel, or check-in URI evidence, avoiding a match on user agent alone.", "HTTP 遥测同时包含脚本/库 User-Agent 与明确的 beacon、gate、tasking、panel 或 check-in URI，避免仅凭 User-Agent 命中。"),
        ("HTTP telemetry combined POST, JSON/octet-stream content, and tasking/check-in URI labels. Generic POST requests alone are excluded.", "HTTP 遥测同时包含 POST、JSON/octet-stream 内容以及任务下发/check-in URI 标签；普通 POST 请求不会单独命中。"),
        ("HTTP telemetry reported script, library, legacy, or command-line user agents commonly seen in automated beacons and downloaders. User-agent evidence alone is low-confidence triage; constrained C2 rules require URI, tasking, or classification context.", "HTTP 遥测报告脚本、库、旧版或命令行 User-Agent，这些常见于自动化 Beacon 和下载器。User-Agent 证据本身为低置信分诊；受约束 C2 规则需要 URI、任务或分类上下文。"),
        ("HTTP transfer hints for authenticated upload or exfiltration", "HTTP 传输提示认证上传或外传"),
        ("HTTP transfer hints for executable download", "HTTP 传输提示可执行载荷下载"),
        ("HTTP URI contained both /api/ and gate plus an id-like query parameter in the same field, a constrained C2 gate pattern.", "HTTP URI 同一字段同时包含 /api/ 与 gate，并含类似 id 的查询参数，是受约束的 C2 gate 模式。"),
        ("HTTP URI contains API gate and bot identifier", "HTTP URI 同时包含 API gate 与 Bot 标识"),
        ("HTTP, TLS, or driver network telemetry contained explicit beacon, callback, check-in, tasking, URI, or protocol classification fields often used to label C2 activity. Script/library user agents are handled by constrained companion rules.", "HTTP、TLS 或驱动网络遥测包含常用于标记 C2 活动的 beacon、callback、check-in、tasking、URI 或协议分类字段。脚本/库 User-Agent 由受约束的配套规则处理。"),
        ("HTTP/PCAP metadata identified a DNS-over-HTTPS endpoint and included high-entropy or long-query DNS metadata.", "HTTP/PCAP 元数据识别 DNS-over-HTTPS 端点，并包含高熵或长查询 DNS 元数据。"),
        ("HTTP/PCAP metadata records a DNS-over-HTTPS POST to /dns-query with DNS message content and an unusually long or encoded query payload.", "HTTP/PCAP 元数据记录发往 /dns-query 的 DNS-over-HTTPS POST，具有 DNS message 内容类型和异常长或编码的查询载荷。"),
        ("HTTP/PCAP metadata shows a WSMan POST to a WinRM port with CreateShell or Command SOAP action evidence.", "HTTP/PCAP 元数据显示发往 WinRM 端口的 WSMan POST，并包含 CreateShell 或 Command SOAP action 证据。"),
        ("Human interaction checks gate execution or exit", "人机交互检查控制执行或退出"),
        ("Human interaction gate API observed", "观察到人机交互门控 API"),
        ("Virtual machine runbook generated", "已生成虚拟机运行手册"),
        ("IE Browser Helper Object user-writable payload", "IE BHO 用户可写载荷"),
        ("IFEO debugger persistence path", "IFEO 调试器持久化路径"),
        ("IFEO GlobalFlag enables SilentProcessExit persistence", "IFEO GlobalFlag 启用 SilentProcessExit 持久化"),
        ("IFEO VerifierDll points to user-writable DLL", "IFEO VerifierDll 指向用户可写 DLL"),
        ("Image load metadata observed", "观察到镜像加载元数据"),
        ("Image-load telemetry referenced a DLL or module path under Temp, AppData, ProgramData, Public, or Downloads, supporting DLL injection or hijack triage.", "镜像加载遥测引用了 Temp、AppData、ProgramData、Public 或 Downloads 下的 DLL/模块路径，可辅助 DLL 注入或劫持排查。"),
        ("Injection or image telemetry reports reflective/manual-map loading behavior for a DLL staged under a user-writable path.", "注入或映像遥测报告对用户可写路径下 DLL 的反射式或手动映射加载行为。"),
        ("Injection telemetry reported a suspended target process with QueueUserAPC/NtQueueApcThread and LoadLibrary-style DLL loading context.", "注入遥测报告挂起目标进程，并包含 QueueUserAPC/NtQueueApcThread 与 LoadLibrary DLL 加载上下文。"),
        ("InstallUtil launches downloaded user-writable assembly", "InstallUtil 启动下载的用户可写程序集"),
        ("InstallUtil proxy execution is paired with a remote transfer source and execution of a staged EXE or DLL under a user-writable directory.", "InstallUtil 代理执行与远程传输来源以及用户可写目录下 EXE 或 DLL 的执行相关联。"),
        ("Kerberos ticket export command", "Kerberos 票据导出命令"),
        ("Kernel driver service install evidence", "内核驱动服务安装证据"),
        ("Kernel or API telemetry reported remote thread creation through CreateRemoteThread, NtCreateThreadEx, RtlCreateUserThread, or a driver thread event.", "内核或 API 遥测报告通过 CreateRemoteThread、NtCreateThreadEx、RtlCreateUserThread 或驱动线程事件创建远程线程。"),
        ("Kernel or normalized process telemetry reported a cross-process virtual memory write such as WriteProcessMemory or NtWriteVirtualMemory.", "内核或规范化进程遥测报告跨进程虚拟内存写入，例如 WriteProcessMemory 或 NtWriteVirtualMemory。"),
        ("Known packer or UPX-like PE traits", "已知壳或 UPX 类 PE 特征"),
        ("Large authenticated HTTP upload metadata", "带认证信息的大体量 HTTP 上传元数据"),
        ("Large HTTP POST upload observed", "观察到大体量 HTTP POST 上传"),
        ("Legacy R0 collector IOCTL pending diagnostic", "旧版 R0 采集器 IOCTL 待读诊断"),
        ("Listener metadata reported common Tor/SOCKS ports 9050 or 9150 using numeric range predicates.", "监听器元数据通过数值范围谓词报告常见 Tor/SOCKS 9050 或 9150 端口。"),
        ("Living-off-the-land binary string", "Living-off-the-land 二进制字符串"),
        ("LoadLibrary remote-thread target", "LoadLibrary 远程线程目标"),
        ("LoadLibrary-style DLL injection signal", "LoadLibrary 风格 DLL 注入信号"),
        ("Local Tor/SOCKS listener port opened", "本地 Tor/SOCKS 监听端口打开"),
        ("Logon script points to user-writable payload", "登录脚本指向用户可写载荷"),
        ("LOLBin executes payload from WebDAV URL", "LOLBin 从 WebDAV URL 执行载荷"),
        ("Long sleep duration requested", "请求长时间休眠"),
        ("Long sleep or time-skew anti-sandbox check", "长时间休眠或时间偏移反沙箱检查"),
        ("Low user interaction count gates execution", "低用户交互计数触发执行门控"),
        ("Low user-interaction gate before exit", "低用户交互退出门控"),
        ("Low-resource sandbox classification", "低资源沙箱分类"),
        ("Low-resource sandbox gate before exit or delay", "低资源沙箱门控后退出或延迟"),
        ("Low-resource sandbox resource inventory observed", "低资源沙箱环境盘点"),
        ("LSA authentication package persistence registry value", "LSA 身份验证包持久化注册表值"),
        ("LSA security provider persistence path", "LSA 安全提供程序持久化路径"),
        ("LSASS dump command line", "LSASS 转储命令行"),
        ("LSASS dump file created", "已创建 LSASS 转储文件"),
        ("LSASS dump-like file created", "创建类似 LSASS 转储的文件"),
        ("LSASS memory dump command", "LSASS 内存转储命令"),
        ("LSASS process access observed", "观察到 LSASS 进程访问"),
        ("MAC, disk, or device fingerprint command", "MAC、磁盘或设备指纹命令"),
        ("Mass file-write burst with encryption classification", "带加密分类的大量文件写入突增"),
        ("Mass registry Run-key change burst", "大量 Run 键注册表变更突增"),
        ("Memory dump artifact captured", "已捕获内存转储证据文件"),
        ("Memory dump artifact tied to process identity", "内存转储产物关联到进程身份"),
        ("Memory dump capture skipped", "内存转储捕获已跳过"),
        ("Memory or API telemetry referenced section creation/mapping with target-process context, a stronger signal for section-map/manual-map injection than static imports alone.", "内存或 API 遥测在目标进程上下文中引用 Section 创建/映射，比单纯静态导入更能说明 Section-map/manual-map 注入。"),
        ("Memory telemetry reported section creation or MapViewOfSection with executable protection in a remote process.", "内存遥测报告在远程进程中创建节或 MapViewOfSection，并具有可执行保护。"),
        ("Memory telemetry reported writes into an image-backed module followed by executable protection or module-stomping classification.", "内存遥测报告写入 image-backed 模块，并随后出现可执行保护或 module stomping 分类。"),
        ("Memory/API telemetry reported NtMapViewOfSection or section-map behavior with executable protection and anonymous, pagefile, transacted, or otherwise unbacked mapping context.", "内存/API 遥测报告 NtMapViewOfSection/section map 行为，同时包含可执行权限和匿名、pagefile、事务或无文件映射上下文；用于识别 section-based 注入。"),
        ("Microsoft Defender disable or exclusion command", "Microsoft Defender 禁用或排除命令"),
        ("MiniDumpWriteDump targeting LSASS", "MiniDumpWriteDump 目标为 LSASS"),
        ("MMC loads user-writable MSC snap-in", "MMC 加载用户可写 MSC 管理单元"),
        ("Module stomping write and execute transition", "模块覆盖写入并转为可执行"),
        ("MSBuild executes a project in a user-writable location with inline-task indicators, a high-signal proxy execution shape when observed in sandboxed malware analysis.", "MSBuild 执行用户可写位置的项目并带有内联任务迹象；在沙箱样本分析中这是较高信号的代理执行形态。"),
        ("MSBuild inline task from user-writable project", "MSBuild 从用户可写项目运行内联任务"),
        ("Mshta or normalized download-execute telemetry references a remote HTA/scriptlet and a subsequent user-writable executable or script payload.", "Mshta 或规范化下载执行遥测引用远程 HTA/脚本组件，并随后启动用户可写可执行或脚本载荷。"),
        ("MSHTA or Regsvr32 remote scriptlet execution", "MSHTA 或 Regsvr32 远程脚本执行"),
        ("Mshta remote scriptlet launches user-writable payload", "Mshta 远程脚本组件启动用户可写载荷"),
        ("Mshta script proxy execution", "Mshta 脚本代理执行"),
        ("Msiexec remote package execution", "Msiexec 远程安装包执行"),
        ("MSXSL remote XSL script execution", "MSXSL 远程 XSL 脚本执行"),
        ("Mutual TLS client certificate with rare or suspicious JA3", "带罕见或可疑 JA3 的双向 TLS 客户端证书"),
        ("Named-pipe client impersonation API observed", "观察到命名管道客户端模拟 API"),
        ("Net use admin share with credentials", "使用凭据连接管理共享"),
        ("Netsh helper DLL persistence registry value", "Netsh Helper DLL 持久化注册表值"),
        ("Netsh helper DLL registered from user-writable path", "Netsh Helper 注册用户可写 DLL"),
        ("Netsh helper registration pointed HelperDll or equivalent helper data to a user-writable DLL path, a command-shell extension persistence technique.", "Netsh helper 注册将 HelperDll 等数据指向用户可写 DLL，可作为命令扩展持久化。"),
        ("Network event with IP literal", "包含 IP 字面量的网络事件"),
        ("Network flow classified as periodic check-in", "网络流被分类为周期性 Check-in"),
        ("Network metadata correlated Host/SNI mismatch or domain-fronting classification with SNI, Host, and suspicious JA3 reputation fields.", "网络元数据将 Host/SNI 不一致或 domain fronting 分类与 SNI、Host 和可疑 JA3 信誉字段关联；比单独 fronting 标签更适合作为 C2 证据。"),
        ("Network metadata reported TCP port 3389 using numeric range predicates, indicating possible Remote Desktop lateral movement or discovery.", "网络元数据通过数值范围谓词报告 TCP 3389 端口，可能表示远程桌面横向移动或发现。"),
        ("Network metadata reported TCP port 445 using numeric range predicates, indicating possible SMB staging or admin-share lateral movement.", "网络元数据通过数值范围谓词报告 TCP 445 端口，可能表示 SMB 投递或管理共享横向移动。"),
        ("Network metadata reported WinRM ports 5985 or 5986 using numeric range predicates.", "网络元数据通过数值范围谓词报告 WinRM 5985 或 5986 端口。"),
        ("Network or download API imports", "网络或下载 API 导入"),
        ("Network, HTTP, C2, or PCAP metadata carried beacon interval, jitter, or periodic-check-in fields suitable for C2 triage.", "网络、HTTP、C2 或 PCAP 元数据携带 beacon 间隔、抖动或周期性 check-in 字段，可用于 C2 排查。"),
        ("Network-flow metadata ties a user-writable payload process to a periodic beacon interval, bounded jitter, destination IP, and explicit C2/beacon classification.", "网络流元数据将用户可写负载进程与周期性 beacon 间隔、有限抖动、目标 IP 和明确 C2/beacon 分类关联起来。"),
        ("New process observed after launch", "启动后观察到新进程"),
        ("Non-browser access to Chromium cookie database", "非浏览器访问 Chromium Cookie 数据库"),
        ("Non-browser access to Chromium Local State", "非浏览器访问 Chromium Local State"),
        ("NTDS database file path accessed", "访问 NTDS 数据库文件路径"),
        ("Ntdsutil IFM credential database staging", "Ntdsutil IFM 凭据数据库暂存"),
        ("Odbcconf REGSVR proxy execution from user-writable DLL", "Odbcconf 从用户可写 DLL 代理执行 REGSVR"),
        ("Office macro security weakened", "Office 宏安全被削弱"),
        ("Office or script host execution referenced a remote template, add-in, or document relationship and then a user-writable payload launch path.", "Office 或脚本宿主执行引用远程模板、加载项或文档关系，并随后启动用户可写路径载荷。"),
        ("Office remote template or add-in launch chain", "Office 远程模板或加载项启动链"),
        ("Outbound RDP port observed", "观察到出站 RDP 端口"),
        ("Outbound SMB/admin-share port observed", "观察到出站 SMB/管理共享端口"),
        ("Outbound TCP activity observed", "观察到出站 TCP 活动"),
        ("Outbound WinRM port observed", "观察到出站 WinRM 端口"),
        ("Outlook form or homepage persistence", "Outlook 表单或主页持久化"),
        ("Parsed R0 file telemetry reported a dropped-file candidate in the Startup folder family.", "解析后的 R0 文件遥测报告启动目录族中的 dropped-file 候选。"),
        ("Parsed R0 file telemetry reported droppedFileCandidate=true in Temp, ProgramData, Public, or another writable drop-location family.", "解析后的 R0 文件遥测在 Temp、ProgramData、Public 或其他可写落地位置报告 droppedFileCandidate=true。"),
        ("Parsed R0 image-load telemetry reported imageLoadFamily=user-writable-image and injectionCandidate=true.", "解析后的 R0 镜像加载遥测报告 imageLoadFamily=user-writable-image 且 injectionCandidate=true。"),
        ("Parsed R0 network telemetry reported an HTTP/TLS flow with downloadExecuteCandidate=true. Treat as web-transfer triage until paired with file/process execution evidence.", "解析后的 R0 网络遥测报告 HTTP/TLS 流且 downloadExecuteCandidate=true；在与文件/进程执行证据配对前作为 Web 传输分诊。"),
        ("Parsed R0 network telemetry reported networkEvidenceKind=dns-flow. This is DNS semantic evidence for correlation with PCAP/DNS rows, not C2 by itself.", "解析后的 R0 网络遥测报告 networkEvidenceKind=dns-flow；这是用于关联 PCAP/DNS 行的 DNS 语义证据，单独不代表 C2。"),
        ("Parsed R0 network telemetry reported networkEvidenceKind=lateral-movement-flow and lateralMovementCandidate=true for SMB/RPC/RDP/WinRM-style ports.", "解析后的 R0 网络遥测在 SMB/RPC/RDP/WinRM 等端口上报告 networkEvidenceKind=lateral-movement-flow 且 lateralMovementCandidate=true。"),
        ("Parsed R0 registry telemetry reported ifeoPersistenceCandidate=true with an IFEO debugger persistence family.", "解析后的 R0 注册表遥测报告 ifeoPersistenceCandidate=true，并归类为 IFEO debugger 持久化族。"),
        ("Parsed R0 registry telemetry reported persistenceFamily=autorun-run-key and startupRegistryCandidate=true for a registry write/create event.", "解析后的 R0 注册表遥测在写入/创建事件中报告 persistenceFamily=autorun-run-key 且 startupRegistryCandidate=true。"),
        ("Parsed R0 registry telemetry reported servicePersistenceCandidate=true with service-configuration persistence family.", "解析后的 R0 注册表遥测报告 servicePersistenceCandidate=true，并归类为 service-configuration 持久化族。"),
        ("PCAP artifact imported", "已导入 PCAP 证据文件"),
        ("PCAP beacon timing metadata observed", "PCAP 周期信标时间元数据"),
        ("PCAP DNS NXDOMAIN burst or DGA metadata", "PCAP DNS NXDOMAIN 突发或 DGA 元数据"),
        ("PCAP DNS query observed", "观察到 PCAP DNS 查询"),
        ("PCAP DNS TXT long-label exfiltration pattern", "PCAP DNS TXT 长标签外传模式"),
        ("PCAP HTTP request observed", "观察到 PCAP HTTP 请求"),
        ("PCAP network flow observed", "观察到 PCAP 网络流"),
        ("PCAP protocol row tied to capture artifact", "PCAP 协议行关联到抓包产物"),
        ("PCAP protocol summary metadata observed", "PCAP 协议摘要元数据"),
        ("PCAP SMB admin-share session metadata", "PCAP SMB 管理共享会话元数据"),
        ("PCAP TLS ClientHello observed", "观察到 PCAP TLS ClientHello"),
        ("PE export table present", "存在 PE 导出表"),
        ("PE import table present", "存在 PE 导入表"),
        ("PE overlay non-certificate data observed", "观察到非证书 PE Overlay 数据"),
        ("PE resource directory present", "存在 PE 资源目录"),
        ("PE signature or certificate-table metadata present", "存在 PE 签名或证书表元数据"),
        ("PE summary reported a zero entry point RVA", "PE 摘要显示入口点 RVA 为零"),
        ("Periodic network beacon metadata", "周期性网络 Beacon 元数据"),
        ("Persistence-capable API imports", "具备持久化能力的 API 导入"),
        ("PowerShell Copy-Item to remote admin share", "PowerShell Copy-Item 写入远程管理共享"),
        ("PowerShell download to user-writable path", "PowerShell 下载到用户可写路径"),
        ("PowerShell download, extract, and launch chain", "PowerShell 下载、解压并启动链"),
        ("PowerShell encoded command execution", "PowerShell 编码命令执行"),
        ("PowerShell encoded command with base64 payload", "PowerShell EncodedCommand 携带 Base64 负载"),
        ("PowerShell evasion or download abuse", "PowerShell 规避或下载滥用"),
        ("PowerShell in-memory reflection loader", "PowerShell 内存反射加载器"),
        ("PowerShell or WinRM command telemetry includes a remote target plus encoded/scriptblock execution context.", "PowerShell 或 WinRM 命令遥测同时包含远程目标和编码/脚本块执行上下文。"),
        ("PowerShell profile persistence in user profile", "用户配置文件中的 PowerShell Profile 持久化"),
        ("PowerShell remoting syntax launches an Invoke-Command, Enter-PSSession, or New-PSSession operation with a remote computer name or session and script block context.", "PowerShell 远程管理语法通过远程计算机名或会话执行 Invoke-Command、Enter-PSSession 或 New-PSSession，并带有脚本块上下文。"),
        ("PowerShell script block disables AMSI", "PowerShell 脚本块禁用 AMSI"),
        ("PowerShell security logging disabled", "PowerShell 安全日志被禁用"),
        ("PowerShell spawned LOLBin child", "PowerShell 衍生 LOLBin 子进程"),
        ("PowerShell web download followed by execution", "PowerShell Web 下载后立即执行"),
        ("Print monitor DLL persistence registry value", "打印监视器 DLL 持久化注册表值"),
        ("Print processor registry driver points to user-writable DLL", "Print Processor 注册表驱动指向用户可写 DLL"),
        ("Process access telemetry reported a high-rights handle to lsass.exe, often preceding credential theft or injection.", "进程访问遥测报告对 lsass.exe 打开高权限句柄，常见于凭据窃取或注入之前。"),
        ("Process access with debug or all-access rights", "使用调试或全访问权限访问进程"),
        ("Process discovery telemetry or command line referenced common analysis, debugger, VM, or sandbox tool process names.", "进程发现遥测或命令行引用常见分析、调试器、虚拟机或沙箱工具进程名。"),
        ("Process doppelgänging or transacted-section injection primitive", "进程 Doppelgänging 或事务 Section 注入原语"),
        ("Process doppelgänging transaction and section execution sequence", "Process Doppelgänging 事务和节执行序列"),
        ("Process ghosting delete-pending image section", "Process Ghosting 删除挂起映像节"),
        ("Process handle access for injection", "用于注入排查的进程句柄访问"),
        ("Process hollowing or suspended-process replacement signal", "进程空洞化或挂起进程替换信号"),
        ("Process hollowing unmap/write/context/resume sequence", "进程空洞化 unmap/write/context/resume 序列"),
        ("Process or API telemetry references virtualization MAC address OUIs such as VMware, VirtualBox, Hyper-V, or QEMU vendors.", "进程或 API 遥测引用 VMware、VirtualBox、Hyper-V 或 QEMU 等虚拟化 MAC 地址 OUI。"),
        ("Process or driver enumeration for anti-analysis", "用于反分析的进程或驱动枚举"),
        ("Process or normalized download-execute telemetry links certutil URL cache retrieval from HTTP(S) to execution of a user-writable payload.", "进程或规范化下载执行遥测将 certutil URL 缓存 HTTP(S) 拉取与用户可写载荷执行关联。"),
        ("Process tree child-count metadata observed", "观察到进程树子进程计数元数据"),
        ("Process tree node observed", "观察到进程树节点"),
        ("Process tree root unavailable", "进程树根不可用"),
        ("Process tree spawned many children", "进程树产生大量子进程"),
        ("Process, API, or driver telemetry reported a virtual-memory write, allocation, or section map targeting LSASS, Winlogon, Services, CSRSS, Explorer, or a similar sensitive process.", "进程、API 或驱动遥测报告对 LSASS、Winlogon、Services、CSRSS、Explorer 等敏感进程执行虚拟内存写入、分配或 Section 映射；这是高优先级注入/凭据访问证据。"),
        ("Process, API, or driver telemetry reported LSASS as the target process or image for access that should be reviewed for credential dumping.", "进程、API 或驱动遥测报告 LSASS 是访问目标进程或镜像，应复核是否存在凭据转储。"),
        ("Process-access telemetry requested debug privilege, PROCESS_ALL_ACCESS, VM write, or thread creation rights against another process.", "进程访问遥测请求调试权限、PROCESS_ALL_ACCESS、VM 写入或远程线程创建权限。"),
        ("Process-access telemetry requested VM-write/create-thread/all-access rights against sensitive process names, supporting injection or credential-access triage.", "进程访问遥测针对敏感进程请求 VM_WRITE、CREATE_THREAD 或全访问权限，可支持注入或凭据访问排查。"),
        ("Process-injection-capable API imports observed", "观察到具备进程注入能力的 API 导入"),
        ("Process-tree metadata reported at least 20 child processes using an all-field numeric range predicate.", "进程树元数据通过全字段数值范围谓词报告至少 20 个子进程。"),
        ("Process-tree telemetry shows an archive, self-extractor, or installer launching a child from a user-writable staging location.", "进程树遥测显示压缩工具、自解压程序或安装器启动了用户可写暂存位置中的子进程。"),
        ("Process-tree telemetry shows PowerShell spawning proxy-execution utilities such as rundll32, regsvr32, mshta, certutil, bitsadmin, or installutil.", "进程树遥测显示 PowerShell 启动 rundll32、regsvr32、mshta、certutil、bitsadmin 或 installutil 等代理执行工具。"),
        ("Process/image evidence showed a delete-pending executable file being converted into an image section or launched process, consistent with process ghosting-style injection.", "进程或映像证据显示删除挂起的可执行文件被转换为映像节或启动进程，符合 Process Ghosting 类注入。"),
        ("PsExec or remote service lateral movement command", "PsExec 或远程服务横向移动命令"),
        ("PsExec service binary staged on admin share", "PsExec 服务二进制暂存到管理共享"),
        ("PsExec-style remote service ImagePath", "PsExec 风格远程服务 ImagePath"),
        ("PsExec-style SMB service pipe or service evidence", "PsExec 风格 SMB 服务管道或服务证据"),
        ("QueueUserAPC LoadLibrary into suspended process", "QueueUserAPC 将 LoadLibrary 注入挂起进程"),
        ("R0 collector backpressure or event loss observed", "观察到 R0 采集背压或事件丢失"),
        ("R0 collector device unavailable", "R0 采集器设备不可用"),
        ("R0 collector health or batch rows report queue backpressure, dropped counters, sequence loss, or high-watermark evidence. This is evidence-quality context and not a malicious sample behavior finding by itself.", "R0 采集健康或批次行报告队列背压、丢弃计数、序列丢失或高水位证据；这是证据质量上下文，本身不是样本恶意行为判定。"),
        ("R0 collector IOCTL or protocol failure", "R0 采集器 IOCTL 或协议失败"),
        ("R0 collector lifecycle event", "R0 采集器生命周期事件"),
        ("R0 collector mock driver event", "R0 采集器模拟驱动事件"),
        ("R0 collector start failed", "R0 采集器启动失败"),
        ("R0 cross-process virtual memory write", "R0 跨进程虚拟内存写入"),
        ("R0 driver file write or rename signal", "R0 驱动文件写入或重命名信号"),
        ("R0 driver health queried", "已查询 R0 驱动健康状态"),
        ("R0 driver network signal", "R0 驱动网络信号"),
        ("R0 driver process callback event", "R0 驱动进程回调事件"),
        ("R0 driver registry mutation signal", "R0 驱动注册表变更信号"),
        ("R0 driver startup heartbeat observed", "观察到 R0 驱动启动心跳"),
        ("R0 remote thread creation primitive", "R0 远程线程创建原语"),
        ("R0 semantic DNS flow observed", "R0 语义 DNS 流"),
        ("R0 semantic dropped-file with download-execute hint", "R0 语义释放文件带下载执行提示"),
        ("R0 semantic IFEO debugger persistence candidate", "R0 语义 IFEO Debugger 持久化候选"),
        ("R0 semantic lateral-movement network flow", "R0 语义横向移动网络流"),
        ("R0 semantic Run-key persistence candidate", "R0 语义 Run Key 持久化候选"),
        ("R0 semantic service persistence candidate", "R0 语义服务持久化候选"),
        ("R0 semantic startup-folder dropped file", "R0 语义启动目录释放文件"),
        ("R0 semantic user-writable dropped-file candidate", "R0 语义用户可写释放文件候选"),
        ("R0 semantic user-writable image injection candidate", "R0 语义用户可写镜像注入候选"),
        ("R0 semantic web flow download-execute candidate", "R0 语义 Web 流下载执行候选"),
        ("R0Collector could not open the configured driver device; this records driver health rather than malicious sample behavior.", "R0Collector 无法打开已配置的驱动设备；这是驱动健康状态记录，不是样本恶意行为。"),
        ("R0Collector emitted a synthetic driver event for JSONL and Guest Agent plumbing tests.", "R0Collector 为 JSONL 和来宾 Agent 管道测试输出了合成驱动事件。"),
        ("R0Collector emitted startup, heartbeat, device-open, or stopped lifecycle telemetry for driver-side collection visibility.", "R0Collector 输出启动、心跳、设备打开或停止生命周期遥测，用于驱动侧采集可见性。"),
        ("R0Collector reported an IOCTL, argument, output, or driver protocol error. This is collection-health evidence rather than direct sample behavior.", "R0Collector 报告 IOCTL、参数、输出或驱动协议错误。这是采集健康证据，而不是直接样本行为。"),
        ("R0Collector successfully queried the KSword sandbox driver health or queue status through DeviceIoControl.", "R0Collector 已通过 DeviceIoControl 成功查询 KSword 沙箱驱动健康或队列状态。"),
        ("Ransom note file artifact created", "创建勒索说明文件"),
        ("RDP RestrictedAdmin registry enablement", "RDP RestrictedAdmin 注册表启用"),
        ("RDP shadow or RestrictedAdmin command", "RDP Shadow 或 RestrictedAdmin 命令"),
        ("Reflective loader maps user-writable module into process", "反射式加载器将用户可写模块映射进进程"),
        ("Registry activity metadata reported at least 50 set operations and Run/RunOnce or persistence scope evidence.", "注册表活动元数据报告至少 50 次设置操作，并带有 Run/RunOnce 或持久化范围证据。"),
        ("Registry hive save command for credentials", "用于凭据的注册表 Hive 保存命令"),
        ("Registry modification observed", "观察到注册表修改"),
        ("Registry or policy telemetry referenced a Windows logon script location together with a user-writable executable or script payload path.", "注册表或策略遥测引用 Windows 登录脚本位置，并包含用户可写目录中的可执行或脚本载荷路径。"),
        ("Registry persistence API imports", "注册表持久化 API 导入"),
        ("Registry telemetry enabled DisableRestrictedAdmin=0, which can support credential-safe or pass-the-hash RDP lateral movement workflows.", "注册表遥测将 DisableRestrictedAdmin 设置为 0，可支撑凭据安全或 pass-the-hash 风格的 RDP 横向移动流程。"),
        ("Registry telemetry modified shell open command handler paths with script interpreters, proxy binaries, or user-writable payload paths.", "注册表遥测修改 shell open command 处理器路径，并指向脚本解释器、代理二进制或用户可写载荷路径。"),
        ("Registry telemetry reported queries for VMware, VirtualBox, Hyper-V, QEMU, or sandbox artifact keys.", "注册表遥测报告查询 VMware、VirtualBox、Hyper-V、QEMU 或沙箱痕迹键。"),
        ("Registry telemetry shows a per-user or machine COM CLSID scriptlet/scrobj registration that points to a remote script or user-writable payload.", "注册表遥测显示用户或机器范围 COM CLSID scriptlet/scrobj 注册指向远程脚本或用户可写载荷。"),
        ("Regsvr32 scriptlet proxy execution", "Regsvr32 Scriptlet 代理执行"),
        ("Remote APC queue injection primitive", "远程 APC 队列注入原语"),
        ("Remote DCOM Excel.Application launch command", "远程 DCOM Excel.Application 启动命令"),
        ("Remote memory write followed by executable protection", "远程内存写入后设置可执行保护"),
        ("Remote registry persistence command", "远程注册表持久化命令"),
        ("Remote scheduled task command", "远程计划任务命令"),
        ("Remote scheduled task create or run", "远程创建或运行计划任务"),
        ("Remote scheduled task create or run with credentials", "带凭据的远程计划任务创建或运行"),
        ("Remote section-map execution primitive", "远程 Section 映射执行原语"),
        ("Remote service control creates user-writable service binary", "远程服务控制创建用户可写服务二进制"),
        ("Remote service control via sc.exe", "通过 sc.exe 远程控制服务"),
        ("Remote service creation using admin-share binary path", "远程服务创建引用管理共享载荷"),
        ("Remote thread into sensitive process", "向敏感进程创建远程线程"),
        ("Remote thread or APC injection primitive", "远程线程或 APC 注入原语"),
        ("Remote thread or cross-process injection event", "远程线程或跨进程注入事件"),
        ("Remote thread starts in RWX memory", "远程线程从 RWX 内存启动"),
        ("Remote UAC token filtering disabled", "远程 UAC 令牌过滤被禁用"),
        ("Remote WMI process creation command", "远程 WMI 进程创建命令"),
        ("Remote-thread telemetry explicitly targeted LoadLibrary or LdrLoadDll while also carrying target-process context.", "远程线程遥测明确指向 LoadLibrary 或 LdrLoadDll，并携带目标进程上下文。"),
        ("Remote-thread telemetry targeted LSASS, Explorer, Winlogon, services, or service-host processes, strengthening process-injection evidence beyond a bare API name.", "远程线程遥测目标为 LSASS、Explorer、Winlogon、services 或 service-host 进程，比单独 API 名称提供更强的进程注入证据。"),
        ("Resource extraction API imports", "资源提取 API 导入"),
        ("Resource payload candidate", "资源载荷候选"),
        ("Resource threshold check before exit or delay", "退出或延迟前进行资源阈值检查"),
        ("Root certificate store modification command", "根证书存储修改命令"),
        ("Root certificate store registry change", "根证书存储注册表变更"),
        ("Run key launches script interpreter or LOLBin", "Run 启动项启动脚本解释器或 LOLBin"),
        ("Run key persistence", "Run 键持久化"),
        ("Run key points to user-writable payload", "Run 启动项指向用户可写载荷"),
        ("Run-key persistence points to dropped payload", "Run 键持久化指向投放负载"),
        ("Rundll32 executes DLL from URL or web cache", "Rundll32 从 URL 或 Web 缓存执行 DLL"),
        ("Rundll32 mshtml remote script download-execute chain", "Rundll32 mshtml 远程脚本下载执行链"),
        ("Rundll32 remote script or URL execution", "Rundll32 远程脚本或 URL 执行"),
        ("Rundll32/mshtml proxy execution references a remote script source and correlates to a user-writable payload launch path.", "Rundll32/mshtml 代理执行引用远程脚本来源，并关联到用户可写载荷启动路径。"),
        ("RunOnceEx Depend DLL persistence value", "RunOnceEx Depend DLL 持久化值"),
        ("Runtime API telemetry reported SetWindowsHookEx/NtUserSetWindowsHookEx with a hook module path under a user-writable directory.", "运行时 API 遥测报告 SetWindowsHookEx/NtUserSetWindowsHookEx，并带有用户可写目录中的 hook 模块路径。"),
        ("Runtime process-query telemetry referenced VM, sandbox, debugger, packet-capture, or reverse-engineering tool process names. Sandbox agent self-telemetry is excluded.", "运行时进程查询遥测引用 VM、沙箱、调试器、抓包或逆向工具进程名，并排除沙箱 Agent 自身遥测。"),
        ("Runtime telemetry referenced input-idle, cursor, keyboard, foreground-window, or user-interaction checks commonly used to gate sandbox execution.", "运行时遥测引用空闲输入、鼠标、键盘、前台窗口或用户交互检查，常用于门控沙箱执行。"),
        ("SAM/SYSTEM hive credential material access", "SAM/SYSTEM Hive 凭据材料访问"),
        ("Sample accepted for sandbox planning", "样本已接受用于沙箱规划"),
        ("Sample process start failed", "样本进程启动失败"),
        ("Sample still running at timeout", "样本在超时时仍在运行"),
        ("Sandbox check paired with long sleep gate", "沙箱检查与长时间休眠门控组合"),
        ("Sandbox or analysis tool process enumeration", "枚举沙箱或分析工具进程"),
        ("Sandbox tool enumeration gates execution or exit", "沙箱工具枚举控制执行或退出"),
        ("Sandbox-check or fingerprint telemetry referenced hostnames, usernames, domains, or sandbox-user defaults used to gate execution.", "沙箱检查或指纹遥测引用主机名、用户名、域名或沙箱默认用户，用于决定是否执行。"),
        ("Scheduled task COM handler persistence", "计划任务 COM Handler 持久化"),
        ("Scheduled task COM handler resolves to user-writable DLL", "计划任务 COM Handler 指向用户可写 DLL"),
        ("Scheduled task launches user-writable payload", "计划任务启动用户可写负载"),
        ("Scheduled task logon/start trigger with user-writable payload", "计划任务登录/启动触发用户可写载荷"),
        ("Scheduled task persistence command", "计划任务持久化命令"),
        ("Scheduled task RunLevel highest with user-writable action", "计划任务最高权限运行用户可写动作"),
        ("Scheduled task XML targets user-writable payload", "计划任务 XML 指向用户可写载荷"),
        ("Scheduled TaskCache registry persistence", "计划任务 TaskCache 注册表持久化"),
        ("Scheduled Tasks folder file write", "计划任务文件夹写入"),
        ("Scheduled-task metadata or TaskCache data referenced a user-writable executable/script payload path matched by regex.", "计划任务元数据或 TaskCache 数据引用用户可写的可执行/脚本负载路径，由正则匹配。"),
        ("Scheduled-task metadata or TaskCache registry evidence indicates a COM handler action whose DLL path is under a user-writable location.", "计划任务元数据或 TaskCache 注册表证据显示 COM Handler 动作的 DLL 路径位于用户可写位置。"),
        ("Scheduled-task telemetry referenced hidden/highest-privilege task XML or action metadata together with user-writable target paths.", "计划任务遥测引用隐藏或最高权限任务 XML/动作元数据，并包含用户可写目标路径。"),
        ("Scheduled-task telemetry set RunLevel highest while the task action points to a user-writable executable or script path.", "计划任务遥测设置最高权限运行，同时动作指向用户可写可执行/脚本路径；排查是否借任务提权或持久化。"),
        ("Screen saver executable set to user-writable payload", "屏保程序设置为用户可写载荷"),
        ("Screensaver autostart points to user-writable payload", "屏幕保护程序自启动指向用户可写载荷"),
        ("Screenshot artifact captured", "已捕获截图证据文件"),
        ("Screenshot artifact tied to capture event", "截图产物关联到捕获事件"),
        ("Screenshot capture skipped", "截图捕获已跳过"),
        ("Script block text contained both AmsiUtils and amsiInitFailed, using same-field AND matching to avoid single-token false positives.", "脚本块文本同时包含 AmsiUtils 与 amsiInitFailed，使用同字段 AND 避免单个令牌误报。"),
        ("Script file dropped or modified", "脚本文件落地或修改"),
        ("Script file execution command", "脚本文件执行命令"),
        ("Script interpreter launched Mark-of-the-Web download", "脚本解释器启动带 Mark-of-the-Web 的下载文件"),
        ("Script or LOLBin network download command", "脚本或 LOLBin 网络下载命令"),
        ("Script or process execution API imports", "脚本或进程执行 API 导入"),
        ("Script user-agent with beacon URI", "脚本 User-Agent 搭配 Beacon URI"),
        ("Security tool stop or kill command", "安全工具停止或终止命令"),
        ("Security-tool discovery through process listing", "通过进程列表发现安全工具"),
        ("Sensitive privilege enabled", "敏感权限被启用"),
        ("Service binary path points to user-writable location", "服务二进制路径指向用户可写位置"),
        ("Service failure command persistence", "服务失败命令持久化"),
        ("Service failure command points to user-writable payload", "服务失败恢复命令指向用户可写载荷"),
        ("Service ImagePath has unquoted-space hijack risk", "服务 ImagePath 存在未加引号空格劫持风险"),
        ("Service ImagePath launches script or LOLBin", "服务 ImagePath 启动脚本或 LOLBin"),
        ("Service ImagePath or ServiceDll registry change", "服务 ImagePath 或 ServiceDll 注册表变更"),
        ("Service ImagePath points to user-writable payload", "服务 ImagePath 指向用户可写负载"),
        ("Service inventory or ACL telemetry indicated that low-privilege users can change service configuration, binary path, or DACL values.", "服务清单或 ACL 遥测显示低权限用户可修改服务配置、二进制路径或 DACL。"),
        ("Service registry or inventory telemetry pointed ImagePath, ServiceDll, or raw command fields at script interpreters or proxy-execution binaries.", "服务注册表或清单遥测将 ImagePath、ServiceDll 或原始命令字段指向脚本解释器或代理执行二进制。"),
        ("Service registry or inventory telemetry referenced a kernel-driver service type or .sys ImagePath, which can indicate privileged driver installation.", "服务注册表或清单遥测引用内核驱动服务类型或 .sys ImagePath，可能表示安装了高权限驱动。"),
        ("Service-control or process telemetry ties a remote host to service creation/start with a user-writable service binary path.", "服务控制或进程遥测将远程主机与创建/启动服务及用户可写服务二进制路径关联。"),
        ("Service-control persistence API imports", "服务控制持久化 API 导入"),
        ("Service-style export entry point", "服务风格导出入口点"),
        ("SetThreadContext against suspended target process", "对挂起目标进程调用 SetThreadContext"),
        ("SetWindowsHookEx loads user-writable DLL", "SetWindowsHookEx 加载用户可写 DLL"),
        ("Shadow copy deletion command", "卷影副本删除命令"),
        ("Shell open command hijack", "Shell open command 劫持"),
        ("Short system uptime gates execution", "短系统运行时间控制执行路径"),
        ("SilentCleanup UAC environment hijack", "SilentCleanup UAC 环境变量劫持"),
        ("SilentProcessExit MonitorProcess points to user-writable payload", "SilentProcessExit MonitorProcess 指向用户可写载荷"),
        ("Sleep acceleration ratio mismatch", "Sleep 加速比例异常"),
        ("Sleep duration telemetry observed", "观察到 Sleep 时长遥测"),
        ("Sleep or delay API observed", "观察到 Sleep 或延迟 API"),
        ("Sleep or timeout metadata requested at least five minutes using numeric range predicates, a common sandbox-evasion delay.", "休眠或超时元数据通过数值范围谓词显示请求至少五分钟延迟，是常见沙箱规避方式。"),
        ("Sleep skew or time acceleration gates execution", "睡眠偏移或时间加速检测控制执行"),
        ("Sleep skipped or fast-forwarded telemetry", "Sleep 被跳过或快进的遥测"),
        ("Sleep telemetry explicitly reported skipped, fast-forwarded, or accelerated delay behavior. Plain process timeouts without sleep fields are not enough.", "Sleep 遥测明确报告延迟被跳过、快进或加速；不含 sleep 字段的普通进程超时不足以命中。"),
        ("Sleep/timing telemetry reported a long requested delay but a much shorter observed wait together with acceleration, fast-forward, or time-skew labels.", "Sleep/计时遥测报告较长请求延迟但实际等待很短，并带有加速、快进或时间偏移标签；用于识别按时间逃避沙箱的门控逻辑。"),
        ("SMB ATSVC named pipe remote task registration", "SMB ATSVC 命名管道远程任务注册"),
        ("SMB metadata records access to the svcctl named pipe, commonly used for remote service control and PsExec-like movement.", "SMB 元数据记录访问 svcctl 命名管道，该管道常用于远程服务控制和 PsExec 类横向移动。"),
        ("SMB network port observed", "观察到 SMB 网络端口"),
        ("SMB or driver network telemetry reports the ATSVC named pipe with remote scheduled-task registration or legacy job-add operation context.", "SMB 或驱动网络遥测报告 ATSVC 命名管道，并带有远程计划任务注册或旧式 job-add 操作上下文。"),
        ("SMB or PCAP flow metadata reported session setup, tree connect, or named pipe access to ADMIN$, C$, IPC$, svcctl, samr, or winreg.", "SMB 或 PCAP 流元数据报告对 ADMIN$、C$、IPC$、svcctl、samr 或 winreg 的会话建立、树连接或命名管道访问。"),
        ("SMB pipe telemetry referenced PSEXESVC-style or service-control named pipes used by remote service execution over SMB.", "SMB 管道遥测出现 PSEXESVC 或服务控制命名管道，常见于通过 SMB 进行远程服务执行。"),
        ("SMB svcctl named pipe opened", "打开 SMB svcctl 命名管道"),
        ("SMB svcctl named-pipe service execution metadata", "SMB svcctl 命名管道服务执行元数据"),
        ("SMB/PCAP metadata reported svcctl named-pipe traffic with service creation/start operations or executable service image metadata.", "SMB/PCAP 元数据报告 svcctl 命名管道流量，并伴随服务创建/启动操作或可执行服务镜像字段；排查是否为 PsExec/远程服务执行链。"),
        ("Startup folder link or script persistence", "启动文件夹链接或脚本持久化"),
        ("Startup folder persistence path", "启动文件夹持久化路径"),
        ("StartupApproved autostart state modified", "StartupApproved 自启动状态被修改"),
        ("Static analysis extracted a .onion domain string. This can support proxy/C2 triage but does not prove a Tor connection occurred at runtime.", "静态分析提取到 .onion 域名字符串，可支撑代理/C2 分诊，但不证明运行时发生了 Tor 连接。"),
        ("Static analysis extracted a bare domain-like string after suppressing common framework references and file-extension false positives. This is triage metadata unless runtime DNS/HTTP/TLS activity corroborates it.", "静态分析在抑制常见框架引用和文件扩展误报后提取到裸域名类字符串。除非运行时 DNS/HTTP/TLS 活动佐证，否则仅作分诊元数据。"),
        ("Static analysis extracted a domain containing common dynamic-DNS markers. Treat this as infrastructure triage until runtime DNS or network behavior is observed.", "静态分析提取到包含常见动态 DNS 标记的域名。在运行时 DNS 或网络行为出现前，应作为基础设施分诊。"),
        ("Static analysis extracted command strings for PowerShell, BITS, certutil, curl, wget, or msiexec download staging. This is string triage unless matching runtime process activity is observed.", "静态分析提取到 PowerShell、BITS、certutil、curl、wget 或 msiexec 下载暂存命令字符串。除非匹配运行时进程活动，否则仅为字符串分诊。"),
        ("Static analysis extracted debugger, sandbox, VM, or analysis-tool strings.", "静态分析提取到调试器、沙箱、虚拟机或分析工具相关字符串。"),
        ("Static analysis extracted encoded-command or base64 execution markers in command strings.", "静态分析在命令字符串中提取到 encoded-command 或 base64 执行标记。"),
        ("Static analysis extracted IPv4-like strings from the sample. Version/resource-shaped values are triage metadata unless corroborated by runtime network telemetry.", "静态分析提取到 IPv4 类字符串。版本号/资源形态的值属于分诊元数据，除非运行时网络遥测佐证。"),
        ("Static analysis extracted registry path strings, including service or Run-key paths when present.", "静态分析提取到注册表路径字符串，若存在也包括服务或 Run 键路径。"),
        ("Static analysis extracted Run-key, Startup-folder, service, or similar persistence-oriented strings.", "静态分析提取到 Run 键、Startup 文件夹、服务或类似持久化导向字符串。"),
        ("Static analysis extracted strings associated with Defender, AMSI, ETW, event-log, firewall, or security-tool tampering. This is static triage unless matching runtime behavior is observed.", "静态分析提取到 Defender、AMSI、ETW、事件日志、防火墙或安全工具篡改相关字符串。除非匹配运行时行为，否则只是静态分诊。"),
        ("Static analysis extracted strings associated with LSASS, SAM/SECURITY/NTDS material, DPAPI, Vault, or credential dumping tools. This is static triage unless corroborated by runtime access.", "静态分析提取到 LSASS、SAM/SECURITY/NTDS 材料、DPAPI、Vault 或凭据转储工具相关字符串。除非运行时访问佐证，否则只是静态分诊。"),
        ("Static analysis extracted strings referencing scripting interpreters or common command execution utilities.", "静态分析提取到引用脚本解释器或常见命令执行工具的字符串。"),
        ("Static analysis extracted strings referencing signed Windows utilities often used for proxy execution or download helpers.", "静态分析提取到常被用于代理执行或下载辅助的签名 Windows 工具字符串。"),
        ("Static analysis extracted upload-oriented command strings such as curl form upload, FTP script mode, or WinHTTP/WinINet write markers. Treat this as triage until runtime network evidence confirms data transfer.", "静态分析提取到 curl 表单上传、FTP 脚本模式或 WinHTTP/WinINet 写入标记等上传导向命令字符串。运行时网络证据确认数据传输前仅作分诊。"),
        ("Static analysis extracted URL-like strings from the sample. Manifest, schema, and vendor/fwlink URLs are triage metadata, not observed transfer behavior.", "静态分析从样本中提取到 URL 类字符串。清单、schema、厂商或/fwlink URL 属于分诊元数据，不代表已观察到传输行为。"),
        ("Static analysis extracted Windows filesystem path strings that may help triage dropped files or staging locations.", "静态分析提取到 Windows 文件系统路径字符串，可帮助分诊落地文件或暂存位置。"),
        ("Static analysis found a PE TLS directory or callback pointer, which can execute code before the main entry point and is useful to triage for packing or evasion.", "静态分析发现 PE TLS 目录或回调指针，这些代码可在主入口点之前执行，可用于打包或规避分诊。"),
        ("Static analysis found a writable executable, very high entropy, or low-entropy section. This remains static triage until runtime unpacking, injection, or payload behavior is observed.", "静态分析发现可写可执行、高熵或低熵 PE 节；在观察到运行时解包、注入或载荷行为前仅作为静态分诊。"),
        ("Static analysis found appended PE overlay bytes outside the Authenticode certificate table. This is triage metadata for packed, staged, or self-extracting content and is not runtime behavior by itself.", "静态分析发现 Authenticode 证书表之外追加的 PE Overlay 字节。这是打包、暂存或自解压内容的分诊元数据，本身不是运行时行为。"),
        ("Static analysis found debugger or timing API imports/strings commonly used in sandbox or debugger checks.", "静态分析发现调试器或计时 API 导入/字符串，常用于沙箱或调试器检查。"),
        ("Static analysis found DllRegisterServer, DllUnregisterServer, or DllInstall exports that may be invoked through regsvr32-style execution.", "静态分析发现 DllRegisterServer、DllUnregisterServer 或 DllInstall 导出，可能通过 regsvr32 类执行调用。"),
        ("Static analysis found high-entropy non-certificate PE overlay data. This can indicate packed, encrypted, or appended payload content and should be corroborated with section, import, and runtime evidence.", "静态分析发现高熵的非证书 PE Overlay 数据，可能表示打包、加密或追加载荷内容，应结合节、导入和运行时证据佐证。"),
        ("Static analysis found high-entropy or abnormal PE section traits.", "静态分析发现高熵或异常 PE 节特征。"),
        ("Static analysis found high-entropy resource data, which can indicate compressed or encrypted embedded content.", "静态分析发现高熵资源数据，可能表示压缩、加密或混淆的内嵌内容。"),
        ("Static analysis found imports associated with AMSI/ETW/event-log, service-control, file-attribute, or filesystem-redirection tampering. This is import-only triage, not proof of defense evasion.", "静态分析发现与 AMSI/ETW/事件日志、服务控制、文件属性或文件系统重定向篡改相关的导入。这是导入分诊，不是防御规避证明。"),
        ("Static analysis found imports associated with minidumps, Windows credential APIs, DPAPI, Vault, LSA, SAM, or token impersonation. This is import-only triage, not observed credential theft.", "静态分析发现与 minidump、Windows 凭据 API、DPAPI、Vault、LSA、SAM 或令牌模拟相关的导入。这只是导入分诊，不是已观察到的凭据窃取。"),
        ("Static analysis found imports commonly used to create, copy, move, delete, or write files.", "静态分析发现常用于创建、复制、移动、删除或写入文件的导入。"),
        ("Static analysis found imports commonly used to find, load, lock, or size PE resources before extracting embedded content.", "静态分析发现常用于查找、加载、锁定或计算 PE 资源大小以提取内嵌内容的导入。"),
        ("Static analysis found imports commonly used to launch command interpreters, scripts, or child processes.", "静态分析发现常用于启动命令解释器、脚本或子进程的导入。"),
        ("Static analysis found imports commonly used to retrieve remote content through URLMon, WinINet, or WinHTTP. This is import-only triage, not observed download behavior.", "静态分析发现常用于通过 URLMon、WinINet 或 WinHTTP 获取远程内容的导入。这只是导入分诊，不是已观察到的下载行为。"),
        ("Static analysis found imports or API-like strings associated with cross-process memory, mapping, thread, APC, or context primitives. This is import-only triage, not observed process injection.", "静态分析发现与跨进程内存、映射、线程、APC 或上下文原语相关的导入/API 类字符串。这只是导入分诊，不是已观察到的进程注入。"),
        ("Static analysis found imports or API-like strings commonly used for native Windows execution, memory, persistence, network, or anti-analysis behavior.", "静态分析发现常用于原生 Windows 执行、内存、持久化、网络或反分析行为的导入/API 类字符串。"),
        ("Static analysis found imports or API-like strings used for dynamic code loading, memory mapping, or memory protection changes.", "静态分析发现用于动态代码加载、内存映射或内存保护变更的导入/API 类字符串。"),
        ("Static analysis found MZ/PE-like bytes inside a PE resource data entry.", "静态分析在 PE 资源数据项中发现 MZ/PE 样式字节。"),
        ("Static analysis found packer tags such as UPX section names, known packer section markers, or packer strings.", "静态分析发现 UPX 节名、已知壳节标记或壳相关字符串等打包器标签。"),
        ("Static analysis found RCDATA, HTML, named, unknown, large, or embedded resource data that may carry a staged payload.", "静态分析发现 RCDATA、HTML、命名、未知、大体积或嵌入型资源数据，可能承载暂存 payload。"),
        ("Static analysis found registry APIs that can support autostart or configuration persistence.", "静态分析发现可支持自启动或配置持久化的注册表 API。"),
        ("Static analysis found registry, service-control, or shell execution API imports that can support persistence changes.", "静态分析发现注册表、服务控制或 Shell 执行 API 导入，可支撑持久化变更判断。"),
        ("Static analysis found service-control APIs that can create or alter Windows services.", "静态分析发现可创建或修改 Windows 服务的服务控制 API。"),
        ("Static analysis found service-oriented export names such as ServiceMain, useful for DLL/service triage.", "静态分析发现 ServiceMain 等服务导向导出名，可用于 DLL/服务分诊。"),
        ("Static analysis found socket, FTP, WinHTTP, or WinINet write/send imports that can support upload or exfiltration paths. Runtime flow or HTTP evidence is required before treating it as exfiltration behavior.", "静态分析发现可支持上传或外传路径的 socket、FTP、WinHTTP 或 WinINet 写入/发送导入。需运行时流量或 HTTP 证据才能视为外传行为。"),
        ("Static analysis found WinINet, WinHTTP, URLMon, or Winsock import evidence that can support network behavior. This is triage-only unless runtime network traffic is observed.", "静态分析发现 WinINet、WinHTTP、URLMon 或 Winsock 导入证据，可支撑网络行为判断；除非观察到运行时网络流量，否则仅作分诊。"),
        ("Static analysis observed PE security-directory, certificate-table, or Authenticode metadata. This is provenance context only and should not increase risk by itself.", "静态分析观察到 PE 安全目录、证书表或 Authenticode 元数据；该命中仅提供来源/签名上下文，不应单独提高风险。"),
        ("Static analysis parsed a PE export directory; exported names may appear in interesting strings for DLL triage.", "静态分析解析到 PE 导出目录；导出名可能会作为 DLL 分诊线索出现在可疑字符串中。"),
        ("Static analysis parsed a PE resource directory; resource type and payload hints may appear in static evidence.", "静态分析解析到 PE 资源目录；资源类型、大小、熵值和载荷线索会在 granular resource 事件中展开。"),
        ("Static analysis parsed at least one PE import descriptor; imported module/API evidence may appear in interesting strings.", "静态分析解析到至少一个 PE 导入描述符；导入模块/API 证据可能会出现在可疑字符串中。"),
        ("Static analysis reported a built-in lightweight YARA-like rule match. This is static triage metadata; review the rule name, matched string IDs, optional MITRE metadata, and runtime evidence before treating it as behavior.", "静态分析报告内置轻量 YARA 类规则命中。这是静态分诊元数据；在视为行为前应复核规则名、匹配字符串 ID、可选 MITRE 元数据和运行时证据。"),
        ("Static PE parse warning observed", "静态 PE 解析告警"),
        ("Static PE summary metadata reported entryPointRva=0. This can be benign for some artifacts, so it is retained as low-confidence structural context only.", "静态 PE 摘要元数据显示 entryPointRva=0；某些样本中可能是良性情况，因此仅保留为低置信结构上下文。"),
        ("Static section metadata showed a virtual-only or oversized-virtual section. This is an obfuscation/unpacking triage clue, not observed runtime behavior.", "静态节元数据显示仅虚拟映射或虚拟大小异常的 PE 节；这是混淆/解包分诊线索，不代表已观察到运行时行为。"),
        ("Static YARA-like rule matched", "命中静态 YARA 类规则"),
        ("Suspended process hollowing sequence metadata", "挂起进程空洞化序列元数据"),
        ("Suspicious HTTP C2 user agent", "可疑 HTTP C2 User-Agent"),
        ("Suspicious Windows API import or string", "可疑 Windows API 导入或字符串"),
        ("Svchost ServiceDll points to user-writable DLL", "Svchost ServiceDll 指向用户可写 DLL"),
        ("System directory executable write", "系统目录可执行文件写入"),
        ("System fingerprinting command for anti-analysis", "用于反分析的系统指纹命令"),
        ("System recovery configuration disabled", "系统恢复配置被禁用"),
        ("System-fingerprint telemetry carried an explicit low-resource or sandbox-resource classification, avoiding matches on ordinary CPU/memory inventory fields alone.", "系统指纹遥测携带明确的低资源或沙箱资源分类，避免仅因普通 CPU/内存盘点字段而命中。"),
        ("Telemetry reported a long sleep, accelerated sleep detection, GetTickCount timing check, or time-skew comparison used to evade sandboxes.", "遥测报告长时间休眠、休眠加速检测、GetTickCount 计时检查或时间偏移比较，用于规避沙箱。"),
        ("Telemetry reported creation of WMI EventFilter, EventConsumer, FilterToConsumerBinding, or a repository write associated with permanent WMI subscription persistence.", "遥测报告创建 WMI EventFilter、EventConsumer、FilterToConsumerBinding，或与永久 WMI 订阅持久化相关的存储库写入。"),
        ("Telemetry reported sleep, delay, or wait API usage that can be used to evade short sandbox windows.", "遥测报告 sleep、delay 或 wait API 用法，可能用于规避较短沙箱窗口。"),
        ("Telemetry reported suspended process creation combined with unmap, write, context, or resume operations associated with process hollowing.", "遥测报告挂起进程创建，并伴随 unmap、write、context 或 resume 等进程空洞化相关操作。"),
        ("Telemetry shows a suspended process or thread context modification sequence consistent with hollowing preparation.", "遥测显示挂起进程或线程上下文修改序列，符合进程镂空准备行为。"),
        ("Temp/AppData or executable file drop", "Temp/AppData 或可执行文件落地"),
        ("The command line contains WMIC, shadowcopy, and delete in the same field, a recovery-inhibition ransomware behavior.", "同一命令行字段同时包含 WMIC、shadowcopy 与 delete，是勒索软件抑制恢复的行为。"),
        ("The copied dropped-file artifact path or source path indicates an executable, script, library, driver, or archive payload staged during execution.", "复制的落地文件证据路径或源路径指向执行期间暂存的可执行、脚本、库、驱动或归档载荷。"),
        ("The guest agent could not start the optional R0Collector sidecar; this records collection health rather than malicious sample behavior.", "来宾 Agent 无法启动可选的 R0Collector 侧车；这是采集健康状态记录，不是样本恶意行为。"),
        ("The guest agent observed a file creation or modification during execution.", "来宾 Agent 在执行期间观察到文件创建或修改。"),
        ("The guest agent observed a new TCP connection after sample execution.", "来宾 Agent 在样本执行后观察到新的 TCP 连接。"),
        ("The guest agent observed a non-baseline process after sample execution started. Sandbox plumbing helpers are excluded so the finding stays focused on sample-visible process activity.", "来宾 Agent 在样本执行开始后观察到非基线进程。沙箱管道辅助进程已排除，使命中聚焦于样本可见的进程活动。"),
        ("The guest agent or driver event stream reported a file deletion during execution.", "来宾 Agent 或驱动事件流在执行期间报告了文件删除。"),
        ("The guest artifact collector copied a newly-created sample working-directory file into artifacts/dropped-files for post-run analysis.", "来宾证据采集器将新建的样本工作目录文件复制到 artifacts/dropped-files，供运行后分析。"),
        ("The guest artifact writer produced a manifest that can correlate screenshots, dropped files, memory dumps, and other artifacts with normalized events.", "来宾证据写入器生成了清单，可将截图、落地文件、内存转储和其他证据与规范化事件关联起来。"),
        ("The guest executor failed to start the submitted sample or helper process; failure metadata is surfaced because launch failures can mask behavior.", "来宾执行器无法启动提交的样本或辅助进程；报告失败元数据，因为启动失败可能掩盖行为。"),
        ("The guest screenshot probe captured a desktop image artifact with dimensions or artifact path metadata for behavior review.", "来宾截图探针捕获了桌面图像证据，并带有尺寸或证据路径元数据供行为复核。"),
        ("The guest screenshot probe was enabled but could not capture the desktop; reason and diagnostic fields are surfaced for collection quality review.", "来宾截图探针已启用但无法捕获桌面；原因和诊断字段会展示给采集质量复核。"),
        ("The host accepted a local sample path and created a planning artifact.", "主机接受本地样本路径并创建规划证据。"),
        ("The host artifact-import summary reports ready screenshots, memory dumps, and packet captures together with safe primary relative selectors, preserving evidence availability without treating collection status as malicious behavior.", "Host artifact-import 摘要同时报告截图、内存转储和抓包已就绪，并带有安全主相对选择器；它保留证据可用性，但不把采集状态当作恶意行为。"),
        ("The host generated a reproducible provider-specific execution plan for review.", "主机生成可复现的 provider-specific 执行计划供复核。"),
        ("The kernel driver emitted a startup heartbeat through the R0 event drain path; current builds use a reserved self-test event and later builds may emit driver.load.", "内核驱动通过 R0 事件排空路径输出启动心跳；当前版本使用保留自测事件，后续版本可能输出 driver.load。"),
        ("The opt-in guest memory dump probe captured a minidump artifact for the launched sample process.", "按需启用的来宾内存转储探针为启动的样本进程捕获了 minidump 证据。"),
        ("The opt-in memory dump probe was enabled but could not produce a dump; diagnostics explain whether the root PID, platform, or API call failed.", "按需启用的内存转储探针无法生成 dump；诊断会说明根 PID、平台或 API 调用是否失败。"),
        ("The process-tree probe could not locate the expected root process in the snapshot, which may happen after rapid exit or collection timing races.", "进程树探针无法在快照中定位预期根进程，快速退出或采集时序竞争时可能发生。"),
        ("The process-tree probe emitted a node with parent, root, depth, child-count, or lineage metadata, enabling full descendant review beyond single process-start rows.", "进程树探针输出带有父进程、根、深度、子进程数或谱系元数据的节点，可超越单个 process-start 行审阅完整后代。"),
        ("The sample process was still running when the configured analysis window ended. This is common for GUI applications such as Notepad and is reported as execution-state metadata, not malicious behavior by itself.", "配置的分析窗口结束时样本进程仍在运行。这对记事本等 GUI 应用较常见，报告为执行状态元数据，本身不是恶意行为。"),
        ("The static analyzer recorded PE parse warnings or malformed-header tags. This is parser/format context for analyst review, not proof of malicious behavior.", "静态分析器记录了 PE 解析告警或格式异常标签；这是供分析员复核的解析/格式上下文，不代表恶意行为已发生。"),
        ("Thread context hijacking sequence", "线程上下文劫持序列"),
        ("Thread or API telemetry contains the same-field sequence CREATE_SUSPENDED, QueueUserAPC, and ResumeThread with target process/thread context.", "线程或 API 遥测在同一字段中包含 CREATE_SUSPENDED、QueueUserAPC 和 ResumeThread 序列，并带有目标进程/线程上下文。"),
        ("Thread telemetry reported CreateRemoteThread/NtCreateThreadEx with target process context, start address, and executable writable memory protection.", "线程遥测报告 CreateRemoteThread/NtCreateThreadEx，同时包含目标进程、启动地址和可执行可写内存保护；这是强注入证据。"),
        ("Timing telemetry reported a sleep/time-skew check with a threshold and an execution gate or abort action.", "计时遥测报告睡眠/时间偏移检查、阈值以及执行门控或中止动作。"),
        ("TLS certificate common name is IP literal or dynamic host", "TLS 证书 CN 为 IP 字面量或动态主机名"),
        ("TLS certificate metadata reports an expired, not-yet-valid, or otherwise invalid validity window, a structured asymmetric-certificate quality signal for encrypted channels.", "TLS 证书元数据报告过期、尚未生效或其他无效的有效期窗口，这是加密通道的结构化非对称证书质量信号。"),
        ("TLS certificate reputation risk", "TLS 证书信誉风险"),
        ("TLS certificate validity window failed", "TLS 证书有效期窗口异常"),
        ("TLS directory or callback pointer present", "存在 TLS 目录或回调指针"),
        ("TLS JA3 observed without SNI", "TLS JA3 存在但缺少 SNI"),
        ("TLS metadata combined missing/encrypted SNI with rare, suspicious, or malicious JA3 reputation. Either field alone remains weaker TLS triage.", "TLS 元数据同时包含缺失/加密 SNI 与 rare/suspicious/malicious JA3 信誉；任一字段单独出现仅作为较弱 TLS 排查信号。"),
        ("TLS metadata contained a JA3 hash but no sni/serverName fields, using all-regex plus not-exists predicates for suspicious TLS automation.", "TLS 元数据包含 JA3 哈希但缺少 sni/serverName 字段，使用全字段正则与不存在谓词识别可疑 TLS 自动化。"),
        ("TLS metadata exposed SNI/serverName values using onion or common dynamic-DNS domains associated with evasive or commodity C2 infrastructure.", "TLS 元数据暴露的 SNI/serverName 使用 onion 或常见动态 DNS 域名，常见于规避性或通用 C2 基础设施。"),
        ("TLS metadata exposes a certificate common name that is an IP literal, dynamic-DNS style host, or onion host, using structured certificate CN fields instead of raw handshake text.", "TLS 元数据通过结构化证书 CN 字段暴露 IP 字面量、动态 DNS 风格主机或 onion 主机，而不是依赖原始握手文本。"),
        ("TLS metadata labeled a certificate, thumbprint, issuer, or chain as malicious, suspicious, revoked, abused, or newly observed.", "TLS 元数据将证书、指纹、签发者或证书链标记为恶意、可疑、吊销、滥用或新近出现。"),
        ("TLS metadata reported a missing SNI combined with rare JA3, unusual ALPN, or C2 classification fields.", "TLS 元数据报告缺失 SNI，并伴随罕见 JA3、异常 ALPN 或 C2 分类字段。"),
        ("TLS metadata reported encrypted-client-hello or ESNI, no SNI, a JA3 fingerprint, and risky JA3 reputation/classification.", "TLS 元数据报告 ECH/ESNI、缺失 SNI、JA3 指纹以及高风险 JA3 信誉或分类。"),
        ("TLS metadata reported SNI as an IP literal, high-entropy hostname, dynamic DNS domain, or DGA classification.", "TLS 元数据报告 SNI 为 IP 字面量、高熵主机名、动态 DNS 域名或 DGA 分类。"),
        ("TLS metadata shows a client certificate plus concrete SNI/JA3 context where the JA3 reputation is rare, suspicious, malicious, or C2-labeled.", "TLS 元数据显示客户端证书以及具体 SNI/JA3 上下文，且 JA3 声誉为罕见、可疑、恶意或 C2 标记。"),
        ("TLS no-SNI connection with rare JA3 metadata", "无 SNI 且 JA3 罕见的 TLS 连接"),
        ("TLS no-SNI with risky JA3", "TLS 无 SNI 且 JA3 风险较高"),
        ("TLS or HTTPS network activity observed", "观察到 TLS 或 HTTPS 网络活动"),
        ("TLS or PCAP metadata paired a young domain, suspicious reputation, rare JA3, or C2 classification with TLS SNI/certificate fields.", "TLS 或 PCAP 元数据将新注册域名、可疑信誉、罕见 JA3 或 C2 分类与 SNI/证书字段关联；用于补强 TLS 侧 C2 线索，需结合进程和流量上下文判断。"),
        ("TLS or PCAP metadata reported a self-signed, expired, invalid, or untrusted certificate.", "TLS 或 PCAP 元数据报告自签名、过期、无效或不受信任证书。"),
        ("TLS risky new-domain or C2 JA3 metadata", "TLS 新注册风险域名或 C2 JA3 元数据"),
        ("TLS self-signed or invalid certificate metadata", "TLS 自签名或无效证书元数据"),
        ("TLS SNI IP literal or DGA-like hostname", "TLS SNI 为 IP 字面量或 DGA 风格主机名"),
        ("TLS SNI uses dynamic DNS or onion domain", "TLS SNI 使用动态 DNS 或 Onion 域名"),
        ("TLS SNI, JA3, or certificate metadata observed", "观察到 TLS SNI、JA3 或证书元数据"),
        ("TLS telemetry included SNI, JA3/JA3S, certificate hash, or TLS version fields for encrypted web-protocol triage.", "TLS 遥测包含 SNI、JA3/JA3S、证书哈希或 TLS 版本字段，用于加密 Web 协议分诊。"),
        ("Token impersonation or duplication API observed", "观察到令牌模拟或复制 API"),
        ("Token or API telemetry enabled SeDebugPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeTakeOwnershipPrivilege, or related privileges commonly used for credential theft or escalation.", "令牌或 API 遥测启用了 SeDebugPrivilege、SeBackupPrivilege、SeRestorePrivilege、SeTakeOwnershipPrivilege 等常用于凭据窃取或提权的权限。"),
        ("Tor hidden-service domain string", "Tor 隐藏服务域名字符串"),
        ("TSCON RDP session switch from elevated context", "高权限上下文中的 TSCON RDP 会话切换"),
        ("Typed driver DNS network traffic", "类型化驱动 DNS 网络流量"),
        ("Typed driver outbound network connection", "类型化驱动出站网络连接"),
        ("Typed driver registry Run-key persistence", "类型化驱动注册表 Run 键持久化"),
        ("Typed driver registry Scheduled TaskCache persistence", "类型化驱动注册表计划任务 TaskCache 持久化"),
        ("Typed driver registry service persistence", "类型化驱动注册表服务持久化"),
        ("Typed driver web protocol or web-port traffic", "类型化驱动 Web 协议或 Web 端口流量"),
        ("UAC policy weakened in registry", "注册表削弱 UAC 策略"),
        ("UDP network activity observed", "观察到 UDP 网络活动"),
        ("Upload or exfil-capable API imports", "上传或外传能力 API 导入"),
        ("User activity or interaction check", "用户活动或交互检查"),
        ("User-interaction telemetry reported a low idle/input threshold together with an exit, terminate, delay, or gate action.", "用户交互遥测报告较低空闲/输入阈值，并同时出现退出、终止、延迟或门控动作。"),
        ("User-writable payload shows periodic C2 flow", "用户可写负载出现周期性 C2 流量"),
        ("User-writable process-tree descendant with lineage", "带谱系的用户可写路径进程树子进程"),
        ("Very long NXDOMAIN DNS query", "超长 NXDOMAIN DNS 查询"),
        ("Virtual machine MAC OUI check", "虚拟机 MAC OUI 检查"),
        ("Virtual-memory write into sensitive Windows process", "向敏感 Windows 进程写入虚拟内存"),
        ("Virtual-only or oversized PE section", "仅虚拟映射或虚拟大小异常的 PE 节"),
        ("VirusTotal API key not configured", "未配置 VirusTotal API Key"),
        ("VirusTotal enrichment returned a found result for a SHA-256 and exposed provider counts plus a permalink. This confirms external enrichment coverage only; verdict-specific rules carry malicious or suspicious scoring.", "VirusTotal 富化对 SHA-256 返回已收录结果，并暴露引擎计数和永久链接；这仅确认外部富化覆盖，恶意或可疑评分由判定专用规则承担。"),
        ("VirusTotal enrichment returned a malicious verdict for the submitted SHA-256. This is external reputation evidence, not a local ATT&CK behavior by itself.", "VirusTotal 富化对提交的 SHA-256 返回恶意判定。这是外部信誉证据，本身不是本地 ATT&CK 行为。"),
        ("VirusTotal enrichment returned a malicious verdict for the submitted SHA-256. This is external reputation evidence, not a local ATT&amp;CK behavior by itself.", "VirusTotal 富化对提交的 SHA-256 返回恶意判定。这是外部信誉证据，本身不是本地 ATT&CK 行为。"),
        ("VirusTotal enrichment returned a suspicious verdict without malicious detections; use it as external reputation triage evidence.", "VirusTotal 富化返回可疑判定但无恶意命中；应作为外部信誉排查证据使用。"),
        ("VirusTotal enrichment was skipped because no API key is configured. This quiet diagnostic should not affect maliciousness verdicts.", "由于未配置 API Key，VirusTotal 富化被跳过。此静默诊断不应影响恶意性判定。"),
        ("VirusTotal found result persisted", "VirusTotal 已收录结果已持久化"),
        ("VirusTotal hash not found", "VirusTotal 未收录哈希"),
        ("VirusTotal lookup rate-limited", "VirusTotal 查询被限速"),
        ("VirusTotal malicious verdict", "VirusTotal 恶意判定"),
        ("VirusTotal returned 404/not_found for the SHA-256. This documents enrichment coverage, not malicious or benign behavior.", "VirusTotal 对该 SHA-256 返回 404/not_found。这记录富化覆盖情况，不表示恶意或良性行为。"),
        ("VirusTotal returned a rate-limit status. Reports should show this as enrichment quality metadata instead of a lookup failure with ambiguous meaning.", "VirusTotal 返回限速状态。报告应将其显示为富化质量元数据，而不是语义不清的查询失败。"),
        ("VirusTotal suspicious verdict", "VirusTotal 可疑判定"),
        ("VM artifact check tied to long sleep gate", "VM 痕迹检查关联长休眠门控"),
        ("VM artifact registry query", "虚拟机痕迹注册表查询"),
        ("VM device object probe gates execution", "虚拟机设备对象探测控制执行"),
        ("VM service or registry artifact probe gates execution", "虚拟机服务或注册表痕迹探测控制执行"),
        ("VM, sandbox, debugger, or analysis-tool artifact query", "VM、沙箱、调试器或分析工具痕迹查询"),
        ("Weak service permission hijack metadata", "弱服务权限劫持元数据"),
        ("WebSocket upgrade with non-browser automation user agent", "带非浏览器自动化 User-Agent 的 WebSocket Upgrade"),
        ("Windows credential vault or DPAPI material access", "Windows Credential Vault 或 DPAPI 材料访问"),
        ("Windows event log clearing command", "Windows 事件日志清除命令"),
        ("Windows firewall or network defense disable command", "Windows 防火墙或网络防护禁用命令"),
        ("Windows Script Host execution", "Windows Script Host 执行"),
        ("Windows service creation command", "Windows 服务创建命令"),
        ("Windows service persistence registry path", "Windows 服务持久化注册表路径"),
        ("Windows Time Provider DLL from user-writable path", "Windows 时间提供程序加载用户可写 DLL"),
        ("Windows Time Provider DLL persistence", "Windows Time Provider DLL 持久化"),
        ("Winlogon persistence registry path", "Winlogon 持久化注册表路径"),
        ("Winlogon Shell/Userinit/Notify/GinaDLL registry values referenced user-writable paths or script/proxy execution payloads.", "Winlogon Shell/Userinit/Notify/GinaDLL 注册表值引用用户可写路径或脚本/代理执行载荷。"),
        ("Winlogon value points to user-writable payload", "Winlogon 值指向用户可写载荷"),
        ("WinRM network port observed", "观察到 WinRM 网络端口"),
        ("WinRM or PowerShell remoting command", "WinRM 或 PowerShell 远程命令"),
        ("WinRM or PowerShell remoting target specified", "指定 WinRM 或 PowerShell 远程目标"),
        ("WinRM PowerShell remote script block execution", "WinRM PowerShell 远程脚本块执行"),
        ("WinRM remote management enabled", "启用 WinRM 远程管理"),
        ("WinRM remote target runs encoded PowerShell command", "WinRM 远程目标运行编码 PowerShell 命令"),
        ("WinRM WSMan CreateShell SOAP action", "WinRM WSMan CreateShell SOAP 动作"),
        ("WinRM WSMan remote shell command over HTTP", "通过 HTTP 的 WinRM WSMan 远程 Shell 命令"),
        ("Winsock provider catalog references user-writable DLL", "Winsock Provider Catalog 引用用户可写 DLL"),
        ("WMI command-line event consumer launches user-writable payload", "WMI 命令行事件消费者启动用户可写载荷"),
        ("WMI event subscription creation command", "WMI 事件订阅创建命令"),
        ("WMI event subscription persistence path", "WMI 事件订阅持久化路径"),
        ("WMI event-consumer telemetry ties a CommandLine or ActiveScript consumer to a payload path in a user-writable location.", "WMI 事件消费者遥测将 CommandLine 或 ActiveScript 消费者与用户可写位置中的载荷路径关联。"),
        ("WMI or process telemetry links a remote host to Win32_Process creation of a payload staged through ADMIN$, C$, or remote Windows temporary paths.", "WMI 或进程遥测将远程主机与通过 ADMIN$、C$ 或远程 Windows 临时路径暂存的载荷执行关联。"),
        ("WMI permanent event subscription persistence", "WMI 永久事件订阅持久化"),
        ("WMI remote execution command", "WMI 远程执行命令"),
        ("WMI remote process create executes admin-share payload", "WMI 远程进程创建执行管理共享载荷"),
        ("WMI remote process create with explicit credentials", "带显式凭据的 WMI 远程进程创建"),
        ("WMI Win32_Process Create targets a remote host", "WMI Win32_Process Create 指向远程主机"),
        ("WMIC remote process creation", "WMIC 远程创建进程"),
        ("WMIC shadow copy deletion command", "WMIC 删除卷影副本命令"),
        ("Writable executable, very high entropy, or low-entropy section", "可写可执行、高熵或低熵 PE 节"),
        ("WScript or CScript executes remote script URL", "WScript/CScript 执行远程脚本 URL")
    ];

    /// <summary>
    /// Converts event data dictionary to stable plain text.
    /// Inputs are one event, processing sorts key/value pairs, and the method
    /// returns text suitable for display and clipboard copy.
    /// </summary>
    private static string EventDataToText(SandboxEvent evt)
    {
        if (evt.Data.Count == 0)
        {
            return "-";
        }

        return string.Join(
            Environment.NewLine,
            evt.Data.OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase)
                .Select(pair => $"{pair.Key}={pair.Value}"));
    }

    /// <summary>
    /// Converts event data to a bounded evidence block for finding summaries.
    /// Inputs are one event and size caps; processing keeps high-signal fields
    /// while truncating bulky static/r0 dictionaries; the method returns
    /// clipboard-friendly but report-size-safe text.
    /// </summary>
    private static string EventDataToBoundedText(SandboxEvent evt, int maxPairs, int maxValueLength)
    {
        if (evt.Data.Count == 0)
        {
            return "-";
        }

        var pairs = evt.Data
            .OrderBy(pair => BulkyEvidenceFieldRank(pair.Key))
            .ThenBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase)
            .Take(maxPairs)
            .Select(pair => $"{pair.Key}={FormatBoundedEvidenceFieldValue(pair.Key, pair.Value, maxValueLength)}")
            .ToList();
        var hidden = Math.Max(0, evt.Data.Count - pairs.Count);
        if (hidden > 0)
        {
            pairs.Add($"__omittedDataPairs={hidden}");
        }

        return string.Join(Environment.NewLine, pairs);
    }

    /// <summary>
    /// Converts a normalized event to a one-block evidence string.
    /// Inputs are one event, processing concatenates common and data fields,
    /// and the method returns clipboard-friendly evidence text.
    /// </summary>
    private static string EventToPlainText(SandboxEvent evt)
    {
        var builder = new StringBuilder();
        builder.AppendLine($"time={evt.Timestamp:u}");
        builder.AppendLine($"type={evt.EventType}");
        builder.AppendLine($"source={evt.Source}");
        builder.AppendLine($"process={evt.ProcessName ?? "-"}");
        builder.AppendLine($"pid={evt.ProcessId?.ToString() ?? "-"}");
        builder.AppendLine($"ppid={evt.ParentProcessId?.ToString() ?? "-"}");
        builder.AppendLine($"path={evt.Path ?? "-"}");
        builder.AppendLine($"commandLine={evt.CommandLine ?? "-"}");
        builder.Append(EventDataToText(evt));
        return builder.ToString();
    }

    private static string EventToBoundedPlainText(SandboxEvent evt, int maxDataPairs, int maxValueLength)
    {
        var builder = new StringBuilder();
        builder.AppendLine($"time={evt.Timestamp:u}");
        builder.AppendLine($"type={evt.EventType}");
        builder.AppendLine($"source={evt.Source}");
        builder.AppendLine($"process={evt.ProcessName ?? "-"}");
        builder.AppendLine($"pid={evt.ProcessId?.ToString() ?? "-"}");
        builder.AppendLine($"ppid={evt.ParentProcessId?.ToString() ?? "-"}");
        builder.AppendLine($"path={evt.Path ?? "-"}");
        builder.AppendLine($"commandLine={AbbreviateEvidenceValue(evt.CommandLine ?? "-", maxValueLength)}");
        builder.Append(EventDataToBoundedText(evt, maxDataPairs, maxValueLength));
        return builder.ToString();
    }

    private static int BulkyEvidenceFieldRank(string key)
    {
        return IsBulkyEvidenceFieldKey(key) ? 1 : 0;
    }

    private static string FormatBoundedEvidenceFieldValue(string key, string value, int maxLength)
    {
        if (!IsBulkyEvidenceFieldKey(key))
        {
            return AbbreviateEvidenceValue(value, maxLength);
        }

        if (string.IsNullOrWhiteSpace(value))
        {
            return value;
        }

        var itemCount = value
            .Split([',', ';', '\n', '\r'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Length;
        var preview = value
            .Split([',', ';', '\n', '\r'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Take(5)
            .ToList();
        var previewText = preview.Count == 0 ? string.Empty : " preview=" + string.Join(", ", preview);
        return $"<{key} list: {itemCount} item(s), {value.Length} chars>{AbbreviateEvidenceValue(previewText, Math.Min(maxLength, 120))}";
    }

    private static string AbbreviateEvidenceValue(string value, int maxLength)
    {
        if (string.IsNullOrEmpty(value) || value.Length <= maxLength)
        {
            return value;
        }

        return value[..Math.Max(0, maxLength)] + $"…<truncated {value.Length - maxLength} chars>";
    }

    /// <summary>
    /// Builds lookup keys that let event rows link back to indexed artifacts.
    /// Inputs are report artifact descriptors; processing indexes full paths,
    /// relative paths, safe links, file names, and preserved guest paths; the
    /// method returns a case-insensitive key map.
    /// </summary>
    private static IReadOnlyDictionary<string, List<ArtifactDescriptor>> BuildArtifactLookup(IEnumerable<ArtifactDescriptor> artifacts)
    {
        var lookup = new Dictionary<string, List<ArtifactDescriptor>>(StringComparer.OrdinalIgnoreCase);
        foreach (var artifact in artifacts)
        {
            foreach (var key in ArtifactLookupKeys(artifact))
            {
                if (string.IsNullOrWhiteSpace(key))
                {
                    continue;
                }

                if (!lookup.TryGetValue(key, out var bucket))
                {
                    bucket = [];
                    lookup[key] = bucket;
                }

                if (!bucket.Any(existing => string.Equals(ArtifactKey(existing), ArtifactKey(artifact), StringComparison.OrdinalIgnoreCase)))
                {
                    bucket.Add(artifact);
                }
            }
        }

        return lookup;
    }

    /// <summary>
    /// Finds artifacts referenced by one event.
    /// Inputs are a normalized event plus artifact lookup/index data; processing
    /// matches event paths, path-like data values, screenshot/file import rows,
    /// and R0/driver events; the method returns related descriptors.
    /// </summary>
    private static IReadOnlyCollection<ArtifactDescriptor> FindRelatedArtifacts(
        SandboxEvent evt,
        IReadOnlyDictionary<string, List<ArtifactDescriptor>> artifactLookup,
        IReadOnlyCollection<ArtifactDescriptor> artifacts)
    {
        var related = new Dictionary<string, ArtifactDescriptor>(StringComparer.OrdinalIgnoreCase);
        AddRelatedByValue(related, artifactLookup, evt.Path);

        foreach (var pair in evt.Data)
        {
            if (IsArtifactReferenceKey(pair.Key) || LooksLikeArtifactReference(pair.Value))
            {
                AddRelatedByValue(related, artifactLookup, pair.Value);
            }
        }

        if (IsR0Event(evt) || evt.Source.Contains("driver", StringComparison.OrdinalIgnoreCase))
        {
            AddRelatedByKind(related, artifacts, ArtifactKind.DriverEventsJsonLines);
        }

        if (string.Equals(evt.EventType, "screenshot.captured", StringComparison.OrdinalIgnoreCase))
        {
            AddRelatedByKind(related, artifacts, ArtifactKind.Screenshot);
        }

        if (evt.EventType.StartsWith("memory_dump.", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("memory-dump.", StringComparison.OrdinalIgnoreCase))
        {
            AddRelatedByKind(related, artifacts, ArtifactKind.MemoryDump);
        }

        if (evt.EventType.StartsWith("pcap.", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("packet_capture.", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("packet-capture.", StringComparison.OrdinalIgnoreCase))
        {
            AddRelatedByKind(related, artifacts, ArtifactKind.PacketCapture);
        }

        if (evt.EventType.StartsWith("guest.events.", StringComparison.OrdinalIgnoreCase))
        {
            AddRelatedByKind(related, artifacts, ArtifactKind.GuestEventsJson);
            AddRelatedByKind(related, artifacts, ArtifactKind.DriverEventsJsonLines);
            AddRelatedByKind(related, artifacts, ArtifactKind.ArtifactManifest);
        }

        return related.Values
            .OrderBy(artifact => ArtifactKindRank(artifact.Kind))
            .ThenBy(artifact => artifact.RelativePath, StringComparer.OrdinalIgnoreCase)
            .ThenBy(artifact => artifact.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>
    /// Renders an inline event location with a compact artifact link when one is
    /// available. Inputs are one event and related artifacts; processing keeps
    /// the original event path visible while adding the durable safe link.
    /// </summary>
    private static string RenderInlineEventLocation(SandboxEvent evt, IReadOnlyCollection<ArtifactDescriptor> relatedArtifacts)
    {
        var label = evt.Path ?? evt.CommandLine ?? string.Empty;
        if (string.IsNullOrWhiteSpace(label))
        {
            return string.Empty;
        }

        var link = relatedArtifacts.FirstOrDefault(artifact => !string.IsNullOrWhiteSpace(ArtifactHref(artifact)));
        if (link is null)
        {
            return E(label);
        }

        return $"{E(label)} {RenderArtifactActionButtons(link, inline: true)}";
    }

    /// <summary>
    /// Renders the path/target cell for event tables.
    /// Inputs are one event and related artifacts; processing adds report-local
    /// anchors for dropped files, screenshots, driver JSONL, and manifests.
    /// </summary>
    private static string RenderEventPathAndCommand(SandboxEvent evt, IReadOnlyCollection<ArtifactDescriptor> relatedArtifacts)
    {
        var path = ExtractReadableEventTarget(evt);
        var html = new StringBuilder();
        html.Append($"<code>{E(path)}</code>");

        var links = relatedArtifacts
            .Where(artifact => !string.IsNullOrWhiteSpace(ArtifactHref(artifact)))
            .Take(4)
            .ToList();
        foreach (var artifact in links)
        {
            html.Append($"<br>{RenderArtifactActionButtons(artifact, inline: true)}");
        }

        if (!string.IsNullOrWhiteSpace(evt.CommandLine))
        {
            html.Append(RenderTechnicalField("Command line", evt.CommandLine!));
        }

        return html.ToString();
    }

    /// <summary>
    /// Renders a copy button for related artifact descriptors.
    /// Inputs are related artifacts; processing serializes descriptor evidence
    /// into one clipboard block; the method returns an empty string when there
    /// are no related artifacts.
    /// </summary>
    private static string RenderCopyArtifactsButton(IReadOnlyCollection<ArtifactDescriptor> artifacts)
    {
        if (artifacts.Count == 0)
        {
            return string.Empty;
        }

        var copy = string.Join(
            $"{Environment.NewLine}---{Environment.NewLine}",
            artifacts.Select(ArtifactToPlainText));
        return CopyButton("Copy artifacts", copy);
    }

    /// <summary>
    /// Renders collapsible related-artifact evidence for one event.
    /// Inputs are related descriptors; processing writes safe links plus flat
    /// inline copy actions; the method returns trusted local HTML.
    /// </summary>
    private static string RenderRelatedArtifacts(IReadOnlyCollection<ArtifactDescriptor> artifacts)
    {
        if (artifacts.Count == 0)
        {
            return string.Empty;
        }

        var html = new StringBuilder();
        html.AppendLine($"<details class=\"flat-details related-artifacts-flat\"><summary>Related artifacts ({artifacts.Count})</summary><ul class=\"artifact-list\">");
        foreach (var artifact in artifacts)
        {
            var plain = ArtifactToPlainText(artifact);
            html.Append("<li>");
            html.Append(RenderArtifactLocation(artifact));
            html.Append($"<br><span class=\"muted\">{E(artifact.Kind.ToString())} / {E(artifact.Category)}</span>");
            html.Append($"<br><span class=\"inline-actions\">{CopyButton("Copy artifact evidence", plain)}</span>");
            html.AppendLine("</li>");
        }

        html.AppendLine("</ul></details>");
        return html.ToString();
    }

    /// <summary>
    /// Builds the report artifact list from a host index plus paths embedded in
    /// events. Inputs are report events and optional descriptors; processing
    /// deduplicates safe/indexed files and guest-local path hints; the method
    /// returns sorted artifact descriptors for the HTML artifact section.
    /// </summary>
    private static IReadOnlyCollection<ArtifactDescriptor> BuildReportArtifactList(AnalysisReport report, IEnumerable<ArtifactDescriptor>? artifacts)
    {
        var merged = new Dictionary<string, ArtifactDescriptor>(StringComparer.OrdinalIgnoreCase);
        if (artifacts is not null)
        {
            foreach (var artifact in artifacts)
            {
                AddReportArtifact(merged, ArtifactDescriptorFactory.NormalizeDescriptor(artifact));
            }
        }

        foreach (var artifact in InferArtifactsFromEvents(report))
        {
            AddReportArtifact(merged, artifact);
        }

        return merged.Values
            .Where(artifact => IsReportArtifactKind(artifact.Kind))
            .OrderBy(artifact => ArtifactKindRank(artifact.Kind))
            .ThenBy(artifact => artifact.RelativePath, StringComparer.OrdinalIgnoreCase)
            .ThenBy(artifact => artifact.FullPath, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>
    /// Infers artifact descriptors from normalized events when no host index
    /// was supplied. Inputs are report events; processing discovers imported
    /// guest outputs, sibling JSONL, screenshots, and file-event paths; the
    /// method returns path descriptors.
    /// </summary>
    private static IEnumerable<ArtifactDescriptor> InferArtifactsFromEvents(AnalysisReport report)
    {
        var descriptors = new List<ArtifactDescriptor>();
        foreach (var evt in report.Events)
        {
            if (evt.EventType.StartsWith("guest.events.", StringComparison.OrdinalIgnoreCase) &&
                !string.IsNullOrWhiteSpace(evt.Path))
            {
                var reportRoot = TryResolveReportRoot(report.JobId, evt.Path);
                var importedKind = evt.Path.EndsWith(".jsonl", StringComparison.OrdinalIgnoreCase)
                    ? ArtifactKind.DriverEventsJsonLines
                    : ArtifactKind.GuestEventsJson;
                AddPathDescriptor(descriptors, evt.Path, reportRoot, importedKind, importedKind == ArtifactKind.GuestEventsJson ? "events.json" : "driver-events");
                AddGuestOutputArtifacts(descriptors, evt.Path, reportRoot);
            }

            if (string.Equals(evt.EventType, "screenshot.captured", StringComparison.OrdinalIgnoreCase) &&
                !string.IsNullOrWhiteSpace(evt.Path))
            {
                AddPathDescriptor(descriptors, evt.Path, TryResolveReportRoot(report.JobId, evt.Path), ArtifactKind.Screenshot, "screenshot");
            }

            if ((evt.EventType.StartsWith("memory_dump.", StringComparison.OrdinalIgnoreCase) ||
                    evt.EventType.StartsWith("memory-dump.", StringComparison.OrdinalIgnoreCase)) &&
                !string.IsNullOrWhiteSpace(evt.Path))
            {
                AddPathDescriptor(descriptors, evt.Path, TryResolveReportRoot(report.JobId, evt.Path), ArtifactKind.MemoryDump, "memory-dump");
            }

            if ((evt.EventType.StartsWith("pcap.", StringComparison.OrdinalIgnoreCase) ||
                    evt.EventType.StartsWith("packet_capture.", StringComparison.OrdinalIgnoreCase) ||
                    evt.EventType.StartsWith("packet-capture.", StringComparison.OrdinalIgnoreCase)) &&
                !string.IsNullOrWhiteSpace(evt.Path))
            {
                AddPathDescriptor(descriptors, evt.Path, TryResolveReportRoot(report.JobId, evt.Path), ArtifactKind.PacketCapture, "packet-capture");
            }

            if (evt.EventType.StartsWith("file.", StringComparison.OrdinalIgnoreCase) &&
                !string.IsNullOrWhiteSpace(evt.Path))
            {
                AddPathDescriptor(descriptors, evt.Path, TryResolveReportRoot(report.JobId, evt.Path), ArtifactKind.DroppedFile, "file-event-path");
            }

            foreach (var driverPath in EnumerateDriverPathHints(evt))
            {
                AddPathDescriptor(descriptors, driverPath, TryResolveReportRoot(report.JobId, driverPath), ArtifactKind.DriverEventsJsonLines, "driver-events");
            }
        }

        return descriptors;
    }

    private static void AddGuestOutputArtifacts(List<ArtifactDescriptor> descriptors, string eventsPath, string? reportRoot)
    {
        if (string.IsNullOrWhiteSpace(eventsPath))
        {
            return;
        }

        string? guestOutputRoot;
        try
        {
            guestOutputRoot = Path.GetDirectoryName(Path.GetFullPath(eventsPath));
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(guestOutputRoot) || !Directory.Exists(guestOutputRoot))
        {
            return;
        }

        foreach (var jsonlPath in Directory.EnumerateFiles(guestOutputRoot, "*.jsonl", SearchOption.AllDirectories)
            .Where(path => Path.GetFileName(path).Contains("driver", StringComparison.OrdinalIgnoreCase)))
        {
            AddPathDescriptor(descriptors, jsonlPath, reportRoot, ArtifactKind.DriverEventsJsonLines, "driver-events");
        }

        var screenshotsRoot = Path.Combine(guestOutputRoot, "screenshots");
        if (Directory.Exists(screenshotsRoot))
        {
            foreach (var screenshotPath in Directory.EnumerateFiles(screenshotsRoot, "*", SearchOption.AllDirectories))
            {
                AddPathDescriptor(descriptors, screenshotPath, reportRoot, ArtifactKind.Screenshot, "screenshot");
            }
        }

        var artifactsRoot = Path.Combine(guestOutputRoot, "artifacts");
        if (!Directory.Exists(artifactsRoot))
        {
            return;
        }

        var manifestPath = Path.Combine(artifactsRoot, "manifest.json");
        if (File.Exists(manifestPath))
        {
            AddPathDescriptor(descriptors, manifestPath, reportRoot, ArtifactKind.ArtifactManifest, "artifact-manifest");
            descriptors.AddRange(TryReadGuestManifestArtifacts(manifestPath, guestOutputRoot, reportRoot));
        }

        foreach (var droppedPath in Directory.EnumerateFiles(artifactsRoot, "*", SearchOption.AllDirectories)
            .Where(path => !string.Equals(Path.GetFullPath(path), Path.GetFullPath(manifestPath), StringComparison.OrdinalIgnoreCase)))
        {
            AddPathDescriptor(descriptors, droppedPath, reportRoot, ArtifactKind.DroppedFile, "dropped-file");
        }
    }

    private static IReadOnlyCollection<ArtifactDescriptor> TryReadGuestManifestArtifacts(string manifestPath, string guestOutputRoot, string? reportRoot)
    {
        try
        {
            var manifest = JsonSerializer.Deserialize<ArtifactManifest>(File.ReadAllText(manifestPath), ArtifactJsonOptions);
            if (manifest is null || manifest.Artifacts.Count == 0)
            {
                return [];
            }

            var linkRoot = string.IsNullOrWhiteSpace(reportRoot) ? guestOutputRoot : reportRoot;
            var descriptors = new List<ArtifactDescriptor>();
            foreach (var descriptor in manifest.Artifacts)
            {
                var relativePath = ArtifactDescriptorFactory.NormalizeRelativePath(descriptor.RelativePath);
                if (string.IsNullOrWhiteSpace(relativePath))
                {
                    continue;
                }

                var metadata = descriptor.Metadata is null
                    ? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    : new Dictionary<string, string>(descriptor.Metadata, StringComparer.OrdinalIgnoreCase);
                metadata["origin"] = "guest-manifest";
                metadata["manifestPath"] = manifestPath;
                if (!string.IsNullOrWhiteSpace(descriptor.FullPath) &&
                    !metadata.ContainsKey("guestFullPath"))
                {
                    metadata["guestFullPath"] = descriptor.FullPath;
                }

                if (!metadata.ContainsKey("evidenceRole"))
                {
                    metadata["evidenceRole"] = string.IsNullOrWhiteSpace(descriptor.Category)
                        ? ArtifactDescriptorFactory.CategoryForKind(descriptor.Kind)
                        : descriptor.Category;
                }

                var hostPath = Path.GetFullPath(Path.Combine(guestOutputRoot, relativePath));
                var normalized = File.Exists(hostPath)
                    ? ArtifactDescriptorFactory.FromExistingFile(hostPath, linkRoot, descriptor.Kind, metadata, descriptor.Category)
                    : ArtifactDescriptorFactory.FromKnownPath(hostPath, linkRoot, descriptor.Kind, metadata, descriptor.Category);

                descriptors.Add(normalized with
                {
                    Name = string.IsNullOrWhiteSpace(descriptor.Name) ? normalized.Name : descriptor.Name,
                    MimeType = string.IsNullOrWhiteSpace(descriptor.MimeType) ? normalized.MimeType : descriptor.MimeType,
                    SizeBytes = descriptor.SizeBytes > 0 ? descriptor.SizeBytes : normalized.SizeBytes,
                    Sha256 = string.IsNullOrWhiteSpace(descriptor.Sha256) ? normalized.Sha256 : descriptor.Sha256,
                    Hashes = MergeArtifactHashes(descriptor, normalized),
                    CreatedAtUtc = descriptor.CreatedAtUtc == default ? normalized.CreatedAtUtc : descriptor.CreatedAtUtc,
                    Metadata = metadata
                });
            }

            return descriptors;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or ArgumentException or NotSupportedException or PathTooLongException)
        {
            return [];
        }
    }

    private static IEnumerable<string> EnumerateDriverPathHints(SandboxEvent evt)
    {
        if (!string.IsNullOrWhiteSpace(evt.Path) &&
            evt.Path.EndsWith(".jsonl", StringComparison.OrdinalIgnoreCase))
        {
            yield return evt.Path;
        }

        foreach (var pair in evt.Data)
        {
            if (pair.Value.EndsWith(".jsonl", StringComparison.OrdinalIgnoreCase) &&
                (Path.IsPathFullyQualified(pair.Value) || File.Exists(pair.Value)))
            {
                yield return pair.Value;
            }
        }
    }

    private static void AddPathDescriptor(List<ArtifactDescriptor> descriptors, string path, string? reportRoot, ArtifactKind kind, string evidenceRole)
    {
        var metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["origin"] = "report",
            ["evidenceRole"] = evidenceRole
        };
        descriptors.Add(ArtifactDescriptorFactory.FromKnownPath(path, reportRoot, kind, metadata));
    }

    private static IEnumerable<string> ArtifactLookupKeys(ArtifactDescriptor artifact)
    {
        yield return NormalizeLookupKey(artifact.FullPath);
        yield return NormalizeLookupKey(artifact.RelativePath);
        yield return NormalizeLookupKey(artifact.SafeLink);
        yield return NormalizeLookupKey(artifact.Name);

        foreach (var pair in artifact.Metadata ?? [])
        {
            if (IsArtifactReferenceKey(pair.Key) || LooksLikeArtifactReference(pair.Value))
            {
                yield return NormalizeLookupKey(pair.Value);
            }
        }
    }

    private static void AddRelatedByValue(
        Dictionary<string, ArtifactDescriptor> related,
        IReadOnlyDictionary<string, List<ArtifactDescriptor>> artifactLookup,
        string? value)
    {
        var key = NormalizeLookupKey(value);
        if (string.IsNullOrWhiteSpace(key) || !artifactLookup.TryGetValue(key, out var artifacts))
        {
            return;
        }

        foreach (var artifact in artifacts)
        {
            related[ArtifactKey(artifact)] = artifact;
        }
    }

    private static void AddRelatedByKind(
        Dictionary<string, ArtifactDescriptor> related,
        IReadOnlyCollection<ArtifactDescriptor> artifacts,
        ArtifactKind kind)
    {
        foreach (var artifact in artifacts.Where(artifact => artifact.Kind == kind))
        {
            related[ArtifactKey(artifact)] = artifact;
        }
    }

    private static bool EventHasArtifactReference(SandboxEvent evt)
    {
        if (LooksLikeArtifactReference(evt.Path))
        {
            return true;
        }

        return evt.Data.Any(pair => IsArtifactReferenceKey(pair.Key) || LooksLikeArtifactReference(pair.Value));
    }

    private static bool IsArtifactReferenceKey(string key)
    {
        return key.Contains("path", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("artifact", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("screenshot", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("manifest", StringComparison.OrdinalIgnoreCase) ||
            key.Contains("driverEvent", StringComparison.OrdinalIgnoreCase);
    }

    private static bool LooksLikeArtifactReference(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var normalized = value.Replace('\\', '/');
        return normalized.Contains("/artifacts/", StringComparison.OrdinalIgnoreCase) ||
            normalized.StartsWith("artifacts/", StringComparison.OrdinalIgnoreCase) ||
            normalized.Contains("/screenshots/", StringComparison.OrdinalIgnoreCase) ||
            normalized.StartsWith("screenshots/", StringComparison.OrdinalIgnoreCase) ||
            normalized.EndsWith("driver-events.jsonl", StringComparison.OrdinalIgnoreCase) ||
            normalized.EndsWith("manifest.json", StringComparison.OrdinalIgnoreCase) ||
            normalized.EndsWith(".jsonl", StringComparison.OrdinalIgnoreCase) ||
            normalized.EndsWith(".bmp", StringComparison.OrdinalIgnoreCase) ||
            normalized.EndsWith(".png", StringComparison.OrdinalIgnoreCase) ||
            normalized.EndsWith(".jpg", StringComparison.OrdinalIgnoreCase) ||
            normalized.EndsWith(".jpeg", StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeLookupKey(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var trimmed = value.Trim().Trim('"', '\'');
        try
        {
            if (Path.IsPathFullyQualified(trimmed))
            {
                return Path.GetFullPath(trimmed)
                    .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                    .ToLowerInvariant();
            }
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return string.Empty;
        }

        var relative = ArtifactDescriptorFactory.NormalizeRelativePath(trimmed);
        return string.IsNullOrWhiteSpace(relative)
            ? trimmed.Replace('\\', '/').Trim('/').ToLowerInvariant()
            : relative.ToLowerInvariant();
    }

    private static void AddReportArtifact(Dictionary<string, ArtifactDescriptor> artifacts, ArtifactDescriptor artifact)
    {
        if (!IsReportArtifactKind(artifact.Kind))
        {
            return;
        }

        var key = ArtifactKey(artifact);
        if (artifacts.TryGetValue(key, out var existing))
        {
            artifacts[key] = MergeArtifactDescriptor(existing, artifact);
            return;
        }

        artifacts[key] = artifact;
    }

    private static ArtifactDescriptor MergeArtifactDescriptor(ArtifactDescriptor existing, ArtifactDescriptor incoming)
    {
        var metadata = new Dictionary<string, string>(existing.Metadata, StringComparer.OrdinalIgnoreCase);
        foreach (var pair in incoming.Metadata)
        {
            metadata.TryAdd(pair.Key, pair.Value);
        }

        var hashes = new Dictionary<string, string>(existing.Hashes, StringComparer.OrdinalIgnoreCase);
        foreach (var pair in incoming.Hashes)
        {
            hashes.TryAdd(pair.Key, pair.Value);
        }

        if (!string.IsNullOrWhiteSpace(incoming.Sha256))
        {
            hashes.TryAdd("sha256", incoming.Sha256);
        }

        return existing with
        {
            Category = string.IsNullOrWhiteSpace(existing.Category) ? incoming.Category : existing.Category,
            RelativePath = string.IsNullOrWhiteSpace(existing.RelativePath) ? incoming.RelativePath : existing.RelativePath,
            FullPath = string.IsNullOrWhiteSpace(existing.FullPath) ? incoming.FullPath : existing.FullPath,
            SafeLink = string.IsNullOrWhiteSpace(existing.SafeLink) ? incoming.SafeLink : existing.SafeLink,
            MimeType = string.IsNullOrWhiteSpace(existing.MimeType) ? incoming.MimeType : existing.MimeType,
            SizeBytes = existing.SizeBytes > 0 ? existing.SizeBytes : incoming.SizeBytes,
            Sha256 = string.IsNullOrWhiteSpace(existing.Sha256) ? incoming.Sha256 : existing.Sha256,
            Hashes = hashes,
            Metadata = metadata
        };
    }

    private static string ArtifactKey(ArtifactDescriptor artifact)
    {
        if (!string.IsNullOrWhiteSpace(artifact.FullPath))
        {
            return $"{artifact.Kind}|{artifact.FullPath}";
        }

        if (!string.IsNullOrWhiteSpace(artifact.RelativePath))
        {
            return $"{artifact.Kind}|{artifact.RelativePath}";
        }

        return $"{artifact.Kind}|{artifact.Name}";
    }

    private static bool IsReportArtifactKind(ArtifactKind kind)
    {
        return kind is ArtifactKind.GuestEventsJson or
            ArtifactKind.DriverEventsJsonLines or
            ArtifactKind.ArtifactManifest or
            ArtifactKind.Screenshot or
            ArtifactKind.MemoryDump or
            ArtifactKind.PacketCapture or
            ArtifactKind.DroppedFile;
    }

    private static int ArtifactKindRank(ArtifactKind kind)
    {
        return kind switch
        {
            ArtifactKind.GuestEventsJson => 0,
            ArtifactKind.DriverEventsJsonLines => 1,
            ArtifactKind.ArtifactManifest => 2,
            ArtifactKind.Screenshot => 3,
            ArtifactKind.MemoryDump => 4,
            ArtifactKind.PacketCapture => 5,
            ArtifactKind.DroppedFile => 6,
            _ => 9
        };
    }

    private static string? TryResolveReportRoot(Guid jobId, string path)
    {
        try
        {
            var fullPath = Path.GetFullPath(path);
            var directory = File.Exists(fullPath)
                ? new FileInfo(fullPath).Directory
                : new DirectoryInfo(Path.GetDirectoryName(fullPath) ?? fullPath);
            var marker = jobId.ToString("N");
            string? candidate = null;
            while (directory is not null)
            {
                if (string.Equals(directory.Name, marker, StringComparison.OrdinalIgnoreCase))
                {
                    candidate = directory.FullName;
                }

                directory = directory.Parent;
            }

            return candidate;
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return null;
        }
    }

    private static string RenderArtifactIndexEvidence(ArtifactDescriptor artifact)
    {
        var fields = new List<(string Label, string Value)>
        {
            ("selector", FirstNonEmpty(
                MetadataValue(artifact.Metadata, "downloadSelector"),
                artifact.RelativePath,
                artifact.ImportPath,
                "-")),
            ("href", FirstNonEmpty(
                ArtifactHref(artifact),
                MetadataValue(artifact.Metadata, "downloadSafeLink", "safeLink"),
                "-")),
            ("importPath", FirstNonEmpty(artifact.ImportPath, MetadataValue(artifact.Metadata, "importPath"), "-"))
        };

        AddArtifactIndexField(fields, "duplicate", DuplicateArtifactLabel(artifact));
        AddArtifactIndexField(fields, "rejection", ArtifactRejectionLabel(artifact));

        var copy = ArtifactIndexEvidenceLine(artifact);
        var html = new StringBuilder();
        html.Append("<div class=\"relationship-tags artifact-index-fields\">");
        foreach (var field in fields.Where(field => !string.IsNullOrWhiteSpace(field.Value)))
        {
            html.Append($"<span class=\"chip chip-info copyable\" data-copy=\"{A(field.Label + "=" + field.Value)}\">{E(field.Label)}={E(field.Value)}</span>");
        }

        html.Append("</div>");
        html.Append($"<details class=\"flat-details\"><summary>Download selector / duplicate / rejection diagnostics</summary><pre class=\"copyable\" data-copy=\"{A(copy)}\">{E(copy)}</pre></details>");
        return html.ToString();
    }

    private static void AddArtifactIndexField(List<(string Label, string Value)> fields, string label, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            fields.Add((label, value));
        }
    }

    private static bool HasDownloadSelectorEvidence(ArtifactDescriptor artifact)
    {
        return !string.IsNullOrWhiteSpace(artifact.RelativePath) ||
            !string.IsNullOrWhiteSpace(artifact.SafeLink) ||
            !string.IsNullOrWhiteSpace(artifact.ImportPath) ||
            !string.IsNullOrWhiteSpace(MetadataValue(artifact.Metadata, "downloadSelector", "safeRelativeSelector", "downloadSafeLink", "safeLink"));
    }

    private static bool IsDuplicateArtifactDescriptor(ArtifactDescriptor artifact)
    {
        return TextEqualsAny(MetadataValue(artifact.Metadata, "isDuplicate") ?? string.Empty, "true", "1", "yes") ||
            !string.IsNullOrWhiteSpace(MetadataValue(artifact.Metadata, "duplicateOfArtifactRelativePath")) ||
            (int.TryParse(MetadataValue(artifact.Metadata, "duplicateOrdinal"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var ordinal) && ordinal > 0);
    }

    private static bool HasArtifactRejectionDiagnostics(ArtifactDescriptor artifact)
    {
        return TextEqualsAny(MetadataValue(artifact.Metadata, "rejectionDiagnosticsAvailable") ?? string.Empty, "true", "1", "yes") ||
            ArtifactRejectedCount(artifact) > 0 ||
            !string.IsNullOrWhiteSpace(MetadataValue(artifact.Metadata, "artifactRejectionReasons", "lastRejectedArtifactSelector", "zhRejectionHint"));
    }

    private static int ArtifactRejectedCount(ArtifactDescriptor artifact)
    {
        return int.TryParse(MetadataValue(artifact.Metadata, "rejectedArtifactCount"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var count)
            ? Math.Max(0, count)
            : 0;
    }

    private static string? DuplicateArtifactLabel(ArtifactDescriptor artifact)
    {
        var groupCount = MetadataValue(artifact.Metadata, "duplicateGroupCount");
        var primary = MetadataValue(artifact.Metadata, "duplicatePrimarySelector", "duplicateOfArtifactRelativePath");
        var isDuplicate = MetadataValue(artifact.Metadata, "isDuplicate");
        if (string.IsNullOrWhiteSpace(groupCount) && string.IsNullOrWhiteSpace(primary) && string.IsNullOrWhiteSpace(isDuplicate))
        {
            return null;
        }

        return $"isDuplicate={FirstNonEmpty(isDuplicate, "false")}; groupCount={FirstNonEmpty(groupCount, "-")}; primary={FirstNonEmpty(primary, "-")}";
    }

    private static string? ArtifactRejectionLabel(ArtifactDescriptor artifact)
    {
        if (!HasArtifactRejectionDiagnostics(artifact))
        {
            return null;
        }

        return $"count={ArtifactRejectedCount(artifact)}; reasons={FirstNonEmpty(MetadataValue(artifact.Metadata, "artifactRejectionReasons"), "-")}; last={FirstNonEmpty(MetadataValue(artifact.Metadata, "lastRejectedArtifactSelector"), "-")}";
    }

    private static string ArtifactIndexEvidenceLine(ArtifactDescriptor artifact)
    {
        return string.Join(
            " | ",
            [
                $"artifact={ArtifactDisplayName(artifact)}",
                $"kind={artifact.Kind}",
                $"downloadSelector={FirstNonEmpty(MetadataValue(artifact.Metadata, "downloadSelector"), artifact.RelativePath, "-")}",
                $"safeLink={FirstNonEmpty(ArtifactHref(artifact), MetadataValue(artifact.Metadata, "downloadSafeLink", "safeLink"), "-")}",
                $"safeRelativeSelector={FirstNonEmpty(MetadataValue(artifact.Metadata, "safeRelativeSelector"), artifact.RelativePath, "-")}",
                $"importPath={FirstNonEmpty(artifact.ImportPath, MetadataValue(artifact.Metadata, "importPath"), "-")}",
                $"duplicate={DuplicateArtifactLabel(artifact) ?? "false"}",
                $"rejection={ArtifactRejectionLabel(artifact) ?? "none"}"
            ]);
    }

    private static string RenderArtifactLocation(ArtifactDescriptor artifact)
    {
        var displayPath = !string.IsNullOrWhiteSpace(artifact.RelativePath)
            ? artifact.RelativePath
            : ArtifactDisplayName(artifact);
        var html = new StringBuilder();
        html.Append("<div class=\"artifact-location\">");
        html.Append($"<code class=\"copyable\" data-copy=\"{A(displayPath)}\">{E(string.IsNullOrWhiteSpace(displayPath) ? "-" : displayPath)}</code>");
        html.Append(RenderArtifactActionButtons(artifact));

        if (!string.IsNullOrWhiteSpace(artifact.FullPath))
        {
            html.Append($"<div class=\"artifact-copy-path\"><span class=\"muted\">Host/local path (copy only)</span><br><code class=\"copyable\" data-copy=\"{A(artifact.FullPath)}\">{E(artifact.FullPath)}</code></div>");
        }

        html.Append("</div>");
        return html.ToString();
    }

    private static string RenderArtifactPreview(ArtifactDescriptor artifact)
    {
        var href = ArtifactHref(artifact);
        if (artifact.Kind == ArtifactKind.Screenshot && !string.IsNullOrWhiteSpace(href))
        {
            return $"<details class=\"artifact-preview\"><summary>Screenshot preview</summary><a href=\"{A(href)}\"><img alt=\"{A(artifact.Name)}\" src=\"{A(href)}\"></a></details>";
        }

        var preview = TryReadTextArtifactPreview(artifact);
        if (string.IsNullOrWhiteSpace(preview))
        {
            return string.Empty;
        }

        var title = artifact.Kind switch
        {
            ArtifactKind.DriverEventsJsonLines => "Driver JSONL preview",
            ArtifactKind.ArtifactManifest => "Manifest preview",
            ArtifactKind.GuestEventsJson => "Events JSON preview",
            _ => "Text preview"
        };
        return $"<details class=\"flat-details\"><summary>{E(title)}</summary><pre class=\"copyable\" data-copy=\"{A(preview)}\">{E(preview)}</pre></details>";
    }

    private static string ArtifactToPlainText(ArtifactDescriptor artifact)
    {
        var builder = new StringBuilder();
        builder.AppendLine($"kind={artifact.Kind}");
        builder.AppendLine($"category={artifact.Category}");
        builder.AppendLine($"name={artifact.Name}");
        builder.AppendLine($"relativePath={artifact.RelativePath}");
        builder.AppendLine($"safeLink={artifact.SafeLink}");
        builder.AppendLine($"fullPath={artifact.FullPath}");
        builder.AppendLine($"mimeType={artifact.MimeType}");
        builder.AppendLine($"sizeBytes={artifact.SizeBytes}");
        builder.AppendLine($"sha256={ArtifactSha256(artifact)}");
        foreach (var hash in (artifact.Hashes ?? []).OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase))
        {
            builder.AppendLine($"hash.{hash.Key}={hash.Value}");
        }

        foreach (var pair in (artifact.Metadata ?? []).OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase))
        {
            builder.AppendLine($"metadata.{pair.Key}={pair.Value}");
        }

        return builder.ToString();
    }

    private static string ArtifactDisplayName(ArtifactDescriptor artifact)
    {
        if (!string.IsNullOrWhiteSpace(artifact.RelativePath))
        {
            return artifact.RelativePath;
        }

        if (!string.IsNullOrWhiteSpace(artifact.Name))
        {
            return artifact.Name;
        }

        return artifact.Kind.ToString();
    }

    private static string? TryReadTextArtifactPreview(ArtifactDescriptor artifact)
    {
        if (artifact.Kind is not (ArtifactKind.DriverEventsJsonLines or ArtifactKind.ArtifactManifest or ArtifactKind.GuestEventsJson))
        {
            return null;
        }

        if (string.IsNullOrWhiteSpace(artifact.FullPath) || !File.Exists(artifact.FullPath))
        {
            return null;
        }

        try
        {
            using var stream = new FileStream(artifact.FullPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
            var buffer = new char[ArtifactPreviewCharacterLimit + 1];
            var read = reader.ReadBlock(buffer, 0, buffer.Length);
            var preview = new string(buffer, 0, Math.Min(read, ArtifactPreviewCharacterLimit));
            if (read > ArtifactPreviewCharacterLimit || stream.Position < stream.Length)
            {
                preview += $"{Environment.NewLine}... truncated after {ArtifactPreviewCharacterLimit} characters ...";
            }

            return preview;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or DecoderFallbackException or ArgumentException or NotSupportedException or PathTooLongException)
        {
            return null;
        }
    }

    private static string FormatArtifactSize(long sizeBytes)
    {
        return sizeBytes > 0 ? FormatBytes(sizeBytes) : "-";
    }

    private static string ArtifactSha256(ArtifactDescriptor artifact)
    {
        if (!string.IsNullOrWhiteSpace(artifact.Sha256))
        {
            return artifact.Sha256;
        }

        return artifact.Hashes is not null && artifact.Hashes.TryGetValue("sha256", out var hash) && !string.IsNullOrWhiteSpace(hash)
            ? hash
            : "-";
    }

    private static Dictionary<string, string> MergeArtifactHashes(ArtifactDescriptor descriptor, ArtifactDescriptor normalized)
    {
        var hashes = new Dictionary<string, string>(normalized.Hashes ?? [], StringComparer.OrdinalIgnoreCase);
        foreach (var pair in descriptor.Hashes ?? [])
        {
            hashes[pair.Key] = pair.Value;
        }

        if (!string.IsNullOrWhiteSpace(descriptor.Sha256))
        {
            hashes["sha256"] = descriptor.Sha256;
        }

        return hashes;
    }

    /// <summary>
    /// Appends local JavaScript for copy interactions.
    /// Inputs are a StringBuilder, processing writes a self-contained script,
    /// and the method returns no value.
    /// </summary>
    private static void AppendReportScripts(StringBuilder html)
    {
        html.AppendLine("""
<script>
(function () {
  function copyText(value) {
    if (!value) { return; }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(value).catch(function () { fallbackCopyText(value); });
      return;
    }

    fallbackCopyText(value);
  }

  function fallbackCopyText(value) {
    var area = document.createElement('textarea');
    area.value = value;
    area.style.position = 'fixed';
    area.style.left = '-9999px';
    document.body.appendChild(area);
    area.focus();
    area.select();
    try { document.execCommand('copy'); } finally { document.body.removeChild(area); }
  }

  document.addEventListener('contextmenu', function (event) {
    var target = event.target.closest('[data-copy], code, pre, td, th, li, p, h1, h2, h3, a, button');
    if (!target) { return; }
    var value = target.getAttribute('data-copy') || target.innerText || target.textContent || '';
    if (!value.trim()) { return; }
    event.preventDefault();
    copyText(value);
  });

  document.addEventListener('click', function (event) {
    var target = event.target.closest('[data-copy-button]');
    if (!target) { return; }
    copyText(target.getAttribute('data-copy') || '');
    var original = target.textContent;
    target.textContent = 'Copied';
    window.setTimeout(function () { target.textContent = original; }, 900);
  });

  document.documentElement.classList.add('report-js');
  var reportSidebar = document.querySelector('.report-sidebar');
  var sidebarToggle = document.querySelector('.sidebar-toggle');
  function setSidebarExpanded(expanded) {
    if (!reportSidebar || !sidebarToggle) { return; }
    reportSidebar.classList.toggle('is-open', expanded);
    sidebarToggle.setAttribute('aria-expanded', expanded ? 'true' : 'false');
  }

  if (sidebarToggle) {
    sidebarToggle.addEventListener('click', function () {
      setSidebarExpanded(sidebarToggle.getAttribute('aria-expanded') !== 'true');
    });
  }

  var sidebarLinks = Array.prototype.slice.call(document.querySelectorAll('.report-sidebar a[href^="#"]'));
  function setActiveSidebarSection(sectionId) {
    sidebarLinks.forEach(function (link) {
      var active = link.getAttribute('href') === '#' + sectionId;
      link.classList.toggle('is-active', active);
      if (active) { link.setAttribute('aria-current', 'location'); }
      else { link.removeAttribute('aria-current'); }
    });
  }

  sidebarLinks.forEach(function (link) {
    link.addEventListener('click', function () {
      setActiveSidebarSection((link.getAttribute('href') || '').slice(1));
      if (window.matchMedia('(max-width: 640px)').matches) { setSidebarExpanded(false); }
    });
  });

  var observedSections = document.querySelectorAll('header#cover, main section[id]');
  if ('IntersectionObserver' in window) {
    var sectionObserver = new IntersectionObserver(function (entries) {
      var visible = entries
        .filter(function (entry) { return entry.isIntersecting; })
        .sort(function (left, right) { return Math.abs(left.boundingClientRect.top) - Math.abs(right.boundingClientRect.top); });
      if (visible.length > 0) { setActiveSidebarSection(visible[0].target.id); }
    }, { rootMargin: '-8% 0px -76% 0px', threshold: [0, 0.01] });
    observedSections.forEach(function (section) { sectionObserver.observe(section); });
  }

  window.addEventListener('hashchange', function () {
    if (window.location.hash.length > 1) { setActiveSidebarSection(window.location.hash.slice(1)); }
  });
  setActiveSidebarSection(window.location.hash.length > 1 ? window.location.hash.slice(1) : 'cover');
})();
</script>
""");
    }
}
