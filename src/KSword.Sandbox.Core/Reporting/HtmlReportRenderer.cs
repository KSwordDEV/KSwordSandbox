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

    private sealed record BehaviorGraphEdge(string From, string Relation, string To, string Evidence);

    private sealed record ProcessGraphNode(string Label, string Detail, string CopyText);

    private sealed record ProcessTreeActivity(int EventCount, int FileCount, int RegistryCount, int NetworkCount);

    private sealed record EvidenceSummaryCard(string Title, string Value, string Detail, string Css, string CopyText);

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
        "<(?:code|pre)\\b[^>]*>.*?</(?:code|pre)>|\\sdata-copy=\"[^\"]*\"",
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
            ? LocalizeChineseHtml(html)
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
        AppendTableOfContents(html);
        AppendQuickNavigation(html, report, artifactLinks);
        html.AppendLine("<main>");
        AppendRiskSummary(html, report);
        AppendBehaviorDetections(html, report);
        AppendMitreDetections(html, report);
        AppendRuleHits(html, report);
        AppendStaticAnalysis(html, report);
        AppendDynamicAnalysis(html, report);
        AppendVirusTotalSummary(html, report, artifactLookup, artifactLinks);
        AppendBehaviorGraph(html, report, artifactLookup, artifactLinks);
        AppendArtifactLinks(html, report, artifactLinks);
        AppendTimeline(html, report, artifactLookup, artifactLinks);
        AppendProcessDetails(html, report, artifactLookup, artifactLinks);
        AppendDroppedFiles(html, report, artifactLookup, artifactLinks);
        AppendRegistryBehavior(html, report, artifactLookup, artifactLinks);
        AppendNetworkBehavior(html, report, artifactLookup, artifactLinks);
        AppendR0Events(html, report, artifactLookup, artifactLinks);
        AppendFailureReasons(html, report, artifactLookup, artifactLinks);
        AppendRawEvents(html, report, artifactLookup, artifactLinks);
        html.AppendLine("</main>");
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
main,nav{max-width:1280px;margin:24px auto;padding:0 24px}main{counter-reset:report-section}.card{background:#fff;border:1px solid var(--line);border-radius:2px;box-shadow:none;margin:18px 0;padding:22px;position:relative}
section.card{counter-increment:report-section;max-height:75vh;max-height:var(--section-max);overflow:auto;scrollbar-color:var(--primary) #eaf4ff;scrollbar-width:thin}.card:before{background:var(--primary);border-radius:0;content:'';height:100%;left:0;opacity:.9;position:absolute;top:0;width:3px}
.language-entry{align-items:center;display:flex;flex-wrap:wrap;gap:10px}.language-entry strong{color:#075985}.language-entry .hint{color:var(--muted);font-size:13px}.language-entry a{background:var(--primary);border-radius:2px;color:white;font-weight:800;padding:8px 12px;text-decoration:none}.language-entry a.secondary{background:#334155}.language-entry a:hover{outline:2px solid rgba(67,160,255,.18)}
.quick-nav{border-color:#b9ddff;position:sticky;top:8px;z-index:20}.quick-nav:before{background:var(--primary)}.quick-nav h2{font-size:16px;margin-bottom:8px}.quick-nav .hint{color:var(--muted);font-size:12px;margin:0 0 10px}.quick-links{display:flex;flex-wrap:wrap;gap:8px}.quick-link{align-items:center;background:#fff;border:1px solid #cfe6fb;border-radius:2px;color:#075985;display:inline-flex;gap:8px;min-height:40px;padding:7px 10px;text-decoration:none}.quick-link strong{font-size:13px}.quick-link small{background:#dff0ff;border-radius:2px;color:#075985;font-weight:900;min-width:24px;padding:3px 7px;text-align:center}.quick-link:hover{border-color:var(--primary);outline:2px solid rgba(67,160,255,.16)}
.card h2{align-items:center;display:flex;gap:10px;margin:0 0 14px}.card h2:before{background:var(--primary);border-radius:0;content:'';display:inline-block;height:12px;width:12px}section.card>h2{backdrop-filter:none;background:#fff;border-bottom:1px solid #dbeafe;margin:-22px -22px 16px;padding:16px 22px;position:sticky;top:-22px;z-index:3}section.card>h2:after{background:var(--primary);border-radius:2px;color:white;content:'Step ' counter(report-section);font-size:11px;font-weight:900;margin-left:auto;padding:5px 9px;text-transform:uppercase}
.grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(170px,1fr))}.metric{background:#fff;border:1px solid var(--line);border-left:3px solid var(--primary);border-radius:2px;padding:14px}.metric b{display:block;font-size:26px;margin-top:4px}
.muted{color:var(--muted)}.risk-high{color:#b91c1c}.risk-medium{color:#b45309}.risk-low{color:#047857}.risk-info{color:var(--primary-deep)}
.badge,.chip,.evidence-count{border:1px solid transparent;border-radius:2px;display:inline-block;font-weight:700;padding:5px 9px}.chip{font-size:12px;margin:2px 4px 2px 0;padding:3px 7px}.evidence-count{background:#f8fbff;border-color:#cfe6fb;color:#075985;font-size:12px;margin:2px 6px 2px 0}
.badge-high,.chip-high{background:#fee2e2;color:#991b1b}.badge-medium,.chip-medium{background:#fef3c7;color:#92400e}.badge-low,.chip-low{background:#dcfce7;color:#166534}.badge-info,.chip-info{background:var(--primary-soft);color:#075985}
.section-note{background:#f7fbff;border:1px solid #dbeafe;border-left:4px solid var(--primary);border-radius:2px;color:#475569;margin:10px 0;padding:10px 12px}
table{border-collapse:collapse;border-spacing:0;width:100%;margin-top:14px}td,th{border-bottom:1px solid #e5edf6;padding:10px;text-align:left;vertical-align:top}th{background:#f8fbff;color:#475569;font-size:12px;position:sticky;text-transform:uppercase;top:0;z-index:1}
code{background:#f1f7ff;border-radius:2px;padding:2px 5px;word-break:break-all}.toc a{background:#fff;border:1px solid var(--line);border-radius:2px;color:#075985;display:inline-block;font-weight:700;margin:4px 8px 4px 0;padding:7px 12px;text-decoration:none}.toc a:hover{border-color:var(--primary);outline:2px solid rgba(67,160,255,.16)}
.empty{background:#fff;border:1px dashed #b9d7f3;border-radius:2px;color:var(--muted);padding:14px}
.copy-btn{background:#fff;border:1px solid rgba(67,160,255,.55);border-radius:2px;color:#075985;cursor:pointer;font-size:12px;font-weight:700;margin:2px 6px 2px 0;padding:4px 8px}.copyable{cursor:copy}.copy-hint{color:var(--muted);font-size:12px;margin-top:8px}
.toolbar,.inline-actions{align-items:center;display:inline-flex;flex-wrap:wrap;gap:6px;justify-content:flex-start;margin:0 0 4px}.event-table-wrap{border:1px solid var(--line);border-radius:2px;margin-top:14px;max-height:var(--subsection-max);overflow:auto}.event-table-wrap table{margin-top:0}.event-table-wrap th{top:0}.bounded-list{max-height:var(--subsection-max);overflow:auto}
.event-table td:first-child{white-space:nowrap}.event-table td:nth-child(2){min-width:140px}.event-table td:nth-child(4){min-width:140px}.event-table td:nth-child(5){min-width:260px}.event-table .evidence{min-width:280px}
.timeline-groups{display:grid;gap:10px;margin-top:14px}.timeline-group{background:#fff;border:1px solid var(--line);border-radius:2px;overflow:hidden}.timeline-group>summary{align-items:flex-start;cursor:pointer;display:flex;gap:10px;justify-content:space-between;list-style:none;padding:12px 14px}.timeline-group>summary::-webkit-details-marker{display:none}.timeline-group>summary:before{color:var(--primary-deep);content:'▶';font-weight:900;margin-top:2px}.timeline-group[open]>summary:before{content:'▼'}.timeline-group small{color:var(--muted);display:block;line-height:1.4;margin-top:3px}.timeline{border-left:3px solid rgba(67,160,255,.45);margin:0 14px 14px 20px;padding:12px 0 0 18px}.timeline-item{background:#fff;border:1px solid var(--line);border-radius:2px;margin:0 0 10px;padding:10px 12px;position:relative}.timeline-item:before{background:var(--primary);border:2px solid var(--primary-soft);border-radius:2px;content:'';height:10px;left:-25px;position:absolute;top:13px;width:10px}.timeline-overflow{background:#f1f7ff;border:1px dashed #b9d7f3;border-radius:2px;color:var(--muted);margin:0 0 12px;padding:9px 11px}
.graph-map{display:grid;gap:10px;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));margin-top:12px}.graph-node{background:#fff;border:1px solid var(--line);border-left:4px solid var(--primary);border-radius:2px;padding:12px}.graph-node strong{display:block;margin-bottom:4px}.graph-node small{color:var(--muted);display:block;line-height:1.4}.behavior-chain{background:#fff;border:1px solid var(--line);border-radius:2px;counter-reset:chain;margin:12px 0;max-height:var(--subsection-max);overflow:auto;padding:8px 10px}.behavior-chain li{align-items:flex-start;background:#fff;border-bottom:1px solid #dbeafe;border-radius:0;counter-increment:chain;display:grid;gap:8px;grid-template-columns:auto 1fr;margin:0;padding:10px}.behavior-chain li:last-child{border-bottom:0}.behavior-chain li:before{align-items:center;background:var(--primary);border-radius:2px;color:white;content:counter(chain);display:inline-flex;font-weight:900;height:24px;justify-content:center;width:24px}.behavior-chain details{grid-column:2}.behavior-chain pre{max-height:var(--detail-max);overflow:auto;white-space:pre-wrap;word-break:break-word}.edge-table td:nth-child(1),.edge-table td:nth-child(3){min-width:170px}.ioc-grid{display:grid;gap:10px;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));margin-top:14px}.ioc-card{background:#fff;border:1px solid var(--line);border-radius:2px;padding:12px}.ioc-card h3{font-size:15px;margin:0 0 8px}.ioc-card ul{margin:0;padding-left:18px}.ioc-card li{margin:5px 0;word-break:break-word}
.evidence-summary-grid,.relation-grid,.overview-strip,.evidence-story-board{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));margin-top:14px}.evidence-summary-card,.relation-card,.overview-item,.evidence-story-lane{background:#fff;border:1px solid var(--line);border-left:4px solid var(--primary);border-radius:2px;box-shadow:none;max-height:var(--subsection-max);overflow:auto;padding:14px;position:relative}.evidence-summary-card:before,.relation-card:before,.overview-item:before,.evidence-story-lane:before{display:none}.evidence-summary-card h3,.relation-card h3,.overview-item h3,.evidence-story-lane h3{font-size:15px;margin:0 0 8px;padding-left:0}.summary-value,.overview-value{color:#075985;display:block;font-size:26px;font-weight:900;letter-spacing:-.04em}.overview-value.risk-medium{color:#b45309}.overview-value.risk-high{color:#b91c1c}.overview-value.risk-low{color:#047857}.overview-value.risk-info{color:var(--primary-deep)}.overview-item p,.story-lead{color:var(--muted);font-size:13px;line-height:1.45;margin:6px 0 0}.compact-evidence-summary{background:#f8fbff;border:1px solid #cfe6fb;border-left:3px solid var(--primary);color:#334155;font-size:13px;line-height:1.45;margin:8px 0;padding:8px 10px;word-break:break-word}.compact-evidence-summary strong{color:#075985}.story-metrics{display:flex;flex-wrap:wrap;gap:6px;margin:10px 0}.story-metrics span{background:#f8fbff;border:1px solid #cfe6fb;border-radius:2px;color:#075985;font-size:12px;font-weight:800;padding:6px 8px}.story-evidence-list{font-family:Consolas,monospace;font-size:12px;line-height:1.45;margin:8px 0 0;padding-left:18px}.story-evidence-list li{margin:3px 0;word-break:break-word}.relationship-meta{display:grid;gap:6px;grid-template-columns:repeat(2,minmax(0,1fr));margin:10px 0}.relationship-meta span{background:#f8fbff;border:1px solid #cfe6fb;border-radius:2px;color:#075985;font-size:12px;font-weight:700;padding:7px}.relationship-tags{display:flex;flex-wrap:wrap;gap:6px;margin:8px 0}.relationship-tags .chip{margin:0}.evidence-expansion-card{background:#f8fbff;border:1px solid #cfe6fb;border-left:3px solid var(--primary);margin-top:10px;padding:8px 10px}.evidence-expansion-card[open]{background:#fff}.relationship-details,.flat-details,.event-evidence-fields,.technical-field,.raw-technical-fields,.raw-technical-field{background:transparent;border:0;border-left:2px solid #cfe6fb;border-radius:0;margin-top:8px;padding:4px 0 4px 8px}.relationship-details summary,.flat-details summary,.event-evidence-fields summary,.technical-field summary,.raw-technical-fields summary,.raw-technical-field summary,.evidence-expansion-card summary{cursor:pointer;font-weight:800}.relationship-details pre,.flat-details pre,.event-evidence-fields pre,.technical-field pre,.raw-technical-field pre,.evidence-expansion-card pre{max-height:var(--detail-max);overflow:auto;white-space:pre-wrap;word-break:break-word}.relationship-title{display:flex;align-items:flex-start;gap:8px;justify-content:space-between}.relationship-title code{max-width:100%;overflow-wrap:anywhere}.anchor-offset{scroll-margin-top:18px}.mono-list{font-family:Consolas,monospace;font-size:12px;line-height:1.45;margin:6px 0 0 0;padding-left:18px}.mono-list li{margin:3px 0;word-break:break-word}
.tree{font-family:Consolas,monospace;line-height:1.5;margin:12px 0}.tree ul{border-left:1px dashed #b9d7f3;list-style:none;margin:0 0 0 18px;padding-left:14px}.tree li{margin:5px 0}.process-tree{background:#fff;border:1px solid var(--line);border-radius:2px;max-height:var(--subsection-max);overflow:auto;padding:12px}.process-tree details.process-tree-node{margin:4px 0}.process-tree summary,.process-tree-leaf{align-items:center;cursor:pointer;display:flex;flex-wrap:wrap;gap:8px;list-style:none}.process-tree summary::-webkit-details-marker{display:none}.process-tree summary:before{color:var(--primary-deep);content:'▶';font-weight:900}.process-tree details[open]>summary:before{content:'▼'}.tree-badges{display:flex;flex-wrap:wrap;gap:5px}.tree-badge{background:#eef7ff;border:1px solid #cfe6fb;border-radius:2px;color:#075985;font-family:Segoe UI,Arial,sans-serif;font-size:11px;font-weight:800;padding:2px 7px}
.evidence{max-width:560px}.evidence summary{cursor:pointer;font-weight:700}.evidence pre{white-space:pre-wrap;word-break:break-word}
.columns{display:grid;gap:14px;grid-template-columns:1fr 1fr}.compact-list{margin:8px 0 0 0;padding-left:18px}.compact-list li{margin:4px 0}
.artifact-ref{font-weight:700}.artifact-location{display:grid;gap:6px}.artifact-actions{align-items:center;display:inline-flex;flex-wrap:wrap;gap:6px;margin-top:4px}.artifact-actions-inline{display:inline-flex;margin-left:6px;margin-top:0;vertical-align:middle}.artifact-btn{background:#fff;border:1px solid rgba(67,160,255,.72);border-radius:2px;box-shadow:none;color:#075985;display:inline-block;font-size:12px;font-weight:900;padding:4px 8px;text-decoration:none}.artifact-btn.download{background:#eef7ff;color:#075985}.artifact-btn:hover{outline:2px solid rgba(67,160,255,.14)}.artifact-no-link{background:#fff;border:1px dashed #cbd5e1;border-radius:2px;color:var(--muted);display:inline-block;font-size:12px;font-weight:800;padding:4px 8px}.artifact-copy-path{background:#fff;border:1px solid var(--line);border-radius:2px;padding:8px}.artifact-list{list-style:none;margin:8px 0 0 0;padding:0}.artifact-list li{border-top:1px solid #e2e8f0;margin-top:8px;padding-top:8px}.artifact-preview{max-height:var(--subsection-max);overflow:auto}.artifact-preview img{border:1px solid #cbd5e1;border-radius:2px;max-height:var(--artifact-preview-img-max);max-width:100%;object-fit:contain}
.raw-field-list{margin:6px 0 0 0;padding-left:18px}.raw-field-list li{margin:4px 0;word-break:break-word}.raw-events-shell{background:#fff;border:1px solid var(--line);border-radius:2px;margin-top:14px;overflow:hidden}.raw-events-shell>summary{cursor:pointer;font-weight:800;list-style:none;padding:12px 14px}.raw-events-shell>summary::-webkit-details-marker{display:none}.raw-events-shell>summary:before{color:var(--primary-deep);content:'▶';display:inline-block;margin-right:8px}.raw-events-shell[open]>summary:before{content:'▼'}.raw-events-panel{border-top:1px solid var(--line);max-height:58vh;overflow:auto;padding:12px}.raw-events-panel .event-table-wrap{max-height:32vh}.raw-event-pages{display:grid;gap:10px}.raw-event-page{background:#fff;border:1px solid #dbeafe;border-radius:2px;overflow:hidden}.raw-event-page>summary{background:#eef7ff;color:#075985;cursor:pointer;font-weight:900;list-style:none;padding:10px 12px}.raw-event-page>summary::-webkit-details-marker{display:none}.raw-event-page>summary:before{content:'▶';display:inline-block;margin-right:8px}.raw-event-page[open]>summary:before{content:'▼'}.raw-event-page table{margin:0}.raw-source-hints{background:#fff;border:1px solid var(--line);border-radius:2px;margin-top:12px;padding:12px}.raw-source-hints ul{list-style:none;margin:8px 0 0 0;padding:0}.raw-source-hints li{border-top:1px solid #e2e8f0;margin-top:8px;padding-top:8px}.raw-source-hints li:first-child{border-top:0;margin-top:0;padding-top:0}.raw-source-hints .hint-label{font-weight:800}

/* Square, flat operator theme: no pill/card nesting beyond one visual layer. */
.modern-sandbox-report header:after{display:none}.modern-sandbox-report .card,.modern-sandbox-report section.card,.modern-sandbox-report .metric,.modern-sandbox-report .quick-link,.modern-sandbox-report .language-entry a,.modern-sandbox-report .badge,.modern-sandbox-report .chip,.modern-sandbox-report .section-note,.modern-sandbox-report code,.modern-sandbox-report .toc a,.modern-sandbox-report .empty,.modern-sandbox-report .copy-btn,.modern-sandbox-report .event-table-wrap,.modern-sandbox-report .timeline-group,.modern-sandbox-report .timeline-item,.modern-sandbox-report .timeline-overflow,.modern-sandbox-report .graph-node,.modern-sandbox-report .behavior-chain,.modern-sandbox-report .behavior-chain li,.modern-sandbox-report .behavior-chain details,.modern-sandbox-report .ioc-card,.modern-sandbox-report .evidence-summary-card,.modern-sandbox-report .evidence-story-lane,.modern-sandbox-report .relation-card,.modern-sandbox-report .overview-item,.modern-sandbox-report .relationship-meta span,.modern-sandbox-report .relationship-details,.modern-sandbox-report .evidence-expansion-card,.modern-sandbox-report .process-tree,.modern-sandbox-report .tree-badge,.modern-sandbox-report .evidence details,.modern-sandbox-report .artifact-btn,.modern-sandbox-report .artifact-no-link,.modern-sandbox-report .artifact-copy-path,.modern-sandbox-report .artifact-preview img,.modern-sandbox-report .technical-field,.modern-sandbox-report .raw-technical-fields,.modern-sandbox-report .raw-technical-field,.modern-sandbox-report .raw-events-shell,.modern-sandbox-report .raw-event-page,.modern-sandbox-report .raw-source-hints{border-radius:0!important}.modern-sandbox-report .card:before,.modern-sandbox-report .evidence-summary-card:before,.modern-sandbox-report .evidence-story-lane:before,.modern-sandbox-report .relation-card:before,.modern-sandbox-report .overview-item:before{border-radius:0!important}.modern-sandbox-report .badge,.modern-sandbox-report .chip,.modern-sandbox-report .copy-btn,.modern-sandbox-report .artifact-btn,.modern-sandbox-report .artifact-no-link{box-shadow:none!important}.modern-sandbox-report .event-evidence-fields,.modern-sandbox-report .flat-technical-fields,.modern-sandbox-report .related-artifacts-flat{background:transparent;border:0;border-radius:0;padding:0}.modern-sandbox-report .flat-technical-fields{border-top:1px solid var(--line);margin-top:8px;padding-top:8px}.modern-sandbox-report .related-artifacts-flat ul{border-top:1px solid var(--line);list-style:none;margin:6px 0 0 0;padding:0}.modern-sandbox-report .related-artifacts-flat li{border-top:1px solid #e2e8f0;margin-top:6px;padding-top:6px}.modern-sandbox-report .related-artifacts-flat li:first-child{border-top:0}.modern-sandbox-report .self-noise-note{background:#f8fafc;border-left:4px solid #94a3b8;color:#475569;margin:10px 0;padding:10px 12px}
@media(max-width:900px){.grid,.columns{grid-template-columns:1fr 1fr}table{display:block;overflow-x:auto}}@media(max-width:640px){header{padding:28px 24px}.grid,.columns{grid-template-columns:1fr}main,nav{padding:0 14px}}

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
    /// Appends fixed report navigation.
    /// Inputs are a StringBuilder, processing writes anchor links matching the
    /// target report structure, and the method returns no value.
    /// </summary>
    private static void AppendTableOfContents(StringBuilder html)
    {
        html.AppendLine("<nav id=\"toc\" class=\"card toc\"><h2>Table of contents</h2>");
        foreach (var (href, title) in new[]
        {
            ("cover", "Cover"),
            ("risk", "Risk summary"),
            ("behavior", "Behavior detections"),
            ("mitre", "Multi-dimensional / MITRE"),
            ("rules", "Engine and rule hits"),
            ("static", "Static analysis"),
            ("dynamic", "Dynamic analysis"),
            ("vt", "VirusTotal / reputation"),
            ("graph", "Behavior graph / IOC summary"),
            ("artifacts", "Artifact links"),
            ("timeline", "Timeline"),
            ("process", "Process details"),
            ("files", "File system activity"),
            ("registry", "Registry behavior"),
            ("network", "Network behavior"),
            ("r0", "R0 / driver events"),
            ("failure", "Failure reasons"),
            ("events", "Raw normalized events")
        })
        {
            html.AppendLine($"<a href=\"#{href}\">{E(title)}</a>");
        }

        html.AppendLine("</nav>");
    }

    /// <summary>
    /// Appends a sticky subnav for high-traffic operator sections.
    /// Inputs are report counts and indexed artifacts; processing writes quick
    /// Process / Files / Network / R0 / VT / Artifacts quick navigation links;
    /// the method returns no value.
    /// </summary>
    private static void AppendQuickNavigation(StringBuilder html, AnalysisReport report, IReadOnlyCollection<ArtifactDescriptor> artifacts)
    {
        html.AppendLine("<nav id=\"quick-nav\" class=\"card quick-nav\" aria-label=\"Sticky subnav\">");
        html.AppendLine("<h2>Quick navigation</h2>");
        html.AppendLine("<p class=\"hint\">Sticky subnav for Process / Files / Network / R0 / VT / Artifacts quick navigation; counts show currently embedded representative evidence. R0 health, collector self-noise, and VT status rows are counted in their own lanes rather than primary behavior.</p>");
        html.AppendLine("<div class=\"quick-links\">");
        QuickLink(html, "risk", "Risk summary", PrimaryBehaviorFindings(report).Count().ToString());
        QuickLink(html, "process", "Process details", report.Events.Count(IsSampleBehaviorProcessEvent).ToString());
        QuickLink(html, "files", "File system activity", report.Events.Count(IsSampleBehaviorFileEvent).ToString());
        QuickLink(html, "network", "Network behavior", report.Events.Count(IsSampleBehaviorNetworkEvent).ToString());
        QuickLink(html, "r0", "R0 health", report.Events.Count(IsR0Event).ToString());
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
        Metric(html, "High risk", CountSeverity(primaryFindings, "high").ToString(), "risk-high");
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
        Metric(html, "R0 / driver events", report.Events.Count(IsR0Event).ToString(), "risk-info");
        html.AppendLine("</div></section>");
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
        Metric(html, "Network events", report.Events.Count(IsSampleBehaviorNetworkEvent).ToString(), "risk-medium");
        Metric(html, "R0 / driver events", report.Events.Count(IsR0Event).ToString(), "risk-info");
        Metric(html, "Collection health", report.Events.Count(IsCollectionHealthEvent).ToString(), "risk-info");
        Metric(html, "VT lookups", report.Events.Count(IsVirusTotalEvent).ToString(), "risk-info");
        Metric(html, "Failure markers", report.Events.Count(IsOperationalFailureEvent).ToString(), "risk-high");
        html.AppendLine("</div></section>");
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
        Metric(html, "VT rule hits", vtFindings.Count.ToString(), vtFindings.Any(finding => NormalizeSeverity(finding.Severity) == "high") ? "risk-high" : "risk-info");
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

        html.AppendLine("<div class=\"section-note\"><strong>Weak-interaction graph.</strong> This section summarizes process, file, registry, network, and artifact relationships from normalized telemetry so the report remains stable without client-side graph libraries.</div>");
        html.AppendLine("<div class=\"grid\">");
        Metric(html, "Graph processes", processNodes.Count.ToString(), "risk-info");
        Metric(html, "Graph edges", edges.Count.ToString(), "risk-info");
        Metric(html, "Network IOCs", networkIocs.Count.ToString(), "risk-medium");
        Metric(html, "File IOCs", fileIocs.Count.ToString(), "risk-medium");
        Metric(html, "Registry IOCs", registryIocs.Count.ToString(), "risk-medium");
        Metric(html, "Artifact IOCs", artifactIocs.Count.ToString(), "risk-info");
        html.AppendLine("</div>");

        AppendEvidenceSummaryCards(html, report, processNodes, edges, fileIocs, registryIocs, networkIocs, artifactIocs);
        AppendEvidenceStoryBoard(html, report, artifacts);
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
            html.AppendLine($"<details class=\"evidence-expansion-card\"><summary>Expand bounded story evidence ({E(shownEvidenceCount.ToString(CultureInfo.InvariantCulture))}/{E(observedEvidenceCount.ToString(CultureInfo.InvariantCulture))} observed rows)</summary><ol class=\"story-evidence-list\">");
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
        var processEvents = sampleEvents.Where(IsProcessTreeCandidate).ToList();
        var processNodes = BuildProcessGraphNodes(report).Take(8).ToList();
        var processChildHints = processEvents.Count(HasParentProcessEvidence);
        var processEvidence = processEvents.Take(8).Select(EventOneLine).ToList();
        if (processEvidence.Count == 0)
        {
            processEvidence.AddRange(processNodes.Take(8).Select(node => node.CopyText));
        }

        var droppedArtifacts = StoryArtifactsByKind(artifacts, ArtifactKind.DroppedFile);
        var droppedEvents = sampleEvents.Where(IsDroppedFileEvidenceEvent).ToList();
        var fileEvents = sampleEvents.Where(IsFileEvent).ToList();
        var droppedEvidence = BuildStoryEvidenceLines(droppedArtifacts, droppedEvents.Count > 0 ? droppedEvents : fileEvents);

        var screenshotArtifacts = StoryArtifactsByKind(artifacts, ArtifactKind.Screenshot);
        var screenshotEvents = report.Events.Where(IsScreenshotEvidenceEvent).OrderBy(evt => evt.Timestamp).ToList();
        var screenshotEvidence = BuildStoryEvidenceLines(screenshotArtifacts, screenshotEvents);

        var memoryArtifacts = StoryArtifactsByKind(artifacts, ArtifactKind.MemoryDump);
        var memoryEvents = report.Events.Where(IsMemoryDumpEvidenceEvent).OrderBy(evt => evt.Timestamp).ToList();
        var childDumpEvents = memoryEvents.Count(evt => TextEqualsAny(FirstEventDataValue(evt, "childProcessDumpEnabled", "includeChildProcesses", "childDumpEnabled") ?? string.Empty, "true", "enabled", "yes"));
        var memoryEvidence = BuildStoryEvidenceLines(memoryArtifacts, memoryEvents);

        var packetArtifacts = StoryArtifactsByKind(artifacts, ArtifactKind.PacketCapture);
        var packetEvents = report.Events.Where(IsPacketCaptureEvidenceEvent).OrderBy(evt => evt.Timestamp).ToList();
        var networkEvents = sampleEvents.Where(IsNetworkEvent).ToList();
        var networkEvidence = BuildStoryEvidenceLines(packetArtifacts, packetEvents.Concat(networkEvents).OrderBy(evt => evt.Timestamp).ToList());
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
            .Concat(r0SelfNoiseEvents.Take(4))
            .Select(EventOneLine))
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
                    $"Unique file targets: {fileEvents.Select(ExtractReadableEventTarget).Where(value => !string.IsNullOrWhiteSpace(value)).Distinct(StringComparer.OrdinalIgnoreCase).Count()}"
                ],
                droppedEvidence),
            CreateEvidenceStoryCard(
                "Screenshot evidence",
                $"{screenshotArtifacts.Count} captures",
                screenshotArtifacts.Count + screenshotEvents.Count > 0 ? "info" : "low",
                "Screenshot capture is kept visible as visual evidence; previews remain collapsible and safe links are handled in Artifact links.",
                [
                    $"Screenshot artifacts: {screenshotArtifacts.Count}",
                    $"Screenshot events: {screenshotEvents.Count}",
                    $"Captured bytes: {screenshotArtifacts.Sum(artifact => Math.Max(0, artifact.SizeBytes))}",
                    $"Latest capture: {LatestEventTime(screenshotEvents)}"
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
                    $"Captured bytes: {memoryArtifacts.Sum(artifact => Math.Max(0, artifact.SizeBytes))}"
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
                    $"DNS/HTTP/TLS/flow: {dnsCount}/{httpCount}/{tlsCount}/{flowCount}"
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

    private static bool IsDroppedFileEvidenceEvent(SandboxEvent evt)
    {
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
        return evt.EventType.StartsWith("screenshot.", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(FirstEventDataValue(evt, "collectionName"), "screenshots", StringComparison.OrdinalIgnoreCase) ||
            EventTextContainsAny(evt, "screenshotRelativePath", "screenshotPath", "screenshots");
    }

    private static bool IsMemoryDumpEvidenceEvent(SandboxEvent evt)
    {
        return evt.EventType.StartsWith("memory_dump.", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("memory-dump.", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(FirstEventDataValue(evt, "collectionName"), "memory-dumps", StringComparison.OrdinalIgnoreCase) ||
            EventTextContainsAny(evt, "memoryDumpRelativePath", "memoryDumpPath", "memory-dumps", ".dmp");
    }

    private static bool IsPacketCaptureEvidenceEvent(SandboxEvent evt)
    {
        return evt.EventType.StartsWith("packet_capture.", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("packet-capture.", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("pcap.", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(FirstEventDataValue(evt, "collectionName"), "packet-captures", StringComparison.OrdinalIgnoreCase) ||
            EventTextContainsAny(evt, "packetCaptureRelativePath", "pcapRelativePath", "pcapngRelativePath", "pktmon", ".pcap", ".pcapng", ".etl");
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
        var cards = BuildArtifactCollectionStatusCards(report, artifacts);
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
                $"Artifact compact summary: collection={card.Name}; status={card.Status}; artifacts={card.ArtifactCount}; events={card.EventCount}; detail={card.Detail}",
                "Copy compact summary");
            html.AppendLine($"<details class=\"evidence-expansion-card\"><summary>Expand collection evidence</summary><pre class=\"copyable\" data-copy=\"{A(card.CopyText)}\">{E(card.CopyText)}</pre></details>");
            html.AppendLine("</article>");
        }

        html.AppendLine("</div>");
    }

    private static IReadOnlyList<ArtifactCollectionStatusCard> BuildArtifactCollectionStatusCards(
        AnalysisReport report,
        IReadOnlyCollection<ArtifactDescriptor> artifacts)
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
                "Copied files released or modified by the sample when collection was enabled."),
            BuildArtifactCollectionStatusCard(
                "Screenshots",
                "screenshots",
                ArtifactKind.Screenshot,
                artifacts,
                report.Events,
                evt => evt.EventType.StartsWith("screenshot.", StringComparison.OrdinalIgnoreCase),
                "Desktop screenshots captured around sample execution when enabled."),
            BuildArtifactCollectionStatusCard(
                "Memory dumps",
                "memory-dumps",
                ArtifactKind.MemoryDump,
                artifacts,
                report.Events,
                evt => evt.EventType.StartsWith("memory_dump.", StringComparison.OrdinalIgnoreCase),
                "Opt-in process and child-process memory dump artifacts."),
            BuildArtifactCollectionStatusCard(
                "Packet captures",
                "packet-captures",
                ArtifactKind.PacketCapture,
                artifacts,
                report.Events,
                evt => evt.EventType.StartsWith("packet_capture.", StringComparison.OrdinalIgnoreCase) || evt.EventType.StartsWith("pcap.", StringComparison.OrdinalIgnoreCase),
                "Opt-in pktmon/PCAP artifacts and imported DNS/HTTP/TLS/flow rows."),
            BuildArtifactCollectionStatusCard(
                "Driver events",
                "driver-events",
                ArtifactKind.DriverEventsJsonLines,
                artifacts,
                report.Events,
                IsR0Event,
                "R0Collector JSONL and driver-originated telemetry.")
        ];
    }

    private static ArtifactCollectionStatusCard BuildArtifactCollectionStatusCard(
        string name,
        string collectionName,
        ArtifactKind kind,
        IReadOnlyCollection<ArtifactDescriptor> artifacts,
        IReadOnlyCollection<SandboxEvent> events,
        Func<SandboxEvent, bool> eventPredicate,
        string defaultDetail)
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
                .. collectionArtifacts.Take(8).Select(ArtifactToPlainText),
                .. collectionEvents.Take(8).Select(EventOneLine)
            ]);
        return new ArtifactCollectionStatusCard(name, status, css, collectionArtifacts.Count, collectionEvents.Count, detail, copy);
    }

    private static string InferArtifactCollectionStatus(
        IReadOnlyCollection<ArtifactDescriptor> artifacts,
        IReadOnlyCollection<SandboxEvent> events)
    {
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
            Empty(html, "No failure reason was recorded.");
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
        html.AppendLine($"<div class=\"section-note\"><strong>Slim raw event sample.</strong> Raw events are collapsed by default. Raw events shown inline: {inlineEvents.Count}/{orderedEvents.Count}. Inline page size: {RawEventPageSize}. Raw evidence height limit: 58vh. Hidden raw events: {hiddenCount}. Inline raw pages use native details; command, stdout, stderr, PowerShell, script blocks, and oversized payloads stay folded in every row. Open report.json or raw source artifacts for complete evidence.</div>");
        AppendRawEventReadingGuide(html, orderedEvents, inlineEvents.Count, hiddenCount);
        AppendRawSourceHints(html, report, artifacts);
        AppendRawEventDistribution(html, orderedEvents);
        AppendRawEventPageIndex(html, orderedEvents);

        if (orderedEvents.Count == 0)
        {
            Empty(html, "No events were collected for this section.");
        }
        else
        {
            html.AppendLine($"<details class=\"raw-events-shell\"><summary>Show inline raw events ({inlineEvents.Count}/{orderedEvents.Count}; {hiddenCount} hidden)</summary>");
            html.AppendLine("<div class=\"raw-events-panel\">");
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
            var open = pageNumber == 1 ? " open" : string.Empty;
            var copy = string.Join(Environment.NewLine, pageEvents.Select(EventOneLine));
            var pageFamilies = string.Join(
                ", ",
                pageEvents.Select(EventFamilyLabel).Distinct(StringComparer.OrdinalIgnoreCase).Take(3));
            var pageTypes = string.Join(
                ", ",
                pageEvents
                    .Select(evt => string.IsNullOrWhiteSpace(evt.EventType) ? "(empty)" : evt.EventType)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Take(3));
            html.AppendLine($"<details class=\"raw-event-page copyable\" data-copy=\"{A(copy)}\"{open}><summary>Raw event page {pageNumber}: rows {first}-{last} of {totalEventCount}; families {E(FirstNonEmpty(pageFamilies, "-"))}; top types {E(FirstNonEmpty(pageTypes, "-"))}</summary>");
            html.AppendLine($"<div class=\"toolbar\">{CopyButton("Copy raw page", copy)}</div>");
            html.AppendLine("<div class=\"copy-hint\">Page evidence sample. This page is a bounded native-details chunk; long command/output/script fields remain folded. Use the copy button or right-click to copy this inline page; open report.json/events.json for complete row payloads.</div>");
            AppendEventRows(html, pageEvents, artifactLookup, artifacts);
            html.AppendLine("</details>");
            pageNumber++;
        }

        html.AppendLine("</div>");
    }

    private static int RawEventPageCount(int inlineEventCount)
    {
        return inlineEventCount == 0
            ? 0
            : (int)Math.Ceiling(inlineEventCount / (double)RawEventPageSize);
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
    /// Appends compact source-path hints for complete raw evidence.
    /// Inputs are the report and indexed artifacts; processing lists the
    /// co-located report JSON plus raw guest/driver source artifacts, and the
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
        html.AppendLine("<p class=\"muted\"><strong>Raw source guide.</strong> report.json is the complete normalized report; guest events, driver JSONL, and manifests are original source artifacts when indexed. Safe report-relative paths get Open/Download buttons; host or guest absolute paths remain copy-only.</p><ul>");
        var reportJsonCopy = string.Join(
            Environment.NewLine,
            [
                "report.json",
                $"locationHint={reportJsonHint}",
                "description=Complete normalized event and finding source."
            ]);
        AppendRawSourceHint(
            html,
            "Complete normalized report JSON (all events)",
            "report.json",
            $"Complete normalized event and finding source. Expected location: {reportJsonHint}",
            "report.json",
            reportJsonCopy);

        if (rawArtifacts.Count == 0)
        {
            html.AppendLine("<li class=\"muted\">No raw source artifacts were indexed; report.json remains the complete normalized source.</li>");
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
        html.AppendLine("<div class=\"section-note\"><strong>Process relationship tree.</strong> Native expandable process tree grouped by stable process key when available, with PID/PPID fallback.</div>");
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
        var badges = ProcessTreeBadges(evt, childEvents.Count, activity);
        if (childEvents.Count > 0)
        {
            var open = ShouldOpenProcessTreeNode(depth, activity) ? " open" : string.Empty;
            html.AppendLine($"<li><details class=\"process-tree-node\"{open}><summary class=\"copyable\" data-copy=\"{A(EventToPlainText(evt))}\"><code>{E(label)}</code>{badges}</summary>");
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

        html.AppendLine($"<li><div class=\"process-tree-leaf copyable\" data-copy=\"{A(EventToPlainText(evt))}\"><code>{E(label)}</code>{badges}</div></li>");
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
        var image = !string.IsNullOrWhiteSpace(evt.Path)
            ? evt.Path
            : evt.CommandLine ?? string.Empty;
        return $"{ProcessGraphLabel(evt)} ppid:{ResolveParentProcessId(evt)?.ToString() ?? "-"} {image}".Trim();
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

    private static string ProcessTreeBadges(SandboxEvent evt, int childCount, ProcessTreeActivity activity)
    {
        var stableKey = FirstEventDataValue(evt, "processKey", "processGuid", "processUniqueId", "snapshotKey", "processSnapshotKey");
        var keyLabel = string.IsNullOrWhiteSpace(stableKey) ? $"pid:{evt.ProcessId?.ToString() ?? "-"}" : stableKey;
        var badges = new StringBuilder();
        badges.Append("<span class=\"tree-badges\">");
        badges.Append($"<span class=\"tree-badge\">key {E(keyLabel)}</span>");
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
        html.AppendLine("<div class=\"section-note\"><strong>Process relationship evidence.</strong> Cards summarize child, file, registry, network, and linked artifact evidence per stable process identity; long command lines stay folded and collector self-noise is excluded.</div>");
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
            html.AppendLine($"<details class=\"evidence-expansion-card\"><summary>Expand top process evidence</summary><pre class=\"copyable\" data-copy=\"{A(string.Join(Environment.NewLine, card.EvidenceLines))}\">{E(string.Join(Environment.NewLine, card.EvidenceLines))}</pre></details>");
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
        html.AppendLine("<div class=\"section-note\"><strong>Network category view.</strong> Cards split DNS, HTTP, TLS, flow, and linked PCAP/source artifacts so endpoint relationships stay readable without opening raw rows.</div>");
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
            html.AppendLine($"<details class=\"evidence-expansion-card\"><summary>Expand top network evidence</summary><pre class=\"copyable\" data-copy=\"{A(string.Join(Environment.NewLine, card.EvidenceLines))}\">{E(string.Join(Environment.NewLine, card.EvidenceLines))}</pre></details>");
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
                Target = ExtractNetworkTarget(evt) ?? $"unresolved:{evt.EventType}"
            })
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
        if (NetworkEventsShouldLinkPacketCapture(events))
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
        var protocol = FirstEventDataValue(evt, "protocol", "applicationProtocol", "appProtocol", "networkProtocol", "ipProtocol");
        if (ContainsProtocolOrType(protocol, "dns") ||
            evt.EventType.Contains("dns", StringComparison.OrdinalIgnoreCase) ||
            HasEventDataKeyContaining(evt, "dns", "queryName", "queryType", "answers"))
        {
            return "DNS";
        }

        if (ContainsProtocolOrType(protocol, "http") ||
            evt.EventType.Contains("http", StringComparison.OrdinalIgnoreCase) ||
            HasEventDataKeyContaining(evt, "http", "url", "uri", "userAgent", "statusCode", "method"))
        {
            return "HTTP";
        }

        if (ContainsProtocolOrType(protocol, "tls") ||
            ContainsProtocolOrType(protocol, "ssl") ||
            evt.EventType.Contains("tls", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.Contains("ssl", StringComparison.OrdinalIgnoreCase) ||
            HasEventDataKeyContaining(evt, "tls", "ssl", "sni", "serverName", "ja3", "certificate", "certSubject"))
        {
            return "TLS";
        }

        return "Flow";
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
        foreach (var evt in report.Events.OrderBy(evt => evt.Timestamp))
        {
            if (!IsSampleBehaviorEvent(evt))
            {
                continue;
            }

            var from = EventProcessActor(evt);
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

                edges.Add(new BehaviorGraphEdge(parent, "spawn", ResolveProcessLabel(evt, processLabels), EventToPlainText(evt)));
            }

            if (IsFileEvent(evt) && !string.IsNullOrWhiteSpace(evt.Path))
            {
                edges.Add(new BehaviorGraphEdge(from, "file", evt.Path!, EventToPlainText(evt)));
            }

            if (IsRegistryEvent(evt) && !string.IsNullOrWhiteSpace(evt.Path))
            {
                edges.Add(new BehaviorGraphEdge(from, "registry", evt.Path!, EventToPlainText(evt)));
            }

            var networkTarget = ExtractNetworkTarget(evt);
            if (!string.IsNullOrWhiteSpace(networkTarget))
            {
                edges.Add(new BehaviorGraphEdge(from, "network", networkTarget, EventToPlainText(evt)));
            }

            foreach (var artifact in FindRelatedArtifacts(evt, artifactLookup, artifacts).Take(3))
            {
                edges.Add(new BehaviorGraphEdge(from, "artifact", ArtifactDisplayName(artifact), ArtifactToPlainText(artifact)));
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

        if (!string.IsNullOrWhiteSpace(evt.Path) &&
            (evt.Path.Contains("://", StringComparison.Ordinal) || evt.Path.Contains('.', StringComparison.Ordinal)))
        {
            return evt.Path;
        }

        var preferred = FirstEventDataValue(
            evt,
            "url",
            "uri",
            "host",
            "hostname",
            "domain",
            "queryName",
            "query",
            "dnsName",
            "sni",
            "serverName",
            "remoteEndpoint",
            "remoteAddress",
            "destinationAddress",
            "ip");
        if (string.IsNullOrWhiteSpace(preferred))
        {
            preferred = evt.Data
                .Where(pair => LooksLikeNetworkIndicatorKey(pair.Key) && !string.IsNullOrWhiteSpace(pair.Value))
                .Select(pair => pair.Value)
                .FirstOrDefault();
        }

        if (string.IsNullOrWhiteSpace(preferred))
        {
            return null;
        }

        var port = FirstEventDataValue(evt, "remotePort", "destinationPort", "port");
        return string.IsNullOrWhiteSpace(port) || preferred.Contains(':', StringComparison.Ordinal)
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
            "objectName",
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
        return !IsCollectionHealthEvent(evt) &&
            !IsCollectorSelfNoiseEvent(evt) &&
            !IsVirusTotalEvent(evt);
    }

    private static bool IsSampleBehaviorFileEvent(SandboxEvent evt) => IsSampleBehaviorEvent(evt) && IsFileEvent(evt);

    private static bool IsSampleBehaviorRegistryEvent(SandboxEvent evt) => IsSampleBehaviorEvent(evt) && IsRegistryEvent(evt);

    private static bool IsSampleBehaviorNetworkEvent(SandboxEvent evt) => IsSampleBehaviorEvent(evt) && IsNetworkEvent(evt);

    private static bool IsSampleBehaviorProcessEvent(SandboxEvent evt) =>
        IsSampleBehaviorEvent(evt) && evt.EventType.StartsWith("process.", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Detects rows produced by KSword's own collector/agent plumbing.
    /// Inputs are one event; processing checks process identity, R0Collector
    /// staging paths, device paths, and source tokens; the method returns true
    /// when the row should be treated as collection metadata rather than sample
    /// behavior.
    /// </summary>
    private static bool IsCollectorSelfNoiseEvent(SandboxEvent evt)
    {
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
            evt.EventType.StartsWith("r0collector.driverProtocolError", StringComparison.OrdinalIgnoreCase) ||
            EventTextContainsAny(evt, "readiness", "diagnose", "diagnostic", "unavailable", "driverCapabilities", "driverStatus", "driver状态"))
        {
            return true;
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
            finding.Evidence.All(evt => IsCollectionHealthEvent(evt) || IsCollectorSelfNoiseEvent(evt)))
        {
            return true;
        }

        if (finding.Tags.Any(tag =>
                string.Equals(tag, "plumbing", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(tag, "driver-health", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(tag, "collection", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(tag, "diagnostic", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(tag, "metadata", StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        return finding.RuleId.StartsWith("host-", StringComparison.OrdinalIgnoreCase) ||
            finding.RuleId.StartsWith("runbook-", StringComparison.OrdinalIgnoreCase) ||
            finding.RuleId.StartsWith("r0collector-", StringComparison.OrdinalIgnoreCase) ||
            finding.RuleId.Contains("unavailable", StringComparison.OrdinalIgnoreCase);
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
            "high" => 0,
            "medium" => 1,
            "low" => 2,
            _ => 3
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
        return value is "high" or "medium" or "low" ? value : "info";
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
    private static string LocalizeChineseHtml(string html)
    {
        var protectedFragments = new List<string>();
        html = ProtectChineseRawEvidenceFragments(html, protectedFragments);

        foreach (var (english, chinese) in ChineseHtmlTranslations.OrderByDescending(pair => pair.English.Length))
        {
            html = html.Replace(english, chinese, StringComparison.Ordinal);
        }

        html = ChineseVisibleEventCountRegex.Replace(html, " 个事件");
        html = RestoreChineseRawEvidenceFragments(html, protectedFragments);
        return html;
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
        ("High risk", "高风险"),
        ("Suspicious", "可疑行为"),
        (">Queued<", ">已排队<"),
        (">Planning<", ">规划中<"),
        (">Planned<", ">已规划<"),
        (">Running<", ">运行中<"),
        (">Completed<", ">已完成<"),
        (">Failed<", ">失败<"),
        (">high<", ">高<"),
        (">medium<", ">中<"),
        (">low<", ">低<"),
        (">info<", ">信息<"),
        ("Table of contents", "目录"),
        ("Cover", "封面"),
        ("Report language", "报告语言"),
        ("English report", "英文报告"),
        ("Default report", "默认报告"),
        ("Default report.html uses Simplified Chinese; report.en.html keeps English operator chrome. Evidence values stay original in both reports. The WebUI also serves these through /api/jobs/{jobId}/report/html?lang=zh and ?lang=en.", "默认 report.html 使用简体中文；report.en.html 保留英文操作界面。两份报告中的证据值保持原文。WebUI 也通过 /api/jobs/{jobId}/report/html?lang=zh 和 ?lang=en 提供这些报告。"),
        ("The WebUI also serves these through /api/jobs/{jobId}/report/html?lang=zh and ?lang=en.", "WebUI 也通过 /api/jobs/{jobId}/report/html?lang=zh 和 ?lang=en 提供这些报告。"),
        ("Quick navigation", "快速导航"),
        ("Sticky subnav", "固定子导航"),
        ("Sticky subnav for Process / Files / Network / R0 / VT / Artifacts quick navigation; counts show currently embedded representative evidence. R0 health, collector self-noise, and VT status rows are counted in their own lanes rather than primary behavior.", "固定子导航用于快速跳转进程 / 文件 / 网络 / R0 / VT / 证据文件；计数表示当前内联的代表性证据。R0 健康、采集器自噪声和 VT 状态行会计入各自通道，而不是主要行为。"),
        ("Sticky subnav for Process / Files / Network / R0 / VT / Artifacts quick navigation; counts show currently embedded representative evidence.", "固定子导航用于快速跳转进程 / 文件 / 网络 / R0 / VT / 证据文件；计数表示当前内联的代表性证据。"),
        ("R0 health", "R0 健康状态"),
        ("VT lookups", "VT 查询"),
        ("Risk summary", "风险摘要"),
        ("Behavior detections", "行为命中"),
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
        ("Evidence story board", "证据故事板"),
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
        ("Health alerts:", "健康告警："),
        ("no health rows", "无健康行"),
        ("unavailable/degraded", "不可用/降级"),
        ("attention needed", "需要关注"),
        ("available", "可用"),
        ("Artifact links", "证据文件链接"),
        ("Artifact evidence cards.", "证据文件证据卡。"),
        ("Collection status, safe download selectors, duplicate grouping, and rejection diagnostics are summarized before the dense artifact table. Safe report-relative links can open or download; absolute host/guest paths remain copy-only evidence.", "采集状态、安全下载选择器、重复分组和拒绝诊断会先于密集证据文件表汇总。安全的报告相对链接可以打开或下载；主机/guest 绝对路径保持为仅复制证据。"),
        ("Artifact collection status", "证据采集状态"),
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
        ("Complete normalized report JSON", "完整规范化报告 JSON"),
        ("(all events)", "（全部事件）"),
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
        ("No raw source artifacts were indexed; report.json remains the complete normalized source.", "未索引原始来源证据；report.json 仍是完整的规范化来源。"),
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
        ("Native expandable process tree grouped by stable process key when available, with PID/PPID fallback.", "使用原生可展开进程树；有稳定进程键时按键分组，否则回退到 PID/PPID。"),
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
        ("memory-dump", "内存转储"),
        ("packet-capture", "网络抓包"),
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
        ("very high entropy", "熵值非常高"),
        ("high entropy", "熵值高"),
        ("low entropy", "熵值低"),
        ("virtual only", "仅虚拟节区"),
        ("large virtual/raw gap", "虚拟/原始大小差距大"),
        ("UPX-like", "疑似 UPX")
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
})();
</script>
""");
    }
}
