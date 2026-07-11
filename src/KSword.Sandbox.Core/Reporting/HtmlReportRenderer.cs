using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
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
    private const int ArtifactPreviewCharacterLimit = 12_000;
    private const int TimelineEventInlineLimit = 120;
    private const int TimelineGroupEventInlineLimit = 12;
    private const int EventTableInlineLimit = 80;
    private const int StaticStringInlineLimit = 200;
    private const int RawEventInlineLimit = 100;
    private const int RawEventPageSize = 50;
    private const int EventCompactFieldInlineLimit = 28;
    private const int EventCompactFieldValueLimit = 220;
    private const int FindingEvidenceDataPairLimit = 16;
    private const int FindingEvidenceValueLimit = 180;

    private sealed record TimelineGroup(
        string Window,
        string Summary,
        int TotalEventCount,
        IReadOnlyList<SandboxEvent> Events,
        string CopyText);

    private sealed record BehaviorGraphEdge(string From, string Relation, string To, string Evidence);

    private sealed record ProcessGraphNode(string Label, string Detail, string CopyText);

    private sealed record EvidenceSummaryCard(string Title, string Value, string Detail, string Css, string CopyText);

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
        string CopyText);

    private sealed record NetworkRelationshipCard(
        string Target,
        string RiskCss,
        int EventCount,
        string Protocols,
        string FirstSeen,
        string LastSeen,
        IReadOnlyList<string> Processes,
        IReadOnlyList<string> EventTypes,
        IReadOnlyList<string> EvidenceLines,
        string CopyText);

    private static readonly JsonSerializerOptions ArtifactJsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter() }
    };

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
    /// Converts one AnalysisReport plus optional artifact descriptors to HTML.
    /// Inputs are a report and host/guest artifact index entries; processing
    /// renders artifact links before behavior timelines; the method returns a
    /// complete HTML document string.
    /// </summary>
    public string Render(AnalysisReport report, IEnumerable<ArtifactDescriptor>? artifacts) =>
        Render(report, artifacts, HtmlReportLanguage.English);

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
    /// Converts one AnalysisReport to the default English HTML variant.
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
:root{--primary:#43A0FF;--primary-deep:#0969c9;--primary-soft:#e7f3ff;--ink:#0f172a;--muted:#64748b;--line:#dce8f5;--panel:#ffffff}
*{box-sizing:border-box}html{scroll-behavior:smooth}
body{margin:0;background:radial-gradient(circle at 8% 5%,rgba(67,160,255,.22),transparent 28%),linear-gradient(180deg,#f4f9ff 0,#f8fafc 46%,#eef6ff 100%);color:var(--ink);font-family:Segoe UI,Arial,sans-serif}
body.modern-sandbox-report:before{background:linear-gradient(90deg,var(--primary),#7dd3fc,#22d3ee);content:'';display:block;height:5px;width:100%}
header{background:radial-gradient(circle at 80% 15%,rgba(67,160,255,.55),transparent 34%),linear-gradient(135deg,#08111f,#123d66 62%,#0d5fa8);color:white;padding:38px 48px;position:relative;overflow:hidden}
header:after{border:1px solid rgba(255,255,255,.18);border-radius:999px;content:'';height:220px;position:absolute;right:-70px;top:-80px;width:220px}
header h1{font-size:34px;letter-spacing:-.03em;margin:0 0 8px}header .muted{color:#dbeafe}
header table{background:rgba(8,17,31,.32);border:1px solid rgba(255,255,255,.16);border-radius:16px;overflow:hidden}header td,header th{border-bottom:1px solid rgba(255,255,255,.14);color:white}header th{background:rgba(255,255,255,.08);position:static}
main,nav{max-width:1280px;margin:24px auto;padding:0 24px}main{counter-reset:report-section}.card{background:rgba(255,255,255,.94);border:1px solid var(--line);border-radius:22px;box-shadow:0 18px 48px rgba(15,23,42,.08);margin:22px 0;padding:24px;position:relative}
section.card{counter-increment:report-section;max-height:75vh;overflow:auto;scrollbar-color:var(--primary) #eaf4ff;scrollbar-width:thin}.card:before{background:linear-gradient(180deg,var(--primary),rgba(67,160,255,0));border-radius:22px 0 0 22px;content:'';height:100%;left:0;opacity:.9;position:absolute;top:0;width:4px}
.language-entry{align-items:center;display:flex;flex-wrap:wrap;gap:10px}.language-entry strong{color:#075985}.language-entry .hint{color:var(--muted);font-size:13px}.language-entry a{background:var(--primary);border-radius:999px;color:white;font-weight:800;padding:8px 12px;text-decoration:none}.language-entry a.secondary{background:#334155}.language-entry a:hover{box-shadow:0 0 0 4px rgba(67,160,255,.14)}
.quick-nav{border-color:#b9ddff;position:sticky;top:8px;z-index:20}.quick-nav:before{background:linear-gradient(180deg,#43A0FF,#0ea5e9)}.quick-nav h2{font-size:16px;margin-bottom:8px}.quick-nav .hint{color:var(--muted);font-size:12px;margin:0 0 10px}.quick-links{display:flex;flex-wrap:wrap;gap:8px}.quick-link{align-items:center;background:linear-gradient(180deg,#fff,#eef7ff);border:1px solid #cfe6fb;border-radius:14px;color:#075985;display:inline-flex;gap:8px;min-height:42px;padding:7px 10px;text-decoration:none}.quick-link strong{font-size:13px}.quick-link small{background:#dff0ff;border-radius:999px;color:#075985;font-weight:900;min-width:24px;padding:3px 7px;text-align:center}.quick-link:hover{border-color:var(--primary);box-shadow:0 0 0 4px rgba(67,160,255,.14)}
.card h2{align-items:center;display:flex;gap:10px;margin:0 0 14px}.card h2:before{background:var(--primary);box-shadow:0 0 0 6px rgba(67,160,255,.14);border-radius:999px;content:'';display:inline-block;height:12px;width:12px}section.card>h2{backdrop-filter:blur(10px);background:linear-gradient(90deg,rgba(255,255,255,.98),rgba(231,243,255,.95));border-bottom:1px solid #dbeafe;margin:-24px -24px 16px;padding:16px 24px;position:sticky;top:-24px;z-index:3}section.card>h2:after{background:var(--primary);border-radius:999px;color:white;content:'Step ' counter(report-section);font-size:11px;font-weight:900;margin-left:auto;padding:5px 9px;text-transform:uppercase}
.grid{display:grid;gap:14px;grid-template-columns:repeat(auto-fit,minmax(170px,1fr))}.metric{background:linear-gradient(180deg,#fff,#f7fbff);border:1px solid var(--line);border-top:3px solid var(--primary);border-radius:16px;padding:15px}.metric b{display:block;font-size:26px;margin-top:4px}
.muted{color:var(--muted)}.risk-high{color:#b91c1c}.risk-medium{color:#b45309}.risk-low{color:#047857}.risk-info{color:var(--primary-deep)}
.badge,.chip{border-radius:999px;display:inline-block;font-weight:700;padding:6px 12px}.chip{font-size:12px;margin:2px 4px 2px 0;padding:3px 8px}
.badge-high,.chip-high{background:#fee2e2;color:#991b1b}.badge-medium,.chip-medium{background:#fef3c7;color:#92400e}.badge-low,.chip-low{background:#dcfce7;color:#166534}.badge-info,.chip-info{background:var(--primary-soft);color:#075985}
.section-note{background:#f7fbff;border-left:4px solid var(--primary);border-radius:10px;color:#475569;margin:10px 0;padding:11px 13px}
table{border-collapse:separate;border-spacing:0;width:100%;margin-top:14px}td,th{border-bottom:1px solid #e5edf6;padding:10px;text-align:left;vertical-align:top}th{background:rgba(248,251,255,.96);color:#475569;font-size:12px;position:sticky;text-transform:uppercase;top:0;z-index:1}
code{background:#f1f7ff;border-radius:6px;padding:2px 5px;word-break:break-all}.toc a{background:#f7fbff;border:1px solid var(--line);border-radius:999px;color:#075985;display:inline-block;font-weight:700;margin:4px 8px 4px 0;padding:7px 12px;text-decoration:none}.toc a:hover{border-color:var(--primary);box-shadow:0 0 0 4px rgba(67,160,255,.14)}
.empty{background:linear-gradient(180deg,#fff,#f7fbff);border:1px dashed #b9d7f3;border-radius:12px;color:var(--muted);padding:14px}
.copy-btn{background:rgba(67,160,255,.12);border:1px solid rgba(67,160,255,.45);border-radius:999px;color:#075985;cursor:pointer;font-size:12px;font-weight:700;margin:2px 0;padding:5px 10px}.copyable{cursor:copy}.copy-hint{color:var(--muted);font-size:12px;margin-top:8px}
.event-table-wrap{border:1px solid var(--line);border-radius:14px;margin-top:14px;max-height:60vh;overflow:auto}.event-table-wrap table{margin-top:0}.event-table-wrap th{top:0}.bounded-list{max-height:42vh;overflow:auto}
.event-table td:first-child{white-space:nowrap}.event-table td:nth-child(2){min-width:140px}.event-table td:nth-child(4){min-width:140px}.event-table td:nth-child(5){min-width:260px}.event-table .evidence{min-width:280px}
.timeline-groups{display:grid;gap:12px;margin-top:14px}.timeline-group{background:#fbfdff;border:1px solid var(--line);border-radius:16px;overflow:hidden}.timeline-group>summary{align-items:flex-start;cursor:pointer;display:flex;gap:10px;justify-content:space-between;list-style:none;padding:12px 14px}.timeline-group>summary::-webkit-details-marker{display:none}.timeline-group>summary:before{color:var(--primary-deep);content:'▶';font-weight:900;margin-top:2px}.timeline-group[open]>summary:before{content:'▼'}.timeline-group small{color:var(--muted);display:block;line-height:1.4;margin-top:3px}.timeline{border-left:3px solid rgba(67,160,255,.45);margin:0 14px 14px 20px;padding:12px 0 0 18px}.timeline-item{background:#f9fcff;border:1px solid var(--line);border-radius:12px;margin:0 0 12px;padding:10px 12px;position:relative}.timeline-item:before{background:var(--primary);border:3px solid var(--primary-soft);border-radius:999px;content:'';height:11px;left:-26px;position:absolute;top:13px;width:11px}.timeline-overflow{background:#f1f7ff;border:1px dashed #b9d7f3;border-radius:12px;color:var(--muted);margin:0 0 12px;padding:9px 11px}
.graph-map{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));margin-top:12px}.graph-node{background:#f8fbff;border:1px solid var(--line);border-left:4px solid var(--primary);border-radius:14px;padding:12px}.graph-node strong{display:block;margin-bottom:4px}.graph-node small{color:var(--muted);display:block;line-height:1.4}.behavior-chain{background:linear-gradient(180deg,#fbfdff,#f1f7ff);border:1px solid var(--line);border-radius:16px;counter-reset:chain;margin:12px 0;max-height:42vh;overflow:auto;padding:10px 12px}.behavior-chain li{align-items:flex-start;background:#fff;border:1px solid #dbeafe;border-radius:13px;counter-increment:chain;display:grid;gap:8px;grid-template-columns:auto 1fr;margin:8px 0;padding:10px}.behavior-chain li:before{align-items:center;background:var(--primary);border-radius:999px;color:white;content:counter(chain);display:inline-flex;font-weight:900;height:24px;justify-content:center;width:24px}.behavior-chain details{grid-column:2;background:#f8fbff;border:1px solid var(--line);border-radius:10px;padding:6px}.behavior-chain pre{max-height:24vh;overflow:auto;white-space:pre-wrap;word-break:break-word}.edge-table td:nth-child(1),.edge-table td:nth-child(3){min-width:170px}.ioc-grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));margin-top:14px}.ioc-card{background:#ffffff;border:1px solid var(--line);border-radius:14px;padding:12px}.ioc-card h3{font-size:15px;margin:0 0 8px}.ioc-card ul{margin:0;padding-left:18px}.ioc-card li{margin:5px 0;word-break:break-word}
.evidence-summary-grid,.relation-grid{display:grid;gap:14px;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));margin-top:14px}.evidence-summary-card,.relation-card{background:linear-gradient(180deg,#ffffff,#f7fbff);border:1px solid var(--line);border-radius:18px;box-shadow:0 10px 28px rgba(15,23,42,.06);max-height:46vh;overflow:auto;padding:14px;position:relative}.evidence-summary-card:before,.relation-card:before{background:linear-gradient(180deg,var(--primary),#93c5fd);border-radius:18px 0 0 18px;content:'';height:100%;left:0;position:absolute;top:0;width:3px}.evidence-summary-card h3,.relation-card h3{font-size:15px;margin:0 0 8px;padding-left:4px}.summary-value{color:#075985;display:block;font-size:26px;font-weight:900;letter-spacing:-.04em}.relationship-meta{display:grid;gap:6px;grid-template-columns:repeat(2,minmax(0,1fr));margin:10px 0}.relationship-meta span{background:#eef7ff;border:1px solid #cfe6fb;border-radius:10px;color:#075985;font-size:12px;font-weight:700;padding:7px}.relationship-tags{display:flex;flex-wrap:wrap;gap:6px;margin:8px 0}.relationship-tags .chip{margin:0}.relationship-details{background:#fbfdff;border:1px solid var(--line);border-radius:12px;margin-top:10px;padding:8px}.relationship-details summary{cursor:pointer;font-weight:800}.relationship-details pre{max-height:30vh;overflow:auto;white-space:pre-wrap;word-break:break-word}.relationship-title{display:flex;align-items:flex-start;gap:8px;justify-content:space-between}.relationship-title code{max-width:100%;overflow-wrap:anywhere}.anchor-offset{scroll-margin-top:18px}.mono-list{font-family:Consolas,monospace;font-size:12px;line-height:1.45;margin:6px 0 0 0;padding-left:18px}.mono-list li{margin:3px 0;word-break:break-word}
.tree{font-family:Consolas,monospace;line-height:1.5;margin:12px 0}.tree ul{border-left:1px dashed #b9d7f3;list-style:none;margin:0 0 0 18px;padding-left:14px}.tree li{margin:5px 0}.process-tree{background:#fbfdff;border:1px solid var(--line);border-radius:16px;max-height:46vh;overflow:auto;padding:12px}.process-tree details.process-tree-node{margin:4px 0}.process-tree summary,.process-tree-leaf{align-items:center;cursor:pointer;display:flex;flex-wrap:wrap;gap:8px;list-style:none}.process-tree summary::-webkit-details-marker{display:none}.process-tree summary:before{color:var(--primary-deep);content:'▶';font-weight:900}.process-tree details[open]>summary:before{content:'▼'}.tree-badges{display:flex;flex-wrap:wrap;gap:5px}.tree-badge{background:#eef7ff;border:1px solid #cfe6fb;border-radius:999px;color:#075985;font-family:Segoe UI,Arial,sans-serif;font-size:11px;font-weight:800;padding:2px 7px}
.evidence{max-width:560px}.evidence details{background:#f7fbff;border:1px solid var(--line);border-radius:12px;padding:8px}.evidence summary{cursor:pointer;font-weight:700}.evidence pre{white-space:pre-wrap;word-break:break-word}
.toolbar{display:flex;gap:8px;justify-content:flex-end}.columns{display:grid;gap:14px;grid-template-columns:1fr 1fr}.compact-list{margin:8px 0 0 0;padding-left:18px}.compact-list li{margin:4px 0}
.artifact-ref{font-weight:700}.artifact-location{display:grid;gap:8px}.artifact-actions{display:flex;flex-wrap:wrap;gap:7px;margin-top:6px}.artifact-actions-inline{display:inline-flex;margin-left:6px;margin-top:0;vertical-align:middle}.artifact-btn{background:var(--primary);border:1px solid rgba(67,160,255,.72);border-radius:999px;box-shadow:0 8px 18px rgba(67,160,255,.18);color:white;display:inline-block;font-size:12px;font-weight:900;padding:6px 10px;text-decoration:none}.artifact-btn.download{background:#eef7ff;color:#075985}.artifact-btn:hover{box-shadow:0 0 0 4px rgba(67,160,255,.14)}.artifact-no-link{background:#f8fafc;border:1px dashed #cbd5e1;border-radius:999px;color:var(--muted);display:inline-block;font-size:12px;font-weight:800;padding:5px 9px}.artifact-copy-path{background:#fbfdff;border:1px solid var(--line);border-radius:10px;padding:8px}.artifact-list{list-style:none;margin:8px 0 0 0;padding:0}.artifact-list li{border-top:1px solid #e2e8f0;margin-top:8px;padding-top:8px}.artifact-preview img{border:1px solid #cbd5e1;border-radius:10px;max-height:260px;max-width:100%}
.technical-field,.raw-technical-fields{background:#fbfdff;border:1px solid var(--line);border-radius:12px;margin-top:8px;padding:8px}.technical-field summary,.raw-technical-fields summary,.raw-technical-field summary{cursor:pointer;font-weight:800}.technical-field pre,.raw-technical-field pre{max-height:30vh;overflow:auto;white-space:pre-wrap;word-break:break-word}.raw-field-list{margin:6px 0 0 0;padding-left:18px}.raw-field-list li{margin:4px 0;word-break:break-word}.raw-technical-field{background:#fff;border:1px solid #dbeafe;border-radius:10px;margin-top:8px;padding:7px}
.raw-events-shell{background:#f9fcff;border:1px solid var(--line);border-radius:16px;margin-top:14px;overflow:hidden}.raw-events-shell>summary{cursor:pointer;font-weight:800;list-style:none;padding:12px 14px}.raw-events-shell>summary::-webkit-details-marker{display:none}.raw-events-shell>summary:before{color:var(--primary-deep);content:'▶';display:inline-block;margin-right:8px}.raw-events-shell[open]>summary:before{content:'▼'}.raw-events-panel{border-top:1px solid var(--line);max-height:58vh;overflow:auto;padding:12px}.raw-event-pages{display:grid;gap:12px}.raw-event-page{background:#fff;border:1px solid #dbeafe;border-radius:14px;overflow:hidden}.raw-event-page>summary{background:linear-gradient(90deg,#eef7ff,#ffffff);color:#075985;cursor:pointer;font-weight:900;list-style:none;padding:10px 12px}.raw-event-page>summary::-webkit-details-marker{display:none}.raw-event-page>summary:before{content:'▶';display:inline-block;margin-right:8px}.raw-event-page[open]>summary:before{content:'▼'}.raw-event-page table{margin:0}.raw-source-hints{background:#f8fbff;border:1px solid var(--line);border-radius:14px;margin-top:12px;padding:12px}.raw-source-hints ul{list-style:none;margin:8px 0 0 0;padding:0}.raw-source-hints li{border-top:1px solid #e2e8f0;margin-top:8px;padding-top:8px}.raw-source-hints li:first-child{border-top:0;margin-top:0;padding-top:0}.raw-source-hints .hint-label{font-weight:800}
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
        html.AppendLine("<span class=\"hint\">The WebUI also serves these through /api/jobs/{jobId}/report/html?lang=zh and ?lang=en.</span>");
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
        html.AppendLine("<p class=\"hint\">Sticky subnav for Process / Files / Network / R0 / VT / Artifacts quick navigation; counts show currently embedded representative evidence.</p>");
        html.AppendLine("<div class=\"quick-links\">");
        QuickLink(html, "risk", "Risk summary", PrimaryBehaviorFindings(report).Count().ToString());
        QuickLink(html, "process", "Process details", report.Events.Count(evt => evt.EventType.StartsWith("process.", StringComparison.OrdinalIgnoreCase)).ToString());
        QuickLink(html, "files", "File system activity", report.Events.Count(IsFileEvent).ToString());
        QuickLink(html, "network", "Network behavior", report.Events.Count(IsNetworkEvent).ToString());
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
        Metric(html, "File events", report.Events.Count(IsFileEvent).ToString(), "risk-medium");
        Metric(html, "Network events", report.Events.Count(IsNetworkEvent).ToString(), "risk-medium");
        Metric(html, "Registry events", report.Events.Count(IsRegistryEvent).ToString(), "risk-medium");
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
            $"<div class=\"toolbar\">{CopyButton("Copy behavior evidence", full)}</div>" +
            $"<span class=\"chip chip-info copyable\" data-copy=\"{A(summary)}\">{E(summary)}</span>" +
            $"<details><summary>Top evidence summary</summary><pre class=\"copyable\" data-copy=\"{A(full)}\">{E(compact)}</pre></details>";
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
        Metric(html, "Process starts", CountEvents(report, "process.start").ToString(), "risk-info");
        Metric(html, "Process exits", CountEvents(report, "process.exit").ToString(), "risk-info");
        Metric(html, "Registry events", report.Events.Count(IsRegistryEvent).ToString(), "risk-medium");
        Metric(html, "File events", report.Events.Count(IsFileEvent).ToString(), "risk-medium");
        Metric(html, "Network events", report.Events.Count(IsNetworkEvent).ToString(), "risk-medium");
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
                html.AppendLine($"<td class=\"evidence\"><div class=\"toolbar\">{CopyButton("Copy graph edge", copy)}</div><details><summary>Evidence fields</summary><pre class=\"copyable\" data-copy=\"{A(copy)}\">{E(copy)}</pre></details></td>");
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
            html.AppendLine($"<details><summary>Edge evidence</summary><pre class=\"copyable\" data-copy=\"{A(edge.Evidence)}\">{E(edge.Evidence)}</pre></details>");
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
            html.AppendLine($"<details class=\"relationship-details\"><summary>Evidence summary</summary><pre class=\"copyable\" data-copy=\"{A(card.CopyText)}\">{E(card.CopyText)}</pre></details>");
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
    /// Appends host-safe artifact links and paths.
    /// Inputs are normalized artifact descriptors; processing renders links for
    /// safe relative paths and plain text for guest-local or unsafe paths; the
    /// method returns no value.
    /// </summary>
    private static void AppendArtifactLinks(StringBuilder html, AnalysisReport report, IReadOnlyCollection<ArtifactDescriptor> artifacts)
    {
        html.AppendLine("<section id=\"artifacts\" class=\"card\"><h2>Artifact links</h2>");
        AppendArtifactCollectionStatusCards(html, report, artifacts);
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
            html.AppendLine($"<td class=\"evidence\"><div class=\"toolbar\">{CopyButton("Copy artifact", plain)}</div><details><summary>Artifact evidence</summary><pre class=\"copyable\" data-copy=\"{A(plain)}\">{E(plain)}</pre></details>{RenderArtifactPreview(artifact)}</td>");
            html.AppendLine("</tr>");
        }

        html.AppendLine("</tbody></table>");
        html.AppendLine("<div class=\"copy-hint\">Safe links are relative to the report artifact root; unsafe or guest-local paths are shown as copyable text only.</div>");
        html.AppendLine("</section>");
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
            html.AppendLine($"<details class=\"relationship-details\"><summary>Collection evidence</summary><pre class=\"copyable\" data-copy=\"{A(card.CopyText)}\">{E(card.CopyText)}</pre></details>");
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
        AppendProcessRelationshipCards(html, report);
        AppendEventRows(html, report.Events.Where(e => e.EventType.StartsWith("process.", StringComparison.OrdinalIgnoreCase)).ToList(), artifactLookup, artifacts);
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
        AppendEventTable(html, "files", "File system activity", report.Events.Where(IsFileEvent), artifactLookup, artifacts);
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
        AppendEventTable(html, "registry", "Registry behavior", report.Events.Where(IsRegistryEvent), artifactLookup, artifacts);
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
        var networkEvents = report.Events.Where(IsNetworkEvent).ToList();
        html.AppendLine("<section id=\"network\" class=\"card\"><h2>Network behavior</h2>");
        AppendNetworkRelationshipCards(html, networkEvents);
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
        var healthEvents = r0Events.Where(IsR0CollectionHealthEvent).ToList();
        var telemetryEvents = r0Events.Where(evt => !IsR0CollectionHealthEvent(evt)).ToList();
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
        Metric(html, "Driver telemetry rows", telemetryEvents.Count.ToString(), "risk-info");
        Metric(html, "Kernel file rows", telemetryEvents.Count(IsFileEvent).ToString(), "risk-medium");
        Metric(html, "Kernel registry rows", telemetryEvents.Count(IsRegistryEvent).ToString(), "risk-medium");
        Metric(html, "Kernel network rows", telemetryEvents.Count(IsNetworkEvent).ToString(), "risk-medium");
        Metric(html, "Health alerts", healthEvents.Count(IsCollectionHealthAlertEvent).ToString(), healthEvents.Any(IsCollectionHealthAlertEvent) ? "risk-medium" : "risk-info");
        html.AppendLine("</div>");

        AppendR0CollectionHealthStatus(html, healthEvents, artifactLookup, artifacts);

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
    /// Appends R0 collection health separately from driver telemetry so
    /// unavailable devices, driver health, backpressure, and dropped counters
    /// are not presented as malicious behavior.
    /// </summary>
    private static void AppendR0CollectionHealthStatus(
        StringBuilder html,
        IReadOnlyCollection<SandboxEvent> healthEvents,
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

        if (healthEvents.Count == 0)
        {
            Empty(html, "No R0 collection health rows were imported.");
            return;
        }

        AppendEventRows(html, healthEvents, artifactLookup, artifacts);
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
        html.AppendLine($"<div class=\"section-note\"><strong>Raw events are collapsed by default.</strong> Raw events shown inline: {inlineEvents.Count}/{orderedEvents.Count}. Inline page size: {RawEventPageSize}. Hidden raw events: {hiddenCount}. Open report.json or raw source artifacts for complete evidence.</div>");
        AppendRawSourceHints(html, report, artifacts);
        AppendRawEventDistribution(html, orderedEvents);

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
            html.AppendLine($"<details class=\"raw-event-page copyable\" data-copy=\"{A(copy)}\"{open}><summary>Raw event page {pageNumber}: rows {first}-{last} of {totalEventCount}</summary>");
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
        html.AppendLine("<table class=\"event-table\"><thead><tr><th>Time</th><th>Type</th><th>Source</th><th>Process</th><th>Path / Command</th><th>Data</th></tr></thead><tbody>");
        foreach (var evt in inlineEvents)
        {
            var plain = EventToBoundedPlainText(evt, maxDataPairs: 40, maxValueLength: 300);
            var relatedArtifacts = FindRelatedArtifacts(evt, artifactLookup, artifacts);
            html.AppendLine("<tr>");
            html.AppendLine($"<td class=\"copyable\" data-copy=\"{A(evt.Timestamp.ToString("u"))}\">{E(evt.Timestamp.ToString("u"))}</td>");
            html.AppendLine($"<td class=\"copyable\" data-copy=\"{A(evt.EventType)}\">{E(evt.EventType)}</td>");
            html.AppendLine($"<td class=\"copyable\" data-copy=\"{A(evt.Source)}\">{E(evt.Source)}</td>");
            html.AppendLine($"<td class=\"copyable\" data-copy=\"{A((evt.ProcessName ?? "-") + " (" + (evt.ProcessId?.ToString() ?? "-") + ")")}\">{E(evt.ProcessName ?? "-")} ({E(evt.ProcessId?.ToString() ?? "-")})</td>");
            html.AppendLine($"<td class=\"copyable\" data-copy=\"{A((evt.Path ?? string.Empty) + Environment.NewLine + (evt.CommandLine ?? string.Empty))}\">{RenderEventPathAndCommand(evt, relatedArtifacts)}</td>");
            html.AppendLine($"<td class=\"evidence\"><div class=\"toolbar\">{CopyButton("Copy event", plain)}{RenderCopyArtifactsButton(relatedArtifacts)}</div>{RenderEventEvidenceDetails(evt)}{RenderRelatedArtifacts(relatedArtifacts)}</td>");
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

        html.AppendLine("<div class=\"raw-source-hints\"><strong>Raw source paths</strong><ul>");
        AppendRawSourceHint(
            html,
            "Complete normalized report JSON",
            "report.json",
            reportJsonHint,
            "report.json",
            reportJsonHint);

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
                var note = RawSourceArtifactNote(artifact);
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
            .Where(e => IsProcessTreeCandidate(e) && e.ProcessId.HasValue)
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
        var roots = starts
            .Where(e => !ParentProcessLookupKeys(e).Any(known.Contains))
            .ToList();

        html.AppendLine("<h3>Process tree</h3>");
        html.AppendLine("<div class=\"section-note\"><strong>Process relationship tree.</strong> Native expandable process tree grouped by stable process key when available, with PID/PPID fallback.</div>");
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
            AppendProcessTreeNode(html, root, children, new HashSet<string>(StringComparer.OrdinalIgnoreCase));
        }

        html.AppendLine("</ul></div>");
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
        HashSet<string> visited)
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
        var badges = ProcessTreeBadges(evt, childEvents.Count);
        if (childEvents.Count > 0)
        {
            html.AppendLine($"<li><details class=\"process-tree-node\" open><summary class=\"copyable\" data-copy=\"{A(EventToPlainText(evt))}\"><code>{E(label)}</code>{badges}</summary>");
            if (!visited.Add(processKey))
            {
                html.AppendLine("<ul><li><span class=\"muted\">Cycle suppressed for stable rendering.</span></li></ul>");
                html.AppendLine("</details></li>");
                return;
            }

            html.AppendLine("<ul>");
            foreach (var child in childEvents)
            {
                AppendProcessTreeNode(html, child, children, new HashSet<string>(visited, StringComparer.OrdinalIgnoreCase));
            }

            html.AppendLine("</ul>");
            html.AppendLine("</details></li>");
            return;
        }

        html.AppendLine($"<li><div class=\"process-tree-leaf copyable\" data-copy=\"{A(EventToPlainText(evt))}\"><code>{E(label)}</code>{badges}</div></li>");
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

    private static string ProcessTreeBadges(SandboxEvent evt, int childCount)
    {
        var stableKey = FirstEventDataValue(evt, "processKey", "processGuid", "processUniqueId", "snapshotKey", "processSnapshotKey");
        var keyLabel = string.IsNullOrWhiteSpace(stableKey) ? $"pid:{evt.ProcessId?.ToString() ?? "-"}" : stableKey;
        var badges = new StringBuilder();
        badges.Append("<span class=\"tree-badges\">");
        badges.Append($"<span class=\"tree-badge\">key {E(keyLabel)}</span>");
        badges.Append($"<span class=\"tree-badge\">children {E(childCount.ToString())}</span>");
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
    private static void AppendProcessRelationshipCards(StringBuilder html, AnalysisReport report)
    {
        var cards = BuildProcessRelationshipCards(report).Take(24).ToList();
        html.AppendLine("<h3 id=\"process-relationship-cards\" class=\"anchor-offset\">Process relationship cards</h3>");
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
            html.AppendLine("</div>");
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
            html.AppendLine($"<details class=\"relationship-details\"><summary>Top evidence</summary><pre class=\"copyable\" data-copy=\"{A(string.Join(Environment.NewLine, card.EvidenceLines))}\">{E(string.Join(Environment.NewLine, card.EvidenceLines))}</pre></details>");
            html.AppendLine("</article>");
        }

        html.AppendLine("</div>");
    }

    /// <summary>
    /// Builds process relationship cards from normalized events.
    /// Inputs are an analysis report; processing groups by stable process key
    /// and computes child/event category counters; returns copyable cards.
    /// </summary>
    private static IReadOnlyList<ProcessRelationshipCard> BuildProcessRelationshipCards(AnalysisReport report)
    {
        var starts = report.Events
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

        return report.Events
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
                var copyText = string.Join(
                    Environment.NewLine,
                    [
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
    private static void AppendNetworkRelationshipCards(StringBuilder html, IReadOnlyCollection<SandboxEvent> networkEvents)
    {
        var cards = BuildNetworkRelationshipCards(networkEvents).Take(24).ToList();
        html.AppendLine("<h3 id=\"network-relationship-cards\" class=\"anchor-offset\">Network relationship cards</h3>");
        if (cards.Count == 0)
        {
            Empty(html, "No network relationship cards could be derived from DNS, HTTP, TLS, PCAP, TCP, or UDP telemetry.");
            return;
        }

        html.AppendLine("<div class=\"section-note\"><strong>Endpoint-centric view.</strong> Network events are grouped by domain, SNI, URL, IP, or endpoint so analysts can read the relationship map without opening raw events first.</div>");
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
            html.AppendLine("</div>");
            html.AppendLine("<div class=\"relationship-tags\">");
            foreach (var process in card.Processes.Take(8))
            {
                html.AppendLine($"<span class=\"chip chip-info copyable\" data-copy=\"{A(process)}\">{E(process)}</span>");
            }

            foreach (var eventType in card.EventTypes.Take(8))
            {
                html.AppendLine($"<span class=\"chip chip-medium copyable\" data-copy=\"{A(eventType)}\">{E(eventType)}</span>");
            }

            html.AppendLine("</div>");
            html.AppendLine("<div class=\"toolbar\">");
            html.AppendLine(CopyButton("Copy network card", card.CopyText));
            html.AppendLine("</div>");
            html.AppendLine($"<details class=\"relationship-details\"><summary>Top evidence</summary><pre class=\"copyable\" data-copy=\"{A(string.Join(Environment.NewLine, card.EvidenceLines))}\">{E(string.Join(Environment.NewLine, card.EvidenceLines))}</pre></details>");
            html.AppendLine("</article>");
        }

        html.AppendLine("</div>");
    }

    /// <summary>
    /// Builds endpoint-centric network relationship cards.
    /// Inputs are network events; processing groups by extracted target and
    /// summarizes protocols/process actors; returns copyable cards.
    /// </summary>
    private static IReadOnlyList<NetworkRelationshipCard> BuildNetworkRelationshipCards(IReadOnlyCollection<SandboxEvent> networkEvents)
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
                var processes = events.Select(ProcessDisplayName).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(value => value, StringComparer.OrdinalIgnoreCase).ToList();
                var eventTypes = events.Select(evt => evt.EventType).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(value => value, StringComparer.OrdinalIgnoreCase).ToList();
                var evidenceLines = events.Take(12).Select(EventOneLine).ToList();
                var copyText = string.Join(
                    Environment.NewLine,
                    [
                        $"target={group.Key}",
                        $"events={events.Count}",
                        $"protocols={string.Join(",", protocols)}",
                        $"firstSeen={first.Timestamp:u}",
                        $"lastSeen={last.Timestamp:u}",
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
                    first.Timestamp.ToString("u"),
                    last.Timestamp.ToString("u"),
                    processes,
                    eventTypes,
                    evidenceLines,
                    copyText);
            })
            .OrderByDescending(card => card.EventCount)
            .ThenBy(card => card.Target, StringComparer.OrdinalIgnoreCase)
            .ToList();
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
        var canonicalKeys = BuildProcessCanonicalKeyLookup(report);
        var eventsByProcess = report.Events
            .Where(evt => evt.ProcessId.HasValue || !string.IsNullOrWhiteSpace(evt.ProcessName) || !string.IsNullOrWhiteSpace(evt.Path))
            .GroupBy(evt => ResolveProcessGroupKey(evt, canonicalKeys), StringComparer.OrdinalIgnoreCase)
            .ToList();
        var processLabels = BuildProcessLabelLookup(report);
        var known = report.Events
            .Where(evt => IsProcessTreeCandidate(evt) && evt.ProcessId.HasValue)
            .SelectMany(ProcessLookupKeys)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var childCounts = report.Events
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
            .Where(IsFileEvent)
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
            .Where(IsRegistryEvent)
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
            .Where(evt => IsProcessTreeCandidate(evt) && evt.ProcessId.HasValue)
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
            .Where(evt => IsProcessTreeCandidate(evt) && evt.ProcessId.HasValue)
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
    /// path/command, then common Data payload keys emitted by Guest/R0/PCAP
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

        if (!string.IsNullOrWhiteSpace(evt.CommandLine))
        {
            return evt.CommandLine!;
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
            evt.EventType.StartsWith("r0collector.driverStatus", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("r0collector.driverPoll", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("r0collector.driverReadEvents", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("r0collector.ioctlFailure", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("r0collector.driverProtocolError", StringComparison.OrdinalIgnoreCase) ||
            EventTextContainsAny(evt, "readiness", "diagnose", "diagnostic", "unavailable"))
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
            "totalEventsDropped",
            "totalEventsBackpressured",
            "backpressureObserved");
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
        html.Append($"<details class=\"event-evidence-fields\" data-copy=\"{A(EventToBoundedPlainText(evt, maxDataPairs: 40, maxValueLength: 300))}\"><summary>Evidence fields</summary>");
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
                    html.Append($"<details class=\"raw-technical-field\"><summary>Hidden technical field summary: {E(field.Label)} ({E(field.Value.Length.ToString())} chars)</summary><pre class=\"copyable\" data-copy=\"{A(copy)}\">{E(copy)}</pre></details>");
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
        foreach (var (english, chinese) in ChineseHtmlTranslations.OrderByDescending(pair => pair.English.Length))
        {
            html = html.Replace(english, chinese, StringComparison.Ordinal);
        }

        return html;
    }

    private static readonly IReadOnlyList<(string English, string Chinese)> ChineseHtmlTranslations =
    [
        ("<html lang=\"en\">", "<html lang=\"zh-CN\">"),
        ("<title>KSword Sandbox Report</title>", "<title>KSword 沙箱分析报告</title>"),
        ("KSword Sandbox Report", "KSword 沙箱分析报告"),
        (" generated at ", " 生成于 "),
        ("Analysis failed", "分析失败"),
        ("No high-risk behavior", "未发现高风险行为"),
        ("High risk", "高风险"),
        ("Suspicious", "可疑行为"),
        ("Table of contents", "目录"),
        ("Cover", "封面"),
        ("Report language", "报告语言"),
        ("English report", "英文报告"),
        ("Default report", "默认报告"),
        ("The WebUI also serves these through /api/jobs/{jobId}/report/html?lang=zh and ?lang=en.", "WebUI 也通过 /api/jobs/{jobId}/report/html?lang=zh 和 ?lang=en 提供这些报告。"),
        ("Quick navigation", "快速导航"),
        ("Sticky subnav", "固定子导航"),
        ("Sticky subnav for Process / Files / Network / R0 / VT / Artifacts quick navigation; counts show currently embedded representative evidence.", "固定子导航用于快速跳转进程 / 文件 / 网络 / R0 / VT / 证据文件；计数表示当前内联的代表性证据。"),
        ("R0 health", "R0 健康状态"),
        ("VT lookups", "VT 查询"),
        ("Risk summary", "风险摘要"),
        ("Behavior detections", "行为命中"),
        ("Static triage", "静态分诊"),
        ("Collection diagnostics", "采集诊断"),
        ("Collection health", "采集健康状态"),
        ("No primary sample behavior rules matched. Static triage and collection diagnostics are separated below so operational health does not inflate the verdict.", "未命中主要样本行为规则。静态分诊和采集诊断已在下方分离展示，避免运行健康状态抬高判定。"),
        ("Static triage indicators", "静态分诊指标"),
        ("Static-only findings are useful triage signals, but they do not by themselves prove runtime malicious behavior.", "仅静态发现可作为有用分诊信号，但本身不能证明运行时恶意行为。"),
        ("Collection and pipeline diagnostics", "采集与流水线诊断"),
        ("Collector health, runbook, import, and timing diagnostics explain evidence quality and are not sample behavior.", "采集器健康、运行手册、导入和时序诊断用于说明证据质量，不属于样本行为。"),
        ("Copy behavior evidence", "复制行为证据"),
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
        ("Behavior graph / IOC summary", "行为图谱 / IOC 摘要"),
        ("Artifact links", "证据文件链接"),
        ("Artifact collection status", "证据采集状态"),
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
        ("No non-health R0 driver telemetry rows were imported. Collection health rows above describe evidence quality rather than sample behavior.", "未导入非健康类 R0 驱动遥测行。上方采集健康行描述证据质量，而不是样本行为。"),
        ("No R0 collection health rows were imported.", "未导入 R0 采集健康行。"),
        ("Failure reasons", "失败原因"),
        ("Raw normalized events", "原始事件"),
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
        ("Guest events JSON", "来宾事件 JSON"),
        ("Driver events JSONL", "驱动事件 JSONL"),
        ("Artifact manifest", "证据清单"),
        ("Raw source artifact", "原始来源证据"),
        ("Raw events are collapsed by default.", "原始事件默认折叠。"),
        ("Raw events shown inline", "原始事件内联显示"),
        ("Open report.json or raw source artifacts for complete evidence.", "打开 report.json 或原始来源证据查看完整证据。"),
        ("Show inline raw events", "显示内联原始事件"),
        ("Raw event distribution", "原始事件分布"),
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
        ("Timeline grouping.", "时间线分组。"),
        ("Grouped by UTC minute with process/type summaries; large buckets show representative events first.", "按 UTC 分钟分组并显示进程/类型摘要；较大的分组优先展示代表性事件。"),
        ("Timeline is capped for readability; open Raw normalized events or report.json for complete evidence.", "时间线为保证可读性已限制数量；打开原始事件或 report.json 查看完整证据。"),
        ("additional timeline events are hidden.", "条额外时间线事件已隐藏。"),
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
        ("Copy artifact", "复制证据文件"),
        ("Copy artifacts", "复制证据文件"),
        ("Copy event", "复制事件"),
        ("Copy process card", "复制进程卡"),
        ("Copy network card", "复制网络卡"),
        ("Copied", "已复制"),
        ("Command line hidden by default", "命令行默认隐藏"),
        ("Command/stdout/stderr/PowerShell fields hidden by default", "command/stdout/stderr/PowerShell 字段默认隐藏"),
        ("Hidden technical field", "隐藏技术字段"),
        ("chars", "字符"),
        ("Process tree", "进程树"),
        ("Process relationship tree.", "进程关系树。"),
        ("Native expandable process tree grouped by stable process key when available, with PID/PPID fallback.", "使用原生可展开进程树；有稳定进程键时按键分组，否则回退到 PID/PPID。"),
        ("Cycle suppressed for stable rendering.", "已抑制循环以保持稳定渲染。"),
        ("Stable relationship map", "稳定关系图"),
        ("Relationship lines:", "关系行："),
        ("Parent:", "父进程："),
        ("Process relationship cards", "进程关系卡"),
        ("Network relationship cards", "网络关系卡"),
        ("No process relationship cards could be derived from normalized telemetry.", "无法从规范化遥测生成进程关系卡。"),
        ("No network relationship cards could be derived from DNS, HTTP, TLS, PCAP, TCP, or UDP telemetry.", "无法从 DNS、HTTP、TLS、PCAP、TCP 或 UDP 遥测生成网络关系卡。"),
        ("No root process was resolved from parent keys; showing earliest/deepest process tree candidates as bounded fallback roots.", "未能从父进程键解析根进程；改为限量显示最早/最深的进程树候选作为回退根节点。"),
        ("Endpoint-centric view.", "端点中心视图。"),
        ("Network events are grouped by domain, SNI, URL, IP, or endpoint so analysts can read the relationship map without opening raw events first.", "网络事件按域名、SNI、URL、IP 或端点分组，分析人员无需先打开原始事件即可阅读关系图。"),
        ("Children:", "子进程："),
        ("Files:", "文件："),
        ("Registry:", "注册表："),
        ("Network:", "网络："),
        ("Events:", "事件："),
        ("Processes:", "进程："),
        ("First seen:", "首次出现："),
        ("Last seen:", "最后出现："),
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
        ("Path / Command", "路径 / 命令"),
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
        ("unknown", "未知")
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
    /// Renders the path/command cell for event tables.
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
    /// Inputs are related descriptors; processing writes safe links and a nested
    /// descriptor evidence block; the method returns trusted local HTML.
    /// </summary>
    private static string RenderRelatedArtifacts(IReadOnlyCollection<ArtifactDescriptor> artifacts)
    {
        if (artifacts.Count == 0)
        {
            return string.Empty;
        }

        var html = new StringBuilder();
        html.AppendLine($"<details><summary>Related artifacts ({artifacts.Count})</summary><ul class=\"artifact-list\">");
        foreach (var artifact in artifacts)
        {
            var plain = ArtifactToPlainText(artifact);
            html.Append("<li>");
            html.Append(RenderArtifactLocation(artifact));
            html.Append($"<br><span class=\"muted\">{E(artifact.Kind.ToString())} / {E(artifact.Category)}</span>");
            html.Append($"<details><summary>Artifact evidence</summary><pre class=\"copyable\" data-copy=\"{A(plain)}\">{E(plain)}</pre></details>");
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
        return $"<details><summary>{E(title)}</summary><pre class=\"copyable\" data-copy=\"{A(preview)}\">{E(preview)}</pre></details>";
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
