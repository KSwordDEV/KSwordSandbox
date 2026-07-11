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
    private const int RawEventInlineLimit = 200;

    private sealed record BehaviorGraphEdge(string From, string Relation, string To, string Evidence);

    private sealed record ProcessGraphNode(string Label, string Detail, string CopyText);

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
        html.AppendLine("<main>");
        AppendRiskSummary(html, report);
        AppendBehaviorDetections(html, report);
        AppendMitreDetections(html, report);
        AppendRuleHits(html, report);
        AppendStaticAnalysis(html, report);
        AppendDynamicAnalysis(html, report);
        AppendBehaviorGraph(html, report, artifactLookup, artifactLinks);
        AppendArtifactLinks(html, artifactLinks);
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
main,nav{max-width:1280px;margin:24px auto;padding:0 24px}.card{background:rgba(255,255,255,.94);border:1px solid var(--line);border-radius:22px;box-shadow:0 18px 48px rgba(15,23,42,.08);margin:22px 0;padding:24px;position:relative}
section.card{max-height:75vh;overflow:auto;scrollbar-color:var(--primary) #eaf4ff;scrollbar-width:thin}.card:before{background:linear-gradient(180deg,var(--primary),rgba(67,160,255,0));border-radius:22px 0 0 22px;content:'';height:100%;left:0;opacity:.9;position:absolute;top:0;width:4px}
.language-entry{align-items:center;display:flex;flex-wrap:wrap;gap:10px}.language-entry strong{color:#075985}.language-entry .hint{color:var(--muted);font-size:13px}.language-entry a{background:var(--primary);border-radius:999px;color:white;font-weight:800;padding:8px 12px;text-decoration:none}.language-entry a.secondary{background:#334155}.language-entry a:hover{box-shadow:0 0 0 4px rgba(67,160,255,.14)}
.card h2{align-items:center;display:flex;gap:10px;margin:0 0 14px}.card h2:before{background:var(--primary);box-shadow:0 0 0 6px rgba(67,160,255,.14);border-radius:999px;content:'';display:inline-block;height:12px;width:12px}
.grid{display:grid;gap:14px;grid-template-columns:repeat(auto-fit,minmax(170px,1fr))}.metric{background:linear-gradient(180deg,#fff,#f7fbff);border:1px solid var(--line);border-top:3px solid var(--primary);border-radius:16px;padding:15px}.metric b{display:block;font-size:26px;margin-top:4px}
.muted{color:var(--muted)}.risk-high{color:#b91c1c}.risk-medium{color:#b45309}.risk-low{color:#047857}.risk-info{color:var(--primary-deep)}
.badge,.chip{border-radius:999px;display:inline-block;font-weight:700;padding:6px 12px}.chip{font-size:12px;margin:2px 4px 2px 0;padding:3px 8px}
.badge-high,.chip-high{background:#fee2e2;color:#991b1b}.badge-medium,.chip-medium{background:#fef3c7;color:#92400e}.badge-low,.chip-low{background:#dcfce7;color:#166534}.badge-info,.chip-info{background:var(--primary-soft);color:#075985}
.section-note{background:#f7fbff;border-left:4px solid var(--primary);border-radius:10px;color:#475569;margin:10px 0;padding:11px 13px}
table{border-collapse:separate;border-spacing:0;width:100%;margin-top:14px}td,th{border-bottom:1px solid #e5edf6;padding:10px;text-align:left;vertical-align:top}th{background:rgba(248,251,255,.96);color:#475569;font-size:12px;position:sticky;text-transform:uppercase;top:0;z-index:1}
code{background:#f1f7ff;border-radius:6px;padding:2px 5px;word-break:break-all}.toc a{background:#f7fbff;border:1px solid var(--line);border-radius:999px;color:#075985;display:inline-block;font-weight:700;margin:4px 8px 4px 0;padding:7px 12px;text-decoration:none}.toc a:hover{border-color:var(--primary);box-shadow:0 0 0 4px rgba(67,160,255,.14)}
.empty{background:linear-gradient(180deg,#fff,#f7fbff);border:1px dashed #b9d7f3;border-radius:12px;color:var(--muted);padding:14px}
.copy-btn{background:rgba(67,160,255,.12);border:1px solid rgba(67,160,255,.45);border-radius:999px;color:#075985;cursor:pointer;font-size:12px;font-weight:700;margin:2px 0;padding:5px 10px}.copyable{cursor:copy}.copy-hint{color:var(--muted);font-size:12px;margin-top:8px}
.event-table td:first-child{white-space:nowrap}.event-table td:nth-child(2){min-width:140px}.event-table td:nth-child(4){min-width:140px}.event-table td:nth-child(5){min-width:260px}.event-table .evidence{min-width:280px}
.timeline{border-left:3px solid rgba(67,160,255,.45);margin:14px 0 0 8px;padding-left:18px}.timeline-item{background:#f9fcff;border:1px solid var(--line);border-radius:12px;margin:0 0 12px;padding:10px 12px;position:relative}.timeline-item:before{background:var(--primary);border:3px solid var(--primary-soft);border-radius:999px;content:'';height:11px;left:-26px;position:absolute;top:13px;width:11px}
.graph-map{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));margin-top:12px}.graph-node{background:#f8fbff;border:1px solid var(--line);border-left:4px solid var(--primary);border-radius:14px;padding:12px}.graph-node strong{display:block;margin-bottom:4px}.graph-node small{color:var(--muted);display:block;line-height:1.4}.edge-table td:nth-child(1),.edge-table td:nth-child(3){min-width:170px}.ioc-grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));margin-top:14px}.ioc-card{background:#ffffff;border:1px solid var(--line);border-radius:14px;padding:12px}.ioc-card h3{font-size:15px;margin:0 0 8px}.ioc-card ul{margin:0;padding-left:18px}.ioc-card li{margin:5px 0;word-break:break-word}
.tree{font-family:Consolas,monospace;line-height:1.5;margin:12px 0}.tree ul{border-left:1px dashed #b9d7f3;list-style:none;margin:0 0 0 18px;padding-left:14px}.tree li{margin:5px 0}
.evidence{max-width:560px}.evidence details{background:#f7fbff;border:1px solid var(--line);border-radius:12px;padding:8px}.evidence summary{cursor:pointer;font-weight:700}.evidence pre{white-space:pre-wrap;word-break:break-word}
.toolbar{display:flex;gap:8px;justify-content:flex-end}.columns{display:grid;gap:14px;grid-template-columns:1fr 1fr}.compact-list{margin:8px 0 0 0;padding-left:18px}.compact-list li{margin:4px 0}
.artifact-ref{font-weight:700}.artifact-list{list-style:none;margin:8px 0 0 0;padding:0}.artifact-list li{border-top:1px solid #e2e8f0;margin-top:8px;padding-top:8px}.artifact-preview img{border:1px solid #cbd5e1;border-radius:10px;max-height:260px;max-width:100%}
.raw-events-shell{background:#f9fcff;border:1px solid var(--line);border-radius:16px;margin-top:14px;overflow:hidden}.raw-events-shell>summary{cursor:pointer;font-weight:800;list-style:none;padding:12px 14px}.raw-events-shell>summary::-webkit-details-marker{display:none}.raw-events-shell>summary:before{color:var(--primary-deep);content:'▶';display:inline-block;margin-right:8px}.raw-events-shell[open]>summary:before{content:'▼'}.raw-events-panel{border-top:1px solid var(--line);max-height:58vh;overflow:auto;padding:0 12px 12px}.raw-source-hints{background:#f8fbff;border:1px solid var(--line);border-radius:14px;margin-top:12px;padding:12px}.raw-source-hints ul{list-style:none;margin:8px 0 0 0;padding:0}.raw-source-hints li{border-top:1px solid #e2e8f0;margin-top:8px;padding-top:8px}.raw-source-hints li:first-child{border-top:0;margin-top:0;padding-top:0}.raw-source-hints .hint-label{font-weight:800}
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
            ("graph", "Behavior graph / IOC summary"),
            ("artifacts", "Artifact links"),
            ("timeline", "Timeline"),
            ("process", "Process details"),
            ("files", "Dropped files"),
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
    /// Appends high-level metrics similar to cloud sandbox summary cards.
    /// Inputs are a report, processing counts findings, MITRE hits, and event
    /// classes, and the method returns no value.
    /// </summary>
    private static void AppendRiskSummary(StringBuilder html, AnalysisReport report)
    {
        html.AppendLine("<section id=\"risk\" class=\"card\"><h2>Risk summary</h2><div class=\"grid\">");
        Metric(html, "High risk", CountSeverity(report, "high").ToString(), "risk-high");
        Metric(html, "Suspicious", CountSeverity(report, "medium").ToString(), "risk-medium");
        Metric(html, "General / info", (CountSeverity(report, "low") + CountSeverity(report, "info")).ToString(), "risk-info");
        Metric(html, "MITRE techniques", report.Findings.Where(f => !string.IsNullOrWhiteSpace(f.MitreTechniqueId)).Select(f => f.MitreTechniqueId).Distinct().Count().ToString(), "risk-low");
        Metric(html, "Events", report.Events.Count.ToString(), "risk-info");
        Metric(html, "Rule hits", report.Findings.Count.ToString(), "risk-info");
        Metric(html, "Static tags", (report.StaticAnalysis?.Tags.Count ?? 0).ToString(), "risk-info");
        Metric(html, "Static URLs", (report.StaticAnalysis?.Urls.Count ?? 0).ToString(), "risk-medium");
        Metric(html, "Dropped files", report.Events.Count(IsFileEvent).ToString(), "risk-medium");
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
        var findings = report.Findings.OrderBy(f => SeverityRank(f.Severity)).ThenBy(f => f.Title).ToList();
        if (findings.Count == 0)
        {
            Empty(html, "No behavior rules matched.");
        }
        else
        {
            html.AppendLine("<table><thead><tr><th>Severity</th><th>Behavior</th><th>Evidence</th></tr></thead><tbody>");
            foreach (var finding in findings)
            {
                html.AppendLine($"<tr><td class=\"risk-{E(NormalizeSeverity(finding.Severity))}\">{E(finding.Severity)}</td><td><strong>{E(finding.Title)}</strong><br><span class=\"muted\">{E(finding.Summary)}</span></td><td>{finding.Evidence.Count}</td></tr>");
            }

            html.AppendLine("</tbody></table>");
        }

        html.AppendLine("</section>");
    }

    /// <summary>
    /// Appends ATT&CK mapping rows for findings with technique metadata.
    /// Inputs are a report and output builder, processing groups findings by
    /// MITRE technique, and the method returns no value.
    /// </summary>
    private static void AppendMitreDetections(StringBuilder html, AnalysisReport report)
    {
        html.AppendLine("<section id=\"mitre\" class=\"card\"><h2>Multi-dimensional / MITRE detections</h2>");
        var groups = report.Findings
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

        html.AppendLine("<ul>");
        foreach (var value in values)
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
        Metric(html, "Failure markers", report.Events.Count(IsFailureEvent).ToString(), "risk-high");
        html.AppendLine("</div></section>");
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
    /// Appends host-safe artifact links and paths.
    /// Inputs are normalized artifact descriptors; processing renders links for
    /// safe relative paths and plain text for guest-local or unsafe paths; the
    /// method returns no value.
    /// </summary>
    private static void AppendArtifactLinks(StringBuilder html, IReadOnlyCollection<ArtifactDescriptor> artifacts)
    {
        html.AppendLine("<section id=\"artifacts\" class=\"card\"><h2>Artifact links</h2>");
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
            .Take(80)
            .ToList();
        if (events.Count == 0)
        {
            Empty(html, "No timeline events were collected.");
            html.AppendLine("</section>");
            return;
        }

        html.AppendLine("<div class=\"timeline\">");
        foreach (var evt in events)
        {
            var copy = EventToPlainText(evt);
            var relatedArtifacts = FindRelatedArtifacts(evt, artifactLookup, artifacts);
            html.AppendLine($"<div class=\"timeline-item copyable\" data-copy=\"{A(copy)}\"><strong>{E(evt.Timestamp.ToString("u"))}</strong> <span class=\"badge badge-info\">{E(evt.EventType)}</span><br><span class=\"muted\">{E(evt.ProcessName ?? evt.Source)} {RenderInlineEventLocation(evt, relatedArtifacts)}</span></div>");
        }

        html.AppendLine("</div><div class=\"copy-hint\">Right-click timeline entries, table cells, or evidence blocks to copy their contents.</div></section>");
    }

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
        AppendEventTable(html, "files", "Dropped files", report.Events.Where(IsFileEvent), artifactLookup, artifacts);
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
        AppendEventTable(html, "network", "Network behavior", report.Events.Where(IsNetworkEvent), artifactLookup, artifacts);
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
        html.AppendLine("<section id=\"r0\" class=\"card\"><h2>R0 / driver events</h2>");
        if (r0Events.Count == 0)
        {
            Empty(html, "No R0Collector or driver-originated events were imported.");
            html.AppendLine("</section>");
            return;
        }

        html.AppendLine("<div class=\"grid\">");
        Metric(html, "Collector lifecycle", r0Events.Count(e => e.EventType.StartsWith("r0collector.", StringComparison.OrdinalIgnoreCase)).ToString(), "risk-info");
        Metric(html, "Driver payloads", r0Events.Count(e => e.EventType.StartsWith("driver.", StringComparison.OrdinalIgnoreCase) || e.Source.Contains("driver", StringComparison.OrdinalIgnoreCase)).ToString(), "risk-info");
        Metric(html, "Kernel file rows", r0Events.Count(IsFileEvent).ToString(), "risk-medium");
        Metric(html, "Kernel registry rows", r0Events.Count(IsRegistryEvent).ToString(), "risk-medium");
        Metric(html, "Kernel network rows", r0Events.Count(IsNetworkEvent).ToString(), "risk-medium");
        Metric(html, "R0 failures", r0Events.Count(IsFailureEvent).ToString(), "risk-high");
        html.AppendLine("</div>");
        AppendEventRows(html, r0Events, artifactLookup, artifacts);
        html.AppendLine("</section>");
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
        var failures = report.Events.Where(IsFailureEvent).ToList();
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
        Metric(html, "Hidden raw events", hiddenCount.ToString(), hiddenCount > 0 ? "risk-medium" : "risk-info");
        html.AppendLine("</div>");
        html.AppendLine($"<div class=\"section-note\"><strong>Raw events are collapsed by default.</strong> Raw events shown inline: {inlineEvents.Count}/{orderedEvents.Count}. Hidden raw events: {hiddenCount}. Open report.json or raw source artifacts for complete evidence.</div>");
        AppendRawSourceHints(html, report, artifacts);

        if (orderedEvents.Count == 0)
        {
            Empty(html, "No events were collected for this section.");
        }
        else
        {
            html.AppendLine($"<details class=\"raw-events-shell\"><summary>Show inline raw events ({inlineEvents.Count}/{orderedEvents.Count}; {hiddenCount} hidden)</summary>");
            html.AppendLine("<div class=\"raw-events-panel\">");
            AppendEventRows(html, inlineEvents, artifactLookup, artifacts);
            html.AppendLine("</div>");
            html.AppendLine("</details>");
        }

        html.AppendLine("</section>");
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

        html.AppendLine("<table class=\"event-table\"><thead><tr><th>Time</th><th>Type</th><th>Source</th><th>Process</th><th>Path / Command</th><th>Data</th></tr></thead><tbody>");
        foreach (var evt in events.OrderBy(e => e.Timestamp))
        {
            var plain = EventToPlainText(evt);
            var data = EventDataToText(evt);
            var relatedArtifacts = FindRelatedArtifacts(evt, artifactLookup, artifacts);
            html.AppendLine("<tr>");
            html.AppendLine($"<td class=\"copyable\" data-copy=\"{A(evt.Timestamp.ToString("u"))}\">{E(evt.Timestamp.ToString("u"))}</td>");
            html.AppendLine($"<td class=\"copyable\" data-copy=\"{A(evt.EventType)}\">{E(evt.EventType)}</td>");
            html.AppendLine($"<td class=\"copyable\" data-copy=\"{A(evt.Source)}\">{E(evt.Source)}</td>");
            html.AppendLine($"<td class=\"copyable\" data-copy=\"{A((evt.ProcessName ?? "-") + " (" + (evt.ProcessId?.ToString() ?? "-") + ")")}\">{E(evt.ProcessName ?? "-")} ({E(evt.ProcessId?.ToString() ?? "-")})</td>");
            html.AppendLine($"<td class=\"copyable\" data-copy=\"{A((evt.Path ?? string.Empty) + Environment.NewLine + (evt.CommandLine ?? string.Empty))}\">{RenderEventPathAndCommand(evt, relatedArtifacts)}</td>");
            html.AppendLine($"<td class=\"evidence\"><div class=\"toolbar\">{CopyButton("Copy event", plain)}{RenderCopyArtifactsButton(relatedArtifacts)}</div><details><summary>Evidence fields</summary><pre class=\"copyable\" data-copy=\"{A(data)}\">{E(data)}</pre></details>{RenderRelatedArtifacts(relatedArtifacts)}</td>");
            html.AppendLine("</tr>");
        }

        html.AppendLine("</tbody></table>");
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
                    string.IsNullOrWhiteSpace(artifact.SafeLink) ? null : artifact.SafeLink,
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
            html.Append($"<a href=\"{A(link)}\">{E(display)}</a>");
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
    /// Appends a lightweight process tree from process.start events.
    /// Inputs are normalized process events, processing groups by PID/PPID, and
    /// the method returns no value.
    /// </summary>
    private static void AppendProcessTree(StringBuilder html, AnalysisReport report)
    {
        var starts = report.Events
            .Where(e => string.Equals(e.EventType, "process.start", StringComparison.OrdinalIgnoreCase) && e.ProcessId.HasValue)
            .GroupBy(e => e.ProcessId!.Value)
            .Select(g => g.OrderBy(e => e.Timestamp).First())
            .OrderBy(e => e.Timestamp)
            .ToList();
        if (starts.Count == 0)
        {
            Empty(html, "No process start events were available to build a process tree.");
            return;
        }

        var children = starts
            .Where(e => e.ParentProcessId.HasValue)
            .GroupBy(e => e.ParentProcessId!.Value)
            .ToDictionary(g => g.Key, g => g.ToList());
        var known = starts.Select(e => e.ProcessId!.Value).ToHashSet();
        var roots = starts
            .Where(e => !e.ParentProcessId.HasValue || !known.Contains(e.ParentProcessId.Value))
            .ToList();

        html.AppendLine("<h3>Process tree</h3><div class=\"tree\"><ul>");
        foreach (var root in roots)
        {
            AppendProcessTreeNode(html, root, children, new HashSet<int>());
        }

        html.AppendLine("</ul></div>");
    }

    /// <summary>
    /// Appends one process tree node recursively.
    /// Inputs are a process event, child lookup, and visited set; processing
    /// prevents cycles; the method returns no value.
    /// </summary>
    private static void AppendProcessTreeNode(StringBuilder html, SandboxEvent evt, IReadOnlyDictionary<int, List<SandboxEvent>> children, HashSet<int> visited)
    {
        var processId = evt.ProcessId ?? -1;
        var label = $"{evt.ProcessName ?? "process"} pid={processId} ppid={evt.ParentProcessId?.ToString() ?? "-"} {evt.Path ?? evt.CommandLine ?? string.Empty}".Trim();
        html.AppendLine($"<li class=\"copyable\" data-copy=\"{A(EventToPlainText(evt))}\"><code>{E(label)}</code>");
        if (processId >= 0 && visited.Add(processId) && children.TryGetValue(processId, out var childEvents))
        {
            html.AppendLine("<ul>");
            foreach (var child in childEvents.OrderBy(e => e.Timestamp))
            {
                AppendProcessTreeNode(html, child, children, visited);
            }

            html.AppendLine("</ul>");
        }

        html.AppendLine("</li>");
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
        var eventsByProcess = report.Events
            .Where(evt => evt.ProcessId.HasValue || !string.IsNullOrWhiteSpace(evt.ProcessName) || !string.IsNullOrWhiteSpace(evt.Path))
            .GroupBy(ProcessIdentityKey, StringComparer.OrdinalIgnoreCase)
            .ToList();
        var childCounts = report.Events
            .Where(evt => evt.ProcessId.HasValue && evt.ParentProcessId.HasValue)
            .GroupBy(evt => evt.ParentProcessId!.Value)
            .ToDictionary(group => group.Key, group => group.Select(evt => evt.ProcessId!.Value).Distinct().Count());

        return eventsByProcess
            .Select(group =>
            {
                var first = group.OrderBy(evt => evt.Timestamp).First();
                var label = ProcessGraphLabel(first);
                var childCount = first.ProcessId.HasValue && childCounts.TryGetValue(first.ProcessId.Value, out var children)
                    ? children
                    : 0;
                var detail = $"pid={first.ProcessId?.ToString() ?? "-"} ppid={first.ParentProcessId?.ToString() ?? "-"} events={group.Count()} children={childCount} firstSeen={first.Timestamp:u}";
                return new ProcessGraphNode(
                    label,
                    detail,
                    string.Join(Environment.NewLine, [$"process={label}", detail, $"path={first.Path ?? "-"}", $"commandLine={first.CommandLine ?? "-"}"]));
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
        foreach (var evt in report.Events.OrderBy(evt => evt.Timestamp))
        {
            var from = EventProcessActor(evt);
            if (string.Equals(evt.EventType, "process.start", StringComparison.OrdinalIgnoreCase) && evt.ProcessId.HasValue)
            {
                var parent = evt.ParentProcessId.HasValue ? $"pid:{evt.ParentProcessId.Value}" : from;
                edges.Add(new BehaviorGraphEdge(parent, "spawn", ProcessGraphLabel(evt), EventToPlainText(evt)));
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
        if (evt.ProcessId.HasValue)
        {
            return $"pid:{evt.ProcessId.Value}";
        }

        if (!string.IsNullOrWhiteSpace(evt.ProcessName))
        {
            return $"name:{evt.ProcessName}";
        }

        return $"path:{evt.Path ?? evt.Source}";
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
        return report.Findings.Count(f => string.Equals(f.Severity, severity, StringComparison.OrdinalIgnoreCase));
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

        if (CountSeverity(report, "high") > 0)
        {
            return ("High risk", "high");
        }

        if (CountSeverity(report, "medium") > 0)
        {
            return ("Suspicious", "medium");
        }

        return ("No high-risk behavior", "info");
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
        ("Risk summary", "风险摘要"),
        ("Behavior detections", "行为命中"),
        ("Multi-dimensional / MITRE detections", "多维 / MITRE 检测"),
        ("Multi-dimensional / MITRE", "多维 / MITRE"),
        ("Engine and rule hits", "引擎和规则命中"),
        ("Static analysis", "静态分析"),
        ("Dynamic analysis", "动态分析"),
        ("Behavior graph / IOC summary", "行为图谱 / IOC 摘要"),
        ("Artifact links", "证据文件链接"),
        ("Timeline", "时间线"),
        ("Process details", "进程详情"),
        ("Dropped files", "落地文件"),
        ("Registry behavior", "注册表行为"),
        ("Network behavior", "网络行为"),
        ("R0 / driver events", "R0 / 驱动事件"),
        ("Failure reasons", "失败原因"),
        ("Raw normalized events", "原始事件"),
        ("Total events", "事件总数"),
        ("Inline rendered", "内联渲染"),
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
        ("Screenshot preview", "截图预览"),
        ("Driver JSONL preview", "驱动 JSONL 预览"),
        ("Manifest preview", "清单预览"),
        ("Events JSON preview", "事件 JSON 预览"),
        ("Text preview", "文本预览"),
        ("Copy artifact", "复制证据文件"),
        ("Copy artifacts", "复制证据文件"),
        ("Copy event", "复制事件"),
        ("Copied", "已复制"),
        ("Process tree", "进程树"),
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

        var link = relatedArtifacts.FirstOrDefault(artifact => !string.IsNullOrWhiteSpace(artifact.SafeLink));
        if (link is null)
        {
            return E(label);
        }

        return $"{E(label)} <a class=\"artifact-ref\" href=\"{A(link.SafeLink)}\">artifact: {E(ArtifactDisplayName(link))}</a>";
    }

    /// <summary>
    /// Renders the path/command cell for event tables.
    /// Inputs are one event and related artifacts; processing adds report-local
    /// anchors for dropped files, screenshots, driver JSONL, and manifests.
    /// </summary>
    private static string RenderEventPathAndCommand(SandboxEvent evt, IReadOnlyCollection<ArtifactDescriptor> relatedArtifacts)
    {
        var path = string.IsNullOrWhiteSpace(evt.Path) ? "-" : evt.Path;
        var html = new StringBuilder();
        html.Append($"<code>{E(path)}</code>");

        var links = relatedArtifacts
            .Where(artifact => !string.IsNullOrWhiteSpace(artifact.SafeLink))
            .Take(4)
            .ToList();
        foreach (var artifact in links)
        {
            html.Append($"<br><a class=\"artifact-ref\" href=\"{A(artifact.SafeLink)}\">Open {E(ArtifactDisplayName(artifact))}</a>");
        }

        if (!string.IsNullOrWhiteSpace(evt.CommandLine))
        {
            html.Append($"<br><span class=\"muted\">{E(evt.CommandLine)}</span>");
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
            : artifact.FullPath;
        if (!string.IsNullOrWhiteSpace(artifact.SafeLink))
        {
            var fullPath = string.IsNullOrWhiteSpace(artifact.FullPath)
                ? string.Empty
                : $"<br><code>{E(artifact.FullPath)}</code>";
            return $"<a href=\"{A(artifact.SafeLink)}\">{E(displayPath)}</a>{fullPath}";
        }

        return $"<code>{E(string.IsNullOrWhiteSpace(displayPath) ? "-" : displayPath)}</code>";
    }

    private static string RenderArtifactPreview(ArtifactDescriptor artifact)
    {
        if (artifact.Kind == ArtifactKind.Screenshot && !string.IsNullOrWhiteSpace(artifact.SafeLink))
        {
            return $"<details class=\"artifact-preview\"><summary>Screenshot preview</summary><a href=\"{A(artifact.SafeLink)}\"><img alt=\"{A(artifact.Name)}\" src=\"{A(artifact.SafeLink)}\"></a></details>";
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
