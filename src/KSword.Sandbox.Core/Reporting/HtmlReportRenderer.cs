using System.Net;
using System.Text;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Abstractions.Artifacts;
using KSword.Sandbox.Core.Artifacts;

namespace KSword.Sandbox.Core.Reporting;

/// <summary>
/// Renders a local, self-contained HTML report from normalized analysis data.
/// Inputs are report models, processing groups findings and events into a
/// Microstep-style report layout, and the method returns a complete HTML
/// document string.
/// </summary>
public sealed class HtmlReportRenderer
{
    /// <summary>
    /// Converts one AnalysisReport to HTML.
    /// The input is a completed or planned report, processing writes cover,
    /// summary, detection, static, dynamic, network, and failure sections, and
    /// the method returns HTML text.
    /// </summary>
    public string Render(AnalysisReport report)
    {
        return Render(report, []);
    }

    /// <summary>
    /// Converts one AnalysisReport plus optional artifact descriptors to HTML.
    /// Inputs are a report and host/guest artifact index entries; processing
    /// renders artifact links before behavior timelines; the method returns a
    /// complete HTML document string.
    /// </summary>
    public string Render(AnalysisReport report, IEnumerable<ArtifactDescriptor>? artifacts)
    {
        var artifactLinks = BuildReportArtifactList(report, artifacts);
        var html = new StringBuilder();
        html.AppendLine("<!doctype html>");
        html.AppendLine("<html lang=\"en\">");
        AppendHead(html);
        html.AppendLine("<body>");
        AppendCover(html, report);
        AppendTableOfContents(html);
        html.AppendLine("<main>");
        AppendRiskSummary(html, report);
        AppendBehaviorDetections(html, report);
        AppendMitreDetections(html, report);
        AppendRuleHits(html, report);
        AppendStaticAnalysis(html, report);
        AppendDynamicAnalysis(html, report);
        AppendArtifactLinks(html, artifactLinks);
        AppendTimeline(html, report);
        AppendProcessDetails(html, report);
        AppendDroppedFiles(html, report);
        AppendRegistryBehavior(html, report);
        AppendNetworkBehavior(html, report);
        AppendFailureReasons(html, report);
        AppendRawEvents(html, report);
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
        html.AppendLine("body{margin:0;background:#f5f7fb;color:#111827;font-family:Segoe UI,Arial,sans-serif}header{background:linear-gradient(135deg,#101827,#1d4ed8);color:white;padding:32px 42px}main,nav{max-width:1180px;margin:22px auto;padding:0 24px}.card{background:white;border:1px solid #e5e7eb;border-radius:16px;box-shadow:0 10px 30px rgba(15,23,42,.06);margin:18px 0;padding:22px}.grid{display:grid;gap:14px;grid-template-columns:repeat(4,1fr)}.metric{background:#f8fafc;border:1px solid #e2e8f0;border-radius:12px;padding:14px}.metric b{display:block;font-size:26px;margin-top:4px}.muted{color:#64748b}.risk-high{color:#b91c1c}.risk-medium{color:#b45309}.risk-low{color:#047857}.risk-info{color:#1d4ed8}.badge{border-radius:999px;display:inline-block;font-weight:700;padding:6px 12px}.badge-high{background:#fee2e2;color:#991b1b}.badge-medium{background:#fef3c7;color:#92400e}.badge-low{background:#dcfce7;color:#166534}.badge-info{background:#dbeafe;color:#1e40af}table{border-collapse:collapse;width:100%;margin-top:14px}td,th{border-bottom:1px solid #e5e7eb;padding:9px;text-align:left;vertical-align:top}th{color:#475569;font-size:12px;text-transform:uppercase}code{background:#f1f5f9;border-radius:6px;padding:2px 5px;word-break:break-all}.toc a{display:inline-block;margin:4px 14px 4px 0}.empty{border:1px dashed #cbd5e1;border-radius:10px;color:#64748b;padding:14px}.copy-btn{background:#eef2ff;border:1px solid #c7d2fe;border-radius:999px;color:#3730a3;cursor:pointer;font-size:12px;font-weight:700;margin:2px 0;padding:4px 9px}.copyable{cursor:copy}.copy-hint{color:#64748b;font-size:12px;margin-top:8px}.timeline{border-left:3px solid #bfdbfe;margin:14px 0 0 8px;padding-left:18px}.timeline-item{margin:0 0 14px;position:relative}.timeline-item:before{background:#2563eb;border:3px solid #dbeafe;border-radius:999px;content:'';height:11px;left:-25px;position:absolute;top:3px;width:11px}.tree{font-family:Consolas,monospace;line-height:1.5;margin:12px 0}.tree ul{border-left:1px dashed #cbd5e1;list-style:none;margin:0 0 0 18px;padding-left:14px}.tree li{margin:5px 0}.evidence{max-width:520px}.evidence details{background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;padding:8px}.evidence summary{cursor:pointer;font-weight:700}.evidence pre{white-space:pre-wrap;word-break:break-word}.toolbar{display:flex;gap:8px;justify-content:flex-end}@media(max-width:900px){.grid{grid-template-columns:1fr 1fr}table{display:block;overflow-x:auto}}");
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
        html.AppendLine("<header>");
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
    /// Appends fixed report navigation.
    /// Inputs are a StringBuilder, processing writes anchor links matching the
    /// target report structure, and the method returns no value.
    /// </summary>
    private static void AppendTableOfContents(StringBuilder html)
    {
        html.AppendLine("<nav class=\"card toc\"><h2>Table of contents</h2>");
        foreach (var (href, title) in new[]
        {
            ("risk", "Risk summary"),
            ("behavior", "Behavior detections"),
            ("mitre", "Multi-dimensional / MITRE"),
            ("rules", "Engine and rule hits"),
            ("static", "Static analysis"),
            ("dynamic", "Dynamic analysis"),
            ("artifacts", "Artifact links"),
            ("timeline", "Timeline"),
            ("process", "Process details"),
            ("files", "Dropped files"),
            ("registry", "Registry behavior"),
            ("network", "Network behavior"),
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
        Metric(html, "Dropped files", CountEvents(report, "file.created", "file.modified").ToString(), "risk-medium");
        Metric(html, "Network events", CountEvents(report, "network.tcp").ToString(), "risk-medium");
        Metric(html, "Registry events", CountEventsByPrefix(report, "registry.").ToString(), "risk-medium");
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
        AppendStringList(html, "URLs", staticAnalysis.Urls);
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

        html.AppendLine("<table><thead><tr><th>Name</th><th>VA</th><th>Virtual size</th><th>Raw size</th><th>Entropy</th></tr></thead><tbody>");
        foreach (var section in staticAnalysis.Sections)
        {
            html.AppendLine($"<tr><td>{E(section.Name)}</td><td><code>{E(section.VirtualAddress)}</code></td><td>{section.VirtualSize}</td><td>{section.RawDataSize}</td><td>{section.Entropy:F3}</td></tr>");
        }

        html.AppendLine("</tbody></table>");
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
            html.AppendLine($"<li><code>{E(value)}</code></li>");
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
        Metric(html, "Registry events", CountEventsByPrefix(report, "registry.").ToString(), "risk-medium");
        Metric(html, "File events", CountEventsByPrefix(report, "file.").ToString(), "risk-medium");
        Metric(html, "Driver / R0 events", report.Events.Count(e => e.Source.Contains("driver", StringComparison.OrdinalIgnoreCase) || e.Source.Contains("r0", StringComparison.OrdinalIgnoreCase) || e.EventType.StartsWith("driver.", StringComparison.OrdinalIgnoreCase) || e.EventType.StartsWith("r0collector.", StringComparison.OrdinalIgnoreCase)).ToString(), "risk-info");
        Metric(html, "Failure markers", report.Events.Count(IsFailureEvent).ToString(), "risk-high");
        html.AppendLine("</div></section>");
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

        html.AppendLine("<table><thead><tr><th>Category</th><th>Artifact</th><th>Path / safe link</th><th>Size</th><th>SHA-256</th><th>MIME</th></tr></thead><tbody>");
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
    private static void AppendTimeline(StringBuilder html, AnalysisReport report)
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
            html.AppendLine($"<div class=\"timeline-item copyable\" data-copy=\"{A(copy)}\"><strong>{E(evt.Timestamp.ToString("u"))}</strong> <span class=\"badge badge-info\">{E(evt.EventType)}</span><br><span class=\"muted\">{E(evt.ProcessName ?? evt.Source)} {E(evt.Path ?? evt.CommandLine ?? string.Empty)}</span></div>");
        }

        html.AppendLine("</div><div class=\"copy-hint\">Right-click timeline entries, table cells, or evidence blocks to copy their contents.</div></section>");
    }

    /// <summary>
    /// Appends process-related event rows.
    /// Inputs are a report and output builder, processing filters process
    /// events, and the method returns no value.
    /// </summary>
    private static void AppendProcessDetails(StringBuilder html, AnalysisReport report)
    {
        html.AppendLine("<section id=\"process\" class=\"card\"><h2>Process details</h2>");
        AppendProcessTree(html, report);
        AppendEventRows(html, report.Events.Where(e => e.EventType.StartsWith("process.", StringComparison.OrdinalIgnoreCase)).ToList());
        html.AppendLine("</section>");
    }

    /// <summary>
    /// Appends file creation and modification events.
    /// Inputs are a report and output builder, processing filters file events,
    /// and the method returns no value.
    /// </summary>
    private static void AppendDroppedFiles(StringBuilder html, AnalysisReport report)
    {
        AppendEventTable(html, "files", "Dropped files", report.Events.Where(e => e.EventType.StartsWith("file.", StringComparison.OrdinalIgnoreCase)));
    }

    /// <summary>
    /// Appends registry behavior events.
    /// Inputs are a report and output builder, processing filters registry
    /// events, and the method returns no value.
    /// </summary>
    private static void AppendRegistryBehavior(StringBuilder html, AnalysisReport report)
    {
        AppendEventTable(html, "registry", "Registry behavior", report.Events.Where(e => e.EventType.StartsWith("registry.", StringComparison.OrdinalIgnoreCase) || e.EventType.StartsWith("driver.registry", StringComparison.OrdinalIgnoreCase)));
    }

    /// <summary>
    /// Appends network behavior events.
    /// Inputs are a report and output builder, processing filters network
    /// events, and the method returns no value.
    /// </summary>
    private static void AppendNetworkBehavior(StringBuilder html, AnalysisReport report)
    {
        AppendEventTable(html, "network", "Network behavior", report.Events.Where(e => e.EventType.StartsWith("network.", StringComparison.OrdinalIgnoreCase)));
    }

    /// <summary>
    /// Appends explicit failure and timeout information.
    /// Inputs are a report and output builder, processing filters failed status
    /// and timeout/error events, and the method returns no value.
    /// </summary>
    private static void AppendFailureReasons(StringBuilder html, AnalysisReport report)
    {
        var failures = report.Events.Where(IsFailureEvent).ToList();
        html.AppendLine("<section id=\"failure\" class=\"card\"><h2>Failure reasons</h2>");
        if (report.Status != AnalysisStatus.Failed && failures.Count == 0)
        {
            Empty(html, "No failure reason was recorded.");
        }
        else
        {
            AppendEventRows(html, failures);
        }

        html.AppendLine("</section>");
    }

    /// <summary>
    /// Appends all normalized events for auditability.
    /// Inputs are a report and output builder, processing orders events by time,
    /// and the method returns no value.
    /// </summary>
    private static void AppendRawEvents(StringBuilder html, AnalysisReport report)
    {
        AppendEventTable(html, "events", "Raw normalized events", report.Events);
    }

    /// <summary>
    /// Appends a standard event table section.
    /// Inputs are a section id, title, and events, processing renders rows or
    /// an empty-state block, and the method returns no value.
    /// </summary>
    private static void AppendEventTable(StringBuilder html, string id, string title, IEnumerable<SandboxEvent> events)
    {
        html.AppendLine($"<section id=\"{E(id)}\" class=\"card\"><h2>{E(title)}</h2>");
        AppendEventRows(html, events.ToList());
        html.AppendLine("</section>");
    }

    /// <summary>
    /// Appends event rows without opening a section.
    /// Inputs are event records, processing encodes row fields and data, and
    /// the method returns no value.
    /// </summary>
    private static void AppendEventRows(StringBuilder html, IReadOnlyCollection<SandboxEvent> events)
    {
        if (events.Count == 0)
        {
            Empty(html, "No events were collected for this section.");
            return;
        }

        html.AppendLine("<table><thead><tr><th>Time</th><th>Type</th><th>Source</th><th>Process</th><th>Path / Command</th><th>Data</th></tr></thead><tbody>");
        foreach (var evt in events.OrderBy(e => e.Timestamp))
        {
            var plain = EventToPlainText(evt);
            var data = EventDataToText(evt);
            html.AppendLine("<tr>");
            html.AppendLine($"<td class=\"copyable\" data-copy=\"{A(evt.Timestamp.ToString("u"))}\">{E(evt.Timestamp.ToString("u"))}</td>");
            html.AppendLine($"<td class=\"copyable\" data-copy=\"{A(evt.EventType)}\">{E(evt.EventType)}</td>");
            html.AppendLine($"<td class=\"copyable\" data-copy=\"{A(evt.Source)}\">{E(evt.Source)}</td>");
            html.AppendLine($"<td class=\"copyable\" data-copy=\"{A((evt.ProcessName ?? "-") + " (" + (evt.ProcessId?.ToString() ?? "-") + ")")}\">{E(evt.ProcessName ?? "-")} ({E(evt.ProcessId?.ToString() ?? "-")})</td>");
            html.AppendLine($"<td class=\"copyable\" data-copy=\"{A((evt.Path ?? string.Empty) + Environment.NewLine + (evt.CommandLine ?? string.Empty))}\"><code>{E(evt.Path ?? "-")}</code><br><span class=\"muted\">{E(evt.CommandLine ?? string.Empty)}</span></td>");
            html.AppendLine($"<td class=\"evidence\"><div class=\"toolbar\">{CopyButton("Copy event", plain)}</div><details><summary>Evidence fields</summary><pre class=\"copyable\" data-copy=\"{A(data)}\">{E(data)}</pre></details></td>");
            html.AppendLine("</tr>");
        }

        html.AppendLine("</tbody></table>");
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
        html.AppendLine($"<tr><th>{E(label)}</th><td>{E(value)}</td></tr>");
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
        }

        foreach (var droppedPath in Directory.EnumerateFiles(artifactsRoot, "*", SearchOption.AllDirectories)
            .Where(path => !string.Equals(Path.GetFullPath(path), Path.GetFullPath(manifestPath), StringComparison.OrdinalIgnoreCase)))
        {
            AddPathDescriptor(descriptors, droppedPath, reportRoot, ArtifactKind.DroppedFile, "dropped-file");
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

    private static void AddReportArtifact(Dictionary<string, ArtifactDescriptor> artifacts, ArtifactDescriptor artifact)
    {
        if (!IsReportArtifactKind(artifact.Kind))
        {
            return;
        }

        var key = ArtifactKey(artifact);
        if (artifacts.TryGetValue(key, out var existing) &&
            !string.IsNullOrWhiteSpace(existing.SafeLink))
        {
            return;
        }

        artifacts[key] = artifact;
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
            ArtifactKind.DroppedFile => 4,
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
        builder.Append($"sha256={ArtifactSha256(artifact)}");
        return builder.ToString();
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
      navigator.clipboard.writeText(value);
      return;
    }
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
    var target = event.target.closest('[data-copy]');
    if (!target) { return; }
    event.preventDefault();
    copyText(target.getAttribute('data-copy') || target.textContent || '');
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
