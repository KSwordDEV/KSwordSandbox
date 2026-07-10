using System.Net;
using System.Text;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Core.Reporting;

/// <summary>
/// Renders a local, self-contained HTML report from normalized analysis data.
/// Inputs are report models, processing HTML-encodes every dynamic value, and
/// the method returns a complete HTML document string.
/// </summary>
public sealed class HtmlReportRenderer
{
    /// <summary>
    /// Converts one AnalysisReport to HTML.
    /// The input is a completed or planned report, processing writes sections
    /// for summary, findings, and events, and the method returns HTML text.
    /// </summary>
    public string Render(AnalysisReport report)
    {
        var html = new StringBuilder();
        html.AppendLine("<!doctype html>");
        html.AppendLine("<html lang=\"en\"><head><meta charset=\"utf-8\"><title>KSword Sandbox Report</title>");
        html.AppendLine("<style>body{font-family:Segoe UI,Arial,sans-serif;margin:32px;color:#1f2937}table{border-collapse:collapse;width:100%;margin:16px 0}td,th{border:1px solid #d1d5db;padding:8px;text-align:left}th{background:#f3f4f6}.sev-high{color:#b91c1c}.sev-medium{color:#b45309}.sev-low{color:#047857}.muted{color:#6b7280}code{background:#f3f4f6;padding:2px 4px}</style>");
        html.AppendLine("</head><body>");
        html.AppendLine("<h1>KSword Sandbox Report</h1>");
        html.AppendLine($"<p class=\"muted\">Job {E(report.JobId.ToString())} generated at {E(report.GeneratedAt.ToString("u"))}</p>");
        AppendSummary(html, report);
        AppendFindings(html, report);
        AppendEvents(html, report);
        html.AppendLine("</body></html>");
        return html.ToString();
    }

    /// <summary>
    /// Appends the report summary table.
    /// Inputs are a StringBuilder and report, processing writes static rows
    /// with encoded data, and the method returns no value.
    /// </summary>
    private static void AppendSummary(StringBuilder html, AnalysisReport report)
    {
        html.AppendLine("<h2>Summary</h2><table><tbody>");
        Row(html, "Sample", report.Sample.FileName);
        Row(html, "SHA-256", report.Sample.Sha256);
        Row(html, "Size", report.Sample.SizeBytes.ToString());
        Row(html, "Status", report.Status.ToString());
        Row(html, "Events", report.Events.Count.ToString());
        Row(html, "Findings", report.Findings.Count.ToString());
        html.AppendLine("</tbody></table>");
    }

    /// <summary>
    /// Appends behavior findings and MITRE mapping.
    /// Inputs are a StringBuilder and report, processing writes one row per
    /// finding, and the method returns no value.
    /// </summary>
    private static void AppendFindings(StringBuilder html, AnalysisReport report)
    {
        html.AppendLine("<h2>Behavior Findings</h2>");
        html.AppendLine("<table><thead><tr><th>Severity</th><th>Rule</th><th>MITRE</th><th>Evidence</th></tr></thead><tbody>");
        foreach (var finding in report.Findings)
        {
            var severityClass = "sev-" + finding.Severity.ToLowerInvariant();
            var mitre = string.IsNullOrWhiteSpace(finding.MitreTechniqueId)
                ? "-"
                : $"{finding.MitreTechniqueId} {finding.MitreTechniqueName}".Trim();
            html.AppendLine($"<tr><td class=\"{E(severityClass)}\">{E(finding.Severity)}</td><td><strong>{E(finding.Title)}</strong><br>{E(finding.Summary)}</td><td>{E(mitre)}</td><td>{finding.Evidence.Count}</td></tr>");
        }

        if (report.Findings.Count == 0)
        {
            html.AppendLine("<tr><td colspan=\"4\">No behavior rules matched.</td></tr>");
        }

        html.AppendLine("</tbody></table>");
    }

    /// <summary>
    /// Appends the normalized event table.
    /// Inputs are a StringBuilder and report, processing writes one row per
    /// event, and the method returns no value.
    /// </summary>
    private static void AppendEvents(StringBuilder html, AnalysisReport report)
    {
        html.AppendLine("<h2>Normalized Events</h2>");
        html.AppendLine("<table><thead><tr><th>Time</th><th>Type</th><th>Process</th><th>Path</th><th>Command</th></tr></thead><tbody>");
        foreach (var evt in report.Events.OrderBy(evt => evt.Timestamp))
        {
            html.AppendLine($"<tr><td>{E(evt.Timestamp.ToString("u"))}</td><td>{E(evt.EventType)}</td><td>{E(evt.ProcessName ?? "-")} ({E(evt.ProcessId?.ToString() ?? "-")})</td><td>{E(evt.Path ?? "-")}</td><td><code>{E(evt.CommandLine ?? "-")}</code></td></tr>");
        }

        if (report.Events.Count == 0)
        {
            html.AppendLine("<tr><td colspan=\"5\">No events were collected.</td></tr>");
        }

        html.AppendLine("</tbody></table>");
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
    /// Encodes dynamic text for safe HTML output.
    /// The input is arbitrary text, processing applies WebUtility.HtmlEncode,
    /// and the method returns encoded text.
    /// </summary>
    private static string E(string value)
    {
        return WebUtility.HtmlEncode(value);
    }
}
