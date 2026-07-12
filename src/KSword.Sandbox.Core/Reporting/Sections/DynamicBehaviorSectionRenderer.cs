using System.Net;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Core.Reporting.Sections;

/// <summary>
/// Renders a simple bilingual dynamic-behavior event summary.
/// Inputs are AnalysisReport events and metrics; processing groups the bounded
/// inline report events and surfaces raw/sampled counts; Render returns an HTML
/// fragment with event-type counts that are explicitly labelled as sampled.
/// </summary>
public sealed class DynamicBehaviorSectionRenderer : IReportSectionRenderer
{
    public string SectionId => "dynamic-summary";

    public string Title => "动态行为摘要 / Dynamic behavior summary";

    /// <inheritdoc />
    public string Render(AnalysisReport report)
    {
        var rawCount = Metric(report, "rawEvents", report.Events.Count);
        var inlineCount = Metric(report, "reportEvents", report.Events.Count);
        var omittedCount = Metric(report, "omittedReportEvents", 0);
        var rows = string.Join(
            string.Empty,
            report.Events
                .GroupBy(evt => evt.EventType)
                .OrderBy(group => group.Key)
                .Select(group => $"<tr><td>{WebUtility.HtmlEncode(group.Key)}</td><td>{group.Count()}</td></tr>"));
        return $"<section id=\"dynamic-summary\"><h2>动态行为摘要 / Dynamic behavior summary</h2><p>下表统计的是报告内联采样事件，不是完整 raw event 总数。/ Counts below are sampled inline report events, not the full raw event total. Raw={rawCount}, inline={inlineCount}, omitted={omittedCount}.</p><table><thead><tr><th>事件类型 / Event type</th><th>内联采样数量 / Sampled inline count</th></tr></thead><tbody>{rows}</tbody></table></section>";
    }

    private static int Metric(AnalysisReport report, string key, int fallback)
    {
        return report.Metrics.TryGetValue(key, out var value) ? value : fallback;
    }
}
