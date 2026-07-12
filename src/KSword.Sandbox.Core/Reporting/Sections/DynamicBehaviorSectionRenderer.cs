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
        var eventGroups = report.Events
            .GroupBy(evt => evt.EventType)
            .OrderBy(group => group.Key)
            .ToList();
        var rows = eventGroups.Count == 0
            ? "<tr><td colspan=\"2\">未采集到内联事件；0 计数表示本节没有导入遥测，不代表样本没有行为。</td></tr>"
            : string.Join(
                string.Empty,
                eventGroups.Select(group => $"<tr><td>{WebUtility.HtmlEncode(group.Key)}</td><td>{group.Count()}</td></tr>"));
        return $"<section id=\"dynamic-summary\"><h2>动态行为摘要</h2><p>下表统计的是报告内联采样事件，不是完整 raw event 总数。Raw={rawCount}, inline={inlineCount}, omitted={omittedCount}.</p><table><thead><tr><th>事件类型</th><th>内联采样数量</th></tr></thead><tbody>{rows}</tbody></table></section>";
    }

    private static int Metric(AnalysisReport report, string key, int fallback)
    {
        return report.Metrics.TryGetValue(key, out var value) ? value : fallback;
    }
}
