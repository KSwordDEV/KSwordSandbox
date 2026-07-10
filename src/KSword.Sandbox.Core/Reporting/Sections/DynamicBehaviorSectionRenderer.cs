using System.Net;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Core.Reporting.Sections;

/// <summary>
/// Renders a simple dynamic-behavior event summary.
/// Inputs are AnalysisReport events; processing groups event types; Render
/// returns an HTML fragment with counts by event type.
/// </summary>
public sealed class DynamicBehaviorSectionRenderer : IReportSectionRenderer
{
    public string SectionId => "dynamic-summary";

    public string Title => "Dynamic behavior summary";

    /// <inheritdoc />
    public string Render(AnalysisReport report)
    {
        var rows = string.Join(
            string.Empty,
            report.Events
                .GroupBy(evt => evt.EventType)
                .OrderBy(group => group.Key)
                .Select(group => $"<tr><td>{WebUtility.HtmlEncode(group.Key)}</td><td>{group.Count()}</td></tr>"));
        return $"<section id=\"dynamic-summary\"><h2>Dynamic behavior summary</h2><table>{rows}</table></section>";
    }
}
