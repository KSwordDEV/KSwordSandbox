using System.Net;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Core.Reporting.Sections;

/// <summary>
/// Renders the report cover section from sample identity and job status.
/// Inputs are AnalysisReport values; processing HTML-encodes dynamic fields;
/// Render returns a compact cover HTML fragment.
/// </summary>
public sealed class CoverReportSectionRenderer : IReportSectionRenderer
{
    public string SectionId => "cover";

    public string Title => "Cover";

    /// <inheritdoc />
    public string Render(AnalysisReport report)
    {
        return $"<section id=\"cover\"><h1>KSword Sandbox Report</h1><p>{E(report.Sample.FileName)}</p><p>{E(report.Sample.Sha256)}</p><p>{E(report.Status.ToString())}</p></section>";
    }

    /// <summary>
    /// Encodes dynamic text for safe HTML output.
    /// The input is arbitrary text, processing applies HTML encoding, and the
    /// method returns encoded text.
    /// </summary>
    private static string E(string value)
    {
        return WebUtility.HtmlEncode(value);
    }
}
