using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Core.Reporting.Sections;

/// <summary>
/// Defines a focused HTML report section renderer.
/// Inputs are AnalysisReport models; processing is section-specific; Render
/// returns an HTML fragment for composition by a larger renderer.
/// </summary>
public interface IReportSectionRenderer
{
    string SectionId { get; }

    string Title { get; }

    /// <summary>
    /// Renders one report section.
    /// The input is an AnalysisReport, processing is renderer-specific, and
    /// the method returns an HTML fragment.
    /// </summary>
    string Render(AnalysisReport report);
}
