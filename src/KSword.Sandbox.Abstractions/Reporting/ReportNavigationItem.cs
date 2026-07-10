namespace KSword.Sandbox.Abstractions.Reporting;

/// <summary>
/// Represents one navigation link in the generated HTML report.
/// Inputs are section descriptors and optional severity metadata, processing
/// converts section IDs to anchors, and the record is returned to renderers.
/// </summary>
public sealed record ReportNavigationItem
{
    public string Anchor { get; init; } = string.Empty;

    public string Label { get; init; } = string.Empty;

    public string? Severity { get; init; }
}
