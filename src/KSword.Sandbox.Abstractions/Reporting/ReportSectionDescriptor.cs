namespace KSword.Sandbox.Abstractions.Reporting;

/// <summary>
/// Describes one report section independently from a concrete renderer.
/// Inputs are renderer metadata, processing orders sections by Order, and the
/// record is returned to report navigation builders.
/// </summary>
public sealed record ReportSectionDescriptor
{
    public string Id { get; init; } = string.Empty;

    public string Title { get; init; } = string.Empty;

    public int Order { get; init; }

    public bool Required { get; init; } = true;
}
