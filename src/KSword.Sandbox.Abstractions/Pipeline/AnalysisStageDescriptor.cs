namespace KSword.Sandbox.Abstractions.Pipeline;

/// <summary>
/// Describes a pipeline stage that can be shown in the WebUI and logs.
/// Inputs are static stage metadata, processing orders stages by Order, and the
/// record is returned to clients that render progress.
/// </summary>
public sealed record AnalysisStageDescriptor
{
    public string StageId { get; init; } = string.Empty;

    public string Title { get; init; } = string.Empty;

    public int Order { get; init; }

    public bool Required { get; init; } = true;
}
