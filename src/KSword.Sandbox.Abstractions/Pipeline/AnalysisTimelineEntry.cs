namespace KSword.Sandbox.Abstractions.Pipeline;

/// <summary>
/// Captures timing and outcome for one pipeline stage attempt.
/// Inputs are emitted by the pipeline runner, processing records UTC timing and
/// status, and the record is returned in job diagnostics.
/// </summary>
public sealed record AnalysisTimelineEntry
{
    public string StageId { get; init; } = string.Empty;

    public AnalysisStageStatus Status { get; init; } = AnalysisStageStatus.Pending;

    public DateTimeOffset StartedAtUtc { get; init; } = DateTimeOffset.UtcNow;

    public DateTimeOffset? FinishedAtUtc { get; init; }

    public string? Message { get; init; }
}
