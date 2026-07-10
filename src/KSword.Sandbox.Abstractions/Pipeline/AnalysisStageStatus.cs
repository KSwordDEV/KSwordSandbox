namespace KSword.Sandbox.Abstractions.Pipeline;

/// <summary>
/// Represents execution state for one analysis pipeline stage.
/// Inputs are set by the host pipeline runner, processing compares symbolic
/// values, and the enum is returned in timeline API responses.
/// </summary>
public enum AnalysisStageStatus
{
    Pending = 0,
    Running,
    Completed,
    Failed,
    Skipped
}
