using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Abstractions.Pipeline;

namespace KSword.Sandbox.Core.Pipeline;

/// <summary>
/// Carries mutable state while a staged analysis pipeline executes.
/// Inputs are submission and configuration data; processing stages fill sample,
/// runbook, report, and timeline fields; callers read the final context.
/// </summary>
public sealed class AnalysisPipelineContext
{
    public Guid JobId { get; init; } = Guid.NewGuid();

    public required SandboxConfig Config { get; init; }

    public required SandboxSubmission Submission { get; init; }

    public SampleIdentity? Sample { get; set; }

    public SandboxRunbook? Runbook { get; set; }

    public AnalysisReport? Report { get; set; }

    public List<AnalysisTimelineEntry> Timeline { get; } = [];

    public Dictionary<string, object> Scratch { get; } = new(StringComparer.OrdinalIgnoreCase);
}
