using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Orchestration;
using KSword.Sandbox.Core.Pipeline;

namespace KSword.Sandbox.Core.Pipeline.Stages;

/// <summary>
/// Plans Hyper-V work after a sample identity has been computed.
/// Inputs are pipeline context with Config and Sample; processing calls the
/// runbook builder; the stage returns after context.Runbook is populated.
/// </summary>
public sealed class RunbookPlanningStage : IAnalysisPipelineStage
{
    private readonly HyperVRunbookBuilder builder = new();

    public string StageId => "hyperv.runbook.plan";

    public string Title => "Plan Hyper-V analysis runbook";

    /// <inheritdoc />
    public Task ExecuteAsync(AnalysisPipelineContext context, CancellationToken cancellationToken = default)
    {
        var config = ApplySubmissionArtifactCollectionOverrides(context.Config, context.Submission);
        context.Runbook = builder.Build(
            config,
            context.JobId,
            context.Sample ?? throw new InvalidOperationException("Sample identity is required before runbook planning."));
        return Task.CompletedTask;
    }

    /// <summary>
    /// Applies per-submission artifact collection opt-ins to the stage config.
    /// Inputs are the pipeline config defaults and submission overrides;
    /// processing overlays only nullable collection fields; the method returns
    /// the config used by HyperVRunbookBuilder for Guest Agent flags.
    /// </summary>
    private static SandboxConfig ApplySubmissionArtifactCollectionOverrides(SandboxConfig config, SandboxSubmission submission)
    {
        return config with
        {
            ArtifactCollection = config.ArtifactCollection with
            {
                CollectDroppedFiles = submission.CollectDroppedFiles ?? config.ArtifactCollection.CollectDroppedFiles,
                CaptureScreenshots = submission.CaptureScreenshots ?? config.ArtifactCollection.CaptureScreenshots,
                CaptureMemoryDumps = submission.CaptureMemoryDumps ?? config.ArtifactCollection.CaptureMemoryDumps,
                CapturePacketCapture = submission.CapturePacketCapture ?? config.ArtifactCollection.CapturePacketCapture
            }
        };
    }
}
