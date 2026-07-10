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
        context.Runbook = builder.Build(
            context.Config,
            context.JobId,
            context.Sample ?? throw new InvalidOperationException("Sample identity is required before runbook planning."));
        return Task.CompletedTask;
    }
}
