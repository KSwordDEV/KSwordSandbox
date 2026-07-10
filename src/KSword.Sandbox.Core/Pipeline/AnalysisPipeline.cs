using KSword.Sandbox.Abstractions.Pipeline;

namespace KSword.Sandbox.Core.Pipeline;

/// <summary>
/// Runs host analysis stages in a deterministic order.
/// Inputs are pipeline stages and a context; processing records timing and
/// failures; ExecuteAsync returns the updated context or rethrows failures.
/// </summary>
public sealed class AnalysisPipeline
{
    private readonly IReadOnlyList<IAnalysisPipelineStage> stages;

    /// <summary>
    /// Creates a pipeline from ordered stages.
    /// Inputs are stage instances, processing snapshots them into a list, and
    /// the constructor returns no value.
    /// </summary>
    public AnalysisPipeline(IEnumerable<IAnalysisPipelineStage> stages)
    {
        this.stages = stages.ToList();
    }

    /// <summary>
    /// Executes all stages in order.
    /// Inputs are a pipeline context and cancellation token; processing awaits
    /// each stage and records timeline entries; the method returns the context.
    /// </summary>
    public async Task<AnalysisPipelineContext> ExecuteAsync(AnalysisPipelineContext context, CancellationToken cancellationToken = default)
    {
        foreach (var stage in stages)
        {
            var started = DateTimeOffset.UtcNow;
            try
            {
                context.Timeline.Add(new AnalysisTimelineEntry { StageId = stage.StageId, Status = AnalysisStageStatus.Running, StartedAtUtc = started });
                await stage.ExecuteAsync(context, cancellationToken);
                context.Timeline.Add(new AnalysisTimelineEntry { StageId = stage.StageId, Status = AnalysisStageStatus.Completed, StartedAtUtc = started, FinishedAtUtc = DateTimeOffset.UtcNow });
            }
            catch (Exception ex)
            {
                context.Timeline.Add(new AnalysisTimelineEntry { StageId = stage.StageId, Status = AnalysisStageStatus.Failed, StartedAtUtc = started, FinishedAtUtc = DateTimeOffset.UtcNow, Message = ex.Message });
                throw;
            }
        }

        return context;
    }
}
