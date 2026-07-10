namespace KSword.Sandbox.Core.Pipeline;

/// <summary>
/// Defines one isolated pipeline stage for the host analysis workflow.
/// Inputs are an AnalysisPipelineContext and cancellation token; processing is
/// stage-specific; ExecuteAsync returns when the stage has updated context.
/// </summary>
public interface IAnalysisPipelineStage
{
    string StageId { get; }

    string Title { get; }

    /// <summary>
    /// Executes the stage against a shared context.
    /// Inputs are context and cancellation token, processing is implemented by
    /// the concrete stage, and the method returns when the stage is complete.
    /// </summary>
    Task ExecuteAsync(AnalysisPipelineContext context, CancellationToken cancellationToken = default);
}
