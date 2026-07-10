using KSword.Sandbox.Core.Pipeline;

namespace KSword.Sandbox.Core.Pipeline.Stages;

/// <summary>
/// Validates the host-visible sample path before expensive analysis work.
/// Inputs are the pipeline context; processing checks the submitted file; the
/// stage returns by updating context only when validation succeeds.
/// </summary>
public sealed class SubmissionValidationStage : IAnalysisPipelineStage
{
    public string StageId => "submission.validation";

    public string Title => "Validate submitted executable";

    /// <inheritdoc />
    public Task ExecuteAsync(AnalysisPipelineContext context, CancellationToken cancellationToken = default)
    {
        if (!File.Exists(context.Submission.SamplePath))
        {
            throw new FileNotFoundException("Submitted executable was not found.", context.Submission.SamplePath);
        }

        return Task.CompletedTask;
    }
}
