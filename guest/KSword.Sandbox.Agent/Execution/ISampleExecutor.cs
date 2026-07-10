namespace KSword.Sandbox.Agent.Execution;

/// <summary>
/// Defines sample execution inside the guest VM.
/// Inputs are a launch plan and cancellation token; processing starts and
/// observes the sample; ExecuteAsync returns process outcome metadata.
/// </summary>
internal interface ISampleExecutor
{
    /// <summary>
    /// Executes the sample according to a launch plan.
    /// Inputs are plan and cancellation token, processing is executor-specific,
    /// and the method returns a SampleExecutionResult.
    /// </summary>
    Task<SampleExecutionResult> ExecuteAsync(SampleLaunchPlan plan, CancellationToken cancellationToken = default);
}
