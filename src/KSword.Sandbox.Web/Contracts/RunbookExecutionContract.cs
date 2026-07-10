namespace KSword.Sandbox.Web.Contracts;

/// <summary>
/// Inputs: execution mode, success flag, summary message, executed step labels, and completion time.
/// Processing: summarizes runbook execution without leaking executor implementation details.
/// Return behavior: instances are serialized as runbook execution payloads.
/// </summary>
/// <param name="Live">Indicates whether the runbook was executed in live mode.</param>
/// <param name="Succeeded">Indicates whether every required runbook step succeeded.</param>
/// <param name="Message">Caller-facing summary of the runbook result.</param>
/// <param name="Steps">Ordered labels for steps included in the execution response.</param>
/// <param name="CompletedAtUtc">UTC timestamp captured after the execution result was produced.</param>
public sealed record RunbookExecutionContract(
    bool Live,
    bool Succeeded,
    string Message,
    IReadOnlyList<string> Steps,
    DateTimeOffset CompletedAtUtc)
{
    /// <summary>
    /// Copyable per-step execution rows for the WebUI. Values include stdout,
    /// stderr, exit code, duration, and step status when an endpoint has moved
    /// from the legacy label-only list to the richer experience contract.
    /// </summary>
    public IReadOnlyList<RunbookStepExecutionContract> StepResults { get; init; } = [];

    /// <summary>
    /// Inputs: a reason string and a UTC timestamp from the caller.
    /// Processing: creates a non-live, non-successful result that still uses the normal contract shape.
    /// Return behavior: returns a skipped execution payload with an empty step list.
    /// </summary>
    public static RunbookExecutionContract Skipped(string reason, DateTimeOffset completedAtUtc)
    {
        return new RunbookExecutionContract(false, false, reason, Array.Empty<string>(), completedAtUtc);
    }
}
