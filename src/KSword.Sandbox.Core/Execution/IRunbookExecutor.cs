using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Core.Execution;

/// <summary>
/// Executes or records a prepared sandbox runbook.
/// Inputs are a <see cref="SandboxRunbook"/>, execution options, and optional
/// cancellation; processing either records all commands in dry-run mode or
/// launches them in order in live mode; the method returns captured execution
/// status and per-step output.
/// </summary>
public interface IRunbookExecutor
{
    /// <summary>
    /// Runs the supplied runbook according to the requested options.
    /// Inputs are the immutable runbook plan, mode/options, and cancellation
    /// token; processing stops at the first live step failure; the returned
    /// result contains stdout, stderr, exit code, duration, and status data.
    /// </summary>
    Task<SandboxRunbookExecutionResult> ExecuteAsync(
        SandboxRunbook runbook,
        SandboxRunbookExecutionOptions options,
        CancellationToken cancellationToken = default);
}
