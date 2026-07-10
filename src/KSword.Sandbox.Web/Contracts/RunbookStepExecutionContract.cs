namespace KSword.Sandbox.Web.Contracts;

/// <summary>
/// Inputs: one runbook step result returned by the executor.
/// Processing: preserves stdout, stderr, exit code, duration, and status fields
/// needed by the WebUI table without requiring the browser to infer them from
/// free-form messages.
/// Return behavior: instances are serialized as copyable runbook step rows.
/// </summary>
/// <param name="StepIndex">Zero-based runbook step index.</param>
/// <param name="StepId">Stable runbook step identifier.</param>
/// <param name="Title">Operator-facing step title.</param>
/// <param name="Succeeded">True when the step succeeded or was safely skipped.</param>
/// <param name="Skipped">True when the executor skipped the step.</param>
/// <param name="ExitCode">PowerShell exit code when a process was launched.</param>
/// <param name="Duration">Elapsed step duration.</param>
/// <param name="StandardOutput">Captured stdout text.</param>
/// <param name="StandardError">Captured stderr text.</param>
/// <param name="Message">Failure or skip detail.</param>
public sealed record RunbookStepExecutionContract(
    int StepIndex,
    string StepId,
    string Title,
    bool Succeeded,
    bool Skipped,
    int? ExitCode,
    TimeSpan Duration,
    string StandardOutput,
    string StandardError,
    string? Message);
