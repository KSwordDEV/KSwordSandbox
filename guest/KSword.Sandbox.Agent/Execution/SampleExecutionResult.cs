using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Agent.Execution;

/// <summary>
/// Captures outcome and events from one sample execution attempt.
/// Inputs are process metadata and collected events; processing stores exit and
/// timeout state; the record is returned to guest orchestration.
/// </summary>
internal sealed record SampleExecutionResult
{
    public bool Started { get; init; }

    public bool TimedOut { get; init; }

    public int? ExitCode { get; init; }

    public List<SandboxEvent> Events { get; init; } = [];
}
