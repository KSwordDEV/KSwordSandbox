namespace KSword.Sandbox.Agent.Collection;

/// <summary>
/// Identifies when a guest probe captured data relative to sample execution.
/// Inputs are selected by collection orchestration, processing uses symbolic
/// enum values, and values are returned in probe result metadata.
/// </summary>
internal enum ProbePhase
{
    BeforeStart = 0,
    AfterStart,
    /// <summary>
    /// A bounded in-flight sample poll. Dynamic probes use this phase to
    /// retain short-lived process, file, and TCP deltas that can disappear
    /// before the final AfterRun sweep.
    /// </summary>
    DuringRun,
    AfterRun,
    Cleanup
}
