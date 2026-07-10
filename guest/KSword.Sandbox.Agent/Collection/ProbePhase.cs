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
    AfterRun,
    Cleanup
}
