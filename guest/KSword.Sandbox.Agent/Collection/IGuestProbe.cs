using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Agent.Collection;

/// <summary>
/// Defines one guest-side probe that can observe VM state.
/// Inputs are a probe phase and cancellation token; processing is
/// implementation-specific; CollectAsync returns normalized events.
/// </summary>
internal interface IGuestProbe
{
    string ProbeId { get; }

    /// <summary>
    /// Collects events for the requested phase.
    /// Inputs are phase and cancellation token, processing observes local guest
    /// state, and the method returns zero or more SandboxEvent records.
    /// </summary>
    Task<IReadOnlyList<SandboxEvent>> CollectAsync(ProbePhase phase, CancellationToken cancellationToken = default);
}
