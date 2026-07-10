using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Agent.Collection;

/// <summary>
/// Runs a set of guest probes and converts probe failures into events.
/// Inputs are probe instances and a phase; processing calls each probe in
/// order; methods return collected or diagnostic SandboxEvent records.
/// </summary>
internal sealed class GuestProbeRunner
{
    private readonly IReadOnlyList<IGuestProbe> probes;

    /// <summary>
    /// Creates a probe runner.
    /// The input is a probe sequence, processing snapshots it, and the
    /// constructor returns no value.
    /// </summary>
    public GuestProbeRunner(IEnumerable<IGuestProbe> probes)
    {
        this.probes = probes.ToList();
    }

    /// <summary>
    /// Runs every configured probe for one phase.
    /// Inputs are phase and cancellation token, processing catches probe
    /// exceptions, and the method returns collected events.
    /// </summary>
    public async Task<IReadOnlyList<SandboxEvent>> CollectAsync(ProbePhase phase, CancellationToken cancellationToken = default)
    {
        var events = new List<SandboxEvent>();
        foreach (var probe in probes)
        {
            try
            {
                events.AddRange(await probe.CollectAsync(phase, cancellationToken));
            }
            catch (Exception ex)
            {
                events.Add(new SandboxEvent
                {
                    EventType = "probe.failed",
                    Source = "guest",
                    Data =
                    {
                        ["probeId"] = probe.ProbeId,
                        ["phase"] = phase.ToString(),
                        ["exceptionType"] = ex.GetType().FullName ?? ex.GetType().Name,
                        ["message"] = ex.Message
                    }
                });
            }
        }

        return events;
    }
}
