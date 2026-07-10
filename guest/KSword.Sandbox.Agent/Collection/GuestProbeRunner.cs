using System.Diagnostics;
using System.Globalization;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Agent.Collection;

/// <summary>
/// Runs a set of guest probes and converts probe failures into events.
/// Inputs are probe instances, a phase, and run context; processing calls each
/// probe in order; methods return collected or diagnostic SandboxEvent records.
/// </summary>
internal sealed class GuestProbeRunner
{
    private static readonly TimeSpan DefaultProbeTimeout = TimeSpan.FromSeconds(10);
    private readonly IReadOnlyList<IGuestProbe> probes;
    private readonly TimeSpan probeTimeout;

    /// <summary>
    /// Creates a probe runner.
    /// The input is a probe sequence, processing snapshots it, and the
    /// constructor returns no value.
    /// </summary>
    public GuestProbeRunner(IEnumerable<IGuestProbe> probes, TimeSpan? probeTimeout = null)
    {
        this.probes = probes.ToList();
        this.probeTimeout = probeTimeout.GetValueOrDefault(DefaultProbeTimeout);
        if (this.probeTimeout <= TimeSpan.Zero)
        {
            this.probeTimeout = DefaultProbeTimeout;
        }
    }

    /// <summary>
    /// Runs every configured probe for one phase.
    /// Inputs are phase, shared run context, and cancellation token; processing
    /// catches probe exceptions; the method returns collected events.
    /// </summary>
    public async Task<IReadOnlyList<SandboxEvent>> CollectAsync(
        ProbePhase phase,
        GuestProbeContext context,
        CancellationToken cancellationToken = default)
    {
        var events = new List<SandboxEvent>();
        foreach (var probe in probes)
        {
            var elapsed = Stopwatch.StartNew();
            try
            {
                events.AddRange(await CollectProbeWithTimeoutAsync(probe, phase, context, cancellationToken));
            }
            catch (ProbeTimeoutException)
            {
                events.Add(CreateProbeTimeoutEvent(probe, phase, elapsed.Elapsed));
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (OperationCanceledException ex)
            {
                events.Add(CreateProbeFailureEvent("probe.canceled", probe, phase, elapsed.Elapsed, ex));
            }
            catch (Exception ex)
            {
                events.Add(CreateProbeFailureEvent("probe.failed", probe, phase, elapsed.Elapsed, ex));
            }
        }

        return events;
    }

    /// <summary>
    /// Runs one probe and races it against the configured timeout.
    /// Inputs are probe, phase, context, and caller cancellation token;
    /// processing links cancellation and observes timed-out tasks in the
    /// background; the method returns probe events or throws a diagnostic
    /// exception consumed by CollectAsync.
    /// </summary>
    private async Task<IReadOnlyList<SandboxEvent>> CollectProbeWithTimeoutAsync(
        IGuestProbe probe,
        ProbePhase phase,
        GuestProbeContext context,
        CancellationToken cancellationToken)
    {
        using var timeoutCts = new CancellationTokenSource();
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);
        var probeTask = probe.CollectAsync(phase, context, linkedCts.Token);
        var timeoutTask = Task.Delay(probeTimeout, cancellationToken);

        if (await Task.WhenAny(probeTask, timeoutTask).ConfigureAwait(false) == probeTask)
        {
            return await probeTask.ConfigureAwait(false);
        }

        cancellationToken.ThrowIfCancellationRequested();
        await timeoutCts.CancelAsync().ConfigureAwait(false);
        _ = ObserveTimedOutProbeAsync(probeTask);
        throw new ProbeTimeoutException();
    }

    /// <summary>
    /// Observes a timed-out probe task so late exceptions do not surface as
    /// unobserved task failures. The input is a task left running after timeout;
    /// processing awaits and suppresses its outcome; the method returns no
    /// value to the caller.
    /// </summary>
    private static async Task ObserveTimedOutProbeAsync(Task<IReadOnlyList<SandboxEvent>> probeTask)
    {
        try
        {
            _ = await probeTask.ConfigureAwait(false);
        }
        catch
        {
        }
    }

    /// <summary>
    /// Creates a normalized probe timeout event.
    /// Inputs are probe identity, phase, and elapsed duration; processing adds
    /// bounded timeout metadata; the method returns a SandboxEvent.
    /// </summary>
    private SandboxEvent CreateProbeTimeoutEvent(IGuestProbe probe, ProbePhase phase, TimeSpan elapsed)
    {
        return new SandboxEvent
        {
            EventType = "probe.timeout",
            Source = "guest",
            Data =
            {
                ["probeId"] = probe.ProbeId,
                ["phase"] = phase.ToString(),
                ["timeoutMilliseconds"] = probeTimeout.TotalMilliseconds.ToString("0", CultureInfo.InvariantCulture),
                ["elapsedMilliseconds"] = elapsed.TotalMilliseconds.ToString("0", CultureInfo.InvariantCulture)
            }
        };
    }

    /// <summary>
    /// Creates a normalized probe failure event.
    /// Inputs are event type, probe, phase, elapsed time, and exception;
    /// processing copies exception details and timing metadata; the method
    /// returns a SandboxEvent.
    /// </summary>
    private static SandboxEvent CreateProbeFailureEvent(
        string eventType,
        IGuestProbe probe,
        ProbePhase phase,
        TimeSpan elapsed,
        Exception exception)
    {
        return new SandboxEvent
        {
            EventType = eventType,
            Source = "guest",
            Data =
            {
                ["probeId"] = probe.ProbeId,
                ["phase"] = phase.ToString(),
                ["elapsedMilliseconds"] = elapsed.TotalMilliseconds.ToString("0", CultureInfo.InvariantCulture),
                ["exceptionType"] = exception.GetType().FullName ?? exception.GetType().Name,
                ["message"] = exception.Message
            }
        };
    }

    /// <summary>
    /// Marks an internal probe timeout without depending on localized exception
    /// messages. Inputs are none; processing is type identity only.
    /// </summary>
    private sealed class ProbeTimeoutException : TimeoutException
    {
    }
}
