using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Agent.Collection;

/// <summary>
/// Buffers guest-side events before they are written to artifacts.
/// Inputs are normalized SandboxEvent records from probes and execution code;
/// processing appends them in memory; methods return snapshots for output.
/// </summary>
internal sealed class GuestCollectionEventSink
{
    private readonly List<SandboxEvent> events = [];

    /// <summary>
    /// Adds one event to the sink.
    /// The input is a SandboxEvent, processing appends it unchanged, and the
    /// method returns no value.
    /// </summary>
    public void Add(SandboxEvent evt)
    {
        events.Add(evt);
    }

    /// <summary>
    /// Adds multiple events to the sink.
    /// The input is an event sequence, processing appends each event, and the
    /// method returns no value.
    /// </summary>
    public void AddRange(IEnumerable<SandboxEvent> items)
    {
        events.AddRange(items);
    }

    /// <summary>
    /// Returns a stable event snapshot.
    /// There are no inputs; processing copies the current list; the method
    /// returns events in insertion order.
    /// </summary>
    public IReadOnlyList<SandboxEvent> Snapshot()
    {
        return events.ToList();
    }
}
