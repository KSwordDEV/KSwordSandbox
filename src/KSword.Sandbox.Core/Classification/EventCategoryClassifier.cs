using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Core.Classification;

/// <summary>
/// Applies fast event-type prefix classification before heavy rule matching.
/// Inputs are normalized SandboxEvent records; processing checks stable event
/// prefixes; methods return ClassifiedEvent values.
/// </summary>
public sealed class EventCategoryClassifier
{
    /// <summary>
    /// Classifies one event by event type and source.
    /// The input is a SandboxEvent, processing evaluates known prefixes, and
    /// the method returns category metadata plus the original event.
    /// </summary>
    public ClassifiedEvent Classify(SandboxEvent evt)
    {
        var eventType = evt.EventType ?? string.Empty;
        var category = eventType switch
        {
            var value when value.StartsWith("process.", StringComparison.OrdinalIgnoreCase) => EventCategory.Process,
            var value when value.StartsWith("file.", StringComparison.OrdinalIgnoreCase) => EventCategory.FileSystem,
            var value when value.StartsWith("registry.", StringComparison.OrdinalIgnoreCase) => EventCategory.Registry,
            var value when value.StartsWith("network.", StringComparison.OrdinalIgnoreCase) => EventCategory.Network,
            var value when value.StartsWith("image.", StringComparison.OrdinalIgnoreCase) => EventCategory.Module,
            var value when value.StartsWith("driver.", StringComparison.OrdinalIgnoreCase) => EventCategory.Driver,
            var value when value.StartsWith("agent.", StringComparison.OrdinalIgnoreCase) => EventCategory.GuestAgent,
            var value when value.StartsWith("hyperv.", StringComparison.OrdinalIgnoreCase) => EventCategory.HostOrchestration,
            _ => EventCategory.Unknown
        };

        return new ClassifiedEvent
        {
            Event = evt,
            Category = category,
            Reason = category == EventCategory.Unknown ? "No prefix mapping matched." : "Matched normalized event type prefix."
        };
    }

    /// <summary>
    /// Classifies a sequence of events.
    /// The input is an event sequence, processing classifies each item, and the
    /// method returns a materialized list.
    /// </summary>
    public IReadOnlyList<ClassifiedEvent> ClassifyMany(IEnumerable<SandboxEvent> events)
    {
        return events.Select(Classify).ToList();
    }
}
