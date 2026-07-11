using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Core.Telemetry;

/// <summary>
/// Removes duplicate live events without changing their classification state.
/// Inputs are normalized SandboxEvent records; processing builds stable keys;
/// methods return the first occurrence of each event.
/// </summary>
public sealed class EventDeduplicator
{
    /// <summary>
    /// Deduplicates events by common identity fields and data values.
    /// The input is an event sequence, processing keeps a hash set of keys, and
    /// the method returns a list in original order.
    /// </summary>
    public IReadOnlyList<SandboxEvent> Deduplicate(IEnumerable<SandboxEvent> events)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var result = new List<SandboxEvent>();
        foreach (var evt in events)
        {
            if (seen.Add(BuildKey(evt)))
            {
                result.Add(evt);
            }
        }

        return result;
    }

    /// <summary>
    /// Builds a stable comparison key for one event.
    /// The input is a SandboxEvent, processing combines common fields and
    /// sorted data, and the method returns a string key.
    /// </summary>
    private static string BuildKey(SandboxEvent evt)
    {
        var data = evt.Data is null
            ? string.Empty
            : string.Join(";", evt.Data.OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase).Select(pair => $"{pair.Key}={pair.Value}"));
        return string.Join("|", evt.EventType, evt.Source, evt.Timestamp.ToString("O"), evt.ProcessId?.ToString() ?? string.Empty, evt.Path ?? string.Empty, data);
    }
}
