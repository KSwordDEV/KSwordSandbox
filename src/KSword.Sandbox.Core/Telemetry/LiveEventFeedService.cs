using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Core.Telemetry;

/// <summary>
/// Creates paged live-event snapshots from one or more file sources.
/// Inputs are job IDs, source paths, and paging values; processing loads,
/// deduplicates, sorts, and slices events; methods return LiveEventSnapshot.
/// </summary>
public sealed class LiveEventFeedService
{
    private readonly FileLiveEventSource source = new();
    private readonly EventDeduplicator deduplicator = new();

    /// <summary>
    /// Builds a live snapshot from file paths.
    /// Inputs are job ID, paths, offset, and take; processing reads current
    /// event files and applies paging; the method returns a snapshot.
    /// </summary>
    public LiveEventSnapshot Build(Guid jobId, IEnumerable<string> paths, int offset, int take)
    {
        var files = paths
            .Where(File.Exists)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
            .ToList();
        var events = deduplicator.Deduplicate(files.SelectMany(source.ReadForLiveMonitor))
            .OrderBy(evt => evt.Timestamp)
            .ThenBy(evt => evt.EventType, StringComparer.OrdinalIgnoreCase)
            .ThenBy(evt => evt.Source, StringComparer.OrdinalIgnoreCase)
            .ThenBy(evt => evt.Path, StringComparer.OrdinalIgnoreCase)
            .ToList();
        var safeOffset = Math.Max(0, offset);
        var safeTake = Math.Clamp(take, 1, 500);
        var page = events.Skip(safeOffset).Take(safeTake).ToList();
        return new LiveEventSnapshot
        {
            JobId = jobId,
            TotalEvents = events.Count,
            NextOffset = Math.Min(events.Count, safeOffset + page.Count),
            HasMore = safeOffset + page.Count < events.Count,
            Sources = files,
            Events = page
        };
    }
}
