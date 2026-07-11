using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Core.Reporting;

/// <summary>
/// Controls how many normalized events are embedded directly into HTML/report
/// payloads. Inputs are raw guest/driver/host events; processing keeps high
/// value progress/process/network rows plus a bounded sample of noisy types;
/// the output is a compact, sanitized event list and an omitted-event count.
/// </summary>
public sealed record ReportEventSamplingOptions
{
    public int MaxInlineEvents { get; init; } = 220;

    public int MaxEventsPerType { get; init; } = 30;

    public int MaxHighValueEventsPerType { get; init; } = 80;

    public int MaxEvidenceEventsPerFinding { get; init; } = 8;

    public int MaxEventDataPairs { get; init; } = 16;

    public int MaxEventDataValueCharacters { get; init; } = 512;

    public int MaxPathCharacters { get; init; } = 4096;
}

/// <summary>
/// Describes the outcome of report-event sampling. Inputs are the raw count and
/// sanitized selected rows; processing computes omitted row metadata; callers
/// embed Events in report.json/report.html while keeping raw artifacts on disk.
/// </summary>
public sealed record ReportEventSamplingResult
{
    public required List<SandboxEvent> Events { get; init; }

    public int RawEventCount { get; init; }

    public int SelectedRawEventCount { get; init; }

    public int OmittedEventCount => Math.Max(0, RawEventCount - SelectedRawEventCount);

    public bool WasSampled => OmittedEventCount > 0;
}

/// <summary>
/// Shared report sampler used by WebUI regeneration and the post-process tool.
/// It prevents R0-heavy runs from producing giant HTML while preserving enough
/// representative evidence for operator review and keeping all raw files on
/// disk for deep analysis.
/// </summary>
public static class ReportEventSampler
{
    public static readonly ReportEventSamplingOptions DefaultOptions = new();

    private static readonly string[] PriorityDataKeys =
    [
        "collectionName",
        "evidenceRole",
        "capturePhase",
        "captureState",
        "importMode",
        "sourceArtifactRelativePath",
        "sourceArtifactSha256",
        "sourceArtifactSizeBytes",
        "artifactRelativePath",
        "relativePath",
        "driverEventPath",
        "rawEventsPath",
        "driverEventsPath",
        "processName",
        "imageName",
        "operationName",
        "operation",
        "queryName",
        "host",
        "url",
        "sni",
        "remoteAddress",
        "remotePort"
    ];

    /// <summary>
    /// Samples and sanitizes normalized events for report embedding. Inputs are
    /// ordered or unordered raw events plus optional source-path hints;
    /// processing orders by timestamp, applies per-type caps, adds a sampling
    /// marker when rows were omitted, and returns compact report events.
    /// </summary>
    public static ReportEventSamplingResult SampleForReport(
        IReadOnlyCollection<SandboxEvent> rawEvents,
        ReportEventSamplingOptions? options = null,
        string? jobRoot = null,
        string? eventsPath = null,
        string? driverEventsPath = null)
    {
        var resolvedOptions = options ?? DefaultOptions;
        var orderedEvents = rawEvents.OrderBy(evt => evt.Timestamp).ToList();
        var selected = SelectEvents(orderedEvents, resolvedOptions)
            .Select(evt => SanitizeEvent(evt, resolvedOptions))
            .ToList();

        var result = new ReportEventSamplingResult
        {
            Events = selected,
            RawEventCount = orderedEvents.Count,
            SelectedRawEventCount = selected.Count
        };

        if (result.WasSampled)
        {
            result.Events.Insert(0, BuildSamplingMarker(result, resolvedOptions, jobRoot, eventsPath, driverEventsPath));
        }

        return result;
    }

    /// <summary>
    /// Caps evidence rows per finding and sanitizes large fields. Inputs are raw
    /// findings from the rule engine; processing preserves rule metadata and a
    /// bounded evidence prefix; the method returns report-safe findings.
    /// </summary>
    public static List<BehaviorFinding> SanitizeFindings(IEnumerable<BehaviorFinding> findings, ReportEventSamplingOptions? options = null)
    {
        var resolvedOptions = options ?? DefaultOptions;
        return findings.Select(finding => finding with
        {
            Evidence = finding.Evidence
                .Take(resolvedOptions.MaxEvidenceEventsPerFinding)
                .Select(evt => SanitizeEvent(evt, resolvedOptions))
                .ToList()
        }).ToList();
    }

    /// <summary>
    /// Truncates one event's unbounded fields for safe HTML/JSON embedding.
    /// Inputs are a normalized event and sampling options; processing preserves
    /// common fields while bounding path, command line, and data payloads.
    /// </summary>
    public static SandboxEvent SanitizeEvent(SandboxEvent evt, ReportEventSamplingOptions? options = null)
    {
        var resolvedOptions = options ?? DefaultOptions;
        return evt with
        {
            EventType = string.IsNullOrWhiteSpace(evt.EventType) ? "unknown" : evt.EventType,
            Source = string.IsNullOrWhiteSpace(evt.Source) ? "guest" : evt.Source,
            Path = Truncate(evt.Path, resolvedOptions.MaxPathCharacters),
            CommandLine = Truncate(evt.CommandLine, resolvedOptions.MaxPathCharacters),
            Data = SanitizeData(evt.Data, resolvedOptions)
        };
    }

    private static IEnumerable<SandboxEvent> SelectEvents(IReadOnlyList<SandboxEvent> orderedEvents, ReportEventSamplingOptions options)
    {
        if (orderedEvents.Count <= options.MaxInlineEvents)
        {
            return orderedEvents;
        }

        var selected = new bool[orderedEvents.Count];
        var perType = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var selectedCount = 0;

        for (var index = 0; index < orderedEvents.Count && selectedCount < options.MaxInlineEvents; index++)
        {
            var evt = orderedEvents[index];
            var eventType = NormalizeEventType(evt.EventType);
            var typeLimit = IsHighValueReportEvent(evt)
                ? options.MaxHighValueEventsPerType
                : options.MaxEventsPerType;

            perType.TryGetValue(eventType, out var currentForType);
            if (currentForType >= typeLimit)
            {
                continue;
            }

            selected[index] = true;
            selectedCount++;
            perType[eventType] = currentForType + 1;
        }

        // If the first pass did not reach the requested max because most events
        // were one noisy type, keep the report intentionally smaller. Raw JSONL
        // remains the authority; avoiding a fill pass prevents driver.file or
        // registry noise from overwhelming user-facing reports.
        var result = new List<SandboxEvent>(selectedCount);
        for (var index = 0; index < orderedEvents.Count; index++)
        {
            if (selected[index])
            {
                result.Add(orderedEvents[index]);
            }
        }

        return result;
    }

    private static SandboxEvent BuildSamplingMarker(
        ReportEventSamplingResult result,
        ReportEventSamplingOptions options,
        string? jobRoot,
        string? eventsPath,
        string? driverEventsPath)
    {
        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["reason"] = "raw event volume exceeded report inline limit",
            ["rawEventCount"] = result.RawEventCount.ToString(),
            ["selectedRawEventCount"] = result.SelectedRawEventCount.ToString(),
            ["reportEventCount"] = (result.SelectedRawEventCount + 1).ToString(),
            ["omittedEventCount"] = result.OmittedEventCount.ToString(),
            ["maxInlineEvents"] = options.MaxInlineEvents.ToString(),
            ["maxEventsPerType"] = options.MaxEventsPerType.ToString(),
            ["maxHighValueEventsPerType"] = options.MaxHighValueEventsPerType.ToString()
        };

        if (!string.IsNullOrWhiteSpace(eventsPath))
        {
            data["rawEventsPath"] = eventsPath;
        }

        if (!string.IsNullOrWhiteSpace(driverEventsPath))
        {
            data["driverEventsPath"] = driverEventsPath;
        }

        return new SandboxEvent
        {
            EventType = "report.events.sampled",
            Timestamp = DateTimeOffset.UtcNow,
            Source = "host",
            Path = jobRoot,
            Data = data
        };
    }

    private static bool IsHighValueReportEvent(SandboxEvent evt)
    {
        var eventType = evt.EventType ?? string.Empty;
        return eventType.Contains("process", StringComparison.OrdinalIgnoreCase) ||
            eventType.Contains("network", StringComparison.OrdinalIgnoreCase) ||
            eventType.Contains("tcp", StringComparison.OrdinalIgnoreCase) ||
            eventType.Contains("dns", StringComparison.OrdinalIgnoreCase) ||
            eventType.Contains("http", StringComparison.OrdinalIgnoreCase) ||
            eventType.Contains("tls", StringComparison.OrdinalIgnoreCase) ||
            eventType.Contains("r0collector", StringComparison.OrdinalIgnoreCase) ||
            eventType.Contains("agent.", StringComparison.OrdinalIgnoreCase) ||
            eventType.Contains("report.", StringComparison.OrdinalIgnoreCase) ||
            eventType.Contains("guest.events", StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeEventType(string? eventType) =>
        string.IsNullOrWhiteSpace(eventType) ? "unknown" : eventType.Trim();

    private static Dictionary<string, string> SanitizeData(Dictionary<string, string>? data, ReportEventSamplingOptions options)
    {
        var sanitized = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (data is null || data.Count == 0)
        {
            return sanitized;
        }

        foreach (var key in PriorityDataKeys)
        {
            if (sanitized.Count >= options.MaxEventDataPairs)
            {
                break;
            }

            if (data.TryGetValue(key, out var value))
            {
                sanitized[key] = Truncate(value, options.MaxEventDataValueCharacters) ?? string.Empty;
            }
        }

        foreach (var pair in data)
        {
            if (sanitized.Count >= options.MaxEventDataPairs)
            {
                break;
            }

            if (sanitized.ContainsKey(pair.Key))
            {
                continue;
            }

            sanitized[pair.Key] = Truncate(pair.Value, options.MaxEventDataValueCharacters) ?? string.Empty;
        }

        if (data.Count > sanitized.Count)
        {
            sanitized["__omittedDataPairs"] = (data.Count - sanitized.Count).ToString();
        }

        return sanitized;
    }

    private static string? Truncate(string? value, int maxCharacters)
    {
        if (string.IsNullOrEmpty(value) || value.Length <= maxCharacters)
        {
            return value;
        }

        return value[..maxCharacters] + $"…<truncated {value.Length - maxCharacters} chars>";
    }
}
