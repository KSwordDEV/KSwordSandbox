using KSword.Sandbox.Abstractions;
using System.Globalization;
using System.Text.Json;

namespace KSword.Sandbox.Core.Telemetry;

/// <summary>
/// Reads live events from JSON and JSONL files that may still be changing.
/// Inputs are artifact paths; processing tolerates IO and parse failures by
/// skipping bad rows; methods return normalized event objects.
/// </summary>
public sealed class FileLiveEventSource
{
    private const long MaxJsonArrayBytes = 8L * 1024 * 1024;

    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    /// <summary>
    /// Reads events from one artifact path.
    /// The input is a file path, processing selects JSON array or JSON Lines,
    /// and the method returns zero or more events.
    /// </summary>
    public IReadOnlyList<SandboxEvent> Read(string path)
    {
        return ReadCore(path, includeStatusEvent: false);
    }

    /// <summary>
    /// Reads one artifact path for live-monitor transport, including one stable
    /// synthetic source-status event.
    /// Inputs are JSON or JSONL paths that may be empty or still being written;
    /// processing skips duplicate/malformed payload rows and reports read state;
    /// the method returns source status plus parsed events.
    /// </summary>
    public IReadOnlyList<SandboxEvent> ReadForLiveMonitor(string path)
    {
        return ReadCore(path, includeStatusEvent: true);
    }

    /// <summary>
    /// Reads a JSON event array through a shared file handle.
    /// The input may still be open by the live Hyper-V sync loop; processing
    /// uses read/write/delete sharing and returns an empty page for partial
    /// JSON instead of failing the WebUI endpoint.
    /// </summary>
    private static IReadOnlyList<SandboxEvent> ReadCore(string path, bool includeStatusEvent)
    {
        if (!File.Exists(path))
        {
            return includeStatusEvent
                ? [BuildStatusEvent(path, new LiveSourceReadState("missing", FormatForPath(path)))]
                : [];
        }

        try
        {
            var state = string.Equals(Path.GetExtension(path), ".jsonl", StringComparison.OrdinalIgnoreCase)
                ? ReadJsonLines(path)
                : ReadJsonArray(path);
            return includeStatusEvent
                ? [BuildStatusEvent(path, state), .. state.Events]
                : state.Events;
        }
        catch (IOException ex)
        {
            return includeStatusEvent
                ? [BuildStatusEvent(path, new LiveSourceReadState("pending", FormatForPath(path), ExceptionType: ex.GetType().Name, Message: ex.Message))]
                : [];
        }
        catch (UnauthorizedAccessException ex)
        {
            return includeStatusEvent
                ? [BuildStatusEvent(path, new LiveSourceReadState("pending", FormatForPath(path), ExceptionType: ex.GetType().Name, Message: ex.Message))]
                : [];
        }
    }

    private static LiveSourceReadState ReadJsonArray(string path)
    {
        using var stream = OpenSharedRead(path);
        if (stream.Length == 0)
        {
            return new LiveSourceReadState("empty", "json", SizeBytes: 0);
        }

        var info = new FileInfo(path);
        if (stream.Length > MaxJsonArrayBytes)
        {
            return new LiveSourceReadState(
                "too-large",
                "json",
                SizeBytes: stream.Length,
                Message: $"JSON array live parsing skipped because the file is larger than {MaxJsonArrayBytes} bytes; use JSONL or import the report for full processing.");
        }

        try
        {
            using var document = JsonDocument.Parse(stream);
            if (document.RootElement.ValueKind != JsonValueKind.Array)
            {
                return new LiveSourceReadState(
                    "parse-error",
                    "json",
                    SizeBytes: stream.Length,
                    ParseErrorCount: 1,
                    Message: "Expected a JSON array of SandboxEvent objects.");
            }

            var events = new List<SandboxEvent>();
            var parseErrors = 0;
            var index = 0;
            foreach (var element in document.RootElement.EnumerateArray())
            {
                index++;
                try
                {
                    var evt = DeserializeEvent(element, StableFallbackTimestamp(info, index));
                    if (evt is not null)
                    {
                        events.Add(evt);
                    }
                }
                catch (JsonException)
                {
                    parseErrors++;
                }
            }

            return new LiveSourceReadState(
                parseErrors == 0 ? "ready" : "partial",
                "json",
                events,
                SizeBytes: stream.Length,
                RecordCount: index,
                ParseErrorCount: parseErrors);
        }
        catch (JsonException ex)
        {
            return new LiveSourceReadState(
                "pending",
                "json",
                SizeBytes: stream.Length,
                ParseErrorCount: 1,
                ExceptionType: ex.GetType().Name,
                Message: "JSON array is not complete yet.");
        }
    }

    /// <summary>
    /// Reads one JSON object per line.
    /// The input is a JSONL path, processing ignores malformed lines for live
    /// display, and the method returns parsed sandbox events.
    /// </summary>
    private static LiveSourceReadState ReadJsonLines(string path)
    {
        var events = new List<SandboxEvent>();
        using var stream = OpenSharedRead(path);
        if (stream.Length == 0)
        {
            return new LiveSourceReadState("empty", "jsonl", SizeBytes: 0);
        }

        var info = new FileInfo(path);
        using var reader = new StreamReader(stream);
        var lineNumber = 0;
        var blankLineCount = 0;
        var parseErrorCount = 0;
        var partialLineCount = 0;
        while (reader.ReadLine() is { } line)
        {
            lineNumber++;
            if (string.IsNullOrWhiteSpace(line))
            {
                blankLineCount++;
                continue;
            }

            try
            {
                var evt = DeserializeEvent(line, StableFallbackTimestamp(info, lineNumber));
                if (evt is not null)
                {
                    events.Add(evt);
                }
            }
            catch (JsonException)
            {
                if (LooksIncompleteJsonLine(line))
                {
                    partialLineCount++;
                }
                else
                {
                    parseErrorCount++;
                }
            }
        }

        var status = partialLineCount > 0
            ? "pending"
            : parseErrorCount > 0
                ? "partial"
                : "ready";
        return new LiveSourceReadState(
            status,
            "jsonl",
            events,
            SizeBytes: stream.Length,
            RecordCount: lineNumber,
            BlankLineCount: blankLineCount,
            ParseErrorCount: parseErrorCount,
            PartialLineCount: partialLineCount);
    }

    /// <summary>
    /// Opens an artifact for live reading while PowerShell Direct or the guest
    /// collector may still be writing/copying it.
    /// </summary>
    private static FileStream OpenSharedRead(string path)
    {
        return new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete);
    }

    private static SandboxEvent? DeserializeEvent(string json, DateTimeOffset fallbackTimestamp)
    {
        using var document = JsonDocument.Parse(json);
        return DeserializeEvent(document.RootElement, fallbackTimestamp);
    }

    private static SandboxEvent? DeserializeEvent(JsonElement element, DateTimeOffset fallbackTimestamp)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        var hasTimestamp = HasProperty(element, "timestamp");
        var evt = element.Deserialize<SandboxEvent>(JsonOptions);
        if (evt is null || string.IsNullOrWhiteSpace(evt.EventType))
        {
            return null;
        }

        var data = evt.Data is null
            ? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, string>(evt.Data, StringComparer.OrdinalIgnoreCase);
        return evt with
        {
            Source = string.IsNullOrWhiteSpace(evt.Source) ? "guest" : evt.Source,
            Timestamp = !hasTimestamp || evt.Timestamp == default ? fallbackTimestamp : evt.Timestamp,
            Data = data
        };
    }

    private static bool HasProperty(JsonElement element, string propertyName)
    {
        foreach (var property in element.EnumerateObject())
        {
            if (string.Equals(property.Name, propertyName, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static bool LooksIncompleteJsonLine(string line)
    {
        var trimmed = line.TrimEnd();
        if (string.IsNullOrWhiteSpace(trimmed))
        {
            return false;
        }

        return (trimmed.StartsWith("{", StringComparison.Ordinal) && !trimmed.EndsWith("}", StringComparison.Ordinal)) ||
            (trimmed.StartsWith("[", StringComparison.Ordinal) && !trimmed.EndsWith("]", StringComparison.Ordinal));
    }

    private static SandboxEvent BuildStatusEvent(string path, LiveSourceReadState state)
    {
        var info = TryGetFileInfo(path);
        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["status"] = state.Status,
            ["format"] = state.Format,
            ["sourceFileName"] = SafeFileName(path),
            ["eventCount"] = state.Events.Count.ToString(CultureInfo.InvariantCulture),
            ["recordCount"] = state.RecordCount.ToString(CultureInfo.InvariantCulture),
            ["blankLineCount"] = state.BlankLineCount.ToString(CultureInfo.InvariantCulture),
            ["parseErrorCount"] = state.ParseErrorCount.ToString(CultureInfo.InvariantCulture),
            ["partialLineCount"] = state.PartialLineCount.ToString(CultureInfo.InvariantCulture),
            ["sizeBytes"] = (info?.Length ?? state.SizeBytes).ToString(CultureInfo.InvariantCulture),
            ["cursorStable"] = "true"
        };

        if (info is not null)
        {
            data["lastWriteTimeUtc"] = new DateTimeOffset(info.LastWriteTimeUtc).ToString("O", CultureInfo.InvariantCulture);
        }

        if (!string.IsNullOrWhiteSpace(state.ExceptionType))
        {
            data["exceptionType"] = state.ExceptionType;
        }

        if (!string.IsNullOrWhiteSpace(state.Message))
        {
            data["message"] = state.Message;
        }

        return new SandboxEvent
        {
            EventType = "live.events.source_status",
            Source = "host",
            Timestamp = DateTimeOffset.UnixEpoch,
            Path = path,
            Data = data
        };
    }

    private static FileInfo? TryGetFileInfo(string path)
    {
        try
        {
            var info = new FileInfo(path);
            return info.Exists ? info : null;
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static DateTimeOffset StableFallbackTimestamp(FileInfo info, int ordinal)
    {
        var baseTime = info.CreationTimeUtc > DateTime.UnixEpoch
            ? info.CreationTimeUtc
            : info.LastWriteTimeUtc;
        if (baseTime <= DateTime.UnixEpoch)
        {
            baseTime = DateTime.UnixEpoch;
        }

        return new DateTimeOffset(DateTime.SpecifyKind(baseTime, DateTimeKind.Utc)).AddTicks(Math.Max(0, ordinal));
    }

    private static string FormatForPath(string path)
    {
        return string.Equals(Path.GetExtension(path), ".jsonl", StringComparison.OrdinalIgnoreCase)
            ? "jsonl"
            : "json";
    }

    private static string SafeFileName(string path)
    {
        try
        {
            var fileName = Path.GetFileName(path);
            return string.IsNullOrWhiteSpace(fileName) ? "events" : fileName;
        }
        catch (ArgumentException)
        {
            return "events";
        }
    }

    private sealed record LiveSourceReadState(
        string Status,
        string Format,
        IReadOnlyList<SandboxEvent>? ParsedEvents = null,
        long SizeBytes = 0,
        int RecordCount = 0,
        int BlankLineCount = 0,
        int ParseErrorCount = 0,
        int PartialLineCount = 0,
        string? ExceptionType = null,
        string? Message = null)
    {
        public IReadOnlyList<SandboxEvent> Events { get; } = ParsedEvents ?? [];
    }
}
