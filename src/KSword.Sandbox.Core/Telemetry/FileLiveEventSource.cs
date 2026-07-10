using System.Text.Json;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Core.Telemetry;

/// <summary>
/// Reads live events from JSON and JSONL files that may still be changing.
/// Inputs are artifact paths; processing tolerates IO and parse failures by
/// skipping bad rows; methods return normalized event objects.
/// </summary>
public sealed class FileLiveEventSource
{
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    /// <summary>
    /// Reads events from one artifact path.
    /// The input is a file path, processing selects JSON array or JSON Lines,
    /// and the method returns zero or more events.
    /// </summary>
    public IReadOnlyList<SandboxEvent> Read(string path)
    {
        if (!File.Exists(path))
        {
            return [];
        }

        return string.Equals(Path.GetExtension(path), ".jsonl", StringComparison.OrdinalIgnoreCase)
            ? ReadJsonLines(path)
            : JsonSerializer.Deserialize<List<SandboxEvent>>(File.ReadAllText(path), JsonOptions) ?? [];
    }

    /// <summary>
    /// Reads one JSON object per line.
    /// The input is a JSONL path, processing ignores malformed lines for live
    /// display, and the method returns parsed sandbox events.
    /// </summary>
    private static IReadOnlyList<SandboxEvent> ReadJsonLines(string path)
    {
        var events = new List<SandboxEvent>();
        foreach (var line in File.ReadLines(path))
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            try
            {
                var evt = JsonSerializer.Deserialize<SandboxEvent>(line, JsonOptions);
                if (evt is not null)
                {
                    events.Add(evt);
                }
            }
            catch (JsonException)
            {
            }
        }

        return events;
    }
}
