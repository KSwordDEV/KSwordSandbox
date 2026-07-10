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

        try
        {
            return string.Equals(Path.GetExtension(path), ".jsonl", StringComparison.OrdinalIgnoreCase)
                ? ReadJsonLines(path)
                : ReadJsonArray(path);
        }
        catch (IOException)
        {
            return [];
        }
        catch (UnauthorizedAccessException)
        {
            return [];
        }
        catch (JsonException)
        {
            return [];
        }
    }

    /// <summary>
    /// Reads a JSON event array through a shared file handle.
    /// The input may still be open by the live Hyper-V sync loop; processing
    /// uses read/write/delete sharing and returns an empty page for partial
    /// JSON instead of failing the WebUI endpoint.
    /// </summary>
    private static IReadOnlyList<SandboxEvent> ReadJsonArray(string path)
    {
        using var stream = OpenSharedRead(path);
        return JsonSerializer.Deserialize<List<SandboxEvent>>(stream, JsonOptions) ?? [];
    }

    /// <summary>
    /// Reads one JSON object per line.
    /// The input is a JSONL path, processing ignores malformed lines for live
    /// display, and the method returns parsed sandbox events.
    /// </summary>
    private static IReadOnlyList<SandboxEvent> ReadJsonLines(string path)
    {
        var events = new List<SandboxEvent>();
        using var stream = OpenSharedRead(path);
        using var reader = new StreamReader(stream);
        while (reader.ReadLine() is { } line)
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
}
