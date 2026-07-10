using System.Text.Json;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Agent.Output;

/// <summary>
/// Writes guest events and summaries into the configured output directory.
/// Inputs are output paths and event lists; processing serializes JSON files;
/// methods return paths to written artifacts.
/// </summary>
internal sealed class GuestArtifactWriter
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true
    };

    /// <summary>
    /// Writes events.json to an output directory.
    /// Inputs are output directory and events, processing creates the directory
    /// and serializes events, and the method returns the file path.
    /// </summary>
    public string WriteEvents(string outputDirectory, IReadOnlyList<SandboxEvent> events)
    {
        Directory.CreateDirectory(outputDirectory);
        var path = Path.Combine(outputDirectory, "events.json");
        File.WriteAllText(path, JsonSerializer.Serialize(events, JsonOptions));
        return path;
    }

    /// <summary>
    /// Writes a compact agent summary JSON file.
    /// Inputs are output directory, sample path, and event count; processing
    /// serializes summary metadata; the method returns the file path.
    /// </summary>
    public string WriteSummary(string outputDirectory, string samplePath, int eventCount)
    {
        Directory.CreateDirectory(outputDirectory);
        var path = Path.Combine(outputDirectory, "agent-summary.json");
        File.WriteAllText(path, JsonSerializer.Serialize(new
        {
            sample = samplePath,
            eventCount,
            generatedAt = DateTimeOffset.UtcNow
        }, JsonOptions));
        return path;
    }
}
