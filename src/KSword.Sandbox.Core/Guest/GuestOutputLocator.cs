namespace KSword.Sandbox.Core.Guest;

/// <summary>
/// Locates guest-produced JSON and JSONL artifacts after or during a run.
/// Inputs are host-side guest output folders; processing searches newest files
/// first; methods return candidate artifact paths.
/// </summary>
public sealed class GuestOutputLocator
{
    /// <summary>
    /// Enumerates event artifacts under a guest output root.
    /// The input is a directory path, processing filters events.json and JSONL
    /// files, and the method returns ordered paths.
    /// </summary>
    public IReadOnlyList<string> EnumerateEventArtifacts(string guestOutputRoot)
    {
        if (!Directory.Exists(guestOutputRoot))
        {
            return [];
        }

        return Directory.EnumerateFiles(guestOutputRoot, "*.*", SearchOption.AllDirectories)
            .Where(path => string.Equals(Path.GetFileName(path), "events.json", StringComparison.OrdinalIgnoreCase) ||
                           string.Equals(Path.GetExtension(path), ".jsonl", StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(File.GetLastWriteTimeUtc)
            .ToList();
    }
}
