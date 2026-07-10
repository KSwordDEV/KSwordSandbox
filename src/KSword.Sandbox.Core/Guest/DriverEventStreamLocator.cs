namespace KSword.Sandbox.Core.Guest;

/// <summary>
/// Finds R0 collector JSON Lines streams in a collected guest output tree.
/// Inputs are host-side output paths; processing applies strict file-name
/// filters; methods return candidate driver event stream paths.
/// </summary>
public sealed class DriverEventStreamLocator
{
    /// <summary>
    /// Enumerates likely driver event JSONL files.
    /// The input is a guest output root, processing searches recursively for
    /// driver-prefixed JSONL files, and the method returns ordered paths.
    /// </summary>
    public IReadOnlyList<string> EnumerateDriverStreams(string guestOutputRoot)
    {
        if (!Directory.Exists(guestOutputRoot))
        {
            return [];
        }

        return Directory.EnumerateFiles(guestOutputRoot, "*.jsonl", SearchOption.AllDirectories)
            .Where(path => Path.GetFileName(path).Contains("driver", StringComparison.OrdinalIgnoreCase))
            .OrderBy(File.GetLastWriteTimeUtc)
            .ToList();
    }
}
