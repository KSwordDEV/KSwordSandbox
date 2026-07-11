using KSword.Sandbox.Abstractions.Artifacts;
using KSword.Sandbox.Core.Artifacts;

namespace KSword.Sandbox.Core.Guest;

/// <summary>
/// Finds R0 collector JSON Lines streams in a collected guest output tree.
/// Inputs are host-side output paths; processing applies strict file-name
/// filters; methods return candidate driver event stream paths.
/// </summary>
public sealed class DriverEventStreamLocator
{
    public const string CanonicalFileName = "driver-events.jsonl";

    /// <summary>
    /// Enumerates likely driver event JSONL files.
    /// The input is a guest output root, processing searches recursively for
    /// driver-prefixed JSONL files, and the method returns ordered paths.
    /// </summary>
    public IReadOnlyList<string> EnumerateDriverStreams(string guestOutputRoot)
    {
        return EnumerateDriverStreamArtifacts(guestOutputRoot)
            .Select(descriptor => descriptor.FullPath)
            .ToList();
    }

    /// <summary>
    /// Enumerates likely driver event JSONL files as artifact descriptors.
    /// Inputs are a collected guest output root; processing prefers canonical
    /// driver-events.jsonl and falls back to driver-named JSONL streams; returned
    /// descriptors carry safe relative links and JSONL telemetry metadata.
    /// </summary>
    public IReadOnlyList<ArtifactDescriptor> EnumerateDriverStreamArtifacts(string guestOutputRoot)
    {
        if (string.IsNullOrWhiteSpace(guestOutputRoot) || !Directory.Exists(guestOutputRoot))
        {
            return [];
        }

        var fullRoot = Path.GetFullPath(guestOutputRoot);
        return EnumerateFilesSafely(fullRoot)
            .Where(path => string.Equals(Path.GetExtension(path), ".jsonl", StringComparison.OrdinalIgnoreCase) &&
                Path.GetFileName(path).Contains("driver", StringComparison.OrdinalIgnoreCase))
            .OrderBy(path => string.Equals(Path.GetFileName(path), CanonicalFileName, StringComparison.OrdinalIgnoreCase) ? 0 : 1)
            .ThenBy(GetLastWriteTimeUtcSafe)
            .ThenBy(path => path, StringComparer.OrdinalIgnoreCase)
            .Select(path => CreateDescriptor(path, fullRoot))
            .Where(descriptor => descriptor is not null)
            .Select(descriptor => descriptor!)
            .ToList();
    }

    private static ArtifactDescriptor? CreateDescriptor(string path, string guestOutputRoot)
    {
        var relativePath = ArtifactDescriptorFactory.SafeRelativePath(guestOutputRoot, path);
        if (string.IsNullOrWhiteSpace(relativePath))
        {
            return null;
        }

        var metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["origin"] = "guest-output",
            ["importPath"] = relativePath,
            ["evidenceRole"] = "driver-events",
            ["collectionName"] = "driver-events",
            ["captureState"] = "available",
            ["telemetryFormat"] = "jsonl",
            ["telemetrySource"] = "r0collector",
            ["hrefPolicy"] = "relative-safe-link-only"
        };

        return ArtifactDescriptorFactory.FromExistingFile(
            path,
            guestOutputRoot,
            ArtifactKind.DriverEventsJsonLines,
            metadata);
    }

    private static IEnumerable<string> EnumerateFilesSafely(string root)
    {
        string[] paths;
        try
        {
            paths = Directory.GetFiles(root, "*.jsonl", SearchOption.AllDirectories);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or DirectoryNotFoundException)
        {
            return [];
        }

        return paths;
    }

    private static DateTime GetLastWriteTimeUtcSafe(string path)
    {
        try
        {
            return File.GetLastWriteTimeUtc(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or FileNotFoundException)
        {
            return DateTime.MinValue;
        }
    }
}
