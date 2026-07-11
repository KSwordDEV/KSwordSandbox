using KSword.Sandbox.Abstractions.Artifacts;
using KSword.Sandbox.Core.Artifacts;

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
        return EnumerateFilesSafely(guestOutputRoot)
            .Where(path => string.Equals(Path.GetFileName(path), "events.json", StringComparison.OrdinalIgnoreCase) ||
                           string.Equals(Path.GetExtension(path), ".jsonl", StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(GetLastWriteTimeUtcSafe)
            .ThenBy(path => path, StringComparer.OrdinalIgnoreCase)
            .Select(Path.GetFullPath)
            .ToList();
    }

    /// <summary>
    /// Enumerates all host-visible guest output artifacts that should be linked
    /// from UI/report evidence surfaces.
    /// Inputs are a collected guest output root; processing classifies known
    /// telemetry, manifest, screenshot, dropped-file, packet-capture, and memory
    /// dump paths; descriptors expose safe relative links, not absolute hrefs.
    /// </summary>
    public IReadOnlyList<ArtifactDescriptor> EnumerateArtifacts(string guestOutputRoot)
    {
        if (string.IsNullOrWhiteSpace(guestOutputRoot) || !Directory.Exists(guestOutputRoot))
        {
            return [];
        }

        var fullRoot = Path.GetFullPath(guestOutputRoot);
        return EnumerateFilesSafely(fullRoot)
            .Select(path => TryCreateDescriptor(path, fullRoot))
            .Where(descriptor => descriptor is not null)
            .Select(descriptor => descriptor!)
            .OrderBy(descriptor => descriptor.RelativePath, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static ArtifactDescriptor? TryCreateDescriptor(string path, string guestOutputRoot)
    {
        var classification = Classify(path, guestOutputRoot);
        if (classification.Kind == ArtifactKind.Unknown)
        {
            return null;
        }

        var relativePath = ArtifactDescriptorFactory.SafeRelativePath(guestOutputRoot, path);
        if (string.IsNullOrWhiteSpace(relativePath))
        {
            return null;
        }

        var metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["origin"] = "guest-output",
            ["guestOutputRoot"] = guestOutputRoot,
            ["importPath"] = relativePath,
            ["hrefPolicy"] = "relative-safe-link-only"
        };
        AddIfNotEmpty(metadata, "evidenceRole", classification.EvidenceRole);
        AddIfNotEmpty(metadata, "collectionName", classification.CollectionName);
        AddIfNotEmpty(metadata, "capturePhase", classification.CapturePhase);
        AddIfNotEmpty(metadata, "captureState", classification.CaptureState);
        foreach (var pair in classification.Metadata ?? EmptyMetadata)
        {
            metadata[pair.Key] = pair.Value;
        }

        return ArtifactDescriptorFactory.FromExistingFile(path, guestOutputRoot, classification.Kind, metadata, classification.Category);
    }

    private static ArtifactClassification Classify(string path, string guestOutputRoot)
    {
        var fileName = Path.GetFileName(path);
        var relativePath = ArtifactDescriptorFactory.SafeRelativePath(guestOutputRoot, path);
        if (string.IsNullOrWhiteSpace(relativePath))
        {
            return new ArtifactClassification(ArtifactKind.Unknown);
        }

        if (string.Equals(fileName, "events.json", StringComparison.OrdinalIgnoreCase))
        {
            return new ArtifactClassification(
                ArtifactKind.GuestEventsJson,
                EvidenceRole: "guest-events",
                CollectionName: "guest-events",
                CaptureState: "available",
                Metadata: new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["telemetryFormat"] = "json",
                    ["telemetrySource"] = "guest-agent"
                });
        }

        if (string.Equals(fileName, "driver-events.jsonl", StringComparison.OrdinalIgnoreCase) ||
            (string.Equals(Path.GetExtension(path), ".jsonl", StringComparison.OrdinalIgnoreCase) &&
                fileName.Contains("driver", StringComparison.OrdinalIgnoreCase)))
        {
            return new ArtifactClassification(
                ArtifactKind.DriverEventsJsonLines,
                EvidenceRole: "driver-events",
                CollectionName: "driver-events",
                CaptureState: "available",
                Metadata: new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["telemetryFormat"] = "jsonl",
                    ["telemetrySource"] = "r0collector"
                });
        }

        if (string.Equals(fileName, GuestArtifactManifestReader.ManifestFileName, StringComparison.OrdinalIgnoreCase) &&
            (relativePath.EndsWith($"/{GuestArtifactManifestReader.ArtifactsDirectoryName}/{GuestArtifactManifestReader.ManifestFileName}", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(relativePath, $"{GuestArtifactManifestReader.ArtifactsDirectoryName}/{GuestArtifactManifestReader.ManifestFileName}", StringComparison.OrdinalIgnoreCase)))
        {
            return new ArtifactClassification(
                ArtifactKind.ArtifactManifest,
                EvidenceRole: "artifact-manifest",
                CollectionName: "artifact-manifests",
                CaptureState: "available");
        }

        if (relativePath.Contains("/screenshots/", StringComparison.OrdinalIgnoreCase) ||
            relativePath.StartsWith("screenshots/", StringComparison.OrdinalIgnoreCase))
        {
            return new ArtifactClassification(
                ArtifactKind.Screenshot,
                EvidenceRole: "screenshot",
                CollectionName: "screenshots",
                CapturePhase: InferCapturePhase(fileName),
                CaptureState: "captured");
        }

        if (relativePath.Contains("/memory-dumps/", StringComparison.OrdinalIgnoreCase) ||
            relativePath.StartsWith("memory-dumps/", StringComparison.OrdinalIgnoreCase))
        {
            return new ArtifactClassification(
                ArtifactKind.MemoryDump,
                EvidenceRole: "memory-dump",
                CollectionName: "memory-dumps",
                CapturePhase: InferCapturePhase(fileName),
                CaptureState: "captured");
        }

        if (relativePath.Contains("/packet-captures/", StringComparison.OrdinalIgnoreCase) ||
            relativePath.StartsWith("packet-captures/", StringComparison.OrdinalIgnoreCase) ||
            ArtifactDescriptorFactory.IsPacketCapturePath(path))
        {
            return new ArtifactClassification(
                ArtifactKind.PacketCapture,
                EvidenceRole: "packet-capture",
                CollectionName: "packet-captures",
                CapturePhase: InferCapturePhase(fileName),
                CaptureState: "available",
                Metadata: new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["captureSource"] = "external",
                    ["hostCaptureStarted"] = "false",
                    ["importMode"] = "external-artifact",
                    ["pcapFormat"] = string.Equals(Path.GetExtension(path), ".pcapng", StringComparison.OrdinalIgnoreCase)
                        ? "pcapng"
                        : string.Equals(Path.GetExtension(path), ".pcap", StringComparison.OrdinalIgnoreCase)
                            ? "pcap"
                            : "unknown"
                });
        }

        if (relativePath.Contains("/artifacts/dropped-files/", StringComparison.OrdinalIgnoreCase) ||
            relativePath.StartsWith("artifacts/dropped-files/", StringComparison.OrdinalIgnoreCase) ||
            ((relativePath.Contains("/artifacts/", StringComparison.OrdinalIgnoreCase) ||
                relativePath.StartsWith("artifacts/", StringComparison.OrdinalIgnoreCase)) &&
                !relativePath.EndsWith("/artifacts/manifest.json", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(relativePath, "artifacts/manifest.json", StringComparison.OrdinalIgnoreCase)))
        {
            return new ArtifactClassification(
                ArtifactKind.DroppedFile,
                EvidenceRole: "dropped-file",
                CollectionName: "dropped-files",
                CaptureState: "captured");
        }

        if (string.Equals(fileName, "agent-summary.json", StringComparison.OrdinalIgnoreCase))
        {
            return new ArtifactClassification(
                ArtifactKind.GuestSummaryJson,
                EvidenceRole: "guest-summary",
                CollectionName: "guest-summary",
                CaptureState: "available");
        }

        return new ArtifactClassification(ArtifactKind.Unknown);
    }

    private static IEnumerable<string> EnumerateFilesSafely(string root)
    {
        if (string.IsNullOrWhiteSpace(root) || !Directory.Exists(root))
        {
            yield break;
        }

        string[] paths;
        try
        {
            paths = Directory.GetFiles(root, "*.*", SearchOption.AllDirectories);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or DirectoryNotFoundException)
        {
            yield break;
        }

        foreach (var path in paths)
        {
            yield return path;
        }
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

    private static string? InferCapturePhase(string fileName)
    {
        if (fileName.StartsWith("after-start", StringComparison.OrdinalIgnoreCase))
        {
            return "after-start";
        }

        if (fileName.StartsWith("after-run", StringComparison.OrdinalIgnoreCase))
        {
            return "after-run";
        }

        if (fileName.StartsWith("before-start", StringComparison.OrdinalIgnoreCase))
        {
            return "before-start";
        }

        return null;
    }

    private static void AddIfNotEmpty(Dictionary<string, string> metadata, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            metadata[key] = value;
        }
    }

    private static readonly IReadOnlyDictionary<string, string> EmptyMetadata =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    private sealed record ArtifactClassification(
        ArtifactKind Kind,
        string? Category = null,
        string? EvidenceRole = null,
        string? CollectionName = null,
        string? CapturePhase = null,
        string? CaptureState = null,
        IReadOnlyDictionary<string, string>? Metadata = null);
}
