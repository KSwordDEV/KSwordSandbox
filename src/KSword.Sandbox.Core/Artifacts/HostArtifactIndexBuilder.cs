using KSword.Sandbox.Abstractions.Artifacts;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace KSword.Sandbox.Core.Artifacts;

/// <summary>
/// Builds and persists host-side artifact indexes for job directories.
/// Inputs are a job ID and job root; processing scans known report, telemetry,
/// screenshot, memory-dump, packet-capture, manifest, and dropped-file paths;
/// methods return index models or the descriptor for artifact-index.json.
/// </summary>
public sealed class HostArtifactIndexBuilder
{
    public const string IndexFileName = "artifact-index.json";

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    /// <summary>
    /// Builds an in-memory host artifact index.
    /// Inputs are a job ID and job root; processing recursively scans files and
    /// classifies known artifact names; the method returns a stable index.
    /// </summary>
    public HostArtifactIndex Build(Guid jobId, string jobRoot)
    {
        var fullJobRoot = Path.GetFullPath(jobRoot);
        var artifacts = new List<ArtifactDescriptor>();
        if (Directory.Exists(fullJobRoot))
        {
            foreach (var path in Directory.EnumerateFiles(fullJobRoot, "*", SearchOption.AllDirectories)
                .Where(path => !string.Equals(Path.GetFileName(path), IndexFileName, StringComparison.OrdinalIgnoreCase))
                .OrderBy(path => ArtifactDescriptorFactory.SafeRelativePath(fullJobRoot, path), StringComparer.OrdinalIgnoreCase))
            {
                var classification = Classify(path, fullJobRoot);
                if (classification.Kind == ArtifactKind.Unknown)
                {
                    continue;
                }

                var metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["origin"] = "host",
                    ["indexRoot"] = fullJobRoot,
                    ["importPath"] = ArtifactDescriptorFactory.SafeRelativePath(fullJobRoot, path)
                };
                if (!string.IsNullOrWhiteSpace(classification.EvidenceRole))
                {
                    metadata["evidenceRole"] = classification.EvidenceRole;
                }

                if (!string.IsNullOrWhiteSpace(classification.CollectionName))
                {
                    metadata["collectionName"] = classification.CollectionName;
                }

                if (!string.IsNullOrWhiteSpace(classification.CapturePhase))
                {
                    metadata["capturePhase"] = classification.CapturePhase;
                }

                if (!string.IsNullOrWhiteSpace(classification.CaptureState))
                {
                    metadata["captureState"] = classification.CaptureState;
                }

                foreach (var pair in classification.Metadata ?? EmptyMetadata)
                {
                    metadata[pair.Key] = pair.Value;
                }

                artifacts.Add(ArtifactDescriptorFactory.FromExistingFile(
                    path,
                    fullJobRoot,
                    classification.Kind,
                    metadata,
                    classification.Category));
            }
        }

        return new HostArtifactIndex
        {
            JobId = jobId,
            RootPath = fullJobRoot,
            GeneratedAtUtc = DateTimeOffset.UtcNow,
            Collections = BuildCollections(artifacts),
            Artifacts = artifacts
        };
    }

    /// <summary>
    /// Writes artifact-index.json under the job root.
    /// Inputs are a job ID and job root; processing builds and serializes the
    /// index; the method returns a descriptor for the index artifact.
    /// </summary>
    public ArtifactDescriptor WriteIndex(Guid jobId, string jobRoot)
    {
        var fullJobRoot = Path.GetFullPath(jobRoot);
        Directory.CreateDirectory(fullJobRoot);
        var index = Build(jobId, fullJobRoot);
        var indexPath = Path.Combine(fullJobRoot, IndexFileName);
        File.WriteAllText(indexPath, JsonSerializer.Serialize(index, JsonOptions));
        return ArtifactDescriptorFactory.FromExistingFile(
            indexPath,
            fullJobRoot,
            ArtifactKind.ArtifactIndex,
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["origin"] = "host",
                ["schemaVersion"] = index.SchemaVersion.ToString()
            });
    }

    /// <summary>
    /// Reads artifact-index.json when it exists.
    /// Inputs are a job root; processing deserializes the index; the method
    /// returns null when no index has been written.
    /// </summary>
    public HostArtifactIndex? TryReadIndex(string jobRoot)
    {
        var indexPath = Path.Combine(Path.GetFullPath(jobRoot), IndexFileName);
        if (!File.Exists(indexPath))
        {
            return null;
        }

        return JsonSerializer.Deserialize<HostArtifactIndex>(File.ReadAllText(indexPath), JsonOptions);
    }

    private static ArtifactClassification Classify(string path, string jobRoot)
    {
        var fileName = Path.GetFileName(path);
        var relativePath = ArtifactDescriptorFactory.SafeRelativePath(jobRoot, path);
        if (string.Equals(fileName, "report.json", StringComparison.OrdinalIgnoreCase))
        {
            return new ArtifactClassification(ArtifactKind.ReportJson);
        }

        if (string.Equals(fileName, "report.html", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(fileName, "report.zh.html", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(fileName, "report.en.html", StringComparison.OrdinalIgnoreCase))
        {
            return new ArtifactClassification(ArtifactKind.ReportHtml);
        }

        if (string.Equals(fileName, "runbook.json", StringComparison.OrdinalIgnoreCase))
        {
            return new ArtifactClassification(ArtifactKind.RunbookJson);
        }

        if (string.Equals(fileName, "runbook-execution.json", StringComparison.OrdinalIgnoreCase))
        {
            return new ArtifactClassification(ArtifactKind.RunbookExecutionJson);
        }

        if (string.Equals(fileName, "events.json", StringComparison.OrdinalIgnoreCase))
        {
            return new ArtifactClassification(ArtifactKind.GuestEventsJson);
        }

        if (string.Equals(fileName, "agent-summary.json", StringComparison.OrdinalIgnoreCase))
        {
            return new ArtifactClassification(ArtifactKind.GuestSummaryJson);
        }

        if (string.Equals(fileName, "artifact-manifest.json", StringComparison.OrdinalIgnoreCase) ||
            relativePath.EndsWith("/artifacts/manifest.json", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(relativePath, "artifacts/manifest.json", StringComparison.OrdinalIgnoreCase))
        {
            return new ArtifactClassification(ArtifactKind.ArtifactManifest);
        }

        if (string.Equals(Path.GetExtension(path), ".jsonl", StringComparison.OrdinalIgnoreCase) &&
            fileName.Contains("driver", StringComparison.OrdinalIgnoreCase))
        {
            return new ArtifactClassification(ArtifactKind.DriverEventsJsonLines, EvidenceRole: "driver-events", CollectionName: "driver-events");
        }

        if (relativePath.Contains("/screenshots/", StringComparison.OrdinalIgnoreCase) ||
            relativePath.StartsWith("screenshots/", StringComparison.OrdinalIgnoreCase))
        {
            return new ArtifactClassification(ArtifactKind.Screenshot, EvidenceRole: "screenshot", CollectionName: "screenshots", CapturePhase: InferCapturePhase(fileName));
        }

        if (relativePath.Contains("/memory-dumps/", StringComparison.OrdinalIgnoreCase) ||
            relativePath.StartsWith("memory-dumps/", StringComparison.OrdinalIgnoreCase))
        {
            return new ArtifactClassification(ArtifactKind.MemoryDump, Category: "memory-dump", EvidenceRole: "memory-dump", CollectionName: "memory-dumps", CapturePhase: InferCapturePhase(fileName));
        }

        if (relativePath.Contains("/packet-captures/", StringComparison.OrdinalIgnoreCase) ||
            relativePath.StartsWith("packet-captures/", StringComparison.OrdinalIgnoreCase) ||
            ArtifactDescriptorFactory.IsPacketCapturePath(path))
        {
            return new ArtifactClassification(
                ArtifactKind.PacketCapture,
                Category: "packet-capture",
                EvidenceRole: "packet-capture",
                CollectionName: "packet-captures",
                CapturePhase: InferCapturePhase(fileName),
                CaptureState: "available",
                Metadata: BuildPacketCaptureMetadata(path));
        }

        if (relativePath.Contains("/artifacts/", StringComparison.OrdinalIgnoreCase) ||
            relativePath.StartsWith("artifacts/", StringComparison.OrdinalIgnoreCase))
        {
            return new ArtifactClassification(ArtifactKind.DroppedFile, EvidenceRole: "dropped-file", CollectionName: "dropped-files");
        }

        if (string.Equals(Path.GetExtension(path), ".log", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(Path.GetExtension(path), ".txt", StringComparison.OrdinalIgnoreCase))
        {
            return new ArtifactClassification(ArtifactKind.Log, CollectionName: "logs");
        }

        return new ArtifactClassification(ArtifactKind.Unknown);
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

    private static List<ArtifactCollectionDescriptor> BuildCollections(IEnumerable<ArtifactDescriptor> artifacts)
    {
        return artifacts
            .Where(artifact => !string.IsNullOrWhiteSpace(artifact.CollectionName))
            .GroupBy(artifact => artifact.CollectionName, StringComparer.OrdinalIgnoreCase)
            .OrderBy(group => group.Key, StringComparer.OrdinalIgnoreCase)
            .Select(group => BuildCollection(group.Key, group.OrderBy(artifact => artifact.RelativePath, StringComparer.OrdinalIgnoreCase).ToList()))
            .ToList();
    }

    private static ArtifactCollectionDescriptor BuildCollection(string collectionName, IReadOnlyList<ArtifactDescriptor> artifacts)
    {
        var first = artifacts[0];
        var relativePath = InferCollectionRelativePath(collectionName, artifacts);
        var mimeTypes = artifacts
            .Select(artifact => artifact.MimeType)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
            .ToList();
        var metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["origin"] = "host",
            ["discoveredBy"] = nameof(HostArtifactIndexBuilder),
            ["artifactCount"] = artifacts.Count.ToString(CultureInfo.InvariantCulture),
            ["totalBytes"] = artifacts.Sum(artifact => artifact.SizeBytes).ToString(CultureInfo.InvariantCulture)
        };
        if (mimeTypes.Count > 0)
        {
            metadata["mimeTypes"] = string.Join(",", mimeTypes);
        }

        if (string.Equals(collectionName, "packet-captures", StringComparison.OrdinalIgnoreCase))
        {
            metadata["captureSource"] = "external";
            metadata["hostCaptureStarted"] = "false";
            metadata["importMode"] = "external-artifact";
            metadata["extensions"] = string.Join(
                ",",
                artifacts
                    .Select(artifact => Path.GetExtension(artifact.Name).ToLowerInvariant())
                    .Where(extension => !string.IsNullOrWhiteSpace(extension))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(extension => extension, StringComparer.OrdinalIgnoreCase));
        }

        return new ArtifactCollectionDescriptor
        {
            Name = collectionName,
            Kind = artifacts.Select(artifact => artifact.Kind).Distinct().Count() == 1
                ? first.Kind
                : ArtifactKind.Unknown,
            Category = first.Category,
            EvidenceRole = first.EvidenceRole,
            RelativePath = relativePath,
            SafeLink = ArtifactDescriptorFactory.BuildSafeLink(relativePath),
            ImportPath = relativePath,
            Enabled = true,
            Implemented = true,
            Status = "captured",
            Reason = string.Equals(collectionName, "packet-captures", StringComparison.OrdinalIgnoreCase)
                ? "external-pcap-artifacts-indexed"
                : string.Empty,
            Metadata = metadata
        };
    }

    private static string InferCollectionRelativePath(string collectionName, IReadOnlyList<ArtifactDescriptor> artifacts)
    {
        foreach (var artifact in artifacts)
        {
            var relativePath = ArtifactDescriptorFactory.NormalizeRelativePath(artifact.RelativePath);
            var segments = relativePath.Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            for (var index = 0; index < segments.Length; index++)
            {
                if (string.Equals(segments[index], collectionName, StringComparison.OrdinalIgnoreCase))
                {
                    return string.Join("/", segments.Take(index + 1));
                }
            }
        }

        return CommonDirectory(artifacts
            .Select(artifact => ArtifactDescriptorFactory.NormalizeRelativePath(artifact.RelativePath))
            .Where(path => !string.IsNullOrWhiteSpace(path)));
    }

    private static string CommonDirectory(IEnumerable<string> relativePaths)
    {
        var directories = relativePaths
            .Select(path => path.Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .Where(segments => segments.Length > 1)
            .Select(segments => segments.Take(segments.Length - 1).ToArray())
            .ToList();
        if (directories.Count == 0)
        {
            return string.Empty;
        }

        var prefix = directories[0].ToList();
        foreach (var directory in directories.Skip(1))
        {
            var length = 0;
            while (length < prefix.Count &&
                length < directory.Length &&
                string.Equals(prefix[length], directory[length], StringComparison.OrdinalIgnoreCase))
            {
                length++;
            }

            prefix = prefix.Take(length).ToList();
            if (prefix.Count == 0)
            {
                break;
            }
        }

        return string.Join("/", prefix);
    }

    private static IReadOnlyDictionary<string, string> BuildPacketCaptureMetadata(string path)
    {
        var extension = Path.GetExtension(path).ToLowerInvariant();
        return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["captureSource"] = "external",
            ["hostCaptureStarted"] = "false",
            ["importMode"] = "external-artifact",
            ["pcapFormat"] = string.Equals(extension, ".pcapng", StringComparison.OrdinalIgnoreCase)
                ? "pcapng"
                : string.Equals(extension, ".pcap", StringComparison.OrdinalIgnoreCase)
                    ? "pcap"
                    : "unknown"
        };
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
