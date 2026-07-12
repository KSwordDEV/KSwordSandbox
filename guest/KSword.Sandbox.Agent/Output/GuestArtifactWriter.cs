using System.Text.Json;
using System.Text.Json.Serialization;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Abstractions.Artifacts;

namespace KSword.Sandbox.Agent.Output;

/// <summary>
/// Describes the result of writing a guest-side artifact manifest.
/// Inputs are produced by GuestArtifactWriter; processing is immutable storage;
/// callers use the manifest path and descriptor/collection counts for events.
/// </summary>
internal sealed record GuestArtifactManifestWriteResult(string ManifestPath, int ArtifactCount, int CollectionCount);

/// <summary>
/// Preserves original dropped-file evidence metadata for copied artifacts.
/// Inputs are the VM-local source path, source-relative path, and source event;
/// processing stores strings for manifest metadata only.
/// </summary>
internal sealed record DroppedFileArtifactMetadata(
    string OriginalFullPath,
    string OriginalRelativePath,
    string SourceEventType,
    long? OriginalSizeBytes = null,
    DateTime? OriginalCreationTimeUtc = null,
    DateTime? OriginalLastWriteTimeUtc = null,
    DateTimeOffset? SourceEventTimestampUtc = null,
    DateTimeOffset? CopiedAtUtc = null,
    string? OriginalSha256 = null,
    string? CopiedSha256 = null);

/// <summary>
/// Carries operator-selected guest artifact collection options into manifest
/// serialization. Inputs are parsed CLI flags and sidecar settings; processing
/// records collection-lane status without enabling sensitive capture by default.
/// </summary>
internal sealed record GuestArtifactCollectionOptions
{
    public bool CaptureScreenshots { get; init; }

    public bool CollectDroppedFiles { get; init; }

    public bool CaptureMemoryDump { get; init; }

    public bool CapturePacketCapture { get; init; }

    public bool DriverEventsRequested { get; init; }

    public bool R0CollectorRequested { get; init; }
}

/// <summary>
/// Writes guest events, summaries, and artifact manifests into the configured
/// output directory. Inputs are output paths and event lists; processing
/// serializes JSON files and builds safe artifact descriptors; methods return
/// paths to written artifacts.
/// </summary>
internal sealed class GuestArtifactWriter
{
    public const string ArtifactsDirectoryName = "artifacts";

    public const string ManifestFileName = "manifest.json";

    private const string DroppedFilesDirectoryName = "dropped-files";

    private const string ScreenshotsDirectoryName = "screenshots";

    private const string MemoryDumpsDirectoryName = "memory-dumps";

    private const string PacketCapturesDirectoryName = "packet-captures";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true
    };

    private static readonly JsonSerializerOptions ManifestJsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
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

    /// <summary>
    /// Writes artifacts/manifest.json for durable guest-side artifacts.
    /// Inputs are the output directory created by --out; processing scans known
    /// artifact folders and serializes a manifest; the method returns the path.
    /// </summary>
    public string WriteArtifactManifest(string outputDirectory)
    {
        return WriteArtifactManifest(
            outputDirectory,
            metadataByRelativePath: null,
            events: Array.Empty<SandboxEvent>(),
            collectionOptions: new GuestArtifactCollectionOptions()).ManifestPath;
    }

    /// <summary>
    /// Writes artifacts/manifest.json with optional original source metadata.
    /// Inputs are the output directory and copied artifact metadata keyed by
    /// manifest-relative path; processing records size/hash/path metadata and
    /// preserves original guest paths; the method returns write metadata.
    /// </summary>
    public GuestArtifactManifestWriteResult WriteArtifactManifest(
        string outputDirectory,
        IReadOnlyDictionary<string, DroppedFileArtifactMetadata>? metadataByRelativePath)
    {
        return WriteArtifactManifest(
            outputDirectory,
            metadataByRelativePath,
            events: Array.Empty<SandboxEvent>(),
            collectionOptions: new GuestArtifactCollectionOptions());
    }

    /// <summary>
    /// Writes artifacts/manifest.json with descriptors and collection lanes.
    /// Inputs are the output directory, optional dropped-file metadata, collected
    /// events, and collection options; processing scans only safe paths below
    /// the output root; the method returns write metadata.
    /// </summary>
    public GuestArtifactManifestWriteResult WriteArtifactManifest(
        string outputDirectory,
        IReadOnlyDictionary<string, DroppedFileArtifactMetadata>? metadataByRelativePath,
        IReadOnlyList<SandboxEvent>? events,
        GuestArtifactCollectionOptions? collectionOptions)
    {
        Directory.CreateDirectory(outputDirectory);
        var fullOutputDirectory = Path.GetFullPath(outputDirectory);
        var artifactsRoot = Path.Combine(fullOutputDirectory, ArtifactsDirectoryName);
        Directory.CreateDirectory(artifactsRoot);
        var manifestPath = Path.Combine(artifactsRoot, ManifestFileName);
        var safeEvents = events ?? Array.Empty<SandboxEvent>();
        var descriptorEventMetadata = BuildEventMetadataByRelativePath(fullOutputDirectory, safeEvents);
        var descriptors = EnumerateArtifactDescriptors(
            fullOutputDirectory,
            manifestPath,
            metadataByRelativePath,
            descriptorEventMetadata);
        var collections = BuildCollections(
            descriptors,
            safeEvents,
            collectionOptions ?? new GuestArtifactCollectionOptions());
        var manifest = new ArtifactManifest
        {
            RuntimeRoot = fullOutputDirectory,
            RootPath = artifactsRoot,
            ImportRoot = fullOutputDirectory,
            Producer = "KSword.Sandbox.Agent",
            Collections = collections,
            Artifacts = descriptors
        };

        File.WriteAllText(manifestPath, JsonSerializer.Serialize(manifest, ManifestJsonOptions));
        return new GuestArtifactManifestWriteResult(manifestPath, descriptors.Count, collections.Count);
    }

    private static List<ArtifactDescriptor> EnumerateArtifactDescriptors(
        string outputDirectory,
        string manifestPath,
        IReadOnlyDictionary<string, DroppedFileArtifactMetadata>? droppedFileMetadataByRelativePath,
        IReadOnlyDictionary<string, Dictionary<string, string>> eventMetadataByRelativePath)
    {
        if (!Directory.Exists(outputDirectory))
        {
            return [];
        }

        var descriptors = new List<ArtifactDescriptor>();
        var fullManifestPath = Path.GetFullPath(manifestPath);
        foreach (var path in EnumerateFilesSafe(outputDirectory)
            .Select(Path.GetFullPath)
            .Where(path => !string.Equals(path, fullManifestPath, StringComparison.OrdinalIgnoreCase))
            .OrderBy(path => path, StringComparer.OrdinalIgnoreCase))
        {
            var relativePath = NormalizeRelativePath(Path.GetRelativePath(outputDirectory, path));
            if (string.IsNullOrWhiteSpace(relativePath) || !TryClassifyArtifact(relativePath, out var classification))
            {
                continue;
            }

            eventMetadataByRelativePath.TryGetValue(relativePath, out var eventMetadata);
            DroppedFileArtifactMetadata? droppedFileMetadata = null;
            droppedFileMetadataByRelativePath?.TryGetValue(relativePath, out droppedFileMetadata);
            try
            {
                descriptors.Add(CreateArtifactDescriptor(outputDirectory, path, relativePath, classification, eventMetadata, droppedFileMetadata));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException or PathTooLongException)
            {
                // A locked or disappearing optional artifact must not prevent
                // events.json, summary, or other evidence from being written.
            }
        }

        return descriptors;
    }

    private static ArtifactDescriptor CreateArtifactDescriptor(
        string outputDirectory,
        string path,
        string relativePath,
        ArtifactClassification classification,
        IReadOnlyDictionary<string, string>? eventMetadata,
        DroppedFileArtifactMetadata? droppedFileMetadata)
    {
        _ = outputDirectory;
        var info = new FileInfo(path);
        var sha256 = ComputeSha256(info.FullName);
        var metadata = CreateBaseMetadata(classification, info.FullName, relativePath, eventMetadata, droppedFileMetadata);
        AddDescriptorFileIntegrityMetadata(classification, metadata, info, sha256);
        return new ArtifactDescriptor
        {
            Kind = classification.Kind,
            Category = classification.Category,
            Name = info.Name,
            RelativePath = relativePath,
            FullPath = info.FullName,
            SafeLink = BuildSafeLink(relativePath),
            EvidenceRole = classification.EvidenceRole,
            CapturePhase = ValueOrEmpty(metadata, "capturePhase", "phase"),
            CaptureState = ValueOrEmpty(metadata, "captureState"),
            GuestPath = ValueOrEmpty(metadata, "guestFullPath", "guestPath"),
            ImportPath = relativePath,
            CollectionName = classification.CollectionName,
            MimeType = MimeTypeForPath(info.FullName),
            SizeBytes = info.Length,
            Sha256 = sha256,
            Hashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["sha256"] = sha256
            },
            CreatedAtUtc = info.CreationTimeUtc,
            Metadata = metadata
        };
    }

    private static Dictionary<string, string> CreateBaseMetadata(
        ArtifactClassification classification,
        string artifactFullPath,
        string relativePath,
        IReadOnlyDictionary<string, string>? eventMetadata,
        DroppedFileArtifactMetadata? droppedFileMetadata)
    {
        var metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (eventMetadata is not null)
        {
            foreach (var pair in eventMetadata)
            {
                AddIfNotEmpty(metadata, pair.Key, pair.Value);
            }
        }

        AddIfNotEmpty(metadata, "origin", "guest");
        AddIfNotEmpty(metadata, "evidenceRole", classification.EvidenceRole);
        AddIfNotEmpty(metadata, "collectionName", classification.CollectionName);
        AddIfNotEmpty(metadata, "artifactSemanticType", ArtifactSemanticTypeForClassification(classification));
        AddIfNotEmpty(metadata, "eventSemanticClass", $"artifact-{ArtifactSemanticTypeForClassification(classification)}");
        AddIfNotEmpty(metadata, "semanticEventCategory", "artifact-evidence");
        AddIfNotEmpty(metadata, "semanticEventTags", SemanticTagsForClassification(classification));
        AddIfNotEmpty(metadata, "behaviorCounted", "false");
        AddIfNotEmpty(metadata, "nonbehavior", "true");
        AddIfNotEmpty(metadata, "notSampleBehavior", "true");
        AddIfNotEmpty(metadata, "sampleBehaviorCandidate", "false");
        AddIfNotEmpty(metadata, "sampleBehaviorCandidateReason", "guest-artifact-descriptor");
        AddIfNotEmpty(metadata, "summaryRow", "false");
        AddIfNotEmpty(metadata, "reportRowKind", $"{ArtifactSemanticTypeForClassification(classification)}-artifact");
        AddIfNotEmpty(metadata, "capturePolicy", CapturePolicyForClassification(classification));
        AddIfNotEmpty(metadata, "importPath", relativePath);
        AddIfNotEmpty(metadata, "artifactRelativePath", relativePath);
        AddIfNotEmpty(metadata, "artifactSelector", relativePath);
        AddIfNotEmpty(metadata, "stableArtifactSelector", relativePath);
        AddIfNotEmpty(metadata, "canonicalArtifactSelector", relativePath);
        AddIfNotEmpty(metadata, "downloadSelector", relativePath);
        AddIfNotEmpty(metadata, "artifactSelectorKind", "safe-output-relative-path");
        AddIfNotEmpty(metadata, "artifactSelectorVersion", "artifact-selectors-v1");
        AddIfNotEmpty(metadata, "sourceArtifactRelativePath", relativePath);
        AddIfNotEmpty(metadata, "artifactFullPath", artifactFullPath);
        AddIfNotEmpty(metadata, "guestFullPath", FirstNonEmpty(droppedFileMetadata?.OriginalFullPath, ValueOrEmpty(metadata, "guestFullPath", "guestPath"), artifactFullPath));
        AddIfNotEmpty(metadata, "captureState", InferCaptureState(classification, metadata));
        AddPacketCaptureMetadataDefaults(classification, metadata, artifactFullPath);

        if (droppedFileMetadata is not null)
        {
            metadata["guestRelativePath"] = droppedFileMetadata.OriginalRelativePath;
            metadata["sourceEventType"] = droppedFileMetadata.SourceEventType;
            if (droppedFileMetadata.OriginalSizeBytes is not null)
            {
                metadata["originalSizeBytes"] = droppedFileMetadata.OriginalSizeBytes.Value.ToString(System.Globalization.CultureInfo.InvariantCulture);
                AddIfMissing(metadata, "sourceSizeBytes", metadata["originalSizeBytes"]);
            }

            if (droppedFileMetadata.OriginalCreationTimeUtc is not null)
            {
                metadata["originalCreationTimeUtc"] = droppedFileMetadata.OriginalCreationTimeUtc.Value.ToString("O", System.Globalization.CultureInfo.InvariantCulture);
            }

            if (droppedFileMetadata.OriginalLastWriteTimeUtc is not null)
            {
                metadata["originalLastWriteTimeUtc"] = droppedFileMetadata.OriginalLastWriteTimeUtc.Value.ToString("O", System.Globalization.CultureInfo.InvariantCulture);
                AddIfMissing(metadata, "sourceLastWriteUtc", metadata["originalLastWriteTimeUtc"]);
                AddIfMissing(metadata, "sourceMtimeUtc", metadata["originalLastWriteTimeUtc"]);
            }

            if (droppedFileMetadata.SourceEventTimestampUtc is not null)
            {
                metadata["sourceEventTimestampUtc"] = droppedFileMetadata.SourceEventTimestampUtc.Value.ToString("O", System.Globalization.CultureInfo.InvariantCulture);
            }

            if (droppedFileMetadata.CopiedAtUtc is not null)
            {
                metadata["copiedAtUtc"] = droppedFileMetadata.CopiedAtUtc.Value.ToString("O", System.Globalization.CultureInfo.InvariantCulture);
            }

            if (!string.IsNullOrWhiteSpace(droppedFileMetadata.OriginalSha256))
            {
                metadata["originalSha256"] = droppedFileMetadata.OriginalSha256;
                AddIfMissing(metadata, "sourceSha256", droppedFileMetadata.OriginalSha256);
                AddIfMissing(metadata, "sourceHashAlgorithm", "sha256");
            }

            if (!string.IsNullOrWhiteSpace(droppedFileMetadata.CopiedSha256))
            {
                metadata["copiedSha256"] = droppedFileMetadata.CopiedSha256;
                AddIfMissing(metadata, "artifactSha256", droppedFileMetadata.CopiedSha256);
            }
        }

        if (metadata.TryGetValue("phase", out var phase))
        {
            AddIfNotEmpty(metadata, "capturePhase", phase);
        }

        AddArtifactDescriptorQualityFallbacks(classification, metadata);
        return metadata;
    }

    private static void AddArtifactDescriptorQualityFallbacks(
        ArtifactClassification classification,
        Dictionary<string, string> metadata)
    {
        var artifactRelativePath = ValueOrEmpty(
            metadata,
            "artifactRelativePath",
            "relativePath",
            "importPath",
            "sourceArtifactRelativePath",
            "packetCaptureRelativePath",
            "pcapngRelativePath",
            "memoryDumpRelativePath",
            "screenshotRelativePath");
        AddStableFallback(metadata, "artifactRelativePath", artifactRelativePath);

        var rootProcessId = ValueOrEmpty(metadata, "rootProcessId", "processRootId", "rootPid");
        AddStableFallback(metadata, "rootProcessId", rootProcessId);

        var treeLineage = ValueOrEmpty(metadata, "treeLineage", "targetTreeLineage", "processTreeLineage");
        if (string.IsNullOrWhiteSpace(treeLineage) && !string.IsNullOrWhiteSpace(rootProcessId))
        {
            treeLineage = rootProcessId;
        }

        AddStableFallback(metadata, "treeLineage", treeLineage);
        AddIfMissing(metadata, "rootProcessIdStatus", string.IsNullOrWhiteSpace(rootProcessId) ? "unavailable" : "available");
        AddIfMissing(metadata, "treeLineageStatus", string.IsNullOrWhiteSpace(treeLineage) ? "unavailable" : "stable");
        AddIfMissing(metadata, "zhHint", ArtifactDescriptorZhHint(classification));
    }

    private static List<ArtifactCollectionDescriptor> BuildCollections(
        IReadOnlyList<ArtifactDescriptor> descriptors,
        IReadOnlyList<SandboxEvent> events,
        GuestArtifactCollectionOptions options)
    {
        return
        [
            CreateCollection(descriptors, events, "dropped-files", ArtifactKind.DroppedFile, "dropped-file", "dropped-file",
                CombineRelative(ArtifactsDirectoryName, DroppedFilesDirectoryName), options.CollectDroppedFiles, implemented: true,
                capturedEventPrefixes: ["artifact.dropped_file.copied"], skippedEventPrefixes: ["artifact.dropped_file.skipped"],
                disabledEventPrefixes: ["artifact.dropped_file.disabled"], reasonWhenDisabled: "collectDroppedFilesNotRequested"),
            CreateCollection(descriptors, events, "screenshots", ArtifactKind.Screenshot, "screenshot", "screenshot",
                ScreenshotsDirectoryName, options.CaptureScreenshots, implemented: true,
                capturedEventPrefixes: ["screenshot.captured"], skippedEventPrefixes: ["screenshot.skipped"],
                disabledEventPrefixes: ["screenshot.disabled"], reasonWhenDisabled: "screenshotNotRequested"),
            CreateCollection(descriptors, events, "memory-dumps", ArtifactKind.MemoryDump, "memory-dump", "memory-dump",
                MemoryDumpsDirectoryName, options.CaptureMemoryDump, implemented: true,
                capturedEventPrefixes: ["memory_dump.captured"], skippedEventPrefixes: ["memory_dump.skipped"],
                disabledEventPrefixes: ["memory_dump.disabled"], reasonWhenDisabled: "memoryDumpNotRequested"),
            CreateCollection(descriptors, events, "driver-events", ArtifactKind.DriverEventsJsonLines, "telemetry", "driver-events",
                FirstRelativePath(descriptors, "driver-events") ?? "driver-events.jsonl",
                options.DriverEventsRequested || descriptors.Any(artifact => string.Equals(artifact.CollectionName, "driver-events", StringComparison.OrdinalIgnoreCase)),
                implemented: true, capturedEventPrefixes: ["driver.load", "driver.process", "driver.file", "driver.registry", "driver.network", "driver.event", "driver.parse_error", "image.load", "r0collector.driver", "r0collector.exited"],
                skippedEventPrefixes: ["driver.events.missing", "r0collector.failed"], disabledEventPrefixes: [], reasonWhenDisabled: "driverEventsNotRequested",
                failedEventPrefixes: ["driver.read_error"]),
            CreateCollection(descriptors, events, "r0-logs", ArtifactKind.Log, "log", "diagnostic-log",
                FirstRelativePath(descriptors, "r0-logs") ?? "r0collector.stdout.log",
                options.R0CollectorRequested || descriptors.Any(artifact => string.Equals(artifact.CollectionName, "r0-logs", StringComparison.OrdinalIgnoreCase)),
                implemented: true, capturedEventPrefixes: ["r0collector.started", "r0collector.exited", "r0collector.failed"],
                skippedEventPrefixes: [], disabledEventPrefixes: [], reasonWhenDisabled: "r0CollectorNotRequested"),
            CreateCollection(descriptors, events, "packet-captures", ArtifactKind.PacketCapture, "packet-capture", "packet-capture",
                PacketCapturesDirectoryName, options.CapturePacketCapture, implemented: true,
                capturedEventPrefixes: ["packet_capture.captured"], skippedEventPrefixes: ["packet_capture.skipped"],
                disabledEventPrefixes: ["packet_capture.disabled"], reasonWhenDisabled: "packetCaptureNotRequested", failedEventPrefixes: ["packet_capture.failed"])
        ];
    }

    private static ArtifactCollectionDescriptor CreateCollection(
        IReadOnlyList<ArtifactDescriptor> descriptors,
        IReadOnlyList<SandboxEvent> events,
        string name,
        ArtifactKind kind,
        string category,
        string evidenceRole,
        string relativePath,
        bool enabled,
        bool implemented,
        IReadOnlyList<string> capturedEventPrefixes,
        IReadOnlyList<string> skippedEventPrefixes,
        IReadOnlyList<string> disabledEventPrefixes,
        string reasonWhenDisabled,
        IReadOnlyList<string>? failedEventPrefixes = null)
    {
        var artifactCount = descriptors.Count(artifact => string.Equals(artifact.CollectionName, name, StringComparison.OrdinalIgnoreCase));
        var capturedEventCount = CountEvents(events, capturedEventPrefixes);
        var skippedEventCount = CountEvents(events, skippedEventPrefixes);
        var disabledEventCount = CountEvents(events, disabledEventPrefixes);
        var failedEventCount = (failedEventPrefixes is null ? 0 : CountEvents(events, failedEventPrefixes)) + CountProbeFailureEvents(events, name);
        var status = DetermineCollectionStatus(enabled, implemented, artifactCount, capturedEventCount, skippedEventCount, disabledEventCount, failedEventCount);
        var normalizedRelativePath = NormalizeRelativePath(relativePath);
        var disabledCount = enabled ? disabledEventCount : Math.Max(1, disabledEventCount);
        var capturedCount = Math.Max(artifactCount, capturedEventCount);
        var collectionArtifacts = descriptors
            .Where(artifact => string.Equals(artifact.CollectionName, name, StringComparison.OrdinalIgnoreCase))
            .ToList();
        var totalBytes = collectionArtifacts.Sum(artifact => artifact.SizeBytes);
        var artifactHashComputedCount = collectionArtifacts.Count(static artifact =>
            !string.IsNullOrWhiteSpace(artifact.Sha256) ||
            artifact.Hashes.ContainsKey("sha256") ||
            (artifact.Metadata.TryGetValue("artifactHashStatus", out var hashStatus) &&
             string.Equals(hashStatus, "computed", StringComparison.OrdinalIgnoreCase)));
        var artifactHashFailedCount = collectionArtifacts.Count(static artifact =>
            artifact.Metadata.TryGetValue("artifactHashStatus", out var hashStatus) &&
            string.Equals(hashStatus, "failed", StringComparison.OrdinalIgnoreCase));
        var metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["collectionName"] = name,
            ["evidenceRole"] = evidenceRole,
            ["collectionSummaryVersion"] = "artifact-collection-summary-v2",
            ["summaryRow"] = "true",
            ["reportRowKind"] = "artifact-collection-summary",
            ["eventSemanticClass"] = $"artifact-{ArtifactSemanticTypeForCollection(name)}-collection-summary",
            ["semanticEventCategory"] = "artifact-evidence",
            ["semanticEventTags"] = $"artifact,{ArtifactSemanticTypeForCollection(name)},collection,summary,nonbehavior",
            ["artifactSemanticType"] = ArtifactSemanticTypeForCollection(name),
            ["behaviorCounted"] = "false",
            ["nonbehavior"] = "true",
            ["notSampleBehavior"] = "true",
            ["sampleBehaviorCandidate"] = "false",
            ["sampleBehaviorCandidateReason"] = "guest-artifact-collection-summary",
            ["requested"] = enabled.ToString(System.Globalization.CultureInfo.InvariantCulture).ToLowerInvariant(),
            ["captureEnabled"] = enabled.ToString(System.Globalization.CultureInfo.InvariantCulture).ToLowerInvariant(),
            ["capturePolicy"] = CapturePolicyForCollection(name),
            ["implemented"] = implemented.ToString(System.Globalization.CultureInfo.InvariantCulture).ToLowerInvariant(),
            ["artifactCount"] = artifactCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["capturedArtifactCount"] = artifactCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["downloadableArtifactCount"] = artifactCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["fileCount"] = artifactCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["totalBytes"] = totalBytes.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["artifactTotalBytes"] = totalBytes.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["artifactHashComputedCount"] = artifactHashComputedCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["artifactHashFailedCount"] = artifactHashFailedCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["artifactIntegrityState"] = CollectionArtifactIntegrityState(artifactCount, artifactHashComputedCount, artifactHashFailedCount, status),
            ["artifactSelectorVersion"] = "artifact-selectors-v1",
            ["capturedCount"] = capturedCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["skippedCount"] = skippedEventCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["disabledCount"] = disabledCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["failedCount"] = failedEventCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["capturedEventCount"] = capturedEventCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["skippedEventCount"] = skippedEventCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["disabledEventCount"] = disabledEventCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["failedEventCount"] = failedEventCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["safeByDefault"] = (!enabled).ToString(System.Globalization.CultureInfo.InvariantCulture)
        };

        if (kind == ArtifactKind.PacketCapture)
        {
            AddIfMissing(metadata, "captureSource", enabled ? "guest-pktmon" : "not-requested");
            AddIfMissing(metadata, "captureTool", "pktmon.exe");
            AddIfMissing(metadata, "conversionTool", "pktmon.exe");
            AddIfMissing(metadata, "expectedRelativePath", "packet-captures/*.pcapng");
            AddIfMissing(metadata, "pcapArtifactCount", artifactCount.ToString(System.Globalization.CultureInfo.InvariantCulture));
            AddIfMissing(metadata, "packetCaptureFileCount", artifactCount.ToString(System.Globalization.CultureInfo.InvariantCulture));
            AddIfMissing(metadata, "protocolSummaryAvailable", "false");
            AddIfMissing(metadata, "protocolSummaryState", "capture-metadata-only");
            AddIfMissing(metadata, "protocolSummaryStatus", "skipped");
            AddIfMissing(metadata, "protocolSummaryReason", "protocolParserNotImplemented");
            AddIfMissing(metadata, "protocolDiagnosticsAvailable", "true");
            AddIfMissing(metadata, "protocolDiagnostics", "pcapng-block-counters");
            AddIfMissing(metadata, "protocolFamiliesExpected", "dns,http,tls");
            AddIfMissing(metadata, "dnsSummaryState", "not-parsed");
            AddIfMissing(metadata, "httpSummaryState", "not-parsed");
            AddIfMissing(metadata, "tlsSummaryState", "not-parsed");
            AddIfMissing(metadata, "zhHint", "未集成协议解析时，请优先查看 artifactCount/fileCount/totalBytes、lastArtifactRelativePath、lastDiagnosticEtlRelativePath、lastDiagnosticPacketCountStatus 与 sha256 等文件完整性字段。");
        }

        AddCollectionArtifactFieldDefaults(metadata, collectionArtifacts, status);
        AddLastCollectionEventMetadata(
            metadata,
            events,
            name,
            capturedEventPrefixes,
            skippedEventPrefixes,
            disabledEventPrefixes,
            failedEventPrefixes ?? Array.Empty<string>());
        AddCollectionProcessFallbacks(metadata);
        var concreteStatusReason = LastCollectionReason(
            events,
            name,
            status,
            skippedEventPrefixes,
            disabledEventPrefixes,
            failedEventPrefixes ?? Array.Empty<string>());
        var reason = status switch
        {
            "disabled" => reasonWhenDisabled,
            "not-implemented" => "collectorNotImplemented",
            "skipped" => concreteStatusReason ?? "collectorSkippedOrUnavailable",
            "failed" => concreteStatusReason ?? "collectorFailed",
            "enabled-empty" => "noArtifactsProduced",
            _ => string.Empty
        };
        metadata["zhStatus"] = ZhCollectionStatus(status);
        metadata["zhReason"] = ZhCollectionReason(reason);
        metadata["zhHint"] = ZhCollectionHint(name, status, reason);
        if (kind == ArtifactKind.PacketCapture && string.IsNullOrWhiteSpace(metadata["zhHint"]))
        {
            metadata["zhHint"] = "未集成协议解析时，请优先查看 artifactCount/fileCount/totalBytes、lastArtifactRelativePath、lastDiagnosticEtlRelativePath、lastDiagnosticPacketCountStatus 与 sha256 等文件完整性字段。";
        }

        AddCollectionArtifactExtremes(metadata, collectionArtifacts);
        AddCollectionReasonSummary(metadata, events, name, skippedEventPrefixes, disabledEventPrefixes, failedEventPrefixes ?? Array.Empty<string>());

        return new ArtifactCollectionDescriptor
        {
            Name = name,
            Kind = kind,
            Category = category,
            EvidenceRole = evidenceRole,
            RelativePath = normalizedRelativePath,
            SafeLink = BuildSafeLink(normalizedRelativePath),
            ImportPath = normalizedRelativePath,
            Enabled = enabled,
            Implemented = implemented,
            Status = status,
            Reason = reason,
            Metadata = metadata
        };
    }

    private static void AddCollectionArtifactFieldDefaults(
        Dictionary<string, string> metadata,
        IReadOnlyList<ArtifactDescriptor> collectionArtifacts,
        string status)
    {
        if (collectionArtifacts.Count > 0)
        {
            var primary = collectionArtifacts
                .OrderBy(artifact => artifact.RelativePath, StringComparer.OrdinalIgnoreCase)
                .First();
            AddIfMissing(metadata, "artifactRelativePath", primary.RelativePath);
            AddIfMissing(metadata, "artifactRelativePathStatus", "captured");
            AddIfMissing(metadata, "artifactSelector", primary.RelativePath);
            AddIfMissing(metadata, "stableArtifactSelector", primary.RelativePath);
            AddIfMissing(metadata, "canonicalArtifactSelector", primary.RelativePath);
            AddIfMissing(metadata, "downloadSelector", primary.RelativePath);
            AddIfMissing(metadata, "artifactSafeLink", primary.SafeLink);
            AddIfMissing(metadata, "artifactSelectorKind", "safe-output-relative-path");
            AddIfMissing(metadata, "sizeBytes", primary.SizeBytes.ToString(System.Globalization.CultureInfo.InvariantCulture));
            AddIfMissing(metadata, "artifactSizeBytes", primary.SizeBytes.ToString(System.Globalization.CultureInfo.InvariantCulture));
            AddIfMissing(metadata, "sizeBytesStatus", "computed");
            AddIfMissing(metadata, "sha256", primary.Sha256);
            AddIfMissing(metadata, "artifactSha256", primary.Sha256);
            AddIfMissing(metadata, "sha256Status", string.IsNullOrWhiteSpace(primary.Sha256) ? "missing" : "computed");
            AddIfMissing(metadata, "artifactHashStatus", string.IsNullOrWhiteSpace(primary.Sha256) ? "missing" : "computed");
            AddIfMissing(metadata, "hashStatus", string.IsNullOrWhiteSpace(primary.Sha256) ? "missing" : "computed");
            AddIfMissing(metadata, "artifactExists", "true");
            return;
        }

        var emptyStatus = status switch
        {
            "disabled" => "disabled",
            "failed" => "failed",
            "skipped" => "skipped",
            "enabled-empty" => "not-created",
            "not-implemented" => "not-implemented",
            _ => "not-created"
        };
        metadata.TryAdd("artifactRelativePath", string.Empty);
        AddIfMissing(metadata, "artifactRelativePathStatus", emptyStatus);
        metadata.TryAdd("sizeBytes", string.Empty);
        metadata.TryAdd("sha256", string.Empty);
        AddIfMissing(metadata, "sizeBytesStatus", emptyStatus);
        AddIfMissing(metadata, "sha256Status", emptyStatus);
        AddIfMissing(metadata, "artifactHashStatus", emptyStatus);
        AddIfMissing(metadata, "hashStatus", emptyStatus);
        AddIfMissing(metadata, "artifactExists", "false");
    }

    private static void AddCollectionProcessFallbacks(Dictionary<string, string> metadata)
    {
        var rootProcessId = ValueOrEmpty(metadata, "rootProcessId", "lastRootProcessId");
        AddStableFallback(metadata, "rootProcessId", rootProcessId);

        var treeLineage = ValueOrEmpty(metadata, "treeLineage", "lastTreeLineage");
        if (string.IsNullOrWhiteSpace(treeLineage) && !string.IsNullOrWhiteSpace(rootProcessId))
        {
            treeLineage = rootProcessId;
        }

        AddStableFallback(metadata, "treeLineage", treeLineage);
        AddIfMissing(metadata, "rootProcessIdStatus", string.IsNullOrWhiteSpace(rootProcessId) ? "unavailable" : "available");
        AddIfMissing(metadata, "treeLineageStatus", string.IsNullOrWhiteSpace(treeLineage) ? "unavailable" : "stable");
    }

    private static string DetermineCollectionStatus(
        bool enabled,
        bool implemented,
        int artifactCount,
        int capturedEventCount,
        int skippedEventCount,
        int disabledEventCount,
        int failedEventCount)
    {
        if (artifactCount > 0 || capturedEventCount > 0)
        {
            return "captured";
        }

        if (!enabled)
        {
            return "disabled";
        }

        if (!implemented)
        {
            return "not-implemented";
        }

        if (failedEventCount > 0)
        {
            return "failed";
        }

        if (disabledEventCount > 0)
        {
            return "disabled";
        }

        if (skippedEventCount > 0)
        {
            return "skipped";
        }

        return "enabled-empty";
    }

    private static string CollectionArtifactIntegrityState(
        int artifactCount,
        int artifactHashComputedCount,
        int artifactHashFailedCount,
        string status)
    {
        if (artifactCount == 0)
        {
            return status switch
            {
                "disabled" => "disabled",
                "skipped" => "skipped",
                "failed" => "failed",
                "enabled-empty" => "not-applicable-empty",
                _ => "not-applicable"
            };
        }

        if (artifactHashComputedCount >= artifactCount && artifactHashFailedCount == 0)
        {
            return "verified";
        }

        if (artifactHashComputedCount > 0)
        {
            return "partial";
        }

        return artifactHashFailedCount > 0 ? "hash-failed" : "unknown";
    }

    private static void AddCollectionArtifactExtremes(
        Dictionary<string, string> metadata,
        IReadOnlyList<ArtifactDescriptor> collectionArtifacts)
    {
        if (collectionArtifacts.Count == 0)
        {
            return;
        }

        var first = collectionArtifacts.OrderBy(artifact => artifact.RelativePath, StringComparer.OrdinalIgnoreCase).First();
        var last = collectionArtifacts.OrderBy(artifact => artifact.RelativePath, StringComparer.OrdinalIgnoreCase).Last();
        metadata["artifactSelectorState"] = "available";
        metadata["artifactSelectorMode"] = "relative-path-order-and-size";
        AddCollectionArtifactSelector(metadata, "first", first, "first-relative-path");
        AddCollectionArtifactSelector(metadata, "last", last, "last-relative-path");

        var largest = collectionArtifacts
            .OrderByDescending(artifact => artifact.SizeBytes)
            .ThenBy(artifact => artifact.RelativePath, StringComparer.OrdinalIgnoreCase)
            .First();
        AddCollectionArtifactSelector(metadata, "largest", largest, "largest-size-bytes");
    }

    private static void AddCollectionArtifactSelector(
        Dictionary<string, string> metadata,
        string prefix,
        ArtifactDescriptor artifact,
        string selectionReason)
    {
        var titlePrefix = char.ToUpperInvariant(prefix[0]) + prefix[1..];
        AddIfMissing(metadata, $"{prefix}ArtifactSelector", artifact.RelativePath);
        AddIfMissing(metadata, $"{prefix}ArtifactRelativePath", artifact.RelativePath);
        AddIfMissing(metadata, $"{prefix}ArtifactSafeLink", artifact.SafeLink);
        AddIfMissing(metadata, $"{prefix}ArtifactImportPath", artifact.ImportPath);
        AddIfMissing(metadata, $"{prefix}ArtifactName", artifact.Name);
        AddIfMissing(metadata, $"{prefix}ArtifactSha256", artifact.Sha256);
        AddIfMissing(metadata, $"{prefix}ArtifactSizeBytes", artifact.SizeBytes.ToString(System.Globalization.CultureInfo.InvariantCulture));
        AddIfMissing(metadata, $"{prefix}ArtifactMimeType", artifact.MimeType);
        AddIfMissing(metadata, $"{prefix}ArtifactCapturePhase", artifact.CapturePhase);
        AddIfMissing(metadata, $"{prefix}ArtifactSelectionReason", selectionReason);
        AddIfMissing(metadata, $"has{titlePrefix}ArtifactSelector", "true");
    }

    private static void AddCollectionReasonSummary(
        Dictionary<string, string> metadata,
        IReadOnlyList<SandboxEvent> events,
        string collectionName,
        IReadOnlyList<string> skippedEventPrefixes,
        IReadOnlyList<string> disabledEventPrefixes,
        IReadOnlyList<string> failedEventPrefixes)
    {
        var reasonCounts = events
            .Where(evt =>
                HasCollectionName(evt, collectionName) &&
                (EventTypeMatches(evt, skippedEventPrefixes) ||
                 EventTypeMatches(evt, disabledEventPrefixes) ||
                 EventTypeMatches(evt, failedEventPrefixes)))
            .Select(evt => evt.Data.TryGetValue("reason", out var reason) ? reason : string.Empty)
            .Where(static reason => !string.IsNullOrWhiteSpace(reason))
            .GroupBy(static reason => reason, StringComparer.OrdinalIgnoreCase)
            .OrderBy(static group => group.Key, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(static group => group.Key, static group => group.Count(), StringComparer.OrdinalIgnoreCase);

        if (reasonCounts.Count == 0)
        {
            return;
        }

        metadata["reasonCount"] = reasonCounts.Count.ToString(System.Globalization.CultureInfo.InvariantCulture);
        metadata["reasons"] = string.Join(",", reasonCounts.Keys);
        metadata["reasonCounts"] = string.Join(
            ";",
            reasonCounts.Select(pair => $"{pair.Key}={pair.Value.ToString(System.Globalization.CultureInfo.InvariantCulture)}"));
        metadata["reasonCountsJson"] = JsonSerializer.Serialize(reasonCounts);
    }

    private static Dictionary<string, Dictionary<string, string>> BuildEventMetadataByRelativePath(string outputDirectory, IReadOnlyList<SandboxEvent> events)
    {
        var metadataByRelativePath = new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var evt in events)
        {
            foreach (var relativePath in CandidateRelativePaths(outputDirectory, evt).Distinct(StringComparer.OrdinalIgnoreCase))
            {
                if (!metadataByRelativePath.TryGetValue(relativePath, out var metadata))
                {
                    metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    metadataByRelativePath[relativePath] = metadata;
                }

                metadata["sourceEventType"] = evt.EventType;
                metadata["sourceEventSource"] = evt.Source;
                AddIfNotEmpty(metadata, "eventPath", evt.Path);
                if (evt.ProcessId is not null)
                {
                    metadata["processId"] = evt.ProcessId.Value.ToString(System.Globalization.CultureInfo.InvariantCulture);
                }

                AddIfNotEmpty(metadata, "processName", evt.ProcessName);
                if (evt.ParentProcessId is not null)
                {
                    metadata["parentProcessId"] = evt.ParentProcessId.Value.ToString(System.Globalization.CultureInfo.InvariantCulture);
                }

                AddIfNotEmpty(metadata, "commandLine", evt.CommandLine);

                foreach (var pair in evt.Data)
                {
                    AddIfNotEmpty(metadata, pair.Key, pair.Value);
                }

                AddIfNotEmpty(metadata, "captureState", InferCaptureState(evt.EventType));
            }
        }

        return metadataByRelativePath;
    }

    private static IEnumerable<string> CandidateRelativePaths(string outputDirectory, SandboxEvent evt)
    {
        if (!string.IsNullOrWhiteSpace(evt.Path))
        {
            var relativePath = TryGetRelativePath(outputDirectory, evt.Path);
            if (!string.IsNullOrWhiteSpace(relativePath))
            {
                yield return relativePath;
            }
        }

        foreach (var key in new[]
        {
            "relativePath",
            "artifactRelativePath",
            "sourceArtifactRelativePath",
            "sourceArtifactImportPath",
            "driverEventPath",
            "driverEventsPath",
            "driverEventsRelativePath",
            "jsonlPath",
            "jsonlRelativePath",
            "stdoutPath",
            "stdoutRelativePath",
            "stderrPath",
            "stderrRelativePath",
            "screenshotRelativePath",
            "memoryDumpRelativePath",
            "dumpRelativePath",
            "pcapRelativePath",
            "pcapngRelativePath",
            "packetCaptureRelativePath",
            "etlRelativePath",
            "diagnosticRelativePath"
        })
        {
            if (!evt.Data.TryGetValue(key, out var relative) || string.IsNullOrWhiteSpace(relative))
            {
                continue;
            }

            var normalized = NormalizeRelativePath(relative);
            if (!string.IsNullOrWhiteSpace(normalized))
            {
                yield return normalized;
            }
        }

        foreach (var key in new[]
        {
            "artifactFullPath",
            "sourceArtifactFullPath",
            "driverEventPath",
            "driverEventsPath",
            "jsonlPath",
            "stdoutPath",
            "stderrPath",
            "screenshotPath",
            "memoryDumpPath",
            "dumpPath",
            "pcapPath",
            "pcapngPath",
            "packetCapturePath",
            "etlPath"
        })
        {
            if (evt.Data.TryGetValue(key, out var eventPath) && !string.IsNullOrWhiteSpace(eventPath))
            {
                var relativePath = TryGetRelativePath(outputDirectory, eventPath);
                if (!string.IsNullOrWhiteSpace(relativePath))
                {
                    yield return relativePath;
                }
            }
        }
    }

    private static bool TryClassifyArtifact(string relativePath, out ArtifactClassification classification)
    {
        var fileName = Path.GetFileName(relativePath);
        var extension = Path.GetExtension(relativePath).ToLowerInvariant();
        if (string.Equals(relativePath, "events.json", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(relativePath, "agent-summary.json", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(relativePath, CombineRelative(ArtifactsDirectoryName, ManifestFileName), StringComparison.OrdinalIgnoreCase))
        {
            classification = ArtifactClassification.Unknown;
            return false;
        }

        if (relativePath.StartsWith($"{ArtifactsDirectoryName}/", StringComparison.OrdinalIgnoreCase))
        {
            classification = new ArtifactClassification(ArtifactKind.DroppedFile, "dropped-file", "dropped-file", "dropped-files");
            return true;
        }

        if (relativePath.StartsWith($"{ScreenshotsDirectoryName}/", StringComparison.OrdinalIgnoreCase))
        {
            classification = new ArtifactClassification(ArtifactKind.Screenshot, "screenshot", "screenshot", "screenshots");
            return true;
        }

        if (relativePath.StartsWith($"{MemoryDumpsDirectoryName}/", StringComparison.OrdinalIgnoreCase))
        {
            classification = new ArtifactClassification(ArtifactKind.MemoryDump, "memory-dump", "memory-dump", "memory-dumps");
            return true;
        }

        if (relativePath.StartsWith($"{PacketCapturesDirectoryName}/", StringComparison.OrdinalIgnoreCase) ||
            extension is ".pcap" or ".pcapng")
        {
            classification = new ArtifactClassification(ArtifactKind.PacketCapture, "packet-capture", "packet-capture", "packet-captures");
            return true;
        }

        if (string.Equals(extension, ".jsonl", StringComparison.OrdinalIgnoreCase) &&
            fileName.Contains("driver", StringComparison.OrdinalIgnoreCase))
        {
            classification = new ArtifactClassification(ArtifactKind.DriverEventsJsonLines, "telemetry", "driver-events", "driver-events");
            return true;
        }

        if (string.Equals(extension, ".log", StringComparison.OrdinalIgnoreCase) ||
            fileName.StartsWith("r0collector.", StringComparison.OrdinalIgnoreCase))
        {
            classification = new ArtifactClassification(ArtifactKind.Log, "log", "diagnostic-log", "r0-logs");
            return true;
        }

        classification = ArtifactClassification.Unknown;
        return false;
    }

    private static IEnumerable<string> EnumerateFilesSafe(string root)
    {
        var pending = new Stack<string>();
        pending.Push(root);
        while (pending.Count > 0)
        {
            var directory = pending.Pop();
            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(directory).ToList();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
            {
                continue;
            }

            foreach (var file in files)
            {
                yield return file;
            }

            IEnumerable<string> directories;
            try
            {
                directories = Directory.EnumerateDirectories(directory).ToList();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
            {
                continue;
            }

            foreach (var child in directories)
            {
                pending.Push(child);
            }
        }
    }

    private static string? FirstRelativePath(IReadOnlyList<ArtifactDescriptor> descriptors, string collectionName)
    {
        return descriptors
            .Where(artifact => string.Equals(artifact.CollectionName, collectionName, StringComparison.OrdinalIgnoreCase))
            .OrderBy(artifact => artifact.RelativePath, StringComparer.OrdinalIgnoreCase)
            .Select(artifact => artifact.RelativePath)
            .FirstOrDefault(path => !string.IsNullOrWhiteSpace(path));
    }

    private static int CountEvents(IReadOnlyList<SandboxEvent> events, IReadOnlyList<string> eventPrefixes)
    {
        if (eventPrefixes.Count == 0)
        {
            return 0;
        }

        return events.Count(evt => EventTypeMatches(evt, eventPrefixes));
    }

    private static int CountProbeFailureEvents(IReadOnlyList<SandboxEvent> events, string collectionName)
    {
        return events.Count(evt => IsProbeFailureForCollection(evt, collectionName));
    }

    private static bool EventTypeMatches(SandboxEvent evt, IReadOnlyList<string> eventPrefixes)
    {
        return eventPrefixes.Count > 0 &&
            eventPrefixes.Any(prefix => evt.EventType.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsProbeFailureEvent(SandboxEvent evt)
    {
        return string.Equals(evt.EventType, "probe.timeout", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(evt.EventType, "probe.failed", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(evt.EventType, "probe.canceled", StringComparison.OrdinalIgnoreCase);
    }

    private static bool HasCollectionName(SandboxEvent evt, string collectionName)
    {
        return evt.Data.TryGetValue("collectionName", out var value) &&
            string.Equals(value, collectionName, StringComparison.OrdinalIgnoreCase);
    }

    private static string? LastCollectionReason(
        IReadOnlyList<SandboxEvent> events,
        string collectionName,
        string status,
        IReadOnlyList<string> skippedEventPrefixes,
        IReadOnlyList<string> disabledEventPrefixes,
        IReadOnlyList<string> failedEventPrefixes)
    {
        for (var index = events.Count - 1; index >= 0; index--)
        {
            var evt = events[index];
            var matchesStatus = status switch
            {
                "failed" => EventTypeMatches(evt, failedEventPrefixes) || IsProbeFailureForCollection(evt, collectionName),
                "skipped" => EventTypeMatches(evt, skippedEventPrefixes),
                "disabled" => EventTypeMatches(evt, disabledEventPrefixes),
                _ => false
            };
            if (!matchesStatus)
            {
                continue;
            }

            if (evt.Data.TryGetValue("reason", out var reason) && !string.IsNullOrWhiteSpace(reason))
            {
                return reason;
            }
        }

        return null;
    }

    private static void AddLastCollectionEventMetadata(
        Dictionary<string, string> metadata,
        IReadOnlyList<SandboxEvent> events,
        string collectionName,
        IReadOnlyList<string> capturedEventPrefixes,
        IReadOnlyList<string> skippedEventPrefixes,
        IReadOnlyList<string> disabledEventPrefixes,
        IReadOnlyList<string> failedEventPrefixes)
    {
        SandboxEvent? lastRelevant = null;
        SandboxEvent? lastDiagnostic = null;
        SandboxEvent? lastAncillary = null;
        for (var index = 0; index < events.Count; index++)
        {
            var evt = events[index];
            if (!IsCollectionEvent(evt, collectionName, capturedEventPrefixes, skippedEventPrefixes, disabledEventPrefixes, failedEventPrefixes))
            {
                continue;
            }

            if (IsCollectionStateEvent(evt, collectionName, capturedEventPrefixes, skippedEventPrefixes, disabledEventPrefixes, failedEventPrefixes))
            {
                lastRelevant = evt;
            }
            else
            {
                lastAncillary = evt;
            }

            if (HasDiagnosticData(evt))
            {
                lastDiagnostic = evt;
            }
        }

        lastRelevant ??= lastAncillary;
        if (lastRelevant is not null)
        {
            CopyEventDataIfPresent(metadata, lastRelevant, "phase", "lastPhase");
            CopyEventDataIfPresent(metadata, lastRelevant, "capturePhase", "lastCapturePhase");
            CopyEventDataIfPresent(metadata, lastRelevant, "status", "lastStatus");
            CopyEventDataIfPresent(metadata, lastRelevant, "captureState", "lastCaptureState");
            CopyEventDataIfPresent(metadata, lastRelevant, "zhMessage", "lastZhMessage");
            CopyEventDataIfPresent(metadata, lastRelevant, "zhHint", "lastZhHint");
            CopyEventDataIfPresent(metadata, lastRelevant, "zhReason", "lastZhReason");
            CopyEventDataIfPresent(metadata, lastRelevant, "nonfatal", "lastNonfatal");
            CopyEventDataIfPresent(metadata, lastRelevant, "artifactRelativePath", "lastArtifactRelativePath");
            CopyEventDataIfPresent(metadata, lastRelevant, "relativePath", "lastRelativePath");
            CopyArtifactDiagnosticData(metadata, lastRelevant, "last");
            CopyProcessIdentity(metadata, lastRelevant);
        }

        if (lastDiagnostic is not null)
        {
            metadata["lastEventType"] = lastDiagnostic.EventType;
            CopyEventDataIfPresent(metadata, lastDiagnostic, "reason", "lastReason");
            CopyEventDataIfPresent(metadata, lastDiagnostic, "zhMessage", "lastDiagnosticZhMessage");
            CopyEventDataIfPresent(metadata, lastDiagnostic, "zhHint", "lastDiagnosticZhHint");
            CopyEventDataIfPresent(metadata, lastDiagnostic, "zhReason", "lastDiagnosticZhReason");
            CopyEventDataIfPresent(metadata, lastDiagnostic, "diagnosticStage", "lastDiagnosticStage");
            CopyEventDataIfPresent(metadata, lastDiagnostic, "exceptionType", "lastExceptionType");
            CopyEventDataIfPresent(metadata, lastDiagnostic, "win32Error", "lastWin32Error");
            CopyEventDataIfPresent(metadata, lastDiagnostic, "commandFileName", "lastCommandFileName");
            CopyEventDataIfPresent(metadata, lastDiagnostic, "commandExitCode", "lastCommandExitCode");
            CopyEventDataIfPresent(metadata, lastDiagnostic, "commandTimedOut", "lastCommandTimedOut");
            CopyEventDataIfPresent(metadata, lastDiagnostic, "commandExceptionType", "lastCommandExceptionType");
            CopyEventDataIfPresent(metadata, lastDiagnostic, "commandMessage", "lastCommandMessage");
            CopyEventDataIfPresent(metadata, lastDiagnostic, "probeId", "lastProbeId");
            CopyArtifactDiagnosticData(metadata, lastDiagnostic, "lastDiagnostic");
            CopyProcessIdentity(metadata, lastDiagnostic);
        }
    }

    private static bool IsCollectionEvent(
        SandboxEvent evt,
        string collectionName,
        IReadOnlyList<string> capturedEventPrefixes,
        IReadOnlyList<string> skippedEventPrefixes,
        IReadOnlyList<string> disabledEventPrefixes,
        IReadOnlyList<string> failedEventPrefixes)
    {
        return HasCollectionName(evt, collectionName) ||
            IsProbeFailureForCollection(evt, collectionName) ||
            EventTypeMatches(evt, capturedEventPrefixes) ||
            EventTypeMatches(evt, skippedEventPrefixes) ||
            EventTypeMatches(evt, disabledEventPrefixes) ||
            EventTypeMatches(evt, failedEventPrefixes);
    }

    private static bool IsCollectionStateEvent(
        SandboxEvent evt,
        string collectionName,
        IReadOnlyList<string> capturedEventPrefixes,
        IReadOnlyList<string> skippedEventPrefixes,
        IReadOnlyList<string> disabledEventPrefixes,
        IReadOnlyList<string> failedEventPrefixes)
    {
        return IsProbeFailureForCollection(evt, collectionName) ||
            EventTypeMatches(evt, capturedEventPrefixes) ||
            EventTypeMatches(evt, skippedEventPrefixes) ||
            EventTypeMatches(evt, disabledEventPrefixes) ||
            EventTypeMatches(evt, failedEventPrefixes);
    }

    private static bool IsProbeFailureForCollection(SandboxEvent evt, string collectionName)
    {
        if (!IsProbeFailureEvent(evt))
        {
            return false;
        }

        if (HasCollectionName(evt, collectionName))
        {
            return true;
        }

        if (!evt.Data.TryGetValue("probeId", out var probeId) || string.IsNullOrWhiteSpace(probeId))
        {
            return false;
        }

        var mappedCollection = probeId switch
        {
            "screenshot" => "screenshots",
            "memory-dump" => "memory-dumps",
            "packet-capture" => "packet-captures",
            _ => string.Empty
        };
        return string.Equals(mappedCollection, collectionName, StringComparison.OrdinalIgnoreCase);
    }

    private static bool HasDiagnosticData(SandboxEvent evt)
    {
        if (IsNonDiagnosticSummaryEvent(evt))
        {
            return false;
        }

        return evt.Data.ContainsKey("reason") ||
            evt.Data.ContainsKey("diagnosticStage") ||
            evt.Data.ContainsKey("exceptionType") ||
            evt.Data.ContainsKey("commandMessage") ||
            evt.Data.ContainsKey("protocolSummaryAvailable") ||
            IsProbeFailureEvent(evt);
    }

    private static bool IsNonDiagnosticSummaryEvent(SandboxEvent evt)
    {
        if (!evt.Data.TryGetValue("summaryEvent", out var summaryEvent) ||
            !string.Equals(summaryEvent, "true", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return !evt.EventType.EndsWith(".skipped", StringComparison.OrdinalIgnoreCase) &&
            !evt.EventType.EndsWith(".failed", StringComparison.OrdinalIgnoreCase) &&
            !evt.EventType.EndsWith(".timeout", StringComparison.OrdinalIgnoreCase) &&
            !evt.EventType.EndsWith(".parse_error", StringComparison.OrdinalIgnoreCase);
    }

    private static void CopyEventDataIfPresent(Dictionary<string, string> metadata, SandboxEvent evt, string sourceKey, string destinationKey)
    {
        if (evt.Data.TryGetValue(sourceKey, out var value) && !string.IsNullOrWhiteSpace(value))
        {
            metadata[destinationKey] = value;
        }
    }

    private static void CopyArtifactDiagnosticData(Dictionary<string, string> metadata, SandboxEvent evt, string prefix)
    {
        foreach (var key in new[]
        {
            "sourcePath",
            "guestFullPath",
            "guestRelativePath",
            "sourceEventRelativePath",
            "sourceExists",
            "sourceMissing",
            "sourceSizeBytes",
            "sourceEventSizeBytes",
            "sourceLastWriteUtc",
            "sourceMtimeUtc",
            "sourceEventLastWriteUtc",
            "sourceSha256",
            "sourceHashAlgorithm",
            "sourceHashStatus",
            "originalSha256",
            "sha256",
            "hashAlgorithm",
            "artifactSha256",
            "artifactHashAlgorithm",
            "artifactSizeBytes",
            "artifactRelativePath",
            "hashStatus",
            "artifactHashStatus",
            "artifactIntegrityState",
            "artifactExists",
            "artifactRelativePathStatus",
            "artifactSelector",
            "stableArtifactSelector",
            "canonicalArtifactSelector",
            "downloadSelector",
            "artifactSelectorKind",
            "artifactSelectorVersion",
            "artifactSelectorState",
            "artifactSelectorMode",
            "eventSemanticClass",
            "semanticEventCategory",
            "semanticEventTags",
            "artifactSemanticType",
            "reportRowKind",
            "summaryRow",
            "firstArtifactSelector",
            "firstArtifactRelativePath",
            "firstArtifactSafeLink",
            "firstArtifactSha256",
            "firstArtifactSizeBytes",
            "firstArtifactSelectionReason",
            "lastArtifactSelector",
            "lastArtifactRelativePath",
            "lastArtifactSafeLink",
            "lastArtifactSha256",
            "lastArtifactSizeBytes",
            "lastArtifactSelectionReason",
            "largestArtifactSelector",
            "largestArtifactRelativePath",
            "largestArtifactSafeLink",
            "largestArtifactSha256",
            "largestArtifactSizeBytes",
            "largestArtifactSelectionReason",
            "sizeBytesStatus",
            "sha256Status",
            "reasonCode",
            "reasonCategory",
            "reasonTaxonomy",
            "reasonTaxonomyVersion",
            "coverageTaxonomy",
            "coverageTaxonomyVersion",
            "behaviorCounted",
            "nonbehavior",
            "notSampleBehavior",
            "sampleBehaviorCandidate",
            "sampleBehaviorCandidateReason",
            "collectionHealth",
            "skippedReasons",
            "skippedReasonCounts",
            "sourceCopiedSha256Match",
            "capturePolicy",
            "screenshotRelativePath",
            "memoryDumpRelativePath",
            "dumpRelativePath",
            "dumpTargetSelectionMode",
            "descendantProcessDumpEnabled",
            "directChildProcessDumpEnabled",
            "deeperDescendantProcessDumpEnabled",
            "descendantDumpOptInScope",
            "descendantDumpOptInMetadataVersion",
            "descendantDumpOptInApplied",
            "directChildDumpOptInApplied",
            "deeperDescendantDumpOptInApplied",
            "rootProcessDumpTarget",
            "childProcessDumpTarget",
            "descendantProcessDumpTarget",
            "targetProcessId",
            "targetParentProcessId",
            "targetProcessName",
            "targetProcessPath",
            "targetProcessRole",
            "targetTreeDepth",
            "targetTreeLineage",
            "targetSelectionSource",
            "dumpTargetKey",
            "duplicate",
            "alreadyCaptured",
            "rootVisibleInSnapshot",
            "rootPidReuseSkipped",
            "rootPidReuseSkippedCount",
            "rootProcessCoverageState",
            "childProcessCoverageState",
            "memoryDumpCoverageState",
            "rootDescendantCoverageState",
            "descendantTargetCount",
            "directChildTargetCount",
            "deeperDescendantTargetCount",
            "descendantAttemptedCount",
            "directChildAttemptedCount",
            "deeperDescendantAttemptedCount",
            "descendantCapturedCount",
            "directChildCapturedCount",
            "deeperDescendantCapturedCount",
            "descendantSkippedCount",
            "directChildSkippedCount",
            "deeperDescendantSkippedCount",
            "descendantAlreadyCapturedCount",
            "directChildAlreadyCapturedCount",
            "deeperDescendantAlreadyCapturedCount",
            "directChildCoverageState",
            "deeperDescendantCoverageState",
            "descendantCoverageCompleteness",
            "copiedSha256",
            "copiedHashAlgorithm",
            "copiedHashStatus",
            "sizeBytes",
            "artifactLastWriteUtc",
            "mtimeUtc",
            "etlRelativePath",
            "pcapRelativePath",
            "pcapngRelativePath",
            "packetCaptureRelativePath",
            "diagnosticRelativePath",
            "pcapFormat",
            "pcapExists",
            "pcapSizeBytes",
            "pcapLastWriteUtc",
            "pcapSha256",
            "pcapHashAlgorithm",
            "pcapHashStatus",
            "pcapHashExceptionType",
            "pcapHashMessage",
            "protocolSummaryAvailable",
            "protocolSummaryState",
            "protocolSummaryStatus",
            "protocolSummaryReason",
            "protocolSummaryFormat",
            "protocolsObserved",
            "protocolDiagnosticsAvailable",
            "protocolDiagnostics",
            "protocolFamiliesExpected",
            "dnsSummaryState",
            "httpSummaryState",
            "tlsSummaryState",
            "sourceTool",
            "sourceToolMode",
            "artifactSourceTool",
            "packetCaptureSourceTool",
            "packetCaptureSource",
            "captureTool",
            "captureToolMode",
            "captureToolCommand",
            "conversionTool",
            "conversionCommand",
            "conversionStatus",
            "conversionSourceFormat",
            "conversionTargetFormat",
            "captureStartedUtc",
            "captureStoppedUtc",
            "fileCount",
            "packetCaptureFileCount",
            "packetCount",
            "packetCountStatus",
            "pcapngBlockCount",
            "pcapngPacketBlockCount",
            "pcapngEnhancedPacketBlockCount",
            "pcapngSimplePacketBlockCount",
            "pcapngSectionHeaderCount",
            "pcapngByteOrder",
            "pcapngDiagnosticsAvailable",
            "packetCountConfidence",
            "conversionOutputSummaryAvailable",
            "pktmonReportedPacketCount",
            "pcapngExists",
            "pcapngSizeBytes",
            "pcapngLastWriteUtc",
            "pcapngSha256",
            "pcapngHashAlgorithm",
            "pcapngHashStatus",
            "pcapngHashExceptionType",
            "pcapngHashMessage",
            "etlExists",
            "etlSizeBytes",
            "etlLastWriteUtc",
            "etlSha256",
            "etlHashAlgorithm",
            "etlHashStatus",
            "etlHashExceptionType",
            "etlHashMessage",
            "zhMessage",
            "zhHint",
            "zhReason"
        })
        {
            CopyEventDataIfPresent(metadata, evt, key, $"{prefix}{char.ToUpperInvariant(key[0])}{key[1..]}");
        }
    }

    private static string ZhCollectionStatus(string status)
    {
        return status switch
        {
            "captured" => "已采集到证据文件或事件。",
            "disabled" => "该证据通道未启用。",
            "failed" => "该证据通道执行失败。",
            "skipped" => "该证据通道被跳过或不可用。",
            "enabled-empty" => "该证据通道已启用，但未产出文件。",
            "not-implemented" => "该证据通道尚未实现。",
            _ => string.Empty
        };
    }

    private static string ZhCollectionReason(string reason)
    {
        return reason switch
        {
            "driverEventsNotRequested" => "未请求 driver-events JSONL。",
            "r0CollectorNotRequested" => "未请求 R0Collector sidecar。",
            "packetCaptureNotRequested" => "未请求 packet capture。",
            "memoryDumpNotRequested" => "未请求 memory dump。",
            "screenshotNotRequested" => "未请求 screenshot。",
            "collectDroppedFilesNotRequested" => "未请求 dropped-file 复制。",
            "collectorNotImplemented" => "采集器尚未实现该通道。",
            "collectorSkippedOrUnavailable" => "采集器跳过或环境不可用。",
            "collectorFailed" => "采集器执行失败。",
            "noArtifactsProduced" => "已启用但没有产出文件。",
            "sourcePathMissing" => "源事件没有可复制路径。",
            "sourcePathInvalid" => "源路径无效。",
            "sourceFileMissing" => "复制时源文件已不存在。",
            "outsideWorkingDirectory" => "源文件位于样本工作目录之外，按策略跳过复制。",
            "underOutputDirectory" => "源文件位于输出目录下，按策略跳过递归采集。",
            "destinationPathInvalid" => "无法生成安全的证据目标路径。",
            "copyFailed" => "掉落文件复制失败。",
            "notWindows" => "该采集通道仅支持 Windows guest。",
            "captureAlreadyActive" => "已有抓包会话处于活动状态。",
            "captureWasNotStarted" => "抓包会话未成功启动。",
            "pktmonStartFailed" => "pktmon start 失败。",
            "pktmonStopFailed" => "pktmon stop 失败。",
            "pktmonConvertFailed" => "pktmon ETL 转 PCAPNG 失败。",
            "protocolParserNotImplemented" => "协议解析摘要尚未实现。",
            "process-tree-empty" => "没有可见的根/子进程可供采集。",
            "root-process" => "样本根进程 ID 不可用。",
            "root-process-final" => "最终 sweep 阶段样本根进程 ID 不可用。",
            "process-tree-snapshot" => "采集进程树快照失败。",
            "duplicate" => "目标进程已在本次运行中采集过。",
            _ => string.Empty
        };
    }


    private static string ArtifactSemanticTypeForClassification(ArtifactClassification classification)
    {
        return ArtifactSemanticTypeForCollection(classification.CollectionName);
    }

    private static string ArtifactSemanticTypeForCollection(string collectionName)
    {
        return collectionName switch
        {
            "dropped-files" => "dropped-file",
            "screenshots" => "screenshot",
            "memory-dumps" => "memory-dump",
            "packet-captures" => "packet-capture",
            "driver-events" => "driver-events",
            "r0-logs" => "diagnostic-log",
            _ => "artifact"
        };
    }

    private static string SemanticTagsForClassification(ArtifactClassification classification)
    {
        var semanticType = ArtifactSemanticTypeForClassification(classification);
        return $"artifact,{semanticType},captured,nonbehavior";
    }

    private static string CapturePolicyForCollection(string collectionName)
    {
        return collectionName switch
        {
            "dropped-files" => "explicit-opt-in-copy-working-directory-new-files",
            "screenshots" => "explicit-opt-in-screenshot",
            "memory-dumps" => "explicit-opt-in-sensitive-memory-dump",
            "packet-captures" => "explicit-opt-in-network-packet-capture",
            "driver-events" => "explicit-input-driver-jsonl",
            "r0-logs" => "explicit-opt-in-r0collector-sidecar",
            _ => "guest-artifact-discovery"
        };
    }

    private static string CapturePolicyForClassification(ArtifactClassification classification)
    {
        return CapturePolicyForCollection(classification.CollectionName);
    }

    private static string ZhCollectionHint(string collectionName, string status, string reason)
    {
        if (string.Equals(status, "disabled", StringComparison.OrdinalIgnoreCase))
        {
            return $"如需 {collectionName} 证据，请显式启用对应采集开关；字段 reason 保持机器可解析，不翻译。";
        }

        if (string.Equals(status, "failed", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(status, "skipped", StringComparison.OrdinalIgnoreCase))
        {
            return $"请查看 collection metadata 的 lastReason/lastDiagnostic* 以及事件中的 zhHint 来定位 {collectionName} 证据缺口。";
        }

        if (string.Equals(reason, "noArtifactsProduced", StringComparison.OrdinalIgnoreCase))
        {
            return $"该通道已启用但没有文件产出；请结合对应事件确认是否没有可采集对象或采集条件未触发。";
        }

        if (string.Equals(status, "captured", StringComparison.OrdinalIgnoreCase))
        {
            return $"该 {collectionName} collection summary 不代表样本行为；请使用 artifactRelativePath/sizeBytes/sha256 和 first/last/largest selector 校验证据。";
        }

        return $"该 {collectionName} collection metadata 用于解释证据链质量，不应计入样本行为统计。";
    }

    private static string ArtifactDescriptorZhHint(ArtifactClassification classification)
    {
        return classification.CollectionName switch
        {
            "dropped-files" => "掉落文件 artifact descriptor 不代表样本行为；请用 artifactRelativePath 下载，并用 sizeBytes/sha256 校验证据完整性。",
            "screenshots" => "截图 artifact descriptor 不代表样本行为；请用 artifactRelativePath 下载，并用 sizeBytes/sha256 校验证据完整性。",
            "memory-dumps" => "内存转储 artifact descriptor 不代表样本行为；dump 可能包含敏感内容，请用 sizeBytes/sha256 校验证据完整性。",
            "packet-captures" => "抓包 artifact descriptor 不代表样本行为；请用 artifactRelativePath 下载 PCAP/PCAPNG，并用 sizeBytes/sha256 校验证据完整性。",
            "driver-events" => "driver-events artifact descriptor 是采集链路证据；请结合 collection metadata 和 sha256 判断 JSONL 完整性。",
            "r0-logs" => "R0Collector 日志 artifact descriptor 是采集诊断证据；请结合 collection metadata 和 sha256 判断日志完整性。",
            _ => "artifact descriptor 用于解释证据链质量，不应计入样本行为统计。"
        };
    }

    private static void CopyProcessIdentity(Dictionary<string, string> metadata, SandboxEvent evt)
    {
        if (evt.ProcessId is not null)
        {
            metadata["lastProcessId"] = evt.ProcessId.Value.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }

        if (evt.ParentProcessId is not null)
        {
            metadata["lastParentProcessId"] = evt.ParentProcessId.Value.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }

        AddIfNotEmpty(metadata, "lastProcessName", evt.ProcessName);
        CopyEventDataIfPresent(metadata, evt, "processId", "lastProcessId");
        CopyEventDataIfPresent(metadata, evt, "rootProcessId", "lastRootProcessId");
        CopyEventDataIfPresent(metadata, evt, "parentProcessId", "lastParentProcessId");
        CopyEventDataIfPresent(metadata, evt, "processName", "lastProcessName");
        CopyEventDataIfPresent(metadata, evt, "targetProcessName", "lastTargetProcessName");
        CopyEventDataIfPresent(metadata, evt, "targetProcessPath", "lastTargetProcessPath");
        CopyEventDataIfPresent(metadata, evt, "processRole", "lastProcessRole");
        CopyEventDataIfPresent(metadata, evt, "processTreeRole", "lastProcessTreeRole");
        CopyEventDataIfPresent(metadata, evt, "treeNodeRole", "lastTreeNodeRole");
        CopyEventDataIfPresent(metadata, evt, "treeDepth", "lastTreeDepth");
        CopyEventDataIfPresent(metadata, evt, "rootRelativeDepth", "lastRootRelativeDepth");
        CopyEventDataIfPresent(metadata, evt, "descendantDepth", "lastDescendantDepth");
        CopyEventDataIfPresent(metadata, evt, "treeLineage", "lastTreeLineage");
        CopyEventDataIfPresent(metadata, evt, "treeLineageDisplay", "lastTreeLineageDisplay");
        CopyEventDataIfPresent(metadata, evt, "treeLineageStatus", "lastTreeLineageStatus");
        CopyEventDataIfPresent(metadata, evt, "lineageStabilityReason", "lastLineageStabilityReason");
        CopyEventDataIfPresent(metadata, evt, "rootProcessIdStatus", "lastRootProcessIdStatus");
        CopyEventDataIfPresent(metadata, evt, "rootAncestorProcessId", "lastRootAncestorProcessId");
        CopyEventDataIfPresent(metadata, evt, "processTreeCoverageState", "lastProcessTreeCoverageState");
        CopyEventDataIfPresent(metadata, evt, "processTreeCompleteness", "lastProcessTreeCompleteness");
        CopyEventDataIfPresent(metadata, evt, "childProcessCount", "lastChildProcessCount");
        CopyEventDataIfPresent(metadata, evt, "processMissing", "lastProcessMissing");
        CopyEventDataIfPresent(metadata, evt, "exitMissing", "lastExitMissing");
        CopyEventDataIfPresent(metadata, evt, "processExited", "lastProcessExited");
        CopyEventDataIfPresent(metadata, evt, "rootMissing", "lastRootMissing");
        CopyEventDataIfPresent(metadata, evt, "rootExited", "lastRootExited");
    }

    private static string? InferCaptureState(ArtifactClassification classification, IReadOnlyDictionary<string, string> metadata)
    {
        if (metadata.TryGetValue("captureState", out var state) && !string.IsNullOrWhiteSpace(state))
        {
            return state;
        }

        if (metadata.TryGetValue("sourceEventType", out var eventType))
        {
            return InferCaptureState(eventType);
        }

        return classification.Kind == ArtifactKind.Log || classification.Kind == ArtifactKind.DriverEventsJsonLines
            ? "available"
            : "captured";
    }

    private static void AddDescriptorFileIntegrityMetadata(
        ArtifactClassification classification,
        Dictionary<string, string> metadata,
        FileInfo info,
        string sha256)
    {
        AddIfMissing(metadata, "artifactExists", "true");
        AddIfMissing(metadata, "sizeBytes", info.Length.ToString(System.Globalization.CultureInfo.InvariantCulture));
        AddIfMissing(metadata, "artifactSizeBytes", info.Length.ToString(System.Globalization.CultureInfo.InvariantCulture));
        AddIfMissing(metadata, "artifactLastWriteUtc", info.LastWriteTimeUtc.ToString("O", System.Globalization.CultureInfo.InvariantCulture));
        AddIfMissing(metadata, "mtimeUtc", info.LastWriteTimeUtc.ToString("O", System.Globalization.CultureInfo.InvariantCulture));
        AddIfMissing(metadata, "sha256", sha256);
        AddIfMissing(metadata, "artifactSha256", sha256);
        AddIfMissing(metadata, "hashAlgorithm", "sha256");
        AddIfMissing(metadata, "hashStatus", "computed");
        AddIfMissing(metadata, "artifactHashAlgorithm", "sha256");
        AddIfMissing(metadata, "artifactHashStatus", "computed");
        AddIfMissing(metadata, "artifactIntegrityState", "verified");
        AddIfMissing(metadata, "sizeBytesStatus", "computed");
        AddIfMissing(metadata, "sha256Status", "computed");

        if (metadata.TryGetValue("rootProcessId", out var rootProcessId) && !string.IsNullOrWhiteSpace(rootProcessId))
        {
            AddIfMissing(metadata, "treeLineage", rootProcessId);
            AddIfMissing(metadata, "processRole", "sample-root-context");
            AddIfMissing(metadata, "rootProcessIdStatus", "available");
            AddIfMissing(metadata, "treeLineageStatus", "stable");
        }

        if (classification.Kind == ArtifactKind.PacketCapture)
        {
            AddPacketCaptureFileIntegrityAliases(metadata, info, sha256);
        }
    }

    private static void AddPacketCaptureFileIntegrityAliases(
        Dictionary<string, string> metadata,
        FileInfo info,
        string sha256)
    {
        var extension = Path.GetExtension(info.FullName);
        var prefix = string.Equals(extension, ".pcapng", StringComparison.OrdinalIgnoreCase)
            ? "pcapng"
            : string.Equals(extension, ".pcap", StringComparison.OrdinalIgnoreCase)
                ? "pcap"
                : "packetCapture";

        AddIfMissing(metadata, $"{prefix}Exists", "true");
        AddIfMissing(metadata, $"{prefix}SizeBytes", info.Length.ToString(System.Globalization.CultureInfo.InvariantCulture));
        AddIfMissing(metadata, $"{prefix}LastWriteUtc", info.LastWriteTimeUtc.ToString("O", System.Globalization.CultureInfo.InvariantCulture));
        AddIfMissing(metadata, $"{prefix}Sha256", sha256);
        AddIfMissing(metadata, $"{prefix}HashAlgorithm", "sha256");
        AddIfMissing(metadata, $"{prefix}HashStatus", "computed");
        AddIfMissing(metadata, "protocolDiagnosticsAvailable", "true");
        AddIfMissing(metadata, "protocolDiagnostics", "pcapng-block-counters");
        AddIfMissing(metadata, "protocolFamiliesExpected", "dns,http,tls");
        AddIfMissing(metadata, "dnsSummaryState", "not-parsed");
        AddIfMissing(metadata, "httpSummaryState", "not-parsed");
        AddIfMissing(metadata, "tlsSummaryState", "not-parsed");
        AddIfMissing(metadata, "protocolsObserved", "not-parsed");
    }

    private static void AddPacketCaptureMetadataDefaults(
        ArtifactClassification classification,
        Dictionary<string, string> metadata,
        string artifactFullPath)
    {
        if (classification.Kind != ArtifactKind.PacketCapture)
        {
            return;
        }

        var extension = Path.GetExtension(artifactFullPath);
        var artifactRelativePath = ValueOrEmpty(metadata, "artifactRelativePath", "relativePath", "importPath");
        AddIfMissing(metadata, "pcapFormat", string.Equals(extension, ".pcapng", StringComparison.OrdinalIgnoreCase)
            ? "pcapng"
            : string.Equals(extension, ".pcap", StringComparison.OrdinalIgnoreCase)
                ? "pcap"
                : "unknown");
        AddIfMissing(metadata, "packetCaptureRelativePath", artifactRelativePath);
        AddIfMissing(metadata, "sourceArtifactRelativePath", artifactRelativePath);
        if (string.Equals(extension, ".pcapng", StringComparison.OrdinalIgnoreCase))
        {
            AddIfMissing(metadata, "pcapngRelativePath", artifactRelativePath);
        }
        else if (string.Equals(extension, ".pcap", StringComparison.OrdinalIgnoreCase))
        {
            AddIfMissing(metadata, "pcapRelativePath", artifactRelativePath);
        }

        AddIfMissing(metadata, "captureSource", metadata.ContainsKey("collector") ? "guest-pktmon" : "guest-output");
        AddIfMissing(metadata, "hostCaptureStarted", "false");
        AddIfMissing(metadata, "importMode", "guest-artifact");
        AddIfMissing(metadata, "packetCaptureFileCount", "1");
        AddIfMissing(metadata, "fileCount", "1");
        AddIfMissing(metadata, "captureTool", metadata.ContainsKey("collector") ? "pktmon.exe" : "unknown");
        AddIfMissing(metadata, "conversionTool", metadata.ContainsKey("collector") ? "pktmon.exe" : "unknown");
        AddIfMissing(metadata, "protocolSummaryAvailable", "false");
        AddIfMissing(metadata, "protocolSummaryState", "capture-metadata-only");
        AddIfMissing(metadata, "protocolSummaryStatus", "skipped");
        AddIfMissing(metadata, "protocolSummaryReason", "protocolParserNotImplemented");
        AddIfMissing(metadata, "protocolDiagnosticsAvailable", "true");
        AddIfMissing(metadata, "protocolDiagnostics", "pcapng-block-counters");
        AddIfMissing(metadata, "protocolFamiliesExpected", "dns,http,tls");
        AddIfMissing(metadata, "dnsSummaryState", "not-parsed");
        AddIfMissing(metadata, "httpSummaryState", "not-parsed");
        AddIfMissing(metadata, "tlsSummaryState", "not-parsed");
        AddIfMissing(metadata, "protocolsObserved", "not-parsed");
        AddIfMissing(metadata, "zhHint", "未集成协议解析时，此条目仍提供 PCAP/PCAPNG 路径、大小、sha256、采集/转换状态和可下载证据。请下载 artifactRelativePath 进行外部协议分析。");
    }

    private static string? InferCaptureState(string eventType)
    {
        if (eventType.EndsWith(".captured", StringComparison.OrdinalIgnoreCase) ||
            eventType.EndsWith(".copied", StringComparison.OrdinalIgnoreCase) ||
            eventType.EndsWith(".written", StringComparison.OrdinalIgnoreCase) ||
            eventType.EndsWith(".exited", StringComparison.OrdinalIgnoreCase))
        {
            return "captured";
        }

        if (eventType.EndsWith(".skipped", StringComparison.OrdinalIgnoreCase))
        {
            return "skipped";
        }

        if (eventType.EndsWith(".disabled", StringComparison.OrdinalIgnoreCase))
        {
            return "disabled";
        }

        if (eventType.EndsWith(".failed", StringComparison.OrdinalIgnoreCase) ||
            eventType.EndsWith(".timeout", StringComparison.OrdinalIgnoreCase))
        {
            return "failed";
        }

        return null;
    }

    private static string ComputeSha256(string path)
    {
        using var stream = File.OpenRead(path);
        var hash = System.Security.Cryptography.SHA256.HashData(stream);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static string TryGetRelativePath(string root, string path)
    {
        try
        {
            var fullRoot = Path.GetFullPath(root);
            var fullPath = Path.GetFullPath(path);
            if (!IsSameOrUnderDirectory(fullPath, fullRoot))
            {
                return string.Empty;
            }

            return NormalizeRelativePath(Path.GetRelativePath(fullRoot, fullPath));
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return string.Empty;
        }
    }

    private static bool IsSameOrUnderDirectory(string path, string directory)
    {
        var fullPath = Path.GetFullPath(path);
        var fullDirectory = Path.GetFullPath(directory);
        if (string.Equals(
            Path.TrimEndingDirectorySeparator(fullPath),
            Path.TrimEndingDirectorySeparator(fullDirectory),
            StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var directoryWithSeparator = Path.EndsInDirectorySeparator(fullDirectory)
            ? fullDirectory
            : fullDirectory + Path.DirectorySeparatorChar;
        return fullPath.StartsWith(directoryWithSeparator, StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeRelativePath(string relativePath)
    {
        if (string.IsNullOrWhiteSpace(relativePath))
        {
            return string.Empty;
        }

        var unified = relativePath.Replace('\\', '/').Trim();
        if (Path.IsPathFullyQualified(unified) || unified.StartsWith("/", StringComparison.Ordinal))
        {
            return string.Empty;
        }

        var segments = unified
            .Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(segment => !string.Equals(segment, ".", StringComparison.Ordinal))
            .ToList();
        if (segments.Count == 0 ||
            segments.Any(segment =>
                string.Equals(segment, "..", StringComparison.Ordinal) ||
                segment.Contains(':', StringComparison.Ordinal)))
        {
            return string.Empty;
        }

        return string.Join("/", segments);
    }

    private static string BuildSafeLink(string relativePath)
    {
        var normalized = NormalizeRelativePath(relativePath);
        if (string.IsNullOrWhiteSpace(normalized))
        {
            return string.Empty;
        }

        return string.Join("/", normalized.Split('/').Select(Uri.EscapeDataString));
    }

    private static string MimeTypeForPath(string path)
    {
        return Path.GetExtension(path).ToLowerInvariant() switch
        {
            ".json" => "application/json",
            ".jsonl" => "application/x-ndjson",
            ".html" or ".htm" => "text/html",
            ".txt" or ".log" => "text/plain",
            ".bmp" => "image/bmp",
            ".png" => "image/png",
            ".jpg" or ".jpeg" => "image/jpeg",
            ".gif" => "image/gif",
            ".dmp" => "application/vnd.microsoft.minidump",
            ".pcap" => "application/vnd.tcpdump.pcap",
            ".pcapng" => "application/x-pcapng",
            ".zip" => "application/zip",
            ".exe" or ".dll" or ".sys" => "application/vnd.microsoft.portable-executable",
            _ => "application/octet-stream"
        };
    }

    private static string CombineRelative(params string[] segments)
    {
        return string.Join("/", segments.Where(segment => !string.IsNullOrWhiteSpace(segment)).Select(segment => segment.Trim('/', '\\')));
    }

    private static string ValueOrEmpty(IReadOnlyDictionary<string, string> metadata, params string[] keys)
    {
        foreach (var key in keys)
        {
            if (metadata.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return string.Empty;
    }

    private static string FirstNonEmpty(params string?[] values)
    {
        foreach (var value in values)
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return string.Empty;
    }

    private static void AddIfNotEmpty(Dictionary<string, string> metadata, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            metadata[key] = value;
        }
    }

    private static void AddIfMissing(Dictionary<string, string> metadata, string key, string? value)
    {
        if ((!metadata.ContainsKey(key) || string.IsNullOrWhiteSpace(metadata[key])) &&
            !string.IsNullOrWhiteSpace(value))
        {
            metadata[key] = value;
        }
    }

    private static void AddStableFallback(Dictionary<string, string> metadata, string key, string value)
    {
        if (!metadata.ContainsKey(key) || string.IsNullOrWhiteSpace(metadata[key]))
        {
            metadata[key] = value;
        }
    }

    private sealed record ArtifactClassification(ArtifactKind Kind, string Category, string EvidenceRole, string CollectionName)
    {
        public static ArtifactClassification Unknown { get; } = new(ArtifactKind.Unknown, string.Empty, string.Empty, string.Empty);
    }
}
