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
internal sealed record DroppedFileArtifactMetadata(string OriginalFullPath, string OriginalRelativePath, string SourceEventType);

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
        AddIfNotEmpty(metadata, "importPath", relativePath);
        AddIfNotEmpty(metadata, "artifactRelativePath", relativePath);
        AddIfNotEmpty(metadata, "artifactFullPath", artifactFullPath);
        AddIfNotEmpty(metadata, "guestFullPath", FirstNonEmpty(droppedFileMetadata?.OriginalFullPath, ValueOrEmpty(metadata, "guestFullPath", "guestPath"), artifactFullPath));
        AddIfNotEmpty(metadata, "captureState", InferCaptureState(classification, metadata));

        if (droppedFileMetadata is not null)
        {
            metadata["guestRelativePath"] = droppedFileMetadata.OriginalRelativePath;
            metadata["sourceEventType"] = droppedFileMetadata.SourceEventType;
        }

        if (metadata.TryGetValue("phase", out var phase))
        {
            AddIfNotEmpty(metadata, "capturePhase", phase);
        }

        return metadata;
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
                reasonWhenDisabled: "collectDroppedFilesNotRequested"),
            CreateCollection(descriptors, events, "screenshots", ArtifactKind.Screenshot, "screenshot", "screenshot",
                ScreenshotsDirectoryName, options.CaptureScreenshots, implemented: true,
                capturedEventPrefixes: ["screenshot.captured"], skippedEventPrefixes: ["screenshot.skipped"],
                reasonWhenDisabled: "screenshotNotRequested"),
            CreateCollection(descriptors, events, "memory-dumps", ArtifactKind.MemoryDump, "memory-dump", "memory-dump",
                MemoryDumpsDirectoryName, options.CaptureMemoryDump, implemented: true,
                capturedEventPrefixes: ["memory_dump.captured"], skippedEventPrefixes: ["memory_dump.skipped"],
                reasonWhenDisabled: "memoryDumpNotRequested"),
            CreateCollection(descriptors, events, "driver-events", ArtifactKind.DriverEventsJsonLines, "telemetry", "driver-events",
                FirstRelativePath(descriptors, "driver-events") ?? "driver-events.jsonl",
                options.DriverEventsRequested || descriptors.Any(artifact => string.Equals(artifact.CollectionName, "driver-events", StringComparison.OrdinalIgnoreCase)),
                implemented: true, capturedEventPrefixes: ["driver.load", "driver.process", "driver.file", "driver.registry", "driver.network", "driver.event", "driver.parse_error", "image.load", "r0collector.driver", "r0collector.exited"],
                skippedEventPrefixes: ["driver.events.missing", "r0collector.failed"], reasonWhenDisabled: "driverEventsNotRequested",
                failedEventPrefixes: ["driver.read_error"]),
            CreateCollection(descriptors, events, "r0-logs", ArtifactKind.Log, "log", "diagnostic-log",
                FirstRelativePath(descriptors, "r0-logs") ?? "r0collector.stdout.log",
                options.R0CollectorRequested || descriptors.Any(artifact => string.Equals(artifact.CollectionName, "r0-logs", StringComparison.OrdinalIgnoreCase)),
                implemented: true, capturedEventPrefixes: ["r0collector.started", "r0collector.exited", "r0collector.failed"],
                skippedEventPrefixes: [], reasonWhenDisabled: "r0CollectorNotRequested"),
            CreateCollection(descriptors, events, "packet-captures", ArtifactKind.PacketCapture, "packet-capture", "packet-capture",
                PacketCapturesDirectoryName, options.CapturePacketCapture, implemented: true,
                capturedEventPrefixes: ["packet_capture.captured"], skippedEventPrefixes: ["packet_capture.skipped"],
                reasonWhenDisabled: "packetCaptureNotRequested", failedEventPrefixes: ["packet_capture.failed"])
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
        string reasonWhenDisabled,
        IReadOnlyList<string>? failedEventPrefixes = null)
    {
        var artifactCount = descriptors.Count(artifact => string.Equals(artifact.CollectionName, name, StringComparison.OrdinalIgnoreCase));
        var capturedEventCount = CountEvents(events, capturedEventPrefixes);
        var skippedEventCount = CountEvents(events, skippedEventPrefixes);
        var failedEventCount = (failedEventPrefixes is null ? 0 : CountEvents(events, failedEventPrefixes)) + CountProbeFailureEvents(events, name);
        var status = DetermineCollectionStatus(enabled, implemented, artifactCount, capturedEventCount, skippedEventCount, failedEventCount);
        var normalizedRelativePath = NormalizeRelativePath(relativePath);
        var metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["collectionName"] = name,
            ["evidenceRole"] = evidenceRole,
            ["artifactCount"] = artifactCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["capturedEventCount"] = capturedEventCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["skippedEventCount"] = skippedEventCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["failedEventCount"] = failedEventCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["safeByDefault"] = (!enabled).ToString(System.Globalization.CultureInfo.InvariantCulture)
        };

        AddLastCollectionEventMetadata(
            metadata,
            events,
            name,
            capturedEventPrefixes,
            skippedEventPrefixes,
            failedEventPrefixes ?? Array.Empty<string>());
        var concreteStatusReason = LastCollectionReason(
            events,
            name,
            status,
            skippedEventPrefixes,
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

    private static string DetermineCollectionStatus(
        bool enabled,
        bool implemented,
        int artifactCount,
        int capturedEventCount,
        int skippedEventCount,
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

        if (skippedEventCount > 0)
        {
            return "skipped";
        }

        return "enabled-empty";
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

        if (evt.Data.TryGetValue("relativePath", out var relative) && !string.IsNullOrWhiteSpace(relative))
        {
            var normalized = NormalizeRelativePath(relative);
            if (!string.IsNullOrWhiteSpace(normalized))
            {
                yield return normalized;
            }
        }

        if (evt.Data.TryGetValue("artifactRelativePath", out var artifactRelativePath) && !string.IsNullOrWhiteSpace(artifactRelativePath))
        {
            var normalized = NormalizeRelativePath(artifactRelativePath);
            if (!string.IsNullOrWhiteSpace(normalized))
            {
                yield return normalized;
            }
        }

        foreach (var key in new[] { "driverEventsPath", "stdoutPath", "stderrPath", "jsonlPath" })
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
        IReadOnlyList<string> failedEventPrefixes)
    {
        for (var index = events.Count - 1; index >= 0; index--)
        {
            var evt = events[index];
            var matchesStatus = status switch
            {
                "failed" => EventTypeMatches(evt, failedEventPrefixes) || IsProbeFailureForCollection(evt, collectionName),
                "skipped" => EventTypeMatches(evt, skippedEventPrefixes),
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
        IReadOnlyList<string> failedEventPrefixes)
    {
        SandboxEvent? lastRelevant = null;
        SandboxEvent? lastDiagnostic = null;
        for (var index = 0; index < events.Count; index++)
        {
            var evt = events[index];
            if (!IsCollectionEvent(evt, collectionName, capturedEventPrefixes, skippedEventPrefixes, failedEventPrefixes))
            {
                continue;
            }

            lastRelevant = evt;
            if (HasDiagnosticData(evt))
            {
                lastDiagnostic = evt;
            }
        }

        if (lastRelevant is not null)
        {
            CopyEventDataIfPresent(metadata, lastRelevant, "phase", "lastPhase");
            CopyEventDataIfPresent(metadata, lastRelevant, "capturePhase", "lastCapturePhase");
            CopyEventDataIfPresent(metadata, lastRelevant, "status", "lastStatus");
            CopyEventDataIfPresent(metadata, lastRelevant, "captureState", "lastCaptureState");
            CopyEventDataIfPresent(metadata, lastRelevant, "nonfatal", "lastNonfatal");
            CopyEventDataIfPresent(metadata, lastRelevant, "artifactRelativePath", "lastArtifactRelativePath");
            CopyEventDataIfPresent(metadata, lastRelevant, "relativePath", "lastRelativePath");
            CopyProcessIdentity(metadata, lastRelevant);
        }

        if (lastDiagnostic is not null)
        {
            metadata["lastEventType"] = lastDiagnostic.EventType;
            CopyEventDataIfPresent(metadata, lastDiagnostic, "reason", "lastReason");
            CopyEventDataIfPresent(metadata, lastDiagnostic, "diagnosticStage", "lastDiagnosticStage");
            CopyEventDataIfPresent(metadata, lastDiagnostic, "exceptionType", "lastExceptionType");
            CopyEventDataIfPresent(metadata, lastDiagnostic, "win32Error", "lastWin32Error");
            CopyEventDataIfPresent(metadata, lastDiagnostic, "commandFileName", "lastCommandFileName");
            CopyEventDataIfPresent(metadata, lastDiagnostic, "commandExitCode", "lastCommandExitCode");
            CopyEventDataIfPresent(metadata, lastDiagnostic, "commandTimedOut", "lastCommandTimedOut");
            CopyEventDataIfPresent(metadata, lastDiagnostic, "commandExceptionType", "lastCommandExceptionType");
            CopyEventDataIfPresent(metadata, lastDiagnostic, "commandMessage", "lastCommandMessage");
            CopyEventDataIfPresent(metadata, lastDiagnostic, "probeId", "lastProbeId");
            CopyProcessIdentity(metadata, lastDiagnostic);
        }
    }

    private static bool IsCollectionEvent(
        SandboxEvent evt,
        string collectionName,
        IReadOnlyList<string> capturedEventPrefixes,
        IReadOnlyList<string> skippedEventPrefixes,
        IReadOnlyList<string> failedEventPrefixes)
    {
        return HasCollectionName(evt, collectionName) ||
            IsProbeFailureForCollection(evt, collectionName) ||
            EventTypeMatches(evt, capturedEventPrefixes) ||
            EventTypeMatches(evt, skippedEventPrefixes) ||
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
        return evt.Data.ContainsKey("reason") ||
            evt.Data.ContainsKey("diagnosticStage") ||
            evt.Data.ContainsKey("exceptionType") ||
            evt.Data.ContainsKey("commandMessage") ||
            IsProbeFailureEvent(evt);
    }

    private static void CopyEventDataIfPresent(Dictionary<string, string> metadata, SandboxEvent evt, string sourceKey, string destinationKey)
    {
        if (evt.Data.TryGetValue(sourceKey, out var value) && !string.IsNullOrWhiteSpace(value))
        {
            metadata[destinationKey] = value;
        }
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

    private sealed record ArtifactClassification(ArtifactKind Kind, string Category, string EvidenceRole, string CollectionName)
    {
        public static ArtifactClassification Unknown { get; } = new(ArtifactKind.Unknown, string.Empty, string.Empty, string.Empty);
    }
}
