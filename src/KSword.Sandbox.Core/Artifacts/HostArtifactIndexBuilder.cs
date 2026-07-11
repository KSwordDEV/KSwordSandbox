using KSword.Sandbox.Abstractions;
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
    public HostArtifactIndex Build(Guid jobId, string jobRoot, ArtifactCollectionConfig? artifactCollection = null)
    {
        var fullJobRoot = Path.GetFullPath(jobRoot);
        var guestManifests = Directory.Exists(fullJobRoot)
            ? LoadGuestManifests(fullJobRoot)
            : [];
        var guestEventContexts = Directory.Exists(fullJobRoot)
            ? LoadGuestEventContexts(fullJobRoot, guestManifests)
            : [];
        var guestArtifactsByFullPath = BuildGuestArtifactLookup(guestManifests, out var guestArtifactRejections);
        var eventMetadataByFullPath = BuildEventMetadataLookup(guestEventContexts);
        var collectionEventMetadata = BuildCollectionEventMetadataLookup(guestEventContexts);
        var artifacts = new List<ArtifactDescriptor>();
        var indexedFullPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
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
                    ["importPath"] = ArtifactDescriptorFactory.SafeRelativePath(fullJobRoot, path),
                    ["hrefPolicy"] = "relative-safe-link-only"
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

                var fullPath = Path.GetFullPath(path);
                if (eventMetadataByFullPath.TryGetValue(fullPath, out var eventMetadata))
                {
                    foreach (var pair in eventMetadata)
                    {
                        metadata[pair.Key] = pair.Value;
                    }
                }

                var descriptor = ArtifactDescriptorFactory.FromExistingFile(
                    path,
                    fullJobRoot,
                    classification.Kind,
                    metadata,
                    classification.Category);
                if (guestArtifactsByFullPath.TryGetValue(fullPath, out var guestArtifact))
                {
                    descriptor = MergeGuestDescriptor(descriptor, guestArtifact, fullJobRoot);
                }

                artifacts.Add(descriptor);
                indexedFullPaths.Add(fullPath);
            }
        }

        foreach (var guestArtifact in guestArtifactsByFullPath.Values
            .OrderBy(artifact => ArtifactDescriptorFactory.SafeRelativePath(fullJobRoot, artifact.FullPath), StringComparer.OrdinalIgnoreCase))
        {
            var fullPath = Path.GetFullPath(guestArtifact.FullPath);
            if (!File.Exists(fullPath) || !indexedFullPaths.Add(fullPath))
            {
                continue;
            }

            var kind = guestArtifact.Kind == ArtifactKind.Unknown
                ? Classify(fullPath, fullJobRoot).Kind
                : guestArtifact.Kind;
            if (kind == ArtifactKind.Unknown)
            {
                continue;
            }

            var descriptor = ArtifactDescriptorFactory.FromExistingFile(
                fullPath,
                fullJobRoot,
                kind,
                MergeMetadata(
                    CreateGuestDescriptorMetadata(guestArtifact, fullJobRoot),
                    eventMetadataByFullPath.GetValueOrDefault(fullPath)),
                guestArtifact.Category);
            artifacts.Add(MergeGuestDescriptor(descriptor, guestArtifact, fullJobRoot));
        }

        artifacts = MarkDuplicateArtifacts(artifacts)
            .OrderBy(artifact => artifact.RelativePath, StringComparer.OrdinalIgnoreCase)
            .ToList();
        var collections = BuildCollections(artifacts, guestManifests, collectionEventMetadata, guestArtifactRejections, fullJobRoot);
        collections = AddExpectedArtifactCollections(collections, artifactCollection, collectionEventMetadata)
            .OrderBy(collection => collection.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

        return new HostArtifactIndex
        {
            JobId = jobId,
            RootPath = fullJobRoot,
            CollectionCount = collections.Count,
            ArtifactCount = artifacts.Count,
            DownloadableArtifactCount = artifacts.Count(IsDownloadableArtifact),
            SensitiveArtifactCount = artifacts.Count(IsSensitiveArtifact),
            DuplicateArtifactCount = artifacts.Count(IsDuplicateArtifact),
            RejectedArtifactCount = guestArtifactRejections.Count,
            GeneratedAtUtc = DateTimeOffset.UtcNow,
            Collections = collections,
            Artifacts = artifacts
        };
    }

    /// <summary>
    /// Writes artifact-index.json under the job root.
    /// Inputs are a job ID and job root; processing builds and serializes the
    /// index; the method returns a descriptor for the index artifact.
    /// </summary>
    public ArtifactDescriptor WriteIndex(Guid jobId, string jobRoot, ArtifactCollectionConfig? artifactCollection = null)
    {
        var fullJobRoot = Path.GetFullPath(jobRoot);
        Directory.CreateDirectory(fullJobRoot);
        var index = Build(jobId, fullJobRoot, artifactCollection);
        var indexPath = Path.Combine(fullJobRoot, IndexFileName);
        File.WriteAllText(indexPath, JsonSerializer.Serialize(index, JsonOptions));
        return ArtifactDescriptorFactory.FromExistingFile(
            indexPath,
            fullJobRoot,
            ArtifactKind.ArtifactIndex,
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["origin"] = "host",
                ["schemaVersion"] = index.SchemaVersion.ToString(CultureInfo.InvariantCulture),
                ["rootPathPolicy"] = index.RootPathPolicy,
                ["downloadPolicy"] = index.DownloadPolicy,
                ["artifactCount"] = index.ArtifactCount.ToString(CultureInfo.InvariantCulture),
                ["collectionCount"] = index.CollectionCount.ToString(CultureInfo.InvariantCulture),
                ["downloadableArtifactCount"] = index.DownloadableArtifactCount.ToString(CultureInfo.InvariantCulture),
                ["sensitiveArtifactCount"] = index.SensitiveArtifactCount.ToString(CultureInfo.InvariantCulture),
                ["duplicateArtifactCount"] = index.DuplicateArtifactCount.ToString(CultureInfo.InvariantCulture),
                ["rejectedArtifactCount"] = index.RejectedArtifactCount.ToString(CultureInfo.InvariantCulture)
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

    private static List<GuestManifestContext> LoadGuestManifests(string jobRoot)
    {
        var manifests = new List<GuestManifestContext>();
        var reader = new GuestArtifactManifestReader();
        foreach (var manifestPath in Directory
            .EnumerateFiles(jobRoot, GuestArtifactManifestReader.ManifestFileName, SearchOption.AllDirectories)
            .OrderBy(path => path, StringComparer.OrdinalIgnoreCase))
        {
            var artifactsDirectory = Path.GetDirectoryName(manifestPath);
            if (string.IsNullOrWhiteSpace(artifactsDirectory) ||
                !string.Equals(Path.GetFileName(artifactsDirectory), GuestArtifactManifestReader.ArtifactsDirectoryName, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var guestRoot = Directory.GetParent(artifactsDirectory)?.FullName;
            if (string.IsNullOrWhiteSpace(guestRoot) || !IsSameOrUnderDirectory(guestRoot, jobRoot))
            {
                continue;
            }

            try
            {
                var manifest = reader.TryRead(guestRoot);
                if (manifest is null)
                {
                    continue;
                }

                manifests.Add(new GuestManifestContext(
                    Path.GetFullPath(guestRoot),
                    ArtifactDescriptorFactory.SafeRelativePath(jobRoot, guestRoot),
                    manifest));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or NotSupportedException or PathTooLongException)
            {
                // A corrupt optional guest manifest must not prevent host-side
                // indexing of the files that were successfully collected.
            }
        }

        return manifests;
    }

    private static Dictionary<string, ArtifactDescriptor> BuildGuestArtifactLookup(
        IReadOnlyList<GuestManifestContext> guestManifests,
        out List<ArtifactIndexRejection> rejections)
    {
        var artifacts = new Dictionary<string, ArtifactDescriptor>(StringComparer.OrdinalIgnoreCase);
        rejections = [];
        foreach (var context in guestManifests)
        {
            foreach (var artifact in context.Manifest.Artifacts ?? [])
            {
                var fullPath = ResolveGuestArtifactFullPath(context.GuestRoot, artifact);
                if (string.IsNullOrWhiteSpace(fullPath))
                {
                    rejections.Add(CreateArtifactRejection(context, artifact, "unsafeGuestArtifactPath"));
                    continue;
                }

                if (!File.Exists(fullPath))
                {
                    rejections.Add(CreateArtifactRejection(context, artifact with { FullPath = fullPath }, "missingGuestArtifactFile"));
                    continue;
                }

                if (artifacts.ContainsKey(fullPath))
                {
                    rejections.Add(CreateArtifactRejection(context, artifact with { FullPath = fullPath }, "duplicateGuestArtifactReference"));
                    continue;
                }

                artifacts.Add(fullPath, artifact with { FullPath = fullPath });
            }
        }

        return artifacts;
    }

    private static List<GuestEventContext> LoadGuestEventContexts(
        string jobRoot,
        IReadOnlyList<GuestManifestContext> guestManifests)
    {
        var contexts = new List<GuestEventContext>();
        var seenGuestRoots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var context in guestManifests)
        {
            if (seenGuestRoots.Add(context.GuestRoot))
            {
                AddGuestEventContext(context.GuestRoot, jobRoot, contexts);
            }
        }

        foreach (var eventsPath in Directory
            .EnumerateFiles(jobRoot, "events.json", SearchOption.AllDirectories)
            .OrderBy(path => path, StringComparer.OrdinalIgnoreCase))
        {
            var guestRoot = Path.GetDirectoryName(eventsPath);
            if (string.IsNullOrWhiteSpace(guestRoot) || !IsSameOrUnderDirectory(guestRoot, jobRoot))
            {
                continue;
            }

            if (seenGuestRoots.Add(Path.GetFullPath(guestRoot)))
            {
                AddGuestEventContext(guestRoot, jobRoot, contexts);
            }
        }

        return contexts;
    }

    private static void AddGuestEventContext(
        string guestRoot,
        string jobRoot,
        List<GuestEventContext> contexts)
    {
        var eventsPath = Path.Combine(guestRoot, "events.json");
        var events = TryLoadSandboxEvents(eventsPath);
        if (events.Count == 0)
        {
            return;
        }

        contexts.Add(new GuestEventContext(
            Path.GetFullPath(guestRoot),
            ArtifactDescriptorFactory.SafeRelativePath(jobRoot, guestRoot),
            eventsPath,
            events));
    }

    private static IReadOnlyList<SandboxEvent> TryLoadSandboxEvents(string eventsPath)
    {
        if (!File.Exists(eventsPath))
        {
            return [];
        }

        try
        {
            return JsonSerializer.Deserialize<List<SandboxEvent>>(File.ReadAllText(eventsPath), JsonOptions) ?? [];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or NotSupportedException)
        {
            return [];
        }
    }

    private static Dictionary<string, Dictionary<string, string>> BuildEventMetadataLookup(
        IReadOnlyList<GuestEventContext> guestEventContexts)
    {
        var metadataByFullPath = new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var context in guestEventContexts)
        {
            foreach (var evt in context.Events)
            {
                foreach (var fullPath in CandidateEventArtifactPaths(context, evt).Distinct(StringComparer.OrdinalIgnoreCase))
                {
                    if (!metadataByFullPath.TryGetValue(fullPath, out var metadata))
                    {
                        metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                        metadataByFullPath[fullPath] = metadata;
                    }

                    MergeEventMetadata(metadata, evt, context);
                }
            }
        }

        return metadataByFullPath;
    }

    private static Dictionary<string, Dictionary<string, string>> BuildCollectionEventMetadataLookup(
        IReadOnlyList<GuestEventContext> guestEventContexts)
    {
        var metadataByCollection = new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var context in guestEventContexts)
        {
            foreach (var evt in context.Events)
            {
                var collectionName = ResolveEventCollectionName(evt);
                if (string.IsNullOrWhiteSpace(collectionName))
                {
                    continue;
                }

                if (!metadataByCollection.TryGetValue(collectionName, out var metadata))
                {
                    metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["eventSummarySource"] = "events.json",
                        ["eventSummaryPath"] = context.EventsPath
                    };
                    metadataByCollection[collectionName] = metadata;
                }

                IncrementMetadataCount(metadata, "eventCount");
                var state = InferCaptureState(evt.EventType);
                if (!string.IsNullOrWhiteSpace(state))
                {
                    IncrementMetadataCount(metadata, $"{state}EventCount");
                    metadata["lastCaptureState"] = state;
                }

                AddIfNotEmpty(metadata, "lastEventType", evt.EventType);
                AddIfNotEmpty(metadata, "lastEventPath", evt.Path);
                CopyEventDataIfPresent(metadata, evt, "reason", "lastReason");
                CopyEventDataIfPresent(metadata, evt, "exceptionType", "lastExceptionType");
                CopyEventDataIfPresent(metadata, evt, "diagnosticStage", "lastDiagnosticStage");
                CopyEventDataIfPresent(metadata, evt, "win32Error", "lastWin32Error");
                CopyEventDataIfPresent(metadata, evt, "commandMessage", "lastCommandMessage");
                CopyEventDataIfPresent(metadata, evt, "commandExceptionType", "lastCommandExceptionType");
                CopyEventDataIfPresent(metadata, evt, "zhMessage", "lastZhMessage");
                CopyEventDataIfPresent(metadata, evt, "zhHint", "lastZhHint");
                CopyEventDataIfPresent(metadata, evt, "zhStatus", "lastZhStatus");
                CopyEventDataIfPresent(metadata, evt, "zhReason", "lastZhReason");
                CopyEventDataIfPresent(metadata, evt, "status", "lastStatus");
                CopyEventDataIfPresent(metadata, evt, "captureState", "lastCaptureState");
                CopyFirstEventDataIfPresent(metadata, evt, "lastArtifactRelativePath",
                    "artifactRelativePath",
                    "sourceArtifactRelativePath",
                    "packetCaptureRelativePath",
                    "pcapngRelativePath",
                    "pcapRelativePath",
                    "screenshotRelativePath",
                    "memoryDumpRelativePath",
                    "dumpRelativePath",
                    "relativePath",
                    "importPath");
                CopyFirstEventDataIfPresent(metadata, evt, "lastPhase", "phase", "capturePhase", "screenshotStage");
                CopyEventDataIfPresent(metadata, evt, "capturePhase", "lastCapturePhase");
                CopyEventDataIfPresent(metadata, evt, "processId", "lastProcessId");
                CopyEventDataIfPresent(metadata, evt, "parentProcessId", "lastParentProcessId");
                CopyEventDataIfPresent(metadata, evt, "rootProcessId", "lastRootProcessId");
                CopyEventDataIfPresent(metadata, evt, "processRole", "lastProcessRole");
                CopyEventDataIfPresent(metadata, evt, "treeDepth", "lastTreeDepth");
                CopyEventDataIfPresent(metadata, evt, "treeLineage", "lastTreeLineage");
                CopyEventDataIfPresent(metadata, evt, "childProcessCount", "lastChildProcessCount");
                CopyEventDataIfPresent(metadata, evt, "sourceHashStatus", "lastSourceHashStatus");
                CopyEventDataIfPresent(metadata, evt, "sourceSha256", "lastSourceSha256");
                CopyEventDataIfPresent(metadata, evt, "copiedSha256", "lastCopiedSha256");
                CopyEventDataIfPresent(metadata, evt, "packetCountStatus", "lastDiagnosticPacketCountStatus");
                CopyEventDataIfPresent(metadata, evt, "packetCount", "lastDiagnosticPacketCount");
                CopyEventDataIfPresent(metadata, evt, "pcapngBlockCount", "lastDiagnosticPcapngBlockCount");
                CopyEventDataIfPresent(metadata, evt, "pcapngEnhancedPacketBlockCount", "lastDiagnosticPcapngEnhancedPacketBlockCount");
                CopyEventDataIfPresent(metadata, evt, "pcapngSimplePacketBlockCount", "lastDiagnosticPcapngSimplePacketBlockCount");
                CopyEventDataIfPresent(metadata, evt, "pcapngSectionHeaderCount", "lastDiagnosticPcapngSectionHeaderCount");
                CopyFirstEventDataIfPresent(metadata, evt, "lastDiagnosticPcapngRelativePath",
                    "pcapngRelativePath",
                    "packetCaptureRelativePath",
                    "pcapRelativePath",
                    "artifactRelativePath",
                    "sourceArtifactRelativePath");
                CopyFirstEventDataIfPresent(metadata, evt, "lastDiagnosticPcapngSizeBytes",
                    "pcapngSizeBytes",
                    "sourceArtifactSizeBytes",
                    "sizeBytes");
                CopyFirstEventDataIfPresent(metadata, evt, "lastDiagnosticPcapngSha256",
                    "pcapngSha256",
                    "sourceArtifactSha256",
                    "sha256");

                if (evt.ProcessId is not null)
                {
                    metadata["lastProcessId"] = evt.ProcessId.Value.ToString(CultureInfo.InvariantCulture);
                }

                if (evt.ParentProcessId is not null)
                {
                    metadata["lastParentProcessId"] = evt.ParentProcessId.Value.ToString(CultureInfo.InvariantCulture);
                }

                if (string.Equals(evt.EventType, "memory_dump.sweep", StringComparison.OrdinalIgnoreCase))
                {
                    CopyEventDataIfPresent(metadata, evt, "rootProcessId", "sweepRootProcessId");
                    CopyEventDataIfPresent(metadata, evt, "visibleTargetCount", "sweepVisibleTargetCount");
                    CopyEventDataIfPresent(metadata, evt, "attemptedCount", "sweepAttemptedCount");
                    CopyEventDataIfPresent(metadata, evt, "capturedCount", "sweepCapturedCount");
                    CopyEventDataIfPresent(metadata, evt, "skippedCount", "sweepSkippedCount");
                    CopyEventDataIfPresent(metadata, evt, "alreadyCapturedCount", "sweepAlreadyCapturedCount");
                }
            }
        }

        return metadataByCollection;
    }

    private static IEnumerable<string> CandidateEventArtifactPaths(GuestEventContext context, SandboxEvent evt)
    {
        foreach (var relativePath in CandidateEventRelativePaths(evt))
        {
            var fullPath = ResolveRelativeUnderRoot(context.GuestRoot, relativePath);
            if (!string.IsNullOrWhiteSpace(fullPath))
            {
                yield return fullPath;
            }
        }

        foreach (var path in CandidateEventAbsolutePaths(evt))
        {
            var fullPath = ResolveAbsoluteUnderRoot(context.GuestRoot, path);
            if (!string.IsNullOrWhiteSpace(fullPath))
            {
                yield return fullPath;
            }
        }
    }

    private static IEnumerable<string> CandidateEventRelativePaths(SandboxEvent evt)
    {
        foreach (var key in new[]
        {
            "artifactRelativePath",
            "relativePath",
            "importPath",
            "expectedRelativePath",
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
            "etlRelativePath",
            "diagnosticRelativePath"
        })
        {
            if (!evt.Data.TryGetValue(key, out var raw) || string.IsNullOrWhiteSpace(raw) || raw.Contains('*', StringComparison.Ordinal))
            {
                continue;
            }

            var normalized = ArtifactDescriptorFactory.NormalizeRelativePath(raw);
            if (!string.IsNullOrWhiteSpace(normalized))
            {
                yield return normalized;
            }
        }
    }

    private static IEnumerable<string> CandidateEventAbsolutePaths(SandboxEvent evt)
    {
        if (!string.IsNullOrWhiteSpace(evt.Path))
        {
            yield return evt.Path;
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
            if (evt.Data.TryGetValue(key, out var raw) && !string.IsNullOrWhiteSpace(raw))
            {
                yield return raw;
            }
        }
    }

    private static string ResolveRelativeUnderRoot(string root, string relativePath)
    {
        try
        {
            var fullPath = Path.GetFullPath(Path.Combine(root, relativePath));
            return IsSameOrUnderDirectory(fullPath, root) ? fullPath : string.Empty;
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return string.Empty;
        }
    }

    private static string ResolveAbsoluteUnderRoot(string root, string path)
    {
        try
        {
            var fullPath = Path.GetFullPath(path);
            return IsSameOrUnderDirectory(fullPath, root) ? fullPath : string.Empty;
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return string.Empty;
        }
    }

    private static void MergeEventMetadata(
        Dictionary<string, string> metadata,
        SandboxEvent evt,
        GuestEventContext context)
    {
        AddIfNotEmpty(metadata, "sourceEventType", evt.EventType);
        AddIfNotEmpty(metadata, "sourceEventSource", evt.Source);
        AddIfNotEmpty(metadata, "sourceEventPath", evt.Path);
        AddIfNotEmpty(metadata, "sourceEventsPath", context.EventsPath);
        AddIfNotEmpty(metadata, "guestOutputRoot", context.HostRelativeGuestRoot);
        AddIfNotEmpty(metadata, "processName", evt.ProcessName);
        AddIfNotEmpty(metadata, "commandLine", evt.CommandLine);
        if (evt.ProcessId is not null)
        {
            metadata["processId"] = evt.ProcessId.Value.ToString(CultureInfo.InvariantCulture);
        }

        if (evt.ParentProcessId is not null)
        {
            metadata["parentProcessId"] = evt.ParentProcessId.Value.ToString(CultureInfo.InvariantCulture);
        }

        foreach (var pair in evt.Data)
        {
            AddIfNotEmpty(metadata, pair.Key, pair.Value);
        }

        AddIfNotEmpty(metadata, "captureState", InferCaptureState(evt.EventType));
    }

    private static string ResolveEventCollectionName(SandboxEvent evt)
    {
        if (evt.Data.TryGetValue("collectionName", out var collectionName) && !string.IsNullOrWhiteSpace(collectionName))
        {
            return collectionName;
        }

        if (evt.EventType.StartsWith("artifact.dropped_file.", StringComparison.OrdinalIgnoreCase))
        {
            return "dropped-files";
        }

        if (evt.EventType.StartsWith("screenshot.", StringComparison.OrdinalIgnoreCase))
        {
            return "screenshots";
        }

        if (evt.EventType.StartsWith("memory_dump.", StringComparison.OrdinalIgnoreCase))
        {
            return "memory-dumps";
        }

        if (evt.EventType.StartsWith("packet_capture.", StringComparison.OrdinalIgnoreCase))
        {
            return "packet-captures";
        }

        if (evt.EventType.StartsWith("pcap.", StringComparison.OrdinalIgnoreCase))
        {
            return "packet-captures";
        }

        if (evt.EventType.StartsWith("driver.", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(evt.EventType, "image.load", StringComparison.OrdinalIgnoreCase))
        {
            return "driver-events";
        }

        if (evt.EventType.StartsWith("r0collector.", StringComparison.OrdinalIgnoreCase))
        {
            return "r0-logs";
        }

        return string.Empty;
    }

    private static string? InferCaptureState(string eventType)
    {
        if (eventType.EndsWith(".captured", StringComparison.OrdinalIgnoreCase) ||
            eventType.EndsWith(".copied", StringComparison.OrdinalIgnoreCase) ||
            eventType.EndsWith(".written", StringComparison.OrdinalIgnoreCase))
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

        if (eventType.EndsWith(".disabled", StringComparison.OrdinalIgnoreCase))
        {
            return "disabled";
        }

        if (eventType.EndsWith(".sweep", StringComparison.OrdinalIgnoreCase))
        {
            return "summary";
        }

        return null;
    }

    private static void IncrementMetadataCount(Dictionary<string, string> metadata, string key)
    {
        var next = metadata.TryGetValue(key, out var text) && int.TryParse(text, CultureInfo.InvariantCulture, out var current)
            ? current + 1
            : 1;
        metadata[key] = next.ToString(CultureInfo.InvariantCulture);
    }

    private static void CopyEventDataIfPresent(
        Dictionary<string, string> metadata,
        SandboxEvent evt,
        string sourceKey,
        string destinationKey)
    {
        if (evt.Data.TryGetValue(sourceKey, out var value) && !string.IsNullOrWhiteSpace(value))
        {
            metadata[destinationKey] = value;
        }
    }

    private static void CopyFirstEventDataIfPresent(
        Dictionary<string, string> metadata,
        SandboxEvent evt,
        string destinationKey,
        params string[] sourceKeys)
    {
        foreach (var sourceKey in sourceKeys)
        {
            if (evt.Data.TryGetValue(sourceKey, out var value) && !string.IsNullOrWhiteSpace(value))
            {
                metadata[destinationKey] = value;
                return;
            }
        }
    }

    private static string ResolveGuestArtifactFullPath(string guestRoot, ArtifactDescriptor artifact)
    {
        foreach (var relativePath in CandidateGuestArtifactSelectors(artifact).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                var fullPath = Path.GetFullPath(Path.Combine(guestRoot, relativePath));
                if (IsSameOrUnderDirectory(fullPath, guestRoot))
                {
                    return fullPath;
                }
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
            {
            }
        }

        if (HasGuestArtifactSelector(artifact))
        {
            return string.Empty;
        }

        if (!string.IsNullOrWhiteSpace(artifact.FullPath))
        {
            try
            {
                var fullPath = Path.GetFullPath(artifact.FullPath);
                var hostRelativePath = ArtifactDescriptorFactory.SafeRelativePath(guestRoot, fullPath);
                if (!string.IsNullOrWhiteSpace(hostRelativePath) &&
                    IsSameOrUnderDirectory(fullPath, guestRoot))
                {
                    return fullPath;
                }
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
            {
            }
        }

        return string.Empty;
    }

    private static IEnumerable<string> CandidateGuestArtifactSelectors(ArtifactDescriptor artifact)
    {
        foreach (var candidate in new[]
        {
            artifact.RelativePath,
            artifact.ImportPath,
            artifact.SafeLink,
            MetadataValue(artifact.Metadata, "artifactRelativePath"),
            MetadataValue(artifact.Metadata, "sourceArtifactRelativePath"),
            MetadataValue(artifact.Metadata, "downloadSelector"),
            MetadataValue(artifact.Metadata, "safeRelativeSelector"),
            MetadataValue(artifact.Metadata, "downloadSafeLink")
        })
        {
            var normalized = ArtifactDescriptorFactory.NormalizeSelector(candidate);
            if (!string.IsNullOrWhiteSpace(normalized))
            {
                yield return normalized;
            }
        }
    }

    private static bool HasGuestArtifactSelector(ArtifactDescriptor artifact)
    {
        return !string.IsNullOrWhiteSpace(artifact.RelativePath) ||
            !string.IsNullOrWhiteSpace(artifact.ImportPath) ||
            !string.IsNullOrWhiteSpace(artifact.SafeLink) ||
            HasMetadataValue(artifact.Metadata, "artifactRelativePath") ||
            HasMetadataValue(artifact.Metadata, "sourceArtifactRelativePath") ||
            HasMetadataValue(artifact.Metadata, "downloadSelector") ||
            HasMetadataValue(artifact.Metadata, "safeRelativeSelector") ||
            HasMetadataValue(artifact.Metadata, "downloadSafeLink");
    }

    private static ArtifactIndexRejection CreateArtifactRejection(
        GuestManifestContext context,
        ArtifactDescriptor artifact,
        string reason)
    {
        var collectionName = FirstNonEmpty(
            artifact.CollectionName,
            MetadataValue(artifact.Metadata, "collectionName"),
            CollectionNameForKind(artifact.Kind),
            "unclassified-artifacts");
        var attemptedSelector = FirstNonEmpty(
            artifact.RelativePath,
            artifact.ImportPath,
            artifact.SafeLink,
            artifact.Name,
            artifact.FullPath);

        return new ArtifactIndexRejection(
            collectionName,
            artifact.Kind,
            artifact.Name,
            attemptedSelector,
            reason,
            context.HostRelativeGuestRoot);
    }

    private static ArtifactDescriptor MergeGuestDescriptor(
        ArtifactDescriptor scanned,
        ArtifactDescriptor guest,
        string jobRoot)
    {
        var metadata = CreateGuestDescriptorMetadata(guest, jobRoot);
        foreach (var pair in scanned.Metadata)
        {
            AddIfMissing(metadata, pair.Key, pair.Value);
        }

        AddArtifactIdentityMetadata(metadata, scanned);
        AddIfNotEmpty(metadata, "hostRelativePath", scanned.RelativePath);
        AddIfNotEmpty(metadata, "hostFullPath", scanned.FullPath);
        AddIfNotEmpty(metadata, "indexedBy", nameof(HostArtifactIndexBuilder));

        return scanned with
        {
            Kind = guest.Kind == ArtifactKind.Unknown ? scanned.Kind : guest.Kind,
            Category = FirstNonEmpty(guest.Category, scanned.Category),
            EvidenceRole = FirstNonEmpty(guest.EvidenceRole, scanned.EvidenceRole, MetadataValue(metadata, "evidenceRole")),
            CapturePhase = FirstNonEmpty(guest.CapturePhase, scanned.CapturePhase, MetadataValue(metadata, "capturePhase", "phase")),
            CaptureState = FirstNonEmpty(guest.CaptureState, scanned.CaptureState, MetadataValue(metadata, "captureState")),
            GuestPath = FirstNonEmpty(guest.GuestPath, scanned.GuestPath, MetadataValue(metadata, "guestFullPath", "guestPath", "sourcePath")),
            CollectionName = FirstNonEmpty(guest.CollectionName, scanned.CollectionName, MetadataValue(metadata, "collectionName")),
            MimeType = FirstNonEmpty(scanned.MimeType, guest.MimeType),
            SizeBytes = scanned.SizeBytes > 0 ? scanned.SizeBytes : guest.SizeBytes,
            Sha256 = FirstNonEmpty(scanned.Sha256, guest.Sha256),
            Hashes = MergeHashes(scanned, guest, metadata),
            Metadata = metadata
        };
    }

    private static Dictionary<string, string> CreateGuestDescriptorMetadata(ArtifactDescriptor guest, string jobRoot)
    {
        _ = jobRoot;
        var metadata = CopyMetadata(guest.Metadata);
        AddIfMissing(metadata, "origin", "guest");
        AddIfMissing(metadata, "hrefPolicy", "relative-safe-link-only");
        AddIfNotEmpty(metadata, "guestManifestRelativePath", guest.RelativePath);
        AddIfNotEmpty(metadata, "guestManifestImportPath", guest.ImportPath);
        AddIfNotEmpty(metadata, "guestManifestFullPath", guest.FullPath);
        AddIfNotEmpty(metadata, "evidenceRole", guest.EvidenceRole);
        AddIfNotEmpty(metadata, "capturePhase", guest.CapturePhase);
        AddIfNotEmpty(metadata, "captureState", guest.CaptureState);
        AddIfNotEmpty(metadata, "collectionName", guest.CollectionName);
        AddIfNotEmpty(metadata, "guestFullPath", guest.GuestPath);
        if (guest.SizeBytes > 0)
        {
            metadata["guestManifestSizeBytes"] = guest.SizeBytes.ToString(CultureInfo.InvariantCulture);
        }

        AddIfNotEmpty(metadata, "rootProcessId", MetadataValue(guest.Metadata, "rootProcessId", "rootPid", "processRootId"));
        AddIfNotEmpty(metadata, "treeLineage", MetadataValue(guest.Metadata, "treeLineage", "processTreeLineage", "lineage"));
        AddIfNotEmpty(metadata, "guestManifestSha256", guest.Sha256);
        if (guest.Hashes is not null)
        {
            foreach (var pair in guest.Hashes)
            {
                AddIfNotEmpty(metadata, $"guestManifestHash.{pair.Key}", pair.Value);
            }
        }

        return metadata;
    }

    private static Dictionary<string, string> MergeHashes(
        ArtifactDescriptor scanned,
        ArtifactDescriptor guest,
        Dictionary<string, string> metadata)
    {
        var hashes = CopyMetadata(scanned.Hashes);
        if (guest.Hashes is not null)
        {
            foreach (var pair in guest.Hashes)
            {
                if (hashes.TryGetValue(pair.Key, out var existing) &&
                    !string.Equals(existing, pair.Value, StringComparison.OrdinalIgnoreCase))
                {
                    AddIfNotEmpty(metadata, $"guestManifestHash.{pair.Key}", pair.Value);
                    continue;
                }

                AddIfNotEmpty(hashes, pair.Key, pair.Value);
            }
        }

        if (!string.IsNullOrWhiteSpace(guest.Sha256) &&
            hashes.TryGetValue("sha256", out var sha256) &&
            !string.Equals(sha256, guest.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            metadata["guestManifestSha256"] = guest.Sha256;
        }
        else
        {
            AddIfNotEmpty(hashes, "sha256", guest.Sha256);
        }

        return hashes;
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

        if (string.Equals(fileName, "enrichment-events.json", StringComparison.OrdinalIgnoreCase))
        {
            return new ArtifactClassification(
                ArtifactKind.GuestEventsJson,
                EvidenceRole: "enrichment-events",
                CollectionName: "enrichment",
                CapturePhase: "host-enrichment",
                CaptureState: "available",
                Metadata: new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["telemetrySource"] = "host-enrichment",
                    ["containsVirusTotalLookup"] = "true"
                });
        }

        if (string.Equals(fileName, "agent-summary.json", StringComparison.OrdinalIgnoreCase))
        {
            return new ArtifactClassification(
                ArtifactKind.GuestSummaryJson,
                EvidenceRole: "guest-summary",
                CollectionName: "guest-summary",
                CaptureState: "available");
        }

        if (string.Equals(fileName, "artifact-manifest.json", StringComparison.OrdinalIgnoreCase) ||
            relativePath.EndsWith("/artifacts/manifest.json", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(relativePath, "artifacts/manifest.json", StringComparison.OrdinalIgnoreCase))
        {
            return new ArtifactClassification(
                ArtifactKind.ArtifactManifest,
                EvidenceRole: "artifact-manifest",
                CollectionName: "artifact-manifests",
                CaptureState: "available");
        }

        if (string.Equals(Path.GetExtension(path), ".jsonl", StringComparison.OrdinalIgnoreCase) &&
            fileName.Contains("driver", StringComparison.OrdinalIgnoreCase))
        {
            return new ArtifactClassification(
                ArtifactKind.DriverEventsJsonLines,
                EvidenceRole: "driver-events",
                CollectionName: "driver-events",
                CaptureState: "available",
                Metadata: new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["telemetryFormat"] = "jsonl"
                });
        }

        if (relativePath.Contains("/screenshots/", StringComparison.OrdinalIgnoreCase) ||
            relativePath.StartsWith("screenshots/", StringComparison.OrdinalIgnoreCase) ||
            IsScreenshotNamedImage(path, relativePath))
        {
            return new ArtifactClassification(
                ArtifactKind.Screenshot,
                EvidenceRole: "screenshot",
                CollectionName: "screenshots",
                CapturePhase: InferCapturePhase(fileName),
                CaptureState: "captured");
        }

        if (relativePath.Contains("/memory-dumps/", StringComparison.OrdinalIgnoreCase) ||
            relativePath.StartsWith("memory-dumps/", StringComparison.OrdinalIgnoreCase) ||
            relativePath.Contains("/dumps/", StringComparison.OrdinalIgnoreCase) ||
            relativePath.StartsWith("dumps/", StringComparison.OrdinalIgnoreCase) ||
            ArtifactDescriptorFactory.IsMemoryDumpPath(path))
        {
            return new ArtifactClassification(
                ArtifactKind.MemoryDump,
                Category: "memory-dump",
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
                Category: "packet-capture",
                EvidenceRole: "packet-capture",
                CollectionName: "packet-captures",
                CapturePhase: InferCapturePhase(fileName),
                CaptureState: "available",
                Metadata: BuildPacketCaptureMetadata(path));
        }

        if (relativePath.Contains("/artifacts/", StringComparison.OrdinalIgnoreCase) ||
            relativePath.StartsWith("artifacts/", StringComparison.OrdinalIgnoreCase) ||
            relativePath.Contains("/dropped-files/", StringComparison.OrdinalIgnoreCase) ||
            relativePath.StartsWith("dropped-files/", StringComparison.OrdinalIgnoreCase))
        {
            return new ArtifactClassification(
                ArtifactKind.DroppedFile,
                EvidenceRole: "dropped-file",
                CollectionName: "dropped-files",
                CaptureState: "captured");
        }

        if (fileName.StartsWith("r0collector.", StringComparison.OrdinalIgnoreCase) &&
            (string.Equals(Path.GetExtension(path), ".log", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(Path.GetExtension(path), ".txt", StringComparison.OrdinalIgnoreCase)))
        {
            return new ArtifactClassification(
                ArtifactKind.Log,
                EvidenceRole: "diagnostic-log",
                CollectionName: "r0-logs",
                CaptureState: "available");
        }

        if (string.Equals(Path.GetExtension(path), ".log", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(Path.GetExtension(path), ".txt", StringComparison.OrdinalIgnoreCase))
        {
            return new ArtifactClassification(
                ArtifactKind.Log,
                EvidenceRole: "log",
                CollectionName: "logs",
                CaptureState: "available");
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

    private static List<ArtifactCollectionDescriptor> BuildCollections(
        IReadOnlyList<ArtifactDescriptor> artifacts,
        IReadOnlyList<GuestManifestContext> guestManifests,
        IReadOnlyDictionary<string, Dictionary<string, string>> collectionEventMetadata,
        IReadOnlyList<ArtifactIndexRejection> guestArtifactRejections,
        string jobRoot)
    {
        var collections = artifacts
            .Where(artifact => !string.IsNullOrWhiteSpace(artifact.CollectionName))
            .GroupBy(artifact => artifact.CollectionName, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(
                group => group.Key,
                group => BuildCollection(
                    group.Key,
                    group.OrderBy(artifact => artifact.RelativePath, StringComparer.OrdinalIgnoreCase).ToList(),
                    collectionEventMetadata.GetValueOrDefault(group.Key)),
                StringComparer.OrdinalIgnoreCase);

        foreach (var context in guestManifests)
        {
            foreach (var collection in context.Manifest.Collections ?? [])
            {
                if (string.IsNullOrWhiteSpace(collection.Name))
                {
                    continue;
                }

                var normalized = NormalizeGuestCollectionForHost(
                    collection,
                    context,
                    collectionEventMetadata.GetValueOrDefault(collection.Name),
                    jobRoot);
                if (collections.TryGetValue(collection.Name, out var hostCollection))
                {
                    collections[collection.Name] = MergeGuestCollection(hostCollection, normalized);
                }
                else
                {
                    collections[collection.Name] = normalized;
                }
            }
        }

        foreach (var group in guestArtifactRejections
            .Where(rejection => !string.IsNullOrWhiteSpace(rejection.CollectionName))
            .GroupBy(rejection => rejection.CollectionName, StringComparer.OrdinalIgnoreCase))
        {
            if (collections.TryGetValue(group.Key, out var existing))
            {
                collections[group.Key] = AddArtifactRejectionDiagnostics(existing, group.ToList());
            }
            else
            {
                collections[group.Key] = BuildRejectedCollection(group.Key, group.ToList());
            }
        }

        return collections.Values
            .OrderBy(collection => collection.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static ArtifactCollectionDescriptor NormalizeGuestCollectionForHost(
        ArtifactCollectionDescriptor collection,
        GuestManifestContext context,
        IReadOnlyDictionary<string, string>? eventMetadata,
        string jobRoot)
    {
        _ = jobRoot;
        var guestRelativePath = FirstNonEmpty(collection.RelativePath, collection.ImportPath, collection.Name);
        var hostRelativePath = PrefixGuestRelativePath(context, guestRelativePath);
        var metadata = CopyMetadata(collection.Metadata);
        foreach (var pair in eventMetadata ?? EmptyMetadata)
        {
            AddIfMissing(metadata, pair.Key, pair.Value);
        }

        AddIfMissing(metadata, "origin", "guest-manifest");
        AddIfMissing(metadata, "hrefPolicy", "relative-safe-link-only");
        AddIfNotEmpty(metadata, "guestManifestRoot", context.HostRelativeGuestRoot);
        AddIfNotEmpty(metadata, "guestManifestCollectionPath", guestRelativePath);
        AddIfNotEmpty(metadata, "guestManifestStatus", collection.Status);
        AddIfNotEmpty(metadata, "guestManifestReason", collection.Reason);
        metadata["guestCollectionEnabled"] = collection.Enabled.ToString(CultureInfo.InvariantCulture).ToLowerInvariant();
        metadata["guestCollectionImplemented"] = collection.Implemented.ToString(CultureInfo.InvariantCulture).ToLowerInvariant();
        AddIfNotEmpty(metadata, "guestCollectionStatus", collection.Status);
        AddIfNotEmpty(metadata, "guestCollectionReason", collection.Reason);
        AddCollectionPresentationMetadata(
            metadata,
            collection.Name,
            collection.Kind,
            collection.Status,
            collection.Reason,
            ParseMetadataCount(metadata, "downloadableArtifactCount", "artifactCount"));

        return collection with
        {
            Category = string.IsNullOrWhiteSpace(collection.Category)
                ? ArtifactDescriptorFactory.CategoryForKind(collection.Kind)
                : collection.Category,
            RelativePath = hostRelativePath,
            SafeLink = ArtifactDescriptorFactory.BuildSafeLink(hostRelativePath),
            ImportPath = hostRelativePath,
            Metadata = metadata
        };
    }

    private static ArtifactCollectionDescriptor MergeGuestCollection(
        ArtifactCollectionDescriptor host,
        ArtifactCollectionDescriptor guest)
    {
        var metadata = CopyMetadata(guest.Metadata);
        foreach (var pair in host.Metadata)
        {
            metadata[pair.Key] = pair.Value;
        }

        AddIfNotEmpty(metadata, "guestManifestStatus", guest.Status);
        AddIfNotEmpty(metadata, "guestManifestReason", guest.Reason);

        var merged = host with
        {
            Kind = guest.Kind == ArtifactKind.Unknown ? host.Kind : guest.Kind,
            Category = FirstNonEmpty(guest.Category, host.Category),
            EvidenceRole = FirstNonEmpty(guest.EvidenceRole, host.EvidenceRole),
            RelativePath = FirstNonEmpty(host.RelativePath, guest.RelativePath),
            SafeLink = FirstNonEmpty(host.SafeLink, guest.SafeLink),
            ImportPath = FirstNonEmpty(host.ImportPath, guest.ImportPath),
            Enabled = host.Enabled || guest.Enabled,
            Implemented = host.Implemented || guest.Implemented,
            Status = string.Equals(host.Status, "captured", StringComparison.OrdinalIgnoreCase)
                ? host.Status
                : FirstNonEmpty(guest.Status, host.Status),
            Reason = string.Equals(host.Status, "captured", StringComparison.OrdinalIgnoreCase)
                ? FirstNonEmpty(host.Reason, guest.Reason)
                : FirstNonEmpty(guest.Reason, host.Reason),
            Metadata = metadata
        };
        AddCollectionPresentationMetadata(
            metadata,
            merged.Name,
            merged.Kind,
            merged.Status,
            merged.Reason,
            ParseMetadataCount(metadata, "downloadableArtifactCount", "artifactCount"));
        return merged with { Metadata = metadata };
    }

    private static List<ArtifactCollectionDescriptor> AddExpectedArtifactCollections(
        IReadOnlyList<ArtifactCollectionDescriptor> collections,
        ArtifactCollectionConfig? artifactCollection,
        IReadOnlyDictionary<string, Dictionary<string, string>> collectionEventMetadata)
    {
        var byName = collections.ToDictionary(collection => collection.Name, StringComparer.OrdinalIgnoreCase);
        foreach (var expectation in ExpectedArtifactCollections)
        {
            if (byName.ContainsKey(expectation.CollectionName))
            {
                continue;
            }

            var requested = artifactCollection is not null && expectation.IsRequested(artifactCollection);
            var eventMetadata = collectionEventMetadata.GetValueOrDefault(expectation.CollectionName);
            var hasEventSignal = eventMetadata is not null && eventMetadata.Count > 0;
            if (artifactCollection is null && !hasEventSignal)
            {
                continue;
            }

            var status = FirstNonEmpty(
                MetadataValue(eventMetadata, "lastStatus", "lastCaptureState"),
                requested ? "missing" : "disabled");
            var reason = FirstNonEmpty(
                MetadataValue(eventMetadata, "lastReason", "guestManifestReason"),
                requested ? "noDownloadableArtifacts" : expectation.NotRequestedReason);

            var metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["origin"] = "host-expected-collection",
                ["discoveredBy"] = nameof(HostArtifactIndexBuilder),
                ["hrefPolicy"] = "relative-safe-link-only",
                ["artifactCount"] = "0",
                ["downloadableArtifactCount"] = "0",
                ["hasDownloadableArtifacts"] = "false",
                ["expectedRelativePath"] = expectation.RelativePath,
                ["expectedArtifactKind"] = expectation.Kind.ToString(),
                ["requested"] = requested.ToString(CultureInfo.InvariantCulture).ToLowerInvariant(),
                ["diagnosticCategory"] = "artifact-import",
                ["diagnosticCode"] = requested ? "artifact-collection-missing" : "artifact-collection-disabled",
                ["downloadResolutionState"] = requested ? "missing" : "unavailable",
                ["downloadRejectionCode"] = requested ? "missing-artifact-file" : "collection-not-requested",
                ["downloadUnavailableReason"] = reason,
                ["downloadAvailable"] = "false",
                ["isDownloadable"] = "false"
            };

            foreach (var pair in eventMetadata ?? EmptyMetadata)
            {
                AddIfMissing(metadata, pair.Key, pair.Value);
            }

            AddCollectionPresentationMetadata(metadata, expectation.CollectionName, expectation.Kind, status, reason, 0);
            byName[expectation.CollectionName] = new ArtifactCollectionDescriptor
            {
                Name = expectation.CollectionName,
                Kind = expectation.Kind,
                Category = ArtifactDescriptorFactory.CategoryForKind(expectation.Kind),
                EvidenceRole = EvidenceRoleForKind(expectation.Kind),
                RelativePath = expectation.RelativePath,
                SafeLink = ArtifactDescriptorFactory.BuildSafeLink(expectation.RelativePath),
                ImportPath = expectation.RelativePath,
                Enabled = requested,
                Implemented = true,
                Status = status,
                Reason = reason,
                Metadata = metadata
            };
        }

        return byName.Values.ToList();
    }

    private static ArtifactCollectionDescriptor BuildCollection(
        string collectionName,
        IReadOnlyList<ArtifactDescriptor> artifacts,
        IReadOnlyDictionary<string, string>? eventMetadata)
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
            ["hrefPolicy"] = "relative-safe-link-only",
            ["artifactCount"] = artifacts.Count.ToString(CultureInfo.InvariantCulture),
            ["totalBytes"] = artifacts.Sum(artifact => artifact.SizeBytes).ToString(CultureInfo.InvariantCulture),
            ["duplicateArtifactCount"] = artifacts.Count(IsDuplicateArtifact).ToString(CultureInfo.InvariantCulture)
        };
        AddCollectionDuplicateMetadata(metadata, artifacts);
        if (mimeTypes.Count > 0)
        {
            metadata["mimeTypes"] = string.Join(",", mimeTypes);
        }

        foreach (var pair in eventMetadata ?? EmptyMetadata)
        {
            AddIfMissing(metadata, pair.Key, pair.Value);
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

        var reason = string.Equals(collectionName, "packet-captures", StringComparison.OrdinalIgnoreCase)
            ? "external-pcap-artifacts-indexed"
            : string.Empty;
        AddCollectionPresentationMetadata(metadata, collectionName, first.Kind, "captured", reason, artifacts.Count(IsDownloadableArtifact));

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
            Reason = reason,
            Metadata = metadata
        };
    }

    private static ArtifactCollectionDescriptor AddArtifactRejectionDiagnostics(
        ArtifactCollectionDescriptor collection,
        IReadOnlyList<ArtifactIndexRejection> rejections)
    {
        if (rejections.Count == 0)
        {
            return collection;
        }

        var metadata = CopyMetadata(collection.Metadata);
        AddRejectionMetadata(metadata, rejections);
        AddCollectionPresentationMetadata(
            metadata,
            collection.Name,
            collection.Kind,
            collection.Status,
            string.IsNullOrWhiteSpace(collection.Reason)
                ? FirstNonEmpty(rejections[^1].Reason, "guestManifestArtifactRejected")
                : collection.Reason,
            ParseMetadataCount(metadata, "downloadableArtifactCount", "artifactCount"));
        return collection with
        {
            Reason = string.IsNullOrWhiteSpace(collection.Reason)
                ? FirstNonEmpty(rejections[^1].Reason, "guestManifestArtifactRejected")
                : collection.Reason,
            Metadata = metadata
        };
    }

    private static ArtifactCollectionDescriptor BuildRejectedCollection(
        string collectionName,
        IReadOnlyList<ArtifactIndexRejection> rejections)
    {
        var kind = rejections.Select(rejection => rejection.Kind).FirstOrDefault(kind => kind != ArtifactKind.Unknown);
        if (kind == ArtifactKind.Unknown)
        {
            kind = KindForCollection(collectionName);
        }

        var relativePath = FirstNonEmpty(
            rejections.Select(rejection => ArtifactDescriptorFactory.NormalizeRelativePath(rejection.AttemptedSelector))
                .FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)),
            collectionName);
        var metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["origin"] = "guest-manifest",
            ["hrefPolicy"] = "relative-safe-link-only",
            ["downloadableArtifactCount"] = "0"
        };
        AddRejectionMetadata(metadata, rejections);
        AddCollectionPresentationMetadata(
            metadata,
            collectionName,
            kind,
            "rejected",
            FirstNonEmpty(rejections[^1].Reason, "guestManifestArtifactRejected"),
            0);

        return new ArtifactCollectionDescriptor
        {
            Name = collectionName,
            Kind = kind,
            Category = ArtifactDescriptorFactory.CategoryForKind(kind),
            EvidenceRole = EvidenceRoleForKind(kind),
            RelativePath = ArtifactDescriptorFactory.NormalizeRelativePath(relativePath),
            SafeLink = ArtifactDescriptorFactory.BuildSafeLink(relativePath),
            ImportPath = ArtifactDescriptorFactory.NormalizeRelativePath(relativePath),
            Enabled = true,
            Implemented = true,
            Status = "rejected",
            Reason = FirstNonEmpty(rejections[^1].Reason, "guestManifestArtifactRejected"),
            Metadata = metadata
        };
    }

    private static void AddRejectionMetadata(
        Dictionary<string, string> metadata,
        IReadOnlyList<ArtifactIndexRejection> rejections)
    {
        if (rejections.Count == 0)
        {
            return;
        }

        var last = rejections[^1];
        metadata["rejectionDiagnosticsAvailable"] = "true";
        metadata["rejectedArtifactCount"] = rejections.Count.ToString(CultureInfo.InvariantCulture);
        metadata["lastRejectedArtifactReason"] = last.Reason;
        AddIfNotEmpty(metadata, "lastRejectedArtifactName", last.Name);
        AddIfNotEmpty(metadata, "lastRejectedArtifactSelector", last.AttemptedSelector);
        AddIfNotEmpty(metadata, "lastRejectedArtifactKind", last.Kind == ArtifactKind.Unknown ? string.Empty : last.Kind.ToString());
        AddIfNotEmpty(metadata, "lastRejectedGuestRoot", last.HostRelativeGuestRoot);
        metadata["artifactRejectionReasons"] = string.Join(
            ",",
            rejections
                .Select(rejection => rejection.Reason)
                .Where(reason => !string.IsNullOrWhiteSpace(reason))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(reason => reason, StringComparer.OrdinalIgnoreCase));
        metadata["artifactRejectionsJson"] = JsonSerializer.Serialize(
            rejections.Select(rejection => new
            {
                rejection.CollectionName,
                Kind = rejection.Kind == ArtifactKind.Unknown ? string.Empty : rejection.Kind.ToString(),
                rejection.Name,
                rejection.AttemptedSelector,
                rejection.Reason,
                rejection.HostRelativeGuestRoot
            }),
            JsonOptions);
        metadata["zhRejectionHint"] = "Host 已拒绝不安全、缺失或不可下载的 guest manifest 产物引用；只有 job 输出目录下的已索引相对路径可以下载。";
    }

    private static void AddCollectionDuplicateMetadata(
        Dictionary<string, string> metadata,
        IReadOnlyList<ArtifactDescriptor> artifacts)
    {
        var duplicateGroups = artifacts
            .Where(artifact => TryReadPositiveInt(MetadataValue(artifact.Metadata, "duplicateGroupCount"), out var count) && count > 1)
            .GroupBy(artifact => FirstNonEmpty(MetadataValue(artifact.Metadata, "duplicateGroupId"), MetadataValue(artifact.Metadata, "duplicateGroupKey")), StringComparer.OrdinalIgnoreCase)
            .Where(group => !string.IsNullOrWhiteSpace(group.Key))
            .OrderBy(group => group.Key, StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (duplicateGroups.Count == 0)
        {
            AddIfMissing(metadata, "duplicateDiagnosticsAvailable", "false");
            AddIfMissing(metadata, "duplicateGroupCount", "0");
            AddIfMissing(metadata, "hasDuplicateArtifacts", "false");
            return;
        }

        var summaries = duplicateGroups
            .Select(group =>
            {
                var members = group
                    .OrderBy(artifact => artifact.RelativePath, StringComparer.OrdinalIgnoreCase)
                    .ToList();
                var primary = members.FirstOrDefault(artifact =>
                    string.Equals(MetadataValue(artifact.Metadata, "duplicateRole"), "primary", StringComparison.OrdinalIgnoreCase)) ?? members[0];
                return new
                {
                    GroupId = group.Key,
                    GroupKey = FirstNonEmpty(MetadataValue(primary.Metadata, "duplicateGroupKey"), group.Key),
                    Count = members.Count,
                    PrimarySelector = primary.RelativePath,
                    PrimarySafeLink = primary.SafeLink,
                    MemberSelectors = members.Select(artifact => artifact.RelativePath).ToList()
                };
            })
            .ToList();

        metadata["duplicateDiagnosticsAvailable"] = "true";
        metadata["duplicateGroupCount"] = summaries.Count.ToString(CultureInfo.InvariantCulture);
        metadata["hasDuplicateArtifacts"] = "true";
        metadata["duplicateGroupIds"] = string.Join(",", summaries.Select(summary => summary.GroupId));
        metadata["duplicatePrimarySelectors"] = string.Join(",", summaries.Select(summary => summary.PrimarySelector));
        metadata["duplicateGroupSummariesJson"] = JsonSerializer.Serialize(summaries, JsonOptions);
    }

    private static void AddCollectionPresentationMetadata(
        Dictionary<string, string> metadata,
        string collectionName,
        ArtifactKind kind,
        string status,
        string reason,
        int downloadableArtifactCount)
    {
        var resolvedKind = kind == ArtifactKind.Unknown ? KindForCollection(collectionName) : kind;
        var normalizedStatus = FirstNonEmpty(status, "unknown");
        var normalizedReason = FirstNonEmpty(reason, MetadataValue(metadata, "lastReason"), MetadataValue(metadata, "guestManifestReason"));
        AddIfMissing(metadata, "apiMetadataVersion", "artifact-collection-v1");
        AddIfMissing(metadata, "collectionDisplayName", CollectionDisplayName(collectionName, resolvedKind));
        AddIfMissing(metadata, "collectionDisplayNameZh", CollectionDisplayNameZh(collectionName, resolvedKind));
        AddIfMissing(metadata, "collectionNameZh", CollectionDisplayNameZh(collectionName, resolvedKind));
        AddIfMissing(metadata, "artifactKindZh", ArtifactKindNameZh(resolvedKind));
        AddIfMissing(metadata, "downloadableArtifactCount", downloadableArtifactCount.ToString(CultureInfo.InvariantCulture));
        AddIfMissing(metadata, "hasDownloadableArtifacts", (downloadableArtifactCount > 0).ToString(CultureInfo.InvariantCulture).ToLowerInvariant());
        AddIfMissing(metadata, "sensitiveCollection", IsSensitiveArtifactKind(resolvedKind).ToString(CultureInfo.InvariantCulture).ToLowerInvariant());
        AddIfMissing(metadata, "downloadSelectorPolicy", "relative-index-selectors-only");
        AddIfMissing(metadata, "downloadSecurityPolicy", "server-indexed-relative-selector");
        AddIfMissing(metadata, "downloadRejectionPolicy", "reject-empty-absolute-traversal-unindexed-missing");
        AddIfMissing(metadata, "safeSelectorFields", "relativePath,safeLink,importPath,downloadSelector,downloadSafeLink");
        AddIfMissing(metadata, "selectorMetadataVersion", "artifact-selector-v2");
        AddIfMissing(metadata, "selectorAuthority", "host-artifact-index");
        AddIfMissing(metadata, "selectorAvailability", downloadableArtifactCount > 0 ? "available" : "unavailable");
        AddIfMissing(metadata, "zhStatus", CollectionStatusZh(normalizedStatus));
        AddIfMissing(metadata, "zhReason", CollectionReasonZh(normalizedReason));
        AddIfMissing(metadata, "zhHint", CollectionHintZh(collectionName, normalizedStatus, normalizedReason, downloadableArtifactCount));
        AddIfMissing(metadata, "downloadHintZh", downloadableArtifactCount > 0
            ? "请使用 artifact-index.json 中的相对 selector 下载；不要传入本机绝对路径。"
            : "当前集合没有可下载文件；这通常表示未请求、采集失败、文件缺失或来宾清单引用被拒绝，不代表样本行为。");
    }

    private static int ParseMetadataCount(IReadOnlyDictionary<string, string> metadata, params string[] keys)
    {
        foreach (var key in keys)
        {
            if (metadata.TryGetValue(key, out var value) &&
                int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var count))
            {
                return Math.Max(0, count);
            }
        }

        return 0;
    }

    private static bool IsSensitiveArtifactKind(ArtifactKind kind)
    {
        return kind is ArtifactKind.DroppedFile or ArtifactKind.Screenshot or ArtifactKind.MemoryDump or ArtifactKind.PacketCapture;
    }

    private static string CollectionDisplayName(string collectionName, ArtifactKind kind)
    {
        return kind switch
        {
            ArtifactKind.DroppedFile => "Dropped files",
            ArtifactKind.Screenshot => "Screenshots",
            ArtifactKind.MemoryDump => "Memory dumps",
            ArtifactKind.PacketCapture => "Packet captures",
            ArtifactKind.DriverEventsJsonLines => "Driver events",
            ArtifactKind.GuestEventsJson => "Guest events",
            ArtifactKind.GuestSummaryJson => "Guest summary",
            ArtifactKind.ArtifactManifest => "Artifact manifests",
            ArtifactKind.ArtifactIndex => "Artifact index",
            _ => string.IsNullOrWhiteSpace(collectionName) ? "Artifacts" : collectionName
        };
    }

    private static string CollectionDisplayNameZh(string collectionName, ArtifactKind kind)
    {
        return kind switch
        {
            ArtifactKind.DroppedFile => "掉落文件",
            ArtifactKind.Screenshot => "截图",
            ArtifactKind.MemoryDump => "内存转储",
            ArtifactKind.PacketCapture => "抓包文件",
            ArtifactKind.DriverEventsJsonLines => "R0 事件",
            ArtifactKind.GuestEventsJson => "Guest 事件",
            ArtifactKind.GuestSummaryJson => "Guest 摘要",
            ArtifactKind.ArtifactManifest => "产物清单",
            ArtifactKind.ArtifactIndex => "产物索引",
            _ => string.IsNullOrWhiteSpace(collectionName) ? "产物" : collectionName
        };
    }

    private static string CollectionStatusZh(string status)
    {
        return status.ToLowerInvariant() switch
        {
            "captured" => "已采集",
            "available" => "可用",
            "skipped" => "已跳过",
            "failed" => "采集失败",
            "disabled" => "未启用",
            "rejected" => "已拒绝",
            "missing" => "缺失",
            "summary" => "摘要",
            _ => "未知状态"
        };
    }

    private static string CollectionReasonZh(string reason)
    {
        if (string.IsNullOrWhiteSpace(reason))
        {
            return string.Empty;
        }

        return reason.Trim().ToLowerInvariant() switch
        {
            "nodownloadableartifacts" => "没有可下载产物",
            "not-requested" => "未请求采集",
            "notrequested" => "未请求采集",
            "screenshotnotrequested" => "未请求截图",
            "memorydumpnotrequested" => "未请求内存转储",
            "packetcapturenotrequested" => "未请求抓包",
            "droppedfilesnotrequested" => "未请求掉落文件收集",
            "desktopunavailable" => "桌面会话不可用",
            "targetprocessexited" => "目标进程已退出",
            "pktmonstartfailed" => "pktmon 启动失败",
            "unsafeguestartifactpath" => "guest manifest 产物路径不安全",
            "missingguestartifactfile" => "guest manifest 指向的文件缺失",
            "duplicateguestartifactreference" => "guest manifest 重复引用同一产物",
            "guestmanifestartifactrejected" => "guest manifest 产物引用已被拒绝",
            "external-pcap-artifacts-indexed" => "已索引外部抓包产物",
            _ => reason
        };
    }

    private static string CollectionHintZh(
        string collectionName,
        string status,
        string reason,
        int downloadableArtifactCount)
    {
        if (downloadableArtifactCount > 0)
        {
            return "Host 已为该 collection 建立安全相对下载选择器；请使用 artifact-index.json 中的 selector 下载，绝对路径仅用于诊断。";
        }

        if (string.Equals(status, "rejected", StringComparison.OrdinalIgnoreCase) ||
            reason.Contains("unsafe", StringComparison.OrdinalIgnoreCase) ||
            reason.Contains("missingGuestArtifactFile", StringComparison.OrdinalIgnoreCase) ||
            reason.Contains("duplicateGuestArtifactReference", StringComparison.OrdinalIgnoreCase))
        {
            return "Host 已保留 manifest 拒绝/重复诊断，但不会为不安全、缺失或重复的引用生成下载链接。";
        }

        return collectionName switch
        {
            "dropped-files" => "掉落文件默认关闭；请确认已启用收集、样本在工作目录内创建文件，且复制到 artifacts/dropped-files 成功。",
            "screenshots" => "截图默认关闭；请确认已启用截图，来宾桌面会话、GDI 权限和输出路径可用。",
            "memory-dumps" => "内存转储默认关闭；请确认已启用转储、目标进程仍可见，并且 MiniDumpWriteDump 权限可用。",
            "packet-captures" => "抓包默认关闭；请确认已启用抓包、pktmon 可用并成功转换，或导入已有 .pcap/.pcapng。",
            _ => "没有可下载产物时仅记录采集健康诊断，不会把缺口当作样本行为。"
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

    private static string CollectionNameForKind(ArtifactKind kind)
    {
        return kind switch
        {
            ArtifactKind.DroppedFile => "dropped-files",
            ArtifactKind.Screenshot => "screenshots",
            ArtifactKind.MemoryDump => "memory-dumps",
            ArtifactKind.PacketCapture => "packet-captures",
            ArtifactKind.DriverEventsJsonLines => "driver-events",
            ArtifactKind.GuestEventsJson => "guest-events",
            ArtifactKind.GuestSummaryJson => "guest-summary",
            ArtifactKind.ArtifactManifest => "artifact-manifests",
            ArtifactKind.ArtifactIndex => "artifact-index",
            _ => string.Empty
        };
    }

    private static ArtifactKind KindForCollection(string collectionName)
    {
        return collectionName.ToLowerInvariant() switch
        {
            "dropped-files" => ArtifactKind.DroppedFile,
            "screenshots" => ArtifactKind.Screenshot,
            "memory-dumps" => ArtifactKind.MemoryDump,
            "packet-captures" => ArtifactKind.PacketCapture,
            "driver-events" => ArtifactKind.DriverEventsJsonLines,
            "guest-events" => ArtifactKind.GuestEventsJson,
            "guest-summary" => ArtifactKind.GuestSummaryJson,
            "artifact-manifests" => ArtifactKind.ArtifactManifest,
            "artifact-index" => ArtifactKind.ArtifactIndex,
            _ => ArtifactKind.Unknown
        };
    }

    private static string EvidenceRoleForKind(ArtifactKind kind)
    {
        return kind switch
        {
            ArtifactKind.DroppedFile => "dropped-file",
            ArtifactKind.Screenshot => "screenshot",
            ArtifactKind.MemoryDump => "memory-dump",
            ArtifactKind.PacketCapture => "packet-capture",
            ArtifactKind.DriverEventsJsonLines => "driver-events",
            ArtifactKind.GuestEventsJson => "guest-events",
            ArtifactKind.GuestSummaryJson => "guest-summary",
            ArtifactKind.ArtifactManifest => "artifact-manifest",
            ArtifactKind.ArtifactIndex => "artifact-index",
            _ => string.Empty
        };
    }


    private static List<ArtifactDescriptor> MarkDuplicateArtifacts(IReadOnlyList<ArtifactDescriptor> artifacts)
    {
        var grouped = artifacts
            .Select((artifact, index) => new { artifact, index })
            .GroupBy(item => DuplicateKey(item.artifact), StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.OrderBy(item => item.artifact.RelativePath, StringComparer.OrdinalIgnoreCase).ToList(), StringComparer.OrdinalIgnoreCase);
        var result = new ArtifactDescriptor[artifacts.Count];
        foreach (var group in grouped.Values)
        {
            var primary = group[0].artifact;
            var duplicateKey = DuplicateKey(primary);
            var duplicateGroupId = DuplicateGroupId(primary, duplicateKey);
            var memberSelectors = string.Join(
                ",",
                group
                    .Select(item => item.artifact.RelativePath)
                    .Where(path => !string.IsNullOrWhiteSpace(path)));
            var memberSelectorsJson = JsonSerializer.Serialize(
                group
                    .Select(item => item.artifact.RelativePath)
                    .Where(path => !string.IsNullOrWhiteSpace(path))
                    .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
                    .ToList());
            for (var ordinal = 0; ordinal < group.Count; ordinal++)
            {
                var artifact = group[ordinal].artifact;
                var metadata = CopyMetadata(artifact.Metadata);
                AddArtifactIdentityMetadata(metadata, artifact);
                AddArtifactPresentationMetadata(metadata, artifact);
                if (group.Count > 1 && !string.IsNullOrWhiteSpace(DuplicateKey(artifact)))
                {
                    metadata["duplicateGroupKey"] = DuplicateKey(artifact);
                    metadata["duplicateGroupId"] = duplicateGroupId;
                    metadata["duplicateGroupCount"] = group.Count.ToString(CultureInfo.InvariantCulture);
                    metadata["duplicateOrdinal"] = ordinal.ToString(CultureInfo.InvariantCulture);
                    metadata["isDuplicate"] = (ordinal > 0).ToString(CultureInfo.InvariantCulture).ToLowerInvariant();
                    metadata["duplicateRole"] = ordinal == 0 ? "primary" : "duplicate";
                    metadata["duplicatePrimarySelector"] = primary.RelativePath;
                    metadata["duplicatePrimarySafeLink"] = primary.SafeLink;
                    metadata["duplicatePrimaryImportPath"] = primary.ImportPath;
                    metadata["duplicateOfArtifactRelativePath"] = primary.RelativePath;
                    metadata["duplicateGroupMemberSelectors"] = memberSelectors;
                    metadata["duplicateGroupMemberSelectorsJson"] = memberSelectorsJson;
                    metadata["duplicateSetLabel"] = $"{group.Count.ToString(CultureInfo.InvariantCulture)} files share the same SHA-256 and size";
                    metadata["duplicateSetLabelZh"] = $"{group.Count.ToString(CultureInfo.InvariantCulture)} 个产物具有相同 SHA-256 和大小";
                }
                else
                {
                    AddIfMissing(metadata, "isDuplicate", "false");
                    AddIfMissing(metadata, "duplicateRole", "unique");
                }

                result[group[ordinal].index] = artifact with { Metadata = metadata };
            }
        }

        return result.ToList();
    }

    private static string DuplicateKey(ArtifactDescriptor artifact)
    {
        var sha256 = FirstNonEmpty(artifact.Sha256, MetadataValue(artifact.Metadata, "sha256", "sourceArtifactSha256", "hash.sha256"));
        return !string.IsNullOrWhiteSpace(sha256) && artifact.SizeBytes > 0
            ? $"sha256:{sha256};size:{artifact.SizeBytes.ToString(CultureInfo.InvariantCulture)}"
            : string.Empty;
    }

    private static string DuplicateGroupId(ArtifactDescriptor artifact, string duplicateKey)
    {
        var sha256 = FirstNonEmpty(artifact.Sha256, MetadataValue(artifact.Metadata, "sha256", "sourceArtifactSha256", "hash.sha256"));
        if (!string.IsNullOrWhiteSpace(sha256))
        {
            return $"sha256:{sha256[..Math.Min(16, sha256.Length)]}";
        }

        return string.IsNullOrWhiteSpace(duplicateKey)
            ? string.Empty
            : duplicateKey;
    }

    private static bool IsDuplicateArtifact(ArtifactDescriptor artifact)
    {
        return string.Equals(MetadataValue(artifact.Metadata, "isDuplicate"), "true", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsDownloadableArtifact(ArtifactDescriptor artifact)
    {
        return !string.IsNullOrWhiteSpace(artifact.RelativePath) &&
            !string.IsNullOrWhiteSpace(artifact.SafeLink) &&
            File.Exists(artifact.FullPath) &&
            string.Equals(MetadataValue(artifact.Metadata, "isDownloadable"), "true", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsSensitiveArtifact(ArtifactDescriptor artifact)
    {
        return artifact.Kind is ArtifactKind.DroppedFile or ArtifactKind.Screenshot or ArtifactKind.MemoryDump or ArtifactKind.PacketCapture;
    }

    private static void AddArtifactIdentityMetadata(Dictionary<string, string> metadata, ArtifactDescriptor artifact)
    {
        AddIfMissing(metadata, "artifactKind", artifact.Kind.ToString());
        AddIfMissing(metadata, "sourceArtifactKind", artifact.Kind.ToString());
        AddIfMissing(metadata, "sourceArtifactKindZh", ArtifactKindNameZh(artifact.Kind));
        AddIfMissing(metadata, "artifactRelativePath", artifact.RelativePath);
        AddIfMissing(metadata, "sourceArtifactRelativePath", artifact.RelativePath);
        AddIfMissing(metadata, "importPath", artifact.ImportPath);
        AddIfMissing(metadata, "sourceArtifactPath", artifact.FullPath);
        AddIfMissing(metadata, "fullPath", artifact.FullPath);
        if (artifact.SizeBytes > 0)
        {
            var sizeText = artifact.SizeBytes.ToString(CultureInfo.InvariantCulture);
            AddIfMissing(metadata, "sizeBytes", sizeText);
            AddIfMissing(metadata, "sourceArtifactSizeBytes", sizeText);
        }

        AddIfMissing(metadata, "sha256", artifact.Sha256);
        AddIfMissing(metadata, "sourceArtifactSha256", artifact.Sha256);
        AddIfMissing(metadata, "hash.sha256", artifact.Hashes.TryGetValue("sha256", out var hash) ? hash : artifact.Sha256);
    }

    private static void AddArtifactPresentationMetadata(Dictionary<string, string> metadata, ArtifactDescriptor artifact)
    {
        var contentType = FirstNonEmpty(artifact.MimeType, ArtifactDescriptorFactory.MimeTypeForPath(FirstNonEmpty(artifact.FullPath, artifact.Name)));
        var fileName = string.IsNullOrWhiteSpace(artifact.Name)
            ? Path.GetFileName(artifact.RelativePath)
            : artifact.Name;
        var safeFileName = SafeDownloadFileName(fileName);
        AddIfMissing(metadata, "apiMetadataVersion", "artifact-descriptor-v1");
        AddIfMissing(metadata, "contentType", contentType);
        AddIfMissing(metadata, "downloadContentType", contentType);
        AddIfMissing(metadata, "downloadFileName", fileName);
        AddIfMissing(metadata, "safeDownloadFileName", safeFileName);
        AddIfMissing(metadata, "contentDispositionFileName", safeFileName);
        AddIfMissing(metadata, "safeContentDispositionFileName", safeFileName);
        AddIfMissing(metadata, "contentDispositionPolicy", "attachment-filename-sanitized-from-indexed-artifact-name");
        AddIfMissing(metadata, "downloadSelector", artifact.RelativePath);
        AddIfMissing(metadata, "downloadSafeLink", artifact.SafeLink);
        AddIfMissing(metadata, "safeRelativeSelector", artifact.RelativePath);
        AddIfMissing(metadata, "reportRelativeHref", artifact.SafeLink);
        AddIfMissing(metadata, "reportRelativeDownloadName", safeFileName);
        AddIfMissing(metadata, "downloadAvailable", "true");
        AddIfMissing(metadata, "downloadResolutionState", "available");
        AddIfMissing(metadata, "downloadReadiness", "host-file-present");
        AddIfMissing(metadata, "downloadRejectionCode", "none");
        AddIfMissing(metadata, "downloadSelectorKind", "relativePath");
        AddIfMissing(metadata, "selectorMetadataVersion", "artifact-selector-v2");
        AddIfMissing(metadata, "selectorAuthority", "host-artifact-index");
        AddIfMissing(metadata, "selectorArtifactKind", artifact.Kind.ToString());
        AddIfMissing(metadata, "selectorCollectionName", artifact.CollectionName);
        AddIfMissing(metadata, "selectorSafety", "normalized-relative-indexed");
        AddIfMissing(metadata, "streamAuthority", "host-artifact-index");
        AddIfMissing(metadata, "selectorEncoding", "path-segment-url-encoded-safeLink");
        AddIfMissing(metadata, "selectorFields", "relativePath,safeLink,importPath,downloadSelector,downloadSafeLink");
        AddIfMissing(metadata, "downloadSecurityPolicy", "server-indexed-relative-selector");
        AddIfMissing(metadata, "downloadRejectionPolicy", "reject-empty-absolute-traversal-unindexed-missing");
        AddIfMissing(metadata, "downloadIndexPolicy", "artifact-index-relative-selectors-only");
        AddIfMissing(metadata, "downloadHintZh", "仅允许使用 Host artifact-index.json 中的相对 downloadSelector 下载；拒绝绝对路径、路径穿越、未索引或已缺失文件。");
        AddIfMissing(metadata, "zhHint", "这是 Host 产物索引元数据，用于安全下载和溯源，不作为样本行为判定。");
        AddIfMissing(metadata, "isDownloadable", "true");
        if (artifact.SizeBytes > 0)
        {
            AddIfMissing(metadata, "sizeDisplay", FormatByteCount(artifact.SizeBytes));
        }

        var sha256 = FirstNonEmpty(artifact.Sha256, MetadataValue(artifact.Metadata, "sha256", "sourceArtifactSha256", "hash.sha256"));
        if (!string.IsNullOrWhiteSpace(sha256))
        {
            AddIfMissing(metadata, "sha256Short", sha256[..Math.Min(12, sha256.Length)]);
        }

        AddIfMissing(metadata, "previewLabel", PreviewLabel(artifact.Kind, fileName));
        AddIfMissing(metadata, "previewLabelZh", PreviewLabelZh(artifact.Kind, fileName));
    }

    private static string ArtifactKindNameZh(ArtifactKind kind)
    {
        return kind switch
        {
            ArtifactKind.DroppedFile => "掉落文件",
            ArtifactKind.Screenshot => "截图",
            ArtifactKind.MemoryDump => "内存转储",
            ArtifactKind.PacketCapture => "抓包文件",
            ArtifactKind.DriverEventsJsonLines => "R0 事件",
            ArtifactKind.GuestEventsJson => "Guest 事件",
            ArtifactKind.GuestSummaryJson => "Guest 摘要",
            ArtifactKind.ArtifactManifest => "产物清单",
            ArtifactKind.ArtifactIndex => "产物索引",
            ArtifactKind.ReportJson => "JSON 报告",
            ArtifactKind.ReportHtml => "HTML 报告",
            ArtifactKind.RunbookJson => "Runbook",
            ArtifactKind.RunbookExecutionJson => "Runbook 执行记录",
            ArtifactKind.StaticAnalysisJson => "静态分析",
            ArtifactKind.Log => "日志",
            ArtifactKind.Bundle => "归档包",
            _ => "产物"
        };
    }

    private static string FormatByteCount(long bytes)
    {
        if (bytes < 1024)
        {
            return $"{bytes.ToString(CultureInfo.InvariantCulture)} B";
        }

        var kib = bytes / 1024d;
        if (kib < 1024)
        {
            return $"{kib.ToString("0.#", CultureInfo.InvariantCulture)} KiB";
        }

        var mib = kib / 1024d;
        return $"{mib.ToString("0.#", CultureInfo.InvariantCulture)} MiB";
    }

    private static string PreviewLabel(ArtifactKind kind, string fileName)
    {
        var label = kind switch
        {
            ArtifactKind.DroppedFile => "Dropped file",
            ArtifactKind.Screenshot => "Screenshot",
            ArtifactKind.MemoryDump => "Memory dump",
            ArtifactKind.PacketCapture => "Packet capture",
            ArtifactKind.DriverEventsJsonLines => "Driver events",
            ArtifactKind.GuestEventsJson => "Guest events",
            ArtifactKind.ArtifactManifest => "Artifact manifest",
            ArtifactKind.ArtifactIndex => "Artifact index",
            _ => "Artifact"
        };

        return string.IsNullOrWhiteSpace(fileName) ? label : $"{label}: {fileName}";
    }

    private static string PreviewLabelZh(ArtifactKind kind, string fileName)
    {
        var label = kind switch
        {
            ArtifactKind.DroppedFile => "掉落文件",
            ArtifactKind.Screenshot => "截图",
            ArtifactKind.MemoryDump => "内存转储",
            ArtifactKind.PacketCapture => "抓包文件",
            ArtifactKind.DriverEventsJsonLines => "R0 事件",
            ArtifactKind.GuestEventsJson => "Guest 事件",
            ArtifactKind.ArtifactManifest => "产物清单",
            ArtifactKind.ArtifactIndex => "产物索引",
            _ => "产物"
        };

        return string.IsNullOrWhiteSpace(fileName) ? label : $"{label}：{fileName}";
    }

    private static string PrefixGuestRelativePath(GuestManifestContext context, string relativePath)
    {
        var normalized = ArtifactDescriptorFactory.NormalizeRelativePath(relativePath);
        if (string.IsNullOrWhiteSpace(normalized))
        {
            return context.HostRelativeGuestRoot;
        }

        if (string.IsNullOrWhiteSpace(context.HostRelativeGuestRoot))
        {
            return normalized;
        }

        var prefix = context.HostRelativeGuestRoot.Trim('/', '\\');
        return normalized.StartsWith(prefix + "/", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(normalized, prefix, StringComparison.OrdinalIgnoreCase)
            ? normalized
            : $"{prefix}/{normalized}";
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

    private static string? MetadataValue(IDictionary<string, string>? metadata, params string[] keys)
    {
        if (metadata is null)
        {
            return null;
        }

        foreach (var key in keys)
        {
            if (metadata.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return null;
    }

    private static string SafeDownloadFileName(string value)
    {
        var fileName = Path.GetFileName(value.Replace('\\', '/'));
        if (string.IsNullOrWhiteSpace(fileName))
        {
            fileName = "artifact.bin";
        }

        foreach (var invalid in Path.GetInvalidFileNameChars())
        {
            fileName = fileName.Replace(invalid, '_');
        }

        return new string(fileName.Select(ch => char.IsControl(ch) ? '_' : ch).ToArray());
    }

    private static bool IsScreenshotNamedImage(string path, string relativePath)
    {
        if (!ArtifactDescriptorFactory.IsScreenshotImagePath(path))
        {
            return false;
        }

        if (relativePath.Contains("/artifacts/dropped-files/", StringComparison.OrdinalIgnoreCase) ||
            relativePath.StartsWith("artifacts/dropped-files/", StringComparison.OrdinalIgnoreCase) ||
            relativePath.Contains("/dropped-files/", StringComparison.OrdinalIgnoreCase) ||
            relativePath.StartsWith("dropped-files/", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var fileName = Path.GetFileNameWithoutExtension(path);
        return fileName.Contains("screenshot", StringComparison.OrdinalIgnoreCase) ||
            fileName.Contains("screen", StringComparison.OrdinalIgnoreCase) ||
            fileName.Contains("desktop", StringComparison.OrdinalIgnoreCase) ||
            fileName.Contains("capture", StringComparison.OrdinalIgnoreCase);
    }

    private static bool HasMetadataValue(IDictionary<string, string>? metadata, string key)
    {
        return metadata is not null &&
            metadata.TryGetValue(key, out var value) &&
            !string.IsNullOrWhiteSpace(value);
    }

    private static bool TryReadPositiveInt(string? value, out int count)
    {
        return int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out count) && count > 0;
    }

    private static Dictionary<string, string> CopyMetadata(IDictionary<string, string>? metadata)
    {
        return metadata is null
            ? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, string>(metadata, StringComparer.OrdinalIgnoreCase);
    }

    private static Dictionary<string, string> MergeMetadata(params IDictionary<string, string>?[] sources)
    {
        var merged = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var source in sources)
        {
            if (source is null)
            {
                continue;
            }

            foreach (var pair in source)
            {
                AddIfNotEmpty(merged, pair.Key, pair.Value);
            }
        }

        return merged;
    }

    private static void AddIfMissing(Dictionary<string, string> metadata, string key, string? value)
    {
        if (!metadata.ContainsKey(key) || string.IsNullOrWhiteSpace(metadata[key]))
        {
            AddIfNotEmpty(metadata, key, value);
        }
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

    private sealed record GuestManifestContext(
        string GuestRoot,
        string HostRelativeGuestRoot,
        ArtifactManifest Manifest);

    private sealed record GuestEventContext(
        string GuestRoot,
        string HostRelativeGuestRoot,
        string EventsPath,
        IReadOnlyList<SandboxEvent> Events);

    private sealed record ArtifactIndexRejection(
        string CollectionName,
        ArtifactKind Kind,
        string Name,
        string AttemptedSelector,
        string Reason,
        string HostRelativeGuestRoot);

    private sealed record ArtifactClassification(
        ArtifactKind Kind,
        string? Category = null,
        string? EvidenceRole = null,
        string? CollectionName = null,
        string? CapturePhase = null,
        string? CaptureState = null,
        IReadOnlyDictionary<string, string>? Metadata = null);

    private sealed record ExpectedArtifactCollection(
        string CollectionName,
        ArtifactKind Kind,
        string RelativePath,
        string NotRequestedReason,
        Func<ArtifactCollectionConfig, bool> IsRequested);

    private static readonly ExpectedArtifactCollection[] ExpectedArtifactCollections =
    [
        new(
            "dropped-files",
            ArtifactKind.DroppedFile,
            "artifacts/dropped-files",
            "droppedFilesNotRequested",
            config => config.CollectDroppedFiles),
        new(
            "screenshots",
            ArtifactKind.Screenshot,
            "screenshots",
            "screenshotNotRequested",
            config => config.CaptureScreenshots),
        new(
            "memory-dumps",
            ArtifactKind.MemoryDump,
            "memory-dumps",
            "memoryDumpNotRequested",
            config => config.CaptureMemoryDumps),
        new(
            "packet-captures",
            ArtifactKind.PacketCapture,
            "packet-captures",
            "packetCaptureNotRequested",
            config => config.CapturePacketCapture)
    ];
}
