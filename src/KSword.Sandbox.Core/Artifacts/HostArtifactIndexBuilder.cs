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
    public HostArtifactIndex Build(Guid jobId, string jobRoot)
    {
        var fullJobRoot = Path.GetFullPath(jobRoot);
        var guestManifests = Directory.Exists(fullJobRoot)
            ? LoadGuestManifests(fullJobRoot)
            : [];
        var guestEventContexts = Directory.Exists(fullJobRoot)
            ? LoadGuestEventContexts(fullJobRoot, guestManifests)
            : [];
        var guestArtifactsByFullPath = BuildGuestArtifactLookup(guestManifests);
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

        artifacts = artifacts
            .OrderBy(artifact => artifact.RelativePath, StringComparer.OrdinalIgnoreCase)
            .ToList();

        return new HostArtifactIndex
        {
            JobId = jobId,
            RootPath = fullJobRoot,
            GeneratedAtUtc = DateTimeOffset.UtcNow,
            Collections = BuildCollections(artifacts, guestManifests, collectionEventMetadata, fullJobRoot),
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

    private static Dictionary<string, ArtifactDescriptor> BuildGuestArtifactLookup(IReadOnlyList<GuestManifestContext> guestManifests)
    {
        var artifacts = new Dictionary<string, ArtifactDescriptor>(StringComparer.OrdinalIgnoreCase);
        foreach (var context in guestManifests)
        {
            foreach (var artifact in context.Manifest.Artifacts ?? [])
            {
                var fullPath = ResolveGuestArtifactFullPath(context.GuestRoot, artifact);
                if (string.IsNullOrWhiteSpace(fullPath))
                {
                    continue;
                }

                artifacts[fullPath] = artifact with { FullPath = fullPath };
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

    private static string ResolveGuestArtifactFullPath(string guestRoot, ArtifactDescriptor artifact)
    {
        if (!string.IsNullOrWhiteSpace(artifact.FullPath))
        {
            try
            {
                var fullPath = Path.GetFullPath(artifact.FullPath);
                if (IsSameOrUnderDirectory(fullPath, guestRoot))
                {
                    return fullPath;
                }
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
            {
            }
        }

        foreach (var candidate in new[] { artifact.RelativePath, artifact.ImportPath })
        {
            var relativePath = ArtifactDescriptorFactory.NormalizeRelativePath(candidate);
            if (string.IsNullOrWhiteSpace(relativePath))
            {
                continue;
            }

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

        return string.Empty;
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
            relativePath.StartsWith("memory-dumps/", StringComparison.OrdinalIgnoreCase) ||
            relativePath.Contains("/dumps/", StringComparison.OrdinalIgnoreCase) ||
            relativePath.StartsWith("dumps/", StringComparison.OrdinalIgnoreCase))
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

        return host with
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
            ["totalBytes"] = artifacts.Sum(artifact => artifact.SizeBytes).ToString(CultureInfo.InvariantCulture)
        };
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

    private sealed record ArtifactClassification(
        ArtifactKind Kind,
        string? Category = null,
        string? EvidenceRole = null,
        string? CollectionName = null,
        string? CapturePhase = null,
        string? CaptureState = null,
        IReadOnlyDictionary<string, string>? Metadata = null);
}
