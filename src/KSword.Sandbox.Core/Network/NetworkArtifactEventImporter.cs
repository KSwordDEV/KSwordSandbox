using System.Text.Json;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Abstractions.Artifacts;
using KSword.Sandbox.Core.Artifacts;

namespace KSword.Sandbox.Core.Network;

/// <summary>
/// Imports network evidence from a collected guest output root. Inputs are a
/// guest artifact manifest, packet-capture files, and nearby JSONL sidecars;
/// processing resolves only safe paths under the collected root and delegates
/// decoding to PCAP/sidecar importers; the method returns standardized
/// DNS/HTTP/TLS/connection rows plus a network.import.summary event.
/// </summary>
public sealed class NetworkArtifactEventImporter
{
    private readonly GuestArtifactManifestReader manifestReader;
    private readonly PcapArtifactEventImporter pcapImporter;
    private readonly NetworkSidecarEventImporter sidecarImporter;

    public NetworkArtifactEventImporter()
        : this(new GuestArtifactManifestReader(), new PcapArtifactEventImporter(), new NetworkSidecarEventImporter())
    {
    }

    internal NetworkArtifactEventImporter(
        GuestArtifactManifestReader manifestReader,
        PcapArtifactEventImporter pcapImporter,
        NetworkSidecarEventImporter sidecarImporter)
    {
        this.manifestReader = manifestReader;
        this.pcapImporter = pcapImporter;
        this.sidecarImporter = sidecarImporter;
    }

    public IReadOnlyList<SandboxEvent> ImportGuestArtifacts(string guestOutputRoot)
    {
        return ImportGuestArtifacts(guestOutputRoot, includeCanonicalDriverJsonl: true);
    }

    /// <summary>
    /// Imports network evidence from a collected guest output root. Inputs are a
    /// guest output root plus a switch for canonical driver-events.jsonl rows;
    /// processing resolves only safe paths under the collected root and
    /// delegates decoding to PCAP/sidecar importers while avoiding duplicate
    /// adjacent-sidecar imports; the method returns standardized network rows.
    /// </summary>
    public IReadOnlyList<SandboxEvent> ImportGuestArtifacts(string guestOutputRoot, bool includeCanonicalDriverJsonl)
    {
        if (string.IsNullOrWhiteSpace(guestOutputRoot) || !Directory.Exists(guestOutputRoot))
        {
            return [];
        }

        var importRoot = Path.GetFullPath(guestOutputRoot);
        var manifest = TryReadManifest(importRoot);
        var candidates = DiscoverCandidates(importRoot, manifest, includeCanonicalDriverJsonl).ToList();
        var events = new List<SandboxEvent>();
        var eventKeys = new HashSet<string>(StringComparer.Ordinal);
        var pcapArtifactCount = 0;
        var sidecarArtifactCount = 0;
        foreach (var candidate in candidates)
        {
            if (ArtifactDescriptorFactory.IsPacketCapturePath(candidate.Source.FullPath))
            {
                pcapArtifactCount++;
                foreach (var evt in pcapImporter.Import(candidate.Source.FullPath, candidate.Source, includeSidecars: false))
                {
                    AddIfNew(events, eventKeys, evt);
                }

                continue;
            }

            sidecarArtifactCount++;
            foreach (var evt in sidecarImporter.ImportEvents(candidate.Source.FullPath, candidate.Source))
            {
                AddIfNew(events, eventKeys, evt);
            }
        }

        return
        [
            NetworkTelemetrySchema.CreateImportSummary(
                importRoot,
                NetworkArtifactSource.FromPath(importRoot, importRoot, artifactKind: "Directory", collectionName: "network-import", evidenceRole: "network-import-root"),
                events,
                new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["importer"] = nameof(NetworkArtifactEventImporter),
                    ["importScope"] = "guest-artifacts",
                    ["manifestPresent"] = (manifest is not null).ToString().ToLowerInvariant(),
                    ["artifactCount"] = candidates.Count.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    ["pcapArtifactCount"] = pcapArtifactCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    ["sidecarArtifactCount"] = sidecarArtifactCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    ["tsharkRequired"] = "false"
                }),
            .. events
        ];
    }

    private ArtifactManifest? TryReadManifest(string importRoot)
    {
        try
        {
            return manifestReader.TryRead(importRoot);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return null;
        }
    }

    private static IEnumerable<NetworkImportCandidate> DiscoverCandidates(
        string importRoot,
        ArtifactManifest? manifest,
        bool includeCanonicalDriverJsonl)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (manifest is not null)
        {
            foreach (var descriptor in manifest.Artifacts ?? [])
            {
                if (!includeCanonicalDriverJsonl && IsCanonicalDriverEventsPath(FirstNonEmpty(descriptor.RelativePath, descriptor.ImportPath, descriptor.FullPath, descriptor.Name)))
                {
                    continue;
                }

                if (!IsNetworkImportDescriptor(descriptor))
                {
                    continue;
                }

                var source = NetworkArtifactSource.FromDescriptor(descriptor, importRoot);
                if (File.Exists(source.FullPath) && IsUnderRoot(source.FullPath, importRoot) && seen.Add(source.FullPath))
                {
                    yield return new NetworkImportCandidate(source, "manifest");
                }
            }
        }

        foreach (var path in SafeEnumerateFiles(importRoot, path =>
                IsNetworkImportPath(path) &&
                (includeCanonicalDriverJsonl || !IsCanonicalDriverEventsPath(path)))
            .OrderBy(path => path, StringComparer.OrdinalIgnoreCase))
        {
            var fullPath = Path.GetFullPath(path);
            if (seen.Add(fullPath))
            {
                yield return new NetworkImportCandidate(
                    NetworkArtifactSource.FromPath(
                        fullPath,
                        importRoot,
                        ArtifactDescriptorFactory.IsPacketCapturePath(fullPath) ? ArtifactKind.PacketCapture.ToString() : ArtifactKind.Log.ToString(),
                        ArtifactDescriptorFactory.IsPacketCapturePath(fullPath) ? "packet-captures" : "network-sidecars",
                        ArtifactDescriptorFactory.IsPacketCapturePath(fullPath) ? "packet-capture" : "network-telemetry-sidecar",
                        ArtifactDescriptorFactory.IsPacketCapturePath(fullPath) ? "external-artifact" : "sidecar-artifact"),
                    "filesystem");
            }
        }
    }

    private static bool IsNetworkImportDescriptor(ArtifactDescriptor descriptor)
    {
        if (descriptor.Kind == ArtifactKind.PacketCapture ||
            ArtifactDescriptorFactory.IsPacketCapturePath(descriptor.RelativePath) ||
            ArtifactDescriptorFactory.IsPacketCapturePath(descriptor.ImportPath) ||
            ArtifactDescriptorFactory.IsPacketCapturePath(descriptor.FullPath))
        {
            return true;
        }

        return IsNetworkSidecarDescriptor(descriptor);
    }

    private static bool IsNetworkSidecarDescriptor(ArtifactDescriptor descriptor)
    {
        if (NetworkSidecarEventImporter.IsLikelyNetworkSidecarPath(FirstNonEmpty(descriptor.RelativePath, descriptor.ImportPath, descriptor.FullPath, descriptor.Name)))
        {
            return true;
        }

        var metadata = descriptor.Metadata;
        return string.Equals(descriptor.CollectionName, "network-sidecars", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(descriptor.CollectionName, "packet-captures", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(descriptor.EvidenceRole, "network-telemetry-sidecar", StringComparison.OrdinalIgnoreCase) ||
            (metadata is not null &&
                (MetadataEquals(metadata, "collectionName", "network-sidecars") ||
                    MetadataEquals(metadata, "evidenceRole", "network-telemetry-sidecar") ||
                    MetadataEquals(metadata, "telemetryDomain", "network")));
    }

    private static bool IsNetworkImportPath(string path)
    {
        return ArtifactDescriptorFactory.IsPacketCapturePath(path) ||
            NetworkSidecarEventImporter.IsLikelyNetworkSidecarPath(path);
    }

    private static bool IsCanonicalDriverEventsPath(string path)
    {
        return string.Equals(Path.GetFileName(path), "driver-events.jsonl", StringComparison.OrdinalIgnoreCase);
    }

    private static IEnumerable<string> SafeEnumerateFiles(string root, Func<string, bool> predicate)
    {
        IEnumerable<string> files;
        try
        {
            files = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or DirectoryNotFoundException)
        {
            yield break;
        }

        foreach (var file in files)
        {
            if (predicate(file))
            {
                yield return file;
            }
        }
    }

    private static bool IsUnderRoot(string path, string root)
    {
        var fullRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root)) + Path.DirectorySeparatorChar;
        var fullPath = Path.GetFullPath(path);
        return fullPath.StartsWith(fullRoot, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(Path.TrimEndingDirectorySeparator(fullPath), Path.TrimEndingDirectorySeparator(root), StringComparison.OrdinalIgnoreCase);
    }

    private static void AddIfNew(List<SandboxEvent> events, HashSet<string> eventKeys, SandboxEvent evt)
    {
        if (eventKeys.Add(EventKey(evt)))
        {
            events.Add(evt);
        }
    }

    private static string EventKey(SandboxEvent evt)
    {
        var data = string.Join(";", evt.Data.OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase).Select(pair => $"{pair.Key}={pair.Value}"));
        return string.Join("|", evt.EventType, evt.Source, evt.Timestamp.ToString("O"), evt.Path ?? string.Empty, data);
    }

    private static bool MetadataEquals(IReadOnlyDictionary<string, string> metadata, string key, string expected)
    {
        return metadata.TryGetValue(key, out var value) &&
            string.Equals(value, expected, StringComparison.OrdinalIgnoreCase);
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

    private sealed record NetworkImportCandidate(NetworkArtifactSource Source, string DiscoverySource);
}
