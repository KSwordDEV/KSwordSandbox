using KSword.Sandbox.Abstractions.Artifacts;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace KSword.Sandbox.Core.Artifacts;

/// <summary>
/// Loads guest-produced artifact manifests from collected output folders.
/// Inputs are host paths that contain guest output, processing looks for the
/// canonical artifacts/manifest.json file, and methods return manifest models
/// that host code can merge into reports or artifact indexes later.
/// </summary>
public sealed class GuestArtifactManifestReader
{
    public const string ArtifactsDirectoryName = "artifacts";

    public const string ManifestFileName = "manifest.json";

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter() }
    };

    /// <summary>
    /// Returns the canonical manifest path for a guest output directory.
    /// The input is a guest output root, processing appends artifacts/manifest.json,
    /// and the method returns the expected host path.
    /// </summary>
    public string BuildManifestPath(string guestOutputRoot)
    {
        return Path.Combine(guestOutputRoot, ArtifactsDirectoryName, ManifestFileName);
    }

    /// <summary>
    /// Tries to load a guest artifact manifest.
    /// Inputs are a guest output root and cancellation token, processing reads
    /// the canonical manifest when it exists, and the method returns null when
    /// no manifest was produced.
    /// </summary>
    public async Task<ArtifactManifest?> TryReadAsync(string guestOutputRoot, CancellationToken cancellationToken = default)
    {
        var manifestPath = BuildManifestPath(guestOutputRoot);
        if (!File.Exists(manifestPath))
        {
            return null;
        }

        await using var stream = File.OpenRead(manifestPath);
        var manifest = await JsonSerializer.DeserializeAsync<ArtifactManifest>(stream, JsonOptions, cancellationToken);
        if (manifest is null)
        {
            return null;
        }

        return NormalizeManifest(manifest, guestOutputRoot, manifestPath);
    }

    /// <summary>
    /// Tries to load a guest artifact manifest synchronously for callers that
    /// already operate on a filesystem scan.
    /// Inputs are a guest output root; processing reads the canonical manifest
    /// when it exists; the method returns null when no manifest was produced.
    /// </summary>
    public ArtifactManifest? TryRead(string guestOutputRoot)
    {
        var manifestPath = BuildManifestPath(guestOutputRoot);
        if (!File.Exists(manifestPath))
        {
            return null;
        }

        var manifest = JsonSerializer.Deserialize<ArtifactManifest>(File.ReadAllText(manifestPath), JsonOptions);
        if (manifest is null)
        {
            return null;
        }

        return NormalizeManifest(manifest, guestOutputRoot, manifestPath);
    }

    /// <summary>
    /// Normalizes a loaded guest manifest for host-side use.
    /// Inputs are the raw manifest, guest output root, and manifest path;
    /// processing fills missing roots and absolute descriptor paths from
    /// relative paths, and the method returns a manifest copy.
    /// </summary>
    private static ArtifactManifest NormalizeManifest(ArtifactManifest manifest, string guestOutputRoot, string manifestPath)
    {
        var fullGuestRoot = Path.GetFullPath(guestOutputRoot);
        var artifactsRoot = Path.GetDirectoryName(Path.GetFullPath(manifestPath)) ?? fullGuestRoot;
        var artifacts = (manifest.Artifacts ?? [])
            .Select(artifact => NormalizeDescriptor(artifact, fullGuestRoot))
            .ToList();
        var collections = (manifest.Collections ?? [])
            .Select(NormalizeCollection)
            .ToList();

        return manifest with
        {
            RuntimeRoot = fullGuestRoot,
            RootPath = artifactsRoot,
            ImportRoot = fullGuestRoot,
            Producer = string.IsNullOrWhiteSpace(manifest.Producer) ? "KSword.Sandbox.Agent" : manifest.Producer,
            Collections = collections,
            Artifacts = artifacts
        };
    }

    /// <summary>
    /// Normalizes one descriptor loaded from a guest manifest.
    /// Inputs are a descriptor and host guest-output root; processing resolves a
    /// missing full path from RelativePath while preserving supplied metadata,
    /// and the method returns a descriptor copy.
    /// </summary>
    private static ArtifactDescriptor NormalizeDescriptor(ArtifactDescriptor descriptor, string guestOutputRoot)
    {
        var relativePath = ArtifactDescriptorFactory.NormalizeRelativePath(descriptor.RelativePath);
        var descriptorKind = ResolveDescriptorKind(descriptor, relativePath);
        if (string.IsNullOrWhiteSpace(relativePath))
        {
            return ArtifactDescriptorFactory.NormalizeDescriptor(descriptor with { Kind = descriptorKind }) with
            {
                RelativePath = string.Empty,
                SafeLink = string.Empty
            };
        }

        var metadata = CopyMetadata(descriptor.Metadata);
        AddIfNotEmpty(metadata, "evidenceRole", descriptor.EvidenceRole);
        AddIfNotEmpty(metadata, "capturePhase", descriptor.CapturePhase);
        AddIfNotEmpty(metadata, "captureState", descriptor.CaptureState);
        AddIfNotEmpty(metadata, "collectionName", descriptor.CollectionName);
        AddIfNotEmpty(metadata, "importPath", string.IsNullOrWhiteSpace(descriptor.ImportPath) ? relativePath : descriptor.ImportPath);
        AddPacketCaptureImportDefaults(descriptorKind, metadata);
        if (!string.IsNullOrWhiteSpace(FirstNonEmpty(descriptor.GuestPath, descriptor.FullPath)) &&
            !metadata.ContainsKey("guestFullPath"))
        {
            metadata["guestFullPath"] = FirstNonEmpty(descriptor.GuestPath, descriptor.FullPath);
        }

        var fullPath = Path.GetFullPath(Path.Combine(guestOutputRoot, relativePath));
        if (descriptorKind == ArtifactKind.PacketCapture && File.Exists(fullPath))
        {
            AddIfMissing(metadata, "captureState", "available");
        }

        var normalized = File.Exists(fullPath)
            ? ArtifactDescriptorFactory.FromExistingFile(fullPath, guestOutputRoot, descriptorKind, metadata)
            : ArtifactDescriptorFactory.FromKnownPath(fullPath, guestOutputRoot, descriptorKind, metadata);

        return normalized with
        {
            Category = string.IsNullOrWhiteSpace(descriptor.Category) ? normalized.Category : descriptor.Category,
            MimeType = string.IsNullOrWhiteSpace(descriptor.MimeType) ? normalized.MimeType : descriptor.MimeType,
            SizeBytes = descriptor.SizeBytes > 0 ? descriptor.SizeBytes : normalized.SizeBytes,
            Sha256 = string.IsNullOrWhiteSpace(descriptor.Sha256) ? normalized.Sha256 : descriptor.Sha256,
            Hashes = MergeHashes(descriptor, normalized),
            CreatedAtUtc = descriptor.CreatedAtUtc == default ? normalized.CreatedAtUtc : descriptor.CreatedAtUtc,
            EvidenceRole = FirstNonEmpty(descriptor.EvidenceRole, normalized.EvidenceRole, MetadataValue(metadata, "evidenceRole")),
            CapturePhase = FirstNonEmpty(descriptor.CapturePhase, normalized.CapturePhase, MetadataValue(metadata, "capturePhase", "phase")),
            CaptureState = FirstNonEmpty(descriptor.CaptureState, normalized.CaptureState, MetadataValue(metadata, "captureState")),
            GuestPath = FirstNonEmpty(descriptor.GuestPath, MetadataValue(metadata, "guestFullPath", "guestPath"), descriptor.FullPath),
            ImportPath = FirstNonEmpty(descriptor.ImportPath, normalized.ImportPath, relativePath),
            CollectionName = FirstNonEmpty(descriptor.CollectionName, normalized.CollectionName, MetadataValue(metadata, "collectionName")),
            Metadata = metadata
        };
    }

    private static ArtifactKind ResolveDescriptorKind(ArtifactDescriptor descriptor, string relativePath)
    {
        if (descriptor.Kind != ArtifactKind.Unknown)
        {
            return descriptor.Kind;
        }

        if (ArtifactDescriptorFactory.IsPacketCapturePath(relativePath) ||
            ArtifactDescriptorFactory.IsPacketCapturePath(descriptor.Name) ||
            ArtifactDescriptorFactory.IsPacketCapturePath(descriptor.FullPath))
        {
            return ArtifactKind.PacketCapture;
        }

        return descriptor.Kind;
    }

    private static ArtifactCollectionDescriptor NormalizeCollection(ArtifactCollectionDescriptor collection)
    {
        var relativePath = ArtifactDescriptorFactory.NormalizeRelativePath(collection.RelativePath);
        return collection with
        {
            Category = string.IsNullOrWhiteSpace(collection.Category)
                ? ArtifactDescriptorFactory.CategoryForKind(collection.Kind)
                : collection.Category,
            RelativePath = relativePath,
            SafeLink = string.IsNullOrWhiteSpace(collection.SafeLink)
                ? ArtifactDescriptorFactory.BuildSafeLink(relativePath)
                : collection.SafeLink,
            ImportPath = string.IsNullOrWhiteSpace(collection.ImportPath)
                ? relativePath
                : ArtifactDescriptorFactory.NormalizeRelativePath(collection.ImportPath),
            Metadata = CopyMetadata(collection.Metadata)
        };
    }

    private static Dictionary<string, string> MergeHashes(ArtifactDescriptor descriptor, ArtifactDescriptor normalized)
    {
        var hashes = new Dictionary<string, string>(normalized.Hashes, StringComparer.OrdinalIgnoreCase);
        if (descriptor.Hashes is not null)
        {
            foreach (var pair in descriptor.Hashes)
            {
                hashes[pair.Key] = pair.Value;
            }
        }

        if (!string.IsNullOrWhiteSpace(descriptor.Sha256))
        {
            hashes["sha256"] = descriptor.Sha256;
        }

        return hashes;
    }

    private static Dictionary<string, string> CopyMetadata(IDictionary<string, string>? metadata)
    {
        return metadata is null
            ? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, string>(metadata, StringComparer.OrdinalIgnoreCase);
    }

    private static void AddIfNotEmpty(Dictionary<string, string> metadata, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            metadata[key] = value;
        }
    }

    private static void AddPacketCaptureImportDefaults(ArtifactKind kind, Dictionary<string, string> metadata)
    {
        if (kind != ArtifactKind.PacketCapture)
        {
            return;
        }

        AddIfMissing(metadata, "evidenceRole", "packet-capture");
        AddIfMissing(metadata, "collectionName", "packet-captures");
        AddIfMissing(metadata, "captureSource", "external");
        AddIfMissing(metadata, "hostCaptureStarted", "false");
        AddIfMissing(metadata, "importMode", "external-artifact");
    }

    private static void AddIfMissing(Dictionary<string, string> metadata, string key, string value)
    {
        if (!metadata.ContainsKey(key) || string.IsNullOrWhiteSpace(metadata[key]))
        {
            metadata[key] = value;
        }
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

    private static string? MetadataValue(IDictionary<string, string> metadata, params string[] keys)
    {
        foreach (var key in keys)
        {
            if (metadata.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return null;
    }
}
