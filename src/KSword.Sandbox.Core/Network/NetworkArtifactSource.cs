using KSword.Sandbox.Abstractions.Artifacts;
using KSword.Sandbox.Core.Artifacts;
using ArtifactKindEnum = KSword.Sandbox.Abstractions.Artifacts.ArtifactKind;

namespace KSword.Sandbox.Core.Network;

/// <summary>
/// Carries host-side identity for a network evidence artifact while normalized
/// DNS/HTTP/TLS/connection rows are produced from PCAPs or sidecar telemetry.
/// Inputs are host paths and optional manifest metadata; processing derives
/// safe relative selectors and file identity lazily; importers attach the
/// values to every generated event for traceability.
/// </summary>
public sealed record NetworkArtifactSource(
    string FullPath,
    string ImportRoot,
    string ArtifactKind,
    string CollectionName,
    string EvidenceRole,
    string ImportMode,
    IReadOnlyDictionary<string, string>? Metadata = null)
{
    public static NetworkArtifactSource FromPath(
        string fullPath,
        string? importRoot = null,
        string? artifactKind = null,
        string? collectionName = null,
        string? evidenceRole = null,
        string? importMode = null,
        IReadOnlyDictionary<string, string>? metadata = null)
    {
        var kind = string.IsNullOrWhiteSpace(artifactKind)
            ? (ArtifactDescriptorFactory.IsPacketCapturePath(fullPath)
                ? ArtifactKindEnum.PacketCapture.ToString()
                : ArtifactKindEnum.Log.ToString())
            : artifactKind;
        return new NetworkArtifactSource(
            Path.GetFullPath(fullPath),
            string.IsNullOrWhiteSpace(importRoot)
                ? (Path.GetDirectoryName(Path.GetFullPath(fullPath)) ?? string.Empty)
                : Path.GetFullPath(importRoot),
            kind,
            string.IsNullOrWhiteSpace(collectionName) ? InferCollectionName(fullPath, metadata) : collectionName,
            string.IsNullOrWhiteSpace(evidenceRole) ? InferEvidenceRole(fullPath, metadata) : evidenceRole,
            string.IsNullOrWhiteSpace(importMode) ? "external-artifact" : importMode,
            metadata);
    }

    public static NetworkArtifactSource FromDescriptor(ArtifactDescriptor descriptor, string importRoot)
    {
        var metadata = descriptor.Metadata is null
            ? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, string>(descriptor.Metadata, StringComparer.OrdinalIgnoreCase);
        var path = ResolveDescriptorPath(descriptor, importRoot);
        return FromPath(
            path,
            importRoot,
            ResolveArtifactKind(descriptor, path),
            FirstNonEmpty(descriptor.CollectionName, MetadataValue(metadata, "collectionName")),
            FirstNonEmpty(descriptor.EvidenceRole, MetadataValue(metadata, "evidenceRole")),
            FirstNonEmpty(MetadataValue(metadata, "importMode"), InferImportMode(path)),
            metadata);
    }

    public string RelativePath => ArtifactDescriptorFactory.SafeRelativePath(ImportRoot, FullPath);

    public string Name => Path.GetFileName(FullPath);

    private static string InferCollectionName(string path, IReadOnlyDictionary<string, string>? metadata)
    {
        var explicitValue = MetadataValue(metadata, "collectionName");
        if (!string.IsNullOrWhiteSpace(explicitValue))
        {
            return explicitValue;
        }

        return ArtifactDescriptorFactory.IsPacketCapturePath(path)
            ? "packet-captures"
            : "network-sidecars";
    }

    private static string InferEvidenceRole(string path, IReadOnlyDictionary<string, string>? metadata)
    {
        var explicitValue = MetadataValue(metadata, "evidenceRole");
        if (!string.IsNullOrWhiteSpace(explicitValue))
        {
            return explicitValue;
        }

        return ArtifactDescriptorFactory.IsPacketCapturePath(path)
            ? "packet-capture"
            : "network-telemetry-sidecar";
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

    private static string ResolveDescriptorPath(ArtifactDescriptor descriptor, string importRoot)
    {
        var candidates = new[]
        {
            descriptor.FullPath,
            !string.IsNullOrWhiteSpace(descriptor.ImportPath) ? Path.Combine(importRoot, descriptor.ImportPath) : null,
            !string.IsNullOrWhiteSpace(descriptor.RelativePath) ? Path.Combine(importRoot, descriptor.RelativePath) : null
        };

        foreach (var candidate in candidates)
        {
            if (IsUsableCandidate(candidate, importRoot, requireExisting: true))
            {
                return Path.GetFullPath(candidate!);
            }
        }

        foreach (var candidate in candidates)
        {
            if (IsUsableCandidate(candidate, importRoot, requireExisting: false))
            {
                return Path.GetFullPath(candidate!);
            }
        }

        return FirstNonEmpty(candidates);
    }

    private static string? ResolveArtifactKind(ArtifactDescriptor descriptor, string path)
    {
        if (ArtifactDescriptorFactory.IsPacketCapturePath(path))
        {
            return ArtifactKindEnum.PacketCapture.ToString();
        }

        return descriptor.Kind == ArtifactKindEnum.Unknown
            ? null
            : descriptor.Kind.ToString();
    }

    private static string InferImportMode(string path)
    {
        return ArtifactDescriptorFactory.IsPacketCapturePath(path)
            ? "external-artifact"
            : "sidecar-artifact";
    }

    private static bool IsUsableCandidate(string? candidate, string importRoot, bool requireExisting)
    {
        if (string.IsNullOrWhiteSpace(candidate))
        {
            return false;
        }

        try
        {
            var fullPath = Path.GetFullPath(candidate);
            if (!IsUnderRoot(fullPath, importRoot))
            {
                return false;
            }

            return !requireExisting || File.Exists(fullPath);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }
    }

    private static bool IsUnderRoot(string path, string root)
    {
        var fullRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root)) + Path.DirectorySeparatorChar;
        var fullPath = Path.GetFullPath(path);
        return fullPath.StartsWith(fullRoot, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(Path.TrimEndingDirectorySeparator(fullPath), Path.TrimEndingDirectorySeparator(root), StringComparison.OrdinalIgnoreCase);
    }

    private static string? MetadataValue(IReadOnlyDictionary<string, string>? metadata, string key)
    {
        return metadata is not null && metadata.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : null;
    }
}
