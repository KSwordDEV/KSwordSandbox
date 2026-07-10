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
    /// Normalizes a loaded guest manifest for host-side use.
    /// Inputs are the raw manifest, guest output root, and manifest path;
    /// processing fills missing roots and absolute descriptor paths from
    /// relative paths, and the method returns a manifest copy.
    /// </summary>
    private static ArtifactManifest NormalizeManifest(ArtifactManifest manifest, string guestOutputRoot, string manifestPath)
    {
        var fullGuestRoot = Path.GetFullPath(guestOutputRoot);
        var artifactsRoot = Path.GetDirectoryName(Path.GetFullPath(manifestPath)) ?? fullGuestRoot;
        var artifacts = manifest.Artifacts
            .Select(artifact => NormalizeDescriptor(artifact, fullGuestRoot))
            .ToList();

        return manifest with
        {
            RuntimeRoot = fullGuestRoot,
            RootPath = artifactsRoot,
            Producer = string.IsNullOrWhiteSpace(manifest.Producer) ? "KSword.Sandbox.Agent" : manifest.Producer,
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
        if (string.IsNullOrWhiteSpace(relativePath))
        {
            return ArtifactDescriptorFactory.NormalizeDescriptor(descriptor) with
            {
                RelativePath = string.Empty,
                SafeLink = string.Empty
            };
        }

        var metadata = new Dictionary<string, string>(descriptor.Metadata, StringComparer.OrdinalIgnoreCase);
        if (!string.IsNullOrWhiteSpace(descriptor.FullPath) &&
            !metadata.ContainsKey("guestFullPath"))
        {
            metadata["guestFullPath"] = descriptor.FullPath;
        }

        var fullPath = Path.GetFullPath(Path.Combine(guestOutputRoot, relativePath));
        var normalized = File.Exists(fullPath)
            ? ArtifactDescriptorFactory.FromExistingFile(fullPath, guestOutputRoot, descriptor.Kind, metadata)
            : ArtifactDescriptorFactory.FromKnownPath(fullPath, guestOutputRoot, descriptor.Kind, metadata);

        return normalized with
        {
            Category = string.IsNullOrWhiteSpace(descriptor.Category) ? normalized.Category : descriptor.Category,
            MimeType = string.IsNullOrWhiteSpace(descriptor.MimeType) ? normalized.MimeType : descriptor.MimeType,
            SizeBytes = descriptor.SizeBytes > 0 ? descriptor.SizeBytes : normalized.SizeBytes,
            Sha256 = string.IsNullOrWhiteSpace(descriptor.Sha256) ? normalized.Sha256 : descriptor.Sha256,
            Hashes = MergeHashes(descriptor, normalized),
            CreatedAtUtc = descriptor.CreatedAtUtc == default ? normalized.CreatedAtUtc : descriptor.CreatedAtUtc,
            Metadata = metadata
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
}
