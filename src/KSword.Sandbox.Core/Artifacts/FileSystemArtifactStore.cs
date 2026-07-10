using KSword.Sandbox.Abstractions.Artifacts;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace KSword.Sandbox.Core.Artifacts;

/// <summary>
/// Stores artifacts on the local filesystem under the configured runtime root.
/// Inputs are job IDs and artifact content; processing creates job folders and
/// writes files; methods return artifact descriptors or file content.
/// </summary>
public sealed class FileSystemArtifactStore : IArtifactStore
{
    private static readonly JsonSerializerOptions ManifestJsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    private readonly ArtifactPathBuilder paths;

    /// <summary>
    /// Creates a filesystem artifact store.
    /// The input is a runtime root, processing initializes a path builder, and
    /// the constructor returns no value.
    /// </summary>
    public FileSystemArtifactStore(string runtimeRoot)
    {
        paths = new ArtifactPathBuilder(runtimeRoot);
    }

    /// <inheritdoc />
    public async Task<ArtifactDescriptor> WriteTextAsync(Guid jobId, string name, ArtifactKind kind, string content, CancellationToken cancellationToken = default)
    {
        var artifactPath = paths.BuildArtifactPath(jobId, name);
        Directory.CreateDirectory(Path.GetDirectoryName(artifactPath)!);
        await File.WriteAllTextAsync(artifactPath, content, cancellationToken);
        return CreateDescriptor(
            artifactPath,
            paths.BuildJobRoot(jobId),
            kind,
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["origin"] = "host"
            });
    }

    /// <inheritdoc />
    public async Task<ArtifactDescriptor> WriteManifestAsync(Guid jobId, ArtifactManifest manifest, CancellationToken cancellationToken = default)
    {
        var manifestPath = paths.BuildArtifactManifestPath(jobId);
        Directory.CreateDirectory(Path.GetDirectoryName(manifestPath)!);
        var normalizedManifest = manifest with
        {
            JobId = manifest.JobId == Guid.Empty ? jobId : manifest.JobId,
            RuntimeRoot = string.IsNullOrWhiteSpace(manifest.RuntimeRoot)
                ? paths.BuildJobRoot(jobId)
                : manifest.RuntimeRoot,
            RootPath = string.IsNullOrWhiteSpace(manifest.RootPath)
                ? paths.BuildJobRoot(jobId)
                : manifest.RootPath,
            Producer = string.IsNullOrWhiteSpace(manifest.Producer)
                ? "KSword.Sandbox.Core"
                : manifest.Producer,
            GeneratedAtUtc = DateTimeOffset.UtcNow
        };

        await File.WriteAllTextAsync(
            manifestPath,
            JsonSerializer.Serialize(normalizedManifest, ManifestJsonOptions),
            cancellationToken);

        return CreateDescriptor(
            manifestPath,
            paths.BuildJobRoot(jobId),
            ArtifactKind.ArtifactManifest,
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["origin"] = "host",
                ["schemaVersion"] = normalizedManifest.SchemaVersion.ToString()
            });
    }

    /// <inheritdoc />
    public Task<string> ReadTextAsync(ArtifactDescriptor descriptor, CancellationToken cancellationToken = default)
    {
        return File.ReadAllTextAsync(descriptor.FullPath, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<ArtifactManifest> ReadManifestAsync(ArtifactDescriptor descriptor, CancellationToken cancellationToken = default)
    {
        var json = await ReadTextAsync(descriptor, cancellationToken);
        return JsonSerializer.Deserialize<ArtifactManifest>(json, ManifestJsonOptions)
            ?? throw new InvalidDataException($"Artifact manifest '{descriptor.FullPath}' could not be deserialized.");
    }

    /// <summary>
    /// Creates a descriptor from filesystem metadata.
    /// Inputs are an artifact path, root path, artifact kind, and metadata;
    /// processing reads length, creation time, relative path, and SHA-256; the
    /// method returns a durable descriptor for manifests or API responses.
    /// </summary>
    private static ArtifactDescriptor CreateDescriptor(
        string artifactPath,
        string rootPath,
        ArtifactKind kind,
        Dictionary<string, string> metadata)
    {
        var info = new FileInfo(artifactPath);
        return new ArtifactDescriptor
        {
            Kind = kind,
            Name = info.Name,
            RelativePath = Path.GetRelativePath(rootPath, info.FullName),
            FullPath = info.FullName,
            SizeBytes = info.Length,
            Sha256 = ComputeSha256(info.FullName),
            CreatedAtUtc = info.CreationTimeUtc,
            Metadata = metadata
        };
    }

    /// <summary>
    /// Computes a SHA-256 digest for an artifact file.
    /// The input is a full path, processing streams the file through SHA-256,
    /// and the method returns lowercase hexadecimal digest text.
    /// </summary>
    private static string ComputeSha256(string fullPath)
    {
        using var stream = File.OpenRead(fullPath);
        var hash = SHA256.HashData(stream);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
