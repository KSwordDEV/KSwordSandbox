using KSword.Sandbox.Abstractions.Artifacts;
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
        return ArtifactDescriptorFactory.FromExistingFile(
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
            ImportRoot = string.IsNullOrWhiteSpace(manifest.ImportRoot)
                ? paths.BuildJobRoot(jobId)
                : manifest.ImportRoot,
            Producer = string.IsNullOrWhiteSpace(manifest.Producer)
                ? "KSword.Sandbox.Core"
                : manifest.Producer,
            GeneratedAtUtc = DateTimeOffset.UtcNow
        };
        normalizedManifest = normalizedManifest with
        {
            Artifacts = (normalizedManifest.Artifacts ?? [])
                .Select(ArtifactDescriptorFactory.NormalizeDescriptor)
                .ToList(),
            Collections = (normalizedManifest.Collections ?? [])
                .Select(NormalizeCollection)
                .ToList()
        };

        await File.WriteAllTextAsync(
            manifestPath,
            JsonSerializer.Serialize(normalizedManifest, ManifestJsonOptions),
            cancellationToken);

        return ArtifactDescriptorFactory.FromExistingFile(
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

    private static ArtifactCollectionDescriptor NormalizeCollection(ArtifactCollectionDescriptor collection)
    {
        var importPath = ArtifactDescriptorFactory.NormalizeSelector(collection.ImportPath);
        var relativePath = FirstNonEmpty(
            ArtifactDescriptorFactory.NormalizeRelativePath(collection.RelativePath),
            importPath,
            ArtifactDescriptorFactory.NormalizeSelector(collection.SafeLink));
        var safeLink = ArtifactDescriptorFactory.BuildSafeLink(relativePath);
        if (string.IsNullOrWhiteSpace(safeLink))
        {
            safeLink = ArtifactDescriptorFactory.NormalizeSafeLink(collection.SafeLink);
        }

        return collection with
        {
            Category = string.IsNullOrWhiteSpace(collection.Category)
                ? ArtifactDescriptorFactory.CategoryForKind(collection.Kind)
                : collection.Category,
            RelativePath = relativePath,
            SafeLink = safeLink,
            ImportPath = FirstNonEmpty(importPath, relativePath),
            Metadata = collection.Metadata is null
                ? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                : new Dictionary<string, string>(collection.Metadata, StringComparer.OrdinalIgnoreCase)
        };
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
}
