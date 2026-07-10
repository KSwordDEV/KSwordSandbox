using System.Text.Json;
using System.Text.Json.Serialization;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Abstractions.Artifacts;

namespace KSword.Sandbox.Agent.Output;

/// <summary>
/// Describes the result of writing a guest-side artifact manifest.
/// Inputs are produced by GuestArtifactWriter; processing is immutable storage;
/// callers use the manifest path and descriptor count for events.
/// </summary>
internal sealed record GuestArtifactManifestWriteResult(string ManifestPath, int ArtifactCount);

/// <summary>
/// Preserves original dropped-file evidence metadata for copied artifacts.
/// Inputs are the VM-local source path, source-relative path, and source event;
/// processing stores strings for manifest metadata only.
/// </summary>
internal sealed record DroppedFileArtifactMetadata(string OriginalFullPath, string OriginalRelativePath, string SourceEventType);

/// <summary>
/// Writes guest events and summaries into the configured output directory.
/// Inputs are output paths and event lists; processing serializes JSON files;
/// methods return paths to written artifacts.
/// </summary>
internal sealed class GuestArtifactWriter
{
    public const string ArtifactsDirectoryName = "artifacts";

    public const string ManifestFileName = "manifest.json";

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
    /// Writes artifacts/manifest.json for dropped files in the guest output.
    /// Inputs are the output directory created by --out; processing scans the
    /// artifacts subdirectory, records size/hash/path metadata for each file,
    /// and serializes a manifest; the method returns the manifest path.
    /// </summary>
    public string WriteArtifactManifest(string outputDirectory)
    {
        return WriteArtifactManifest(outputDirectory, metadataByRelativePath: null).ManifestPath;
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
        Directory.CreateDirectory(outputDirectory);
        var artifactsRoot = Path.Combine(outputDirectory, ArtifactsDirectoryName);
        Directory.CreateDirectory(artifactsRoot);
        var manifestPath = Path.Combine(artifactsRoot, ManifestFileName);
        var descriptors = EnumerateDroppedFileArtifacts(outputDirectory, artifactsRoot, manifestPath, metadataByRelativePath);
        var manifest = new ArtifactManifest
        {
            RuntimeRoot = Path.GetFullPath(outputDirectory),
            RootPath = Path.GetFullPath(artifactsRoot),
            Producer = "KSword.Sandbox.Agent",
            Artifacts = descriptors
        };

        File.WriteAllText(manifestPath, JsonSerializer.Serialize(manifest, ManifestJsonOptions));
        return new GuestArtifactManifestWriteResult(manifestPath, descriptors.Count);
    }

    /// <summary>
    /// Enumerates dropped-file descriptors below the artifacts directory.
    /// Inputs are output/artifact roots and the manifest path; processing skips
    /// the manifest itself and hashes readable files; the method returns
    /// descriptors suitable for the manifest JSON.
    /// </summary>
    private static List<ArtifactDescriptor> EnumerateDroppedFileArtifacts(
        string outputDirectory,
        string artifactsRoot,
        string manifestPath,
        IReadOnlyDictionary<string, DroppedFileArtifactMetadata>? metadataByRelativePath)
    {
        if (!Directory.Exists(artifactsRoot))
        {
            return [];
        }

        var fullOutputDirectory = Path.GetFullPath(outputDirectory);
        var fullManifestPath = Path.GetFullPath(manifestPath);
        return Directory
            .EnumerateFiles(artifactsRoot, "*", SearchOption.AllDirectories)
            .Select(Path.GetFullPath)
            .Where(path => !string.Equals(path, fullManifestPath, StringComparison.OrdinalIgnoreCase))
            .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
            .Select(path => CreateDroppedFileDescriptor(fullOutputDirectory, path, metadataByRelativePath))
            .ToList();
    }

    /// <summary>
    /// Creates one dropped-file artifact descriptor from filesystem metadata.
    /// Inputs are the guest output root and a file path; processing reads file
    /// metadata and SHA-256, and the method returns the manifest descriptor.
    /// </summary>
    private static ArtifactDescriptor CreateDroppedFileDescriptor(
        string outputDirectory,
        string path,
        IReadOnlyDictionary<string, DroppedFileArtifactMetadata>? metadataByRelativePath)
    {
        var info = new FileInfo(path);
        var relativePath = NormalizeRelativePath(Path.GetRelativePath(outputDirectory, info.FullName));
        var sha256 = ComputeSha256(info.FullName);
        DroppedFileArtifactMetadata? sourceMetadata = null;
        metadataByRelativePath?.TryGetValue(relativePath, out sourceMetadata);
        return new ArtifactDescriptor
        {
            Kind = ArtifactKind.DroppedFile,
            Category = "dropped-file",
            Name = info.Name,
            RelativePath = relativePath,
            FullPath = info.FullName,
            SafeLink = BuildSafeLink(relativePath),
            MimeType = MimeTypeForPath(info.FullName),
            SizeBytes = info.Length,
            Sha256 = sha256,
            Hashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["sha256"] = sha256
            },
            CreatedAtUtc = info.CreationTimeUtc,
            Metadata = CreateDroppedFileMetadata(info.FullName, sourceMetadata)
        };
    }

    /// <summary>
    /// Builds manifest metadata for a copied dropped-file artifact.
    /// Inputs are the copied artifact path and optional original source
    /// metadata; processing preserves the original guest path when known; the
    /// method returns string metadata for ArtifactDescriptor.
    /// </summary>
    private static Dictionary<string, string> CreateDroppedFileMetadata(
        string artifactFullPath,
        DroppedFileArtifactMetadata? sourceMetadata)
    {
        var metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["origin"] = "guest",
            ["evidenceRole"] = "dropped-file",
            ["guestFullPath"] = sourceMetadata?.OriginalFullPath ?? artifactFullPath,
            ["artifactFullPath"] = artifactFullPath
        };

        if (sourceMetadata is not null)
        {
            metadata["guestRelativePath"] = sourceMetadata.OriginalRelativePath;
            metadata["sourceEventType"] = sourceMetadata.SourceEventType;
        }

        return metadata;
    }

    /// <summary>
    /// Computes a SHA-256 digest for a guest artifact.
    /// The input is a full file path, processing streams file bytes through the
    /// hash algorithm, and the method returns lowercase hexadecimal text.
    /// </summary>
    private static string ComputeSha256(string path)
    {
        using var stream = File.OpenRead(path);
        var hash = System.Security.Cryptography.SHA256.HashData(stream);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    /// <summary>
    /// Normalizes manifest-relative paths to safe slash-separated text.
    /// The input may contain platform separators; processing rejects rooted or
    /// parent-traversal segments; the method returns safe relative path text.
    /// </summary>
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

    /// <summary>
    /// Builds a link target for local reports from a relative manifest path.
    /// Inputs are slash-separated relative path text; processing URL-encodes
    /// each segment; the method returns safe href text or empty text.
    /// </summary>
    private static string BuildSafeLink(string relativePath)
    {
        var normalized = NormalizeRelativePath(relativePath);
        if (string.IsNullOrWhiteSpace(normalized))
        {
            return string.Empty;
        }

        return string.Join("/", normalized.Split('/').Select(Uri.EscapeDataString));
    }

    /// <summary>
    /// Maps common artifact file names to MIME types.
    /// The input is a path; processing checks the extension; the method returns
    /// a deterministic content type string.
    /// </summary>
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
            ".zip" => "application/zip",
            ".exe" or ".dll" or ".sys" => "application/vnd.microsoft.portable-executable",
            _ => "application/octet-stream"
        };
    }
}
