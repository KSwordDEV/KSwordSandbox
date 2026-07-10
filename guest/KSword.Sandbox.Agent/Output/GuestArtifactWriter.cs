using System.Text.Json;
using System.Text.Json.Serialization;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Abstractions.Artifacts;

namespace KSword.Sandbox.Agent.Output;

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
        Directory.CreateDirectory(outputDirectory);
        var artifactsRoot = Path.Combine(outputDirectory, ArtifactsDirectoryName);
        Directory.CreateDirectory(artifactsRoot);
        var manifestPath = Path.Combine(artifactsRoot, ManifestFileName);
        var descriptors = EnumerateDroppedFileArtifacts(outputDirectory, artifactsRoot, manifestPath);
        var manifest = new ArtifactManifest
        {
            RuntimeRoot = Path.GetFullPath(outputDirectory),
            RootPath = Path.GetFullPath(artifactsRoot),
            Producer = "KSword.Sandbox.Agent",
            Artifacts = descriptors
        };

        File.WriteAllText(manifestPath, JsonSerializer.Serialize(manifest, ManifestJsonOptions));
        return manifestPath;
    }

    /// <summary>
    /// Enumerates dropped-file descriptors below the artifacts directory.
    /// Inputs are output/artifact roots and the manifest path; processing skips
    /// the manifest itself and hashes readable files; the method returns
    /// descriptors suitable for the manifest JSON.
    /// </summary>
    private static List<ArtifactDescriptor> EnumerateDroppedFileArtifacts(string outputDirectory, string artifactsRoot, string manifestPath)
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
            .Select(path => CreateDroppedFileDescriptor(fullOutputDirectory, path))
            .ToList();
    }

    /// <summary>
    /// Creates one dropped-file artifact descriptor from filesystem metadata.
    /// Inputs are the guest output root and a file path; processing reads file
    /// metadata and SHA-256, and the method returns the manifest descriptor.
    /// </summary>
    private static ArtifactDescriptor CreateDroppedFileDescriptor(string outputDirectory, string path)
    {
        var info = new FileInfo(path);
        return new ArtifactDescriptor
        {
            Kind = ArtifactKind.DroppedFile,
            Name = info.Name,
            RelativePath = Path.GetRelativePath(outputDirectory, info.FullName),
            FullPath = info.FullName,
            SizeBytes = info.Length,
            Sha256 = ComputeSha256(info.FullName),
            CreatedAtUtc = info.CreationTimeUtc,
            Metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["origin"] = "guest",
                ["evidenceRole"] = "dropped-file",
                ["guestFullPath"] = info.FullName
            }
        };
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
}
