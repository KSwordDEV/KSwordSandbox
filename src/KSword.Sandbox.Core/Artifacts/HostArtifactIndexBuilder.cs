using KSword.Sandbox.Abstractions.Artifacts;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace KSword.Sandbox.Core.Artifacts;

/// <summary>
/// Builds and persists host-side artifact indexes for job directories.
/// Inputs are a job ID and job root; processing scans known report, telemetry,
/// screenshot, manifest, and dropped-file paths; methods return index models
/// or the descriptor for artifact-index.json.
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
        var artifacts = new List<ArtifactDescriptor>();
        if (Directory.Exists(fullJobRoot))
        {
            foreach (var path in Directory.EnumerateFiles(fullJobRoot, "*", SearchOption.AllDirectories)
                .Where(path => !string.Equals(Path.GetFileName(path), IndexFileName, StringComparison.OrdinalIgnoreCase))
                .OrderBy(path => ArtifactDescriptorFactory.SafeRelativePath(fullJobRoot, path), StringComparer.OrdinalIgnoreCase))
            {
                var kind = Classify(path, fullJobRoot);
                if (kind == ArtifactKind.Unknown)
                {
                    continue;
                }

                artifacts.Add(ArtifactDescriptorFactory.FromExistingFile(
                    path,
                    fullJobRoot,
                    kind,
                    new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["origin"] = "host",
                        ["indexRoot"] = fullJobRoot
                    }));
            }
        }

        return new HostArtifactIndex
        {
            JobId = jobId,
            RootPath = fullJobRoot,
            GeneratedAtUtc = DateTimeOffset.UtcNow,
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

    private static ArtifactKind Classify(string path, string jobRoot)
    {
        var fileName = Path.GetFileName(path);
        var relativePath = ArtifactDescriptorFactory.SafeRelativePath(jobRoot, path);
        if (string.Equals(fileName, "report.json", StringComparison.OrdinalIgnoreCase))
        {
            return ArtifactKind.ReportJson;
        }

        if (string.Equals(fileName, "report.html", StringComparison.OrdinalIgnoreCase))
        {
            return ArtifactKind.ReportHtml;
        }

        if (string.Equals(fileName, "runbook.json", StringComparison.OrdinalIgnoreCase))
        {
            return ArtifactKind.RunbookJson;
        }

        if (string.Equals(fileName, "runbook-execution.json", StringComparison.OrdinalIgnoreCase))
        {
            return ArtifactKind.RunbookExecutionJson;
        }

        if (string.Equals(fileName, "events.json", StringComparison.OrdinalIgnoreCase))
        {
            return ArtifactKind.GuestEventsJson;
        }

        if (string.Equals(fileName, "agent-summary.json", StringComparison.OrdinalIgnoreCase))
        {
            return ArtifactKind.GuestSummaryJson;
        }

        if (string.Equals(fileName, "artifact-manifest.json", StringComparison.OrdinalIgnoreCase) ||
            relativePath.EndsWith("/artifacts/manifest.json", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(relativePath, "artifacts/manifest.json", StringComparison.OrdinalIgnoreCase))
        {
            return ArtifactKind.ArtifactManifest;
        }

        if (string.Equals(Path.GetExtension(path), ".jsonl", StringComparison.OrdinalIgnoreCase) &&
            fileName.Contains("driver", StringComparison.OrdinalIgnoreCase))
        {
            return ArtifactKind.DriverEventsJsonLines;
        }

        if (relativePath.Contains("/screenshots/", StringComparison.OrdinalIgnoreCase) ||
            relativePath.StartsWith("screenshots/", StringComparison.OrdinalIgnoreCase))
        {
            return ArtifactKind.Screenshot;
        }

        if (relativePath.Contains("/artifacts/", StringComparison.OrdinalIgnoreCase) ||
            relativePath.StartsWith("artifacts/", StringComparison.OrdinalIgnoreCase))
        {
            return ArtifactKind.DroppedFile;
        }

        if (string.Equals(Path.GetExtension(path), ".log", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(Path.GetExtension(path), ".txt", StringComparison.OrdinalIgnoreCase))
        {
            return ArtifactKind.Log;
        }

        return ArtifactKind.Unknown;
    }
}
