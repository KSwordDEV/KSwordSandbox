namespace KSword.Sandbox.Core.Artifacts;

/// <summary>
/// Builds deterministic host artifact paths for one sandbox job.
/// Inputs are a runtime root and job IDs; processing combines safe path
/// segments; methods return absolute or configured-local filesystem paths.
/// </summary>
public sealed class ArtifactPathBuilder
{
    private readonly string runtimeRoot;

    /// <summary>
    /// Creates a path builder rooted at the configured runtime directory.
    /// The input is a runtime root, processing stores its full path when
    /// possible, and the constructor returns no value.
    /// </summary>
    public ArtifactPathBuilder(string runtimeRoot)
    {
        this.runtimeRoot = Path.GetFullPath(runtimeRoot);
    }

    /// <summary>
    /// Returns the job root folder for one analysis.
    /// The input is a job ID, processing formats it without separators, and the
    /// method returns the host job directory path.
    /// </summary>
    public string BuildJobRoot(Guid jobId)
    {
        return Path.Combine(runtimeRoot, "jobs", jobId.ToString("N"));
    }

    /// <summary>
    /// Returns the guest-output collection folder for one analysis.
    /// The input is a job ID, processing appends the guest segment, and the
    /// method returns the host directory path.
    /// </summary>
    public string BuildGuestOutputRoot(Guid jobId)
    {
        return Path.Combine(BuildJobRoot(jobId), "guest");
    }

    /// <summary>
    /// Returns a named artifact path under the job root.
    /// Inputs are a job ID and file name, processing strips directory segments
    /// from the file name, and the method returns the artifact path.
    /// </summary>
    public string BuildArtifactPath(Guid jobId, string fileName)
    {
        return Path.Combine(BuildJobRoot(jobId), Path.GetFileName(fileName));
    }

    /// <summary>
    /// Returns the canonical host artifact manifest path for one job.
    /// Inputs are a job ID, processing appends the reserved manifest file name
    /// to the job root, and the method returns the manifest path.
    /// </summary>
    public string BuildArtifactManifestPath(Guid jobId)
    {
        return BuildArtifactPath(jobId, "artifact-manifest.json");
    }
}
