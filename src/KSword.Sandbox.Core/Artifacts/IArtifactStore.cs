using KSword.Sandbox.Abstractions.Artifacts;

namespace KSword.Sandbox.Core.Artifacts;

/// <summary>
/// Defines durable artifact storage for host-side reports and runbooks.
/// Inputs are job IDs, artifact names, and content; processing is implemented
/// by storage adapters; methods return descriptors or loaded text.
/// </summary>
public interface IArtifactStore
{
    /// <summary>
    /// Writes text content as a named artifact.
    /// Inputs are job ID, artifact name, kind, and content; processing persists
    /// data; the method returns the descriptor for the stored artifact.
    /// </summary>
    Task<ArtifactDescriptor> WriteTextAsync(Guid jobId, string name, ArtifactKind kind, string content, CancellationToken cancellationToken = default);

    /// <summary>
    /// Writes an artifact manifest for a job.
    /// Inputs are job ID and a manifest model, processing serializes the
    /// manifest beside other job artifacts, and the method returns the manifest
    /// descriptor.
    /// </summary>
    Task<ArtifactDescriptor> WriteManifestAsync(Guid jobId, ArtifactManifest manifest, CancellationToken cancellationToken = default);

    /// <summary>
    /// Reads a text artifact by path.
    /// The input is a descriptor, processing opens the referenced file, and the
    /// method returns text content.
    /// </summary>
    Task<string> ReadTextAsync(ArtifactDescriptor descriptor, CancellationToken cancellationToken = default);

    /// <summary>
    /// Reads an artifact manifest by path.
    /// The input is a descriptor, processing deserializes JSON, and the method
    /// returns the manifest model.
    /// </summary>
    Task<ArtifactManifest> ReadManifestAsync(ArtifactDescriptor descriptor, CancellationToken cancellationToken = default);
}
