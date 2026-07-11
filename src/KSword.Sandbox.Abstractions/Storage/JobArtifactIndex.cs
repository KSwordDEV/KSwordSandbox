using KSword.Sandbox.Abstractions.Artifacts;

namespace KSword.Sandbox.Abstractions.Storage;

/// <summary>
/// Stores the current artifact index for one analysis job.
/// Inputs are artifact descriptors discovered by storage code, processing
/// records update time, and the record is returned by future artifact APIs.
/// </summary>
public sealed record JobArtifactIndex
{
    public int SchemaVersion { get; init; } = 1;

    public Guid JobId { get; init; }

    public DateTimeOffset UpdatedAtUtc { get; init; } = DateTimeOffset.UtcNow;

    public List<ArtifactCollectionDescriptor> Collections { get; init; } = [];

    public List<ArtifactDescriptor> Artifacts { get; init; } = [];
}
