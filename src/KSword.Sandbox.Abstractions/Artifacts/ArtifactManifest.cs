namespace KSword.Sandbox.Abstractions.Artifacts;

/// <summary>
/// Indexes artifacts generated for a single job directory.
/// Inputs are produced by artifact storage, processing appends descriptors as
/// files appear, and the record is returned for WebUI artifact browsing.
/// </summary>
public sealed record ArtifactManifest
{
    public int SchemaVersion { get; init; } = 1;

    public Guid JobId { get; init; }

    public string RuntimeRoot { get; init; } = string.Empty;

    public string RootPath { get; init; } = string.Empty;

    public string ImportRoot { get; init; } = string.Empty;

    public string Producer { get; init; } = string.Empty;

    public DateTimeOffset GeneratedAtUtc { get; init; } = DateTimeOffset.UtcNow;

    public List<ArtifactCollectionDescriptor> Collections { get; init; } = [];

    public List<ArtifactDescriptor> Artifacts { get; init; } = [];
}
