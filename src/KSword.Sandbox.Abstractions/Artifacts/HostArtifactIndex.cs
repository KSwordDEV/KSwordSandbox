namespace KSword.Sandbox.Abstractions.Artifacts;

/// <summary>
/// Host-side index of files visible under one job artifact directory.
/// Inputs are descriptors discovered after report/guest collection; processing
/// records normalized paths and safe links; the record is serialized as
/// artifact-index.json for UI and report navigation.
/// </summary>
public sealed record HostArtifactIndex
{
    public int SchemaVersion { get; init; } = 1;

    public Guid JobId { get; init; }

    public string RootPath { get; init; } = string.Empty;

    public string Producer { get; init; } = "KSword.Sandbox.Core";

    public DateTimeOffset GeneratedAtUtc { get; init; } = DateTimeOffset.UtcNow;

    public List<ArtifactDescriptor> Artifacts { get; init; } = [];
}
