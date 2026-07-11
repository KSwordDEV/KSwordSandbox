namespace KSword.Sandbox.Abstractions.Artifacts;

/// <summary>
/// Host-side index of files visible under one job artifact directory.
/// Inputs are descriptors discovered after report/guest collection; processing
/// records normalized paths, safe links, and discovered collection lanes; the
/// record is serialized as artifact-index.json for UI and report navigation.
/// </summary>
public sealed record HostArtifactIndex
{
    public int SchemaVersion { get; init; } = 1;

    public Guid JobId { get; init; }

    public string RootPath { get; init; } = string.Empty;

    public string Producer { get; init; } = "KSword.Sandbox.Core";

    public string RootPathPolicy { get; init; } = "server-owned-not-exposed-in-web-api";

    public string DownloadPolicy { get; init; } = "relative-index-selectors-only";

    public int CollectionCount { get; init; }

    public int ArtifactCount { get; init; }

    public int DownloadableArtifactCount { get; init; }

    public int SensitiveArtifactCount { get; init; }

    public int DuplicateArtifactCount { get; init; }

    public int RejectedArtifactCount { get; init; }

    public DateTimeOffset GeneratedAtUtc { get; init; } = DateTimeOffset.UtcNow;

    public List<ArtifactCollectionDescriptor> Collections { get; init; } = [];

    public List<ArtifactDescriptor> Artifacts { get; init; } = [];
}
