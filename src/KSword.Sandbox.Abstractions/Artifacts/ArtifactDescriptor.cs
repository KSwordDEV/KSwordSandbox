namespace KSword.Sandbox.Abstractions.Artifacts;

/// <summary>
/// Describes one host-visible artifact without loading its contents.
/// Inputs are filesystem metadata and optional hashes, processing stores only
/// durable identity fields, and the record is returned to UI and manifests.
/// </summary>
public sealed record ArtifactDescriptor
{
    public ArtifactKind Kind { get; init; } = ArtifactKind.Unknown;

    public string Category { get; init; } = string.Empty;

    public string Name { get; init; } = string.Empty;

    public string RelativePath { get; init; } = string.Empty;

    public string FullPath { get; init; } = string.Empty;

    public string SafeLink { get; init; } = string.Empty;

    public string EvidenceRole { get; init; } = string.Empty;

    public string CapturePhase { get; init; } = string.Empty;

    public string CaptureState { get; init; } = string.Empty;

    public string GuestPath { get; init; } = string.Empty;

    public string ImportPath { get; init; } = string.Empty;

    public string CollectionName { get; init; } = string.Empty;

    public string MimeType { get; init; } = string.Empty;

    public long SizeBytes { get; init; }

    public string? Sha256 { get; init; }

    public Dictionary<string, string> Hashes { get; init; } = new(StringComparer.OrdinalIgnoreCase);

    public DateTimeOffset CreatedAtUtc { get; init; } = DateTimeOffset.UtcNow;

    public Dictionary<string, string> Metadata { get; init; } = new(StringComparer.OrdinalIgnoreCase);
}
