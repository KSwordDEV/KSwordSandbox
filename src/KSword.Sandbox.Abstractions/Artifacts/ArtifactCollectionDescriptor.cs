namespace KSword.Sandbox.Abstractions.Artifacts;

/// <summary>
/// Describes an artifact collection lane even when no file was produced.
/// Inputs are producer capabilities and operator-selected options; processing
/// serializes this plan into manifests so host importers can distinguish
/// disabled, skipped, unavailable, and future-placeholder evidence.
/// </summary>
public sealed record ArtifactCollectionDescriptor
{
    public string Name { get; init; } = string.Empty;

    public ArtifactKind Kind { get; init; } = ArtifactKind.Unknown;

    public string Category { get; init; } = string.Empty;

    public string EvidenceRole { get; init; } = string.Empty;

    public string RelativePath { get; init; } = string.Empty;

    public string SafeLink { get; init; } = string.Empty;

    public string ImportPath { get; init; } = string.Empty;

    public bool Enabled { get; init; }

    public bool Implemented { get; init; } = true;

    public string Status { get; init; } = "disabled";

    public string Reason { get; init; } = string.Empty;

    public Dictionary<string, string> Metadata { get; init; } = new(StringComparer.OrdinalIgnoreCase);
}
