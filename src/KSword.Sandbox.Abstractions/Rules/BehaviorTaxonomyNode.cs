namespace KSword.Sandbox.Abstractions.Rules;

/// <summary>
/// Connects normalized event types to behavior categories and MITRE IDs.
/// Inputs are rule taxonomy entries, processing maps events to categories, and
/// the record is returned to classification and report layers.
/// </summary>
public sealed record BehaviorTaxonomyNode
{
    public string Id { get; init; } = string.Empty;

    public string Title { get; init; } = string.Empty;

    public string Category { get; init; } = string.Empty;

    public string? MitreTechniqueId { get; init; }

    public List<string> EventTypes { get; init; } = [];
}
