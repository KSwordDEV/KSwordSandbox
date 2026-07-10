using KSword.Sandbox.Abstractions.Rules;

namespace KSword.Sandbox.Core.Rules.Import;

/// <summary>
/// Carries imported taxonomy nodes plus parser diagnostics.
/// Inputs are parsed rule data and diagnostics, processing stores both
/// collections, and the record is returned by import services.
/// </summary>
public sealed record RuleImportResult
{
    public List<BehaviorTaxonomyNode> TaxonomyNodes { get; init; } = [];

    public List<RuleImportDiagnostic> Diagnostics { get; init; } = [];
}
