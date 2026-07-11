namespace KSword.Sandbox.Core.Rules;

/// <summary>
/// Container for behavior rules loaded from JSON.
/// Inputs are deserialized rule documents, processing keeps version metadata,
/// and the value is returned to the rule engine.
/// </summary>
public sealed record BehaviorRuleSet
{
    public string Version { get; init; } = "1";

    public List<BehaviorRule> Rules { get; init; } = [];
}

/// <summary>
/// Declarative rule for matching normalized sandbox events.
/// Inputs are event type, exact data, and substring criteria; processing
/// performs case-insensitive matching, and matching rules return behavior
/// findings.
/// </summary>
public sealed record BehaviorRule
{
    public required string Id { get; init; }

    public required string Title { get; init; }

    public string Severity { get; init; } = "info";

    public string Confidence { get; init; } = "medium";

    public string Summary { get; init; } = string.Empty;

    public string? MitreTechniqueId { get; init; }

    public string? MitreTechniqueName { get; init; }

    public List<string> EventTypes { get; init; } = [];

    public List<string> ContainsPath { get; init; } = [];

    public List<string> ContainsCommandLine { get; init; } = [];

    public List<string> DataKeys { get; init; } = [];

    public Dictionary<string, List<string>> DataEquals { get; init; } = new(StringComparer.OrdinalIgnoreCase);

    public Dictionary<string, List<string>> DataContains { get; init; } = new(StringComparer.OrdinalIgnoreCase);

    public List<string> ExcludeProcessNames { get; init; } = [];

    public List<string> ExcludePathContains { get; init; } = [];

    public List<string> ExcludeCommandLineContains { get; init; } = [];

    public Dictionary<string, List<string>> ExcludeDataEquals { get; init; } = new(StringComparer.OrdinalIgnoreCase);

    public Dictionary<string, List<string>> ExcludeDataContains { get; init; } = new(StringComparer.OrdinalIgnoreCase);

    public List<string> EvidenceFields { get; init; } = [];

    public List<string> Tags { get; init; } = [];
}
