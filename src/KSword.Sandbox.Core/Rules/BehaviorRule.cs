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
/// Inclusive numeric range predicate for rule data fields.
/// Inputs are optional minimum/maximum bounds, processing compares parsed
/// invariant-culture doubles, and the value is used by behavior rules.
/// </summary>
public sealed record BehaviorRuleNumericRange
{
    public double? Min { get; init; }

    public double? Max { get; init; }

    public bool ExclusiveMin { get; init; }

    public bool ExclusiveMax { get; init; }
}

/// <summary>
/// Declarative rule for matching normalized sandbox events.
/// Inputs are event type, exact data, regex, numeric-range, existence,
/// all-of, and substring criteria; processing performs deterministic
/// case-insensitive matching, and matching rules return behavior findings.
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

    public List<string> AllContainsPath { get; init; } = [];

    public List<string> PathRegex { get; init; } = [];

    public List<string> ContainsCommandLine { get; init; } = [];

    public List<string> AllContainsCommandLine { get; init; } = [];

    public List<string> CommandLineRegex { get; init; } = [];

    public List<string> DataKeys { get; init; } = [];

    public List<string> AllDataKeys { get; init; } = [];

    public List<string> AbsentDataKeys { get; init; } = [];

    public Dictionary<string, List<string>> DataEquals { get; init; } = new(StringComparer.OrdinalIgnoreCase);

    public Dictionary<string, List<string>> AllDataEquals { get; init; } = new(StringComparer.OrdinalIgnoreCase);

    public Dictionary<string, List<string>> DataContains { get; init; } = new(StringComparer.OrdinalIgnoreCase);

    public Dictionary<string, List<string>> AllDataContains { get; init; } = new(StringComparer.OrdinalIgnoreCase);

    public Dictionary<string, List<string>> DataContainsAll { get; init; } = new(StringComparer.OrdinalIgnoreCase);

    public Dictionary<string, List<string>> DataRegex { get; init; } = new(StringComparer.OrdinalIgnoreCase);

    public Dictionary<string, List<string>> AllDataRegex { get; init; } = new(StringComparer.OrdinalIgnoreCase);

    public Dictionary<string, List<BehaviorRuleNumericRange>> DataNumericRanges { get; init; } = new(StringComparer.OrdinalIgnoreCase);

    public Dictionary<string, List<BehaviorRuleNumericRange>> AllDataNumericRanges { get; init; } = new(StringComparer.OrdinalIgnoreCase);

    public List<string> ExcludeProcessNames { get; init; } = [];

    public List<string> ExcludePathContains { get; init; } = [];

    public List<string> ExcludeCommandLineContains { get; init; } = [];

    public Dictionary<string, List<string>> ExcludeDataEquals { get; init; } = new(StringComparer.OrdinalIgnoreCase);

    public Dictionary<string, List<string>> ExcludeDataContains { get; init; } = new(StringComparer.OrdinalIgnoreCase);

    public bool IncludeNonBehaviorEvidence { get; init; }

    public List<string> EvidenceFields { get; init; } = [];

    public List<string> Tags { get; init; } = [];
}
