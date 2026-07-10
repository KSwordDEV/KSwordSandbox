namespace KSword.Sandbox.SmokeTests.Framework;

/// <summary>
/// Carries repository and runtime paths for smoke-test scenarios.
/// Inputs are resolved by scripts or test entry points; processing stores path
/// metadata only; the record is returned to scenario classes.
/// </summary>
internal sealed record SmokeTestContext
{
    public required string RepositoryRoot { get; init; }

    public required string RuntimeRoot { get; init; }

    public string RulesDirectory => Path.Combine(RepositoryRoot, "rules");
}
