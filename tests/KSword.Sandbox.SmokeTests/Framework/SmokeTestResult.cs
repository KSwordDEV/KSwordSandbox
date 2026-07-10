namespace KSword.Sandbox.SmokeTests.Framework;

/// <summary>
/// Represents one smoke-test scenario outcome.
/// Inputs are scenario execution results; processing stores pass/fail state and
/// diagnostics; the record is returned to the console runner.
/// </summary>
internal sealed record SmokeTestResult
{
    public required string ScenarioId { get; init; }

    public bool Passed { get; init; }

    public string Message { get; init; } = string.Empty;

    public List<string> Artifacts { get; init; } = [];
}
