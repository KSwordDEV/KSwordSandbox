using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies that the repository keeps the expected high-level project layout.
/// Inputs are repository paths; processing checks important directories; the
/// scenario returns pass/fail metadata.
/// </summary>
internal sealed class RepositoryLayoutScenario : ISmokeTestScenario
{
    public string ScenarioId => "repository.layout";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        SmokeAssert.True(Directory.Exists(Path.Combine(context.RepositoryRoot, "src")), "src directory is missing.");
        SmokeAssert.True(Directory.Exists(Path.Combine(context.RepositoryRoot, "guest")), "guest directory is missing.");
        SmokeAssert.True(Directory.Exists(Path.Combine(context.RepositoryRoot, "driver")), "driver directory is missing.");
        SmokeAssert.True(Directory.Exists(context.RulesDirectory), "rules directory is missing.");

        return Task.FromResult(new SmokeTestResult { ScenarioId = ScenarioId, Passed = true, Message = "Repository layout is present." });
    }
}
