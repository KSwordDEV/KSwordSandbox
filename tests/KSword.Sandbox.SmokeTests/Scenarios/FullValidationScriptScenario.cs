using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies that the repository has a single operator-facing validation entry
/// point. Inputs are script and progress docs; processing checks command
/// coverage; the scenario returns pass/fail metadata.
/// </summary>
internal sealed class FullValidationScriptScenario : ISmokeTestScenario
{
    public string ScenarioId => "validation.full-script.contract";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var scriptPath = Path.Combine(context.RepositoryRoot, "scripts", "Invoke-FullValidation.ps1");
        var progressPath = Path.Combine(context.RepositoryRoot, "docs", "progress.md");
        SmokeAssert.True(File.Exists(scriptPath), "Invoke-FullValidation.ps1 is missing.");
        SmokeAssert.True(File.Exists(progressPath), "docs/progress.md is missing.");

        var script = File.ReadAllText(scriptPath);
        var progress = File.ReadAllText(progressPath);

        RequireContains(script, "dotnet build", "Full validation should run dotnet build.");
        RequireContains(script, "KSword.Sandbox.SmokeTests", "Full validation should run smoke tests.");
        RequireContains(script, "Invoke-NativeBuild.ps1", "Full validation should run native build.");
        RequireContains(script, "Test-RepositoryPolicy.ps1", "Full validation should run repository policy.");
        RequireContains(script, "Test-HyperVReadiness.ps1", "Full validation should include Hyper-V readiness.");
        RequireContains(script, "Test-R0Readiness.ps1", "Full validation should include R0 readiness.");
        RequireContains(script, "SkipNative", "Full validation should allow skipping native build when needed.");
        RequireContains(script, "StagedPolicyOnly", "Full validation should support staged-only policy checks.");

        RequireContains(progress, "Overall v1 deliverable", "Progress doc should include overall progress.");
        RequireContains(progress, "Remaining P0 gaps", "Progress doc should list remaining P0 gaps.");
        RequireContains(progress, "R0 Driver + R0Collector", "Progress doc should track R0 progress.");
        RequireContains(progress, "Hyper-V", "Progress doc should track Hyper-V progress.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Full validation script and conservative progress document are present."
        });
    }

    /// <summary>
    /// Requires a text fragment to be present. Inputs are content, expected
    /// text, and failure message; processing throws on absence; return value is
    /// none.
    /// </summary>
    private static void RequireContains(string content, string expected, string message)
    {
        SmokeAssert.True(content.Contains(expected, StringComparison.Ordinal), message);
    }
}
