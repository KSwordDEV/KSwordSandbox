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
        RequireContains(script, "$output = @(& powershell.exe @argumentList 2>&1)", "Full validation should capture child PowerShell output separately from exit code.");
        RequireContains(script, "return $exitCode", "Full validation should return only the child process exit code from Invoke-PowerShellFile.");
        RequireContains(script, "Test-LiveTelemetryFramework.ps1", "Full validation should include the live telemetry contract gate.");
        RequireContains(script, "-ContractOnly", "Full validation should run live telemetry in non-mutating contract-only mode.");
        RequireContains(script, "-RequireImplementedStream", "Full validation should require the implemented SSE stream route.");
        RequireContains(script, "Invoke-LocalPipelineSmoke.ps1", "Full validation should include the local WebUI/API pipeline smoke.");
        RequireContains(script, "local WebUI/API pipeline smoke", "Full validation should name the local pipeline smoke gate.");
        RequireContains(script, "SkipLocalPipelineSmoke", "Full validation should allow skipping the local pipeline smoke when needed.");
        RequireContains(script, "Invoke-HyperVE2E.ps1", "Full validation should include the Hyper-V E2E script contract.");
        RequireContains(script, "Hyper-V E2E PlanOnly contract", "Full validation should name the safe Hyper-V PlanOnly gate.");
        RequireContains(script, "sandbox.planonly.json", "Full validation should use a temporary Hyper-V PlanOnly config.");
        RequireContains(script, "-ConfigPath", "Full validation should pass the temporary PlanOnly config to Hyper-V E2E.");
        RequireContains(script, "$config.paths.runtimeRoot", "Full validation should redirect Hyper-V PlanOnly runtime artifacts outside the repo.");
        RequireContains(script, "-PlanOnly", "Full validation should exercise Hyper-V E2E plan-only mode.");
        RequireContains(script, "-WhatIf", "Full validation should exercise Hyper-V E2E WhatIf safety.");
        RequireContains(script, "Remove-Item -LiteralPath $contractRoot -Recurse -Force", "Full validation should clean up temporary Hyper-V PlanOnly artifacts.");
        RequireContains(script, "SkipNative", "Full validation should allow skipping native build when needed.");
        RequireContains(script, "StagedPolicyOnly", "Full validation should support staged-only policy checks.");

        RequireContains(progress, "Overall v1 deliverable", "Progress doc should include overall progress.");
        RequireContains(progress, "Remaining P0 gaps", "Progress doc should list remaining P0 gaps.");
        RequireContains(progress, "R0 Driver + R0Collector", "Progress doc should track R0 progress.");
        RequireContains(progress, "Hyper-V", "Progress doc should track Hyper-V progress.");
        RequireContains(progress, "local WebUI/API pipeline smoke", "Progress doc should mention the local WebUI/API smoke gate.");

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
