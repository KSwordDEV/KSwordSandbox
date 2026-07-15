using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Regression coverage for the WebUI main dashboard runbook summary. Inputs are
/// WebUI source files; processing checks that the root page stays a compact
/// status surface and sends full 1..N runbook review to the execution-flow page;
/// the scenario returns pass/fail metadata.
/// </summary>
internal sealed class WebUiDashboardRunbookRegressionScenario : ISmokeTestScenario
{
    public string ScenarioId => "webui.dashboard-runbook.regression";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var dashboard = ReadRepositoryText(context, "src", "KSword.Sandbox.Web", "Dashboard", "DashboardExperiencePage.cs");
        var executionFlow = ReadRepositoryText(context, "src", "KSword.Sandbox.Web", "Dashboard", "RunbookExecutionFlowPage.cs");

        RequireContains(
            dashboard,
            "buildProgressFocusSteps(steps, currentIndex, failed, done)",
            "Dashboard should derive a compact focused runbook-progress set for the main page.");
        RequireContains(
            dashboard,
            "return interesting.slice(-4);",
            "Dashboard main-page progress chips should be capped to a small focused set.");
        RequireContains(
            dashboard,
            "state === 'completed' || state === 'failed' || state === 'canceled'",
            "Dashboard background polling should treat cancellation as a terminal state.");
        RequireContains(
            dashboard,
            "/jobs/${encodeURIComponent(jobId)}/execution-flow",
            "Dashboard should route full runbook review to the dedicated execution-flow page.");
        RequireContains(
            executionFlow,
            "dashboard no longer expands all steps inline",
            "Execution-flow page should document that full runbook details are off the main dashboard.");
        RequireContains(
            dashboard,
            "not inline the 1~16 runbook steps, PowerShell, stdout, or stderr",
            "Dashboard source should explicitly document that the main page does not show the long 16-step runbook flow.");
        RequireContains(
            executionFlow,
            "主界面不再铺开 1~16 步",
            "Execution-flow page should tell operators the full 16-step flow is not expanded on the main dashboard.");

        RequireNotContains(
            dashboard,
            "const rows = steps.map(step => renderRunbookStepChip(step, currentIndex)).join('');",
            "Dashboard should not render every UI-safe runbook progress step into the main page.");
        RequireNotContains(
            dashboard,
            "<div class=\"runbook-step-grid\">${rows}</div>",
            "Dashboard should not include a full 1..N runbook step grid on the main page.");
        RequireNotContains(
            dashboard,
            "steps.map(step => renderRunbookStepChip",
            "Dashboard should not map the complete runbook step collection into main-page DOM.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "WebUI dashboard runbook progress remains compact and full step review stays on execution-flow page."
        });
    }

    /// <summary>
    /// Reads a repository file as text.
    /// </summary>
    private static string ReadRepositoryText(SmokeTestContext context, params string[] relativeSegments)
    {
        var allSegments = new string[relativeSegments.Length + 1];
        allSegments[0] = context.RepositoryRoot;
        relativeSegments.CopyTo(allSegments, 1);
        var path = Path.Combine(allSegments);
        return File.ReadAllText(path);
    }

    /// <summary>
    /// Requires a literal value to be present.
    /// </summary>
    private static void RequireContains(string content, string expected, string message)
    {
        SmokeAssert.True(content.Contains(expected, StringComparison.Ordinal), message);
    }

    /// <summary>
    /// Requires a literal value to be absent.
    /// </summary>
    private static void RequireNotContains(string content, string forbidden, string message)
    {
        SmokeAssert.True(!content.Contains(forbidden, StringComparison.Ordinal), message);
    }
}
