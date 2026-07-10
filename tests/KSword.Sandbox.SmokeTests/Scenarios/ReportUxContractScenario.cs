using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies that the HTML report renderer and UX documentation expose the
/// operator-facing sections needed for a live sandbox demo. Inputs are source
/// and docs files; processing performs static contract checks; the scenario
/// returns pass/fail metadata.
/// </summary>
internal sealed class ReportUxContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "report.ux.contract";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var rendererPath = Path.Combine(context.RepositoryRoot, "src", "KSword.Sandbox.Core", "Reporting", "HtmlReportRenderer.cs");
        var docPath = Path.Combine(context.RepositoryRoot, "docs", "report-ux.md");

        SmokeAssert.True(File.Exists(rendererPath), "HTML report renderer is missing.");
        SmokeAssert.True(File.Exists(docPath), "Report UX documentation is missing.");

        var renderer = File.ReadAllText(rendererPath);
        var doc = File.ReadAllText(docPath);

        RequireContains(renderer, "AppendTimeline", "Report renderer should include a timeline section.");
        RequireContains(renderer, "AppendProcessTree", "Report renderer should include a process tree.");
        RequireContains(renderer, "AppendRegistryBehavior", "Report renderer should include registry behavior.");
        RequireContains(renderer, "data-copy", "Report renderer should expose copyable evidence fields.");
        RequireContains(renderer, "contextmenu", "Report renderer should support right-click copy.");
        RequireContains(renderer, "Copy event", "Report renderer should provide explicit copy buttons.");
        RequireContains(renderer, "Raw normalized events", "Report renderer should include raw event evidence.");

        RequireContains(doc, "Timeline", "Report UX doc should list the timeline section.");
        RequireContains(doc, "Process tree", "Report UX doc should list the process tree.");
        RequireContains(doc, "Registry behavior", "Report UX doc should list registry behavior.");
        RequireContains(doc, "Right-click", "Report UX doc should describe right-click copy.");
        RequireContains(doc, "raw events only", "Report UX doc should distinguish live raw events from final classification.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Report UX sections and copyable evidence contracts are present."
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
