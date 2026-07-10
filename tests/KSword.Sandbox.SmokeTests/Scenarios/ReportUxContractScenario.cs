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
        var reportStagePath = Path.Combine(context.RepositoryRoot, "src", "KSword.Sandbox.Core", "Pipeline", "Stages", "ReportArtifactStage.cs");
        var analysisModelsPath = Path.Combine(context.RepositoryRoot, "src", "KSword.Sandbox.Abstractions", "AnalysisModels.cs");
        var docPath = Path.Combine(context.RepositoryRoot, "docs", "report-ux.md");

        SmokeAssert.True(File.Exists(rendererPath), "HTML report renderer is missing.");
        SmokeAssert.True(File.Exists(reportStagePath), "Report artifact stage is missing.");
        SmokeAssert.True(File.Exists(analysisModelsPath), "Analysis job model is missing.");
        SmokeAssert.True(File.Exists(docPath), "Report UX documentation is missing.");

        var renderer = File.ReadAllText(rendererPath);
        var reportStage = File.ReadAllText(reportStagePath);
        var analysisModels = File.ReadAllText(analysisModelsPath);
        var doc = File.ReadAllText(docPath);

        RequireContains(renderer, "AppendTimeline", "Report renderer should include a timeline section.");
        RequireContains(renderer, "AppendProcessTree", "Report renderer should include a process tree.");
        RequireContains(renderer, "AppendRegistryBehavior", "Report renderer should include registry behavior.");
        RequireContains(renderer, "data-copy", "Report renderer should expose copyable evidence fields.");
        RequireContains(renderer, "contextmenu", "Report renderer should support right-click copy.");
        RequireContains(renderer, "Copy event", "Report renderer should provide explicit copy buttons.");
        RequireContains(renderer, "Raw normalized events", "Report renderer should include raw event evidence.");
        RequireContains(renderer, "#43A0FF", "Report renderer should use the required primary accent color.");
        RequireAnyContains(
            renderer,
            ["modern sandbox report", "modern-sandbox-report", "report-shell", "dashboard"],
            "Report renderer should expose a modern sandbox report layout.");
        RequireContainsNormalized(renderer, "max-height:75vh", "Major report sections should be bounded to around 75vh.");
        RequireContainsNormalized(renderer, "overflow:auto", "Major report sections should scroll overflowing evidence.");
        RequireAnyContains(
            renderer,
            ["report.zh.html", "report.en.html", "RenderChinese", "RenderEnglish", "zh-CN", "en-US"],
            "Report renderer should support Chinese and English report rendering entrypoints.");
        RequireContains(renderer, "report.zh.html", "Report renderer should include the report.zh.html output clue.");
        RequireContains(renderer, "report.en.html", "Report renderer should include the report.en.html output clue.");
        RequireContains(renderer, "RenderBilingualReports", "Report renderer should provide a bilingual report generation entrypoint.");
        RequireContains(analysisModels, "HtmlReportZhPath", "Analysis job model should have a Chinese HTML report path for automatic report links.");
        RequireContains(analysisModels, "HtmlReportEnPath", "Analysis job model should have an English HTML report path for automatic report links.");
        RequireContains(reportStage, "report.artifacts.write", "Report stage should expose a stable progress stage id.");
        RequireContains(reportStage, "Write report artifacts", "Report stage should expose an operator-facing progress title.");
        RequireContains(reportStage, "report.html", "Report stage should keep writing the default report.html artifact.");

        RequireContains(doc, "Timeline", "Report UX doc should list the timeline section.");
        RequireContains(doc, "Process tree", "Report UX doc should list the process tree.");
        RequireContains(doc, "Registry behavior", "Report UX doc should list registry behavior.");
        RequireContains(doc, "Right-click", "Report UX doc should describe right-click copy.");
        RequireContains(doc, "raw events only", "Report UX doc should distinguish live raw events from final classification.");
        RequireContains(doc, "#43A0FF", "Report UX doc should specify the report primary accent color.");
        RequireContains(doc, "modern sandbox report layout", "Report UX doc should require the modern sandbox report layout.");
        RequireContains(doc, "75vh", "Report UX doc should specify bounded major report section height.");
        RequireContains(doc, "overflow:auto", "Report UX doc should specify scrolling major report sections.");
        RequireContains(doc, "Chinese and English", "Report UX doc should require Chinese and English report rendering support.");
        RequireContains(doc, "report.zh.html", "Report UX doc should mention report.zh.html.");
        RequireContains(doc, "report.en.html", "Report UX doc should mention report.en.html.");

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

    /// <summary>
    /// Requires one of several text fragments to be present. Inputs are content,
    /// expected alternatives, and failure message; processing throws on absence;
    /// return value is none.
    /// </summary>
    private static void RequireAnyContains(string content, IReadOnlyCollection<string> expectedAny, string message)
    {
        SmokeAssert.True(expectedAny.Any(expected => content.Contains(expected, StringComparison.Ordinal)), message);
    }

    /// <summary>
    /// Requires a CSS-like fragment to be present after whitespace removal.
    /// Inputs are content, expected normalized text, and failure message;
    /// processing throws on absence; return value is none.
    /// </summary>
    private static void RequireContainsNormalized(string content, string expected, string message)
    {
        var normalized = new string(content.Where(c => !char.IsWhiteSpace(c)).ToArray());
        SmokeAssert.True(normalized.Contains(expected, StringComparison.Ordinal), message);
    }
}
