using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies the static WebUI experience contract without starting the Web host
/// or a VM. Inputs are repository paths from SmokeTestContext; processing reads
/// dashboard, contract, and documentation files for required status, path,
/// telemetry, runbook, and copy affordances; the scenario returns pass/fail
/// metadata.
/// </summary>
internal sealed class WebUiExperienceContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "webui.experience.contract";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var program = ReadRepositoryText(context, "src", "KSword.Sandbox.Web", "Program.cs");
        var dashboard = ReadRepositoryText(context, "src", "KSword.Sandbox.Web", "Dashboard", "DashboardExperiencePage.cs");
        var copyScript = ReadRepositoryText(context, "src", "KSword.Sandbox.Web", "Dashboard", "DashboardClientScripts.cs");
        var executionFlow = ReadRepositoryText(context, "src", "KSword.Sandbox.Web", "Dashboard", "RunbookExecutionFlowPage.cs");
        var artifactContract = ReadRepositoryText(context, "src", "KSword.Sandbox.Web", "Contracts", "JobArtifactPathsContract.cs");
        var importContract = ReadRepositoryText(context, "src", "KSword.Sandbox.Web", "Contracts", "GuestImportStatusContract.cs");
        var stepContract = ReadRepositoryText(context, "src", "KSword.Sandbox.Web", "Contracts", "RunbookStepExecutionContract.cs");
        var doc = ReadRepositoryText(context, "docs", "webui-framework.md");

        RequireContains(program, "DashboardExperiencePage.Render()", "Program.cs should route the root WebUI through the Dashboard layer.");
        RequireContains(program, "\"/jobs/{jobId:guid}/execution-flow\"", "Program.cs should expose a dedicated execution-flow route.");
        RequireContains(program, "RunbookExecutionFlowPage.Render", "Program.cs should expose a separate execution-flow page for runbook details.");

        RequireContains(dashboard, "<html lang=\"zh-CN\">", "Dashboard should default to Chinese.");
        RequireContains(dashboard, "onclick=\"toggleLanguage()\"", "Dashboard should expose the top-right Chinese/English switch.");
        RequireContains(dashboard, "data-zh=\"English\" data-en=\"中文\"", "Language switch should toggle between Chinese and English labels.");
        RequireContains(dashboard, "Upload .exe", "Dashboard should clarify upload-and-plan entry text.");
        RequireContains(dashboard, "Create dry-run plan from path", "Dashboard should clarify host-path planning.");
        RequireContains(dashboard, "Scan and plan first candidate", "Dashboard should expose one-click scan-and-plan.");
        RequireContains(dashboard, "Guest import status", "Dashboard should display guest import status.");
        RequireContains(dashboard, "Live raw event monitor", "Dashboard should include a live raw telemetry area.");
        RequireContains(dashboard, "report.json", "Dashboard should display report.json path.");
        RequireContains(dashboard, "report.html", "Dashboard should display report.html path.");
        RequireContains(dashboard, "events.json", "Dashboard should display events.json path.");
        RequireContains(dashboard, "driver-events.jsonl", "Dashboard should display driver-events.jsonl path.");
        RequireContains(dashboard, "runbook-execution.json", "Dashboard should display runbook execution result path.");
        RequireContains(dashboard, "执行流程", "Dashboard should link to the separate execution-flow page instead of rendering all steps inline.");
        RequireContains(dashboard, "formatJobStatus", "Dashboard should translate numeric enum status values into readable labels.");
        RequireContains(dashboard, """<div id="jobResult" class="hint"><span""", "Dashboard dynamic job container should not be directly translated and wiped after renderJob.");
        RequireContains(dashboard, "element.id === 'jobResult'", "Dashboard language switching should skip dynamic job containers.");
        RequireNotContains(dashboard, "<ol>${steps}</ol>", "Dashboard should not render all planned runbook steps inline.");
        RequireNotContains(dashboard, "planned runbook PowerShell", "Dashboard should not expose planned PowerShell commands on the main page.");
        RequireNotContains(dashboard, "step.standardOutput", "Dashboard should not render runbook stdout inline on the main page.");
        RequireNotContains(dashboard, "step.standardError", "Dashboard should not render runbook stderr inline on the main page.");
        RequireContains(executionFlow, "stdout/stderr", "Execution-flow page should document that command output is intentionally hidden from the main page.");
        RequireContains(executionFlow, "Step status", "Execution-flow page should show human-readable step status.");
        RequireContains(dashboard, "copy-btn", "Dashboard should render explicit copy buttons.");
        RequireContains(dashboard, "data-copy", "Dashboard should mark paths and evidence as copyable.");
        RequireContains(dashboard, "contextmenu", "Dashboard should support right-click copy.");

        RequireContains(copyScript, "button.copy-btn[data-copy]", "Shared dashboard copy script should handle explicit copy buttons.");
        RequireContains(copyScript, "[data-copy], code, pre, td, th", "Shared dashboard copy script should support right-click table/path copying.");

        RequireContains(artifactContract, "ReportJsonPath", "Artifact contract should include report.json.");
        RequireContains(artifactContract, "ReportHtmlPath", "Artifact contract should include report.html.");
        RequireContains(artifactContract, "EventsJsonPath", "Artifact contract should include events.json.");
        RequireContains(artifactContract, "DriverEventsJsonlPath", "Artifact contract should include driver-events.jsonl.");
        RequireContains(importContract, "GuestImportStatusContract", "Guest import status contract should exist.");
        RequireContains(stepContract, "StandardOutput", "Runbook step contract should preserve stdout.");
        RequireContains(stepContract, "StandardError", "Runbook step contract should preserve stderr.");
        RequireContains(stepContract, "ExitCode", "Runbook step contract should preserve exit code.");
        RequireContains(stepContract, "Duration", "Runbook step contract should preserve duration.");

        RequireContains(doc, "WebUI experience contract", "WebUI framework doc should describe the experience contract.");
        RequireContains(doc, "right-click", "WebUI framework doc should describe right-click copy.");
        RequireContains(doc, "driver-events.jsonl", "WebUI framework doc should describe driver event paths.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "WebUI one-click, status/path, telemetry, runbook, guest import, and copy contracts are present."
        });
    }


    /// <summary>
    /// Requires that a text block does not contain a literal value.
    /// Inputs are text, forbidden literal, and assertion message; processing
    /// uses ordinal substring matching; the method returns no value on success.
    /// </summary>
    private static void RequireNotContains(string content, string forbidden, string message)
    {
        SmokeAssert.True(!content.Contains(forbidden, StringComparison.Ordinal), message);
    }

    /// <summary>
    /// Reads a repository file as text.
    /// Inputs are the smoke context and relative path segments; processing joins
    /// the path under RepositoryRoot and reads the file; the method returns the
    /// complete file text.
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
    /// Requires that a text block contains a literal value.
    /// Inputs are text, expected literal, and assertion message; processing uses
    /// ordinal substring matching; the method returns no value on success.
    /// </summary>
    private static void RequireContains(string content, string expected, string message)
    {
        SmokeAssert.True(content.Contains(expected, StringComparison.Ordinal), message);
    }
}
