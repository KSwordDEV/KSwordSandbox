using System.Text.RegularExpressions;
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
        var submissionModel = ReadRepositoryText(context, "src", "KSword.Sandbox.Abstractions", "AnalysisModels.cs");
        var jobService = ReadRepositoryText(context, "src", "KSword.Sandbox.Core", "Jobs", "SandboxJobService.cs");
        var stageDescriptor = ReadRepositoryText(context, "src", "KSword.Sandbox.Abstractions", "Pipeline", "AnalysisStageDescriptor.cs");
        var timelineEntry = ReadRepositoryText(context, "src", "KSword.Sandbox.Abstractions", "Pipeline", "AnalysisTimelineEntry.cs");
        var doc = ReadRepositoryText(context, "docs", "webui-framework.md");

        RequireContains(program, "DashboardExperiencePage.Render()", "Program.cs should route the root WebUI through the Dashboard layer.");
        RequireContains(program, "\"/jobs/{jobId:guid}/execution-flow\"", "Program.cs should expose a dedicated execution-flow route.");
        RequireContains(program, "RunbookExecutionFlowPage.Render", "Program.cs should expose a separate execution-flow page for runbook details.");

        RequireContains(dashboard, "<html lang=\"zh-CN\">", "Dashboard should default to Chinese.");
        RequireContains(dashboard, "onclick=\"toggleLanguage()\"", "Dashboard should expose the top-right Chinese/English switch.");
        RequireContains(dashboard, "data-zh=\"English\" data-en=\"中文\"", "Language switch should toggle between Chinese and English labels.");
        RequireContains(dashboard, "role=\"tablist\"", "Planning entries should be separated by an accessible tablist.");
        RequireMinimumCount(dashboard, "role=\"tab\"", 3, "Planning UI should expose three accessible tabs.");
        RequireMinimumCount(dashboard, "role=\"tabpanel\"", 3, "Planning UI should expose one tab panel per planning entry.");
        RequireRegex(
            dashboard,
            @"(?is)(aria-selected=""true""[^>]*(upload|上传|sampleUpload)|(?:upload|上传|sampleUpload)[^>]*aria-selected=""true"")",
            "The upload planning tab should be selected by default.");
        RequireContains(dashboard, "Upload .exe", "Dashboard should clarify upload-and-plan entry text.");
        RequireAnyContains(
            dashboard,
            ["Create dry-run plan from path", "Create plan from path"],
            "Dashboard should clarify host-path planning.");
        RequireContains(dashboard, "Scan and plan first candidate", "Dashboard should expose one-click scan-and-plan.");
        foreach (var vmField in new[]
        {
            "goldenVmName",
            "goldenSnapshotName",
            "guestUserName",
            "guestWorkingDirectory",
            "guestPayloadRoot",
            "useMockCollector"
        })
        {
            RequireContains(dashboard, vmField, $"Dashboard should render and submit VM configuration field '{vmField}'.");
        }

        RequireAnyContains(
            dashboard,
            ["Guest import status", "Event import status", "事件导入状态"],
            "Dashboard should display guest import status.");
        RequireAnyContains(
            dashboard,
            ["Live raw event monitor", "Standalone live monitor", "实时监控独立页"],
            "Dashboard should link to the dedicated live raw telemetry monitor.");
        RequireAnyContains(
            program,
            ["LiveEventsPage.Render", "LiveRawEventMonitorPage.Render", "RawEventMonitorPage.Render", "LiveEventMonitorPage.Render"],
            "Program.cs should route a dedicated live raw telemetry monitor page.");
        RequireRegex(
            program,
            @"MapGet\(""/jobs/\{jobId:guid\}/[^""]*(?:live|raw)[^""]*""",
            "Program.cs should expose a non-API job-scoped live raw monitor page route.");
        RequireAnyContains(
            dashboard,
            ["liveEventsHref", "liveMonitorHref", "rawMonitorHref", "eventMonitorHref"],
            "Dashboard should build a dedicated live raw monitor page link instead of rendering the monitor inline.");
        RequireContains(dashboard, "report.json", "Dashboard should display report.json path.");
        RequireContains(dashboard, "report.html", "Dashboard should display report.html path.");
        RequireContains(dashboard, "renderJob(payload)", "Planning responses should automatically render job report links.");
        RequireContains(dashboard, "servedReportHref", "Dashboard should build the served report link automatically from the planned job id.");
        RequireAnyContains(
            dashboard,
            ["Open served HTML report", "Open served report", "打开服务内报告"],
            "Dashboard should expose an automatic served HTML report link.");
        RequireAnyContains(
            dashboard,
            ["stage-progress", "progressStages", "renderProgressStages", "Stage progress", "阶段进度"],
            "Dashboard should render operator-facing progress stages.");
        RequireContains(dashboard, "events.json", "Dashboard should display events.json path.");
        RequireContains(dashboard, "driver-events.jsonl", "Dashboard should display driver-events.jsonl path.");
        RequireContains(dashboard, "runbook-execution.json", "Dashboard should display runbook execution result path.");
        RequireContains(dashboard, "执行流程", "Dashboard should link to the separate execution-flow page instead of rendering all steps inline.");
        RequireContains(dashboard, "formatJobStatus", "Dashboard should translate numeric enum status values into readable labels.");
        RequireContains(dashboard, """<div id="jobResult" class="hint"><span""", "Dashboard dynamic job container should not be directly translated and wiped after renderJob.");
        RequireContains(dashboard, "element.id === 'jobResult'", "Dashboard language switching should skip dynamic job containers.");
        RequireNotContains(dashboard, "<ol>${steps}</ol>", "Dashboard should not render all planned runbook steps inline.");
        RequireNotContains(dashboard, "planned runbook PowerShell", "Dashboard should not expose planned PowerShell commands on the main page.");
        RequireNotContains(dashboard, "runbook-output", "Dashboard should not render runbook command/output blocks on the main page.");
        RequireNotContains(dashboard, "step.powerShell", "Dashboard should not render planned PowerShell text on the main page.");
        RequireNotContains(dashboard, "result.powerShell", "Dashboard should not render executed PowerShell text on the main page.");
        RequireNotContains(dashboard, "standardOutput", "Dashboard should not render runbook stdout on the main page.");
        RequireNotContains(dashboard, "standardError", "Dashboard should not render runbook stderr on the main page.");
        RequireNotContains(dashboard, "step.standardOutput", "Dashboard should not render runbook stdout inline on the main page.");
        RequireNotContains(dashboard, "step.standardError", "Dashboard should not render runbook stderr inline on the main page.");
        RequireNotContains(dashboard, "startLiveMonitor(jobId)", "Dashboard should not start the live raw monitor inline.");
        RequireNotContains(dashboard, "function renderLiveEventRows", "Dashboard should not render live raw event rows inline.");
        RequireNotContains(dashboard, "liveEventRows", "Dashboard should not own live raw event row containers.");
        RequireNotContains(dashboard, "new EventSource(url)", "Dashboard should leave raw SSE streaming to the dedicated monitor page.");
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
        foreach (var vmProperty in new[]
        {
            "GoldenVmName",
            "GoldenSnapshotName",
            "GuestUserName",
            "GuestWorkingDirectory",
            "GuestPayloadRoot",
            "UseMockCollector"
        })
        {
            RequireContains(submissionModel, vmProperty, $"Submission contract should carry VM configuration property '{vmProperty}'.");
            RequireContains(jobService, vmProperty, $"Job service should preserve VM configuration property '{vmProperty}' during planning.");
        }

        RequireContains(stageDescriptor, "StageId", "Progress stage descriptor should expose a stable stage id.");
        RequireContains(stageDescriptor, "Title", "Progress stage descriptor should expose an operator-facing title.");
        RequireContains(stageDescriptor, "Order", "Progress stage descriptor should expose deterministic order.");
        RequireContains(timelineEntry, "AnalysisStageStatus", "Progress timeline should expose per-stage status.");
        RequireContains(timelineEntry, "StartedAtUtc", "Progress timeline should expose stage start time.");
        RequireContains(timelineEntry, "FinishedAtUtc", "Progress timeline should expose stage finish time.");

        RequireContains(doc, "WebUI experience contract", "WebUI framework doc should describe the experience contract.");
        RequireContains(doc, "default selected tab", "WebUI framework doc should require the upload tab as the default planning tab.");
        RequireContains(doc, "dedicated live raw monitor page", "WebUI framework doc should require live raw telemetry on a separate page.");
        RequireContains(doc, "VM configuration fields", "WebUI framework doc should document VM configuration fields.");
        RequireContains(doc, "stage progress", "WebUI framework doc should document progress stages.");
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
    /// Requires that a text block contains at least one of several literals.
    /// Inputs are text, alternatives, and assertion message; processing uses
    /// ordinal substring matching; the method returns no value on success.
    /// </summary>
    private static void RequireAnyContains(string content, IReadOnlyCollection<string> expectedAny, string message)
    {
        SmokeAssert.True(expectedAny.Any(expected => content.Contains(expected, StringComparison.Ordinal)), message);
    }

    /// <summary>
    /// Requires a minimum literal occurrence count.
    /// Inputs are content, literal, count, and message; processing uses ordinal
    /// scanning; the method returns no value on success.
    /// </summary>
    private static void RequireMinimumCount(string content, string expected, int minimumCount, string message)
    {
        var count = 0;
        var index = 0;
        while (index < content.Length)
        {
            var found = content.IndexOf(expected, index, StringComparison.Ordinal);
            if (found < 0)
            {
                break;
            }

            count++;
            index = found + expected.Length;
        }

        SmokeAssert.True(count >= minimumCount, $"{message} Found {count}, expected at least {minimumCount}.");
    }

    /// <summary>
    /// Requires that a regular expression match a text block.
    /// Inputs are text, regex pattern, and assertion message; processing uses
    /// invariant ignore-case matching; the method returns no value on success.
    /// </summary>
    private static void RequireRegex(string content, string pattern, string message)
    {
        SmokeAssert.True(Regex.IsMatch(content, pattern, RegexOptions.CultureInvariant | RegexOptions.IgnoreCase), message);
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
