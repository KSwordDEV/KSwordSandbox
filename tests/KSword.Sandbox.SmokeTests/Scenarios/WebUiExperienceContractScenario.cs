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
        var liveEventsPage = ReadRepositoryText(context, "src", "KSword.Sandbox.Web", "Dashboard", "LiveEventsPage.cs");
        var settingsPage = ReadRepositoryText(context, "src", "KSword.Sandbox.Web", "Dashboard", "SettingsPage.cs");
        var virusTotalLookup = ReadRepositoryText(context, "src", "KSword.Sandbox.Web", "Infrastructure", "VirusTotalLookupService.cs");
        var virusTotalSettings = ReadRepositoryText(context, "src", "KSword.Sandbox.Web", "Infrastructure", "VirusTotalSettingsStore.cs");
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
        var reportUxDoc = ReadRepositoryText(context, "docs", "report-ux.md");

        RequireContains(program, "DashboardExperiencePage.Render()", "Program.cs should route the root WebUI through the Dashboard layer.");
        RequireContains(program, "\"/jobs/{jobId:guid}/execution-flow\"", "Program.cs should expose a dedicated execution-flow route.");
        RequireContains(program, "RunbookExecutionFlowPage.Render", "Program.cs should expose a separate execution-flow page for runbook details.");
        RequireContains(program, "\"/api/jobs/{jobId:guid}/runbook/progress\"", "Program.cs should expose a UI-safe real runbook progress endpoint.");
        RequireContains(program, "RunbookProgressStore", "Program.cs should store executor progress snapshots for live WebUI polling.");
        RequireContains(program, "ProgressSink = new Progress<SandboxRunbookProgressSnapshot>", "Runbook execute endpoint should pass a real progress sink into the executor.");
        RequireContains(program, "\"/settings\"", "Program.cs should expose the local settings page.");
        RequireContains(program, "\"/api/settings/virustotal\"", "Program.cs should expose VirusTotal settings endpoints.");
        RequireContains(program, "\"/api/jobs/{jobId:guid}/virustotal\"", "Program.cs should expose per-job VirusTotal hash lookup.");
        RequireContains(program, "AddHttpClient<VirusTotalLookupService>", "Program.cs should register the VirusTotal lookup HTTP client.");

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
        RequireContains(dashboard, "上传 .exe → 自动分析并打开监控", "Upload flow should be labeled as one-click analysis plus monitor entry.");
        RequireContains(dashboard, "auto analyze and open monitor", "Upload flow should have an English one-click analysis plus monitor label.");
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
            ["Live raw event monitor", "Standalone live monitor", "实时监控独立页", "Standalone page: dynamic monitor", "独立页：动态监控"],
            "Dashboard should link to the dedicated live raw telemetry monitor / dynamic monitor.");
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
        RequireContains(dashboard, "data-report-current", "Dashboard should mark current-language report links for stable language switching.");
        RequireContains(dashboard, "refreshLocalizedReportLinks", "Dashboard should update current-language report links after the language toggle.");
        RequireContains(dashboard, "showReportReadyNotice", "Dashboard should show a stable report-ready notice after generation or import.");
        RequireContains(dashboard, "setTimeout(() => openReport(jobId)", "Dashboard should auto-open the current-language report after successful live analysis.");
        RequireContains(dashboard, "buildLiveMonitorHref", "Dashboard should build dynamic monitor links from the job id.");
        RequireContains(dashboard, "openLiveMonitor(String(jobId), true)", "Upload flow should automatically enter the dynamic monitor page after planning.");
        RequireContains(dashboard, "showLiveMonitorNotice", "Dashboard should render a bilingual fallback when automatic monitor opening is blocked.");
        RequireContains(dashboard, "window.open(href, '_blank')", "Automatic dynamic monitor entry should keep the dashboard tab alive by opening a separate tab.");
        RequireAnyContains(
            dashboard,
            ["Open served HTML report", "Open served report", "打开服务内报告"],
            "Dashboard should expose an automatic served HTML report link.");
        RequireAnyContains(
            dashboard,
            ["打开进度页（执行流程）", "Open progress page (execution flow)"],
            "Dashboard should expose a natural progress-page link beside job actions and progress.");
        RequireAnyContains(
            dashboard,
            ["进入动态监控页", "Enter dynamic monitor"],
            "Dashboard should expose a natural dynamic monitor page link.");
        RequireAnyContains(
            dashboard,
            ["stage-progress", "progressStages", "renderProgressStages", "Stage progress", "阶段进度"],
            "Dashboard should render operator-facing progress stages.");
        RequireContains(dashboard, "/runbook/progress", "Dashboard should poll the real runbook progress endpoint.");
        RequireContains(dashboard, "startRunbookProgressPolling", "Dashboard should start real runbook progress polling during execution.");
        RequireContains(dashboard, "renderRunbookProgress", "Dashboard should render exact executor runbook step progress.");
        RequireContains(dashboard, "不含命令行", "Dashboard should state that expanded runbook progress omits command lines.");
        RequireContains(dashboard, "executeRunbook(String(jobId), true)", "Upload flow should automatically start live VM analysis after planning.");
        RequireContains(dashboard, "href=\"/settings\"", "Dashboard should link to the settings page.");
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
        RequireNotContains(dashboard, "等待 PowerShell Direct 可用", "Dashboard stage text should avoid command-line transport details on the main page.");
        RequireNotContains(dashboard, "startLiveMonitor(jobId)", "Dashboard should not start the live raw monitor inline.");
        RequireNotContains(dashboard, "function renderLiveEventRows", "Dashboard should not render live raw event rows inline.");
        RequireNotContains(dashboard, "liveEventRows", "Dashboard should not own live raw event row containers.");
        RequireNotContains(dashboard, "new EventSource(url)", "Dashboard should leave raw SSE streaming to the dedicated monitor page.");
        RequireContains(executionFlow, "stdout/stderr", "Execution-flow page should document that command output is intentionally hidden from the main page.");
        RequireContains(executionFlow, "不展示命令行细节", "Execution-flow page should state that command-line details stay hidden from the main dashboard.");
        RequireContains(executionFlow, "Step status", "Execution-flow page should show human-readable step status.");
        RequireContains(dashboard, "copy-btn", "Dashboard should render explicit copy buttons.");
        RequireContains(dashboard, "data-copy", "Dashboard should mark paths and evidence as copyable.");
        RequireContains(dashboard, "contextmenu", "Dashboard should support right-click copy.");

        RequireContains(copyScript, "button.copy-btn[data-copy]", "Shared dashboard copy script should handle explicit copy buttons.");
        RequireContains(copyScript, "[data-copy], code, pre, td, th", "Shared dashboard copy script should support right-click table/path copying.");

        RequireContains(liveEventsPage, "/virustotal", "Live monitor should fetch the per-job VirusTotal lookup endpoint.");
        RequireContains(liveEventsPage, "VirusTotal 官方结果", "Live monitor should display a VirusTotal result card.");
        RequireContains(liveEventsPage, "不上传样本", "Live monitor should state that VirusTotal integration does not upload samples.");
        RequireContains(liveEventsPage, "如果此页由上传流程自动打开", "Live monitor should explain the automatic upload-flow opening behavior.");
        RequireContains(liveEventsPage, "keep the dashboard tab running analysis", "Live monitor should have an English hint to keep the dashboard request alive.");
        RequireContains(settingsPage, "VirusTotal API Key", "Settings page should allow operators to set the VirusTotal API key.");
        RequireContains(settingsPage, "/api/settings/virustotal", "Settings page should save VirusTotal settings through the API endpoint.");
        RequireContains(settingsPage, "不会提交到仓库", "Settings page should explain that local settings are not committed.");
        RequireContains(virusTotalSettings, "KSWORDBOX_VIRUSTOTAL_API_KEY", "VirusTotal settings should support an environment variable override.");
        RequireContains(virusTotalSettings, "virustotal.key", "VirusTotal settings should persist under the runtime settings folder.");
        RequireContains(virusTotalLookup, "https://www.virustotal.com/api/v3/", "VirusTotal lookup should call the official v3 API base URL.");
        RequireContains(virusTotalLookup, "files/{Uri.EscapeDataString(normalizedHash)}", "VirusTotal lookup should use the files/{hash} endpoint.");
        RequireContains(virusTotalLookup, "x-apikey", "VirusTotal lookup should authenticate with the x-apikey header.");
        RequireContains(virusTotalLookup, "not upload", "VirusTotal lookup code comments should document that it does not upload samples.");

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
        RequireRegex(doc, @"automatically opens the dedicated\s+dynamic monitor page", "WebUI framework doc should require automatic monitor entry after upload.");
        RequireContains(doc, "Enter dynamic monitor", "WebUI framework doc should require a fallback link when automatic monitor opening is blocked.");
        RequireContains(doc, "progress-page link", "WebUI framework doc should describe natural progress-page navigation.");
        RequireRegex(doc, @"current Chinese/English\s+dashboard language", "WebUI framework doc should describe current-language report links.");
        RequireContains(doc, "VM configuration fields", "WebUI framework doc should document VM configuration fields.");
        RequireContains(doc, "stage progress", "WebUI framework doc should document progress stages.");
        RequireContains(doc, "right-click", "WebUI framework doc should describe right-click copy.");
        RequireContains(doc, "driver-events.jsonl", "WebUI framework doc should describe driver event paths.");

        RequireContains(reportUxDoc, "automatic current-language report navigation", "Report UX doc should require automatic report page navigation.");
        RequireContains(reportUxDoc, "opened automatically by the upload flow", "Report UX doc should require upload-to-monitor navigation.");
        RequireContains(reportUxDoc, "leave the dashboard tab running the analysis request", "Report UX doc should explain why the dashboard tab must stay alive.");
        RequireContains(reportUxDoc, "progress-page", "Report UX doc should describe the progress page link.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "WebUI one-click upload, monitor/report/progress navigation, status/path, telemetry, runbook, guest import, and copy contracts are present."
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
