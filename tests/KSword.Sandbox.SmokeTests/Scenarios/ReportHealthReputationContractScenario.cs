using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Reporting;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies that collection-health and reputation-status evidence stays out of
/// the primary malicious-behavior lane. Inputs are behavior rules plus the HTML
/// renderer; processing classifies synthetic R0 unavailable and VT not-found /
/// rate-limit rows, renders a report, and checks that operators see them as
/// collection/reputation status rather than sample behavior.
/// </summary>
internal sealed class ReportHealthReputationContractScenario : ISmokeTestScenario
{
    private static readonly string[] DiagnosticRuleIds =
    [
        "virustotal-not-found",
        "virustotal-rate-limited"
    ];

    public string ScenarioId => "report.health-reputation.contract";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var rules = RuleEngine.LoadRuleSet(Path.Combine(context.RulesDirectory, "behavior-rules.json"));
        var events = BuildContractEvents();
        var findings = new RuleEngine(rules).Classify(events);
        AssertDiagnosticRuleContracts(findings);
        AssertRendererSourceContracts(context);
        AssertRenderedReportContracts(events, findings);

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "R0 unavailable and VT not-found/rate-limit evidence remain diagnostics/reputation status, not primary malicious behavior."
        });
    }

    /// <summary>
    /// Builds normalized health/status-only events for contract rendering.
    /// </summary>
    private static List<SandboxEvent> BuildContractEvents()
    {
        var timestamp = new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero);
        return
        [
            new SandboxEvent
            {
                EventType = "r0collector.deviceUnavailable",
                Timestamp = timestamp,
                Source = "r0collector",
                Path = @"\\.\KSwordSandboxDriver",
                Data =
                {
                    ["behaviorCounted"] = "false",
                    ["sampleBehaviorCandidate"] = "false",
                    ["nonbehavior"] = "true",
                    ["collectionHealth"] = "true",
                    ["diagnosticCode"] = "open_device_not_found",
                    ["readinessState"] = "unavailable",
                    ["driverStateName"] = "DeviceUnavailable"
                }
            },
            CreateVirusTotalStatusEvent(timestamp.AddSeconds(1), "not_found", "404"),
            CreateVirusTotalStatusEvent(timestamp.AddSeconds(2), "rate_limited", "429")
        ];
    }

    /// <summary>
    /// Creates one VT hash-reputation status event without sample upload data.
    /// </summary>
    private static SandboxEvent CreateVirusTotalStatusEvent(DateTimeOffset timestamp, string status, string httpStatusCode)
    {
        return new SandboxEvent
        {
            EventType = "enrichment.virustotal.lookup",
            Timestamp = timestamp,
            Source = "virustotal",
            Data =
            {
                ["sha256"] = new string('a', 64),
                ["vtStatus"] = status,
                ["status"] = status,
                ["vtVerdict"] = status,
                ["verdict"] = status,
                ["vtMalicious"] = "0",
                ["vtSuspicious"] = "0",
                ["httpStatusCode"] = httpStatusCode,
                ["permalink"] = "https://www.virustotal.com/gui/file/" + new string('a', 64)
            }
        };
    }

    /// <summary>
    /// Checks that rule metadata classifies status-only evidence as diagnostic
    /// or reputation metadata with no ATT&CK technique mapping.
    /// </summary>
    private static void AssertDiagnosticRuleContracts(IReadOnlyCollection<BehaviorFinding> findings)
    {
        var indexedFindings = findings.ToDictionary(finding => finding.RuleId, StringComparer.OrdinalIgnoreCase);
        foreach (var ruleId in DiagnosticRuleIds)
        {
            SmokeAssert.True(indexedFindings.TryGetValue(ruleId, out var finding), $"Synthetic status evidence should match rule '{ruleId}'.");
            SmokeAssert.True(string.Equals(finding!.Severity, "info", StringComparison.OrdinalIgnoreCase), $"Rule '{ruleId}' should remain info severity.");
            SmokeAssert.True(string.IsNullOrWhiteSpace(finding.MitreTechniqueId), $"Rule '{ruleId}' should not map status evidence to ATT&CK.");
            SmokeAssert.True(finding.Tags.Contains("metadata", StringComparer.OrdinalIgnoreCase), $"Rule '{ruleId}' should be tagged as metadata.");
        }

        SmokeAssert.True(!indexedFindings.ContainsKey("r0collector-device-unavailable"), "R0 unavailable should remain R0 health/raw evidence, not a behavior-rule finding.");

        foreach (var ruleId in new[] { "virustotal-not-found", "virustotal-rate-limited" })
        {
            var vtFinding = indexedFindings[ruleId];
            SmokeAssert.True(vtFinding.Tags.Contains("virustotal", StringComparer.OrdinalIgnoreCase), $"Rule '{ruleId}' should stay in the VT namespace.");
            SmokeAssert.True(vtFinding.Tags.Contains("reputation", StringComparer.OrdinalIgnoreCase) || vtFinding.Tags.Contains("rate-limit", StringComparer.OrdinalIgnoreCase), $"Rule '{ruleId}' should be reputation/status metadata.");
        }
    }

    /// <summary>
    /// Checks renderer source guardrails for raw-event bounds and separation
    /// helpers. These are static contracts so future refactors keep the shape.
    /// </summary>
    private static void AssertRendererSourceContracts(SmokeTestContext context)
    {
        var rendererSource = ReadRepositoryText(context, "src", "KSword.Sandbox.Core", "Reporting", "HtmlReportRenderer.cs");

        RequireContains(rendererSource, "RawEventInlineLimit = 30", "Raw events should keep a slim fixed inline row limit.");
        RequireContains(rendererSource, "RawEventPageSize = 25", "Raw events should keep compact bounded native pages.");
        RequireContains(rendererSource, "raw-events-shell", "Raw events should render inside a collapsed details shell.");
        RequireContains(rendererSource, "raw-events-panel{border-top:1px solid var(--line);max-height:58vh;overflow:auto", "Expanded raw events should have a finite scroll height.");
        RequireContains(rendererSource, "Report view.", "Rendered reports should explain the compact raw-event view.");
        RequireContains(rendererSource, "IsUserFacingEvent", "Renderer should filter the primary event explorer to sample-facing evidence.");
        RequireContains(rendererSource, "--raw-evidence-max:58vh", "Renderer should keep a finite raw evidence height cap.");
        RequireContains(rendererSource, "IsVirusTotalStatusIssue", "Renderer should explicitly separate VT status issues.");
        RequireContains(rendererSource, "Missing keys, rate limits, or not-found responses are enrichment status", "Renderer should describe VT status rows as enrichment status.");
        RequireContains(rendererSource, "PrimaryBehaviorFindings", "Renderer should keep a primary behavior filter.");
    }

    /// <summary>
    /// Renders English and Chinese reports and verifies the operator-facing
    /// separation between primary behavior, diagnostics, reputation, and R0
    /// health sections.
    /// </summary>
    private static void AssertRenderedReportContracts(List<SandboxEvent> events, IReadOnlyCollection<BehaviorFinding> findings)
    {
        var report = new AnalysisReport
        {
            JobId = Guid.Parse("22222222-3333-4444-5555-666666666666"),
            GeneratedAt = new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero),
            Status = AnalysisStatus.Completed,
            Sample = new SampleIdentity
            {
                FileName = "health-reputation-contract.exe",
                FullPath = @"D:\Samples\health-reputation-contract.exe",
                Sha256 = new string('a', 64),
                Sha1 = new string('b', 40),
                Md5 = new string('c', 32),
                Crc32 = "1234abcd",
                SizeBytes = 4096
            },
            Events = events,
            Findings = findings.ToList(),
            Metrics = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
            {
                ["events.total"] = events.Count
            }
        };

        var renderer = new HtmlReportRenderer();
        var englishHtml = renderer.RenderEnglish(report);
        var chineseHtml = renderer.RenderChinese(report);

        AssertExecutionBoundaryVerdictContracts(renderer, report, events);

        RequireMetric(englishHtml, "High risk", "0", "risk-high");
        RequireMetric(englishHtml, "Suspicious", "0", "risk-medium");
        RequireMetric(englishHtml, "General / info", "0", "risk-info");
        RequireContains(englishHtml, "No high-risk behavior", "Report verdict should not become malicious for health/status-only evidence.");

        var behaviorSection = ExtractSection(englishHtml, "behavior");
        var primaryBehaviorArea = TextBefore(behaviorSection, "<details class=\"relationship-details\"><summary>Static triage indicators");
        RequireContains(primaryBehaviorArea, "No sample-attributed behavior was observed in the captured runtime events.", "Primary behavior section should stay empty for health/status-only evidence.");
        RequireNotContains(primaryBehaviorArea, "R0 collector device unavailable", "R0 unavailable should not enter primary behavior rows.");
        RequireNotContains(primaryBehaviorArea, "VirusTotal hash not found", "VT not_found should not enter primary behavior rows.");
        RequireNotContains(primaryBehaviorArea, "VirusTotal lookup rate-limited", "VT rate-limit should not enter primary behavior rows.");
        RequireNotContains(behaviorSection, "Collection and pipeline diagnostics", "Collection diagnostics should stay out of the primary behavior UI.");

        var r0Section = ExtractSection(englishHtml, "r0");
        RequireContains(r0Section, "No sample-attributed driver behavior was captured.", "R0 health-only evidence should not create a sample behavior section.");
        RequireContains(r0Section, "Collection health status", "R0 collection health should remain visible in its dedicated R0 section.");

        var vtSection = ExtractSection(englishHtml, "vt");
        RequireContains(vtSection, "Hash-only enrichment.", "VT section should describe reputation enrichment.");
        RequireContains(vtSection, "rate limits, or not-found responses are enrichment status, not malicious sample behavior.", "VT status rows should be explicitly non-malicious.");
        RequireMetric(vtSection, "VT malicious", "0", "risk-high");
        RequireMetric(vtSection, "VT suspicious", "0", "risk-medium");
        RequireMetric(vtSection, "VT status issues", "1", "risk-info");
        RequireContains(vtSection, "VirusTotal hash not found", "VT not_found should be rendered in the reputation section.");
        RequireContains(vtSection, "VirusTotal lookup rate-limited", "VT rate-limit should be rendered in the reputation section.");

        var rawSection = ExtractSection(englishHtml, "events");
        RequireContains(rawSection, "<details class=\"raw-events-shell\"><summary><span class=\"fold-label\">Closed by default</span>", "Raw events should be collapsed even for small reports.");
        RequireContains(rawSection, "Show inline raw events (3/3; 0 hidden; 1 native pages)", "Raw event summary should include bounded native pagination.");
        RequireContains(rawSection, "<div class=\"raw-events-panel\">", "Raw events should expand into the bounded panel.");
        RequireContains(rawSection, "Report view.", "Raw event guidance should disclose the compact bounded view.");

        RequireContains(chineseHtml, "<html lang=\"zh-CN\">", "Chinese report should keep zh-CN metadata.");
        RequireContains(chineseHtml, "R0 / 驱动事件", "Chinese report should include the localized R0 section.");
        RequireNotContains(chineseHtml, "R0 可用性", "Chinese report should not expose the removed R0 health card in the main UI.");
        RequireContains(chineseHtml, "原始事件", "Chinese report should include the localized raw-event section.");
    }

    /// <summary>
    /// Verifies that launch blocks and CLR early exits do not render a
    /// reassuring no-risk verdict without complete runtime behavior, while a
    /// report with substantive dynamic evidence keeps the normal verdict path.
    /// </summary>
    private static void AssertExecutionBoundaryVerdictContracts(
        HtmlReportRenderer renderer,
        AnalysisReport baseline,
        IReadOnlyCollection<SandboxEvent> baselineEvents)
    {
        var staticEvent = new SandboxEvent
        {
            EventType = "static.pe.import.module",
            Timestamp = baseline.GeneratedAt,
            Source = "static",
            Path = baseline.Sample.FullPath,
            Data =
            {
                ["staticOnly"] = "true",
                ["moduleName"] = "wininet.dll"
            }
        };
        var blockedStart = new SandboxEvent
        {
            EventType = "process.start_failed",
            Timestamp = baseline.GeneratedAt.AddSeconds(1),
            Source = "guest",
            ProcessName = baseline.Sample.FileName,
            Path = baseline.Sample.FullPath,
            Data =
            {
                ["exceptionType"] = "System.ComponentModel.Win32Exception",
                ["nativeErrorCode"] = "225",
                ["message"] = "Windows Defender blocked this file (WinError 225)."
            }
        };
        var staticFinding = new BehaviorFinding
        {
            RuleId = "static-import-anti-analysis-api",
            Title = "Anti-analysis API imports or strings",
            TitleZh = "反分析 API 导入或字符串",
            Severity = "low",
            Confidence = "low",
            Summary = "Static analysis found debugger or timing API imports/strings commonly used in sandbox or debugger checks.",
            SummaryZh = "静态分析发现调试器或计时 API 导入/字符串，常用于沙箱或调试器检查。",
            Tags = ["static", "imports", "anti-analysis", "triage"],
            Evidence = [staticEvent]
        };
        var staticOnlyReport = baseline with
        {
            Events = [staticEvent],
            Findings = [staticFinding]
        };
        var staticOnlyHtml = renderer.RenderEnglish(staticOnlyReport);
        RequireContains(staticOnlyHtml, "Static capability clue (unverified): Anti-analysis API imports or strings", "Static findings must be labelled as unverified capability clues.");
        RequireContains(staticOnlyHtml, "Static evidence only: imports, API-like strings, URLs, YARA matches, entropy, and PE metadata do not prove execution", "Static findings must carry an explicit runtime boundary.");
        RequireContains(staticOnlyHtml, "Static-only / unverified", "Static findings must expose an evidence class instead of a risk-only severity label.");
        RequireNotContains(staticOnlyHtml, "<td class=\"risk-medium\">", "Static-only triage must not render as a medium-risk metric cell.");
        var staticOnlyChineseHtml = renderer.RenderChinese(staticOnlyReport);
        RequireContains(staticOnlyChineseHtml, "静态能力线索（未验证）：反分析 API 导入或字符串", "Chinese static findings must keep the unverified capability label.");
        RequireContains(staticOnlyChineseHtml, "静态证据边界", "Chinese static analysis must expose the runtime evidence boundary.");
        var blockedStartReport = baseline with
        {
            Events = baselineEvents.Concat([staticEvent, blockedStart]).ToList(),
            Findings = [staticFinding]
        };
        var blockedStartHtml = renderer.RenderEnglish(blockedStartReport);
        RequireContains(blockedStartHtml, "Execution blocked / runtime indeterminate", "WinError 225 launch block should make runtime coverage indeterminate.");
        RequireNotContains(blockedStartHtml, "No high-risk behavior", "A WinError 225 launch block must not render a reassuring no-risk verdict.");
        RequireContains(blockedStartHtml, "static-only evidence", "Static evidence should remain explicitly static-only after a launch block.");
        RequireContains(renderer.RenderChinese(blockedStartReport), "执行被阻断/运行期不可判定", "Chinese reports should localize the indeterminate runtime verdict.");

        var blockedClrExit = new SandboxEvent
        {
            EventType = "process.exit",
            Timestamp = baseline.GeneratedAt.AddSeconds(2),
            Source = "guest",
            ProcessName = baseline.Sample.FileName,
            Path = baseline.Sample.FullPath,
            Data =
            {
                ["runtime"] = "CLR",
                ["exitCode"] = "-2146232576"
            }
        };
        var blockedClrReport = baseline with
        {
            Events = [staticEvent, blockedClrExit],
            Findings = [staticFinding]
        };
        var blockedClrHtml = renderer.RenderEnglish(blockedClrReport);
        RequireContains(blockedClrHtml, "Execution blocked / runtime indeterminate", "A non-zero CLR early exit without behavior should make runtime coverage indeterminate.");
        RequireContains(blockedClrHtml, "-2146232576", "Non-zero process exits must preserve the original numeric exit code.");
        RequireContains(blockedClrHtml, "0x80131700", "CLR startup failures should expose a hexadecimal representation.");
        RequireContains(blockedClrHtml, "CLR startup-stage failure", "Known CLR startup failures should expose their common semantic hint.");
        RequireContains(blockedClrHtml, "Sample-attributed behavior is indeterminate", "Non-zero process exits must keep sample behavior indeterminate rather than implying maliciousness.");
        RequireNotContains(blockedClrHtml, "No high-risk behavior", "A non-zero CLR early exit must not render a reassuring no-risk verdict.");

        // A failed sample launch can carry a weak/false classifier marker when
        // the guest could not establish normal lineage. The submitted sample
        // path/name remains authoritative for this execution boundary, so the
        // report must still surface the failure at the cover and failure lane.
        var weaklyCorrelatedClrExit = blockedClrExit with
        {
            Data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["runtime"] = "CLR",
                ["exitCode"] = "-2146232576",
                ["sampleBehaviorCandidate"] = "false",
                ["sampleCorrelation"] = "unknown"
            }
        };
        var weaklyCorrelatedClrReport = baseline with
        {
            Events = [staticEvent, weaklyCorrelatedClrExit],
            Findings = [staticFinding]
        };
        var weaklyCorrelatedClrHtml = renderer.RenderEnglish(weaklyCorrelatedClrReport);
        RequireContains(weaklyCorrelatedClrHtml, "Sample execution failed / runtime indeterminate", "The report cover must surface a failed sample exit even when correlation is weak.");
        RequireContains(weaklyCorrelatedClrHtml, "Sample execution outcome", "Weakly correlated sample exit must remain in the failure lane.");
        RequireNotContains(weaklyCorrelatedClrHtml, "No high-risk behavior", "A weakly correlated non-zero sample exit must not render a reassuring no-risk verdict.");
        RequireContains(renderer.RenderChinese(weaklyCorrelatedClrReport), "样本执行失败/运行期不可判定", "Chinese reports must surface failed sample execution at the cover.");

        var completeBehavior = new SandboxEvent
        {
            EventType = "network.http",
            Timestamp = baseline.GeneratedAt.AddSeconds(3),
            Source = "guest",
            ProcessName = baseline.Sample.FileName,
            Path = baseline.Sample.FullPath,
            Data =
            {
                ["host"] = "example.test",
                ["method"] = "GET"
            }
        };
        var completedBehaviorReport = baseline with
        {
            Events = [staticEvent, blockedClrExit, completeBehavior],
            Findings = [staticFinding]
        };
        var completedBehaviorHtml = renderer.RenderEnglish(completedBehaviorReport);
        RequireContains(completedBehaviorHtml, "No high-risk behavior", "A non-zero exit with substantive runtime behavior should use the normal verdict path.");
        RequireNotContains(completedBehaviorHtml, "Execution blocked / runtime indeterminate", "Complete runtime behavior should clear the indeterminate execution verdict.");
    }

    /// <summary>
    /// Reads a repository file as text.
    /// </summary>
    private static string ReadRepositoryText(SmokeTestContext context, params string[] relativeSegments)
    {
        var allSegments = new string[relativeSegments.Length + 1];
        allSegments[0] = context.RepositoryRoot;
        relativeSegments.CopyTo(allSegments, 1);
        return File.ReadAllText(Path.Combine(allSegments));
    }

    /// <summary>
    /// Extracts one top-level report section by anchor id.
    /// </summary>
    private static string ExtractSection(string html, string sectionId)
    {
        var start = html.IndexOf($"<section id=\"{sectionId}\"", StringComparison.Ordinal);
        SmokeAssert.True(start >= 0, $"Rendered HTML should contain section '{sectionId}'.");
        var end = html.IndexOf("</section>", start, StringComparison.Ordinal);
        SmokeAssert.True(end > start, $"Rendered HTML section '{sectionId}' should close.");
        return html[start..(end + "</section>".Length)];
    }

    /// <summary>
    /// Returns the text before a marker when present, otherwise the full text.
    /// </summary>
    private static string TextBefore(string text, string marker)
    {
        var index = text.IndexOf(marker, StringComparison.Ordinal);
        return index < 0 ? text : text[..index];
    }

    /// <summary>
    /// Requires one rendered metric label/value pair.
    /// </summary>
    private static void RequireMetric(string html, string label, string value, string css)
    {
        RequireContains(html, $"<span class=\"muted\">{label}</span><b class=\"{css}\">{value}</b>", $"Rendered metric '{label}' should equal {value}.");
    }

    /// <summary>
    /// Requires a literal value in text.
    /// </summary>
    private static void RequireContains(string content, string expected, string message)
    {
        SmokeAssert.True(content.Contains(expected, StringComparison.Ordinal), message);
    }

    /// <summary>
    /// Requires a literal value to be absent from text.
    /// </summary>
    private static void RequireNotContains(string content, string forbidden, string message)
    {
        SmokeAssert.True(!content.Contains(forbidden, StringComparison.Ordinal), message);
    }
}
