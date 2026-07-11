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
        "r0collector-device-unavailable",
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

        var r0Finding = indexedFindings["r0collector-device-unavailable"];
        SmokeAssert.True(r0Finding.Tags.Contains("diagnostic", StringComparer.OrdinalIgnoreCase), "R0 unavailable should be a diagnostic finding.");
        SmokeAssert.True(r0Finding.Tags.Contains("collection", StringComparer.OrdinalIgnoreCase), "R0 unavailable should be collection-health metadata.");
        SmokeAssert.True(r0Finding.Tags.Contains("driver-health", StringComparer.OrdinalIgnoreCase), "R0 unavailable should be driver-health metadata.");

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

        RequireContains(rendererSource, "RawEventInlineLimit = 200", "Raw events should keep a fixed inline row limit.");
        RequireContains(rendererSource, "RawEventPageSize = 50", "Raw events should keep bounded native pages.");
        RequireContains(rendererSource, "raw-events-shell", "Raw events should render inside a collapsed details shell.");
        RequireContains(rendererSource, "raw-events-panel{border-top:1px solid var(--line);max-height:58vh;overflow:auto", "Expanded raw events should have a finite scroll height.");
        RequireContains(rendererSource, "Raw events are collapsed by default.", "Rendered reports should explain the raw-event collapse.");
        RequireContains(rendererSource, "IsR0CollectionHealthEvent", "Renderer should explicitly separate R0 collection health.");
        RequireContains(rendererSource, "R0 unavailable, driver health, queue backpressure", "Renderer should describe R0 health as collection quality.");
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

        RequireMetric(englishHtml, "High risk", "0", "risk-high");
        RequireMetric(englishHtml, "Suspicious", "0", "risk-medium");
        RequireMetric(englishHtml, "General / info", "0", "risk-info");
        RequireContains(englishHtml, "No high-risk behavior", "Report verdict should not become malicious for health/status-only evidence.");

        var behaviorSection = ExtractSection(englishHtml, "behavior");
        var primaryBehaviorArea = TextBefore(behaviorSection, "<details class=\"relationship-details\"><summary>Static triage indicators");
        RequireContains(primaryBehaviorArea, "No primary sample behavior rules matched.", "Primary behavior section should stay empty for health/status-only evidence.");
        RequireNotContains(primaryBehaviorArea, "R0 collector device unavailable", "R0 unavailable should not enter primary behavior rows.");
        RequireNotContains(primaryBehaviorArea, "VirusTotal hash not found", "VT not_found should not enter primary behavior rows.");
        RequireNotContains(primaryBehaviorArea, "VirusTotal lookup rate-limited", "VT rate-limit should not enter primary behavior rows.");
        RequireContains(behaviorSection, "Collection and pipeline diagnostics", "Diagnostic findings should still be visible in a secondary group.");

        var r0Section = ExtractSection(englishHtml, "r0");
        RequireContains(r0Section, "Collection health status.", "R0 section should explain collection health.");
        RequireContains(r0Section, "not malicious sample behavior", "R0 section should state health rows are not malicious behavior.");
        RequireMetric(r0Section, "Collection health rows", "1", "risk-medium");
        RequireMetric(r0Section, "Device unavailable", "1", "risk-medium");
        RequireMetric(r0Section, "Driver telemetry rows", "0", "risk-info");
        RequireContains(r0Section, "No non-health R0 driver telemetry rows were imported.", "R0 unavailable alone should not create driver telemetry evidence.");

        var vtSection = ExtractSection(englishHtml, "vt");
        RequireContains(vtSection, "Hash-only enrichment.", "VT section should describe reputation enrichment.");
        RequireContains(vtSection, "rate limits, or not-found responses are enrichment status, not malicious sample behavior.", "VT status rows should be explicitly non-malicious.");
        RequireMetric(vtSection, "VT malicious", "0", "risk-high");
        RequireMetric(vtSection, "VT suspicious", "0", "risk-medium");
        RequireMetric(vtSection, "VT status issues", "1", "risk-info");
        RequireContains(vtSection, "VirusTotal hash not found", "VT not_found should be rendered in the reputation section.");
        RequireContains(vtSection, "VirusTotal lookup rate-limited", "VT rate-limit should be rendered in the reputation section.");

        var rawSection = ExtractSection(englishHtml, "events");
        RequireContains(rawSection, "<details class=\"raw-events-shell\"><summary>Show inline raw events (3/3; 0 hidden)</summary>", "Raw events should be collapsed even for small reports.");
        RequireContains(rawSection, "<div class=\"raw-events-panel\">", "Raw events should expand into the bounded panel.");

        RequireContains(chineseHtml, "<html lang=\"zh-CN\">", "Chinese report should keep zh-CN metadata.");
        RequireContains(chineseHtml, "R0 / 驱动事件", "Chinese report should include the localized R0 section.");
        RequireContains(chineseHtml, "原始事件", "Chinese report should include the localized raw-event section.");
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
