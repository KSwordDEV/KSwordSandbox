using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Reporting;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies that R0Collector's own driver/file/network activity is treated as
/// collection-side self-noise instead of sample behavior. Inputs are synthetic
/// driver telemetry rows; processing renders the report and checks behavior
/// counts, section filtering, R0 self-noise summary, and raw-event retention;
/// the scenario returns pass/fail metadata.
/// </summary>
internal sealed class ReportR0CollectorSelfNoiseContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "report.r0collector-self-noise.behavior-contract";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var report = BuildContractReport();
        var renderer = new HtmlReportRenderer();
        var englishHtml = renderer.RenderEnglish(report);
        var chineseHtml = renderer.RenderChinese(report);

        AssertRendererSourceContracts(context);
        AssertRenderedContracts(englishHtml, chineseHtml);

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "R0Collector self-noise is hidden from sample behavior while remaining auditable in R0/raw sections."
        });
    }

    /// <summary>
    /// Builds a report with one real driver file row plus two collector-origin
    /// driver rows that must not count as behavior.
    /// </summary>
    private static AnalysisReport BuildContractReport()
    {
        var timestamp = new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero);
        var sampleDriverFile = new SandboxEvent
        {
            EventType = "driver.file.create",
            Timestamp = timestamp,
            Source = "driver",
            ProcessName = "contract-sample.exe",
            ProcessId = 4242,
            Path = @"C:\Users\Public\sample-drop.bin",
            Data =
            {
                ["driverEventPath"] = "driver-events.jsonl"
            }
        };
        var collectorFileNoise = new SandboxEvent
        {
            EventType = "driver.file.create",
            Timestamp = timestamp.AddSeconds(1),
            Source = "driver",
            ProcessName = "KSword.Sandbox.R0Collector.exe",
            ProcessId = 9001,
            Path = @"C:\KSwordSandbox\r0collector\collector-self-noise.tmp",
            Data =
            {
                ["producer"] = "KSword.Sandbox.R0Collector",
                ["eventOrigin"] = "synthetic-r0collector"
            }
        };
        var collectorNetworkNoise = new SandboxEvent
        {
            EventType = "driver.network.connect",
            Timestamp = timestamp.AddSeconds(2),
            Source = "driver",
            ProcessName = "KSword.Sandbox.R0Collector.exe",
            ProcessId = 9001,
            Data =
            {
                ["remoteAddress"] = "127.0.0.1",
                ["remotePort"] = "18080",
                ["collectorProcessName"] = "KSword.Sandbox.R0Collector.exe"
            }
        };

        return new AnalysisReport
        {
            JobId = Guid.Parse("33333333-4444-5555-6666-777777777777"),
            GeneratedAt = timestamp,
            Status = AnalysisStatus.Completed,
            Sample = new SampleIdentity
            {
                FileName = "r0-self-noise-contract.exe",
                FullPath = @"D:\Samples\r0-self-noise-contract.exe",
                Sha256 = new string('a', 64),
                Sha1 = new string('b', 40),
                Md5 = new string('c', 32),
                Crc32 = "1234abcd",
                SizeBytes = 4096
            },
            Events = [sampleDriverFile, collectorFileNoise, collectorNetworkNoise],
            Metrics = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
            {
                ["events.total"] = 3
            }
        };
    }

    /// <summary>
    /// Checks static renderer guardrails for self-noise filtering helpers.
    /// </summary>
    private static void AssertRendererSourceContracts(SmokeTestContext context)
    {
        var rendererPath = Path.Combine(context.RepositoryRoot, "src", "KSword.Sandbox.Core", "Reporting", "HtmlReportRenderer.cs");
        var rendererSource = File.ReadAllText(rendererPath);

        RequireContains(rendererSource, "IsCollectorSelfNoiseEvent", "Renderer should explicitly detect collector self-noise.");
        RequireContains(rendererSource, "IsSampleBehaviorEvent", "Renderer should separate sample behavior from collection plumbing.");
        RequireContains(rendererSource, "IsSampleBehaviorFileEvent", "File behavior counts should use the sample-behavior filter.");
        RequireContains(rendererSource, "IsSampleBehaviorNetworkEvent", "Network behavior counts should use the sample-behavior filter.");
        RequireContains(rendererSource, "Collector self-noise hidden", "R0 section should expose an auditable self-noise count.");
        RequireContains(rendererSource, "R0 noise policy", "R0 section should explain that self-noise and health lanes do not affect behavior counts.");
        RequireContains(rendererSource, "Self-noise excluded", "Process tree overview should disclose collector self-noise exclusion.");
    }

    /// <summary>
    /// Checks rendered English and Chinese reports for self-noise behavior.
    /// </summary>
    private static void AssertRenderedContracts(string englishHtml, string chineseHtml)
    {
        var quickNav = ExtractNav(englishHtml, "quick-nav");
        RequireContains(quickNav, "<a class=\"quick-link\" href=\"#files\"><strong>File system activity</strong><small>1</small></a>", "Quick file count should exclude collector self-noise.");
        RequireContains(quickNav, "<a class=\"quick-link\" href=\"#network\"><strong>Network behavior</strong><small>0</small></a>", "Quick network count should exclude collector self-noise.");

        var riskSection = ExtractSection(englishHtml, "risk");
        RequireMetric(riskSection, "File events", "1", "risk-medium");
        RequireMetric(riskSection, "Network events", "0", "risk-medium");
        RequireMetric(riskSection, "Registry events", "0", "risk-medium");

        var dynamicSection = ExtractSection(englishHtml, "dynamic");
        RequireMetric(dynamicSection, "File events", "1", "risk-medium");
        RequireMetric(dynamicSection, "Network events", "0", "risk-medium");

        var fileSection = ExtractSection(englishHtml, "files");
        RequireContains(fileSection, @"C:\Users\Public\sample-drop.bin", "File behavior should retain the real sample driver row.");
        RequireNotContains(fileSection, "KSword.Sandbox.R0Collector.exe", "File behavior should hide collector self-noise.");
        RequireNotContains(fileSection, "collector-self-noise.tmp", "File behavior should not render collector file self-noise.");

        var networkSection = ExtractSection(englishHtml, "network");
        RequireNotContains(networkSection, "KSword.Sandbox.R0Collector.exe", "Network behavior should hide collector self-noise.");
        RequireNotContains(networkSection, "127.0.0.1:18080", "Network behavior should not render collector network self-noise.");

        var graphSection = ExtractSection(englishHtml, "graph");
        RequireContains(graphSection, "contract-sample.exe pid:4242", "Behavior graph should retain sample driver behavior.");
        RequireNotContains(graphSection, "KSword.Sandbox.R0Collector.exe", "Behavior graph should exclude collector self-noise.");

        var r0Section = ExtractSection(englishHtml, "r0");
        RequireMetric(r0Section, "Driver telemetry rows", "1", "risk-info");
        RequireMetric(r0Section, "Collector self-noise hidden", "2", "risk-info");
        RequireContains(r0Section, "R0 noise policy.", "R0 section should explain the low-noise policy.");
        RequireContains(r0Section, "Behavior impact", "R0 health summary should explicitly keep health impact out of behavior counts.");
        RequireContains(r0Section, "Collector self-noise hidden from behavior sections.", "R0 section should explain self-noise filtering.");
        RequireContains(r0Section, "collector-self-noise.tmp", "R0 self-noise summary should remain auditable.");

        var rawSection = ExtractSection(englishHtml, "events");
        RequireContains(rawSection, "KSword.Sandbox.R0Collector.exe", "Raw events should retain collector self-noise.");
        RequireContains(rawSection, "collector-self-noise.tmp", "Raw events should retain collector self-noise paths.");

        RequireContains(chineseHtml, "采集器自噪声已隐藏", "Chinese report should localize the self-noise count.");
        RequireContains(chineseHtml, "采集器自噪声已从行为章节隐藏。", "Chinese report should localize self-noise guidance.");
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
    /// Extracts one nav block by id.
    /// </summary>
    private static string ExtractNav(string html, string navId)
    {
        var start = html.IndexOf($"<nav id=\"{navId}\"", StringComparison.Ordinal);
        SmokeAssert.True(start >= 0, $"Rendered HTML should contain nav '{navId}'.");
        var end = html.IndexOf("</nav>", start, StringComparison.Ordinal);
        SmokeAssert.True(end > start, $"Rendered nav '{navId}' should close.");
        return html[start..(end + "</nav>".Length)];
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
