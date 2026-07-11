using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Reporting;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Golden-style synthetic report coverage for R0Collector self-noise. Inputs
/// are generated normalized events; processing renders HTML only; the scenario
/// proves collector-owned file/registry rows stay out of sample behavior
/// sections while remaining audit-visible in R0/raw evidence.
/// </summary>
internal sealed class R0CollectorNoiseReportContractScenario : ISmokeTestScenario
{
    private const string VisibleSampleFile = "sample-visible-drop.txt";
    private const string VisibleSampleRegistry = "SampleVisibleRunKey";
    private const string CollectorFileNoise = "r0collector-self-noise-file-marker.log";
    private const string CollectorRegistryNoise = "R0CollectorSelfNoiseMarker";
    private const string CollectorGuestRegistryNoise = "R0CollectorGuestSelfNoiseMarker";

    public string ScenarioId => "report.r0collector-self-noise.contract";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var report = BuildContractReport();
        var html = new HtmlReportRenderer().RenderEnglish(report);

        AssertGoldenReportShell(html);
        AssertBehaviorSectionsExcludeCollectorNoise(html);
        AssertR0AndRawSectionsPreserveCollectorNoiseAuditTrail(html);

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "R0Collector self-noise is hidden from file/registry behavior sections and preserved as R0/raw evidence."
        });
    }

    private static AnalysisReport BuildContractReport()
    {
        var timestamp = new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero);
        return new AnalysisReport
        {
            JobId = Guid.Parse("33333333-4444-5555-6666-777777777777"),
            GeneratedAt = timestamp,
            Status = AnalysisStatus.Completed,
            Sample = new SampleIdentity
            {
                FileName = "r0-noise-contract.exe",
                FullPath = @"D:\Samples\r0-noise-contract.exe",
                Sha256 = new string('a', 64),
                Sha1 = new string('b', 40),
                Md5 = new string('c', 32),
                Crc32 = "1234abcd",
                SizeBytes = 4096
            },
            Events =
            [
                new SandboxEvent
                {
                    EventType = "file.created",
                    Timestamp = timestamp,
                    Source = "guest",
                    ProcessName = "r0-noise-contract.exe",
                    ProcessId = 4242,
                    Path = $@"C:\Users\Public\{VisibleSampleFile}"
                },
                new SandboxEvent
                {
                    EventType = "registry.set",
                    Timestamp = timestamp.AddSeconds(1),
                    Source = "guest",
                    ProcessName = "r0-noise-contract.exe",
                    ProcessId = 4242,
                    Path = $@"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\{VisibleSampleRegistry}"
                },
                new SandboxEvent
                {
                    EventType = "driver.file.create",
                    Timestamp = timestamp.AddSeconds(2),
                    Source = "driver",
                    ProcessName = "KSword.Sandbox.R0Collector.exe",
                    ProcessId = 4500,
                    Path = $@"C:\KSwordSandbox\r0collector\{CollectorFileNoise}",
                    Data =
                    {
                        ["producer"] = "KSword.Sandbox.R0Collector",
                        ["eventOrigin"] = "synthetic-r0collector",
                        ["noise"] = "true",
                        ["driverEventPath"] = "driver-events.jsonl"
                    }
                },
                new SandboxEvent
                {
                    EventType = "driver.registry.set",
                    Timestamp = timestamp.AddSeconds(3),
                    Source = "driver",
                    ProcessName = "KSword.Sandbox.R0Collector.exe",
                    ProcessId = 4500,
                    Path = $@"HKLM\Software\KSwordSandbox\{CollectorRegistryNoise}",
                    Data =
                    {
                        ["producer"] = "KSword.Sandbox.R0Collector",
                        ["eventOrigin"] = "synthetic-r0collector",
                        ["noise"] = "true",
                        ["driverEventPath"] = "driver-events.jsonl"
                    }
                },
                new SandboxEvent
                {
                    EventType = "registry.set",
                    Timestamp = timestamp.AddSeconds(4),
                    Source = "guest",
                    ProcessName = "KSword.Sandbox.R0Collector.exe",
                    ProcessId = 4500,
                    Path = $@"HKCU\Software\KSwordSandbox\{CollectorGuestRegistryNoise}",
                    Data =
                    {
                        ["producer"] = "KSword.Sandbox.R0Collector",
                        ["eventOrigin"] = "synthetic-r0collector",
                        ["noise"] = "true"
                    }
                }
            ],
            Metrics = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
            {
                ["events.total"] = 5
            }
        };
    }

    private static void AssertGoldenReportShell(string html)
    {
        RequireContains(html, "<section id=\"files\" class=\"card\"><h2>File system activity</h2>", "Report should keep the file behavior section anchor and heading.");
        RequireContains(html, "<section id=\"registry\" class=\"card\"><h2>Registry behavior</h2>", "Report should keep the registry behavior section anchor and heading.");
        RequireContains(html, "<section id=\"r0\" class=\"card\"><h2>R0 / driver events</h2>", "Report should keep the R0 section anchor and heading.");
        RequireContains(html, "<section id=\"events\" class=\"card\"><h2>Raw normalized events</h2>", "Report should keep the raw-events section anchor and heading.");
        RequireContains(html, "<span class=\"muted\">Collector self-noise hidden</span><b class=\"risk-info\">2</b>", "R0 section should expose the self-noise count as bounded evidence-quality metadata.");
    }

    private static void AssertBehaviorSectionsExcludeCollectorNoise(string html)
    {
        var fileSection = ExtractSection(html, "files");
        RequireContains(fileSection, VisibleSampleFile, "File behavior should still include sample-owned file activity.");
        RequireNotContains(fileSection, CollectorFileNoise, "File behavior should not include collector-owned R0 file self-noise.");
        RequireNotContains(fileSection, "KSword.Sandbox.R0Collector.exe", "File behavior should not attribute rows to the collector process.");

        var registrySection = ExtractSection(html, "registry");
        RequireContains(registrySection, VisibleSampleRegistry, "Registry behavior should still include sample-owned registry activity.");
        RequireNotContains(registrySection, CollectorRegistryNoise, "Registry behavior should not include driver-originated collector self-noise.");
        RequireNotContains(registrySection, CollectorGuestRegistryNoise, "Registry behavior should not include guest-normalized collector self-noise.");
        RequireNotContains(registrySection, "KSword.Sandbox.R0Collector.exe", "Registry behavior should not attribute rows to the collector process.");
    }

    private static void AssertR0AndRawSectionsPreserveCollectorNoiseAuditTrail(string html)
    {
        var r0Section = ExtractSection(html, "r0");
        RequireContains(r0Section, "Collector self-noise hidden from behavior sections.", "R0 section should explain that collector self-noise is hidden from behavior sections.");
        RequireContains(r0Section, CollectorFileNoise, "R0 section should keep a bounded example of hidden collector file self-noise.");
        RequireContains(r0Section, CollectorRegistryNoise, "R0 section should keep a bounded example of hidden collector registry self-noise.");

        var rawSection = ExtractSection(html, "events");
        RequireContains(rawSection, CollectorFileNoise, "Raw events should preserve collector file self-noise for auditability.");
        RequireContains(rawSection, CollectorRegistryNoise, "Raw events should preserve collector registry self-noise for auditability.");
        RequireContains(rawSection, CollectorGuestRegistryNoise, "Raw events should preserve guest-normalized collector self-noise for auditability.");
    }

    private static string ExtractSection(string html, string sectionId)
    {
        var start = html.IndexOf($"<section id=\"{sectionId}\"", StringComparison.Ordinal);
        SmokeAssert.True(start >= 0, $"Rendered HTML should contain section '{sectionId}'.");
        var end = html.IndexOf("</section>", start, StringComparison.Ordinal);
        SmokeAssert.True(end > start, $"Rendered HTML section '{sectionId}' should close.");
        return html[start..(end + "</section>".Length)];
    }

    private static void RequireContains(string content, string expected, string message)
    {
        SmokeAssert.True(content.Contains(expected, StringComparison.Ordinal), message);
    }

    private static void RequireNotContains(string content, string forbidden, string message)
    {
        SmokeAssert.True(!content.Contains(forbidden, StringComparison.Ordinal), message);
    }
}
