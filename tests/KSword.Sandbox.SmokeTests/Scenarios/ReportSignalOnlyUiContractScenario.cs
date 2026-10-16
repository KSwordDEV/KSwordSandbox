using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Reporting;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies that the operator-facing report keeps the primary view focused on
/// sample-attributed runtime evidence. Inputs include one behavior row and one
/// collector/environment row; processing renders both localized reports while
/// raw evidence remains available in the final section.
/// </summary>
internal sealed class ReportSignalOnlyUiContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "report.signal-only-ui.contract";

    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var report = BuildReport();
        var renderer = new HtmlReportRenderer();
        var english = renderer.RenderEnglish(report);
        var chinese = renderer.RenderChinese(report);

        AssertSignalOnlyMainView(english);
        AssertSignalOnlyMainView(chinese);
        SmokeAssert.True(english.Contains("<section id=\"events\"", StringComparison.Ordinal), "Raw normalized events section must remain available.");
        SmokeAssert.True(english.Contains("environment.snapshot", StringComparison.Ordinal), "Raw evidence must retain the environment row.");
        SmokeAssert.True(english.Contains("contract-sample.exe", StringComparison.Ordinal), "Sample behavior must remain visible.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Main report view contains sample-attributed evidence only; operational noise remains available through raw evidence."
        });
    }

    private static AnalysisReport BuildReport()
    {
        var timestamp = new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero);
        return new AnalysisReport
        {
            JobId = Guid.Parse("77777777-8888-9999-aaaa-bbbbbbbbbbbb"),
            GeneratedAt = timestamp,
            Status = AnalysisStatus.Completed,
            Sample = new SampleIdentity
            {
                FileName = "signal-only-contract.exe",
                FullPath = @"D:\Samples\signal-only-contract.exe",
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
                    EventType = "process.start",
                    Timestamp = timestamp,
                    Source = "guest",
                    ProcessName = "contract-sample.exe",
                    ProcessId = 4242,
                    Path = @"C:\Users\Public\signal-only-contract.exe"
                },
                new SandboxEvent
                {
                    EventType = "environment.snapshot",
                    Timestamp = timestamp.AddSeconds(1),
                    Source = "guest",
                    ProcessName = "explorer.exe",
                    Data =
                    {
                        ["behaviorCounted"] = "false",
                        ["nonbehavior"] = "true",
                        ["notSampleBehavior"] = "true"
                    }
                }
            ]
        };
    }

    private static void AssertSignalOnlyMainView(string html)
    {
        var rawStart = html.IndexOf("<section id=\"events\"", StringComparison.Ordinal);
        SmokeAssert.True(rawStart > 0, "Rendered report must include a raw evidence section.");
        var main = html[..rawStart];
        foreach (var forbidden in new[]
        {
            "Behavior story counts exclude rows marked",
            "行为叙事会排除标记为",
            "No primary sample behavior rules matched",
            "未命中主要样本行为规则",
            "Collection/self-noise policy",
            "Graph self-noise boundary",
            "Behavior story routing",
            "R0 noise policy",
            "Collector self-noise hidden from behavior sections",
            "environment.snapshot"
        })
        {
            SmokeAssert.True(!main.Contains(forbidden, StringComparison.Ordinal), $"Main report view must hide '{forbidden}'.");
        }
    }
}
