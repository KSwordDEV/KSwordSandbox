using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Reporting;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Keeps generic R0 telemetry findings out of the primary behavior table while
/// retaining them in a collapsed support lane. Inputs include one semantic
/// sample action and one broad driver row; processing verifies that the
/// semantic action drives the verdict and the telemetry row remains reviewable.
/// </summary>
internal sealed class ReportFindingRoutingContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "report.finding-routing.contract";

    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var timestamp = new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero);
        var sampleEvent = new SandboxEvent
        {
            EventType = "process.start",
            Timestamp = timestamp,
            Source = "etwLive",
            ProcessName = "cmd.exe",
            ProcessId = 4243,
            ParentProcessId = 4242,
            CommandLine = "/c powershell Set-MpPreference -DisableRealtimeMonitoring $true",
            Data =
            {
                ["sampleCorrelation"] = "confirmed",
                ["behaviorCounted"] = "true",
                ["sampleBehaviorCandidate"] = "true"
            }
        };
        var driverEvent = new SandboxEvent
        {
            EventType = "driver.file",
            Timestamp = timestamp.AddMilliseconds(20),
            Source = "driver",
            ProcessName = "contract-sample.exe",
            ProcessId = 4242,
            Path = @"\Device\HarddiskVolume3\Users\Public\noise.tmp",
            Data =
            {
                ["sampleCorrelation"] = "confirmed",
                ["behaviorCounted"] = "true",
                ["sampleBehaviorCandidate"] = "true"
            }
        };
        var report = new AnalysisReport
        {
            JobId = Guid.Parse("99999999-aaaa-bbbb-cccc-dddddddddddd"),
            GeneratedAt = timestamp,
            Status = AnalysisStatus.Completed,
            Sample = new SampleIdentity
            {
                FileName = "contract-sample.exe",
                FullPath = @"D:\Samples\contract-sample.exe",
                Sha256 = new string('a', 64),
                Sha1 = new string('b', 40),
                Md5 = new string('c', 32),
                Crc32 = "1234abcd",
                SizeBytes = 4096
            },
            Events = [sampleEvent, driverEvent],
            Findings =
            [
                new BehaviorFinding
                {
                    RuleId = "defender-disable-command",
                    Title = "Microsoft Defender disable or exclusion command",
                    TitleZh = "Microsoft Defender 禁用或排除命令",
                    Severity = "high",
                    Confidence = "high",
                    Summary = "A sample-linked command attempts to weaken Defender.",
                    SummaryZh = "归属于样本的命令尝试削弱 Defender。",
                    Tags = ["defense-evasion"],
                    Evidence = [sampleEvent]
                },
                new BehaviorFinding
                {
                    RuleId = "r0-driver-file-write-signal",
                    Title = "R0 driver file write or rename signal",
                    TitleZh = "R0 驱动文件写入或重命名信号",
                    Severity = "medium",
                    Confidence = "medium",
                    Summary = "A generic R0 file row was observed.",
                    SummaryZh = "观察到通用 R0 文件行。",
                    Tags = ["driver", "r0"],
                    Evidence = [driverEvent]
                }
            ]
        };

        var renderer = new HtmlReportRenderer();
        var english = renderer.RenderEnglish(report);
        var chinese = renderer.RenderChinese(report);
        AssertRouting(english, "Microsoft Defender disable or exclusion command", "R0 / collection support findings", "R0 driver file write or rename signal");
        AssertRouting(chinese, "Microsoft Defender 禁用或排除命令", "R0 / 采集支持命中", "R0 驱动文件写入或重命名信号");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Semantic behavior findings drive the primary view; generic R0 telemetry remains in a collapsed support lane."
        });
    }

    private static void AssertRouting(string html, string primaryTitle, string supportHeading, string supportTitle)
    {
        var behaviorStart = html.IndexOf("<section id=\"behavior\"", StringComparison.Ordinal);
        var supportStart = html.IndexOf(supportHeading, behaviorStart, StringComparison.Ordinal);
        var behaviorEnd = html.IndexOf("<section id=\"mitre\"", behaviorStart, StringComparison.Ordinal);
        SmokeAssert.True(behaviorStart >= 0 && supportStart > behaviorStart && behaviorEnd > supportStart, $"Behavior section should expose the support lane before MITRE details (behavior={behaviorStart}, support={supportStart}, end={behaviorEnd}).");
        var primary = html[behaviorStart..supportStart];
        var support = html[supportStart..behaviorEnd];
        SmokeAssert.True(primary.Contains(primaryTitle, StringComparison.Ordinal), "Semantic finding should remain in the primary behavior view.");
        SmokeAssert.True(!primary.Contains(supportTitle, StringComparison.Ordinal), "Generic R0 finding must not occupy the primary behavior view.");
        SmokeAssert.True(support.Contains(supportTitle, StringComparison.Ordinal), "Generic R0 finding must remain reviewable in the support lane.");
    }
}
