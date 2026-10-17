using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Correlation;
using KSword.Sandbox.Core.Reporting;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Keeps ordinary System32 discovery utilities out of the sample verdict while
/// retaining their normalized rows and preserving explicit high-signal rules.
/// </summary>
internal sealed class SystemNativeDiscoveryVerdictRegressionScenario : ISmokeTestScenario
{
    public string ScenarioId => "report.system-native-discovery-verdict-regression";

    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var timestamp = new DateTimeOffset(2026, 10, 17, 12, 0, 0, TimeSpan.Zero);
        var sample = new SandboxEvent
        {
            EventType = "process.start",
            Timestamp = timestamp,
            Source = "etwLive",
            ProcessName = "sample.exe",
            ProcessId = 7000,
            Path = @"C:\Users\Public\sample.exe",
            CommandLine = @"C:\Users\Public\sample.exe"
        };
        var hostname = new SandboxEvent
        {
            EventType = "process.start",
            Timestamp = timestamp.AddMilliseconds(100),
            Source = "etwLive",
            ProcessName = "hostname.exe",
            ProcessId = 7001,
            ParentProcessId = 7000,
            Path = @"C:\Windows\System32\hostname.exe",
            CommandLine = @"C:\Windows\System32\hostname.exe",
            Data =
            {
                ["processImagePath"] = @"C:\Windows\System32\hostname.exe"
            }
        };

        var classified = SampleCorrelationClassifier.Apply([sample, hostname], sample.Path);
        var classifiedHostname = classified.Single(evt => evt.ProcessId == 7001);
        SmokeAssert.True(
            string.Equals(classifiedHostname.Data.GetValueOrDefault("sampleCorrelation"), "environment", StringComparison.OrdinalIgnoreCase),
            "System32 hostname discovery should be retained as environment evidence.");
        SmokeAssert.True(
            string.Equals(classifiedHostname.Data.GetValueOrDefault("behaviorCounted"), "false", StringComparison.OrdinalIgnoreCase),
            "System32 hostname discovery should not count as sample behavior.");
        SmokeAssert.True(
            string.Equals(classifiedHostname.Data.GetValueOrDefault("sampleCorrelationReason"), "system32-signed-or-known-discovery-utility-without-high-signal-behavior", StringComparison.OrdinalIgnoreCase),
            "System32 discovery suppression should expose a stable reason in raw evidence.");

        var rules = RuleEngine.LoadRuleSet(Path.Combine(context.RulesDirectory, "behavior-rules.json"));
        var findings = new RuleEngine(rules).Classify(classified);
        SmokeAssert.True(
            !findings.Any(finding => string.Equals(finding.RuleId, "system-discovery-command", StringComparison.OrdinalIgnoreCase)),
            "Environment-classified hostname evidence must not create a primary discovery finding.");

        var highSignalHostname = hostname with
        {
            Data = new Dictionary<string, string>(hostname.Data, StringComparer.OrdinalIgnoreCase)
            {
                ["persistenceCandidate"] = "true",
                ["persistenceFamily"] = "service-configuration"
            }
        };
        var highSignalClassified = SampleCorrelationClassifier.Apply([sample, highSignalHostname], sample.Path)
            .Single(evt => evt.ProcessId == 7001);
        SmokeAssert.True(
            string.Equals(highSignalClassified.Data.GetValueOrDefault("sampleCorrelation"), "confirmed", StringComparison.OrdinalIgnoreCase),
            "Explicit persistence evidence must bypass the System32 discovery baseline guard.");

        // A pre-correlation/externally produced report can still contain the
        // old rule hit. Renderer routing must demote it without dropping raw
        // events or evidence.
        var legacyFinding = new BehaviorFinding
        {
            RuleId = "system-discovery-command",
            Title = "System information discovery command",
            Severity = "medium",
            Tags = ["discovery", "system", "command"],
            Summary = "A command collected host details.",
            Evidence =
            [
                hostname with
                {
                    Data = new Dictionary<string, string>(hostname.Data, StringComparer.OrdinalIgnoreCase)
                    {
                        ["sampleCorrelation"] = "confirmed",
                        ["sampleCorrelationStatus"] = "correlated",
                        ["behaviorCounted"] = "true",
                        ["sampleBehaviorCandidate"] = "true"
                    }
                }
            ]
        };
        var report = new AnalysisReport
        {
            JobId = Guid.Parse("11111111-2222-3333-4444-555555555555"),
            GeneratedAt = timestamp.AddSeconds(1),
            Status = AnalysisStatus.Completed,
            Sample = new SampleIdentity
            {
                FileName = "sample.exe",
                FullPath = sample.Path,
                Sha256 = new string('a', 64),
                Sha1 = new string('b', 40),
                Md5 = new string('c', 32),
                Crc32 = "1234abcd",
                SizeBytes = 1
            },
            Events = classified,
            Findings = [legacyFinding]
        };

        var html = new HtmlReportRenderer().RenderEnglish(report);
        var highRisk = html.Contains("class=\"focus-verdict badge badge-high\"", StringComparison.OrdinalIgnoreCase);
        var critical = html.Contains("class=\"focus-verdict badge badge-critical\"", StringComparison.OrdinalIgnoreCase);
        SmokeAssert.True(!highRisk && !critical,
            $"A discovery-only System32 finding must not raise a high/critical report verdict (high={highRisk}, critical={critical}).");
        SmokeAssert.True(
            html.Contains("<span>Primary findings</span><strong class=\"risk-low\">0</strong>", StringComparison.OrdinalIgnoreCase),
            "A discovery-only System32 finding must be absent from the primary finding count.");
        SmokeAssert.True(html.Contains("System information discovery command", StringComparison.Ordinal),
            "Demoted discovery evidence must remain visible in the report.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "System32 hostname discovery remains raw evidence and cannot drive a suspicious primary verdict."
        });
    }
}
