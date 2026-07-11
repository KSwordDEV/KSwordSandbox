using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Reporting;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Regression coverage for benign GUI applications that are still running when
/// a short sandbox window ends. Inputs are a Notepad-like process.timeout event;
/// processing verifies rule classification and report verdict rendering; the
/// scenario returns pass/fail metadata.
/// </summary>
internal sealed class BenignGuiTimeoutRegressionScenario : ISmokeTestScenario
{
    public string ScenarioId => "behavior.benign-gui-timeout.regression";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var rules = RuleEngine.LoadRuleSet(Path.Combine(context.RepositoryRoot, "rules", "behavior-rules.json"));
        var engine = new RuleEngine(rules);
        var timeoutEvent = BuildBenignNotepadTimeoutEvent();
        var findings = engine.Classify([timeoutEvent]);

        SmokeAssert.True(
            findings.Any(finding =>
                string.Equals(finding.RuleId, "process-timeout-long-sleep", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(finding.Severity, "info", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(finding.Confidence, "low", StringComparison.OrdinalIgnoreCase)),
            "Benign Notepad GUI timeout should be retained only as low-confidence info execution-state metadata.");
        SmokeAssert.True(
            !findings.Any(IsMediumOrHigher),
            $"Benign Notepad GUI timeout should not produce high/medium behavior findings. Findings: {DescribeFindings(findings)}");
        SmokeAssert.True(
            !findings.Any(finding => string.Equals(finding.RuleId, "anti-analysis-sleep-duration-metadata", StringComparison.OrdinalIgnoreCase)),
            "A plain Notepad process.timeout with timeoutSeconds should not be promoted to sleep-duration anti-analysis.");
        SmokeAssert.True(
            !findings.Any(finding => string.Equals(finding.RuleId, "anti-analysis-accelerated-sleep-metadata", StringComparison.OrdinalIgnoreCase)),
            "A plain Notepad process.timeout should not be promoted to accelerated-sleep anti-analysis.");

        var evasionFindings = engine.Classify([BuildExplicitSleepEvasionEvent()]);
        SmokeAssert.True(
            evasionFindings.Any(finding =>
                string.Equals(finding.RuleId, "anti-analysis-sleep-duration-metadata", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(finding.Severity, "medium", StringComparison.OrdinalIgnoreCase)),
            "Explicit sleep-duration telemetry should still classify as medium anti-analysis evidence.");

        var html = new HtmlReportRenderer().RenderEnglish(BuildGuiTimeoutReport(timeoutEvent, findings));
        RequireContains(
            html,
            "<span class=\"badge badge-info\">No high-risk behavior</span>",
            "Completed benign GUI timeout report should keep an info verdict.");
        RequireContains(
            html,
            "<span class=\"muted\">High risk</span><b class=\"risk-high\">0</b>",
            "Completed benign GUI timeout report should count zero high-risk behavior findings.");
        RequireContains(
            html,
            "<span class=\"muted\">Suspicious</span><b class=\"risk-medium\">0</b>",
            "Completed benign GUI timeout report should count zero medium behavior findings.");
        RequireNotContains(
            html,
            "<span class=\"badge badge-high\">Analysis failed</span>",
            "Completed benign GUI timeout report should not render a failed/high-risk verdict.");
        RequireNotContains(
            html,
            "<span class=\"badge badge-medium\">Suspicious</span>",
            "Completed benign GUI timeout report should not render a medium-risk verdict.");
        RequireContains(html, "notepad.exe", "Report should still show the timed-out benign GUI process name.");
        RequireContains(html, "Windows GUI", "Report should still show GUI subsystem context.");
        RequireContains(html, "Sample still running at timeout", "Report should preserve the timeout metadata finding.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Benign Notepad/GUI timeout remains info-only and does not inflate report risk."
        });
    }

    /// <summary>
    /// Creates a benign GUI timeout event matching Notepad behavior.
    /// </summary>
    private static SandboxEvent BuildBenignNotepadTimeoutEvent()
    {
        return new SandboxEvent
        {
            EventType = "process.timeout",
            Timestamp = new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero),
            Source = "guest",
            ProcessName = "notepad.exe",
            ProcessId = 4242,
            Path = @"C:\Windows\System32\notepad.exe",
            CommandLine = @"C:\Windows\System32\notepad.exe",
            Data =
            {
                ["timeoutSeconds"] = "5",
                ["subsystem"] = "Windows GUI"
            }
        };
    }

    /// <summary>
    /// Creates an explicit positive control for real sleep-evasion telemetry.
    /// </summary>
    private static SandboxEvent BuildExplicitSleepEvasionEvent()
    {
        return new SandboxEvent
        {
            EventType = "api.sleep",
            Timestamp = new DateTimeOffset(2026, 1, 2, 3, 4, 6, TimeSpan.Zero),
            Source = "guest",
            ProcessName = "suspicious-delay.exe",
            ProcessId = 5000,
            CommandLine = "suspicious-delay.exe",
            Data =
            {
                ["api"] = "Sleep",
                ["durationMs"] = "600000"
            }
        };
    }

    /// <summary>
    /// Builds a completed report whose only finding is the benign timeout.
    /// </summary>
    private static AnalysisReport BuildGuiTimeoutReport(SandboxEvent timeoutEvent, IReadOnlyCollection<BehaviorFinding> findings)
    {
        return new AnalysisReport
        {
            JobId = Guid.Parse("33333333-4444-5555-6666-777777777777"),
            GeneratedAt = timeoutEvent.Timestamp.AddSeconds(1),
            Status = AnalysisStatus.Completed,
            Sample = new SampleIdentity
            {
                FileName = "notepad.exe",
                FullPath = @"C:\Windows\System32\notepad.exe",
                Sha256 = new string('d', 64),
                Sha1 = new string('e', 40),
                Md5 = new string('f', 32),
                Crc32 = "feedbeef",
                SizeBytes = 4096
            },
            StaticAnalysis = new StaticAnalysisResult
            {
                FileFormat = "PE32+",
                Magic = "MZ",
                IsPe = true,
                Architecture = "x64",
                Subsystem = "Windows GUI",
                EntryPointRva = "0x1000",
                SectionCount = 1,
                Sections =
                [
                    new PeSectionInfo
                    {
                        Name = ".text",
                        VirtualAddress = "0x1000",
                        VirtualSize = 4096,
                        RawDataSize = 2048,
                        Entropy = 5.1
                    }
                ],
                Tags = ["gui"]
            },
            Events = [timeoutEvent],
            Findings = findings.ToList(),
            Metrics = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
            {
                ["events.total"] = 1
            }
        };
    }

    /// <summary>
    /// Determines whether a finding is medium severity or higher.
    /// </summary>
    private static bool IsMediumOrHigher(BehaviorFinding finding)
    {
        return string.Equals(finding.Severity, "medium", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(finding.Severity, "high", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(finding.Severity, "critical", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Formats findings for actionable assertion messages.
    /// </summary>
    private static string DescribeFindings(IReadOnlyCollection<BehaviorFinding> findings)
    {
        return findings.Count == 0
            ? "(none)"
            : string.Join(", ", findings.Select(finding => $"{finding.RuleId}:{finding.Severity}"));
    }

    /// <summary>
    /// Requires a literal value in rendered HTML.
    /// </summary>
    private static void RequireContains(string content, string expected, string message)
    {
        SmokeAssert.True(content.Contains(expected, StringComparison.Ordinal), message);
    }

    /// <summary>
    /// Requires a literal value to be absent from rendered HTML.
    /// </summary>
    private static void RequireNotContains(string content, string forbidden, string message)
    {
        SmokeAssert.True(!content.Contains(forbidden, StringComparison.Ordinal), message);
    }
}
